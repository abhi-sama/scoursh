#!/usr/bin/env bash
# lib/findings.sh - the finding data model, fingerprinting, the severity rubric,
# redaction, evidence normalisation, the shard writer and merge, and derived
# (composite) findings.
#
# Owns:
#   docs/DESIGN.md   §4 (lib/findings.sh)
#   docs/FOUNDATION.md tension  5 (fingerprint identity)
#   docs/FOUNDATION.md tension  6 (derived / composite findings)
#   docs/FOUNDATION.md tension  7 (check_id, and no field named `id`)
#   docs/FOUNDATION.md tension  8 (base severity versus rubric adjustment)
#   docs/FOUNDATION.md tension  9 (redaction versus evidence versus fingerprint)
#   docs/FOUNDATION.md tension 10 (untrusted evidence: normalise in, escape out)
#   docs/FOUNDATION.md tension 11 (the frozen pipeline: merge and dedup)
#   docs/FOUNDATION.md tension 17 (per-worker shards, deterministic merge)
#   docs/FOUNDATION.md tension 22 (a logical identity on every finding)
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_FINDINGS_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_FINDINGS_SOURCED=1

# shellcheck source=lib/records.sh
source "${BASH_SOURCE[0]%/*}/records.sh"

# ---------------------------------------------------------------------------
# 1. Frozen schema identifiers
# ---------------------------------------------------------------------------
readonly FP_SCHEMA='fp/1'      # tension 5
readonly UK_SCHEMA='uk/1'      # tension 18
export FP_SCHEMA UK_SCHEMA

: "${SCOURSH_EVIDENCE_MAX_BYTES:=512}"
# Evidence arrives from a scanned target and may be arbitrarily large.  The
# normalisation below is byte-at-a-time in bash for the rare non-ASCII case, so
# the input is bounded first.  Everything past this bound would be discarded by
# the final truncation to evidence_max_bytes in any event; redaction has already
# run over the WHOLE text by then, so no partial secret can be exposed by it.
: "${SCOURSH_EVIDENCE_INPUT_MAX_BYTES:=8192}"
: "${SCOURSH_REDACT_SECRETS:=true}"

# ---------------------------------------------------------------------------
# 2. Digests (tensions 5 and 9)
# ---------------------------------------------------------------------------

# Strip ALL whitespace.  Reindenting or reformatting therefore does not churn
# identity; changing the code does, which is correct, because the matched text
# IS the finding.
#
# This collapses runs AND the zero-versus-one-space distinction, and the second
# half is the point.  Collapsing runs alone is not insensitivity to whitespace:
# zero spaces versus one space is not a run, and that is exactly what a code
# formatter changes.  Under run-collapsing, `eval( x )` and `eval(x)` hashed
# differently, so a `black` / `prettier` / `gofmt` pass over a repository gave
# every affected finding a new fingerprint - the old one absent, hence classified
# `fixed` by tension 12 - and wrote a wave of remediations that never happened
# into `state/`, with `--fail-on-new` firing on the whole set.
#
# THE COST, stated rather than hidden: `a b` and `ab` now share a digest.  They
# remain two distinct findings, told apart by the `occurrence` ordinal exactly as
# two byte-identical matches already are, and by path, so identity is not lost -
# only the discriminator changes.  That slightly widens the bounded ordinal churn
# tension 5 already documents, and it buys immunity to the far more common
# formatter case.  The normalisation can only ever MERGE digests, never split
# them, so it cannot manufacture a `new` finding.
fingerprint_normalise() {
  local s=$1
  s=${s//[$' \t\n\r\f\v']/}
  printf '%s' "$s"
}

# tension 9: consumes the RAW matched text, hashes it, returns 16 hex
# characters, and retains only the hash.  Because it hashes the raw text, two
# different keys in one file are two different findings, which is what tension 5
# needs; because only the hash is retained, the secret never reaches disk.
# The text is piped, never passed as an argument (tension 9 handling rule 1).
fingerprint_digest() {
  local norm digest
  norm=$(fingerprint_normalise "$1")
  digest=$(printf '%s' "$norm" | sha256_of)
  printf '%s' "${digest:0:16}"
}

# tension 5.  NUL is the separator; no location component can contain NUL
# (rules/RULE-FORMAT.md §3.1), and command substitution would strip it, so the
# components are streamed into the hash rather than joined in a variable.
fingerprint_compute() {
  local module=$1 check_id=$2
  shift 2
  _fingerprint_stream "$module" "$check_id" "$@" | sha256_of
}

_fingerprint_stream() {
  local c
  printf '%s' "$FP_SCHEMA"
  for c in "$@"; do
    printf '\0%s' "$c"
  done
}

# tension 18: derived from a work unit's INPUTS, so it exists before the unit
# runs.  §10's word "fingerprint" is a spec-wording error; a unit that runs and
# finds nothing produces no fingerprint at all, yet it is precisely the unit a
# resume must know to skip.
unit_key() {
  local module=$1 check_id=$2
  shift 2
  _unit_key_stream "$module" "$check_id" "$@" | sha256_of
}

_unit_key_stream() {
  local c
  printf '%s' "$UK_SCHEMA"
  for c in "$@"; do
    printf '\0%s' "$c"
  done
}

# ---------------------------------------------------------------------------
# 3. The fingerprint location profile (tension 5, frozen table)
# ---------------------------------------------------------------------------
# Exactly one fingerprint function exists and no module computes a fingerprint
# itself, so the component order lives here and nowhere else.
_fp_profile_for() {
  local module=$1 check_id=$2
  case $module in
    sast)
      if [[ $check_id == SAST-HIST-* ]]; then printf '%s' history; else printf '%s' path; fi
      ;;
    iac | containers) printf '%s' path ;;
    sca) printf '%s' sca ;;
    dast) printf '%s' dast ;;
    cloud) printf '%s' cloud ;;
    posture) printf '%s' posture ;;
    derived) printf '%s' derived ;;
    *) return 1 ;;
  esac
}

_fp_components_for() {
  case $1 in
    path) printf '%s\n' path match_digest occurrence ;;
    history) printf '%s\n' blob_sha match_digest occurrence ;;
    sca) printf '%s\n' ecosystem package advisory_id ;;
    dast) printf '%s\n' target method path_template param_location param_name ;;
    cloud) printf '%s\n' account_id region resource_key sub_key ;;
    posture) printf '%s\n' control_id scope_key ;;
    derived) printf '%s\n' correlation ;;
    *) return 1 ;;
  esac
}

# Only these profiles need the `occurrence` discriminator; every other module's
# component tuple is already unique per issue (tension 5).
_fp_profile_needs_occurrence() {
  case $1 in
    path | history) return 0 ;;
    *) return 1 ;;
  esac
}

# tension 5: replace volatile path segments with {id}, so /users/123 and
# /users/456 are one finding.  A segment is replaced when it is entirely digits,
# or matches a UUID, or matches a ULID, or is hexadecimal and at least 16
# characters long.  Everything else is kept literally.
path_template_of() {
  local p=$1 out='' seg rest
  [[ ${p:0:1} == '/' ]] && p=${p#/} && out=''
  rest=$p
  local first=1
  while [[ -n $rest || $first == 1 ]]; do
    seg=${rest%%/*}
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=''; fi
    first=0
    if [[ $seg =~ ^[0-9]+$ ]] \
      || [[ $seg =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
      || [[ $seg =~ ^[0-7][0-9A-HJKMNP-TV-Z]{25}$ ]] \
      || [[ $seg =~ ^[0-9a-fA-F]{16,}$ ]]; then
      seg='{id}'
    fi
    out="$out/$seg"
    [[ -n $rest ]] || break
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 4. The occurrence ordinal (tension 5)
# ---------------------------------------------------------------------------
# The 0-based ordinal of this match among the matches IN THE SAME SCANNING UNIT,
# for the same check_id, with an identical match_digest, ordered by ascending
# line number and then by ascending byte offset within the line.
#
# The caller feeds matches in that order; the byte-offset tie-break is why
# lib/core.sh's scan_match_offsets exists (rules/RULE-FORMAT.md §10.3), because
# a bare `-n` reports each matching line once and cannot produce this ordinal.
#
# The scanning unit is the FILE for SAST, IaC and containers, and the BLOB for
# SAST history (tension 13): scoping it to a path instead would reintroduce
# per-commit duplication, since the same content is reachable under a renamed
# path.
#
# Every top-level associative/indexed array in this file is `declare -g`,
# never bare - see lib/records.sh's `_SCHEMA_LOADED` comment for the measured
# failure (tools/vendor-engines.sh's advisories bootstrap sources this file,
# transitively, from inside a short-lived function) that this defends
# against.
declare -gA _OCC=()
OCCURRENCE_RESULT=0

# Clears every ordinal space.  A real run is one process, so this is normally
# implicit; a test harness that simulates several runs in one process must call
# it, or a counter from the previous run leaks into the next one's identities.
occurrence_reset_all() {
  _OCC=()
  SCOURSH_SCAN_UNIT=''
}

occurrence_reset_unit() {
  SCOURSH_SCAN_UNIT=$1
  local k
  (( ${#_OCC[@]} > 0 )) || return 0
  for k in "${!_OCC[@]}"; do
    [[ $k == "$1"$'\x1f'* ]] && unset '_OCC[$k]'
  done
  return 0
}

# SETS OCCURRENCE_RESULT rather than printing it, and must be called in the
# current shell: `n=$(occurrence_next ...)` would increment the counter inside
# the command substitution's subshell and throw the increment away, so every
# repeated byte-identical match in a file would take ordinal 0, collapse onto
# one fingerprint, and be deduped by the merge - which is exactly the collision
# the discriminator exists to eliminate.
# The scanning unit comes from the fingerprint PROFILE, so tension 5's frozen
# table is the single source and no fallback can reach a different answer.
#
# It was a fallback chain - SCOURSH_SCAN_UNIT, then loc_path, then loc_blob_sha -
# and it never reached the blob.  A SAST-HIST-* finding always carries a path,
# because tension 13 requires the path in the reported location for navigation,
# so loc_path always won; and after any working-tree scan the leftover
# SCOURSH_SCAN_UNIT won ahead of both, keying every history finding in the run on
# the last file scanned.
#
# The consequence was the churn tension 13 exists to prevent: a blob's ordinal
# depended on how many OTHER blobs at the same path carrying the same secret were
# enumerated before it, so adding one older commit to the history window
# renumbered an untouched blob and the diff reported one `fixed` plus one `new`
# for a secret nobody had touched.  Path scoping also collides two findings for
# one blob reachable at two paths onto a single fingerprint, breaking tension 5's
# "fingerprints are unique within a run".
_occurrence_unit_for() {
  case $1 in
    history) printf '%s' "${_F[loc_blob_sha]:-}" ;;
    *) printf '%s' "${SCOURSH_SCAN_UNIT:-${_F[loc_path]:-}}" ;;
  esac
}

occurrence_next() {
  local unit=$1 check_id=$2 digest=$3
  local k="$unit"$'\x1f'"$check_id"$'\x1f'"$digest"
  OCCURRENCE_RESULT=${_OCC[$k]:-0}
  _OCC[$k]=$(( OCCURRENCE_RESULT + 1 ))
}

# ---------------------------------------------------------------------------
# 5. Redaction (tension 9)
# ---------------------------------------------------------------------------
_REDACTION_LOADED=0
_REDACTION_COMBINED=''
# Short inputs are memoised: a rule's title and remediation are redacted once per
# finding and are identical across every finding of that check, and each miss
# costs an engine fork.  Evidence is usually longer and usually unique, so the
# size cap keeps the cache small.
declare -gA _REDACT_MEMO=()
declare -ga _REDACTION_IDS=()

# The path argument is optional and defaults to the shipped file.  Callers that
# pass one - the fixture harness and the test suites - live outside this file and
# are therefore invisible to the linter.  Older releases report SC2120 here and
# newer ones do not, so it is silenced explicitly rather than left to whichever
# version a CI image happens to ship.
# shellcheck disable=SC2120
redaction_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/rules/redaction.rules}
  _REDACTION_LOADED=1
  _REDACTION_COMBINED=''
  _REDACTION_IDS=()
  _REDACT_MEMO=()
  [[ -r $path ]] || return 0
  records_load "$path" redaction redaction || die "$SCOURSH_EXIT_INPUT" \
    "rules/redaction.rules failed to parse"
  local n i pat
  n=$(records_count redaction)
  for (( i = 0; i < n; i++ )); do
    _REDACTION_IDS+=("$i")
    pat=$(records_field redaction "$i" pattern)
    if [[ -n $_REDACTION_COMBINED ]]; then
      _REDACTION_COMBINED="$_REDACTION_COMBINED|($pat)"
    else
      _REDACTION_COMBINED="($pat)"
    fi
  done
}

# `redact TEXT` - produces what is written ANYWHERE: evidence, logs, run.json,
# JSON, SARIF, Markdown, HTML.  Each match of a rule in rules/redaction.rules is
# replaced with <redacted:KIND:DDDDDDDD>, where DDDDDDDD is the first 8 hex
# characters of the SHA-256 of the raw matched bytes.  The short digest is what
# makes a redacted report usable: a reader can tell two distinct secrets apart
# and recognise the same secret in three places, without the secret being
# present.
#
# The patterns are applied by the SAME engine the scanner uses, over a pipe.
# That is deliberate: bash's own `=~` uses the system regcomp, which on
# macOS/BSD supports none of \b, \w, \s or \d (measured), so an in-process bash
# match would silently fail to redact on exactly the platform the CI matrix
# mandates.  Routing through lib/core.sh's engine wrapper makes redaction obey
# rules/RULE-FORMAT.md §8.2 exactly, on every host.
redact() {
  local text=$1
  if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
    printf '%s' "$text"
    return 0
  fi
  # shellcheck disable=SC2119
  # shellcheck disable=SC2119
  (( _REDACTION_LOADED )) || redaction_load
  if [[ -z $_REDACTION_COMBINED || -z $text ]]; then
    printf '%s' "$text"
    return 0
  fi
  local memo_key=$text
  if (( ${#text} <= 512 )) && [[ -n ${_REDACT_MEMO[$text]+set} ]]; then
    printf '%s' "${_REDACT_MEMO[$text]}"
    return 0
  fi
  # Fast path: one engine call decides whether any rule matches at all, which
  # for the overwhelming majority of evidence is "no".
  local any
  any=$(printf '%s' "$text" | scan_match_stdin "$_REDACTION_COMBINED" || true)
  if [[ -z $any ]]; then
    _redact_memoise "$memo_key" "$text"
    printf '%s' "$text"
    return 0
  fi
  local i pat kind m d hits
  for i in "${_REDACTION_IDS[@]+"${_REDACTION_IDS[@]}"}"; do
    pat=$(records_field redaction "$i" pattern)
    kind=$(records_field redaction "$i" kind)
    hits=$(printf '%s' "$text" | scan_match_stdin "$pat" || true)
    [[ -n $hits ]] || continue
    while IFS= read -r m; do
      [[ -n $m ]] || continue
      [[ $text == *"$m"* ]] || continue
      d=$(printf '%s' "$m" | sha256_of)
      text=${text//"$m"/"<redacted:$kind:${d:0:8}>"}
    done <<<"$hits"
  done
  _redact_memoise "$memo_key" "$text"
  printf '%s' "$text"
}

_redact_memoise() {
  (( ${#1} <= 512 )) || return 0
  _REDACT_MEMO[$1]=$2
}

# ---------------------------------------------------------------------------
# 6. Evidence normalisation (tension 10)
# ---------------------------------------------------------------------------
# Evidence is, for every DAST finding, bytes the scanned target chose to send.
# A scanner that renders attacker-influenced bytes into HTML without escaping is
# a stored-XSS delivery mechanism aimed at the engineer reading the report.
# Normalise once on the way in, escape once per emitter on the way out.
#
# In order: redact, strip C0 controls (preserving line structure as a literal
# \n), replace invalid UTF-8 with \xNN, truncate on a character boundary.
evidence_normalise() {
  local s=$1
  s=$(redact "$s")
  if (( ${#s} > SCOURSH_EVIDENCE_INPUT_MAX_BYTES )); then
    s=${s:0:SCOURSH_EVIDENCE_INPUT_MAX_BYTES}
  fi
  # Line structure that matters is preserved by replacing each stripped LF with
  # a literal backslash-n two-byte sequence BEFORE stripping.
  s=${s//$'\n'/\\n}
  # Fast path: printable ASCII only, which is valid UTF-8 and control-free by
  # construction, so nothing below can change it.
  if [[ $s == *[!$'\x20'-$'\x7e']* ]]; then
    s=$(_evidence_scrub "$s")
  fi
  s=$(_evidence_truncate "$s")
  printf '%s' "$s"
}

# Removes every C0 control character and DEL, and rewrites any byte that is not
# part of a well-formed UTF-8 sequence as \xNN, so every downstream format
# receives valid UTF-8.
_evidence_scrub() {
  local s=$1
  local n=${#s}
  local out='' i=0 c need k d ok lo hi seq
  while (( i < n )); do
    printf -v c '%d' "'${s:i:1}"
    if (( c < 32 || c == 127 )); then
      i=$(( i + 1 ))
      continue
    fi
    if (( c < 128 )); then
      out+=${s:i:1}
      i=$(( i + 1 ))
      continue
    fi
    lo=128
    hi=191
    if (( c >= 194 && c <= 223 )); then need=1
    elif (( c == 224 )); then need=2; lo=160
    elif (( c >= 225 && c <= 236 )); then need=2
    elif (( c == 237 )); then need=2; hi=159
    elif (( c >= 238 && c <= 239 )); then need=2
    elif (( c == 240 )); then need=3; lo=144
    elif (( c >= 241 && c <= 243 )); then need=3
    elif (( c == 244 )); then need=3; hi=143
    else need=-1
    fi
    ok=1
    if (( need < 0 || i + need >= n )); then
      ok=0
    else
      for (( k = 1; k <= need; k++ )); do
        printf -v d '%d' "'${s:i+k:1}"
        if (( k == 1 )); then
          (( d >= lo && d <= hi )) || { ok=0; break; }
        else
          (( d >= 128 && d <= 191 )) || { ok=0; break; }
        fi
      done
    fi
    if (( ok )); then
      seq=${s:i:need+1}
      out+=$seq
      i=$(( i + need + 1 ))
    else
      printf -v seq '\\x%02X' "$c"
      out+=$seq
      i=$(( i + 1 ))
    fi
  done
  printf '%s' "$out"
}

# Truncate to evidence_max_bytes on a UTF-8 character boundary, appending
# " ...[truncated]".
_evidence_truncate() {
  local s=$1 max=$SCOURSH_EVIDENCE_MAX_BYTES
  (( ${#s} > max )) || { printf '%s' "$s"; return 0; }
  local cut=$max c
  while (( cut > 0 )); do
    printf -v c '%d' "'${s:cut:1}"
    if (( c >= 128 && c <= 191 )); then
      cut=$(( cut - 1 ))            # inside a sequence: step back to its start
    else
      break
    fi
  done
  printf '%s ...[truncated]' "${s:0:cut}"
}

# ---------------------------------------------------------------------------
# 7. Escaping on the way out (tension 10)
# ---------------------------------------------------------------------------
# JSON is lib/core.sh's json_string.  These are the other two.
html_escape() {
  local s=$1
  s=${s//&/\&amp;}
  s=${s//</\&lt;}
  s=${s//>/\&gt;}
  s=${s//\"/\&quot;}
  s=${s//\'/\&#39;}
  printf '%s' "$s"
}

# A fence one backtick longer than the longest backtick run in the content, with
# a minimum of three, so evidence cannot break out of a Markdown code block.
md_fence_for() {
  local s=$1
  local n=${#s}
  local i=0 run=0 longest=0
  while (( i < n )); do
    if [[ ${s:i:1} == '`' ]]; then
      run=$(( run + 1 ))
      (( run > longest )) && longest=$run
    else
      run=0
    fi
    i=$(( i + 1 ))
  done
  local want=$(( longest + 1 ))
  (( want < 3 )) && want=3
  local fence=''
  for (( i = 0; i < want; i++ )); do fence+='`'; done
  printf '%s' "$fence"
}

# ---------------------------------------------------------------------------
# 8. The severity rubric (tension 8)
# ---------------------------------------------------------------------------
# The rubric ALWAYS runs.  It is a pure, total function whose only inputs are
# fields already recorded on the finding:
#
#   final = clamp( base + sum(modifiers), floor, ceiling )
#
# It may read nothing outside the finding record: no wall clock, no random, no
# host state, no network, no ordering.  Facts absent from a finding take their
# documented default, so the function is total and never depends on whether a
# module bothered to set a field.
declare -gA _RUBRIC=()
_RUBRIC_LOADED=0

# The path argument is optional and defaults to the shipped file.  Callers that
# pass one - the fixture harness and the test suites - live outside this file and
# are therefore invisible to the linter.  Older releases report SC2120 here and
# newer ones do not, so it is silenced explicitly rather than left to whichever
# version a CI image happens to ship.
# shellcheck disable=SC2120
rubric_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/data/severity-rubric.conf}
  _RUBRIC=()
  _RUBRIC_LOADED=1
  [[ -r $path ]] || return 0
  records_load "$path" severity-modifier rubric \
    || die "$SCOURSH_EXIT_INPUT" "data/severity-rubric.conf failed to parse"
  local n i fact eq mod
  n=$(records_count rubric)
  for (( i = 0; i < n; i++ )); do
    fact=$(records_field rubric "$i" fact)
    eq=$(records_field rubric "$i" equals)
    mod=$(records_field rubric "$i" modifier)
    _RUBRIC["$fact|$eq"]=$mod
  done
}

_rubric_mod() {
  local v=${_RUBRIC["$1|$2"]:-0}
  [[ $v =~ ^[+-]?[0-9]+$ ]] || v=0
  printf '%s' "${v#+}"
}

# severity_final BASE EXPOSURE AUTH SENSITIVE CONFIDENCE [FLOOR] [CEILING]
severity_final() {
  local base=$1 exposure=${2:-unknown} auth=${3:-user} sensitive=${4:-false}
  local confidence=${5:-medium} floor=${6:-} ceiling=${7:-}
  # shellcheck disable=SC2119
  (( _RUBRIC_LOADED )) || rubric_load
  local n
  n=$(severity_rank "$base")
  (( n >= 0 )) || n=0
  n=$(( n + $(_rubric_mod exposure "$exposure") ))
  n=$(( n + $(_rubric_mod auth "$auth") ))
  n=$(( n + $(_rubric_mod sensitive-data "$sensitive") ))
  n=$(( n + $(_rubric_mod confidence "$confidence") ))
  (( n < 0 )) && n=0
  (( n > 4 )) && n=4
  local lim
  if [[ -n $floor ]]; then
    lim=$(severity_rank "$floor")
    (( lim >= 0 && n < lim )) && n=$lim
  fi
  if [[ -n $ceiling ]]; then
    lim=$(severity_rank "$ceiling")
    (( lim >= 0 && n > lim )) && n=$lim
  fi
  severity_name "$n"
}

# The CVSS vector is an OUTPUT, not an input.  It is generated from the same
# facts by this frozen mapping and stored for auditability, so it can never
# disagree with the severity it accompanies.
cvss_vector_of() {
  local exposure=${1:-unknown} auth=${2:-user} sensitive=${3:-false} confidence=${4:-medium}
  local av ac pr c
  case $exposure in
    internal) av=A ;;
    *) av=N ;;
  esac
  case $confidence in
    low) ac=H ;;
    *) ac=L ;;
  esac
  case $auth in
    none) pr=N ;;
    admin) pr=H ;;
    *) pr=L ;;
  esac
  case $sensitive in
    true) c=H ;;
    *) c=L ;;
  esac
  printf 'CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:N/S:U/C:%s/I:L/A:N' "$av" "$ac" "$pr" "$c"
}

# The base score for each vector this mapping can produce.
#
# A frozen table rather than arithmetic: the CVSS 3.1 base formula is defined
# over floating point with a roundup that is sensitive to the last bit, and
# tension 24 requires byte-identical output between GNU and BSD userlands, which
# awk's double handling cannot be relied on to give.  A 24-row table is exact
# everywhere.  Generated from the published CVSS 3.1 formula; the generator is
# pinned by tests/suites/findings.sh, which independently checks the two vectors
# whose scores are publicly documented.
cvss_score_of() {
  case $1 in
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) printf '%s' 8.2 ;;
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) printf '%s' 6.5 ;;
    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N) printf '%s' 7.1 ;;
    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N) printf '%s' 5.4 ;;
    CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.5 ;;
    CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N) printf '%s' 3.8 ;;
    CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N) printf '%s' 6.5 ;;
    CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N) printf '%s' 4.8 ;;
    CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.9 ;;
    CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N) printf '%s' 4.2 ;;
    CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.0 ;;
    CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N) printf '%s' 3.3 ;;
    CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) printf '%s' 7.1 ;;
    CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) printf '%s' 5.4 ;;
    CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N) printf '%s' 6.3 ;;
    CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N) printf '%s' 4.6 ;;
    CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.2 ;;
    CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N) printf '%s' 3.5 ;;
    CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.9 ;;
    CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N) printf '%s' 4.2 ;;
    CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N) printf '%s' 5.4 ;;
    CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N) printf '%s' 3.7 ;;
    CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N) printf '%s' 4.8 ;;
    CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N) printf '%s' 3.1 ;;
    *) printf '%s' 0.0 ;;
  esac
}

# ---------------------------------------------------------------------------
# 9. Cloud target attribution (rules/RULE-FORMAT.md §9.2.2)
# ---------------------------------------------------------------------------
# A cloud-live finding has no scope-target name in its identity, so `target` is
# supplied by attribution.  Attribution is a CORRELATION ATTRIBUTE ONLY and is
# never a fingerprint input: putting it into a cloud finding's identity would
# make every cloud finding churn to `new` the moment an operator edited
# config/scope.conf, which is the instability tension 5 exists to prevent.
declare -gA _ATTR_HOST=()      # host -> LF-joined target ids
declare -gA _ATTR_SUBDOMAIN=() # target -> LF-joined hosts allowing subdomains
_ATTR_LOADED=0

# The path argument is optional and defaults to the shipped file.  Callers that
# pass one - the fixture harness and the test suites - live outside this file and
# are therefore invisible to the linter.  Older releases report SC2120 here and
# newer ones do not, so it is silenced explicitly rather than left to whichever
# version a CI image happens to ship.
# shellcheck disable=SC2120
attribution_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  _ATTR_HOST=()
  _ATTR_SUBDOMAIN=()
  _ATTR_LOADED=1
  [[ -r $path ]] || return 0
  records_load "$path" scope-target scope || die "$SCOURSH_EXIT_INPUT" \
    "config/scope.conf failed to parse"
  local n i id url host subs h
  n=$(records_count scope)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id scope "$i")
    # DESIGN §4 requires run.json to name the targets a run was scoped to.
    # Recorded here, where scope.conf is actually read, so the audit record
    # cannot drift from the gate's own view of what was in scope.
    run_record targets "$id"
    url=$(records_field scope "$i" base-url)
    subs=$(records_field_or scope "$i" allow-subdomains false)
    host=$(_host_of_url "$url")
    _attr_add "$host" "$id" "$subs"
    while IFS= read -r h; do
      [[ -n $h ]] || continue
      # extra-host is `host[:port]` (rules/RULE-FORMAT.md §9.4), the same
      # authority grammar http_scope_load feeds through http_url_normalize -
      # scope_split_authority is the shared parser for that grammar (see its
      # ADR above _host_of_url), so a bracketed IPv6 extra-host no longer
      # truncates to "[" here the way it did before this shared helper.
      if scope_split_authority "$h"; then
        _attr_add "$_SAH_HOST" "$id" "$subs"
      fi
    done <<<"$(records_list scope "$i" extra-host)"
  done
}

_attr_add() {
  local host=$1 id=$2 subs=$3
  [[ -n $host ]] || return 0
  if [[ -n ${_ATTR_HOST[$host]:-} ]]; then
    _ATTR_HOST[$host]="${_ATTR_HOST[$host]}"$'\n'"$id"
  else
    _ATTR_HOST[$host]=$id
  fi
  if [[ $subs == true ]]; then
    if [[ -n ${_ATTR_SUBDOMAIN[$id]:-} ]]; then
      _ATTR_SUBDOMAIN[$id]="${_ATTR_SUBDOMAIN[$id]}"$'\n'"$host"
    else
      _ATTR_SUBDOMAIN[$id]=$host
    fi
  fi
}

# ADR: one shared authority (host[:port]) canonicalizer for scope.conf hosts
# Context: a config/scope.conf host feeds two independent readers - the DAST
#   network gate (lib/http.sh http_scope_load -> http_url_normalize) and
#   this file's cloud-finding correlation (attribution_load below) - and
#   this file's own comment on _normalise_host claimed "attribution
#   normalises identically [to the gate] so the two can never disagree".
#   That claim was false: http_url_normalize percent-decodes once, strips
#   userinfo up to the LAST '@', and is bracket-aware for an IPv6 host
#   before splitting off the port; this file's _host_of_url and
#   attribution_load's extra-host loop instead split on the FIRST ':',
#   with no percent-decoding and no userinfo handling.  A bracketed
#   extra-host ("[::1]:8443") truncated to the single byte "[" here; a
#   userinfo-bearing base-url ("https://user@host/") kept "user@host" as
#   the host.  Either one silently breaks correlation for a host the
#   network gate authorises correctly - three call sites (http.sh's
#   authority split, this file's _host_of_url, this file's extra-host
#   loop) computing one conceptual value with two disagreeing on it.
# Decision: scope_split_authority is that one function.  It owns
#   percent-decoding (once), userinfo stripping, and bracket-aware
#   host/port splitting; lib/http.sh's http_url_normalize now calls it
#   too instead of re-implementing the same three steps, then layers its
#   own numeric-literal (octal/hex/decimal IPv4, embedded-IPv4 IPv6)
#   canonicalization on top of the shared result.  It lives in this file,
#   not lib/http.sh, because attribution_load (cloud-only runs) must
#   never require lib/http.sh to be sourced - lib/http.sh already sources
#   this file, never the reverse.
# Alternatives considered: leaving the numeric-literal canonicalization
#   itself out of the shared function - it is deliberate SSRF hardening
#   for a live network call, not needed for a correlation-only lookup,
#   and folding it in here would blur the documented gate-versus-
#   attribution distinction (tension 19: attribution is a correlation
#   attribute, never a fingerprint input and never a gate).
# Consequences: the gate and attribution can no longer silently disagree
#   on what a scope.conf host STRING means; a new decoding/splitting rule
#   is now a one-file change. An operator-authored NUMERIC LITERAL host
#   (SSRF-style spelling) still only canonicalizes on the gate path -
#   attribution can in principle still miss correlating one - which is a
#   narrower, separately tracked gap, not silently "fixed" by this change.
_scope_pct_decode() {
  local s=$1 out='' i=0 c hex
  local len=${#s}
  while (( i < len )); do
    c=${s:i:1}
    if [[ $c == '%' ]] && (( i + 3 <= len )); then
      hex=${s:i+1:2}
      if [[ $hex =~ ^[0-9A-Fa-f][0-9A-Fa-f]$ ]]; then
        # shellcheck disable=SC2059
        out+=$(printf "\\x$hex")
        i=$(( i + 3 ))
        continue
      fi
    fi
    out+=$c
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

# `scope_split_authority AUTHORITY` - percent-decodes once, strips userinfo
# (up to the LAST '@', RFC 3986 - not the first, so `user%40name@evil`,
# which decodes to `user@name@evil`, splits at the right '@'), and splits a
# bracket-aware host[:port].  Sets _SAH_HOST (already lowercased and
# trailing-dot-stripped via _normalise_host), _SAH_PORT (raw, unvalidated -
# callers that care about port range/defaults validate it themselves),
# _SAH_HAD_USERINFO and _SAH_BRACKETED (true when the host was written
# `[...]`, the caller's signal to attempt IPv6 handling).  Returns 1 for an
# empty authority or an empty host after userinfo is stripped; the globals
# are then unreliable and must not be read.
scope_split_authority() {
  local authority=$1
  _SAH_HOST='' _SAH_PORT='' _SAH_HAD_USERINFO=false _SAH_BRACKETED=false
  [[ -n $authority ]] || return 1

  authority=$(_scope_pct_decode "$authority")

  if [[ $authority == *@* ]]; then
    _SAH_HAD_USERINFO=true
    authority=${authority##*@}
  fi

  local host port
  if [[ $authority == \[* ]]; then
    _SAH_BRACKETED=true
    host=${authority#\[}
    host=${host%%]*}
    local after=${authority#*]}
    if [[ $after == :* ]]; then port=${after#:}; else port=''; fi
  elif [[ $authority == *:* ]]; then
    host=${authority%%:*}
    port=${authority#*:}
  else
    host=$authority
    port=''
  fi
  [[ -n $host ]] || return 1

  _SAH_HOST=$(_normalise_host "$host")
  _SAH_PORT=$port
  return 0
}

_host_of_url() {
  local u=$1
  u=${u#*://}
  u=${u%%/*}
  u=${u%%\?*}
  scope_split_authority "$u" || return 0
  printf '%s' "$_SAH_HOST"
}

# The scope gate lowercases the host and strips a trailing dot (tension 19);
# scope_split_authority (above) is what makes attribution normalise
# identically to the gate, by construction rather than by two independently
# maintained implementations agreeing.
_normalise_host() {
  local h=$1
  h=${h,,}
  h=${h%.}
  printf '%s' "$h"
}

# Zero matches: no target value, no participation.  Exactly one: that target id.
# More than one: NO target value, and the ambiguity is a coverage_gap - two
# targets legitimately share a host whenever an operator authors two
# path-scoped targets on one host, which tension 19 explicitly supports, so this
# must not be an error.  Declining to attribute is the same conservative outcome
# as zero matches: guessing a correlation value is worse than not having one.
attribute_target() {
  local matches='' host t id sub
  # shellcheck disable=SC2119
  (( _ATTR_LOADED )) || attribution_load
  for host in "$@"; do
    [[ -n $host ]] || continue
    host=$(_normalise_host "$host")
    if [[ -n ${_ATTR_HOST[$host]:-} ]]; then
      matches+="${_ATTR_HOST[$host]}"$'\n'
    fi
    # allow-subdomains: true additionally matches any host that is a subdomain
    # of one of the target's hosts.  Omitting this would make attribution flip
    # on a flag §9.2.2 never mentions.
    for id in "${!_ATTR_SUBDOMAIN[@]}"; do
      while IFS= read -r sub; do
        [[ -n $sub ]] || continue
        [[ $host == *".$sub" ]] && matches+="$id"$'\n'
      done <<<"${_ATTR_SUBDOMAIN[$id]}"
    done
  done
  [[ -n $matches ]] || return 1
  local uniq
  uniq=$(printf '%s' "$matches" | sort -u)
  local count=0
  while IFS= read -r t; do
    [[ -n $t ]] || continue
    count=$(( count + 1 ))
  done <<<"$uniq"
  if (( count == 1 )); then
    printf '%s' "${uniq//$'\n'/}"
    return 0
  fi
  run_record coverage_gap "cloud finding matched $count scope targets on hosts [$*]; no target correlation value assigned"
  return 1
}

# ---------------------------------------------------------------------------
# 10. The internal field encoding
# ---------------------------------------------------------------------------
# A finding is written twice: as JSON to the shard rules/FOUNDATION tension 17
# names (`shards/<worker-id>.jsonl`, which is durable and is what a resume
# reads), and as one encoded line to a sidecar the merge sorts and the report
# renders from.  The sidecar exists so nothing in this repository has to parse
# JSON in bash.
_enc() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//$'\t'/\\t}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  printf '%s' "$s"
}

# shellcheck disable=SC1003
_dec() {
  local s=$1 out='' i=0 n c
  n=${#s}
  while (( i < n )); do
    c=${s:i:1}
    # shellcheck disable=SC1003
    if [[ $c == '\' ]]; then
      case ${s:i+1:1} in
        t) out+=$'\t'; i=$(( i + 2 )); continue ;;
        n) out+=$'\n'; i=$(( i + 2 )); continue ;;
        r) out+=$'\r'; i=$(( i + 2 )); continue ;;
        '\') out+='\'; i=$(( i + 2 )); continue ;;
      esac
    fi
    out+=$c
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 11. The finding record
# ---------------------------------------------------------------------------
declare -gA _F=()

# The complete field set.  An unknown field is an error rather than a silent
# no-op, because a typo in a module would otherwise drop a fact the rubric or
# the fingerprint reads.
_finding_known_field() {
  case $1 in
    check_id | module | title | severity | base_severity | confidence | cwe | owasp | \
      remediation | evidence | exposure | auth | sensitive_data | cell | status | \
      first_seen | last_seen | suppressed | suppressed_by | rule_digest | logical_kind | \
      logical_fqn | line | url | commit | path | unit_key | \
      loc_path | loc_line | loc_match_digest | loc_occurrence | loc_blob_sha | \
      loc_ecosystem | loc_package | loc_version | loc_advisory_id | loc_target | \
      loc_method | loc_path_template | loc_param_location | loc_param_name | \
      loc_account_id | loc_region | loc_resource_key | loc_sub_key | \
      loc_control_id | loc_scope_key | loc_correlation | \
      corr_target | corr_account | corr_account_region | corr_file | \
      oldest_reaching_commit_time)
      return 0
      ;;
    *) return 1 ;;
  esac
}

_finding_list_field() {
  case $1 in
    references | cis | contributors | derived_into | related | endpoint_hosts) return 0 ;;
    *) return 1 ;;
  esac
}

finding_new() {
  _F=()
  _F[status]=new
  _F[suppressed]=false
  _F[confidence]=medium
  _F[exposure]=unknown
  _F[auth]=user
  _F[sensitive_data]=false
}

# Fields that carry TARGET-DERIVED free text and are therefore redacted at the
# setter.  tension 9 defines redact() as what is written ANYWHERE - "evidence,
# logs, run.json, JSON, SARIF, Markdown, HTML" - and DESIGN §14 says
# redact_secrets scrubs secret-matching patterns from all evidence AND reports.
# Wiring it only into finding_set_evidence left a credential in a crawled URL's
# query string, in a logical name built from target-supplied method and parameter
# data, or in an adapter-supplied title or remediation, written out in the clear.
#
# `path_template` and `param_name` are fingerprint inputs.  Redacting them is
# still stable, because redact() is deterministic - the same bytes in always
# produce the same bytes out - so identity does not churn.
_finding_redacted_field() {
  case $1 in
    title | remediation | url | logical_fqn | loc_path_template | loc_param_name) return 0 ;;
    *) return 1 ;;
  esac
}

finding_set() {
  local k=$1 v=$2
  _finding_known_field "$k" || die "$SCOURSH_EXIT_INCOMPLETE" \
    "finding_set: unknown field '$k'"
  if [[ -n $v ]] && _finding_redacted_field "$k"; then
    findings_ensure_loaded
    v=$(redact "$v")
  fi
  _F[$k]=$v
}

finding_add() {
  local k=$1 v=$2
  _finding_list_field "$k" || die "$SCOURSH_EXIT_INCOMPLETE" \
    "finding_add: '$k' is not a list field"
  if [[ -n ${_F[$k]:-} ]]; then
    _F[$k]="${_F[$k]}"$'\n'"$v"
  else
    _F[$k]=$v
  fi
}

finding_get() { printf '%s' "${_F[$1]:-}"; }

# The ONLY path to the evidence field (tension 9 handling rule 3).
# tests/lint-shell.sh fails on any direct assignment to it.
finding_set_evidence() {
  findings_ensure_loaded
  _F[evidence]=$(evidence_normalise "$1")
}

# The redaction rules, the severity rubric, and the scope attribution map are all
# read inside command substitutions further down.  A lazy load THERE would run in
# a subshell, be thrown away, and re-parse the file for every single finding, so
# they are loaded here, in the caller's shell, exactly once.
findings_ensure_loaded() {
  # shellcheck disable=SC2119
  (( _REDACTION_LOADED )) || redaction_load
  # shellcheck disable=SC2119
  (( _RUBRIC_LOADED )) || rubric_load
  # shellcheck disable=SC2119
  (( _ATTR_LOADED )) || attribution_load
}

# Records the match digest from the RAW matched text.  The raw text is hashed
# and discarded here; it is never stored, never written, and never an argument.
finding_set_match() {
  _F[loc_match_digest]=$(fingerprint_digest "$1")
}

# ---------------------------------------------------------------------------
# 8a. A secrets check never writes the credential it matched (tension 9).
# ---------------------------------------------------------------------------
# redact() masks by SHAPE, from rules/redaction.rules.  That list is maintained
# independently of the secrets checks in modules/*/rules/*.rules, and the two
# drifted: a generic quoted `password = "..."` literal and an uppercase
# `API_KEY = "..."` are matched by secrets.rules and by nothing in
# redaction.rules, so with `redact-secrets: true` in force the raw credential
# was written in the clear into findings.jsonl, findings.json, findings.fields,
# report.md, report.html and the per-worker shards.  Two more shapes - a bare
# `AKIA...` access key id and a lowercase `api_key = "..."` - were masked only
# incidentally, by the PEM-body and Bearer rules, under a `kind` that does not
# describe them.
#
# The fix is PROVENANCE rather than one more pattern: a finding produced by a
# check whose whole purpose is finding a credential never carries that
# credential as evidence, whatever redaction.rules happens to contain.  Adding
# the missing patterns alone would close today's two holes and leave the
# mechanism that produced them - two lists that must agree and have no way to
# notice when they stop agreeing - exactly as it was.
#
# rules/redaction.rules is still wanted, and still applies: it is what masks a
# credential that turns up INCIDENTALLY, in some other check's evidence, in a
# crawled URL, or in an adapter-supplied title.  The two layers answer different
# questions and neither subsumes the other.

# The canonical "is this check id one whose match IS a credential" predicate.
# modules/sast/engine.sh's `_sast_check_is_sensitive` - which modules/iac,
# modules/sast/history.sh and the semgrep and trivy adapters all already reuse -
# delegates here, so there is ONE list rather than a second one to drift against
# the first.
#
# The id is upper-cased first because an adapter mints its check id from the
# engine's own rule id (docs/ADAPTERS.md §6, `<engine>:<engine's own rule id>`)
# and those are conventionally lower case.
#
# `gitleaks:` gets an arm of its own because gitleaks is a secrets-only scanner:
# every finding it produces is a credential by the engine's own purpose, and
# none of its rule ids (`aws-access-token`, `stripe-access-token`, ...) contains
# any of the substrings below.  semgrep and trivy get no such arm, because they
# are general-purpose and their non-secret rules must keep their evidence.
#
# `*-SEC-*` is the NAMESPACE arm, and it is here because the substring list
# below is a list maintained in parallel with modules/sast/rules/secrets.rules -
# which is the exact failure mode this whole section exists to end, reappearing
# one level up.  It did reappear: secrets.rules gained
# `SAST-SEC-ENV_ASSIGNMENT-01`, whose id contains none of those substrings
# (`SEC-ENV` is not `SECRET`), so four of its findings wrote the matched
# credential in the clear into findings.jsonl, findings.json, findings.fields,
# report.md, report.html and both shards - measured on
# tests/fixtures/sast-secret-forms/, and NOT caught by the shape layer either,
# because `passwd: x`, `API_KEY: x` and `DB_PASSWORD = x` are unquoted,
# colon-separated or spaced and match no rule in rules/redaction.rules.
#
# `SAST-SEC-` is that pack's own id namespace, so keying on it covers the next
# check the pack adds on the DAY IT LANDS rather than the day somebody remembers
# to widen a glob here.  It is checked rather than assumed to be narrow: across
# all 157 check ids shipped in this repository, `-SEC-` matches those seven and
# nothing else - no `DAST-COOKIE-NO_SECURE-01`, no `IAC-*-HARDCODED_SECRET-01`
# (those already match `*SECRET*` on their own and are unaffected).
finding_check_is_secret_family() {
  local id=${1^^}
  case $id in
    GITLEAKS:*) return 0 ;;
    *-SEC-*) return 0 ;;
    *SECRET* | *PRIVATE_KEY* | *API_KEY* | *PASSWORD* | *AKID* | *JWT*) return 0 ;;
    *) return 1 ;;
  esac
}

# True when a string is already exactly one redaction placeholder, so the
# backstop below can leave alone what redact() has already handled.
#
# Deliberately globs rather than using `[[ =~ ]]`: bash's `=~` goes to the
# system regcomp, and `\<` - the obvious way to anchor the literal `<` - is a
# GNU word-start extension there, so the pattern would mean something different
# on the BSD userland this tool is developed on than on the GNU one it reaches
# Windows through.  Neither a KIND nor a digest can contain `<` or `>`, so
# "starts with the prefix, ends with `>`, and has no other `>`" identifies
# exactly one placeholder and nothing else.
_finding_is_redaction_placeholder() {
  local s=$1
  [[ $s == '<redacted:'*'>' ]] || return 1
  [[ ${s%'>'} != *'>'* ]]
}

# The masked rendering: the same `<redacted:KIND:DDDDDDDD>` vocabulary redact()
# already emits, with the same short-digest property, so a report speaks one
# language whichever layer masked a given string.  The digest is the first eight
# hex characters of the SHA-256 of the RAW bytes, which is what lets a reader
# tell two secrets apart and recognise one secret across three findings without
# the secret being present (rules/redaction.rules' own header states the trade).
_finding_secret_placeholder() {
  local d
  d=$(printf '%s' "$1" | sha256_of)
  printf '<redacted:SECRET:%s>' "${d:0:8}"
}

# `finding_set_secret_match TEXT` - the setter for an emitter whose TEXT is a
# raw credential the scan just matched.  It does what finding_set_match and
# finding_set_evidence do together, except that the raw bytes never reach
# evidence while `redact-secrets` is on.
#
# loc_match_digest is computed EXACTLY as finding_set_match computes it, from
# the raw bytes.  That is load-bearing rather than incidental:
# modules/sast/adapters/gitleaks/adapter.sh dedups a gitleaks finding against a
# native secrets.rules finding by comparing loc_match_digest at the same path,
# so digesting the masked text here would silently defeat that dedup.
#
# With `redact-secrets: false` the raw text is written, exactly as it is today.
# That is the declared meaning of the setting rather than a leftover of one code
# path serving both: an operator rotating a credential has to be able to ask for
# the literal bytes.  run.json records `redact_secrets: false`, and report.md
# and report.html both carry a warning banner, so an unredacted report can never
# be mistaken for a redacted one.
#
# Evidence is set through finding_set_evidence in BOTH arms, never by assigning
# _F[evidence] here: that is the invariant tests/lint-shell.sh's "no direct
# assignment to a redacted field" check enforces over this very file, and a
# second way to write the field is what tension 9's handling rule 3 exists to
# prevent.  Normalising the placeholder costs one no-op pass - no redaction rule
# matches it, and it is short, control-free ASCII.
finding_set_secret_match() {
  local text=$1
  _F[loc_match_digest]=$(fingerprint_digest "$text")
  _F[_secret_match]=1
  if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
    finding_set_evidence "$text"
    return 0
  fi
  finding_set_evidence "$(_finding_secret_placeholder "$text")"
}

# The backstop, called from finding_emit - the ONE point every finding passes
# through on its way to a shard, and therefore to every format downstream of the
# merge, including a SARIF emitter that does not exist yet.  An emitter that
# reaches for the ordinary finding_set_evidence with a credential in hand is
# masked here anyway.
#
# The module condition is the load-bearing one, and it is an invariant rather
# than a convenience: in `sast` and `iac`, evidence is BY CONSTRUCTION the raw
# bytes matched in a file, so a secrets-family check's evidence is its
# credential.  In `dast` it is a composed sentence - lib/paranoid.sh's egress
# finding puts the observed destination there, and modules/dast/jwt_engine.sh
# puts its one actionable sentence there under ids like `DAST-JWT-ALG_NONE`,
# which match the *JWT* arm above.  Masking those would destroy the finding and
# hide no credential.
#
# `sensitive_data` deliberately does NOT gate this.  It would have read as the
# natural third condition, and it is the wrong one twice over: lib/http.sh and
# lib/paranoid.sh set it on findings whose evidence is a destination address,
# and a future sast emitter that forgot the secret setter would most likely
# forget this flag in the same breath - so gating on it would switch the net off
# in exactly the case the net exists for.  Erring towards masking is the trade
# rules/redaction.rules' own header already states: over-redaction costs a
# reader some evidence, under-redaction discloses a credential.
_finding_secret_backstop() {
  [[ $SCOURSH_REDACT_SECRETS == true ]] || return 0
  [[ -z ${_F[_secret_match]:-} ]] || return 0
  [[ -n ${_F[evidence]:-} ]] || return 0
  case ${_F[module]:-} in
    sast | iac) ;;
    *) return 0 ;;
  esac
  finding_check_is_secret_family "${_F[check_id]:-}" || return 0
  if _finding_is_redaction_placeholder "${_F[evidence]}"; then
    return 0
  fi
  finding_set_evidence "$(_finding_secret_placeholder "${_F[evidence]}")"
  return 0
}

# Populate a rule-derived finding's static fields from a parsed record.
finding_from_record() {
  local set=$1 idx=$2
  finding_set check_id "$(records_id "$set" "$idx")"
  finding_set title "$(records_field "$set" "$idx" title)"
  finding_set base_severity "$(records_field "$set" "$idx" severity)"
  finding_set confidence "$(records_field_or "$set" "$idx" confidence medium)"
  finding_set cwe "$(records_field "$set" "$idx" cwe)"
  finding_set owasp "$(records_field "$set" "$idx" owasp)"
  finding_set remediation "$(records_field "$set" "$idx" remediation)"
  finding_set rule_digest "$(records_digest "$set" "$idx")"
  local v
  while IFS= read -r v; do
    [[ -n $v ]] || continue
    finding_add references "$v"
  done <<<"$(records_list "$set" "$idx" references)"
  while IFS= read -r v; do
    [[ -n $v ]] || continue
    finding_add cis "$v"
  done <<<"$(records_list "$set" "$idx" cis)"
  _F[_severity_floor]=$(records_field_or "$set" "$idx" severity-floor '')
  _F[_severity_ceiling]=$(records_field_or "$set" "$idx" severity-ceiling '')
}

# ---------------------------------------------------------------------------
# 12. Emitting
# ---------------------------------------------------------------------------
# The first fingerprint component is NOT simply the `module` field.
#
# tension 6 freezes the composite's identity as
#   sha256( "fp/1" \0 "composite" \0 check_id \0 correlation_value )
# with "composite" spelled out, while the emitted `module` field is `derived` -
# which is what tension 5's table row is LABELLED and what the report groups by.
# Those are two different things, and putting the module field in the frozen
# slot hashed `derived` and silently produced an identity no conformant
# implementation would agree with.  That matters more than it looks: composite
# fingerprints are persisted into `state/` and `config/baseline.json`, so a
# baseline written by a conformant implementation would suppress nothing, and
# correcting it after release costs an fp_schema bump and a full-backlog churn.
_fp_module_token() {
  case $1 in
    derived) printf '%s' 'composite' ;;
    *) printf '%s' "$1" ;;
  esac
}

finding_fingerprint() {
  local module=${_F[module]} check_id=${_F[check_id]}
  local profile comp
  profile=$(_fp_profile_for "$module" "$check_id") \
    || die "$SCOURSH_EXIT_INCOMPLETE" "no fingerprint profile for module '$module'"
  local -a parts=("$(_fp_module_token "$module")" "$check_id")
  while IFS= read -r comp; do
    [[ -n $comp ]] || continue
    parts+=("${_F[loc_$comp]:-}")
  done <<<"$(_fp_components_for "$profile")"
  fingerprint_compute "${parts[@]+"${parts[@]}"}"
}

# tension 22 / SARIF-01: a profile-driven default logical identity, computed
# ONCE here rather than by each of the ~30 emitting scripts - the same "a
# control every caller must remember is not a control" argument AGENTS.md
# already makes for dast_check_selected and dast_auth_apply.  Applied only
# when the emitter has not already set logical_kind, so modules/sca/,
# modules/iac/ and the derived composite path (which all set their own
# identity before finding_emit runs) keep it unchanged.
#
# logical_kind/logical_fqn are deliberately absent from _fp_components_for for
# every profile above, so nothing here can move a fingerprint - and the
# reverse must stay true too: this function must never assign to a field that
# IS a fingerprint component (e.g. loc_target, loc_path), only to
# logical_kind/logical_fqn themselves.
#
# fqn goes through finding_set, not a direct _F[] assignment, because
# logical_fqn is a _finding_redacted_field (tension 9): a dast fqn is built
# from target-supplied method and parameter data and must be redacted exactly
# as it is today.
_finding_default_logical() {
  local profile=$1
  [[ -z ${_F[logical_kind]:-} ]] || return 0
  case $profile in
    path | history)
      finding_set logical_kind file
      finding_set logical_fqn "${_F[loc_path]:-}:${_F[loc_line]:-}"
      ;;
    dast)
      finding_set logical_kind endpoint
      finding_set logical_fqn \
        "${_F[loc_target]:-}:${_F[loc_method]:-} ${_F[loc_path_template]:-}#${_F[loc_param_name]:-}"
      ;;
    cloud)
      finding_set logical_kind resource
      finding_set logical_fqn "${_F[loc_resource_key]:-}"
      ;;
    posture)
      finding_set logical_kind control
      finding_set logical_fqn "${_F[loc_control_id]:-}"
      ;;
    # sca and derived always set their own logical identity before
    # finding_emit is called (modules/sca/, the composite path in this file) -
    # nothing to default.
  esac
}

finding_emit() {
  findings_ensure_loaded
  local k
  for k in check_id module title base_severity cwe owasp; do
    [[ -n ${_F[$k]:-} ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
      "finding_emit: required field '$k' is unset"
  done
  [[ -n ${SCOURSH_RUN_DIR:-} ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "finding_emit: no run directory (call run_init first)"

  # Before anything is serialised: a secrets check never writes the credential
  # it matched, even if its emitter reached for the ordinary
  # finding_set_evidence (section 8a).
  _finding_secret_backstop

  local profile
  profile=$(_fp_profile_for "${_F[module]}" "${_F[check_id]}")

  # The occurrence ordinal is computed HERE and never by a module, so two
  # conformant call sites cannot disagree about it (tension 5).
  if _fp_profile_needs_occurrence "$profile" && [[ -z ${_F[loc_occurrence]:-} ]]; then
    local unit
    unit=$(_occurrence_unit_for "$profile")
    occurrence_next "$unit" "${_F[check_id]}" "${_F[loc_match_digest]:-}"
    _F[loc_occurrence]=$OCCURRENCE_RESULT
  fi
  if [[ $profile == dast && -z ${_F[loc_path_template]:-} && -n ${_F[path]:-} ]]; then
    _F[loc_path_template]=$(path_template_of "${_F[path]}")
  fi

  # The rubric ALWAYS runs (tension 8).
  _F[severity]=$(severity_final "${_F[base_severity]}" "${_F[exposure]}" "${_F[auth]}" \
    "${_F[sensitive_data]}" "${_F[confidence]}" "${_F[_severity_floor]:-}" "${_F[_severity_ceiling]:-}")
  local vector
  vector=$(cvss_vector_of "${_F[exposure]}" "${_F[auth]}" "${_F[sensitive_data]}" "${_F[confidence]}")
  _F[_cvss_vector]=$vector
  _F[_cvss_score]=$(cvss_score_of "$vector")

  _finding_fill_correlation "$profile"

  : "${_F[first_seen]:=${SCOURSH_RUN_TIMESTAMP:-$(now_iso)}}"
  : "${_F[last_seen]:=${SCOURSH_RUN_TIMESTAMP:-$(now_iso)}}"
  _finding_default_logical "$profile"
  _F[fingerprint]=$(finding_fingerprint)

  local shard
  worker_id_set
  shard=$SCOURSH_RUN_DIR/shards/$SCOURSH_WORKER_ID
  _finding_json >>"$shard.jsonl"
  printf '\n' >>"$shard.jsonl"
  _finding_fields >>"$shard.fields"
  printf '\n' >>"$shard.fields"
  return 0
}

_finding_fill_correlation() {
  local profile=$1
  case $profile in
    path | history)
      : "${_F[corr_file]:=${_F[loc_path]:-}}"
      ;;
    sca)
      : "${_F[corr_file]:=${_F[path]:-}}"
      ;;
    dast)
      : "${_F[corr_target]:=${_F[loc_target]:-}}"
      ;;
    cloud)
      : "${_F[corr_account]:=${_F[loc_account_id]:-}}"
      if [[ -n ${_F[loc_account_id]:-} && -n ${_F[loc_region]:-} ]]; then
        : "${_F[corr_account_region]:=${_F[loc_account_id]}/${_F[loc_region]}}"
      fi
      if [[ -z ${_F[corr_target]:-} && -n ${_F[endpoint_hosts]:-} ]]; then
        local -a hosts=()
        local h
        while IFS= read -r h; do
          [[ -n $h ]] || continue
          hosts+=("$h")
        done <<<"${_F[endpoint_hosts]}"
        local t
        if t=$(attribute_target "${hosts[@]+"${hosts[@]}"}"); then
          _F[corr_target]=$t
        fi
      fi
      ;;
    posture)
      local sk=${_F[loc_scope_key]:-}
      case $sk in
        */*) : "${_F[corr_account_region]:=$sk}"; : "${_F[corr_account]:=${sk%%/*}}" ;;
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) : "${_F[corr_account]:=$sk}" ;;
        ?*) : "${_F[corr_target]:=$sk}" ;;
      esac
      ;;
  esac
}

# Fixed key order, so two runs of the same scan produce byte-identical JSON.
_finding_json() {
  local profile comp
  profile=$(_fp_profile_for "${_F[module]}" "${_F[check_id]}")
  printf '{'
  printf '"check_id":%s' "$(json_string "${_F[check_id]}")"
  printf ',"module":%s' "$(json_string "${_F[module]}")"
  printf ',"title":%s' "$(json_string "${_F[title]}")"
  printf ',"severity":%s' "$(json_string "${_F[severity]}")"
  printf ',"base_severity":%s' "$(json_string "${_F[base_severity]}")"
  printf ',"confidence":%s' "$(json_string "${_F[confidence]}")"
  printf ',"cwe":%s' "$(json_string "${_F[cwe]}")"
  printf ',"owasp":%s' "$(json_string "${_F[owasp]}")"
  printf ',"cvss":{"vector":%s,"score":%s}' \
    "$(json_string "${_F[_cvss_vector]}")" "$(json_number "${_F[_cvss_score]}")"
  printf ',"location":{'
  local first=1
  while IFS= read -r comp; do
    [[ -n $comp ]] || continue
    (( first )) || printf ','
    first=0
    printf '%s:%s' "$(json_string "$comp")" "$(json_string "${_F[loc_$comp]:-}")"
  done <<<"$(_fp_components_for "$profile")"
  if [[ -n ${_F[loc_line]:-} ]]; then
    (( first )) || printf ','
    first=0
    printf '"line":%s' "$(json_number "${_F[loc_line]}")"
  fi
  if [[ -n ${_F[url]:-} ]]; then
    (( first )) || printf ','
    printf '"url":%s' "$(json_string "${_F[url]}")"
  fi
  printf '}'
  printf ',"logical":{"kind":%s,"fqn":%s}' \
    "$(json_string "${_F[logical_kind]:-}")" "$(json_string "${_F[logical_fqn]:-}")"
  printf ',"evidence":%s' "$(json_string "${_F[evidence]:-}")"
  printf ',"remediation":%s' "$(json_string "${_F[remediation]:-}")"
  _json_list references
  _json_list cis
  printf ',"exposure":%s' "$(json_string "${_F[exposure]}")"
  printf ',"auth":%s' "$(json_string "${_F[auth]}")"
  printf ',"sensitive_data":%s' "$(json_bool "${_F[sensitive_data]}")"
  if [[ -n ${_F[cell]+set} ]]; then
    printf ',"cell":%s' "$(json_string "${_F[cell]}")"
  else
    printf ',"cell":null'
  fi
  printf ',"status":%s' "$(json_string "${_F[status]}")"
  printf ',"first_seen":%s' "$(json_string "${_F[first_seen]}")"
  printf ',"last_seen":%s' "$(json_string "${_F[last_seen]}")"
  printf ',"suppressed":%s' "$(json_bool "${_F[suppressed]}")"
  printf ',"suppressed_by":%s' \
    "$(if [[ -n ${_F[suppressed_by]:-} ]]; then json_string "${_F[suppressed_by]}"; else printf 'null'; fi)"
  _json_list contributors
  _json_list derived_into
  _json_list related
  _json_list endpoint_hosts
  printf ',"rule_digest":%s' "$(json_string "${_F[rule_digest]:-}")"
  printf ',"fingerprint":%s' "$(json_string "${_F[fingerprint]}")"
  printf '}'
}

_json_list() {
  local k=$1 v first=1
  printf ',%s:[' "$(json_string "$k")"
  if [[ -n ${_F[$k]:-} ]]; then
    while IFS= read -r v; do
      [[ -n $v ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s' "$(json_string "$v")"
    done <<<"${_F[$k]}"
  fi
  printf ']'
}

# The key order is sorted, not the associative array's iteration order, so two
# runs of the same scan produce byte-identical shard files on any bash build.
_finding_fields() {
  local k first=1
  while IFS= read -r k; do
    [[ -n $k ]] || continue
    [[ $k == _* ]] && continue
    (( first )) || printf '\t'
    first=0
    printf '%s=%s' "$k" "$(_enc "${_F[$k]}")"
  done <<<"$(_sorted_keys_of_F)"
  printf '\t_cvss_vector=%s\t_cvss_score=%s' "$(_enc "${_F[_cvss_vector]}")" "${_F[_cvss_score]}"
}

_sorted_keys_of_F() {
  (( ${#_F[@]} > 0 )) || return 0
  printf '%s\n' "${!_F[@]}" | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 13. Reading a merged finding back
# ---------------------------------------------------------------------------
# Decoded findings land in the dedicated global _DF.  Namerefs (`local -n`) are
# deliberately not used anywhere in this repository: `declare -n` arrived in bash
# 4.3 and tension 24 freezes the minimum interpreter at 4.2.
declare -gA _DF=()

finding_decode() {
  local line=$1 pair k v
  _DF=()
  while IFS= read -r pair; do
    [[ -n $pair ]] || continue
    k=${pair%%=*}
    v=${pair#*=}
    _DF[$k]=$(_dec "$v")
  done <<<"${line//$'\t'/$'\n'}"
}

# Copy the last decoded finding into the current-finding slot, so the JSON
# emitter can render it.
finding_adopt_decoded() {
  local k
  _F=()
  (( ${#_DF[@]} > 0 )) || return 0
  for k in "${!_DF[@]}"; do
    _F[$k]=${_DF[$k]}
  done
}

# ---------------------------------------------------------------------------
# 14. Merge (tension 17, and tension 11 step 3)
# ---------------------------------------------------------------------------
# Each worker writes only to its own shard, so no locking is needed: there is no
# sharing.  At end of run the shards are merged, sorted by
# (module, check_id, fingerprint) under LC_ALL=C.  Sorting is not cosmetic: it
# makes the output byte-reproducible across runs regardless of scheduling, which
# is what §4's audit-record claim needs.  The sort key is total because the
# fingerprint is unique within a run, which holds only because tension 5's
# location components carry an `occurrence` discriminator.
findings_merge() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  local tmp=$SCOURSH_SCRATCH/merge.$$
  : >"$tmp"
  local shard
  for shard in "$rundir"/shards/*.fields; do
    [[ -e $shard ]] || continue
    _merge_shard "$shard" >>"$tmp"
  done
  _findings_sort_and_dedup "$tmp" "$rundir/findings.fields"
  rm -f "$tmp"
}

# Emits `module \t check_id \t fingerprint \t <encoded line>` for sorting.
_merge_shard() {
  local line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\t%s\t%s\t%s\n' "${_DF[module]}" "${_DF[check_id]}" "${_DF[fingerprint]}" "$line"
  done <"$1"
}

_findings_sort_and_dedup() {
  local keyed=$1 out=$2
  local sorted=$SCOURSH_SCRATCH/sorted.$$
  LC_ALL=C sort -t$'\t' -k1,1 -k2,2 -k3,3 "$keyed" >"$sorted"
  # Dedup on fingerprint: a merge of ONE finding seen by two engines, not a
  # collapse of distinct occurrences (tension 11 step 3).  Fingerprints are
  # unique per occurrence, so an equal pair here is a genuine duplicate.
  local prev='' m c fp rest dups=0
  : >"$out"
  while IFS=$'\t' read -r m c fp rest; do
    [[ -n $fp ]] || continue
    if [[ $fp == "$prev" ]]; then
      dups=$(( dups + 1 ))
      continue
    fi
    prev=$fp
    printf '%s\n' "$rest" >>"$out"
  done <"$sorted"
  (( dups == 0 )) || run_record merged_duplicates "$dups"
  rm -f "$sorted"
}

# Re-sort an already-merged findings.fields in place, used after derived
# findings are appended so every artifact of the run shares one order.
_findings_resort() {
  local file=$1
  local keyed=$SCOURSH_SCRATCH/resort.$$
  _merge_shard "$file" >"$keyed"
  _findings_sort_and_dedup "$keyed" "$file"
  rm -f "$keyed"
}

# findings.jsonl, regenerated from the merged, sorted, deduped set so its order
# matches every other artifact of the run.
findings_write_jsonl() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  local line
  : >"$rundir/findings.jsonl"
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    finding_adopt_decoded
    _finding_json >>"$rundir/findings.jsonl"
    printf '\n' >>"$rundir/findings.jsonl"
  done <"$rundir/findings.fields"
}

findings_write_json() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  local line first=1
  {
    printf '{"fp_schema":%s,"uk_schema":%s,"findings":[' \
      "$(json_string "$FP_SCHEMA")" "$(json_string "$UK_SCHEMA")"
    if [[ -s $rundir/findings.fields ]]; then
      while IFS= read -r line; do
        [[ -n $line ]] || continue
        (( first )) || printf ','
        first=0
        printf '\n  '
        finding_decode "$line"
        finding_adopt_decoded
        _finding_json
      done <"$rundir/findings.fields"
      printf '\n'
    fi
    printf ']}\n'
  } >"$rundir/findings.json"
}

# Suppression is a late ANNOTATION and NEVER a deletion (tension 11 step 6),
# which is what makes removing a baseline entry unable to manufacture a `new`
# finding and lets a baselined finding still be reported `fixed`.
# The baseline reader that decides WHICH fingerprints to mark is §13 step 7;
# this is the primitive it will call.
findings_mark_suppressed() {
  local rundir=$1 fingerprint=$2 reason=$3
  local tmp=$SCOURSH_SCRATCH/suppress.$$ line
  : >"$tmp"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    if [[ ${_DF[fingerprint]} == "$fingerprint" ]]; then
      _DF[suppressed]=true
      _DF[suppressed_by]=$reason
      _reencode_decoded >>"$tmp"
      printf '\n' >>"$tmp"
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$rundir/findings.fields"
  mv "$tmp" "$rundir/findings.fields"
}

findings_count() {
  local rundir=${1:-$SCOURSH_RUN_DIR} n=0 line
  [[ -s $rundir/findings.fields ]] || { printf '%s' 0; return 0; }
  while IFS= read -r line; do
    [[ -n $line ]] && n=$(( n + 1 ))
  done <"$rundir/findings.fields"
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# 15. Derived / composite findings (tension 6)
# ---------------------------------------------------------------------------
# Evaluated exactly once, after all modules have completed and after native and
# adapter results are merged and deduped, and BEFORE baseline suppression, diff
# classification, and state persistence.
#
# Because evaluation is before suppression, baselining a contributor does not
# silently destroy the composite; because it is before classification, the
# composite participates in new / recurring / fixed like any other finding.
#
# FIRING NEEDS NO COVERAGE TEST AT ALL.  A composite fires, this run, for every
# correlation value where its requires/any-of predicate holds over the findings
# actually present.  If the contributors are there, the chain is real, whatever
# else the run did or did not visit.  Classification is a separate operation with
# separate rules (classify_derived below); conflating the two is what produces
# phantom remediation.
derive_findings() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  local derived_file=${2:-$SCOURSH_INSTALL_ROOT/rules/derived.rules}
  [[ -r $derived_file ]] || return 0
  records_load "$derived_file" derived derivedset || die "$SCOURSH_EXIT_INPUT" \
    "$derived_file failed to parse"
  local n
  n=$(records_count derivedset)
  (( n > 0 )) || return 0

  # Index this run's findings by (check_id, correlation key, correlation value).
  _DERIVE_PRESENT=()
  _DERIVE_SEV=()
  local line ck ckey cv key
  if [[ -s $rundir/findings.fields ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      ck=${_DF[check_id]}
      _DERIVE_SEV[${_DF[fingerprint]}]=$(severity_rank "${_DF[severity]}")
      for ckey in none target account account-region file; do
        cv=$(_corr_value_of "$ckey")
        [[ -n $cv ]] || continue
        key="$ck|$ckey|$cv"
        if [[ -n ${_DERIVE_PRESENT[$key]:-} ]]; then
          _DERIVE_PRESENT[$key]="${_DERIVE_PRESENT[$key]}"$'\n'"${_DF[fingerprint]}"
        else
          _DERIVE_PRESENT[$key]=${_DF[fingerprint]}
        fi
      done
    done <"$rundir/findings.fields"
  fi

  # Composites go into their own shard, so appending them to the merged set
  # cannot re-append this worker's ordinary findings.
  local saved_unit=${SCOURSH_UNIT_INDEX:-0}
  SCOURSH_UNIT_INDEX=derived
  worker_id_set
  local wid=$SCOURSH_WORKER_ID
  rm -f "$rundir/shards/$wid.fields" "$rundir/shards/$wid.jsonl"

  _DERIVE_BACKREF=()
  local i
  for (( i = 0; i < n; i++ )); do
    _derive_one "$rundir" "$i"
  done
  SCOURSH_UNIT_INDEX=$saved_unit

  if [[ -s $rundir/shards/$wid.fields ]]; then
    cat "$rundir/shards/$wid.fields" >>"$rundir/findings.fields"
    _findings_resort "$rundir/findings.fields"
    _derived_apply_back_references "$rundir"
  fi
}

declare -gA _DERIVE_PRESENT=()
declare -gA _DERIVE_SEV=()
declare -gA _DERIVE_BACKREF=()

# The correlation value of the last decoded finding, for one correlation key.
_corr_value_of() {
  case $1 in
    none) printf '%s' 'none' ;;
    target) printf '%s' "${_DF[corr_target]:-}" ;;
    account) printf '%s' "${_DF[corr_account]:-}" ;;
    account-region) printf '%s' "${_DF[corr_account_region]:-}" ;;
    file) printf '%s' "${_DF[corr_file]:-}" ;;
  esac
}

_derive_one() {
  local rundir=$1 ridx=$2
  local id corr
  id=$(records_id derivedset "$ridx")
  corr=$(records_field derivedset "$ridx" correlate-on)

  # Every correlation value any contributor supplied.  `correlate-on: none`
  # means the composite fires at most once per run.
  local -a values=()
  local -A seen=()
  local c v k
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    (( ${#_DERIVE_PRESENT[@]} > 0 )) || break
    for k in "${!_DERIVE_PRESENT[@]}"; do
      [[ $k == "$c|$corr|"* ]] || continue
      v=${k#"$c|$corr|"}
      if [[ -z ${seen[$v]:-} ]]; then
        seen[$v]=1
        values+=("$v")
      fi
    done
  done <<<"$(_derived_contributors "$ridx")"

  local val
  for val in "${values[@]+"${values[@]}"}"; do
    _derive_fire "$rundir" "$ridx" "$corr" "$val"
  done
}

_derived_contributors() {
  records_list derivedset "$1" requires
  printf '\n'
  records_list derivedset "$1" any-of
}

_derive_fire() {
  local rundir=$1 ridx=$2 corr=$3 val=$4
  local c ok=1 anyok=0 anycount=0 fp
  local -a contributors=()

  # requires: ALL listed checks must have produced at least one finding this run
  # for this correlation value.
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    if [[ -n ${_DERIVE_PRESENT["$c|$corr|$val"]:-} ]]; then
      while IFS= read -r fp; do
        [[ -n $fp ]] && contributors+=("$fp")
      done <<<"${_DERIVE_PRESENT["$c|$corr|$val"]}"
    else
      ok=0
    fi
  done <<<"$(records_list derivedset "$ridx" requires)"
  (( ok )) || return 0

  # any-of: AT LEAST ONE listed check must have produced a finding this run.
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    anycount=$(( anycount + 1 ))
    if [[ -n ${_DERIVE_PRESENT["$c|$corr|$val"]:-} ]]; then
      anyok=1
      while IFS= read -r fp; do
        [[ -n $fp ]] && contributors+=("$fp")
      done <<<"${_DERIVE_PRESENT["$c|$corr|$val"]}"
    fi
  done <<<"$(records_list derivedset "$ridx" any-of)"
  if (( anycount > 0 && anyok == 0 )); then return 0; fi
  (( ${#contributors[@]} > 0 )) || return 0

  finding_new
  finding_from_record derivedset "$ridx"
  finding_set module derived
  finding_set loc_correlation "$val"
  finding_set logical_kind composite
  finding_set confidence "$(records_field_or derivedset "$ridx" confidence high)"
  finding_set logical_fqn "${_F[check_id]}@$val"
  # A derived finding has NO coverage cell; its persisted cell is JSON null,
  # never the string "none", because "none" is a legal path-root and a legal
  # scope target id and a string sentinel could collide with either (tension 12).
  unset '_F[cell]'

  # Severity: the record's declared severity is the base, then it is clamped
  # UPWARD to the highest final severity among its contributors, then the
  # standard rubric runs.  A roll-up can never be less severe than its worst
  # part.
  local best r
  best=$(severity_rank "${_F[base_severity]}")
  for fp in "${contributors[@]+"${contributors[@]}"}"; do
    r=${_DERIVE_SEV[$fp]:-0}
    (( r > best )) && best=$r
  done
  finding_set base_severity "$(severity_name "$best")"

  # Contributor fingerprints are deliberately NOT in the identity: they are
  # recorded in the body as evidence.  That is what makes the diff behave - the
  # composite keeps one stable identity across runs even as the contributing
  # evidence shifts, so a reader sees "this chain is still open" rather than a
  # churn of new and fixed.
  local -A added=()
  local composite_id
  composite_id=$(records_id derivedset "$ridx")
  for fp in "${contributors[@]+"${contributors[@]}"}"; do
    [[ -n ${added[$fp]:-} ]] && continue
    added[$fp]=1
    finding_add contributors "$fp"
    if [[ -n ${_DERIVE_BACKREF[$fp]:-} ]]; then
      _DERIVE_BACKREF[$fp]="${_DERIVE_BACKREF[$fp]}"$'\n'"$composite_id"
    else
      _DERIVE_BACKREF[$fp]=$composite_id
    fi
  done
  finding_set_evidence "correlated on $corr=$val over ${#added[@]} contributing findings"
  finding_emit
}

# Each contributing finding gains a back-reference `derived_into`; contributors
# are retained as findings in their own right rather than being absorbed.
# Applied in one pass over the merged set rather than one pass per contributor.
_derived_apply_back_references() {
  local rundir=$1
  (( ${#_DERIVE_BACKREF[@]} > 0 )) || return 0
  local tmp=$SCOURSH_SCRATCH/backref.$$
  local line fp c
  : >"$tmp"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    fp=${_DF[fingerprint]}
    if [[ -n ${_DERIVE_BACKREF[$fp]:-} ]]; then
      while IFS= read -r c; do
        [[ -n $c ]] || continue
        if [[ -n ${_DF[derived_into]:-} ]]; then
          _DF[derived_into]="${_DF[derived_into]}"$'\n'"$c"
        else
          _DF[derived_into]=$c
        fi
      done <<<"${_DERIVE_BACKREF[$fp]}"
      _reencode_decoded >>"$tmp"
      printf '\n' >>"$tmp"
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$rundir/findings.fields"
  mv "$tmp" "$rundir/findings.fields"
}

_reencode_decoded() {
  local k first=1
  while IFS= read -r k; do
    [[ -n $k ]] || continue
    (( first )) || printf '\t'
    first=0
    printf '%s=%s' "$k" "$(_enc "${_DF[$k]}")"
  done <<<"$(_sorted_keys_of_DF)"
}

_sorted_keys_of_DF() {
  (( ${#_DF[@]} > 0 )) || return 0
  printf '%s\n' "${!_DF[@]}" | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 16. Classifying a prior composite that did not fire this run (tension 6)
# ---------------------------------------------------------------------------
# `classify_derived CHECK_ID CORRELATION FIRED PRIOR_CONTRIBUTORS
#                   PRIOR_STATE_FILE COVERED_THIS_RUN_FILE PRIOR_COVERED_FILE
#                   THIS_RUN_OLDEST_COMMIT_TIME`
#
# Prints `fixed` or `unknown` (with a reason on the second field).
#
# A prior composite is `fixed` only if ALL THREE hold; if any fails it is
# `unknown`:
#
#   (a) the composite's own record was selected and evaluated this run;
#   (b) every check named in `requires` and `any-of` is covered this run, judged
#       per (b1)/(b2);
#   (c) the predicate no longer holds.
#
# Each exists because leaving it out produces a false `fixed`.
#
# Input formats, all line-oriented so this function stays pure and testable
# before §13 step 7 writes state/:
#   PRIOR_STATE_FILE     fingerprint \t check_id \t cell \t oldest_reaching_commit_time
#   COVERED_THIS_RUN     check_id \t cell
#   PRIOR_COVERED        check_id \t cell
classify_derived() {
  local check_id=$1 correlation=$2 fired=$3 prior_contributors=$4
  local prior_state=$5 covered_now=$6 covered_prior=$7 oldest_commit_time=${8:-}

  # (a) Own selection.  A composite has no coverage cell, so tension 12's
  # (check, cell) test cannot protect it, and nothing else asks whether the
  # composite record itself survived tension 15's filter chain.  It still can
  # not: `--profile-scan quick` drops any composite with no `quick` tag, and
  # `--allow-intrusive` off drops one tagged `intrusive` (lib/checks.sh
  # exempts `derived` from the --intensity ceiling specifically - finding F8 -
  # so --intensity alone no longer does this, but the other two filters
  # still can).  Without (a), `scan.sh all` followed by
  # `scan.sh all --profile-scan quick` classifies the flagship composite
  # `fixed (chain broken)` with all three contributors still present and the
  # chain fully open.
  if ! _derived_record_selected "$check_id"; then
    printf 'unknown\tcomposite-not-selected'
    return 0
  fi

  # A prior composite finding whose state predates `contributors` cannot be
  # judged: the weak "covered in at least one cell" fallback is exactly the
  # formulation this tension replaced, and a region-narrowed run would report
  # the flagship composite `fixed` through it.  So it is not used.
  if [[ -z $prior_contributors ]]; then
    printf 'unknown\tcontributors-unavailable'
    return 0
  fi

  local ridx
  ridx=$(records_index_of_id derivedset "$check_id") || {
    printf 'unknown\tcomposite-not-selected'
    return 0
  }

  local c uncovered=''
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    if ! _contributor_covered "$c" "$prior_contributors" "$prior_state" \
      "$covered_now" "$covered_prior" "$oldest_commit_time"; then
      uncovered="${uncovered:+$uncovered,}$c"
    fi
  done <<<"$(_derived_contributors "$ridx")"

  if [[ -n $uncovered ]]; then
    printf 'unknown\tcontributor-not-covered:%s@%s' "$uncovered" "$correlation"
    return 0
  fi

  # (c) the ordinary predicate re-evaluation, which the caller has already done.
  if [[ $fired == true ]]; then
    printf 'recurring\t'
    return 0
  fi
  printf 'fixed\tchain-broken'
}

# (b) has two branches because contributors divide into two kinds.
_contributor_covered() {
  local check=$1 prior_contributors=$2 prior_state=$3
  local covered_now=$4 covered_prior=$5 oldest_commit_time=$6

  # (b1) A check that produced a prior contributor finding.  Its (check_id,
  # cell) pair is read from state/ and must be covered this run.  Additionally
  # that contributor must itself be `fixed`-ELIGIBLE, not merely cell-covered:
  # the rule is general, not a SAST-HIST-* special case - a contributor counts
  # as covered only under the same test that would let its own finding be
  # classified `fixed`.
  local fp found=0 line c_check c_cell c_time
  while IFS= read -r fp; do
    [[ -n $fp ]] || continue
    while IFS=$'\t' read -r line c_check c_cell c_time; do
      [[ $line == "$fp" ]] || continue
      [[ $c_check == "$check" ]] || continue
      found=1
      _pair_covered "$check" "$c_cell" "$covered_now" || return 1
      if [[ $check == SAST-HIST-* ]]; then
        # tension 13: a covered cell is necessary but not sufficient.  Reading
        # only the cell would let a composite be `fixed` while the history
        # contributor it depends on is itself correctly `unknown`.
        [[ -n $c_time && -n $oldest_commit_time ]] || return 1
        [[ $c_time > $oldest_commit_time || $c_time == "$oldest_commit_time" ]] || return 1
      fi
    done <"$prior_state"
  done <<<"${prior_contributors//,/$'\n'}"
  (( found )) && return 0

  # (b2) A listed check that produced no prior contributor finding.
  # `contributors` records only the checks that actually FIRED, so a listed
  # any-of alternative that did not fire leaves no pair to look up and would
  # otherwise be invisible.  Such a check counts as covered only when BOTH hold.
  #
  #   1. A FLOOR: the check has an entry in THIS run's covered_checks with at
  #      least one cell.  A check with no entry at all is not covered, whatever
  #      the prior run recorded.  Without the floor, an empty prior cell set
  #      makes the subset test hold vacuously and the composite is reported
  #      `fixed (chain broken)` while the alternative that could keep
  #      A AND (B OR C) live was never assessed in either run.
  #   2. A SUBSET: the prior state's cells for that check are a subset of this
  #      run's, so every cell the prior run covered it over was revisited.
  #      Without the subset test, a --regions-narrowed run slips through.
  #
  # Neither half is sufficient alone.
  local any_now=0 cell
  while IFS=$'\t' read -r c_check cell; do
    [[ $c_check == "$check" ]] || continue
    any_now=1
  done <"$covered_now"
  (( any_now )) || return 1

  while IFS=$'\t' read -r c_check cell; do
    [[ $c_check == "$check" ]] || continue
    _pair_covered "$check" "$cell" "$covered_now" || return 1
  done <"$covered_prior"
  return 0
}

_pair_covered() {
  local check=$1 cell=$2 covered=$3 c k
  while IFS=$'\t' read -r c k; do
    [[ $c == "$check" && $k == "$cell" ]] && return 0
  done <"$covered"
  return 1
}

_derived_record_selected() {
  local id=$1
  [[ -n ${SCOURSH_SELECTED_CHECKS:-} ]] || return 0    # no filter chain: all selected
  [[ $'\n'"$SCOURSH_SELECTED_CHECKS"$'\n' == *$'\n'"$id"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 17. Classifying an ORDINARY (non-derived) finding against state/
#     (docs/STEP7-STATE-PLAN.md STATE-03; tension 12's four-row table and its
#     two guards; tension 11 stage 5)
# ---------------------------------------------------------------------------
# This is the classification ENGINE only: pure functions over plain scalars
# and line-oriented files, in the same tradition `classify_derived` above
# already established for the composite case (a caller with real state/ -
# lib/state.sh's loader and this run's own write-side coverage builder -
# converts them into these shapes; nothing here sources lib/state.sh or
# reaches into its arrays, so there is no new shellcheck -x source edge
# added here - see AGENTS.md's "Sharp edges" for why that graph is guarded).
# This ticket wires nothing into scan_main, scan.sh diff, or the report:
# that is STATE-06 (docs/STEP7-STATE-PLAN.md), which converts a REAL loaded
# state/latest.json and this run's real findings.fields into the inputs
# below and applies the result.
#
# A derived finding (cell is JSON null) is NOT handled here - it has no
# coverage cell, so tension 12's (check, cell) test does not apply to it at
# all, and its own three-condition rule is `classify_derived` above
# (STATE-05, not this ticket).  A caller filters null-cell findings out
# before reaching any function below.
#
# The four-row table (tension 12), for a prior finding with check_id C and
# cell K, is:
#
#   | Prior finding | This run | Status                                    |
#   |----------------|----------|------------------------------------------|
#   | present, (C,K) covered | present | recurring                         |
#   | present, (C,K) covered | absent  | fixed                             |
#   | present, (C,K) NOT covered | absent | unknown, carried fwd w/ first_seen|
#   | absent         | present | new                                      |
#
# A finding PRESENT this run implies its own (check_id, cell) was covered
# this run by construction - it cannot have been emitted otherwise - so the
# "present | present" row's coverage qualifier needs no separate test: only
# fingerprint membership in the prior set decides new versus recurring.
# Coverage matters only on the "prior present, this run absent" side, which
# is `findings_classify_absent` below.

# `findings_classify_guard THIS_FP_SCHEMA THIS_SCAN_ROOT_ID THIS_HAS_PATH_ROOT
#                          PRIOR_FP_SCHEMA PRIOR_SCAN_ROOT_ID`
#
# PRIOR_FP_SCHEMA empty means no prior state was loaded at all (the ordinary
# first-run case - lib/state.sh's `state_loaded` returning false), handled
# identically to a real mismatch: both make the prior set (or the relevant
# slice of it) incomparable.
# THIS_HAS_PATH_ROOT is 'true' when this run's OWN covered_checks include at
# least one path-root-scoped check - i.e. its selected modules are ones
# whose findings live in path-root cells (SAST/IaC/SCA/history).  A run that
# never touches a path-root cell cannot be invalidated by a scan_root_id
# mismatch, because nothing it classifies depends on scan_root_id at all
# (tension 12: "the gate is scoped to path-root cells and to nothing else").
#
# Prints one of: usable | no_prior_state | fp_schema_mismatch |
#                scan_root_id_mismatch
findings_classify_guard() {
  local this_fp_schema=$1 this_scan_root_id=$2 this_has_path_root=$3
  local prior_fp_schema=$4 prior_scan_root_id=$5
  if [[ -z $prior_fp_schema ]]; then
    printf 'no_prior_state'
    return 0
  fi
  if [[ $prior_fp_schema != "$this_fp_schema" ]]; then
    printf 'fp_schema_mismatch'
    return 0
  fi
  if [[ $this_has_path_root == true && $prior_scan_root_id != "$this_scan_root_id" ]]; then
    printf 'scan_root_id_mismatch'
    return 0
  fi
  printf 'usable'
}

# `findings_diff_usable GUARD` -> 'true' or 'false'.
# Tension 11 stage 5: diff_usable governs the GATE only and never overrides a
# `status` - every status below is decided by the table above and by nothing
# else, including on a first run (no prior state), whose findings are still
# `new`, not `unknown` (tension 11's own withdrawn-earlier-draft note).
findings_diff_usable() {
  if [[ $1 == usable ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

# `findings_classify_present FINGERPRINT GUARD SCOPE PRIOR_FINGERPRINTS_FILE`
#
# Classifies ONE finding PRESENT in this run's findings.fields.
# PRIOR_FINGERPRINTS_FILE is one fingerprint per line (lib/state.sh's
# `state_finding_fingerprints`, unfiltered - the exclusion below is applied
# HERE, by scope, never by pre-filtering the file, so one file always
# represents the whole prior set).  SCOPE is this finding's own
# coverage-scope (path-root/target/account-region/scope-key), needed only
# to decide whether the scan_root_id guard applies to IT specifically.
#
# The local variable is spelled `coverage_scope`, never the shorter `scope`
# a first draft used - measured, not a style preference.  With `scope` as
# the local name here (and in `findings_classify_absent` below), a
# whole-tree `shellcheck -x` run produced two SC2100 findings on an
# UNRELATED file, `tests/suites/dast-scope-precheck.sh` line 254-255,
# neither of which is real (confirmed by re-running the identical
# `shellcheck -x -s bash` invocation against that file alone, with only this
# rename applied) - some coincidence in how `-x` merges this file's own
# inlined source graph with that one's.  Do not rename it back.
#
# Prints 'new' or 'recurring'.
findings_classify_present() {
  local fp=$1 guard=$2 coverage_scope=$3 prior_file=$4
  case $guard in
    fp_schema_mismatch | no_prior_state)
      printf 'new'
      return 0
      ;;
    scan_root_id_mismatch)
      if [[ $coverage_scope == path-root ]]; then
        printf 'new'
        return 0
      fi
      ;;
  esac
  local pfp
  while IFS= read -r pfp; do
    [[ -n $pfp ]] || continue
    if [[ $pfp == "$fp" ]]; then
      printf 'recurring'
      return 0
    fi
  done <"$prior_file"
  printf 'new'
}

# `findings_classify_absent CHECK_ID CELL SCOPE GUARD COVERED_NOW_FILE`
#
# Classifies ONE PRIOR finding ABSENT from this run's findings.fields.
# COVERED_NOW_FILE is `check_id \t cell` lines, this run's own covered pairs
# (the identical format `classify_derived`'s COVERED_THIS_RUN already uses,
# and `_pair_covered` above is reused unchanged - one coverage test, one
# owner, for an ordinary finding and a composite contributor alike).
#
# Prints '<status>\t<reason>'.  status is 'fixed' or 'unknown'; reason is
# empty for 'fixed'.
findings_classify_absent() {
  local check_id=$1 cell=$2 coverage_scope=$3 guard=$4 covered_now=$5
  case $guard in
    fp_schema_mismatch)
      printf 'unknown\tfp_schema_mismatch'
      return 0
      ;;
    no_prior_state)
      # Unreachable in ordinary use: no prior state means no prior findings
      # to classify as absent in the first place.  Guarded here anyway so a
      # caller that reaches this function out of order fails safe rather
      # than falling through to a coverage test against nothing.
      printf 'unknown\tno_prior_state'
      return 0
      ;;
    scan_root_id_mismatch)
      if [[ $coverage_scope == path-root ]]; then
        printf 'unknown\tscan_root_id_mismatch'
        return 0
      fi
      ;;
  esac
  if _pair_covered "$check_id" "$cell" "$covered_now"; then
    printf 'fixed\t'
  else
    printf 'unknown\tnot-covered-this-run'
  fi
}

# `findings_rule_digest_changed PRIOR_DIGEST THIS_DIGEST` -> 'true'/'false'.
# Tension 12: "a rule_digest change classifies normally but flags 'rule
# changed' in the report."  Classification itself (above) does not read this
# at all - a rule edit is not a reason to withhold fixed/recurring/unknown,
# only a reason to annotate the report once STATE-06 wires that in.  An
# empty PRIOR_DIGEST (the check did not exist in the prior run at all) is
# not a change to flag - there is nothing to compare against yet.
findings_rule_digest_changed() {
  local prior_digest=$1 this_digest=$2
  if [[ -n $prior_digest && $prior_digest != "$this_digest" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}
