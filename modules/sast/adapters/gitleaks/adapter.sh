#!/usr/bin/env bash
# modules/sast/adapters/gitleaks/adapter.sh - the gitleaks optional engine
# adapter (docs/DESIGN.md §6.4, §13 step 9; docs/ADAPTERS.md; this ticket,
# the SECOND concrete adapter, built entirely on the shared plumbing the
# semgrep ticket shipped - lib/engines.sh's has_engine() and the
# --use-engines flag - rather than duplicating either).
#
# Owns: docs/ADAPTERS.md §5's three-function contract, applied to gitleaks.
# Mirrors modules/sast/adapters/semgrep/adapter.sh's own shape and header
# reasoning throughout; only the parts that differ because gitleaks' CLI
# and JSON shape differ from semgrep's are called out below.
#
# THE THREE FUNCTIONS (docs/ADAPTERS.md §5) - `gitleaks_detect`,
# `gitleaks_run`, `gitleaks_normalize` - are this file's public interface
# and the only functions a caller (modules/sast/run.sh, via lib/engines.sh's
# `has_engine`) is ever meant to call.  Every other function here is a
# private `_gitleaks_*` helper (same public/private split every other
# engine file in this repository uses).
#
# NEVER FETCHES ANYTHING (docs/ADAPTERS.md §2).  This file contains no
# curl/wget/nc/ncat/netcat/openssl-s_client invocation and never sources or
# calls tools/vendor-engines.sh - tests/lint-shell.sh's "no bypass" and "no
# wiring of tools/vendor-engines.sh" checks both cover this file like every
# other file under modules/.
#
# UNTRUSTED OUTPUT (CLAUDE.md §6 / docs/FOUNDATION.md tension 9's "evidence
# is untrusted target output" applied to a THIRD-PARTY TOOL's output):
# gitleaks' JSON is DATA, never instructions.  `gitleaks_normalize` never
# `eval`s any part of it, never uses it to build a command, and only ever
# reaches the finding model through lib/findings.sh's existing public
# setters, which already redact and JSON-escape everything they touch.  The
# `File` field gitleaks reports is additionally validated to resolve inside
# the scan root before it is ever trusted as a finding's location (see
# `_gitleaks_resolve_location`), the identical boundary check
# `_semgrep_resolve_location` already applies (OWASP A01).
#
# WORKING TREE ONLY, NOT GIT HISTORY.  `gitleaks_run` invokes the binary
# with `--no-git`: this adapter scans the working tree the same way every
# other SAST check does, and deliberately leaves git-history secret
# scanning to modules/sast/history.sh's own, already-shipped `SAST-HIST-*`
# mechanism (§13 step 3e) - running gitleaks over history here too would
# duplicate that mechanism's job with a different fingerprint profile and a
# different truncation/coverage story, rather than complementing it.
#
# shellcheck shell=bash
#
# SC2329: several `_gitleaks_*` helpers are only reachable through the three
# contract functions above, not through a literal call shellcheck's static
# graph can follow from this file alone.
# SC1003: `[[ $c == '\' ]]` compares against a literal single backslash
# character - the identical disable modules/sast/adapters/semgrep/adapter.sh
# already carries for the identical reason.
# shellcheck disable=SC2329,SC1003

if [[ -n ${SCOURSH_GITLEAKS_ADAPTER_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_GITLEAKS_ADAPTER_SOURCED=1

GITLEAKS_ADAPTER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
GITLEAKS_BIN=$GITLEAKS_ADAPTER_DIR/bin/gitleaks
GITLEAKS_CONFIG=$GITLEAKS_ADAPTER_DIR/rules/gitleaks.toml

# Same bound-the-adversarial-input discipline SCOURSH_SEMGREP_MAX_RESULTS
# already applies (OWASP A10): a malformed or hostile-sized gitleaks JSON
# document degrades this adapter's coverage rather than turning into
# unbounded work or a crashed scan.
SCOURSH_GITLEAKS_MAX_RESULTS=${SCOURSH_GITLEAKS_MAX_RESULTS:-5000}

# ---------------------------------------------------------------------------
# 1. gitleaks_detect - pure filesystem check (docs/ADAPTERS.md §5).  Never
#    touches the network, never runs the engine, never writes anything.
# ---------------------------------------------------------------------------
gitleaks_detect() {
  [[ -x $GITLEAKS_BIN ]] || return 1
  [[ -f $GITLEAKS_CONFIG ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# 2. gitleaks_run OUTPUT_FILE TARGET... - runs the vendored binary fully
#    offline against the working tree, writing its native JSON report to
#    OUTPUT_FILE.  Exits non-zero only on a genuine engine failure
#    (docs/ADAPTERS.md §5); the caller (modules/sast/run.sh) turns that into
#    a coverage_reduction rather than aborting the run.
#
#    Flags, per docs/DESIGN.md §6.4 ("gitleaks --no-banner") plus what this
#    adapter itself needs:
#      detect              - scan a target for leaks (gitleaks' own verb).
#      --no-banner         - the flag §6.4 names explicitly.
#      --no-git            - scan the working tree as plain files rather than
#                             walking git history; history is history.sh's
#                             job (this file's own header).
#      --source            - the target to scan (TARGET... - only the first
#                             is used; gitleaks scans one source tree per
#                             invocation, and modules/sast/run.sh only ever
#                             calls this adapter with the resolved scan root,
#                             the same single-target shape semgrep_run's own
#                             "$@" -> "$root" call site already uses).
#      --config            - the vendored, offline ruleset only; gitleaks
#                             never reaches for its own built-in default
#                             config or the network when --config is given.
#      --report-format json / --report-path - write gitleaks' own JSON here
#                             rather than to stdout, so a huge report cannot
#                             blow past a captured-variable size limit.
#      --exit-code 0       - gitleaks' own default exit code is 1 when leaks
#                             are found, which is this scanner's NORMAL,
#                             successful outcome, not an engine failure; a
#                             non-zero exit from this invocation is reserved
#                             for a genuine crash (bad config, permission
#                             error, ...).
# ---------------------------------------------------------------------------
gitleaks_run() {
  local out=$1
  shift
  (( $# > 0 )) || { : >"$out"; return 1; }
  local target=$1

  local rc=0 errfile=$SCOURSH_SCRATCH/gitleaks-stderr.$$
  "$GITLEAKS_BIN" detect \
    --no-banner --no-git --exit-code 0 \
    --source "$target" \
    --config "$GITLEAKS_CONFIG" \
    --report-format json --report-path "$out" \
    >"$errfile" 2>&1 || rc=$?

  # gitleaks does not write a report file at all when it finds nothing under
  # some versions; an absent-but-successful run is a clean empty result, not
  # a failure - gitleaks_normalize's own `[[ -r $infile ]]` guard already
  # treats a missing file as zero findings, so nothing further is needed
  # here beyond not letting that show up as rc != 0.
  if (( rc != 0 )); then
    log_warn "sast: gitleaks adapter exited $rc - $(cat "$errfile" 2>/dev/null | head -n 5)"
  fi
  rm -f "$errfile"
  return "$rc"
}

# ---------------------------------------------------------------------------
# 3. gitleaks_normalize INPUT_FILE - reads INPUT_FILE (gitleaks' own JSON,
#    written by gitleaks_run) and emits one scoursh finding per result via
#    lib/findings.sh's public API only (docs/ADAPTERS.md §5/§8).
#
#    Also performs the SECOND, narrower dedup pass this ticket's own scope
#    item 3 adds on top of the ordinary per-run fingerprint dedup
#    (lib/findings.sh's findings_merge): see _gitleaks_dup_of_native_secret's
#    own comment for why that ordinary dedup cannot catch this overlap on
#    its own.
# ---------------------------------------------------------------------------
gitleaks_normalize() {
  local infile=$1
  [[ -r $infile ]] || return 0

  local objects=$SCOURSH_SCRATCH/gitleaks-results.$$
  _gitleaks_split_results "$infile" >"$objects"

  local scan_root=${_SCAN_RESOLVED_PATH:-.}
  scan_root=$(scan_root_of "$scan_root")

  local obj count=0 dup=0 truncated=0
  while IFS= read -r obj; do
    [[ -n $obj ]] || continue
    if [[ $obj == __TRUNCATED__ ]]; then
      truncated=1
      break
    fi
    if _gitleaks_emit_finding "$obj" "$scan_root"; then
      count=$(( count + 1 ))
    else
      dup=$(( dup + 1 ))
    fi
  done <"$objects"
  rm -f "$objects"

  if (( truncated )); then
    run_record coverage_reduction \
      "module=sast reason=engine_results_truncated engine=gitleaks max=$SCOURSH_GITLEAKS_MAX_RESULTS"
  fi
  if (( dup > 0 )); then
    run_record coverage_reduction \
      "module=sast reason=dedup_native_secret engine=gitleaks count=$dup"
  fi
  run_record coverage_reduction "module=sast reason=engine_boosted_not_a_replacement engine=gitleaks results=$count"
}

# ---------------------------------------------------------------------------
# Private helpers below.  Never called directly by anything outside this
# file (docs/ADAPTERS.md §5's contract is the three functions above).
# ---------------------------------------------------------------------------

# _gitleaks_split_results FILE - writes one complete result object's raw
# JSON text (whitespace-flattened, guaranteed to carry no embedded raw
# newline, per the identical JSON-well-formedness argument
# _semgrep_split_results's own comment already makes) per output line, for
# every element of the TOP-LEVEL array.
#
# UNLIKE semgrep's `{"results":[...]}` envelope, gitleaks' own report is a
# BARE top-level JSON array (`[{...},{...}]`, or `[]`/absent when nothing
# was found) - there is no `"results"` key to locate first, so this walk
# starts directly at the first `[`.  Depth- and string-aware for the same
# reason and by the same construction as _semgrep_split_results.  Bounded by
# SCOURSH_GITLEAKS_MAX_RESULTS; prints a literal `__TRUNCATED__` sentinel
# line and stops if the bound is hit, which the caller turns into a
# coverage_reduction rather than silently dropping the remainder.
_gitleaks_split_results() {
  local file=$1
  awk -v max="$SCOURSH_GITLEAKS_MAX_RESULTS" '
    { content = content $0 " " }
    END {
      n = length(content)
      i = 1
      while (i <= n && substr(content, i, 1) ~ /[ \t]/) i++
      if (substr(content, i, 1) != "[") { exit }
      i++
      depth = 0; instr = 0; esc = 0; capturing = 0; buf = ""; count = 0
      for (; i <= n; i++) {
        c = substr(content, i, 1)
        if (instr) {
          if (capturing) buf = buf c
          if (esc) { esc = 0 }
          else if (c == "\\") { esc = 1 }
          else if (c == "\"") { instr = 0 }
          continue
        }
        if (c == "\"") { instr = 1; if (capturing) buf = buf c; continue }
        if (c == "{") {
          if (depth == 0) { capturing = 1; buf = "{"; depth = 1; continue }
          depth++
          if (capturing) buf = buf c
          continue
        }
        if (c == "[") {
          depth++
          if (capturing) buf = buf c
          continue
        }
        if (c == "}") {
          depth--
          if (capturing) buf = buf c
          if (depth == 0) {
            print buf
            capturing = 0; buf = ""
            count++
            if (count >= max) { print "__TRUNCATED__"; exit }
          }
          continue
        }
        if (c == "]") {
          if (depth == 0) { exit }
          depth--
          if (capturing) buf = buf c
          continue
        }
        if (capturing) buf = buf c
      }
    }
  ' "$file"
}

# _gitleaks_json_string_field OBJ KEY - identical contract and identical
# implementation to _semgrep_json_string_field (kept as a separate copy,
# not a shared helper, because docs/ADAPTERS.md §4 scopes each adapter
# directory to be self-contained and independently vendorable - the same
# reason modules/sca/php_engine.sh does not reach into
# modules/sca/engine.sh's private helpers either, only its public ones).
_gitleaks_json_string_field() {
  local obj=$1 key=$2
  local marker="\"$key\""
  [[ $obj == *"$marker"* ]] || return 1
  local rest=${obj#*"$marker"}
  rest=${rest#*:}
  while [[ ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' ]]; do rest=${rest:1}; done
  [[ ${rest:0:1} == '"' ]] || return 1
  rest=${rest:1}
  local out='' i=0 c esc=0 n=${#rest}
  while (( i < n )); do
    c=${rest:i:1}
    if (( esc )); then
      case $c in
        n) out+=$'\n' ;;
        t) out+=$'\t' ;;
        r) out+=$'\r' ;;
        b) out+=$'\b' ;;
        f) out+=$'\f' ;;
        '"' | '\' | /) out+=$c ;;
        u) out+='?'; i=$(( i + 4 )) ;;
        *) out+=$c ;;
      esac
      esc=0
    elif [[ $c == '\' ]]; then
      esc=1
    elif [[ $c == '"' ]]; then
      break
    else
      out+=$c
    fi
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

# _gitleaks_json_number_field OBJ KEY - identical contract to
# _semgrep_json_number_field; same portable-ERE-only precedent
# (docs/FOUNDATION.md tension 2), applied here to gitleaks' StartLine.
_gitleaks_json_number_field() {
  local obj=$1 key=$2
  [[ $obj =~ \"$key\"[[:space:]]*:[[:space:]]*(-?[0-9]+) ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

# _gitleaks_resolve_location - identical contract and implementation to
# _semgrep_resolve_location (see that function's own comment for the full
# rationale: REPORTED_PATH is untrusted, third-party-engine-reported
# output, and must resolve inside the scan root before it is ever trusted
# as a finding's loc_path).
_gitleaks_resolve_location() {
  local root=$1 reported=$2
  [[ -n $reported ]] || return 1
  local abspath=$reported
  if [[ ${reported:0:1} != / ]]; then
    abspath=$root/$reported
  fi
  abspath=$(realpath_of "$abspath")
  case $abspath in
    "$root" | "$root"/*) ;;
    *) return 1 ;;
  esac
  printf '%s' "$abspath"
}

# _gitleaks_match_text SECRET MATCH ABSPATH LINE FALLBACK - the raw matched
# text for the fingerprint/evidence.
#
# UNLIKE _semgrep_match_text, this does NOT prefer a re-derived whole LINE
# read from disk.  gitleaks' own JSON already reports the exact matched
# secret bytes in `Secret` (or, absent that, `Match`, gitleaks' own
# slightly wider capture) - that is precisely the "raw matched text" every
# other emitter in this codebase hashes: modules/sast/engine.sh's own
# _sast_emit_finding computes ITS match_digest from `$text`, the exact
# regex MATCH substring `scan_match_offsets` captured (rules/RULE-FORMAT.md
# §10.3's pass 1), never the surrounding line - `sast_scan_file`'s own
# `while IFS=: read -r ln off text` line shows `text` is the match, not a
# `sed -n "${ln}p"` read.  Preferring gitleaks' own `Secret` field over a
# re-derived line is therefore what makes THIS adapter's match_digest
# comparable to a native secrets.rules finding's own loc_match_digest at
# all (see _gitleaks_dup_of_native_secret below): both sides end up hashing
# the identical substring - the secret itself - for the identical
# hardcoded-AWS-key-on-line-N case, where semgrep's own line-level
# surrogate would not (semgrep has no analogous "just the matched
# substring" field to prefer, which is why THAT adapter reads the line
# instead - a difference in the upstream tool's own JSON shape, not a
# contradiction in this codebase's own conventions).
#
# The real-file line read is kept as a THIRD-TIER fallback only, for the
# rare case where a gitleaks rule reports neither `Secret` nor `Match`
# (some allowlist/generic rules only ever populate `Description`) - at
# that point re-deriving from disk is strictly better than nothing, the
# same tension 5/11 reasoning semgrep's own adapter applies as its
# PRIMARY source.
_gitleaks_match_text() {
  local secret=$1 match=$2 abspath=$3 line=$4 fallback=$5
  if [[ -n $secret ]]; then
    printf '%s' "$secret"
    return 0
  fi
  if [[ -n $match ]]; then
    printf '%s' "$match"
    return 0
  fi
  if [[ -n $abspath && -r $abspath && $line =~ ^[0-9]+$ ]] && (( line > 0 )); then
    local text
    text=$(sed -n "${line}p" -- "$abspath" 2>/dev/null || true)
    if [[ -n $text ]]; then
      printf '%s' "$text"
      return 0
    fi
  fi
  printf '%s' "$fallback"
}

# _gitleaks_dup_of_native_secret RELPATH MATCH_DIGEST - 0 (duplicate) iff
# THIS RUN's own not-yet-merged shards already carry a `module=sast`,
# `check_id=SAST-SEC-*` finding at the same loc_path with the same
# loc_match_digest.
#
# WHY THIS EXISTS ON TOP OF THE ORDINARY PER-RUN DEDUP
# (lib/findings.sh's findings_merge, tension 11 step 3): that pass dedups on
# the FULL fingerprint, and `check_id` is one of the fingerprint's own
# hashed components (finding_fingerprint: `parts=(module_token check_id
# loc_*...)`) - so `gitleaks:generic-api-key` and `SAST-SEC-GENERIC_API_KEY-01`
# hash to two DIFFERENT fingerprints even when they report the identical
# file, line, and raw secret text.  findings_merge would keep both.  This
# ticket's own scope item 3 ("both target secrets, so overlap is expected
# and must be deduplicated ... not double-reported") is a NARROWER,
# cross-check-id identity: same file, same underlying matched bytes.
#
# READS THE SHARD DIRECTLY, NOT THROUGH findings_merge, because this
# adapter runs strictly after modules/sast/engine.sh's native pattern scan
# in modules/sast/run.sh's own `_sast_run_module` (sast_scan_tree, then
# history.sh, then the engine adapters) and BEFORE findings_merge is ever
# called for this run - so the native secrets.rules findings this run
# already produced are sitting, unmerged, in this same worker's own shard
# file (modules/sast/run.sh runs single-worker per its own
# "single_worker_no_parallel_scan_yet" coverage_reduction, so there is
# exactly one shard to read).  finding_decode is lib/findings.sh's own
# public reader for that shard format (§13 of lib/findings.sh) - this
# function never parses the `.fields` line itself.
_gitleaks_dup_of_native_secret() {
  local relpath=$1 digest=$2
  [[ -n ${SCOURSH_RUN_DIR:-} ]] || return 1
  local shard line
  for shard in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -e $shard ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      [[ ${_DF[module]:-} == sast ]] || continue
      [[ ${_DF[check_id]:-} == SAST-SEC-* ]] || continue
      [[ ${_DF[loc_path]:-} == "$relpath" ]] || continue
      [[ ${_DF[loc_match_digest]:-} == "$digest" ]] || continue
      return 0
    done <"$shard"
  done
  return 1
}

# _gitleaks_emit_finding OBJ SCAN_ROOT - OBJ is one complete result object's
# raw JSON text (from _gitleaks_split_results).  Mints a finding purely
# through lib/findings.sh's public API (docs/ADAPTERS.md §5/§8's round-trip
# requirement), unless _gitleaks_dup_of_native_secret says this is a
# duplicate of a native secrets.rules finding this same run already
# emitted, in which case it is skipped and the caller counts it as a dedup
# rather than a normal result (return 1 signals "skipped: duplicate", not
# an error - gitleaks_normalize's own caller loop reads it that way).
_gitleaks_emit_finding() {
  local obj=$1 scan_root=$2

  local rule_id path_raw description line_raw
  rule_id=$(_gitleaks_json_string_field "$obj" RuleID) || rule_id=''
  [[ -n $rule_id ]] || return 1

  path_raw=$(_gitleaks_json_string_field "$obj" File) || path_raw=''
  description=$(_gitleaks_json_string_field "$obj" Description) || description=''
  line_raw=$(_gitleaks_json_number_field "$obj" StartLine) || line_raw=''

  local resolved
  resolved=$(_gitleaks_resolve_location "$scan_root" "$path_raw") || {
    run_record coverage_reduction \
      "module=sast reason=engine_reported_path_outside_scan_root engine=gitleaks check=gitleaks:$rule_id"
    return 1
  }
  local relpath
  relpath=$(sast_relpath "$scan_root" "$resolved")

  local secret_raw match_raw
  secret_raw=$(_gitleaks_json_string_field "$obj" Secret) || secret_raw=''
  match_raw=$(_gitleaks_json_string_field "$obj" Match) || match_raw=''

  local match_text
  match_text=$(_gitleaks_match_text "$secret_raw" "$match_raw" "$resolved" "${line_raw:-0}" "$description")

  local digest
  digest=$(fingerprint_digest "$match_text")
  if _gitleaks_dup_of_native_secret "$relpath" "$digest"; then
    return 1
  fi

  local check_id="gitleaks:$rule_id"
  local title=$description
  [[ -n $title ]] || title="gitleaks: $rule_id"

  finding_new
  finding_set check_id "$check_id"
  finding_set module sast
  finding_set title "$title"
  # gitleaks reports no per-finding severity of its own; every rule in a
  # dedicated secret-detection engine's ruleset is, by construction, a
  # hardcoded-credential finding, so this adapter fixes severity/confidence
  # the same way modules/sast/rules/secrets.rules' own highest-confidence
  # rules do (SAST-SEC-AWS_AKID-01, SAST-SEC-PRIVATE_KEY-01: critical/high) -
  # never "critical" itself, per the same reservation
  # _semgrep_severity_map's own comment states (data/severity-rubric.conf's
  # escalation, not a raw engine report).
  finding_set base_severity high
  finding_set confidence high
  finding_set cwe CWE-798
  finding_set owasp A07:2021
  finding_set loc_path "$relpath"
  finding_set loc_line "${line_raw:-0}"
  finding_set cell "${SCOURSH_PATH_ROOT:-.}"
  finding_set logical_kind file
  finding_set logical_fqn "$relpath:${line_raw:-0}"
  # Every gitleaks finding is, by the engine's own purpose, a secret - never
  # a heuristic (unlike semgrep_normalize's _sast_check_is_sensitive
  # substring guess over a general-purpose rule id).
  finding_set sensitive_data true
  finding_set remediation \
    "Remove the secret from source and rotate it immediately (gitleaks rule '$rule_id'): ${description:-no further detail reported}. A committed secret must be treated as compromised even if the commit is reverted."
  finding_set_match "$match_text"
  finding_set_evidence "$match_text"
  finding_emit
  return 0
}
