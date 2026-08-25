#!/usr/bin/env bash
# lib/records.sh - the parser for the FROZEN record format.
#
# Normative source: rules/RULE-FORMAT.md.  §3 is the lexical syntax, §3.2 the
# ordered line-kind classification, §4 records, §5 fields, §6 continuations, §7
# the reference parse algorithm, §9 the schemas, §13 the error codes.
# docs/FOUNDATION.md tension 1 is why the format exists, tension 26 is why every
# human-authored config file shares it.
#
# This is the ONLY parser.  Every `*.rules` pack, every `checks.rules`,
# `rules/derived.rules`, `rules/redaction.rules`, `data/severity-rubric.conf`,
# and every `config/*.conf` loads through it.  Record files are DATA and are
# never sourced, evaluated, or shell-expanded (rules/RULE-FORMAT.md §11).
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_RECORDS_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_RECORDS_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# ---------------------------------------------------------------------------
# 1. Schema definitions (rules/RULE-FORMAT.md §9)
# ---------------------------------------------------------------------------
# Each entry is `key:required:cardinality:multiline`.
#   required     req | opt
#   cardinality  single | repeatable
#   multiline    ml | sl
#
# The parser itself consults cardinality (for E014) and multi-line (for E016),
# which is exactly why rules/RULE-FORMAT.md §9 insists every schema is defined in
# that document rather than alongside its consumer: a file whose key cardinality
# lives elsewhere cannot be parsed at all.
#
# INVARIANT, checked by tests/suites/records.sh: no key is both *repeatable* and
# *multi-line* in any schema.  Repeatable values are therefore LF-free, which is
# what lets a repeated key's values be stored LF-joined.

_schema_def() {
  case $1 in
    pattern-rule)
      printf '%s\n' \
        'id:req:single:sl' 'title:req:single:sl' 'severity:req:single:sl' \
        'confidence:opt:single:sl' 'cwe:req:single:sl' 'owasp:req:single:sl' \
        'pattern:req:single:sl' 'dialect:opt:single:sl' \
        'files:opt:repeatable:sl' 'exclude-files:opt:repeatable:sl' \
        'context-require:opt:repeatable:sl' 'context-deny:opt:repeatable:sl' \
        'context-window:opt:single:sl' 'remediation:req:single:ml' \
        'references:opt:repeatable:sl' 'cis:opt:repeatable:sl' \
        'tags:opt:repeatable:sl' 'severity-floor:opt:single:sl' \
        'severity-ceiling:opt:single:sl' 'format-version:opt:single:sl'
      ;;
    derived)
      printf '%s\n' \
        'id:req:single:sl' 'kind:req:single:sl' 'title:req:single:sl' \
        'severity:req:single:sl' 'confidence:opt:single:sl' \
        'cwe:req:single:sl' 'owasp:req:single:sl' \
        'requires:opt:repeatable:sl' 'any-of:opt:repeatable:sl' \
        'correlate-on:req:single:sl' 'remediation:req:single:ml' \
        'references:opt:repeatable:sl' 'cis:opt:repeatable:sl' \
        'tags:opt:repeatable:sl' 'format-version:opt:single:sl'
      ;;
    redaction)
      printf '%s\n' \
        'id:req:single:sl' 'title:req:single:sl' 'pattern:req:single:sl' \
        'dialect:opt:single:sl' 'kind:req:single:sl' 'format-version:opt:single:sl'
      ;;
    scope-target)
      printf '%s\n' \
        'id:req:single:sl' 'base-url:req:single:sl' 'extra-host:opt:repeatable:sl' \
        'allow-subdomains:opt:single:sl' 'allow-private-addresses:opt:single:sl' \
        'notes:opt:single:ml' 'format-version:opt:single:sl'
      ;;
    script-check)
      printf '%s\n' \
        'id:req:single:sl' 'title:req:single:sl' 'script:req:single:sl' \
        'entry:opt:single:sl' 'severity:req:single:sl' 'confidence:opt:single:sl' \
        'cwe:req:single:sl' 'owasp:req:single:sl' 'tags:req:repeatable:sl' \
        'coverage-scope:req:single:sl' 'requires-config:opt:repeatable:sl' \
        'requires-cmd:opt:repeatable:sl' 'requires-identities:opt:single:sl' \
        'remediation:req:single:ml' 'references:opt:repeatable:sl' \
        'cis:opt:repeatable:sl' 'severity-floor:opt:single:sl' \
        'severity-ceiling:opt:single:sl' 'format-version:opt:single:sl'
      ;;
    scanner-config)
      printf '%s\n' \
        'id:req:single:sl' 'requests-per-second:opt:single:sl' 'jobs:opt:single:sl' \
        'http-timeout:opt:single:sl' 'max-redirects:opt:single:sl' \
        'request-budget:opt:single:sl' 'circuit-breaker-failures:opt:single:sl' \
        'circuit-breaker-window:opt:single:sl' 'fail-on:opt:single:sl' \
        'min-confidence:opt:single:sl' 'redact-secrets:opt:single:sl' \
        'formats:opt:repeatable:sl' 'max-matches-per-file:opt:single:sl' \
        'evidence-max-bytes:opt:single:sl' 'scratch-dir:opt:single:sl' \
        'state-retain-runs:opt:single:sl' 'history-window-days:opt:single:sl' \
        'history-max-commits:opt:single:sl' 'lock-stale-seconds:opt:single:sl' \
        'mutex-timeout-seconds:opt:single:sl' 'paranoid-allow:opt:repeatable:sl' \
        'contact:opt:single:sl' \
        'notes:opt:single:ml' 'format-version:opt:single:sl'
      ;;
    auth-identity)
      printf '%s\n' \
        'id:req:single:sl' 'mode:req:single:sl' 'secret-file:opt:single:sl' \
        'token:opt:single:sl' 'header-name:opt:single:sl' 'username:opt:single:sl' \
        'password:opt:single:sl' 'login-path:opt:single:sl' 'token-url:opt:single:sl' \
        'client-id:opt:single:sl' 'client-secret:opt:single:sl' 'scope:opt:single:sl' \
        'pool-id:opt:single:sl' 'notes:opt:single:ml' 'format-version:opt:single:sl'
      ;;
    discovery-input)
      printf '%s\n' \
        'id:req:single:sl' 'openapi-path:opt:single:sl' 'graphql-schema-path:opt:single:sl' \
        'postman-path:opt:single:sl' 'har-path:opt:single:sl' 'crawl-depth:opt:single:sl' \
        'include-path:opt:repeatable:sl' 'exclude-path:opt:repeatable:sl' \
        'notes:opt:single:ml' 'format-version:opt:single:sl'
      ;;
    posture-expectation)
      printf '%s\n' \
        'id:req:single:sl' 'check:req:single:sl' 'scope-key:req:single:sl' \
        'expect:req:single:sl' 'value:opt:single:sl' 'notes:opt:single:ml' \
        'format-version:opt:single:sl'
      ;;
    severity-modifier)
      printf '%s\n' \
        'id:req:single:sl' 'fact:req:single:sl' 'equals:req:single:sl' \
        'modifier:req:single:sl' 'format-version:opt:single:sl'
      ;;
    *)
      return 1
      ;;
  esac
}

records_schema_names() {
  printf '%s\n' pattern-rule derived redaction scope-target script-check \
    scanner-config auth-identity discovery-input posture-expectation severity-modifier
}

# Schemas holding exactly one record, whose `id` is a frozen literal
# (rules/RULE-FORMAT.md §9, E071).
_schema_single_record_id() {
  case $1 in
    scanner-config) printf '%s' 'scanner' ;;
    *) return 1 ;;
  esac
}

# Schemas whose `id` is a check id in the check-id namespace
# (rules/RULE-FORMAT.md §9.1.1a).
records_schema_is_check_id() {
  case $1 in
    pattern-rule | derived | redaction | script-check) return 0 ;;
    *) return 1 ;;
  esac
}

# rules/RULE-FORMAT.md §9 path table.  The first matching row wins, which is why
# the two `checks` rows are first: the basename is reserved repository-wide, and
# without that reservation the `modules/iac/*.rules` glob would capture
# `modules/iac/checks.rules` and fail E023 on every record in it.
# The path is install-root-relative.
#
# The second row - `checks-<name>.rules` - is the per-owner spelling of the same
# §9.5 script-check registry, so that peers adding phase scripts to one module
# directory in parallel do not collide on a single co-owned file.  Three things
# about the glob are deliberate and each is pinned in tests/suites/records.sh:
#
#   `checks-?*.rules`, not `checks-*.rules`, because `?*` requires at least one
#   character - the bare `checks-.rules` names no owner and stays E070.
#
#   It sits ABOVE the pattern-rule rows for the same reason the `checks.rules`
#   row does: `modules/iac/checks-terraform.rules` must resolve to the script
#   check schema rather than being captured by `modules/iac/*.rules` and failing
#   E023 on every record for a missing `pattern`.
#
#   It legalises exactly one shape and does not open the extension up.  An
#   arbitrary `*.rules` at a module path is still E070, which is what keeps
#   `modules/dast/passive/cookies.rules` (and `headers-checks.rules`, the
#   DAST-05 attempt - the SUFFIX spelling, which this row does NOT legalise)
#   illegal.
#
# Nothing about ownership or identity moves with a record between these two
# rows: records_owning_module below keys on the DIRECTORY, so E018/E081 hold a
# split file's ids to the same module prefix, and a check id is unchanged by the
# file it lives in, so E019 uniqueness stays repository-wide.  That is what makes
# a split a byte-identical move rather than a fingerprint change
# (rules/RULE-FORMAT.md §14's second worked example).
records_schema_for_path() {
  local p=$1
  local base
  p=${p#./}
  # `config/*.example` files take the schema of the file they are an example of,
  # so the linter can run over them in CI and the examples cannot drift from the
  # schema (docs/FOUNDATION.md tension 26).
  p=${p%.example}
  # The two `checks` rows are matched on the BASENAME, never with a `*/`-prefixed
  # glob.  Bash's `*` matches `/` as well, so `*/checks-?*.rules` would also
  # match `a/checks-x/y.rules` - a DIRECTORY called `checks-x` would silently
  # turn every `.rules` file beneath it into a script-check registry.  Stripping
  # to the basename first is what confines the reservation to a filename, and
  # tests/suites/records.sh pins that nested case in both directions.
  base=${p##*/}
  case $base in
    checks.rules | checks-?*.rules) printf '%s' script-check; return 0 ;;
  esac
  case $p in
    modules/sast/rules/*.rules) printf '%s' pattern-rule ;;
    modules/iac/*.rules) printf '%s' pattern-rule ;;
    rules/derived.rules) printf '%s' derived ;;
    rules/redaction.rules) printf '%s' redaction ;;
    config/scope.conf) printf '%s' scope-target ;;
    config/scanner.conf) printf '%s' scanner-config ;;
    config/auth.conf) printf '%s' auth-identity ;;
    config/discovery.conf) printf '%s' discovery-input ;;
    config/posture.conf) printf '%s' posture-expectation ;;
    data/severity-rubric.conf) printf '%s' severity-modifier ;;
    *) return 1 ;;                                   # E070
  esac
}

# rules/RULE-FORMAT.md §9.5.1 owning-module map, most specific first, first match
# wins.  Ownership is NOT the first path segment: posture nests under
# modules/cloud/posture/ while POSTURE is a module in its own right, and two
# rule files live outside modules/ entirely.
records_owning_module() {
  local p=$1
  p=${p#./}
  case $p in
    modules/cloud/posture/*) printf '%s' POSTURE ;;
    modules/cloud/*) printf '%s' CLOUD ;;
    modules/sast/*) printf '%s' SAST ;;
    modules/sca/*) printf '%s' SCA ;;
    modules/iac/*) printf '%s' IAC ;;
    modules/dast/*) printf '%s' DAST ;;
    rules/derived.rules) printf '%s' COMPOSITE ;;
    rules/redaction.rules) printf '%s' SAST ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 2. Schema lookup helpers
# ---------------------------------------------------------------------------
declare -A _SCHEMA_LOADED=()
declare -A _SCHEMA_REQ=()
declare -A _SCHEMA_CARD=()
declare -A _SCHEMA_ML=()
declare -A _SCHEMA_KEYS=()

_schema_ensure() {
  local schema=$1 line key req card ml
  [[ -z ${_SCHEMA_LOADED[$schema]:-} ]] || return 0
  local defs
  defs=$(_schema_def "$schema") || return 1
  _SCHEMA_KEYS[$schema]=''
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    IFS=':' read -r key req card ml <<<"$line"
    _SCHEMA_REQ["$schema|$key"]=$req
    _SCHEMA_CARD["$schema|$key"]=$card
    _SCHEMA_ML["$schema|$key"]=$ml
    _SCHEMA_KEYS[$schema]+="$key"$'\n'
  done <<<"$defs"
  _SCHEMA_LOADED[$schema]=1
}

records_schema_keys() {
  _schema_ensure "$1" || return 1
  printf '%s' "${_SCHEMA_KEYS[$1]}"
}

records_key_is_known() { _schema_ensure "$1" && [[ -n ${_SCHEMA_REQ["$1|$2"]:-} ]]; }
records_key_is_repeatable() { [[ ${_SCHEMA_CARD["$1|$2"]:-single} == repeatable ]]; }
records_key_is_multiline() { [[ ${_SCHEMA_ML["$1|$2"]:-sl} == ml ]]; }
records_key_is_required() { [[ ${_SCHEMA_REQ["$1|$2"]:-opt} == req ]]; }

# ---------------------------------------------------------------------------
# 3. Diagnostics
# ---------------------------------------------------------------------------
# Every diagnostic is `path:line:col: CODE record-id message`, so it is
# greppable and an editor can jump to it (rules/RULE-FORMAT.md §13).
RECORDS_ERRORS=0
RECORDS_DIAGNOSTICS=()

records_diag() {
  local path=$1 line=$2 col=$3 code=$4 id=$5
  shift 5
  local msg="$path:$line:$col: $code ${id:--} $*"
  RECORDS_DIAGNOSTICS+=("$msg")
  case $code in
    # A W-class diagnostic is a rule-authoring note (a reviewed, deliberate
    # trade-off - e.g. W033, docs/FOUNDATION.md finding F4) meant for whoever
    # edits a *.rules file, not for someone running a scan against their own
    # project.  It is always recorded in RECORDS_DIAGNOSTICS above (so
    # tests/lint-rules.sh, which reads that array directly rather than
    # stderr, sees every one regardless), but only PRINTED here when
    # SCOURSH_SHOW_RULE_WARNINGS is set - scan.sh's --verbose flag - so a
    # normal scan run isn't opened with a wall of warnings nobody scanning
    # their own code can act on.
    W*)
      [[ ${SCOURSH_SHOW_RULE_WARNINGS:-} == true ]] || return 0
      ;;
    *) RECORDS_ERRORS=$(( RECORDS_ERRORS + 1 )) ;;
  esac
  printf '%s\n' "$msg" >&2
}

records_reset_diagnostics() {
  RECORDS_ERRORS=0
  RECORDS_DIAGNOSTICS=()
}

# ---------------------------------------------------------------------------
# 4. File-level checks (rules/RULE-FORMAT.md §3.1, codes E001-E004)
# ---------------------------------------------------------------------------

# A NUL cannot survive `read` into a shell variable, so it is located here with
# `read -d ''`, whose delimiter IS NUL: the first chunk read is everything before
# the first NUL, which gives its byte offset, its line, and its column exactly.
_records_check_nul() {
  local path=$1 chunk='' before nl_count col
  if IFS= read -r -d '' chunk <"$path"; then
    before=${#chunk}
    local tail=${chunk##*$'\n'}
    nl_count=${chunk//[!$'\n']/}
    records_diag "$path" "$(( ${#nl_count} + 1 ))" "$(( ${#tail} + 1 ))" E004 '' \
      "file contains NUL at byte offset $before"
    return 1
  fi
  return 0
}

_records_check_bom() {
  local path=$1 head3
  head3=$(head -c 3 -- "$path" 2>/dev/null || printf '%s' '')
  if [[ $head3 == $'\xEF\xBB\xBF' ]]; then
    records_diag "$path" 1 1 E003 '' 'file begins with a byte-order mark'
    return 1
  fi
  return 0
}

# UTF-8 validation, byte-exact, in pure bash under LC_ALL=C.
#
# Deliberately NOT in awk: `awk` hex source constants are a GNU extension, and
# BSD awk (onetrue awk 20200816) evaluates `0x80` as 0 - measured - so an awk
# validator written with hex bounds silently rejects every file.  That is the
# class of "confidently-stated shell fact" this project cannot afford.
#
# Rejects lone continuation bytes, truncated sequences, overlong forms, UTF-16
# surrogates (U+D800..U+DFFF), and anything above U+10FFFF.
# Prints the 1-based byte column of the first invalid byte, or nothing.
_records_line_utf8_bad_col() {
  local s=$1
  # Fast path: a line with no byte at or above 0x80 is valid UTF-8 by
  # construction, which is every line of a normal record file.
  [[ $s == *[$'\x80'-$'\xff']* ]] || return 0
  local n=${#s}
  local i=0 c need lo hi k d
  while (( i < n )); do
    printf -v c '%d' "'${s:i:1}"
    if (( c < 128 )); then i=$(( i + 1 )); continue; fi
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
    else printf '%s' "$(( i + 1 ))"; return 0
    fi
    if (( i + need >= n )); then printf '%s' "$(( i + 1 ))"; return 0; fi
    for (( k = 1; k <= need; k++ )); do
      printf -v d '%d' "'${s:i+k:1}"
      if (( k == 1 )); then
        (( d >= lo && d <= hi )) || { printf '%s' "$(( i + 1 ))"; return 0; }
      else
        (( d >= 128 && d <= 191 )) || { printf '%s' "$(( i + 1 ))"; return 0; }
      fi
    done
    i=$(( i + need + 1 ))
  done
  return 0
}

_records_utf8_first_bad() {
  local lineno=0 raw col
  while IFS= read -r raw || [[ -n $raw ]]; do
    lineno=$(( lineno + 1 ))
    col=$(_records_line_utf8_bad_col "$raw")
    if [[ -n $col ]]; then
      printf '%s %s' "$lineno" "$col"
      return 0
    fi
  done <"$1"
  return 0
}

_records_check_utf8() {
  local path=$1 bad line col
  bad=$(_records_utf8_first_bad "$path")
  if [[ -n $bad ]]; then
    line=${bad%% *}
    col=${bad##* }
    records_diag "$path" "$line" "$col" E001 '' 'file is not valid UTF-8'
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 5. Parsed-record storage
# ---------------------------------------------------------------------------
# Records live in a named SET so two files can be loaded at once (findings.sh
# holds the redaction rules and the severity rubric simultaneously).
declare -A _REC_S=()      # set|idx|key -> scalar value
declare -A _REC_L=()      # set|idx|key -> LF-joined repeated values
declare -A _REC_ORDER=()  # set|idx     -> LF-joined key order
declare -A _REC_LINE=()   # set|idx     -> line number the record starts at
declare -A _REC_N=()      # set         -> record count
declare -A _REC_PATH=()   # set         -> source path
declare -A _REC_SCHEMA=() # set         -> schema name
declare -A _REC_BYID=()   # set|id      -> idx
declare -A _REC_DIGEST=() # set|idx     -> rule_digest, computed lazily

records_count() { printf '%s' "${_REC_N[$1]:-0}"; }
records_path() { printf '%s' "${_REC_PATH[$1]:-}"; }
records_schema() { printf '%s' "${_REC_SCHEMA[$1]:-}"; }
records_line() { printf '%s' "${_REC_LINE["$1|$2"]:-0}"; }
records_id() { printf '%s' "${_REC_S["$1|$2|id"]:-}"; }
records_keys() { printf '%s' "${_REC_ORDER["$1|$2"]:-}"; }

records_has() { [[ -n ${_REC_S["$1|$2|$3"]+set} ]]; }

# Scalar access.  For a repeatable key this is the LAST value; use records_list.
records_field() {
  local v=${_REC_S["$1|$2|$3"]:-}
  printf '%s' "$v"
}

records_field_or() {
  if records_has "$1" "$2" "$3"; then records_field "$1" "$2" "$3"; else printf '%s' "$4"; fi
}

# LF-separated values of a repeatable key, in file order.
records_list() {
  printf '%s' "${_REC_L["$1|$2|$3"]:-}"
}

records_index_of_id() {
  local idx=${_REC_BYID["$1|$2"]:-}
  [[ -n $idx ]] || return 1
  printf '%s' "$idx"
}

records_clear() {
  local set=$1 k
  for k in "${!_REC_S[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_S[$k]'; done
  for k in "${!_REC_L[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_L[$k]'; done
  for k in "${!_REC_ORDER[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_ORDER[$k]'; done
  for k in "${!_REC_LINE[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_LINE[$k]'; done
  for k in "${!_REC_BYID[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_BYID[$k]'; done
  for k in "${!_REC_DIGEST[@]}"; do [[ $k == "$set|"* ]] && unset '_REC_DIGEST[$k]'; done
  unset '_REC_N[$set]' '_REC_PATH[$set]' '_REC_SCHEMA[$set]'
}

# `rule_digest` (docs/FOUNDATION.md tension 12): the SHA-256 of the record that
# defines a check.  Defined over the PARSED fields in file order rather than the
# raw bytes, so re-wrapping a comment or adding one does not report "rule
# changed" on every finding for that check, while any change to a key or a value
# does.
#   rule_digest = sha256( "rd/1" \0 key_1 \0 value_1 \0 key_2 \0 value_2 ... )
# Repeated keys contribute one key/value pair per occurrence, in file order.
records_digest() {
  local set=$1 idx=$2
  if [[ -n ${_REC_DIGEST["$set|$idx"]:-} ]]; then
    printf '%s' "${_REC_DIGEST["$set|$idx"]}"
    return 0
  fi
  local digest
  digest=$(_records_digest_stream "$set" "$idx" | sha256_of)
  _REC_DIGEST["$set|$idx"]=$digest
  printf '%s' "$digest"
}

# _REC_ORDER records a key once per OCCURRENCE, so a repeatable key appears in it
# as many times as it was authored.  Its values are emitted as a group the first
# time it is seen and skipped thereafter, which is what "one key/value pair per
# occurrence, in file order" means - and what stops a two-entry `tags` from
# contributing its values twice.
_records_digest_stream() {
  local set=$1 idx=$2 key val schema
  local -A seen=()
  schema=${_REC_SCHEMA[$set]:-}
  printf '%s' 'rd/1'
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    [[ -n ${seen[$key]:-} ]] && continue
    seen[$key]=1
    if records_key_is_repeatable "$schema" "$key"; then
      while IFS= read -r val; do
        printf '\0%s\0%s' "$key" "$val"
      done <<<"${_REC_L["$set|$idx|$key"]}"
    else
      printf '\0%s\0%s' "$key" "${_REC_S["$set|$idx|$key"]}"
    fi
  done <<<"${_REC_ORDER["$set|$idx"]}"
}

# ---------------------------------------------------------------------------
# 6. The parser (rules/RULE-FORMAT.md §7)
# ---------------------------------------------------------------------------
# `records_load PATH [SCHEMA] [SET]`
#
# SCHEMA defaults to the §9 path-table resolution of PATH relative to the
# install root; test fixtures and ad-hoc packs pass it explicitly.
# Returns non-zero if the file produced any error, having reported EVERY error
# it found.  It never repairs, never skips a bad record silently, and never
# partially loads a pack: on any error the set is left empty.
records_load() {
  local path=$1 schema=${2:-} set=${3:-default}
  local rel

  if [[ ! -r $path ]]; then
    records_diag "$path" 0 0 E070 '' 'record file is not readable'
    return 1
  fi

  if [[ -z $schema ]]; then
    rel=$(_records_relpath "$path")
    if ! schema=$(records_schema_for_path "$rel"); then
      records_diag "$path" 0 0 E070 '' 'record file matches no row of the §9 path table'
      return 1
    fi
  fi
  if ! _schema_ensure "$schema"; then
    records_diag "$path" 0 0 E070 '' "unknown schema '$schema'"
    return 1
  fi

  records_clear "$set"
  _REC_PATH[$set]=$path
  _REC_SCHEMA[$set]=$schema
  _REC_N[$set]=0

  local errs_before=$RECORDS_ERRORS
  local file_ok=0
  _records_check_nul "$path" || file_ok=1
  _records_check_bom "$path" || file_ok=1
  _records_check_utf8 "$path" || file_ok=1
  if (( file_ok != 0 )); then
    records_clear "$set"
    return 1
  fi

  _records_parse_lines "$path" "$schema" "$set"

  if (( RECORDS_ERRORS > errs_before )); then
    records_clear "$set"
    return 1
  fi
  return 0
}

_records_relpath() {
  local abs
  abs=$(realpath_of "$1")
  printf '%s' "${abs#"${SCOURSH_INSTALL_ROOT%/}"/}"
}

# The branch order below is exactly rules/RULE-FORMAT.md §3.2's test order and is
# not an implementation choice: several tests overlap and a different order
# accepts different files.
# SC2094 fires on every diagnostic below because the loop reads $path while
# records_diag mentions it; records_diag only writes to stderr and to arrays.
# shellcheck disable=SC2094
_records_parse_lines() {
  local path=$1 schema=$2 set=$3
  local lineno=0 raw
  local cur=-1 last_key='' idx
  local id_seen

  # `|| [[ -n $raw ]]` accepts a final line with no terminator and treats it as
  # a complete line (§3.1 rule 5).
  while IFS= read -r raw || [[ -n $raw ]]; do
    lineno=$(( lineno + 1 ))

    # CR is rejected here rather than in a whole-file pass so the diagnostic can
    # name the column.  A CRLF file would put a literal \r at the end of every
    # `pattern` value and the regex would silently fail to match at end of line.
    if [[ $raw == *$'\r'* ]]; then
      local pre=${raw%%$'\r'*}
      records_diag "$path" "$lineno" "$(( ${#pre} + 1 ))" E002 '' 'file contains CR (0x0D)'
      last_key=''
      continue
    fi

    # --- §3.2 test 1: Blank (zero bytes) ---
    if [[ -z $raw ]]; then
      cur=-1
      last_key=''
      continue
    fi

    # --- §3.2 test 2: whitespace-only.  MUST precede the Continuation test. ---
    if [[ $raw != *[!$'\x20'$'\x09']* ]]; then
      records_diag "$path" "$lineno" 1 E011 "$(_cur_id "$set" "$cur")" \
        'line is non-empty and entirely whitespace: not a separator, not a continuation'
      last_key=''
      continue
    fi

    # --- §3.2 test 3: leading TAB (with content; test 2 already ran) ---
    if [[ ${raw:0:1} == $'\t' ]]; then
      records_diag "$path" "$lineno" 1 E021 "$(_cur_id "$set" "$cur")" \
        'leading TAB used as indentation'
      last_key=''
      continue
    fi

    # --- §3.2 test 4: Comment.  The record continues; the field does not. ---
    if [[ ${raw:0:1} == '#' ]]; then
      last_key=''
      continue
    fi

    # --- §3.2 test 5: Continuation (first two bytes are 0x20 0x20) ---
    if [[ ${raw:0:2} == '  ' ]]; then
      if (( cur < 0 )); then
        records_diag "$path" "$lineno" 1 E015 '' 'continuation line with no preceding field'
        continue
      fi
      if [[ -z $last_key ]]; then
        records_diag "$path" "$lineno" 1 E012 "$(_cur_id "$set" "$cur")" \
          'comment line between a field line and its continuations'
        continue
      fi
      if ! records_key_is_multiline "$schema" "$last_key"; then
        records_diag "$path" "$lineno" 1 E016 "$(_cur_id "$set" "$cur")" \
          "continuation on key '$last_key', which is single-line only"
        continue
      fi
      _REC_S["$set|$cur|$last_key"]+=$'\n'"${raw:2}"
      continue
    fi

    # --- §3.2 test 6: Field ---
    if [[ ! $raw =~ ^([a-z][a-z0-9-]*):\ (.+)$ ]]; then
      # --- §3.2 test 7: Invalid ---
      if [[ $raw =~ ^[a-z][a-z0-9-]*:[\ ]*$ ]]; then
        records_diag "$path" "$lineno" 1 E013 "$(_cur_id "$set" "$cur")" \
          'field line with an empty value'
      else
        records_diag "$path" "$lineno" 1 E010 "$(_cur_id "$set" "$cur")" \
          'line matches no line kind in §3.2'
      fi
      last_key=''
      continue
    fi
    local key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}

    if (( cur < 0 )); then
      if [[ $key != id ]]; then
        records_diag "$path" "$lineno" 1 E020 '' "record's first field is '$key', not 'id'"
        # Open the record anyway so later lines are still classified and every
        # error in the file is reported rather than only the first.
      fi
      idx=${_REC_N[$set]}
      cur=$idx
      _REC_N[$set]=$(( idx + 1 ))
      _REC_LINE["$set|$cur"]=$lineno
      _REC_ORDER["$set|$cur"]=''
    fi

    if ! records_key_is_known "$schema" "$key"; then
      records_diag "$path" "$lineno" 1 E017 "$(_cur_id "$set" "$cur")" \
        "unknown key '$key' for schema '$schema'"
      last_key=''
      continue
    fi

    if records_key_is_repeatable "$schema" "$key"; then
      if [[ -n ${_REC_L["$set|$cur|$key"]:-} ]]; then
        _REC_L["$set|$cur|$key"]+=$'\n'"$value"
      else
        _REC_L["$set|$cur|$key"]=$value
      fi
      _REC_S["$set|$cur|$key"]=$value
    else
      if [[ -n ${_REC_S["$set|$cur|$key"]+set} ]]; then
        records_diag "$path" "$lineno" 1 E014 "$(_cur_id "$set" "$cur")" \
          "duplicate single key '$key'"
        last_key=$key
        continue
      fi
      _REC_S["$set|$cur|$key"]=$value
    fi
    _REC_ORDER["$set|$cur"]+="$key"$'\n'

    if [[ $key == id ]]; then
      id_seen=${_REC_BYID["$set|$value"]:-}
      if [[ -n $id_seen ]]; then
        records_diag "$path" "$lineno" 1 E019 "$value" \
          "duplicate id '$value' (first seen at record $id_seen)"
      else
        _REC_BYID["$set|$value"]=$cur
      fi
    fi
    last_key=$key
  done <"$path"
}

_cur_id() {
  local set=$1 idx=$2
  (( idx >= 0 )) || { printf '%s' ''; return 0; }
  printf '%s' "${_REC_S["$set|$idx|id"]:-}"
}

# `records_register_checks SET` - record every check id in SET as having run.
#
# DESIGN §4 asks run.json for "which checks ran/skipped and why".  Only the
# skipped half existed, so a reader could not tell "this check ran and found
# nothing" from "this check was never loaded" - the distinction §15's honesty
# requirement rests on.
#
# This is the set of checks the run LOADED AND EXECUTED.  It is not tension 12's
# `covered_checks`, which is per-(check, cell) coverage persisted in `state/` and
# is owned by §13 step 7; a check can appear here and still be uncovered for a
# cell the run never visited.
records_register_checks() {
  local set=$1 schema n i
  schema=${_REC_SCHEMA[$set]:-}
  records_schema_is_check_id "$schema" || return 0
  n=$(records_count "$set")
  for (( i = 0; i < n; i++ )); do
    run_record checks_run "$(records_id "$set" "$i")"
  done
}

# ---------------------------------------------------------------------------
# 7. Schema validation (rules/RULE-FORMAT.md §9 and §13)
# ---------------------------------------------------------------------------
# Split from the parser: the parser owns §3-§7 (syntax) and must run before any
# schema question can be asked, while these checks need the whole file.
# `records_validate SET` reports and counts; it does not clear the set.
records_validate() {
  local set=$1 schema path n i
  schema=${_REC_SCHEMA[$set]:-}
  path=${_REC_PATH[$set]:-}
  n=$(records_count "$set")
  local before=$RECORDS_ERRORS
  local literal
  if literal=$(_schema_single_record_id "$schema"); then
    if (( n != 1 )); then
      records_diag "$path" 1 1 E071 '' \
        "single-record schema '$schema' holds $n records, expected exactly 1"
    elif [[ $(records_id "$set" 0) != "$literal" ]]; then
      records_diag "$path" "$(records_line "$set" 0)" 1 E071 "$(records_id "$set" 0)" \
        "single-record schema '$schema' must have id '$literal'"
    fi
  fi
  for (( i = 0; i < n; i++ )); do
    _records_validate_record "$set" "$i" "$schema" "$path"
  done
  (( RECORDS_ERRORS == before ))
}

_records_validate_record() {
  local set=$1 i=$2 schema=$3 path=$4
  local id line key v
  id=$(records_id "$set" "$i")
  line=$(records_line "$set" "$i")

  # E023 missing required key
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    if records_key_is_required "$schema" "$key" && ! records_has "$set" "$i" "$key"; then
      records_diag "$path" "$line" 1 E023 "$id" "missing required key '$key'"
    fi
  done <<<"$(records_schema_keys "$schema")"

  # E027 id form, per namespace (§9.1.1a)
  _records_check_id_form "$set" "$i" "$schema" "$path" "$line" "$id"

  # E018 module component versus owning module
  if records_schema_is_check_id "$schema" && [[ -n $path ]]; then
    local rel owner
    rel=$(_records_relpath "$path")
    if owner=$(records_owning_module "$rel"); then
      if [[ ${id%%-*} != "$owner" ]]; then
        records_diag "$path" "$line" 1 E018 "$id" \
          "id module component '${id%%-*}' does not match owning module '$owner'"
      fi
    elif [[ $(basename -- "$rel") == checks.rules ]]; then
      records_diag "$path" "$line" 1 E081 "$id" \
        'checks.rules sits outside every prefix of the §9.5.1 owning-module map'
    fi
  fi

  # E024 enums
  _records_check_enum "$set" "$i" "$path" "$line" "$id" severity critical high medium low info
  _records_check_enum "$set" "$i" "$path" "$line" "$id" confidence high medium low
  _records_check_enum "$set" "$i" "$path" "$line" "$id" dialect ere pcre
  _records_check_enum "$set" "$i" "$path" "$line" "$id" severity-floor critical high medium low info
  _records_check_enum "$set" "$i" "$path" "$line" "$id" severity-ceiling critical high medium low info
  _records_check_enum "$set" "$i" "$path" "$line" "$id" allow-subdomains true false
  _records_check_enum "$set" "$i" "$path" "$line" "$id" allow-private-addresses true false
  _records_check_enum "$set" "$i" "$path" "$line" "$id" redact-secrets true false
  _records_check_enum "$set" "$i" "$path" "$line" "$id" expect present absent equals at-least at-most
  _records_check_enum "$set" "$i" "$path" "$line" "$id" fact exposure auth sensitive-data confidence
  _records_check_enum "$set" "$i" "$path" "$line" "$id" correlate-on none target account account-region file
  _records_check_enum "$set" "$i" "$path" "$line" "$id" mode \
    bearer api-key form oauth2-password oauth2-client srp external
  case $schema in
    auth-identity)
      _records_check_auth_mode "$set" "$i" "$path" "$line" "$id"
      ;;
    derived)
      _records_check_enum "$set" "$i" "$path" "$line" "$id" kind derived
      ;;
    redaction)
      v=$(records_field "$set" "$i" kind)
      if [[ -n $v && ! $v =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        records_diag "$path" "$line" 1 E024 "$id" "kind '$v' does not match ^[A-Z][A-Z0-9_]*$"
      fi
      ;;
    script-check)
      _records_check_coverage_scope "$set" "$i" "$path" "$line" "$id"
      ;;
  esac

  # E025 / E026
  if records_has "$set" "$i" cwe; then
    v=$(records_field "$set" "$i" cwe)
    [[ $v =~ ^(CWE-[0-9]+|none)$ ]] \
      || records_diag "$path" "$line" 1 E025 "$id" "cwe '$v' does not match ^(CWE-[0-9]+|none)$"
  fi
  if records_has "$set" "$i" owasp; then
    v=$(records_field "$set" "$i" owasp)
    [[ $v =~ ^(A[0-9]{2}:[0-9]{4}|none)$ ]] \
      || records_diag "$path" "$line" 1 E026 "$id" "owasp '$v' does not match ^(A[0-9]{2}:[0-9]{4}|none)$"
  fi

  # E029 floor above ceiling
  if records_has "$set" "$i" severity-floor && records_has "$set" "$i" severity-ceiling; then
    local fl ce
    fl=$(severity_rank "$(records_field "$set" "$i" severity-floor)")
    ce=$(severity_rank "$(records_field "$set" "$i" severity-ceiling)")
    (( fl <= ce )) || records_diag "$path" "$line" 1 E029 "$id" \
      'severity-floor is above severity-ceiling'
  fi

  # E045 format-version
  if records_has "$set" "$i" format-version; then
    v=$(records_field "$set" "$i" format-version)
    [[ $v == 1 ]] || records_diag "$path" "$line" 1 E045 "$id" \
      "format-version '$v' is not 1"
  fi

  # E031 / E032 the context directive (§10)
  if records_has "$set" "$i" context-window; then
    v=$(records_field "$set" "$i" context-window)
    if ! records_has "$set" "$i" context-require && ! records_has "$set" "$i" context-deny; then
      records_diag "$path" "$line" 1 E031 "$id" \
        'context-window with no context-require and no context-deny'
    fi
    if [[ ! $v =~ ^(0|[1-9][0-9]*)$ ]] || (( v > 50 )); then
      records_diag "$path" "$line" 1 E032 "$id" \
        "context-window '$v' is not a non-negative integer at or below 50"
    fi
  fi

  # W033 (docs/FOUNDATION.md finding F4, §10.2): a context-deny with an
  # effective window above 0 can silently suppress a genuine, unrelated
  # finding whose only fault is sharing a window with the deny token - a
  # false negative masquerading as a fix once tension 12 sees it (the
  # suppressed match is reported `fixed`, not `new`).  A same-line-intent
  # guard (the common case - a literal flag on the matched call itself) must
  # pin `context-window: 0`; §12.1's `SAST-SEC-AWS_AKID-01` and the corrected
  # §12.2 `SAST-PY-YAML_LOAD-01` both do.  The window defaults to 2
  # (rules/RULE-FORMAT.md §10.1) when the key is absent, so an ABSENT
  # context-window with a context-deny present is the same hazard and must
  # warn too - only checking an EXPLICIT value would miss the common case
  # where an author never wrote context-window at all.  Deliberately a
  # warning (`W*` never increments RECORDS_ERRORS, records_diag) rather than
  # an error: a wider deny window is sometimes a deliberate, reviewed
  # trade-off (§10.2), never a syntax mistake.
  if records_has "$set" "$i" context-deny; then
    local ctx_win=2
    records_has "$set" "$i" context-window && ctx_win=$(records_field "$set" "$i" context-window)
    if [[ $ctx_win =~ ^[0-9]+$ ]] && (( ctx_win > 0 )); then
      records_diag "$path" "$line" 1 W033 "$id" \
        "context-deny with context-window $ctx_win (effective) can silently suppress a genuine finding within the window; use context-window: 0 for a same-line-intent guard (docs/FOUNDATION.md finding F4, §10.2)"
    fi
  fi

  # E030 trailing space on a regex value; W022 elsewhere (§5.3)
  _records_check_trailing_space "$set" "$i" "$path" "$line" "$id" "$schema"

  # E042 glob operators (§9.1.2)
  local g
  for key in files exclude-files include-path exclude-path; do
    if records_has "$set" "$i" "$key"; then
      while IFS= read -r g; do
        [[ -n $g ]] || continue
        # shellcheck disable=SC1003
        if [[ $g == *'\'* || $g == *'{'* || $g == *'}'* ]]; then
          records_diag "$path" "$line" 1 E042 "$id" \
            "$key glob '$g' uses \\ or {} ; brace expansion is not supported"
        fi
      done <<<"$(records_list "$set" "$i" "$key")"
    fi
  done

  # §8: regex dialect subset, complexity, and compilability
  _records_check_regexes "$set" "$i" "$path" "$line" "$id"

  # §9.1.3 tags
  _records_check_tags "$set" "$i" "$path" "$line" "$id" "$schema"

  # §9.2 derived-record structure (contributor existence is E051/E052 and needs
  # the whole catalog, so it lives in the linter, not here).
  if [[ $schema == derived ]]; then
    if ! records_has "$set" "$i" requires && ! records_has "$set" "$i" any-of; then
      records_diag "$path" "$line" 1 E050 "$id" 'derived record has neither requires nor any-of'
    fi
  fi
}

_records_check_id_form() {
  local set=$1 i=$2 schema=$3 path=$4 line=$5 id=$6
  local re_check='^(SAST|SCA|IAC|DAST|CLOUD|POSTURE|COMPOSITE)-[A-Z0-9]+-[A-Z0-9_]+(-[0-9]{2})?$'
  local re_lower='^[a-z][a-z0-9-]*$'
  case $schema in
    derived)
      if [[ ! $id =~ $re_check ]]; then
        records_diag "$path" "$line" 1 E027 "$id" 'id does not match the check-id form (§9.1.1)'
      elif [[ $id =~ -[0-9]{2}$ ]]; then
        records_diag "$path" "$line" 1 E027 "$id" \
          'a derived id MUST omit the SEQ suffix (§9.1.1)'
      fi
      ;;
    pattern-rule | redaction | script-check)
      if [[ ! $id =~ $re_check ]]; then
        records_diag "$path" "$line" 1 E027 "$id" 'id does not match the check-id form (§9.1.1)'
      elif [[ ! $id =~ -[0-9]{2}$ ]]; then
        records_diag "$path" "$line" 1 E027 "$id" \
          'the SEQ suffix is required outside the derived schema (§9.1.1)'
      fi
      ;;
    auth-identity)
      [[ $id =~ ^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$ ]] \
        || records_diag "$path" "$line" 1 E027 "$id" 'id must be <target-id>.<label>'
      ;;
    scanner-config) ;;                       # frozen literal, checked by E071
    *)
      [[ $id =~ $re_lower ]] \
        || records_diag "$path" "$line" 1 E027 "$id" 'id must match ^[a-z][a-z0-9-]*$'
      ;;
  esac
}

# E074, rules/RULE-FORMAT.md §9.6.2: "Which optional keys are required is a
# function of `mode`, checked as `E074`."
#
# §9.6.2 states that the rule exists and freezes the key set, but not the table
# itself, so the table is stated HERE, once, and modules/dast/auth_engine.sh
# consumes these modes rather than restating which keys each one needs - two
# copies of it would drift, and the copy an operator's config is validated
# against would stop being the copy the login path actually reads.
#
# Two shapes of requirement, because the schema has two.  `need` is a plain
# required key.  `alt` is a set of which AT LEAST ONE must be present, which is
# how §9.6.2 expresses the credential itself: `secret-file` is "preferred over
# inline values", so an inline `token` / `password` / `client-secret` is a legal
# alternative rather than a second required key, and a record naming neither has
# no credential at all.
#
# `srp` requires a TOKEN rather than a username and a pool: docs/DESIGN.md §7.0
# offers the implementer a choice - "compute the SRP handshake in shell, or
# accept a pre-obtained token to avoid re-implementing crypto" - and this
# repository takes the second, so a record supplying only a username and a
# pool-id would validate and then be unable to authenticate.  E074 says so at
# config-load time instead.
_records_check_auth_mode() {
  local set=$1 i=$2 path=$3 line=$4 id=$5
  local mode k found
  local -a need=() alt=()
  mode=$(records_field "$set" "$i" mode)
  case $mode in
    bearer | api-key | external | srp) alt=(token secret-file) ;;
    form) need=(username login-path); alt=(password secret-file) ;;
    oauth2-password) need=(token-url username); alt=(password secret-file) ;;
    oauth2-client) need=(token-url client-id); alt=(client-secret secret-file) ;;
    # An unrecognised mode is E024's to report; reporting it twice would make
    # one typo look like two separate faults.
    *) return 0 ;;
  esac

  for k in "${need[@]+"${need[@]}"}"; do
    records_has "$set" "$i" "$k" \
      || records_diag "$path" "$line" 1 E074 "$id" \
        "mode '$mode' requires '$k', which this record does not set (§9.6.2)"
  done

  found=0
  for k in "${alt[@]+"${alt[@]}"}"; do
    records_has "$set" "$i" "$k" && found=1
  done
  if (( ! found )) && (( ${#alt[@]} > 0 )); then
    if [[ $mode == srp ]]; then
      records_diag "$path" "$line" 1 E074 "$id" \
        "mode 'srp' requires a pre-obtained token, via 'secret-file' (preferred) or 'token'; scoursh does not compute the SRP handshake itself (docs/DESIGN.md §7.0 permits either, and this build accepts the token), so a username and a pool-id alone cannot authenticate (§9.6.2)"
    else
      records_diag "$path" "$line" 1 E074 "$id" \
        "mode '$mode' requires a credential: one of ${alt[*]}, with 'secret-file' preferred over an inline value (§9.6.2)"
    fi
  fi
  return 0
}

_records_check_coverage_scope() {
  local set=$1 i=$2 path=$3 line=$4 id=$5
  local mod=${id%%-*} want v
  v=$(records_field "$set" "$i" coverage-scope)
  case $mod in
    SAST | SCA | IAC) want='path-root' ;;
    DAST) want='target' ;;
    CLOUD) want='account-region' ;;
    POSTURE) want='scope-key' ;;
    *) return 0 ;;
  esac
  [[ $v == "$want" ]] || records_diag "$path" "$line" 1 E079 "$id" \
    "coverage-scope '$v' is not '$want', the required value for module $mod (§9.5.1)"
}

_records_check_enum() {
  local set=$1 i=$2 path=$3 line=$4 id=$5 key=$6
  shift 6
  records_has "$set" "$i" "$key" || return 0
  local v c
  v=$(records_field "$set" "$i" "$key")
  for c in "$@"; do
    [[ $v == "$c" ]] && return 0
  done
  records_diag "$path" "$line" 1 E024 "$id" "$key '$v' is outside its permitted set: $*"
}

# §5.3: because there is no trimming, a value can legally end in a space, and a
# space is invisible.  On a regex value that is an error (E030) and the author is
# directed to write [ ] or \s; elsewhere it is a warning (W022).
_records_check_trailing_space() {
  local set=$1 i=$2 path=$3 line=$4 id=$5 schema=$6
  local key v
  local -A seen=()
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    # Once per key, not once per occurrence, or a repeatable key's values would
    # each be reported as many times as the key was authored.
    [[ -n ${seen[$key]:-} ]] && continue
    seen[$key]=1
    if records_key_is_repeatable "$schema" "$key"; then
      while IFS= read -r v; do
        _records_trailing_space_one "$path" "$line" "$id" "$key" "$v"
      done <<<"${_REC_L["$set|$i|$key"]}"
    else
      _records_trailing_space_one "$path" "$line" "$id" "$key" "${_REC_S["$set|$i|$key"]}"
    fi
  done <<<"${_REC_ORDER["$set|$i"]}"
}

_records_trailing_space_one() {
  local path=$1 line=$2 id=$3 key=$4 v=$5
  [[ $v == *' ' || $v == *$'\t' ]] || return 0
  case $key in
    pattern | context-require | context-deny)
      records_diag "$path" "$line" 1 E030 "$id" \
        "$key value ends in whitespace; write [ ] or \\s instead"
      ;;
    *)
      records_diag "$path" "$line" 1 W022 "$id" "trailing whitespace on '$key'"
      ;;
  esac
}

_records_check_tags() {
  local set=$1 i=$2 path=$3 line=$4 id=$5 schema=$6
  case $schema in
    pattern-rule | derived | script-check) ;;
    *) return 0 ;;
  esac
  records_has "$set" "$i" tags || {
    if [[ $schema == script-check ]]; then return 0; fi   # E023 already fired
    if [[ $schema == pattern-rule ]]; then
      records_diag "$path" "$line" 1 E044 "$id" 'no type tag (§9.1.3 requires exactly one)'
    fi
    return 0
  }
  local t types=0 want
  case $schema in
    pattern-rule) want='static' ;;
    derived) want='derived' ;;
    script-check) want='passive safe-active active config-read posture' ;;
  esac
  while IFS= read -r t; do
    [[ -n $t ]] || continue
    case $t in
      static | passive | safe-active | active | config-read | posture | derived)
        types=$(( types + 1 ))
        if [[ " $want " != *" $t "* ]]; then
          records_diag "$path" "$line" 1 E044 "$id" \
            "type tag '$t' is illegal for schema '$schema' (expected one of: $want)"
        fi
        ;;
      intrusive)
        if [[ $schema == pattern-rule ]]; then
          records_diag "$path" "$line" 1 E043 "$id" 'intrusive tag on a pattern rule'
        fi
        ;;
      quick | compliance) ;;
      *)
        records_diag "$path" "$line" 1 E044 "$id" "tag '$t' is outside the §9.1.3 vocabulary"
        ;;
    esac
  done <<<"$(records_list "$set" "$i" tags)"
  (( types == 1 )) || records_diag "$path" "$line" 1 E044 "$id" \
    "expected exactly one type tag, found $types"
}

# ---------------------------------------------------------------------------
# 8. Regex checks (rules/RULE-FORMAT.md §8, codes E040, E041, E046)
# ---------------------------------------------------------------------------
_records_check_regexes() {
  local set=$1 i=$2 path=$3 line=$4 id=$5
  local dialect key v
  dialect=$(records_field_or "$set" "$i" dialect ere)
  local schema=${_REC_SCHEMA[$set]:-}
  for key in pattern context-require context-deny; do
    records_has "$set" "$i" "$key" || continue
    if records_key_is_repeatable "$schema" "$key"; then
      while IFS= read -r v; do
        [[ -n $v ]] || continue
        _records_check_one_regex "$path" "$line" "$id" "$key" "$v" "$dialect"
      done <<<"$(records_list "$set" "$i" "$key")"
    else
      _records_check_one_regex "$path" "$line" "$id" "$key" \
        "$(records_field "$set" "$i" "$key")" "$dialect"
    fi
  done
}

_records_check_one_regex() {
  local path=$1 line=$2 id=$3 key=$4 re=$5 dialect=$6
  local bad
  if [[ $dialect == ere ]]; then
    if bad=$(records_ere_violation "$re"); then
      records_diag "$path" "$line" 1 E040 "$id" \
        "$key uses '$bad', which is outside the §8.2 portable ERE subset"
    fi
  fi
  if records_regex_has_nested_unbounded "$re"; then
    records_diag "$path" "$line" 1 E041 "$id" \
      "$key contains nested unbounded quantification (catastrophic-backtracking shape)"
  fi
  # E046: does it compile under its declared dialect?
  if [[ $dialect == ere ]]; then
    if ! _records_regex_compiles "$re"; then
      records_diag "$path" "$line" 1 E046 "$id" "$key does not compile as an ERE"
    fi
  elif core_has_pcre; then
    if ! _records_regex_compiles_pcre "$re"; then
      records_diag "$path" "$line" 1 E046 "$id" "$key does not compile as a PCRE"
    fi
  fi
}

_records_regex_compiles() {
  local rc=0
  "${SCOURSH_GREP[@]+"${SCOURSH_GREP[@]}"}" -e "$1" /dev/null >/dev/null 2>&1 || rc=$?
  (( rc <= 1 ))
}

_records_regex_compiles_pcre() {
  local rc=0
  "${SCOURSH_GREP_PCRE[@]+"${SCOURSH_GREP_PCRE[@]}"}" -e "$1" /dev/null >/dev/null 2>&1 || rc=$?
  (( rc <= 1 ))
}

# Returns 0 and prints the offending construct when the pattern leaves the §8.2
# portable ERE subset.  Backslash escapes and bracket expressions are tracked so
# an escaped or bracketed occurrence is not a false positive.
# SC1003 fires on the case patterns matching a literal backslash, which is what
# they are for.
# shellcheck disable=SC1003
records_ere_violation() {
  local re=$1
  # `local re=$1 n=${#re}` would evaluate ${#re} BEFORE re is assigned (bash
  # gives 0), so the length is taken on its own line.
  local n=${#re}
  local i=0 ch nxt in_class=0
  while (( i < n )); do
    ch=${re:i:1}
    if (( in_class )); then
      case $ch in
        '\') i=$(( i + 2 )); continue ;;
        ']') in_class=0 ;;
      esac
      i=$(( i + 1 ))
      continue
    fi
    case $ch in
      '\')
        nxt=${re:i+1:1}
        case $nxt in
          [1-9]) printf '%s' "\\$nxt"; return 0 ;;
          A | z | Z | K) printf '%s' "\\$nxt"; return 0 ;;
        esac
        i=$(( i + 2 ))
        continue
        ;;
      '[')
        in_class=1
        # A ] immediately after [ or [^ is a literal ]
        if [[ ${re:i+1:1} == '^' ]]; then i=$(( i + 1 )); fi
        if [[ ${re:i+1:1} == ']' ]]; then i=$(( i + 1 )); fi
        ;;
      '(')
        if [[ ${re:i+1:1} == '?' ]]; then
          printf '%s' "${re:i:3}"
          return 0
        fi
        ;;
      '*' | '+' | '?')
        nxt=${re:i+1:1}
        case $nxt in
          '?') printf '%s' "$ch?"; return 0 ;;      # lazy quantifier
          '+') printf '%s' "$ch+"; return 0 ;;      # possessive quantifier
        esac
        ;;
    esac
    i=$(( i + 1 ))
  done
  return 1
}

# §8.4: a * or + applied to a group that itself contains an unbounded
# quantifier, such as (a+)+ or (\s*\w*)*.  An unbounded quantifier on a single
# character class is fine.
# shellcheck disable=SC1003
records_regex_has_nested_unbounded() {
  local re=$1
  local n=${#re}
  local i=0 ch nxt in_class=0
  local -a stack=()
  local top
  while (( i < n )); do
    ch=${re:i:1}
    if (( in_class )); then
      case $ch in
        '\') i=$(( i + 2 )); continue ;;
        ']') in_class=0 ;;
      esac
      i=$(( i + 1 ))
      continue
    fi
    case $ch in
      '\') i=$(( i + 2 )); continue ;;
      '[')
        in_class=1
        if [[ ${re:i+1:1} == '^' ]]; then i=$(( i + 1 )); fi
        if [[ ${re:i+1:1} == ']' ]]; then i=$(( i + 1 )); fi
        ;;
      '(') stack+=(0) ;;
      ')')
        if (( ${#stack[@]} > 0 )); then
          top=${stack[-1]}
          unset 'stack[-1]'
          nxt=${re:i+1:1}
          if (( top == 1 )) && { [[ $nxt == '*' || $nxt == '+' ]] || _is_unbounded_brace "$re" "$(( i + 1 ))"; }; then
            return 0
          fi
          # An unbounded quantifier inside this group also counts for the group
          # enclosing it.
          if (( ${#stack[@]} > 0 )) && (( top == 1 )); then stack[-1]=1; fi
        fi
        ;;
      '*' | '+')
        if (( ${#stack[@]} > 0 )); then stack[-1]=1; fi
        ;;
      '{')
        if _is_unbounded_brace "$re" "$i" && (( ${#stack[@]} > 0 )); then stack[-1]=1; fi
        ;;
    esac
    i=$(( i + 1 ))
  done
  return 1
}

# True when position $2 in $1 starts a `{n,}` (an unbounded repetition).
_is_unbounded_brace() {
  local re=$1 pos=$2 rest=${1:$2}
  [[ ${re:pos:1} == '{' ]] || return 1
  [[ $rest =~ ^\{[0-9]+,\} ]]
}

# ---------------------------------------------------------------------------
# 9. Severity ordering (shared with lib/findings.sh)
# ---------------------------------------------------------------------------
severity_rank() {
  case $1 in
    info) printf '%s' 0 ;;
    low) printf '%s' 1 ;;
    medium) printf '%s' 2 ;;
    high) printf '%s' 3 ;;
    critical) printf '%s' 4 ;;
    *) printf '%s' -1 ;;
  esac
}

severity_name() {
  case $1 in
    0) printf '%s' info ;;
    1) printf '%s' low ;;
    2) printf '%s' medium ;;
    3) printf '%s' high ;;
    4) printf '%s' critical ;;
    *) printf '%s' info ;;
  esac
}
