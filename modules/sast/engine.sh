#!/usr/bin/env bash
# modules/sast/engine.sh - the native SAST pattern engine (docs/DESIGN.md §6.1,
# §13 step 3).
#
# Owns:
#   docs/DESIGN.md      §6.1 "native tier: a bash pattern engine ... walks the
#                        repo, applies per-language rule packs, emits findings"
#   docs/FOUNDATION.md  tension 2's "the walker that §13 step 3 builds,
#                        alongside files/exclude-files" obligation
#   docs/FOUNDATION.md  tension 3 / rules/RULE-FORMAT.md §10 - the context
#                        directive.  THIS is the first ticket that evaluates
#                        it: nothing before §13 step 3 has a rule engine.
#   docs/FOUNDATION.md  tension 5 - fingerprints with no line number, the
#                        occurrence ordinal for repeat matches in one file.
#
# A pure function library: sourced once, defines functions, no side effects at
# source time (modules/sast/run.sh is the file that DOES something when
# sourced).  Every regex is matched only through lib/core.sh's scan_match /
# scan_match_offsets / scan_match_stdin - tension 4 rule 2 forbids bare
# grep/rg repository-wide, and this file is not exempt.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SAST_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SAST_ENGINE_SOURCED=1

# `scan_dispatch` resolves modules relative to $SCOURSH_INSTALL_ROOT
# (lib/checks.sh's own comment on checks_registry_load), which can be a
# fixture root entirely separate from wherever the REAL lib/ directory
# lives (tests/suites/sast.sh's own check-selection integration case
# exercises exactly that: a fixture root carrying only config/ and
# modules/sast/, no lib/ sibling at all).  When scan.sh runs normally it has
# ALREADY sourced lib/report.sh and lib/config.sh from ITS OWN directory
# before scan_dispatch ever runs (scan.sh section 1) - both guard against a
# second source and would be a no-op here regardless - so the self-relative
# path below is needed, and safe to resolve, ONLY for the standalone case
# (tests/suites/sast.sh sourcing this file directly, where the real lib/ is
# genuinely two directories up from the real engine.sh).  Skipping it
# whenever an outer caller already sourced these is what keeps a
# copied-into-a-fixture-root engine.sh from failing on a lib/ that was never
# meant to be there.
if [[ -z ${SCOURSH_REPORT_SOURCED:-} ]]; then
  # shellcheck source=lib/report.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/report.sh"
fi
if [[ -z ${SCOURSH_CONFIG_SOURCED:-} ]]; then
  # shellcheck source=lib/config.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/config.sh"
fi

# ---------------------------------------------------------------------------
# 1. Directory walk
# ---------------------------------------------------------------------------
# Directories never worth walking, regardless of any rule's own `files` /
# `exclude-files` (rules/RULE-FORMAT.md §9.1.2), which cannot see them at all:
# scan_match takes one file at a time (docs/FOUNDATION.md tension 2 - "file
# enumeration is the caller's job"), so nothing upstream of this walker ever
# had a chance to skip `.git`'s packed objects.  `history.sh` (docs/DESIGN.md
# §6.3) is the module that deliberately DOES read git history; the working-
# tree walker here must not duplicate that by wandering into `.git` itself.
# This is a WALKER-level default, separate from and in addition to the
# per-rule `files` / `exclude-files` glob (§9.1.2), never a replacement for
# it - exactly the split tension 2 records as this ticket's obligation.
SAST_DEFAULT_EXCLUDE_DIRS=(.git node_modules vendor .venv venv __pycache__
  .mypy_cache .pytest_cache .tox dist build reports state .terraform)

_sast_dir_excluded() {
  local base=$1
  local d
  for d in "${SAST_DEFAULT_EXCLUDE_DIRS[@]+"${SAST_DEFAULT_EXCLUDE_DIRS[@]}"}"; do
    [[ $base == "$d" ]] && return 0
  done
  return 1
}

# sast_walk_files ROOT - prints one scan-root-relative path per line, in
# LC_ALL=C sorted order (rules/RULE-FORMAT.md §7's reproducibility contract),
# skipping SAST_DEFAULT_EXCLUDE_DIRS at any depth.  ROOT itself may be a file
# (a `--path` naming one file directly) or a directory.
sast_walk_files() {
  local root=$1
  if [[ -f $root ]]; then
    printf '%s\n' "$root"
    return 0
  fi
  local -a prune=()
  local d first=1
  for d in "${SAST_DEFAULT_EXCLUDE_DIRS[@]+"${SAST_DEFAULT_EXCLUDE_DIRS[@]}"}"; do
    (( first )) || prune+=(-o)
    prune+=(-path "$root/*/$d" -o -path "$root/$d")
    first=0
  done
  find "$root" \( "${prune[@]+"${prune[@]}"}" \) -prune -o -type f -print 2>/dev/null | LC_ALL=C sort
}

# sast_relpath ROOT PATH - PATH relative to ROOT, or "." when they are equal
# (mirrors lib/core.sh's path_root_cell, which does the same for the scan
# root cell rather than a single file).
sast_relpath() {
  local root=$1 path=$2
  if [[ $path == "$root" ]]; then
    printf '.'
    return 0
  fi
  local rel=${path#"$root"/}
  printf '%s' "$rel"
}

# ---------------------------------------------------------------------------
# 2. `files` / `exclude-files` glob matching (rules/RULE-FORMAT.md §9.1.2)
# ---------------------------------------------------------------------------
# Translates a §9.1.2 glob to a portable ERE anchored with ^...$, then matches
# with bash's own `=~` (system regcomp).  This is glob-to-anchor translation
# only - no user-authored regex ever reaches this path (`pattern`,
# `context-require`, `context-deny` always go through scan_match /
# scan_match_stdin, never here) - so tension 2's "bash =~ lacks \b\w\s\d on
# BSD" hazard does not apply: nothing produced by _sast_glob_to_ere uses them.
_sast_glob_to_ere() {
  local g=$1
  local out='' i=0 n=${#g} c j
  while (( i < n )); do
    c=${g:i:1}
    case $c in
      '*')
        if [[ ${g:i:2} == '**' ]]; then
          out+='.*'
          i=$(( i + 2 ))
          continue
        fi
        out+='[^/]*'
        ;;
      '?') out+='[^/]' ;;
      '[')
        j=$(( i + 1 ))
        if [[ ${g:j:1} == '^' || ${g:j:1} == '!' ]]; then j=$(( j + 1 )); fi
        if [[ ${g:j:1} == ']' ]]; then j=$(( j + 1 )); fi
        while (( j < n )) && [[ ${g:j:1} != ']' ]]; do j=$(( j + 1 )); done
        out+=${g:i:$(( j - i + 1 ))}
        i=$j
        ;;
      '.' | '^' | '$' | '+' | '(' | ')' | '|')
        out+="\\$c"
        ;;
      *) out+=$c ;;
    esac
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

# sast_glob_match GLOB PATH - true if PATH (scan-root-relative, `/`-separated)
# matches GLOB per §9.1.2.  An unanchored glob (no leading `/`) may match at
# any depth, so it is tried against every path-segment-aligned suffix of PATH.
sast_glob_match() {
  local glob=$1 path=$2 ere anchored=0
  if [[ ${glob:0:1} == / ]]; then
    anchored=1
    glob=${glob#/}
  fi
  ere=$(_sast_glob_to_ere "$glob")
  if (( anchored )); then
    [[ $path =~ ^$ere$ ]]
  else
    [[ $path =~ ^(.*/)?$ere$ ]]
  fi
}

# sast_rule_matches_file SET IDX RELPATH - applies `files` (OR, default "every
# file") then `exclude-files` (removes matches, applied after).
sast_rule_matches_file() {
  local set=$1 idx=$2 relpath=$3 g matched=0
  if records_has "$set" "$idx" files; then
    while IFS= read -r g; do
      [[ -n $g ]] || continue
      if sast_glob_match "$g" "$relpath"; then
        matched=1
        break
      fi
    done <<<"$(records_list "$set" "$idx" files)"
  else
    matched=1
  fi
  (( matched )) || return 1
  if records_has "$set" "$idx" exclude-files; then
    while IFS= read -r g; do
      [[ -n $g ]] || continue
      sast_glob_match "$g" "$relpath" && return 1
    done <<<"$(records_list "$set" "$idx" exclude-files)"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The context directive (rules/RULE-FORMAT.md §10, docs/FOUNDATION.md
#    tension 3) - THE FIRST evaluation of it anywhere in the codebase.
# ---------------------------------------------------------------------------
# One rule pattern per context pattern, matched against the WINDOW TEXT with
# the SAME engine wrapper used for everything else, never bash's own `=~`
# (tension 2's BSD \b\w\s\d hazard applies here exactly as it does to
# pattern/redact()).  `sed -n 'lo,hip'` only slices line RANGES - a numeric
# operation, not a regex match - so it carries none of the "which engine"
# risk `pattern`/`context-*` values do; the actual match is scan_match_stdin.
_sast_context_matches() {
  local pattern=$1 text=$2 rc=0
  printf '%s\n' "$text" | scan_match_stdin "$pattern" >/dev/null || rc=$?
  (( rc == 0 ))
}

# sast_context_ok SET IDX FILE LINE TOTAL_LINES - §10.1's predicate: every
# context-require satisfied (AND) and no context-deny satisfied (OR, deny
# wins).  True (finding fires) when neither key is present at all.
sast_context_ok() {
  local set=$1 idx=$2 file=$3 line=$4 total=$5
  records_has "$set" "$idx" context-require || records_has "$set" "$idx" context-deny || return 0

  local win=2
  records_has "$set" "$idx" context-window && win=$(records_field "$set" "$idx" context-window)
  local lo=$(( line - win )) hi=$(( line + win ))
  (( lo < 1 )) && lo=1
  (( hi > total )) && hi=$total

  # No `--` before the path: measured (this codebase's own "measured, not
  # assumed" discipline) that BSD sed 2.6.0-FreeBSD has NO end-of-options
  # marker at all ("illegal option -- -"), unlike GNU sed where it is
  # optional.  Every path this function is ever called with is already an
  # ABSOLUTE path (sast_walk_files walks $_SCAN_RESOLVED_PATH, itself
  # resolved through realpath_of), so it can never be misread as an option.
  local window_text
  window_text=$(sed -n "${lo},${hi}p" "$file")

  local p
  if records_has "$set" "$idx" context-require; then
    while IFS= read -r p; do
      [[ -n $p ]] || continue
      _sast_context_matches "$p" "$window_text" || return 1
    done <<<"$(records_list "$set" "$idx" context-require)"
  fi
  if records_has "$set" "$idx" context-deny; then
    while IFS= read -r p; do
      [[ -n $p ]] || continue
      _sast_context_matches "$p" "$window_text" && return 1
    done <<<"$(records_list "$set" "$idx" context-deny)"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. Check registry lookup: id -> "set idx", built once per sast_run call
# ---------------------------------------------------------------------------
declare -A _SAST_CHECK_LOC=()

sast_index_checks() {
  _SAST_CHECK_LOC=()
  local set n i id
  for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
    n=$(records_count "$set")
    for (( i = 0; i < n; i++ )); do
      id=$(records_id "$set" "$i")
      _SAST_CHECK_LOC[$id]="$set $i"
    done
  done
}

# ---------------------------------------------------------------------------
# 5. Sensitive-data heuristic (mirrors tests/e2e/fixture-scan.sh's own, which
#    this ticket generalises: a secrets-family check id marks its findings
#    sensitive_data=true, which the rubric (data/severity-rubric.conf) reads.)
# ---------------------------------------------------------------------------
_sast_check_is_sensitive() {
  case $1 in
    *SECRET* | *PRIVATE_KEY* | *API_KEY* | *PASSWORD* | *AKID* | *JWT*) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. Per-file, per-check scan: the two-pass design (rules/RULE-FORMAT.md
#    §10.3) - pass 1 collects every match with its byte offset in one
#    scan_match_offsets call, pass 2 evaluates the context window per match.
# ---------------------------------------------------------------------------
sast_scan_file() {
  local set=$1 idx=$2 relpath=$3 abspath=$4
  local pattern id
  pattern=$(records_field "$set" "$idx" pattern)
  id=$(records_id "$set" "$idx")

  local hits=$SCOURSH_SCRATCH/sast-hits.$$
  if ! scan_match_offsets "$hits" "$pattern" "$abspath"; then
    rm -f "$hits"
    return 0
  fi

  local total='' ln off text count=0 overflow=0
  # off is read to consume the byte-offset field so `text` lands in the right
  # position; the ordinal itself is computed inside finding_emit, exactly the
  # same shape as tests/e2e/fixture-scan.sh's own scan_tree.
  # shellcheck disable=SC2034
  while IFS=: read -r ln off text; do
    [[ -n $ln ]] || continue
    count=$(( count + 1 ))
    if (( count > SCOURSH_SAST_MAX_MATCHES_PER_FILE )); then
      overflow=1
      break
    fi
    [[ -n $total ]] || total=$(awk 'END{print NR}' "$abspath")
    if sast_context_ok "$set" "$idx" "$abspath" "$ln" "$total"; then
      _sast_emit_finding "$set" "$idx" "$relpath" "$ln" "$text"
    fi
  done <"$hits"
  rm -f "$hits"

  if (( overflow )); then
    run_record truncated_matches "check=$id file=$relpath max=$SCOURSH_SAST_MAX_MATCHES_PER_FILE"
    finding_new
    finding_set check_id "$id"
    finding_set module sast
    finding_set title "Match count truncated at $SCOURSH_SAST_MAX_MATCHES_PER_FILE for $relpath"
    finding_set base_severity info
    finding_set confidence high
    finding_set cwe none
    finding_set owasp none
    finding_set loc_path "$relpath"
    finding_set loc_line "$SCOURSH_SAST_MAX_MATCHES_PER_FILE"
    finding_set cell "$SCOURSH_PATH_ROOT"
    finding_set logical_kind file
    finding_set logical_fqn "$relpath:truncated"
    finding_set remediation 'No action on this entry itself; it records that scanning stopped early for this (check, file) pair. Split the file or raise max-matches-per-file in config/scanner.conf if the remaining matches matter.'
    finding_set_match "truncated at $SCOURSH_SAST_MAX_MATCHES_PER_FILE matches"
    finding_set_evidence "truncated at $SCOURSH_SAST_MAX_MATCHES_PER_FILE matches"
    finding_emit
  fi
}

_sast_emit_finding() {
  local set=$1 idx=$2 relpath=$3 ln=$4 text=$5
  local id
  id=$(records_id "$set" "$idx")
  finding_new
  finding_from_record "$set" "$idx"
  finding_set module sast
  finding_set loc_path "$relpath"
  finding_set loc_line "$ln"
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set logical_kind file
  finding_set logical_fqn "$relpath:$ln"
  if _sast_check_is_sensitive "$id"; then
    finding_set sensitive_data true
  fi
  # The RAW matched text feeds the digest and evidence; nothing raw is kept
  # beyond this call (docs/FOUNDATION.md tension 9).
  finding_set_match "$text"
  finding_set_evidence "$text"
  finding_emit
}

# ---------------------------------------------------------------------------
# 7. Tree scan: every selected check against every eligible file.
# ---------------------------------------------------------------------------
# The scanning unit for the occurrence ordinal is the FILE (docs/FOUNDATION.md
# tension 5), so occurrence_reset_unit is called once per file, ahead of every
# check, exactly as tests/e2e/fixture-scan.sh's own scan_tree already does.
#
# `config_scanner_value` can `die()` (an invalid config/scanner.conf value),
# and wrapping a die-capable function in `$(...)` makes that die unreliable -
# scan.sh's own `_scan_capture` comment measures why.  This module is sourced
# both from inside scan.sh (where `_scan_capture` already exists) AND
# directly by tests/suites/sast.sh (which sources only this file), so it
# carries its own copy rather than depending on a caller-supplied helper.
_sast_capture_max_matches() {
  local tmp=$SCOURSH_SCRATCH/_sast_max_matches.$$
  config_scanner_value max-matches-per-file '' >"$tmp"
  # config_scanner_value prints with `printf '%s'` - deliberately no trailing
  # newline (lib/config.sh) - so `read` would otherwise see EOF before a
  # newline and return 1 even though it captured the value correctly
  # (measured; scan.sh's own `_scan_capture` carries the identical fix and
  # comment).
  printf '\n' >>"$tmp"
  IFS= read -r SCOURSH_SAST_MAX_MATCHES_PER_FILE <"$tmp"
  rm -f "$tmp"
}

sast_scan_tree() {
  local root=$1
  shift
  local -a ids=("$@")
  _sast_capture_max_matches
  # Every file's identity (`files`/`exclude-files` matching, §9.1.2, AND
  # `loc_path` - a fingerprint component, tension 5) is relative to the SCAN
  # ROOT (the git toplevel, or the resolved path when not a git repo -
  # tension 12), never to `--path` itself.  `--path` is a run parameter and
  # is deliberately absent from a finding's identity: "src/sub/x.py is
  # consistent with a root of ., src, or src/sub" only holds if the same
  # physical file gets the same relative path regardless of which of those
  # was scanned, which requires the SCAN root, not the walk root, as the
  # base.  `--path src/sub` would otherwise report `x.py` while `--path .`
  # reports `src/sub/x.py` for the identical file and vulnerability - two
  # different fingerprints for one issue.
  local scan_root
  scan_root=$(scan_root_of "$root")
  local abspath rel id loc set idx
  while IFS= read -r abspath; do
    [[ -n $abspath ]] || continue
    rel=$(sast_relpath "$scan_root" "$abspath")
    occurrence_reset_unit "$rel"
    for id in "${ids[@]+"${ids[@]}"}"; do
      loc=${_SAST_CHECK_LOC[$id]:-}
      [[ -n $loc ]] || continue
      read -r set idx <<<"$loc"
      sast_rule_matches_file "$set" "$idx" "$rel" || continue
      sast_scan_file "$set" "$idx" "$rel" "$abspath"
    done
  done < <(sast_walk_files "$root")
}

# ---------------------------------------------------------------------------
# 8. Gate evaluation - docs/FOUNDATION.md tension 14: "the gate itself lands
#    in step 10 but its inputs exist from step 2".  What is implemented here
#    is exactly what is decidable with no state/ (step 7) and no diff engine
#    (step 10) on disk yet: every finding this run produces is `status: new`
#    by construction (finding_new's own default, never overwritten - nothing
#    before step 7 exists that could set anything else), so on the first-ever
#    run tension 12's own table already says `new` is the correct status, and
#    `--fail-on-new` therefore degenerates to exactly `--fail-on` rather than
#    needing diff_usable / unknown-exclusion, neither of which has an input to
#    read yet.  This function does not anticipate step 10's refinements; it
#    computes the one case that is already fully determined.
sast_evaluate_gate() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  # SCAN_FLAGS is scan.sh's own global associative array; when this module is
  # exercised standalone (tests/suites/sast.sh sources only this file, never
  # scan.sh), it never existed at all, and `${SCAN_FLAGS[fail-on-new]:-false}`
  # against a wholly UNDECLARED array is not the safe "unset" case under
  # `set -u` - measured: bash instead parses the hyphenated subscript as
  # arithmetic (indexed-array fallback) and dies on the first bare word in
  # it.  Declaring it (once, only if absent) makes the lookup behave exactly
  # like every other unset-key read in this file.
  #
  # `${SCAN_FLAGS+set}` is NOT the right test here: measured (bash 5.3.9, and
  # this is not version-specific - it is how `${arr+set}` has always worked),
  # `${arr+set}` on an associative array tests element `[0]`/`["0"]`, not "is
  # the array declared" - `declare -A G=([fail-on-new]=true); [[ ${G+set} ]]`
  # is FALSE, because there is no key literally named `0`.  Called from
  # inside a function, that makes the guard's RHS run unconditionally, and
  # `declare -A SCAN_FLAGS=()` inside a function - with no `-g` - creates a
  # new LOCAL that shadows the real global for the rest of this function's
  # body, so every subsequent `${SCAN_FLAGS[...]}` read in this function
  # would silently see empty regardless of what the caller actually set.
  # `declare -p SCAN_FLAGS &>/dev/null` tests declaredness directly and is
  # unaffected by which keys happen to be populated - the same pattern
  # history.sh's `_sast_history_run` uses for the identical case.
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()
  local fail_on=${SCOURSH_FAIL_ON:-none}
  if [[ -z $fail_on || $fail_on == none ]]; then
    SCOURSH_GATE_RESULT=not-evaluated
    SCOURSH_GATED_FINDINGS=0
    export SCOURSH_GATE_RESULT SCOURSH_GATED_FINDINGS
    return 0
  fi
  local fail_on_new=${SCAN_FLAGS[fail-on-new]:-false}
  local min_confidence=${SCOURSH_MIN_CONFIDENCE:-low}
  local threshold conf_threshold
  threshold=$(severity_rank "$fail_on")
  conf_threshold=$(_sast_confidence_rank "$min_confidence")

  local line count=0
  if [[ -s $rundir/findings.fields ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      [[ ${_DF[suppressed]:-false} != true ]] || continue
      if [[ $fail_on_new == true ]]; then
        [[ ${_DF[status]:-new} == new ]] || continue
      fi
      (( $(severity_rank "${_DF[severity]:-info}") >= threshold )) || continue
      (( $(_sast_confidence_rank "${_DF[confidence]:-medium}") >= conf_threshold )) || continue
      count=$(( count + 1 ))
    done <"$rundir/findings.fields"
  fi

  SCOURSH_GATED_FINDINGS=$count
  export SCOURSH_GATED_FINDINGS
  if (( count > 0 )); then
    SCOURSH_GATE_RESULT=fail
    # Sets the CALLER's `gate` local (scan_main's, via the sourced-not-
    # subprocess contract scan.sh's own header documents) so
    # scan_exit_code's precedence table produces SCOURSH_EXIT_GATE.  A plain
    # assignment with no `local` here is deliberate, not an oversight: `gate`
    # is scan_main's OWN local variable, reached by bash's dynamic scoping
    # through the sourced-not-subprocess chain, and must never be exported -
    # it is not meant to be a real environment variable.  shellcheck cannot
    # see that caller across the source boundary (same reason lib/checks.sh
    # disables SC2034 for its own cross-file-read globals).
    # shellcheck disable=SC2034
    gate=1
  else
    SCOURSH_GATE_RESULT=pass
  fi
  export SCOURSH_GATE_RESULT
}

_sast_confidence_rank() {
  case $1 in
    low) printf '%s' 0 ;;
    medium) printf '%s' 1 ;;
    high) printf '%s' 2 ;;
    *) printf '%s' 0 ;;
  esac
}
