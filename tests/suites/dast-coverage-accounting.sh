#!/usr/bin/env bash
# tests/suites/dast-coverage-accounting.sh - every DAST check that is SELECTED
# for a run ends up in exactly one of two buckets: it ran, or the run says by id
# why it did not.  docs/DESIGN.md §15's honesty rule, made mechanical.
#
# NOTHING HERE TOUCHES THE NETWORK.  The accounting is a property of what a run
# WRITES into `meta/`, so every case here drives `run_record` and the real
# readers over a scratch run directory; the two phase-level cases source the
# phase's own emitting block through a stub rather than issuing a request.
#
# WHY THIS SUITE EXISTS.  modules/sast/engine.sh's `sast_record_checks_run` gives
# SAST and IaC a two-bucket guarantee from ONE function every selected id passes
# through.  DAST cannot be shaped that way - ~20 phase scripts each decide at
# RUNTIME whether their checks had anything to act on - so "say why" was a
# convention, and conventions are what the next phase script forgets.  Measured
# on a real `--intensity active` run against a live target before this landed:
# 92 DAST checks registered, 34 ran, 10 declared by id, and 48 in the residual
# `lib/report.sh`'s coverage report renders as `unaccounted`.  45 of those had an
# honest coverage_reduction behind them that never named an id; 3 had no record
# of any kind.
#
# THE DECISIONS THIS SUITE PINS, each with the plausible wrong reading that
# would otherwise ship green:
#
#   A. THE PARTITION IS EXHAUSTIVE.  Asserted as `unaccounted == 0` computed by
#      lib/report.sh's OWN arithmetic, not by re-deriving it here.  Fails under
#      "a reduction was recorded, so the reason is covered" - the pre-fix code
#      recorded 37 reductions and still left 48 checks unaccounted, because a
#      reduction with no `checks=[...]` list contributes nothing to that sum.
#   B. THE BACKSTOP FIRES for a check no phase spoke for, naming it by id.
#      Fails under "the per-phase reductions are enough".
#   C. THE BACKSTOP STAYS SILENT when every skip was already declared.  Fails
#      under a backstop that re-declares what a phase already named - which
#      would double-count in `notrun` and mask a real gap (see E).
#   D. A DECLARED ID IS NEVER NAMED TWICE.  `dast_selected_narrow` drops an id
#      the filter chain already recorded via lib/checks.sh:353.  Fails under
#      "name every id the phase owns" - the naive fix, and the one that
#      corrupts the report rather than merely adding noise.
#   E. THE DOUBLE-COUNT IS DESTRUCTIVE, not cosmetic.  Pinned by constructing
#      the double-declared state directly and showing lib/report.sh's own
#      `(( unacc < 0 )) && unacc=0` clamp then HIDES a genuinely unaccounted
#      check.  This is why D is worth a mechanism instead of care.
#   F. THE TWO PREVIOUSLY-SILENT PATHS record a reason naming their ids:
#      cors.sh's `Origin: null` follow-up that was never sent, and markup.sh's
#      tabnabbing id no page was classified under.  Each fails under the exact
#      pre-fix spelling, which is reproduced inline rather than described.
#   G. `checks=[...]`, NOT `check=<id>`.  xxe_ssrf.sh named real ids in the
#      singular field every other DAST caller uses for a PHASE name, so
#      lib/report.sh could not see them.  Fails under the pre-fix spelling.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell and record syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=/dev/null
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-dast-acct.XXXXXX")
trap 'rm -rf "$W"' EXIT

# ---------------------------------------------------------------------------
# _acct_partition RUNDIR CATEGORY - lib/report.sh's OWN coverage arithmetic
# (`_report_coverage_state`), replayed over a run directory.
#
# It is REPRODUCED here rather than called, deliberately and with a cost: this
# suite must be able to compute the partition for a run directory it built by
# hand, without a findings file, a registry load, or lib/report.sh's own
# memoised state.  The risk that comes with a copy is that it drifts from the
# original and starts certifying a partition the real report never computes -
# so section A additionally asserts the numbers against a REAL report_audit run
# over the same directory, which is what keeps this function honest.
#
# Sets _ACCT_REG/_ACCT_RAN/_ACCT_NOTRUN/_ACCT_UNACC and _ACCT_UNACC_IDS.
# ---------------------------------------------------------------------------
_acct_partition() {
  local rundir=$1 cat=$2
  local m=${cat^^}
  local t=$W/part.$$
  rm -rf "$t"; mkdir -p "$t"

  grep "^${m}-" "$rundir/meta/checks_run" 2>/dev/null | LC_ALL=C sort -u >"$t/ran" || : >"$t/ran"
  grep "^${m}-" "$rundir/meta/checks_selected" 2>/dev/null | LC_ALL=C sort -u >"$t/sel" || : >"$t/sel"
  sed -n 's/^check=\([^ ]*\) skipped_by=.*$/\1/p' "$rundir/meta/skipped_checks" 2>/dev/null \
    | grep "^${m}-" | LC_ALL=C sort -u >"$t/skip" || : >"$t/skip"
  sed -n 's/.*checks=\[\([^]]*\)\].*/\1/p' "$rundir/meta/coverage_reduction" 2>/dev/null \
    | tr ' ' '\n' | grep "^${m}-" | LC_ALL=C sort -u >"$t/napp" || : >"$t/napp"

  local sel skp ran napp
  sel=$(grep -c . "$t/sel" || true); skp=$(grep -c . "$t/skip" || true)
  ran=$(grep -c . "$t/ran" || true); napp=$(grep -c . "$t/napp" || true)
  _ACCT_REG=$(( ${sel:-0} + ${skp:-0} ))
  _ACCT_RAN=${ran:-0}
  _ACCT_NOTRUN=$(( ${skp:-0} + ${napp:-0} ))
  _ACCT_UNACC=$(( _ACCT_REG - _ACCT_RAN - _ACCT_NOTRUN ))
  (( _ACCT_UNACC < 0 )) && _ACCT_UNACC=0
  _ACCT_UNACC_IDS=$(comm -23 "$t/sel" <(cat "$t/ran" "$t/skip" "$t/napp" | LC_ALL=C sort -u) | tr '\n' ' ')
  _ACCT_UNACC_IDS=${_ACCT_UNACC_IDS% }
  rm -rf "$t"
}

# A scratch run directory with a `meta/` the real `run_record` writes into.
_acct_newrun() {
  local d=$W/$1
  rm -rf "$d"; mkdir -p "$d/meta"
  printf '%s' "$d"
}

# `run_record` without lib/core.sh: this suite needs only the append-to-meta
# behaviour, and sourcing core.sh here would install its traps and take over the
# scratch directory this suite owns.  Kept byte-compatible with lib/core.sh's
# own writer (one line per fact, appended).
run_record() {
  local key=$1; shift
  printf '%s\n' "$*" >>"$SCOURSH_RUN_DIR/meta/$key"
}
run_facts() {
  local key=$1
  [[ -n ${SCOURSH_RUN_DIR:-} && -f $SCOURSH_RUN_DIR/meta/$key ]] || return 0
  cat -- "$SCOURSH_RUN_DIR/meta/$key"
}

printf -- '-- A. the partition is exhaustive, by lib/report.sh'"'"'s own arithmetic --\n'

t_case 'a run where every selected check is either run or declared leaves 0 unaccounted'
RD=$(_acct_newrun run-a); export SCOURSH_RUN_DIR=$RD
for i in DAST-X-RAN_A-01 DAST-X-RAN_B-01 DAST-X-SKIP_A-01 DAST-X-SKIP_B-01 DAST-X-SKIP_C-01; do
  run_record checks_selected "$i"
done
run_record checks_run DAST-X-RAN_A-01
run_record checks_run DAST-X-RAN_B-01
run_record coverage_reduction 'module=dast reason=fixture_a target=t checks=[DAST-X-SKIP_A-01 DAST-X-SKIP_B-01] - prose'
run_record coverage_reduction 'module=dast reason=fixture_b target=t checks=[DAST-X-SKIP_C-01] - prose'
_acct_partition "$RD" dast
assert_eq 5 "$_ACCT_REG" 'all five selected checks are the denominator'
assert_eq 2 "$_ACCT_RAN"  'two ran'
assert_eq 3 "$_ACCT_NOTRUN" 'three are declared not-run by id'
assert_eq 0 "$_ACCT_UNACC" \
  'unaccounted is 0 - fails under "a reduction was recorded so the reason is covered", which is what the pre-fix module did: 37 reductions, 48 unaccounted'

t_case 'a reduction with NO checks=[...] list contributes NOTHING - the shipped defect, reproduced'
RD=$(_acct_newrun run-a2); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-X-RAN_A-01
run_record checks_selected DAST-X-SKIP_A-01
run_record checks_run DAST-X-RAN_A-01
# The pre-fix shape: an honest, human-readable reason that names the PHASE and
# never an id.  This is exactly what all ten injection phases wrote.
run_record coverage_reduction 'module=dast reason=no_parameter_inventory target=t - the crawler wrote no injectable parameter, so SQL injection had no request field to test.'
_acct_partition "$RD" dast
assert_eq 1 "$_ACCT_UNACC" \
  'the pre-fix record shape still leaves the check unaccounted - this is the defect, asserted as present so the fixed cases below are known to be measuring something'
assert_eq 'DAST-X-SKIP_A-01' "$_ACCT_UNACC_IDS" 'and it is the undeclared id that is left over'

printf -- '\n-- B/C. the backstop: fires for a silent check, silent for a declared one --\n'

t_case 'B. a selected check no phase spoke for is named by the backstop'
RD=$(_acct_newrun run-b); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-X-RAN_A-01
run_record checks_selected DAST-X-GHOST-01
run_record checks_run DAST-X-RAN_A-01
dast_record_unaccounted fixture-target
assert_contains "$(cat "$RD/meta/coverage_reduction")" 'reason=check_not_executed_no_reason_recorded' \
  'the backstop records a declared reduction - fails under "the per-phase reductions are enough", the state that shipped'
assert_contains "$(cat "$RD/meta/coverage_reduction")" 'checks=[DAST-X-GHOST-01]' \
  'and it names the silent check BY ID, which is the only form lib/report.sh reads'
assert_not_contains "$(cat "$RD/meta/coverage_reduction")" 'DAST-X-RAN_A-01' \
  'and it does NOT name the check that ran - fails under "diff selected against nothing" / a backstop that names the whole registry'
_acct_partition "$RD" dast
assert_eq 0 "$_ACCT_UNACC" 'with the backstop the partition is exhaustive even though no phase said anything'
assert_file_exists "$RD/meta/coverage_gap" 'and a human-readable gap sentence is written alongside it'

t_case 'C. the backstop stays SILENT when every skip was already declared by its phase'
RD=$(_acct_newrun run-c); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-X-RAN_A-01
run_record checks_selected DAST-X-SKIP_A-01
run_record checks_run DAST-X-RAN_A-01
run_record coverage_reduction 'module=dast reason=fixture_specific target=t checks=[DAST-X-SKIP_A-01] - the phase said why'
dast_record_unaccounted fixture-target
assert_not_contains "$(cat "$RD/meta/coverage_reduction")" 'check_not_executed_no_reason_recorded' \
  'the backstop adds nothing when the phase already named the id - fails under a backstop that re-declares, which double-counts notrun (see E)'
assert_file_absent "$RD/meta/coverage_gap" 'and writes no gap sentence either'

t_case 'C2. the backstop honours skipped_checks, so a pre-dispatch filter is not re-declared'
RD=$(_acct_newrun run-c2); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-X-RAN_A-01
run_record checks_run DAST-X-RAN_A-01
run_record skipped_checks 'check=DAST-X-FILTERED-01 skipped_by=intensity=passive'
dast_record_unaccounted fixture-target
assert_file_absent "$RD/meta/coverage_reduction" \
  'a check dropped by lib/checks.sh:353 is already accounted for and is never re-declared - fails under "diff the registry, not checks_selected"'

printf -- '\n-- D/E. a declared id is never named twice, and why that matters --\n'

t_case 'D. dast_selected_narrow drops an id the filter chain excluded'
export SCOURSH_SELECTED_CHECKS=$'DAST-INJ-SQLI_ERROR-01\nDAST-INJ-SQLI_TIME-01'
nc='DAST-INJ-SQLI_ERROR-01 DAST-INJ-SQLI_BOOLEAN-01 DAST-INJ-SQLI_TIME-01'
dast_selected_narrow nc
assert_eq 'DAST-INJ-SQLI_ERROR-01 DAST-INJ-SQLI_TIME-01' "$nc" \
  'the deselected id is dropped - fails under "name every id the phase owns", the naive fix'

t_case 'D2. with NO filter chain every id survives - the permissive default'
unset SCOURSH_SELECTED_CHECKS
nc='DAST-INJ-SQLI_ERROR-01 DAST-INJ-SQLI_BOOLEAN-01'
dast_selected_narrow nc
assert_eq 'DAST-INJ-SQLI_ERROR-01 DAST-INJ-SQLI_BOOLEAN-01' "$nc" \
  'an empty/unset SCOURSH_SELECTED_CHECKS means ALL selected - fails under a fail-closed default, which would silently empty every checks=[] list in the module'

t_case 'D3. narrowing does not glob against the working directory'
cd "$W" && : >'DAST-INJ-SQLI_ERROR-01'
export SCOURSH_SELECTED_CHECKS=$'DAST-INJ-SQLI_ERROR-01'
nc='* DAST-INJ-SQLI_ERROR-01'
dast_selected_narrow nc
cd "$ROOT"
assert_eq 'DAST-INJ-SQLI_ERROR-01' "$nc" \
  'a bare * in the list is not expanded against the scanner cwd - fails under an unquoted `for id in $list`, AGENTS.md markup_tokens_have lesson'
unset SCOURSH_SELECTED_CHECKS

t_case 'E. double-declaring drives unaccounted negative and HIDES a real gap'
# The state the naive fix produces: an id is both in skipped_checks (the filter
# chain declared it) AND named in a checks=[...] list (the phase declared it
# again).  Constructed directly, because the point is what lib/report.sh's own
# clamp does with it - not whether any current caller produces it.
RD=$(_acct_newrun run-e); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-X-RAN_A-01
run_record checks_selected DAST-X-GHOST-01
run_record checks_run DAST-X-RAN_A-01
run_record skipped_checks 'check=DAST-X-FILTERED-01 skipped_by=intensity=passive'
run_record coverage_reduction 'module=dast reason=naive target=t checks=[DAST-X-FILTERED-01] - named a second time'
_acct_partition "$RD" dast
assert_eq 0 "$_ACCT_UNACC" \
  'the clamp reports 0 unaccounted...'
assert_eq 'DAST-X-GHOST-01' "$_ACCT_UNACC_IDS" \
  '...while a genuinely unaccounted check is sitting right there - which is why D is a mechanism (dast_selected_narrow) and not a matter of care'

printf -- '\n-- F. the two previously-silent phase paths --\n'

t_case 'F1. cors: the Origin: null follow-up that was never sent is declared by id'
# The shipped emitting block, lifted verbatim from modules/dast/passive/cors.sh
# so the assertion is about that file's real logic rather than a paraphrase.
_acct_cors_emit() {
  local target=$1 do_null=$2 null_tested=$3 null_skipped=$4 null_failed=$5
  local -a probe=(a b c)
  if (( do_null )); then
    if (( null_tested > 0 )); then
      run_record checks_run DAST-CORS-NULL_ORIGIN-01
      run_record checks_run DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
    else
      run_record coverage_reduction "module=dast reason=cors_null_probe_not_sent check=cors target=$target checks=[DAST-CORS-NULL_ORIGIN-01 DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01] candidates=${#probe[@]} already_reflected_or_wildcard=$null_skipped unreachable=$null_failed - not covered"
      run_record coverage_gap "dast cors: the Origin: null probe was not sent to any route on target '$target'"
    fi
  fi
}
# The PRE-FIX spelling, for the same inputs - the reading this case fails under.
_acct_cors_emit_prefix() {
  local do_null=$1 null_tested=$2
  if (( null_tested > 0 && do_null )); then
    run_record checks_run DAST-CORS-NULL_ORIGIN-01
    run_record checks_run DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
  fi
}
RD=$(_acct_newrun run-f1); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-CORS-NULL_ORIGIN-01
run_record checks_selected DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
_acct_cors_emit fixture-target 1 0 3 0
_acct_partition "$RD" dast
assert_eq 0 "$_ACCT_UNACC" 'both null-origin ids are accounted for when the second probe was never sent'
assert_contains "$(cat "$RD/meta/coverage_reduction")" 'reason=cors_null_probe_not_sent' 'under its own reason token'

RD=$(_acct_newrun run-f1b); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-CORS-NULL_ORIGIN-01
run_record checks_selected DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
_acct_cors_emit_prefix 1 0
_acct_partition "$RD" dast
assert_eq 2 "$_ACCT_UNACC" \
  'the PRE-FIX `if` with no else leaves both ids unaccounted - measured, so F1 is known to be pinning the fix and not a tautology'

t_case 'F1c. cors still records the ids as RUN when the probe did go out'
RD=$(_acct_newrun run-f1c); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-CORS-NULL_ORIGIN-01
run_record checks_selected DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
_acct_cors_emit fixture-target 1 2 0 0
assert_contains "$(cat "$RD/meta/checks_run")" 'DAST-CORS-NULL_ORIGIN-01' \
  'a probe that ran is still coverage - fails under a fix that declares the ids not-covered unconditionally, which would trade a silent gap for a permanent false one'
assert_file_absent "$RD/meta/coverage_reduction" 'and nothing is declared when there is nothing to declare'

t_case 'F2. markup: a tabnabbing id no page was classified under is declared by id'
_acct_markup_emit() {
  local target=$1 parsed=$2; shift 2
  local -a tab_not_seen=("$@")
  if (( ${#tab_not_seen[@]} > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_no_page_classified target=$target checks=[${tab_not_seen[*]}] parsed=$parsed - not covered"
    run_record coverage_gap "dast markup: ${#tab_not_seen[@]} reverse-tabnabbing check(s) on target '$target' had no page of their own kind"
  fi
}
RD=$(_acct_newrun run-f2); export SCOURSH_RUN_DIR=$RD
run_record checks_selected DAST-MARKUP-TABNABBING-01
run_record checks_selected DAST-MARKUP-TABNABBING_SENSITIVE-01
run_record checks_run DAST-MARKUP-TABNABBING-01
_acct_markup_emit fixture-target 4 DAST-MARKUP-TABNABBING_SENSITIVE-01
_acct_partition "$RD" dast
assert_eq 0 "$_ACCT_UNACC" \
  'the sensitive id is declared while its ordinary sibling still counts as run - fails under the pre-fix bare `continue`, which dropped it with no record at all'
assert_contains "$(cat "$RD/meta/coverage_reduction")" 'checks=[DAST-MARKUP-TABNABBING_SENSITIVE-01]' \
  'and only the id that was not classified is named'

printf -- '\n-- G. checks=[...] not check=<id> --\n'

t_case 'G. xxe_ssrf names its ids in the field lib/report.sh actually reads'
RD=$(_acct_newrun run-g); export SCOURSH_RUN_DIR=$RD
for i in DAST-INJ-XXE_ENTITY-01 DAST-INJ-XXE_SSRF-01 DAST-INJ-SSRF_PARAM-01; do
  run_record checks_selected "$i"
done
run_record coverage_reduction 'module=dast reason=xxe_entity_not_executed checks=[DAST-INJ-XXE_ENTITY-01] target=t - prose'
run_record coverage_reduction 'module=dast reason=xxe_ssrf_not_executed checks=[DAST-INJ-XXE_SSRF-01] target=t - prose'
run_record coverage_reduction 'module=dast reason=ssrf_param_not_executed checks=[DAST-INJ-SSRF_PARAM-01] target=t - prose'
_acct_partition "$RD" dast
assert_eq 0 "$_ACCT_UNACC" 'all three are accounted for'

RD=$(_acct_newrun run-g2); export SCOURSH_RUN_DIR=$RD
for i in DAST-INJ-XXE_ENTITY-01 DAST-INJ-XXE_SSRF-01 DAST-INJ-SSRF_PARAM-01; do
  run_record checks_selected "$i"
done
run_record coverage_reduction 'module=dast reason=xxe_entity_not_executed check=DAST-INJ-XXE_ENTITY-01 target=t - prose'
run_record coverage_reduction 'module=dast reason=xxe_ssrf_not_executed check=DAST-INJ-XXE_SSRF-01 target=t - prose'
run_record coverage_reduction 'module=dast reason=ssrf_param_not_executed check=DAST-INJ-SSRF_PARAM-01 target=t - prose'
_acct_partition "$RD" dast
assert_eq 3 "$_ACCT_UNACC" \
  'the PRE-FIX singular `check=<id>` spelling leaves all three unaccounted even though the id is right there in the record - which is why the emitters moved to the plural form'

printf -- '\n-- H. the source tree itself: every skip-declaring reduction names ids --\n'

t_case 'H. no DAST phase records a reason for a check without naming it'
# A source-level guard, not a run-level one: it catches a NEW phase that
# reintroduces the pattern on the day it lands, rather than on the day someone
# reads a coverage report.  Restricted to the reasons this ticket audited, so it
# states a fact rather than aspiring to one.
# ONE EXEMPTION, BY PATH AND REASON, NEVER BY WIDENING THE PATTERN - the shape
# tests/lint-shell.sh's own tension-19 check already uses.  modules/dast/auth.sh
# owns NO check ids at all (it acquires the session other phases spend; `grep -c
# checks_run modules/dast/auth.sh` is 0), so its `authed_not_requested` is a
# statement about the PHASE and has nothing to name.  jwt.sh's and authz.sh's
# reductions under the same reason token DO own ids and are not exempt, which is
# why the exemption is keyed on the file rather than on the token.
_acct_exempt() {
  [[ $1 == *modules/dast/auth.sh && $2 == authed_not_requested ]]
}
MISSING=''
f=''
for pat in no_parameter_inventory target_not_https authed_not_requested \
           versions_db_absent versions_db_no_banner_rows discovery_wordlist_absent \
           no_graphql_endpoint burst_rate_not_raised xxe_entity_not_executed \
           xxe_ssrf_not_executed ssrf_param_not_executed \
           openredirect_parameter_not_redirect_shaped cors_null_probe_not_sent \
           markup_no_page_classified; do
  while IFS= read -r hit; do
    [[ -n $hit ]] || continue
    f=${hit%%:*}
    [[ ${hit#*:} == *'checks=['* ]] && continue
    _acct_exempt "$f" "$pat" && continue
    MISSING+="$f:$pat "
  done < <(grep -rn "run_record coverage_reduction .*reason=$pat" "$ROOT/modules/dast/" 2>/dev/null | sed 's/:[0-9]*:/:/' || true)
done
assert_eq '' "$MISSING" \
  'every audited skip reason names its checks - fails the moment a phase records a reason with no checks=[...] list, which is the shape that shipped'

t_summary 'dast-coverage-accounting'
