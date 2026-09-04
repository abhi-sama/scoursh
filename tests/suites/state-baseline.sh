#!/usr/bin/env bash
# tests/suites/state-baseline.sh - lib/diff.sh's `baseline_apply`
# (docs/STEP7-STATE-PLAN.md STATE-07): config/baseline.json suppression.
#
# Suppression is the one feature whose bugs are silent by construction: a
# suppression that is too broad hides real findings and looks exactly like a
# clean scan.  Every case here either proves what gets suppressed OR proves
# what still gets through - never only the former - and every case names the
# reading it FAILS under, per AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# lib/diff.sh is sourced directly by the four run.sh files that call
# baseline_apply, not by modules/sast/engine.sh itself - see
# modules/sast/run.sh's own comment on why.  This suite calls baseline_apply
# without going through any of them, so it needs its own explicit source,
# exactly as tests/suites/state-diff.sh already does for diff_classify_run.
# shellcheck source=lib/diff.sh
source "$ROOT/lib/diff.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/state-baseline
rm -rf "$W"
mkdir -p "$W"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"
attribution_load "$ROOT/tests/fixtures/config/scope.conf"

# An ISOLATED install root, for the identical reason tests/suites/state-diff.sh
# uses one: `_baseline_resolve_file`'s default path is
# "$SCOURSH_INSTALL_ROOT/config/baseline.json", and a shared location would
# let one t_case's fixture leak into the next, or into the real repository's
# own (never-shipped) config/baseline.json.
INSTALL=$W/install
mkdir -p "$INSTALL/config"
SCOURSH_INSTALL_ROOT=$INSTALL
export SCOURSH_INSTALL_ROOT
STATE_DIR=$INSTALL/state

# `new_run NAME [SCAN_ROOT_ID]` - a fresh run directory AND a fresh write-side
# state/ builder, mirroring tests/suites/state-diff.sh's own helper of the
# same name.
new_run() {
  rm -rf "${W:?}/run.$1"
  SCOURSH_RUN_DIR=''
  SCOURSH_RUN_ID=''
  occurrence_reset_all
  run_init "$W/run.$1"
  state_reset
  SCOURSH_SCAN_ROOT_ID=${2:-root-default}
  SCOURSH_PATH_ROOT=.
  export SCOURSH_SCAN_ROOT_ID SCOURSH_PATH_ROOT
  state_set_run "$SCOURSH_RUN_ID" "$SCOURSH_SCAN_ROOT_ID" "$FP_SCHEMA" test-tool-version
}

emit_match() {                   # emit_match RUNDIR CHECK PATH LINE TEXT
  finding_new
  finding_set check_id "$2"
  finding_set module sast
  finding_set title t
  finding_set base_severity high
  finding_set cwe none
  finding_set owasp none
  finding_set loc_path "$3"
  finding_set loc_line "$4"
  finding_set cell .
  finding_set_match "$5"
  finding_set_evidence "$5"
  finding_emit
}

fp_of_check() {                  # fp_of_check RUNDIR CHECK -> its fingerprint
  local d=$1 check=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]} == "$check" ]] || continue
    printf '%s' "${_DF[fingerprint]}"
    return 0
  done <"$d/findings.fields"
}

suppressed_of() {                # suppressed_of RUNDIR CHECK -> true/false
  local d=$1 check=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]} == "$check" ]] || continue
    printf '%s' "${_DF[suppressed]:-false}"
    return 0
  done <"$d/findings.fields"
}

suppressed_by_of() {             # suppressed_by_of RUNDIR CHECK -> reason
  local d=$1 check=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]} == "$check" ]] || continue
    printf '%s' "${_DF[suppressed_by]:-}"
    return 0
  done <"$d/findings.fields"
}

status_of() {                    # status_of RUNDIR CHECK -> its status field
  local d=$1 check=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]} == "$check" ]] || continue
    printf '%s' "${_DF[status]}"
    return 0
  done <"$d/findings.fields"
}

absent_row() {                   # absent_row RUNDIR CHECK -> "status\treason"
  local d=$1 check=$2 line
  [[ -r $d/meta/diff_absent ]] || return 0
  while IFS=$'\x1f' read -r status reason c cell severity first_seen fp; do
    [[ $c == "$check" ]] || continue
    printf '%s\t%s' "$status" "$reason"
    return 0
  done <"$d/meta/diff_absent"
}

state_suppressed_of() {          # state_suppressed_of FINGERPRINT (write-side)
  printf '%s' "${_STATE_W_F_SUPPRESSED[$1]:-}"
}

# `write_baseline FILE CONTENT` - CONTENT is the raw JSON body (no trailing
# newline requirement).
write_baseline() {
  printf '%s' "$2" >"$1"
}

DEFAULT_BASELINE=$INSTALL/config/baseline.json

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: no baseline configured at all is a quiet, honest no-op --\n'
# ---------------------------------------------------------------------------

rm -f "$DEFAULT_BASELINE"
unset SCAN_FLAGS 2>/dev/null || true

t_case 'no --baseline flag and no config/baseline.json on disk: nothing dies, nothing is suppressed'
new_run noop
d=$SCOURSH_RUN_DIR
occurrence_reset_unit noop.py
emit_match "$d" SAST-BASE-NOOP-01 noop.py 1 nA
findings_merge "$d"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq false "$(suppressed_of "$d" SAST-BASE-NOOP-01)" 'with no baseline at all, nothing is suppressed'
assert_eq false "$(cat "$d/meta/baseline_used" 2>/dev/null)" 'meta/baseline_used honestly says false'
assert_eq '' "$(cat "$d/meta/baseline_file" 2>/dev/null)" 'meta/baseline_file is empty'
assert_eq 0 "$(cat "$d/meta/baseline_entries" 2>/dev/null)" 'meta/baseline_entries is 0'

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: a finding NOT in the baseline still surfaces (this ticket'"'"'s own acceptance criterion) --\n'
# ---------------------------------------------------------------------------
# The failure mode named in this ticket's own brief: a suppression mechanism
# that is too BROAD hides real findings and looks exactly like a clean scan.
# This case proves the mechanism is narrow - matching on the EXACT
# fingerprint, never the check id, the file, or "everything else present".

t_case 'a baseline naming an unrelated fingerprint leaves an unrelated, present finding fully live'
new_run narrow
d=$SCOURSH_RUN_DIR
occurrence_reset_unit narrow.py
emit_match "$d" SAST-BASE-NARROW-01 narrow.py 1 nrA
findings_merge "$d"
write_baseline "$DEFAULT_BASELINE" '["not-this-findings-fingerprint-at-all"]'
diff_classify_run "$d"
baseline_apply "$d"
assert_eq false "$(suppressed_of "$d" SAST-BASE-NARROW-01)" \
  'a baseline entry for a DIFFERENT fingerprint must not suppress this finding - fails under any "broad" match (by check id, by file, or "suppress everything when a baseline exists")'
report_count "$d"
assert_eq 1 "$_RPT_LIVE" 'the finding is counted as a LIVE finding, not folded into accepted risk'
assert_eq 0 "$_RPT_SUPPRESSED" 'and the accepted-risk count is genuinely zero'
assert_contains "$(cat "$d/meta/baseline_stale" 2>/dev/null)" 'not-this-findings-fingerprint-at-all' \
  'the unmatched baseline entry is reported stale rather than silently dropped'

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: bare-string and full-object entries both suppress --\n'
# ---------------------------------------------------------------------------

rm -f "$DEFAULT_BASELINE"

t_case 'a bare fingerprint string suppresses its exact match, with an empty reason (tension 11 §11 shape)'
new_run bare
d=$SCOURSH_RUN_DIR
occurrence_reset_unit bare.py
emit_match "$d" SAST-BASE-BARE-01 bare.py 1 bA
findings_merge "$d"
FP1=$(fp_of_check "$d" SAST-BASE-BARE-01)
write_baseline "$DEFAULT_BASELINE" "[\"$FP1\"]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-BARE-01)" 'the bare string matched by exact fingerprint equality'
assert_eq '' "$(suppressed_by_of "$d" SAST-BASE-BARE-01)" 'a bare-string entry carries no reason - the §11 default'
assert_eq true "$(state_suppressed_of "$FP1")" \
  'the write-side state record (already added by diff_classify_run before this call) is updated too - tension 11 stage 8: persist ALL findings, suppressed ones included, with the TRUE suppressed value'

t_case 'a full object entry suppresses and carries its reason into suppressed_by'
new_run obj
d=$SCOURSH_RUN_DIR
occurrence_reset_unit obj.py
emit_match "$d" SAST-BASE-OBJ-01 obj.py 1 oA
findings_merge "$d"
FP2=$(fp_of_check "$d" SAST-BASE-OBJ-01)
write_baseline "$DEFAULT_BASELINE" \
  "[{\"fingerprint\": \"$FP2\", \"reason\": \"accepted: tracked in TICKET-9\", \"added\": \"2026-01-01\", \"expires\": \"2099-01-01\"}]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-OBJ-01)" 'the object entry matched by fingerprint'
assert_eq 'accepted: tracked in TICKET-9' "$(suppressed_by_of "$d" SAST-BASE-OBJ-01)" \
  'its reason is carried into suppressed_by, which SARIF and both reports already render'
report_all "$d"
assert_contains "$(cat "$d/report.md")" 'accepted: tracked in TICKET-9' \
  'the reason reaches the human-readable report'
assert_contains "$(cat "$d/report.html")" 'accepted: tracked in TICKET-9' \
  'and the HTML report too'

t_case 'run.json baseline object reports used/file/entries honestly for a real baseline'
report_run_json "$d"
RUNJSON=$(cat "$d/run.json")
assert_contains "$RUNJSON" '"used": true' 'a real baseline file was consulted'
# `realpath_of` may normalise a symlinked tmpdir (e.g. macOS /var -> /private/var),
# so this asserts the meaningful suffix rather than $DEFAULT_BASELINE's own
# unresolved literal path.
assert_contains "$RUNJSON" 'install/config/baseline.json' 'run.json names the resolved file'
assert_contains "$RUNJSON" '"entries": 1' 'and the entry count'

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: suppression excludes a finding from the gate (tension 11 stage 7 reads suppressed==false, unchanged by this ticket) --\n'
# ---------------------------------------------------------------------------

rm -f "$DEFAULT_BASELINE"
t_case 'a critical finding baselined away does not trip --fail-on critical'
new_run gated
d=$SCOURSH_RUN_DIR
occurrence_reset_unit gated.py
finding_new
finding_set check_id SAST-BASE-GATE-01
finding_set module sast
finding_set title t
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set loc_path gated.py
finding_set loc_line 1
finding_set cell .
finding_set_match gA
finding_set_evidence gA
finding_emit
findings_merge "$d"
FP3=$(fp_of_check "$d" SAST-BASE-GATE-01)
write_baseline "$DEFAULT_BASELINE" "[\"$FP3\"]"
diff_classify_run "$d"
baseline_apply "$d"
declare -A SCAN_FLAGS=()
SCOURSH_FAIL_ON=critical
export SCOURSH_FAIL_ON
sast_evaluate_gate "$d"
assert_eq pass "$SCOURSH_GATE_RESULT" \
  'the ONLY finding this run is critical and would otherwise fail the gate - passing proves suppression really excludes it, not merely that nothing else fired'
assert_eq 0 "$SCOURSH_GATED_FINDINGS" 'zero findings counted toward the gate'
unset SCAN_FLAGS SCOURSH_FAIL_ON

# ---------------------------------------------------------------------------
printf '\n-- tension 11'"'"'s four ordering hazards --\n'
# ---------------------------------------------------------------------------

rm -rf "$STATE_DIR"
rm -f "$DEFAULT_BASELINE"

t_case 'seed run 1: a finding is present and baselined (suppressed), and persisted'
new_run haz1 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit hazard.py
emit_match "$d" SAST-BASE-HAZ-01 hazard.py 1 hzA
findings_merge "$d"
HAZ_FP=$(fp_of_check "$d" SAST-BASE-HAZ-01)
write_baseline "$DEFAULT_BASELINE" "[\"$HAZ_FP\"]"
state_add_covered SAST-BASE-HAZ-01 digest-haz path-root .
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-HAZ-01)" 'suppressed in run 1'
state_write "$STATE_DIR" 30
_t_ok 'run 1 persisted with suppressed:true'

t_case 'ordering hazard 1 - unsuppress does not create new: remove the baseline entry, the identical finding recurs as recurring, never new'
rm -f "$DEFAULT_BASELINE"
new_run haz2 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit hazard.py
emit_match "$d" SAST-BASE-HAZ-01 hazard.py 1 hzA
findings_merge "$d"
state_add_covered SAST-BASE-HAZ-01 digest-haz path-root .
diff_classify_run "$d"
baseline_apply "$d"
assert_eq recurring "$(status_of "$d" SAST-BASE-HAZ-01)" \
  'removing the baseline entry must not manufacture "new" - fails if suppression were treated as a diff input (tension 11 rejected option 2) instead of a late annotation persisted regardless of suppressed state'
assert_eq false "$(suppressed_of "$d" SAST-BASE-HAZ-01)" 'and it is genuinely unsuppressed now, live in this report'
state_write "$STATE_DIR" 30

t_case 'ordering hazard 2 - suppressed-can-still-be-fixed: baseline it again, then let the finding disappear for real'
rm -f "$DEFAULT_BASELINE"
new_run haz3 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit hazard.py
emit_match "$d" SAST-BASE-HAZ-01 hazard.py 1 hzA
findings_merge "$d"
write_baseline "$DEFAULT_BASELINE" "[\"$HAZ_FP\"]"
state_add_covered SAST-BASE-HAZ-01 digest-haz path-root .
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-HAZ-01)" 'suppressed again, seeding the next run'
state_write "$STATE_DIR" 30

new_run haz4 root-H
d=$SCOURSH_RUN_DIR
# The finding is genuinely gone this run (nothing emitted for it); the check
# is still covered, and the SAME baseline entry is still on disk - it now
# matches nothing.
state_add_covered SAST-BASE-HAZ-01 digest-haz path-root .
diff_classify_run "$d"
baseline_apply "$d"
read -r st reason <<<"$(absent_row "$d" SAST-BASE-HAZ-01)"
assert_eq fixed "$st" \
  'a SUPPRESSED prior finding that genuinely disappears is still reported fixed - fails if suppression were consulted anywhere in absent-finding classification instead of being pipeline stage 6, strictly after classify (5)'
assert_contains "$(cat "$d/meta/baseline_stale" 2>/dev/null)" "$HAZ_FP" \
  'and the now-useless baseline entry is reported stale - the report'"'"'s own "note to prune the entry" (tension 11)'

t_case 'ordering hazard 3 - an expired entry stops suppressing a still-present finding'
rm -rf "$STATE_DIR"
new_run haz5 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit expiring.py
emit_match "$d" SAST-BASE-EXP-01 expiring.py 1 exA
findings_merge "$d"
EXP_FP=$(fp_of_check "$d" SAST-BASE-EXP-01)
write_baseline "$DEFAULT_BASELINE" \
  "[{\"fingerprint\": \"$EXP_FP\", \"reason\": \"temporary\", \"added\": \"2020-01-01\", \"expires\": \"2020-06-30\"}]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq false "$(suppressed_of "$d" SAST-BASE-EXP-01)" \
  'an entry whose expires date is long past must not suppress - fails if expiry is parsed but never actually checked'
assert_contains "$(cat "$d/meta/baseline_expired" 2>/dev/null)" "$EXP_FP" \
  'and the run records WHY: an expired entry, distinct from a stale one'
assert_not_contains "$(cat "$d/meta/baseline_stale" 2>/dev/null)" "$EXP_FP" \
  'an expired-but-MATCHING entry is "expired", never "stale" - the two answer different operator questions'

t_case 'an entry whose expires date is still in the future keeps suppressing'
new_run haz6 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit expiring.py
emit_match "$d" SAST-BASE-EXP-01 expiring.py 1 exA
findings_merge "$d"
write_baseline "$DEFAULT_BASELINE" \
  "[{\"fingerprint\": \"$EXP_FP\", \"reason\": \"temporary\", \"added\": \"2020-01-01\", \"expires\": \"2099-01-01\"}]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-EXP-01)" \
  'a far-future expires date has not passed, so the entry still suppresses - fails under an inverted expiry comparison'

t_case 'ordering hazard 4 - a stale entry is reported, and does not stop other entries in the same file from being applied'
rm -f "$DEFAULT_BASELINE"
new_run haz7 root-H
d=$SCOURSH_RUN_DIR
occurrence_reset_unit stale-mix.py
emit_match "$d" SAST-BASE-MIX-01 stale-mix.py 1 mxA
findings_merge "$d"
MIX_FP=$(fp_of_check "$d" SAST-BASE-MIX-01)
write_baseline "$DEFAULT_BASELINE" "[\"$MIX_FP\", \"totally-unmatched-fingerprint-xyz\"]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-MIX-01)" \
  'the entry that DOES match is still applied even though a sibling entry in the same file matches nothing'
assert_contains "$(cat "$d/meta/baseline_stale" 2>/dev/null)" 'totally-unmatched-fingerprint-xyz' \
  'and the unmatched sibling is reported stale, not silently dropped or fatal'

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: called more than once in one process (scan.sh all'"'"'s own shape) --\n'
# ---------------------------------------------------------------------------

rm -rf "$STATE_DIR"
rm -f "$DEFAULT_BASELINE"
t_case 'a second call over a GROWN findings.fields recomputes fresh: an entry stale on the first call becomes suppressing once its finding exists'
new_run multi root-M
d=$SCOURSH_RUN_DIR
occurrence_reset_unit multi.py
emit_match "$d" SAST-BASE-MULTI-A-01 multi.py 1 mA
findings_merge "$d"
MULTI_FP_A=$(fp_of_check "$d" SAST-BASE-MULTI-A-01)
write_baseline "$DEFAULT_BASELINE" "[\"$MULTI_FP_A\", \"multi-b-not-yet-emitted\"]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-MULTI-A-01)" 'first call: A is present and suppressed'
assert_contains "$(cat "$d/meta/baseline_stale")" 'multi-b-not-yet-emitted' 'first call: B not emitted yet, reported stale'
# A second module now appends its own finding to the SAME findings.fields,
# exactly as modules/iac/run.sh's own diff_classify_run/baseline_apply calls
# do in a real `scan.sh all` run.
finding_new
finding_set check_id SAST-BASE-MULTI-B-01
finding_set module sast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path multi.py
finding_set loc_line 2
finding_set cell .
finding_set_match mB
finding_set_evidence mB
finding_emit
findings_merge "$d"
MULTI_FP_B=$(fp_of_check "$d" SAST-BASE-MULTI-B-01)
write_baseline "$DEFAULT_BASELINE" "[\"$MULTI_FP_A\", \"$MULTI_FP_B\"]"
diff_classify_run "$d"
baseline_apply "$d"
assert_eq true "$(suppressed_of "$d" SAST-BASE-MULTI-A-01)" 'second call: A is still suppressed'
assert_eq true "$(suppressed_of "$d" SAST-BASE-MULTI-B-01)" \
  'second call: B now exists and is suppressed too - fails if a prior call''s ledger were merged/appended rather than fully recomputed'
assert_not_contains "$(cat "$d/meta/baseline_stale")" "$MULTI_FP_B" \
  'B is no longer reported stale once it actually matches something'
assert_eq 2 "$(cat "$d/meta/baseline_entries")" 'the entry count reflects the LAST call only, not an accumulation across calls'

# ---------------------------------------------------------------------------
printf '\n-- baseline_apply: an unusable baseline fails LOUDLY, never silently everything-or-nothing --\n'
# ---------------------------------------------------------------------------
# docs/USAGE.md's own named failure this ticket closes: "a CI pipeline with a
# typo in the baseline path gets a clean exit and no trace anywhere that
# suppression never ran."  Every case below must be a real, nonzero,
# distinguishable exit - never a quiet fall-through to "no baseline".

rm -f "$DEFAULT_BASELINE"

t_case 'an explicit --baseline naming a path that does not exist dies loudly (SCOURSH_EXIT_INPUT), rather than the pre-fix silent accept'
new_run badexplicit
d=$SCOURSH_RUN_DIR
declare -A SCAN_FLAGS=([baseline]="$W/no-such-baseline.json")
ERR=$W/err.badexplicit
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'a typo''d --baseline path is a real error - fails under docs/USAGE.md''s documented pre-fix behaviour, "accepted with no error and no warning"'
assert_contains "$(cat "$ERR")" 'no such file' 'and the message names the problem'
unset SCAN_FLAGS

t_case 'the DEFAULT config/baseline.json missing is fine, but present-and-unreadable is not silently treated as absent'
if [[ $(id -u) -eq 0 ]]; then
  _t_ok 'skipped: running as root, permission bits are not enforced'
else
  new_run unreadable
  d=$SCOURSH_RUN_DIR
  write_baseline "$DEFAULT_BASELINE" '[]'
  chmod 000 "$DEFAULT_BASELINE"
  ERR=$W/err.unreadable
  rc=0
  ( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
  chmod 644 "$DEFAULT_BASELINE"
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
    'a baseline file that exists but cannot be opened is reported, never silently treated as "no baseline" - the direction that would silently suppress NOTHING'
  assert_contains "$(cat "$ERR")" 'not readable' 'with a message naming why'
fi
rm -f "$DEFAULT_BASELINE"

t_case 'malformed JSON in the default file dies loudly'
write_baseline "$DEFAULT_BASELINE" '[{"fingerprint": "abc"'
new_run badjson
d=$SCOURSH_RUN_DIR
ERR=$W/err.badjson
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'unparsable JSON is a real error, not a quiet empty baseline'
assert_contains "$(cat "$ERR")" 'not valid JSON' 'with a message saying so'
rm -f "$DEFAULT_BASELINE"

t_case 'a top-level object instead of an array dies loudly'
write_baseline "$DEFAULT_BASELINE" '{"fingerprint": "abc"}'
new_run badtoplevel
d=$SCOURSH_RUN_DIR
ERR=$W/err.badtoplevel
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'a bare object at the top level is rejected, never silently treated as one entry or as none'
rm -f "$DEFAULT_BASELINE"

t_case 'an object entry with no fingerprint at all dies loudly'
write_baseline "$DEFAULT_BASELINE" '[{"reason": "oops, forgot the fingerprint"}]'
new_run badnofp
d=$SCOURSH_RUN_DIR
ERR=$W/err.badnofp
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'an entry with no fingerprint suppresses nothing meaningful and is rejected rather than silently ignored'
assert_contains "$(cat "$ERR")" 'no fingerprint' 'with a message naming the missing field'
rm -f "$DEFAULT_BASELINE"

t_case 'an unrecognized field in an entry dies loudly (catches a typo''d key rather than silently ignoring it)'
write_baseline "$DEFAULT_BASELINE" '[{"fingerprint": "abc", "raeson": "typo"}]'
new_run badfield
d=$SCOURSH_RUN_DIR
ERR=$W/err.badfield
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'a misspelled key is rejected loudly - fails under a lenient reader that would silently drop the reason a typo like this was meant to carry'
rm -f "$DEFAULT_BASELINE"

t_case 'two entries sharing one fingerprint die loudly (ambiguous which reason/expiry would apply)'
write_baseline "$DEFAULT_BASELINE" '["dup-fp-one", {"fingerprint": "dup-fp-one", "reason": "second"}]'
new_run baddupe
d=$SCOURSH_RUN_DIR
ERR=$W/err.baddupe
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'a duplicate fingerprint is rejected rather than silently keeping one of the two'
assert_contains "$(cat "$ERR")" 'duplicate fingerprint' 'with a message naming which'
rm -f "$DEFAULT_BASELINE"

t_case 'an unparseable expires date dies loudly rather than silently never-expiring or always-expiring'
write_baseline "$DEFAULT_BASELINE" '[{"fingerprint": "abc", "reason": "x", "expires": "not-a-date"}]'
new_run baddate
d=$SCOURSH_RUN_DIR
ERR=$W/err.baddate
rc=0
( baseline_apply "$d" ) >/dev/null 2>"$ERR" || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'a garbage expires value is rejected rather than silently misinterpreted in either direction'
rm -f "$DEFAULT_BASELINE"

t_summary 'state-baseline' || FAILED=1
exit "${FAILED:-0}"
