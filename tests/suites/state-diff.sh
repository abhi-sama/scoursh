#!/usr/bin/env bash
# tests/suites/state-diff.sh - lib/diff.sh (docs/STEP7-STATE-PLAN.md STATE-06):
# the `diff` command, automatic per-run classification, and the report delta.
#
# What this ticket wires together was already built and fixture-tested in
# isolation (STATE-01 through STATE-05): this suite is what proves the wiring
# itself - that a REAL loaded state/latest.json and a REAL run's own
# findings.fields, run through lib/diff.sh, actually produce the tension-12
# table's answers and a report a human can read the difference in.
#
# Every case names the reading it FAILS under, per AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/state-diff
rm -rf "$W"
mkdir -p "$W"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"
attribution_load "$ROOT/tests/fixtures/config/scope.conf"

# An ISOLATED install root for the whole suite: `lib/state.sh`'s
# `state_default_dir` has no override besides `SCOURSH_INSTALL_ROOT`, and this
# suite writes and reads real state/latest.json files - a shared location
# would let one t_case's prior state leak into the next, or into the real
# repository's own `state/` (docs/STEP7-STATE-PLAN.md STATE-06's own fix to
# tests/suites/sast.sh and iac.sh documents the identical hazard for real
# `scan.sh` subprocesses).
INSTALL=$W/install
mkdir -p "$INSTALL"
SCOURSH_INSTALL_ROOT=$INSTALL
export SCOURSH_INSTALL_ROOT
STATE_DIR=$INSTALL/state

# `new_run NAME [SCAN_ROOT_ID] [PATH_ROOT]` - a fresh run directory AND a
# fresh write-side state/ builder (`state_reset` + `state_set_run`), mirroring
# scan_main's own `_scan_state_begin` - the write-side builder is a set of
# plain globals that otherwise accumulates across calls in one process
# (tests/suites/findings.sh's own `new_run` establishes the identical
# run-directory half of this convention; STATE-06 needs the state half too).
new_run() {
  rm -rf "${W:?}/run.$1"
  SCOURSH_RUN_DIR=''
  SCOURSH_RUN_ID=''
  occurrence_reset_all
  run_init "$W/run.$1"
  state_reset
  SCOURSH_SCAN_ROOT_ID=${2:-root-default}
  SCOURSH_PATH_ROOT=${3:-.}
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

first_seen_of() {                # first_seen_of RUNDIR CHECK -> its first_seen
  local d=$1 check=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]} == "$check" ]] || continue
    printf '%s' "${_DF[first_seen]}"
    return 0
  done <"$d/findings.fields"
}

# `absent_row RUNDIR CHECK` -> the meta/diff_absent line for CHECK, or empty.
absent_row() {
  local d=$1 check=$2 line
  [[ -r $d/meta/diff_absent ]] || return 0
  while IFS=$'\x1f' read -r status reason c cell severity first_seen fp; do
    [[ $c == "$check" ]] || continue
    printf '%s\t%s' "$status" "$reason"
    return 0
  done <"$d/meta/diff_absent"
}

# ---------------------------------------------------------------------------
printf '\n-- diff_classify_run: the four-row table over a real state/latest.json --\n'
# ---------------------------------------------------------------------------

rm -rf "$STATE_DIR"
t_case 'a first-ever run: every finding is new, not unknown (tension 11: a first run is new, never unknown)'
new_run first
d=$SCOURSH_RUN_DIR
occurrence_reset_unit first.py
emit_match "$d" SAST-DIFF-ONE-01 first.py 1 xa
findings_merge "$d"
state_add_covered SAST-DIFF-ONE-01 digest1 path-root .
diff_classify_run "$d"
assert_eq new "$(status_of "$d" SAST-DIFF-ONE-01)" 'no prior state at all: new, not unknown'
assert_eq false "${SCOURSH_DIFF_USABLE:-}" 'diff_usable is false with no prior state'
assert_eq no_prior_state "${SCOURSH_DIFF_GUARD:-}" 'and the guard says why'

# Persist THIS run as the "prior" state for every scenario below.
state_write "$STATE_DIR" 30

t_case 'recurring: the identical finding, present again, classifies recurring and its ORIGINAL first_seen is preserved'
new_run recur
d=$SCOURSH_RUN_DIR
occurrence_reset_unit first.py
emit_match "$d" SAST-DIFF-ONE-01 first.py 1 xa
findings_merge "$d"
state_add_covered SAST-DIFF-ONE-01 digest1 path-root .
diff_classify_run "$d"
assert_eq recurring "$(status_of "$d" SAST-DIFF-ONE-01)" \
  'identical fingerprint present in state/latest.json -> recurring, not new'
assert_eq true "$SCOURSH_DIFF_USABLE" 'usable prior state makes diff_usable true'
PRIOR_FIRST_SEEN=$(first_seen_of "$W/run.first" SAST-DIFF-ONE-01)
assert_eq "$PRIOR_FIRST_SEEN" "$(first_seen_of "$d" SAST-DIFF-ONE-01)" \
  'tension 11 stage 8: first_seen is PRESERVED across a recurring classification - fails under "every emitted finding stamps first_seen at emission time, unconditionally", the pre-STATE-06 behaviour'

t_case 'fixed: covered this run, prior finding absent -> fixed'
new_run fixed
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-ONE-01 digest1 path-root .
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" SAST-DIFF-ONE-01)"
assert_eq fixed "$st" 'the check and cell were covered this run and the finding is gone -> fixed'

t_case 'unknown: NOT covered this run, prior finding absent -> unknown (not fixed) - the middle row of tension 12s table'
new_run notcov
d=$SCOURSH_RUN_DIR
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" SAST-DIFF-ONE-01)"
assert_eq unknown "$st" \
  'the check was never run this run, so absence proves nothing - fails under a naive diff that reports fixed on any absence'
assert_eq not-covered-this-run "$reason" 'and the reason names why'

t_case 'a genuinely new check id, never seen before, classifies new'
new_run brandnew
d=$SCOURSH_RUN_DIR
occurrence_reset_unit second.py
emit_match "$d" SAST-DIFF-TWO-01 second.py 1 yb
findings_merge "$d"
state_add_covered SAST-DIFF-TWO-01 digest2 path-root .
diff_classify_run "$d"
assert_eq new "$(status_of "$d" SAST-DIFF-TWO-01)" 'no prior finding for this check at all -> new'

# ---------------------------------------------------------------------------
printf '\n-- diff_classify_run: the two guards --\n'
# ---------------------------------------------------------------------------

# `FP_SCHEMA` (lib/findings.sh) is a frozen, readonly constant (tension 5) -
# a real run can never observe a different value of its OWN. What CAN differ
# is the PRIOR run's persisted value, which is exactly what a tool upgrade
# that bumps fp/1 to fp/2 looks like from a later run's point of view, so the
# prior state built here carries a fake, mismatched fp_schema rather than
# trying (and failing) to override the real constant.
rm -rf "$STATE_DIR"
t_case 'fp_schema mismatch: seed a prior run under a different fp_schema'
new_run schemaseed
d=$SCOURSH_RUN_DIR
occurrence_reset_unit schemamismatch.py
emit_match "$d" SAST-DIFF-SCHEMA-PRESENT-01 schemamismatch.py 1 smA
findings_merge "$d"
SEED_FP=$(fp_of_check "$d" SAST-DIFF-SCHEMA-PRESENT-01)
state_add_covered SAST-DIFF-SCHEMA-PRESENT-01 digest-s1 path-root .
state_add_covered SAST-DIFF-SCHEMA-ABSENT-01 digest-s2 path-root .
state_add_finding "$SEED_FP" SAST-DIFF-SCHEMA-PRESENT-01 . high 2025-01-01T00:00:00Z 2025-01-01T00:00:00Z false
state_add_finding fp-schema-absent SAST-DIFF-SCHEMA-ABSENT-01 . high 2025-01-01T00:00:00Z 2025-01-01T00:00:00Z false
# Overrides only the run-level fields (fp_schema included); state_set_run
# never clears already-recorded coverage/findings (its own header comment).
state_set_run schemaseed root-default fp/999-mismatch test-tool-version
state_write "$STATE_DIR" 30
_t_ok 'prior seeded under fp/999-mismatch'

t_case 'fp_schema mismatch: the prior set is treated as empty - present is new, absent is unknown, never fixed'
new_run schemamismatch
d=$SCOURSH_RUN_DIR
occurrence_reset_unit schemamismatch.py
emit_match "$d" SAST-DIFF-SCHEMA-PRESENT-01 schemamismatch.py 1 smA
findings_merge "$d"
state_add_covered SAST-DIFF-SCHEMA-PRESENT-01 digest-s1 path-root .
state_add_covered SAST-DIFF-SCHEMA-ABSENT-01 digest-s2 path-root .
diff_classify_run "$d"
assert_eq new "$(status_of "$d" SAST-DIFF-SCHEMA-PRESENT-01)" \
  'the identical fingerprint reappears under a bumped fp_schema, but the table never reaches it - fails under "the raw table decides, so the whole backlog reports fixed"'
assert_eq false "$SCOURSH_DIFF_USABLE" 'an fp_schema mismatch is fail-closed at the gate'
assert_eq fp_schema_mismatch "$SCOURSH_DIFF_GUARD" 'and the report can say which guard fired'
read -r st reason <<<"$(absent_row "$d" SAST-DIFF-SCHEMA-ABSENT-01)"
assert_eq unknown "$st" 'the prior backlog is carried forward unknown, never fixed, across an fp_schema bump'
assert_eq fp_schema_mismatch "$reason" 'with the mismatch as its own reason'

t_case 'scan_root_id mismatch: scoped to path-root cells only - a target-scoped prior finding is unaffected'
rm -rf "$STATE_DIR"
new_run scoperoot-a root-A
d=$SCOURSH_RUN_DIR
occurrence_reset_unit scoped.py
emit_match "$d" SAST-DIFF-SCOPED-01 scoped.py 1 zc
findings_merge "$d"
state_add_covered SAST-DIFF-SCOPED-01 digest3 path-root .
state_add_covered DAST-DIFF-TARGET-01 digest4 target staging
finding_new
finding_set check_id DAST-DIFF-TARGET-01
finding_set module dast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_target staging
finding_set cell staging
finding_set_match dast-marker
finding_set_evidence dast-marker
finding_emit
findings_merge "$d"
diff_classify_run "$d"
state_write "$STATE_DIR" 30

new_run scoperoot-b root-B
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-SCOPED-01 digest3 path-root .
state_add_covered DAST-DIFF-TARGET-01 digest4 target staging
diff_classify_run "$d"
assert_eq false "$SCOURSH_DIFF_USABLE" 'a path-root-scoped run with a scan_root_id mismatch is fail-closed'
assert_eq scan_root_id_mismatch "$SCOURSH_DIFF_GUARD" 'and the report can say which guard fired'
read -r st reason <<<"$(absent_row "$d" SAST-DIFF-SCOPED-01)"
assert_eq unknown "$st" 'the path-root prior finding is unknown, never fixed, across a scan_root_id change'
assert_eq scan_root_id_mismatch "$reason" 'with the mismatch as its own reason'
read -r st2 reason2 <<<"$(absent_row "$d" DAST-DIFF-TARGET-01)"
assert_eq fixed "$st2" \
  'the target-scoped prior finding is classified NORMALLY despite the scan_root_id mismatch - fails under a global gate, which would report it unknown for a reason (the scan root) that has nothing to do with a DAST target'
assert_eq '' "$reason2" 'a fixed classification carries no reason - one is only ever recorded for unknown'

# ---------------------------------------------------------------------------
printf '\n-- diff_classify_run: SAST-HIST-* boundary refinement (tension 13) --\n'
# ---------------------------------------------------------------------------

rm -rf "$STATE_DIR"
t_case 'seed a history finding with a known oldest_reaching_commit_time'
new_run histseed root-H
d=$SCOURSH_RUN_DIR
state_add_covered SAST-HIST-DIFF-01 digest5 path-root .
state_add_finding fp-hist-1 SAST-HIST-DIFF-01 . critical 2025-01-01T00:00:00Z 2025-01-01T00:00:00Z false 2025-01-01T00:00:00Z
state_add_history_boundary SAST-HIST-DIFF-01 abc123 2025-01-01T00:00:00Z 100 window-days
state_write "$STATE_DIR" 30
_t_ok 'fixture seeded'

t_case 'the boundary receded past the finding: unknown, not fixed'
new_run histrecede root-H
d=$SCOURSH_RUN_DIR
state_add_covered SAST-HIST-DIFF-01 digest5 path-root .
state_add_history_boundary SAST-HIST-DIFF-01 def456 2026-01-01T00:00:00Z 50 window-days
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" SAST-HIST-DIFF-01)"
assert_eq unknown "$st" \
  'this run could not have seen a blob whose only reaching commit predates the walk boundary - fails under a bare (check,cell)-covered test, which would report fixed'
assert_eq history_boundary_receded "$reason" 'with the tension-13 reason recorded'

t_case 'the boundary still reaches the finding: fixed'
new_run histreach root-H
d=$SCOURSH_RUN_DIR
state_add_covered SAST-HIST-DIFF-01 digest5 path-root .
state_add_history_boundary SAST-HIST-DIFF-01 def456 2024-01-01T00:00:00Z 200 window-days
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" SAST-HIST-DIFF-01)"
assert_eq fixed "$st" 'the walk could have seen the blob and did not -> fixed'

# ---------------------------------------------------------------------------
printf '\n-- diff_classify_run: rule_changed_checks --\n'
# ---------------------------------------------------------------------------

rm -rf "$STATE_DIR"
new_run ruleseed root-R
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-RULE-01 digest-v1 path-root .
state_write "$STATE_DIR" 30

t_case 'a covered checks rule_digest changed since the prior run is flagged in run.json'
new_run rulechanged root-R
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-RULE-01 digest-v2 path-root .
diff_classify_run "$d"
assert_contains "$(cat "$d/meta/rule_changed_checks" 2>/dev/null || true)" 'SAST-DIFF-RULE-01' \
  'the digest changed, so the report can flag "new/fixed for this check may reflect the rule edit"'

t_case 'an UNCHANGED rule_digest is never flagged'
new_run rulesame root-R
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-RULE-01 digest-v1 path-root .
diff_classify_run "$d"
assert_not_contains "$(cat "$d/meta/rule_changed_checks" 2>/dev/null || true)" 'SAST-DIFF-RULE-01' \
  'the digest is unchanged, so nothing is flagged'

# ---------------------------------------------------------------------------
printf '\n-- diff_classify_run: derived (composite) findings, tension 6 --\n'
# ---------------------------------------------------------------------------
# Reuses the project-wide fixture composite (tests/fixtures/rules/derived.rules)
# STATE-03/04/05's own suites already test classify_derived against - this
# section proves lib/diff.sh actually CALLS it for a real prior composite,
# never a second, ad hoc reimplementation of tension 6's rule.

rm -rf "$STATE_DIR"
DERIVED_RULES=$ROOT/tests/fixtures/rules/derived.rules

t_case 'a composite present again (both contributors still fire) classifies recurring, exactly like an ordinary finding'
new_run compseed root-C
d=$SCOURSH_RUN_DIR
occurrence_reset_unit comp.py
finding_new
finding_set check_id SAST-SEC-AWS_SECRET-01
finding_set module sast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path comp.py
finding_set loc_line 1
finding_set cell .
finding_set_match secretA
finding_set_evidence secretA
finding_emit
finding_new
finding_set check_id SAST-PY-EVAL-01
finding_set module sast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path comp.py
finding_set loc_line 2
finding_set cell .
finding_set_match evalA
finding_set_evidence evalA
finding_emit
findings_merge "$d"
derive_findings "$d" "$DERIVED_RULES"
state_add_covered SAST-SEC-AWS_SECRET-01 digestA path-root .
state_add_covered SAST-PY-EVAL-01 digestB path-root .
COMP_FP=$(fp_of_check "$d" COMPOSITE-FIXTURE-CHAIN)
assert_ne '' "$COMP_FP" 'the fixture composite fired (its fingerprint is non-empty)'
diff_classify_run "$d"
assert_eq new "$(status_of "$d" COMPOSITE-FIXTURE-CHAIN)" 'no prior composite of this fingerprint -> new, same rule as any ordinary finding'
# diff_classify_run itself records every present finding - composite and
# ordinary contributors alike - into the write-side state builder (tension 11
# stage 8), so state_write below persists this run's real composite, cell
# JSON null and all, with no manual state_add_finding call needed here.
state_write "$STATE_DIR" 30

new_run compagain root-C
d=$SCOURSH_RUN_DIR
occurrence_reset_unit comp.py
finding_new
finding_set check_id SAST-SEC-AWS_SECRET-01
finding_set module sast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path comp.py
finding_set loc_line 1
finding_set cell .
finding_set_match secretA
finding_set_evidence secretA
finding_emit
finding_new
finding_set check_id SAST-PY-EVAL-01
finding_set module sast
finding_set title t
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path comp.py
finding_set loc_line 2
finding_set cell .
finding_set_match evalA
finding_set_evidence evalA
finding_emit
findings_merge "$d"
derive_findings "$d" "$DERIVED_RULES"
state_add_covered SAST-SEC-AWS_SECRET-01 digestA path-root .
state_add_covered SAST-PY-EVAL-01 digestB path-root .
diff_classify_run "$d"
assert_eq recurring "$(status_of "$d" COMPOSITE-FIXTURE-CHAIN)" \
  'the identical composite fingerprint (correlate-on: file, same file) fired again -> recurring, not new'

t_case 'the composite no longer fires and its contributors were revisited (chain broken) -> fixed'
new_run compbroken root-C
d=$SCOURSH_RUN_DIR
state_add_covered SAST-SEC-AWS_SECRET-01 digestA path-root .
state_add_covered SAST-PY-EVAL-01 digestB path-root .
# The fixture composite's `any-of` names TWO alternatives
# (SAST-PY-EVAL-01, SAST-PY-YAML_LOAD-01); only the first ever fired, but
# (b2)'s FLOOR test (tension 6 case 9) requires every LISTED alternative to
# have an entry in THIS run's covered_checks, fired or not - so the second
# is covered here too, or this composite stays unknown for the same reason
# the "not revisited" case below is unknown, and the two tests would prove
# nothing different from each other.
state_add_covered SAST-PY-YAML_LOAD-01 digestC path-root .
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" COMPOSITE-FIXTURE-CHAIN)"
assert_eq fixed "$st" \
  'every contributor cell (both any-of alternatives, and requires) was revisited and neither finding recurred - fails if lib/diff.sh reimplements a weaker coverage test instead of calling classify_derived'

t_case 'the composite no longer fires and a contributor cell was NOT revisited -> unknown, never fixed'
new_run compuncov root-C
d=$SCOURSH_RUN_DIR
state_add_covered SAST-SEC-AWS_SECRET-01 digestA path-root .
diff_classify_run "$d"
read -r st reason <<<"$(absent_row "$d" COMPOSITE-FIXTURE-CHAIN)"
assert_eq unknown "$st" \
  'SAST-PY-EVAL-01 (an any-of alternative) was never covered this run, so the chain could still be open - fails under "covered in at least one contributor" style leniency'

# ---------------------------------------------------------------------------
printf '\n-- the report distinguishes "fixed" from "not assessed this run" in TEXT a human reads --\n'
# ---------------------------------------------------------------------------
# The ticket's own acceptance criterion, verbatim: a reader must be able to
# tell "we checked and it is gone" from "we never looked" from the rendered
# report, not only from run.json.

rm -rf "$STATE_DIR"
new_run reportseed root-P
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFF-FIXED-01 digestF path-root .
state_add_covered SAST-DIFF-UNKNOWN-01 digestU path-root .
state_add_finding fp-will-be-fixed SAST-DIFF-FIXED-01 . high 2025-01-01T00:00:00Z 2025-01-01T00:00:00Z false
state_add_finding fp-will-be-unknown SAST-DIFF-UNKNOWN-01 . high 2025-01-01T00:00:00Z 2025-01-01T00:00:00Z false
state_write "$STATE_DIR" 30

t_case 'report.md text distinguishes fixed vs not-assessed-this-run'
new_run reportfinal root-P
d=$SCOURSH_RUN_DIR
# This run covers SAST-DIFF-FIXED-01 (so its prior finding is verified gone)
# but never covers SAST-DIFF-UNKNOWN-01 (so its prior finding was never
# looked at).
state_add_covered SAST-DIFF-FIXED-01 digestF path-root .
diff_classify_run "$d"
sast_evaluate_gate "$d"
report_all "$d"
REPORT=$(cat "$d/report.md")
assert_contains "$REPORT" '## Since last scan' 'the delta leads the report (tension 11 stage 9)'
assert_contains "$REPORT" 'Fixed since last scan' 'a heading names the fixed finding'
assert_contains "$REPORT" 'Not assessed this run' 'a DIFFERENT heading names the unknown finding'
assert_contains "$REPORT" 'SAST-DIFF-FIXED-01' 'the fixed check id is listed under "Fixed since last scan"'
assert_contains "$REPORT" 'SAST-DIFF-UNKNOWN-01' 'the unknown check id is listed under "Not assessed this run"'
assert_contains "$REPORT" 'unknown, not verified fixed' \
  'the unknown section spells out in prose that this is NOT evidence of remediation - the exact blur tension 12 exists to prevent'
# The two check ids must not merely both appear somewhere - each must be
# under ITS OWN heading, never the other's, or the distinction is cosmetic.
FIXED_SECTION=${REPORT#*Fixed since last scan}
FIXED_SECTION=${FIXED_SECTION%%Not assessed this run*}
assert_contains "$FIXED_SECTION" 'SAST-DIFF-FIXED-01' 'the fixed check sits in the Fixed section'
assert_not_contains "$FIXED_SECTION" 'SAST-DIFF-UNKNOWN-01' \
  'the unknown check must NOT appear in the Fixed section - fails if the two ledgers are rendered as one undifferentiated list'
UNKNOWN_SECTION=${REPORT#*Not assessed this run}
assert_contains "$UNKNOWN_SECTION" 'SAST-DIFF-UNKNOWN-01' 'the unknown check sits in the Not-assessed section'
assert_not_contains "$UNKNOWN_SECTION" 'SAST-DIFF-FIXED-01' \
  'the fixed check must NOT appear in the Not-assessed section'

HTML_REPORT=$(cat "$d/report.html")
assert_contains "$HTML_REPORT" 'Fixed since last scan' 'the HTML report carries the identical distinction'
assert_contains "$HTML_REPORT" 'Not assessed this run' 'in its own heading'
assert_contains "$HTML_REPORT" 'unknown, not verified fixed' 'and the same prose warning'

# ---------------------------------------------------------------------------
printf '\n-- diff_render_against: the standalone `scan.sh diff --against <dir>` command --\n'
# ---------------------------------------------------------------------------
# Unlike diff_classify_run (this run's own findings, classified in place),
# this performs no scan at all: it classifies state/latest.json (the most
# recently completed real run - built here as "laterrun") against the state
# recorded for an explicit prior run directory ("priorrun"), matched to its
# own state/<run-id>.json by run id.

rm -rf "$STATE_DIR"
t_case 'seed the --against run (an older, already-persisted run)'
new_run priorrun root-D
d=$SCOURSH_RUN_DIR
state_add_covered SAST-DIFFCMD-FIXED-01 digestF path-root .
state_add_covered SAST-DIFFCMD-UNKNOWN-01 digestU path-root .
state_add_finding fp-diffcmd-fixed SAST-DIFFCMD-FIXED-01 . high 2025-02-01T00:00:00Z 2025-02-01T00:00:00Z false
state_add_finding fp-diffcmd-unknown SAST-DIFFCMD-UNKNOWN-01 . medium 2025-02-01T00:00:00Z 2025-02-01T00:00:00Z false
state_write "$STATE_DIR" 30
PRIOR_RUN_DIR=$d
_t_ok 'prior run seeded and persisted to its own state/run.priorrun.json'

t_case 'seed "this run" (the most recently completed real scan - state/latest.json)'
new_run laterrun root-D
d=$SCOURSH_RUN_DIR
occurrence_reset_unit diffcmd.py
emit_match "$d" SAST-DIFFCMD-NEW-01 diffcmd.py 1 dcNew
findings_merge "$d"
state_add_covered SAST-DIFFCMD-FIXED-01 digestF path-root .
# SAST-DIFFCMD-UNKNOWN-01 is deliberately NOT covered this run.
diff_classify_run "$d"
state_write "$STATE_DIR" 30
_t_ok '"this run" seeded and persisted as state/latest.json'

t_case 'diff_render_against classifies latest.json against the named prior run'
new_run diffcmdout root-D
d=$SCOURSH_RUN_DIR
diff_render_against "$PRIOR_RUN_DIR" "$d"
assert_eq true "$SCOURSH_DIFF_USABLE" 'same fp_schema and scan_root_id: the diff is usable'
assert_eq usable "$SCOURSH_DIFF_GUARD" 'and the guard says so'
assert_contains "$(cat "$d/meta/diff_present" 2>/dev/null)" 'SAST-DIFFCMD-NEW-01' \
  '"this run"''s own new finding is recorded in the present ledger'
NEW_LINE=$(grep -F 'SAST-DIFFCMD-NEW-01' "$d/meta/diff_present")
assert_eq new "${NEW_LINE%%$'\x1f'*}" 'and classified new (no prior fingerprint matches it)'
read -r st reason <<<"$(absent_row "$d" SAST-DIFFCMD-FIXED-01)"
assert_eq fixed "$st" 'covered this run, absent from it -> fixed, exactly as the automatic path would classify it'
read -r st reason <<<"$(absent_row "$d" SAST-DIFFCMD-UNKNOWN-01)"
assert_eq unknown "$st" 'never covered this run -> unknown, never fixed'

t_case 'diff_render_against renders its own report.md with the identical fixed/unknown distinction'
report_md "$d"
DIFFCMD_REPORT=$(cat "$d/report.md")
assert_contains "$DIFFCMD_REPORT" 'Fixed since last scan' 'the standalone command'"'"'s own report leads with the same delta section'
assert_contains "$DIFFCMD_REPORT" 'SAST-DIFFCMD-FIXED-01' 'naming the fixed check'
assert_contains "$DIFFCMD_REPORT" 'Not assessed this run' 'and the not-assessed heading'
assert_contains "$DIFFCMD_REPORT" 'SAST-DIFFCMD-UNKNOWN-01' 'naming the unknown check'

t_case 'diff_render_against with no completed run recorded is a clean, declared no-op'
rm -rf "$STATE_DIR"
new_run diffcmdempty root-D
d=$SCOURSH_RUN_DIR
diff_render_against "$PRIOR_RUN_DIR" "$d"
assert_contains "$(cat "$d/meta/coverage_reduction" 2>/dev/null || true)" 'no_completed_run_recorded' \
  'with no state/latest.json at all, this is a declared reduction, never a crash - fails if the function dies or silently produces an empty-but-successful report'

t_summary 'state-diff' || FAILED=1
exit "${FAILED:-0}"
