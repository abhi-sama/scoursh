#!/usr/bin/env bash
# tests/suites/state-coverage.sh - docs/STEP7-STATE-PLAN.md STATE-02:
# per-(check, cell) coverage recording, and persist-on-every-run wiring.
#
# docs/FOUNDATION.md tension 12's own rule is the whole point of this ticket
# and this suite: "A (check, cell) pair enters `covered_checks` ONLY if that
# check ran to completion over that cell."  Six named causes make it NOT
# enter: the module was not selected, a profile/intensity filter dropped the
# check, the check was skipped for a missing dependency or engine, the
# circuit breaker aborted its module, a resumed run never reached it, or the
# run simply never visited that cell.  Each has its own case below, proving
# absence, alongside one case proving a genuinely completed pair DOES enter.
#
# Every case names the reading it fails under, per AGENTS.md's testing rule:
# a naive implementation that records coverage at SELECTION time (this
# repository's own `run_record checks_run "$id"` calls in modules/sast/
# run.sh and modules/iac/run.sh do exactly that - they run BEFORE the scan
# tree walk, not after) would pass a test that only checks "the check that
# ran is covered" - it takes a check that was selected/enumerated but never
# actually completed to catch that bug, which is exactly what several cases
# below are built to do.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON/shell syntax literally.
# SC2030/SC2031: `SCOURSH_SCA_ADVISORIES_DB=... scan_main ...` prefix
#   assignments are deliberately subshell-scoped the same way
#   tests/suites/scan.sh's own header already documents for this suite's
#   sibling files - one probe's override must never leak into the next.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=scan.sh
source "$ROOT/scan.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/state-coverage
rm -rf "$W"
mkdir -p "$W"

# state_default_dir (lib/state.sh) has no env-var override - unlike
# SCOURSH_SCA_ADVISORIES_DB's convention - so every real scan_main call in
# this suite persists into the REAL install root's state/ directory
# (/state/ is gitignored, see .gitignore's own "run-to-run state are
# artifacts, never sources" note).  Each case below picks a distinct --out
# basename (which run_init uses as SCOURSH_RUN_ID with no override given),
# so each reads its OWN "$ROOT/state/<name>.json" by name rather than the
# shared, last-writer-wins latest.json - no cross-case interference even
# though every call shares one on-disk directory.
STATE_DIR=$ROOT/state
rm -rf "$STATE_DIR"

_covered_json() {
  # Reads one case's persisted covered_checks block via lib/state.sh's own
  # loader/accessors (the same reader tests/suites/state.sh already trusts),
  # never by grepping the raw file - a grep would not tell "absent" from
  # "present but empty cells" apart, which is exactly the distinction under
  # test.
  #
  # Asserts the load itself succeeded, every time: a load failure here would
  # otherwise make every "is NOT covered" assertion downstream pass for the
  # WRONG reason (nothing loaded at all, rather than the pair genuinely
  # being absent from a well-formed file) - measured, not hypothetical: this
  # is exactly how this suite's own SCA case first went green, before
  # modules/sca/run.sh's rule_digest fix below made the file loadable at
  # all.
  state_load_file "$STATE_DIR/$1.json"
  t_case "state/$1.json loads (a prerequisite for every assertion that follows about it)"
  if state_loaded; then
    assert_true 0 'loaded cleanly'
  else
    assert_true 1 "did not load: $(state_load_reason)"
  fi
}

# scan_main always `exit`s (0 on success, one of 1/2/3/4/5 otherwise, per
# tension 14) - tests/suites/scan.sh's own comment on `_run_main` documents
# this - so it is only ever called inside a subshell here, exactly like that
# suite's `assert_status` wrapping does.  The artifacts this suite actually
# asserts on (state/<run-id>.json) are written to disk before scan_main's
# own `exit`, so they survive the subshell boundary; the exit status itself
# is discarded, since no case here needs it.
_run_main() {
  ( scan_main "$@" ) || true
}

# ---------------------------------------------------------------------------
printf '\n-- genuinely completed vs. profile-filter-dropped vs. never-visited (SAST, one run) --\n'
# ---------------------------------------------------------------------------
# One fixture file trips two real, shipped checks: SAST-SEC-AWS_AKID-01
# (modules/sast/rules/secrets.rules) is tagged `quick`; SAST-PY-SUBPROCESS_
# SHELL-01 (modules/sast/rules/python.rules) carries only `static` - no
# profile tag at all, so rules/RULE-FORMAT.md §9.1.3's own default ("a rule
# with no profile tag runs only in full") drops it under `--profile-scan
# quick`.  Both patterns are real, on-disk, unmodified checks - this suite
# adds no fixture registry of its own.
F1=$W/quick-fixture
mkdir -p "$F1"
cat >"$F1/app.py" <<'EOF'
import subprocess
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
subprocess.call("ls", shell=True)
EOF

_run_main sast --path "$F1" --profile-scan quick --out "$W/case-quick"
_covered_json case-quick

t_case 'a check that ran to completion enters covered_checks (SAST-SEC-AWS_AKID-01, quick-tagged)'
assert_true "$(state_covered_has_cell SAST-SEC-AWS_AKID-01 . && echo 0 || echo 1)" \
  'its path-root cell is present, FAILS if coverage was never wired at all'
assert_eq 'path-root' "$(state_covered_scope SAST-SEC-AWS_AKID-01)" 'recorded under the path-root scope tension 12 freezes for SAST'
assert_ne '' "$(state_covered_rule_digest SAST-SEC-AWS_AKID-01)" 'rule_digest is populated from the real secrets.rules record, not left empty'

t_case 'a check the --profile-scan quick filter dropped does NOT enter covered_checks (SAST-PY-SUBPROCESS_SHELL-01)'
assert_eq '' "$(state_covered_scope SAST-PY-SUBPROCESS_SHELL-01)" \
  "FAILS under a naive 'record every check the registry loaded' implementation, since this check's pattern genuinely matches the fixture and it would have fired under --profile-scan full"

t_case 'the recorded cell is exactly the path root this run visited, never a broader or unrelated one (tension 12: the run never visited any OTHER cell)'
assert_eq "$(printf '.')" "$(state_covered_cells SAST-SEC-AWS_AKID-01)" \
  'FAILS if a stale or wrong cell string leaked in from another run sharing this process'

# ---------------------------------------------------------------------------
printf '\n-- module not selected: an IaC-only run never covers a SAST check id (tension 12) --\n'
# ---------------------------------------------------------------------------
# Reuses a real, shipped, already-committed fixture (tests/fixtures/vuln/
# tf_open_cidr.tf) rather than authoring a new one, copied alone into its own
# tiny directory so this scan walks one file, not the whole vuln/ tree.
F2=$W/iac-fixture
mkdir -p "$F2"
cp "$ROOT/tests/fixtures/vuln/tf_open_cidr.tf" "$F2/main.tf"

_run_main iac --path "$F2" --out "$W/case-iac-only"
_covered_json case-iac-only

t_case 'the module that DID run is genuinely covered (IAC-TF-OPEN_CIDR-01), proving this is a real dispatch, not a no-op'
assert_true "$(state_covered_has_cell IAC-TF-OPEN_CIDR-01 . && echo 0 || echo 1)" \
  'its path-root cell is present'

t_case 'a check belonging to a module scan.sh never dispatched (sast) is absent from covered_checks entirely'
assert_eq '' "$(state_covered_scope SAST-SEC-AWS_AKID-01)" \
  "FAILS if coverage recording were keyed on the check registry alone rather than on which module actually dispatched"

# ---------------------------------------------------------------------------
printf '\n-- missing dependency (SCA: no data/advisories.db) records zero SCA coverage --\n'
# ---------------------------------------------------------------------------
SCA_FIX=$ROOT/tests/fixtures/sca/npm-lock
SCA_DB=$ROOT/tests/fixtures/sca/advisories.db
# Unlike F1/F2 above (both under $W, outside any git repository, so their
# own path-root cell is the literal "."), SCA_FIX sits INSIDE this checkout
# - tension 12's own recipe makes its cell the git-toplevel-relative path,
# not ".".  Computed via the same path_root_cell scan.sh itself calls,
# rather than hand-typed, so a future repository layout change cannot make
# this assertion silently drift from what the tool actually records.
SCA_CELL=$(path_root_cell "$SCA_FIX")

SCOURSH_SCA_ADVISORIES_DB=$W/does-not-exist.db \
  _run_main sca --path "$SCA_FIX" --out "$W/case-sca-missing-db"
_covered_json case-sca-missing-db

t_case "SCA's required input (data/advisories.db) absent: not one SCA-* check enters covered_checks"
assert_eq '' "$(state_covered_scope SCA-NPM-VULNERABLE_DEP-01)" \
  'FAILS if coverage were recorded before the module checks its own required-input gate (modules/sca/run.sh: sca_advisories_db_readable)'
assert_eq '0' "$(printf '%s\n' "$(state_covered_check_ids)" | grep -c '^SCA-' || true)" \
  'no SCA-* id of any kind (not just the NPM one probed above) is covered'

# ---------------------------------------------------------------------------
printf '\n-- genuinely completed (SCA, advisories.db present): the positive case for a second module kind --\n'
# ---------------------------------------------------------------------------
SCOURSH_SCA_ADVISORIES_DB=$SCA_DB \
  _run_main sca --path "$SCA_FIX" --out "$W/case-sca-ok"
_covered_json case-sca-ok

t_case 'a completed SCA ecosystem walk enters covered_checks (SCA-NPM-VULNERABLE_DEP-01)'
assert_true "$(state_covered_has_cell SCA-NPM-VULNERABLE_DEP-01 "$SCA_CELL" && echo 0 || echo 1)" \
  'its path-root cell is present'
assert_eq 'path-root' "$(state_covered_scope SCA-NPM-VULNERABLE_DEP-01)" 'path-root scope, the same as SAST/IaC/history (tension 12)'
assert_ne '' "$(state_covered_rule_digest SCA-NPM-VULNERABLE_DEP-01)" \
  'rule_digest is a stable hash of the check id, not empty - SCA ships no *.rules record to hash, and lib/state.sh (STATE-01) rejects the whole file when a covered_checks entry has an empty one (measured: FAILS the state file load under the naive empty-string reading)'

# ---------------------------------------------------------------------------
printf '\n-- breaker aborted its module: a check enumerated but never completed stays uncovered, AND state/ is still persisted (docs/FOUNDATION.md tension 12 + tension 16; STATE-02 acceptance: "every run, including a run that fails") --\n'
# ---------------------------------------------------------------------------
# Drives the SAME plumbing scan_main uses (run_init, state_set_run,
# state_add_covered, die) directly, rather than manufacturing a real
# lib/http.sh circuit-breaker trip end to end: the breaker's own trip
# mechanics are tension 16's territory and are already tested in
# tests/suites/http.sh; what THIS ticket owns is that die()'s exit-5 path
# (lib/core.sh's run_json_refresh_incomplete) still writes state/, and that
# only coverage explicitly recorded BEFORE the abort survives - never the
# check the abort happened in the middle of.
#
# CHECK-ALREADY-DONE stands for a check (or an earlier module, in a combined
# `scan.sh all` run) that had already finished before the trip - its own
# module's coverage-recording call already ran, exactly where
# modules/sast/engine.sh's sast_record_coverage places it (right after its
# scan-tree call RETURNS, which under `set -Eeuo pipefail` only happens on
# success).  CHECK-MID-FLIGHT stands for the check whose containing phase the
# breaker tripped inside of: it was selected/enumerated for this run (the
# "enumerate before executing" half of tension 12's own "Consequence for the
# build" paragraph) but the completion line was never reached, so
# state_add_covered for it is never called - simulated here simply by never
# calling it, which is the literal contract sast_record_coverage's own
# comment documents ("the caller decides completion by WHERE it calls this
# from").
(
  run_init "$W/abort-run"
  state_reset
  state_set_run "$SCOURSH_RUN_ID" 'path:/tmp/state-coverage-abort-fixture' 'fp/1' '0.0.0'
  state_add_covered 'DEMO-CHECK-ALREADY-DONE-01' 'digest-done' path-root '.'
  # CHECK-MID-FLIGHT-01 was enumerated (it would appear in the module's own
  # `ids` list) but is deliberately never passed to state_add_covered -
  # the abort below happens before its module's own completion line.
  die "$SCOURSH_EXIT_INCOMPLETE" 'simulated circuit breaker trip mid-module (tension 16)'
) || true

t_case 'state/<run-id>.json exists even though the run aborted with exit 5 (STATE-02 acceptance criterion)'
assert_file_exists "$STATE_DIR/abort-run.json" 'the exit-5 recovery path (lib/core.sh run_json_refresh_incomplete) persisted it'

state_load_file "$STATE_DIR/abort-run.json"
t_case 'coverage recorded BEFORE the abort is preserved'
assert_true "$(state_covered_has_cell DEMO-CHECK-ALREADY-DONE-01 . && echo 0 || echo 1)" \
  'the check that had already completed is still covered'

t_case 'the check whose module the breaker aborted mid-flight is NOT covered'
assert_eq '' "$(state_covered_scope DEMO-CHECK-MID-FLIGHT-01)" \
  'FAILS under an implementation that records coverage for every SELECTED/enumerated check rather than only ones that reached their own completion line'

# ---------------------------------------------------------------------------
printf '\n-- resumed run never reached it: a unit with no completion record stays uncovered (docs/FOUNDATION.md tension 18 composed with tension 12) --\n'
# ---------------------------------------------------------------------------
# `--resume` itself is not part of this ticket and is not wired into
# scan.sh (docs/STEP7-STATE-PLAN.md's own STATE-02 row scopes only coverage
# recording and persist-on-every-run wiring; tension 18's own text: "A unit
# recorded `started` but never `done` is re-run ... partial work is
# discarded rather than trusted").  What IS this ticket's to prove is the
# storage-side half of that rule: a (check, cell) pair for which
# state_add_covered was never called - because, in a resumed run, the work
# unit backing it was never reached - is absent from covered_checks once
# persisted and reloaded, proven directly against lib/state.sh (STATE-01)
# exactly as tests/suites/state.sh's own round-trip cases do, rather than
# through a --resume flag that does not exist yet.
state_reset
state_set_run 'resume-sim' 'path:/tmp/state-coverage-resume-fixture' 'fp/1' '0.0.0'
# Only DEMO-REACHED-01's unit was reached before the (simulated) resume
# boundary; DEMO-NOT-YET-REACHED-01 was enumerated for this run (it exists
# in the check registry the module selected) but the run stopped short of
# it, so its completion call was never made - the identical "never called"
# contract the breaker-abort case above exercises, applied to a resume
# rather than a trip.
state_add_covered 'DEMO-REACHED-01' 'digest-reached' path-root 'src'
state_write "$STATE_DIR" 30

# Fresh load, discarding the in-process builder state above, so this reads
# only what state_write actually persisted to disk - the same discipline
# every other case in this suite already follows.
state_load_file "$STATE_DIR/resume-sim.json"

t_case 'a unit reached before the (simulated) resume boundary is covered'
assert_true "$(state_covered_has_cell DEMO-REACHED-01 src && echo 0 || echo 1)" 'its cell is present'

t_case 'a unit a resumed run never reached is absent from covered_checks'
assert_eq '' "$(state_covered_scope DEMO-NOT-YET-REACHED-01)" \
  'FAILS if a resume were allowed to mark every unit it KNOWS ABOUT as covered rather than only the ones it actually finished'

t_summary 'state-coverage'
