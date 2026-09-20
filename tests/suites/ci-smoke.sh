#!/usr/bin/env bash
# tests/suites/ci-smoke.sh - the CI-facing smoke matrix over scan.sh's exit
# codes and profiles, against a minimal fixture repo (this ticket).
#
# Distinct from tests/suites/exit-code-matrix.sh, which already pins ONE
# canonical scenario per documented exit code as a real subprocess.  This
# suite is deliberately narrower in what it PROVES and wider in what it
# ITERATES: it adds the --profile-scan dimension (quick/full/compliance)
# that matrix has no reason to touch, and it treats "scan.sh is missing"
# as its own first-class failure rather than something the harness might
# paper over.  Where a scenario here is the exact same one matrix already
# owns (scope.conf present but --target unknown -> exit 3), this suite
# reruns it rather than re-deriving it, and says so, so the two suites
# cannot silently drift onto different expected codes for the same case.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2030/SC2031/SC2329: same house-style reasons as
# tests/suites/exit-code-matrix.sh's header - _bin_run and every _row_*
# function are only ever called indirectly, and VAR=val fn ... prefix
# assignments are deliberately reaching a real bash subprocess spawned
# inside the function they are attached to (measured, not assumed, in that
# suite; not re-measured here).
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

# ---------------------------------------------------------------------------
# AC3: fail LOUDLY, not vacuously, if scan.sh is absent.
#
# This check runs BEFORE tests/lib/assert.sh is even sourced, so a missing
# scan.sh can never be swallowed by "0 assertions ran, 0 failed" - the
# failure mode a `[[ -f scan.sh ]] && run-smoke || echo skipping` guard
# would produce (exit 0).  It also runs whether this file is invoked through
# tests/run-tests.sh or directly as `bash tests/suites/ci-smoke.sh`.
# ---------------------------------------------------------------------------
if [[ ! -f $ROOT/scan.sh ]]; then
  printf 'FATAL: %s not found - the scoursh entry point is missing, the CI smoke matrix cannot run (this is not a skip)\n' \
    "$ROOT/scan.sh" >&2
  exit 2
fi
if [[ ! -r $ROOT/scan.sh ]]; then
  printf 'FATAL: %s exists but is not readable - cannot run the CI smoke matrix\n' "$ROOT/scan.sh" >&2
  exit 2
fi

# lib/core.sh only (not the whole of scan.sh, which this suite never sources):
# it is the source of SCOURSH_SCRATCH and the SCOURSH_EXIT_* constants this
# suite asserts against, and every scenario below drives scan.sh as a real
# subprocess via _bin_run rather than calling scan_main in-process.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/ci-smoke
rm -rf "$W"
mkdir -p "$W"

_bin_run() {
  local rc=0
  bash "$ROOT/scan.sh" "$@" >"$W/bin.out" 2>&1 || rc=$?
  return "$rc"
}

# A fixture install root carrying only config/, so the scope.conf scenarios
# below run against a KNOWN scope.conf rather than this repo's own (which is
# not guaranteed to declare fixture-target - it currently doesn't).
ROOT_GOOD_SCOPE=$W/root-good-scope
mkdir -p "$ROOT_GOOD_SCOPE/config"
cp "$ROOT/tests/fixtures/config/scope.conf" "$ROOT_GOOD_SCOPE/config/scope.conf"

# The malformed scope.conf is generated here rather than committed under
# tests/fixtures/, matching tests/suites/records.sh's own convention for
# section 12.6 negative examples: tests/lint-rules.sh's fixture_record_files
# sweep parses and validates EVERY *.conf/*.rules file under tests/fixtures/
# and fails the build if one does not parse - exactly what this fixture is
# for, so it cannot live there without turning a deliberate negative example
# into a real lint failure. The single space on its own line is E011
# (whitespace-only line, rules/RULE-FORMAT.md section 3.2) - a parse error,
# never a blank-line record separator.
ROOT_BAD_SCOPE=$W/root-bad-scope
mkdir -p "$ROOT_BAD_SCOPE/config"
# Built with printf, not a heredoc literal, because a heredoc's blank-looking
# line is easy to accidentally leave truly empty (0 bytes, a valid separator)
# rather than whitespace-only (the E011 condition this fixture needs) - a
# distinction an editor's trim-trailing-whitespace setting would silently
# erase if it were written as a literal line in this file.
printf 'id: fixture-target\nbase-url: https://app.fixture.invalid/\n \nnotes: E011 fixture - the single-space line above is the point of this file.\n' \
  >"$ROOT_BAD_SCOPE/config/scope.conf"

# =============================================================================
printf -- '\n-- profile x fixture matrix: sast against the minimal fixture repo --\n'
# =============================================================================
# The minimal fixture repo is tests/fixtures/{clean,vuln} - already the
# fixture tree tests/suites/e2e.sh and tests/e2e/fixture-scan.sh drive; reused
# here rather than duplicated so there is exactly one "clean" and one
# "vuln-shaped" tree to keep in sync with the record schema and rule shapes.
#
# docs/STEP7-STATE-PLAN.md STATE-08 has since landed `modules/sast/run.sh`,
# the real pattern engine, AND the `--fail-on-new` gate carve-out - this row
# used to document a build with no rule engine at all, where a scan of
# tests/fixtures/vuln (a real eval() sink and two hardcoded AWS secrets)
# exited 0 for the honest reason that nothing could find them yet. That is no
# longer true: this build DOES find them (`checks_run`/`findings.jsonl` are
# real). It still exits 0 here for a completely different, and still
# correct, reason - **the gate is opt-in and none of these invocations pass
# `--fail-on`** (`SCOURSH_FAIL_ON` defaults to `none`, `sast_evaluate_gate`
# returns `not-evaluated` unconditionally), so a real finding sitting
# unevaluated is not a false negative. `tests/suites/sast.sh`'s own
# "exit-code flip" section is what proves the gate actually fires when
# `--fail-on`/`--fail-on-new` ARE given; this row is deliberately not that
# test.
PROFILES=(quick full compliance)
FIXTURE_TREES=(clean vuln)

for _profile in "${PROFILES[@]}"; do
  for _tree in "${FIXTURE_TREES[@]}"; do
    t_case "sast --profile-scan $_profile against tests/fixtures/$_tree"
    assert_status 0 \
      "profile=$_profile tree=$_tree exits 0 as a real subprocess - fails under a reading where --profile-scan is rejected as an unknown flag, or where scanning the vuln-shaped tree trips a gate even though no --fail-on was given" \
      _bin_run sast --path "$ROOT/tests/fixtures/$_tree" --profile-scan "$_profile" --out "$W/run-$_profile-$_tree"
  done
done

t_case '--profile-scan is actually validated, not merely accepted as a no-op flag'
assert_status "$SCOURSH_EXIT_USAGE" \
  "an unrecognised profile name dies exit 2 (usage) as a real subprocess - fails under a reading where scan_validate_flag_value's profile-scan case (scan.sh) or checks_valid_profile (lib/checks.sh) silently accepts any string" \
  _bin_run sast --path "$ROOT/tests/fixtures/clean" --profile-scan bogus-profile --out "$W/run-bad-profile"

# =============================================================================
printf -- '\n-- misconfigured scope.conf: two distinct failure shapes, two distinct codes --\n'
# =============================================================================
# "Misconfigured" covers both an operator typo in --target (a well-formed
# file, wrong id: exit 3, config_scope_require's own gate) and a genuinely
# broken scope.conf (a file that fails to parse at all: exit 4,
# config_load_or_die - "a file that EXISTS but is malformed always dies...
# it is never treated as if it were absent", lib/config.sh). Both are
# exercised under a NON-default profile too, to prove --profile-scan cannot
# perturb the scope gate's own exit code (the gate runs before
# _scan_apply_profile_filter in scan_main - scan.sh section 8a/8, dast case).
t_case 'dast --target naming an id absent from a well-formed scope.conf'
SCOURSH_INSTALL_ROOT=$ROOT_GOOD_SCOPE assert_status "$SCOURSH_EXIT_SCOPE" \
  "exits 3, never 4 - the same scenario tests/suites/exit-code-matrix.sh's _row_scope pins; reasserted here under --profile-scan quick to prove the profile flag does not change it" \
  _bin_run dast --target no-such-target --profile-scan quick --out "$W/scope-unknown-target"

t_case 'dast --target against a scope.conf that exists but fails to parse (E011, whitespace-only line)'
SCOURSH_INSTALL_ROOT=$ROOT_BAD_SCOPE assert_status "$SCOURSH_EXIT_INPUT" \
  "exits 4, never 3 - a malformed-but-present scope.conf is a DIFFERENT failure from 'valid file, unknown target id'; fails under a reading that conflates 'misconfigured' with only the exit-3 case" \
  _bin_run dast --target fixture-target --profile-scan compliance --out "$W/scope-malformed"

t_summary 'ci-smoke' || FAILED=1
exit "${FAILED:-0}"
