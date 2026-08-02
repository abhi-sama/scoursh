#!/usr/bin/env bash
# tests/suites/exit-code-matrix.sh - a table-driven matrix over scan.sh's six
# documented exit codes (docs/DESIGN.md §5; the precedence rule and the
# declared-vs-unplanned split in docs/FOUNDATION.md tension 14).
#
# tests/suites/scan.sh (built alongside scan.sh itself) already exercises
# usage/scope/input/precedence extensively, mostly by sourcing scan.sh and
# calling scan_main directly.  This suite is deliberately narrower and
# complementary: ONE canonical scenario per documented code, every one of
# them run as a REAL SUBPROCESS (`bash scan.sh ...`), because the exit code a
# CI pipeline actually reads is `$?` of the real process, not the return
# value of a sourced bash function - a regression in the top-level `exit`
# call at the bottom of scan_main, or in the re-exec search at the top of the
# file, would not be caught by a sourced-function test at all.
#
# EXIT_CODE_TABLE below is the literal table AC1 asks for: it is iterated,
# not just documented, so adding/removing/reordering a row is a code change
# a reviewer sees, and the "exactly six rows, exactly these codes" assertion
# below fails immediately if a documented code is ever dropped from the
# matrix by accident.
#
# Per AGENTS.md's testing rule, every assertion below names the specific
# wrong reading it fails under - this is this project's chosen mechanism for
# AC2 ("confirmed to fail when the exit code is broken"): a test whose
# message does not name a losing reading is, by that rule, worth less than
# no test.  Alongside that, this suite was run against several deliberate
# mutations of scan.sh/lib/core.sh while writing it (precedence order
# swapped, the SIGTERM handler's exit code changed, the --path-missing die
# call's code changed) and confirmed red in each case before being reverted;
# see the QA comment on this ticket for the transcript.
#
# Exit 1 (gate) has NO live trigger anywhere in the current build: scan_main
# hard-codes `local incomplete=0 gate=0` and never reassigns either (no
# findings pipeline, no gate evaluation exists yet - docs/DESIGN.md §13 build
# order, step 2 of 10), and `SCOURSH_EXIT_GATE` is not referenced by any
# `die`/`exit` call anywhere outside scan_exit_code's own branch and this
# test file (checked with `grep -rn SCOURSH_EXIT_GATE`).  Its row therefore
# pins the *precedence function* (scan_exit_code, already unit-testable on
# its own per scan.sh's own §5 comment) rather than a subprocess scenario,
# and says so rather than faking one.  A follow-up ticket tracks giving it a
# live end-to-end trigger once the gate pipeline lands.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is inherited from tests/lib/assert.sh's own
#   reporting shape.
# SC2016: assertion prose quotes shell syntax literally.
# SC2030/SC2031: `VAR=val fn ...` prefix assignments are DELIBERATELY
#   subshell/function-local in the way bash implements them for a shell
#   FUNCTION invocation (measured directly below, not assumed) - they reach a
#   real `bash` subprocess spawned inside that function without leaking back
#   into this script afterward.
# SC2329: `_bin_run` and every `_row_*` function are only ever invoked
#   indirectly - `_bin_run` via `assert_status`'s "$@" forwarding, and each
#   `_row_*` via EXIT_CODE_TABLE's driving loop (`"$_fn" "$_code"`) - neither
#   of which shellcheck's static call graph follows, same as `_run_main` in
#   tests/suites/scan.sh.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=scan.sh
source "$ROOT/scan.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/exit-code-matrix
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf '\n-- the propagation this suite depends on: measured, not assumed --\n'
# =============================================================================
# `VAR=val fn args...` where fn is a shell function that itself spawns a real
# `bash` child: does the child see VAR?  Every scope/incomplete scenario below
# threads SCOURSH_INSTALL_ROOT through exactly this shape (a prefix
# assignment on a call to a wrapper function that calls _bin_run, which
# spawns `bash scan.sh` for real), so if this were false every one of those
# scenarios would silently test the wrong install root.
t_case 'a prefix assignment on a shell-function call reaches a real subprocess spawned inside it'
_ecm_probe_inner() { bash -c 'printf %s "$ECM_PROBE"'; }
_ecm_probe_outer() { _ecm_probe_inner; }
got=$(ECM_PROBE=reaches-through _ecm_probe_outer)
assert_eq reaches-through "$got" \
  'fails under "temporary assignments before a function call are function-local shell variables only, not exported to children it spawns"'
assert_eq '' "${ECM_PROBE:-}" 'and it does not leak into this script afterward'

# =============================================================================
printf '\n-- fixtures --\n'
# =============================================================================
ROOT_WITH_SCOPE=$W/root-with-scope
mkdir -p "$ROOT_WITH_SCOPE/config"
cp "$ROOT/tests/fixtures/config/scope.conf" "$ROOT_WITH_SCOPE/config/scope.conf"

# A fixture install root whose modules/sast/run.sh (the exact file
# scan_dispatch sources for real - docs/DESIGN.md §13 build order: "nothing
# under modules/ has landed", so today's scan_dispatch always takes the
# "no run.sh yet" branch; this fixture supplies one on purpose) writes a
# ready marker and then blocks, so a SIGTERM can be delivered to a
# genuinely in-flight `scan.sh` process deterministically rather than raced.
# The synchronise-on-a-ready-file-then-signal shape mirrors the one already
# proven in tests/suites/e2e.sh's F12/SIGTERM test; this is the first time it
# is driven through the real scan.sh binary rather than a hand-rolled script
# sourcing lib/report.sh directly.
ROOT_SLOW_MODULE=$W/root-slow-module
mkdir -p "$ROOT_SLOW_MODULE/modules/sast"
SLOW_READY=$W/slow-module-ready
cat >"$ROOT_SLOW_MODULE/modules/sast/run.sh" <<EOF
printf 'ready\n' >"$SLOW_READY"
while :; do sleep 1; done
EOF

_bin_run() {
  local rc=0
  bash "$ROOT/scan.sh" "$@" >"$W/bin.out" 2>&1 || rc=$?
  return "$rc"
}

# =============================================================================
printf -- '\n-- THE TABLE (AC1): every documented code, one canonical scenario each --\n'
# =============================================================================
# code|name|scenario function|one-line description
EXIT_CODE_TABLE=(
  "0|clean|_row_clean|a sast dispatch with no gate evaluated and nothing incomplete"
  "1|gate|_row_gate|*no live trigger in this build*; pinned at scan_exit_code, see header comment"
  "2|usage|_row_usage|an unrecognised subcommand - the invocation itself is invalid"
  "3|scope|_row_scope|dast --target naming an id absent from a PRESENT scope.conf"
  "4|input|_row_input|sast --path pointing at a directory that does not exist"
  "5|incomplete|_row_incomplete|SIGTERM delivered to a genuinely in-flight scan.sh process"
)

t_case 'the table has exactly the six codes docs/DESIGN.md §5 documents, in that order'
codes=''
for _row in "${EXIT_CODE_TABLE[@]}"; do
  codes+="${_row%%|*} "
done
assert_eq '0 1 2 3 4 5 ' "$codes" \
  'fails if a documented code is silently dropped, duplicated, or reordered in the matrix'

_row_clean() {
  local code=$1
  assert_status "$code" \
    'sast --path <repo> --out DIR, run as a real subprocess, dispatches cleanly - fails under any reading where a healthy run does not exit 0' \
    _bin_run sast --path "$ROOT" --out "$W/row-clean"
}

_row_gate() {
  local code=$1
  # No subcommand/flag combination can make SCOURSH_GATE (gate=1) true today
  # (see header comment); the scenario that "triggers exactly it" is a direct
  # call to the precedence function scan.sh documents as unit-testable on its
  # own for this reason.
  assert_eq "$code" "$(scan_exit_code 0 0 0 0 1)" \
    'gate alone -> 1 - fails under "worst finding wins" or "highest code wins", both rejected in docs/FOUNDATION.md tension 14'
  assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$(scan_exit_code 0 0 0 1 1)" \
    'gate finding this run also cannot mask incomplete: incomplete+gate -> 5, never 1 - the tension-14 worked example, restated here because THIS row is the one it disambiguates from clean gate-only'
}

_row_usage() {
  local code=$1
  assert_status "$code" \
    "'scan.sh bogus' as a real subprocess exits 2 - fails under a reading where the top-level exit is never reached and the process falls through to some other status" \
    _bin_run bogus
}

_row_scope() {
  local code=$1
  SCOURSH_INSTALL_ROOT=$ROOT_WITH_SCOPE assert_status "$code" \
    "dast --target no-such-target as a real subprocess exits 3, never 4 - fails under 'any scope.conf problem is exit 4', which docs/FOUNDATION.md tension 14 explicitly rejects" \
    _bin_run dast --target no-such-target --out "$W/row-scope"
}

_row_input() {
  local code=$1
  assert_status "$code" \
    "sast --path pointing at a directory that does not exist, as a real subprocess, exits 4 - fails under a reading where a bad --path is only caught when a module actually reads it" \
    _bin_run sast --path "$W/does-not-exist-at-all" --out "$W/row-input"
}

_row_incomplete() {
  local code=$1
  rm -f "$SLOW_READY"
  rm -rf "$W/row-incomplete"
  SCOURSH_INSTALL_ROOT=$ROOT_SLOW_MODULE \
    bash "$ROOT/scan.sh" sast --path "$ROOT" --out "$W/row-incomplete" >"$W/sigterm.out" 2>&1 &
  local child=$!
  local waited=0
  while [[ ! -f $SLOW_READY ]] && (( waited < 100 )); do
    sleep 0.1
    waited=$(( waited + 1 ))
  done
  assert_file_exists "$SLOW_READY" \
    'the fixture module actually started and reached its ready marker before the signal is sent (a race here would make the SIGTERM assertion below meaningless, not just flaky)'
  kill -TERM "$child" 2>/dev/null || true
  local rc=0
  wait "$child" 2>/dev/null || rc=$?
  assert_eq "$code" "$rc" \
    'SIGTERM to a genuinely in-flight real scan.sh process exits 5 via core_on_signal - fails under a reading where scan.sh has no live trigger for exit 5 at all, and fails under "the default SIGTERM disposition (143) is close enough"'
  assert_contains "$(cat "$W/row-incomplete/meta/incomplete_reason" 2>/dev/null || printf '')" 'SIGTERM' \
    'and run.json/meta records why, which is the exit-5 predicate per docs/FOUNDATION.md tension 14 ("incomplete_reason non-empty is exactly the exit-5 predicate")'
}

for _row in "${EXIT_CODE_TABLE[@]}"; do
  IFS='|' read -r _code _name _fn _desc <<<"$_row"
  t_case "exit $_code ($_name): $_desc"
  "$_fn" "$_code"
done
unset -v _row _code _name _fn _desc IFS

t_summary 'exit-code-matrix' || FAILED=1
exit "${FAILED:-0}"
