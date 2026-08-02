#!/usr/bin/env bash
# tests/suites/scan.sh - scan.sh: the §5 CLI grammar, the tension-14 exit-code
# precedence contract, and "the config loader runs before dispatch".
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is the intended reporting shape (inherited from
#   tests/lib/assert.sh's own style).
# SC2016: assertion prose and scan.sh's own usage text quote shell syntax
#   literally.
# SC2030/SC2031: a prefix `VAR=val assert_status ...` or `VAR=val _run ...`
#   is DELIBERATELY subshell-scoped (assert_status/`_run` both run their
#   command in `( ... )`), so one probe's override can never leak into the
#   next.
# SC2329: `_run_main` is only ever invoked indirectly, as an argument to
#   assert_status, which shellcheck's static call graph does not follow.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=scan.sh
source "$ROOT/scan.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/scan
rm -rf "$W"
mkdir -p "$W"

# A fixture SCOURSH_INSTALL_ROOT with a real config/scope.conf (reused from
# tests/fixtures/config/scope.conf, the same fixture tests/suites/config.sh
# and tests/e2e/fixture-scan.sh already use), and one with no scope.conf at
# all.
ROOT_WITH_SCOPE=$W/root-with-scope
mkdir -p "$ROOT_WITH_SCOPE/config"
cp "$ROOT/tests/fixtures/config/scope.conf" "$ROOT_WITH_SCOPE/config/scope.conf"

ROOT_NO_SCOPE=$W/root-no-scope
mkdir -p "$ROOT_NO_SCOPE/config"

# A fixture SCOURSH_INSTALL_ROOT whose config/scanner.conf fails schema
# validation, to prove the config loader really runs (and dies) before
# scan_dispatch is ever reached.
ROOT_BAD_SCANNER=$W/root-bad-scanner
mkdir -p "$ROOT_BAD_SCANNER/config"
printf 'id: scanner\njobs: not-a-number\n' >"$ROOT_BAD_SCANNER/config/scanner.conf"

ROOT_OK_SCANNER=$W/root-ok-scanner
mkdir -p "$ROOT_OK_SCANNER/config"
printf 'id: scanner\njobs: 2\n' >"$ROOT_OK_SCANNER/config/scanner.conf"

# scan_main always `exit`s (0 on success, one of 2/3/4/5/1 otherwise), so it
# is only ever called through assert_status, which contains that exit inside
# its own subshell.
_run_main() { scan_main "$@"; }

# Portability (docs/FOUNDATION.md tension 24) is a structural property, not
# something a text scan of the source can pin: `getopts` (the bash builtin)
# has no long-option support, and GNU getopt's long-option parsing is not
# what BSD/macOS getopt implements, so scan.sh's parser (below) is a
# hand-rolled `case`/`shift` loop over bash builtins and string operators
# only - the same reason every other `--flag`/`--flag=value` test in this
# suite exercises the parser directly rather than through either external
# tool.  What IS asserted here is the parser's actual behaviour for both
# forms, immediately below.

# =============================================================================
printf -- '\n-- successful parses: --flag value, --flag=value, and booleans --\n'
# =============================================================================
t_case '--flag value form'
scan_parse_args sast --path /tmp/x --lang py,js
assert_eq sast "$SCAN_COMMAND" 'command captured'
assert_eq /tmp/x "${SCAN_FLAGS[path]}" '--path value captured'
assert_eq py,js "${SCAN_FLAGS[lang]}" '--lang value captured'

t_case '--flag=value form parses identically to --flag value'
scan_parse_args sast --path=/tmp/x --lang=py,js
assert_eq /tmp/x "${SCAN_FLAGS[path]}" \
  '--path=/tmp/x captured the same value as --path /tmp/x - fails under "the two forms are parsed by different code paths and can drift"'
assert_eq py,js "${SCAN_FLAGS[lang]}" '--lang=py,js captured the same as --lang py,js'

t_case 'boolean flags take no value and do not consume the next argument'
scan_parse_args sast --history --path /tmp/y
assert_eq true "${SCAN_FLAGS[history]}" '--history is recorded as boolean true'
assert_eq /tmp/y "${SCAN_FLAGS[path]}" \
  '--path after --history still gets /tmp/y - fails under "a boolean flag swallows the following token as its value"'

t_case 'global flags are valid on any command'
scan_parse_args iac --path . --profile-scan quick --jobs 8 --format json,html
assert_eq quick "${SCAN_FLAGS[profile-scan]}" 'global --profile-scan parsed on iac'
assert_eq 8 "${SCAN_FLAGS[jobs]}" 'global --jobs parsed on iac'
assert_eq json,html "${SCAN_FLAGS[format]}" 'global --format parsed on iac'

t_case '"--" ends flag parsing (and nothing may follow it, since no command takes positionals)'
scan_parse_args sast --path . --
assert_eq . "${SCAN_FLAGS[path]}" 'flags before -- are still parsed'

# =============================================================================
printf '\n-- exit 2: usage errors - the invocation was invalid, nothing ran --\n'
# =============================================================================
t_case 'no command at all'
assert_status 2 'scan.sh with zero arguments dies exit 2' scan_parse_args

t_case 'unknown command'
assert_status 2 "'scan.sh bogus' dies exit 2, not exit 4 (missing input) - the command name itself is the invocation, not an input)" \
  scan_parse_args bogus

t_case 'unknown flag for the given command'
assert_status 2 "'--regions' (a cloud-only flag) is rejected on sast" \
  scan_parse_args sast --regions us-east-1

t_case 'a value-flag with no value at end of argv'
assert_status 2 "'--path' with nothing after it dies exit 2" \
  scan_parse_args sast --path

t_case 'a value-flag whose next token looks like another flag'
assert_status 2 "'--path --lang py' treats --lang as a missing value for --path, not as --path's value" \
  scan_parse_args sast --path --lang py

t_case 'an empty inline value'
assert_status 2 "'--path=' (empty via the inline form) dies exit 2 - fails under 'only the space form checks emptiness'" \
  scan_parse_args sast --path=

t_case 'an invalid enum value'
assert_status 2 "'--profile-scan bogus' is not quick|full|compliance" \
  scan_parse_args sast --profile-scan bogus --path .

t_case 'a non-numeric --jobs'
assert_status 2 "'--jobs abc' is not a positive integer" \
  scan_parse_args sast --jobs abc --path .

t_case '--fail-on-new requires --fail-on in the SAME invocation'
assert_status 2 '--fail-on-new with no --fail-on dies exit 2 (docs/FOUNDATION.md tension 14, the missing-gate-flags paragraph)' \
  scan_parse_args sast --fail-on-new --path .
scan_parse_args sast --fail-on-new --fail-on high --path .
assert_eq true "${SCAN_FLAGS[fail-on-new]}" '--fail-on-new with --fail-on present parses cleanly'

t_case "'dast' requires --target"
assert_status 2 "'scan.sh dast' with no --target dies exit 2" \
  scan_parse_args dast

t_case "'diff' requires --against, 'report' requires --from"
assert_status 2 "'scan.sh diff' with no --against dies exit 2" scan_parse_args diff
assert_status 2 "'scan.sh report' with no --from dies exit 2" scan_parse_args report

t_case 'an unexpected positional argument'
assert_status 2 'no documented command takes a bare positional (docs/DESIGN.md §5 is entirely flag-based)' \
  scan_parse_args sast extra-arg --path .

# =============================================================================
printf '\n-- exit-code precedence (docs/FOUNDATION.md tension 14) --\n'
# =============================================================================
t_case 'each condition alone maps to its own code'
assert_eq 2 "$(scan_exit_code 1 0 0 0 0)" 'usage alone -> 2'
assert_eq 3 "$(scan_exit_code 0 1 0 0 0)" 'scope alone -> 3'
assert_eq 4 "$(scan_exit_code 0 0 1 0 0)" 'input alone -> 4'
assert_eq 5 "$(scan_exit_code 0 0 0 1 0)" 'incomplete alone -> 5'
assert_eq 1 "$(scan_exit_code 0 0 0 0 1)" 'gate alone -> 1'
assert_eq 0 "$(scan_exit_code 0 0 0 0 0)" 'nothing set -> 0 (clean)'

t_case 'the worked example: breaker tripped AND gated findings exits 5, never 1'
assert_eq 5 "$(scan_exit_code 0 0 0 1 1)" \
  'incomplete+gate both true -> 5 - fails under "worst finding wins" (which would give 1): docs/FOUNDATION.md tension 14 says a run that cannot assert "I finished what I was asked" may not also assert "and it passed/failed the gate"'

t_case 'usage outranks every other condition, even all of them at once'
assert_eq 2 "$(scan_exit_code 1 1 1 1 1)" \
  'every condition true -> 2, not 5 (highest-numbered) and not 1 (worst finding) - fails under either rejected reading from tension 14 options 1 and 2'

t_case 'scope outranks input, incomplete, and gate'
assert_eq 3 "$(scan_exit_code 0 1 1 1 1)" 'scope+input+incomplete+gate -> 3, never masked by a later condition'

t_case 'input outranks incomplete and gate'
assert_eq 4 "$(scan_exit_code 0 0 1 1 1)" 'input+incomplete+gate -> 4'

# =============================================================================
printf '\n-- required-input gates: dast (docs/DESIGN.md §7, the non-bypassable gate) --\n'
# =============================================================================
t_case 'a --target with no entry in a PRESENT scope.conf is exit 3, never exit 4'
SCOURSH_INSTALL_ROOT=$ROOT_WITH_SCOPE assert_status 3 \
  "dast --target no-such-target dies exit 3 - fails under 'any scope.conf problem is exit 4'" \
  _run_main dast --target no-such-target --out "$W/run-scope-violation"

t_case 'a --target that DOES resolve dispatches cleanly (exit 0: the module is not built yet, which is a declared no-op, not a failure)'
SCOURSH_INSTALL_ROOT=$ROOT_WITH_SCOPE assert_status 0 \
  'dast --target fixture-target exits 0 once the scope gate passes' \
  _run_main dast --target fixture-target --out "$W/run-scope-ok"

t_case 'a WHOLLY MISSING scope.conf is exit 4, never exit 3'
SCOURSH_INSTALL_ROOT=$ROOT_NO_SCOPE assert_status 4 \
  "dast --target anything with no config/scope.conf file at all dies exit 4 - fails under 'no file also means no matching entry, so it is exit 3 too' (docs/FOUNDATION.md tension 14: missing scope.conf is exit 4 only for dast)" \
  _run_main dast --target anything --out "$W/run-no-scope"

# =============================================================================
printf '\n-- required-input gates: --path (sast/sca/iac), and the prior-run dirs (diff/report) --\n'
# =============================================================================
t_case 'a --path that does not exist is exit 4'
SCOURSH_INSTALL_ROOT=$ROOT_OK_SCANNER assert_status 4 "--path pointing nowhere dies exit 4" \
  _run_main sast --path "$W/does-not-exist-at-all" --out "$W/run-bad-path"

t_case '--path defaulting to "." and existing dispatches cleanly'
SCOURSH_INSTALL_ROOT=$ROOT_OK_SCANNER assert_status 0 "sast with no --path defaults to '.' and succeeds" \
  _run_main sast --out "$W/run-default-path"

t_case 'diff --against a directory with no run.json/findings.jsonl is exit 4'
mkdir -p "$W/not-a-run-dir"
assert_status 4 "--against a directory that is not a prior run dies exit 4" \
  _run_main diff --against "$W/not-a-run-dir" --out "$W/run-diff-bad"

t_case 'diff --against a real prior run dir dispatches cleanly'
mkdir -p "$W/prior-run"
printf '{}' >"$W/prior-run/run.json"
assert_status 0 "--against a directory that has a run.json succeeds" \
  _run_main diff --against "$W/prior-run" --out "$W/run-diff-ok"

t_case "report --from mirrors diff --against"
assert_status 4 "report --from a non-run directory dies exit 4" \
  _run_main report --from "$W/not-a-run-dir" --out "$W/run-report-bad"
assert_status 0 "report --from a real prior run dir succeeds" \
  _run_main report --from "$W/prior-run" --out "$W/run-report-ok"

# =============================================================================
printf '\n-- the config loader runs before scan_dispatch (this ticket''s 3rd acceptance criterion) --\n'
# =============================================================================
t_case 'a malformed config/scanner.conf dies exit 4 BEFORE any module is dispatched'
OUT=$W/run-bad-scanner
SCOURSH_INSTALL_ROOT=$ROOT_BAD_SCANNER assert_status 4 \
  "config/scanner.conf with jobs: not-a-number dies exit 4" \
  _run_main sast --path . --out "$OUT"
# The proof that dispatch never ran: scan_dispatch's own log line ("has no
# run.sh yet") would appear in run.json's notes/coverage_reduction if it had
# executed.  A run directory may still exist (run_init happens first, so die()
# can record incomplete_reason into it), but coverage_reduction must be empty.
if [[ -f $OUT/meta/coverage_reduction ]]; then
  _t_no 'scan_dispatch never records coverage_reduction for a run that died in config loading' \
    "found: $(cat "$OUT/meta/coverage_reduction")"
else
  _t_ok 'scan_dispatch never records coverage_reduction for a run that died in config loading'
fi

t_case 'a valid config/scanner.conf lets the same invocation reach dispatch (exit 0)'
SCOURSH_INSTALL_ROOT=$ROOT_OK_SCANNER assert_status 0 \
  'the identical command with a schema-valid scanner.conf reaches the (not-yet-built) module and exits 0' \
  _run_main sast --path . --out "$W/run-good-scanner"
assert_file_exists "$W/run-good-scanner/meta/coverage_reduction" \
  'this time scan_dispatch DID run and recorded the declared skip'

# =============================================================================
printf '\n-- real end-to-end: scan.sh executed as an actual script, not sourced --\n'
# =============================================================================
_bin_run() {
  local rc=0
  bash "$ROOT/scan.sh" "$@" >"$W/bin.out" 2>&1 || rc=$?
  return "$rc"
}

t_case '--help exits 0 and prints the documented grammar'
assert_status 0 './scan.sh --help exits 0' _bin_run --help
assert_contains "$(cat "$W/bin.out")" 'scan.sh <command> [options]' 'usage text is printed'

t_case 'an unknown command exits 2 when run as a real script, matching the sourced-function behaviour'
assert_status 2 './scan.sh bogus exits 2' _bin_run bogus

t_case 'a full sast invocation exits 0 and writes a real run.json to disk'
rm -rf "$W/real-run"
assert_status 0 './scan.sh sast --path . --out DIR exits 0 end to end' \
  _bin_run sast --path "$ROOT" --out "$W/real-run"
assert_file_exists "$W/real-run/run.json" 'run.json was written by the real script, not just the sourced function'
assert_contains "$(cat "$W/real-run/run.json")" '"gate": "not-evaluated"' \
  'run.json honestly reports that no gate has been evaluated yet (no findings pipeline exists yet)'

t_summary 'scan' || FAILED=1
exit "${FAILED:-0}"
