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
# SC2317: the same indirect-invocation pattern as SC2329 above, applied to
#   `_bin_run` (invoked only as an argument to assert_status, e.g. `assert_status
#   0 '...' _bin_run --help`) - shellcheck's static call graph does not follow
#   it either, and newer shellcheck (0.9.0+, e.g. Ubuntu 24.04's apt package)
#   reports every statement inside as "unreachable" where older releases
#   (0.8.0, and Homebrew's 0.11.0) do not.  Same root cause as SC2329, a
#   different rule id depending on version, per AGENTS.md's "ShellCheck
#   versions disagree" note - silenced explicitly rather than left to
#   whichever version a CI image happens to ship.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329,SC2317

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

t_case "scan_validate_flag_value's profile-scan/intensity branches are driven directly off lib/checks.sh's CHECKS_PROFILES/CHECKS_INTENSITIES (checks_valid_profile/checks_valid_intensity), not a separately hardcoded regex here - walks both arrays so a name added to one array alone is caught here rather than only at the lib/checks.sh layer"
for _p in "${CHECKS_PROFILES[@]}"; do
  assert_status 0 "scan_validate_flag_value accepts profile-scan='$_p' (a CHECKS_PROFILES member)" \
    scan_validate_flag_value profile-scan "$_p"
done
assert_status 1 "scan_validate_flag_value rejects profile-scan='bogus' (not a CHECKS_PROFILES member)" \
  scan_validate_flag_value profile-scan bogus
for _i in "${CHECKS_INTENSITIES[@]}"; do
  assert_status 0 "scan_validate_flag_value accepts intensity='$_i' (a CHECKS_INTENSITIES member)" \
    scan_validate_flag_value intensity "$_i"
done
assert_status 1 "scan_validate_flag_value rejects intensity='bogus' (not a CHECKS_INTENSITIES member)" \
  scan_validate_flag_value intensity bogus
unset _p _i

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
printf '\n-- the own-your-target affirmation (docs/STEP5-DAST-PLAN.md DAST-32) --\n'
# =============================================================================
# Every case here runs against scan_parse_args alone, because the affirmation
# rules are PURE: they read SCAN_FLAGS and die, and they touch no run
# directory.  That is what lets them run before anything is created, which is
# the whole point - a usage error that fires after a scan has started is a
# usage error that has already sent traffic.

t_case '--i-own-target must name the very host this run scans'
assert_status 2 \
  "--i-own-target naming a DIFFERENT host than --target dies exit 2 - fails under 'the affirmation is a switch, so its value is decoration', which is exactly how a stale CI file or a copied shell alias carries an affirmation to a target that changed hands" \
  scan_parse_args dast --target host-a --i-own-target host-b
assert_status 2 \
  '--i-own-target with no --target at all is the same mistake and dies exit 2, rather than being silently accepted as an affirmation of nothing' \
  scan_parse_args all --i-own-target host-a
scan_parse_args dast --target host-a --i-own-target host-a
assert_eq host-a "${SCAN_FLAGS[i-own-target]}" \
  'a matching affirmation parses cleanly'

t_case 'the affirmation is a key, not a switch: alone it changes nothing'
scan_parse_args dast --target host-a --i-own-target host-a
assert_eq '' "${SCAN_FLAGS[intensity]:-}" \
  '--i-own-target on its own does not select a higher intensity - fails under a single flag that raises intensity, removes the rate limit and enables side-effecting checks together, which hands the maximum blast radius to one token'
assert_eq '' "${SCAN_FLAGS[allow-intrusive]:-}" \
  'and does not turn on side-effecting checks either'

t_case 'the --intensity ceiling is passive without an affirmation'
assert_status 2 \
  "'dast --intensity safe' with no affirmation dies exit 2 - fails if the ceiling is only the check-registry filter's default, which a single flag then silently raises against a host this tool cannot vouch for ('safe' puts hundreds of 404s in someone's logs)" \
  scan_parse_args dast --target host-a --intensity safe
assert_status 2 \
  "'dast --intensity active' with no affirmation dies exit 2 as well - active sends injection payloads, which no permission to browse covers" \
  scan_parse_args dast --target host-a --intensity active
scan_parse_args dast --target host-a --intensity passive
assert_eq passive "${SCAN_FLAGS[intensity]}" \
  'an explicit --intensity passive needs no affirmation: it is the ceiling, not above it - fails under "any --intensity flag requires the affirmation", which would make the conservative choice cost the same as the loud one'
scan_parse_args dast --target host-a
assert_eq '' "${SCAN_FLAGS[intensity]:-}" \
  'and an operator who passes no --intensity at all never meets this rule, since passive is already the default'
scan_parse_args dast --target host-a --intensity active --i-own-target host-a
assert_eq active "${SCAN_FLAGS[intensity]}" \
  'a matched affirmation is what makes active reachable'

t_case '--allow-intrusive is brought under the affirmation'
assert_status 2 \
  "'dast --allow-intrusive' with no affirmation dies exit 2 - fails under 'it already has its own opt-in, so that is enough': its blast radius escapes the target, since §7.4's checks create users and send messages, and owning a host does not confer permission to do that to its users" \
  scan_parse_args dast --target host-a --allow-intrusive
assert_status 2 \
  "and the same holds for 'all' once a --target makes DAST reachable" \
  scan_parse_args all --target host-a --allow-intrusive --path .
scan_parse_args all --allow-intrusive --path .
assert_eq true "${SCAN_FLAGS[allow-intrusive]}" \
  "'all' with NO --target runs no DAST at all, so --allow-intrusive there is not refused - fails under a blanket rule, which would refuse an invocation that cannot reach a live endpoint"
scan_parse_args sast --allow-intrusive --path .
assert_eq true "${SCAN_FLAGS[allow-intrusive]}" \
  'and it stays a global flag on the non-network commands, so docs/DESIGN.md §5'"'"'s grammar block is not diverged from'
scan_parse_args dast --target host-a --allow-intrusive --i-own-target host-a
assert_eq true "${SCAN_FLAGS[allow-intrusive]}" \
  'a matched affirmation plus the separate opt-in is what enables it - two flags, never one'

t_case '--i-own-target is not offered where it would only become boilerplate'
assert_status 2 \
  '--i-own-target is not a valid flag on sast - fails if it is declared global, which invites it into CI files for runs that never touch a host' \
  scan_parse_args sast --i-own-target host-a --path .

t_case 'the two User-Agent inputs refuse a header-injecting value'
assert_status 2 \
  "a --contact carrying a space (the first byte of a second header token) is refused at parse time - fails if the flag is validated only by the generic non-empty rule, which lets an operator value be concatenated straight into a request header" \
  scan_parse_args dast --target host-a --contact 'me and you'
scan_parse_args dast --target host-a --contact 'security@operator.example'
assert_eq 'security@operator.example' "${SCAN_FLAGS[contact]}" \
  'an ordinary contact parses cleanly'
scan_parse_args dast --target host-a --user-agent-suffix 'operator-ci/2.1'
assert_eq 'operator-ci/2.1' "${SCAN_FLAGS[user-agent-suffix]}" \
  'and so does a product token for the suffix'

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
printf -- '\n-- lib/checks.sh wiring: --profile-scan actually changes which checks run --\n'
# =============================================================================
# A fixture install root carrying a REAL on-disk check registry (unlike every
# other fixture root above, which has none - this is the one that proves
# checks_registry_load's glob really does pick up a file once it exists,
# rather than only being exercised directly against tests/suites/checks.sh's
# own fixture).
mkdir -p "$W/root-with-checks/config" "$W/root-with-checks/modules/sast/rules"
printf 'id: scanner\njobs: 2\n' >"$W/root-with-checks/config/scanner.conf"
cp "$ROOT/tests/fixtures/checks-registry/modules/sast/rules/demo.rules" \
  "$W/root-with-checks/modules/sast/rules/demo.rules"
# Canonicalised (`cd && pwd -P`), NOT just "$W/root-with-checks": lib/records.sh
# resolves every loaded file's path via realpath and strips $SCOURSH_INSTALL_ROOT
# as a literal prefix, so the two must agree on the canonical form or the
# strip silently fails and every fixture check hits E070.  This matters here
# specifically because $SCOURSH_SCRATCH (which $W descends from) is built
# under $TMPDIR, and macOS's $TMPDIR resolves through a `/var` -> `/private/var`
# symlink - measured, not assumed (docs/FOUNDATION.md's own "measured, not
# assumed" discipline). Every fixture root ABOVE this point in the file never
# hit this because they only ever load files through explicit-schema calls
# (config_load_or_die), which never consults the path table at all.
ROOT_WITH_CHECKS=$(cd -- "$W/root-with-checks" && pwd -P)

t_case '--profile-scan quick against a real on-disk registry records only the quick-tagged check as run'
SCOURSH_INSTALL_ROOT=$ROOT_WITH_CHECKS assert_status 0 \
  'sast --profile-scan quick succeeds' \
  _run_main sast --path . --profile-scan quick --out "$W/run-quick"
assert_contains "$(cat "$W/run-quick/meta/checks_selected")" 'SAST-GEN-DEMO_QUICK-01' \
  'the quick+compliance-tagged fixture rule is recorded as run'
assert_not_contains "$(cat "$W/run-quick/meta/checks_selected")" 'SAST-GEN-DEMO_FULL-01' \
  'the full-only fixture rule is NOT recorded as run under --profile-scan quick'
assert_contains "$(cat "$W/run-quick/meta/skipped_checks")" \
  'check=SAST-GEN-DEMO_FULL-01 skipped_by=profile-scan=quick' \
  'the full-only rule is recorded as skipped, with the profile-scan reason - this ticket''s 1st acceptance criterion, end to end'

t_case '--profile-scan full (or the default, no flag at all) against the SAME registry records both'
SCOURSH_INSTALL_ROOT=$ROOT_WITH_CHECKS assert_status 0 \
  'sast with no --profile-scan defaults to full' \
  _run_main sast --path . --out "$W/run-full"
assert_contains "$(cat "$W/run-full/meta/checks_selected")" 'SAST-GEN-DEMO_QUICK-01' \
  'quick-tagged rule still runs under the default'
assert_contains "$(cat "$W/run-full/meta/checks_selected")" 'SAST-GEN-DEMO_FULL-01' \
  "full-only rule ALSO runs under the default - fails under 'no --profile-scan silently narrows the scan'"
assert_file_absent "$W/run-full/meta/skipped_checks" \
  'nothing was skipped under full - both fixture rules ran, so meta/skipped_checks was never written'

t_case "an unknown --profile-scan value is refused at the CLI layer, never reaches the registry (this ticket's 2nd acceptance criterion)"
SCOURSH_INSTALL_ROOT=$ROOT_WITH_CHECKS assert_status 2 \
  "'--profile-scan bogus' dies exit 2, not a silent fallback to full" \
  _run_main sast --path . --profile-scan bogus --out "$W/run-bogus-profile"

t_case 'a module with no registry on disk still exits 0 and declares why, distinctly from "no run.sh yet"'
SCOURSH_INSTALL_ROOT=$ROOT_OK_SCANNER assert_status 0 \
  'sca (no modules/sca/ under this fixture root) still succeeds' \
  _run_main sca --path . --out "$W/run-no-registry"
assert_contains "$(cat "$W/run-no-registry/meta/coverage_reduction")" \
  'module=sca reason=no_check_registry_on_disk_yet' \
  'the filter-chain reason is recorded distinctly from scan_dispatch''s own not_yet_built reason'

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

# `all` is the ONLY command that dispatches more than one module into a single
# process, so it is the only one that can catch a module library whose state
# does not survive the FIRST `scan_dispatch` return.  This case must run as a
# real subprocess for the same reason the three above it do, and for one more:
# every consumer of `modules/sast/engine.sh` is reached through `scan_dispatch`,
# which is a FUNCTION that `source`s its module - so a unit test that calls
# `sast_index_checks` directly passes under both the broken and the fixed
# reading, and pins nothing.  Only the second consumer in one process fails.
t_case 'scan.sh all dispatches every module in one process and each one still contributes findings'
rm -rf "$W/run-all" "$W/all-tree"
mkdir -p "$W/all-tree"
# One canonical fixture file per module rather than the whole
# tests/fixtures/vuln tree: this case has to prove BOTH modules really ran, and
# the smallest tree that does so keeps it at a couple of seconds instead of the
# ~50s the full tree costs.  They are copies of the shared fixture files, not
# new inline content, so a rule change that retires either one is visible here.
cp "$ROOT/tests/fixtures/vuln/go_exec_concat.go" \
  "$ROOT/tests/fixtures/vuln/tf_open_cidr.tf" "$W/all-tree/"
assert_status 0 './scan.sh all --path DIR --out DIR exits 0 end to end' \
  _bin_run all --path "$W/all-tree" --out "$W/run-all"
assert_not_contains "$(cat "$W/bin.out")" 'unbound variable' \
  'no module library lost its state when the previous module''s scan_dispatch returned - fails under "a file-scope declare -A in a library sourced from inside scan_dispatch is a global", which makes the SECOND consumer index checks into an undeclared name and evaluate its check-id subscript as arithmetic'
assert_file_exists "$W/run-all/run.json" 'run.json was written by the real script'
_all_findings=$(cat "$W/run-all/findings.jsonl")
assert_contains "$_all_findings" '"module":"sast"' \
  'the sast module contributed a finding'
assert_contains "$_all_findings" '"module":"iac"' \
  'the iac module contributed a finding TOO - fails under "all aborted after the first module", which leaves a report that silently omits every later module while run.json still declares the run complete'

# =============================================================================
printf '\n-- --format actually selects which artifacts get written --\n'
# =============================================================================
# Reuses $W/all-tree (one sast fixture, one iac fixture) from the case above,
# so every --format run below has at least one real finding to report, not an
# empty tree that would write the same five near-empty files whatever
# --format asked for and pin nothing.

t_case 'no --format: the five artifacts this project has always written are all still written'
rm -rf "$W/fmt-default"
assert_status 0 './scan.sh all --path DIR --out DIR (no --format) exits 0' \
  _bin_run all --path "$W/all-tree" --out "$W/fmt-default"
for f in findings.json findings.jsonl report.md report.html run.json; do
  assert_file_exists "$W/fmt-default/$f" \
    "$f is written with no --format given - pins today's unchanged default, fails under a default that silently narrows what a caller who never asked for --format gets"
done

t_case '--format md writes only report.md, plus the two mandatory records'
rm -rf "$W/fmt-md"
assert_status 0 './scan.sh all --format md exits 0' \
  _bin_run all --path "$W/all-tree" --out "$W/fmt-md" --format md
assert_file_exists "$W/fmt-md/report.md" 'report.md is written'
assert_file_exists "$W/fmt-md/findings.jsonl" \
  'findings.jsonl is written regardless - it is a mandatory per-run record, not one of the four --format values'
assert_file_exists "$W/fmt-md/run.json" \
  'run.json is written regardless - every run writes run.json (docs/DESIGN.md §4)'
assert_file_absent "$W/fmt-md/findings.json" \
  "findings.json is NOT written - fails under the shipped defect where --format is parsed and then discarded, so 'md' still got findings.json too"
assert_file_absent "$W/fmt-md/report.html" \
  "report.html is NOT written - fails under the same discarded-format defect"

t_case '--format json,html (multi-format) writes exactly those two, and nothing findings.jsonl/run.json would not already cover'
rm -rf "$W/fmt-json-html"
assert_status 0 './scan.sh all --format json,html exits 0' \
  _bin_run all --path "$W/all-tree" --out "$W/fmt-json-html" --format json,html
assert_file_exists "$W/fmt-json-html/findings.json" 'findings.json is written'
assert_file_exists "$W/fmt-json-html/report.html" 'report.html is written'
assert_file_absent "$W/fmt-json-html/report.md" \
  "report.md is NOT written - fails under 'every format list still writes all five artifacts'"

t_case '--format sarif alone: no SARIF emitter exists yet (docs/DESIGN.md §13 step 10), so it selects nothing beyond the two mandatory records'
rm -rf "$W/fmt-sarif"
assert_status 0 './scan.sh all --format sarif exits 0' \
  _bin_run all --path "$W/all-tree" --out "$W/fmt-sarif" --format sarif
assert_file_exists "$W/fmt-sarif/findings.jsonl" 'findings.jsonl is still written (mandatory)'
assert_file_exists "$W/fmt-sarif/run.json" 'run.json is still written (mandatory)'
assert_file_absent "$W/fmt-sarif/findings.json" 'findings.json is NOT written for --format sarif'
assert_file_absent "$W/fmt-sarif/report.md" 'report.md is NOT written for --format sarif'
assert_file_absent "$W/fmt-sarif/report.html" 'report.html is NOT written for --format sarif'

# =============================================================================
printf '\n-- per-subcommand help: scan.sh <command> --help --\n'
# =============================================================================
t_case 'dast --help exits 0 with no --target given, and states it is only partially built'
assert_status 0 './scan.sh dast --help exits 0 with no --target' _bin_run dast --help
DAST_HELP=$(cat "$W/bin.out")
assert_contains "$DAST_HELP" 'scan.sh dast [options]' 'command-specific header'
assert_contains "$DAST_HELP" 'partially built' \
  "dast states plainly that it is only partially built - fails under the shipped defect where every subcommand prints the same global usage and says nothing about build status"
assert_contains "$DAST_HELP" 'scan phases implemented' \
  'the phase count is stated, not just a bare "partial"'
assert_not_contains "$DAST_HELP" 'Commands:' \
  "dast --help is NOT the global usage text - fails under 'scan.sh dast --help prints the same global usage' (the shipped defect this ticket fixes)"

t_case 'cloud --help exits 0 and states plainly it is not built'
assert_status 0 './scan.sh cloud --help exits 0' _bin_run cloud --help
CLOUD_HELP=$(cat "$W/bin.out")
assert_contains "$CLOUD_HELP" 'scan.sh cloud [options]' 'command-specific header'
assert_contains "$CLOUD_HELP" 'NOT built' 'cloud states plainly that it is not built'
assert_contains "$CLOUD_HELP" 'modules/cloud/aws/run.sh does not exist' \
  'the reason is the real, checkable fact scan_dispatch itself acts on, not a hand-typed claim'

t_case 'diff --help exits 0 with no --against given, and states plainly it is not built'
assert_status 0 './scan.sh diff --help exits 0 with no --against' _bin_run diff --help
DIFF_HELP=$(cat "$W/bin.out")
assert_contains "$DIFF_HELP" 'scan.sh diff [options]' 'command-specific header'
assert_contains "$DIFF_HELP" 'NOT built' 'diff states plainly that it is not built'
assert_contains "$DIFF_HELP" 'state/' 'the reason names the real step-7 dependency, not a vague "later"'

t_case 'sca --help exits 0 and states plainly it IS built'
assert_status 0 './scan.sh sca --help exits 0' _bin_run sca --help
SCA_HELP=$(cat "$W/bin.out")
assert_contains "$SCA_HELP" 'scan.sh sca [options]' 'command-specific header'
assert_contains "$SCA_HELP" 'Status: built.' \
  'sca is real (modules/sca/run.sh exists) and says so, distinctly from a NOT-built command'

t_case 'four different --help outputs are four different texts, never one shared global usage'
assert_ne "$DAST_HELP" "$CLOUD_HELP" 'dast --help differs from cloud --help'
assert_ne "$CLOUD_HELP" "$DIFF_HELP" 'cloud --help differs from diff --help'
assert_ne "$DIFF_HELP" "$SCA_HELP" \
  "diff --help differs from sca --help - fails under the shipped defect where 'scan.sh dast --help, scan.sh cloud --help, scan.sh diff --help and scan.sh sca --help all print the same global usage'"

t_case 'every accepted flag for a command is listed in its own --help - generated from the parser''s own table, not hand-typed'
assert_contains "$DAST_HELP" '--target VALUE' "dast's own required flag is listed"
assert_contains "$DAST_HELP" '--intensity VALUE' "dast's own --intensity is listed"
assert_contains "$DAST_HELP" '--format VALUE' 'a global flag (--format) is listed too, since every command accepts it'

t_summary 'scan' || FAILED=1
exit "${FAILED:-0}"
