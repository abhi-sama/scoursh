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

# docs/STEP-GUIDE-PLAN.md GUIDE-03: `_run_main` alone is no longer safe for a
# guided-eligible case now that a real G1/G2/G8 menu exists to block on -
# `assert_status`'s own `( "$@" ) >/dev/null 2>&1` redirects stdout/stderr
# but never stdin (AGENTS.md: "tests/run-tests.sh runs each suite as `bash
# <path>` with no stdin ... redirection, and at a developer's terminal a
# suite file therefore has stdin ... on a tty"), so an un-redirected guided
# call here would try to read THIS suite's own real terminal.  `_run_main_in`
# attaches STDIN (a here-string, a file, or /dev/null) directly to the
# `scan_main` invocation itself - never through `$(...)`, which would let a
# `die()` inside it escape only the subshell rather than the process, the
# same hazard `_scan_require_readable_path`'s own comment documents at
# length - so every guided case below that could reach a real prompt states
# exactly what it feeds it rather than leaving that to chance.
_run_main_in() {
  local stdin_src=$1
  shift
  scan_main "$@" <"$stdin_src"
}

# `_run_main_answers ANSWERS CMD...` - the scripted-answer-stream sibling of
# `_run_main_in`, for a case that must actually walk through G1/G2/G8 rather
# than hit EOF immediately.  ANSWERS is fed via process substitution, the
# same `< <(printf ...)` idiom tests/suites/guide.sh's own `guide_menu`
# cases already use, for the identical reason: attaching the redirect
# directly to the `scan_main` call keeps it OUT of any `$(...)` a die() could
# only half-escape.
_run_main_answers() {
  local answers=$1
  shift
  scan_main "$@" < <(printf '%s' "$answers")
}

# `_guide_env [NAME=VALUE...] CMD...` - STATE the environment a guided case
# needs instead of inheriting it from whatever machine the suite runs on.
#
# lib/guide.sh's five-condition gate reads NINE non-interactive environment
# markers, and a hosted CI runner sets two of them (`CI` and `GITHUB_ACTIONS`)
# for every process it starts.  `SCOURSH_GUIDE_FORCE_TTY` forces ONLY the two
# terminal checks - deliberately, per that file's own header, so that a case
# proving "the marker refuses even when the terminal check would pass" really
# exercises the marker rather than re-proving the terminal gate - so it does
# NOT make guided mode eligible on a runner, and a case that needs
# ELIGIBILITY has to clear those markers for itself.  Inheriting eligibility
# from "a developer's terminal happens not to be a CI runner" is an ambient
# fact, and depending on it is what made this whole section pass at a
# terminal and fail 13 assertions on BOTH `ubuntu-latest` and `macos-latest`
# (identical counts on two userlands is what identifies it as an environment
# difference rather than a GNU/BSD one).
#
# The clear-then-override order is what makes the two REFUSAL cases below
# discriminating rather than vacuous: `_guide_env CI=1 ...` proves the `CI`
# marker refuses because every other marker was removed first, and
# `_guide_env SCOURSH_NO_PROMPT=1 ...` proves SCOURSH_NO_PROMPT refuses for
# the same reason.  Run unchanged on a runner, each of those would have
# passed off the runner's OWN inherited `CI`, certifying green whatever the
# variable it names actually did.
#
# The marker list is read from lib/guide.sh's own `_GUIDE_ENV_MARKERS`, never
# a second copy here: a copy would drift silently from the gate it exists to
# mirror, and the drift would show up as this exact failure again.
#
# NONE OF THIS IS A NEW CONVENTION.  tests/suites/guide.sh has shipped the
# identical shape since GUIDE-01 - `_GUIDE_TEST_CONTROLLED_VARS` plus
# `_guide_test_prompt`, whose own comment already states the reason in as many
# words ("so a real CI runner's own CI=true/GITHUB_ACTIONS=true ... never leaks
# into a 'should allow' case").  This file's guided cases simply did not adopt
# it, and the difference is the whole bug: that suite passed on CI and this one
# did not.  A guided case added here later belongs in `_guide_env` for the same
# reason, and a change to the gate's own condition list belongs in
# `_GUIDE_ENV_MARKERS`, which both helpers read.
#
# Every caller runs this inside a subshell - `assert_status`'s own `( "$@" )`,
# or an explicit `( ... ) >file 2>&1` capture - so the unsets and exports are
# contained and one case can never alter the next.
_guide_env() {
  local _m
  for _m in "${_GUIDE_ENV_MARKERS[@]+"${_GUIDE_ENV_MARKERS[@]}"}"; do
    unset -v "$_m"
  done
  unset -v SCOURSH_NO_PROMPT
  # Leading NAME=VALUE tokens only; the scan stops at the first token that is
  # not one, which is the command to run.  Every command below is a `_run_main*`
  # helper name, so there is no token this could mistake for an assignment.
  while [[ ${1-} == [A-Za-z_]*=* ]]; do
    export "${1?}"
    shift
  done
  "$@"
}

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

# docs/STEP-GUIDE-PLAN.md GUIDE-02 moved the required-flag and cross-flag
# block these four assertions pin out of scan_parse_args and into its own
# `_scan_check_required`, called by scan_main AFTER its guided-mode routing
# rather than from scan_parse_args itself - see that function's own header
# for why. `scan_parse_args` ALONE no longer dies for any of these cases (a
# bare `scan.sh dast` now parses cleanly, with no --target); this helper
# runs the two in the same order scan_main does, so the four assertions
# below keep pinning the exact same rules and exit-2 text they always did.
_parse_and_require() {
  scan_parse_args "$@"
  _scan_check_required
}

t_case '--fail-on-new requires --fail-on in the SAME invocation'
assert_status 2 '--fail-on-new with no --fail-on dies exit 2 (docs/FOUNDATION.md tension 14, the missing-gate-flags paragraph)' \
  _parse_and_require sast --fail-on-new --path .
scan_parse_args sast --fail-on-new --fail-on high --path .
assert_eq true "${SCAN_FLAGS[fail-on-new]}" '--fail-on-new with --fail-on present parses cleanly'

t_case "'dast' requires --target"
assert_status 2 "'scan.sh dast' with no --target dies exit 2" \
  _parse_and_require dast
assert_status 0 \
  "'scan.sh dast' with no --target parses cleanly through scan_parse_args ALONE - fails under 'the required-flag block never moved', which is exactly what would break 'scan.sh dast --guided' (docs/STEP-GUIDE-PLAN.md GUIDE-02)" \
  scan_parse_args dast

t_case "'diff' requires --against, 'report' requires --from"
assert_status 2 "'scan.sh diff' with no --against dies exit 2" _parse_and_require diff
assert_status 2 "'scan.sh report' with no --from dies exit 2" _parse_and_require report

t_case 'an unexpected positional argument'
assert_status 2 'no documented command takes a bare positional (docs/DESIGN.md §5 is entirely flag-based)' \
  scan_parse_args sast extra-arg --path .

# =============================================================================
printf '\n-- docs/STEP-GUIDE-PLAN.md GUIDE-02: the guided-flow settable-flag registry --\n'
# =============================================================================
# GUIDE_SETTABLE_FLAGS lives in lib/guide.sh (scan.sh sources it), and is the
# single source of truth every later GUIDE-0x ticket appends a flag NAME to
# as it wires a real prompt. This is what makes "a guided prompt's flag must
# already be legal for the parser" structural rather than a convention - see
# that array's own header comment for the full contract. It is no longer
# empty as of GUIDE-04 (G3/G5/G6's own `target`/`intensity`/`i-own-target`/
# `requests-per-second`/`request-budget`/`allow-intrusive`), so the `for`
# loop below now actually asserts something on every run rather than the
# zero-iteration no-op it was under GUIDE-02 alone.
t_case 'every entry in GUIDE_SETTABLE_FLAGS names a real _SCAN_FLAG_KIND key'
if (( ${#GUIDE_SETTABLE_FLAGS[@]} == 0 )); then
  _t_ok 'GUIDE_SETTABLE_FLAGS is empty - GUIDE-02 wires no real prompt yet, so there is nothing to check against _SCAN_FLAG_KIND, and a for loop over it below would run zero iterations either way'
else
  for _guide_flag in "${GUIDE_SETTABLE_FLAGS[@]}"; do
    _guide_flag_found=0
    for _guide_key in "${!_SCAN_FLAG_KIND[@]}"; do
      [[ $_guide_key == *":$_guide_flag" ]] && _guide_flag_found=1 && break
    done
    if (( _guide_flag_found )); then
      _t_ok "GUIDE_SETTABLE_FLAGS entry '$_guide_flag' matches a real _SCAN_FLAG_KIND key"
    else
      _t_no "GUIDE_SETTABLE_FLAGS entry '$_guide_flag' matches a real _SCAN_FLAG_KIND key" \
        "no '*:$_guide_flag' key exists in _SCAN_FLAG_KIND - a guided prompt would compose a flag the parser itself refuses"
    fi
  done
fi
unset _guide_flag _guide_key _guide_flag_found

t_case "--guided and --print-command (this ticket's own two additions) parse as ordinary global bool flags"
scan_parse_args sast --guided --path .
assert_eq true "${SCAN_FLAGS[guided]}" '--guided parses to true on an arbitrary command, since it is declared global'
scan_parse_args sast --print-command --path .
assert_eq true "${SCAN_FLAGS[print-command]}" '--print-command parses to true the same way'

# =============================================================================
printf '\n-- docs/STEP-GUIDE-PLAN.md GUIDE-02: guided-mode routing in scan_main --\n'
# =============================================================================
# Every case here runs scan_main FOR REAL, through _run_main, never
# scan_parse_args alone - the routing this ticket adds lives in scan_main
# itself, both before and after the scan_parse_args call (see scan_main's
# own comments at its top). assert_status already redirects both stdout and
# stderr to /dev/null (tests/lib/assert.sh's own `( "$@" ) >/dev/null 2>&1`),
# which alone makes stderr non-a-terminal for every case below, exactly as
# tests/suites/scan.sh's own `_bin_run` helper already relies on further
# down this file; SCOURSH_GUIDE_FORCE_TTY is the only way to force the
# TERMINAL half of the gate under that redirection, the identical hook
# tests/suites/guide.sh already uses for lib/guide.sh's own gate.
#
# The terminal half is not the whole gate, and every case below goes through
# `_guide_env` (defined above with the other `_run_main*` helpers) for the
# rest of it: whether guided mode is eligible, ineligible-for-the-terminal,
# or ineligible-for-a-named-marker is stated per case rather than inherited
# from the machine.  Nothing here reads as "eligible" merely because the
# developer running it is not sitting inside a CI runner.  Read that
# function's own header for the measured failure this shape exists to
# prevent.
#
# STDIN IS STATED TOO, not inherited.  tests/run-tests.sh runs each suite as
# `bash <path>` with no stdin redirection, so at a real developer terminal a
# suite file's stdin IS a tty while on a headless runner it is not - and
# `assert_status`/`( ... ) >file 2>&1` redirect stdout and stderr but never
# stdin.  A case whose expected REASON is the stdin check therefore has to
# attach its own stdin (`_run_main_in /dev/null`), or it names whichever
# condition the ambient stdin happens to leave failing - the mirror image of
# the marker problem, failing at a terminal and passing on a runner.

t_case 'bare scan.sh (zero arguments) with no terminal is UNCHANGED: today''s "no command given" usage error, never a guided-mode message'
# Genuinely ZERO arguments, on purpose - `--out X` alone makes `$#` 2, which
# never satisfies scan_main's own `(( $# == 0 ))` guided-mode test and so
# would exercise "unknown command: '--out'" instead of the case this claims
# to test; both dead ends exit 2, which is exactly how that mistake would
# stay invisible if made here.
cd "$W"
assert_status 2 \
  'zero arguments with no terminal falls straight through to the unmodified scan_parse_args call - the dedicated byte-identical non-regression case further below in this file proves the text itself never changed' \
  _run_main
cd "$ROOT"

t_case 'bare scan.sh (zero arguments) with a forced terminal: guided mode is eligible and reaches the real G1 menu (docs/STEP-GUIDE-PLAN.md GUIDE-03) - EOF at G1 refuses honestly rather than running an unconfigured scan'
cd "$W"
assert_status 2 \
  "eligible zero-arg guided mode with no scripted answer hits EOF at G1's own menu and dies exit 2 - fails under 'fall back to silently running today's usage error', indistinguishable from the ineligible case above, and under 'silently run some default scan', which the plan calls a worse outcome than a clear refusal" \
  _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_in /dev/null
cd "$ROOT"
assert_file_absent "$W/reports" 'a refused zero-argument invocation - eligible or not - never reaches run_init, so no default reports/<timestamp> directory was created under the cwd it ran from'

t_case '--guided explicitly given with no terminal: fails LOUDLY with the concrete reason, before any required-flag check ever runs'
# `_guide_env` with no override and `_run_main_in /dev/null` between them make
# stdin the ONE failing condition: no marker is set, and stdin is a file.  That
# is what makes the assertion below discriminating, since `guide_ineligible_reason`
# names the FIRST failing condition in the gate's own order - with the ambient
# stdin of a developer's terminal it would name stderr instead, and with a
# runner's inherited `CI` left in place "no terminal" and "a CI marker is set"
# would be indistinguishable, which is exactly what that assertion claims to
# rule out.
rm -rf "$W/run-guide-explicit-noterm"
assert_status 2 \
  '--guided with no terminal dies exit 2, even though `dast` was given no --target at all - fails if the moved required-flag check still ran first and reported the wrong reason' \
  _guide_env _run_main_in /dev/null dast --guided --out "$W/run-guide-explicit-noterm"
GUIDE_NOTERM_OUT=$W/guide-noterm.out
( _guide_env _run_main_in /dev/null dast --guided --out "$W/run-guide-explicit-noterm2" ) >"$GUIDE_NOTERM_OUT" 2>&1 || true
assert_contains "$(cat "$GUIDE_NOTERM_OUT")" 'standard input is not a terminal' \
  'the concrete reason is named, not a generic refusal - fails under a message that cannot distinguish "no terminal" from "a CI marker is set" from "SCOURSH_NO_PROMPT is set"'
assert_file_absent "$W/run-guide-explicit-noterm" 'no run directory was created'

t_case '--guided explicitly given with a forced terminal: eligible, skips G1 (the command was already typed) and reaches G8 - EOF there refuses honestly (same "nothing ran" outcome as the bare-terminal case)'
rm -rf "$W/run-guide-explicit-tty"
assert_status 2 \
  '--guided with a forced terminal and no CI marker, and no scripted answer, hits EOF at G8 (dast has no G2 follow-ups) and dies exit 2' \
  _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_in /dev/null dast --guided --out "$W/run-guide-explicit-tty"
assert_file_absent "$W/run-guide-explicit-tty" 'no run directory was created'

t_case 'a CI marker refuses --guided even with a forced terminal - the environment layer can only ever turn prompting OFF, never on'
rm -rf "$W/run-guide-ci"
assert_status 2 \
  "'CI' set in the environment refuses --guided even though the terminal checks would pass - fails under 'a pty-allocating CI runner is interactive', exactly the shape docs/STEP-GUIDE-PLAN.md's condition 4 exists to catch" \
  _guide_env CI=1 SCOURSH_GUIDE_FORCE_TTY=true _run_main dast --guided --out "$W/run-guide-ci"
GUIDE_CI_OUT=$W/guide-ci.out
( _guide_env CI=1 SCOURSH_GUIDE_FORCE_TTY=true _run_main dast --guided --out "$W/run-guide-ci2" ) >"$GUIDE_CI_OUT" 2>&1 || true
assert_contains "$(cat "$GUIDE_CI_OUT")" "'CI' is set in the environment" \
  'the CI marker itself is named as the concrete reason'
assert_file_absent "$W/run-guide-ci" 'no run directory was created'

t_case 'SCOURSH_NO_PROMPT refuses --guided even with a forced terminal and no CI marker - the one documented way to force guided mode off'
rm -rf "$W/run-guide-noprompt"
assert_status 2 \
  'SCOURSH_NO_PROMPT refuses --guided' \
  _guide_env SCOURSH_NO_PROMPT=1 SCOURSH_GUIDE_FORCE_TTY=true _run_main_in /dev/null dast --guided --out "$W/run-guide-noprompt"
# The exit status ALONE does not pin this, and did not before `_guide_env`
# either: an ELIGIBLE `--guided` that reads EOF at G8 also dies exit 2, so a
# gate that ignored SCOURSH_NO_PROMPT entirely would still satisfy the status
# assertion above.  Measured, not reasoned: with `guide_may_prompt` mutated to
# drop its environment layer, the sibling `CI` case below went red on its own
# reason assertion and this case stayed green until this one was added.  The
# reason is what discriminates, exactly as it does for `CI`.
GUIDE_NOPROMPT_OUT=$W/guide-noprompt.out
( _guide_env SCOURSH_NO_PROMPT=1 SCOURSH_GUIDE_FORCE_TTY=true \
    _run_main_in /dev/null dast --guided --out "$W/run-guide-noprompt2" ) >"$GUIDE_NOPROMPT_OUT" 2>&1 || true
assert_contains "$(cat "$GUIDE_NOPROMPT_OUT")" 'SCOURSH_NO_PROMPT is set' \
  'SCOURSH_NO_PROMPT itself is named as the concrete reason - fails under a gate that dropped its environment layer, where the exit-2 status alone would still pass off the EOF an eligible run reaches at G8'
assert_file_absent "$W/run-guide-noprompt" 'no run directory was created'
assert_file_absent "$W/run-guide-noprompt2" 'and none for the reason probe either'

t_case 'a fully-flagged command with no --guided is silent even on a forced terminal - guided mode never runs unless it was asked for'
mkdir -p "$W/guide-silent-tree"
printf 'print("hello")\n' >"$W/guide-silent-tree/x.py"
rm -rf "$W/run-guide-silent"
assert_status 0 \
  "sast --path with everything it needs and no --guided runs normally on a 'terminal' - fails under 'guided mode fires whenever a terminal is present', which would make an ordinary interactive invocation impossible without a flag to suppress it" \
  _guide_env SCOURSH_INSTALL_ROOT="$ROOT_OK_SCANNER" SCOURSH_GUIDE_FORCE_TTY=true \
  _run_main sast --path "$W/guide-silent-tree" --out "$W/run-guide-silent"
assert_file_exists "$W/run-guide-silent/run.json" 'the run actually happened - this is not another refusal that merely exits 0'

# =============================================================================
printf '\n-- docs/STEP-GUIDE-PLAN.md GUIDE-03: the G1 scan-type menu --\n'
# =============================================================================
# This ticket's own acceptance criterion, verbatim: "a suite case asserting
# the menu's ready set equals the set of modules with a run.sh on disk,
# because a shared-function convention is a thing a future edit can break."
# Two proofs, not one: against the REAL tree (where this project's own
# build-order state decides the answer, and is worth pinning as of this
# ticket - sast/sca/iac/dast all landed, cloud has not), and against a
# FIXTURE tree built to name an arbitrary subset, so the assertion is
# discriminating rather than a coincidence of what this checkout happens to
# have on disk right now.
t_case "_guide_g1_reachable equals _scan_module_built (\"the same probe scan_dispatch uses\") on the real tree"
for _guide_mod in sast sca iac dast cloud; do
  _guide_on_disk=0
  [[ -f $(_scan_module_script "$_guide_mod") ]] && _guide_on_disk=1
  _guide_reachable=0
  _guide_g1_reachable "$_guide_mod" && _guide_reachable=1
  assert_eq "$_guide_on_disk" "$_guide_reachable" \
    "guided-menu reachability for '$_guide_mod' matches modules/$_guide_mod/run.sh (or, for cloud, modules/cloud/aws/run.sh) on disk"
done
unset _guide_mod _guide_on_disk _guide_reachable

t_case '_guide_g1_reachable tracks an arbitrary fixture set of run.sh files, not a hardcoded list - fails under a hardcoded true/false per module name'
ROOT_GUIDE_SUBSET=$W/root-guide-subset
rm -rf "$ROOT_GUIDE_SUBSET"
mkdir -p "$ROOT_GUIDE_SUBSET/modules/sast" "$ROOT_GUIDE_SUBSET/modules/iac"
printf '#!/usr/bin/env bash\n' >"$ROOT_GUIDE_SUBSET/modules/sast/run.sh"
printf '#!/usr/bin/env bash\n' >"$ROOT_GUIDE_SUBSET/modules/iac/run.sh"
for _guide_mod in sast sca iac dast cloud; do
  _guide_want=0
  [[ $_guide_mod == sast || $_guide_mod == iac ]] && _guide_want=1
  _guide_got=0
  SCOURSH_INSTALL_ROOT=$ROOT_GUIDE_SUBSET _guide_g1_reachable "$_guide_mod" && _guide_got=1
  assert_eq "$_guide_want" "$_guide_got" \
    "on a fixture tree with only sast/iac run.sh present, '$_guide_mod' reachability matches"
done
unset _guide_mod _guide_want _guide_got

# The five cases below all pick a scan type AT G1, which is only reachable
# through the bare-zero-argument branch (docs/STEP-GUIDE-PLAN.md's own
# `--guided` skips G1 whenever a command was already typed - see the preset
# case further below).  Genuinely zero arguments means no `--out` either
# (the earlier "bare scan.sh" cases above already establish why one more
# token, even `--out X`, defeats scan_main's own `(( $# == 0 ))` test and
# would exercise "unknown command" instead of the guided menu) - so each
# case `cd`s into its own scratch directory instead, letting the default
# `reports/<timestamp>` fall there if it were ever created, and always
# `cd`s back out afterward.
t_case "picking an item whose module has no run.sh loops back to G1, and picking one that does proceeds - the menu's fixed 7 items never reorder"
GUIDE_CLOUD_LOOP_DIR=$W/guide-cloud-loop
rm -rf "$GUIDE_CLOUD_LOOP_DIR"
mkdir -p "$GUIDE_CLOUD_LOOP_DIR"
cd "$GUIDE_CLOUD_LOOP_DIR"
assert_status 0 \
  "item 5 (cloud, not built) explains and returns to G1; item 7 (quit) then exits 0 with nothing scanned - fails if the menu numbering shifted an unavailable item out of its fixed slot, or if picking it dispatched anyway" \
  _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'5\n7\n'
cd "$ROOT"
assert_file_absent "$GUIDE_CLOUD_LOOP_DIR/reports" 'quitting from the guided flow never creates a run directory'

GUIDE_CLOUD_LOOP_OUT=$W/guide-cloud-loop.out
cd "$GUIDE_CLOUD_LOOP_DIR"
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'5\n7\n' ) >"$GUIDE_CLOUD_LOOP_OUT" 2>&1 || true
cd "$ROOT"
assert_contains "$(cat "$GUIDE_CLOUD_LOOP_OUT")" 'not built yet in this version of' \
  'the loop-back explanation names the module as not built - fails under a message that cannot distinguish this from an ordinary refusal'
assert_contains "$(cat "$GUIDE_CLOUD_LOOP_OUT")" 'Cancelled.  Nothing was scanned.' \
  'quit (item 7) reached after the loop-back prints the ordinary cancellation message, never a guided-specific one'

t_case 'sca with no advisories.db explains and still proceeds - the operator may proceed, per this ticket'"'"'s own G1 wording'
GUIDE_SCA_DIR=$W/guide-sca-dir
rm -rf "$GUIDE_SCA_DIR"
mkdir -p "$GUIDE_SCA_DIR"
GUIDE_SCA_OUT=$W/guide-sca.out
GUIDE_SCA_RC=0
cd "$GUIDE_SCA_DIR"
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'2\n\n1\n' ) >"$GUIDE_SCA_OUT" 2>&1 || GUIDE_SCA_RC=$?
cd "$ROOT"
assert_eq 2 "$GUIDE_SCA_RC" 'sca proceeds through G2/G8 to the "no G9 yet" refusal, never a loop-back, even with no advisories.db'
assert_contains "$(cat "$GUIDE_SCA_OUT")" 'No advisory database is installed' \
  'the missing-db explanation is shown - fails under sca silently being treated as ready'
assert_contains "$(cat "$GUIDE_SCA_OUT")" 'scan.sh sca' \
  'and the composed preview still names sca, proving it was not bounced back to G1'
assert_file_absent "$GUIDE_SCA_DIR/reports" 'no run directory was created (G9 does not exist yet)'

t_case 'dast (module built, guided target setup not landed) proceeds past G1 with a note, skips G2 entirely, and only asks G8'
GUIDE_DAST_DIR=$W/guide-dast-dir
rm -rf "$GUIDE_DAST_DIR"
mkdir -p "$GUIDE_DAST_DIR"
GUIDE_DAST_OUT=$W/guide-dast.out
GUIDE_DAST_RC=0
cd "$GUIDE_DAST_DIR"
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'4\n1\n' ) >"$GUIDE_DAST_OUT" 2>&1 || GUIDE_DAST_RC=$?
cd "$ROOT"
assert_eq 2 "$GUIDE_DAST_RC" 'two answers only (scan type, then the CI gate) reach the "no G9 yet" refusal - fails if G2 were asked for dast, which needs a third answer that is not here'
assert_contains "$(cat "$GUIDE_DAST_OUT")" 'guided setup beyond the scan type' \
  'the prerequisite-honesty note names the real gap (GUIDE-04 not landed), never the stale "not built" text this plan'"'"'s own G1 mockup used before DAST landed'
assert_contains "$(cat "$GUIDE_DAST_OUT")" 'scan.sh dast' \
  'the composed preview names dast with no --path/--lang/--history, since none of those flags exist for dast'
assert_file_absent "$GUIDE_DAST_DIR/reports" 'no run directory was created'

t_case 'a bad --path is re-asked once, then returns to G1 (never dies) - docs/STEP-GUIDE-PLAN.md'"'"'s own G2 row'
GUIDE_BADPATH_DIR=$W/guide-badpath-dir
rm -rf "$GUIDE_BADPATH_DIR"
mkdir -p "$GUIDE_BADPATH_DIR"
GUIDE_BADPATH_OUT=$W/guide-badpath.out
GUIDE_BADPATH_RC=0
cd "$GUIDE_BADPATH_DIR"
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'1\n/no/such/dir-scoursh-guide-test\n/still/bad-scoursh-guide-test\n7\n' ) >"$GUIDE_BADPATH_OUT" 2>&1 || GUIDE_BADPATH_RC=$?
cd "$ROOT"
assert_eq 0 "$GUIDE_BADPATH_RC" 'two bad paths return to G1, where quit (item 7) exits 0 - fails under scan_parse_args-style die() on a bad guided-mode path answer'
assert_contains "$(cat "$GUIDE_BADPATH_OUT")" 'does not exist, or is not readable' \
  'the re-ask explanation is shown'
assert_contains "$(cat "$GUIDE_BADPATH_OUT")" 'Returning to the scan-type menu' \
  'and the second bad answer sends the operator back to G1 rather than a third re-ask'
assert_file_absent "$GUIDE_BADPATH_DIR/reports" 'no run directory was created'

t_case 'the full local-surface path (docs/STEP-GUIDE-PLAN.md G1+G2+G8) composes the expected flags into the preview'
GUIDE_SAST_DIR=$W/guide-sast-dir
rm -rf "$GUIDE_SAST_DIR"
mkdir -p "$GUIDE_SAST_DIR/guide-sast-tree"
GUIDE_SAST_OUT=$W/guide-sast.out
GUIDE_SAST_RC=0
cd "$GUIDE_SAST_DIR"
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'1\nguide-sast-tree\npy,js\n2\n4\n' ) >"$GUIDE_SAST_OUT" 2>&1 || GUIDE_SAST_RC=$?
cd "$ROOT"
assert_eq 2 "$GUIDE_SAST_RC" 'sast through G1/G2 (path, languages, git history) and G8 (fail-on) reaches the "no G9 yet" refusal'
GUIDE_SAST_TEXT=$(cat "$GUIDE_SAST_OUT")
assert_contains "$GUIDE_SAST_TEXT" 'scan.sh sast --fail-on medium --history --lang py,js --path guide-sast-tree' \
  'the composed preview names every answered flag, alphabetically sorted, with the boolean --history carrying no value token - fails under a preview that drops an answer or mis-renders a bool as a value flag'
assert_file_absent "$GUIDE_SAST_DIR/reports" 'no run directory was created'

mkdir -p "$W/guide-sast-tree"

t_case '`scan.sh sast --path X --guided` skips G1 (the command was already typed) and G2''s path question (--path was already given) - docs/STEP-GUIDE-PLAN.md: "'"'"'--guided'"'"' only ever fills flags that were not supplied on the command line"'
GUIDE_PRESET_OUT=$W/guide-preset.out
GUIDE_PRESET_RC=0
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_answers $'\n1\n1\n' sast --path "$W/guide-sast-tree" --guided --out "$W/run-guide-preset" ) >"$GUIDE_PRESET_OUT" 2>&1 || GUIDE_PRESET_RC=$?
assert_eq 2 "$GUIDE_PRESET_RC" 'three answers (languages default, no history, no gate) are enough - a fourth for --path would mean G1 or the path question ran unexpectedly'
assert_contains "$(cat "$GUIDE_PRESET_OUT")" "scan.sh sast --out $W/run-guide-preset --path $W/guide-sast-tree" \
  'the already-typed --path (and --out, also already typed) survive into the composed preview unchanged, alphabetically sorted'
assert_not_contains "$(cat "$GUIDE_PRESET_OUT")" 'What do you want to scan?' \
  'G1 never printed - the command line already named the scan type'
assert_file_absent "$W/run-guide-preset" 'no run directory was created'

t_case 'a fully-flagged `--guided` invocation asks nothing at all and degrades to just the preview - docs/STEP-GUIDE-PLAN.md: "this is also how it degrades to a no-op"'
GUIDE_FULL_OUT=$W/guide-full.out
GUIDE_FULL_RC=0
( _guide_env SCOURSH_GUIDE_FORCE_TTY=true _run_main_in /dev/null sast --path "$W/guide-sast-tree" --lang py --history --fail-on high --guided --out "$W/run-guide-full" ) >"$GUIDE_FULL_OUT" 2>&1 || GUIDE_FULL_RC=$?
assert_eq 2 "$GUIDE_FULL_RC" 'every flag G1/G2/G8 could have asked about was already supplied, so /dev/null stdin (immediate EOF) never gets read at all - fails if any question were still asked, which would die exit 2 with a DIFFERENT message ("input ended...") instead of reaching the composed preview'
assert_contains "$(cat "$GUIDE_FULL_OUT")" "scan.sh sast --fail-on high --history --lang py --out $W/run-guide-full --path $W/guide-sast-tree" \
  'the preview is exactly what was typed, byte for byte'

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

# =============================================================================
printf '\n-- docs/STEP-GUIDE-PLAN.md GUIDE-04: --requests-per-second / --request-budget --\n'
# =============================================================================
# DAST-32 already reads both as config/scanner.conf keys with a conservative
# ceiling; this ticket is what gives the guided flow's G6 rate/budget prompts
# (lib/guide.sh) a real flag to emit, per this plan's own "every prompt has a
# flag equivalent" rule.

t_case '--requests-per-second/--request-budget parse on dast and all, same shape lib/config.sh already enforces'
scan_parse_args dast --target host-a --requests-per-second 20 --request-budget 20000
assert_eq 20 "${SCAN_FLAGS[requests-per-second]}" 'requests-per-second parses'
assert_eq 20000 "${SCAN_FLAGS[request-budget]}" 'request-budget parses'
scan_parse_args all --requests-per-second 0.5 --request-budget 100000 --path .
assert_eq 0.5 "${SCAN_FLAGS[requests-per-second]}" 'a fractional rate parses on all too (rules/RULE-FORMAT.md §9.6.1 allows a decimal)'
assert_status 2 \
  '--requests-per-second is not a valid flag on sast - it has nothing to throttle' \
  scan_parse_args sast --requests-per-second 4 --path .
assert_status 2 \
  '--request-budget rejects zero - unlike requests-per-second, a budget of nothing is never legal (there is always a budget)' \
  scan_parse_args dast --target host-a --request-budget 0
assert_status 2 \
  '--request-budget rejects a non-integer' \
  scan_parse_args dast --target host-a --request-budget 4.5
scan_parse_args dast --target host-a --requests-per-second 0
assert_eq 0 "${SCAN_FLAGS[requests-per-second]}" \
  'requests-per-second 0 is schema-legal at the CLI shape-validation layer - lib/http.sh is what actually refuses it, at run start, not the parser (see lib/guide.sh, "the limiter has no literal unbounded sentinel")'

t_case 'a guided-composed dast argv round-trips through the real parser and the real affirmation check'
DW=$SCOURSH_SCRATCH/scan-guide-roundtrip
mkdir -p "$DW/config"
cat >"$DW/config/scope.conf" <<'EOF'
id: staging-api
base-url: https://staging-api.fixture.example
allow-subdomains: false
allow-private-addresses: false
EOF
_scan_with_root() {
  local SCOURSH_INSTALL_ROOT=$1
  shift
  "$@"
}
_scan_with_root "$DW" guide_dast_configure < <(printf '1\n3\nstaging-api\n2\n1\n2\n') 2>/dev/null
assert_eq '--target staging-api --intensity active --i-own-target staging-api --requests-per-second 20 --request-budget 5000 --allow-intrusive' \
  "${GUIDE_DAST_ARGV[*]}" 'the guided flow composed the expected argv (mirrors tests/suites/guide.sh'"'"'s own identical case)'
_scan_guide_argv=("${GUIDE_DAST_ARGV[@]}")
scan_parse_args dast "${_scan_guide_argv[@]}"
assert_eq staging-api "${SCAN_FLAGS[target]}" 'round-trip: target'
assert_eq active "${SCAN_FLAGS[intensity]}" 'round-trip: intensity'
assert_eq staging-api "${SCAN_FLAGS[i-own-target]}" 'round-trip: i-own-target'
assert_eq 20 "${SCAN_FLAGS[requests-per-second]}" 'round-trip: requests-per-second'
assert_eq 5000 "${SCAN_FLAGS[request-budget]}" 'round-trip: request-budget'
assert_eq true "${SCAN_FLAGS[allow-intrusive]}" 'round-trip: allow-intrusive'
_scan_check_affirmation
_t_ok '_scan_check_affirmation accepts the composed argv with no die (i-own-target matches target; intensity and allow-intrusive are both covered by it)'

t_case 'the two-header form of the item-1-everywhere acceptance test round-trips to an unaffirmed, unraised parse too'
_scan_with_root "$DW" guide_dast_configure < <(printf '1\n1\n') 2>/dev/null
_scan_guide_argv=("${GUIDE_DAST_ARGV[@]}")
scan_parse_args dast "${_scan_guide_argv[@]}"
assert_eq '' "${SCAN_FLAGS[i-own-target]:-}" 'no affirmation on the conservative path'
assert_eq '' "${SCAN_FLAGS[intensity]:-}" 'no --intensity flag at all - passive is the unspoken default'
_scan_check_affirmation
_t_ok '_scan_check_affirmation accepts the conservative composed argv with no die - nothing here needed an affirmation'

t_case 'the two SCOURSH_CONFIG_* env vars reflect the CLI flag and are restored (never leaked) across a second scan_main-shaped call'
(
  unset SCOURSH_CONFIG_REQUESTS_PER_SECOND SCOURSH_CONFIG_REQUEST_BUDGET
  _SCAN_ENV_RPS_PRISTINE='' _SCAN_ENV_RPS_PRISTINE_SET=''
  _SCAN_ENV_BUDGET_PRISTINE='' _SCAN_ENV_BUDGET_PRISTINE_SET=''
  SCAN_FLAGS=([requests-per-second]=20 [request-budget]=20000)
  if [[ -n ${SCAN_FLAGS[requests-per-second]:-} ]]; then
    export SCOURSH_CONFIG_REQUESTS_PER_SECOND=${SCAN_FLAGS[requests-per-second]}
  elif [[ -n $_SCAN_ENV_RPS_PRISTINE_SET ]]; then
    export SCOURSH_CONFIG_REQUESTS_PER_SECOND=$_SCAN_ENV_RPS_PRISTINE
  else
    unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
  fi
  [[ ${SCOURSH_CONFIG_REQUESTS_PER_SECOND:-} == 20 ]] || exit 1
  # A SECOND "call" giving neither flag must restore the pristine (unset) state.
  SCAN_FLAGS=()
  if [[ -n ${SCAN_FLAGS[requests-per-second]:-} ]]; then
    export SCOURSH_CONFIG_REQUESTS_PER_SECOND=${SCAN_FLAGS[requests-per-second]}
  elif [[ -n $_SCAN_ENV_RPS_PRISTINE_SET ]]; then
    export SCOURSH_CONFIG_REQUESTS_PER_SECOND=$_SCAN_ENV_RPS_PRISTINE
  else
    unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
  fi
  [[ -z ${SCOURSH_CONFIG_REQUESTS_PER_SECOND+set} ]] || exit 2
)
rc=$?
assert_eq 0 "$rc" \
  'FAILS if the first "call"'"'"'s export leaked into the second, flagless one (exit 2), or if the export never took effect at all (exit 1) - scan_main can run more than once in one process (tests/suites/scan.sh calls it repeatedly), so a leaked SCOURSH_CONFIG_REQUESTS_PER_SECOND would silently change an unrelated later run'

t_case 'the real scan_main-run pristine-snapshot variables exist and reflect this process'"'"'s own environment at source time'
assert_eq "${SCOURSH_CONFIG_REQUESTS_PER_SECOND-}" "$_SCAN_ENV_RPS_PRISTINE" \
  '_SCAN_ENV_RPS_PRISTINE was captured once, at the top of scan.sh, before any flag was parsed'
assert_eq "${SCOURSH_CONFIG_REQUEST_BUDGET-}" "$_SCAN_ENV_BUDGET_PRISTINE" \
  '_SCAN_ENV_BUDGET_PRISTINE likewise'

t_case 'the two flags are in GUIDE_SETTABLE_FLAGS, which the earlier section already proved matches _SCAN_FLAG_KIND'
assert_contains "${GUIDE_SETTABLE_FLAGS[*]}" 'requests-per-second' 'requests-per-second is guided-settable'
assert_contains "${GUIDE_SETTABLE_FLAGS[*]}" 'request-budget' 'request-budget is guided-settable'

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

t_case "GUIDE-02 non-regression: bare scan.sh with no terminal keeps today's exit-2 usage text byte-identically"
# The direct non-regression test docs/STEP-GUIDE-PLAN.md GUIDE-02 names by
# name: a script piping scan.sh with no arguments today must see NO change
# whatsoever once guided-mode routing lands. tests/fixtures/scan-usage/
# no-command-given.txt is the real output of THIS repository's scan.sh,
# captured before any GUIDE-02 code existed, with only the wall-clock
# timestamp normalised to a fixed placeholder (die()'s message is otherwise
# static and untouched by this ticket - see scan_usage's own heredoc and
# scan_die_usage, neither of which this ticket edits). A real subprocess,
# never the sourced function, and stdin explicitly redirected from
# /dev/null so this assertion holds regardless of whether the process
# running the suite itself has a terminal attached.
GUIDE02_BASELINE=$ROOT/tests/fixtures/scan-usage/no-command-given.txt
GUIDE02_ACTUAL=$W/guide02-bare.out
GUIDE02_RC=0
bash "$ROOT/scan.sh" >"$GUIDE02_ACTUAL" 2>&1 </dev/null || GUIDE02_RC=$?
assert_eq 2 "$GUIDE02_RC" 'bare scan.sh with no terminal still exits 2'
GUIDE02_NORM=$W/guide02-bare.norm
sed -E 's/^[0-9TZ:-]{20} error/<TIMESTAMP> error/' "$GUIDE02_ACTUAL" >"$GUIDE02_NORM"
if diff -q "$GUIDE02_BASELINE" "$GUIDE02_NORM" >/dev/null 2>&1; then
  _t_ok 'output is byte-identical (modulo the wall-clock timestamp) to the frozen pre-GUIDE-02 fixture - fails under any change to what a piped, argument-less scan.sh prints or how it exits'
else
  _t_no 'output is byte-identical (modulo the wall-clock timestamp) to the frozen pre-GUIDE-02 fixture' \
    "diff: $(diff "$GUIDE02_BASELINE" "$GUIDE02_NORM" || true)"
fi

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
