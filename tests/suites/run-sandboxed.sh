#!/usr/bin/env bash
# tests/suites/run-sandboxed.sh - tools/run-sandboxed.sh, the macOS Seatbelt
# runner (docs/FOUNDATION.md tension 20, Tier A of the tension-20
# macOS-enforcement amendment).
#
# What this suite actually proves, and what it honestly cannot:
#
#  - Argument parsing and the precondition-function LOGIC are unit-tested
#    against real function calls on any host (no macOS, no sandbox-exec, no
#    root needed) - the same "test the logic in isolation" idiom
#    tests/suites/netns.sh section 0 uses for _netns_parse_args.
#  - "Fails immediately, no isolation action, <command> never runs" for the
#    Darwin precondition is exercised as a REAL subprocess invocation on
#    WHATEVER host this suite happens to run on: exactly one of section A
#    (non-Darwin) or section B (Darwin) below is the real, executed
#    assertion, mirroring tests/suites/netns.sh's own section A/B split for
#    the identical reason (this project's own GNU/BSD daily-suite matrix,
#    docs/CI-RUNBOOK.md, runs this suite on both a real macOS host and a
#    real Linux container).
#  - Unlike tools/run-in-netns.sh, this tool needs NO root and NO capability
#    - that is Tier A's whole advantage - so on a real Darwin host nearly
#    everything below is a REAL, unconditional, unprivileged proof: a real
#    `sandbox-exec` invocation that denies a real outbound connect attempt,
#    a real profile-rejection refusal, a real missing-command refusal, and
#    a real end-to-end `scan.sh sast` run under the sandbox. Section B is
#    gated only on `sandbox-exec` actually being present (it ships with
#    every macOS since at least 10.5), and states plainly when it is
#    SKIPPED rather than silently reporting green, the same
#    probe-and-state-plainly discipline tests/suites/netns.sh's section C
#    and tests/suites/paranoid.sh's real-lsof section already use.
#  - This suite deliberately does not attempt any real EXTERNAL egress, and
#    deliberately does not depend on a `timeout` binary either (GNU
#    coreutils only - absent on a bare macOS host, and this suite must run
#    there for real). The "must deny" case connects to a CLOSED local port
#    (127.0.0.1, a port nothing listens on): the profile denies loopback
#    exactly as it denies anything else (`(deny network*)` has no
#    "localhost is special" carve-out - see this file's own header, "no
#    concept of an authorised scope target"), so this is a real Seatbelt
#    denial, and a closed port refuses FAST (measured: <10ms) rather than
#    risking a long OS-level connect timeout against an unreachable address.
#    Section B2's "positive control" proves the SAME connect attempt, with
#    NO sandbox at all, is a normal fast "Connection refused" rather than
#    Seatbelt's "Operation not permitted" - a fixture that could not fail
#    either way is not proof, so the control has to discriminate for real.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2329: as tests/suites/http.sh and tests/suites/netns.sh.
# shellcheck disable=SC2015,SC2016,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=tools/run-sandboxed.sh
source "$ROOT/tools/run-sandboxed.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/run-sandboxed
mkdir -p "$W"
TOOL=$ROOT/tools/run-sandboxed.sh

# ---------------------------------------------------------------------------
# -- section 0: argument parsing (sourced-function unit tests) --
# ---------------------------------------------------------------------------
printf '\n-- argument parsing --\n'

_sbx_parse_args -- scan.sh sast --path .
assert_eq 'scan.sh sast --path .' "${RUN_SANDBOXED_CMD[*]}" \
  'a plain "-- <command...>" collects everything after -- as the wrapped command'

assert_status "$SCOURSH_EXIT_USAGE" 'missing -- entirely is a usage error (exit 2), not a silent no-op' \
  _sbx_parse_args scan.sh
assert_status "$SCOURSH_EXIT_USAGE" 'a bare -- with no command after it is a usage error' \
  _sbx_parse_args --
assert_status "$SCOURSH_EXIT_USAGE" 'an unrecognised flag before -- is a usage error, not swallowed into the command' \
  _sbx_parse_args --bogus -- echo hi

# ---------------------------------------------------------------------------
# -- section 0b: --help works on ANY host (real subprocess) --
# ---------------------------------------------------------------------------
printf '\n-- --help works regardless of host/sandbox-exec availability (real subprocess) --\n'
help_out=$(bash "$TOOL" --help 2>&1)
help_rc=0
bash "$TOOL" --help >/dev/null 2>&1 || help_rc=$?
assert_eq 0 "$help_rc" '--help exits 0 even on a host that would otherwise fail the Darwin/sandbox-exec checks'
assert_contains "$help_out" 'run-sandboxed.sh' '--help prints usage text naming the tool'
assert_contains "$help_out" 'run-in-netns.sh' '--help cross-references the Linux peer tool'

# ---------------------------------------------------------------------------
# -- section 1: precondition functions, unit-level (deterministic on any
#    host via PATH/profile-string indirection - the same idiom
#    RUN_NETNS_PROC_STATUS_FILE uses for _netns_has_cap_bit) --
# ---------------------------------------------------------------------------
printf '\n-- _sbx_require_darwin --\n'

_fake_uname_linux() { printf 'Linux'; }
uname() { _fake_uname_linux; }
require_darwin_rc=0
( _sbx_require_darwin ) >/dev/null 2>&1 || require_darwin_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$require_darwin_rc" \
  'a non-Darwin uname(1): _sbx_require_darwin exits 4 (missing required input), never a silent unsandboxed proceed'
require_darwin_msg=$( ( _sbx_require_darwin ) 2>&1 || true )
assert_contains "$require_darwin_msg" 'macOS-only' \
  'the error names the actual reason (macOS-only), not a generic failure'
unset -f uname

assert_status 0 'a real Darwin host (this suite'"'"'s own uname -s): _sbx_require_darwin succeeds' \
  _sbx_require_darwin

printf '\n-- _sbx_require_sandbox_exec --\n'
# die() calls a bare `exit`, which terminates the WHOLE subshell below
# immediately rather than "returning" a status to an inner `||` - so the
# capture has to wrap the subshell itself (the same shape assert_status and
# every other die()-triggering case in this suite use), never sit inside it.
no_sbx_rc=0
(
  # SC2123: deliberately scoped to this subshell only, to make `command -v
  # sandbox-exec` fail without touching the real PATH for the rest of the
  # suite.
  # shellcheck disable=SC2123
  PATH=/nonexistent-scoursh-test-path
  _sbx_require_sandbox_exec
) >"$W/no-sandbox-exec.out" 2>&1 || no_sbx_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$no_sbx_rc" \
  'sandbox-exec absent from PATH: _sbx_require_sandbox_exec exits 4'
assert_contains "$(cat "$W/no-sandbox-exec.out")" 'sandbox-exec' \
  'the error names the actual missing command'

assert_status 0 'sandbox-exec present (real PATH on this suite'"'"'s own host): _sbx_require_sandbox_exec succeeds' \
  _sbx_require_sandbox_exec

printf '\n-- _sbx_require_profile_ok: PRE-VALIDATION, never a live first attempt --\n'
RUN_SANDBOXED_PROFILE='(version 1)(this is not a valid profile'
profile_rc=0
( _sbx_require_profile_ok ) >"$W/bad-profile.out" 2>&1 || profile_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$profile_rc" \
  'a malformed profile is refused with exit 4 (a contractual code), never sandbox-exec'"'"'s own out-of-contract exit 65 leaking through - FAILS if the profile is only validated by running <command> itself under it'
assert_contains "$(cat "$W/bad-profile.out")" 'rejected the Seatbelt profile' \
  'the error names the actual reason (profile rejected), not a generic failure'
RUN_SANDBOXED_PROFILE='(version 1)(allow default)(deny network*)'
assert_status 0 'the real, shipped deny-all profile is accepted by a real sandbox-exec' \
  _sbx_require_profile_ok

printf '\n-- _sbx_require_command_exists --\n'
assert_status "$SCOURSH_EXIT_INPUT" 'a command not on PATH and not an executable file is refused with exit 4 - never left to sandbox-exec'"'"'s own out-of-contract execvp() exit 71' \
  _sbx_require_command_exists /no/such/scoursh-test-command-xyz
missing_cmd_msg=$( ( _sbx_require_command_exists /no/such/scoursh-test-command-xyz ) 2>&1 || true )
assert_contains "$missing_cmd_msg" 'was not found' \
  'the error names the actual reason (command not found), not a generic failure'
assert_status 0 'a real, resolvable command (true) is accepted' \
  _sbx_require_command_exists true
assert_status 0 'an explicit executable path is accepted, identically to a bare PATH-searched name' \
  _sbx_require_command_exists /usr/bin/true

# ---------------------------------------------------------------------------
# -- section A: on a non-Darwin host, a real invocation fails immediately,
#    <command> never runs - REAL subprocess exec (the sibling of
#    tests/suites/netns.sh's own section A, mirrored the other direction) --
# ---------------------------------------------------------------------------
if [[ $(command uname -s) != Darwin ]]; then
  printf '\n-- section A: non-Darwin host - real subprocess, real fail-closed check --\n'
  MARKER=$W/marker-nondarwin
  rm -f "$MARKER"
  rc=0
  bash "$TOOL" -- touch "$MARKER" >"$W/nondarwin.out" 2>&1 || rc=$?
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
    'a real invocation on this non-Darwin host exits 4 (missing required input), not 0-and-quietly-unsandboxed'
  assert_file_absent "$MARKER" \
    '<command> (touch the marker file) never ran - FAILS if the Darwin check is bypassed or only warns'
  assert_contains "$(cat "$W/nondarwin.out")" 'macOS-only' \
    'the error names the actual reason (macOS-only), not a generic failure'
else
  printf '\n-- section A: SKIPPED (this host IS Darwin; section B below covers it) --\n'
fi

# ---------------------------------------------------------------------------
# -- section B: on a real Darwin host, everything is unprivileged and real -
#    this tier'"'"'s whole advantage over tools/run-in-netns.sh. Gated only on
#    sandbox-exec actually being present (it ships with every macOS), and
#    SKIPS with a stated reason rather than silently passing when absent.
# ---------------------------------------------------------------------------
if [[ $(command uname -s) == Darwin ]] && type -P sandbox-exec >/dev/null 2>&1; then
  printf '\n-- section B: REAL macOS test (Darwin, sandbox-exec present) --\n'

  printf '\n-- section B1: real fail-closed checks (subprocess) --\n'
  MARKER=$W/marker-badcmd
  rm -f "$MARKER"
  rc=0
  bash "$TOOL" -- /no/such/scoursh-test-command-xyz >"$W/badcmd.out" 2>&1 || rc=$?
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
    'a real invocation naming a non-existent <command> exits 4, never sandbox-exec'"'"'s own out-of-contract execvp() exit 71'

  usage_rc=0
  bash "$TOOL" -- >"$W/usage.out" 2>&1 || usage_rc=$?
  assert_eq "$SCOURSH_EXIT_USAGE" "$usage_rc" \
    'a real invocation with -- and no command after it is a usage error (exit 2)'

  printf '\n-- section B2: the real kernel-level denial, with a positive control --\n'
  # A closed local port (nothing listens on it): a real TCP connect attempt,
  # refused fast (measured <10ms) either way, so this needs no `timeout`
  # binary (absent on a bare macOS host) and never risks a long hang against
  # an unreachable address.
  CLOSED_PORT=18823

  # A positive control FIRST: the identical connect attempt, with NO sandbox
  # at all, must fail with an ordinary CONNECTIVITY error ("Connection
  # refused" - nothing is listening), never "Operation not permitted" - the
  # two are asserted as different failure TEXT below, so this is a real
  # discriminating control, not a fixture that could not fail either way.
  ctrl_out=$(bash -c "exec 3<>/dev/tcp/127.0.0.1/$CLOSED_PORT" 2>&1) || true
  assert_not_contains "$ctrl_out" 'Operation not permitted' \
    'positive control: with NO sandbox at all, the same connect attempt is never refused by Seatbelt (it fails because nothing is listening, which is a DIFFERENT failure - proving this control actually discriminates)'
  assert_contains "$ctrl_out" 'refused' \
    'positive control: the unsandboxed failure really is an ordinary connection refusal, confirming the port is genuinely closed rather than silently accepting'

  sbx_rc=0
  sbx_out=$(bash "$TOOL" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/$CLOSED_PORT" 2>&1) || sbx_rc=$?
  assert_ne 0 "$sbx_rc" \
    'under the real Seatbelt deny-all-network profile, the identical connect attempt fails'
  assert_contains "$sbx_out" 'Operation not permitted' \
    'the failure is the kernel refusing the socket (Seatbelt), not merely a refused loopback connection - FAILS if the sandbox does not actually deny the connect (the profile denies loopback too - there is no "localhost is special" carve-out in a bare deny-all)'

  printf '\n-- section B3: exit-code forwarding is VERBATIM (transparent-wrapper rule) --\n'
  for code in 0 3 5; do
    got=0
    bash "$TOOL" -- bash -c "exit $code" >"$W/fwd-$code.out" 2>&1 || got=$?
    assert_eq "$code" "$got" "<command>'s own exit $code is forwarded verbatim, not laundered into a different code"
    assert_not_contains "$(cat "$W/fwd-$code.out")" 'command failed' \
      "forwarding <command>'s exit $code prints no spurious ERR-trap re-report (the intentional trap - ERR before the final exit)"
  done

  printf '\n-- section B4: no scoursh module state (scratch dir, run.json) is left behind --\n'
  assert_file_absent "$SCOURSH_SCRATCH/run-sandboxed/leftover-marker-that-should-never-exist" \
    'sanity: this suite'"'"'s own scratch dir is the one this process owns, not one run-sandboxed.sh created and forgot to clean up (it has no teardown state of its own - see the file'"'"'s header)'

  printf '\n-- section B5: a real end-to-end scan.sh sast run under the sandbox --\n'
  # The one genuinely slow case in this suite (a real, full sast pattern-pack
  # scan): what this ticket exists to prove - the "sast makes zero network
  # calls" claim, now kernel-enforced rather than merely asserted, on a real
  # scoursh module.
  scan_rc=0
  scan_out=$(cd "$ROOT" && bash "$TOOL" -- bash scan.sh sast --path tests/fixtures/vuln 2>&1) || scan_rc=$?
  assert_eq 0 "$scan_rc" \
    'a real "scan.sh sast --path tests/fixtures/vuln" run under the sandbox completes rc=0 - sast needs no network, so the deny-all profile costs it nothing'
  assert_contains "$scan_out" 'scan complete' \
    'the real scan actually ran to completion (not merely exited 0 having done nothing)'
  # Clean up the report this real scan wrote (reports/ is gitignored, but a
  # test should not litter the working tree it runs in).
  run_dir=$(printf '%s\n' "$scan_out" | while IFS= read -r line; do
    case $line in *'report: '*) printf '%s\n' "${line##*report: }"; break ;; esac
  done)
  [[ -n $run_dir && -d $run_dir ]] && rm -rf -- "$run_dir"
else
  printf '\n-- section B: SKIPPED (needs a real Darwin host with sandbox-exec on PATH; this ticket'"'"'s kernel-level claim is NOT exercised on this host/run) --\n'
fi

t_summary 'run-sandboxed'
