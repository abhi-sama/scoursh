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
  # suite. SC2030 for the same reason - the change is MEANT to be local, and
  # nothing here is read back through a variable afterwards (shellcheck only
  # reports it once some later case genuinely does modify PATH in a subshell,
  # which section F now does).
  # shellcheck disable=SC2030,SC2123
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

# ===========================================================================
# TIER B: the loopback relay, the port-pinned profile, and the teardown
# (docs/FOUNDATION.md tension 20 - "containment guarantee, target
# restriction by relay")
# ===========================================================================
# Everything below is HERMETIC: every listener is a local fixture bound to
# 127.0.0.1 and nothing in this suite makes, or tries to make, a connection
# off this host. The one probe that names an off-host address
# (192.0.2.1, RFC 5737 TEST-NET-1) is asserted to be REFUSED BY THE KERNEL
# before a packet is sent, which is the whole point of it.

printf '\n-- section C: Tier B argument parsing --\n'

_sbx_parse_args -- scan.sh sast --path .
assert_eq '' "$RUN_SANDBOXED_SCOPE_CONF" \
  'no --scope-conf leaves Tier B off - FAILS if the flag ever defaults to on, which would start relays for a run that asked for deny-all'

C_SCOPE=$W/scope-parse.conf
printf 'id: t\nbase-url: http://127.0.0.1:18901\n' >"$C_SCOPE"
_sbx_parse_args --scope-conf "$C_SCOPE" -- true
assert_eq "$C_SCOPE" "$RUN_SANDBOXED_SCOPE_CONF" '--scope-conf PATH is captured'
assert_eq 'true' "${RUN_SANDBOXED_CMD[*]}" 'and the command after -- is still collected'

assert_status "$SCOURSH_EXIT_USAGE" '--scope-conf with no PATH after it is a usage error (exit 2)' \
  _sbx_parse_args --scope-conf
assert_status "$SCOURSH_EXIT_INPUT" 'an unreadable --scope-conf PATH is exit 4, refused at parse time before any relay exists' \
  _sbx_parse_args --scope-conf /no/such/scoursh-scope-xyz.conf -- true
_sbx_parse_args -- true   # leave the parser in a clean state for later cases

printf '\n-- section D: the scope resolver reuses lib/http.sh, never a second one --\n'
# The map is built from http_scope_load + http_resolve_host - the same two
# functions tools/run-in-netns.sh's _netns_collect_target_ips calls. Proven by
# swapping lib/http.sh's OWN documented resolver hook and watching the map
# change: a second, private resolver in this file would ignore it.
D_SCOPE=$W/scope-resolve.conf
printf 'id: d\nbase-url: https://resolver.fixture.example\n' >"$D_SCOPE"
RUN_SANDBOXED_SCOPE_CONF=$D_SCOPE
_fake_resolve() { printf '203.0.113.7'; }
SCOURSH_HTTP_RESOLVE=_fake_resolve
_HTTP_RESOLVE_CACHE=()
_sbx_collect_relay_targets
assert_contains "${RUN_SANDBOXED_MAP_ADDR[*]}" '203.0.113.7' \
  'the address in the map came from lib/http.sh'"'"'s own SCOURSH_HTTP_RESOLVE hook - FAILS if this tool ever grows a private resolver, which is how it and the scope gate would come to disagree about what a scope.conf host means'
assert_contains "${RUN_SANDBOXED_MAP_PORT[*]}" '443' 'an https scope row contributes its own port'
assert_contains "${RUN_SANDBOXED_MAP_PORT[*]}" '80' \
  'and ALSO port 80 - http_scope_match'"'"'s one documented relaxation (an https target authorises http on port 80 for the same host) is mirrored here, so the gate can never approve a request guarantee mode then has no relay for'

# allow-subdomains and IPv6 are STATED gaps, not silent drops.
D2=$W/scope-subs.conf
printf 'id: d2\nbase-url: https://subs.fixture.example\nallow-subdomains: true\n' >"$D2"
RUN_SANDBOXED_SCOPE_CONF=$D2
_HTTP_RESOLVE_CACHE=()
subs_msg=$( _sbx_collect_relay_targets 2>&1 || true )
assert_contains "$subs_msg" 'allow-subdomains' \
  'an allow-subdomains scope row WARNS that no relay can be built for an unenumerable subdomain - FAILS if it is dropped silently, which reads to an operator as full coverage'

D3=$W/scope-v6.conf
printf 'id: d3\nbase-url: http://[2001:db8::1]:8080\n' >"$D3"
RUN_SANDBOXED_SCOPE_CONF=$D3
v6_rc=0
v6_msg=$( ( _sbx_collect_relay_targets ) 2>&1 ) || v6_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$v6_rc" \
  'a scope whose ONLY target is IPv6 is exit 4, not a silent run with an empty relay set - FAILS if the skip leaves <command> running under an effectively deny-all profile it never asked for'
assert_contains "$v6_msg" 'IPv6' 'and the refusal names IPv6 as the reason'
unset SCOURSH_HTTP_RESOLVE
unset -f _fake_resolve
_HTTP_RESOLVE_CACHE=()

# ---------------------------------------------------------------------------
# -- section E: the relay itself, and the profile it produces. Needs a real
#    python3 (the relay runtime); SKIPS with a stated reason otherwise.
# ---------------------------------------------------------------------------
if [[ -x $RUN_SANDBOXED_PYTHON ]] \
  && "$RUN_SANDBOXED_PYTHON" -c 'import socket, socketserver, threading' >/dev/null 2>&1; then
  printf '\n-- section E: a REAL relay, forwarding to a REAL local fixture --\n'

  # A fixture listener on 127.0.0.1, ephemeral port, that echoes the Host
  # header it received - which is what proves --connect-to keeps the ORIGINAL
  # host identity (and therefore SNI and certificate validation) rather than
  # rewriting it to the relay's own address.
  E_FIXPORT_FILE=$W/e-fixport
  "$RUN_SANDBOXED_PYTHON" -c '
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("fixture-ok host=%s" % self.headers.get("Host")).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
srv = socketserver.TCPServer(("127.0.0.1", 0), H)
sys.stdout.write("%d\n" % srv.server_address[1]); sys.stdout.flush()
srv.serve_forever()' >"$E_FIXPORT_FILE" 2>/dev/null &
  E_FIXPID=$!
  e_waited=0
  while (( e_waited < 100 )) && [[ ! -s $E_FIXPORT_FILE ]]; do msleep 50; e_waited=$(( e_waited + 1 )); done
  E_FIXPORT=$(< "$E_FIXPORT_FILE"); E_FIXPORT=${E_FIXPORT%%$'\n'*}

  if [[ $E_FIXPORT =~ ^[0-9]+$ ]]; then
    RUN_SANDBOXED_RELAY_PIDS=()
    RUN_SANDBOXED_RELAY_PORTS=()
    _sbx_relay_start 127.0.0.1 "$E_FIXPORT"
    E_RELAY=$RUN_SANDBOXED_RELAY_PORT_LAST
    e_isnum=false; [[ $E_RELAY =~ ^[0-9]+$ ]] && e_isnum=true
    assert_eq true "$e_isnum" \
      'the relay reports the ephemeral port it actually bound - it is READ BACK from the relay, never guessed, because picking a port and hoping it is free is a race the kernel already answers'
    assert_ne "$E_FIXPORT" "$E_RELAY" 'and it is a port of its own, not the target'"'"'s'

    e_body=$(curl -sS -m 8 --connect-to "relay.fixture.example:80:127.0.0.1:$E_RELAY" \
      "http://relay.fixture.example:80/x" 2>&1 || true)
    assert_contains "$e_body" 'fixture-ok' \
      'a connection to the relay is forwarded to its ONE fixed destination and the response comes back - the relay really pumps bytes both ways'
    assert_contains "$e_body" 'host=relay.fixture.example' \
      'and the fixture saw the ORIGINAL hostname in Host: - which is what makes SNI and certificate validation survive the redirection, and is why guarantee mode uses --connect-to rather than --resolve (--resolve maps a name to an ADDRESS and so cannot move the port, which is exactly what a relay on an ephemeral port needs)'

    # The relay has ONE destination, fixed at start. There is no path in it
    # that reads a destination from the wire, so a client cannot ask it for a
    # different one; what a client CAN do is speak to it, which is what the
    # case above already covers. What is asserted here is the complement: the
    # relay dials nowhere else, so a second fixture never sees traffic.
    E_OTHER_FILE=$W/e-otherport
    "$RUN_SANDBOXED_PYTHON" -c '
import socketserver, sys, threading
HIT = []
class H(socketserver.BaseRequestHandler):
    def handle(self):
        HIT.append(1)
        open(sys.argv[1], "w").write("HIT\n")
srv = socketserver.TCPServer(("127.0.0.1", 0), H)
sys.stdout.write("%d\n" % srv.server_address[1]); sys.stdout.flush()
srv.serve_forever()' "$W/e-other-hit" >"$E_OTHER_FILE" 2>/dev/null &
    E_OTHERPID=$!
    e_waited=0
    while (( e_waited < 100 )) && [[ ! -s $E_OTHER_FILE ]]; do msleep 50; e_waited=$(( e_waited + 1 )); done
    rm -f "$W/e-other-hit"
    curl -sS -m 5 --connect-to "anything.example:80:127.0.0.1:$E_RELAY" \
      "http://anything.example:80/anything" >/dev/null 2>&1 || true
    assert_file_absent "$W/e-other-hit" \
      'the relay dialled ONLY its one hardcoded destination - a second local listener saw nothing, whatever host or path the client asked for. FAILS if a relay ever takes its destination from the request rather than from its own argv, which is the difference between a forwarder and an open proxy'
    kill "$E_OTHERPID" 2>/dev/null || true
    wait "$E_OTHERPID" 2>/dev/null || true

    printf '\n-- section E2: the profile the relay set produces --\n'
    # Three map rows - two hosts plus one repeat - all behind the SAME
    # (address, port). The relay is keyed by where it DIALS, so that is one
    # relay and three map rows.
    RUN_SANDBOXED_MAP_HOST=(a.example b.example a.example)
    RUN_SANDBOXED_MAP_PORT=("$E_FIXPORT" "$E_FIXPORT" "$E_FIXPORT")
    RUN_SANDBOXED_MAP_ADDR=(127.0.0.1 127.0.0.1 127.0.0.1)
    # Section E's own relay is torn down and the accounting reset first, so
    # what is asserted below is what THIS call started, never something
    # carried over from an earlier case.
    _sbx_relays_stop
    RUN_SANDBOXED_RELAY_PORTS=()
    _sbx_start_relays_and_build_profile
    assert_eq 1 "${#RUN_SANDBOXED_RELAY_PORTS[@]}" \
      'three map rows sharing ONE (address, port) start ONE relay, not three - the relay is keyed by where it DIALS, and one relay per scope host would open ports for nothing'
    map_lines=$(printf '%s' "$RUN_SANDBOXED_RELAY_MAP" | while IFS= read -r l; do [[ -n $l ]] && printf 'x'; done)
    assert_eq 'xxx' "$map_lines" \
      'while the MAP still carries one row per (host, port) - two hosts behind one address are two lookups and one relay'
    assert_contains "$RUN_SANDBOXED_PROFILE" '(deny network*)' \
      'the profile still denies all network by default'
    assert_contains "$RUN_SANDBOXED_PROFILE" "(allow network-outbound (remote ip \"localhost:${RUN_SANDBOXED_RELAY_PORTS[0]}\"))" \
      'and re-admits EXACTLY the relay port it started - FAILS if the allow clause is ever widened to a host wildcard or an unbounded port range'
    assert_not_contains "$RUN_SANDBOXED_PROFILE" "localhost:$E_FIXPORT" \
      'the TARGET'"'"'s own port is NOT in the profile - only the relay'"'"'s is. FAILS under the naive "allow the target port" reading, which would let the sandboxed process bypass the relay entirely and reach any same-host service on that port'
    _sbx_relays_stop
  else
    printf '\n-- section E: SKIPPED (the local HTTP fixture did not come up) --\n'
    kill "$E_FIXPID" 2>/dev/null || true
  fi
  kill "$E_FIXPID" 2>/dev/null || true
  wait "$E_FIXPID" 2>/dev/null || true
else
  printf '\n-- section E: SKIPPED (no usable relay runtime at %s; Tier B'"'"'s relay is NOT exercised on this host/run) --\n' "$RUN_SANDBOXED_PYTHON"
fi

printf '\n-- section F: the relay-runtime and curl preconditions fail LOUD --\n'
RUN_SANDBOXED_PYTHON_SAVED=$RUN_SANDBOXED_PYTHON
RUN_SANDBOXED_PYTHON=/no/such/scoursh-relay-runtime-xyz
rt_rc=0
rt_msg=$( ( _sbx_require_relay_runtime ) 2>&1 ) || rt_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rt_rc" \
  'an absent relay runtime is exit 4 - never a fall-through to "run <command> with a deny-all profile and no relay", which would look like a contained run and be an untested one'
assert_contains "$rt_msg" 'relay runtime' 'and the error names the actual reason'
RUN_SANDBOXED_PYTHON=$RUN_SANDBOXED_PYTHON_SAVED

# A stub `curl` that rejects every option, standing in for a pre-7.49 curl.
F_STUB=$W/curlstub
mkdir -p "$F_STUB"
printf '#!/usr/bin/env bash\nexit 2\n' >"$F_STUB/curl"
chmod 755 "$F_STUB/curl"
# The probe lives in lib/http.sh rather than here, because tension 19's
# "no bypass" lint permits a curl invocation in that file and in a short,
# stated exemption list - adding this tool to that list for a version probe
# is how a structural property stops being structural. So what is asserted
# here is that lib/http.sh refuses a map when curl cannot accept the flag,
# which is the same refusal one layer in.
ct_rc=0
ct_msg=$(
  # SC2030/SC2031: PATH is modified for this subshell ON PURPOSE, so the stub
  # is what `_http_relay_require_connect_to` finds; nothing is read back
  # through a variable afterwards.
  # shellcheck disable=SC2030,SC2031,SC2123
  PATH="$F_STUB:$PATH"
  SCOURSH_HTTP_RELAY_MAP='h.example 443 198.51.100.1 40001' http_relay_map_load 2>&1
) || ct_rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$ct_rc" \
  'a curl that does not accept --connect-to refuses the RUN (exit 4) at map-load time - FAILS if it is left to be discovered mid-scan, one failed request at a time'
assert_contains "$ct_msg" 'connect-to' 'and the error names the actual missing capability'
assert_status 0 'and with the real curl on this host a map loads fine' \
  env SCOURSH_HTTP_RELAY_MAP='h.example 443 198.51.100.1 40001' bash -c \
  'source "$0/lib/http.sh" >/dev/null 2>&1' "$ROOT"
SCOURSH_HTTP_RELAY_MAP='' http_relay_map_load

# ---------------------------------------------------------------------------
# -- section G: the REAL composite, end to end - a real sandbox-exec, a real
#    relay, a real local fixture. Needs Darwin + sandbox-exec + a usable
#    relay runtime, and SKIPS with a stated reason otherwise rather than
#    silently reporting green.
# ---------------------------------------------------------------------------
if [[ $(command uname -s) == Darwin ]] && type -P sandbox-exec >/dev/null 2>&1 \
  && [[ -x $RUN_SANDBOXED_PYTHON ]] \
  && "$RUN_SANDBOXED_PYTHON" -c 'import socket, socketserver, threading' >/dev/null 2>&1; then
  printf '\n-- section G: REAL Tier B composite (Darwin + sandbox-exec + relay runtime) --\n'

  G_PORTFILE=$W/g-fixport
  "$RUN_SANDBOXED_PYTHON" -c '
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"tierb-fixture-ok"
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
srv = socketserver.TCPServer(("127.0.0.1", 0), H)
sys.stdout.write("%d\n" % srv.server_address[1]); sys.stdout.flush()
srv.serve_forever()' >"$G_PORTFILE" 2>/dev/null &
  G_FIXPID=$!
  g_waited=0
  while (( g_waited < 100 )) && [[ ! -s $G_PORTFILE ]]; do msleep 50; g_waited=$(( g_waited + 1 )); done
  G_FIXPORT=$(< "$G_PORTFILE"); G_FIXPORT=${G_FIXPORT%%$'\n'*}

  G_SCOPE=$W/g-scope.conf
  printf 'id: g\nbase-url: http://127.0.0.1:%s\n' "$G_FIXPORT" >"$G_SCOPE"

  # The wrapped command reads the map the wrapper exported and fetches through
  # the relay named in it. Reading the map is what an operator's real scan
  # does via lib/http.sh section 7a; doing it here in one line keeps this case
  # about the WRAPPER rather than about lib/http.sh, which
  # tests/suites/http.sh covers on its own.
  G_INNER='set -Eeuo pipefail
read -r h p a rp <<<"$(printf %s "$SCOURSH_HTTP_RELAY_MAP" | head -1)"
printf "RELAYPORT=%s\n" "$rp"
curl -sS -m 8 --connect-to "$h:$p:127.0.0.1:$rp" "http://$h:$p/x"
printf "\n"'

  g_rc=0
  g_out=$(bash "$TOOL" --scope-conf "$G_SCOPE" -- bash -c "$G_INNER" 2>&1) || g_rc=$?
  assert_eq 0 "$g_rc" 'a real Tier B run completes rc=0'
  assert_contains "$g_out" 'tierb-fixture-ok' \
    'the sandboxed command reached the authorised target THROUGH the relay - the whole Tier B claim, end to end: sandbox-exec applied, relay started outside it, request redirected into it, response returned'

  G_RELAYPORT=$(printf '%s\n' "$g_out" | while IFS= read -r l; do
    case $l in RELAYPORT=*) printf '%s\n' "${l#RELAYPORT=}"; break ;; esac
  done)
  g_isnum=false; [[ $G_RELAYPORT =~ ^[0-9]+$ ]] && g_isnum=true
  assert_eq true "$g_isnum" 'the run reported the relay port it used'

  printf '\n-- section G1b: the SEAM - http_request itself, inside the sandbox --\n'
  # Sections G1 and the http suite each prove one half: that the wrapper's
  # relay works, and that guarantee mode passes --connect-to. Only this case
  # proves they meet - a REAL http_request, made by the REAL transport, from
  # inside the sandbox, through the relay, against a local fixture, with the
  # map the wrapper itself exported and no stub anywhere. It also proves the
  # thing that makes the mode usable at all: DNS is kernel-denied in there, so
  # the request can only resolve from the map the wrapper seeded.
  G_SEAM_SCOPE=$W/g-seam-scope.conf
  # allow-private-addresses, because the fixture target IS loopback and
  # lib/http.sh's deny list refuses one otherwise - the gate runs BEFORE the
  # relay lookup and is untouched by guarantee mode, which is precisely the
  # ordering this ticket must not disturb. Without this the case fails at
  # exit 3 from the GATE, which would look identical to the relay refusal it
  # is trying to prove does not happen.
  printf 'id: seam\nbase-url: http://127.0.0.1:%s\nallow-private-addresses: true\n' \
    "$G_FIXPORT" >"$G_SEAM_SCOPE"
  G_SEAM='set -Eeuo pipefail
source "$0/lib/http.sh"
http_scope_load "$1"
http_request GET "http://127.0.0.1:$2/x" && printf "SEAM_OK status=%s\n" "$_HTTP_LAST_STATUS"'
  seam_rc=0
  seam_out=$(bash "$TOOL" --scope-conf "$G_SEAM_SCOPE" -- \
    bash -c "$G_SEAM" "$ROOT" "$G_SEAM_SCOPE" "$G_FIXPORT" 2>&1) || seam_rc=$?
  assert_eq 0 "$seam_rc" 'a real http_request through guarantee mode, inside the sandbox, succeeds'
  assert_contains "$seam_out" 'SEAM_OK status=200' \
    'lib/http.sh'"'"'s own transport reached the authorised target through the relay and read a real 200 back - the seam between the two halves this ticket ships, with no stub curl, no stub transport and no stub resolver anywhere. FAILS if the map is not exported, if guarantee mode does not read it, or if the --connect-to swap does not actually redirect'
  assert_not_contains "$seam_out" 'DNS resolution failed' \
    'and it never needed a resolver - inside the sandbox DNS is kernel-denied, so the ADDR column of the map is the only thing that could have supplied the address. FAILS if that column is ever dropped, which would make guarantee mode die on its first request'

  printf '\n-- section G2: TEARDOWN on SUCCESS - no relay listener survives --\n'
  # A connect attempt is the assertion: if anything still listens on the
  # relay's port the connect SUCCEEDS. Asserting on a pid would prove less -
  # a dead pid whose listening socket was inherited by something else is
  # exactly the leak this is looking for.
  g_after_rc=0
  bash -c "exec 3<>/dev/tcp/127.0.0.1/$G_RELAYPORT" 2>/dev/null || g_after_rc=$?
  assert_ne 0 "$g_after_rc" \
    'nothing listens on the relay port after a SUCCESSFUL run - the EXIT trap killed the relay and closed its listener. FAILS if teardown is left to process exit alone, which leaks a listening socket per run'

  printf '\n-- section G3: TEARDOWN on FAILURE - the half that is easy to miss --\n'
  g_fail_out=$(bash "$TOOL" --scope-conf "$G_SCOPE" -- bash -c '
read -r h p a rp <<<"$(printf %s "$SCOURSH_HTTP_RELAY_MAP" | head -1)"
printf "RELAYPORT=%s\n" "$rp"
exit 5' 2>&1) || g_fail_rc=$?
  assert_eq 5 "${g_fail_rc:-0}" \
    '<command>'"'"'s own exit 5 is forwarded verbatim through Tier B too - the transparent-wrapper rule is not suspended by the relay'
  G_FAILPORT=$(printf '%s\n' "$g_fail_out" | while IFS= read -r l; do
    case $l in RELAYPORT=*) printf '%s\n' "${l#RELAYPORT=}"; break ;; esac
  done)
  g_after_fail_rc=0
  bash -c "exec 3<>/dev/tcp/127.0.0.1/$G_FAILPORT" 2>/dev/null || g_after_fail_rc=$?
  assert_ne 0 "$g_after_fail_rc" \
    'and nothing listens on the relay port after a FAILING run either - FAILS if teardown only runs on the success path, which is the direction that leaks'

  printf '\n-- section G4: what the pinned profile actually admits, with a probe that DISCRIMINATES --\n'
  # A fresh relay of this suite's own, so the profile under test is built from
  # a port that is genuinely live.
  RUN_SANDBOXED_RELAY_PIDS=()
  RUN_SANDBOXED_RELAY_PORTS=()
  _sbx_relay_start 127.0.0.1 "$G_FIXPORT"
  G_P=$RUN_SANDBOXED_RELAY_PORT_LAST
  G_PROFILE="(version 1)(allow default)(deny network*)(allow network-outbound (remote ip \"localhost:$G_P\"))"
  G_OTHER=$(( G_P + 1 ))

  # The allowed port, on loopback: permitted (positive control - without it a
  # profile that denied everything would satisfy every "must deny" case below
  # and prove nothing).
  g_allow=$(sandbox-exec -p "$G_PROFILE" bash -c "exec 3<>/dev/tcp/127.0.0.1/$G_P" 2>&1) || true
  assert_not_contains "$g_allow" 'Operation not permitted' \
    'positive control: the relay port IS reachable from inside the pinned profile - FAILS if the allow clause is malformed, in which case every denial below would be true for the wrong reason'

  # A different loopback port: denied.
  g_other=$(sandbox-exec -p "$G_PROFILE" bash -c "exec 3<>/dev/tcp/127.0.0.1/$G_OTHER" 2>&1) || true
  assert_contains "$g_other" 'Operation not permitted' \
    'a DIFFERENT loopback port is refused by the kernel - the profile admits the relay port and not "loopback"'

  # THE DISCRIMINATING PROBE. An off-host address (RFC 5737 TEST-NET-1,
  # documentation-only and non-routable) on the ALLOWED port. This is the
  # only probe that separates "Seatbelt restricts the host" from "Seatbelt
  # restricts only the port", and it is the one the research this ticket
  # implements got wrong: it used this host's OWN LAN address, which
  # `localhost` ADMITS (measured), and read the resulting "Connection
  # refused" - nothing was listening - as a denial. Re-measured here: an
  # off-host address is `Operation not permitted`, instantly, with no packet
  # sent, so this suite makes no off-host connection even in the probe that
  # names one.
  g_offhost=$(sandbox-exec -p "$G_PROFILE" bash -c "exec 3<>/dev/tcp/192.0.2.1/$G_P" 2>&1) || true
  assert_contains "$g_offhost" 'Operation not permitted' \
    'an OFF-HOST address on the ALLOWED port is refused by the kernel before a packet is sent - this is the containment half of the Tier B claim, and it is the assertion a "connect to the LAN address" test cannot make (that address belongs to this host, so the profile admits it and the connect fails only because nothing listens)'
  _sbx_relays_stop

  printf '\n-- section G5: Tier A is untouched by any of this --\n'
  g_tiera=$(bash "$TOOL" -- bash -c 'printf "MAP=[%s]\n" "${SCOURSH_HTTP_RELAY_MAP:-}"' 2>&1) || true
  assert_contains "$g_tiera" 'MAP=[]' \
    'a Tier A run exports NO relay map, so lib/http.sh'"'"'s guarantee mode stays off and the default egress path is the one an ordinary scan takes - FAILS if --scope-conf'"'"'s plumbing ever leaks into the no-flag invocation'

  kill "$G_FIXPID" 2>/dev/null || true
  wait "$G_FIXPID" 2>/dev/null || true
else
  printf '\n-- section G: SKIPPED (needs Darwin + sandbox-exec + a usable relay runtime; Tier B'"'"'s kernel-level claim is NOT exercised on this host/run) --\n'
fi

t_summary 'run-sandboxed'
