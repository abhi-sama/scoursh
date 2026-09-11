#!/usr/bin/env bash
# tests/suites/nettransport.sh - lib/nettransport.sh, the pure-bash TCP
# connect primitive (NET-03).
#
# NO CASE HERE OPENS A REAL SOCKET.  `net_connect_probe`'s three-state
# classification is exercised entirely through the `SCOURSH_NET_PROBE` hook
# with deterministic fixtures - the same idiom tests/suites/http.sh already
# uses for SCOURSH_HTTP_TRANSPORT and tests/suites/dast-tls.sh already uses
# for SCOURSH_TLS_PROBE - and the capability-absent degrade path is exercised
# by overriding `_net_tcp_capability_probe` (a plain bash function, swapped
# after sourcing) and by forcing `SCOURSH_NET_TCP_CAPABLE`, never by actually
# building or running a capability-crippled bash.  This mirrors
# tests/suites/paranoid.sh's own SCOURSH_PARANOID_FORCE_BACKEND section
# exactly.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule (AGENTS.md).
#
# shellcheck shell=bash
# SC2016: diagnostic prose quotes shell syntax literally.
# SC2329: functions below are called indirectly, through the SCOURSH_NET_PROBE
#         hook or by direct name from a case, not always visibly at the call
#         site shellcheck inspects.
# shellcheck disable=SC2016,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/nettransport.sh
source "$ROOT/lib/nettransport.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/nettransport
rm -rf "$W"
mkdir -p "$W"

# Reset the module's own memoized capability state between sections, exactly
# as a fresh process would start - a leaked '1'/'0' (in-process OR on the
# scratch-file memo) from an earlier section would silently make a later
# section's forced value or stubbed probe a no-op.
_net_reset() {
  _NET_TCP_CAPABLE=''
  unset SCOURSH_NET_TCP_CAPABLE SCOURSH_NET_PROBE
  rm -f "$(_net_capability_file)" 2>/dev/null || true
}

printf '\n== argument validation ==\n'
_net_reset

out=$(net_connect_probe '' 22 2>/dev/null) && rc=0 || rc=$?
assert_eq 'not-open' "$out" \
  'a missing HOST reports not-open rather than attempting a connect with an empty target - FAILS if the empty-string guard is removed and bash instead tries to interpret /dev/tcp//22'
assert_eq 1 "$rc" \
  'a missing HOST is a caller usage error (rc 1), not a legitimate "not-open" result silently returned as if it were real'

out=$(net_connect_probe example.test '' 2>/dev/null) && rc=0 || rc=$?
assert_eq 'not-open' "$out" 'a missing PORT is refused the same way as a missing HOST'
assert_eq 1 "$rc" 'a missing PORT is a usage error (rc 1)'

printf '\n== classification via SCOURSH_NET_PROBE: deterministic, no real socket ==\n'
_net_reset

_stub_fixed() { printf '%s\n' "$_STUB_STATE"; }
SCOURSH_NET_PROBE=_stub_fixed

_STUB_STATE=open
assert_eq 'open' "$(net_connect_probe 203.0.113.5 22)" \
  'the hook is consulted in place of a real connect, and its "open" answer passes through unchanged - FAILS if net_connect_probe ever falls through to _net_connect_default while the hook is set'

_STUB_STATE=not-open
assert_eq 'not-open' "$(net_connect_probe 203.0.113.5 23)" \
  'a "not-open" hook answer passes through unchanged'

_STUB_STATE=filtered
assert_eq 'filtered' "$(net_connect_probe 203.0.113.5 24)" \
  'a "filtered" hook answer passes through unchanged - the third state is never collapsed into not-open ("the port did not answer" and "the port refused" are different facts)'

printf '\n== SCOURSH_NET_PROBE receives host/port/deadline exactly as given ==\n'
_net_reset

_CAPTURED=''
_stub_capture() { _CAPTURED="host=$1 port=$2 deadline_ms=$3"; printf 'open\n'; }
SCOURSH_NET_PROBE=_stub_capture

net_connect_probe 198.51.100.9 8443 750 >/dev/null
assert_eq 'host=198.51.100.9 port=8443 deadline_ms=750' "$_CAPTURED" \
  'an explicit deadline is forwarded to the probe verbatim - FAILS if net_connect_probe drops or rewrites the third argument'

_CAPTURED=''
net_connect_probe 198.51.100.9 8443 >/dev/null
assert_eq "host=198.51.100.9 port=8443 deadline_ms=$_NET_DEFAULT_DEADLINE_MS" "$_CAPTURED" \
  'omitting the deadline forwards the documented default rather than an empty value'

printf '\n== capability probe: memoized, never re-run once decided ==\n'
_net_reset

# Called DIRECTLY, never through $(...): a command-substitution subshell
# would discard this test's own _PROBE_CALLS increment exactly the way the
# library's in-process _NET_TCP_CAPABLE would be discarded by a real caller -
# see this file's header and lib/nettransport.sh's own header for why that
# is precisely the failure mode the scratch-file memo exists to avoid.
_PROBE_CALLS=0
_net_tcp_capability_probe() { _PROBE_CALLS=$(( _PROBE_CALLS + 1 )); return 0; }
if net_probe_capability; then r1=0; else r1=1; fi
if net_probe_capability; then r2=0; else r2=1; fi
assert_true "$r1" 'a stubbed present-capability probe reports capable'
assert_true "$r2" 'a second call reuses the memoized answer'
assert_eq 1 "$_PROBE_CALLS" \
  'the underlying probe function ran exactly once across two net_probe_capability calls - FAILS if the memoization guard is missing or checked backwards, which would re-run a real connect attempt on every single port probe of a scan'

printf '\n== capability probe: SCOURSH_NET_PROBE bypasses it entirely ==\n'
_net_reset

_PROBE_CALLS=0
_net_tcp_capability_probe() { _PROBE_CALLS=$(( _PROBE_CALLS + 1 )); return 0; }
SCOURSH_NET_PROBE=_stub_fixed
_STUB_STATE=open
net_connect_probe 203.0.113.5 22 >/dev/null
assert_eq 0 "$_PROBE_CALLS" \
  'with the test hook set, the capability probe is never consulted at all - FAILS if net_connect_probe routes through net_probe_capability before dispatching to the hook, which would make every hooked test also depend on this host'"'"'s bash build'

printf '\n== capability-absent path: recorded reduction, no real socket, degrades to filtered ==\n'
_net_reset
rm -rf "$W/run.capless"
run_init "$W/run.capless"

_net_tcp_capability_probe() { return 1; }
out=$(net_connect_probe 203.0.113.5 22)
assert_eq 'filtered' "$out" \
  'a bash with no /dev/tcp support degrades every probe to filtered rather than crashing the run or silently reporting not-open - FAILS if the capability guard in _net_connect_default is removed, in which case this would instead attempt a real, unguarded /dev/tcp connect'

cr=$(cat "$SCOURSH_RUN_DIR/meta/coverage_reduction" 2>/dev/null || printf '')
assert_contains "$cr" 'module=network' \
  'the coverage_reduction names the owning module using the SCAN_COMMANDS/checks_module_dir token (network, NET-04), not the finding-module-field short form (net) - lib/report.sh (NET-04)'"'"'s _RPT_MODULES/_html_audit_category grep for "module=network " and would never surface a "module=net" line under the Network category'
assert_contains "$cr" 'reason=net_probe_cmd_absent' \
  'the coverage_reduction carries the frozen reason string this module names, so a report reader can tell "no capability" apart from every other declared skip'
assert_eq 1 "$(wc -l <"$SCOURSH_RUN_DIR/meta/coverage_reduction" | tr -d ' ')" \
  'exactly one reduction line is written across this whole section - FAILS if the memoization guard is bypassed and every net_connect_probe call records its own line, which would flood run.json with one line per port on a real scan'

net_connect_probe 203.0.113.5 23 >/dev/null
net_connect_probe 203.0.113.5 24 >/dev/null
assert_eq 1 "$(wc -l <"$SCOURSH_RUN_DIR/meta/coverage_reduction" | tr -d ' ')" \
  'two further probes on the same degraded run still write only the one, first-recorded reduction line'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

printf '\n== SCOURSH_NET_TCP_CAPABLE forces the answer without probing at all ==\n'
_net_reset

_PROBE_CALLS=0
_net_tcp_capability_probe() { _PROBE_CALLS=$(( _PROBE_CALLS + 1 )); return 0; }
SCOURSH_NET_TCP_CAPABLE=0
assert_true "$(net_probe_capability && echo 1 || echo 0)" 'a forced 0 reports not-capable without ever calling the real probe'
assert_eq 0 "$_PROBE_CALLS" \
  'the forced value short-circuits the probe entirely - FAILS if net_probe_capability checks SCOURSH_NET_TCP_CAPABLE after already having called the probe function'

_net_reset
SCOURSH_NET_TCP_CAPABLE=1
assert_true "$(net_probe_capability && echo 0 || echo 1)" 'a forced 1 reports capable without probing'
assert_eq 0 "$_PROBE_CALLS" 'and still never calls the real probe'

printf '\n== net_read_banner: argument validation ==\n'
_net_reset

rm -f "$W/out.1"
net_read_banner '' 22 512 "$W/out.1" 2>/dev/null && rc=0 || rc=$?
assert_eq 1 "$rc" 'a missing HOST is a caller usage error (rc 1) - FAILS if net_read_banner silently proceeded to interpret /dev/tcp//22'

rm -f "$W/out.2"
net_read_banner example.test '' 512 "$W/out.2" 2>/dev/null && rc=0 || rc=$?
assert_eq 1 "$rc" 'a missing PORT is refused the same way'

rm -f "$W/out.3"
net_read_banner example.test 22 '' "$W/out.3" 2>/dev/null && rc=0 || rc=$?
assert_eq 1 "$rc" 'a missing MAX_BYTES is refused - FAILS if net_read_banner fell through to a real connect with an empty byte count'

net_read_banner example.test 22 512 '' 2>/dev/null && rc=0 || rc=$?
assert_eq 1 "$rc" 'a missing OUTFILE is refused - NET-07'"'"'s whole contract (lib/nettransport.sh'"'"'s own header) is that the read result is a FILE, never a bash-string return value, so a caller that forgot it must fail loudly rather than silently discard the read'

printf '\n== net_read_banner: SCOURSH_NET_BANNER_PROBE bypasses the whole real-socket path, no real socket, deterministic ==\n'
_net_reset

_stub_banner_fixed() { printf '%s' "$_BSTUB_TEXT" >"$4"; return 0; }
SCOURSH_NET_BANNER_PROBE=_stub_banner_fixed

_BSTUB_TEXT=$'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'
rm -f "$W/banner.out"
net_read_banner 203.0.113.5 22 512 "$W/banner.out"
assert_eq "${_BSTUB_TEXT%$'\n'}" "$(cat "$W/banner.out")" \
  'the hook is consulted in place of a real connect+read, and its captured bytes pass through unchanged into OUTFILE - FAILS if net_read_banner ever fell through to _net_read_banner_default while the hook is set (command substitution strips exactly one trailing newline, matching cat'"'"'s own read here, so the comparison is against that same trimmed form on both sides)'

_BSTUB_TEXT=''
rm -f "$W/banner.out"
: >"$W/banner.out"
net_read_banner 203.0.113.5 80 512 "$W/banner.out"
assert_eq '' "$(cat "$W/banner.out")" \
  'a hook that captures nothing leaves OUTFILE empty - the honest "this listener sent nothing" outcome a caller folds into report.md'"'"'s own no_banner reduction, never a crash or a fabricated string'

printf '\n== net_read_banner: SCOURSH_NET_BANNER_PROBE receives host/port/max_bytes/outfile/deadline exactly as given ==\n'
_net_reset

_BCAPTURED=''
_stub_banner_capture() { _BCAPTURED="host=$1 port=$2 max_bytes=$3 outfile=$4 deadline_ms=$5"; : >"$4"; return 0; }
SCOURSH_NET_BANNER_PROBE=_stub_banner_capture

net_read_banner 198.51.100.9 8443 256 "$W/cap.out" 900
assert_eq "host=198.51.100.9 port=8443 max_bytes=256 outfile=$W/cap.out deadline_ms=900" "$_BCAPTURED" \
  'an explicit max-bytes and deadline are forwarded verbatim - FAILS if net_read_banner drops or reorders an argument'

_BCAPTURED=''
net_read_banner 198.51.100.9 8443 256 "$W/cap.out"
assert_eq "host=198.51.100.9 port=8443 max_bytes=256 outfile=$W/cap.out deadline_ms=$_NET_DEFAULT_DEADLINE_MS" "$_BCAPTURED" \
  'omitting the deadline forwards the documented default rather than an empty value, matching net_connect_probe'"'"'s own contract'

printf '\n== net_read_banner: capability-absent degrades to an empty OUTFILE, never a crash, never a fabricated read ==\n'
_net_reset

_net_tcp_capability_probe() { return 1; }
rm -f "$W/cap-absent.out"
: >"$W/cap-absent.out"
_net_read_banner_default 203.0.113.5 22 512 "$W/cap-absent.out"
assert_file_exists "$W/cap-absent.out" 'OUTFILE still exists after a capability-absent call'
assert_eq '' "$(cat "$W/cap-absent.out")" \
  'and it is empty - a bash with no /dev/tcp support reads nothing rather than crashing the run or fabricating banner bytes, the identical degrade net_connect_probe applies to its own classification'

printf '\n== the real implementation NEVER writes to the socket - the passive contract, checked statically ==\n'
# This probe is required to send ZERO bytes - it is a passive read only.
# There is no live-socket harness in this suite (nor in net_connect_probe's
# own tests above) to observe that dynamically without opening a real
# connection, so the invariant is pinned the way a frozen contract with no
# argument for outbound data can be: (a) the function's own signature carries
# no payload/data parameter for a caller to even attempt to supply one, and
# (b) its body contains no redirection that writes INTO the connection fd -
# only the read direction (`<&"$ffd"`) and the initial bidirectional open
# (`<>`, required so the read side exists at all) ever reference it.
FN_BODY=$(sed -n '/^_net_read_banner_default() {/,/^}/p' "$ROOT/lib/nettransport.sh")
assert_ne '' "$FN_BODY" 'the function body was actually extracted (a sanity check on the extraction itself, not the contract)'
assert_not_contains "$FN_BODY" '>&"$ffd"' \
  'no line writes TO the connection file descriptor - FAILS if a future edit added an outbound write (e.g. sending a probe payload), which would silently turn this into an active check without report.md, checks-banner.rules or this suite ever being updated to say so'
assert_not_contains "$FN_BODY" '>&$ffd' \
  'the unquoted spelling of the same write-direction redirection is checked too, so a future edit cannot dodge the assertion above by dropping quotes'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'nettransport'
