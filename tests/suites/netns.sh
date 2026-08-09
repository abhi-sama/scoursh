#!/usr/bin/env bash
# tests/suites/netns.sh - tools/run-in-netns.sh, the network-namespace runner
# (docs/FOUNDATION.md tension 20, "the guarantee" half; NETNS-01).
#
# What this suite actually proves, and what it honestly cannot:
#
#  - Argument parsing, the capability-bit arithmetic, the target-IP/
#    nameserver collectors, and the exact build/teardown COMMAND SEQUENCE
#    are unit-tested against stubs on ANY host (no root, no Linux, no real
#    namespace - `ip`/`iptables`/`sysctl` are shadowed by test functions
#    that log what they were called with instead of touching the kernel).
#    This is real coverage of the tool's LOGIC, but it is not, and is never
#    described as, proof that a real kernel namespace actually blocks
#    anything - shadowed functions cannot fail the way a real `ip netns add`
#    without CAP_SYS_ADMIN would.
#  - "Fails immediately, no isolation action, <command> never runs" (this
#    ticket's ACs 3 and 4) IS exercised for real, as a real subprocess, on
#    WHATEVER host this suite happens to run on - not gated on Linux/root,
#    because at least one of those two preconditions is false on every
#    host this project's own CI matrix runs (docs/CI-RUNBOOK.md's GNU/BSD
#    matrix: the macOS leg is non-Linux; an unprivileged Linux leg has
#    neither root nor the two capabilities). Exactly one of the two
#    "-- section A/B --" blocks below is a real, executed assertion on any
#    given run; which one depends on the host.
#  - The one thing that genuinely requires a privileged Linux host - AC2,
#    "an out-of-scope connection fails at the kernel level" - is written as
#    a real end-to-end case (section C) that builds an actual namespace via
#    a real subprocess invocation and attempts a real connection to an
#    RFC 5737 TEST-NET-3 address that is guaranteed to have no route. It is
#    gated behind a genuine capability probe (Linux + (root or both caps) +
#    `ip` + `iptables`) and states plainly when it is SKIPPED rather than
#    silently reporting green - the same probe-and-state-plainly discipline
#    this codebase already uses for `ss`/`strace` (tension 20) and `shred`
#    (finding F16). A SKIP here is not a pass; it is recorded as exactly
#    what it is, so a human reviewing this run knows AC2's kernel-level
#    claim was not exercised on THIS host.
#  - Section C deliberately does not attempt a live IN-scope connection
#    (i.e. that the admitted addresses actually work): that would need real
#    egress/DNS inside CI, which conflicts with this project's own no-live-
#    network testing discipline everywhere else (docs/DESIGN.md §12: DAST
#    logic is tested against recorded mocks, never a live target). Section
#    B (the command-sequence tests) already proves the correct /32 routes
#    ARE added for resolved in-scope addresses and for nameservers; section
#    C proves specifically that an address NOT in that set is refused.
#    Together they cover this ticket's AC1 and AC2 without a flaky live
#    socket.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2329: as tests/suites/http.sh.
# shellcheck disable=SC2015,SC2016,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=tools/run-in-netns.sh
source "$ROOT/tools/run-in-netns.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/netns
mkdir -p "$W"
FIXTURE_SCOPE=$ROOT/tests/fixtures/config/netns-scope.conf
TOOL=$ROOT/tools/run-in-netns.sh

# ---------------------------------------------------------------------------
# -- section 0: usage / argument parsing (sourced-function unit tests) --
# ---------------------------------------------------------------------------
printf '\n-- argument parsing --\n'

_netns_parse_args -- scan.sh --profile-scan quick
assert_eq 'scan.sh --profile-scan quick' "${RUN_NETNS_CMD[*]}" \
  'a plain "-- <command...>" collects everything after -- as the wrapped command'

_netns_parse_args --scope-conf /tmp/x.conf -- echo hi
assert_eq '/tmp/x.conf' "$RUN_NETNS_SCOPE_CONF" '--scope-conf PATH is captured'
assert_eq 'echo hi' "${RUN_NETNS_CMD[*]}" '--scope-conf does not consume any part of the command'

assert_status "$SCOURSH_EXIT_USAGE" 'missing -- entirely is a usage error (exit 2), not a silent no-op' \
  _netns_parse_args scan.sh
assert_status "$SCOURSH_EXIT_USAGE" 'a bare -- with no command after it is a usage error' \
  _netns_parse_args --
assert_status "$SCOURSH_EXIT_USAGE" 'an unrecognised flag before -- is a usage error, not swallowed into the command' \
  _netns_parse_args --bogus -- echo hi

# ---------------------------------------------------------------------------
# -- section 0b: real subprocess exec, -h/--help works on ANY host --
# ---------------------------------------------------------------------------
printf '\n-- --help works regardless of host/privilege (real subprocess) --\n'
help_out=$(bash "$TOOL" --help 2>&1)
help_rc=0
bash "$TOOL" --help >/dev/null 2>&1 || help_rc=$?
assert_eq 0 "$help_rc" '--help exits 0 even on a host that would otherwise fail the Linux/privilege checks'
assert_contains "$help_out" 'run-in-netns.sh' '--help prints usage text naming the tool'

# ---------------------------------------------------------------------------
# -- section 1: the capability-bit check (CapEff bitmask arithmetic) --
# ---------------------------------------------------------------------------
printf '\n-- _netns_has_cap_bit: CapEff bitmask extraction --\n'

_cap_case() {
  local hex=$1 want12=$2 want21=$3 msg=$4
  printf 'CapEff:\t%s\n' "$hex" >"$W/capeff.status"
  RUN_NETNS_PROC_STATUS_FILE=$W/capeff.status
  local got12=0 got21=0
  _netns_has_cap_bit 12 && got12=1
  _netns_has_cap_bit 21 && got21=1
  assert_eq "$want12 $want21" "$got12 $got21" "$msg"
}

_cap_case '0000000000000000' 0 0 'no capabilities set: neither bit reads as present'
_cap_case 'ffffffffffffffff' 1 1 'the full effective set: both bits present - FAILS if the hex parse or shift breaks on a fully-set mask'
_cap_case '0000000000201000' 1 1 'exactly CAP_NET_ADMIN|CAP_SYS_ADMIN set and nothing else'
_cap_case '0000000000001000' 1 0 'only CAP_NET_ADMIN (bit 12) set - CAP_SYS_ADMIN alone is not sufficient'
_cap_case '0000000000200000' 0 1 'only CAP_SYS_ADMIN (bit 21) set - CAP_NET_ADMIN alone is not sufficient'
_cap_case '8000000000001000' 1 0 \
  'bit 63 (the sign bit under bash 64-bit signed arithmetic) set alongside CAP_NET_ADMIN: bit 12 must still read 1 - FAILS under a naive comparison-based bit test that mishandles a negative intermediate value'

RUN_NETNS_PROC_STATUS_FILE=$W/does-not-exist.status
assert_status 1 '_netns_has_cap_bit fails closed (returns non-zero) when the status file is unreadable, never assuming the capability is present' \
  _netns_has_cap_bit 12
RUN_NETNS_PROC_STATUS_FILE=/proc/self/status

# ---------------------------------------------------------------------------
# -- section 2: the allowlist collectors (lib/http.sh's pinned resolution
#    cache + the resolv.conf nameserver set) --
# ---------------------------------------------------------------------------
printf '\n-- _netns_collect_target_ips: lib/http.sh pinned resolution cache --\n'

_test_netns_resolve() {
  case $1 in
    good.netns.fixture.example) printf '93.184.216.34' ;;
    v6only.netns.fixture.example) printf '2001:db8::1' ;;
    unresolvable.netns.fixture.example) return 1 ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_test_netns_resolve
RUN_NETNS_SCOPE_CONF=$FIXTURE_SCOPE

_netns_collect_target_ips
_ips_joined=$(printf '%s\n' "${RUN_NETNS_TARGET_IPS[@]+"${RUN_NETNS_TARGET_IPS[@]}"}" | LC_ALL=C sort -u)
assert_contains "$_ips_joined" '93.184.216.34' \
  'a scope host resolved through http_resolve_host (the SAME pinned-cache function the scope gate uses) is admitted'
assert_contains "$_ips_joined" '198.51.100.7' \
  'a scope host that is already an IPv4 literal is admitted directly, with no resolution attempted'
assert_not_contains "$_ips_joined" '2001:db8::1' \
  'an IPv6-resolved scope host is NOT admitted - IPv6 routing is out-of-scope for this tool (FAILS if the IPv6 skip branch is removed)'
assert_eq 2 "${#RUN_NETNS_TARGET_IPS[@]}" \
  'exactly two addresses survive from the four-entry fixture: the IPv6-resolving host and the unresolvable host are both skipped, not silently admitted or silently crashing the collector'

printf '\n-- _netns_collect_nameservers: /etc/resolv.conf parsing (fixture, not the real file) --\n'
cat >"$W/resolv-fixture.conf" <<'RESOLV_EOF'
# a comment line, and a leading-whitespace nameserver line
  nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver	10.0.0.53
options ndots:1
RESOLV_EOF

_netns_collect_nameservers_from() {
  # A thin test-only wrapper: the shipped function reads the hardcoded
  # /etc/resolv.conf path deliberately (an operator-facing tool has no
  # reason to point elsewhere), so this test exercises the SAME regex body
  # against a fixture path instead of monkeypatching /etc/resolv.conf itself.
  RUN_NETNS_NAMESERVERS=()
  local line
  while IFS= read -r line; do
    if [[ $line =~ ^[[:space:]]*nameserver[[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3})([[:space:]]|$) ]]; then
      RUN_NETNS_NAMESERVERS+=("${BASH_REMATCH[1]}")
    fi
  done <"$1"
}
_netns_collect_nameservers_from "$W/resolv-fixture.conf"
_ns_joined=$(printf '%s\n' "${RUN_NETNS_NAMESERVERS[@]+"${RUN_NETNS_NAMESERVERS[@]}"}" | LC_ALL=C sort -u)
assert_eq '10.0.0.53
8.8.8.8' "$_ns_joined" \
  'both IPv4 nameservers are collected regardless of leading whitespace or tab-vs-space separation; the IPv6 nameserver and the non-nameserver "options" line are excluded'

# The real function against the REAL /etc/resolv.conf: only asserts it does
# not blow up and only ever collects well-formed IPv4 dotted-quads - the
# actual content is host-dependent so nothing about specific addresses is
# asserted here.
_netns_collect_nameservers
for _ns in "${RUN_NETNS_NAMESERVERS[@]+"${RUN_NETNS_NAMESERVERS[@]}"}"; do
  assert_true "$([[ $_ns =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && echo 0 || echo 1)" \
    "real /etc/resolv.conf nameserver '$_ns' is a well-formed IPv4 dotted-quad"
done

# ---------------------------------------------------------------------------
# -- section 3: build/teardown COMMAND SEQUENCE against shadowed ip/
#    iptables/sysctl (logic-level, not a real kernel test - see header) --
# ---------------------------------------------------------------------------
printf '\n-- _netns_build / _netns_teardown: command sequence against stubbed ip/iptables/sysctl --\n'

CMDLOG=$W/cmdlog.txt
: >"$CMDLOG"
ip() {
  printf 'ip %s\n' "$*" >>"$CMDLOG"
  if [[ $1 == route && $2 == show ]]; then
    printf 'default via 192.0.2.1 dev eth0\n'
  fi
  return 0
}
iptables() { printf 'iptables %s\n' "$*" >>"$CMDLOG"; return 0; }
sysctl() { printf 'sysctl %s\n' "$*" >>"$CMDLOG"; return 0; }

RUN_NETNS_SCOPE_CONF=$FIXTURE_SCOPE
_netns_build
NS_NAME_USED=$RUN_NETNS_NAME
_build_log=$(cat "$CMDLOG")

assert_contains "$_build_log" "ip netns add $NS_NAME_USED" 'build creates the namespace'
assert_contains "$_build_log" 'type veth peer name' 'build creates a veth pair'
assert_contains "$_build_log" "ip netns exec $NS_NAME_USED ip route add 93.184.216.34/32" \
  'build routes the resolved in-scope address into the namespace'
assert_contains "$_build_log" "ip netns exec $NS_NAME_USED ip route add 198.51.100.7/32" \
  'build routes the literal in-scope address into the namespace'
assert_not_contains "$_build_log" 'route add 0.0.0.0/0' \
  'NO default route is ever installed inside the namespace - FAILS if a default route sneaks in, since that would make the "only admitted addresses are reachable" guarantee false'
assert_contains "$_build_log" 'MASQUERADE' 'build sets up NAT for the namespace to reach the outside world'
assert_contains "$_build_log" "$NS_NAME_USED ip link set lo up" 'loopback is brought up inside the namespace'

: >"$CMDLOG"
_netns_teardown
_teardown_log=$(cat "$CMDLOG")
assert_contains "$_teardown_log" "iptables -t nat -D POSTROUTING" 'teardown removes the exact MASQUERADE rule build added'
assert_contains "$_teardown_log" "ip link del" 'teardown deletes the veth pair (which cascades to the namespace-side peer)'
assert_contains "$_teardown_log" "ip netns del $NS_NAME_USED" 'teardown deletes the namespace itself'
assert_eq 0 "${#RUN_NETNS_NAT_RULES[@]}" 'teardown clears its own NAT-rule bookkeeping, so a second teardown call is a safe no-op'

printf '\n-- a build failure partway through still tears down everything already created --\n'
: >"$CMDLOG"
ip() {
  printf 'ip %s\n' "$*" >>"$CMDLOG"
  if [[ $1 == route && $2 == show ]]; then
    return 0   # no output at all: egress-interface detection fails
  fi
  return 0
}
SCOURSH_HTTP_RESOLVE=_test_netns_resolve
RUN_NETNS_SCOPE_CONF=$FIXTURE_SCOPE
build_rc=0
# _netns_build's failure path goes through die(), which is exit(2) by
# contract (tension 14) - a bare, un-subshelled call here would take this
# WHOLE test script down with it, not just this assertion (die's `exit` has
# no idea it is "supposed to" only fail a function call). So the call runs in
# a subshell, and an EXIT trap installed only for this probe (NOT the real
# _netns_on_exit/core_cleanup, which would erase this suite's own
# SCOURSH_SCRATCH out from under it per scratch_is_owned_here - tension 4
# rule 5, finding F13) snapshots the globals _netns_build had set BEFORE die
# fired, so the parent can restore them and drive the REAL _netns_teardown
# against the exact partial state a real invocation would have left.
STATEFILE=$W/partial-build-state.sh
(
  trap 'declare -p RUN_NETNS_NAME RUN_NETNS_VETH_HOST RUN_NETNS_NS_CREATED \
    RUN_NETNS_VETH_CREATED RUN_NETNS_IPFWD_CHANGED RUN_NETNS_IPFWD_ORIG \
    RUN_NETNS_NAT_RULES >"$STATEFILE"' EXIT
  _netns_build
) >/dev/null 2>&1 || build_rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$build_rc" \
  'an undetectable egress interface fails the build with exit 5 (incomplete), still inside the 0-5 contract'
# shellcheck source=/dev/null
source "$STATEFILE"
_partial_ns=$RUN_NETNS_NAME
_netns_teardown
_partial_log=$(cat "$CMDLOG")
assert_contains "$_partial_log" "ip netns del $_partial_ns" \
  'teardown still deletes the namespace created before the failure, even though build never reached the NAT step'
assert_not_contains "$_partial_log" 'MASQUERADE' \
  'teardown never attempts to remove NAT rules that were never added (no iptables -D for a rule build never issued the -A for)'

# ---------------------------------------------------------------------------
# -- section A: on a non-Linux host, a real invocation fails immediately,
#    <command> never runs (this ticket's AC3) - REAL subprocess exec --
# ---------------------------------------------------------------------------
if [[ $(uname -s) != Linux ]]; then
  printf '\n-- section A: non-Linux host - real subprocess, real fail-closed check --\n'
  MARKER=$W/marker-nonlinux
  rm -f "$MARKER"
  rc=0
  bash "$TOOL" -- touch "$MARKER" >"$W/nonlinux.out" 2>&1 || rc=$?
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
    'a real invocation on this non-Linux host exits 4 (missing required input), not 0-and-quietly-degraded'
  assert_file_absent "$MARKER" \
    '<command> (touch the marker file) never ran - FAILS if the Linux check is bypassed or only warns'
  assert_contains "$(cat "$W/nonlinux.out")" 'Linux-only' \
    'the error names the actual reason (Linux-only), not a generic failure'
else
  printf '\n-- section A: SKIPPED (this host IS Linux; section B below covers the Linux legs) --\n'
fi

# ---------------------------------------------------------------------------
# -- section B: on Linux without root/CAP_NET_ADMIN+CAP_SYS_ADMIN, a real
#    invocation fails immediately, <command> never runs (this ticket's AC4)
#    - REAL subprocess exec --
# ---------------------------------------------------------------------------
_have_netns_privilege() {
  [[ $(uname -s) == Linux ]] || return 1
  [[ $(id -u) -eq 0 ]] && return 0
  _netns_has_cap_bit 21 && _netns_has_cap_bit 12
}

if [[ $(uname -s) == Linux ]] && ! _have_netns_privilege; then
  printf '\n-- section B: Linux, unprivileged - real subprocess, real fail-closed check --\n'
  MARKER=$W/marker-noroot
  rm -f "$MARKER"
  rc=0
  bash "$TOOL" -- touch "$MARKER" >"$W/noroot.out" 2>&1 || rc=$?
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
    'a real invocation with no root/capabilities exits 4, not 0-and-quietly-degraded'
  assert_file_absent "$MARKER" \
    '<command> never ran - FAILS if the privilege check is bypassed or only warns'
  assert_contains "$(cat "$W/noroot.out")" 'CAP_NET_ADMIN' \
    'the error names the actual missing capabilities'
elif [[ $(uname -s) == Linux ]]; then
  printf '\n-- section B: SKIPPED (this Linux host IS privileged; section C below covers the real kernel test) --\n'
else
  printf '\n-- section B: SKIPPED (not Linux; section A above already covers this host'"'"'s fail-closed path) --\n'
fi

# ---------------------------------------------------------------------------
# -- section C: THE real, kernel-level test (this ticket's AC2) - gated on
#    Linux + privilege + required tools. This is the ONLY block in this
#    suite that creates a genuine namespace and makes a genuine connection
#    attempt; everything else above is a stub/logic test (see header).
# ---------------------------------------------------------------------------
if [[ $(uname -s) == Linux ]] && _have_netns_privilege \
  && command -v ip >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
  printf '\n-- section C: REAL kernel-level test (Linux, privileged, ip+iptables present) --\n'

  EMPTY_SCOPE=$W/empty-scope.conf
  : >"$EMPTY_SCOPE"

  rc=0
  # 203.0.113.5 is RFC 5737 TEST-NET-3: documented as non-routable and, more
  # to the point here, never added to this run's route table at all (the
  # fixture scope is empty), so the namespace has NO route to it whatsoever.
  # `timeout` bounds this in case some host-specific quirk turns "no route"
  # into a hang instead of the expected immediate ENETUNREACH.
  bash "$TOOL" --scope-conf "$EMPTY_SCOPE" -- \
    timeout 5 bash -c 'exec 3<>/dev/tcp/203.0.113.5/80' >"$W/c-out.txt" 2>&1 || rc=$?
  assert_ne 0 "$rc" \
    'a connection attempt from inside the real namespace to an address outside its route table fails - FAILS (rc=0) if the namespace has any route to the outside world it should not have'

  ns_left=$(ip netns list 2>/dev/null || true)
  assert_not_contains "$ns_left" 'scoursh-ns-' \
    'no scoursh-created namespace is left behind after the run - teardown ran even though <command> itself failed'
else
  printf '\n-- section C: SKIPPED (needs Linux + root/CAP_NET_ADMIN+CAP_SYS_ADMIN + ip + iptables; this ticket'"'"'s AC2 kernel-level claim is NOT exercised on this host/run - see the header comment) --\n'
fi

t_summary 'netns'
