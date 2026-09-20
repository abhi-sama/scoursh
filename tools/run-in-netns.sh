#!/usr/bin/env bash
# tools/run-in-netns.sh - the network-namespace runner (docs/DESIGN.md §13
# step 8, second half; docs/FOUNDATION.md tension 20).
#
# Owns:
#   docs/DESIGN.md    §13 step 8 ("Optional netns isolation ... belt-and-
#                      suspenders for high-assurance environments")
#   docs/FOUNDATION.md tension 20 (paranoid mode versus infrastructure
#                      traffic - THIS file is "the guarantee" half of that
#                      resolution; `--paranoid` is "the detector" half and is
#                      a separate ticket, PARANOID-01, not built here)
#   docs/STEP8-PARANOID-PLAN.md (the sub-ticket split; this file is NETNS-01)
#
# WHAT THIS IS.  A Linux-only, root/CAP_NET_ADMIN+CAP_SYS_ADMIN-requiring
# wrapper: `tools/run-in-netns.sh -- <command...>` creates a network
# namespace whose route table admits only two sets of addresses, in EACH
# address family it supports (IPv4 and IPv6 alike) -
#
#   1. Resolved addresses of scoursh's in-scope targets, from
#      lib/http.sh's pinned resolution cache (tension 19: http_scope_load +
#      http_resolve_host, the SAME functions the scope gate itself uses -
#      never a re-implementation of scope parsing or DNS resolution). An
#      admitted address is whichever family it actually is - an IPv6 literal
#      scope host, or a hostname that resolved to an IPv6 address, is
#      admitted as IPv6 exactly as an IPv4 one is admitted as IPv4; see
#      _netns_collect_target_ips below.
#   2. The nameserver addresses parsed from /etc/resolv.conf, plus loopback -
#      the identical "infrastructure" set docs/FOUNDATION.md tension 20
#      names as `--paranoid`'s allowlist set 3 (port 53 is that set's
#      *intent*; the honest limitation on enforcing that specific port at
#      THIS tool's layer is stated in section 4 below). Both an IPv4 and an
#      IPv6 nameserver line are collected.
#
# - then execs <command...> inside that namespace via `ip netns exec`.  An
# attempted connection to any address outside those two sets, IN EITHER
# FAMILY, has no route and fails at the kernel level (ENETUNREACH/EAFNOSUPPORT)
# before a single packet is sent - it is not sampled, observed, or logged
# after the fact the way `--paranoid` is; it is categorically impossible,
# which is exactly the "guarantee vs detector" distinction tension 20's
# RESOLUTION draws between this file and `--paranoid`.  A dual-stack target
# (one scope entry that resolves or is declared in both families) cannot be
# used to bypass this: EACH family gets its own explicit /32-or-/128 route
# and NEITHER family ever gets a default route, so a family that happens to
# carry no admitted address for THIS run is simply unreachable in that
# family - the same "no route in, no route out" guarantee IPv4 has always
# had, extended rather than weakened by adding a second family alongside it.
#
# IPv6 SUPPORT (this file's own follow-up ticket, filed when NETNS-01
# originally shipped IPv4-only - ROADMAP.md's "Outside that ordering" list,
# AGENTS.md's "Step 8" section, and docs/FOUNDATION.md tension 20's own
# "Consequence for the build" paragraph all named it as scoped out and
# deferred). The namespace's loopback and its veth pair are given IPv6
# addressing and routing ALONGSIDE IPv4, unconditionally, on every run -
# never only when the currently-resolved scope happens to contain an IPv6
# address - because the guarantee this tool exists to provide is that
# NOTHING escapes the namespace in either family, not merely that whatever
# happens to be in scope today is contained. `_netns_require_ipv6` (section
# 2) is therefore an unconditional precondition, exactly like
# `_netns_require_tools`: this host must have IPv6 kernel support and
# `ip6tables` before ANY isolation action is taken, and refuses loudly (exit
# 4, before creating any namespace/veth/route state, <command> never runs)
# rather than silently building an IPv4-only namespace that LOOKS like the
# full guarantee but is not - see `_netns_require_ipv6`'s own comment for
# why a silent v4-only fallback would be worse than refusing outright.
#
# WHAT THIS DELIBERATELY IS NOT (see this ticket's own "Out-of-scope" and
# docs/STEP8-PARANOID-PLAN.md's NETNS-01 row):
#   - It does not depend on, call, or wrap PARANOID-01's connection-observer
#     mechanism in any way. The two are independent, peer mechanisms.
#   - It is never invoked automatically by scan.sh. scan.sh is untouched by
#     this ticket; an operator runs this tool explicitly and deliberately.
#   - It carries no AWS-endpoint set (tension 20's set 2) and no
#     `scanner.conf` `paranoid_allow` set (set 4) - only sets 1 and 3, per
#     this ticket's own acceptance criteria ("addresses ... plus the shared
#     nameserver set"), which are the only two sets `--paranoid` uses that
#     have nothing to do with `--paranoid`'s own AWS-iteration state or its
#     operator-authored infra allowlist.
#   - General IPv6 CIDR/IDN support beyond what lib/http.sh's own resolution
#     cache and scope-literal parsing already provide is still out of scope
#     here, exactly as it is for lib/http.sh itself (tension 19's own stated
#     limitation) - this ticket routes whatever address lib/http.sh hands
#     back, in whichever family, and does not add a second resolver or a
#     CIDR matcher of its own.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

# A test suite sources this file to reach individual functions (arg parsing,
# the resolv.conf parser, the capability-bit check, the target-IP collector)
# without running the privileged main flow or execing anything - the exact
# same dual-mode idiom scan.sh uses for the same reason.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  RUN_NETNS_MAIN=1
else
  RUN_NETNS_MAIN=0
fi

RUN_NETNS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# -x back-edge cut: lib/core.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$RUN_NETNS_DIR/lib/core.sh"
# shellcheck source=lib/http.sh
source "$RUN_NETNS_DIR/lib/http.sh"

# ---------------------------------------------------------------------------
# 1. Exit-code discipline (tension 14; this ticket's own AC6)
# ---------------------------------------------------------------------------
# Every failure THIS script produces - bad usage, wrong host, missing
# privilege, missing tooling, a namespace/veth/iptables step that itself
# fails - goes through lib/core.sh's `die`, which is already restricted to
# 0-5 (die() downgrades anything else to SCOURSH_EXIT_INCOMPLETE and says
# so).  The ONE exit path that is deliberately NOT run through `die` is the
# wrapped command's own exit status (section 7): a transparent wrapper must
# forward what `<command>` actually returned rather than launder it, and the
# documented invocation (`tools/run-in-netns.sh -- scan.sh ...`) already
# names a command that is itself contractually bound to exit 0-5
# (docs/FOUNDATION.md tension 14). Forcing an arbitrary wrapped command's
# exit status into 0-5 would misreport what happened; it is the wrapped
# command's own contract to keep, not this tool's to fake.
#
# We override lib/core.sh's own `trap core_cleanup EXIT` (installed when it
# was sourced above) so that OUR namespace/veth/iptables teardown also runs
# on every exit path, in addition to (not instead of) the scratch-dir
# cleanup core_cleanup performs. core_cleanup is not simply called from our
# handler: it re-reads `$?` at its own entry (`local status=$?`), which
# would capture whatever _netns_teardown's last internal command left, not
# the ORIGINAL exit status this process is unwinding with. So this handler
# inlines core_cleanup's own two steps after capturing status ONCE, rather
# than chaining to it - the same "capture $? before touching anything else"
# discipline core_cleanup and die() already use, just not re-entrant through
# a second function call.
_netns_on_exit() {
  local status=$?
  _netns_teardown
  if [[ -n ${_SCOURSH_SLEEPFD:-} ]]; then
    exec {_SCOURSH_SLEEPFD}>&- 2>/dev/null || true
    _SCOURSH_SLEEPFD=''
  fi
  if scratch_is_owned_here; then
    erase_dir "$SCOURSH_SCRATCH"
  fi
  return "$status"
}

_netns_usage() {
  cat <<'EOF'
usage: tools/run-in-netns.sh [--scope-conf PATH] -- <command> [args...]

Runs <command> inside a Linux network namespace whose route table admits
only the resolved addresses of scoursh's in-scope targets (from
lib/http.sh's pinned resolution cache) plus the host's own nameservers
(parsed from /etc/resolv.conf) and loopback - in BOTH IPv4 and IPv6. Any
other destination, in either family, has no route and fails at the kernel
level.

Requires: Linux, and root or CAP_NET_ADMIN+CAP_SYS_ADMIN, and `ip`
(iproute2), `iptables`, and `ip6tables` on PATH, and host IPv6 kernel
support (IPv6 containment is built unconditionally, alongside IPv4, on
every run - see the header comment). Fails immediately, before creating
any namespace/veth/route state and without running <command>, if any of
those are not met.

  --scope-conf PATH   use PATH instead of config/scope.conf (mainly for
                       tests; matches lib/http.sh's own default resolution)
  -h, --help          print this message and exit 0

Example:
  tools/run-in-netns.sh -- scan.sh --target my-target --profile-scan quick

This tool is never invoked by scan.sh itself, and does not depend on or
wrap `--paranoid` (a separate, independent mechanism - the observer/
detector half of docs/FOUNDATION.md tension 20; this tool is the guarantee
half). Run it standalone, deliberately, when you need kernel-enforced
isolation rather than sampled observation.
EOF
}

# ---------------------------------------------------------------------------
# 2. Preconditions that must fail BEFORE any privileged action is attempted
#    (this ticket's ACs 3 and 4: fail immediately, no isolation action taken,
#    <command> never runs)
# ---------------------------------------------------------------------------
_netns_require_linux() {
  local os
  os=$(uname -s)
  if [[ $os != Linux ]]; then
    die "$SCOURSH_EXIT_INPUT" \
      "tools/run-in-netns.sh is Linux-only (network namespaces are a Linux kernel feature); this host reports '$os'. Refusing to run <command> at all rather than silently proceeding with no isolation."
  fi
}

# CAP_NET_ADMIN=12, CAP_SYS_ADMIN=21 (linux/capability.h). Reads the
# process's OWN effective-capability bitmask from /proc/self/status: a
# right-shift-then-mask-by-1 correctly extracts a single bit regardless of
# whether the value's top bit (and hence its sign under bash's 64-bit signed
# arithmetic) is set, because arithmetic right shift only ever affects bits
# ABOVE the one being tested, and `& 1` discards everything except the
# tested bit.  No bare grep: tension 4 rule 2 forbids it in engine files
# (lib/, modules/, tools/), so the line is found with a plain `while read`
# and a `[[ == CapEff:* ]]` prefix match instead.
#
# The path is a variable (default /proc/self/status, real on Linux) rather
# than a hardcoded literal so a test suite can point it at a fixture file
# with a crafted CapEff line - the same SCOURSH_HTTP_RESOLVE-style
# indirection lib/http.sh uses so no test ever needs a real resolver or,
# here, a real /proc.
RUN_NETNS_PROC_STATUS_FILE=${RUN_NETNS_PROC_STATUS_FILE:-/proc/self/status}

_netns_has_cap_bit() {
  local bit=$1 line hex=''
  [[ -r $RUN_NETNS_PROC_STATUS_FILE ]] || return 1
  while IFS= read -r line; do
    if [[ $line == CapEff:* ]]; then
      hex=${line#CapEff:}
      hex=${hex//[[:space:]]/}
      break
    fi
  done <"$RUN_NETNS_PROC_STATUS_FILE"
  [[ $hex =~ ^[0-9a-fA-F]+$ ]] || return 1
  (( (16#$hex >> bit) & 1 ))
}

_netns_require_privilege() {
  if [[ $(id -u) -eq 0 ]]; then
    log_info "run-in-netns: running as root (uid 0)"
    return 0
  fi
  if _netns_has_cap_bit 21 && _netns_has_cap_bit 12; then
    log_info "run-in-netns: running unprivileged but with CAP_SYS_ADMIN and CAP_NET_ADMIN in the effective set"
    return 0
  fi
  die "$SCOURSH_EXIT_INPUT" \
    "tools/run-in-netns.sh requires root or CAP_NET_ADMIN+CAP_SYS_ADMIN to create a network namespace and its veth/route plumbing; this process has neither. Refusing to run <command> at all rather than proceeding as though isolation had been applied. Re-run as root, or grant both capabilities (e.g. 'sudo setcap cap_net_admin,cap_sys_admin+ep tools/run-in-netns.sh' - note bash scripts do not honour file capabilities on every kernel/filesystem combination, so 'sudo' is the reliable option)."
}

_netns_require_tools() {
  require_cmd ip iptables
}

# The path is a variable (default /proc/net/if_inet6, real on any Linux
# kernel built with IPv6 support) rather than a hardcoded literal for the
# same reason RUN_NETNS_PROC_STATUS_FILE is above: a test suite can point it
# at a fixture path without a real /proc.  /proc/net/if_inet6 is created by
# the kernel's IPv6 module and is absent when IPv6 was compiled out or the
# module never loaded - it is not a claim about administrative state (a
# host that booted with every interface's IPv6 disabled via sysctl can
# still have this file), only about whether the kernel can speak IPv6 at
# all.  A host with the module loaded but IPv6 administratively disabled
# everywhere fails later, loudly, inside _netns_build's own `ip -6` calls -
# set -Eeuo pipefail's ERR trap (lib/core.sh) turns that into
# SCOURSH_EXIT_INCOMPLETE rather than a silent no-op, so "fails loudly" is
# still true even where this precondition under-detects.
RUN_NETNS_IF_INET6_FILE=${RUN_NETNS_IF_INET6_FILE:-/proc/net/if_inet6}

_netns_has_ipv6_kernel_support() {
  [[ -r $RUN_NETNS_IF_INET6_FILE ]]
}

# Unconditional, exactly like _netns_require_tools above: this tool builds
# IPv6 containment alongside IPv4 on EVERY run (see the header comment for
# why), so IPv6 support is required before anything privileged happens, not
# only when the currently-resolved scope happens to contain an IPv6
# address.  The alternative - silently skip IPv6 setup when the host lacks
# it and proceed IPv4-only - is exactly the "silently degrading the
# guarantee" this ticket exists to refuse: an operator who later authorises
# an IPv6 or dual-stack target against a namespace that was quietly built
# without IPv6 containment would have no way to know that family was never
# actually contained.
_netns_require_ipv6() {
  require_cmd ip6tables
  _netns_has_ipv6_kernel_support || die "$SCOURSH_EXIT_INPUT" \
    "tools/run-in-netns.sh requires host IPv6 kernel support ('$RUN_NETNS_IF_INET6_FILE' is missing or unreadable, meaning the kernel's IPv6 stack is absent or fully disabled) to build the namespace's IPv6 containment alongside its IPv4 containment - the whole point of this tool is that NOTHING escapes it, in EITHER address family. Refusing to run <command> at all rather than silently degrading the guarantee to IPv4-only. If this host genuinely has no IPv6 stack (e.g. booted with 'ipv6.disable=1'), this tool cannot be used against an IPv6 or dual-stack target on it."
}

# ---------------------------------------------------------------------------
# 3. Argument parsing: `[--scope-conf PATH] -- <command...>`
# ---------------------------------------------------------------------------
RUN_NETNS_SCOPE_CONF=''
RUN_NETNS_CMD=()

_netns_parse_args() {
  RUN_NETNS_SCOPE_CONF=''
  RUN_NETNS_CMD=()
  while (( $# )); do
    case $1 in
      -h | --help)
        _netns_usage
        exit "$SCOURSH_EXIT_OK"
        ;;
      --scope-conf)
        (( $# >= 2 )) || die "$SCOURSH_EXIT_USAGE" "--scope-conf requires a PATH argument"
        RUN_NETNS_SCOPE_CONF=$2
        shift 2
        ;;
      --)
        shift
        RUN_NETNS_CMD=("$@")
        (( ${#RUN_NETNS_CMD[@]} > 0 )) || die "$SCOURSH_EXIT_USAGE" \
          "missing <command> after '--' (usage: tools/run-in-netns.sh [--scope-conf PATH] -- <command...>)"
        return 0
        ;;
      *)
        die "$SCOURSH_EXIT_USAGE" "unrecognised argument before '--': '$1' (usage: tools/run-in-netns.sh [--scope-conf PATH] -- <command...>)"
        ;;
    esac
  done
  die "$SCOURSH_EXIT_USAGE" "missing '--' separator and <command> (usage: tools/run-in-netns.sh [--scope-conf PATH] -- <command...>)"
}

# ---------------------------------------------------------------------------
# 4. The allowlist: lib/http.sh's pinned resolution cache (set 1) plus the
#    resolv.conf nameserver set (set 3, tension 20's own naming) - each
#    split by address family, IPv4 and IPv6 admitted alike.
# ---------------------------------------------------------------------------
# Populates the global RUN_NETNS_TARGET_IPS (IPv4 dotted-quads) and
# RUN_NETNS_TARGET_IPS6 (IPv6 literals) arrays, NOT yet deduplicated - see
# _netns_build. Calls ONLY lib/http.sh's own public entry points -
# http_scope_load and http_resolve_host - never a re-implementation of scope
# parsing or DNS resolution, so this tool and the scope gate can never
# disagree about what a scope.conf host means (the same principle
# lib/http.sh's own header states for attribution vs. the gate). An IPv6
# scope host (an already-normalised, bracket-stripped literal straight out
# of _HTTP_SCOPE_HOST - http_url_normalize validated and canonicalised it
# when the scope was loaded, so it is not re-validated here) or an
# IPv6-resolving hostname is admitted into the IPv6 array rather than
# skipped: this is the change this ticket makes over the original
# IPv4-only NETNS-01 (see the header comment's "IPv6 SUPPORT" paragraph).
#
# A fixed-name global, not a generic "return an array via a passed name"
# helper: `local -n` (namerefs) arrived in bash 4.3, and tension 24 freezes
# the minimum interpreter at 4.2 - lib/findings.sh's own header states this
# repository deliberately uses namerefs nowhere, and this file follows suit.
RUN_NETNS_TARGET_IPS=()
RUN_NETNS_TARGET_IPS6=()

_netns_collect_target_ips() {
  RUN_NETNS_TARGET_IPS=()
  RUN_NETNS_TARGET_IPS6=()
  http_scope_load "${RUN_NETNS_SCOPE_CONF:-}"
  local n=${#_HTTP_SCOPE_HOST[@]} i host addr
  for (( i = 0; i < n; i++ )); do
    host=${_HTTP_SCOPE_HOST[i]}
    if [[ $host == *:* ]]; then
      RUN_NETNS_TARGET_IPS6+=("$host")
      continue
    fi
    if [[ $host =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      addr=$host
    elif ! addr=$(http_resolve_host "$host"); then
      log_warn "run-in-netns: DNS resolution failed for scope host '$host' - it will NOT be reachable from inside the namespace (the route table can only admit addresses it could resolve)"
      continue
    fi
    if [[ $addr == *:* ]]; then
      RUN_NETNS_TARGET_IPS6+=("$addr")
      continue
    fi
    RUN_NETNS_TARGET_IPS+=("$addr")
  done
}

# Populates the global RUN_NETNS_NAMESERVERS (IPv4) and
# RUN_NETNS_NAMESERVERS6 (IPv6) arrays from /etc/resolv.conf's `nameserver`
# lines. No bare grep (tension 4 rule 2): a plain `while read` with
# bash-regex matching. Same fixed-global rationale as
# _netns_collect_target_ips above.
RUN_NETNS_NAMESERVERS=()
RUN_NETNS_NAMESERVERS6=()

_netns_collect_nameservers() {
  RUN_NETNS_NAMESERVERS=()
  RUN_NETNS_NAMESERVERS6=()
  if [[ ! -r /etc/resolv.conf ]]; then
    log_warn "run-in-netns: /etc/resolv.conf is not readable - no nameserver route will be added; DNS resolution inside the namespace will fail unless the wrapped command uses --resolve or a hosts file"
    return 0
  fi
  local line
  while IFS= read -r line; do
    if [[ $line =~ ^[[:space:]]*nameserver[[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3})([[:space:]]|$) ]]; then
      RUN_NETNS_NAMESERVERS+=("${BASH_REMATCH[1]}")
    elif [[ $line =~ ^[[:space:]]*nameserver[[:space:]]+([0-9a-fA-F:]+) ]]; then
      RUN_NETNS_NAMESERVERS6+=("${BASH_REMATCH[1]}")
    fi
  done </etc/resolv.conf
}

# Deduplicates the newline-joined LIST given on stdin, LC_ALL=C (tension
# 17's own sort discipline), without sort -V (tension 24 restricts that to
# lib/core.sh) - plain `sort -u` is not on that restricted list. Prints one
# entry per line; the caller re-reads it into an array with a plain `while
# read` loop, same as every other array-building loop in this file (no
# nameref needed since this is a pure stdin -> stdout filter).
_netns_dedupe_lines() {
  LC_ALL=C sort -u
}

# ---------------------------------------------------------------------------
# 5. Namespace/veth/route/NAT plumbing
# ---------------------------------------------------------------------------
# All state this section creates is tracked in these globals so
# _netns_teardown (section 6) can reverse EXACTLY what was done, in any
# partially-constructed state (a failure three steps into setup must still
# tear down the first two).
RUN_NETNS_NAME=''
RUN_NETNS_VETH_HOST=''
RUN_NETNS_VETH_NS=''
RUN_NETNS_VETH_CREATED=0
RUN_NETNS_NS_CREATED=0
RUN_NETNS_IPFWD_ORIG=''
RUN_NETNS_IPFWD_CHANGED=0
RUN_NETNS_IP6FWD_ORIG=''
RUN_NETNS_IP6FWD_CHANGED=0
RUN_NETNS_NAT_RULES=()   # each entry: "FAMILY|TABLE|CHAIN|arg\x1farg\x1f..." as added, for exact -D removal
RUN_NETNS_EGRESS_IF=''

_netns_pick_link_names() {
  # IFNAMSIZ is 15 bytes; "vh"/"vn" + a pid (<=7 digits on stock Linux
  # pid_max) comfortably fits.
  RUN_NETNS_NAME="scoursh-ns-$$"
  RUN_NETNS_VETH_HOST="vh$$"
  RUN_NETNS_VETH_NS="vn$$"
}

_netns_detect_egress_if() {
  local line
  while IFS= read -r line; do
    if [[ $line =~ ^default[[:space:]] ]] && [[ $line =~ dev[[:space:]]+([^[:space:]]+) ]]; then
      RUN_NETNS_EGRESS_IF=${BASH_REMATCH[1]}
      return 0
    fi
  done < <(ip route show default 2>/dev/null)
  return 1
}

# FAMILY is 4 or 6, selecting iptables vs. ip6tables - the two tools have
# identical CLI grammar (ip6tables is not "iptables with a -6 flag", but the
# subset of syntax this file uses - -t TABLE, -A/-D CHAIN, -s/-i/-o/-j/-m -
# is the same across both), so one function serves both families rather
# than forking a second copy.
_netns_add_nat_rule() {
  local family=$1 table=$2 chain=$3
  shift 3
  local args=("$@")
  local bin=iptables
  [[ $family == 6 ]] && bin=ip6tables
  local table_flag=(-t "$table")
  [[ $table == filter ]] && table_flag=()
  "$bin" "${table_flag[@]+"${table_flag[@]}"}" -A "$chain" "${args[@]+"${args[@]}"}"
  RUN_NETNS_NAT_RULES+=("$family|$table|$chain|$(printf '%s\x1f' "${args[@]+"${args[@]}"}")")
}

_netns_build() {
  _netns_pick_link_names

  log_info "run-in-netns: creating namespace '$RUN_NETNS_NAME'"
  ip netns add "$RUN_NETNS_NAME"
  RUN_NETNS_NS_CREATED=1

  ip link add "$RUN_NETNS_VETH_HOST" type veth peer name "$RUN_NETNS_VETH_NS"
  RUN_NETNS_VETH_CREATED=1
  ip link set "$RUN_NETNS_VETH_NS" netns "$RUN_NETNS_NAME"

  # A 169.254.0.0/16 (RFC 3927) /30 for the IPv4 point-to-point link, offset
  # by (pid % 250) to reduce (never eliminate) collision risk against
  # anything else on the host that happens to use the same convention - a
  # stated, best-effort choice, the same class of documented limitation as
  # lib/core.sh's tmpfs/erase_dir note for `shred`.  This link address is
  # NOT itself a "scope" address; it is never reachable from outside the
  # namespace and carries no scan traffic of its own.
  #
  # The IPv6 point-to-point link reuses the SAME pid-derived offset, folded
  # into a fd00::/8 (RFC 4193) Unique Local Address /126 rather than
  # relying on the veth pair's automatic fe80::/10 link-local addresses:
  # this file explicitly assigns and tracks every address it uses (see the
  # IPv4 comment just above), and a manually-assigned ULA keeps that
  # discipline rather than mixing an explicit v4 scheme with an implicit v6
  # one.  Like the v4 link, it is never reachable from outside the
  # namespace and carries no scan traffic of its own.
  local octet=$(( ($$ % 250) + 2 ))
  local host_addr="169.254.${octet}.1"
  local ns_addr="169.254.${octet}.2"
  local octet6
  octet6=$(printf '%x' "$octet")
  local host_addr6="fd00:5c02:${octet6}::1"
  local ns_addr6="fd00:5c02:${octet6}::2"

  ip addr add "${host_addr}/30" dev "$RUN_NETNS_VETH_HOST"
  ip -6 addr add "${host_addr6}/126" dev "$RUN_NETNS_VETH_HOST"
  ip link set "$RUN_NETNS_VETH_HOST" up

  ip netns exec "$RUN_NETNS_NAME" ip addr add "${ns_addr}/30" dev "$RUN_NETNS_VETH_NS"
  ip netns exec "$RUN_NETNS_NAME" ip -6 addr add "${ns_addr6}/126" dev "$RUN_NETNS_VETH_NS"
  ip netns exec "$RUN_NETNS_NAME" ip link set "$RUN_NETNS_VETH_NS" up
  # `ip link set lo up` brings up BOTH families' loopback addresses in one
  # call - 127.0.0.1/8 and ::1 are both assigned by the kernel automatically
  # the instant lo transitions to UP, so no separate `ip -6 addr add` is
  # needed for the namespace's own IPv6 loopback.
  ip netns exec "$RUN_NETNS_NAME" ip link set lo up

  local addr
  _netns_collect_target_ips
  _netns_collect_nameservers
  local allowed=() allowed6=()
  if (( ${#RUN_NETNS_TARGET_IPS[@]} > 0 || ${#RUN_NETNS_NAMESERVERS[@]} > 0 )); then
    local deduped
    deduped=$(printf '%s\n' \
      "${RUN_NETNS_TARGET_IPS[@]+"${RUN_NETNS_TARGET_IPS[@]}"}" \
      "${RUN_NETNS_NAMESERVERS[@]+"${RUN_NETNS_NAMESERVERS[@]}"}" \
      | _netns_dedupe_lines)
    while IFS= read -r addr; do
      [[ -n $addr ]] && allowed+=("$addr")
    done <<<"$deduped"
  fi
  if (( ${#RUN_NETNS_TARGET_IPS6[@]} > 0 || ${#RUN_NETNS_NAMESERVERS6[@]} > 0 )); then
    local deduped6
    deduped6=$(printf '%s\n' \
      "${RUN_NETNS_TARGET_IPS6[@]+"${RUN_NETNS_TARGET_IPS6[@]}"}" \
      "${RUN_NETNS_NAMESERVERS6[@]+"${RUN_NETNS_NAMESERVERS6[@]}"}" \
      | _netns_dedupe_lines)
    while IFS= read -r addr; do
      [[ -n $addr ]] && allowed6+=("$addr")
    done <<<"$deduped6"
  fi

  if (( ${#allowed[@]} == 0 && ${#allowed6[@]} == 0 )); then
    log_warn "run-in-netns: no in-scope addresses and no nameservers resolved in either address family - the namespace's route table admits nothing beyond loopback; <command> will have no network reachability at all inside it"
  fi
  for addr in "${allowed[@]+"${allowed[@]}"}"; do
    log_info "run-in-netns: admitting $addr/32 into the namespace route table (via $host_addr)"
    ip netns exec "$RUN_NETNS_NAME" ip route add "${addr}/32" via "$host_addr" dev "$RUN_NETNS_VETH_NS"
  done
  for addr in "${allowed6[@]+"${allowed6[@]}"}"; do
    log_info "run-in-netns: admitting $addr/128 into the namespace route table (via $host_addr6)"
    ip netns exec "$RUN_NETNS_NAME" ip -6 route add "${addr}/128" via "$host_addr6" dev "$RUN_NETNS_VETH_NS"
  done

  # Deliberately no default route inside the namespace, in EITHER family
  # (this ticket's AC2, extended from IPv4-only to both): anything not
  # explicitly admitted above has no route at all, so a connection attempt
  # to it fails at the kernel level (ENETUNREACH) rather than being merely
  # refused by a firewall rule.  This is also what makes a dual-stack
  # target safe: a family with nothing admitted this run gets no route of
  # any kind, so it cannot become an accidental bypass for the other.

  RUN_NETNS_IPFWD_ORIG=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf '0')
  if [[ $RUN_NETNS_IPFWD_ORIG != 1 ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    RUN_NETNS_IPFWD_CHANGED=1
  fi
  RUN_NETNS_IP6FWD_ORIG=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || printf '0')
  if [[ $RUN_NETNS_IP6FWD_ORIG != 1 ]]; then
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    RUN_NETNS_IP6FWD_CHANGED=1
  fi

  if ! _netns_detect_egress_if; then
    die "$SCOURSH_EXIT_INCOMPLETE" "run-in-netns: could not determine the host's default egress interface ('ip route show default' had no parseable default route) - cannot set up NAT for the namespace"
  fi

  # NAT: only the namespace's own point-to-point address may be
  # masqueraded, and only FORWARD traffic to/from this run's veth is
  # permitted - both scoped as tightly as the plumbing allows, and both
  # reversed exactly (section 6) rather than left as a standing rule.  The
  # IPv6 rules reuse the SAME detected egress interface as the IPv4 ones: on
  # the overwhelmingly common single-NIC dual-stack host this is correct,
  # and a host whose IPv6 route to the outside world genuinely leaves via a
  # different interface is a stated, narrow limitation (not a safety gap -
  # the namespace's own route table, not this NAT plumbing, is what makes
  # an unadmitted destination unreachable; picking the "wrong" egress
  # interface here can only break reachability for admitted v6 addresses,
  # never widen what is reachable).
  _netns_add_nat_rule 4 nat POSTROUTING -s "${ns_addr}/32" -o "$RUN_NETNS_EGRESS_IF" -j MASQUERADE
  _netns_add_nat_rule 4 filter FORWARD -i "$RUN_NETNS_VETH_HOST" -o "$RUN_NETNS_EGRESS_IF" -j ACCEPT
  _netns_add_nat_rule 4 filter FORWARD -i "$RUN_NETNS_EGRESS_IF" -o "$RUN_NETNS_VETH_HOST" \
    -m state --state ESTABLISHED,RELATED -j ACCEPT
  _netns_add_nat_rule 6 nat POSTROUTING -s "${ns_addr6}/128" -o "$RUN_NETNS_EGRESS_IF" -j MASQUERADE
  _netns_add_nat_rule 6 filter FORWARD -i "$RUN_NETNS_VETH_HOST" -o "$RUN_NETNS_EGRESS_IF" -j ACCEPT
  _netns_add_nat_rule 6 filter FORWARD -i "$RUN_NETNS_EGRESS_IF" -o "$RUN_NETNS_VETH_HOST" \
    -m state --state ESTABLISHED,RELATED -j ACCEPT
}

# ---------------------------------------------------------------------------
# 6. Teardown - unconditionally, on success AND failure (this ticket's AC6),
#    reversing exactly what _netns_build created, in reverse order, and
#    never itself failing (it runs from the EXIT trap - same discipline as
#    lib/core.sh's core_cleanup / erase_dir).
# ---------------------------------------------------------------------------
_netns_teardown() {
  local entry family table chain argstr args
  for entry in "${RUN_NETNS_NAT_RULES[@]+"${RUN_NETNS_NAT_RULES[@]}"}"; do
    family=${entry%%|*}
    local rest=${entry#*|}
    table=${rest%%|*}
    rest=${rest#*|}
    chain=${rest%%|*}
    argstr=${rest#*|}
    args=()
    local part
    while IFS= read -r -d $'\x1f' part; do
      args+=("$part")
    done <<<"$argstr"
    local bin=iptables
    [[ $family == 6 ]] && bin=ip6tables
    local table_flag=(-t "$table")
    [[ $table == filter ]] && table_flag=()
    "$bin" "${table_flag[@]+"${table_flag[@]}"}" -D "$chain" "${args[@]+"${args[@]}"}" 2>/dev/null || true
  done
  RUN_NETNS_NAT_RULES=()

  if (( RUN_NETNS_IPFWD_CHANGED )); then
    sysctl -w net.ipv4.ip_forward="${RUN_NETNS_IPFWD_ORIG:-0}" >/dev/null 2>&1 || true
    RUN_NETNS_IPFWD_CHANGED=0
  fi
  if (( RUN_NETNS_IP6FWD_CHANGED )); then
    sysctl -w net.ipv6.conf.all.forwarding="${RUN_NETNS_IP6FWD_ORIG:-0}" >/dev/null 2>&1 || true
    RUN_NETNS_IP6FWD_CHANGED=0
  fi

  if (( RUN_NETNS_VETH_CREATED )); then
    # Deleting either end of a veth pair deletes the peer too, even if the
    # peer now lives in a different (or already-deleted) namespace.
    ip link del "$RUN_NETNS_VETH_HOST" 2>/dev/null || true
    RUN_NETNS_VETH_CREATED=0
  fi

  if (( RUN_NETNS_NS_CREATED )); then
    # Deleting the namespace also destroys its entire route table, its
    # veth-ns end (if somehow not already gone), and everything else scoped
    # to it - this is the kernel doing the bulk of "tear down all
    # namespace/veth/route state" for us.
    ip netns del "$RUN_NETNS_NAME" 2>/dev/null || true
    RUN_NETNS_NS_CREATED=0
  fi
}

# ---------------------------------------------------------------------------
# 7. Main
# ---------------------------------------------------------------------------
_netns_main() {
  trap _netns_on_exit EXIT

  # Argument parsing (including -h/--help) comes first, deliberately ahead
  # of the Linux/privilege checks below: --help must work on any host so an
  # operator on the "wrong" platform can still read why, and a bad usage
  # error is cheaper to report than an environment check. Every path that
  # can actually reach a wrapped command still goes through
  # _netns_require_linux and _netns_require_privilege before anything
  # privileged happens (this ticket's ACs 3 and 4).
  _netns_parse_args "$@"
  _netns_require_linux
  _netns_require_privilege
  _netns_require_tools
  _netns_require_ipv6

  (( ${#RUN_NETNS_CMD[@]} > 0 )) || die "$SCOURSH_EXIT_USAGE" "no command given after '--'"

  _netns_build

  log_info "run-in-netns: executing inside '$RUN_NETNS_NAME': ${RUN_NETNS_CMD[*]}"
  local rc=0
  ip netns exec "$RUN_NETNS_NAME" "${RUN_NETNS_CMD[@]+"${RUN_NETNS_CMD[@]}"}" || rc=$?
  exit "$rc"
}

if (( RUN_NETNS_MAIN )); then
  _netns_main "$@"
fi
