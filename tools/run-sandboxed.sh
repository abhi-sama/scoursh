#!/usr/bin/env bash
# tools/run-sandboxed.sh - the macOS Seatbelt runner (docs/FOUNDATION.md
# tension 20, Tiers A and B of the tension-20 macOS-enforcement amendment).
#
# TWO MODES, AND THE FLAG IS THE WHOLE DIFFERENCE.
#   `-- <command...>`                    Tier A: deny ALL network access.
#   `--scope-conf F -- <command...>`     Tier B: deny all network access
#                                        EXCEPT one loopback relay per
#                                        authorised (address, port) in F,
#                                        each forwarding to exactly that
#                                        target - so dast/cloud become
#                                        runnable under a real kernel
#                                        restriction. See section 1b for the
#                                        mechanism and for why its label is a
#                                        distinct third one rather than
#                                        "guarantee" or "detector".
#
# Owns:
#   docs/FOUNDATION.md tension 20 ("What macOS still does NOT get" - the
#                       paragraph this ticket amends to add Tier A and
#                       Tier C alongside the existing detector/`lsof` half)
#   docs/USAGE.md       the operator-facing section documenting this tool
#                       and its Tier C sibling route, right after
#                       `--paranoid`'s own section
#
# WHAT THIS IS.  An UNPRIVILEGED macOS peer of tools/run-in-netns.sh:
# `tools/run-sandboxed.sh -- <command...>` runs <command> under the Seatbelt
# profile `(version 1)(allow default)(deny network*)`, via `sandbox-exec`.
# It makes the claim AGENTS.md already asserts about `sast`/`sca`/`iac` -
# "those three modules alone genuinely make zero network calls" -
# KERNEL-ENFORCED instead of merely asserted: any attempt by <command> or any
# descendant it spawns (`man 7 sandbox`: "New processes inherit the sandbox
# of their parent") to open a network socket is refused by the kernel at the
# connect() boundary, before a single packet is sent.
#
# WHY THIS IS NOT tools/run-in-netns.sh's EQUIVALENT, IN EITHER MODE.
# Seatbelt's network address filter accepts only `*` or `localhost` as the
# host part of a `(remote ip "...")` clause, so it cannot name the authorised
# target the way the netns tool's per-target route table does.  `localhost`
# is not port-only and not 127.0.0.1-only either: MEASURED, it admits any
# address belonging to THIS HOST on the named port, and denies every off-host
# address on every port (section 1b carries the four-row measurement and the
# probe that actually discriminates).  So:
#   - Tier A expresses **no network access of any kind**, which is exactly
#     what `sast`/`sca`/`iac` need (docs/FOUNDATION.md §1: those three
#     modules make zero network calls by design) and makes that claim
#     kernel-enforced rather than asserted.
#   - Tier B expresses **no OFF-HOST access of any kind, plus these loopback
#     relay ports**, and scoursh's own relay - not the kernel - is what makes
#     the bytes on those ports go to the authorised target.  That split is
#     why Tier B is labelled "containment guarantee, target restriction by
#     relay" rather than being folded into either of tension 20's two
#     existing words; under the netns tool the kernel enforces both halves,
#     and that difference is real.
#
# THE CAPTAIN'S DECISION THIS TICKET IMPLEMENTS: sandbox-exec is ACCEPTED as
# load-bearing despite being nine years deprecated (`man sandbox-exec`,
# dated March 9, 2017) and still fully functional - Apple's own system
# daemons depend on the underlying facility - WITH fail-loud-on-absence:
# this tool refuses (exit 4) and NEVER silently runs <command> unsandboxed.
# There is no degraded mode here. If sandbox-exec is ever removed from a
# future macOS, this tool stops working outright rather than quietly
# becoming a no-op; the documented fallback for that host is Tier C
# (docs/USAGE.md), a Linux container with `tools/run-in-netns.sh` run
# inside it unmodified, never a degraded unsandboxed run of this tool.
#
# CONTRACT, MIRRORING tools/run-in-netns.sh SECTION FOR SECTION:
#   - Preconditions, before any action, in this order: `uname -s` is
#     `Darwin` (else exit 4, <command> never runs - the exact shape
#     `_netns_require_linux` uses for its own platform check); `sandbox-exec`
#     is on PATH (else exit 4); the fixed deny-all profile is one
#     `sandbox-exec` itself accepts (else exit 4 - see "PRE-VALIDATION,
#     NEVER A LIVE FIRST ATTEMPT" below); <command>'s first token resolves
#     to something executable (else exit 4). NO root and NO capability
#     check are required at any point - that absence is this tier's
#     headline advantage over the netns tool.
#   - Fail loud, never degrade. Every one of the four preconditions above
#     goes through `die`, which always terminates the process; there is no
#     code path that logs a warning and proceeds unsandboxed.
#   - Exit codes. Real `sandbox-exec` failures are sysexits codes (65 for a
#     rejected profile, 71 for `execvp()` of a missing command), which sit
#     OUTSIDE scoursh's frozen 0-5 contract (docs/FOUNDATION.md tension 14).
#     Both are pre-validated away before the real invocation (see below), so
#     the ONLY way `sandbox-exec`'s own exit status can reach the caller of
#     this script is if a `sandbox-exec` failure of the pre-validated kind
#     somehow still occurs at the real invocation - which the pre-validation
#     is specifically built to make impossible in the ordinary case. The
#     WRAPPED command's own exit status is otherwise forwarded VERBATIM
#     (measured: 0/3/5 pass through unchanged) - the identical
#     transparent-wrapper rule tools/run-in-netns.sh section 1 states for
#     itself, for the identical reason: a scoursh module invoked through
#     this wrapper is itself contractually bound to exit 0-5, and this tool
#     must report what it actually returned rather than launder it.
#   - Teardown: none needed, and that is the point. There is no namespace,
#     no veth, no sysctl, no iptables rule, no global host state of any
#     kind - the sandbox is scoped to the process tree it was applied to
#     and dies with it. A crashed run leaves nothing behind on the host,
#     which is strictly better than the netns tool's own (already
#     well-contained, but non-empty) teardown surface. Consequently this
#     script does NOT override lib/core.sh's own `trap core_cleanup EXIT`
#     the way tools/run-in-netns.sh's `_netns_on_exit` does - there is no
#     privileged state of this tool's own to reverse, so the default trap
#     lib/core.sh already installs at source time (`core_install_traps`,
#     called unconditionally when it is sourced) is all that is needed:
#     it erases the scratch directory and preserves whatever exit status
#     this script's own `exit "$rc"` set.
#   - PRE-VALIDATION, NEVER A LIVE FIRST ATTEMPT. The fixed profile is
#     applied to a known-good, side-effect-free command (`/usr/bin/true`,
#     present on every Darwin install) before <command> is ever touched -
#     never validated by running <command> itself under a possibly-bad
#     profile and inspecting the result, which would leak a raw 65 out of
#     this tool on a rejected profile instead of a contractual exit 4, and
#     would make a profile-rejection failure indistinguishable from
#     <command>'s own exit status for an arbitrary wrapped command (an
#     arbitrary command is under no obligation to stay inside scoursh's own
#     0-5 contract the way a scoursh module is).
#   - Profile via `-p`, built in memory as a literal, fixed string with no
#     substitution of caller-controlled data. No file ever touches disk, so
#     there is no predictable-scratch-path/symlink surface of the kind this
#     project's own `cors_engine.sh` scratch-path defect (docs/FOUNDATION.md
#     "Sharp edges") had to be fixed for.
#   - Never invoked by scan.sh; run deliberately, exactly like
#     tools/run-in-netns.sh.
#
# WHAT THIS DELIBERATELY IS NOT, IN EITHER MODE:
#   - It is never invoked by scan.sh; it is run deliberately, exactly like
#     tools/run-in-netns.sh, and it does not depend on, call, or wrap
#     `--paranoid`'s connection observer (lib/paranoid.sh) or the netns tool.
#     All three are independent, peer mechanisms under tension 20's
#     RESOLUTION.
#   - Tier A grants no network access to any authorised target and has no
#     concept of one. Wrapping a `dast`/`cloud` command in Tier A means it
#     gets ZERO network access and fails loudly on its own first request -
#     the intended, honest outcome. `--scope-conf` is the mode for those.
#   - Tier B does NOT redirect the raw TLS handshake
#     `modules/dast/passive/tls.sh` opens through tension 19's transport
#     exception: that socket is opened by the module itself, goes off-host,
#     and is therefore kernel-refused inside the sandbox. It fails CLOSED,
#     which is the safe direction, and is a stated gap - see lib/http.sh
#     section 7a's own note.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

# A test suite sources this file to reach individual functions (argument
# parsing, the precondition checks, the profile constant) without running
# the main flow or execing anything - the exact same dual-mode idiom
# tools/run-in-netns.sh and scan.sh both use for the same reason.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  RUN_SANDBOXED_MAIN=1
else
  RUN_SANDBOXED_MAIN=0
fi

RUN_SANDBOXED_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# -x back-edge cut: lib/http.sh below reaches lib/core.sh itself, so following
# this edge too would inline the whole hub chain twice for every consumer of
# this file (docs/CI-RUNBOOK.md, "the memory model"). Lossless - core.sh is
# still inlined once, via the kept edge - and the identical cut
# tools/run-in-netns.sh makes for the identical pair.
# shellcheck source=/dev/null
source "$RUN_SANDBOXED_DIR/lib/core.sh"
# Tier B only: http_scope_load/http_resolve_host, the SAME two functions the
# scope gate itself uses and the same two _netns_collect_target_ips calls -
# never a second resolver.
# shellcheck source=lib/http.sh
source "$RUN_SANDBOXED_DIR/lib/http.sh"

# ---------------------------------------------------------------------------
# 1. The fixed profile - a literal, unconditional deny-all-network string.
#    Overridable ONLY so a test can prove the "profile rejected" fail path
#    for real (a malformed override), never to let an operator or a caller
#    widen what this tool actually enforces - there is no flag or env var
#    documented in --help that changes it.
# ---------------------------------------------------------------------------
RUN_SANDBOXED_PROFILE=${RUN_SANDBOXED_PROFILE:-'(version 1)(allow default)(deny network*)'}

# The known-good, side-effect-free command used to pre-validate the profile
# without ever running <command> itself under an unvalidated one. Present on
# every Darwin install; this path is fixed rather than resolved via PATH so
# validation cannot be redirected by a caller-controlled PATH.
RUN_SANDBOXED_PROBE_CMD=${RUN_SANDBOXED_PROBE_CMD:-/usr/bin/true}

# ---------------------------------------------------------------------------
# 1b. TIER B: the loopback relay and the port-pinned profile
#     (docs/FOUNDATION.md tension 20 - "containment guarantee, target
#     restriction by relay")
# ---------------------------------------------------------------------------
# WHAT --scope-conf ADDS, AND THE ONE THING IT IS NOT.  Without it this tool
# is Tier A and grants ZERO network access.  With it, it resolves the
# authorised scope, starts one forwarder per authorised (address, port)
# OUTSIDE the sandbox, and emits a Seatbelt profile admitting EXACTLY those
# loopback ports and nothing else - so `dast`/`cloud` become runnable under a
# real kernel restriction instead of being simply excluded.
#
# THE LABEL IS A DISTINCT THIRD ONE, DELIBERATELY, AND IT IS NOT "GUARANTEE"
# AND NOT "DETECTOR".  tension 20's whole framing is built on those two words
# and this mechanism is honestly neither, so it gets its own:
# **containment guarantee, target restriction by relay.**  Split by who
# enforces which half:
#   - The KERNEL guarantees that off-host egress is categorically impossible.
#     Every process in the tree - every `xargs -P` worker included, since
#     `man 7 sandbox` makes the sandbox inherited - can open exactly the
#     relay ports, and only to an address of THIS HOST.  That is not sampled
#     and it is not this project's code.
#   - scoursh's OWN RELAY, not the kernel, guarantees that the bytes then go
#     to the authorised target.  The relay is a few lines with a destination
#     fixed at process start, so it is auditable - but it is this project's
#     code, and calling that "the kernel guarantees only the target is
#     reachable" would be an inflation of exactly the kind tension 20 exists
#     to prevent.  Under `tools/run-in-netns.sh` the kernel route table
#     enforces BOTH halves; that is the honest difference, and it is why this
#     is not simply called a guarantee.
#
# WHAT `localhost:PORT` ACTUALLY MEANS, MEASURED - AND WHY THE OBVIOUS TEST
# DOES NOT DISCRIMINATE.  Seatbelt's filter admits an address belonging to
# THIS HOST on that port; it is not restricted to 127.0.0.1, and it is not
# port-only either.  Measured on macOS 26.6.2 with a listener bound to
# 0.0.0.0 and a profile allowing one port P:
#
#   sandboxed -> 127.0.0.1:P        connected
#   sandboxed -> <this host's LAN address>:P    connected
#   sandboxed -> 192.0.2.1:P (TEST-NET-1, off-host)   Operation not permitted
#   sandboxed -> anything:<any other port>            Operation not permitted
#
# The LAN-address row is why a "connect to the LAN address and check it
# fails" test proves nothing on its own: with nothing listening there it
# fails as `Connection refused` whether Seatbelt denied it or not, and the
# only discriminating probe is one against a genuinely OFF-HOST address,
# where a denial is instant `Operation not permitted` and a permit is a
# timeout.  The consequence to state rather than discover: a DIFFERENT
# service already listening on the same port number on another of this
# host's own interfaces would also be reachable from inside.  The relay binds
# 127.0.0.1 only and takes an EPHEMERAL port the kernel just handed it, so
# nothing else holds that port - but the containment claim is "cannot leave
# this host", not "cannot reach any other socket on this host", and the two
# are different sentences.
#
# THE RELAY IS PYTHON, AND THAT CHOICE IS MEASURED RATHER THAN PREFERRED.
# The smallest dependency was wanted and bash cannot supply it: bash's
# `/dev/tcp` can only DIAL, never LISTEN (measured - the failure is
# `bash: connect: ...`, a connect attempt, because there is no listen form of
# the construct at all), so there is no bash-only forwarder to write.  `nc`
# ships with macOS but forwarding between two `nc` processes needs a FIFO for
# the reverse direction and handles one connection at a time, which a scan
# running `--jobs N` workers would serialise; `socat` is not present on a
# stock macOS.  `python3` is present on every macOS with the Command Line
# Tools, gives a concurrent listener in a few lines, and is pre-validated
# here exactly as `sandbox-exec` is - fail loud (exit 4), never a degraded
# run.  The destination is passed as ARGV and never interpolated into the
# program text, so no address can alter the program; the relay accepts no
# instruction over the wire, reads no configuration, and forwards bytes
# between the connection it accepted and the one fixed destination it was
# started for.
#
# THE RELAY IS UNAUTHENTICATED ON LOOPBACK, AND THAT IS A REAL PROPERTY RATHER
# THAN AN OVERSIGHT.  Any process on this host that can reach 127.0.0.1 can
# connect to a live relay and so reach the authorised target through it, for as
# long as the run lasts.  Three things bound it and none of them is "nobody
# will notice": the destination is fixed, so the relay is a path to the target
# the operator already authorised and to nothing else; the port is ephemeral
# and unpublished; and it exists only between the first precondition passing
# and the EXIT trap firing.  What it is NOT suitable for is a multi-user host
# where reaching the target at all is meant to be a privilege - there, a local
# user who finds the port gets the same reach the scan has.  The netns tier has
# no equivalent exposure, because its enforcement is a route table rather than
# a listener, and that is a second real difference behind Tier B's label.
#
# TEARDOWN IS REAL HERE, UNLIKE TIER A.  Relays are children of this process
# and an EXIT trap kills them and closes their listeners on BOTH success and
# failure.  Everything is per-process, per-port, bound to 127.0.0.1: no host
# mutation, nothing global, nothing that outlives the run.  This is the one
# place this tool departs from its own "no teardown surface" header note, and
# the note says Tier A; Tier B has exactly this one piece of state.
RUN_SANDBOXED_SCOPE_CONF=''
RUN_SANDBOXED_RELAY_PIDS=()
RUN_SANDBOXED_RELAY_PORTS=()
RUN_SANDBOXED_MAP_HOST=()
RUN_SANDBOXED_MAP_PORT=()
RUN_SANDBOXED_MAP_ADDR=()
RUN_SANDBOXED_RELAY_PORT_LAST=''

# The interpreter, a FIXED path by default for the same reason
# RUN_SANDBOXED_PROBE_CMD is one: validation and the relay itself must not be
# redirectable by a caller-controlled PATH.  Overridable only so a test can
# drive the absent/unusable-runtime refusal for real.
RUN_SANDBOXED_PYTHON=${RUN_SANDBOXED_PYTHON:-/usr/bin/python3}

# The whole relay.  Held as one constant so it is auditable in one place and
# never touches disk (the same argument the profile string makes for itself).
# It binds 127.0.0.1 on an EPHEMERAL port, prints that port on stdout so the
# parent learns it without guessing, and forwards between each accepted
# connection and sys.argv[1]:sys.argv[2] - which is fixed for the life of the
# process.  There is no path in it that reads a destination from anywhere else.
read -r -d '' RUN_SANDBOXED_RELAY_SRC <<'RELAYEOF' || true
import socket, socketserver, sys, threading
DST = (sys.argv[1], int(sys.argv[2]))
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            up = socket.create_connection(DST, 30)
        except OSError:
            self.request.close()
            return
        def pump(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
            finally:
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t = threading.Thread(target=pump, args=(self.request, up))
        t.daemon = True
        t.start()
        pump(up, self.request)
        t.join()
        up.close()
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
srv = S(("127.0.0.1", 0), H)
sys.stdout.write("%d\n" % srv.server_address[1])
sys.stdout.flush()
srv.serve_forever()
RELAYEOF

_sbx_require_relay_runtime() {
  [[ -x $RUN_SANDBOXED_PYTHON ]] || die "$SCOURSH_EXIT_INPUT" \
    "tools/run-sandboxed.sh --scope-conf: the relay runtime '$RUN_SANDBOXED_PYTHON' is not an executable file. The loopback relay needs it (bash's /dev/tcp can dial but cannot listen, so there is no bash-only forwarder to fall back to - see this file's header). Refusing rather than running <command> with no relay and a deny-all profile, which would look like a contained run and be an untested one."
  "$RUN_SANDBOXED_PYTHON" -c 'import socket, socketserver, threading' >/dev/null 2>&1 \
    || die "$SCOURSH_EXIT_INPUT" \
      "tools/run-sandboxed.sh --scope-conf: the relay runtime '$RUN_SANDBOXED_PYTHON' could not import socket/socketserver/threading. On macOS /usr/bin/python3 is a stub until the Command Line Tools are installed, which is the ordinary cause. Refusing rather than proceeding without a relay."
}

# Resolves the authorised scope into map rows, through lib/http.sh's OWN
# http_scope_load/http_resolve_host - the same two functions
# tools/run-in-netns.sh's _netns_collect_target_ips calls, and never a second
# resolver, so this tool and the scope gate can never disagree about what a
# scope.conf host means.  Resolution happens HERE, outside the sandbox, which
# is the only place it can: inside, DNS is kernel-denied.
#
# THE https -> http:80 RELAXATION IS MIRRORED ON PURPOSE.  http_scope_match
# admits `http` on port 80 for a host whose scope row is `https` (its one
# documented relaxation), so a map built from the scope rows alone would have
# the gate approve a request guarantee mode then has no relay for - a refusal
# whose real cause is this builder, not the operator.  One extra row per https
# host closes it.
_sbx_collect_relay_targets() {
  RUN_SANDBOXED_MAP_HOST=()
  RUN_SANDBOXED_MAP_PORT=()
  RUN_SANDBOXED_MAP_ADDR=()
  http_scope_load "$RUN_SANDBOXED_SCOPE_CONF"
  local n=${#_HTTP_SCOPE_HOST[@]} i host port scheme subs addr
  (( n > 0 )) || die "$SCOURSH_EXIT_INPUT" \
    "tools/run-sandboxed.sh --scope-conf '$RUN_SANDBOXED_SCOPE_CONF': no usable scope target was loaded, so there is nothing to build a relay for. Refusing rather than running <command> under a deny-all profile it was not asked for."
  for (( i = 0; i < n; i++ )); do
    host=${_HTTP_SCOPE_HOST[i]}
    port=${_HTTP_SCOPE_PORT[i]}
    scheme=${_HTTP_SCOPE_SCHEME[i]}
    subs=${_HTTP_SCOPE_SUBS[i]}
    if [[ $subs == true ]]; then
      log_warn "run-sandboxed: scope host '$host' has allow-subdomains: true, and a subdomain cannot be enumerated ahead of time - no relay is built for one. The gate will still admit it and lib/http.sh will then refuse it with exit 3 naming this reason, rather than attempting a connection the sandbox would deny anyway."
    fi
    if [[ $host == *:* ]]; then
      log_warn "run-sandboxed: scope host '$host' is an IPv6 literal and the relay is IPv4-only (it binds and dials over IPv4), so no relay is built for it - it will NOT be reachable from inside the sandbox. This is a stated gap, not a silent drop."
      continue
    fi
    if [[ $host =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      addr=$host
    elif ! addr=$(http_resolve_host "$host"); then
      log_warn "run-sandboxed: DNS resolution failed for scope host '$host' - no relay is built for it, and it will NOT be reachable from inside the sandbox (inside, DNS is kernel-denied, so this address can only be resolved out here)."
      continue
    fi
    if [[ $addr == *:* ]]; then
      log_warn "run-sandboxed: scope host '$host' resolved to the IPv6 address '$addr' and the relay is IPv4-only, so no relay is built for it."
      continue
    fi
    RUN_SANDBOXED_MAP_HOST+=("$host")
    RUN_SANDBOXED_MAP_PORT+=("$port")
    RUN_SANDBOXED_MAP_ADDR+=("$addr")
    if [[ $scheme == https && $port != 80 ]]; then
      RUN_SANDBOXED_MAP_HOST+=("$host")
      RUN_SANDBOXED_MAP_PORT+=(80)
      RUN_SANDBOXED_MAP_ADDR+=("$addr")
    fi
  done
  (( ${#RUN_SANDBOXED_MAP_HOST[@]} > 0 )) || die "$SCOURSH_EXIT_INPUT" \
    "tools/run-sandboxed.sh --scope-conf '$RUN_SANDBOXED_SCOPE_CONF': every scope target was skipped (see the warnings above), so no relay could be built and <command> would have no reachable target at all. Refusing rather than running it under an effectively deny-all profile."
}

# Starts ONE relay for (ADDR, PORT) and sets RUN_SANDBOXED_RELAY_PORT_LAST to
# the ephemeral port it bound.  The port is READ BACK from the relay rather
# than chosen here: picking a port and hoping it is free is a race, and the
# kernel already answers the question.
_sbx_relay_start() {
  local addr=$1 port=$2 portfile rc=0 waited=0 pid
  RUN_SANDBOXED_RELAY_PORT_LAST=''
  portfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/relay-port.XXXXXX") || rc=$?
  (( rc == 0 )) || die "$SCOURSH_EXIT_INPUT" "run-sandboxed: could not create a scratch file for the relay's port"
  chmod 600 "$portfile"
  "$RUN_SANDBOXED_PYTHON" -c "$RUN_SANDBOXED_RELAY_SRC" "$addr" "$port" >"$portfile" 2>/dev/null &
  pid=$!
  RUN_SANDBOXED_RELAY_PIDS+=("$pid")
  # Bounded wait: the relay prints its port and flushes immediately, so this
  # is a startup race and not a poll of anything slow.  A relay that never
  # reports is a hard failure, never a silent "assume it worked".
  while (( waited < 100 )); do
    if [[ -s $portfile ]]; then
      RUN_SANDBOXED_RELAY_PORT_LAST=$(< "$portfile")
      RUN_SANDBOXED_RELAY_PORT_LAST=${RUN_SANDBOXED_RELAY_PORT_LAST%%$'\n'*}
      break
    fi
    kill -0 "$pid" 2>/dev/null || break
    msleep 50
    waited=$(( waited + 1 ))
  done
  rm -f "$portfile"
  [[ $RUN_SANDBOXED_RELAY_PORT_LAST =~ ^[0-9]+$ ]] || die "$SCOURSH_EXIT_INPUT" \
    "run-sandboxed: the relay for $addr:$port did not report a listening port. Refusing rather than emitting a profile with a port nothing is listening on, which would look like a contained run and silently fail every request."
  RUN_SANDBOXED_RELAY_PORTS+=("$RUN_SANDBOXED_RELAY_PORT_LAST")
}

# Kills every relay this process started.  Runs from the EXIT trap, so it must
# never itself fail - the same discipline tools/run-in-netns.sh's own teardown
# states for itself.
_sbx_relays_stop() {
  local pid
  for pid in "${RUN_SANDBOXED_RELAY_PIDS[@]+"${RUN_SANDBOXED_RELAY_PIDS[@]}"}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${RUN_SANDBOXED_RELAY_PIDS[@]+"${RUN_SANDBOXED_RELAY_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
  done
  RUN_SANDBOXED_RELAY_PIDS=()
}

# We override lib/core.sh's own `trap core_cleanup EXIT` in Tier B only, so
# the relays are torn down on EVERY exit path - success, failure, and a die()
# from any precondition after the first relay started.  It replicates what
# core_cleanup would have done afterwards (the same shape
# tools/run-in-netns.sh's _netns_on_exit uses) and preserves the status.
_sbx_on_exit() {
  local status=$?
  _sbx_relays_stop
  if [[ -n ${_SCOURSH_SLEEPFD:-} ]]; then
    exec {_SCOURSH_SLEEPFD}>&- 2>/dev/null || true
    _SCOURSH_SLEEPFD=''
  fi
  if scratch_is_owned_here; then
    erase_dir "$SCOURSH_SCRATCH"
  fi
  return "$status"
}

# Starts one relay per DISTINCT (addr, port) - two scope hosts behind one
# address share a relay, since the relay is keyed by where it dials - and
# builds both the profile and the map from the result.  Sets
# RUN_SANDBOXED_PROFILE and RUN_SANDBOXED_RELAY_MAP.
RUN_SANDBOXED_RELAY_MAP=''

_sbx_start_relays_and_build_profile() {
  local n=${#RUN_SANDBOXED_MAP_HOST[@]} i key addr port relayport allow=''
  local -a seen_key=() seen_port=()
  local j found
  RUN_SANDBOXED_RELAY_MAP=''
  for (( i = 0; i < n; i++ )); do
    addr=${RUN_SANDBOXED_MAP_ADDR[i]}
    port=${RUN_SANDBOXED_MAP_PORT[i]}
    key="$addr:$port"
    found=''
    for (( j = 0; j < ${#seen_key[@]}; j++ )); do
      if [[ ${seen_key[j]} == "$key" ]]; then found=${seen_port[j]}; break; fi
    done
    if [[ -z $found ]]; then
      _sbx_relay_start "$addr" "$port"
      found=$RUN_SANDBOXED_RELAY_PORT_LAST
      seen_key+=("$key")
      seen_port+=("$found")
      allow+="(allow network-outbound (remote ip \"localhost:$found\"))"
      log_info "run-sandboxed: relay 127.0.0.1:$found -> $addr:$port"
    fi
    RUN_SANDBOXED_RELAY_MAP+="${RUN_SANDBOXED_MAP_HOST[i]} $port $addr $found"$'\n'
  done
  RUN_SANDBOXED_PROFILE="(version 1)(allow default)(deny network*)$allow"
}

_sbx_usage() {
  cat <<'EOF'
usage: tools/run-sandboxed.sh [--scope-conf PATH] -- <command> [args...]

Runs <command> under a macOS Seatbelt profile via `sandbox-exec`, so that
<command> and every descendant process it spawns is restricted by the KERNEL
at the connect() boundary, before a single packet is sent.

Two modes:

  (no --scope-conf)   Tier A. The profile is
                      "(version 1)(allow default)(deny network*)": NO network
                      access of any kind. This makes the "sast/sca/iac make
                      zero network calls" claim kernel-enforced instead of
                      merely asserted, and is what those three modules want.

  --scope-conf PATH   Tier B. PATH is read as a scope.conf; its targets are
                      resolved through lib/http.sh's own scope loader and
                      pinned resolver (never a second resolver), one loopback
                      relay is started per authorised (address, port), and
                      the profile admits EXACTLY those relay ports and
                      nothing else. lib/http.sh then redirects every request
                      through them (with `curl --connect-to`, so SNI, the Host
                      header and certificate validation are all preserved).
                      Off-host egress is kernel-impossible; that the bytes on
                      those ports reach the authorised target is guaranteed
                      by scoursh's own relay rather than by the kernel - see
                      docs/FOUNDATION.md tension 20 for why that is named as
                      a distinct third thing.
                      Relays are children of this process and are torn down
                      by an EXIT trap on success and failure alike.

  -h, --help          print this message and exit 0

Requires: macOS (Darwin) and `sandbox-exec` on PATH. No root, no
capabilities - that is this tool's whole advantage over
tools/run-in-netns.sh. Tier B additionally requires a working python3 (the
relay: bash's /dev/tcp can dial but cannot listen). A `curl` that accepts
`--connect-to` (7.49+) is required too and is checked by lib/http.sh itself,
which is the one file permitted to invoke it. Fails immediately, before <command> ever runs, if any
requirement is not met or if `sandbox-exec` rejects the profile - there is no
degraded, unsandboxed mode.

Examples:
  tools/run-sandboxed.sh -- scan.sh sast --path .
  tools/run-sandboxed.sh --scope-conf config/scope.conf -- \
      scan.sh dast --target my-target

Never invoked by scan.sh, and independent of `--paranoid` and
tools/run-in-netns.sh (peer mechanisms under docs/FOUNDATION.md tension 20).
See docs/USAGE.md for the full account; a Linux container running
tools/run-in-netns.sh unmodified is "Tier C".
EOF
}

# ---------------------------------------------------------------------------
# 2. Preconditions that must fail BEFORE any action is attempted - fail
#    loud, never degrade to an unsandboxed run.
# ---------------------------------------------------------------------------
_sbx_require_darwin() {
  local os
  os=$(uname -s)
  if [[ $os != Darwin ]]; then
    die "$SCOURSH_EXIT_INPUT" \
      "tools/run-sandboxed.sh is macOS-only (it wraps Apple's Seatbelt sandbox-exec facility); this host reports '$os'. Refusing to run <command> at all rather than silently proceeding with no isolation. On a non-Darwin host, tools/run-in-netns.sh (Linux) is the peer mechanism - see docs/USAGE.md."
  fi
}

_sbx_require_sandbox_exec() {
  require_cmd sandbox-exec
}

# Applies the fixed profile to a known-good, side-effect-free command and
# checks it actually succeeds, so a rejected profile is caught as a
# contractual exit 4 rather than leaking sandbox-exec's own out-of-contract
# exit 65 out of a REAL invocation of <command>. See this file's own header,
# "PRE-VALIDATION, NEVER A LIVE FIRST ATTEMPT".
_sbx_require_profile_ok() {
  local rc=0
  sandbox-exec -p "$RUN_SANDBOXED_PROFILE" "$RUN_SANDBOXED_PROBE_CMD" >/dev/null 2>&1 || rc=$?
  if (( rc != 0 )); then
    die "$SCOURSH_EXIT_INPUT" \
      "tools/run-sandboxed.sh: sandbox-exec rejected the Seatbelt profile (probe exit $rc, outside scoursh's 0-5 contract). Refusing to run <command> at all rather than proceeding unsandboxed. This is a fail-loud precondition, not a degraded mode: the fallback for a host whose sandbox-exec cannot apply this profile is Tier C (a Linux container running tools/run-in-netns.sh - see docs/USAGE.md), never an unsandboxed run of <command>."
  fi
}

# <command>'s first token must resolve to something executable BEFORE the
# real invocation, so a missing command is this tool's own contractual exit
# 4 rather than sandbox-exec's own out-of-contract exit 71
# (`execvp() ... failed`). `command -v` resolves both a bare PATH-searched
# name and an explicit (relative or absolute) path identically, so no
# special-casing on the presence of a `/` is needed.
_sbx_require_command_exists() {
  local cmd=$1
  command -v -- "$cmd" >/dev/null 2>&1 || die "$SCOURSH_EXIT_INPUT" \
    "tools/run-sandboxed.sh: <command> '$cmd' was not found (not on PATH and not an executable file). Refusing to run it at all rather than letting sandbox-exec's own execvp() failure (exit 71, outside scoursh's 0-5 contract) leak through."
}

# ---------------------------------------------------------------------------
# 3. Argument parsing: `[-h|--help] -- <command...>`
# ---------------------------------------------------------------------------
RUN_SANDBOXED_CMD=()

_sbx_parse_args() {
  RUN_SANDBOXED_CMD=()
  RUN_SANDBOXED_SCOPE_CONF=''
  while (( $# )); do
    case $1 in
      -h | --help)
        _sbx_usage
        exit "$SCOURSH_EXIT_OK"
        ;;
      --scope-conf)
        shift
        (( $# )) || die "$SCOURSH_EXIT_USAGE" "--scope-conf needs a PATH argument"
        RUN_SANDBOXED_SCOPE_CONF=$1
        shift
        [[ -r $RUN_SANDBOXED_SCOPE_CONF ]] || die "$SCOURSH_EXIT_INPUT" \
          "--scope-conf '$RUN_SANDBOXED_SCOPE_CONF' is not readable"
        continue
        ;;
      --)
        shift
        RUN_SANDBOXED_CMD=("$@")
        (( ${#RUN_SANDBOXED_CMD[@]} > 0 )) || die "$SCOURSH_EXIT_USAGE" \
          "missing <command> after '--' (usage: tools/run-sandboxed.sh [--scope-conf PATH] -- <command...>)"
        return 0
        ;;
      *)
        die "$SCOURSH_EXIT_USAGE" "unrecognised argument before '--': '$1' (usage: tools/run-sandboxed.sh [--scope-conf PATH] -- <command...>)"
        ;;
    esac
  done
  die "$SCOURSH_EXIT_USAGE" "missing '--' separator and <command> (usage: tools/run-sandboxed.sh [--scope-conf PATH] -- <command...>)"
}

# ---------------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------------
_sbx_main() {
  # Argument parsing (including -h/--help) comes first, deliberately ahead
  # of the Darwin/sandbox-exec/profile/command checks below - --help must
  # work on any host so an operator on the "wrong" platform can still read
  # why, and a bad usage error is cheaper to report than an environment
  # check. Every path that can actually reach a wrapped command still goes
  # through every precondition below first.
  _sbx_parse_args "$@"

  _sbx_require_darwin
  _sbx_require_sandbox_exec

  # TIER B, and ONLY when --scope-conf was given. Ordered so that every
  # refusal that CAN happen before a relay exists does happen before one
  # exists: the runtime and curl probes are pure checks, the scope resolution
  # touches no listener, and only then is the EXIT trap armed and the first
  # relay started. The trap is armed BEFORE `_sbx_start_relays_and_build_
  # profile`, never after, so a die() from partway through relay startup
  # still tears down the relays that had already come up.
  #
  # RUN_SANDBOXED_PROFILE is rebuilt here, so `_sbx_require_profile_ok` below
  # validates the profile that will ACTUALLY be applied - the port-pinned one
  # - rather than the deny-all default it would otherwise still be holding.
  # Pre-validating a string that is not the one used is the shape of check
  # that passes while proving nothing.
  if [[ -n $RUN_SANDBOXED_SCOPE_CONF ]]; then
    _sbx_require_relay_runtime
    _sbx_collect_relay_targets
    trap _sbx_on_exit EXIT
    _sbx_start_relays_and_build_profile
    export SCOURSH_HTTP_RELAY_MAP=$RUN_SANDBOXED_RELAY_MAP
  fi

  _sbx_require_profile_ok
  _sbx_require_command_exists "${RUN_SANDBOXED_CMD[0]}"

  if [[ -n $RUN_SANDBOXED_SCOPE_CONF ]]; then
    log_info "run-sandboxed: executing under Seatbelt (off-host egress denied; ${#RUN_SANDBOXED_RELAY_PORTS[@]} relay port(s) admitted): ${RUN_SANDBOXED_CMD[*]}"
  else
    log_info "run-sandboxed: executing under Seatbelt (deny-all-network): ${RUN_SANDBOXED_CMD[*]}"
  fi
  local rc=0
  sandbox-exec -p "$RUN_SANDBOXED_PROFILE" "${RUN_SANDBOXED_CMD[@]+"${RUN_SANDBOXED_CMD[@]}"}" || rc=$?
  # An intentional, transparent forward of <command>'s own exit status is not
  # an error for lib/core.sh's ERR trap to re-report - the same reasoning
  # die() already states for itself. Without this, a non-zero $rc here fires
  # the ERR trap a second time from inside the EXIT trap's own
  # `core_cleanup` (its final `return "$status"` is itself a non-zero
  # "command" under `set -Eeuo pipefail`), printing a spurious
  # "command failed" line after the real one - cosmetic only (the forwarded
  # exit CODE is unaffected either way), but needless noise on every
  # non-zero <command>.
  trap - ERR
  exit "$rc"
}

if (( RUN_SANDBOXED_MAIN )); then
  _sbx_main "$@"
fi
