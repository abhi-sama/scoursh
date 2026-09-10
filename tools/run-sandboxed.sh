#!/usr/bin/env bash
# tools/run-sandboxed.sh - the macOS Seatbelt runner (docs/FOUNDATION.md
# tension 20, Tier A of the tension-20 macOS-enforcement amendment).
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
# WHY THIS IS NOT tools/run-in-netns.sh's EQUIVALENT, NOT A REPLACEMENT FOR
# IT.  Seatbelt's network address filter accepts only `*` or `localhost` as
# the host part of a `(remote ip "...")` clause - it can restrict *ports*,
# never *which remote host* - so unlike the netns tool's per-target route
# table, this profile cannot express "only the authorised scope target is
# reachable".  What it CAN express, and what this tool ships, is a strictly
# narrower but still genuine guarantee: **no network access of any kind**.
# That is exactly what `sast`/`sca`/`iac` need (docs/FOUNDATION.md §1: those
# three modules make zero network calls by design), so this tool is scoped
# to that claim and no further - it is never proposed as a substitute for
# scope-restricted egress control on `dast`/`cloud`/`network`, which need
# real, target-specific network access to do their job at all.  Restricting
# an authorised target's traffic to loopback-only, the way a future
# `--connect-to`-based relay could, is a SEPARATE, larger change (a real
# edit to lib/http.sh) and is deliberately not this ticket's scope - see the
# tension-20 amendment this ticket makes in docs/FOUNDATION.md for the full
# three-tier picture and why the loopback-relay tier is tracked separately.
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
# WHAT THIS DELIBERATELY IS NOT (Tier B, out of scope for this ticket - see
# the tension-20 amendment in docs/FOUNDATION.md for the full three-tier
# account):
#   - It does not resolve `config/scope.conf`, does not start a loopback
#     relay, and grants no network access to any authorised target. A
#     command that itself needs real network access (dast/cloud/network)
#     is not what this tool is for; wrapping one here means it gets ZERO
#     network access and most likely fails loudly on its own first request
#     - which is the intended, honest outcome for a tool whose only claim is
#     "no network calls happen inside this sandbox", not "only the
#     authorised target is reachable".
#   - It carries no `--scope-conf` equivalent, because there is no scope to
#     resolve: the profile this tool applies is the same fixed deny-all
#     string on every invocation, unconditionally.
#   - It does not depend on, call, or wrap `--paranoid`'s connection-observer
#     mechanism (lib/paranoid.sh) or tools/run-in-netns.sh in any way. All
#     three are independent, peer mechanisms under tension 20's RESOLUTION.
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
# shellcheck source=lib/core.sh
source "$RUN_SANDBOXED_DIR/lib/core.sh"

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

_sbx_usage() {
  cat <<'EOF'
usage: tools/run-sandboxed.sh -- <command> [args...]

Runs <command> under the macOS Seatbelt profile
"(version 1)(allow default)(deny network*)" via `sandbox-exec`: <command> and
every descendant process it spawns is kernel-refused from opening any
network socket, before a single packet is sent. This makes the "sast/sca/iac
make zero network calls" claim kernel-enforced instead of merely asserted.

Requires: macOS (Darwin) and `sandbox-exec` on PATH. No root, no
capabilities - that is this tool's whole advantage over
tools/run-in-netns.sh. Fails immediately, before <command> ever runs, if
either requirement is not met, or if `sandbox-exec` itself rejects the fixed
profile.

  -h, --help          print this message and exit 0

Example:
  tools/run-sandboxed.sh -- scan.sh sast --path .

This tool restricts <command> to NO network access at all - it has no
concept of an authorised scope target, unlike tools/run-in-netns.sh, and is
therefore suited to sast/sca/iac (which need none) and not to dast/cloud/
network (which need real access to their declared target). It is never
invoked by scan.sh, and does not depend on or wrap `--paranoid` or
tools/run-in-netns.sh - independent, peer mechanisms under
docs/FOUNDATION.md tension 20. See docs/USAGE.md for the full three-tier
account (this tool is "Tier A"; a Linux container running
tools/run-in-netns.sh unmodified is "Tier C").
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
  while (( $# )); do
    case $1 in
      -h | --help)
        _sbx_usage
        exit "$SCOURSH_EXIT_OK"
        ;;
      --)
        shift
        RUN_SANDBOXED_CMD=("$@")
        (( ${#RUN_SANDBOXED_CMD[@]} > 0 )) || die "$SCOURSH_EXIT_USAGE" \
          "missing <command> after '--' (usage: tools/run-sandboxed.sh -- <command...>)"
        return 0
        ;;
      *)
        die "$SCOURSH_EXIT_USAGE" "unrecognised argument before '--': '$1' (usage: tools/run-sandboxed.sh -- <command...>)"
        ;;
    esac
  done
  die "$SCOURSH_EXIT_USAGE" "missing '--' separator and <command> (usage: tools/run-sandboxed.sh -- <command...>)"
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
  # through every precondition below first. No teardown to arrange (see this
  # file's header): lib/core.sh's own default `trap core_cleanup EXIT`,
  # armed when it was sourced above, is all that is needed.
  _sbx_parse_args "$@"

  _sbx_require_darwin
  _sbx_require_sandbox_exec
  _sbx_require_profile_ok
  _sbx_require_command_exists "${RUN_SANDBOXED_CMD[0]}"

  log_info "run-sandboxed: executing under Seatbelt (deny-all-network): ${RUN_SANDBOXED_CMD[*]}"
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
