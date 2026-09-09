#!/usr/bin/env bash
# lib/nettransport.sh - the pure-bash TCP connect primitive (NET-03).
#
# Owns:
#   data/scoursh-network-scan-design/report.md §6.2-6.6 (the measured
#     transport decisions this file implements) and the NET-03 row in §7.
#
# `net_connect_probe HOST PORT [DEADLINE_MS]` prints exactly one of three
# states on stdout: `open` / `not-open` / `filtered`.
#
# AUTHORIZATION IS DELIBERATELY NOT HERE.  This function takes an address the
# CALLER already gated - through lib/http.sh's `http_authorize_raw_connection`
# or an equivalent scope check - and connects to it unconditionally.  Adding a
# scope/allowlist check in this file would be a second, divergent copy of that
# gate; there is exactly one chokepoint and it is not this one.  See
# `modules/dast/passive/tls.sh` for the same division of labour applied to a
# raw TLS handshake.
#
# CLASSIFICATION (binding, design report §6.3): rc=0 -> open; deadline fired
# -> filtered; anything else -> not-open.  The connect's own strerror text
# ("Connection refused", "Operation timed out", ...) is kept as EVIDENCE ONLY
# by a caller that wants it and is NEVER the discriminator here - it is
# locale-dependent under glibc (measured: BSD libc does not localize
# strerror, glibc does, so a test written on the BSD leg of
# tools/daily-suite.sh would pass under both the correct and the broken
# reading; only the GNU container leg would catch it).  lib/core.sh:34's
# `export LC_ALL=C` is what makes this safe at all - it is cited here because
# it is load-bearing for this classifier, not because this file sets it.
# Classify on the connect's own exit status and the deadline timer, never on
# message text.
#
# DEADLINE (design report §6.1/§6.3): `timeout(1)` is absent on macOS, so the
# deadline is FORK-POLL-KILL: the connect attempt runs in a background
# subshell that records its own result to a scratch file, this function polls
# with lib/core.sh's `msleep` (the tension-24 capability-measured sleep -
# `read -t </dev/null` does not sleep at all, finding F14), and
# `kill -TERM`s the subshell once the deadline elapses with no result yet.
#
# CAPABILITY (design report §6.2, mirroring lib/paranoid.sh:163's own
# `/dev/udp`-without-`--enable-net-redirections` caveat): a bash built
# without `--enable-net-redirections` has no `/dev/tcp` at all.  Probed once
# per run and degraded to a recorded `coverage_reduction` with a stated
# reason - never assumed present.  The memoized decision is kept in a
# SCRATCH FILE, not only the in-process `_NET_TCP_CAPABLE` variable: the
# natural way a caller consumes this function's stdout contract is
# `state=$(net_connect_probe "$host" "$port")`, which runs the whole call in
# a subshell, and a subshell's writes to a shell variable are discarded the
# moment it exits (AGENTS.md "Things measured on this codebase" - the same
# reason `occurrence_next`/`worker_id_set` SET a variable rather than
# printing one).  An in-process-only memo would therefore re-probe, and
# re-record the reduction, on every single call a real caller makes.  The
# file write is guarded by `mutex_acquire`/`mutex_release`
# (`nettransport-capability`), the tension-16 shared-state-across-`xargs -P`
# -workers pattern lib/core.sh's rate limiter and request budget already
# use, so two workers racing to probe for the first time still write, and
# record, the decision exactly once.
#
# TESTABILITY (the lib/http.sh `SCOURSH_HTTP_TRANSPORT` /
# modules/dast/passive/tls_engine.sh `SCOURSH_TLS_PROBE` idiom, applied
# here): `SCOURSH_NET_PROBE` names a function (or executable) taking
# `(host, port, deadline_ms)` and printing one of `open`/`not-open`/
# `filtered` on stdout.  When set, it REPLACES the whole real-socket path
# below, exactly like the two precedents it mirrors, so a test suite never
# opens a real socket.  `SCOURSH_NET_TCP_CAPABLE` (`0`/`1`) is the matching
# hook for the capability probe alone - the `SCOURSH_PARANOID_FORCE_BACKEND`
# idiom applied here - so a test can exercise the capability-absent degrade
# path deterministically without opening one either.
#
# NOT IN THIS FILE, by design: any module, dispatch entry, phase script, rule
# pack or finding.  Those are NET-04 and later.

set -Eeuo pipefail

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# ---------------------------------------------------------------------------
# 1. Capability probe: does this bash have /dev/tcp at all?
# ---------------------------------------------------------------------------
_NET_TCP_CAPABLE=''

# Loopback only, deliberately: this connect attempt never leaves the host, so
# it needs no scope authorization and carries no scan target - the same
# reasoning that exempts lib/paranoid.sh's own `/dev/udp/127.0.0.1/9` control
# socket.  Port 1 (tcpmux) is almost universally closed, so a WORKING
# /dev/tcp implementation completes this attempt near-instantly with a real,
# socket-layer "connection refused" failure.  A bash built WITHOUT
# --enable-net-redirections instead fails one layer further out, at the
# shell's own open() of the literal path "/dev/tcp/127.0.0.1/1" - which is
# not a real file - because that build never recognises /dev/tcp/HOST/PORT as
# special redirection syntax in the first place.  Those two failures are
# measurably different ("Connection refused" vs "No such file or directory")
# even though both are a nonzero exit status, and the text - not the status -
# is what discriminates capability here.  (This is the one place in this
# file where message text is load-bearing; §6.3's "evidence only" rule is
# about classifying an OPERATOR'S port, a question this probe never asks.)
_NET_CAPABILITY_PROBE_ADDR=127.0.0.1
_NET_CAPABILITY_PROBE_PORT=1

_net_tcp_capability_probe() {
  local err rc=0
  # The fd this opens lives and dies entirely inside the $(...) subshell -
  # there is nothing to close afterward, because the subshell process's own
  # exit reclaims it the same way any process's open descriptors are
  # reclaimed on exit.  An earlier draft closed it from out here instead
  # (`exec {fd}>&-` after the substitution), which referenced a shell
  # variable only the subshell had ever assigned - a stale no-op in this
  # scope (shellcheck SC2030/SC2031 both flag exactly that class of mistake).
  # `fd` itself is never read - only the exec's own success/failure matters -
  # so `local fd` is intentionally write-only here.
  # shellcheck disable=SC2034
  err=$( { local fd; exec {fd}<>"/dev/tcp/$_NET_CAPABILITY_PROBE_ADDR/$_NET_CAPABILITY_PROBE_PORT"; } 2>&1 ) || rc=$?
  (( rc == 0 )) && return 0
  [[ $err != *'No such file or directory'* ]]
}

_net_capability_file() { printf '%s/nettransport-capability' "$SCOURSH_SCRATCH"; }

# Memoized at TWO levels: `_NET_TCP_CAPABLE` is the fast, in-process check for
# the common case of several calls inside one shell (never discarded, since
# nothing here forks a subshell around it); the scratch file is what makes
# the decision - and the coverage_reduction it may cause - survive the
# command-substitution subshell a real caller's `state=$(net_connect_probe
# ...)` runs the whole call inside.  See this file's own header for why an
# in-process variable alone is not enough.
net_probe_capability() {
  if [[ -n $_NET_TCP_CAPABLE ]]; then
    (( _NET_TCP_CAPABLE == 1 ))
    return
  fi
  if [[ -n ${SCOURSH_NET_TCP_CAPABLE:-} ]]; then
    _NET_TCP_CAPABLE=$SCOURSH_NET_TCP_CAPABLE
    (( _NET_TCP_CAPABLE == 1 ))
    return
  fi
  local file
  file=$(_net_capability_file)
  if [[ -r $file ]]; then
    _NET_TCP_CAPABLE=$(<"$file")
    (( _NET_TCP_CAPABLE == 1 ))
    return
  fi
  mutex_acquire nettransport-capability
  if [[ -r $file ]]; then
    # Lost the race to another worker; its decision (and its
    # coverage_reduction, if any) already stands.
    _NET_TCP_CAPABLE=$(<"$file")
  else
    if _net_tcp_capability_probe; then _NET_TCP_CAPABLE=1; else _NET_TCP_CAPABLE=0; fi
    printf '%s' "$_NET_TCP_CAPABLE" >"$file.tmp.$BASHPID"
    mv -f "$file.tmp.$BASHPID" "$file"
    if (( _NET_TCP_CAPABLE == 0 )); then
      log_warn "nettransport: this bash has no /dev/tcp support (built without --enable-net-redirections); every net_connect_probe call degrades to 'filtered' with a recorded reduction"
      run_record coverage_reduction "module=net reason=net_probe_cmd_absent - this bash was built without --enable-net-redirections, so no TCP connect can be attempted at all; every port probe on this run reports 'filtered' rather than a real result."
    fi
  fi
  mutex_release nettransport-capability
  (( _NET_TCP_CAPABLE == 1 ))
}

# ---------------------------------------------------------------------------
# 2. The real /dev/tcp connect, deadline-bounded by fork-poll-kill.
# ---------------------------------------------------------------------------
_NET_DEFAULT_DEADLINE_MS=2000
_NET_POLL_STEP_MS=50

# Runs as the caller of net_connect_probe (never itself backgrounded by the
# caller - the backgrounding happens one level down, inside this function).
_net_connect_default() {
  local host=$1 port=$2 deadline_ms=${3:-$_NET_DEFAULT_DEADLINE_MS}

  net_probe_capability || { printf 'filtered\n'; return 0; }

  local dir=$SCOURSH_SCRATCH/nettransport
  mkdir -p "$dir"
  local donefile=$dir/probe.$BASHPID.$RANDOM.$RANDOM
  rm -f "$donefile" "$donefile.tmp"

  # The connect attempt's own exit status is written to a scratch file rather
  # than read back from `wait`, because this function may `kill -TERM` the
  # subshell before it exits on its own - at that point its exit status is
  # "killed by SIGTERM", which is a fact about the deadline, not about the
  # connect, and must never be reported as `not-open`.  The write is
  # write-then-rename so the poll loop below never observes a partially
  # written result.
  (
    trap - ERR
    local frc=0 ffd
    { exec {ffd}<>"/dev/tcp/$host/$port"; } 2>/dev/null || frc=$?
    [[ $frc -eq 0 ]] && { exec {ffd}>&- 2>/dev/null || true; }
    printf '%s' "$frc" >"$donefile.tmp"
    mv -f "$donefile.tmp" "$donefile"
  ) &
  local pid=$!

  local waited=0
  while (( waited < deadline_ms )); do
    [[ -e $donefile ]] && break
    proc_alive "$pid" || break
    msleep "$_NET_POLL_STEP_MS"
    (( waited += _NET_POLL_STEP_MS ))
  done

  local state
  if [[ -e $donefile ]]; then
    local rc
    rc=$(<"$donefile")
    if [[ $rc == 0 ]]; then state=open; else state=not-open; fi
  else
    # Either the deadline elapsed with the subshell still connecting, or the
    # subshell is gone without ever writing a result (the identical "we
    # never got an answer" fact, from a different cause).  Both are
    # `filtered`, per §6.3's binding rule - never inferred from any message
    # text, and never folded into `not-open` (design report §3.1: "the port
    # did not answer" and "the port refused" are different facts).
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    state=filtered
  fi
  rm -f "$donefile" "$donefile.tmp" 2>/dev/null || true
  printf '%s\n' "$state"
}

# ---------------------------------------------------------------------------
# 3. Public entry point
# ---------------------------------------------------------------------------
net_connect_probe() {
  local host=${1:-} port=${2:-} deadline_ms=${3:-$_NET_DEFAULT_DEADLINE_MS}
  if [[ -z $host || -z $port ]]; then
    log_error "nettransport: net_connect_probe requires HOST and PORT"
    printf 'not-open\n'
    return 1
  fi
  "${SCOURSH_NET_PROBE:-_net_connect_default}" "$host" "$port" "$deadline_ms"
}
