#!/usr/bin/env bash
# lib/nettransport.sh - the pure-bash TCP connect primitive (NET-03), plus
# the NET-07 read-on-connect primitive added to it below.
#
# Owns:
#   data/scoursh-network-scan-design/report.md §6.2-6.6 (the measured
#     transport decisions this file implements) and the NET-03 row in §7.
#   data/scoursh-network-scan-design/report.md §3.2 item 1, the NET-07 row
#     in §7: "Connect, read up to N bytes with a deadline, close" -
#     `net_read_banner`, section 4 below.  Landed here rather than as a
#     private copy in modules/network/banner_engine.sh because it is a
#     TRANSPORT primitive, not a banner-parsing one - the identical
#     reasoning `net_connect_probe` itself already establishes for this
#     file, one operation further along the same connection lifecycle.
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
      # `module=network`, not the finding-module-field short form `net`
      # (lib/findings.sh's `_fp_profile_for`): every OTHER caller of this
      # `module=` convention (modules/dast/run.sh, modules/cloud/aws/run.sh,
      # scan.sh's own `_scan_apply_profile_filter`) spells it with the
      # SCAN_COMMANDS/checks_module_dir token, which NET-04 fixes at
      # `network`, so that is the token lib/report.sh's `_RPT_MODULES`/
      # `_html_audit_category` grep for here too - a `module=net` line would
      # be invisible to that grep and never render under the Network category
      # in the audit report, which is the exact "declared but not machine-
      # readable" failure AGENTS.md's own dast authz.sh section warns about.
      run_record coverage_reduction "module=network reason=net_probe_cmd_absent - this bash was built without --enable-net-redirections, so no TCP connect can be attempted at all; every port probe on this run reports 'filtered' rather than a real result."
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
# 3. Public entry point (connect classification)
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

# ---------------------------------------------------------------------------
# 4. Read-on-connect (NET-07): connect, read up to MAX_BYTES, close - never
#    writes a byte to the socket.
# ---------------------------------------------------------------------------
# `net_read_banner HOST PORT MAX_BYTES OUTFILE [DEADLINE_MS]` connects to an
# address the CALLER already gated (the identical division of labour
# `net_connect_probe` above documents at its own header - this function
# authorizes nothing) and writes up to MAX_BYTES of whatever the listener
# volunteers, unprompted, into OUTFILE.  OUTFILE always exists afterward, and
# is empty when nothing was read - the caller decides what an empty read
# means (data/scoursh-network-scan-design/report.md §5.2 rule 2: "sent
# nothing" is its own honest outcome, `no_banner`, never folded into a
# connect-failure state).
#
# OUTFILE, NOT STDOUT, IS THE CONTRACT, and that is deliberate: a service's
# own greeting is bytes it chose (report.md §5.3 - "not text by construction"
# one step further out than an HTTP body), so it may contain a NUL byte a
# bash STRING cannot hold at all (AGENTS.md's "Things measured on this
# codebase" - the identical trap `_net_json_flatten`'s own JSON reading
# guards against, one layer up).  A caller that wants text sanitizes the
# file's bytes through a byte-stream tool (e.g. `tr`) before ever assigning
# them to a bash variable - modules/network/banner_engine.sh's own reader
# does exactly that - never through this function's return value.
#
# DEADLINE AND CLASSIFICATION reuse `net_connect_probe`'s own fork-poll-kill
# shape verbatim (§6.1/§6.3), for the identical capability/portability
# reasons that file's header states: `timeout(1)` is absent on macOS, and the
# connect step is a bash builtin redirection (`exec {fd}<>/dev/tcp/...`)
# rather than a forked external command specifically so a SIGTERM delivered
# to the timed subshell interrupts it directly, with nothing to orphan.  The
# READ step keeps that property on purpose: it is bash's own `read -N ... -t
# ...` builtin, never a forked `head`/`dd`, because a forked child blocked on
# its own read(2) would NOT be interrupted by a SIGTERM the PARENT subshell
# receives (only the parent dies; the child becomes an orphan still waiting
# on a socket that may never send more or close) - this was reasoned through
# and rejected before being written, not discovered by a hang.  `read -N` at
# bash 4.2 (this project's frozen minimum, lib/core.sh) returns any bytes
# already read when `-t` times out, so a deadline that fires mid-read still
# yields whatever arrived first, which is normally the whole of a short
# protocol greeting.
_net_read_banner_default() {
  local host=$1 port=$2 max_bytes=$3 outfile=$4 deadline_ms=${5:-$_NET_DEFAULT_DEADLINE_MS}
  : >"$outfile"

  net_probe_capability || return 0

  local dir=$SCOURSH_SCRATCH/nettransport
  mkdir -p "$dir"
  local tag=$BASHPID.$RANDOM.$RANDOM
  local donefile=$dir/banner.$tag.done
  local datafile=$dir/banner.$tag.data
  rm -f "$donefile" "$datafile" "$datafile.tmp"

  (
    trap - ERR
    local frc=0 ffd
    { exec {ffd}<>"/dev/tcp/$host/$port"; } 2>/dev/null || frc=$?
    if [[ $frc -eq 0 ]]; then
      # `read`'s own `-t` is seconds, not milliseconds, and rounds UP so a
      # sub-second deadline never collapses to zero (which bash treats as
      # "poll, do not block" rather than "no time left").  This is a
      # defense-in-depth bound - the OUTER poll-and-kill loop below is the
      # real deadline enforcer, exactly as it is for the plain connect probe
      # above, so a `read` builtin that ignored `-t` entirely would still be
      # bounded by it.
      local chunk='' rt_s=$(( (deadline_ms + 999) / 1000 ))
      (( rt_s < 1 )) && rt_s=1
      IFS= read -r -N "$max_bytes" -t "$rt_s" chunk <&"$ffd" || true
      printf '%s' "$chunk" >"$datafile.tmp"
      exec {ffd}>&- 2>/dev/null || true
      mv -f "$datafile.tmp" "$datafile" 2>/dev/null || true
    fi
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

  if [[ ! -e $donefile ]]; then
    # The deadline elapsed with the subshell still connecting or reading, or
    # it is gone without ever writing a result.  Either way `$datafile` was
    # never renamed into place (the write-then-rename above only happens on
    # a graceful finish), so OUTFILE stays empty - a killed attempt reports
    # the same honest "nothing captured" outcome as a listener that truly
    # sent nothing, which is the correct fold: report.md §5.2 rule 2 names
    # exactly one skip reason for this check, `no_banner`, not a second one
    # for "we could not tell in time".
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  [[ -f $datafile ]] && mv -f "$datafile" "$outfile"
  rm -f "$donefile" "$donefile.tmp" "$datafile" "$datafile.tmp" 2>/dev/null || true
  return 0
}

# `net_read_banner HOST PORT MAX_BYTES OUTFILE [DEADLINE_MS]` - public entry
# point.  `SCOURSH_NET_BANNER_PROBE` names a function (or executable) taking
# the same five positional arguments and writing to OUTFILE, replacing the
# whole real-socket path below - the identical `SCOURSH_NET_PROBE` idiom this
# file's own connect probe already uses, so a test suite never opens a real
# socket for a banner read either.
net_read_banner() {
  local host=${1:-} port=${2:-} max_bytes=${3:-} outfile=${4:-} deadline_ms=${5:-$_NET_DEFAULT_DEADLINE_MS}
  if [[ -z $host || -z $port || -z $max_bytes || -z $outfile ]]; then
    log_error "nettransport: net_read_banner requires HOST, PORT, MAX_BYTES and OUTFILE"
    return 1
  fi
  "${SCOURSH_NET_BANNER_PROBE:-_net_read_banner_default}" "$host" "$port" "$max_bytes" "$outfile" "$deadline_ms"
}
