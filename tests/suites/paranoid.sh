#!/usr/bin/env bash
# tests/suites/paranoid.sh - lib/paranoid.sh, the --paranoid connection
# observer and abort mechanism (docs/FOUNDATION.md tension 20).
#
# DETERMINISM (mirrors tests/suites/http.sh's own header exactly, same
# reasoning applied to the sampler instead of the resolver/transport): `ss`
# and `strace` are Linux-only, `lsof` is not installed everywhere either, and
# this suite runs on both userlands (AGENTS.md "GNU/BSD dual-runner"), so
# nothing in the default path depends on any of the three being installed.
# SCOURSH_PARANOID_FORCE_BACKEND stands in for the backend probe (same idiom
# as lib/core.sh's SCOURSH_FORCE_MSLEEP_IMPL) and SCOURSH_PARANOID_SAMPLE
# stands in for the sampler itself (same idiom as lib/http.sh's
# SCOURSH_HTTP_RESOLVE/SCOURSH_HTTP_TRANSPORT), so a passing run here means
# the ALLOWLIST + ABORT WIRING is correct, deterministically, on every host -
# exactly what tension 20 asks the no-egress fixture to prove ("a passing
# test means zero connections outside loopback rather than zero connections
# we did not expect").
#
# ONE SECTION IS HOST-CONDITIONAL AND DELIBERATELY UNMOCKED: "REAL lsof"
# below runs the actual lsof binary against actual sockets, including a full
# `scan_main --paranoid` run that aborts with exit 3 on a real socket held by
# a real descendant.  It is still a NO-EGRESS test: the sockets it opens are
# *connected UDP* sockets, and connect(2) on a UDP socket only records a
# default peer, transmitting nothing - so an RFC 5737 TEST-NET-3 destination
# is observable without a single packet leaving the machine.  On a host with
# no lsof the section prints SKIPPED, which is not a pass (the same
# convention tests/suites/netns.sh uses for its root-requiring section).
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# REGRESSION PROOF (AC2/AC3 of this ticket): manually verified before this
# file was committed by copying the repo to a scratch directory and adding
# `return 0` as the first line of paranoid_addr_allowed's body (the gate
# defeated - every destination reads as allowed).  Re-running this suite
# against that copy failed every "is NOT allowed" / "is refused" assertion
# in the "allowlist building" section (they call the predicate directly)
# plus both "AC2/AC3" cases below (exit 3 became exit 0; no
# PARANOID-EGRESS-VIOLATION finding was written) - 7 failures in total -
# while every "IS allowed" positive case, the AWS-set/backend-probe/exit-4
# sections (which never reach the predicate on a denied path), and the
# already-allowlisted-destination case kept passing.  That is exactly the
# shape defeating one predicate, and only that predicate, should produce.
#
# REGRESSION PROOF FOR THE `lsof` BACKEND (the macOS one), by the same
# method: each mutation below was applied to a scratch copy of lib/paranoid.sh
# and this suite re-run against it, rather than the tests being reasoned about.
# Every one was caught by exactly the case whose own name predicts it:
#
#   peer address read as the LOCAL one (`${peer%%->*}`)     -> 2 failures
#   `-a` dropped so `-i`/`-p` OR instead of AND             -> 0 failures (!)
#   the family-pid check removed (trust lsof `-p` alone)    -> 1 failure
#   the `->` test removed (every `n` line is a destination) -> 1 failure
#   the probe reduced to `command -v lsof`                  -> 1 failure
#   `lsof` moved AHEAD of `strace` in the probe order       -> 1 failure
#   the `lsof` case removed from _paranoid_sample           -> 1 failure
#   the chunk stride raised so the pid list is never split  -> 1 failure
#
# The `-a` row is reported rather than hidden, and it is not a missing test:
# with the family-pid check in place, ORing `-i` and `-p` produces no
# observable difference at all (every extra line lsof then prints is dropped
# either by that check or by the `->` test), so `-a` is a cost control and
# nothing in the output can pin it.  lib/paranoid.sh says the same thing at
# the check itself.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2030/SC2031/SC2329: as tests/suites/scan.sh (assert_status
# subshell-scoping, prose quoting shell syntax, indirect invocation).
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=scan.sh
source "$ROOT/scan.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/paranoid
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Fixture install root: a scope.conf target, a scanner.conf with
# paranoid_allow entries, and a fake /etc/resolv.conf.
# ---------------------------------------------------------------------------
FROOT=$W/root
mkdir -p "$FROOT/config"
cat >"$FROOT/config/scope.conf" <<'EOF'
id: fixture-target
base-url: https://svc.paranoid.fixture.example/api
EOF
cat >"$FROOT/config/scanner.conf" <<'EOF'
id: scanner
paranoid-allow: 198.51.100.7:9443
EOF
RESOLV=$W/resolv.conf
cat >"$RESOLV" <<'EOF'
# fixture resolv.conf - never the real one
nameserver 10.10.10.10
nameserver 10.10.10.11
EOF

_test_resolve() {
  case $1 in
    svc.paranoid.fixture.example) printf '203.0.113.9' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_test_resolve

# =============================================================================
printf -- '\n-- allowlist building: the four sets (docs/FOUNDATION.md tension 20) --\n'
# =============================================================================
# Populated directly in THIS shell (not a subshell) so every assert_status
# call below - each of which subshells only the one predicate call - sees
# the same populated _PARANOID_ADDR/_PARANOID_PORT arrays by ordinary fork
# inheritance.
SCOURSH_INSTALL_ROOT=$FROOT
SCOURSH_RESOLV_CONF=$RESOLV
config_scanner_load
paranoid_allowlist_build

t_case 'loopback (set 3) is allowed on an arbitrary port - the unrestricted half of set 3'
assert_status 0 '127.0.0.1 on an arbitrary port' paranoid_addr_allowed 127.0.0.1 9
assert_status 0 '::1 on an arbitrary port' paranoid_addr_allowed ::1 51234

t_case 'resolv.conf nameserver (set 3) is allowed on port 53 only - fails under the rejected reading (tension 20 option 1: "allowlist anything on port 53")'
assert_status 0 'nameserver:53 allowed' paranoid_addr_allowed 10.10.10.10 53
assert_status 1 'same nameserver address on port 80 is NOT allowed' paranoid_addr_allowed 10.10.10.10 80
assert_status 1 'a non-nameserver address on port 53 is NOT allowed' paranoid_addr_allowed 9.9.9.9 53

t_case 'in-scope resolved target (set 1) is allowed on its authorised port only'
assert_status 0 'resolved scope host:443 allowed' paranoid_addr_allowed 203.0.113.9 443
assert_status 1 'same resolved address on a DIFFERENT port is NOT allowed' paranoid_addr_allowed 203.0.113.9 8080

t_case 'scanner.conf paranoid_allow (set 4) is allowed on its declared addr:port exactly'
assert_status 0 'operator paranoid_allow entry allowed' paranoid_addr_allowed 198.51.100.7 9443
assert_status 1 'same address on a different port is NOT allowed (paranoid_allow is addr:port, not addr:*)' \
  paranoid_addr_allowed 198.51.100.7 80

t_case 'an address in none of the four sets is refused'
assert_status 1 'arbitrary out-of-scope destination refused' paranoid_addr_allowed 203.0.113.99 443

# =============================================================================
printf -- '\n-- AWS set (set 2): empty with a stated reason (no regions.sh yet) --\n'
# =============================================================================
_test_aws_set_no_cloud() {
  SCOURSH_INSTALL_ROOT=$FROOT
  SCOURSH_RESOLV_CONF=$RESOLV
  run_init "$W/aws-note-run"
  config_scanner_load
  SCAN_COMMAND=''
  paranoid_allowlist_build
  grep -q 'set=aws reason=no_aws_scan_this_run addresses=0' "$W/aws-note-run/meta/paranoid_allowlist_note"
}
t_case 'AWS allowlist set 2 records reason=no_aws_scan_this_run when SCAN_COMMAND is not cloud (docs/STEP8-PARANOID-PLAN.md forward-dependency pattern, DAST-09-style)'
assert_status 0 'no-cloud run: AWS set empty with reason=no_aws_scan_this_run' _test_aws_set_no_cloud

_test_aws_set_cloud_unbuilt() {
  SCOURSH_INSTALL_ROOT=$FROOT
  SCOURSH_RESOLV_CONF=$RESOLV
  run_init "$W/aws-note-run-cloud"
  config_scanner_load
  SCAN_COMMAND=cloud
  paranoid_allowlist_build
  grep -q 'set=aws reason=modules_cloud_aws_regions_sh_not_yet_built addresses=0' \
    "$W/aws-note-run-cloud/meta/paranoid_allowlist_note"
}
t_case 'AWS allowlist set 2 records reason=modules_cloud_aws_regions_sh_not_yet_built when SCAN_COMMAND=cloud - modules/cloud/aws/regions.sh genuinely does not exist on this branch'
assert_status 0 'cloud run with no regions.sh: AWS set empty with the unbuilt-module reason' _test_aws_set_cloud_unbuilt

# =============================================================================
printf -- '\n-- unit: _paranoid_family_pids (the descendant-family walk itself) --\n'
# =============================================================================
# QA (round 1) correctly flagged that every case up to this point drives the
# detection mechanism through SCOURSH_PARANOID_SAMPLE, which bypasses
# _paranoid_family_pids, _paranoid_sample_ss, and _paranoid_sample_strace
# entirely - so a regex bug in either parser, or a bug in the fixed-point
# descendant walk, would silently defeat the real observer while this suite
# stayed green.  The three sections below call those functions DIRECTLY,
# with no sampler-level mock in the way, closing that gap.
GRANDCHILD_PIDFILE=$W/family-grandchild.pid

_test_family_walk_probe() {
  local root=$BASHPID
  sleep 30 &
  local child=$!
  # A grandchild, forked from a backgrounded subshell - this is the shape
  # an `xargs -P` worker that itself forks a helper takes, and is exactly
  # what the fixed-point loop (as opposed to a single "direct children
  # only" pass) exists to find.
  rm -f "$GRANDCHILD_PIDFILE"
  ( sleep 30 & echo $! >"$GRANDCHILD_PIDFILE"; wait ) &
  local mid=$!
  local waited=0
  while [[ ! -s $GRANDCHILD_PIDFILE && $waited -lt 100 ]]; do
    msleep 20
    waited=$(( waited + 1 ))
  done
  local grandchild
  grandchild=$(cat "$GRANDCHILD_PIDFILE" 2>/dev/null || true)
  local family ok=1
  family=$(_paranoid_family_pids "$root")
  grep -qx "$root" <<<"$family" || ok=0
  grep -qx "$child" <<<"$family" || ok=0
  grep -qx "$mid" <<<"$family" || ok=0
  [[ -n $grandchild ]] || ok=0
  [[ -n $grandchild ]] && { grep -qx "$grandchild" <<<"$family" || ok=0; }
  kill "$child" "$mid" "$grandchild" 2>/dev/null || true
  wait "$child" "$mid" 2>/dev/null || true
  (( ok ))
}
t_case '_paranoid_family_pids finds the root, a direct child, and a grandchild forked from a backgrounded subshell - fails under a "direct children only" (non-fixed-point) reading'
assert_status 0 'root + child + grandchild all present in the walked family' _test_family_walk_probe

_test_family_walk_excludes_unrelated() {
  local root=$BASHPID
  sleep 30 &
  local child=$!
  # pid 1 always exists and is never a descendant of $root (it is an
  # ancestor of literally everything) - a deterministic "definitely not in
  # this family" probe that needs no fragile "pick an unused pid" guess.
  local family ok=1
  family=$(_paranoid_family_pids "$root")
  grep -qx 1 <<<"$family" && ok=0
  kill "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  (( ok ))
}
t_case '_paranoid_family_pids does NOT include pid 1 (or any other non-descendant) - fails under "treat the whole ps table as the family" (an overly broad reading this must rule out)'
assert_status 0 'pid 1 excluded from the walked family' _test_family_walk_excludes_unrelated

# =============================================================================
printf -- '\n-- unit: _paranoid_sample_ss (the ss -Htnp output parser, pid-filtered) --\n'
# =============================================================================
FAMILY_CHILD_PID=''

_test_ss_canned_output() {
  # Column 4 is local, column 5 is peer (remote) addr:port; the pid is read
  # out of the trailing users:() field.  One line's pid is a real member of
  # the family (the backgrounded sleep below); the other's is pid 1, which
  # _paranoid_family_pids's own test above already established is never a
  # member - so this line must be dropped even though it is syntactically
  # well-formed ss output.
  printf 'ESTAB 0 0 127.0.0.1:51000 203.0.113.5:443 users:(("curl",pid=%s,fd=5))\n' "$FAMILY_CHILD_PID"
  printf 'ESTAB 0 0 127.0.0.1:51001 198.51.100.9:9443 users:(("curl",pid=1,fd=5))\n'
}

_test_sample_ss_probe() {
  local root=$BASHPID
  sleep 30 &
  FAMILY_CHILD_PID=$!
  SCOURSH_PARANOID_SS_CMD=_test_ss_canned_output
  local out
  out=$(_paranoid_sample_ss "$root")
  kill "$FAMILY_CHILD_PID" 2>/dev/null || true
  wait "$FAMILY_CHILD_PID" 2>/dev/null || true
  unset SCOURSH_PARANOID_SS_CMD
  [[ $out == '203.0.113.5 443' ]]
}
t_case '_paranoid_sample_ss parses the peer addr:port out of column 5 and keeps only lines whose pid is in the family - fails if the pid filter or the column/regex parse is broken'
assert_status 0 'ss sample: family-pid line kept as "203.0.113.5 443", non-family pid=1 line dropped' _test_sample_ss_probe

# =============================================================================
printf -- '\n-- unit: _paranoid_sample_strace (the strace -f connect() log parser) --\n'
# =============================================================================
_test_sample_strace_probe() {
  local logfile
  logfile=$(_paranoid_strace_logfile)
  mkdir -p "${logfile%/*}"
  cat >"$logfile" <<'STRACEEOF'
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.5")}, 16) = -1 EINPROGRESS (Operation now in progress)
connect(5, {sa_family=AF_INET6, sin6_port=htons(9443), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_family=AF_INET6}, 28) = -1 EINPROGRESS (Operation now in progress)
this line is neither shape and must be silently skipped, not raised
STRACEEOF
  local out
  out=$(_paranoid_sample_strace)
  rm -f "$logfile"
  [[ $out == $'203.0.113.5 443\n::1 9443' ]]
}
t_case '_paranoid_sample_strace parses both the AF_INET and AF_INET6 connect() shapes strace -f prints, and skips a non-matching line rather than erroring - fails if either regex or the read loop is broken'
assert_status 0 'strace sample: both shapes parsed in order, third line ignored' _test_sample_strace_probe

# =============================================================================
printf -- '\n-- unit: _paranoid_sample_lsof (the `lsof -F pn` parser, pid-filtered) --\n'
# =============================================================================
# The macOS backend.  Driven against CANNED `lsof -F pn` text for the same
# reason the ss section above is: `lsof` is not installed everywhere, and this
# suite must pass on a host without it.  The canned text below is a verbatim
# transcript of what `lsof -w -nP -i -a -p <pids> -F pn` printed on macOS
# 26.5.2 (arm64) while measuring this backend, with the addresses swapped for
# RFC 5737 documentation ranges - the field IDs, the always-present `f` line,
# the `[v6]:port` bracket form and the arrow-less LISTEN form are all real.
LSOF_FAMILY_PID=''

_test_lsof_canned_output() {
  # 1. a family pid with a real IPv4 peer            -> kept
  printf 'p%s\n' "$LSOF_FAMILY_PID"
  printf 'f3\n'
  printf 'n192.168.4.26:58214->203.0.113.5:443\n'
  # 2. the same family pid, IPv6 bracket form        -> kept
  printf 'f4\n'
  printf 'n[2001:db8::1]:58217->[2001:db8::99]:9443\n'
  # 3. the same family pid, a LISTEN socket (no ->)  -> dropped
  printf 'f5\n'
  printf 'n127.0.0.1:19097\n'
  # 4. the same family pid, a fully unbound socket   -> dropped
  #    (`n*:*` is not invented: 24 of them were open on the measuring host)
  printf 'f6\n'
  printf 'n*:*\n'
  # 5. pid 1, syntactically perfect                  -> dropped (not family)
  printf 'p1\n'
  printf 'f7\n'
  printf 'n192.168.4.26:58215->198.51.100.9:9443\n'
}

_test_sample_lsof_probe() {
  local root=$BASHPID
  sleep 30 &
  LSOF_FAMILY_PID=$!
  SCOURSH_PARANOID_LSOF_CMD=_test_lsof_canned_output
  local out
  out=$(_paranoid_sample_lsof "$root")
  kill "$LSOF_FAMILY_PID" 2>/dev/null || true
  wait "$LSOF_FAMILY_PID" 2>/dev/null || true
  unset SCOURSH_PARANOID_LSOF_CMD
  [[ $out == $'203.0.113.5 443\n2001:db8::99 9443' ]]
}
t_case '_paranoid_sample_lsof keeps only the family pid`s CONNECTED sockets, parsing both the IPv4 and the bracketed IPv6 peer form - fails under "take the local address" (field 4 vs field 5 of the arrow), under "trust lsof -p and skip the pid check" (the pid=1 line survives), and under "any n line is a destination" (the LISTEN and `*:*` lines become bogus violations)'
assert_status 0 'lsof sample: two peers parsed, LISTEN/unbound/non-family lines all dropped' _test_sample_lsof_probe

_test_sample_lsof_chunking() {
  # The chunk loop must call the command for EVERY chunk, not just the first.
  # With a 128-pid chunk size, a family of one is a single chunk, so this
  # asserts the loop's arithmetic directly instead: it counts invocations for
  # a synthetic 300-entry pid list.  Fails under a "call lsof once with the
  # whole list" reading (1 invocation) and under an off-by-one chunk stride.
  local countfile=$W/lsof-chunk-count
  : >"$countfile"
  _test_lsof_count_cmd() {
    printf 'x\n' >>"$countfile"
    printf ''
  }
  _test_lsof_big_family() { local i; for (( i = 1000; i < 1300; i++ )); do printf '%s\n' "$i"; done; }
  local saved_family
  saved_family=$(declare -f _paranoid_family_pids)
  eval "_paranoid_family_pids() { _test_lsof_big_family; }"
  SCOURSH_PARANOID_LSOF_CMD=_test_lsof_count_cmd
  _paranoid_sample_lsof 1 >/dev/null
  unset SCOURSH_PARANOID_LSOF_CMD
  eval "$saved_family"
  local n
  n=$(wc -l <"$countfile" | tr -d ' ')
  [[ $n == 3 ]]   # ceil(300 / 128)
}
t_case 'the lsof sampler chunks its pid list rather than passing an unbounded argv - 300 family pids become exactly 3 invocations at a stride of 128'
assert_status 0 '300 pids -> 3 lsof invocations' _test_sample_lsof_chunking

# =============================================================================
printf -- '\n-- backend probe: forced override (SCOURSH_PARANOID_FORCE_BACKEND) --\n'
# =============================================================================
_test_forced_backend_none() {
  SCOURSH_PARANOID_FORCE_BACKEND=none
  paranoid_probe_backend
  [[ $PARANOID_BACKEND == none ]]
}
t_case 'SCOURSH_PARANOID_FORCE_BACKEND=none is honoured by the probe'
assert_status 0 'forced backend=none is read back as none' _test_forced_backend_none

# =============================================================================
printf -- '\n-- backend probe: the ss -> strace -> lsof ORDER (a pinned decision) --\n'
# =============================================================================
# Each case stubs availability rather than depending on which of the three
# tools this host happens to ship, so the ORDER is pinned identically on
# Linux and on macOS.  assert_status runs its command in a subshell, so a
# stub defined inside one of these functions cannot leak into the next.
_test_backend_order() {
  local have_ss=$1 strace_ok=$2 lsof_ok=$3 want=$4
  unset SCOURSH_PARANOID_FORCE_BACKEND
  _have() { [[ $1 == ss && $have_ss == yes ]]; }
  _paranoid_probe_strace() { [[ $strace_ok == yes ]]; }
  _paranoid_probe_lsof() { [[ $lsof_ok == yes ]]; }
  paranoid_probe_backend
  [[ $PARANOID_BACKEND == "$want" ]]
}

t_case 'ss still wins when everything is available - fails under "prefer lsof because it is portable", which would silently change every existing Linux host`s backend'
assert_status 0 'ss + strace + lsof -> ss' _test_backend_order yes yes yes ss
t_case 'strace still beats lsof when ss is absent - fails under "insert lsof ahead of strace"; strace is a TRACER (it sees a connect() that opens and closes between two polls) and lsof is a SAMPLER, so where strace is usable it is the stronger detector'
assert_status 0 'no ss, strace usable, lsof usable -> strace' _test_backend_order no yes yes strace
t_case 'lsof is selected when neither ss nor a usable strace exists - THE macOS CASE; fails under the pre-change reading, where this host resolved to `none` and --paranoid refused the whole run with exit 4'
assert_status 0 'no ss, no strace, lsof usable -> lsof' _test_backend_order no no yes lsof
t_case 'none of the three usable still resolves to `none` - the lsof addition must not turn an unobservable host into a silently-unobserved one'
assert_status 0 'no ss, no strace, no lsof -> none' _test_backend_order no no no none

# =============================================================================
printf -- '\n-- unit: _paranoid_probe_lsof needs a POSITIVE CONTROL, not just an exit code --\n'
# =============================================================================
# lsof exits 1 both when it matched nothing and (on a restricted host) when it
# was not permitted to look, so an exit-status probe cannot tell "no sockets
# open" from "you will never be shown any".  These two cases shadow the real
# `lsof` binary with a bash function - which `command -v` (and therefore
# `_have`) finds - so the discriminating behaviour is exercised on every host,
# including one where the real lsof works perfectly and could never produce
# the restricted case.
_test_lsof_probe_rejects_blind_lsof() {
  unset SCOURSH_PARANOID_FORCE_BACKEND
  # Present on PATH, runs, exits 1, shows nothing: a restricted host.
  lsof() { return 1; }
  ! _paranoid_probe_lsof
}
t_case 'the lsof probe REFUSES a present-but-blind lsof - fails under both rejected readings: "command -v lsof is enough" and "any exit status <= 1 means usable", each of which would attach an observer that can never see anything and report the run as watched'
assert_status 0 'blind lsof: probe returns non-zero' _test_lsof_probe_rejects_blind_lsof

_test_lsof_probe_accepts_reporting_lsof() {
  unset SCOURSH_PARANOID_FORCE_BACKEND
  # Reports the probe's own control socket back, which is the whole test.
  lsof() { printf 'p%s\nf9\nn127.0.0.1:54321->127.0.0.1:9\n' "$BASHPID"; }
  _paranoid_probe_lsof
}
t_case 'the lsof probe ACCEPTS an lsof that reports the control socket back - without this half the case above is satisfiable by a probe that rejects everything'
assert_status 0 'reporting lsof: probe returns 0' _test_lsof_probe_accepts_reporting_lsof

_test_lsof_probe_does_not_swallow_stderr() {
  unset SCOURSH_PARANOID_FORCE_BACKEND
  lsof() { printf 'p%s\nf9\nn127.0.0.1:54321->127.0.0.1:9\n' "$BASHPID"; }
  local errfile=$W/probe-stderr.err
  rm -f "$errfile"
  ( _paranoid_probe_lsof >/dev/null || true; printf 'STDERR-STILL-ALIVE\n' >&2 ) 2>"$errfile"
  [[ -s $errfile ]] || return 1
  local got
  got=$(cat "$errfile")
  [[ $got == *'STDERR-STILL-ALIVE'* ]]
}
t_case 'the lsof probe leaves the calling shell`s STDERR intact - fails under the natural `exec {fd}<>/dev/udp/... 2>/dev/null` spelling, where `exec` with redirections and no command makes 2>/dev/null PERMANENT and silences every log line the rest of the run would print, including the violation message itself, while the exit code stays correct'
assert_status 0 'probe: stderr survives the control-socket open' _test_lsof_probe_does_not_swallow_stderr

# =============================================================================
printf -- '\n-- REAL lsof: the probe and the sampler against sockets this test opens --\n'
# =============================================================================
# Everything above drives the lsof backend through canned text or a stub.
# This section runs the REAL `lsof` binary against REAL sockets, so a defect
# in the actual invocation (a wrong flag, `-a` omitted so `-i`/`-p` OR rather
# than AND, an `-F` field this lsof build does not emit) cannot hide behind a
# fixture.  It is host-conditional and states plainly when it is SKIPPED - a
# SKIP here is not a pass, the same convention tests/suites/netns.sh uses for
# its own root-requiring section.
#
# NO PACKET LEAVES THIS MACHINE, by construction: the sockets below are
# *connected UDP* sockets, and connect(2) on a UDP socket only records a
# default peer - it transmits nothing.  So the out-of-allowlist case can use a
# real RFC 5737 TEST-NET-3 address and still be a genuinely no-egress test,
# which is what tension 20's §12 fixture requires.
if ! command -v lsof >/dev/null 2>&1; then
  printf -- '\n-- SKIPPED: no `lsof` on this host, so the real-backend cases below did NOT run (the canned-output and ordering cases above still did) --\n'
else
  _test_real_lsof_probe() {
    unset SCOURSH_PARANOID_FORCE_BACKEND
    _paranoid_probe_lsof
  }
  t_case '_paranoid_probe_lsof reports usable on a host that really ships lsof - the positive half; the discriminating negative half is the stubbed case below, which this host cannot produce for real'
  assert_status 0 'real lsof probe: usable' _test_real_lsof_probe

  _test_real_lsof_sees_out_of_allowlist() {
    local root=$BASHPID out=''
    # A descendant holding a connected UDP socket to TEST-NET-3 (RFC 5737).
    ( exec 3<>/dev/udp/198.51.100.250/4444 || exit 1; sleep 10 ) &
    local holder=$!
    msleep 300
    out=$(_paranoid_sample_lsof "$root")
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    [[ $out == *'198.51.100.250 4444'* ]]
  }
  t_case 'the REAL lsof sampler observes a real out-of-allowlist socket held by a DESCENDANT of the root pid - fails under a "look at the root pid only" reading (the socket belongs to a child, not to the observer)'
  assert_status 0 'real lsof sample: descendant`s 198.51.100.250:4444 peer observed' _test_real_lsof_sees_out_of_allowlist

  _test_real_lsof_ignores_non_family() {
    # Same real sampler, rooted at a SIBLING of the socket holder.  Deliberately
    # not pid 1: pid 1 is an ANCESTOR of everything, so rooting the walk there
    # would make the whole machine "family" and this case would fail for a
    # reason that says nothing about the -p filter.  Two siblings are the
    # correct shape - neither is a descendant of the other.
    local out=''
    ( sleep 10 ) &
    local unrelated_root=$!
    ( exec 3<>/dev/udp/198.51.100.251/4445 || exit 1; sleep 10 ) &
    local holder=$!
    msleep 300
    out=$(_paranoid_sample_lsof "$unrelated_root") || true
    kill "$holder" "$unrelated_root" 2>/dev/null || true
    wait "$holder" "$unrelated_root" 2>/dev/null || true
    [[ $out != *'198.51.100.251'* ]]
  }
  t_case 'the REAL lsof sampler does NOT report a socket belonging to a process outside the watched family - fails under "drop -p and scan every process on the host", which would abort a run because some unrelated program had a connection open'
  assert_status 0 'real lsof sample: non-family socket not reported' _test_real_lsof_ignores_non_family

  # --- the whole mechanism, unmocked: real backend, real socket, real abort ---
  _test_real_lsof_run_aborts() {
    export SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_RESOLV_CONF=$RESOLV
    export SCOURSH_PARANOID_FORCE_BACKEND=lsof SCOURSH_PARANOID_POLL_MS=20
    unset SCOURSH_PARANOID_SAMPLE
    # Forked HERE, not inside a nested subshell, because paranoid_attach takes
    # $BASHPID of the process running scan_main as the family root - a holder
    # forked inside a nested subshell would not be a descendant of it, and the
    # test would pass for the wrong reason (nothing observed, so no abort).
    # `scan_main` exits this subshell directly on the abort, so the holder is
    # cleaned up by _paranoid_kill_siblings rather than by a line below.
    ( exec 3<>/dev/udp/198.51.100.250/4444 || exit 1; sleep 30 ) &
    scan_main sast --paranoid --out "$W/run-real-lsof-violation"
  }
  t_case 'END TO END, nothing mocked: a real out-of-allowlist socket held by a descendant of a real `scan_main --paranoid` run, observed by the real lsof sampler, aborts the run with exit 3 - this is the case that was IMPOSSIBLE on macOS before this change, where the same run exited 4 before dispatching a single module'
  assert_status "$SCOURSH_EXIT_SCOPE" 'real lsof end-to-end: exit 3' _test_real_lsof_run_aborts

  _test_real_lsof_run_clean() {
    export SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_RESOLV_CONF=$RESOLV
    export SCOURSH_PARANOID_FORCE_BACKEND=lsof SCOURSH_PARANOID_POLL_MS=20
    unset SCOURSH_PARANOID_SAMPLE
    # Identical shape, and forked from the same place for the same reason as
    # above, but the peer is loopback - allowlist set 3.  scan_main exits this
    # subshell on success too, so the holder is left to expire on its own
    # (it is orphaned, holds one loopback UDP socket, and blocks nothing).
    ( exec 3<>/dev/udp/127.0.0.1/9 || exit 1; sleep 30 ) &
    scan_main sast --paranoid --out "$W/run-real-lsof-clean"
  }
  t_case 'END TO END, nothing mocked: the SAME shape with an allowlisted (loopback) peer completes normally - fails under "abort on any observed connection", and without this half the case above is satisfiable by a detector that aborts everything'
  assert_status "$SCOURSH_EXIT_OK" 'real lsof end-to-end: allowlisted peer, exit 0' _test_real_lsof_run_clean
fi

# =============================================================================
printf -- '\n-- AC4: no usable backend at all -> exit 4 (SCOURSH_EXIT_INPUT) --\n'
# =============================================================================
t_case '--paranoid with no usable backend dies exit 4, not silently running unobserved'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=none assert_status "$SCOURSH_EXIT_INPUT" \
  'no ss/strace: exit 4' scan_main sast --paranoid --out "$W/run-no-backend"

# =============================================================================
printf -- '\n-- AC5 (deterministic no-egress fixture): clean run, zero non-loopback --\n'
# =============================================================================
# The scripted samplers below are the "recorded mock response" tension 20
# asks for, applied to the OBSERVER rather than to DNS: each reports exactly
# what a real ss/strace sampler would see for a specific, scripted run -
# deterministic on every host, unlike a real ss/strace capture would be.
#
# DEVIATION FROM AC5'S LITERAL TEXT, STATED EXPLICITLY (QA round 1 flagged
# that round 1's summary reported this as an unqualified pass without
# calling the substitution out - this paragraph is the correction):
# AC5 as written asks for a fixture that runs "against recorded mock
# responses, file:// inputs, and pre-seeded --resolve entries for a
# loopback mock listener."  `modules/dast/` (the only module that would
# ever open an outbound HTTP connection scoursh could point at a loopback
# listener) has not landed on this branch - `scan_main` is driven here with
# `sast`, which never opens a socket at all - so there is currently nothing
# in scoursh that talks to a mock listener in a testable way.  The two
# sections immediately above this one (_paranoid_sample_ss /
# _paranoid_sample_strace) instead prove the PARSERS against canned
# ss/strace-shaped text, and this section and the one below prove the
# ALLOWLIST + ABORT WIRING against a scripted SCOURSH_PARANOID_SAMPLE
# standing in for "whatever a real sampler observed."  Between the two, the
# whole pipeline (parse -> filter -> allowlist -> abort) is exercised
# deterministically end-to-end, without a real loopback listener - but it is
# not literally what AC5 describes, and a real loopback-listener fixture
# (once modules/dast/ exists to generate real outbound connections to
# assert against) is follow-up work, not something this ticket built.
_test_paranoid_sample_clean() {
  printf '127.0.0.1 4321\n'
  printf '::1 53\n'
}

t_case 'a run whose only observed connections are loopback completes normally (exit 0), never aborting'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_clean SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_OK" 'clean loopback-only run exits 0 under --paranoid' \
  scan_main sast --paranoid --out "$W/run-clean"

t_case 'the clean run states the "detector, not guarantee" framing in run.json (the report output, AC6) - not just in docs'
RUNJSON=$(cat "$W/run-clean/run.json" 2>/dev/null || true)
assert_contains "$RUNJSON" 'detector' 'run.json coverage_gap mentions the mechanism is a detector'
assert_contains "$RUNJSON" 'run-in-netns' 'run.json coverage_gap names tools/run-in-netns.sh as the actual guarantee'

# =============================================================================
printf -- '\n-- AC2/AC3: an out-of-allowlist connection aborts the run, exit 3 --\n'
# =============================================================================
_test_paranoid_sample_violation() {
  printf '203.0.113.250 4444\n'   # TEST-NET-3 (RFC 5737); in none of the four sets
}

t_case 'a connection outside the four-set allowlist aborts the run with exit 3 (SCOURSH_EXIT_SCOPE), not a warning'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_violation SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_SCOPE" \
  'out-of-allowlist connection: exit 3, fails under "log a warning and continue" (tension 20 option 2, rejected)' \
  scan_main sast --paranoid --out "$W/run-violation"

_test_violation_finding_written() {
  local f
  for f in "$W"/run-violation/shards/*.jsonl; do
    [[ -e $f ]] || continue
    grep -q 'PARANOID-EGRESS-VIOLATION' "$f" && return 0
  done
  return 1
}
t_case 'the abort is auditable: a PARANOID-EGRESS-VIOLATION finding is written (mirrors lib/http.sh _http_gate_audit)'
assert_status 0 'violation finding recorded in a shard' _test_violation_finding_written

# =============================================================================
printf -- '\n-- an allowlisted destination never aborts, under the same backend/poll wiring --\n'
# =============================================================================
_test_paranoid_sample_allowed_only() {
  printf '198.51.100.7 9443\n'   # exactly the scanner.conf paranoid_allow entry
}
t_case 'an allowlisted (operator paranoid_allow) destination does not trip the observer - fails under "abort on ANY sampled connection" (an overly broad reading this suite must also rule out)'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_allowed_only SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_OK" 'allowlisted destination: exit 0' \
  scan_main sast --paranoid --out "$W/run-allowed-only"

# =============================================================================
printf -- '\n-- --paranoid absent: zero behaviour change (no attach, no observer) --\n'
# =============================================================================
t_case 'without --paranoid, a run with no usable backend still succeeds (the observer is never engaged)'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=none assert_status "$SCOURSH_EXIT_OK" \
  'no --paranoid flag: exit 0 regardless of backend availability' \
  scan_main sast --out "$W/run-no-paranoid"

t_summary paranoid
