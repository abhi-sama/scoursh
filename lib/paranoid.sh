#!/usr/bin/env bash
# lib/paranoid.sh - the --paranoid connection observer and abort mechanism.
#
# Owns:
#   docs/DESIGN.md    §2 ("Paranoid mode"), §13 step 8
#   docs/FOUNDATION.md tension 20 (paranoid mode versus infrastructure traffic
#                      - the frozen RESOLUTION this file implements: the
#                      four-set allowlist, process-group-level attachment,
#                      exit 3 on violation, exit 4 when neither ss nor a
#                      usable strace is available, and the "detector, not
#                      guarantee" framing)
#   docs/STEP8-PARANOID-PLAN.md PARANOID-01 (this ticket's own sub-ticket row)
#
# THE FRAMING (stated here because tension 20 requires it stated plainly, not
# just implied): --paranoid is a DETECTOR, not a guarantee.  It samples
# outbound connections on a timer and aborts the run on the first destination
# it observes outside the allowlist.  A sufficiently short-lived connection
# can open and close between two samples and never be observed at all.
# `tools/run-in-netns.sh` (NETNS-01, not built by this ticket - see
# docs/STEP8-PARANOID-PLAN.md) is the actual guarantee: a network namespace
# whose only route is the declared scope makes an out-of-scope connection
# categorically impossible rather than merely observable.  This framing is
# recorded into every run's `run.json` (via `coverage_gap`, read by both
# lib/report.sh limitations sections) whenever --paranoid is engaged, so the
# report never overstates what the mechanism proved (docs/DESIGN.md §15).
#
# WHAT THIS FILE DOES NOT DO: attach to a Linux cgroup directly (that needs
# root or a systemd-managed unit, neither of which this ticket assumes).  The
# RESOLUTION text says "ss sampling filtered by the run's cgroup OR process
# group" - the portable, unprivileged reading of that is "every process this
# run itself forked", which this file implements as the DESCENDANT-PROCESS
# FAMILY rooted at the main scan.sh pid (_paranoid_family_pids below), not
# the raw OS process group (`ps -o pgid=`).  That distinction is deliberate,
# not decorative: a plain `cmd &`/`( ... )` never changes pgid, so scan.sh's
# own pgid is whatever process group ITS OWN invoker happens to be in - an
# interactive shell, a wrapper script that `source`s it, or (measured
# directly while building this ticket, the hard way: it took out the test
# harness driving this suite) this project's own test runner - none of which
# call `setsid` to give scan.sh a process group of its own.  Killing "the
# process group" on a violation would then reach every unrelated sibling
# sharing that group, not just this run's own children.  Every `xargs -P`
# worker IS a descendant of the invoking scan.sh process regardless of pgid,
# so walking the descendant tree gets AC3's "not per-pid" coverage without
# that blast radius.
#
# TESTABILITY (docs/DESIGN.md §12, and consistent with lib/http.sh's own
# SCOURSH_HTTP_RESOLVE / SCOURSH_HTTP_TRANSPORT precedent): the connection
# SAMPLER is swappable via SCOURSH_PARANOID_SAMPLE (a function name), exactly
# like http.sh's resolver/transport hooks, so tests/suites/paranoid.sh can
# feed the abort logic a deterministic, scripted sequence of "observed"
# connections instead of depending on real `ss`/`strace` output, which is
# unavailable on every non-Linux CI leg (tension 20: "made deterministic by
# removing DNS from it entirely" - the same principle applied here to the
# sampler itself, not just to DNS).  SCOURSH_PARANOID_FORCE_BACKEND overrides
# the ss/strace probe the same way SCOURSH_FORCE_MSLEEP_IMPL (lib/core.sh)
# overrides the msleep probe.
#
# shellcheck shell=bash
#
# SC2329: several functions here are only ever invoked indirectly (through
# the sampler hook, a trap, or a background job), not by a literal call that
# static analysis can follow.
# shellcheck disable=SC2329

if [[ -n ${SCOURSH_PARANOID_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_PARANOID_SOURCED=1

# shellcheck source=lib/http.sh
source "${BASH_SOURCE[0]%/*}/http.sh"

# ---------------------------------------------------------------------------
# 1. Backend probe: `ss`, or a usable `strace -f -e trace=connect`, or none.
# ---------------------------------------------------------------------------
# "Usable" is measured, not assumed (AGENTS.md "Things measured on this
# codebase" is the standing house style for exactly this class of claim):
# strace can be present on PATH and still be unusable under a seccomp
# profile or a restrictive `yama/ptrace_scope`, so the probe actually
# attaches to a disposable child rather than trusting `command -v strace`.
PARANOID_BACKEND=''

_paranoid_probe_strace() {
  _have strace || return 1
  ( exec sleep 2 ) &
  local probe_pid=$! ok=1 spid
  local errfile="$SCOURSH_SCRATCH/paranoid-strace-probe.$BASHPID"
  mkdir -p "$SCOURSH_SCRATCH"
  # Backgrounded deliberately: a synchronous `strace -p` would block this
  # probe for as long as the traced process lives (the probe target is
  # `sleep 2` for exactly that reason - short-lived, disposable, and long
  # enough to outlast the attach check below).  Whether the ATTACH itself
  # succeeded is read from `$spid` still being alive a moment later, never
  # from the background job's own (always-0) start-up exit status.
  strace -f -e trace=connect -o /dev/null -p "$probe_pid" >"$errfile" 2>&1 &
  spid=$!
  msleep 150
  proc_alive "$spid" || ok=0
  kill "$spid" 2>/dev/null || true
  wait "$spid" 2>/dev/null || true
  kill "$probe_pid" 2>/dev/null || true
  wait "$probe_pid" 2>/dev/null || true
  rm -f "$errfile"
  (( ok ))
}

paranoid_probe_backend() {
  if [[ -n ${SCOURSH_PARANOID_FORCE_BACKEND:-} ]]; then
    PARANOID_BACKEND=$SCOURSH_PARANOID_FORCE_BACKEND
  elif _have ss; then
    PARANOID_BACKEND=ss
  elif _paranoid_probe_strace; then
    PARANOID_BACKEND=strace
  else
    PARANOID_BACKEND=none
  fi
  export PARANOID_BACKEND
  run_record paranoid_backend "$PARANOID_BACKEND"
}

# ---------------------------------------------------------------------------
# 2. The four-set allowlist (docs/FOUNDATION.md tension 20 RESOLUTION)
# ---------------------------------------------------------------------------
declare -a _PARANOID_ADDR=() _PARANOID_PORT=() _PARANOID_SET=()

_paranoid_allow_add() {
  _PARANOID_ADDR+=("$1")
  _PARANOID_PORT+=("$2")   # a decimal port number, or '*' for any port
  _PARANOID_SET+=("$3")
}

# Set 3 (infrastructure): parsed from the host's OWN /etc/resolv.conf,
# port 53 only, plus loopback (any port - the resolver entries are
# port-restricted because tension 20 explicitly rejected "allowlist anything
# on port 53" as too wide; loopback has no such worry, since it never
# leaves the host).
_paranoid_allowlist_infra() {
  local resolv=${SCOURSH_RESOLV_CONF:-/etc/resolv.conf} line ip count=0
  _paranoid_allow_add 127.0.0.0/8 '*' infra-loopback
  _paranoid_allow_add ::1 '*' infra-loopback
  if [[ -r $resolv ]]; then
    while IFS= read -r line; do
      if [[ $line =~ ^[[:space:]]*nameserver[[:space:]]+([0-9A-Fa-f:.]+) ]]; then
        ip=${BASH_REMATCH[1]}
        _paranoid_allow_add "$ip" 53 infra-resolver
        count=$(( count + 1 ))
      fi
    done <"$resolv"
  fi
  run_record paranoid_allowlist_note "set=infra reason=parsed_resolv_conf path=$resolv nameservers=$count"
}

# Set 4: config/scanner.conf's `paranoid_allow` list (already shape-validated
# by lib/config.sh as `addr:port`).  Not a CLI flag (rules/RULE-FORMAT.md
# §9.6.1); resolved through the normal CLI>env>file>default chain with no CLI
# layer available for it, matching lib/config.sh's own comment on the key.
_paranoid_allowlist_operator() {
  local line addr port count=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    addr=${line%:*}
    port=${line##*:}
    _paranoid_allow_add "$addr" "$port" operator-paranoid-allow
    count=$(( count + 1 ))
  done < <(config_scanner_list paranoid-allow '')
  run_record paranoid_allowlist_note "set=operator reason=scanner_conf_paranoid_allow entries=$count"
}

# Set 1: in-scope resolved addresses/ports, from lib/http.sh's pinned
# resolution cache (tension 19).  Resolved PROACTIVELY, here, rather than
# read passively from whatever the cache already holds: paranoid_attach calls
# this BEFORE starting the sampler (see its own comment), so every in-scope
# host this run could ever contact is pinned before there is anything
# watching - the same "resolve DNS before the observer can object to its own
# lookup" ordering tension 20 describes for the bootstrapping problem, just
# solved by sequencing instead of by a DNS-specific allowlist carve-out
# (which tension 20 explicitly rejected as too wide: "allowlist anything on
# port 53" would authorise exfiltration dressed as DNS).
_paranoid_allowlist_in_scope() {
  http_scope_load
  local i n=${#_HTTP_SCOPE_HOST[@]} host port addr count=0
  for (( i = 0; i < n; i++ )); do
    host=${_HTTP_SCOPE_HOST[i]}
    port=${_HTTP_SCOPE_PORT[i]}
    if [[ $host =~ ^[0-9]+(\.[0-9]+){3}$ || $host == *:* ]]; then
      addr=$host   # an IP literal scope host never goes through http_resolve_host
    elif ! addr=$(http_resolve_host "$host" 2>/dev/null); then
      log_warn "paranoid: could not pre-resolve in-scope host '$host' for the allowlist; it will be treated as OUT of scope for this run's connection observer"
      continue
    fi
    _paranoid_allow_add "$addr" "$port" in-scope-target
    count=$(( count + 1 ))
  done
  run_record paranoid_allowlist_note "set=in-scope reason=lib_http_resolution_cache addresses=$count"
}

# Set 2: resolved AWS endpoint addresses for regions ACTUALLY iterated.
# `modules/cloud/aws/regions.sh` (docs/DESIGN.md §13 step 6) does not exist
# yet on this branch, so this degrades to an empty set with a stated reason
# rather than erroring - the same forward-dependency pattern
# docs/STEP5-DAST-PLAN.md's DAST-09 used for the unbuilt `data/versions.db`.
# The hook (`aws_regions_iterated_addresses`, "addr port" lines) is checked
# by NAME so step 6 landing later needs no change here at all.
_paranoid_allowlist_aws() {
  if declare -F aws_regions_iterated_addresses >/dev/null 2>&1; then
    local addr port count=0
    while IFS=' ' read -r addr port; do
      [[ -n $addr ]] || continue
      _paranoid_allow_add "$addr" "${port:-443}" aws-endpoint
      count=$(( count + 1 ))
    done < <(aws_regions_iterated_addresses)
    run_record paranoid_allowlist_note "set=aws reason=modules_cloud_aws_regions_sh_present addresses=$count"
    return 0
  fi
  if [[ ${SCAN_COMMAND:-} == cloud ]] \
    || [[ ${SCAN_COMMAND:-} == all && ${SCAN_FLAGS[live]:-} == true ]]; then
    log_warn "paranoid: AWS endpoint allowlist (set 2) is empty - modules/cloud/aws/regions.sh does not exist yet (docs/DESIGN.md §13 step 6, unbuilt)"
    run_record paranoid_allowlist_note 'set=aws reason=modules_cloud_aws_regions_sh_not_yet_built addresses=0'
  else
    run_record paranoid_allowlist_note 'set=aws reason=no_aws_scan_this_run addresses=0'
  fi
}

paranoid_allowlist_build() {
  _PARANOID_ADDR=() _PARANOID_PORT=() _PARANOID_SET=()
  _paranoid_allowlist_infra
  _paranoid_allowlist_operator
  _paranoid_allowlist_in_scope
  _paranoid_allowlist_aws
}

_paranoid_ipv4_in_cidr() {
  # Named prefix_bits, not `bits` - lib/http.sh's _http_ipv4_denied has an
  # unrelated ARRAY local also named `bits` in the same sourced chain, and a
  # cross-file lint pass (run with -x) conflates the two names across
  # function scopes and misreports this scalar as an array-turned-string
  # (SC2178/SC2128); the rename is the fix, not a real bug here.
  local ip=$1 base=${2%/*} prefix_bits=${2#*/}
  local a b c d addr baseaddr mask
  [[ $prefix_bits =~ ^[0-9]+$ ]] && (( prefix_bits <= 32 )) || return 1
  local IFS=.
  read -r a b c d <<<"$ip" 2>/dev/null || return 1
  [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $c =~ ^[0-9]+$ && $d =~ ^[0-9]+$ ]] || return 1
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  addr=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  read -r a b c d <<<"$base" 2>/dev/null || return 1
  [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $c =~ ^[0-9]+$ && $d =~ ^[0-9]+$ ]] || return 1
  baseaddr=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( prefix_bits == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_bits)) & 0xFFFFFFFF ))
  (( (addr & mask) == (baseaddr & mask) ))
}

# `paranoid_addr_allowed ADDR PORT` - the pure predicate, exported for direct
# unit testing (tests/suites/paranoid.sh) independent of any sampler.
paranoid_addr_allowed() {
  local addr=${1,,} port=$2 i n=${#_PARANOID_ADDR[@]} a p
  for (( i = 0; i < n; i++ )); do
    a=${_PARANOID_ADDR[i]} p=${_PARANOID_PORT[i]}
    if [[ $a == */* ]]; then
      _paranoid_ipv4_in_cidr "$addr" "$a" || continue
    elif [[ $a == '::1' ]]; then
      [[ $addr == '::1' ]] || continue
    else
      [[ $addr == "${a,,}" ]] || continue
    fi
    [[ $p == '*' || $p == "$port" ]] || continue
    return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# 3. Samplers - `ss` (preferred) and `strace` (fallback), both swappable.
# ---------------------------------------------------------------------------
# Print "ADDR PORT" lines, one per remote endpoint currently observed for a
# process in this run's own family (see _paranoid_family_pids below for what
# "family" means and why).  Both are best-effort and approximate by design
# (docs/FOUNDATION.md tension 20's "detector, not guarantee": a
# closed-before-the-next-poll connection is invisible to either).

# The run's own process FAMILY: the main scan.sh process plus every one of
# its descendants (found by walking ps's pid/ppid table), which is what
# AC3 ("process-group level, not per-pid") actually needs covered - every
# `xargs -P` worker IS a descendant of the invoking scan.sh process.
#
# Deliberately NOT the raw OS process group (`ps -o pgid=`), even though
# tension 20's RESOLUTION text says "cgroup or process group": a plain
# `cmd &`/`( ... )` never changes pgid, so scan.sh's pgid is whatever
# process group its OWN invoker happens to be in - the interactive shell
# that ran it, a wrapper script that `source`d it, or (measured directly
# while building this ticket) this project's own test harness, none of
# which called `setsid` to give scan.sh a pgid of its own.  A kill-the-
# process-group abort in that shape reaches every unrelated sibling in the
# same session, not just this run's children - up to and including the
# harness driving the run itself.  Walking the descendant tree gets the
# SAME coverage tension 20 actually cares about (every worker this run
# forked) without that blast radius.
_paranoid_family_pids() {
  local root=$1 pid ppid entry f grew
  declare -A family=()
  family[$root]=1
  local -a table=()
  while IFS= read -r pid ppid; do
    [[ -n $pid && -n $ppid ]] && table+=("$pid $ppid")
  done < <(ps -Ao pid=,ppid= 2>/dev/null)
  # Fixed-point over the (small, per-run) pid/ppid table: repeat until a
  # full pass adds no new pid, which correctly finds a descendant however
  # deep the fork chain (a worker's own forked helper, etc.), not just
  # direct children of root.
  grew=1
  while (( grew )); do
    grew=0
    for entry in "${table[@]+"${table[@]}"}"; do
      pid=${entry%% *}
      ppid=${entry##* }
      if [[ -n ${family[$ppid]:-} && -z ${family[$pid]:-} ]]; then
        family[$pid]=1
        grew=1
      fi
    done
  done
  for f in "${!family[@]}"; do printf '%s\n' "$f"; done
}

_paranoid_ss_cmd() { ss -Htnp 2>/dev/null || true; }

# One line of `ss -Htnp` output looks like:
#   ESTAB 0 0 127.0.0.1:51000 127.0.0.1:8080 users:(("curl",pid=1234,fd=5))
# Column 4 is the peer (remote) address:port; the pid is read out of the
# trailing `users:` field so a line cannot be attributed to a process outside
# this run's own family (see _paranoid_family_pids above).
_paranoid_sample_ss() {
  local root_pid=$1 line pid peer addr port
  declare -A fampids=()
  local p
  while IFS= read -r p; do [[ -n $p ]] && fampids[$p]=1; done < <(_paranoid_family_pids "$root_pid")
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ $line =~ pid=([0-9]+) ]] || continue
    pid=${BASH_REMATCH[1]}
    [[ -n ${fampids[$pid]:-} ]] || continue
    peer=$(awk '{print $5}' <<<"$line")
    [[ -n $peer ]] || continue
    if [[ $peer =~ ^\[(.+)\]:([0-9]+)$ ]]; then
      addr=${BASH_REMATCH[1]}
      port=${BASH_REMATCH[2]}
    elif [[ $peer =~ ^(.+):([0-9]+)$ ]]; then
      addr=${BASH_REMATCH[1]}
      port=${BASH_REMATCH[2]}
    else
      continue
    fi
    printf '%s %s\n' "$addr" "$port"
  done < <("${SCOURSH_PARANOID_SS_CMD:-_paranoid_ss_cmd}")
}

_paranoid_strace_logfile() { printf '%s/paranoid/strace.log' "$SCOURSH_SCRATCH"; }
PARANOID_STRACE_PID=''

_paranoid_strace_start() {
  local pid=$1 logfile
  logfile=$(_paranoid_strace_logfile)
  mkdir -p "${logfile%/*}"
  : >"$logfile"
  strace -f -e trace=connect -o "$logfile" -p "$pid" >/dev/null 2>&1 &
  PARANOID_STRACE_PID=$!
}

_paranoid_strace_stop() {
  [[ -n $PARANOID_STRACE_PID ]] || return 0
  kill "$PARANOID_STRACE_PID" 2>/dev/null || true
  wait "$PARANOID_STRACE_PID" 2>/dev/null || true
  PARANOID_STRACE_PID=''
}

# Parses the two connect() shapes strace -f prints for AF_INET/AF_INET6:
#   connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = ...
#   connect(3, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "::1", ...
# Re-reads the whole (bounded, per-run) log each poll rather than tracking a
# byte cursor: a connection already judged allowed is simply judged allowed
# again, which is harmless and far simpler than cursor bookkeeping.
_paranoid_sample_strace() {
  local logfile line
  logfile=$(_paranoid_strace_logfile)
  [[ -r $logfile ]] || return 0
  while IFS= read -r line; do
    if [[ $line =~ sin_port=htons\(([0-9]+)\).*sin_addr=inet_addr\(\"([0-9.]+)\"\) ]]; then
      printf '%s %s\n' "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    elif [[ $line =~ sin6_port=htons\(([0-9]+)\).*inet_pton\([^,]+,[[:space:]]*\"([0-9A-Fa-f:]+)\" ]]; then
      printf '%s %s\n' "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    fi
  done <"$logfile"
}

_paranoid_sample() {
  case $PARANOID_BACKEND in
    ss) _paranoid_sample_ss "$1" ;;
    strace) _paranoid_sample_strace "$1" ;;
    *) return 0 ;;
  esac
}

# ---------------------------------------------------------------------------
# 4. Attach / detach / abort
# ---------------------------------------------------------------------------
PARANOID_SAMPLER_PID=''
PARANOID_MAIN_PID=''

_paranoid_dir() { printf '%s/paranoid' "$SCOURSH_SCRATCH"; }

# Runs as a BACKGROUND job (started by paranoid_attach).  A plain `cmd &`
# never re-parents itself away from the process that started it, so this
# loop's own pid is always found by _paranoid_family_pids("$PARANOID_MAIN_PID")
# - it is watching a family it is itself a member of, same as every
# xargs -P worker is; neither is a special case.
_paranoid_sampler_loop() {
  local root_pid=$1 dir addr port
  dir=$(_paranoid_dir)
  while [[ ! -e "$dir/done" ]]; do
    while IFS=' ' read -r addr port; do
      [[ -n $addr ]] || continue
      if ! paranoid_addr_allowed "$addr" "$port"; then
        printf 'addr=%s port=%s\n' "$addr" "$port" >"$dir/violation"
        kill -USR2 "$PARANOID_MAIN_PID" 2>/dev/null || true
        return 0
      fi
    done < <("${SCOURSH_PARANOID_SAMPLE:-_paranoid_sample}" "$root_pid")
    msleep "${SCOURSH_PARANOID_POLL_MS:-200}"
  done
}

# Best-effort: stop everything else in the run's own process FAMILY (see
# _paranoid_family_pids) except this process (which is about to die() itself,
# below, with the correct exit code) and the sampler (already exiting on its
# own) - a violation means "abort the run", not "abort only the shell
# noticing it".  Deliberately family-scoped, not process-group-scoped - see
# _paranoid_family_pids's own comment for the incident that ruled the latter
# out.
_paranoid_kill_siblings() {
  local root_pid=$1 pid
  [[ -n $root_pid ]] || return 0
  while IFS= read -r pid; do
    [[ -n $pid && $pid != "$BASHPID" && $pid != "$PARANOID_SAMPLER_PID" ]] || continue
    kill -TERM "$pid" 2>/dev/null || true
  done < <(_paranoid_family_pids "$root_pid")
}

# Mirrors lib/http.sh's _http_gate_audit - same finding pipeline, same
# tension-9 redaction path, and reuses the `dast` fingerprint profile (target,
# method, path_template, param_location) rather than adding a new module to
# the closed module enum (lib/findings.sh's _fp_profile_for) for one check.
_paranoid_audit_violation() {
  local addr=$1 port=$2
  log_error "paranoid: connection to $addr:$port is outside this run's allowlist - aborting (docs/FOUNDATION.md tension 20)"
  [[ -n ${SCOURSH_RUN_DIR:-} ]] || return 0
  finding_new
  finding_set check_id 'PARANOID-EGRESS-VIOLATION'
  finding_set module dast
  finding_set title 'paranoid mode observed a connection outside the run allowlist'
  finding_set base_severity critical
  finding_set cwe CWE-918
  finding_set owasp A10:2021
  finding_set confidence medium
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set remediation 'Add the destination to config/scope.conf (in-scope targets), scanner.conf paranoid_allow (addr:port), or investigate why this run attempted an out-of-scope connection - a rule, dependency, or module may be misconfigured or compromised. Remember: --paranoid is a sampling DETECTOR, not a guarantee (docs/FOUNDATION.md tension 20); tools/run-in-netns.sh is the mechanism that makes this categorically impossible rather than merely observed.'
  finding_set loc_target 'unattributed'
  finding_set loc_method 'CONNECT'
  finding_set loc_path_template "$addr:$port"
  finding_set loc_param_location network
  finding_set_evidence "addr=$addr port=$port backend=$PARANOID_BACKEND family_root=$PARANOID_MAIN_PID"
  finding_emit
}

paranoid_on_violation() {
  local dir line addr='' port=''
  dir=$(_paranoid_dir)
  if [[ -r $dir/violation ]]; then
    IFS= read -r line <"$dir/violation" || true
    if [[ $line =~ ^addr=([^[:space:]]*)[[:space:]]+port=(.*)$ ]]; then
      addr=${BASH_REMATCH[1]}
      port=${BASH_REMATCH[2]}
    fi
  fi
  _paranoid_kill_siblings "$PARANOID_MAIN_PID"
  _paranoid_audit_violation "$addr" "$port"
  die "$SCOURSH_EXIT_SCOPE" "paranoid: connection to ${addr:-?}:${port:-?} not in this run's allowlist"
}

# Called once, before any module dispatch (scan.sh scan_main).  Dies exit 4
# (SCOURSH_EXIT_INPUT, AC4) rather than silently running unobserved when
# neither backend is usable.
paranoid_attach() {
  paranoid_probe_backend
  if [[ $PARANOID_BACKEND == none ]]; then
    die "$SCOURSH_EXIT_INPUT" "--paranoid requires 'ss' or a usable 'strace -f -e trace=connect'; neither is available/permitted on this host"
  fi

  # Allowlist BEFORE the observer starts (see _paranoid_allowlist_in_scope's
  # own comment): every DNS lookup this needs happens here, unobserved,
  # closing tension 20's bootstrapping problem by sequencing rather than by
  # a DNS-specific carve-out.
  paranoid_allowlist_build

  local dir
  dir=$(_paranoid_dir)
  mkdir -p "$dir"
  rm -f "$dir/violation" "$dir/done"

  PARANOID_MAIN_PID=$BASHPID

  if [[ $PARANOID_BACKEND == strace ]]; then
    _paranoid_strace_start "$PARANOID_MAIN_PID"
  fi

  trap 'paranoid_on_violation' USR2

  _paranoid_sampler_loop "$PARANOID_MAIN_PID" &
  PARANOID_SAMPLER_PID=$!

  run_record paranoid_attached "backend=$PARANOID_BACKEND family_root=$PARANOID_MAIN_PID sampler_pid=$PARANOID_SAMPLER_PID"
  run_record coverage_gap "paranoid: this run enabled --paranoid, a connection detector (sampler, backend=$PARANOID_BACKEND), not a guarantee - a sufficiently short-lived connection can open and close between two samples and evade detection entirely. tools/run-in-netns.sh (NETNS-01) is the mechanism that makes an out-of-scope connection categorically impossible rather than merely observable (docs/FOUNDATION.md tension 20)."
  log_info "paranoid: connection observer attached (backend=$PARANOID_BACKEND, family root pid=$PARANOID_MAIN_PID) - detector, not guarantee"
}

# Called once, at the very end of a run that did NOT abort.  Stops the
# background sampler cleanly and records the clean result (also surfaced via
# coverage_gap at attach time, above, so the framing is present even if a
# reader only looks at the report and not at this specific fact key).
paranoid_detach() {
  [[ -n $PARANOID_SAMPLER_PID ]] || return 0
  local dir
  dir=$(_paranoid_dir)
  : >"$dir/done"
  wait "$PARANOID_SAMPLER_PID" 2>/dev/null || true
  [[ $PARANOID_BACKEND == strace ]] && _paranoid_strace_stop
  trap - USR2
  run_record paranoid_result 'status=clean observed_out_of_allowlist=0'
  log_info "paranoid: connection observer detached cleanly - zero out-of-allowlist connections observed this run (sampling-based; see docs/FOUNDATION.md tension 20 for what this does and does not prove)"
  PARANOID_SAMPLER_PID=''
}
