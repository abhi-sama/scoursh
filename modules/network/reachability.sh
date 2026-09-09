#!/usr/bin/env bash
# modules/network/reachability.sh - the NET-06 tier-2 probe: THREE-STATE
# listener verification and the `NET-PORT-*` checks
# (data/scoursh-network-scan-design/report.md §3.1, §5.1, §5.2, §9 D5).
#
# THIS IS A PHASE SCRIPT: modules/network/engine.sh's `net_run_phase` reaches
# it with a plain `source` (at tier `safe`, so it does not run below
# `--intensity safe`), so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's contract it
# carries NO sourced-once guard - one run can legitimately reach the same
# phase twice (a second target, a second scan_main invocation in one
# process).  The pure half - the listeners.json reader, the posture.conf
# reader, the two finding emitters - is
# modules/network/reachability_engine.sh; this file resolves the run's own
# live inputs (the target, the declared listener set, the transport
# primitive, the expect-closed baseline) and drives them, the identical
# engine.sh/phase-script split every module in this tree already uses.
#
# THIS IS THE FOUNDATIONAL PROBE: NET-07 (banner) and NET-08 (tlsport) reuse
# this file's own THREE-STATE classification and its `listeners.json`
# reading shape - `reach_listeners_load` is written to be a plain function
# call any future NET-0x phase can reuse, exactly as
# modules/dast/passive/response_engine.sh's `resp_endpoints_load` is reused
# by six DAST peers.
#
# WHAT THIS PROBE SENDS, AND WHY IT IS `safe-active` AND NOT `passive`.  One
# TCP connect per declared listener via lib/nettransport.sh's own
# `net_connect_probe`, ZERO BYTES SENT - the transport primitive opens a
# socket and immediately closes it (or lets the deadline fire), never
# writing to the fd.  That is a real connection to a real port the operator
# did not necessarily expect a scanner to knock on, which report.md's own
# §5.1 table tags `safe-active` (never `passive`, which report.md reserves
# for a check that opens no connection at all, e.g. reading a banner a
# listener volunteers unprompted - NET-07's job, not this one).
#
# shellcheck shell=bash
# shellcheck source=modules/network/reachability_engine.sh
source "${BASH_SOURCE[0]%/*}/reachability_engine.sh"
# lib/nettransport.sh (NET-03) carries no sourced-once guard of its own
# (redefining bash functions is idempotent, and it is designed to be sourced
# by more than one caller in one process - see its own header) - sourced
# unconditionally here rather than guarded, matching that file's own
# contract, and needed directly by this phase script for `net_connect_probe`
# and `net_probe_capability`.
# shellcheck source=lib/nettransport.sh
source "${BASH_SOURCE[0]%/*}/../../lib/nettransport.sh"
# For http_authorize_raw_connection - the SAME anti-TOCTOU pinned-resolution,
# rate-limiter, request-budget and circuit-breaker chokepoint report.md
# §2.5's own table says a raw TCP probe is gated through, called AGAIN here
# (a second, independent pass, not a reuse of inventory.sh's own earlier
# authorization) for the identical reason modules/dast/passive/tls.sh
# re-authorizes immediately before ITS OWN raw connection rather than
# trusting an artifact written by an earlier phase: listeners.json is
# already-authorized OPERATOR CONFIG, so re-running the fatal gate here is
# report.md §5.2 rule 1's first half ("an operator-configured tuple is
# refused exactly like an out-of-scope DAST target"), and re-resolving the
# hostname AT PROBE TIME (rather than trusting whatever inventory.sh may
# have resolved earlier in this run) is what keeps the pinned-resolution
# anti-TOCTOU guarantee real for a probe that can run an arbitrary amount of
# time after inventory.sh wrote its artifact.  A direct-engine test suite
# that sources this file with no lib/http.sh anywhere in the process is the
# identical shape tests/suites/dast-cors.sh's own `dast_check_selected`
# guard exists for - permissive-when-absent everywhere this file calls it,
# via `declare -F`.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# `_reach_capability_reduction TARGET` - the ONE check-level reduction for a
# bash built without --enable-net-redirections (lib/nettransport.sh's own
# `net_probe_capability`, tension-24-style capability probe, memoized once
# per scratch dir).  Checked BEFORE the listener loop rather than left to
# happen naturally (every net_connect_probe call would itself degrade to
# 'filtered' and this file's own filtered accounting would technically still
# be honest) because letting it happen per-listener would still record
# `checks_run NET-PORT-DECLARED_NOT_ANSWERING-01` the moment ANY listener was
# attempted, even though on this host EVERY attempt is guaranteed
# inconclusive - the identical "checks_run must count what SUCCEEDED, not
# what was merely attempted" lesson AGENTS.md's authz.sh section records.
# lib/nettransport.sh's own `net_probe_capability` already records ONE
# module-level reduction the first time it is probed in this scratch dir;
# this is a SECOND, check-level reduction naming both NET-PORT-* ids as
# uncovered for this target specifically, because a module-level note alone
# does not tell a reader of `checks_run` WHICH checks were affected.
_reach_capability_reduction() {
  local target=$1
  run_record coverage_reduction "module=network reason=net_probe_cmd_absent check=[NET-PORT-DECLARED_NOT_ANSWERING-01 NET-PORT-UNEXPECTED_LISTENER-01] target=$target - this bash was built without --enable-net-redirections (lib/nettransport.sh), so no TCP connect could be attempted for any of this target's declared listeners; neither NET-PORT check produced a real result and neither is recorded as covered."
  return 0
}

_reach_no_listeners_reduction() {
  local target=$1 why=$2
  run_record coverage_reduction "module=network phase=reachability.sh reason=no_declared_listeners target=$target - $why"
  run_record coverage_gap "network reachability: target '$(net_scope_safe_text "$target" 80)' has no usable declared listener set this run ($why), so neither NET-PORT check probed anything. This is the absence of a test, not the absence of a problem."
  return 0
}

_reach_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/reachability.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  if declare -F net_probe_capability >/dev/null 2>&1 && ! net_probe_capability; then
    _reach_capability_reduction "$target"
    return 0
  fi

  if declare -F net_inventory_read >/dev/null 2>&1; then
    net_inventory_read
  else
    _NET_LISTENERS_FILE='' _NET_LISTENERS_STATE=absent
  fi

  case $_NET_LISTENERS_STATE in
    absent)
      _reach_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json was not written this run (modules/network/inventory.sh's report.md §5.2 rule 3: a target with only base-url, or every extra-host dropped, writes no artifact)"
      return 0
      ;;
    empty)
      _reach_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json exists but is empty"
      return 0
      ;;
  esac

  reach_listeners_load "$_NET_LISTENERS_FILE" "$target"
  if (( _REACH_N == 0 )); then
    _reach_no_listeners_reduction "$target" \
      "reports/<run>/inventory/listeners.json named no listener for target '$(net_scope_safe_text "$target" 80)'"
    return 0
  fi

  reach_posture_load "$target"

  local i role scheme host port url addr state
  local tested=0 open_ct=0 notopen_ct=0 filtered_ct=0 unresolvable_ct=0
  local unresolvable_reasons=''
  local -A unresolvable_reason_seen=() seen_ports=()

  for (( i = 0; i < _REACH_N; i++ )); do
    role=${_REACH_ROLE[i]}
    scheme=${_REACH_SCHEME[i]}
    host=${_REACH_HOST[i]}
    port=${_REACH_PORT[i]}
    seen_ports[$port]=1
    url="$scheme://$host:$port/"

    # report.md §5.2 rule 1, first half: an operator-configured tuple (this
    # IS one - listeners.json is a snapshot of config/scope.conf's own
    # base-url/extra-host entries) is refused FATALLY on every reason except
    # a transient DNS failure, which degrades to one counted reduction
    # rather than aborting every sibling listener - the identical `false`
    # dns_fatal argument modules/network/inventory.sh already passes.
    if ! http_authorize_raw_connection "$url" "$target" false; then
      unresolvable_ct=$(( unresolvable_ct + 1 ))
      if [[ -z ${unresolvable_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        unresolvable_reason_seen[$_HTTP_RAW_REASON]=1
        unresolvable_reasons+="${unresolvable_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
      continue
    fi
    addr=$_HTTP_RAW_ADDR

    state=$(net_connect_probe "$addr" "$port")
    tested=$(( tested + 1 ))
    case $state in
      open)
        open_ct=$(( open_ct + 1 ))
        if [[ -n ${_REACH_EXPECT_CLOSED[$port]:-} ]]; then
          reach_emit_unexpected_listener "$target" "$role" "$scheme" "$host" "$port" \
            "${_REACH_EXPECT_CLOSED[$port]}"
        fi
        ;;
      not-open)
        notopen_ct=$(( notopen_ct + 1 ))
        reach_emit_not_answering "$target" "$role" "$scheme" "$host" "$port"
        ;;
      filtered | *)
        # report.md §5.2 rule 4: filtered is NEVER folded into not-open, and
        # is never a finding - it is the absence of a conclusive answer, not
        # a fact about the listener.  `*` reaches this arm too so an
        # unrecognised SCOURSH_NET_PROBE stub result degrades to the SAME
        # honest "we could not tell" accounting rather than silently being
        # read as not-open.
        filtered_ct=$(( filtered_ct + 1 ))
        ;;
    esac
  done

  if (( unresolvable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=reachability.sh reason=net_listener_unresolvable target=$target count=$unresolvable_ct - that many declared listener(s) could not be re-authorised/re-resolved at probe time (they were authorised when modules/network/inventory.sh ran earlier this same run), so no TCP connect was attempted for them. Reason(s): $unresolvable_reasons."
  fi
  if (( filtered_ct > 0 )); then
    run_record coverage_reduction "module=network phase=reachability.sh reason=filtered target=$target count=$filtered_ct - that many declared listener(s) neither accepted nor refused a TCP connection before this probe's deadline. 'Did not answer in time' and 'refused' are different facts (report.md §5.2 rule 4): these are reported as filtered, never folded into not-open, and produce no finding either way."
  fi
  if (( tested > 0 )); then
    run_record checks_run NET-PORT-DECLARED_NOT_ANSWERING-01
  fi

  if [[ $_REACH_POSTURE_STATE == absent ]]; then
    run_record coverage_reduction "module=network phase=reachability.sh reason=net_check_not_applicable check=NET-PORT-UNEXPECTED_LISTENER-01 target=$target path=$_REACH_POSTURE_PATH - config/posture.conf does not exist, so no operator-declared expect-closed baseline was compared against this target's $open_ct open listener(s). This is a declared skip (report.md §9 D5), never an error, and does not affect the exit code."
  else
    if (( tested > 0 )); then
      run_record checks_run NET-PORT-UNEXPECTED_LISTENER-01
    fi
    local p oos_ct=0 oos_ports=''
    for p in "${!_REACH_EXPECT_CLOSED[@]}"; do
      [[ -n ${seen_ports[$p]:-} ]] && continue
      oos_ct=$(( oos_ct + 1 ))
      oos_ports+="${oos_ports:+ }$p"
    done
    if (( oos_ct > 0 )); then
      run_record coverage_reduction "module=network phase=reachability.sh reason=port_out_of_scope check=NET-PORT-UNEXPECTED_LISTENER-01 target=$target count=$oos_ct ports=[$oos_ports] - that many config/posture.conf expect-closed expectation(s) for this target name a port that is not among its declared/authorised listener set (config/scope.conf), so they were never probed and could not be compared against anything this run."
    fi
  fi

  if (( tested == 0 )); then
    run_record coverage_gap "network reachability: none of this target's declared listener(s) produced a real TCP connect result on target '$(net_scope_safe_text "$target" 80)' (${unresolvable_ct} unresolvable of ${_REACH_N} declared), so neither NET-PORT check observed anything. This is not evidence of safety."
  fi

  log_info "network reachability: target '$target' - probed $tested of $_REACH_N declared listener(s) (open=$open_ct not-open=$notopen_ct filtered=$filtered_ct unresolvable=$unresolvable_ct)"
  return 0
}

_reach_run
