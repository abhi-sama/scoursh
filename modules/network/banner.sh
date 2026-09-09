#!/usr/bin/env bash
# modules/network/banner.sh - the NET-07 tier-2 probe: read-on-connect
# service identification and the `NET-SVC-BANNER_DISCLOSURE-01` check
# (data/scoursh-network-scan-design/report.md §3.2 item 1, §5.1, §5.2, §5.3).
#
# THIS IS A PHASE SCRIPT: modules/network/engine.sh's `net_run_phase` reaches
# it with a plain `source` (at tier `passive`, so it runs on every network
# run, including the default intensity), so it inherits the whole run
# context and anything it emits lands in this process's shard.  Per that
# function's contract it carries NO sourced-once guard.  The pure half - the
# banner sanitizer, the product/version identifier, the finding emitter - is
# modules/network/banner_engine.sh.
#
# WHAT THIS PROBE SENDS, AND WHY IT IS `passive` AND NOT `safe-active`.  ZERO
# BYTES, ever, to any listener - lib/nettransport.sh's `net_read_banner`
# opens a socket, reads whatever the far end volunteers within a bounded
# deadline, and closes it, never writing to the fd (that file's own header
# states the same about `net_connect_probe`, and this function shares its
# connect step).  report.md §5.1's own table gives this check the `passive`
# tag for exactly that reason, distinct from NET-06's `safe-active` connect
# probe - see modules/network/checks-banner.rules' own header for the
# contrast in full.
#
# THIS PROBE REUSES NET-06'S OWN OPEN/NOT-OPEN/FILTERED CLASSIFICATION, AND
# DOES NOT RE-IMPLEMENT IT.  Every declared listener is classified via the
# SAME `net_connect_probe` (lib/nettransport.sh) modules/network/
# reachability.sh itself calls, with a SECOND, independent connection - not
# a read of any artifact reachability.sh produced, because that phase writes
# no persisted per-listener state (report.md's own three-state table lives
# entirely in that phase's own process; there is nothing on disk for a
# sibling phase to read).  "Reuse the classification" therefore means "call
# the same shared primitive reachability.sh calls", never "invent a second
# way to decide whether a port is open" - the identical division of labour
# every §7.3 DAST probe already applies to `http_request` rather than
# growing its own transport.  Only an `open` listener is ever handed to
# `net_read_banner`; a not-open or filtered one is counted into this check's
# own `net_check_not_applicable` reduction and is never read from.
#
# shellcheck shell=bash
#
# SC2016: see modules/network/banner_engine.sh's own header for why.
# shellcheck disable=SC2016
#
# shellcheck source=modules/network/banner_engine.sh
source "${BASH_SOURCE[0]%/*}/banner_engine.sh"
# lib/nettransport.sh (NET-03/NET-07) carries no sourced-once guard of its
# own (redefining bash functions is idempotent) - sourced unconditionally
# here, matching modules/network/reachability.sh's own identical comment,
# for `net_connect_probe`, `net_probe_capability` and `net_read_banner`.
# shellcheck source=lib/nettransport.sh
source "${BASH_SOURCE[0]%/*}/../../lib/nettransport.sh"
# For http_authorize_raw_connection - re-authorized and re-resolved
# immediately before THIS probe's own connections, for the identical
# anti-TOCTOU reasoning modules/network/reachability.sh's own header states
# at length (listeners.json is already-authorized operator config, but the
# pinned-resolution guarantee is only real when re-asserted at the moment a
# probe actually dials out, which can happen an arbitrary amount of time
# after inventory.sh wrote that artifact).  Permissive-when-absent via
# `declare -F` everywhere this file calls it, the identical
# direct-engine-test shape reachability.sh's own header names.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# The number of bytes read per listener.  Large enough for a multi-line SMTP
# greeting (several "220-..." lines plus a final "220 ..." line) while
# staying well inside `SCOURSH_EVIDENCE_MAX_BYTES` (512, lib/findings.sh)
# once the evidence text around it is added - `_banner_safe_text`'s own 200
# byte bound is what actually reaches a finding, this is only how much is
# ever read off the wire.
: "${_NET_BANNER_MAX_BYTES:=1024}"

# `_banner_capability_reduction TARGET` - the ONE check-level reduction for a
# bash built without --enable-net-redirections, byte-identical in shape to
# modules/network/reachability.sh's own `_reach_capability_reduction` and
# for the identical reason (AGENTS.md's "checks_run must count what
# SUCCEEDED" lesson): checked BEFORE the listener loop rather than left to
# happen per-listener, so a host with no /dev/tcp support records ONE named
# reduction naming this check, not a `checks_run` entry the moment any
# listener was merely attempted.
_banner_capability_reduction() {
  local target=$1
  run_record coverage_reduction "module=network phase=banner.sh reason=net_probe_cmd_absent check=[NET-SVC-BANNER_DISCLOSURE-01] target=$target - this bash was built without --enable-net-redirections (lib/nettransport.sh), so no TCP connect could be attempted for any of this target's declared listeners; the check produced no real result and is not recorded as covered."
  return 0
}

_banner_no_listeners_reduction() {
  local target=$1 why=$2
  run_record coverage_reduction "module=network phase=banner.sh reason=no_declared_listeners check=NET-SVC-BANNER_DISCLOSURE-01 target=$target - $why"
  run_record coverage_gap "network banner: target '$(net_scope_safe_text "$target" 80)' has no usable declared listener set this run ($why), so no listener was read for a banner. This is the absence of a test, not the absence of a problem."
  return 0
}

_banner_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/banner.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  if declare -F net_probe_capability >/dev/null 2>&1 && ! net_probe_capability; then
    _banner_capability_reduction "$target"
    return 0
  fi

  if declare -F net_inventory_read >/dev/null 2>&1; then
    net_inventory_read
  else
    _NET_LISTENERS_FILE='' _NET_LISTENERS_STATE=absent
  fi

  case $_NET_LISTENERS_STATE in
    absent)
      _banner_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json was not written this run (modules/network/inventory.sh's report.md §5.2 rule 3: a target with only base-url, or every extra-host dropped, writes no artifact)"
      return 0
      ;;
    empty)
      _banner_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json exists but is empty"
      return 0
      ;;
  esac

  reach_listeners_load "$_NET_LISTENERS_FILE" "$target"
  if (( _REACH_N == 0 )); then
    _banner_no_listeners_reduction "$target" \
      "reports/<run>/inventory/listeners.json named no listener for target '$(net_scope_safe_text "$target" 80)'"
    return 0
  fi

  local i role scheme host port url addr state
  local open_ct=0 notopen_ct=0 filtered_ct=0 unresolvable_ct=0 nobanner_ct=0 disclosed_ct=0
  local unresolvable_reasons=''
  local -A unresolvable_reason_seen=()
  local bfile=$SCOURSH_SCRATCH/net-banner.$BASHPID

  for (( i = 0; i < _REACH_N; i++ )); do
    role=${_REACH_ROLE[i]}
    scheme=${_REACH_SCHEME[i]}
    host=${_REACH_HOST[i]}
    port=${_REACH_PORT[i]}
    url="$scheme://$host:$port/"

    # report.md §5.2 rule 1, first half - the identical re-authorization
    # modules/network/reachability.sh's own header explains at length.
    if ! http_authorize_raw_connection "$url" "$target" false; then
      unresolvable_ct=$(( unresolvable_ct + 1 ))
      if [[ -z ${unresolvable_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        unresolvable_reason_seen[$_HTTP_RAW_REASON]=1
        unresolvable_reasons+="${unresolvable_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
      continue
    fi
    addr=$_HTTP_RAW_ADDR

    # THE ONE PLACE THIS FILE REUSES NET-06'S CLASSIFICATION: the SAME
    # net_connect_probe call reachability.sh makes, on a second, independent
    # connection - see this file's own header for why that is "reuse", not
    # "re-implement".
    state=$(net_connect_probe "$addr" "$port")
    case $state in
      open)
        open_ct=$(( open_ct + 1 ))
        rm -f "$bfile"
        net_read_banner "$addr" "$port" "$_NET_BANNER_MAX_BYTES" "$bfile" || true
        if [[ -s $bfile ]]; then
          local text
          text=$(net_banner_read_text "$bfile" "$_NET_BANNER_MAX_BYTES")
          rm -f "$bfile"
          if [[ -n $text ]] && net_banner_identify_text "$text"; then
            disclosed_ct=$(( disclosed_ct + 1 ))
            banner_emit_disclosure "$target" "$role" "$scheme" "$host" "$port" \
              "$_NET_BANNER_PRODUCT" "$_NET_BANNER_VERSION" "$text"
          fi
          # A banner that arrived but identified nothing recognisable is a
          # real, honest "checked, nothing to flag" outcome (this check's
          # own registry header) - it is NOT no_banner (report.md's own
          # `no_banner` names a listener that sent NOTHING at all), so it is
          # neither a finding nor a reduction.
        else
          rm -f "$bfile"
          nobanner_ct=$(( nobanner_ct + 1 ))
        fi
        ;;
      not-open)
        notopen_ct=$(( notopen_ct + 1 ))
        ;;
      filtered | *)
        # `*` catches an unrecognised SCOURSH_NET_PROBE stub result the
        # identical way modules/network/reachability.sh's own case does,
        # folding it into the same honest "we could not tell" accounting
        # rather than reading it as not-open.
        filtered_ct=$(( filtered_ct + 1 ))
        ;;
    esac
  done

  if (( unresolvable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=net_listener_unresolvable check=NET-SVC-BANNER_DISCLOSURE-01 target=$target count=$unresolvable_ct - that many declared listener(s) could not be re-authorised/re-resolved at probe time, so no banner was attempted for them. Reason(s): $unresolvable_reasons."
  fi

  local not_applicable_ct=$(( notopen_ct + filtered_ct ))
  if (( not_applicable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=net_check_not_applicable check=NET-SVC-BANNER_DISCLOSURE-01 target=$target count=$not_applicable_ct not_open=$notopen_ct filtered=$filtered_ct - that many declared listener(s) were not open (report.md §5.2 rule 4: 'did not answer in time' and 'refused' are different facts, and neither is read for a banner), so this check was not applicable to them and nothing was read."
  fi

  if (( nobanner_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=no_banner check=NET-SVC-BANNER_DISCLOSURE-01 target=$target count=$nobanner_ct - that many OPEN declared listener(s) accepted a TCP connection but sent no bytes within the read deadline, so no banner could be examined. Most services (a bare web server, most databases without a greeting) never send one unprompted; this is not evidence of anything about them by itself."
  fi

  if (( open_ct > 0 )); then
    run_record checks_run NET-SVC-BANNER_DISCLOSURE-01
  else
    run_record coverage_gap "network banner: none of this target's declared listener(s) were open on target '$(net_scope_safe_text "$target" 80)' (${unresolvable_ct} unresolvable, ${notopen_ct} not-open, ${filtered_ct} filtered of ${_REACH_N} declared), so no connection was ever read for a banner. This is not evidence of safety."
  fi

  log_info "network banner: target '$target' - $open_ct of $_REACH_N declared listener(s) open, read $disclosed_ct disclosure(s) ($nobanner_ct sent nothing)"
  return 0
}

_banner_run
