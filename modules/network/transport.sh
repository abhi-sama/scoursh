#!/usr/bin/env bash
# modules/network/transport.sh - the NET-10 tier-3 probe: transport POSTURE
# on non-HTTP listeners and the `NET-TRANSPORT-*` checks
# (data/scoursh-network-scan-design/report.md §3.3, §5.1, §5.2, §7's NET-10
# row).
#
# THIS IS A PHASE SCRIPT: modules/network/engine.sh's `net_run_phase` reaches
# it with a plain `source` (at tier `passive`, so it runs on every network
# run, including the default intensity), so it inherits the whole run
# context and anything it emits lands in this process's shard.  Per that
# function's contract it carries NO sourced-once guard.  The pure half - the
# plaintext-twin table, the STARTTLS-advertisement text match, the two
# finding emitters - is modules/network/transport_engine.sh; see that file's
# own header for the full reasoning behind both checks and for why this
# probe does its own connecting rather than reading a NET-07/NET-08
# artifact (neither phase persists one).
#
# ONLY NON-BASE-URL (extra-host) LISTENERS ARE PROBED, matching
# modules/network/tlsport.sh's own boundary and for the identical reason:
# the base-url listener is DAST-TRANSPORT-*'s own subject
# (modules/dast/passive/transport.sh already assesses plaintext exposure on
# the target's own HTTP(S) origin), and this module's own title is
# "transport posture on NON-HTTP listeners" - re-probing base-url here would
# double-report the identical listener under a second module namespace.
#
# WHAT THIS PROBE SENDS, AND WHY IT IS `passive`.  Every reused primitive -
# `net_connect_probe`, `tls_probe`, `net_read_banner` - is one that a
# sibling phase already tags `passive` for the SAME reason: the transport
# handshake and the banner read are both connect-and-observe, never a
# protocol command this scanner composes and sends of its own (report.md
# §2.6's "no protocol conversation" boundary, applied to STARTTLS
# specifically in transport_engine.sh's own header).  A listener that
# genuinely requires an EHLO/CAPA/FEAT round-trip before it names STARTTLS
# is a stated recall gap (transport_engine.sh's own header), not something
# this phase, or any DAST peer at this tier, ever sends to find out.
#
# shellcheck shell=bash
#
# SC2016: see modules/network/banner_engine.sh's own header for why -
# operator-facing config directives are quoted literally in remediation
# prose below.
# shellcheck disable=SC2016
#
# shellcheck source=modules/network/transport_engine.sh
source "${BASH_SOURCE[0]%/*}/transport_engine.sh"
# lib/nettransport.sh (NET-03/NET-07) carries no sourced-once guard of its
# own - sourced unconditionally here, matching every sibling phase's
# identical comment, for `net_connect_probe`, `net_probe_capability` and
# `net_read_banner`.
# shellcheck source=lib/nettransport.sh
source "${BASH_SOURCE[0]%/*}/../../lib/nettransport.sh"
# For http_authorize_raw_connection - re-authorized and re-resolved
# immediately before THIS probe's own connections, the identical
# anti-TOCTOU reasoning modules/network/reachability.sh's own header states
# at length.  Permissive-when-absent via `declare -F` everywhere this file
# calls it, the identical direct-engine-test shape every sibling phase's own
# header names.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

_NET_TRANSPORT_IDS='NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01'

# The number of bytes read per listener for the STARTTLS-advertisement
# check - modules/network/banner.sh's own `_NET_BANNER_MAX_BYTES`, byte for
# byte: an IMAP greeting with an inline capability list is the longest
# realistic unprompted line this check needs to see, and this value already
# proved sufficient for that shape.
: "${_NET_TRANSPORT_BANNER_MAX_BYTES:=1024}"

_transport_capability_reduction() {
  local target=$1
  run_record coverage_reduction "module=network phase=transport.sh reason=net_probe_cmd_absent checks=[$_NET_TRANSPORT_IDS] target=$target - this bash was built without --enable-net-redirections (lib/nettransport.sh), so no TCP connect could be attempted for any of this target's declared listeners; neither NET-TRANSPORT-* check produced a real result and neither is recorded as covered."
  return 0
}

_transport_openssl_reduction() {
  local target=$1
  run_record coverage_reduction "module=network phase=transport.sh reason=requires_cmd_absent cmd=openssl checks=[$_NET_TRANSPORT_IDS] target=$target - the plaintext-service check needs openssl for its native-TLS-absence handshake (report.md §3.3), and it is not on PATH, so neither NET-TRANSPORT-* check ran (the STARTTLS-advertisement check depends on the SAME plaintext-versus-TLS classification, so it is withheld too rather than run on an unverified assumption of cleartext)."
  run_record coverage_gap "network transport: openssl is not available, so neither NET-TRANSPORT-* check ran on target '$target''s non-base-url listeners. Their transport posture was not tested."
  return 0
}

_transport_no_listeners_reduction() {
  local target=$1 why=$2
  run_record coverage_reduction "module=network phase=transport.sh reason=no_declared_listeners checks=[$_NET_TRANSPORT_IDS] target=$target - $why"
  run_record coverage_gap "network transport: target '$(net_scope_safe_text "$target" 80)' has no usable declared listener set this run ($why), so neither NET-TRANSPORT-* check probed anything. This is the absence of a test, not the absence of a problem."
  return 0
}

_transport_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/transport.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  # openssl is this check's one external dependency (report.md §3.3's own
  # native-TLS-absence measurement, via tls_probe) - absent is a declared
  # skip naming both ids, never an error, per AGENTS.md's authz.sh
  # "checks_run must count what SUCCEEDED" lesson.
  if ! _have openssl; then
    _transport_openssl_reduction "$target"
    return 0
  fi

  if declare -F net_probe_capability >/dev/null 2>&1 && ! net_probe_capability; then
    _transport_capability_reduction "$target"
    return 0
  fi

  if declare -F net_inventory_read >/dev/null 2>&1; then
    net_inventory_read
  else
    _NET_LISTENERS_FILE='' _NET_LISTENERS_STATE=absent
  fi

  if [[ $_NET_LISTENERS_STATE != present ]]; then
    _transport_no_listeners_reduction "$target" \
      "reports/<run>/inventory/listeners.json was not usable this run (modules/network/inventory.sh's report.md §5.2 rule 3: a target with only base-url, or every extra-host dropped, writes no artifact, or it exists but is empty)"
    return 0
  fi

  reach_listeners_load "$_NET_LISTENERS_FILE" "$target"

  # ONLY non-base-url listeners - this file's own header, mirroring
  # modules/network/tlsport.sh's identical boundary.
  local i role scheme host port
  local -a xh_scheme=() xh_host=() xh_port=()
  for (( i = 0; i < _REACH_N; i++ )); do
    role=${_REACH_ROLE[i]}
    [[ $role == extra-host ]] || continue
    xh_scheme+=("${_REACH_SCHEME[i]}")
    xh_host+=("${_REACH_HOST[i]}")
    xh_port+=("${_REACH_PORT[i]}")
  done

  if (( ${#xh_host[@]} == 0 )); then
    _transport_no_listeners_reduction "$target" \
      "the declared listener set for this target names no non-base-url (extra-host) entry, and modules/dast/passive/transport.sh already assesses plaintext exposure on base-url"
    return 0
  fi

  local timeout_s
  timeout_s=$(config_scanner_value http-timeout)

  local unresolvable_ct=0 filtered_ct=0 notopen_ct=0 open_ct=0
  local plaintext_notapplicable_ct=0 plaintext_ct=0 tlsonly_ct=0
  local starttls_notapplicable_ct=0 starttls_ct=0 starttls_clean_ct=0
  local plaintext_applicable_ct=0 starttls_applicable_ct=0
  local unresolvable_reasons=''
  local -A unresolvable_reason_seen=()
  local url addr state proto twin transcript bfile text

  for (( i = 0; i < ${#xh_host[@]}; i++ )); do
    scheme=${xh_scheme[i]} host=${xh_host[i]} port=${xh_port[i]}
    url="$scheme://$host:$port/"

    # report.md §5.2 rule 1, first half - the identical re-authorization
    # every sibling phase's own header explains at length.
    if ! http_authorize_raw_connection "$url" "$target" false; then
      unresolvable_ct=$(( unresolvable_ct + 1 ))
      if [[ -z ${unresolvable_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        unresolvable_reason_seen[$_HTTP_RAW_REASON]=1
        unresolvable_reasons+="${unresolvable_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
      continue
    fi
    addr=$_HTTP_RAW_ADDR

    # THE OPEN-STATE CLASSIFICATION: the SAME net_connect_probe call every
    # sibling phase makes, on the same gate-pinned address, with the
    # identical three-state vocabulary and the identical
    # filtered-is-never-not-open discipline (report.md §5.2 rule 4).
    state=$(net_connect_probe "$addr" "$port")
    case $state in
      open) : ;;
      not-open)
        notopen_ct=$(( notopen_ct + 1 ))
        continue
        ;;
      filtered | *)
        filtered_ct=$(( filtered_ct + 1 ))
        continue
        ;;
    esac
    open_ct=$(( open_ct + 1 ))

    if ! net_transport_plaintext_twin "$port"; then
      # Neither check has anything to identify on an unmapped port -
      # transport_engine.sh's own header: identification is by port number
      # alone, a stated limitation rather than a silent one.
      plaintext_notapplicable_ct=$(( plaintext_notapplicable_ct + 1 ))
      starttls_notapplicable_ct=$(( starttls_notapplicable_ct + 1 ))
      continue
    fi
    proto=$_NET_TRANSPORT_PROTO
    twin=$_NET_TRANSPORT_TWIN
    plaintext_applicable_ct=$(( plaintext_applicable_ct + 1 ))

    transcript=$SCOURSH_SCRATCH/net-transport-tls-$$-$RANDOM-$i.transcript
    : >"$transcript"
    if tls_probe "$addr" "$port" "$host" "$timeout_s" "$transcript" && tls_parse_session "$transcript"; then
      # This port already speaks TLS directly - the standard-encrypted-twin
      # deployment working as intended.  Not a finding; modules/network/
      # tlsport.sh already assesses whether THIS session is any good.
      tlsonly_ct=$(( tlsonly_ct + 1 ))
      run_record notes "module=network check=transport target=$target endpoint=$host:$port protocol=$proto plaintext_port_speaks_tls=true - no plaintext finding; see NET-TLS-* for this session's own quality"
      rm -f -- "$transcript"
      # STARTTLS-not-required cannot apply either: there is no plaintext
      # exchange for this listener to have exposed at all.
      starttls_notapplicable_ct=$(( starttls_notapplicable_ct + 1 ))
      continue
    fi
    rm -f -- "$transcript"

    plaintext_ct=$(( plaintext_ct + 1 ))
    transport_emit_plaintext_service "$target" extra-host "$scheme" "$host" "$port" "$proto" "$twin"

    if ! net_transport_proto_starttls_capable "$proto"; then
      starttls_notapplicable_ct=$(( starttls_notapplicable_ct + 1 ))
      continue
    fi
    starttls_applicable_ct=$(( starttls_applicable_ct + 1 ))

    bfile=$SCOURSH_SCRATCH/net-transport-banner.$BASHPID
    rm -f "$bfile"
    net_read_banner "$addr" "$port" "$_NET_TRANSPORT_BANNER_MAX_BYTES" "$bfile" || true
    text=''
    if [[ -s $bfile ]]; then
      text=$(net_transport_banner_read_text "$bfile" "$_NET_TRANSPORT_BANNER_MAX_BYTES" 2>/dev/null || printf '')
    fi
    rm -f "$bfile"

    if [[ -n $text ]] && net_transport_banner_advertises_starttls "$text"; then
      starttls_ct=$(( starttls_ct + 1 ))
      transport_emit_starttls_not_required "$target" extra-host "$scheme" "$host" "$port" "$proto" "$text"
    else
      starttls_clean_ct=$(( starttls_clean_ct + 1 ))
    fi
  done

  # Every reduction below names both ids as `checks=[ID ID]` when the reason
  # applies to both (the not-yet-classified TCP states), or the single
  # applicable id when a reason is check-specific (protocol applicability
  # diverges between the two checks the moment a listener speaks TLS
  # directly - see the loop above) - modules/network/banner.sh's own note on
  # why this spelling, not reachability.sh's singular `check=`, is what
  # modules/network/run.sh's `_net_record_unaccounted` backstop recognises.
  if (( unresolvable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=transport.sh reason=net_listener_unresolvable checks=[$_NET_TRANSPORT_IDS] target=$target count=$unresolvable_ct - that many non-base-url listener(s) could not be re-authorised/re-resolved at probe time, so neither NET-TRANSPORT-* check was attempted for them. Reason(s): $unresolvable_reasons."
  fi
  local non_open_ct=$(( notopen_ct + filtered_ct ))
  if (( non_open_ct > 0 )); then
    run_record coverage_reduction "module=network phase=transport.sh reason=net_check_not_applicable checks=[$_NET_TRANSPORT_IDS] target=$target count=$non_open_ct not_open=$notopen_ct filtered=$filtered_ct - that many non-base-url listener(s) were not open this run (report.md §5.2 rule 4: 'did not answer in time' and 'refused' are different facts, kept separate here in the breakdown even though both prevent either check from applying), so neither NET-TRANSPORT-* check was applicable to them."
  fi
  if (( plaintext_notapplicable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=transport.sh reason=proto_not_recognised checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01] target=$target count=$plaintext_notapplicable_ct - that many open non-base-url listener(s) are on a port outside this check's static plaintext-protocol table (FTP 21, SMTP 25, POP3 110, IMAP 143, LDAP 389), so no standard encrypted variant could be named for them and this check does not apply."
  fi
  if (( starttls_notapplicable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=transport.sh reason=proto_not_starttls_capable checks=[NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01] target=$target count=$starttls_notapplicable_ct - that many open non-base-url listener(s) either name a protocol this check cannot read an unprompted STARTTLS signal for (LDAP, whose StartTLS is a binary extended operation with no greeting to read, or FTP, whose AUTH TLS advertisement uses a different token and is not volunteered unprompted), already speak TLS directly (no plaintext exchange to have exposed), or are on a port outside the plaintext-protocol table entirely, so this check does not apply to them."
  fi

  if (( plaintext_applicable_ct > 0 )); then
    run_record checks_run NET-TRANSPORT-PLAINTEXT_SERVICE-01
  fi
  if (( starttls_applicable_ct > 0 )); then
    run_record checks_run NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01
  fi

  if (( plaintext_applicable_ct == 0 && starttls_applicable_ct == 0 )); then
    run_record coverage_gap "network transport: none of target '$(net_scope_safe_text "$target" 80)''s non-base-url listener(s) matched a protocol either NET-TRANSPORT-* check recognises this run (${#xh_host[@]} declared, $open_ct open, $unresolvable_ct unresolvable, $non_open_ct not open/filtered, $plaintext_notapplicable_ct on an unmapped port), so neither check observed anything. This is not evidence of safety."
  fi

  log_info "network transport: target '$target' - ${#xh_host[@]} non-base-url listener(s), $open_ct open, plaintext=$plaintext_ct tls-direct=$tlsonly_ct starttls-advertised=$starttls_ct starttls-clean=$starttls_clean_ct (unresolvable=$unresolvable_ct not-open=$notopen_ct filtered=$filtered_ct unmapped=$plaintext_notapplicable_ct)"
  return 0
}

_transport_run
