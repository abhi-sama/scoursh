#!/usr/bin/env bash
# modules/network/tlsport.sh - the NET-08 tier-2 probe: TLS identification on
# a non-`base-url` listener, and the `NET-TLS-*` checks.
#
# THIS IS A PHASE SCRIPT: modules/network/engine.sh's `net_run_phase` reaches
# it with a plain `source` (at tier `passive`, so it runs at every
# `--intensity`), so it inherits the whole run context and anything it emits
# lands in this process's shard.  Per that function's contract it carries NO
# sourced-once guard - one run can legitimately reach the same phase twice (a
# second target, a second scan_main invocation in one process).
#
# WHY THIS DOES ITS OWN OPEN-STATE CLASSIFICATION RATHER THAN TRUSTING A PRIOR
# reachability.sh PASS.  modules/network/reachability.sh (NET-06) sits at tier
# `safe`; this phase sits at tier `passive`.  A run invoked with
# `--intensity passive` therefore runs THIS phase and SKIPS reachability.sh
# entirely (net_intensity_permits fails for a `safe`-tier phase under a
# `passive` run) - so there is no "reachability already ran this pass" fact
# this phase could depend on, and no artifact NET-06 writes that would carry
# one (reachability.sh emits findings and coverage records, not a
# `listener-state.json`). "Reuse NET-06's open-state classification" therefore
# means reusing the SAME MECHANISM reachability.sh uses to decide
# open/not-open/filtered - `lib/nettransport.sh`'s `net_connect_probe`, on the
# gate-pinned address `http_authorize_raw_connection` already resolved, with
# the identical three-state vocabulary and the identical
# filtered-is-never-not-open discipline -  reached the
# same way reachability.sh itself reaches it: a second, independent classify
# call, never a cached result from a different phase this run may not have
# run at all.
#
# tls_engine.sh (modules/dast/passive/tls_engine.sh) IS REUSED VERBATIM, PER
# THIS TICKET'S OWN INSTRUCTION, AND NOT FORKED.  Every parser, every
# predicate and the one `openssl s_client` invocation (`tls_probe`, behind the
# swappable SCOURSH_TLS_PROBE hook) live there unchanged; this file supplies
# only the live inputs (which listener, which target, which config) and the
# `net` module's own finding shape.  tests/lint-shell.sh's tension-19
# no-bypass check already exempts `modules/dast/passive/tls.sh` and
# `modules/dast/passive/tls_engine.sh` BY PATH - this file introduces no new
# `openssl s_client` call site, so that exemption list needs no edit.
#
# WHY NET-TLS-* AND NOT DAST-TLS-*.  `modules/dast/passive/tls.sh` already
# assesses the target's own `base-url` listener; this phase is genuinely new
# coverage - DAST-TLS-* only ever looks at the
# base-url listener.  This phase therefore probes every OTHER declared
# listener (config/scope.conf's `extra-host` entries, NET-05's `role:
# extra-host` rows) and skips the `base-url` row outright - reusing tls.sh's
# module=dast/base-url pass a second time under a different check id would
# double-report the identical listener under two different module namespaces.
#
# THE HONESTY CONTRACT, APPLIED PER LISTENER BUT REPORTED
# AGGREGATED.  A listener that is not-open, filtered, or open-but-not-TLS
# (the handshake produced no session) is a counted coverage_reduction, never a
# silent clean run and never a finding - reachability.sh's own "ONE reduction
# naming the count, never one per dropped tuple" discipline is reused here
# rather than flooding run.json with a line per port.  Per-listener facts -
# the finding itself, and the protocol/cipher `notes` line this check
# reports even when nothing fires - are still emitted per
# listener, because those ARE listener-specific facts; only the SKIP
# categories are aggregated.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/passive/tls_engine.sh
source "${BASH_SOURCE[0]%/*}/../dast/passive/tls_engine.sh"
# `reach_listeners_load` (NET-06's own listeners.json reader) is reused
# rather than a second copy - this file's own header names the same
# "shellcheck -x does not memoise" cost every sibling `*_engine.sh` in this
# tree already weighs, and reachability_engine.sh is a small, already-guarded
# leaf (it sources only lib/core.sh), so the edge this adds is cheap and the
# alternative is a byte-identical THIRD copy of a JSON reader this tree
# already has two of (this file's own listeners.json shape and
# modules/dast/crawl_engine.sh's endpoints.json shape).
# shellcheck source=modules/network/reachability_engine.sh
source "${BASH_SOURCE[0]%/*}/reachability_engine.sh"
# lib/nettransport.sh (NET-03) carries no sourced-once guard of its own (see
# its own header) - sourced unconditionally here rather than guarded, matching
# reachability.sh's own contract, for `net_connect_probe`/`net_probe_capability`.
# shellcheck source=lib/nettransport.sh
source "${BASH_SOURCE[0]%/*}/../../lib/nettransport.sh"
# For http_authorize_raw_connection - see reachability.sh's own header for why
# this is called AGAIN here rather than trusted from inventory.sh's earlier
# pass: listeners.json is already-authorized OPERATOR CONFIG, so re-running
# the fatal gate refuses an operator-configured tuple, and re-resolving the
# hostname AT PROBE TIME is what keeps the pinned-resolution anti-TOCTOU
# guarantee real for a probe that can run an arbitrary amount of time after
# inventory.sh wrote its artifact.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

_NET_TLS_IDS='NET-TLS-WEAK_PROTOCOL-01 NET-TLS-WEAK_CIPHER-01 NET-TLS-CERT_EXPIRED-01 NET-TLS-CERT_EXPIRING-01 NET-TLS-SELF_SIGNED-01 NET-TLS-WILDCARD_CERT-01'

# `_net_tls_emit CHECK_ID TITLE SEVERITY CWE OWASP TARGET HOST PORT TRANSPORT
# EVIDENCE REMEDIATION` - one helper so every NET-TLS-* finding carries the
# `net` fingerprint location profile (lib/findings.sh: target host port
# transport - NET-02) and only the per-check fields vary.  Byte-identical
# shape to modules/network/reachability_engine.sh's own `reach_emit_*`
# helpers, one module file over.
_net_tls_emit() {
  local check_id=$1 title=$2 severity=$3 cwe=$4 owasp=$5
  local target=$6 host=$7 port=$8 transport=$9 evidence=${10} remediation=${11}

  finding_new
  finding_set check_id "$check_id"
  finding_set module net
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence high
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$transport"
  finding_set corr_target "$target"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# `_net_tls_assess TRANSCRIPT PEM NOW WARN_DAYS EXPECT_WILDCARD TARGET HOST
# PORT TRANSPORT` - every check this phase asks tls_engine.sh for, over one
# already-captured handshake against ONE listener.  A direct, one-listener
# port of modules/dast/passive/tls.sh's own `_dast_tls_assess`, adapted to
# the `net` finding shape above instead of the `dast` one (target/host/port/
# transport rather than target/method/path_template/param_location/
# param_name) and to per-target AGGREGATED skip accounting instead of a
# single target's own `run_record coverage_reduction` calls: this function
# sets status flags for its caller's loop to accumulate rather than recording
# a reduction itself, per this file's own header.
#
#   _NET_TLS_HAD_SESSION   1 when the handshake produced a real session
#                          (protocol+cipher), 0 when it did not (open TCP,
#                          but not TLS, or the handshake failed outright)
#   _NET_TLS_HAD_CERT      1 when a leaf certificate was recovered and its
#                          expiry/self-signed/wildcard checks ran, 0 otherwise
_net_tls_assess() {
  local transcript=$1 pem=$2 now=$3 warn_days=$4 expect_wildcard=$5
  local target=$6 host=$7 port=$8 transport=$9
  local endpoint="$host:$port"
  local subject issuer enddate epoch state days names name wildcards='' n=0

  _NET_TLS_HAD_SESSION=0
  _NET_TLS_HAD_CERT=0

  if ! tls_parse_session "$transcript"; then
    return 0
  fi
  _NET_TLS_HAD_SESSION=1

  # The negotiated pair is recorded on the run unconditionally, mirroring
  # modules/dast/passive/tls.sh's own reporting-versus-judging split: protocol/cipher
  # is REPORTED, and a healthy session
  # is not itself a finding.
  run_record notes "module=network check=tlsport target=$target endpoint=$endpoint protocol=${_TLS_PROTOCOL:-unknown} cipher=${_TLS_CIPHER:-unknown} verify_code=${_TLS_VERIFY_CODE:-none}"

  if [[ -n $_TLS_PROTOCOL ]] && tls_protocol_is_weak "$_TLS_PROTOCOL"; then
    _net_tls_emit 'NET-TLS-WEAK_PROTOCOL-01' \
      'TLS endpoint on a declared listener negotiated a deprecated protocol version' high \
      CWE-327 A02:2021 "$target" "$host" "$port" "$transport" \
      "the handshake with $endpoint negotiated $_TLS_PROTOCOL (cipher ${_TLS_CIPHER:-unknown}); RFC 8996 deprecates TLS 1.0 and 1.1 and SSL 2 and 3 are broken" \
      'Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 on this listener and offer TLS 1.2 and TLS 1.3 only. Where a client genuinely cannot be upgraded, terminate its traffic on a separate listener with its own hostname so the deprecated version is not offered to every client of this one.'
  elif [[ -n $_TLS_PROTOCOL ]] && ! tls_protocol_is_known "$_TLS_PROTOCOL"; then
    # Deliberately NOT a finding - see tls_protocol_is_weak's own header.
    run_record coverage_reduction "module=network reason=tls_protocol_unrecognised check=tlsport target=$target endpoint=$endpoint protocol=$_TLS_PROTOCOL - this version is not in tls_engine.sh's table, so it was neither cleared nor reported weak."
  fi

  if [[ -n $_TLS_CIPHER ]] && tls_cipher_is_weak "$_TLS_CIPHER"; then
    _net_tls_emit 'NET-TLS-WEAK_CIPHER-01' \
      'TLS endpoint on a declared listener negotiated a weak cipher suite' high \
      CWE-327 A02:2021 "$target" "$host" "$port" "$transport" \
      "the handshake with $endpoint negotiated cipher $_TLS_CIPHER over ${_TLS_PROTOCOL:-an unknown protocol}; the suite uses a broken, export-grade, anonymous or absent primitive" \
      'Restrict the listener cipher list to AEAD suites with forward secrecy (ECDHE or DHE key exchange with AES-GCM or ChaCha20-Poly1305). Remove every NULL, anonymous, export, RC4, single-DES, 3DES, IDEA, SEED and MD5 suite; on TLS 1.3 leave the default suite set alone and fix the TLS 1.2 list instead.'
  fi

  if [[ ! -s $pem ]]; then
    return 0
  fi
  _NET_TLS_HAD_CERT=1

  subject=$(tls_cert_dn "$pem" subject 2>/dev/null || printf '')
  issuer=$(tls_cert_dn "$pem" issuer 2>/dev/null || printf '')
  [[ -n $subject ]] || subject=$_TLS_SUBJECT
  [[ -n $issuer ]] || issuer=$_TLS_ISSUER

  # -- expiry --------------------------------------------------------------
  enddate=$(tls_cert_enddate "$pem" 2>/dev/null || printf '')
  if [[ -z $enddate ]] || ! epoch=$(tls_time_to_epoch "$enddate"); then
    run_record coverage_reduction "module=network reason=tls_enddate_unparseable check=tlsport target=$target endpoint=$endpoint - the certificate's notAfter could not be read ('${enddate:-absent}'), so its expiry was not assessed."
  else
    state=$(tls_expiry_state "$epoch" "$now" "$warn_days")
    days=$(tls_days_until "$epoch" "$now")
    case $state in
      expired)
        _net_tls_emit 'NET-TLS-CERT_EXPIRED-01' \
          'TLS certificate on a declared listener has expired' critical \
          CWE-324 A02:2021 "$target" "$host" "$port" "$transport" \
          "the certificate $endpoint presents expired at $enddate, $days day(s) ago; every conformant client now refuses this endpoint or is being trained to click through the warning" \
          'Renew the certificate and reload the listener. Automate renewal (ACME or the platform certificate manager) and alert on the remaining lifetime, so the next renewal is not a manual step that can be missed again.'
        ;;
      expiring)
        _net_tls_emit 'NET-TLS-CERT_EXPIRING-01' \
          'TLS certificate on a declared listener expires soon' medium \
          CWE-324 A02:2021 "$target" "$host" "$port" "$transport" \
          "the certificate $endpoint presents expires at $enddate, in $days day(s), inside the configured ${warn_days}-day warning window (config/scanner.conf tls-expiry-warn-days)" \
          'Renew the certificate before it expires and confirm the listener picks up the new one. If renewal is already automated, check that the automation is running and that its own alerting fires - a silent renewal failure looks exactly like a working one until the day it expires.'
        ;;
    esac
  fi

  # -- self-signed -----------------------------------------------------------
  if tls_is_self_signed "$subject" "$issuer" "$_TLS_VERIFY_CODE"; then
    _net_tls_emit 'NET-TLS-SELF_SIGNED-01' \
      'TLS certificate on a declared listener is self-signed and chains to no trusted issuer' high \
      CWE-295 A02:2021 "$target" "$host" "$port" "$transport" \
      "the certificate $endpoint presents has subject '${subject:-unknown}' and issuer '${issuer:-unknown}' (openssl verify code ${_TLS_VERIFY_CODE:-none}${_TLS_VERIFY_TEXT:+: $_TLS_VERIFY_TEXT}); it authenticates nothing a client can check" \
      'Replace the certificate with one issued by a certificate authority the intended clients already trust, and serve the full intermediate chain. If this endpoint is internal and must use a private CA, distribute that CA to the clients and keep them verifying - never disable verification in the client, which is the change this finding usually provokes and is strictly worse than the certificate it works around.'
  fi

  # -- wildcard, against the per-target expectation ---------------------------
  names=$(tls_cert_text "$pem" 2>/dev/null | tls_sans_from_text || printf '')
  if [[ -z $names ]]; then
    name=$(tls_dn_attr "$subject" CN 2>/dev/null || printf '')
    [[ -n $name ]] && names=${name,,}
  fi
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    n=$(( n + 1 ))
    if tls_is_wildcard "$name"; then
      [[ -n $wildcards ]] && wildcards+=' '
      wildcards+=$name
    fi
  done <<<"$names"

  if (( n == 0 )); then
    run_record coverage_reduction "module=network reason=tls_no_names_in_cert check=tlsport target=$target endpoint=$endpoint - the certificate carries neither a subjectAltName nor a subject CN, so the wildcard expectation could not be evaluated."
  elif [[ -n $wildcards && $expect_wildcard != true ]]; then
    _net_tls_emit 'NET-TLS-WILDCARD_CERT-01' \
      'TLS endpoint on a declared listener serves a wildcard certificate where a host-specific one is expected' medium \
      CWE-693 A02:2021 "$target" "$host" "$port" "$transport" \
      "the certificate $endpoint presents covers [$wildcards] out of $n name(s), and target '$target' does not set tls-expect-wildcard: true in config/scope.conf; one private key therefore authenticates every host under those labels" \
      'Issue a certificate whose subjectAltName names this host specifically, so a compromise of its private key cannot impersonate every sibling host under the wildcard label. If a wildcard is genuinely the intended design for this target, record that by setting tls-expect-wildcard: true on its config/scope.conf entry - which makes the expectation explicit and reviewable rather than making this finding disappear silently.'
  elif [[ -n $wildcards ]]; then
    run_record notes "module=network check=tlsport target=$target endpoint=$endpoint wildcard_certificate=[$wildcards] expected=true - no finding, config/scope.conf declares a wildcard is expected for this target"
  fi
  return 0
}

_net_tlsport_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/tlsport.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  # openssl is this check's one external dependency and the whole
  # measurement, exactly as modules/dast/passive/tls.sh's own check.  Absent
  # is a declared skip (rules/RULE-FORMAT.md §9.5 requires-cmd), never an
  # error - named against all six check ids, not a generic module note, per
  # AGENTS.md's authz.sh "checks_run must count what SUCCEEDED" lesson.
  if ! _have openssl; then
    run_record coverage_reduction "module=network reason=requires_cmd_absent cmd=openssl checks=[$_NET_TLS_IDS] target=$target - the TLS-identification checks need openssl for the handshake and the certificate, and it is not on PATH, so none of them ran."
    run_record coverage_gap "network tlsport: openssl is not available, so the TLS-identification checks (protocol, cipher, certificate expiry, self-signing, wildcard) did not run on target '$target''s non-base-url listeners. Their transport was not tested."
    return 0
  fi

  # The bash /dev/tcp capability this phase's own open-state classification
  # needs (lib/nettransport.sh's net_probe_capability) - checked BEFORE the
  # listener loop for the identical reason reachability.sh's own
  # `_reach_capability_reduction` is: letting every listener degrade to
  # 'filtered' naturally would still record checks_run for a check that was
  # never really covered.  A direct-engine test suite that sources this file
  # with no lib/nettransport.sh anywhere in the process is the identical
  # shape tests/suites/dast-cors.sh's own guards exist for - permissive when
  # absent.
  if declare -F net_probe_capability >/dev/null 2>&1 && ! net_probe_capability; then
    run_record coverage_reduction "module=network reason=net_probe_cmd_absent checks=[$_NET_TLS_IDS] target=$target - this bash was built without --enable-net-redirections (lib/nettransport.sh), so no TCP connect could be attempted for any of this target's non-base-url listeners; none of the six NET-TLS-* checks produced a real result and none is recorded as covered."
    return 0
  fi

  if declare -F net_inventory_read >/dev/null 2>&1; then
    net_inventory_read
  else
    _NET_LISTENERS_FILE='' _NET_LISTENERS_STATE=absent
  fi

  if [[ $_NET_LISTENERS_STATE != present ]]; then
    run_record coverage_reduction "module=network reason=no_declared_listeners checks=[$_NET_TLS_IDS] target=$target - reports/<run>/inventory/listeners.json was not usable this run (modules/network/inventory.sh writes no artifact, or an empty one, for a target with only base-url, or every extra-host dropped)."
    run_record coverage_gap "network tlsport: target '$(net_scope_safe_text "$target" 80)' has no usable declared listener set beyond its base-url this run, so no NET-TLS-* check probed anything. This is the absence of a test, not the absence of a problem."
    return 0
  fi

  reach_listeners_load "$_NET_LISTENERS_FILE" "$target"

  # ONLY non-base-url listeners: modules/dast/passive/tls.sh already assesses
  # the target's own base-url row (this file's own header).  A target whose
  # only surviving row IS base-url (defensive - NET-05 never writes a file in
  # that case, but a direct-engine test or a hand-edited artifact could)
  # collapses to the identical no-listeners outcome above.
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
    run_record coverage_reduction "module=network reason=no_declared_listeners checks=[$_NET_TLS_IDS] target=$target - the declared listener set for this target names no non-base-url (extra-host) entry, and modules/dast/passive/tls.sh already assesses base-url."
    run_record coverage_gap "network tlsport: target '$(net_scope_safe_text "$target" 80)' declares no non-base-url listener, so no NET-TLS-* check had anything of its own to probe. This is the absence of a test, not the absence of a problem."
    return 0
  fi

  local warn_days timeout_s now url addr state expect_wildcard
  warn_days=$(config_scanner_value tls-expiry-warn-days)
  timeout_s=$(config_scanner_value http-timeout)
  expect_wildcard=$(config_scope_field_or "$target" tls-expect-wildcard false)
  now=$(now_epoch)

  local unresolvable_ct=0 filtered_ct=0 notopen_ct=0 probe_failed_ct=0 nosession_ct=0
  local unresolvable_reasons=''
  local -A unresolvable_reason_seen=()
  local session_ever=0 cert_ever=0 open_ct=0
  local transcript pem

  for (( i = 0; i < ${#xh_host[@]}; i++ )); do
    scheme=${xh_scheme[i]} host=${xh_host[i]} port=${xh_port[i]}
    url="$scheme://$host:$port/"

    # An operator-configured tuple is
    # refused FATALLY on every reason except a transient DNS failure, which
    # degrades to one counted reduction rather than aborting every sibling
    # listener - identical to reachability.sh's own `false` dns_fatal arg.
    if ! http_authorize_raw_connection "$url" "$target" false; then
      unresolvable_ct=$(( unresolvable_ct + 1 ))
      if [[ -z ${unresolvable_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        unresolvable_reason_seen[$_HTTP_RAW_REASON]=1
        unresolvable_reasons+="${unresolvable_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
      continue
    fi
    addr=$_HTTP_RAW_ADDR

    # THE OPEN-STATE CLASSIFICATION THIS FILE'S OWN HEADER PROMISES: the same
    # net_connect_probe call reachability.sh makes, on the same gate-pinned
    # address, with the same three-state vocabulary. A listener that is not
    # open never reaches a TLS handshake at all - the module's own
    # honesty contract: "a probe that did not run is a counted reduction,
    # never a silent clean".
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

    transcript=$SCOURSH_SCRATCH/net-tls-$$-$RANDOM-$i.transcript
    pem=$SCOURSH_SCRATCH/net-tls-$$-$RANDOM-$i.pem
    : >"$transcript"
    : >"$pem"

    if ! tls_probe "$addr" "$port" "$host" "$timeout_s" "$transcript"; then
      probe_failed_ct=$(( probe_failed_ct + 1 ))
      rm -f -- "$transcript" "$pem"
      continue
    fi

    tls_extract_pem "$transcript" "$pem" || true
    _net_tls_assess "$transcript" "$pem" "$now" "$warn_days" "$expect_wildcard" \
      "$target" "$host" "$port" "$scheme"
    if (( _NET_TLS_HAD_SESSION )); then
      session_ever=1
    else
      nosession_ct=$(( nosession_ct + 1 ))
    fi
    (( _NET_TLS_HAD_CERT )) && cert_ever=1

    # The transcript holds the certificate the target presented (public
    # information) and no credential this phase sent - it sent none. Removed
    # anyway, exactly as modules/dast/passive/tls.sh does: the run directory
    # is the artifact surface and a transient probe capture is not part of it.
    rm -f -- "$transcript" "$pem"
  done

  if (( unresolvable_ct > 0 )); then
    run_record coverage_reduction "module=network reason=net_listener_unresolvable checks=[$_NET_TLS_IDS] target=$target count=$unresolvable_ct - that many non-base-url listener(s) could not be re-authorised/re-resolved at probe time (they were authorised when modules/network/inventory.sh ran earlier this same run), so no TLS handshake was attempted for them. Reason(s): $unresolvable_reasons."
  fi
  if (( filtered_ct > 0 )); then
    run_record coverage_reduction "module=network reason=filtered checks=[$_NET_TLS_IDS] target=$target count=$filtered_ct - that many non-base-url listener(s) neither accepted nor refused a TCP connection before this probe's deadline. 'Did not answer in time' and 'refused' are different facts: these are never handshaked with and produce no finding either way."
  fi
  if (( notopen_ct > 0 )); then
    run_record coverage_reduction "module=network reason=net_check_not_applicable checks=[$_NET_TLS_IDS] target=$target count=$notopen_ct - that many non-base-url listener(s) did not accept a TCP connection this run, so TLS identification does not apply to them; nothing about their transport was assessed."
  fi
  if (( probe_failed_ct > 0 )); then
    run_record coverage_reduction "module=network reason=tls_probe_failed checks=[$_NET_TLS_IDS] target=$target count=$probe_failed_ct - that many open listener(s) produced no TLS transcript at all (connection refused, reset, or timed out after ${timeout_s}s) once the handshake was attempted, so no transport property of them was assessed."
  fi
  if (( nosession_ct > 0 )); then
    run_record coverage_reduction "module=network reason=tls_handshake_failed checks=[$_NET_TLS_IDS] target=$target count=$nosession_ct - that many open listener(s) accepted a TCP connection but produced no completed TLS session (the transcript records no negotiated protocol and cipher), so the listener does not appear to speak TLS on this port and none of its transport properties were assessed."
  fi

  # checks_run counts what SUCCEEDED, recorded ONCE for the whole target
  # rather than once per listener - AGENTS.md's own authz.sh lesson, applied
  # per check rather than per phase: WEAK_PROTOCOL/WEAK_CIPHER need only a
  # completed session (any listener), the four cert-dependent checks need a
  # recovered certificate (any listener) - the identical split
  # modules/dast/passive/tls.sh's own _dast_tls_assess draws for a single
  # target, generalised to "at least one listener this run" for a probe that
  # covers several.
  if (( session_ever )); then
    run_record checks_run 'NET-TLS-WEAK_PROTOCOL-01'
    run_record checks_run 'NET-TLS-WEAK_CIPHER-01'
  fi
  if (( cert_ever )); then
    run_record checks_run 'NET-TLS-CERT_EXPIRED-01'
    run_record checks_run 'NET-TLS-CERT_EXPIRING-01'
    run_record checks_run 'NET-TLS-SELF_SIGNED-01'
    run_record checks_run 'NET-TLS-WILDCARD_CERT-01'
  fi

  if (( ! session_ever )); then
    run_record coverage_gap "network tlsport: none of target '$(net_scope_safe_text "$target" 80)''s non-base-url listener(s) produced a completed TLS session this run (${#xh_host[@]} declared, $open_ct open, $unresolvable_ct unresolvable, $filtered_ct filtered, $notopen_ct not-open, $probe_failed_ct probe-failed, $nosession_ct no-session), so none of the six NET-TLS-* checks observed a real transport property. This is not evidence of safety."
  fi

  log_info "network tlsport: target '$target' - ${#xh_host[@]} non-base-url listener(s), $open_ct open, sessions=$session_ever certs=$cert_ever (unresolvable=$unresolvable_ct filtered=$filtered_ct not-open=$notopen_ct probe-failed=$probe_failed_ct no-session=$nosession_ct)"
  return 0
}

_net_tlsport_run
