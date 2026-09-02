#!/usr/bin/env bash
# modules/dast/passive/tls.sh - the §7.1 transport-security PHASE
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-07).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - one run can legitimately reach the same phase
# twice (a second scope target, a second `scan_main` in one process) and a guard
# would silently make the second one a no-op.  The pure functions - every parser
# and every predicate - live in modules/dast/passive/tls_engine.sh, which does
# have a guard.
#
# ============================================================================
# THIS FILE IS THE ONE DOCUMENTED EXCEPTION TO THE lib/http.sh CHOKEPOINT.
# ============================================================================
# docs/FOUNDATION.md tension 19 requires every network call in scoursh to go
# through `http_request`, and tests/lint-shell.sh fails the build for a bare
# curl/wget/nc/`openssl s_client` in any other file.  This check is exempted,
# and the reason is not convenience: what §7.1 asks for here is the negotiated
# PROTOCOL and CIPHER and the certificate the server PRESENTS, which are
# properties of a TLS handshake.  They are not carried in an HTTP request or
# response at all, curl does not expose them, and no composition of
# `http_request` calls can obtain them.  The handshake itself is the
# measurement.
#
# THE EXEMPTION IS FROM THE TRANSPORT AND FROM NOTHING ELSE, and that is
# enforced structurally rather than promised in a comment:
#
#   * THE SCOPE GATE STILL BINDS.  The target URL goes through
#     `http_authorize_raw_connection` (lib/http.sh §9b), which runs the
#     identical `http_gate_url` pipeline `http_request` runs - normalisation,
#     userinfo refusal, the config/scope.conf tuple compare, and the
#     resolution-pinning deny list - and dies with exit 3 through the same audit
#     path on a refusal.  There is no raw-URL path into this file.
#   * THE ADDRESS IS THE ONE THE GATE PINNED.  `s_client -connect` is given the
#     resolved address, never the hostname, so this check cannot reach a
#     different machine than the gate approved.  The hostname travels in SNI
#     only.
#   * THE TENSION-16 CONTROLS STILL BIND.  The same call spends a token of the
#     same rate limiter, decrements the same per-run request budget, and checks
#     the same circuit breaker, so a handshake costs exactly what a request
#     costs and `--jobs` cannot multiply it.
#
# What this file owns, therefore, is one `openssl s_client` invocation - which
# lives in tls_engine.sh's `_tls_probe_default`, behind the swappable
# `SCOURSH_TLS_PROBE` hook - and nothing else.
#
# NON-DESTRUCTIVE, AND PASSIVE IN THE §7.1 SENSE.  One TLS handshake per target
# is opened, no application data is sent (stdin is /dev/null), no request is
# made, and the connection is closed.  Nothing on the target changes.
#
# WHAT IS CONFIGURABLE, AND WHY EACH KNOB IS WHERE IT IS.  Both are
# operator-supplied per this ticket's own requirement, and both are ADDITIVE
# OPTIONAL keys on an existing frozen schema (rules/RULE-FORMAT.md §14's worked
# `contact` case: item 2 only, no format_version bump):
#
#   * `tls-expiry-warn-days` on config/scanner.conf (§9.6.1), default 30.  It is
#     a SCANNER-WIDE policy - "how much notice does this operator want" is a
#     property of the operator, not of one host - and it sits beside the other
#     run-shaping numbers rather than being repeated per target.
#   * `tls-expect-wildcard` on config/scope.conf (§9.4), default `false`.  It is
#     PER TARGET, because whether a wildcard certificate is expected is a fact
#     about that deployment: a multi-tenant edge legitimately serves one, and a
#     single host-specific service does not.  A scanner-wide setting would force
#     one answer onto an estate that has both, and the false positive it
#     produced would be indistinguishable from a real finding.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/passive/tls_engine.sh
source "${BASH_SOURCE[0]%/*}/tls_engine.sh"

# `_dast_tls_emit CHECK_ID TITLE SEVERITY CWE OWASP EVIDENCE REMEDIATION` - one
# helper, so every TLS finding carries the same DAST location profile
# (docs/FOUNDATION.md tension 5: target, method, path_template, param_location,
# param_name) and only the per-check fields vary.
#
# THE LOCATION PROFILE FOR A TRANSPORT FINDING, AND WHY IT IS NOT A URL.  A TLS
# weakness is a property of a (host, port) endpoint, not of a request or a
# parameter: every path on that listener has it, and reporting it against one
# crawled path would make the finding's identity depend on which page the
# crawler happened to reach first - so an unrelated crawl change would re-report
# every TLS finding as `new` once step 7's diff exists.  `method` is therefore
# the literal `TLS` (this is a handshake, not a verb), `path_template` is `/`
# (the listener as a whole), and `param_name` is `host:port`, which is what
# genuinely distinguishes two findings of the same kind under one target with
# two `extra-host` listeners.  `check_id` is itself a fingerprint component, so
# two different TLS weaknesses on one listener stay two findings.
_dast_tls_emit() {
  local check_id=$1 title=$2 severity=$3 cwe=$4 owasp=$5 evidence=$6 remediation=$7
  local target=${SCOURSH_DAST_TARGET:-}

  finding_new
  finding_set check_id "$check_id"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence high
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method TLS
  finding_set loc_path_template '/'
  finding_set loc_param_location transport
  finding_set loc_param_name "${_DAST_TLS_ENDPOINT:-unknown}"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# `_dast_tls_assess TRANSCRIPT PEM NOW WARN_DAYS EXPECT_WILDCARD HOST` - every
# check §7.1 asks this module for, over one already-captured handshake.
#
# It is split out from the phase body so the whole decision surface is reachable
# from a recorded transcript with no scope config, no run directory and no
# network - which is how tests/suites/dast-tls.sh drives it.
_dast_tls_assess() {
  local transcript=$1 pem=$2 now=$3 warn_days=$4 expect_wildcard=$5 host=$6
  local endpoint=${_DAST_TLS_ENDPOINT:-$host}
  local target=${SCOURSH_DAST_TARGET:-}
  local subject issuer enddate epoch state days names name wildcards='' n=0

  if ! tls_parse_session "$transcript"; then
    run_record coverage_reduction "module=dast reason=tls_handshake_failed check=tls target=$target endpoint=$endpoint - the TLS handshake produced no session (the transcript records no negotiated protocol or cipher), so no transport property of this endpoint was assessed."
    run_record coverage_gap "dast tls: the TLS handshake with '$endpoint' did not complete, so its protocol, cipher and certificate were NOT examined. A clean transport result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  # ---------------------------------------------------------------------
  # Protocol and cipher, which §7.1 asks to be REPORTED as well as judged.
  # ---------------------------------------------------------------------
  # The negotiated pair is recorded on the run unconditionally - a reader of
  # run.json can see what the target actually speaks even when nothing about it
  # is a finding, which is the reporting half of "report on protocol and cipher
  # negotiated" and is not expressible as a finding, because a healthy TLS 1.3
  # session is not one.
  run_record notes "module=dast check=tls target=$target endpoint=$endpoint protocol=${_TLS_PROTOCOL:-unknown} cipher=${_TLS_CIPHER:-unknown} verify_code=${_TLS_VERIFY_CODE:-none}"

  run_record checks_run 'DAST-TLS-WEAK_PROTOCOL-01'
  if [[ -n $_TLS_PROTOCOL ]] && tls_protocol_is_weak "$_TLS_PROTOCOL"; then
    _dast_tls_emit 'DAST-TLS-WEAK_PROTOCOL-01' \
      'TLS endpoint negotiated a deprecated protocol version' high \
      CWE-327 A02:2021 \
      "the handshake with $endpoint negotiated $_TLS_PROTOCOL (cipher ${_TLS_CIPHER:-unknown}); RFC 8996 deprecates TLS 1.0 and 1.1 and SSL 2 and 3 are broken" \
      'Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 on this listener and offer TLS 1.2 and TLS 1.3 only. Where a client genuinely cannot be upgraded, terminate its traffic on a separate listener with its own hostname so the deprecated version is not offered to every client of this one.'
  elif [[ -n $_TLS_PROTOCOL ]] && ! tls_protocol_is_known "$_TLS_PROTOCOL"; then
    # Deliberately NOT a finding: see tls_protocol_is_weak's own header for why
    # an unrecognised version must not be reported broken.
    run_record coverage_reduction "module=dast reason=tls_protocol_unrecognised check=tls target=$target endpoint=$endpoint protocol=$_TLS_PROTOCOL - this version is not in the engine's table, so it was neither cleared nor reported weak."
    run_record coverage_gap "dast tls: '$endpoint' negotiated protocol '$_TLS_PROTOCOL', which modules/dast/passive/tls_engine.sh does not recognise. It was NOT assessed either way - reporting an unknown version as broken would put a false finding on every target that adopts the next TLS version before this table is updated."
  fi

  run_record checks_run 'DAST-TLS-WEAK_CIPHER-01'
  if [[ -n $_TLS_CIPHER ]] && tls_cipher_is_weak "$_TLS_CIPHER"; then
    _dast_tls_emit 'DAST-TLS-WEAK_CIPHER-01' \
      'TLS endpoint negotiated a weak cipher suite' high \
      CWE-327 A02:2021 \
      "the handshake with $endpoint negotiated cipher $_TLS_CIPHER over ${_TLS_PROTOCOL:-an unknown protocol}; the suite uses a broken, export-grade, anonymous or absent primitive" \
      'Restrict the listener cipher list to AEAD suites with forward secrecy (ECDHE or DHE key exchange with AES-GCM or ChaCha20-Poly1305). Remove every NULL, anonymous, export, RC4, single-DES, 3DES, IDEA, SEED and MD5 suite; on TLS 1.3 leave the default suite set alone and fix the TLS 1.2 list instead.'
  fi

  # ---------------------------------------------------------------------
  # The certificate.  Absent is a recorded gap, never a silent pass.
  # ---------------------------------------------------------------------
  if [[ ! -s $pem ]]; then
    run_record coverage_reduction "module=dast reason=tls_no_certificate check=tls target=$target endpoint=$endpoint - the transcript carried no PEM certificate, so expiry, self-signing and the wildcard expectation were not assessed."
    run_record coverage_gap "dast tls: no leaf certificate was recovered from the handshake with '$endpoint', so its expiry, its issuer and its subject alternative names were NOT examined."
    return 0
  fi

  subject=$(tls_cert_dn "$pem" subject 2>/dev/null || printf '')
  issuer=$(tls_cert_dn "$pem" issuer 2>/dev/null || printf '')
  [[ -n $subject ]] || subject=$_TLS_SUBJECT
  [[ -n $issuer ]] || issuer=$_TLS_ISSUER

  # -- expiry ------------------------------------------------------------
  run_record checks_run 'DAST-TLS-CERT_EXPIRED-01'
  run_record checks_run 'DAST-TLS-CERT_EXPIRING-01'
  enddate=$(tls_cert_enddate "$pem" 2>/dev/null || printf '')
  if [[ -z $enddate ]] || ! epoch=$(tls_time_to_epoch "$enddate"); then
    run_record coverage_reduction "module=dast reason=tls_enddate_unparseable check=tls target=$target endpoint=$endpoint - the certificate's notAfter could not be read ('${enddate:-absent}'), so its expiry was not assessed."
    run_record coverage_gap "dast tls: the notAfter date of '$endpoint''s certificate could not be parsed, so neither expiry nor the ${warn_days}-day expiring-soon window was evaluated. It was not treated as valid; it was not evaluated."
  else
    state=$(tls_expiry_state "$epoch" "$now" "$warn_days")
    days=$(tls_days_until "$epoch" "$now")
    case $state in
      expired)
        _dast_tls_emit 'DAST-TLS-CERT_EXPIRED-01' \
          'TLS certificate has expired' critical \
          CWE-324 A02:2021 \
          "the certificate $endpoint presents expired at $enddate, $days day(s) ago; every conformant client now refuses this endpoint or is being trained to click through the warning" \
          'Renew the certificate and reload the listener. Automate renewal (ACME or the platform certificate manager) and alert on the remaining lifetime, so the next renewal is not a manual step that can be missed again.'
        ;;
      expiring)
        _dast_tls_emit 'DAST-TLS-CERT_EXPIRING-01' \
          'TLS certificate expires soon' medium \
          CWE-324 A02:2021 \
          "the certificate $endpoint presents expires at $enddate, in $days day(s), inside the configured ${warn_days}-day warning window (config/scanner.conf tls-expiry-warn-days)" \
          'Renew the certificate before it expires and confirm the listener picks up the new one. If renewal is already automated, check that the automation is running and that its own alerting fires - a silent renewal failure looks exactly like a working one until the day it expires.'
        ;;
    esac
  fi

  # -- self-signed -------------------------------------------------------
  run_record checks_run 'DAST-TLS-SELF_SIGNED-01'
  if tls_is_self_signed "$subject" "$issuer" "$_TLS_VERIFY_CODE"; then
    _dast_tls_emit 'DAST-TLS-SELF_SIGNED-01' \
      'TLS certificate is self-signed and chains to no trusted issuer' high \
      CWE-295 A02:2021 \
      "the certificate $endpoint presents has subject '${subject:-unknown}' and issuer '${issuer:-unknown}' (openssl verify code ${_TLS_VERIFY_CODE:-none}${_TLS_VERIFY_TEXT:+: $_TLS_VERIFY_TEXT}); it authenticates nothing a client can check" \
      'Replace the certificate with one issued by a certificate authority the intended clients already trust, and serve the full intermediate chain. If this endpoint is internal and must use a private CA, distribute that CA to the clients and keep them verifying - never disable verification in the client, which is the change this finding usually provokes and is strictly worse than the certificate.'
  fi

  # -- wildcard, against the per-target expectation -----------------------
  run_record checks_run 'DAST-TLS-WILDCARD_CERT-01'
  names=$(tls_cert_text "$pem" 2>/dev/null | tls_sans_from_text || printf '')
  # The CN is consulted only as a FALLBACK, and only when the certificate
  # carries no SAN at all.  RFC 6125 §6.4.4 and every current client ignore the
  # CN when a SAN is present, so reading it anyway would report a wildcard the
  # target does not actually serve to anyone.
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
    run_record coverage_reduction "module=dast reason=tls_no_names_in_cert check=tls target=$target endpoint=$endpoint - the certificate carries neither a subjectAltName nor a subject CN, so the wildcard expectation could not be evaluated."
    run_record coverage_gap "dast tls: no DNS name could be read from '$endpoint''s certificate, so whether it is a wildcard was NOT determined."
  elif [[ -n $wildcards && $expect_wildcard != true ]]; then
    _dast_tls_emit 'DAST-TLS-WILDCARD_CERT-01' \
      'TLS endpoint serves a wildcard certificate where a host-specific one is expected' medium \
      CWE-693 A02:2021 \
      "the certificate $endpoint presents covers [$wildcards] out of $n name(s), and target '$target' does not set tls-expect-wildcard: true in config/scope.conf; one private key therefore authenticates every host under those labels" \
      'Issue a certificate whose subjectAltName names this host specifically, so a compromise of its private key cannot impersonate every sibling host under the wildcard label. If a wildcard is genuinely the intended design for this target, record that by setting tls-expect-wildcard: true on its config/scope.conf entry - which makes the expectation explicit and reviewable rather than making this finding disappear silently.'
  elif [[ -n $wildcards ]]; then
    # The expectation was set and the certificate matches it.  Recorded so a
    # reader can see the check ran and was satisfied, rather than inferring it
    # from an absent finding.
    run_record notes "module=dast check=tls target=$target endpoint=$endpoint wildcard_certificate=[$wildcards] expected=true - no finding, config/scope.conf declares a wildcard is expected for this target"
  fi
  return 0
}

_dast_tls_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local base_url scheme host port endpoint warn_days expect_wildcard now
  local transcript pem timeout_s

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/tls.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # openssl is this check's one external dependency, and it is the whole
  # measurement rather than a helper.  Absent is a declared skip with a reason
  # (rules/RULE-FORMAT.md §9.5 `requires-cmd`), never an error.
  if ! _have openssl; then
    run_record coverage_reduction "module=dast reason=requires_cmd_absent cmd=openssl check=tls target=$target - the transport-security checks need openssl for the TLS handshake and the certificate, and it is not on PATH, so none of them ran."
    run_record coverage_gap "dast tls: openssl is not available, so the transport-security checks (protocol, cipher, certificate expiry, self-signing, wildcard) did not run on target '$target'. Its transport was not tested."
    return 0
  fi

  # WHY THIS READS `base-url` AND NOT DAST-04'S `inventory/endpoints.json`.
  # Every other tier-2 check is per ENDPOINT, so reading the inventory is what
  # it means for them to have a surface at all.  A transport property is not:
  # the negotiated protocol, the negotiated cipher and the presented
  # certificate belong to a LISTENER, `host:port`, and every endpoint in that
  # inventory that shares a listener shares all three by construction.  Two
  # consequences make the distinction load-bearing rather than stylistic.
  # First, this phase's fingerprint (docs/FOUNDATION.md tension 5: target,
  # method, path_template, param_location, param_name) has no component that
  # differs between two endpoints on one listener, so iterating the inventory
  # would emit N identical findings that findings_merge then dedups back to
  # one - N-1 handshakes spent to reach the same output.  Second, it would
  # spend N tokens of the tension-16 request budget for one measurement, on a
  # check whose place in the `quick` profile is earned by costing exactly one.
  # Hence `coverage-scope: target` on all six records in checks.rules.  The
  # inventory is still the right input for a listener this target reaches that
  # `base-url` does not name - a second origin the crawl discovered - and that
  # is a real gap this check does not close; it is DAST-30 (`transport.sh`,
  # §7.4) territory, which already owns the cross-origin transport question.
  #
  # The scope RECORD SET is already loaded: modules/dast/run.sh calls
  # `config_scope_require` for every target before the phase loop runs, and
  # docs/DESIGN.md §7's "scope gate FIRST" is what puts it there.  Re-requiring
  # here would reload from the DEFAULT config/scope.conf path and silently
  # discard whatever path the caller resolved - the same reason
  # modules/dast/crawl.sh reads the field directly rather than re-requiring.
  # The gate itself is re-asserted below, where it belongs, through
  # http_authorize_raw_connection.
  base_url=$(config_scope_field "$target" base-url)
  expect_wildcard=$(config_scope_field_or "$target" tls-expect-wildcard false)

  if ! http_url_normalize "$base_url"; then
    run_record coverage_reduction "module=dast reason=tls_base_url_unparseable check=tls target=$target - config/scope.conf's base-url for this target could not be normalised, so no endpoint to handshake with was resolved."
    return 0
  fi
  scheme=$_HN_SCHEME host=$_HN_HOST port=$_HN_PORT

  # A PLAIN-http TARGET IS A RECORDED GAP, NOT A FINDING FROM THIS CHECK.
  # "this target offers no TLS at all" is a real and more serious result than
  # anything below, and it belongs to DAST-30 (`transport.sh`, §7.4), which owns
  # the HTTP-versus-HTTPS question and can distinguish "no TLS" from "TLS
  # available but not redirected to".  Emitting it here as well would put two
  # findings with two check ids on one fact and make whichever ticket lands
  # second look like a regression.
  if [[ $scheme != https ]]; then
    run_record coverage_reduction "module=dast reason=target_not_https check=tls target=$target - config/scope.conf's base-url for this target is '$scheme://$host:$port', so there is no TLS listener to handshake with and no transport property to assess."
    run_record coverage_gap "dast tls: target '$target' is configured over plain $scheme, so the transport-security checks (protocol, cipher, certificate expiry, self-signing, wildcard) did not run. Whether this target SHOULD be offering TLS is DAST-30's (modules/dast/transport.sh) question, not this check's, and that phase has not landed."
    return 0
  fi

  endpoint="$host:$port"
  _DAST_TLS_ENDPOINT=$endpoint

  # THE GATE, THE PINNED ADDRESS AND THE TENSION-16 SPEND, ALL FROM lib/http.sh.
  # See this file's header: this call is what keeps the exemption narrow.  It
  # still dies with exit 3 on a genuine scope refusal (not in config/scope.conf,
  # userinfo, or the private/loopback deny list), exactly as http_request would.
  #
  # DNS_FATAL IS PASSED false, DELIBERATELY, AND ONLY HERE.  "the operator did
  # not authorise this host" and "this authorised host does not resolve right
  # now" are different facts (see this project's DAST-07 tls.sh fix), and only
  # the first deserves to abort every other phase and every other target in
  # this run.  A resolution failure is instead a declared coverage reduction
  # below, the same vocabulary this phase already uses for an absent openssl
  # or a failed handshake.
  if ! http_authorize_raw_connection "$scheme://$host:$port/" "$target" false; then
    run_record coverage_reduction "module=dast reason=tls_host_unresolvable check=tls target=$target endpoint=$endpoint - $_HTTP_RAW_REASON, so no transport property of this endpoint was assessed."
    run_record coverage_gap "dast tls: '$endpoint' did not resolve ($_HTTP_RAW_REASON), so its protocol, cipher and certificate were NOT examined. A clean transport result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  warn_days=$(config_scanner_value tls-expiry-warn-days)
  timeout_s=$(config_scanner_value http-timeout)
  now=$(now_epoch)

  transcript=$SCOURSH_SCRATCH/dast-tls-$$-$RANDOM.transcript
  pem=$SCOURSH_SCRATCH/dast-tls-$$-$RANDOM.pem
  : >"$transcript"
  : >"$pem"

  if ! tls_probe "$_HTTP_RAW_ADDR" "$port" "$host" "$timeout_s" "$transcript"; then
    run_record coverage_reduction "module=dast reason=tls_probe_failed check=tls target=$target endpoint=$endpoint - the TLS handshake produced no transcript at all (connection refused, reset, or timed out after ${timeout_s}s), so no transport property was assessed."
    run_record coverage_gap "dast tls: no TLS handshake with '$endpoint' could be completed, so its protocol, cipher and certificate were NOT examined. A clean transport result here is the absence of a test, not the absence of a problem."
    rm -f -- "$transcript" "$pem"
    return 0
  fi

  tls_extract_pem "$transcript" "$pem" || true
  _dast_tls_assess "$transcript" "$pem" "$now" "$warn_days" "$expect_wildcard" "$host"

  # The transcript holds the certificate the target presented, which is public
  # information, and no credential - this phase sends none.  It is removed
  # anyway rather than left in the scratch directory, because the run directory
  # is the artifact surface and a transient probe capture is not part of it.
  rm -f -- "$transcript" "$pem"

  log_info "dast tls: target '$target' endpoint $endpoint - protocol=${_TLS_PROTOCOL:-unknown} cipher=${_TLS_CIPHER:-unknown}"
  return 0
}

_dast_tls_phase
