#!/usr/bin/env bash
# modules/network/httpport.sh - NET-09, the `safe-active` HTTP-identification
# probe against a declared NON-STANDARD HTTP port: one `http_request` GET.
# Everything modules/dast/passive/banner.sh already
# does, pointed at port 8080 instead of 443, and it reuses banner_engine.sh's
# product normalisation and the data/versions.db `banner` namespace
# unchanged.
#
# THIS IS A PHASE SCRIPT: `net_run_phase` (modules/network/engine.sh) reaches
# it with a plain `source`, at the `httpport.sh:safe` phase-table row, so it
# DOES something at source time and carries NO sourced-once guard - one run
# can legitimately reach the same phase twice (a second target, a second
# scan_main invocation in one process), and a guard would silently make the
# second a no-op. The pure, testable half is
# modules/network/httpport_engine.sh.
#
# A DECLARED LISTENER, NEVER A DISCOVERED ONE.  Unlike DAST's crawl-derived
# endpoint set, every candidate this phase probes comes straight out of
# NET-05's `reports/<run>/inventory/listeners.json`, which is itself a
# faithful restatement of config/scope.conf's own `extra-host` entries
# (modules/network/inventory.sh's own header) - nothing here invents a URL
# or a port.
#
# ONE GET PER LISTENER, SAFE-ACTIVE, NOT PASSIVE - this ticket's own type
# tag.  A raw TCP banner read (a future NET-07) sends zero
# bytes; issuing an HTTP request line is a step further than that, which is
# why this check's own `tags: safe-active` (modules/network/checks-httpport.rules)
# differs from a future NET-07's `passive` even though both describe "a
# service disclosed its version" in prose.
#
# EVERY REQUEST GOES THROUGH lib/http.sh's `http_request` (tension 19's "no
# bypass"), which is where the scope gate, the rate limiter, the per-run
# request budget, the circuit breaker and DAST-32's ceilings all sit - this
# module inherits every one of them, unchanged, the identical reasoning
# modules/dast/passive/banner.sh's own header gives.
#
# THE GATE IS APPLIED TWICE, DELIBERATELY, MATCHING THE ARTIFACT-TUPLE SHAPE
# modules/network/engine.sh's own header reserves for exactly this ticket
# ("the non-fatal ARTIFACT-tuple path ... is reserved for a FUTURE tuple
# source ... that does not exist yet"; modules/network/inventory.sh's own
# header names the same reservation from the producer side).  Every row in
# listeners.json already passed `http_authorize_raw_connection` once, inside
# NET-05's own run of this same process - but a phase reading an ARTIFACT
# THIS SCANNER WROTE, rather than config/scope.conf directly, is exactly the
# shape `net_endpoint_keep`/`net_scope_record_skips` exist for: a single
# stale or malformed listeners.json row degrades to one counted
# `coverage_reduction` (reason `artifact_tuple_out_of_scope`) rather than
# aborting the whole target's run at exit 3 over a row this phase did not
# author either.  Anything that survives the pre-check is still sent through
# `http_request`, which re-gates it fatally on the way out and on every
# redirect hop - the pre-check is not the gate, and both are required
# (modules/dast/engine.sh section 3b's own reasoning, applied one module
# down).
#
# shellcheck shell=bash
#
# SC2016: the remediation prose in modules/network/checks-httpport.rules
#   quotes config directives literally; nothing here or there is meant to
#   expand.
# shellcheck disable=SC2016
#
# shellcheck source=modules/network/httpport_engine.sh
source "${BASH_SOURCE[0]%/*}/httpport_engine.sh"
# lib/http.sh is the chokepoint; a network run does not otherwise load it
# (modules/network/engine.sh's own header), so a phase that issues traffic
# sources it, guarded exactly as modules/network/inventory.sh and every
# traffic-issuing modules/dast/ phase already do.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# Declared listeners probed in one run.  config/scope.conf's own `extra-host`
# list is operator-authored and ordinarily small, but a bound that truncates
# silently is indistinguishable from a surface that was really that small
# (docs/DESIGN.md §15) - the identical reasoning
# modules/dast/passive/banner_engine.sh's own `_BANNER_MAX_ENDPOINTS` states,
# applied to a list this module reads rather than discovers.
: "${_HTTPPORT_MAX_LISTENERS:=20}"

# `_httpport_transport_prose SCHEME` - the sentence fragment naming which
# transport carried the disclosure, so the evidence tells a reader which
# listener to change without them having to re-read `loc_host`/`loc_port`.
_httpport_transport_prose() {
  case $1 in
    https) printf 'an HTTPS response' ;;
    *) printf 'an HTTP response' ;;
  esac
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The `net` location profile is (target, host, port, transport)
# (lib/findings.sh) - no method, no path, no product, no channel.  ONE
# finding per check id per listener is therefore the most this fingerprint
# can express, which is exactly what this phase produces: at most three
# findings per probed listener (server/version/outdated), each accumulated
# across every disclosure this ONE response carried and reported once, with
# every disclosed product named in its evidence rather than split across
# findings a coarser identity could not tell apart.
_httpport_emit() {
  local kind=$1 scheme=$2 host=$3 port=$4 names=$5
  local target=${SCOURSH_NET_TARGET:-} check title base conf cwe owasp remed evi where transport

  transport=$scheme
  where=$(_httpport_transport_prose "$scheme")

  case $kind in
    server)
      check=NET-SVC-HTTP_SERVER_DISCLOSURE-01; base=info; conf=high
      cwe=CWE-200; owasp=A05:2021
      title='Server or framework disclosed by an HTTP response on a non-standard port'
      remed='Suppress or overwrite the product token in the response. On the origin server this is `server_tokens off` (nginx), `ServerTokens Prod` plus `ServerSignature Off` (Apache), `expose_php = Off` (PHP) or removing `X-Powered-By` in the application framework; where the origin cannot be changed, strip the header at the reverse proxy or CDN. This is defence in depth, not a fix on its own: treat it as one, and patch the component itself on its own schedule.'
      evi="$where from $host:$port (a declared listener, not the target's base-url) names: $names. This listener identifies its running software to every client that reaches it." ;;
    version)
      check=NET-SVC-HTTP_VERSION_DISCLOSURE-01; base=low; conf=high
      cwe=CWE-200; owasp=A05:2021
      title='Framework or component version disclosed by an HTTP response on a non-standard port'
      remed='Stop publishing the exact version to unauthenticated clients on this listener: suppress the product token in the response header, remove any generator meta tag, and serve bundles under a content-hashed filename rather than a version-numbered one. Then keep the component patched, because a version an attacker can also fingerprint by behaviour is only hidden, not fixed.'
      evi="$where from $host:$port discloses: $names. An exact version turns exploit selection into a lookup on this listener the same way it would on the target's primary one." ;;
    outdated)
      check=NET-SVC-HTTP_OUTDATED_COMPONENT-01; base=${_BANNER_SEVERITY:-high}; conf=medium
      cwe=CWE-1104; owasp=A06:2021
      title='Component version on a non-standard HTTP listener named in the vendored known-vulnerable list'
      remed='Upgrade the component on this listener to a release that is not named in the advisory, or apply the vendor backport for it. Where an upgrade is not immediately possible, put a compensating control in front of the specific weakness the advisory describes and track the upgrade as remediation rather than treating the control as one. Verify the running version afterwards from the same listener. The version came from a banner; a backported fix under an unchanged upstream version string would not be visible here.'
      evi="$where from $host:$port identifies: $names, at least one of which the vendored list at data/versions.db names as affected (when more than one is named, the advisory details below are for the last one matched - consult data/versions.db directly for the others).${_BANNER_ADVISORIES:+ Advisory id(s): ${_BANNER_ADVISORIES}.}${_BANNER_SUMMARY:+ Summary: ${_BANNER_SUMMARY}.}${_BANNER_FIXED:+ Fixed in: ${_BANNER_FIXED}.} That list is an offline snapshot${_BANNER_DB_GENERATED:+ generated ${_BANNER_DB_GENERATED}} and is only as current as its last refresh (docs/VERSIONS-DB.md)." ;;
    *)
      die "$SCOURSH_EXIT_INCOMPLETE" "internal: modules/network/httpport.sh emitted an unknown finding kind '$kind'" ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module net
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set remediation "$remed"
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$transport"
  finding_set url "$scheme://$host:$port/"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

# `_httpport_probe_listener SCHEME HOST PORT TARGET` - the one GET, then the
# three banner_engine.sh channels over that one response, accumulated and
# emitted at most once per check id for THIS listener.  Returns 0 whether or
# not the transport succeeded; the caller counts the difference.
_httpport_probe_listener() {
  local scheme=$1 host=$2 port=$3 target=$4
  local url="$scheme://$host:$port/"
  local bodyf=$SCOURSH_SCRATCH/net-httpport.body.$$
  local hdrf=$SCOURSH_SCRATCH/net-httpport.hdr.$$

  http_request_reset
  http_request_capture "$bodyf" "$hdrf"
  : >"$hdrf"
  if ! http_request GET "$url" 3 "$target"; then
    rm -f -- "$bodyf" "$hdrf"
    return 1
  fi

  # `db_outdated_ok` is `_net_httpport_phase`'s own local (this function is
  # its direct callee, so dynamic scoping resolves it there); folded in here
  # alongside tension-15 selection so `_httpport_consider` reads ONE combined
  # `do_outdated` rather than two signals it would have to remember to AND
  # together itself.
  local do_disclosure=1 do_outdated=${db_outdated_ok:-1}
  if declare -F net_check_selected >/dev/null; then
    net_check_selected NET-SVC-HTTP_SERVER_DISCLOSURE-01 || do_disclosure=0
    net_check_selected NET-SVC-HTTP_OUTDATED_COMPONENT-01 || do_outdated=0
  fi

  local -A seen_disc=() seen_out=()
  local -a server_names=() version_names=() outdated_names=()
  local hname hvalue prod ver

  # Channel 1: the allow-listed response headers - byte-identical set and
  # reader to modules/dast/passive/banner.sh's own.
  for hname in "${_BANNER_HEADERS[@]+"${_BANNER_HEADERS[@]}"}"; do
    hvalue=$(banner_header_value "$hdrf" "$hname")
    [[ -n $hvalue ]] || continue
    while IFS=$'\t' read -r prod ver; do
      [[ -n $prod ]] || continue
      _httpport_consider "$prod" "$ver"
    done < <(banner_products_from_header "$hname" "$hvalue")
  done

  # Channels 2 and 3 need the body, and only when it looks like markup - a
  # JSON API answer or an image carries no generator tag and no bundle
  # reference, the identical guard modules/dast/passive/banner.sh applies.
  case ${_HTTP_LAST_CONTENT_TYPE:-} in
    *html* | '' )
      if [[ -s $bodyf ]]; then
        local trimmed=$SCOURSH_SCRATCH/net-httpport.trim.$$
        head -c "${_BANNER_MAX_BODY_BYTES:-262144}" -- "$bodyf" >"$trimmed" 2>/dev/null || true
        while IFS=$'\t' read -r prod ver; do
          [[ -n $prod && -n $ver ]] || continue
          _httpport_consider "$prod" "$ver"
        done < <(banner_products_from_meta "$trimmed")
        while IFS=$'\t' read -r prod ver; do
          [[ -n $prod && -n $ver ]] || continue
          _httpport_consider "$prod" "$ver"
        done < <(banner_products_from_bundles "$trimmed")
        rm -f -- "$trimmed"
      fi
      ;;
  esac
  rm -f -- "$bodyf" "$hdrf"

  (( ${#server_names[@]} > 0 )) \
    && _httpport_emit server "$scheme" "$host" "$port" "$(IFS=', '; printf '%s' "${server_names[*]}")"
  (( ${#version_names[@]} > 0 )) \
    && _httpport_emit version "$scheme" "$host" "$port" "$(IFS=', '; printf '%s' "${version_names[*]}")"
  (( ${#outdated_names[@]} > 0 )) \
    && _httpport_emit outdated "$scheme" "$host" "$port" "$(IFS=', '; printf '%s' "${outdated_names[*]}")"

  return 0
}

# `_httpport_consider PRODUCT VERSION` - the one place a discovered component
# becomes a candidate for this listener's (at most) three findings, so the
# dedup, the selection gate and the vendored-list lookup cannot be applied in
# one channel and forgotten in another.
#
# Written as a function that reads its CALLER's locals by name
# (`do_disclosure`/`do_outdated`/`seen_disc`/`seen_out`/`server_names`/
# `version_names`/`outdated_names`, all declared in `_httpport_probe_listener`
# just above) rather than a by-name/nameref parameter list: bash resolves an
# unshadowed variable through the call stack (dynamic scoping), which is
# exactly the mechanism modules/dast/passive/banner.sh's own `_banner_consider`
# relies on for its own caller's locals - and bash 4.2 (tension 24's frozen
# minimum) has no `local -n` nameref to pass an array by name across a
# function boundary instead.
_httpport_consider() {
  local prod=$1 ver=$2 key

  key="$prod"
  if (( do_disclosure )) && [[ -z ${seen_disc[$key]:-} ]]; then
    seen_disc[$key]=1
    if [[ -n $ver ]]; then
      version_names+=("$prod $ver")
    else
      server_names+=("$prod")
    fi
  fi

  [[ -n $ver ]] || return 0
  (( do_outdated )) || return 0
  key="$prod@$ver"
  [[ -z ${seen_out[$key]:-} ]] || return 0
  seen_out[$key]=1
  if banner_db_match "$prod" "$ver"; then
    outdated_names+=("$prod@$ver")
  fi
  return 0
}

_net_httpport_phase() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/httpport.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  net_inventory_read "$SCOURSH_RUN_DIR"
  case $_NET_LISTENERS_STATE in
    absent)
      run_record coverage_reduction "module=network reason=no_http_listener target=$target - no declared listener beyond the target's own base-url exists for this target (modules/network/inventory.sh, NET-05), so there is no non-standard HTTP port to probe. 'This host has one listener' and 'scoursh did not look' are different facts - this phase records the same fact for its own honesty."
      run_record coverage_gap "network httpport: target '$target' declares no listener beyond its base-url, so no non-standard-port HTTP response was examined for a service disclosure."
      return 0
      ;;
    empty)
      run_record coverage_reduction "module=network reason=no_http_listener target=$target - reports/<run>/inventory/listeners.json exists but is empty for this target, so there is no declared non-standard-port listener to probe."
      run_record coverage_gap "network httpport: target '$target' has an empty declared-listener artifact, so no non-standard-port HTTP response was examined for a service disclosure."
      return 0
      ;;
  esac

  httpport_listeners_load "$_NET_LISTENERS_FILE" "$target"
  if (( _HTTPPORT_L_N == 0 )); then
    run_record coverage_reduction "module=network reason=no_http_listener target=$target - reports/<run>/inventory/listeners.json exists but names no extra-host listener with an http/https scheme this phase can probe, so there is no non-standard HTTP port to identify."
    run_record coverage_gap "network httpport: target '$target' declares listeners, but none is a non-standard HTTP(S) port this phase can probe."
    return 0
  fi

  local n=$_HTTPPORT_L_N truncated=0
  if (( n > _HTTPPORT_MAX_LISTENERS )); then
    truncated=$(( n - _HTTPPORT_MAX_LISTENERS ))
    n=$_HTTPPORT_MAX_LISTENERS
  fi

  # The vendored list, read once per run.  Its state decides only whether the
  # outdated-component check can run; the two disclosure checks need no data
  # at all, so a fresh clone still gets them - the identical split
  # modules/dast/passive/banner.sh applies.  Named distinctly from
  # `_httpport_probe_listener`'s own per-listener `do_outdated` below (which
  # ALSO folds in tension-15 selection): both are read together there, and a
  # single shared name at two different call-stack depths would let the
  # inner one silently shadow this one instead of combining with it.
  local db_outdated_ok=1
  banner_db_state
  case $_BANNER_DB_STATE in
    absent)
      db_outdated_ok=0
      local _nc='NET-SVC-HTTP_OUTDATED_COMPONENT-01'
      run_record coverage_reduction "module=network reason=versions_db_absent target=$target checks=[$_nc] - the vendored known-vulnerable version list at data/versions.db is missing or unreadable, so discovered component versions on non-standard HTTP listeners were not checked against it. Version DISCLOSURE was still checked. Populate the list on a networked box (docs/VERSIONS-DB.md); nothing in a scan ever fetches it."
      ;;
    no_banner_rows)
      db_outdated_ok=0
      local _nc2='NET-SVC-HTTP_OUTDATED_COMPONENT-01'
      run_record coverage_reduction "module=network reason=versions_db_no_banner_rows target=$target checks=[$_nc2] - data/versions.db exists but carries no \`banner\` rows, so no discovered component version could be matched against a known-vulnerable one. This is the state of a fresh clone: the list is vendored by an operator action, never by a scan (docs/VERSIONS-DB.md). Version DISCLOSURE was still checked."
      ;;
    present)
      run_record notes "module=network phase=httpport target=$target versions_db=present${_BANNER_DB_GENERATED:+ generated=$_BANNER_DB_GENERATED}"
      ;;
  esac

  if declare -F net_scope_skips_reset >/dev/null; then
    net_scope_skips_reset
  fi

  local i scheme host port url requested=0 probed_ok=0 transport_failed=0
  for (( i = 0; i < n; i++ )); do
    scheme=${_HTTPPORT_L_SCHEME[$i]}
    host=${_HTTPPORT_L_HOST[$i]}
    port=${_HTTPPORT_L_PORT[$i]}
    url="$scheme://$host:$port/"
    if declare -F net_endpoint_keep >/dev/null; then
      net_endpoint_keep "$url" "$target" || continue
    fi
    requested=$(( requested + 1 ))
    if _httpport_probe_listener "$scheme" "$host" "$port" "$target"; then
      probed_ok=$(( probed_ok + 1 ))
    else
      transport_failed=$(( transport_failed + 1 ))
    fi
  done

  # Recorded BEFORE the `requested == 0` / `probed_ok == 0` returns below, not
  # after - the identical ordering modules/dast/passive/banner.sh's own
  # comment gives, so a run whose every declared listener was out of scope
  # still explains why rather than reaching a branch that never prints it.
  if declare -F net_scope_record_skips >/dev/null; then
    net_scope_record_skips httpport "$target"
  fi

  if (( requested == 0 )); then
    run_record coverage_gap "network httpport: every declared non-standard HTTP listener for target '$target' was out of scope for this run (see the artifact_tuple_out_of_scope reduction above), so no request was sent."
    return 0
  fi

  if (( probed_ok > 0 )); then
    run_record checks_run NET-SVC-HTTP_SERVER_DISCLOSURE-01
    run_record checks_run NET-SVC-HTTP_VERSION_DISCLOSURE-01
    (( db_outdated_ok )) && run_record checks_run NET-SVC-HTTP_OUTDATED_COMPONENT-01
  fi

  if (( transport_failed > 0 )); then
    run_record coverage_reduction "module=network reason=net_http_unavailable target=$target count=$transport_failed - that many declared non-standard HTTP listener(s) for this target did not answer at the transport (connection refused, timed out, or an unhandled protocol), so no response was examined for them. 'Filtered'/connection-refused and 'answered cleanly' are different facts - this is not evidence the listener speaks HTTP cleanly."
  fi

  if (( probed_ok == 0 )); then
    run_record coverage_gap "network httpport: every one of the $requested declared non-standard HTTP listener(s) probed for target '$target' failed at the transport, so no response was examined for a service disclosure."
    return 0
  fi

  if (( truncated > 0 )); then
    run_record coverage_gap "network httpport: target '$target' declares $_HTTPPORT_L_N non-standard HTTP(S) listener(s) and this check probed the first $_HTTPPORT_MAX_LISTENERS of them, so $truncated were not examined. That is a coverage bound, not a clean result."
  fi

  log_info "network httpport: target '$target' - probed $probed_ok of $requested declared listener(s) (versions_db=$_BANNER_DB_STATE)"
  return 0
}

_net_httpport_phase
