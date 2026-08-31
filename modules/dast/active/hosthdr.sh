#!/usr/bin/env bash
# modules/dast/active/hosthdr.sh - the §7.3 HOST-HEADER-INJECTION phase
# (docs/DESIGN.md §7.3 "Host-header injection (`hosthdr.sh`) - send a spoofed
# `Host`/`X-Forwarded-Host`; flag if it's reflected into links, redirects, or
# password-reset URLs (cache-poisoning / reset-poisoning risk)."; tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it
# carries NO sourced-once guard - one run can legitimately reach the same
# phase twice. The pure half - the sentinel, the two sinks, the emission - is
# modules/dast/active/hosthdr_engine.sh; this file resolves the ONE live
# input the check needs (the endpoint list) and drives it, the same split
# cors.sh/cors_engine.sh already establish for a sibling
# request-a-header-and-classify-the-response check.
#
# WHY THIS IS `active` AND NOT `passive`, EVEN THOUGH IT LOOKS LIKE cors.sh.
# §7.3 is docs/DESIGN.md's own injection-family section (and
# modules/dast/engine.sh's phase table has always listed this row at
# `active`), so it only runs at `--intensity active` or above, unlike
# cors.sh's §7.1 placement. The traffic pattern is otherwise identical to
# cors.sh's: one extra request header on an endpoint the crawler already
# inventoried, no body sent, no state mutated. Nothing about the request
# itself would need the higher tier; the tier reflects where §7.3 already
# filed the ticket, and this file does not relitigate it.
#
# ONLY IDEMPOTENT (GET/HEAD) ENDPOINTS ARE PROBED, exactly as cors.sh
# restricts itself, and for the identical reason: a POST/PUT/PATCH/DELETE
# endpoint the crawler found is never requested at all here, not under its
# own method and not under a substituted one. That is what keeps a
# detection-oriented, non-destructive probe (§7.3's own DAST-36 amendment)
# honest about never submitting a form or resending a discovered mutation.
#
# WHAT THIS TICKET DELIBERATELY DID NOT BUILD, so the boundary is not
# rediscovered:
#   * Live confirmation of password-reset-link poisoning. §7.3's bullet names
#     it as one of three sinks, but confirming it needs a POST to a reset
#     endpoint and, against a real target, sends a real outbound email - a
#     stateful, external side effect out of scope for a detection-only probe
#     (the same boundary DAST-03's own auth.sh draws around a "live"
#     enumeration probe). hosthdr_engine.sh's own header explains why the
#     BODY-reflection check is the right-sized substitute: it proves the same
#     root cause (the server trusts a client Host value when building an
#     absolute URL) that a poisoned reset link would also depend on.
#   * An authenticated probe pass. As with cors.sh, this is a stated,
#     recorded bound (`_hh_record_unauthenticated_bound` below) rather than a
#     silent gap: a Host-header trust bug on an authenticated route (a
#     password-change confirmation page, say) can be invisible to an
#     unauthenticated crawl.
#   * A CACHE-POISONING PROOF. §7.3's own posture (docs/DESIGN.md's injection
#     principle, restated at the top of this ticket) is "report the
#     reflection; do not attempt cache poisoning" - this file sends exactly
#     one request per candidate per technique and never issues a second
#     request to observe whether a cache actually served the poisoned
#     response back.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/active/hosthdr_engine.sh
source "${BASH_SOURCE[0]%/*}/hosthdr_engine.sh"
# crawl_engine.sh for the frozen endpoints.json reader (crawl_json_flatten,
# docs/INVENTORY-FORMAT.md). Carries a sourced-once guard and has no
# source-time side effect, so on a real run (crawl.sh has already run and
# sourced it) this is a no-op; standalone it is what lets
# tests/suites/dast-hosthdr.sh drive this phase without scan.sh.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"
# For an authenticated-bound record only (see `_hh_record_unauthenticated_bound`
# below); consulted only under --authed.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# The path component of a URL, query and fragment removed, for the finding's
# location (path_template_of templates it). A URL with no path is `/`. Same
# helper, same contract, as cors.sh's own `_cors_path_of`.
_hh_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_hh_candidates TARGET FILE` - print `METHOD<TAB>URL` for every endpoint in
# the inventory FILE that belongs to TARGET and uses an idempotent method.
# Same shape, same reason, as cors.sh's own `_cors_candidates`: it reads
# through crawl_engine.sh's `crawl_json_flatten`, the one frozen JSON reader
# every inventory producer/consumer shares.
_hh_candidates() {
  local target=$1 file=$2
  [[ -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p type v rest idx key last_idx='' m='' u='' t=''
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _hh_candidate_emit "$target" "$m" "$u" "$t"
      m='' u='' t=''
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    case $key in
      method) m=$v ;;
      url) u=$v ;;
      target) t=$v ;;
    esac
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _hh_candidate_emit "$target" "$m" "$u" "$t"
  return 0
}

# Emit one `METHOD<TAB>URL` line if the endpoint is for TARGET and idempotent.
_hh_candidate_emit() {
  local target=$1 m=${2:-GET} u=$3 t=$4
  [[ -n $u ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  case ${m^^} in
    GET | HEAD) ;;
    *) return 0 ;;
  esac
  printf '%s\t%s\n' "${m^^}" "$u"
  return 0
}

# `_hh_record_unauthenticated_bound TARGET` - the stated bound for a run that
# holds a session but sent no probe with it. Same helper, same reasoning, as
# cors.sh's own `_cors_record_unauthenticated_bound`.
_hh_record_unauthenticated_bound() {
  local target=$1
  [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] || return 0
  declare -F dast_auth_authenticated_labels_set >/dev/null || return 0
  dast_auth_authenticated_labels_set "$target"
  (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )) || return 0
  run_record coverage_reduction "module=dast reason=hosthdr_probe_is_unauthenticated check=hosthdr target=$target - this run holds an authenticated session, but the Host-header probe was sent WITHOUT it. A Host-header trust defect reachable only from an authenticated route (a password-change confirmation page, for example) would answer this probe with nothing to reflect, so a clean result for such a target is not evidence its authenticated responses are safe."
  return 0
}

_dast_hosthdr_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local endpoints_file=${SCOURSH_DAST_ENDPOINTS:-}
  local line method url path key

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/hosthdr.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; `dast_check_selected` is the DAST-side reader of
  # it. Consulted only if that function exists, exactly as cors.sh, sqli.sh
  # and openredirect.sh already guard it - absent, everything the tier
  # already permitted runs, which is the "empty means all selected" fallback
  # a direct-engine test relies on.
  local do_body=1 do_location=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-HOSTHDR-REFLECTED_BODY-01 || do_body=0
    dast_check_selected DAST-HOSTHDR-REFLECTED_LOCATION-01 || do_location=0
  fi
  if (( do_body == 0 && do_location == 0 )); then
    run_record coverage_reduction "module=dast reason=all_hosthdr_checks_deselected check=hosthdr target=$target - every Host-header check id was removed by the check-selection filters, so no spoofed-Host probe was sent."
    return 0
  fi

  # THE ONE LIVE INPUT. `modules/dast/run.sh` resolves SCOURSH_DAST_ENDPOINTS
  # before the phase loop starts while crawl.sh writes it several phases
  # LATER in that same loop, so the export is empty on exactly the run that
  # has just discovered a surface; the run-directory artifact is read as a
  # fallback, the same fix (and the same paths) cors.sh and openredirect.sh
  # already apply for themselves.
  if [[ -z $endpoints_file && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    endpoints_file=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi

  local -a candidates=()
  while IFS= read -r line; do
    [[ -n $line ]] && candidates+=("$line")
  done < <(_hh_candidates "$target" "$endpoints_file")

  if (( ${#candidates[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory check=hosthdr target=$target - the endpoint inventory (${endpoints_file:-none}, docs/INVENTORY-FORMAT.md) named no idempotent (GET/HEAD) endpoint for this target, so the Host-header probe had nowhere to send a request."
    run_record coverage_gap "dast hosthdr: target '$target' has no known idempotent endpoint (docs/INVENTORY-FORMAT.md endpoints.json was ${endpoints_file:-absent}), so no spoofed 'Host'/'X-Forwarded-Host' probe was sent. A clean result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  # DEDUPE BY (METHOD, PATH TEMPLATE), NOT BY URL, for the identical reason
  # cors.sh dedupes its own candidate list: a Host-header trust decision is a
  # property of the ROUTE the application code implements, not of any one
  # instance URL, so `/orders/1` and `/orders/2` are one thing to test.
  local max=${SCOURSH_DAST_HOSTHDR_MAX_ENDPOINTS:-$_HH_MAX_ENDPOINTS}
  [[ $max =~ ^[0-9]+$ ]] || max=$_HH_MAX_ENDPOINTS
  (( max < 1 )) && max=1
  local -a probe=()
  local -A seen=()
  local truncated=0
  # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - modules/dast/
  # engine.sh section 3b carries the long form, and passive/cors.sh (whose
  # candidate shape this file already reuses) applies it in the same place.
  # `http_request` gates FATALLY, which is right for an operator-configured URL
  # and exactly wrong for one lifted out of an inventory another module wrote,
  # where one bad row aborts the whole run at exit 3. Applied before the dedupe
  # and the cap, so an out-of-scope row cannot spend a bounded route slot.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi
  for line in "${candidates[@]+"${candidates[@]}"}"; do
    method=${line%%$'\t'*}
    url=${line#*$'\t'}
    if declare -F dast_endpoint_keep >/dev/null; then
      dast_endpoint_keep "$url" "$target" || continue
    fi
    path=$(_hh_path_of "$url")
    key="$method $(path_template_of "$path")"
    [[ -n ${seen[$key]+set} ]] && continue
    seen[$key]=1
    if (( ${#probe[@]} >= max )); then
      truncated=$(( truncated + 1 ))
      continue
    fi
    probe+=("$line")
  done

  if declare -F dast_scope_record_skips >/dev/null; then
    dast_scope_record_skips hosthdr "$target"
  fi

  _hh_record_unauthenticated_bound "$target"

  local header tested=0 failed=0 body_hits=0 loc_hits=0 body_truncated_ct=0
  for line in "${probe[@]+"${probe[@]}"}"; do
    method=${line%%$'\t'*}
    url=${line#*$'\t'}
    path=$(_hh_path_of "$url")
    for header in "${HOSTHDR_TECHNIQUES[@]+"${HOSTHDR_TECHNIQUES[@]}"}"; do
      if ! hh_probe "$target" "$method" "$url" "$header"; then
        # A TRANSPORT FAILURE IS NOT "NO REFLECTION". Counting it as tested
        # would let a breaker-opened run report a route clean it never
        # reached, the exact overstated coverage docs/DESIGN.md §15 forbids.
        failed=$(( failed + 1 ))
        continue
      fi
      tested=$(( tested + 1 ))
      (( _HH_BODY_TRUNCATED )) && body_truncated_ct=$(( body_truncated_ct + 1 ))

      if (( do_location )) && (( _HH_LOCATION_REFLECTED )); then
        loc_hits=$(( loc_hits + 1 ))
        _hh_emit_location "$target" "$method" "$url" "$path" "$header"
      fi
      if (( do_body )) && (( _HH_BODY_REFLECTED )); then
        body_hits=$(( body_hits + 1 ))
        _hh_emit_body "$target" "$method" "$url" "$path" "$header"
      fi
    done
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition). Recorded only when at least one probe got a real response -
  # both ids together, because one response answers both verdicts, exactly as
  # cors.sh records all three of its own ids off one response.
  if (( tested > 0 )); then
    (( do_body )) && run_record checks_run DAST-HOSTHDR-REFLECTED_BODY-01
    (( do_location )) && run_record checks_run DAST-HOSTHDR-REFLECTED_LOCATION-01
  fi

  if (( truncated > 0 )); then
    run_record coverage_gap "dast hosthdr: the idempotent endpoint surface on target '$target' exceeded this check's per-run cap of $max distinct routes, so $truncated route(s) were not probed for Host-header reflection. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( failed > 0 )); then
    run_record coverage_reduction "module=dast reason=hosthdr_probe_transport_failed check=hosthdr target=$target count=$failed - $failed Host-header probe(s) never received a response (the circuit breaker, the per-run request budget or name resolution stopped them), so those route/technique pairs were not tested either way."
  fi
  if (( body_truncated_ct > 0 )); then
    run_record coverage_reduction "module=dast reason=hosthdr_body_scan_truncated check=hosthdr target=$target count=$body_truncated_ct - $body_truncated_ct response body/bodies exceeded this check's ${_HH_MAX_BODY_BYTES}-byte scan cap, so only the first ${_HH_MAX_BODY_BYTES} bytes were searched for a reflected Host value; a reflection appearing later in the body would be missed."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast hosthdr: none of the ${#probe[@]} candidate route(s) on target '$target' returned a response, so no Host-header reflection was observed either way. Nothing was tested; this is not a finding of safety."
  fi

  log_info "dast hosthdr: target '$target' - probed $tested of $(( ${#probe[@]} * ${#HOSTHDR_TECHNIQUES[@]} )) route/technique pair(s) (body=$body_hits location=$loc_hits, ${failed} unreachable)"
  return 0
}

# `_hh_emit_body`/`_hh_emit_location` - one wrapper per sink, each building its
# own title/evidence and calling the shared `hh_emit_finding`.
_hh_emit_body() {
  local target=$1 method=$2 url=$3 path=$4 header=$5
  local evi="$method $path was requested with '$header: $HOSTHDR_SENTINEL' (HTTP $_HH_STATUS), and the response body contains that sentinel host. Nothing else in this request carried that value, so the server read it from the '$header' header and echoed it into the response - the same trust an attacker-controlled absolute URL (a link, a cache-busted asset reference, a canonical tag, or a password-reset link built the same way) would inherit."
  (( _HH_BODY_TRUNCATED )) && evi+=" (the body exceeded this check's scan cap; only the first ${_HH_MAX_BODY_BYTES} bytes were searched.)"
  hh_emit_finding \
    DAST-HOSTHDR-REFLECTED_BODY-01 \
    'Host header value reflected into the response body' \
    medium high \
    "$target" "$method" "$url" "$path" "$header" \
    "$evi" \
    "$(hh_remediation_body)"
  return 0
}

_hh_emit_location() {
  local target=$1 method=$2 url=$3 path=$4 header=$5
  local loc_text evi
  loc_text=$(_hh_safe_text "$_HH_LOCATION")
  evi="$method $path was requested with '$header: $HOSTHDR_SENTINEL' (HTTP $_HH_STATUS), and the endpoint answered with 'Location: $loc_text', whose authority is that same sentinel host. Only this request's own spoofed '$header' header could have supplied that value, so the redirect destination is built from a client-controlled transport header without validation."
  hh_emit_finding \
    DAST-HOSTHDR-REFLECTED_LOCATION-01 \
    "Host header value reflected into a redirect Location's authority" \
    medium high \
    "$target" "$method" "$url" "$path" "$header" \
    "$evi" \
    "$(hh_remediation_location)"
  return 0
}

_dast_hosthdr_phase
