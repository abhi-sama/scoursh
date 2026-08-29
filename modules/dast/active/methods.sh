#!/usr/bin/env bash
# modules/dast/active/methods.sh - the §7.2 HTTP method-enumeration PHASE
# (docs/DESIGN.md §7.2 "safe active"; docs/STEP5-DAST-PLAN.md DAST-13, tier 3).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` at tier `safe`, so it inherits the whole run context and
# anything it emits lands in this process's shard. Per that function's contract
# it carries NO sourced-once guard - one run can legitimately reach the same
# phase twice. The parsing half lives in
# modules/dast/active/method_engine.sh; this file is the orchestration: which
# endpoints to ask, what to ask them, and what to say about the answer.
#
# THE ONE RULE THIS CHECK IS BUILT AROUND: ESTABLISH ACCEPTANCE, NEVER EXERCISE
# IT. `PUT`, `DELETE`, `PATCH` and `CONNECT` are NEVER SENT, on any endpoint,
# under any flag this phase reads. The only two methods that leave this file are
# `OPTIONS` - defined as having no effect on the resource (RFC 7231 §4.3.7) -
# and `TRACE`, defined as an echo of the request with no effect on the resource
# (RFC 7231 §4.3.8). Everything else is read out of what the server itself says,
# in the `Allow` header of either response, which a `405` is REQUIRED to carry
# (RFC 7231 §6.5.5). That is why a write-method finding here is `confidence:
# medium` and says so in its evidence: the run holds the server's claim and
# deliberately did not spend a state change to upgrade it to a demonstration.
# Anything that "confirms" a `PUT` by sending one is a different tool.
#
# READ THE ENDPOINT LIST; DO NOT CRAWL. This phase discovers nothing. It reads
# reports/<run>/inventory/endpoints.json (docs/INVENTORY-FORMAT.md, tension 21),
# which modules/dast/crawl.sh (DAST-04) writes earlier in this same run, and
# follows no link out of any response. The reader is `inject_inventory_load`
# from modules/dast/active/inject_engine.sh rather than a new one written here,
# for that file's own stated reason: a second, subtly different reader for one
# frozen artifact is the failure mode it exists to prevent.
#
# UNLIKE THE PASSIVE COOKIE PHASE, THIS ONE DOES NOT FILTER THE INVENTORY DOWN
# TO ITS `GET` ROWS, and the difference is not an inconsistency. That phase had
# to, because it dials each endpoint WITH THE METHOD THE CRAWLER RECORDED, and
# dialling a recorded `POST /login` is a state change. This phase never uses the
# recorded method as the method to send - it sends `OPTIONS` and `TRACE` and
# nothing else - so a `POST` row is a perfectly safe thing to ask `OPTIONS`
# about, and skipping it would drop exactly the endpoints (the write-shaped
# ones) whose method surface is most worth knowing.
#
# EVERY REQUEST GOES THROUGH `http_request` (docs/FOUNDATION.md tension 19's "No
# bypass"), which is where the scope gate, DAST-01's rate limiter, the per-run
# request budget, the circuit breaker and DAST-32's ceilings all sit. The
# endpoint URLs are UNTRUSTED target output (tension 10,
# docs/INVENTORY-FORMAT.md §6) - a crawled URL is attacker-influenced text - so
# each one is re-gated by `http_request` on the way out.
#
# HONESTY. A clean result here must never read as "no dangerous method is
# enabled" when it is "the server told us nothing": no endpoint inventory, a
# server that answered every `OPTIONS` with no `Allow` header at all, a cap that
# truncated the list, and the standing fact that no write method was exercised
# are each recorded so the report says which one happened (docs/DESIGN.md §15).
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes header and method syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/method_engine.sh
source "${BASH_SOURCE[0]%/*}/method_engine.sh"
# The frozen-artifact reader, and (through it) lib/http.sh - the chokepoint a
# dast run does not otherwise load. Both carry their own sourced-once guards, so
# this is a no-op on a run where another probe already sourced them.
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated pass, when the run asked for one and auth.sh obtained a
# session: an application routinely exposes a write method only behind a login,
# so an unauthenticated-only enumeration has a real hole, stated below when the
# run did not close it.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh). A method finding maps onto its
# first three and leaves the last two EMPTY, which is the honest shape: the
# subject of the finding is a method on a path, and no request parameter is
# involved at all. `loc_method` is the method being REPORTED (`PUT`), not the
# method that was SENT (`OPTIONS`) - that is what makes two dangerous methods on
# one path two findings rather than one, which they are: `PUT` and `DELETE` on
# the same resource have different consequences and different fixes. How the
# fact was established is not left to be inferred from the location; it is
# stated in the evidence of every finding, per this ticket's own criterion.
#
# EVIDENCE IS HARD-CAPPED AT `SCOURSH_EVIDENCE_MAX_BYTES` (512 by default,
# lib/findings.sh), SO IT LEADS WITH THE MECHANISM AND SAYS NOTHING TWICE. That
# is not a style note: a first draft of this function wrote a paragraph per
# finding and `_evidence_truncate` silently cut the tail off every one, which is
# where "how acceptance was determined" and "this was not exercised" happened to
# sit - so the two sentences this ticket exists to put in front of a reader were
# the exact two the emitter dropped. Measured by the assertions in
# tests/suites/dast-methods.sh, which failed on it. Background prose belongs in
# `remediation`, which carries no cap; evidence states what was observed.
_methods_emit() {
  local kind=$1 method=$2 raw=$3 url=$4 how=$5 detail=$6
  local target=${SCOURSH_DAST_TARGET:-}
  local path check title base conf cwe owasp evi remed authv=none
  path=$(method_path_of "$url")
  [[ -n ${_METHODS_AUTH_LABEL:-} ]] && authv=user

  local spelling=''
  [[ $raw != "$method" ]] \
    && spelling=" The server spelled it \`$raw\`, not \`$method\`."

  case $kind in
    trace)
      check=DAST-METHOD-TRACE_ENABLED-01; base=medium; conf=high
      cwe=CWE-693; owasp=A05:2021
      title='HTTP TRACE is enabled (Cross-Site Tracing)'
      evi="MEASURED, not read from an \`Allow\` header: \`TRACE $path\` $how and returned a real echo of the request rather than an application page. Sending \`TRACE\` changes no resource (RFC 7231 §4.3.8), which is why this one method could be confirmed. The echo reflects headers page script cannot otherwise read - \`Cookie\`, \`Authorization\` - so a cross-site-scripting flaw can read an \`HttpOnly\` session cookie (Cross-Site Tracing).$detail"
      remed='Disable `TRACE` at the web server and at every proxy in front of it - `TraceEnable off` in Apache httpd, and an explicit rejection of `TRACE` in nginx, which does not implement it but will pass it upstream. Disable `TRACK` in the same change: it is IIS'"'"'s equivalent and is not covered by the `TRACE` setting. Do not rely on `HttpOnly` alone to keep a session cookie away from script while `TRACE` is answered, because the echo returns the cookie the browser attached. Verify at the edge as well as at the origin: a CDN or load balancer that answers `TRACE` itself reintroduces the issue after the origin is fixed.' ;;
    write)
      check=DAST-METHOD-WRITE_ADVERTISED-01; base=high; conf=medium
      cwe=CWE-749; owasp=A05:2021
      title="HTTP $method is advertised as allowed on this endpoint"
      evi="acceptance of \`$method\` on $path was $how.$spelling NOT EXERCISED: no \`$method\` was sent, because completing one would create, overwrite or delete a resource on a target under audit - so this is the server's own claim, hence \`confidence: medium\`. \`$method\` changes or removes the resource it names, so a route accepting it without an authorisation check lets anyone who can reach it alter content.$detail"
      remed='Confirm the method is intended on this route. If it is not, refuse it at the application router and at the web server or proxy in front of it, rather than relying on the framework'"'"'s default - `PUT`, `DELETE` and `PATCH` are commonly left enabled by a permissive `WebDAV`, upload or REST module nobody chose. If the method IS intended, check that it enforces authentication AND per-object authorisation on every path that reaches it (an `Allow` header is a routing fact and says nothing about who may act), that it validates the target path against traversal, and that a written file can never be served back as executable content. Add the route to whatever test suite proves the authorisation, since this is exactly the check a refactor silently drops.' ;;
    connect)
      check=DAST-METHOD-CONNECT_ADVERTISED-01; base=high; conf=medium
      cwe=CWE-441; owasp=A05:2021
      title='HTTP CONNECT is advertised as allowed on this endpoint'
      evi="acceptance of \`CONNECT\` on $path was $how.$spelling NOT EXERCISED: no tunnel was opened, because doing so would send this scanner's traffic to a third party, which its egress model forbids outright - so this is the server's own claim. \`CONNECT\` asks the server to tunnel to a host the CLIENT names (RFC 7231 §4.3.6), so honouring it from an untrusted client makes this host an open proxy into its own network.$detail"
      remed='Unless this host is deliberately a forward proxy, refuse `CONNECT` outright at the web server and at every proxy in front of it. If it IS a forward proxy, it must never be reachable from an untrusted network: bind it to the interface its clients are on, require authentication, and restrict the destination host and port set to an explicit allow list (an unrestricted `CONNECT` to port 25 is how a host ends up relaying mail). Confirm from off-network that the port is not reachable, since a proxy intended for internal use that is exposed by a cloud security-group default is the ordinary way this happens.' ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation "$remed"
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location ''
  finding_set loc_param_name ''
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

_dast_methods_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/methods.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # tension-15 per-check selection, guarded exactly as active/sqli.sh and
  # passive/cookies.sh guard it: `dast_check_selected` does not exist on every
  # path this file is reachable from, and absent it everything the tier already
  # permitted runs.
  local do_trace=1 do_write=1 do_connect=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-METHOD-TRACE_ENABLED-01 || do_trace=0
    dast_check_selected DAST-METHOD-WRITE_ADVERTISED-01 || do_write=0
    dast_check_selected DAST-METHOD-CONNECT_ADVERTISED-01 || do_connect=0
  fi
  if (( do_trace == 0 && do_write == 0 && do_connect == 0 )); then
    run_record coverage_reduction "module=dast reason=methods_no_check_selected target=$target - every DAST-METHOD-* check was filtered out by --profile-scan/--intensity, so no endpoint's method surface was enumerated."
    return 0
  fi

  # THE ENDPOINT FILE IS RE-RESOLVED HERE RATHER THAN TAKEN FROM
  # SCOURSH_DAST_ENDPOINTS ALONE, AND THAT IS NOT BELT-AND-BRACES.
  # modules/dast/run.sh calls `dast_inventory_read` ONCE, before the phase loop,
  # and exports SCOURSH_DAST_ENDPOINTS from what it found THEN - which on a fresh
  # run is nothing, because crawl.sh is a phase and has not run yet. It writes
  # reports/<run>/inventory/endpoints.json a few phases later in the same loop
  # and nothing re-reads it, so a consumer that trusts the exported variable
  # alone sees an empty surface on precisely the ordinary run (active/sqli.sh
  # does exactly that today). This file therefore prefers the exported path when
  # it is usable and falls back to the run directory's own artifact - the file
  # docs/INVENTORY-FORMAT.md names, the same artifact by the same path, just read
  # after the producer wrote it. SCOURSH_DAST_METHOD_ENDPOINTS overrides both, so
  # the reader is testable against a fixture without a crawl (the swappable-seam
  # idiom lib/http.sh's own transport/resolver hooks use). The general fix belongs
  # to modules/dast/run.sh and affects every inventory consumer, so it is filed
  # rather than widened into this ticket.
  local epf=${SCOURSH_DAST_METHOD_ENDPOINTS:-}
  if [[ -z $epf ]]; then
    epf=${SCOURSH_DAST_ENDPOINTS:-}
    [[ -n $epf && -r $epf && -s $epf ]] || epf=${SCOURSH_RUN_DIR:-}/inventory/endpoints.json
  fi
  if [[ ! -r $epf || ! -s $epf ]]; then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - no endpoint inventory (docs/INVENTORY-FORMAT.md) was readable, so no endpoint's method surface was enumerated."
    run_record coverage_gap "dast methods: target '$target' has no known endpoint, so no endpoint was asked which HTTP methods it accepts. This is a coverage gap - nothing was tested - not a finding that no dangerous method is enabled."
    return 0
  fi

  inject_inventory_load "$epf" ''

  # THE ENDPOINT ORDER IS SORTED, AND THAT IS NOT COSMETIC. `_INJ_EP_URL` is a
  # bash ASSOCIATIVE array, whose iteration order is its internal hash order and
  # is not the order the crawler wrote. With a cap below, an unsorted walk would
  # make WHICH endpoints get probed depend on hash order - so two runs over the
  # identical surface could enumerate different endpoints and produce different
  # findings, which is the opposite of this repository's byte-reproducible-output
  # property. Sorted under LC_ALL=C, the same surface always yields the same walk.
  local -a urls=()
  local -A seen_url=()
  local url
  while IFS= read -r url; do
    [[ -n $url ]] || continue
    [[ -n ${seen_url[$url]:-} ]] && continue
    seen_url[$url]=1
    urls+=("$url")
  done < <(
    local id
    for id in "${!_INJ_EP_URL[@]}"; do
      printf '%s\n' "${_INJ_EP_URL[$id]}"
    done | LC_ALL=C sort -u
  )

  local max=${SCOURSH_DAST_METHOD_MAX_ENDPOINTS:-25}
  [[ $max =~ ^[0-9]+$ ]] || max=25
  (( max < 1 )) && max=1
  local truncated=0
  if (( ${#urls[@]} > max )); then
    truncated=$(( ${#urls[@]} - max ))
    urls=("${urls[@]:0:max}")
  fi

  if (( ${#urls[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - the endpoint inventory carried no usable endpoint, so no endpoint's method surface was enumerated."
    run_record coverage_gap "dast methods: no endpoint on target '$target' could be asked which HTTP methods it accepts. This is a coverage gap - nothing was tested - not a finding that no dangerous method is enabled."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained a session this run. An application routinely refuses a write method
  # to an anonymous caller and accepts it from a logged-in one, so an
  # unauthenticated-only enumeration under-reports; that is stated below when the
  # run did not close it.
  #
  # THE CREDENTIAL IS ATTACHED BY `dast_auth_apply`, WHICH IS auth_engine.sh's
  # OWN PUBLIC ENTRY POINT, AND NEVER BY READING THE SESSION STORE HERE. It
  # attaches BOTH halves of a session - the bearer/`Authorization` token in the
  # identity's own configured header and scheme, AND the cookie jar - whereas a
  # cookie-only attachment silently sends nothing at all for a token-mode
  # identity, which is the majority shape for an API. It consumes lib/http.sh's
  # per-request context (section 9a), which `http_request` resets at entry, so it
  # is called immediately before EVERY request rather than once per endpoint: a
  # credential attached once would ride only the first `OPTIONS` and the `TRACE`
  # that follows it would go out anonymous, which is the silently-half-
  # authenticated pass that reads as "this endpoint refuses the method".
  _METHODS_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] \
    && declare -F dast_auth_authenticated_labels_set >/dev/null \
    && declare -F dast_auth_apply >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _METHODS_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=methods target=$target identity=$_METHODS_AUTH_LABEL authenticated_pass=1"
    fi
  fi
  if [[ -z $_METHODS_AUTH_LABEL ]]; then
    run_record coverage_reduction "module=dast reason=methods_unauthenticated_only target=$target - the method surface below was enumerated from UNAUTHENTICATED responses only. An application commonly refuses a write method to an anonymous caller and accepts it from a logged-in one, so this run under-reports rather than clears. Run with --authed and a config/auth.conf to cover it."
  fi

  # REDIRECTS ARE NOT FOLLOWED BY DEFAULT, and that is a correctness choice
  # rather than caution. The subject of every finding here is "which methods does
  # THIS path accept"; following a 301 would answer that question about a
  # different path and label the answer with the one that was asked. A 3xx is
  # counted below as an endpoint that could not be enumerated.
  local maxred=${SCOURSH_DAST_METHOD_MAX_REDIRECTS:-0}
  [[ $maxred =~ ^[0-9]+$ ]] || maxred=0

  local scratch=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}
  local hdrfile=$scratch/dast-methods-hdr.$$ bodyfile=$scratch/dast-methods-body.$$
  local probed=0 failed=0 no_allow=0 redirected=0 trace_found=0 write_found=0
  local connect_found=0 trace_claimed_unconfirmed=0
  local -a ep_allow=() ep_raw=() ep_how=()
  local -A ep_seen=()
  local i canon rawtok how cls status

  # `_methods_absorb LABEL` - merge the `Allow` header of the response currently
  # sitting in $hdrfile into this endpoint's accumulator, recording WHERE each
  # method was learned from. Both sources are real and neither subsumes the
  # other: a `200 OPTIONS` names the set directly, and a `405` rejection is
  # REQUIRED to name it too (RFC 7231 §6.5.5) - so a server that refuses
  # `OPTIONS` outright can still be the one that tells us the most. Reading only
  # the 2xx case is a false negative on exactly those servers.
  #
  # IT READS AND WRITES ITS CALLER'S LOCALS BY DYNAMIC SCOPE (`hdrfile`,
  # `ep_allow`, `ep_raw`, `ep_how`, `ep_seen`, `canon`), which is why it is
  # written here rather than at file scope: bash function definitions are global
  # whatever their nesting, so defining it inside the phase buys no
  # encapsulation - what it buys is that the definition sits next to the only
  # frame whose locals make it callable. It is not a general helper and calling
  # it from anywhere else fails under `set -u`. It SETS rather than prints, for
  # `worker_id_set`'s reason (lib/core.sh): run through `$(...)` it would append
  # to a copy of the accumulator in a subshell and every advertisement would be
  # discarded.
  _methods_absorb() {
    local label=$1 k
    method_allow_collect "$hdrfile"
    (( _METHOD_ALLOW_PRESENT )) || return 0
    for (( k = 0; k < ${#_METHOD_ALLOW[@]}; k++ )); do
      canon=${_METHOD_ALLOW[k]}
      [[ -n ${ep_seen[$canon]:-} ]] && continue
      ep_seen[$canon]=1
      ep_allow+=("$canon")
      ep_raw+=("${_METHOD_ALLOW_RAW[k]}")
      ep_how+=("$label")
    done
    return 0
  }

  for url in "${urls[@]+"${urls[@]}"}"; do
    local path
    path=$(method_path_of "$url")
    ep_allow=(); ep_raw=(); ep_how=(); ep_seen=()
    local reached=0

    # --- 1. OPTIONS: the pure read (RFC 7231 §4.3.7, "no effect") -----------
    : >"$hdrfile"; : >"$bodyfile"
    if [[ -n $_METHODS_AUTH_LABEL ]]; then
      dast_auth_apply "$target" "$_METHODS_AUTH_LABEL" || true
    fi
    http_request_capture "$bodyfile" "$hdrfile"
    if http_request OPTIONS "$url" "$maxred" "$target"; then
      reached=1
      status=${_HTTP_LAST_STATUS:-}
      if [[ $status =~ ^3[0-9][0-9]$ ]]; then
        redirected=$(( redirected + 1 ))
      fi
      _methods_absorb "read from the \`Allow\` header of the \`$status\` response to \`OPTIONS $path\`"
    else
      failed=$(( failed + 1 ))
    fi

    # --- 2. TRACE: the one dangerous method that is safe to send ------------
    # RFC 7231 §4.3.8 defines TRACE as an echo with no effect on the resource,
    # which is precisely what makes measuring it legitimate here. Its response
    # is a second `Allow` source as well when the server rejects it.
    local trace_status='' trace_ctype=''
    if (( do_trace )); then
      : >"$hdrfile"; : >"$bodyfile"
      if [[ -n $_METHODS_AUTH_LABEL ]]; then
        dast_auth_apply "$target" "$_METHODS_AUTH_LABEL" || true
      fi
      http_request_capture "$bodyfile" "$hdrfile"
      if http_request TRACE "$url" "$maxred" "$target"; then
        reached=1
        trace_status=${_HTTP_LAST_STATUS:-}
        trace_ctype=${_HTTP_LAST_CONTENT_TYPE:-}
        _methods_absorb "read from the \`Allow\` header of the \`$trace_status\` response to \`TRACE $path\` (RFC 7231 §6.5.5 requires a 405 to carry one)"
        if method_trace_enabled "$trace_status" "$trace_ctype" "$bodyfile" "$path"; then
          local how_trace="answered \`$trace_status\`"
          [[ -n $trace_ctype ]] && how_trace+=" with \`Content-Type: $trace_ctype\`"
          local extra=''
          [[ -n ${ep_seen[TRACE]:-} ]] \
            || extra=' The server named `TRACE` in NO `Allow` header; only the echo revealed it.'
          _methods_emit trace TRACE TRACE "$url" "$how_trace" "$extra"
          trace_found=$(( trace_found + 1 ))
        elif [[ -n ${ep_seen[TRACE]:-} ]]; then
          # THE ADVERTISEMENT LOSES TO THE MEASUREMENT, and it must. A server
          # that names `TRACE` in `Allow` and then rejects the `TRACE` this run
          # actually sent does not have TRACE enabled; reporting Cross-Site
          # Tracing off the header alone would be a finding the operator can
          # neither reproduce nor fix. The contradiction is still worth
          # recording, because it is a real routing-table defect.
          trace_claimed_unconfirmed=$(( trace_claimed_unconfirmed + 1 ))
          run_record notes "module=dast phase=methods target=$target path=$path trace_advertised_not_confirmed=1 status=$trace_status - the server names \`TRACE\` in its \`Allow\` header but did not answer a real TRACE echo, so no Cross-Site Tracing finding is raised: the measurement is the stronger evidence and it says the method is not served."
        fi
      else
        failed=$(( failed + 1 ))
      fi
    fi

    (( reached )) && probed=$(( probed + 1 ))
    if (( reached )) && (( ${#ep_allow[@]} == 0 )); then
      no_allow=$(( no_allow + 1 ))
    fi

    # --- 3. Report what the server advertised, without exercising any of it -
    for (( i = 0; i < ${#ep_allow[@]}; i++ )); do
      canon=${ep_allow[i]}
      rawtok=${ep_raw[i]}
      how=${ep_how[i]}
      cls=$(method_class "$canon")
      case $cls in
        write)
          if (( do_write )); then
            _methods_emit write "$canon" "$rawtok" "$url" "$how" ''
            write_found=$(( write_found + 1 ))
          fi ;;
        connect)
          if (( do_connect )); then
            _methods_emit connect CONNECT "$rawtok" "$url" "$how" ''
            connect_found=$(( connect_found + 1 ))
          fi ;;
      esac
    done
  done
  rm -f "$hdrfile" "$bodyfile"

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's coverage roll-up
  # reads - recorded only when an endpoint was actually reached, so a run that
  # enumerated nothing is never reported as having covered these checks.
  if (( probed > 0 )); then
    (( do_trace )) && run_record checks_run DAST-METHOD-TRACE_ENABLED-01
    (( do_write )) && run_record checks_run DAST-METHOD-WRITE_ADVERTISED-01
    (( do_connect )) && run_record checks_run DAST-METHOD-CONNECT_ADVERTISED-01
  fi

  # THE STANDING LIMIT, RECORDED ON EVERY RUN THAT ENUMERATED ANYTHING. It is
  # not conditional on having found something, because its point is what the
  # ABSENCE of a write finding does and does not mean: this run established
  # acceptance from the server's own advertisement and never sent `PUT`,
  # `DELETE`, `PATCH` or `CONNECT`, so an endpoint that accepts one without
  # saying so in `Allow` is invisible here. That is a deliberate, permanent bound
  # of a non-destructive check, not a defect to be closed later.
  if (( probed > 0 )); then
    run_record coverage_reduction "module=dast reason=methods_write_not_exercised target=$target endpoints=$probed - acceptance was established from the server's own \`Allow\` header and from a \`TRACE\` echo, which are pure reads. \`PUT\`, \`DELETE\`, \`PATCH\` and \`CONNECT\` were never sent to any endpoint, because completing one would create, overwrite or delete a resource on a target under audit. An endpoint that accepts a write method WITHOUT advertising it is therefore not covered by this check."
  fi
  if (( no_allow > 0 )); then
    run_record coverage_reduction "module=dast reason=methods_no_allow_header target=$target count=$no_allow - $no_allow endpoint(s) answered without an \`Allow\` header on either the \`OPTIONS\` or the \`TRACE\` response, so this run does not know which methods they accept. Their absence from the findings below is silence from the server, not a clean result."
    if (( no_allow >= probed )); then
      run_record coverage_gap "dast methods: no endpoint on target '$target' named its accepted methods - every \`OPTIONS\` and \`TRACE\` response came back with no \`Allow\` header. The method surface of this target is UNKNOWN, not clean."
    fi
  fi
  if (( redirected > 0 )); then
    run_record coverage_reduction "module=dast reason=methods_endpoint_redirected target=$target count=$redirected - $redirected endpoint(s) answered \`OPTIONS\` with a redirect, which was not followed: the methods the redirect TARGET accepts are a fact about a different path, and reporting them against this one would mislabel them. Set SCOURSH_DAST_METHOD_MAX_REDIRECTS to follow them."
  fi
  if (( truncated > 0 )); then
    run_record coverage_gap "dast methods: the endpoint surface on target '$target' exceeded the per-phase cap of $max endpoint(s), so $truncated endpoint(s) were never asked which methods they accept. Their absence from this report is a coverage bound, not a clean result. Raise SCOURSH_DAST_METHOD_MAX_ENDPOINTS to widen it."
  fi
  if (( failed > 0 )); then
    run_record coverage_reduction "module=dast reason=methods_request_failed target=$target count=$failed - $failed method-enumeration request(s) failed at the transport, so those endpoints' method surface was not established."
  fi
  if (( probed == 0 )); then
    run_record coverage_gap "dast methods: every one of the ${#urls[@]} endpoint(s) on target '$target' failed to answer, so no method surface was enumerated - a coverage gap, not a clean result."
  fi

  log_info "dast methods: target '$target' - enumerated $probed of ${#urls[@]} endpoint(s); TRACE confirmed on $trace_found, write method advertised $write_found time(s), CONNECT advertised $connect_found time(s), $no_allow endpoint(s) named nothing"
  return 0
}

_dast_methods_phase
