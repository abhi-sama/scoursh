#!/usr/bin/env bash
# modules/dast/passive/cookies.sh - the §7.1 passive cookie-flag PHASE
# (docs/DESIGN.md §7.1 "cookies.sh - Secure, HttpOnly, SameSite flags per
# cookie"; docs/STEP5-DAST-PLAN.md DAST-06, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs on every dast run), so it
# inherits the whole run context and anything it emits lands in this process's
# shard. Per that function's contract it carries NO sourced-once guard - one run
# can legitimately reach the same phase twice. The parsing half - which is the
# substance of this ticket - lives in modules/dast/passive/cookie_engine.sh; this
# file is the orchestration: which responses to look at, and what to say about
# what the parser found.
#
# PASSIVE MEANS NO MUTATION OF STATE (docs/DESIGN.md §7.1's own first sentence).
# Only `GET` endpoints from the inventory are requested. A `POST`/`PUT`/`PATCH`/
# `DELETE` endpoint the crawler recorded is deliberately NOT dialled - sending it
# would be a state change, which is §7.2's tier and not this one's - and its
# omission is a recorded coverage_reduction rather than a silent skip, because a
# login POST is exactly where the most interesting cookie usually gets set and a
# reader must not mistake this check's silence for that cookie being fine.
#
# READ THE ENDPOINT LIST; DO NOT CRAWL. This phase discovers nothing. It reads
# reports/<run>/inventory/endpoints.json (docs/INVENTORY-FORMAT.md, tension 21),
# which modules/dast/crawl.sh (DAST-04) writes earlier in this same run, sends
# one GET per distinct endpoint, and follows no link out of any response. The
# reader is `inject_inventory_load` from modules/dast/active/inject_engine.sh
# rather than a new one written here, for that file's own stated reason: a second,
# subtly different reader for one frozen artifact is the failure mode it exists
# to prevent. Sourcing it is side-effect-free (it is a guarded pure library) and
# nothing in this file uses its request composer - a cookie check composes no
# parameter, it asks for the endpoint exactly as the crawler recorded it.
#
# EVERY REQUEST GOES THROUGH `http_request` (docs/FOUNDATION.md tension 19's "No
# bypass"), which is where the scope gate, DAST-01's rate limiter, the per-run
# request budget, the circuit breaker and DAST-32's ceilings all sit. The
# endpoint URLs are UNTRUSTED target output (tension 10,
# docs/INVENTORY-FORMAT.md §6) - a crawled URL is attacker-influenced text - so
# each one is re-gated by `http_request` on the way out and on every redirect
# hop, exactly as the crawler's own links are.
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test": no endpoint inventory, a surface with no GET endpoint, a cap
# that truncated the list, and a run in which no response set a cookie at all are
# each recorded so the report says which one happened (docs/DESIGN.md §15).
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes cookie-attribute syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/passive/cookie_engine.sh
source "${BASH_SOURCE[0]%/*}/cookie_engine.sh"
# The frozen-artifact reader, and (through it) lib/http.sh - the chokepoint a
# dast run does not otherwise load. Both carry their own sourced-once guards, so
# this is a no-op on a run where an injection probe already sourced them.
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/../active/inject_engine.sh"
# For an authenticated pass, when the run asked for one and auth.sh obtained a
# session. A session cookie is frequently only set on an authenticated response,
# so a cookie check that never looked at one has a real hole; consulted only
# under --authed, and a passive/unauthed run attaches nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`.
_cookies_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_cookies_scheme_of URL` - `https`, `http`, or '' when the URL carries neither.
_cookies_scheme_of() {
  local url=$1
  case ${url,,} in
    https://*) printf 'https' ;;
    http://*) printf 'http' ;;
    *) printf '' ;;
  esac
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh). A cookie maps onto it exactly:
# `param_location` is `cookie` - one of docs/INVENTORY-FORMAT.md §3's own seven
# location values, so this introduces no vocabulary - and `param_name` is the
# cookie name. That is what makes two flags missing on one cookie two findings
# rather than one, and one flag missing on two cookies two findings rather than
# one: the attribute lives in `check_id`, which is itself a fingerprint
# component.
_cookies_emit() {
  local kind=$1 name=$2 url=$3 method=$4 detail=$5
  local target=${SCOURSH_DAST_TARGET:-}
  local path check title base conf cwe owasp evi remed authv=none
  path=$(_cookies_path_of "$url")
  [[ -n ${_COOKIES_AUTH_LABEL:-} ]] && authv=user

  local hint=''
  cookie_looks_session "$name" \
    && hint=" The name '$name' is a conventional session/authentication cookie name, so treat this one first."

  case $kind in
    no_secure)
      check=DAST-COOKIE-NO_SECURE-01; base=medium; conf=high
      cwe=CWE-614; owasp=A05:2021
      title='Cookie set without the Secure attribute'
      evi="the response to $method $path set the cookie '$name' with no \`Secure\` attribute$detail, so a browser will also send it over plaintext \`http\`; anyone able to observe or inject onto the network path - a shared network, a hostile hop, or a single \`http://\` link or resource on the site - receives the cookie's value in the clear.$hint"
      remed='Set the `Secure` attribute on every cookie the application issues, so a browser only ever sends it over TLS. Serve the site over HTTPS only and add HSTS so the first, pre-redirect request cannot carry the cookie either. For a session cookie, set `Secure`, `HttpOnly` and an explicit `SameSite` together - each defends a different attack and none substitutes for another.' ;;
    no_httponly)
      check=DAST-COOKIE-NO_HTTPONLY-01; base=medium; conf=high
      cwe=CWE-1004; owasp=A05:2021
      title='Cookie set without the HttpOnly attribute'
      evi="the response to $method $path set the cookie '$name' with no \`HttpOnly\` attribute$detail, so page JavaScript can read it through \`document.cookie\`; any cross-site-scripting flaw anywhere on this origin - including one in a third-party script the page loads - can then read the cookie's value and replay it, turning a scripting bug into account takeover.$hint"
      remed='Set the `HttpOnly` attribute on every cookie no client-side script legitimately needs to read, which for a session or authentication cookie is always. If a script genuinely needs a value, put that value in a separate, non-authenticating cookie and leave the session cookie `HttpOnly`. Note that `HttpOnly` limits the damage of a cross-site-scripting flaw and does not fix one.' ;;
    samesite_absent)
      check=DAST-COOKIE-SAMESITE_ABSENT-01; base=low; conf=high
      cwe=CWE-1275; owasp=A01:2021
      title='Cookie set with no SameSite attribute'
      evi="the response to $method $path set the cookie '$name' with NO \`SameSite\` attribute at all, so the policy is whatever the visitor's browser defaults to rather than one this site chose - Chromium-based browsers apply \`Lax\`, and other engines have shipped both \`Lax\` and no restriction at all, so the same request is cross-site-protected for some visitors and not for others. This is the ABSENT case, not an explicitly weak one: the server stated no policy.$hint"
      remed='State the policy explicitly rather than relying on a browser default that differs between engines and changes between releases: `SameSite=Lax` for a session cookie (which still survives ordinary top-level navigation to the site), `SameSite=Strict` where no cross-site entry point needs the cookie. Only use `SameSite=None` for a cookie a third-party context genuinely requires, and pair it with `Secure`. `SameSite` reduces cross-site request forgery exposure and is not a substitute for an anti-CSRF token on a state-changing request.' ;;
    samesite_weak)
      check=DAST-COOKIE-SAMESITE_WEAK-01; base=medium; conf=high
      cwe=CWE-1275; owasp=A01:2021
      title='Cookie set with a SameSite value that gives no cross-site protection'
      evi="the response to $method $path set the cookie '$name' with $detail, so the cookie is attached to cross-site requests. This is the EXPLICIT case, not an absent attribute: the server sent a \`SameSite\` value, and that value is one under which a request originated by another site still carries this cookie - which is the precondition for cross-site request forgery against any state-changing endpoint that trusts it.$hint"
      remed='Use `SameSite=Lax` (or `Strict`) unless a third-party context genuinely needs the cookie. If it does, `SameSite=None` is only honoured when `Secure` is also set - modern browsers reject a `None` cookie without it outright, so the cookie is silently dropped rather than merely unprotected. Correct an unrecognised value rather than leaving it: browsers do not agree on how to treat one. Protect every state-changing endpoint with an anti-CSRF token regardless.' ;;
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
  finding_set loc_param_location cookie
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

# `_cookies_analyse URL METHOD HDRFILE` - parse every Set-Cookie in one captured
# response and emit what is missing. Adds to `_COOKIES_SEEN` and `_COOKIES_BAD`.
#
# DEDUPLICATION IS ON (check, cookie name, observed flag state), NOT ON THE PATH.
# The fingerprint carries `path_template`, so without this an application that
# sets one session cookie on forty pages produces forty identical findings and
# the report becomes unreadable - the defect is one cookie issued once, however
# many responses carry it. The FLAG STATE is in the key on purpose: a cookie of
# the same name genuinely set with different attributes on two paths is two
# different facts, and collapsing those would hide the weaker one behind the
# stronger. The first URL a given state was seen at is the one reported, and the
# endpoint order is deterministic (see the sort in the phase body), so the
# reported URL is stable between runs over the same surface.
_cookies_analyse() {
  local url=$1 method=$2 hdrfile=$3
  local value scheme key detail
  scheme=$(_cookies_scheme_of "$url")

  while IFS= read -r value; do
    [[ -n $value ]] || continue
    cookie_parse "$value" || continue
    local name=$_COOKIE_NAME
    _COOKIES_SEEN=$(( _COOKIES_SEEN + 1 ))
    key="$name|$_COOKIE_SECURE$_COOKIE_HTTPONLY|$_COOKIE_SAMESITE_STATE"
    local bad=0

    if (( ! _COOKIE_SECURE && _COOKIES_DO_SECURE )); then
      detail=''
      [[ $scheme == https ]] && detail=' - and it was set on an `https` response, so the application is already able to require TLS for it'
      [[ $scheme == http ]] && detail=' - the response itself was plaintext `http`, so the cookie has already travelled in the clear once before any flag could help'
      if [[ -z ${_COOKIES_DONE[no_secure$key]:-} ]]; then
        _COOKIES_DONE[no_secure$key]=1
        _cookies_emit no_secure "$name" "$url" "$method" "$detail"
      fi
      bad=1
    fi

    if (( ! _COOKIE_HTTPONLY && _COOKIES_DO_HTTPONLY )); then
      detail=''
      if [[ -z ${_COOKIES_DONE[no_httponly$key]:-} ]]; then
        _COOKIES_DONE[no_httponly$key]=1
        _cookies_emit no_httponly "$name" "$url" "$method" "$detail"
      fi
      bad=1
    fi

    # The absent/weak split (cookie_engine.sh's header states why these are two
    # check ids). `strict` and `lax` are the two states with nothing to report.
    case $_COOKIE_SAMESITE_STATE in
      absent)
        if (( _COOKIES_DO_SS_ABSENT )) && [[ -z ${_COOKIES_DONE[ss_absent$key]:-} ]]; then
          _COOKIES_DONE[ss_absent$key]=1
          _cookies_emit samesite_absent "$name" "$url" "$method" ''
        fi
        bad=1
        ;;
      none)
        detail='an explicit `SameSite=None`'
        (( _COOKIE_SECURE )) \
          || detail+=' and NO `Secure` attribute, a combination modern browsers reject outright - the cookie is dropped rather than merely unprotected, so this is also a functional defect'
        if (( _COOKIES_DO_SS_WEAK )) && [[ -z ${_COOKIES_DONE[ss_weak$key]:-} ]]; then
          _COOKIES_DONE[ss_weak$key]=1
          _cookies_emit samesite_weak "$name" "$url" "$method" "$detail"
        fi
        bad=1
        ;;
      unrecognised)
        # The raw value goes through redaction/escaping like any other evidence
        # (tension 10): it is target-controlled text.
        detail="a \`SameSite\` value browsers do not recognise (\`SameSite=$_COOKIE_SAMESITE_RAW\`), which no engine treats as a stated policy"
        if (( _COOKIES_DO_SS_WEAK )) && [[ -z ${_COOKIES_DONE[ss_weak$key]:-} ]]; then
          _COOKIES_DONE[ss_weak$key]=1
          _cookies_emit samesite_weak "$name" "$url" "$method" "$detail"
        fi
        bad=1
        ;;
    esac

    (( bad )) && _COOKIES_BAD=$(( _COOKIES_BAD + 1 ))
  done < <(cookie_extract_set_cookie "$hdrfile" || true)
  return 0
}

_dast_cookies_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/cookies.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # tension-15 per-check selection, guarded exactly as active/sqli.sh guards it.
  # `dast_check_selected` (modules/dast/engine.sh) now exists, so on any run
  # reached through `dast_run_phase` this narrows what is inspected for real;
  # the guard is kept because this file is also reachable from a direct-engine
  # test that never sources engine.sh, where an unguarded call would be exit 127
  # and would deselect all four checks rather than none of them.
  local do_secure=1 do_httponly=1 do_ss_absent=1 do_ss_weak=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-COOKIE-NO_SECURE-01 || do_secure=0
    dast_check_selected DAST-COOKIE-NO_HTTPONLY-01 || do_httponly=0
    dast_check_selected DAST-COOKIE-SAMESITE_ABSENT-01 || do_ss_absent=0
    dast_check_selected DAST-COOKIE-SAMESITE_WEAK-01 || do_ss_weak=0
  fi
  if (( do_secure == 0 && do_httponly == 0 && do_ss_absent == 0 && do_ss_weak == 0 )); then
    run_record coverage_reduction "module=dast reason=cookies_no_check_selected target=$target - every DAST-COOKIE-* check was filtered out by --profile-scan/--intensity, so no response was inspected for cookie flags."
    return 0
  fi

  # THE ENDPOINT FILE IS RE-RESOLVED HERE RATHER THAN TAKEN FROM
  # SCOURSH_DAST_ENDPOINTS ALONE, AND THAT IS NOT BELT-AND-BRACES.
  # modules/dast/run.sh calls `dast_inventory_read` ONCE, before the phase loop,
  # and exports SCOURSH_DAST_ENDPOINTS from what it found THEN - which on a fresh
  # run is nothing, because crawl.sh is a phase and has not run yet. It writes
  # reports/<run>/inventory/endpoints.json a few phases later in the same loop and
  # nothing re-reads it, so a consumer that trusts the exported variable alone
  # sees an empty surface on precisely the ordinary run. This file therefore
  # prefers the exported path when it is usable and falls back to the run
  # directory's own artifact - the file docs/INVENTORY-FORMAT.md names - which is
  # the same artifact by the same path, just read after the producer wrote it.
  # SCOURSH_DAST_COOKIE_ENDPOINTS overrides both, so the reader is testable
  # against a fixture without a crawl (the swappable-seam idiom lib/http.sh's own
  # transport/resolver hooks use). The general fix belongs to modules/dast/run.sh
  # and affects every inventory consumer, so it is filed rather than widened into
  # this ticket.
  local epf=${SCOURSH_DAST_COOKIE_ENDPOINTS:-}
  if [[ -z $epf ]]; then
    epf=${SCOURSH_DAST_ENDPOINTS:-}
    [[ -n $epf && -r $epf && -s $epf ]] || epf=${SCOURSH_RUN_DIR:-}/inventory/endpoints.json
  fi
  if [[ ! -r $epf || ! -s $epf ]]; then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - no endpoint inventory (docs/INVENTORY-FORMAT.md) was readable, so the cookie check had no response to inspect."
    run_record coverage_gap "dast cookies: target '$target' has no known endpoint, so no response was inspected for \`Secure\`/\`HttpOnly\`/\`SameSite\`. This is a coverage gap - nothing was tested - not a finding that the application's cookies are correctly flagged."
    return 0
  fi

  inject_inventory_load "$epf" ''

  # THE ENDPOINT ORDER IS SORTED, AND THAT IS NOT COSMETIC. `_INJ_EP_URL` is a
  # bash ASSOCIATIVE array, whose iteration order is its internal hash order and
  # is not the order the crawler wrote. With a cap below, an unsorted walk would
  # make WHICH endpoints get probed depend on hash order - so two runs over the
  # identical surface could inspect different responses and produce different
  # findings, which is the opposite of this repository's byte-reproducible-output
  # property. Sorted under LC_ALL=C, the same surface always yields the same walk.
  local -a rows=()
  local id row skipped_method=0
  while IFS= read -r row; do
    [[ -n $row ]] && rows+=("$row")
  done < <(
    for id in "${!_INJ_EP_URL[@]}"; do
      printf '%s\t%s\n' "${_INJ_EP_URL[$id]}" "${_INJ_EP_METHOD[$id]:-GET}"
    done | LC_ALL=C sort -u
  )

  # GET only (see this file's header: passive means no mutation of state), and
  # one request per distinct URL - the crawler already strips query strings off
  # an endpoint URL, so two paginated links are one endpoint here, not fifty.
  local -a urls=()
  local -A seen_url=()
  local url method
  local i
  for (( i = 0; i < ${#rows[@]}; i++ )); do
    url=${rows[i]%%$'\t'*}
    method=${rows[i]##*$'\t'}
    [[ -n $url ]] || continue
    if [[ ${method^^} != GET ]]; then
      skipped_method=$(( skipped_method + 1 ))
      continue
    fi
    [[ -n ${seen_url[$url]:-} ]] && continue
    seen_url[$url]=1
    urls+=("$url")
  done

  local max=${SCOURSH_DAST_COOKIE_MAX_ENDPOINTS:-25}
  [[ $max =~ ^[0-9]+$ ]] || max=25
  (( max < 1 )) && max=1
  local truncated=0
  if (( ${#urls[@]} > max )); then
    truncated=$(( ${#urls[@]} - max ))
    urls=("${urls[@]:0:max}")
  fi

  if (( ${#urls[@]} == 0 )); then
    if (( skipped_method > 0 )); then
      run_record coverage_reduction "module=dast reason=cookies_no_get_endpoint target=$target non_get=$skipped_method - every discovered endpoint is a non-GET method, and a passive check may not send one (docs/DESIGN.md §7.1 'No mutation of state'), so no response was inspected."
    else
      run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - the endpoint inventory carried no usable endpoint, so the cookie check had no response to inspect."
    fi
    run_record coverage_gap "dast cookies: no response on target '$target' could be inspected for cookie flags. This is a coverage gap - nothing was tested - not a finding that the application's cookies are correctly flagged."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained a session this run. A session cookie is often only issued on an
  # authenticated response, so an unauthenticated-only cookie check has a real
  # hole - which is stated below when the run did not close it.
  _COOKIES_AUTH_LABEL=''
  local cookie_header=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _COOKIES_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      if declare -F dast_auth_cookie_header_set >/dev/null; then
        dast_auth_cookie_header_set "$target" "$_COOKIES_AUTH_LABEL"
        cookie_header=${_DAST_AUTH_COOKIE:-}
      fi
      run_record notes "module=dast phase=cookies target=$target identity=$_COOKIES_AUTH_LABEL authenticated_pass=1"
    fi
  fi
  if [[ -z $_COOKIES_AUTH_LABEL ]]; then
    run_record coverage_reduction "module=dast reason=cookies_unauthenticated_only target=$target - the cookie flags below were read from UNAUTHENTICATED responses only. A session cookie is frequently issued only after a login, so this run says nothing about the flags on one. Run with --authed and a config/auth.conf to cover it."
  fi

  declare -gA _COOKIES_DONE=()
  _COOKIES_SEEN=0 _COOKIES_BAD=0
  # Published as globals because `_cookies_analyse` is a function and the
  # selection was resolved above; a `local` here would be invisible to it.
  declare -g _COOKIES_DO_SECURE=$do_secure _COOKIES_DO_HTTPONLY=$do_httponly
  declare -g _COOKIES_DO_SS_ABSENT=$do_ss_absent _COOKIES_DO_SS_WEAK=$do_ss_weak
  local hdrfile=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/dast-cookies-hdr.$$
  local fetched=0 failed=0
  for url in "${urls[@]+"${urls[@]}"}"; do
    : >"$hdrfile"
    [[ -n $cookie_header ]] && http_request_header Cookie "$cookie_header"
    http_request_capture '' "$hdrfile"
    if ! http_request GET "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
      failed=$(( failed + 1 ))
      continue
    fi
    fetched=$(( fetched + 1 ))
    _cookies_analyse "$url" GET "$hdrfile"
  done
  rm -f "$hdrfile"

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's coverage roll-up
  # reads - recorded only when a response was actually inspected, so a run that
  # reached no endpoint is never reported as having covered these checks.
  if (( fetched > 0 )); then
    (( do_secure )) && run_record checks_run DAST-COOKIE-NO_SECURE-01
    (( do_httponly )) && run_record checks_run DAST-COOKIE-NO_HTTPONLY-01
    (( do_ss_absent )) && run_record checks_run DAST-COOKIE-SAMESITE_ABSENT-01
    (( do_ss_weak )) && run_record checks_run DAST-COOKIE-SAMESITE_WEAK-01
  fi

  if (( skipped_method > 0 )); then
    run_record coverage_reduction "module=dast reason=cookies_non_get_endpoints_not_dialled target=$target count=$skipped_method - $skipped_method discovered endpoint(s) use a non-GET method and were not requested, because a passive check may not change state (docs/DESIGN.md §7.1). A login POST is exactly where a session cookie is usually set, so its flags were not read here."
  fi
  if (( truncated > 0 )); then
    run_record coverage_gap "dast cookies: the GET surface on target '$target' exceeded the per-phase cap of $max endpoint(s), so $truncated endpoint(s) were not requested and any cookie only they set was not inspected. Their absence from this report is a coverage bound, not a clean result. Raise SCOURSH_DAST_COOKIE_MAX_ENDPOINTS to widen it."
  fi
  if (( failed > 0 )); then
    run_record coverage_reduction "module=dast reason=cookies_request_failed target=$target count=$failed - $failed endpoint request(s) failed at the transport, so any cookie those responses set was not inspected."
  fi
  if (( fetched == 0 )); then
    run_record coverage_gap "dast cookies: every one of the ${#urls[@]} endpoint request(s) on target '$target' failed, so no response was inspected for cookie flags - a coverage gap, not a clean result."
  elif (( _COOKIES_SEEN == 0 )); then
    run_record notes "module=dast phase=cookies target=$target endpoints_fetched=$fetched cookies_seen=0 - no response set a cookie, so there was no cookie flag to check. This is a real negative over the surface inspected, bounded by the coverage records for this phase."
  fi

  log_info "dast cookies: target '$target' - inspected $fetched of ${#urls[@]} GET endpoint(s), saw $_COOKIES_SEEN Set-Cookie header(s), $_COOKIES_BAD with a missing or weak flag"
  return 0
}

_dast_cookies_phase
