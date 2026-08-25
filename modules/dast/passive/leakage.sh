#!/usr/bin/env bash
# modules/dast/passive/leakage.sh - the §7.1 INFORMATION-DISCLOSURE phase
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-10, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs on every dast run), so it
# inherits the whole run context and anything it emits lands in this process's
# shard.  Per that function's contract it carries NO sourced-once guard - one run
# can legitimately reach the same phase twice - and every array it declares uses
# `declare -g`.  The pure, testable half is
# modules/dast/passive/leakage_engine.sh; this file is the orchestration: choose
# what to request, ask through the ONE chokepoint, decide, and emit.
#
# PASSIVE, RESTATED (docs/DESIGN.md §7.1 "No mutation of state").  Every request
# this phase sends is a plain GET to a URL that is either the operator's own
# `base-url` or an endpoint the crawl already fetched.  It sends no payload, sets
# no cookie, submits no form, and provokes no error - a 500 page is inspected
# only if the target already returns one to an ordinary visitor.  DELIBERATELY
# PROVOKING an error to harvest its stack trace is the obvious way to raise this
# family's recall and it is out of scope for the tier and for this ticket: it is
# active probing, and it belongs behind `--intensity` and the ticket that owns
# it.  Non-GET endpoints are counted and declared, never silently dropped.
#
# PRECISION OVER RECALL, WHICH IS THIS FAMILY'S DEFINING CONSTRAINT.  Each of the
# five families has a naive implementation that fires on ordinary, correct sites,
# and a report whose top finding is a retina image asset or a site's own contact
# address is a report nobody opens twice.  The technique that keeps each family
# precise is stated in modules/dast/passive/leakage_engine.sh's own header, one
# numbered paragraph per family, and each is pinned by a negative fixture in
# tests/suites/dast-leakage.sh that the naive reading flags and this
# implementation does not.  In summary:
#
#   STACK_TRACE          requires a STRUCTURED FRAME (a source file plus a line
#                        number) or an interactive-debugger banner - never a
#                        framework name or the word "error", which is what a
#                        branded 404 carries.
#   PROXY_HEADER         requires the VALUE to name an internal identity (an
#                        RFC 1918 / loopback / link-local / CGN address, or a
#                        reserved-internal DNS suffix).  The header NAME alone
#                        selects a candidate; a public CDN POP code and a
#                        product name are not flagged.
#   EMAIL                subtracts every address the site publishes as a
#                        `mailto:` link, every RFC 2142 role alias and every
#                        placeholder localpart, and rejects a "domain" whose
#                        final label is a file extension.
#   JS_CONFIG            subtracts an ALLOW-LIST of public-by-design key names
#                        and value prefixes FIRST, then reports only a
#                        never-client-safe key name with a non-placeholder
#                        literal, or a vendor-declared secret value shape.
#   THIRD_PARTY_ORIGIN   subtracts the response's own host and everything
#                        sharing its registrable domain, and is INFORMATIONAL.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test".  No endpoint inventory and no base-url, an endpoint the scope
# gate declines, a response that never arrived, a body that was truncated at a
# bound, and a FAMILY that no fetched response was applicable to are each
# recorded as a coverage_gap or a coverage_reduction the report renders - exactly
# as modules/dast/passive/headers.sh, auth.sh and crawl.sh do for their own gaps.
# The family-applicability record is the one that matters most here: a run that
# only ever fetched JSON has tested nothing about served JavaScript, and
# `DAST-LEAK-JS_CONFIG-01` reporting nothing on it is the absence of a test.
#
# A CANDIDATE SECRET NEVER REACHES THE REPORT.  Family 4's finding carries the
# key name, a description of the shape that matched and the value's length, and
# not the value - see the engine's section 5.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes header, URL and JS syntax
#   literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/passive/leakage_engine.sh
source "${BASH_SOURCE[0]%/*}/leakage_engine.sh"

# ---------------------------------------------------------------------------
# The check catalog, in the shell
# ---------------------------------------------------------------------------
# modules/dast/passive/checks-leakage.rules is the REGISTRY - what tension 12 computes
# coverage over and tension 15's filter chain filters - and this table is what a
# finding actually carries.  They are two copies on purpose and for the same
# reason modules/dast/passive/headers.sh and active/sqli.sh each carry their
# own: `finding_set` is fed by the emitting script, not by the registry loader,
# and a phase that read its severity out of a records file at emit time would be
# a second consumer of that format for every module to keep in step.  Keep the
# two in sync when either changes; tests/suites/dast-leakage.sh asserts they
# agree on every id, field by field.
#
# Sets `_LKC_TITLE`, `_LKC_SEV`, `_LKC_CONF`, `_LKC_CWE`, `_LKC_OWASP` and
# `_LKC_REM`.  Returns 1 for an id that is not this phase's.
_leak_catalog() {
  _LKC_TITLE='' _LKC_SEV='' _LKC_CONF='' _LKC_CWE='' _LKC_OWASP='' _LKC_REM=''
  case $1 in
    DAST-LEAK-STACK_TRACE-01)
      _LKC_TITLE='Response body discloses a server stack trace or debugger page'
      _LKC_SEV=medium; _LKC_CONF=high; _LKC_CWE=CWE-209; _LKC_OWASP=A05:2021
      _LKC_REM='Turn the framework debug flag off in every deployed environment and serve a generic error document instead, with the detail written to a server-side log the visitor cannot read. Treat this as a configuration default rather than a per-page fix: the same flag governs every handler, and an interactive debugger page frequently also exposes an evaluation console, which turns disclosure into remote code execution. Verify by requesting a path that is known to raise and confirming the response carries no filesystem path, no line number and no framework version.' ;;
    DAST-LEAK-PROXY_HEADER-01)
      _LKC_TITLE='Response header discloses internal infrastructure'
      _LKC_SEV=low; _LKC_CONF=high; _LKC_CWE=CWE-200; _LKC_OWASP=A05:2021
      _LKC_REM='Strip the header at the edge before the response leaves the perimeter, rather than at the application, so a route that bypasses the application is covered too. Most reverse proxies add these for internal debugging and have a directive to unset them on egress. An internal address or an internal DNS name is reconnaissance for a later server-side request forgery or a lateral move: it tells an attacker the private range in use, the naming convention, and often the orchestration platform.' ;;
    DAST-LEAK-EMAIL-01)
      _LKC_TITLE='Email address disclosed outside a published contact link'
      _LKC_SEV=low; _LKC_CONF=medium; _LKC_CWE=CWE-200; _LKC_OWASP=A01:2021
      _LKC_REM='Remove the address from the served bytes where it is incidental - a leftover HTML comment, a serialised record in an embedded JSON blob, or a bundled test fixture. A named individual address harvested this way is the raw material for a targeted phishing or password-reset attempt, and it is also a username on many systems. Where an address must be published, publish a role alias on a contact page rather than an individual mailbox: this check deliberately does not report addresses the site links as `mailto:`, which is the publication route it treats as intentional.' ;;
    DAST-LEAK-JS_CONFIG-01)
      _LKC_TITLE='Served JavaScript carries a credential or internal configuration value'
      _LKC_SEV=high; _LKC_CONF=medium; _LKC_CWE=CWE-540; _LKC_OWASP=A05:2021
      _LKC_REM='Treat the value as compromised and rotate it before anything else: every visitor since the bundle was published has had it. Then move the secret server-side and have the browser call an endpoint that holds it, rather than shipping it. Audit the build pipeline for the cause, which is usually a whole environment file inlined into the bundle rather than one deliberate variable - so assume siblings. Keep only values a vendor documents as browser-safe (a publishable key, an OAuth client id, an analytics id) in client code; this check allow-lists those by name and by prefix and does not report them.' ;;
    DAST-LEAK-THIRD_PARTY_ORIGIN-01)
      _LKC_TITLE='Page loads content from third-party origins'
      _LKC_SEV=info; _LKC_CONF=high; _LKC_CWE=CWE-829; _LKC_OWASP=A08:2021
      _LKC_REM='This is an inventory rather than a defect: review the list and confirm each origin is one the application means to depend on. Each third-party origin serving active content can execute script in this page context, so its compromise is this application compromised. Reduce the list where a dependency can be self-hosted, pin what remains with Subresource Integrity, and constrain the set with a Content-Security-Policy that names exactly these origins - so an origin added later, by an attacker or by an unreviewed change, is blocked rather than silently trusted.' ;;
    *) return 1 ;;
  esac
  return 0
}

# Every id this phase can emit, in report order.
declare -ga _LEAK_CHECK_IDS=(
  DAST-LEAK-STACK_TRACE-01
  DAST-LEAK-PROXY_HEADER-01
  DAST-LEAK-EMAIL-01
  DAST-LEAK-JS_CONFIG-01
  DAST-LEAK-THIRD_PARTY_ORIGIN-01
)

# ---------------------------------------------------------------------------
# tension-15 per-check selection
# ---------------------------------------------------------------------------
# scan.sh's filter chain records which ids survived
# --profile-scan/--intensity/--allow-intrusive and exports them as
# SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected` is the
# reader.  Consulted only if that function exists - it does not today, and both
# modules/dast/passive/headers.sh and active/sqli.sh guard it the same way - so
# this file does not hard-depend on it: absent, everything the tier already
# permitted runs, which is the "empty means all selected" fallback a
# direct-engine test relies on.
_leak_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
# The DAST location profile is (target, method, path_template, param_location,
# param_name) (lib/findings.sh).  A leakage finding names no parameter, so the
# last two are empty and the identity is (target, GET, path_template) plus the
# check id.
#
# TWO GRAINS, AND THE SPLIT IS DELIBERATE.  A stack trace and a bundled
# credential are properties of ONE HANDLER - the broken route, the built
# bundle - so those two emit once per PATH, and two paths that both leak are two
# findings an operator fixes in two places.  An internal proxy header, the set of
# addresses a site discloses, and the set of third-party origins it loads are
# properties of the APPLICATION, configured once; emitting those per path would
# report one misconfiguration at every URL and bury everything else, so they
# accumulate and emit ONCE, located at the first response that exhibited them
# (in `leak_endpoints_load`'s deterministic order, which puts the operator's own
# base-url first) with the affected/tested count in the evidence.  This is the
# same reasoning modules/dast/passive/headers.sh applies to every one of its
# checks; the difference is that two of these five genuinely are per-handler.
_leak_emit() {
  local check=$1 url=$2 path=$3 evidence=$4
  local target=${SCOURSH_DAST_TARGET:-}
  _leak_catalog "$check" || return 0

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$_LKC_TITLE"
  finding_set base_severity "$_LKC_SEV"
  finding_set confidence "$_LKC_CONF"
  finding_set cwe "$_LKC_CWE"
  finding_set owasp "$_LKC_OWASP"
  finding_set exposure external
  finding_set auth "${_LEAK_AUTH_VALUE:-none}"
  # Family 3 and family 4 are, by construction, findings ABOUT data that should
  # not have been served; the other three are about configuration.
  case $check in
    DAST-LEAK-EMAIL-01 | DAST-LEAK-JS_CONFIG-01) finding_set sensitive_data true ;;
    *) finding_set sensitive_data false ;;
  esac
  finding_set remediation "$_LKC_REM"
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method GET
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location ''
  finding_set loc_param_name ''
  finding_set url "$url"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# The per-family accumulators
# ---------------------------------------------------------------------------
# `_LKF_EVAL[check]` counts the responses a family was APPLICABLE to.  This, not
# the number of requests, is what decides whether the check appears in
# `checks_run` - a JS-config check over a run that only ever fetched JSON
# covered nothing, and saying otherwise is the overstated coverage
# docs/DESIGN.md §15 forbids.
_leak_acc_reset() {
  declare -gA _LKF_EVAL=() _LKF_HIT=() _LKF_URL=() _LKF_PATH=() _LKF_DETAIL=()
  leak_emails_reset
  leak_js_reset
  leak_origins_reset
  declare -ga _LEAK_TRACE_ROWS=() _LEAK_JS_ROWS=()
}

_leak_eval() {
  local c=$1
  _LKF_EVAL[$c]=$(( ${_LKF_EVAL[$c]:-0} + 1 ))
}

_leak_hit() {
  local c=$1 url=$2 path=$3 detail=$4
  if [[ -z ${_LKF_HIT[$c]:-} ]]; then
    _LKF_HIT[$c]=1
    _LKF_URL[$c]=$url
    _LKF_PATH[$c]=$path
    _LKF_DETAIL[$c]=$detail
  else
    _LKF_HIT[$c]=$(( _LKF_HIT[$c] + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Analysis of one response
# ---------------------------------------------------------------------------
# Reads the `_HDR_*` header state and the `_LEAK_LINES` body state already
# published for one response, and feeds the accumulators.  Sends nothing itself.
_leak_analyse_one() {
  local url=$1 path=$2 kind=$3
  local sep=$'\x1f'
  local self n line name v

  # -- Family 2: infrastructure headers, on EVERY response ----------------
  # Header-only, so it applies whatever the body turned out to be.
  if _leak_selected DAST-LEAK-PROXY_HEADER-01; then
    _leak_eval DAST-LEAK-PROXY_HEADER-01
    # EVERY matching header on the response is named, not just the first.
    # One response routinely carries two - a `Via` from the proxy and an
    # `X-Backend-Server` from the load balancer - and they are two separate
    # places the operator has to unset it.  Stopping at the first would report
    # one of them and leave the other in place after the "fix", with the run
    # afterwards looking identical.
    local found=''
    for name in "${_LEAK_INFRA_HEADERS[@]+"${_LEAK_INFRA_HEADERS[@]}"}"; do
      hdr_present "$name" || continue
      hdr_value "$name"; v=${_HDR_V//$'\n'/, }
      if leak_internal_identity_in "$v"; then
        local how='an address in a range that is not routable on the public internet'
        [[ $_LEAK_IDENTITY_KIND == dns ]] \
          && how='a DNS name under a reserved-internal suffix, which does not resolve outside the perimeter'
        found+="${found:+; }the $name response header carries $(leak_safe_text "$_LEAK_IDENTITY" 80), $how (full value: \"$(leak_safe_text "$v" 120)\")"
      fi
    done
    [[ -n $found ]] && _leak_hit DAST-LEAK-PROXY_HEADER-01 "$url" "$path" "$found"
  fi

  # Everything below reads the BODY, so a response whose body this phase could
  # not read (a bound, an empty body, a binary type) contributes to no family
  # and must not be counted as one it was applicable to.
  (( _LEAK_NLINES > 0 )) || return 0

  self=$(leak_host_of "$url")

  # -- Family 1: stack trace / debugger page ------------------------------
  # Applicable to any TEXTUAL body: a trace is served as HTML by a debug page,
  # as JSON by an API's error handler, and as plain text by a bare framework.
  local textual=0
  case $kind in html | js | json | text) textual=1 ;; esac

  if (( textual )) && _leak_selected DAST-LEAK-STACK_TRACE-01; then
    _leak_eval DAST-LEAK-STACK_TRACE-01
    for (( n = 0; n < _LEAK_NLINES; n++ )); do
      line=${_LEAK_LINES[$n]}
      if leak_stack_frame_in "$line"; then
        _LEAK_TRACE_ROWS+=("$url$sep$path$sep$_LEAK_STACK_KIND$sep$(leak_safe_text "$_LEAK_STACK_HIT" 140)")
        break
      fi
    done
  fi

  # -- Family 3: email disclosure -----------------------------------------
  if (( textual )) && _leak_selected DAST-LEAK-EMAIL-01; then
    _leak_eval DAST-LEAK-EMAIL-01
    for (( n = 0; n < _LEAK_NLINES; n++ )); do
      leak_emails_scan "${_LEAK_LINES[$n]}" "$path"
    done
  fi

  # -- Family 4: client-config leakage in served JavaScript ---------------
  # JavaScript proper, and the inline `<script>` blocks of an HTML document -
  # which is where a server-rendered application puts its client config, and
  # skipping them would miss the commonest real shape of this defect.  A JSON
  # document is included too: a `/config.json` served to the browser is client
  # config by any other name.
  local js_applicable=0
  case $kind in js | json) js_applicable=1 ;; html) js_applicable=1 ;; esac
  if (( js_applicable )) && _leak_selected DAST-LEAK-JS_CONFIG-01; then
    _leak_eval DAST-LEAK-JS_CONFIG-01
    local before=${#_LEAK_JSCFG[@]}
    for (( n = 0; n < _LEAK_NLINES; n++ )); do
      leak_js_config_in "${_LEAK_LINES[$n]}" "$path"
    done
    if (( ${#_LEAK_JSCFG[@]} > before )); then
      local i
      for (( i = before; i < ${#_LEAK_JSCFG[@]}; i++ )); do
        _LEAK_JS_ROWS+=("$url$sep$path$sep${_LEAK_JSCFG[$i]}")
      done
    fi
  fi

  # -- Family 5: third-party origins --------------------------------------
  # Documents and scripts only.  A JSON API response naming an external URL is
  # DATA rather than something the browser loads, and counting it would turn a
  # search result into a third-party dependency.
  local origin_applicable=0
  case $kind in html | js) origin_applicable=1 ;; esac
  if (( origin_applicable )) && _leak_selected DAST-LEAK-THIRD_PARTY_ORIGIN-01; then
    _leak_eval DAST-LEAK-THIRD_PARTY_ORIGIN-01
    for (( n = 0; n < _LEAK_NLINES; n++ )); do
      leak_origins_in "${_LEAK_LINES[$n]}" "$self"
    done
  fi
  return 0
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_leakage_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/leakage.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE, AND
  # THAT IS NOT BELT-AND-BRACES.  modules/dast/run.sh reads the inventory and
  # exports SCOURSH_DAST_ENDPOINTS BEFORE the phase loop starts, so on a first
  # run - the ordinary case - it is EMPTY, because crawl.sh writes
  # reports/<run>/inventory/endpoints.json a few phases later in the same loop.
  # A passive check that trusted the export alone would therefore see no
  # endpoints on exactly the run that has just discovered them.  The run
  # directory's own artifact is the authority (docs/INVENTORY-FORMAT.md §1), so
  # it is consulted when the export is empty - the identical fallback, by the
  # identical path, that modules/dast/passive/headers.sh and cookies.sh already
  # make.  Fixing the export itself belongs to modules/dast/run.sh and is filed
  # separately rather than changed here.
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi

  # The operator's own base-url, which is config-derived rather than
  # target-derived and is the one URL that exists whatever the crawl found.
  local base=''
  if declare -F config_scope_field_or >/dev/null; then
    base=$(config_scope_field_or "$target" base-url '' 2>/dev/null || printf '')
  fi

  _leak_acc_reset
  _LEAK_AUTH_VALUE=none

  leak_endpoints_load "$epf" "$target" "$base"
  if (( _LEAK_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_to_inspect target=$target - neither an endpoint inventory (docs/INVENTORY-FORMAT.md) nor a base-url in config/scope.conf gave this phase a URL to request, so no response was inspected for information disclosure."
    run_record coverage_gap "dast leakage: target '$target' offered no URL to request, so NONE of the five information-disclosure families was evaluated. This is a coverage gap - nothing was tested - not a finding that the target discloses nothing."
    return 0
  fi

  local i url path tested=0 refused=0 unreachable=0 nobody=0 truncated=0
  local sep=$'\x1f'
  for (( i = 0; i < _LEAK_N; i++ )); do
    url=${_LEAK_URL[$i]}
    path=${_LEAK_PATH[$i]}

    # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - the identical
    # split modules/dast/crawl.sh's `_crawl_in_scope` records.  `http_request`
    # gates FATALLY (an out-of-scope URL there is a caller bug, exit 3), which is
    # right for the operator's own base-url and exactly wrong for a URL lifted
    # out of an inventory some other module wrote: one bad row would abort the
    # whole run.  This decides only whether the URL is worth ASKING FOR;
    # everything that survives still goes through http_request, which re-gates it
    # and re-gates every redirect hop.
    if ! http_gate_url "$url" "$target"; then
      refused=$(( refused + 1 ))
      continue
    fi

    local bodyfile=$SCOURSH_SCRATCH/dast-leakage.$$.$i.body
    local hdrfile=$SCOURSH_SCRATCH/dast-leakage.$$.$i.hdr
    # The capture is set immediately before the call because `http_request`
    # consumes and clears the per-request context at entry, so it can never ride
    # along on a later request (lib/http.sh §9a).
    http_request_capture "$bodyfile" "$hdrfile"
    if ! http_request GET "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$bodyfile" "$hdrfile"
      continue
    fi
    if ! hdr_parse_capture "$hdrfile"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$bodyfile" "$hdrfile"
      continue
    fi
    tested=$(( tested + 1 ))

    # The body is optional: family 2 works on headers alone, so a response with
    # no readable body is still a tested response for that family and an
    # untested one for the other four.
    local kind
    hdr_first content-type
    kind=$(leak_ctype_kind "$_HDR_V")
    if ! leak_body_read "$bodyfile"; then
      nobody=$(( nobody + 1 ))
      declare -ga _LEAK_LINES=()
      declare -g _LEAK_NLINES=0
    fi
    (( ${_LEAK_BODY_TRUNCATED:-0} )) && truncated=$(( truncated + 1 ))
    rm -f "$bodyfile" "$hdrfile"

    _leak_analyse_one "$url" "$path" "$kind"
  done

  if (( tested == 0 )); then
    run_record coverage_gap "dast leakage: none of the $_LEAK_N URL(s) selected on target '$target' produced a response this phase could read ($refused declined by the scope gate, $unreachable did not answer), so NONE of the five information-disclosure families was evaluated. A clean result here is the absence of a test."
    return 0
  fi

  _leak_emit_all "$tested"

  # checks_run is the set of checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), and it is the honest input modules/dast/run.sh's coverage
  # roll-up reads.  A family is recorded only when at least one response it was
  # APPLICABLE to was actually inspected.
  local c
  for c in "${_LEAK_CHECK_IDS[@]+"${_LEAK_CHECK_IDS[@]}"}"; do
    (( ${_LKF_EVAL[$c]:-0} > 0 )) && run_record checks_run "$c"
  done

  # Every bound and every gap, named.  docs/DESIGN.md §15: a bound that
  # truncates silently is indistinguishable from a surface that was really that
  # small.
  if (( _LEAK_TRUNCATED > 0 )); then
    run_record coverage_gap "dast leakage: target '$target' offered more distinct endpoints than this phase requests - $_LEAK_TRUNCATED were NOT fetched (cap $_LEAK_MAX_ENDPOINTS). Their responses were not inspected and their absence from this report is a coverage bound, not a clean result."
  fi
  if (( _LEAK_SKIPPED_NON_GET > 0 )); then
    run_record coverage_reduction "module=dast reason=leakage_non_get_endpoint_skipped target=$target count=$_LEAK_SKIPPED_NON_GET - $_LEAK_SKIPPED_NON_GET discovered endpoint(s) are not GET. Re-sending them to read their responses would change target state, which docs/DESIGN.md §7.1 forbids at the passive tier, so they were not inspected."
  fi
  if (( refused > 0 )); then
    run_record coverage_reduction "module=dast reason=leakage_endpoint_out_of_scope target=$target count=$refused - $refused URL(s) in the inventory are not authorised by config/scope.conf and were not requested (${_HTTP_GATE_REASON:-declined by the scope gate})."
  fi
  if (( unreachable > 0 )); then
    run_record coverage_reduction "module=dast reason=leakage_endpoint_unreachable target=$target count=$unreachable - $unreachable URL(s) returned no readable response, so they were not inspected."
  fi
  if (( nobody > 0 )); then
    run_record coverage_reduction "module=dast reason=leakage_response_had_no_body target=$target count=$nobody - $nobody response(s) carried no readable body, so only the header-based family (DAST-LEAK-PROXY_HEADER-01) was evaluated against them."
  fi
  if (( truncated > 0 )); then
    run_record coverage_gap "dast leakage: $truncated response body(ies) on target '$target' were larger than this phase reads (caps: $_LEAK_MAX_BODY_BYTES bytes, $_LEAK_MAX_BODY_LINES lines) and were inspected only up to that bound. A disclosure past it was NOT looked for."
  fi

  # THE FAMILY-APPLICABILITY RECORD, WHICH IS THIS TICKET'S OWN ACCEPTANCE
  # CRITERION AND THE MOST IMPORTANT LINE HERE.  A run that fetched only JSON
  # tested nothing about served JavaScript or about third-party origins, and
  # letting those families report nothing without saying so is exactly the
  # unevaluated-reads-as-clean failure docs/DESIGN.md §15 forbids.
  local uncovered='' c2
  for c2 in "${_LEAK_CHECK_IDS[@]+"${_LEAK_CHECK_IDS[@]}"}"; do
    (( ${_LKF_EVAL[$c2]:-0} > 0 )) || uncovered+="${uncovered:+ }$c2"
  done
  if [[ -n $uncovered ]]; then
    run_record coverage_reduction "module=dast reason=leakage_family_not_applicable target=$target checks=[$uncovered] tested=$tested - none of the $tested response(s) inspected was one these families apply to (the stack-trace and email families need a textual body; the client-config family needs HTML, JavaScript or JSON; the third-party-origin family needs a document or a script), or the check was deselected by the profile/intensity filter. They are NOT covered on this target and their silence here is the absence of a test."
  fi

  log_info "dast leakage: target '$target' - inspected $tested of $_LEAK_N selected endpoint(s) for information disclosure"
  return 0
}

# ---------------------------------------------------------------------------
# Emission of all five families
# ---------------------------------------------------------------------------
_leak_emit_all() {
  local tested=$1
  local sep=$'\x1f'
  local row url path kind hit n

  # -- Family 1: one finding per PATH that carried a trace ----------------
  for row in "${_LEAK_TRACE_ROWS[@]+"${_LEAK_TRACE_ROWS[@]}"}"; do
    IFS=$sep read -r url path kind hit <<<"$row"
    _leak_emit DAST-LEAK-STACK_TRACE-01 "$url" "$path" \
      "GET $path returned a response body carrying a structured $kind stack frame or debugger banner: \"$hit\". A frame names a source file and a line number on the server's own disk, which discloses the framework, its version, the deployment layout and often the absolute installation path - none of which a handled error page carries. This check requires that structure precisely so that a branded error page is not reported as a trace."
  done

  # -- Family 4: one finding per PATH, listing every key found there ------
  local -A js_by_path=() js_url=() js_count=()
  local key why shape len where order='' p
  for row in "${_LEAK_JS_ROWS[@]+"${_LEAK_JS_ROWS[@]}"}"; do
    IFS=$sep read -r url path key why shape len where <<<"$row"
    if [[ -z ${js_by_path[$path]:-} ]]; then
      js_url[$path]=$url
      js_count[$path]=0
      order+="${order:+$sep}$path"
    fi
    js_by_path[$path]="${js_by_path[$path]:-}${js_by_path[$path]:+; }'$key' - $why $shape (value length ${len})"
    js_count[$path]=$(( js_count[$path] + 1 ))
  done
  if [[ -n $order ]]; then
    local IFS=$sep
    # shellcheck disable=SC2206  # deliberate split on the US separator
    local -a paths=($order)
    unset IFS
    for p in "${paths[@]+"${paths[@]}"}"; do
      local pub=''
      (( _LEAK_JSCFG_PUBLIC > 0 )) \
        && pub=" A further $_LEAK_JSCFG_PUBLIC value(s) across the responses inspected matched a public-by-design key name or value prefix (a publishable key, an OAuth client id, an analytics id) and are deliberately NOT reported."
      _leak_emit DAST-LEAK-JS_CONFIG-01 "${js_url[$p]}" "$p" \
        "GET $p served ${js_count[$p]} configuration value(s) that a browser has no legitimate use for: ${js_by_path[$p]}. THE VALUES ARE NOT REPRODUCED HERE - a finding that quotes a credential copies it into this report, this run's shard file and the operator's terminal - so the key name, the matched shape and the value's length are given instead, which is enough to locate it in the served bytes and not enough to use it.$pub"
    done
  fi

  # -- Family 3: one roll-up per target -----------------------------------
  if (( ${_LKF_EVAL[DAST-LEAK-EMAIL-01]:-0} > 0 )); then
    leak_emails_finish
    if (( ${#_LEAK_EMAILS[@]} > 0 )); then
      local list='' a shown=0
      for a in "${_LEAK_EMAILS[@]+"${_LEAK_EMAILS[@]}"}"; do
        if (( shown >= 20 )); then
          list+=", and $(( ${#_LEAK_EMAILS[@]} - shown )) more"
          break
        fi
        list+="${list:+, }$a"
        shown=$(( shown + 1 ))
      done
      local pubnote=''
      (( ${_LEAK_EMAILS_PUBLISHED:-0} > 0 )) \
        && pubnote=" A further ${_LEAK_EMAILS_PUBLISHED} address(es) are published by the site as \`mailto:\` links and are deliberately NOT reported: publishing a contact address is intentional, and reporting it would bury the ones that are not."
      local first=${_LEAK_EMAILS[0]}
      local wpath=${_LEAK_EMAIL_WHERE[$first]:-${_LEAK_PATH[0]}}
      _leak_emit DAST-LEAK-EMAIL-01 "${_LEAK_URL[0]}" "$wpath" \
        "${#_LEAK_EMAILS[@]} email address(es) appear in the bytes served to an unauthenticated client outside any published contact link, across the $tested response(s) inspected: $list. Role aliases (info@, support@, security@ and their RFC 2142 siblings), placeholder localparts and file-like domains such as an \`img@2x.png\` srcset entry are excluded by construction.$pubnote"
    fi
  fi

  # -- Family 2: one finding per target, with the count -------------------
  if (( ${_LKF_HIT[DAST-LEAK-PROXY_HEADER-01]:-0} > 0 )); then
    _leak_emit DAST-LEAK-PROXY_HEADER-01 \
      "${_LKF_URL[DAST-LEAK-PROXY_HEADER-01]}" "${_LKF_PATH[DAST-LEAK-PROXY_HEADER-01]}" \
      "on GET ${_LKF_PATH[DAST-LEAK-PROXY_HEADER-01]}, ${_LKF_DETAIL[DAST-LEAK-PROXY_HEADER-01]}. Observed on ${_LKF_HIT[DAST-LEAK-PROXY_HEADER-01]} of the ${_LKF_EVAL[DAST-LEAK-PROXY_HEADER-01]} response(s) this check applied to. Only an unroutable address or a reserved-internal DNS suffix is reported: a public CDN's edge POP code and a proxy product name are carried by the same headers and are not infrastructure disclosure."
  fi

  # -- Family 5: one INFORMATIONAL roll-up per target ----------------------
  if (( ${_LKF_EVAL[DAST-LEAK-THIRD_PARTY_ORIGIN-01]:-0} > 0 )) && (( ${#_LEAK_ORIGINS[@]} > 0 )); then
    local olist='' o oshown=0 sorted=()
    while IFS= read -r o; do
      [[ -n $o ]] || continue
      sorted+=("$o")
    done < <(printf '%s\n' "${_LEAK_ORIGINS[@]+"${_LEAK_ORIGINS[@]}"}" | LC_ALL=C sort -u)
    for o in "${sorted[@]+"${sorted[@]}"}"; do
      if (( oshown >= _LEAK_MAX_ORIGINS_REPORTED )); then
        olist+=", and $(( ${#sorted[@]} - oshown )) more"
        break
      fi
      olist+="${olist:+, }$o"
      oshown=$(( oshown + 1 ))
    done
    _leak_emit DAST-LEAK-THIRD_PARTY_ORIGIN-01 "${_LEAK_URL[0]}" "${_LEAK_PATH[0]}" \
      "${#sorted[@]} distinct third-party origin(s) are referenced by the ${_LKF_EVAL[DAST-LEAK-THIRD_PARTY_ORIGIN-01]} document/script response(s) inspected on this target: $olist. This is an INVENTORY, recorded at informational severity: each of these origins can execute script in this page's context, so this is the set of parties whose compromise is this application's compromise. Hosts sharing this target's own registrable domain were subtracted (${_LEAK_ORIGINS_SAMESITE} reference(s)); that subtraction approximates the registrable domain by the last two labels, with no Public Suffix List in this repository, so it errs toward under-reporting a third party rather than mislabelling a first-party host as one."
  fi
  return 0
}

_dast_leakage_phase
