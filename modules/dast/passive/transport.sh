#!/usr/bin/env bash
# modules/dast/passive/transport.sh - the TRANSPORT-EXPOSURE phase
# (docs/DESIGN.md §7.4's `transport.sh` bullet; docs/STEP5-DAST-PLAN.md
# DAST-30).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice -
# and every array it declares uses `declare -g`.  The pure, testable half is
# modules/dast/passive/transport_engine.sh; this file is the orchestration:
# choose what to request, ask through the ONE chokepoint, decide, and emit.
#
# WHY THIS FILE IS AT `passive/` AND AT TIER `passive`, WHEN §7.4 IS AN ACTIVE
# SECTION.  `modules/dast/engine.sh`'s phase table carried this ticket's row as
# `transport.sh:active` from DAST-02 onward, transcribed from docs/DESIGN.md's
# own section HEADING (§7.4 is "Active - auth, API, and access-control
# checks").  That transcription is right for the section's other four scripts
# and wrong for this one, and the phase table's own header says what to do about
# it: "a later ticket whose checks legitimately carry a LOWER type tag than the
# tier its row declares here must change that row in the same change and say
# why, rather than leaving two gates that disagree".  This is that change, and
# this is the why:
#
#   1. NOTHING HERE MUTATES TARGET STATE, which is the whole of §7.1's admission
#      criterion.  Every request this phase sends is a plain GET to a URL that
#      is either the operator's own `base-url` or an endpoint some earlier phase
#      already fetched.  It submits no form, sends no payload, and never
#      re-sends a discovered POST.  §7.4's shared contract - "prove the weakness
#      with a signal" - is what makes its other four scripts active; this one
#      proves nothing by probing, it reads what the target already volunteers.
#   2. §7.4's OWN WORDING FOR THIS BULLET calls it a complement to "the TLS
#      passive check".  The grouping in §7.4 is topical (transport sits with
#      auth and API because it is the same review conversation), not a statement
#      about intensity.
#   3. AT `active` IT WOULD NEVER RUN.  `--intensity` defaults to `passive`
#      (scan.sh, `CHECKS_INTENSITY_DEFAULT`), and anything above it additionally
#      requires `--i-own-target`.  A plain `scan.sh dast --target <t>` would
#      therefore skip this phase entirely, so the two exposure classes it exists
#      to report would be invisible on the ordinary run - while costing an
#      operator who did affirm ownership nothing they had not already granted.
#
# The row is now `passive/transport.sh:passive`, the records in
# `passive/checks.rules` carry the matching `passive` type tag, and
# tests/suites/dast-transport.sh section E asserts both halves agree - which is
# tension 15's intersection rule: both gates must permit and neither can widen
# the other.
#
# SCOPE BOUNDARY WITH ITS THREE NEIGHBOURS is stated at length in
# transport_engine.sh's header and restated in passive/checks.rules; in one
# line: passive/tls.sh owns the CONNECTION, passive/headers.sh owns HSTS,
# passive/cookies.sh owns the `Secure` ATTRIBUTE, and this file owns what
# TRAVELS unencrypted and what an encrypted page LOADS unencrypted.
#
# ONE FINDING PER CHECK PER TARGET.  A transport misconfiguration is a property
# of a deployment, not of a page: a site that forgot its TLS redirect forgot it
# for every path, and one finding per endpoint reports the same single defect
# ten times and buries everything else.  Each check accumulates across the
# endpoints tested and emits ONCE, located at the FIRST endpoint (in
# `tr_endpoints_load`'s deterministic order, which puts the operator's own
# base-url first) that exhibited it, with the evidence stating how many of how
# many responses did.  The count is what keeps this honest: "1 of 10" and
# "10 of 10" are different facts about a target.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test".  No endpoint inventory and no base-url, an endpoint the
# scope gate declines, a response that never arrived, and - the case this
# ticket's own acceptance criteria name - a run that observed no HTTPS response
# at all, are each recorded as a coverage_gap or coverage_reduction the report
# renders, exactly as modules/dast/auth.sh, crawl.sh, passive/headers.sh and
# active/sqli.sh do for their own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes URL and markup syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/passive/transport_engine.sh
source "${BASH_SOURCE[0]%/*}/transport_engine.sh"

# ---------------------------------------------------------------------------
# The per-check accumulator
# ---------------------------------------------------------------------------
# `_TRF_EVAL[check]`   responses the check was APPLICABLE to.  A mixed-content
#                      check is not applicable to a plaintext response (there is
#                      no secure context to mix into); a plaintext check is not
#                      applicable to an HTTPS one.  This, not the number of
#                      requests, decides whether the check is reported in
#                      `checks_run` - a check that was never applicable was not
#                      covered, and saying otherwise is the overstated coverage
#                      docs/DESIGN.md §15 forbids.
# `_TRF_HIT[check]`    responses that exhibited the defect.
# `_TRF_URL/_PATH`     the FIRST such response, which becomes the location.
# `_TRF_DETAIL`        the first such response's own specifics, for evidence.
_tr_acc_reset() {
  declare -gA _TRF_EVAL=() _TRF_HIT=() _TRF_URL=() _TRF_PATH=() _TRF_DETAIL=()
}

_tr_eval() {
  local c=$1
  _TRF_EVAL[$c]=$(( ${_TRF_EVAL[$c]:-0} + 1 ))
}

# `_tr_hit CHECK URL PATH DETAIL` - records one exhibiting response.  The first
# one wins the location and the detail; later ones only advance the count.
_tr_hit() {
  local c=$1 url=$2 path=$3 detail=$4
  if [[ -z ${_TRF_HIT[$c]:-} ]]; then
    _TRF_HIT[$c]=1
    _TRF_URL[$c]=$url
    _TRF_PATH[$c]=$path
    _TRF_DETAIL[$c]=$detail
  else
    _TRF_HIT[$c]=$(( _TRF_HIT[$c] + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# The check catalog, in the shell
# ---------------------------------------------------------------------------
# modules/dast/passive/checks.rules is the REGISTRY - what tension 12 computes
# coverage over and tension 15's filter chain filters - and this table is what a
# finding actually carries.  They are two copies on purpose and for the reason
# passive/headers.sh and active/sqli.sh already record: `finding_set` is fed by
# the emitting script, not by the registry loader, and a phase that read its
# severity out of a records file at emit time would be a second consumer of that
# format for every module to keep in step.  Keep the two in sync when either
# changes; tests/suites/dast-transport.sh asserts they agree on every id.
#
# FIVE IDS RATHER THAN ONE, FOR THE REASON THE DAST LOCATION PROFILE FORCES.
# That profile is (target, method, path_template, param_location, param_name)
# and carries NO component naming the defect, so a single
# `DAST-TRANSPORT-EXPOSURE-01` would make a plaintext login page and a mixed
# script reference on the same path collide on one fingerprint and dedupe to one
# finding.  They are also five different conversations with an operator, with
# five different fixes, and browsers treat three of them differently from each
# other - blockable mixed content is refused outright, optionally-blockable is
# loaded with a downgraded lock icon, and a mixed form action gets its own
# interstitial.
_tr_catalog() {
  _TRC_TITLE='' _TRC_SEV='' _TRC_CONF='' _TRC_CWE='' _TRC_OWASP='' _TRC_REM=''
  case $1 in
    DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01)
      _TRC_TITLE='Sensitive content is served over plaintext HTTP'
      _TRC_SEV=high; _TRC_CONF=high; _TRC_CWE=CWE-319; _TRC_OWASP=A02:2021
      _TRC_REM='Serve this content over HTTPS only. Redirect the plaintext origin to https:// with a 301 before any body is written, then add "Strict-Transport-Security: max-age=31536000; includeSubDomains" so a browser that has visited once never attempts plaintext again. A redirect alone does not undo this exposure: the first request, and anything it carried, was already on the wire in the clear, so any credential or session token observed here must be treated as compromised and rotated.' ;;
    DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)
      _TRC_TITLE='Plaintext HTTP endpoint does not redirect to HTTPS'
      _TRC_SEV=medium; _TRC_CONF=high; _TRC_CWE=CWE-319; _TRC_OWASP=A02:2021
      _TRC_REM='Answer the plaintext origin with a 301 to the identical https:// URL and nothing else - no body, no cookie, no content negotiation. Serving real content on port 80 means every visitor who types the bare hostname is served over an unauthenticated channel that any network position can rewrite. Follow the redirect with an HSTS header on the HTTPS response so the second visit never touches port 80 at all.' ;;
    DAST-TRANSPORT-MIXED_ACTIVE-01)
      _TRC_TITLE='HTTPS document loads active sub-resources over plaintext HTTP'
      _TRC_SEV=high; _TRC_CONF=high; _TRC_CWE=CWE-311; _TRC_OWASP=A02:2021
      _TRC_REM='Change these references to https:// (or to a protocol-relative or root-relative form, both of which inherit the document scheme). Active mixed content - script, stylesheet, iframe, object, embed - executes inside the origin, so a network attacker who rewrites one of them owns the page regardless of how good the TLS on the document itself is. Every current browser blocks these outright, so the affected feature is already broken for real users, not merely insecure. A "Content-Security-Policy: upgrade-insecure-requests" header is a migration aid, not a fix, because it protects only browsers that honour it.' ;;
    DAST-TRANSPORT-MIXED_PASSIVE-01)
      _TRC_TITLE='HTTPS document loads passive sub-resources over plaintext HTTP'
      _TRC_SEV=low; _TRC_CONF=high; _TRC_CWE=CWE-311; _TRC_OWASP=A02:2021
      _TRC_REM='Change these references to https:// or to a scheme-relative form. Passive mixed content - images, audio, video, track files - is still loaded by browsers rather than blocked, which is why it is reported separately and at a lower severity than the active kind: nothing executes, but the resource is unauthenticated so its bytes can be replaced in transit, the request leaks the referring page to any observer, and the browser withholds the secure padlock from the whole document.' ;;
    DAST-TRANSPORT-MIXED_FORM-01)
      _TRC_TITLE='HTTPS document submits a form to a plaintext HTTP action'
      _TRC_SEV=high; _TRC_CONF=high; _TRC_CWE=CWE-319; _TRC_OWASP=A02:2021
      _TRC_REM='Point the form action at the https:// URL. A secure page carrying an insecure form action is worse than an insecure page: the padlock tells the user their input is protected while the submission itself - every field, including any password or payment detail - is sent in the clear and can be read or altered by any network position. Browsers show a separate interstitial for exactly this reason. Fix the action rather than relying on a server-side redirect, which happens only after the plaintext request has already been sent.' ;;
    *) return 1 ;;
  esac
  return 0
}

# Every id this phase can emit, in report order.
declare -ga _TR_CHECK_IDS=(
  DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01
  DAST-TRANSPORT-NO_HTTPS_REDIRECT-01
  DAST-TRANSPORT-MIXED_ACTIVE-01
  DAST-TRANSPORT-MIXED_PASSIVE-01
  DAST-TRANSPORT-MIXED_FORM-01
)

# The two ids that need a plaintext response to say anything, and the three that
# need an HTTPS one.  Kept as data because the applicability roll-up and the
# `checks_run` decision both read them, and two hand-written lists would drift.
declare -ga _TR_CHECKS_NEED_HTTP=(
  DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01
  DAST-TRANSPORT-NO_HTTPS_REDIRECT-01
)
declare -ga _TR_CHECKS_NEED_HTTPS=(
  DAST-TRANSPORT-MIXED_ACTIVE-01
  DAST-TRANSPORT-MIXED_PASSIVE-01
  DAST-TRANSPORT-MIXED_FORM-01
)

# ---------------------------------------------------------------------------
# tension-15 per-check selection
# ---------------------------------------------------------------------------
# scan.sh's filter chain records which ids survived
# --profile-scan/--intensity/--allow-intrusive and exports them as
# SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected` is the
# reader.  Consulted only if that function exists - it does not today, and
# passive/headers.sh and active/sqli.sh guard it the same way - so this file
# does not hard-depend on it: absent, everything the tier already permitted
# runs, which is the "empty means all selected" fallback a direct-engine test
# relies on.
_tr_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
# The DAST location profile is (target, method, path_template, param_location,
# param_name) (lib/findings.sh).  A transport finding names no parameter, so the
# last two are empty and the identity is (target, GET, path_template) plus the
# check id - which is exactly the "one finding per check per path" grain this
# phase wants, and is why the defect lives in the CHECK ID rather than in the
# evidence: two defects on one page would otherwise collide on one fingerprint
# and the merge would silently keep one.
_tr_emit() {
  local check=$1 url=$2 path=$3 evidence=$4
  local target=${SCOURSH_DAST_TARGET:-}
  _tr_catalog "$check" || return 0

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$_TRC_TITLE"
  finding_set base_severity "$_TRC_SEV"
  finding_set confidence "$_TRC_CONF"
  finding_set cwe "$_TRC_CWE"
  finding_set owasp "$_TRC_OWASP"
  finding_set exposure external
  finding_set auth "${_TR_AUTH_VALUE:-none}"
  # `sensitive_data` is the one field that differs per check rather than per
  # phase, and it is set from what the check MEANS rather than uniformly: the
  # plaintext-exposure check fires only when a credential, a session cookie or
  # authenticated content was observed in the clear, which is precisely what
  # this flag is for.  A mixed image reference is a real defect and is not
  # sensitive data, and marking it so would inflate every rubric that reads
  # this field.
  case $check in
    DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01 | DAST-TRANSPORT-MIXED_FORM-01)
      finding_set sensitive_data true ;;
    *) finding_set sensitive_data false ;;
  esac
  finding_set remediation "$_TRC_REM"
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
# Analysis of one PLAINTEXT (http://) response
# ---------------------------------------------------------------------------
# Reads the `_HDR_*` state `hdr_parse_capture` published plus the body file, and
# feeds the accumulator.  Sends nothing itself.
#
# THE TWO PLAINTEXT CHECKS ARE NOT THE SAME CHECK AT TWO SEVERITIES, AND THE
# SPLIT IS LOAD-BEARING.  `NO_HTTPS_REDIRECT` is about the TRANSPORT: this
# origin answers on port 80 with something other than a redirect to TLS, which
# is true of a plain marketing page and is a hardening gap.
# `PLAINTEXT_SENSITIVE` is about the CONTENT: a credential form, a session
# cookie, or authenticated data actually crossed the wire unencrypted, which is
# an exposure that has already happened.  Reporting the first as the second
# would make every plaintext site a high-severity data-exposure finding and
# drown the ones that really are; reporting the second as the first would
# understate a leaked session.  The suite pins both directions with two
# plaintext pages that differ only in their content.
_tr_analyse_plaintext() {
  local url=$1 path=$2 bodyfile=$3 status=$4 location=$5

  # -- No redirect to TLS -------------------------------------------------
  if _tr_selected DAST-TRANSPORT-NO_HTTPS_REDIRECT-01; then
    _tr_eval DAST-TRANSPORT-NO_HTTPS_REDIRECT-01
    tr_redirect_verdict "$status" "$location"
    local why=''
    case $_TR_REDIR_VERDICT in
      to_https) : ;;  # correct, and the only non-finding case
      none)
        why="the plaintext endpoint answered $status with content rather than redirecting to https://" ;;
      to_http)
        why="the plaintext endpoint answered $status but redirects to another http:// URL ($(hdr_safe_text "$location" 120)), so the visitor is still on an unencrypted channel afterwards" ;;
      relative)
        why="the plaintext endpoint answered $status with a scheme-relative or path-only Location ($(hdr_safe_text "$location" 120)), which a browser resolves against the CURRENT scheme - so it redirects from http:// to http://" ;;
      unknown)
        why="the plaintext endpoint answered $status with no Location header at all, so no redirect happens and the browser is left on the unencrypted origin" ;;
    esac
    [[ -n $why ]] && _tr_hit DAST-TRANSPORT-NO_HTTPS_REDIRECT-01 "$url" "$path" "$why"
  fi

  # -- Sensitive content in the clear -------------------------------------
  if _tr_selected DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01; then
    _tr_eval DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01
    declare -g _TR_SENS_REASONS='' _TR_SENS_PW=0
    # Body-derived: a password control on the page.  A 3xx has no meaningful
    # body, so this only ever fires on a response that actually served content.
    tr_sensitivity_scan "$bodyfile" || true
    # Header-derived: a cookie issued over the clear channel.  This is NOT
    # DAST-COOKIE-NO_SECURE-01 and the evidence says so - that check asks
    # whether the ATTRIBUTE would let a browser send the cookie in the clear;
    # this one records that the server already did, which no attribute can undo.
    if hdr_present set-cookie; then
      local ncookie=${_HDR_COUNT[set-cookie]:-1}
      tr_add_reason "the server issued $ncookie Set-Cookie header(s) on this unencrypted response, so the cookie value was observable in transit before any Secure attribute on it could matter (the attribute itself is DAST-COOKIE-NO_SECURE-01's subject, not this finding's)"
    fi
    # Session-derived: the run held an authenticated session, so whatever came
    # back is authenticated content that travelled in the clear.
    if [[ ${_TR_AUTH_VALUE:-none} != none ]]; then
      tr_add_reason "this request carried the run's authenticated session, so the response is authenticated content delivered over an unencrypted channel"
    fi
    if [[ -n ${_TR_SENS_REASONS:-} ]]; then
      _tr_hit DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01 "$url" "$path" "$(tr_reasons_sentence)"
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Analysis of one HTTPS response
# ---------------------------------------------------------------------------
# Mixed content is a property of a DOCUMENT: a browser only mixes when it is
# parsing markup into a secure context, so a JSON API response over HTTPS
# neither loads sub-resources nor has a lock icon to downgrade.  The three
# checks are therefore not applicable to a non-document response, and
# `hdr_is_document` (passive/headers.sh's own gate, reused rather than
# re-decided) is what says so.  Recording them as applicable to a JSON endpoint
# would report the whole family as covered on an API-only target that was never
# tested for it.
_tr_analyse_https() {
  local url=$1 path=$2 bodyfile=$3
  local ctype=''
  hdr_first content-type; ctype=$_HDR_V
  hdr_is_document "$ctype" || return 0

  tr_mixed_scan "$bodyfile" "$url" || return 0

  local cls check n
  for cls in active passive form; do
    case $cls in
      active) check=DAST-TRANSPORT-MIXED_ACTIVE-01 ;;
      passive) check=DAST-TRANSPORT-MIXED_PASSIVE-01 ;;
      form) check=DAST-TRANSPORT-MIXED_FORM-01 ;;
    esac
    _tr_selected "$check" || continue
    _tr_eval "$check"
    n=${_TR_MIX_N[$cls]:-0}
    (( n > 0 )) || continue
    local shown=$n extra=''
    if (( n > _TR_MAX_EVIDENCE_REFS )); then
      shown=$_TR_MAX_EVIDENCE_REFS
      extra=" (the first $shown of $n are named; the rest are the same defect on this page)"
    fi
    local viabase=''
    [[ -n ${_TR_BASE_HREF:-} ]] && viabase=" The document sets <base href=\"$(hdr_safe_text "$_TR_BASE_HREF" 120)\">, which retargets every RELATIVE reference on the page, so the fix is likely that one element rather than each reference individually."
    _tr_hit "$check" "$url" "$path" \
      "the https:// document references $n plaintext http:// resource(s) via ${_TR_MIX_TAGS[$cls]:-an element}: $(tr_mix_refs_sentence "$cls")$extra.$viabase"
  done
  return 0
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_transport_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/transport.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE, AND
  # THAT IS NOT BELT-AND-BRACES.  modules/dast/run.sh reads the inventory and
  # exports SCOURSH_DAST_ENDPOINTS BEFORE the phase loop starts, so on a first
  # run - the ordinary case - it is EMPTY, because crawl.sh writes
  # reports/<run>/inventory/endpoints.json a few phases later in the same loop.
  # A check that trusted the export alone would therefore see no endpoints on
  # exactly the run that has just discovered them.  The run directory's own
  # artifact is the authority (docs/INVENTORY-FORMAT.md §1), so it is consulted
  # when the export is empty.  Fixing the export itself belongs to
  # modules/dast/run.sh and is DAST-05's already-filed follow-up, not this
  # ticket's to change under its peers.
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

  _tr_acc_reset
  # An authenticated run marks its findings so the report can say the exposure
  # was of authenticated content.  `dast_auth_state` is DAST-03's and is guarded
  # exactly as passive/headers.sh guards it: absent, the run is unauthenticated
  # and `none` is the truth rather than a fallback.
  _TR_AUTH_VALUE=none
  if declare -F dast_auth_state >/dev/null; then
    [[ $(dast_auth_state 2>/dev/null || printf 'failed') == ok ]] && _TR_AUTH_VALUE=session
  fi

  tr_endpoints_load "$epf" "$target" "$base"
  if (( _TR_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_to_inspect target=$target - neither an endpoint inventory (docs/INVENTORY-FORMAT.md) nor a base-url in config/scope.conf gave this phase a URL to request, so no transport exposure was inspected."
    run_record coverage_gap "dast transport: target '$target' offered no URL to request, so NO plaintext-exposure or mixed-content check ran. This is a coverage gap - nothing was tested - not a finding that the target's transport is sound."
    return 0
  fi

  local i url path scheme tested=0 refused=0 unreachable=0
  # The gate's reason is captured AT REFUSAL TIME, never read after the loop.
  # `http_gate_url` clears `_HTTP_GATE_REASON` at entry on every call
  # (lib/http.sh), so by the time the loop ends it holds whatever the LAST call
  # left - empty after a success, which is the ordinary case, so the roll-up
  # would silently degrade to its generic fallback.  With more than one refusal
  # it would also attribute one URL's reason to all of them.  Distinct reasons
  # are collected and reported together.
  local refused_reasons=''
  declare -A _tr_reason_seen=()
  local http_seen=0 https_seen=0 https_doc_seen=0 nav_plaintext_total=0
  for (( i = 0; i < _TR_N; i++ )); do
    url=${_TR_URL[$i]}
    path=${_TR_PATH[$i]}
    scheme=$(tr_url_scheme "$url")

    # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - the identical
    # split modules/dast/crawl.sh's `_crawl_in_scope` records and
    # passive/headers.sh already mirrors.  `http_request` gates FATALLY (an
    # out-of-scope URL there is a caller bug, exit 3), which is right for the
    # operator's own base-url and exactly wrong for a URL lifted out of an
    # inventory some other module wrote: one bad row would abort the whole run.
    # This decides only whether the URL is worth ASKING FOR; everything that
    # survives still goes through http_request, which re-gates it and re-gates
    # every redirect hop.
    if ! http_gate_url "$url" "$target"; then
      refused=$(( refused + 1 ))
      local why_gate=${_HTTP_GATE_REASON:-declined by the scope gate}
      if [[ -z ${_tr_reason_seen[$why_gate]:-} ]]; then
        _tr_reason_seen[$why_gate]=1
        refused_reasons+="${refused_reasons:+; }$(hdr_safe_text "$why_gate" 120)"
      fi
      continue
    fi

    local bodyfile=$SCOURSH_SCRATCH/dast-transport.$$.$i.body
    local hdrfile=$SCOURSH_SCRATCH/dast-transport.$$.$i.hdr

    # THE REDIRECT BUDGET DIFFERS BY SCHEME, AND THAT IS THE MECHANISM RATHER
    # THAN AN INCONSISTENCY.  A plaintext URL is requested with ZERO hops
    # because the FIRST response is the whole question: `http_request` follows
    # redirects internally and reports the final status, so a target that
    # correctly 301s to HTTPS and one that serves the page on port 80 both come
    # back `200` and the two facts become one string (see
    # `tr_redirect_verdict`'s header).  An HTTPS URL is requested normally,
    # because there the question is what the DELIVERED document loads, and
    # stopping at a redirect would read the wrong body.
    local hops=0
    [[ $scheme == https ]] && hops=${SCOURSH_MAX_REDIRECTS:-5}

    # The capture is set immediately before the call because `http_request`
    # consumes and clears the per-request context at entry, so it can never ride
    # along on a later request (lib/http.sh §9a).
    http_request_capture "$bodyfile" "$hdrfile"
    if ! http_request GET "$url" "$hops" "$target"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$bodyfile" "$hdrfile"
      continue
    fi
    if ! tr_read_capture "$hdrfile"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$bodyfile" "$hdrfile"
      continue
    fi
    tested=$(( tested + 1 ))

    if [[ $scheme == https ]]; then
      https_seen=$(( https_seen + 1 ))
      local ct=''
      hdr_first content-type; ct=$_HDR_V
      if hdr_is_document "$ct"; then
        https_doc_seen=$(( https_doc_seen + 1 ))
      fi
      # ALWAYS ZEROED BEFORE THE CALL, never merely read after it.
      # `_TR_NAV_PLAINTEXT` is a global that `tr_mixed_scan` resets - but
      # `_tr_analyse_https` returns EARLY, before calling it, for a non-document
      # response.  Reading the global after such a response therefore adds the
      # PREVIOUS document's count a second time, so a run that fetched one page
      # with two plaintext links and then any JSON endpoint would report four.
      # This is the same stale-shared-state class of bug that the reset inside
      # `hdr_parse_capture` exists to prevent one level down, and it is pinned
      # by a test that fails without this line.
      _TR_NAV_PLAINTEXT=0
      _tr_analyse_https "$url" "$path" "$bodyfile"
      nav_plaintext_total=$(( nav_plaintext_total + ${_TR_NAV_PLAINTEXT:-0} ))
    else
      http_seen=$(( http_seen + 1 ))
      _tr_analyse_plaintext "$url" "$path" "$bodyfile" "$_TR_STATUS" "$_TR_LOCATION"
    fi
    rm -f "$bodyfile" "$hdrfile"
  done

  if (( tested == 0 )); then
    run_record coverage_gap "dast transport: none of the $_TR_N URL(s) selected on target '$target' produced a response this phase could read ($refused declined by the scope gate, $unreachable did not answer), so NO plaintext-exposure or mixed-content check ran. A clean result here is the absence of a test."
    return 0
  fi

  # Emit: one finding per check that fired, located at the first response that
  # exhibited it, with the affected/tested count in the evidence.
  local c
  for c in "${_TR_CHECK_IDS[@]+"${_TR_CHECK_IDS[@]}"}"; do
    (( ${_TRF_HIT[$c]:-0} > 0 )) || continue
    _tr_emit "$c" "${_TRF_URL[$c]}" "${_TRF_PATH[$c]}" \
      "on GET ${_TRF_PATH[$c]}, ${_TRF_DETAIL[$c]}. Observed on ${_TRF_HIT[$c]} of the ${_TRF_EVAL[$c]:-$tested} response(s) this check applied to (of $tested fetched on target '$target')."
  done

  # checks_run is the set of checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), and it is the honest input modules/dast/run.sh's coverage
  # roll-up reads.  A check is recorded only when at least one response it was
  # APPLICABLE to was actually inspected - a mixed-content check over a run that
  # only ever saw plaintext covered nothing, and saying otherwise would report
  # an untested control as tested.
  for c in "${_TR_CHECK_IDS[@]+"${_TR_CHECK_IDS[@]}"}"; do
    (( ${_TRF_EVAL[$c]:-0} > 0 )) && run_record checks_run "$c"
  done

  # -- Every bound and every gap, named ------------------------------------
  # docs/DESIGN.md §15: a bound that truncates silently is indistinguishable
  # from a surface that was really that small.
  if (( _TR_TRUNCATED > 0 )); then
    run_record coverage_gap "dast transport: target '$target' offered more distinct (scheme, path) endpoints than this phase requests - $_TR_TRUNCATED were NOT fetched (cap $_TR_MAX_ENDPOINTS). Their transport was not inspected and their absence from this report is a coverage bound, not a clean result."
  fi
  if (( _TR_SKIPPED_NON_GET > 0 )); then
    run_record coverage_reduction "module=dast reason=transport_non_get_endpoint_skipped target=$target count=$_TR_SKIPPED_NON_GET - $_TR_SKIPPED_NON_GET discovered endpoint(s) are not GET. Re-sending them to read their transport would change target state, which docs/DESIGN.md §7.1 forbids at the passive tier, so they were not inspected."
  fi
  if (( refused > 0 )); then
    run_record coverage_reduction "module=dast reason=transport_endpoint_out_of_scope target=$target count=$refused - $refused URL(s) in the inventory are not authorised by config/scope.conf and were not requested (${refused_reasons:-declined by the scope gate})."
  fi
  if (( unreachable > 0 )); then
    run_record coverage_reduction "module=dast reason=transport_endpoint_unreachable target=$target count=$unreachable - $unreachable URL(s) returned no readable response, so their transport was not inspected."
  fi
  # A plaintext navigation link is a deliberate NON-finding (see
  # tr_html_scan's header: it is not mixed content in any browser).  It is
  # counted and stated anyway, because an operator who can see the http:// link
  # in their own markup is entitled to know this phase looked at it and decided,
  # rather than being left to wonder whether it was missed.
  if (( nav_plaintext_total > 0 )); then
    run_record notes "module=dast phase=transport target=$target plaintext_navigation_links=$nav_plaintext_total reason=not_mixed_content - these are <a>/<area> hyperlinks to http:// destinations. A hyperlink loads nothing into the secure document, so no browser treats it as mixed content and it is deliberately NOT reported as such."
  fi

  # -- Applicability, which is this ticket's own acceptance criterion -------
  # "Nothing was mixed" and "nothing was testable" are different facts and must
  # never render as the same clean result.  A run that saw no HTTPS response at
  # all could not evaluate a single mixed-content check; a run that saw no
  # plaintext response could not evaluate either plaintext check.  Both are
  # recorded, under one reason, naming the ids that are NOT covered on this
  # target.  A silent pass here is precisely the overstated coverage
  # docs/DESIGN.md §15 forbids.
  local uncovered='' c2
  for c2 in "${_TR_CHECK_IDS[@]+"${_TR_CHECK_IDS[@]}"}"; do
    (( ${_TRF_EVAL[$c2]:-0} > 0 )) || uncovered+="${uncovered:+ }$c2"
  done
  if [[ -n $uncovered ]]; then
    local why=''
    (( https_seen == 0 )) \
      && why+=' No https:// response was observed on this target at all, so no mixed-content check had a secure document to evaluate.'
    (( https_seen > 0 && https_doc_seen == 0 )) \
      && why+=' Every https:// response observed was a non-document (an API or asset response), which loads no sub-resources, so no mixed-content check was applicable.'
    (( http_seen == 0 )) \
      && why+=' No http:// response was observed on this target at all, so neither plaintext check had an unencrypted response to evaluate.'
    run_record coverage_reduction "module=dast reason=transport_check_not_applicable target=$target checks=[$uncovered] https_responses=$https_seen https_documents=$https_doc_seen http_responses=$http_seen -$why These checks are NOT covered on this target: their silence is the absence of a test, not a clean result."
  fi

  log_info "dast transport: target '$target' - inspected $tested of $_TR_N selected endpoint(s) ($https_seen https, $http_seen http) for transport exposure"
  return 0
}

_dast_transport_phase
