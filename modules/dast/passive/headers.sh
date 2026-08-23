#!/usr/bin/env bash
# modules/dast/passive/headers.sh - the §7.1 SECURITY-HEADER phase
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-05, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs on every dast run), so it
# inherits the whole run context and anything it emits lands in this process's
# shard.  Per that function's contract it carries NO sourced-once guard - one run
# can legitimately reach the same phase twice - and every array it declares uses
# `declare -g`.  The pure, testable half is
# modules/dast/passive/headers_engine.sh; this file is the orchestration: choose
# what to request, ask through the ONE chokepoint, decide, and emit.
#
# PASSIVE, RESTATED (docs/DESIGN.md §7.1 "No mutation of state").  Every request
# this phase sends is a plain GET to a URL that is either the operator's own
# `base-url` or an endpoint some earlier phase already fetched.  It sends no
# payload, sets no cookie, submits no form, and touches no discovered POST -
# re-sending one to read its response headers would be a state change wearing a
# passive check's name.  Non-GET endpoints are counted and declared, never
# silently dropped.
#
# ONE FINDING PER CHECK PER TARGET, AND THAT IS A DELIBERATE CHOICE.  A security
# header is configured once for an application and observed once per response,
# so the naive shape - one finding per endpoint - reports the same single
# misconfiguration ten times and buries everything else in the report.  Instead
# each check accumulates across the endpoints tested and emits ONE finding,
# located at the FIRST endpoint (in `hdr_endpoints_load`'s deterministic order,
# which puts the operator's own base-url first) that exhibited it, with the
# evidence stating how many of how many responses did.  The count is what keeps
# this honest: "1 of 10" and "10 of 10" are different facts about a target and
# the reader gets to see which one it is.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test".  No endpoint inventory and no base-url, an endpoint the scope
# gate declines, a response that never arrived, a check that no tested response
# was applicable to, and a missing recommended-headers list are each recorded as
# a coverage_gap or coverage_reduction the report renders - exactly as
# modules/dast/auth.sh, crawl.sh and active/sqli.sh do for their own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes header and CSP syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/passive/headers_engine.sh
source "${BASH_SOURCE[0]%/*}/headers_engine.sh"

# ---------------------------------------------------------------------------
# The per-check accumulator
# ---------------------------------------------------------------------------
# `_HDRF_EVAL[check]`   responses the check was APPLICABLE to (an HSTS check is
#                       not applicable to a plaintext response, a CSP-absence
#                       check is not applicable to a JSON one).  This, not the
#                       number of requests, is what decides whether the check
#                       is reported in `checks_run` - a check that was never
#                       applicable was not covered, and saying otherwise is the
#                       overstated coverage docs/DESIGN.md §15 forbids.
# `_HDRF_HIT[check]`    responses that exhibited the defect.
# `_HDRF_URL/_PATH`     the FIRST such response, which becomes the location.
# `_HDRF_DETAIL`        the first such response's own specifics, for evidence.
_hdr_acc_reset() {
  declare -gA _HDRF_EVAL=() _HDRF_HIT=() _HDRF_URL=() _HDRF_PATH=() _HDRF_DETAIL=()
}

_hdr_eval() {
  local c=$1
  _HDRF_EVAL[$c]=$(( ${_HDRF_EVAL[$c]:-0} + 1 ))
}

# `_hdr_hit CHECK URL PATH DETAIL` - records one exhibiting response.  The first
# one wins the location and the detail; later ones only advance the count.
_hdr_hit() {
  local c=$1 url=$2 path=$3 detail=$4
  if [[ -z ${_HDRF_HIT[$c]:-} ]]; then
    _HDRF_HIT[$c]=1
    _HDRF_URL[$c]=$url
    _HDRF_PATH[$c]=$path
    _HDRF_DETAIL[$c]=$detail
  else
    _HDRF_HIT[$c]=$(( _HDRF_HIT[$c] + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# The check catalog, in the shell
# ---------------------------------------------------------------------------
# modules/dast/passive/checks.rules is the REGISTRY - what tension 12 computes
# coverage over and tension 15's filter chain filters - and this table is what a
# finding actually carries.  They are two copies on purpose and for the same
# reason modules/dast/active/sqli.sh carries its own: `finding_set` is fed by the
# emitting script, not by the registry loader, and a phase that read its
# severity out of a records file at emit time would be a second consumer of that
# format for every module to keep in step.  Keep the two in sync when either
# changes; tests/suites/dast-headers.sh asserts they agree on every id.
#
# Sets `_HDRC_TITLE`, `_HDRC_SEV`, `_HDRC_CONF`, `_HDRC_CWE`, `_HDRC_OWASP` and
# `_HDRC_REM`.  Returns 1 for an id that is not this phase's.
_hdr_catalog() {
  _HDRC_TITLE='' _HDRC_SEV='' _HDRC_CONF='' _HDRC_CWE='' _HDRC_OWASP='' _HDRC_REM=''
  case $1 in
    DAST-HDR-CSP_MISSING-01)
      _HDRC_TITLE='No Content-Security-Policy on a document response'
      _HDRC_SEV=medium; _HDRC_CONF=high; _HDRC_CWE=CWE-1021; _HDRC_OWASP=A05:2021
      _HDRC_REM="Serve a Content-Security-Policy header on every document response. Start from a restrictive base such as \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\", then widen it one source at a time against a report-only deployment. A Content-Security-Policy-Report-Only header collects violations but enforces nothing, so it does not close this gap on its own." ;;
    DAST-HDR-CSP_UNSAFE-01)
      _HDRC_TITLE='Content-Security-Policy permits unsafe-inline or unsafe-eval for script'
      _HDRC_SEV=medium; _HDRC_CONF=high; _HDRC_CWE=CWE-79; _HDRC_OWASP=A03:2021
      _HDRC_REM="Remove 'unsafe-inline' and 'unsafe-eval' from the script fetch directive. Move inline event handlers and inline script blocks into files, or authorise the ones that must stay with a per-response nonce or a hash - a directive carrying a nonce or hash makes browsers ignore 'unsafe-inline' anyway, so the two are alternatives rather than complements. Replace eval, new Function and string-argument setTimeout so 'unsafe-eval' can go." ;;
    DAST-HDR-CSP_DATA_SOURCE-01)
      _HDRC_TITLE='Content-Security-Policy allows a data: source for script or object content'
      _HDRC_SEV=medium; _HDRC_CONF=medium; _HDRC_CWE=CWE-79; _HDRC_OWASP=A03:2021
      _HDRC_REM='Drop data: from script-src, object-src and any default-src that governs them. A data: URI is attacker-authorable in full, so allowing it as a script source restores the arbitrary script execution that the rest of the policy exists to prevent. Where inline data really is needed, keep it to img-src or font-src, which this check does not flag.' ;;
    DAST-HDR-CSP_WILDCARD-01)
      _HDRC_TITLE='Content-Security-Policy allows a wildcard host for active content'
      _HDRC_SEV=medium; _HDRC_CONF=medium; _HDRC_CWE=CWE-942; _HDRC_OWASP=A05:2021
      _HDRC_REM='Replace the wildcard host with the specific origins the page actually loads from. A bare * allows any origin on the internet; a *.example wildcard allows every subdomain, including any one an attacker can get control of through a dangling DNS record or a shared hosting tenant.' ;;
    DAST-HDR-HSTS_MISSING-01)
      _HDRC_TITLE='No Strict-Transport-Security header on an HTTPS response'
      _HDRC_SEV=medium; _HDRC_CONF=high; _HDRC_CWE=CWE-319; _HDRC_OWASP=A02:2021
      _HDRC_REM='Send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on every HTTPS response. Without it, a user first request of a session - or any request after the pin expires - can be downgraded to plaintext and intercepted before the redirect to HTTPS is ever seen. Confirm every subdomain is HTTPS-ready before adding includeSubDomains.' ;;
    DAST-HDR-HSTS_WEAK-01)
      _HDRC_TITLE='Strict-Transport-Security max-age is too short to be protective'
      _HDRC_SEV=low; _HDRC_CONF=high; _HDRC_CWE=CWE-319; _HDRC_OWASP=A02:2021
      _HDRC_REM='Raise max-age to at least 31536000 (one year), the floor the preload list requires. A short max-age narrows the window in which a browser refuses plaintext to a few days or hours, and max-age=0 actively clears an existing pin - which is a rollback switch, not a policy. Ramp up gradually if the site is still being migrated, then leave it at a year.' ;;
    DAST-HDR-HSTS_MALFORMED-01)
      _HDRC_TITLE='Strict-Transport-Security header is present but unusable'
      _HDRC_SEV=medium; _HDRC_CONF=high; _HDRC_CWE=CWE-319; _HDRC_OWASP=A02:2021
      _HDRC_REM='Fix the header so it carries exactly one decimal max-age directive, for example "max-age=31536000; includeSubDomains". RFC 6797 makes max-age required and tells the browser to ignore the whole header without it, so a malformed value gives the same protection as sending nothing while looking in a configuration review as though the control is in place.' ;;
    DAST-HDR-CLICKJACKING-01)
      _HDRC_TITLE='Document response has no framing protection'
      _HDRC_SEV=medium; _HDRC_CONF=high; _HDRC_CWE=CWE-1021; _HDRC_OWASP=A05:2021
      _HDRC_REM="Add \"Content-Security-Policy: frame-ancestors 'none'\" (or a list of the origins genuinely allowed to frame the page) and keep \"X-Frame-Options: DENY\" alongside it for older browsers. ALLOW-FROM is obsolete and is honoured by no current browser, so a policy that relies on it is not enforced anywhere." ;;
    DAST-HDR-NOSNIFF_MISSING-01)
      _HDRC_TITLE='No X-Content-Type-Options nosniff on the response'
      _HDRC_SEV=low; _HDRC_CONF=high; _HDRC_CWE=CWE-430; _HDRC_OWASP=A05:2021
      _HDRC_REM='Send "X-Content-Type-Options: nosniff" on every response. Without it a browser may ignore the declared Content-Type and execute a user-uploaded or user-influenced file as script or stylesheet on the basis of its bytes, which turns an upload feature into a cross-site scripting vector.' ;;
    DAST-HDR-REFERRER_LEAKY-01)
      _HDRC_TITLE='Referrer-Policy sends the full URL to cross-origin destinations'
      _HDRC_SEV=low; _HDRC_CONF=high; _HDRC_CWE=CWE-200; _HDRC_OWASP=A01:2021
      _HDRC_REM='Set "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer". Under unsafe-url or no-referrer-when-downgrade the whole URL - path, query string, and any password-reset or invitation token in it - is sent to every third-party host the page links to or loads a resource from.' ;;
    DAST-HDR-RECOMMENDED_MISSING-01)
      _HDRC_TITLE='Recommended security headers are not set'
      _HDRC_SEV=info; _HDRC_CONF=high; _HDRC_CWE=CWE-693; _HDRC_OWASP=A05:2021
      _HDRC_REM='Add the headers named in this finding evidence. Each is a defence in depth rather than the fix for a specific defect, which is why they are one finding and not several: Permissions-Policy withholds powerful browser features from the document and anything it embeds, the Cross-Origin-* trio isolates the page from cross-origin windows and embedders, and X-Permitted-Cross-Domain-Policies stops a legacy client honouring a crossdomain.xml this site may not know it serves. The list is data, in modules/dast/passive/recommended-headers.txt.' ;;
    *) return 1 ;;
  esac
  return 0
}

# Every id this phase can emit, in report order.
declare -ga _HDR_CHECK_IDS=(
  DAST-HDR-CSP_MISSING-01
  DAST-HDR-CSP_UNSAFE-01
  DAST-HDR-CSP_DATA_SOURCE-01
  DAST-HDR-CSP_WILDCARD-01
  DAST-HDR-HSTS_MISSING-01
  DAST-HDR-HSTS_WEAK-01
  DAST-HDR-HSTS_MALFORMED-01
  DAST-HDR-CLICKJACKING-01
  DAST-HDR-NOSNIFF_MISSING-01
  DAST-HDR-REFERRER_LEAKY-01
  DAST-HDR-RECOMMENDED_MISSING-01
)

# ---------------------------------------------------------------------------
# Analysis of one response
# ---------------------------------------------------------------------------
# Reads the `_HDR_*` state `hdr_parse_capture` published for one response and
# feeds the accumulator.  Sends nothing itself.
_hdr_analyse_one() {
  local url=$1 path=$2
  local ctype='' policy='' via='' v='' n=''

  hdr_first content-type; ctype=$_HDR_V
  local is_doc=0
  hdr_is_document "$ctype" && is_doc=1
  local is_https=0
  hdr_url_is_https "$url" && is_https=1

  # -- Content-Security-Policy -------------------------------------------
  hdr_first content-security-policy; policy=$_HDR_V
  if (( is_doc )) && _hdr_selected DAST-HDR-CSP_MISSING-01; then
    _hdr_eval DAST-HDR-CSP_MISSING-01
    if [[ -z $policy ]]; then
      # Report-Only is named explicitly because an operator who deployed it will
      # otherwise read this finding as simply wrong.  It enforces nothing.
      local ro=''
      hdr_present content-security-policy-report-only \
        && ro=' A Content-Security-Policy-Report-Only header IS present, which reports violations and blocks nothing.'
      _hdr_hit DAST-HDR-CSP_MISSING-01 "$url" "$path" \
        "the response carries no Content-Security-Policy header at all.$ro"
    fi
  fi

  # SEVERAL CSP HEADERS ON ONE RESPONSE MEAN THE INTERSECTION OF THEM ALL, AND
  # THIS PHASE ANALYSES ONE, SO IT ANALYSES NONE.  CSP3 §2.2 has a user agent
  # enforce every policy it received, so a permissive first header can be
  # narrowed to nothing by a second - reporting `'unsafe-inline'` out of the
  # first would then be a finding about a source the browser actually blocks.
  # The three CSP-CONTENT checks are therefore declined for such a response and
  # the reduction is recorded, rather than guessed at in either direction.  The
  # ABSENCE check is unaffected: two policies are still not zero policies.
  local csp_analysable=1
  if (( ${_HDR_COUNT[content-security-policy]:-0} > 1 )); then
    csp_analysable=0
    run_record coverage_reduction "module=dast reason=headers_multiple_csp_headers target=${SCOURSH_DAST_TARGET:-} path=$(hdr_safe_text "$path" 120) count=${_HDR_COUNT[content-security-policy]} - the response carries more than one Content-Security-Policy header, whose effective policy is the INTERSECTION of all of them. This phase evaluates one policy, so the CSP-content and framing checks were NOT applied to this response rather than risk reporting a source or an ancestor the combined policy actually blocks."
  fi

  # ALWAYS reloaded, or explicitly emptied, before anything reads it: this
  # function is called once per response and `_HDR_CSP_DIR` is a global, so a
  # policy left over from the PREVIOUS response would otherwise be read as this
  # one's - the same stale-shared-state class of bug the reset in
  # `hdr_parse_capture` exists to prevent one level down.
  if [[ -n $policy ]]; then
    hdr_csp_load "$policy"
  else
    declare -gA _HDR_CSP_DIR=()
  fi

  if [[ -n $policy ]] && (( csp_analysable )); then
    # The script fetch context, which is the one that decides whether an
    # injected string can execute.  `hdr_csp_effective` applies CSP's own
    # default-src fallback, so `default-src 'self' 'unsafe-inline'` with no
    # script-src is caught - the commonest real shape of this defect.
    if hdr_csp_effective script-src; then
      local script_src=$_HDR_CSP_SRC
      via=$_HDR_CSP_VIA
      if _hdr_selected DAST-HDR-CSP_UNSAFE-01; then
        _hdr_eval DAST-HDR-CSP_UNSAFE-01
        local unsafe=''
        # 'unsafe-inline' is IGNORED by every CSP2+ browser when the same
        # directive carries a nonce or a hash, so flagging it there is a false
        # positive on a policy that is doing the right thing.
        if [[ " $script_src " == *" 'unsafe-inline' "* ]] && ! hdr_csp_has_nonce_or_hash "$script_src"; then
          unsafe="'unsafe-inline'"
        fi
        if [[ " $script_src " == *" 'unsafe-eval' "* ]]; then
          [[ -n $unsafe ]] && unsafe="$unsafe and "
          unsafe="${unsafe}'unsafe-eval'"
        fi
        if [[ -n $unsafe ]]; then
          _hdr_hit DAST-HDR-CSP_UNSAFE-01 "$url" "$path" \
            "the effective script source list ($via: $(hdr_safe_text "$script_src" 120)) permits $unsafe"
        fi
      fi
    fi
    # `data:` and a wildcard host are checked across the three directives that
    # govern ACTIVE content.  img-src and font-src are deliberately excluded:
    # `img-src data:` is ordinary and flagging it would drown the real finding.
    local d
    if _hdr_selected DAST-HDR-CSP_DATA_SOURCE-01; then
      _hdr_eval DAST-HDR-CSP_DATA_SOURCE-01
      for d in script-src object-src default-src; do
        [[ -n ${_HDR_CSP_DIR[$d]+set} ]] || continue
        if hdr_csp_data_in "${_HDR_CSP_DIR[$d]}"; then
          _hdr_hit DAST-HDR-CSP_DATA_SOURCE-01 "$url" "$path" \
            "the $d directive lists the data: scheme as a source ($(hdr_safe_text "${_HDR_CSP_DIR[$d]}" 120))"
          break
        fi
      done
    fi
    if _hdr_selected DAST-HDR-CSP_WILDCARD-01; then
      _hdr_eval DAST-HDR-CSP_WILDCARD-01
      for d in script-src object-src frame-src connect-src default-src; do
        [[ -n ${_HDR_CSP_DIR[$d]+set} ]] || continue
        if hdr_csp_wildcard_in "${_HDR_CSP_DIR[$d]}"; then
          local kind='a wildcard host'
          [[ $_HDR_CSP_WILDCARD == '*' ]] && kind='a bare * source, which allows every origin on the internet'
          _hdr_hit DAST-HDR-CSP_WILDCARD-01 "$url" "$path" \
            "the $d directive lists $kind ($(hdr_safe_text "$_HDR_CSP_WILDCARD" 80))"
          break
        fi
      done
    fi
  fi

  # -- Strict-Transport-Security -----------------------------------------
  # Only on HTTPS.  RFC 6797 §7.2 has the browser ignore the header outright on
  # a plaintext response, so neither its absence nor its value says anything
  # there, and reporting it would be an assertion about a control the transport
  # already made irrelevant.
  if (( is_https )); then
    if hdr_present strict-transport-security; then
      hdr_first strict-transport-security; v=$_HDR_V
      hdr_hsts_parse "$v"
      case $_HDR_HSTS_STATE in
        ok)
          if _hdr_selected DAST-HDR-HSTS_WEAK-01; then
            _hdr_eval DAST-HDR-HSTS_WEAK-01
            if (( _HDR_HSTS_MAXAGE < SCOURSH_DAST_HSTS_MIN_MAX_AGE )); then
              local why="max-age=$_HDR_HSTS_MAXAGE is below the $SCOURSH_DAST_HSTS_MIN_MAX_AGE-second floor this run holds HSTS to"
              (( _HDR_HSTS_MAXAGE == 0 )) \
                && why='max-age=0, which instructs the browser to DELETE any HSTS pin it already holds for this host'
              _hdr_hit DAST-HDR-HSTS_WEAK-01 "$url" "$path" "$why"
            fi
          fi
          if _hdr_selected DAST-HDR-HSTS_MALFORMED-01; then
            _hdr_eval DAST-HDR-HSTS_MALFORMED-01
            # Several STS headers on one response is unusable in a different
            # way: RFC 6797 §8.1 has the UA process the FIRST and there is no
            # way to tell which one the operator meant.
            if (( ${_HDR_COUNT[strict-transport-security]:-1} > 1 )); then
              _hdr_hit DAST-HDR-HSTS_MALFORMED-01 "$url" "$path" \
                "the response carries ${_HDR_COUNT[strict-transport-security]} separate Strict-Transport-Security headers; a browser applies only the first and the rest are silently discarded"
            fi
          fi
          ;;
        no_max_age | bad_max_age)
          if _hdr_selected DAST-HDR-HSTS_MALFORMED-01; then
            _hdr_eval DAST-HDR-HSTS_MALFORMED-01
            local what='names no max-age directive at all'
            [[ $_HDR_HSTS_STATE == bad_max_age ]] && what='carries a max-age that is not a decimal integer'
            _hdr_hit DAST-HDR-HSTS_MALFORMED-01 "$url" "$path" \
              "the Strict-Transport-Security value \"$(hdr_safe_text "$v" 100)\" $what, so RFC 6797 has the browser ignore the whole header - the response is protected exactly as if none had been sent"
          fi
          ;;
      esac
    elif _hdr_selected DAST-HDR-HSTS_MISSING-01; then
      _hdr_eval DAST-HDR-HSTS_MISSING-01
      _hdr_hit DAST-HDR-HSTS_MISSING-01 "$url" "$path" \
        'the HTTPS response carries no Strict-Transport-Security header, so a browser that has never pinned this host will still attempt plaintext'
    fi
  fi

  # -- Clickjacking: X-Frame-Options / CSP frame-ancestors ----------------
  if (( is_doc && csp_analysable )) && _hdr_selected DAST-HDR-CLICKJACKING-01; then
    _hdr_eval DAST-HDR-CLICKJACKING-01
    local fa='' xfo='' protected=0 detail=''
    if [[ -n $policy && -n ${_HDR_CSP_DIR[frame-ancestors]+set} ]]; then
      fa=${_HDR_CSP_DIR[frame-ancestors]}
      # `frame-ancestors *` is present and permits everything, which is not
      # protection - and CSP frame-ancestors OVERRIDES X-Frame-Options where
      # both are sent, so a permissive one is worse than none.
      if [[ " $fa " == *' * '* || $fa == '*' ]]; then
        detail="the CSP frame-ancestors directive is '$(hdr_safe_text "$fa" 80)', which permits framing by any origin and overrides X-Frame-Options where both are sent"
      else
        protected=1
      fi
    fi
    if (( ! protected )) && [[ -z $fa ]]; then
      hdr_first x-frame-options; xfo=${_HDR_V,,}
      xfo=${xfo#"${xfo%%[![:space:]]*}"}
      case $xfo in
        deny | sameorigin) protected=1 ;;
        '') detail='neither an X-Frame-Options header nor a CSP frame-ancestors directive is present, so the page may be framed by any origin' ;;
        allow-from*) detail="X-Frame-Options is \"$(hdr_safe_text "$_HDR_V" 80)\"; ALLOW-FROM was never implemented by Chrome or Edge and was removed from Firefox, so this response has no framing protection in any current browser" ;;
        *) detail="X-Frame-Options is \"$(hdr_safe_text "$_HDR_V" 80)\", which is not one of the two values a browser recognises (DENY, SAMEORIGIN), so it is ignored" ;;
      esac
    fi
    (( protected )) || _hdr_hit DAST-HDR-CLICKJACKING-01 "$url" "$path" "$detail"
  fi

  # -- X-Content-Type-Options --------------------------------------------
  # Every response, not documents only: the whole point of nosniff is the
  # response whose declared type a browser might override, and that is usually
  # NOT the HTML page.
  if _hdr_selected DAST-HDR-NOSNIFF_MISSING-01; then
    _hdr_eval DAST-HDR-NOSNIFF_MISSING-01
    hdr_first x-content-type-options; v=${_HDR_V,,}
    v=${v#"${v%%[![:space:]]*}"}
    v=${v%"${v##*[![:space:]]}"}
    if [[ $v != nosniff ]]; then
      local d2='the response carries no X-Content-Type-Options header'
      [[ -n $v ]] && d2="X-Content-Type-Options is \"$(hdr_safe_text "$_HDR_V" 60)\" rather than \"nosniff\", which is the only value browsers act on"
      _hdr_hit DAST-HDR-NOSNIFF_MISSING-01 "$url" "$path" "$d2"
    fi
  fi

  # -- Referrer-Policy ----------------------------------------------------
  # Only a PRESENT, leaky value is a finding here; absence goes to the roll-up,
  # because every current browser defaults to strict-origin-when-cross-origin
  # and calling that a leak would be false.
  if hdr_present referrer-policy && _hdr_selected DAST-HDR-REFERRER_LEAKY-01; then
    _hdr_eval DAST-HDR-REFERRER_LEAKY-01
    hdr_value referrer-policy; v=${_HDR_V//$'\n'/,}
    hdr_referrer_effective "$v"
    if [[ -n $_HDR_REF_TOKEN ]] && hdr_referrer_leaks_full_url "$_HDR_REF_TOKEN"; then
      local extra=''
      [[ $_HDR_REF_TOKEN == no-referrer-when-downgrade ]] \
        && extra=' - it withholds the referrer only on an HTTPS-to-HTTP downgrade, and sends the full URL to every cross-origin HTTPS destination'
      _hdr_hit DAST-HDR-REFERRER_LEAKY-01 "$url" "$path" \
        "the effective Referrer-Policy is \"$_HDR_REF_TOKEN\"$extra"
    fi
  fi

  # -- The recommended-headers roll-up ------------------------------------
  # Counted per response here; the decision about what to report is made once,
  # after every response has been seen (see `_hdr_emit_rollup`).
  if (( ${#_HDR_RECOMMENDED[@]} > 0 )); then
    for n in "${_HDR_RECOMMENDED[@]+"${_HDR_RECOMMENDED[@]}"}"; do
      hdr_present "$n" && continue
      _HDR_REC_MISSING[$n]=$(( ${_HDR_REC_MISSING[$n]:-0} + 1 ))
    done
  fi
  return 0
}

# ---------------------------------------------------------------------------
# tension-15 per-check selection
# ---------------------------------------------------------------------------
# scan.sh's filter chain records which ids survived
# --profile-scan/--intensity/--allow-intrusive and exports them as
# SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected` is the
# reader, and it now EXISTS - so on any run reached through `dast_run_phase`
# this really does narrow what the phase evaluates.
#
# THE `declare -F` GUARD IS KEPT ON PURPOSE, and is not dead weight now that the
# function is defined.  tests/suites/dast-headers.sh sources THIS file directly
# with no modules/dast/engine.sh anywhere in the process (so do dast-sqli.sh and
# dast-discovery.sh for their own phases).  Without the guard the call would be
# a `command not found`, exit 127, non-zero - so every check would read as
# DESELECTED and the phase would go inert while every "stays quiet" assertion in
# that suite still passed green.  Fail-open on an absent reader is the same
# permissive default `dast_check_selected` itself applies to an absent list.
_hdr_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
# The DAST location profile is (target, method, path_template, param_location,
# param_name) (lib/findings.sh).  A header finding names no parameter, so the
# last two are empty and the identity is (target, GET, path_template) plus the
# check id - which is exactly the "one finding per check per path" grain this
# phase wants, and is why the defect is in the CHECK ID rather than in the
# evidence: two defects on one page would otherwise collide on one fingerprint
# and the merge would silently keep one.
_hdr_emit() {
  local check=$1 url=$2 path=$3 evidence=$4
  local target=${SCOURSH_DAST_TARGET:-}
  _hdr_catalog "$check" || return 0

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$_HDRC_TITLE"
  finding_set base_severity "$_HDRC_SEV"
  finding_set confidence "$_HDRC_CONF"
  finding_set cwe "$_HDRC_CWE"
  finding_set owasp "$_HDRC_OWASP"
  finding_set exposure external
  finding_set auth "${_HDR_AUTH_VALUE:-none}"
  finding_set sensitive_data false
  finding_set remediation "$_HDRC_REM"
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

# The roll-up.  A recommended header is reported as NOT SET only when it was
# absent from EVERY response tested: a header present on some pages is a
# consistency problem rather than an absent control, and the two get different
# sentences rather than one wrong one.
_hdr_emit_rollup() {
  local tested=$1 url=$2 path=$3
  local n absent='' inconsistent=0 inconsistent_names=''
  for n in "${_HDR_RECOMMENDED[@]+"${_HDR_RECOMMENDED[@]}"}"; do
    if (( ${_HDR_REC_MISSING[$n]:-0} == tested )); then
      absent+="${absent:+, }$n"
    elif (( ${_HDR_REC_MISSING[$n]:-0} > 0 )); then
      inconsistent=$(( inconsistent + 1 ))
      inconsistent_names+="${inconsistent_names:+, }$n"
    fi
  done
  [[ -n $absent ]] || return 0
  local evi="none of the $tested response(s) tested on this target set: $absent."
  (( inconsistent > 0 )) \
    && evi+=" A further $inconsistent recommended header(s) were set on some responses and not others ($inconsistent_names), which is a consistency problem rather than an absent control."
  evi+=' The list is operator-configurable (modules/dast/passive/recommended-headers.txt).'
  _hdr_emit DAST-HDR-RECOMMENDED_MISSING-01 "$url" "$path" "$evi"
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_headers_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/headers.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE, AND
  # THAT IS NOT BELT-AND-BRACES.  modules/dast/run.sh reads the inventory and
  # exports SCOURSH_DAST_ENDPOINTS BEFORE the phase loop starts, so on a first
  # run - the ordinary case - it is EMPTY, because crawl.sh writes
  # reports/<run>/inventory/endpoints.json a few phases later in the same loop.
  # A passive check that trusted the export alone would therefore see no
  # endpoints on exactly the run that has just discovered them.  The run
  # directory's own artifact is the authority (docs/INVENTORY-FORMAT.md §1), so
  # it is consulted when the export is empty.  Fixing the export itself belongs
  # to modules/dast/run.sh and is filed separately rather than changed here,
  # where six peer tickets are editing the same tree.
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

  _hdr_acc_reset
  declare -gA _HDR_REC_MISSING=()
  _HDR_AUTH_VALUE=none

  # The configurable roll-up list.  Absent or empty degrades that ONE check to a
  # recorded reduction, exactly as a missing payload file degrades one SQLi
  # technique, and never errors.
  local do_rollup=1
  if ! hdr_load_recommended; then
    do_rollup=0
    run_record coverage_reduction "module=dast reason=recommended_header_list_unavailable target=$target - the recommended-header list (modules/dast/passive/recommended-headers.txt, or SCOURSH_DAST_RECOMMENDED_HEADERS_FILE) is absent, unreadable or empty, so the 'recommended headers not set' roll-up did not run. This is a coverage reduction, not a clean result."
  fi
  _hdr_selected DAST-HDR-RECOMMENDED_MISSING-01 || do_rollup=0
  if (( ${#_HDR_RECOMMENDED_DROPPED[@]} > 0 )); then
    run_record notes "module=dast phase=headers target=$target recommended_list_ignored=[${_HDR_RECOMMENDED_DROPPED[*]}] reason=each_has_its_own_check_id"
  fi

  hdr_endpoints_load "$epf" "$target" "$base"
  if (( _HDR_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_to_inspect target=$target - neither an endpoint inventory (docs/INVENTORY-FORMAT.md) nor a base-url in config/scope.conf gave this phase a URL to request, so no response header was read."
    run_record coverage_gap "dast headers: target '$target' offered no URL to request, so NO security header was inspected. This is a coverage gap - nothing was tested - not a finding that the target's headers are sound."
    return 0
  fi

  local i url path tested=0 refused=0 unreachable=0
  for (( i = 0; i < _HDR_N; i++ )); do
    url=${_HDR_URL[$i]}
    path=${_HDR_PATH[$i]}

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

    local hdrfile=$SCOURSH_SCRATCH/dast-headers.$$.$i.hdr
    # The capture is set immediately before the call because `http_request`
    # consumes and clears the per-request context at entry, so it can never ride
    # along on a later request (lib/http.sh §9a).
    http_request_capture '' "$hdrfile"
    if ! http_request GET "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$hdrfile"
      continue
    fi
    if ! hdr_parse_capture "$hdrfile"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$hdrfile"
      continue
    fi
    rm -f "$hdrfile"
    tested=$(( tested + 1 ))
    _hdr_analyse_one "$url" "$path"
  done

  if (( tested == 0 )); then
    run_record coverage_gap "dast headers: none of the $_HDR_N URL(s) selected on target '$target' produced a response this phase could read ($refused declined by the scope gate, $unreachable did not answer), so NO security header was inspected. A clean result here is the absence of a test."
    return 0
  fi

  # Emit: one finding per check that fired, located at the first response that
  # exhibited it, with the affected/tested count in the evidence.
  local c
  for c in "${_HDR_CHECK_IDS[@]+"${_HDR_CHECK_IDS[@]}"}"; do
    [[ $c == DAST-HDR-RECOMMENDED_MISSING-01 ]] && continue
    (( ${_HDRF_HIT[$c]:-0} > 0 )) || continue
    _hdr_emit "$c" "${_HDRF_URL[$c]}" "${_HDRF_PATH[$c]}" \
      "on GET ${_HDRF_PATH[$c]}, ${_HDRF_DETAIL[$c]}. Observed on ${_HDRF_HIT[$c]} of the ${_HDRF_EVAL[$c]:-$tested} response(s) this check applied to (of $tested fetched on target '$target')."
  done
  (( do_rollup )) && _hdr_emit_rollup "$tested" "${_HDR_URL[0]}" "${_HDR_PATH[0]}"

  # checks_run is the set of checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), and it is the honest input modules/dast/run.sh's coverage
  # roll-up reads.  A check is recorded only when at least one response it was
  # APPLICABLE to was actually inspected - an HSTS check over a run that only
  # ever saw plaintext responses covered nothing, and saying otherwise would
  # report an untested control as tested.
  for c in "${_HDR_CHECK_IDS[@]+"${_HDR_CHECK_IDS[@]}"}"; do
    if [[ $c == DAST-HDR-RECOMMENDED_MISSING-01 ]]; then
      (( do_rollup )) && run_record checks_run "$c"
      continue
    fi
    (( ${_HDRF_EVAL[$c]:-0} > 0 )) && run_record checks_run "$c"
  done

  # Every bound and every gap, named.  docs/DESIGN.md §15: a bound that
  # truncates silently is indistinguishable from a surface that was really that
  # small.
  if (( _HDR_TRUNCATED > 0 )); then
    run_record coverage_gap "dast headers: target '$target' offered more distinct endpoints than this phase requests - $_HDR_TRUNCATED were NOT fetched (cap $_HDR_MAX_ENDPOINTS). Their response headers were not inspected and their absence from this report is a coverage bound, not a clean result."
  fi
  if (( _HDR_SKIPPED_NON_GET > 0 )); then
    run_record coverage_reduction "module=dast reason=headers_non_get_endpoint_skipped target=$target count=$_HDR_SKIPPED_NON_GET - $_HDR_SKIPPED_NON_GET discovered endpoint(s) are not GET. Re-sending them to read their response headers would change target state, which docs/DESIGN.md §7.1 forbids at the passive tier, so their headers were not inspected."
  fi
  if (( refused > 0 )); then
    run_record coverage_reduction "module=dast reason=headers_endpoint_out_of_scope target=$target count=$refused - $refused URL(s) in the inventory are not authorised by config/scope.conf and were not requested (${_HTTP_GATE_REASON:-declined by the scope gate})."
  fi
  if (( unreachable > 0 )); then
    run_record coverage_reduction "module=dast reason=headers_endpoint_unreachable target=$target count=$unreachable - $unreachable URL(s) returned no readable response, so their headers were not inspected."
  fi
  local uncovered='' c2
  for c2 in "${_HDR_CHECK_IDS[@]+"${_HDR_CHECK_IDS[@]}"}"; do
    [[ $c2 == DAST-HDR-RECOMMENDED_MISSING-01 ]] && continue
    (( ${_HDRF_EVAL[$c2]:-0} > 0 )) || uncovered+="${uncovered:+ }$c2"
  done
  if [[ -n $uncovered ]]; then
    run_record coverage_reduction "module=dast reason=headers_check_not_applicable target=$target checks=[$uncovered] - none of the $tested response(s) inspected was one these checks apply to (a CSP or framing check needs a document response; an HSTS check needs an HTTPS one; a CSP-content or Referrer-Policy check needs the header to be present at all). They are NOT covered on this target."
  fi

  log_info "dast headers: target '$target' - inspected $tested of $_HDR_N selected endpoint(s) for security headers"
  return 0
}

_dast_headers_phase
