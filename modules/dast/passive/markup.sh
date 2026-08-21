#!/usr/bin/env bash
# modules/dast/passive/markup.sh - the §7.1 HTML-MARKUP phase
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-11, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs on every dast run), so it
# inherits the whole run context and anything it emits lands in this process's
# shard.  Per that function's contract it carries NO sourced-once guard - one
# run can legitimately reach the same phase twice - and every array it declares
# uses `declare -g`.  The pure, testable half is
# modules/dast/passive/markup_engine.sh, whose header is the authority for
# exactly what the parser handles and what it does not; this file is the
# orchestration: choose what to request, ask through the ONE chokepoint,
# decide, and emit.
#
# PASSIVE, RESTATED (docs/DESIGN.md §7.1 "No mutation of state").  Every request
# this phase sends is a plain GET to a URL that is either the operator's own
# `base-url` or an endpoint some earlier phase already fetched.  IT NEVER
# SUBMITS A FORM.  That bears saying twice for this phase in particular,
# because one of its four checks is about forms: a CSRF check that proved its
# point by POSTing the form would be a state change wearing a passive check's
# name, so the finding is made entirely out of the markup as served.
#
# READ THE ENDPOINT LIST; DO NOT CRAWL.  `crawl.sh` (DAST-04) owns discovery and
# writes `reports/<run>/inventory/endpoints.json`; this phase consumes it and
# follows no link it finds in a page it parsed.  Every link in the markup is
# CLASSIFIED (same-origin or not, https or not) and none of them is requested.
#
# ONE FINDING PER CHECK PER PAGE, WHICH IS DELIBERATELY NOT `headers.sh`'s
# GRAIN, AND THE CONTRAST IS THE ARGUMENT.  A security header is a server
# configuration property: it is the same on every response, so `headers.sh`
# collapses to one finding per target and puts "on N of M responses" in the
# evidence, because reporting the same single misconfiguration ten times buries
# everything else.  Markup is a TEMPLATE property: the login page and the help
# page are different documents with different defects and different fixes, and
# collapsing them would tell an operator that "a page" on this target has a
# form with no CSRF token without saying which.  The DAST location profile
# already carries `path_template`, so a per-page finding is exactly one
# fingerprint per (check, template) - and the endpoint chooser has ALREADY
# deduplicated by path template and capped the set, so the report is bounded by
# construction rather than by hope.  Within one page, every offending element
# for one check is ONE finding, with the elements enumerated (bounded) in the
# evidence and a count: a shared footer with six unsafe links is one defect.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test".  No endpoint inventory and no base-url, an endpoint the
# scope gate declines, a response that never arrived, a response that is not
# markup at all, a document the parser had to abandon part-way, a document that
# hit the byte cap, and - the big one - a CLIENT-RENDERED page whose real DOM
# this tool cannot see are each recorded as a coverage_gap or
# coverage_reduction the report renders, exactly as modules/dast/auth.sh,
# crawl.sh, passive/headers.sh and active/sqli.sh do for their own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes HTML attribute syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/passive/markup_engine.sh
source "${BASH_SOURCE[0]%/*}/markup_engine.sh"

# ---------------------------------------------------------------------------
# The check catalog, in the shell
# ---------------------------------------------------------------------------
# modules/dast/passive/checks.rules is the REGISTRY - what tension 12 computes
# coverage over and tension 15's filter chain filters - and this table is what a
# finding actually carries.  They are two copies on purpose and for the same
# reason modules/dast/passive/headers.sh and modules/dast/active/sqli.sh each
# carry their own: `finding_set` is fed by the emitting script, not by the
# registry loader, and a phase that read its severity out of a records file at
# emit time would be a second consumer of that format for every module to keep
# in step.  Keep the two in sync when either changes;
# tests/suites/dast-markup.sh asserts they agree on every id.
#
# Sets `_MKC_TITLE`, `_MKC_SEV`, `_MKC_CONF`, `_MKC_CWE`, `_MKC_OWASP` and
# `_MKC_REM`.  Returns 1 for an id that is not this phase's.
_mk_catalog() {
  _MKC_TITLE='' _MKC_SEV='' _MKC_CONF='' _MKC_CWE='' _MKC_OWASP='' _MKC_REM=''
  case $1 in
    DAST-MARKUP-SRI_MISSING-01)
      _MKC_TITLE='Cross-origin script or stylesheet loaded without Subresource Integrity'
      _MKC_SEV=medium; _MKC_CONF=high; _MKC_CWE=CWE-353; _MKC_OWASP=A08:2021
      _MKC_REM='Add an integrity attribute carrying the sha384 (or sha256/sha512) digest of the exact file, and a crossorigin attribute alongside it - without crossorigin the response is opaque, the browser cannot verify the digest, and it blocks the resource instead. Pin the version in the URL as well: an integrity hash against a "latest" URL breaks on every upstream release, which is what pushes teams to remove the attribute. Where a third party will not serve a stable, hashable artifact, self-host the file instead; until then this page executes whatever that origin serves it, with full access to this page DOM, cookies and storage.' ;;
    DAST-MARKUP-TABNABBING-01)
      _MKC_TITLE='Cross-origin target=_blank link without rel=noopener'
      _MKC_SEV=low; _MKC_CONF=high; _MKC_CWE=CWE-1022; _MKC_OWASP=A01:2021
      _MKC_REM='Add rel="noopener noreferrer" to every link that opens a cross-origin destination in a new browsing context. The opened page receives a window.opener handle to this one and can navigate it to anywhere it likes, so a user who returns to the original tab may be looking at an attacker page at the address they expected. Current Chromium, Firefox and Safari imply noopener for target=_blank, so this is defence for older and embedded browsers and for any code that opens the window with window.open - which is NOT covered by the implicit default and needs the noopener feature string passed explicitly.' ;;
    DAST-MARKUP-TABNABBING_SENSITIVE-01)
      _MKC_TITLE='Cross-origin target=_blank link without rel=noopener on an authentication or redirect page'
      _MKC_SEV=medium; _MKC_CONF=high; _MKC_CWE=CWE-1022; _MKC_OWASP=A01:2021
      _MKC_REM='Add rel="noopener noreferrer" to every link that opens a cross-origin destination in a new browsing context, and treat this page as the priority: it is an authentication, credential or redirect page, so the tab an attacker can rewrite through window.opener is the one the user is about to type a password into or has just been handed control of. rel="noreferrer" matters here beyond noopener as well - without it the full URL of this page, including any single-use login, reset or continuation token in its query string, is sent to the third-party destination as the Referer.' ;;
    DAST-MARKUP-FRAME_INSECURE_SCHEME-01)
      _MKC_TITLE='Frame or embedded object loaded over plaintext HTTP'
      _MKC_SEV=medium; _MKC_CONF=high; _MKC_CWE=CWE-319; _MKC_OWASP=A02:2021
      _MKC_REM='Serve the framed document over https:// and change the src to match. A plaintext frame is readable and rewritable by anyone on the network path, and whatever the user types into it is too. Where the page itself is HTTPS this is active mixed content, which current browsers block outright - so the frame is not merely insecure, it does not load, and the feature it provides is silently broken. Add a Content-Security-Policy with block-all-mixed-content or upgrade-insecure-requests to catch the next one.' ;;
    DAST-MARKUP-FRAME_UNTRUSTED-01)
      _MKC_TITLE='Cross-origin frame embedded without a sandbox attribute'
      _MKC_SEV=low; _MKC_CONF=medium; _MKC_CWE=CWE-829; _MKC_OWASP=A08:2021
      _MKC_REM='Add a sandbox attribute naming only the capabilities the embedded document genuinely needs, and constrain what may be framed at all with a Content-Security-Policy frame-src directive listing the specific origins. An unsandboxed cross-origin frame can navigate the top-level window, open dialogs and run plugins in this page context. Note that sandbox="allow-scripts allow-same-origin" together defeats the sandbox for a same-origin document, so do not use that pair as a default. This check reports the absence of a control, not a compromised third party: a frame whose origin you own and trust may legitimately carry no sandbox, which is why its confidence is medium.' ;;
    DAST-MARKUP-CSRF_TOKEN_ABSENT-01)
      _MKC_TITLE='State-changing form served without an anti-CSRF token'
      _MKC_SEV=medium; _MKC_CONF=medium; _MKC_CWE=CWE-352; _MKC_OWASP=A01:2021
      _MKC_REM='Issue a per-session (or per-form) synchroniser token, render it into every state-changing form as a hidden field, and reject any POST whose token is absent or does not match. Set SameSite=Lax or Strict on the session cookie as well: it is a real second layer and on its own it does not cover a same-site subdomain an attacker controls, nor a cross-origin request that carries the credential some other way. This check reads only the markup as served, so it cannot see a token a script injects at submit time, a double-submit cookie, or an Origin/Referer check made server-side - which is why its confidence is medium and why a finding here is a prompt to confirm the defence, not proof there is none.' ;;
    *) return 1 ;;
  esac
  return 0
}

# Every id this phase can emit, in report order.
declare -ga _MK_CHECK_IDS=(
  DAST-MARKUP-SRI_MISSING-01
  DAST-MARKUP-TABNABBING-01
  DAST-MARKUP-TABNABBING_SENSITIVE-01
  DAST-MARKUP-FRAME_INSECURE_SCHEME-01
  DAST-MARKUP-FRAME_UNTRUSTED-01
  DAST-MARKUP-CSRF_TOKEN_ABSENT-01
)

# ---------------------------------------------------------------------------
# tension-15 per-check selection
# ---------------------------------------------------------------------------
# scan.sh's filter chain records which ids survived
# --profile-scan/--intensity/--allow-intrusive and exports them as
# SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected` is the
# reader.  Consulted only if that function exists - it does not today, and
# modules/dast/passive/headers.sh and active/sqli.sh guard it the same way - so
# this file does not hard-depend on it: absent, everything the tier already
# permitted runs, which is the "empty means all selected" fallback a
# direct-engine test relies on.
_mk_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# ---------------------------------------------------------------------------
# The per-page accumulator
# ---------------------------------------------------------------------------
# `_MK_COUNT[check]`  offending elements found on THIS page.
# `_MK_ITEMS[check]`  the first `_MARKUP_MAX_EVIDENCE_ITEMS` of them, as prose.
# Reset per page, because a finding is per page (see this file's header).
_mk_page_reset() {
  declare -gA _MK_COUNT=() _MK_ITEMS=()
}

_mk_add() {
  local c=$1 item=$2 n
  n=${_MK_COUNT[$c]:-0}
  _MK_COUNT[$c]=$(( n + 1 ))
  if (( n < _MARKUP_MAX_EVIDENCE_ITEMS )); then
    _MK_ITEMS[$c]="${_MK_ITEMS[$c]:+${_MK_ITEMS[$c]}; }$item"
  fi
}

# `_mk_abs REF` - the absolute form of one reference, resolved against this
# page's `<base href>` if it declared one and against the page URL otherwise.
# Returns 1 for a reference that is not a fetchable http(s) URL - `javascript:`,
# `mailto:`, `data:`, a bare `#fragment` - which is `crawl_url_resolve`'s own
# contract and is right for every check here: none of those loads a subresource,
# opens a browsing context at another origin, or posts a form.
_mk_abs() {
  crawl_url_resolve "$_MK_BASE" "$1"
}

# ---------------------------------------------------------------------------
# Analysis of one document
# ---------------------------------------------------------------------------
# Reads the tokenizer's record stream for ONE response and fills the per-page
# accumulator.  Sends nothing itself.
#
# TWO PASSES, AND THE FIRST ONE IS NOT OPTIONAL.  `<base href>` changes what
# every relative reference on the page resolves to, and
# `<input type="password">` decides which of the two tabnabbing check ids the
# page's findings carry.  Both are facts about the WHOLE document that a
# single forward pass would only learn after it had already misclassified the
# elements above them - `<base>` is required to precede any URL-using element,
# but a password field is routinely below the footer links being classified.
_mk_analyse_one() {
  local url=$1 path=$2 recfile=$3
  local kind ln a b c d

  _mk_page_reset
  declare -g _MK_BASE=$url _MK_SENSITIVE=0 _MK_TRUNC_REASONS='' _MK_FORMS_SEEN=0
  declare -g _MK_FORMS_CROSS_ORIGIN=0 _MK_ELEMENTS=0

  # -- pass one: document-wide facts --------------------------------------
  local base_seen=0 resolved
  while IFS=$'\x1f' read -r kind ln a b c d; do
    case $kind in
      base)
        (( base_seen )) && continue
        # A <base href> is itself resolved against the document URL, so a
        # relative one ("/app/") is meaningful.  Only the FIRST is honoured -
        # HTML ignores every later one - and one that will not resolve to an
        # http(s) URL is ignored rather than allowed to poison every reference
        # on the page.
        if resolved=$(crawl_url_resolve "$url" "$a" 2>/dev/null); then
          _MK_BASE=$resolved
          base_seen=1
        fi
        ;;
      field)
        [[ $b == password ]] && _MK_SENSITIVE=1
        ;;
      trunc)
        case $_MK_TRUNC_REASONS in
          *"$a"*) ;;
          *) _MK_TRUNC_REASONS="${_MK_TRUNC_REASONS:+$_MK_TRUNC_REASONS,}$a" ;;
        esac
        ;;
    esac
  done <"$recfile"

  # The path signal is the weaker of the two and only ever ADDS to the content
  # signal (markup_engine.sh §5): a page with a password field is sensitive
  # whatever it is called, and a page called /login is sensitive even when the
  # form is drawn by a script this tool cannot see.
  markup_path_is_sensitive "$path" && _MK_SENSITIVE=1

  local tab_check=DAST-MARKUP-TABNABBING-01
  (( _MK_SENSITIVE )) && tab_check=DAST-MARKUP-TABNABBING_SENSITIVE-01
  declare -g _MK_TAB_CHECK=$tab_check

  # -- pass two: the elements ---------------------------------------------
  local in_form=0 f_method='' f_action='' f_line=0 f_token=0 f_fields=0 f_pw=0
  local abs=''
  while IFS=$'\x1f' read -r kind ln a b c d; do
    _MK_ELEMENTS=$(( _MK_ELEMENTS + 1 ))
    case $kind in
      script | link)
        _mk_selected DAST-MARKUP-SRI_MISSING-01 || continue
        # A <link> only takes SRI for a relationship that fetches something the
        # document then executes or applies; a favicon does not.
        if [[ $kind == link ]]; then
          markup_link_takes_sri "$d" || continue
        fi
        abs=$(_mk_abs "$a") || continue
        # Same-origin is out of scope for SRI by design: the integrity
        # attribute defends against a THIRD PARTY serving something else, and
        # an origin that can already serve this page can serve anything.
        markup_same_origin "$abs" "$url" && continue
        [[ -n $b ]] && continue
        _mk_add DAST-MARKUP-SRI_MISSING-01 \
          "line $ln: <$kind> loads $(markup_safe_text "$abs") from another origin with no integrity attribute"
        ;;
      anchor)
        _mk_selected "$tab_check" || continue
        # `target` is a browsing-context NAME, not a token list: a single value
        # compared whole, case-insensitively.  Only `_blank` opens a new
        # context whose opener is this page; a named target reuses one.
        [[ ${b,,} == _blank ]] || continue
        abs=$(_mk_abs "$a") || continue
        markup_same_origin "$abs" "$url" && continue
        markup_tokens_have "$c" noopener && continue
        markup_tokens_have "$c" noreferrer && continue
        _mk_add "$tab_check" \
          "line $ln: <$d target=\"_blank\"> to $(markup_safe_text "$abs") carries rel=\"$(markup_safe_text "$c" 60)\", which names neither noopener nor noreferrer"
        ;;
      frame)
        abs=$(_mk_abs "$a") || continue
        # PRECEDENCE, DELIBERATELY: a plaintext frame is reported as a
        # plaintext frame and not also as an unsandboxed one.  They are two
        # different defects with two different fixes, but they are ONE element,
        # and reporting it twice trains a reader to skim.  The transport is the
        # more serious of the two and is named first; the untrusted-embedding
        # finding still fires for every cross-origin frame that is not
        # plaintext.
        if markup_is_plaintext_url "$abs"; then
          _mk_selected DAST-MARKUP-FRAME_INSECURE_SCHEME-01 || continue
          local mixed=''
          [[ ${url,,} == https://* ]] \
            && mixed=' - and because this page is itself HTTPS this is ACTIVE MIXED CONTENT, which current browsers block outright, so the embedded feature does not load at all'
          _mk_add DAST-MARKUP-FRAME_INSECURE_SCHEME-01 \
            "line $ln: <$b> embeds $(markup_safe_text "$abs") over plaintext http://$mixed"
          continue
        fi
        _mk_selected DAST-MARKUP-FRAME_UNTRUSTED-01 || continue
        markup_same_origin "$abs" "$url" && continue
        [[ $c == 1 ]] && continue
        _mk_add DAST-MARKUP-FRAME_UNTRUSTED-01 \
          "line $ln: <$b> embeds the cross-origin document $(markup_safe_text "$abs") with no sandbox attribute"
        ;;
      form)
        in_form=1 f_method=${a^^} f_action=$b f_line=$ln f_token=0 f_fields=0 f_pw=0
        ;;
      field)
        (( in_form )) || continue
        f_fields=$(( f_fields + 1 ))
        [[ $b == password ]] && f_pw=1
        markup_field_is_csrf_token "$a" "$b" && f_token=1
        ;;
      formend)
        (( in_form )) || continue
        in_form=0
        _mk_form_verdict "$url" "$f_method" "$f_action" "$f_line" "$f_token" "$f_fields" "$f_pw"
        ;;
    esac
  done <"$recfile"
  return 0
}

# One closed form, decided.  Split out of the walk so the decision can be read -
# and tested - on its own rather than buried in a `case` arm.
_mk_form_verdict() {
  local url=$1 method=$2 action=$3 line=$4 has_token=$5 n_fields=$6 has_pw=$7
  # A GET form is not state-changing by definition (HTML: a GET form submission
  # is a navigation), so a synchroniser token on one defends nothing and its
  # absence is not a finding.  An application that changes state on GET has a
  # different and larger problem, and it is not one this check can see.
  [[ $method == POST ]] || return 0
  _MK_FORMS_SEEN=$(( _MK_FORMS_SEEN + 1 ))
  (( has_token )) && return 0
  _mk_selected DAST-MARKUP-CSRF_TOKEN_ABSENT-01 || return 0

  # A form that POSTs to ANOTHER ORIGIN is not this application's CSRF problem -
  # a payment gateway, a search partner or an analytics beacon legitimately
  # receives a cross-origin POST and is responsible for its own request
  # validation, and flagging every one of them would put a finding on the
  # checkout page of most of the internet.  Counted and declared rather than
  # dropped.
  local abs=''
  if [[ -n $action ]]; then
    if abs=$(_mk_abs "$action" 2>/dev/null); then
      if ! markup_same_origin "$abs" "$url"; then
        _MK_FORMS_CROSS_ORIGIN=$(( _MK_FORMS_CROSS_ORIGIN + 1 ))
        return 0
      fi
    fi
  fi

  local what='form'
  (( has_pw )) && what='login form (it carries a password field)'
  local where=${action:-<the page itself, no action attribute>}
  _mk_add DAST-MARKUP-CSRF_TOKEN_ABSENT-01 \
    "line $line: POST $what to \"$(markup_safe_text "$where" 100)\" with $n_fields control(s), none of which is named like an anti-CSRF token"
  return 0
}

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
# The DAST location profile is (target, method, path_template, param_location,
# param_name) (lib/findings.sh).  A markup finding names no request parameter,
# so the last two are empty and the identity is (target, GET, path_template)
# plus the check id - which is exactly the "one finding per check per page"
# grain this phase wants (see this file's header), and is why the DEFECT lives
# in the CHECK ID rather than in the evidence: two different markup defects on
# one page would otherwise collide on one fingerprint and the merge would
# silently keep one.
#
# The offending elements are NOT part of the location, deliberately.  A CDN URL
# routinely carries a content hash, so putting it in the identity would mint a
# brand-new finding on every deploy and destroy the tension-12 diff that
# `--fail-on-new` gates on.  They go in the evidence, where they inform without
# churning.
_mk_emit() {
  local check=$1 url=$2 path=$3 evidence=$4
  local target=${SCOURSH_DAST_TARGET:-}
  _mk_catalog "$check" || return 0

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$_MKC_TITLE"
  finding_set base_severity "$_MKC_SEV"
  finding_set confidence "$_MKC_CONF"
  finding_set cwe "$_MKC_CWE"
  finding_set owasp "$_MKC_OWASP"
  finding_set exposure external
  finding_set auth "${_MK_AUTH_VALUE:-none}"
  finding_set sensitive_data false
  finding_set remediation "$_MKC_REM"
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

# Everything the accumulator holds for ONE page, emitted.  Called once per
# parsed document, immediately after `_mk_analyse_one`.
_mk_emit_page() {
  local url=$1 path=$2 c n more evi
  for c in "${_MK_CHECK_IDS[@]+"${_MK_CHECK_IDS[@]}"}"; do
    n=${_MK_COUNT[$c]:-0}
    (( n > 0 )) || continue
    _MK_FIRED[$c]=$(( ${_MK_FIRED[$c]:-0} + 1 ))
    more=''
    if (( n > _MARKUP_MAX_EVIDENCE_ITEMS )); then
      more=" (and $(( n - _MARKUP_MAX_EVIDENCE_ITEMS )) more not listed; the list is bounded at $_MARKUP_MAX_EVIDENCE_ITEMS elements so one page cannot become the report)"
    fi
    evi="on GET $path, $n element(s) in the served markup exhibit this: ${_MK_ITEMS[$c]}.$more"
    if [[ -n $_MK_TRUNC_REASONS ]]; then
      evi+=" The parser did not read the whole of this document ($_MK_TRUNC_REASONS), so there may be more below the point it stopped."
    fi
    _mk_emit "$c" "$url" "$path" "$evi"
  done
  return 0
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_markup_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/markup.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE, AND
  # THAT IS NOT BELT-AND-BRACES.  modules/dast/run.sh reads the inventory and
  # exports SCOURSH_DAST_ENDPOINTS BEFORE the phase loop starts, so on a first
  # run - the ordinary case - it is EMPTY, because crawl.sh writes
  # reports/<run>/inventory/endpoints.json a few phases later in that same
  # loop.  A passive check that trusted the export alone would therefore see no
  # endpoints on exactly the run that has just discovered them; this ticket's
  # whole surface IS that endpoint list.  The run directory's own artifact is
  # the authority (docs/INVENTORY-FORMAT.md §1), so it is consulted when the
  # export is empty - the same fallback, for the same reason,
  # modules/dast/passive/headers.sh and cookies.sh already carry.  Fixing the
  # export itself belongs to modules/dast/run.sh and is filed separately.
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

  declare -gA _MK_FIRED=()
  _MK_AUTH_VALUE=none

  markup_endpoints_load "$epf" "$target" "$base"
  if (( _MARKUP_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_to_inspect target=$target - neither an endpoint inventory (docs/INVENTORY-FORMAT.md) nor a base-url in config/scope.conf gave this phase a URL to request, so no markup was parsed."
    run_record coverage_gap "dast markup: target '$target' offered no URL to request, so NO page's HTML was inspected. This is a coverage gap - nothing was tested - not a finding that the target's markup is sound."
    return 0
  fi

  local i url path parsed=0 refused=0 unreachable=0 not_markup=0 spa=0 truncated_docs=0
  local spa_paths='' trunc_paths=''
  for (( i = 0; i < _MARKUP_N; i++ )); do
    url=${_MARKUP_URL[$i]}
    path=${_MARKUP_PATH[$i]}

    # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - the identical
    # split modules/dast/crawl.sh's `_crawl_in_scope` records.  `http_request`
    # gates FATALLY (an out-of-scope URL there is a caller bug, exit 3), which
    # is right for the operator's own base-url and exactly wrong for a URL
    # lifted out of an inventory some other module wrote: one bad row would
    # abort the whole run.  This decides only whether the URL is worth ASKING
    # FOR; everything that survives still goes through http_request, which
    # re-gates it and re-gates every redirect hop.
    if ! http_gate_url "$url" "$target"; then
      refused=$(( refused + 1 ))
      continue
    fi

    local bodyfile=$SCOURSH_SCRATCH/dast-markup.$$.$i.body
    local recfile=$SCOURSH_SCRATCH/dast-markup.$$.$i.rec
    # The capture is set immediately before the call because `http_request`
    # consumes and clears the per-request context at entry, so it can never
    # ride along on a later request (lib/http.sh §9a).  Only the BODY is
    # captured: `http_request` publishes the final hop's Content-Type in
    # `_HTTP_LAST_CONTENT_TYPE` itself, so this phase needs no header sink and
    # no second copy of a response-header reader.
    http_request_capture "$bodyfile" ''
    if ! http_request GET "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
      unreachable=$(( unreachable + 1 ))
      rm -f "$bodyfile"
      continue
    fi
    if ! markup_is_html "${_HTTP_LAST_CONTENT_TYPE:-}"; then
      not_markup=$(( not_markup + 1 ))
      rm -f "$bodyfile"
      continue
    fi
    if [[ ! -s $bodyfile ]]; then
      not_markup=$(( not_markup + 1 ))
      rm -f "$bodyfile"
      continue
    fi

    markup_html_extract <"$bodyfile" >"$recfile" 2>/dev/null || true
    # A page whose real DOM a script builds is the ONE limitation of this phase
    # that changes what a clean result means, so it is decided per page and
    # named per page.  crawl_engine.sh's heuristic is reused rather than
    # re-invented; it can only be wrong about an adjective (see its header),
    # and here as there it gates only the wording of a gap, never a finding.
    if crawl_html_looks_client_rendered "$bodyfile"; then
      spa=$(( spa + 1 ))
      spa_paths+="${spa_paths:+ }$path"
    fi
    rm -f "$bodyfile"

    parsed=$(( parsed + 1 ))
    _mk_analyse_one "$url" "$path" "$recfile"
    if [[ -n $_MK_TRUNC_REASONS ]]; then
      truncated_docs=$(( truncated_docs + 1 ))
      trunc_paths+="${trunc_paths:+ }$path($_MK_TRUNC_REASONS)"
    fi
    _mk_emit_page "$url" "$path"
    rm -f "$recfile"
  done

  if (( parsed == 0 )); then
    run_record coverage_gap "dast markup: none of the $_MARKUP_N URL(s) selected on target '$target' produced a markup document this phase could parse ($refused declined by the scope gate, $unreachable did not answer, $not_markup answered with something that is not HTML), so NO page's markup was inspected. A clean result here is the absence of a test."
    return 0
  fi

  # checks_run is the set of checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), and it is the honest input modules/dast/run.sh's coverage
  # roll-up reads.  Every one of these checks is applicable to any HTML
  # document - a page with no external script really was tested for SRI and
  # really has none to hash - so the condition is "at least one document was
  # parsed AND tension 15 left this id selected", and the two tabnabbing ids
  # are recorded separately because a run that saw only ordinary pages did not
  # cover the authentication-page one.
  local c
  for c in "${_MK_CHECK_IDS[@]+"${_MK_CHECK_IDS[@]}"}"; do
    _mk_selected "$c" || continue
    case $c in
      DAST-MARKUP-TABNABBING-01 | DAST-MARKUP-TABNABBING_SENSITIVE-01)
        (( ${_MK_FIRED[$c]:-0} > 0 )) || continue ;;
    esac
    run_record checks_run "$c"
  done

  # Every bound and every gap, named.  docs/DESIGN.md §15: a bound that
  # truncates silently is indistinguishable from a surface that was really that
  # small.
  if (( spa > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_client_rendered_page target=$target count=$spa paths=[$(markup_safe_text "$spa_paths" 400)] - these page(s) look client-rendered: scoursh executes no JavaScript and gets no browser (docs/DESIGN.md §7.5), so the DOM a visitor's browser actually builds - including any link, frame or form a script adds to it - was NOT inspected. A clean markup result for them is the absence of a test, not evidence the markup is sound."
    run_record coverage_gap "dast markup: $spa of the $parsed page(s) parsed on target '$target' look client-rendered, so their real DOM was never seen. Reverse tabnabbing, missing Subresource Integrity, insecure frames and missing anti-CSRF tokens are all invisible in a document a script has yet to build."
  fi
  if (( truncated_docs > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_document_truncated target=$target count=$truncated_docs detail=[$(markup_safe_text "$trunc_paths" 400)] - the parser stopped before the end of these document(s) (an unterminated quoted attribute value, an unterminated comment or tag, or the ${_MARKUP_MAX_BYTES}-byte cap). Everything after the stopping point was NOT examined; see modules/dast/passive/markup_engine.sh's header for why an unterminated value is abandoned rather than guessed at."
  fi
  if (( _MARKUP_TRUNCATED > 0 )); then
    run_record coverage_gap "dast markup: target '$target' offered more distinct path templates than this phase requests - $_MARKUP_TRUNCATED were NOT fetched (cap $_MARKUP_MAX_ENDPOINTS). Their markup was not inspected and their absence from this report is a coverage bound, not a clean result."
  fi
  if (( _MARKUP_SKIPPED_NON_GET > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_non_get_endpoint_skipped target=$target count=$_MARKUP_SKIPPED_NON_GET - $_MARKUP_SKIPPED_NON_GET discovered endpoint(s) are not GET. Re-sending them to read the markup they return would change target state, which docs/DESIGN.md §7.1 forbids at the passive tier, so their markup was not inspected."
  fi
  if (( refused > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_endpoint_out_of_scope target=$target count=$refused - $refused URL(s) in the inventory are not authorised by config/scope.conf and were not requested (${_HTTP_GATE_REASON:-declined by the scope gate})."
  fi
  if (( unreachable > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_endpoint_unreachable target=$target count=$unreachable - $unreachable URL(s) returned no readable response, so their markup was not inspected."
  fi
  if (( not_markup > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_response_not_html target=$target count=$not_markup - $not_markup response(s) were not an HTML or XHTML document (or carried no body), so there was no markup to parse. This is not a defect in them: a JSON API response has no links, frames or forms."
  fi
  if (( _MK_FORMS_CROSS_ORIGIN > 0 )); then
    run_record coverage_reduction "module=dast reason=markup_form_posts_cross_origin target=$target count=$_MK_FORMS_CROSS_ORIGIN - $_MK_FORMS_CROSS_ORIGIN POST form(s) submit to another origin and were NOT evaluated for an anti-CSRF token. Request validation for those submissions belongs to the receiving origin, which this run is not scanning."
  fi

  log_info "dast markup: target '$target' - parsed $parsed of $_MARKUP_N selected endpoint(s) for HTML security defects"
  return 0
}

_dast_markup_phase
