#!/usr/bin/env bash
# modules/dast/active/crlf.sh - the §7.3 CRLF / header-injection PHASE:
# inject an encoded CR/LF sequence into a request parameter and detect a
# resulting header split (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md
# DAST-23, tier 4).
#
# This is a PHASE SCRIPT, exactly like modules/dast/active/ldapi.sh:
# modules/dast/engine.sh's `dast_run_phase` reaches it with a plain `source`
# (at tier `active`, so it does not run below `--intensity active`), so it
# inherits the whole run context and anything it emits lands in this
# process's shard. Per that function's contract it carries NO sourced-once
# guard - one run can legitimately reach the same phase twice. The shared,
# testable half lives in modules/dast/active/inject_engine.sh (the inventory
# reader, the request composer, the one door to the network), which every
# §7.3 probe reuses; this file is the CRLF-specific part: the per-run marker,
# the candidate filter, and the two detections.
#
# THE SIGNAL, AND WHY IT NEEDS NO BASELINE. Like
# modules/dast/active/openredirect.sh's sentinel, this probe's marker (a
# header line and a body sentinel, both generated once per run from
# $RANDOM/$$) is put into a parameter and the response is asked one question:
# did that EXACT, per-run-random string reach the response? Nothing but this
# run's own request could have put it there, so a single confirmed response
# is sufficient evidence with no benign baseline to compare against.
#
# TWO CHECKS, NOT ONE, AND WHY THE SECOND IS SENT ONLY AFTER THE FIRST FIRES.
#   (a) header injection - an arbitrary, uniquely-named extra header survives
#       into the response's header block. Confirms CWE-113 with no further
#       claim.
#   (b) response splitting - a full second status line, closed with its own
#       blank line, plus a body sentinel checked for at the very FRONT of the
#       captured response body. If found there, this transport's own
#       header/body boundary moved to where the payload put it - proof that
#       request-controlled data can forge a complete second HTTP message,
#       which any cache or proxy in front of the target could split into and
#       serve separately (cache poisoning). This is the stronger, more
#       severely rated signal, and it SUBSUMES (a) on the same parameter: at
#       most one finding is emitted per parameter, the same discipline
#       modules/dast/passive/cors_engine.sh's own header states for its
#       credentialed-subsumes-plain case. Template (b) is sent only once
#       template (a) has already confirmed a signal - escalating a payload
#       against a parameter that has not even cleared the bare case would
#       spend a second request for nothing.
# See modules/dast/payloads/crlf-payloads.txt for the two vendored templates
# and the full reasoning for the placeholders they use.
#
# WHY THE `header` PARAMETER LOCATION IS NEVER A CANDIDATE, AND WHY THIS IS
# NOT OPTIONAL. `inject_send` (inject_engine.sh) routes a `header`-location
# parameter's value straight to `http_request_header`, which `die`s the
# WHOLE PROCESS (exit SCOURSH_EXIT_INPUT) the instant a value carries a CR or
# LF - it is refused there as request smuggling against THIS SCANNER's own
# outbound request, which is a different, unrelated protection than the one
# this probe is testing for on the TARGET. A `header`-location parameter is
# therefore skipped as uninjectable for this probe specifically (every other
# §7.3 probe can send it fine, because their payloads never contain a raw
# CR/LF byte); sending one here would abort the entire scan rather than
# merely fail this one check.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Detection-only. Nothing is written, nothing is changed,
# and nothing is exfiltrated beyond the minimal evidence that confirms the
# signal. `_INJ_MAX_REDIRECTS=0`: if the injected value forges a `Location`
# field, this probe never follows it, exactly as
# modules/dast/active/openredirect.sh never follows its own sentinel
# redirect - relying on the scope gate to refuse a hop is testing a control
# rather than using it.
#
# HONESTY. A clean result here must never read as "tested and safe" when it
# is "could not test": no parameter inventory, every discovered parameter
# being a `header`/`graphql` location, or a missing payload file are each
# recorded as a coverage_gap/coverage_reduction the report renders, exactly
# as modules/dast/active/ldapi.sh and openredirect.sh do for their own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes parameter and header syntax
#   literally, single-quoted on purpose.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For the response-header reader (`hdr_parse_capture`/`hdr_present`) - see
# that file's own header for why a later ticket that needs the same reader
# should source it rather than growing a second copy. Its sourced-once guard
# makes this a no-op when a passive header check already ran this process.
# shellcheck source=modules/dast/passive/headers_engine.sh
source "${BASH_SOURCE[0]%/*}/../passive/headers_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run
# attaches nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# `_crlf_read_payload_file FILE` - prints the file's payload lines (dropping
# whole-line `#` comments and blanks). Returns 1 when the file is unreadable,
# so a caller degrades the technique rather than erroring. Same helper, same
# contract, as modules/dast/active/ldapi.sh's `_ldapi_read_payload_file`.
_crlf_read_payload_file() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`. Same helper, same contract, as sibling probes' `_*_path_of`.
_crlf_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_crlf_marker_set` - sets this run's own random marker: a full header line
# (`_CRLF_MARKER_HEADER`, e.g. `X-Scoursh-Crlf-1a2b3c4d5e6f: 1`), the bare
# header NAME alone (`_CRLF_MARKER_NAME`, for `hdr_present`), and a body
# sentinel (`_CRLF_MARKER_BODY`). Not configurable, by design - see
# modules/dast/payloads/crlf-payloads.txt's own header for why a vendored or
# fixed value here would defeat the whole "no baseline needed" argument.
# `$RANDOM` mixed with `$$`, the same idiom and the same reasoning as
# modules/dast/active/openredirect.sh's `_or_sentinel_set`: this is a
# uniqueness-within-a-run label, not a secret.
_crlf_marker_set() {
  local hex=''
  printf -v hex '%04x%04x%04x' "$(( RANDOM ))" "$(( RANDOM ))" "$(( RANDOM ^ $$ ))"
  _CRLF_MARKER_NAME="X-Scoursh-Crlf-${hex}"
  _CRLF_MARKER_HEADER="${_CRLF_MARKER_NAME}: 1"
  _CRLF_MARKER_BODY="scoursh-crlf-split-${hex}"
}

# `_crlf_safe_text TEXT [MAX]` - bounded, single-line target-derived text for
# an evidence sentence. `finding_set_evidence` still does the real escaping
# and redaction (tension 9/10); this only stops one pathological value from
# dominating the sentence it appears in. Same helper, same contract, as
# openredirect.sh's `_or_safe_text`.
_crlf_safe_text() {
  local s=$1 max=${2:-200}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# `_crlf_header_present_in BLOB` - 0 when BLOB (a lib/http.sh header capture,
# ACCUMULATES every hop per lib/http.sh §9a) carries this run's marker header
# NAME anywhere in its final block, per hdr_parse_capture's own
# reset-on-status-line reading (modules/dast/passive/headers_engine.sh). A
# forged status line inside an injected value is itself a line that reading
# matches and resets on - which is the wanted behaviour here, not a bug: it
# means the marker header, sent AFTER the forged status line in template 2,
# is read as belonging to the (fake) final hop rather than being discarded,
# exactly as it would be read for a real trailing redirect hop.
_crlf_header_present_in() {
  local blob=$1 f
  [[ -n $blob ]] || return 1
  f=$SCOURSH_SCRATCH/crlf.$$.hdrs
  printf '%s' "$blob" >"$f"
  hdr_parse_capture "$f" || { rm -f "$f"; return 1; }
  rm -f "$f"
  hdr_present "$_CRLF_MARKER_NAME"
}

# `_crlf_body_split BODY` - 0 when BODY starts, after any leading whitespace
# (the class a CR/LF/space run belongs to), with this run's body sentinel.
# Requiring the sentinel at the FRONT rather than merely present anywhere in
# BODY is what tells a real response split apart from an application that
# merely echoes the whole raw (rejected) parameter value into an error page:
# an HTML error page has boilerplate before any reflected text, so the
# sentinel would not be the first thing in the body; a real split puts it
# there because the transport's own header/body boundary moved to
# immediately in front of it.
_crlf_body_split() {
  local body=$1 trimmed
  [[ -n $body ]] || return 1
  trimmed=${body#"${body%%[![:space:]]*}"}
  [[ $trimmed == "$_CRLF_MARKER_BODY"* ]]
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# TWO CHECK IDS, NOT ONE, FOR THE REASON openredirect.sh's own two ids exist:
# the DAST location profile is (target, method, path_template, param_location,
# param_name) and carries nothing naming which SIGNAL fired, so a bare header
# injection and a full response split on the same parameter would fingerprint
# identically and findings_merge would silently keep one. They are graded
# differently for good reason too: a bare extra header is a header-injection
# primitive whose impact depends on what the application does with it, while a
# confirmed response split is a forged complete HTTP message any downstream
# cache or proxy can act on independently of this application's own logic.
_crlf_emit() {
  local i=$1 sink=$2 payload=$3
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title base conf evi authv=none
  path=$(_crlf_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $sink in
    header)
      check=DAST-INJ-CRLF_HEADER_INJECTION-01; base=high; conf=high
      title='CRLF injection - request parameter reaches raw HTTP response header construction'
      evi="parameter '$name' ($loc) of $method $path was sent the value '$(_crlf_safe_text "$payload")' containing an encoded CR/LF followed by the header line '$_CRLF_MARKER_HEADER'; that exact, per-run-random header name appeared in the response's own header block. Only this run's own request can have put that name there, so request-derived data reaches raw HTTP response header construction without escaping the CR/LF sequence." ;;
    split)
      check=DAST-INJ-CRLF_RESPONSE_SPLITTING-01; base=critical; conf=high
      title='CRLF injection allows a full forged second HTTP response (response splitting)'
      evi="parameter '$name' ($loc) of $method $path was sent the value '$(_crlf_safe_text "$payload")' containing an encoded CR/LF, a forged 'HTTP/1.1 200 OK' status line, the header line '$_CRLF_MARKER_HEADER', and a closing blank line followed by the body sentinel '$_CRLF_MARKER_BODY'; the marker header appeared in the response's header block AND the sentinel appeared at the very front of the response body, which means the header/body boundary moved to where this payload put it. Only this run's own request can have produced that exact sentinel placement, so request-derived data can forge a complete second HTTP message - a cache or proxy in front of this target could split it into and serve as a separate response." ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe CWE-113
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never build a response header by concatenating request-derived data into raw header text. Use the web framework or HTTP library'"'"'s own header-setting API, which refuses or strips an embedded CR/LF, rather than writing a header line by hand. Strip or reject CR and LF from any request-derived value before it can reach header construction, and encode values placed into a redirect target, a cookie, or any other reflected header field.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

_dast_crlf_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/crlf.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored templates. SCOURSH_DAST_CRLF_PAYLOAD_DIR overrides the
  # location so an operator can vendor a custom set (the same swappable-seam
  # idiom every sibling probe's own payload-dir override uses) and so the
  # graceful-degradation branch is testable against an empty directory;
  # unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_CRLF_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  local line
  _CRLF_TEMPLATES=()
  while IFS= read -r line; do _CRLF_TEMPLATES+=("$line"); done \
    < <(_crlf_read_payload_file "$pdir/crlf-payloads.txt" || true)

  local do_crlf=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it. Consulted only if that function exists (guarded exactly as
  # every sibling probe guards it), so this file does not hard-depend on it:
  # absent, everything the tier already permitted runs. Both check ids share
  # one gate here because they come from the SAME probe pass on the SAME
  # parameter (technique 2 only ever runs after technique 1 fires), unlike
  # openredirect.sh's two genuinely independent sinks evaluated every time.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-CRLF_HEADER_INJECTION-01 || do_crlf=0
    if (( do_crlf == 0 )) && dast_check_selected DAST-INJ-CRLF_RESPONSE_SPLITTING-01; then
      do_crlf=1
    fi
  fi

  if (( ${#_CRLF_TEMPLATES[@]} < 2 )); then
    do_crlf=0
    run_record coverage_reduction "module=dast reason=crlf_payloads_missing target=$target - modules/dast/payloads/crlf-payloads.txt is absent, empty, or missing one of its two templates, so no CRLF/header-injection probe could be composed. This is a coverage reduction, not a clean result."
    run_record coverage_gap "dast crlf: no CRLF/header-injection payload templates are available on target '$target', so nothing was probed. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi
  if (( do_crlf == 0 )); then
    run_record coverage_gap "dast crlf: every CRLF/header-injection check was filtered out of this run's check set on target '$target', so nothing was probed."
    return 0
  fi

  # modules/dast/run.sh resolves SCOURSH_DAST_ENDPOINTS/SCOURSH_DAST_PARAMETERS
  # BEFORE the phase loop starts while modules/dast/crawl.sh writes them
  # several phases LATER in that same loop, so on the ordinary run the exports
  # are empty on exactly the run that has just discovered a surface. The
  # run-directory artifact is read as a fallback, the same fix (and the same
  # paths) every sibling probe applies for itself.
  local epf=${SCOURSH_DAST_ENDPOINTS:-} pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi
  inject_inventory_load "$epf" "$pf" crlf
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so the CRLF/header-injection probe had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast crlf: target '$target' has no known request parameters, so no CRLF/header-injection probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained at least one session this run; otherwise the probe runs against
  # the public surface and attaches nothing.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=crlf target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  _crlf_marker_set
  # The two opt-in engine knobs (inject_engine.sh section 0a): every request
  # this probe sends wants the response headers, and none of them may follow
  # a redirect a forged Location field might create.
  _INJ_WANT_HEADERS=1
  _INJ_MAX_REDIRECTS=0

  local i loc base_val tmpl1 tmpl2 v1 v2 tested=0 uninjectable=0 fired=0
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    # graphql is a structured operation body, not a scalar this probe
    # substitutes one field of; header is refused for the reason this file's
    # own header explains at length - sending a CR/LF-carrying value there
    # would abort the whole scan, not just this one check.
    if [[ $loc == graphql || $loc == header ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_val=$(inject_benign_value "$i")

    tmpl1=${_CRLF_TEMPLATES[0]}
    v1=${tmpl1//%B/$base_val}
    v1=${v1//%NL/$'\r\n'}
    v1=${v1//%H/$_CRLF_MARKER_HEADER}
    v1=${v1//%K/$_CRLF_MARKER_BODY}

    if ! inject_send "$i" "$v1"; then
      # An uninjectable location this probe did not already know to skip (a
      # path parameter with no template slot) or a transport failure: nothing
      # to test.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    tested=$(( tested + 1 ))

    if ! _crlf_header_present_in "$_INJ_HEADERS"; then
      continue
    fi

    # Template 1 already confirmed the marker header survives; escalate with
    # template 2 to see whether the same parameter forges a full second
    # response, and report whichever signal this second request actually
    # produced.
    tmpl2=${_CRLF_TEMPLATES[1]}
    v2=${tmpl2//%B/$base_val}
    v2=${v2//%NL/$'\r\n'}
    v2=${v2//%H/$_CRLF_MARKER_HEADER}
    v2=${v2//%K/$_CRLF_MARKER_BODY}

    if inject_send "$i" "$v2" \
      && _crlf_header_present_in "$_INJ_HEADERS" \
      && _crlf_body_split "$_INJ_BODY"; then
      _crlf_emit "$i" split "$v2"
    else
      _crlf_emit "$i" header "$v1"
    fi
    fired=$(( fired + 1 ))
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up
  # reads - recorded only when at least one parameter was really probed, so a
  # run with a parameter surface but no candidate in it is not reported as
  # covered. Both ids are recorded together: they come from one probe pass,
  # and which one fires is a property of the RESULT, not of what was tested.
  if (( tested > 0 )); then
    run_record checks_run DAST-INJ-CRLF_HEADER_INJECTION-01
    run_record checks_run DAST-INJ-CRLF_RESPONSE_SPLITTING-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast crlf: the parameter surface on target '$target' exceeded the shared per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) never reached this probe at all. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=crlf_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation, a header-location parameter (refused here to avoid aborting this scanner's own outbound request), a path segment with no template slot this probe could substitute, or an endpoint every request to which failed at the transport; they were not tested for CRLF injection here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast crlf: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every request failed), so no CRLF-injection test was sent."
  fi

  log_info "dast crlf: target '$target' - tested $tested of $_INJ_N parameter(s) for CRLF/header injection, $fired confirmed signal(s)"
  return 0
}

_dast_crlf_phase
