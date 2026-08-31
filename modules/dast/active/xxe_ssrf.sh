#!/usr/bin/env bash
# modules/dast/active/xxe_ssrf.sh - the §7.3 XXE / SSRF phase (docs/DESIGN.md
# §7.3; docs/STEP5-DAST-PLAN.md DAST-20, tier 4).
#
# THIS IS A PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`), so it inherits the whole run
# context and anything it emits lands in this process's shard. Per that
# function's contract it carries NO sourced-once guard. The shared, testable
# half lives in modules/dast/active/inject_engine.sh (the parameter
# inventory, the per-parameter request composer, `inject_send`), which this
# file reuses for its per-parameter SSRF technique; the two XML techniques
# below compose their OWN request (a full body override, not a single
# parameter substituted in place) because the injection point for an XXE
# probe is the WHOLE document, not one field of it.
#
# THREE CHECK IDS, THREE DIFFERENT SIGNALS (modules/dast/active/checks.rules):
#
#   DAST-INJ-XXE_ENTITY-01   an INTERNAL, general entity declared in a request
#                            body's own DOCTYPE is substituted and reflected
#                            back. This never leaves the process: no URL, no
#                            network activity beyond the one request itself.
#                            It proves the XML parser does not reject a
#                            DOCTYPE with an entity declaration - the
#                            necessary precondition for XXE - without proving
#                            SSRF impact. "The reachable sink"
#                            (docs/DESIGN.md §7.3's own phrase): medium
#                            confidence, flagged for manual review, nothing
#                            chased further.
#   DAST-INJ-XXE_SSRF-01     an EXTERNAL entity's SYSTEM identifier names the
#                            in-scope sentinel (see "SCOPE ENFORCEMENT"
#                            below); the response reflects a content
#                            signature this run independently fetched from
#                            that same sentinel, proving the parser fetched it
#                            and echoed the result back. High confidence, full
#                            impact demonstrated - the parser can be made to
#                            issue outbound requests server-side.
#   DAST-INJ-SSRF_PARAM-01   the identical in-scope sentinel URL, sent as an
#                            ORDINARY parameter value (no XML at all) via
#                            inject_engine's own per-parameter substitution,
#                            confirmed by the same content-signature match.
#                            Covers the "fetch this URL" feature shape (avatar
#                            import, webhook registration, URL preview, ...)
#                            that has nothing to do with XML parsing.
#
# Three ids rather than one because the DAST location profile (target,
# method, path_template, param_location, param_name) carries no component
# naming the DEFECT CLASS, and the three techniques exercise genuinely
# different code paths with genuinely different remediation - the same
# argument active/ssti.sh's four family ids and active/sqli.sh's three
# technique ids already make for their own siblings.
#
# ---------------------------------------------------------------------------
# SCOPE ENFORCEMENT AT PROBE TIME - the hard boundary this ticket exists to
# keep (docs/DESIGN.md §7.3: "detection via safe internal sentinels only, and
# only against in-scope hosts... never arbitrary metadata endpoints unless
# the operator explicitly opts in").
# ---------------------------------------------------------------------------
#
# THE VALUE THIS PROBE PUTS INTO THE TARGET'S REQUEST - THE ENTITY'S SYSTEM
# IDENTIFIER, OR THE PARAMETER'S VALUE - IS NEVER A HOST THIS SCRIPT INVENTS,
# NEVER AN OPERATOR-SUPPLIED ARBITRARY URL, AND NEVER 169.254.169.254 OR ANY
# OTHER CLOUD-METADATA ADDRESS. It is drawn EXCLUSIVELY from
# `lib/http.sh`'s own already-loaded scope-tuple set
# (`_HTTP_SCOPE_ID`/`_HTTP_SCOPE_SCHEME`/`_HTTP_SCOPE_HOST`/`_HTTP_SCOPE_PORT`,
# built by `http_scope_load` from config/scope.conf): the CURRENT target's own
# `base-url`, or - preferred, when the operator has declared one - one of that
# same target's `extra-host` entries (rules/RULE-FORMAT.md §9.4). Both are
# things the operator has ALREADY authorised this run to talk to; this probe
# widens nothing and invents nothing. `_xs_sentinel_set` is the one function
# that makes this choice, and it is the ONLY place in this file that decides
# what host the payload names - every other function receives that decision
# already made. There is no flag, config key, or environment variable that
# substitutes a different host: doing so would be handing an attacker-chosen
# destination to the very probe whose job is to prove the target does not
# already do that (the identical argument active/openredirect.sh's header
# makes for its own un-configurable sentinel).
#
# THE ACTUAL OUTBOUND SSRF/XXE CONNECTION IS MADE BY THE TARGET, NOT BY THIS
# SCANNER, AND SCOURSH DOES NOT AND CANNOT OBSERVE IT DIRECTLY - that is the
# whole nature of the vulnerability class. Two, and only two, network calls
# belong to scoursh itself in this whole file, and both go through the one
# chokepoint (`http_request`, `lib/http.sh`, tension 19) exactly like every
# other probe's traffic: (1) the ordinary request the target endpoint under
# test receives (the XML body, or the parameter carrying the sentinel URL),
# which is gated to the endpoint's own already-in-scope host precisely as
# every other injection probe's request is; and (2) the "oracle" fetch this
# script makes of the sentinel URL ITSELF, once per run, so it can compare a
# signature of what THAT host actually returns against what comes back from
# the endpoint under test. Because the oracle fetch's URL is built from the
# same already-loaded scope tuple, it always passes the gate - this is
# defence in depth, not the control that matters here. THE CONTROL THAT
# MATTERS is that the value handed to the target is never anything other than
# a host the operator put in config/scope.conf with their own hand.
#
# NO AFFIRMATION WIDENS THIS (docs/STEP5-DAST-PLAN.md's DAST-36 amendment for
# DAST-20): `--allow-intrusive`/`--i-own-target` govern whether this phase
# runs at all (tier `active`), never what host its payloads may name.
#
# WHEN NO `extra-host` IS DECLARED, the sentinel is the target's own
# `base-url` (a self-referential probe: "can this application make this
# application fetch its own front page"). That is still a fully safe,
# fully in-scope, fully operator-declared host, and it is what keeps this
# probe usable on the ordinary run that declares no extra-host at all -
# DAST-20's "operator-declared sentinel" is satisfied by the target
# declaration itself, and an `extra-host` is the strictly stronger,
# cross-host variant an operator can opt into by adding one line to
# config/scope.conf.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; DAST-36's amendment for
# DAST-14..DAST-25). Every payload is bounded and evidence-only: an internal
# entity substitutes a random label this process just minted, an external
# entity fetches nothing but a plain GET of an already-authorised host's root
# path, and the ONLY data ever read back is a short (<=96 byte) content
# signature - never a local file, never an internal service's private
# response, never anything beyond "did this URL's own already-known content
# come back". This probe stops at "the sink is reachable"; it never chases a
# metadata endpoint, a file read, or a second hop.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes XML/parameter syntax literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, exactly as every other §7.3 probe wires it.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# ---------------------------------------------------------------------------
# Check ids
# ---------------------------------------------------------------------------
_XS_CHECK_ENTITY=DAST-INJ-XXE_ENTITY-01
_XS_CHECK_XXE_SSRF=DAST-INJ-XXE_SSRF-01
_XS_CHECK_SSRF_PARAM=DAST-INJ-SSRF_PARAM-01

# `_xs_technique_selected CHECK_ID` - tension-15 per-check selection, guarded
# exactly as every sibling probe guards it (dast_check_selected does not exist
# in this build - see docs/STEP5-DAST-PLAN.md's DAST-08 landing note - so
# "unset" reads as "all selected", that function's own documented contract).
_xs_technique_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# The path component of a URL, query and fragment stripped, for the finding's
# location (path_template_of templates it further). A URL with no path is
# `/`. Duplicated in every §7.3 probe rather than shared, per that
# convention's own precedent (active/ssti.sh, active/pathtraversal.sh).
_xs_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# ---------------------------------------------------------------------------
# The in-scope sentinel (see this file's header, "SCOPE ENFORCEMENT")
# ---------------------------------------------------------------------------
# `_xs_sentinel_set TARGET` - sets `_XS_SENTINEL_URL` and `_XS_SENTINEL_HOST`
# to an already-authorised host for TARGET: an `extra-host` entry when one is
# declared (preferred - a genuinely different host than the target itself,
# which is what the "operator-declared sentinel" language in docs/DESIGN.md
# §7.3 is describing), else the target's own `base-url` (self-referential,
# still fully in scope). Returns 1 only when TARGET has no scope.conf entry
# at all, which should not happen for a target modules/dast/run.sh already
# resolved, but is handled rather than assumed.
_xs_sentinel_set() {
  local target=$1
  (( _HTTP_SCOPE_LOADED )) || http_scope_load
  _XS_SENTINEL_URL='' _XS_SENTINEL_HOST='' _XS_SENTINEL_IS_SELF=1
  local i n=${#_HTTP_SCOPE_ID[@]}
  local primary_host='' self_scheme='' self_host='' self_port=''
  local extra_scheme='' extra_host='' extra_port=''
  for (( i = 0; i < n; i++ )); do
    [[ ${_HTTP_SCOPE_ID[i]} == "$target" ]] || continue
    if [[ -z $primary_host ]]; then
      primary_host=${_HTTP_SCOPE_HOST[i]}
      self_scheme=${_HTTP_SCOPE_SCHEME[i]}
      self_host=${_HTTP_SCOPE_HOST[i]}
      self_port=${_HTTP_SCOPE_PORT[i]}
    elif [[ -z $extra_host && ${_HTTP_SCOPE_HOST[i]} != "$primary_host" ]]; then
      extra_scheme=${_HTTP_SCOPE_SCHEME[i]}
      extra_host=${_HTTP_SCOPE_HOST[i]}
      extra_port=${_HTTP_SCOPE_PORT[i]}
    fi
  done
  [[ -n $primary_host ]] || return 1

  local scheme host port
  if [[ -n $extra_host ]]; then
    scheme=$extra_scheme; host=$extra_host; port=$extra_port
    _XS_SENTINEL_IS_SELF=0
  else
    scheme=$self_scheme; host=$self_host; port=$self_port
    _XS_SENTINEL_IS_SELF=1
  fi
  local portsuf=''
  if { [[ $scheme == http && $port != 80 ]] || [[ $scheme == https && $port != 443 ]]; }; then
    portsuf=":$port"
  fi
  _XS_SENTINEL_HOST=$host
  _XS_SENTINEL_URL="$scheme://$host$portsuf/"
  return 0
}

# `_xs_xml_attr_escape TEXT` - escapes `&`, `"` and `<` for embedding TEXT
# inside a double-quoted XML attribute value (a SYSTEM identifier literal).
# `&` first, so the ampersands the other two substitutions introduce are never
# re-escaped.
_xs_xml_attr_escape() {
  local s=$1
  s=${s//&/&amp;}
  s=${s//\"/&quot;}
  s=${s//</&lt;}
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# The oracle: what does the sentinel itself actually return?
# ---------------------------------------------------------------------------
# `_xs_oracle_fetch TARGET` - fetches `_XS_SENTINEL_URL` exactly once per
# process (idempotent: a second call reuses the first result) through the
# ordinary `http_request` chokepoint, and derives a short content signature
# from the middle of the body. Sets `_XS_ORACLE_OK` (0/1) and, on success,
# `_XS_ORACLE_SIG`; on failure, `_XS_ORACLE_REASON`.
#
# THE SIGNATURE IS A SLICE FROM THE MIDDLE OF THE BODY, NOT THE START. A
# response's opening bytes are the most likely to be boilerplate shared
# across an entire site (a `<!DOCTYPE html>`, a common `<head>`), which is
# exactly the shape that would make a self-referential sentinel (see
# `_XS_SENTINEL_IS_SELF`) produce a spurious match against every OTHER
# endpoint's own baseline - not a wrong finding by itself, since every hit is
# still required to be ABSENT from that endpoint's own baseline first (see
# `_dast_xxe_ssrf_phase`'s "noisy" handling below), but a needlessly weak
# signature invites exactly that noise. A body shorter than
# `_XS_ORACLE_MIN_BYTES` is refused outright: too little content to be a
# reliable, non-generic signature.
_xs_oracle_fetch() {
  local target=$1
  (( _XS_ORACLE_DONE )) && { (( _XS_ORACLE_OK )) && return 0; return 1; }
  _XS_ORACLE_DONE=1 _XS_ORACLE_OK=0 _XS_ORACLE_SIG='' _XS_ORACLE_REASON=''

  [[ -n ${_XS_SENTINEL_URL:-} ]] || { _XS_ORACLE_REASON='no_sentinel_available'; return 1; }

  http_request_reset
  local bodyf=$SCOURSH_SCRATCH/xs.$$.oracle.body
  http_request_capture "$bodyf" ''
  local rc=0
  http_request GET "$_XS_SENTINEL_URL" 2 "$target" || rc=$?
  if (( rc != 0 )); then
    rm -f "$bodyf"
    _XS_ORACLE_REASON='sentinel_unreachable'
    return 1
  fi
  local body=''
  # Bounded AT READ TIME via `read -N`, reusing inject_engine.sh's own
  # `_INJ_MAX_BODY_BYTES` cap (this file sources inject_engine.sh, so it is
  # already in scope) - this read previously carried NO bound at all, worse
  # than the plain "trim after a full slurp" shape modules/dast/active/
  # discovery.sh's own `_discovery_probe` fixed, since even the after-the-fact
  # trim never ran here. The signature is a slice starting a QUARTER of the
  # way into `body` (see the comment above this function), so capping the
  # read changes what "a quarter of the way in" means only for a sentinel
  # response larger than the cap - an edge case, and still a real,
  # non-generic signature slice either way. `read -N` returns non-zero at EOF
  # for the ordinary case (a body smaller than the cap), so `|| true` stays
  # required, matching every other capped read in this codebase.
  if [[ -r $bodyf ]]; then
    IFS= read -r -N "$_INJ_MAX_BODY_BYTES" body <"$bodyf" || true
  fi
  rm -f "$bodyf"

  local blen=${#body}
  if (( blen < _XS_ORACLE_MIN_BYTES )); then
    _XS_ORACLE_REASON='sentinel_body_too_short_or_empty'
    return 1
  fi
  local off=$(( blen / 4 )) len=$_XS_ORACLE_SIG_LEN
  (( off + len > blen )) && off=$(( blen > len ? blen - len : 0 ))
  _XS_ORACLE_SIG=${body:off:len}
  if (( ${#_XS_ORACLE_SIG} < _XS_ORACLE_MIN_BYTES )); then
    _XS_ORACLE_REASON='sentinel_signature_too_short'
    return 1
  fi
  _XS_ORACLE_OK=1
  return 0
}

# `_xs_body_contains BODY SIG` - a plain, literal substring test (never a
# regex: the sentinel's own content may carry ERE metacharacters, and this is
# an exact-bytes comparison, not a pattern match). Empty SIG never matches, so
# an oracle that was never successfully fetched cannot manufacture a hit.
_xs_body_contains() {
  local body=$1 sig=$2
  [[ -n $sig && $body == *"$sig"* ]]
}

# ---------------------------------------------------------------------------
# The endpoint-level request: a full BODY OVERRIDE, not a parameter
# substitution
# ---------------------------------------------------------------------------
# `_xs_send_xml TARGET EPID XML` - sends EPID's own endpoint with every
# discovered sibling parameter (query/header/cookie/path) at its benign value
# exactly as inject_send composes them, but with the BODY REPLACED WHOLESALE
# by XML and Content-Type forced to `application/xml`. Any discovered
# body/formData sibling is dropped rather than merged in: this probe is
# testing whether the endpoint's XML PARSER is reachable at all, which is
# orthogonal to whatever body shape the crawler observed. Sets `_XS_STATUS`,
# `_XS_BODY` (bounded to inject_engine's own `_INJ_MAX_BODY_BYTES`) and
# `_XS_SENT_URL`. Returns 1 on a transport failure or an endpoint this file
# never heard of.
_xs_send_xml() {
  local target=$1 epid=$2 xml=$3
  local method=${_INJ_EP_METHOD[$epid]:-POST} base=${_INJ_EP_URL[$epid]:-} tmpl_path=${_INJ_EP_PATH[$epid]:-}
  _XS_STATUS='' _XS_BODY='' _XS_SENT_URL=''
  [[ -n $base ]] || return 1

  local -a query=() hdr_names=() hdr_values=()
  local cookie='' path_out=$tmpl_path
  local j jn jl jv enc
  for (( j = 0; j < _INJ_N; j++ )); do
    [[ -n $epid && ${_INJ_EPID[$j]} == "$epid" ]] || continue
    jn=${_INJ_NAME[$j]}; jl=${_INJ_LOCATION[$j]}
    jv=$(inject_benign_value "$j")
    case $jl in
      query)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        inject_urlencode "$jn"; query+=("$_INJ_ENC=$enc")
        ;;
      header)
        hdr_names+=("$jn"); hdr_values+=("$jv")
        ;;
      cookie)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        inject_urlencode "$jn"
        [[ -n $cookie ]] && cookie+='; '
        cookie+="$_INJ_ENC=$enc"
        ;;
      path)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        path_out=${path_out//"{$jn}"/$enc}
        base=${base//"{$jn}"/$enc}
        ;;
      body|formData) : ;;
    esac
  done

  local url=$base
  if [[ -n $path_out && $path_out != "$tmpl_path" ]]; then
    local authority=${base#*://} scheme=${base%%://*} slash=/
    authority=${authority%%/*}
    [[ ${path_out:0:1} == / ]] && slash=''
    url="$scheme://$authority$slash$path_out"
  fi
  if (( ${#query[@]} > 0 )); then
    local IFS='&'
    url="$url?${query[*]}"
  fi
  _XS_SENT_URL=$url

  http_request_reset
  if [[ -n ${_INJ_AUTH_TARGET:-} && -n ${_INJ_AUTH_LABEL:-} ]] \
    && declare -F dast_auth_apply >/dev/null; then
    dast_auth_apply "$_INJ_AUTH_TARGET" "$_INJ_AUTH_LABEL" || true
  fi
  local hi
  for (( hi = 0; hi < ${#hdr_names[@]}; hi++ )); do
    http_request_header "${hdr_names[$hi]}" "${hdr_values[$hi]}"
  done
  [[ -n $cookie ]] && http_request_header Cookie "$cookie"
  http_request_header Content-Type 'application/xml'
  http_request_body "$xml"

  local bodyf=$SCOURSH_SCRATCH/xs.$$.$epid.body
  http_request_capture "$bodyf" ''
  local maxred=${_INJ_MAX_REDIRECTS:-${SCOURSH_DAST_INJECT_MAX_REDIRECTS:-2}}
  [[ $maxred =~ ^[0-9]+$ ]] || maxred=2
  local rc=0
  http_request "$method" "$url" "$maxred" "$target" || rc=$?
  if (( rc != 0 )); then
    rm -f "$bodyf"
    return 1
  fi
  _XS_STATUS=$_HTTP_LAST_STATUS
  # Bounded AT READ TIME via `read -N`, not by a full slurp trimmed
  # afterward - see `_xs_oracle_fetch`'s identical comment above, and
  # modules/dast/active/discovery.sh's own `_discovery_probe` for the fix
  # this shape is copied from. `|| true` stays required for the ordinary
  # under-cap case, which is EOF for `read -N`.
  if [[ -r $bodyf ]]; then
    IFS= read -r -N "$_INJ_MAX_BODY_BYTES" _XS_BODY <"$bodyf" || true
  fi
  rm -f "$bodyf"
  return 0
}

# `_xs_marker_set` - a fresh random, per-call label under this project's own
# `scoursh-xxe-` prefix (no scan target named anywhere - docs/DESIGN.md §1;
# tests/lint-shell.sh's DAST-35 checks enforce this over every shipped file).
# RANDOM and never configurable, for the identical reason
# active/openredirect.sh's `_or_sentinel_set` gives for its own label: a
# response naming it can only have been produced by THIS request, which is
# what makes a single response sufficient evidence with no baseline needed.
_xs_marker_set() {
  local hex=''
  printf -v hex '%04x%04x%04x' "$(( RANDOM ))" "$(( RANDOM ))" "$(( RANDOM ^ $$ ))"
  _XS_MARKER="scoursh-xxe-${hex}"
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
_xs_emit_entity() {
  local url=$1 method=$2 marker=$3
  local target=${SCOURSH_DAST_TARGET:-} path authv=none
  path=$(_xs_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user

  finding_new
  finding_set check_id "$_XS_CHECK_ENTITY"
  finding_set module dast
  finding_set title 'XML parser processes a DOCTYPE-declared entity (candidate XXE sink)'
  finding_set base_severity medium
  finding_set confidence medium
  finding_set cwe CWE-611
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Disable DOCTYPE processing (or at minimum external general/parameter entity resolution) in every XML parser this endpoint can reach: for Java, set the JAXP/DocumentBuilderFactory/SAXParserFactory/XMLInputFactory FEATURE_SECURE_PROCESSING and disallow-doctype-decl features; for libxml2-based parsers (PHP, Python lxml, Ruby Nokogiri), do not pass LIBXML_NOENT/resolve_entities and load external entities; for .NET, use XmlReaderSettings with DtdProcessing.Prohibit. A parser that still substitutes an entity declared in the request body confirms these settings are not applied, which is the precondition for XML External Entity (XXE) attacks including SSRF and local file disclosure.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location body
  finding_set loc_param_name '(xml-entity-internal)'
  finding_set url "$url"
  finding_set_evidence "an XML request body containing '<!DOCTYPE scoursh [<!ENTITY x \"$marker\">]><scoursh>&x;</scoursh>' was sent to $method $path with Content-Type: application/xml, and the response body came back carrying the literal marker '$marker' - a random label this run generated fresh and that appears nowhere else. Substitution happened, which means the parser did not reject the DOCTYPE declaration and does expand a declared entity. This is the candidate sink docs/DESIGN.md §7.3 calls for: detection stopped here, no external entity or file reference was sent, and nothing beyond this one substitution was attempted."
  finding_emit
  return 0
}

_xs_emit_xxe_ssrf() {
  local url=$1 method=$2 sentinel_url=$3
  local target=${SCOURSH_DAST_TARGET:-} path authv=none
  path=$(_xs_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user

  finding_new
  finding_set check_id "$_XS_CHECK_XXE_SSRF"
  finding_set module dast
  finding_set title 'XML external entity causes the server to fetch an in-scope URL (XXE-driven SSRF)'
  finding_set base_severity critical
  finding_set confidence high
  finding_set cwe CWE-918
  finding_set owasp A10:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Disable external entity resolution in this endpoint'"'"'s XML parser (see DAST-INJ-XXE_ENTITY-01'"'"'s remediation for the per-platform settings) - this is the confirmed-impact case, not merely a candidate. Independently, apply an SSRF allow-list to any code path that lets request-derived data choose a server-side fetch destination: resolve the destination server-side, then require the resolved address to match an explicit allow-list of intended hosts before the fetch is issued, rejecting private/loopback/link-local ranges and any redirect that leaves the allow-listed set.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location body
  finding_set loc_param_name '(xml-entity-external)'
  finding_set url "$url"
  finding_set_evidence "an XML request body declaring an external entity SYSTEM \"$sentinel_url\" was sent to $method $path with Content-Type: application/xml, and the response body came back carrying a content signature this run independently fetched from that exact URL moments earlier - a signature absent from this same endpoint's own baseline response. The signature could only have reached the response by the server itself fetching '$sentinel_url' and returning what it found: this is a confirmed server-side fetch of request-controlled destination data (SSRF), reached via XML external entity processing. '$sentinel_url' is a host config/scope.conf already authorises this scan to reach; nothing beyond this URL was requested."
  finding_emit
  return 0
}

_xs_emit_ssrf_param() {
  local i=$1 sentinel_url=$2
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path authv=none
  path=$(_xs_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user

  finding_new
  finding_set check_id "$_XS_CHECK_SSRF_PARAM"
  finding_set module dast
  finding_set title 'Server-side request forgery via request parameter'
  finding_set base_severity critical
  finding_set confidence high
  finding_set cwe CWE-918
  finding_set owasp A10:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never let request-derived data choose a server-side fetch destination directly. Resolve the destination host server-side and require the RESOLVED address (not the string a client supplied) to match an explicit allow-list of intended hosts before issuing the fetch, reject private/loopback/link-local/CGN ranges outright, and re-validate on every redirect hop rather than trusting the first check alone.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "parameter '$name' ($loc) of $method $path was sent the value '$sentinel_url', and the response body came back carrying a content signature this run independently fetched from that exact URL moments earlier - a signature absent from this same parameter's own benign baseline response. The signature could only have reached the response by the server itself fetching '$sentinel_url' and returning what it found: a confirmed server-side fetch of a request-controlled URL (SSRF). '$sentinel_url' is a host config/scope.conf already authorises this scan to reach; nothing beyond this URL was requested."
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_xxe_ssrf_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/xxe_ssrf.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  : "${_XS_MAX_ENDPOINTS:=${SCOURSH_DAST_XXE_SSRF_MAX_ENDPOINTS:-100}}"
  : "${_XS_ORACLE_MIN_BYTES:=32}"
  : "${_XS_ORACLE_SIG_LEN:=96}"
  _XS_ORACLE_DONE=0

  # tension-15 per-check selection, one flag per technique. A run whose
  # filter chain excluded all three sends nothing at all.
  local sel_entity=1 sel_xxe_ssrf=1 sel_ssrf_param=1
  _xs_technique_selected "$_XS_CHECK_ENTITY" || sel_entity=0
  _xs_technique_selected "$_XS_CHECK_XXE_SSRF" || sel_xxe_ssrf=0
  _xs_technique_selected "$_XS_CHECK_SSRF_PARAM" || sel_ssrf_param=0
  local id
  for id in "$_XS_CHECK_ENTITY:$sel_entity" "$_XS_CHECK_XXE_SSRF:$sel_xxe_ssrf" "$_XS_CHECK_SSRF_PARAM:$sel_ssrf_param"; do
    [[ ${id##*:} == 0 ]] || continue
    run_record coverage_reduction "module=dast reason=check_not_selected check=${id%%:*} target=$target - excluded by --profile-scan/--intensity/--allow-intrusive filtering, so this XXE/SSRF technique was not probed."
  done
  if (( ! sel_entity && ! sel_xxe_ssrf && ! sel_ssrf_param )); then
    run_record coverage_gap "dast xxe_ssrf: every XXE/SSRF technique was excluded by the check filter on target '$target', so no probe was sent."
    return 0
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE -
  # see active/ssti.sh's own header for why (modules/dast/run.sh exports the
  # two paths before crawl.sh writes them, so the export is empty on the
  # ordinary first run).
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  local pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi
  inject_inventory_load "$epf" "$pf" xxe_ssrf

  if (( _INJ_N == 0 )) && (( ${#_INJ_EP_METHOD[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - the crawler wrote no endpoint or parameter (docs/INVENTORY-FORMAT.md), so XXE/SSRF had no request to compose. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable endpoints."
    run_record coverage_gap "dast xxe_ssrf: target '$target' has no known endpoint or parameter, so no XXE/SSRF probe was sent. This is a coverage gap, not a finding of safety."
    return 0
  fi

  # Optional authenticated pass, exactly as every other §7.3 probe wires it.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=xxe_ssrf target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  # The in-scope sentinel and its oracle signature - see this file's header
  # ("SCOPE ENFORCEMENT") for what this may and may not name.
  _xs_sentinel_set "$target" || true
  if [[ -z ${_XS_SENTINEL_URL:-} ]]; then
    if (( sel_xxe_ssrf || sel_ssrf_param )); then
      run_record coverage_reduction "module=dast reason=no_ssrf_sentinel_available target=$target - config/scope.conf has no resolvable base-url for this target, so external-entity/parameter SSRF confirmation ($_XS_CHECK_XXE_SSRF, $_XS_CHECK_SSRF_PARAM) could not run; internal-entity detection ($_XS_CHECK_ENTITY) is unaffected."
    fi
  elif (( sel_xxe_ssrf || sel_ssrf_param )); then
    _xs_oracle_fetch "$target" || true
    if (( ! _XS_ORACLE_OK )); then
      run_record coverage_reduction "module=dast reason=${_XS_ORACLE_REASON:-ssrf_sentinel_oracle_unavailable} target=$target sentinel=$_XS_SENTINEL_URL - could not establish a content signature from the in-scope SSRF sentinel, so external-entity/parameter SSRF confirmation was not attempted this run; internal-entity detection is unaffected."
    fi
  fi

  # ------------------------------------------------------------------------
  # Techniques 1 and 2: endpoint-level, full-body XML override.
  # POST/PUT/PATCH only - the methods whose semantics include a request body
  # (RFC 7231); GET/HEAD/DELETE bodies are undefined behaviour and a stated
  # gap, not a silent one (see the coverage_reduction below).
  # ------------------------------------------------------------------------
  local -a epids=()
  local _xs_epid_line
  while IFS= read -r _xs_epid_line; do
    [[ -n $_xs_epid_line ]] && epids+=("$_xs_epid_line")
  done < <(printf '%s\n' "${!_INJ_EP_METHOD[@]}" | LC_ALL=C sort)
  local epid method ep_tested=0 ep_truncated=0 ep_wrong_method=0 ep_baseline_failed=0
  local entity_executed=0 entity_found=0
  local xxe_ssrf_executed=0 xxe_ssrf_found=0 xxe_ssrf_noisy=0

  if (( sel_entity || sel_xxe_ssrf )); then
    for epid in "${epids[@]+"${epids[@]}"}"; do
      method=${_INJ_EP_METHOD[$epid]:-GET}
      case $method in
        POST|PUT|PATCH) ;;
        *) ep_wrong_method=$(( ep_wrong_method + 1 )); continue ;;
      esac
      if (( ep_tested >= _XS_MAX_ENDPOINTS )); then
        ep_truncated=$(( ep_truncated + 1 ))
        continue
      fi
      ep_tested=$(( ep_tested + 1 ))

      if ! _xs_send_xml "$target" "$epid" '<?xml version="1.0" encoding="UTF-8"?><scoursh>baseline</scoursh>'; then
        ep_baseline_failed=$(( ep_baseline_failed + 1 ))
        continue
      fi
      local baseline_body=$_XS_BODY

      if (( sel_entity )); then
        _xs_marker_set
        local xml1
        xml1=$(printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE scoursh [<!ENTITY x "%s">]><scoursh>&x;</scoursh>' "$_XS_MARKER")
        if _xs_send_xml "$target" "$epid" "$xml1"; then
          entity_executed=$(( entity_executed + 1 ))
          if _xs_body_contains "$_XS_BODY" "$_XS_MARKER"; then
            _xs_emit_entity "$_XS_SENT_URL" "$method" "$_XS_MARKER"
            entity_found=$(( entity_found + 1 ))
          fi
        fi
      fi

      if (( sel_xxe_ssrf )) && (( _XS_ORACLE_OK )); then
        if _xs_body_contains "$baseline_body" "$_XS_ORACLE_SIG"; then
          xxe_ssrf_noisy=$(( xxe_ssrf_noisy + 1 ))
        else
          local sys_url xml2
          sys_url=$(_xs_xml_attr_escape "$_XS_SENTINEL_URL")
          xml2=$(printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE scoursh [<!ENTITY x SYSTEM "%s">]><scoursh>&x;</scoursh>' "$sys_url")
          if _xs_send_xml "$target" "$epid" "$xml2"; then
            xxe_ssrf_executed=$(( xxe_ssrf_executed + 1 ))
            if _xs_body_contains "$_XS_BODY" "$_XS_ORACLE_SIG"; then
              _xs_emit_xxe_ssrf "$_XS_SENT_URL" "$method" "$_XS_SENTINEL_URL"
              xxe_ssrf_found=$(( xxe_ssrf_found + 1 ))
            fi
          fi
        fi
      fi
    done
  fi

  # ------------------------------------------------------------------------
  # Technique 3: per-parameter SSRF, reusing inject_engine's own composer.
  # ------------------------------------------------------------------------
  local ssrf_tested=0 ssrf_uninjectable=0 ssrf_noisy=0 ssrf_found=0 ssrf_executed=0
  if (( sel_ssrf_param )) && (( _XS_ORACLE_OK )); then
    local i loc base_val base_body
    for (( i = 0; i < _INJ_N; i++ )); do
      loc=${_INJ_LOCATION[$i]}
      if [[ $loc == graphql ]]; then
        ssrf_uninjectable=$(( ssrf_uninjectable + 1 ))
        continue
      fi
      base_val=$(inject_benign_value "$i")
      if ! inject_send "$i" "$base_val"; then
        ssrf_uninjectable=$(( ssrf_uninjectable + 1 ))
        continue
      fi
      base_body=$_INJ_BODY
      ssrf_tested=$(( ssrf_tested + 1 ))
      if _xs_body_contains "$base_body" "$_XS_ORACLE_SIG"; then
        ssrf_noisy=$(( ssrf_noisy + 1 ))
        continue
      fi
      if inject_send "$i" "$_XS_SENTINEL_URL"; then
        ssrf_executed=$(( ssrf_executed + 1 ))
        if _xs_body_contains "$_INJ_BODY" "$_XS_ORACLE_SIG"; then
          _xs_emit_ssrf_param "$i" "$_XS_SENTINEL_URL"
          ssrf_found=$(( ssrf_found + 1 ))
        fi
      fi
    done
  fi

  # --------------------------------------------------------------------
  # checks_run carries ONLY the ids whose payload actually went out at
  # least once; everything else is a named reduction (lib/records.sh's own
  # definition of checks_run, and DAST-29's own H3 lesson applied here).
  # --------------------------------------------------------------------
  if (( sel_entity )); then
    if (( entity_executed > 0 )); then
      run_record checks_run "$_XS_CHECK_ENTITY"
    else
      run_record coverage_reduction "module=dast reason=xxe_entity_not_executed check=$_XS_CHECK_ENTITY target=$target - no POST/PUT/PATCH endpoint in the inventory accepted a body-override request this run, so internal-entity XXE detection was not assessed."
    fi
  fi
  if (( sel_xxe_ssrf )); then
    if (( xxe_ssrf_executed > 0 )); then
      run_record checks_run "$_XS_CHECK_XXE_SSRF"
    else
      run_record coverage_reduction "module=dast reason=xxe_ssrf_not_executed check=$_XS_CHECK_XXE_SSRF target=$target - either no in-scope SSRF sentinel/oracle was available, no POST/PUT/PATCH endpoint existed, or every endpoint's baseline already carried the sentinel's own content signature (noisy), so XXE-driven SSRF confirmation was not assessed."
    fi
  fi
  if (( sel_ssrf_param )); then
    if (( ssrf_executed > 0 )); then
      run_record checks_run "$_XS_CHECK_SSRF_PARAM"
    else
      run_record coverage_reduction "module=dast reason=ssrf_param_not_executed check=$_XS_CHECK_SSRF_PARAM target=$target - either no in-scope SSRF sentinel/oracle was available, the discovered parameters were all GraphQL/path-uninjectable, or every baseline already carried the sentinel's own content signature (noisy), so per-parameter SSRF confirmation was not assessed."
    fi
  fi

  if (( ep_wrong_method > 0 )); then
    run_record coverage_reduction "module=dast reason=xxe_ssrf_non_body_method target=$target count=$ep_wrong_method - $ep_wrong_method discovered endpoint(s) use a method (GET/HEAD/DELETE/OPTIONS) whose body semantics are undefined by RFC 7231, so they were not tested with an XML body override."
  fi
  if (( ep_truncated > 0 )); then
    run_record coverage_gap "dast xxe_ssrf: the endpoint surface on target '$target' exceeded the per-probe cap of $_XS_MAX_ENDPOINTS, so $ep_truncated endpoint(s) were not tested for XXE. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( ep_baseline_failed > 0 )); then
    run_record coverage_reduction "module=dast reason=xxe_baseline_failed target=$target count=$ep_baseline_failed - $ep_baseline_failed endpoint(s) failed to answer even a benign XML baseline request (transport failure), so they were not tested for XXE."
  fi
  if (( xxe_ssrf_noisy > 0 )); then
    run_record coverage_reduction "module=dast reason=xxe_ssrf_noisy_baseline target=$target count=$xxe_ssrf_noisy - $xxe_ssrf_noisy endpoint(s) returned a BASELINE response that already carried the sentinel's own content signature, so a matching signature after injection could not be attributed to the request; they were skipped rather than reported."
  fi
  if (( ssrf_uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=ssrf_param_uninjectable target=$target count=$ssrf_uninjectable - $ssrf_uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for SSRF."
  fi
  if (( ssrf_noisy > 0 )); then
    run_record coverage_reduction "module=dast reason=ssrf_param_noisy_baseline target=$target count=$ssrf_noisy - $ssrf_noisy parameter(s) returned a BASELINE response that already carried the sentinel's own content signature, so a matching signature after injection could not be attributed to the request; they were skipped rather than reported."
  fi
  if (( ep_tested == 0 )) && (( sel_entity || sel_xxe_ssrf )); then
    run_record coverage_gap "dast xxe_ssrf: target '$target' had ${#epids[@]} discovered endpoint(s) but none used POST/PUT/PATCH, so no XML body-override probe was sent."
  fi
  if (( sel_ssrf_param )) && (( _XS_ORACLE_OK )) && (( ssrf_tested == 0 )); then
    run_record coverage_gap "dast xxe_ssrf: target '$target' had $_INJ_N discovered parameter(s) but none were injectable (or every baseline request failed), so no per-parameter SSRF probe was sent."
  fi

  log_info "dast xxe_ssrf: target '$target' - tested $ep_tested endpoint(s) for XXE ($entity_found internal-entity, $xxe_ssrf_found external-entity SSRF confirmed) and $ssrf_tested parameter(s) for SSRF ($ssrf_found confirmed)"
  return 0
}

_dast_xxe_ssrf_phase
