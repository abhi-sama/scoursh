#!/usr/bin/env bash
# modules/dast/active/hosthdr_engine.sh - the DAST-24 Host-header-injection
# check's pure function library (docs/DESIGN.md §7.3 "Host-header injection
# (`hosthdr.sh`) - send a spoofed `Host`/`X-Forwarded-Host`; flag if it's
# reflected into links, redirects, or password-reset URLs (cache-poisoning /
# reset-poisoning risk)."; docs/STEP5-DAST-PLAN.md DAST-24, tier 4).
#
# WHAT THIS FILE IS. Every piece of DAST-24 that can be exercised with no
# network: the sentinel, the response reader, the two reflection detectors,
# and finding emission. modules/dast/active/hosthdr.sh is the phase script
# that resolves the live input (the endpoint list crawl.sh wrote) and drives
# this file - the engine/phase split modules/sast/ established, reused
# exactly as cors_engine.sh/cors.sh already reuse it for a sibling
# request-a-header-and-classify-the-response check.
#
# NON-DESTRUCTIVE, PER §7.3's OWN AMENDMENT (DAST-36: "no data modification,
# no destructive action"). Every probe is a GET or HEAD the crawler already
# inventoried, carrying one extra request header; nothing is written, no form
# is submitted, and no discovered POST endpoint is ever requested. The one
# thing this check deliberately does NOT do is confirm "reset-poisoning" by
# actually triggering a password-reset flow: that needs a POST to a reset
# endpoint and, on a real target, sends a real email - a stateful, external
# side effect exactly as far out of scope as DAST-03's own declined "live"
# user-enumeration probe. What this check proves instead is the ROOT CAUSE
# §7.3's bullet names for all three sinks alike: that the server trusts a
# client-supplied Host/X-Forwarded-Host value when it builds an absolute URL
# at all. A password-reset link built the same way inherits the identical
# defect, which is why a passive reflection signal here is the right-sized
# proof for this ticket rather than reproducing the reset flow.
#
# TWO SINKS, TWO CHECK IDS (modules/dast/active/checks.rules), FOR THE REASON
# openredirect.sh's own header/meta split gives: the DAST location profile
# (target, method, path_template, param_location, param_name) carries nothing
# naming the SINK, so a body-reflection hit and a Location-reflection hit on
# one endpoint would collide onto one fingerprint and findings_merge would
# silently keep one. The HEADER TECHNIQUE (Host vs X-Forwarded-Host) is NOT a
# third id: it is carried in `loc_param_name`, exactly as cors_engine.sh
# carries its Origin probe in `loc_param_name=Origin` - the location profile
# already has a slot for "which request field", and a technique the profile
# can express does not need a second check id to stay distinct.
#
#   DAST-HOSTHDR-REFLECTED_BODY-01      the sentinel host appears anywhere in
#                                       the response body (an absolute link,
#                                       a cache-busted asset URL, a canonical
#                                       tag, ...). Matched as a SUBSTRING,
#                                       deliberately, and that is the one
#                                       design choice in this file most
#                                       worth defending: see
#                                       `hh_body_reflects` below.
#   DAST-HOSTHDR-REFLECTED_LOCATION-01  the sentinel is the AUTHORITY of the
#                                       response's `Location` header - parsed,
#                                       never matched as a substring, for
#                                       the identical false-positive reason
#                                       openredirect.sh's own `_or_url_host`
#                                       exists (see `hh_url_host` below).
#
# WHY THE BODY CHECK IS A SUBSTRING TEST AND THE LOCATION CHECK IS NOT, EVEN
# THOUGH BOTH LOOK FOR THE SAME STRING. openredirect.sh's whole argument
# against a substring test is that the payload it injects is a REALISTIC URL
# value flowing through a REQUEST PARAMETER the application may legitimately
# echo elsewhere (`?next=https://sentinel/` reflected into the page, or into
# an on-origin Location's own query string, is a common SAFE shape). Nothing
# here is analogous: the sentinel is injected ONLY as the value of a `Host` or
# `X-Forwarded-Host` REQUEST HEADER, which is not a value this probe also
# places in the URL, the query string, or the body it sends - there is no
# other place in the request the target could have copied it from. Wherever
# it appears in the response, it can only have arrived there because the
# server read the spoofed header and used it, so a substring match carries no
# realistic false-positive risk in the body, where the string can legitimately
# show up in many different HTML positions (an `<a href>`, a `<link
# rel="canonical">`, an inlined cache key, an Open-Graph tag, ...) that would
# be expensive to enumerate one at a time for no gain in precision. The
# `Location` header is different in kind, not degree: it has exactly ONE
# authority, that authority is the concrete redirect destination a browser (or
# a bare HTTP client) will actually go to, and the finding's own claim is "this
# response redirects to a host we control" - a claim a substring hit cannot
# support (the sentinel could just as easily sit in an on-origin `Location`'s
# own query string, exactly as it can for openredirect.sh, if this response
# happens to reflect request context into it), so it is held to the same
# authority-only, WHATWG-shaped parser openredirect.sh already proved correct.
#
# EVERY REQUEST GOES THROUGH `http_request` (docs/FOUNDATION.md tension 19),
# so the scope gate, DAST-01's rate limiter, the per-run request budget, the
# circuit breaker and DAST-32's ceilings all bind it. There is no second path
# to the network in this file.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes header/URL syntax literally,
#   single-quoted on purpose.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_HOSTHDR_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_HOSTHDR_ENGINE_SOURCED=1

# lib/http.sh only when an outer caller has not already sourced it - scan.sh
# sources it at top level before `scan_dispatch`, so in a real run this is a
# no-op, and the conditional is what lets a standalone test source THIS file
# directly. Same shape, same reason, as cors_engine.sh's own guard.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# passive/response_engine.sh for the shared response-header reader
# (hdr_parse_capture / hdr_present / hdr_first). It resets on every
# `HTTP/x.y NNN` status line because http_request_capture's header sink
# ACCUMULATES every redirect hop (lib/http.sh §9a) - the identical trap
# cors_header_last and _or_location_of each independently defend against. This
# used to name passive/headers_engine.sh, DAST-05's own file; the reader has
# since been lifted into a leaf module of its own that sources nothing, so an
# active-tier probe that only reads a header block no longer drags in that
# ticket's CSP/HSTS parsers and endpoint chooser to do it. No call site changed.
# shellcheck source=modules/dast/passive/response_engine.sh
source "${BASH_SOURCE[0]%/*}/../passive/response_engine.sh"

# ---------------------------------------------------------------------------
# 1. The sentinel
# ---------------------------------------------------------------------------
# The header value the probe injects. Two properties, each load-bearing:
#
#   RESERVED. `.example` is reserved by RFC 2606 §2 / RFC 6761 §6.5, so it
#   names nothing that exists and nothing an operator could accidentally
#   attack - the identical property cors_engine.sh's own sentinel origin
#   relies on.
#   UNMISTAKABLE. It is a garbage label no real target's configuration would
#   ever legitimately answer with, which is what makes a bare substring hit
#   in the body meaningful evidence rather than a coincidence.
#
# Overridable by SCOURSH_DAST_HOSTHDR_SENTINEL for the same reason
# cors_engine.sh's CORS_SENTINEL_ORIGIN is overridable - so a test can prove
# the classifier is comparing against the CONFIGURED sentinel rather than a
# hardcoded literal it happens to agree with. It is not a documented operator
# knob and has no config key: the value is an implementation detail of the
# probe, not a policy.
HOSTHDR_SENTINEL=${SCOURSH_DAST_HOSTHDR_SENTINEL:-scoursh-hosthdr-probe.example}

# The two header techniques §7.3's own bullet names, tried independently so a
# server that trusts one and not the other is still caught. Order is the
# order findings are considered in, and is otherwise not meaningful.
declare -ga HOSTHDR_TECHNIQUES=(Host X-Forwarded-Host)

# ---------------------------------------------------------------------------
# 2. Bounds (docs/DESIGN.md §15: a bound that truncates silently is
# indistinguishable from a surface that was really that small, so each one
# records a coverage_gap/coverage_reduction when it bites - the phase script
# does that; this file only enforces the bound).
# ---------------------------------------------------------------------------
# Distinct routes probed in one run.
: "${_HH_MAX_ENDPOINTS:=25}"
# Bytes of a response body read for the substring scan. A whole-page HTML
# response is comfortably under this; a multi-megabyte asset is not read past
# it, and the phase records the truncation as a coverage_reduction rather than
# silently reporting a partial scan as a complete one.
: "${_HH_MAX_BODY_BYTES:=1048576}"
# Bytes of a Location/evidence value carried into a finding sentence.
: "${_HH_MAX_EVIDENCE_FIELD:=200}"

# `_hh_safe_text TEXT [MAX]` - bounded, single-line target-derived text for an
# evidence sentence. `finding_set_evidence` still does the real escaping and
# redaction (tension 9/10); this only stops one pathological header or body
# snippet from dominating the sentence it appears in. Same helper, same
# contract, as openredirect.sh's `_or_safe_text`.
_hh_safe_text() {
  local s=$1 max=${2:-$_HH_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# 3. URL authority parsing for the Location sink - a duplicate of
# openredirect.sh's own `_or_url_host`/`_or_host_is_sentinel`, not a shared
# call. openredirect.sh is a PHASE SCRIPT (it invokes its own phase function
# at source time, per modules/dast/engine.sh's contract), so sourcing it here
# would run open-redirect's whole probe as a side effect of loading this file
# - there is no engine-only file to reuse it from. The logic itself, and every
# property it exists to get right, is copied verbatim from that proven
# implementation rather than re-derived: WHATWG backslash folding, the split
# on the LAST `@` (userinfo), IPv6-bracket-aware port stripping, and a
# lowercased result. See openredirect.sh's own header comment for the full
# argument each line defends against; it is not repeated here.
# ---------------------------------------------------------------------------
# `hh_url_host URL` - sets `_HH_HOST` to the lowercased HOST of URL and
# returns 0; returns 1 (leaving `_HH_HOST` empty) for a URL with no authority
# at all, which includes every relative `Location` - the ordinary, safe case.
hh_url_host() {
  local u=$1 authority rest
  _HH_HOST=''
  u=${u#"${u%%[![:space:]]*}"}
  u=${u%"${u##*[![:space:]]}"}
  [[ -n $u ]] || return 1
  u=${u//\\//}

  if [[ $u == //* ]]; then
    rest=${u#//}
  elif [[ $u =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]]; then
    rest=${u#*:}
    [[ $rest == /* ]] || return 1
    rest=${rest#"${rest%%[!/]*}"}
  else
    return 1
  fi

  authority=${rest%%[/?#]*}
  [[ -n $authority ]] || return 1
  authority=${authority##*@}
  if [[ $authority == \[*\]* ]]; then
    authority=${authority%%\]*}
    authority=${authority#\[}
  else
    authority=${authority%%:*}
  fi
  [[ -n $authority ]] || return 1
  _HH_HOST=${authority,,}
  return 0
}

# `hh_host_is_sentinel HOST` - 0 when HOST is the sentinel exactly (case
# folded). Unlike openredirect.sh's own `_or_host_is_sentinel` there is no
# subdomain arm: this probe never places the sentinel inside a larger value a
# target could prefix (it is a whole Host header, not one component of a URL
# a payload template built), so exact equality is the correct - and simplest
# - reading here.
hh_host_is_sentinel() {
  local h=${1,,}
  [[ $h == "${HOSTHDR_SENTINEL,,}" ]]
}

# ---------------------------------------------------------------------------
# 4. The two sinks
# ---------------------------------------------------------------------------
# `hh_location_reflects HEADER_FILE` - 0 when the final response's `Location`
# authority is the sentinel. Sets `_HH_LOCATION` to the raw header value for
# the evidence sentence.
hh_location_reflects() {
  local f=$1
  _HH_LOCATION=''
  hdr_parse_capture "$f" || return 1
  hdr_present Location || return 1
  hdr_first Location
  _HH_LOCATION=$_HDR_V
  [[ -n $_HH_LOCATION ]] || return 1
  hh_url_host "$_HH_LOCATION" || return 1
  hh_host_is_sentinel "$_HH_HOST"
}

# `hh_body_reflects BODY_FILE` - 0 when the sentinel appears anywhere in the
# first `_HH_MAX_BODY_BYTES` of BODY_FILE. Sets `_HH_BODY_TRUNCATED` to 1 when
# the file was larger than that cap, so the caller can record the bound
# rather than silently reporting a partial read as a complete scan (the same
# honesty leakage_engine.sh's own bundle-chunking note asks for, applied here
# as a hard cap rather than a chunk walk because a page this check reads is
# ordinarily whole-document HTML rather than a multi-megabyte bundle).
#
# A PLAIN BASH SUBSTRING TEST, NOT `scan_match`. The sentinel is this file's
# own literal (never target-derived text, tension 9/10's concern is about the
# opposite direction), so there is no regex-injection risk to guard against
# by routing it through the pattern engine, and `[[ $body == *"$sentinel"* ]]`
# is the same literal-substring idiom openredirect.sh's own candidate filter
# and cors_engine.sh's classifier already use for a fixed, self-authored
# needle. Case-folded because a hostname is case-insensitive by definition and
# a target may lowercase (or, per HTTP/2, be required to lowercase) a header
# value before it echoes it.
hh_body_reflects() {
  local f=$1 size body
  _HH_BODY_TRUNCATED=0
  [[ -s $f ]] || return 1
  size=$(wc -c <"$f" 2>/dev/null) || size=0
  size=${size//[[:space:]]/}
  [[ $size =~ ^[0-9]+$ ]] || size=0
  if (( size > _HH_MAX_BODY_BYTES )); then
    _HH_BODY_TRUNCATED=1
    body=$(head -c "$_HH_MAX_BODY_BYTES" -- "$f" 2>/dev/null) || body=''
  else
    body=$(cat -- "$f" 2>/dev/null) || body=''
  fi
  [[ ${body,,} == *"${HOSTHDR_SENTINEL,,}"* ]]
}

# ---------------------------------------------------------------------------
# 5. The probe
# ---------------------------------------------------------------------------
# `hh_probe TARGET METHOD URL HEADER_NAME` - send ONE request carrying
# `HEADER_NAME: <sentinel>` and set:
#
#   _HH_STATUS   the HTTP status ('' on a transport-level failure)
#   _HH_BODY_REFLECTED / _HH_LOCATION_REFLECTED   1/0
#   _HH_LOCATION       the raw Location value, when present
#   _HH_BODY_TRUNCATED 1 when the body exceeded the scan cap
#
# Returns 1 on a transport-level failure (breaker open, budget spent,
# resolution failure), which the caller must treat as "not tested", never as
# "no reflection" - cors_engine.sh's `cors_probe` makes the identical
# distinction for the identical reason.
#
# max_redirects 0: a redirect is never followed, both because the finding is
# about the Location VALUE itself (following it teaches nothing new) and
# because lib/http.sh drops every caller header on a cross-origin hop anyway,
# so a followed hop would arrive with no spoofed header at all.
hh_probe() {
  local target=$1 method=$2 url=$3 header=$4
  local bodyfile hdrfile
  _HH_STATUS='' _HH_BODY_REFLECTED=0 _HH_LOCATION_REFLECTED=0
  _HH_LOCATION='' _HH_BODY_TRUNCATED=0

  # `mktemp`, never a name built from $BASHPID: lib/http.sh's own
  # `_http_transport_default` idiom, for the CWE-377/CWE-59 reason
  # cors_header_last's own header states in full - this path falls back to a
  # world-writable /tmp whenever SCOURSH_SCRATCH is unset (every standalone
  # caller, including this repository's own tests), and a pid-derived name is
  # predictable. It also receives the target's own response, which should not
  # land wherever a local user chose to pre-place a symlink.
  bodyfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/hosthdr-body.XXXXXX")
  hdrfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/hosthdr-hdr.XXXXXX")
  chmod 600 "$bodyfile" "$hdrfile" 2>/dev/null || true

  http_request_reset
  http_request_header "$header" "$HOSTHDR_SENTINEL"
  http_request_capture "$bodyfile" "$hdrfile"
  if ! http_request "$method" "$url" 0 "$target"; then
    rm -f "$bodyfile" "$hdrfile"
    return 1
  fi
  _HH_STATUS=$_HTTP_LAST_STATUS

  hh_location_reflects "$hdrfile" && _HH_LOCATION_REFLECTED=1
  hh_body_reflects "$bodyfile" && _HH_BODY_REFLECTED=1

  rm -f "$bodyfile" "$hdrfile"
  return 0
}

# ---------------------------------------------------------------------------
# 6. Emitting a finding
# ---------------------------------------------------------------------------
# One helper so every hosthdr finding carries the same DAST location profile
# (docs/FOUNDATION.md tension 5) and only the id/title/severity/evidence vary.
# `loc_param_location` is `header` and `loc_param_name` is the technique
# (`Host` or `X-Forwarded-Host`) - the request field this check varies is
# that header, so the same weakness reached through both techniques on one
# endpoint stays two findings, exactly as cors_engine.sh's own emit helper
# argues for `Origin`.
hh_emit_finding() {
  local check_id=$1 title=$2 severity=$3 confidence=$4
  local target=$5 method=$6 url=$7 path=$8 header=$9 evidence=${10}
  local remediation=${11}

  finding_new
  finding_set check_id "$check_id"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence "$confidence"
  finding_set cwe CWE-807
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location header
  finding_set loc_param_name "$header"
  finding_set url "$url"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

hh_remediation_body() {
  printf '%s' 'Do not build an absolute URL, a canonical link, an asset reference or any other response content from the incoming Host or X-Forwarded-Host header. Compute the application origin from a server-side configuration value (or from a fixed, operator-set allow-list of expected Host values, rejecting any request whose Host does not match one) rather than from client-supplied transport headers. Where a reverse proxy is expected to set X-Forwarded-Host, strip or overwrite any value the client itself supplied before it reaches the application, and never trust it from a request that did not traverse that proxy.'
}

hh_remediation_location() {
  printf '%s' 'Do not construct a redirect Location from the incoming Host or X-Forwarded-Host header. Build the redirect against a server-side configuration value for this application'"'"'s own origin, never against a client-supplied transport header, and apply the same fixed allow-list of expected Host values recommended for response-body construction. This is the same defect class that makes a password-reset link, a cache key, or any other absolute URL the application builds from the Host header poisonable by whoever sends the request.'
}
