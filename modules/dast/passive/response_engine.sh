#!/usr/bin/env bash
# modules/dast/passive/response_engine.sh - the HTTP response reader every DAST
# check that looks at a response head shares.  Lifted out of
# modules/dast/passive/headers_engine.sh, which asked for exactly this once it
# had a second consumer.
#
# ADR: the shared response reader is its own LEAF module, and keeps the `hdr_`
#      prefix.
# Context: `hdr_parse_capture` and friends were written for DAST-05 and lived in
#      `passive/headers_engine.sh`.  Six landed files now need them -
#      `passive/headers.sh`, `passive/leakage_engine.sh`,
#      `passive/transport_engine.sh`, `active/crlf.sh`,
#      `active/hosthdr_engine.sh` and `ratelimit_engine.sh` - so five of them
#      sourced a file named for, and owned by, one ticket, and four dragged in
#      that ticket's CSP/HSTS/Referrer parsers, its recommended-header loader,
#      its endpoint chooser, `lib/http.sh` and `crawl_engine.sh` merely to read
#      a header block.  `shellcheck -x` re-expands every source edge it follows
#      (docs/CI-RUNBOOK.md, "the memory model"), so that subtree was paid for
#      once per consumer.
# Decision: this file holds the reader ONLY and sources NOTHING - it is a leaf
#      in the static source graph, pure bash, with no side effect at source
#      time.  `headers_engine.sh` sources it and keeps its own parsers and
#      endpoint chooser; the four reader-only consumers source this file
#      instead of it.  Function and global names are UNCHANGED, so no call site
#      moves.
# Alternatives considered: leave the reader in `headers_engine.sh` and keep
#      sourcing it - rejected, the false ownership and the duplicated subtree
#      both grow with every new consumer.  Rename `hdr_*` to `resp_*` -
#      rejected, the published contract is not only these eight functions but
#      the globals `_HDR_STATUS`/`_HDR_NAMES`/`_HDR_VALUE`/`_HDR_COUNT`/`_HDR_V`
#      that consumers read directly, so a function-only rename leaves the
#      contract half-renamed, and a full one doubles the blast radius across
#      eleven landed files, buys no behaviour, and turns `git blame` on every
#      one of them into a redirect.
#      Move `hdr_endpoints_load` in here too - rejected, it has two callers
#      rather than a shared need, and it depends on `crawl_engine.sh` and
#      `path_template_of`, which would put source edges straight back into the
#      leaf and undo the reason this file exists.
# Consequences: a check that only reads a response head now costs one small,
#      dependency-free file instead of the whole DAST-05 subtree, and any future
#      response-level helper has an obvious, unowned home.  The cost is that
#      `hdr_` no longer names the file it lives in - which is why this block
#      says so, and why `headers_engine.sh` points here.
#
# THE LOAD-BEARING PROPERTY IN THIS FILE IS `hdr_parse_capture`'S RESET.
# `http_request_capture`'s header sink ACCUMULATES every redirect hop
# (lib/http.sh section 9a), so a capture file for a request that redirected
# holds two or more header blocks, and a whole-file match reads the REDIRECT's
# header and reports it as the delivered response's - backwards for every header
# whose absence on the final response is the finding.  The parse resets on every
# `HTTP/x.y NNN` status line for that reason.  It is pinned three times, each
# failing under a different shape of the mistake: at the unit level in
# tests/suites/dast-response-engine.sh, and end to end in
# tests/suites/dast-headers.sh and tests/suites/dast-leakage.sh.
#
# THIS FILE DOES NOT TALK TO THE NETWORK AND CANNOT.  It sources no transport
# and defines no request function; every request a DAST phase sends goes through
# `http_request` (lib/http.sh) - docs/FOUNDATION.md tension 19's single
# chokepoint, where the scope gate, the rate limiter, the per-run request budget,
# the circuit breaker and DAST-32's ceilings all sit.  This file parses what came
# back; a phase script is what asks.
#
# NEVER A BARE `grep` (tension 4).  Nothing here shells out to a match engine at
# all: a response-header block is line-structured and small, so it is read with
# bash's own `read`, which cannot confuse "no match" with "the engine failed" -
# the failure mode that rule exists to prevent.
#
# EVERYTHING PARSED HERE IS UNTRUSTED TARGET OUTPUT (tension 10).  A header value
# is attacker-controlled text; it reaches a report only through
# `finding_set_evidence`, and `hdr_safe_text` bounds it first so one absurd
# 40 KiB CSP cannot become the report.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_RESPONSE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_RESPONSE_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 0. Bounds
# ---------------------------------------------------------------------------
# Bytes of any one header value carried into evidence.  It travels WITH
# `hdr_safe_text` rather than staying behind in headers_engine.sh: that function
# reads it as a parameter default, so a consumer sourcing this file alone would
# otherwise hit an unbound variable under `set -u` - the shape a lift most
# easily leaves behind, because the owning file's own tests never notice.
: "${_HDR_MAX_EVIDENCE_FIELD:=200}"

# `hdr_safe_text TEXT [MAX]` - bounded, single-line target-derived text for a
# diagnostic or an evidence sentence.  `finding_set_evidence` still does the
# real escaping and redaction (tension 9/10); this only stops one pathological
# header from dominating the sentence it appears in.
hdr_safe_text() {
  local s=$1 max=${2:-$_HDR_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# 1. The response-header reader
# ---------------------------------------------------------------------------
# `hdr_parse_capture FILE` - reads a lib/http.sh header capture and publishes the
# FINAL hop's response headers:
#
#   _HDR_STATUS              the final status line's code, '' when there is none
#   _HDR_NAMES               the field names seen, lowercased, in arrival order
#   _HDR_VALUE[name]         the value; several same-named headers join with LF
#   _HDR_COUNT[name]         how many times the field appeared
#
# Returns 1 (leaving everything empty) when the file is unreadable or carries no
# status line, so a caller can tell "no response" from "a response with no
# headers" - a distinction the whole honesty story here rests on.
#
# ONLY THE FINAL HOP COUNTS, AND THAT IS THE WHOLE REASON THIS IS NOT A GREP -
# see this file's header block for the measurement and for where it is pinned.
#
# `declare -g`, never bare: in a real run this file is sourced from inside
# `dast_run_phase`, so an undecorated `declare` would create a local that dies
# with the phase (modules/dast/engine.sh's phase table documents this at length).
hdr_parse_capture() {
  local f=$1 line name value lower
  declare -gA _HDR_VALUE=() _HDR_COUNT=()
  declare -ga _HDR_NAMES=()
  declare -g _HDR_STATUS=''
  [[ -n $f && -r $f && -s $f ]] || return 1

  local seen_status=0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
      # A new hop: everything read so far belonged to a response that is not
      # the one the caller received.
      _HDR_STATUS=${BASH_REMATCH[1]}
      _HDR_VALUE=() _HDR_COUNT=() _HDR_NAMES=()
      seen_status=1
      continue
    fi
    (( seen_status )) || continue
    [[ $line == *:* ]] || continue
    name=${line%%:*}
    # A field name is an RFC 7230 token.  Anything else on a header line is not
    # a header - a folded continuation, or garbage - and is dropped rather than
    # guessed at.
    [[ $name =~ ^[A-Za-z0-9!#\$%\&\'*+.^_\`|~-]+$ ]] || continue
    value=${line#*:}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    lower=${name,,}
    if [[ -n ${_HDR_COUNT[$lower]:-} ]]; then
      _HDR_VALUE[$lower]="${_HDR_VALUE[$lower]}"$'\n'"$value"
      _HDR_COUNT[$lower]=$(( _HDR_COUNT[$lower] + 1 ))
    else
      _HDR_VALUE[$lower]=$value
      _HDR_COUNT[$lower]=1
      _HDR_NAMES+=("$lower")
    fi
  done <"$f"

  (( seen_status )) || return 1
  return 0
}

# `hdr_present NAME` - 0 when the final response carried the (case-insensitive)
# field at all.  A field present with an EMPTY value is present:
# `X-Frame-Options:` with nothing after it is a misconfiguration, not an
# absence, and the two get different sentences.
hdr_present() {
  local n=${1,,}
  [[ -n ${_HDR_COUNT[$n]:-} ]]
}

# `hdr_value NAME` - sets `_HDR_V` to the field's value (LF-joined if repeated).
hdr_value() {
  local n=${1,,}
  _HDR_V=${_HDR_VALUE[$n]:-}
}

# `hdr_first NAME` - sets `_HDR_V` to the FIRST value only, for the fields where
# a repeat is itself the defect and the analysis wants one of them to talk about.
hdr_first() {
  local n=${1,,}
  _HDR_V=${_HDR_VALUE[$n]:-}
  _HDR_V=${_HDR_V%%$'\n'*}
}

# ---------------------------------------------------------------------------
# 2. Content-Type classification
# ---------------------------------------------------------------------------
# `hdr_is_document CTYPE` - 0 for a media type a browser renders as a top-level
# document, which is the only kind of response `Content-Security-Policy` and
# `X-Frame-Options` govern.
#
# THIS GATE IS THE DIFFERENCE BETWEEN A REPORT AND A WALL OF NOISE, and it is
# also the honest reading: a JSON API response is not framed and executes no
# script, so "this endpoint has no CSP" is not a statement about it.  Its
# callers apply it SELECTIVELY - passive/headers.sh gates CSP-absence and
# clickjacking on it and nothing else, because sniffing, transport downgrade and
# referrer leakage are not document-only problems.
hdr_is_document() {
  local ct=${1,,}
  ct=${ct%%;*}
  ct=${ct%"${ct##*[![:space:]]}"}
  case $ct in
    text/html | application/xhtml+xml | text/xml | application/xml) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 3. What a response check needs to know about the request it made
# ---------------------------------------------------------------------------
# The path component of a URL, query and fragment removed.  A URL with no path
# is `/`.  Same helper, same reason, as modules/dast/active/sqli.sh's own.
hdr_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `hdr_url_is_https URL` - 0 for an `https://` URL.  HSTS is meaningless on a
# plaintext response (RFC 6797 section 7.2: a UA MUST ignore an STS header
# received over non-secure transport), so neither its absence nor its value is a
# finding there - the cleartext transport is, and that is DAST-30's check.
hdr_url_is_https() {
  [[ ${1,,} == https://* ]]
}
