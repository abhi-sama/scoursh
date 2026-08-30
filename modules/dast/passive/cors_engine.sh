#!/usr/bin/env bash
# modules/dast/passive/cors_engine.sh - the DAST CORS check's pure function
# library (docs/DESIGN.md §7.1 `cors.sh`; docs/STEP5-DAST-PLAN.md DAST-08).
#
# WHAT THIS FILE IS.  Every piece of DAST-08 that can be exercised with no
# network: the response-header reader, the Access-Control-Allow-Origin
# classifier, the credentials predicate, and the finding emission.
# modules/dast/passive/cors.sh is the phase script that resolves the live input
# (the endpoint list crawl.sh wrote) and drives this file.  The engine/phase
# split is modules/sast/'s, reused exactly as auth_engine.sh, crawl_engine.sh
# and jwt_engine.sh already reuse it, and it is what lets
# tests/suites/dast-cors.sh pin the classifier against RECORDED responses
# without a target, a run directory, or scan.sh.
#
# THIS CHECK SENDS A REQUEST, WHICH ITS PASSIVE SIBLINGS DO NOT, AND THAT IS
# NOT A LICENCE TO TOUCH STATE.  docs/DESIGN.md §7.1's contract is "No mutation
# of state", not "no traffic" - §7.1's own cors.sh bullet spells the probe out
# as "`Origin: <sentinel>` -> check `Access-Control-Allow-Origin` +
# credentials", so a request is the check.  Six properties keep it inside the
# passive contract, and each one is asserted by tests/suites/dast-cors.sh
# rather than only claimed here:
#
#   1. ONLY IDEMPOTENT ENDPOINTS ARE PROBED.  cors.sh filters the inventory to
#      GET and HEAD before anything reaches this file, so a POST/PUT/PATCH/
#      DELETE endpoint the crawler found is never requested at all - not with a
#      different method, not "just to read its headers".
#   2. THE REQUEST IS THE ONE THE CRAWLER ALREADY MADE, PLUS ONE HEADER.  No
#      body is attached (`http_request_body` is never called), no parameter
#      value is altered, no method is overridden, and no query string is
#      rewritten.  The single difference from a benign fetch is one `Origin`
#      request header.
#   3. ONE REQUEST PER CANDIDATE.  There is no retry, no second shape, and no
#      preflight: an `OPTIONS` preflight would be a second request per endpoint
#      for a header set the actual-request response already carries, and
#      `OPTIONS` enumeration is DAST-13's (`active/methods.sh`) subject at the
#      safe-active tier, not this one's at passive.
#   4. THE RESPONSE BODY IS DISCARDED.  Only the header capture sink is set, so
#      no target content is read into this process or written to an artifact.
#      A CORS policy lives entirely in response headers.
#   5. REDIRECTS ARE NOT FOLLOWED (max_redirects 0).  A CORS policy is a
#      property of the URL that was asked, and lib/http.sh drops caller headers
#      on a cross-origin hop anyway - so following one could only produce a
#      verdict about a different resource, from a request that no longer
#      carried the sentinel.
#   6. THE SENTINEL ORIGIN IS NEVER DIALLED.  It is a header VALUE and nothing
#      else; no request is ever addressed to it, and it is a reserved RFC 2606
#      `.example` name that cannot resolve, so even a mistake could not reach a
#      third party.  It is also, deliberately, not a real product or company
#      name - AGENTS.md §1's target-agnostic rule binds a sentinel exactly as it
#      binds a rule.
#
# And, as for every other DAST probe: the request goes through lib/http.sh's
# `http_request` (docs/FOUNDATION.md tension 19's one chokepoint), so the scope
# gate, DAST-01's rate limiter, the per-run request budget, the circuit breaker
# and DAST-32's ceilings all bind it.  There is no second path to the network
# in this file.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_CORS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_CORS_ENGINE_SOURCED=1

# lib/http.sh is sourced only when an outer caller has not already done so -
# scan.sh sources it at top level before `scan_dispatch`, so in a real run this
# is a no-op, and the conditional is what lets the suite source THIS file on
# its own.  The same shape, and the same reason, as jwt_engine.sh's own guard.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi

# ---------------------------------------------------------------------------
# 1. The sentinel origin
# ---------------------------------------------------------------------------
# The origin the probe claims to come from.  Three properties, each load-bearing:
#
#   * RESERVED.  `.example` is reserved by RFC 2606 §2 / RFC 6761 §6.5 and can
#     never be delegated, so this string names nothing that exists and nothing
#     an operator could accidentally attack.  It is a header value only and is
#     never a request destination (see property 6 in the header above).
#   * UNMISTAKABLE.  A reflection verdict is an EXACT string equality against
#     this value, so it has to be a string no legitimate allowlist would ever
#     contain by coincidence.
#   * TARGET-AGNOSTIC.  It names no application, company, product or
#     environment, which AGENTS.md §1 requires of every shipped byte.
#
# `https://`, not `http://`: a server that only reflects HTTPS origins would
# otherwise be reported clean for a reason that has nothing to do with its CORS
# policy.
#
# Overridable by SCOURSH_DAST_CORS_ORIGIN for the same reason lib/http.sh's
# transport and resolver are swappable - so the suite can prove the classifier
# is comparing against the configured sentinel rather than a hardcoded literal
# it happens to agree with.  It is NOT a documented operator knob and has no
# config key: the value is an implementation detail of the probe, not a policy.
CORS_SENTINEL_ORIGIN=${SCOURSH_DAST_CORS_ORIGIN:-https://scoursh-cors-probe.example}

# ---------------------------------------------------------------------------
# 2. Reading a response header (tension 4: never a bare grep)
# ---------------------------------------------------------------------------
# `cors_header_last FILE NAME` - sets `_CORS_HDR_VALUE` to the value of the LAST
# `NAME:` line in the raw response-header capture FILE, and returns 1 (leaving
# the value empty) when the header is not present at all.
#
# THE MATCH IS CASE-INSENSITIVE ON THE FIELD NAME, WHICH IS NOT A NICETY.
# RFC 7230 §3.2 makes field names case-insensitive and HTTP/2 (RFC 7540 §8.1.2)
# REQUIRES them lowercase on the wire, so a real target behind an HTTP/2 edge
# answers `access-control-allow-origin:` and a check matching the RFC 6454
# spelling byte-for-byte would report every one of them clean.  The suite pins
# the lowercase form for exactly that reason.
#
# LAST WINS.  A conformant server sends one Access-Control-Allow-Origin, but the
# capture sink ACCUMULATES hops (lib/http.sh's http_request_capture) and a
# misconfigured stack can emit the header twice - once from the application and
# once from a reverse proxy.  The last one is the one nearest the wire, and
# taking the first would let a permissive proxy value hide behind a strict
# application one.  `cors_probe` sends with max_redirects 0, so in practice
# there is exactly one hop and this only ever disambiguates a duplicated header.
#
# Goes through `scan_match`, never a bare grep: grep exits 1 on no-match, which
# is the NORMAL case here (most endpoints send no CORS header at all), and under
# `set -Eeuo pipefail` a bare call would take the run with it - while a `|| true`
# would make "the engine failed" indistinguishable from "the target sends no
# CORS header", i.e. would report a broken check as a clean target.
cors_header_last() {
  local file=$1 name=$2 hits line value=''
  _CORS_HDR_VALUE=''
  [[ -r $file ]] || return 1
  # `mktemp`, never a name built from $BASHPID - lib/http.sh's own
  # `_http_transport_default` idiom, and for a security reason rather than a
  # stylistic one.  This path falls back to a world-writable /tmp whenever
  # SCOURSH_SCRATCH is unset (every standalone-engine caller, including this
  # repository's own suite), and a pid-derived name is predictable, so a local
  # user who pre-creates it as a symlink gets whatever this process then writes
  # through it - CWE-377 via CWE-59.  mktemp fails rather than following one.
  hits=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cors-hdr.XXXXXX")
  chmod 600 "$hits" 2>/dev/null || true
  # The name is a fixed literal from this file's own callers, never target
  # input, so it needs no regex quoting; it is still anchored at line start so
  # a header VALUE that happens to contain the name cannot match.
  #
  # `-i` is what makes the field-name match case-insensitive, and it is the
  # whole of this function's HTTP/2 defence - without it an
  # `access-control-allow-origin:` line is invisible and every HTTP/2 target
  # reports clean.  The flag is passed through `scan_match` (never a bare grep,
  # tension 4) and is accepted identically by both bound engines: `grep -E -i`
  # and `rg -i`, the same way `scan_match_offsets` already passes `-b -o`.  It
  # widens only the field NAME - the pattern stops at the colon and the OWS, so
  # no header value is ever matched case-insensitively by it.
  if ! scan_match "$hits" -i -e "^${name}:[[:space:]]*" -- "$file"; then
    rm -f "$hits"
    return 1
  fi
  local found=1
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    # `grep -n` / `rg -n` are bound unconditionally into SCOURSH_GREP
    # (lib/core.sh core_bind_engine), so every hit is prefixed `<lineno>:`.
    line=${line#*:}
    line=${line%$'\r'}
    value=${line#*:}
    # Trim leading and trailing horizontal whitespace (RFC 7230 §3.2.4 OWS).
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    found=0
  done <"$hits"
  rm -f "$hits"
  (( found == 0 )) || return 1
  _CORS_HDR_VALUE=$value
  return 0
}

# `cors_credentials_true VALUE` - 0 when an Access-Control-Allow-Credentials
# value means "true".  The Fetch standard defines the ONLY credible value as the
# byte string "true", but it is matched case-insensitively here because servers
# do emit `True`/`TRUE` and a browser's own header parse is not what decides
# whether the operator has a misconfiguration worth fixing.  Anything else -
# `false`, empty, `1`, absent - is not credentialed.
cors_credentials_true() {
  local v=${1:-}
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  [[ ${v,,} == true ]]
}

# ---------------------------------------------------------------------------
# 3. Classifying an Access-Control-Allow-Origin value
# ---------------------------------------------------------------------------
# `cors_classify ACAO_PRESENT ACAO_VALUE [SENTINEL]` - sets `_CORS_POLICY` to
# exactly one of:
#
#   absent       no Access-Control-Allow-Origin in the response
#   wildcard     the literal `*`
#   reflected    the sentinel origin, echoed back verbatim
#   allowlisted  some other single origin (or `null`), which is NOT the sentinel
#
# ACAO_PRESENT is passed separately from the value because an empty
# `Access-Control-Allow-Origin:` header is a real, distinct thing from no header
# at all, and collapsing the two would make `absent` unreachable for it.
#
# THE THREE DISTINCTIONS THIS FUNCTION EXISTS TO MAKE, EACH WITH THE WRONG
# READING THAT WOULD SHIP GREEN:
#
#   * `*` IS NOT REFLECTION.  A wildcard says "any origin may read this
#     UNAUTHENTICATED" - the Fetch standard forbids a browser from honouring `*`
#     together with credentials at all - whereas reflection says "whatever
#     origin asked is trusted", which composes with cookies into a full
#     cross-origin read of an authenticated response.  A check that treated
#     "an ACAO header came back" as the signal would grade a public CDN asset
#     the same as an authenticated API, and DAST-08's own ticket asks for these
#     to be different findings with different severity.
#   * A STATIC ALLOWLIST IS NOT A FINDING.  A server answering
#     `Access-Control-Allow-Origin: https://app.internal.example` to our
#     sentinel is doing precisely the right thing: it validated the Origin,
#     refused it, and stated its own policy.  Reporting that would be a false
#     positive on correct configuration, which is the single fastest way to make
#     a scanner ignored.
#   * REFLECTION IS EXACT EQUALITY, NOT A SUBSTRING.  A substring test would
#     call `https://scoursh-cors-probe.example.attacker.invalid` a reflection of
#     the sentinel when it is in fact a (differently broken) suffix-match bug,
#     and would report the sentinel as reflected out of any value that merely
#     mentioned it.  The suite pins a value that CONTAINS the sentinel and is
#     not equal to it.
cors_classify() {
  local present=$1 value=${2:-} sentinel=${3:-$CORS_SENTINEL_ORIGIN}
  _CORS_POLICY=absent
  [[ $present == 1 ]] || return 0
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  if [[ $value == '*' ]]; then
    _CORS_POLICY=wildcard
  elif [[ $value == "$sentinel" ]]; then
    _CORS_POLICY=reflected
  else
    # Everything else: a single origin the server chose, which is the CORRECT
    # answer to our sentinel and is not a finding.  An EMPTY value lands here
    # too - a header the server sent and a browser will reject.  It is neither a
    # wildcard nor a reflection and it is certainly not a deliberate allowlist
    # entry, but it IS a stated (if broken) policy rather than an absent one, so
    # it is not `absent` either, and it produces no finding.
    _CORS_POLICY=allowlisted
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. The probe
# ---------------------------------------------------------------------------
# `cors_probe TARGET METHOD URL [SENTINEL]` - send ONE request carrying
# `Origin: <sentinel>` and set:
#
#   _CORS_STATUS         the HTTP status ('' on a transport-level failure)
#   _CORS_ACAO_PRESENT   1/0
#   _CORS_ACAO           the Access-Control-Allow-Origin value
#   _CORS_ACAC           the Access-Control-Allow-Credentials value
#   _CORS_VARY_ORIGIN    1 when a `Vary:` header lists Origin, else 0
#
# Returns 1 on a transport-level failure (breaker open, budget spent, resolution
# failure), which the caller must treat as "not tested" and never as "no CORS
# header" - the whole honesty argument of this repository in one branch.
#
# EVERYTHING SAFE ABOUT THIS CHECK CONVERGES ON THIS ONE FUNCTION, exactly as
# jwt_engine.sh's `jwt_probe` does for §7.4: it goes through `http_request`, it
# attaches one header and no body, it captures ONLY headers, and it follows no
# redirect.  See this file's header for the six-property statement.
cors_probe() {
  local target=$1 method=$2 url=$3 sentinel=${4:-$CORS_SENTINEL_ORIGIN}
  local hdrfile
  _CORS_STATUS='' _CORS_ACAO='' _CORS_ACAC='' _CORS_ACAO_PRESENT=0 _CORS_VARY_ORIGIN=0

  # `mktemp`, for the reason `cors_header_last` states in full: a pid-derived
  # name under a world-writable fallback /tmp is a symlink target a local user
  # can pre-create, and `: >"$file"` would then truncate through it.  This one
  # also RECEIVES the target's own response headers, which is data that should
  # not land in a file another local user chose the location of.
  hdrfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cors-resp.XXXXXX")
  chmod 600 "$hdrfile" 2>/dev/null || true

  http_request_reset
  http_request_header Origin "$sentinel"
  # BODY SINK EMPTY, HEADER SINK SET.  A CORS policy is entirely in the headers,
  # and not asking for the body is what keeps target content out of this process
  # and out of every artifact (passive property 4).
  http_request_capture '' "$hdrfile"
  # max_redirects 0 - passive property 5.
  if ! http_request "$method" "$url" 0 "$target"; then
    rm -f "$hdrfile"
    return 1
  fi
  _CORS_STATUS=$_HTTP_LAST_STATUS

  if cors_header_last "$hdrfile" 'Access-Control-Allow-Origin'; then
    _CORS_ACAO_PRESENT=1
    _CORS_ACAO=$_CORS_HDR_VALUE
  fi
  if cors_header_last "$hdrfile" 'Access-Control-Allow-Credentials'; then
    _CORS_ACAC=$_CORS_HDR_VALUE
  fi
  # `Vary: Origin` does not make a reflecting policy safe, but its ABSENCE makes
  # a reflecting one cacheable: a shared cache can store the response minted for
  # one origin and serve it to another.  It is read from the same response, at
  # no extra request, and it sharpens the evidence rather than minting a finding
  # of its own.
  if cors_header_last "$hdrfile" 'Vary'; then
    local v=${_CORS_HDR_VALUE,,}
    [[ $v == *origin* ]] && _CORS_VARY_ORIGIN=1
  fi

  rm -f "$hdrfile"
  return 0
}

# ---------------------------------------------------------------------------
# 5. Emitting a finding
# ---------------------------------------------------------------------------
# One helper, so every CORS finding carries the same DAST location profile
# (docs/FOUNDATION.md tension 5: target, method, path_template, param_location,
# param_name) and only the id, title, severity and evidence vary.
#
# `param_location` is `header` and `param_name` is `Origin`: the request field
# this check varies IS the Origin header, so two different weaknesses on one
# endpoint stay distinct (their check_id differs) while the same weakness on two
# path templates also stays distinct (their path_template differs).  Since the
# technique is not part of the location profile, the three verdicts MUST be three
# check ids or the merge would silently dedupe a wildcard and a reflection on one
# endpoint into one finding - the same argument modules/dast/active/sqli.sh makes
# for its own three ids.
cors_emit_finding() {
  local check_id=$1 title=$2 severity=$3 confidence=$4 cwe=$5
  local target=$6 method=$7 url=$8 path=$9 evidence=${10} remediation=${11}
  local sensitive=${12:-true}

  finding_new
  finding_set check_id "$check_id"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence "$confidence"
  finding_set cwe "$cwe"
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data "$sensitive"
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location header
  finding_set loc_param_name Origin
  finding_set url "$url"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# The three remediation paragraphs, held as functions rather than as globals so
# a phase that is sourced twice cannot end up with a stale copy, and so the
# checks.rules record and the emitted finding can be compared side by side.
cors_remediation_reflection() {
  printf '%s' 'Do not echo the request Origin into Access-Control-Allow-Origin. Compare the Origin against a server-side allowlist of exact origins (scheme, host and port) and emit that stored value, or emit no CORS header at all when it does not match; never derive the header from the request. Reject on mismatch rather than falling back to a permissive default, and if any origin must be trusted for an authenticated resource, keep Access-Control-Allow-Credentials off unless that specific origin is on the allowlist. Add Vary: Origin so a shared cache cannot serve one origin the response minted for another, and check any framework CORS middleware for a wildcard, regex or suffix match that accepts more origins than intended.'
}

cors_remediation_wildcard() {
  printf '%s' 'Access-Control-Allow-Origin: * makes this response readable by script from every origin on the internet. That is correct for a genuinely public, unauthenticated asset and wrong for anything else: replace it with a server-side allowlist of the exact origins that need cross-origin access, and confirm the resource carries no user-specific or otherwise non-public data. Note that a browser will refuse to combine * with credentials, so a wildcard is not itself a route to authenticated data - but it is a statement that the resource is public, and it should only be present where that is deliberately true.'
}
