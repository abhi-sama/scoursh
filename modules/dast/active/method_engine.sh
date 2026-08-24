#!/usr/bin/env bash
# modules/dast/active/method_engine.sh - the parsing half of the §7.2 HTTP
# method-enumeration probe (docs/DESIGN.md §7.2; docs/STEP5-DAST-PLAN.md
# DAST-13, tier 3).
#
# A PURE LIBRARY. It issues no request, emits no finding and touches nothing at
# source time; modules/dast/active/methods.sh is the orchestration half, in the
# same split modules/dast/passive/{cookies,cookie_engine}.sh already uses one
# directory over. Everything here is a function of bytes already received, so
# every one of its decisions is testable from a recorded response.
#
# WHAT "ENUMERATION WITHOUT MUTATION" ACTUALLY MEANS, because it is the whole
# design constraint and it is easy to lose. There are two ways to learn that an
# endpoint accepts `PUT`:
#
#   1. Send a `PUT` and see what happens.  This CREATES OR OVERWRITES A
#      RESOURCE when it works, which is the one thing §7.2's tier forbids and
#      which no scanner may do to somebody's running application.
#   2. Ask the server what it allows and read the answer.  `OPTIONS` is defined
#      as having no effect on the resource (RFC 7231 §4.3.7) and a `405`
#      rejection is REQUIRED to name the allowed set (RFC 7231 §6.5.5).  Both
#      are pure reads.
#
# This file only ever knows (2). The single method it treats as directly
# measurable is `TRACE`, and only because `TRACE` is defined as an echo with no
# effect on the resource (RFC 7231 §4.3.8) - which is exactly why it is the one
# dangerous method a scanner can confirm rather than merely report as claimed.
# `PUT`, `DELETE`, `PATCH` and `CONNECT` are reported from the server's OWN
# advertisement and are never sent, which is why their findings carry
# `confidence: medium`: an `Allow` header is a claim, and the run deliberately
# does not spend a state change to upgrade it to a demonstration.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_METHOD_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_METHOD_ENGINE_SOURCED=1

# lib/core.sh for `scan_match` (tension 4 rule 2) and the scratch dir. Guarded,
# so sourcing this from a phase inside a real run - where scan.sh loaded it long
# ago - is a no-op, and sourcing it from a test on its own still works.
if [[ -z ${SCOURSH_CORE_SOURCED:-} ]]; then
  # shellcheck source=lib/core.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/core.sh"
fi

# ---------------------------------------------------------------------------
# 1. Reading the `Allow` header out of a captured response
# ---------------------------------------------------------------------------
# `method_allow_extract HDRFILE` - prints the raw VALUE of every `Allow` header
# in a captured response, one per line, CR stripped and leading OWS trimmed.
# Returns 0 when at least one was found and 1 when none was, and never conflates
# the two: "the server named its methods" and "the server named nothing" are
# different facts, and only the second is a coverage gap.
#
# THE HEADER NAME IS ANCHORED AT THE START OF THE LINE, AND THAT ANCHOR IS THE
# WHOLE POINT OF THIS FUNCTION. `Access-Control-Allow-Methods` contains the
# bytes `Allow-Methods` and is a completely different statement: it is what a
# BROWSER is permitted to send CROSS-ORIGIN after a preflight, not what the
# endpoint accepts. An unanchored, case-insensitive match for `allow` - the
# obvious one-liner - reads a CORS policy as an acceptance claim and reports
# `PUT` as allowed on every API that permits a cross-origin `PUT` from a single
# trusted front end. CORS preflight analysis is a different check family and is
# explicitly out of this ticket's scope; this function's job is to not silently
# perform a bad version of it. `Access-Control-Allow-Methods` does not begin
# with `allow`, so the anchor is a total defence and needs no deny list.
#
# THROUGH `scan_match`, NEVER A BARE GREP (docs/FOUNDATION.md tension 4 rule 2):
# `set -Eeuo pipefail` is mandatory here and grep exits 1 on no-match, which is
# the ORDINARY case - most responses carry no `Allow` at all. A bare grep would
# either kill the run on an ordinary response or, wrapped in `|| true`, would
# report an engine failure as "this server advertised no methods", which is a
# coverage hole in the direction that reads as a clean result.
method_allow_extract() {
  local hdrfile=$1 hits line value
  [[ -n $hdrfile && -r $hdrfile ]] || return 1
  hits=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/dast-method-allow.$$
  if ! scan_match "$hits" -i -e '^allow:' -- "$hdrfile"; then
    rm -f "$hits"
    return 1
  fi
  local found=1
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    # SCOURSH_GREP binds `-n` unconditionally (lib/core.sh core_bind_engine), so
    # every hit arrives prefixed `<lineno>:`. Strip that, then the header name.
    # Both strips are non-greedy, so a `:` inside the value survives.
    line=${line#*:}
    # A CAPTURED HEADER LINE ENDS CRLF (RFC 7230 §3.5), and curl's own `-D`
    # dump preserves it. Without this strip the LAST token of every real
    # response's `Allow` list is `DELETE` with a trailing CR, which matches no
    # method name - so the most dangerous member of the list is precisely the
    # one silently dropped.
    line=${line%$'\r'}
    value=${line#*:}
    value=${value#"${value%%[![:space:]]*}"}
    printf '%s\n' "$value"
    found=0
  done <"$hits"
  rm -f "$hits"
  return "$found"
}

# ---------------------------------------------------------------------------
# 2. Splitting one `Allow` value into method tokens
# ---------------------------------------------------------------------------
# `method_allow_split VALUE` - sets `_METHOD_TOKENS` to the comma-separated
# members of one `Allow` value, each with its surrounding optional whitespace
# removed and empty members dropped.
#
# `Allow` is a plain RFC 7230 §7 comma-delimited list - unlike `Set-Cookie`,
# where the same reading is a shipped bug (modules/dast/passive/cookie_engine.sh
# documents why) - so splitting on `,` IS correct here. What is not optional is
# the OWS trim: RFC 7230 §7 permits `GET, PUT`, `GET ,PUT` and `GET,   PUT` as
# the identical list, and a bare `IFS=, read -ra` keeps the space, yielding the
# token ` PUT`, which compares equal to no method name. A server advertising a
# write method in the ordinary, single-space spelling every server on earth uses
# would then be reported as advertising none - a false negative, the direction
# that reads as a pass.
#
# An empty member is dropped rather than kept as an empty method: `Allow: GET,`
# and `Allow: GET,,PUT` are both real-world spellings, and an empty token would
# otherwise be classified and reported as a nameless method.
method_allow_split() {
  local value=$1 part
  declare -ga _METHOD_TOKENS=()
  local rest=$value
  while [[ -n $rest ]]; do
    if [[ $rest == *,* ]]; then
      part=${rest%%,*}
      rest=${rest#*,}
    else
      part=$rest
      rest=''
    fi
    # Trim leading, then trailing, whitespace.  THE TRAILING TRIM IS DOING TWO
    # JOBS AND ONLY ONE OF THEM IS OBVIOUS: besides the OWS above, a CARRIAGE
    # RETURN is a `[[:space:]]` character, so this is also what removes the CR a
    # CRLF-terminated header line leaves on its final token.  There is
    # deliberately no separate `${part%$'\r'}` here - it would be dead code, and
    # dead code that looks like the defence makes the real one easy to delete by
    # accident.  Measured: with the trailing trim removed, the last member of
    # `Allow: GET, DELETE<CR>` is the token `DELETE<CR>`, which classifies as
    # `other` and is silently dropped - and the last member is routinely the
    # dangerous one.
    part=${part#"${part%%[![:space:]]*}"}
    part=${part%"${part##*[![:space:]]}"}
    [[ -n $part ]] || continue
    _METHOD_TOKENS+=("$part")
  done
  return 0
}

# `method_allow_collect HDRFILE` - the two above composed. Sets:
#
#   _METHOD_ALLOW          the canonical (uppercased) method names, deduped, in
#                          the order the server first named them
#   _METHOD_ALLOW_RAW      the token exactly as the server spelled it, parallel
#                          to _METHOD_ALLOW by index
#   _METHOD_ALLOW_PRESENT  1 when an `Allow` header was seen at all, else 0
#
# Returns 0 always: a response with no `Allow` is the ordinary case, not an
# error, and `_METHOD_ALLOW_PRESENT` is how a caller tells "advertised nothing"
# from "advertised an empty list".
#
# THE ORDER IS THE SERVER'S, AND THE DEDUP IS ON THE CANONICAL FORM. A server
# may split its list over two `Allow` headers (RFC 7230 §3.2.2 permits it for a
# list-valued field) and may repeat a member; the walk below is order-preserving
# so the same surface always produces the same walk, which is what keeps the
# report byte-reproducible between runs over that surface.
method_allow_collect() {
  local hdrfile=$1 value tok canon
  declare -ga _METHOD_ALLOW=() _METHOD_ALLOW_RAW=()
  declare -gA _METHOD_ALLOW_SEEN=()
  declare -g _METHOD_ALLOW_PRESENT=0
  while IFS= read -r value; do
    _METHOD_ALLOW_PRESENT=1
    method_allow_split "$value"
    for tok in "${_METHOD_TOKENS[@]+"${_METHOD_TOKENS[@]}"}"; do
      canon=${tok^^}
      [[ -n ${_METHOD_ALLOW_SEEN[$canon]:-} ]] && continue
      _METHOD_ALLOW_SEEN[$canon]=1
      _METHOD_ALLOW+=("$canon")
      _METHOD_ALLOW_RAW+=("$tok")
    done
  done < <(method_allow_extract "$hdrfile" || true)
  return 0
}

# ---------------------------------------------------------------------------
# 3. Classifying a method token
# ---------------------------------------------------------------------------
# `method_class TOKEN` - prints one of:
#
#   write    PUT, DELETE, PATCH - a method whose success changes or removes a
#            resource, which is what makes its availability worth reporting.
#   connect  CONNECT - turns the server into a tunnel for whoever asks.
#   trace    TRACE - echoes the request, including headers page script was
#            never meant to be able to read.
#   safe     GET, HEAD, OPTIONS, POST - the ordinary surface of a web
#            application.  POST is `safe` HERE in the narrow sense that finding
#            it allowed on an endpoint the crawler already found is not itself
#            a finding; it is the normal way a form works.
#   other    anything else, including a WebDAV extension method.  Out of scope
#            for this ticket by its own statement, and classified rather than
#            dropped so a later ticket has somewhere to hang.
#
# CASE-INSENSITIVE, DELIBERATELY, AND THE RAW TOKEN IS STILL WHAT GETS REPORTED.
# RFC 7231 §4.1 makes method names case-sensitive, so `Allow: put` is, read
# strictly, not an advertisement of `PUT` at all. That strict reading is the
# wrong one for a scanner: a server answering `allow: get, put` is a server
# whose `PUT` handler an attacker will find, and reporting nothing because the
# operator's reverse proxy lowercases its headers is a false negative on a real
# exposure. The token the server actually sent is carried through to the
# evidence, so the operator sees the spelling rather than a normalisation this
# tool invented.
method_class() {
  local token=$1
  case ${token^^} in
    PUT | DELETE | PATCH) printf 'write' ;;
    CONNECT) printf 'connect' ;;
    TRACE) printf 'trace' ;;
    GET | HEAD | OPTIONS | POST) printf 'safe' ;;
    *) printf 'other' ;;
  esac
}

# ---------------------------------------------------------------------------
# 4. Confirming TRACE, as opposed to believing a status code
# ---------------------------------------------------------------------------
# `method_trace_enabled STATUS CTYPE BODYFILE PATH` - 0 when the response really
# is a TRACE echo, 1 otherwise.
#
# A 2xx STATUS ALONE IS NOT EVIDENCE, and treating it as such is the classic
# false positive in this check. Very many applications answer every unrouted
# request with a 200 and their front-end shell - a single-page app's
# `index.html` catch-all is the standard modern shape - so "TRACE returned 200"
# is true on a great many servers that have no TRACE handler at all, and would
# put a Cross-Site Tracing finding in front of an operator with nothing to fix.
# RFC 7231 §4.3.8 says exactly what a real TRACE response looks like:
# `Content-Type: message/http`, with a body that is the request the server
# received. Either of those two facts is accepted here, because a proxy in front
# of the application may rewrite the content type while still echoing, and a
# body opening with the request line `TRACE <path>` cannot be produced by an
# application shell that never saw the method.
#
# The path check is a substring rather than an anchored comparison because the
# echoed request line carries the origin-form path the SERVER received, which
# may differ from what was sent by a prefix a reverse proxy stripped or added.
method_trace_enabled() {
  local status=$1 ctype=$2 bodyfile=$3 path=$4 line
  [[ $status =~ ^2[0-9][0-9]$ ]] || return 1
  case ${ctype,,} in
    *message/http*) return 0 ;;
  esac
  [[ -n $bodyfile && -r $bodyfile ]] || return 1
  # The echo is the FIRST line of a well-formed TRACE body, but a proxy may
  # prepend its own hop, so the first few lines are inspected rather than only
  # line one. Bounded at 10 so a large error page is not walked in full.
  local n=0
  while IFS= read -r line && (( n < 10 )); do
    n=$(( n + 1 ))
    line=${line%$'\r'}
    if [[ ${line^^} == TRACE\ * ]]; then
      [[ -z $path || $path == / || $line == *"$path"* ]] && return 0
    fi
  done <"$bodyfile"
  return 1
}

# ---------------------------------------------------------------------------
# 5. URL helpers
# ---------------------------------------------------------------------------
# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via `path_template_of`). A URL with no
# path is `/`. Identical in shape and reason to the cookie phase's own helper.
method_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}
