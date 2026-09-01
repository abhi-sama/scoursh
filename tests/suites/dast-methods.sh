#!/usr/bin/env bash
# tests/suites/dast-methods.sh - modules/dast/active/methods.sh and its parser
# modules/dast/active/method_engine.sh: HTTP method enumeration per endpoint
# (docs/DESIGN.md §7.2; docs/STEP5-DAST-PLAN.md DAST-13, tier 3).
#
# NOTHING HERE TOUCHES THE NETWORK. Every response is RECORDED: the whole suite
# runs against a stubbed SCOURSH_HTTP_TRANSPORT that writes canned headers and
# bodies into the capture files lib/http.sh hands it, with SCOURSH_HTTP_RESOLVE
# stubbed too (docs/DESIGN.md §12: "DAST logic is testable with no live
# target"). It runs on a host with no network and no Docker, and passes on its
# own via `tests/run-tests.sh dast-methods`.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing. Six readings are rejected here, and every one of
# them is a plausible first draft:
#
#   1. `Access-Control-Allow-Methods` IS NOT `Allow`.  A case-insensitive
#      substring match for `allow` over the header block - the obvious
#      one-liner - reports a CORS preflight policy as an acceptance claim, so
#      every API that permits a cross-origin PUT from its own front end is
#      reported as accepting PUT from anyone.  CORS analysis is a different
#      check family and out of this ticket's scope; doing a bad version of it by
#      accident is the failure this pins.
#   2. THE OWS AROUND EACH COMMA MUST GO.  RFC 7230 §7 makes `GET, PUT` and
#      `GET ,PUT` the same list; a bare `IFS=, read -ra` yields the token
#      ` PUT`, which equals no method name, so the ordinary single-space
#      spelling every server uses is read as advertising nothing - a false
#      negative, the direction that reads as a pass.
#   3. A CAPTURED HEADER LINE ENDS CRLF.  Without the CR strip the last token of
#      a real `Allow` list is `DELETE\r`, so the most dangerous member of the
#      list is exactly the one dropped.
#   4. A 200 IS NOT A TRACE ECHO.  A single-page app answers every unrouted
#      request with 200 and its shell, so "TRACE returned 200 means TRACE is
#      enabled" fires on a great many servers with no TRACE handler at all.
#   5. A `405` REJECTION IS AN `Allow` SOURCE.  RFC 7231 §6.5.5 requires it to
#      carry one; reading only a 2xx OPTIONS misses every server that refuses
#      OPTIONS and still names its methods in the refusal.
#   6. THE MEASUREMENT BEATS THE ADVERTISEMENT, IN BOTH DIRECTIONS.  TRACE
#      confirmed but not named in `Allow` is still a finding (Apache's historical
#      default is exactly this); TRACE named in `Allow` but demonstrably
#      rejected is NOT a finding.  A single "trust the header" or "trust the
#      status" reading gets one of those two wrong.
#
# And it pins the property the ticket exists for: NO WRITE METHOD IS EVER SENT.
# The request log is asserted to contain no PUT, DELETE, PATCH, POST or CONNECT
# at all, on a fixture surface where every one of them is advertised.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header and method syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# SC2100: `target=method-fixture` and `cell=method-fixture` are plain strings,
#   not the arithmetic subtraction the hyphenated shape suggests.
# shellcheck disable=SC2016,SC2030,SC2031,SC2100

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/core.sh (scratch dir, traps, the pattern
# engine binding scan_match needs).
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/method_engine.sh"
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-methods-workspace
rm -rf "$W"; mkdir -p "$W"

# ===========================================================================
printf '== A. the parser: method_engine.sh in isolation ==\n'
# ===========================================================================
# Every case here is a pure function call over a recorded header block. No run
# directory, no transport, no finding - just the grammar.

_hdr() { printf '%b' "$2" >"$1"; }

# --- reading 1: Access-Control-Allow-Methods is not Allow -------------------
t_case 'an `Allow` header is read'
H=$W/h1
_hdr "$H" 'HTTP/1.1 200 OK\nAllow: GET, HEAD, PUT\nContent-Type: text/html\n\n'
method_allow_collect "$H"
assert_eq 1 "$_METHOD_ALLOW_PRESENT" 'the Allow header is seen'
assert_eq 'GET HEAD PUT' "${_METHOD_ALLOW[*]}" 'and yields three method tokens'

t_case '`Access-Control-Allow-Methods` is NOT read as `Allow`'
H=$W/h2
_hdr "$H" 'HTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Methods: PUT, DELETE\n\n'
method_allow_collect "$H"
assert_eq 0 "$_METHOD_ALLOW_PRESENT" \
  'a response carrying ONLY a CORS preflight policy advertises no accepted method - FAILS under a case-insensitive substring match for `allow` over the header block, which reads what a BROWSER may send cross-origin as what the ENDPOINT accepts and reports PUT/DELETE as allowed on every CORS-enabled API'
assert_eq 0 "${#_METHOD_ALLOW[@]}" 'and no method token is produced from it'

t_case 'a real `Allow` beside a CORS header is still read, and only it'
H=$W/h3
_hdr "$H" 'HTTP/1.1 200 OK\nAccess-Control-Allow-Methods: PUT, DELETE\nAllow: GET, HEAD\n\n'
method_allow_collect "$H"
assert_eq 'GET HEAD' "${_METHOD_ALLOW[*]}" \
  'the CORS methods are not merged in - FAILS under the substring match, which would yield GET HEAD PUT DELETE and invent two acceptances the server never claimed'

t_case 'a folded continuation line is NOT read as an `Allow` header'
H=$W/h4b
_hdr "$H" 'HTTP/1.1 200 OK\nX-Policy: gateway rules\n\tallow: PUT, DELETE\n\n'
method_allow_collect "$H"
assert_eq 0 "$_METHOD_ALLOW_PRESENT" \
  'an obs-fold continuation (RFC 7230 §3.2.4) whose text happens to read `allow: PUT, DELETE` names no accepted method - FAILS under matching `allow:` anywhere on the line rather than anchored at its start, which lets any target-controlled header value manufacture an acceptance claim, and every response header is untrusted target output (tension 10)'

t_case 'the header NAME is matched case-insensitively'
H=$W/h4
_hdr "$H" 'HTTP/1.1 200 OK\nallow: get, put\n\n'
method_allow_collect "$H"
assert_eq 'GET PUT' "${_METHOD_ALLOW[*]}" \
  'a lowercased header name and lowercased tokens still enumerate - FAILS under a case-sensitive match, which reports nothing for a reverse proxy that lowercases its headers, on a server whose PUT handler is genuinely reachable'
assert_eq 'get put' "${_METHOD_ALLOW_RAW[*]}" \
  'and the token the SERVER sent is preserved, so the finding can quote the spelling rather than a normalisation this tool invented'

# --- reading 2: the OWS trim ------------------------------------------------
t_case 'optional whitespace around each comma is trimmed'
method_allow_split 'GET,  PUT ,DELETE'
assert_eq 'GET' "${_METHOD_TOKENS[0]}" 'the first token has no padding'
assert_eq 'PUT' "${_METHOD_TOKENS[1]}" \
  '`,  PUT ,` yields the token PUT - FAILS under a bare `IFS=, read -ra`, which yields "  PUT " and compares equal to no method name, so a server advertising PUT in the ordinary spelling is reported as advertising none'
assert_eq 'DELETE' "${_METHOD_TOKENS[2]}" 'and the last token is trimmed too'
assert_eq 3 "${#_METHOD_TOKENS[@]}" 'three members, not four'

t_case 'an empty list member is dropped, not kept as a nameless method'
method_allow_split 'GET,,PUT,'
assert_eq 2 "${#_METHOD_TOKENS[@]}" \
  '`GET,,PUT,` is two methods - FAILS under keeping empty members, which classifies and reports a method with no name'

# --- reading 3: the CRLF ----------------------------------------------------
t_case 'a CR left on the last token is stripped by the splitter'
method_allow_split "GET, DELETE"$'\r'
assert_eq 'DELETE' "${_METHOD_TOKENS[1]}" \
  'the trailing CR of a CRLF-terminated header line is not part of the method name - FAILS under dropping the TRAILING half of the OWS trim (a CR is a `[[:space:]]` character, so that trim is what removes it), which yields the token `DELETE<CR>`: it matches no method name, classifies as `other`, and is silently dropped, and the last member of an Allow list is routinely the dangerous one. Asserted on the SPLITTER rather than through a header file on purpose: ripgrep strips a CRLF terminator itself while BSD/GNU grep does not, so a test routed through `scan_match` passes on an rg host whichever way the code reads and pins nothing there - measured, not assumed.'
assert_eq 'write' "$(method_class "${_METHOD_TOKENS[1]}")" 'and it still classifies as a write method'

t_case 'a CRLF-terminated header line does not corrupt its last token'
H=$W/h5
_hdr "$H" 'HTTP/1.1 200 OK\r\nAllow: GET, DELETE\r\nContent-Type: text/html\r\n\r\n'
method_allow_collect "$H"
assert_eq 'GET DELETE' "${_METHOD_ALLOW[*]}" \
  'the trailing CR is stripped - FAILS under reading the line as-is, which yields the token `DELETE<CR>`: it matches no method name, so on every real (CRLF) response the LAST member of the Allow list is the one silently dropped, and the last member is routinely the dangerous one'
assert_eq 'write' "$(method_class "${_METHOD_ALLOW[1]}")" 'and DELETE still classifies as a write method'

# --- reading 5: two Allow headers, and repeats ------------------------------
t_case 'a list split over two `Allow` headers is one list, deduped, in order'
H=$W/h6
_hdr "$H" 'HTTP/1.1 200 OK\nAllow: GET, HEAD\nAllow: HEAD, PATCH\n\n'
method_allow_collect "$H"
assert_eq 'GET HEAD PATCH' "${_METHOD_ALLOW[*]}" \
  'RFC 7230 §3.2.2 permits a list-valued field to be split across headers; the repeat of HEAD is collapsed and the order is the server`s - FAILS under reading only the first Allow header, which loses PATCH'

# --- classification ---------------------------------------------------------
t_case 'method classification'
assert_eq 'write' "$(method_class PUT)" 'PUT is a write method'
assert_eq 'write' "$(method_class DELETE)" 'DELETE is a write method'
assert_eq 'write' "$(method_class PATCH)" 'PATCH is a write method'
assert_eq 'connect' "$(method_class CONNECT)" 'CONNECT is its own class'
assert_eq 'trace' "$(method_class TRACE)" 'TRACE is its own class'
assert_eq 'safe' "$(method_class GET)" 'GET is not a finding'
assert_eq 'safe' "$(method_class POST)" \
  'POST is not a finding either - finding it allowed on an endpoint the crawler already found is how a form works, not an exposure'
assert_eq 'other' "$(method_class PROPFIND)" \
  'a WebDAV extension method classifies as `other` and is not reported - WebDAV enumeration is explicitly out of this ticket`s scope, and classifying it (rather than dropping it) leaves a later ticket somewhere to hang'
assert_eq 'write' "$(method_class put)" \
  'a lowercase token classifies the same - FAILS under case-sensitive classification'

# --- reading 4: a 200 is not a TRACE echo -----------------------------------
_trace_verdict() { if method_trace_enabled "$1" "$2" "$3" "$4"; then printf 'enabled'; else printf 'not'; fi; }

t_case 'a TRACE echo is confirmed by `message/http`'
assert_eq 'enabled' "$(_trace_verdict 200 'message/http' '' /x)" \
  'RFC 7231 §4.3.8`s own content type is sufficient evidence'

t_case 'a TRACE echo is confirmed by the echoed request line'
B=$W/b1
printf 'TRACE /echo HTTP/1.1\r\nHost: t.example\r\n\r\n' >"$B"
assert_eq 'enabled' "$(_trace_verdict 200 'text/plain' "$B" /echo)" \
  'a body that opens with the request line the server received cannot be produced by an application shell that never saw the method - FAILS under requiring `Content-Type: message/http`, which a proxy in front of the application routinely rewrites'

t_case 'a plain 200 with an HTML body is NOT a TRACE echo'
B=$W/b2
printf '<!doctype html>\n<html><body>App</body></html>\n' >"$B"
assert_eq 'not' "$(_trace_verdict 200 'text/html' "$B" /spa)" \
  'a catch-all 200 serving the front-end shell is not TRACE - FAILS under "status 200 means TRACE is enabled", which fires on the standard single-page-app routing shape and puts a Cross-Site Tracing finding in front of an operator with nothing to fix'

t_case 'a 405 is never a TRACE echo whatever it carries'
assert_eq 'not' "$(_trace_verdict 405 'message/http' '' /x)" \
  'a rejection is a rejection - FAILS under testing the content type before the status, which would confirm TRACE off the `message/http` a well-behaved server puts on its own 405'

# ===========================================================================
printf '== B. the phase, against recorded responses ==\n'
# ===========================================================================
# Scope, resolver and scanner limits, exactly as tests/suites/dast-cookies.sh
# sets them: a rate high enough that the DAST-32 ceiling never real-sleeps, and
# the affirmation the ceiling reads.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOS'
id: method-fixture
base-url: https://methods.fixture.example/
notes: Fixture target for tests/suites/dast-methods.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOS
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
cat >"$W/scanner.conf" <<'EOS'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOS
config_scanner_load "$W/scanner.conf"

_mt_resolve() { case $1 in methods.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_mt_resolve

REQ_LOG=$W/requests.log
# The REQUEST headers lib/http.sh was about to send, one `METHOD PATH<TAB>NAME:
# VALUE` line each. They are logged separately from REQ_LOG so a request-count
# assertion is never perturbed by a header, and they are read from
# `_HTTP_TX_HEADERS` - section 9a's own outbound context, the array the real
# curl config is built from - rather than from anything the phase told the test,
# so "the credential was attached" is asserted at the transport boundary.
REQ_HDR_LOG=$W/request-headers.log
_req_reset() { : >"$REQ_LOG"; : >"$REQ_HDR_LOG"; }

# The mock target. Each path answers OPTIONS and TRACE differently; the recorded
# response headers go into the capture file lib/http.sh passes as
# _HTTP_TX_HEADERS_OUT and the body into _HTTP_TX_BODY_OUT, which are the same
# files the phase then reads - so the phase is exercised through the real capture
# path, not through a hand-fed string.
_mt_transport() {
  local method=$1 path=$5
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  local _h
  for _h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    printf '%s %s\t%s\n' "$method" "$path" "$_h" >>"$REQ_HDR_LOG"
  done
  local status=405 ctype='text/plain' location='' hdr='' body=''
  case $method/$path in
    # A plain, well-behaved root.
    OPTIONS//)          status=200; hdr='Allow: GET, HEAD, OPTIONS\r\n' ;;
    # OWS variety and two write methods (reading 2).
    OPTIONS//upload)    status=200; hdr='Allow: GET,  PUT ,DELETE\r\n' ;;
    # ONLY a CORS preflight policy - no Allow at all (reading 1).
    OPTIONS//cors)      status=204; hdr='Access-Control-Allow-Methods: PUT, DELETE\r\nAccess-Control-Allow-Origin: *\r\n' ;;
    # A real TRACE echo, typed per RFC 7231 §4.3.8.
    OPTIONS//echo)      status=200; hdr='Allow: GET, OPTIONS\r\n' ;;
    TRACE//echo)        status=200; ctype='message/http'
                        body='TRACE /echo HTTP/1.1\r\nHost: methods.fixture.example\r\n\r\n' ;;
    # A TRACE echo a proxy has retyped: confirmed by the echoed request line
    # alone, and NOT named in any Allow header (reading 6, first direction).
    OPTIONS//echo2)     status=200 ;;
    TRACE//echo2)       status=200; ctype='text/plain'
                        body='TRACE /echo2 HTTP/1.1\r\nHost: methods.fixture.example\r\n\r\n' ;;
    # The single-page-app catch-all: 200 for anything, front-end shell body.
    OPTIONS//spa)       status=200; ctype='text/html'; body='<!doctype html><html></html>\n' ;;
    TRACE//spa)         status=200; ctype='text/html'; body='<!doctype html><html></html>\n' ;;
    # Advertises TRACE and then rejects it (reading 6, second direction).
    OPTIONS//claimed)   status=200; hdr='Allow: GET, TRACE\r\n' ;;
    TRACE//claimed)     status=405; hdr='Allow: GET, TRACE\r\n' ;;
    # CONNECT advertised.
    OPTIONS//proxy)     status=200; hdr='Allow: GET, CONNECT\r\n' ;;
    # A 405 rejection of OPTIONS that still names the set (reading 5).
    OPTIONS//reject)    status=405; hdr='Allow: GET, PATCH\r\n' ;;
    # Lowercased header name and tokens.
    OPTIONS//lower)     status=200; hdr='allow: get, put\r\n' ;;
    # The POST-only endpoint from the inventory: still asked, safely.
    OPTIONS//login)     status=200; hdr='Allow: POST, OPTIONS\r\n' ;;
    # A redirect, which must not be followed.
    OPTIONS//redir)     status=301; location='https://methods.fixture.example/elsewhere' ;;
    # A transport failure.
    */fail)             return 1 ;;
    # Everything else: a bare 405 naming nothing.
    *)                  status=405 ;;
  esac
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    { printf 'HTTP/1.1 %s X\r\n' "$status"
      printf 'Content-Type: %s\r\n' "$ctype"
      [[ -n $hdr ]] && printf '%b' "$hdr"
      printf '\r\n'
    } >>"$_HTTP_TX_HEADERS_OUT"
  fi
  if [[ -n ${_HTTP_TX_BODY_OUT:-} && -n $body ]]; then
    printf '%b' "$body" >"$_HTTP_TX_BODY_OUT"
  fi
  printf '%s\n%s\n%s\n' "$status" "$location" "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_mt_transport

FULL_INV=$W/endpoints.json
cat >"$FULL_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_root",    "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/",        "path": "/" },
  { "id": "ep_upload",  "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/upload",  "path": "/upload" },
  { "id": "ep_cors",    "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/cors",    "path": "/cors" },
  { "id": "ep_echo",    "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/echo",    "path": "/echo" },
  { "id": "ep_echo2",   "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/echo2",   "path": "/echo2" },
  { "id": "ep_spa",     "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/spa",     "path": "/spa" },
  { "id": "ep_claimed", "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/claimed", "path": "/claimed" },
  { "id": "ep_proxy",   "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/proxy",   "path": "/proxy" },
  { "id": "ep_reject",  "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/reject",  "path": "/reject" },
  { "id": "ep_lower",   "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/lower",   "path": "/lower" },
  { "id": "ep_redir",   "target": "method-fixture", "method": "GET",  "url": "https://methods.fixture.example/redir",   "path": "/redir" },
  { "id": "ep_login",   "target": "method-fixture", "method": "POST", "url": "https://methods.fixture.example/login",   "path": "/login" }
] }
EOS

_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target method-fixture
  occurrence_reset_all
  _req_reset
  SCOURSH_DAST_TARGET=method-fixture
  SCOURSH_DAST_CELL=method-fixture
  SCOURSH_DAST_AUTHED=false
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
}

# `_count CHECK METHOD PATHTPL` - findings whose check_id, loc_method and
# loc_path_template all match exactly. The shard `.fields` format is one finding
# per line, TAB-delimited `key=value` (lib/findings.sh's `_finding_fields`).
_count() {
  local check=$1 meth=$2 tpl=$3 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      local okc=0 okm=0 okp=0
      while IFS= read -r fld; do
        [[ $fld == "check_id=$check" ]] && okc=1
        [[ $fld == "loc_method=$meth" ]] && okm=1
        [[ -z $tpl || $fld == "loc_path_template=$tpl" ]] && okp=1
      done < <(printf '%s' "$line" | tr '\t' '\n')
      (( okc && okm && okp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

_shards() { cat "$SCOURSH_RUN_DIR"/shards/*.fields 2>/dev/null || true; }
_meta_text() { run_facts "$1" 2>/dev/null || true; }

# --- the main pass ---------------------------------------------------------
_new_run main
SCOURSH_DAST_METHOD_ENDPOINTS=$FULL_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=modules/dast/active/methods.sh
source "$ROOT/modules/dast/active/methods.sh"

# --- THE PROPERTY THIS CHECK EXISTS FOR ------------------------------------
t_case 'no state-changing method is ever sent, on any endpoint'
LOG=$(cat "$REQ_LOG")
assert_not_contains "$LOG" 'PUT ' \
  'no PUT is sent even though /upload and /lower both advertise it - FAILS under "confirm the Allow header by trying the method", which creates or overwrites a resource on a target under audit and is exactly what docs/DESIGN.md §7.2`s tier forbids'
assert_not_contains "$LOG" 'DELETE ' \
  'no DELETE is sent even though /upload advertises it - same rejected reading, with the additional property that a successful confirmation would have destroyed the resource it confirmed'
assert_not_contains "$LOG" 'PATCH ' 'no PATCH is sent even though /reject advertises it'
assert_not_contains "$LOG" 'CONNECT ' \
  'no CONNECT is sent even though /proxy advertises it - opening the tunnel would also send this tool`s traffic to a third party, which the egress model forbids outright'
assert_not_contains "$LOG" 'POST ' \
  'no POST is sent even though /login is a POST endpoint in the inventory - the recorded method is never used as the method to send'

t_case 'the only two methods that leave this phase are OPTIONS and TRACE'
BAD=''
while IFS= read -r l; do
  [[ -n $l ]] || continue
  case ${l%% *} in OPTIONS | TRACE) ;; *) BAD+="$l;" ;; esac
done <"$REQ_LOG"
assert_eq '' "$BAD" \
  'every request is OPTIONS or TRACE, both defined as having no effect on the resource (RFC 7231 §4.3.7, §4.3.8) - FAILS under any probe that establishes acceptance by exercising it'

t_case 'a non-GET endpoint IS asked, unlike in the passive cookie phase'
assert_contains "$LOG" 'OPTIONS /login' \
  'the POST-only endpoint is enumerated with OPTIONS - FAILS under copying passive/cookies.sh`s GET-only filter, which would drop exactly the write-shaped endpoints whose method surface is most worth knowing, while this phase never dials the recorded method at all'

# --- reading 1: the CORS trap, end to end ----------------------------------
t_case 'a CORS preflight policy produces no acceptance finding'
assert_eq 0 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 PUT /cors)" \
  '/cors advertises PUT and DELETE ONLY in Access-Control-Allow-Methods and yields no finding - FAILS under matching `allow` as a substring, which turns every CORS-enabled API into a reported PUT exposure'
assert_eq 0 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 DELETE /cors)" 'and none for DELETE either'

# --- reading 2 and 3, end to end -------------------------------------------
t_case 'an OWS-padded Allow list yields both of its write methods'
assert_eq 1 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 PUT /upload)" \
  '`Allow: GET,  PUT ,DELETE` reports PUT - FAILS under a bare `IFS=, read -ra`, which produces "  PUT " and matches no method name'
assert_eq 1 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 DELETE /upload)" \
  'and DELETE, which is the LAST member of a CRLF-terminated header - FAILS under omitting the CR strip, which drops precisely the last member of every real response`s list'

t_case 'two write methods on one path are two findings, not one'
assert_eq 2 "$(( $(_count DAST-METHOD-WRITE_ADVERTISED-01 PUT /upload) + $(_count DAST-METHOD-WRITE_ADVERTISED-01 DELETE /upload) ))" \
  'PUT and DELETE on /upload have different consequences and different fixes - FAILS under one finding per endpoint, which would leave the reader unable to tell which method to close'

t_case 'a lowercase advertisement is still reported, and quotes what the server sent'
assert_eq 1 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 PUT /lower)" \
  '`allow: get, put` reports PUT - FAILS under strict RFC 7231 §4.1 case-sensitivity, which reports nothing on a server whose PUT handler is genuinely reachable behind a header-lowercasing proxy'
assert_contains "$(_shards)" 'spelled it `put`, not `PUT`' \
  'and the evidence quotes the server`s own spelling rather than the normalisation this tool applied'

# --- reading 5: the 405 rejection as an Allow source ------------------------
t_case 'a 405 rejection that names its methods IS read'
assert_eq 1 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 PATCH /reject)" \
  '/reject refuses OPTIONS with a 405 and names PATCH in the rejection`s Allow header, which RFC 7231 §6.5.5 REQUIRES it to carry - FAILS under reading Allow only from a 2xx response, which learns nothing from exactly the servers that refuse OPTIONS and still say what they accept'
assert_contains "$(_shards)" '405' 'and the evidence names the status the fact came from'

# --- reading 4 and 6: TRACE ------------------------------------------------
t_case 'a real TRACE echo is reported'
assert_eq 1 "$(_count DAST-METHOD-TRACE_ENABLED-01 TRACE /echo)" \
  'the message/http echo on /echo is Cross-Site Tracing'

t_case 'a TRACE echo NOT named in Allow is still reported'
assert_eq 1 "$(_count DAST-METHOD-TRACE_ENABLED-01 TRACE /echo2)" \
  '/echo2 echoes the request while naming TRACE in no Allow header at all, and is still a finding - FAILS under "report what Allow names", which misses the ordinary shape of this defect: a server with TRACE on by default and no Allow header at all'
assert_contains "$(_shards)" 'named `TRACE` in NO `Allow` header' \
  'and the evidence says the advertisement was absent, so the operator knows the finding was measured'

t_case 'a catch-all 200 is NOT reported as TRACE'
assert_eq 0 "$(_count DAST-METHOD-TRACE_ENABLED-01 TRACE /spa)" \
  '/spa answers every request 200 with its front-end shell and yields no finding - FAILS under "TRACE returned 200 means TRACE is enabled", which fires on the standard single-page-app routing shape'

t_case 'TRACE advertised but demonstrably rejected is NOT a finding'
assert_eq 0 "$(_count DAST-METHOD-TRACE_ENABLED-01 TRACE /claimed)" \
  '/claimed names TRACE in Allow and answers the actual TRACE with 405, so no Cross-Site Tracing finding is raised - FAILS under trusting the header over the measurement, which reports a defect the operator can neither reproduce nor fix'
assert_contains "$(_meta_text notes)" 'trace_advertised_not_confirmed' \
  'and the contradiction is still recorded, because a routing table that names a method it refuses is a real defect'

t_case 'TRACE is never reported through the write or connect check'
assert_eq 0 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 TRACE '')" 'TRACE is not a write method'
assert_eq 0 "$(_count DAST-METHOD-CONNECT_ADVERTISED-01 TRACE '')" 'nor a CONNECT'

# --- CONNECT ---------------------------------------------------------------
t_case 'an advertised CONNECT is reported'
assert_eq 1 "$(_count DAST-METHOD-CONNECT_ADVERTISED-01 CONNECT /proxy)" \
  '/proxy advertises CONNECT and is reported as an open-proxy shape'

# --- the safe methods are not findings --------------------------------------
t_case 'GET, HEAD, OPTIONS and POST are never reported'
for M in GET HEAD OPTIONS POST; do
  assert_eq 0 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 "$M" '')" \
    "$M is advertised somewhere on this surface and is not a finding - FAILS under reporting every method the Allow header names, which buries the three that matter under the ordinary surface of every web application"
done

# --- the honesty records ----------------------------------------------------
t_case 'each finding states HOW acceptance was determined'
SH=$(_shards)
assert_contains "$SH" 'Allow` header of the `200` response to `OPTIONS' \
  'a finding learned from a 200 OPTIONS says so'
assert_contains "$SH" 'Allow` header of the `405` response' \
  'a finding learned from a 405 rejection says so, and names the different status'
assert_contains "$SH" 'NOT EXERCISED: no ' \
  'and every advertisement-derived finding states that the method was not sent - FAILS under evidence that only names the method, which lets a reader assume the scanner demonstrated the write'

t_case 'the standing "no write method was exercised" bound is recorded'
assert_contains "$(_meta_text coverage_reduction)" 'methods_write_not_exercised' \
  'the run states that acceptance came from the server`s advertisement and that an endpoint accepting a write method without advertising it is not covered - FAILS under recording nothing, which lets the absence of a write finding read as "no write method is enabled" when it means "none was advertised"'

t_case 'an endpoint that named nothing is recorded, not counted as clean'
assert_contains "$(_meta_text coverage_reduction)" 'methods_no_allow_header' \
  '/cors and /spa answered without any Allow header and the run says so - FAILS under staying quiet, which reports silence from the server as a clean method surface'

t_case 'a redirect is not followed and is recorded'
assert_not_contains "$LOG" '/elsewhere' \
  'the 301 on /redir is not followed - FAILS under following it, which answers "which methods does /elsewhere accept" and labels the answer /redir'
assert_contains "$(_meta_text coverage_reduction)" 'methods_endpoint_redirected' 'and the omission is recorded'

t_case 'the checks that ran are recorded as run'
CR=$(_meta_text checks_run)
assert_contains "$CR" 'DAST-METHOD-TRACE_ENABLED-01' 'TRACE_ENABLED is in checks_run'
assert_contains "$CR" 'DAST-METHOD-WRITE_ADVERTISED-01' 'WRITE_ADVERTISED is in checks_run'
assert_contains "$CR" 'DAST-METHOD-CONNECT_ADVERTISED-01' 'CONNECT_ADVERTISED is in checks_run'

t_case 'an unauthenticated-only pass says so'
assert_contains "$(_meta_text coverage_reduction)" 'methods_unauthenticated_only' \
  'the run states that no authenticated response was enumerated - FAILS under staying quiet, since an application routinely refuses a write method to an anonymous caller and accepts it from a logged-in one'

t_case 'the findings carry CWE, OWASP, confidence and remediation'
assert_contains "$SH" 'cwe=CWE-693' 'TRACE is CWE-693'
assert_contains "$SH" 'cwe=CWE-749' 'an exposed write method is CWE-749'
assert_contains "$SH" 'cwe=CWE-441' 'CONNECT is CWE-441'
assert_contains "$SH" 'owasp=A05:2021' 'all three map to A05'
assert_contains "$SH" 'remediation=' 'every finding carries remediation text'
assert_contains "$SH" 'confidence=medium' \
  'an advertisement-derived finding is medium confidence - FAILS under presenting a claim and a measurement at one confidence, which leaves the reader unable to tell which is which'
assert_contains "$SH" 'confidence=high' 'and the measured TRACE finding is high'

# --- determinism ------------------------------------------------------------
t_case 'the endpoint walk is deterministic'
RUN1=$(cat "$REQ_LOG")
_new_run repeat
SCOURSH_DAST_METHOD_ENDPOINTS=$FULL_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_eq "$RUN1" "$(cat "$REQ_LOG")" \
  'two runs over the identical surface issue the identical requests in the identical order - FAILS under iterating the endpoint map in bash associative-array (hash) order, which makes a capped run`s coverage unpredictable and the output non-reproducible'

# ===========================================================================
printf '== C. degradation: every way of covering nothing is recorded ==\n'
# ===========================================================================
t_case 'no endpoint inventory is a recorded gap, not a clean result and not an error'
_new_run noinv
SCOURSH_DAST_METHOD_ENDPOINTS=$W/absent-inventory.json
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_contains "$(_meta_text coverage_gap)" 'no known endpoint' \
  'the report says nothing was tested - FAILS under returning quietly, which produces a report with no method findings and no reason'
assert_contains "$(_meta_text coverage_reduction)" 'no_endpoint_inventory' 'and records the machine-readable reason'
assert_eq '' "$(cat "$REQ_LOG")" 'and sends no request at all'
assert_not_contains "$(_meta_text checks_run)" 'DAST-METHOD-TRACE_ENABLED-01' \
  'and does NOT record the check as run - FAILS under recording coverage for a check that enumerated nothing, which is what makes a gap invisible in tension 12`s (check, cell) coverage'

t_case 'an empty endpoint inventory is the same gap'
EMPTY_INV=$W/empty.json
cat >"$EMPTY_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [] }
EOS
_new_run emptyinv
SCOURSH_DAST_METHOD_ENDPOINTS=$EMPTY_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_eq '' "$(cat "$REQ_LOG")" 'no request is sent for an inventory with an empty endpoint list'
assert_contains "$(_meta_text coverage_reduction)" 'no_endpoint_inventory' 'and the reason is recorded'
assert_contains "$(_meta_text coverage_gap)" 'coverage gap' 'and a human-readable gap is written'

t_case 'the per-phase endpoint cap is a recorded coverage bound'
_new_run cap
SCOURSH_DAST_METHOD_ENDPOINTS=$FULL_INV
SCOURSH_DAST_METHOD_MAX_ENDPOINTS=2
export SCOURSH_DAST_METHOD_ENDPOINTS SCOURSH_DAST_METHOD_MAX_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
_paths() { local l out=''; while IFS= read -r l; do [[ -n $l ]] && out+="${l##* }"$'\n'; done <"$REQ_LOG"; printf '%s' "$out" | LC_ALL=C sort -u | tr '\n' ' '; }
assert_eq 2 "$(_paths | wc -w | tr -d ' ')" 'exactly the cap of 2 distinct endpoints is enumerated'
assert_eq '/ /claimed ' "$(_paths)" \
  'and they are the two LC_ALL=C-lowest endpoint URLs, not two of the twelve - FAILS under iterating `_INJ_EP_URL` in bash associative-array (hash) order, which makes WHICH endpoints a capped run enumerates depend on the hash of their names, so two installs over the identical surface report different findings and the output stops being reproducible'
assert_contains "$(_meta_text coverage_gap)" 'exceeded the per-phase cap' \
  'the truncation is stated - FAILS under silently enumerating a prefix of the surface and reporting the same verdict'
unset SCOURSH_DAST_METHOD_MAX_ENDPOINTS

t_case 'a failing endpoint is recorded and does not stop the rest'
FAILINV=$W/fail.json
cat >"$FAILINV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_fail",   "target": "method-fixture", "method": "GET", "url": "https://methods.fixture.example/fail",   "path": "/fail" },
  { "id": "ep_upload", "target": "method-fixture", "method": "GET", "url": "https://methods.fixture.example/upload", "path": "/upload" }
] }
EOS
_new_run failcase
SCOURSH_DAST_METHOD_ENDPOINTS=$FAILINV
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_eq 1 "$(_count DAST-METHOD-WRITE_ADVERTISED-01 PUT /upload)" \
  'the endpoint after the failing one is still enumerated - FAILS under aborting the phase on the first transport failure'
assert_contains "$(_meta_text coverage_reduction)" 'methods_request_failed' 'and the failure is recorded'

t_case 'a surface where nothing names its methods is a gap, not a clean result'
QUIET_INV=$W/quiet.json
cat >"$QUIET_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_cors", "target": "method-fixture", "method": "GET", "url": "https://methods.fixture.example/cors", "path": "/cors" }
] }
EOS
_new_run quiet
SCOURSH_DAST_METHOD_ENDPOINTS=$QUIET_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_contains "$(_meta_text coverage_gap)" 'UNKNOWN, not clean' \
  'a target where no endpoint named a single method is reported as unknown - FAILS under emitting nothing, which is indistinguishable from a target that answered fully and cleanly'

# ===========================================================================
printf '== E. the authenticated pass actually carries the credential ==\n'
# ===========================================================================
# An application routinely refuses a write method to an anonymous caller and
# accepts it from a logged-in one, so an authenticated pass that quietly sends
# nothing does not merely lose coverage - it reports the LOGGED-OUT method
# surface as if it were the logged-in one, and the run says
# `authenticated_pass=1` while it does so.
#
# A `bearer` identity is used because it acquires with ZERO network (the
# operator already handed us the token), so this stays a recorded-response
# suite. It is asserted on the outbound header context at the transport
# boundary, not on anything the phase reports about itself.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/auth_engine.sh"

AUTH_CONF=$W/auth.conf
: >"$AUTH_CONF"
chmod 600 "$AUTH_CONF"
printf 'id: method-fixture.op\nmode: bearer\ntoken: t0ken-m\n' >"$AUTH_CONF"

AUTH_INV=$W/endpoints-auth.json
cat >"$AUTH_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_echo", "target": "method-fixture", "method": "GET", "url": "https://methods.fixture.example/echo", "path": "/echo" }
] }
EOS

t_case 'under --authed, every request this phase issues carries the session'
_new_run authed
dast_auth_load "$AUTH_CONF"
dast_auth_acquire method-fixture op
assert_eq authenticated "$_DAST_AUTH_STATE" \
  'the fixture identity is authenticated with no request sent, so this section stays a recorded-response test'
_req_reset
SCOURSH_DAST_AUTHED=true
SCOURSH_DAST_METHOD_ENDPOINTS=$AUTH_INV
export SCOURSH_DAST_AUTHED SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"

assert_contains "$(cat "$REQ_HDR_LOG")" 'OPTIONS /echo	Authorization: Bearer t0ken-m' \
  'the OPTIONS carries the identity - FAILS under attaching the session through a helper that does not exist, which a `declare -F` guard turns into a silently anonymous pass that still records authenticated_pass=1'
assert_contains "$(cat "$REQ_HDR_LOG")" 'TRACE /echo	Authorization: Bearer t0ken-m' \
  'and so does the TRACE - FAILS under attaching the credential ONCE per endpoint, since lib/http.sh consumes its per-request context at entry, so the second request of the pair would go out anonymous'
assert_contains "$(_meta_text coverage_reduction)" 'methods_write_not_exercised' \
  'the standing not-exercised bound is still recorded on an authenticated run'
assert_not_contains "$(_meta_text coverage_reduction)" 'methods_unauthenticated_only' \
  'and the unauthenticated-only reduction is NOT - FAILS under recording it unconditionally, which would tell an operator who did authenticate that the run did not'

t_case 'without --authed the same surface sends no credential at all'
_new_run unauthed
_req_reset
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_METHOD_ENDPOINTS=$AUTH_INV
export SCOURSH_DAST_AUTHED SCOURSH_DAST_METHOD_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh"
assert_not_contains "$(cat "$REQ_HDR_LOG")" 'Authorization:' \
  'a run that did not ask to authenticate sends no credential - FAILS under attaching whatever session happens to be in the store, which would put a credential on the wire the operator never asked this run to use'

# ===========================================================================
printf '== D. registration ==\n'
# ===========================================================================
t_case 'the phase table reaches this script, and only at safe or above'
FOUND=0
for spec in "${_DAST_PHASES[@]}"; do
  [[ $spec == 'active/methods.sh:safe' ]] && FOUND=1
done
assert_eq 1 "$FOUND" \
  'modules/dast/engine.sh names active/methods.sh at tier safe, so scan_dispatch dast runs it from --intensity safe upward'

SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'active/methods.sh:safe' safe method-fixture >/dev/null 2>&1 || true
assert_eq 1 "$_DAST_PHASE_PRESENT" \
  'dast_run_phase now finds the script on disk - FAILS while the file is absent, which is the state every DAST-0x row starts in'

SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'active/methods.sh:safe' passive method-fixture >/dev/null 2>&1 || true
assert_eq 'skipped_intensity' "$_DAST_PHASE_OUTCOME" \
  'a passive run does NOT reach it - FAILS under declaring the phase at tier passive, which would send OPTIONS and TRACE on a run whose whole contract is that it only reads what the target volunteers'

t_case 'every check id this phase emits is in the registry'
SCOURSH_INSTALL_ROOT=$ROOT checks_registry_load dast DASTMT
REG=''
for s in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
  n=$(records_count "$s")
  for (( ri = 0; ri < n; ri++ )); do
    REG+=$(records_id "$s" "$ri")
    REG+=' '
  done
done
for id in DAST-METHOD-TRACE_ENABLED-01 DAST-METHOD-WRITE_ADVERTISED-01 \
          DAST-METHOD-CONNECT_ADVERTISED-01; do
  assert_contains "$REG" "$id" \
    "$id is registered in modules/dast/active/checks.rules - FAILS if a check is emitted with no registry record, which leaves tension 12 unable to compute coverage for it and tension 15 unable to filter it"
done

t_summary dast-methods
