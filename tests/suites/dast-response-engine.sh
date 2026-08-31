#!/usr/bin/env bash
# tests/suites/dast-response-engine.sh - modules/dast/passive/response_engine.sh:
# the shared HTTP response reader every DAST check that looks at a response head
# uses.
#
# WHY THIS SUITE EXISTS SEPARATELY FROM tests/suites/dast-headers.sh.  The reader
# was DAST-05's, and its unit cases lived in that ticket's suite.  Six landed
# files now depend on it, so its tests moved here with it - a shared component
# whose only tests live in one consumer's suite is a component the next consumer
# is free to break quietly, because nothing named it.  The end-to-end pins stay
# where they are: tests/suites/dast-headers.sh and tests/suites/dast-leakage.sh
# each still have a PHASE-level case that goes red if the last-hop reset is
# removed, so the property is measured at both grains and in three places.
#
# SECTIONS A-F TOUCH NO NETWORK, AND UNLIKE EVERY OTHER dast-* SUITE THEY
# CANNOT.  Up to and including section F, this suite sources the file under
# test and tests/lib/assert.sh and nothing else - no lib/http.sh, no
# lib/core.sh, no scratch dir, no stubbed transport, no stubbed resolver.  That
# is not a convenience: section A asserts it, because "response_engine.sh is a
# LEAF in the source graph" is the property the reader lift bought
# (docs/CI-RUNBOOK.md, "the memory model": `shellcheck -x` re-expands every
# source edge it follows, so a consumer that only wants the reader used to pay
# for lib/http.sh, crawl_engine.sh and DAST-05's parsers to get it).  A source
# edge added back to response_engine.sh ITSELF turns section A red rather than
# being noticed a year later as a slow linter.
#
# SECTION G IS DIFFERENT, AND SAYS SO WHERE IT STARTS.  It tests
# `resp_endpoints_load`, the shared GET-endpoint chooser
# (docs/STEP5-DAST-PLAN.md, "lift the shared passive endpoint chooser into
# modules/dast/passive/response_engine.sh") - a function response_engine.sh
# DEFINES but does not itself make callable, because it calls
# `crawl_json_flatten`/`crawl_json_unescape` and `path_template_of` BY NAME
# without sourcing the files that define them (see response_engine.sh's own
# ADR block for why: sourcing them here would undo the reader lift's whole
# point for the five reader-only consumers).  Exercising it for real therefore
# needs `modules/dast/crawl_engine.sh` and `lib/findings.sh` sourced first,
# which pulls in `lib/records.sh` -> `lib/core.sh` and its scratch
# dir/traps - the section says so before it does it, so section A's "sourcing
# response_engine.sh ALONE defines none of this" assertions, which run first,
# are not contradicted by anything later in the file.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header, URL and shell syntax literally, in
#   single quotes on purpose - there is nothing in it to expand.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# The file under test, and NOTHING ELSE.  Deliberately not `-x`-cut: this is the
# only source edge in the suite and cutting a file's only edge is a real loss of
# analysis (docs/CI-RUNBOOK.md).  It is cheap precisely because the target is a
# leaf.
# shellcheck source=modules/dast/passive/response_engine.sh
source "$ROOT/modules/dast/passive/response_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

# No lib/core.sh means no SCOURSH_SCRATCH, so this suite owns its own directory
# and removes it itself.  `mktemp -d`, never a name built from `$BASHPID`: a
# predictable path under a world-writable /tmp is one a local user can
# pre-create as a symlink that this process then writes through
# (modules/dast/passive/cors_engine.sh's own CWE-377-via-CWE-59 lesson).
W=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-response-engine.XXXXXX")
chmod 700 "$W" 2>/dev/null || true
trap 'rm -rf "$W"' EXIT
CAP=$W/cap

# `_defined NAME` prints yes/no.  A bare `declare -F` would abort the suite
# under `set -e` on exactly the absent case these assertions are about.
_defined() { declare -F "$1" >/dev/null 2>&1 && printf 'yes' || printf 'no'; }

# ===========================================================================
printf '== A. the file is a LEAF, and holds the reader and only the reader ==\n'
# ===========================================================================
t_case 'leaf'
assert_eq yes "$(_defined hdr_parse_capture)" 'the reader is here'
assert_eq yes "$(_defined hdr_present)" 'and its accessors'
assert_eq yes "$(_defined hdr_value)" 'hdr_value'
assert_eq yes "$(_defined hdr_first)" 'hdr_first'
assert_eq yes "$(_defined hdr_safe_text)" 'hdr_safe_text'
assert_eq yes "$(_defined hdr_is_document)" 'hdr_is_document'
assert_eq yes "$(_defined hdr_path_of)" 'hdr_path_of'
assert_eq yes "$(_defined hdr_url_is_https)" 'hdr_url_is_https'

# THE PROPERTY THE LIFT BOUGHT.  Sourcing the reader must not drag a transport,
# a JSON flattener, or a config loader in behind it.  Each of these WOULD be
# defined had this suite sourced headers_engine.sh, which is what every consumer
# of the reader used to do.
assert_eq no "$(_defined http_request)" \
  'sourcing the reader defines NO transport - FAILS the moment a source edge back to lib/http.sh is added, which is the edge the lift removed and the one a future "just source http.sh here" change would restore'
assert_eq no "$(_defined crawl_json_flatten)" \
  'and no inventory flattener - FAILS under a source edge to crawl_engine.sh, which resp_endpoints_load (below) calls BY NAME rather than by sourcing it, exactly so this stays no'
assert_eq no "$(_defined config_scanner_list)" \
  'and no config loader'

# The parsers, the recommended-header loader and the endpoint chooser stayed in
# headers_engine.sh where they belong.  Asserting their ABSENCE is what stops
# this file quietly re-accumulating into the shared-scaffolding module the
# passive tier deliberately never created.
assert_eq no "$(_defined hdr_csp_load)" \
  'the CSP parsers stayed in headers_engine.sh - FAILS under a lift that moved the whole file rather than the reader'
assert_eq no "$(_defined hdr_hsts_parse)" 'so did the HSTS parser'
assert_eq no "$(_defined hdr_referrer_effective)" 'so did the Referrer-Policy parser'
assert_eq no "$(_defined hdr_load_recommended)" 'so did the recommended-header loader'
assert_eq no "$(_defined hdr_endpoints_load)" \
  'hdr_endpoints_load the NAME stayed in headers_engine.sh, as a thin wrapper, so no caller of it had to change - FAILS if the wrapper were deleted in favour of every caller reading resp_endpoints_load (below) directly'
assert_eq yes "$(_defined resp_endpoints_load)" \
  'the shared endpoint chooser IS here, under its own name, once markup_engine.sh shipped a second byte-identical copy of hdr_endpoints_load and made the duplication real rather than hypothetical (AGENTS.md: two real cases, not one)'

assert_eq 200 "$_HDR_MAX_EVIDENCE_FIELD" \
  "hdr_safe_text's evidence cap travelled WITH it - FAILS under a lift that moves the function and leaves its default behind in headers_engine.sh, where it is unbound under set -u for anyone sourcing the reader alone"

# ===========================================================================
printf '== B. the reader: only the FINAL hop counts ==\n'
# ===========================================================================
t_case 'reader-final-hop'
# `http_request_capture`'s header sink ACCUMULATES every redirect hop
# (lib/http.sh §9a), so a capture for a request that redirected holds two or
# more header blocks.  This is the reader's whole reason for existing.
printf 'HTTP/1.1 302 Found\r\nStrict-Transport-Security: max-age=31536000\r\nLocation: /final\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 200 "$_HDR_STATUS" \
  'the reader reports the FINAL hop status, not the redirect - FAILS if it stops at the first status line'
assert_true "$(hdr_present x-content-type-options && printf 0 || printf 1)" \
  'a header on the final hop is present'
assert_true "$(hdr_present strict-transport-security && printf 1 || printf 0)" \
  'HSTS set only on the REDIRECT hop is NOT reported as present on the final response - FAILS under a whole-file grep, which is the whole reason this reader exists'
assert_eq '' "${_HDR_VALUE[location]:-}" \
  "the redirect's own Location does not survive into the final hop's values either - FAILS under a reset that clears only _HDR_COUNT and leaves _HDR_VALUE populated, which hdr_value would then happily return"

# The reset must fire on EVERY status line, not only the second.
printf 'HTTP/1.1 301 Moved\r\nX-A: 1\r\n\r\nHTTP/1.1 302 Found\r\nX-B: 2\r\n\r\nHTTP/1.1 204 No Content\r\nX-C: 3\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 204 "$_HDR_STATUS" 'three hops: the third status is the reported one'
assert_eq no "$(hdr_present x-a && printf yes || printf no)" 'the first hop is gone'
assert_eq no "$(hdr_present x-b && printf yes || printf no)" \
  'and so is the SECOND - FAILS under a reset that runs once rather than on every status line, a shape the two-hop case above cannot tell apart from the correct one'
assert_eq yes "$(hdr_present x-c && printf yes || printf no)" 'the last hop survives'

t_case 'reader-shape'
printf 'HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 2 "${_HDR_COUNT[set-cookie]}" \
  'a repeated field is counted, not overwritten - the HSTS_MALFORMED duplicate case depends on it'
assert_eq $'a=1\nb=2' "${_HDR_VALUE[set-cookie]}" 'and both values are kept, LF-joined'

printf 'HTTP/1.1 200 OK\r\nX-First: 1\r\nX-Second: 2\r\nX-First: 3\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 'x-first x-second' "${_HDR_NAMES[*]}" \
  'names are published lowercased, in ARRIVAL order, once each - FAILS under an append-per-occurrence, which would list x-first twice and make a caller iterating _HDR_NAMES read the same field twice'

printf 'HTTP/1.1 200 OK\r\nX-Frame-Options:\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq yes "$(hdr_present x-frame-options && printf yes || printf no)" \
  'a field with an EMPTY value is PRESENT - FAILS under a non-empty-value test, which reports a misconfigured header as an absent one and gives the operator the wrong sentence'

printf 'HTTP/1.1 200 OK\r\nX-Case-Test: v\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq yes "$(hdr_present X-CASE-TEST && printf yes || printf no)" \
  'lookup is case-insensitive on the field name - FAILS under a byte compare, and RFC 7540 §8.1.2 REQUIRES lowercase on the wire, so every HTTP/2-fronted target would read clean'

printf 'HTTP/1.1 200 OK\r\nX-Good: 1\r\nnot a header line\r\n  folded continuation\r\nX-Bad Name: 2\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq yes "$(hdr_present x-good && printf yes || printf no)" 'a well-formed field is read'
assert_eq 1 "${#_HDR_NAMES[@]}" \
  'and a line whose name is not an RFC 7230 token is DROPPED rather than guessed at - FAILS under a plain split on the first colon, which mints a header named "  folded continuation" out of a continuation line'

t_case 'reader-refusals'
# `hdr_parse_capture` publishes GLOBALS, so a refusal case must call it in THIS
# shell and capture the status into a variable.  Calling it as
# `$(hdr_parse_capture ...)` runs it in a subshell whose assignments are
# discarded (AGENTS.md, "Things measured on this codebase"), so `_HDR_STATUS`
# would still hold the PREVIOUS case's value and the assertion below would be
# reading stale state rather than the refusal.  The status assertions therefore
# use `_rc`; the `|| _rc=$?` is what keeps `set -e` from aborting on the
# deliberate non-zero return.
_rc=0; hdr_parse_capture "$CAP" || _rc=$?
: >"$CAP"
_rc=0; hdr_parse_capture "$CAP" || _rc=$?
assert_eq 1 "$_rc" \
  'an empty capture returns non-zero rather than reporting a response with no headers'
assert_eq '' "$_HDR_STATUS" \
  'and CLEARS the status rather than leaving the previous response in place - FAILS under a reader that returns early before resetting, which hands the next caller the last response it happened to parse'
printf 'X-Orphan: 1\r\n' >"$CAP"
_rc=0; hdr_parse_capture "$CAP" || _rc=$?
assert_eq 1 "$_rc" \
  'a capture with header lines but NO status line is also non-zero - FAILS under a reader that returns 0 whenever it read something, which would report a truncated capture as a real response'
assert_eq no "$(hdr_present x-orphan && printf yes || printf no)" \
  'and nothing before the first status line is published - FAILS under a parser that accumulates from byte 0, which trusts bytes no response claimed'
assert_true "$(hdr_parse_capture "$W/does-not-exist" && printf 1 || printf 0)" \
  'an unreadable capture is non-zero, so "no response" and "a response with no headers" stay distinguishable'

# ===========================================================================
printf '== C. hdr_value and hdr_first ==\n'
# ===========================================================================
t_case 'accessors'
printf 'HTTP/1.1 200 OK\r\nX-Multi: one\r\nX-Multi: two\r\nX-Solo:   spaced   \r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
hdr_value x-multi
assert_eq $'one\ntwo' "$_HDR_V" 'hdr_value returns every occurrence, LF-joined'
hdr_first x-multi
assert_eq one "$_HDR_V" \
  'hdr_first returns the FIRST occurrence only - FAILS under a last-wins reading, and under one that returns the LF-joined string, which a caller would then match a pattern across two headers with'
hdr_value x-solo
assert_eq spaced "$_HDR_V" \
  'leading and trailing whitespace is trimmed off the value (RFC 7230 OWS) - FAILS under a bare cut at the colon, which leaves a leading space in front of every value and defeats an anchored comparison'
hdr_value x-absent
assert_eq '' "$_HDR_V" 'an absent field yields the empty string rather than an unbound-variable abort'
hdr_first x-absent
assert_eq '' "$_HDR_V" 'and so does hdr_first'

# ===========================================================================
printf '== D. hdr_is_document ==\n'
# ===========================================================================
t_case 'content-type'
assert_true "$(hdr_is_document 'text/html; charset=utf-8' && printf 0 || printf 1)" 'text/html is a document'
assert_true "$(hdr_is_document 'application/json' && printf 1 || printf 0)" 'application/json is not'
assert_true "$(hdr_is_document 'TEXT/HTML; charset=utf-8  ' && printf 0 || printf 1)" \
  'the media type is matched case-insensitively, after the parameters and any TRAILING whitespace are cut - FAILS under a byte compare, which reports a document response as a non-document and silently drops the CSP and framing checks for it. RFC 7231 §3.1.1.1 makes the type case-insensitive, and a proxy appending a space before the CRLF is ordinary.'
assert_true "$(hdr_is_document 'application/xhtml+xml' && printf 0 || printf 1)" 'xhtml is a document'
assert_true "$(hdr_is_document 'text/plain' && printf 1 || printf 0)" 'text/plain is not'
assert_true "$(hdr_is_document '' && printf 1 || printf 0)" 'and neither is an absent Content-Type'

# LEADING whitespace is deliberately NOT trimmed here, and that is safe only
# because of where the value comes from: `hdr_parse_capture` strips RFC 7230 OWS
# off every value before any caller sees it, so a leading space cannot reach
# this function through the real path.  Asserting the two TOGETHER is what pins
# that, rather than asserting a trim this function does not do (which was this
# suite's first draft, and it went red against correct code) or asserting the
# untrimmed input in isolation (which would silently become wrong the day
# `hdr_parse_capture` stopped trimming).
printf 'HTTP/1.1 200 OK\r\nContent-Type:   text/html; charset=utf-8\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
hdr_first content-type
assert_true "$(hdr_is_document "$_HDR_V" && printf 0 || printf 1)" \
  'a Content-Type sent with extra leading OWS is still a document once it has been through hdr_parse_capture - FAILS if that reader stops trimming values, which would silently switch the CSP and framing checks off for every such response'

# ===========================================================================
printf '== E. hdr_safe_text ==\n'
# ===========================================================================
t_case 'safe-text'
assert_eq 'a b c d' "$(hdr_safe_text $'a\nb\rc\td')" \
  'CR, LF and TAB in target-derived text are flattened to spaces - FAILS if they are passed through, and a raw CR/LF in an evidence sentence is a log-injection primitive the target chose'
LONG=$(printf 'x%.0s' $(seq 1 300))
OUT=$(hdr_safe_text "$LONG")
assert_eq 203 "${#OUT}" \
  'a value over the cap is truncated to the cap plus the "..." marker - FAILS under an uncapped read, which lets one 40 KiB CSP become the whole evidence field'
assert_eq '...' "${OUT: -3}" 'and the truncation is MARKED, so a reader is never shown a silently shortened value as if it were complete'
assert_eq 'short' "$(hdr_safe_text short)" 'a value under the cap is returned unchanged'
assert_eq 'abcde' "$(hdr_safe_text abcde 99)" 'an explicit cap above the length changes nothing'
assert_eq 'ab...' "$(hdr_safe_text abcde 2)" 'and an explicit cap below it wins over the default'

# ===========================================================================
printf '== F. hdr_path_of and hdr_url_is_https ==\n'
# ===========================================================================
t_case 'url-helpers'
assert_eq /a/b "$(hdr_path_of https://h.example/a/b)" 'the path of an absolute URL'
assert_eq / "$(hdr_path_of https://h.example)" \
  'a URL with NO path is `/` - FAILS under a reading that returns the empty string, which makes path_template_of and every path-keyed dedup treat the front door as a nameless endpoint'
assert_eq / "$(hdr_path_of https://h.example/)" 'and so is a bare trailing slash'
assert_eq /a "$(hdr_path_of 'https://h.example/a?q=1&r=2')" \
  'the query string is stripped - FAILS if it is kept, which turns one paginated handler into fifty endpoints'
assert_eq /a "$(hdr_path_of 'https://h.example/a#frag')" 'and so is the fragment'
assert_eq /a "$(hdr_path_of 'https://h.example/a?q=1#frag')" 'both together, fragment first'
assert_eq /p "$(hdr_path_of 'https://user:pw@h.example/p')" 'userinfo in the authority does not become the path'

assert_true "$(hdr_url_is_https https://h.example/ && printf 0 || printf 1)" 'an https URL'
assert_true "$(hdr_url_is_https http://h.example/ && printf 1 || printf 0)" 'a plaintext one is not'
assert_true "$(hdr_url_is_https HTTPS://h.example/ && printf 0 || printf 1)" \
  'the scheme is matched case-insensitively (RFC 3986 §3.1 makes it so) - FAILS under a byte compare, which reports an https target as plaintext and skips the HSTS evaluation entirely'
assert_true "$(hdr_url_is_https 'https-not-a-scheme://h/' && printf 1 || printf 0)" \
  'and the match is anchored on the real scheme - FAILS under a substring test'

# ===========================================================================
printf '== G. resp_endpoints_load: the shared GET-endpoint chooser ==\n'
# ===========================================================================
# FROM HERE ON THIS SUITE IS NO LONGER A LEAF TEST - see this file's own header
# for why testing this one function needs more than response_engine.sh alone.
# shellcheck source=modules/dast/crawl_engine.sh
source "$ROOT/modules/dast/crawl_engine.sh"
# lib/findings.sh is sourced for `path_template_of` alone; it pulls in
# lib/records.sh -> lib/core.sh, which bootstraps a scratch dir and traps as a
# source-time side effect (AGENTS.md, "Things measured on this codebase" is not
# about this specifically, but lib/core.sh's own `scratch_init`/
# `core_install_traps` calls at its own top level are what do it).
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
t_case 'resp_endpoints_load'

_g_inv() {
  local name=$1; shift
  local f=$W/$name.endpoints.json rows='' u m t i=0
  while (( $# > 0 )); do
    u=$1; m=$2; t=$3; shift 3
    rows+="${rows:+,}"$'\n'"  { \"id\": \"e$i\", \"target\": \"$t\", \"method\": \"$m\", \"url\": \"$u\", \"path\": \"$(hdr_path_of "$u")\" }"
    i=$(( i + 1 ))
  done
  printf '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [%s\n] }\n' "$rows" >"$f"
  printf '%s' "$f"
}

# 1. base-url first, and outside the sort.
INV=$(_g_inv base https://h.example/z GET t https://h.example/a GET t)
resp_endpoints_load "$INV" t https://h.example/front 10
assert_eq /front "${_RESP_PATH[0]}" \
  "the operator's own base-url is candidate zero, ahead of every inventory row - FAILS under a plain sort of the combined set, which would put /a first"
assert_eq 3 "$_RESP_N" 'the base-url plus the two distinct inventory rows'

# 2. GET only; a non-GET row is counted and dropped, never requested.
INV=$(_g_inv methods https://h.example/get GET t https://h.example/post POST t)
resp_endpoints_load "$INV" t '' 10
assert_eq 1 "$_RESP_N" 'only the GET row survives'
assert_eq /get "${_RESP_PATH[0]}" 'and it is the GET one'
assert_eq 1 "$_RESP_SKIPPED_NON_GET" \
  'the POST row is COUNTED as skipped, not silently dropped - a caller reports this rather than staying quiet about it'

# 3. deduped by PATH TEMPLATE, not by URL.
INV=$(_g_inv dedupe https://h.example/order/1 GET t https://h.example/order/2 GET t)
resp_endpoints_load "$INV" t '' 10
assert_eq 1 "$_RESP_N" \
  '/order/1 and /order/2 are one path template and cost one candidate - FAILS under a per-URL dedup, which would spend two'

# 4. sorted, then capped, and the cap is a PARAMETER.
INV=$(_g_inv cap https://h.example/p1 GET t https://h.example/p2 GET t \
  https://h.example/p3 GET t https://h.example/p4 GET t)
resp_endpoints_load "$INV" t '' 2
assert_eq 2 "$_RESP_N" 'the cap is honoured'
assert_eq 2 "$_RESP_TRUNCATED" 'and the two dropped candidates are counted, never silently absent'
# The SAME inventory, a DIFFERENT cap, is what pins that MAX_ENDPOINTS is read
# from the call rather than from a `: "${VAR:=N}"` global that only the FIRST
# caller in a process could ever set - the shape that would matter the moment
# headers.sh (cap 10) and markup.sh (cap 25) both run in one dast_run_phase
# loop, which they do on every real scan.
resp_endpoints_load "$INV" t '' 3
assert_eq 3 "$_RESP_N" \
  'a second call with a different MAX_ENDPOINTS gets its OWN cap - FAILS under a set-once default, which would still be pinned at 2 from the call above'

# A target mismatch drops a row; a row with no target at all is kept.
INV=$(_g_inv target https://h.example/mine GET t https://h.example/theirs GET other \
  https://h.example/notarget GET '')
resp_endpoints_load "$INV" t '' 10
_paths="${_RESP_PATH[*]}"
assert_contains "$_paths" /mine 'a row naming this target is kept'
assert_not_contains "$_paths" /theirs \
  "a row naming a DIFFERENT scope target is dropped - it belongs to that target's own cell"
assert_contains "$_paths" /notarget \
  'a row naming NO target at all is kept - an imported inventory may legitimately carry none, and http_request re-gates it regardless'

# An absent, empty or unreadable inventory is the NORMAL case, never an error,
# and the base-url alone is still a full answer.
resp_endpoints_load "$W/does-not-exist.json" t https://h.example/only 10
assert_eq 1 "$_RESP_N" 'no inventory: the base-url alone is candidate zero and the whole set'
: >"$W/empty.json"
resp_endpoints_load "$W/empty.json" t https://h.example/only 10
assert_eq 1 "$_RESP_N" 'an empty inventory file behaves identically to no inventory at all'
resp_endpoints_load '' t '' 10
assert_eq 0 "$_RESP_N" 'no inventory and no base-url: nothing to request, and no error either'

# ===========================================================================
printf '\n== dast-response-engine: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
