#!/usr/bin/env bash
# tests/suites/dast-crawl.sh - modules/dast/crawl.sh and crawl_engine.sh:
# crawling, parameter and specification discovery (docs/DESIGN.md §7.5;
# docs/STEP5-DAST-PLAN.md DAST-04).
#
# The decisions this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. AN OFF-TARGET LINK ON A CRAWLED PAGE PRODUCES NO REQUEST TO IT, and does
#      not abort the run either.  The wrong reading is "http_request gates
#      everything, so just hand it the link" - which is true about safety and
#      false about behaviour: http_request treats an out-of-scope URL as a
#      caller bug and exits 3, so a scanned site could stop its own scan by
#      linking to a search engine.  Proven against a REQUEST LOG, not against
#      a return value: the assertion is that the off-target host appears
#      nowhere in the list of things the transport was asked to fetch.
#   2. THE SPA / CLIENT-RENDERED GAP REALLY REACHES run.json AND report.md
#      when no specification is supplied.  The wrong reading is "the
#      limitation is documented in DESIGN.md §7.5, so it is stated" - which
#      docs/STEP5-DAST-PLAN.md explicitly rejects for this ticket.  Asserted
#      on the artifacts a consumer opens, and asserted ABSENT when a spec IS
#      supplied, so it cannot be satisfied by printing it unconditionally.
#   3. A SPECIFICATION'S OWN HOST IS NEVER SCANNED.  An OpenAPI `servers[].url`
#      , a Postman URL and a HAR entry all name a host, routinely a production
#      one.  The wrong reading is "the spec knows where the API is, use it" -
#      which turns a config file into a way past the scope gate.  Only the
#      PATH is taken; the host is always the operator's `--target`.
#   4. THE YAML FRONT-END REFUSES WHAT IT CANNOT REPRESENT.  The wrong reading
#      is "skip the lines you do not understand and parse the rest", which
#      yields a SHORT endpoint list indistinguishable from a complete one -
#      the overstated coverage docs/DESIGN.md §15 forbids.
#   5. AN INVENTORY ANOTHER MODULE WROTE IS MERGED, NOT OVERWRITTEN (tension
#      21).  The wrong reading is "the crawler is the producer, so it owns the
#      file" - which silently deletes every route SAST extracted.
#   6. A CREDENTIAL-NAMED PARAMETER'S OBSERVED VALUE NEVER REACHES DISK.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.  No case here needs a network or Docker: the
# transport and the resolver are stubbed through lib/http.sh's own
# SCOURSH_HTTP_TRANSPORT / SCOURSH_HTTP_RESOLVE hooks, which is the same
# idiom tests/suites/http.sh and tests/suites/paranoid.sh already use.  The
# real-target proof is tests/e2e/dast-crawl-target.sh, which is opt-in
# because it needs Docker.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes URL, flag and JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a fixture root cannot leak into the next
#   case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=modules/dast/crawl_engine.sh
source "$ROOT/modules/dast/crawl_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-crawl
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh strips $SCOURSH_INSTALL_ROOT as a
# literal prefix from each loaded rule file's realpath, so a fixture root reached
# through macOS's /var -> /private/var $TMPDIR symlink would make the strip fail
# and fire a spurious E081 (see tests/suites/scan.sh's ROOT_WITH_CHECKS).
W=$(cd -- "$W" && pwd -P)
FIXTURES=$ROOT/tests/fixtures/dast-crawl

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# ===========================================================================
printf -- '\n-- the JSON flattener (crawl_engine.sh §2) --\n'
# ===========================================================================
US=$(printf '\037')

t_case 'objects, arrays, and every scalar type flatten to one line per leaf'
FLAT=$(printf '%s' '{"a":1,"b":["x","y"],"c":{"d":"e","g":true},"h":null}' | crawl_json_flatten)
assert_contains "$FLAT" "a	n	1" 'a number leaf carries its type'
assert_contains "$FLAT" "b${US}0	s	x" 'an array element is indexed by position'
assert_contains "$FLAT" "b${US}1	s	y" 'and the second one too'
assert_contains "$FLAT" "c${US}d	s	e" 'a nested object key is joined with US, not with a character a URL can contain'
assert_contains "$FLAT" "c${US}g	b	true" 'a boolean is typed b'
assert_contains "$FLAT" "h	z	null" 'and null is typed z rather than becoming an empty string'

t_case 'a string containing a newline stays ONE line, because it stays escaped'
FLAT=$(printf '%s' '{"k":"one\ntwo\tthree"}' | crawl_json_flatten)
assert_eq 1 "$(printf '%s\n' "$FLAT" | LC_ALL=C wc -l | tr -d ' ')" \
  'one leaf is one output line - FAILS if the flattener unescapes before emitting, which turns a target-controlled value into two records and lets it forge a second endpoint'
assert_contains "$FLAT" 'one\ntwo\tthree' 'the value is emitted still escaped'

t_case 'a key carrying an ESCAPED path separator cannot forge a nested path'
# A US byte can only reach a JSON string as the six characters "backslash
# u001f" (RFC 8259 §7 forbids the raw byte), and the flattener emits keys and
# values STILL escaped, so it stays six characters and never becomes the
# separator.  BS holds one literal backslash so this file can spell a JSON
# escape without the shell - or anything that later edits this file -
# collapsing it first.
# SC1003: one literal backslash is exactly what this needs to hold.
# shellcheck disable=SC1003
BS=$(printf '\\')
FLAT=$(printf '%s' "{\"a${BS}u001fb\":\"v\"}" | crawl_json_flatten)
assert_contains "$FLAT" "a${BS}u001fb	s	v" \
  'the escaped US stays escaped, so the key is ONE path segment - FAILS if the flattener decodes \u escapes while building the path, which would let a crafted key impersonate a nested path and put a forged endpoint into the inventory'

t_case 'crawl_json_unescape decodes only what it promises'
assert_eq 'a
b/c' "$(crawl_json_unescape "a${BS}nb${BS}/c")" 'the standard two-character escapes decode'
assert_eq 'A' "$(crawl_json_unescape "${BS}u0041")" 'an ASCII \u escape decodes'
assert_eq "${BS}u00e9" "$(crawl_json_unescape "${BS}u00e9")" \
  'a non-ASCII \u escape is left as its literal escape text rather than composed - FAILS under "decode everything", which hand-builds UTF-8 for a value that is then compared against the scope allowlist as bytes'
assert_eq "a${BS}xb" "$(crawl_json_unescape "a${BS}${BS}xb")" \
  'a literal backslash from the input is never re-read as an escape - FAILS if the decoder runs printf %b over the finished string, which reinterprets target-controlled text as an escape sequence'

# ===========================================================================
printf -- '\n-- the YAML block-subset front-end (crawl_engine.sh §3) --\n'
# ===========================================================================

t_case 'the block subset flattens to the SAME stream shape as JSON'
FLAT=$(printf 'paths:\n  /users:\n    get:\n      parameters:\n        - name: page\n          in: query\n' | crawl_yaml_flatten)
assert_contains "$FLAT" "paths${US}/users${US}get${US}parameters${US}0${US}name	s	page" \
  'a nested sequence of mappings resolves to the same path a JSON document would produce - FAILS if the two front-ends disagree, which would need two copies of every extractor'
assert_contains "$FLAT" "paths${US}/users${US}get${US}parameters${US}0${US}in	s	query" 'both keys of the same sequence entry land under the same index'

t_case 'comments and quoted scalars are handled'
FLAT=$(printf '# leading comment\nkey: "a value" # trailing\nother: '"'"'q'"'"'\n' | crawl_yaml_flatten)
assert_contains "$FLAT" 'key	s	a value' 'a double-quoted scalar is unquoted and its trailing comment removed'
assert_contains "$FLAT" 'other	s	q' 'a single-quoted scalar too'

# Each of these FAILS under "skip the line you do not understand and keep
# going", which is the reading that produces a short endpoint list looking
# exactly like a complete one.
t_case 'an unsupported construct refuses the WHOLE document, loudly'
for spec in 'a: {b: 1}:flow-style' 'a: &anchor v:anchors' 'a: |
  block:block scalars' 'a: 1
---
b: 2:multi-document'; do
  want=${spec##*:}
  doc=${spec%:*}
  out=$(printf '%s\n' "$doc" | crawl_yaml_flatten 2>&1) && rc=0 || rc=$?
  assert_ne 0 "$rc" "a document using $want is refused with a non-zero status"
  assert_contains "$out" '__YAML_UNSUPPORTED__' "and says so on stdout rather than emitting a partial parse ($want)"
done

t_case 'the refusal reaches the operator as a named, fixable reason'
OUT=$(printf 'a: {b: 1}\n' | crawl_yaml_flatten 2>&1 || true)
assert_contains "$OUT" 'flow-style' \
  'the reason names the construct - FAILS under "unsupported YAML", which leaves an operator with a spec and no idea what to change'

# ===========================================================================
printf -- '\n-- HTML extraction and URL resolution (crawl_engine.sh §4, §5) --\n'
# ===========================================================================

t_case 'links, forms and their inputs are extracted in document order'
EX=$(crawl_html_extract <"$FIXTURES/pages/index.html")
assert_contains "$EX" 'link	/about.html' 'an absolute-path href'
assert_contains "$EX" 'link	deep1.html' 'a relative href'
assert_contains "$EX" 'form	POST	/login' 'a form with its method uppercased and its action'
assert_contains "$EX" 'input	username' 'a named input inside that form'
assert_contains "$EX" 'input	remember' 'and a named button, which is submitted like any other control'
assert_contains "$EX" 'form	GET	/find' 'a second form'

t_case 'a commented-out link and a URL inside <script> are NOT links'
assert_not_contains "$EX" 'commented-out' \
  'markup inside an HTML comment is skipped - FAILS under a regex that scans for href= anywhere, which would request a path the page deliberately disabled'
assert_not_contains "$EX" 'only-in-javascript' \
  'a URL-shaped string in a script body is not mined - FAILS under "mine the bundles too", which guesses routes and requests paths the application may never have had'

t_case 'an unnamed control contributes no parameter'
assert_not_contains "$EX" 'input	submit' 'an input with no name attribute is not a parameter'

t_case 'URL resolution follows RFC 3986, including the dot segments'
B=https://h.example/dir/page.html
assert_eq 'https://h.example/abs?q=1' "$(crawl_url_resolve "$B" '/abs?q=1')" 'a rooted reference keeps its query'
assert_eq 'https://h.example/dir/rel.html' "$(crawl_url_resolve "$B" 'rel.html')" 'a relative reference resolves against the base directory'
assert_eq 'https://h.example/up' "$(crawl_url_resolve "$B" '../up')" 'a parent reference climbs one level'
assert_eq 'https://other.example/x' "$(crawl_url_resolve "$B" '//other.example/x')" 'a protocol-relative reference inherits the scheme'
assert_eq 'https://h.example/etc' "$(crawl_url_resolve "$B" '/a/../../etc')" \
  'dot segments collapse past the root - FAILS if remove_dot_segments is skipped, which leaves a path a path-scoped scope target compares differently from what is actually requested'
assert_eq 'https://h.example/dir/page.html' "$(crawl_url_resolve "$B" 'page.html#section')" \
  'a fragment is always dropped - FAILS if it is kept, which makes one endpoint look like many and costs a real request each'

t_case 'a reference that is not a fetchable http(s) URL is REJECTED, not coerced'
for ref in '#top' 'javascript:alert(1)' 'mailto:a@b.example' 'data:text/html,x' 'tel:+100' 'ws://h.example/s'; do
  crawl_url_resolve "$B" "$ref" >/dev/null 2>&1 && rc=0 || rc=$?
  assert_ne 0 "$rc" "'$ref' is rejected - FAILS under \"resolve it and let the gate sort it out\", which turns a non-link into a request"
done

# ===========================================================================
printf -- '\n-- specification ingestion (crawl_engine.sh §8) --\n'
# ===========================================================================
TGT=https://crawl.fixture.invalid

_ep_lines() {
  local r
  for r in "${_CRAWL_EP[@]+"${_CRAWL_EP[@]}"}"; do printf '%s|%s|%s\n' "$(printf '%s' "$r" | cut -f3)" "$(printf '%s' "$r" | cut -f4)" "$(printf '%s' "$r" | cut -f7)"; done
}
_param_lines() {
  local r
  for r in "${_CRAWL_PARAM[@]+"${_CRAWL_PARAM[@]}"}"; do printf '%s|%s|%s|%s\n' "$(printf '%s' "$r" | cut -f6)" "$(printf '%s' "$r" | cut -f7)" "$(printf '%s' "$r" | cut -f8)" "$(printf '%s' "$r" | cut -f9)"; done
}

t_case 'an OpenAPI 3 document yields every operation, including one nothing links to'
crawl_inv_reset
crawl_spec_openapi "$FIXTURES/specs/openapi.json" crawl-fixture "$TGT" || _t_no 'openapi parsed' "$_CRAWL_SPEC_ERROR"
EPS=$(_ep_lines)
assert_contains "$EPS" "GET|$TGT/api/v2/pets|openapi" 'GET /pets, under the servers[] path prefix'
assert_contains "$EPS" "POST|$TGT/api/v2/pets|openapi" 'POST on the same path is a separate endpoint'
assert_contains "$EPS" "DELETE|$TGT/api/v2/pets/{petId}|openapi" 'a templated path keeps its template segment'
assert_contains "$EPS" "GET|$TGT/api/v2/never-linked-from-anywhere|openapi" \
  'an endpoint no page links to is discovered - FAILS under "the crawl is the inventory", which is the whole reason §7.5 calls a spec the preferred input'

t_case 'a spec-declared host is NEVER scanned; only its path prefix is taken'
assert_not_contains "$EPS" 'spec-declared-host' \
  'the servers[].url host does not appear in any endpoint - FAILS under "the spec knows where the API lives", which makes config/discovery.conf a way past the scope gate that docs/DESIGN.md §7 says must not be bypassable'
assert_contains "$EPS" "$TGT/api/v2/" 'but its PATH prefix is honoured, because that is a fact about the API and not about who to talk to'

t_case 'operation-level and path-level parameters both land, at their stated location'
PARAMS=$(_param_lines)
assert_contains "$PARAMS" 'limit|query|openapi' 'an operation-level query parameter'
assert_contains "$PARAMS" 'X-Trace-Id|header|openapi' 'a header parameter keeps location=header, which §7.3 iterates separately'
assert_contains "$PARAMS" 'petId|path|openapi' \
  'a PATH-level parameter array applies to the operations under it - FAILS if only operation-level arrays are read, which drops the {id} parameter an IDOR check needs most'

t_case 'a Swagger 2.0 document in block YAML parses through the same extractor'
crawl_inv_reset
crawl_spec_openapi "$FIXTURES/specs/openapi.yaml" crawl-fixture "$TGT" || _t_no 'yaml openapi parsed' "$_CRAWL_SPEC_ERROR"
EPS=$(_ep_lines)
assert_contains "$EPS" "GET|$TGT/v1/users|openapi" 'basePath is the Swagger 2 spelling of the same prefix'
assert_contains "$EPS" "POST|$TGT/v1/users|openapi" 'and a second method on it'
assert_contains "$EPS" "GET|$TGT/v1/users/{userId}|openapi" 'and a templated path'
assert_contains "$(_param_lines)" 'page|query|openapi' 'its parameters land too'

t_case 'a YAML spec using an unsupported construct fails LOUDLY, with a reason'
crawl_inv_reset
crawl_spec_openapi "$FIXTURES/specs/openapi-flow.yaml" crawl-fixture "$TGT" && rc=0 || rc=$?
assert_ne 0 "$rc" 'the ingest reports failure - FAILS under "parse what you can", which reports partial coverage as complete'
assert_contains "$_CRAWL_SPEC_ERROR" 'flow-style' 'and the reason is the operator-actionable one, not "no paths found"'

t_case 'a Postman collection yields nested items and its query parameters'
crawl_inv_reset
crawl_spec_postman "$FIXTURES/specs/postman.json" crawl-fixture "$TGT" || _t_no 'postman parsed' "$_CRAWL_SPEC_ERROR"
EPS=$(_ep_lines)
assert_contains "$EPS" "GET|$TGT/find|postman" 'a top-level item'
assert_contains "$EPS" "POST|$TGT/items|postman" 'an item nested in a folder, in the short url form'
assert_not_contains "$EPS" 'collection-declared-host' 'and the collection'"'"'s own host is not scanned'
PARAMS=$(_param_lines)
assert_contains "$PARAMS" 'term|query|postman' \
  'the query parameters of a collection URL are recorded - FAILS if the accumulator'"'"'s own url split is read back after crawl_add_endpoint has overwritten it, which drops every one of them silently'
assert_contains "$PARAMS" 'sort|query|postman' 'both of them'

t_case 'an unresolved {{variable}} is dropped rather than requested literally'
assert_not_contains "$EPS" 'unresolved' \
  'a templated Postman URL contributes no endpoint - FAILS under "send it and see", which requests a literal path containing braces'
assert_eq 1 "${_CRAWL_SPEC_DROPPED:-0}" 'and the drop is counted rather than silent'

t_case 'a HAR capture yields the XHR endpoints a static crawl cannot see'
crawl_inv_reset
crawl_spec_har "$FIXTURES/specs/capture.har" crawl-fixture "$TGT" || _t_no 'har parsed' "$_CRAWL_SPEC_ERROR"
EPS=$(_ep_lines)
assert_contains "$EPS" "GET|$TGT/xhr/profile|har" 'a recorded XHR GET'
assert_contains "$EPS" "POST|$TGT/xhr/login|har" 'and a recorded POST'
assert_not_contains "$EPS" 'har-declared-host' 'against this run'"'"'s target, never the host the capture happened to name'
PARAMS=$(_param_lines)
assert_contains "$PARAMS" 'fields|query|har|all' 'a query parameter keeps its observed value'
assert_contains "$PARAMS" 'email|body|har|someone@example.invalid' 'a posted form field is location=body'

t_case 'a credential-named parameter keeps its NAME and loses its VALUE'
assert_contains "$PARAMS" 'password|body|har|' \
  'the password parameter is still inventoried, with an EMPTY example - FAILS under "redact() covers it", which it provably cannot: no redaction rule can classify an arbitrary human-chosen password by shape, so a real captured password would land on disk'
assert_not_contains "$PARAMS" 'correct-horse-battery' 'the captured value appears nowhere'

t_case 'a GraphQL SDL schema yields one endpoint and one parameter per root field'
crawl_inv_reset
crawl_spec_graphql "$FIXTURES/specs/schema.graphql" crawl-fixture "$TGT/graphql" || _t_no 'sdl parsed' "$_CRAWL_SPEC_ERROR"
assert_eq 1 "${#_CRAWL_EP[@]}" 'GraphQL has ONE endpoint, whatever the schema declares'
PARAMS=$(_param_lines)
assert_contains "$PARAMS" 'users|graphql|graphql' 'a Query root field'
assert_contains "$PARAMS" 'currentUser|graphql|graphql' 'and another'
assert_contains "$PARAMS" 'login|graphql|graphql' 'a Mutation root field too'
assert_not_contains "$PARAMS" 'email|graphql' \
  'but not a field of a non-root type - FAILS under "enumerate every field in the schema", which fills the inventory with names no request can carry'

t_case 'an introspection RESULT parses through the JSON front-end, honouring renamed roots'
crawl_inv_reset
crawl_spec_graphql "$FIXTURES/specs/introspection.json" crawl-fixture "$TGT/graphql" || _t_no 'introspection parsed' "$_CRAWL_SPEC_ERROR"
PARAMS=$(_param_lines)
assert_contains "$PARAMS" 'nodes|graphql|graphql' 'a field of the type named by queryType'
assert_contains "$PARAMS" 'signIn|graphql|graphql' 'and of the one named by mutationType'
assert_not_contains "$PARAMS" 'viewer|graphql|graphql|x' 'no stray field shape'
assert_not_contains "$PARAMS" 'email|graphql' \
  'a field of an ordinary type is not an operation - FAILS under "match the literal type name Query", which misses a schema whose root is called RootQuery and is wrong for one that has a non-root type called Query'

# ===========================================================================
printf -- '\n-- IMPORT-05: import-time hardening of untrusted param name + location (crawl_engine.sh §6) --\n'
# ===========================================================================
# Two pre-existing defects a hostile spec/HAR/hand-written inventory can trip
# (the api-surface-import scout report §7), fixed at the one place every
# producer already funnels through: crawl_add_param.
#
#   (a) A header-location name that is not an RFC 7230 token reaches
#       http_request_header, which `die`s the WHOLE PROCESS (exit 5,
#       lib/http.sh:625-630) - reproduced end to end, in an isolated
#       subprocess, in tests/suites/dast-inject-engine.sh, since that is
#       where the crash actually happens. Proven HERE: crawl_add_param never
#       admits the name in the first place.
#   (b) A `location` outside docs/INVENTORY-FORMAT.md §3's seven-value
#       vocabulary was stored as-is (only non-empty name + dedup were
#       checked), and inject_send had no arm for it - "tested clean" for a
#       parameter nothing was ever sent for (also reproduced in
#       tests/suites/dast-inject-engine.sh, against a byte copy of the
#       pre-fix file).

t_case 'a header-location parameter whose name is not an RFC 7230 token is never admitted'
crawl_inv_reset
crawl_add_param ep1 crawl-fixture GET "$TGT/x" 'X Bad Name' header openapi ''
assert_eq 0 "${#_CRAWL_PARAM[@]}" \
  'the row is not stored - FAILS if crawl_add_param validates only non-empty name (its pre-IMPORT-05 shape), which is exactly what let this name become a header inventory row'
assert_eq 1 "${_CRAWL_PARAM_INVALID_HEADER_NAME:-0}" \
  'and the refusal is counted, so it can reach run.json as a coverage_reduction rather than vanishing silently'

t_case 'a VALID header-location name is unaffected - this is a token check, not a header ban'
crawl_inv_reset
crawl_add_param ep1 crawl-fixture GET "$TGT/x" 'X-Trace-Id' header openapi ''
assert_eq 1 "${#_CRAWL_PARAM[@]}" 'the row IS stored'
assert_eq 0 "${_CRAWL_PARAM_INVALID_HEADER_NAME:-0}" 'and nothing was counted as invalid'

t_case 'a non-header location is never held to the header token rule'
crawl_inv_reset
crawl_add_param ep1 crawl-fixture GET "$TGT/x" 'not a token either' query openapi ''
assert_eq 1 "${#_CRAWL_PARAM[@]}" \
  'a query parameter with the identical unfriendly name is stored anyway - FAILS if the token check applied regardless of location, which would reject query parameter names no rule requires to be tokens at all'

t_case 'a location outside the frozen seven-value vocabulary is never stored'
crawl_inv_reset
crawl_add_param ep1 crawl-fixture GET "$TGT/x" name json openapi ''
assert_eq 0 "${#_CRAWL_PARAM[@]}" \
  'the row is not stored - FAILS if crawl_add_param stores whatever location string it is handed, which inject_send then has no arm for and silently drops while still reporting the send as clean'
assert_eq 1 "${_CRAWL_PARAM_INVALID_LOCATION:-0}" 'and the refusal is counted'

t_case 'every value in the frozen vocabulary is still accepted'
crawl_inv_reset
for loc in query body path header cookie formData graphql; do
  name=n_$loc
  [[ $loc == header ]] && name=X-Ok
  crawl_add_param ep1 crawl-fixture GET "$TGT/x" "$name" "$loc" openapi ''
done
assert_eq 7 "${#_CRAWL_PARAM[@]}" \
  'all seven land - FAILS if the vocabulary check is stricter than docs/INVENTORY-FORMAT.md §3 actually declares'
assert_eq 0 "${_CRAWL_PARAM_INVALID_LOCATION:-0}" 'none of them were counted as invalid'

# The end-to-end proof (a hostile spec, through a real scan.sh dast crawl
# phase) needs $FIX and _crawl_scan, which the stubbed-transport section below
# defines - see 'a hostile OpenAPI header-parameter name is dropped end to
# end' further down, right after the crawl-depth case.

# ===========================================================================
printf -- '\n-- the tension-21 inventory merge (crawl_engine.sh §7) --\n'
# ===========================================================================

t_case 'an inventory another module wrote is READ, with its provenance intact'
crawl_inv_reset
crawl_inv_merge_endpoints "$FIXTURES/inventory/endpoints.json" crawl-fixture
assert_eq 2 "$_CRAWL_MERGED_COUNT" 'both routes are imported'
EPS=$(_ep_lines)
assert_contains "$EPS" 'GET|https://crawl.fixture.invalid/internal/health|sast-routes' \
  'and each keeps the source the producer declared - FAILS if the merger stamps its own source, which erases the audit trail tension 21 requires of imported inventory'
assert_contains "$EPS" 'POST|https://crawl.fixture.invalid/internal/admin/reset|sast-routes' 'the second one too'

t_case 'a merged endpoint the crawler also reaches is ONE endpoint, keeping the import provenance'
crawl_add_endpoint crawl-fixture GET https://crawl.fixture.invalid/internal/health crawl 1 200 text/html
assert_eq 2 "${#_CRAWL_EP[@]}" 'no duplicate is created'
assert_contains "$(_ep_lines)" 'sast-routes' \
  'and the earlier provenance survives - FAILS under "last writer wins", which reports a route SAST asserted as one a crawl confirmed'

t_case 'an unreadable or empty inventory is not an error'
: >"$W/empty.json"
crawl_inv_merge_endpoints "$W/empty.json" crawl-fixture && rc=0 || rc=$?
assert_ne 0 "$rc" 'an empty file reports "nothing read"'
crawl_inv_merge_endpoints "$W/does-not-exist.json" crawl-fixture && rc=0 || rc=$?
assert_ne 0 "$rc" 'and so does an absent one, without dying'

t_case 'the writer and the reader agree, whatever the layout'
crawl_inv_reset
crawl_add_endpoint crawl-fixture GET https://crawl.fixture.invalid/a crawl 0 200 text/html
crawl_add_endpoint crawl-fixture POST https://crawl.fixture.invalid/b crawl 0 '' ''
crawl_inv_write_endpoints "$W/roundtrip.json"
crawl_inv_reset
crawl_inv_merge_endpoints "$W/roundtrip.json" crawl-fixture
assert_eq 2 "$_CRAWL_MERGED_COUNT" \
  'this module can read back what it wrote - FAILS if the reader matches literal bytes rather than parsing, which is what makes a "frozen schema" unusable by three different producers'
assert_contains "$(_ep_lines)" 'GET|https://crawl.fixture.invalid/a|crawl' 'with fields intact'

t_case 'every value in the written JSON goes through the single string writer'
crawl_inv_reset
crawl_add_endpoint crawl-fixture GET 'https://crawl.fixture.invalid/x?"><script>alert(1)</script>' crawl 0 200 text/html
crawl_inv_write_endpoints "$W/hostile.json"
HOSTILE=$(_slurp "$W/hostile.json")
assert_not_contains "$HOSTILE" '"url": "https://crawl.fixture.invalid/x?"><script>' \
  'a quote in a target-derived URL cannot break out of its JSON string - FAILS if any field is interpolated at the call site instead of through json_string (docs/FOUNDATION.md tension 10)'
crawl_inv_reset
crawl_inv_merge_endpoints "$W/hostile.json" crawl-fixture
assert_eq 1 "$_CRAWL_MERGED_COUNT" 'and the escaped document still parses'

t_case 'crawl_safe_text strips what would forge a second run record'
OUT=$(crawl_safe_text "$(printf 'a\nb\tc')")
assert_eq 'a b c' "$OUT" \
  'a newline in a target-derived name becomes a space - FAILS if it is passed through, which makes one crafted form name into two coverage_gap lines in the report'
OUT=$(crawl_safe_text "$(printf 'x\033[31mred')")
assert_not_contains "$OUT" "$(printf '\033')" 'and an ANSI escape cannot reach the terminal of whoever reads the report'

# ===========================================================================
printf -- '\n-- the crawl itself, against a stubbed transport --\n'
# ===========================================================================
# The stub is an EXECUTABLE, not a shell function, so the very same one binds
# an in-process call and a real `scan.sh dast` subprocess: lib/http.sh invokes
# `"${SCOURSH_HTTP_TRANSPORT:-...}"` as a command, which resolves a function
# when there is one and a program on PATH otherwise.  Nothing here touches a
# network - that is the point of exercising the crawl this way rather than
# against a live server, which tests/e2e/dast-crawl-target.sh does separately.
STUB_DIR=$W/stub
mkdir -p "$STUB_DIR"
REQLOG=$W/requests.log
: >"$REQLOG"

cat >"$STUB_DIR/transport" <<'STUBEOF'
#!/usr/bin/env bash
# METHOD SCHEME HOST PORT PATH ADDR [BODY_OUT] [HEADERS_OUT] - lib/http.sh's transport
# contract.  Serves tests/fixtures/dast-crawl/pages/ and logs every request it
# is ASKED to make, which is the evidence the scope-gate cases assert on.
set -Eeuo pipefail
# The body sink arrives as argument 7.  A global would NOT reach this stub: it
# is a separate executable, so nothing but argv and the environment crosses the
# fork - which is the whole reason http_request appends it.
method=$1; host=$3; path=$5; bodyout=${7:-}
printf '%s %s %s\n' "$method" "$host" "$path" >>"$CRAWL_STUB_LOG"
p=${path%%\?*}
case $p in
  /) f=index.html ;;
  /spa) f=spa.html ;;
  *) f=${p#/} ;;
esac
src=$CRAWL_STUB_PAGES/$f
if [[ -f $src ]]; then
  [[ -n $bodyout ]] && cat -- "$src" >"$bodyout"
  printf '200\n\ntext/html; charset=utf-8\n'
else
  [[ -n $bodyout ]] && printf 'not found\n' >"$bodyout"
  printf '404\n\ntext/html\n'
fi
STUBEOF
chmod 0755 "$STUB_DIR/transport"

cat >"$STUB_DIR/resolve" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  crawl.fixture.invalid) printf '93.184.216.34' ;;
  off-target.example.invalid) printf '93.184.216.35' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$STUB_DIR/resolve"

# A fixture install root: a real COPY of the tree's code, its own config/.
# A copy, not a symlink: lib/records.sh resolves each loaded rule file through
# realpath, which would follow a symlinked `modules/` back to the real repo -
# outside $SCOURSH_INSTALL_ROOT - and fire a spurious E081 on
# modules/dast/active/checks.rules, aborting the run.  `cp -RL` keeps each file's
# realpath inside the canonical root ($W is canonical, see above).
FIX=$W/root
mkdir -p "$FIX/config"
for e in lib modules rules data tools VERSION scan.sh; do
  [[ -e $ROOT/$e ]] && cp -RL "$ROOT/$e" "$FIX/$e"
done
cat >"$FIX/config/scope.conf" <<'EOF'
id: crawl-fixture
base-url: https://crawl.fixture.invalid/
allow-subdomains: false
notes: Fixture scope target for tests/suites/dast-crawl.sh. The transport is
  stubbed, so nothing is ever sent to it; the point of the entry is that the
  gate has exactly one authorised host to compare a crawled link against.
EOF

# `_crawl_scan RUNDIR [ARGS...]` - one real `scan.sh dast` subprocess, the way
# an operator hits it, with the stubs bound.  Sets _RC and _LOG.
_crawl_scan() {
  local rundir=$1
  shift
  _LOG=$rundir.log
  _RC=0
  : >"$REQLOG"
  SCOURSH_INSTALL_ROOT=$FIX \
    SCOURSH_HTTP_TRANSPORT=$STUB_DIR/transport \
    SCOURSH_HTTP_RESOLVE=$STUB_DIR/resolve \
    CRAWL_STUB_LOG=$REQLOG \
    CRAWL_STUB_PAGES=$FIXTURES/pages \
    bash "$ROOT/scan.sh" dast --target crawl-fixture --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

t_case 'a real scan.sh dast run crawls, and exits 0'
_crawl_scan "$W/run-basic"
assert_eq 0 "$_RC" 'the run is clean'
assert_file_exists "$W/run-basic/inventory/endpoints.json" 'endpoints.json was written'
assert_file_exists "$W/run-basic/inventory/parameters.json" 'parameters.json was written'
EPJSON=$(_slurp "$W/run-basic/inventory/endpoints.json")
PARJSON=$(_slurp "$W/run-basic/inventory/parameters.json")
assert_contains "$EPJSON" '"url": "https://crawl.fixture.invalid/"' 'the root is an endpoint'
assert_contains "$EPJSON" '"url": "https://crawl.fixture.invalid/about.html"' 'a followed link is an endpoint'
assert_contains "$EPJSON" '"url": "https://crawl.fixture.invalid/search"' \
  'a link carrying a query is ONE endpoint with the query removed - FAILS if the query is part of the endpoint, which turns a paginated listing into fifty endpoints and re-tests one handler fifty times'
assert_contains "$PARJSON" '"name": "q"' 'and its query parameter is in parameters.json instead'
assert_contains "$PARJSON" '"name": "page"' 'both of them'

t_case 'a form is an endpoint and its inputs are parameters, with nothing submitted'
assert_contains "$EPJSON" '"url": "https://crawl.fixture.invalid/login"' 'the form action is an endpoint'
assert_contains "$EPJSON" '"method": "POST"' 'recorded at the form'"'"'s own method'
assert_contains "$PARJSON" '"name": "username"' 'its inputs are parameters'
assert_contains "$PARJSON" '"location": "body"' 'at location=body for a POST form'
assert_not_contains "$(_slurp "$REQLOG")" 'POST' \
  'and NO POST was ever sent - FAILS under "submit the form to see what happens", which is a state change and is forbidden at the passive tier docs/DESIGN.md §7.1 defines'

t_case 'THE SCOPE GATE HOLDS DURING A CRAWL: an off-target link produces no request'
LOG=$(_slurp "$REQLOG")
assert_contains "$LOG" 'crawl.fixture.invalid' 'the authorised host was requested'
assert_not_contains "$LOG" 'off-target.example.invalid' \
  'the off-target host in the root page was never requested - FAILS if a discovered link is handed to http_request without a pre-check, and this is asserted on the transport'"'"'s own request log rather than on a return value'
assert_eq 0 "$_RC" \
  'and the run still completed cleanly - FAILS under "let http_request die 3 on it", which lets any scanned site abort its own scan by linking to a search engine'
assert_not_contains "$EPJSON" 'off-target' 'nor did it reach the inventory'
NOTES=$(_slurp "$W/run-basic/meta/notes")
assert_contains "$NOTES" 'scope_refused_links=1' \
  'the drop is declared (module=dast/engine.sh section 3b'"'"'s dast_endpoint_keep, converged onto here) as a `notes` record, not a coverage_reduction: this is a crawled LINK, not an inventory row, and refusing one is the tool working rather than a hole in what it examined'
assert_contains "$NOTES" 'off-target.example.invalid' 'and it carries the gate own reason, naming the host'

# ---------------------------------------------------------------------------
# WITHOUT the shared pre-check, the same off-target link kills the whole run.
# ---------------------------------------------------------------------------
MUT=$W/mutation.sh
cat >"$MUT" <<'EOM'
set -Eeuo pipefail
ROOT=$1 FIX=$2 PAGES=$3 LOG=$4
source "$ROOT/modules/dast/engine.sh"
source "$ROOT/lib/http.sh"
source "$ROOT/modules/dast/crawl_engine.sh"
http_scope_load "$FIX/config/scope.conf"
config_scope_load "$FIX/config/scope.conf"
cat >"$FIX/config/scanner.conf" <<'EOS'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOS
config_scanner_load "$FIX/config/scanner.conf"
_m_resolve() {
  case $1 in
    crawl.fixture.invalid) printf '93.184.216.34' ;;
    off-target.example.invalid) printf '93.184.216.35' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_m_resolve
_m_transport() {
  local method=$1 host=$3 path=$5 bodyout=${7:-}
  printf '%s %s %s\n' "$method" "$host" "$path" >>"$LOG"
  case $path in
    /) [[ -n $bodyout ]] && cat -- "$PAGES/index.html" >"$bodyout"; printf '200\n\ntext/html\n' ;;
    *) printf '404\n\ntext/html\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_m_transport
# THE MUTATION ITSELF: the pre-check keeps every row, byte-for-byte the
# behaviour before modules/dast/engine.sh section 3b existed.
dast_endpoint_keep() { return 0; }
dast_endpoint_in_scope() { return 0; }
run_init "$FIX/run.mutation"
run_record authorization_affirmed true
run_record authorization_target crawl-fixture
SCOURSH_DAST_TARGET=crawl-fixture
export SCOURSH_DAST_TARGET
source "$ROOT/modules/dast/crawl.sh"
EOM
MUT_LOG=$W/mutation-requests.log
: >"$MUT_LOG"
MUT_RC=0
bash "$MUT" "$ROOT" "$FIX" "$FIXTURES/pages" "$MUT_LOG" >"$W/mutation.out" 2>&1 || MUT_RC=$?

t_case 'WITHOUT the pre-check the same off-target link kills the whole run'
assert_eq 3 "$MUT_RC" \
  'the mutated phase exits SCOURSH_EXIT_SCOPE (3) - this is the defect the shared pre-check exists to remove, reproduced rather than described. If this case ever reports 0, the pre-check has stopped being load-bearing and the section above is passing for some other reason.'
assert_not_contains "$(cat "$MUT_LOG")" 'off-target' \
  'and it never even reached the unauthorised host - the gate inside http_request refuses BEFORE the transport'

t_case 'a page-relative link resolves against the page, not against the root'
assert_contains "$LOG" 'GET crawl.fixture.invalid /deep1.html' \
  'deep1.html was requested at the path it resolves to'

t_case 'crawl-depth bounds the walk, and the bound is recorded rather than silent'
mkdir -p "$FIX/config"
cat >"$FIX/config/discovery.conf" <<'EOF'
id: crawl-fixture
crawl-depth: 1
EOF
_crawl_scan "$W/run-depth1"
assert_eq 0 "$_RC" 'a depth-bounded run is clean'
LOG=$(_slurp "$REQLOG")
assert_contains "$LOG" '/deep1.html' 'depth 1 is fetched'
assert_not_contains "$LOG" '/deep2.html' \
  'depth 2 is NOT - FAILS if crawl-depth is read but never compared, which is a bound that exists only in the config file'
RUNJSON=$(_slurp "$W/run-depth1/run.json")
assert_contains "$RUNJSON" 'reason=crawl_depth_reached' \
  'and the links it cost are recorded - FAILS under "the operator set the depth, so they know", which is indistinguishable in the report from a site that really had no more pages'
rm -f "$FIX/config/discovery.conf"

t_case 'IMPORT-05: a hostile OpenAPI header-parameter name is dropped end to end, and the scan degrades rather than dies'
cat >"$FIX/config/discovery.conf" <<EOF
id: crawl-fixture
openapi-path: $FIXTURES/specs/openapi-hostile-params.json
EOF
_crawl_scan "$W/run-hostile-header"
assert_eq 0 "$_RC" \
  'the run completes cleanly - FAILS under the pre-IMPORT-05 reading, in which this exact parameter reaches inject_send on a later active run and dies exit 5 (reproduced in tests/suites/dast-inject-engine.sh)'
PARJSON=$(_slurp "$W/run-hostile-header/inventory/parameters.json")
assert_not_contains "$PARJSON" 'X Bad Name' 'the malformed name never reaches the inventory at all'
assert_contains "$PARJSON" 'X-Good-Name' 'but its well-formed sibling on the same operation still does'
RUNJSON=$(_slurp "$W/run-hostile-header/run.json")
assert_contains "$RUNJSON" 'reason=param_invalid_header_name' 'and the drop is a counted coverage_reduction, not a silent one'
rm -f "$FIX/config/discovery.conf"

# ===========================================================================
printf -- '\n-- the SPA gap actually reaches run.json and the report (constraint 2) --\n'
# ===========================================================================

t_case 'with no specification supplied, the gap is in run.json AND in report.md'
_crawl_scan "$W/run-nospec"
RUNJSON=$(_slurp "$W/run-nospec/run.json")
REPORTMD=$(_slurp "$W/run-nospec/report.md")
REPORTHTML=$(_slurp "$W/run-nospec/report.html")
assert_contains "$RUNJSON" 'no OpenAPI, GraphQL schema, Postman collection or HAR capture was supplied' \
  'run.json carries the SPA gap - FAILS under "docs/DESIGN.md §7.5 states the limitation", which docs/STEP5-DAST-PLAN.md explicitly rejects as sufficient for this ticket'
assert_contains "$RUNJSON" 'reason=no_specification_supplied' 'with a machine-readable reason beside the sentence'
assert_contains "$REPORTMD" 'Limitations and coverage' 'report.md has the section'
assert_contains "$REPORTMD" 'client-rendered application' \
  'and states the limitation where a human reads it - FAILS under "run.json is the audit surface", which leaves the report reader believing the endpoint list is the application'
assert_contains "$REPORTHTML" 'client-rendered' 'report.html states it too'
assert_not_contains "$REPORTHTML" '<script' \
  'and the HTML report still contains no script tag at all, with target-derived text in it (docs/FOUNDATION.md tension 10)'

t_case 'the gap names the mitigations, so it is actionable rather than an apology'
assert_contains "$RUNJSON" 'config/discovery.conf' 'it names where to supply a spec'
assert_contains "$RUNJSON" 'tension 21' 'and the SAST-route mitigation for the server-side half'

t_case 'WITH a specification supplied, the SPA gap is ABSENT'
cat >"$FIX/config/discovery.conf" <<EOF
id: crawl-fixture
openapi-path: $FIXTURES/specs/openapi.json
EOF
_crawl_scan "$W/run-spec"
assert_eq 0 "$_RC" 'a run with a spec is clean'
RUNJSON=$(_slurp "$W/run-spec/run.json")
assert_not_contains "$RUNJSON" 'reason=no_specification_supplied' \
  'the gap is not recorded when a spec closed it - FAILS if the gap is printed unconditionally, in which case asserting its presence above proves nothing at all'
EPJSON=$(_slurp "$W/run-spec/inventory/endpoints.json")
assert_contains "$EPJSON" '"source": "openapi"' 'the spec endpoints are in the inventory'
assert_contains "$EPJSON" '"source": "crawl"' 'alongside the crawled ones, in one merged file'
assert_contains "$EPJSON" 'never-linked-from-anywhere' 'including the one no page links to'

t_case 'a supplied specification that does not parse is its own, louder gap'
cat >"$FIX/config/discovery.conf" <<EOF
id: crawl-fixture
openapi-path: $FIXTURES/specs/openapi-flow.yaml
EOF
_crawl_scan "$W/run-badspec"
assert_eq 0 "$_RC" 'an unusable spec does not fail the run'
RUNJSON=$(_slurp "$W/run-badspec/run.json")
assert_contains "$RUNJSON" 'reason=specification_unusable' \
  'it is recorded as unusable - FAILS under "no endpoints from it, so treat it as absent", which leaves an operator believing the gap they closed is closed'
assert_contains "$RUNJSON" 'contributed NOTHING' 'in a sentence a human reads'
assert_contains "$RUNJSON" 'flow-style' 'naming the construct to fix'
rm -f "$FIX/config/discovery.conf"

t_case 'an inventory another module wrote survives the crawl that runs after it'
mkdir -p "$W/run-merge/inventory"
cp "$FIXTURES/inventory/endpoints.json" "$W/run-merge/inventory/endpoints.json"
_crawl_scan "$W/run-merge"
assert_eq 0 "$_RC" 'a run with a pre-existing inventory is clean'
EPJSON=$(_slurp "$W/run-merge/inventory/endpoints.json")
assert_contains "$EPJSON" '/internal/admin/reset' \
  'the imported route is still there after the crawler wrote the file - FAILS under "the crawler is the producer, so it owns the file", which silently deletes every route SAST extracted'
assert_contains "$EPJSON" '"source": "sast-routes"' 'with its provenance'
assert_contains "$EPJSON" '"source": "crawl"' 'and the crawl'"'"'s own endpoints merged in'
RUNJSON=$(_slurp "$W/run-merge/run.json")
assert_contains "$RUNJSON" 'inventory_merged=2' 'and the merge is recorded with a count'

t_case 'an --authed run with no session says the crawl was unauthenticated'
_crawl_scan "$W/run-authed" --authed
assert_eq 0 "$_RC" 'the run is clean'
RUNJSON=$(_slurp "$W/run-authed/run.json")
assert_contains "$RUNJSON" 'reason=authenticated_crawl_unavailable' \
  'the gap is recorded - FAILS under "--authed is a flag auth.sh reads", which leaves a crawl that reached only the public surface indistinguishable from one that logged in'
assert_contains "$RUNJSON" 'UNAUTHENTICATED' 'in a sentence a human reads'

t_case 'a run WITHOUT --authed does not claim an authentication gap'
RUNJSON=$(_slurp "$W/run-basic/run.json")
assert_not_contains "$RUNJSON" 'reason=authenticated_crawl_unavailable' \
  'FAILS if the gap is unconditional, which would put a warning about a login nobody asked for into every anonymous scan'

t_summary dast-crawl
