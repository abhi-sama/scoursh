#!/usr/bin/env bash
# tests/suites/dast-graphql.sh - modules/dast/graphql.sh and its engine
# modules/dast/graphql_engine.sh: GraphQL/AppSync introspection exposure and the
# correlation input §7.4's second sentence asks for
# (docs/DESIGN.md §7.4, §8.5; docs/STEP5-DAST-PLAN.md DAST-27, tier 5).
#
# NOTHING HERE TOUCHES THE NETWORK. Every response is RECORDED: the whole suite
# runs against a stubbed SCOURSH_HTTP_TRANSPORT that writes canned JSON into the
# capture file lib/http.sh hands it, with SCOURSH_HTTP_RESOLVE stubbed too
# (docs/DESIGN.md §12: "DAST logic is testable with no live target"). It runs on
# a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing, and review round 5 found four rounds of tests
# that had certified their own author's reading green. The three hazards this
# check exists to get right each have a case whose rejected reading is the
# obvious shell implementation:
#
#   1. `case $body in *__schema*)` - the substring reading of the response. A
#      server with introspection correctly DISABLED answers with an error whose
#      MESSAGE quotes the string `__schema`, so the substring reading reports a
#      misconfiguration against a correctly-configured server, on the very
#      response that proves the opposite. Section B pins this.
#   2. Counting flattened LEAVES rather than distinct array indices, which
#      doubles every type count because each type carries both `name` and
#      `kind`. Section B pins this.
#   3. A SUBSTRING match on the path for the mount-path signal, which makes
#      every URL merely mentioning the word a GraphQL endpoint. Section A pins
#      this.
#
# It also pins the things that make the phase a phase rather than a parser: it
# sends NOTHING when the inventory names no GraphQL endpoint (this ticket's
# first acceptance criterion), every request goes through `http_request`, an
# introspection-disabled endpoint is reported as a real negative rather than as
# silence, and the emitted finding really does participate in a
# `correlate-on: target` composite (section E).
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes GraphQL and shell syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/core.sh and lib/findings.sh via
# crawl_engine.sh, which is what gives this suite the scratch dir, the traps and
# the finding writers without scan.sh.
# -x back-edge cut (modules/dast/graphql_engine.sh): this file already reaches that
# target through another edge, so following it here only re-expands the
# lib/ hub chain a second time - which is what peak RSS is made of. See
# docs/CI-RUNBOOK.md, "the memory model".
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql_engine.sh"
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-graphql-workspace
rm -rf "$W"; mkdir -p "$W"

# ===========================================================================
printf '== A. identifying a GraphQL endpoint: graphql_is_endpoint in isolation ==\n'
# ===========================================================================
# Pure function calls. No run directory, no transport, no finding.
# Arguments are (SOURCE, HOST, PATH, CONTENT_TYPE).

_is() { if graphql_is_endpoint "$@"; then printf 'yes'; else printf 'no'; fi; }

t_case 'signal 1: the inventory says source=graphql'
assert_eq yes "$(_is graphql host.example /api '')" \
  'an endpoint the crawler ingested a GraphQL schema for is a GraphQL endpoint whatever its path - FAILS under a path-only classifier, which is the whole reason docs/INVENTORY-FORMAT.md §2 has a `source` enum'
assert_eq yes "$(_is GraphQL host.example /api '')" \
  'the source comparison is case-insensitive'

t_case 'signal 2: a GraphQL media type on the observed response'
assert_eq yes "$(_is crawl host.example /api application/graphql-response+json)" \
  'the GraphQL-over-HTTP media type identifies a GraphQL server by that media type own definition'
assert_eq yes "$(_is crawl host.example /api 'application/graphql-response+json; charset=utf-8')" \
  'a charset parameter does not defeat the media-type signal - FAILS under an exact-equality comparison of the whole header value, which is how a real server actually sends it'
assert_eq yes "$(_is crawl host.example /api application/graphql+json)" \
  'the older application/graphql+json media type is recognised too'
assert_eq no "$(_is crawl host.example /api application/json)" \
  'plain application/json is NOT a GraphQL signal - it is what most of the web answers with, so treating it as one would classify every JSON API as GraphQL'

t_case 'signal 3: the managed-GraphQL service DNS shape (docs/DESIGN.md §8.5)'
assert_eq yes "$(_is crawl abc123.appsync-api.eu-west-1.amazonaws.com /graph '')" \
  'the managed-GraphQL DNS shape is recognised whatever the path - §7.4 says "GraphQL/AppSync" and §8.5 names the service, so this implements the design'
assert_eq yes "$(_is crawl ABC123.APPSYNC-API.US-EAST-1.AMAZONAWS.COM /graph '')" \
  'the host comparison is case-insensitive, as DNS is'
assert_eq yes "$(_is crawl abc.appsync-api.eu-west-1.amazonaws.com. /x '')" \
  'a fully-qualified host with a trailing dot still matches - the same normalisation lib/http.sh scope gate applies'
assert_eq no "$(_is crawl notappsync.example.com /x '')" \
  'an unrelated host is not a managed GraphQL API'
assert_eq no "$(_is crawl s3.eu-west-1.amazonaws.com /x '')" \
  'a DIFFERENT service under the same provider suffix is not a GraphQL API - FAILS under matching the provider suffix alone, which would classify every object-storage bucket as GraphQL'

t_case 'signal 4: the conventional mount path'
assert_eq yes "$(_is crawl host.example /graphql '')" 'the conventional mount path at the root'
assert_eq yes "$(_is crawl host.example /api/graphql '')" 'the conventional mount path nested'
assert_eq yes "$(_is crawl host.example /v1/graphql/ '')" \
  'a trailing slash does not defeat it - FAILS if the trailing slash is not stripped before the last-segment split, which leaves an empty final segment'
assert_eq yes "$(_is crawl host.example /GraphQL '')" 'the path segment comparison is case-insensitive'
assert_eq yes "$(_is crawl host.example /graphiql '')" \
  'the browser IDE path is only ever mounted next to a real GraphQL endpoint'

t_case 'the mount-path signal is a SEGMENT match, never a substring'
assert_eq no "$(_is crawl host.example /graphql-docs '')" \
  'a documentation page whose path merely BEGINS with the word is not an endpoint - FAILS under `case $path in *graphql*)`, the obvious shell reading, which spends a real request on a documentation page'
assert_eq no "$(_is crawl host.example /blog/a-graphql-primer '')" \
  'an article whose slug contains the word is not an endpoint - same rejected substring reading'
assert_eq no "$(_is crawl host.example /graphqlish '')" \
  'a segment that merely starts with the word is not the word - same rejected reading'
assert_eq no "$(_is crawl host.example /api/users '')" 'an ordinary REST path is not GraphQL'
assert_eq no "$(_is crawl host.example / '')" 'the site root alone is not GraphQL'

t_case 'the deciding signal is reported, so an operator can see WHY'
graphql_is_endpoint graphql host.example /api ''
assert_contains "$_GQL_WHY" 'source=graphql' 'the source signal names itself'
graphql_is_endpoint crawl host.example /api/graphql ''
assert_contains "$_GQL_WHY" 'mount path' 'the path signal names itself'
assert_contains "$_GQL_WHY" 'graphql' 'and quotes the segment it matched on'

# ===========================================================================
printf '\n== B. classifying the response: graphql_classify_response ==\n'
# ===========================================================================
# Still pure. Each case writes a RECORDED response body to a file and classifies
# it, exactly as graphql_probe does with the file lib/http.sh captured into.

_classify() { printf '%s' "$1" >"$W/body.json"; graphql_classify_response "$W/body.json"; }

t_case 'a schema that comes back is classified `schema`'
_classify '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},{"name":"String","kind":"SCALAR"}]}}}'
assert_eq schema "$_GQL_CLASS" 'introspection enabled: the schema was returned'
assert_eq 3 "$_GQL_TYPE_COUNT" \
  'three types are counted as THREE - FAILS under counting flattened LEAVES, which sees six because every type carries both `name` and `kind`, and so writes a number into the evidence that is simply double the truth'
assert_eq Query "$_GQL_QUERY_TYPE" 'the query root type name is read'
assert_eq 1 "$_GQL_HAS_MUTATION" 'a named mutation root is detected'

t_case 'a schema with NO mutation root is not reported as having one'
_classify '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[{"name":"Query","kind":"OBJECT"}]}}}'
assert_eq schema "$_GQL_CLASS" 'still a schema exposure'
assert_eq 0 "$_GQL_HAS_MUTATION" \
  '`"mutationType": null` is NO mutation root - it flattens to the leaf `data/__schema/mutationType`, a DIFFERENT path from the one this branch reads, so it is the path that decides this case rather than the type tag (measured; see the next case for what the tag itself defends)'

t_case 'a mutation root whose NAME is JSON null is not a mutation root either'
_classify '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":null},"types":[{"name":"Query","kind":"OBJECT"}]}}}'
assert_eq schema "$_GQL_CLASS" 'still a schema exposure'
assert_eq 0 "$_GQL_HAS_MUTATION" \
  '`"mutationType": {"name": null}` flattens to the SAME path a real name does, with type `z` and the four-byte value `null` - FAILS under reading the flattened value without checking its type tag, which reports a mutation root named "null" and tells the operator the schema maps state-changing operations it does not have. This is the case the type-tag guard actually defends, and the `mutationType: null` case above does NOT pin it'

# --- THE HEADLINE HAZARD ---------------------------------------------------
t_case 'introspection DISABLED is classified `disabled`, even though the refusal quotes `__schema`'
_classify '{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema","locations":[{"line":1,"column":11}]}]}'
assert_eq disabled "$_GQL_CLASS" \
  'a server that correctly REFUSES introspection is classified disabled - FAILS under `case $body in *__schema*)`, the obvious shell reading, because the literal string `__schema` appears quoted INSIDE the very error message saying introspection is off: the substring reading reports a critical misconfiguration against a correctly-configured server, on the exact response that proves the opposite. Parsing to the STRUCTURAL path data.__schema.types.<n>.name is what makes this decidable, because a JSON string contents never become a path'
assert_eq 0 "$_GQL_TYPE_COUNT" 'and no types are counted from an error message'
assert_contains "$_GQL_ERROR_NOTE" 'not allowed' 'the first error message is kept for the run record'

t_case 'a refusal that quotes the whole introspection query back is still `disabled`'
_classify '{"data":null,"errors":[{"message":"Cannot query field \"__schema\" on type \"Query\". Did you mean __schema? types name kind mutationType queryType"}]}'
assert_eq disabled "$_GQL_CLASS" \
  'an error message echoing EVERY field name the introspection document asked for is still a refusal - FAILS under any substring reading, including one hardened to also look for `types` or `queryType`, because an error message can quote all of them'
assert_eq 0 "$_GQL_TYPE_COUNT" 'and still counts no types'

t_case 'a non-GraphQL JSON response is `not_graphql`, and is NOT a clean result'
_classify '{"message":"Not Found"}'
assert_eq not_graphql "$_GQL_CLASS" \
  'a plain JSON error body is neither a schema exposure nor a GraphQL endpoint with introspection off - reporting it as `disabled` would let a 404 read as a correctly-hardened GraphQL endpoint'

t_case 'an HTML response is `not_graphql`'
_classify '<!doctype html><title>__schema types</title>'
assert_eq not_graphql "$_GQL_CLASS" \
  'an HTML page that happens to contain the words is not a schema - FAILS under the substring reading, and note the flattener yields nothing at all for non-JSON, so this is decided by structure rather than by luck'

t_case 'a `data.__schema` present but carrying no types is not a schema exposure'
_classify '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}'
assert_eq not_graphql "$_GQL_CLASS" \
  'the server answered the SHAPE without the content, so nothing was exposed and nothing was cleared'
assert_eq 0 "$_GQL_TYPE_COUNT" 'no types counted'

t_case 'an empty or absent body is `empty`, never an error'
: >"$W/body.json"
graphql_classify_response "$W/body.json"
assert_eq empty "$_GQL_CLASS" 'an empty capture file classifies as empty'
graphql_classify_response "$W/does-not-exist"
assert_eq empty "$_GQL_CLASS" \
  'an absent capture file classifies as empty and returns 0 - a target may answer anything at all, and this is untrusted target output (tension 10), so it must never be a hard error'

t_case 'the classifier state is fully reset between calls'
_classify '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"M"},"types":[{"name":"A","kind":"OBJECT"}]}}}'
assert_eq 1 "$_GQL_HAS_MUTATION" 'first call sees a mutation root'
_classify '{"message":"nope"}'
assert_eq 0 "$_GQL_HAS_MUTATION" \
  'the second call does not inherit the first call mutation flag - FAILS if the reset at the top of the function is dropped, which would carry one endpoint schema facts onto the next endpoint finding'
assert_eq 0 "$_GQL_TYPE_COUNT" 'nor its type count'
assert_eq '' "$_GQL_QUERY_TYPE" 'nor its query root name'

# ===========================================================================
printf '\n== C. the introspection document is a query, never a mutation ==\n'
# ===========================================================================
t_case 'the request body is well-formed JSON carrying the introspection query'
BODY=$(graphql_introspection_body)
assert_contains "$BODY" '"query":' 'the body is a JSON object with a `query` member'
assert_contains "$BODY" '__schema' 'and the document asks for __schema'
printf '%s' "$BODY" >"$W/doc.json"
FLAT=$(crawl_json_flatten <"$W/doc.json")
assert_contains "$FLAT" 'query' \
  'the body parses as JSON through this repository own reader - FAILS if the document is interpolated rather than passed through json_string, since the document contains characters JSON must escape'

t_case 'the document is a `query` operation and never constructs a mutation'
assert_contains "$_GQL_INTROSPECTION_DOC" 'query IntrospectionQuery' \
  'the operation is explicitly a query, which GraphQL specifies as side-effect free - this is what makes the POST verb read-only'
assert_not_contains "$_GQL_INTROSPECTION_DOC" 'mutation {' \
  'the document never opens a mutation selection set - FAILS if a future edit borrows a fuller introspection document that executes one, which would make this active check a state-changing one'
assert_not_contains "$_GQL_INTROSPECTION_DOC" 'mutation I' \
  'nor declares a mutation operation'
assert_contains "$_GQL_INTROSPECTION_DOC" 'mutationType { name }' \
  'it only READS THE NAME of the mutation root type, which is a schema fact rather than an invocation'

t_case 'the GET fallback query string is percent-encoded'
QS=$(graphql_introspection_query_string)
assert_contains "$QS" 'query=' 'it is a `query=` parameter'
assert_not_contains "$QS" ' ' \
  'no raw space survives into a URL - FAILS under string interpolation without encoding, which produces a URL curl would reject or silently truncate'
assert_not_contains "$QS" '{' 'no raw brace either'
assert_contains "$QS" '%20' 'spaces are percent-encoded'

# ===========================================================================
printf '\n== D. the phase, against recorded responses ==\n'
# ===========================================================================
# Scope, resolver and scanner limits, exactly as tests/suites/dast-cookies.sh
# sets them: a rate high enough that the DAST-32 ceiling never real-sleeps, and
# the authorisation affirmation the ceiling reads.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: gql-fixture
base-url: https://graphql.fixture.example/
notes: Fixture target for tests/suites/dast-graphql.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_gql_resolve() { case $1 in graphql.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_gql_resolve

# The mock target. One path per introspection posture. The recorded body is
# written into the capture file lib/http.sh passes as _HTTP_TX_BODY_OUT, which
# is the same file the phase then classifies - so the phase is exercised through
# the REAL capture path, not through a hand-fed string.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }
_req_count() { [[ -s $REQ_LOG ]] && /usr/bin/wc -l <"$REQ_LOG" | tr -d ' ' || printf 0; }

SRV_405_UNTIL_GET=0

_gql_transport() {
  local method=$1 path=$5 body out
  # The request body the phase actually sent is visible here, which is what lets
  # section D assert that a mutation is never transmitted.
  printf '%s %s body=%s\n' "$method" "$path" "${_HTTP_TX_BODY:-}" >>"$REQ_LOG"

  if (( SRV_405_UNTIL_GET )) && [[ $method == POST ]]; then
    printf '405\n\napplication/json\n'
    return 0
  fi

  case ${path%%\?*} in
    /graphql)
      body='{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"}]}}}'
      ;;
    /api/graphql)
      # Introspection correctly disabled - and the refusal quotes `__schema`.
      body='{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema"}]}'
      ;;
    /hardened/graphql)
      body='{"errors":[{"message":"introspection disabled"}]}'
      ;;
    /notreally/graphql)
      body='{"message":"Not Found"}'
      ;;
    /fail/graphql) return 1 ;;
    *) body='{"message":"no"}' ;;
  esac
  out=${_HTTP_TX_BODY_OUT:-}
  [[ -n $out ]] && printf '%s' "$body" >>"$out"
  printf '200\n\napplication/graphql-response+json\n'
}
SCOURSH_HTTP_TRANSPORT=_gql_transport

_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target gql-fixture
  occurrence_reset_all
  _req_reset
  SRV_405_UNTIL_GET=0
  SCOURSH_DAST_TARGET=gql-fixture
  SCOURSH_DAST_CELL=gql-fixture
  SCOURSH_DAST_AUTHED=false
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
}

# `_shards` - every finding this run emitted, as raw shard text.
_shards() { cat "$SCOURSH_RUN_DIR"/shards/*.fields 2>/dev/null || true; }
# `_count CHECK` - findings whose check_id matches exactly.
_count() {
  local check=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      while IFS= read -r fld; do
        [[ $fld == "check_id=$check" ]] && n=$(( n + 1 ))
      done < <(printf '%s' "$line" | tr '\t' '\n')
    done <"$f"
  done
  printf '%s' "$n"
}
_field() {                       # _field CHECK KEY - first matching finding value
  local check=$1 key=$2 f line fld hit='' want=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      hit='' want=''
      while IFS= read -r fld; do
        [[ $fld == "check_id=$check" ]] && hit=1
        [[ $fld == "$key="* ]] && want=${fld#"$key="}
      done < <(printf '%s' "$line" | tr '\t' '\n')
      if [[ -n $hit ]]; then printf '%s' "$want"; return 0; fi
    done <"$f"
  done
  printf ''
}
_meta() { run_facts "$1" 2>/dev/null || true; }

_inv() {                         # _inv NAME <<< json
  local f=$W/inv.$1.json
  cat >"$f"
  printf '%s' "$f"
}

# --- AC1: no GraphQL endpoint means a DECLARED reduction and ZERO requests ---
NO_GQL=$(_inv nogql <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e1", "target": "gql-fixture", "method": "GET", "url": "https://graphql.fixture.example/",          "path": "/",           "source": "crawl" },
  { "id": "e2", "target": "gql-fixture", "method": "GET", "url": "https://graphql.fixture.example/api/users", "path": "/api/users",  "source": "crawl" },
  { "id": "e3", "target": "gql-fixture", "method": "GET", "url": "https://graphql.fixture.example/graphql-docs", "path": "/graphql-docs", "source": "crawl" }
] }
EOF
)
t_case 'an inventory with no GraphQL endpoint: nothing is sent, and the run says so'
_new_run nogql
SCOURSH_DAST_GQL_ENDPOINTS=$NO_GQL
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=modules/dast/graphql.sh
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_req_count)" \
  'ZERO requests are sent when no endpoint classifies as GraphQL - FAILS under the "POST an introspection query everywhere and see who answers" design, which sends unsolicited GraphQL traffic to every URL the crawler found on an application that has no GraphQL at all'
assert_eq 0 "$(_count DAST-GQL-INTROSPECTION-01)" 'and no finding is emitted'
assert_contains "$(_meta coverage_reduction)" 'reason=no_graphql_endpoint' \
  'a DECLARED coverage reduction is recorded - this ticket first acceptance criterion, and the difference between "this application has no GraphQL" and "scoursh did not look"'
assert_contains "$(_meta coverage_gap)" 'no GraphQL or AppSync endpoint was identified' \
  'and a human-readable coverage gap reaches the report limitations section'
assert_eq '' "$(_meta checks_run)" \
  'checks_run stays EMPTY, so modules/dast/run.sh coverage roll-up cannot report this check as covered - FAILS if checks_run is recorded unconditionally, which would make a run that looked at nothing indistinguishable from one that found nothing'
assert_not_contains "$(_meta coverage_reduction)" 'graphql-docs' \
  'the documentation page was not probed either'

t_case 'no endpoint inventory at all is a different, equally declared reduction'
_new_run noinv
SCOURSH_DAST_GQL_ENDPOINTS=$W/absent-inventory.json
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_req_count)" 'still zero requests'
assert_contains "$(_meta coverage_reduction)" 'reason=no_endpoint_inventory' \
  '"there is no inventory" is recorded as its own reason, not folded into "no GraphQL endpoint" - the two are different facts and only the second says anything about the application'

# --- the main pass: introspection ENABLED -----------------------------------
ON_INV=$(_inv on <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "g1", "target": "gql-fixture", "method": "POST", "url": "https://graphql.fixture.example/graphql", "path": "/graphql", "source": "crawl", "content_type": "" },
  { "id": "r1", "target": "gql-fixture", "method": "GET",  "url": "https://graphql.fixture.example/api/users", "path": "/api/users", "source": "crawl" }
] }
EOF
)
t_case 'introspection enabled: one finding, with the DAST location profile'
_new_run on
SCOURSH_DAST_GQL_ENDPOINTS=$ON_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 1 "$(_count DAST-GQL-INTROSPECTION-01)" 'exactly one finding for the one exposed endpoint'
assert_eq 1 "$(_req_count)" \
  'exactly ONE request was sent - the non-GraphQL endpoint in the same inventory was not probed'
assert_eq gql-fixture "$(_field DAST-GQL-INTROSPECTION-01 loc_target)" \
  'loc_target carries the scope target id, which is what populates corr_target and is this finding whole contract with the derived layer (§9.2.2 gives DAST `target` and only `target`)'
assert_eq gql-fixture "$(_field DAST-GQL-INTROSPECTION-01 cell)" \
  'and the coverage cell is the same string, per §9.5.1 DAST row'
assert_eq POST "$(_field DAST-GQL-INTROSPECTION-01 loc_method)" 'the method that produced the answer'
assert_eq body "$(_field DAST-GQL-INTROSPECTION-01 loc_param_location)" \
  'the introspection document travels in the request body, so that is honestly where the issue lives'
assert_eq query "$(_field DAST-GQL-INTROSPECTION-01 loc_param_name)" 'under the `query` member'
assert_contains "$(_field DAST-GQL-INTROSPECTION-01 loc_path_template)" 'graphql' 'and the endpoint path template'
assert_contains "$(_meta checks_run)" 'DAST-GQL-INTROSPECTION-01' \
  'checks_run IS recorded now, because a GraphQL response really was classified'

t_case 'the evidence counts the schema without reproducing it'
EV=$(_field DAST-GQL-INTROSPECTION-01 evidence)
assert_contains "$EV" '2 type(s)' 'the evidence states how many types were exposed'
assert_contains "$EV" 'mutation root is present' 'and that a mutation root exists, which is the sharper fact'
assert_not_contains "$EV" 'kind' \
  'the schema itself is NOT reproduced in the artifact - §7.4 says "without exfiltrating data" and a type name is frequently a business-domain noun'
assert_contains "$EV" 'mount path' 'and the evidence names the signal that identified the endpoint, so a wrong inventory is correctable'

t_case 'the request that was actually transmitted is a query, never a mutation'
SENT=$(cat "$REQ_LOG")
assert_contains "$SENT" 'POST /graphql' 'the introspection document went to the GraphQL endpoint'
assert_contains "$SENT" 'IntrospectionQuery' 'and it carried the introspection document'
assert_not_contains "$SENT" 'mutation {' \
  'no mutation selection set was transmitted - asserted on the REQUEST LOG rather than on the document constant, so it also covers anything the phase might have added on the way'
assert_not_contains "$SENT" '/api/users' \
  'and the non-GraphQL endpoint in the same inventory was never contacted'

# --- introspection DISABLED: a real negative, not silence -------------------
OFF_INV=$(_inv off <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "g2", "target": "gql-fixture", "method": "POST", "url": "https://graphql.fixture.example/api/graphql", "path": "/api/graphql", "source": "crawl" }
] }
EOF
)
t_case 'introspection disabled: no finding, but the check IS recorded as covered'
_new_run off
SCOURSH_DAST_GQL_ENDPOINTS=$OFF_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_count DAST-GQL-INTROSPECTION-01)" \
  'a server that refuses introspection produces NO finding - FAILS under the substring reading of the response, whose refusal message quotes `__schema`, end to end through the real phase rather than only in the classifier'
assert_contains "$(_meta checks_run)" 'DAST-GQL-INTROSPECTION-01' \
  'checks_run IS recorded, which is what makes this a real negative rather than an absent test - the whole difference between "we looked and it is off" and "we could not look"'
assert_contains "$(_meta notes)" 'introspection=disabled' \
  'and the run states the good outcome positively, bounded to the endpoints inspected'
assert_not_contains "$(_meta coverage_reduction)" 'reason=no_graphql_endpoint' \
  'the endpoint WAS identified and probed, so the "nothing to look at" reduction must not fire'

t_case 'an endpoint that answers with a non-GraphQL response is neither reported nor cleared'
NOTREALLY=$(_inv notreally <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "g3", "target": "gql-fixture", "method": "POST", "url": "https://graphql.fixture.example/notreally/graphql", "path": "/notreally/graphql", "source": "crawl" }
] }
EOF
)
_new_run notreally
SCOURSH_DAST_GQL_ENDPOINTS=$NOTREALLY
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_count DAST-GQL-INTROSPECTION-01)" 'no finding is invented from a 404-shaped body'
assert_contains "$(_meta coverage_reduction)" 'reason=graphql_response_not_graphql' \
  'it is recorded as UNKNOWN rather than counted as a pass - the weakest signal (the mount path) matching a non-GraphQL URL is the likeliest cause, and saying so is what lets an operator correct the inventory instead of trusting a silence'
assert_eq '' "$(_meta checks_run)" \
  'and checks_run stays empty, because nothing about this endpoint introspection posture was established'

t_case 'a transport failure is a recorded reduction, never a clean result'
FAILINV=$(_inv fail <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "g4", "target": "gql-fixture", "method": "POST", "url": "https://graphql.fixture.example/fail/graphql", "path": "/fail/graphql", "source": "crawl" }
] }
EOF
)
_new_run fail
SCOURSH_DAST_GQL_ENDPOINTS=$FAILINV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_count DAST-GQL-INTROSPECTION-01)" 'no finding'
assert_contains "$(_meta coverage_reduction)" 'reason=graphql_request_failed' 'the failure is declared'
assert_contains "$(_meta coverage_gap)" 'failed at the transport' 'and reaches the report limitations section'
assert_eq '' "$(_meta checks_run)" 'checks_run stays empty when every probe failed'

t_case 'a 405 on POST falls back to GET, once, and the finding records the verb that worked'
_new_run fallback
SRV_405_UNTIL_GET=1
SCOURSH_DAST_GQL_ENDPOINTS=$ON_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 1 "$(_count DAST-GQL-INTROSPECTION-01)" \
  'a server that serves queries over GET and refuses POST is still covered - FAILS with no fallback, where such a server classifies as "not GraphQL" and the check silently never ran against it'
assert_eq GET "$(_field DAST-GQL-INTROSPECTION-01 loc_method)" \
  'the finding records the verb that actually produced the answer, not the one first tried'
assert_eq 2 "$(_req_count)" \
  'exactly two requests: the POST that got the 405 and the GET that worked - FAILS if the fallback is unconditional, which doubles this phase request count against every endpoint for no extra decision'
assert_contains "$(cat "$REQ_LOG")" 'GET /graphql?query=' 'the fallback carried the document as a query string'

t_case 'the per-phase endpoint cap bites visibly rather than silently'
MANY=$W/inv.many.json
{ printf '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [\n'
  for i in 1 2 3; do
    [[ $i == 1 ]] || printf ',\n'
    printf '  { "id": "m%s", "target": "gql-fixture", "method": "POST", "url": "https://graphql.fixture.example/s%s/graphql", "path": "/s%s/graphql", "source": "crawl" }' "$i" "$i" "$i"
  done
  printf '\n] }\n'
} >"$MANY"
_new_run cap
SCOURSH_DAST_GQL_ENDPOINTS=$MANY
SCOURSH_DAST_GQL_MAX_ENDPOINTS=1
export SCOURSH_DAST_GQL_ENDPOINTS SCOURSH_DAST_GQL_MAX_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 1 "$(_req_count)" 'the cap really bounds the requests sent'
assert_contains "$(_meta coverage_gap)" 'were not probed' \
  'and the two endpoints it skipped are named as a coverage BOUND - docs/INVENTORY-FORMAT.md §8 "no bound truncates silently", because a bound that bit invisibly is indistinguishable from a surface that was really that small'
unset SCOURSH_DAST_GQL_MAX_ENDPOINTS

t_case 'an endpoint belonging to a DIFFERENT target is not probed'
OTHER=$(_inv other <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "x1", "target": "some-other-target", "method": "POST", "url": "https://graphql.fixture.example/graphql", "path": "/graphql", "source": "crawl" }
] }
EOF
)
_new_run othertarget
SCOURSH_DAST_GQL_ENDPOINTS=$OTHER
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
assert_eq 0 "$(_req_count)" \
  'an inventory entry carrying another target id is not this target surface - FAILS if the target filter is dropped, which would attribute one target findings to another and break the coverage cell'
assert_contains "$(_meta coverage_reduction)" 'reason=no_graphql_endpoint' 'and the run says it found nothing to probe'

t_case 'an out-of-scope inventory row is SKIPPED, and the run continues'
OOS=$(_inv oos <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "o1", "target": "gql-fixture", "method": "POST", "url": "https://not-in-scope.invalid/graphql", "path": "/graphql", "source": "crawl" }
] }
EOF
)
_new_run oos
SCOURSH_DAST_GQL_ENDPOINTS=$OOS
export SCOURSH_DAST_GQL_ENDPOINTS
# THIS CASE USED TO ASSERT EXIT 3, AND THAT WAS THE DEFECT RATHER THAN THE
# CONTRACT. Handing an inventory-derived URL straight to `http_request` is
# fail-CLOSED and still fatal, so ONE bad row in an artifact tension 21 lets
# three other producers write - and lets an operator write by hand - ended the
# whole scan instead of skipping one endpoint. The shared, NON-fatal pre-check
# in modules/dast/engine.sh section 3b is what changed it; the gate itself is
# untouched, and tests/suites/dast-scope-precheck.sh section D pins that
# `http_request` still dies on a URL handed to it directly, which is what keeps
# a redirect the target chose - and any future caller that forgets the
# pre-check - gated.
#
# `|| GATE_RC=$?` rather than a bare call followed by `$?`: this suite runs under
# `set -Eeuo pipefail`, so a subshell exiting non-zero outside a condition aborts
# the WHOLE FILE. Written the bare way, this case never executed and the suite
# stopped here having printed no failure - 102 green assertions and a silent
# truncation, which is exactly the "a skipped suite is never a pass" hazard.
# Measured, not reasoned about: the first draft did precisely that.
GATE_RC=0
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh" || GATE_RC=$?
assert_eq 0 "$GATE_RC" \
  'the phase completes on an inventory whose only row is out of scope - FAILS on the pre-fix code, which handed the URL to http_request and died SCOURSH_EXIT_SCOPE (3), killing the run over one row of a file the scanner did not author'
assert_eq 0 "$(_req_count)" \
  'and it dialled nothing - asserted on the REQUEST LOG, so "it skipped" cannot be satisfied by a phase that sent the request and then returned non-zero'
assert_contains "$(_meta coverage_reduction)" 'reason=inventory_endpoint_out_of_scope' \
  'and it says WHY the row was not probed - FAILS under dropping it quietly, which reports a schema-exposure clean result for an endpoint that was never asked'
assert_contains "$(_meta coverage_reduction)" 'phase=graphql' 'under this phase own name'

# ===========================================================================
printf '\n== E. the correlation input DAST-10 derived finding consumes ==\n'
# ===========================================================================
# THIS IS THIS TICKET SECOND ACCEPTANCE CRITERION, PROVED RATHER THAN ASSERTED.
# docs/DESIGN.md §7.4 asks that a long-lived API key found in served JS (§7.1,
# DAST-10) be reported against an exposed schema "as a correlated finding". That
# correlated finding is COMPOSITE-TOKEN-HIJACK, computed by §9.2 derived layer
# in lib/findings.sh - "not scanner scripts", per §9.2 own first line. What
# graphql.sh owes is to be a usable CONTRIBUTOR, and the only thing that takes
# is a populated `corr_target`, since §9.2.2 frozen capability table gives DAST
# the `target` correlation key and no other.
#
# `rules/derived.rules` IS STILL NOT SEEDED, and this section does not seed it:
# findings F5/F20 record that seeding COMPOSITE-TOKEN-HIJACK before its
# contributors exist is a guaranteed `E051`, and DAST-10 leakage check id does
# not exist yet. So the composite below is written into this suite own SCRATCH
# directory - never under tests/fixtures/, which tests/lint-rules.sh lints and
# would fail on an unknown contributor id - and it names two REAL, REGISTERED
# DAST check ids rather than inventing one. DAST-COOKIE-NO_SECURE-01 stands in
# for DAST-10 own id, which is honest about what is being proved: that a
# DAST-GQL-INTROSPECTION-01 finding joins a second DAST finding on `target`
# through the shipped derived machinery. Swapping the stand-in for DAST-10 real
# id, once it exists, is a one-token change.

# A minimal second DAST contributor at the same target, standing in for
# DAST-10's key-exposure finding.
_emit_stand_in() {
  finding_new
  finding_set check_id DAST-COOKIE-NO_SECURE-01
  finding_set module dast
  finding_set title 'stand-in contributor'
  finding_set base_severity medium
  finding_set cwe CWE-614
  finding_set owasp A05:2021
  finding_set cell gql-fixture
  finding_set loc_target "$1"
  finding_set loc_method GET
  finding_set loc_path_template /
  finding_set loc_param_location cookie
  finding_set loc_param_name sid
  finding_set_evidence 'stand-in for DAST-10 key-exposure finding'
  finding_emit
}

COMPOSITE=$W/token-hijack.rules
cat >"$COMPOSITE" <<'EOF'
id: COMPOSITE-FIXTURE-TOKEN-HIJACK
kind: derived
title: An exposed GraphQL schema alongside a second exposure on the same target
severity: high
confidence: high
cwe: CWE-200
owasp: A05:2021
requires: DAST-GQL-INTROSPECTION-01
any-of: DAST-COOKIE-NO_SECURE-01
correlate-on: target
tags: derived
remediation: Disable introspection and fix the correlated exposure together.
EOF

t_case 'the introspection finding carries corr_target, which is the whole contract'
_new_run corr
SCOURSH_DAST_GQL_ENDPOINTS=$ON_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
findings_merge "$SCOURSH_RUN_DIR"
assert_contains "$(cat "$SCOURSH_RUN_DIR/findings.fields")" 'corr_target=gql-fixture' \
  'lib/findings.sh _finding_fill_correlation populated corr_target from loc_target - FAILS if the finding is emitted without a loc_target, in which case it silently has no correlation value and can never participate in the composite §7.4 asks for, with no error anywhere'

t_case 'the composite does NOT fire on the introspection finding alone'
derive_findings "$SCOURSH_RUN_DIR" "$COMPOSITE"
assert_not_contains "$(cat "$SCOURSH_RUN_DIR/findings.fields")" 'COMPOSITE-FIXTURE-TOKEN-HIJACK' \
  'one contributor is not a chain - this is what makes the next case a real join rather than a freebie that would pass however the finding was emitted'

t_case 'with both contributors on the same target, the composite fires'
_new_run corr2
SCOURSH_DAST_GQL_ENDPOINTS=$ON_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
_emit_stand_in gql-fixture
findings_merge "$SCOURSH_RUN_DIR"
derive_findings "$SCOURSH_RUN_DIR" "$COMPOSITE"
assert_contains "$(cat "$SCOURSH_RUN_DIR/findings.fields")" 'COMPOSITE-FIXTURE-TOKEN-HIJACK' \
  'DAST-GQL-INTROSPECTION-01 really is consumable as a `correlate-on: target` contributor by the shipped derived machinery - which is the correlation input §7.4 second sentence asks for, demonstrated end to end rather than claimed'
assert_contains "$(cat "$SCOURSH_RUN_DIR/findings.fields")" 'derived_into=' \
  'and the contributor carries the back-reference lib/findings.sh writes onto a finding that fed a composite'

t_case 'contributors on DIFFERENT targets do not correlate'
_new_run corr3
SCOURSH_DAST_GQL_ENDPOINTS=$ON_INV
export SCOURSH_DAST_GQL_ENDPOINTS
# shellcheck source=/dev/null
source "$ROOT/modules/dast/graphql.sh"
_emit_stand_in a-different-target
findings_merge "$SCOURSH_RUN_DIR"
derive_findings "$SCOURSH_RUN_DIR" "$COMPOSITE"
assert_not_contains "$(cat "$SCOURSH_RUN_DIR/findings.fields")" 'COMPOSITE-FIXTURE-TOKEN-HIJACK' \
  'the join is on the target VALUE, not merely on both check ids being present - FAILS under a predicate that only asks "did both checks fire this run", which would chain a schema exposed on one deployment to a key leaked on another. rules/RULE-FORMAT.md §9.2.2 authoring note names this exact hazard'

# ===========================================================================
printf '\n== F. registration: scan_dispatch dast really runs this phase ==\n'
# ===========================================================================
t_case 'modules/dast/engine.sh phase table names graphql.sh at tier active'
FOUND=0
for spec in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
  [[ $spec == 'graphql.sh:active' ]] && FOUND=1
done
assert_eq 1 "$FOUND" \
  'modules/dast/engine.sh names graphql.sh at tier active, so scan_dispatch dast runs it as a phase - docs/DESIGN.md §7.4 is headed "Active", and this row predates the file, which is why nothing in engine.sh needed editing for this ticket'

t_case 'dast_run_phase now finds the script on disk'
SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'graphql.sh:active' active gql-fixture >/dev/null 2>&1 || true
assert_eq 1 "$_DAST_PHASE_PRESENT" \
  'dast_run_phase finds the script - FAILS while the file is absent, which is the state every DAST-0x row starts in'

t_case 'the intensity ceiling refuses this phase below `active`'
SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'graphql.sh:active' passive gql-fixture >/dev/null 2>&1 || true
assert_eq skipped_intensity "$_DAST_PHASE_OUTCOME" \
  'a --intensity passive run does not reach this phase at all - FAILS if the row tier is lowered without lowering the check own type tag, leaving two gates that disagree'
SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'graphql.sh:active' safe gql-fixture >/dev/null 2>&1 || true
assert_eq skipped_intensity "$_DAST_PHASE_OUTCOME" 'nor does a --intensity safe run'

t_case 'the check id this phase emits is in the registry'
SCOURSH_INSTALL_ROOT=$ROOT checks_registry_load dast DASTGQL
REG=''
for s in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
  n=$(records_count "$s")
  for (( ri = 0; ri < n; ri++ )); do
    REG+=$(records_id "$s" "$ri")
    REG+=' '
  done
done
assert_contains "$REG" 'DAST-GQL-INTROSPECTION-01' \
  'DAST-GQL-INTROSPECTION-01 is registered in modules/dast/checks.rules - FAILS if a check is emitted with no registry record, which leaves tension 12 unable to compute coverage for it and tension 15 unable to filter it'

t_case 'no scan target, hostname or endpoint is baked into the shipped files'
for f in modules/dast/graphql.sh modules/dast/graphql_engine.sh modules/dast/checks.rules; do
  assert_not_contains "$(cat "$ROOT/$f")" 'fixture.example' \
    "$f names no test target - every concrete host comes from the operator config/scope.conf by way of the inventory"
done
assert_not_contains "$(cat "$ROOT/modules/dast/graphql_engine.sh")" 'base-url' \
  'and the engine declares no scope record of its own (DAST-35 own lint asserts this repository-wide; this is the local restatement)'

t_summary dast-graphql
