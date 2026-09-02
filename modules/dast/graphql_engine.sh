#!/usr/bin/env bash
# modules/dast/graphql_engine.sh - the pure half of the §7.4 GraphQL check
# (docs/DESIGN.md §7.4, §8.5; docs/STEP5-DAST-PLAN.md DAST-27).
#
# The engine.sh/phase.sh split is modules/sast/'s, reused verbatim, exactly as
# auth_engine.sh + auth.sh, cookie_engine.sh + cookies.sh and jwt_engine.sh +
# jwt.sh already do: THIS file is a pure function library with a sourced-once
# guard and no side effect at source time, and modules/dast/graphql.sh is the
# file that DOES something when sourced.
#
# docs/DESIGN.md §7.4's whole sentence for this check is:
#
#   "graphql.sh - introspection & key exposure.  If a GraphQL/AppSync endpoint
#    is in scope: send a standard introspection query and flag if the schema is
#    returned (introspection enabled in prod).  If a long-lived API key was
#    found in the served JS (§7.1 leakage.sh), report that the key grants
#    schema/content access - as a correlated finding, without exfiltrating
#    data."
#
# The first half is this file.  The second half is the DERIVED layer's job and
# is deliberately not a second check id here - see section 6.
#
# WHY A POST IS PERMITTED HERE AND IS NOT A MUTATION.  This phase sits at the
# `active` tier (modules/dast/engine.sh's table: `graphql.sh:active`; §7.4 is
# headed "Active - auth, API, and access-control checks"), so it may send a
# method a passive check may not.  But the stronger guarantee is GraphQL's own:
# an operation is a MUTATION only when the document says `mutation`, and every
# document this file constructs is a `query` (section 3).  A GraphQL query is
# specified as side-effect free, so the POST verb here carries a read-only
# operation.  Nothing in this file ever emits the token `mutation` into a
# request body; the introspection document only READS the NAME of the mutation
# root type, which is a schema fact, not an invocation.  Executing an actual
# mutation is explicitly out of scope for DAST-27.
#
# NO SCAN TARGET, HOSTNAME OR ENDPOINT IS BAKED INTO THIS FILE (AGENTS.md's
# target-agnosticism rule, docs/DESIGN.md §1).  Section 2's signals describe
# CLASSES - the two registered GraphQL media types, the conventional mount path
# a GraphQL server is served under, and the DNS SHAPE of a managed GraphQL
# service - in the same way modules/iac/dockerfile.rules names the basename
# `Dockerfile` and modules/iac/docker-compose.rules names `docker-compose.yml`.
# None of them names an application, a company, a product, an environment or a
# deployment, and every concrete host this phase contacts comes from the
# operator's own config/scope.conf by way of the inventory.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_GRAPHQL_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_GRAPHQL_ENGINE_SOURCED=1

# crawl_engine.sh is the frozen JSON reader every inventory producer and
# consumer shares (docs/INVENTORY-FORMAT.md §7), and it is reused TWICE here
# rather than re-implemented: once to read endpoints.json, and once to read the
# target's own introspection RESPONSE, which is also JSON.  It carries a
# sourced-once guard and no source-time side effect, so in a real run - where
# crawl.sh has already sourced it - this is a no-op, and standalone it is what
# lets tests/suites/dast-graphql.sh drive this engine without scan.sh.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/crawl_engine.sh"

# ---------------------------------------------------------------------------
# 1. Bounds
# ---------------------------------------------------------------------------
# NO BOUND TRUNCATES SILENTLY - the rule docs/INVENTORY-FORMAT.md §8 freezes for
# the inventory, applied to this phase.  A bound that bit invisibly would be
# indistinguishable from a surface that was really that small, which is the
# overstated coverage docs/DESIGN.md §15 forbids; graphql.sh records a
# coverage_gap whenever one bites.
: "${SCOURSH_DAST_GQL_MAX_ENDPOINTS:=10}"   # distinct GraphQL endpoints probed
: "${SCOURSH_DAST_GQL_MAX_BODY:=524288}"    # bytes of a response body parsed

# ---------------------------------------------------------------------------
# 2. Deciding whether an inventory endpoint is a GraphQL endpoint
# ---------------------------------------------------------------------------
# THE ANSWER IS A CLASSIFICATION OVER THE INVENTORY, NOT A PROBE, AND THAT IS
# THE POINT OF THIS TICKET'S FIRST ACCEPTANCE CRITERION.  DAST-27 runs "only
# when the DAST-04 inventory contains a GraphQL/AppSync endpoint", so an
# inventory with no such endpoint must produce a declared coverage reduction and
# ZERO requests.  Doing it the other way round - POST an introspection document
# at every endpoint and see which one answers - would send unsolicited GraphQL
# traffic to every URL the crawler found, on a run whose application has no
# GraphQL at all.  That is traffic no operator asked for, which
# modules/dast/engine.sh's own header already refuses on this module's behalf.
#
# `graphql_is_endpoint SOURCE HOST PATH CONTENT_TYPE` - returns 0 when the
# endpoint is a GraphQL endpoint, 1 otherwise, and sets `_GQL_WHY` to the single
# signal that decided it.  That sentence reaches the finding's evidence, so an
# operator can see WHY scoursh treated a URL as GraphQL and correct the
# inventory when it is wrong.  Signals are ordered strongest first, first match
# wins.
#
#   1. `source: graphql`   docs/INVENTORY-FORMAT.md §2's own enum.  The crawler
#                          ingested a GraphQL schema for this endpoint, so the
#                          operator has ASSERTED it is one.  Strongest possible
#                          signal, and it names nothing.
#   2. content type        `application/graphql-response+json` (the
#                          GraphQL-over-HTTP media type) and the older
#                          `application/graphql+json`.  A server answering in
#                          one of these is a GraphQL server by that media type's
#                          own definition.
#   3. managed-service DNS shape
#                          A managed GraphQL service publishes every API under a
#                          fixed provider-owned DNS shape with the operator's own
#                          api id as the leftmost label.  docs/DESIGN.md §8.5 -
#                          "AppSync / managed GraphQL" - and §7.4's own
#                          "GraphQL/AppSync" wording put that service in scope BY
#                          NAME, so recognising its DNS shape implements the
#                          design rather than baking in a target: the pattern
#                          matches every such API in every account and region and
#                          identifies no particular one.
#   4. mount path          The conventional path a GraphQL endpoint is served
#                          under, plus the browser IDE paths only ever mounted
#                          next to one.  A convention, exactly like the
#                          `Dockerfile` basename in modules/iac/.
#
# The path signal is deliberately the WEAKEST and is still sufficient alone,
# because the two errors cost asymmetrically: treating a non-GraphQL URL as
# GraphQL costs one POST that comes back classified `not_graphql` with NO
# finding, while missing a real GraphQL endpoint means the check silently never
# ran - the outcome §15 forbids.
graphql_is_endpoint() {
  local source=$1 host=$2 path=$3 ctype=$4
  _GQL_WHY=''

  # 1. The inventory says so outright.
  if [[ ${source,,} == graphql ]]; then
    _GQL_WHY='inventory source=graphql (a GraphQL schema was ingested for this endpoint)'
    return 0
  fi

  # 2. A GraphQL media type on the observed response.  Matched as a PREFIX of
  #    the header value so a `; charset=utf-8` parameter does not defeat it.
  case ${ctype,,} in
    application/graphql-response+json*)
      _GQL_WHY='observed Content-Type: application/graphql-response+json'
      return 0
      ;;
    application/graphql+json*)
      _GQL_WHY='observed Content-Type: application/graphql+json'
      return 0
      ;;
  esac

  # 3. The managed-GraphQL DNS shape (docs/DESIGN.md §8.5).  A trailing dot is
  #    stripped first, the same normalisation lib/http.sh's scope gate applies.
  local h=${host,,}
  h=${h%.}
  case $h in
    *.appsync-api.*.amazonaws.com | *.appsync-realtime-api.*.amazonaws.com)
      _GQL_WHY='host matches the managed-GraphQL service DNS shape (docs/DESIGN.md §8.5)'
      return 0
      ;;
  esac

  # 4. The conventional mount path.  Compared on the LAST non-empty path
  #    segment, case-insensitively, with any trailing slash removed - so
  #    `/api/graphql`, `/v1/graphql/` and `/graphql` all match while
  #    `/graphql-docs` and `/a-graphql-blog-post` do not.  A SUBSTRING match here
  #    would make every page whose URL merely mentions the word a GraphQL
  #    endpoint, which is a false positive that costs a real request.
  local p=${path%/}
  local seg=${p##*/}
  case ${seg,,} in
    graphql | graphiql | playground | altair)
      _GQL_WHY="conventional GraphQL mount path (last path segment '$seg')"
      return 0
      ;;
  esac

  return 1
}

# ---------------------------------------------------------------------------
# 3. The introspection document
# ---------------------------------------------------------------------------
# THE DOCUMENT IS A `query`, NEVER A `mutation`, AND IT IS DELIBERATELY THE
# SMALL INTROSPECTION QUERY RATHER THAN THE CANONICAL FULL ONE.  What this check
# decides is a single yes/no - did the server hand back its schema - and the
# full IntrospectionQuery that the reference implementation ships is several
# kilobytes that recurse through every type's every field's every argument's
# type ref.  Asking for that makes the server materialise its entire type system
# to answer a question `types { name kind }` already answers, and drags a large
# body back across a link the operator is rate-limiting.  The fields requested
# are exactly the ones section 4 classifies on and section 6 reports, and no
# more: "without exfiltrating data", which §7.4 says in as many words, applies
# to the schema too - scoursh reports THAT the schema is exposed and counts it,
# and never writes the schema itself into an artifact.
_GQL_INTROSPECTION_DOC='query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }'

# `graphql_introspection_body` - the request body, a JSON object with a `query`
# member, ready for `http_request_body`.  The document goes through
# lib/core.sh's `json_string` rather than being interpolated, for the reason
# docs/INVENTORY-FORMAT.md §6 gives for every other JSON this tool writes.
graphql_introspection_body() {
  printf '{"query":%s}' "$(json_string "$_GQL_INTROSPECTION_DOC")"
}

# Percent-encoding, for the GET fallback in section 5.
#
# `local LC_ALL=C` is load-bearing rather than tidiness, and the lesson is
# auth_engine.sh's `_dast_auth_urlencode`, recorded there and repeated here
# because this is a separate function: without it bash indexes a UTF-8 string by
# CHARACTER and `"'$c"` yields the code point, so a non-ASCII byte would be
# encoded as one out-of-range %XX instead of its two or three real bytes.  This
# is a small private copy rather than a call into auth_engine.sh on purpose -
# that function is private to that engine and sourcing a 50KB session library to
# borrow twenty lines of parameter expansion would couple this phase to the auth
# phase for nothing.
_gql_urlencode() {
  local LC_ALL=C
  local s=$1 out='' i n c
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    c=${s:i:1}
    case $c in
      [A-Za-z0-9.~_-]) out+=$c ;;
      *) printf -v c '%%%02X' "'$c"; out+=$c ;;
    esac
  done
  _GQL_ENC=$out
  return 0
}

# `graphql_introspection_query_string` - the same document as a `?query=` query
# string.
graphql_introspection_query_string() {
  _gql_urlencode "$_GQL_INTROSPECTION_DOC"
  printf 'query=%s' "$_GQL_ENC"
}

# ---------------------------------------------------------------------------
# 4. Classifying the response
# ---------------------------------------------------------------------------
# `graphql_classify_response BODY_FILE` - sets:
#
#   _GQL_CLASS        schema | disabled | not_graphql | empty
#   _GQL_TYPE_COUNT   number of types named under data.__schema.types
#   _GQL_HAS_MUTATION 1 when data.__schema.mutationType.name is a real name
#   _GQL_QUERY_TYPE   the query root type's name, or ''
#   _GQL_ERROR_NOTE   for `disabled`, the FIRST error message only
#
# and returns 0 always.  An unreadable or unparseable body is `empty`, never an
# error: a target may answer anything at all, and this is UNTRUSTED target
# output (docs/FOUNDATION.md tension 10).
#
# IT PARSES, IT DOES NOT GREP, AND THE DIFFERENCE IS A REAL DEFECT AVOIDED.
# The obvious shell reading is `case $body in *__schema*)` - and that is wrong
# in the direction that reads as a FINDING.  A server with introspection
# correctly DISABLED answers with
#
#   {"errors":[{"message":"GraphQL introspection is not allowed, but the query
#    contained __schema"}]}
#
# - the literal string `__schema` appears, quoted inside the very error message
# saying introspection is off.  A substring match reports a misconfiguration
# against a server that is correctly configured, on the exact response that
# proves the opposite.  This function therefore goes through
# `crawl_json_flatten` - docs/INVENTORY-FORMAT.md §7's depth- and string-aware
# reader - and asks for a leaf at the STRUCTURAL path
# `data.__schema.types.<n>.name`, which an error message cannot fabricate
# because a JSON string's contents never become a path.
# tests/suites/dast-graphql.sh pins this with the response above, as a case that
# fails under the substring reading.
graphql_classify_response() {
  local bodyf=$1
  local sep=$'\x1f' p type v rest idx
  local -A seen_type_idx=()

  _GQL_CLASS=empty
  _GQL_TYPE_COUNT=0
  _GQL_HAS_MUTATION=0
  _GQL_QUERY_TYPE=''
  _GQL_ERROR_NOTE=''

  [[ -n $bodyf && -r $bodyf && -s $bodyf ]] || return 0

  local saw_errors=0 saw_data_schema=0
  while IFS=$'\t' read -r p type v; do
    case $p in
      "data${sep}__schema${sep}types${sep}"*)
        saw_data_schema=1
        rest=${p#"data${sep}__schema${sep}types${sep}"}
        idx=${rest%%"$sep"*}
        # Count DISTINCT array indices, not leaves.  Each type contributes both
        # a `name` and a `kind`, so counting leaves would double every count and
        # put a number in the evidence that is simply wrong.
        [[ $idx =~ ^[0-9]+$ ]] && seen_type_idx[$idx]=1
        ;;
      "data${sep}__schema${sep}queryType${sep}name")
        saw_data_schema=1
        [[ $type == s ]] && _GQL_QUERY_TYPE=$(crawl_json_unescape "$v")
        ;;
      "data${sep}__schema${sep}mutationType${sep}name")
        saw_data_schema=1
        # THE TYPE TAG IS LOAD-BEARING, AND NOT FOR THE REASON THAT LOOKS
        # OBVIOUS.  A schema with no mutation root reports `"mutationType":
        # null`, and that case is handled by the PATH rather than by the tag:
        # `crawl_json_flatten` emits it as the leaf `data/__schema/mutationType`
        # with type `z`, which does not match this branch at all (measured, not
        # assumed - a first draft of this comment claimed the opposite and the
        # test written from it passed under both readings, pinning nothing).
        # What the tag actually defends is `"mutationType": {"name": null}`,
        # which flattens to THIS path with type `z` and the four-byte value
        # `null` - so a reading that took the value alone would report a
        # mutation root named "null" and tell the operator the schema maps
        # state-changing operations it does not have.  Only a `s` leaf is a real
        # type name.
        [[ $type == s ]] && _GQL_HAS_MUTATION=1
        ;;
      "data${sep}__schema"*)
        saw_data_schema=1
        ;;
      "errors${sep}"*)
        saw_errors=1
        if [[ -z $_GQL_ERROR_NOTE && $p == *"${sep}message" && $type == s ]]; then
          _GQL_ERROR_NOTE=$(crawl_json_unescape "$v")
        fi
        ;;
    esac
  done < <(head -c "$SCOURSH_DAST_GQL_MAX_BODY" <"$bodyf" 2>/dev/null \
    | crawl_json_flatten 2>/dev/null)

  _GQL_TYPE_COUNT=${#seen_type_idx[@]}

  if (( saw_data_schema && _GQL_TYPE_COUNT > 0 )); then
    # The schema came back.  This is the finding.
    _GQL_CLASS=schema
  elif (( saw_errors )); then
    # The server understood a GraphQL document and refused THIS one: a GraphQL
    # endpoint with introspection off.  The only branch here that is good news,
    # and it is a real negative rather than an absence of testing.
    _GQL_CLASS=disabled
  else
    # Either `data.__schema` present but carrying no types - the server answered
    # the shape without the content - or a response that is not a GraphQL
    # response at all.  Neither is a schema exposure and neither is evidence the
    # endpoint is safe, so both are `not_graphql` and graphql.sh records the
    # endpoint as uncovered rather than clean.
    _GQL_CLASS=not_graphql
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 5. One endpoint, end to end
# ---------------------------------------------------------------------------
# `graphql_probe TARGET URL [AUTH_APPLY_FN]` - sends the introspection document
# to URL, sets section 4's variables plus:
#
#   _GQL_PROBE_STATUS  the final HTTP status, or '' on a transport failure
#   _GQL_PROBE_METHOD  POST | GET - which verb produced the classified answer
#   _GQL_PROBE_OK      1 when a response was classified, 0 when none was
#
# EVERY REQUEST GOES THROUGH `http_request` AND THERE IS NO OTHER PATH OUT OF
# THIS FILE (docs/FOUNDATION.md tension 19's "No bypass").  That is what makes
# the scope gate, DAST-01's rate limiter, the per-run request budget and the
# circuit breaker all apply to this check without it opting in to any of them -
# and it is why this file contains no `curl`, no `wget` and no `/dev/tcp`.  It
# also fixes this phase's exit-code behaviour inside the frozen 0-5 range on
# every path: `http_request` either returns (0 for a classified response, 1 for
# a transport failure, which this function absorbs) or `die`s with one of the
# codes lib/core.sh already validates - scope 3, budget/breaker 5, usage 2.
# Nothing here invents an exit code or calls `exit` directly.
#
# THE GET FALLBACK IS TRIED ONLY ON A 405, AND THAT BOUND IS THE POINT.  The
# GraphQL-over-HTTP convention is POST, but a server may be configured to serve
# queries over GET and refuse POST outright; without the fallback such a server
# classifies as "not GraphQL" and the check silently never ran there.  Retrying
# unconditionally would instead double this phase's request count against every
# endpoint for no extra decision, so it is gated on the one status that actually
# means "wrong verb".  Worst case is two requests per endpoint, both drawn from
# the same per-run budget as everything else.
#
# AUTH_APPLY_FN IS A FUNCTION NAME, NOT A HEADER NAME AND VALUE, AND THE
# INDIRECTION IS LOAD-BEARING.  lib/http.sh section 9a resets the per-request
# header context at the ENTRY of every `http_request`, precisely so a credential
# attached for one request can never ride along on the next one - so a caller
# that computed a header once and handed it here would have to re-attach it for
# the 405 fallback, and a phase that forgot would send its second request
# UNAUTHENTICATED and silently under-report against an endpoint that only
# answers a session.  Taking the applier by name means the credential is
# re-attached by construction on every request this function makes, and it also
# means this engine never handles the credential itself: `dast_auth_apply` is
# the auth engine's own public applier and it attaches both the Authorization
# header and the session cookies, neither of which this file has to know about
# (docs/FOUNDATION.md tension 9 - a secret is never an argument).  An empty
# AUTH_APPLY_FN is the unauthenticated probe.
graphql_probe() {
  local target=$1 url=$2 auth_apply=${3:-}
  local bodyf=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/dast-gql-body.$$

  _GQL_PROBE_STATUS='' _GQL_PROBE_METHOD='' _GQL_PROBE_OK=0
  _GQL_CLASS=empty _GQL_TYPE_COUNT=0 _GQL_HAS_MUTATION=0
  _GQL_QUERY_TYPE='' _GQL_ERROR_NOTE=''

  : >"$bodyf"
  [[ -n $auth_apply ]] && "$auth_apply"
  http_request_header Content-Type application/json
  http_request_header Accept 'application/graphql-response+json, application/json'
  http_request_body "$(graphql_introspection_body)"
  http_request_capture "$bodyf" ''
  if http_request POST "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
    _GQL_PROBE_STATUS=$_HTTP_LAST_STATUS
    _GQL_PROBE_METHOD=POST
    _GQL_PROBE_OK=1
    graphql_classify_response "$bodyf"
  fi

  # The 405 fallback, with the credential re-attached - see this function's
  # header for why that is structural rather than remembered.
  if (( _GQL_PROBE_OK )) && [[ $_GQL_PROBE_STATUS == 405 ]]; then
    : >"$bodyf"
    [[ -n $auth_apply ]] && "$auth_apply"
    http_request_header Accept 'application/graphql-response+json, application/json'
    http_request_capture "$bodyf" ''
    if http_request GET "$url?$(graphql_introspection_query_string)" \
      "${SCOURSH_MAX_REDIRECTS:-5}" "$target"; then
      _GQL_PROBE_STATUS=$_HTTP_LAST_STATUS
      _GQL_PROBE_METHOD=GET
      graphql_classify_response "$bodyf"
    fi
  fi

  rm -f "$bodyf"
  return 0
}

# ---------------------------------------------------------------------------
# 6. Emitting the finding, and the correlation input
# ---------------------------------------------------------------------------
# `graphql_emit_introspection TARGET URL PATH WHY` - one finding, in the shape
# jwt_engine.sh's `jwt_emit_finding` established for this module.
#
# THIS FINDING IS THE CORRELATION INPUT §7.4's SECOND SENTENCE ASKS FOR, AND
# THAT IS WHY THERE IS NO SECOND CHECK ID HERE.  §7.4 wants "a long-lived API
# key was found in the served JS (§7.1) + introspection enabled" reported "as a
# correlated finding".  A correlated finding is precisely what
# rules/RULE-FORMAT.md §9.2's DERIVED layer computes, in lib/findings.sh, once
# per run, after every module has finished - §9.2's own first line says it is
# computed there and "not scanner scripts".  Minting a `DAST-GQL-KEY_EXPOSURE-01`
# in this file would be a second, competing implementation of the composite the
# register already owns as `COMPOSITE-TOKEN-HIJACK`, and it could not work
# anyway: this phase runs before §7.1's leakage findings are merged, and §8.5's
# AppSync key-expiry contributor comes from a different MODULE entirely.
#
# What a contributor actually owes the derived layer is ONE thing, and this
# function does it: `loc_target` is set, so `_finding_fill_correlation` fills
# `corr_target`, so `derive_findings` indexes this finding under
# (check_id, target, <target id>) and any `correlate-on: target` composite
# naming `DAST-GQL-INTROSPECTION-01` in its `requires`/`any-of` picks it up with
# no further cooperation from here.  §9.2.2's frozen capability table gives DAST
# `target` and only `target`, which is why that composite must correlate on that
# key and why this finding must carry a target to be usable at all.
#
# `rules/derived.rules` IS STILL NOT SEEDED BY THIS TICKET, DELIBERATELY.
# Findings F5 and F20 record that seeding COMPOSITE-TOKEN-HIJACK before its
# contributors exist is a guaranteed `E051` (every requires/any-of value must
# name an EXISTING check id), and DAST-10's leakage check id does not exist yet.
# DAST-10 is the ticket that can finally seed it.  What this ticket owes instead
# is proof that the input END is real, which tests/suites/dast-graphql.sh gives
# by running the shipped finding through `derive_findings` against a FIXTURE
# composite - `derive_findings RUNDIR DERIVED_FILE` takes the rule file as its
# second argument, the same way tests/fixtures/rules/derived.rules has stood in
# for the unseeded file since step 1.
#
# THE SCHEMA ITSELF IS NEVER WRITTEN INTO AN ARTIFACT.  §7.4 says "without
# exfiltrating data" and the schema IS the data here: the evidence carries the
# COUNT of exposed types, the root type names, and nothing else.  A type name is
# frequently a business-domain noun, and a scoursh report is a document that
# leaves the operator's machine.
graphql_emit_introspection() {
  local target=$1 url=$2 path=$3 why=$4
  local evidence

  evidence="GraphQL introspection is enabled at this endpoint: one introspection"
  evidence+=" query returned the schema, naming $_GQL_TYPE_COUNT type(s)"
  [[ -n $_GQL_QUERY_TYPE ]] && evidence+=", query root '$_GQL_QUERY_TYPE'"
  if (( _GQL_HAS_MUTATION )); then
    evidence+=", and a mutation root is present - so the schema also maps every"
    evidence+=" state-changing operation the API offers"
  else
    evidence+=", with no mutation root"
  fi
  evidence+=". Identified as GraphQL by: $why. Answered over $_GQL_PROBE_METHOD"
  evidence+=" with HTTP $_GQL_PROBE_STATUS. The schema itself is deliberately not"
  evidence+=" reproduced here."

  finding_new
  finding_set check_id DAST-GQL-INTROSPECTION-01
  finding_set module dast
  finding_set title 'GraphQL introspection is enabled and returns the full schema'
  finding_set base_severity medium
  finding_set confidence high
  finding_set cwe CWE-200
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  # loc_target is what populates corr_target, and corr_target is the whole of
  # this finding's contract with the derived layer.  See this section's header.
  finding_set loc_target "$target"
  finding_set loc_method "${_GQL_PROBE_METHOD:-POST}"
  finding_set loc_path_template "$(path_template_of "$path")"
  # The introspection document travels as the `query` member of the request
  # body, so that is honestly where the issue lives.  With path_template these
  # are what keep this to one finding per GraphQL endpoint rather than one per
  # run - the DAST fingerprint profile is
  # (target, method, path_template, param_location, param_name).
  finding_set loc_param_location body
  finding_set loc_param_name query
  finding_set remediation 'Disable introspection on production deployments - every
  GraphQL server implementation has a switch for it, and a managed GraphQL service
  gates it through the API authorisation mode. Introspection is a development
  affordance: it hands a caller a complete map of every type, field, argument and
  mutation, which is the reconnaissance step that precedes targeted field-level
  abuse. Disabling it is not access control on its own - pair it with per-field
  authorisation and query depth and complexity limits, because a caller who
  already has the schema is unaffected by hiding it. Keep it enabled in
  development and staging, where the tooling that needs it lives.'
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
