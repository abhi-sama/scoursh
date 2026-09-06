#!/usr/bin/env bash
# tests/e2e/dast-import-target.sh - IMPORT-08: proof that an IMPORTED
# parameter (OpenAPI requestBody, and a HAR JSON body) reaches a real
# injection probe, against the REAL local DAST test target: the pinned OWASP
# Juice Shop container tools/dast-test-target.sh manages, authorized by
# tools/dast-test-target/scope.conf and
# docs/DAST-TEST-TARGET-AUTHORIZATION.md.
#
# NOT part of tests/run-tests.sh's default suite list, for the same reason
# tests/e2e/dast-crawl-target.sh and tests/e2e/dast-auth-live.sh are not: it
# needs Docker and a real network to pull an image.  Run it by hand:
#
#     bash tests/e2e/dast-import-target.sh
#
# WHY THIS PROOF NEEDS A REAL TARGET, NOT A STUB.  Every unit suite
# (tests/suites/dast-crawl.sh, tests/suites/dast-inject-engine.sh) proves the
# JSON-body model against a stubbed transport - that the ENGINE composes a
# correct document.  What none of them can prove is that a JSON-body
# parameter discovered from an OpenAPI `requestBody` or a HAR `postData.text`
# actually reaches a live socket, on a target whose own real API surface is
# invisible to a static crawl (docs/DESIGN.md §7.5's SPA gap, made concrete:
# Juice Shop is an Angular application whose entire B2B order-creation
# surface is `POST /b2b/v2/orders` with an EMPTY `parameters: []` - the
# report's own §1a/§1b reproduction). This file is that missing proof.
#
# THE OPENAPI FIXTURE BELOW IS JUICE SHOP'S OWN REAL SCHEMA, NOT INVENTED.
# It was extracted from this pinned image (bkimminich/juice-shop:v20.1.1) by
# fetching its live `/api-docs/swagger-ui-init.js` and parsing the embedded
# `swaggerDoc` object - the exact document Juice Shop's own Swagger UI
# renders - then committing the `/orders` path and its `Order`/`OrderLine`/
# `OrderLines`/`OrderLinesData` schemas verbatim as a static fixture here,
# the same way tests/e2e/dast-crawl-target.sh's own section D generates a
# spec fixture rather than depending on one arriving over the network at test
# time (a spec is target-specific input, docs/DESIGN.md §1, and pinning it
# here means this file exercises the real schema without an extra runtime
# JS-parsing step of its own). Re-extract it by hand if the pinned image
# version ever changes: `curl -s $DTT_URL/api-docs/swagger-ui-init.js`.
#
# HOW THE OUTGOING JSON BODY IS OBSERVED.  `lib/http.sh`'s own header (section
# 9a) states the request body is deliberately withheld from an EXTERNAL
# transport script - "an external transport gets the sinks and never the
# request context" - because it may carry a credential (tension 9). That is
# exactly right for a subprocess, and exactly why the observing transport
# used by tests/e2e/dast-crawl-target.sh (a separate script file) can log
# METHOD/HOST/PATH but never a request BODY. This file instead injects a
# TRANSPORT FUNCTION (not a script) into the `scan.sh` subprocess's own
# environment via bash's `BASH_ENV` (sourced by a non-interactive bash before
# it runs the named script - verified directly against this bash before
# relying on it), so the observer is a function running inside the very same
# process `http_request` runs in - the one place `_HTTP_TX_BODY` is ever
# populated - and reads it exactly as `_http_transport_default` itself does,
# with no fork and no boundary crossed. It then delegates to
# `_http_transport_default "$@"` unchanged, so every request is still real.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes URL, JSON and shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"

require_cmd docker

# `_e2e_any_substring HAYSTACK SUB...` - prints `true`/`false` for
# `assert_true`, since which discovered body parameter a given technique
# happens to be "under test" against at any one request is not something this
# file predicts exactly - only that ONE of a known, small set of payload
# shapes must appear somewhere in the log.
_e2e_any_substring() {
  local haystack=$1 s
  shift
  for s in "$@"; do
    if [[ $haystack == *"$s"* ]]; then
      printf 'true'
      return 0
    fi
  done
  printf 'false'
}

W=$SCOURSH_SCRATCH/dast-import-target
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh strips $SCOURSH_INSTALL_ROOT as a
# literal prefix from each loaded rule file's realpath, so a fixture root reached
# through macOS's /var -> /private/var $TMPDIR symlink would make the strip fail
# and fire a spurious E081 (tests/suites/dast-crawl.sh carries the identical note).
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
printf -- '-- the target starts and serves --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-target.sh start exits 0'
if bash "$ROOT/tools/dast-test-target.sh" start >"$W/start.out" 2>&1; then
  _t_ok 'target start succeeded'
else
  cat "$W/start.out" >&2
  _t_no 'target start succeeded' 'see stderr above'
fi

# A fixture install root: the real tree's code, and the AUTHORIZED scope file
# as its config/scope.conf - the same pattern tests/suites/dast-crawl.sh uses
# for its own real `scan.sh dast` subprocess.  The repository ships no
# config/scope.conf at all (DAST-35), so a run has to be given one, and the
# one given here is the only file in this tree authorized to name a live
# host.  `cp -RL` (COPY, dereferencing symlinks), never `ln -sfn`: a
# symlinked `modules/` resolves, under `checks_registry_load`'s own realpath
# canonicalisation, back to this REPOSITORY's real path rather than one
# under `$FIX` - which is outside every prefix of the §9.5.1 owning-module
# map and fires a spurious E081 on `modules/dast/active/checks.rules`,
# aborting the run before a single request is sent. Reproduced directly: the
# `--intensity active` this file needs (unlike tests/e2e/dast-crawl-target.sh,
# which never reaches past `passive`) is exactly what makes E081 fire, since
# only an active-tier run loads `modules/dast/active/checks.rules` at all.
FIX=$W/root
mkdir -p "$FIX/config"
for e in lib modules rules data tools VERSION scan.sh; do
  [[ -e $ROOT/$e ]] && cp -RL "$ROOT/$e" "$FIX/$e"
done
cp "$ROOT/tools/dast-test-target/scope.conf" "$FIX/config/scope.conf"

# ---------------------------------------------------------------------------
# The observing TRANSPORT FUNCTION, injected via BASH_ENV rather than shipped
# as a separate script - see this file's own header for why.  It logs
# METHOD, HOST, PATH and the real outgoing BODY (`_HTTP_TX_BODY`, populated by
# lib/http.sh immediately before this is called), one request per line
# separated by US (0x1f) so a body containing a literal tab or newline can
# never be misread as a later field - the same DAST-11 lesson every other
# multi-field stream in this tree already applies.  It then delegates to
# `_http_transport_default "$@"` UNCHANGED, so what is measured is the real
# request and the log is a faithful record of what was actually sent.
# ---------------------------------------------------------------------------
REQLOG=$W/requests.log
cat >"$W/transport-env.sh" <<TEOF
_e2e_import_observe() {
  printf '%s\x1f%s\x1f%s\x1f%s\n' "\$1" "\$3" "\$5" "\$_HTTP_TX_BODY" >>"$REQLOG"
  _http_transport_default "\$@"
}
TEOF

# ---------------------------------------------------------------------------
# Juice Shop's OWN OpenAPI document, extracted from the running v20.1.1
# image's `/api-docs/swagger-ui-init.js` - see this file's own header.  Only
# what IMPORT-03 reads is kept: the one `/orders` path plus the schemas its
# `requestBody` $refs transitively.  `servers[].url` is `/b2b/v2` on THIS real
# document too, so this fixture is also a live re-confirmation of §4a's
# host-discard property (there is no host to adopt here - only a path prefix
# - but a future document that added one would still be caught by section C
# below).
# ---------------------------------------------------------------------------
cat >"$W/juiceshop-openapi.json" <<'EOF'
{
  "openapi": "3.0.0",
  "servers": [{"url": "/b2b/v2"}],
  "info": {"version": "2.0.0", "title": "NextGen B2B API"},
  "paths": {
    "/orders": {
      "post": {
        "operationId": "createCustomerOrder",
        "requestBody": {
          "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Order"}}
          },
          "description": "Customer order to be placed"
        },
        "responses": {"200": {"description": "ok"}}
      }
    }
  },
  "components": {
    "schemas": {
      "Order": {
        "required": ["cid"],
        "properties": {
          "cid": {"type": "string", "example": "JS0815DE"},
          "orderLines": {"$ref": "#/components/schemas/OrderLines"},
          "orderLinesData": {"$ref": "#/components/schemas/OrderLinesData"}
        }
      },
      "OrderLine": {
        "required": ["productId", "quantity"],
        "properties": {
          "productId": {"type": "integer", "example": 8},
          "quantity": {"type": "integer", "example": 500},
          "customerReference": {"type": "string", "example": "PO0000001"}
        }
      },
      "OrderLines": {
        "type": "array",
        "items": {"$ref": "#/components/schemas/OrderLine"}
      },
      "OrderLinesData": {
        "type": "string",
        "example": "[{\"productId\": 12,\"quantity\": 10000}]"
      }
    }
  }
}
EOF

# `_import_run RUNDIR [ARGS...]` - one real `scan.sh dast` subprocess against
# the live target, with the observing transport FUNCTION bound via BASH_ENV.
# `--intensity active` is required for the tier-4 injection phases
# (`active/sqli.sh:active` etc., modules/dast/engine.sh's phase table) to run
# at all, and that ceiling itself requires `--i-own-target`
# (docs/STEP5-DAST-PLAN.md DAST-32).
#
# `unset SCOURSH_SCRATCH` in the subshell that execs scan.sh, and ONLY there:
# this file's own top-level `source lib/http.sh` already ran `lib/core.sh`'s
# file-scope `scratch_init` (line ~1271 of that file) once, in THIS process,
# which both creates AND EXPORTS a scratch directory - "SCOURSH_SCRATCH is
# exported so workers use the parent's directory" (lib/core.sh's own
# comment), a deliberate property for an `xargs -P` worker. Left alone here it
# has the opposite effect: every one of this file's THREE supposedly
# independent `scan.sh` invocations would inherit and REUSE the identical
# scratch directory, and with it the same rate-limiter/request-budget/
# circuit-breaker state files a single target's requests accumulate into.
# Measured directly: with the export left in place, section B's real POST to
# /b2b/v2/orders never reached the observing transport at all - section A's
# own run had already used the shared scratch dir, and something in that
# accumulated state (most likely the breaker) silently absorbed section B's
# attempts before a transport was ever invoked, while an otherwise-identical
# single-invocation reproduction (no prior run sharing its scratch dir) sent
# and logged every request exactly as composed. `unset` inside the subshell
# leaves this script's OWN `$W`-derived paths (already resolved) untouched
# and gives each of the three invocations its own fresh, unshared scratch
# directory - which is what "three independent scans" is supposed to mean.
_import_run() {
  local rundir=$1
  shift
  : >"$REQLOG"
  _RC=0
  (
    unset SCOURSH_SCRATCH
    BASH_ENV=$W/transport-env.sh \
      SCOURSH_HTTP_TRANSPORT=_e2e_import_observe \
      SCOURSH_INSTALL_ROOT=$FIX \
      exec bash "$ROOT/scan.sh" dast \
        --target dast-test-target --i-own-target dast-test-target \
        --intensity active \
        --out "$rundir" "$@" >"$rundir.log" 2>&1
  ) || _RC=$?
  return 0
}

# ===========================================================================
printf -- '\n-- A. the negative: no spec/HAR supplied, the status quo the report reproduced --\n'
# ===========================================================================
rm -f "$FIX/config/discovery.conf"
t_case 'without any discovery input, the run records the SPA coverage_gap'
_import_run "$W/run-nospec"
if (( _RC != 0 )); then tail -60 "$W/run-nospec.log" >&2; fi
assert_eq 0 "$_RC" 'the run exits 0 against the live target'
RUNJSON0=$(cat "$W/run-nospec/run.json")
assert_contains "$RUNJSON0" 'no_specification_supplied' \
  'the machine-readable SPA gap is recorded - the §1 status quo the scout report reproduced against this same target'
PAR0=$(cat "$W/run-nospec/inventory/parameters.json")
assert_not_contains "$PAR0" '"location": "body"' \
  'and NO body-location parameter exists to inject - FAILS if the static crawler somehow discovered the requestBody-only /orders surface on its own, which would make this whole ticket unnecessary'
assert_not_contains "$(cat "$REQLOG")" '/orders' \
  'and no request was ever sent to /orders - there was nothing to test it with'

# ===========================================================================
printf -- '\n-- B. OpenAPI requestBody: the imported parameter reaches a real probe --\n'
# ===========================================================================
cat >"$FIX/config/discovery.conf" <<EOF
id: dast-test-target
openapi-path: $W/juiceshop-openapi.json
EOF

t_case 'a run with the OpenAPI spec supplied'
_import_run "$W/run-openapi"
if (( _RC != 0 )); then tail -60 "$W/run-openapi.log" >&2; fi
assert_eq 0 "$_RC" 'the run exits 0'
EP1=$(cat "$W/run-openapi/inventory/endpoints.json")
PAR1=$(cat "$W/run-openapi/inventory/parameters.json")
assert_contains "$EP1" '"url": "http://127.0.0.1:3400/b2b/v2/orders"' \
  "the spec's own basePath (/b2b/v2, servers[].url) is joined to the OPERATOR's authorised base-url - the spec names no host of its own here to adopt or refuse"
assert_contains "$EP1" '"request_body_type": "json"' 'and the endpoint is recorded as a JSON body (IMPORT-02/03)'

t_case 'requestBody produced the nested body parameters the static crawl could never see'
assert_contains "$PAR1" '"name": "/cid"' 'the top-level cid field is a body parameter'
assert_contains "$PAR1" '"name": "/orderLines/0/productId"' \
  'and the array-nested productId field is too, as an RFC 6901 pointer - this exact shape (§1a) is what a flat parameters[] parser could never produce'
assert_contains "$PAR1" '"name": "/orderLines/0/quantity"' 'and quantity'
assert_contains "$PAR1" '"name": "/orderLines/0/customerReference"' 'and customerReference'
assert_contains "$PAR1" '"location": "body"' 'all at location=body'
assert_contains "$PAR1" '"source": "openapi"' 'with source=openapi, never rewritten'

t_case 'an injection probe actually SENT a request with a JSON body carrying the payload - asserted on the request log, never a return value'
REQ1=$(cat "$REQLOG")
assert_contains "$REQ1" $'POST\x1f127.0.0.1\x1f/b2b/v2/orders\x1f' \
  'at least one POST to /b2b/v2/orders was logged by the observing transport - FAILS if the endpoint the spec described was never actually requested'
# The sqli error technique appends a bare quote to the parameter's own
# baseline value (modules/dast/payloads/sqli-error-payloads.txt: %B'), and
# every leaf value in a composed JSON body is written through json_string
# (inject_engine.sh section 2a) - so the schema's own example, with a
# trailing quote appended, is exactly what should appear in at least one
# logged body. Checked against ANY of the four body fields' own examples,
# since which parameter is "under test" at any one request rotates.
assert_true "$(_e2e_any_substring "$REQ1" "8'" "JS0815DE'" "500'" "PO0000001'")" \
  'a sqli error-technique payload (baseline example + a trailing quote) appears in a logged /orders request body - FAILS if the JSON-body model never actually reached inject_send, which is exactly the "engine tested in isolation, never proven live" gap this ticket closes'
assert_contains "$REQ1" '"orderLines":[{' \
  'and the body really is the NESTED document IMPORT-02 composes - not a flat form-urlencoded blob'

# ===========================================================================
printf -- '\n-- C. the specification host, if any, is still never adopted --\n'
# ===========================================================================
t_case "the spec's own basePath contributes no host of its own"
assert_not_contains "$EP1" '"host": ""' 'sanity: the endpoint really does carry a resolved host (the operator'"'"'s own)'
assert_contains "$EP1" '"host": "127.0.0.1:3400"' \
  'and it is the AUTHORISED host, never one the spec could have named (§4a) - this spec names no host at all, which is itself the common, safest case'

# ===========================================================================
printf -- '\n-- D. HAR JSON body: the committed fixture, imported against the same live target --\n'
# ===========================================================================
cat >"$FIX/config/discovery.conf" <<EOF
id: dast-test-target
har-path: $ROOT/tests/fixtures/dast-crawl/specs/capture.har
EOF

t_case 'a run with the committed HAR fixture supplied'
_import_run "$W/run-har"
if (( _RC != 0 )); then tail -60 "$W/run-har.log" >&2; fi
assert_eq 0 "$_RC" 'the run exits 0'
PAR2=$(cat "$W/run-har/inventory/parameters.json")
EP2=$(cat "$W/run-har/inventory/endpoints.json")

t_case "the HAR's postData.text JSON body reached parameters.json as RFC 6901 pointers"
assert_contains "$PAR2" '"name": "/email"' 'the register entry'"'"'s top-level email field'
assert_contains "$PAR2" '"name": "/profile/age"' \
  'and its NESTED profile.age field - the shape a flat postData.params reader could never produce (this is what IMPORT-04 added over IMPORT-01'"'"'s day-one HAR support)'
assert_contains "$PAR2" '"source": "har"' 'source=har, never rewritten'
assert_not_contains "$EP2" 'har-declared-host.example.invalid' \
  "the HAR entry's own recorded host is discarded (§4a) - only its PATH (/xhr/register) was reused, re-based onto the operator's own authorised host"
assert_contains "$EP2" '"url": "http://127.0.0.1:3400/xhr/register"' \
  'confirmed: the path was kept, the host was not'

t_case 'the HAR-imported JSON body reached a real probe too, on the SAME live target'
REQ2=$(cat "$REQLOG")
assert_contains "$REQ2" $'POST\x1f127.0.0.1\x1f/xhr/register\x1f' \
  'at least one POST to the HAR-derived path was logged - the endpoint does not exist on the real server (a 404 is expected and irrelevant), which is exactly why this is asserted on the REQUEST rather than the response'
assert_true "$(_e2e_any_substring "$REQ2" "new@example.invalid'" "hunter2'" "30'")" \
  "a sqli payload built from the HAR's own captured example values appears in a logged request body"

t_summary dast-import-target
