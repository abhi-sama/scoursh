#!/usr/bin/env bash
# tests/suites/cloud-apigw.sh - modules/cloud/aws/live/apigw.sh: the §8.4 API
# Gateway read-only checks AND the write side of the cross-module endpoint
# inventory (docs/STEP6-CLOUD-PLAN.md CLOUD-22).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently:
#
#   1. BOTH DIRECTIONS, IN ONE RUN.  An open route, a key-only route and a
#      properly-authorized route are examined by the SAME scan, so "the check
#      fires" and "the check stays quiet" are asserted against one code path.
#   2. `OPTIONS` IS NEVER FLAGGED, EVEN THOUGH IT CARRIES `authorizationType:
#      NONE` IN THE FIXTURE - the CORS-preflight false-positive apigw_engine.sh's
#      own header records.
#   3. A METHOD'S EMBEDDED `methodIntegration.httpMethod` (a Lambda-proxy
#      integration is always `POST`) IS NEVER MISTAKEN FOR A SECOND VERB.
#      Every fixture method below carries one, deliberately, because this is
#      exactly the shape that broke a naive "glob every httpMethod leaf"
#      reading during development.
#   4. EVERY FINDING CITES AN EXECUTE-API ARN, REGION AND ACCOUNT, AND CARRIES
#      NO `cis` VALUE (CIS v3.0.0 has no API Gateway section).
#   5. A DENIED `get-resources` IS A `coverage_reduction`, NEVER SILENCE, and a
#      REST API with a denied `get-stages` still has its methods examined -
#      the two calls fail independently.
#   6. THE ENDPOINT INVENTORY IS WRITTEN in the frozen
#      `scoursh.inventory.endpoints/1` shape, ONE ROW PER (VERB, STAGE), an
#      OPTIONS-carrying resource contributes no OPTIONS row, and a PRE-EXISTING
#      `inventory/endpoints.json` (as if SAST route extraction had already run)
#      is MERGED rather than overwritten.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-apigw/.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a stub root cannot leak into the next case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/cloud/aws/live/apigw_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, which drags in
# modules/sast/engine.sh plus the whole lib/ hub chain - the identical cut
# tests/suites/cloud-s3.sh's own header records for the identical reason.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/apigw_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-apigw
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath, so a fixture root reached through
# macOS's /var -> /private/var $TMPDIR symlink would fail E070 for a reason
# that has nothing to do with the file (tests/suites/cloud.sh and
# tests/suites/cloud-s3.sh both document the same fact).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-apigw
OPEN_API=apiopen1
GOOD_API=apigood1
DENY_API=apideny1

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from.
_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add apigateway get-api-keys "$FIX/get-api-keys.json"
  aws_fixture_route_add apigateway get-rest-apis "$FIX/get-rest-apis.json"

  aws_fixture_route_add_for apigateway get-stages "$OPEN_API" "$FIX/get-stages.open.json"
  aws_fixture_route_add_for apigateway get-stages "$GOOD_API" "$FIX/get-stages.good.json"
  aws_fixture_route_add_for apigateway get-stages "$DENY_API" "$FIX/get-stages.denied.err"

  aws_fixture_route_add_for apigateway get-resources "$OPEN_API" "$FIX/get-resources.open.json"
  aws_fixture_route_add_for apigateway get-resources "$GOOD_API" "$FIX/get-resources.good.json"
  aws_fixture_route_add_for apigateway get-resources "$DENY_API" "$FIX/get-resources.denied.err"
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess.
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR`, per
# tests/suites/cloud-s3.sh's own documented reason: two cases calling the same
# operation with a different fixture behind it must not share a cache key.
_run_cloud() {
  local out=$1
  shift
  _RC=0
  rm -rf "$out"
  PATH="$W/bin:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") \
    bash "$ROOT/scan.sh" cloud --live "$@" --out "$out" >"$out.log" 2>&1 || _RC=$?
  return 0
}

# `_run_cloud_seeded OUT SEED_FILE [ARGS...]` - the identical shape, EXCEPT the
# `rm -rf "$out"` runs FIRST and the pre-existing `inventory/endpoints.json`
# (SEED_FILE's content) is written AFTER it, immediately before the scan
# starts. `_run_cloud` alone cannot express "seed a file inside the run
# directory, then scan it": its own `rm -rf "$out"` would delete a file a
# caller wrote before calling it, which is exactly the trap section F's first
# draft fell into.
_run_cloud_seeded() {
  local out=$1 seed=$2
  shift 2
  _RC=0
  rm -rf "$out"
  mkdir -p "$out/inventory"
  cp -- "$seed" "$out/inventory/endpoints.json"
  PATH="$W/bin:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") \
    bash "$ROOT/scan.sh" cloud --live "$@" --out "$out" >"$out.log" 2>&1 || _RC=$?
  return 0
}

_json() {
  python3 - "$1" "$2" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cur = doc
for part in sys.argv[2].split('.'):
    if part.isdigit() and isinstance(cur, list):
        cur = cur[int(part)]
    else:
        cur = cur.get(part) if isinstance(cur, dict) else None
    if cur is None:
        break
print('' if cur is None else (json.dumps(cur, separators=(',', ':')) if isinstance(cur, (list, dict)) else cur))
PY
}

# One `check_id<TAB>loc_resource_key<TAB>loc_region<TAB>cell<TAB>cis<TAB>account_id` line
# per finding, read from findings.jsonl.
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print('\t'.join([
        f.get('check_id', ''),
        loc.get('resource_key', '') or '',
        loc.get('region', '') or '',
        f.get('cell') or '',
        ','.join(f.get('cis') or []),
        loc.get('account_id', '') or '',
    ]))
PY
}

_row_for() {
  local table=$1 check=$2 arn_substr=$3
  printf '%s\n' "$table" | awk -F'\t' -v c="$check" -v a="$arn_substr" '$1 == c && index($2, a) { print; exit }'
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

apigw_doc_load "$FIX/get-resources.open.json"
_m=''
apigw_resource_methods_set _m 1
assert_eq 'GET OPTIONS' "$_m" 'A1 the public resource carries GET and OPTIONS, sorted LC_ALL=C, and no phantom third verb from methodIntegration.httpMethod'
_m=''
apigw_resource_methods_set _m 2
assert_eq 'POST' "$_m" 'A2 the keyed resource carries POST alone'
_m=''
apigw_resource_methods_set _m 0
assert_eq '' "$_m" 'A3 the root resource, whose resourceMethods is an empty object, carries no verb at all'

_at=''
apigw_method_authtype_set _at 1 GET
assert_eq 'NONE' "$_at" 'A4 GET on the public resource has authorizationType NONE'
_at=''
apigw_method_authtype_set _at 1 OPTIONS
assert_eq 'NONE' "$_at" 'A5 OPTIONS also reads NONE off the fixture - the exclusion is apigw.sh policy, not a classifier fact'

assert_true "$(apigw_method_apikey_required 1 GET && echo 1 || echo 0)" 'A6 the public GET does not require an API key'
assert_true "$(apigw_method_apikey_required 2 POST && echo 0 || echo 1)" 'A7 the keyed POST DOES require one'

apigw_doc_load "$FIX/get-resources.good.json"
_at=''
apigw_method_authtype_set _at 1 GET
assert_eq 'AWS_IAM' "$_at" 'A8 the secure resource is gated by AWS_IAM'
assert_true "$(apigw_method_is_open AWS_IAM && echo 1 || echo 0)" 'A9 AWS_IAM is not "open"'
assert_true "$(apigw_method_is_open NONE && echo 0 || echo 1)" 'A10 NONE is'

assert_eq 'aws' "$(apigw_partition_of 'arn:aws:iam::123456789012:user/x')" 'A11 partition: commercial'
assert_eq 'aws-us-gov' "$(apigw_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A12 partition: GovCloud'
assert_eq 'aws' "$(apigw_partition_of '')" 'A13 partition: an unresolved caller ARN falls back to aws'

assert_eq 'arn:aws:execute-api:eu-west-2:123456789012:apiopen1/*/GET/public' \
  "$(apigw_method_arn aws eu-west-2 123456789012 apiopen1 GET /public)" \
  'A14 the method ARN carries a wildcard stage, per AWS own IAM-policy convention'
assert_eq 'arn:aws:execute-api:eu-west-2:123456789012:apiopen1/*/GET/pets/{petId}' \
  "$(apigw_method_arn aws eu-west-2 123456789012 apiopen1 GET '/pets/{petId}')" \
  'A15 a nested path keeps its internal slash and loses only the ARN-format leading one'

# ===========================================================================
# B. One scan, three APIs: fires on the open and key-only routes, quiet on
#    the properly-authorized one, in the SAME run.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
OPEN_IDS=$(printf '%s\n' "$TBL" | awk -F'\t' -v a="$OPEN_API" '{ if (index($2, a)) print $1 }' | LC_ALL=C sort -u)
GOOD_IDS=$(printf '%s\n' "$TBL" | awk -F'\t' -v a="$GOOD_API" '{ if (index($2, a)) print $1 }' | LC_ALL=C sort -u)

assert_contains "$OPEN_IDS" 'CLOUD-APIGW-OPEN_AUTH_ROUTE-01' 'B3 the fully-open GET /public is reported by OPEN_AUTH_ROUTE'
assert_contains "$OPEN_IDS" 'CLOUD-APIGW-OPEN_AUTH_KEY_ONLY-01' 'B4 the key-only POST /keyed is reported by OPEN_AUTH_KEY_ONLY, in the SAME run'
assert_not_contains "$(_row_for "$TBL" CLOUD-APIGW-OPEN_AUTH_ROUTE-01 "$OPEN_API/*/OPTIONS")" . \
  'B5 OPTIONS on /public is never flagged, even though its own authorizationType is NONE in the fixture'

# ... and the properly-authorized API in the SAME run produces no finding at
# all.  This is the half a pack gone inert would also pass, which is why B3/B4
# are asserted from the same run: only both together distinguish "classifies
# correctly" from "never fires".
assert_eq '' "$GOOD_IDS" 'B6 the AWS_IAM-gated /secure route in the SAME run produces no finding'

# ===========================================================================
# C. Finding citation: ARN, region, account, and no invented CIS value.
# ===========================================================================
t_case 'C. finding citation'

_open_row=$(_row_for "$TBL" CLOUD-APIGW-OPEN_AUTH_ROUTE-01 "$OPEN_API")
# `awk -F'\t'`, NEVER `IFS=$'\t' read`: this row's own `cis` field is
# EMPTY (C5's whole point), and bash's `read` treats tab as an IFS-*whitespace*
# character regardless of what else IFS holds, so it COLLAPSES the resulting
# run of adjacent tabs into one delimiter and shifts every field after the
# empty one left by one - the identical DAST-11 lesson AGENTS.md records,
# reproduced here rather than avoided, and caught only because C2/C5 assert
# the empty-cis case directly rather than a row that happens to have every
# field populated. `tests/suites/cloud-s3.sh` avoids the same trap by reading
# its own empty-`cis` rows through `awk` rather than `read`, for this exact
# reason.
_c_arn=$(printf '%s\n' "$_open_row" | awk -F'\t' '{print $2}')
_c_region=$(printf '%s\n' "$_open_row" | awk -F'\t' '{print $3}')
_c_cell=$(printf '%s\n' "$_open_row" | awk -F'\t' '{print $4}')
_c_cis=$(printf '%s\n' "$_open_row" | awk -F'\t' '{print $5}')
_c_account=$(printf '%s\n' "$_open_row" | awk -F'\t' '{print $6}')

assert_eq "arn:aws:execute-api:eu-west-2:123456789012:$OPEN_API/*/GET/public" "$_c_arn" \
  'C1 the finding cites the execute-api method ARN with the wildcard stage'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region this pass actually ran in'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell is <account>/<region> - CLOUD is the one module whose cell IS the finding-s own region, unlike S3-s global pass'
assert_eq '' "$_c_cis" 'C5 no cis value is invented - CIS v3.0.0 has no API Gateway section'

_keyonly_row=$(_row_for "$TBL" CLOUD-APIGW-OPEN_AUTH_KEY_ONLY-01 "$OPEN_API")
assert_contains "$_keyonly_row" "$OPEN_API/*/POST/keyed" 'C6 the key-only finding cites its own resource-s ARN'

# ===========================================================================
# D. Honesty: a denied get-resources is a reduction; get-stages fails
#    independently of get-resources.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-APIGW-OPEN_AUTH_ROUTE-01' \
  'D1 a check that answered for at least one method is in checks_run'
assert_contains "$REDUCTIONS" 'operation=get-resources' 'D2 the denied get-resources on the third API is a coverage_reduction'
assert_contains "$REDUCTIONS" "api=$DENY_API" 'D3 ... naming the denied API'
assert_not_contains "$TBL" "$DENY_API" 'D4 no finding is invented for an API whose resources were never read'

assert_contains "$REDUCTIONS" 'operation=get-stages' \
  'D5 the denied get-stages on the same API is its OWN, separate reduction (D2/D3 already pin the get-resources one) - one call failing never swallows the other'

# The whole REST API list unreadable: nothing examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add apigateway get-api-keys "$FIX/get-api-keys.json"
aws_fixture_route_add apigateway get-rest-apis "$FIX/get-rest-apis.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-APIGW-' 'D6 a denied get-rest-apis credits no apigw check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'REST API list' \
  'D7 ... and the coverage_gap says the REST API list could not be read'

# A REST API with zero methods on any resource is a REAL answer (vacuous),
# never a loss - proven with a narrower route table carrying only the good
# (single, AWS_IAM-gated) API.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add apigateway get-api-keys "$FIX/get-api-keys.json"
aws_fixture_route_add apigateway get-rest-apis "$FIX/get-rest-apis.json"
aws_fixture_route_add_for apigateway get-stages "$OPEN_API" "$FIX/get-stages.open.json"
aws_fixture_route_add_for apigateway get-stages "$GOOD_API" "$FIX/get-stages.good.json"
aws_fixture_route_add_for apigateway get-stages "$DENY_API" "$FIX/get-stages.denied.err"
aws_fixture_route_add_for apigateway get-resources "$OPEN_API" "$FIX/get-resources.good.json"
aws_fixture_route_add_for apigateway get-resources "$GOOD_API" "$FIX/get-resources.good.json"
aws_fixture_route_add_for apigateway get-resources "$DENY_API" "$FIX/get-resources.denied.err"
_run_cloud "$W/run-narrow"
assert_eq '0' "$_RC" 'D8 a run whose only two readable APIs both use AWS_IAM exits 0 with no apigw finding'
assert_not_contains "$(cat "$W/run-narrow/findings.jsonl" 2>/dev/null)" 'CLOUD-APIGW-OPEN_AUTH' \
  'D9 ... and reports neither open-auth check'
assert_contains "$(_json "$W/run-narrow/run.json" checks_run)" 'CLOUD-APIGW-OPEN_AUTH_ROUTE-01' \
  'D10 ... while still crediting the check as covered (it answered NONE for every method it saw)'

# ===========================================================================
# E. get-stages failing does not stop the auth check from running.
# ===========================================================================
t_case 'E. independent failures'

aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add apigateway get-api-keys "$FIX/get-api-keys.json"
aws_fixture_route_add apigateway get-rest-apis "$FIX/get-rest-apis.json"
aws_fixture_route_add_for apigateway get-stages "$OPEN_API" "$FIX/get-stages.denied.err"
aws_fixture_route_add_for apigateway get-stages "$GOOD_API" "$FIX/get-stages.good.json"
aws_fixture_route_add_for apigateway get-stages "$DENY_API" "$FIX/get-stages.denied.err"
aws_fixture_route_add_for apigateway get-resources "$OPEN_API" "$FIX/get-resources.open.json"
aws_fixture_route_add_for apigateway get-resources "$GOOD_API" "$FIX/get-resources.good.json"
aws_fixture_route_add_for apigateway get-resources "$DENY_API" "$FIX/get-resources.denied.err"
_run_cloud "$W/run-e"
assert_eq '0' "$_RC" 'E1 exits 0'
E_TBL=$(_findings_table "$W/run-e/findings.jsonl")
assert_contains "$(printf '%s\n' "$E_TBL" | awk -F'\t' '{print $1}')" 'CLOUD-APIGW-OPEN_AUTH_ROUTE-01' \
  'E2 the open API-s auth finding still fires even though ITS OWN get-stages call was denied'
E_INV=$(cat "$W/run-e/inventory/endpoints.json")
assert_not_contains "$E_INV" "$OPEN_API.execute-api" \
  'E3 ... but none of its routes reach the endpoint inventory, since none has a resolvable stage'

# ===========================================================================
# F. The endpoint inventory: shape, one row per (verb, stage), and merge with
#    a pre-existing file rather than overwrite.
# ===========================================================================
t_case 'F. endpoint inventory'

_routes_default
SEED=$W/seed-endpoints.json
cat >"$SEED" <<'JSON'
{
  "schema": "scoursh.inventory.endpoints/1",
  "run_id": "prior-run",
  "generated_by": "modules/sast/route_extraction.sh",
  "endpoints": [
    {"id": "sastroute01", "target": "", "method": "GET", "url": "https://internal.example/admin", "host": "internal.example", "path": "/admin", "source": "imported", "depth": 0, "status": "", "content_type": ""}
  ]
}
JSON
# `_run_cloud_seeded`, NEVER `_run_cloud` here: `_run_cloud`'s own `rm -rf
# "$out"` would delete a pre-existing inventory/endpoints.json written before
# it runs - the trap this case's first draft fell into, which silently turned
# "merge with what SAST already wrote" into "there was never anything to
# merge" (F4 failed under that reading, with the merged SAST route simply
# absent).
_run_cloud_seeded "$W/run-f" "$SEED"
assert_eq '0' "$_RC" 'F1 exits 0'
INV=$W/run-f/inventory/endpoints.json
assert_file_exists "$INV" 'F2 endpoints.json exists after the run'
assert_eq 'scoursh.inventory.endpoints/1' "$(_json "$INV" schema)" 'F3 the schema string is the frozen one'

assert_contains "$(cat "$INV")" 'internal.example/admin' \
  'F4 a route SAST already wrote is MERGED, never overwritten'
assert_contains "$(cat "$INV")" "https://$OPEN_API.execute-api.eu-west-2.amazonaws.com/prod/public" \
  'F5 the open API-s single stage produces a real, requestable invoke URL'
assert_contains "$(cat "$INV")" "https://$GOOD_API.execute-api.eu-west-2.amazonaws.com/prod/secure" \
  'F6 the good API-s route is present under its prod stage'
assert_contains "$(cat "$INV")" "https://$GOOD_API.execute-api.eu-west-2.amazonaws.com/dev/secure" \
  'F7 ... AND under its dev stage - one row per stage, not one row per API'
assert_contains "$(cat "$INV")" "https://$OPEN_API.execute-api.eu-west-2.amazonaws.com/prod/keyed" \
  'F7b the key-only route is a candidate for DAST too, whatever its own authorization looks like'
NEP=$(python3 - "$INV" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
print(len(doc['endpoints']))
PY
)
assert_eq '5' "$NEP" \
  'F8 exactly five endpoints total: the one merged SAST route, GET /public (one stage), POST /keyed (one stage), and GET /secure under BOTH of its two stages'
assert_not_contains "$(cat "$INV")" '"method": "OPTIONS"' 'F9 OPTIONS never reaches the inventory either - only a method the auth check itself considered'

t_summary cloud-apigw
