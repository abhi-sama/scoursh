#!/usr/bin/env bash
# tests/suites/cloud-dynamodb.sh - modules/cloud/aws/live/dynamodb.sh: the
# §8.1 DynamoDB read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-16).
#
# What this suite exists to pin, mirroring tests/suites/cloud-s3.sh's and
# tests/suites/cloud-rds.sh's own reasoning (see those files' headers for the
# full argument each point makes):
#
#   1. BOTH DIRECTIONS, IN ONE RUN - an unencrypted/backup-less table and a
#      hardened one are examined by the SAME scan; a default-policy VPC
#      endpoint and a Condition-narrowed one are examined by the SAME call.
#   2. EVERY FINDING CITES ARN, REGION AND ACCOUNT. NONE CARRIES A CIS VALUE
#      - CIS v3.0.0 has no DynamoDB section at all (checks-dynamodb.rules's
#      own header), an honest absence rather than a gap.
#   3. THE CELL IS `<account>/<region>`, THE SAME REGION THE FINDING CITES -
#      `dynamodb` is a REGIONAL service, the ordinary case tension 12 is
#      built around.
#   4. A DENIED CALL IS A coverage_reduction, NEVER SILENCE - at the list
#      level (the whole table list, the whole endpoint list) and the
#      per-resource level (one table's own encryption/backup properties).
#   5. THE FINDING ROUND-TRIPS - into findings.jsonl, into a real
#      account-region coverage cell, and into every report format.
#
# PLUS THIS SERVICE'S OWN TRUNCATION SHARP EDGE: `list-tables` paginates with
# `LastEvaluatedTableName`, which lib/awscli.sh's shared truncation detector
# does not recognise (dynamodb_engine.sh's own header) - section F proves
# this file's own detection catches what the shared one would miss.
#
# NO NETWORK AND NO AWS ACCOUNT. Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-dynamodb/.
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
# -x back-edge cut: see tests/suites/cloud-s3.sh's own identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/dynamodb_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-dynamodb
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: see tests/suites/cloud-s3.sh's own identical macOS
# /var -> /private/var $TMPDIR note.
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-dynamodb
PUB=scoursh-fixture-public-table
HARD=scoursh-fixture-hardened-table
DENY=scoursh-fixture-denied-table
PUB_ARN="arn:aws:dynamodb:eu-west-2:123456789012:table/$PUB"
HARD_ARN="arn:aws:dynamodb:eu-west-2:123456789012:table/$HARD"
DEFAULT_VPCE_ARN=arn:aws:ec2:eu-west-2:123456789012:vpc-endpoint/vpce-scoursh-fixture-default
NARROWED_VPCE_ARN=arn:aws:ec2:eu-west-2:123456789012:vpc-endpoint/vpce-scoursh-fixture-narrowed

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from. An
# optional argument names ONE operation whose default fixture is swapped for
# an alternate - the identical `swap_op`/`swap_path` shape
# tests/suites/cloud-rds.sh's own `_routes_default` uses.
_routes_default() {
  local swap_op=${1:-} swap_path=${2:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  # `s3` and `rds` (CLOUD-05/CLOUD-15) are `_CLOUD_SERVICES` peers that run in
  # the SAME `scan.sh cloud --live` invocation this suite drives - see
  # tests/suites/cloud-rds.sh's own identical note on why an empty response
  # for each keeps their passes clean, silent no-ops rather than "no route
  # registered" noise this suite has no reason to route around.
  aws_fixture_route_add s3api list-buckets "$FIX/list-buckets.empty.json"
  aws_fixture_route_add rds describe-db-instances "$FIX/describe-db-instances.empty.json"
  aws_fixture_route_add rds describe-db-snapshots "$FIX/describe-db-snapshots.empty.json"

  if [[ $swap_op == describe-vpc-endpoints ]]; then
    aws_fixture_route_add ec2 describe-vpc-endpoints "$swap_path"
  else
    aws_fixture_route_add ec2 describe-vpc-endpoints "$FIX/describe-vpc-endpoints.json"
  fi

  if [[ $swap_op == list-tables ]]; then
    aws_fixture_route_add dynamodb list-tables "$swap_path"
  else
    aws_fixture_route_add dynamodb list-tables "$FIX/list-tables.json"
  fi

  aws_fixture_route_add_for dynamodb describe-table "$PUB"  "$FIX/describe-table.public.json"
  aws_fixture_route_add_for dynamodb describe-table "$HARD" "$FIX/describe-table.hardened.json"
  aws_fixture_route_add_for dynamodb describe-table "$DENY" "$FIX/describe-table.denied.err"

  aws_fixture_route_add_for dynamodb describe-continuous-backups "$PUB"  "$FIX/describe-continuous-backups.public.json"
  aws_fixture_route_add_for dynamodb describe-continuous-backups "$HARD" "$FIX/describe-continuous-backups.hardened.json"
  aws_fixture_route_add_for dynamodb describe-continuous-backups "$DENY" "$FIX/describe-continuous-backups.denied.err"
}

# `_run_cloud OUT [ARGS...]` - byte-identical reasoning to
# tests/suites/cloud-rds.sh's own `_run_cloud`.
_run_cloud() {
  local out=$1
  shift
  _RC=0
  rm -rf "$out"
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
        loc.get('sub_key', '') or '',
    ]))
PY
}

_ids_for_resource() {
  local table=$1 key=$2
  printf '%s\n' "$table" | awk -F'\t' -v k="$key" '$2 == k { print $1 }' | LC_ALL=C sort
}

# `_row_col ROW N` - the Nth tab-separated field of ROW via `awk -F`, never
# `IFS=$'\t' read` - see tests/suites/cloud-rds.sh's own identical note on
# why bash `read` silently drops an empty middle field under a tab IFS.
_row_col() {
  awk -F'\t' -v n="$2" '{print $n}' <<<"$1"
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

ddb_doc_load "$FIX/list-tables.json"
assert_eq "$PUB" "${_DDB_DOC[$(ddb_path TableNames 0)]:-}" 'A1 list-tables: the first table name is read'
assert_true "$(ddb_doc_has "$(ddb_path TableNames 2)" && echo 0 || echo 1)" \
  'A2 the third table is present (the walk does not stop early)'
assert_true "$(ddb_doc_has "$(ddb_path TableNames 3)" && echo 1 || echo 0)" \
  'A3 there is no fourth table (the walk has a real end)'

# The truncation sharp edge this file's header names: `LastEvaluatedTableName`,
# which `_awscli_detect_truncation`'s frozen vocabulary does not recognise.
# The reading A4/A5 fail under is trusting SCOURSH_AWS_RO_OUTCOME alone, which
# would report this exact fixture as a complete, untruncated list.
ddb_doc_load "$FIX/list-tables.json"
assert_true "$(ddb_last_evaluated_present && echo 1 || echo 0)" \
  'A4 an untruncated response (no LastEvaluatedTableName) is NOT reported as truncated'
ddb_doc_load "$FIX/list-tables.truncated.json"
assert_true "$(ddb_last_evaluated_present && echo 0 || echo 1)" \
  'A5 a response carrying LastEvaluatedTableName IS reported as truncated'

ddb_doc_load "$FIX/describe-table.hardened.json"
assert_true "$(ddb_table_encrypted && echo 0 || echo 1)" 'A6 SSEDescription.Status ENABLED is encrypted'
ddb_doc_load "$FIX/describe-table.public.json"
assert_true "$(ddb_table_encrypted && echo 1 || echo 0)" \
  'A7 no SSEDescription at all is reported as NOT explicitly encrypted (the default-AWS-owned-key case)'

ddb_doc_load "$FIX/describe-continuous-backups.hardened.json"
assert_true "$(ddb_pitr_enabled && echo 0 || echo 1)" 'A8 PointInTimeRecoveryStatus ENABLED is a pass'
ddb_doc_load "$FIX/describe-continuous-backups.public.json"
assert_true "$(ddb_pitr_enabled && echo 1 || echo 0)" 'A9 PointInTimeRecoveryStatus DISABLED is not'

# The VPC-endpoint-policy text-shape classifier. The reading A11 fails under
# is Principal="*" alone (no Action check), which would flag a policy that
# narrows only the action list; the reading A12 fails under is ignoring
# `Condition` entirely, which would flag a deliberately-narrowed policy that
# still happens to carry wildcard Principal/Action text.
_default_policy='{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}'
_narrowed_policy='{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"dynamodb:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-x"}}}]}'
_action_only_policy='{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"dynamodb:GetItem","Resource":"*"}]}'
assert_true "$(ddb_vpce_policy_is_default_full_access "$_default_policy" && echo 0 || echo 1)" \
  'A10 the exact AWS default (Principal "*", Action "*", no Condition) IS flagged'
assert_true "$(ddb_vpce_policy_is_default_full_access "$_narrowed_policy" && echo 1 || echo 0)" \
  'A11 a Condition-narrowed policy is NOT flagged, even carrying Principal "*"'
assert_true "$(ddb_vpce_policy_is_default_full_access "$_action_only_policy" && echo 1 || echo 0)" \
  'A12 a policy whose Action is narrowed (no bare "*") is NOT flagged'

# The ARN. Byte-identical reasoning to tests/suites/cloud-s3.sh's own A27-A30.
assert_eq 'aws' "$(ddb_partition_of 'arn:aws:iam::123456789012:user/x')" 'A13 partition: commercial'
assert_eq 'aws-cn' "$(ddb_partition_of 'arn:aws-cn:iam::123456789012:user/x')" 'A14 partition: China'
assert_eq 'arn:aws:ec2:eu-west-2:123456789012:vpc-endpoint/vpce-x' \
  "$(ddb_vpc_endpoint_arn aws 123456789012 eu-west-2 vpce-x)" \
  'A15 the VPC endpoint ARN carries the ec2 service segment, the EC2 resource type it really is'

# ===========================================================================
# B. One scan, two tables and two endpoints: fires on the bad, quiet on the
#    hardened/narrowed.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_resource "$TBL" "$PUB_ARN")
HARD_IDS=$(_ids_for_resource "$TBL" "$HARD_ARN")

assert_contains "$PUB_IDS" CLOUD-DYNAMODB-NO_ENCRYPTION-01 'B3 the no-SSEDescription table is reported by NO_ENCRYPTION'
assert_contains "$PUB_IDS" CLOUD-DYNAMODB-NO_BACKUPS-01 'B4 the PITR-disabled table is reported by NO_BACKUPS'
assert_eq '' "$HARD_IDS" 'B5 the hardened table in the SAME run produces no per-table finding'

DEFAULT_IDS=$(_ids_for_resource "$TBL" "$DEFAULT_VPCE_ARN")
NARROWED_IDS=$(_ids_for_resource "$TBL" "$NARROWED_VPCE_ARN")
assert_contains "$DEFAULT_IDS" CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01 \
  'B6 the default-policy VPC endpoint fires CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01'
assert_eq '' "$NARROWED_IDS" \
  'B7 the Condition-narrowed VPC endpoint, examined in the SAME call, produces no finding'

# Neither the unrelated `dynamodb-streams` endpoint nor the wrong-TYPE
# `dynamodb` Interface endpoint is examined at all - both carry the identical
# default-policy text, so a finding on either proves the service-name suffix
# or the Gateway-type filter was not really applied.
assert_not_contains "$TBL" 'vpce-scoursh-fixture-unrelated' \
  'B8 a same-region-different-service endpoint (dynamodb-streams) is never examined'
assert_not_contains "$TBL" 'vpce-scoursh-fixture-wrong-type' \
  'B9 a non-Gateway endpoint naming the dynamodb service is never examined'

# ===========================================================================
# C. ARN, region, account, and the (deliberate) absence of CIS.
# ===========================================================================
t_case 'C. finding citation'

_enc_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-DYNAMODB-NO_ENCRYPTION-01" { print; exit }')
_c_arn=$(_row_col "$_enc_row" 2)
_c_region=$(_row_col "$_enc_row" 3)
_c_cell=$(_row_col "$_enc_row" 4)
_c_cis=$(_row_col "$_enc_row" 5)
_c_account=$(_row_col "$_enc_row" 6)

assert_eq "$PUB_ARN" "$_c_arn" 'C1 the finding cites the table ARN, read directly off describe-table'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '' "$_c_cis" \
  'C4 the finding carries NO cis value - CIS v3.0.0 has no DynamoDB section at all (an honest absence)'
# `dynamodb` is regional, the identical reasoning tests/suites/cloud-rds.sh's
# own C5 gives: the cell and the region are the SAME value here.
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C5 the cell is <account>/<region>, matching the region the pass actually covered'

_vpce_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01" { print; exit }')
_v_arn=$(_row_col "$_vpce_row" 2)
_v_sub=$(_row_col "$_vpce_row" 7)
assert_eq "$DEFAULT_VPCE_ARN" "$_v_arn" 'C6 the endpoint finding cites the constructed vpc-endpoint ARN'
assert_eq 'vpce-scoursh-fixture-default' "$_v_sub" 'C7 the endpoint id rides in loc_sub_key'

_nfp=$(python3 - "$W/run-b/findings.jsonl" <<'PY'
import json, sys
fps = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        fps.add(json.loads(line)['fingerprint'])
print(len(fps))
PY
)
_nf=$(grep -c . "$W/run-b/findings.jsonl")
assert_eq "$_nf" "$_nfp" 'C8 every finding in the run has a distinct fingerprint'

# ===========================================================================
# D. Honesty: a denied call is a reduction, never silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The denied table's describe-table and describe-continuous-backups were both
# AccessDenied. Both checks still ran (two other tables answered each), so
# BOTH are in checks_run - and the partial loss is recorded beside each.
assert_contains "$CHECKS_RUN" 'CLOUD-DYNAMODB-NO_ENCRYPTION-01' \
  'D1 a check that answered for SOME tables is in checks_run'
assert_contains "$CHECKS_RUN" 'CLOUD-DYNAMODB-NO_BACKUPS-01' 'D1b ... both of them'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on one table is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'resources_unanswered=1' \
  'D3 the reduction says how many resources did not answer'
assert_not_contains "$(_ids_for_resource "$TBL" "arn:aws:dynamodb:eu-west-2:123456789012:table/$DENY")" \
  'CLOUD-DYNAMODB' \
  'D4 no finding is invented for the table whose properties were never read'

# The whole table list unreadable: no table examined by the per-table checks,
# and the gap stated where a consumer actually reads it - the reading D6/D7
# fail under is exit 0 with an empty findings set and no explanation.
_routes_default list-tables "$FIX/list-tables.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-DYNAMODB-NO_ENCRYPTION-01' \
  'D5 a denied list-tables credits no per-table check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'table list' \
  'D6 ... and the coverage_gap says the table list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'table list' \
  'D7 ... and it reaches report.md, the surface a consumer actually reads'
# The table-list failure must NOT stop the VPC-endpoint check from being
# tried - the two are independent AWS calls, and abandoning the second
# because the first failed would suppress a real, answerable check.
assert_contains "$CR2" 'CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01' \
  'D8 the endpoint-policy check still ran even though the table list was denied'

# The whole endpoint list unreadable, independently of the table list.
_routes_default describe-vpc-endpoints "$FIX/describe-vpc-endpoints.denied.err"
_run_cloud "$W/run-denied-vpce"
RED3=$(_json "$W/run-denied-vpce/run.json" coverage_reduction)
CR3=$(_json "$W/run-denied-vpce/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01' \
  'D9 a denied describe-vpc-endpoints credits no endpoint-policy check at all'
assert_contains "$RED3" 'operation=describe-vpc-endpoints' 'D10 ... and the reduction names the failed operation'
assert_contains "$CR3" 'CLOUD-DYNAMODB-NO_ENCRYPTION-01' \
  'D11 ... while the per-table checks still ran unaffected'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the regions the run resolved'
assert_eq '123456789012' "$(_json "$RUNJSON" cloud.account_id)" 'E2 run.json records the scanned account'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E3 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E4 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-DYNAMODB-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-DYNAMODB-NO_ENCRYPTION-01 account-region 123456789012/eu-west-2' \
  'E5 the run wrote a REAL account-region coverage cell for the region it actually covered'

assert_file_exists "$W/run-b/report.md" 'E6 report.md written'
assert_file_exists "$W/run-b/report.html" 'E7 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$PUB_ARN" 'E8 report.md names the table ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E9 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-DYNAMODB-NO_ENCRYPTION-01' 'E10 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$PUB_ARN" 'E11 the SARIF result names the resource'

# ===========================================================================
# F. This service's own truncation sharp edge, end to end.
# ===========================================================================
t_case 'F. LastEvaluatedTableName truncation, end to end'

_routes_default list-tables "$FIX/list-tables.truncated.json"
_run_cloud "$W/run-truncated"
RED4=$(_json "$W/run-truncated/run.json" coverage_reduction)
assert_contains "$RED4" 'aws_api_truncated' \
  'F1 a LastEvaluatedTableName-truncated table list is recorded as a coverage_reduction, even though SCOURSH_AWS_RO_OUTCOME reported ok'
assert_contains "$(_json "$W/run-truncated/run.json" coverage_gap)" 'table list' \
  'F2 ... and the coverage_gap says the table list was truncated'

t_summary cloud-dynamodb
