#!/usr/bin/env bash
# tests/suites/cloud-ecs.sh - modules/cloud/aws/live/ecs.sh: the §8.1 ECS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-26).
#
# Mirrors tests/suites/cloud-s3.sh's own five-section shape, narrowed to what
# is different about ECS: a FOUR-LEVEL call chain
# (list-clusters -> list-services -> describe-services -> describe-task-
# definition -> the shared iam_policy_engine.sh driver's own list-role-
# policies -> get-role-policy), where a failure at any level is a coverage
# loss for exactly what it blocks and never a reason to abandon the rest of
# the walk - section D exercises a denial at the SECOND level
# (list-services), the one s3.sh/cloud-s3.sh's own two-level chain has no
# analogue for.
#
# ECS IS `regional`, so - exactly as cloud-ecr.sh's own section C states for
# the identical reason - a finding's `cell` and its `loc_region` are the
# SAME value, unlike S3's global pass.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-ecs/.
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
# -x back-edge cut: see cloud-s3.sh's identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/ecs_engine.sh"
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/iam_policy_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-ecs
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-ecs
BAD_CLUSTER=arn:aws:ecs:eu-west-2:123456789012:cluster/scoursh-fixture-ecs-bad-cluster
GOOD_CLUSTER=arn:aws:ecs:eu-west-2:123456789012:cluster/scoursh-fixture-ecs-good-cluster
DENIED_CLUSTER=arn:aws:ecs:eu-west-2:123456789012:cluster/scoursh-fixture-ecs-denied-cluster
BAD_SERVICE=arn:aws:ecs:eu-west-2:123456789012:service/scoursh-fixture-ecs-bad-cluster/scoursh-fixture-ecs-bad-service
GOOD_SERVICE=arn:aws:ecs:eu-west-2:123456789012:service/scoursh-fixture-ecs-good-cluster/scoursh-fixture-ecs-good-service
BAD_TASKDEF=arn:aws:ecs:eu-west-2:123456789012:task-definition/scoursh-fixture-ecs-bad-task:1
GOOD_TASKDEF=arn:aws:ecs:eu-west-2:123456789012:task-definition/scoursh-fixture-ecs-good-task:1
BAD_ROLE=arn:aws:iam::123456789012:role/scoursh-fixture-ecs-bad-role
GOOD_ROLE=arn:aws:iam::123456789012:role/scoursh-fixture-ecs-good-role
# The IAM calls take `--role-name`, the bare NAME (the last path segment of
# the ARN) - never the ARN itself - so the route qualifier must match on
# the name, which is the literal argv word `iam_role_overpermissive`
# actually passes.
BAD_ROLE_NAME=scoursh-fixture-ecs-bad-role
GOOD_ROLE_NAME=scoursh-fixture-ecs-good-role

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add ecs list-clusters       "$FIX/list-clusters.json"
  aws_fixture_route_add_for ecs list-services "$BAD_CLUSTER"    "$FIX/list-services.bad.json"
  aws_fixture_route_add_for ecs list-services "$GOOD_CLUSTER"   "$FIX/list-services.good.json"
  aws_fixture_route_add_for ecs list-services "$DENIED_CLUSTER" "$FIX/list-services.denied.err"
  aws_fixture_route_add_for ecs describe-services "$BAD_SERVICE"  "$FIX/describe-services.bad.json"
  aws_fixture_route_add_for ecs describe-services "$GOOD_SERVICE" "$FIX/describe-services.good.json"
  aws_fixture_route_add_for ecs describe-task-definition "$BAD_TASKDEF"  "$FIX/describe-task-definition.bad.json"
  aws_fixture_route_add_for ecs describe-task-definition "$GOOD_TASKDEF" "$FIX/describe-task-definition.good.json"
  aws_fixture_route_add_for iam list-role-policies "$BAD_ROLE_NAME"  "$FIX/iam.list-role-policies.bad.json"
  aws_fixture_route_add_for iam list-role-policies "$GOOD_ROLE_NAME" "$FIX/iam.list-role-policies.good.json"
  aws_fixture_route_add_for iam get-role-policy "$BAD_ROLE_NAME"  "$FIX/iam.get-role-policy.bad.json"
  aws_fixture_route_add_for iam get-role-policy "$GOOD_ROLE_NAME" "$FIX/iam.get-role-policy.good.json"
}

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

# FIELDS ARE JOINED WITH 0x1f, NEVER A TAB - see cloud-ecr.sh's own
# `_findings_table` for why: a tab is an IFS-*whitespace* character, so
# bash's `read` collapses a run of them (POSIX XCU 2.6.5) and silently
# drops an empty field, shifting every column after it. `sub_key` is empty
# for CLOUD-ECS-PUBLIC_SERVICE-01, so this file hits exactly that hazard.
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
SEP = '\x1f'
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print(SEP.join([
        f.get('check_id', ''),
        loc.get('resource_key', '') or '',
        loc.get('region', '') or '',
        f.get('cell') or '',
        loc.get('account_id', '') or '',
        loc.get('sub_key', '') or '',
    ]))
PY
}

_ids_for() {
  local table=$1 key=$2
  printf '%s\n' "$table" | awk -F$'\x1f' -v k="$key" '$2 == k { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

ecs_doc_load "$FIX/list-clusters.json"
local_arr=()
ecs_array_collect local_arr clusterArns
assert_eq '3' "${local_arr_n:-0}" 'A1 list-clusters: all three cluster ARNs are collected'
assert_eq "$BAD_CLUSTER" "${local_arr[0]}" 'A2 list-clusters: the first ARN is read in order'

ecs_doc_load "$FIX/describe-services.bad.json"
assert_true "$(ecs_service_assigns_public_ip && echo 0 || echo 1)" 'A3 the bad service assigns a public IP'
_svcarn=''
ecs_service_arn_set _svcarn
assert_eq "$BAD_SERVICE" "$_svcarn" 'A4 the service ARN is read directly, never constructed'
_td=''
ecs_service_task_definition_set _td
assert_eq "$BAD_TASKDEF" "$_td" 'A5 the task definition ARN is read'

ecs_doc_load "$FIX/describe-services.good.json"
assert_true "$(ecs_service_assigns_public_ip && echo 1 || echo 0)" 'A6 the good service does NOT assign a public IP'

ecs_doc_load "$FIX/describe-task-definition.bad.json"
_role=''
ecs_task_role_arn_set _role
assert_eq "$BAD_ROLE" "$_role" 'A7 the task role ARN is read'
assert_eq 'scoursh-fixture-ecs-bad-role' "$(ecs_iam_role_name_of "$_role")" \
  'A8 the IAM role NAME is the last path segment of the ARN'

# The shared iam_policy_engine.sh classifier, exercised directly: a bare-
# scalar Action/Resource ("*", not ["*"]) is still found - the reading this
# fails under only checks the array shape.
iampol_doc_load "$FIX/iam.get-role-policy.bad.json"
_g='' _rc9=0
iampol_wildcard_admin_grant_set _g PolicyDocument || _rc9=$?
assert_eq '0' "$_rc9" 'A9 a bare-scalar Action:"*" Resource:"*" Allow statement is found'
assert_eq 'AdminAccess' "$_g" 'A10 the offending Sid is reported'

iampol_doc_load "$FIX/iam.get-role-policy.good.json"
_g='' _rc11=0
iampol_wildcard_admin_grant_set _g PolicyDocument || _rc11=$?
assert_eq '1' "$_rc11" 'A11 a scoped policy (specific actions, specific resource) is NOT flagged'

# ===========================================================================
# B. One scan, two clusters: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
BAD_SVC_IDS=$(_ids_for "$TBL" "$BAD_SERVICE")
GOOD_SVC_IDS=$(_ids_for "$TBL" "$GOOD_SERVICE")
BAD_ROLE_IDS=$(_ids_for "$TBL" "$BAD_ROLE")
GOOD_ROLE_IDS=$(_ids_for "$TBL" "$GOOD_ROLE")

assert_contains "$BAD_SVC_IDS" 'CLOUD-ECS-PUBLIC_SERVICE-01' 'B3 the bad service is reported by PUBLIC_SERVICE'
assert_contains "$BAD_ROLE_IDS" 'CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01' 'B4 the bad task role is reported by TASK_ROLE_OVERPERMISSIVE'
assert_eq '' "$GOOD_SVC_IDS" 'B5 the good service in the SAME run produces no public-IP finding'
assert_eq '' "$GOOD_ROLE_IDS" 'B6 the good task role in the SAME run produces no over-permissive finding'

# ===========================================================================
# C. ARN, region, account - resource_key is the ROLE for the role check.
# ===========================================================================
t_case 'C. finding citation'

_svc_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-ECS-PUBLIC_SERVICE-01" { print; exit }')
IFS=$'\x1f' read -r _s_id _s_arn _s_region _s_cell _s_account _s_sub <<<"$_svc_row"
assert_eq "$BAD_SERVICE" "$_s_arn" 'C1 the PUBLIC_SERVICE finding cites the service ARN'
assert_eq 'eu-west-2' "$_s_region" 'C2 the finding cites the region'
assert_eq '123456789012' "$_s_account" 'C3 the finding cites the account id'
assert_eq '123456789012/eu-west-2' "$_s_cell" 'C4 the cell is <account>/<region> - ecs is regional, unlike s3'
assert_eq "$_s_region" "${_s_cell#*/}" 'C5 cell and loc_region agree for a regional service'

_role_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01" { print; exit }')
_r_arn=$(printf '%s\n' "$_role_row" | awk -F$'\x1f' '{print $2}')
_r_sub=$(printf '%s\n' "$_role_row" | awk -F$'\x1f' '{print $6}')
assert_eq "$BAD_ROLE" "$_r_arn" 'C6 the role finding cites the ROLE ARN, not the service ARN'
assert_eq 'scoursh-fixture-wildcard-admin:AdminAccess' "$_r_sub" 'C7 loc_sub_key names the offending policy and statement'

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
# D. Honesty: a denial at the SECOND level of the chain is a reduction.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# list-services was denied for the THIRD cluster - a coverage loss for BOTH
# checks over the services that cluster would have had, never silence, and
# never a reason to abandon the other two clusters.
assert_contains "$REDUCTIONS" 'operation=list-services' \
  'D1 the denied cluster records a coverage_reduction naming list-services'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' 'D2 ... classified as access_denied'
assert_contains "$CHECKS_RUN" 'CLOUD-ECS-PUBLIC_SERVICE-01' \
  'D3 the OTHER two clusters still cover the check - one denial does not blank checks_run'
assert_contains "$CHECKS_RUN" 'CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01' \
  'D4 ... for both checks'

# A task definition naming NO task role is a real, checked answer, not a
# coverage loss - covered by the good service/role pairing already being in
# checks_run above.  Now prove the whole cluster list unreadable case:
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add ecs list-clusters       "$FIX/list-services.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-ECS-' 'D5 a denied list-clusters credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'cluster list' \
  'D6 ... and the coverage_gap says the cluster list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the regions the run resolved'
RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E2 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E3 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-ECS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-ECS-PUBLIC_SERVICE-01 account-region 123456789012/eu-west-2' \
  'E4 the run wrote a real account-region coverage cell'

assert_file_exists "$W/run-b/report.md" 'E5 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$BAD_SERVICE" 'E6 report.md names the service ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E7 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01' 'E8 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$BAD_ROLE" 'E9 the SARIF result names the role ARN'

t_summary cloud-ecs
