#!/usr/bin/env bash
# tests/suites/cloud-eks.sh - modules/cloud/aws/live/eks.sh: the §8.1 EKS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-27).
#
# Mirrors tests/suites/cloud-ecs.sh's own shape (a multi-level call chain
# through the shared iam_policy_engine.sh driver), narrowed to EKS's own two
# checks: `describe-cluster`'s directly-returned endpoint-exposure fields
# need no per-resource follow-up at all, while the node-role check needs
# `list-nodegroups` -> `describe-nodegroup` -> the shared driver's own
# `list-role-policies`/`get-role-policy` chain.
#
# THE "POD ROLE" SUBSTITUTION IS ASSERTED EXPLICITLY (section A) RATHER THAN
# LEFT IMPLICIT: this check evaluates the NODE GROUP's own IAM role, not a
# literal per-Kubernetes-ServiceAccount IRSA binding - eks_engine.sh's own
# header states why that binding is unreachable through any `aws eks *`
# call.  Section A's own case names the reading a reader might otherwise
# assume (a literal per-pod audit) and confirms what is actually read
# instead.
#
# EKS IS `regional`, so a finding's `cell` and its `loc_region` are the SAME
# value, exactly as cloud-ecr.sh's and cloud-ecs.sh's own section C states
# for the identical reason.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-eks/.
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
source "$ROOT/modules/cloud/aws/live/eks_engine.sh"
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/iam_policy_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-eks
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-eks
BAD_CLUSTER=scoursh-fixture-eks-bad-cluster
GOOD_CLUSTER=scoursh-fixture-eks-good-cluster
BAD_CLUSTER_ARN=arn:aws:eks:eu-west-2:123456789012:cluster/scoursh-fixture-eks-bad-cluster
GOOD_CLUSTER_ARN=arn:aws:eks:eu-west-2:123456789012:cluster/scoursh-fixture-eks-good-cluster
BAD_NG=scoursh-fixture-eks-bad-ng
GOOD_NG=scoursh-fixture-eks-good-ng
BAD_ROLE=arn:aws:iam::123456789012:role/scoursh-fixture-eks-bad-role
GOOD_ROLE=arn:aws:iam::123456789012:role/scoursh-fixture-eks-good-role
# The IAM calls take `--role-name`, the bare NAME - never the ARN - so the
# route qualifier must match on the name, the literal argv word
# `iam_role_overpermissive` actually passes.
BAD_ROLE_NAME=scoursh-fixture-eks-bad-role
GOOD_ROLE_NAME=scoursh-fixture-eks-good-role

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add eks list-clusters       "$FIX/list-clusters.json"
  aws_fixture_route_add_for eks describe-cluster "$BAD_CLUSTER"  "$FIX/describe-cluster.bad.json"
  aws_fixture_route_add_for eks describe-cluster "$GOOD_CLUSTER" "$FIX/describe-cluster.good.json"
  aws_fixture_route_add_for eks list-nodegroups "$BAD_CLUSTER"  "$FIX/list-nodegroups.bad.json"
  aws_fixture_route_add_for eks list-nodegroups "$GOOD_CLUSTER" "$FIX/list-nodegroups.good.json"
  aws_fixture_route_add_for eks describe-nodegroup "$BAD_NG"  "$FIX/describe-nodegroup.bad.json"
  aws_fixture_route_add_for eks describe-nodegroup "$GOOD_NG" "$FIX/describe-nodegroup.good.json"
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
# for CLOUD-EKS-PUBLIC_ENDPOINT-01, so this file hits exactly that hazard.
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

eks_doc_load "$FIX/list-clusters.json"
list_arr=()
eks_array_collect list_arr clusters
assert_eq '2' "${list_arr_n:-0}" 'A1 list-clusters: both cluster names are collected'
assert_eq "$BAD_CLUSTER" "${list_arr[0]}" 'A2 list-clusters: names, not ARNs, in order'

eks_doc_load "$FIX/describe-cluster.bad.json"
assert_true "$(eks_cluster_endpoint_public && echo 0 || echo 1)" 'A3 the bad cluster has a public endpoint'
_arn=''
eks_cluster_arn_set _arn
assert_eq "$BAD_CLUSTER_ARN" "$_arn" 'A4 the cluster ARN is read directly, never constructed'
_cidrs=''
eks_cluster_public_cidrs_set _cidrs
assert_eq '0.0.0.0/0' "$_cidrs" 'A5 the public CIDR list is read'

eks_doc_load "$FIX/describe-cluster.good.json"
assert_true "$(eks_cluster_endpoint_public && echo 1 || echo 0)" \
  'A6 the good cluster does NOT have a public endpoint, even though it still carries a publicAccessCidrs of 0.0.0.0/0 - the reading this fails under checks the CIDR list alone rather than endpointPublicAccess first'

# An ABSENT publicAccessCidrs list means the widest case (0.0.0.0/0), the
# AWS default the moment public access is on with no restriction - the
# reading this fails under treats an absent list as narrower than an
# explicit one.
printf '{"cluster":{"resourcesVpcConfig":{"endpointPublicAccess":true}}}\n' >"$W/no-cidrs.json"
eks_doc_load "$W/no-cidrs.json"
eks_cluster_public_cidrs_set _cidrs
assert_eq '0.0.0.0/0' "$_cidrs" 'A7 an absent publicAccessCidrs defaults to the open case, not a narrower one'

eks_doc_load "$FIX/describe-nodegroup.bad.json"
_role=''
eks_nodegroup_role_arn_set _role
assert_eq "$BAD_ROLE" "$_role" 'A8 the node role ARN is read'
assert_eq 'scoursh-fixture-eks-bad-role' "$(eks_iam_role_name_of "$_role")" \
  'A9 the IAM role NAME is the last path segment of the ARN'

# The shared classifier, exercised with an ARRAY-shaped Action/Resource
# (["*"], not the bare "*" cloud-ecs.sh's own fixture uses) - both shapes
# are legal IAM policy grammar and the classifier must catch both.
iampol_doc_load "$FIX/iam.get-role-policy.bad.json"
_g='' _rc10=0
iampol_wildcard_admin_grant_set _g PolicyDocument || _rc10=$?
assert_eq '0' "$_rc10" 'A10 an array-shaped Action:["*"] Resource:["*"] Allow statement is found'
assert_eq 'NodeAdminAccess' "$_g" 'A11 the offending Sid is reported'

iampol_doc_load "$FIX/iam.get-role-policy.good.json"
_g='' _rc12=0
iampol_wildcard_admin_grant_set _g PolicyDocument || _rc12=$?
assert_eq '1' "$_rc12" 'A12 a scoped policy (one repository ARN, two named actions) is NOT flagged'

# ===========================================================================
# B. One scan, two clusters: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
BAD_CLUSTER_IDS=$(_ids_for "$TBL" "$BAD_CLUSTER_ARN")
GOOD_CLUSTER_IDS=$(_ids_for "$TBL" "$GOOD_CLUSTER_ARN")
BAD_ROLE_IDS=$(_ids_for "$TBL" "$BAD_ROLE")
GOOD_ROLE_IDS=$(_ids_for "$TBL" "$GOOD_ROLE")

assert_contains "$BAD_CLUSTER_IDS" 'CLOUD-EKS-PUBLIC_ENDPOINT-01' 'B3 the bad cluster is reported by PUBLIC_ENDPOINT'
assert_contains "$BAD_ROLE_IDS" 'CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01' 'B4 the bad node role is reported by POD_ROLE_OVERPERMISSIVE'
assert_eq '' "$GOOD_CLUSTER_IDS" 'B5 the good cluster in the SAME run produces no endpoint finding'
assert_eq '' "$GOOD_ROLE_IDS" 'B6 the good node role in the SAME run produces no over-permissive finding'

# ===========================================================================
# C. ARN, region, account - resource_key is the ROLE for the role check.
# ===========================================================================
t_case 'C. finding citation'

_ep_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-EKS-PUBLIC_ENDPOINT-01" { print; exit }')
IFS=$'\x1f' read -r _e_id _e_arn _e_region _e_cell _e_account _e_sub <<<"$_ep_row"
assert_eq "$BAD_CLUSTER_ARN" "$_e_arn" 'C1 the finding cites the cluster ARN'
assert_eq 'eu-west-2' "$_e_region" 'C2 the finding cites the region'
assert_eq '123456789012' "$_e_account" 'C3 the finding cites the account id'
assert_eq '123456789012/eu-west-2' "$_e_cell" 'C4 the cell is <account>/<region> - eks is regional, unlike s3'
assert_eq "$_e_region" "${_e_cell#*/}" 'C5 cell and loc_region agree for a regional service'

_role_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01" { print; exit }')
_r_arn=$(printf '%s\n' "$_role_row" | awk -F$'\x1f' '{print $2}')
_r_sub=$(printf '%s\n' "$_role_row" | awk -F$'\x1f' '{print $6}')
assert_eq "$BAD_ROLE" "$_r_arn" 'C6 the role finding cites the NODE ROLE ARN, not the cluster ARN'
assert_eq 'scoursh-fixture-wildcard-admin:NodeAdminAccess' "$_r_sub" 'C7 loc_sub_key names the offending policy and statement'

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
# D. Honesty: a denied describe-nodegroup is a reduction, never silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
CHECKS_RUN=$(_json "$RUNJSON" checks_run)
assert_contains "$CHECKS_RUN" 'CLOUD-EKS-PUBLIC_ENDPOINT-01' 'D1 the endpoint check is covered'
assert_contains "$CHECKS_RUN" 'CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01' 'D2 the role check is covered'

# Deny describe-nodegroup for the bad cluster's node group specifically -
# the role check must lose coverage for exactly that node group and record
# why, never emit a finding it never actually confirmed and never abandon
# the still-answering good cluster.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add eks list-clusters       "$FIX/list-clusters.json"
aws_fixture_route_add_for eks describe-cluster "$BAD_CLUSTER"  "$FIX/describe-cluster.bad.json"
aws_fixture_route_add_for eks describe-cluster "$GOOD_CLUSTER" "$FIX/describe-cluster.good.json"
aws_fixture_route_add_for eks list-nodegroups "$BAD_CLUSTER"  "$FIX/list-nodegroups.bad.json"
aws_fixture_route_add_for eks list-nodegroups "$GOOD_CLUSTER" "$FIX/list-nodegroups.good.json"
aws_fixture_route_add_for eks describe-nodegroup "$BAD_NG"  "$FIX/describe-nodegroup.denied.err"
aws_fixture_route_add_for eks describe-nodegroup "$GOOD_NG" "$FIX/describe-nodegroup.good.json"
aws_fixture_route_add_for iam list-role-policies "$GOOD_ROLE_NAME" "$FIX/iam.list-role-policies.good.json"
aws_fixture_route_add_for iam get-role-policy "$GOOD_ROLE_NAME" "$FIX/iam.get-role-policy.good.json"
_run_cloud "$W/run-d"
RED2=$(_json "$W/run-d/run.json" checks_run)
RJ2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_contains "$RJ2" 'operation=describe-nodegroup' \
  'D3 a denied describe-nodegroup records a coverage_reduction naming the operation'
assert_contains "$RED2" 'CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01' \
  'D4 the role check is STILL covered - the good cluster answered even though the bad one did not'

# The whole cluster list unreadable: nothing examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add eks list-clusters       "$FIX/list-clusters.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-EKS-' 'D5 an unreadable cluster list credits no check at all'
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
    if cid.startswith('CLOUD-EKS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-EKS-PUBLIC_ENDPOINT-01 account-region 123456789012/eu-west-2' \
  'E4 the run wrote a real account-region coverage cell'

assert_file_exists "$W/run-b/report.md" 'E5 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$BAD_CLUSTER_ARN" 'E6 report.md names the cluster ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E7 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01' 'E8 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$BAD_ROLE" 'E9 the SARIF result names the role ARN'

t_summary cloud-eks
