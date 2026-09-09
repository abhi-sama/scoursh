#!/usr/bin/env bash
# tests/suites/cloud-ssm.sh - modules/cloud/aws/live/ssm.sh: the §8.1 SSM
# (Systems Manager Parameter Store) read-only checks
# (docs/STEP6-CLOUD-PLAN.md CLOUD-09).
#
# Same shape as tests/suites/cloud-kms.sh; see that suite's own header for
# the five general properties it and this one both pin.  SSM-specific:
#
#   6. THE ARN IS BUILT, NEVER TRUSTED FROM A RESPONSE FIELD - `describe-
#      parameters` has none - so section C asserts the finding's ARN against
#      the constructed form `ssm_engine.sh`'s own header documents, not
#      against anything the fixture could echo back.
#   7. THE TWO CHECKS ARE INDEPENDENT: a SecureString parameter with a public
#      resource policy is flagged for the policy and NOT for its type; a
#      String parameter with a sensitive name and an empty policy is flagged
#      for its type and NOT for a policy.
#
# NO NETWORK AND NO AWS ACCOUNT - the routed stub `aws`
# (tests/lib/aws-fixtures.sh) over tests/fixtures/aws/cloud-ssm/.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see cloud-kms.sh's own identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/ssm_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-ssm
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-ssm
GOOD_ARN=arn:aws:ssm:eu-west-2:123456789012:parameter/app/prod/db-password
BAD_ARN=arn:aws:ssm:eu-west-2:123456789012:parameter/app/prod/api-token
BENIGN_ARN=arn:aws:ssm:eu-west-2:123456789012:parameter/app/prod/feature-flags
DENY_ARN=arn:aws:ssm:eu-west-2:123456789012:parameter/app/prod/deny-secret

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add ssm describe-parameters "$FIX/describe-parameters.json"

  aws_fixture_route_add_for ssm get-resource-policies "$GOOD_ARN"   "$FIX/get-resource-policies.empty.json"
  aws_fixture_route_add_for ssm get-resource-policies "$BAD_ARN"    "$FIX/get-resource-policies.public.json"
  aws_fixture_route_add_for ssm get-resource-policies "$BENIGN_ARN" "$FIX/get-resource-policies.empty.json"
  aws_fixture_route_add_for ssm get-resource-policies "$DENY_ARN"   "$FIX/get-resource-policies.denied.err"
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

# A TAB is not a safe field separator here - see tests/suites/cloud-kms.sh's
# own identical note for the full account: it is IFS *whitespace*, so a `read`
# folds a RUN of tabs into ONE delimiter, which is exactly what happens the
# moment a row with an empty `cis` field (every check here) is read. 0x1f
# (US) is this codebase's own established fix (AGENTS.md's DAST-11 lesson).
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
US = '\x1f'
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print(US.join([
        f.get('check_id', ''),
        loc.get('resource_key', '') or '',
        loc.get('region', '') or '',
        f.get('cell') or '',
        ','.join(f.get('cis') or []),
        loc.get('account_id', '') or '',
    ]))
PY
}

_ids_for_arn() {
  local table=$1 arn=$2
  printf '%s\n' "$table" | awk -F$'\x1f' -v b="$arn" '$2 == b { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

assert_eq 'arn:aws:ssm:eu-west-2:123456789012:parameter/app/prod/db-password' \
  "$(ssm_parameter_arn aws eu-west-2 123456789012 /app/prod/db-password)" \
  'A1 a hierarchical name (leading slash) is not doubled in the ARN'
assert_eq 'arn:aws:ssm:eu-west-2:123456789012:parameter/flatName' \
  "$(ssm_parameter_arn aws eu-west-2 123456789012 flatName)" \
  'A2 a flat name (no leading slash) needs nothing stripped'

assert_true "$(ssm_name_looks_sensitive '/app/prod/db-password' && echo 0 || echo 1)" 'A3 a name containing "password" looks sensitive'
assert_true "$(ssm_name_looks_sensitive '/app/prod/api-token' && echo 0 || echo 1)" 'A4 a name containing "token" looks sensitive'
assert_true "$(ssm_name_looks_sensitive '/app/prod/feature-flags' && echo 1 || echo 0)" \
  'A5 a name matching none of the keyword shapes does not look sensitive'

ssm_doc_load "$FIX/get-resource-policies.public.json"
_pol=''
ssm_policy_entry_field_set _pol 0 Policy
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 0 || echo 1)" \
  'A6 an unconditioned wildcard-Principal Allow statement in an SSM resource policy IS public'

# ===========================================================================
# B. One scan, four parameters: both checks fire independently.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/ssm-run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/ssm-run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/ssm-run-b/findings.jsonl")
GOOD_IDS=$(_ids_for_arn "$TBL" "$GOOD_ARN")
BAD_IDS=$(_ids_for_arn "$TBL" "$BAD_ARN")
BENIGN_IDS=$(_ids_for_arn "$TBL" "$BENIGN_ARN")

assert_eq '' "$GOOD_IDS" 'B3 a SecureString parameter, even with a sensitive-looking name, produces no finding'
assert_contains "$BAD_IDS" CLOUD-SSM-STRING_TYPE_SENSITIVE-01 'B4 a String parameter with a sensitive-looking name is flagged'
assert_contains "$BAD_IDS" CLOUD-SSM-PUBLIC_POLICY-01 'B5 the same parameter is independently flagged for its public resource policy'
assert_eq '' "$BENIGN_IDS" 'B6 a String parameter whose name matches no sensitive keyword, in the SAME run, produces no finding'

# ===========================================================================
# C. ARN, region, account, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-SSM-STRING_TYPE_SENSITIVE-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"
assert_eq "$BAD_ARN" "$_c_arn" 'C1 the finding cites the CONSTRUCTED parameter ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell is <account>/<region>, matching loc_region for a regional service'
assert_eq '' "$_c_cis" \
  'C5 CLOUD-SSM-STRING_TYPE_SENSITIVE-01 carries NO cis id - CIS v3.0.0 has no SSM Parameter Store section, and this project never invents one'

# ===========================================================================
# D. Honesty: a denied call is a reduction, never silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/ssm-run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" CLOUD-SSM-PUBLIC_POLICY-01 'D1 a check that answered for SOME parameters is in checks_run'
assert_contains "$REDUCTIONS" aws_api_access_denied \
  'D2 the AccessDenied on the deny-secret resource-policies call is recorded as a coverage_reduction'
assert_not_contains "$(_ids_for_arn "$TBL" "$DENY_ARN")" CLOUD-SSM-PUBLIC_POLICY-01 \
  'D3 no policy finding is invented for the parameter whose policy was never read'
# The STRING_TYPE check never costs a call, so it is unaffected by the denial:
# the deny-secret parameter is SecureString, so it produces no finding for
# that check either, and the denial above is exclusively attributed to the
# policy check.
assert_not_contains "$REDUCTIONS" 'check=CLOUD-SSM-STRING_TYPE_SENSITIVE-01' \
  'D4 the resource-policy denial does not bleed into the type-heuristic check, which made no call at all'

aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add ssm describe-parameters "$FIX/get-resource-policies.denied.err"
_run_cloud "$W/ssm-run-denied"
CR2=$(_json "$W/ssm-run-denied/run.json" checks_run)
assert_not_contains "$CR2" CLOUD-SSM- 'D5 a denied describe-parameters credits no check at all'
assert_contains "$(_json "$W/ssm-run-denied/run.json" coverage_gap)" 'parameter list' \
  'D6 the coverage_gap says the parameter list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and SARIF.
# ===========================================================================
t_case 'E. round-trip'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E1 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E2 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-SSM-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-SSM-PUBLIC_POLICY-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell'

_routes_default
_run_cloud "$W/ssm-run-sarif" --format sarif
assert_file_exists "$W/ssm-run-sarif/report.sarif" 'E4 --format sarif writes report.sarif'
_SARIF=$(cat "$W/ssm-run-sarif/report.sarif")
assert_contains "$_SARIF" CLOUD-SSM-STRING_TYPE_SENSITIVE-01 'E5 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$BAD_ARN" 'E6 the SARIF result names the resource'

# The tri-service half of tests/suites/cloud-s3.sh's own E16/E17 guard: SSM is
# the last of CLOUD-07/08/09 landed in this ticket, so this is where the
# audit view's coverage-strength note is checked for the FULL, updated
# sentence rather than only the fact that it changed at all. CLOUD-22
# (apigw.sh) landed alongside CLOUD-07/08/09 on dev, so the sentence names all
# five landed services rather than four.
_routes_default
_run_cloud "$W/ssm-run-audit" --format audit
assert_file_exists "$W/ssm-run-audit/report-audit.html" 'E7 --format audit writes report-audit.html'
_AUDIT=$(cat "$W/ssm-run-audit/report-audit.html")
assert_contains "$_AUDIT" 'ships the S3, API Gateway, KMS, Secrets Manager and SSM services so far' \
  'E8 the audit view names all five landed cloud services'

t_summary cloud-ssm
