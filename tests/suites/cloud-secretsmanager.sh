#!/usr/bin/env bash
# tests/suites/cloud-secretsmanager.sh - modules/cloud/aws/live/
# secretsmanager.sh: the §8.1 Secrets Manager read-only checks
# (docs/STEP6-CLOUD-PLAN.md CLOUD-08).
#
# Same shape as tests/suites/cloud-kms.sh; see that suite's own header for the
# five properties it and this one both pin.  The Secrets-Manager-specific
# property this suite adds:
#
#   6. A SECRET OWNED BY ANOTHER AWS SERVICE, AND ONE ALREADY SCHEDULED FOR
#      DELETION, ARE OUT OF SCOPE FOR THE ROTATION CHECK - neither evaluated
#      nor lost, the identical "out of scope, not a loss" distinction
#      cloud-kms.sh pins for an AWS-managed key.
#   7. AN ABSENT `ResourcePolicy` FIELD IN A SUCCESSFUL RESPONSE IS "NO
#      POLICY", NOT AN ERROR - the mirror image of tension 23's `NoSuch*`
#      lesson: here the call itself never fails at all.
#
# NO NETWORK AND NO AWS ACCOUNT - the routed stub `aws`
# (tests/lib/aws-fixtures.sh) over tests/fixtures/aws/cloud-secretsmanager/.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see cloud-kms.sh's own identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/secretsmanager_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-secretsmanager
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-secretsmanager
GOOD_ARN=arn:aws:secretsmanager:eu-west-2:123456789012:secret:good-secret-AbCdEf
BAD_ARN=arn:aws:secretsmanager:eu-west-2:123456789012:secret:bad-secret-GhIjKl
OWNED_ARN=arn:aws:secretsmanager:eu-west-2:123456789012:secret:owned-secret-MnOpQr
DELETED_ARN=arn:aws:secretsmanager:eu-west-2:123456789012:secret:deleted-secret-StUvWx
DENY_ARN=arn:aws:secretsmanager:eu-west-2:123456789012:secret:deny-secret-YzAbCd

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add secretsmanager list-secrets "$FIX/list-secrets.json"

  aws_fixture_route_add_for secretsmanager get-resource-policy "$GOOD_ARN"    "$FIX/get-resource-policy.absent.json"
  aws_fixture_route_add_for secretsmanager get-resource-policy "$BAD_ARN"     "$FIX/get-resource-policy.public.json"
  aws_fixture_route_add_for secretsmanager get-resource-policy "$OWNED_ARN"   "$FIX/get-resource-policy.owned.json"
  aws_fixture_route_add_for secretsmanager get-resource-policy "$DELETED_ARN" "$FIX/get-resource-policy.deleted.json"
  aws_fixture_route_add_for secretsmanager get-resource-policy "$DENY_ARN"    "$FIX/get-resource-policy.denied.err"
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

secm_doc_load "$FIX/list-secrets.json"
assert_true "$(secm_secret_rotation_enabled 0 && echo 0 || echo 1)" 'A1 good-secret (index 0): RotationEnabled true is read'
assert_true "$(secm_secret_rotation_enabled 1 && echo 1 || echo 0)" 'A2 bad-secret (index 1): RotationEnabled false is read'
assert_eq 'rds.amazonaws.com' "$(secm_secret_owning_service 2)" 'A3 owned-secret (index 2): OwningService is read'
assert_true "$(secm_secret_deleted 3 && echo 0 || echo 1)" 'A4 deleted-secret (index 3): DeletedDate presence is detected'
assert_true "$(secm_secret_deleted 0 && echo 1 || echo 0)" 'A5 good-secret has no DeletedDate'

secm_doc_load "$FIX/get-resource-policy.absent.json"
assert_eq '' "$(secm_policy_field)" 'A6 an absent ResourcePolicy field reads as empty, not an error'

secm_doc_load "$FIX/get-resource-policy.public.json"
_pol=$(secm_policy_field)
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 0 || echo 1)" \
  'A7 an unconditioned wildcard-Principal Allow statement in ResourcePolicy IS public'

# ===========================================================================
# B. One scan, five secrets: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/secm-run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/secm-run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/secm-run-b/findings.jsonl")
GOOD_IDS=$(_ids_for_arn "$TBL" "$GOOD_ARN")
BAD_IDS=$(_ids_for_arn "$TBL" "$BAD_ARN")
OWNED_IDS=$(_ids_for_arn "$TBL" "$OWNED_ARN")
DELETED_IDS=$(_ids_for_arn "$TBL" "$DELETED_ARN")

assert_contains "$BAD_IDS" CLOUD-SECRETSMANAGER-NO_ROTATION-01 'B3 the bad secret is reported for disabled rotation'
assert_contains "$BAD_IDS" CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01 'B4 the bad secret is reported for its public resource policy'
assert_eq '' "$GOOD_IDS" 'B5 the good secret in the SAME run produces no finding at all'
assert_eq '' "$OWNED_IDS" 'B6 a secret owned by another AWS service produces no finding - out of scope, not silently clean'
assert_eq '' "$DELETED_IDS" 'B7 a secret already scheduled for deletion produces no finding'

# ===========================================================================
# C. ARN, region, account, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-SECRETSMANAGER-NO_ROTATION-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"
assert_eq "$BAD_ARN" "$_c_arn" 'C1 the finding cites the secret ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell is <account>/<region>, matching loc_region for a regional service'
assert_eq '' "$_c_cis" \
  'C5 CLOUD-SECRETSMANAGER-NO_ROTATION-01 carries NO cis id - CIS v3.0.0 has no Secrets Manager section, and this project never invents one'

# ===========================================================================
# D. Honesty: a denied call is a reduction; an out-of-scope secret is neither.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/secm-run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01 \
  'D1 a check that answered for SOME secrets is in checks_run'
assert_contains "$REDUCTIONS" aws_api_access_denied \
  'D2 the AccessDenied on the deny-secret policy call is recorded as a coverage_reduction'
assert_not_contains "$(_ids_for_arn "$TBL" "$DENY_ARN")" CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01 \
  'D3 no policy finding is invented for the secret whose policy was never read'
assert_not_contains "$REDUCTIONS" "secret_arn=$OWNED_ARN" \
  'D4 the owned secret is never reported as a coverage loss for rotation - it was correctly judged out of scope'
assert_not_contains "$REDUCTIONS" "secret_arn=$DELETED_ARN" \
  'D5 the deleted secret is never reported as a coverage loss for rotation either'

aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add secretsmanager list-secrets "$FIX/get-resource-policy.denied.err"
_run_cloud "$W/secm-run-denied"
CR2=$(_json "$W/secm-run-denied/run.json" checks_run)
assert_not_contains "$CR2" CLOUD-SECRETSMANAGER- 'D6 a denied list-secrets credits no check at all'
assert_contains "$(_json "$W/secm-run-denied/run.json" coverage_gap)" 'secret list' \
  'D7 the coverage_gap says the secret list could not be read'

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
    if cid.startswith('CLOUD-SECRETSMANAGER-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell'

_routes_default
_run_cloud "$W/secm-run-sarif" --format sarif
assert_file_exists "$W/secm-run-sarif/report.sarif" 'E4 --format sarif writes report.sarif'
_SARIF=$(cat "$W/secm-run-sarif/report.sarif")
assert_contains "$_SARIF" CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01 'E5 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$BAD_ARN" 'E6 the SARIF result names the resource'

t_summary cloud-secretsmanager
