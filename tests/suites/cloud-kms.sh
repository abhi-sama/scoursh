#!/usr/bin/env bash
# tests/suites/cloud-kms.sh - modules/cloud/aws/live/kms.sh: the §8.1 KMS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-07).
#
# Mirrors tests/suites/cloud-s3.sh's own shape and pins the identical five
# properties over KMS's own resources, plus one KMS-specific one:
#
#   1. BOTH DIRECTIONS, IN ONE RUN (a good key and a bad key, same scan).
#   2. EVERY FINDING CITES ARN, REGION, ACCOUNT and (for ROTATION_DISABLED
#      only) a CIS control id.
#   3. THE CELL IS `<account>/<region>`, SAME AS `loc_region` - unlike S3,
#      KMS is a REGIONAL service, so there is no global-cell/real-region
#      split to assert; asserting the two agree is still worth doing because
#      an implementation that copied S3's cell literally (`<account>/global`)
#      would otherwise pass every other assertion here.
#   4. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE.
#   5. THE FINDING ROUND-TRIPS - findings.jsonl, a real account-region
#      coverage cell, and SARIF.
#   6. AN AWS-MANAGED KEY AND AN INELIGIBLE KEY TYPE ARE NEITHER EVALUATED NOR
#      LOST - a key this pass correctly judges out of scope must not spend an
#      API call it cannot answer meaningfully, and must not be reported as a
#      coverage loss either.
#
# NO NETWORK AND NO AWS ACCOUNT - the routed stub `aws`
# (tests/lib/aws-fixtures.sh) over tests/fixtures/aws/cloud-kms/.
#
# shellcheck shell=bash
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a stub root cannot leak into the next case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's own identical note - the
# whole lib/ hub chain is already reachable through kms_engine.sh's own
# runtime-guarded source of engine.sh, and following it here from a second
# entry point would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking the module's own entry point does not already do.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/kms_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-kms
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath - tests/suites/cloud-s3.sh's own
# note explains the macOS /var -> /private/var $TMPDIR symlink hazard this
# avoids.
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-kms
GOOD=1111aaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
BAD=2222bbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
AWSM=3333cccc-cccc-cccc-cccc-cccccccccccc
DENY=4444dddd-dddd-dddd-dddd-dddddddddddd
INEL=5555eeee-eeee-eeee-eeee-eeeeeeeeeeee
GOOD_ARN="arn:aws:kms:eu-west-2:123456789012:key/$GOOD"
BAD_ARN="arn:aws:kms:eu-west-2:123456789012:key/$BAD"
AWSM_ARN="arn:aws:kms:eu-west-2:123456789012:key/$AWSM"
DENY_ARN="arn:aws:kms:eu-west-2:123456789012:key/$DENY"
INEL_ARN="arn:aws:kms:eu-west-2:123456789012:key/$INEL"

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add kms list-keys           "$FIX/list-keys.json"

  aws_fixture_route_add_for kms describe-key "$GOOD" "$FIX/describe-key.good.json"
  aws_fixture_route_add_for kms describe-key "$BAD"  "$FIX/describe-key.bad.json"
  aws_fixture_route_add_for kms describe-key "$AWSM" "$FIX/describe-key.aws-managed.json"
  aws_fixture_route_add_for kms describe-key "$DENY" "$FIX/describe-key.deny.json"
  aws_fixture_route_add_for kms describe-key "$INEL" "$FIX/describe-key.ineligible.json"

  aws_fixture_route_add_for kms get-key-rotation-status "$GOOD" "$FIX/get-key-rotation-status.good.json"
  aws_fixture_route_add_for kms get-key-rotation-status "$BAD"  "$FIX/get-key-rotation-status.bad.json"
  aws_fixture_route_add_for kms get-key-rotation-status "$DENY" "$FIX/get-key-rotation-status.denied.err"
  # NO route for $INEL or $AWSM: kms.sh must never call this operation for
  # either, and an unmatched route fails LOUDLY at the stub - the whole point
  # of routing (tests/lib/aws-fixtures.sh's own header) - so if a future
  # regression widens the eligibility gate, this suite fails on the missing
  # route rather than silently accepting an extra call.

  aws_fixture_route_add_for kms get-key-policy "$GOOD" "$FIX/get-key-policy.hardened.json"
  aws_fixture_route_add_for kms get-key-policy "$BAD"  "$FIX/get-key-policy.public.json"
  aws_fixture_route_add_for kms get-key-policy "$DENY" "$FIX/get-key-policy.hardened.json"
  # PUBLIC, deliberately, unlike every other non-BAD key: this is what proves
  # B7 below - an ineligible-for-rotation key is still policy-checked, rather
  # than silently skipped for BOTH checks because ONE of them does not apply.
  aws_fixture_route_add_for kms get-key-policy "$INEL" "$FIX/get-key-policy.public.json"
  # NO route for $AWSM: an AWS-managed key's policy is never read either.
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

# A TAB is not a safe field separator here: it is IFS *whitespace* (POSIX XCU
# 2.6.5), so a bash `read` folds a RUN of tabs into ONE delimiter rather than
# treating each as its own field boundary - and `cis` is legitimately EMPTY
# on every check but ROTATION_DISABLED-01, which collapses it into the
# NEXT field the moment a row with an empty `cis` is read.  0x1f (US) is this
# codebase's own answer to exactly this trap (AGENTS.md, "Things measured on
# this codebase", the DAST-11 record-stream lesson) - never whitespace, so a
# run of them never collapses.  Measured: the tab-separated first draft of
# this suite passed A-B and failed C2/C5 on exactly the mechanism this
# comment describes, reproduced by hand before being fixed here.
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

kms_doc_load "$FIX/describe-key.good.json"
assert_eq CUSTOMER "$(kms_key_manager)" 'A1 describe-key: KeyManager is read'
assert_eq Enabled "$(kms_key_state)" 'A2 describe-key: KeyState is read'
assert_true "$(kms_key_is_customer_managed && echo 0 || echo 1)" 'A3 a CUSTOMER key is customer-managed'
assert_true "$(kms_key_rotation_eligible && echo 0 || echo 1)" 'A4 an enabled AWS_KMS-origin symmetric ENCRYPT_DECRYPT key is rotation-eligible'

kms_doc_load "$FIX/describe-key.aws-managed.json"
assert_true "$(kms_key_is_customer_managed && echo 1 || echo 0)" 'A5 an AWS-managed key is NOT customer-managed'

kms_doc_load "$FIX/describe-key.ineligible.json"
assert_true "$(kms_key_is_customer_managed && echo 0 || echo 1)" 'A6 an ineligible key can still be customer-managed'
assert_true "$(kms_key_rotation_eligible && echo 1 || echo 0)" \
  'A7 an asymmetric (SIGN_VERIFY) key is NOT rotation-eligible, the reading a KeyUsage-blind gate fails under'

_r=''
kms_doc_load "$FIX/get-key-rotation-status.good.json"
assert_true "$(kms_rotation_enabled_set _r && echo 0 || echo 1)" 'A8 KeyRotationEnabled true is a pass'
kms_doc_load "$FIX/get-key-rotation-status.bad.json"
assert_true "$(kms_rotation_enabled_set _r && echo 1 || echo 0)" 'A9 KeyRotationEnabled false is not'

# The policy classifier: an unqualified wildcard Allow statement is public,
# the SAME statement narrowed by any Condition is not, and a plain
# account-root grant is not. Each is asserted against the reading it fails
# under, per AGENTS.md's testing rule.
kms_doc_load "$FIX/get-key-policy.hardened.json"
_pol=$(kms_policy_field)
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 1 || echo 0)" \
  'A10 a root-only key policy is not public - the reading a bare-wildcard-anywhere-in-the-document scan fails under'

kms_doc_load "$FIX/get-key-policy.public.json"
_pol=$(kms_policy_field)
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 0 || echo 1)" \
  'A11 a policy with an unconditioned Principal "*" statement IS public, even with a root statement ahead of it'

cat >"$W/cond.json" <<'J'
{"Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Decrypt\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-example\"}}}]}"}
J
kms_doc_load "$W/cond.json"
_pol=$(kms_policy_field)
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 1 || echo 0)" \
  'A12 a wildcard Principal WITH a Condition is treated as narrowed, never public - the coarse-but-safe direction this classifier is built to fail in'

cat >"$W/deny.json" <<'J'
{"Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"}
J
kms_doc_load "$W/deny.json"
_pol=$(kms_policy_field)
assert_true "$(cloud_policy_load "$_pol" && cloud_policy_is_public && echo 1 || echo 0)" \
  'A13 a Deny statement with a wildcard principal is not a public GRANT'

# ===========================================================================
# B. One scan, five keys: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/kms-run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/kms-run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/kms-run-b/findings.jsonl")
GOOD_IDS=$(_ids_for_arn "$TBL" "$GOOD_ARN")
BAD_IDS=$(_ids_for_arn "$TBL" "$BAD_ARN")
AWSM_IDS=$(_ids_for_arn "$TBL" "$AWSM_ARN")
INEL_IDS=$(_ids_for_arn "$TBL" "$INEL_ARN")

assert_contains "$BAD_IDS" CLOUD-KMS-ROTATION_DISABLED-01 'B3 the bad key is reported for disabled rotation'
assert_contains "$BAD_IDS" CLOUD-KMS-PUBLIC_POLICY-01 'B4 the bad key is reported for its public policy'
assert_eq '' "$GOOD_IDS" 'B5 the good key in the SAME run produces no finding at all'
assert_eq '' "$AWSM_IDS" 'B6 the AWS-managed key produces no finding - it is out of scope, not silently clean'
assert_eq 'CLOUD-KMS-PUBLIC_POLICY-01' "$INEL_IDS" \
  'B7 the ineligible (asymmetric) key is still checked for a public policy, just not for rotation'

# ===========================================================================
# C. ARN, region, account, CIS, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-KMS-ROTATION_DISABLED-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"
assert_eq "$BAD_ARN" "$_c_arn" 'C1 the finding cites the key ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '3.6' "$_c_cis" 'C4 CLOUD-KMS-ROTATION_DISABLED-01 carries the cis control id authored on its check record'
# KMS is REGIONAL, unlike S3: the cell is <account>/<region>, the SAME value
# as loc_region, not a separate global cell - the reading this fails under is
# copying S3's cell literally.
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C5 the cell is <account>/<region>, matching loc_region for a regional service'

_pol_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-KMS-PUBLIC_POLICY-01" { print; exit }')
_pol_cis=$(printf '%s' "$_pol_row" | awk -F$'\x1f' '{print $5}')
assert_eq '' "$_pol_cis" \
  'C6 CLOUD-KMS-PUBLIC_POLICY-01 carries NO cis id - CIS v3.0.0 has no KMS-key-policy control, and this project never invents one'

# ===========================================================================
# D. Honesty: a denied call is a reduction; an out-of-scope key is neither.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/kms-run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" CLOUD-KMS-ROTATION_DISABLED-01 \
  'D1 a check that answered for SOME keys is in checks_run'
assert_contains "$REDUCTIONS" aws_api_access_denied \
  'D2 the AccessDenied on the DENY key rotation-status call is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'keys_unanswered=1' 'D3 the reduction says how many keys did not answer'
assert_not_contains "$(_ids_for_arn "$TBL" "$DENY_ARN")" CLOUD-KMS-ROTATION_DISABLED-01 \
  'D4 no rotation finding is invented for the key whose rotation status was never read'
# The DENY key's policy call succeeded (hardened), so it produces no finding
# either way - proving the partial denial did not suppress its OTHER check.
assert_not_contains "$(_ids_for_arn "$TBL" "$DENY_ARN")" CLOUD-KMS-PUBLIC_POLICY-01 \
  'D5 the DENY key is correctly hardened on the check that DID answer for it'

assert_not_contains "$REDUCTIONS" "key_id=$INEL" \
  'D6 the ineligible key is never reported as a coverage loss for rotation - it was correctly judged out of scope, never attempted'

# A whole-account denial: no key examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add kms list-keys           "$FIX/get-key-rotation-status.denied.err"
_run_cloud "$W/kms-run-denied"
CR3=$(_json "$W/kms-run-denied/run.json" checks_run)
assert_not_contains "$CR3" CLOUD-KMS- 'D7 a denied list-keys credits no check at all'
assert_contains "$(_json "$W/kms-run-denied/run.json" coverage_gap)" 'key list' \
  'D8 the coverage_gap says the key list could not be read'

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
    if cid.startswith('CLOUD-KMS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-KMS-ROTATION_DISABLED-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for a REGIONAL cloud service'

_routes_default
_run_cloud "$W/kms-run-sarif" --format sarif
assert_file_exists "$W/kms-run-sarif/report.sarif" 'E4 --format sarif writes report.sarif'
_SARIF=$(cat "$W/kms-run-sarif/report.sarif")
assert_contains "$_SARIF" CLOUD-KMS-ROTATION_DISABLED-01 'E5 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$BAD_ARN" 'E6 the SARIF result names the resource'
assert_contains "$_SARIF" '3.6' 'E7 the CIS control id authored on the check record reaches the SARIF rule tags'

t_summary cloud-kms
