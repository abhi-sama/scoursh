#!/usr/bin/env bash
# tests/suites/cloud-cloudfront.sh - modules/cloud/aws/live/cloudfront.sh: the
# §8.1 CloudFront read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-24).
#
# Modelled on tests/suites/cloud-s3.sh, section for section; what differs
# here because CloudFront differs from S3, rather than being restated:
#
#   1. `loc_region` IS THE LITERAL `global` FOR EVERY FINDING, AND IT AGREES
#      WITH THE CELL.  A CloudFront distribution has no per-resource AWS
#      region at all (cloudfront_engine.sh's own header), unlike an S3
#      bucket - so there is no cell-vs-resource-region split to assert the
#      way cloud-s3.sh's section C does.
#   2. ONE LIST CALL, THEN ONE `get-distribution` PER DISTRIBUTION - all five
#      checks read from the SAME per-distribution document, unlike s3.sh's
#      seven-calls-per-bucket shape.
#   3. A NON-S3 ORIGIN IS OUT OF THE ORIGIN-EXPOSURE CHECK'S SCOPE.  The
#      public distribution's second origin is a `CustomOriginConfig` (an ALB
#      backend), and case B asserts it produces NO
#      `CLOUD-CLOUDFRONT-ORIGIN_EXPOSED-01` finding - the reading a substring
#      or "any origin with no OAI" test would fail under.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-cloudfront/.
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
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/cloudfront_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-cloudfront
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise - tests/suites/cloud-s3.sh's identical note on why.
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-cloudfront
HARD=EHARD1FIXTURE
PUB=EPUB1FIXTURE
DENY=EDENY1FIXTURE
HARD_ARN="arn:aws:cloudfront::123456789012:distribution/$HARD"
PUB_ARN="arn:aws:cloudfront::123456789012:distribution/$PUB"

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add cloudfront list-distributions "$FIX/list-distributions.json"

  if [[ $omit != get-distribution ]]; then
    aws_fixture_route_add_for cloudfront get-distribution "$HARD" "$FIX/get-distribution.hardened.json"
    aws_fixture_route_add_for cloudfront get-distribution "$PUB"  "$FIX/get-distribution.public.json"
    aws_fixture_route_add_for cloudfront get-distribution "$DENY" "$FIX/get-distribution.denied.err"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess.
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR` - cloud-s3.sh's own note.
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
        loc.get('account_id', '') or '',
        loc.get('sub_key', '') or '',
    ]))
PY
}

_ids_for_resource() {
  local table=$1 key=$2
  printf '%s\n' "$table" | awk -F'\t' -v k="$key" '$2 == k { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

assert_status 0 'A1 allow-all permits plain HTTP' cfd_viewer_policy_allows_http allow-all
assert_status 1 'A2 redirect-to-https does not' cfd_viewer_policy_allows_http redirect-to-https
assert_status 1 'A3 https-only does not' cfd_viewer_policy_allows_http https-only

assert_status 1 'A4 TLSv1.2_2021 is not weak' cfd_min_protocol_is_weak TLSv1.2_2021
assert_status 1 'A5 TLSv1.2_2018 is not weak (matched by prefix)' cfd_min_protocol_is_weak TLSv1.2_2018
assert_status 0 'A6 TLSv1 (the CloudFront default-certificate floor) is weak' cfd_min_protocol_is_weak TLSv1
assert_status 0 'A7 TLSv1_2016 is weak' cfd_min_protocol_is_weak TLSv1_2016
assert_status 0 'A8 TLSv1.1_2016 is weak' cfd_min_protocol_is_weak TLSv1.1_2016
assert_status 0 'A9 SSLv3 is weak' cfd_min_protocol_is_weak SSLv3

# ===========================================================================
# B. One scan, three distributions: fires on the public one, quiet on the
#    hardened one - and the public distribution's SECOND, non-S3 origin
#    produces no origin-exposure finding at all.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_resource "$TBL" "$PUB_ARN")
HARD_IDS=$(_ids_for_resource "$TBL" "$HARD_ARN")

for want in CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01 CLOUD-CLOUDFRONT-WEAK_MIN_TLS-01 \
  CLOUD-CLOUDFRONT-NO_WAF-01 CLOUD-CLOUDFRONT-ORIGIN_EXPOSED-01 CLOUD-CLOUDFRONT-NO_LOGGING-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public distribution is reported by $want"
done

# ... and the hardened distribution, in the SAME run, produces no finding at
# all - the half a pack gone inert would also pass (cloud-s3.sh's own
# reasoning for asserting both from one run).
assert_eq '' "$HARD_IDS" 'B4 the hardened distribution in the SAME run produces no finding at all'

# Exactly ONE origin-exposure finding on the public distribution, not two -
# its second origin is a CustomOriginConfig (a plain ALB backend), and OAC/OAI
# is exclusively an S3-origin mechanism.  The reading this fails under treats
# "no OriginAccessIdentity" as sufficient on its own, which would flag the ALB
# origin too since that field is simply absent from a non-S3 origin.
_origin_count=$(printf '%s\n' "$TBL" | awk -F'\t' -v k="$PUB_ARN" \
  '$1 == "CLOUD-CLOUDFRONT-ORIGIN_EXPOSED-01" && $2 == k' | grep -c .)
assert_eq '1' "$_origin_count" 'B5 the origin-exposure check fires exactly once - only for the S3 origin, never the custom (ALB) one'

# ===========================================================================
# C. Finding citation: ARN, region (always `global`), account, cell.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F'\t' -v k="$PUB_ARN" '$1 == "CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01" && $2 == k { print; exit }')
IFS=$'\t' read -r _c_id _c_arn _c_region _c_cell _c_account _c_sub <<<"$_row"

assert_eq "$PUB_ARN" "$_c_arn" 'C1 the finding cites the distribution ARN, read from the API, never constructed'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'global' "$_c_region" 'C3 the finding cites region `global` - CloudFront has no per-resource region'
assert_eq '123456789012/global' "$_c_cell" 'C4 the cell is <account>/global, matching the pass that actually covered it'

# No `cis:` on any CLOUD-CLOUDFRONT-* record (CIS v3.0.0 has no CloudFront
# section) - so no finding here carries one.
_cis_present=$(python3 - "$W/run-b/findings.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    if f.get('check_id', '').startswith('CLOUD-CLOUDFRONT-') and f.get('cis'):
        print(f['check_id'])
PY
)
assert_eq '' "$_cis_present" 'C5 no CLOUD-CLOUDFRONT-* finding carries a cis control id (v3.0.0 has no CloudFront section)'

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
assert_eq "$_nf" "$_nfp" 'C6 every finding in the run has a distinct fingerprint'

# ===========================================================================
# D. Honesty: a denied `get-distribution` is a reduction, never silence, and
#    it does not suppress the OTHER two distributions' real answers.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01' \
  'D1 a check that answered for SOME distributions is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the denied get-distribution call is recorded as a coverage_reduction, never silence'
assert_contains "$REDUCTIONS" "distribution=$DENY" 'D3 the reduction names the specific distribution that was denied'
assert_not_contains "$(_ids_for_resource "$TBL" "arn:aws:cloudfront::123456789012:distribution/$DENY")" \
  'CLOUD-CLOUDFRONT' 'D4 no finding is invented for the distribution that was never read'

# A wholly denied account: the list call fails, nothing credited, and the gap
# is stated where a consumer reads it.  The reading D6 fails under is exit 0
# with an empty findings set and no explanation.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add cloudfront list-distributions "$FIX/get-distribution.denied.err"
_run_cloud "$W/run-denied"
assert_eq '0' "$_RC" 'D5 a wholly-denied account still exits 0 (a coverage gap, not a tool failure)'
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-CLOUDFRONT-' 'D6 a denied distribution list credits no check at all'
assert_contains "$(cat "$W/run-denied/report.md")" 'distribution list' \
  'D7 ... and report.md, the surface a consumer actually reads, names the failed call'

# A check denied for EVERY distribution must NOT be in checks_run.
_routes_default get-distribution
aws_fixture_route_add cloudfront get-distribution "$FIX/get-distribution.denied.err"
_run_cloud "$W/run-alldenied"
CR3=$(_json "$W/run-alldenied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-CLOUDFRONT-' \
  'D8 every get-distribution call denied credits no CLOUD-CLOUDFRONT-* check at all'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_eq '123456789012' "$(_json "$RUNJSON" cloud.account_id)" 'E1 run.json records the scanned account'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E2 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E3 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-CLOUDFRONT-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01 account-region 123456789012/global' \
  'E4 the run wrote a real account-region coverage cell for cloudfront, cell = <account>/global'

assert_file_exists "$W/run-b/report.md" 'E5 report.md written'
assert_file_exists "$W/run-b/report.html" 'E6 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$PUB_ARN" 'E7 report.md names the distribution ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E8 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-CLOUDFRONT-NO_WAF-01' 'E9 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$PUB_ARN" 'E10 the SARIF result names the resource'

t_summary cloud-cloudfront
