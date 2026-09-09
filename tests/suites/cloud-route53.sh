#!/usr/bin/env bash
# tests/suites/cloud-route53.sh - modules/cloud/aws/live/route53.sh: the
# §8.1 Route53 dangling-record (S3-website subdomain-takeover) check
# (docs/STEP6-CLOUD-PLAN.md CLOUD-11).
#
# Mirrors tests/suites/cloud-s3.sh's own shape - see that suite's header for
# the full five-point reasoning. SPECIFIC to this suite: `route53` is
# `global` like `s3`, but UNLIKE s3 its `loc_region` is the literal string
# `global` too (a hosted zone has no per-resource region to resolve), so
# section C asserts region==cell's region component, not a divergence; and
# the check's own scope decision (S3-website ALIAS/CNAME only) means several
# record shapes in one zone must produce NO finding at all - a wildcard
# record, an unrelated record type, and a CloudFront alias - which section B
# pins alongside the two S3-website records that DO discriminate.
#
# NO NETWORK AND NO AWS ACCOUNT: every case runs against tests/lib/aws-
# fixtures.sh's routed stub, serving tests/fixtures/aws/cloud-route53/.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/route53_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-route53
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

# `awk -F'\x1f'` does NOT reliably parse the hex escape as the real byte
# (measured: BSD/macOS awk 20200816 treats it as a literal no-op and leaves
# the whole line as ONE field, so every `$2 == ...` compare is silently
# false) - the fix is a shell variable holding the ACTUAL byte, passed to
# `-F"$SEP"`, never the hex-escape spelling in the -F argument itself.
SEP=$'\x1f'
FIX=$ROOT/tests/fixtures/aws/cloud-route53
Z1=Z1DANGLING000
Z2=Z2DENIEDZONE0
ZONE1_ARN=arn:aws:route53:::hostedzone/Z1DANGLING000

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity  "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions     "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add s3api list-buckets       "$FIX/list-buckets.json"
  aws_fixture_route_add route53 list-hosted-zones "$FIX/list-hosted-zones.json"

  if [[ $omit != list-resource-record-sets ]]; then
    aws_fixture_route_add_for route53 list-resource-record-sets "$Z1" "$FIX/list-resource-record-sets.zone1.json"
    aws_fixture_route_add_for route53 list-resource-record-sets "$Z2" "$FIX/list-resource-record-sets.denied.err"
  fi
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

_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print('\x1f'.join([
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

# ===========================================================================
# A. The classifiers, against fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

assert_true "$(route53_record_is_wildcard '\052.example.com.' && echo 0 || echo 1)" 'A1 the \052 escape is recognised as a wildcard label'
assert_true "$(route53_record_is_wildcard 'www.example.com.' && echo 1 || echo 0)" 'A2 an ordinary name is not a wildcard'

assert_true "$(route53_target_is_s3_website 'www.example.com.s3-website-us-east-1.amazonaws.com' && echo 0 || echo 1)" \
  'A3 the hyphenated S3-website endpoint form is recognised'
assert_true "$(route53_target_is_s3_website 'd123456abcdef8.cloudfront.net.' && echo 1 || echo 0)" \
  'A4 a CloudFront target is NOT an S3-website target'

assert_eq 'www.example.com' "$(route53_record_bucket_candidate 'www.example.com.')" \
  'A5 the trailing root dot is stripped from the candidate bucket name'
assert_eq 'www.example.com' "$(route53_record_bucket_candidate 'WWW.EXAMPLE.COM.')" \
  'A6 the candidate is folded to lowercase (S3 bucket names are always lowercase)'

assert_eq 'aws' "$(route53_partition_of 'arn:aws:iam::123456789012:user/x')" 'A7 partition: commercial'
assert_eq 'arn:aws:route53:::hostedzone/Z123' "$(route53_zone_arn aws '/hostedzone/Z123')" \
  'A8 the zone ARN strips the /hostedzone/ prefix the API adds to Id'

# ===========================================================================
# B. One scan, one zone with five record shapes: fires on exactly one.
# ===========================================================================
t_case 'B. discriminates among record shapes in ONE zone'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
DANGLING_ROWS=$(printf '%s\n' "$TBL" | awk -F"$SEP" '$1 == "CLOUD-ROUTE53-DANGLING_RECORD-01"')

assert_contains "$DANGLING_ROWS" 'dangling.example.com.:CNAME' \
  'B3 the CNAME to a nonexistent bucket dangles and fires'
assert_not_contains "$DANGLING_ROWS" 'www.example.com.:CNAME' \
  'B4 the CNAME to an S3-website endpoint whose bucket EXISTS is quiet'
assert_not_contains "$DANGLING_ROWS" '\\052' \
  'B5 the wildcard record is never treated as a candidate at all'
assert_not_contains "$DANGLING_ROWS" 'mail.example.com' \
  'B6 an unrelated record type (MX) is never a candidate'
assert_not_contains "$DANGLING_ROWS" 'app.example.com' \
  'B7 an ALIAS to a non-S3-website target (CloudFront) is never a candidate'
assert_eq '1' "$(printf '%s\n' "$DANGLING_ROWS" | grep -c .)" \
  'B8 exactly one finding came out of this zone, not one per record'

# ===========================================================================
# C. ARN, region ("global"), account, cell - and NO cis.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$DANGLING_ROWS" | head -n1)
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_row"

assert_eq "$ZONE1_ARN" "$_c_arn" 'C1 the finding cites the hosted zones ARN (records have none of their own)'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'global' "$_c_region" 'C3 the region is the literal string "global" - a hosted zone has no per-resource region'
assert_eq '123456789012/global' "$_c_cell" 'C4 the cell agrees with the region here (both are the accounts global namespace)'
assert_eq 'dangling.example.com.:CNAME' "$_c_sub" 'C5 the record name and type ride in loc_sub_key, differentiating records within one zone'
assert_eq '' "$_c_cis" 'C6 the finding carries NO cis value - CIS AWS Foundations Benchmark v3.0.0 has no Route53 section'

# ===========================================================================
# D. Honesty: a denied zone is a reduction, never silence; a denied bucket
#    list refuses the WHOLE check rather than guessing.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-ROUTE53-DANGLING_RECORD-01' \
  'D1 the check answered for at least one zone, so it is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the denied second zone is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'zones_unanswered=1' \
  'D3 the reduction says how many zones did not answer'

# A denied BUCKET LIST refuses the whole check - never reports every S3-
# website record as dangling just because the universe of real buckets could
# not be read (that is the direction that reads as a false positive flood).
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity  "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions     "$FIX/ec2.describe-regions.json"
aws_fixture_route_add s3api list-buckets       "$FIX/list-buckets.denied.err"
aws_fixture_route_add route53 list-hosted-zones "$FIX/list-hosted-zones.json"
_run_cloud "$W/run-nobuckets"
CR_NB=$(_json "$W/run-nobuckets/run.json" checks_run)
assert_not_contains "$CR_NB" 'CLOUD-ROUTE53-' \
  'D4 a denied bucket list credits no check at all, rather than guessing every candidate is dangling'
DANGLING_NB=$(_findings_table "$W/run-nobuckets/findings.jsonl" 2>/dev/null | awk -F"$SEP" '$1=="CLOUD-ROUTE53-DANGLING_RECORD-01"' || true)
assert_eq '' "$DANGLING_NB" 'D5 ... and no dangling-record finding is manufactured either'

# The whole account unreadable at the zone-list step.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity  "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions     "$FIX/ec2.describe-regions.json"
aws_fixture_route_add s3api list-buckets       "$FIX/list-buckets.json"
aws_fixture_route_add route53 list-hosted-zones "$FIX/list-hosted-zones.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-ROUTE53-' 'D6 a denied list-hosted-zones credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'hosted-zone list' \
  'D7 ... and the coverage_gap says the hosted-zone list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
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
    if cid.startswith('CLOUD-ROUTE53-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-ROUTE53-DANGLING_RECORD-01 account-region 123456789012/global' \
  'E3 the run wrote a real account-region coverage cell for the global pass'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$ZONE1_ARN" 'E5 report.md names the hosted zone ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-ROUTE53-DANGLING_RECORD-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$ZONE1_ARN" 'E8 the SARIF result names the resource'

t_summary cloud-route53
