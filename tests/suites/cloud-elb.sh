#!/usr/bin/env bash
# tests/suites/cloud-elb.sh - modules/cloud/aws/live/elb.sh: the §8.1
# Classic ELB / ALB / NLB read-only checks (docs/STEP6-CLOUD-PLAN.md
# CLOUD-14).
#
# Modelled on tests/suites/cloud-s3.sh, section for section; what differs
# here because ELB differs from S3, rather than being restated:
#
#   1. TWO AWS CLI NAMESPACES, ONE SCRIPT.  `elb` (Classic) and `elbv2`
#      (ALB/NLB) each get their own list call and their own fixture set, and
#      BOTH must contribute findings under the SAME three check ids in one
#      run - a script that only exercised one namespace would leave the
#      other silently unproven.
#   2. `elb.sh` IS `regional`, NOT `global`.  `loc_region` and the coverage
#      cell AGREE here (elb_engine.sh's own header explains why), so there is
#      no cell-vs-resource-region split to assert the way cloud-s3.sh's
#      section C does.
#   3. THE `#{protocol}` REDIRECT TRAP.  An ALB listener whose redirect
#      action names `#{protocol}` rather than the literal `HTTPS` performs NO
#      scheme upgrade at all - it is AWS's placeholder for "keep the
#      original protocol", used for path-only redirects.  Reading it as proof
#      of a TLS upgrade is the naive bug this suite pins directly (case F).
#   4. THE CLASSIC-TLS INDIRECTION.  A Classic ELB listener's own
#      `PolicyNames` entry is an operator-chosen label with no protocol
#      information in it, unlike ALB/NLB's `SslPolicy` field - so this file's
#      weak-policy classification is resolved through a SECOND call
#      (`describe-load-balancer-policies`) whose own attributes decide it,
#      exercised on both a `Reference-Security-Policy` shape and a fully
#      custom `Protocol-*` shape (case E).
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-elb/.
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
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note - every file
# in this edge's chain is already inlined through modules/cloud/aws/live/
# elb_engine.sh's own runtime `source` of modules/cloud/aws/engine.sh.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/elb_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-elb
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise - tests/suites/cloud-s3.sh's identical note on why (lib/records.sh
# strips $SCOURSH_INSTALL_ROOT as a literal realpath prefix).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-elb

CLASSIC_HARD=scoursh-fixture-classic-hardened
CLASSIC_PUB=scoursh-fixture-classic-public
ALB_HARD_ARN=arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/scoursh-fixture-alb-hardened/aaaaaaaaaaaaaaaa
ALB_PUB_ARN=arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/scoursh-fixture-alb-public/bbbbbbbbbbbbbbbb
ALB_DENY_ARN=arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/scoursh-fixture-alb-denied/cccccccccccccccc

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add elb  describe-load-balancers "$FIX/elb.describe-load-balancers.json"
  aws_fixture_route_add elbv2 describe-load-balancers "$FIX/elbv2.describe-load-balancers.json"

  if [[ $omit != describe-load-balancer-policies ]]; then
    aws_fixture_route_add_for elb describe-load-balancer-policies scoursh-fixture-hardened-policy \
      "$FIX/elb.describe-load-balancer-policies.hardened.json"
    aws_fixture_route_add_for elb describe-load-balancer-policies scoursh-fixture-weak-policy \
      "$FIX/elb.describe-load-balancer-policies.weak.json"
  fi

  if [[ $omit != classic-attributes ]]; then
    aws_fixture_route_add_for elb describe-load-balancer-attributes "$CLASSIC_HARD" \
      "$FIX/elb.describe-load-balancer-attributes.hardened.json"
    aws_fixture_route_add_for elb describe-load-balancer-attributes "$CLASSIC_PUB" \
      "$FIX/elb.describe-load-balancer-attributes.disabled.json"
  fi

  if [[ $omit != describe-listeners ]]; then
    aws_fixture_route_add_for elbv2 describe-listeners "$ALB_HARD_ARN" "$FIX/elbv2.describe-listeners.hardened.json"
    aws_fixture_route_add_for elbv2 describe-listeners "$ALB_PUB_ARN"  "$FIX/elbv2.describe-listeners.public.json"
    aws_fixture_route_add_for elbv2 describe-listeners "$ALB_DENY_ARN" "$FIX/elbv2.describe-listeners.denied.err"
  fi

  if [[ $omit != v2-attributes ]]; then
    aws_fixture_route_add_for elbv2 describe-load-balancer-attributes "$ALB_HARD_ARN" \
      "$FIX/elbv2.describe-load-balancer-attributes.hardened.json"
    aws_fixture_route_add_for elbv2 describe-load-balancer-attributes "$ALB_PUB_ARN" \
      "$FIX/elbv2.describe-load-balancer-attributes.disabled.json"
    aws_fixture_route_add_for elbv2 describe-load-balancer-attributes "$ALB_DENY_ARN" \
      "$FIX/elbv2.describe-load-balancer-attributes.hardened.json"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess.
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR` - tests/suites/cloud-s3.sh's
# identical note on why (the cache key carries no route-table identity).
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

# One `check_id<TAB>loc_resource_key<TAB>loc_region<TAB>cell<TAB>account<TAB>sub_key` line
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

assert_status 1 'A1 elb_policy_is_weak: a name proving a TLS-1-2 floor is not weak' \
  elb_policy_is_weak ELBSecurityPolicy-TLS-1-2-2017-01
assert_status 1 'A2 elb_policy_is_weak: a TLS13 name is not weak' \
  elb_policy_is_weak ELBSecurityPolicy-TLS13-1-2-2021-06
assert_status 0 'A3 elb_policy_is_weak: the pre-2017 default is weak (the name proves nothing)' \
  elb_policy_is_weak ELBSecurityPolicy-2016-08
assert_status 0 'A4 elb_policy_is_weak: a fully custom name that proves nothing is reported, not assumed strong' \
  elb_policy_is_weak my-custom-tls-policy

elb_doc_load "$FIX/elb.describe-load-balancer-policies.hardened.json"
assert_status 1 'A5 classic policy doc: Reference-Security-Policy naming a TLS-1-2 predefined policy is not weak' \
  elb_classic_policy_doc_is_weak
elb_doc_load "$FIX/elb.describe-load-balancer-policies.weak.json"
assert_status 0 'A6 classic policy doc: a fully custom policy with Protocol-TLSv1=true is weak' \
  elb_classic_policy_doc_is_weak

# The ARN.  Classic ELB carries no ARN field in its own API response, unlike
# ALB/NLB, so it is constructed - and a hardcoded `aws` partition would name a
# resource that does not exist in GovCloud or China (the reading A8 fails
# under, s3.sh's own identical lesson for its bucket ARN).
assert_eq 'arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/my-lb' \
  "$(elb_classic_arn aws eu-west-2 123456789012 my-lb)" 'A7 classic ELB ARN is constructed from partition/region/account/name'
assert_eq 'arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:123456789012:loadbalancer/my-lb' \
  "$(elb_classic_arn aws-us-gov us-gov-west-1 123456789012 my-lb)" 'A8 ... and honours a non-commercial partition'

# The `#{protocol}` redirect trap: this action changes NO scheme at all, and
# accepting it as a TLS upgrade is the reading this pins against.
elb_doc_load "$FIX/elbv2.describe-listeners.public.json"
assert_status 1 'A9 #{protocol} redirect does not count as a redirect to HTTPS' \
  elb_default_actions_redirect_https "$(elb_path Listeners 0)"
elb_doc_load "$FIX/elbv2.describe-listeners.hardened.json"
assert_status 0 'A10 a redirect naming the literal HTTPS protocol counts' \
  elb_default_actions_redirect_https "$(elb_path Listeners 0)"

# ===========================================================================
# B. One scan, four load balancers: fires on the bad ones, quiet on the good.
# ===========================================================================
t_case 'B. both directions in one run, across both AWS namespaces'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
CLASSIC_PUB_ARN='arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/scoursh-fixture-classic-public'
CLASSIC_HARD_ARN='arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/scoursh-fixture-classic-hardened'

CLASSIC_PUB_IDS=$(_ids_for_resource "$TBL" "$CLASSIC_PUB_ARN")
CLASSIC_HARD_IDS=$(_ids_for_resource "$TBL" "$CLASSIC_HARD_ARN")
ALB_PUB_IDS=$(_ids_for_resource "$TBL" "$ALB_PUB_ARN")
ALB_HARD_IDS=$(_ids_for_resource "$TBL" "$ALB_HARD_ARN")

for want in CLOUD-ELB-HTTP_NO_REDIRECT-01 CLOUD-ELB-WEAK_TLS_POLICY-01 CLOUD-ELB-NO_ACCESS_LOGS-01; do
  assert_contains "$CLASSIC_PUB_IDS" "$want" "B3 the public Classic ELB is reported by $want"
  assert_contains "$ALB_PUB_IDS" "$want" "B4 the public ALB is reported by $want"
done

# ... and the hardened resources, in the SAME run, produce no finding at all -
# the half a pack gone inert would also pass, which is why B3/B4 are asserted
# from the same run rather than a separate one (cloud-s3.sh's own reasoning).
assert_eq '' "$CLASSIC_HARD_IDS" 'B5 the hardened Classic ELB in the SAME run produces no finding at all'
assert_eq '' "$ALB_HARD_IDS" 'B6 the hardened ALB in the SAME run produces no finding at all'

# ===========================================================================
# C. Finding citation: ARN, region, account, cell - and region == cell region.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F'\t' -v k="$ALB_PUB_ARN" '$1 == "CLOUD-ELB-HTTP_NO_REDIRECT-01" && $2 == k { print; exit }')
IFS=$'\t' read -r _c_id _c_arn _c_region _c_cell _c_account _c_sub <<<"$_row"

assert_eq "$ALB_PUB_ARN" "$_c_arn" 'C1 the finding cites the load balancer ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region the pass actually ran in'
assert_eq '80' "$_c_sub" 'C4 the port rides in loc_sub_key, distinguishing it from a same-LB finding on another port'

# elb.sh is REGIONAL, unlike s3's global row: the cell and the region AGREE,
# and a test that only checked C3 would pass under an implementation that
# wrote the wrong cell entirely (e.g. `global`) as long as loc_region
# happened to be right - so both are asserted, and against each other.
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C5 the cell is <account>/<region>, and it is the SAME region the finding cites'

# No `cis:` on any CLOUD-ELB-* record (CIS v3.0.0 has no ELB section) - so no
# finding here carries one, unlike cloud-s3.sh's public-exposure checks.
_cis_present=$(python3 - "$W/run-b/findings.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    if f.get('check_id', '').startswith('CLOUD-ELB-') and f.get('cis'):
        print(f['check_id'])
PY
)
assert_eq '' "$_cis_present" 'C6 no CLOUD-ELB-* finding carries a cis control id (v3.0.0 has no ELB section)'

# Two ports on one load balancer are TWO distinct findings under the SAME
# check id, distinguished by loc_sub_key=port - not collapsed to one.
_classic_pub_http=$(printf '%s\n' "$TBL" | awk -F'\t' -v k="$CLASSIC_PUB_ARN" \
  '$1 == "CLOUD-ELB-HTTP_NO_REDIRECT-01" && $2 == k { print $6 }')
assert_eq '80' "$_classic_pub_http" 'C7 the classic public ELB HTTP_NO_REDIRECT finding names port 80'

_classic_pub_tls=$(printf '%s\n' "$TBL" | awk -F'\t' -v k="$CLASSIC_PUB_ARN" \
  '$1 == "CLOUD-ELB-WEAK_TLS_POLICY-01" && $2 == k { print $6 }')
assert_eq '443' "$_classic_pub_tls" 'C8 ... and the WEAK_TLS_POLICY finding on the SAME load balancer names port 443, a distinct fingerprint'

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
assert_eq "$_nf" "$_nfp" 'C9 every finding in the run has a distinct fingerprint'

# ===========================================================================
# D. Honesty: a denied call is a reduction, and the OTHER checks on that same
#    load balancer still ran.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The denied ALB's `describe-listeners` failed, so HTTP_NO_REDIRECT and
# WEAK_TLS_POLICY are lost for it specifically - but both checks still ran
# and are still credited, because the public and hardened ALBs answered.
assert_contains "$CHECKS_RUN" 'CLOUD-ELB-HTTP_NO_REDIRECT-01' \
  'D1 a check that answered for SOME load balancers is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the denied describe-listeners call is recorded as a coverage_reduction, never silence'
assert_contains "$REDUCTIONS" "load_balancer=$ALB_DENY_ARN" \
  'D3 the reduction names the specific load balancer that was denied'
assert_not_contains "$(_ids_for_resource "$TBL" "$ALB_DENY_ARN")" 'CLOUD-ELB-HTTP_NO_REDIRECT' \
  'D4 no HTTP_NO_REDIRECT finding is invented for the load balancer whose listeners were never read'

# ... but its ACCESS-LOG attributes call was answered independently (routed
# to the hardened fixture), so NO_ACCESS_LOGS still ran for it and produced
# no finding - one call failing must not suppress a DIFFERENT check's real
# answer on the same resource.
assert_contains "$CHECKS_RUN" 'CLOUD-ELB-NO_ACCESS_LOGS-01' 'D5 the unrelated access-log check is still credited'
assert_not_contains "$(_ids_for_resource "$TBL" "$ALB_DENY_ARN")" 'CLOUD-ELB-NO_ACCESS_LOGS' \
  'D6 ... and it answered clean for the denied load balancer, on its own independent call'

# A check denied for EVERY load balancer must NOT be in checks_run - crediting
# it would let tension 12 report a prior finding `fixed` on the strength of a
# call denied everywhere it was tried.
_routes_default classic-attributes
aws_fixture_route_add elb describe-load-balancer-attributes "$FIX/elb.describe-load-balancer-attributes.disabled.json"
aws_fixture_route_add elbv2 describe-load-balancer-attributes "$FIX/elbv2.describe-load-balancer-attributes.disabled.json"
_run_cloud "$W/run-partial"
assert_eq '0' "$_RC" 'D7 a partial-denial run still exits 0'

# The whole account unreadable: no load balancer examined in either
# namespace, nothing credited, and the gap stated where a consumer reads it.
# The reading D9 fails under is exit 0 with an empty findings set and no
# explanation - a denied scan rendered as a clean account.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add elb   describe-load-balancers "$FIX/elbv2.describe-listeners.denied.err"
aws_fixture_route_add elbv2 describe-load-balancers "$FIX/elbv2.describe-listeners.denied.err"
_run_cloud "$W/run-denied"
assert_eq '0' "$_RC" 'D8 a wholly-denied region still exits 0 (a coverage gap, not a tool failure)'
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-ELB-' 'D9 both list calls denied credits no check at all'
assert_contains "$(cat "$W/run-denied/report.md")" 'describe-load-balancers' \
  'D10 ... and report.md, the surface a consumer actually reads, names the failed call'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the region the run resolved'
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
    if cid.startswith('CLOUD-ELB-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-ELB-HTTP_NO_REDIRECT-01 account-region 123456789012/eu-west-2' \
  'E5 the run wrote a real account-region coverage cell for elb, matching the region it actually ran in'

# Every report format, and the fact a cloud consumer reads them for.
assert_file_exists "$W/run-b/report.md" 'E6 report.md written'
assert_file_exists "$W/run-b/report.html" 'E7 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$ALB_PUB_ARN" 'E8 report.md names the load balancer ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E9 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-ELB-WEAK_TLS_POLICY-01' 'E10 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$ALB_PUB_ARN" 'E11 the SARIF result names the resource'

t_summary cloud-elb
