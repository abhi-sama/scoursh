#!/usr/bin/env bash
# tests/suites/cloud-redshift.sh - modules/cloud/aws/live/redshift.sh: the
# §8.1 Redshift read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-18).
#
# Mirrors tests/suites/cloud-s3.sh's own shape (read that suite's header
# first). What is specific to this service:
#
#   1. TWO OF THREE CHECKS ARE DIRECT API BOOLEANS (PubliclyAccessible,
#      Encrypted) - no heuristic, `confidence: high` for both, and section A
#      pins them read straight off `describe-clusters` with no second call.
#   2. THE THIRD CHECK NEEDS A SECOND, PER-CLUSTER CALL
#      (`describe-cluster-parameters`) keyed on the cluster's OWN parameter
#      group name, and section D exercises that call being denied
#      independently of the first call succeeding - a partial loss on ONE of
#      the three checks, not all three, unlike a denied `describe-domain` in
#      the OpenSearch suite which loses all three at once.
#
# NO NETWORK AND NO AWS ACCOUNT.  tests/lib/aws-fixtures.sh's routed stub,
# fixtures under tests/fixtures/aws/cloud-redshift/.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/redshift_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-redshift
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-redshift
PUB=scoursh-fixture-public-cluster
HARD=scoursh-fixture-hardened-cluster
DENY=scoursh-fixture-denied-cluster
PUB_PG=scoursh-fixture-public-pg
HARD_PG=scoursh-fixture-hardened-pg
DENY_PG=scoursh-fixture-denied-pg

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add redshift describe-clusters "$FIX/describe-clusters.json"

  if [[ $omit != describe-cluster-parameters ]]; then
    aws_fixture_route_add_for redshift describe-cluster-parameters "$PUB_PG"  "$FIX/describe-cluster-parameters.public.json"
    aws_fixture_route_add_for redshift describe-cluster-parameters "$HARD_PG" "$FIX/describe-cluster-parameters.hardened.json"
    aws_fixture_route_add_for redshift describe-cluster-parameters "$DENY_PG" "$FIX/describe-cluster-parameters.denied.err"
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

# Fields are 0x1f-separated, NEVER tab - see tests/suites/cloud-opensearch.sh's
# identical note: `cis` is legitimately empty for two of these three checks,
# and tab is POSIX "IFS whitespace", so `read` under `IFS=$'\t'` collapses a
# run of them and silently drops an empty middle field.
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
    ]))
PY
}

_ids_for_cluster() {
  local table=$1 cluster=$2
  printf '%s\n' "$table" | awk -F'\037' -v c="cluster:$cluster" '$2 ~ c { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

redshift_doc_load "$FIX/describe-cluster-parameters.public.json"
assert_true "$(redshift_require_ssl_enabled && echo 1 || echo 0)" 'A1 the public cluster parameter group leaves require_ssl false'
redshift_doc_load "$FIX/describe-cluster-parameters.hardened.json"
assert_true "$(redshift_require_ssl_enabled && echo 0 || echo 1)" 'A2 the hardened cluster parameter group sets require_ssl true'

# A parameter list that never mentions require_ssl at all is NOT a pass - the
# reading A3 fails under is treating "not found" as "not set, therefore ok".
cat >"$W/no-require-ssl.json" <<'J'
{"Parameters": [{"ParameterName": "statement_timeout", "ParameterValue": "0"}]}
J
redshift_doc_load "$W/no-require-ssl.json"
assert_true "$(redshift_require_ssl_enabled && echo 1 || echo 0)" 'A3 an absent require_ssl parameter is treated as NOT enabled'

assert_eq 'arn:aws:redshift:eu-west-2:123456789012:cluster:my-cluster' \
  "$(redshift_cluster_arn aws eu-west-2 123456789012 my-cluster)" \
  'A4 the ARN is the constructed cluster:<identifier> form, never the namespace ARN'

# ===========================================================================
# B. One scan, three clusters: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_cluster "$TBL" "$PUB")
HARD_IDS=$(_ids_for_cluster "$TBL" "$HARD")

for want in CLOUD-REDSHIFT-PUBLIC_ACCESS-01 CLOUD-REDSHIFT-NO_ENCRYPTION_AT_REST-01 \
  CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public cluster is reported by $want"
done
assert_eq '' "$HARD_IDS" 'B4 the hardened cluster in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account, cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F'\037' '$1 == "CLOUD-REDSHIFT-PUBLIC_ACCESS-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "arn:aws:redshift:eu-west-2:123456789012:cluster:$PUB" "$_c_arn" 'C1 the finding cites the CONSTRUCTED cluster ARN, not the namespace ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell equals the region, since redshift is a regional service'
assert_eq '' "$_c_cis" 'C5 no cis id is cited - CIS v3.0.0 has no Redshift section'

# ===========================================================================
# D. Honesty: a denied call is a reduction, scoped to the ONE check it
#    affects rather than all three.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-REDSHIFT-PUBLIC_ACCESS-01' \
  'D1 the direct-field checks are covered for every cluster including the one whose param call was denied'
assert_contains "$CHECKS_RUN" 'CLOUD-REDSHIFT-NO_ENCRYPTION_AT_REST-01' 'D1b ... both of them'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the denied cluster''s describe-cluster-parameters is recorded as a coverage_reduction'
DENY_IDS=$(_ids_for_cluster "$TBL" "$DENY")
assert_eq '' "$DENY_IDS" \
  'D3 the denied cluster is not itself public or unencrypted in the fixture, so it produces no finding (only lost coverage on the in-transit check)'
assert_contains "$REDUCTIONS" "check=CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01" \
  'D4 the reduction names the SPECIFIC check the denied call affects, not all three'

# A check denied for EVERY cluster's param group must not be in checks_run.
_routes_default describe-cluster-parameters
aws_fixture_route_add redshift describe-cluster-parameters "$FIX/describe-cluster-parameters.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01' \
  'D5 a check denied for every cluster is absent from checks_run'
assert_contains "$CR2" 'CLOUD-REDSHIFT-PUBLIC_ACCESS-01' \
  'D6 ... while the direct-field checks, unaffected by the denial, are still credited'
assert_contains "$RED2" 'check=CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01' \
  'D7 ... and it has its own coverage_reduction saying so'

# The whole account unreadable: no cluster examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add redshift describe-clusters "$FIX/describe-cluster-parameters.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-REDSHIFT-' 'D8 a denied describe-clusters credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'cluster list' \
  'D9 ... and the coverage_gap says the cluster list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

_routes_default
_run_cloud "$W/run-e"
RUNJSON2=$W/run-e/run.json
RUN_ID=$(_json "$RUNJSON2" run_id)
assert_ne '' "$RUN_ID" 'E1 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E2 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-REDSHIFT-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-REDSHIFT-PUBLIC_ACCESS-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for this service'

assert_file_exists "$W/run-e/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-e/report.md")
assert_contains "$_MD" "arn:aws:redshift:eu-west-2:123456789012:cluster:$PUB" 'E5 report.md names the cluster ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-REDSHIFT-PUBLIC_ACCESS-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "arn:aws:redshift:eu-west-2:123456789012:cluster:$PUB" 'E8 the SARIF result names the resource'

t_summary cloud-redshift
