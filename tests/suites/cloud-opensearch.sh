#!/usr/bin/env bash
# tests/suites/cloud-opensearch.sh - modules/cloud/aws/live/opensearch.sh: the
# §8.1 OpenSearch read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-17).
#
# Mirrors tests/suites/cloud-s3.sh's own shape and reasoning (read that
# suite's header first - it is not repeated here in full): one scan visits a
# public, a hardened and a permission-denied domain in the SAME run, so "the
# check fires" and "the check stays quiet" are asserted against one code path
# rather than two separate runs that could each go inert unnoticed.
#
# What is specific to this service, over and above the s3 suite's own list:
#
#   1. THE PUBLIC-ACCESS CHECK NEEDS TWO INDEPENDENT SIGNALS TO FIRE - no VPC
#      AND a wide-open policy - and section B's hardened domain is
#      deliberately VPC-attached so this is exercised, not merely a policy
#      difference.
#   2. THE CELL AND THE REGION ARE THE SAME VALUE, unlike S3's global pass:
#      `opensearch` is `regional`, so every domain examined in one pass is
#      genuinely in that pass's own region and there is no bucket-style
#      resource-region-vs-cell split to assert.
#   3. A DENIED describe-domain LOSES ALL THREE CHECKS FOR THAT DOMAIN AT
#      ONCE, never a partial finding - unlike S3's per-property calls, one
#      OpenSearch API call answers every check here.
#
# NO NETWORK AND NO AWS ACCOUNT.  tests/lib/aws-fixtures.sh's routed stub,
# fixtures under tests/fixtures/aws/cloud-opensearch/.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note - the
# module's engine.sh (and the whole lib/ hub chain behind it) is already
# inlined elsewhere for this entry point's own graph.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/opensearch_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-opensearch
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-opensearch
PUB=scoursh-fixture-public-domain
HARD=scoursh-fixture-hardened-domain
DENY=scoursh-fixture-denied-domain

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add opensearch list-domain-names "$FIX/list-domain-names.json"

  if [[ $omit != describe-domain ]]; then
    aws_fixture_route_add_for opensearch describe-domain "$PUB"  "$FIX/describe-domain.public.json"
    aws_fixture_route_add_for opensearch describe-domain "$HARD" "$FIX/describe-domain.hardened.json"
    aws_fixture_route_add_for opensearch describe-domain "$DENY" "$FIX/describe-domain.denied.err"
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

# Fields are 0x1f-separated, NEVER tab: `cis` is legitimately empty for six of
# these nine checks (no CIS v3.0.0 OpenSearch/Redshift section exists), and a
# tab is POSIX "IFS whitespace" - `read -r ... <<<"$row"` under `IFS=$'\t'`
# COLLAPSES a run of them, silently dropping the empty middle field and
# shifting every later one left by one, which is precisely AGENTS.md's own
# "Sharp edges" lesson for DAST-11's markup engine (`modules/dast/passive/
# markup_engine.sh`) applied to a test helper instead of shipped code.
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

_ids_for_domain() {
  local table=$1 domain=$2
  printf '%s\n' "$table" | awk -F'\037' -v d="domain/$domain" '$2 ~ d { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

opensearch_doc_load "$FIX/describe-domain.public.json"
assert_true "$(opensearch_is_vpc_attached && echo 1 || echo 0)" 'A1 public domain: no VPCOptions'
assert_true "$(opensearch_is_publicly_open && echo 0 || echo 1)" 'A2 public domain: wide-open policy + no VPC is publicly open'
assert_true "$(opensearch_encrypted_at_rest && echo 1 || echo 0)" 'A3 public domain: encryption at rest is off'
assert_true "$(opensearch_encrypted_in_transit && echo 1 || echo 0)" 'A4 public domain: node-to-node encryption is off'
_arn=''
opensearch_arn_set _arn
assert_eq "arn:aws:es:eu-west-2:123456789012:domain/$PUB" "$_arn" 'A5 the ARN is read verbatim off DomainStatus.ARN'

opensearch_doc_load "$FIX/describe-domain.hardened.json"
assert_true "$(opensearch_is_vpc_attached && echo 0 || echo 1)" 'A6 hardened domain: VPCOptions present'
assert_true "$(opensearch_is_publicly_open && echo 1 || echo 0)" \
  'A7 hardened domain: VPC-attached is NOT publicly open even though a policy exists'
assert_true "$(opensearch_encrypted_at_rest && echo 0 || echo 1)" 'A8 hardened domain: encryption at rest is on'
assert_true "$(opensearch_encrypted_in_transit && echo 0 || echo 1)" 'A9 hardened domain: node-to-node encryption is on'

# A domain with a wide-open policy but IN a VPC is not publicly open - the
# reading A10 fails under is a policy-only test that ignores VPC placement
# entirely, which would flag a domain no internet host can even route to.
cat >"$W/vpc-but-open.json" <<'J'
{
  "DomainStatus": {
    "ARN": "arn:aws:es:eu-west-2:123456789012:domain/vpc-but-open",
    "VPCOptions": {"VPCId": "vpc-0123456789abcdef0"},
    "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"es:*\",\"Resource\":\"*\"}]}",
    "EncryptionAtRestOptions": {"Enabled": true},
    "NodeToNodeEncryptionOptions": {"Enabled": true}
  }
}
J
opensearch_doc_load "$W/vpc-but-open.json"
assert_true "$(opensearch_is_publicly_open && echo 1 || echo 0)" \
  'A10 a wide-open policy on a VPC-attached domain is NOT reported public'

# ===========================================================================
# B. One scan, three domains: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_domain "$TBL" "$PUB")
HARD_IDS=$(_ids_for_domain "$TBL" "$HARD")

for want in CLOUD-OPENSEARCH-PUBLIC_ACCESS-01 CLOUD-OPENSEARCH-NO_ENCRYPTION_AT_REST-01 \
  CLOUD-OPENSEARCH-NO_ENCRYPTION_IN_TRANSIT-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public domain is reported by $want"
done
assert_eq '' "$HARD_IDS" 'B4 the hardened domain in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account, cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F'\037' '$1 == "CLOUD-OPENSEARCH-PUBLIC_ACCESS-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "arn:aws:es:eu-west-2:123456789012:domain/$PUB" "$_c_arn" 'C1 the finding cites the domain ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell equals the region, since opensearch is a regional service'
assert_eq '' "$_c_cis" 'C5 no cis id is cited - CIS v3.0.0 has no OpenSearch section'

# ===========================================================================
# D. Honesty: a denied call is a reduction; nothing is invented for it.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-OPENSEARCH-PUBLIC_ACCESS-01' \
  'D1 a check that answered for SOME domains is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the denied domain is recorded as a coverage_reduction'
assert_eq '' "$(_ids_for_domain "$TBL" "$DENY")" \
  'D3 no finding is invented for the domain whose describe-domain call was denied'

# A denied domain-list call: no domain examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add opensearch list-domain-names "$FIX/describe-domain.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-OPENSEARCH-' 'D4 a denied list-domain-names credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'domain list' \
  'D5 ... and the coverage_gap says the domain list could not be read'

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
    if cid.startswith('CLOUD-OPENSEARCH-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-OPENSEARCH-PUBLIC_ACCESS-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for this service'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "arn:aws:es:eu-west-2:123456789012:domain/$PUB" 'E5 report.md names the domain ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-OPENSEARCH-PUBLIC_ACCESS-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "arn:aws:es:eu-west-2:123456789012:domain/$PUB" 'E8 the SARIF result names the resource'

t_summary cloud-opensearch
