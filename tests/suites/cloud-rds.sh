#!/usr/bin/env bash
# tests/suites/cloud-rds.sh - modules/cloud/aws/live/rds.sh: the §8.1 RDS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-15).
#
# What this suite exists to pin, mirroring tests/suites/cloud-s3.sh's own
# reasoning (see that file's header for the full argument each of these five
# points makes):
#
#   1. BOTH DIRECTIONS, IN ONE RUN - a public/unencrypted/backup-less instance
#      and a hardened one are examined by the SAME scan.
#   2. EVERY FINDING CITES ARN, REGION, ACCOUNT AND - WHERE ONE EXISTS - CIS.
#   3. THE CELL IS `<account>/<region>`, THE SAME REGION THE FINDING CITES -
#      unlike S3's global/per-bucket split, `rds` is a REGIONAL service, so
#      this is the ordinary case tension 12 is built around rather than the
#      exception S3 argues for.
#   4. A DENIED CALL IS A coverage_reduction, NEVER SILENCE - at BOTH the
#      list-level (the whole instance/snapshot list) and the per-resource
#      level (one snapshot's own attributes).
#   5. THE FINDING ROUND-TRIPS - into findings.jsonl, into a real
#      account-region coverage cell, and into every report format.
#
# PLUS ONE THING SPECIFIC TO THIS SERVICE: RDS's OWN TRUNCATION SIGNAL. Every
# RDS describe-* operation paginates with a bare `Marker`, which
# lib/awscli.sh's shared `_awscli_detect_truncation` does not recognise (see
# rds_engine.sh's own header) - section F below proves this file's own
# detection catches what the shared one would miss.
#
# NO NETWORK AND NO AWS ACCOUNT. Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-rds/.
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
# -x back-edge cut: see tests/suites/cloud-s3.sh's own identical note - every
# file this edge would reach is already inlined from the module's own entry
# point, and shellcheck -x re-expands every source edge it follows.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/rds_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-rds
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath (tests/suites/cloud-s3.sh documents
# the same macOS /var -> /private/var $TMPDIR hazard).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-rds
PUB=scoursh-fixture-public-db
HARD=scoursh-fixture-hardened-db
PUB_ARN="arn:aws:rds:eu-west-2:123456789012:db:$PUB"
HARD_ARN="arn:aws:rds:eu-west-2:123456789012:db:$HARD"
PUB_SNAP_ARN=arn:aws:rds:eu-west-2:123456789012:snapshot:scoursh-fixture-public-db-snap
HARD_SNAP_ARN=arn:aws:rds:eu-west-2:123456789012:snapshot:scoursh-fixture-hardened-db-snap
DENY_SNAP=scoursh-fixture-denied-db-snap

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from.  An
# optional argument names ONE operation whose default fixture is swapped for
# an alternate, so a case can exercise a failure without hand-building the
# whole table - the identical `omit`-style parameter tests/suites/cloud-s3.sh's
# own `_routes_default` uses, generalised to "swap" since this suite's
# failure cases replace a fixture rather than omit a per-resource row.
_routes_default() {
  local swap_op=${1:-} swap_path=${2:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  # `s3` (CLOUD-05, already merged on dev) is a `global` row in
  # `_CLOUD_SERVICES` and runs in the SAME `scan.sh cloud --live` invocation
  # this suite drives - unrelated to what this suite tests, but its pass
  # still makes a real `aws_ro` call the stub must be able to answer. An empty
  # bucket list keeps its pass a clean, silent no-op rather than a stream of
  # "no route registered" noise this suite has no reason to route around.
  aws_fixture_route_add s3api list-buckets "$FIX/list-buckets.empty.json"

  if [[ $swap_op == describe-db-instances ]]; then
    aws_fixture_route_add rds describe-db-instances "$swap_path"
  else
    aws_fixture_route_add rds describe-db-instances "$FIX/describe-db-instances.json"
  fi

  if [[ $swap_op == describe-db-snapshots ]]; then
    aws_fixture_route_add rds describe-db-snapshots "$swap_path"
  else
    aws_fixture_route_add rds describe-db-snapshots "$FIX/describe-db-snapshots.json"
  fi

  aws_fixture_route_add_for rds describe-db-snapshot-attributes scoursh-fixture-public-db-snap \
    "$FIX/describe-db-snapshot-attributes.public.json"
  aws_fixture_route_add_for rds describe-db-snapshot-attributes scoursh-fixture-hardened-db-snap \
    "$FIX/describe-db-snapshot-attributes.shared.json"
  aws_fixture_route_add_for rds describe-db-snapshot-attributes "$DENY_SNAP" \
    "$FIX/describe-db-snapshot-attributes.denied.err"
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess,
# byte-identical reasoning to tests/suites/cloud-s3.sh's own `_run_cloud`: a
# subprocess exercises the CLI parser, the dispatch arm, the check-registry
# load and the exit-code precedence table together, and each invocation gets
# its OWN cache dir so two cases with different route tables are never served
# from one shared cache keyed only on service|region|account|op|args.
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

# One `check_id<TAB>loc_resource_key<TAB>loc_region<TAB>cell<TAB>cis<TAB>account<TAB>sub_key` line
# per finding - byte-identical shape to tests/suites/cloud-s3.sh's own
# `_findings_table`.
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
        ','.join(f.get('cis') or []),
        loc.get('account_id', '') or '',
        loc.get('sub_key', '') or '',
    ]))
PY
}

_ids_for_resource() {
  local table=$1 key=$2
  printf '%s\n' "$table" | awk -F'\t' -v k="$key" '$2 == k { print $1 }' | LC_ALL=C sort
}

# `_row_col ROW N` - the Nth tab-separated field of ROW, via `awk -F` rather
# than `IFS=$'\t' read`.  Bash's `read` treats a tab as one of its default
# "blank" IFS characters REGARDLESS of being explicitly assigned, so it
# COLLAPSES a run of them and silently drops an EMPTY middle field - measured
# directly (`IFS=$'\t' read -r a b c d e f g <<<"1<TAB>2<TAB>3<TAB><TAB>5<TAB>6"`
# yields `d=5 e=6 f=<empty> g=<empty>`, not `d=<empty> e=5 f=6`). A row whose
# `cis` column is legitimately empty (CLOUD-RDS-NO_BACKUPS-01: CIS v3.0.0 has
# no RDS backup-retention control) is exactly the shape that trips this, so
# `read` is never used on a `_findings_table` row in this suite.
_row_col() {
  awk -F'\t' -v n="$2" '{print $n}' <<<"$1"
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

rds_doc_load "$FIX/describe-db-instances.json"
assert_eq "$PUB" "${_RDS_DOC[$(rds_path DBInstances 0 DBInstanceIdentifier)]:-}" \
  'A1 describe-db-instances: the first instance identifier is read'
assert_true "$(rds_doc_has "$(rds_path DBInstances 1 DBInstanceIdentifier)" && echo 0 || echo 1)" \
  'A2 the second instance is present (the walk does not stop early)'
assert_true "$(rds_doc_has "$(rds_path DBInstances 2 DBInstanceIdentifier)" && echo 1 || echo 0)" \
  'A3 there is no third instance (the walk has a real end)'

# The truncation sharp edge this file's header names: a `Marker` key, which
# `_awscli_detect_truncation`'s frozen vocabulary does not recognise at all.
# The reading A4/A5 fail under is trusting SCOURSH_AWS_RO_OUTCOME alone, which
# would report this exact fixture as a complete, untruncated list.
rds_doc_load "$FIX/describe-db-instances.json"
assert_true "$(rds_marker_present && echo 1 || echo 0)" \
  'A4 an untruncated response (no Marker key) is NOT reported as truncated'
rds_doc_load "$FIX/describe-db-instances.truncated.json"
assert_true "$(rds_marker_present && echo 0 || echo 1)" \
  'A5 a response carrying a Marker IS reported as truncated'

# The snapshot-public classifier. A SHARE with a specific account id is not
# the same fact as `all`, and the reading A7 fails under is a bare
# non-empty-AttributeValues test, which would flag an ordinary cross-account
# backup-copy share as a public exposure.
rds_doc_load "$FIX/describe-db-snapshot-attributes.public.json"
assert_true "$(rds_snapshot_attribute_is_public && echo 0 || echo 1)" \
  'A6 restore=[all] IS public'
rds_doc_load "$FIX/describe-db-snapshot-attributes.shared.json"
assert_true "$(rds_snapshot_attribute_is_public && echo 1 || echo 0)" \
  'A7 restore=[a specific account id] is a SHARE, not a public exposure'

# ===========================================================================
# B. One scan, two instances: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_resource "$TBL" "$PUB_ARN")
HARD_IDS=$(_ids_for_resource "$TBL" "$HARD_ARN")

for want in CLOUD-RDS-PUBLIC_ACCESS-01 CLOUD-RDS-NO_ENCRYPTION-01 CLOUD-RDS-NO_BACKUPS-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public/unencrypted/backup-less instance is reported by $want"
done
assert_eq '' "$HARD_IDS" 'B4 the hardened instance in the SAME run produces no instance-level finding'

# The snapshot check, on the SAME resource keys as B3/B4 above.
PUB_SNAP_IDS=$(_ids_for_resource "$TBL" "$PUB_SNAP_ARN")
HARD_SNAP_IDS=$(_ids_for_resource "$TBL" "$HARD_SNAP_ARN")
assert_contains "$PUB_SNAP_IDS" CLOUD-RDS-PUBLIC_SNAPSHOT-01 \
  'B5 the snapshot shared with "all" fires CLOUD-RDS-PUBLIC_SNAPSHOT-01'
assert_eq '' "$HARD_SNAP_IDS" \
  'B6 the snapshot shared with one named account produces no public-snapshot finding'

# The automated snapshot in the fixture (`SnapshotType: automated`) must never
# reach describe-db-snapshot-attributes at all - AWS does not permit sharing
# one, so a route table with NO row for it (this suite's does not) would make
# the stub fail loudly if the script tried. Exit 0 above already proves it did
# not; this is the same fact stated from the finding side.
assert_not_contains "$TBL" 'rds:scoursh-fixture-hardened-db-2024-01-01-00-00' \
  'B7 the automated snapshot produces no finding and no attempted lookup'

# ===========================================================================
# C. ARN, region, account, CIS, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_pub_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-RDS-PUBLIC_ACCESS-01" { print; exit }')
_c_arn=$(_row_col "$_pub_row" 2)
_c_region=$(_row_col "$_pub_row" 3)
_c_cell=$(_row_col "$_pub_row" 4)
_c_cis=$(_row_col "$_pub_row" 5)
_c_account=$(_row_col "$_pub_row" 6)

assert_eq "$PUB_ARN" "$_c_arn" 'C1 the finding cites the instance ARN, read directly off the API response'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '2.3.3' "$_c_cis" 'C4 the finding carries the cis control id authored on its check record'

# UNLIKE S3, the cell and the region are the SAME value here - `rds` is
# regional, so the pass visited exactly the region the resource is in. The
# reading a test that asserted only C3 would pass under is the S3-shaped
# "cell always differs from region" implementation, which is the wrong shape
# for a regional service and would leave every remediated instance `unknown`
# forever under tension 12 the moment the cell stopped matching the pass that
# actually covered it.
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C5 the cell is <account>/<region>, matching the region the pass actually covered'

_enc_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-RDS-NO_ENCRYPTION-01" { print; exit }')
_e_cis=$(_row_col "$_enc_row" 5)
assert_eq '2.3.1' "$_e_cis" 'C6 the encryption check carries its own cis control id'

_bak_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-RDS-NO_BACKUPS-01" { print; exit }')
_b_cis=$(_row_col "$_bak_row" 5)
assert_eq '' "$_b_cis" \
  'C7 the backup/PITR check carries NO cis value - CIS v3.0.0 has no RDS backup-retention control (an honest absence, not a gap)'

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
# D. Honesty: a denied call is a reduction; a share is not a public finding.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The denied snapshot's attributes could not be read. The snapshot-public
# check still ran (two other manual snapshots answered), so it IS in
# checks_run - and the partial loss is recorded beside it.
assert_contains "$CHECKS_RUN" 'CLOUD-RDS-PUBLIC_SNAPSHOT-01' \
  'D1 a check that answered for SOME resources is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on one snapshot is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'resources_unanswered=1' \
  'D3 the reduction says how many resources did not answer'
assert_not_contains "$(_ids_for_resource "$TBL" arn:aws:rds:eu-west-2:123456789012:snapshot:"$DENY_SNAP")" \
  'CLOUD-RDS-PUBLIC_SNAPSHOT' \
  'D4 no public-snapshot finding is invented for the snapshot whose attributes were never read'

# The whole instance list unreadable: no instance examined for the three
# instance-level checks, and the gap stated where a consumer actually reads
# it. The reading D6/D7 fail under is exit 0 with an empty findings set and
# no explanation, which is a denied scan rendered as a clean region.
_routes_default describe-db-instances "$FIX/describe-db-instances.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-RDS-PUBLIC_ACCESS-01' \
  'D5 a denied describe-db-instances credits no instance-level check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'instance list' \
  'D6 ... and the coverage_gap says the instance list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'instance list' \
  'D7 ... and it reaches report.md, the surface a consumer actually reads'
# The instance list failing must NOT stop the snapshot list from being tried
# - the two are independent AWS calls, and abandoning the second because the
# first failed would suppress a real, answerable check.
assert_contains "$CR2" 'CLOUD-RDS-PUBLIC_SNAPSHOT-01' \
  'D8 the snapshot-public check still ran even though the instance list was denied'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the regions the run resolved'
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
    if cid.startswith('CLOUD-RDS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-RDS-PUBLIC_ACCESS-01 account-region 123456789012/eu-west-2' \
  'E5 the run wrote a REAL account-region coverage cell for the region it actually covered'

assert_file_exists "$W/run-b/report.md" 'E6 report.md written'
assert_file_exists "$W/run-b/report.html" 'E7 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$PUB_ARN" 'E8 report.md names the instance ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E9 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-RDS-PUBLIC_ACCESS-01' 'E10 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$PUB_ARN" 'E11 the SARIF result names the resource'
assert_contains "$_SARIF" '2.3.3' \
  'E12 the CIS control id authored on the check record reaches the SARIF rule tags'

# ===========================================================================
# F. This service's own truncation sharp edge, end to end.
# ===========================================================================
t_case 'F. RDS Marker truncation, end to end'

_routes_default describe-db-instances "$FIX/describe-db-instances.truncated.json"
_run_cloud "$W/run-truncated"
RED3=$(_json "$W/run-truncated/run.json" coverage_reduction)
assert_contains "$RED3" 'aws_api_truncated' \
  'F1 a Marker-truncated instance list is recorded as a coverage_reduction, even though SCOURSH_AWS_RO_OUTCOME reported ok'
assert_contains "$(_json "$W/run-truncated/run.json" coverage_gap)" 'instance list' \
  'F2 ... and the coverage_gap says the instance list was truncated'

t_summary cloud-rds
