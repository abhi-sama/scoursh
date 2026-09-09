#!/usr/bin/env bash
# tests/suites/cloud-backup.sh - modules/cloud/aws/live/backup.sh: the §8.1
# AWS Backup EBS-coverage check (docs/STEP6-CLOUD-PLAN.md CLOUD-12).
#
# Mirrors tests/suites/cloud-s3.sh's own shape - see that suite's header for
# the full five-point reasoning. SPECIFIC to this suite: two independent
# calls (`ec2 describe-volumes`, `backup list-protected-resources`) both have
# to answer before ANYTHING is decided, and a failure of EITHER is a reduction
# over the WHOLE check - section D pins both failure points, and in
# particular that a denied `list-protected-resources` must NOT be read as
# "therefore unprotected" (backup_engine.sh's own header states why that
# direction is the dangerous one to get wrong: it would manufacture a finding
# against a properly-backed-up volume purely because a permission was
# missing).
#
# NO NETWORK AND NO AWS ACCOUNT: every case runs against tests/lib/aws-
# fixtures.sh's routed stub, serving tests/fixtures/aws/cloud-backup/.
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
source "$ROOT/modules/cloud/aws/live/backup_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-backup
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

# `awk -F'\x1f'` does NOT reliably parse the hex escape as the real byte
# (measured: BSD/macOS awk 20200816 treats it as a literal no-op and leaves
# the whole line as ONE field, so every `$2 == ...` compare is silently
# false) - the fix is a shell variable holding the ACTUAL byte, passed to
# `-F"$SEP"`, never the hex-escape spelling in the -F argument itself.
SEP=$'\x1f'
FIX=$ROOT/tests/fixtures/aws/cloud-backup
UNPROTECTED=arn:aws:ec2:eu-west-2:123456789012:volume/vol-0000000000000001
PROTECTED=arn:aws:ec2:eu-west-2:123456789012:volume/vol-0000000000000002

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity        "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions           "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add ec2 describe-volumes           "$FIX/describe-volumes.json"
  aws_fixture_route_add backup list-protected-resources "$FIX/list-protected-resources.json"
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
    ]))
PY
}

_ids_for_arn() {
  local table=$1 arn=$2
  printf '%s\n' "$table" | awk -F"$SEP" -v a="$arn" '$2 == a { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

assert_eq 'aws' "$(backup_partition_of 'arn:aws:iam::123456789012:user/x')" 'A1 partition: commercial'
assert_eq "$UNPROTECTED" "$(backup_volume_arn aws eu-west-2 123456789012 vol-0000000000000001)" \
  'A2 the volume ARN is built in the ec2:region:account:volume/id shape'

# ===========================================================================
# B. One scan, two volumes: fires on the unprotected one, quiet on the other.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
UNPROT_IDS=$(_ids_for_arn "$TBL" "$UNPROTECTED")
PROT_IDS=$(_ids_for_arn "$TBL" "$PROTECTED")

assert_contains "$UNPROT_IDS" 'CLOUD-BACKUP-NO_PLAN_COVERAGE-01' \
  'B3 the volume with no recovery point fires'
assert_eq '' "$PROT_IDS" \
  'B4 the volume AWS Backup names as protected, in the SAME run, produces no finding'

# ===========================================================================
# C. ARN, region, account, cell - and NO cis (an honest absence).
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F"$SEP" '$1 == "CLOUD-BACKUP-NO_PLAN_COVERAGE-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "$UNPROTECTED" "$_c_arn" 'C1 the finding cites the volume ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq "123456789012/eu-west-2" "$_c_cell" 'C4 the cell agrees with the region for a regional service'
assert_eq '' "$_c_cis" 'C5 the finding carries NO cis value - CIS AWS Foundations Benchmark v3.0.0 has no AWS Backup section'

# ===========================================================================
# D. Honesty: EITHER denied call is a reduction, and a denied
#    list-protected-resources must NEVER be read as "therefore unprotected".
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
CHECKS_RUN=$(_json "$RUNJSON" checks_run)
assert_contains "$CHECKS_RUN" 'CLOUD-BACKUP-NO_PLAN_COVERAGE-01' \
  'D1 the check answered for this region, so it is in checks_run'

aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add ec2 describe-volumes    "$FIX/describe-volumes.denied.err"
_run_cloud "$W/run-novolumes"
CR2=$(_json "$W/run-novolumes/run.json" checks_run)
RED2=$(_json "$W/run-novolumes/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-BACKUP-' \
  'D2 a denied describe-volumes credits no check at all'
assert_contains "$RED2" 'aws_api_access_denied' \
  'D3 ... and it is recorded as a coverage_reduction'

# The sharper trap: a denied list-protected-resources must not manufacture a
# finding against every volume - it must refuse the check entirely instead.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity        "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions           "$FIX/ec2.describe-regions.json"
aws_fixture_route_add ec2 describe-volumes           "$FIX/describe-volumes.json"
aws_fixture_route_add backup list-protected-resources "$FIX/list-protected-resources.denied.err"
_run_cloud "$W/run-noprotected"
CR3=$(_json "$W/run-noprotected/run.json" checks_run)
RED3=$(_json "$W/run-noprotected/run.json" coverage_reduction)
FINDINGS3=$(cat "$W/run-noprotected/findings.jsonl" 2>/dev/null || true)
assert_not_contains "$CR3" 'CLOUD-BACKUP-' \
  'D4 a denied list-protected-resources ALSO credits no check at all'
assert_not_contains "$FINDINGS3" 'CLOUD-BACKUP-NO_PLAN_COVERAGE-01' \
  'D5 ... and it does NOT manufacture a finding against every volume - a denied read of "what is protected" is never read as "therefore nothing is"'
assert_contains "$RED3" 'operation=list-protected-resources' \
  'D6 ... and the reduction names the call that failed'

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
    if cid.startswith('CLOUD-BACKUP-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-BACKUP-NO_PLAN_COVERAGE-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for the region actually visited'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$UNPROTECTED" 'E5 report.md names the volume ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-BACKUP-NO_PLAN_COVERAGE-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$UNPROTECTED" 'E8 the SARIF result names the resource'

t_summary cloud-backup
