#!/usr/bin/env bash
# tests/suites/cloud-efs.sh - modules/cloud/aws/live/efs.sh: the §8.1 EFS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-19).
#
# Mirrors tests/suites/cloud-s3.sh's own shape (read that suite's header
# first). What is specific to this service:
#
#   1. ONE `describe-file-system-policy` CALL SERVES TWO CHECKS (public
#      access, encryption in transit), AND AN ABSENT POLICY
#      (`PolicyNotFound`, classified `not_found`) IS READ IN OPPOSITE
#      DIRECTIONS BY THE TWO - a real answer meaning "not public" for the
#      first, and "not enforced" (the finding fires) for the second.  Section
#      D's fourth file system exists specifically to exercise this: it is
#      Encrypted=true and has NO policy at all, so it must produce exactly
#      ONE finding (NO_ENCRYPTION_IN_TRANSIT), never two and never zero.
#   2. THE ARN COMES DIRECTLY FROM THE LIST RESPONSE (`FileSystemArn`), the
#      same shape opensearch.sh's `DomainStatus.ARN` gives - no per-resource
#      region-resolution call, unlike S3.
#   3. `CLOUD-EFS-NO_ENCRYPTION_AT_REST-01` IS THE ONE CHECK IN ALL NINE THAT
#      CITES A REAL CIS CONTROL (`2.4.1`) - CIS v3.0.0 has no OpenSearch or
#      Redshift section, but EFS encryption at rest is in scope.
#
# NO NETWORK AND NO AWS ACCOUNT.  tests/lib/aws-fixtures.sh's routed stub,
# fixtures under tests/fixtures/aws/cloud-efs/.
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
source "$ROOT/modules/cloud/aws/live/efs_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-efs
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-efs
PUB=fsid-public
HARD=fsid-hardened
DENY=fsid-denied
NOPOLICY=fsid-nopolicy

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add efs describe-file-systems "$FIX/describe-file-systems.json"

  if [[ $omit != describe-file-system-policy ]]; then
    aws_fixture_route_add_for efs describe-file-system-policy "$PUB"       "$FIX/describe-file-system-policy.public.json"
    aws_fixture_route_add_for efs describe-file-system-policy "$HARD"      "$FIX/describe-file-system-policy.hardened.json"
    aws_fixture_route_add_for efs describe-file-system-policy "$DENY"      "$FIX/describe-file-system-policy.denied.err"
    aws_fixture_route_add_for efs describe-file-system-policy "$NOPOLICY"  "$FIX/describe-file-system-policy.nopolicy.err"
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

_ids_for_fs() {
  local table=$1 fsid=$2
  printf '%s\n' "$table" | awk -F'\037' -v f="file-system/$fsid" '$2 ~ f { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

assert_true "$(efs_is_encrypted false && echo 1 || echo 0)" 'A1 Encrypted=false is not encrypted'
assert_true "$(efs_is_encrypted true && echo 0 || echo 1)" 'A2 Encrypted=true is encrypted'

_pub_policy=$(python3 -c "import json; print(json.load(open('$FIX/describe-file-system-policy.public.json'))['Policy'])")
_hard_policy=$(python3 -c "import json; print(json.load(open('$FIX/describe-file-system-policy.hardened.json'))['Policy'])")

assert_true "$(efs_policy_is_wide_open "$_pub_policy" && echo 0 || echo 1)" 'A3 a Principal "*" Allow statement is wide open'
assert_true "$(efs_policy_is_wide_open "$_hard_policy" && echo 1 || echo 0)" 'A4 a policy scoped to one named role is not wide open'
assert_true "$(efs_policy_is_wide_open '' && echo 1 || echo 0)" 'A5 an empty (absent) policy is NOT wide open'

assert_true "$(efs_policy_denies_insecure_transport "$_pub_policy" && echo 1 || echo 0)" \
  'A6 the public policy has no Deny-on-plaintext statement, so transit encryption is not enforced'
assert_true "$(efs_policy_denies_insecure_transport "$_hard_policy" && echo 0 || echo 1)" \
  'A7 the hardened policy denies aws:SecureTransport=false, so transit encryption IS enforced'
# The reading A8 fails under is folding "no policy" into the same answer as
# "policy present but does not deny plaintext" - efs.sh's own header explains
# why the two must be read in OPPOSITE directions by the two checks that
# share this one call.
assert_true "$(efs_policy_denies_insecure_transport '' && echo 1 || echo 0)" \
  'A8 an empty (absent) policy does NOT deny insecure transport either - no policy means no enforcement'

# ===========================================================================
# B. One scan, four file systems: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_fs "$TBL" "$PUB")
HARD_IDS=$(_ids_for_fs "$TBL" "$HARD")

for want in CLOUD-EFS-PUBLIC_ACCESS-01 CLOUD-EFS-NO_ENCRYPTION_AT_REST-01 \
  CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public file system is reported by $want"
done
assert_eq '' "$HARD_IDS" 'B4 the hardened file system in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account, cis, cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F'\037' '$1 == "CLOUD-EFS-NO_ENCRYPTION_AT_REST-01" && $2 ~ /public/ { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "arn:aws:elasticfilesystem:eu-west-2:123456789012:file-system/$PUB" "$_c_arn" 'C1 the finding cites the file system ARN, read verbatim from the list response'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C4 the cell equals the region, since efs is a regional service'
assert_eq '2.4.1' "$_c_cis" 'C5 the encryption-at-rest finding cites CIS 2.4.1 - the one control among all nine checks that exists in v3.0.0'

_row2=$(printf '%s\n' "$TBL" | awk -F'\037' '$1 == "CLOUD-EFS-PUBLIC_ACCESS-01" { print; exit }')
IFS=$'\x1f' read -r _c2_id _c2_arn _c2_region _c2_cell _c2_cis _c2_account <<<"$_row2"
assert_eq '' "$_c2_cis" 'C6 the public-access finding cites no cis id - CIS v3.0.0 has no EFS access-policy control'

# ===========================================================================
# D. Honesty: a denied policy call is a reduction; a genuinely ABSENT policy
#    is answered - correctly, in OPPOSITE directions by the two checks that
#    share it.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-EFS-PUBLIC_ACCESS-01' \
  'D1 a check that answered for SOME file systems is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the denied file system''s policy call is recorded as a coverage_reduction'
assert_eq '' "$(_ids_for_fs "$TBL" "$DENY")" \
  'D3 no finding is invented for the file system whose policy call was denied'

# The NOPOLICY file system: encrypted at rest (no finding there), no policy
# at all - PolicyNotFound.  Exactly one finding (NO_ENCRYPTION_IN_TRANSIT),
# never PUBLIC_ACCESS and never zero findings.
NOPOLICY_IDS=$(_ids_for_fs "$TBL" "$NOPOLICY")
assert_eq 'CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01' "$NOPOLICY_IDS" \
  'D4 a file system with NO policy at all fires ONLY the in-transit check, never public-access, never neither'
assert_contains "$CHECKS_RUN" 'CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01' \
  'D5 PolicyNotFound counts as the in-transit check having been covered (it IS an answer, not a loss)'

# A check denied for EVERY file system's policy call must not be in
# checks_run, while the encryption-at-rest check (unaffected) still is.
_routes_default describe-file-system-policy
aws_fixture_route_add efs describe-file-system-policy "$FIX/describe-file-system-policy.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-EFS-PUBLIC_ACCESS-01' \
  'D6 a check denied for every file system is absent from checks_run'
assert_contains "$CR2" 'CLOUD-EFS-NO_ENCRYPTION_AT_REST-01' \
  'D7 ... while the unaffected encryption-at-rest check is still credited'
assert_contains "$RED2" 'operation=describe-file-system-policy' \
  'D8 ... and it has its own coverage_reduction naming the failed call'

# The whole account unreadable: no file system examined, nothing credited.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add efs describe-file-systems "$FIX/describe-file-system-policy.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-EFS-' 'D9 a denied describe-file-systems credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'file system list' \
  'D10 ... and the coverage_gap says the file system list could not be read'

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
    if cid.startswith('CLOUD-EFS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-EFS-NO_ENCRYPTION_AT_REST-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for this service'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "arn:aws:elasticfilesystem:eu-west-2:123456789012:file-system/$PUB" 'E5 report.md names the file system ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-EFS-NO_ENCRYPTION_AT_REST-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" '2.4.1' 'E8 the CIS control id authored on the check record reaches the SARIF rule tags'
assert_contains "$_SARIF" "arn:aws:elasticfilesystem:eu-west-2:123456789012:file-system/$PUB" 'E9 the SARIF result names the resource'

t_summary cloud-efs
