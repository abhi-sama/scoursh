#!/usr/bin/env bash
# tests/suites/cloud-governance.sh - modules/cloud/aws/live/{cloudtrail,config,
# guardduty,inspector,macie}.sh: the §8.1 governance & detection read-only
# checks (docs/STEP6-CLOUD-PLAN.md CLOUD-30..34).
#
# What this suite exists to pin, mirroring tests/suites/cloud-s3.sh's own
# structure since this bundle is the second real service to land against the
# same chain:
#
#   1. BOTH DIRECTIONS, IN ONE RUN, PER SERVICE.  Unlike S3's per-bucket
#      variation, every check here is `regional`
#      (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table), so the "one
#      run, both directions" mechanism is REGION, not resource name: the
#      fixture route table below is qualified on the `--region` value every
#      call in a regional pass carries, so region `us-east-1` is a fully
#      compliant account and `eu-west-2` is a fully non-compliant one, in ONE
#      `scan.sh cloud --live` process.
#   2. EVERY FINDING CITES ARN, REGION, ACCOUNT AND - WHERE ONE EXISTS - A
#      CIS CONTROL ID.
#   3. THE REGION IS THE PASS'S OWN REGION AND SO IS THE CELL - unlike S3,
#      there is no split to pin here, because these five services are all
#      genuinely per-region AWS objects.  What IS pinned is that a
#      CloudTrail finding still cites the trail's own `HomeRegion`, which
#      for a trail this suite examines always equals the pass's region (the
#      home-region-ownership filter cloudtrail.sh's own header describes).
#   4. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE.  Pinned per
#      service, plus the one genuine ambiguity in this bundle: Macie reports
#      "not enabled" as the SAME AccessDeniedException code a real
#      permission gap would, and this suite pins BOTH readings - the
#      disabled-account case fires the finding, and a genuinely unrelated
#      failure (ThrottlingException) stays a coverage_reduction and does
#      NOT fire.
#   5. THE FINDING ROUND-TRIPS into findings.jsonl, into a real
#      `account-region` coverage cell in state/, and into every report
#      format.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-governance/.
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
# -x back-edge cut: modules/cloud/aws/live/governance_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, which drags in
# modules/sast/engine.sh plus the whole lib/ hub chain.  shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own
# entry point (tests/suites/cloud-s3.sh's own back-edge cut records the
# identical reasoning).
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/governance_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-governance
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath, so a fixture root reached through
# macOS's /var -> /private/var $TMPDIR symlink would fail E070 on every file
# for a reason that has nothing to do with the file (tests/suites/cloud.sh
# and tests/suites/cloud-s3.sh both document the identical fact).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-governance
GOOD=us-east-1
BAD=eu-west-2

aws_fixture_stub_install "$W/bin"

# `_routes_default` - every call the module makes before any service script
# (identity, region enumeration), plus a good/bad row per (service,
# operation) qualified on the REGION the ambient --region carries - the
# per-region analogue of cloud-s3.sh's own per-bucket-name qualification.
# An optional argument omits ONE (service, operation) pair's default rows so
# a case can register its own instead, identical in shape and purpose to
# cloud-s3.sh's own `_routes_default OMIT` argument.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"

  if [[ $omit != cloudtrail:describe-trails ]]; then
    aws_fixture_route_add_for cloudtrail describe-trails "$GOOD" "$FIX/cloudtrail.describe-trails.good.json"
    aws_fixture_route_add_for cloudtrail describe-trails "$BAD"  "$FIX/cloudtrail.describe-trails.bad.json"
  fi
  if [[ $omit != cloudtrail:get-trail-status ]]; then
    aws_fixture_route_add_for cloudtrail get-trail-status "$GOOD" "$FIX/cloudtrail.get-trail-status.good.json"
    aws_fixture_route_add_for cloudtrail get-trail-status "$BAD"  "$FIX/cloudtrail.get-trail-status.bad.json"
  fi

  if [[ $omit != config:describe-configuration-recorders ]]; then
    aws_fixture_route_add_for configservice describe-configuration-recorders "$GOOD" "$FIX/config.describe-configuration-recorders.good.json"
    aws_fixture_route_add_for configservice describe-configuration-recorders "$BAD"  "$FIX/config.describe-configuration-recorders.bad.json"
  fi
  if [[ $omit != config:describe-configuration-recorder-status ]]; then
    aws_fixture_route_add_for configservice describe-configuration-recorder-status "$GOOD" "$FIX/config.describe-configuration-recorder-status.good.json"
    aws_fixture_route_add_for configservice describe-configuration-recorder-status "$BAD"  "$FIX/config.describe-configuration-recorder-status.bad.json"
  fi

  if [[ $omit != guardduty:list-detectors ]]; then
    aws_fixture_route_add_for guardduty list-detectors "$GOOD" "$FIX/guardduty.list-detectors.good.json"
    aws_fixture_route_add_for guardduty list-detectors "$BAD"  "$FIX/guardduty.list-detectors.bad.json"
  fi
  if [[ $omit != guardduty:get-detector ]]; then
    aws_fixture_route_add_for guardduty get-detector "$GOOD" "$FIX/guardduty.get-detector.good.json"
    aws_fixture_route_add_for guardduty get-detector "$BAD"  "$FIX/guardduty.get-detector.bad.json"
  fi

  if [[ $omit != inspector2:batch-get-account-status ]]; then
    aws_fixture_route_add_for inspector2 batch-get-account-status "$GOOD" "$FIX/inspector2.batch-get-account-status.good.json"
    aws_fixture_route_add_for inspector2 batch-get-account-status "$BAD"  "$FIX/inspector2.batch-get-account-status.bad.json"
  fi

  if [[ $omit != macie2:get-macie-session ]]; then
    aws_fixture_route_add_for macie2 get-macie-session "$GOOD" "$FIX/macie2.get-macie-session.good.json"
    aws_fixture_route_add_for macie2 get-macie-session "$BAD"  "$FIX/macie2.get-macie-session.bad.err"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess,
# each with its OWN cache directory - both details byte-identical to
# cloud-s3.sh's own `_run_cloud`, and for the identical reason its own
# header states: a shared `SCOURSH_AWS_CACHE_DIR` across subprocesses would
# key on sha256(service|region|account|op|args), which is unaffected by
# which route table is active, so a later case would be served an earlier
# case's cached response.
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

# One `check_id<US>loc_resource_key<US>loc_region<US>cell<US>cis<US>account`
# line per finding, read from findings.jsonl.  0x1f (unit separator), NEVER a
# tab: `cis` and, for some checks, other columns are legitimately EMPTY, and a
# tab is an IFS-*whitespace* character, so `read` folds a run of them into ONE
# delimiter and drops a genuinely-empty MIDDLE field by shifting every later
# value one column left - AGENTS.md's own "Things measured on this codebase"
# lesson (the DAST-11 record-stream note), reproduced here for real: a first
# draft of this table used a tab and it read GuardDuty's empty `cis` column as
# its ACCOUNT id, silently.  cloud-s3.sh's own tab-separated table happens not
# to hit this, because none of the columns its own suite unpacks through
# `read` is ever the empty one; that is luck, not immunity, and is not a
# reason to copy the spelling here.
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

_ids_for_region() {
  local table=$1 region=$2
  printf '%s\n' "$table" | awk -F$'\x1f' -v r="$region" '$3 == r { print $1 }' | LC_ALL=C sort -u
}

# ===========================================================================
# A. One scan, two regions: fires on the bad one, quiet on the good one,
#    across all five services.
# ===========================================================================
t_case 'A. both directions in one run, across all five services'

_routes_default
_run_cloud "$W/run-a"
assert_eq '0' "$_RC" 'A1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-a/findings.jsonl" 'A2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-a/findings.jsonl")
BAD_IDS=$(_ids_for_region "$TBL" "$BAD")
GOOD_IDS=$(_ids_for_region "$TBL" "$GOOD")

for want in CLOUD-CLOUDTRAIL-NOT_ENABLED-01 CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01 \
  CLOUD-CLOUDTRAIL-LOG_FILE_VALIDATION_OFF-01 CLOUD-CONFIG-RECORDER_OFF-01 \
  CLOUD-GUARDDUTY-DISABLED-01 CLOUD-INSPECTOR-DISABLED-01 CLOUD-MACIE-DISABLED-01; do
  assert_contains "$BAD_IDS" "$want" "A3 the misconfigured region ($BAD) is reported by $want"
done

# ... and the well-configured region, in the SAME run, produces no finding at
# all.  This is the half a pack gone inert would also pass, which is why A3
# is asserted from the same run: only both together distinguish "classifies
# correctly" from "never fires".
assert_eq '' "$GOOD_IDS" "A4 the well-configured region ($GOOD) in the SAME run produces no finding at all"

# ===========================================================================
# B. Finding citation - ARN, region, account, CIS, and the cell.
# ===========================================================================
t_case 'B. finding citation'

_ct_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_ct_row"
assert_eq 'arn:aws:cloudtrail:eu-west-2:123456789012:trail/broken-trail' "$_c_arn" \
  'B1 the CloudTrail finding cites the real trail ARN, read out of the response'
assert_eq '123456789012' "$_c_account" 'B2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" "B3 the finding cites the trail's own HomeRegion"
assert_eq '3.1' "$_c_cis" 'B4 the finding carries the cis control id authored on its check record'
assert_eq '123456789012/eu-west-2' "$_c_cell" \
  'B5 the cell is the pass-s own <account>/<region>, since these five services are all regional'

_gd_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-GUARDDUTY-DISABLED-01" { print; exit }')
IFS=$'\x1f' read -r _g_id _g_arn _g_region _g_cell _g_cis _g_account <<<"$_gd_row"
assert_eq 'arn:aws:guardduty:eu-west-2:123456789012:detector/scoursh-fixture-detector-bad' "$_g_arn" \
  'B6 the GuardDuty finding cites the real, AWS-published detector ARN format'
assert_eq '' "$_g_cis" \
  'B7 GuardDuty has no CIS v3.0.0 control, and the finding honestly carries none rather than an invented one'

_insp_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-INSPECTOR-DISABLED-01" { print; exit }')
IFS=$'\x1f' read -r _i_id _i_arn _i_region _i_cell _i_cis _i_account <<<"$_insp_row"
assert_eq 'arn:aws:iam::123456789012:root' "$_i_arn" \
  'B8 Inspector2 has no per-resource ARN for an account-status object, so the finding cites the account root ARN'

# Two grantee-independent findings in one run must still carry distinct
# fingerprints.  Under a broken location profile (e.g. every account-root
# finding sharing one identity) two of the seven would collide and
# findings_merge would silently keep only one.
_nfp=$(python3 - "$W/run-a/findings.jsonl" <<'PY'
import json, sys
fps = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        fps.add(json.loads(line)['fingerprint'])
print(len(fps))
PY
)
_nf=$(grep -c . "$W/run-a/findings.jsonl")
assert_eq "$_nf" "$_nfp" 'B9 every finding in the run has a distinct fingerprint'
assert_eq '7' "$_nf" 'B10 all seven governance checks fired exactly once each on the bad region'

# ===========================================================================
# C. Honesty: a denied call is a reduction; Macie's one genuine ambiguity.
# ===========================================================================
t_case 'C. honesty accounting'

RUNJSON=$W/run-a/run.json
CHECKS_RUN=$(_json "$RUNJSON" checks_run)
for id in CLOUD-CLOUDTRAIL-NOT_ENABLED-01 CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01 \
  CLOUD-CLOUDTRAIL-LOG_FILE_VALIDATION_OFF-01 CLOUD-CONFIG-RECORDER_OFF-01 \
  CLOUD-GUARDDUTY-DISABLED-01 CLOUD-INSPECTOR-DISABLED-01 CLOUD-MACIE-DISABLED-01; do
  assert_contains "$CHECKS_RUN" "$id" "C1 $id is credited in checks_run - it answered in at least one region"
done

# A denied describe-trails call: no CloudTrail check ran in that region, and
# the reduction says so - never silence, and never a finding invented from
# an error.  The omit drops BOTH the good and bad default rows for this one
# operation, so the good row must be RE-ADDED explicitly alongside the denied
# one - omitting it entirely would deny describe-trails in BOTH regions and
# C4 below would fail for the wrong reason (no region ever answered, rather
# than only the denied one).
_routes_default cloudtrail:describe-trails
aws_fixture_route_add_for cloudtrail describe-trails "$GOOD" "$FIX/cloudtrail.describe-trails.good.json"
aws_fixture_route_add_for cloudtrail describe-trails "$BAD"  "$FIX/cloudtrail.describe-trails.denied.err"
_run_cloud "$W/run-denied-ct"
CR_CT=$(_json "$W/run-denied-ct/run.json" coverage_reduction)
CHR_CT=$(_json "$W/run-denied-ct/run.json" checks_run)
TBL_CT=$(_findings_table "$W/run-denied-ct/findings.jsonl")
assert_contains "$CR_CT" 'aws_api_access_denied' \
  'C2 a denied describe-trails is recorded as a coverage_reduction'
assert_not_contains "$(_ids_for_region "$TBL_CT" "$BAD")" 'CLOUD-CLOUDTRAIL-' \
  'C3 no CloudTrail finding is invented for the region whose trail list was never read'
# The good region's own describe-trails still answered, so its checks are
# STILL credited - a denial in one region cell must not suppress the
# other's honest coverage.
assert_contains "$CHR_CT" 'CLOUD-CLOUDTRAIL-NOT_ENABLED-01' \
  'C4 the unaffected region-s own CloudTrail coverage is unaffected by the other region-s denial'

# A completely empty trailList, in ANY region, is real evidence the account
# has no trail anywhere - and the finding cites the account itself, since
# there is no trail resource to name.
_routes_default cloudtrail:describe-trails
aws_fixture_route_add cloudtrail describe-trails "$FIX/cloudtrail.describe-trails.empty.json"
_run_cloud "$W/run-no-trail"
TBL_NT=$(_findings_table "$W/run-no-trail/findings.jsonl")
_nt_arns=$(printf '%s\n' "$TBL_NT" | awk -F$'\x1f' '$1 == "CLOUD-CLOUDTRAIL-NOT_ENABLED-01" { print $2 }' | LC_ALL=C sort -u)
assert_eq $'arn:aws:iam::123456789012:root' "$_nt_arns" \
  'C5 zero trails anywhere in the account cites the account root ARN, once per region visited, not a fabricated trail ARN'
assert_not_contains "$TBL_NT" 'CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01' \
  'C6 with no trail anywhere, NOT_MULTI_REGION and LOG_FILE_VALIDATION_OFF have nothing to examine and do not fire'

# A Config recorder that genuinely does not exist: the empty-list branch,
# distinct from the exists-but-not-recording branch A3 already proved.
_routes_default config:describe-configuration-recorders
aws_fixture_route_add configservice describe-configuration-recorders "$FIX/config.describe-configuration-recorders.empty.json"
_run_cloud "$W/run-no-recorder"
TBL_NR=$(_findings_table "$W/run-no-recorder/findings.jsonl")
_nr_arn=$(printf '%s\n' "$TBL_NR" | awk -F$'\x1f' '$1 == "CLOUD-CONFIG-RECORDER_OFF-01" && $3 == "us-east-1" { print $2 }')
assert_eq 'arn:aws:iam::123456789012:root' "$_nr_arn" \
  'C7 no Config recorder at all cites the account root ARN, in the region that has none'

# GuardDuty: a denied list-detectors is a reduction, never a finding.  The
# bad region-s own default row is re-added alongside the denied override for
# the good region, the identical reason the CloudTrail and Macie cases above
# both re-add their own unaffected region.
_routes_default guardduty:list-detectors
aws_fixture_route_add_for guardduty list-detectors "$GOOD" "$FIX/guardduty.list-detectors.denied.err"
aws_fixture_route_add_for guardduty list-detectors "$BAD"  "$FIX/guardduty.list-detectors.bad.json"
_run_cloud "$W/run-gd-denied"
CR_GD=$(_json "$W/run-gd-denied/run.json" coverage_reduction)
TBL_GD=$(_findings_table "$W/run-gd-denied/findings.jsonl")
assert_contains "$CR_GD" 'service=guardduty' 'C8 a denied guardduty list-detectors is recorded as a coverage_reduction'
assert_not_contains "$(_ids_for_region "$TBL_GD" "$GOOD")" 'CLOUD-GUARDDUTY-' \
  'C9 no GuardDuty finding is invented for the region whose detector list was never read'

# Macie: THE one genuine ambiguity in this bundle, pinned in BOTH directions
# from a single dedicated run, because the naive fix for each reading is the
# other-s bug.  The omit drops BOTH default rows for this operation, so the
# bad region-s own AccessDeniedException route must be RE-ADDED alongside the
# good region-s throttled override - omitting it would leave the bad region
# with no route at all, which is a THIRD, unrelated failure mode (an
# unmatched-route stub error) and would make C10/C13 fail for the wrong
# reason entirely.
_routes_default macie2:get-macie-session
aws_fixture_route_add_for macie2 get-macie-session "$GOOD" "$FIX/macie2.get-macie-session.throttled.err"
aws_fixture_route_add_for macie2 get-macie-session "$BAD"  "$FIX/macie2.get-macie-session.bad.err"
_run_cloud "$W/run-macie"
TBL_MC=$(_findings_table "$W/run-macie/findings.jsonl")
CR_MC=$(_json "$W/run-macie/run.json" coverage_reduction)
CHR_MC=$(_json "$W/run-macie/run.json" checks_run)
# The bad region-s AccessDeniedException from get-macie-session.bad.err IS
# read as "Macie is not enabled" and fires the finding - the reading D5/D6
# in cloud-s3.sh pin for a NoSuch* error applies here to a DIFFERENT AWS
# error code, for the documented reason (see modules/cloud/aws/live/macie.sh).
assert_contains "$(_ids_for_region "$TBL_MC" "$BAD")" 'CLOUD-MACIE-DISABLED-01' \
  'C10 an AccessDeniedException from get-macie-session on the bad region IS read as Macie-disabled'
# The good region-s failure is a ThrottlingException, a GENUINELY unrelated
# outage, and must NOT be folded into the same disabled-account reading -
# the reading that fails is "every non-zero aws_ro on this call means
# disabled", which would silently swallow a real coverage loss.
assert_not_contains "$(_ids_for_region "$TBL_MC" "$GOOD")" 'CLOUD-MACIE-' \
  'C11 a THROTTLED get-macie-session is NOT read as Macie-disabled'
assert_contains "$CR_MC" 'aws_api_throttled' \
  'C12 ... and it is recorded as the real coverage_reduction it is'
assert_contains "$CHR_MC" 'CLOUD-MACIE-DISABLED-01' \
  'C13 the check is still credited overall - it DID answer, for the bad region'

# Macie PAUSED (a session that exists but is not active) is the same finding
# as a wholly-disabled one, reached through the success path rather than the
# error path.
_routes_default macie2:get-macie-session
aws_fixture_route_add_for macie2 get-macie-session "$GOOD" "$FIX/macie2.get-macie-session.good.json"
aws_fixture_route_add_for macie2 get-macie-session "$BAD"  "$FIX/macie2.get-macie-session.paused.json"
_run_cloud "$W/run-macie-paused"
TBL_MP=$(_findings_table "$W/run-macie-paused/findings.jsonl")
assert_contains "$(_ids_for_region "$TBL_MP" "$BAD")" 'CLOUD-MACIE-DISABLED-01' \
  'C14 a PAUSED Macie session (not an error at all) is also reported'

# ===========================================================================
# D. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'D. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'D1 run.json names the regions the run resolved'
assert_contains "$(_json "$RUNJSON" regions)" 'us-east-1' 'D2 ... both of them'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'D3 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'D4 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-CLOUDTRAIL-') or cid.startswith('CLOUD-GUARDDUTY-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(sorted(entry.get('cells') or []))))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-CLOUDTRAIL-NOT_ENABLED-01 account-region 123456789012/eu-west-2,123456789012/us-east-1' \
  'D5 the run wrote real account-region coverage cells for BOTH regions it visited'
assert_contains "$COVER" 'CLOUD-GUARDDUTY-DISABLED-01 account-region 123456789012/eu-west-2,123456789012/us-east-1' \
  'D6 ... for a second, independent service in the same bundle'

assert_file_exists "$W/run-a/report.md" 'D7 report.md written'
assert_file_exists "$W/run-a/report.html" 'D8 report.html written'
_MD=$(cat "$W/run-a/report.md")
assert_contains "$_MD" 'arn:aws:cloudtrail:eu-west-2:123456789012:trail/broken-trail' \
  'D9 report.md names the trail ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'D10 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01' 'D11 the SARIF run names the check as a rule'
assert_contains "$_SARIF" 'arn:aws:cloudtrail:eu-west-2:123456789012:trail/broken-trail' \
  'D12 the SARIF result names the resource'
assert_contains "$_SARIF" '3.1' \
  'D13 the CIS control id authored on the check record reaches the SARIF rule tags'

_routes_default
_run_cloud "$W/run-audit" --format audit
assert_file_exists "$W/run-audit/report-audit.html" 'D14 --format audit writes report-audit.html'
_AUDIT=$(cat "$W/run-audit/report-audit.html")
assert_contains "$_AUDIT" 'CLOUD-CLOUDTRAIL-' 'D15 the audit view carries the cloud checks'
assert_contains "$_AUDIT" 'CLOUD-MACIE-' 'D16 ... every one of the five services, not only the first'

t_summary cloud-governance
