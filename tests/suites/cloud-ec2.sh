#!/usr/bin/env bash
# tests/suites/cloud-ec2.sh - modules/cloud/aws/live/ec2.sh: the §8.1 EC2/VPC
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-13), copying the merged
# S3 template (tests/suites/cloud-s3.sh) and proving REAL multi-region
# iteration, which s3's own suite never needed to (s3 is a `global` pass).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently:
#
#   1. MULTI-REGION ITERATION IS REAL, NOT A SINGLE-CELL ARTIFACT.  us-east-1
#      carries a deliberately misconfigured account (open admin/db ports, a
#      default SG in use, a public AMI, a public snapshot, an unencrypted
#      volume, IMDSv2 unenforced, no VPC flow log); eu-west-2 carries a
#      hardened one. Both are examined by the SAME run, so "the checks fire"
#      and "the checks stay quiet" are asserted against one code path in one
#      process, and each region's own findings cite THAT region - never the
#      other one's.
#   2. UNLIKE S3, THE CELL AND THE REGION ARE THE SAME VALUE.  Every EC2/VPC
#      API used here is itself region-scoped, so `<account>/<region>` is both
#      the cell `cloud_run_service` published for the pass AND the region the
#      resource actually lives in - there is no s3-shaped "cell differs from
#      the resource's own region" case to assert here; asserting they are
#      equal (rather than merely both present) is what would catch a script
#      that accidentally forked s3.sh's global-cell reasoning in unchanged.
#   3. EVERY FINDING CITES ARN, REGION, ACCOUNT, AND - WHERE ONE EXISTS - A
#      CIS CONTROL ID.  Four of the eight checks cite a real CIS v3.0.0
#      control (5.2, 5.4, 5.6, 3.7); the other four cite none, because no
#      v3.0.0 control covers them - asserted in both directions, since citing
#      one where none exists is exactly the misattribution
#      docs/CIS-MAPPINGS.md forbids.
#   4. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE - AND ONE
#      FAMILY'S DENIAL DOES NOT STOP ITS PEERS.  Unlike S3 (one list call
#      every check depends on), EC2/VPC's eight checks are fed by six
#      INDEPENDENT API families, so a role denied `ec2:DescribeImages` must
#      still get the other seven checks answered.
#   5. THE FINDING ROUND-TRIPS into findings.jsonl, into a real
#      `account-region` coverage cell in state/ for BOTH regions this run
#      visited, and into every report format including SARIF and the audit
#      view.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-ec2/.  The per-region list calls are routed by
# QUALIFYING ON THE REGION NAME rather than on a resource id: `lib/awscli.sh`'s
# `aws_ro` appends `--region <region>` to the CLI argv whenever
# `aws_ro_use_region` set one, and `cloud_run_service` does exactly that for
# every regional pass - so the region name is a real, distinguishing argv word
# the routed stub's per-argument qualifier can match on, exactly as
# `tests/suites/cloud-s3.sh` matches on a bucket name. The two genuinely
# per-resource calls (describe-image-attribute, describe-snapshot-attribute)
# are qualified on the image/snapshot id instead, the same way s3's per-bucket
# calls are.
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
# -x back-edge cut: modules/cloud/aws/live/ec2_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain - see
# tests/suites/cloud-s3.sh's own identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/ec2_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-ec2
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL prefix
# from every loaded file's realpath, so a fixture root reached through macOS's
# /var -> /private/var $TMPDIR symlink would fail E070 on every file
# (tests/suites/cloud-s3.sh documents the same fact).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-ec2
BAD=us-east-1
HARD=eu-west-2

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from: the two
# calls modules/cloud/aws/run.sh makes before any service script, plus one
# region-qualified row per (operation, region), plus one id-qualified row per
# AMI/snapshot attribute call.
#
# An optional argument names ONE operation whose rows are omitted, so a case
# can register its own row (or none at all) for it instead - the identical
# mechanism tests/suites/cloud-s3.sh's own `_routes_default` uses.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"

  if [[ $omit != describe-security-groups ]]; then
    aws_fixture_route_add_for ec2 describe-security-groups "$BAD"  "$FIX/describe-security-groups.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-security-groups "$HARD" "$FIX/describe-security-groups.eu-west-2.json"
  fi
  if [[ $omit != describe-network-interfaces ]]; then
    aws_fixture_route_add_for ec2 describe-network-interfaces "$BAD"  "$FIX/describe-network-interfaces.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-network-interfaces "$HARD" "$FIX/describe-network-interfaces.eu-west-2.json"
  fi
  if [[ $omit != describe-images ]]; then
    aws_fixture_route_add_for ec2 describe-images "$BAD"  "$FIX/describe-images.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-images "$HARD" "$FIX/describe-images.eu-west-2.json"
  fi
  aws_fixture_route_add_for ec2 describe-image-attribute ami-badpublic1   "$FIX/image-attribute.badpublic.json"
  aws_fixture_route_add_for ec2 describe-image-attribute ami-hardprivate1 "$FIX/image-attribute.hardprivate.json"

  if [[ $omit != describe-snapshots ]]; then
    aws_fixture_route_add_for ec2 describe-snapshots "$BAD"  "$FIX/describe-snapshots.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-snapshots "$HARD" "$FIX/describe-snapshots.eu-west-2.json"
  fi
  aws_fixture_route_add_for ec2 describe-snapshot-attribute snap-badpublic1   "$FIX/snapshot-attribute.badpublic.json"
  aws_fixture_route_add_for ec2 describe-snapshot-attribute snap-hardprivate1 "$FIX/snapshot-attribute.hardprivate.json"

  if [[ $omit != describe-volumes ]]; then
    aws_fixture_route_add_for ec2 describe-volumes "$BAD"  "$FIX/describe-volumes.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-volumes "$HARD" "$FIX/describe-volumes.eu-west-2.json"
  fi
  if [[ $omit != describe-instances ]]; then
    aws_fixture_route_add_for ec2 describe-instances "$BAD"  "$FIX/describe-instances.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-instances "$HARD" "$FIX/describe-instances.eu-west-2.json"
  fi
  if [[ $omit != describe-vpcs ]]; then
    aws_fixture_route_add_for ec2 describe-vpcs "$BAD"  "$FIX/describe-vpcs.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-vpcs "$HARD" "$FIX/describe-vpcs.eu-west-2.json"
  fi
  if [[ $omit != describe-flow-logs ]]; then
    aws_fixture_route_add_for ec2 describe-flow-logs "$BAD"  "$FIX/describe-flow-logs.us-east-1.json"
    aws_fixture_route_add_for ec2 describe-flow-logs "$HARD" "$FIX/describe-flow-logs.eu-west-2.json"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess, and
# its own `SCOURSH_AWS_CACHE_DIR` - both for the reasons
# tests/suites/cloud-s3.sh's own `_run_cloud` gives at length (a subprocess
# exercises the CLI parser, the dispatch arm and the check-registry load
# together; a shared cache key would serve one case's response to another).
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

# One `check_id<0x1f>loc_resource_key<0x1f>loc_region<0x1f>cell<0x1f>cis<0x1f>
# account_id` line per finding, read from findings.jsonl.
#
# THE SEPARATOR IS 0x1f, NEVER A TAB - `cis` and other columns here are
# legitimately EMPTY for several checks (docs/CIS-MAPPINGS.md's own "an honest
# absence" rule), and a tab is a POSIX IFS-*whitespace* character: `read`
# folds a RUN of tabs into ONE delimiter and strips leading/trailing ones, so
# a six-column record whose fifth column is empty arrives as five columns and
# every later value (the account id, here) shifts left into the wrong
# variable. This is AGENTS.md's own DAST-11 lesson
# (modules/dast/passive/markup_engine.sh), measured here the identical way: a
# first draft of this suite used a tab and C6/C8 asserted an empty `cis` but
# read the ACCOUNT ID instead, because SG_OPEN_DB_PORT-01 and PUBLIC_AMI-01
# both carry no `cis` value.
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
US = chr(0x1f)
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
  printf '%s\n' "$table" | awk -F$'\x1f' -v a="$arn" '$2 == a { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

ec2_doc_load "$FIX/describe-security-groups.us-east-1.json"
_rules=''
ec2_sg_public_ingress_set _rules 0
assert_contains "$_rules" 'tcp 22 22' 'A1 an SG open to 0.0.0.0/0 on 22 is read as a public ingress rule'
assert_true "$(ec2_ports_open_in_rules "$_rules" "$EC2_ADMIN_PORTS" && echo 0 || echo 1)" \
  'A2 port 22 is recognised as an admin port'
assert_true "$(ec2_ports_open_in_rules "$_rules" "$EC2_DB_PORTS" && echo 1 || echo 0)" \
  'A3 port 22 is NOT a database port'

ec2_sg_public_ingress_set _rules 1
assert_contains "$_rules" 'tcp 3306 3306' 'A4 an SG open to 0.0.0.0/0 on 3306 is read as a public ingress rule'
assert_true "$(ec2_ports_open_in_rules "$_rules" "$EC2_DB_PORTS" && echo 0 || echo 1)" \
  'A5 port 3306 is recognised as a database port'

# The `-1` ("all traffic") default-SG self-referencing rule carries NO
# CidrIp at all (only a UserIdGroupPairs self-reference), so it must produce
# NO public ingress line - the reading this fails under is treating an absent
# FromPort/ToPort as matching nothing, which would ALSO silently swallow a
# genuine `-1`-to-0.0.0.0/0 rule elsewhere.
ec2_sg_public_ingress_set _rules 2
assert_eq '' "$_rules" 'A6 a self-referencing (no CidrIp) rule is not a public ingress rule'

ec2_doc_load "$FIX/describe-security-groups.eu-west-2.json"
ec2_sg_public_ingress_set _rules 0
assert_eq '' "$_rules" 'A7 an SG restricted to an internal CIDR grants no public ingress'

# `ec2_port_in_range` with an absent FromPort/ToPort (protocol -1) covers
# EVERY port - the reading this fails under is treating empty bounds as a
# zero-width range, which would make the single most permissive rule shape
# match nothing.
assert_true "$(ec2_port_in_range '' '' 22 && echo 0 || echo 1)" \
  'A8 an absent port range (protocol -1) covers port 22'
assert_true "$(ec2_port_in_range 20 25 22 && echo 0 || echo 1)" 'A9 22 is inside 20-25'
assert_true "$(ec2_port_in_range 20 25 80 && echo 1 || echo 0)" 'A10 80 is outside 20-25'

assert_true "$(ec2_protocol_is_relevant tcp && echo 0 || echo 1)" 'A11 tcp is relevant'
assert_true "$(ec2_protocol_is_relevant -1 && echo 0 || echo 1)" 'A12 -1 (all protocols) is relevant'
assert_true "$(ec2_protocol_is_relevant udp && echo 1 || echo 0)" 'A13 udp is not relevant (no admin/db port here is ordinarily served over UDP)'

ec2_doc_load "$FIX/image-attribute.badpublic.json"
assert_true "$(ec2_launch_permission_is_public && echo 0 || echo 1)" 'A14 a launchPermission naming group "all" is public'
ec2_doc_load "$FIX/image-attribute.hardprivate.json"
assert_true "$(ec2_launch_permission_is_public && echo 1 || echo 0)" 'A15 an empty launchPermission list is not public'

ec2_doc_load "$FIX/snapshot-attribute.badpublic.json"
assert_true "$(ec2_create_volume_permission_is_public && echo 0 || echo 1)" 'A16 a createVolumePermission naming group "all" is public'
ec2_doc_load "$FIX/snapshot-attribute.hardprivate.json"
assert_true "$(ec2_create_volume_permission_is_public && echo 1 || echo 0)" 'A17 an empty createVolumePermission list is not public'

ec2_doc_load "$FIX/describe-volumes.us-east-1.json"
assert_true "$(ec2_volume_is_encrypted_at 0 && echo 1 || echo 0)" 'A18 Encrypted: false is read as unencrypted'
ec2_doc_load "$FIX/describe-volumes.eu-west-2.json"
assert_true "$(ec2_volume_is_encrypted_at 0 && echo 0 || echo 1)" 'A19 Encrypted: true is read as encrypted'

assert_true "$(ec2_imdsv2_not_enforced optional && echo 0 || echo 1)" 'A20 HttpTokens optional is NOT enforced'
assert_true "$(ec2_imdsv2_not_enforced required && echo 1 || echo 0)" 'A21 HttpTokens required IS enforced'
assert_true "$(ec2_imdsv2_not_enforced '' && echo 0 || echo 1)" 'A22 an absent HttpTokens is NOT enforced (IMDSv1 is still reachable)'

assert_eq 'aws' "$(ec2_partition_of 'arn:aws:iam::123456789012:user/x')" 'A23 partition: commercial'
assert_eq 'aws-us-gov' "$(ec2_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A24 partition: GovCloud'
assert_eq 'arn:aws:ec2:us-east-1:123456789012:volume/vol-1' \
  "$(ec2_arn aws us-east-1 123456789012 volume vol-1)" \
  'A25 the EC2 ARN carries region and account, unlike an S3 bucket ARN'

# ===========================================================================
# B. One scan, two regions: fires in the bad region, quiet in the hardened
#    one - and each region resolves its OWN resources, proving multi-region
#    iteration is real rather than a single cell reused twice.
# ===========================================================================
t_case 'B. both directions, across two regions, in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")

# The bad region is wrong in every way the eight checks can observe.
for want_arn in \
  'CLOUD-EC2-SG_OPEN_ADMIN_PORT-01 arn:aws:ec2:us-east-1:123456789012:security-group/sg-badadmin1' \
  'CLOUD-EC2-SG_OPEN_DB_PORT-01 arn:aws:ec2:us-east-1:123456789012:security-group/sg-baddb1' \
  'CLOUD-EC2-DEFAULT_SG_IN_USE-01 arn:aws:ec2:us-east-1:123456789012:security-group/sg-defaultbad' \
  'CLOUD-EC2-PUBLIC_AMI-01 arn:aws:ec2:us-east-1:123456789012:image/ami-badpublic1' \
  'CLOUD-EC2-PUBLIC_EBS_SNAPSHOT-01 arn:aws:ec2:us-east-1:123456789012:snapshot/snap-badpublic1' \
  'CLOUD-EC2-UNENCRYPTED_VOLUME-01 arn:aws:ec2:us-east-1:123456789012:volume/vol-badunencrypted1' \
  'CLOUD-EC2-IMDSV2_NOT_ENFORCED-01 arn:aws:ec2:us-east-1:123456789012:instance/i-badimds1' \
  'CLOUD-EC2-FLOW_LOGS_OFF-01 arn:aws:ec2:us-east-1:123456789012:vpc/vpc-bad1' \
; do
  set -- $want_arn
  assert_contains "$(_ids_for_arn "$TBL" "$2")" "$1" "B3 $1 fires against its bad-region resource"
done

# ... and the hardened region in the SAME run produces NOTHING - the half a
# pack gone inert would also pass, which is why B3 is asserted from the same
# run: only both together distinguish "classifies correctly" from "never
# fires".
HARD_IDS=$(printf '%s\n' "$TBL" | awk -F$'\x1f' -v r="eu-west-2" '$3 == r { print $1 }' | LC_ALL=C sort -u)
assert_eq '' "$HARD_IDS" 'B4 the hardened region in the SAME run produces no finding at all'

# A terminated instance is never examined for IMDSv2, however its
# MetadataOptions read - the reading this fails under would report it forever,
# regardless of remediation, since a terminated instance can never be "fixed".
assert_not_contains "$TBL" 'i-badterminated1' 'B5 a terminated instance is excluded from the IMDSv2 check'

# ===========================================================================
# C. ARN, region, account, CIS, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_row() {
  printf '%s\n' "$TBL" | awk -F$'\x1f' -v id="$1" '$1 == id { print; exit }'
}

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-SG_OPEN_ADMIN_PORT-01)"
assert_eq 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-badadmin1' "$_c_arn" 'C1 the finding cites the security group ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'us-east-1' "$_c_region" 'C3 the finding cites the resource-s own region'
assert_eq '5.2' "$_c_cis" 'C4 SG_OPEN_ADMIN_PORT carries CIS 5.2, authored on the check record'

# UNLIKE S3, THE CELL EQUALS THE REGION HERE - both are `<account>/<region>`,
# because every EC2/VPC API this file calls is itself region-scoped.  The
# reading this fails under is a script that copied s3.sh's `global`-cell
# reasoning in unchanged, which would file every EC2 finding under
# `<account>/global` no regional pass ever covers.
assert_eq '123456789012/us-east-1' "$_c_cell" 'C5 the cell is <account>/<region>, the SAME region as loc_region'

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-SG_OPEN_DB_PORT-01)"
assert_eq '' "$_c_cis" 'C6 SG_OPEN_DB_PORT carries NO cis value - v3.0.0 has no database-port control, and citing 5.2 against it would misattribute'

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-DEFAULT_SG_IN_USE-01)"
assert_eq '5.4' "$_c_cis" 'C7 DEFAULT_SG_IN_USE carries CIS 5.4'

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-PUBLIC_AMI-01)"
assert_eq '' "$_c_cis" 'C8 PUBLIC_AMI carries no cis value - v3.0.0 has no control for AMI sharing'

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-IMDSV2_NOT_ENFORCED-01)"
assert_eq '5.6' "$_c_cis" 'C9 IMDSV2_NOT_ENFORCED carries CIS 5.6'

IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$(_row CLOUD-EC2-FLOW_LOGS_OFF-01)"
assert_eq '3.7' "$_c_cis" 'C10 FLOW_LOGS_OFF carries CIS 3.7'

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
assert_eq "$_nf" "$_nfp" 'C11 every finding in the run has a distinct fingerprint'

# ===========================================================================
# D. Honesty: a denied family is a reduction; peer families are unaffected.
# ===========================================================================
t_case 'D. honesty accounting'

_routes_default describe-images
aws_fixture_route_add ec2 describe-images "$FIX/describe-images.denied.err"
_run_cloud "$W/run-d"
assert_eq '0' "$_RC" 'D1 a denied AMI list still exits 0 - a coverage loss, never a crash'
RUNJSON_D=$W/run-d/run.json
CHECKS_RUN_D=$(_json "$RUNJSON_D" checks_run)
REDUCTIONS_D=$(_json "$RUNJSON_D" coverage_reduction)

assert_not_contains "$CHECKS_RUN_D" 'CLOUD-EC2-PUBLIC_AMI-01' \
  'D2 a check whose ONLY family was denied is absent from checks_run'
assert_contains "$REDUCTIONS_D" 'operation=describe-images' \
  'D3 the denied describe-images call is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS_D" 'aws_api_access_denied' \
  'D4 classified through lib/awscli.sh-s own vocabulary, not a second one'

# The peer families - fed by SEPARATE API calls - are UNAFFECTED.  The reading
# this fails under is one family-s failure aborting the whole region pass, the
# way S3-s single list-buckets call legitimately does for every S3 check at
# once; EC2/VPC has no such single point of failure.
assert_contains "$CHECKS_RUN_D" 'CLOUD-EC2-SG_OPEN_ADMIN_PORT-01' \
  'D5 a peer check fed by a different API family still ran'
assert_contains "$CHECKS_RUN_D" 'CLOUD-EC2-UNENCRYPTED_VOLUME-01' \
  'D6 ... and so does another'
TBL_D=$(_findings_table "$W/run-d/findings.jsonl")
assert_contains "$(_ids_for_arn "$TBL_D" 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-badadmin1')" \
  'CLOUD-EC2-SG_OPEN_ADMIN_PORT-01' 'D7 ... and still produces a real finding'

# A check answered for NO resource in an ENTIRE ACCOUNT (denied in both
# regions) must never be silently reported as clean.  Deny the security-group
# family everywhere and confirm the two checks it alone feeds vanish from
# checks_run while a peer, unrelated check remains.
_routes_default describe-security-groups
aws_fixture_route_add ec2 describe-security-groups "$FIX/describe-security-groups.denied.err"
_run_cloud "$W/run-d2"
CR2=$(_json "$W/run-d2/run.json" checks_run)
RED2=$(_json "$W/run-d2/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-EC2-SG_OPEN_ADMIN_PORT-01' \
  'D9 a check denied in EVERY region is absent from checks_run entirely'
assert_not_contains "$CR2" 'CLOUD-EC2-DEFAULT_SG_IN_USE-01' \
  'D10 ... including its sibling that shares the same denied list call'
assert_contains "$CR2" 'CLOUD-EC2-IMDSV2_NOT_ENFORCED-01' \
  'D11 ... while an unrelated check is still credited'
assert_contains "$RED2" 'check=CLOUD-EC2-SG_OPEN_ADMIN_PORT-01' \
  'D12 ... and each has its own coverage_reduction saying so'

# ===========================================================================
# E. Round-trip: coverage cell in BOTH regions, and every report format.
# ===========================================================================
t_case 'E. round-trip'

RUNJSON=$W/run-b/run.json
assert_contains "$(_json "$RUNJSON" regions)" 'us-east-1' 'E1 run.json names us-east-1'
assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1b ... and eu-west-2 too'
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
    if cid.startswith('CLOUD-EC2-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(sorted(entry.get('cells') or []))))
print('\n'.join(out))
PYCOVER
)
# Every security group in EITHER region is "examined" for SG_OPEN_ADMIN_PORT
# whether or not it fires (`_ec2_pass_security_groups` notes it evaluated
# either way, exactly as `s3.sh`'s own per-bucket checks do for a hardened
# bucket), so its own cell list carries BOTH regions - asserted here as two
# separate substrings rather than one combined string, since the combined
# ordering (`eu-west-2` sorts first) would otherwise make a naive single
# assert_contains for "...123456789012/us-east-1" alone fail to match text
# that actually reads "...eu-west-2,123456789012/us-east-1".
_ADMIN_COVER=$(printf '%s\n' "$COVER" | awk '$1 == "CLOUD-EC2-SG_OPEN_ADMIN_PORT-01"')
assert_contains "$_ADMIN_COVER" 'account-region' \
  'E5 the run wrote a real account-region coverage cell for SG_OPEN_ADMIN_PORT-01'
assert_contains "$_ADMIN_COVER" '123456789012/us-east-1' \
  'E5b ... including the bad region'
# THIS IS THE MULTI-REGION PROOF: a check that answered in BOTH regions (an
# unencrypted volume in us-east-1, an ENCRYPTED one in eu-west-2 - still
# EXAMINED, just not a finding) is covered for BOTH cells, not only the one
# that produced a finding.  The reading this fails under is a walk that only
# ever visits one region in practice, which a single-cell assertion alone
# could not distinguish from the real thing.
assert_contains "$COVER" 'CLOUD-EC2-UNENCRYPTED_VOLUME-01 account-region 123456789012/eu-west-2,123456789012/us-east-1' \
  'E6 a check examined in BOTH regions is covered for BOTH cells - real multi-region iteration, not a single cell reused'

assert_file_exists "$W/run-b/report.md" 'E7 report.md written'
assert_file_exists "$W/run-b/report.html" 'E8 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-badadmin1' 'E9 report.md names the security group ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E10 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-EC2-SG_OPEN_ADMIN_PORT-01' 'E11 the SARIF run names the check as a rule'
assert_contains "$_SARIF" 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-badadmin1' 'E12 the SARIF result names the resource'
assert_contains "$_SARIF" '5.2' 'E13 the CIS control id authored on the check record reaches the SARIF rule tags'

_routes_default
_run_cloud "$W/run-audit" --format audit
assert_file_exists "$W/run-audit/report-audit.html" 'E14 --format audit writes report-audit.html'
_AUDIT=$(cat "$W/run-audit/report-audit.html")
assert_contains "$_AUDIT" 'CLOUD-EC2-' 'E15 the audit view carries the EC2/VPC checks'
# lib/report.sh's own coverage-strength note for the cloud category named the
# live catalog's real, current extent; this ticket adds a third service to
# it (S3 and API Gateway having already landed), and both halves are pinned
# here so the NEXT service to land finds a failing assertion rather than a
# stale sentence - the same discipline tests/suites/cloud-s3.sh's own E16/E17
# already established.
assert_contains "$_AUDIT" 'ships S3, API Gateway and EC2/VPC so far' \
  'E16 the audit view states the real, current extent of the live catalog'
assert_not_contains "$_AUDIT" 'ships the S3 and API Gateway services only so far' \
  'E17 ... and no longer claims S3+API Gateway are the only two'

t_summary cloud-ec2
