#!/usr/bin/env bash
# tests/suites/cloud-s3.sh - modules/cloud/aws/live/s3.sh: the §8.1 S3
# read-only checks, and the first end-to-end proof of the whole cloud chain
# (docs/STEP6-CLOUD-PLAN.md CLOUD-05).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently:
#
#   1. BOTH DIRECTIONS, IN ONE RUN.  A public bucket and a hardened bucket are
#      examined by the SAME scan, so "the check fires" and "the check stays
#      quiet" are asserted against one code path in one process.  A pack gone
#      inert passes every silence assertion ever written, and two separate
#      runs (one all-bad, one all-good) cannot tell the two apart - which is
#      why tests/lib/aws-fixtures.sh grew per-argument routing for this
#      ticket rather than this suite settling for two runs.
#   2. EVERY FINDING CITES ARN, REGION, ACCOUNT AND - WHERE ONE EXISTS - A CIS
#      CONTROL ID.  Asserted on the emitted finding's own fields, not on the
#      script's intent.
#   3. THE REGION IS THE BUCKET'S, THE CELL IS THE PASS'S, AND THEY DIFFER.
#      The public bucket is in eu-west-2 and the hardened one in us-east-1 (via
#      the `LocationConstraint: null` spelling), while BOTH findings sit in the
#      `<account>/global` cell - the cell modules/cloud/aws/run.sh actually
#      credits coverage to.  A test that only checked the region would pass
#      under the implementation that writes the region into the cell too,
#      which is the defect that leaves every remediated bucket permanently
#      `unknown`.
#   4. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE, AND A
#      `NoSuch*` ERROR IS AN ANSWER.  Both are pinned, because the naive fix
#      for each is the other's bug: treat every error as a loss and the three
#      absence checks stop firing on exactly the buckets that have the
#      problem; treat every error as an answer and an AccessDenied renders as a
#      correctly-configured bucket.
#   5. THE FINDING ROUND-TRIPS.  Into findings.jsonl, into a real
#      `account-region` coverage cell in state/ (lib/state.sh's own header
#      records that no real emitter existed before this ticket), and into
#      every report format including SARIF and the audit view.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-s3/.
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
# -x back-edge cut: modules/cloud/aws/live/s3_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain.  shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own entry
# point.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/s3_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-s3
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL prefix
# from every loaded file's realpath, so a fixture root reached through macOS's
# /var -> /private/var $TMPDIR symlink would fail E070 on every file for a
# reason that has nothing to do with the file (tests/suites/cloud.sh documents
# the same fact).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-s3
PUB=scoursh-fixture-public-bucket
HARD=scoursh-fixture-hardened-bucket
DENY=scoursh-fixture-denied-bucket

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from: the two
# calls modules/cloud/aws/run.sh makes before any service script, plus
# `list-buckets`, plus a per-bucket row for each of the three fixture buckets.
#
# THE PER-BUCKET ROWS ARE QUALIFIED ON THE BUCKET NAME, which is what puts a
# public, a hardened and a permission-denied bucket into ONE run.  An
# unqualified row would serve all three buckets the same response, and the
# suite would then be unable to distinguish a check that classifies correctly
# from one that reports whatever the last fixture said.
# An optional argument names ONE operation whose per-bucket rows are omitted,
# so a case can register a single unqualified row for it instead.  Without
# that, an unqualified row added afterwards would never be reached: a
# qualified row always wins for the bucket it names, which is the whole point
# of qualified routing and is exactly the shape a test can get wrong silently
# (the case would then assert against the ORIGINAL fixtures and pass for the
# wrong reason).
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add s3api list-buckets      "$FIX/list-buckets.json"

  if [[ $omit != get-bucket-location ]]; then
    aws_fixture_route_add_for s3api get-bucket-location "$PUB"  "$FIX/get-bucket-location.public.json"
    aws_fixture_route_add_for s3api get-bucket-location "$HARD" "$FIX/get-bucket-location.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-location "$DENY" "$FIX/get-bucket-location.denied.json"
  fi

  if [[ $omit != get-bucket-acl ]]; then
    aws_fixture_route_add_for s3api get-bucket-acl "$PUB"  "$FIX/get-bucket-acl.public.json"
    aws_fixture_route_add_for s3api get-bucket-acl "$HARD" "$FIX/get-bucket-acl.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-acl "$DENY" "$FIX/get-bucket-acl.denied.err"
  fi

  if [[ $omit != get-bucket-policy-status ]]; then
    aws_fixture_route_add_for s3api get-bucket-policy-status "$PUB"  "$FIX/get-bucket-policy-status.public.json"
    aws_fixture_route_add_for s3api get-bucket-policy-status "$HARD" "$FIX/get-bucket-policy-status.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-policy-status "$DENY" "$FIX/get-bucket-policy-status.nopolicy.err"
  fi

  if [[ $omit != get-public-access-block ]]; then
    aws_fixture_route_add_for s3api get-public-access-block "$PUB"  "$FIX/get-public-access-block.absent.err"
    aws_fixture_route_add_for s3api get-public-access-block "$HARD" "$FIX/get-public-access-block.hardened.json"
    aws_fixture_route_add_for s3api get-public-access-block "$DENY" "$FIX/get-public-access-block.partial.json"
  fi

  if [[ $omit != get-bucket-encryption ]]; then
    aws_fixture_route_add_for s3api get-bucket-encryption "$PUB"  "$FIX/get-bucket-encryption.absent.err"
    aws_fixture_route_add_for s3api get-bucket-encryption "$HARD" "$FIX/get-bucket-encryption.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-encryption "$DENY" "$FIX/get-bucket-encryption.hardened.json"
  fi

  if [[ $omit != get-bucket-versioning ]]; then
    aws_fixture_route_add_for s3api get-bucket-versioning "$PUB"  "$FIX/get-bucket-versioning.absent.json"
    aws_fixture_route_add_for s3api get-bucket-versioning "$HARD" "$FIX/get-bucket-versioning.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-versioning "$DENY" "$FIX/get-bucket-versioning.suspended.json"
  fi

  if [[ $omit != get-bucket-logging ]]; then
    aws_fixture_route_add_for s3api get-bucket-logging "$PUB"  "$FIX/get-bucket-logging.absent.json"
    aws_fixture_route_add_for s3api get-bucket-logging "$HARD" "$FIX/get-bucket-logging.hardened.json"
    aws_fixture_route_add_for s3api get-bucket-logging "$DENY" "$FIX/get-bucket-logging.hardened.json"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess.  A
# subprocess rather than a sourced call, for tests/suites/cloud.sh's own
# reason: the CLI parser, the dispatch arm, the check-registry load and the
# exit-code precedence table are four separate mechanisms this suite asserts
# the interaction of, and only a subprocess exercises all four.
#
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR`, and without that this
# suite tests the wrong thing.  `SCOURSH_SCRATCH` is exported, so every
# subprocess would otherwise inherit ONE cache whose key is
# sha256(service|region|account|op|args) - byte-identical across two cases
# whose ROUTE TABLE differs, so the second case would be served the first
# case's responses.  tests/suites/cloud.sh measured exactly that failure and
# tests/lib/aws-fixtures.sh's own header records it from the other side.
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

# One `check_id<TAB>loc_resource_key<TAB>loc_region<TAB>cell<TAB>cis` line per
# finding, read from findings.jsonl.
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

_ids_for_bucket() {
  local table=$1 bucket=$2
  printf '%s\n' "$table" | awk -F'\t' -v b="arn:aws:s3:::$bucket" '$2 == b { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

s3_doc_load "$FIX/list-buckets.json"
assert_eq "$PUB" "${_S3_DOC[$(s3_path Buckets 0 Name)]:-}" 'A1 list-buckets: first bucket name is read'
assert_true "$(s3_doc_has "$(s3_path Buckets 2 Name)" && echo 0 || echo 1)" \
  'A2 list-buckets: the third bucket is present (the walk does not stop early)'
assert_true "$(s3_doc_has "$(s3_path Buckets 3 Name)" && echo 1 || echo 0)" \
  'A3 list-buckets: there is no fourth bucket (the walk has a real end)'

# The region rule, all three spellings.  A parser that takes the value verbatim
# labels every us-east-1 bucket with an empty region - and loc_region is a
# fingerprint component, so the finding's identity would change the day the
# parser was fixed and the old finding could never be classified `fixed`.
_r=''
s3_doc_load "$FIX/get-bucket-location.public.json"; s3_location_region_set _r
assert_eq 'eu-west-2' "$_r" 'A4 get-bucket-location: an explicit constraint is the region'
s3_doc_load "$FIX/get-bucket-location.hardened.json"; s3_location_region_set _r
assert_eq 'us-east-1' "$_r" 'A5 get-bucket-location: JSON null means us-east-1, not the empty string'
printf '{"LocationConstraint": "EU"}\n' >"$W/eu.json"
s3_doc_load "$W/eu.json"; s3_location_region_set _r
assert_eq 'eu-west-1' "$_r" 'A6 get-bucket-location: the legacy EU alias resolves to eu-west-1'

# The ACL.  The owner grant comes FIRST in a real response and carries no
# Grantee.URI, so a walk that stops at the first URI-less grant reports every
# bucket clean - the reading A7 fails under.
s3_doc_load "$FIX/get-bucket-acl.public.json"
_g=''
s3_acl_public_grants_set _g
assert_contains "$_g" 'AllUsers READ' 'A7 ACL: a public grant AFTER the owner grant is still found'
assert_contains "$_g" 'AllUsers READ_ACP' 'A8 ACL: every public grant is reported, not only the first'
assert_contains "$_g" 'AuthenticatedUsers WRITE' 'A9 ACL: AuthenticatedUsers is a public grantee too'
assert_eq '3' "$(printf '%s\n' "$_g" | grep -c .)" 'A10 ACL: the owner CanonicalUser grant is NOT reported'

s3_doc_load "$FIX/get-bucket-acl.hardened.json"
s3_acl_public_grants_set _g
assert_eq '' "$_g" 'A11 ACL: an owner-only ACL yields no public grant'

# A grantee whose DISPLAY NAME contains the group name is not a public grant.
# The reading this fails under is a substring test over the whole document.
cat >"$W/acl-lookalike.json" <<'J'
{
    "Owner": {"DisplayName": "AllUsers", "ID": "2222"},
    "Grants": [
        {
            "Grantee": {"DisplayName": "http://acs.amazonaws.com/groups/global/AllUsers", "ID": "2222", "Type": "CanonicalUser"},
            "Permission": "FULL_CONTROL"
        }
    ]
}
J
s3_doc_load "$W/acl-lookalike.json"
s3_acl_public_grants_set _g
assert_eq '' "$_g" 'A12 ACL: a canonical-user grantee whose DisplayName echoes the group URI is not public'

assert_true "$(s3_permission_is_write FULL_CONTROL && echo 0 || echo 1)" 'A13 FULL_CONTROL counts as write'
assert_true "$(s3_permission_is_write WRITE_ACP && echo 0 || echo 1)" 'A14 WRITE_ACP counts as write'
assert_true "$(s3_permission_is_write READ && echo 1 || echo 0)" 'A15 READ does not count as write'

s3_doc_load "$FIX/get-bucket-policy-status.public.json"
assert_true "$(s3_policy_is_public && echo 0 || echo 1)" 'A16 policy-status: IsPublic true is public'
s3_doc_load "$FIX/get-bucket-policy-status.hardened.json"
assert_true "$(s3_policy_is_public && echo 1 || echo 0)" 'A17 policy-status: IsPublic false is not public'

# All four Block Public Access settings are required, and an ABSENT key is a
# gap.  The reading A19 fails under is `[[ $v == false ]]`, which reports a
# response that simply omits a setting as fully protected.
_gp=''
s3_doc_load "$FIX/get-public-access-block.hardened.json"; s3_bpa_gaps_set _gp
assert_eq '' "$_gp" 'A18 BPA: all four true is no gap'
s3_doc_load "$FIX/get-public-access-block.partial.json"; s3_bpa_gaps_set _gp
assert_eq 'BlockPublicPolicy RestrictPublicBuckets' "$_gp" \
  'A19 BPA: an explicitly-false AND an entirely absent setting are both gaps'

_a=''
s3_doc_load "$FIX/get-bucket-encryption.hardened.json"
assert_true "$(s3_encryption_algorithm_set _a && echo 0 || echo 1)" 'A20 encryption: SSE-S3 (AES256) counts as configured'
s3_doc_load "$FIX/get-bucket-encryption.hardened.json"; s3_encryption_algorithm_set _a || true
assert_eq 'AES256' "$_a" 'A21 encryption: the algorithm is read out of the first rule'

_v=''
s3_doc_load "$FIX/get-bucket-versioning.hardened.json"; s3_versioning_status_set _v || true
assert_eq 'Enabled' "$_v" 'A22 versioning: Enabled is read'
s3_doc_load "$FIX/get-bucket-versioning.absent.json"; s3_versioning_status_set _v || true
assert_eq 'None' "$_v" 'A23 versioning: an empty {} document is None, not the empty string'
s3_doc_load "$FIX/get-bucket-versioning.suspended.json"
assert_true "$(s3_versioning_status_set _v && echo 1 || echo 0)" 'A24 versioning: Suspended is not a pass'

_t=''
s3_doc_load "$FIX/get-bucket-logging.hardened.json"
assert_true "$(s3_logging_target_set _t && echo 0 || echo 1)" 'A25 logging: a LoggingEnabled block is a pass'
s3_doc_load "$FIX/get-bucket-logging.absent.json"
assert_true "$(s3_logging_target_set _t && echo 1 || echo 0)" 'A26 logging: an empty {} document is not'

# The ARN.  A hardcoded `aws` partition names a resource that does not exist in
# GovCloud or China, which is the reading A28/A29 fail under.
assert_eq 'aws' "$(s3_partition_of 'arn:aws:iam::123456789012:user/x')" 'A27 partition: commercial'
assert_eq 'aws-us-gov' "$(s3_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A28 partition: GovCloud'
assert_eq 'aws-cn' "$(s3_partition_of 'arn:aws-cn:iam::123456789012:user/x')" 'A29 partition: China'
assert_eq 'aws' "$(s3_partition_of '')" 'A30 partition: an unresolved caller ARN falls back to aws'
assert_eq 'arn:aws:s3:::b' "$(s3_bucket_arn aws b)" 'A31 bucket ARN carries no account and no region, by the ARN format'

# ===========================================================================
# B. One scan, three buckets: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_bucket "$TBL" "$PUB")
HARD_IDS=$(_ids_for_bucket "$TBL" "$HARD")

# The public bucket is wrong in every way the seven checks can observe.
for want in CLOUD-S3-PUBLIC_ACL_READ-01 CLOUD-S3-PUBLIC_ACL_WRITE-01 \
  CLOUD-S3-PUBLIC_POLICY-01 CLOUD-S3-BLOCK_PUBLIC_ACCESS_OFF-01 \
  CLOUD-S3-NO_DEFAULT_ENCRYPTION-01 CLOUD-S3-NO_VERSIONING-01 CLOUD-S3-NO_LOGGING-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public bucket is reported by $want"
done

# ... and the hardened bucket is right in every one of them.  This is the half
# a pack gone inert would also pass, which is why B3 is asserted from the same
# run: only both together distinguish "classifies correctly" from "never
# fires".
assert_eq '' "$HARD_IDS" 'B4 the hardened bucket in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account, CIS, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_acl_read_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-S3-PUBLIC_ACL_READ-01" { print; exit }')
IFS=$'\t' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_acl_read_row"

assert_eq "arn:aws:s3:::$PUB" "$_c_arn" 'C1 the finding cites the bucket ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the BUCKET-s own region, not the run-s'
assert_eq '2.1.4' "$_c_cis" 'C4 the finding carries the cis control id authored on its check record'
assert_eq 'AllUsers' "$_c_sub" 'C5 the grantee class rides in loc_sub_key'

# The cell is the PASS-s, and it differs from the region on purpose.  A test
# that asserted only C3 would pass under the implementation that also writes
# the bucket-s region into the cell - which files every finding in a cell no
# pass ever covers, so tension 12 can never classify one `fixed` and every
# remediated bucket sits at `unknown` forever.
assert_eq '123456789012/global' "$_c_cell" 'C6 the cell is <account>/global, the cell the pass actually covered'

# The hardened bucket is in us-east-1 via the `LocationConstraint: null`
# spelling, so its region can only be checked through a finding - and it has
# none.  The NO_DEFAULT_ENCRYPTION finding on the DENIED bucket is the one
# whose fixtures make it hardened, so use versioning, which is Suspended there.
_deny_ver=$(printf '%s\n' "$TBL" | awk -F'\t' -v b="arn:aws:s3:::$DENY" \
  '$1 == "CLOUD-S3-NO_VERSIONING-01" && $2 == b { print $3; exit }')
assert_eq 'eu-west-2' "$_deny_ver" 'C7 a second bucket-s finding cites that bucket-s own region'

# Two grantee classes on one bucket are TWO findings, because loc_sub_key is a
# fingerprint component.  Under one shared sub_key they would collide and
# findings_merge would keep whichever sorted first.
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
# D. Honesty: a denied call is a reduction; a NoSuch* error is an answer.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The denied bucket-s get-bucket-acl was AccessDenied.  The ACL checks still
# ran (two other buckets answered), so they ARE in checks_run - and the partial
# loss is recorded beside them.  Reporting only the first overstates coverage;
# reporting only the second suppresses a cell the run genuinely did visit.
assert_contains "$CHECKS_RUN" 'CLOUD-S3-PUBLIC_ACL_READ-01' \
  'D1 a check that answered for SOME buckets is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on one bucket is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'buckets_unanswered=1' \
  'D3 the reduction says how many buckets did not answer'
assert_not_contains "$(_ids_for_bucket "$TBL" "$DENY")" 'CLOUD-S3-PUBLIC_ACL' \
  'D4 no ACL finding is invented for the bucket whose ACL was never read'

# `NoSuchPublicAccessBlockConfiguration` and
# `ServerSideEncryptionConfigurationNotFoundError` are ERRORS that carry the
# answer.  The reading D5/D6 fail under is "every non-zero aws_ro is a coverage
# loss", which suppresses these two findings on exactly the buckets that have
# the problem.
assert_contains "$PUB_IDS" 'CLOUD-S3-BLOCK_PUBLIC_ACCESS_OFF-01' \
  'D5 an absent Block Public Access configuration (a NoSuch* error) IS the finding'
assert_contains "$PUB_IDS" 'CLOUD-S3-NO_DEFAULT_ENCRYPTION-01' \
  'D6 an absent encryption configuration (a NotFoundError) IS the finding'

# `NoSuchBucketPolicy` is the mirror image: an answer meaning "no policy", so
# no finding and no reduction for that check on that bucket.
assert_not_contains "$(_ids_for_bucket "$TBL" "$DENY")" 'CLOUD-S3-PUBLIC_POLICY-01' \
  'D7 NoSuchBucketPolicy is "no policy", not a public one'
assert_contains "$CHECKS_RUN" 'CLOUD-S3-PUBLIC_POLICY-01' \
  'D8 ... and it counts as the check having been covered'

# A check that answered for NO bucket must NOT be in checks_run: crediting it
# would let tension 12 report a prior finding `fixed` on the strength of a call
# that was denied for every bucket in the account.
_routes_default get-bucket-versioning
aws_fixture_route_add s3api get-bucket-versioning "$FIX/get-bucket-acl.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-S3-NO_VERSIONING-01' \
  'D9 a check denied for EVERY bucket is absent from checks_run'
assert_contains "$CR2" 'CLOUD-S3-NO_LOGGING-01' \
  'D10 ... while its unaffected peers are still credited'
assert_contains "$RED2" 'check=CLOUD-S3-NO_VERSIONING-01' \
  'D11 ... and it has its own coverage_reduction saying so'

# The whole account unreadable: no bucket examined, nothing credited, and the
# gap stated in the surfaces a consumer reads.  The reading D13 fails under is
# exit 0 with an empty findings set and no explanation, which is a denied scan
# rendered as a clean account.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add s3api list-buckets      "$FIX/get-bucket-acl.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-S3-' 'D12 a denied list-buckets credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'bucket list' \
  'D13 ... and the coverage_gap says the bucket list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'bucket list' \
  'D14 ... and it reaches report.md, the surface a consumer actually reads'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the regions the run resolved'
assert_eq '123456789012' "$(_json "$RUNJSON" cloud.account_id)" 'E2 run.json records the scanned account'

# lib/state.sh's own header records that `account-region` had NO REAL EMITTER
# before this ticket - "the fixtures are HAND-AUTHORED, schema-only proof".
# This is the assertion that closes that gap, and it is made on the state
# snapshot THIS run wrote, located by the run id run.json itself carries rather
# than by guessing at the newest file in a shared directory.
RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E3 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E4 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-S3-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-S3-PUBLIC_ACL_READ-01 account-region 123456789012/global' \
  'E5 the run wrote a REAL account-region coverage cell - the first in this repository'
assert_not_contains "$COVER" '123456789012/eu-west-2' \
  'E6 coverage is credited to the cell the pass covered, never to a bucket-s own region'

# Every report format, and the two facts a cloud consumer reads them for.
assert_file_exists "$W/run-b/report.md" 'E7 report.md written'
assert_file_exists "$W/run-b/report.html" 'E8 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "arn:aws:s3:::$PUB" 'E9 report.md names the bucket ARN'
# THE CIS CONTROL ID REACHES SARIF, NOT report.md, AND THAT IS THE CURRENT
# CONTRACT RATHER THAN A GAP THIS TICKET LEFT.  docs/CIS-MAPPINGS.md §7 states
# it in terms: the label table "renders nothing - no CIS section exists in
# report.md or report.html", because the CIS report VIEW is COMPLIANCE-04, a
# separate ticket that this one unblocks by being the first check to author a
# real `cis:` value.  Asserting a CIS section in report.md would therefore pin
# a behaviour nothing has built; asserting its ABSENCE is what makes the day
# COMPLIANCE-04 lands visible here instead of silent.
assert_not_contains "$_MD" 'CIS Amazon Web Services Foundations Benchmark' \
  'E10 report.md carries no CIS section yet - that view is COMPLIANCE-04, which this ticket unblocks'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E11 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-S3-PUBLIC_ACL_READ-01' 'E12 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "arn:aws:s3:::$PUB" 'E13 the SARIF result names the resource'
assert_contains "$_SARIF" '2.1.4' \
  'E13b the CIS control id authored on the check record reaches the SARIF rule tags'

_routes_default
_run_cloud "$W/run-audit" --format audit
assert_file_exists "$W/run-audit/report-audit.html" 'E14 --format audit writes report-audit.html'
_AUDIT=$(cat "$W/run-audit/report-audit.html")
assert_contains "$_AUDIT" 'CLOUD-S3-' 'E15 the audit view carries the cloud checks'
# lib/report.sh's own coverage-strength note for the cloud category described
# `modules/cloud/aws/live/` as shipping no service script at all.  That claim
# is this ticket's to correct, and it is pinned in both directions here so the
# next service to land finds a failing assertion rather than a stale sentence.
# CLOUD-22 (`aws/live/apigw.sh`) is exactly that next service, and it DID find
# this assertion failing - updated here, in the same change that widened
# lib/report.sh's own sentence, rather than left to go stale a second time.
assert_contains "$_AUDIT" 'ships the S3 and API Gateway services only so far' \
  'E16 the audit view states the real, current extent of the live catalog'
assert_not_contains "$_AUDIT" 'ships no service script yet' \
  'E17 ... and no longer claims the catalog is empty'

t_summary cloud-s3
