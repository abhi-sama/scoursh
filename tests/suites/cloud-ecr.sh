#!/usr/bin/env bash
# tests/suites/cloud-ecr.sh - modules/cloud/aws/live/ecr.sh: the §8.1 ECR
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-25).
#
# Mirrors tests/suites/cloud-s3.sh's own five-section shape (classifiers,
# both-directions-in-one-run, finding citation, honesty accounting,
# round-trip), narrowed to what is different about a REGIONAL service:
#
#   ECR IS `regional` IN `_CLOUD_SERVICES`, UNLIKE S3's `global`.  The
#   finding's `cell` and its `loc_region` are therefore the SAME value - the
#   pass's own region IS the repository's real region, with no separate
#   per-resource region-resolution call the way s3.sh needs.  Section C
#   below asserts they are EQUAL, the opposite of cloud-s3.sh's own section C
#   (which asserts they DIFFER, because S3's pass is account-wide).
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-ecr/.
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
# -x back-edge cut: see cloud-s3.sh's identical note - a real run already has
# modules/cloud/aws/engine.sh inlined by the time a service script is
# reached; following it from here would put this suite's hub sum over
# tests/lint-source-graph.sh's cap for no checking this tree does not already
# do from the module's own entry point.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/ecr_engine.sh"
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/iam_policy_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-ecr
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-ecr
BAD=scoursh-fixture-ecr-bad
GOOD=scoursh-fixture-ecr-good
DENY=scoursh-fixture-ecr-denied

aws_fixture_stub_install "$W/bin"

_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add ecr describe-repositories "$FIX/describe-repositories.json"
  aws_fixture_route_add_for ecr get-repository-policy "$BAD"  "$FIX/get-repository-policy.bad.json"
  aws_fixture_route_add_for ecr get-repository-policy "$GOOD" "$FIX/get-repository-policy.good.err"
  aws_fixture_route_add_for ecr get-repository-policy "$DENY" "$FIX/get-repository-policy.denied.err"
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

# FIELDS ARE JOINED WITH 0x1f, NEVER A TAB.  Most of these checks author no
# `cis` value at all (this file's own header explains why), so the CIS
# column is routinely EMPTY - and a tab is an IFS-*whitespace* character, so
# bash's own `read` COLLAPSES a run of them into one delimiter (POSIX XCU
# 2.6.5), silently dropping the empty field and shifting every column after
# it left by one. This is AGENTS.md's own DAST-11 "record stream" lesson,
# measured here for the first time in this module: cloud-s3.sh's identical
# TSV shape never tripped it only because the one row its own suite reads
# always carries a non-empty `cis`.
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
SEP = '\x1f'
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print(SEP.join([
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

_ids_for_repo() {
  local table=$1 repo=$2
  printf '%s\n' "$table" | awk -F$'\x1f' -v r="arn:aws:ecr:eu-west-2:123456789012:repository/$repo" '$2 == r { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

ecr_doc_load "$FIX/describe-repositories.json"
_n=''
ecr_repo_name_set _n 0
assert_eq "$BAD" "$_n" 'A1 describe-repositories: the first repository name is read'
assert_true "$(ecr_repo_tags_mutable 0 && echo 0 || echo 1)" 'A2 repo 0 (bad) has MUTABLE tags'
assert_true "$(ecr_repo_scan_on_push_off 0 && echo 0 || echo 1)" 'A3 repo 0 (bad) has scan-on-push off'
assert_true "$(ecr_repo_tags_mutable 1 && echo 1 || echo 0)" 'A4 repo 1 (good) does NOT have mutable tags'
assert_true "$(ecr_repo_scan_on_push_off 1 && echo 1 || echo 0)" 'A5 repo 1 (good) does NOT have scan-on-push off'
_arn=''
ecr_repo_arn_set _arn 0
assert_eq "arn:aws:ecr:eu-west-2:123456789012:repository/$BAD" "$_arn" \
  'A6 the repository ARN is read directly from the response, never constructed'

# ECR's policyText is a STRING field, still JSON-escaped inside the outer
# document - the reading this fails under is loading it as if it were
# already a nested object, which finds no Statement array at all.
ecr_doc_load "$FIX/get-repository-policy.bad.json"
_pt=''
ecr_doc_get _pt "$(ecr_path policyText)"
iampol_doc_load_text "$_pt"
# `iampol_public_principal_grant_set` is a SETTER: calling it inside a
# `$(...)` command substitution runs it in a subshell, so the `_sid` it
# writes is discarded the instant that subshell exits and the caller reads
# whatever `_sid` held BEFORE the call - the exact subshell hazard
# AGENTS.md's "things measured on this codebase" section names
# (`worker_id_set`'s own lesson). Call it directly, never through `$(...)`.
_sid='' _rc7=0
iampol_public_principal_grant_set _sid || _rc7=$?
assert_eq '0' "$_rc7" 'A7 a policyText with Principal "*" is found via the double-parse path'
assert_eq 'AllowPublicPull' "$_sid" 'A8 the offending statement Sid is reported'

# A statement with a real, non-wildcard principal is a real, checked "not
# public" answer - the reading this fails under is treating the double-parse
# path itself as evidence of publicness, regardless of what it finds.
cat >"$W/scoped-policy.json" <<'J'
{"Version":"2008-10-17","Statement":[{"Sid":"AllowOneAccount","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["ecr:BatchGetImage"]}]}
J
iampol_doc_load_text "$(cat "$W/scoped-policy.json")"
_sid='' _rc9=0
iampol_public_principal_grant_set _sid || _rc9=$?
assert_eq '1' "$_rc9" 'A9 a policy naming one specific account is NOT reported as public'

# ===========================================================================
# B. One scan, three repositories: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
BAD_IDS=$(_ids_for_repo "$TBL" "$BAD")
GOOD_IDS=$(_ids_for_repo "$TBL" "$GOOD")

for want in CLOUD-ECR-PUBLIC_REPOSITORY-01 CLOUD-ECR-SCAN_ON_PUSH_OFF-01 CLOUD-ECR-MUTABLE_TAGS-01; do
  assert_contains "$BAD_IDS" "$want" "B3 the bad repository is reported by $want"
done

# ... and the good repository in the SAME run produces no finding - the same
# run distinguishes "classifies correctly" from "never fires", the identical
# argument cloud-s3.sh's own section B makes.
assert_eq '' "$GOOD_IDS" 'B4 the good repository in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account - and cell EQUALS region, unlike S3's global pass.
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-ECR-MUTABLE_TAGS-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_row"

assert_eq "arn:aws:ecr:eu-west-2:123456789012:repository/$BAD" "$_c_arn" 'C1 the finding cites the repository ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '' "$_c_cis" \
  'C4 no cis value: CIS AWS Foundations Benchmark v3.0.0 has no ECR section (an honest absence, not a gap)'

# THE READING THIS FAILS UNDER IS S3's OWN SHAPE (cell always <account>/global
# regardless of the pass's real region), which would be wrong here: ECR is
# `regional`, so the cell IS this pass's own account/region cell, and it
# equals loc_region rather than differing from it the way S3's bucket region
# does.
assert_eq "123456789012/eu-west-2" "$_c_cell" 'C5 the cell is <account>/<region> - the pass this region actually covered'
assert_eq "$_c_region" "${_c_cell#*/}" 'C6 cell and loc_region agree, because ecr is a regional service'

_pub_row=$(printf '%s\n' "$TBL" | awk -F$'\x1f' '$1 == "CLOUD-ECR-PUBLIC_REPOSITORY-01" { print; exit }')
_pub_sub=$(printf '%s\n' "$_pub_row" | awk -F$'\x1f' '{print $7}')
assert_eq 'AllowPublicPull' "$_pub_sub" 'C7 the offending statement Sid rides in loc_sub_key'

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
# D. Honesty: a denied call is a reduction; NotFound is an answer.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The denied repository's get-repository-policy was AccessDenied. The check
# still ran (two other repositories answered), so it IS in checks_run - and
# the partial loss is recorded beside it.
assert_contains "$CHECKS_RUN" 'CLOUD-ECR-PUBLIC_REPOSITORY-01' \
  'D1 a check that answered for SOME repositories is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on one repository is recorded as a coverage_reduction'
assert_not_contains "$(_ids_for_repo "$TBL" "$DENY")" 'CLOUD-ECR-PUBLIC_REPOSITORY' \
  'D3 no public-repository finding is invented for a repository whose policy was never read'

# `RepositoryPolicyNotFoundException` is an ANSWER meaning "no policy, so not
# public" - the reading D4/D5 fail under is "every non-zero aws_ro is a
# coverage loss", which would suppress the finding on the bad repository too
# were it the one denied instead of not-found.
assert_not_contains "$(_ids_for_repo "$TBL" "$GOOD")" 'CLOUD-ECR-PUBLIC_REPOSITORY' \
  'D4 NoSuch*/NotFoundException is "no policy", not a public one'
assert_contains "$CHECKS_RUN" 'CLOUD-ECR-PUBLIC_REPOSITORY-01' \
  'D5 ... and it still counts as the check having been covered'

# The whole repository list unreadable: nothing examined, nothing credited,
# and the gap stated where a consumer reads it.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add ecr describe-repositories "$FIX/get-repository-policy.denied.err"
_run_cloud "$W/run-denied"
CR2=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-ECR-' 'D6 a denied describe-repositories credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'repository list' \
  'D7 ... and the coverage_gap says the repository list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'E1 run.json names the regions the run resolved'
RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E2 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E3 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-ECR-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-ECR-MUTABLE_TAGS-01 account-region 123456789012/eu-west-2' \
  'E4 the run wrote a real account-region coverage cell for the region it actually visited'

assert_file_exists "$W/run-b/report.md" 'E5 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "arn:aws:ecr:eu-west-2:123456789012:repository/$BAD" 'E6 report.md names the repository ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E7 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-ECR-MUTABLE_TAGS-01' 'E8 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "arn:aws:ecr:eu-west-2:123456789012:repository/$BAD" 'E9 the SARIF result names the resource'

t_summary cloud-ecr
