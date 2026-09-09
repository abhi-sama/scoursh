#!/usr/bin/env bash
# tests/suites/cloud-lambda.sh - modules/cloud/aws/live/lambda.sh: the §8.6
# Lambda read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-21).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently - the same five-part shape tests/suites/cloud-s3.sh
# established for this module's first service:
#
#   1. BOTH DIRECTIONS, IN ONE RUN. A public function and a hardened function
#      are examined by the SAME scan, so "the check fires" and "the check
#      stays quiet" are asserted against one code path in one process.
#   2. EVERY FINDING CITES ARN, REGION, ACCOUNT. `lambda` is a REGIONAL row in
#      `_CLOUD_SERVICES` (unlike `s3`'s `global` one), so - UNLIKE S3 - the
#      CELL and the finding's own `loc_region` are the SAME fact here: both
#      are the region the pass ran in, because `lambda list-functions` itself
#      only ever answers for one region at a time. Asserted directly, rather
#      than assumed by analogy to S3's own global/regional split.
#   3. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE, AND A
#      `ResourceNotFoundException`/`NoSuchEntity` IS AN ANSWER. Both are
#      pinned for `lambda get-policy` (not_found means "no resource policy",
#      not a loss) and for the IAM role-policy calls (a role whose BOTH
#      inline and attached-policy lookups are denied is a TOTAL loss for both
#      role checks, not a role that quietly reports zero grants).
#   4. THE TWO POLICY-DOCUMENT SHAPES BOTH PARSE. `lambda get-policy`'s
#      `Policy` field is always a JSON STRING; an IAM `PolicyDocument`/
#      `PolicyVersion.Document` MAY already arrive as a native object
#      (lambda_engine.sh section 4's own header explains the ambiguity this
#      codebase cannot resolve without a live AWS account) - this suite's
#      fixtures deliberately use the STRING shape for the role's INLINE
#      policy and the native-OBJECT shape for its ATTACHED MANAGED policy, so
#      one run proves both branches of `lambda_policy_prefix_set`.
#   5. THE FINDING ROUND-TRIPS, into findings.jsonl, into a real
#      `account-region` coverage cell, and into every report format.
#
# NO NETWORK AND NO AWS ACCOUNT. Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-lambda/.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a stub root cannot leak into the next
#   case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/cloud/aws/live/lambda_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain. shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own
# entry point.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/lambda_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-lambda
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath, so a fixture root reached through
# macOS's /var -> /private/var $TMPDIR symlink would fail E070 on every file
# for a reason that has nothing to do with the file (tests/suites/cloud-s3.sh
# documents the same fact).
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-lambda
PUB=scoursh-fixture-public-lambda
HARD=scoursh-fixture-hardened-lambda
DENY=scoursh-fixture-denied-lambda
PUB_ROLE=scoursh-fixture-lambda-admin-role
HARD_ROLE=scoursh-fixture-lambda-scoped-role
DENY_ROLE=scoursh-fixture-lambda-deny-role
MANAGED_ARN=arn:aws:iam::123456789012:policy/ExtraIamAccessPolicy

aws_fixture_stub_install "$W/bin"

# `_routes_default` - the route table every scan case starts from.
_routes_default() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add lambda list-functions    "$FIX/list-functions.json"

  aws_fixture_route_add_for lambda list-function-url-configs "$PUB"  "$FIX/list-function-url-configs.public.json"
  aws_fixture_route_add_for lambda list-function-url-configs "$HARD" "$FIX/list-function-url-configs.absent.json"
  aws_fixture_route_add_for lambda list-function-url-configs "$DENY" "$FIX/list-function-url-configs.denied.err"

  aws_fixture_route_add_for lambda get-policy "$PUB"  "$FIX/get-policy.public.json"
  aws_fixture_route_add_for lambda get-policy "$HARD" "$FIX/get-policy.notfound.err"
  aws_fixture_route_add_for lambda get-policy "$DENY" "$FIX/get-policy.denied.err"

  aws_fixture_route_add_for iam list-role-policies "$PUB_ROLE"  "$FIX/iam.list-role-policies.admin.json"
  aws_fixture_route_add_for iam list-role-policies "$HARD_ROLE" "$FIX/iam.list-role-policies.scoped.json"
  aws_fixture_route_add_for iam list-role-policies "$DENY_ROLE" "$FIX/iam.list-role-policies.denied.err"

  aws_fixture_route_add_for iam get-role-policy AdminAccess  "$FIX/iam.get-role-policy.admin-access.json"
  aws_fixture_route_add_for iam get-role-policy BasicLogging "$FIX/iam.get-role-policy.basic-logging.json"

  aws_fixture_route_add_for iam list-attached-role-policies "$PUB_ROLE"  "$FIX/iam.list-attached-role-policies.admin.json"
  aws_fixture_route_add_for iam list-attached-role-policies "$HARD_ROLE" "$FIX/iam.list-attached-role-policies.empty.json"
  aws_fixture_route_add_for iam list-attached-role-policies "$DENY_ROLE" "$FIX/iam.list-attached-role-policies.denied.err"

  aws_fixture_route_add_for iam get-policy "$MANAGED_ARN" "$FIX/iam.get-policy.extra-iam-access.json"
  aws_fixture_route_add_for iam get-policy-version "$MANAGED_ARN" "$FIX/iam.get-policy-version.extra-iam-access.json"
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess -
# tests/suites/cloud-s3.sh's own `_run_cloud`, copied: only a subprocess
# exercises the CLI parser, the dispatch arm, the check-registry load and the
# exit-code precedence table together. EACH INVOCATION GETS ITS OWN
# `SCOURSH_AWS_CACHE_DIR` for the identical reason that file's header states -
# `SCOURSH_SCRATCH` is exported, so every subprocess would otherwise share one
# cache keyed on `sha256(service|region|account|op|args)`, byte-identical
# across two cases whose ROUTE TABLE differs.
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

# One `check_id<US>loc_resource_key<US>loc_region<US>cell<US>cis<US>account<US>sub_key`
# line per finding, US (0x1f) rather than a TAB - tests/suites/cloud-s3.sh's own
# `_findings_table` uses a tab and gets away with it only because every S3
# public-exposure finding's `cis` field is non-empty; EVERY CLOUD-LAMBDA-*
# finding carries an EMPTY `cis` (no CIS v3.0.0 Lambda section exists to cite),
# and a tab is an IFS-*whitespace* character - `read` folds a run of them into
# ONE delimiter and drops a leading/trailing empty field (AGENTS.md's DAST-11
# lesson, "Things measured on this codebase"), which silently shifts every
# later column left by one. Measured here: the first draft of this suite
# copied cloud-s3.sh's tab-separated shape verbatim and its own C2/C4/C5/C7
# read the account id into the cis slot and the sub_key into the account slot.
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
        loc.get('sub_key', '') or '',
    ]))
PY
}

_ids_for_function() {
  local table=$1 fn=$2
  printf '%s\n' "$table" | awk -F $'\x1f' -v a="arn:aws:lambda:eu-west-2:123456789012:function:$fn" \
    '$2 == a { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

# The ARN partition and the role-name extraction.
assert_eq 'aws' "$(lambda_partition_of 'arn:aws:iam::123456789012:user/x')" 'A1 partition: commercial'
assert_eq 'aws-us-gov' "$(lambda_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A2 partition: GovCloud'
assert_eq 'aws' "$(lambda_partition_of '')" 'A3 partition: an unresolved caller ARN falls back to aws'
assert_eq 'my-role' "$(lambda_role_name_of 'arn:aws:iam::123456789012:role/my-role')" \
  'A4 role name: no IAM path'
assert_eq 'my-role' "$(lambda_role_name_of 'arn:aws:iam::123456789012:role/service-role/my-role')" \
  'A5 role name: an IAM path component is stripped, not just the first slash after role/ (the reading that fails takes everything after the FIRST slash, which would hand --role-name "service-role/my-role")'

# list-functions: the master doc, and the env-var reader over it.
lambda_doc_load "$FIX/list-functions.json"
_arn=''
lambda_function_field _arn 0 FunctionArn
assert_eq "arn:aws:lambda:eu-west-2:123456789012:function:$PUB" "$_arn" 'A6 list-functions: first function ARN is read'
_keys=''
lambda_env_keys_set _keys 0
assert_contains "$_keys" 'DB_PASSWORD' 'A7 env keys: DB_PASSWORD is present on the public function'
assert_contains "$_keys" 'AWS_KEY' 'A8 env keys: AWS_KEY is present on the public function'
assert_eq '0' "$(lambda_env_error_present 0 && echo 1 || echo 0)" 'A9 env error: the public function has no decrypt error'
assert_eq '1' "$(lambda_env_error_present 2 && echo 1 || echo 0)" \
  'A10 env error: the denied function DOES carry Environment.Error (index 2, the third function)'

# The secret-keyword and value-shape classifiers.
declare -a _LAMBDA_SECRET_KEYWORDS=()
lambda_secret_keywords_load "$ROOT/modules/cloud/aws/live/lambda-secret-env-keywords.txt"
assert_true "$(lambda_secret_keyword_matches "$(lambda_normalise_env_key DB_PASSWORD)" && echo 0 || echo 1)" \
  'A11 secret keyword: DB_PASSWORD matches (substring PASSWORD)'
assert_true "$(lambda_secret_keyword_matches "$(lambda_normalise_env_key STAGE)" && echo 1 || echo 0)" \
  'A12 secret keyword: STAGE does not match'
assert_eq 'an AWS access key id' "$(lambda_secret_value_shape AKIAABCDEFGHIJKLMNOP)" \
  'A13 value shape: a 20-char AKIA... value is recognised'
assert_true "$(lambda_secret_value_shape 'just-a-normal-value' >/dev/null && echo 1 || echo 0)" \
  'A14 value shape: an ordinary string matches nothing'

# The two policy-document shapes, both via lambda_policy_prefix_set, both
# feeding lambda_policy_scan - the reading A17/A19 fail under is handling
# only ONE of the two shapes lambda get-policy/iam get-role-policy can arrive
# in.
lambda_doc_load "$FIX/iam.get-role-policy.admin-access.json"
_prefix=''
lambda_policy_prefix_set _prefix PolicyDocument "$W"
assert_eq '' "$_prefix" 'A15 policy prefix: a STRING PolicyDocument reloads to a fresh document at the empty (root) prefix'
_admin=0; _sensitive=''
lambda_policy_scan "$_prefix" _admin _sensitive 'iam kms secretsmanager sts organizations ec2'
assert_eq '1' "$_admin" 'A16 policy scan: Action "*" + Resource "*" is admin'

lambda_doc_load "$FIX/iam.get-policy-version.extra-iam-access.json"
_prefix=''
lambda_policy_prefix_set _prefix "$(lambda_path PolicyVersion Document)" "$W"
assert_eq "$(lambda_path PolicyVersion Document)" "$_prefix" \
  'A17 policy prefix: a NATIVE OBJECT PolicyVersion.Document is read in place, no reload'
_admin=0; _sensitive=''
lambda_policy_scan "$_prefix" _admin _sensitive 'iam kms secretsmanager sts organizations ec2'
assert_eq '0' "$_admin" 'A18 policy scan: iam:* alone (Resource "*") is NOT admin'
assert_eq 'iam' "$_sensitive" 'A19 policy scan: iam:* is a sensitive-service match'

# The scoped (BasicLogging) policy triggers neither check - the reading this
# fails under is treating ANY Resource "*" grant as a hit, which the vast
# majority of ordinary Lambda execution-role boilerplate carries.
lambda_doc_load "$FIX/iam.get-role-policy.basic-logging.json"
_prefix=''
lambda_policy_prefix_set _prefix PolicyDocument "$W"
_admin=0; _sensitive=''
lambda_policy_scan "$_prefix" _admin _sensitive 'iam kms secretsmanager sts organizations ec2'
assert_eq '0' "$_admin" 'A20 policy scan: ordinary CloudWatch Logs boilerplate is not admin'
assert_eq '' "$_sensitive" 'A21 policy scan: ... and matches no sensitive service either'

# The resource policy's public-principal test, and the function-URL reader.
lambda_doc_load "$FIX/get-policy.public.json"
_prefix=''
lambda_policy_prefix_set _prefix Policy "$W"
assert_true "$(lambda_policy_public_principal "$_prefix" && echo 0 || echo 1)" \
  'A22 resource policy: Principal "*" is public'

lambda_doc_load "$FIX/list-function-url-configs.public.json"
_urls=''
lambda_url_public_urls_set _urls || true
assert_contains "$_urls" 'lambda-url.eu-west-2.on.aws' 'A23 function URL: AuthType NONE is reported'
lambda_doc_load "$FIX/list-function-url-configs.absent.json"
_urls='sentinel-must-be-cleared'
lambda_url_public_urls_set _urls || true
assert_eq '' "$_urls" 'A24 function URL: an empty FunctionUrlConfigs list is a clean answer'

# ===========================================================================
# B. One scan, three functions: fires on the bad one, quiet on the good one.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_function "$TBL" "$PUB")
HARD_IDS=$(_ids_for_function "$TBL" "$HARD")

for want in CLOUD-LAMBDA-ROLE_WILDCARD-01 CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01 \
  CLOUD-LAMBDA-PUBLIC_FUNCTION_URL-01 CLOUD-LAMBDA-PUBLIC_POLICY-01 \
  CLOUD-LAMBDA-ENV_SECRET-01 CLOUD-LAMBDA-ENV_NOT_ENCRYPTED-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public function is reported by $want"
done

# The hardened function, in the SAME run, produces nothing - the half a pack
# gone inert would also pass, which is why B3 is asserted from the same run:
# only both together distinguish "classifies correctly" from "never fires".
assert_eq '' "$HARD_IDS" 'B4 the hardened function in the SAME run produces no finding at all'

# The public function's ENV_SECRET-01 fires TWICE - once per credential-
# shaped variable (DB_PASSWORD by name, AWS_KEY by value shape) - because
# loc_sub_key carries the variable name and is a fingerprint component.
_secret_count=$(printf '%s\n' "$TBL" | awk -F $'\x1f' -v a="arn:aws:lambda:eu-west-2:123456789012:function:$PUB" \
  '$1 == "CLOUD-LAMBDA-ENV_SECRET-01" && $2 == a' | wc -l | tr -d '[:space:]')
assert_eq '2' "$_secret_count" 'B5 two distinct credential-shaped env vars are two distinct findings'

# ===========================================================================
# C. ARN, region, account, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_wild_row=$(printf '%s\n' "$TBL" | awk -F $'\x1f' '$1 == "CLOUD-LAMBDA-ROLE_WILDCARD-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_wild_row"

assert_eq "arn:aws:lambda:eu-west-2:123456789012:function:$PUB" "$_c_arn" 'C1 the finding cites the function ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq '' "$_c_cis" 'C4 no CIS control is cited - CIS v3.0.0 has no Lambda section (data/cis-mappings own header)'
assert_eq 'AdminAccess' "$_c_sub" 'C5 the offending inline policy name rides in loc_sub_key'

# UNLIKE S3 (whose cell is <account>/global and whose loc_region is the
# bucket's own region - two DIFFERENT facts), lambda is a REGIONAL service:
# the cell and loc_region are the SAME fact here, because list-functions only
# ever answers for the region it was addressed to. A test that only checked
# C3 would pass under an implementation that put the WRONG value in the cell
# (e.g. a literal "global"), so both are asserted and compared.
assert_eq '123456789012/eu-west-2' "$_c_cell" 'C6 the cell is <account>/<region> - the same region the finding itself cites'

_sensitive_row=$(printf '%s\n' "$TBL" | awk -F $'\x1f' '$1 == "CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01" { print; exit }')
IFS=$'\x1f' read -r _s_id _s_arn _s_region _s_cell _s_cis _s_account _s_sub <<<"$_sensitive_row"
assert_eq 'iam' "$_s_sub" 'C7 the sensitive-service sub_key names the matched service'

# Every finding in the run has a distinct fingerprint - two grantee/env
# classes on one resource are two fingerprints, never a collision.
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
# D. Honesty: a denied call is a reduction; a NotFound/ResourceNotFound is an
#    answer; a role whose BOTH policy calls fail is a total, declared loss.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

# The hardened function's `lambda get-policy` is ResourceNotFoundException -
# an ANSWER ("no resource policy"), not a loss. The reading D1/D2 fail under
# treats every non-zero aws_ro as a coverage loss, which would suppress
# PUBLIC_POLICY-01 as "not evaluated" for a function that is in fact clean.
assert_contains "$CHECKS_RUN" 'CLOUD-LAMBDA-PUBLIC_POLICY-01' \
  'D1 PUBLIC_POLICY-01 is credited as covered (it answered for the public AND the hardened function)'
assert_not_contains "$(_ids_for_function "$TBL" "$HARD")" 'CLOUD-LAMBDA-PUBLIC_POLICY-01' \
  'D2 ... and the hardened function itself carries no finding for it'

# The denied function: BOTH iam list-role-policies AND
# iam list-attached-role-policies fail, so _lambda_classify_role reports a
# TOTAL loss and NEITHER role check is credited as having answered for it -
# distinct from every OTHER function's role check still being credited from
# the public/hardened functions in the SAME run.
assert_contains "$REDUCTIONS" 'reason=aws_api_access_denied service=lambda operation=list-role-policies' \
  'D3 the denied role-s inline-policy lookup is its own declared coverage_reduction'
assert_contains "$REDUCTIONS" 'reason=aws_api_access_denied service=lambda operation=list-attached-role-policies' \
  'D4 ... and so is its attached-policy lookup, independently'
assert_contains "$REDUCTIONS" 'reason=role_unreadable' \
  'D5 the per-function role-check accounting records the TOTAL loss once both halves failed'
assert_contains "$CHECKS_RUN" 'CLOUD-LAMBDA-ROLE_WILDCARD-01' \
  'D6 ROLE_WILDCARD-01 is STILL credited overall - it answered for the public and hardened functions'

# The denied function's function-URL and resource-policy calls are each their
# own declared reduction - never silence, and never folded into one another.
assert_contains "$REDUCTIONS" 'operation=list-function-url-configs' \
  'D7 the denied function-URL lookup is a declared reduction'
assert_contains "$REDUCTIONS" 'operation=get-policy function=arn:aws:lambda:eu-west-2:123456789012:function:scoursh-fixture-denied-lambda' \
  'D8 ... and so is its resource-policy lookup'

# ENV_NOT_ENCRYPTED-01 is UNAFFECTED by the denied function's env-DECRYPT
# error: KMSKeyArn is a separate field from Variables, so this check still
# answers "no KMS key" for it even though ENV_SECRET-01 could not read the
# values. The reading this fails under folds both env checks into one
# all-or-nothing evaluation.
assert_contains "$(_ids_for_function "$TBL" "$DENY")" 'CLOUD-LAMBDA-ENV_NOT_ENCRYPTED-01' \
  'D9 ENV_NOT_ENCRYPTED-01 still fires for the denied function - it does not depend on decrypting the values'
assert_not_contains "$(_ids_for_function "$TBL" "$DENY")" 'CLOUD-LAMBDA-ENV_SECRET-01' \
  'D10 ENV_SECRET-01 does NOT fire for it - the values could not be decrypted at all'
assert_contains "$REDUCTIONS" 'reason=env_decrypt_error' \
  'D11 ... and that is its own declared reduction, not silent absence'

# A role denied for EVERY function in the run is absent from checks_run - the
# S3-equivalent "a check that answered for NO resource must not be credited"
# rule, reproduced here with `_routes_default` swapping BOTH role-policy
# calls to denied for every function.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add lambda list-functions    "$FIX/list-functions.json"
aws_fixture_route_add lambda list-function-url-configs "$FIX/list-function-url-configs.absent.json"
aws_fixture_route_add lambda get-policy "$FIX/get-policy.notfound.err"
aws_fixture_route_add iam list-role-policies "$FIX/iam.list-role-policies.denied.err"
aws_fixture_route_add iam list-attached-role-policies "$FIX/iam.list-attached-role-policies.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
assert_not_contains "$CR2" 'CLOUD-LAMBDA-ROLE_WILDCARD-01' \
  'D12 a check denied for EVERY function is absent from checks_run'
assert_not_contains "$CR2" 'CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01' 'D13 ... both role checks, together'
assert_contains "$CR2" 'CLOUD-LAMBDA-PUBLIC_FUNCTION_URL-01' \
  'D14 ... while its unaffected peer (function URL, a clean absent-config answer here) is still credited'

# The whole region unreachable: no function examined, nothing credited, the
# gap stated in the surfaces a consumer reads. The reading D17 fails under is
# exit 0 with an empty findings set and no explanation.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add lambda list-functions "$FIX/get-policy.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-LAMBDA-' 'D15 a denied list-functions credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'function list' \
  'D16 ... and the coverage_gap says the function list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'function list' \
  'D17 ... and it reaches report.md, the surface a consumer actually reads'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

_routes_default
_run_cloud "$W/run-e"
RUNJSON2=$W/run-e/run.json
assert_contains "$(_json "$RUNJSON2" regions)" 'eu-west-2' 'E1 run.json names the region the run resolved'
assert_eq '123456789012' "$(_json "$RUNJSON2" cloud.account_id)" 'E2 run.json records the scanned account'

RUN_ID=$(_json "$RUNJSON2" run_id)
assert_ne '' "$RUN_ID" 'E3 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E4 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-LAMBDA-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-LAMBDA-ROLE_WILDCARD-01 account-region 123456789012/eu-west-2' \
  'E5 the run wrote a REAL account-region coverage cell for lambda too'

assert_file_exists "$W/run-e/report.md" 'E6 report.md written'
assert_file_exists "$W/run-e/report.html" 'E7 report.html written'
_MD=$(cat "$W/run-e/report.md")
assert_contains "$_MD" "arn:aws:lambda:eu-west-2:123456789012:function:$PUB" 'E8 report.md names the function ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E9 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-LAMBDA-ROLE_WILDCARD-01' 'E10 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "arn:aws:lambda:eu-west-2:123456789012:function:$PUB" 'E11 the SARIF result names the resource'

_routes_default
_run_cloud "$W/run-audit" --format audit
assert_file_exists "$W/run-audit/report-audit.html" 'E12 --format audit writes report-audit.html'
_AUDIT=$(cat "$W/run-audit/report-audit.html")
assert_contains "$_AUDIT" 'CLOUD-LAMBDA-' 'E13 the audit view carries the lambda checks'
assert_contains "$_AUDIT" 'ships the S3 and lambda services only so far' \
  'E14 the audit view states the real, current extent of the live catalog, updated for this ticket'
assert_not_contains "$_AUDIT" 'ships the S3 service only so far' \
  'E15 ... and the pre-CLOUD-21 sentence naming only S3 is gone rather than left standing beside it'

t_summary cloud-lambda
