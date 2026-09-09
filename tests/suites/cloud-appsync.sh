#!/usr/bin/env bash
# tests/suites/cloud-appsync.sh - modules/cloud/aws/live/appsync.sh: the §8.5
# AppSync read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-23).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently - the same five-part shape tests/suites/cloud-s3.sh
# established, adapted for a REGIONAL service and for TWO INDEPENDENT checks
# over two DIFFERENT resource kinds (an API; one of its keys):
#
#   1. BOTH DIRECTIONS, IN ONE RUN.  A plain-API-key API, an AWS_IAM API, a
#      Cognito API whose own additional API key is STILL long-lived, and an
#      access-denied API are all examined by the SAME scan - "the check fires"
#      and "the check stays quiet" are asserted against one code path in one
#      process, exactly as cloud-s3.sh's own section B argues.
#   2. THE TWO CHECKS ARE GENUINELY INDEPENDENT.  An API whose default auth is
#      Cognito, not API_KEY, still has a key that can be long-lived (an
#      additional authentication provider) - CLOUD-APPSYNC-
#      API_KEY_DEFAULT_AUTH-01 must stay quiet on it while CLOUD-APPSYNC-
#      API_KEY_LONG_EXPIRY-01 still fires, in the SAME run.
#   3. UNLIKE S3, APPSYNC IS REGIONAL - AND THE SECOND, EMPTY REGION IS A REAL
#      ASSERTION, NOT A GAP.  eu-west-2 has zero GraphQL APIs; the pass must
#      still record that it looked (a `notes ... covered vacuously` line) and
#      must NOT credit either check's coverage cell for a region it examined
#      but found nothing in - the identical (check, cell) pairing
#      docs/FOUNDATION.md tension 12 exists to enforce.
#   4. EVERY FINDING CITES ARN, REGION, ACCOUNT - AND, DELIBERATELY, NO `cis`
#      VALUE.  CIS Amazon Web Services Foundations Benchmark v3.0.0 has no
#      AppSync section at all, so an honest absence is asserted directly
#      rather than left untested, per the identical judgement
#      modules/cloud/aws/live/checks.rules records for three of S3's own
#      checks.
#   5. A DENIED `list-api-keys` CALL IS A `coverage_reduction`, NEVER SILENCE
#      - AND, UNLIKE S3, NEITHER CHECK HERE HAS A `NoSuch*`-SHAPED "absence IS
#      the answer" CASE, so every non-ok outcome on that call is a loss, full
#      stop.
#   6. THE FINDING ROUND-TRIPS - into findings.jsonl, into a real
#      `account-region` coverage cell in state/ for BOTH region cells, and
#      into every report format including SARIF.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-appsync/.
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
# -x back-edge cut: modules/cloud/aws/live/appsync_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain.  shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own entry
# point.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/appsync_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-appsync
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL prefix
# from every loaded file's realpath, so a fixture root reached through macOS's
# /var -> /private/var $TMPDIR symlink would fail E070 on every file for a
# reason that has nothing to do with the file (tests/suites/cloud-s3.sh
# documents the same fact).
W=$(cd -- "$W" && pwd -P)

# THE REAL 0x1f BYTE, NEVER THE FOUR-CHARACTER STRING `\x1f` PASSED TO `awk
# -F` DIRECTLY.  `awk -F'\x1f'` was this suite's own first draft and it is a
# real, measured defect: POSIX awk's `-F` value undergoes the SAME escape
# processing as a string literal inside the AWK language, which covers `\t`,
# `\n`, and a handful of others, but has no portable `\x` hex-escape - so
# whether `\x1f` is even recognised at all depends on the awk implementation,
# and on one that does not it is read as the literal four bytes `\`, `x`, `1`,
# `f`, which appears nowhere in the joined table, so the whole line becomes
# field 1 and every `$2 == ...` comparison below silently never matches.
# Expanding the REAL byte here, once, and handing awk `-F"$US"` sidesteps its
# escape processing entirely - the shell has already turned it into one raw
# byte before awk ever sees the argument.  Measured while writing this suite:
# B3/B6/B7/B9 and C1/C2/C3/C5/C6 all read as "the finding was never emitted"
# under the `-F'\x1f'` spelling, on a table that a hexdump confirmed carried
# real, correctly-separated fields all along.
US=$'\x1f'

FIX=$ROOT/tests/fixtures/aws/cloud-appsync
PLAINKEY=abcdefapikey01
IAMAUTH=abcdefiamauth02
COGNITO=abcdefcognito03
DENIED=abcdefdenied04

aws_fixture_stub_install "$W/bin"

# A FIXED "now" for the whole suite, so a fixture `expires` timestamp
# evaluates identically whenever this suite happens to run - the identical
# injectable-clock seam modules/dast/passive/tls_engine.sh's own
# `tls_expiry_state` establishes, applied through
# `SCOURSH_APPSYNC_NOW_EPOCH` (modules/cloud/aws/live/appsync.sh).
NOW=1700000000

# `_routes_default` - the route table every scan case starts from: the two
# calls modules/cloud/aws/run.sh makes before any service script, plus
# `list-graphql-apis` once per region (qualified on the REGION NAME, which
# `aws_ro`'s own ambient `--region` argument puts into argv for every call in
# a regional pass), plus a per-API `list-api-keys` row qualified on the api
# id.  An optional argument names ONE operation whose qualified rows are
# omitted, exactly as tests/suites/cloud-s3.sh's own `_routes_default` does,
# so a case can register a single unqualified override for it instead.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"

  if [[ $omit != list-graphql-apis ]]; then
    aws_fixture_route_add_for appsync list-graphql-apis us-east-1 "$FIX/list-graphql-apis.us-east-1.json"
    aws_fixture_route_add_for appsync list-graphql-apis eu-west-2 "$FIX/list-graphql-apis.eu-west-2.json"
  fi

  if [[ $omit != list-api-keys ]]; then
    aws_fixture_route_add_for appsync list-api-keys "$PLAINKEY" "$FIX/list-api-keys.plainkey.json"
    aws_fixture_route_add_for appsync list-api-keys "$IAMAUTH"  "$FIX/list-api-keys.iamauth.json"
    aws_fixture_route_add_for appsync list-api-keys "$COGNITO"  "$FIX/list-api-keys.cognito.json"
    aws_fixture_route_add_for appsync list-api-keys "$DENIED"   "$FIX/list-api-keys.denied.err"
  fi
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess, for
# the identical reason tests/suites/cloud-s3.sh's own helper gives: the CLI
# parser, the dispatch arm, the check-registry load and the exit-code
# precedence table are four separate mechanisms this suite asserts the
# interaction of, and only a subprocess exercises all four.
#
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR`, for the identical
# reason cloud-s3.sh's own helper documents at length: `SCOURSH_SCRATCH` is
# exported, so every subprocess would otherwise share ONE response cache keyed
# on sha256(service|region|account|op|args) - byte-identical across two cases
# whose ROUTE TABLE differs.
_run_cloud() {
  local out=$1
  shift
  _RC=0
  rm -rf "$out"
  PATH="$W/bin:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") \
    SCOURSH_APPSYNC_NOW_EPOCH=$NOW \
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
# line per finding, read from findings.jsonl.  THE SEPARATOR IS 0x1f, NEVER A
# TAB: `cis` and `sub_key` are legitimately empty for these two checks (no CIS
# control exists for AppSync; neither check needs a sub-key), and a tab is an
# IFS-*whitespace* character - AGENTS.md's own DAST-11 lesson - so `read`
# folds a RUN of tabs around an empty field into ONE delimiter and every field
# after it shifts left by one. Measured while writing this suite: with a
# tab-joined table, C2/C4/C7 below read the account id into the cis variable
# and the empty string into the account variable. `awk -F` does not have this
# problem (an explicit field separator is never collapsed), which is why
# `_ids_for_resource`'s own awk-based extraction was unaffected and only the
# `read`-based single-row extraction in section C broke.
_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
SEP = chr(0x1f)
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

_ids_for_resource() {
  local table=$1 resource=$2
  printf '%s\n' "$table" | awk -F"$US" -v r="$resource" '$2 == r { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against the committed fixtures, with no scan at all.
# ===========================================================================
t_case 'A. classifiers'

appsync_doc_load "$FIX/list-graphql-apis.us-east-1.json"
assert_eq "$PLAINKEY" "${_APPSYNC_DOC[$(appsync_path graphqlApis 0 apiId)]:-}" \
  'A1 list-graphql-apis: the first apiId is read'
assert_eq 'API_KEY' "${_APPSYNC_DOC[$(appsync_path graphqlApis 0 authenticationType)]:-}" \
  'A2 list-graphql-apis: the first authenticationType is read'
assert_true "$(appsync_doc_has "$(appsync_path graphqlApis 3 apiId)" && echo 0 || echo 1)" \
  'A3 list-graphql-apis: the fourth API (index 3) is present - the walk does not stop early'
assert_true "$(appsync_doc_has "$(appsync_path graphqlApis 4 apiId)" && echo 1 || echo 0)" \
  'A4 list-graphql-apis: there is no fifth API - the walk has a real end'

assert_true "$(appsync_auth_type_is_key API_KEY && echo 0 || echo 1)" 'A5 API_KEY is the API-key auth type'
assert_true "$(appsync_auth_type_is_key AWS_IAM && echo 1 || echo 0)" 'A6 AWS_IAM is not'
assert_true "$(appsync_auth_type_is_key AMAZON_COGNITO_USER_POOLS && echo 1 || echo 0)" 'A7 nor is Cognito'
# A substring test is the reading this fails under: a hypothetical future auth
# type embedding the literal bytes "API_KEY" must not be misread as this one.
assert_true "$(appsync_auth_type_is_key API_KEY_LEGACY_SHAPE && echo 1 || echo 0)" \
  'A8 a whole-value compare, never a substring one'

# The expiry boundary.  Strict `>`, not `>=` - the reading A10 fails under is
# `>=`, which would report every key issued with an exactly-90-day validity,
# the round number an operator's own tooling is likely to default to.
assert_eq 'ok' "$(appsync_key_expiry_state $(( NOW + 90 * 86400 )) "$NOW" 90)" \
  'A9 exactly 90 days remaining is NOT long-lived'
assert_eq 'long_lived' "$(appsync_key_expiry_state $(( NOW + 90 * 86400 + 1 )) "$NOW" 90)" \
  'A10 90 days and one second remaining IS'
assert_eq 'expired' "$(appsync_key_expiry_state $(( NOW - 1 )) "$NOW" 90)" \
  'A11 a key that has already expired is `expired`, never `long_lived`'
assert_eq 'expired' "$(appsync_key_expiry_state "$NOW" "$NOW" 90)" \
  'A12 a key expiring at this exact instant is expired, not valid'
assert_eq '200' "$(appsync_days_until $(( NOW + 200 * 86400 )) "$NOW")" \
  'A13 days-until rounds down to whole days'

assert_eq 'aws' "$(appsync_partition_of 'arn:aws:iam::123456789012:user/x')" 'A14 partition: commercial'
assert_eq 'aws-us-gov' "$(appsync_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A15 partition: GovCloud'
assert_eq 'aws-cn' "$(appsync_partition_of 'arn:aws-cn:iam::123456789012:user/x')" 'A16 partition: China'
assert_eq 'aws' "$(appsync_partition_of '')" 'A17 partition: an unresolved caller ARN falls back to aws'

assert_eq 'arn:aws:appsync:us-east-1:123456789012:apis/abc' \
  "$(appsync_api_arn aws 123456789012 us-east-1 abc)" 'A18 the fallback API ARN is well-formed'
assert_eq 'arn:aws:appsync:us-east-1:123456789012:apis/abc/apikeys/da2-xyz' \
  "$(appsync_key_arn 'arn:aws:appsync:us-east-1:123456789012:apis/abc' da2-xyz)" \
  'A19 a key ARN is built by appending to its own API ARN, never by re-deriving one'

# The response actually served for a real API always carries `arn` - this
# proves the SCRIPT prefers it, not the classifier (which has no opinion),
# by loading the one committed fixture that omits it and confirming the field
# really does come back empty, which is the precondition
# modules/cloud/aws/live/appsync.sh's own fallback branch exists for.
appsync_doc_load "$FIX/list-graphql-apis.no-arn.json"
assert_eq '' "${_APPSYNC_DOC[$(appsync_path graphqlApis 0 arn)]:-}" \
  'A20 a response with no arn field really does read back empty'

# ===========================================================================
# B. One scan, four APIs: fires on the bad ones, quiet on the good ones - and
#    the two checks are independent of each other.
# ===========================================================================
t_case 'B. both directions, and independence, in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
API_ARN_PLAINKEY="arn:aws:appsync:us-east-1:123456789012:apis/$PLAINKEY"
API_ARN_IAM="arn:aws:appsync:us-east-1:123456789012:apis/$IAMAUTH"
API_ARN_COGNITO="arn:aws:appsync:us-east-1:123456789012:apis/$COGNITO"
API_ARN_DENIED="arn:aws:appsync:us-east-1:123456789012:apis/$DENIED"
KEY_ARN_LONG="$API_ARN_PLAINKEY/apikeys/da2-longlivedkey01"
KEY_ARN_SHORT="$API_ARN_PLAINKEY/apikeys/da2-shortlivedkey01"
KEY_ARN_COGNITO="$API_ARN_COGNITO/apikeys/da2-cognitolongkey01"

PLAINKEY_IDS=$(_ids_for_resource "$TBL" "$API_ARN_PLAINKEY")
IAM_IDS=$(_ids_for_resource "$TBL" "$API_ARN_IAM")
COGNITO_IDS=$(_ids_for_resource "$TBL" "$API_ARN_COGNITO")
DENIED_IDS=$(_ids_for_resource "$TBL" "$API_ARN_DENIED")

assert_contains "$PLAINKEY_IDS" 'CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01' \
  'B3 the plain-API-key API is reported for its default auth'
assert_eq '' "$IAM_IDS" 'B4 the AWS_IAM API is reported by nothing at the API level'
assert_eq '' "$COGNITO_IDS" 'B5 the Cognito API is ALSO reported by nothing at the API level'
assert_contains "$DENIED_IDS" 'CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01' \
  'B6 the denied API is still reported for its default auth - that check reads list-graphql-apis alone'

assert_contains "$(_ids_for_resource "$TBL" "$KEY_ARN_LONG")" 'CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01' \
  'B7 the long-lived key on the plain-API-key API is reported'
assert_eq '' "$(_ids_for_resource "$TBL" "$KEY_ARN_SHORT")" \
  'B8 its short-lived sibling, in the SAME run, is not'

# The independence claim: a Cognito-default API is clean at B5, and its OWN
# key is STILL long-lived and STILL reported - proving the two checks do not
# share one verdict.  The reading this fails under is a script that only
# evaluates key expiry when the API's default auth is already API_KEY.
assert_contains "$(_ids_for_resource "$TBL" "$KEY_ARN_COGNITO")" 'CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01' \
  'B9 a long-lived key on a Cognito-default API is reported too - the two checks are independent'

# ===========================================================================
# C. ARN, region, account, and cell - on the finding itself; NO cis value.
# ===========================================================================
t_case 'C. finding citation'

_auth_row=$(printf '%s\n' "$TBL" | awk -F"$US" -v a="$API_ARN_PLAINKEY" '$1 == "CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01" && $2 == a { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_auth_row"

assert_eq "$API_ARN_PLAINKEY" "$_c_arn" 'C1 the finding cites the API ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'us-east-1' "$_c_region" 'C3 the finding cites the region the API actually lives in'
# NO CIS CONTROL: CIS AWS Foundations Benchmark v3.0.0 has no AppSync section
# at all, so an honest absence is the correct value here - the reading this
# fails under is a check record that invented a control id to avoid an empty
# field, which is exactly the overstated-coverage failure docs/DESIGN.md §15
# forbids.
assert_eq '' "$_c_cis" 'C4 the finding carries NO cis control id - none exists to cite'

# UNLIKE S3, THE CELL AND THE REGION AGREE: appsync is a REGIONAL row in
# _CLOUD_SERVICES, so the cell the pass covered IS the region the resource
# lives in.  A test that only checked C3 would pass under an implementation
# that quietly reused S3's global-cell shape for a regional service, which
# would misfile every finding into `<account>/global` and make it invisible
# to any per-region diff.
assert_eq '123456789012/us-east-1' "$_c_cell" 'C5 the cell is <account>/<region> - the region the pass actually covered'

_key_row=$(printf '%s\n' "$TBL" | awk -F"$US" -v a="$KEY_ARN_LONG" '$1 == "CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01" && $2 == a { print; exit }')
IFS=$'\x1f' read -r _k_id _k_arn _k_region _k_cell _k_cis _k_account _k_sub <<<"$_key_row"
assert_eq "$KEY_ARN_LONG" "$_k_arn" 'C6 a key finding cites the KEY-s own ARN, built off its API'
assert_eq '' "$_k_cis" 'C7 the key-expiry check also carries no cis control id'

# Two entirely different resources (the API; one of its keys) are two
# findings with two distinct fingerprints, because loc_resource_key differs.
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
# D. Honesty: a denied call is a reduction; a second, empty region is a
#    real, vacuous pass rather than silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)
NOTES=$(_json "$RUNJSON" notes)

# The denied API's list-api-keys was AccessDenied.  DEFAULT_AUTH-01 needed no
# extra call and is unaffected; LONG_EXPIRY-01 ran for the other three APIs so
# it IS in checks_run, with the partial loss recorded beside it - reporting
# only the first overstates coverage, reporting only the second suppresses a
# cell the run genuinely did visit.
assert_contains "$CHECKS_RUN" 'CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01' \
  'D1 a check that answered for SOME APIs is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the one API is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'apis_unanswered=1' \
  'D3 the reduction says how many APIs did not answer'
assert_not_contains "$(_ids_for_resource "$TBL" "$API_ARN_DENIED/apikeys/")" 'CLOUD-APPSYNC-API_KEY_LONG_EXPIRY' \
  'D4 no key-expiry finding is invented for the API whose keys were never read'

# eu-west-2 has zero GraphQL APIs.  The pass must say it looked and found
# nothing, and must NOT claim a check ran there - the reading this fails
# under is silence, which renders identically to a region this run never
# visited at all.
assert_contains "$NOTES" 'service=appsync account=123456789012 region=eu-west-2 apis=0' \
  'D5 the empty region records that it was examined and found nothing'
assert_contains "$REDUCTIONS" 'service=appsync check=CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01 account=123456789012 region=eu-west-2' \
  'D6 ... and its own per-check reduction says the check answered for no API IN THAT REGION'

# A check denied for EVERY api must NOT be in checks_run: crediting it would
# let tension 12 report a prior finding `fixed` on the strength of a call that
# was denied for every API in the account.
_routes_default list-api-keys
aws_fixture_route_add appsync list-api-keys "$FIX/list-api-keys.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01' \
  'D7 a check denied for EVERY API is absent from checks_run'
assert_contains "$CR2" 'CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01' \
  'D8 ... while its unaffected peer is still credited'
assert_contains "$RED2" 'check=CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01' \
  'D9 ... and it has its own coverage_reduction saying so'

# The whole region unreadable: no API examined, nothing credited, and the gap
# stated in the surfaces a consumer reads.  The reading this fails under is
# exit 0 with an empty findings set and no explanation, which is a denied scan
# rendered as a clean region.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add appsync list-graphql-apis "$FIX/list-api-keys.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-APPSYNC-' 'D10 a denied list-graphql-apis credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'GraphQL API list' \
  'D11 ... and the coverage_gap says the API list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'GraphQL API list' \
  'D12 ... and it reaches report.md, the surface a consumer actually reads'

# ===========================================================================
# E. Round-trip: coverage cells for BOTH regions, and every report format.
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
    if cid.startswith('CLOUD-APPSYNC-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01 account-region 123456789012/us-east-1' \
  'E5 the run wrote a real account-region coverage cell for the region it actually covered'
assert_not_contains "$COVER" '123456789012/eu-west-2' \
  'E6 the EMPTY region is not credited as covered, even though the pass genuinely visited it - it evaluated no API'
assert_not_contains "$COVER" '123456789012/global' \
  'E7 appsync never writes a global cell - it is a REGIONAL row in _CLOUD_SERVICES, unlike S3'

assert_file_exists "$W/run-b/report.md" 'E8 report.md written'
assert_file_exists "$W/run-b/report.html" 'E9 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$API_ARN_PLAINKEY" 'E10 report.md names the API ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E11 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01' 'E12 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$API_ARN_PLAINKEY" 'E13 the SARIF result names the resource'

t_summary cloud-appsync
