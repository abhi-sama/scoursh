#!/usr/bin/env bash
# tests/suites/cloud-sns.sh - modules/cloud/aws/live/sns.sh: the §8.1 SNS
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-28).
#
# Mirrors tests/suites/cloud-s3.sh's own shape and the five things it exists
# to pin (both directions in one run; every finding cites ARN/region/account;
# the cell and region AGREE for a regional service, unlike S3's global pass;
# a denied call is a reduction, never silence; the finding round-trips into
# state and every report format) - see that suite's own header for the full
# reasoning, not restated here.  What is SPECIFIC to this suite: SNS carries
# NO `cis` value at all (data/cis-mappings has no SNS section in CIS AWS
# Foundations Benchmark v3.0.0), so section C asserts that ABSENCE rather than
# a value, the honest-absence rule this module's checks.rules header states
# at length.
#
# NO NETWORK AND NO AWS ACCOUNT: every case runs against tests/lib/aws-
# fixtures.sh's routed stub, serving tests/fixtures/aws/cloud-sns/.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note - every file
# on this edge is already inlined via modules/cloud/aws/live/sns_engine.sh's
# own runtime-guarded source of engine.sh, and shellcheck -x re-expands every
# edge it follows rather than memoising (tests/lint-source-graph.sh).
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/sns_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-sns
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a literal
# prefix from every loaded file's realpath (tests/suites/cloud-s3.sh's own
# identical note on the macOS /var -> /private/var $TMPDIR symlink).
W=$(cd -- "$W" && pwd -P)

# `awk -F'\x1f'` does NOT reliably parse the hex escape as the real byte
# (measured: BSD/macOS awk 20200816 treats it as a literal no-op and leaves
# the whole line as ONE field, so every `$2 == ...` compare is silently
# false) - the fix is a shell variable holding the ACTUAL byte, passed to
# `-F"$SEP"`, never the hex-escape spelling in the -F argument itself.
SEP=$'\x1f'
FIX=$ROOT/tests/fixtures/aws/cloud-sns
PUB=arn:aws:sns:eu-west-2:123456789012:scoursh-fixture-public-topic
HARD=arn:aws:sns:eu-west-2:123456789012:scoursh-fixture-hardened-topic
DENY=arn:aws:sns:eu-west-2:123456789012:scoursh-fixture-denied-topic

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add sns list-topics         "$FIX/list-topics.json"

  if [[ $omit != get-topic-attributes ]]; then
    aws_fixture_route_add_for sns get-topic-attributes "$PUB"  "$FIX/get-topic-attributes.public.json"
    aws_fixture_route_add_for sns get-topic-attributes "$HARD" "$FIX/get-topic-attributes.hardened.json"
    aws_fixture_route_add_for sns get-topic-attributes "$DENY" "$FIX/get-topic-attributes.denied.err"
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

# `sns_topic_policy_string_set`/`sns_topic_kms_key_set` are SETTERS - called
# directly, never through `$(...)`, for this codebase's standing subshell
# lesson (AGENTS.md's "Things measured on this codebase": a side-effecting
# function called as `$(f)` runs in a subshell and its writes are discarded).
# The return status is captured into a plain variable first and asserted
# separately, so the setter's OWN assignment survives into the next
# assertion.
sns_doc_load "$FIX/get-topic-attributes.public.json"
_pol='' _rc=0
sns_topic_policy_string_set _pol || _rc=1
assert_true "$_rc" 'A1 policy string is read off Attributes.Policy'
sns_policy_string_load "$_pol"
assert_true "$(sns_policy_is_public && echo 0 || echo 1)" 'A2 a wildcard AWS principal with no Condition is public'

sns_doc_load "$FIX/get-topic-attributes.hardened.json"
sns_topic_policy_string_set _pol
sns_policy_string_load "$_pol"
assert_true "$(sns_policy_is_public && echo 1 || echo 0)" 'A3 a principal scoped to one account id is not public'

_kms='' _rc=0
sns_topic_kms_key_set _kms || _rc=1
assert_true "$_rc" 'A4 KmsMasterKeyId present is encrypted'
sns_doc_load "$FIX/get-topic-attributes.public.json"
_rc=0
sns_topic_kms_key_set _kms || _rc=1
assert_true "$(( 1 - _rc ))" 'A5 KmsMasterKeyId absent is not encrypted'

# A wildcard principal narrowed by ANY Condition is not reported - the
# reading this fails under is a policy scan that ignores Condition entirely.
cat >"$W/wildcard-with-condition.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"SNS:Publish","Resource":"arn:x","Condition":{"StringEquals":{"aws:SourceOwner":"123456789012"}}}]}
J
sns_policy_string_load "$(cat "$W/wildcard-with-condition.json")"
assert_true "$(sns_policy_is_public && echo 1 || echo 0)" 'A6 a wildcard principal with ANY Condition is treated as narrowed, not public'

# A Service principal (the ordinary shape of an SNS topic's own default
# policy allowing e.g. CloudWatch alarms to publish) is not a wildcard.
cat >"$W/service-principal.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudwatch.amazonaws.com"},"Action":"SNS:Publish","Resource":"arn:x"}]}
J
sns_policy_string_load "$(cat "$W/service-principal.json")"
assert_true "$(sns_policy_is_public && echo 1 || echo 0)" 'A7 a Service principal is not a wildcard principal'

# The bare-string Principal form ("Principal": "*", valid IAM grammar,
# distinct from {"AWS":"*"}) is ALSO public.
cat >"$W/bare-wildcard.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"SNS:Publish","Resource":"arn:x"}]}
J
sns_policy_string_load "$(cat "$W/bare-wildcard.json")"
assert_true "$(sns_policy_is_public && echo 0 || echo 1)" 'A8 a bare string Principal "*" is public too'

# ===========================================================================
# B. One scan, three topics: fires on the public one, quiet on the hardened.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
PUB_IDS=$(_ids_for_arn "$TBL" "$PUB")
HARD_IDS=$(_ids_for_arn "$TBL" "$HARD")

for want in CLOUD-SNS-PUBLIC_POLICY-01 CLOUD-SNS-NO_ENCRYPTION-01; do
  assert_contains "$PUB_IDS" "$want" "B3 the public topic is reported by $want"
done
assert_eq '' "$HARD_IDS" 'B4 the hardened topic in the SAME run produces no finding at all'

# ===========================================================================
# C. ARN, region, account, cell - and NO cis (an honest absence).
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F"$SEP" '$1 == "CLOUD-SNS-PUBLIC_POLICY-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "$PUB" "$_c_arn" 'C1 the finding cites the topic ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq "123456789012/eu-west-2" "$_c_cell" 'C4 the cell agrees with the region for a REGIONAL service (unlike S3s global pass)'
assert_eq '' "$_c_cis" 'C5 the finding carries NO cis value - CIS AWS Foundations Benchmark v3.0.0 has no SNS section, and inventing one is forbidden'

# ===========================================================================
# D. Honesty: a denied call is a reduction, never silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-SNS-PUBLIC_POLICY-01' \
  'D1 a check that answered for SOME topics is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the denied topic is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'topics_unanswered=1' \
  'D3 the reduction says how many topics did not answer'
assert_not_contains "$(_ids_for_arn "$TBL" "$DENY")" 'CLOUD-SNS-' \
  'D4 no finding is invented for the topic whose attributes were never read'

# A check denied for EVERY topic must not appear in checks_run at all.
_routes_default get-topic-attributes
aws_fixture_route_add sns get-topic-attributes "$FIX/get-topic-attributes.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-SNS-' \
  'D5 a check denied for every topic is absent from checks_run entirely'
assert_contains "$RED2" 'check=CLOUD-SNS-PUBLIC_POLICY-01' \
  'D6 ... and it has its own coverage_reduction saying so'

# The whole region unreadable: no topic examined, nothing credited, and the
# gap stated where a consumer reads it.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add sns list-topics         "$FIX/get-topic-attributes.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-SNS-' 'D7 a denied list-topics credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'topic list' \
  'D8 ... and the coverage_gap says the topic list could not be read'
assert_contains "$(cat "$W/run-denied/report.md")" 'topic list' \
  'D9 ... and it reaches report.md, the surface a consumer actually reads'

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
    if cid.startswith('CLOUD-SNS-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-SNS-PUBLIC_POLICY-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for the region actually visited'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
assert_file_exists "$W/run-b/report.html" 'E5 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$PUB" 'E6 report.md names the topic ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E7 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-SNS-PUBLIC_POLICY-01' 'E8 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$PUB" 'E9 the SARIF result names the resource'

t_summary cloud-sns
