#!/usr/bin/env bash
# tests/suites/cloud-iam.sh - modules/cloud/aws/live/iam.sh: the §8.1 IAM
# read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-06), copying
# tests/suites/cloud-s3.sh's own contract and structure.
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently - the same five categories cloud-s3.sh's own
# header names, applied to IAM's resources (the account itself, users, and
# roles) rather than buckets:
#
#   1. BOTH DIRECTIONS, IN ONE RUN. A full-admin user/role and a hardened
#      user/role are examined by the SAME scan, so "the check fires" and "the
#      check stays quiet" are asserted against one code path in one process.
#   2. EVERY FINDING CITES ARN, REGION ("global", literally), ACCOUNT AND -
#      WHERE ONE EXISTS - A CIS CONTROL ID.
#   3. THE CELL AND THE REGION ARE THE SAME STRING HERE, unlike S3 - see
#      modules/cloud/aws/live/iam_engine.sh's own header for why IAM has no
#      per-resource region to differ from the cell at all.
#   4. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE, AND A
#      `NoSuchEntity`/`NoSuchEntity`-shaped ANSWER (no console password, no
#      account password policy at all) is a real answer, not a loss.
#   5. THE FINDING ROUND-TRIPS: into findings.jsonl, into a real
#      `account-region` coverage cell in state/, and into every report
#      format including SARIF.
#
# NO NETWORK AND NO AWS ACCOUNT. Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-iam/.
#
# `SCOURSH_IAM_NOW_EPOCH` PINS "NOW" FOR EVERY INTEGRATION CASE, mirroring
# modules/dast/passive/tls_engine.sh's own injectable-`now` reasoning
# (AGENTS.md's "Things measured on this codebase"): every fixture date below
# is authored against 2025-06-15T00:00:00Z, and without pinning it a "fresh"
# fixture (a 14-day-old access key, say) would start reading as "stale" the
# day the real calendar carries it past the 45/90-day threshold.
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
# -x back-edge cut: modules/cloud/aws/live/iam_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain. shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own entry
# point - the identical cut tests/suites/cloud-s3.sh makes.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/iam_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-iam
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise, for cloud-s3.sh's own reason (tests/suites/cloud.sh documents
# the same fact): lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL
# prefix from every loaded file's realpath, so a fixture root reached through
# macOS's /var -> /private/var $TMPDIR symlink would fail E070 for a reason
# unrelated to the file.
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-iam
ADMIN=scoursh-fixture-admin-user
CLEAN=scoursh-fixture-clean-user
DENYU=scoursh-fixture-denied-user
OPEN=scoursh-fixture-open-role
XACC=scoursh-fixture-crossaccount-role
HARD=scoursh-fixture-hardened-role
DENYR=scoursh-fixture-denied-role

ADMIN_KEY=AKIAADMIN0000000001
CLEAN_KEY=AKIACLEAN00000000001
ADMIN_POLICY_ARN=arn:aws:iam::123456789012:policy/AdminManaged
RO_POLICY_ARN=arn:aws:iam::123456789012:policy/ReadOnlyManaged

# 2025-06-15T00:00:00Z, pinned for every integration case below.
NOW_EPOCH=1749945600

aws_fixture_stub_install "$W/bin"

# `_routes_bad_account` - the route table for the "bad account" run: a
# root/password-policy/analyzer state that fails all four account-wide
# checks, plus three users and four roles covering every per-identity check
# in both directions in ONE run - the identical "one scan, both directions"
# shape cloud-s3.sh's own `_routes_default` uses.
_routes_bad_account() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add iam get-account-summary "$FIX/get-account-summary.bad.json"
  aws_fixture_route_add iam get-account-password-policy "$FIX/get-account-password-policy.weak.json"
  aws_fixture_route_add accessanalyzer list-analyzers "$FIX/list-analyzers.none.json"
  aws_fixture_route_add iam list-users "$FIX/list-users.json"
  aws_fixture_route_add iam list-roles "$FIX/list-roles.json"

  aws_fixture_route_add_for iam get-user "$ADMIN" "$FIX/get-user.admin.json"
  aws_fixture_route_add_for iam get-user "$CLEAN" "$FIX/get-user.clean.json"
  aws_fixture_route_add_for iam get-user "$DENYU" "$FIX/get-user.denied.err"

  aws_fixture_route_add_for iam get-login-profile "$ADMIN" "$FIX/get-login-profile.admin.json"
  aws_fixture_route_add_for iam get-login-profile "$CLEAN" "$FIX/get-login-profile.clean.err"

  aws_fixture_route_add_for iam list-access-keys "$ADMIN" "$FIX/list-access-keys.admin.json"
  aws_fixture_route_add_for iam list-access-keys "$CLEAN" "$FIX/list-access-keys.clean.json"
  aws_fixture_route_add_for iam list-access-keys "$DENYU" "$FIX/list-access-keys.denied.err"

  aws_fixture_route_add_for iam get-access-key-last-used "$ADMIN_KEY" "$FIX/get-access-key-last-used.admin.json"
  aws_fixture_route_add_for iam get-access-key-last-used "$CLEAN_KEY" "$FIX/get-access-key-last-used.clean.json"

  aws_fixture_route_add_for iam list-user-policies "$ADMIN" "$FIX/list-user-policies.admin.json"
  aws_fixture_route_add_for iam list-user-policies "$CLEAN" "$FIX/list-user-policies.clean.json"
  aws_fixture_route_add iam get-user-policy "$FIX/get-user-policy.json"

  aws_fixture_route_add_for iam list-attached-user-policies "$ADMIN" "$FIX/list-attached-user-policies.admin.json"
  aws_fixture_route_add_for iam list-attached-user-policies "$CLEAN" "$FIX/list-attached-user-policies.clean.json"

  aws_fixture_route_add_for iam get-policy "$ADMIN_POLICY_ARN" "$FIX/get-policy.adminmanaged.json"
  aws_fixture_route_add_for iam get-policy "$RO_POLICY_ARN" "$FIX/get-policy.readonlymanaged.json"
  aws_fixture_route_add_for iam get-policy-version "$ADMIN_POLICY_ARN" "$FIX/get-policy-version.adminmanaged.json"
  aws_fixture_route_add_for iam get-policy-version "$RO_POLICY_ARN" "$FIX/get-policy-version.readonlymanaged.json"

  aws_fixture_route_add_for iam get-role "$OPEN" "$FIX/get-role.open.json"
  aws_fixture_route_add_for iam get-role "$XACC" "$FIX/get-role.crossaccount.json"
  aws_fixture_route_add_for iam get-role "$HARD" "$FIX/get-role.hardened.json"
  aws_fixture_route_add_for iam get-role "$DENYR" "$FIX/get-role.denied.err"

  aws_fixture_route_add_for iam list-role-policies "$OPEN" "$FIX/list-role-policies.open.json"
  aws_fixture_route_add_for iam list-role-policies "$XACC" "$FIX/list-role-policies.crossaccount.json"
  aws_fixture_route_add_for iam list-role-policies "$HARD" "$FIX/list-role-policies.hardened.json"
  aws_fixture_route_add iam get-role-policy "$FIX/get-role-policy.json"

  aws_fixture_route_add_for iam list-attached-role-policies "$OPEN" "$FIX/list-attached-role-policies.open.json"
  aws_fixture_route_add_for iam list-attached-role-policies "$XACC" "$FIX/list-attached-role-policies.crossaccount.json"
  aws_fixture_route_add_for iam list-attached-role-policies "$HARD" "$FIX/list-attached-role-policies.hardened.json"
}

# `_routes_good_account` - a hardened account with no users and no roles at
# all, for asserting the four account-wide checks stay quiet AND that an
# empty roster is credited as vacuous coverage rather than a loss.
_routes_good_account() {
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add iam get-account-summary "$FIX/get-account-summary.good.json"
  aws_fixture_route_add iam get-account-password-policy "$FIX/get-account-password-policy.strong.json"
  aws_fixture_route_add accessanalyzer list-analyzers "$FIX/list-analyzers.active.json"
  aws_fixture_route_add iam list-users "$FIX/list-users.empty.json"
  aws_fixture_route_add iam list-roles "$FIX/list-roles.empty.json"
}

# `_run_cloud OUT [ARGS...]` - one real `scan.sh cloud --live` subprocess,
# with `SCOURSH_IAM_NOW_EPOCH` pinned and its own `SCOURSH_AWS_CACHE_DIR` -
# both for cloud-s3.sh's own `_run_cloud` reasons (a shared cache keyed on
# sha256(service|region|account|op|args) would serve one case's responses to
# the next).
_run_cloud() {
  local out=$1
  shift
  _RC=0
  rm -rf "$out"
  PATH="$W/bin:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") \
    SCOURSH_IAM_NOW_EPOCH=$NOW_EPOCH \
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

# One `check_id<TAB>loc_resource_key<TAB>loc_region<TAB>cell<TAB>cis<TAB>account<TAB>sub_key`
# line per finding, read from findings.jsonl - byte-identical shape to
# cloud-s3.sh's own `_findings_table`.
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

_ids_for_arn() {
  local table=$1 arn=$2
  printf '%s\n' "$table" | awk -F'\t' -v a="$arn" '$2 == a { print $1 }' | LC_ALL=C sort
}

ADMIN_ARN="arn:aws:iam::123456789012:user/$ADMIN"
CLEAN_ARN="arn:aws:iam::123456789012:user/$CLEAN"
OPEN_ARN="arn:aws:iam::123456789012:role/$OPEN"
XACC_ARN="arn:aws:iam::123456789012:role/$XACC"
HARD_ARN="arn:aws:iam::123456789012:role/$HARD"
ROOT_ARN="arn:aws:iam::123456789012:root"

# ===========================================================================
# A. The classifiers, against committed and synthetic fixtures, no scan.
# ===========================================================================
t_case 'A. classifiers'

assert_eq 'arn:aws:iam::123456789012:root' "$(iam_account_root_arn aws 123456789012)" \
  'A1 the account root ARN carries no user/role path, only :root'
assert_eq 'aws' "$(iam_partition_of 'arn:aws:iam::123456789012:user/x')" 'A2 partition: commercial'
assert_eq 'aws-us-gov' "$(iam_partition_of 'arn:aws-us-gov:iam::123456789012:user/x')" 'A3 partition: GovCloud'

# Percent-decoding round-trips, including the shape every real policy
# document arrives in - '{' and '"' both encoded, never left literal.
_decoded=$(iam_url_decode '%7B%22Effect%22%3A%22Allow%22%7D')
assert_eq '{"Effect":"Allow"}' "$_decoded" 'A4 url-decode: a policy-shaped percent-encoded string decodes correctly'
assert_eq 'plain text, no percent signs' "$(iam_url_decode 'plain text, no percent signs')" \
  'A5 url-decode: a string with no % sequence passes through unchanged'

# get-account-summary: SummaryMap values are NUMBERS, not booleans - A7 is
# the case that fails under a `== true` comparison.
iam_doc_load "$FIX/get-account-summary.bad.json"
_mfa=0
iam_summary_flag_set _mfa AccountMFAEnabled || true
assert_eq '0' "$_mfa" 'A6 get-account-summary: AccountMFAEnabled is read as the numeric flag it is'
_keys=0
iam_summary_flag_set _keys AccountAccessKeysPresent || true
assert_eq '1' "$_keys" 'A7 get-account-summary: AccountAccessKeysPresent=1 is read correctly, not compared against the string true'
iam_doc_load "$FIX/get-account-summary.good.json"
iam_summary_flag_set _mfa AccountMFAEnabled || true
assert_eq '1' "$_mfa" 'A8 get-account-summary: a hardened account reads AccountMFAEnabled=1'

# get-account-password-policy: the response is wrapped under `PasswordPolicy`
# - A9 is the reading that fails if a caller reads the two leaves unprefixed.
iam_doc_load "$FIX/get-account-password-policy.weak.json"
_gaps=''
iam_password_policy_gaps_set _gaps
assert_eq 'min_length reuse_prevention' "$_gaps" 'A9 password policy: both CIS minimums reported as gaps for a weak policy'
iam_doc_load "$FIX/get-account-password-policy.strong.json"
iam_password_policy_gaps_set _gaps
assert_eq '' "$_gaps" 'A10 password policy: a policy meeting both minimums has no gap'

# accessanalyzer: field names are lowercase, unlike every other call in this
# file - A12 is the reading that fails under a PascalCase `Status` lookup.
iam_doc_load "$FIX/list-analyzers.none.json"
assert_true "$(iam_analyzer_has_active && echo 1 || echo 0)" 'A11 access analyzer: an empty analyzers array has no active one'
iam_doc_load "$FIX/list-analyzers.active.json"
assert_true "$(iam_analyzer_has_active && echo 0 || echo 1)" 'A12 access analyzer: a real ACTIVE analyzer (lowercase field names) is found'

# get-user/get-role wrap their entity under `User`/`Role` - A14 and the
# get-role case below are what fails if a caller forgets the wrapper.
iam_doc_load "$FIX/get-user.admin.json"
assert_true "$(iam_has_permission_boundary User && echo 1 || echo 0)" 'A13 permission boundary: absent on the admin user'
iam_doc_load "$FIX/get-user.clean.json"
assert_true "$(iam_has_permission_boundary User && echo 0 || echo 1)" 'A14 permission boundary: present on the clean user, read through the User wrapper'
iam_doc_load "$FIX/get-role.hardened.json"
assert_true "$(iam_has_permission_boundary Role && echo 0 || echo 1)" 'A15 permission boundary: present on the hardened role, read through the Role wrapper'

# ISO 8601 time arithmetic.
_epoch=''
# Called BARE, never through `$(...)`: iam_iso8601_to_epoch is a SETTER
# (this file's own standing convention - lib/core.sh's `worker_id_set`
# lesson), and a command substitution would set `_epoch` in a subshell that
# then exits, leaving the outer `_epoch` untouched.
_epoch=''
iam_iso8601_to_epoch _epoch '2025-06-15T00:00:00Z' || true
assert_eq "$NOW_EPOCH" "$_epoch" 'A16 iso8601: a Z-suffixed timestamp parses to this suite-s own pinned NOW'
_epoch=''
iam_iso8601_to_epoch _epoch '2025-06-15T00:00:00+00:00' || true
assert_eq "$NOW_EPOCH" "$_epoch" 'A17 iso8601: the +00:00 spelling agrees with Z on the same instant'
_epoch=''
iam_iso8601_to_epoch _epoch 'not a timestamp' || true
assert_eq '' "$_epoch" 'A18 iso8601: an unparseable string leaves the variable empty rather than guessing an epoch'
assert_eq '45' "$(iam_age_days $(( NOW_EPOCH - 45 * 86400 )) "$NOW_EPOCH")" 'A19 age_days: 45 real days apart reads as 45'

# The trust policy: a bare wildcard Principal (A20), a nested Principal.AWS
# naming a different account with no ExternalId condition (A21), and the
# SAME shape WITH an ExternalId condition, which must NOT fire (A22 is the
# reading that fails if the Condition scan is never consulted at all).
iam_doc_load "$FIX/get-role.open.json"
_raw=''
iam_role_assume_policy_raw _raw
iam_doc_load_string "$(iam_url_decode "$_raw")"
assert_true "$(iam_trust_has_wildcard_principal && echo 0 || echo 1)" 'A20 trust policy: a bare Principal "*" is a wildcard'

iam_doc_load "$FIX/get-role.crossaccount.json"
iam_role_assume_policy_raw _raw
iam_doc_load_string "$(iam_url_decode "$_raw")"
assert_true "$(iam_trust_has_unconditional_cross_account 123456789012 && echo 0 || echo 1)" \
  'A21 trust policy: a different account with no Condition at all is unconditional cross-account'

cat >"$W/trust-with-eid.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"a-real-secret"}}}]}
J
iam_doc_load_string "$(cat "$W/trust-with-eid.json")"
assert_true "$(iam_trust_has_unconditional_cross_account 123456789012 && echo 1 || echo 0)" \
  'A22 trust policy: the SAME cross-account principal WITH an sts:ExternalId condition does not fire - the naive "any cross-account principal" reading fails here'
assert_true "$(iam_trust_has_unconditional_cross_account 999999999999 && echo 1 || echo 0)" \
  'A23 trust policy: a principal naming this account ITSELF is never cross-account'

# The full-admin policy shape: Effect Allow, Action "*", Resource "*", no
# Condition. A25 pins the required absence of Condition; a real policy that
# is merely broad but conditioned must not match.
cat >"$W/admin.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
J
iam_doc_load_string "$(cat "$W/admin.json")"
assert_true "$(iam_policy_doc_has_full_admin && echo 0 || echo 1)" 'A24 full-admin: Effect Allow, Action "*", Resource "*", no Condition matches'

cat >"$W/admin-conditioned.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example"}}}]}
J
iam_doc_load_string "$(cat "$W/admin-conditioned.json")"
assert_true "$(iam_policy_doc_has_full_admin && echo 1 || echo 0)" \
  'A25 full-admin: the SAME shape but with a real Condition does NOT match - a real evaluation is out of scope, so a conditioned statement is excluded rather than guessed at'

cat >"$W/admin-array.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}
J
iam_doc_load_string "$(cat "$W/admin-array.json")"
assert_true "$(iam_policy_doc_has_full_admin && echo 0 || echo 1)" 'A26 full-admin: Action/Resource wrapped in a one-element array still matches'

cat >"$W/narrow.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
J
iam_doc_load_string "$(cat "$W/narrow.json")"
assert_true "$(iam_policy_doc_has_full_admin && echo 1 || echo 0)" 'A27 full-admin: a narrow action with a wildcard resource does not match'

# ===========================================================================
# B. One scan, every identity: fires on the bad ones, quiet on the clean ones.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_bad_account
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
ADMIN_IDS=$(_ids_for_arn "$TBL" "$ADMIN_ARN")
CLEAN_IDS=$(_ids_for_arn "$TBL" "$CLEAN_ARN")
OPEN_IDS=$(_ids_for_arn "$TBL" "$OPEN_ARN")
XACC_IDS=$(_ids_for_arn "$TBL" "$XACC_ARN")
HARD_IDS=$(_ids_for_arn "$TBL" "$HARD_ARN")
ROOT_IDS=$(_ids_for_arn "$TBL" "$ROOT_ARN")

for want in CLOUD-IAM-ROOT_MFA_OFF-01 CLOUD-IAM-ROOT_ACCESS_KEY-01 \
  CLOUD-IAM-WEAK_PASSWORD_POLICY-01 CLOUD-IAM-ACCESS_ANALYZER_DISABLED-01; do
  assert_contains "$ROOT_IDS" "$want" "B3 the account root is reported by $want"
done

for want in CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 \
  CLOUD-IAM-POLICY_SPRAWL-01 CLOUD-IAM-UNUSED_CREDENTIAL-01 CLOUD-IAM-ACCESS_KEY_ROTATION-01; do
  assert_contains "$ADMIN_IDS" "$want" "B4 the admin user is reported by $want"
done
assert_eq '' "$CLEAN_IDS" 'B5 the clean user, in the SAME run, produces no finding at all'

assert_contains "$OPEN_IDS" 'CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01' 'B6 the open role is reported for its wildcard trust principal'
assert_contains "$OPEN_IDS" 'CLOUD-IAM-POLICY_FULL_ADMIN-01' 'B7 the open role is reported for its inline full-admin policy'
assert_contains "$OPEN_IDS" 'CLOUD-IAM-NO_PERMISSION_BOUNDARY-01' 'B8 the open role is reported for having no permission boundary'
assert_contains "$OPEN_IDS" 'CLOUD-IAM-POLICY_SPRAWL-01' 'B9 the open role is reported for mixing inline and attached policies'
assert_contains "$OPEN_IDS" 'CLOUD-IAM-UNUSED_ROLE-01' 'B10 the open role is reported as never assumed'
assert_not_contains "$OPEN_IDS" 'CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01' \
  'B11 the open role-s wildcard trust is reported as WILDCARD, not additionally as a no-ExternalId cross-account finding'

assert_eq 'CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01' "$XACC_IDS" \
  'B12 the cross-account role is reported for exactly one thing: the missing ExternalId - it is otherwise clean (used recently, has a boundary, no admin policy)'

assert_eq '' "$HARD_IDS" 'B13 the hardened role, in the SAME run, produces no finding at all'

# ===========================================================================
# C. ARN, region, account, CIS, and the cell - on the finding itself.
# ===========================================================================
t_case 'C. finding citation'

_mfa_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-IAM-ROOT_MFA_OFF-01" { print; exit }')
IFS=$'\t' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_mfa_row"

assert_eq "$ROOT_ARN" "$_c_arn" 'C1 the finding cites the account root ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'global' "$_c_region" 'C3 the finding-s region is the literal string global - IAM has no per-resource region at all'
assert_eq '1.5' "$_c_cis" 'C4 the finding carries the cis control id authored on its check record'
assert_eq '123456789012/global' "$_c_cell" 'C5 the cell is <account>/global, the SAME string as the region for this service'

_wpp_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-IAM-WEAK_PASSWORD_POLICY-01" { print; exit }')
_wpp_cis=$(printf '%s' "$_wpp_row" | awk -F'\t' '{ print $5 }')
assert_eq '1.8,1.9' "$_wpp_cis" 'C6 the weak-password-policy finding carries BOTH cis controls it fails at once'

_admin_row=$(printf '%s\n' "$TBL" | awk -F'\t' '$1 == "CLOUD-IAM-POLICY_FULL_ADMIN-01" && $2 == "'"$ADMIN_ARN"'" { print; exit }')
_admin_cis=$(printf '%s' "$_admin_row" | awk -F'\t' '{ print $5 }')
assert_eq '' "$_admin_cis" 'C7 full-admin carries NO cis value - CIS v3.0.0 control 1.16 has no seeded row (docs/CIS-MAPPINGS.md 4), and an honest absence beats an invented one'

# Two stale credentials on one user (the password AND the access key) are
# TWO findings, because loc_sub_key is a fingerprint component.
_admin_unused_subs=$(printf '%s\n' "$TBL" | awk -F'\t' -v a="$ADMIN_ARN" \
  '$1 == "CLOUD-IAM-UNUSED_CREDENTIAL-01" && $2 == a { print $7 }' | LC_ALL=C sort)
assert_eq "$ADMIN_KEY
password" "$_admin_unused_subs" 'C8 the admin user-s stale password and stale access key are two distinct sub_key findings'

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
assert_eq "$_nf" "$_nfp" 'C9 every finding in the run has a distinct fingerprint'

# ===========================================================================
# D. Honesty: a denied call is a reduction; an absent policy IS the finding.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

DENYU_ARN="arn:aws:iam::123456789012:user/$DENYU"
DENYR_ARN="arn:aws:iam::123456789012:role/$DENYR"
assert_eq '' "$(_ids_for_arn "$TBL" "$DENYU_ARN")" 'D1 no finding is invented for the denied user'
assert_eq '' "$(_ids_for_arn "$TBL" "$DENYR_ARN")" 'D2 no finding is invented for the denied role'

# The denied user-s get-user AND list-access-keys are BOTH AccessDenied,
# independently - checks that answered for the OTHER users/roles must still
# be credited, and the denial recorded, rather than the whole check going
# uncredited because ONE identity failed.
assert_contains "$CHECKS_RUN" 'CLOUD-IAM-POLICY_FULL_ADMIN-01' \
  'D3 a check that answered for OTHER identities is in checks_run despite the denied user/role'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D4 the AccessDenied on the denied user/role is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'operation=get-user resource='"$DENYU" \
  'D5 the reduction names the operation and the resource that did not answer'
assert_contains "$REDUCTIONS" 'operation=get-role resource='"$DENYR" \
  'D6 ... and the same for the denied role'

# The full-account cascade: an account whose IDENTITY cannot even be resolved
# examines nothing at all and says so, rather than reporting a clean account.
# The reading D8/D9 fail under is exit 0 with an empty findings set and no
# explanation.
aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/get-user.denied.err"
_run_cloud "$W/run-noident"
CR_NOIDENT=$(_json "$W/run-noident/run.json" coverage_gap)
assert_contains "$CR_NOIDENT" 'never learned which account' \
  'D7 an unresolvable identity records a coverage_gap saying the run never learned its own account, not a clean result'

# A password policy that is ENTIRELY ABSENT (NoSuchEntity) is itself the
# finding, mirroring cloud-s3.sh-s NoSuchBucketPolicy rule. The reading D9
# fails under is "every non-zero aws_ro is a coverage loss", which would
# suppress this finding on exactly the accounts that have the problem.
_routes_bad_account
aws_fixture_route_add iam get-account-password-policy "$FIX/get-account-password-policy.missing.err"
_run_cloud "$W/run-nopolicy"
NOPOLICY_TBL=$(_findings_table "$W/run-nopolicy/findings.jsonl")
assert_contains "$(_ids_for_arn "$NOPOLICY_TBL" "$ROOT_ARN")" 'CLOUD-IAM-WEAK_PASSWORD_POLICY-01' \
  'D8 an ENTIRELY ABSENT password policy (NoSuchEntity) IS the finding'
NOPOLICY_CHECKS=$(_json "$W/run-nopolicy/run.json" checks_run)
assert_contains "$NOPOLICY_CHECKS" 'CLOUD-IAM-WEAK_PASSWORD_POLICY-01' \
  'D9 ... and it counts as the check having been covered, not lost'

# A console password that does not exist at all (get-login-profile:
# NoSuchEntity) is an ANSWER for the clean user, not a loss - checked here on
# the run-b fixtures where the clean user genuinely has no console password.
assert_contains "$CHECKS_RUN" 'CLOUD-IAM-UNUSED_CREDENTIAL-01' \
  'D10 UNUSED_CREDENTIAL is covered even though the clean user has no console password to be stale'
assert_not_contains "$CLEAN_IDS" 'CLOUD-IAM-UNUSED_CREDENTIAL-01' \
  'D11 ... and the clean user itself carries no such finding'

# ===========================================================================
# E. Round-trip: the good account, coverage cell, state, and every format.
# ===========================================================================
t_case 'E. round-trip'

_routes_good_account
_run_cloud "$W/run-good"
assert_eq '0' "$_RC" 'E1 a hardened, empty account still exits 0'
GOOD_TBL=$(_findings_table "$W/run-good/findings.jsonl" 2>/dev/null || true)
assert_eq '' "$GOOD_TBL" 'E2 a hardened account with no users or roles produces NO finding at all'
GOOD_NOTES=$(_json "$W/run-good/run.json" notes)
assert_contains "$GOOD_NOTES" 'covered vacuously' \
  'E3 an empty user/role roster is recorded as vacuous coverage, not silently dropped'

assert_contains "$(_json "$RUNJSON" regions)" 'us-east-1' 'E4 run.json names the region the run resolved'
assert_eq '123456789012' "$(_json "$RUNJSON" cloud.account_id)" 'E5 run.json records the scanned account'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E6 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E7 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-IAM-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-IAM-ROOT_MFA_OFF-01 account-region 123456789012/global' \
  'E8 the run wrote a real account-region coverage cell for an IAM check'

assert_file_exists "$W/run-b/report.md" 'E9 report.md written'
assert_file_exists "$W/run-b/report.html" 'E10 report.html written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$ADMIN_ARN" 'E11 report.md names the admin user-s ARN'

_routes_bad_account
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E12 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-IAM-ROOT_MFA_OFF-01' 'E13 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$ADMIN_ARN" 'E14 the SARIF result names the resource'
assert_contains "$_SARIF" '1.5' 'E15 the CIS control id authored on the check record reaches the SARIF rule tags'

t_summary cloud-iam
