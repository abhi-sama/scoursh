#!/usr/bin/env bash
# tests/suites/cloud-cognito.sh - modules/cloud/aws/live/cognito.sh: the §8.3
# Cognito read-only checks (docs/STEP6-CLOUD-PLAN.md CLOUD-20).
#
# What this suite exists to pin, because each has a plausible wrong reading
# that would ship silently:
#
#   1. BOTH DIRECTIONS, IN ONE RUN.  A misconfigured user pool, a hardened
#      one, a misconfigured app client and a hardened one, an open identity
#      pool and a closed one are all examined by the SAME scan, so "the check
#      fires" and "the check stays quiet" are asserted against one code path in
#      one process.  A pack gone inert passes every silence assertion ever
#      written, and two separate runs (one all-bad, one all-good) cannot tell
#      the two apart.
#   2. EVERY FINDING CITES ARN, REGION AND ACCOUNT.  Asserted on the emitted
#      finding's own fields, not on the script's intent.  The `cis` column is
#      asserted EMPTY, deliberately - see section C's own note, and the
#      registry's: CIS AWS Foundations Benchmark v3.0.0 has no Cognito section,
#      and citing an IAM-user control against an application's user pool is the
#      misattribution docs/CIS-MAPPINGS.md §5 item 5 forbids.
#   3. THE CELL IS THE REGION'S, AND IT IS NOT `global`.  Cognito is a
#      `regional` row, unlike the `s3` row beside it, so a copy of s3.sh's
#      `<account>/global` cell would file every finding in a cell no pass ever
#      covers - tension 12 could then never classify one `fixed`.
#   4. AN APP-CLIENT FINDING CITES THE POOL'S REAL ARN WITH THE CLIENT ID IN
#      `loc_sub_key`, AND NEVER AN INVENTED CLIENT ARN.  AWS defines no ARN for
#      an app client; `loc_resource_key` is a fingerprint component, so an
#      invented one would change every stored baseline the day it was removed.
#   5. A DENIED CALL IS A `coverage_reduction`, NEVER SILENCE, AND THE TWO API
#      NAMESPACES FAIL INDEPENDENTLY.  A denied `list-user-pools` must not be
#      reported as having lost the identity-pool checks, which are reached
#      through a different service.
#   6. THE UNAUTHENTICATED ROLE IS REALLY INSPECTED, AT TWO GRADES, AND A
#      CONDITIONED WILDCARD IS SET ASIDE RATHER THAN JUDGED.
#   7. THE FINDINGS ROUND-TRIP.  Into findings.jsonl, into a real
#      `account-region` coverage cell in state/, and into every report format
#      including SARIF.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against tests/lib/aws-
# fixtures.sh's routed stub `aws`, serving committed fixtures from
# tests/fixtures/aws/cloud-cognito/.
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
# -x back-edge cut: modules/cloud/aws/live/cognito_engine.sh sources
# modules/cloud/aws/engine.sh at RUNTIME behind its own guard, and that file
# drags in modules/sast/engine.sh plus the whole lib/ hub chain.  shellcheck -x
# re-expands EVERY source edge it follows rather than memoising, so following
# it from here would put this suite's hub sum over tests/lint-source-graph.sh's
# cap for no checking this tree does not already do from the module's own entry
# point.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/cognito_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-cognito
rm -rf "$W"
mkdir -p "$W/bin"
# Canonicalise: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a LITERAL prefix
# from every loaded file's realpath, so a fixture root reached through macOS's
# /var -> /private/var $TMPDIR symlink would fail E070 on every file for a
# reason that has nothing to do with the file.
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/aws/cloud-cognito

WEAK_POOL=eu-west-2_weakpool01
HARD_POOL=eu-west-2_hardpool01
OPT_POOL=eu-west-2_optpool01
NOPOL_POOL=eu-west-2_nopolicy01
WEAK_CLIENT=weakclient000000000000000
HARD_CLIENT=hardclient000000000000000
OFF_CLIENT=oauthoffclient0000000000
OPEN_IDP='eu-west-2:11111111-1111-1111-1111-111111111111'
HARD_IDP='eu-west-2:22222222-2222-2222-2222-222222222222'
BROAD_IDP='eu-west-2:33333333-3333-3333-3333-333333333333'
OPEN_ROLE=Cognito_openpoolUnauth_Role
BROAD_ROLE=Cognito_broadpoolUnauth_Role
BROAD_POLICY_ARN='arn:aws:iam::123456789012:policy/scoursh-fixture-managed-broad'

POOL_ARN_PREFIX='arn:aws:cognito-idp:eu-west-2:123456789012:userpool'
IDP_ARN_PREFIX='arn:aws:cognito-identity:eu-west-2:123456789012:identitypool'

aws_fixture_stub_install "$W/bin"

# `_routes_default [OMIT_OPERATION]` - the route table every scan case starts
# from: the two calls modules/cloud/aws/run.sh makes before any service script,
# then the two list calls, then a per-resource row for each fixture resource.
#
# THE PER-RESOURCE ROWS ARE QUALIFIED ON THE RESOURCE ID, which is what puts a
# misconfigured and a hardened resource of each kind into ONE run.  An
# unqualified row would serve every resource the same response, and the suite
# would then be unable to distinguish a check that classifies correctly from
# one that reports whatever the last fixture said.
#
# An optional argument names ONE operation whose per-resource rows are omitted,
# so a case can register a single unqualified row for it instead.  Without
# that, an unqualified row added afterwards would never be reached: a qualified
# row always wins for the resource it names, so the case would assert against
# the ORIGINAL fixtures and pass for the wrong reason.
_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"

  [[ $omit == list-user-pools ]] \
    || aws_fixture_route_add cognito-idp list-user-pools "$FIX/list-user-pools.json"
  [[ $omit == list-identity-pools ]] \
    || aws_fixture_route_add cognito-identity list-identity-pools "$FIX/list-identity-pools.json"

  if [[ $omit != describe-user-pool ]]; then
    aws_fixture_route_add_for cognito-idp describe-user-pool "$WEAK_POOL"  "$FIX/describe-user-pool.weak.json"
    aws_fixture_route_add_for cognito-idp describe-user-pool "$HARD_POOL"  "$FIX/describe-user-pool.hardened.json"
    aws_fixture_route_add_for cognito-idp describe-user-pool "$OPT_POOL"   "$FIX/describe-user-pool.optional.json"
    aws_fixture_route_add_for cognito-idp describe-user-pool "$NOPOL_POOL" "$FIX/describe-user-pool.nopolicy.json"
  fi

  if [[ $omit != list-user-pool-clients ]]; then
    aws_fixture_route_add_for cognito-idp list-user-pool-clients "$WEAK_POOL"  "$FIX/list-user-pool-clients.weak.json"
    aws_fixture_route_add_for cognito-idp list-user-pool-clients "$HARD_POOL"  "$FIX/list-user-pool-clients.empty.json"
    aws_fixture_route_add_for cognito-idp list-user-pool-clients "$OPT_POOL"   "$FIX/list-user-pool-clients.optional.json"
    aws_fixture_route_add_for cognito-idp list-user-pool-clients "$NOPOL_POOL" "$FIX/list-user-pool-clients.empty.json"
  fi

  if [[ $omit != describe-user-pool-client ]]; then
    aws_fixture_route_add_for cognito-idp describe-user-pool-client "$WEAK_CLIENT" "$FIX/describe-user-pool-client.weak.json"
    aws_fixture_route_add_for cognito-idp describe-user-pool-client "$HARD_CLIENT" "$FIX/describe-user-pool-client.hardened.json"
    aws_fixture_route_add_for cognito-idp describe-user-pool-client "$OFF_CLIENT"  "$FIX/describe-user-pool-client.oauth-off.json"
  fi

  if [[ $omit != describe-identity-pool ]]; then
    aws_fixture_route_add_for cognito-identity describe-identity-pool "$OPEN_IDP"  "$FIX/describe-identity-pool.open.json"
    aws_fixture_route_add_for cognito-identity describe-identity-pool "$HARD_IDP"  "$FIX/describe-identity-pool.hardened.json"
    aws_fixture_route_add_for cognito-identity describe-identity-pool "$BROAD_IDP" "$FIX/describe-identity-pool.broad.json"
  fi

  if [[ $omit != get-identity-pool-roles ]]; then
    aws_fixture_route_add_for cognito-identity get-identity-pool-roles "$OPEN_IDP"  "$FIX/get-identity-pool-roles.open.json"
    aws_fixture_route_add_for cognito-identity get-identity-pool-roles "$HARD_IDP"  "$FIX/get-identity-pool-roles.hardened.json"
    aws_fixture_route_add_for cognito-identity get-identity-pool-roles "$BROAD_IDP" "$FIX/get-identity-pool-roles.broad.json"
  fi

  # The IAM half.  Qualified on the ROLE NAME, which is what the pass derives
  # from the role ARN - so if `cognito_role_name_of` ever split on the FIRST
  # `/` instead of the last, the open pool's role would resolve to
  # `service-role`, no route would match it, and the stub would fail loudly
  # rather than the check quietly reporting the account's most permissive role
  # clean.  That is section F's assertion, made real by this routing.
  if [[ $omit != iam ]]; then
    aws_fixture_route_add_for iam list-role-policies "$OPEN_ROLE"  "$FIX/iam.list-role-policies.open.json"
    aws_fixture_route_add_for iam list-role-policies "$BROAD_ROLE" "$FIX/iam.list-role-policies.broad.json"
    aws_fixture_route_add_for iam list-attached-role-policies "$OPEN_ROLE"  "$FIX/iam.list-attached-role-policies.open.json"
    aws_fixture_route_add_for iam list-attached-role-policies "$BROAD_ROLE" "$FIX/iam.list-attached-role-policies.broad.json"
    aws_fixture_route_add_for iam get-role-policy "$OPEN_ROLE" "$FIX/iam.get-role-policy.open.json"
    aws_fixture_route_add_for iam get-policy "$BROAD_POLICY_ARN" "$FIX/iam.get-policy.broad.json"
    aws_fixture_route_add_for iam get-policy-version "$BROAD_POLICY_ARN" "$FIX/iam.get-policy-version.broad.json"
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
# case's responses.
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

# One `check_id US resource_key US region US cell US cis US account US sub_key`
# line per finding, read from findings.jsonl, where US is 0x1f.
#
# 0x1f AND NEVER A TAB, BECAUSE THREE OF THESE SEVEN COLUMNS ARE LEGITIMATELY
# EMPTY AND TWO OF THEM SIT IN THE MIDDLE.  A tab is an IFS-*whitespace*
# character, so a `read` over a tab-separated record folds a RUN of tabs into
# ONE delimiter and drops leading and trailing ones (POSIX XCU 2.6.5) - a
# seven-column record whose `cis` column is empty arrives as six columns and
# every later value is silently shifted left.  Measured here rather than
# reasoned about: with a tab, a pool finding's empty `cis` shifted `account`
# into it, so the assertion that a cognito finding carries NO CIS id read back
# the ACCOUNT ID, and the assertion that it cites the account read back the
# empty string - two failures pointing at an emitter that was correct.
# AGENTS.md records the identical lesson from
# `modules/dast/passive/markup_engine.sh`, where the shift made a `<link>`
# with no `integrity` report an attribute the server never sent - the
# direction that reads as a pass.  0x1f is not IFS whitespace, so an empty
# field survives as an empty field.
#
# `awk -F` does NOT have this problem - it splits on every separator
# occurrence - which is why the per-resource lookups below passed while the
# two `read` sites did not.  Both use 0x1f anyway: one separator per stream is
# what stops the next reader picking the wrong one.
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
        loc.get('sub_key', '') or '',
    ]))
PY
}

# Check ids reported against one resource ARN, optionally narrowed to one
# sub_key.  Reading the SHARD or the JSONL as raw text is deliberately avoided:
# a finding's remediation prose names sibling check ids on purpose (the
# IDPOOL_UNAUTH_IDENTITIES record names IDPOOL_UNAUTH_CREDENTIALS), so a
# substring test over the file finds ids no finding carries - the lesson
# tests/suites/dast-authz.sh records at length.
_ids_for() {
  local table=$1 arn=$2 sub=${3-}
  if (( $# >= 3 )); then
    printf '%s\n' "$table" | awk -F"$(printf '\037')" -v a="$arn" -v s="$sub" \
      '$2 == a && $7 == s { print $1 }' | LC_ALL=C sort
  else
    printf '%s\n' "$table" | awk -F"$(printf '\037')" -v a="$arn" '$2 == a { print $1 }' | LC_ALL=C sort
  fi
}

# ===========================================================================
# A. The user-pool classifiers, against the committed fixtures, no scan.
# ===========================================================================
t_case 'A. user-pool classifiers'

_v=''
cognito_doc_load "$FIX/describe-user-pool.weak.json"
assert_true "$(cognito_pool_password_weaknesses_set _v && echo 0 || echo 1)" \
  'A1 password policy: a pool WITH a policy object is read (return 0 means "a policy was present")'
cognito_doc_load "$FIX/describe-user-pool.weak.json"
cognito_pool_password_weaknesses_set _v || true
assert_contains "$_v" 'min_length_lt_8' 'A2 password policy: a minimum below 8 is a weakness'
assert_contains "$_v" 'no_uppercase' 'A3 password policy: an explicitly-false Require flag is a weakness'
# The reading A4 fails under is `[[ $v == false ]]`, which only reports an
# EXPLICITLY false setting.  The weak fixture omits RequireSymbols entirely,
# which the API treats as false - so a document that simply does not mention a
# requirement must not read as having it.
assert_contains "$_v" 'no_symbols' \
  'A4 password policy: an ENTIRELY ABSENT Require flag is a weakness too, not a pass'
assert_not_contains "$_v" 'no_lowercase' 'A5 password policy: a true Require flag is not reported'

cognito_doc_load "$FIX/describe-user-pool.hardened.json"
cognito_pool_password_weaknesses_set _v || true
assert_eq '' "$_v" 'A6 password policy: a policy meeting the baseline yields no weakness'

# A pool with NO PasswordPolicy object at all is at Cognito's own default
# (8 characters, all four classes) rather than at nothing.  The reading A7
# fails under is "an absent policy means every field is absent means five
# weaknesses", which puts five false positives on the safest configuration.
cognito_doc_load "$FIX/describe-user-pool.nopolicy.json"
assert_true "$(cognito_pool_password_weaknesses_set _v && echo 1 || echo 0)" \
  'A7 password policy: a pool that configures NO policy is reported as having none, not as weak'

cognito_doc_load "$FIX/describe-user-pool.weak.json"
assert_true "$(cognito_pool_temp_password_days_set _v && echo 0 || echo 1)" \
  'A8 temp password: 30 days exceeds the 7-day default'
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_temp_password_days_set _v && echo 1 || echo 0)" \
  'A9 temp password: exactly the 7-day default is not reported'

for _f in weak:OFF hardened:ON optional:OPTIONAL; do
  cognito_doc_load "$FIX/describe-user-pool.${_f%%:*}.json"
  cognito_pool_mfa_set _v || true
  assert_eq "${_f#*:}" "$_v" "A10 MFA: the ${_f%%:*} pool reads as ${_f#*:}"
done
# An MfaConfiguration a document does not carry is OFF, not unknown: the field
# is returned on every response, and reading an absence as "no answer" would
# silence the check on exactly the pools that never turned MFA on.
printf '{"UserPool": {"Id": "x"}}\n' >"$W/nomfa.json"
cognito_doc_load "$W/nomfa.json"
cognito_pool_mfa_set _v || true
assert_eq 'OFF' "$_v" 'A11 MFA: an absent MfaConfiguration is OFF, not the empty string'

# AUDIT is NOT a pass.  The reading A13 fails under treats any non-OFF value as
# configured, which reports every audit-only pool as having adaptive auth -
# and in AUDIT mode Cognito computes the risk score and acts on none of it.
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_advanced_security_set _v && echo 0 || echo 1)" \
  'A12 advanced security: ENFORCED is a pass'
cognito_doc_load "$FIX/describe-user-pool.optional.json"
assert_true "$(cognito_pool_advanced_security_set _v && echo 1 || echo 0)" \
  'A13 advanced security: AUDIT is NOT a pass'
cognito_doc_load "$FIX/describe-user-pool.optional.json"
cognito_pool_advanced_security_set _v || true
assert_eq 'AUDIT' "$_v" 'A14 advanced security: the mode is reported so the remediation can differ'

# The polarity trap: the field is AllowAdminCreateUserOnly, so `false` is the
# OPEN case.  The reading A15/A16 fail under is `[[ $v == true ]]`, which
# reports every locked-down pool as open and every open pool as locked down.
cognito_doc_load "$FIX/describe-user-pool.weak.json"
assert_true "$(cognito_pool_self_registration_open && echo 0 || echo 1)" \
  'A15 self-registration: AllowAdminCreateUserOnly false means OPEN'
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_self_registration_open && echo 1 || echo 0)" \
  'A16 self-registration: AllowAdminCreateUserOnly true means closed'

# Recovery is decided on the HIGHEST-PRIORITY mechanism, not on membership.
# The reading A18 fails under is a membership test, which flags the ordinary
# and reasonable email-first-phone-second configuration.
cognito_doc_load "$FIX/describe-user-pool.weak.json"
assert_true "$(cognito_pool_recovery_set _v && echo 0 || echo 1)" \
  'A17 recovery: verified_phone_number at priority 1 is the finding'
cognito_doc_load "$FIX/describe-user-pool.optional.json"
assert_true "$(cognito_pool_recovery_set _v && echo 1 || echo 0)" \
  'A18 recovery: email first with phone at priority 2 is NOT reported'
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_recovery_set _v && echo 1 || echo 0)" \
  'A19 recovery: admin_only is a pass, not a weaker channel'

cognito_doc_load "$FIX/describe-user-pool.weak.json"
assert_true "$(cognito_pool_deletion_protection_off && echo 0 || echo 1)" \
  'A20 deletion protection: INACTIVE is the finding'
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_deletion_protection_off && echo 1 || echo 0)" \
  'A21 deletion protection: ACTIVE is a pass'

cognito_doc_load "$FIX/describe-user-pool.weak.json"
cognito_pool_self_service_surface_set _v || true
assert_contains "$_v" 'SignUp' 'A22 self-service surface: open self-registration exposes SignUp'
assert_contains "$_v" 'ForgotPassword' 'A23 self-service surface: a non-admin_only recovery exposes ForgotPassword'
assert_contains "$_v" 'ResendConfirmationCode' \
  'A24 self-service surface: open registration plus an auto-verified attribute exposes ResendConfirmationCode'
cognito_doc_load "$FIX/describe-user-pool.hardened.json"
assert_true "$(cognito_pool_self_service_surface_set _v && echo 1 || echo 0)" \
  'A25 self-service surface: admin-only creation plus admin_only recovery exposes nothing'

# ===========================================================================
# B. The app-client classifiers.
# ===========================================================================
t_case 'B. app-client classifiers'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_plaintext_flows_set _v || true
assert_contains "$_v" 'ALLOW_USER_PASSWORD_AUTH' 'B1 auth flows: the public password flow is found'
assert_contains "$_v" 'ALLOW_ADMIN_USER_PASSWORD_AUTH' 'B2 auth flows: the admin password flow is found'
assert_not_contains "$_v" 'ALLOW_REFRESH_TOKEN_AUTH' 'B3 auth flows: an SRP/refresh flow is not reported'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_plaintext_flows_set _v && echo 1 || echo 0)" \
  'B4 auth flows: an SRP-only client is quiet'

# The membership test is WHOLE-LINE.  `ALLOW_USER_PASSWORD_AUTH` is a SUBSTRING
# of `ALLOW_ADMIN_USER_PASSWORD_AUTH`, so a `*"$v"*` test reports a client that
# permits only the admin flow as permitting the public one - citing a flow the
# client does not have.  B5 is the case that fails under that reading.
cat >"$W/client-adminonly.json" <<'J'
{"UserPoolClient": {"ClientId": "c", "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH"]}}
J
cognito_doc_load "$W/client-adminonly.json"
cognito_client_plaintext_flows_set _v || true
assert_not_contains "$_v" $'\nALLOW_USER_PASSWORD_AUTH' \
  'B5 auth flows: ALLOW_USER_PASSWORD_AUTH is not read out of ALLOW_ADMIN_USER_PASSWORD_AUTH'
assert_eq 'ALLOW_ADMIN_USER_PASSWORD_AUTH' "$_v" 'B5b ... and the flow that IS present is the only one reported'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
assert_true "$(cognito_client_implicit_oauth && echo 0 || echo 1)" \
  'B6 implicit OAuth: an implicit flow on an OAuth-enabled client is the finding'
# The reading B7 fails under is "the flow list alone", which reports a client
# whose OAuth endpoints Cognito refuses outright - a finding nobody can act on.
cognito_doc_load "$FIX/describe-user-pool-client.oauth-off.json"
assert_true "$(cognito_client_implicit_oauth && echo 1 || echo 0)" \
  'B7 implicit OAuth: a stale implicit flow on a client with AllowedOAuthFlowsUserPoolClient false is NOT reported'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_insecure_urls_set _v || true
assert_contains "$_v" 'http://staging.example.com/callback' 'B8 callbacks: a plaintext URL is the finding'
# The reading B9 fails under is "any http:// URL", which puts a finding on the
# development configuration of nearly every native client - RFC 8252 §7.3
# endorses a loopback redirect precisely because it never leaves the machine.
assert_not_contains "$_v" 'localhost' 'B9 callbacks: http://localhost is NOT reported'
assert_not_contains "$_v" '127.0.0.1' 'B9b callbacks: http://127.0.0.1 is NOT reported either'
# ... and the exclusion is on the HOST, so a name that merely begins with
# `localhost` is a real, remote destination and IS reported.
cat >"$W/client-lookalike.json" <<'J'
{"UserPoolClient": {"ClientId": "c", "CallbackURLs": ["http://localhost.attacker.example/cb"]}}
J
cognito_doc_load "$W/client-lookalike.json"
cognito_client_insecure_urls_set _v || true
assert_contains "$_v" 'localhost.attacker.example' \
  'B10 callbacks: http://localhost.attacker.example is a remote host and IS reported'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_wildcard_urls_set _v || true
assert_contains "$_v" 'https://*.example.com/callback' 'B11 callbacks: a wildcard host is the finding'
assert_not_contains "$_v" 'https://app.example.com/callback' 'B12 callbacks: a concrete https URL is not'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_wildcard_urls_set _v && echo 1 || echo 0)" \
  'B13 callbacks: a client with only concrete URLs is quiet'

# The unit default is PER TOKEN KIND: hours for access/ID, days for refresh.
# The reading B15 fails under is "seconds when TokenValidityUnits omits the
# kind", which understates a 24-hour access token by 3600x - and reads clean.
cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_token_seconds_set _v AccessToken || true
assert_eq '86400' "$_v" 'B14 token lifetime: 24 with unit hours is 86400 seconds'
cognito_token_seconds_set _v IdToken || true
assert_eq '3600' "$_v" 'B15 token lifetime: 60 with unit minutes is 3600 seconds'
cat >"$W/client-nounits.json" <<'J'
{"UserPoolClient": {"ClientId": "c", "AccessTokenValidity": 24, "RefreshTokenValidity": 3650}}
J
cognito_doc_load "$W/client-nounits.json"
cognito_token_seconds_set _v AccessToken || true
assert_eq '86400' "$_v" 'B16 token lifetime: with NO TokenValidityUnits the access token defaults to HOURS'
cognito_token_seconds_set _v RefreshToken || true
assert_eq '315360000' "$_v" 'B17 token lifetime: ... and the refresh token defaults to DAYS, not hours'
# An unconfigured validity is NOT zero and NOT excessive: Cognito's own
# defaults sit inside every threshold, so a client that sets nothing must be
# reported as unconfigured.
cat >"$W/client-notokens.json" <<'J'
{"UserPoolClient": {"ClientId": "c"}}
J
cognito_doc_load "$W/client-notokens.json"
assert_true "$(cognito_token_seconds_set _v AccessToken && echo 1 || echo 0)" \
  'B18 token lifetime: an unconfigured validity returns "not configured", never 0'
assert_true "$(cognito_client_long_tokens_set _v && echo 1 || echo 0)" \
  'B19 token lifetime: ... so a client at Cognito defaults produces no finding'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_long_tokens_set _v || true
assert_contains "$_v" 'AccessToken 86400' 'B20 token lifetime: a 24-hour access token is over the 12-hour threshold'
assert_contains "$_v" 'RefreshToken 315360000' 'B21 token lifetime: a 10-year refresh token is over the 90-day threshold'
assert_not_contains "$_v" 'IdToken' 'B22 token lifetime: the 60-minute ID token is NOT reported - the check is per kind'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
assert_true "$(cognito_client_revocation_off && echo 0 || echo 1)" 'B23 revocation: false is the finding'
cognito_doc_load "$W/client-notokens.json"
assert_true "$(cognito_client_revocation_off && echo 0 || echo 1)" \
  'B24 revocation: an ABSENT EnableTokenRevocation is off - the state of every pre-feature client'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_revocation_off && echo 1 || echo 0)" 'B25 revocation: true is a pass'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_sensitive_writes_set _v || true
assert_contains "$_v" 'email_verified' 'B26 writable attributes: a writable email_verified is the finding'
assert_contains "$_v" 'custom:role' 'B27 writable attributes: a custom privilege attribute is matched'
# The custom-attribute match is on the WHOLE name, never a substring.  The
# reading B28 fails under is `*role*`, which flags an ordinary preference.
assert_not_contains "$_v" 'custom:wardrobe' \
  'B28 writable attributes: custom:wardrobe is NOT matched (the comparison is whole-name, not substring)'
assert_not_contains "$_v" $'\nemail\n' 'B29 writable attributes: a plain writable email is not reported'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_sensitive_writes_set _v && echo 1 || echo 0)" \
  'B30 writable attributes: a client writing only preferences is quiet'

# Public/confidential is read from the PRESENCE of ClientSecret, never from
# GenerateSecret - which describe-user-pool-client does not return at all, so a
# classifier reading it would report every client as public.
cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
assert_true "$(cognito_client_is_public && echo 0 || echo 1)" 'B31 public client: no ClientSecret means public'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_is_public && echo 1 || echo 0)" 'B32 public client: a ClientSecret means confidential'
cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
cognito_client_confidential_only_flows_set _v || true
assert_contains "$_v" 'client_credentials' 'B33 public+confidential: client_credentials on a public client is the finding'
assert_contains "$_v" 'ALLOW_ADMIN_USER_PASSWORD_AUTH' 'B34 public+confidential: an ADMIN_* flow on a public client too'
# A CONFIDENTIAL client with the same flows is not this finding: the whole
# check is about the client having no secret.  The reading B35 fails under
# drops the is-public test and reports every server-side client in the estate.
cat >"$W/client-confidential-cc.json" <<'J'
{"UserPoolClient": {"ClientId": "c", "ClientSecret": "s", "AllowedOAuthFlows": ["client_credentials"]}}
J
cognito_doc_load "$W/client-confidential-cc.json"
assert_true "$(cognito_client_confidential_only_flows_set _v && echo 1 || echo 0)" \
  'B35 public+confidential: a client WITH a secret using client_credentials is NOT reported'

cognito_doc_load "$FIX/describe-user-pool-client.weak.json"
assert_true "$(cognito_client_user_existence_errors_off && echo 0 || echo 1)" \
  'B36 user existence: LEGACY is the enumeration oracle'
cognito_doc_load "$W/client-notokens.json"
assert_true "$(cognito_client_user_existence_errors_off && echo 0 || echo 1)" \
  'B37 user existence: an ABSENT setting is LEGACY, not unknown'
cognito_doc_load "$FIX/describe-user-pool-client.hardened.json"
assert_true "$(cognito_client_user_existence_errors_off && echo 1 || echo 0)" \
  'B38 user existence: ENABLED is a pass'

# ===========================================================================
# C. The identity-pool and IAM-policy classifiers.
# ===========================================================================
t_case 'C. identity-pool and policy classifiers'

# describe-identity-pool has NO response envelope, unlike the two user-pool
# describes.  A classifier written against `IdentityPool.AllowUnauthenticated-
# Identities` reads every field as absent, which reports every identity pool as
# having anonymous access switched off - the direction that reads as clean.
cognito_doc_load "$FIX/describe-identity-pool.open.json"
assert_true "$(cognito_idpool_allows_unauth && echo 0 || echo 1)" \
  'C1 identity pool: AllowUnauthenticatedIdentities is read from the TOP LEVEL, with no envelope'
assert_true "$(cognito_idpool_classic_flow && echo 0 || echo 1)" 'C2 identity pool: AllowClassicFlow true is the finding'
cognito_doc_load "$FIX/describe-identity-pool.hardened.json"
assert_true "$(cognito_idpool_allows_unauth && echo 1 || echo 0)" 'C3 identity pool: false is a pass'
assert_true "$(cognito_idpool_classic_flow && echo 1 || echo 0)" 'C4 identity pool: classic flow false is a pass'

cognito_doc_load "$FIX/get-identity-pool-roles.open.json"
assert_true "$(cognito_idpool_role_set _v unauthenticated && echo 0 || echo 1)" \
  'C5 roles: an unauthenticated role ARN is read'
cognito_doc_load "$FIX/get-identity-pool-roles.hardened.json"
assert_true "$(cognito_idpool_role_set _v unauthenticated && echo 1 || echo 0)" \
  'C6 roles: a pool with only an authenticated role reports no unauthenticated one'

# The role NAME is everything after the LAST `/`.  A Cognito-console-created
# role sits in the `service-role/` path, and splitting on the first `/` yields
# `service-role` - every later iam call then answers NoSuchEntity, so the
# unauthenticated role's policies read as absent and the highest-severity check
# in this pack reports the pool clean.
assert_eq 'Cognito_openpoolUnauth_Role' \
  "$(cognito_role_name_of 'arn:aws:iam::123456789012:role/service-role/Cognito_openpoolUnauth_Role')" \
  'C7 role name: a role in a PATH resolves to its last segment, not to service-role'
assert_eq 'Plain_Role' "$(cognito_role_name_of 'arn:aws:iam::123456789012:role/Plain_Role')" \
  'C8 role name: a role with no path resolves to itself'

# AuthenticatedRole is the PERMISSIVE resolution and Deny is the safe one,
# which is the opposite of what the names suggest.  C10 is the case that fails
# under the reversed reading.
cognito_doc_load "$FIX/get-identity-pool-roles.open.json"
cognito_idpool_ambiguous_mappings_set _v || true
assert_contains "$_v" 'Token' 'C9 role mapping: an AuthenticatedRole resolution is reported with its mapping type'
cognito_doc_load "$FIX/get-identity-pool-roles.hardened.json"
assert_true "$(cognito_idpool_ambiguous_mappings_set _v && echo 1 || echo 0)" \
  'C10 role mapping: a Deny resolution is NOT reported'

# A `Statement` that is a single OBJECT rather than an array is legal policy
# and is the ordinary shape for a hand-written Cognito unauthenticated role.
# The reading C11 fails under walks only the array form and reports the most
# permissive role in the account as having no statements at all.
cognito_doc_load "$FIX/iam.get-role-policy.open.json"
assert_true "$(cognito_policy_grants_set _v PolicyDocument && echo 0 || echo 1)" \
  'C11 policy: a single-OBJECT Statement is walked, not only an array'
cognito_doc_load "$FIX/iam.get-role-policy.open.json"
cognito_policy_grants_set _v PolicyDocument || true
assert_eq 'admin * *' "$_v" 'C12 policy: Action "*" on Resource "*" grades as admin'
assert_eq 'admin' "$(cognito_policy_worst_grade "$_v")" 'C13 policy: the worst grade of an admin grant is admin'

cognito_doc_load "$FIX/iam.get-policy-version.broad.json"
cognito_policy_grants_set _v PolicyVersion Document || true
assert_eq 'service s3:* *' "$_v" 'C14 policy: a service-wide wildcard grades as service, and is the ONLY grant reported'
assert_eq 'service' "$(cognito_policy_worst_grade "$_v")" 'C15 policy: its worst grade is service, not admin'
# Three negatives in one document, each of which the naive reading gets wrong:
assert_not_contains "$_v" 'dynamodb' \
  'C16 policy: a wildcard statement carrying a Condition is SET ASIDE, not judged'
assert_eq '1' "$_COGNITO_POLICY_CONDITIONED" \
  'C17 policy: ... and it is COUNTED, so the limit can be declared rather than silently dropped'
assert_not_contains "$_v" 's3:GetObject' 'C18 policy: a narrow, named action is not reported'
cognito_doc_load "$FIX/iam.get-policy-version.broad.json"
cognito_policy_grants_set _v PolicyVersion Document || true
assert_not_contains "$_v" 'admin' 'C19 policy: a DENY statement with Action "*" is not read as a grant'

# NotAction / NotResource invert the set, so a statement using either grants
# everything EXCEPT what it names - over-permissive by construction.
cat >"$W/policy-notaction.json" <<'J'
{"PolicyDocument": {"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}]}}
J
cognito_doc_load "$W/policy-notaction.json"
assert_true "$(cognito_policy_grants_set _v PolicyDocument && echo 0 || echo 1)" \
  'C20 policy: a NotAction statement is reported'
# A statement with no Resource at all is malformed rather than a wildcard.  The
# reading C21 fails under reads an absent Resource as "*", manufacturing a
# critical finding out of a document this parser did not understand.
cat >"$W/policy-noresource.json" <<'J'
{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}
J
cognito_doc_load "$W/policy-noresource.json"
assert_true "$(cognito_policy_grants_set _v PolicyDocument && echo 1 || echo 0)" \
  'C21 policy: an absent Resource is NOT read as "*"'

# ===========================================================================
# D. One scan, both directions, and the finding citation.
# ===========================================================================
t_case 'D. one run, both directions'

# `--format json,sarif,html,md` on the SINGLE main run rather than a second
# scan for SARIF alone.  `--format` is a CSV (scan.sh's own
# `_scan_validate_csv`), `report_all` writes findings.jsonl and run.json
# unconditionally, and every other format is gated on the list - so one
# invocation produces every surface section G asserts against.  That is not
# only a saving: asserting the JSONL, the markdown and the SARIF against ONE
# run means they cannot disagree about what the run found, which two runs over
# a fixture set could quietly start doing.
_routes_default
_run_cloud "$W/run-d" --format json,sarif,html,md
assert_eq '0' "$_RC" 'D1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-d/findings.jsonl" 'D2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-d/findings.jsonl")
WEAK_ARN=$POOL_ARN_PREFIX/$WEAK_POOL
HARD_ARN=$POOL_ARN_PREFIX/$HARD_POOL
NOPOL_ARN=$POOL_ARN_PREFIX/$NOPOL_POOL
OPEN_IDP_ARN=$IDP_ARN_PREFIX/$OPEN_IDP
HARD_IDP_ARN=$IDP_ARN_PREFIX/$HARD_IDP
BROAD_IDP_ARN=$IDP_ARN_PREFIX/$BROAD_IDP

# The misconfigured pool is wrong in every way the eight pool checks observe.
WEAK_POOL_IDS=$(_ids_for "$TBL" "$WEAK_ARN" '')
for want in CLOUD-COGNITO-WEAK_PASSWORD_POLICY-01 CLOUD-COGNITO-TEMP_PASSWORD_VALIDITY-01 \
  CLOUD-COGNITO-MFA_OFF-01 CLOUD-COGNITO-ADVANCED_SECURITY_OFF-01 \
  CLOUD-COGNITO-SELF_REGISTRATION_OPEN-01 CLOUD-COGNITO-RECOVERY_SMS_ONLY-01 \
  CLOUD-COGNITO-DELETION_PROTECTION_OFF-01 CLOUD-COGNITO-SELF_SERVICE_SURFACE-01; do
  assert_contains "$WEAK_POOL_IDS" "$want" "D3 the misconfigured user pool is reported by $want"
done
# ... and the hardened pool in the SAME run is right in every one of them.
# This is the half a pack gone inert would also pass, which is why D3 is
# asserted from the same run: only both together distinguish "classifies
# correctly" from "never fires".
assert_eq '' "$(_ids_for "$TBL" "$HARD_ARN")" \
  'D4 the hardened user pool in the SAME run produces no finding at all'
# The default-policy pool produces the two findings its own fixture earns and
# specifically NOT the weak-password one, which is what proves the "no policy
# object means Cognito's default" reading reached the real pass.
assert_not_contains "$(_ids_for "$TBL" "$NOPOL_ARN")" 'WEAK_PASSWORD_POLICY' \
  'D5 a pool that configures NO password policy is not reported as having a weak one'

# MFA_OFF and MFA_OPTIONAL are two ids, and the OPTIONAL pool gets the second
# rather than the first.  One id would collide the two on one fingerprint and
# make the meaning of an unchanged finding flip between runs.
OPT_ARN=$POOL_ARN_PREFIX/$OPT_POOL
OPT_IDS=$(_ids_for "$TBL" "$OPT_ARN" '')
assert_contains "$OPT_IDS" 'CLOUD-COGNITO-MFA_OPTIONAL-01' 'D6 an OPTIONAL pool is reported by MFA_OPTIONAL'
assert_not_contains "$OPT_IDS" 'CLOUD-COGNITO-MFA_OFF-01' 'D7 ... and NOT by MFA_OFF'
assert_contains "$WEAK_POOL_IDS" 'CLOUD-COGNITO-MFA_OFF-01' 'D8 an OFF pool is reported by MFA_OFF'
assert_not_contains "$WEAK_POOL_IDS" 'CLOUD-COGNITO-MFA_OPTIONAL-01' 'D9 ... and NOT by MFA_OPTIONAL'
assert_contains "$OPT_IDS" 'CLOUD-COGNITO-ADVANCED_SECURITY_OFF-01' \
  'D10 an AUDIT-mode pool is reported: AUDIT computes a risk score and acts on none of it'

# The app clients.  Both directions again, in the same run, on the same pool.
WEAK_CLIENT_IDS=$(_ids_for "$TBL" "$WEAK_ARN" "$WEAK_CLIENT")
for want in CLOUD-COGNITO-CLIENT_PLAINTEXT_AUTH-01 CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01 \
  CLOUD-COGNITO-CLIENT_INSECURE_CALLBACK-01 CLOUD-COGNITO-CLIENT_WILDCARD_CALLBACK-01 \
  CLOUD-COGNITO-CLIENT_TOKEN_LIFETIME-01 CLOUD-COGNITO-CLIENT_TOKEN_REVOCATION_OFF-01 \
  CLOUD-COGNITO-CLIENT_WRITABLE_ATTRIBUTE-01 CLOUD-COGNITO-CLIENT_USER_EXISTENCE_ERRORS-01 \
  CLOUD-COGNITO-CLIENT_PUBLIC_CONFIDENTIAL_FLOW-01; do
  assert_contains "$WEAK_CLIENT_IDS" "$want" "D11 the misconfigured app client is reported by $want"
done
assert_eq '' "$(_ids_for "$TBL" "$WEAK_ARN" "$HARD_CLIENT")" \
  'D12 the hardened app client OF THE SAME POOL produces no finding at all'

# The identity pools, at all three severities of the escalation ladder.
OPEN_IDS=$(_ids_for "$TBL" "$OPEN_IDP_ARN")
assert_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01' 'D13 the open identity pool: anonymous identities'
assert_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01' 'D14 ... and an unauthenticated role really attached'
assert_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01' 'D15 ... whose inline policy is a full administrator'
assert_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01' 'D16 ... and the classic flow is on'
assert_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01' 'D17 ... and a role mapping falls back to the authenticated role'
assert_eq '' "$(_ids_for "$TBL" "$HARD_IDP_ARN")" \
  'D18 the hardened identity pool in the SAME run produces no finding at all'

# The BROAD pool is the second grade, and it must be the second id rather than
# the first.  The reading D20 fails under grades every wildcard as admin, which
# reports an s3:* grant at critical - and its mirror image, grading everything
# as service, understates a full administrator.
BROAD_IDS=$(_ids_for "$TBL" "$BROAD_IDP_ARN")
assert_contains "$BROAD_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01' \
  'D19 a service-wide wildcard on the unauthenticated role is the BROAD finding'
assert_not_contains "$BROAD_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01' \
  'D20 ... and NOT the ADMIN one'
assert_not_contains "$OPEN_IDS" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01' \
  'D21 ... while the full-administrator role is NOT also reported at the lower grade'
assert_not_contains "$BROAD_IDS" 'CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01' \
  'D22 the broad pool has the classic flow OFF and is not reported for it'

# ===========================================================================
# E. Citation: ARN, region, account, cell, sub_key - and the CIS column.
# ===========================================================================
t_case 'E. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F"$(printf '\037')" '$1 == "CLOUD-COGNITO-MFA_OFF-01" { print; exit }')
IFS=$'\x1f' read -r _e_id _e_arn _e_region _e_cell _e_cis _e_account _e_sub <<<"$_row"
assert_eq "$WEAK_ARN" "$_e_arn" 'E1 the finding cites the user pool ARN'
assert_eq '123456789012' "$_e_account" 'E2 the finding cites the account id'
assert_eq 'eu-west-2' "$_e_region" 'E3 the finding cites the region'

# THE CELL IS THE REGION'S, NOT `global`.  Cognito is a `regional` row, so a
# copy of s3.sh's `<account>/global` cell would file every finding in a cell no
# pass ever covers - tension 12 could then never classify one `fixed` and every
# remediated pool would sit at `unknown` forever.
assert_eq '123456789012/eu-west-2' "$_e_cell" 'E4 the cell is <account>/<region>, the cell this pass covered'
assert_not_contains "$_e_cell" 'global' 'E5 ... and specifically NOT <account>/global, which is the s3 row-s cell'

# THE CIS COLUMN IS EMPTY, DELIBERATELY, AND THIS ASSERTION IS THE PLACE THAT
# SAYS SO.  data/cis-mappings declares CIS AWS Foundations Benchmark v3.0.0,
# which has no Cognito section at all; citing 1.8 (the IAM ACCOUNT password
# policy) against an application user pool's policy, or 1.10 (MFA for IAM users
# with console access) against a pool's MFA setting, is the misattribution
# docs/CIS-MAPPINGS.md §5 item 5 forbids.  The invariant asserted in section G
# is the durable one: every `cis` value this module DOES author must resolve in
# the label table.
assert_eq '' "$_e_cis" 'E6 a cognito finding carries no CIS control id - v3.0.0 has no Cognito section'

# An app-client finding cites the POOL's real ARN with the client id in
# sub_key.  AWS defines no ARN for an app client, and loc_resource_key is a
# fingerprint component - so an invented `.../userpool/<pool>/client/<id>`
# would change every stored baseline the day someone noticed and removed it.
_row=$(printf '%s\n' "$TBL" | awk -F"$(printf '\037')" '$1 == "CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01" { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account _c_sub <<<"$_row"
assert_eq "$WEAK_ARN" "$_c_arn" 'E7 an app-client finding cites the USER POOL ARN, a real AWS identifier'
assert_eq "$WEAK_CLIENT" "$_c_sub" 'E8 ... with the client id in loc_sub_key'
assert_not_contains "$_c_arn" '/client/' 'E9 ... and never an invented app-client ARN'

# Two clients of one pool are TWO findings, because loc_sub_key is a
# fingerprint component.  Under one shared sub_key they would collide and
# findings_merge would keep whichever sorted first.
_nfp=$(python3 - "$W/run-d/findings.jsonl" <<'PY'
import json, sys
fps = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        fps.add(json.loads(line)['fingerprint'])
print(len(fps))
PY
)
_nf=$(grep -c . "$W/run-d/findings.jsonl")
assert_eq "$_nf" "$_nfp" 'E10 every finding in the run has a distinct fingerprint'

# ===========================================================================
# F. Honesty: what a denied call does, and what it must NOT claim.
# ===========================================================================
t_case 'F. honesty accounting'

CHECKS_RUN=$(_json "$W/run-d/run.json" checks_run)
for want in CLOUD-COGNITO-MFA_OFF-01 CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01 \
  CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01; do
  assert_contains "$CHECKS_RUN" "$want" "F1 a check that answered is recorded in checks_run ($want)"
done

# A denied `describe-user-pool` on ONE pool loses the pool checks for that pool
# and nothing else: the other pools still answer, so the checks stay credited
# AND the partial loss is recorded beside them.  Reporting only the first
# overstates coverage; reporting only the second suppresses a cell the run
# genuinely did visit.
_routes_default describe-user-pool
aws_fixture_route_add_for cognito-idp describe-user-pool "$WEAK_POOL"  "$FIX/describe-user-pool.denied.err"
aws_fixture_route_add_for cognito-idp describe-user-pool "$HARD_POOL"  "$FIX/describe-user-pool.hardened.json"
aws_fixture_route_add_for cognito-idp describe-user-pool "$OPT_POOL"   "$FIX/describe-user-pool.optional.json"
aws_fixture_route_add_for cognito-idp describe-user-pool "$NOPOL_POOL" "$FIX/describe-user-pool.nopolicy.json"
_run_cloud "$W/run-f1"
assert_eq '0' "$_RC" 'F2 a partially-denied run still exits 0'
RED=$(_json "$W/run-f1/run.json" coverage_reduction)
CR=$(_json "$W/run-f1/run.json" checks_run)
assert_contains "$RED" 'aws_api_access_denied' 'F3 the AccessDenied on one pool is a coverage_reduction'
assert_contains "$RED" 'operation=describe-user-pool' 'F4 ... naming the operation that was denied'
assert_contains "$CR" 'CLOUD-COGNITO-MFA_OFF-01' 'F5 ... while a check other pools answered stays credited'
TBL_F1=$(_findings_table "$W/run-f1/findings.jsonl")
# The assertion is on the POOL-LEVEL findings - the ones whose `loc_sub_key` is
# empty - and NOT on the pool ARN being absent from the table.  An app-client
# finding of this same pool carries the pool's ARN in `loc_resource_key` by
# design (AWS defines no app-client ARN, see section E), and those clients ARE
# still examined - so an "ARN absent" test asserts something the correct
# implementation does not do.  It was written that way first and failed against
# working code, which is the cheaper direction for this mistake to fail in.
assert_eq '' "$(_ids_for "$TBL_F1" "$WEAK_ARN" '')" \
  'F6 no user-pool finding is invented for the pool whose describe was denied'
# ... and the app clients of that pool are STILL examined, because they are
# reached through a different call.  The reading F7 fails under abandons the
# whole pool on a denied describe, turning one permission gap into nine more.
assert_contains "$TBL_F1" 'CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01' \
  'F7 ... but that pool-s app clients ARE still examined - list-user-pool-clients is a separate call'

# The two API NAMESPACES fail independently.  A denied `list-user-pools` must
# not be reported as having lost the identity-pool checks: they are reached
# through cognito-identity, a different service.  The reading F10 fails under
# marks all twenty-four checks lost, which hides that half the pass ran fine.
_routes_default list-user-pools
aws_fixture_route_add cognito-idp list-user-pools "$FIX/access-denied.err"
_run_cloud "$W/run-f2"
CR2=$(_json "$W/run-f2/run.json" checks_run)
RED2=$(_json "$W/run-f2/run.json" coverage_reduction)
GAP2=$(_json "$W/run-f2/run.json" coverage_gap)
assert_not_contains "$CR2" 'CLOUD-COGNITO-MFA_OFF-01' 'F8 a denied list-user-pools credits no user-pool check'
assert_not_contains "$CR2" 'CLOUD-COGNITO-CLIENT_' 'F9 ... and no app-client check either'
assert_contains "$CR2" 'CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01' \
  'F10 ... while the identity-pool checks, reached through a DIFFERENT service, are still credited'
assert_contains "$GAP2" 'user-pool list' 'F11 ... and the coverage_gap says the user-pool list could not be read'
assert_contains "$RED2" 'operation=list-user-pools' 'F12 ... with a machine-readable reduction naming the operation'
# The gap reaches report.md, the surface a consumer actually reads - not only
# run.json, which nobody opens.
assert_contains "$(cat "$W/run-f2/report.md")" 'user-pool list' \
  'F13 ... and it reaches report.md, not only run.json'

# The mirror image: a denied `list-identity-pools` loses the identity-pool
# checks and leaves the user-pool half credited.
_routes_default list-identity-pools
aws_fixture_route_add cognito-identity list-identity-pools "$FIX/access-denied.err"
_run_cloud "$W/run-f3"
CR3=$(_json "$W/run-f3/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-COGNITO-IDPOOL_' 'F14 a denied list-identity-pools credits no identity-pool check'
assert_contains "$CR3" 'CLOUD-COGNITO-MFA_OFF-01' 'F15 ... while the user-pool half is unaffected'

# A ROLE WITH NO POLICY AT ALL IS AN ANSWER, NOT A LOSS.  The question "is this
# anonymous role over-permissive" has the answer "it grants nothing", so the
# two role checks are covered and stay quiet.  The reading F17 fails under
# treats an empty policy list as an unexamined role, which would leave a prior
# finding at `unknown` forever after an operator emptied the role - the correct
# remediation.
_routes_default iam
aws_fixture_route_add iam list-role-policies "$FIX/iam.list-role-policies.empty.json"
aws_fixture_route_add iam list-attached-role-policies "$FIX/iam.list-attached-role-policies.empty.json"
_run_cloud "$W/run-f4"
CR4=$(_json "$W/run-f4/run.json" checks_run)
TBL4=$(_findings_table "$W/run-f4/findings.jsonl")
assert_contains "$CR4" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01' \
  'F16 a role with no attached policy COVERS the over-permissiveness checks'
assert_not_contains "$TBL4" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_' 'F17 ... and reports neither of them'
# ... while the pool that has the role still gets the credentials finding,
# which is about the role EXISTING rather than about what it grants.
assert_contains "$TBL4" 'CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01' \
  'F18 ... and the anonymous-credentials finding, which is a different question, still fires'

# The conditioned-statement carve-out is DECLARED, not silent.  A limit that
# only ever appears as an absence is a limit nobody learns about.
assert_contains "$(_json "$W/run-d/run.json" coverage_reduction)" 'cognito_conditioned_statement_not_assessed' \
  'F19 a wildcard statement carrying a Condition is recorded as a stated limit'

# ===========================================================================
# G. Round-trip: coverage cell, state, every report format, and the registry.
# ===========================================================================
t_case 'G. round-trip'

RUNJSON=$W/run-d/run.json
assert_contains "$(_json "$RUNJSON" regions)" 'eu-west-2' 'G1 run.json names the region the run resolved'
assert_eq '123456789012' "$(_json "$RUNJSON" cloud.account_id)" 'G2 run.json records the scanned account'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'G3 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'G4 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-COGNITO-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-COGNITO-MFA_OFF-01 account-region 123456789012/eu-west-2' \
  'G5 the run wrote a REAL per-region account-region coverage cell'
assert_not_contains "$COVER" '123456789012/global' \
  'G6 coverage is credited to the region the pass visited, never to the global cell'

assert_file_exists "$W/run-d/report.md" 'G7 report.md written'
assert_file_exists "$W/run-d/report.html" 'G8 report.html written'
assert_contains "$(cat "$W/run-d/report.md")" "$WEAK_ARN" 'G9 report.md names the user pool ARN'

assert_file_exists "$W/run-d/report.sarif" 'G10 the same run also wrote report.sarif'
_SARIF=$(cat "$W/run-d/report.sarif")
assert_contains "$_SARIF" 'CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01' 'G11 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$OPEN_IDP_ARN" 'G12 the SARIF result names the identity pool ARN'

# THE DURABLE CIS INVARIANT.  Section E asserts that cognito authors no `cis`
# value today; this asserts the rule that outlives that decision - every `cis`
# value ANY check under modules/cloud/ authors must resolve to a row in
# data/cis-mappings.  A future ticket that adds a Cognito control number
# without transcribing its label (docs/CIS-MAPPINGS.md §5) fails here rather
# than shipping a finding whose control expands to nothing.
_CIS_UNKNOWN=$(python3 - "$ROOT" <<'PYCIS'
import os, re, sys
root = sys.argv[1]
known = set()
for line in open(os.path.join(root, 'data', 'cis-mappings')):
    if line.startswith('id: '):
        known.add(line[4:].strip())
bad = []
for dirpath, _dirs, files in os.walk(os.path.join(root, 'modules', 'cloud')):
    for name in files:
        if not name.endswith('.rules'):
            continue
        path = os.path.join(dirpath, name)
        for line in open(path):
            if line.startswith('cis: '):
                v = line[5:].strip()
                if v not in known:
                    bad.append('%s: %s' % (os.path.relpath(path, root), v))
print('\n'.join(bad))
PYCIS
)
assert_eq '' "$_CIS_UNKNOWN" \
  'G13 every cis value authored under modules/cloud/ resolves in data/cis-mappings'

# The registry and the script agree on which ids exist.  A record with no
# emitter is a check that can never fire and an emitter with no record is an
# exit-3 internal error at runtime - both are silent until someone looks.
_REG_IDS=$(grep '^id: CLOUD-COGNITO-' "$ROOT/modules/cloud/aws/live/checks-cognito.rules" \
  | sed 's/^id: //' | LC_ALL=C sort)
_SCRIPT_IDS=$(grep -oE 'CLOUD-COGNITO-[A-Z0-9_]+-01' "$ROOT/modules/cloud/aws/live/cognito.sh" \
  | LC_ALL=C sort -u)
assert_eq "$_REG_IDS" "$_SCRIPT_IDS" \
  'G14 the registry ids and the ids the pass names are exactly the same set'
assert_eq '24' "$(printf '%s\n' "$_REG_IDS" | grep -c .)" 'G15 the pack ships 24 check ids'

t_summary cloud-cognito
