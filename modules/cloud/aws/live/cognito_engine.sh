#!/usr/bin/env bash
# modules/cloud/aws/live/cognito_engine.sh - the pure half of the §8.3 Cognito
# read-only service (docs/DESIGN.md §8.3; docs/STEP6-CLOUD-PLAN.md CLOUD-20).
#
# The `live/<service>_engine.sh` + `live/<service>.sh` split
# modules/cloud/aws/live/s3_engine.sh established for step 6, applied verbatim:
# this file is a pure function library with the standard sourced-once guard and
# no side effect at source time, and modules/cloud/aws/live/cognito.sh is the
# file that DOES something when `cloud_run_service` sources it.  Nothing here
# calls `aws_ro`, reads the run context or emits anything by itself; every
# function takes a response document (or a string) and answers one question
# about it, which is what lets tests/suites/cloud-cognito.sh exercise the
# classifiers against committed fixtures with no scan, no stub and no run
# directory.
#
# ONE SERVICE SCRIPT, TWO AWS API NAMESPACES, AND THAT IS §8.3'S OWN WORDING.
# `cognito-idp` (user pools and their app clients) and `cognito-identity`
# (identity pools) are separate CLI services, and §8.3's first line puts both
# under one script: "Uses `cognito-idp` + `cognito-identity`".  They are one
# check surface because an identity pool's whole purpose is to exchange a user
# pool's token for AWS credentials - splitting them into two service rows would
# put the two halves of one exposure chain in two passes that cannot see each
# other.  A THIRD namespace, `iam`, is reached for exactly one purpose: reading
# the policies attached to an identity pool's UNAUTHENTICATED role, which
# §8.3's identity-pool bullet requires be inspected "for over-permissiveness
# ... as its own high-severity finding, not a note".
#
# WHY THE CLASSIFIERS ARE HERE AND NOT IN modules/cloud/aws/engine.sh: that
# file is the MODULE's shared library (the service table, the cell, the JSON
# reader, the one door into a service script) and every one of §8.1's thirty
# services sources it.  A classifier that knows what a Cognito
# `AmbiguousRoleResolution` value means belongs to Cognito and to nothing else,
# and putting it there would grow a file every service sources into the union
# of thirty services' response formats.
#
# EVERY CLASSIFIER IS CONFIG-DERIVED AND SENDS NOTHING, which is §8.3's closing
# instruction rather than an implementation preference: "Prefer config-derived
# detection of user-enumeration and self-signup over live endpoint probing -
# active probing creates real users and fires verification email/SMS."  Nothing
# in this file or in cognito.sh calls `SignUp`, `ForgotPassword`,
# `InitiateAuth` or `GetCredentialsForIdentity`; every answer is read out of a
# `describe-*`/`list-*`/`get-*` response.  A future ticket that wants the live
# probe needs `--allow-intrusive` and an `intrusive` type tag, and it is a
# DIFFERENT check id - not a widening of one of these.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_COGNITO_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_COGNITO_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` /
# `cloud_json_unescape` and is ALREADY SOURCED in every real run - regions.sh
# sources it before the service walk begins - so this is reached only by a
# direct-engine test.  The guard is what makes both true at once.
#
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is reached,
# and `shellcheck -x` re-expands EVERY source edge it follows rather than
# memoising - see tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's "the
# memory model".  A direct-engine test suite sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, NEVER a bare `declare`, on every global this file introduces,
# for the reason modules/cloud/aws/engine.sh's own service table documents at
# length: in a real run NOTHING sources this file at top level.
# `cloud_run_service` is a FUNCTION and reaches a service script by running
# `source` from inside itself, so every line here executes in that function's
# scope, where a bare `declare -A` creates a LOCAL that dies with the first
# service pass.  A plain assignment (the sourced-once guard above) IS global
# and DOES survive, which is why that one line needs no `-g`.  The same rule
# rules out `readonly` for the constants below - `readonly` is `declare -r`, so
# inside a function it is local too.
declare -gA _CG_DOC=()
declare -gA _CG_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `cognito_doc_load FILE` - flatten FILE once into `_CG_DOC` (path -> unescaped
# scalar) and `_CG_DOCT` (path -> `s`/`n`/`b`/`z` type), both keyed by
# `cloud_json_flatten`'s US-joined path.  Returns 1 and leaves both EMPTY when
# the document does not parse or the file is unreadable.
#
# The same shape, and for the same two reasons, as s3_engine.sh's
# `s3_doc_load`: re-flattening per lookup costs a full parse per leaf (a
# `describe-user-pool` response is read by nine separate checks here), and an
# ARRAY - `ExplicitAuthFlows`, `CallbackURLs`, `RecoveryMechanisms`,
# `Statement` - cannot be read leaf-by-leaf at all without already knowing how
# many entries it has.
#
# THE TYPE MAP IS NOT AN OPTIONAL EXTRA HERE EITHER, and Cognito gives it more
# work than S3 did.  `"AllowUnauthenticatedIdentities": false` (a real answer:
# the pool is configured and anonymous identities are off) and an absent key (a
# response shape this parser did not expect, or a field the account's API
# version does not return) both read as the empty string, and only the type map
# separates them.  Reporting the second as the first is the direction that
# reads as a clean identity pool.
cognito_doc_load() {
  local file=$1
  _CG_DOC=()
  _CG_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell: a
  # `cloud_json_flatten <"$f" | while ...` loop runs its body in a subshell and
  # every key it stored is discarded when that subshell exits, leaving an empty
  # map and a check that reports every pool clean.  This codebase's standing
  # subshell lesson (lib/core.sh's `worker_id_set`), in its loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _CG_DOC[$path]=$val
    _CG_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `cognito_path P...` - join path segments with the US byte
# `cloud_json_flatten` uses.  A function rather than an inline `$'\x1f'` at each
# call site: the separator is the module engine's published contract, and
# thirty service scripts each spelling a control byte by hand is thirty chances
# to spell it wrong.
cognito_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# `cognito_doc_has PATH` / `cognito_doc_get VARNAME PATH` - membership and read.
# `cognito_doc_get` SETS rather than prints, this codebase's standing
# convention for anything a caller reads in a loop.
cognito_doc_has() {
  [[ -n ${_CG_DOCT[$1]+set} ]]
}

cognito_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_CG_DOC[$__path]:-}"
  [[ -n ${_CG_DOCT[$__path]+set} ]]
}

# `cognito_list_set VARNAME PATH...` - the values of the JSON array at PATH, one
# per line, in document order.  Empty output means the array is absent or empty,
# and the two are distinguished by `cognito_doc_has` on index 0 where a caller
# needs to tell them apart.
#
# THE WALK ENDS AT THE FIRST ABSENT INDEX, WHICH IS CORRECT ONLY BECAUSE A JSON
# ARRAY IS DENSE.  `cloud_json_flatten` emits `<path><US><index>` for every
# element it saw, with no gaps, so index N being absent means the array had N
# elements.  A sparse map keyed by something other than a contiguous index
# would need a different walk; nothing Cognito returns is one.
cognito_list_set() {
  local __var=$1
  shift
  local __base __i=0 __out='' __p
  __base=$(cognito_path "$@")
  while :; do
    __p=$__base$'\x1f'$__i
    cognito_doc_has "$__p" || break
    __out+="${__out:+$'\n'}${_CG_DOC[$__p]:-}"
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `cognito_list_contains LIST VALUE` - whole-line membership in a newline-
# separated list, never a substring test.
#
# WHOLE-LINE, AND THE SUBSTRING READING IS A REAL DEFECT HERE RATHER THAN A
# THEORETICAL ONE.  `ALLOW_USER_PASSWORD_AUTH` is a SUBSTRING of
# `ALLOW_ADMIN_USER_PASSWORD_AUTH`, so a `*"$v"*` test would report a client
# that permits only the admin flow as permitting the public one, citing a flow
# the client does not have.  It also fails in the other direction on the OAuth
# flow list, where `code` is a substring of nothing but would match a future
# value that contained it.
cognito_list_contains() {
  local list=$1 want=$2
  [[ $'\n'"$list"$'\n' == *$'\n'"$want"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 2. ARNs
# ---------------------------------------------------------------------------
# `cognito_partition_of CALLER_ARN` - the ARN partition (`aws`, `aws-cn`,
# `aws-us-gov`) read out of the caller identity's own ARN, defaulting to `aws`.
#
# READ, NEVER HARDCODED, for s3_engine.sh's own reason: a user pool ARN in
# GovCloud is `arn:aws-us-gov:cognito-idp:...` and in China
# `arn:aws-cn:cognito-idp:...`, and a finding citing `arn:aws:...` in either
# partition names a resource that does not exist - an operator pasting it into
# a console or a policy gets silence rather than an error.  The caller ARN is a
# fact this run already resolved (`sts get-caller-identity`,
# modules/cloud/aws/run.sh), so there is nothing to guess.
cognito_partition_of() {
  local arn=${1:-} rest part
  case $arn in
    arn:*)
      rest=${arn#arn:}
      part=${rest%%:*}
      [[ -n $part ]] && { printf '%s' "$part"; return 0; }
      ;;
  esac
  printf '%s' aws
}

# `cognito_user_pool_arn PARTITION REGION ACCOUNT POOL_ID` -
# `arn:<partition>:cognito-idp:<region>:<account>:userpool/<pool id>`.
#
# CONSTRUCTED ONLY AS A FALLBACK.  `describe-user-pool` returns the pool's own
# `Arn` on every current API version, and cognito.sh prefers it; this builder
# is what covers a response that omits it.  Preferring the API's own value
# matters because `loc_resource_key` is a fingerprint component (tension 5), so
# a constructed ARN that ever disagreed with the real one by a byte would give
# the same pool two identities across the day the disagreement was fixed.
cognito_user_pool_arn() {
  printf 'arn:%s:cognito-idp:%s:%s:userpool/%s' "$1" "$2" "$3" "$4"
}

# `cognito_identity_pool_arn PARTITION REGION ACCOUNT POOL_ID` -
# `arn:<partition>:cognito-identity:<region>:<account>:identitypool/<pool id>`.
#
# ALWAYS CONSTRUCTED, because `describe-identity-pool` returns no ARN at all -
# an identity pool is addressed by its `IdentityPoolId` everywhere in the API.
# The ARN format itself is AWS's published one for the resource type, so this
# is a spelling of a real identifier rather than an invented one.
cognito_identity_pool_arn() {
  printf 'arn:%s:cognito-identity:%s:%s:identitypool/%s' "$1" "$2" "$3" "$4"
}

# `cognito_role_name_of ROLE_ARN` - the role NAME an IAM role ARN carries,
# which is what every `iam` operation takes as `--role-name`.
#
# THE NAME IS EVERYTHING AFTER THE LAST `/`, NEVER AFTER THE FIRST.  A role in
# a path - `arn:aws:iam::123456789012:role/service-role/Cognito_poolUnauth` -
# is the ordinary shape for a role the Cognito console created, and splitting
# on the first `/` yields `service-role`, a name that does not exist.  Every
# subsequent `iam` call then returns NoSuchEntity, which this module correctly
# reports as `not_found` - so the unauthenticated role's policies read as
# absent and the over-permissiveness check reports the pool clean.  A silent
# false negative on precisely the check §8.3 says must be high-severity.
cognito_role_name_of() {
  local arn=${1:-}
  [[ $arn == *'/'* ]] || { printf '%s' "$arn"; return 0; }
  printf '%s' "${arn##*/}"
}

# ---------------------------------------------------------------------------
# 3. User-pool classifiers
# ---------------------------------------------------------------------------
# Every function in this section reads a `describe-user-pool` document already
# loaded by `cognito_doc_load`.  The response envelope is `UserPool`, so every
# path below starts there.
declare -g COGNITO_POOL_ROOT='UserPool'

# `cognito_pool_password_weaknesses_set VARNAME` - the space-separated names of
# the password-policy weaknesses this pool carries, empty when the policy meets
# the baseline.  Vocabulary: `min_length_lt_8`, `no_uppercase`, `no_lowercase`,
# `no_numbers`, `no_symbols`.
#
# THE THRESHOLD IS 8 AND IT IS §8.3'S OWN NUMBER ("min length `< 8`"), not a
# figure chosen here.  It is deliberately NOT 14, the number CIS control 1.8
# names: that control is about the IAM account password policy, which governs
# IAM PRINCIPALS with console access to the AWS account, and a Cognito user
# pool governs an APPLICATION'S END USERS.  Citing an IAM-user control against
# an application's sign-in policy would misattribute the finding, which
# docs/CIS-MAPPINGS.md §5 item 5 forbids in terms - see this check's registry
# record for why it cites no CIS control at all.
#
# AN ABSENT `PasswordPolicy` IS NOT A WEAKNESS AND IS REPORTED AS ITS OWN
# STATE, via the return status.  Cognito applies a documented default policy
# (8 characters, all four character classes required) when a pool sets none,
# so a pool with no `Policies.PasswordPolicy` object is at that default rather
# than at nothing - and listing five weaknesses for it would be five false
# positives on the safest possible configuration.  The caller distinguishes
# them: return 0 means a policy was present and was read, return 1 means there
# was none to read.
#
# AN ABSENT `Require*` FLAG INSIDE A PRESENT POLICY IS THE OPPOSITE CASE AND IS
# A WEAKNESS.  The API returns all four booleans on a policy it has, and an
# omitted one is `false` by the API's own default - the identical "an absent
# key is a gap, not a pass" rule s3_engine.sh's `s3_bpa_gaps_set` records.
cognito_pool_password_weaknesses_set() {
  local __var=$1 __out='' __p __v __min __key
  printf -v "$__var" '%s' ''
  __p=$(cognito_path "$COGNITO_POOL_ROOT" Policies PasswordPolicy)
  cognito_doc_has "$__p"$'\x1f'MinimumLength \
    || cognito_doc_has "$__p"$'\x1f'RequireUppercase \
    || cognito_doc_has "$__p"$'\x1f'RequireLowercase \
    || cognito_doc_has "$__p"$'\x1f'RequireNumbers \
    || cognito_doc_has "$__p"$'\x1f'RequireSymbols \
    || return 1

  __key=$__p$'\x1f'MinimumLength
  __min=${_CG_DOC[$__key]:-}
  # A non-numeric or absent MinimumLength is NOT read as 0: that would report
  # `min_length_lt_8` for a document whose length field this parser failed on,
  # which is a finding invented out of a parse failure.
  if [[ $__min =~ ^[0-9]+$ ]] && (( __min < 8 )); then
    __out+="${__out:+ }min_length_lt_8"
  fi
  # The path is built into a plain variable before the array read: an
  # associative-array subscript carrying its own `${var%%:*}` expansion parses,
  # but it is exactly the spelling a later edit gets subtly wrong, and a
  # mis-built subscript here reads as "the flag is not true" - so every policy
  # would report all four complexity weaknesses, on the safest configuration.
  for __v in Uppercase:no_uppercase Lowercase:no_lowercase \
    Numbers:no_numbers Symbols:no_symbols; do
    __key=$__p$'\x1f'Require${__v%%:*}
    [[ ${_CG_DOC[$__key]:-} == true ]] || __out+="${__out:+ }${__v#*:}"
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `cognito_pool_temp_password_days_set VARNAME` - the pool's
# `TemporaryPasswordValidityDays`, and true when it EXCEEDS the baseline.
#
# THE BASELINE IS 7 DAYS, which is Cognito's own documented default for a pool
# that sets none.  A pool that has not raised it is therefore never reported,
# and the check fires only where an operator deliberately widened the window in
# which an administratively-created password stays usable.  A longer window is
# a longer period in which a password sitting in an email inbox - the channel
# it was almost certainly delivered over - is still a working credential.
cognito_pool_temp_password_days_set() {
  local __var=$1 __p __v
  __p=$(cognito_path "$COGNITO_POOL_ROOT" Policies PasswordPolicy TemporaryPasswordValidityDays)
  __v=${_CG_DOC[$__p]:-}
  printf -v "$__var" '%s' "$__v"
  [[ $__v =~ ^[0-9]+$ ]] || return 1
  (( __v > 7 ))
}

# `cognito_pool_mfa_set VARNAME` - the pool's `MfaConfiguration`, normalised to
# one of `ON`, `OPTIONAL`, `OFF`.  Returns 0 when it is `ON`.
#
# AN ABSENT VALUE IS `OFF`, not unknown: the field is returned on every
# `describe-user-pool` response and its absence in practice means the pool has
# never had MFA configured.  Reporting the absence as "unknown, no finding"
# would silence the check on exactly the pools that never turned MFA on.
cognito_pool_mfa_set() {
  local __var=$1 __v
  __v=${_CG_DOC[$(cognito_path "$COGNITO_POOL_ROOT" MfaConfiguration)]:-}
  case $__v in
    ON | OPTIONAL) : ;;
    *) __v=OFF ;;
  esac
  printf -v "$__var" '%s' "$__v"
  [[ $__v == ON ]]
}

# `cognito_pool_advanced_security_set VARNAME` - the pool's
# `UserPoolAddOns.AdvancedSecurityMode`, normalised to `ENFORCED`, `AUDIT` or
# `OFF`.  Returns 0 when it is `ENFORCED`.
#
# `AUDIT` IS NOT A PASS AND THAT IS THE WHOLE POINT OF THE THREE-VALUE
# VOCABULARY.  In `AUDIT` mode Cognito computes a risk score for every sign-in
# and publishes it - and takes no action on it, so a sign-in from a
# known-compromised credential succeeds exactly as it would with the feature
# off.  Treating it as configured would report every audit-only pool as having
# adaptive authentication, which is the direction that reads as a control being
# present.  The finding's evidence names which of the two it saw, because the
# remediation differs: `OFF` needs the feature turned on at all, `AUDIT` needs
# one setting changed.
cognito_pool_advanced_security_set() {
  local __var=$1 __v
  __v=${_CG_DOC[$(cognito_path "$COGNITO_POOL_ROOT" UserPoolAddOns AdvancedSecurityMode)]:-}
  case $__v in
    ENFORCED | AUDIT) : ;;
    *) __v=OFF ;;
  esac
  printf -v "$__var" '%s' "$__v"
  [[ $__v == ENFORCED ]]
}

# `cognito_pool_self_registration_open` - true when this pool permits
# self-service sign-up, that is when
# `AdminCreateUserConfig.AllowAdminCreateUserOnly` is not `true`.
#
# THE POLARITY IS INVERTED AND THAT IS THE TRAP.  The field is
# `AllowAdminCreateUserOnly`, so `false` (or absent - the API default for a
# pool created without the option) is the OPEN case and `true` is the closed
# one.  A classifier written as `[[ $v == true ]]` reports every locked-down
# pool as open and every open pool as locked down, which passes any test whose
# fixtures happen to be the wrong way round too.
#
# THIS IS THE CONFIG-DERIVED HALF OF §8.3'S "SignUp enabled" BULLET, and it is
# derived rather than probed for the reason that section's closing paragraph
# gives: calling `SignUp` to find out creates a real user in the operator's own
# pool and fires a verification email or SMS to whatever address the probe
# invented.
cognito_pool_self_registration_open() {
  local p
  p=$(cognito_path "$COGNITO_POOL_ROOT" AdminCreateUserConfig AllowAdminCreateUserOnly)
  [[ ${_CG_DOC[$p]:-} != true ]]
}

# `cognito_pool_recovery_set VARNAME` - the pool's account-recovery mechanisms,
# comma-joined in PRIORITY ORDER, and true when the highest-priority mechanism
# is not a phone/SMS one.
#
# SIM SWAP IS THE THREAT AND PRIORITY IS WHAT DECIDES IT.  A pool that lists
# `verified_phone_number` at priority 1 sends the recovery code by SMS first,
# so an attacker who has ported the victim's number owns the account regardless
# of what mechanism sits at priority 2.  A pool that lists `verified_email`
# first and phone second is materially different, and reporting both would flag
# the ordinary, reasonable configuration.  So the test is on the FIRST
# mechanism, not on membership.
#
# `admin_only` IS A PASS.  It means there is no self-service recovery at all -
# a support process, not a weaker channel.
cognito_pool_recovery_set() {
  local __var=$1 __base __i=0 __out='' __name __prio
  local __best_prio='' __best_name=''
  __base=$(cognito_path "$COGNITO_POOL_ROOT" AccountRecoverySetting RecoveryMechanisms)
  while :; do
    cognito_doc_has "$__base"$'\x1f'"$__i"$'\x1f'Name || break
    __name=${_CG_DOC[$__base$'\x1f'$__i$'\x1f'Name]:-}
    __prio=${_CG_DOC[$__base$'\x1f'$__i$'\x1f'Priority]:-}
    [[ $__prio =~ ^[0-9]+$ ]] || __prio=99
    __out+="${__out:+,}$__name(priority $__prio)"
    if [[ -z $__best_prio ]] || (( __prio < __best_prio )); then
      __best_prio=$__prio
      __best_name=$__name
    fi
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  # No recovery setting at all: Cognito's own default is verified_email first,
  # so an absent block is not the SMS-first case and must not fire.
  [[ -n $__best_name ]] || return 1
  [[ $__best_name == verified_phone_number || $__best_name == phone_number ]]
}

# `cognito_pool_deletion_protection_off` - true when `DeletionProtection` is
# anything other than `ACTIVE`.  Absent counts as off: the field defaults to
# `INACTIVE` on a pool created before it existed, which is the ordinary shape
# for an established estate and is exactly the population this check is for.
cognito_pool_deletion_protection_off() {
  [[ ${_CG_DOC[$(cognito_path "$COGNITO_POOL_ROOT" DeletionProtection)]:-} != ACTIVE ]]
}

# `cognito_pool_self_service_surface_set VARNAME` - a comma-separated list of
# the UNAUTHENTICATED self-service operations this pool's configuration
# exposes, derived entirely from the `describe-user-pool` response.  Returns 0
# when the list is non-empty.
#
# THIS IS §8.3'S FOURTH CHECK GROUP - "Unauthenticated user-pool API surface
# (config-derived; report which self-service operations are exposed)" - and it
# is informational by design.  Every one of these operations is a legitimate
# feature that a great many applications intend to expose; the finding's value
# is that an operator can see, in one place, which anonymous entry points their
# pool actually has, and compare that against what the application is supposed
# to offer.  Making it a warning would flag every consumer-facing application
# in existence, which is the false-positive flood this module's honesty rules
# exist to avoid.
#
# WHAT IS DERIVED, AND FROM WHAT:
#   SignUp                 `AdminCreateUserConfig.AllowAdminCreateUserOnly` is
#                          not true, so anyone may create an account.
#   ForgotPassword         the pool has at least one non-`admin_only` recovery
#                          mechanism, so the self-service reset flow is
#                          reachable.  §8.3's own bullet.
#   ResendConfirmationCode  self-registration is open AND at least one
#                          attribute is auto-verified, which is what makes an
#                          unconfirmed user - and therefore that operation -
#                          possible at all.
#
# NOTHING HERE IS PROBED.  §8.3's closing paragraph and the ticket both say so:
# calling ForgotPassword to find out whether it answers sends a real password
# reset to a real user's real inbox, and calling it for an address that does
# not exist is the user-enumeration test §7.4 owns under `--allow-intrusive`.
cognito_pool_self_service_surface_set() {
  local __var=$1 __out='' __rec='' __i=0 __base __name __any_recovery=0 __verified=''
  if cognito_pool_self_registration_open; then
    __out+="${__out:+,}SignUp"
  fi
  __base=$(cognito_path "$COGNITO_POOL_ROOT" AccountRecoverySetting RecoveryMechanisms)
  while :; do
    cognito_doc_has "$__base"$'\x1f'"$__i"$'\x1f'Name || break
    __name=${_CG_DOC[$__base$'\x1f'$__i$'\x1f'Name]:-}
    [[ $__name == admin_only ]] || __any_recovery=1
    __i=$(( __i + 1 ))
  done
  # No AccountRecoverySetting at all means the pool is on Cognito's own default,
  # which IS a self-service email reset - so the surface is present, not absent.
  (( __i == 0 )) && __any_recovery=1
  (( __any_recovery )) && __out+="${__out:+,}ForgotPassword"

  cognito_list_set __verified "$COGNITO_POOL_ROOT" AutoVerifiedAttributes
  if [[ -n $__verified ]] && cognito_pool_self_registration_open; then
    __out+="${__out:+,}ResendConfirmationCode"
  fi
  __rec=$__out
  printf -v "$__var" '%s' "$__rec"
  [[ -n $__rec ]]
}

# ---------------------------------------------------------------------------
# 4. App-client classifiers
# ---------------------------------------------------------------------------
# Every function in this section reads a `describe-user-pool-client` document
# already loaded by `cognito_doc_load`.  The response envelope is
# `UserPoolClient`.
declare -g COGNITO_CLIENT_ROOT='UserPoolClient'

# The authentication flows that carry a password in the clear to Cognito rather
# than proving knowledge of it through SRP.  Compared as WHOLE VALUES through
# `cognito_list_contains`, never as substrings - `ALLOW_USER_PASSWORD_AUTH` is
# a substring of `ALLOW_ADMIN_USER_PASSWORD_AUTH`.
#
# ALL FOUR SPELLINGS ARE LISTED BECAUSE ALL FOUR ARE RETURNED IN PRACTICE.  The
# `ALLOW_`-prefixed names are the current API's; the bare `USER_PASSWORD_AUTH`,
# `ADMIN_NO_SRP_AUTH` and `CUSTOM_AUTH_FLOW_ONLY` spellings are the legacy ones
# a client created before the rename still reports, and §8.3 names the legacy
# case explicitly ("or legacy `USER_PASSWORD_AUTH`").  A list carrying only the
# modern spellings reports every long-lived client clean, which is the
# population most likely to have the problem.
declare -g COGNITO_PLAINTEXT_AUTH_FLOWS='ALLOW_USER_PASSWORD_AUTH
ALLOW_ADMIN_USER_PASSWORD_AUTH
USER_PASSWORD_AUTH
ADMIN_NO_SRP_AUTH'

# The Cognito app-client attributes whose value is a SECURITY DECISION rather
# than a user preference.  A client that may WRITE one of these can assert its
# own verification state, which is a privilege escalation wherever the
# application - or a Cognito trigger, or a downstream authorizer - trusts the
# claim.
declare -g COGNITO_SENSITIVE_WRITE_ATTRIBUTES='email_verified
phone_number_verified'

# `cognito_client_plaintext_flows_set VARNAME` - the plaintext/non-SRP
# authentication flows this client permits, newline-separated, empty when it
# permits none.  Returns 0 when at least one was found.
cognito_client_plaintext_flows_set() {
  local __var=$1 __flows='' __f='' __out=''
  cognito_list_set __flows "$COGNITO_CLIENT_ROOT" ExplicitAuthFlows
  while IFS= read -r __f; do
    [[ -n $__f ]] || continue
    cognito_list_contains "$__flows" "$__f" && __out+="${__out:+$'\n'}$__f"
  done <<<"$COGNITO_PLAINTEXT_AUTH_FLOWS"
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `cognito_client_implicit_oauth` - true when this client's
# `AllowedOAuthFlows` contains `implicit`.
#
# THE FLOW LIST IS ONLY MEANINGFUL WHEN THE HOSTED UI IS ON, and that is
# checked rather than assumed: `AllowedOAuthFlowsUserPoolClient` false means
# Cognito refuses the OAuth endpoints for this client entirely, so a stale
# `implicit` left in the flow list authorises nothing.  Firing on the list
# alone reports a client whose OAuth surface is switched off, which is a
# finding an operator cannot act on and will learn to ignore.
cognito_client_implicit_oauth() {
  local flows=''
  [[ ${_CG_DOC[$(cognito_path "$COGNITO_CLIENT_ROOT" AllowedOAuthFlowsUserPoolClient)]:-} == true ]] \
    || return 1
  cognito_list_set flows "$COGNITO_CLIENT_ROOT" AllowedOAuthFlows
  cognito_list_contains "$flows" implicit
}

# `cognito_client_insecure_urls_set VARNAME` - the client's callback and logout
# URLs that are served over PLAINTEXT HTTP, newline-separated as
# `<kind> <url>`.  Returns 0 when at least one was found.
#
# `http://localhost` AND `http://127.0.0.1` ARE EXCLUDED, DELIBERATELY.  A
# loopback redirect URI is the one plaintext case OAuth 2.0 for Native Apps
# (RFC 8252 §7.3) explicitly endorses, because the redirect never leaves the
# user's own machine and no network path exists to intercept it - and Cognito
# itself permits `http://localhost` for exactly that reason while rejecting
# every other `http://` URL at the console.  Flagging it would put a finding on
# the development configuration of nearly every mobile and desktop client,
# which is the false-positive flood that gets a check switched off.  Only the
# HOST is examined for the exclusion, so `http://localhost.attacker.example`
# is NOT loopback and IS reported.
cognito_client_insecure_urls_set() {
  local __var=$1 __out='' __kind __urls='' __u __host
  for __kind in CallbackURLs LogoutURLs; do
    cognito_list_set __urls "$COGNITO_CLIENT_ROOT" "$__kind"
    while IFS= read -r __u; do
      [[ -n $__u ]] || continue
      [[ $__u == http://* ]] || continue
      __host=${__u#http://}
      __host=${__host%%/*}
      __host=${__host%%:*}
      case $__host in
        localhost | 127.0.0.1 | '[::1]' | ::1) continue ;;
      esac
      __out+="${__out:+$'\n'}${__kind%URLs} $__u"
    done <<<"$__urls"
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `cognito_client_wildcard_urls_set VARNAME` - the client's callback and logout
# URLs that are WILDCARDED or otherwise not a single concrete destination,
# newline-separated as `<kind> <url>`.  Returns 0 when at least one was found.
#
# THREE SHAPES, AND EACH IS A DIFFERENT WAY TO END UP WITH THE SAME EXPOSURE -
# an authorization code or a token delivered to a host the operator did not
# choose:
#   a literal `*` anywhere in the URL   - a wildcard host or path.
#   a bare scheme-and-wildcard host     - `https://*.example.com`, which admits
#                                         every subdomain including one an
#                                         attacker got hold of.
#   a URL with no host at all           - `https:///cb` or a value that is not
#                                         a URL, which Cognito will not match
#                                         the way the operator expects.
#
# Cognito's own console refuses a wildcard callback URL today, so a client
# carrying one was created through the API or predates that validation - which
# makes this a check about the long-lived clients an estate has forgotten,
# exactly the population an audit exists to find.
cognito_client_wildcard_urls_set() {
  local __var=$1 __out='' __kind __urls='' __u __rest __host
  for __kind in CallbackURLs LogoutURLs; do
    cognito_list_set __urls "$COGNITO_CLIENT_ROOT" "$__kind"
    while IFS= read -r __u; do
      [[ -n $__u ]] || continue
      if [[ $__u == *'*'* ]]; then
        __out+="${__out:+$'\n'}${__kind%URLs} $__u"
        continue
      fi
      # A URL whose authority is empty names no destination.  Split on `://`
      # rather than on `//` so a path containing `//` cannot be mistaken for
      # the scheme separator.
      [[ $__u == *'://'* ]] || continue
      __rest=${__u#*://}
      __host=${__rest%%/*}
      [[ -n $__host ]] && continue
      __out+="${__out:+$'\n'}${__kind%URLs} $__u"
    done <<<"$__urls"
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `cognito_token_seconds_set VARNAME KIND` - the configured validity of KIND
# (`AccessToken`, `IdToken` or `RefreshToken`) in SECONDS, over the loaded
# client document.  Returns 1 - and sets VARNAME empty - when the client
# configures none.
#
# AN UNCONFIGURED VALIDITY IS NOT ZERO AND MUST NOT BE READ AS ONE.  Cognito
# applies its own defaults (1 hour for the access and ID tokens, 30 days for
# the refresh token) to a client that sets nothing, and those defaults are
# inside every threshold this module uses - so a classifier that returned 0 for
# an absent field would report every default client as having a zero-second
# token, and one that returned a large number would report every default client
# as excessive.  Returning "not configured" is the only reading that is true.
#
# THE UNIT IS PART OF THE VALUE AND ITS DEFAULT IS PER-TOKEN.  `TokenValidityUnits`
# is optional, and when it is absent - or names no unit for this token kind -
# AWS's documented default is `hours` for the access and ID tokens and `days`
# for the refresh token.  Reading a bare `AccessTokenValidity: 24` as 24
# SECONDS understates it by 3600x and reads as a clean client; reading a bare
# `RefreshTokenValidity: 3650` as 3650 hours understates a ten-year refresh
# token as five months.  Both are silent.
cognito_token_seconds_set() {
  local __var=$1 __kind=$2
  local __v __unit __mult
  printf -v "$__var" '%s' ''
  __v=${_CG_DOC[$(cognito_path "$COGNITO_CLIENT_ROOT" "${__kind}Validity")]:-}
  [[ $__v =~ ^[0-9]+$ ]] || return 1
  __unit=${_CG_DOC[$(cognito_path "$COGNITO_CLIENT_ROOT" TokenValidityUnits "$__kind")]:-}
  if [[ -z $__unit ]]; then
    if [[ $__kind == RefreshToken ]]; then __unit=days; else __unit=hours; fi
  fi
  case $__unit in
    seconds) __mult=1 ;;
    minutes) __mult=60 ;;
    hours) __mult=3600 ;;
    days) __mult=86400 ;;
    # An unrecognised unit is a response shape this parser does not understand.
    # Guessing one would put a number in a finding that is wrong by an unknown
    # factor, so it reports "not configured" and the caller records the gap.
    *) return 1 ;;
  esac
  printf -v "$__var" '%s' "$(( __v * __mult ))"
  return 0
}

# The excessive-lifetime thresholds, in seconds, one per token kind.  Spelled
# once so the classifier, the evidence and the suite all read the same numbers.
#
# 12 HOURS FOR THE ACCESS AND ID TOKENS, 90 DAYS FOR THE REFRESH TOKEN, AND
# EACH NUMBER IS ANCHORED TO ONE COGNITO PUBLISHES RATHER THAN TO AN OPINION.
# Cognito's own default for the access and ID tokens is ONE HOUR and its own
# hard maximum is TWENTY-FOUR, so 12 hours is the midpoint of the permitted
# range and twelve times the default: a client that reaches it has been
# deliberately pushed most of the way to the ceiling, and one left at the
# default - or at a generous but ordinary 8 hours - is never reported.  Setting
# the threshold AT the 24-hour maximum instead was the rejected alternative and
# is worth recording, because it looks like the more conservative choice and is
# in fact a check that can barely fire: with a `>` comparison nothing can
# exceed a hard ceiling, so the two arms would be dead code, and with a `>=`
# one they would fire on exactly one value.  The refresh threshold is well
# inside Cognito's own 10-year maximum and is the point past which a revoked or
# compromised session outlives any plausible incident response.
#
# SC2034: all three are read through the INDIRECT expansion
# `${!COGNITO_MAX_${kind^^}_SECONDS}` in `cognito_client_long_tokens_set`
# below, which the linter cannot follow - the name is composed at runtime from
# the token kind, which is the whole point of spelling them as three globals
# rather than as a `case`.  They are the published thresholds this file's
# header documents and `tests/suites/cloud-cognito.sh` asserts against, not
# dead stores.
# shellcheck disable=SC2034
declare -g COGNITO_MAX_ACCESSTOKEN_SECONDS=43200
# shellcheck disable=SC2034
declare -g COGNITO_MAX_IDTOKEN_SECONDS=43200
# shellcheck disable=SC2034
declare -g COGNITO_MAX_REFRESHTOKEN_SECONDS=7776000

# `cognito_client_long_tokens_set VARNAME` - the token kinds whose configured
# validity exceeds this module's threshold, newline-separated as
# `<kind> <seconds> <threshold>`.  Returns 0 when at least one was found.
cognito_client_long_tokens_set() {
  local __var=$1 __out='' __kind __secs='' __max __ref
  for __kind in AccessToken IdToken RefreshToken; do
    cognito_token_seconds_set __secs "$__kind" || continue
    __ref=COGNITO_MAX_${__kind^^}_SECONDS
    __max=${!__ref}
    (( __secs > __max )) || continue
    __out+="${__out:+$'\n'}$__kind $__secs $__max"
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `cognito_client_revocation_off` - true when `EnableTokenRevocation` is not
# `true`.
#
# ABSENT IS OFF, and that is the API's own semantics rather than an assumption:
# token revocation was added after Cognito shipped and is off for every client
# created before it, which is precisely the population that has long-lived
# refresh tokens and no way to invalidate them.  A classifier that treated an
# absent field as unknown would report those clients clean.
cognito_client_revocation_off() {
  [[ ${_CG_DOC[$(cognito_path "$COGNITO_CLIENT_ROOT" EnableTokenRevocation)]:-} != true ]]
}

# `cognito_client_user_existence_errors_off` - true when
# `PreventUserExistenceErrors` is not `ENABLED`.
#
# THIS IS A CLIENT-LEVEL SETTING, THOUGH §8.3 LISTS IT UNDER BOTH THE USER POOL
# AND THE APP CLIENT, and the discrepancy is the API's rather than the design's:
# `PreventUserExistenceErrors` exists on `describe-user-pool-client` and on
# nothing else.  It is implemented here, once, where the value actually lives -
# adding a second, pool-level check would be a check with no field to read,
# which could only ever report the pool clean.
#
# WHAT IT ACTUALLY CONTROLS.  With it `LEGACY` (or absent, which is `LEGACY`
# for a client created before the setting existed), Cognito answers
# `UserNotFoundException` for an unknown username and `NotAuthorizedException`
# for a known username with the wrong password - so an anonymous caller can
# enumerate every account in the pool one request at a time, with no rate limit
# that distinguishes the two.  With it `ENABLED` both answer identically.  This
# is the CONFIG-DERIVED user-enumeration detection §8.3's closing paragraph
# asks for, in place of sending the probe.
cognito_client_user_existence_errors_off() {
  [[ ${_CG_DOC[$(cognito_path "$COGNITO_CLIENT_ROOT" PreventUserExistenceErrors)]:-} != ENABLED ]]
}

# `cognito_client_sensitive_writes_set VARNAME` - the sensitive attributes this
# client may WRITE, newline-separated.  Returns 0 when at least one was found.
#
# A `custom:` ATTRIBUTE WHOSE NAME SUGGESTS A PRIVILEGE IS INCLUDED, and the
# name list is deliberately short and conservative.  §8.3 asks for "custom
# privilege attrs", which cannot be recognised in general - a custom attribute
# is whatever the application called it - so this matches a small set of names
# that are privileges in effectively every application that uses them, and
# nothing else.  The alternative readings both fail: matching every `custom:`
# attribute reports a writable `custom:favourite_colour`, and matching none
# leaves the commonest real privilege-escalation shape - a client-writable
# `custom:role` - undetected.  The finding's evidence names the attribute, so
# an operator can dismiss a false match in one glance.
declare -g COGNITO_SENSITIVE_CUSTOM_ATTRIBUTE_WORDS='role
roles
admin
is_admin
isadmin
group
groups
tier
plan
permission
permissions
scope
scopes
entitlement
entitlements'

cognito_client_sensitive_writes_set() {
  local __var=$1 __out='' __attrs='' __a __s __base __word
  cognito_list_set __attrs "$COGNITO_CLIENT_ROOT" WriteAttributes
  while IFS= read -r __a; do
    [[ -n $__a ]] || continue
    while IFS= read -r __s; do
      [[ -n $__s ]] || continue
      [[ $__a == "$__s" ]] && { __out+="${__out:+$'\n'}$__a"; continue 2; }
    done <<<"$COGNITO_SENSITIVE_WRITE_ATTRIBUTES"
    [[ $__a == custom:* ]] || continue
    # The comparison is on the WHOLE custom-attribute name, lowercased, never
    # on a substring: a substring test makes `custom:preferred_role_display`
    # match `role`, and - worse in the other direction - makes an application
    # that named an ordinary field `custom:wardrobe` match nothing while
    # looking like it was checked.
    __base=${__a#custom:}
    __base=${__base,,}
    while IFS= read -r __word; do
      [[ -n $__word ]] || continue
      [[ $__base == "$__word" ]] && { __out+="${__out:+$'\n'}$__a"; break; }
    done <<<"$COGNITO_SENSITIVE_CUSTOM_ATTRIBUTE_WORDS"
  done <<<"$__attrs"
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `cognito_client_is_public` - true when the client has NO client secret.
#
# READ FROM THE PRESENCE OF `ClientSecret`, NEVER FROM `GenerateSecret`.  The
# latter is a CREATE-time parameter and `describe-user-pool-client` does not
# return it; the response carries a `ClientSecret` field if and only if the
# client is confidential.  A classifier reading a field the API never sends
# would report every client - confidential ones included - as public.
cognito_client_is_public() {
  ! cognito_doc_has "$(cognito_path "$COGNITO_CLIENT_ROOT" ClientSecret)"
}

# `cognito_client_confidential_only_flows_set VARNAME` - the flows this client
# permits that ASSUME the client can keep a secret, newline-separated.  Returns
# 0 when the client is public AND permits at least one of them.
#
# WHY THIS IS NOT THE SAME CHECK AS `cognito_client_plaintext_flows_set`.  That
# one is about the credential travelling in the clear to Cognito, and it fires
# whether or not the client is confidential.  This one is about a client with
# no secret being given a flow whose security model rests on there being one -
# §8.3's own "public client (no secret) using flows that assume
# confidentiality".  A public client is by definition one whose code an
# attacker holds (a single-page app, a mobile binary), so anything it is
# allowed to do, anyone is allowed to do.
#
# THE TWO FLOWS THAT QUALIFY:
#   `client_credentials`            authenticates the CLIENT ITSELF and has no
#                                   user in it at all, so its entire security
#                                   rests on the secret.
#   `ALLOW_ADMIN_USER_PASSWORD_AUTH`  the ADMIN_* server-side flows are meant to
#                                   be called by a trusted backend holding the
#                                   secret, not by the end-user's own device.
cognito_client_confidential_only_flows_set() {
  local __var=$1 __out='' __oauth='' __explicit=''
  printf -v "$__var" '%s' ''
  cognito_client_is_public || return 1
  cognito_list_set __oauth "$COGNITO_CLIENT_ROOT" AllowedOAuthFlows
  cognito_list_contains "$__oauth" client_credentials \
    && __out+="${__out:+$'\n'}client_credentials"
  cognito_list_set __explicit "$COGNITO_CLIENT_ROOT" ExplicitAuthFlows
  cognito_list_contains "$__explicit" ALLOW_ADMIN_USER_PASSWORD_AUTH \
    && __out+="${__out:+$'\n'}ALLOW_ADMIN_USER_PASSWORD_AUTH"
  cognito_list_contains "$__explicit" ALLOW_ADMIN_USER_SRP_AUTH \
    && __out+="${__out:+$'\n'}ALLOW_ADMIN_USER_SRP_AUTH"
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# ---------------------------------------------------------------------------
# 5. Identity-pool classifiers
# ---------------------------------------------------------------------------
# `describe-identity-pool` has NO response envelope - its fields sit at the top
# level of the document, unlike `describe-user-pool` and
# `describe-user-pool-client`.  That asymmetry is the API's, and a classifier
# written against the wrong one reads every field as absent, which for
# `AllowUnauthenticatedIdentities` means reporting every identity pool as
# having anonymous access switched off.

# `cognito_idpool_allows_unauth` - true when `AllowUnauthenticatedIdentities`
# is `true`.
cognito_idpool_allows_unauth() {
  [[ ${_CG_DOC[AllowUnauthenticatedIdentities]:-} == true ]]
}

# `cognito_idpool_classic_flow` - true when `AllowClassicFlow` is `true`.
#
# WHAT THE CLASSIC FLOW ACTUALLY IS, since the field name says nothing.  It
# re-enables Cognito Identity's original two-step exchange - `GetOpenIdToken`
# followed by `sts assume-role-with-web-identity` - alongside the modern
# single-step `GetCredentialsForIdentity`.  The two-step form hands the caller
# an OpenID token they can then present to STS directly, which widens the
# surface for token replay and takes role selection out of the identity pool's
# own role-mapping rules.  AWS's guidance is to leave it off; a pool that has
# it on either needs it for a legacy client or had it switched on and forgotten.
cognito_idpool_classic_flow() {
  [[ ${_CG_DOC[AllowClassicFlow]:-} == true ]]
}

# `cognito_idpool_role_set VARNAME KIND` - the role ARN a
# `get-identity-pool-roles` document maps for KIND (`unauthenticated` or
# `authenticated`).  Returns 1 when the document maps none.
cognito_idpool_role_set() {
  local __var=$1 __kind=$2 __v
  __v=${_CG_DOC[$(cognito_path Roles "$__kind")]:-}
  printf -v "$__var" '%s' "$__v"
  [[ -n $__v ]]
}

# `cognito_idpool_ambiguous_mappings_set VARNAME` - the role-mapping providers
# whose `AmbiguousRoleResolution` is `AuthenticatedRole`, newline-separated as
# `<provider> <type>`.  Returns 0 when at least one was found.
#
# `AuthenticatedRole` IS THE PERMISSIVE RESOLUTION AND `Deny` IS THE SAFE ONE,
# which is the opposite of what the value names suggest at a glance.  A
# role-mapping rule set exists to hand different roles to different classes of
# user; `AmbiguousRoleResolution` says what happens when a token matches
# several rules or none.  `AuthenticatedRole` falls back to the pool's DEFAULT
# authenticated role, so a token carrying an unexpected claim - or a claim an
# attacker controls, since a provider's token is the thing being mapped - gets
# whatever that default role can do, silently.  `Deny` refuses instead.
#
# THE WALK IS OVER THE PROVIDER KEYS, NOT OVER AN ARRAY.  `RoleMappings` is a
# JSON OBJECT keyed by provider name (`cognito-idp.eu-west-2.amazonaws.com/
# eu-west-2_abc123:1h57...`), so there is no index to count up through; the
# provider names are recovered from the flattened paths themselves.
cognito_idpool_ambiguous_mappings_set() {
  local __var=$1 __out='' __k __provider __rest __seen=''
  local __prefix='RoleMappings'$'\x1f'
  for __k in "${!_CG_DOC[@]}"; do
    [[ $__k == "$__prefix"* ]] || continue
    __rest=${__k#"$__prefix"}
    __provider=${__rest%%$'\x1f'*}
    [[ -n $__provider ]] || continue
    [[ $'\n'"$__seen"$'\n' == *$'\n'"$__provider"$'\n'* ]] && continue
    __seen+="${__seen:+$'\n'}$__provider"
  done
  # LC_ALL=C sorted, because `${!array[@]}` iterates a hash in an order bash
  # does not define.  A finding's evidence that changed order between two runs
  # over an unchanged account would churn nothing in the fingerprint (evidence
  # is not a component) but would make two reports of the same account
  # gratuitously un-diffable, and an unstable order is exactly the kind of
  # thing a later change starts depending on by accident.
  while IFS= read -r __provider; do
    [[ -n $__provider ]] || continue
    [[ ${_CG_DOC[$(cognito_path RoleMappings "$__provider" AmbiguousRoleResolution)]:-} == AuthenticatedRole ]] \
      || continue
    __out+="${__out:+$'\n'}$__provider ${_CG_DOC[$(cognito_path RoleMappings "$__provider" Type)]:-unknown}"
  done < <(printf '%s\n' "$__seen" | LC_ALL=C sort)
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# ---------------------------------------------------------------------------
# 6. IAM policy over-permissiveness
# ---------------------------------------------------------------------------
# §8.3's identity-pool bullet requires that when `AllowUnauthenticatedIdentities`
# is on, the UNAUTHENTICATED IAM role's policy is inspected "for
# over-permissiveness", and that the result is "its own high-severity finding,
# not a note".  This section is that inspection.
#
# THIS IS NOT A RE-IMPLEMENTATION OF IAM POLICY EVALUATION, AND THE LINE IS
# DRAWN DELIBERATELY.  s3_engine.sh's `s3_policy_is_public` records the reason
# at length: deciding what a policy really permits means evaluating conditions,
# principals, permission boundaries, SCPs and resource policies together, and a
# shell approximation of that is confidently wrong.  For S3 there was an API
# that answers the question (`get-bucket-policy-status`); for an IAM role there
# is not.  So this classifier answers a NARROWER question it can answer
# exactly: does an `Allow` statement with NO `Condition` grant a wildcard
# action against a wildcard resource?  That shape permits what it appears to
# permit under every evaluation, which is why it is reported with high
# confidence - and a statement that DOES carry a condition is counted and
# reported as unassessed rather than judged, which is the honest half.

# `cognito_policy_grants_set VARNAME` - over-permissive grants in the IAM policy
# document already loaded by `cognito_doc_load`, newline-separated as
# `<grade> <action> <resource>`.  `grade` is `admin` or `service`.  Returns 0
# when at least one was found.  Sets the companion global
# `_COGNITO_POLICY_CONDITIONED` to the number of wildcard statements that were
# SKIPPED because they carried a `Condition`.
#
# `ROOT` NAMES THE PATH THE `Statement` KEY SITS UNDER, because the same
# classifier reads three differently-wrapped documents: `iam get-role-policy`
# nests the policy under `PolicyDocument`, `iam get-policy-version` under
# `PolicyVersion`+`Document`, and a bare policy document has it at the top
# level.  Passing the wrapper in is what keeps one classifier rather than three.
#
# `Statement` IS AN ARRAY *OR* A SINGLE OBJECT, and both are legal JSON policy.
# A walk that only handles the array form reads a single-statement policy -
# which is the ordinary shape for a Cognito unauthenticated role - as having no
# statements at all, and reports the most over-permissive role in the account
# clean.  The two are told apart by asking whether index 0 exists.
declare -g _COGNITO_POLICY_CONDITIONED=0

cognito_policy_grants_set() {
  local __var=$1
  shift
  local __base __out='' __i=0 __stmt
  _COGNITO_POLICY_CONDITIONED=0
  printf -v "$__var" '%s' ''
  if (( $# > 0 )); then
    __base=$(cognito_path "$@" Statement)
  else
    __base=Statement
  fi

  # The single-object form: `Statement` itself carries the keys.
  if cognito_doc_has "$__base"$'\x1f'Effect \
    || cognito_doc_has "$__base"$'\x1f'Action \
    || cognito_doc_has "$__base"$'\x1f'Action$'\x1f'0; then
    _cognito_policy_statement __out "$__base"
    printf -v "$__var" '%s' "$__out"
    [[ -n $__out ]]
    return
  fi

  while :; do
    __stmt=$__base$'\x1f'$__i
    cognito_doc_has "$__stmt"$'\x1f'Effect \
      || cognito_doc_has "$__stmt"$'\x1f'Action \
      || cognito_doc_has "$__stmt"$'\x1f'Action$'\x1f'0 \
      || cognito_doc_has "$__stmt"$'\x1f'NotAction \
      || break
    _cognito_policy_statement __out "$__stmt"
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `_cognito_policy_statement ACCUMULATOR STMT_PATH` - append this statement's
# over-permissive grants to the newline-separated list in ACCUMULATOR.
_cognito_policy_statement() {
  local __accvar=$1 __s=$2
  local __acc=${!__accvar}
  local __effect __actions='' __resources='' __a __r __grade

  __effect=${_CG_DOC[$__s$'\x1f'Effect]:-Allow}
  [[ $__effect == Allow ]] || return 0

  # A `Condition` block narrows the statement in a way this classifier does not
  # evaluate, so the statement is COUNTED and skipped rather than judged.  The
  # count is what the caller turns into a stated limit; dropping it silently
  # would let a policy that is over-permissive in practice - `aws:SourceIp` on
  # `0.0.0.0/0`, say - disappear from the report with no trace that anything
  # was set aside.  Judging it instead would report every properly-narrowed
  # policy in the estate.
  if cognito_doc_has "$__s"$'\x1f'Condition \
    || _cognito_has_prefix "$__s"$'\x1f'Condition$'\x1f'; then
    _COGNITO_POLICY_CONDITIONED=$(( _COGNITO_POLICY_CONDITIONED + 1 ))
    return 0
  fi

  # `NotAction` / `NotResource` invert the set, so a statement using either
  # grants everything EXCEPT what it names - which is over-permissive by
  # construction on an anonymous role, whatever the exception list says.
  if cognito_doc_has "$__s"$'\x1f'NotAction \
    || _cognito_has_prefix "$__s"$'\x1f'NotAction$'\x1f' \
    || cognito_doc_has "$__s"$'\x1f'NotResource \
    || _cognito_has_prefix "$__s"$'\x1f'NotResource$'\x1f'; then
    printf -v "$__accvar" '%s' "${__acc:+$__acc$'\n'}admin NotAction/NotResource *"
    return 0
  fi

  _cognito_scalar_or_list_set __actions "$__s" Action
  _cognito_scalar_or_list_set __resources "$__s" Resource

  # A statement with no `Resource` at all is an identity-policy statement that
  # names no resource, which IAM rejects - so it is not read as `*`.  Reading
  # it as `*` would manufacture a critical finding out of a malformed document.
  [[ -n $__resources ]] || return 0

  local __res_wild=0
  while IFS= read -r __r; do
    [[ $__r == '*' ]] && { __res_wild=1; break; }
  done <<<"$__resources"
  (( __res_wild )) || return 0

  while IFS= read -r __a; do
    [[ -n $__a ]] || continue
    __grade=''
    # `*` alone is full administrative access.  `<service>:*` is every action
    # of one service.  Anything narrower - `s3:GetObject`, or even
    # `s3:Get*` - is a scoped grant this check does not report: an
    # unauthenticated role legitimately needs SOME permission, or it would not
    # exist, and flagging every one of them is the flood that gets a check
    # switched off.
    # Quoted: SC2209 reads a bare `admin` on the right of an assignment as an
    # attempt to run a command of that name, and the quotes are what say it is
    # a literal grade string.
    if [[ $__a == '*' ]]; then
      __grade='admin'
    elif [[ $__a == *':*' ]]; then
      __grade='service'
    fi
    [[ -n $__grade ]] || continue
    __acc+="${__acc:+$'\n'}$__grade $__a *"
  done <<<"$__actions"
  printf -v "$__accvar" '%s' "$__acc"
  return 0
}

# `_cognito_has_prefix PREFIX` - true when any loaded path starts with PREFIX.
# Used to detect a `Condition` (or `NotAction`) that is present as a NESTED
# OBJECT rather than as a scalar leaf, which is the shape a real condition
# always takes: `cloud_json_flatten` emits leaves only, so
# `"Condition": {"StringEquals": {...}}` produces no leaf at the `Condition`
# path itself and `cognito_doc_has Condition` is false for every real one.
# Testing the leaf alone is therefore a check that can never fire, and the
# whole conditioned-statement carve-out above would silently do nothing.
_cognito_has_prefix() {
  local want=$1 k
  for k in "${!_CG_DOC[@]}"; do
    [[ $k == "$want"* ]] && return 0
  done
  return 1
}

# `_cognito_scalar_or_list_set VARNAME STMT_PATH KEY` - KEY's value(s),
# newline-separated, whether the policy wrote it as a bare string or as an
# array.
#
# BOTH FORMS ARE LEGAL AND BOTH ARE COMMON.  `"Action": "*"` and
# `"Action": ["*"]` are the same policy, and a reader that handles only the
# array form misses every single-action statement - which is the shape a
# hand-written `*`-on-`*` policy almost always takes.
_cognito_scalar_or_list_set() {
  local __var=$1 __s=$2 __key=$3
  local __p=$__s$'\x1f'$__key __out='' __i=0
  if cognito_doc_has "$__p"; then
    printf -v "$__var" '%s' "${_CG_DOC[$__p]:-}"
    return 0
  fi
  while :; do
    cognito_doc_has "$__p"$'\x1f'"$__i" || break
    __out+="${__out:+$'\n'}${_CG_DOC[$__p$'\x1f'$__i]:-}"
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `cognito_policy_worst_grade GRANTS` - `admin` when any line of GRANTS is an
# admin grant, `service` when any is a service-wide one, else the empty string.
#
# WHY A GRADE AT ALL RATHER THAN ONE FINDING.  The two grades are two check ids
# with two severities, because `severity` is a per-record registry field
# (rules/RULE-FORMAT.md §9.5) that this project's suites assert the script and
# the registry agree on - so a script that "weighted a finding higher" at
# runtime would put the two into disagreement.  Two ids also keeps an anonymous
# role with `*:*` and one with `s3:*` as two findings rather than one whose
# meaning flips between runs, which is the argument DAST-11's two
# `DAST-MARKUP-TABNABBING*` ids and this module's own two `CLOUD-S3-PUBLIC_ACL_*`
# ids both record.
#
# THE WORST GRADE WINS AND ONLY ONE FINDING IS EMITTED PER ROLE.  A role
# holding both `*` and `s3:*` has one problem an operator fixes once; emitting
# both ids would report the same role twice under two severities and make the
# lower one look like a separate, still-open issue after the higher one was
# fixed.
cognito_policy_worst_grade() {
  local grants=$1
  [[ $'\n'"$grants"$'\n' == *$'\n'admin\ * ]] && { printf '%s' admin; return 0; }
  [[ -n $grants ]] && { printf '%s' service; return 0; }
  printf '%s' ''
}

# ---------------------------------------------------------------------------
# 7. Emission
# ---------------------------------------------------------------------------
# `cognito_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the
# check registry this run loaded.  Returns 1 when no loaded set carries it.
cognito_registry_locate_set() {
  local __setvar=$1 __idxvar=$2 __id=$3 __set='' __idx=''
  printf -v "$__setvar" '%s' ''
  printf -v "$__idxvar" '%s' ''
  for __set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
    __idx=$(records_index_of_id "$__set" "$__id" 2>/dev/null) || continue
    printf -v "$__setvar" '%s' "$__set"
    printf -v "$__idxvar" '%s' "$__idx"
    return 0
  done
  return 1
}

# `cognito_emit_finding CHECK_ID ARN SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, VIA
# `finding_from_record`, AND IS NOT RESTATED HERE - the rule
# s3_engine.sh's own emitter records and this module follows: title, severity,
# confidence, CWE, OWASP category, remediation, references, the rule digest AND
# any `cis` control id are all fields of the registry record, and a script that
# set them by hand would be a second copy of every one of them to keep in step
# with the first.
#
# A CHECK ID WITH NO REGISTRY RECORD IS A LOUD INTERNAL ERROR, never a silently
# hand-built finding: in any real run `_scan_apply_profile_filter` has loaded
# `modules/cloud/**/*.rules` before dispatch, so the only way to reach it is a
# typo in a check id or a record deleted from under its script - both of which
# must stop the run rather than emit a finding with no severity, no remediation
# and no compliance mapping.
#
# THE REGION IS THE PASS'S, AND SO IS THE CELL, WHICH IS WHY THIS EMITTER TAKES
# NEITHER.  Cognito is a `regional` row in `_CLOUD_SERVICES`, so
# `cloud_run_service` sources this pass once per enabled region with
# `SCOURSH_CLOUD_REGION` and `SCOURSH_CLOUD_CELL` both set to that region's -
# and every resource this pass can see is, by construction, in the region it is
# enumerating.  That is the opposite of S3, where the bucket namespace is
# global and the resource's own region had to be resolved per bucket and
# deliberately differs from the cell.  Taking a region parameter here would be
# a parameter that can only ever be handed the value already in the
# environment, and the first caller to hand it something else would file a
# finding in a cell no pass ever covered - so tension 12 could never classify
# it `fixed` and it would sit at `unknown` forever.
cognito_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  cognito_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/cognito emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks-cognito.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # `exposure`/`auth`/`sensitive_data` feed data/severity-rubric.conf's
  # adjustment of the record's base severity.  `external`/`none` is the
  # anonymous-reachability band: an identity pool that hands AWS credentials to
  # an unauthenticated caller, and the app-client settings that an anonymous
  # caller exercises directly (the enumeration oracle, the implicit flow, a
  # callback URL a token is delivered to).  Everything else is a configuration
  # weakness behind a sign-in and takes `internal`/`user`, which is what keeps
  # a missing deletion protection out of the same band as a world-usable
  # administrative role.
  #
  # `external` rather than `internet` is DELIBERATE and follows the rest of the
  # tree: lib/http.sh, lib/paranoid.sh, modules/dast/ and
  # modules/cloud/aws/live/s3_engine.sh all spell it `external` for this band.
  # data/severity-rubric.conf carries no `external` row (its internet row is
  # spelled `internet`), so the value contributes no modifier today - which
  # means these severities are the base severities the registry authors,
  # exactly as every sibling module's are.  Spelling it `internet` here alone
  # would make cognito the one module whose findings for the same exposure
  # class sit a band above its peers', which is a divergence to make
  # deliberately across the tree or not at all.
  case $check_id in
    CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01 | \
      CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01 | \
      CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01 | \
      CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01 | \
      CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01 | \
      CLOUD-COGNITO-CLIENT_USER_EXISTENCE_ERRORS-01 | \
      CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01 | \
      CLOUD-COGNITO-CLIENT_INSECURE_CALLBACK-01 | \
      CLOUD-COGNITO-CLIENT_WILDCARD_CALLBACK-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
