#!/usr/bin/env bash
# modules/cloud/aws/live/iam.sh - the §8.1 IAM read-only service pass
# (docs/DESIGN.md §8.1's `iam` row; docs/STEP6-CLOUD-PLAN.md CLOUD-06).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, exactly as `live/s3.sh` - the header on
# that file gives the reasoning this one inherits verbatim, down to the "no
# sourced-once guard" rule and why. `iam` is a `global` row in
# `_CLOUD_SERVICES`, so this pass runs once per account regardless of how many
# regions the run resolved.
#
# WHY IAM IS `global`, AND WHAT THAT COSTS (LESS THAN S3's VERSION OF THE SAME
# QUESTION).  A user, role or policy is a global IAM object with no home
# region at all - unlike an S3 bucket, whose namespace is global but whose
# individual buckets each sit in a real region.  So every finding here
# carries the literal `loc_region` `global`, and - unlike S3, where the cell
# and the region deliberately differ - the cell and the region are the SAME
# string for every IAM finding.  `docs/STEP6-CLOUD-PLAN.md`'s own CLOUD-06 row
# says so directly: "Global service; findings carry `region: global`."
#
# EVERY ARN IS READ OFF THE API RESPONSE, NEVER BUILT.  `list-users` and
# `list-roles` already return a populated `Arn` per entry, so this file passes
# that ARN through rather than constructing one - see iam_engine.sh's own
# header for why that is the opposite of S3's situation.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23),
# spelled literally at each call site with a literal service and operation -
# never through a local wrapper taking the operation in a variable, for the
# identical reason s3.sh's own header gives at length (`tests/lint-aws-
# readonly.sh` parses the operation out of the source line, and a wrapper
# would make every call here invisible to it).
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, applying s3.sh's own three rules
# to a service whose resources are USERS and ROLES rather than buckets:
#   1. `checks_run` NAMES WHAT SUCCEEDED - a check id is recorded only if its
#      own call actually answered for at least one identity (or, for the four
#      account-wide checks, for the account itself).
#   2. AN `AccessDenied` IS A `coverage_reduction`, NEVER SILENCE.
#   3. `NoSuchEntity` ON `get-login-profile` MEANS "NO CONSOLE PASSWORD", AND
#      ON `get-account-password-policy` MEANS "NO PASSWORD POLICY AT ALL" -
#      both are ANSWERS, the second one the check's own finding, mirroring
#      s3.sh's `NoSuchBucketPolicy`-is-an-answer rule.
#
# THE ACCESS ANALYZER CHECK EXAMINES ONE REGION, AND THAT IS A STATED LIMIT.
# `accessanalyzer list-analyzers` is a per-region call and IAM Access Analyzer
# is genuinely enabled per region (CIS v3.0.0 control 1.20 asks for "all
# regions"), but this pass is `global` and runs with no ambient region at all
# (`cloud_run_service` clears it for every `global` row) - so the call resolves
# whatever region the CLI's own default chain (`--region`, `AWS_DEFAULT_REGION`,
# the profile's configured region) happens to name, not every enabled region.
# Widening this to the full region list is a real ticket (it would need this
# row to also run once per region, which is exactly the `regional` shape this
# row is not), not a fix folded in here without a fixture to prove it against.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/iam_engine.sh
source "${BASH_SOURCE[0]%/*}/iam_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for s3.sh's own reason: this file is sourced from INSIDE
# `cloud_run_service`, so a bare `declare` would make every one of these a
# local that dies with the pass.
declare -g _IAM_USERS_TOTAL=0
declare -g _IAM_ROLES_TOTAL=0
declare -gA _IAM_EVALUATED=()
declare -gA _IAM_LOST=()
declare -gA _IAM_LOST_REASON=()

# Every check id this pass can emit, in registry order - the same "spelled
# once, read by the selection gate, the roll-up and the not-evaluated
# accounting alike" discipline s3.sh's own `_S3_CHECK_IDS` documents.
declare -ga _IAM_CHECK_IDS=(
  CLOUD-IAM-ROOT_MFA_OFF-01
  CLOUD-IAM-ROOT_ACCESS_KEY-01
  CLOUD-IAM-WEAK_PASSWORD_POLICY-01
  CLOUD-IAM-ACCESS_ANALYZER_DISABLED-01
  CLOUD-IAM-POLICY_FULL_ADMIN-01
  CLOUD-IAM-NO_PERMISSION_BOUNDARY-01
  CLOUD-IAM-POLICY_SPRAWL-01
  CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01
  CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01
  CLOUD-IAM-UNUSED_CREDENTIAL-01
  CLOUD-IAM-ACCESS_KEY_ROTATION-01
  CLOUD-IAM-UNUSED_ROLE-01
)

# The three age thresholds this pass applies. CIS v3.0.0's own numbers for the
# first two (controls 1.12 and 1.14); the third has no CIS-numbered control
# (IAM roles carry no long-term credential of their own for CIS to number),
# so it reuses the same 90-day window as a stated, reasonable default rather
# than a transcribed control.
declare -gi IAM_UNUSED_CREDENTIAL_DAYS=45
declare -gi IAM_ACCESS_KEY_ROTATION_DAYS=90
declare -gi IAM_UNUSED_ROLE_DAYS=90

# `_iam_selected ID` - byte-identical to s3.sh's `_s3_selected`, and the same
# `declare -F` PERMISSIVE-WHEN-ABSENT guard for the identical reason: a
# direct-engine test suite sources this file with no module engine in the
# process, so a fail-CLOSED default would make the whole pass inert while
# every "stays quiet" assertion in that suite still passed green.
_iam_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_iam_note_evaluated() {
  _IAM_EVALUATED[$1]=$(( ${_IAM_EVALUATED[$1]:-0} + 1 ))
}

_iam_note_lost() {
  _IAM_LOST[$1]=$(( ${_IAM_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, s3.sh's own reasoning verbatim: the first failure is
  # the actionable one and usually explains every later one too.
  [[ -n ${_IAM_LOST_REASON[$1]:-} ]] || _IAM_LOST_REASON[$1]=$2
}

# `_iam_call_lost OPERATION LABEL IDS...` - shared tail for a call that failed
# in a way that is a coverage loss rather than an answer. LABEL is whatever
# names the thing that did not answer in the reduction's prose (a user name,
# a role name, a policy ARN) - never the check id, which is already `$@`.
_iam_call_lost() {
  local op=$1 label=$2
  shift 2
  local reason='' cid
  aws_ro_reduction_reason_set reason
  for cid in "$@"; do
    _iam_selected "$cid" && _iam_note_lost "$cid" "$reason"
  done
  run_record coverage_reduction "module=cloud reason=$reason service=iam operation=$op resource=$label checks=[$*] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this property was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
  return 0
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_iam_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local partition root_arn
  partition=$(iam_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")
  root_arn=$(iam_account_root_arn "$partition" "$account")

  # `mktemp -d`, never a name built from `$$`/`$BASHPID`, for s3.sh's own
  # reason (CWE-377 via CWE-59) - every path under $SCOURSH_SCRATCH is reached
  # by standalone-engine callers through the `${TMPDIR:-/tmp}` fallback.
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-iam.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_IAM_CHECK_IDS[@]+"${_IAM_CHECK_IDS[@]}"}"; do
    _iam_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_iam_checks_deselected service=iam account=$account - every CLOUD-IAM-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no IAM API call was made."
    return 0
  fi

  # `SCOURSH_IAM_NOW_EPOCH` overrides the real clock, mirroring
  # modules/dast/passive/tls_engine.sh's own injectable-`now` reasoning
  # (AGENTS.md's "Things measured on this codebase" records why
  # `openssl x509 -checkend` was rejected for the identical reason): every
  # age-threshold check in this file (§8 above) needs to keep the SAME
  # verdict years after this file's own test fixtures were authored, and a
  # bare `now_epoch()` would make "fresh" fixtures start reporting stale the
  # day they cross the real threshold's age. Unset in every real run.
  local now=${SCOURSH_IAM_NOW_EPOCH:-}
  [[ -n $now ]] || now=$(now_epoch)

  _iam_check_root "$account" "$root_arn" "$work"
  _iam_check_password_policy "$account" "$root_arn" "$work"
  _iam_check_access_analyzer "$account" "$root_arn" "$work"
  _iam_run_users "$account" "$work" "$now"
  _iam_run_roles "$account" "$work" "$now"

  _iam_record_coverage "$account"
  return 0
}

# ---------------------------------------------------------------------------
# 3. The four account-wide checks
# ---------------------------------------------------------------------------
_iam_check_root() {
  local account=$1 root_arn=$2 work=$3
  local mfa_id=CLOUD-IAM-ROOT_MFA_OFF-01 key_id=CLOUD-IAM-ROOT_ACCESS_KEY-01
  _iam_selected "$mfa_id" || _iam_selected "$key_id" || return 0
  local rc=0
  aws_ro iam get-account-summary >"$work/account-summary.json" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost get-account-summary "$account" "$mfa_id" "$key_id"
    return 0
  fi
  iam_doc_load "$work/account-summary.json"

  if _iam_selected "$mfa_id"; then
    _iam_note_evaluated "$mfa_id"
    local mfa=0
    # `|| true`: iam_summary_flag_set returns 1 when the flag reads 0, which
    # is the ORDINARY case this check exists to find - under `set -e` (every
    # real run), a bare call left unguarded would abort the whole scan the
    # first time it found the very thing it was looking for.
    iam_summary_flag_set mfa AccountMFAEnabled || true
    if (( mfa == 0 )); then
      iam_emit_finding "$mfa_id" "$root_arn" '' \
        "The account's root user has NO multi-factor authentication device registered (get-account-summary reports AccountMFAEnabled=0). The root user cannot be restricted by any IAM policy, so a compromised root credential with no MFA is an immediate, unrestrictable account takeover. Register a hardware or virtual MFA device for root, then use root only for the handful of tasks that genuinely require it. CIS v3.0.0 control 1.5."
    fi
  fi

  if _iam_selected "$key_id"; then
    _iam_note_evaluated "$key_id"
    local keys=0
    # `|| true`: see the identical note on the MFA check above - a return of
    # 1 here means "no keys present", the CLEAN case, and must not abort the
    # scan either.
    iam_summary_flag_set keys AccountAccessKeysPresent || true
    if (( keys == 1 )); then
      iam_emit_finding "$key_id" "$root_arn" '' \
        "The account's root user has at least one active access key (get-account-summary reports AccountAccessKeysPresent=1). The root user should never be used for programmatic access: delete the key(s) under IAM > My Security Credentials and use a named IAM role or user with least-privilege permissions for any automation that currently depends on it. CIS v3.0.0 control 1.4."
    fi
  fi
  return 0
}

_iam_check_password_policy() {
  local account=$1 root_arn=$2 work=$3
  local id=CLOUD-IAM-WEAK_PASSWORD_POLICY-01
  _iam_selected "$id" || return 0
  local rc=0
  aws_ro iam get-account-password-policy >"$work/password-policy.json" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # NoSuchEntity: no password policy configured at all. Both CIS 1.8 and
      # 1.9 fail simultaneously, and that IS the finding - the mirror image of
      # s3.sh's `NoSuchBucketPolicy` rule, applied to an absence that IS a
      # problem rather than one that is not.
      _iam_note_evaluated "$id"
      iam_emit_finding "$id" "$root_arn" '' \
        "The account has NO IAM password policy configured at all (get-account-password-policy returned NoSuchEntity), so every setting CIS v3.0.0 controls 1.8 and 1.9 require - a minimum length of at least $IAM_PASSWORD_MIN_LENGTH_FLOOR characters and remembering the last $IAM_PASSWORD_REUSE_PREVENTION_FLOOR passwords - is unset. Set an account password policy under IAM > Account settings > Password policy."
      return 0
    fi
    _iam_call_lost get-account-password-policy "$account" "$id"
    return 0
  fi
  iam_doc_load "$work/password-policy.json"
  _iam_note_evaluated "$id"
  local gaps=''
  iam_password_policy_gaps_set gaps
  [[ -n $gaps ]] || return 0
  iam_emit_finding "$id" "$root_arn" '' \
    "The account's IAM password policy does not meet CIS v3.0.0's minimums: $gaps not satisfied (get-account-password-policy). A minimum length below $IAM_PASSWORD_MIN_LENGTH_FLOOR characters or fewer than $IAM_PASSWORD_REUSE_PREVENTION_FLOOR remembered prior passwords narrows the effort an attacker needs against a guessed, leaked or reused console password. Controls 1.8 and 1.9."
  return 0
}

_iam_check_access_analyzer() {
  local account=$1 root_arn=$2 work=$3
  local id=CLOUD-IAM-ACCESS_ANALYZER_DISABLED-01
  _iam_selected "$id" || return 0
  local rc=0
  aws_ro accessanalyzer list-analyzers >"$work/analyzers.json" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost list-analyzers "$account" "$id"
    return 0
  fi
  iam_doc_load "$work/analyzers.json"
  _iam_note_evaluated "$id"
  iam_analyzer_has_active && return 0
  iam_emit_finding "$id" "$root_arn" '' \
    "This account has no ACTIVE IAM Access Analyzer in the region examined (list-analyzers names none in the ACTIVE state). CIS v3.0.0 control 1.20 asks for one per region. Access Analyzer flags resources - roles, KMS keys, S3 buckets, Lambda functions and more - whose OWN policy makes them reachable from outside the account or organization, which is exactly the cross-resource class of exposure this module cannot detect by reading one resource's policy in isolation. Enable it under IAM > Access Analyzer in every region this account uses."
  return 0
}

# ---------------------------------------------------------------------------
# 4. Users and roles: the roster walk
# ---------------------------------------------------------------------------
_iam_run_users() {
  local account=$1 work=$2 now=$3
  local -a ids=(CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 \
    CLOUD-IAM-POLICY_SPRAWL-01 CLOUD-IAM-UNUSED_CREDENTIAL-01 CLOUD-IAM-ACCESS_KEY_ROTATION-01)
  local need=0 id
  for id in "${ids[@]+"${ids[@]}"}"; do
    _iam_selected "$id" && need=1
  done
  (( need )) || return 0

  local listf=$work/list-users.json rc=0
  aws_ro iam list-users >"$listf" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost list-users "$account" "${ids[@]+"${ids[@]}"}"
    return 0
  fi
  iam_doc_load "$listf"

  local -a names=() arns=()
  local i=0 n a
  while :; do
    iam_doc_has "$(iam_path Users "$i" UserName)" || break
    n=${_IAM_DOC[$(iam_path Users "$i" UserName)]:-}
    a=${_IAM_DOC[$(iam_path Users "$i" Arn)]:-}
    [[ -n $n ]] && { names+=("$n"); arns+=("$a"); }
    i=$(( i + 1 ))
  done
  _IAM_USERS_TOTAL=${#names[@]}

  local j
  for (( j = 0; j < ${#names[@]}; j++ )); do
    _iam_examine_user "${names[j]}" "${arns[j]}" "$work" "$now"
  done
  return 0
}

_iam_run_roles() {
  local account=$1 work=$2 now=$3
  local -a ids=(CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 \
    CLOUD-IAM-POLICY_SPRAWL-01 CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01 \
    CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01 CLOUD-IAM-UNUSED_ROLE-01)
  local need=0 id
  for id in "${ids[@]+"${ids[@]}"}"; do
    _iam_selected "$id" && need=1
  done
  (( need )) || return 0

  local listf=$work/list-roles.json rc=0
  aws_ro iam list-roles >"$listf" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost list-roles "$account" "${ids[@]+"${ids[@]}"}"
    return 0
  fi
  iam_doc_load "$listf"

  local -a names=() arns=()
  local i=0 n a
  while :; do
    iam_doc_has "$(iam_path Roles "$i" RoleName)" || break
    n=${_IAM_DOC[$(iam_path Roles "$i" RoleName)]:-}
    a=${_IAM_DOC[$(iam_path Roles "$i" Arn)]:-}
    [[ -n $n ]] && { names+=("$n"); arns+=("$a"); }
    i=$(( i + 1 ))
  done
  _IAM_ROLES_TOTAL=${#names[@]}

  local j
  for (( j = 0; j < ${#names[@]}; j++ )); do
    _iam_examine_role "${names[j]}" "${arns[j]}" "$account" "$work" "$now"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 5. One user
# ---------------------------------------------------------------------------
_iam_examine_user() {
  local name=$1 arn=$2 work=$3 now=$4
  local safe=${name//[^A-Za-z0-9._-]/_}
  local rc=0
  aws_ro iam get-user --user-name "$name" >"$work/$safe.user.json" || rc=$?
  if (( rc != 0 )); then
    # The redirect above creates (truncates) the file whether or not the call
    # succeeded, so an EMPTY file is not evidence of a successful empty
    # response - remove it, which is what lets `_iam_examine_user_credentials`
    # below tell "get-user answered" from "get-user was denied" by the file's
    # mere presence rather than by re-deriving the outcome a second time.
    rm -f -- "$work/$safe.user.json"
    _iam_call_lost get-user "$name" CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 \
      CLOUD-IAM-POLICY_SPRAWL-01 CLOUD-IAM-UNUSED_CREDENTIAL-01
  else
    iam_doc_load "$work/$safe.user.json"
    local boundary_ok=0
    iam_has_permission_boundary User && boundary_ok=1
    _iam_examine_policy_holder user "$name" "$arn" "$boundary_ok" "$work"
  fi

  _iam_examine_user_credentials "$name" "$arn" "$work" "$now"
  return 0
}

# ---------------------------------------------------------------------------
# 6. One role
# ---------------------------------------------------------------------------
_iam_examine_role() {
  local name=$1 arn=$2 account=$3 work=$4 now=$5
  local safe=${name//[^A-Za-z0-9._-]/_}
  local rc=0
  aws_ro iam get-role --role-name "$name" >"$work/$safe.role.json" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost get-role "$name" CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 \
      CLOUD-IAM-POLICY_SPRAWL-01 CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01 \
      CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01 CLOUD-IAM-UNUSED_ROLE-01
    return 0
  fi
  iam_doc_load "$work/$safe.role.json"
  local boundary_ok=0
  iam_has_permission_boundary Role && boundary_ok=1

  _iam_examine_policy_holder role "$name" "$arn" "$boundary_ok" "$work"

  # Reload the role's own document: `_iam_examine_policy_holder`'s own calls
  # (get-user-policy, get-policy, get-policy-version, ...) have since
  # overwritten `_IAM_DOC` with THEIR responses.
  iam_doc_load "$work/$safe.role.json"

  if _iam_selected CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01 || _iam_selected CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01; then
    local trust_raw=''
    if iam_role_assume_policy_raw trust_raw; then
      iam_doc_load_string "$(iam_url_decode "$trust_raw")"
      if _iam_selected CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01; then
        _iam_note_evaluated CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01
        if iam_trust_has_wildcard_principal; then
          iam_emit_finding CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01 "$arn" '' \
            "$name's trust policy admits Principal \"*\" - any AWS principal in any account can request to assume this role, with no way for AWS to narrow who that is beyond whatever the request itself claims. Name the specific accounts, roles or services that legitimately need to assume it."
        fi
      fi
      if _iam_selected CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01; then
        _iam_note_evaluated CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01
        if iam_trust_has_unconditional_cross_account "$account"; then
          iam_emit_finding CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01 "$arn" '' \
            "$name's trust policy allows a DIFFERENT AWS account to assume it with no sts:ExternalId condition. Without one, the confused-deputy pattern AWS's own third-party cross-account access guidance warns about becomes possible: if the trusting account (or a service acting on its behalf) reuses this same trust relationship for more than one external customer, one customer's request can end up assuming a role meant for another's resources. Add a Condition requiring a unique, secret sts:ExternalId, per the third party."
        fi
      fi
    fi
  fi

  if _iam_selected CLOUD-IAM-UNUSED_ROLE-01; then
    _iam_note_evaluated CLOUD-IAM-UNUSED_ROLE-01
    # Reload AGAIN: the trust-policy block just above, when it ran, replaced
    # `_IAM_DOC` with the DECODED TRUST DOCUMENT's own content via
    # `iam_doc_load_string` - a role whose trust check ran but whose
    # CreateDate was then read from that leftover document would silently
    # read empty and this check would never fire for any role, with no error
    # anywhere to notice it by. Measured: this is exactly what happened here
    # before this reload was added.
    iam_doc_load "$work/$safe.role.json"
    local created=${_IAM_DOC[$(iam_path Role CreateDate)]:-}
    local create_epoch=''
    iam_iso8601_to_epoch create_epoch "$created" || true
    # A role younger than the unused-window has not had a fair chance to be
    # used yet - flagging it would punish a role for having just been
    # created, the same reasoning s3.sh applies to a freshly-listed bucket
    # that simply has not been examined by anything else yet.
    if [[ -n $create_epoch ]] && (( $(iam_age_days "$create_epoch" "$now") >= IAM_UNUSED_ROLE_DAYS )); then
      local last_epoch='' age
      if ! iam_role_last_used_epoch last_epoch; then
        iam_emit_finding CLOUD-IAM-UNUSED_ROLE-01 "$arn" '' \
          "$name was created over $IAM_UNUSED_ROLE_DAYS days ago and AWS has never recorded it being assumed (RoleLastUsed is absent). An unused role is unnecessary standing access with no owner actively relying on it. Confirm nothing still depends on it and remove it if not."
      else
        age=$(iam_age_days "$last_epoch" "$now")
        if (( age >= IAM_UNUSED_ROLE_DAYS )); then
          iam_emit_finding CLOUD-IAM-UNUSED_ROLE-01 "$arn" '' \
            "$name has not been assumed in at least $age days (get-role's RoleLastUsed). Confirm nothing still depends on it and remove it if not."
        fi
      fi
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 7. Policies: inline + attached, shared between users and roles
# ---------------------------------------------------------------------------
# `_iam_list_inline_policies KIND NAME OUT` / `_iam_get_inline_policy KIND
# NAME POLICY_NAME OUT` / `_iam_list_attached_policies KIND NAME OUT` - the
# same three read-only calls the caller wants, spelled with a literal
# operation name at each call site rather than through an operation held in
# a variable. `tests/lint-aws-readonly.sh`'s check 3 CAN certify a
# variable operation (a `readonly` array of literals in the same file), but
# spelling both branches out here is what every other service script in this
# tree already does and is simpler to read than a second mechanism this
# file alone would introduce for two call sites.
_iam_list_inline_policies() {
  local kind=$1 name=$2 out=$3 rc=0
  if [[ $kind == user ]]; then
    aws_ro iam list-user-policies --user-name "$name" >"$out" || rc=$?
  else
    aws_ro iam list-role-policies --role-name "$name" >"$out" || rc=$?
  fi
  return "$rc"
}

_iam_get_inline_policy() {
  local kind=$1 name=$2 pname=$3 out=$4 rc=0
  if [[ $kind == user ]]; then
    aws_ro iam get-user-policy --user-name "$name" --policy-name "$pname" >"$out" || rc=$?
  else
    aws_ro iam get-role-policy --role-name "$name" --policy-name "$pname" >"$out" || rc=$?
  fi
  return "$rc"
}

_iam_list_attached_policies() {
  local kind=$1 name=$2 out=$3 rc=0
  if [[ $kind == user ]]; then
    aws_ro iam list-attached-user-policies --user-name "$name" >"$out" || rc=$?
  else
    aws_ro iam list-attached-role-policies --role-name "$name" >"$out" || rc=$?
  fi
  return "$rc"
}

# `_iam_examine_policy_holder KIND NAME ARN BOUNDARY_OK WORK` - the three
# policy-shaped checks (full-admin, permission boundary, inline/managed
# sprawl) for one user or one role. KIND is `user` or `role`; this is the
# "role-policy reader" a later per-service ticket (Lambda's execution role,
# among others) is expected to reuse rather than fork, per
# docs/STEP6-CLOUD-PLAN.md's own P6 note.
_iam_examine_policy_holder() {
  local kind=$1 name=$2 arn=$3 boundary_ok=$4 work=$5
  local safe=${name//[^A-Za-z0-9._-]/_}

  local need_fetch=0
  _iam_selected CLOUD-IAM-POLICY_FULL_ADMIN-01 && need_fetch=1
  _iam_selected CLOUD-IAM-POLICY_SPRAWL-01 && need_fetch=1
  _iam_selected CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 && need_fetch=1

  if _iam_selected CLOUD-IAM-NO_PERMISSION_BOUNDARY-01; then
    _iam_note_evaluated CLOUD-IAM-NO_PERMISSION_BOUNDARY-01
  fi

  local inline_count=0 attached_count=0 has_full_admin=0 rc=0

  if (( need_fetch )); then
    rc=0
    _iam_list_inline_policies "$kind" "$name" "$work/$safe.inline-list.json" || rc=$?
    if (( rc != 0 )); then
      _iam_call_lost "list-${kind}-policies" "$name" CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-POLICY_SPRAWL-01
    else
      iam_doc_load "$work/$safe.inline-list.json"
      local names_raw='' pname
      iam_inline_policy_names_set names_raw
      while IFS= read -r pname; do
        [[ -n $pname ]] || continue
        inline_count=$(( inline_count + 1 ))
        (( has_full_admin )) && continue
        rc=0
        _iam_get_inline_policy "$kind" "$name" "$pname" "$work/$safe.inline-$pname.json" || rc=$?
        if (( rc != 0 )); then
          _iam_call_lost "get-${kind}-policy" "$name/$pname" CLOUD-IAM-POLICY_FULL_ADMIN-01
          continue
        fi
        iam_doc_load "$work/$safe.inline-$pname.json"
        local raw=''
        iam_policy_document_raw_set raw || continue
        iam_doc_load_string "$(iam_url_decode "$raw")"
        iam_policy_doc_has_full_admin && has_full_admin=1
      done <<<"$names_raw"
    fi

    rc=0
    _iam_list_attached_policies "$kind" "$name" "$work/$safe.attached-list.json" || rc=$?
    if (( rc != 0 )); then
      _iam_call_lost "list-attached-${kind}-policies" "$name" CLOUD-IAM-POLICY_FULL_ADMIN-01 CLOUD-IAM-POLICY_SPRAWL-01
    else
      iam_doc_load "$work/$safe.attached-list.json"
      local arns_raw='' parn
      iam_attached_policy_arns_set arns_raw
      while IFS= read -r parn; do
        [[ -n $parn ]] || continue
        attached_count=$(( attached_count + 1 ))
        (( has_full_admin )) && continue
        _iam_full_admin_from_managed_policy "$parn" "$work" "$safe" && has_full_admin=1
      done <<<"$arns_raw"
    fi
  fi

  if _iam_selected CLOUD-IAM-POLICY_SPRAWL-01; then
    _iam_note_evaluated CLOUD-IAM-POLICY_SPRAWL-01
    if (( inline_count >= 1 && attached_count >= 1 )); then
      iam_emit_finding CLOUD-IAM-POLICY_SPRAWL-01 "$arn" '' \
        "$name carries $inline_count inline polic$( (( inline_count == 1 )) && printf y || printf ies ) AND $attached_count attached managed polic$( (( attached_count == 1 )) && printf y || printf ies ). Mixing the two management models on one identity makes its effective permission set hard to audit as a whole - a reviewer checking the attached managed policies alone will not see the inline grants, and vice versa. Consolidate onto managed (ideally customer-managed) policies and remove the inline ones once their grants are represented there."
    fi
  fi

  if _iam_selected CLOUD-IAM-POLICY_FULL_ADMIN-01; then
    _iam_note_evaluated CLOUD-IAM-POLICY_FULL_ADMIN-01
    if (( has_full_admin )); then
      iam_emit_finding CLOUD-IAM-POLICY_FULL_ADMIN-01 "$arn" '' \
        "$name carries a policy statement granting Effect Allow, Action \"*\", Resource \"*\" with no Condition - full administrative privileges over every AWS service in the account, unconditionally. This is CIS v3.0.0 control 1.16's own published audit shape (data/cis-mappings has no row for it yet - see docs/CIS-MAPPINGS.md §4 - so this finding carries no cis value). Replace the statement with one scoped to the specific actions and resources $name actually needs."
      if _iam_selected CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 && (( boundary_ok == 0 )); then
        iam_emit_finding CLOUD-IAM-NO_PERMISSION_BOUNDARY-01 "$arn" '' \
          "$name has a policy granting full administrative privileges (Action \"*\", Resource \"*\") and NO permission boundary attached, so nothing caps what a compromised credential, or a future, more permissive policy change on this identity, could reach. Attach a permission boundary that limits its maximum possible permissions even if its own policy is later widened."
      fi
    fi
  fi
  return 0
}

# `_iam_full_admin_from_managed_policy ARN WORK SAFE` - true when the
# attached managed policy at ARN's DEFAULT version matches the full-admin
# shape.  Two calls: `get-policy` for the version id currently in force,
# `get-policy-version` for that version's own document - a managed policy
# carries every version it was ever updated to, and only the default one is
# what is actually in force for anyone it is attached to.
_iam_full_admin_from_managed_policy() {
  local parn=$1 work=$2 safe=$3
  local safepolicy=${parn//[^A-Za-z0-9._-]/_}
  local rc=0
  aws_ro iam get-policy --policy-arn "$parn" >"$work/$safe.policy-$safepolicy.json" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost get-policy "$parn" CLOUD-IAM-POLICY_FULL_ADMIN-01
    return 1
  fi
  iam_doc_load "$work/$safe.policy-$safepolicy.json"
  local vid=''
  iam_policy_default_version_id_set vid || return 1
  rc=0
  aws_ro iam get-policy-version --policy-arn "$parn" --version-id "$vid" \
    >"$work/$safe.policyversion-$safepolicy.json" || rc=$?
  if (( rc != 0 )); then
    _iam_call_lost get-policy-version "$parn" CLOUD-IAM-POLICY_FULL_ADMIN-01
    return 1
  fi
  iam_doc_load "$work/$safe.policyversion-$safepolicy.json"
  local raw=''
  iam_policy_version_document_raw_set raw || return 1
  iam_doc_load_string "$(iam_url_decode "$raw")"
  iam_policy_doc_has_full_admin
}

# ---------------------------------------------------------------------------
# 8. Credentials: console password and access keys (users only)
# ---------------------------------------------------------------------------
# `_iam_examine_user_credentials NAME ARN WORK NOW` - CLOUD-IAM-
# UNUSED_CREDENTIAL-01 (password AND access-key halves) and CLOUD-IAM-
# ACCESS_KEY_ROTATION-01. Roles carry no long-term credential of their own, so
# neither check applies to them.
_iam_examine_user_credentials() {
  local name=$1 arn=$2 work=$3 now=$4
  local safe=${name//[^A-Za-z0-9._-]/_}
  local need_unused=0 need_rotation=0
  _iam_selected CLOUD-IAM-UNUSED_CREDENTIAL-01 && need_unused=1
  _iam_selected CLOUD-IAM-ACCESS_KEY_ROTATION-01 && need_rotation=1
  (( need_unused || need_rotation )) || return 0

  local -a stale_items=() rotate_items=()

  # --- the console-password half of UNUSED_CREDENTIAL ---
  # Guarded on the user's own `get-user` response having been written to disk
  # earlier in `_iam_examine_user`: if that call itself failed, the loss was
  # already recorded there (CLOUD-IAM-UNUSED_CREDENTIAL-01 is in that call's
  # own id list), and nothing further needs recording here for the SAME
  # failure.
  if (( need_unused )) && [[ -r $work/$safe.user.json ]]; then
    iam_doc_load "$work/$safe.user.json"
    local pwd_last_used=${_IAM_DOC[$(iam_path User PasswordLastUsed)]:-}
    local rc=0
    aws_ro iam get-login-profile --user-name "$name" >"$work/$safe.login.json" || rc=$?
    if (( rc == 0 )); then
      _iam_note_evaluated CLOUD-IAM-UNUSED_CREDENTIAL-01
      if [[ -z $pwd_last_used ]]; then
        stale_items+=(password)
      else
        local epoch=''
        if iam_iso8601_to_epoch epoch "$pwd_last_used"; then
          (( $(iam_age_days "$epoch" "$now") >= IAM_UNUSED_CREDENTIAL_DAYS )) && stale_items+=(password)
        fi
      fi
    elif [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # NoSuchEntity: no console password at all. Not applicable, and that IS
      # an answer - the check ran, it simply has nothing to say about a
      # credential this user does not hold.
      _iam_note_evaluated CLOUD-IAM-UNUSED_CREDENTIAL-01
    else
      _iam_call_lost get-login-profile "$name" CLOUD-IAM-UNUSED_CREDENTIAL-01
    fi
  fi

  # --- access keys: both the key half of UNUSED_CREDENTIAL and the whole of
  #     ACCESS_KEY_ROTATION ---
  if (( need_unused || need_rotation )); then
    local rc=0
    aws_ro iam list-access-keys --user-name "$name" >"$work/$safe.keys.json" || rc=$?
    if (( rc != 0 )); then
      local -a lost_ids=()
      (( need_unused )) && lost_ids+=(CLOUD-IAM-UNUSED_CREDENTIAL-01)
      (( need_rotation )) && lost_ids+=(CLOUD-IAM-ACCESS_KEY_ROTATION-01)
      _iam_call_lost list-access-keys "$name" "${lost_ids[@]+"${lost_ids[@]}"}"
    else
      iam_doc_load "$work/$safe.keys.json"
      local i=0 kid status created create_epoch
      while :; do
        iam_doc_has "$(iam_path AccessKeyMetadata "$i" AccessKeyId)" || break
        kid=${_IAM_DOC[$(iam_path AccessKeyMetadata "$i" AccessKeyId)]:-}
        status=${_IAM_DOC[$(iam_path AccessKeyMetadata "$i" Status)]:-}
        created=${_IAM_DOC[$(iam_path AccessKeyMetadata "$i" CreateDate)]:-}
        i=$(( i + 1 ))
        [[ -n $kid && $status == Active ]] || continue

        create_epoch=''
        iam_iso8601_to_epoch create_epoch "$created" || true

        if (( need_rotation )); then
          _iam_note_evaluated CLOUD-IAM-ACCESS_KEY_ROTATION-01
          if [[ -n $create_epoch ]] \
            && (( $(iam_age_days "$create_epoch" "$now") >= IAM_ACCESS_KEY_ROTATION_DAYS )); then
            rotate_items+=("$kid")
          fi
        fi

        if (( need_unused )); then
          local rc2=0
          aws_ro iam get-access-key-last-used --access-key-id "$kid" \
            >"$work/$safe.keylastused-$kid.json" || rc2=$?
          if (( rc2 != 0 )); then
            _iam_call_lost get-access-key-last-used "$kid" CLOUD-IAM-UNUSED_CREDENTIAL-01
            continue
          fi
          _iam_note_evaluated CLOUD-IAM-UNUSED_CREDENTIAL-01
          iam_doc_load "$work/$safe.keylastused-$kid.json"
          local last_used=${_IAM_DOC[$(iam_path AccessKeyLastUsed LastUsedDate)]:-}
          local ref_epoch=''
          if [[ -n $last_used ]]; then
            iam_iso8601_to_epoch ref_epoch "$last_used" || true
          else
            ref_epoch=$create_epoch
          fi
          [[ -n $ref_epoch ]] \
            && (( $(iam_age_days "$ref_epoch" "$now") >= IAM_UNUSED_CREDENTIAL_DAYS )) \
            && stale_items+=("$kid")
        fi
      done
    fi
  fi

  local item
  for item in "${stale_items[@]+"${stale_items[@]}"}"; do
    if [[ $item == password ]]; then
      iam_emit_finding CLOUD-IAM-UNUSED_CREDENTIAL-01 "$arn" password \
        "$name's console password has not been used in at least $IAM_UNUSED_CREDENTIAL_DAYS days, or has never been used at all. A credential nobody is using is a credential nobody will notice if it is stolen. Disable the user's console access, or delete the login profile if it is not needed. CIS v3.0.0 control 1.12."
    else
      iam_emit_finding CLOUD-IAM-UNUSED_CREDENTIAL-01 "$arn" "$item" \
        "Access key $item on $name has not been used in at least $IAM_UNUSED_CREDENTIAL_DAYS days, or has never been used since it was created. Disable or delete it. CIS v3.0.0 control 1.12."
    fi
  done
  for item in "${rotate_items[@]+"${rotate_items[@]}"}"; do
    iam_emit_finding CLOUD-IAM-ACCESS_KEY_ROTATION-01 "$arn" "$item" \
      "Access key $item on $name is at least $IAM_ACCESS_KEY_ROTATION_DAYS days old and has not been rotated. A long-lived static credential has a longer window in which a leak goes undetected before the key itself expires on its own. Create a replacement key, update whatever uses the old one, then delete it. CIS v3.0.0 control 1.14."
  done
  return 0
}

# ---------------------------------------------------------------------------
# 9. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one
# resource (the account itself, for the four account-wide checks; a user or a
# role otherwise), and one `coverage_reduction` per check that did not -
# s3.sh's own `_s3_record_coverage` rule, generalised over `_IAM_CHECK_IDS`.
_iam_record_coverage() {
  local account=$1 id
  local ran=0
  for id in "${_IAM_CHECK_IDS[@]+"${_IAM_CHECK_IDS[@]}"}"; do
    _iam_selected "$id" || continue
    if (( ${_IAM_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_IAM_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_IAM_LOST_REASON[$id]} service=iam check=$id account=$account answered=${_IAM_EVALUATED[$id]} unanswered=${_IAM_LOST[$id]} - this check ran, but ${_IAM_LOST[$id]} resource(s) or call(s) did not answer, so it is covered for some of the account's IAM resources and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_IAM_LOST_REASON[$id]:-no_resource_examined} service=iam check=$id account=$account users_total=${_IAM_USERS_TOTAL} roles_total=${_IAM_ROLES_TOTAL} - this check answered for NO resource in the account and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that everything is configured correctly."
    fi
  done

  if (( _IAM_USERS_TOTAL == 0 && _IAM_ROLES_TOTAL == 0 )); then
    run_record notes "module=cloud service=iam account=$account users=0 roles=0 - the account's user and role lists were read successfully and contain neither, so every per-identity CLOUD-IAM-* check is covered vacuously."
  fi

  if (( ran == 0 )); then
    run_record coverage_gap "cloud iam: NOT ONE of the ${#_IAM_CHECK_IDS[@]} CLOUD-IAM-* checks answered for account $account, so no property of its IAM configuration was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_iam_run_service
