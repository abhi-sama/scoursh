#!/usr/bin/env bash
# modules/cloud/aws/live/lambda.sh - the §8.6 Lambda read-only service pass
# (docs/DESIGN.md §8.6's `lambda` row; docs/STEP6-CLOUD-PLAN.md CLOUD-21).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard. Per that function's own
# contract it carries NO sourced-once guard - `lambda` is a REGIONAL row in
# `_CLOUD_SERVICES` (unlike `s3`'s `global` one), so this file is legitimately
# reached once per enabled region, and a guard would silently make every
# region after the first a no-op - the failure that reads as a complete
# multi-region audit. Its pure half - every classifier, the ARN/role-name
# builders, the IAM-policy-document normaliser and the emitter - is
# modules/cloud/aws/live/lambda_engine.sh, which does have a guard.
#
# WHY LAMBDA IS A `regional` ROW AND WHAT THAT SIMPLIFIES. Unlike S3's
# `list-buckets`, `lambda list-functions` is itself a PER-REGION call: it
# answers only for the functions that live in whatever region the caller
# addressed it to, so `cloud_run_service` already sourced this script with
# `SCOURSH_CLOUD_REGION`/`SCOURSH_CLOUD_CELL` set to that region and
# `aws_ro_use_region` already pointed there. There is therefore no
# `get-bucket-location`-shaped extra call here: a function's own region IS
# the pass's region, and `lambda_emit_finding` cites it directly with no
# separate resolution step.
#
# THREE PROPERTIES, SIX CHECK IDS - docs/DESIGN.md §8.6's own three bullets
# ("over-permissive execution role", "public function URL / `*`-principal
# policy", "secrets in ... env vars") split into SIX ids for the identical
# reason modules/cloud/aws/live/checks.rules' own S3 header states: the CLOUD
# location profile (account_id, region, resource_key, sub_key) carries no
# component naming the DEFECT, so two genuinely different problems on one
# function under one id would collide onto one fingerprint and
# `findings_merge` would keep whichever sorted first. Each pair also differs
# in SEVERITY, which is a per-record registry field - so a script that
# "weighted a finding higher" at runtime would put the two into disagreement
# with the registry, exactly the argument S3's PUBLIC_ACL_READ/WRITE split
# makes. See modules/cloud/aws/live/checks.rules' own lambda section for the
# full reasoning per pair.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23),
# spelled literally at each call site with a literal service and operation -
# never through a local wrapper taking the operation in a variable, for the
# identical reason s3.sh's own header gives: tests/lint-aws-readonly.sh parses
# the operation out of the source line.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, exactly as s3.sh's header states
# for its own three rules: `checks_run` names what SUCCEEDED; an AccessDenied
# (or throttle, or unreachable endpoint) is a `coverage_reduction`, never
# silence; and `ResourceNotFoundException`/`NoSuchEntity` from `lambda
# get-policy` and the IAM role-policy calls are ANSWERS ("this function has no
# resource policy" / "this role has no such policy"), not losses.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/lambda_engine.sh
source "${BASH_SOURCE[0]%/*}/lambda_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for the reason lambda_engine.sh's own note records: this file
# is sourced from INSIDE `cloud_run_service`, so a bare `declare` would make
# every one of these a local that dies with the pass. They are reset here
# rather than only declared, because this pass runs once per REGION and a
# second region in the same process must not inherit the first region's
# counters.
declare -g _LAMBDA_FUNCTIONS_TOTAL=0
declare -g _LAMBDA_FUNCTIONS_EXAMINED=0
declare -g _LAMBDA_LIST_TRUNCATED=0
declare -gA _LAMBDA_EVALUATED=()
declare -gA _LAMBDA_LOST=()
declare -gA _LAMBDA_LOST_REASON=()

# Every check id this pass can emit, in registry order - lambda_engine.sh's
# own `_S3_CHECK_IDS`-shaped comment applies verbatim: spelled once here and
# read by the selection gate, the `checks_run` roll-up and the
# not-evaluated accounting alike.
declare -ga _LAMBDA_CHECK_IDS=(
  CLOUD-LAMBDA-ROLE_WILDCARD-01
  CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01
  CLOUD-LAMBDA-PUBLIC_FUNCTION_URL-01
  CLOUD-LAMBDA-PUBLIC_POLICY-01
  CLOUD-LAMBDA-ENV_SECRET-01
  CLOUD-LAMBDA-ENV_NOT_ENCRYPTED-01
)

# `_lambda_selected ID` - s3.sh's own `_s3_selected`, copied: the
# `declare -F` guard is PERMISSIVE when the function is absent, and inverting
# that is the trap modules/dast/engine.sh's `dast_check_selected` header
# records at length - a direct-engine test suite sources this script with no
# module engine in the process, so a fail-CLOSED default would make the whole
# pass inert while every "stays quiet" assertion in that suite still passed
# green.
_lambda_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_lambda_note_evaluated() {
  _LAMBDA_EVALUATED[$1]=$(( ${_LAMBDA_EVALUATED[$1]:-0} + 1 ))
}

_lambda_note_lost() {
  _LAMBDA_LOST[$1]=$(( ${_LAMBDA_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, s3.sh's own reasoning: the earliest failure is usually
  # the actionable one and the one that explains the rest.
  [[ -n ${_LAMBDA_LOST_REASON[$1]:-} ]] || _LAMBDA_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_lambda_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  # `mktemp -d`, never a fixed or pid-derived name - s3.sh's own header states
  # the CWE-377/CWE-59 reasoning at length; a TEMPLATE with no `-p` (tension
  # 24: `-p` is a GNU spelling).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-lambda.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_LAMBDA_CHECK_IDS[@]+"${_LAMBDA_CHECK_IDS[@]}"}"; do
    _lambda_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_lambda_checks_deselected service=lambda account=$account region=$region - every CLOUD-LAMBDA-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no Lambda API call was made and no function was examined."
    return 0
  fi

  # Vendored data files. A load failure degrades only the ONE check that
  # depends on it (recorded per-function below, via the same coverage_reduction
  # accounting every other lost call uses) rather than aborting the pass -
  # modules/dast/authz_engine.sh's own `authz_sensitive_load` establishes the
  # identical "an absent list is a declared reduction, not a fatal error"
  # contract.
  declare -a _LAMBDA_SECRET_KEYWORDS=()
  lambda_secret_keywords_load || true
  declare -g _LAMBDA_SENSITIVE_SERVICES=''
  lambda_sensitive_services_load || true

  # -------------------------------------------------------------------------
  # The one per-region call.
  # -------------------------------------------------------------------------
  local listf=$work/list-functions.json rc=0
  aws_ro lambda list-functions >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=lambda operation=list-functions account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the function list for this region could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO Lambda function was examined and none of the ${#_LAMBDA_CHECK_IDS[@]} CLOUD-LAMBDA-* checks ran in this region."
    run_record coverage_gap "cloud lambda: the function list for account $account in region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no function's execution role, function URL, resource policy or environment variables were tested in this region. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds lambda:ListFunctions."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _LAMBDA_LIST_TRUNCATED=1
  fi

  # -------------------------------------------------------------------------
  # Extract every function's identifying facts AND run the two checks that
  # need nothing beyond this already-loaded response (ENV_SECRET,
  # ENV_NOT_ENCRYPTED), BEFORE any later call clobbers `_LAMBDA_DOC` - the
  # discipline lambda_engine.sh's own `lambda_doc_load` header states.
  # -------------------------------------------------------------------------
  lambda_doc_load "$listf" || true
  local -a fn_arn=() fn_name=() fn_role=()
  local i=0 arn='' name='' role=''
  while lambda_function_field arn "$i" FunctionArn; do
    [[ -n $arn ]] || { i=$(( i + 1 )); continue; }
    lambda_function_field name "$i" FunctionName || true
    lambda_function_field role "$i" Role || true
    fn_arn+=("$arn")
    fn_name+=("$name")
    fn_role+=("$role")
    _lambda_examine_env "$i" "$arn" "$region"
    i=$(( i + 1 ))
  done
  _LAMBDA_FUNCTIONS_TOTAL=${#fn_arn[@]}

  local j
  for (( j = 0; j < ${#fn_arn[@]}; j++ )); do
    _LAMBDA_FUNCTIONS_EXAMINED=$(( _LAMBDA_FUNCTIONS_EXAMINED + 1 ))
    _lambda_examine_function "${fn_arn[j]}" "${fn_name[j]}" "${fn_role[j]}" "$region" "$work"
  done

  _lambda_record_coverage "$account" "$region"
  return 0
}

# `_lambda_examine_env I ARN REGION` - CLOUD-LAMBDA-ENV_SECRET-01 and
# CLOUD-LAMBDA-ENV_NOT_ENCRYPTED-01, read directly off the already-loaded
# `list-functions` response for function index I. Never returns non-zero.
_lambda_examine_env() {
  local i=$1 arn=$2 region=$3
  local secret_id=CLOUD-LAMBDA-ENV_SECRET-01
  local enc_id=CLOUD-LAMBDA-ENV_NOT_ENCRYPTED-01

  local decrypt_error=0
  lambda_env_error_present "$i" && decrypt_error=1
  local keys=''
  (( decrypt_error )) || lambda_env_keys_set keys "$i"
  # A decrypt error still means the function HAS environment variables
  # configured (that is the only way to get one) - it is what makes
  # ENV_NOT_ENCRYPTED's own "does this function have any env vars at all"
  # question true even though `keys` itself came back empty.
  local has_env=0
  if (( decrypt_error )) || [[ -n $keys ]]; then has_env=1; fi

  if _lambda_selected "$secret_id"; then
    if (( decrypt_error )); then
      _lambda_note_lost "$secret_id" env_decrypt_error
      run_record coverage_reduction "module=cloud reason=env_decrypt_error service=lambda operation=list-functions function=$arn region=$region - this function's environment variables could not be decrypted (Environment.Error was set), so neither their names nor their values could be inspected for a credential-shaped entry."
    elif [[ -z $keys ]]; then
      # No environment variables at all - a real, clean answer, vacuously
      # covered.
      _lambda_note_evaluated "$secret_id"
    elif (( ${#_LAMBDA_SECRET_KEYWORDS[@]} == 0 )); then
      _lambda_note_lost "$secret_id" secret_keywords_unavailable
      run_record coverage_reduction "module=cloud reason=secret_keywords_unavailable service=lambda check=$secret_id function=$arn region=$region - modules/cloud/aws/live/lambda-secret-env-keywords.txt could not be read, so this function's environment-variable names were not matched against it."
    else
      _lambda_note_evaluated "$secret_id"
      local key norm val shape
      while IFS= read -r key; do
        [[ -n $key ]] || continue
        norm=$(lambda_normalise_env_key "$key")
        if lambda_secret_keyword_matches "$norm"; then
          _lambda_emit "$secret_id" "$arn" "$region" "$key" \
            "Environment variable $key on function $arn ($region) has a name that reads as credential-shaped (matched against modules/cloud/aws/live/lambda-secret-env-keywords.txt). Lambda environment variables are visible in plaintext to anyone who can call lambda:GetFunctionConfiguration on this function, which is routinely a broader set of principals than the ones the credential itself is meant to be scoped to."
        else
          val=''
          lambda_env_value_get val "$i" "$key" || true
          shape=''
          if shape=$(lambda_secret_value_shape "$val"); then
            _lambda_emit "$secret_id" "$arn" "$region" "$key" \
              "Environment variable $key on function $arn ($region) holds a value shaped like $shape, visible in plaintext to anyone who can call lambda:GetFunctionConfiguration on this function."
          fi
        fi
      done <<<"$keys"
    fi
  fi

  if _lambda_selected "$enc_id"; then
    if (( has_env )); then
      _lambda_note_evaluated "$enc_id"
      local kms=''
      lambda_function_field kms "$i" KMSKeyArn || true
      if [[ -z $kms ]]; then
        _lambda_emit "$enc_id" "$arn" "$region" '' \
          "Function $arn ($region) has environment variables configured but no customer-managed KMS key set to encrypt them (KMSKeyArn is absent), so they are protected only by the AWS-owned default key - which cannot be rotated, restricted with its own key policy, or have its usage audited separately from every other function relying on that same default key."
      fi
    fi
    # A function with NO environment variables at all has nothing this check
    # is about; it is neither a finding nor a reduction, the identical
    # "nothing to look at" reasoning s3.sh's own zero-bucket case states.
  fi
  return 0
}

# `_lambda_examine_function ARN NAME ROLE_ARN REGION WORKDIR` - the per-function
# drill-down calls (function URL, resource policy, execution role). Never
# returns non-zero: a function that cannot be fully examined is an
# accounted-for reduction, not a reason to abandon the ones after it.
_lambda_examine_function() {
  local arn=$1 name=$2 role_arn=$3 region=$4 work=$5
  local safe=${name//[^A-Za-z0-9._-]/_}

  _lambda_check_url "$arn" "$name" "$region" "$work/$safe.url.json"
  _lambda_check_policy "$arn" "$name" "$region" "$work/$safe.policy.json"
  _lambda_check_role "$arn" "$role_arn" "$region" "$work/$safe-role"
  return 0
}

_lambda_check_url() {
  local arn=$1 name=$2 region=$3 f=$4
  local id=CLOUD-LAMBDA-PUBLIC_FUNCTION_URL-01
  _lambda_selected "$id" || return 0
  local rc=0
  aws_ro lambda list-function-url-configs --function-name "$name" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _lambda_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=lambda operation=list-function-url-configs function=$arn region=$region checks=[$id] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this function's function-URL configuration was NOT tested."
    return 0
  fi
  lambda_doc_load "$f" || true
  _lambda_note_evaluated "$id"
  local urls=''
  lambda_url_public_urls_set urls || return 0
  local url
  while IFS= read -r url; do
    [[ -n $url ]] || continue
    _lambda_emit "$id" "$arn" "$region" "$url" \
      "Function $arn ($region) has a function URL ($url) configured with AuthType NONE, so any request over the internet invokes it with no AWS SigV4 authentication at all. Set AuthType to AWS_IAM and grant lambda:InvokeFunctionUrl to only the principals that need it, or front the URL with an authenticating layer (API Gateway with its own authorizer, CloudFront with signed requests) if anonymous access is genuinely required for a subset of callers."
  done <<<"$urls"
  return 0
}

_lambda_check_policy() {
  local arn=$1 name=$2 region=$3 f=$4
  local id=CLOUD-LAMBDA-PUBLIC_POLICY-01
  _lambda_selected "$id" || return 0
  local rc=0
  aws_ro lambda get-policy --function-name "$name" >"$f" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # ResourceNotFoundException: the function has no resource-based policy
      # at all, so it is not public by way of one. A real answer, and the
      # commonest one for a function nothing else in the account invokes.
      _lambda_note_evaluated "$id"
      return 0
    fi
    local reason=''
    aws_ro_reduction_reason_set reason
    _lambda_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=lambda operation=get-policy function=$arn region=$region checks=[$id] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this function's resource-based policy was NOT tested."
    return 0
  fi
  lambda_doc_load "$f" || true
  _lambda_note_evaluated "$id"
  # `lambda_policy_prefix_set` needs a WORKDIR to reload `Policy`'s embedded
  # JSON string into (`lambda get-policy`'s `Policy` field is always a string -
  # see lambda_engine.sh section 4's own header) - `${f%/*}` is the per-pass
  # workdir this response file itself was written under.
  local prefix=''
  lambda_policy_prefix_set prefix Policy "${f%/*}" || return 0
  lambda_policy_public_principal "$prefix" || return 0
  _lambda_emit "$id" "$arn" "$region" '' \
    "The resource-based policy on function $arn ($region) has an Allow statement whose Principal is, or includes, \"*\" (rather than a specific account, role or AWS-service principal), so any AWS principal - or, combined with lambda:InvokeFunctionUrl, an unauthenticated caller - can invoke this function unless a Condition on the statement narrows it. Review the statement's Condition block: a real narrowing (aws:SourceArn, aws:SourceAccount) may make this an intentional, scoped grant rather than a public one; there is no server-evaluated \"is this policy public\" API for Lambda the way there is for S3, so this is a pattern match rather than AWS's own verdict."
  return 0
}

_lambda_check_role() {
  local arn=$1 role_arn=$2 region=$3 workprefix=$4
  local wid=CLOUD-LAMBDA-ROLE_WILDCARD-01
  local sid=CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01
  _lambda_selected "$wid" || _lambda_selected "$sid" || return 0
  [[ -n $role_arn ]] || return 0

  local role_name
  role_name=$(lambda_role_name_of "$role_arn")

  local admin=0 sensitive='' admin_policy='' status=0
  _lambda_classify_role "$role_name" "$arn" "$region" "$workprefix" admin sensitive admin_policy \
    || status=$?

  if (( status == 1 )); then
    # Total loss: neither the inline nor the attached-policy half of this
    # role could be read at all. _lambda_classify_role has already recorded
    # its own coverage_reduction naming which calls failed; this is the
    # per-check accounting those calls feed.
    _lambda_selected "$wid" && _lambda_note_lost "$wid" role_unreadable
    _lambda_selected "$sid" && _lambda_note_lost "$sid" role_unreadable
    return 0
  fi

  _lambda_selected "$wid" && _lambda_note_evaluated "$wid"
  _lambda_selected "$sid" && _lambda_note_evaluated "$sid"

  if (( admin )) && _lambda_selected "$wid"; then
    _lambda_emit "$wid" "$arn" "$region" "$admin_policy" \
      "The execution role for function $arn ($region) ($role_arn) grants an Allow statement with Action \"*\" on Resource \"*\" in its $admin_policy policy - full account-wide administrative access from the moment this function's code, a dependency, or an injected input can influence what it does. Replace the policy with the specific actions and resource ARNs the function actually calls (AWS IAM Access Analyzer's policy generation, run against this role's own CloudTrail activity, is the fastest path to a scoped replacement)."
  fi
  if [[ -n $sensitive ]] && _lambda_selected "$sid"; then
    local svc
    for svc in $sensitive; do
      _lambda_emit "$sid" "$arn" "$region" "$svc" \
        "The execution role for function $arn ($region) ($role_arn) grants an Allow statement with a wildcard '$svc:*' action, beyond what a function's own runtime needs and reaching into a sensitive AWS service (modules/cloud/aws/live/lambda-sensitive-services.txt names why $svc is on this list). Narrow the action list to the specific $svc calls the function actually makes."
    done
  fi
  return 0
}

# `_lambda_classify_role ROLE_NAME FUNCTION_ARN REGION WORKPREFIX ADMINVAR SENSITIVEVAR ADMIN_POLICYVAR`
#
# Reads every inline and attached-managed policy on ROLE_NAME and folds
# lambda_engine.sh's `lambda_policy_scan` verdict across all of them. Returns
# 0 on a FULL OR PARTIAL read (at least one of the inline/attached halves
# answered; the other, if it failed, has already had its own
# coverage_reduction recorded here) and 1 when NEITHER half answered at all -
# the only case the caller treats as a total loss for both checks.
#
# EMITS FINDINGS PER FUNCTION, NEVER PER ROLE, even though several functions
# routinely share one execution role: the resource under audit throughout
# this file is the FUNCTION (`list-functions` is what this pass walks), and a
# function relying on an over-permissive role is exactly as exposed as one
# with its own - reporting the role's own defect once and leaving every OTHER
# function that shares it silent would be the overstated-coverage failure
# docs/DESIGN.md §15 forbids. `aws_ro`'s own response cache (keyed on
# service|region|account|op|args) is what keeps this affordable: two
# functions sharing a role make the identical `iam get-role-policy` call and
# the second is served from cache rather than re-fetched.
# EVERY LOCAL BELOW IS `__`-PREFIXED. This function receives three
# caller-chosen output-variable NAMES (`__adminvar`/`__sensitivevar`/
# `__policyvar`) and writes through them with `printf -v`; lib/awscli.sh's
# `aws_ro_account_id_set` states why every one of ITS OWN internal locals
# must therefore avoid the caller's chosen names too - `local` shadows, so an
# internal accumulator that happens to share the caller's output name writes
# to its own copy and the caller reads an unset variable. This file's first
# draft named the accumulator `admin` and called this function as
# `_lambda_classify_role ... admin sensitive admin_policy` from
# `_lambda_check_role` below - `printf -v admin` then silently targeted this
# function's OWN local `admin` instead of the caller's, and the caller's
# `admin` stayed `0` regardless of what the role actually granted.
_lambda_classify_role() {
  local __role_name=$1 __arn=$2 __region=$3 __workprefix=$4
  local __adminvar=$5 __sensitivevar=$6 __policyvar=$7

  mkdir -p "$__workprefix"
  local __sensitive_list=${_LAMBDA_SENSITIVE_SERVICES:-}
  local __admin=0 __admin_policy='' __sensitive_set='' __answered=0

  # -- inline policies --------------------------------------------------
  local __rc=0 __f=$__workprefix/list-role-policies.json
  aws_ro iam list-role-policies --role-name "$__role_name" >"$__f" || __rc=$?
  if (( __rc == 0 )); then
    __answered=1
    lambda_doc_load "$__f" || true
    local __names='' __pname __prc __pf __pprefix __a __s
    lambda_field_values_set __names PolicyNames || true
    while IFS= read -r __pname; do
      [[ -n $__pname ]] || continue
      __prc=0
      __pf=$__workprefix/inline-$__pname.json
      aws_ro iam get-role-policy --role-name "$__role_name" --policy-name "$__pname" >"$__pf" || __prc=$?
      if (( __prc != 0 )); then
        run_record coverage_reduction "module=cloud reason=aws_api_$SCOURSH_AWS_RO_OUTCOME service=lambda operation=get-role-policy role=$__role_name policy=$__pname function=$__arn region=$__region checks=[CLOUD-LAMBDA-ROLE_WILDCARD-01,CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01] - the call did not answer, so this one inline policy on the function's execution role was NOT inspected; every other policy on the role was still evaluated."
        continue
      fi
      lambda_doc_load "$__pf" || true
      __pprefix=''
      lambda_policy_prefix_set __pprefix PolicyDocument "$__workprefix" || continue
      __a=0; __s=''
      lambda_policy_scan "$__pprefix" __a __s "$__sensitive_list"
      if (( __a )) && (( ! __admin )); then __admin=1; __admin_policy=$__pname; fi
      __sensitive_set="$__sensitive_set $__s"
    done <<<"$__names"
  else
    run_record coverage_reduction "module=cloud reason=aws_api_$SCOURSH_AWS_RO_OUTCOME service=lambda operation=list-role-policies role=$__role_name function=$__arn region=$__region checks=[CLOUD-LAMBDA-ROLE_WILDCARD-01,CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01] - the call did not answer, so this role's inline policies were NOT inspected."
  fi

  # -- attached managed policies -----------------------------------------
  __rc=0
  __f=$__workprefix/list-attached-role-policies.json
  aws_ro iam list-attached-role-policies --role-name "$__role_name" >"$__f" || __rc=$?
  if (( __rc == 0 )); then
    __answered=1
    lambda_doc_load "$__f" || true
    local __parn __parc __pdf __pverf __verid __pprefix2 __a2 __s2
    # `AttachedPolicies` is an array of OBJECTS ({PolicyName, PolicyArn}), not
    # scalars, so `lambda_field_values_set`'s scalar-or-array reader (built
    # for Action/Resource/Principal.AWS, which are never object arrays) does
    # not apply here; the ARNs are read directly, one index at a time.
    local __k=0
    while lambda_doc_has "$(lambda_path AttachedPolicies "$__k" PolicyArn)"; do
      lambda_doc_get __parn "$(lambda_path AttachedPolicies "$__k" PolicyArn)" || true
      __k=$(( __k + 1 ))
      [[ -n $__parn ]] || continue
      __parc=0
      __pdf=$__workprefix/policy-meta-$__k.json
      aws_ro iam get-policy --policy-arn "$__parn" >"$__pdf" || __parc=$?
      if (( __parc != 0 )); then
        run_record coverage_reduction "module=cloud reason=aws_api_$SCOURSH_AWS_RO_OUTCOME service=lambda operation=get-policy role=$__role_name policy_arn=$__parn function=$__arn region=$__region checks=[CLOUD-LAMBDA-ROLE_WILDCARD-01,CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01] - the call did not answer, so this one attached managed policy on the function's execution role was NOT inspected."
        continue
      fi
      lambda_doc_load "$__pdf" || true
      __verid=''
      lambda_doc_get __verid "$(lambda_path Policy DefaultVersionId)" || true
      [[ -n $__verid ]] || continue
      __pverf=$__workprefix/policy-ver-$__k.json
      __parc=0
      aws_ro iam get-policy-version --policy-arn "$__parn" --version-id "$__verid" >"$__pverf" || __parc=$?
      if (( __parc != 0 )); then
        run_record coverage_reduction "module=cloud reason=aws_api_$SCOURSH_AWS_RO_OUTCOME service=lambda operation=get-policy-version role=$__role_name policy_arn=$__parn function=$__arn region=$__region checks=[CLOUD-LAMBDA-ROLE_WILDCARD-01,CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01] - the call did not answer, so this attached managed policy's document was NOT inspected."
        continue
      fi
      lambda_doc_load "$__pverf" || true
      __pprefix2=''
      lambda_policy_prefix_set __pprefix2 "$(lambda_path PolicyVersion Document)" "$__workprefix" || continue
      __a2=0; __s2=''
      lambda_policy_scan "$__pprefix2" __a2 __s2 "$__sensitive_list"
      if (( __a2 )) && (( ! __admin )); then __admin=1; __admin_policy=$__parn; fi
      __sensitive_set="$__sensitive_set $__s2"
    done
  else
    run_record coverage_reduction "module=cloud reason=aws_api_$SCOURSH_AWS_RO_OUTCOME service=lambda operation=list-attached-role-policies role=$__role_name function=$__arn region=$__region checks=[CLOUD-LAMBDA-ROLE_WILDCARD-01,CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01] - the call did not answer, so this role's attached managed policies were NOT inspected."
  fi

  (( __answered )) || return 1

  printf -v "$__adminvar" '%s' "$__admin"
  printf -v "$__policyvar" '%s' "$__admin_policy"
  printf -v "$__sensitivevar" '%s' \
    "$(printf '%s\n' "$__sensitive_set" | tr ' ' '\n' | LC_ALL=C sort -u | tr '\n' ' ' | sed -e 's/^ *//' -e 's/ *$//')"
  return 0
}

# `_lambda_emit CHECK_ID ARN REGION SUB_KEY EVIDENCE` - thin wrapper over the
# engine's emitter, s3.sh's own reason for having one: a call site never has
# to remember the argument order twice over.
_lambda_emit() {
  lambda_emit_finding "$1" "$2" "$3" "$4" "$5"
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one
# function, and one `coverage_reduction` per check that did not - s3.sh's own
# `_s3_record_coverage`, copied and re-keyed to lambda's own arrays and to the
# region cell (`account/region`, not `account/global` - `lambda` is regional).
_lambda_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_LAMBDA_CHECK_IDS[@]+"${_LAMBDA_CHECK_IDS[@]}"}"; do
    _lambda_selected "$id" || continue
    if (( ${_LAMBDA_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_LAMBDA_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_LAMBDA_LOST_REASON[$id]} service=lambda check=$id account=$account region=$region functions_answered=${_LAMBDA_EVALUATED[$id]} functions_unanswered=${_LAMBDA_LOST[$id]} of ${_LAMBDA_FUNCTIONS_TOTAL} - this check ran, but ${_LAMBDA_LOST[$id]} function(s) did not answer, so it is covered for some of this region's functions and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_LAMBDA_LOST_REASON[$id]:-no_function_examined} service=lambda check=$id account=$account region=$region functions_total=${_LAMBDA_FUNCTIONS_TOTAL} functions_examined=${_LAMBDA_FUNCTIONS_EXAMINED} - this check answered for NO function in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every function is configured correctly."
    fi
  done

  if (( _LAMBDA_FUNCTIONS_TOTAL == 0 )); then
    # A genuinely empty region. The checks above are still credited: the
    # function list was read successfully, so the run DID look and there was
    # nothing to look at - s3.sh's own zero-bucket reasoning, applied here.
    run_record notes "module=cloud service=lambda account=$account region=$region functions=0 - the region's function list was read successfully and contains no function, so every CLOUD-LAMBDA-* check is covered vacuously."
  fi

  if (( _LAMBDA_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=lambda operation=list-functions account=$account region=$region functions_seen=$_LAMBDA_FUNCTIONS_TOTAL - the function list came back INCOMPLETE (a continuation token was present, or the page ceiling was reached), so an unknown number of this region's functions were never enumerated and were not examined by any CLOUD-LAMBDA-* check."
    run_record coverage_gap "cloud lambda: the function list for account $account in region $region was truncated at $_LAMBDA_FUNCTIONS_TOTAL function(s), so an unknown number of functions were never examined. A clean result for those functions is the absence of a test, not the absence of a problem."
  fi

  if (( ran == 0 && _LAMBDA_FUNCTIONS_TOTAL > 0 )); then
    run_record coverage_gap "cloud lambda: account $account region $region has $_LAMBDA_FUNCTIONS_TOTAL function(s) and NOT ONE of the ${#_LAMBDA_CHECK_IDS[@]} CLOUD-LAMBDA-* checks answered for any of them, so no function's execution role, exposure or environment variables were tested in this region. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_lambda_run_service
