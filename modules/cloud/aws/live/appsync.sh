#!/usr/bin/env bash
# modules/cloud/aws/live/appsync.sh - the §8.5 AppSync / managed GraphQL
# read-only service pass (docs/DESIGN.md §8.5; docs/STEP6-CLOUD-PLAN.md
# CLOUD-23).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - `appsync` is a `regional` row in
# `_CLOUD_SERVICES`, so a run legitimately reaches this file once per enabled
# region, and a guard would silently make every region after the first a
# no-op, which is the failure that reads as a complete multi-region audit.
# Its pure half - the classifiers, the ARN builders and the emitter - is
# modules/cloud/aws/live/appsync_engine.sh, which does have one.
#
# WHY APPSYNC IS A `regional` ROW, UNLIKE S3.  A GraphQL API is created in one
# region and `list-graphql-apis` answers for whatever region is ambient when
# it is called - there is no S3-style account-wide list-then-resolve-location
# step, so this pass runs the way `dast_run_phase` and every other regional
# service does: once per enabled region, addressed to that region alone.
# `cloud_run_service` has already called `aws_ro_use_region` with this pass's
# region before sourcing this file, so every `aws_ro` call below inherits it
# with no `--region` argument of its own.
#
# §8.5's TWO CHECKS, IN ONE MULTI-CALL SEQUENCE: `list-graphql-apis`, then
# `list-api-keys --api-id <id>` once per API.  The first call already answers
# CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01 for every API it returns (the default
# `authenticationType` is a field of that same response); only
# CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01 needs the second, per-API call.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), spelled
# literally at each call site with a literal service and operation - never
# through a local wrapper taking the operation in a variable, for the reason
# modules/cloud/aws/live/s3.sh's own header gives at length: `tests/lint-aws-
# readonly.sh` parses the operation out of the source line, and a wrapper
# would make every call in this file invisible to the lint that certifies the
# read-only guarantee.  The response is redirected to a file rather than
# captured with `$(...)`, for `aws_ro_into`'s own stated reason - a command
# substitution runs in a subshell, so every `SCOURSH_AWS_RO_*` outcome global
# is set in a process that then exits and the caller reads pre-call values.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, exactly as s3.sh's own header
# states it:
#   1. `checks_run` NAMES WHAT SUCCEEDED.  A check id is recorded only if its
#      own data actually answered for at least one API.
#   2. AN `AccessDenied` (OR ANY OTHER COVERAGE-LOSS OUTCOME) IS A
#      `coverage_reduction`, NEVER SILENCE.  `aws_ro_outcome_is_coverage_loss`
#      is the single predicate that separates "we looked" from "we did not";
#      this file never re-derives that judgement.
#   3. UNLIKE S3, NEITHER CHECK HERE HAS A `NoSuch*`-SHAPED "absence IS the
#      answer" CASE.  A `list-api-keys` failure is always a coverage loss,
#      never a real answer meaning "no keys" - AWS reports zero keys with a
#      normal, successful, empty `apiKeys` array, not an error.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/appsync_engine.sh
source "${BASH_SOURCE[0]%/*}/appsync_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for the reason appsync_engine.sh's own note records: this file
# is sourced from INSIDE `cloud_run_service`, so a bare `declare` would make
# every one of these a local that dies with the pass.  They are reset here
# rather than only declared, because a second pass in one process (two
# `scan_main` calls in one test process, or this file reached again for a
# second region) must not inherit the previous pass's counters.
declare -g _APPSYNC_APIS_TOTAL=0
declare -g _APPSYNC_APIS_EXAMINED=0
declare -g _APPSYNC_LIST_TRUNCATED=0
declare -gA _APPSYNC_EVALUATED=()
declare -gA _APPSYNC_LOST=()
declare -gA _APPSYNC_LOST_REASON=()

# Every check id this pass can emit, in registry order.  Spelled once, here,
# and read by the selection gate, the `checks_run` roll-up and the
# not-evaluated accounting alike - three places that must agree about what
# "every AppSync check" means, and did not have to be kept in step by hand.
declare -ga _APPSYNC_CHECK_IDS=(
  CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01
  CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01
)

# `_appsync_selected ID` - tension 15's per-check filter, through the module
# engine's own `cloud_check_selected`.  THE `declare -F` GUARD IS PERMISSIVE
# WHEN THE FUNCTION IS ABSENT, and inverting that is the trap
# modules/dast/engine.sh's own `dast_check_selected` header records at
# length: a direct-engine test suite sources this script with no module
# engine in the process, so a fail-CLOSED default - or an unguarded call,
# which is exit 127 and therefore "deselected" - would make the whole pass
# inert while every "stays quiet" assertion in that suite still passed green.
# Nothing is unsafe about the permissive reading: with no engine loaded there
# is no `aws_ro` to call either.
_appsync_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

# `_appsync_note_evaluated ID` / `_appsync_note_lost ID REASON` - the two
# halves of honesty rule 1 above.  Kept as functions so a call site can never
# record one without the other being available beside it.
_appsync_note_evaluated() {
  _APPSYNC_EVALUATED[$1]=$(( ${_APPSYNC_EVALUATED[$1]:-0} + 1 ))
}

_appsync_note_lost() {
  _APPSYNC_LOST[$1]=$(( ${_APPSYNC_LOST[$1]:-0} + 1 ))
  # FIRST reason wins rather than last, for the identical reason
  # `_s3_note_lost` gives: a run whose first nine APIs were denied and whose
  # tenth was throttled should report the permission problem, which is the
  # actionable one and the one that explains the other nine.
  [[ -n ${_APPSYNC_LOST_REASON[$1]:-} ]] || _APPSYNC_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_appsync_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  # `mktemp -d`, never a name built from `$$` or a fixed string, for the
  # identical reason modules/cloud/aws/live/s3.sh's own `_s3_run_service`
  # gives at length (CWE-377 via CWE-59): a predictable name is one a local
  # user can pre-create as a symlink this process then writes THROUGH.
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-appsync.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_APPSYNC_CHECK_IDS[@]+"${_APPSYNC_CHECK_IDS[@]}"}"; do
    _appsync_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_appsync_checks_deselected service=appsync account=$account region=$region - every CLOUD-APPSYNC-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no AppSync API call was made and no GraphQL API was examined."
    return 0
  fi

  # -------------------------------------------------------------------------
  # The one per-region list call.
  # -------------------------------------------------------------------------
  local listf=$work/list-graphql-apis.json rc=0
  aws_ro appsync list-graphql-apis >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=appsync operation=list-graphql-apis account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's GraphQL API list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO API was examined and neither of the ${#_APPSYNC_CHECK_IDS[@]} CLOUD-APPSYNC-* checks ran in this region."
    run_record coverage_gap "cloud appsync: the GraphQL API list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no API's default authentication type or API key expiry was tested in this region. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds appsync:ListGraphqlApis."
    return 0
  fi
  # A truncated list is a SHORT list indistinguishable from a complete one -
  # the §4.3 gap lib/awscli.sh's truncation detection exists for.  The pass
  # still examines the APIs it did get; the bound is declared, not silent.
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _APPSYNC_LIST_TRUNCATED=1
  fi

  # -------------------------------------------------------------------------
  # The APIs.
  # -------------------------------------------------------------------------
  local -a api_ids=() api_names=() api_arns=() api_auths=()
  local i=0 aid='' aname='' aarn='' aauth=''
  appsync_doc_load "$listf" || true
  while :; do
    appsync_doc_has "$(appsync_path graphqlApis "$i" apiId)" || break
    aid='' aname='' aarn='' aauth=''
    appsync_doc_get aid "$(appsync_path graphqlApis "$i" apiId)"
    appsync_doc_get aname "$(appsync_path graphqlApis "$i" name)"
    appsync_doc_get aarn "$(appsync_path graphqlApis "$i" arn)"
    appsync_doc_get aauth "$(appsync_path graphqlApis "$i" authenticationType)"
    if [[ -n $aid ]]; then
      api_ids+=("$aid")
      api_names+=("$aname")
      # Prefer the REAL, observed ARN AWS returned; fall back to a
      # reconstructed one only when the field is somehow absent - see
      # appsync_engine.sh's own note on `appsync_api_arn`.
      [[ -n $aarn ]] || aarn=$(appsync_api_arn "$(appsync_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")" "$account" "$region" "$aid")
      api_arns+=("$aarn")
      api_auths+=("$aauth")
    fi
    i=$(( i + 1 ))
  done
  _APPSYNC_APIS_TOTAL=${#api_ids[@]}

  local j
  for (( j = 0; j < ${#api_ids[@]}; j++ )); do
    _appsync_examine_api "${api_ids[j]}" "${api_names[j]}" "${api_arns[j]}" "${api_auths[j]}" "$work" "$region"
  done

  _appsync_record_coverage "$account" "$region"
  return 0
}

# `_appsync_examine_api API_ID API_NAME API_ARN AUTH_TYPE WORKDIR REGION` -
# the two checks over one API.  Never returns non-zero: an API that cannot be
# fully examined is an accounted-for reduction, not a reason to abandon the
# ones after it.
_appsync_examine_api() {
  local api_id=$1 api_name=$2 api_arn=$3 auth_type=$4 work=$5 region=$6
  local safe=${api_id//[^A-Za-z0-9._-]/_}

  _APPSYNC_APIS_EXAMINED=$(( _APPSYNC_APIS_EXAMINED + 1 ))

  _appsync_check_default_auth "$api_id" "$api_name" "$api_arn" "$auth_type" "$region"
  _appsync_check_key_expiry "$api_id" "$api_name" "$api_arn" "$region" "$work/$safe.keys.json"
  return 0
}

# `_appsync_call_lost API_ID OPERATION IDS...` - shared tail for a per-API
# call that failed in a way that is a coverage loss rather than an answer.
_appsync_call_lost() {
  local api_id=$1 op=$2
  shift 2
  local reason='' cid
  aws_ro_reduction_reason_set reason
  for cid in "$@"; do
    _appsync_note_lost "$cid" "$reason"
  done
  run_record coverage_reduction "module=cloud reason=$reason service=appsync operation=$op api_id=$api_id checks=[$*] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this property of this API was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
  return 0
}

_appsync_check_default_auth() {
  local api_id=$1 api_name=$2 api_arn=$3 auth_type=$4 region=$5
  local id=CLOUD-APPSYNC-API_KEY_DEFAULT_AUTH-01
  _appsync_selected "$id" || return 0
  # `list-graphql-apis` already succeeded - this check reads a field of that
  # SAME response, so there is no second call to fail.  An entry whose
  # `authenticationType` came back empty is a malformed/unexpected response
  # shape (the field is required by the API), and is left uncounted rather
  # than reported as either a finding or a coverage loss: the call itself
  # succeeded, so `_appsync_call_lost` (which records an `aws_ro` failure)
  # would be the wrong vocabulary for it.
  [[ -n $auth_type ]] || return 0
  _appsync_note_evaluated "$id"
  appsync_auth_type_is_key "$auth_type" || return 0
  appsync_emit_finding "$id" "$api_arn" "$region" '' \
    "AppSync API $api_name ($api_id, $region) uses API_KEY as its default authentication type rather than AWS_IAM, AMAZON_COGNITO_USER_POOLS, OPENID_CONNECT or AWS_LAMBDA. An API key is a static, bearer-style credential that carries no caller identity: whoever holds it - however it reached them - gets whatever access the schema grants an API-key caller, with no per-caller authorization, no MFA, and no revocation short of deleting the key itself. Additional authentication providers, if this API has any configured, do not change what the DEFAULT identity can do. Move the API onto AWS_IAM (for first-party, SigV4-signing callers) or Amazon Cognito user pools (for end users who need individual identity and fine-grained @aws_auth field authorization); reserve API_KEY, if it is kept at all, for a short-lived key used only during development."
  return 0
}

_appsync_check_key_expiry() {
  local api_id=$1 api_name=$2 api_arn=$3 region=$4 f=$5
  local id=CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01
  _appsync_selected "$id" || return 0
  local rc=0
  aws_ro appsync list-api-keys --api-id "$api_id" >"$f" || rc=$?
  if (( rc != 0 )); then
    _appsync_call_lost "$api_id" list-api-keys "$id"
    return 0
  fi
  _appsync_note_evaluated "$id"

  appsync_doc_load "$f" || true
  # Injectable "now", the identical seam modules/dast/passive/tls_engine.sh's
  # own `tls_expiry_state` calling convention establishes one layer down: a
  # classifier that read the system clock itself could never be pinned
  # deterministically against a committed fixture whose `expires` timestamp
  # is a fixed number, and would report a different verdict for the same
  # fixture depending on when the suite happened to run.
  # `SCOURSH_APPSYNC_NOW_EPOCH` exists ONLY for that seam; a real run never
  # sets it and gets the real clock.
  local now=${SCOURSH_APPSYNC_NOW_EPOCH:-}
  [[ -n $now ]] || now=$(date -u +%s)

  local k=0 kid='' expires='' state='' key_arn='' days=''
  while :; do
    appsync_doc_has "$(appsync_path apiKeys "$k" id)" || break
    kid='' expires=''
    appsync_doc_get kid "$(appsync_path apiKeys "$k" id)"
    appsync_doc_get expires "$(appsync_path apiKeys "$k" expires)"
    if [[ -n $kid && -n $expires ]]; then
      state=$(appsync_key_expiry_state "$expires" "$now" "$APPSYNC_KEY_LONG_EXPIRY_DAYS")
      if [[ $state == long_lived ]]; then
        key_arn=$(appsync_key_arn "$api_arn" "$kid")
        days=$(appsync_days_until "$expires" "$now")
        appsync_emit_finding "$id" "$key_arn" "$region" '' \
          "AppSync API key $kid on API $api_name ($api_id, $region) does not expire for $days more day(s) (AppSync's own maximum lifetime for an API key is 365 days from creation, and the default when none is specified is 7). The longer a static, unrotatable API key stays valid, the longer it remains useful if it is ever captured - copied into a mobile app's decompiled binary, committed to a repository, or read straight out of a JavaScript bundle a browser downloaded. Issue keys with a short lifetime (the 7-to-30-day range covers most legitimate uses) and rotate them before expiry, or move the API off API-key authentication onto AWS_IAM or Amazon Cognito, neither of which needs a static secret at all."
      fi
    fi
    k=$(( k + 1 ))
  done
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one API,
# and one `coverage_reduction` per check that did not - the accounting rule
# this file's header states as rule 1, and what `_cloud_record_coverage` reads
# to write the `<account>/<region>` coverage cell.
_appsync_record_coverage() {
  local account=$1 region=$2 id
  local ran=0 lost=0
  for id in "${_APPSYNC_CHECK_IDS[@]+"${_APPSYNC_CHECK_IDS[@]}"}"; do
    _appsync_selected "$id" || continue
    if (( ${_APPSYNC_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_APPSYNC_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_APPSYNC_LOST_REASON[$id]} service=appsync check=$id account=$account region=$region apis_answered=${_APPSYNC_EVALUATED[$id]} apis_unanswered=${_APPSYNC_LOST[$id]} of ${_APPSYNC_APIS_TOTAL} - this check ran, but ${_APPSYNC_LOST[$id]} API(s) did not answer, so it is covered for some of this region's APIs and not for others."
      fi
    else
      lost=$(( lost + 1 ))
      run_record coverage_reduction "module=cloud reason=${_APPSYNC_LOST_REASON[$id]:-no_api_examined} service=appsync check=$id account=$account region=$region apis_total=${_APPSYNC_APIS_TOTAL} apis_examined=${_APPSYNC_APIS_EXAMINED} - this check answered for NO API in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every API is configured correctly."
    fi
  done

  if (( _APPSYNC_APIS_TOTAL == 0 )); then
    # A genuinely empty region.  The checks above are still credited: the API
    # list was read successfully, so the run DID look and there was nothing
    # to look at - which is what lets a prior finding for an API that has
    # since been deleted be classified `fixed` rather than sitting at
    # `unknown` forever.
    run_record notes "module=cloud service=appsync account=$account region=$region apis=0 - the region's GraphQL API list was read successfully and contains no API, so every CLOUD-APPSYNC-* check is covered vacuously."
  fi

  if (( _APPSYNC_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=appsync operation=list-graphql-apis account=$account region=$region apis_seen=$_APPSYNC_APIS_TOTAL - the GraphQL API list came back INCOMPLETE (a continuation token was present, or the page ceiling was reached), so an unknown number of this region's APIs were never enumerated and were not examined by any CLOUD-APPSYNC-* check."
    run_record coverage_gap "cloud appsync: the GraphQL API list for account $account region $region was truncated at $_APPSYNC_APIS_TOTAL API(s), so an unknown number of APIs were never examined. A clean result for those APIs is the absence of a test, not the absence of a problem."
  fi

  if (( ran == 0 && _APPSYNC_APIS_TOTAL > 0 )); then
    run_record coverage_gap "cloud appsync: account $account region $region has $_APPSYNC_APIS_TOTAL API(s) and NOT ONE of the ${#_APPSYNC_CHECK_IDS[@]} CLOUD-APPSYNC-* checks answered for any of them, so no API's default authentication or API key expiry was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_appsync_run_service
