#!/usr/bin/env bash
# modules/cloud/aws/live/ecr.sh - the §8.1 ECR read-only service pass
# (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-25).
#
# THIS IS A SERVICE SCRIPT: `cloud_run_service` reaches it with a plain
# `source`, so it inherits the whole run context and carries NO sourced-once
# guard - see modules/cloud/aws/live/s3.sh's own header for why one would be
# the failure that reads as a complete multi-region audit.  `ecr` is
# `regional` in `_CLOUD_SERVICES`, so this file runs once per enabled
# region, with `SCOURSH_CLOUD_REGION` already set to that region and the
# ambient `aws_ro` region already pointed at it - unlike s3.sh, no call here
# ever passes its own `--region`.
#
# TWO CALLS, NOT SEVEN.  `describe-repositories` (the list) already carries
# `imageTagMutability` and `imageScanningConfiguration.scanOnPush` per
# repository, so CLOUD-ECR-MUTABLE_TAGS-01 and
# CLOUD-ECR-SCAN_ON_PUSH_OFF-01 are classified straight off it with no
# per-repository call at all.  Only CLOUD-ECR-PUBLIC_REPOSITORY-01 needs one,
# because a repository's resource policy is not part of the list response.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, exactly as s3.sh's own header
# states it: `checks_run` names what SUCCEEDED, an AccessDenied is a
# `coverage_reduction` never silence, and `RepositoryPolicyNotFoundException`
# is an ANSWER ("this repository has no policy, so it is not public") rather
# than a coverage loss - the identical shape s3.sh's `NoSuchBucketPolicy`
# handling documents.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation at each call site (docs/FOUNDATION.md tension 23) -
# never through a local wrapper, because tests/lint-aws-readonly.sh parses
# the operation out of the source line.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/ecr_engine.sh
source "${BASH_SOURCE[0]%/*}/ecr_engine.sh"
# shellcheck source=modules/cloud/aws/live/iam_policy_engine.sh
source "${BASH_SOURCE[0]%/*}/iam_policy_engine.sh"

# `declare -g`, for the reason ecr_engine.sh's own globals carry it: this
# file is sourced from INSIDE `cloud_run_service`, a function, where a bare
# `declare` would make every one of these a local that dies with the pass.
# Reset here (not only declared) so a second pass in one process - two
# regions in one run - starts each with a clean slate.
declare -g _ECR_REPOS_TOTAL=0
declare -g _ECR_REPOS_EXAMINED=0
declare -g _ECR_LIST_TRUNCATED=0
declare -gA _ECR_EVALUATED=()
declare -gA _ECR_LOST=()
declare -gA _ECR_LOST_REASON=()

declare -ga _ECR_CHECK_IDS=(
  CLOUD-ECR-PUBLIC_REPOSITORY-01
  CLOUD-ECR-SCAN_ON_PUSH_OFF-01
  CLOUD-ECR-MUTABLE_TAGS-01
)

# `_ecr_selected ID` - as s3.sh's `_s3_selected`: permissive when no module
# engine is loaded (a direct-engine test), the identical trap
# modules/dast/engine.sh's own `dast_check_selected` header records at
# length.
_ecr_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_ecr_note_evaluated() {
  _ECR_EVALUATED[$1]=$(( ${_ECR_EVALUATED[$1]:-0} + 1 ))
}

_ecr_note_lost() {
  _ECR_LOST[$1]=$(( ${_ECR_LOST[$1]:-0} + 1 ))
  # FIRST reason wins - s3.sh's own reasoning: the earliest failure is the
  # one that explains every later one, and is the actionable report.
  [[ -n ${_ECR_LOST_REASON[$1]:-} ]] || _ECR_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_ecr_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-ecr.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_ECR_CHECK_IDS[@]+"${_ECR_CHECK_IDS[@]}"}"; do
    _ecr_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_ecr_checks_deselected service=ecr account=$account region=$region - every CLOUD-ECR-* check id was removed by this run's check-selection filters, so no ECR API call was made and no repository was examined."
    return 0
  fi

  local listf=$work/describe-repositories.json rc=0
  aws_ro ecr describe-repositories >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=ecr operation=describe-repositories account=$account region=$region - the repository list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO repository was examined and none of the ${#_ECR_CHECK_IDS[@]} CLOUD-ECR-* checks ran."
    run_record coverage_gap "cloud ecr: the repository list for account $account in $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no repository's exposure, scanning or tag-mutability configuration was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds ecr:DescribeRepositories."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _ECR_LIST_TRUNCATED=1
  fi

  ecr_doc_load "$listf" || true
  local i=0
  local -a names=() arns=()
  while :; do
    ecr_doc_has "$(ecr_path repositories "$i" repositoryName)" || break
    local n='' a=''
    ecr_repo_name_set n "$i"
    ecr_repo_arn_set a "$i"
    if [[ -n $n ]]; then
      names+=("$n")
      arns+=("$a")
    fi
    i=$(( i + 1 ))
  done
  _ECR_REPOS_TOTAL=${#names[@]}

  local j
  for (( j = 0; j < ${#names[@]}; j++ )); do
    _ecr_examine_repo "$j" "${names[$j]}" "${arns[$j]}" "$work" "$listf"
  done

  _ecr_record_coverage "$account" "$region"
  return 0
}

# `_ecr_examine_repo IDX NAME ARN WORKDIR LISTFILE` - the two direct
# classifications off the list document, plus the one per-repository call
# for public exposure.  Never returns non-zero: a repository that cannot be
# examined is an accounted-for reduction, not a reason to abandon the ones
# after it.
#
# LISTFILE IS RELOADED HERE, FIRST, EVERY ITERATION, AND THAT IS LOAD-
# BEARING RATHER THAN DEFENSIVE.  `ecr_doc_load` (like every other engine's
# own `*_doc_load`) repopulates the SHARED `_ECR_DOC`/`_ECR_DOCT` globals in
# place, and `_ecr_check_public`'s own `ecr_doc_load "$polf"` call below
# does exactly that for the PER-REPOSITORY policy response - which means
# the describe-repositories document this function's own two direct
# classifiers read is only intact for repository 0; from repository 1
# onward, without this reload, `_ECR_DOC` would still be holding whatever
# the PREVIOUS repository's policy call last loaded, and every path this
# function looks up would resolve to nothing - which
# `ecr_repo_scan_on_push_off`'s own "an absent key is off, not on" rule then
# reads as scan-on-push being OFF on every repository after the first,
# regardless of what it actually is.  Measured directly: this is the
# defect tests/suites/cloud-ecr.sh's own section B exists to catch, and did.
_ecr_examine_repo() {
  local idx=$1 name=$2 arn=$3 work=$4 listf=$5
  _ECR_REPOS_EXAMINED=$(( _ECR_REPOS_EXAMINED + 1 ))
  ecr_doc_load "$listf" || true

  if _ecr_selected CLOUD-ECR-MUTABLE_TAGS-01; then
    _ecr_note_evaluated CLOUD-ECR-MUTABLE_TAGS-01
    if ecr_repo_tags_mutable "$idx"; then
      ecr_emit_finding CLOUD-ECR-MUTABLE_TAGS-01 "$arn" '' \
        "Repository $name ($arn) has image tag mutability set to MUTABLE, so a tag like :latest or :prod can be silently repointed to a different image after the fact - a deployment or a signature check that trusted the tag rather than the image digest can be undermined without any change to the tag string an operator would notice. Set the repository's tag mutability to IMMUTABLE so a tag, once pushed, can never be reused for a different image; a deployment pipeline that needs to move a tag should push a new one instead."
    fi
  fi

  if _ecr_selected CLOUD-ECR-SCAN_ON_PUSH_OFF-01; then
    _ecr_note_evaluated CLOUD-ECR-SCAN_ON_PUSH_OFF-01
    if ecr_repo_scan_on_push_off "$idx"; then
      ecr_emit_finding CLOUD-ECR-SCAN_ON_PUSH_OFF-01 "$arn" '' \
        "Repository $name ($arn) does not have scan-on-push enabled (imageScanningConfiguration.scanOnPush is not true), so an image is never checked for known-vulnerable packages at the moment it is pushed. Enable scan-on-push, or a registry-wide scanning configuration, so a vulnerable base image or dependency is flagged before anything deploys it rather than discovered later by a separate audit."
    fi
  fi

  _ecr_check_public "$idx" "$name" "$arn" "$work"
  return 0
}

_ecr_check_public() {
  local idx=$1 name=$2 arn=$3 work=$4
  local id=CLOUD-ECR-PUBLIC_REPOSITORY-01
  _ecr_selected "$id" || return 0

  local safe=${name//[^A-Za-z0-9._-]/_}
  local polf=$work/policy-$safe.json rc=0
  aws_ro ecr get-repository-policy --repository-name "$name" >"$polf" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # RepositoryPolicyNotFoundException: no resource policy at all, so the
      # repository grants no principal anything beyond IAM's own permissions
      # - a real answer, the commonest one, and the mirror of s3.sh's
      # NoSuchBucketPolicy handling.
      _ecr_note_evaluated "$id"
      return 0
    fi
    local reason=''
    aws_ro_reduction_reason_set reason
    _ecr_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=ecr operation=get-repository-policy repository=$name - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this repository's exposure was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
    return 0
  fi

  _ecr_note_evaluated "$id"
  local text=''
  ecr_doc_load "$polf" || true
  ecr_doc_get text "$(ecr_path policyText)"
  [[ -n $text ]] || return 0

  iampol_doc_load_text "$text" || true
  local sid=''
  iampol_public_principal_grant_set sid || return 0
  ecr_emit_finding "$id" "$arn" "$sid" \
    "Repository $name ($arn) has a resource policy statement ($sid) with Effect Allow and a wildcard Principal, granting the action to anyone - either every AWS account (Principal.AWS: \"*\") or, if the pull is fronted by no other control, an anonymous caller. This is scoursh's own reading of the policy statement rather than an AWS-evaluated verdict (ECR has no equivalent of S3's get-bucket-policy-status), so confirm by reviewing the full policy with \`aws ecr get-repository-policy --repository-name $name\` before removing the statement. Scope the Principal to named account ids or roles, or remove the statement entirely if no cross-account pull was intended."
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_ecr_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_ECR_CHECK_IDS[@]+"${_ECR_CHECK_IDS[@]}"}"; do
    _ecr_selected "$id" || continue
    if (( ${_ECR_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_ECR_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_ECR_LOST_REASON[$id]} service=ecr check=$id account=$account region=$region repos_answered=${_ECR_EVALUATED[$id]} repos_unanswered=${_ECR_LOST[$id]} of ${_ECR_REPOS_TOTAL} - this check ran, but ${_ECR_LOST[$id]} repository(s) did not answer, so it is covered for some of the account's repositories and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_ECR_LOST_REASON[$id]:-no_repository_examined} service=ecr check=$id account=$account region=$region repos_total=${_ECR_REPOS_TOTAL} repos_examined=${_ECR_REPOS_EXAMINED} - this check answered for NO repository in $region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every repository is configured correctly."
    fi
  done

  if (( _ECR_REPOS_TOTAL == 0 )); then
    run_record notes "module=cloud service=ecr account=$account region=$region repositories=0 - the repository list was read successfully and contains no repository, so every CLOUD-ECR-* check is covered vacuously."
  fi

  if (( _ECR_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=ecr operation=describe-repositories account=$account region=$region repos_seen=$_ECR_REPOS_TOTAL - the repository list came back INCOMPLETE, so an unknown number of this region's repositories were never enumerated and were not examined by any CLOUD-ECR-* check."
    run_record coverage_gap "cloud ecr: the repository list for account $account in $region was truncated at $_ECR_REPOS_TOTAL repository(s), so an unknown number of repositories were never examined. A clean result for those repositories is the absence of a test, not the absence of a problem."
  fi

  if (( ran == 0 && _ECR_REPOS_TOTAL > 0 )); then
    run_record coverage_gap "cloud ecr: account $account region $region has $_ECR_REPOS_TOTAL repository(s) and NOT ONE of the ${#_ECR_CHECK_IDS[@]} CLOUD-ECR-* checks answered for any of them, so no repository's exposure, scanning or tag-mutability posture was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_ecr_run_service
