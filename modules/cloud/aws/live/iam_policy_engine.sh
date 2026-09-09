#!/usr/bin/env bash
# modules/cloud/aws/live/iam_policy_engine.sh - a pure IAM policy-document
# classifier shared by every live/ service that has to judge an IAM policy
# it read rather than an AWS-evaluated verdict (docs/STEP6-CLOUD-PLAN.md
# CLOUD-25/26/27).
#
# WHY THIS FILE EXISTS OUTSIDE THE PER-SERVICE `<service>_engine.sh` SHAPE
# modules/cloud/aws/live/s3_engine.sh's own header establishes.  "Task role
# over-permissive" (CLOUD-26, ecs.sh) and "pod role over-permissive"
# (CLOUD-27, eks.sh) are the SAME question - does this IAM role's own inline
# policy grant `Action: "*"` on `Resource: "*"` - asked about a role reached
# two different ways.  Forking the statement walker into both scripts would
# be two copies of the one thing AGENTS.md's own testing rule warns is
# expensive to keep in step; a shared, GENUINELY CROSS-SERVICE file is the
# S3 precedent's own escape hatch (that file's header: "the classifier
# belongs to S3 and to nothing else" - an IAM policy statement belongs to no
# single service by the same logic run the other way).  A future CLOUD-21
# (`lambda.sh`, an over-permissive execution role) has exactly this need
# again.
#
# THIS FILE IS ALSO NOT PURE, AND THAT IS A DELIBERATE, NAMED DEPARTURE FROM
# THE `<service>_engine.sh` CONVENTION.  s3_engine.sh's own header states the
# rule this breaks: "nothing here calls aws_ro". `iam_role_overpermissive`
# below does, because the AWS call chain here - list a role's inline
# policies, then fetch and classify each one, with the honesty accounting
# for which call failed and how - is ALSO identical between ecs.sh and
# eks.sh.  Splitting only the pure classifier out while leaving the driver
# duplicated would still leave the hard-to-keep-in-step half forked.  A
# caller that wants only the pure half (iampol_doc_load /
# iampol_wildcard_admin_grant_set) is free to call those alone.
#
# NO `local -n` NAMEREFS ANYWHERE IN THIS FILE.  AGENTS.md's own "Things
# measured on this codebase" section records `local -` as a bash-4.4-only
# construct against a project whose frozen minimum is bash 4.2; `local -n`
# is the identical trap one version earlier (bash 4.3).  Every "returns a
# value" function here therefore follows this codebase's standing
# `VARNAME` + `printf -v "$__var"` setter convention instead
# (`s3_doc_get`'s own shape), never a nameref.
#
# WHAT "OVER-PERMISSIVE" MEANS HERE, AND WHAT IT DELIBERATELY DOES NOT COVER.
# A statement is flagged when it is `Effect: Allow` AND its `Action` contains
# the literal string `*` (as a bare scalar or as a member of an array) AND
# its `Resource` does too - the same "admin-equivalent" reading every
# published CSPM tool leads with, because it is the one shape with no
# legitimate narrow use: any single action or any single resource still
# leaves something for a reviewer to name.  `NotAction`/`NotResource` are NOT
# evaluated (a stated gap, not an oversight - see iampol_field_has_star's own
# note) and neither is a managed (attached) policy: `iam_role_overpermissive`
# below reads ONLY the role's INLINE policies
# (list-role-policies/get-role-policy).  Widening to `list-attached-role-
# policies` -> `get-policy` -> `get-policy-version` is a real, useful
# extension with its own multi-call honesty accounting to design - left as a
# stated gap here rather than rushed in alongside two other services in one
# change, the same discipline DAST-04's own "what this ticket deliberately
# did not build" paragraphs established for a scope boundary worth naming
# rather than silently absorbing.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_IAMPOL_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_IAMPOL_ENGINE_SOURCED=1

# -x back-edge cut: reached only by a direct-engine test; a real run always
# has modules/cloud/aws/engine.sh already inlined by the time a service
# sources this file.  See s3_engine.sh's identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, for the identical reason s3_engine.sh's own globals carry it:
# a service script sources this from INSIDE `cloud_run_service`, a function,
# where a bare `declare -A` would create a LOCAL that dies with the pass.
declare -gA _IAMPOL_DOC=()
declare -gA _IAMPOL_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading a policy document - from a FILE or from an already-fetched TEXT
# ---------------------------------------------------------------------------
# `iampol_doc_load FILE` - as s3_doc_load: flatten FILE into `_IAMPOL_DOC` /
# `_IAMPOL_DOCT`.  Used for a response whose policy document is the response
# itself, or is nested a fixed depth under a field name that the caller's
# own path arguments account for (`iam get-role-policy`'s own
# `PolicyDocument` - already a nested object in the CLI's JSON output, since
# IAM's PolicyDocument shapes carry botocore's "jsonvalue" trait, which
# decodes the wire's percent-encoded JSON into a real object before the CLI
# ever renders it).
iampol_doc_load() {
  local file=$1
  _IAMPOL_DOC=()
  _IAMPOL_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _IAMPOL_DOC[$path]=$val
    _IAMPOL_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `iampol_doc_load_text TEXT` - flatten a policy document that arrived as a
# STRING field of a larger response rather than as the response itself.
# `ecr get-repository-policy`'s `policyText` is exactly this shape (ECR has
# no botocore "jsonvalue" trait on it, unlike IAM's PolicyDocument, so the
# CLI hands back the raw JSON-as-a-string an operator would otherwise pipe
# through `python3 -m json.tool` by hand) - a caller reads that field with
# `iampol_doc_get`-style access on the OUTER document loaded separately,
# unescapes it, and passes the result here for a SECOND flatten pass.
iampol_doc_load_text() {
  local text=$1
  _IAMPOL_DOC=()
  _IAMPOL_DOCT=()
  [[ -n $text ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _IAMPOL_DOC[$path]=$val
    _IAMPOL_DOCT[$path]=$type
  done < <(printf '%s' "$text" | cloud_json_flatten 2>/dev/null)
  return 0
}

iampol_doc_has() {
  [[ -n ${_IAMPOL_DOCT[$1]+set} ]]
}

iampol_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 2. The classifiers, over the loaded document
# ---------------------------------------------------------------------------
# Every classifier below takes an optional PREFIX (the empty string when the
# loaded document's own `Statement` array sits at the root, or a field name
# like `PolicyDocument` when it is nested one level under a wrapper the
# caller's response shape supplies) - one implementation for both shapes
# rather than one per shape, since the only difference is where the walk
# starts.
_iampol_stmt_path() {
  local prefix=$1
  shift
  if [[ -n $prefix ]]; then
    iampol_path "$prefix" Statement "$@"
  else
    iampol_path Statement "$@"
  fi
}

# `iampol_field_has_star PREFIX STMT_IDX FIELD` - true when
# Statement[STMT_IDX]'s FIELD (`Action`, `Resource`, or `Principal_AWS`)
# contains the literal `*`, whether the field is a BARE SCALAR
# (`"Action": "*"`) or an ARRAY of scalars (`"Action": ["s3:*", "*"]`) - IAM
# policy grammar allows either shape for every one of these fields, and a
# classifier that only read one would miss the other silently, in the
# direction that under-reports.
#
# `NotAction`/`NotResource` ARE NOT CONSULTED, and that is a stated gap
# rather than an omission: a statement using them denies (or grants) every
# action/resource EXCEPT the named ones, which is a real and different
# question this function does not attempt.
iampol_field_has_star() {
  local prefix=$1 idx=$2 field=$3
  local scalar_path
  scalar_path=$(_iampol_stmt_path "$prefix" "$idx" "$field")
  if iampol_doc_has "$scalar_path"; then
    [[ ${_IAMPOL_DOC[$scalar_path]:-} == '*' ]] && return 0
    # A bare scalar that is present and is not "*" settles the question: IAM
    # policy grammar does not let one field be both a scalar and an array.
    return 1
  fi
  local i=0 p
  while :; do
    p=$(_iampol_stmt_path "$prefix" "$idx" "$field" "$i")
    iampol_doc_has "$p" || break
    [[ ${_IAMPOL_DOC[$p]:-} == '*' ]] && return 0
    i=$(( i + 1 ))
  done
  return 1
}

# `iampol_wildcard_admin_grant_set VARNAME [PREFIX]` - VARNAME is set to the
# offending statement's `Sid` (or its index, when the statement carries
# none) of the FIRST `Effect: Allow` statement whose Action AND Resource
# both carry `*`.  Returns 0 when one was found, 1 when the loaded document
# grants no such statement (a real, checked answer - not a coverage loss).
#
# THE LOOP END IS DETECTED THE WAY s3_engine.sh's ACL-grant walk is: absence
# of ANY of a statement's own likely keys (`Effect`, `Action`, `Resource`)
# at this index means there is no such statement, not that this one
# statement is merely unusual.
iampol_wildcard_admin_grant_set() {
  local __var=$1 __prefix=${2:-}
  printf -v "$__var" '%s' ''
  local __i=0 __effect='' __sid='' __p=''
  while :; do
    __p=$(_iampol_stmt_path "$__prefix" "$__i" Effect)
    if ! iampol_doc_has "$__p" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Action)" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Action 0)" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Resource)" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Resource 0)"; then
      break
    fi
    __effect=${_IAMPOL_DOC[$__p]:-}
    if [[ $__effect == Allow ]] \
      && iampol_field_has_star "$__prefix" "$__i" Action \
      && iampol_field_has_star "$__prefix" "$__i" Resource; then
      __sid=${_IAMPOL_DOC[$(_iampol_stmt_path "$__prefix" "$__i" Sid)]:-}
      [[ -n $__sid ]] || __sid="statement[$__i]"
      printf -v "$__var" '%s' "$__sid"
      return 0
    fi
    __i=$(( __i + 1 ))
  done
  return 1
}

# `iampol_public_principal_grant_set VARNAME [PREFIX]` - VARNAME is set to
# the offending statement's `Sid`/index of the FIRST `Effect: Allow`
# statement whose `Principal` is the wildcard: either the bare string
# `"Principal": "*"` (the anonymous-access shape a resource policy like
# ECR's carries) or `"Principal": {"AWS": "*"}` / `{"AWS": ["*", ...]}` (the
# "any AWS principal in any account" shape).  Returns 1, a real checked
# answer, when no statement grants either.
iampol_public_principal_grant_set() {
  local __var=$1 __prefix=${2:-}
  printf -v "$__var" '%s' ''
  local __i=0 __effect='' __sid='' __p='' __bare=''
  while :; do
    __p=$(_iampol_stmt_path "$__prefix" "$__i" Effect)
    if ! iampol_doc_has "$__p" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Principal)" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Principal AWS)" \
      && ! iampol_doc_has "$(_iampol_stmt_path "$__prefix" "$__i" Principal AWS 0)"; then
      break
    fi
    __effect=${_IAMPOL_DOC[$__p]:-}
    __bare=${_IAMPOL_DOC[$(_iampol_stmt_path "$__prefix" "$__i" Principal)]:-}
    if [[ $__effect == Allow ]] \
      && { [[ $__bare == '*' ]] || iampol_field_has_star "$__prefix" "$__i" Principal_AWS; }; then
      __sid=${_IAMPOL_DOC[$(_iampol_stmt_path "$__prefix" "$__i" Sid)]:-}
      [[ -n $__sid ]] || __sid="statement[$__i]"
      printf -v "$__var" '%s' "$__sid"
      return 0
    fi
    __i=$(( __i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 3. The shared driver - the ONE impure section in this file (see header)
# ---------------------------------------------------------------------------
# `iam_role_overpermissive ROLE_NAME WORKDIR SAFE_KEY RESULTVAR REASONVAR` -
# lists ROLE_NAME's INLINE policies and classifies each with
# `iampol_wildcard_admin_grant_set` until one fires or the list is exhausted.
#
#   return 0   over-permissive: RESULTVAR is set to "<policy-name>:<sid>"
#   return 1   checked, clean: every inline policy (zero or more) was read
#              and none grants Action:* + Resource:* on an Allow statement.
#              RESULTVAR is set to '' - a real answer, not a coverage loss.
#   return 2   coverage loss: RESULTVAR is set to '', REASONVAR carries the
#              aws_ro reduction reason (`aws_ro_reduction_reason_set`'s own
#              vocabulary) for the call that did not answer.
#
# SAFE_KEY is a filesystem-safe token (the caller's own bucket-safe-name
# idiom, s3.sh's `${b//[^A-Za-z0-9._-]/_}`) used only to namespace this
# role's scratch files under WORKDIR so two roles examined in one pass never
# collide.
#
# A CALL THAT FAILS PARTWAY THROUGH THE POLICY LIST IS A COVERAGE LOSS FOR
# THE WHOLE ROLE, not a partial answer that ignores the unread policies:
# the wildcard grant this function exists to find could be sitting in
# exactly the policy that did not answer, and reporting "clean" over an
# unread policy is the silent-clean-account failure this module's every
# other check is built against.
iam_role_overpermissive() {
  local role=$1 work=$2 safe=$3 __resultvar=$4 __reasonvar=$5
  printf -v "$__resultvar" '%s' ''
  printf -v "$__reasonvar" '%s' ''

  local listf=$work/iam-policies-$safe.json rc=0
  aws_ro iam list-role-policies --role-name "$role" >"$listf" || rc=$?
  if (( rc != 0 )); then
    aws_ro_reduction_reason_set "$__reasonvar"
    return 2
  fi

  local -a names=()
  local i=0 path type val
  while IFS=$'\t' read -r path type val; do
    [[ $path == "PolicyNames$(printf '\x1f')$i" ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    [[ -n $val ]] && names+=("$val")
    i=$(( i + 1 ))
  done < <(cloud_json_flatten <"$listf" 2>/dev/null)

  local pname polf grant=''
  for pname in "${names[@]+"${names[@]}"}"; do
    polf=$work/iam-policy-$safe-${pname//[^A-Za-z0-9._-]/_}.json
    rc=0
    aws_ro iam get-role-policy --role-name "$role" --policy-name "$pname" >"$polf" || rc=$?
    if (( rc != 0 )); then
      aws_ro_reduction_reason_set "$__reasonvar"
      return 2
    fi
    iampol_doc_load "$polf" || true
    if iampol_wildcard_admin_grant_set grant PolicyDocument; then
      printf -v "$__resultvar" '%s:%s' "$pname" "$grant"
      return 0
    fi
  done
  return 1
}
