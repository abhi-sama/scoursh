#!/usr/bin/env bash
# modules/cloud/aws/live/appsync_engine.sh - the pure half of the §8.5 AppSync
# read-only service (docs/DESIGN.md §8.5; docs/STEP6-CLOUD-PLAN.md CLOUD-23).
#
# The run.sh/engine.sh split modules/sast/ established, and modules/cloud/aws/
# live/s3.sh + s3_engine.sh copy one level down: this file is a pure function
# library with the standard sourced-once guard and no side effect at source
# time, and modules/cloud/aws/live/appsync.sh is the file that DOES something
# when `cloud_run_service` sources it.  Nothing here calls `aws_ro`, reads the
# run context or emits anything by itself.
#
# APPSYNC IS `regional` (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`
# table), UNLIKE S3, AND THAT SIMPLIFIES EVERY REGION QUESTION THIS FILE WOULD
# OTHERWISE HAVE TO ANSWER.  `list-graphql-apis` is scoped to whatever region
# `cloud_run_service` set as ambient before sourcing appsync.sh, so a GraphQL
# API's real region IS the pass's own region - there is no S3-style
# `get-bucket-location` step to resolve one, and no `--region` argument to
# spell out on any call here: the ambient region `aws_ro_use_region` already
# set is what every `aws_ro` call in this file's sibling script inherits.
#
# §8.5's OWN TWO CHECKS, AND WHY THEY NEED NO SUB_KEY.  "API-key auth in use"
# is a fact about the API's own `authenticationType` field, read straight out
# of `list-graphql-apis` with no further call; "key expiry" needs one
# `list-api-keys` call per API.  Each finding's `loc_resource_key` is already
# the one resource the check is about (the API's ARN, or one key's own ARN),
# so - unlike S3's ACL check, which needs `loc_sub_key` to keep two grantee
# classes on one bucket from colliding onto one fingerprint - nothing here
# needs a second identity component.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_APPSYNC_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_APPSYNC_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` / `cloud_json_unescape`
# and is ALREADY SOURCED in every real run - regions.sh sources it before the
# service walk begins - so this guard is reached only by a direct-engine test.
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
# for the reason modules/cloud/aws/live/s3_engine.sh's own header documents at
# length: in a real run NOTHING sources this file at top level.
# `cloud_run_service` reaches a service script (which sources this one) by
# running `source` from INSIDE ITSELF, so every line here executes in that
# function's scope, where a bare `declare -A` creates a LOCAL that dies with
# the first service pass.
declare -gA _APPSYNC_DOC=()
declare -gA _APPSYNC_DOCT=()

# The threshold this pack flags a key's REMAINING lifetime against.  AppSync
# caps an API key's total lifetime at 365 days from creation and defaults to 7
# when none is given, so 90 days remaining is comfortably inside "this key was
# deliberately issued long-lived" territory and comfortably outside the
# ordinary short-lived case - the same 90-day order of magnitude this
# project's own severity conversations reach for elsewhere (an unrotated
# credential, an unreviewed grant).  It is a hardcoded constant rather than a
# new `config/scanner.conf` key: §9.6.1's key set is frozen, and one more
# tunable for one service's one check is not worth a register change in this
# ticket.  `appsync_key_expiry_state` below takes it as a plain argument
# rather than reading it as a global, so a future ticket that DOES want it
# configurable only has to change where this constant is read from, not the
# classifier's own contract.
declare -g APPSYNC_KEY_LONG_EXPIRY_DAYS=90

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `appsync_doc_load FILE` - flatten FILE once into `_APPSYNC_DOC` (path ->
# unescaped scalar) and `_APPSYNC_DOCT` (path -> `s`/`n`/`b`/`z` type), both
# keyed by `cloud_json_flatten`'s US-joined path.  See
# modules/cloud/aws/live/s3_engine.sh's `s3_doc_load` for why this whole-document
# load beats a per-leaf `cloud_json_leaf` call here: `list-graphql-apis` and
# `list-api-keys` are both ARRAYS walked index by index, and a leaf-by-leaf
# reader cannot answer "how many entries" without already knowing it.
appsync_doc_load() {
  local file=$1
  _APPSYNC_DOC=()
  _APPSYNC_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell - a
  # `cloud_json_flatten <"$f" | while ...` loop runs its body in a subshell and
  # discards every key it stored the moment that subshell exits.  This
  # codebase's standing subshell lesson (lib/core.sh's `worker_id_set`), in its
  # loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _APPSYNC_DOC[$path]=$val
    _APPSYNC_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `appsync_path P...` - join path segments with the US byte cloud_json_flatten
# uses.  A function rather than an inline `$'\x1f'` at each call site, for the
# identical reason `s3_path` gives: the separator is the module engine's
# published contract, and every service script spelling a control byte by hand
# is one more chance to spell it wrong.
appsync_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# `appsync_doc_has PATH` / `appsync_doc_get VARNAME PATH` - membership and
# read.  `appsync_doc_get` SETS rather than prints, this codebase's standing
# convention for anything a caller reads in a loop.
appsync_doc_has() {
  [[ -n ${_APPSYNC_DOCT[$1]+set} ]]
}

appsync_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_APPSYNC_DOC[$__path]:-}"
  [[ -n ${_APPSYNC_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `appsync_partition_of CALLER_ARN` - the ARN partition (`aws`, `aws-cn`,
# `aws-us-gov`) read out of the caller identity's own ARN, defaulting to `aws`.
# A byte-for-byte copy of `s3_partition_of`'s logic: READ, NEVER HARDCODED, for
# the identical reason that file gives - a finding citing the wrong partition
# names a resource that does not exist and an operator gets silence rather
# than an error.
appsync_partition_of() {
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

# `appsync_api_arn PARTITION ACCOUNT REGION API_ID` - the FALLBACK ARN a
# GraphQL API's own `list-graphql-apis` record should never actually need:
# AWS returns a real `arn` field on every entry, and the script prefers that
# real, observed value over reconstructing one.  This exists only for the
# defensive case of a response that omits it, so a finding still cites a
# well-formed ARN rather than an empty `loc_resource_key`.
appsync_api_arn() {
  printf 'arn:%s:appsync:%s:%s:apis/%s' "$1" "$3" "$2" "$4"
}

# `appsync_key_arn API_ARN KEY_ID` - `<api-arn>/apikeys/<key-id>`, AWS's own
# ARN format for an AppSync API key
# (arn:${Partition}:appsync:${Region}:${Account}:apis/${GraphQLApiId}/apikeys/${ApiKeyId}).
# Built by APPENDING to the api's own already-resolved ARN rather than by
# re-deriving partition/region/account separately: `list-api-keys` names no
# partition, region, or account of its own, so anchoring on the API's real ARN
# is what keeps a key's ARN consistent with its own API's, however that ARN
# was obtained (the real field, or the fallback above).
appsync_key_arn() {
  printf '%s/apikeys/%s' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 3. The classifiers - one per check, each over an already-loaded document
# ---------------------------------------------------------------------------
# `appsync_auth_type_is_key AUTH_TYPE` - true when AUTH_TYPE is the literal
# `API_KEY`, compared as a WHOLE VALUE never a substring: AppSync's other four
# authentication types (`AWS_IAM`, `AMAZON_COGNITO_USER_POOLS`,
# `OPENID_CONNECT`, `AWS_LAMBDA`) share no substring with it, but a future
# fifth type might, and a substring test is the wrong habit to carry forward
# regardless.
appsync_auth_type_is_key() {
  [[ $1 == API_KEY ]]
}

# `appsync_key_expiry_state EXPIRES_EPOCH NOW_EPOCH LONG_DAYS` - one of
# `expired`, `long_lived`, `ok`.
#
# THE BOUNDARY IS STRICT `>`, NOT `>=`, AND THAT IS THE OPPOSITE CHOICE FROM
# `tls_expiry_state`'s OWN WARNING WINDOW ON PURPOSE.  That function flags a
# certificate AT its warning boundary because missing an imminent expiry is
# the failure that costs an outage; this function's boundary points the other
# way - it flags a key whose remaining lifetime EXCEEDS the threshold, so a
# key sitting exactly on the line (remaining lifetime bit-for-bit equal to
# `LONG_DAYS` days) is the ORDINARY case this check must stay quiet on, and
# `>=` would report every key issued with the round, common 90-day validity
# an operator's own tooling might default to.  Pinned by a boundary case in
# both directions.
appsync_key_expiry_state() {
  local expires=$1 now=$2 long_days=$3
  if (( expires <= now )); then
    printf '%s' expired
    return 0
  fi
  if (( expires - now > long_days * 86400 )); then
    printf '%s' long_lived
    return 0
  fi
  printf '%s' ok
}

# `appsync_days_until EXPIRES NOW` - whole days between the two, rounded DOWN
# and never signed; a byte-for-byte copy of `tls_days_until`'s shape.  The
# caller already knows the direction from `appsync_key_expiry_state`.
appsync_days_until() {
  local delta=$(( $1 - $2 ))
  (( delta < 0 )) && delta=$(( -delta ))
  printf '%s' $(( delta / 86400 ))
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
# `appsync_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the
# check registry this run loaded.  A byte-for-byte copy of
# `s3_registry_locate_set`; returns 1 when no loaded set carries it.
appsync_registry_locate_set() {
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

# `appsync_emit_finding CHECK_ID RESOURCE_ARN REGION SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, VIA
# `finding_from_record`, exactly as `s3_emit_finding`'s own header explains at
# length - title, severity, confidence, CWE, OWASP category, remediation and
# references are fields of the registry record, never re-typed here.  Neither
# CLOUD-APPSYNC-* record carries a `cis` value: CIS Amazon Web Services
# Foundations Benchmark v3.0.0 has no AppSync section at all (its four
# sections cover IAM, storage, logging, and networking), so citing a control
# number here would be the overstated-coverage failure docs/DESIGN.md §15
# forbids, and `data/cis-mappings`'s own header records the identical judgement
# for the three S3 checks it names for the same reason.
#
# A CHECK ID WITH NO REGISTRY RECORD IS A LOUD INTERNAL ERROR, never a
# silently hand-built finding - the identical `die` s3_emit_finding reaches
# for, and for the identical reason: in any real run
# `_scan_apply_profile_filter` has already loaded `modules/cloud/**/*.rules`
# before dispatch, so the only way to reach this is a typo in a check id or a
# record deleted from under this script.
#
# `exposure` IS SET ONCE, EXPLICITLY, FOR BOTH CHECKS, AND `auth` IS
# DELIBERATELY LEFT AT ITS DEFAULT.  An AppSync GraphQL endpoint is reachable
# from the general internet by default whichever authentication mode guards
# it - this pass observes no WAF web ACL or private-API VPC restriction that
# would narrow that, so `exposure internet` is the honest, observable fact
# rather than a judgement about how likely an attacker is to reach it.  `auth`
# stays at the finding-record default of `user`, never raised to `none`: an
# API-key caller DOES present a credential, however easily that credential is
# copied out of a mobile app or a JavaScript bundle - the credential's own
# weakness and lifetime are what the two checks below exist to flag, not its
# absence.  Compare S3's ACL/policy checks, which set `auth none` because
# AllUsers/AuthenticatedUsers grants require no credential at all; that case
# does not exist here.
#
# THE CELL IS THE PASS'S REGION, WHICH IS ALSO THE FINDING'S OWN REGION -
# UNLIKE S3.  AppSync is a `regional` row in `_CLOUD_SERVICES`
# (modules/cloud/aws/engine.sh), so `SCOURSH_CLOUD_CELL` is already
# `<account>/<region>` for the exact region this pass is examining, and the
# API's own region IS that region (§8.5 has no cross-region GraphQL API).
# There is no S3-style split between "the cell the pass covered" and "the
# resource's own region" to preserve here.
appsync_emit_finding() {
  local check_id=$1 resource_arn=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  appsync_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/appsync emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  finding_set exposure internet
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$resource_arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
