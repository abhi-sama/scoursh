#!/usr/bin/env bash
# modules/cloud/aws/live/s3_engine.sh - the pure half of the §8.1 S3 read-only
# service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-05).
#
# The run.sh/engine.sh split modules/sast/ established and modules/dast/ reuses
# one level down, applied a second level down again: this file is a pure
# function library with the standard sourced-once guard and no side effect at
# source time, and modules/cloud/aws/live/s3.sh is the file that DOES something
# when `cloud_run_service` sources it.  Nothing here calls `aws_ro`, reads the
# run context or emits anything by itself; every function takes a response
# document (or a string) and answers one question about it, which is what lets
# tests/suites/cloud-s3.sh exercise the classifiers against committed fixtures
# with no scan, no stub and no run directory.
#
# WHY A SERVICE GETS AN ENGINE FILE AT ALL, given modules/cloud/aws/engine.sh
# already exists: that file is the MODULE's shared library (the service table,
# the cell, the JSON reader, the one door into a service script) and every one
# of docs/DESIGN.md §8.1's thirty services shares it.  A classifier that knows
# what an S3 ACL grantee URI means belongs to S3 and to nothing else, and
# putting it in the module engine would grow a file every service sources into
# the union of thirty services' response formats.  This is the shape the rest
# of step 6 should copy: `live/<service>_engine.sh` for the pure half,
# `live/<service>.sh` for the pass.  A file whose name does not appear in
# `_CLOUD_SERVICES` is never sourced by the walk, so an `_engine.sh` sibling
# costs the dispatch nothing.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_S3_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_S3_ENGINE_SOURCED=1

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
# and the `-g` is load-bearing for the reason modules/cloud/aws/engine.sh's own
# service table documents at length: in a real run NOTHING sources this file at
# top level.  `cloud_run_service` is a FUNCTION and reaches a service script by
# running `source` from inside itself, so every line here executes in that
# function's scope, where a bare `declare -A` creates a LOCAL that dies with
# the first service pass.  A plain assignment (the sourced-once guard above) IS
# global and DOES survive, which is why that one line needs no `-g`.  The same
# rule rules out `readonly` for the constants below - `readonly` is `declare
# -r`, so inside a function it is local too.
declare -gA _S3_DOC=()
declare -gA _S3_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `s3_doc_load FILE` - flatten FILE once into `_S3_DOC` (path -> unescaped
# scalar) and `_S3_DOCT` (path -> `s`/`n`/`b`/`z` type), both keyed by
# `cloud_json_flatten`'s US-joined path.  Returns 1 and leaves both EMPTY when
# the document does not parse or the file is unreadable.
#
# WHY THIS EXISTS BESIDE `cloud_json_leaf`, WHICH ALREADY READS ONE LEAF.  That
# helper re-flattens the whole document per lookup, which is right for the one
# or two leaves the module engine's own callers want and wrong here for two
# separate reasons.  The cheap one is cost: an ACL document is read eight times
# by the checks below.  The load-bearing one is that a `Grants` ARRAY cannot be
# read leaf-by-leaf at all without already knowing how many entries it has -
# every check in this file that walks an array needs the whole flattened map,
# not a path it can name in advance.
#
# THE TYPE MAP IS NOT AN OPTIONAL EXTRA, and dropping it is the subtle defect.
# `{"LocationConstraint": null}` and `{"LocationConstraint": ""}` both arrive
# with an EMPTY value; only the type tells them apart, and only one of them
# means us-east-1.  The same distinction decides `"IsPublic": false` (a real
# answer) from an absent key (a document shape we did not expect).
s3_doc_load() {
  local file=$1
  _S3_DOC=()
  _S3_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell: a
  # `cloud_json_flatten <"$f" | while ...` loop runs its body in a subshell and
  # every key it stored is discarded when that subshell exits, leaving an
  # empty map and a check that reports every bucket clean.  This codebase's
  # standing subshell lesson (lib/core.sh's `worker_id_set`), in its loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _S3_DOC[$path]=$val
    _S3_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `s3_path P...` - join path segments with the US byte cloud_json_flatten uses.
# A function rather than an inline `$'\x1f'` at each call site: the separator is
# the module engine's published contract, and thirty service scripts each
# spelling a control byte by hand is thirty chances to spell it wrong.
s3_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# `s3_doc_has PATH` / `s3_doc_get VARNAME PATH` - membership and read.
# `s3_doc_get` SETS rather than prints, this codebase's standing convention for
# anything a caller reads in a loop.
s3_doc_has() {
  [[ -n ${_S3_DOCT[$1]+set} ]]
}

s3_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_S3_DOC[$__path]:-}"
  [[ -n ${_S3_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The bucket's own region
# ---------------------------------------------------------------------------
# `s3_location_region_set VARNAME` - the region a `get-bucket-location`
# response names, over the loaded document.
#
# THREE SPELLINGS MEAN us-east-1 AND NONE OF THEM SAYS SO.  The API returns
# `LocationConstraint: null` for us-east-1 (the region that predates the
# constraint), and older accounts can carry the empty string; the CLI renders
# the first as JSON `null`.  A parser that takes the value verbatim therefore
# labels every us-east-1 bucket with an empty region - which lands in
# `loc_region`, so it lands in the FINGERPRINT (tension 5), so the same bucket
# reported by a later, fixed parser is a different finding and the old one is
# never `fixed`.
#
# `EU` IS A REAL, STILL-ACCEPTED VALUE AND IT MEANS eu-west-1.  It is the
# legacy alias for the original European region and buckets created with it
# still return it today; mapping it is the difference between citing a region
# a reader can act on and citing a token AWS's own console no longer displays.
s3_location_region_set() {
  local __var=$1 __raw='' __type=''
  __raw=${_S3_DOC[LocationConstraint]:-}
  __type=${_S3_DOCT[LocationConstraint]:-}
  case $__type in
    '' | z) printf -v "$__var" '%s' us-east-1; return 0 ;;
  esac
  [[ -n $__raw ]] || { printf -v "$__var" '%s' us-east-1; return 0; }
  [[ $__raw == EU ]] && __raw=eu-west-1
  printf -v "$__var" '%s' "$__raw"
  return 0
}

# ---------------------------------------------------------------------------
# 3. The ARN
# ---------------------------------------------------------------------------
# `s3_partition_of CALLER_ARN` - the ARN partition (`aws`, `aws-cn`,
# `aws-us-gov`) read out of the caller identity's own ARN, defaulting to `aws`.
#
# READ, NEVER HARDCODED.  An S3 bucket ARN in GovCloud is
# `arn:aws-us-gov:s3:::name` and in China `arn:aws-cn:s3:::name`; a finding
# citing `arn:aws:s3:::name` in either partition names a resource that does not
# exist, and an operator pasting it into a console or a policy gets silence
# rather than an error.  The caller ARN is a fact this run already resolved
# (`sts get-caller-identity`, modules/cloud/aws/run.sh), so there is nothing to
# guess.
s3_partition_of() {
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

# `s3_bucket_arn PARTITION BUCKET` - `arn:<partition>:s3:::<bucket>`.
# An S3 bucket ARN carries NO account id and NO region - the bucket namespace
# is global, and both fields are empty by the ARN format's own definition.
# That is not a gap in the finding: `loc_account_id` and `loc_region` carry
# them separately, which is exactly why the CLOUD location profile has those
# components at all.
s3_bucket_arn() {
  printf 'arn:%s:s3:::%s' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 4. The classifiers - one per check, each over an already-loaded document
# ---------------------------------------------------------------------------
# The two public grantee groups, by their canonical URI.  Compared as WHOLE
# VALUES, never as a substring: a bucket whose ACL grants a canonical-user
# grantee whose DisplayName happens to contain the string `AllUsers` is not
# public, and a substring test would report it so.
declare -g S3_URI_ALL_USERS='http://acs.amazonaws.com/groups/global/AllUsers'
declare -g S3_URI_AUTH_USERS='http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

# `s3_acl_public_grants_set VARNAME` - one line per public grant in the loaded
# `get-bucket-acl` document: `<class> <permission>`, class being `AllUsers` or
# `AuthenticatedUsers`.  Empty output means the ACL grants nothing publicly.
#
# `AuthenticatedUsers` IS NOT A NARROWING AND IS REPORTED IDENTICALLY.  It
# means "any principal holding any AWS credential anywhere in the partition",
# not "any principal in this account" - anyone who can complete a free AWS
# signup is inside it.  Treating it as the milder case is the reading that
# fails towards a clean report, so both classes are reported and the class
# rides in the finding's `loc_sub_key` (making them two fingerprints, since
# they are two distinct grants an operator removes separately).
s3_acl_public_grants_set() {
  local __var=$1 __out='' __i=0 __uri='' __perm='' __class=''
  while :; do
    __uri=${_S3_DOC[$(s3_path Grants "$__i" Grantee URI)]:-}
    __perm=${_S3_DOC[$(s3_path Grants "$__i" Permission)]:-}
    # The loop ends when the index names no grant at all.  Testing the URI
    # alone would stop at the FIRST canonical-user grant (which has no URI),
    # so an ACL whose owner grant precedes a public one would be reported
    # clean - the ordinary shape, since AWS lists the owner first.
    if ! s3_doc_has "$(s3_path Grants "$__i" Permission)" \
      && ! s3_doc_has "$(s3_path Grants "$__i" Grantee Type)" \
      && ! s3_doc_has "$(s3_path Grants "$__i" Grantee URI)"; then
      break
    fi
    __class=''
    [[ $__uri == "$S3_URI_ALL_USERS" ]] && __class=AllUsers
    [[ $__uri == "$S3_URI_AUTH_USERS" ]] && __class=AuthenticatedUsers
    if [[ -n $__class && -n $__perm ]]; then
      __out+="${__out:+$'\n'}$__class $__perm"
    fi
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `s3_permission_is_write PERMISSION` - true for the permissions that let a
# public principal CHANGE the bucket.
#
# FULL_CONTROL COUNTS AS WRITE AND IS DELIBERATELY NOT ALSO REPORTED AS READ.
# It confers both, so reporting it under both ids would put two findings on one
# grant that is removed once; the write check's own title and remediation name
# full control explicitly, and its severity is the higher of the two, so
# nothing about the grant is understated by folding it in.  READ_ACP is a read
# of the ACL, WRITE_ACP is a rewrite of it - and WRITE_ACP is the sharper of
# the whole set, because a principal holding it can restore any grant an
# operator removes.
s3_permission_is_write() {
  case $1 in
    WRITE | WRITE_ACP | FULL_CONTROL) return 0 ;;
    *) return 1 ;;
  esac
}

# `s3_policy_is_public` - true when the loaded `get-bucket-policy-status`
# document says AWS itself evaluates this bucket's policy as public.
#
# THE VERDICT IS AWS'S, NOT OURS, AND THAT IS THE WHOLE POINT OF USING THIS
# OPERATION.  Deciding publicness by pattern-matching a policy document is a
# re-implementation of IAM policy evaluation: `Principal: "*"` narrowed by a
# real `Condition` on `aws:PrincipalOrgID` or `aws:SourceVpce` is not public,
# while a `Condition` on `aws:Referer` narrows nothing because the client
# supplies it. `get-bucket-policy-status` is AWS answering that question with
# the same evaluator that serves the requests.
s3_policy_is_public() {
  [[ ${_S3_DOC[$(s3_path PolicyStatus IsPublic)]:-} == true ]]
}

# `s3_encryption_algorithm_set VARNAME` - the SSE algorithm the loaded
# `get-bucket-encryption` document configures, or the empty string when it
# configures none.  Only the FIRST rule is read; S3 accepts exactly one.
#
# SSE-S3 (`AES256`) IS NOT A FINDING.  CIS v3.0.0 dropped its predecessor's
# encryption-at-rest control precisely because AWS now applies SSE-S3 by
# default, and reporting every bucket that has not adopted SSE-KMS would flag
# the majority of correctly-configured estates - the false-positive flood this
# module's own honesty rules exist to avoid.  What IS reported is the absence
# of any configuration at all.
s3_encryption_algorithm_set() {
  local __var=$1 __p
  __p=$(s3_path ServerSideEncryptionConfiguration Rules 0 ApplyServerSideEncryptionByDefault SSEAlgorithm)
  printf -v "$__var" '%s' "${_S3_DOC[$__p]:-}"
  [[ -n ${_S3_DOC[$__p]:-} ]]
}

# The four Block Public Access settings, in the order AWS documents them.
declare -g S3_BPA_SETTINGS='BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets'

# `s3_bpa_gaps_set VARNAME` - the space-separated names of the Block Public
# Access settings that are NOT enabled in the loaded `get-public-access-block`
# document.  Empty means all four are on.
#
# AN ABSENT KEY IS A GAP, NOT A PASS.  A response that omits one of the four is
# a response that does not enable it, and the naive `[[ $v == false ]]` test -
# which only reports an explicitly false setting - reports such a bucket as
# fully protected.  All four are required together: the two Acls settings
# neutralise public ACLs while BlockPublicPolicy and RestrictPublicBuckets
# handle the policy route, so three-of-four is an open door, not a rounding
# error.
s3_bpa_gaps_set() {
  local __var=$1 __out='' __k='' __p=''
  for __k in $S3_BPA_SETTINGS; do
    __p=$(s3_path PublicAccessBlockConfiguration "$__k")
    [[ ${_S3_DOC[$__p]:-} == true ]] || __out+="${__out:+ }$__k"
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `s3_versioning_status_set VARNAME` - `Enabled`, `Suspended`, or `None` for the
# loaded `get-bucket-versioning` document.
#
# A BUCKET THAT NEVER HAD VERSIONING RETURNS `{}` - an empty document, not a
# `Status` of anything - so `None` is synthesised here rather than read.  The
# three are kept distinct because only `Enabled` is safe and the other two are
# not the same fact: `Suspended` means versioning was on and existing versions
# are still retained, which changes the recovery advice even though the check
# fires for both.
s3_versioning_status_set() {
  local __var=$1 __v
  __v=${_S3_DOC[Status]:-}
  case $__v in
    Enabled | Suspended) printf -v "$__var" '%s' "$__v" ;;
    *) printf -v "$__var" '%s' None ;;
  esac
  [[ $__v == Enabled ]]
}

# `s3_logging_target_set VARNAME` - the bucket server access logs are delivered
# to, per the loaded `get-bucket-logging` document, or the empty string when
# logging is off.  Logging-off is `{}`, exactly as versioning-never-enabled is.
s3_logging_target_set() {
  local __var=$1 __p
  __p=$(s3_path LoggingEnabled TargetBucket)
  printf -v "$__var" '%s' "${_S3_DOC[$__p]:-}"
  [[ -n ${_S3_DOC[$__p]:-} ]]
}

# ---------------------------------------------------------------------------
# 5. Emission
# ---------------------------------------------------------------------------
# `s3_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the check
# registry this run loaded.  Returns 1 when no loaded set carries it.
s3_registry_locate_set() {
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

# `s3_emit_finding CHECK_ID BUCKET REGION SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, VIA
# `finding_from_record`, AND IS NOT RESTATED HERE.  Title, severity,
# confidence, CWE, OWASP category, remediation, references, the rule digest AND
# the `cis` control id are all fields of the registry record; a script that set
# them by hand would be a second copy of every one of them to keep in step with
# the first, and the `cis` value in particular is authored on the record by
# design (docs/CIS-MAPPINGS.md §1) - re-typing it in the script is precisely how
# a finding ends up citing a control its own registry record does not.  Every
# DAST phase sets these by hand; that is the pattern this module deliberately
# does not copy, and the reason is that a cloud check's compliance mapping is
# the thing a compliance report reads.
#
# A CHECK ID WITH NO REGISTRY RECORD IS A LOUD INTERNAL ERROR, never a
# silently hand-built finding: in any real run `_scan_apply_profile_filter`
# has loaded `modules/cloud/**/*.rules` before dispatch, so the only way to
# reach it is a typo in a check id or a record deleted from under its script -
# both of which must stop the run rather than emit a finding with no severity,
# no remediation and no compliance mapping.
#
# THE CELL IS THE PASS'S, NOT THE BUCKET'S REGION.  `SCOURSH_CLOUD_CELL` is
# what modules/cloud/aws/engine.sh's `cloud_run_service` published for this
# pass and what `_cloud_record_coverage` credits coverage to - for a `global`
# service that is `<account>/global`.  Writing `<account>/<bucket region>` here
# instead would put every finding in a cell no pass ever covered, so tension
# 12 could never classify one `fixed` and every remediated bucket would sit at
# `unknown` forever.  The bucket's real region is still cited, in `loc_region`.
s3_emit_finding() {
  local check_id=$1 bucket=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  s3_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/s3 emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local arn
  arn=$(s3_bucket_arn "$(s3_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")" "$bucket")

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # `exposure`/`auth`/`sensitive_data` feed data/severity-rubric.conf's
  # adjustment of the record's base severity.  A publicly-reachable bucket is
  # `external`/`none`; a configuration weakness on a bucket that is not itself
  # public is `internal`/`user`, which is what keeps NO_VERSIONING from being
  # promoted to the same band as a world-writable ACL.
  case $check_id in
    CLOUD-S3-PUBLIC_ACL_READ-01 | CLOUD-S3-PUBLIC_ACL_WRITE-01 | CLOUD-S3-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/global}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
