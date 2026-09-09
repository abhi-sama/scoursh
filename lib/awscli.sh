#!/usr/bin/env bash
# lib/awscli.sh - the single AWS API chokepoint.
#
# Owns:
#   docs/DESIGN.md      §8 (Module - Cloud / AWS, live + IaC)
#   docs/FOUNDATION.md  tension 23 (a read-only AWS lint that survives contact
#     with reality)
#   docs/FOUNDATION.md  tension 16 (shared state across workers; the AWS
#     response cache is the fourth of its five pieces of state)
#
# Every AWS call scoursh ever makes goes through aws_ro().  It is what
# lib/http.sh (§13 step 3) is for outbound HTTP: one enforcement chokepoint,
# checked at RUNTIME so the read-only guarantee holds even if the lint that
# also checks it is wrong - tension 23's stated reason for choosing this shape
# over a smarter grep.
#
# tests/lint-aws-readonly.sh skips this file by name: it is the one place a
# bare `aws` invocation is legitimate, because it is the only place one exists.
#
# STATUS: docs/DESIGN.md §13 places lib/awscli.sh and modules/cloud/aws/live/
# at the start of step 6.  This file lands ahead of that as the credential-less
# half of the AWS module - the chokepoint, its runtime enforcement, and the
# test infrastructure that exercises it.  See AGENTS.md, "AWS module: what
# exists ahead of step 6". No live/ script exists yet, so aws_ro has no shipped
# caller today; it is exercised by tests/suites/awscli.sh (a stub `aws`, no
# network) and tests/localstack/run.sh (a real emulator, still not an AWS
# account).
#
# STATUS UPDATE (docs/STEP6-CLOUD-PLAN.md P3, P20): `modules/cloud/aws/run.sh`
# now calls `aws_ro_use_profile` before the identity call, and
# `modules/cloud/aws/regions.sh`'s `cloud_assume_role` calls
# `aws_ro_use_credentials` for the `--assume-role` multi-account path - both
# are wired, not merely reachable.  `aws_ro_use_region` is called per service
# invocation by `modules/cloud/aws/engine.sh`'s `cloud_run_service`.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_AWSCLI_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_AWSCLI_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
: "${SCOURSH_AWSCLI_BIN:=aws}"
# tests/aws-readonly-allow.txt is scoursh's own exception list (tension 23 item
# 4), resolved against the install root like every other shipped file
# (tension 26) - never against the scan root, which is a property of the tree
# being scanned and has nothing to do with it.
: "${SCOURSH_AWSCLI_ALLOWLIST:=$SCOURSH_INSTALL_ROOT/tests/aws-readonly-allow.txt}"

# The response cache (tension 16's fourth piece of shared state).  It lives in
# the scratch directory rather than under reports/<run>/ because it is
# genuinely transient (finding F12): it is an optimisation whose absence
# changes no result, and nothing downstream of the run ever reads it.
: "${SCOURSH_AWS_CACHE:=1}"
: "${SCOURSH_AWS_CACHE_DIR:=$SCOURSH_SCRATCH/awscache}"

# The page ceiling for aws_ro_paged.  A loop that follows a continuation token
# forever is a runaway against a real account's API quota, so it is bounded -
# and reaching the bound is a DECLARED truncation (outcome `truncated`), never
# a silently short list.
: "${SCOURSH_AWS_MAX_PAGES:=200}"

# The ambient profile and region, applied to every call that does not carry its
# own.  Empty means "whatever the environment resolves", which is the CLI's own
# default and the behaviour before these existed.
: "${SCOURSH_AWS_PROFILE:=}"
: "${SCOURSH_AWS_REGION:=}"

# The ambient ASSUMED-ROLE session credentials (step 6's multi-account path,
# docs/STEP6-CLOUD-PLAN.md CLOUD-02's `--assume-role` remainder).  All three
# empty (the default) means "no assumed session; resolve credentials the
# ordinary way" - --profile/environment/instance profile, exactly as before
# this existed.  Set together, never individually, by aws_ro_use_credentials.
: "${SCOURSH_AWS_ACCESS_KEY_ID:=}"
: "${SCOURSH_AWS_SECRET_ACCESS_KEY:=}"
: "${SCOURSH_AWS_SESSION_TOKEN:=}"

# The frozen read-only prefix allowlist, byte-identical to tension 23's
# RESOLUTION and to tests/lint-aws-readonly.sh's copy. Kept in one place would
# be nicer, but the lint must be able to check invocations without executing
# this file (it inspects source text), so the two are independently frozen and
# a discrepancy between them is exactly what the lint's own tests pin.
readonly SCOURSH_AWS_RO_PREFIXES='^(describe|list|get|search|lookup|select|head|batch-get|preview|estimate|simulate)(-|$)'

SCOURSH_AWSCLI_CAP=''    # '' = not probed yet; present | absent thereafter
SCOURSH_AWSCLI_MAJOR=''  # '' = not probed yet; 1 | 2 | unknown thereafter

# The resolved caller identity, memoised for the process (see section 7).
SCOURSH_AWS_ACCOUNT_ID=''
SCOURSH_AWS_CALLER_ARN=''

# ---------------------------------------------------------------------------
# 2. The outcome vocabulary - "denied" is not "empty"
# ---------------------------------------------------------------------------
# THE HONESTY PROBLEM THIS SOLVES.  Before this section, aws_ro exec'd the CLI
# and returned its status, classifying nothing.  A read-only role missing one
# permission produced an AccessDenied, the check saw no resources, and the run
# reported CLEAN - the exact shape of the data/advisories.db defect this
# project already paid for once ("it did not look" and "it looked and found
# nothing" rendered identically).  It is WORSE here, because a least-privilege
# read-only role legitimately lacks permissions and an opt-in region
# legitimately refuses, so the misleading run is the ORDINARY one, not an edge
# case.
#
# Each failure class is therefore a DISTINCT outcome a caller records as a
# `coverage_reduction`.  The frozen vocabulary:
#
#   ok                   the call succeeded and the response is complete
#   truncated            the call succeeded and the response is INCOMPLETE - a
#                        continuation token was present, or aws_ro_paged hit
#                        its page ceiling.  Status is 0: the data is valid,
#                        just partial.
#   access_denied        AccessDenied / UnauthorizedOperation family
#   auth_failure         the credential itself was rejected (AuthFailure,
#                        InvalidClientTokenId, expired token, bad signature)
#   no_credentials       no credential could be resolved at all
#   region_not_enabled   an opt-in region that this account has not enabled
#   endpoint_unreachable the service endpoint could not be reached.  Kept
#                        SEPARATE from region_not_enabled deliberately: a
#                        non-enabled opt-in region can present as either, and
#                        labelling a genuine network failure as "region off"
#                        would be a confident wrong answer where an honest
#                        "could not reach it" is available
#   throttled            the API asked us to slow down
#   not_found            the resource does not exist.  This is the ONE failure
#                        that is a real answer rather than a coverage loss:
#                        `NoSuchBucketPolicy` means the bucket has no policy,
#                        which is precisely what the caller asked
#   unsupported          the operation does not exist in this region/partition
#   cli_usage            scoursh built a call the CLI itself rejected - our
#                        bug, not the account's
#   error                anything else
#
# aws_ro_outcome_is_coverage_loss is the single predicate that separates "we
# looked" from "we did not"; do not re-derive that judgement at a call site.
readonly SCOURSH_AWS_RO_OUTCOMES='ok truncated access_denied auth_failure no_credentials region_not_enabled endpoint_unreachable throttled not_found unsupported cli_usage error'

# Set by every aws_ro call, before it returns, on both the success and the
# failure path.  A caller reads these; it never re-parses stderr itself.
#
# SC2034: four of these are written here and read only by a CALLER - a step-6
# check, or tests/suites/awscli.sh - so shellcheck cannot see the read from
# inside this file.  They are the published contract this section documents,
# not dead stores; the disable is on the block rather than on each assignment
# so a later field inherits it (each assignment inside a function carries its
# own, since a file-level directive does not reach into a function body).
SCOURSH_AWS_RO_OUTCOME=''     # one of SCOURSH_AWS_RO_OUTCOMES
SCOURSH_AWS_RO_STATUS=0       # the CLI's own exit status (0 when served from cache)
SCOURSH_AWS_RO_CODE=''        # the AWS error code, verbatim, when there was one
SCOURSH_AWS_RO_ERROR=''       # the first line of the CLI's stderr
SCOURSH_AWS_RO_TRUNCATED=0    # 1 when a continuation token was present
SCOURSH_AWS_RO_NEXT_TOKEN=''  # that token, when the response carried one
SCOURSH_AWS_RO_CACHED=0       # 1 when the response came from the cache
SCOURSH_AWS_RO_PAGES=0        # pages fetched by the last aws_ro_paged call

_awscli_outcome_reset() {
  SCOURSH_AWS_RO_OUTCOME=''
  SCOURSH_AWS_RO_STATUS=0
  SCOURSH_AWS_RO_CODE=''
  SCOURSH_AWS_RO_ERROR=''
  SCOURSH_AWS_RO_TRUNCATED=0
  SCOURSH_AWS_RO_NEXT_TOKEN=''
  SCOURSH_AWS_RO_CACHED=0
}

# `aws_ro_outcome_is_coverage_loss [OUTCOME]` - true when the outcome means the
# scan DID NOT LOOK, so the caller owes a coverage_reduction.  Defaults to the
# outcome of the last call.
#
# Only `ok` and `not_found` are answers.  Everything else - including
# `truncated`, which is a partial answer - is a hole in coverage, and a run
# that reports clean over one is lying by omission.
aws_ro_outcome_is_coverage_loss() {
  local o=${1:-$SCOURSH_AWS_RO_OUTCOME}
  case $o in
    ok | not_found) return 1 ;;
    '') return 1 ;;
    *) return 0 ;;
  esac
}

# `aws_ro_outcome_is_known OUTCOME` - membership in the frozen vocabulary
# above.  It exists so a test can assert that every classified failure lands on
# a NAMED outcome rather than on a string a future edit invented: a caller
# switching on the vocabulary silently drops an unknown value into its default
# arm, which is how a new failure class becomes silence again.
aws_ro_outcome_is_known() {
  local o=$1 known=''
  for known in $SCOURSH_AWS_RO_OUTCOMES; do
    [[ $o == "$known" ]] && return 0
  done
  return 1
}

# `aws_ro_reduction_reason_set VARNAME [OUTCOME]` - the machine-readable reason
# string a caller passes to its own coverage_reduction record.  A setter rather
# than a printer for this file's own reason (see aws_ro_account_id_set).
aws_ro_reduction_reason_set() {
  local __var=$1 __o=${2:-$SCOURSH_AWS_RO_OUTCOME}
  printf -v "$__var" 'aws_api_%s' "${__o:-error}"
}

# `_awscli_classify STATUS ERRFILE` - map a failed call onto the vocabulary.
#
# The AWS CLI reports a service error as
#   An error occurred (CODE) when calling the OP operation: MESSAGE
# and the CODE is what is classified - never the MESSAGE, and never the whole
# stderr as a substring search.  The MESSAGE routinely quotes back caller-
# supplied names, so a bucket literally named `access-denied` would classify a
# perfectly ordinary NoSuchBucket as a permission failure under the naive
# reading; it fails in the direction that manufactures a coverage hole where
# there is none, and its mirror image (a resource name containing `NoSuch`
# inside an AccessDenied message) fails in the direction that hides one.
# tests/suites/awscli.sh pins both.
#
# Shapes with no error code at all - a missing credential, an unreachable
# endpoint, the CLI's own argument parser - are matched on the message, which
# is the only thing there is.
_awscli_classify() {
  local status=$1 errf=$2
  local line='' first='' code=''
  SCOURSH_AWS_RO_STATUS=$status
  if [[ -r $errf ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      [[ -n $first ]] || first=$line
      if [[ -z $code && $line == *'An error occurred ('* ]]; then
        code=${line#*'An error occurred ('}
        code=${code%%')'*}
      fi
    done <"$errf"
  fi
  SCOURSH_AWS_RO_ERROR=$first
  SCOURSH_AWS_RO_CODE=$code

  if [[ -n $code ]]; then
    case $code in
      AccessDenied | AccessDeniedException | AccessDeniedFault | UnauthorizedOperation | \
        Client.UnauthorizedOperation | AuthorizationError | AuthorizationErrorException | \
        NotAuthorized | NotAuthorizedException | UserUnauthorizedException | \
        AccessControlListNotSupported | InsufficientPrivilegesException)
        SCOURSH_AWS_RO_OUTCOME=access_denied ;;
      AuthFailure | InvalidClientTokenId | SignatureDoesNotMatch | UnrecognizedClientException | \
        InvalidAccessKeyId | ExpiredToken | ExpiredTokenException | MissingAuthenticationToken | \
        InvalidSignatureException | IncompleteSignature)
        SCOURSH_AWS_RO_OUTCOME=auth_failure ;;
      OptInRequired | SubscriptionRequiredException | InvalidRegion | UnsupportedRegion | \
        IllegalLocationConstraintException)
        SCOURSH_AWS_RO_OUTCOME=region_not_enabled ;;
      Throttling | ThrottlingException | ThrottledException | RequestThrottled | \
        RequestThrottledException | RequestLimitExceeded | TooManyRequestsException | \
        ProvisionedThroughputExceededException | SlowDown)
        SCOURSH_AWS_RO_OUTCOME=throttled ;;
      # The four globs already carry every specifically-named code this arm
      # used to spell out (NoSuchEntity, ObjectNotFound,
      # ResourceNotFoundException, ...); re-adding one is both dead and an
      # SC2222 that fails the shellcheck stage.  The table in
      # tests/suites/awscli.sh pins the glob coverage instead.
      NoSuch* | *NotFound | *NotFoundException | *NotFoundError | *NotFoundFault | \
        EntityDoesNotExist | ResourceNotDiscoveredException)
        SCOURSH_AWS_RO_OUTCOME=not_found ;;
      InvalidAction | UnsupportedOperation | OperationNotPermitted | \
        UnsupportedOperationException | MethodNotAllowed | \
        UnsupportedAvailabilityZoneException)
        SCOURSH_AWS_RO_OUTCOME=unsupported ;;
      *)
        SCOURSH_AWS_RO_OUTCOME=error ;;
    esac
    return 0
  fi

  case $first in
    *'Unable to locate credentials'* | *'Unable to locate a credential'* | \
      *'could not be found'* | *'You must specify a region'* | \
      *'Partial credentials found'* | *'Failed to resolve credential'*)
      SCOURSH_AWS_RO_OUTCOME=no_credentials ;;
    *'Could not connect to the endpoint URL'* | *'EndpointConnectionError'* | \
      *'Connect timeout on endpoint'* | *'Read timeout on endpoint'*)
      SCOURSH_AWS_RO_OUTCOME=endpoint_unreachable ;;
    *'aws: error:'* | *'Invalid choice'* | *'Unknown options'*)
      SCOURSH_AWS_RO_OUTCOME=cli_usage ;;
    *)
      SCOURSH_AWS_RO_OUTCOME=error ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# 3. Truncation - a short list must never read as a complete one
# ---------------------------------------------------------------------------
# `--output json` hands back one page plus a continuation token for every
# operation the CLI has no registered paginator for, and for any call bounded
# by --max-items.  A caller that ignores the token gets a list that is
# indistinguishable from a complete one - the §4.3 item 2 gap, and the same
# "did not look" failure the outcome vocabulary above exists for.
#
# Detection is on the KEY, not on the bytes: the line is trimmed and must START
# with the quoted key name, because an IAM policy document or a tag value that
# happens to contain the string "NextToken" is response CONTENT, not a
# continuation token.  A `"NextToken": null` (which AWS emits on the LAST page)
# and an `"IsTruncated": false` are both explicitly NOT truncation - each is a
# naive reading that would report every complete list as partial.
# `_awscli_json_key_is TRIMMED KEY` - true when the line really is that KEY's
# entry: the quoted name, then optional whitespace, then a colon.
#
# The colon is the whole point.  A JSON ARRAY OF STRINGS puts a bare
# `"NextToken"` on a line of its own - a tag value, an IAM action name, a list
# of field names - and a prefix test alone accepts it, reads the string itself
# as the continuation token, and reports a complete response as truncated.
# Measured on a fixture; tests/suites/awscli.sh pins it.
_awscli_json_key_is() {
  local t=$1 k=$2 rest
  [[ $t == "\"$k\""* ]] || return 1
  rest=${t#"\"$k\""}
  rest=${rest#"${rest%%[![:space:]]*}"}
  [[ ${rest:0:1} == ':' ]]
}

# Every setter in this file names its own locals with a __ prefix, and that is
# load-bearing rather than a style: `local` shadows, so a helper whose internal
# variable happens to share the caller's chosen output name writes to its own
# copy and the caller reads an unset variable.  Measured here - an internal
# `local acct` in aws_ro_account_id_set silently defeated `..._set acct`.
_awscli_json_scalar_after_colon() {
  local __var=$1 __line=$2 __v
  [[ $__line == *:* ]] || { printf -v "$__var" '%s' ''; return 1; }
  __v=${__line#*:}
  # strip surrounding whitespace, a trailing comma, then surrounding quotes
  __v=${__v#"${__v%%[![:space:]]*}"}
  __v=${__v%"${__v##*[![:space:]]}"}
  __v=${__v%,}
  __v=${__v%"${__v##*[![:space:]]}"}
  if [[ ${__v:0:1} == '"' && ${__v: -1} == '"' ]]; then
    __v=${__v:1:${#__v}-2}
  fi
  printf -v "$__var" '%s' "$__v"
}

_awscli_detect_truncation() {
  local f=$1 line trimmed val
  SCOURSH_AWS_RO_TRUNCATED=0
  SCOURSH_AWS_RO_NEXT_TOKEN=''
  [[ -r $f ]] || return 0
  local key='' matched=''
  while IFS= read -r line || [[ -n $line ]]; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    # Fast path: the overwhelming majority of a response's lines are neither a
    # continuation token nor a truncation flag, and this loop runs over every
    # line of every response, so the cheap case comes before the key test.
    # `position` is API Gateway's own token name (`get-rest-apis`,
    # `get-resources`, `get-api-keys`, ... - the older `get-*` list operations
    # that predate the `list-*`/NextToken convention every other service in
    # this catalog uses). Recognising it here, rather than only in a caller,
    # is what keeps CLOUD-22's calls honest under the identical rule S3's
    # `list-buckets` truncation check already relies on: a caller that trusts
    # `SCOURSH_AWS_RO_OUTCOME` alone must never see `ok` on a response this
    # function silently failed to recognise as partial.
    case $trimmed in
      '"NextToken"'* | '"nextToken"'* | '"NextMarker"'* | '"NextContinuationToken"'* | \
        '"NextPageToken"'* | '"nextForwardToken"'* | '"NextRecordName"'* | '"position"'* | \
        '"IsTruncated"'*) ;;
      *) continue ;;
    esac
    matched=''
    for key in NextToken nextToken NextMarker NextContinuationToken NextPageToken \
      nextForwardToken NextRecordName position; do
      if _awscli_json_key_is "$trimmed" "$key"; then matched=$key; break; fi
    done
    if [[ -n $matched ]]; then
      _awscli_json_scalar_after_colon val "$trimmed" || continue
      if [[ -n $val && $val != null ]]; then
        SCOURSH_AWS_RO_TRUNCATED=1
        SCOURSH_AWS_RO_NEXT_TOKEN=$val
      fi
      continue
    fi
    if _awscli_json_key_is "$trimmed" IsTruncated; then
      _awscli_json_scalar_after_colon val "$trimmed" || continue
      [[ $val == true ]] && SCOURSH_AWS_RO_TRUNCATED=1
    fi
  done <"$f"
  return 0
}

# ---------------------------------------------------------------------------
# 4. The response cache (docs/FOUNDATION.md tension 16)
# ---------------------------------------------------------------------------
# $SCRATCH/awscache/<sha256(service|region|account|op|args)>.json, written by
# mktemp in the same directory then mv'd into place - atomic within a
# filesystem, so a reader never sees a partial file.  On a miss the reader
# takes a per-key mutex and RE-CHECKS inside it, because another worker may
# have filled the cache while this one waited; without the re-check eight
# `xargs -P` workers issue the same describe-* call eight times, which is the
# per-process-state failure tension 16 exists to prevent.
#
# ONLY a successful response is cached.  A failure is deliberately not: an
# AccessDenied is cheap to re-observe and a THROTTLED call may well succeed on
# the next attempt, so caching failures would replay a transient condition as a
# permanent one for the rest of the run - a coverage hole invented by the
# cache itself.
_awscli_cache_key_set() {
  local __var=$1 __svc=$2 __op=$3
  shift 3
  local __joined='' __a=''
  for __a in "$@"; do
    __joined+=$'\x1f'$__a
  done
  # 0x1f between arguments rather than a space: an argument may legitimately be
  # empty or contain a space, and a whitespace-joined key would collide two
  # different calls onto one cache entry.  Same reasoning as the DAST-11
  # record-stream lesson in AGENTS.md.
  printf -v "$__var" '%s' \
    "$(printf '%s|%s|%s|%s%s' "$__svc" "${SCOURSH_AWS_REGION:-}" \
      "${SCOURSH_AWS_ACCOUNT_ID:-}" "$__op" "$__joined" | sha256_of)"
}

aws_ro_cache_enabled() {
  [[ ${SCOURSH_AWS_CACHE:-1} == 1 ]]
}

# `aws_ro_cache_clear` - drop every cached response.  For a caller that has
# just changed identity (an assume-role in step 6's multi-account path), where
# a response cached under the previous principal is no longer this
# principal's answer.  The account id is a cache-key component, so this is
# belt-and-braces rather than the only defence.
aws_ro_cache_clear() {
  [[ -d ${SCOURSH_AWS_CACHE_DIR:-} ]] || return 0
  rm -rf -- "${SCOURSH_AWS_CACHE_DIR:?}"/*.json 2>/dev/null || true
  return 0
}

# ---------------------------------------------------------------------------
# 5. The CLI probe
# ---------------------------------------------------------------------------
# Probed once per process, mirroring the tension 24 capability layer's shape
# (probe once, cache, record). Not folded into that layer itself: `aws` is
# module-specific, not a portability primitive every file needs.
_awscli_probe() {
  [[ -n $SCOURSH_AWSCLI_CAP ]] && return 0
  if _have "$SCOURSH_AWSCLI_BIN"; then
    SCOURSH_AWSCLI_CAP=present
    local v=''
    v=$("$SCOURSH_AWSCLI_BIN" --version 2>&1) || true
    case $v in
      aws-cli/1.*) SCOURSH_AWSCLI_MAJOR=1 ;;
      aws-cli/2.*) SCOURSH_AWSCLI_MAJOR=2 ;;
      *) SCOURSH_AWSCLI_MAJOR=unknown ;;
    esac
  else
    SCOURSH_AWSCLI_CAP=absent
    SCOURSH_AWSCLI_MAJOR=unknown
  fi
  # run_record no-ops with no run directory (e.g. under the test suite), so
  # this is safe to call unconditionally. Finding F17's second half: record the
  # detected major version regardless of which branch below is taken.
  run_record aws_cli_major "$SCOURSH_AWSCLI_MAJOR"
}

# `awscli_allowlisted SERVICE OPERATION` - true only for an exact, uncommented
# "service operation" pair in SCOURSH_AWSCLI_ALLOWLIST. tests/lint-aws-readonly.sh
# parses the same file with the same exactness (whole-token match, `#` strips
# a trailing comment), so the two can never authorise different sets.
awscli_allowlisted() {
  local svc=$1 op=$2
  [[ -f $SCOURSH_AWSCLI_ALLOWLIST ]] || return 1
  scan_match "$SCOURSH_SCRATCH/awscli-allow-hit" \
    -e "^${svc}[[:space:]]+${op}([[:space:]]|\$)" -- "$SCOURSH_AWSCLI_ALLOWLIST"
}

# ---------------------------------------------------------------------------
# 6. Credential plumbing
# ---------------------------------------------------------------------------
# `aws_ro_use_profile NAME` / `aws_ro_use_region NAME` set the AMBIENT profile
# and region, applied to every later call that does not carry its own
# --profile/--region.  An explicit caller argument always wins and is never
# duplicated: two --region flags on one command line is a shape whose winner
# depends on the CLI's argument parser, which is not a thing to depend on.
#
# An empty value CLEARS the ambient setting rather than sending an empty flag.
aws_ro_use_profile() {
  SCOURSH_AWS_PROFILE=${1:-}
  export SCOURSH_AWS_PROFILE
}

aws_ro_use_region() {
  SCOURSH_AWS_REGION=${1:-}
  export SCOURSH_AWS_REGION
}

# `aws_ro_use_credentials [AKID SECRET TOKEN]` - the multi-account analogue of
# aws_ro_use_profile/aws_ro_use_region: sets the ambient ASSUMED-ROLE session
# credentials every later `aws_ro` call uses, until replaced or cleared by a
# no-argument call.  modules/cloud/aws/regions.sh's `cloud_assume_role` is the
# only caller (step 6's `--assume-role` iteration); the single-account path
# never calls this and is therefore unchanged.
#
# NOT EXPORTED, and never written into this process's own environment.  The
# three values are passed to the CLI as a per-invocation ENVIRONMENT PREFIX on
# the one exec line in _awscli_fetch (the identical spelling `AWS_PAGER=''`
# already uses there), never as a process-wide `export`: an exported temporary
# credential would leak into every OTHER subprocess this run ever spawns - a
# `curl` from lib/http.sh, an adapter's vendor.sh, a shellcheck child process -
# which is exactly what tension 9's secret-handling rules exist to prevent one
# layer down, applied here to a session credential instead of a static one.
aws_ro_use_credentials() {
  SCOURSH_AWS_ACCESS_KEY_ID=${1:-}
  SCOURSH_AWS_SECRET_ACCESS_KEY=${2:-}
  SCOURSH_AWS_SESSION_TOKEN=${3:-}
}

# `aws_ro_credentials_active` - true when an assumed-role session is ambient.
# A caller uses this to decide whether to label a call's identity as "the
# assumed session" rather than "the ambient profile/environment" - it is a
# predicate over section 6's own state, not a new concept.
aws_ro_credentials_active() {
  [[ -n $SCOURSH_AWS_ACCESS_KEY_ID ]]
}

_awscli_args_carry() {
  local flag=$1
  shift
  local a=''
  for a in "$@"; do
    [[ $a == "$flag" || $a == "$flag="* ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# 7. aws_ro - the chokepoint
# ---------------------------------------------------------------------------
# `aws_ro SERVICE OPERATION [ARGS...]`
#
#   stdout  the response document, verbatim (--output json is pinned)
#   return  0 the call succeeded (check SCOURSH_AWS_RO_OUTCOME for `truncated`)
#           1 the call FAILED; SCOURSH_AWS_RO_OUTCOME says how
#           3 (die) refused: not a read-only operation, or an unreadable flag
#           4 (die) usage, or no `aws` on PATH
#
# A failure returns 1 and NEVER the CLI's own status.  The CLI exits 252-255 on
# its own error classes, which are outside this project's frozen 0-5 contract
# (tension 14), so a caller writing `aws_ro ... || exit $?` would take the whole
# run outside it.  The status is preserved in SCOURSH_AWS_RO_STATUS for anyone
# who wants it.
#
# A non-read operation aborts with exit 3 (SCOURSH_EXIT_SCOPE), the same class
# as an out-of-scope HTTP host: the tool attempting something it is not
# authorised to do.  This is the guarantee that survives a typo, a
# dynamically-constructed operation name, and a broken lint - tension 23's
# stated reason runtime enforcement backs the lint rather than replacing it.
aws_ro() {
  (( $# >= 2 )) || die "$SCOURSH_EXIT_INPUT" "aws_ro requires SERVICE and OPERATION, got: $*"
  local svc=$1 op=$2
  shift 2
  _awscli_outcome_reset
  _awscli_probe
  [[ $SCOURSH_AWSCLI_CAP == present ]] \
    || die "$SCOURSH_EXIT_INPUT" "aws_ro: '$SCOURSH_AWSCLI_BIN' is not installed"

  # tension 23 item 5: --cli-input-json/--cli-input-yaml would let a call's real
  # shape come from somewhere the lint never sees, so they are refused outright
  # rather than merely un-pinned.  --output is refused too, so the pin below
  # can never be silently overridden by a caller argument that appears first.
  local a=''
  for a in "$@"; do
    case $a in
      --cli-input-json | --cli-input-json=* | --cli-input-yaml | --cli-input-yaml=*)
        die "$SCOURSH_EXIT_SCOPE" \
          "aws_ro: '$svc $op' passes --cli-input-json/--cli-input-yaml, which the read-only lint cannot inspect"
        ;;
      --output | --output=*)
        die "$SCOURSH_EXIT_SCOPE" "aws_ro: '$svc $op' attempts to override the pinned --output json"
        ;;
    esac
  done

  if [[ ! $op =~ $SCOURSH_AWS_RO_PREFIXES ]] && ! awscli_allowlisted "$svc" "$op"; then
    die "$SCOURSH_EXIT_SCOPE" \
      "aws_ro: '$svc $op' is not a read-only operation and is not in $SCOURSH_AWSCLI_ALLOWLIST"
  fi

  # The effective argument vector: the caller's own arguments, then the ambient
  # profile/region for whichever the caller did not supply, then the pinned
  # --output json.
  local eargs=()
  (( $# > 0 )) && eargs=("$@")
  if [[ -n ${SCOURSH_AWS_PROFILE:-} ]] \
    && ! _awscli_args_carry --profile "${eargs[@]+"${eargs[@]}"}"; then
    eargs+=(--profile "$SCOURSH_AWS_PROFILE")
  fi
  if [[ -n ${SCOURSH_AWS_REGION:-} ]] \
    && ! _awscli_args_carry --region "${eargs[@]+"${eargs[@]}"}"; then
    eargs+=(--region "$SCOURSH_AWS_REGION")
  fi
  eargs+=(--output json)

  local key='' cached=''
  if aws_ro_cache_enabled; then
    _awscli_cache_key_set key "$svc" "$op" "${eargs[@]+"${eargs[@]}"}"
    cached=$SCOURSH_AWS_CACHE_DIR/$key.json
    if [[ -f $cached ]]; then
      _awscli_serve_cached "$cached"
      return 0
    fi
    mkdir -p -- "$SCOURSH_AWS_CACHE_DIR"
    mutex_acquire "awscache-$key"
    # Re-check inside the mutex: another worker may have filled it while this
    # one waited, and fetching anyway is exactly the duplicate call the cache
    # exists to prevent.
    if [[ -f $cached ]]; then
      mutex_release "awscache-$key"
      _awscli_serve_cached "$cached"
      return 0
    fi
    local rc=0
    _awscli_fetch "$svc" "$op" "$cached" "${eargs[@]+"${eargs[@]}"}" || rc=$?
    mutex_release "awscache-$key"
    return "$rc"
  fi

  _awscli_fetch "$svc" "$op" '' "${eargs[@]+"${eargs[@]}"}"
}

_awscli_serve_cached() {
  local f=$1
  # shellcheck disable=SC2034  # published contract; see the declarations above
  SCOURSH_AWS_RO_CACHED=1
  SCOURSH_AWS_RO_STATUS=0
  _awscli_detect_truncation "$f"
  if (( SCOURSH_AWS_RO_TRUNCATED )); then
    SCOURSH_AWS_RO_OUTCOME=truncated
  else
    SCOURSH_AWS_RO_OUTCOME=ok
  fi
  cat -- "$f"
  return 0
}

# `_awscli_fetch SERVICE OPERATION CACHE_PATH ARGS...` - the one place a bare
# `aws` is invoked.  CACHE_PATH empty means "do not cache".
_awscli_fetch() {
  local svc=$1 op=$2 cache=$3
  shift 3
  # The scratch files are made in the CACHE directory when there is one, so the
  # mv below is a rename within one filesystem and therefore atomic; with the
  # cache off there is nothing to rename into and the scratch root will do.
  local dir=$SCOURSH_SCRATCH
  [[ -z $cache ]] || dir=${cache%/*}
  mkdir -p -- "$dir"
  local outf errf status=0
  # mktemp with a TEMPLATE in the destination directory, never `mktemp -p`
  # (tension 24: -p is a GNU spelling), so the mv below stays within one
  # filesystem and is therefore atomic.
  outf=$(mktemp "$dir/fetch.XXXXXX")
  errf=$(mktemp "$dir/fetch-err.XXXXXX")
  chmod 600 "$outf" "$errf" 2>/dev/null || true

  # AWS_PAGER='' rather than --no-cli-pager (finding F17): the flag is CLI
  # v2-only and a v1 host rejects it at argument parsing before the call is
  # even attempted, so every AWS call would fail while reporting a tool error
  # rather than a finding.  The environment variable is honoured by both major
  # versions and needs no version detection to use safely.
  #
  # `env` rather than a second bash prefix-assignment: the three assumed-role
  # credential vars are conditional (present only when aws_ro_use_credentials
  # has set them), and a bash prefix assignment cannot be made conditional on
  # its own line the way an `env` argv can - `AWS_ACCESS_KEY_ID=""` as a
  # constant prefix would CLEAR a legitimately-set ambient environment
  # credential on every single-account call, which is the opposite of "empty
  # means resolve the ordinary way" section 1 documents for these globals.
  local -a __envp=(AWS_PAGER=)
  if aws_ro_credentials_active; then
    __envp+=(
      AWS_ACCESS_KEY_ID="$SCOURSH_AWS_ACCESS_KEY_ID"
      AWS_SECRET_ACCESS_KEY="$SCOURSH_AWS_SECRET_ACCESS_KEY"
      AWS_SESSION_TOKEN="$SCOURSH_AWS_SESSION_TOKEN"
    )
  fi
  env "${__envp[@]}" "$SCOURSH_AWSCLI_BIN" "$svc" "$op" "$@" >"$outf" 2>"$errf" || status=$?

  if (( status != 0 )); then
    _awscli_classify "$status" "$errf"
    rm -f -- "$outf" "$errf"
    # Never silence.  Even a caller that forgets to inspect the outcome leaves
    # an audit trail in the run record, which is the same backstop reasoning
    # _finding_secret_backstop applies at finding_emit: the chokepoint is the
    # one place every call passes through.
    run_record aws_api_failure \
      "service=$svc operation=$op outcome=$SCOURSH_AWS_RO_OUTCOME code=${SCOURSH_AWS_RO_CODE:-none} status=$status"
    log_warn "aws_ro: $svc $op failed (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, $SCOURSH_AWS_RO_CODE}): ${SCOURSH_AWS_RO_ERROR:-no diagnostic}"
    return 1
  fi

  rm -f -- "$errf"
  _awscli_detect_truncation "$outf"
  if (( SCOURSH_AWS_RO_TRUNCATED )); then
    SCOURSH_AWS_RO_OUTCOME=truncated
    run_record aws_api_truncated "service=$svc operation=$op"
  else
    SCOURSH_AWS_RO_OUTCOME=ok
  fi
  # shellcheck disable=SC2034  # published contract; see the declarations above
  SCOURSH_AWS_RO_STATUS=0

  if [[ -n $cache ]]; then
    mv -- "$outf" "$cache"
    cat -- "$cache"
  else
    cat -- "$outf"
    rm -f -- "$outf"
  fi
  return 0
}

# `aws_ro_into FILE SERVICE OPERATION [ARGS...]` - the same call with the
# response written to FILE.
#
# Use this, or a plain `aws_ro ... >file`, and NEVER `body=$(aws_ro ...)`: a
# command substitution runs in a SUBSHELL, so every one of the outcome globals
# above is set in a process that then exits, and the caller reads the values
# from before the call.  A caller written that way sees `access_denied` as an
# empty response with an untouched outcome - which is the exact honesty gap
# section 2 exists to close, reintroduced by the calling convention.  This is
# the same subshell hazard lib/core.sh's own core_capture documents for `die`.
aws_ro_into() {
  (( $# >= 3 )) || die "$SCOURSH_EXIT_INPUT" \
    "aws_ro_into requires FILE SERVICE OPERATION, got: $*"
  local out=$1 rc=0
  shift
  aws_ro "$@" >"$out" || rc=$?
  return "$rc"
}

# ---------------------------------------------------------------------------
# 8. Pagination
# ---------------------------------------------------------------------------
# `aws_ro_paged DIR TOKEN_FLAG SERVICE OPERATION [ARGS...]`
#
# Follows the response's continuation token, writing one page document per
# request to DIR/page-0001.json, DIR/page-0002.json, ...  The caller walks
# those files; nothing here merges JSON, because merging pages requires knowing
# which key of which operation holds the list, which is a per-operation fact a
# generic helper cannot know and would get quietly wrong.
#
# TOKEN_FLAG is the caller's, not a guess: `--starting-token` for an operation
# the CLI has a registered paginator for, `--next-token` / `--marker` /
# `--continuation-token` for one it does not.  Which it is, is a fact about the
# operation being called, and a helper that picked one for you would send an
# argument the CLI rejects (cli_usage) on every operation it guessed wrong.
#
# SCOURSH_AWS_RO_PAGES holds the page count.  Hitting SCOURSH_AWS_MAX_PAGES is
# a DECLARED `truncated` outcome, and so is a response that says it is
# truncated while offering no token to continue with (S3's IsTruncated without
# a NextMarker) - in both cases the list is short and the caller must not
# report it as complete.
aws_ro_paged() {
  (( $# >= 4 )) || die "$SCOURSH_EXIT_INPUT" \
    "aws_ro_paged requires DIR TOKEN_FLAG SERVICE OPERATION, got: $*"
  local dir=$1 flag=$2 svc=$3 op=$4
  shift 4
  mkdir -p -- "$dir"
  SCOURSH_AWS_RO_PAGES=0
  local token='' page=0 rc=0 pagef=''
  while :; do
    page=$(( page + 1 ))
    pagef=$(printf '%s/page-%04d.json' "$dir" "$page")
    rc=0
    if [[ -n $token ]]; then
      aws_ro "$svc" "$op" "$@" "$flag" "$token" >"$pagef" || rc=$?
    else
      aws_ro "$svc" "$op" "$@" >"$pagef" || rc=$?
    fi
    if (( rc != 0 )); then
      rm -f -- "$pagef"
      SCOURSH_AWS_RO_PAGES=$(( page - 1 ))
      return 1
    fi
    # shellcheck disable=SC2034  # published contract; see the declarations above
    SCOURSH_AWS_RO_PAGES=$page
    (( SCOURSH_AWS_RO_TRUNCATED )) || { SCOURSH_AWS_RO_OUTCOME=ok; return 0; }
    if [[ -z $SCOURSH_AWS_RO_NEXT_TOKEN ]]; then
      # The response says it is incomplete and hands back nothing to resume
      # with.  Continuing would re-fetch page 1 forever.
      SCOURSH_AWS_RO_OUTCOME=truncated
      run_record aws_api_truncated "service=$svc operation=$op reason=no_continuation_token pages=$page"
      log_warn "aws_ro_paged: $svc $op reported a truncated response with no continuation token after $page page(s)"
      return 0
    fi
    if (( page >= SCOURSH_AWS_MAX_PAGES )); then
      SCOURSH_AWS_RO_OUTCOME=truncated
      run_record aws_api_truncated "service=$svc operation=$op reason=page_ceiling pages=$page"
      log_warn "aws_ro_paged: $svc $op hit the $SCOURSH_AWS_MAX_PAGES-page ceiling; the result is incomplete"
      return 0
    fi
    token=$SCOURSH_AWS_RO_NEXT_TOKEN
  done
}

# ---------------------------------------------------------------------------
# 9. Account identity
# ---------------------------------------------------------------------------
# `aws_ro_account_id_set VARNAME` - resolve, memoise and record the account the
# credentials actually belong to.
#
# It SETS a variable rather than printing one, for this codebase's standing
# reason (worker_id_set, run_fact_first_set): `die` inside a `$(...)` runs in a
# subshell, where `trap - ERR` clears only that subshell's trap and `exit` ends
# only the subshell, so a refusal is swallowed and the caller sees a crash-
# shaped diagnostic instead of the real one.
#
# `sts get-caller-identity` needs NO entry in tests/aws-readonly-allow.txt: the
# frozen `get` prefix already admits it, and an entry that no code needs is
# exactly what the lint's check 4 exists to reject.  Do not seed one.
aws_ro_account_id_set() {
  local __var=$1
  if [[ -n $SCOURSH_AWS_ACCOUNT_ID ]]; then
    printf -v "$__var" '%s' "$SCOURSH_AWS_ACCOUNT_ID"
    return 0
  fi
  local __tmp __rc=0
  __tmp=$(mktemp "$SCOURSH_SCRATCH/awscli-identity.XXXXXX")
  aws_ro sts get-caller-identity >"$__tmp" || __rc=$?
  if (( __rc != 0 )); then
    rm -f -- "$__tmp"
    printf -v "$__var" '%s' ''
    return 1
  fi
  local __line __trimmed __val __acct='' __arn=''
  while IFS= read -r __line || [[ -n $__line ]]; do
    __trimmed=${__line#"${__line%%[![:space:]]*}"}
    if _awscli_json_key_is "$__trimmed" Account; then
      _awscli_json_scalar_after_colon __val "$__trimmed" && __acct=$__val
    elif _awscli_json_key_is "$__trimmed" Arn; then
      _awscli_json_scalar_after_colon __val "$__trimmed" && __arn=$__val
    fi
  done <"$__tmp"
  rm -f -- "$__tmp"
  if [[ -z $__acct ]]; then
    # A 200 whose body carries no Account is not an identity.  Reporting one
    # anyway would put an empty account id into every finding's location.
    SCOURSH_AWS_RO_OUTCOME=error
    SCOURSH_AWS_RO_ERROR='sts get-caller-identity returned no Account field'
    log_warn "aws_ro_account_id_set: $SCOURSH_AWS_RO_ERROR"
    printf -v "$__var" '%s' ''
    return 1
  fi
  SCOURSH_AWS_ACCOUNT_ID=$__acct
  SCOURSH_AWS_CALLER_ARN=$__arn
  run_record cloud_account_id "$__acct"
  [[ -n $__arn ]] && run_record cloud_caller_arn "$__arn"
  printf -v "$__var" '%s' "$__acct"
  return 0
}

# Forget the memoised identity, AND drop the cache with it.  Step 6's
# multi-account path changes principal mid-run (sts assume-role), and a
# memoised account id from the previous one would mislabel every finding after
# the switch.
#
# Clearing the cache is not tidiness, it is required for correctness, and it is
# the mechanism rather than the key's `account` component.  Every response
# already in the cache is the PREVIOUS principal's view; and identity
# resolution itself is the one call whose key cannot carry an account, because
# the account is what it is resolving - so `sts get-caller-identity` under the
# new principal hashes identically to the old one's and is served straight back
# from the cache, reporting the account we just stopped being.  Measured; it is
# what tests/suites/awscli.sh's principal-change case exists to catch.
#
# The `account` component of the key shape docs/FOUNDATION.md freezes is kept
# and is belt-and-braces beside this, not the load-bearing half.
aws_ro_identity_forget() {
  SCOURSH_AWS_ACCOUNT_ID=''
  # shellcheck disable=SC2034  # published contract; see the declarations above
  SCOURSH_AWS_CALLER_ARN=''
  aws_ro_cache_clear
  return 0
}
