#!/usr/bin/env bash
# modules/cloud/aws/live/lambda_engine.sh - the pure half of the §8.6 Lambda
# read-only service (docs/DESIGN.md §8.6; docs/STEP6-CLOUD-PLAN.md CLOUD-21).
#
# The run.sh/engine.sh split modules/sast/ established, reused one level down
# by modules/cloud/aws/engine.sh and a second level down by
# modules/cloud/aws/live/s3_engine.sh, copied here unchanged: this file is a
# pure function library with the standard sourced-once guard and no side
# effect at source time, and modules/cloud/aws/live/lambda.sh is the file that
# DOES something when `cloud_run_service` sources it. Nothing here calls
# `aws_ro`, reads the run context or emits anything by itself; every function
# takes a response document (or a string) and answers one question about it,
# which is what lets tests/suites/cloud-lambda.sh exercise the classifiers
# against committed fixtures with no scan, no stub and no run directory.
#
# WHY A SERVICE GETS ITS OWN ENGINE FILE: modules/cloud/aws/live/s3_engine.sh's
# own header already states the reasoning this file copies verbatim - a
# classifier that knows what a Lambda execution role's IAM policy grants
# belongs to lambda and to nothing else, and every `live/<service>_engine.sh`
# is its own copy rather than a shared module-engine addition, because the
# module engine is what every one of docs/DESIGN.md §8.1-§8.6's services
# shares and growing it per-service would turn it into the union of thirty
# response formats.
#
# WHAT THIS FILE DOES NOT REUSE FROM ANY OTHER SERVICE, AND WHY.
# docs/STEP6-CLOUD-PLAN.md's own dispatch table (P12, "cloud: lambda") notes
# this ticket as "Reuses P6's role-policy reader" - P6 being `aws/live/iam.sh`,
# the CLOUD-06 ticket that was expected to land first and ship a shared
# IAM-policy-document reader this file could import. AS OF THIS TICKET, P6 has
# not landed: `modules/cloud/aws/live/` holds only `s3.sh`/`s3_engine.sh`
# (CLOUD-05) on top of which this lands. There is therefore nothing to reuse
# yet, and this file ships its OWN self-contained IAM policy-document reader
# (section 4 below) rather than block on an unlanded peer - the identical
# "land what's ready, note the gap" precedent AGENTS.md records repeatedly for
# this project's own build order (`lib/http.sh`, `modules/iac/`, `modules/sca/`
# all landed ahead of their nominal step). When `aws/live/iam.sh` lands and
# ships a real shared reader, LIFTING this file's policy-statement walker into
# it - the same move `modules/dast/passive/response_engine.sh`'s own header
# describes for `hdr_endpoints_load` - is the correct follow-up; forking it
# here is not a defect to fix opportunistically under a different, unrelated
# ticket.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_LAMBDA_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_LAMBDA_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` / `cloud_json_unescape`
# and is ALREADY SOURCED in every real run (regions.sh sources it before the
# service walk begins), so this guard is reached only by a direct-engine test.
#
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's
# "the memory model". A direct-engine test suite sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, NEVER a bare `declare`, on every global this file introduces -
# modules/cloud/aws/live/s3_engine.sh's own header states why at length: in a
# real run NOTHING sources this file at top level, `cloud_run_service` reaches
# a service script by running `source` from inside itself, and every line here
# therefore executes in THAT function's scope, where a bare `declare -A`
# creates a LOCAL that dies with the first service pass.
declare -gA _LAMBDA_DOC=()
declare -gA _LAMBDA_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `lambda_doc_load FILE` - flatten FILE once into `_LAMBDA_DOC` (path ->
# unescaped scalar) and `_LAMBDA_DOCT` (path -> `s`/`n`/`b`/`z` type), byte for
# byte s3_engine.sh's own `s3_doc_load`, copied rather than shared for the
# identical reason: every check here walks a `Statement` ARRAY, which cannot
# be read leaf-by-leaf without already knowing how many entries it has, and
# the type map is what tells `{"KMSKeyArn": null}` (a real, decodable answer -
# the function has no customer-managed key) apart from an absent key (a
# document shape this pass did not expect).
#
# CLOBBERS `_LAMBDA_DOC`/`_LAMBDA_DOCT` UNCONDITIONALLY, and that is
# deliberate rather than a limitation to route around: a caller that still
# needs an EARLIER document's data must extract it into a plain bash variable
# BEFORE loading a later one, exactly as `_lambda_run_service` (lambda.sh)
# does with `list-functions`' bucket - sorry, FUNCTION - list before it ever
# calls `lambda_doc_load` again for a per-function response.
lambda_doc_load() {
  local file=$1
  _LAMBDA_DOC=()
  _LAMBDA_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell - the
  # subshell lesson lib/core.sh's `worker_id_set` states and every doc-loading
  # function in this codebase repeats.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _LAMBDA_DOC[$path]=$val
    _LAMBDA_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `lambda_doc_load_string VARNAME STRING WORKDIR` - the same load, over a
# STRING rather than a file: writes STRING to a scratch file under WORKDIR
# (mktemp, never a fixed name, for the reason every scratch path in this
# codebase is - a predictable name is one a local user can pre-create as a
# symlink this process then writes through, CWE-377 via CWE-59) and loads it.
# Exists because `lambda get-policy`'s `Policy` field - and, on some AWS
# CLI/API combinations, `iam get-role-policy`'s `PolicyDocument` field - is
# itself a STRING holding an embedded JSON policy document rather than an
# already-parsed object; section 4 below is what tells the two shapes apart so
# this function is reached only when reloading is really needed.
lambda_doc_load_string() {
  local __string=$1 __workdir=$2 __f
  __f=$(mktemp "$__workdir/policy-doc.XXXXXX")
  printf '%s' "$__string" >"$__f"
  lambda_doc_load "$__f"
  local __rc=$?
  rm -f -- "$__f"
  return "$__rc"
}

# `lambda_path P...` - join path segments with the US byte cloud_json_flatten
# uses. s3_path's own reasoning, copied: the separator is the module engine's
# published contract, and every service script spelling a control byte by
# hand is one more chance to spell it wrong.
lambda_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# `lambda_doc_has PATH` / `lambda_doc_get VARNAME PATH` - membership and read,
# s3_doc_has/s3_doc_get's own shapes.
lambda_doc_has() {
  [[ -n ${_LAMBDA_DOCT[$1]+set} ]]
}

lambda_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_LAMBDA_DOC[$__path]:-}"
  [[ -n ${_LAMBDA_DOCT[$__path]+set} ]]
}

# `lambda_doc_children_set VARNAME PREFIX` - the newline-separated, LC_ALL=C
# SORTED list of immediate child key segments directly under PREFIX (a leaf
# at `PREFIX\x1fCHILD` with no further \x1f after CHILD). Used exactly once -
# to enumerate an environment variable MAP's key names, which unlike every
# `Statement`/`Grants`/`Buckets` array elsewhere in this codebase are not
# numeric indices but arbitrary operator-chosen strings, so the "walk index
# 0,1,2... until missing" idiom every other array-walk in this file uses does
# not apply.
#
# SORTED, RATHER THAN BASH'S OWN ASSOCIATIVE-ARRAY ITERATION ORDER, because a
# finding's `occurrence` ordinal (tension 5) and this run's own emission order
# both derive from the order a resource's properties were visited, and this
# codebase's standing convention wherever a set has no other natural order
# (data/advisories.db's own ecosystem sort, tension 25) is `LC_ALL=C sort`
# rather than an interpreter's own unspecified hash order.
lambda_doc_children_set() {
  local __var=$1 __prefix=$2 __k __rest __out=''
  for __k in "${!_LAMBDA_DOCT[@]}"; do
    [[ $__k == "$__prefix"$'\x1f'* ]] || continue
    __rest=${__k#"$__prefix"$'\x1f'}
    [[ $__rest == *$'\x1f'* ]] && continue
    __out+="${__out:+$'\n'}$__rest"
  done
  printf -v "$__var" '%s' "$(printf '%s' "$__out" | LC_ALL=C sort)"
  [[ -n $__out ]]
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `lambda_partition_of CALLER_ARN` - s3_partition_of's own logic, copied
# rather than shared for the same "own copy, no new hub edge" reason section 0
# above states. READ, NEVER HARDCODED: a Lambda function ARN in GovCloud or
# China carries that partition, and a finding citing the commercial `aws`
# partition in either names a resource that does not exist.
lambda_partition_of() {
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

# `lambda_role_name_of ROLE_ARN` - the IAM role NAME `iam get-role-policy`,
# `iam list-role-policies` and `iam list-attached-role-policies` all need as
# `--role-name`, extracted from the execution role's ARN
# (`arn:PARTITION:iam::ACCOUNT:role/PATH/NAME` or, with no IAM path,
# `arn:PARTITION:iam::ACCOUNT:role/NAME`). The role NAME is everything after
# the LAST `/` - an IAM path component may itself contain slashes, and an
# implementation that took everything after the FIRST `/` following `role/`
# would hand `--role-name` a value that includes the path and every IAM call
# built on it would fail with `NoSuchEntity` against a role that exists.
lambda_role_name_of() {
  local arn=${1:-}
  [[ $arn == */* ]] || { printf '%s' "$arn"; return 0; }
  printf '%s' "${arn##*/}"
}

# ---------------------------------------------------------------------------
# 3. Function-level facts (list-functions is already loaded into _LAMBDA_DOC)
# ---------------------------------------------------------------------------
# `lambda_function_arn ARN` / *_name / *_role / *_kms - thin `lambda_doc_get`
# wrappers over `Functions <i> <field>`, kept as one-line functions only so a
# call site never repeats the path shape by hand.
lambda_function_field() {
  local __var=$1 __i=$2 __field=$3
  lambda_doc_get "$__var" "$(lambda_path Functions "$__i" "$__field")"
}

# `lambda_env_error_present I` - true when `list-functions` reports that this
# function's environment variables could NOT be decrypted
# (`Environment.Error`), which AWS returns instead of `Environment.Variables`
# when the KMS key protecting them cannot be used by the caller. This is a
# real coverage loss for the two env-var checks - the values (and even the
# key NAMES, in this shape) are unavailable - and is reported as one rather
# than silently reading "no Environment key" as "no environment variables".
lambda_env_error_present() {
  lambda_doc_has "$(lambda_path Functions "$1" Environment Error Message)"
}

# `lambda_env_keys_set VARNAME I` - the sorted environment-variable key names
# for function index I, or empty when the function has none configured (a
# real, clean answer - see lambda_env_error_present above for the DIFFERENT,
# lossy case).
lambda_env_keys_set() {
  local __var=$1 __i=$2
  lambda_doc_children_set "$__var" "$(lambda_path Functions "$__i" Environment Variables)"
}

lambda_env_value_get() {
  local __var=$1 __i=$2 __key=$3
  lambda_doc_get "$__var" "$(lambda_path Functions "$__i" Environment Variables "$__key")"
}

# ---------------------------------------------------------------------------
# 4. IAM policy documents - the string-vs-object normalisation
# ---------------------------------------------------------------------------
# `lambda_policy_prefix_set VARNAME PATH WORKDIR` - PATH names where a policy
# document sits in the CURRENTLY LOADED doc (`Policy` for `lambda get-policy`;
# `PolicyDocument` for `iam get-role-policy`; `PolicyVersion\x1fDocument` for
# `iam get-policy-version`). Normalises the one genuine ambiguity in this
# file's whole design: `lambda get-policy`'s `Policy` field is ALWAYS a JSON
# STRING (Lambda's API gives that field no special "document" shape, so the
# CLI passes it through verbatim, still escaped), while an IAM policy
# document field is written by botocore's "document"-shaped parser and MAY
# already arrive as a native, nested JSON object depending on the AWS
# CLI/botocore version resolving the call - this codebase has no networked AWS
# account to observe either shape against directly (see AGENTS.md's own
# "verify before recommending" rule), so BOTH are handled rather than one
# assumed:
#
#   - PATH is a SCALAR STRING leaf (`lambda_doc_has PATH` true, type `s`) -
#     the string IS a JSON document. It is reloaded, via `lambda_doc_load_string`
#     and WORKDIR, as a FRESH top-level document; VARNAME is set to the empty
#     prefix (root of that fresh document).
#   - PATH names an OBJECT already flattened into the CURRENT doc (a leaf
#     exists at `PATH\x1fStatement` or `PATH\x1fStatement\x1f0...`) - nothing
#     is reloaded; VARNAME is set to PATH itself, and every statement is read
#     with PATH as its own prefix.
#
# Returns 1, VARNAME unset, when PATH names neither shape (the field is
# genuinely absent) - the caller's cue that there is no policy to classify.
#
# CLOBBERS `_LAMBDA_DOC`/`_LAMBDA_DOCT` IN THE FIRST BRANCH, exactly as
# `lambda_doc_load_string` (which it calls) always does; a caller must have
# already read anything else it needed from the OUTER document before this
# runs, the identical discipline `lambda_doc_load` states for itself above.
lambda_policy_prefix_set() {
  local __var=$1 __path=$2 __workdir=$3
  if lambda_doc_has "$__path"; then
    local __raw=${_LAMBDA_DOC[$__path]}
    lambda_doc_load_string "$__raw" "$__workdir" || return 1
    printf -v "$__var" '%s' ''
    return 0
  fi
  if lambda_doc_has "$(lambda_path "$__path" Statement)" \
    || lambda_doc_has "$(lambda_path "$__path" Statement 0 Effect)"; then
    printf -v "$__var" '%s' "$__path"
    return 0
  fi
  return 1
}

# `_lambda_stmt_path PREFIX N SEG...` - `<PREFIX(+\x1f if non-empty)>Statement\x1fN\x1fSEG...`,
# the one path shape every statement-level reader below builds.
_lambda_stmt_path() {
  local prefix=$1 n=$2
  shift 2
  if [[ -n $prefix ]]; then
    lambda_path "$prefix" Statement "$n" "$@"
  else
    lambda_path Statement "$n" "$@"
  fi
}

# `lambda_stmt_exists PREFIX N` - true when statement index N exists in the
# document currently loaded under PREFIX (root when PREFIX is empty). Checked
# on Effect/Sid/Action/Action[0] together, the identical multi-field existence
# test `s3_acl_public_grants_set`'s own header explains: a statement missing
# one of these (a malformed or partial document) must not end the walk early
# and silently stop reading the statements after it.
lambda_stmt_exists() {
  local prefix=$1 n=$2
  lambda_doc_has "$(_lambda_stmt_path "$prefix" "$n" Effect)" && return 0
  lambda_doc_has "$(_lambda_stmt_path "$prefix" "$n" Sid)" && return 0
  lambda_doc_has "$(_lambda_stmt_path "$prefix" "$n" Action)" && return 0
  lambda_doc_has "$(_lambda_stmt_path "$prefix" "$n" Action 0)" && return 0
  return 1
}

# `lambda_stmt_effect_get VARNAME PREFIX N`
lambda_stmt_effect_get() {
  local __var=$1 __prefix=$2 __n=$3
  lambda_doc_get "$__var" "$(_lambda_stmt_path "$__prefix" "$__n" Effect)"
}

# `lambda_field_values_set VARNAME PATH` - the newline-separated list of
# string values at PATH, whether PATH is a SCALAR leaf (one value) or an
# ARRAY (`PATH\x1f0`, `PATH\x1f1`, ... - walked by index until missing, the
# same idiom `s3_acl_public_grants_set` uses over `Grants`). IAM's policy
# grammar allows `Action`, `Resource` and `Principal.AWS` to be written either
# way, and a reader that only handled one shape would silently miss every
# document written in the other.
lambda_field_values_set() {
  local __var=$1 __path=$2 __out=''
  if lambda_doc_has "$__path"; then
    printf -v "$__var" '%s' "${_LAMBDA_DOC[$__path]}"
    return 0
  fi
  local __i=0 __p
  while :; do
    __p=$(lambda_path "$__path" "$__i")
    lambda_doc_has "$__p" || break
    __out+="${__out:+$'\n'}${_LAMBDA_DOC[$__p]}"
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `lambda_values_contain LIST VALUE` - whole-line membership over a
# newline-separated list, never a substring test (`*"$VALUE"*` would match
# `s3:*` against a wanted value of `*`, or match `iam:*` against a wanted
# service prefix `am`).
lambda_values_contain() {
  local list=$1 want=$2
  [[ $'\n'"$list"$'\n' == *$'\n'"$want"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 5. Classifiers over one policy document (already normalised to a PREFIX)
# ---------------------------------------------------------------------------
# `lambda_policy_scan PREFIX ADMINVAR SENSITIVEVAR SENSITIVE_LIST` - walks
# every Allow statement once and sets:
#   ADMINVAR      1 when at least one Allow statement grants BOTH a bare `*`
#                 action AND a bare `*` resource (CLOUD-LAMBDA-ROLE_WILDCARD-01,
#                 the account-wide-admin-equivalent case)
#   SENSITIVEVAR  the space-separated, deduplicated set of SENSITIVE_LIST
#                 entries an Allow statement grants a `<service>:*` (or bare
#                 `*`) action for (CLOUD-LAMBDA-ROLE_SENSITIVE_SERVICE-01)
#
# A STATEMENT ALREADY COUNTED AS ADMIN IS NOT ALSO SCANNED FOR A SENSITIVE
# SERVICE MATCH, and that is deliberate rather than an oversight: a bare `*`
# action satisfies both readings simultaneously (it names every sensitive
# service AND every other action there is), so scanning it under both would
# put a critical admin-equivalent finding and up to six high "sensitive
# service" findings on the SAME root cause in the SAME statement - the
# redundant-finding shape `docs/DESIGN.md` never asks for and an operator
# would have to read six times to learn once. A DIFFERENT statement in the
# same document granting a narrower `iam:*` is still scanned and still fires
# its own finding independently.
#
# EVERY LOCAL BELOW IS `__`-PREFIXED, INCLUDING THE PLAIN ACCUMULATORS - not
# only the arguments. `ADMINVAR`/`SENSITIVEVAR` are the CALLER's chosen
# variable NAMES, written through with `printf -v`, and lib/awscli.sh's own
# `aws_ro_account_id_set` states the reason at length: `local` SHADOWS, so a
# setter whose OWN internal variable happens to share the caller's chosen
# output name writes to its own copy and the caller reads an unset variable.
# This file's own first draft named its accumulator `admin` and its caller
# (`_lambda_classify_role`, lambda.sh) ALSO happened to declare a local
# `admin` to receive it - `printf -v admin` then wrote to the callee's own
# local rather than propagating anything back, and the caller's `admin`
# stayed `0` no matter what the policy actually granted. Caught by giving
# every internal name here the same `__` prefix this codebase's setters
# already use, which cannot collide with any caller's own chosen name.
lambda_policy_scan() {
  local __prefix=$1 __adminvar=$2 __sensitivevar=$3 __sensitive_list=$4
  local __admin=0
  local -A __seen=()
  local __out='' __effect __actions __resources __svc __entry
  local __action_has_star __resource_has_star
  local __n=0
  while lambda_stmt_exists "$__prefix" "$__n"; do
    lambda_stmt_effect_get __effect "$__prefix" "$__n" || true
    if [[ $__effect == Allow ]]; then
      __actions=''
      lambda_field_values_set __actions "$(_lambda_stmt_path "$__prefix" "$__n" Action)" || true
      __resources=''
      lambda_field_values_set __resources "$(_lambda_stmt_path "$__prefix" "$__n" Resource)" || true

      __action_has_star=0
      lambda_values_contain "$__actions" '*' && __action_has_star=1
      __resource_has_star=0
      lambda_values_contain "$__resources" '*' && __resource_has_star=1

      if (( __action_has_star && __resource_has_star )); then
        __admin=1
      else
        for __entry in $__sensitive_list; do
          __svc="$__entry:*"
          if (( __action_has_star )) || lambda_values_contain "$__actions" "$__svc"; then
            __seen[$__entry]=1
          fi
        done
      fi
    fi
    __n=$(( __n + 1 ))
  done
  printf -v "$__adminvar" '%s' "$__admin"
  for __entry in "${!__seen[@]}"; do
    __out+="${__out:+ }$__entry"
  done
  printf -v "$__sensitivevar" '%s' \
    "$(printf '%s\n' "$__out" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')"
  return 0
}

# `lambda_policy_public_principal PREFIX` - true when at least one Allow
# statement's `Principal` is the bare string `*`, or its `Principal.AWS`
# equals or contains `*`. A `Service` principal (`apigateway.amazonaws.com`,
# an EventBridge rule, ...) is the ordinary, correct way to let another AWS
# service invoke a function and is DELIBERATELY NOT tested here - only `AWS`
# ever names "any principal, or an arbitrary account", and folding `Service`
# into the same test would flag the routine shape every API-Gateway- or
# EventBridge-triggered function uses.
#
# NO CONDITION IS EVALUATED, unlike S3's own `s3_policy_is_public` (which asks
# AWS's own `get-bucket-policy-status` evaluator and therefore never has to
# reason about a Condition itself). Lambda has no equivalent server-evaluated
# "is this policy public" API, so this is a PATTERN, not a verdict - the
# check's own remediation prose says so and asks an operator to review any
# Condition on the flagged statement before treating a `*` principal as
# necessarily wrong, the same honesty this codebase applies wherever a
# non-authoritative heuristic stands in for a real evaluator.
lambda_policy_public_principal() {
  local prefix=$1
  local n=0 effect vals
  while lambda_stmt_exists "$prefix" "$n"; do
    lambda_stmt_effect_get effect "$prefix" "$n" || true
    if [[ $effect == Allow ]]; then
      vals=''
      lambda_field_values_set vals "$(_lambda_stmt_path "$prefix" "$n" Principal)" || true
      lambda_values_contain "$vals" '*' && return 0
      vals=''
      lambda_field_values_set vals "$(_lambda_stmt_path "$prefix" "$n" Principal AWS)" || true
      lambda_values_contain "$vals" '*' && return 0
    fi
    n=$(( n + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 6. The function URL config and the environment-variable checks
# ---------------------------------------------------------------------------
# `lambda_url_public_urls_set VARNAME` - over an ALREADY-LOADED
# `list-function-url-configs` response, the newline-separated list of
# FunctionUrl values whose AuthType is `NONE`. An empty list means every
# configured URL (there may be none at all - the common case) requires
# `AWS_IAM`, which is the pass condition.
lambda_url_public_urls_set() {
  local __var=$1 __out='' __i=0 __auth __url
  while lambda_doc_has "$(lambda_path FunctionUrlConfigs "$__i" FunctionUrl)"; do
    __auth=''
    lambda_doc_get __auth "$(lambda_path FunctionUrlConfigs "$__i" AuthType)"
    if [[ $__auth == NONE ]]; then
      __url=''
      lambda_doc_get __url "$(lambda_path FunctionUrlConfigs "$__i" FunctionUrl)"
      __out+="${__out:+$'\n'}$__url"
    fi
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  [[ -n $__out ]]
}

# `lambda_normalise_env_key KEY` - uppercase, `_`/`-` stripped, the identical
# normalisation modules/dast/authz_engine.sh's `authz_normalise_field` applies
# to a response field name, cased the other way (upper here, since every
# entry in lambda-secret-env-keywords.txt is written upper-case and an
# environment-variable convention is closer to `SCREAMING_SNAKE_CASE` than to
# `camelCase`).
lambda_normalise_env_key() {
  local n=${1^^}
  n=${n//_/}
  n=${n//-/}
  printf '%s' "$n"
}

# `lambda_secret_keywords_load [FILE]` - fills `_LAMBDA_SECRET_KEYWORDS`. The
# vendored-file-plus-environment-seam shape modules/dast/authz_engine.sh's
# own `authz_sensitive_load` already established for the identical reason
# (rules/RULE-FORMAT.md §9.6.1's key set is frozen; a new
# `config/scanner.conf` key moves that file and tests/lint-rules.sh together).
lambda_secret_keywords_load() {
  local file=${1:-${SCOURSH_CLOUD_LAMBDA_SECRET_ENV_KEYWORDS_FILE:-}}
  [[ -n $file ]] || file=${BASH_SOURCE[0]%/*}/lambda-secret-env-keywords.txt
  _LAMBDA_SECRET_KEYWORDS=()
  [[ -r $file ]] || return 1
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    [[ ${line:0:1} == '#' ]] && continue
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -n $line ]] || continue
    if [[ ${line:0:1} == '=' ]]; then
      _LAMBDA_SECRET_KEYWORDS+=("=$(lambda_normalise_env_key "${line:1}")")
    else
      _LAMBDA_SECRET_KEYWORDS+=("$(lambda_normalise_env_key "$line")")
    fi
  done <"$file"
  (( ${#_LAMBDA_SECRET_KEYWORDS[@]} > 0 ))
}

# `lambda_secret_keyword_matches NORMALISED_KEY` - modules/dast/authz_engine.sh's
# own `authz_field_matches`, copied for env-var keys: a `=` entry is equality,
# a bare entry a substring test.
lambda_secret_keyword_matches() {
  local n=$1 e
  for e in "${_LAMBDA_SECRET_KEYWORDS[@]+"${_LAMBDA_SECRET_KEYWORDS[@]}"}"; do
    if [[ ${e:0:1} == '=' ]]; then
      [[ $n == "${e:1}" ]] && return 0
    else
      [[ $n == *"$e"* ]] && return 0
    fi
  done
  return 1
}

# `lambda_secret_value_shape VALUE` - the small, structural, NAME-INDEPENDENT
# set of value shapes this check also matches directly rather than through
# the keyword file (lambda-secret-env-keywords.txt's own header says why:
# these are facts about the BYTES, not about what the operator happened to
# name the variable). Prints a short label naming which shape matched, or
# nothing.
#
# An AWS access key id is exactly 20 characters, `AKIA` (a long-term IAM
# user's own access key) or `ASIA` (a temporary/STS credential's own access
# key id, which is not itself secret but reliably co-located with the secret
# access key it belongs to) followed by 16 upper-case letters/digits - matched
# on the WHOLE value, never a substring, so a longer string that happens to
# contain those sixteen characters is not falsely flagged.
lambda_secret_value_shape() {
  local v=$1
  [[ $v =~ ^(AKIA|ASIA)[A-Z0-9]{16}$ ]] && { printf 'an AWS access key id'; return 0; }
  [[ $v == *'-----BEGIN '*'PRIVATE KEY'* ]] && { printf 'a PEM private-key block'; return 0; }
  return 1
}

# ---------------------------------------------------------------------------
# 7. Sensitive-service list
# ---------------------------------------------------------------------------
# `lambda_sensitive_services_load [FILE]` - fills `_LAMBDA_SENSITIVE_SERVICES`
# from modules/cloud/aws/live/lambda-sensitive-services.txt (or the
# environment override), one AWS service prefix per line.
lambda_sensitive_services_load() {
  local file=${1:-${SCOURSH_CLOUD_LAMBDA_SENSITIVE_SERVICES_FILE:-}}
  [[ -n $file ]] || file=${BASH_SOURCE[0]%/*}/lambda-sensitive-services.txt
  _LAMBDA_SENSITIVE_SERVICES=''
  [[ -r $file ]] || return 1
  local line out=''
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    [[ ${line:0:1} == '#' ]] && continue
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -n $line ]] || continue
    out+="${out:+ }$line"
  done <"$file"
  printf -v _LAMBDA_SENSITIVE_SERVICES '%s' "$out"
  [[ -n $out ]]
}

# ---------------------------------------------------------------------------
# 8. Emission
# ---------------------------------------------------------------------------
# `lambda_registry_locate_set SETVAR IDXVAR CHECK_ID` - s3_registry_locate_set's
# own logic, copied.
lambda_registry_locate_set() {
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

# `lambda_emit_finding CHECK_ID FUNCTION_ARN REGION SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, VIA
# `finding_from_record`, exactly as s3_emit_finding's own header states at
# length and for the identical reason: a script that set severity, CWE, OWASP
# category or `cis` by hand would be a second copy of every one of them to
# keep in step with the registry, and this module's whole point is that a
# compliance report reads the registry's own `cis` value.
#
# THE CELL IS THE PASS'S REGION, WHICH IS ALSO THE RESOURCE'S REGION - THE ONE
# THING THAT DIFFERS FROM S3'S OWN EMITTER. `lambda` is a `regional` row in
# `_CLOUD_SERVICES` (unlike `s3`'s `global` one), so `cloud_run_service`
# already sourced this script once per enabled region with
# `SCOURSH_CLOUD_REGION` set to the region a Lambda function genuinely lives
# in - there is no separate "resolve the resource's own region" step S3 needs
# for its account-wide `list-buckets` call, because `lambda list-functions`
# itself is a per-region call answering only for functions in that region.
lambda_emit_finding() {
  local check_id=$1 arn=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  lambda_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/lambda emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # `internet`/`none`/true for the two public-exposure checks, matching
  # data/severity-rubric.conf's actual recognised `exposure` vocabulary
  # (`internet`/`internal`/`unknown`) - `internal`/`user` (not the bare
  # default) for the rest, the identical split s3_emit_finding's own case
  # statement makes.
  case $check_id in
    CLOUD-LAMBDA-PUBLIC_FUNCTION_URL-01 | CLOUD-LAMBDA-PUBLIC_POLICY-01)
      finding_set exposure internet
      finding_set auth none
      finding_set sensitive_data true
      ;;
    CLOUD-LAMBDA-ENV_SECRET-01)
      finding_set exposure internal
      finding_set auth user
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
