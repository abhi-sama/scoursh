#!/usr/bin/env bash
# modules/cloud/aws/live/iam_engine.sh - the pure half of the §8.1 IAM
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-06).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3{,_engine}.sh established
# one level down, applied a second time: this file is a pure function library
# with the standard sourced-once guard and no side effect at source time, and
# modules/cloud/aws/live/iam.sh is the file that DOES something when
# `cloud_run_service` sources it.  Nothing here calls `aws_ro`, reads the run
# context or emits anything by itself.
#
# IAM IS A `global` ROW, AND EVERY FINDING CARRIES THE LITERAL `loc_region`
# `global` - not a resolved region, unlike S3.  IAM has no per-resource region
# at all: a user, role or policy ARN carries no region component
# (`arn:<partition>:iam::<account>:<type>/<name>`), so there is nothing to
# resolve the way S3's `get-bucket-location` resolves a bucket's real region.
# `docs/STEP6-CLOUD-PLAN.md`'s own CLOUD-06 row states this in terms ("Global
# service; findings carry `region: global`"), so this module's cell and its
# `loc_region` are the SAME string for every finding - simpler than S3, where
# the two deliberately differ.
#
# EVERY USER/ROLE ARN IS READ OFF THE API RESPONSE, NEVER BUILT.  Unlike an S3
# bucket ARN (which no S3 response ever returns, forcing s3_engine.sh to
# construct one), `list-users`/`get-user`/`list-roles`/`get-role` all return a
# populated `Arn` field directly. Building one by hand here would be a second,
# driftable copy of the same fact IAM's own API already states.
#
# A POLICY DOCUMENT REACHES THIS FILE PERCENT-ENCODED, AND MUST BE DECODED
# BEFORE `cloud_json_flatten` EVER SEES IT.  `AssumeRolePolicyDocument`,
# `get-user-policy`/`get-role-policy`'s `PolicyDocument`, and
# `get-policy-version`'s `PolicyVersion.Document` are all URL-encoded JSON
# strings (RFC 3986 percent-encoding) - the CLI does not decode them, and
# feeding the encoded bytes to the JSON parser fails every leaf lookup
# silently (every statement's `Effect`/`Action`/`Resource` reads as absent,
# which is the trap: a policy document check that never fires reads as a
# clean account). `iam_url_decode` is the inverse.
#
# THE FULL-ADMIN AND TRUST-POLICY CLASSIFIERS ARE PATTERN MATCHES, NOT A REAL
# POLICY EVALUATION, AND THAT IS A STATED LIMIT RATHER THAN A SILENT ONE.
# `iam simulate-principal-policy` (the read-only prefix already admits
# `simulate`) could answer "can this identity actually do X" authoritatively,
# the way S3's `get-bucket-policy-status` answers "is this bucket actually
# public" with AWS's own evaluator - but simulation needs one call PER ACTION
# PER PRINCIPAL and this check has no fixed action list to simulate against,
# so it is out of scope here. The literal shape this file matches - a
# statement with `Effect: Allow`, `Action` containing exactly `*`, `Resource`
# containing exactly `*`, and no `Condition` - is CIS AWS Foundations
# Benchmark v3.0.0 control 1.16's own published audit procedure for "IAM
# policies that allow full administrative privileges", so it is not an
# invented heuristic; it is deliberately narrower than a full evaluation and
# will not catch an equivalent permission set assembled from several
# non-wildcard statements. `data/cis-mappings` does not carry control 1.16
# today (see `docs/CIS-MAPPINGS.md` §4 - it is a stated gap, not an omission
# from this ticket), so `CLOUD-IAM-POLICY_FULL_ADMIN-01` cites no `cis` value;
# do not invent one.
#
# A `Statement` WRITTEN AS A BARE OBJECT RATHER THAN A ONE-ELEMENT ARRAY IS A
# STATED GAP.  IAM's JSON policy grammar permits either shape for a
# single-statement policy; this file walks the array form only
# (`Statement/0/...`, `Statement/1/...`, ...) and does not special-case the
# bare-object form (`Statement/Effect` with no index). Widening it is a
# one-function change (`_iam_statement_prefixes_set`) and is left for the
# ticket that first hits a real policy written that way, rather than guessed
# at here with no fixture to prove it against.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_IAM_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_IAM_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` / `cloud_json_unescape`
# and is ALREADY SOURCED in every real run (regions.sh sources it before the
# service walk begins), so this guard is reached only by a direct-engine test -
# the identical shape s3_engine.sh's own guard documents.
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare`, for the reason s3_engine.sh's own
# header records at length: in a real run nothing sources this file at top
# level, and `cloud_run_service` reaches it from inside a function, where a
# bare `declare -A` would create a local that dies with the pass.
declare -gA _IAM_DOC=()
declare -gA _IAM_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `iam_doc_load FILE` - flatten FILE into `_IAM_DOC`/`_IAM_DOCT`, exactly as
# s3_engine.sh's `s3_doc_load` does, for the identical reasons that file's own
# header gives (an array cannot be read leaf-by-leaf without knowing its
# length first; the type map is what tells `false` apart from absent).
iam_doc_load() {
  local file=$1
  _IAM_DOC=()
  _IAM_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell - the
  # standing subshell lesson (lib/core.sh's `worker_id_set`), in its loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _IAM_DOC[$path]=$val
    _IAM_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `iam_path P...` - join path segments with the US byte cloud_json_flatten
# uses.  A function rather than an inline `$'\x1f'`, for s3_path's own reason:
# the separator is the module engine's published contract.
iam_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

iam_doc_has() {
  [[ -n ${_IAM_DOCT[$1]+set} ]]
}

iam_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_IAM_DOC[$__path]:-}"
  [[ -n ${_IAM_DOCT[$__path]+set} ]]
}

# `iam_doc_load_string JSON` - the same load `iam_doc_load` performs, over a
# JSON document already held as a bash string rather than a file on disk.
# Exists for exactly one shape: a policy document, which arrives nested
# inside a LARGER response as a percent-encoded string leaf (see this file's
# header) - decoding it and re-flattening the result needs no scratch file,
# and every one of this file's other documents already has a real file to
# `iam_doc_load` directly.
iam_doc_load_string() {
  local json=$1
  _IAM_DOC=()
  _IAM_DOCT=()
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _IAM_DOC[$path]=$val
    _IAM_DOCT[$path]=$type
  done < <(cloud_json_flatten <<<"$json" 2>/dev/null)
  return 0
}

# `_iam_doc_has_prefix WANT` - true when some loaded leaf's path is WANT
# itself or begins WANT immediately followed by the path separator.  Used to
# ask "does this object have ANY key under here" for an object whose own
# children are not named in advance (a `Condition` block's operator and
# condition-key names, which the caller does not know ahead of the document).
_iam_doc_has_prefix() {
  local want=$1 k
  for k in "${!_IAM_DOCT[@]}"; do
    case $k in
      "$want" | "$want"$'\x1f'*) return 0 ;;
    esac
  done
  return 1
}

# ---------------------------------------------------------------------------
# 2. Percent-decoding a policy document
# ---------------------------------------------------------------------------
# `iam_url_decode STR` - RFC 3986 percent-decoding, applied once to a
# `PolicyDocument`/`AssumeRolePolicyDocument`/`PolicyVersion.Document` string
# before it is ever handed to `cloud_json_flatten`.  A `+` is left as a
# literal plus rather than decoded to a space: IAM's percent-encoding is the
# generic RFC 3986 form, not HTML form-encoding, and JSON never legitimately
# contains an unencoded `+` that a policy document would rely on this
# distinguishing.
#
# SC1003: the `'\'` literals below are the single backslash byte this
# function exists to interpret, mirroring cloud_json_unescape's own disable
# for the identical reason.
# shellcheck disable=SC1003
iam_url_decode() {
  local s=$1 out='' i n ch hex decoded
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch == '%' ]]; then
      hex=${s:i+1:2}
      if [[ $hex =~ ^[0-9A-Fa-f]{2}$ ]]; then
        # shellcheck disable=SC2059
        printf -v decoded "\\x${hex}"
        out+=$decoded
        i=$(( i + 2 ))
        continue
      fi
    fi
    out+=$ch
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 3. The ARN partition (read off the caller identity, never hardcoded)
# ---------------------------------------------------------------------------
# `iam_partition_of CALLER_ARN` - byte-identical to s3_engine.sh's
# `s3_partition_of`, kept as its own copy rather than a cross-service call for
# the reason that file's own header gives one level up: a service file belongs
# to its own service, and a shared copy would be a third thing
# (`modules/cloud/aws/engine.sh`) every service sources into the union of
# every other service's needs. Used here only as the fallback root ARN for the
# four account-wide checks, since every user/role ARN is read off the API
# response directly (see this file's own header).
iam_partition_of() {
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

# `iam_account_root_arn PARTITION ACCOUNT` - the account's own root principal
# ARN, used as `loc_resource_key` for the four account-wide checks (root MFA,
# root access keys, the password policy, IAM Access Analyzer), none of which
# names a user, role or policy of its own.
iam_account_root_arn() {
  printf 'arn:%s:iam::%s:root' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 4. The root account (get-account-summary)
# ---------------------------------------------------------------------------
# `iam_summary_flag_set VARNAME KEY` - the numeric 0/1 SummaryMap flag at KEY
# in the loaded `get-account-summary` document.  Returns 1 (VARNAME set to 0)
# when the key is absent, which the real API never does for these two keys -
# treating an absence as "off" rather than dying is the same fail-safe-to-a-
# recorded-gap posture `s3_bpa_gaps_set` takes for an absent BPA setting,
# applied to a single scalar instead of four.
#
# `SummaryMap` VALUES ARE JSON NUMBERS, NOT BOOLEANS.  `AccountMFAEnabled` and
# `AccountAccessKeysPresent` are `0`/`1` integers in the real API response, not
# `true`/`false` - a caller that compared against the string `true` would
# never fire.
iam_summary_flag_set() {
  local __var=$1 __key=$2 __p __v
  __p=$(iam_path SummaryMap "$__key")
  __v=${_IAM_DOC[$__p]:-0}
  printf -v "$__var" '%s' "$__v"
  [[ $__v == 1 ]]
}

# ---------------------------------------------------------------------------
# 5. The account password policy (get-account-password-policy)
# ---------------------------------------------------------------------------
# CIS v3.0.0's numbers this file cites: 1.8 (minimum length >= 14), 1.9
# (password reuse prevention - CIS's own audit procedure asks for >= 24
# remembered passwords).
declare -gi IAM_PASSWORD_MIN_LENGTH_FLOOR=14
declare -gi IAM_PASSWORD_REUSE_PREVENTION_FLOOR=24

# `iam_password_policy_gaps_set VARNAME` - over the loaded
# `get-account-password-policy` document, the space-separated names of the
# CIS-required settings that are NOT met: `min_length`, `reuse_prevention`,
# either, both, or neither.  Called only on a SUCCESSFUL response; the
# NoSuchEntity case ("no password policy configured at all") is a script-level
# decision, not a document to load, since there is no document.
#
# THE RESPONSE IS WRAPPED UNDER `PasswordPolicy`, unlike `get-account-summary`
# below, which puts every flag directly under `SummaryMap`.  Reading these two
# leaves unprefixed would silently read nothing (both fall back to `0`,
# meaning "every check is a gap"), which happens to be the right answer for a
# genuinely absent policy but the wrong REASON - it would report a
# present-but-misconfigured policy identically to an absent one, and the
# script owes the reader which of those it actually observed.
iam_password_policy_gaps_set() {
  local __var=$1 __out='' __len __reuse
  __len=${_IAM_DOC[$(iam_path PasswordPolicy MinimumPasswordLength)]:-0}
  __reuse=${_IAM_DOC[$(iam_path PasswordPolicy PasswordReusePrevention)]:-0}
  (( __len >= IAM_PASSWORD_MIN_LENGTH_FLOOR )) || __out+="${__out:+ }min_length"
  (( __reuse >= IAM_PASSWORD_REUSE_PREVENTION_FLOOR )) || __out+="${__out:+ }reuse_prevention"
  printf -v "$__var" '%s' "$__out"
  return 0
}

# ---------------------------------------------------------------------------
# 6. IAM Access Analyzer (accessanalyzer list-analyzers)
# ---------------------------------------------------------------------------
# `iam_analyzer_has_active` - true when the loaded `list-analyzers` document
# names at least one analyzer whose `status` is `ACTIVE`.  `CREATING` and
# `DISABLED` do not count: a `CREATING` analyzer has not finished its initial
# scan yet and a `DISABLED` one has been turned off, so neither is currently
# producing findings, which is the fact CIS control 1.20 is about.
#
# THE FIELD NAMES ARE LOWERCASE (`analyzers`, `status`), NOT PASCAL-CASE.
# Access Analyzer is a newer API than the rest of IAM used here and its JSON
# shape follows a different, all-lowercase convention throughout
# (`analyzers[].arn`/`.name`/`.type`/`.status`) - spelling this the way every
# other call in this file is spelled would silently match nothing and read
# every account as having no analyzer at all, which happens to be this
# check's OWN finding, so a case built only from a positive fixture would
# never catch it.
iam_analyzer_has_active() {
  local i=0 p
  while :; do
    p=$(iam_path analyzers "$i" status)
    iam_doc_has "$p" || break
    [[ ${_IAM_DOC[$p]:-} == ACTIVE ]] && return 0
    i=$(( i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 7. Permission boundaries and RoleLastUsed (get-user / get-role)
# ---------------------------------------------------------------------------
# `iam_has_permission_boundary ENTITY_KEY` - true when the loaded `get-user`/
# `get-role` document carries a `PermissionsBoundary` block.  ENTITY_KEY is
# `User` or `Role`: BOTH operations wrap their whole response one level down
# (`{"User": {...}}` / `{"Role": {...}}`), unlike `ListUsers`/`ListRoles`,
# which wrap the same object shape inside a `Users`/`Roles` ARRAY instead - so
# a caller reading a `GetUser`/`GetRole` response must name which wrapper it
# is unwrapping rather than this file guessing from the file alone.  The
# type-map presence test (never `[[ -n $value ]]`) is what tells "no boundary
# at all" apart from a boundary whose own leaf values happen to be recorded
# oddly; the field checked for existence, `PermissionsBoundaryArn`, is always
# non-empty when AWS returns the block at all.
iam_has_permission_boundary() {
  local entity_key=$1
  iam_doc_has "$(iam_path "$entity_key" PermissionsBoundary PermissionsBoundaryArn)"
}

# `iam_role_last_used_epoch VARNAME` - the UTC epoch of the loaded `get-role`
# document's `Role.RoleLastUsed.LastUsedDate`, or return 1 (VARNAME empty)
# when the role has never been used at all - which is the ordinary, expected
# shape for a role AWS has never recorded an assumption of, not a parse
# failure.  Unlike `iam_has_permission_boundary`, this one is role-only, so
# the `Role` wrapper is spelled directly rather than taking it as a parameter.
iam_role_last_used_epoch() {
  local __var=$1 __raw
  __raw=${_IAM_DOC[$(iam_path Role RoleLastUsed LastUsedDate)]:-}
  if [[ -z $__raw ]]; then
    printf -v "$__var" '%s' ''
    return 1
  fi
  iam_iso8601_to_epoch "$__var" "$__raw"
}

# `iam_role_assume_policy_raw VARNAME` - the still-percent-encoded
# `Role.AssumeRolePolicyDocument` string out of the loaded `get-role`
# document, or return 1 (VARNAME empty) when the field is absent - which
# never happens for a real role (every role has a trust policy by
# construction) but is handled rather than assumed, the same defensive
# posture every other `_set` function in this file takes for a field the real
# API always sends.
iam_role_assume_policy_raw() {
  local __var=$1 __p
  __p=$(iam_path Role AssumeRolePolicyDocument)
  printf -v "$__var" '%s' "${_IAM_DOC[$__p]:-}"
  [[ -n ${_IAM_DOC[$__p]:-} ]]
}

# `iam_policy_document_raw_set VARNAME` - the still-percent-encoded
# `PolicyDocument` string out of a loaded `get-user-policy`/`get-role-policy`
# response (a top-level field, unlike `get-user`/`get-role`'s entity
# wrapper - neither of these two operations wraps its response at all).
iam_policy_document_raw_set() {
  local __var=$1
  printf -v "$__var" '%s' "${_IAM_DOC[PolicyDocument]:-}"
  [[ -n ${_IAM_DOC[PolicyDocument]:-} ]]
}

# `iam_policy_version_document_raw_set VARNAME` - the still-percent-encoded
# `PolicyVersion.Document` string out of a loaded `get-policy-version`
# response.
iam_policy_version_document_raw_set() {
  local __var=$1 __p
  __p=$(iam_path PolicyVersion Document)
  printf -v "$__var" '%s' "${_IAM_DOC[$__p]:-}"
  [[ -n ${_IAM_DOC[$__p]:-} ]]
}

# `iam_policy_default_version_id_set VARNAME` - `Policy.DefaultVersionId` out
# of a loaded `get-policy` response, the version `get-policy-version` must be
# asked for next: a managed policy carries every version it was ever updated
# to, and only the default one is what is actually in force.
iam_policy_default_version_id_set() {
  local __var=$1 __p
  __p=$(iam_path Policy DefaultVersionId)
  printf -v "$__var" '%s' "${_IAM_DOC[$__p]:-}"
  [[ -n ${_IAM_DOC[$__p]:-} ]]
}

# ---------------------------------------------------------------------------
# 8. Time: an ISO 8601 timestamp to a UTC epoch, in bash
# ---------------------------------------------------------------------------
# EVERY IAM TIMESTAMP THIS SERVICE READS (`CreateDate`, `PasswordLastUsed`,
# `LastUsedDate`) IS DECIDED BY ARITHMETIC THIS FILE OWNS, NOT BY `date`, for
# the identical reason modules/dast/passive/tls_engine.sh's own header gives:
# `date -d` is GNU-only and `date -j -f` is BSD-only, so a portable converter
# is required either way, and writing it here makes `now` INJECTABLE - which
# is what lets a committed fixture timestamp exercise "stale" and "fresh"
# deterministically instead of a suite whose verdict changes as the calendar
# moves. This is a fresh, ISO-8601-shaped copy rather than a call into
# tls_engine.sh's ASN.1-shaped one: the two parse different wire formats
# (`Jun  1 12:00:00 2024 GMT` there, `2024-06-01T12:00:00+00:00` here), reusing
# only the shared Howard Hinnant days-from-civil arithmetic, restated here
# rather than sourced across modules for the same reason `iam_partition_of`
# above is its own copy of s3_partition_of - one service does not source
# another's engine file.
_iam_days_from_civil() {
  local y=$1 m=$2 d=$3 era yoe doy doe
  (( m <= 2 )) && y=$(( y - 1 ))
  if (( y >= 0 )); then
    era=$(( y / 400 ))
  else
    era=$(( (y - 399) / 400 ))
  fi
  yoe=$(( y - era * 400 ))
  if (( m > 2 )); then
    doy=$(( (153 * (m - 3) + 2) / 5 + d - 1 ))
  else
    doy=$(( (153 * (m + 9) + 2) / 5 + d - 1 ))
  fi
  doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
  printf '%s' $(( era * 146097 + doe - 719468 ))
}

# `iam_iso8601_to_epoch VARNAME STR` - the UTC epoch seconds of an AWS
# `DateTime` value, or return 1 (VARNAME empty) when STR does not match the
# shape the AWS CLI actually emits: `YYYY-MM-DDTHH:MM:SS` followed by either
# `Z` or a `+HH:MM`/`-HH:MM` UTC offset (`--output json` always resolves to
# UTC, so only the `+00:00` spelling of that offset is accepted - a caller
# that accepted an arbitrary offset without applying it would silently
# mis-date every timestamp by however many hours the offset named).
# Fractional seconds, if present, are truncated rather than rounded.
iam_iso8601_to_epoch() {
  local __var=$1 __s=$2 __yyyy __mm __dd __hh __mi __ss __days
  if [[ ! $__s =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|\+00:00|-00:00)$ ]]; then
    printf -v "$__var" '%s' ''
    return 1
  fi
  __yyyy=${BASH_REMATCH[1]} __mm=${BASH_REMATCH[2]} __dd=${BASH_REMATCH[3]}
  __hh=${BASH_REMATCH[4]} __mi=${BASH_REMATCH[5]} __ss=${BASH_REMATCH[6]}
  __days=$(_iam_days_from_civil "$(( 10#$__yyyy ))" "$(( 10#$__mm ))" "$(( 10#$__dd ))")
  printf -v "$__var" '%s' $(( __days * 86400 + 10#$__hh * 3600 + 10#$__mi * 60 + 10#$__ss ))
  return 0
}

# `iam_age_days EPOCH NOW` - whole days between the two, never signed (a
# caller already knows the direction: every use here is "how long ago").
iam_age_days() {
  local delta=$(( $2 - $1 ))
  (( delta < 0 )) && delta=$(( -delta ))
  printf '%s' $(( delta / 86400 ))
}

# ---------------------------------------------------------------------------
# 9. The trust policy (AssumeRolePolicyDocument, already decoded and loaded)
# ---------------------------------------------------------------------------
# `_iam_statement_indices` - the array indices `Statement/N/...` names in the
# loaded document, in order.  See this file's header for why the bare-object
# `Statement/Effect` form is a stated gap rather than handled here.
_iam_statement_count() {
  local i=0
  while iam_doc_has "$(iam_path Statement "$i" Effect)"; do
    i=$(( i + 1 ))
  done
  printf '%s' "$i"
}

# `_iam_principal_values_set VARNAME PREFIX` - one line per scalar value under
# PREFIX's `Principal` (bare `"Principal": "*"`) or `Principal.AWS` (a string
# or an array of strings) - AWS's two legal shapes for a principal that admits
# an AWS-account-style value at all. `Federated`/`Service` principals are
# deliberately not read here: this function feeds only the two AWS-account
# checks (wildcard, cross-account), and a federated IdP or an AWS service
# principal is neither.
_iam_principal_values_set() {
  local __var=$1 __prefix=$2 __out='' __p __t __i __ip
  __p=$(iam_path "$__prefix" Principal)
  __t=${_IAM_DOCT[$__p]:-}
  if [[ $__t == s ]]; then
    __out+="${_IAM_DOC[$__p]}"$'\n'
  fi
  __p=$(iam_path "$__prefix" Principal AWS)
  __t=${_IAM_DOCT[$__p]:-}
  if [[ $__t == s ]]; then
    __out+="${_IAM_DOC[$__p]}"$'\n'
  else
    __i=0
    while :; do
      __ip=$(iam_path "$__prefix" Principal AWS "$__i")
      iam_doc_has "$__ip" || break
      __out+="${_IAM_DOC[$__ip]:-}"$'\n'
      __i=$(( __i + 1 ))
    done
  fi
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `iam_trust_has_wildcard_principal` - true when any statement's `Principal`
# (bare or `.AWS`) is the literal `*`.  A WHOLE-VALUE COMPARISON, never a
# substring: an AWS account id or a role ARN containing the digit sequence
# nowhere spells the bare asterisk, so there is no lookalike to guard against
# the way S3's ACL-grantee check does, but the discipline is kept for the
# identical reason - a value is either exactly the wildcard or it is not.
iam_trust_has_wildcard_principal() {
  local n i prefix vals v
  n=$(_iam_statement_count)
  for (( i = 0; i < n; i++ )); do
    prefix=$(iam_path Statement "$i")
    _iam_principal_values_set vals "$prefix"
    while IFS= read -r v; do
      [[ -n $v ]] || continue
      [[ $v == '*' ]] && return 0
    done <<<"$vals"
  done
  return 1
}

# `_iam_account_id_from_principal VALUE` - the 12-digit account id a
# `Principal.AWS` value names, or empty when VALUE is not an account-shaped
# principal at all (a service principal, a federated IdP, or a malformed
# value). Accepts a bare 12-digit account id or a full
# `arn:<partition>:iam::<account>:...` ARN, both of which AWS accepts as a
# principal value.
_iam_account_id_from_principal() {
  local v=$1
  if [[ $v =~ ^[0-9]{12}$ ]]; then
    printf '%s' "$v"
    return 0
  fi
  if [[ $v =~ ^arn:[^:]+:iam::([0-9]{12}):.*$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

# `iam_trust_has_unconditional_cross_account OWN_ACCOUNT` - true when any
# statement's `Principal.AWS` names an AWS account other than OWN_ACCOUNT,
# with Effect Allow, and the statement carries no `Condition` naming
# `sts:ExternalId` anywhere under it. `_iam_doc_has_prefix` is what lets this
# ask "any Condition operator, any key, naming this" without knowing which
# operator (`StringEquals`, `StringLike`, ...) the trust policy's author used.
iam_trust_has_unconditional_cross_account() {
  local own=$1 n i prefix effect vals v acct condprefix
  n=$(_iam_statement_count)
  for (( i = 0; i < n; i++ )); do
    prefix=$(iam_path Statement "$i")
    effect=${_IAM_DOC[$(iam_path "$prefix" Effect)]:-}
    [[ $effect == Allow ]] || continue
    _iam_principal_values_set vals "$prefix"
    while IFS= read -r v; do
      [[ -n $v ]] || continue
      acct=$(_iam_account_id_from_principal "$v") || continue
      [[ $acct == "$own" ]] && continue
      condprefix=$(iam_path "$prefix" Condition)
      if _iam_doc_has_prefix "$condprefix" \
        && _iam_condition_names_external_id "$condprefix"; then
        continue
      fi
      return 0
    done <<<"$vals"
  done
  return 1
}

# `_iam_condition_names_external_id CONDPREFIX` - true when some key under
# CONDPREFIX is exactly `sts:ExternalId`, at any nesting depth an operator
# (`StringEquals`, `StringLike`, ...) puts it at.
_iam_condition_names_external_id() {
  local prefix=$1 k
  for k in "${!_IAM_DOCT[@]}"; do
    case $k in
      "$prefix"$'\x1f'*$'\x1f''sts:ExternalId'*) return 0 ;;
      "$prefix"$'\x1f''sts:ExternalId'*) return 0 ;;
    esac
  done
  return 1
}

# ---------------------------------------------------------------------------
# 9b. The two policy rosters (list-user-policies/list-role-policies,
#     list-attached-user-policies/list-attached-role-policies)
# ---------------------------------------------------------------------------
# `iam_inline_policy_names_set VARNAME` - one name per line, out of the loaded
# `list-user-policies`/`list-role-policies` document's `PolicyNames` array.
iam_inline_policy_names_set() {
  local __var=$1 __out='' __i=0 __p
  while :; do
    __p=$(iam_path PolicyNames "$__i")
    iam_doc_has "$__p" || break
    __out+="${_IAM_DOC[$__p]:-}"$'\n'
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `iam_attached_policy_arns_set VARNAME` - one ARN per line, out of the
# loaded `list-attached-user-policies`/`list-attached-role-policies`
# document's `AttachedPolicies` array.  The name alone is not enough to reach
# the policy's own content - `get-policy`/`get-policy-version` are addressed
# by ARN - so only the ARN is read here; a caller wanting the name for
# evidence prose has the ARN's own trailing path segment.
iam_attached_policy_arns_set() {
  local __var=$1 __out='' __i=0 __p
  while :; do
    __p=$(iam_path AttachedPolicies "$__i" PolicyArn)
    iam_doc_has "$__p" || break
    __out+="${_IAM_DOC[$__p]:-}"$'\n'
    __i=$(( __i + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
  return 0
}

# ---------------------------------------------------------------------------
# 10. A policy document (inline or a managed policy's version), already
#     decoded and loaded
# ---------------------------------------------------------------------------
# `_iam_field_has_star PREFIX FIELD` - true when PREFIX's FIELD (`Action` or
# `Resource`) is the bare string `*`, or an array containing it as one whole
# element.  Never a substring match: `s3:*` is a real, narrower action and
# must not be confused with the bare wildcard.
_iam_field_has_star() {
  local prefix=$1 field=$2 p t i pi
  p=$(iam_path "$prefix" "$field")
  t=${_IAM_DOCT[$p]:-}
  if [[ $t == s ]]; then
    [[ ${_IAM_DOC[$p]} == '*' ]]
    return
  fi
  i=0
  while :; do
    pi=$(iam_path "$prefix" "$field" "$i")
    iam_doc_has "$pi" || break
    [[ ${_IAM_DOC[$pi]:-} == '*' ]] && return 0
    i=$(( i + 1 ))
  done
  return 1
}

# `iam_policy_doc_has_full_admin` - true when the loaded policy document
# contains a statement matching CIS v3.0.0 control 1.16's published audit
# shape: `Effect: Allow`, `Action` containing exactly `*`, `Resource`
# containing exactly `*`, and no `Condition` block at all (a real `Condition`
# - even one that narrows nothing - takes the statement out of this file's
# scope rather than being evaluated, per this file's own header note on why a
# real evaluation is out of scope).
iam_policy_doc_has_full_admin() {
  local n i prefix effect
  n=$(_iam_statement_count)
  for (( i = 0; i < n; i++ )); do
    prefix=$(iam_path Statement "$i")
    effect=${_IAM_DOC[$(iam_path "$prefix" Effect)]:-}
    [[ $effect == Allow ]] || continue
    _iam_field_has_star "$prefix" Action || continue
    _iam_field_has_star "$prefix" Resource || continue
    _iam_doc_has_prefix "$(iam_path "$prefix" Condition)" && continue
    return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# 11. Emission
# ---------------------------------------------------------------------------
# `iam_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the
# check registry this run loaded.  Byte-identical to s3_engine.sh's
# `s3_registry_locate_set`; kept as its own copy for the same reason every
# other function in this file is - see this file's header.
iam_registry_locate_set() {
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

# `iam_emit_finding CHECK_ID ARN SUB_KEY EVIDENCE` - the same shape as
# s3_engine.sh's `s3_emit_finding`, with `region` dropped as a parameter: it
# is always the literal `global` here (this file's own header), never a
# per-resource fact to pass in, so a call site cannot forget it and cannot
# disagree with the cell.
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, VIA
# `finding_from_record`, per s3_emit_finding's own note at length: title,
# severity, confidence, cwe, owasp, remediation, references and `cis` are all
# registry fields, never retyped here.
iam_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  iam_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/iam emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # `exposure`/`auth` feed data/severity-rubric.conf's adjustment of the
  # record's base severity. A trust policy admitting `*` or an unconstrained
  # other account is reachable by a principal this account did not choose -
  # `external`/`user` (assuming the role still needs SOME AWS credential, so
  # never `none` the way an anonymous public S3 read is) - while every other
  # IAM check here is a property of this account's own configuration,
  # `internal`/`user`.
  case $check_id in
    CLOUD-IAM-TRUST_WILDCARD_PRINCIPAL-01 | CLOUD-IAM-TRUST_NO_EXTERNAL_ID-01)
      finding_set exposure external
      finding_set auth user
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/global}"
  finding_set loc_account_id "$account"
  finding_set loc_region global
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
