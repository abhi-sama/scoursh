#!/usr/bin/env bash
# modules/cloud/aws/live/apigw_engine.sh - the pure half of the §8.4 API
# Gateway read-only service (docs/DESIGN.md §8.4; docs/STEP6-CLOUD-PLAN.md
# CLOUD-22).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3_engine.sh's own header
# documents, applied a second time: this file is a pure function library with
# the standard sourced-once guard and no side effect at source time, and
# modules/cloud/aws/live/apigw.sh is the file that DOES something when
# `cloud_run_service` sources it. Nothing here calls `aws_ro`, reads the run
# context, or emits anything by itself.
#
# THIS TICKET IS CROSS-MODULE: it is both a §8.1-style read-only service AND
# a PRODUCER of `reports/<run>/inventory/endpoints.json` (docs/FOUNDATION.md
# tension 21; docs/INVENTORY-FORMAT.md), the frozen artifact
# `modules/dast/crawl.sh` (DAST-04) reads. This file therefore owns TWO
# things a sibling §8.1 engine does not: an independent, byte-compatible
# reader/writer for that file (never a `source` of `modules/dast/crawl_engine.sh` -
# tension 21's "modules never invoke each other and never import each
# other's code" applies here exactly as it does to DAST's own SAST-route-
# import half), and the ARN/classifier pair the open-auth check needs.
#
# WHY `get-resources` IS CALLED WITH `--embed methods` RATHER THAN A SEPARATE
# `get-method` PER (resource, http-verb). Without `--embed`, a resource's
# `resourceMethods` map has one key per configured HTTP verb but an EMPTY
# object `{}` as each value - and `cloud_json_flatten` (modules/cloud/aws/
# engine.sh) prints one line per SCALAR leaf only, so an empty object leaves
# NO trace in the flattened stream at all. A verb whose method object is `{}`
# is therefore invisible to any leaf-path reader, not merely under-detailed -
# there is no `resourceMethods<US>GET<US>anything` line to find. `--embed
# methods` embeds the full `Method` shape (`httpMethod`, `authorizationType`,
# `apiKeyRequired`, ...) inline, which is both the fix for that blind spot and
# the one call this ticket's own scope already names ("get-resources for the
# route list"): it costs no extra API call, and every verb this pass can see
# at all necessarily carries a real scalar (`httpMethod`) to anchor on.
#
# WHY `OPTIONS` IS EXCLUDED FROM THE OPEN-AUTH CHECKS BUT NOT FROM THE
# INVENTORY. A CORS preflight request (the Fetch/CORS spec's own definition)
# never carries a credential of any kind by browser design, so API Gateway's
# own CORS console action wires every `OPTIONS` method to a MOCK integration
# with `authorizationType: NONE` - which is the CORRECT, universal
# configuration for that one verb on virtually every CORS-enabled REST API in
# existence. Flagging it would be a false-positive flood on the single most
# common API Gateway configuration there is, the exact failure this
# codebase's other packs (SSE-S3, the S3 CIS table) already refuse to
# reproduce. `ANY` (API Gateway's own catch-all pseudo-verb) is NOT excluded:
# an open `ANY` is a real, high-impact finding.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_APIGW_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_APIGW_ENGINE_SOURCED=1

# See modules/cloud/aws/live/s3_engine.sh's identical guard for why: in a real
# run `regions.sh` has already sourced `engine.sh` before the service walk
# begins, so this is reached only by a direct-engine test.
#
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare`, for the identical reason
# modules/cloud/aws/live/s3_engine.sh's own header gives at length: in a real
# run nothing sources this file at top level, `cloud_run_service` reaches it
# by `source`ing from INSIDE a function, and a bare `declare -A` there creates
# a LOCAL that dies with that one call.
declare -gA _APIGW_DOC=()
declare -gA _APIGW_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `apigw_doc_load FILE` / `apigw_doc_has PATH` / `apigw_doc_get VARNAME PATH` /
# `apigw_path P...` - the identical shape modules/cloud/aws/live/s3_engine.sh
# already establishes (section 1 of that file), copied rather than shared for
# the same reason `cloud_json_flatten` itself is a copy of `lib/state.sh`'s:
# a per-service classifier belongs to that service and to nothing else, and a
# shared reader would grow into the union of thirty services' response shapes.
apigw_doc_load() {
  local file=$1
  _APIGW_DOC=()
  _APIGW_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)`, never a pipe: a `cmd | while read` loop runs its body in a
  # subshell, and every key it stored would be discarded the moment that
  # subshell exits - lib/core.sh's standing subshell lesson, in its loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _APIGW_DOC[$path]=$val
    _APIGW_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

apigw_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

apigw_doc_has() {
  [[ -n ${_APIGW_DOCT[$1]+set} ]]
}

apigw_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_APIGW_DOC[$__path]:-}"
  [[ -n ${_APIGW_DOCT[$__path]+set} ]]
}

# `apigw_resource_methods_set VARNAME RESOURCE_INDEX` - the space-separated,
# `LC_ALL=C`-sorted set of HTTP verbs a `get-resources --embed methods`
# resource at RESOURCE_INDEX actually carries, read off the loaded document.
#
# ANCHORED ON `httpMethod`, NEVER ON THE MAP KEY ALONE.  Every embedded
# `Method` object carries its own `httpMethod` scalar equal to the verb that
# names it, so scanning the loaded map's OWN KEYS for a
# `items<US>N<US>resourceMethods<US><VERB><US>httpMethod` shape and reading
# the verb out of the path segment - rather than trusting the response to be
# well-formed in some other way - is what keeps this working under whatever
# JSON layout `cloud_json_flatten` happened to walk it into.
apigw_resource_methods_set() {
  local __var=$1 __idx=$2
  local __prefix __k __rest __verb __out='' __seen=''
  __prefix=$(apigw_path items "$__idx" resourceMethods)$'\x1f'
  local __suffix=$'\x1f''httpMethod'
  for __k in "${!_APIGW_DOC[@]}"; do
    [[ $__k == "$__prefix"*"$__suffix" ]] || continue
    __rest=${__k#"$__prefix"}
    __verb=${__rest%"$__suffix"}
    # AN EMBEDDED METHOD'S OWN `methodIntegration` SUB-OBJECT CARRIES A
    # SECOND, UNRELATED `httpMethod` FIELD - the backend integration's own
    # call method (a Lambda-proxy integration is always `POST` there, whatever
    # the resource's own verb is). Without this guard, a resource with a
    # single `GET` method and a Lambda-proxy integration would report BOTH
    # `GET` (the real verb) and `GET<US>methodIntegration` (this glob's own
    # unstripped match) as distinct verbs - and the latter would carry no
    # `resourceMethods<US>GET<US>methodIntegration<US>authorizationType` leaf
    # at all, so `apigw_method_authtype_set` would read it as empty and this
    # loop would silently invent a second, permanently-open "method". The `$1f`
    # 0x1f this leaves inside `__verb` is the tell: a real verb name is always
    # a single path segment.
    [[ $__verb == *$'\x1f'* ]] && continue
    [[ $'\n'"$__seen"$'\n' == *$'\n'"$__verb"$'\n'* ]] && continue
    __seen+="${__seen:+$'\n'}$__verb"
  done
  __out=$(printf '%s\n' "$__seen" | LC_ALL=C sort | tr '\n' ' ')
  __out=${__out% }
  printf -v "$__var" '%s' "$__out"
  return 0
}

# `apigw_method_authtype_set VARNAME RESOURCE_INDEX VERB` - the embedded
# method's `authorizationType`, verbatim (`NONE`, `AWS_IAM`, `CUSTOM`,
# `COGNITO_USER_POOLS`). Returns 1, VARNAME empty, when the field is absent.
apigw_method_authtype_set() {
  local __var=$1 __idx=$2 __verb=$3
  local __p
  __p=$(apigw_path items "$__idx" resourceMethods "$__verb" authorizationType)
  printf -v "$__var" '%s' "${_APIGW_DOC[$__p]:-}"
  [[ -n ${_APIGW_DOC[$__p]:-} ]]
}

# `apigw_method_is_open AUTHTYPE` - true when AUTHTYPE means "no authorizer at
# all".  A case statement rather than a bare `[[ $1 == NONE ]]` so a future
# AWS-added value that also means "no authorizer" (there is none today) has
# one place to add.
apigw_method_is_open() {
  case $1 in
    NONE) return 0 ;;
    *) return 1 ;;
  esac
}

# `apigw_method_apikey_required RESOURCE_INDEX VERB` - true when the embedded
# method's `apiKeyRequired` is `true`. An absent field is false: API Gateway
# omits it on some older method shapes rather than defaulting it explicitly,
# and the honest reading of "this response never said a key is required" is
# that one is not.
apigw_method_apikey_required() {
  local idx=$1 verb=$2 p
  p=$(apigw_path items "$idx" resourceMethods "$verb" apiKeyRequired)
  [[ ${_APIGW_DOC[$p]:-} == true ]]
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `apigw_partition_of CALLER_ARN` - byte-identical to
# modules/cloud/aws/live/s3_engine.sh's `s3_partition_of`, copied rather than
# sourced for the identical reason that file's own header gives: a classifier
# belongs to one service, and a cross-service `source` here would be the
# inter-service coupling this catalog's per-service engine-file split exists
# to avoid.
apigw_partition_of() {
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

# `apigw_method_arn PARTITION REGION ACCOUNT API_ID VERB RESOURCE_PATH` -
# `arn:<partition>:execute-api:<region>:<account>:<api-id>/*/<VERB>/<path>`,
# AWS's own documented shape for an API Gateway method
# (docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-
# access-using-iam-policies-to-invoke-api.html).
#
# THE STAGE SEGMENT IS THE LITERAL WILDCARD `*`, NEVER A RESOLVED STAGE NAME,
# and that is a fact about the finding rather than a shortcut around calling
# `get-stages`.  `authorizationType` and `apiKeyRequired` are properties of
# the underlying Method RESOURCE, defined once at the REST API level and
# shared by every stage deployed from it - a stage-specific override exists
# for very few settings and authorization is not one of them - so the defect
# this check reports is genuinely stage-independent, and `*` is the same
# wildcard AWS's own IAM-policy documentation uses to express exactly that
# scope. `apigw_inv_add` (section 3 below) is what resolves a REAL, per-stage
# invoke URL for the endpoint inventory; the two serve different questions and
# neither is a stand-in for the other.
apigw_method_arn() {
  local partition=$1 region=$2 account=$3 api_id=$4 verb=$5 path=$6
  path=${path#/}
  printf 'arn:%s:execute-api:%s:%s:%s/*/%s/%s' "$partition" "$region" "$account" "$api_id" "$verb" "$path"
}

# ---------------------------------------------------------------------------
# 3. The endpoint inventory (docs/FOUNDATION.md tension 21;
#    docs/INVENTORY-FORMAT.md)
# ---------------------------------------------------------------------------
# The tuple shape is US(0x1f)-joined, byte-for-byte the same field ORDER
# `modules/dast/crawl_engine.sh`'s own `_CRAWL_EP` array uses, for the
# identical reason that file's own header gives: a tab is an IFS-*whitespace*
# character, so an empty field ahead of a non-empty one is unsafe under
# `IFS=$'\t' read`, whatever this tuple's field order happens to be.
declare -ga _APIGW_EP=()
declare -gA _APIGW_EP_SEEN=()

# `apigw_inv_reset` - start a fresh, empty accumulator.  Every call site below
# reads whatever is ALREADY at `inventory/endpoints.json` into this
# accumulator FIRST (via `apigw_inv_merge_existing`) and only then adds this
# pass's own routes, so a caller never has to remember the merge-not-overwrite
# rule itself (docs/INVENTORY-FORMAT.md §1).
apigw_inv_reset() {
  _APIGW_EP=()
  _APIGW_EP_SEEN=()
  _APIGW_INV_TRUNCATED=0
}

# `apigw_inv_merge_existing FILE` - read an endpoints.json ANOTHER producer (or
# this same pass, in a prior region) already wrote and fold it into the
# accumulator UNCHANGED - `source` is preserved verbatim, per
# docs/INVENTORY-FORMAT.md §2's "source is never rewritten" - so a route this
# service does not itself understand is never silently dropped on the floor
# the next time this file is written.
#
# Read through `cloud_json_flatten`, so any conformant layout is accepted
# rather than the exact bytes a producer happened to emit - the same
# tolerance `modules/dast/crawl_engine.sh`'s own `crawl_inv_merge_endpoints`
# documents as "what frozen schema has to mean when three modules write the
# file".
apigw_inv_merge_existing() {
  local file=$1
  [[ -r $file && -s $file ]] || return 0
  local sep=$'\x1f'
  local -A cur=()
  local last_idx='' p type v rest idx key
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _apigw_inv_flush cur
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(cloud_json_unescape "$v")
    # shellcheck disable=SC2034  # read through the `cur` nameref-by-name below
    cur[$key]=$v
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _apigw_inv_flush cur
  return 0
}

# Bash 4.2 has no namerefs (tension 24's frozen minimum), so the associative
# array is passed by NAME and read through `${!...}` indirection - the same
# idiom `modules/dast/crawl_engine.sh`'s own `_crawl_merge_flush_endpoint`
# uses for the identical reason.
_apigw_inv_flush() {
  local arrname=$1
  local mref="${arrname}[method]" uref="${arrname}[url]" tref="${arrname}[target]"
  local sref="${arrname}[source]" href="${arrname}[host]" pref="${arrname}[path]"
  local dref="${arrname}[depth]" stref="${arrname}[status]" cref="${arrname}[content_type]"
  local m u t s h p d st c
  m=${!mref:-GET}
  u=${!uref:-}
  t=${!tref:-}
  s=${!sref:-imported}
  h=${!href:-}
  p=${!pref:-}
  d=${!dref:-0}
  st=${!stref:-}
  c=${!cref:-}
  [[ -n $u ]] || return 0
  _apigw_inv_store "$t" "${m^^}" "$u" "$h" "$p" "$s" "$d" "$st" "$c"
  return 0
}

# `apigw_inv_add METHOD URL` - add a route THIS pass discovered.  `target` is
# deliberately left BLANK: this module has no `config/scope.conf` target id of
# its own to attach, and `modules/dast/crawl.sh`'s own merge
# (`_crawl_merge_flush_endpoint`) already falls back to its run's own target
# when a merged row's `target` is empty - so leaving it blank here is not an
# omission, it is handing the field to the one consumer that actually has an
# answer for it. `source` is `imported`, the frozen vocabulary's catch-all for
# "a producer other than crawl.sh itself" (docs/INVENTORY-FORMAT.md §2).
apigw_inv_add() {
  local method=$1 url=$2
  local host='' path=''
  if [[ $url =~ ^[A-Za-z][A-Za-z0-9+.-]*://([^/]*)(/.*)?$ ]]; then
    host=${BASH_REMATCH[1]}
    path=${BASH_REMATCH[2]:-/}
  fi
  _apigw_inv_store '' "${method^^}" "$url" "$host" "$path" imported 0 '' ''
  return 0
}

_APIGW_INV_MAX=5000

_apigw_inv_store() {
  local target=$1 method=$2 url=$3 host=$4 path=$5 source=$6 depth=$7 status=$8 ctype=$9
  local key=$method' '$url
  [[ -n ${_APIGW_EP_SEEN[$key]:-} ]] && return 0
  if (( ${#_APIGW_EP[@]} >= _APIGW_INV_MAX )); then
    _APIGW_INV_TRUNCATED=1
    return 1
  fi
  _APIGW_EP_SEEN[$key]=1
  # US (0x1f), never a tab - `status`/`content_type` are routinely both empty
  # for an apigw-sourced row, and a tab is an IFS-*whitespace* character that
  # `read` folds a run of into ONE delimiter, shifting every later field left
  # (the DAST-11 lesson AGENTS.md records at length, reproduced here rather
  # than relearned).
  _APIGW_EP+=("$target"$'\x1f'"$method"$'\x1f'"$url"$'\x1f'"$host"$'\x1f'"$path"$'\x1f'"$source"$'\x1f'"$depth"$'\x1f'"$status"$'\x1f'"$ctype")
  return 0
}

_APIGW_INV_TRUNCATED=0

# `apigw_inv_write FILE RUN_ID` - the accumulator, written in the frozen
# `scoursh.inventory.endpoints/1` shape.  Every field goes through
# `json_string`/`json_number` (lib/core.sh), the ONE place a string becomes
# JSON in this repository (tension 10) - every value here either came off a
# resolved AWS response or was built out of one, and is therefore untrusted
# text by the identical reasoning docs/INVENTORY-FORMAT.md §6 states for a
# crawled URL.  The `id` is computed HERE, at write time, exactly the way
# `modules/dast/crawl_engine.sh`'s own `crawl_id` does it - "the first 12 of
# the SHA-256 of `<METHOD> <url>`" (docs/INVENTORY-FORMAT.md §2) - so the two
# producers mint an identical id for an identical route without either one
# knowing about the other.
apigw_inv_write() {
  local out=$1 run_id=$2
  local rec target method url host path source depth status ctype id
  {
    printf '{\n'
    printf '  "schema": %s,\n' "$(json_string scoursh.inventory.endpoints/1)"
    printf '  "run_id": %s,\n' "$(json_string "$run_id")"
    printf '  "generated_by": %s,\n' "$(json_string modules/cloud/aws/live/apigw.sh)"
    printf '  "endpoints": ['
    local first=1
    for rec in "${_APIGW_EP[@]+"${_APIGW_EP[@]}"}"; do
      IFS=$'\x1f' read -r target method url host path source depth status ctype <<<"$rec"
      id=$(printf '%s %s' "$method" "$url" | sha256_of)
      id=${id:0:12}
      (( first )) && printf '\n' || printf ',\n'
      first=0
      printf '    {"id": %s, "target": %s, "method": %s, "url": %s, "host": %s, "path": %s, "source": %s, "depth": %s, "status": %s, "content_type": %s}' \
        "$(json_string "$id")" "$(json_string "$target")" "$(json_string "$method")" \
        "$(json_string "$url")" "$(json_string "$host")" "$(json_string "$path")" \
        "$(json_string "$source")" "$(json_number "$depth")" \
        "$(json_string "$status")" "$(json_string "$ctype")"
    done
    (( first )) || printf '\n  '
    printf ']\n}\n'
  } >"$out"
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
# `apigw_registry_locate_set` / `apigw_emit_finding` - byte-identical in shape
# to modules/cloud/aws/live/s3_engine.sh's own `s3_registry_locate_set` /
# `s3_emit_finding`; see that file's header for why every field beyond the
# location profile comes from the check RECORD via `finding_from_record`
# rather than being set by hand here.
apigw_registry_locate_set() {
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

# `apigw_emit_finding CHECK_ID METHOD_ARN REGION EVIDENCE` - `sub_key` is
# always empty: unlike an S3 bucket's ACL (one bucket, several grantee
# classes needing their own fingerprint), the method ARN here already names
# one (account, region, api, resource, verb) combination uniquely, so nothing
# else needs to ride in `loc_sub_key`.
apigw_emit_finding() {
  local check_id=$1 arn=$2 region=$3 evidence=$4
  local set='' idx=''
  apigw_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/apigw emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # An open-auth API Gateway method is reachable by anyone on the internet who
  # has the invoke URL, with no session and no prior access - the identical
  # `exposure`/`auth` pairing modules/cloud/aws/live/s3_engine.sh's own public
  # ACL/policy checks use for the same reason (data/severity-rubric.conf's
  # adjustment of the record's base severity).
  finding_set exposure external
  finding_set auth none
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key ''
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
