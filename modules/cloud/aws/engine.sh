#!/usr/bin/env bash
# modules/cloud/aws/engine.sh - the Cloud/AWS module's pure function library
# (docs/DESIGN.md §8, §13 step 6; docs/STEP6-CLOUD-PLAN.md CLOUD-04).
#
# Owns:
#   docs/DESIGN.md      §8.1 - the per-service read-only catalog, one script
#                       per service, and the "iterate every enabled region"
#                       requirement `regions.sh` implements.
#   docs/FOUNDATION.md  tension 12 / rules/RULE-FORMAT.md §9.5.1 - CLOUD's
#                       coverage cell is `account-region`, spelled
#                       `<account_id>/<region>` or `<account_id>/global`.
#   docs/FOUNDATION.md  tension 23 - every AWS call goes through
#                       lib/awscli.sh's `aws_ro`; nothing here invokes `aws`.
#
# The run.sh / engine.sh split is modules/sast/'s, reused verbatim through
# modules/dast/: this file is a pure function library with the standard
# sourced-once guard and no side effects at source time, and
# modules/cloud/aws/run.sh is the file that DOES something when sourced.
#
# THIS FILE MAKES NO AWS CALL, AND NEITHER DOES run.sh's DISPATCH SHELL.
# CLOUD-04 ships the entry point, the service table and the one door a service
# script is reached through; it ships NO check, because none of the
# `aws/live/*.sh` scripts §8.1's catalog names exists yet.  A run is therefore
# a clean, honestly-declared no-op over whatever regions it resolved, exactly
# the state modules/dast/'s own dispatch was in before its first phase script
# landed.  The two calls a run DOES make - `sts get-caller-identity` for the
# authorization record and `ec2 describe-regions` for the region list - are
# run.sh's and regions.sh's respectively, and both go through `aws_ro`.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ENGINE_SOURCED=1

# modules/sast/engine.sh is sourced for `sast_evaluate_gate` ALONE, exactly as
# modules/dast/engine.sh and modules/iac/run.sh already source it and for the
# identical reason both record: despite its name that function is
# module-agnostic - it re-reads every finding in $rundir/findings.fields and
# applies the severity / confidence / fail-on-new filter chain with no module
# check anywhere in its body.  A fork would be a second copy of tension 14's
# gate semantics to keep in step with the first, and the first is the one the
# exit-code matrix suite pins.
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../../sast/engine.sh"
# lib/awscli.sh is the tension-23 chokepoint every service script and
# regions.sh reaches AWS through.  Sourced only when an outer caller has not
# already done so - `scan.sh` sources it before `scan_dispatch` ever runs, so
# in a real run this is a no-op; the conditional is what lets
# tests/suites/cloud.sh source THIS file on its own.  (The same shape, and the
# same reason, as modules/dast/engine.sh's own lib/checks.sh guard.)
if [[ -z ${SCOURSH_AWSCLI_SOURCED:-} ]]; then
  # -x back-edge cut: lib/awscli.sh's own hub chain (lib/core.sh) is already
  # inlined through modules/sast/engine.sh above, and shellcheck -x re-expands
  # EVERY source edge it follows rather than memoising.  Cutting this one loses
  # no checking and is what keeps the linter's hub sum bounded - see
  # tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's "the memory model".
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../../../lib/awscli.sh"
fi

# ---------------------------------------------------------------------------
# 1. The service table
# ---------------------------------------------------------------------------
# `<module-relative script>:<scope>`, transcribed from docs/DESIGN.md §8.1's
# own seed catalog plus §8.3-§8.6's four larger per-service sections.  One row
# per service; nothing here exists on disk yet, and `cloud_run_service` treats
# an absent script as a clean no-op, which is what lets this table be complete
# now rather than grown one edit at a time - the identical reasoning
# modules/dast/engine.sh's `_DAST_PHASES` records.
#
# THE SCOPE IS `global` OR `regional`, AND IT IS A FACT ABOUT THE SERVICE'S
# API NAMESPACE, NOT A JUDGEMENT MADE HERE.  A `regional` script is sourced
# once per region `regions.sh` resolved, with SCOURSH_CLOUD_REGION set to that
# region and its findings landing in the `<account>/<region>` cell.  A `global`
# script is sourced ONCE per account, with SCOURSH_CLOUD_REGION set to the
# literal `global` and its findings landing in `<account>/global` - the second
# spelling rules/RULE-FORMAT.md §9.5.1's cell column freezes.
#
# Getting a row's scope wrong is a real defect in whichever direction it goes,
# and both directions are silent.  A regional service marked `global` is
# scanned in one region and reported clean for every other - the overstated
# coverage docs/DESIGN.md §15 forbids.  A global service marked `regional` is
# scanned once per region, which multiplies its API cost by the region count
# and mints one duplicate finding per region for the same resource, each in a
# different cell, so tension 12's `fixed` inference then needs every one of
# those cells revisited before a genuinely deleted resource can ever be
# reported remediated.
#
# `s3` is `global` and that is the row most likely to be argued with: an S3
# bucket lives in a region, but `list-buckets` is a single global call whose
# response names every bucket in the account, and each per-bucket call is
# addressed by bucket name rather than by region.  Scanning it once per region
# would issue N identical `list-buckets` calls and emit N copies of every
# finding.  The bucket's own region belongs in the finding's `loc_region`,
# which the script resolves per bucket; it is not a reason to iterate.
#
# `declare -ga`, never a bare `declare -a`, and the `-g` is load-bearing for
# the reason modules/dast/engine.sh's own phase table documents at length: in
# a real run NOTHING sources this file at top level.  `scan_dispatch` (scan.sh
# §7) is a FUNCTION and reaches every module by running `source "$script"`
# from inside itself, so this line executes in that function's scope, and
# `declare -a` with no `-g` there creates a LOCAL that dies with the first
# `scan_dispatch` - while the sourced-once guard above is a plain assignment,
# which IS global and DOES survive.  Any array a service script declares is
# subject to the identical rule.
declare -ga _CLOUD_SERVICES=(
  # Global namespaces - one pass per account (CLOUD-05, CLOUD-06, CLOUD-11,
  # CLOUD-24).
  'live/iam.sh:global'
  'live/s3.sh:global'
  'live/cloudfront.sh:global'
  'live/route53.sh:global'
  # Regional namespaces - one pass per enabled region.
  'live/ec2.sh:regional'
  'live/rds.sh:regional'
  'live/dynamodb.sh:regional'
  'live/kms.sh:regional'
  'live/secretsmanager.sh:regional'
  'live/ssm.sh:regional'
  'live/acm.sh:regional'
  'live/backup.sh:regional'
  'live/elb.sh:regional'
  'live/efs.sh:regional'
  'live/opensearch.sh:regional'
  'live/redshift.sh:regional'
  'live/lambda.sh:regional'
  'live/apigw.sh:regional'
  'live/cognito.sh:regional'
  'live/appsync.sh:regional'
  'live/ecr.sh:regional'
  'live/ecs.sh:regional'
  'live/eks.sh:regional'
  'live/sns.sh:regional'
  'live/sqs.sh:regional'
  'live/cloudtrail.sh:regional'
  'live/config.sh:regional'
  'live/guardduty.sh:regional'
  'live/inspector.sh:regional'
  'live/macie.sh:regional'
)

# `modules/cloud/posture/` IS DELIBERATELY NOT IN THAT TABLE, and its absence
# is a scope boundary rather than an omission.  docs/DESIGN.md §8.7's posture
# checks carry the `scope-key` coverage scope (rules/RULE-FORMAT.md §9.5.1's
# POSTURE row), not `account-region`, so they cannot share the cell this file's
# loop writes; and they read from an operator-declared `config/posture.conf`
# that has no schema yet.  Adding a `posture/` row here would put a second
# coverage-cell vocabulary through one loop and make the cell a per-row fact,
# which is exactly the shape the loop below is written to avoid.  POSTURE-01
# owns that file and its own table.

# ---------------------------------------------------------------------------
# 2. The coverage cell
# ---------------------------------------------------------------------------
# `cloud_cell ACCOUNT REGION` - `<account_id>/<region>`, the one spelling
# rules/RULE-FORMAT.md §9.5.1 freezes for CLOUD, with `global` as the region
# for an account-wide pass.
#
# It PRINTS rather than sets, unlike most of this codebase's two-value
# helpers, because it can neither die nor set state: it is pure string
# concatenation over two arguments, so a `$(...)` subshell discards nothing.
# The convention this codebase actually holds is "never read a DIE-CAPABLE or
# STATE-SETTING function through a command substitution" (lib/core.sh's
# `worker_id_set`), and this is neither.
cloud_cell() {
  printf '%s/%s' "$1" "${2:-global}"
}

# `cloud_partition_of CALLER_ARN` - the ARN partition (`aws`, `aws-cn`,
# `aws-us-gov`), read out of the caller identity's own ARN rather than
# hardcoded, defaulting to `aws`.  s3_engine.sh's own `s3_partition_of` makes
# the identical point at length (a hardcoded `aws` partition names a resource
# that does not exist in GovCloud or China) for its own file; this is the
# SHARED copy every other service's ARN-constructing classifier calls, so a
# service script never has an implicit, sourcing-order-dependent dependency on
# s3_engine.sh having already been sourced by an earlier pass in the same
# process - a real risk for any `regional` service, since `s3` (the only file
# that used to define this) is `global` and is not guaranteed to run before a
# `--profile-scan`-narrowed or otherwise reordered walk reaches a regional
# one.
cloud_partition_of() {
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

# ---------------------------------------------------------------------------
# 3. Per-check selection (docs/FOUNDATION.md tension 15)
# ---------------------------------------------------------------------------
# `cloud_check_selected ID` - 0 when the run's --profile-scan / --intensity /
# --allow-intrusive filter chain kept check ID, 1 when it excluded it.
#
# A byte-for-byte port of modules/dast/engine.sh's `dast_check_selected`,
# including both of the readings that function's own header records as traps,
# because both apply here identically:
#
#   THE UNSET/EMPTY FALLBACK IS PERMISSIVE, AND MUST STAY THAT WAY.  It is
#   lib/findings.sh's `_derived_record_selected` rule verbatim (tension 6
#   condition (a)): no filter chain means everything is selected.  scan.sh
#   exports SCOURSH_SELECTED_CHECKS unconditionally and possibly empty, so both
#   the unset and the empty case must answer "selected" - and a direct-engine
#   test suite sources a service script with no scan.sh anywhere in the
#   process, so a fail-CLOSED default would make every service script inert
#   while every "stays quiet" assertion in that suite still passed green.  That
#   is the worst available failure: invisible from the test output, and it
#   reads as coverage.
#
#   THE MEMBERSHIP TEST IS WHOLE-LINE, NEVER SUBSTRING.  A bare `*"$id"*` glob
#   would select `CLOUD-S3-PUBLIC_ACL-01` because some other selected line ends
#   with those bytes, spending a real read-only API call on a check the
#   operator filtered out.  Wrapping both the list and the needle in newlines
#   is what makes the comparison line-anchored at both ends, including the
#   first and last lines.
cloud_check_selected() {
  local id=$1
  [[ -n ${SCOURSH_SELECTED_CHECKS:-} ]] || return 0   # no filter chain: all selected
  [[ $'\n'"$SCOURSH_SELECTED_CHECKS"$'\n' == *$'\n'"$id"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 4. The shared JSON reader
# ---------------------------------------------------------------------------
# `cloud_json_flatten` - reads JSON on stdin, prints one line per SCALAR leaf
# to stdout: `<path><TAB><type><TAB><raw value>`.  `path` is the leaf's
# location, object keys and array indices joined by US (0x1f); `type` is one of
# `s` `n` `b` `z` (string, number, boolean, null); for a string, `raw value` is
# the bytes between the quotes, STILL JSON-ESCAPED exactly as written, so a raw
# newline or tab inside a string can never desynchronise the TAB-delimited line
# or the US-delimited path (RFC 8259 §7 forbids a raw control byte in a JSON
# string).  On a syntax error it prints `__JSON_ERROR__<TAB><reason>` to stderr
# and exits 1, emitting no further leaves.
#
# WHY THIS LIVES HERE AND NOT IN `lib/`.  Every AWS response is JSON and
# docs/DESIGN.md §8.1's catalog is thirty service scripts, so the alternative
# to one reader in this file is thirty ad-hoc greps over API responses -
# exactly the shape that turns a nested `"Encrypted": false` under an unrelated
# key into a finding.  A reader is therefore required; the only question is
# where it sits, and `lib/` is the wrong answer.  `tests/lint-source-graph.sh`
# caps the hub fan-out of `lib/core.sh`/`records.sh`/`findings.sh`/`http.sh`/
# `config.sh` per entry point at 17, because `shellcheck -x` re-expands every
# source edge it follows rather than memoising it - a NEW `lib/` hub would be
# re-expanded once per consumer across the whole tree, and this project has
# already paid twice for that lesson (30+ GB runs, an OOM-killed CI leg).
# Confining it to this module costs one copy and no hub edge.
#
# WHY IT IS A COPY OF `lib/state.sh`'s `_state_json_flatten` RATHER THAN A
# CALL TO IT.  `lib/state.sh` is not a hub today and must not become one:
# `modules/cloud/aws/` would be its first `modules/` consumer, and it pulls in
# `lib/core.sh` on its own edge.  `lib/state.sh`'s own header already records
# the same decision from the other side ("own copy; see this file's header for
# why"), and `modules/dast/crawl_engine.sh`'s `crawl_json_flatten` is the third
# instance of the identical judgement.  What is NOT acceptable is a FIFTH,
# DIFFERENT parser: this one is byte-identical to `lib/state.sh`'s awk program,
# so a bug found in either is the same bug, and `tests/suites/cloud.sh`
# asserts the two agree leaf-for-leaf on one document rather than trusting this
# sentence.
cloud_json_flatten() {
  awk '
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    function readstr(  s, c) {
      i++
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    function emit(path, type, val) { print path "\t" type "\t" val }
    function value(path,   c, k, idx, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          value(path == "" ? k : path SEP k)
          first = 0
        }
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "]") { i++; return }
          value(path == "" ? idx : path SEP idx)
          idx++
          first = 0
        }
      }
      if (c == "\"") { emit(path, "s", readstr()); return }
      k = readtok()
      if (k == "") fail("unparseable value at byte " i)
      if (k == "true" || k == "false") { emit(path, "b", k); return }
      if (k == "null") { emit(path, "z", k); return }
      emit(path, "n", k)
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      skipws()
      if (i > n) exit 0
      value("")
    }
  '
}

# `cloud_json_unescape RAW` - the inverse of the "still escaped" contract
# above, applied once a leaf's raw text is about to become a real bash value.
# `\uXXXX` above U+007F is left as its literal escape text rather than
# composing UTF-8 by hand, the same call `lib/state.sh`'s `_state_json_unescape`
# and `modules/dast/crawl_engine.sh`'s `crawl_json_unescape` both make, and for
# the same reason: no consumer here needs to decode it further, and leaving it
# visible keeps that gap visible rather than silently guessing.
# SC1003: `'\'` is a literal single backslash, the character this function
# exists to interpret.
# shellcheck disable=SC1003
cloud_json_unescape() {
  local s=$1 out='' i n ch nx code decoded
  if [[ $s != *'\'* ]]; then
    printf '%s' "$s"
    return 0
  fi
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch != '\' ]]; then out+=$ch; continue; fi
    nx=${s:i+1:1}
    case $nx in
      '"') out+='"'; i=$(( i + 1 )) ;;
      '\') out+='\'; i=$(( i + 1 )) ;;
      '/') out+='/'; i=$(( i + 1 )) ;;
      b) out+=$'\b'; i=$(( i + 1 )) ;;
      f) out+=$'\f'; i=$(( i + 1 )) ;;
      n) out+=$'\n'; i=$(( i + 1 )) ;;
      r) out+=$'\r'; i=$(( i + 1 )) ;;
      t) out+=$'\t'; i=$(( i + 1 )) ;;
      u)
        code=${s:i+2:4}
        if [[ $code == 0000 ]]; then
          out+=' '
          i=$(( i + 5 ))
        elif [[ $code =~ ^00[0-7][0-9A-Fa-f]$ ]]; then
          # shellcheck disable=SC2059
          printf -v decoded "\\x${code:2:2}"
          out+=$decoded
          i=$(( i + 5 ))
        else
          out+='\u'
          i=$(( i + 1 ))
        fi
        ;;
      *) out+='\' ;;
    esac
  done
  printf '%s' "$out"
}

# `cloud_json_leaf VARNAME FILE PATH` - sets VARNAME to the UNESCAPED scalar at
# the US-joined PATH in FILE, and returns 1 with VARNAME empty when the
# document has no such leaf.
#
# A SETTER, NEVER A PRINTER, and the reason is the same one lib/awscli.sh's
# `aws_ro_account_id_set` gives one layer down: a service script that reads a
# leaf through `v=$(...)` runs the read in a SUBSHELL, so any outcome global a
# nested call sets is written in a process that then exits and the caller sees
# the values from before the call.  Making the shared helper a setter is what
# keeps a service script from having to remember that.
cloud_json_leaf() {
  local __var=$1 __file=$2 __want=$3
  local __path __type __val
  printf -v "$__var" '%s' ''
  [[ -r $__file ]] || return 1
  while IFS=$'\t' read -r __path __type __val; do
    [[ $__path == "$__want" ]] || continue
    [[ $__type == s ]] && __val=$(cloud_json_unescape "$__val")
    printf -v "$__var" '%s' "$__val"
    return 0
  done < <(cloud_json_flatten <"$__file")
  return 1
}

# ---------------------------------------------------------------------------
# 4b. Resource-policy documents - a JSON document embedded AS A STRING
# ---------------------------------------------------------------------------
# WHY THIS LIVES HERE, ON THE MODULE'S SHARED ENGINE, RATHER THAN ON ONE
# SERVICE'S OWN _engine.sh.  `kms get-key-policy`, `secretsmanager
# get-resource-policy` and `ssm get-resource-policies` (CLOUD-07/08/09, landed
# together in one ticket) all hand back an IAM-policy-shaped JSON document
# under a field (`Policy` / `ResourcePolicy`) whose VALUE is itself JSON text -
# `cloud_json_flatten` reads it as one opaque string leaf, exactly as it must
# per RFC 8259 §7 (a JSON string cannot itself contain an unescaped `{`). Three
# service scripts landing in one ticket needing the identical "is this
# statement an unconditional wildcard grant" classifier is the shape
# `modules/dast/active/inject_engine.sh` was shared for, not the "one service,
# one _engine.sh" shape `s3_engine.sh`'s own header describes - and every
# later service with a resource policy (SNS, SQS, ECR, ...) is another
# consumer, so this is not a one-ticket convenience.
#
# `declare -g`, for the identical reason `s3_engine.sh`'s own `_S3_DOC` is:
# nothing sources this file at top level in a real run, `cloud_run_service`
# reaches a live script by `source`ing it from INSIDE a function, so a bare
# `declare -A` here would create a local that dies with the function.
declare -gA _CLOUD_POLICY_DOC=()
declare -gA _CLOUD_POLICY_DOCT=()

# `cloud_policy_load TEXT` - TEXT is a policy field's value ALREADY UNESCAPED
# EXACTLY ONCE, i.e. what a caller reads back from its own `*_doc_load`'s
# string map (`kms_policy_field`, `secm_policy_field`,
# `ssm_policy_entry_field_set`) - every one of those loaders already runs
# `cloud_json_unescape` on every string leaf as it populates its own map
# (`kms_doc_load`'s own header explains why, one file over), so the `Policy` /
# `ResourcePolicy` field a caller hands here has ALREADY had its one layer of
# JSON-string escaping removed and is ready to re-parse as its own document
# without any further decoding.  Unescaping it a SECOND time here would mangle
# any literal backslash the embedded policy legitimately contains (a
# `Condition` value with a regex, say) - measured while writing this function,
# by round-tripping a fixture and comparing the flattened `Statement<US>0<US>
# Effect` leaf against the source text.
#
# Flattens TEXT as a second, independent document into
# `_CLOUD_POLICY_DOC`/`_CLOUD_POLICY_DOCT` - the same two-map shape
# `s3_engine.sh`'s `s3_doc_load` uses one level up, chosen for the identical
# reason: a policy's `Statement` is an array a caller must be able to walk
# index by index, which an unflattened string cannot support.
#
# Returns 1 and leaves both maps EMPTY when TEXT is empty (no policy attached
# - the ordinary case for a fresh SSM parameter or secret) or does not parse.
cloud_policy_load() {
  local __text=$1
  _CLOUD_POLICY_DOC=()
  _CLOUD_POLICY_DOCT=()
  [[ -n $__text ]] || return 1
  local __path __type __val
  while IFS=$'\t' read -r __path __type __val; do
    [[ -n $__path ]] || continue
    [[ $__type == s ]] && __val=$(cloud_json_unescape "$__val")
    _CLOUD_POLICY_DOC[$__path]=$__val
    _CLOUD_POLICY_DOCT[$__path]=$__type
  done < <(printf '%s' "$__text" | cloud_json_flatten 2>/dev/null)
  (( ${#_CLOUD_POLICY_DOCT[@]} > 0 ))
}

# `_cloud_policy_statement_is_public PREFIX` - true when the statement rooted
# at PREFIX (`Statement` for a single-object policy, `Statement<US><n>` for
# one entry of an array of them - the IAM policy grammar allows both shapes
# for `Statement`) is an `Allow` that grants to an UNQUALIFIED wildcard
# principal.
#
# THE VERDICT IS DELIBERATELY COARSE, THE SAME DIRECTION `s3_policy_is_public`
# ONE LEVEL UP GETS FROM AWS ITSELF: a real `Condition` block anywhere under
# the statement is treated as narrowing it, WHATEVER the condition actually
# tests - `aws:SourceVpce` genuinely narrows, `aws:Referer` narrows nothing at
# all (a client sends whatever `Referer` it likes), and this module has no IAM
# policy evaluator to tell the two apart. Reporting the SECOND as a false
# negative is the failure a stricter-than-necessary verdict accepts on
# purpose: this project's read-only chokepoint has no way to ask AWS's own
# evaluator the question the way `get-bucket-policy-status` answers it for S3,
# so "no Condition at all" is the one shape this classifier can assert without
# guessing, and it never reports a NARROWED grant as public.
_cloud_policy_statement_is_public() {
  local __prefix=$1
  [[ ${_CLOUD_POLICY_DOC[$__prefix$'\x1f'Effect]:-} == Allow ]] || return 1

  local __wild=0
  [[ ${_CLOUD_POLICY_DOC[$__prefix$'\x1f'Principal]:-} == '*' ]] && __wild=1
  [[ ${_CLOUD_POLICY_DOC[$__prefix$'\x1f'Principal$'\x1f'AWS]:-} == '*' ]] && __wild=1
  local __i=0
  while [[ -n ${_CLOUD_POLICY_DOCT[$__prefix$'\x1f'Principal$'\x1f'AWS$'\x1f'$__i]+set} ]]; do
    [[ ${_CLOUD_POLICY_DOC[$__prefix$'\x1f'Principal$'\x1f'AWS$'\x1f'$__i]:-} == '*' ]] && __wild=1
    __i=$(( __i + 1 ))
  done
  (( __wild )) || return 1

  local __k
  for __k in "${!_CLOUD_POLICY_DOCT[@]}"; do
    [[ $__k == "$__prefix"$'\x1f'Condition* ]] && return 1
  done
  return 0
}

# `cloud_policy_is_public` - true when the document `cloud_policy_load` most
# recently loaded contains at least one public statement, over EITHER
# `Statement` shape the IAM policy grammar allows (a lone object, or an array
# of them) - AWS's own default key/secret/parameter policies are generated as
# a one-entry array, but a hand-authored policy may legally be the bare
# object.
cloud_policy_is_public() {
  local __idx=0 __saw_array=0 __prefix=''
  while [[ -n ${_CLOUD_POLICY_DOCT[Statement$'\x1f'$__idx$'\x1f'Effect]+set} ]]; do
    __saw_array=1
    # BUILT INTO A VARIABLE FIRST, NEVER SPLICED DIRECTLY INTO ONE
    # DOUBLE-QUOTED ARGUMENT STRING.  `$'\x1f'` is ANSI-C quoting and is only
    # recognised as such when it is its own shell WORD (bare, or concatenated
    # with adjacent bare/quoted pieces) - nested inside an ENCLOSING pair of
    # double quotes, as `"Statement$'\x1f'$__idx"` would be, it loses that
    # meaning entirely and becomes the nine LITERAL bytes `$`, `'`, `\`, `x`,
    # `1`, `f`, `'` between `Statement` and the index, so the lookup below
    # silently misses every real entry.  This is precisely the reverse of
    # kms_engine.sh's own array-SUBSCRIPT accessors
    # (`${_KMS_DOC[KeyMetadata$'\x1f'KeyManager]}`), where `$'\x1f'` sits
    # inside the subscript brackets rather than inside a second, outer pair
    # of quotes and is expanded correctly - measured by mutation: reverting
    # this line to the spliced form makes B7 in tests/suites/cloud-kms.sh
    # fail (the public-policy check never fires on ANY fixture), the failure
    # mode this note exists to keep from being reintroduced.
    __prefix=Statement$'\x1f'"$__idx"
    _cloud_policy_statement_is_public "$__prefix" && return 0
    __idx=$(( __idx + 1 ))
  done
  if (( ! __saw_array )) && [[ -n ${_CLOUD_POLICY_DOCT[Statement$'\x1f'Effect]+set} ]]; then
    _cloud_policy_statement_is_public Statement && return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 5. The one door into a service script
# ---------------------------------------------------------------------------
# `cloud_run_service SPEC ACCOUNT REGION` - SPEC is one `_CLOUD_SERVICES` row.
# Sets `_CLOUD_SERVICE_OUTCOME` to one of:
#
#   absent   the service's script has not landed yet
#   ran      the script was sourced
#
# and `_CLOUD_SERVICE_PRESENT` to 1/0 independently, so a caller can tell "we
# skipped a service that exists" from "we skipped one that does not" and report
# only the first.  It SETS variables rather than printing them and must never
# be called through `$(...)`: sourcing a service script inside a command
# substitution would run it in a subshell and discard every finding it emitted,
# which is lib/core.sh's `worker_id_set` lesson applied one level up.
#
# THERE IS NO INTENSITY GATE HERE, AND ITS ABSENCE IS DELIBERATE rather than an
# omission from the `dast_run_phase` this function otherwise mirrors.  Every
# §8.1 check is a read-only API call whose type tag is `config-read`, which
# lib/checks.sh's tension-15 ceiling already passes at the default `passive`
# intensity - so a per-service coarse gate would have exactly one value for
# every row and would be a second gate that can only ever agree with the first.
# What DOES bind a cloud check is `cloud_check_selected` above, the fine
# per-check filter, which is where a `--profile-scan quick` narrowing lands.
# A future service script whose checks legitimately carry a HIGHER type tag
# (an intrusive probe, say) adds the gate here in the same change that adds
# the script, and says why - the identical instruction `_DAST_PHASES` carries.
#
# A service script is `source`d, exactly as scan.sh sources a module's run.sh,
# so it inherits the whole run context and its findings land in this process's
# shard.  It therefore must NOT carry a sourced-once guard: one run
# legitimately reaches the same regional script once per region, and a guard
# would silently make every region after the first a no-op - which is the
# failure that reads as a complete multi-region audit.  Any array it declares
# needs `declare -g` for the reason this file's own service table documents.
cloud_run_service() {
  local _cloud_spec=$1 _cloud_account=$2 _cloud_region=$3
  local _cloud_script=${_cloud_spec%%:*} _cloud_path
  _cloud_path=${SCOURSH_INSTALL_ROOT:-}/modules/cloud/aws/$_cloud_script

  _CLOUD_SERVICE_PRESENT=0
  [[ -f $_cloud_path ]] && _CLOUD_SERVICE_PRESENT=1

  if (( ! _CLOUD_SERVICE_PRESENT )); then
    _CLOUD_SERVICE_OUTCOME=absent
    return 0
  fi

  # The service reads its account, region and cell from the exported context
  # modules/cloud/aws/run.sh publishes; they are set here as well so a script
  # never has to trust a variable it did not see set - the same belt-and-braces
  # `dast_run_phase` applies to SCOURSH_DAST_TARGET.
  SCOURSH_CLOUD_ACCOUNT_ID=$_cloud_account
  SCOURSH_CLOUD_REGION=$_cloud_region
  SCOURSH_CLOUD_CELL=$(cloud_cell "$_cloud_account" "$_cloud_region")
  export SCOURSH_CLOUD_ACCOUNT_ID SCOURSH_CLOUD_REGION SCOURSH_CLOUD_CELL
  # The ambient region every `aws_ro` call inside the script inherits, unless
  # it carries its own --region.  `global` is not a real AWS region name, so a
  # global pass CLEARS the ambient region rather than sending it - the CLI
  # would reject `--region global` outright (cli_usage), and every global
  # namespace resolves its own endpoint without one.
  if [[ $_cloud_region == global ]]; then
    aws_ro_use_region ''
  else
    aws_ro_use_region "$_cloud_region"
  fi

  # shellcheck disable=SC1090
  source "$_cloud_path"
  _CLOUD_SERVICE_OUTCOME=ran
  return 0
}

# ---------------------------------------------------------------------------
# 6. Resource-policy heuristics (shared by every service with no S3-style
#    "policy status" evaluator API of its own)
# ---------------------------------------------------------------------------
# S3's own public-policy check (s3_engine.sh's `s3_policy_is_public`) reads
# `get-bucket-policy-status`, AWS'S OWN evaluator, and is exact - the reason
# that check's own header calls out "the verdict is AWS's, not ours".
# OpenSearch and EFS have no equivalent read-only "is this policy public"
# operation: the only way to answer the question is to read the raw resource
# policy document (OpenSearch's `AccessPolicies`, EFS's
# `describe-file-system-policy`'s `Policy`) and evaluate it here.  That is
# necessarily a HEURISTIC rather than AWS's own answer, and every check built
# on it is registered `confidence: medium` for that reason rather than the
# `high` a direct API field or an AWS-evaluated verdict earns.
#
# `cloud_policy_is_wide_open` DELIBERATELY IGNORES `Condition` BLOCKS.  A
# `Condition` narrows an Allow statement only if the caller understands the
# specific operator and key - `aws:SourceVpc`/`aws:SourceVpce` genuinely
# restrict to a VPC, while `aws:Referer` and `aws:UserAgent` (s3_engine.sh's
# own `s3_policy_is_public` header makes the identical point) are attacker-
# supplied and narrow nothing.  A generic reader cannot tell those apart
# without re-implementing IAM policy evaluation, and reading "any Condition
# present" as "therefore not public" fails in the direction that manufactures
# a false negative on a policy that is genuinely public but happens to carry
# an unrelated, non-narrowing condition - the reading this project's own
# testing rule (AGENTS.md) treats as the one to fear.  A wildcard Principal on
# an Allow statement is reported regardless of any Condition; the `medium`
# confidence is what tells a reader this is a heuristic rather than a
# certainty.
#
# `cloud_json_flatten` is reused rather than a second JSON reader (fed a
# STRING via a pipe, not a file - `printf '%s' "$text" | cloud_json_flatten`
# reads identically to `<"$file"`, since awk's END block reads all of stdin
# either way), for the same "one parser, not a fifth copy" reasoning that
# file's own header states.
declare -gA _CLOUD_POLICY_DOC=()
declare -gA _CLOUD_POLICY_DOCT=()
declare -ga _CLOUD_POLICY_STMT_BASES=()

# `cloud_policy_load TEXT` - flatten TEXT (already-unescaped JSON policy text,
# never a file path) into `_CLOUD_POLICY_DOC`/`_CLOUD_POLICY_DOCT`.  Returns 1
# and leaves both empty for an empty or unparseable TEXT - the caller's own
# classifiers then correctly answer "not open" / "does not deny" for a policy
# that could not be read, which is the same "an absent document is not the
# document" convention `s3_doc_load` already establishes for a missing file.
cloud_policy_load() {
  local __text=$1
  _CLOUD_POLICY_DOC=()
  _CLOUD_POLICY_DOCT=()
  [[ -n $__text ]] || return 1
  local __path __type __val
  while IFS=$'\t' read -r __path __type __val; do
    [[ -n $__path ]] || continue
    [[ $__type == s ]] && __val=$(cloud_json_unescape "$__val")
    _CLOUD_POLICY_DOC[$__path]=$__val
    _CLOUD_POLICY_DOCT[$__path]=$__type
  done < <(printf '%s' "$__text" | cloud_json_flatten 2>/dev/null)
  return 0
}

# `_cloud_policy_statement_bases_set` - the list of `Statement<US><i>` (or the
# single `Statement`, for the equally-legal bare-object spelling IAM accepts
# when a policy has exactly one statement) path prefixes in the loaded
# document, over `_CLOUD_POLICY_DOC` set by `cloud_policy_load` above.
_cloud_policy_statement_bases_set() {
  _CLOUD_POLICY_STMT_BASES=()
  local sep=$'\x1f'
  if [[ -n ${_CLOUD_POLICY_DOCT[Statement${sep}0${sep}Effect]+set} ]]; then
    local i=0
    while [[ -n ${_CLOUD_POLICY_DOCT[Statement${sep}${i}${sep}Effect]+set} ]]; do
      _CLOUD_POLICY_STMT_BASES+=("Statement${sep}${i}")
      i=$(( i + 1 ))
    done
  elif [[ -n ${_CLOUD_POLICY_DOCT[Statement${sep}Effect]+set} ]]; then
    _CLOUD_POLICY_STMT_BASES=(Statement)
  fi
  return 0
}

# `cloud_policy_is_wide_open` - true when the LOADED policy document (see
# `cloud_policy_load`) carries an `Effect: Allow` statement whose `Principal`
# is the wildcard `"*"` - spelled bare, as `{"AWS": "*"}`, or as `"*"`
# anywhere inside an `AWS` principal array.  See this section's own header for
# why `Condition` is deliberately not consulted.
cloud_policy_is_wide_open() {
  local sep=$'\x1f' base principal_wild=0 j=0
  _cloud_policy_statement_bases_set
  for base in "${_CLOUD_POLICY_STMT_BASES[@]+"${_CLOUD_POLICY_STMT_BASES[@]}"}"; do
    [[ ${_CLOUD_POLICY_DOC[${base}${sep}Effect]:-} == Allow ]] || continue
    principal_wild=0
    [[ ${_CLOUD_POLICY_DOC[${base}${sep}Principal]:-} == '*' ]] && principal_wild=1
    [[ ${_CLOUD_POLICY_DOC[${base}${sep}Principal${sep}AWS]:-} == '*' ]] && principal_wild=1
    if (( ! principal_wild )); then
      j=0
      while [[ -n ${_CLOUD_POLICY_DOCT[${base}${sep}Principal${sep}AWS${sep}${j}]+set} ]]; do
        [[ ${_CLOUD_POLICY_DOC[${base}${sep}Principal${sep}AWS${sep}${j}]:-} == '*' ]] && principal_wild=1
        j=$(( j + 1 ))
      done
    fi
    (( principal_wild )) && return 0
  done
  return 1
}

# `cloud_policy_denies_insecure_transport` - true when the LOADED policy
# document carries an `Effect: Deny` statement conditioned on
# `Bool.aws:SecureTransport` being the (string, per IAM's own condition-value
# convention) `"false"` - the published AWS pattern for enforcing TLS-only
# access on a resource policy.  Only that one condition shape is recognised;
# a policy expressing the same intent through a different operator is a
# stated gap rather than a guess.
cloud_policy_denies_insecure_transport() {
  local sep=$'\x1f' base
  _cloud_policy_statement_bases_set
  for base in "${_CLOUD_POLICY_STMT_BASES[@]+"${_CLOUD_POLICY_STMT_BASES[@]}"}"; do
    [[ ${_CLOUD_POLICY_DOC[${base}${sep}Effect]:-} == Deny ]] || continue
    [[ ${_CLOUD_POLICY_DOC[${base}${sep}Condition${sep}Bool${sep}aws:SecureTransport]:-} == false ]] && return 0
  done
  return 1
}
