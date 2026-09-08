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
