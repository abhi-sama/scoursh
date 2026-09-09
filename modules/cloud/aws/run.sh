#!/usr/bin/env bash
# modules/cloud/aws/run.sh - the Cloud/AWS module entry point
# (docs/DESIGN.md §8, §13 step 6; docs/STEP6-CLOUD-PLAN.md CLOUD-02/CLOUD-04).
#
# Contract (modules/sast/run.sh's own header, which modules/iac/run.sh and
# modules/dast/run.sh both already reuse verbatim): scan.sh's `scan_dispatch
# cloud` does a plain `source` of this file, never a subprocess, so it inherits
# every already-set variable of the calling scan_main invocation -
# SCOURSH_RUN_DIR, SCOURSH_FAIL_ON, SCOURSH_MIN_CONFIDENCE, SCAN_FLAGS,
# CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every lib/*.sh function,
# all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, and more than one
# scan_main invocation can happen in one process (tests/suites/scan.sh calls it
# repeatedly).  Only modules/cloud/aws/engine.sh and regions.sh, pure function
# libraries, get the standard sourced-once guard - exactly the
# sast/engine.sh and dast/engine.sh split.
#
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  This is the
# dispatch skeleton: it resolves the caller identity, records the authorization
# facts, resolves the enabled-region list, walks the `_CLOUD_SERVICES` table
# once per (service, cell), and writes the `account-region` coverage cells.  It
# ships NO check and makes no AWS call beyond the two it needs to answer "whose
# account is this" and "which regions does it have" - there is no
# `aws/live/*.sh` script on disk yet, so a run is a clean, honestly-declared
# no-op, exactly the state modules/dast/'s own dispatch was in before its first
# phase script landed.  Not shipped here, each by its own ticket: every §8.1
# service script, the §8.7 posture phase (POSTURE-01, which carries a DIFFERENT
# coverage scope - see engine.sh's note on why it is not in the service table),
# and multi-account iteration via `--assume-role` (refused below rather than
# ignored).
#
# THE HONESTY THIS FILE OWES ITS READER IS ITS ACTUAL DELIVERABLE, and it is
# sharper here than in any peer module.  Every other module fails visibly when
# it cannot do its job; a cloud scan under a least-privilege role fails
# INVISIBLY - an `AccessDenied` looks exactly like an account with nothing
# wrong in it.  So every no-op below is recorded as a `coverage_reduction` or a
# `coverage_gap` in the run's own meta, which lib/report.sh renders into
# run.json AND into the limitations section of the markdown and HTML reports -
# the surfaces a consumer actually reads, not an internal record.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/regions.sh
source "${BASH_SOURCE[0]%/*}/regions.sh"
# `regions.sh` sources `engine.sh` itself; naming it again here would be a
# second edge to the same file for `shellcheck -x` to re-expand, which is the
# diamond `tests/lint-source-graph.sh` exists to cap.
#
# lib/diff.sh is sourced directly here rather than from engine.sh for the
# reason modules/dast/run.sh's own copy of this records: this module's sibling
# service-script test suites will each source engine.sh or a single service
# script directly, never this file, so confining the edge here keeps their
# `shellcheck -x` cost unchanged.  Guarded because a fixture root with no lib/
# sibling makes the unconditional form fail to even locate the file, before its
# own internal guard could no-op it.
if [[ -z ${SCOURSH_DIFF_SOURCED:-} ]]; then
  # -x back-edge cut: lib/diff.sh's own hub chain is already inlined through
  # engine.sh -> modules/sast/engine.sh above.
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../../../lib/diff.sh"
fi

# ---------------------------------------------------------------------------
# 1. The authorization record (docs/STEP6-CLOUD-PLAN.md D1, ACCEPTED)
# ---------------------------------------------------------------------------
# THE MODEL IS "CREDENTIALS ARE THE AUTHORIZATION, PLUS AN OPTIONAL
# `--i-own-account`", AND IT IS DELIBERATELY WEAKER THAN DAST'S.
#
# `modules/dast/` requires `--i-own-target` before it will raise a limit,
# because it SENDS injection payloads that can harm a target and its users.
# Cloud cannot: the read-only property is enforced at a runtime chokepoint and
# tested (`lib/awscli.sh`'s `aws_ro`, which refuses any non-read operation with
# exit 3 BEFORE exec'ing the CLI), so there is no state this module can change
# however wrong the invocation is.  Requiring an affirmation for a read-only
# scan would also break `scan.sh all --live` and would train an operator to
# type the affirmation reflexively, which is the failure mode that makes the
# DAST one worthless too.
#
# What the residual risks actually are - CloudTrail noise, API-quota
# consumption, and a possible GuardDuty anomaly alert across a multi-service,
# multi-region sweep - are answered by an AUDIT RECORD and an ECHO-BACK, not by
# a gate.  So:
#
#   1. `sts get-caller-identity` resolves FIRST, before any service script.
#   2. The account id, caller ARN, profile and planned region count are
#      recorded into run.json.
#   3. The resolved account and region count are echoed to STDERR before the
#      first service call - the operator sees which account they are about to
#      sweep while it is still theirs to interrupt.
#   4. `--i-own-account <id>` is OPTIONAL; when given, a mismatch is exit 2
#      naming BOTH ids.  Optional rather than required because the credential
#      is already a real authorization signal in a way "I typed a hostname" is
#      not - but the flag still buys exactly what `--i-own-target` was built
#      for: a stale command pasted into the wrong shell or the wrong CI job.
#
# `_scan_record_authorization` (scan.sh) is the DAST analogue this mirrors and
# is deliberately NOT reused: it records a scope target, a scope.conf digest
# and an intensity, none of which a cloud run has, and it calls
# `http_limits_record`, which is the HTTP transport's.  The shared half is the
# SHAPE - resolve, record, echo - not the fields.
_cloud_record_authorization() {
  local account=$1 arn=$2 profile=$3 nregions=$4 regions_source=$5

  # `cloud_account_id` and `cloud_caller_arn` are already written by
  # lib/awscli.sh's own `aws_ro_account_id_set`, at the moment the identity is
  # resolved, and are NOT re-recorded here: a second write would put two lines
  # in one meta file and `_meta_first` reads the first, so the two could
  # silently disagree if a later edit changed one.  The three below have no
  # other writer.
  run_record cloud_profile "$profile"
  run_record cloud_regions_planned "$nregions"
  run_record cloud_regions_source "$regions_source"
  [[ -n ${SCAN_FLAGS[i-own-account]:-} ]] \
    && run_record cloud_account_affirmed "${SCAN_FLAGS[i-own-account]}"

  # The echo-back.  STDERR, never stdout: stdout is where a `--format json`
  # consumer's report path is announced, and this is an operator-facing notice.
  # It names the account and the region count rather than the region list,
  # because a seventeen-region list wraps to four lines and buries the one fact
  # that matters - which account this is.
  log_info "cloud: scanning AWS account $account${arn:+ as $arn}${profile:+ (profile $profile)} across $nregions region(s), read-only"
  return 0
}

# `_cloud_check_account_affirmation ACCOUNT` - D1's optional affirmation.
#
# Exit 2 (`SCOURSH_EXIT_USAGE`), never 3: a mismatch is a wrong INVOCATION -
# the operator said one account and the credentials resolved another - and
# tension 14's own CI contract is "2/3/4 mean fix the invocation or the
# config".  3 is reserved for the tool attempting something it is not
# authorised to do, which this is not: nothing has been attempted yet.
#
# BOTH IDS ARE NAMED IN THE MESSAGE.  "account mismatch" alone leaves the
# operator to work out which of the two is wrong, and the commonest cause is a
# stale `AWS_PROFILE` in the shell - so the message has to say what the
# credentials actually resolved to, not only what was refused.
_cloud_check_account_affirmation() {
  # Two `local` lines, never one: assignments inside a single `local` do not
  # see each other in this shell (AGENTS.md's "Things measured on this
  # codebase" opens with that fact), and shellcheck's SC2318 flags the shape
  # whether or not this particular pair would have tripped over it.
  local account=$1
  local want=${SCAN_FLAGS[i-own-account]:-}
  [[ -n $want ]] || return 0
  [[ $want == "$account" ]] && return 0
  die "$SCOURSH_EXIT_USAGE" \
    "cloud: --i-own-account named account '$want', but the resolved credentials belong to account '$account' - refusing to scan an account the invocation did not name (check AWS_PROFILE / --profile)"
}

# ---------------------------------------------------------------------------
# 2. Coverage
# ---------------------------------------------------------------------------
# `_cloud_record_coverage CELL SINCE_LINE` - docs/FOUNDATION.md tension 12's
# `account-region` coverage for every CLOUD check that completed since line
# SINCE_LINE of the run-wide `checks_run` fact.  The direct port of
# modules/dast/run.sh's `_dast_record_coverage`, with `target` swapped for
# `account-region` and the id prefix for CLOUD's.
#
# Only `CLOUD-*` ids are ever considered, so a run that also dispatched
# sast/sca/iac/dast before this (`scan.sh all`) cannot have their ids
# misattributed to a cloud cell.  `POSTURE-*` is excluded too, and that is not
# an oversight: a posture check's cell is a `scope-key`, not an
# `account-region`, so crediting one here would write a cell of the wrong kind
# under an id whose registry record declares the other - which
# `lib/state.sh`'s own scope validation would then accept, because it validates
# the VALUE's shape rather than cross-checking it against the record.
#
# Guarded on `declare -F state_add_covered`, the same "an absent function is a
# no-op" contract modules/sast/engine.sh's `sast_record_coverage` documents.
_cloud_record_coverage() {
  declare -F state_add_covered >/dev/null 2>&1 || return 0
  local cell=$1 since=${2:-0}
  local line id set idx digest
  local -A seen=()
  while IFS= read -r line; do
    [[ -n $line && $line == CLOUD-* ]] || continue
    [[ -z ${seen[$line]:-} ]] || continue
    seen[$line]=1
    id=$line
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      idx=$(records_index_of_id "$set" "$id" 2>/dev/null) || continue
      digest=$(records_digest "$set" "$idx")
      state_add_covered "$id" "$digest" account-region "$cell"
      break
    done
  done < <(run_facts checks_run | tail -n "+$(( since + 1 ))")
  return 0
}

# ---------------------------------------------------------------------------
# 3. The module
# ---------------------------------------------------------------------------
_cloud_run_module() {
  # SCAN_FLAGS is scan.sh's own global associative array.  When this module is
  # exercised without scan.sh (tests/suites/cloud.sh sources this file
  # directly), it was never declared at all, and a `${SCAN_FLAGS[live]:-}` read
  # against a wholly UNDECLARED array is not the safe unset case under `set
  # -u` - bash parses the subscript as arithmetic and dies on the first bare
  # word.  The same guard, and the same `declare -p` rather than
  # `${SCAN_FLAGS+set}` test, modules/dast/run.sh and modules/sast/engine.sh
  # both already document at length.
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()

  local live=${SCAN_FLAGS[live]:-false}
  local profile=${SCAN_FLAGS[profile]:-}
  local regions_flag=${SCAN_FLAGS[regions]:-}
  local assume=${SCAN_FLAGS[assume-role]:-}

  # `--assume-role` REFUSES rather than being ignored (docs/STEP6-CLOUD-PLAN.md
  # D3, single-account only in this version).  The flag has been PARSED since
  # step 2 and read by nothing, so an operator who passed it got a
  # single-account scan of whatever ambient credentials resolved, reported with
  # no indication that the other accounts they asked for were never visited -
  # a clean report for an estate that was never looked at.  Refusing is the
  # smaller failure by a wide margin, and it is exit 2 for the same reason the
  # affirmation mismatch is: it is a wrong invocation against this version of
  # the tool, and the fix is to drop the flag or wait for the multi-account
  # ticket.
  #
  # It is checked BEFORE `--live`, so `scan.sh cloud --assume-role ...` with no
  # `--live` is refused too.  Accepting it silently on the one invocation that
  # was going to do nothing anyway would leave the operator believing the flag
  # is supported.
  if [[ -n $assume ]]; then
    die "$SCOURSH_EXIT_USAGE" \
      "cloud: --assume-role is not implemented in this version (single-account only) - it was refused rather than ignored, because ignoring it would report a one-account scan as if it had covered every account named"
  fi

  # `--profile` is HONOURED, at last: it has been parsed since step 2 and read
  # by nothing, so `--profile staging` scanned whatever ambient
  # AWS_PROFILE/default credentials resolved - and then labelled the findings
  # with the account those credentials belonged to, which is at least honest
  # about WHERE it looked but is not what was asked for.  `aws_ro_use_profile`
  # is lib/awscli.sh's own setter, so the profile reaches the CLI through the
  # one chokepoint rather than through an environment variable this module
  # exports behind the chokepoint's back.
  #
  # Set BEFORE the identity call, which is the whole point: resolving the
  # identity under the default profile and then switching would record one
  # account and scan another.
  aws_ro_use_profile "$profile"

  if [[ $live != true ]]; then
    # SC2016: the backticks in the two records below are literal prose - a
    # report reader sees `--live` and `scan.sh iac` as code spans - not command
    # substitution, and the strings are deliberately single-quoted so nothing
    # in them is expanded.
    # shellcheck disable=SC2016
    # docs/DESIGN.md §8 splits this module in two: §8.1's live read-only
    # catalog and §8.2's IaC pattern rules.  The IaC half already ships, as
    # `modules/iac/` (step 4), and is reached by `scan.sh iac` - so a `cloud`
    # run with no `--live` has genuinely nothing to do, and must say so rather
    # than exiting 0 over an empty findings set.
    #
    # NO CREDENTIAL IS TOUCHED ON THIS PATH.  `sts get-caller-identity` is not
    # called, so a `scan.sh cloud` with no `--live` reaches no AWS endpoint at
    # all - which is what makes it safe to run on a machine whose ambient
    # credentials belong to somewhere the operator did not intend to contact.
    run_record coverage_reduction 'module=cloud reason=no_live_flag - `--live` was not given, so no AWS API call was made and no account was examined. The IaC half of docs/DESIGN.md §8 is a separate command (`scan.sh iac`) and is unaffected by this.'
    # shellcheck disable=SC2016
    run_record coverage_gap 'cloud examined no AWS account: `--live` was not given, so this run made no AWS API call at all and tested no property of any account. A clean result here is the absence of a test, not the absence of a problem - re-run with `scan.sh cloud --live`.'
    _cloud_finish
    return 0
  fi

  # -------------------------------------------------------------------------
  # Identity FIRST, before any service script (D1 step 1).
  # -------------------------------------------------------------------------
  # Called DIRECTLY, never through `$(...)`: `aws_ro_account_id_set` is a
  # setter for exactly the reason its own header gives - a `die` inside a
  # command substitution runs in a subshell where `exit` ends only the
  # subshell, and every `SCOURSH_AWS_RO_*` outcome global it sets would be set
  # in a process that then exits.
  local account='' arc=0
  aws_ro_account_id_set account || arc=$?
  if (( arc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason detail=identity_unresolved - \`sts get-caller-identity\` did not resolve a caller identity (${SCOURSH_AWS_RO_OUTCOME:-error}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this run does not know which account it would have been scanning and made no further AWS call. Nothing about any account was examined."
    run_record coverage_gap 'cloud examined no AWS account: the credentials could not be resolved, so scoursh never learned which account it was pointed at and stopped before making a single service call. This is NOT a clean account - it is a run that never looked. Check AWS_PROFILE / --profile, the credential file, and that the role has sts:GetCallerIdentity.'
    # docs/FOUNDATION.md tension 14's per-module required-inputs table:
    # `cloud --live` requires "resolvable AWS credentials", so an unresolvable
    # one is a MISSING REQUIRED INPUT and exit 4 - the identical shape
    # modules/sca/run.sh uses for an absent `data/advisories.db`, down to the
    # `SCAN_COMMAND` test.  Under `all` the same table's other row governs -
    # "a module whose inputs are absent is skipped with a run.json reason" -
    # so the reduction is still recorded and the exit code is untouched,
    # because the other modules did do what they were asked.  Both directions
    # are pinned in tests/suites/cloud.sh, because the naive fix for each is
    # the other's bug.
    if [[ ${SCAN_COMMAND:-cloud} == cloud ]]; then
      # Sets scan_main's OWN `input` local through the sourced-not-subprocess
      # dynamic-scoping contract scan.sh's header documents - the identical
      # mechanism modules/sca/run.sh uses, and for the identical reason:
      # scan_exit_code's precedence table is the one place an exit code is
      # decided, and a module must feed it rather than exit on its own.
      # shellcheck disable=SC2034
      input=1
    fi
    _cloud_finish
    return 0
  fi

  # The affirmation is checked the instant the account is known and BEFORE the
  # region enumeration, so a wrong-account invocation costs one API call rather
  # than one plus an enumeration.
  _cloud_check_account_affirmation "$account"

  # -------------------------------------------------------------------------
  # Regions.
  # -------------------------------------------------------------------------
  cloud_regions_resolve --regions "$regions_flag" || true
  local nregions=${#_CLOUD_REGIONS[@]}
  if [[ -n $_CLOUD_REGIONS_REASON ]]; then
    run_record coverage_reduction "module=cloud reason=$_CLOUD_REGIONS_REASON regions_resolved=$nregions - $_CLOUD_REGIONS_DETAIL"
  fi

  _cloud_record_authorization "$account" "${SCOURSH_AWS_CALLER_ARN:-}" "$profile" \
    "$nregions" "$_CLOUD_REGIONS_SOURCE"

  if (( nregions == 0 )); then
    # Global services can still run - they need no region - so this is a
    # PARTIAL loss and is recorded as one rather than as a dead run.  Saying
    # "no region was scanned" while the global pass did real work would be
    # false in the opposite direction.
    run_record coverage_gap "cloud resolved NO enabled region for account $account, so every regional service in docs/DESIGN.md §8.1's catalog was skipped entirely and nothing regional was tested. Only account-global namespaces were reachable. A clean result for a region is the absence of a test here, not the absence of a problem."
  fi

  # -------------------------------------------------------------------------
  # The service walk.
  # -------------------------------------------------------------------------
  local spec scope cell region
  local ran=0 covered=0 why
  local expected=${#_CLOUD_SERVICES[@]}
  local -a cells=()

  # How many of the catalog's scripts are actually on disk, counted ONCE over
  # the table rather than derived from the walk's `absent` tally.  The walk
  # visits a regional row once per region, so an absent-per-invocation count
  # would report "17 services missing" on a one-region run and "459" on a
  # twenty-seven-region one for the identical tree - a number about the region
  # count wearing a service label.
  local present=0
  for spec in "${_CLOUD_SERVICES[@]+"${_CLOUD_SERVICES[@]}"}"; do
    [[ -f ${SCOURSH_INSTALL_ROOT:-}/modules/cloud/aws/${spec%%:*} ]] \
      && present=$(( present + 1 ))
  done

  # `global` first, then one pass per region, in the order `_CLOUD_SERVICES`
  # and `_CLOUD_REGIONS` declare - a fixed, reproducible order, because a
  # finding's `occurrence` ordinal (tension 5) and this run's own
  # `checks_run` order both derive from the order things were visited, and a
  # set-iteration order that varied between runs would churn both.
  cells=(global)
  for region in "${_CLOUD_REGIONS[@]+"${_CLOUD_REGIONS[@]}"}"; do
    cells+=("$region")
  done

  local _cloud_checks_run_before
  _cloud_checks_run_before=$(run_facts checks_run | wc -l | tr -d '[:space:]')

  for region in "${cells[@]+"${cells[@]}"}"; do
    cell=$(cloud_cell "$account" "$region")
    # `run_record regions` is what fills run.json's own `regions` array, which
    # has been rendered since step 1 and written by nothing (it was always
    # `[]`).  `global` is deliberately NOT recorded into it: that array answers
    # "which AWS regions did this run visit", and `global` is not a region.
    [[ $region == global ]] || run_record regions "$region"
    run_record notes "module=cloud account=$account region=$region coverage-scope=account-region cell=$cell"

    local _cloud_cell_checks_before
    _cloud_cell_checks_before=$(run_facts checks_run | wc -l | tr -d '[:space:]')

    for spec in "${_CLOUD_SERVICES[@]+"${_CLOUD_SERVICES[@]}"}"; do
      scope=${spec##*:}
      # A `global` service runs only in the `global` pass and a `regional` one
      # only in a region pass.  The test is on the ROW's declared scope against
      # the CURRENT cell, never on "is this the first iteration": the loop's
      # first element is `global` today and a later edit that reordered it
      # would otherwise silently run every regional service against no region.
      if [[ $region == global ]]; then
        [[ $scope == global ]] || continue
      else
        [[ $scope == regional ]] || continue
      fi
      cloud_run_service "$spec" "$account" "$region"
      [[ $_CLOUD_SERVICE_OUTCOME == ran ]] && ran=$(( ran + 1 ))
    done

    # Per-cell, so a check that ran in us-east-1 is credited to us-east-1's
    # cell alone.  Crediting it to every cell would let tension 12 infer
    # `fixed` for a region this run never opened a connection to, which is the
    # precise failure that tension's (check, scope-cell) pairing exists to
    # prevent.
    _cloud_record_coverage "$cell" "$_cloud_cell_checks_before"
  done

  # THE HONESTY TEST IS COVERAGE, NOT EXECUTION - modules/dast/run.sh's own
  # lesson, inherited rather than re-learned.  "A service script ran" would
  # start reading as coverage the moment a script exists that legitimately
  # covers nothing in a given region (an account with no EKS cluster, say).
  # What a reader needs to know is whether any CHECK was covered, and
  # `run_record checks_run` is this repository's existing answer to that.
  local line
  while IFS= read -r line; do
    [[ -n $line && $line == CLOUD-* ]] && covered=$(( covered + 1 ))
  done < <(run_facts checks_run | tail -n "+$(( _cloud_checks_run_before + 1 ))")

  if (( covered == 0 )); then
    if (( present == 0 )); then
      why="modules/cloud/aws/live/ ships no service script yet (0 of $expected present, docs/STEP6-CLOUD-PLAN.md), so no service was examined"
      run_record coverage_reduction "module=cloud reason=no_service_scripts_on_disk_yet account=$account services_expected=$expected services_present=0 cells=${#cells[@]}"
    elif (( ran == 0 )); then
      # Reachable only once a script exists that this walk never invoked -
      # every present row today is invoked in one cell or another, so a
      # `present > 0, ran == 0` run means the cell list itself was empty, which
      # cannot happen while `global` is unconditionally first.  Written now
      # rather than left to the `else` arm so a future edit that makes it
      # reachable produces its own reason instead of the wrong one.
      why="$present of the $expected service scripts are present and none was invoked in any of the ${#cells[@]} cell(s) this run resolved"
      run_record coverage_reduction "module=cloud reason=no_service_invoked account=$account services_expected=$expected services_present=$present cells=${#cells[@]}"
    else
      why="$ran service script invocation(s) ran across ${#cells[@]} cell(s) and none of them covered a check - each one's own coverage_reduction above says why"
      run_record coverage_reduction "module=cloud reason=no_check_covered_by_any_service account=$account services_expected=$expected services_present=$present service_runs=$ran cells=${#cells[@]}"
    fi
    run_record coverage_gap "cloud covered nothing in account $account: $why and no property of the account's configuration was tested - a clean result here is the absence of a test, not the absence of a problem"
  fi

  _cloud_finish
  return 0
}

# The same five calls, in the same order, that modules/sast/run.sh,
# modules/iac/run.sh and modules/dast/run.sh all end with.  They run even
# though this module emitted nothing: findings_merge and derive_findings are
# no-ops over an empty shard set, sast_evaluate_gate is what makes `--fail-on`
# apply to cloud findings the moment a service script emits one (and is reused
# rather than forked for the module-agnostic reason modules/iac/run.sh's own
# comment records), and report_all is what puts the coverage records above in
# front of a reader.  Skipping them "because there is nothing to report" is
# exactly how a run with no service scripts would end up with no report saying
# so.
#
# Factored into its own function rather than repeated at each of this module's
# four early returns: a return path that forgot it would leave a run with a
# recorded reason and NO REPORT RENDERING IT, which is the same silence this
# whole file is written against.
_cloud_finish() {
  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-06: classify (tension 11 stage 5) runs
  # strictly after derive (4) and before the gate (7) - lib/diff.sh's own
  # header states the frozen stage order this call site follows.
  diff_classify_run "$SCOURSH_RUN_DIR"
  # STATE-07: suppress (stage 6) runs strictly after classify and before the
  # gate.
  baseline_apply "$SCOURSH_RUN_DIR"
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_cloud_run_module
