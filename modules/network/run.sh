#!/usr/bin/env bash
# modules/network/run.sh - the network/host-scanning module entry point
# (NET-04).
#
# Contract (modules/sast/run.sh's own header, reused verbatim by every module
# in this tree): scan.sh's `scan_dispatch network` does a plain `source` of
# this file, never a subprocess, so it inherits every already-set variable of
# the calling scan_main invocation - SCOURSH_RUN_DIR, SCOURSH_JOBS,
# SCOURSH_FAIL_ON, SCOURSH_MIN_CONFIDENCE, SCOURSH_REDACT_SECRETS,
# SCAN_FLAGS, CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every
# lib/*.sh function, all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, and more than one
# scan_main invocation can happen in one process (tests/suites/scan.sh calls
# it repeatedly).  Only modules/network/engine.sh, a pure function library,
# gets the standard sourced-once guard - the identical sast/engine.sh and
# dast/engine.sh split.
#
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  NET-04 is the
# dispatch skeleton, modelled on modules/dast/run.sh:112-300 (this ticket's
# own explicit instruction): it resolves the target against
# config/scope.conf, resolves and records the intensity, walks the phase
# table in modules/network/engine.sh's own frozen order, and writes
# network's target-scoped coverage cell.  It ships NO check and issues NO
# request - there is no phase script on disk yet, so a run is a clean,
# honestly-declared no-op, exactly the state modules/dast/'s own dispatch was
# in before DAST-03 (`auth.sh`) landed.  Not shipped here, each by its own
# future ticket: the declared listener set config/scope.conf's own
# base-url/extra-host entries produce (NET-05, this module's
# `crawl.sh` equivalent), any `modules/network/checks-<name>.rules`
# registry (there is no script for a §9.5 record to name, and one would fail
# rules/RULE-FORMAT.md's E072 on every row), and multi-target iteration
# (docs/DESIGN.md §5's grammar has one `--target`, so the loop below runs
# once; it is written as a loop for the identical reason
# modules/dast/run.sh's own loop is).
#
# THE HONESTY THIS FILE OWES ITS READER IS ITS ACTUAL DELIVERABLE.  A run
# that does nothing must not leave a report that reads like a clean scan.
# Every no-op below is recorded as a `coverage_reduction` or a
# `coverage_gap` in the run's own meta, which lib/report.sh renders into
# run.json AND into the limitations section of the markdown and HTML
# reports - the surfaces a consumer actually reads, not an internal record.
#
# shellcheck shell=bash
# shellcheck source=modules/network/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"
# docs/STEP7-STATE-PLAN.md STATE-06: see modules/dast/run.sh's own comment on
# why this is sourced directly here rather than from modules/network/engine.sh -
# a future tests/suites/network-<name>.sh phase-script suite sources
# modules/network/engine.sh or a single phase script directly, never this
# file, so confining the edge here keeps their shellcheck -x cost unchanged.
# Guarded for the identical reason modules/dast/run.sh's own copy of this is:
# a fixture root with no lib/ sibling makes the unconditional form fail to
# even locate the file, before its own internal guard could no-op it.
if [[ -z ${SCOURSH_DIFF_SOURCED:-} ]]; then
  # shellcheck source=lib/diff.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/diff.sh"
fi

# `_net_record_coverage TARGET SINCE_LINE` - docs/STEP7-STATE-PLAN.md
# STATE-02 applied to this module: `target` coverage
# (docs/FOUNDATION.md tension 12's frozen table) for every NET-* check that
# completed since line SINCE_LINE of the run-wide `checks_run` fact.  Only
# `NET-*` ids are ever considered, so a run that also dispatched
# sast/sca/iac/dast/cloud before this (`scan.sh all`) cannot have their ids
# misattributed to a network target cell.  Byte-identical shape to
# modules/dast/run.sh's own `_dast_record_coverage`, guarded on `declare -F
# state_add_covered` the same "an absent function is a no-op" contract that
# function documents.
_net_record_coverage() {
  declare -F state_add_covered >/dev/null 2>&1 || return 0
  local target=$1 since=${2:-0}
  local line id set idx digest
  local -A seen=()
  while IFS= read -r line; do
    [[ -n $line && $line == NET-* ]] || continue
    [[ -z ${seen[$line]:-} ]] || continue
    seen[$line]=1
    id=$line
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      idx=$(records_index_of_id "$set" "$id" 2>/dev/null) || continue
      digest=$(records_digest "$set" "$idx")
      state_add_covered "$id" "$digest" target "$target"
      break
    done
  done < <(run_facts checks_run | tail -n "+$(( since + 1 ))")
  return 0
}

# `_net_record_unaccounted TARGET` - modules/dast/engine.sh's
# `dast_record_unaccounted` backstop, applied to `NET-*` ids: a last
# chokepoint that catches a selected-but-unevaluated check no phase spoke
# for, so it is a declared reduction rather than silence.  Inert today (the
# check registry this ticket's own dispatch loads is empty, so
# `checks_selected` never carries a `NET-*` id) - kept for structural parity
# with modules/dast/run.sh and so it is already correct the day the first
# `modules/network/checks-<name>.rules` record lands, rather than a gap a
# later ticket has to remember to add.
_net_record_unaccounted() {
  local target=$1
  local line rest ids id
  local -A accounted=() selected=()

  while IFS= read -r line; do
    [[ -n $line && $line == NET-* ]] || continue
    accounted[$line]=1
  done < <(run_facts checks_run)

  while IFS= read -r line; do
    [[ $line == *"checks=["* ]] || continue
    rest=${line#*checks=[}
    ids=${rest%%]*}
    [[ -n $ids ]] || continue
    local -a idlist=()
    IFS=' ' read -r -a idlist <<<"$ids"
    for id in "${idlist[@]+"${idlist[@]}"}"; do
      [[ -n $id ]] && accounted[$id]=1
    done
  done < <(run_facts coverage_reduction)

  while IFS= read -r line; do
    [[ $line == check=* ]] || continue
    rest=${line#check=}
    id=${rest%% *}
    [[ -n $id ]] && accounted[$id]=1
  done < <(run_facts skipped_checks)

  while IFS= read -r line; do
    [[ -n $line && $line == NET-* ]] || continue
    [[ -n ${accounted[$line]:-} ]] && continue
    selected[$line]=1
  done < <(run_facts checks_selected)

  (( ${#selected[@]} > 0 )) || return 0

  local residual
  residual=$(printf '%s\n' "${!selected[@]}" | LC_ALL=C sort | tr '\n' ' ')
  residual=${residual% }
  run_record coverage_reduction "module=network reason=check_not_executed_no_reason_recorded target=$target checks=[$residual] - these checks were selected for this run and no phase reported either running them or why they did not. That is a defect in modules/network/, not a property of this target: it is recorded here rather than left silent so the coverage report cannot round it up to a clean result (docs/DESIGN.md §15)."
  run_record coverage_gap "network: ${#selected[@]} check(s) on target '$target' were selected but neither ran nor recorded why - see the check_not_executed_no_reason_recorded reduction for the list. Their absence from the findings below is unexplained, which means it is not evidence of anything about this target."
  return 0
}

_net_run_module() {
  # SCAN_FLAGS guard - see modules/dast/run.sh's own comment for why
  # `declare -p` rather than `${SCAN_FLAGS+set}` is load-bearing under
  # `set -u` when this module is exercised without scan.sh
  # (tests/suites/network.sh sources this file directly to prove it
  # re-asserts the scope gate for itself).
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()

  local intensity=${SCAN_FLAGS[intensity]:-$CHECKS_INTENSITY_DEFAULT}
  local intrusive=${SCAN_FLAGS[allow-intrusive]:-false}

  # scan.sh's parser already refuses an unknown --intensity, and lib/checks.sh
  # is the single vocabulary both consult.  Re-checking here is not
  # belt-and-braces: this module can be reached by a caller that never went
  # through that parser.
  checks_valid_intensity "$intensity" \
    || die "$SCOURSH_EXIT_USAGE" "network: unknown --intensity '$intensity' (one of: ${CHECKS_INTENSITIES[*]})"

  # One element today - docs/DESIGN.md §5's grammar has a single --target and
  # scan.sh's parser enforces it.  A LIST because the target set, not the
  # flag, is what a later ticket widens, the identical reasoning
  # modules/dast/run.sh's own comment gives.
  local -a targets=()
  [[ -n ${SCAN_FLAGS[target]:-} ]] \
    || die "$SCOURSH_EXIT_USAGE" "'network' requires --target"
  targets+=("${SCAN_FLAGS[target]}")

  local target phase script tier present why line covered
  local ran absent above expected=${#_NET_PHASES[@]}
  local -a above_names=()

  # An operator-configured out-of-scope
  # tuple is refused exactly like an out-of-scope DAST target.  scan.sh's
  # own network dispatch arm calls config_scope_require ahead of dispatch,
  # and this call is a SECOND, INDEPENDENT assertion rather than a
  # duplicate - a gate that only binds callers who already applied it is not
  # a gate, the identical argument modules/dast/run.sh's own comment (and
  # docs/FOUNDATION.md tension 19) makes for putting the URL gate inside
  # http_request rather than in its callers.  It is its own loop, ahead of
  # the work loop, for the identical reason: every target clears the gate
  # before the run records anything at all.
  for target in "${targets[@]+"${targets[@]}"}"; do
    config_scope_require "$target"
  done

  for target in "${targets[@]+"${targets[@]}"}"; do
    # network's coverage cell is `target`, the config/scope.conf target id
    # (rules/RULE-FORMAT.md §9.5.1, NET-02) - byte-identical convention to
    # DAST's.  `run_record targets` puts the cell this run resolved into
    # run.json's own `targets` array; the exported variables are what a
    # future phase script reads when it emits a finding, so `finding_set
    # cell` carries the same string the run recorded and the two can never
    # drift.
    run_record targets "$target"
    SCOURSH_NET_TARGET=$target
    SCOURSH_NET_CELL=$target
    SCOURSH_NET_INTENSITY=$intensity
    SCOURSH_NET_ALLOW_INTRUSIVE=$intrusive
    export SCOURSH_NET_TARGET SCOURSH_NET_CELL SCOURSH_NET_INTENSITY \
      SCOURSH_NET_ALLOW_INTRUSIVE

    run_record notes "module=network target=$target coverage-scope=target cell=$target intensity=$intensity"

    # docs/STEP7-STATE-PLAN.md STATE-02: the line count of `checks_run`
    # BEFORE this target's own phase loop, so _net_record_coverage below
    # reads only the ids THIS target's phases actually completed - never a
    # prior target's (or, in `scan.sh all`, an earlier module's) ids that
    # happen to share the same shared, run-wide `checks_run` fact file.
    local _net_checks_run_before
    _net_checks_run_before=$(run_facts checks_run | wc -l | tr -d '[:space:]')

    ran=0 absent=0 above=0
    above_names=()
    for phase in "${_NET_PHASES[@]+"${_NET_PHASES[@]}"}"; do
      script=${phase%%:*}
      tier=${phase##*:}
      # Every phase is reached through this call and no other, which is what
      # makes the intensity ceiling structural: there is no second path a
      # later ticket could add a phase to that skips the gate.
      net_run_phase "$phase" "$intensity" "$target"
      case $_NET_PHASE_OUTCOME in
        ran) ran=$(( ran + 1 )) ;;
        absent) absent=$(( absent + 1 )) ;;
        skipped_intensity)
          # Counted only when the script actually exists - the identical
          # "do not bury the one real refusal under N files nobody has
          # written" reasoning modules/dast/run.sh's own comment gives.
          if (( _NET_PHASE_PRESENT )); then
            above=$(( above + 1 ))
            above_names+=("$script(>=$tier)")
          else
            absent=$(( absent + 1 ))
          fi
          ;;
      esac
    done

    if (( above > 0 )); then
      run_record coverage_reduction "module=network reason=phase_above_intensity_ceiling target=$target intensity=$intensity phases=[${above_names[*]}]"
    fi

    # THE HONESTY TEST IS COVERAGE, NOT EXECUTION - modules/dast/run.sh's own
    # comment on `covered`, applied here from the start rather than
    # retrofitted once a first phase lands: with zero phase scripts on disk
    # "did any phase run" and "was any check covered" already have different
    # answers is not yet observable, but a future phase that runs on every
    # pass and, absent some precondition, covers nothing (auth.sh's own
    # shape) would silently read as coverage under the weaker test.
    covered=0
    while IFS= read -r line; do
      [[ -n $line ]] && covered=$(( covered + 1 ))
    done <<<"$(run_facts checks_run)"

    if (( covered == 0 )); then
      # Two distinct records for two distinct readers, the identical split
      # modules/dast/run.sh's own comment gives: coverage_reduction is the
      # machine-readable declared reduction (docs/FOUNDATION.md tension 14),
      # coverage_gap is the sentence a human reads in the report's
      # limitations section without having to know what a phase script is.
      present=$(( expected - absent ))
      if (( present == 0 )); then
        why="this install is missing every network phase script ($present of $expected present on disk), so no request was sent"
        run_record coverage_reduction "module=network reason=no_phase_scripts_on_disk_yet target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=$ran"
      elif (( ran == 0 )); then
        why="all $present of the $expected phase scripts present declare a higher intensity than this run's --intensity $intensity, so no request was sent"
        run_record coverage_reduction "module=network reason=no_phase_permitted_by_intensity target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=0"
      else
        why="$ran of the $expected phase scripts ran and none of them covered a check - each one's own coverage_reduction above says why"
        run_record coverage_reduction "module=network reason=no_check_covered_by_any_phase target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=$ran"
      fi
      # A target with no declared listener beyond
      # base-url records a coverage_gap and exits 0 - the same honest
      # statement modules/dast/run.sh's own coverage_gap makes for a target
      # with no injectable parameter.  A target that DOES declare real
      # extra-host listeners reaches this branch only when every phase
      # covered nothing for it (e.g. every declared listener was filtered),
      # in which case the message above already names why.
      run_record coverage_gap "network covered nothing on target '$target': $why and no property of the target's listeners was tested - a clean result here is the absence of a test, not the absence of a problem."
    fi

    # docs/STEP7-STATE-PLAN.md STATE-02: reached only when every phase for
    # THIS target returned without dying - the identical reasoning
    # modules/dast/run.sh's own comment gives for why an aborted target
    # correctly records zero coverage here.
    _net_record_coverage "$target" "$_net_checks_run_before"

    # The honesty net, LAST for this target - after every phase has had its
    # chance to record its own, better reason.
    _net_record_unaccounted "$target"
  done

  # The same five calls, in the same order, that modules/sast/run.sh,
  # modules/iac/run.sh and modules/dast/run.sh all end with.  They run even
  # though this module emitted nothing: findings_merge and derive_findings
  # are no-ops over an empty shard set, sast_evaluate_gate is what makes
  # `--fail-on` apply to network findings the moment a phase emits one, and
  # report_all is what puts the coverage records above in front of a
  # reader.  Skipping them "because there is nothing to report" is exactly
  # how a run with no phases would end up with no report saying so.
  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-06: classify (tension 11 stage 5) runs
  # strictly after derive (4) and before the gate (7).
  diff_classify_run "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-07: suppress (tension 11 stage 6) runs
  # strictly after classify (5) and before the gate (7).
  baseline_apply "$SCOURSH_RUN_DIR"
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_net_run_module
