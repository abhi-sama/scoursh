#!/usr/bin/env bash
# modules/dast/run.sh - the DAST module entry point (docs/DESIGN.md §13 step 5;
# docs/STEP5-DAST-PLAN.md DAST-02).
#
# Contract (modules/sast/run.sh's own header, which modules/iac/run.sh already
# reuses verbatim): scan.sh's `scan_dispatch dast` does a plain `source` of
# this file, never a subprocess, so it inherits every already-set variable of
# the calling scan_main invocation - SCOURSH_RUN_DIR, SCOURSH_JOBS,
# SCOURSH_FAIL_ON, SCOURSH_MIN_CONFIDENCE, SCOURSH_REDACT_SECRETS, SCAN_FLAGS,
# CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every lib/*.sh function,
# all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, and more than one
# scan_main invocation can happen in one process (tests/suites/scan.sh calls it
# repeatedly).  Only modules/dast/engine.sh, a pure function library, gets the
# standard sourced-once guard - exactly the sast/engine.sh and iac/parse.sh
# split.
#
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  DAST-02 is the
# dispatch skeleton: it resolves the target against config/scope.conf, resolves
# and records the intensity, reads the tension-21 inventory, walks the phase
# table in docs/DESIGN.md §13's frozen order, and writes DAST's target-scoped
# coverage cell.  It ships NO check and issues NO request - there is no phase
# script on disk yet, so a run is a clean, honestly-declared no-op, exactly the
# state modules/sast/'s own dispatch was in before its first rule pack landed.
# Not shipped here, each by its own ticket: the conservative rate/budget/breaker
# ceilings and the `--i-own-target` affirmation (DAST-32), the identifying
# User-Agent (DAST-31), run.json's `authorization` object (DAST-33), any
# `modules/dast/checks.rules` registry (there is no script for a §9.5 record to
# name, and one would fail rules/RULE-FORMAT.md's E072 on every row), and
# multi-target iteration (docs/DESIGN.md §5's grammar has one `--target`, so
# the loop below runs once; it is written as a loop because the target set, not
# the flag, is what a later ticket widens).
#
# THE HONESTY THIS FILE OWES ITS READER IS ITS ACTUAL DELIVERABLE.  A run that
# does nothing must not leave a report that reads like a clean scan.  Every
# no-op below is recorded as a `coverage_reduction` or a `coverage_gap` in the
# run's own meta, which lib/report.sh renders into run.json AND into the
# limitations section of the markdown and HTML reports - the surfaces a
# consumer actually reads, not an internal record.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"

# `_dast_record_inventory_gaps` - one coverage_gap per inventory artifact that
# is not usable input (docs/FOUNDATION.md tension 21).  Absence is the normal
# case today and is never an error; what it is not allowed to be is silent,
# because a standalone dast run that quietly tests a fraction of the surface
# while reporting the same verdict is precisely the overstated coverage
# docs/DESIGN.md §15 forbids.
_dast_record_inventory_gaps() {
  local kind file state
  for kind in endpoint parameter; do
    case $kind in
      endpoint) file=inventory/endpoints.json; state=$_DAST_ENDPOINTS_STATE ;;
      parameter) file=inventory/parameters.json; state=$_DAST_PARAMETERS_STATE ;;
    esac
    case $state in
      absent)
        run_record coverage_gap "dast: no ${kind} inventory at $file was available as INPUT when this module started (reason=${kind}_inventory_absent, docs/FOUNDATION.md tension 21) - no other module wrote one, so this run began knowing no endpoint or parameter beyond what config/scope.conf names. This says nothing about what the run ends with: modules/dast/crawl.sh (DAST-04) runs later in this same run and writes $file itself, so read that file, not this sentence, for the surface the run finished with."
        ;;
      empty)
        run_record coverage_gap "dast: the ${kind} inventory at $file exists but is empty (reason=${kind}_inventory_empty, docs/FOUNDATION.md tension 21) - a producer created it and wrote nothing, which is not the same as a surface with nothing in it"
        ;;
    esac
  done
  return 0
}

_dast_run_module() {
  # SCAN_FLAGS is scan.sh's own global associative array.  When this module is
  # exercised without scan.sh (tests/suites/dast.sh sources this file directly
  # to prove the module re-asserts the scope gate for itself), it was never
  # declared at all, and a `${SCAN_FLAGS[target]:-}` read against a wholly
  # UNDECLARED array is not the safe unset case under `set -u` - bash parses
  # the subscript as arithmetic and dies on the first bare word.  The same
  # guard, and the same `declare -p` rather than `${SCAN_FLAGS+set}` test,
  # modules/sast/engine.sh's `sast_evaluate_gate` already documents at length.
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()

  local intensity=${SCAN_FLAGS[intensity]:-$CHECKS_INTENSITY_DEFAULT}
  local authed=${SCAN_FLAGS[authed]:-false}
  local intrusive=${SCAN_FLAGS[allow-intrusive]:-false}

  # scan.sh's parser already refuses an unknown --intensity, and lib/checks.sh
  # is the single vocabulary both consult.  Re-checking here is not
  # belt-and-braces: this module can be reached by a caller that never went
  # through that parser, and an unrecognised intensity must refuse rather than
  # fall back to a default that would run something.
  checks_valid_intensity "$intensity" \
    || die "$SCOURSH_EXIT_USAGE" "dast: unknown --intensity '$intensity' (one of: ${CHECKS_INTENSITIES[*]})"

  # One element today, because docs/DESIGN.md §5's grammar has a single
  # `--target` and scan.sh's parser enforces it.  It is a LIST because the
  # target set, not the flag, is what a later ticket widens, and because the
  # gate loop and the work loop below both read the same set rather than one
  # reading a flag and the other an array.
  local -a targets=()
  [[ -n ${SCAN_FLAGS[target]:-} ]] \
    || die "$SCOURSH_EXIT_USAGE" "'dast' requires --target"
  targets+=("${SCAN_FLAGS[target]}")

  local target phase script tier present why line covered
  local ran absent above expected=${#_DAST_PHASES[@]}
  local -a above_names=()

  # docs/DESIGN.md §7's first sentence: "the --target name must resolve to an
  # entry in scope.conf. No entry -> exit 3. This is the single most important
  # safety control; do not make it bypassable by raw URL."
  #
  # scan.sh's own dast branch calls config_scope_require ahead of dispatch, and
  # this call is a SECOND, INDEPENDENT assertion rather than a duplicate: a
  # gate that only binds callers who already applied it is not a gate, which is
  # the identical argument docs/FOUNDATION.md tension 19 makes for putting the
  # URL gate inside http_request rather than in its callers.
  # config_scope_require is idempotent (it reloads config/scope.conf and
  # re-checks), it is called directly and never through `$(...)` for the reason
  # lib/config.sh's own comment gives, and it owns both failure codes: a
  # present file with no matching entry is exit 3, a wholly missing file is
  # exit 4.
  #
  # It is its own loop, ahead of the work loop, because §7 says "Scope gate
  # FIRST" and this takes that literally: every target clears the gate before
  # the run records anything at all.  Gating inside the work loop would leave a
  # run that ends up refusing having already written coverage records about a
  # target it was never allowed to look at.
  for target in "${targets[@]+"${targets[@]}"}"; do
    config_scope_require "$target"
  done

  dast_inventory_read
  _dast_record_inventory_gaps

  for target in "${targets[@]+"${targets[@]}"}"; do
    # DAST's coverage cell is `target`, the config/scope.conf target id
    # (rules/RULE-FORMAT.md §9.5.1, docs/FOUNDATION.md tension 12's frozen
    # table).  Two things are done with it, and they answer different
    # questions.  `run_record targets` puts the cell this run resolved into
    # run.json's own `targets` array, deduped, which is what a reader asks
    # ("which targets did this run visit").  The exported variables are what a
    # phase script reads when it emits a finding, so `finding_set cell` carries
    # the same string the run recorded and the two can never drift - the
    # SCOURSH_PATH_ROOT convention scan.sh already uses for the path-scoped
    # modules, applied to the one dimension DAST partitions on.
    #
    # Recording the cell is NOT a claim that anything covered it.  Coverage is
    # a (check, cell) pair (tension 12), no check ran, and nothing below writes
    # `checks_run` - the gap records immediately after this loop are what say
    # so.
    run_record targets "$target"
    SCOURSH_DAST_TARGET=$target
    SCOURSH_DAST_CELL=$target
    SCOURSH_DAST_INTENSITY=$intensity
    # THE FIXED PATH, NOT `_DAST_ENDPOINTS_FILE`/`_DAST_PARAMETERS_FILE` - and
    # published UNCONDITIONALLY, whether or not a file sits there yet.
    # `dast_inventory_read` above ran once, before this loop, to answer
    # `_dast_record_inventory_gaps`' question ("was an inventory available as
    # INPUT when this module started") - and on an ordinary run the honest
    # answer to that is "no", because `crawl.sh` (DAST-04) is itself one of the
    # phases the loop below is about to run and writes these two files partway
    # through it. `_DAST_ENDPOINTS_FILE`/`_DAST_PARAMETERS_FILE` are '' in
    # exactly that case, so exporting them left every later phase in this same
    # loop believing the surface crawl.sh had just discovered did not exist
    # (docs/FOUNDATION.md tension 21's consumer contract is "read the file
    # docs/INVENTORY-FORMAT.md names", not "read whatever a snapshot taken
    # before dispatch found"). The path itself is fixed by that document
    # regardless of whether the file exists yet, so it is always the right
    # answer to "where is it"; each consumer already answers "is there
    # anything in it" for itself with its own `-r`/`-s` test at USE time
    # (`inject_inventory_load`, `dast_inventory_read` itself, ...), which is
    # what makes publishing the path unconditionally safe rather than
    # optimistic.
    SCOURSH_DAST_ENDPOINTS=$SCOURSH_RUN_DIR/inventory/endpoints.json
    SCOURSH_DAST_PARAMETERS=$SCOURSH_RUN_DIR/inventory/parameters.json
    # A phase reads these rather than `SCAN_FLAGS`, which is scan.sh's own
    # global and is a LOCAL inside this function on the test path that declares
    # it here.  Published for the same reason SCOURSH_DAST_TARGET already is:
    # a phase must never have to trust a variable it did not see set.
    SCOURSH_DAST_AUTHED=$authed
    SCOURSH_DAST_ALLOW_INTRUSIVE=$intrusive
    export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
      SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS \
      SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE

    run_record notes "module=dast target=$target coverage-scope=target cell=$target intensity=$intensity authed=$authed"

    ran=0 absent=0 above=0
    above_names=()
    for phase in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
      script=${phase%%:*}
      tier=${phase##*:}
      # Every phase is reached through this call and no other, which is what
      # makes the intensity ceiling structural: there is no second path a
      # later ticket could add a phase to that skips the gate.
      dast_run_phase "$phase" "$intensity" "$target"
      case $_DAST_PHASE_OUTCOME in
        ran) ran=$(( ran + 1 )) ;;
        absent) absent=$(( absent + 1 )) ;;
        skipped_intensity)
          # Counted only when the script actually exists.  Recording the
          # other case would put seventeen "refused by intensity" lines about
          # files nobody has written into every passive run's report, which
          # buries the one line that is about a real refusal.
          if (( _DAST_PHASE_PRESENT )); then
            above=$(( above + 1 ))
            above_names+=("$script(>=$tier)")
          else
            absent=$(( absent + 1 ))
          fi
          ;;
      esac
    done

    if (( above > 0 )); then
      run_record coverage_reduction "module=dast reason=phase_above_intensity_ceiling target=$target intensity=$intensity phases=[${above_names[*]}]"
    fi

    # THE HONESTY TEST IS COVERAGE, NOT EXECUTION, AND THE DIFFERENCE ARRIVED
    # WITH THE FIRST PHASE SCRIPT.  DAST-02 could ask "did any phase run",
    # because none existed and the two questions had one answer.  DAST-03's
    # `auth.sh` runs on every passive run and, without `--authed`, covers
    # nothing - so "a phase ran" would have started reading as coverage on
    # exactly the run that has none.  What a reader needs to know is whether any
    # CHECK was covered, and `run_record checks_run` is this repository's
    # existing answer to that (modules/sast/run.sh, modules/iac/run.sh and every
    # modules/sca/ engine already write it).
    covered=0
    while IFS= read -r line; do
      [[ -n $line ]] && covered=$(( covered + 1 ))
    done <<<"$(run_facts checks_run)"

    if (( covered == 0 )); then
      # The point of this ticket, stated on the consumer surface.  Both records
      # are written, because they answer different readers: the
      # coverage_reduction is the machine-readable declared reduction
      # (docs/FOUNDATION.md tension 14's "declared reduction" row), and the
      # coverage_gap is the sentence a human reads in the report's limitations
      # section without having to know what a phase script is.
      #
      # Two distinct reasons for two distinct causes, the same discipline
      # docs/ADAPTERS.md §7 already applies to `engine_not_vendored` versus
      # `engine_run_failed`.  Today only the first is reachable, because no
      # phase script exists; the second is what keeps this sentence TRUE on
      # the day one lands and a passive run declines to run it, rather than
      # reporting a phase that is sitting right there as "not shipped yet".
      present=$(( expected - absent ))
      if (( present == 0 )); then
        why="modules/dast/ ships no phase script yet ($present of $expected present, docs/STEP5-DAST-PLAN.md tiers 1-5), so no request was sent"
        run_record coverage_reduction "module=dast reason=no_phase_scripts_on_disk_yet target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=$ran"
      elif (( ran == 0 )); then
        why="all $present of the $expected phase scripts present declare a higher intensity than this run's --intensity $intensity, so no request was sent"
        run_record coverage_reduction "module=dast reason=no_phase_permitted_by_intensity target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=0"
      else
        # The new third case: phases exist, were permitted, and ran - and none
        # of them covered a check.  Each one has already recorded its own reason
        # (auth.sh records `authed_not_requested`, `auth_config_absent`, and so
        # on); this is the roll-up a reader sees without knowing what a phase is.
        why="$ran of the $expected phase scripts ran and none of them covered a check - each one's own coverage_reduction above says why"
        run_record coverage_reduction "module=dast reason=no_check_covered_by_any_phase target=$target intensity=$intensity phases_expected=$expected phases_present=$present phases_ran=$ran"
      fi
      run_record coverage_gap "dast covered nothing on target '$target': $why and no property of the running endpoint was tested - a clean result here is the absence of a test, not the absence of a problem"
    fi
  done

  # The same four calls, in the same order, that modules/sast/run.sh and
  # modules/iac/run.sh both end with.  They run even though this module emitted
  # nothing: findings_merge and derive_findings are no-ops over an empty shard
  # set, sast_evaluate_gate is what makes `--fail-on` apply to DAST findings
  # the moment a phase emits one (and is reused rather than forked for the
  # module-agnostic reason modules/iac/run.sh's own comment records), and
  # report_all is what puts the coverage records above in front of a reader.
  # Skipping them "because there is nothing to report" is exactly how a run
  # with no phases would end up with no report saying so.
  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_dast_run_module
