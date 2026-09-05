#!/usr/bin/env bash
# modules/iac/run.sh - the IaC module entry point (docs/DESIGN.md §13 step 4).
#
# Contract (modules/sast/run.sh's own header, reused verbatim here): scan.sh's
# `scan_dispatch iac` does a plain `source` of this file, never a subprocess,
# so it inherits every already-set variable of the calling scan_main
# invocation - SCOURSH_RUN_DIR, SCOURSH_SCAN_ROOT_ID, SCOURSH_PATH_ROOT,
# SCOURSH_JOBS, SCOURSH_FAIL_ON, SCOURSH_MIN_CONFIDENCE,
# SCOURSH_REDACT_SECRETS, _SCAN_RESOLVED_PATH, SCAN_FLAGS,
# CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every lib/*.sh
# function, all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, and more than one
# scan_main invocation can happen in one process (tests/suites/scan.sh calls
# it repeatedly).  Only modules/iac/parse.sh, a pure function library, gets
# the standard sourced-once guard - exactly the sast/engine.sh split.
#
# THE OPTIONAL TRIVY ENGINE ADAPTER (docs/DESIGN.md §6.6's "same pattern as
# §6.4" note; docs/ADAPTERS.md; this ticket, the second concrete adapter and
# the first for a module other than sast) is wired in at the end of
# `_iac_run_module`, below, gated on BOTH `${SCAN_FLAGS[use-engines]:-} ==
# true` AND `has_engine iac trivy` (lib/engines.sh) - identical shape to
# modules/sast/run.sh's own semgrep wiring, docs/ADAPTERS.md §5's pseudocode
# kept independent on purpose.  Absent either, this is a silent, honestly-
# declared native-only continue (`coverage_reduction
# reason=engine_not_vendored`), never an error - see
# `_iac_run_trivy_adapter`'s own comment.
#
# shellcheck shell=bash
# shellcheck source=modules/iac/parse.sh
source "${BASH_SOURCE[0]%/*}/parse.sh"
# docs/STEP7-STATE-PLAN.md STATE-06: see modules/sast/run.sh's own comment on
# why this is sourced directly here (rather than from modules/sast/engine.sh)
# AND why it is guarded (a fixture root with no lib/ sibling makes the
# unconditional form fail to even locate the file).
if [[ -z ${SCOURSH_DIFF_SOURCED:-} ]]; then
  # shellcheck source=lib/diff.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/diff.sh"
fi

# _iac_run_trivy_adapter ROOT - runs the vendored trivy adapter
# (modules/iac/adapters/trivy/adapter.sh, sourced by `has_engine`'s own call
# in _iac_run_module below) and normalizes its results into the finding
# model.  Only ever called after `has_engine iac trivy` has already returned
# 0, so `trivy_run`/`trivy_normalize` are guaranteed to be defined by the
# time this runs.
#
# `trivy_run` failing is a genuine engine crash, not "absent" - handled
# exactly like a missing adapter (docs/ADAPTERS.md §7: "log it, record a
# coverage_reduction with a distinct reason, and continue the run with
# native-only results for that module - never abort the whole scan for an
# opt-in power-up"), with its OWN reason (`engine_run_failed`) so the two
# cases are distinguishable in run.json - the identical shape
# modules/sast/run.sh's own `_sast_run_semgrep_adapter` already uses.
_iac_run_trivy_adapter() {
  local root=$1
  local out=$SCOURSH_SCRATCH/trivy-run.$$.json
  if trivy_run "$out" "$root"; then
    trivy_normalize "$out"
  else
    run_record coverage_reduction 'module=iac reason=engine_run_failed engine=trivy'
  fi
  rm -f "$out"
}

_iac_run_module() {
  local path=${_SCAN_RESOLVED_PATH:-.}

  if (( ${#CHECKS_REGISTRY_SETS[@]} == 0 )); then
    # _scan_apply_profile_filter already recorded coverage_reduction for this
    # (module=iac reason=no_check_registry_on_disk_yet); nothing more to do.
    log_warn 'iac: no pattern-rule registry on disk under modules/iac/ - nothing to scan'
  else
    # sast_index_checks (modules/sast/engine.sh) is reused unchanged: it
    # indexes CHECKS_REGISTRY_SETS by check id, keyed off lib/records.sh
    # alone, with nothing SAST-specific in it.
    sast_index_checks

    local -a ids=()
    local id
    for id in "${CHECKS_LAST_SELECTED_IDS[@]+"${CHECKS_LAST_SELECTED_IDS[@]}"}"; do
      [[ -n ${_SAST_CHECK_LOC[$id]:-} ]] || continue
      ids+=("$id")
      run_record checks_run "$id"
    done

    if (( ${#ids[@]} == 0 )); then
      run_record coverage_reduction 'module=iac reason=no_checks_selected'
    else
      iac_scan_tree "$path" "${ids[@]+"${ids[@]}"}"
      # docs/STEP7-STATE-PLAN.md STATE-02: sast_record_coverage
      # (modules/sast/engine.sh) is reused unchanged, exactly like
      # sast_index_checks/sast_evaluate_gate above - reached only when
      # iac_scan_tree returned without dying.
      sast_record_coverage "$SCOURSH_PATH_ROOT" "${ids[@]+"${ids[@]}"}"
    fi

    # tension 16's parallel workers (rate limiter, request budget, circuit
    # breaker) land at §13 step 5; this run is single-worker, honestly
    # declared rather than silently claimed as parallel - same declaration
    # modules/sast/run.sh makes for itself.
    run_record coverage_reduction 'module=iac reason=single_worker_no_parallel_scan_yet'
  fi

  # Independent of the working-tree registry above, for the same reason
  # modules/sast/run.sh's own semgrep wiring is: the trivy adapter's check
  # ids are minted at runtime, never loaded through CHECKS_REGISTRY_SETS
  # (lib/checks.sh's own header states this boundary explicitly).
  if [[ ${SCAN_FLAGS[use-engines]:-} == true ]]; then
    if has_engine iac trivy; then
      _iac_run_trivy_adapter "$path"
    else
      run_record coverage_reduction 'module=iac reason=engine_not_vendored engine=trivy'
    fi
  fi

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-06: classify (tension 11 stage 5) runs
  # strictly after derive (4) and before the gate (7) - lib/diff.sh's own
  # header states the frozen stage order this call site follows.
  diff_classify_run "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-07: suppress (tension 11 stage 6) runs
  # strictly after classify (5) and before the gate (7).
  baseline_apply "$SCOURSH_RUN_DIR"
  # sast_evaluate_gate (modules/sast/engine.sh) is reused unchanged rather
  # than forked into an "iac_evaluate_gate": despite its name it is already
  # module-agnostic - it re-reads every finding currently in
  # $rundir/findings.fields and applies the severity/confidence/fail-on-new
  # filter chain with no module check anywhere in its body - so calling it
  # again here after iac's own findings are merged evaluates the gate over
  # the run's accumulated findings exactly like the sast module's own call
  # does, and sets the caller's `gate` local through the same
  # sourced-not-subprocess dynamic-scoping contract scan.sh's header
  # documents.
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_iac_run_module
