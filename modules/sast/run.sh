#!/usr/bin/env bash
# modules/sast/run.sh - the SAST module entry point (docs/DESIGN.md §13 step 3).
#
# Contract (scan.sh's own header, PR #6/#7): `scan_dispatch sast` does a plain
# `source` of this file, never a subprocess, so it inherits every already-set
# variable of the calling scan_main invocation - SCOURSH_RUN_DIR,
# SCOURSH_SCAN_ROOT_ID, SCOURSH_PATH_ROOT, SCOURSH_JOBS, SCOURSH_FAIL_ON,
# SCOURSH_MIN_CONFIDENCE, SCOURSH_REDACT_SECRETS, _SCAN_RESOLVED_PATH,
# SCAN_FLAGS, CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every
# lib/*.sh function, all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called (scan.sh's own
# no-op branch - log_warn + run_record, unconditionally, every call - is the
# existing precedent), and more than one scan_main invocation can happen in
# one process (tests/suites/scan.sh calls it repeatedly).  Only
# modules/sast/engine.sh, a pure function library, gets the standard
# sourced-once guard.
#
# shellcheck shell=bash
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"

_sast_run_module() {
  local path=${_SCAN_RESOLVED_PATH:-.}

  if (( ${#CHECKS_REGISTRY_SETS[@]} == 0 )); then
    # _scan_apply_profile_filter already recorded coverage_reduction for this
    # (module=sast reason=no_check_registry_on_disk_yet); nothing more to do.
    log_warn 'sast: no pattern-rule registry on disk under modules/sast/rules/ - nothing to scan'
    return 0
  fi

  sast_index_checks

  local -a ids=()
  local id
  for id in "${CHECKS_LAST_SELECTED_IDS[@]+"${CHECKS_LAST_SELECTED_IDS[@]}"}"; do
    [[ -n ${_SAST_CHECK_LOC[$id]:-} ]] || continue
    ids+=("$id")
    run_record checks_run "$id"
  done

  if (( ${#ids[@]} == 0 )); then
    run_record coverage_reduction 'module=sast reason=no_checks_selected'
  else
    sast_scan_tree "$path" "${ids[@]+"${ids[@]}"}"
  fi

  # tension 16's parallel workers (rate limiter, request budget, circuit
  # breaker) land at §13 step 5; this run is single-worker, honestly declared
  # rather than silently claimed as parallel.
  run_record coverage_reduction 'module=sast reason=single_worker_no_parallel_scan_yet'

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_sast_run_module
