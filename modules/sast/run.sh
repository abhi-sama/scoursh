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
# THE OPTIONAL SEMGREP ENGINE ADAPTER (docs/DESIGN.md §6.4; docs/ADAPTERS.md;
# the semgrep ticket, the first concrete adapter) is wired in at the end of
# `_sast_run_module`, below, gated on BOTH `${SCAN_FLAGS[use-engines]:-} ==
# true` AND `has_engine sast semgrep` (lib/engines.sh) - docs/ADAPTERS.md
# §5's own pseudocode keeps those two conditions independent, never
# collapsed into one check.  Absent either, this is a silent,
# honestly-declared native-only continue (`coverage_reduction
# reason=engine_not_vendored`), never an error - see
# `_sast_run_semgrep_adapter`'s own comment.
#
# THE OPTIONAL GITLEAKS ENGINE ADAPTER (this ticket, the second concrete
# adapter, built on the same plumbing) is wired in immediately after the
# semgrep block, gated the IDENTICAL, INDEPENDENT way -
# `${SCAN_FLAGS[use-engines]:-} == true` AND `has_engine sast gitleaks` -
# so one adapter's presence, absence, or failure never affects the other's
# own gate or its own coverage_reduction line.  See
# `_sast_run_gitleaks_adapter`'s own comment for its failure handling.
#
# shellcheck shell=bash
# -x back-edge cut: modules/sast/engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/engine.sh"
# docs/STEP7-STATE-PLAN.md STATE-06: diff_classify_run (called below, between
# derive_findings and sast_evaluate_gate) lives in lib/diff.sh, sourced here
# rather than from modules/sast/engine.sh - that file is reached by every
# DAST phase test too, and lib/diff.sh's own lib/state.sh edge is genuinely
# new content there (not a diamond a back-edge cut could remove for free),
# which pushed tests/suites/dast-methods.sh over its shellcheck -x memory
# budget and killed a CI run.  Confining this source line to the four run.sh
# files that actually call diff_classify_run keeps that cost off every
# phase-level test that has nothing to do with it.
# shellcheck source=lib/diff.sh
source "${BASH_SOURCE[0]%/*}/../../lib/diff.sh"
# history.sh (docs/DESIGN.md §6.3, §13 step 3e) is the module that deliberately
# DOES read git history; it is its own pure function library, sourced here
# exactly like engine.sh, and its real work only happens when
# _sast_history_run is called below.
# shellcheck source=modules/sast/history.sh
source "${BASH_SOURCE[0]%/*}/history.sh"

# _sast_run_semgrep_adapter ROOT - runs the vendored semgrep adapter
# (modules/sast/adapters/semgrep/adapter.sh, sourced by `has_engine`'s own
# call in _sast_run_module above) and normalizes its results into the
# finding model.  Only ever called after `has_engine sast semgrep` has
# already returned 0, so `semgrep_run`/`semgrep_normalize` are guaranteed to
# be defined by the time this runs.
#
# `semgrep_run` failing is a genuine engine crash, not "absent" - handled
# exactly like a missing adapter (docs/ADAPTERS.md §7: "log it, record a
# coverage_reduction with a distinct reason, and continue the run with
# native-only results for that module - never abort the whole scan for an
# opt-in power-up"), with its OWN reason (`engine_run_failed`) so the two
# cases are distinguishable in run.json.
_sast_run_semgrep_adapter() {
  local root=$1
  local out=$SCOURSH_SCRATCH/semgrep-run.$$.json
  if semgrep_run "$out" "$root"; then
    semgrep_normalize "$out"
  else
    run_record coverage_reduction 'module=sast reason=engine_run_failed engine=semgrep'
  fi
  rm -f "$out"
}

# _sast_run_gitleaks_adapter ROOT - runs the vendored gitleaks adapter
# (modules/sast/adapters/gitleaks/adapter.sh, sourced by `has_engine`'s own
# call in _sast_run_module below) and normalizes its results into the
# finding model.  Only ever called after `has_engine sast gitleaks` has
# already returned 0, so `gitleaks_run`/`gitleaks_normalize` are guaranteed
# to be defined by the time this runs.
#
# Mirrors `_sast_run_semgrep_adapter` exactly, including the
# `engine_run_failed` distinct-reason handling for a genuine engine crash
# (docs/ADAPTERS.md §7) - deliberately called AFTER the semgrep block in
# `_sast_run_module`, and after the native pattern scan above it, so
# `gitleaks_normalize`'s own cross-check-id dedup against
# modules/sast/rules/secrets.rules
# (`_gitleaks_dup_of_native_secret`, in the adapter itself) can read this
# run's own native SAST-SEC-* findings from the still-unmerged shard file.
_sast_run_gitleaks_adapter() {
  local root=$1
  local out=$SCOURSH_SCRATCH/gitleaks-run.$$.json
  if gitleaks_run "$out" "$root"; then
    gitleaks_normalize "$out"
  else
    run_record coverage_reduction 'module=sast reason=engine_run_failed engine=gitleaks'
  fi
  rm -f "$out"
}

_sast_run_module() {
  local path=${_SCAN_RESOLVED_PATH:-.}

  if (( ${#CHECKS_REGISTRY_SETS[@]} == 0 )); then
    # _scan_apply_profile_filter already recorded coverage_reduction for this
    # (module=sast reason=no_check_registry_on_disk_yet); nothing more to do.
    log_warn 'sast: no pattern-rule registry on disk under modules/sast/rules/ - nothing to scan'
  else
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
      # docs/STEP7-STATE-PLAN.md STATE-02: reached only when sast_scan_tree
      # returned without dying, so every id in `ids` genuinely ran to
      # completion over this run's one path-root cell.
      sast_record_coverage "$SCOURSH_PATH_ROOT" "${ids[@]+"${ids[@]}"}"
    fi

    # tension 16's parallel workers (rate limiter, request budget, circuit
    # breaker) land at §13 step 5; this run is single-worker, honestly declared
    # rather than silently claimed as parallel.
    run_record coverage_reduction 'module=sast reason=single_worker_no_parallel_scan_yet'
  fi

  # Independent of the working-tree registry above: history.sh replays only
  # modules/sast/rules/secrets.rules (loaded directly, not through
  # CHECKS_REGISTRY_SETS), and _sast_history_run's own gates (--history
  # requested, scan root is a git repo, not shallow, has commits) decide
  # whether it does anything at all.
  _sast_history_run "$path"

  # Also independent of the working-tree registry above, for the same
  # reason: the semgrep adapter's check ids are minted at runtime, never
  # loaded through CHECKS_REGISTRY_SETS (lib/checks.sh's own header now
  # states this boundary explicitly).
  if [[ ${SCAN_FLAGS[use-engines]:-} == true ]]; then
    if has_engine sast semgrep; then
      _sast_run_semgrep_adapter "$path"
    else
      run_record coverage_reduction 'module=sast reason=engine_not_vendored engine=semgrep'
    fi
    if has_engine sast gitleaks; then
      _sast_run_gitleaks_adapter "$path"
    else
      run_record coverage_reduction 'module=sast reason=engine_not_vendored engine=gitleaks'
    fi
  fi

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-06: classify (tension 11 stage 5) runs
  # strictly after derive (4) and before the gate (7) - lib/diff.sh's own
  # header states the frozen stage order this call site follows.
  diff_classify_run "$SCOURSH_RUN_DIR"
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_sast_run_module
