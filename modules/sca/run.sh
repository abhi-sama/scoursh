#!/usr/bin/env bash
# modules/sca/run.sh - the SCA module entry point (docs/DESIGN.md §13 step 4).
#
# Contract (mirrors modules/sast/run.sh's own header exactly, per this
# ticket's instruction to reuse the proven per-module pattern):
# `scan_dispatch sca` does a plain `source` of this file, never a subprocess,
# so it inherits every already-set variable of the calling scan_main
# invocation - SCOURSH_RUN_DIR, SCOURSH_SCAN_ROOT_ID, SCOURSH_PATH_ROOT,
# SCOURSH_JOBS, SCOURSH_FAIL_ON, SCOURSH_MIN_CONFIDENCE,
# SCOURSH_REDACT_SECRETS, _SCAN_RESOLVED_PATH, SCAN_FLAGS,
# CHECKS_REGISTRY_SETS, CHECKS_LAST_SELECTED_IDS - and every lib/*.sh
# function, all already sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, exactly as
# modules/sast/run.sh documents for itself.
#
# THIS FILE IS SHARED ACROSS EVERY SCA ECOSYSTEM TICKET (this ticket's own
# instruction): if a sibling ecosystem (Python, Go, ...) lands its own
# engine.sh alongside modules/sca/engine.sh, its own run function is called
# from _sca_run_module below, next to _sca_npm_run - do not fork this file
# per ecosystem.
#
# shellcheck shell=bash
# shellcheck source=modules/sca/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"

_sca_npm_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_tree "$path"
}

# _sca_py_run - the Python sibling ecosystem this file's own header
# anticipated ("its own run function is called from _sca_run_module below,
# next to _sca_npm_run"): requirements.txt/poetry.lock/Pipfile.lock, added by
# the ticket that shipped modules/sca/engine.sh's section 10.  Always run
# AFTER _sca_npm_run below - sca_scan_python_tree's own header comment
# documents relying on sca_scan_tree (npm) having already, unconditionally,
# recorded the module-level coverage_reduction facts (db-absent,
# single_worker, gate-not-wired) so this pass does not duplicate them.
_sca_py_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_python_tree "$path"
}

_sca_run_module() {
  # No check-registry gate here the way modules/sast/run.sh has one: SCA is
  # a table lookup, not a pattern-rule engine (this ticket's own framing),
  # so it has no `modules/sca/rules/*.rules` to be empty or non-empty - it
  # always attempts a scan and reports its own real reason
  # (no_advisories_db_on_disk) when there is nothing to match against,
  # exactly as sca_scan_tree's own header documents.
  _sca_npm_run
  _sca_py_run

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_sca_run_module
