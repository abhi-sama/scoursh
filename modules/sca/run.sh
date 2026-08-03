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
# THIS FILE IS SHARED ACROSS EVERY SCA ECOSYSTEM TICKET (the npm ticket's own
# instruction, still honoured): a sibling ecosystem's lockfile/manifest parser
# lands in modules/sca/engine.sh rather than forking this file.
#
# ONE SCAN CALL PER "family", NOT ONE PER ECOSYSTEM - a correction of this
# file's own original plan, recorded here rather than silently diverging from
# it: this header used to say a second ecosystem's own run function would be
# called below "next to _sca_npm_run".  The Ruby ticket found that plan
# unsafe to follow literally for npm+Ruby: SCA-COV-UNKNOWN_VERSION-01's
# fingerprint carries no ecosystem/package/advisory_id (every ecosystem's
# roll-up hashes identically), so two separate sca_scan_tree calls - one per
# ecosystem - would emit two findings that collide on one fingerprint, and
# findings_merge's dedup would silently drop whichever ecosystem lost the
# sort instead of merging their counts.  `sca_scan_tree`
# (modules/sca/engine.sh) therefore walks npm AND RubyGems lockfiles itself,
# in one call, sharing one `unknown_count` table - see that function's own
# header for the full reasoning.
#
# PYTHON AND JAVA BOTH DIVERGED FROM THAT PLAN, DELIBERATELY - each is its own
# correction, added once each ticket landed after the paragraph above was
# written.  Rather than folding a third or fourth ecosystem into
# `sca_scan_tree` itself, Python shipped a sibling function,
# `sca_scan_python_tree` (modules/sca/engine.sh), called from its own
# `_sca_py_run` below, and Java (this ticket) likewise shipped
# `sca_scan_java_tree`, called from its own `_sca_java_run` below - both to
# avoid touching `sca_scan_tree`'s already-tested npm/Ruby code path.  Each
# sibling function's own header states this plainly: a run with BOTH an
# npm/Ruby unknown-version case AND a Python or Java one emits a SEPARATE
# SCA-COV-UNKNOWN_VERSION-01 finding per ecosystem-scan call rather than one
# truly-merged roll-up - the same fingerprint-collision exposure the
# paragraph above describes, accepted as a stated, filed follow-up rather
# than re-touching the tested npm/Ruby path.  `_sca_run_module` below MUST
# keep running `_sca_npm_run` (and so `sca_scan_tree`) before `_sca_py_run`
# and `_sca_java_run`: both `sca_scan_python_tree` and `sca_scan_java_tree`
# deliberately skip the db-absent check and the two module-level
# coverage_reduction facts that `sca_scan_tree` already records
# unconditionally, relying on that ordering to avoid duplicating them (see
# each function's own header).  If a further ecosystem (Go, PHP, ...) lands
# its own engine.sh entry point, its own run function is likewise called from
# _sca_run_module below, next to these three - do not fork this file per
# ecosystem.
#
# shellcheck shell=bash
# shellcheck source=modules/sca/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"

# _sca_npm_run - npm/yarn/pnpm AND RubyGems (Gemfile.lock): both live inside
# the single shared sca_scan_tree call, per the header above.
_sca_npm_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_tree "$path"
}

# _sca_py_run - the Python sibling ecosystem this file's own header
# anticipated ("its own run function is called from _sca_run_module below,
# next to _sca_npm_run"): requirements.txt/poetry.lock/Pipfile.lock, added by
# the ticket that shipped modules/sca/engine.sh's section 10.  Always run
# AFTER _sca_npm_run below - sca_scan_python_tree's own header comment
# documents relying on sca_scan_tree (npm+Ruby) having already,
# unconditionally, recorded the module-level coverage_reduction facts
# (db-absent, single_worker, gate-not-wired) so this pass does not duplicate
# them.
_sca_py_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_python_tree "$path"
}

# _sca_java_run - Java (pom.xml/build.gradle), landed by this ticket alongside
# _sca_npm_run and _sca_py_run above - see modules/sca/engine.sh's own header
# for what each ecosystem covers and does not.  Same "always after
# _sca_npm_run" ordering requirement as _sca_py_run, for the same reason
# (sca_scan_java_tree's own header documents relying on sca_scan_tree having
# already recorded the module-level coverage_reduction facts).
_sca_java_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_java_tree "$path"
}

_sca_run_module() {
  # No check-registry gate here the way modules/sast/run.sh has one: SCA is
  # a table lookup, not a pattern-rule engine (the npm ticket's own framing),
  # so it has no `modules/sca/rules/*.rules` to be empty or non-empty - it
  # always attempts a scan and reports its own real reason
  # (no_advisories_db_on_disk) when there is nothing to match against,
  # exactly as sca_scan_tree's own header documents.
  #
  # _sca_npm_run (sca_scan_tree) covers npm AND RubyGems in one call; see the
  # header above for why Ruby joined that call while Python and Java did not.
  _sca_npm_run
  _sca_py_run
  _sca_java_run

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_sca_run_module
