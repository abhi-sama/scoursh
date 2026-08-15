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
# lands in modules/sca/engine.sh (or, for PHP, its own
# modules/sca/php_engine.sh - see below) rather than forking this file.
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
# (modules/sca/engine.sh) therefore walks npm, RubyGems AND, as of the
# PHP/Composer ticket, composer.lock (parsed by the sibling
# modules/sca/php_engine.sh, sourced below) itself, in one call, sharing one
# `unknown_count` table - see that function's own header for the full
# reasoning.  A future ecosystem sharing this same roll-up is expected to
# extend `sca_scan_tree` itself the same way, not add a fourth call here.
#
# PYTHON AND JAVA BOTH DIVERGED FROM THAT PLAN, DELIBERATELY - each is its own
# correction, added once each ticket landed after the paragraph above was
# written.  Rather than folding a third or fourth ecosystem into
# `sca_scan_tree` itself, Python shipped a sibling function,
# `sca_scan_python_tree` (modules/sca/engine.sh), called from its own
# `_sca_py_run` below, and Java likewise shipped `sca_scan_java_tree`,
# called from its own `_sca_java_run` below - both to avoid touching
# `sca_scan_tree`'s already-tested npm/Ruby/PHP code path.  Each sibling
# function's own header states this plainly: a run with BOTH an
# npm/Ruby/PHP unknown-version case AND a Python or Java one emits a
# SEPARATE SCA-COV-UNKNOWN_VERSION-01 finding per ecosystem-scan call rather
# than one truly-merged roll-up - the same fingerprint-collision exposure the
# paragraph above describes, accepted as a stated, filed follow-up rather
# than re-touching the tested npm/Ruby/PHP path.  `_sca_run_module` below
# MUST keep running `_sca_npm_run` (and so `sca_scan_tree`) before
# `_sca_py_run` and `_sca_java_run`: both `sca_scan_python_tree` and
# `sca_scan_java_tree` deliberately skip the db-absent check and the two
# module-level coverage_reduction facts that `sca_scan_tree` already records
# unconditionally, relying on that ordering to avoid duplicating them (see
# each function's own header).  If a further ecosystem (Go, ...) lands its
# own engine.sh entry point, its own run function is likewise called from
# _sca_run_module below, next to these three - do not fork this file per
# ecosystem.
#
# GO IS THE FOURTH SUCH CALL, AND IT IS FULLY SELF-CONTAINED - the one way
# it differs from Python and Java above, recorded here so the ordering
# constraint is not over-applied to it.  Go went further than PHP did and
# landed its parser in its OWN file, modules/sca/go_engine.sh (go.mod/go.sum
# parsing, SCA-GO-VULNERABLE_DEP-01), sourced below next to
# modules/sca/engine.sh, exactly as this file's original header invited
# ("if a further ecosystem (Go, ...) lands its own ... entry point, its own
# run function is likewise called from _sca_run_module below").
# `sca_go_scan_tree` (modules/sca/go_engine.sh) does run its OWN
# data/advisories.db-readable check and emits its own
# `reason=no_advisories_db_on_disk ecosystem=Go` coverage_reduction, so
# unlike `_sca_py_run` and `_sca_java_run` it does NOT depend on
# `_sca_npm_run` having gone first.  It is still called last below, purely
# for a stable emission order.  It shares the roll-up exposure the
# paragraphs above describe: a run with both an npm/Ruby/PHP (or Python, or
# Java) unknown-version case and a Go one emits a SEPARATE
# SCA-COV-UNKNOWN_VERSION-01 per ecosystem-scan call - the same stated,
# filed follow-up, not a new one.
#
# shellcheck shell=bash
# shellcheck source=modules/sca/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"
# php_engine.sh is also sourced transitively by engine.sh itself (guarded,
# see both files' own headers); sourced again here, explicitly, purely so
# this entry point stays self-documenting about which ecosystems it covers -
# modules/sast/run.sh's own explicit source of history.sh alongside
# engine.sh is the same convention.
# shellcheck source=modules/sca/php_engine.sh
source "${BASH_SOURCE[0]%/*}/php_engine.sh"
# go_engine.sh guards its own engine.sh source the same way, so the order of
# these three lines does not matter; it is sourced explicitly here for the
# same self-documenting reason as php_engine.sh above.
# shellcheck source=modules/sca/go_engine.sh
source "${BASH_SOURCE[0]%/*}/go_engine.sh"
# The SAST engine is sourced for exactly ONE function, sast_evaluate_gate,
# called at the end of _sca_run_module below - none of its pattern-rule
# machinery is used or wanted here, since SCA is a table lookup rather than a
# rule engine.  This is a relative source across module directories, the same
# shape modules/iac/parse.sh already uses to reach the same file, and it is
# what makes the gate REACHABLE: modules/sast/run.sh sources that engine as
# its own sibling and modules/iac/run.sh gets it transitively through
# parse.sh, but this module had no path to it at all, so adding the call
# below without this line fails a standalone `scan.sh sca` run outright -
# measured, `sast_evaluate_gate: command not found`, status 127.
# engine.sh carries the standard sourced-once guard, so a combined
# `scan.sh all` run that dispatches sast before sca in the same shell sources
# it once and re-uses it here.
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"

# _sca_npm_run - npm/yarn/pnpm, RubyGems (Gemfile.lock) AND, as of the
# PHP/Composer ticket, composer.lock: all three live inside the single
# shared sca_scan_tree call, per the header above.
_sca_npm_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_tree "$path"
}

# _sca_py_run - the Python sibling ecosystem this file's own header
# anticipated ("its own run function is called from _sca_run_module below,
# next to _sca_npm_run"): requirements.txt/poetry.lock/Pipfile.lock, added by
# the ticket that shipped modules/sca/engine.sh's section 10.  Always run
# AFTER _sca_npm_run below - sca_scan_python_tree's own header comment
# documents relying on sca_scan_tree (npm+Ruby+PHP) having already,
# unconditionally, recorded the module-level coverage_reduction facts
# (db-absent, single_worker) so this pass does not duplicate them.
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

# _sca_go_run - Go (go.mod/go.sum), the fourth call and the first whose
# parser lives in its own file (modules/sca/go_engine.sh).  Unlike
# _sca_py_run and _sca_java_run it carries no "must run after _sca_npm_run"
# requirement - sca_go_scan_tree does its own db-absent check - but it is
# kept last for a stable emission order.  See the header above.
_sca_go_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_go_scan_tree "$path"
}

_sca_run_module() {
  # No check-registry gate here the way modules/sast/run.sh has one: SCA is
  # a table lookup, not a pattern-rule engine (the npm ticket's own framing),
  # so it has no `modules/sca/rules/*.rules` to be empty or non-empty - it
  # always attempts a scan and reports its own real reason
  # (no_advisories_db_on_disk) when there is nothing to match against,
  # exactly as sca_scan_tree's own header documents.
  #
  # _sca_npm_run (sca_scan_tree) covers npm, RubyGems AND PHP/Composer in
  # one call; see the header above for why Ruby and PHP joined that call
  # while Python, Java and Go did not.
  _sca_npm_run
  _sca_py_run
  _sca_java_run
  _sca_go_run

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # sast_evaluate_gate (modules/sast/engine.sh, sourced at the top of this
  # file) is called here rather than reimplemented as an "sca_evaluate_gate":
  # nothing in its body is SAST-specific despite the prefix - it re-reads
  # $rundir/findings.fields, which by this point holds THIS run's merged and
  # derived findings whatever module produced them, and applies the
  # severity/confidence/suppression/fail-on-new filter chain with no module
  # test anywhere in it.  modules/iac/run.sh reached the same conclusion for
  # the same reason; a third copy of that filter chain would be one more place
  # for `--fail-on` to drift per module, which is exactly how this module came
  # to exit 0 on critical findings in the first place.  Position matters: it
  # must run AFTER derive_findings, so composites and statuses are settled
  # before the gate reads them, and BEFORE report_all, so run.json records the
  # real gate result instead of lib/report.sh's "not-evaluated" default.  It
  # sets scan_main's own `gate` local through the sourced-not-subprocess
  # dynamic-scoping contract scan.sh's header documents, which is what turns a
  # tripped gate into SCOURSH_EXIT_GATE.
  sast_evaluate_gate "$SCOURSH_RUN_DIR"
  report_all "$SCOURSH_RUN_DIR"
}

_sca_run_module
