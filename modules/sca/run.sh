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
# PYTHON AND JAVA BOTH DIVERGED FROM THAT PLAN, DELIBERATELY, AND GO WENT
# FURTHER STILL - each is its own correction, added once each ticket landed
# after the paragraph above was written.  Rather than folding a third or
# fourth ecosystem into `sca_scan_tree` itself, Python shipped a sibling
# function, `sca_scan_python_tree` (modules/sca/engine.sh), called from its
# own `_sca_py_run` below; Java likewise shipped `sca_scan_java_tree`, called
# from `_sca_java_run`; and Go shipped `sca_go_scan_tree` in its OWN file,
# modules/sca/go_engine.sh, called from `_sca_go_run` - all three to avoid
# touching `sca_scan_tree`'s already-tested npm/Ruby/PHP code path.  If a
# further ecosystem lands its own entry point, its run function is likewise
# called from _sca_run_module below, next to these four - do not fork this
# file per ecosystem.
#
# THE COST OF THAT DIVERGENCE WAS REAL, AND IS NOW PAID OFF RATHER THAN
# RESTATED.  Each of the four walks accumulated unknown-version counts in its
# OWN local table and emitted its OWN roll-up, so the collision the paragraph
# above avoided for npm/Ruby/PHP simply reappeared BETWEEN the walks: a run
# with an npm gap and a Python one emitted two SCA-COV-UNKNOWN_VERSION-01
# findings with one fingerprint, findings_merge's dedup kept one, and the
# operator was told a smaller number than the truth (measured 1 reported
# against 4 real on tests/fixtures/sca/mixed-four-ecosystems/).  Every
# sibling function's header used to record that as a stated, filed
# follow-up; it is fixed instead.  modules/sca/engine.sh section 8a holds one
# shared accumulator, `_sca_run_module` below brackets its four calls with
# `sca_rollup_begin`/`sca_rollup_flush`, and each walk still self-flushes when
# called standalone, so the unit tests that call each entry point on its own
# are unaffected.  A fifth ecosystem needs no new roll-up code at all: call
# `sca_rollup_add <ecosystem>` and end with `_sca_rollup_autoflush`.
#
# ONE ORDERING CONSTRAINT SURVIVES, AND IT IS NARROWER THAN IT WAS.
# `_sca_npm_run` (and so `sca_scan_tree`) must still run before the other
# three, because `sca_scan_tree` is the only walk that records the
# module-level `single_worker_no_parallel_scan_yet` coverage_reduction and
# the others deliberately skip it rather than duplicate it.  The db-absent
# announcement is NO LONGER part of that constraint: it belonged to
# `sca_scan_tree` and `sca_go_scan_tree` individually, which is why a plain
# `sca` run recorded the same fact twice while Python and Java recorded
# nothing, and it now belongs to `_sca_run_module` itself - see its own
# comment.  Go remains called last purely for a stable emission order.
#
# shellcheck shell=bash
# -x back-edge cut: modules/sca/engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/engine.sh"
# docs/STEP7-STATE-PLAN.md STATE-06: see modules/sast/run.sh's own comment on
# why this is sourced directly here (rather than from modules/sast/engine.sh)
# AND why it is guarded (a fixture root with no lib/ sibling makes the
# unconditional form fail to even locate the file).
if [[ -z ${SCOURSH_DIFF_SOURCED:-} ]]; then
  # shellcheck source=lib/diff.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/diff.sh"
fi
# php_engine.sh is also sourced transitively by engine.sh itself (guarded,
# see both files' own headers); sourced again here, explicitly, purely so
# this entry point stays self-documenting about which ecosystems it covers -
# modules/sast/run.sh's own explicit source of history.sh alongside
# engine.sh is the same convention.
# -x back-edge cut: modules/sca/php_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
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

# _sca_record_coverage CELL ID... - docs/STEP7-STATE-PLAN.md STATE-02:
# path-root coverage (tension 12's frozen table lists SCA under path-root,
# the same scope SAST/history/IaC use) for a list of SCA check ids that have
# already run to completion.  Unlike modules/sast/engine.sh's
# sast_record_coverage, SCA ships no `*.rules` registry at all (it is a
# table lookup against data/advisories.db, not a pattern-rule engine - this
# file's own header), so there is no rule RECORD to hash the way
# `records_digest` does for a pattern check - matching every SCA finding
# already shipped today, which likewise never calls `finding_set
# rule_digest` (modules/sca/engine.sh's _sca_emit_finding).
#
# `rule_digest` is still REQUIRED to be non-empty here, though: unlike a
# finding (which carries no `rule_digest` field in tension 12's frozen shape
# at all), a `covered_checks` ENTRY does, and lib/state.sh's own loader
# (STATE-01, `_state_validate`) rejects the WHOLE state file as malformed
# when one is empty - measured directly, not assumed: an empty string here
# failed `state_load_file` with "missing rule_digest" and made every OTHER
# module's coverage in the same run unreadable too.  A stable hash of the
# check id itself is what is used instead: SCA's checks are defined in code
# (this file, modules/sca/engine.sh and its siblings), not in an editable
# rule record, so there is no "the rule changed" event to detect the way
# tension 12's own rule_digest note describes for a pattern check - the id
# hash is constant for as long as the id itself is, which is the accurate
# statement to make here rather than an empty placeholder the loader cannot
# accept.  This does not touch lib/state.sh's own validation, which is
# reused exactly as STATE-01 shipped it.
_sca_record_coverage() {
  declare -F state_add_covered >/dev/null 2>&1 || return 0
  local cell=$1
  shift
  local id digest
  for id in "$@"; do
    digest=$(printf '%s' "$id" | sha256_of)
    state_add_covered "$id" "$digest" path-root "$cell"
  done
  return 0
}

# _sca_npm_run - npm/yarn/pnpm, RubyGems (Gemfile.lock) AND, as of the
# PHP/Composer ticket, composer.lock: all three live inside the single
# shared sca_scan_tree call, per the header above.
_sca_npm_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_scan_tree "$path"
  _sca_record_coverage "$SCOURSH_PATH_ROOT" \
    SCA-NPM-VULNERABLE_DEP-01 SCA-RUBY-VULNERABLE_DEP-01 SCA-PHP-VULNERABLE_DEP-01
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
  _sca_record_coverage "$SCOURSH_PATH_ROOT" SCA-PY-VULNERABLE_DEP-01
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
  _sca_record_coverage "$SCOURSH_PATH_ROOT" SCA-JAVA-VULNERABLE_DEP-01
}

# _sca_go_run - Go (go.mod/go.sum), the fourth call and the first whose
# parser lives in its own file (modules/sca/go_engine.sh).  Unlike
# _sca_py_run and _sca_java_run it carries no "must run after _sca_npm_run"
# requirement - sca_go_scan_tree does its own db-absent check - but it is
# kept last for a stable emission order.  See the header above.
_sca_go_run() {
  local path=${_SCAN_RESOLVED_PATH:-.}
  sca_go_scan_tree "$path"
  _sca_record_coverage "$SCOURSH_PATH_ROOT" SCA-GO-VULNERABLE_DEP-01
}

_sca_run_module() {
  # No check-registry gate here the way modules/sast/run.sh has one: SCA is
  # a table lookup, not a pattern-rule engine (the npm ticket's own framing),
  # so it has no `modules/sca/rules/*.rules` to be empty or non-empty.
  #
  # THE ADVISORY-DATABASE GATE IS THIS MODULE'S REQUIRED-INPUT CHECK, and it
  # is decided here, once, rather than inside each walk.  `data/advisories.db`
  # is what every ecosystem is matched against; without it not one dependency
  # is examined, in any ecosystem.  The shipped behaviour was to let each walk
  # discover that for itself and return - two of the four said so (twice, on
  # every run, whatever ecosystems the tree held), the other two said nothing,
  # and the run then exited 0 with zero findings and an empty `checks_run`.
  # An operator reading that could not tell "it did not look" from "it looked
  # and found nothing", which for a dependency scanner is the whole product.
  #
  # WHY EXIT 4 AND WHY ONLY WHEN `sca` WAS SELECTED (docs/FOUNDATION.md
  # tension 14).  The precedence list is frozen and nothing new is minted
  # here: 4 is "missing required input", and tension 14's own "Required
  # inputs are per module" table already assigns it to exactly this shape -
  # `dast` exits 4 for a missing scope.conf, `posture` for a missing
  # posture.conf, and (tension 20) `--paranoid` exits 4 when no connection
  # observer is available on the host.  5 would be wrong: it is reserved for
  # UNPLANNED incompleteness (circuit breaker, request budget, a mid-flight
  # abort), `incomplete_reason` non-empty is its exact predicate, and this run
  # did not fail mid-flight - it never had the input it needed.  The CI
  # contract tension 14 documents settles it too: "5 means investigate the
  # target or the run and re-scan; 2/3/4 mean fix the invocation or the
  # config", and the fix here is to populate the database.
  #
  # Under `all` the same table's other row governs - "a module whose inputs
  # are absent is skipped with a run.json reason" - so the reduction and the
  # finding are still recorded and the exit code is untouched, because the
  # other modules did do what they were asked.  Both directions are pinned in
  # tests/suites/sca.sh, because the naive fix for each is the other's bug.
  if ! sca_advisories_db_readable; then
    sca_report_no_advisories_db
    if [[ ${SCAN_COMMAND:-sca} == sca ]]; then
      # Sets scan_main's OWN `input` local through the sourced-not-subprocess
      # dynamic-scoping contract scan.sh's header documents - the identical
      # mechanism modules/sast/engine.sh's sast_evaluate_gate uses for `gate`,
      # and for the identical reason: scan_exit_code's precedence table is the
      # one place an exit code is decided, and a module must feed it rather
      # than exit on its own.  A plain assignment with no `local` and no
      # `export` is deliberate; shellcheck cannot see that caller across the
      # source boundary.
      # shellcheck disable=SC2034
      input=1
    fi
  else
    # sca_rollup_begin/sca_rollup_flush (modules/sca/engine.sh section 8a)
    # bracket the four walks so their unknown-version counts land in ONE
    # SCA-COV-UNKNOWN_VERSION-01 finding rather than one per walk.  Four
    # roll-ups in a run do not merely read oddly: the check's fingerprint has
    # no ecosystem component (tension 5's SCA profile is ecosystem/package/
    # advisory_id, all empty for a roll-up), so they collide and
    # findings_merge's dedup keeps exactly one - which is how a repository
    # with npm and Python gaps got told about one of them.
    #
    # _sca_npm_run (sca_scan_tree) covers npm, RubyGems AND PHP/Composer in
    # one call; see the header above for why Ruby and PHP joined that call
    # while Python, Java and Go did not.  That grouping is unchanged and now
    # matters less, since every walk feeds the same accumulator either way.
    sca_rollup_begin
    _sca_npm_run
    _sca_py_run
    _sca_java_run
    _sca_go_run
    sca_rollup_flush
  fi

  findings_merge "$SCOURSH_RUN_DIR"
  derive_findings "$SCOURSH_RUN_DIR"
  # docs/STEP7-STATE-PLAN.md STATE-06: classify (tension 11 stage 5) runs
  # strictly after derive (4) and before the gate (7) - lib/diff.sh's own
  # header states the frozen stage order this call site follows.
  diff_classify_run "$SCOURSH_RUN_DIR"
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
