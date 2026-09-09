#!/usr/bin/env bash
# modules/image/run.sh - the container-image-scanning module entry point
# (IMG-01, data/scoursh-image-scan-design/report.md §3.2's exact integration
# cost table and §5.3's IMG-01 row).
#
# Contract (modules/sast/run.sh's own header, reused verbatim by every
# module in this tree): scan.sh's `scan_dispatch image` does a plain
# `source` of this file, never a subprocess, so it inherits every
# already-set variable of the calling scan_main invocation -
# SCOURSH_RUN_DIR, SCAN_FLAGS, CHECKS_REGISTRY_SETS,
# CHECKS_LAST_SELECTED_IDS - and every lib/*.sh function, all already
# sourced by scan.sh itself.
#
# UNLIKE lib/*.sh, this file has no "sourced once" guard: `scan_dispatch` is
# meant to run its module's work EVERY time it is called, and more than one
# scan_main invocation can happen in one process (tests/suites/scan.sh calls
# it repeatedly).  Only modules/image/engine.sh, a pure function library,
# gets the standard sourced-once guard - the identical sast/dast/network
# split.
#
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  IMG-01 is the
# module-foundation ticket ONLY: it resolves the operator-declared `--image`
# id, writes the `image-id` coverage cell (rules/RULE-FORMAT.md §9.5.1) and
# records why nothing was examined.  It ships NO acquisition (no
# docker-save/OCI-layout reader - IMG-02), NO distro enumerator (no
# apk/dpkg/rpm package-DB parser - IMG-04/IMG-07), and NO comparator
# (IMG-05/IMG-08) - there is no `modules/image/acquire.sh` or
# `modules/image/distro/*.sh` on disk yet, so a run is a clean, honestly
# declared no-op over whichever image id it resolved, exactly the state
# modules/dast/'s and modules/network/'s own dispatch were in before their
# first real check landed.
#
# THE HONESTY THIS FILE OWES ITS READER IS ITS ACTUAL DELIVERABLE.  A run
# that does nothing must not leave a report that reads like a clean scan -
# every no-op below is recorded as a `coverage_reduction` or a
# `coverage_gap` in the run's own meta, which lib/report.sh renders into
# run.json AND into the limitations section of the markdown, HTML and audit
# reports - the surfaces a consumer actually reads, never only an internal
# record.
#
# shellcheck shell=bash
# shellcheck source=modules/image/engine.sh
source "${BASH_SOURCE[0]%/*}/engine.sh"
# lib/diff.sh is sourced directly here rather than from engine.sh for the
# reason modules/network/run.sh's own copy of this records: a future
# tests/suites/image-<name>.sh distro-script suite will source engine.sh or
# a single distro script directly, never this file, so confining the edge
# here keeps their shellcheck -x cost unchanged.  Guarded because a fixture
# root with no lib/ sibling makes the unconditional form fail to even
# locate the file, before its own internal guard could no-op it.
if [[ -z ${SCOURSH_DIFF_SOURCED:-} ]]; then
  # shellcheck source=lib/diff.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/diff.sh"
fi

# `_image_record_coverage IMAGE_ID SINCE_LINE` - docs/STEP7-STATE-PLAN.md
# STATE-02 applied to this module: `image-id` coverage
# (docs/FOUNDATION.md tension 12's frozen table) for every IMAGE-* check
# that completed since line SINCE_LINE of the run-wide `checks_run` fact.
# Byte-identical shape to modules/network/run.sh's own
# `_net_record_coverage`, with `target` swapped for `image-id` and the id
# prefix for IMAGE's.  INERT today - modules/image/ ships no check registry
# at all (IMG-01), so `checks_run` never carries an `IMAGE-*` line for this
# to find - kept for structural parity, so it is already correct the day
# the first `modules/image/checks-<name>.rules` record lands (IMG-04+).
_image_record_coverage() {
  declare -F state_add_covered >/dev/null 2>&1 || return 0
  local image_id=$1 since=${2:-0}
  local line id set idx digest
  local -A seen=()
  while IFS= read -r line; do
    [[ -n $line && $line == IMAGE-* ]] || continue
    [[ -z ${seen[$line]:-} ]] || continue
    seen[$line]=1
    id=$line
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      idx=$(records_index_of_id "$set" "$id" 2>/dev/null) || continue
      digest=$(records_digest "$set" "$idx")
      state_add_covered "$id" "$digest" image-id "$image_id"
      break
    done
  done < <(run_facts checks_run | tail -n "+$(( since + 1 ))")
  return 0
}

_image_run_module() {
  # SCAN_FLAGS guard - see modules/dast/run.sh's and modules/network/run.sh's
  # own comment for why `declare -p` rather than `${SCAN_FLAGS+set}` is
  # load-bearing under `set -u` when this module is exercised without
  # scan.sh (tests/suites/image.sh sources this file directly to prove it
  # re-asserts the required-flag check for itself).
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()

  # scan.sh's own _SCAN_REQUIRED_FLAG map already refuses a missing --image
  # with exit 2 before dispatch is ever reached - this is a SECOND,
  # independent assertion rather than a duplicate, the identical "a gate
  # that only binds callers who already applied it is not a gate" argument
  # modules/dast/run.sh's and modules/network/run.sh's own comments make for
  # config_scope_require.
  local image_id=${SCAN_FLAGS[image]:-}
  [[ -n $image_id ]] || die "$SCOURSH_EXIT_USAGE" "'image' requires --image"
  local source=${SCAN_FLAGS[source]:-}

  # `--source` is accepted (scan.sh's own _SCAN_FLAG_KIND) but genuinely
  # unread beyond this notes line: IMG-02 is what teaches this module to
  # open a docker-save tarball or an OCI layout directory. Recording it now
  # costs nothing and means an operator who already scripted `--source` into
  # a CI job sees it acknowledged rather than silently ignored.
  SCOURSH_IMAGE_ID=$image_id
  SCOURSH_IMAGE_SOURCE=$source
  export SCOURSH_IMAGE_ID SCOURSH_IMAGE_SOURCE

  # image's coverage cell is `image-id`, the operator-declared STABLE id
  # (rules/RULE-FORMAT.md §9.5.1, report.md §3.4) - deliberately never the
  # image digest or tag, both of which change on every rebuild/release and
  # would put every finding in a fresh cell forever, destroying the diff
  # (report.md §3.4's own table).
  run_record notes "module=image image=$image_id source=${source:-<none>} coverage-scope=image-id cell=$image_id"

  local _image_checks_run_before
  _image_checks_run_before=$(run_facts checks_run | wc -l | tr -d '[:space:]')

  # No acquisition, no distro enumerator, no comparator exist on disk yet
  # (IMG-01's own scope) - so unlike modules/dast/run.sh's and
  # modules/network/run.sh's phase-table walk, there is nothing here to
  # attempt and no "present but gated by intensity" case to distinguish.
  # The single honest fact this run can state is that report.md's whole v1
  # pipeline (acquire -> enumerate -> compare) has not landed yet.
  run_record coverage_reduction "module=image reason=no_distro_enumerator_on_disk_yet image=$image_id - modules/image/ ships no acquisition code, no apk/dpkg/rpm package-DB parser and no comparator yet (IMG-01; data/scoursh-image-scan-design/report.md §5.3), so no layer was read and no package was looked up."
  run_record coverage_gap "image scanning examined nothing for image '$image_id': modules/image/ is registered but not yet built beyond this dispatch skeleton, so no layer, package or advisory was looked at - a clean result here is the absence of a test, not the absence of a problem."

  # docs/STEP7-STATE-PLAN.md STATE-02: reached only when the (currently
  # nonexistent) work above returns without dying - the identical reasoning
  # modules/dast/run.sh's and modules/network/run.sh's own comments give.
  _image_record_coverage "$image_id" "$_image_checks_run_before"

  # The same five calls, in the same order, that modules/sast/run.sh,
  # modules/iac/run.sh, modules/dast/run.sh, modules/cloud/aws/run.sh and
  # modules/network/run.sh all end with. They run even though this module
  # emitted nothing: findings_merge and derive_findings are no-ops over an
  # empty shard set, sast_evaluate_gate is what makes `--fail-on` apply to
  # image findings the moment a distro enumerator emits one, and report_all
  # is what puts the coverage records above in front of a reader. Skipping
  # them "because there is nothing to report" is exactly how a run with no
  # distro enumerator would end up with no report saying so.
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

_image_run_module
