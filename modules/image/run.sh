#!/usr/bin/env bash
# modules/image/run.sh - the container-image-scanning module entry point
# (IMG-01, data/scoursh-image-scan-design/report.md §3.2's exact integration
# cost table and §5.3's IMG-01 row; wired to real acquisition by IMG-03).
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
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  IMG-01 shipped
# the module-foundation skeleton: it resolves the operator-declared --image
# id, writes the image-id coverage cell (rules/RULE-FORMAT.md §9.5.1) and
# records why nothing was examined.  IMG-03 (this ticket's own scope, on top
# of IMG-02's acquire.sh) is the FIRST to actually resolve --image's source,
# open it, extract /etc/os-release, pick a per-release advisory ecosystem
# key (Alpine-only in v1; report.md §2.4/D2) and gate on whether
# data/advisories.db has any row for it.  It still ships NO distro
# enumerator (no apk/dpkg/rpm package-DB parser - IMG-04/IMG-07) and NO
# comparator (IMG-05/IMG-08) - there is no `modules/image/distro/*.sh` on
# disk yet, so even a run that resolves an ecosystem the database DOES
# cover ends in a declared coverage_reduction rather than a package finding,
# exactly the state modules/dast/'s and modules/network/'s own dispatch were
# in before their first real check landed.
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

  # IMG-03: the first real consumer of modules/image/acquire.sh
  # (acquire.sh's own header names this ticket explicitly). IMG-04/IMG-05
  # (apk enumeration and the version comparator) still do not exist, so
  # even a fully successful resolve/open/parse/gate walk below ends in a
  # coverage_reduction rather than a package finding - report.md §5.3's
  # scope line for this ticket.
  local kind='' path='' ref='' origin=''
  local ecosystem='' distro_id='' distro_version=''
  local rc=0

  image_source_resolve "$image_id" "$source" || rc=$?
  if (( rc != 0 )); then
    run_record coverage_reduction "module=image reason=image_source_unresolved image=$image_id - no config/images.conf record named '$image_id' and no --source override was given (rules/RULE-FORMAT.md §9.6.8), so no image could be opened."
    run_record coverage_gap "image scanning examined nothing for image '$image_id': its source could not be resolved - no config/images.conf record and no --source override. A clean result here is the absence of a test, not the absence of a problem."
  else
    kind=$_IMAGE_SRC_KIND
    path=$_IMAGE_SRC_PATH
    ref=$_IMAGE_SRC_REF
    origin=$_IMAGE_SRC_ORIGIN
    run_record notes "module=image image=$image_id source_kind=$kind source_path=$path source_origin=$origin"

    rc=0
    image_open "$kind" "$path" "$ref" || rc=$?
    if (( rc != 0 )); then
      local open_reason=${_IMAGE_REFUSE_REASON:-}
      [[ -n $open_reason ]] || open_reason=archive_unreadable
      run_record coverage_reduction "module=image reason=image_source_unreadable image=$image_id detail=$open_reason - the image source at '$path' ($kind) could not be opened."
      run_record coverage_gap "image scanning examined nothing for image '$image_id': its source could not be opened ($open_reason). A clean result here is the absence of a test, not the absence of a problem."
    else
      # A dedicated scratch directory, released unconditionally below -
      # image_collect_metadata is the module's one acquisition entry point
      # (acquire.sh's own header) and asks for ONLY the two os-release
      # candidate paths, never the full IMAGE_METADATA_PATHS default: apk/
      # dpkg enumeration is IMG-04/IMG-07's scope, not this ticket's, and
      # extracting those paths now would claim a coverage this module does
      # not have yet.
      local osdir
      osdir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/scoursh-image-osrelease.XXXXXX")
      chmod 700 "$osdir" 2>/dev/null || true
      image_collect_metadata "$kind" "$path" "$osdir" etc/os-release usr/lib/os-release >/dev/null

      local osrel=''
      if [[ -r $osdir/etc/os-release ]]; then
        osrel=$osdir/etc/os-release
      elif [[ -r $osdir/usr/lib/os-release ]]; then
        osrel=$osdir/usr/lib/os-release
      fi

      rc=0
      if [[ -z $osrel ]]; then
        rc=1
        _IMAGE_DISTRO_REASON=no_os_release
      else
        image_distro_ecosystem_resolve "$osrel" || rc=$?
      fi

      if (( rc != 0 )); then
        # report.md §4.3: Alpine advisories are keyed PER RELEASE
        # (Alpine:v3.18 != Alpine:v3.19), so with no resolved release there
        # is no ecosystem to look up - and guessing "latest" would produce
        # a false NEGATIVE on an older image, the direction that reads as a
        # pass. Declared, never guessed.
        run_record coverage_reduction "module=image reason=distro_release_unknown image=$image_id detail=${_IMAGE_DISTRO_REASON:-no_os_release} - /etc/os-release (and usr/lib/os-release) is missing or unparseable in this image, so no advisory ecosystem could be picked."
        run_record coverage_gap "image scanning examined nothing for image '$image_id': its distro release could not be determined from /etc/os-release. A clean result here is the absence of a test, not the absence of a problem."
      else
        ecosystem=$_IMAGE_DISTRO_ECOSYSTEM
        distro_id=$_IMAGE_OS_RELEASE_ID
        distro_version=$_IMAGE_OS_RELEASE_VERSION_ID
        run_record notes "module=image image=$image_id distro_id=$distro_id distro_version=$distro_version ecosystem=$ecosystem"

        # data/advisories.db reuse (report.md §2.3/§4.2): the SAME file and
        # the SAME db_lookup_exact modules/sca/ already uses, keyed on this
        # image's own resolved ecosystem rather than "is there a database
        # at all" - a db that covers Alpine:v3.19 says nothing about an
        # Alpine:v3.18 image.
        if ! image_ecosystem_known "$ecosystem"; then
          image_report_no_advisory_db "$image_id" "$ecosystem"
          # SCOURSH_EXIT_INPUT (4, docs/FOUNDATION.md tension 14's
          # per-module required-inputs table) when `image` was the
          # selected command, mirroring modules/sca/run.sh's own gate
          # verbatim - `input` is scan_main's own local, reached through
          # the sourced-not-subprocess dynamic-scoping contract, so a
          # standalone `all` run degrades this to a declared skip instead
          # (the same table's other row).
          if [[ ${SCAN_COMMAND:-image} == image ]]; then
            # shellcheck disable=SC2034
            input=1
          fi
        else
          run_record coverage_reduction "module=image reason=no_distro_enumerator_on_disk_yet image=$image_id ecosystem=$ecosystem - data/advisories.db has rows for $ecosystem, but modules/image/ ships no apk/dpkg/rpm package-DB parser or comparator yet (IMG-04/IMG-05; data/scoursh-image-scan-design/report.md §5.3), so no package was looked up."
          run_record coverage_gap "image scanning examined nothing for image '$image_id': the advisory database covers $ecosystem, but no distro enumerator or comparator exists yet to match installed packages against it. A clean result here is the absence of a test, not the absence of a problem."
        fi
      fi
      erase_dir "$osdir"
    fi
  fi

  # docs/STEP7-STATE-PLAN.md STATE-02: reached only when the work above
  # returns without dying - the identical reasoning modules/dast/run.sh's
  # and modules/network/run.sh's own comments give.
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
