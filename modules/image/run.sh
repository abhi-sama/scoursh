#!/usr/bin/env bash
# modules/image/run.sh - the container-image-scanning module entry point
# (IMG-01, data/scoursh-image-scan-design/report.md §3.2's exact integration
# cost table and §5.3's IMG-01 row; wired to real acquisition by IMG-03;
# wired to real apk enumeration + matching + the config-blob check, and so
# completing the v1 Alpine slice, by IMG-06; wired to real dpkg enumeration +
# matching, completing the Debian/Ubuntu slice, by IMG-09).
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
# WHAT HAS LANDED, ACROSS THREE TICKETS.  IMG-01 shipped the
# module-foundation skeleton: it resolves the operator-declared --image id,
# writes the image-id coverage cell (rules/RULE-FORMAT.md §9.5.1) and
# records why nothing was examined.  IMG-03 (on top of IMG-02's acquire.sh)
# was the FIRST to actually resolve --image's source, open it, extract
# /etc/os-release, pick a per-release advisory ecosystem key (Alpine-only in
# v1; report.md §2.4/D2) and gate on whether data/advisories.db has any row
# for it.  IMG-06 completes the v1 Alpine slice: it widens the metadata
# collected to include lib/apk/db/installed, wires modules/image/distro/
# apk.sh's enumerator+matcher (IMG-04/IMG-06) and apk_version.sh's
# comparator (IMG-05) into the branch that used to be a bare
# `no_distro_enumerator_on_disk_yet` reduction, and adds the two remaining
# v1 coverage checks report.md §4.1 lists
# (`IMAGE-COV-UNKNOWN_DISTRO-01`/`IMAGE-COV-LAYER_UNREADABLE-01`) plus the
# distro-agnostic `IMAGE-CFG-RUNS_AS_ROOT-01` config-blob check
# (modules/image/config.sh), which runs independently of the ecosystem
# branch below it.  IMG-09 completes the Debian/Ubuntu slice: it widens
# `image_distro_ecosystem_resolve` (modules/image/engine.sh) to resolve
# `debian`/`ubuntu` os-release IDs to their own OSV.dev ecosystem keys
# (`Debian:N`, `Ubuntu:XX.YY`), widens the metadata collected to also
# include `var/lib/dpkg/status`, and wires `modules/image/distro/dpkg.sh`'s
# enumerator+matcher (IMG-07/IMG-09) and `dpkg_version.sh`'s comparator
# (IMG-08) into a sibling branch of the ecosystem dispatch below, dispatched
# on the resolved distro `ID` rather than on the ecosystem string itself.
# rpm (IMG-12) is still out of scope here.
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
# prefix for IMAGE's.  Was INERT from IMG-01 through IMG-05 - no check ever
# reached `checks_run` for it to find - and is now live as of IMG-06,
# whose IMAGE-PKG-VULNERABLE_OS_PACKAGE-01/IMAGE-CFG-RUNS_AS_ROOT-01/
# IMAGE-COV-* checks are the first real `IMAGE-*` lines this function reads.
# `image-id` also had to be added to `lib/state.sh`'s own
# `_STATE_VALID_SCOPES` in this same change - see that file's own comment
# for why an inert call site with a value nobody had exercised yet still
# needed the register to already accept it.
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
      # IMG-06: the image config-blob check is distro-agnostic (report.md
      # §4.4: it reads the EFFECTIVE user across every merged base layer,
      # not any one Dockerfile) and runs unconditionally once the image is
      # open, independent of whether an ecosystem or apk database is ever
      # resolved below - an image whose distro this module cannot yet
      # identify (v1 is Alpine-only, report.md D2) still gets this check.
      image_check_root_user "$kind" "$path" "$image_id"

      # A dedicated scratch directory, released unconditionally below -
      # image_collect_metadata is the module's one acquisition entry point
      # (acquire.sh's own header). IMG-06 widened the wanted set from
      # IMG-03's original two os-release candidates to also ask for
      # lib/apk/db/installed; IMG-09 widens it again to also ask for
      # var/lib/dpkg/status, now that this module has a real dpkg enumerator
      # (IMG-07), comparator (IMG-08) and Debian/Ubuntu advisory ecosystem
      # (this ticket) to feed it to. Both package-manager paths are always
      # requested regardless of which distro's os-release this image turns
      # out to name - the ecosystem-dispatch branch below is what decides
      # which one is actually READ, and asking for both costs nothing (an
      # absent member is the ordinary case for a distro that does not carry
      # it, per acquire.sh's own "tar is the new grep" discipline).
      local metadir
      metadir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/scoursh-image-meta.XXXXXX")
      chmod 700 "$metadir" 2>/dev/null || true
      image_collect_metadata "$kind" "$path" "$metadir" etc/os-release usr/lib/os-release lib/apk/db/installed var/lib/dpkg/status >/dev/null

      # report.md §4.3's `layer_unreadable` reduction: any wanted path a
      # refusal stopped (an unreadable layer, or a malformed member) is a
      # coverage hole distinct from "this image simply does not carry that
      # path" (IMAGE_COLLECT_MISSING, the ordinary case, handled per-path
      # below with no reduction at all). Checked once, for every wanted
      # path in this one collect call, rather than per path - report.md's
      # own table says this reduction "carries count and total".
      if (( ${#IMAGE_COLLECT_REFUSED[@]} > 0 )); then
        image_report_layer_unreadable "$image_id" "${IMAGE_COLLECT_REFUSED[@]+"${IMAGE_COLLECT_REFUSED[@]}"}"
      fi

      local osrel=''
      if [[ -r $metadir/etc/os-release ]]; then
        osrel=$metadir/etc/os-release
      elif [[ -r $metadir/usr/lib/os-release ]]; then
        osrel=$metadir/usr/lib/os-release
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
          # IMG-06 wired real apk enumeration + matching for Alpine; IMG-09
          # adds the mirror-image dpkg branch for Debian/Ubuntu, dispatched
          # on the distro `ID` image_distro_ecosystem_resolve already
          # resolved (never on the ecosystem string itself, which is the
          # advisory-db KEY, not the package-manager SELECTOR - Alpine and
          # a future rpm-based distro could in principle share a prefix
          # scheme some day, and this dispatch must not assume otherwise).
          # apk_scan_installed/dpkg_scan_installed each enumerate their own
          # already-extracted database, look every installed package up
          # against data/advisories.db under this image's own resolved
          # ecosystem (dpkg's lookup key is the RESOLVED SOURCE package
          # name, report.md §2.1 trap 2 - modules/image/distro/dpkg.sh's own
          # section 2 header has the full reasoning), and emit
          # IMAGE-PKG-VULNERABLE_OS_PACKAGE-01/-02 respectively per
          # still-vulnerable (package, advisory) pair.
          rc=0
          case $distro_id in
            alpine)
              apk_scan_installed "$metadir/lib/apk/db/installed" "$image_id" "$ecosystem" || rc=$?
              if (( rc != 0 )); then
                # No apk database in ANY layer, despite a resolved, covered
                # Alpine release (report.md §4.3's `no_package_db_found`
                # row) - a scratch/distroless final stage. Never rendered
                # as a clean scan.
                image_report_unknown_distro "$image_id" "$ecosystem" apk "${_APK_INSTALLED_REASON:-no_package_db_found}"
              elif (( _APK_SCAN_SKIPPED > 0 )); then
                # One or more installed packages carried no comparable
                # version (an empty or malformed `V:` line) and were
                # skipped, never silently dropped - counted once for the
                # whole image rather than one reduction per package.
                run_record coverage_reduction "module=image reason=package_version_unparseable image=$image_id ecosystem=$ecosystem count=$_APK_SCAN_SKIPPED"
              fi
              ;;
            debian | ubuntu)
              dpkg_scan_installed "$metadir/var/lib/dpkg/status" "$image_id" "$ecosystem" || rc=$?
              if (( rc != 0 )); then
                # No dpkg database in ANY layer, despite a resolved, covered
                # Debian/Ubuntu release - the identical apk case above,
                # mirrored for dpkg.
                image_report_unknown_distro "$image_id" "$ecosystem" dpkg "${_DPKG_INSTALLED_REASON:-no_package_db_found}"
              elif (( _DPKG_SCAN_SKIPPED > 0 )); then
                run_record coverage_reduction "module=image reason=package_version_unparseable image=$image_id ecosystem=$ecosystem count=$_DPKG_SCAN_SKIPPED"
              fi
              ;;
          esac
        fi
      fi
      erase_dir "$metadir"
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
