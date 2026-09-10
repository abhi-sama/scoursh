#!/usr/bin/env bash
# modules/image/langdeps.sh - IMG-11 (data/scoursh-image-scan-design/
# report.md §2.2, §4.1's IMAGE-LANGDEP-* row and §5.3's IMG-11 row):
# language dependencies (npm/RubyGems/Composer/PyPI/Maven/Go) shipped INSIDE
# the image rootfs, found by reusing the four existing SCA tree-walkers -
# `sca_scan_tree`, `sca_scan_python_tree`, `sca_scan_java_tree`
# (modules/sca/engine.sh) and `sca_go_scan_tree` (modules/sca/go_engine.sh) -
# against a BOUNDED, DECLARED extraction of this image's own conventional
# manifest locations.  NO new parser: every byte of dependency-file parsing
# and every `data/advisories.db` lookup below is the identical code
# `scan.sh sca` already runs against a checked-out repository.
#
# THE TWO BINDING CAVEATS THIS FILE EXISTS TO SATISFY (report.md §2.2):
#
#   Caveat 1 - this is the ONE image-scanning case that needs a fuller
#   rootfs extraction than report.md §1.6's cheap-metadata-only invariant
#   (a handful of exact, declared paths). Section 1 below is the bound:
#   IMAGE_LANGDEPS_DIRS x IMAGE_LANGDEPS_FILENAMES, a fixed, declared cross
#   product of conventional manifest locations, extracted through the SAME
#   `image_collect_metadata` acquire.sh already uses for
#   etc/os-release/lib/apk/db/installed/var/lib/dpkg/status - never a full
#   rootfs dump, and never a directory LISTING of an unbounded tree. A
#   manifest at a path outside this declared set is genuinely invisible to
#   this check, and that is a stated, declared limitation (section 3 below),
#   never a silent gap.
#
#   Caveat 2 - the SCA walkers finding_set a `path-root` cell
#   (`$SCOURSH_PATH_ROOT`, modules/sca/engine.sh's own `_sca_emit_finding`
#   and siblings), which the `image` command never sets at all (it scans an
#   `--image`, not a `--path`) - calling them straight would land a
#   language-dependency finding under `module=sca` with an empty or
#   meaningless cell, exactly what the caveat forbids. Section 2 below is
#   the fix: the four walkers run with `SCOURSH_RUN_DIR` pointed at a
#   private, meta-less SHADOW run directory, so every `run_record` call
#   inside them is a silent no-op (lib/core.sh's own `run_record` requires a
#   real `meta/` directory) and every `finding_emit` lands only in that
#   shadow's own shard files - never this run's real ones. Section 2's
#   `_image_langdeps_transform_shard` is the ONLY path a language-dependency
#   finding ever reaches this run's real output through: it decodes each
#   shadow finding (lib/findings.sh's public `finding_decode`/
#   `finding_adopt_decoded` reader - never a hand-rolled parse of that
#   format, mirroring the gitleaks adapter's own dedup pass, AGENTS.md's "A
#   secret is never..." bullet), re-mints it under an `IMAGE-LANGDEP-*` id
#   with `module=image` and `cell=$image_id`, and only THEN calls
#   `finding_emit` again - this time with the real `SCOURSH_RUN_DIR`
#   restored.
#
# Run unconditionally once `image_open` succeeds, independent of whether
# this image's distro/ecosystem is ever resolved below it in
# modules/image/run.sh - the identical reasoning modules/image/config.sh's
# own header gives for the three IMAGE-CFG-* checks, and the more important
# case here: a distroless final stage with no apk/dpkg/rpm database at all
# (report.md's IMAGE-COV-UNKNOWN_DISTRO-01 case) is exactly where a copied-in
# `requirements.txt` or `package-lock.json` is the ONLY dependency surface
# this module has any hope of examining.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_LANGDEPS_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_LANGDEPS_SOURCED=1

# modules/sca/go_engine.sh pulls in modules/sca/engine.sh itself (both
# carry their own runtime sourced-once guards, so this is safe and real at
# runtime), which is where every function this file calls - sca_scan_tree,
# sca_scan_python_tree, sca_scan_java_tree, sca_advisories_db_path,
# sca_advisories_db_readable, sca_rollup_begin/sca_rollup_flush - actually
# lives, alongside sca_go_scan_tree itself.
#
# `# shellcheck source=/dev/null` rather than a real edge: modules/sca/
# engine.sh is a genuine shellcheck -x HUB (it sources lib/report.sh and
# lib/config.sh for real, CLAUDE.md's own "a new edge into lib/findings.sh
# ... is not opened for one 17-line function" measurement gives the reason
# this matters) and modules/image/engine.sh already reaches that identical
# lib/report.sh/lib/config.sh subtree through modules/sast/engine.sh (sourced
# there for sast_evaluate_gate) - a second real edge to the same subtree is
# exactly the diamond CLAUDE.md's shellcheck -x measurements warn against.
# The cut costs nothing: modules/sca/run.sh remains a real, unguarded entry
# point of its own, so this subtree is still checked in full at least once.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/../sca/go_engine.sh"

# ---------------------------------------------------------------------------
# 1. The bounded, declared candidate path set (report.md §2.2 caveat 1)
# ---------------------------------------------------------------------------
# Every path this module will ever ask `image_collect_metadata` to extract
# for a language manifest is the cross product of these two arrays - a
# handful of conventional WORKDIR locations across the ecosystems this
# module's own SCA walkers already parse, times the exact filenames those
# walkers' own `find -name` glob for (modules/sca/engine.sh's
# sca_walk_npm_lockfiles/sca_walk_gemfile_locks/sca_walk_python_manifests/
# sca_walk_java_manifests, php_engine.sh's sca_walk_composer_lockfiles,
# go_engine.sh's sca_walk_go_manifests). NOT exhaustive by design - a
# manifest at a genuinely unconventional path (say, a deeply nested
# monorepo subdirectory) is out of scope, and that is section 3's declared
# `no_manifests_found` reduction's whole point: absence of a finding here is
# absence of a look at that path, never evidence the dependency tree is
# clean.
declare -ga IMAGE_LANGDEPS_DIRS=(
  ''
  app
  usr/src/app
  srv
  opt/app
  home/app
)

declare -ga IMAGE_LANGDEPS_FILENAMES=(
  package-lock.json
  yarn.lock
  pnpm-lock.yaml
  Gemfile.lock
  composer.lock
  requirements.txt
  poetry.lock
  Pipfile.lock
  pom.xml
  build.gradle
  go.mod
  go.sum
)

# `image_langdeps_candidate_paths` - the whole IMAGE_LANGDEPS_DIRS x
# IMAGE_LANGDEPS_FILENAMES cross product, one member-shaped path per line
# (no leading slash, matching image_collect_metadata's own convention for
# IMAGE_METADATA_PATHS), LC_ALL=C sorted.
image_langdeps_candidate_paths() {
  local d f
  for d in "${IMAGE_LANGDEPS_DIRS[@]+"${IMAGE_LANGDEPS_DIRS[@]}"}"; do
    for f in "${IMAGE_LANGDEPS_FILENAMES[@]+"${IMAGE_LANGDEPS_FILENAMES[@]}"}"; do
      if [[ -z $d ]]; then
        printf '%s\n' "$f"
      else
        printf '%s/%s\n' "$d" "$f"
      fi
    done
  done | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 2. Re-emission under IMAGE-LANGDEP-* (report.md §2.2 caveat 2)
# ---------------------------------------------------------------------------

# `_image_langdeps_emit_vulnerable_dep IMAGE_ID` - `_DF` (lib/findings.sh)
# holds ONE decoded SCA-*-VULNERABLE_DEP-01 finding from the shadow run's own
# shard. Adopts it wholesale (every loc_ecosystem/loc_package/loc_version/
# loc_advisory_id/path/dep_type/fix_fixed_versions field the original walker
# already computed is correct and reused verbatim - `path` in particular is
# already destroot-relative, which for a call rooted at this image's own
# extraction destroot IS the in-image relative path, e.g. `app/package-
# lock.json`), then overrides only what caveat 2 requires: the check id, the
# module, and the cell/loc_image_id pair - never a host path-root.
_image_langdeps_emit_vulnerable_dep() {
  local image_id=$1
  local eco pkg ver advisory path

  finding_adopt_decoded
  eco=$(finding_get loc_ecosystem)
  pkg=$(finding_get loc_package)
  ver=$(finding_get loc_version)
  advisory=$(finding_get loc_advisory_id)
  path=$(finding_get path)

  finding_set check_id IMAGE-LANGDEP-VULNERABLE_DEP-01
  finding_set module image
  finding_set title "image $image_id: $eco dependency $pkg@$ver is vulnerable ($advisory)"
  # CWE-1104 ("Use of Unmaintained Third-Party Components"), matching
  # modules/image/checks-apk.rules' own IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 -
  # the identical "known-vulnerable pinned dependency" class, one surface
  # over. The decoded SCA finding carries `cwe none` (modules/sca/engine.sh's
  # own convention), which is right for a bare SCA report but not the best
  # answer once this is reframed as a container-image finding.
  finding_set cwe CWE-1104
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set remediation "$(finding_get remediation) Found at '$path' inside container image '$image_id' - rebuild the image with the dependency re-pinned to a fixed version and re-scan."

  finding_emit
}

# `_image_langdeps_transform_shard SHADOW_DIR IMAGE_ID` - the ONLY path a
# finding the shadow-run SCA walk emitted ever reaches this run's real
# output through (caveat 2's own header paragraph above). Reads every
# not-yet-merged finding out of the shadow run's own `shards/*.fields` via
# lib/findings.sh's public `finding_decode` reader, exactly as
# modules/sast/adapters/gitleaks/adapter.sh's own dedup pass does against
# ITS run's shard (AGENTS.md, tension 9's redaction bullet: "never a
# hand-rolled parse of that format").
#
# `SCA-COV-UNKNOWN_VERSION-01` (the one roll-up `sca_rollup_flush` may have
# emitted, bracketed exactly once by `image_langdeps_scan`'s own
# sca_rollup_begin/sca_rollup_flush pair below) is folded into a plain
# `coverage_reduction` line rather than re-minted as its own finding: giving
# it a check id of its own here would need its own fingerprint-safe location
# profile for what is, by construction, a roll-up naming no specific
# dependency (the SAME trap AGENTS.md's "SCA-COV-*" bullet documents - every
# instance would hash identically and collide) for a case
# `IMAGE-COV-LANGDEPS_NOT_SCANNED-01` (section 3) already exists to make
# non-silent at the module level.
_image_langdeps_transform_shard() {
  local shadow=$1 image_id=$2
  local -a shards=()
  local f line module check_id unknown_count=0

  shopt -s nullglob
  shards=("$shadow"/shards/*.fields)
  shopt -u nullglob
  (( ${#shards[@]} > 0 )) || return 0

  for f in "${shards[@]+"${shards[@]}"}"; do
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      module=${_DF[module]:-}
      check_id=${_DF[check_id]:-}
      [[ $module == sca ]] || continue
      case $check_id in
        SCA-NPM-VULNERABLE_DEP-01 | SCA-PY-VULNERABLE_DEP-01 | SCA-JAVA-VULNERABLE_DEP-01 \
          | SCA-RUBY-VULNERABLE_DEP-01 | SCA-PHP-VULNERABLE_DEP-01 | SCA-GO-VULNERABLE_DEP-01)
          _image_langdeps_emit_vulnerable_dep "$image_id"
          ;;
        SCA-COV-UNKNOWN_VERSION-01)
          unknown_count=$(( unknown_count + 1 ))
          ;;
        *)
          log_warn "image: langdeps saw an unexpected shadow-run check id '$check_id' from the SCA walkers - dropped, never re-emitted under module=sca"
          ;;
      esac
    done <"$f"
  done

  if (( unknown_count > 0 )); then
    run_record coverage_reduction "module=image reason=langdeps_unknown_version image=$image_id"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. Honesty - a rootfs with no language manifests is a declared reduction,
#    never a silent clean (the brief's own words)
# ---------------------------------------------------------------------------

# `image_langdeps_report_not_scanned IMAGE_ID DETAIL [DB]` - the ONE
# coverage check this ticket owns. Language-dependency scanning produced no
# meaningful examination of this image, for one of two DETAIL reasons:
# `no_advisories_db` (the same data/advisories.db this scan needs is
# missing/unreadable - report.md §2.3's shared-file reuse means this is the
# identical file IMAGE-COV-NO_ADVISORY_DB-01 already gates the distro side
# on, but that check id belongs to the DISTRO-ecosystem family in
# checks-advisories.rules; this is its own family, own file, per report.md
# §5.1's "one registry per owner" rule) or `no_manifests_found` (the image
# opened fine and every one of section 1's declared candidate paths was
# absent). ONE coverage_reduction, ONE IMAGE-COV-LANGDEPS_NOT_SCANNED-01
# finding, `info` severity - the identical "a blind spot is not a
# vulnerability" reasoning every other IMAGE-COV-* emitter in
# modules/image/engine.sh already gives.
image_langdeps_report_not_scanned() {
  local image_id=$1 detail=$2 db=${3:-}
  local detail_text

  case $detail in
    no_advisories_db)
      log_warn "image: no readable language-ecosystem advisory database at '${db:-<unset>}' - NO language dependency was checked for image '$image_id' (populate it with 'tools/vendor-engines.sh advisories <ecosystem>' on a networked box)"
      detail_text="The language-ecosystem advisory database ($db) is missing or unreadable, so no pinned dependency inside this image was checked against it."
      ;;
    *)
      log_warn "image: no language manifest found under any of this module's declared candidate locations for image '$image_id' - NO language dependency was checked"
      detail_text="This image was opened successfully, but no manifest file (package-lock.json, requirements.txt, go.mod, and similar) was present at any of this module's declared conventional locations. This module bounds its search to a fixed, declared set of candidate directories (data/scoursh-image-scan-design/report.md §2.2) rather than a full rootfs dump; a manifest at a non-conventional path is out of scope and was not examined."
      ;;
  esac

  run_record coverage_reduction "module=image reason=langdeps_$detail image=$image_id"
  run_record checks_run IMAGE-COV-LANGDEPS_NOT_SCANNED-01

  finding_new
  finding_set check_id IMAGE-COV-LANGDEPS_NOT_SCANNED-01
  finding_set module image
  finding_set title "Language-dependency scanning did NOT run inside image '$image_id' ($detail)"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set remediation "$detail_text Until this is corrected, this run says NOTHING about image '$image_id's language dependencies - absence of findings here is absence of evidence, never evidence of absence."
  finding_set_evidence "image: $image_id
detail: $detail
candidate_dirs: ${#IMAGE_LANGDEPS_DIRS[@]}
candidate_filenames: ${#IMAGE_LANGDEPS_FILENAMES[@]}
manifests_found: 0"
  finding_emit
}

# ---------------------------------------------------------------------------
# 4. Orchestration
# ---------------------------------------------------------------------------

# `image_langdeps_scan KIND ARCHIVE IMAGE_ID` - the whole IMG-11 check: the
# bounded, declared extraction (section 1), the shadow-run re-emission
# (section 2), and the honesty reductions (section 3), in one call.
image_langdeps_scan() {
  local kind=$1 archive=$2 image_id=$3
  local db
  db=$(sca_advisories_db_path)

  run_record notes "module=image image=$image_id langdeps_scope=bounded candidate_dirs=${#IMAGE_LANGDEPS_DIRS[@]} candidate_filenames=${#IMAGE_LANGDEPS_FILENAMES[@]}"

  if ! sca_advisories_db_readable "$db"; then
    image_langdeps_report_not_scanned "$image_id" no_advisories_db "$db"
    return 0
  fi

  local destroot
  destroot=$(_image_scratch_dir langdeps) || {
    log_warn "image: could not create a scratch directory for language-dependency extraction on image '$image_id'"
    return 0
  }

  local -a candidates=()
  local p
  while IFS= read -r p; do
    [[ -n $p ]] && candidates+=("$p")
  done < <(image_langdeps_candidate_paths)

  local -a extracted=()
  # image_collect_metadata prints "<path><TAB><layer index>" per successfully
  # extracted path - only the path is wanted here, so the second field is
  # read into `_`, the standard "deliberately unused" discard name.
  while IFS=$'\t' read -r p _; do
    [[ -n $p ]] && extracted+=("$p")
  done < <(image_collect_metadata "$kind" "$archive" "$destroot" "${candidates[@]+"${candidates[@]}"}")

  if (( ${#IMAGE_COLLECT_REFUSED[@]} > 0 )); then
    # A count-only reduction, deliberately never a dedicated finding - the
    # identical shape modules/image/run.sh already uses for
    # `package_version_unparseable`, and for the same reason
    # IMAGE-COV-LAYER_UNREADABLE-01 is not reused here: that check id's own
    # fingerprint carries no per-cause component (only image_id), so a
    # second, independent emission of it for THIS extraction pass would hash
    # identically to modules/image/run.sh's own os-release/apk/dpkg
    # extraction call and one would silently overwrite the other in
    # findings_merge's dedup - the exact SCA-COV-* collision AGENTS.md
    # documents at length, one check id over.
    run_record coverage_reduction "module=image reason=langdeps_layer_unreadable image=$image_id count=${#IMAGE_COLLECT_REFUSED[@]}"
  fi

  if (( ${#extracted[@]} == 0 )); then
    erase_dir "$destroot"
    image_langdeps_report_not_scanned "$image_id" no_manifests_found "$db"
    return 0
  fi

  # Reuse the existing SCA walkers, UNMODIFIED, pointed at the bounded
  # destroot above (report.md §2.2: "no new parser"). A shadow, meta-less
  # run directory (this section's own header paragraph) keeps every raw
  # module=sca / cell=$SCOURSH_PATH_ROOT finding they emit OUT of this run's
  # real shard set; `_image_langdeps_transform_shard` below is what actually
  # reaches this run's real output. `SCOURSH_PATH_ROOT` is saved/defaulted
  # too, for a narrower reason: the `image` command never sets it at all (it
  # scans an `--image`, not a `--path`), so under `set -u` the walkers' own
  # `finding_set cell "$SCOURSH_PATH_ROOT"` calls would abort on a genuinely
  # UNBOUND variable rather than merely an empty one - its actual value is
  # irrelevant either way, since every finding that reads it is discarded
  # (never merged) by the shadow-run redirection itself.
  local shadow real_run_dir=$SCOURSH_RUN_DIR real_path_root=${SCOURSH_PATH_ROOT:-}
  local path_root_was_set=0
  [[ -n ${SCOURSH_PATH_ROOT+x} ]] && path_root_was_set=1
  shadow=$(_image_scratch_dir langdeps-shadow) || {
    log_warn "image: could not create a shadow run directory for language-dependency scanning on image '$image_id'"
    erase_dir "$destroot"
    return 0
  }
  mkdir -p "$shadow/shards"

  SCOURSH_RUN_DIR=$shadow
  SCOURSH_PATH_ROOT=$real_path_root
  sca_rollup_begin
  sca_scan_tree "$destroot"
  sca_scan_python_tree "$destroot"
  sca_scan_java_tree "$destroot"
  sca_go_scan_tree "$destroot"
  sca_rollup_flush
  SCOURSH_RUN_DIR=$real_run_dir
  if (( path_root_was_set )); then
    SCOURSH_PATH_ROOT=$real_path_root
  else
    unset SCOURSH_PATH_ROOT
  fi

  run_record checks_run IMAGE-LANGDEP-VULNERABLE_DEP-01
  _image_langdeps_transform_shard "$shadow" "$image_id"

  erase_dir "$shadow"
  erase_dir "$destroot"
  return 0
}
