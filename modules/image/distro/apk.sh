#!/usr/bin/env bash
# modules/image/distro/apk.sh - apk installed-package ENUMERATION (IMG-04)
# plus advisory matching and finding emission (IMG-06, data/
# scoursh-image-scan-design/report.md §2.1's apk row, §2.3-2.5, and §4.1's
# IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 row).
#
# WHAT THIS FILE IS.  Section 1 (IMG-04, unchanged): given the path of an
# already-extracted `lib/apk/db/installed` file (the exact byte-for-byte
# member `modules/image/acquire.sh`'s `image_collect_metadata` writes when a
# caller asks for it - this file never opens an archive, never resolves a
# layer winner, and never sees a tar itself), read every installed package
# as a (name, version) pair. Section 2 (IMG-06, new): look each one up
# against `data/advisories.db`, decide "still vulnerable" with
# `modules/image/distro/apk_version.sh`'s comparator (IMG-05), and emit
# `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` - the wiring `checks-apk.rules`' own
# header already named this file as the owning driver for.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No archive handling and no layer
# resolution (modules/image/acquire.sh's job, IMG-02) and no
# `modules/image/run.sh` orchestration (the branch that decides WHETHER to
# call apk_scan_installed at all, and what to do with a non-zero
# `_APK_SCAN_SKIPPED`, stays in run.sh). Section 1's own enumerator remains a
# pure reader exactly as it always was - it calls nothing side-effecting and
# is still safely callable standalone (tests/suites/image-apk.sh does
# exactly that); section 2 is where this file starts calling
# `finding_emit`/`run_record`/`db_lookup_prefix`, relying on its caller
# having the full lib/ stack in scope rather than sourcing a copy of it - see
# that section's own header for why.
#
# THE APK DB FORMAT (report.md §2.1's own delightful accident): blank-line
# separated blocks of single-letter `K:value` lines - no space after the
# colon, unlike scoursh's own frozen `key: value` record format
# (rules/RULE-FORMAT.md §4) - with no escaping and a value that runs to end
# of line, exactly the same "reuse the parsing INSTINCT, not the parser"
# read this ticket's brief gives.  A real block looks like:
#
#   C:Q1abc...                              (checksum)
#   P:musl                                  (package NAME - this file's key)
#   V:1.2.4-r2                              (VERSION - this file's other key)
#   A:x86_64
#   S:12345
#   I:67890
#   T:the musl c library (libc) implementation
#   U:https://musl.libc.org/
#   L:MIT
#   o:musl
#   D:so:libc.musl-x86_64.so.1
#
# `P` and `V` are the only two keys this ticket reads; every other key
# (checksum, arch, size, description, url, license, origin, depends,
# provides, maintainer, build time, commit, ...) is a real, legal line this
# parser must pass over WITHOUT treating it as a corrupt block - a `case`
# arm that only matches `P:*`/`V:*` and falls through to a silent no-op for
# everything else is what "handle a malformed/partial block sanely" means in
# practice: this file never dies, and never lets an unrecognised key line
# poison the block it sits in.
#
# TWO PARALLEL ARRAYS, NOT AN ASSOCIATIVE ONE, for the identical reason
# `modules/image/acquire.sh`'s own header gives for keeping layer state in
# order rather than collapsing it: a `name -> version` associative array
# would silently keep only the LAST entry for a package name apk's own
# tooling would never actually duplicate, and a caller auditing a corrupt or
# hand-edited database has no way to tell "one package, reinstalled" from
# "two distinct P: blocks, same name" if the second one already overwrote
# the first before it was ever looked at.  Parallel arrays preserve both.
#
# A SETTER, NEVER A `$(f)` PRINTER, for the reason `image_tar_listing_set`'s
# own header states and AGENTS.md's own "Things measured on this codebase"
# entry pins: a function called as `$(f)` runs in a subshell, so writes to
# arrays or to `_APK_INSTALLED_REASON` inside it would be silently discarded
# the instant a caller tried `x=$(apk_installed_enumerate "$f")`.  This file
# has no printing variant at all, on purpose, so there is no way to call it
# wrong.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_APK_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_APK_SOURCED=1

# `APK_INSTALLED_NAMES` / `APK_INSTALLED_VERSIONS` - the enumeration result,
# in file order, index-aligned (`APK_INSTALLED_NAMES[i]` and
# `APK_INSTALLED_VERSIONS[i]` are one package).  Reset at the start of every
# `apk_installed_enumerate` call, never accumulated across calls, so a
# caller enumerating a second image in one process never sees the first
# image's packages bleed into the second's result.
declare -ga APK_INSTALLED_NAMES=()
declare -ga APK_INSTALLED_VERSIONS=()

# `_APK_INSTALLED_REASON` - set only on a return-1 refusal, for the ONE
# refusal this file recognises: no readable database at the given path,
# which is the ordinary shape of a scratch or distroless image that carries
# no apk database at all (report.md §4.3's `no_package_db_found` reduction).
# A caller turns this into an actual `coverage_reduction`/finding - that
# wiring is IMG-06's scope, not this file's; this variable exists so a unit
# test (and, later, that wiring) can assert on WHY enumeration produced
# nothing without re-deriving the reason from a bare non-zero return code.
_APK_INSTALLED_REASON=''

# `apk_installed_enumerate FILE` - the one entry point.  Returns 0 with
# `APK_INSTALLED_NAMES`/`APK_INSTALLED_VERSIONS` populated (possibly with
# zero packages - an apk database that parses to nothing is a fact about the
# image, not a refusal) when FILE is readable; returns 1 with
# `_APK_INSTALLED_REASON=no_package_db_found` and both arrays left empty
# when it is not.
#
# A package is emitted only when its block carried a non-empty `P:` line -
# there is no such thing as a nameless installed package, so a block with no
# `P:` at all (or an empty one, `P:` with nothing after the colon) is
# dropped rather than enumerated as a package with an empty name.  A block
# that DOES carry `P:` but no `V:` is still emitted, with an empty version
# string, because "this apk database has no version for this package" is a
# real fact worth passing on to a version comparator rather than a parse
# failure to hide - IMG-05's comparator, not this file, is where "no version
# to compare against" gets its own decision.
apk_installed_enumerate() {
  local file=$1
  local line name='' version=''

  APK_INSTALLED_NAMES=()
  APK_INSTALLED_VERSIONS=()
  _APK_INSTALLED_REASON=''

  # `-f` as well as `-r`: a directory is commonly reported readable too (the
  # execute/search bit tracks with the read bit on most setups), and handing
  # a directory to `<"$file"` below fails inside the loop instead of here,
  # with a bash "Is a directory" read error rather than this function's own
  # clean refusal - measured in this ticket's own suite, section C.
  if [[ ! -f $file || ! -r $file ]]; then
    _APK_INSTALLED_REASON=no_package_db_found
    return 1
  fi

  # `|| [[ -n $line ]]` is the same "last line with no trailing newline is
  # not dropped" idiom `image_os_release_parse` already uses - an apk
  # `installed` file with no final blank line still has its last block
  # flushed below rather than silently discarded.
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ -z $line ]]; then
      if [[ -n $name ]]; then
        APK_INSTALLED_NAMES+=("$name")
        APK_INSTALLED_VERSIONS+=("$version")
      fi
      name=''
      version=''
      continue
    fi
    case $line in
      P:*) name=${line#P:} ;;
      V:*) version=${line#V:} ;;
      # Every other key (C/A/S/I/T/U/L/o/m/t/c/D/p/r/...) is real, legal apk
      # metadata this ticket does not read - fall through with no action,
      # never a diagnostic, so an unrecognised-but-legal line never poisons
      # the block it sits in.
      *) ;;
    esac
  done <"$file"

  # The file may end with no trailing blank line - flush whatever block was
  # still open when the loop ran out of input.
  if [[ -n $name ]]; then
    APK_INSTALLED_NAMES+=("$name")
    APK_INSTALLED_VERSIONS+=("$version")
  fi

  return 0
}

# ---------------------------------------------------------------------------
# 2. Advisory matching + finding emission (IMG-06, report.md §2.3-2.5/§4.1's
#    IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 row)
# ---------------------------------------------------------------------------
# WHAT CHANGED FROM IMG-04.  This file's own header above said "no advisory
# lookup, no finding ... that wiring is IMG-06's scope, not this file's" -
# this section is that wiring, landing in the same file
# modules/image/checks-apk.rules already named as the owning driver
# (`script: distro/apk.sh`) for exactly this reason.  apk_installed_enumerate
# above is UNCHANGED; everything below is new and calls run_record/
# finding_new/finding_emit/db_lookup_prefix, which this file still does not
# `source` - it relies on its caller (modules/image/engine.sh, itself only
# ever reached through the full lib/ stack scan.sh's own dispatch already
# loaded) having them in scope, the identical "a leaf calls into an
# already-loaded stack rather than sourcing its own copy" shape
# modules/image/engine.sh's `image_report_no_advisory_db` already uses.
# apk_installed_enumerate itself needs none of that and is still safely
# callable standalone, exactly as before.
#
# THE MATCHING RULE, AND WHY IT DELIBERATELY DEPARTS FROM
# docs/FOUNDATION.md TENSION 25'S EXACT-MATCH RESOLUTION.  Tension 25 freezes
# `data/advisories.db` matching as an EXACT (ecosystem, package, version)
# lookup for pypi/maven/Go/RubyGems/composer, with `fixed_versions` "carried
# as opaque display text and never compared" - correct there because the
# database is pre-expanded to name every affected version explicitly, so a
# byte-equal lookup is sound.  Alpine cannot use that shape: an OSV Alpine
# advisory names ONE recorded affected version per release branch, while a
# real image carries an arbitrary REBUILD of that branch (`-r4` vs `-r10`,
# `report.md §2.4`'s own measured example), and only a real ordering
# comparison can tell whether a given rebuild has reached the fix. That
# measurement - the shipped semver comparator scored 7-of-12 WRONG on real
# OS version pairs, including a false negative, "the exact direction tension
# 25 calls disqualifying" - is why `modules/image/distro/apk_version.sh`
# (IMG-05) exists at all; an exact-match reading of this schema would make
# that whole ticket dead code, which apk_version.sh's own header states
# outright ("It is the piece IMG-06 needs to decide whether an installed V:
# version ... is below an advisory's fixed-in version"). So here, and ONLY
# here in this codebase, `fixed_versions` IS compared - via
# `db_lookup_prefix` on (ecosystem, package) ALONE (never a three-field
# exact prefix, which would silently miss every rebuild that is not the one
# OSV happened to record) and `apk_version_cmp_v` against it.
#
# `_APK_SCAN_SKIPPED` - installed packages with no comparable version (an
# empty `V:` line, or one apk_version_valid rejects) are counted here, once
# per whole scan, rather than reported per package - the same "one roll-up,
# not one finding per package" discipline modules/sca/engine.sh's own
# SCA-COV-UNKNOWN_VERSION-01 already applies, so a corrupt apk database does
# not drown the report in identical-shaped noise. The caller
# (modules/image/run.sh) turns a non-zero count into its own
# coverage_reduction; this file only counts.
_APK_SCAN_SKIPPED=0

# `apk_scan_installed FILE IMAGE_ID ECOSYSTEM [DB]` - the module's one
# apk match+emit entry point. FILE is an already-extracted lib/apk/db/
# installed (image_collect_metadata's own output - this function never opens
# an archive or resolves a layer winner, exactly like
# apk_installed_enumerate above).
#
# Returns 0 (with `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` recorded into
# checks_run) when FILE was readable, REGARDLESS of whether any package
# matched - "the check ran and found nothing" is a real, honest outcome, and
# checks_run must reflect that the check EXECUTED, not merely that it fired.
# Returns 1 with `_APK_INSTALLED_REASON` set (apk_installed_enumerate's own
# reason) and checks_run left untouched when FILE could not be read at all -
# the caller turns THAT into the IMAGE-COV-UNKNOWN_DISTRO-01
# reduction/finding, exactly as modules/image/engine.sh's
# image_report_no_advisory_db already does for its own absent input.
apk_scan_installed() {
  local file=$1 image_id=$2 ecosystem=$3 db=${4:-$(image_advisories_db_path)}
  _APK_SCAN_SKIPPED=0

  apk_installed_enumerate "$file" || return 1

  run_record checks_run IMAGE-PKG-VULNERABLE_OS_PACKAGE-01

  local i n=${#APK_INSTALLED_NAMES[@]}
  local name ver prefix row marked row_eco pkg rver advisory sev fixed
  local -A seen_advisory=()
  for (( i = 0; i < n; i++ )); do
    name=${APK_INSTALLED_NAMES[i]}
    ver=${APK_INSTALLED_VERSIONS[i]}
    # A package with no comparable installed version cannot be ordered
    # against anything, so it is counted (never silently dropped) and
    # skipped - never treated as "equal to nothing" or "always vulnerable",
    # both of which would be a guess this file's own comparator is built to
    # avoid making (apk_version.sh's own header, "MALFORMED INPUT IS
    # UNORDERABLE").
    if [[ -z $ver ]] || ! apk_version_valid "$ver"; then
      _APK_SCAN_SKIPPED=$(( _APK_SCAN_SKIPPED + 1 ))
      continue
    fi
    seen_advisory=()
    prefix=$(printf '%s\t%s\t' "$ecosystem" "$name")
    while IFS= read -r row; do
      [[ -n $row ]] || continue
      # data/advisories.db is real-TAB TSV; translate to \x1f first for the
      # identical reason modules/sca/engine.sh's own _sca_emit_finding does -
      # tab is IFS whitespace even when IFS is set to only tab, so a
      # middle-empty field (an advisory with no published fixed_versions)
      # silently shifts every later field under a literal-tab `read`.
      marked=${row//$'\t'/$'\x1f'}
      IFS=$'\x1f' read -r row_eco pkg rver advisory sev fixed <<<"$marked"
      # One finding per (package, advisory), never per matching row: two db
      # rows can legitimately share one advisory_id (one Alpine advisory
      # recorded against more than one affected version within the same
      # release), and a second finding for the same identity would only be
      # deduped later, after paying for a second finding_emit.
      [[ -n $advisory && -z ${seen_advisory[$advisory]:-} ]] || continue
      _apk_row_still_vulnerable "$ver" "$fixed" || continue
      seen_advisory[$advisory]=1
      _apk_emit_vulnerable_package "$image_id" "$ecosystem" "$name" "$ver" "$advisory" "$sev" "$fixed"
    done < <(db_lookup_prefix "$prefix" "$db")
  done
  return 0
}

# `_apk_row_still_vulnerable INSTALLED FIXED_VERSIONS` - the comparison this
# whole check exists to make. FIXED_VERSIONS is a comma-separated list
# (docs/FOUNDATION.md tension 25's schema); every token that parses under
# apk_version_valid is compared and the LARGEST one wins as the fix
# threshold - conservative on purpose (report.md §2.4: "a false positive:
# noisy, survivable" is the accepted direction; a false negative is not), so
# a package below ANY of several recorded fix points is still reported
# rather than only the smallest. An empty field, or one whose tokens all
# fail to parse, means no comparable fix is known at all - treated as still
# vulnerable, mirroring modules/sca/engine.sh's own accept-risk convention
# for an unfixed advisory (_sca_emit_finding's `accept_risk` branch) rather
# than a silent skip, since "no published fix" is never a reason to call a
# package safe.
_apk_row_still_vulnerable() {
  local installed=$1 fixed_versions=$2
  local -a tokens
  IFS=',' read -r -a tokens <<<"$fixed_versions"
  local t best=''
  for t in "${tokens[@]+"${tokens[@]}"}"; do
    [[ -n $t ]] || continue
    apk_version_valid "$t" || continue
    if [[ -z $best ]]; then
      best=$t
    else
      apk_version_cmp_v "$t" "$best"
      (( _APKV_CMP <= 0 )) || best=$t
    fi
  done
  [[ -n $best ]] || return 0
  apk_version_cmp_v "$installed" "$best" || return 0
  (( _APKV_CMP < 0 ))
}

# `_apk_summary_for ADVISORY_ID` - data/advisory-summaries.db's own row, or a
# placeholder, mirroring modules/sca/engine.sh's `_sca_summary_for`. A local
# copy rather than a `source modules/sca/engine.sh` edge: that file is a real
# shellcheck -x hub (AGENTS.md's own "the shared response reader"/"a
# DIAMOND" measurements document exactly this cost for other consumers), and
# the env var name is reused verbatim so a test pointing
# SCOURSH_SCA_SUMMARIES_DB at a fixture redirects this lookup too - the one
# thing that actually has to agree.
_apk_summary_for() {
  local advisory=$1 db prefix row marked _adv summary
  db=${SCOURSH_SCA_SUMMARIES_DB:-${SCOURSH_INSTALL_ROOT:-}/data/advisory-summaries.db}
  prefix=$(printf '%s\t' "$advisory")
  row=$(db_lookup_exact "$prefix" "$db") || { printf 'no summary available'; return 0; }
  marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r _adv summary <<<"$marked"
  printf '%s' "${summary:-no summary available}"
}

# `_apk_emit_vulnerable_package IMAGE_ID ECOSYSTEM PACKAGE INSTALLED ADVISORY
# SEVERITY FIXED_VERSIONS` - one finding.  `base_severity` is the ROW's own
# value, not the registry's declared default (modules/image/checks-apk.rules'
# own comment: "IMG-06's comparator/emitter is expected to do the identical
# thing against data/advisories.db's row rather than defer to this field",
# the same convention modules/network/checks-banner.rules' own
# NET-SVC-OUTDATED_COMPONENT-01 already established).
_apk_emit_vulnerable_package() {
  local image_id=$1 ecosystem=$2 pkg=$3 installed=$4 advisory=$5 sev=$6 fixed=$7
  local summary
  summary=$(_apk_summary_for "$advisory")

  finding_new
  finding_set check_id IMAGE-PKG-VULNERABLE_OS_PACKAGE-01
  finding_set module image
  finding_set title "$ecosystem: apk package $pkg@$installed is vulnerable ($advisory)"
  finding_set base_severity "$sev"
  finding_set confidence high
  finding_set cwe CWE-1104
  finding_set owasp A06:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set loc_ecosystem "$ecosystem"
  finding_set loc_package "$pkg"
  finding_set loc_version "$installed"
  finding_set loc_advisory_id "$advisory"
  finding_set logical_kind package
  finding_set logical_fqn "image $image_id: $ecosystem/$pkg@$installed"
  # IMG-14 (rules/RULE-FORMAT.md §9.2.2, §9.6.8): populated only when the
  # operator declared this image's `dockerfile` in config/images.conf - the
  # `file` correlation value that lets rules/derived.rules join this finding
  # to the IAC-DOCKER-* findings from scanning that same Dockerfile.  A
  # direct `finding_set corr_file`, never a profile default (lib/findings.sh
  # has no `image` case in `_finding_fill_correlation`), the identical
  # pattern modules/network/*.sh already use for `corr_target`: the IMAGE
  # profile's own components (image_id ecosystem package advisory_id) have
  # no path field a default could read.
  [[ -n ${SCOURSH_IMAGE_DOCKERFILE:-} ]] && finding_set corr_file "$SCOURSH_IMAGE_DOCKERFILE"
  finding_set fix_fixed_versions "$fixed"
  if [[ -n $fixed ]]; then
    finding_set remediation "Rebuild the image against an updated base layer (or upgrade $pkg directly, where the Dockerfile installs it explicitly) to at least $fixed, then re-scan. A base-image bump alone can carry this fix silently."
  else
    finding_set remediation "No fixed version is published upstream yet for $advisory against $pkg; this is an accept-risk candidate pending an upstream fix."
  fi
  finding_set_evidence "image: $image_id
package: $pkg@$installed
ecosystem: $ecosystem
advisory: $advisory ($sev)
fixed_versions: ${fixed:-none published}
summary: $summary"
  finding_emit
}
