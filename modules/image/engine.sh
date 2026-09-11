#!/usr/bin/env bash
# modules/image/engine.sh - the container-image-scanning module's pure
# function library (IMG-01, the module foundation ticket; distro-release detection and the
# advisory-database reuse added by IMG-03; distro/apk.sh, apk_version.sh and
# config.sh sourced here, and the two remaining v1 coverage emitters added,
# by IMG-06; distro-release detection widened to Debian/Ubuntu and
# distro/dpkg.sh, dpkg_version.sh sourced here, by IMG-09; config.sh widened
# with two more distro-agnostic config-blob checks by IMG-10, no new source
# edge since config.sh was already sourced here by IMG-06; langdeps.sh
# sourced here by IMG-11, reusing modules/sca/'s four tree-walkers against a
# bounded, declared extraction of this image's own language manifests).
#
# WHAT IMG-01 SHIPPED, AND WHAT HAS LANDED SINCE.  IMG-01 was the ONLY
# shared-file ticket for this module - it registered the `IMAGE` module
# across every frozen table and shared list (rules/RULE-FORMAT.md,
# lib/records.sh, lib/checks.sh, lib/findings.sh, lib/report.sh, scan.sh -
# see that ticket's own commit) so every later ticket adds only its own
# files.  IMG-03 sources acquire.sh (IMG-02) and adds distro-release
# detection plus the data/advisories.db coverage gate.  IMG-06 completes the
# v1 Alpine slice: it sources distro/apk.sh (IMG-04's enumerator, extended by
# IMG-06 itself with matching + emission), distro/apk_version.sh (IMG-05's
# comparator) and config.sh (IMG-06's own IMAGE-CFG-RUNS_AS_ROOT-01 driver),
# and adds this file's own `image_report_unknown_distro`/
# `image_report_layer_unreadable` - the two coverage reductions report.md
# §4.3 lists that IMG-03 had not yet reached.  IMG-09 completes the
# Debian/Ubuntu slice: it widens `image_distro_ecosystem_resolve` to map
# `debian`/`ubuntu` os-release IDs onto their own OSV.dev ecosystem keys,
# sources distro/dpkg.sh (IMG-07's enumerator, extended by IMG-09 itself
# with matching + emission, mirroring distro/apk.sh's own IMG-04/IMG-06
# shape) and dpkg_version.sh (IMG-08's comparator), and widens
# `image_report_unknown_distro` to take an explicit MANAGER argument so apk
# and dpkg share one emitter rather than each carrying manager-specific
# prose.  Unlike modules/dast/engine.sh and modules/network/engine.sh, it
# declares no phase table: report.md's v1 architecture is
# acquire -> enumerate -> compare, each its own file (`acquire.sh`,
# `distro/apk.sh`, `distro/dpkg.sh`, ...), not a set of intensity-gated
# phases run in a fixed order over one target - there is nothing to gate on
# `--intensity` here, so a phase table would be a table with nothing to put
# in it.
#
# The run.sh / engine.sh split is modules/sast/'s, modules/dast/'s and
# modules/network/'s, reused verbatim: this file is a pure function library
# with the standard sourced-once guard and no side effects at source time,
# and modules/image/run.sh is the file that DOES something when sourced.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_ENGINE_SOURCED=1

# modules/sast/engine.sh is sourced for `sast_evaluate_gate` ALONE, reused
# rather than forked for the identical reason modules/dast/engine.sh's and
# modules/network/engine.sh's own comments give: despite its name that
# function is module-agnostic - it re-reads every finding in
# $rundir/findings.fields and applies the severity/confidence/fail-on-new
# filter chain with no module check anywhere in its body.  Guarded
# internally (its own sourced-once guard), so this source line is safe to
# leave unconditional exactly as its two siblings' are.
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"
if [[ -z ${SCOURSH_CHECKS_SOURCED:-} ]]; then
  # shellcheck source=lib/checks.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/checks.sh"
fi

# acquire.sh (IMG-02) carries its own sourced-once guard, so this is safe to
# leave unconditional exactly like the sast/engine.sh source line above.
# IMG-03 is the first real consumer (acquire.sh's own header names it), and
# it is sourced HERE rather than from modules/image/run.sh directly so
# run.sh keeps its own source list at one line - the same reasoning the
# sast/engine.sh and lib/checks.sh source lines above already give.
# shellcheck source=modules/image/acquire.sh
source "${BASH_SOURCE[0]%/*}/acquire.sh"

# distro/apk.sh (IMG-04/IMG-06), distro/apk_version.sh (IMG-05),
# distro/dpkg.sh (IMG-07/IMG-09), distro/dpkg_version.sh (IMG-08),
# distro/rpm.sh (IMG-12, extended with matching + emission by this ticket)
# and distro/rpm_version.sh (the rpmvercmp comparator), and config.sh
# (IMG-06) - all seven are LEAVES (apk_version.sh's, dpkg_version.sh's and
# rpm_version.sh's own headers: "adds no edge to the shellcheck -x source
# graph ... keep it that way"; the other four source nothing either), so
# adding them here costs nothing like the diamond/cycle measurements
# AGENTS.md records for a real hub. They are sourced from the module's one
# function-library hub, exactly like acquire.sh above, rather than from
# modules/image/run.sh directly, for the identical reason.
# shellcheck source=modules/image/distro/apk.sh
source "${BASH_SOURCE[0]%/*}/distro/apk.sh"
# shellcheck source=modules/image/distro/apk_version.sh
source "${BASH_SOURCE[0]%/*}/distro/apk_version.sh"
# shellcheck source=modules/image/distro/dpkg.sh
source "${BASH_SOURCE[0]%/*}/distro/dpkg.sh"
# shellcheck source=modules/image/distro/dpkg_version.sh
source "${BASH_SOURCE[0]%/*}/distro/dpkg_version.sh"
# shellcheck source=modules/image/distro/rpm.sh
source "${BASH_SOURCE[0]%/*}/distro/rpm.sh"
# shellcheck source=modules/image/distro/rpm_version.sh
source "${BASH_SOURCE[0]%/*}/distro/rpm_version.sh"
# shellcheck source=modules/image/config.sh
source "${BASH_SOURCE[0]%/*}/config.sh"
# langdeps.sh (IMG-11) is sourced from the module's one function-library hub
# exactly like every sibling above, for the identical reason; it carries its
# own shellcheck -x cut on its one real edge into modules/sca/ (its own
# header explains why), so adding it here costs nothing like the five leaves
# above do.
# shellcheck source=modules/image/langdeps.sh
source "${BASH_SOURCE[0]%/*}/langdeps.sh"

# ---------------------------------------------------------------------------
# Distro-release detection (IMG-03, the `distro_release_unknown`
# reduction) - parses the image's own /etc/os-release (or the systemd
# fallback path, usr/lib/os-release) to pick the per-release advisory
# ecosystem key a v1 (Alpine-only) run looks up in data/advisories.db.
# ---------------------------------------------------------------------------

# `image_os_release_parse FILE` - a bash-only KEY=VALUE reader for one
# os-release file, never `source`d (tension 26's "never source a config
# file" rule applies with equal force here even though this is not one of
# scoursh's own config files: the bytes are attacker-adjacent target
# content, and sourcing them would be arbitrary code execution). Sets
# `_IMAGE_OS_RELEASE_ID`/`_IMAGE_OS_RELEASE_VERSION_ID` and returns 0 only
# when `ID` was present - an os-release with no `ID` line names no distro at
# all, which this function treats the same as a missing file.
_IMAGE_OS_RELEASE_ID=''
_IMAGE_OS_RELEASE_VERSION_ID=''
image_os_release_parse() {
  local file=$1 line key val
  _IMAGE_OS_RELEASE_ID=''
  _IMAGE_OS_RELEASE_VERSION_ID=''
  [[ -r $file ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line && $line != '#'* && $line == *=* ]] || continue
    key=${line%%=*}
    val=${line#*=}
    # The systemd os-release spec (os-release(5)) allows a value to be
    # double- or single-quoted; an unquoted value is equally legal and is
    # left untouched. Only a MATCHING pair of surrounding quotes is
    # stripped, so a value that merely starts with a stray quote byte is
    # not mangled.
    if [[ $val == \"*\" && ${#val} -ge 2 ]]; then
      val=${val#\"}
      val=${val%\"}
    elif [[ $val == \'*\' && ${#val} -ge 2 ]]; then
      val=${val#\'}
      val=${val%\'}
    fi
    case $key in
      ID) _IMAGE_OS_RELEASE_ID=$val ;;
      VERSION_ID) _IMAGE_OS_RELEASE_VERSION_ID=$val ;;
    esac
  done <"$file"
  [[ -n $_IMAGE_OS_RELEASE_ID ]]
}

# `image_distro_ecosystem_resolve FILE` - image_os_release_parse plus the
# ID/VERSION_ID -> data/advisories.db ecosystem key mapping (`Alpine:vX.Y`, keyed per RELEASE, never per exact patch
# version - OSV.dev's own Alpine namespace is major.minor only; IMG-09 adds
# Debian and Ubuntu, each keyed the way OSV.dev itself publishes them -
# `Debian:N` is MAJOR-ONLY, e.g. `Debian:12`, never `Debian:12.5` (Debian's
# own point-release number is not part of OSV's ecosystem string at all, so
# keeping it would build a key data/advisories.db never carries a row
# under), while `Ubuntu:XX.YY` is major.minor, identically shaped to
# Alpine's own key and to `VERSION_ID` verbatim - Ubuntu's `VERSION_ID` IS
# already `22.04`/`20.04`, so no reformatting is needed once it is
# extracted). Any OTHER `ID`, or a `VERSION_ID` that does not carry the
# leading numeric component its own distro's key needs, resolves to nothing
# rather than a guess: guessing "latest" on
# a missing/unrecognised release produces a false NEGATIVE on an older
# image, which is the direction that reads as a pass. `_IMAGE_DISTRO_REASON`
# distinguishes "no os-release at all" (`no_os_release`) from "os-release
# named a distro/version this module cannot yet map"
# (`os_release_version_unparseable` / `distro_not_yet_supported`) purely
# for the human-readable detail text - every one of them is reported under
# the SAME `distro_release_unknown` coverage_reduction reason, since from an operator's chair all three answer
# the identical question ("was an advisory ecosystem found for this image")
# the identical way.
_IMAGE_DISTRO_ECOSYSTEM=''
_IMAGE_DISTRO_REASON=''
image_distro_ecosystem_resolve() {
  local file=$1 major minor
  _IMAGE_DISTRO_ECOSYSTEM=''
  _IMAGE_DISTRO_REASON=''
  if ! image_os_release_parse "$file"; then
    _IMAGE_DISTRO_REASON=no_os_release
    return 1
  fi
  case $_IMAGE_OS_RELEASE_ID in
    alpine)
      if [[ $_IMAGE_OS_RELEASE_VERSION_ID =~ ^([0-9]+)\.([0-9]+) ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        _IMAGE_DISTRO_ECOSYSTEM="Alpine:v${major}.${minor}"
        return 0
      fi
      _IMAGE_DISTRO_REASON=os_release_version_unparseable
      return 1
      ;;
    debian)
      # Debian's own OSV.dev namespace is the bare major version -
      # `Debian:11`, `Debian:12` - never the point release (`VERSION_ID` on
      # a real Debian image is typically already just `12`, but a stray
      # `12.5` is tolerated by matching only the LEADING run of digits
      # rather than requiring the whole field to be one integer).
      if [[ $_IMAGE_OS_RELEASE_VERSION_ID =~ ^([0-9]+) ]]; then
        major=${BASH_REMATCH[1]}
        _IMAGE_DISTRO_ECOSYSTEM="Debian:${major}"
        return 0
      fi
      _IMAGE_DISTRO_REASON=os_release_version_unparseable
      return 1
      ;;
    ubuntu)
      # Ubuntu's OSV.dev namespace is major.minor, e.g. `Ubuntu:22.04` -
      # `VERSION_ID` on a real Ubuntu image already carries exactly this
      # shape verbatim, so this is structurally identical to the Alpine
      # branch above rather than a new rule.
      if [[ $_IMAGE_OS_RELEASE_VERSION_ID =~ ^([0-9]+)\.([0-9]+) ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        _IMAGE_DISTRO_ECOSYSTEM="Ubuntu:${major}.${minor}"
        return 0
      fi
      _IMAGE_DISTRO_REASON=os_release_version_unparseable
      return 1
      ;;
    rhel | centos | rocky | almalinux | fedora)
      # Red Hat's own OSV.dev namespace is a single FLAT ecosystem string
      # with NO per-release variant ("Alpine:v3.18,
      # Debian:12, Ubuntu:22.04, Red Hat" - the last one carries no colon or
      # version suffix at all, unlike its three siblings). A real OSV Red
      # Hat advisory's own `versions` entries already carry the RHEL STREAM
      # inside the rpm RELEASE field itself (e.g. `...el8`, `...el9`), so
      # the major/minor release this image's own /etc/os-release reports
      # plays no role in picking the ecosystem KEY - only in which rows the
      # operator chose to import, and in whether an installed package's own
      # release string (compared via rpm_version.sh's rpmvercmp, which
      # orders `.el8` against `.el9` like any other alphanumeric segment)
      # actually matches. `centos`/`rocky`/`almalinux`/`fedora` share the
      # identical ecosystem for the same reason report.md's task brief
      # names all five together: each is a rebuild or close sibling of
      # RHEL's own rpm package stream, and this project has no evidence
      # OSV.dev publishes a separate namespace for any of them.
      #
      # VERSION_ID is deliberately NOT required to be numeric/parseable
      # here, unlike the alpine/debian/ubuntu branches above: those need a
      # parseable release to BUILD the ecosystem key at all, so an
      # unparseable one genuinely leaves no key to look up (report.md
      # §4.3's "guessing 'latest' produces a false negative" argument).
      # Red Hat's key needs no release component, so there is nothing to
      # guess - an RHEL-family image with a missing or oddly-formatted
      # VERSION_ID still names a real, coverable ecosystem. VERSION_ID is
      # still recorded in this module's own `notes` fact (modules/image/
      # run.sh) for operator visibility, whatever it contains.
      _IMAGE_DISTRO_ECOSYSTEM='Red Hat'
      return 0
      ;;
    *)
      _IMAGE_DISTRO_REASON=distro_not_yet_supported
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# The advisory database reuse (IMG-03) - data/
# advisories.db is the SAME file and the SAME `db_lookup_exact` lookup
# modules/sca/ already uses; only the ecosystem key differs. Deliberately a
# one-line reimplementation of `sca_advisories_db_path` rather than a
# `source modules/sca/engine.sh` edge: that file is a real shellcheck -x
# hub (AGENTS.md's own "the shared response reader"/"a DIAMOND" measurements
# document exactly this cost for other consumers), and the env var name is
# reused verbatim so a test pointing SCOURSH_SCA_ADVISORIES_DB at a fixture
# redirects this module too - the one thing that actually has to agree.
image_advisories_db_path() {
  printf '%s' "${SCOURSH_SCA_ADVISORIES_DB:-${SCOURSH_INSTALL_ROOT:-}/data/advisories.db}"
}

# `image_ecosystem_known ECOSYSTEM [DB]` - true when data/advisories.db
# carries ANY row for this exact ecosystem key (e.g. `Alpine:v3.18`). A
# plain existence test, so `db_lookup_exact`'s `-m 1` grep fallback is
# exactly as safe here as `sca_package_known`'s identical use of it
# (modules/sca/engine.sh): neither needs to enumerate every match, only to
# know at least one exists.
image_ecosystem_known() {
  local ecosystem=$1 db=${2:-$(image_advisories_db_path)}
  local prefix
  prefix=$(printf '%s\t' "$ecosystem")
  db_lookup_exact "$prefix" "$db" >/dev/null
}

# `image_report_no_advisory_db IMAGE_ID ECOSYSTEM [DB]` - the module-level
# announcement when data/advisories.db has no rows for the image's own
# resolved ecosystem: ONE coverage_reduction, ONE IMAGE-COV-NO_ADVISORY_DB-01
# finding, `info` severity for the identical reason
# sca_report_no_advisories_db's own comment gives (a blind spot is not a
# vulnerability, and `--fail-on` gating it would report "a complete
# assessment that failed its gate" for a run that never had a database to
# assess against). modules/image/run.sh sets the exit-4 gate itself, on
# `input`, for the identical dynamic-scoping reason modules/sca/run.sh's own
# comment gives.
image_report_no_advisory_db() {
  local image_id=$1 ecosystem=$2 db=${3:-$(image_advisories_db_path)}

  log_warn "image: no advisory database rows for '$ecosystem' at '$db' - NO package was checked for image '$image_id' (populate it with 'tools/vendor-engines.sh advisories alpine' on a networked box)"
  run_record coverage_reduction "module=image reason=no_advisories_db_for_ecosystem image=$image_id ecosystem=$ecosystem"
  run_record checks_run IMAGE-COV-NO_ADVISORY_DB-01

  finding_new
  finding_set check_id IMAGE-COV-NO_ADVISORY_DB-01
  finding_set module image
  finding_set title "Container image scanning did NOT run for '$ecosystem' - no advisory database rows for this distro release, so ZERO packages were checked"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set loc_ecosystem "$ecosystem"
  finding_set remediation "Populate data/advisories.db for $ecosystem with 'tools/vendor-engines.sh advisories alpine' (or the matching distro importer) on a networked box, then re-run. Until then this run says NOTHING about image '$image_id' - absence of findings here is absence of evidence, never evidence of absence."
  finding_set_evidence "advisories_db: $db
ecosystem_not_scanned: $ecosystem
image: $image_id
packages_checked: 0"
  finding_emit
}

# ---------------------------------------------------------------------------
# The remaining v1 coverage reductions (IMG-06)
# ---------------------------------------------------------------------------

# `image_report_unknown_distro IMAGE_ID ECOSYSTEM MANAGER [DETAIL]` - the
# ecosystem WAS resolved (an operator-facing distro/release, e.g.
# `Alpine:v3.18`, `Debian:12`, `Ubuntu:22.04`) and `data/advisories.db` DOES
# cover it, but no MANAGER (`apk` or `dpkg`) package database exists in ANY
# layer of this image - a scratch or distroless final stage that copies
# binaries out without the package manager's own metadata (the
# `no_package_db_found` reason). ONE coverage_reduction, ONE
# `IMAGE-COV-UNKNOWN_DISTRO-01` finding, `info` severity - the identical "a
# blind spot is not a vulnerability" reasoning `image_report_no_advisory_db`
# above already gives, applied to a different absent input. The check id
# reads "unknown distro" despite a resolved os-release because, from a
# packaging standpoint, an image with no package database is one this
# module cannot identify the CONTENTS of, whatever `/etc/os-release` claims;
# the title and evidence below say so explicitly rather than trusting the
# id alone to carry that nuance.
#
# MANAGER is required (IMG-09 widened this function from apk-only to also
# cover dpkg's mirror-image case) - the wording below is
# generic on purpose, which is what let this ticket's own rpm caller reuse
# it with only its own MANAGER value and one new DETAIL-aware branch below.
#
# `rpm_db_binary_format` gets its OWN title/remediation, rather than sharing
# the generic "no $manager package database in any layer" wording apk/dpkg
# always use: this detail means an rpm database WAS found - see
# `modules/image/distro/rpm.sh`'s own header - either
# sqlite3 is absent from PATH (the `requires-cmd: sqlite3` gate), or the
# database is one of the two genuinely-binary shapes (Berkeley DB / ndb)
# this project has no reader for, or it is the modern sqlite backend's own
# REAL two-column native schema, whose per-package NEVRA lives inside an
# opaque blob rather than queryable columns. Reusing the "no database at
# all" wording for that case would misreport a found-but-unreadable
# database as an absent one - a distinct fact this project's own honesty
# doctrine says must not be collapsed into a
# different reason's prose. apk and dpkg never set this detail, so their
# behaviour here is unchanged.
image_report_unknown_distro() {
  local image_id=$1 ecosystem=$2 manager=$3 detail=${4:-no_package_db_found}
  local db_path=''
  case $manager in
    apk) db_path='lib/apk/db/installed' ;;
    dpkg) db_path='var/lib/dpkg/status' ;;
    rpm) db_path='var/lib/rpm/rpmdb.sqlite (or the older var/lib/rpm/Packages / Packages.db)' ;;
  esac

  local title remediation
  if [[ $detail == rpm_db_binary_format ]]; then
    title="Container image scanning did NOT run for '$ecosystem' - this image's rpm database exists but is not text-readable ($detail)"
    remediation="This image's own /etc/os-release names $ecosystem and an rpm database exists at ${db_path:-its usual path}, but this scanner could not read it as text - either sqlite3 is not on this scanning host's PATH ('requires-cmd: sqlite3', modules/image/checks-rpm.rules), or the database is one of the two binary formats (Berkeley DB / ndb) this project has no reader for, or it is the modern sqlite backend's real two-column native schema, which stores every package's NEVRA inside an opaque per-row blob rather than as queryable columns (modules/image/distro/rpm.sh's own header has the full detail). Install sqlite3 on the scanning host if it is absent; until then this run says NOTHING about this image's installed rpm packages."
    log_warn "image: $manager package database in image '$image_id' exists but is not text-readable (resolved ecosystem: $ecosystem, detail=$detail) - NO package was checked"
  else
    title="Container image scanning did NOT run for '$ecosystem' - no $manager package database in any layer of this image"
    remediation="This image's own /etc/os-release names $ecosystem, but no ${db_path:-package database} member exists in any layer - typically a distroless or scratch-based final build stage. If this image really does ship $manager-managed packages, check whether the final build stage strips ${db_path:-the package database}. Until it is present, this run says NOTHING about this image's installed packages."
    log_warn "image: no recognised $manager package database in any layer of image '$image_id' (resolved ecosystem: $ecosystem, detail=$detail) - NO package was checked"
  fi
  run_record coverage_reduction "module=image reason=$detail image=$image_id ecosystem=$ecosystem"
  run_record checks_run IMAGE-COV-UNKNOWN_DISTRO-01

  finding_new
  finding_set check_id IMAGE-COV-UNKNOWN_DISTRO-01
  finding_set module image
  finding_set title "$title"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set loc_ecosystem "$ecosystem"
  finding_set remediation "$remediation"
  finding_set_evidence "ecosystem: $ecosystem
image: $image_id
manager: $manager
detail: $detail
packages_checked: 0"
  finding_emit
}

# `image_report_layer_unreadable IMAGE_ID REFUSED_LINES...` - one or more of
# `image_collect_metadata`'s wanted paths could not be obtained: the archive
# named a layer that failed to list/extract, or a member was refused by
# section 3's own extraction gate (the `layer_unreadable` reason -
# carries count and total). REFUSED_LINES is `IMAGE_COLLECT_REFUSED`
# verbatim, one `<path><TAB><reason>` per array element. ONE reduction and
# ONE finding for the whole run, carrying the COUNT, never one per path -
# an operator wants "how bad" at a glance, and the evidence line still
# lists every affected path and its own reason.
image_report_layer_unreadable() {
  local image_id=$1
  shift
  local -a refused=("$@")
  local n=${#refused[@]}
  (( n > 0 )) || return 0

  local line path reason evline=''
  for line in "${refused[@]+"${refused[@]}"}"; do
    path=${line%%$'\t'*}
    reason=${line#*$'\t'}
    evline+="$path: $reason"$'\n'
  done

  log_warn "image: $n metadata path(s) could not be read from image '$image_id' - see this finding's evidence for detail"
  run_record coverage_reduction "module=image reason=layer_unreadable image=$image_id count=$n"
  run_record checks_run IMAGE-COV-LAYER_UNREADABLE-01

  finding_new
  finding_set check_id IMAGE-COV-LAYER_UNREADABLE-01
  finding_set module image
  finding_set title "Container image scanning is INCOMPLETE for image '$image_id' - $n metadata path(s) could not be read from this image's layers"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set remediation "Re-save or re-export this image and re-scan. If the problem persists, the archive may be corrupt or a layer member may be malformed - see this finding's own evidence for the specific path(s) and refusal reason(s)."
  finding_set_evidence "image: $image_id
paths_unreadable: $n
${evline%$'\n'}"
  finding_emit
}
