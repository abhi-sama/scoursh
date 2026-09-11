#!/usr/bin/env bash
# modules/image/distro/rpm.sh - rpm (RHEL/Fedora) installed-package
# ENUMERATION (IMG-12: "rpm - gated on the v1-distro-scope decision;
# requires-cmd: sqlite3"), first of the rpm sub-chain that mirrors dpkg's
# own IMG-07/08/09 split - enumeration here (section 1, IMG-12's own
# scope), a version comparator next (rpm_version.sh, the rpmvercmp
# comparator), and advisory matching + finding emission last (section 2
# below, this file's own last rpm ticket: the Red Hat advisory ecosystem
# plus wiring rpm enumeration and rpmvercmp into the vulnerable-package
# finding path, mirroring dpkg.sh's own IMG-09).
#
# WHAT SECTION 1 WAS AT IMG-12, AND WHAT SECTION 2 ADDS ON TOP. IMG-12
# shipped section 1 ONLY: enumeration, no comparator, no advisory lookup,
# and no finding emission. Section 1 is UNCHANGED by section 2 below and
# remains a pure reader, still safely callable standalone - no archive
# handling and no layer resolution is added either way.
#
# WHAT THIS FILE IS.  Given the paths of whichever of the three on-disk rpm
# database SHAPES `modules/image/acquire.sh`'s `image_collect_metadata`
# extracted for a given image (never all three at once on a real image - see
# below), enumerate installed packages as a (name, epoch, version, release,
# arch) NEVRA tuple.  This file never opens an archive, never resolves a
# layer winner, and never sees a tar itself - identical to
# `apk_installed_enumerate`/`dpkg_installed_enumerate`.
#
# WHY THIS FILE TAKES THREE FILE ARGUMENTS, UNLIKE ITS TWO SIBLINGS.  apk has
# exactly one on-disk shape (`lib/apk/db/installed`) and dpkg has exactly one
# (`var/lib/dpkg/status`), so each enumerator takes one FILE.  rpm has THREE
# (three physical shapes): the modern sqlite backend
# (`var/lib/rpm/rpmdb.sqlite`, Fedora 33+ default since 2020) and the two
# older binary shapes, Berkeley DB (`var/lib/rpm/Packages`) and ndb
# (`var/lib/rpm/Packages.db`).  A real image carries exactly one of the
# three - rpm does not maintain more than one backend live at once - so
# `rpm_installed_enumerate` is handed all three candidate paths (any of
# which may be empty/absent, exactly as `image_collect_metadata` leaves an
# unwanted-or-missing path unresolved) and picks whichever one is actually
# present, sqlite first.
#
# ===========================================================================
# THE CENTRAL, MEASURED FACT THIS FILE IS BUILT AROUND
# ===========================================================================
# A first draft measured "sqlite3 present, rpm/rpm2cpio absent" on its
# authoring host and read that as "the modern format is thereby readable".
# It is not, and this was RE-MEASURED while writing this file, against
# rpm.org's own db_recovery.html, the Fedora "Sqlite Rpmdb" change proposal,
# and how third-party scanners that already solved this (anchore/syft,
# quay/claircore) actually read it:
#
#   `rpmdb.sqlite`'s own native `Packages` table is `(hnum INTEGER PRIMARY
#   KEY, blob BLOB NOT NULL)` - TWO COLUMNS, full stop.  The sqlite file is
#   only a key-value store; `blob` is the SAME serialized RPM header
#   structure (a binary tag/type/offset/count index over a second binary
#   data segment) that the Berkeley-DB and ndb backends store under the
#   identical key.  The per-tag index tables sqlite ALSO ships (`Name`,
#   `Basenames`, `Providename`, `Requirename`, ...) map an indexed STRING to
#   the `hnum`(s) that carry it - real plain text, but names/capabilities
#   ONLY, never a package's own version/release/epoch/arch, which live
#   solely inside the opaque per-row `blob`.  Every real reader of this
#   format - syft's `rpm/sqlite` package and claircore's own `rpm/sqlite`
#   equivalent - queries `Packages` for `(hnum, blob)` and then runs a real
#   RPM HEADER DECODER over `blob`, the exact same decoder they run against
#   a Berkeley-DB or ndb row.  Nobody gets NEVRA out of this format with a
#   bare `SELECT`.
#
# So "sqlite present" does NOT mean "text-readable", and writing a general RPM-header decoder in pure bash is
# EXACTLY the "unverifiable blob" docs/FOUNDATION.md tension 25 already
# rejects for OS version algebras (quoting
# tension 25 almost verbatim) - a hand-rolled binary tag/type/offset parser
# with no reference implementation to differential-test against in this
# tree is not something this project ships.  This file does not attempt one.
#
# WHAT THIS FILE DOES INSTEAD, AND WHY IT IS STILL THE RIGHT SHAPE FOR THIS
# TICKET.  The sqlite branch below queries `Packages` for a PLAIN
# `(name, epoch, version, release, arch)` projection - the shape
# `requires-cmd: sqlite3` was written for, and the shape a future ticket
# that DOES land a real header decoder (most plausibly as a vendored engine
# adapter per docs/ADAPTERS.md, mirroring how `gitleaks`/`trivy` already
# wrap a real binary rather than a bash reimplementation of one, rather than
# a hand-rolled bash parser) can populate by writing rows into a real sqlite
# database this same query already reads correctly.  Run against an
# UNMODIFIED, real `/var/lib/rpm/rpmdb.sqlite` - the two-column native
# schema above - that query fails (`sqlite3` reports "no such column: name"
# and exits non-zero, since the table it opened really does exist but does
# not have these columns), and this file treats that failure exactly like
# the two genuinely-binary formats: `_RPM_INSTALLED_REASON=rpm_db_binary_format`,
# never a silent zero-package "clean" scan.  `tests/suites/image-rpm.sh`
# section F proves this against a fixture built with the REAL two-column
# native schema, not merely asserted in this comment.  The result: every
# real rpm-based image gets ONE honest, consistent answer today
# ("rpm_db_binary_format") regardless of which of the three on-disk shapes
# it actually carries, while the sqlite code path itself - the query, the
# parallel-array population, the malformed/empty-field handling, the
# `requires-cmd: sqlite3` gate - is real, exercised, working code rather
# than a stub waiting on a decoder that does not exist yet.
#
# THE OLDER FORMATS NEED NO DETECTION BEYOND "WHICH PATH EXISTS" (report.md
# §2.1: "need no text reader available here (rpm2cpio absent)").  Berkeley
# DB and ndb are told apart by their FIXED, DIFFERENT on-disk path alone
# (`var/lib/rpm/Packages` vs `var/lib/rpm/Packages.db` -
# own table), never by sniffing file content: this project has no Berkeley-
# DB or ndb reader of any kind, so which of the two binary shapes it is
# changes nothing about what happens next, only about which fixed path
# acquisition happened to find populated.
#
# THREE PARALLEL ARRAYS PER FIELD, NOT AN ASSOCIATIVE ONE, for the identical
# reason `apk_installed_enumerate`'s and `dpkg_installed_enumerate`'s own
# headers give: an associative array keyed on name would silently keep only
# the LAST row for a name this project's own fixture-building code (or a
# hand-edited database) could duplicate, and a caller has no way to tell
# "one package" from "two rows, same name" once the second has already
# overwritten the first.
#
# A SETTER, NEVER A `$(f)` PRINTER, for the reason `apk_installed_enumerate`'s
# own header states and AGENTS.md's own "Things measured on this codebase"
# entry pins: a function called as `$(f)` runs in a subshell, so writes to
# arrays or to `_RPM_INSTALLED_REASON` inside it would be silently discarded
# the instant a caller tried `x=$(rpm_installed_enumerate "$a" "$b" "$c")`.
# This file has no printing variant at all, on purpose.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_RPM_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_RPM_SOURCED=1

# `RPM_INSTALLED_NAMES` / `_EPOCHS` / `_VERSIONS` / `_RELEASES` / `_ARCHES` -
# the enumeration result, in query order, index-aligned (index `i` of all
# five is one package).  `RPM_INSTALLED_EPOCHS[i]` is commonly the empty
# string - most rpm packages carry no epoch at all, which `rpm`'s own
# tooling renders as "(none)" rather than "0"; this file passes the column
# through verbatim rather than inventing a default, the identical "an empty
# comparable field is a future comparator's decision to make, not this
# enumerator's" convention `dpkg_installed_enumerate` already applies to a
# missing `Version:`.  Reset at the start of every
# `rpm_installed_enumerate` call, never accumulated across calls, so a
# caller enumerating a second image in one process never sees the first
# image's packages bleed into the second's result.
declare -ga RPM_INSTALLED_NAMES=()
declare -ga RPM_INSTALLED_EPOCHS=()
declare -ga RPM_INSTALLED_VERSIONS=()
declare -ga RPM_INSTALLED_RELEASES=()
declare -ga RPM_INSTALLED_ARCHES=()

# `_RPM_INSTALLED_REASON` - set only on a return-1 refusal, one of the two
# reasons this module recognises:
#
#   no_package_db_found    - none of the three candidate paths exist at all,
#                             the ordinary shape of an apk/dpkg image that
#                             carries no rpm database (mirroring apk's and
#                             dpkg's own enumerators for the mirror-image
#                             case).
#   rpm_db_binary_format   - a candidate WAS found, but this file cannot
#                             read it as text: the file is a genuinely
#                             binary format (Berkeley DB / ndb) with no
#                             reader in this project at all, OR it is the
#                             sqlite format and either `sqlite3` is not on
#                             PATH (the `requires-cmd: sqlite3` gate) or the
#                             query this file issues against it failed - the
#                             ordinary outcome against a real, unmodified
#                             `rpmdb.sqlite`, per this file's header.
#
# `_RPM_INSTALLED_FORMAT` - which of the three candidate paths was found
# present, set alongside the reason above (`sqlite` / `bdb` / `ndb` / empty
# when none were).  Not itself a reason report.md names, but the detail a
# future coverage_reduction/finding message needs to say WHICH physical
# shape this image's database was in - "rpm_db_binary_format (bdb)" reads
# very differently from "rpm_db_binary_format (sqlite, no sqlite3 on
# PATH)", and that wiring is a later ticket's scope, not this file's; the
# variable exists here so that ticket does not have to re-derive it.
_RPM_INSTALLED_REASON=''
_RPM_INSTALLED_FORMAT=''

# `rpm_installed_enumerate SQLITE_FILE BDB_FILE NDB_FILE` - the one entry
# point.  Any of the three may be the empty string or a path that does not
# exist - `image_collect_metadata` only ever extracts the shapes a given
# image actually carries, so on a real image at most one of the three is
# ever populated.  Returns 0 with all five `RPM_INSTALLED_*` arrays
# populated (possibly with zero packages, when a readable sqlite database
# parses to no rows - a fact about the image, not a refusal) when a
# candidate was found and was text-readable; returns 1 with
# `_RPM_INSTALLED_REASON`/`_RPM_INSTALLED_FORMAT` set and all five arrays
# left empty otherwise.
#
# SQLITE FIRST, DELIBERATELY.  It is the current rpm default (Fedora 33+,
# Fedora 33+) and the only one of the three this file can ever actually
# read, so on an image whose database happens to carry a stale leftover copy
# of an older backend alongside a live sqlite one (a real shape after a
# `dnf` in-place upgrade migrates the backend but never deletes the old
# file), preferring sqlite reports what the package manager actually reads
# today rather than a fossil it no longer consults.
rpm_installed_enumerate() {
  local sqlite_file=$1 bdb_file=$2 ndb_file=$3

  RPM_INSTALLED_NAMES=()
  RPM_INSTALLED_EPOCHS=()
  RPM_INSTALLED_VERSIONS=()
  RPM_INSTALLED_RELEASES=()
  RPM_INSTALLED_ARCHES=()
  _RPM_INSTALLED_REASON=''
  _RPM_INSTALLED_FORMAT=''

  if [[ -n $sqlite_file && -f $sqlite_file && -r $sqlite_file ]]; then
    _RPM_INSTALLED_FORMAT=sqlite
    _rpm_sqlite_enumerate "$sqlite_file" && return 0
    _RPM_INSTALLED_REASON=rpm_db_binary_format
    return 1
  fi

  if [[ -n $bdb_file && -f $bdb_file && -r $bdb_file ]]; then
    _RPM_INSTALLED_FORMAT=bdb
    _RPM_INSTALLED_REASON=rpm_db_binary_format
    return 1
  fi

  if [[ -n $ndb_file && -f $ndb_file && -r $ndb_file ]]; then
    _RPM_INSTALLED_FORMAT=ndb
    _RPM_INSTALLED_REASON=rpm_db_binary_format
    return 1
  fi

  _RPM_INSTALLED_REASON=no_package_db_found
  return 1
}

# `_rpm_sqlite_enumerate FILE` - the sqlite branch, split out of
# `rpm_installed_enumerate` so the "which candidate did we find" decision
# above stays readable.  Returns 0 with the five arrays populated when
# `sqlite3` is on PATH AND the query below succeeds; returns 1 (with no
# reason of its own - the caller always maps a false return here to
# `rpm_db_binary_format`, per this file's header) otherwise.
#
# `command -v sqlite3` INLINE rather than this project's own `_have`
# (lib/core.sh) helper: this file's section 1, like its apk/dpkg siblings',
# sources nothing and stays safely callable standing entirely alone
# (`tests/suites/image-rpm.sh` sources only this file plus
# `tests/lib/assert.sh`, exactly as `tests/suites/image-dpkg.sh` does) - a
# `source lib/core.sh` edge here would be paid for by every future consumer
# of this file for one two-word command check, the identical "an edge added
# to a leaf is paid for once per consumer" argument
# `modules/image/acquire.sh`'s own header gives for staying off the JSON-
# flattener hub.
#
# `-separator $'\x1f'`, NEVER a tab or a comma: `epoch` is routinely EMPTY
# (most rpm packages carry no epoch at all) and AGENTS.md's own "Sharp
# edges" entry pins the exact failure this avoids - a tab is IFS whitespace,
# so `read` folds it and drops a leading/trailing empty field, silently
# shifting every later column out of alignment for exactly the row this
# reader must get right most often.
_rpm_sqlite_enumerate() {
  local file=$1
  local out rc=0 name epoch version release arch

  command -v sqlite3 >/dev/null 2>&1 || return 1

  out=$(sqlite3 -noheader -separator $'\x1f' "$file" \
    'SELECT name, epoch, version, release, arch FROM Packages ORDER BY rowid;' \
    2>/dev/null) || rc=$?
  (( rc == 0 )) || return 1

  [[ -n $out ]] || return 0

  while IFS=$'\x1f' read -r name epoch version release arch; do
    [[ -n $name ]] || continue
    RPM_INSTALLED_NAMES+=("$name")
    RPM_INSTALLED_EPOCHS+=("$epoch")
    RPM_INSTALLED_VERSIONS+=("$version")
    RPM_INSTALLED_RELEASES+=("$release")
    RPM_INSTALLED_ARCHES+=("$arch")
  done <<<"$out"

  return 0
}

# ---------------------------------------------------------------------------
# 2. Advisory matching + finding emission (the "complete the rpm slice
#    end-to-end" ticket: the Red Hat advisory ecosystem plus wiring rpm
#    enumeration + rpmvercmp into the vulnerable-package finding path,
#    mirroring modules/image/distro/dpkg.sh's own IMG-07 -> IMG-09 shape,
#    the last rpm ticket anticipated: "a future
#    rpm version comparator and the advisory-matching/finding-emission
#    wiring a future Red Hat/Fedora advisory-ecosystem ticket adds are both
#    expected to land in that same file", modules/image/checks-rpm.rules's
#    own header).
# ---------------------------------------------------------------------------
# WHAT CHANGED FROM IMG-12/the rpm-version-comparator ticket. Sections 1
# above (enumeration) and rpm_version.sh (rpmvercmp) are UNCHANGED; this
# section is the wiring `modules/image/checks-rpm.rules` already named this
# file as the owning driver for. It calls run_record/finding_new/
# finding_emit/db_lookup_prefix, which this file still does not `source` -
# the identical "a leaf calls into an already-loaded stack rather than
# sourcing its own copy" shape `modules/image/distro/apk.sh`'s and
# `dpkg.sh`'s own section 2 already use, relying on its caller
# (modules/image/engine.sh, reached only through the full lib/ stack
# scan.sh's own dispatch already loaded) having them in scope, including
# rpm_version.sh's rpm_version_valid/rpm_version_cmp_v, sourced alongside
# this file by that same engine.sh.
#
# THE LOOKUP KEY IS THE PLAIN PACKAGE NAME, UNLIKE DPKG'S SOURCE-PACKAGE
# RESOLUTION. dpkg.sh's own section 2 header explains why Debian/Ubuntu
# advisories are published against the SOURCE package rather than the
# installed binary package - but section 1 above never queries a rpm
# "source RPM" column (real rpm headers carry one, `SOURCERPM`, but it names
# the *building* source rpm, not a distinct advisory-bearing identity the
# way dpkg's `Source:` field does), and Red Hat's own OSV.dev advisories are
# published against the installed rpm's own NAME (report.md's task brief:
# "look up each package's advisory in the resolved ecosystem" - no
# source/binary distinction is named, unlike the dpkg ticket's own explicit
# "resolved SOURCE package name" instruction). So `RPM_INSTALLED_NAMES[i]`
# is used directly as both the lookup key and `loc_package`, with no second
# identity to resolve or record.
#
# THE VERSION COMPARISON JOINS EPOCH/VERSION/RELEASE INTO ONE EVR STRING,
# RATHER THAN CALLING rpm_evr_cmp_v's FIELD FORM DIRECTLY. `data/
# advisories.db`'s `fixed_versions` column is a plain, comma-separated list
# of STRINGS (docs/FOUNDATION.md tension 25's schema; apk's and dpkg's own
# `_apk_row_still_vulnerable`/`_dpkg_row_still_vulnerable` already compare
# strings, never fields) - so joining `RPM_INSTALLED_EPOCHS[i]`/
# `_VERSIONS[i]`/`_RELEASES[i]` into rpm_version.sh's own
# `[epoch:]version[-release]` string form (`_rpm_evr_join` below) and
# comparing through the STRING-form `rpm_version_valid`/`rpm_version_cmp_v`
# keeps this file symmetric with its two siblings, at the cost of one
# trivial join rather than a second parse path for `fixed_versions`
# entries. An empty epoch or empty release joins to the identical shape
# `rpm_version.sh`'s own `_rpmv_parse` already treats as "absent" (epoch 0,
# release ordering below any present one) - the STRING form's own
# documented behaviour, not a new rule invented here.
#
# `_RPM_SCAN_SKIPPED` - installed packages with no comparable version (an
# empty VERSION column, or a joined EVR string `rpm_version_valid` rejects)
# are counted here, once per whole scan, mirroring `_APK_SCAN_SKIPPED`'s and
# `_DPKG_SCAN_SKIPPED`'s identical "one roll-up, not one finding per
# package" discipline. The caller (modules/image/run.sh) turns a non-zero
# count into its own coverage_reduction; this file only counts.
_RPM_SCAN_SKIPPED=0

# `_rpm_evr_join EPOCH VERSION RELEASE` - joins the three parallel-array
# fields `rpm_installed_enumerate` returns into rpm_version.sh's own
# `[epoch:]version[-release]` string form. An empty EPOCH omits the leading
# `epoch:` (rpm_version.sh's own string-form default: absent means epoch 0);
# an empty RELEASE omits the trailing `-release` (absent means "orders below
# any present release", rpm_version.sh's own documented behaviour for that
# shape) - never a literal `:` or trailing `-`, both of which
# `rpm_version_valid` would refuse as a MALFORMED string rather than read as
# an absent field. A VERSION that is itself empty (a malformed enumerated
# row, report.md/tests/suites/image-rpm.sh section H's `no-version-pkg`
# fixture) joins to a string `rpm_version_valid` also refuses, which is
# exactly the "uncomparable, not equal and not less" outcome this file's own
# caller needs.
_rpm_evr_join() {
  local epoch=$1 version=$2 release=$3 out
  if [[ -n $epoch ]]; then
    out="$epoch:$version"
  else
    out=$version
  fi
  if [[ -n $release ]]; then
    out="$out-$release"
  fi
  printf '%s' "$out"
}

# `rpm_scan_installed SQLITE_FILE BDB_FILE NDB_FILE IMAGE_ID ECOSYSTEM [DB]` -
# the module's one rpm match+emit entry point. The first three arguments are
# `rpm_installed_enumerate`'s own three candidate paths, unchanged from
# section 1 - this function never opens an archive or resolves a layer
# winner, exactly like `rpm_installed_enumerate` itself.
#
# Returns 0 (with `IMAGE-PKG-VULNERABLE_OS_PACKAGE-03` recorded into
# checks_run) when enumeration succeeded, REGARDLESS of whether any package
# matched - "the check ran and found nothing" is a real, honest outcome,
# mirroring `apk_scan_installed`'s and `dpkg_scan_installed`'s identical
# contract. Returns 1 with `_RPM_INSTALLED_REASON`/`_RPM_INSTALLED_FORMAT`
# set (section 1's own reasons - `no_package_db_found` or
# `rpm_db_binary_format`) and checks_run left untouched when enumeration
# could not read a usable database at all - the caller turns THAT into the
# `IMAGE-COV-UNKNOWN_DISTRO-01` reduction/finding, with `rpm_db_binary_format`
# getting its own detail-aware wording (modules/image/engine.sh's
# `image_report_unknown_distro`).
rpm_scan_installed() {
  local sqlite_file=$1 bdb_file=$2 ndb_file=$3 image_id=$4 ecosystem=$5 db=${6:-$(image_advisories_db_path)}
  _RPM_SCAN_SKIPPED=0

  rpm_installed_enumerate "$sqlite_file" "$bdb_file" "$ndb_file" || return 1

  run_record checks_run IMAGE-PKG-VULNERABLE_OS_PACKAGE-03

  local i n=${#RPM_INSTALLED_NAMES[@]}
  local name epoch version release arch installed_evr
  local prefix row marked row_eco pkg rver advisory sev fixed
  local -A seen_advisory=()
  for (( i = 0; i < n; i++ )); do
    name=${RPM_INSTALLED_NAMES[i]}
    epoch=${RPM_INSTALLED_EPOCHS[i]}
    version=${RPM_INSTALLED_VERSIONS[i]}
    release=${RPM_INSTALLED_RELEASES[i]}
    arch=${RPM_INSTALLED_ARCHES[i]}
    installed_evr=$(_rpm_evr_join "$epoch" "$version" "$release")
    # A package with no comparable installed version cannot be ordered
    # against anything, so it is counted (never silently dropped) and
    # skipped - the identical "MALFORMED INPUT IS UNORDERABLE" discipline
    # `rpm_version.sh`'s own header states.
    if [[ -z $installed_evr ]] || ! rpm_version_valid "$installed_evr"; then
      _RPM_SCAN_SKIPPED=$(( _RPM_SCAN_SKIPPED + 1 ))
      continue
    fi
    seen_advisory=()
    prefix=$(printf '%s\t%s\t' "$ecosystem" "$name")
    while IFS= read -r row; do
      [[ -n $row ]] || continue
      # data/advisories.db is real-TAB TSV; translate to \x1f first for the
      # identical reason `apk_scan_installed`'s and `dpkg_scan_installed`'s
      # own loops do - tab is IFS whitespace even when IFS is set to only
      # tab, so a middle-empty field (an advisory with no published
      # fixed_versions) silently shifts every later field under a
      # literal-tab `read`.
      marked=${row//$'\t'/$'\x1f'}
      IFS=$'\x1f' read -r row_eco pkg rver advisory sev fixed <<<"$marked"
      # One finding per (package, advisory), never per matching row - the
      # identical reasoning `apk_scan_installed`'s and `dpkg_scan_installed`'s
      # own loops give.
      [[ -n $advisory && -z ${seen_advisory[$advisory]:-} ]] || continue
      _rpm_row_still_vulnerable "$installed_evr" "$fixed" || continue
      seen_advisory[$advisory]=1
      _rpm_emit_vulnerable_package "$image_id" "$ecosystem" "$name" "$installed_evr" "$arch" "$advisory" "$sev" "$fixed"
    done < <(db_lookup_prefix "$prefix" "$db")
  done
  return 0
}

# `_rpm_row_still_vulnerable INSTALLED_EVR FIXED_VERSIONS` - rpm's own
# version of `_apk_row_still_vulnerable`/`_dpkg_row_still_vulnerable`,
# comparing through `rpm_version_cmp_v`/`rpm_version_valid` (rpm_version.sh)
# instead of apk's or dpkg's comparator. FIXED_VERSIONS is a
# comma-separated list of EVR strings (docs/FOUNDATION.md tension 25's
# schema); every token that parses under `rpm_version_valid` is compared and
# the LARGEST one wins as the fix threshold - conservative on purpose
# (a false positive is noisy but survivable, a false
# negative is not), so a package below ANY of several recorded fix points is
# still reported rather than only the smallest. An empty field, or one whose
# tokens all fail to parse, means no comparable fix is known at all -
# treated as still vulnerable, mirroring the two sibling comparators'
# identical accept-risk convention for an unfixed advisory rather than a
# silent skip.
_rpm_row_still_vulnerable() {
  local installed=$1 fixed_versions=$2
  local -a tokens
  IFS=',' read -r -a tokens <<<"$fixed_versions"
  local t best=''
  for t in "${tokens[@]+"${tokens[@]}"}"; do
    [[ -n $t ]] || continue
    rpm_version_valid "$t" || continue
    if [[ -z $best ]]; then
      best=$t
    else
      rpm_version_cmp_v "$t" "$best"
      (( _RPMV_CMP <= 0 )) || best=$t
    fi
  done
  [[ -n $best ]] || return 0
  rpm_version_cmp_v "$installed" "$best" || return 0
  (( _RPMV_CMP < 0 ))
}

# `_rpm_summary_for ADVISORY_ID` - data/advisory-summaries.db's own row, or a
# placeholder, mirroring `apk.sh`'s own `_apk_summary_for` and `dpkg.sh`'s
# own `_dpkg_summary_for` (and, one layer further, `modules/sca/engine.sh`'s
# `_sca_summary_for`). A local copy rather than a `source` edge to either
# sibling distro file - a sibling distro file is not this file's dependency
# any more than `modules/sca/engine.sh` is theirs - and the env var name is
# reused verbatim so a test pointing SCOURSH_SCA_SUMMARIES_DB at a fixture
# redirects this lookup too.
_rpm_summary_for() {
  local advisory=$1 db prefix row marked _adv summary
  db=${SCOURSH_SCA_SUMMARIES_DB:-${SCOURSH_INSTALL_ROOT:-}/data/advisory-summaries.db}
  prefix=$(printf '%s\t' "$advisory")
  row=$(db_lookup_exact "$prefix" "$db") || { printf 'no summary available'; return 0; }
  marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r _adv summary <<<"$marked"
  printf '%s' "${summary:-no summary available}"
}

# `_rpm_emit_vulnerable_package IMAGE_ID ECOSYSTEM PACKAGE INSTALLED_EVR ARCH
# ADVISORY SEVERITY FIXED_VERSIONS` - one finding. `base_severity` is the
# ROW's own value, not the registry's declared default, mirroring
# `checks-rpm.rules`' own comment and `apk.sh`'s/`dpkg.sh`'s identical
# convention. ARCH is recorded in the evidence only - it is not part of the
# advisory lookup key or of `loc_package`/`loc_version`, since Red Hat's own
# OSV.dev advisories are not published per-architecture.
_rpm_emit_vulnerable_package() {
  local image_id=$1 ecosystem=$2 pkg=$3 installed=$4 arch=$5 advisory=$6 sev=$7 fixed=$8
  local summary
  summary=$(_rpm_summary_for "$advisory")

  finding_new
  finding_set check_id IMAGE-PKG-VULNERABLE_OS_PACKAGE-03
  finding_set module image
  finding_set title "$ecosystem: rpm package $pkg@$installed is vulnerable ($advisory)"
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
  finding_set fix_fixed_versions "$fixed"
  if [[ -n $fixed ]]; then
    finding_set remediation "Rebuild the image against an updated base layer (or upgrade the $pkg package directly, where the Dockerfile installs it explicitly) to at least $fixed, then re-scan. A base-image bump alone can carry this fix silently."
  else
    finding_set remediation "No fixed version is published upstream yet for $advisory against $pkg; this is an accept-risk candidate pending an upstream fix."
  fi
  finding_set_evidence "image: $image_id
package: $pkg@$installed
arch: $arch
ecosystem: $ecosystem
advisory: $advisory ($sev)
fixed_versions: ${fixed:-none published}
summary: $summary"
  finding_emit
}
