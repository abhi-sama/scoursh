#!/usr/bin/env bash
# modules/image/distro/rpm.sh - rpm (RHEL/Fedora) installed-package
# ENUMERATION (IMG-12, data/scoursh-image-scan-design/report.md §2.1's rpm
# row and §5.3's IMG-12 row: "rpm - gated on the v1-distro-scope decision;
# requires-cmd: sqlite3"), first of the rpm sub-chain that mirrors dpkg's
# own IMG-07/08/09 split - enumeration here, a version comparator next, then
# advisory matching and finding emission. Section 1 below is the whole of
# this ticket's scope: no comparator, no advisories, no finding.
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
# (report.md §2.1's table): the modern sqlite backend
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
# report.md §2.1 measured "sqlite3 present, rpm/rpm2cpio absent" on its
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
# So "sqlite present" does NOT mean "text-readable" the way report.md's own
# §5.3 row implies, and writing a general RPM-header decoder in pure bash is
# EXACTLY the "unverifiable blob" docs/FOUNDATION.md tension 25 already
# rejects for OS version algebras (report.md §2.1's own words, quoting
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
# (`var/lib/rpm/Packages` vs `var/lib/rpm/Packages.db` - report.md §2.1's
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
# reasons report.md §4.3's table names for this module:
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
# report.md §2.1) and the only one of the three this file can ever actually
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
