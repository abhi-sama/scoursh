#!/usr/bin/env bash
# tests/suites/image-rpm.sh - IMG-12: rpm installed-package
# ENUMERATION, unit-level, against fixtures this suite BUILDS locally with
# `sqlite3` - never committed binary blobs, and never a network call. This
# is the first of the rpm sub-chain that mirrors dpkg's own IMG-07/08/09
# split: enumeration only, no comparator, no advisories, no finding.
#
# What this suite proves, and what it is NOT for:
#
#   A. `rpm_installed_enumerate` (modules/image/distro/rpm.sh) against a
#      real-shaped, multi-package sqlite fixture built with the plain
#      `(name, epoch, version, release, arch)` schema this file's own
#      reader queries: the exact NEVRA set, in query order, including a
#      package that carries an epoch and one that does not (the ordinary
#      case - most rpm packages carry none at all).
#   B. No rpm database at any of the three candidate paths at all (an
#      apk/dpkg image) returns `no_package_db_found` - the mirror-image
#      case apk's and dpkg's own enumerators already cover, and a directory
#      standing in for the sqlite file is refused the same way, never
#      treated as readable.
#   C. A readable sqlite file IS present, but `sqlite3` is not on PATH (the
#      `requires-cmd: sqlite3` gate, simulated by restricting PATH rather
#      than by uninstalling anything) - `rpm_db_binary_format`, never a
#      silent zero-package pass.
#   D. A Berkeley-DB-shaped file at `var/lib/rpm/Packages` (sqlite absent) -
#      `rpm_db_binary_format`. This project has no Berkeley-DB reader of
#      any kind, so the fixture's CONTENT is irrelevant; only its presence
#      at that fixed path matters.
#   E. An ndb-shaped file at `var/lib/rpm/Packages.db` (sqlite and Berkeley
#      both absent) - `rpm_db_binary_format`, the mirror of D.
#   F. THE CENTRAL CLAIM THIS TICKET'S OWN HEADER MAKES, PROVEN EMPIRICALLY
#      RATHER THAN ASSERTED IN A COMMENT: a sqlite file built with rpm's
#      REAL, NATIVE two-column schema (`Packages(hnum INTEGER PRIMARY KEY,
#      blob BLOB)` - no name/epoch/version/release/arch columns at all,
#      confirmed against rpm.org's own db_recovery.html and how
#      anchore/syft and quay/claircore actually read this format) also
#      yields `rpm_db_binary_format`, with `sqlite3` genuinely present and
#      genuinely able to open the file - it is the SQL query against this
#      file's real shape that fails, not the tool. A reader that silently
#      treated "sqlite3 opened the file" as "I can enumerate this" would
#      pass section A and then report a real rpm-based image as carrying
#      ZERO packages - the overstated-coverage failure direction
#      docs/DESIGN.md §15 forbids - which is exactly what this section
#      would catch.
#   G. Priority: when a sqlite file AND a Berkeley-DB file are both present
#      (a real shape after a `dnf` backend migration that never deleted
#      the old file), the sqlite one wins - this file's own header states
#      why (it is the one rpm actually reads today).
#   H. A malformed/partial result: a row with an empty `name` column is
#      dropped rather than enumerated as a nameless package; a row with no
#      comparable version data is still enumerated (mirroring
#      `dpkg_installed_enumerate`'s "an empty comparable field is a future
#      comparator's decision to make, not this enumerator's" convention);
#      and an empty, genuinely-readable sqlite database (zero rows, the
#      plain schema) enumerates to zero packages, never a refusal - the
#      identical "the DB exists and is merely empty" distinction section C
#      of tests/suites/image-dpkg.sh already proves for dpkg.
#   I. `modules/image/checks-rpm.rules` parses under the real record loader
#      with no diagnostics, registers exactly the one rpm check id
#      (`IMAGE-PKG-VULNERABLE_OS_PACKAGE-03`, distinct from apk's `-01` and
#      dpkg's `-02`), declares `requires-cmd: sqlite3`, and is discovered
#      by `checks_registry_load` alongside the module's five other
#      per-owner registries (six now, IMG-12 added the sixth).
#
# NOT this suite's job: no version comparator exists for rpm yet, no
# advisory matching exists, and IMAGE-PKG-VULNERABLE_OS_PACKAGE-03 is never
# actually emitted - it is registered and unreachable, the identical
# "registered, not yet wired" shape tests/suites/image-dpkg.sh's own header
# states IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 was in from IMG-07 through
# IMG-08/09. `modules/image/run.sh` is not touched or invoked by this suite
# at all.
#
# No network: image scanning is offline by construction (docs/DESIGN.md §1).
# `sqlite3` is used here only to BUILD this suite's own local fixtures (and
# is the same tool measured present on a real host) - never
# to reach a network, and section C simulates its absence with a restricted
# PATH rather than skipping.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/record syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SCOURSH_INSTALL_ROOT=$ROOT
# shellcheck source=modules/image/distro/rpm.sh
source "$ROOT/modules/image/distro/rpm.sh"
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

command -v sqlite3 >/dev/null 2>&1 || {
  printf 'tests/suites/image-rpm.sh: sqlite3 is not on PATH; this suite builds its own fixtures with it and cannot run without it\n' >&2
  exit 1
}

_arr_join() {
  local IFS='|'
  printf '%s' "$*"
}

W=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-image-rpm.XXXXXX")
trap 'rm -rf -- "${W:?}"' EXIT

# `_mk_sqlite VAR SQL...` - builds a fresh sqlite database at $W/<VAR>.sqlite
# from the given SQL statements, and sets VAR to its path.
_mk_sqlite() {
  local __var=$1
  shift
  local path=$W/$__var.sqlite
  rm -f -- "$path"
  sqlite3 "$path" "$@"
  printf -v "$__var" '%s' "$path"
}

# =============================================================================
printf -- '\n-- A. a real-shaped, multi-package sqlite fixture (the plain NEVRA schema this reader queries) --\n'
# =============================================================================

_mk_sqlite PLAIN_DB \
  "CREATE TABLE Packages (name TEXT, epoch TEXT, version TEXT, release TEXT, arch TEXT);" \
  "INSERT INTO Packages VALUES ('bash','','5.1.8','6.el9','x86_64');" \
  "INSERT INTO Packages VALUES ('openssl-libs','1','3.0.7','1.el9','x86_64');" \
  "INSERT INTO Packages VALUES ('glibc','','2.34','60.el9','x86_64');"

t_case 'enumerate returns exactly the three installed packages, in query order, with full NEVRA'
_rc=0
rpm_installed_enumerate "$PLAIN_DB" '' '' || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds against a readable, plain-schema sqlite database'
assert_eq 'bash|openssl-libs|glibc' "$(_arr_join "${RPM_INSTALLED_NAMES[@]}")" \
  'the three package NAMES, in query (rowid) order'
assert_eq '|1|' "$(_arr_join "${RPM_INSTALLED_EPOCHS[@]}")" \
  'bash and glibc carry no epoch at all (the ordinary case) and openssl-libs carries epoch 1 - FAILS under a reading that defaults a missing epoch to "0" instead of passing the empty column through verbatim'
assert_eq '5.1.8|3.0.7|2.34' "$(_arr_join "${RPM_INSTALLED_VERSIONS[@]}")" 'the three VERSIONS, index-aligned'
assert_eq '6.el9|1.el9|60.el9' "$(_arr_join "${RPM_INSTALLED_RELEASES[@]}")" 'the three RELEASES, index-aligned'
assert_eq 'x86_64|x86_64|x86_64' "$(_arr_join "${RPM_INSTALLED_ARCHES[@]}")" 'the three ARCHES, index-aligned'
assert_eq '' "$_RPM_INSTALLED_REASON" 'no refusal reason is set on a successful enumeration'
assert_eq sqlite "$_RPM_INSTALLED_FORMAT" 'the detected format is sqlite'

# =============================================================================
printf -- '\n-- B. no rpm database at any of the three candidate paths --\n'
# =============================================================================

t_case 'all three paths absent returns 1 with no_package_db_found, and empties all five arrays'
RPM_INSTALLED_NAMES=(stale)
RPM_INSTALLED_EPOCHS=(stale)
RPM_INSTALLED_VERSIONS=(stale)
RPM_INSTALLED_RELEASES=(stale)
RPM_INSTALLED_ARCHES=(stale)
_rc=0
rpm_installed_enumerate "$W/does-not-exist.sqlite" "$W/does-not-exist-Packages" "$W/does-not-exist-Packages.db" || _rc=$?
assert_eq 1 "$_rc" 'refusal is a plain 1, not a die/abort - an apk/dpkg image with no rpm database at all is the ordinary case'
assert_eq no_package_db_found "$_RPM_INSTALLED_REASON" 'the exact declared coverage_reduction reason for this case'
assert_eq '' "$_RPM_INSTALLED_FORMAT" 'no format was detected - nothing was found at any of the three paths'
assert_eq 0 "${#RPM_INSTALLED_NAMES[@]}" 'RPM_INSTALLED_NAMES is reset to empty, not left holding a stale prior result'
assert_eq 0 "${#RPM_INSTALLED_EPOCHS[@]}" 'RPM_INSTALLED_EPOCHS is reset to empty too'
assert_eq 0 "${#RPM_INSTALLED_VERSIONS[@]}" 'RPM_INSTALLED_VERSIONS is reset to empty too'
assert_eq 0 "${#RPM_INSTALLED_RELEASES[@]}" 'RPM_INSTALLED_RELEASES is reset to empty too'
assert_eq 0 "${#RPM_INSTALLED_ARCHES[@]}" 'RPM_INSTALLED_ARCHES is reset to empty too'

t_case 'empty-string arguments (image_collect_metadata never resolved any of the three) behave identically to nonexistent paths'
_rc=0
rpm_installed_enumerate '' '' '' || _rc=$?
assert_eq 1 "$_rc" 'refusal, not an unbound-variable crash or a directory-mistaken-for-file bug'
assert_eq no_package_db_found "$_RPM_INSTALLED_REASON" 'same declared reason'

t_case 'a directory standing in for the sqlite path is refused the same way, never treated as readable'
_rc=0
rpm_installed_enumerate "$W" '' '' || _rc=$?
assert_eq 1 "$_rc" 'a directory is not a readable database file'
assert_eq no_package_db_found "$_RPM_INSTALLED_REASON" 'falls through all three candidates to the same declared reason - no special-casing "it exists but is the wrong kind of thing"'

# =============================================================================
printf -- '\n-- C. sqlite file present, sqlite3 NOT on PATH (the requires-cmd gate) --\n'
# =============================================================================

t_case 'a readable sqlite database with sqlite3 absent from PATH yields rpm_db_binary_format, never a silent clean'
_EMPTY_PATH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-image-rpm-nopath.XXXXXX")
_OLD_PATH=$PATH
PATH=$_EMPTY_PATH_DIR
_rc=0
rpm_installed_enumerate "$PLAIN_DB" '' '' || _rc=$?
PATH=$_OLD_PATH
rm -rf -- "${_EMPTY_PATH_DIR:?}"
assert_eq 1 "$_rc" 'refusal, not a die/abort - a host missing sqlite3 is a declared limitation, not a fatal error'
assert_eq rpm_db_binary_format "$_RPM_INSTALLED_REASON" \
  'the exact declared reason for this case - FAILS if enumeration were attempted anyway (there would be nothing on PATH to attempt it with) or if the reason fell back to no_package_db_found, which would misreport "we could not read this" as "there is nothing here"'
assert_eq sqlite "$_RPM_INSTALLED_FORMAT" \
  'the format WAS correctly detected as sqlite before the requires-cmd gate refused it - distinct from section B, where nothing was found at all'
assert_eq 0 "${#RPM_INSTALLED_NAMES[@]}" 'no packages are enumerated on a refusal'

# =============================================================================
printf -- '\n-- D/E. Berkeley-DB and ndb shapes: this project has no reader for either --\n'
# =============================================================================

printf 'not a real Berkeley DB, just needs to exist at this path' >"$W/Packages-bdb-stub"

t_case 'a Berkeley-DB-shaped file at var/lib/rpm/Packages (sqlite absent) yields rpm_db_binary_format'
_rc=0
rpm_installed_enumerate '' "$W/Packages-bdb-stub" '' || _rc=$?
assert_eq 1 "$_rc" 'refusal, not an attempted parse - this project has no Berkeley-DB reader of any kind'
assert_eq rpm_db_binary_format "$_RPM_INSTALLED_REASON" 'the same declared reason the sqlite branch uses - one honest answer regardless of which of the three physical shapes the image carries'
assert_eq bdb "$_RPM_INSTALLED_FORMAT" 'the format is recorded as bdb - FAILS if format detection were content-based instead of the fixed-path distinction this reader draws'

printf 'not a real ndb file either, just needs to exist at this path' >"$W/Packages-ndb-stub"

t_case 'an ndb-shaped file at var/lib/rpm/Packages.db (sqlite and Berkeley both absent) yields rpm_db_binary_format'
_rc=0
rpm_installed_enumerate '' '' "$W/Packages-ndb-stub" || _rc=$?
assert_eq 1 "$_rc" 'refusal, not an attempted parse'
assert_eq rpm_db_binary_format "$_RPM_INSTALLED_REASON" 'the same declared reason again'
assert_eq ndb "$_RPM_INSTALLED_FORMAT" 'the format is recorded as ndb, distinct from bdb'

# =============================================================================
printf -- '\n-- F. THE CENTRAL CLAIM: sqlite3 present, file genuinely opens, but the REAL native schema has no NEVRA columns --\n'
# =============================================================================

_mk_sqlite NATIVE_DB \
  "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);" \
  "INSERT INTO Packages (blob) VALUES (X'0102030405');" \
  "INSERT INTO Packages (blob) VALUES (X'060708090a');"

t_case 'a sqlite file built with rpm own real two-column native schema (hnum, blob) also yields rpm_db_binary_format'
_rc=0
rpm_installed_enumerate "$NATIVE_DB" '' '' || _rc=$?
assert_eq 1 "$_rc" \
  'refusal - FAILS under a reading that treats "sqlite3 could open the file" as "I can enumerate this image": that reading would report a REAL rpm-based image (whose rpmdb.sqlite is exactly this two-column shape, per rpm.org and how syft/claircore actually read it) as carrying ZERO installed packages, the silent overstated-coverage failure docs/DESIGN.md §15 forbids'
assert_eq rpm_db_binary_format "$_RPM_INSTALLED_REASON" 'the query against Packages for name/epoch/version/release/arch fails on this real schema (no such column: name) and this file maps that failure to the same declared reason as the two genuinely-binary formats'
assert_eq sqlite "$_RPM_INSTALLED_FORMAT" 'the format is still recorded as sqlite - the FILE genuinely is one, only its per-package data is unreadable as text'
assert_eq 0 "${#RPM_INSTALLED_NAMES[@]}" 'nothing is enumerated - not two nameless rows, not a partial read of whatever columns happened to parse'

t_case 'sqlite3 really can open the native-schema file directly, proving the refusal above is about the SCHEMA and not a broken fixture'
_direct_rc=0
sqlite3 "$NATIVE_DB" 'SELECT count(*) FROM Packages;' >/dev/null || _direct_rc=$?
assert_eq 0 "$_direct_rc" 'the fixture is a genuinely valid, genuinely openable sqlite database - the enumerator refusal above is a SCHEMA mismatch, not a corrupt file sqlite3 itself could not open either'

# =============================================================================
printf -- '\n-- G. priority: sqlite wins when both a sqlite file and a Berkeley-DB file are present --\n'
# =============================================================================

t_case 'when both candidates exist, the sqlite one is read and the Berkeley-DB one is ignored'
_rc=0
rpm_installed_enumerate "$PLAIN_DB" "$W/Packages-bdb-stub" '' || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds - the sqlite candidate was used, not the Berkeley-DB one'
assert_eq sqlite "$_RPM_INSTALLED_FORMAT" 'sqlite is the detected format even though a Berkeley-DB-shaped file was also present'
assert_eq 'bash|openssl-libs|glibc' "$(_arr_join "${RPM_INSTALLED_NAMES[@]}")" 'the sqlite fixture own three packages, not a refusal'

# =============================================================================
printf -- '\n-- H. malformed rows and an empty, genuinely-readable database --\n'
# =============================================================================

_mk_sqlite MALFORMED_DB \
  "CREATE TABLE Packages (name TEXT, epoch TEXT, version TEXT, release TEXT, arch TEXT);" \
  "INSERT INTO Packages VALUES ('coreutils','','9.1','11.el9','x86_64');" \
  "INSERT INTO Packages VALUES ('','','1.0','1.el9','x86_64');" \
  "INSERT INTO Packages VALUES ('no-version-pkg','',NULL,NULL,'x86_64');" \
  "INSERT INTO Packages VALUES ('sed','','4.8','9.el9','x86_64');"

t_case 'a row with an empty name column is dropped, never enumerated as a nameless package'
_rc=0
rpm_installed_enumerate "$MALFORMED_DB" '' '' || _rc=$?
assert_eq 0 "$_rc" 'enumeration still succeeds - a malformed row is not a fatal error'
assert_eq 'coreutils|no-version-pkg|sed' "$(_arr_join "${RPM_INSTALLED_NAMES[@]}")" \
  'three surviving names - FAILS under a reading that emits an empty-named entry for the nameless row'

t_case 'a row with no comparable version/release data is still enumerated, with empty version/release strings'
assert_eq 'no-version-pkg' "${RPM_INSTALLED_NAMES[1]}" 'the version-less row is kept - FAILS under a reading that drops any row missing a field, which would silently under-report installed packages'
assert_eq '' "${RPM_INSTALLED_VERSIONS[1]}" 'its version is the empty string (a NULL sqlite column), not a stale value carried over from an earlier row'
assert_eq '' "${RPM_INSTALLED_RELEASES[1]}" 'its release is the empty string too'
assert_eq 'x86_64' "${RPM_INSTALLED_ARCHES[1]}" 'its arch is still present - only version/release were NULL'

t_case 'the valid rows immediately before and after the malformed ones parse correctly - state did not leak either direction'
assert_eq coreutils "${RPM_INSTALLED_NAMES[0]}" 'first surviving package is coreutils'
assert_eq '9.1' "${RPM_INSTALLED_VERSIONS[0]}" 'with its own real version, unaffected by the nameless row that follows it'
assert_eq sed "${RPM_INSTALLED_NAMES[2]}" 'third and last surviving package is sed'
assert_eq '4.8' "${RPM_INSTALLED_VERSIONS[2]}" \
  'with its own real version - FAILS under a reading that lets the previous row empty version bleed into this one'

_mk_sqlite EMPTY_DB "CREATE TABLE Packages (name TEXT, epoch TEXT, version TEXT, release TEXT, arch TEXT);"

t_case 'an empty, genuinely-readable sqlite database (zero rows, the plain schema) enumerates to zero packages, never a refusal'
_rc=0
rpm_installed_enumerate "$EMPTY_DB" '' '' || _rc=$?
assert_eq 0 "$_rc" 'success with zero packages - the database exists, is readable, and genuinely carries no rows, which is not the same fact as no_package_db_found or rpm_db_binary_format'
assert_eq 0 "${#RPM_INSTALLED_NAMES[@]}" 'zero packages'
assert_eq '' "$_RPM_INSTALLED_REASON" 'no refusal reason - this is not a missing-DB or unreadable-format case'

# =============================================================================
printf -- '\n-- I. checks-rpm.rules registers alongside the module other five per-owner registries --\n'
# =============================================================================

t_case 'modules/image/checks-rpm.rules parses clean under the real record loader'
records_reset_diagnostics
_load_rc=0
records_load "$ROOT/modules/image/checks-rpm.rules" script-check rpmchecks || _load_rc=$?
assert_eq 0 "$_load_rc" 'records_load returns 0 - no schema/format errors'
assert_eq 0 "$RECORDS_ERRORS" \
  "modules/image/checks-rpm.rules has 0 record-format diagnostics - FAILS on a schema mistake (a bad tags/coverage-scope/cwe/owasp/requires-cmd value, a missing required key) that records_load would otherwise catch silently here and loudly only once scan.sh image loads every *.rules file at run time"

t_case 'it registers exactly the one rpm check id IMG-12 calls for, distinct from apks -01 and dpkgs -02'
assert_eq 1 "$(records_count rpmchecks)" 'exactly one record in the file'
assert_eq 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' "$(records_id rpmchecks 0)" \
  "that record's id - FAILS if it collided with apk's -01 or dpkg's -02, which checks-apk.rules/checks-dpkg.rules already own"

t_case 'it declares requires-cmd: sqlite3, so an rpm image scanned on a host without sqlite3 is a declared skip once this check is wired, never a silent pass'
assert_eq 'sqlite3' "$(records_field rpmchecks 0 requires-cmd)" \
  "the requires-cmd value - FAILS if it were absent, which would let a future run.sh wiring select this check on a host with no sqlite3 at all and attempt a doomed enumeration instead of a declared coverage reduction"

t_case 'every per-owner image registry is discoverable by the same *.rules glob checks_registry_load uses'
_files=$(cd -- "$ROOT/modules/image" && printf '%s\n' *.rules | sort)
assert_eq $'checks-advisories.rules\nchecks-apk.rules\nchecks-config.rules\nchecks-coverage.rules\nchecks-dpkg.rules\nchecks-langdeps.rules\nchecks-rpm.rules' "$_files" \
  'exactly these seven files (checks-rpm.rules added by IMG-12, checks-langdeps.rules added by IMG-11) - FAILS if a shared modules/image/checks.rules ever reappears (an explicitly forbidden shape) or if this ticket appended into checks-dpkg.rules instead of shipping its own'

t_summary image-rpm
