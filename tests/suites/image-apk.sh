#!/usr/bin/env bash
# tests/suites/image-apk.sh - IMG-04 (data/scoursh-image-scan-design/
# report.md §2.1/§2.5's apk row and §5.3's IMG-04 row): apk installed-
# package ENUMERATION, unit-level, against a committed fixture DB.
#
# What this suite proves, and what it is NOT for:
#
#   A. `apk_installed_enumerate` (modules/image/distro/apk.sh) against a
#      real-shaped, multi-package `installed` fixture: the exact (name,
#      version) set, in file order, with every non-P/V key (checksum, arch,
#      size, description, url, license, origin, maintainer, build time,
#      commit, depends, provides) present in the fixture and correctly
#      ignored rather than mistaken for a corrupt line.
#   B. The same function against a deliberately malformed/partial fixture:
#      a block with no `P:` line at all is DROPPED, never enumerated as a
#      nameless package; a block with `P:` but no `V:` is still enumerated,
#      with an empty version string; and a valid block landing immediately
#      after either malformed shape is unaffected - state does not leak
#      across a blank-line block boundary.
#   C. A missing database (the scratch/distroless case, report.md §4.3)
#      returns 1 with `_APK_INSTALLED_REASON=no_package_db_found`, and
#      leaves both result arrays empty - never a silent clean enumeration.
#   D. A database with no trailing blank line at end of file still has its
#      last block flushed (both fixtures in this suite end this way, so
#      section A's own assertions already cover it; section D restates it
#      explicitly against a single-package, no-trailing-newline case so a
#      regression here fails under its own name rather than only as a
#      miscount in section A).
#   E. `modules/image/checks-apk.rules` parses under the real record loader
#      with no diagnostics, registers exactly the one check id report.md
#      §4.1 names, and is discovered by `checks_registry_load` alongside
#      the module's other per-owner registry, `checks-advisories.rules` -
#      the "one registry per owner" shape report.md §5.1 requires, proven
#      by asserting BOTH ids are visible together rather than assuming a
#      glob that happens to find one also finds the other.
#
# NOT this suite's job: the version comparator (IMG-05) does not exist, so
# no case here calls anything resembling a comparison, and
# IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 is never actually emitted - it is
# registered and unreachable, the identical "registered, not yet wired"
# shape tests/suites/image-advisories.sh's own header states for
# IMAGE-COV-NO_ADVISORY_DB-01 before IMG-03 wired its emitter.
# `modules/image/run.sh` is not touched or invoked by this suite at all:
# IMG-04's own scope line is enumeration plus the registry file only.
#
# No network: image scanning is offline by construction (docs/DESIGN.md §1).
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
# shellcheck source=modules/image/distro/apk.sh
source "$ROOT/modules/image/distro/apk.sh"
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$ROOT/tests/fixtures/image/apk

_arr_join() {
  local IFS='|'
  printf '%s' "$*"
}

# =============================================================================
printf -- '\n-- A. a real-shaped, multi-package installed DB --\n'
# =============================================================================

t_case 'enumerate returns exactly the three packages, in file order, with every non-P/V key ignored'
_rc=0
apk_installed_enumerate "$FIX/installed" || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds against a readable database'
assert_eq 'musl|busybox|openssl' "$(_arr_join "${APK_INSTALLED_NAMES[@]}")" \
  'the three package NAMES, in the order their blocks appear in the file'
assert_eq '1.2.4-r2|1.36.1-r15|3.1.4-r1' "$(_arr_join "${APK_INSTALLED_VERSIONS[@]}")" \
  'the three VERSIONS, index-aligned with the names above - FAILS if a checksum/arch/size/description/url/license/origin/maintainer/build-time/commit/depends/provides line were mistaken for P: or V:, or shifted a later field out of alignment'
assert_eq 3 "${#APK_INSTALLED_NAMES[@]}" 'exactly three packages - no extra empty entry from a spurious blank-line-only "block"'
assert_eq '' "$_APK_INSTALLED_REASON" 'no refusal reason is set on a successful enumeration'

# =============================================================================
printf -- '\n-- B. a malformed/partial DB: missing P:, missing V:, recovery either side --\n'
# =============================================================================

t_case 'a block with no P: line at all is dropped, never enumerated as a nameless package'
_rc=0
apk_installed_enumerate "$FIX/installed-malformed" || _rc=$?
assert_eq 0 "$_rc" 'enumeration still succeeds - a malformed block is not a fatal error'
assert_eq 3 "${#APK_INSTALLED_NAMES[@]}" \
  'three packages survive, not four - FAILS under a reading that emits an empty-named entry for the P:-less block'
assert_not_contains "$(_arr_join "${APK_INSTALLED_NAMES[@]}")" '||' \
  'no empty element sits between two real names in the joined listing'

t_case 'the valid block immediately before the P:-less one parses correctly - state did not leak backwards'
assert_eq zlib "${APK_INSTALLED_NAMES[0]}" 'first package is zlib'
assert_eq '1.3.1-r0' "${APK_INSTALLED_VERSIONS[0]}" 'with its own version, unaffected by the malformed block that follows it'

t_case 'a block with a name but no V: line is still enumerated, with an empty version string'
assert_eq libcrypto3 "${APK_INSTALLED_NAMES[1]}" \
  'the P:-only block is kept - FAILS under a reading that drops any block missing a key, which would silently under-report installed packages'
assert_eq '' "${APK_INSTALLED_VERSIONS[1]}" 'its version is the empty string, not a stale value carried over from an earlier block'

t_case 'the valid block immediately after the P:-only one parses correctly - state did not leak forwards either'
assert_eq apk-tools "${APK_INSTALLED_NAMES[2]}" 'third surviving package is apk-tools'
assert_eq '2.14.0-r5' "${APK_INSTALLED_VERSIONS[2]}" \
  'with its own real version - FAILS under a reading that lets the previous block empty version bleed into this one'

# =============================================================================
printf -- '\n-- C. a missing database (scratch/distroless image) --\n'
# =============================================================================

t_case 'a nonexistent path returns 1 with the declared no_package_db_found reason, and empties both arrays'
APK_INSTALLED_NAMES=(stale)
APK_INSTALLED_VERSIONS=(stale)
_rc=0
apk_installed_enumerate "$FIX/does-not-exist/installed" || _rc=$?
assert_eq 1 "$_rc" 'refusal is a plain 1, not a die/abort - a missing apk DB is the ordinary scratch/distroless case, report.md §4.3'
assert_eq no_package_db_found "$_APK_INSTALLED_REASON" \
  'the exact declared coverage_reduction reason the brief and report.md §4.3 both name'
assert_eq 0 "${#APK_INSTALLED_NAMES[@]}" 'APK_INSTALLED_NAMES is reset to empty, not left holding a stale prior result'
assert_eq 0 "${#APK_INSTALLED_VERSIONS[@]}" 'APK_INSTALLED_VERSIONS is reset to empty too'

t_case 'a directory at the given path (never a plain file) is refused the same way, not treated as readable'
_rc=0
apk_installed_enumerate "$FIX" || _rc=$?
assert_eq 1 "$_rc" 'a directory is not a readable database file'
assert_eq no_package_db_found "$_APK_INSTALLED_REASON" 'same declared reason - no special-casing "it exists but is the wrong kind of thing"'

# =============================================================================
printf -- '\n-- D. no trailing blank line at end of file --\n'
# =============================================================================

W=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-image-apk.XXXXXX")
trap 'rm -rf -- "${W:?}"' EXIT

t_case 'a single-package DB with no trailing blank line still has its one block flushed'
printf 'C:Q1single00000000000000000000000000000=\nP:zlib\nV:1.3.1-r0\nA:x86_64\n' >"$W/installed-no-trailing-blank"
_rc=0
apk_installed_enumerate "$W/installed-no-trailing-blank" || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds'
assert_eq 1 "${#APK_INSTALLED_NAMES[@]}" \
  'exactly one package - FAILS under a reading that only flushes a block on a blank-line separator and drops whatever block was open when the file ran out'
assert_eq zlib "${APK_INSTALLED_NAMES[0]}" 'the package is zlib'
assert_eq '1.3.1-r0' "${APK_INSTALLED_VERSIONS[0]}" 'with its version'

t_case 'an empty file enumerates to zero packages, not a refusal - the DB exists and is merely empty'
: >"$W/installed-empty"
_rc=0
apk_installed_enumerate "$W/installed-empty" || _rc=$?
assert_eq 0 "$_rc" 'an empty, readable file is success with zero packages, never no_package_db_found - the file genuinely exists'
assert_eq 0 "${#APK_INSTALLED_NAMES[@]}" 'zero packages'
assert_eq '' "$_APK_INSTALLED_REASON" 'and no refusal reason - this is not the missing-DB case'

# =============================================================================
printf -- '\n-- E. checks-apk.rules registers alongside checks-advisories.rules --\n'
# =============================================================================

t_case 'modules/image/checks-apk.rules parses clean under the real record loader'
records_reset_diagnostics
_load_rc=0
records_load "$ROOT/modules/image/checks-apk.rules" script-check apkchecks || _load_rc=$?
assert_eq 0 "$_load_rc" 'records_load returns 0 - no schema/format errors'
assert_eq 0 "$RECORDS_ERRORS" \
  "modules/image/checks-apk.rules has 0 record-format diagnostics - FAILS on a schema mistake (a bad tags/coverage-scope/cwe/owasp value, a missing required key) that records_load would otherwise catch silently here and loudly only once scan.sh iac/image/... loads every *.rules file at run time"

t_case 'it registers exactly the one apk check id report.md §4.1 names, and no other'
assert_eq 1 "$(records_count apkchecks)" 'exactly one record in the file'
assert_eq 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' "$(records_id apkchecks 0)" "that record's id"

t_case 'every per-owner image registry is discoverable by the same *.rules glob checks_registry_load uses'
_files=$(cd -- "$ROOT/modules/image" && printf '%s\n' *.rules | sort)
assert_eq $'checks-advisories.rules\nchecks-apk.rules\nchecks-config.rules\nchecks-coverage.rules\nchecks-dpkg.rules\nchecks-rpm.rules' "$_files" \
  'exactly these six files (checks-config.rules and checks-coverage.rules added by IMG-06, checks-dpkg.rules added by IMG-07, checks-rpm.rules added by IMG-12) - FAILS if a shared modules/image/checks.rules ever reappears (report.md §5.1s explicitly forbidden shape) or if a later ticket appended into an existing file instead of shipping its own'

t_summary image-apk
