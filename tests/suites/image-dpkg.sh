#!/usr/bin/env bash
# tests/suites/image-dpkg.sh - IMG-07: dpkg installed-package
# ENUMERATION, unit-level, against committed fixture status files.
#
# What this suite proves, and what it is NOT for:
#
#   A. `dpkg_installed_enumerate` (modules/image/distro/dpkg.sh) against a
#      real-shaped, multi-package `status` fixture: the exact (name,
#      version, resolved-source) set, in file order, with every non-
#      Package/Status/Version/Source key (Priority, Section,
#      Installed-Size, Maintainer, Architecture, Multi-Arch, Depends,
#      Conffiles, a multi-line Description including a period-only
#      continuation line) present in the fixture and correctly ignored
#      rather than mistaken for a corrupt line or a new block.
#      TRAP 1 (the Status gate): a package whose
#      Status is `deinstall ok config-files` (files removed, only
#      conffiles remain) is EXCLUDED - the fixture plants `perl-base` in
#      that exact state so this suite fails if the gate is dropped. A
#      second package (`half-broken-pkg`) carries `Status: install
#      reinst-required installed`, whose word THREE literally reads
#      "installed" - it is also EXCLUDED, proving the gate is an EXACT
#      three-word match, not a substring/contains test that a naive
#      `[[ $status == *installed* ]]` reading would wrongly pass.
#      TRAP 2 (Source: vs Package:): `bash` carries
#      no `Source:` line at all and must resolve to source name `bash`
#      (the explicit fallback); `zlib1g`/`libssl3` carry a plain `Source:`
#      naming a different package (`zlib`/`openssl`); `libc6` carries a
#      `Source:` with a parenthesised version override
#      (`glibc (2.31-13)`) and must resolve to the bare name `glibc`, not
#      the whole field.
#   B. The same function against a deliberately malformed/partial fixture:
#      a block with no `Package:` line at all is DROPPED, never enumerated
#      as a nameless package, regardless of its own Status/Version; a
#      block with a `Package:` but no `Status:` line at all is DROPPED by
#      the same gate that drops a deinstall/config-files package (an
#      absent status can never equal the one accepted string); a block
#      that passes both gates but carries no `Version:` line is still
#      enumerated, with an empty version string; and a valid block landing
#      immediately before or after any of these three shapes is
#      unaffected - state does not leak across a blank-line block
#      boundary in either direction.
#   C. A missing database (an Alpine image, or a scratch/distroless image)
#      returns 1 with
#      `_DPKG_INSTALLED_REASON=no_package_db_found`, and leaves all three
#      result arrays empty. A directory at the given path is refused the
#      same way, never treated as a readable file.
#   D. A database with no trailing blank line at end of file still has its
#      last block flushed (the main `status` fixture already ends this
#      way, so section A's own assertions already cover it; section D
#      restates it explicitly against a single-package, no-trailing-
#      newline case so a regression here fails under its own name rather
#      than only as a miscount in section A). An empty, readable file
#      enumerates to zero packages, never a refusal.
#   E. `modules/image/checks-dpkg.rules` parses under the real record
#      loader with no diagnostics, registers exactly the one dpkg check id
#      IMG-07 calls for
#      (`IMAGE-PKG-VULNERABLE_OS_PACKAGE-02`, distinct from apk's own `-01`
#      id in its own `checks-apk.rules`), and is discovered by
#      `checks_registry_load` alongside every other per-owner registry
#      under `modules/image/` - the "one registry per owner" shape this
#      module requires.
#
# NOT this suite's job: no version comparator exists for dpkg yet (IMG-08),
# no advisory matching exists (IMG-09), and IMAGE-PKG-VULNERABLE_OS_PACKAGE-02
# is never actually emitted - it is registered and unreachable, the identical
# "registered, not yet wired" shape tests/suites/image-apk.sh's own header
# states IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 was in from IMG-04 through IMG-05.
# `modules/image/run.sh` is not touched or invoked by this suite at all, and
# `var/lib/dpkg/status` is not even in that file's own wanted-path list yet -
# IMG-07's own scope line is enumeration plus the registry file only.
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
# shellcheck source=modules/image/distro/dpkg.sh
source "$ROOT/modules/image/distro/dpkg.sh"
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$ROOT/tests/fixtures/image/dpkg

_arr_join() {
  local IFS='|'
  printf '%s' "$*"
}

# =============================================================================
printf -- '\n-- A. a real-shaped, multi-package status DB --\n'
# =============================================================================

t_case 'enumerate returns exactly the four installed packages, in file order, with every non-key line ignored'
_rc=0
dpkg_installed_enumerate "$FIX/status" || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds against a readable database'
assert_eq 'bash|zlib1g|libssl3|libc6' "$(_arr_join "${DPKG_INSTALLED_NAMES[@]}")" \
  'the four installed package NAMES, in file order - FAILS if perl-base (deinstall ok config-files) or half-broken-pkg (install reinst-required installed) were wrongly included, or if a Priority/Section/Installed-Size/Maintainer/Architecture/Multi-Arch/Depends/Description/Conffiles line were mistaken for Package:/Status:/Version:/Source: or shifted a later field out of alignment'
assert_eq '5.2.15-2+b1|1:1.2.13.dfsg-1|3.0.11-1~deb12u2|2.31-13+deb11u1' "$(_arr_join "${DPKG_INSTALLED_VERSIONS[@]}")" \
  'the four VERSIONS, index-aligned with the names above'
assert_eq 4 "${#DPKG_INSTALLED_NAMES[@]}" 'exactly four packages - two were excluded by the Status gate'
assert_eq '' "$_DPKG_INSTALLED_REASON" 'no refusal reason is set on a successful enumeration'

t_case 'the Source: fallback (trap 2) resolves all four cases correctly'
assert_eq 'bash|zlib|openssl|glibc' "$(_arr_join "${DPKG_INSTALLED_SOURCES[@]}")" \
  'bash has no Source: line at all and falls back explicitly to its own Package: name; zlib1g/libssl3 resolve to their plain Source: values; libc6 resolves to the bare name glibc with the "(2.31-13)" version override stripped, never the whole "glibc (2.31-13)" field - FAILS under a reading that leaves the fallback implicit (an empty string) or fails to strip a parenthesised source version'

t_case 'perl-base (Status: deinstall ok config-files) is excluded by the Status gate (trap 1)'
assert_not_contains "$(_arr_join "${DPKG_INSTALLED_NAMES[@]}")" 'perl-base' \
  'perl-base must never appear in the enumerated set - it has been removed and only its conffiles remain, so reporting it installed is a false positive on nearly every Debian/Ubuntu image - FAILS if the Status gate is dropped or checks for anything other than the exact string "install ok installed"'

t_case 'half-broken-pkg (Status: install reinst-required installed) is excluded too - the gate is EXACT, not a substring test'
assert_not_contains "$(_arr_join "${DPKG_INSTALLED_NAMES[@]}")" 'half-broken-pkg' \
  'its Status line contains the word "installed" as its third token, which a naive [[ $status == *installed* ]] substring test would wrongly accept - FAILS under exactly that reading, and only an exact "install ok installed" comparison excludes it correctly'

# =============================================================================
printf -- '\n-- B. a malformed/partial DB: missing Package:, missing Status:, missing Version:, recovery each side --\n'
# =============================================================================

t_case 'a block with no Package: line at all is dropped, never enumerated as a nameless package'
_rc=0
dpkg_installed_enumerate "$FIX/status-malformed" || _rc=$?
assert_eq 0 "$_rc" 'enumeration still succeeds - a malformed block is not a fatal error'
assert_eq 5 "${#DPKG_INSTALLED_NAMES[@]}" \
  'five packages survive - FAILS under a reading that emits an empty-named entry for the Package:-less block, or that fails to also drop the Status:-less block'
assert_eq 'zlib1g|coreutils|sed|no-version-pkg|grep' "$(_arr_join "${DPKG_INSTALLED_NAMES[@]}")" \
  'the five surviving names, in file order - no-status-pkg is absent (dropped by the Status gate) and the Package:-less block never contributed an entry at all'

t_case 'the valid block immediately before the Package:-less one parses correctly - state did not leak backwards'
assert_eq zlib1g "${DPKG_INSTALLED_NAMES[0]}" 'first surviving package is zlib1g'
assert_eq '1:1.2.13.dfsg-1' "${DPKG_INSTALLED_VERSIONS[0]}" 'with its own version, unaffected by the malformed block that follows it'

t_case 'the valid block immediately after the Package:-less one parses correctly - state did not leak forwards'
assert_eq coreutils "${DPKG_INSTALLED_NAMES[1]}" 'second surviving package is coreutils'
assert_eq '9.1-1' "${DPKG_INSTALLED_VERSIONS[1]}" \
  'with its own real version - FAILS under a reading that lets the previous Package:-less block bleed a stale value into this one'

t_case 'a block with a Package: line but no Status: line at all is dropped by the same gate as an explicit deinstall status'
assert_not_contains "$(_arr_join "${DPKG_INSTALLED_NAMES[@]}")" 'no-status-pkg' \
  'an absent Status: can never equal "install ok installed" - FAILS under a reading that treats a missing Status: as installed by default, which would silently over-report every partially-written or corrupted status block as present'

t_case 'the valid block immediately after the Status:-less one parses correctly'
assert_eq sed "${DPKG_INSTALLED_NAMES[2]}" 'third surviving package is sed'
assert_eq '4.9-2' "${DPKG_INSTALLED_VERSIONS[2]}" 'with its own real version, unaffected by the Status:-less block before it'

t_case 'a block with a name and a passing Status: but no Version: line is still enumerated, with an empty version string'
assert_eq 'no-version-pkg' "${DPKG_INSTALLED_NAMES[3]}" \
  'the Version:-less block is kept - FAILS under a reading that drops any block missing a key, which would silently under-report installed packages'
assert_eq '' "${DPKG_INSTALLED_VERSIONS[3]}" 'its version is the empty string, not a stale value carried over from an earlier block'
assert_eq 'no-version-pkg' "${DPKG_INSTALLED_SOURCES[3]}" 'its resolved source falls back to its own Package: name, since no Source: line was present either'

t_case 'the valid block immediately after the Version:-less one parses correctly - state did not leak forwards either'
assert_eq grep "${DPKG_INSTALLED_NAMES[4]}" 'fifth and last surviving package is grep'
assert_eq '3.11-3' "${DPKG_INSTALLED_VERSIONS[4]}" \
  'with its own real version - FAILS under a reading that lets the previous block empty version bleed into this one'

# =============================================================================
printf -- '\n-- C. a missing database (an Alpine image, or a scratch/distroless image) --\n'
# =============================================================================

t_case 'a nonexistent path returns 1 with the declared no_package_db_found reason, and empties all three arrays'
DPKG_INSTALLED_NAMES=(stale)
DPKG_INSTALLED_VERSIONS=(stale)
DPKG_INSTALLED_SOURCES=(stale)
_rc=0
dpkg_installed_enumerate "$FIX/does-not-exist/status" || _rc=$?
assert_eq 1 "$_rc" 'refusal is a plain 1, not a die/abort - a missing dpkg DB is the ordinary Alpine/scratch/distroless case'
assert_eq no_package_db_found "$_DPKG_INSTALLED_REASON" \
  'the exact declared coverage_reduction reason for this case'
assert_eq 0 "${#DPKG_INSTALLED_NAMES[@]}" 'DPKG_INSTALLED_NAMES is reset to empty, not left holding a stale prior result'
assert_eq 0 "${#DPKG_INSTALLED_VERSIONS[@]}" 'DPKG_INSTALLED_VERSIONS is reset to empty too'
assert_eq 0 "${#DPKG_INSTALLED_SOURCES[@]}" 'DPKG_INSTALLED_SOURCES is reset to empty too'

t_case 'a directory at the given path (never a plain file) is refused the same way, not treated as readable'
_rc=0
dpkg_installed_enumerate "$FIX" || _rc=$?
assert_eq 1 "$_rc" 'a directory is not a readable database file'
assert_eq no_package_db_found "$_DPKG_INSTALLED_REASON" 'same declared reason - no special-casing "it exists but is the wrong kind of thing"'

# =============================================================================
printf -- '\n-- D. no trailing blank line at end of file --\n'
# =============================================================================

W=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-image-dpkg.XXXXXX")
trap 'rm -rf -- "${W:?}"' EXIT

t_case 'a single-package DB with no trailing blank line still has its one block flushed'
printf 'Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13.dfsg-1\nArchitecture: amd64\n' >"$W/status-no-trailing-blank"
_rc=0
dpkg_installed_enumerate "$W/status-no-trailing-blank" || _rc=$?
assert_eq 0 "$_rc" 'enumeration succeeds'
assert_eq 1 "${#DPKG_INSTALLED_NAMES[@]}" \
  'exactly one package - FAILS under a reading that only flushes a block on a blank-line separator and drops whatever block was open when the file ran out'
assert_eq zlib1g "${DPKG_INSTALLED_NAMES[0]}" 'the package is zlib1g'
assert_eq '1:1.2.13.dfsg-1' "${DPKG_INSTALLED_VERSIONS[0]}" 'with its version'
assert_eq zlib1g "${DPKG_INSTALLED_SOURCES[0]}" 'and its source falls back to its own name, since no Source: line was present'

t_case 'an empty file enumerates to zero packages, not a refusal - the DB exists and is merely empty'
: >"$W/status-empty"
_rc=0
dpkg_installed_enumerate "$W/status-empty" || _rc=$?
assert_eq 0 "$_rc" 'an empty, readable file is success with zero packages, never no_package_db_found - the file genuinely exists'
assert_eq 0 "${#DPKG_INSTALLED_NAMES[@]}" 'zero packages'
assert_eq '' "$_DPKG_INSTALLED_REASON" 'and no refusal reason - this is not the missing-DB case'

# =============================================================================
printf -- '\n-- E. checks-dpkg.rules registers alongside checks-apk.rules and the module''s other per-owner registries --\n'
# =============================================================================

t_case 'modules/image/checks-dpkg.rules parses clean under the real record loader'
records_reset_diagnostics
_load_rc=0
records_load "$ROOT/modules/image/checks-dpkg.rules" script-check dpkgchecks || _load_rc=$?
assert_eq 0 "$_load_rc" 'records_load returns 0 - no schema/format errors'
assert_eq 0 "$RECORDS_ERRORS" \
  "modules/image/checks-dpkg.rules has 0 record-format diagnostics - FAILS on a schema mistake (a bad tags/coverage-scope/cwe/owasp value, a missing required key) that records_load would otherwise catch silently here and loudly only once scan.sh image loads every *.rules file at run time"

t_case 'it registers exactly the one dpkg check id IMG-07 calls for, distinct from apks own -01 id'
assert_eq 1 "$(records_count dpkgchecks)" 'exactly one record in the file'
assert_eq 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' "$(records_id dpkgchecks 0)" \
  "that record's id - FAILS if it collided with apk's own IMAGE-PKG-VULNERABLE_OS_PACKAGE-01, which checks-apk.rules already owns"

t_case 'every per-owner image registry is discoverable by the same *.rules glob checks_registry_load uses'
_files=$(cd -- "$ROOT/modules/image" && printf '%s\n' *.rules | sort)
assert_eq $'checks-advisories.rules\nchecks-apk.rules\nchecks-config.rules\nchecks-coverage.rules\nchecks-dpkg.rules\nchecks-langdeps.rules\nchecks-rpm.rules' "$_files" \
  'exactly these seven files (checks-dpkg.rules added by IMG-07, checks-rpm.rules added by IMG-12, checks-langdeps.rules added by IMG-11) - FAILS if a shared modules/image/checks.rules ever reappears (an explicitly forbidden shape) or if this ticket appended into checks-apk.rules instead of shipping its own'

t_summary image-dpkg
