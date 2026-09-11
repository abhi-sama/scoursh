#!/usr/bin/env bash
# tests/suites/image-debian.sh - IMG-09: completes the dpkg (Debian/Ubuntu) slice END TO END -
# the Debian/Ubuntu advisory ecosystems PLUS wiring IMG-07's dpkg enumerator
# and IMG-08's dpkg comparator into the real vulnerable-package finding path,
# mirroring what tests/suites/image-e2e.sh (IMG-06) already proved for apk.
#
# What this suite proves, and what it is NOT for:
#
#   A. `image_distro_ecosystem_resolve` (modules/image/engine.sh), unit
#      level: `ID=debian` resolves to the bare-MAJOR `Debian:N` key (never
#      the point release), `ID=ubuntu` resolves to the major.minor
#      `Ubuntu:XX.YY` key (identically shaped to Alpine's own), a different
#      Debian major resolves to a DIFFERENT ecosystem key, and an
#      unparseable VERSION_ID for either distro refuses rather than
#      guesses - the identical `os_release_version_unparseable` discipline
#      `tests/suites/image-advisories.sh` section A already pins for
#      alpine.
#   B. End to end, through real `scan.sh image` subprocesses against a
#      synthetic Debian-shaped docker-archive fixture carrying a real
#      `var/lib/dpkg/status`: a vulnerable dpkg package - `libssl3`, whose
#      `Source:` names a DIFFERENT package, `openssl` (the Source:-vs-Package:
#      trap, deliberately exercised: binary name != source name) - fires
#      `IMAGE-PKG-VULNERABLE_OS_PACKAGE-02` with `loc_package` carrying the
#      SOURCE name, is quiet once the installed version reaches the fixed
#      version, and the run-over-run diff (same operator-declared --image
#      id) reads the patched CVE as `fixed`, never
#      `unknown`+`new`.
#   C. The advisory-db exit-4 gate (IMG-03's mechanism, reused unchanged)
#      fires correctly for a resolved `Debian:12` ecosystem the fixture db
#      does not cover, and does not fire when it does - mirroring
#      `tests/suites/image-advisories.sh` section C's alpine coverage.
#   D. A resolved, covered Debian/Ubuntu ecosystem with NO
#      `var/lib/dpkg/status` member in any layer reports
#      `IMAGE-COV-UNKNOWN_DISTRO-01` with `manager=dpkg` (never `apk`) -
#      proving `image_report_unknown_distro`'s IMG-09 widening to an
#      explicit MANAGER argument reaches the right branch.
#   E. `veng_advisories_debian`/`veng_advisories_ubuntu`
#      (tools/vendor-engines.sh) are exercised as their own dedicated
#      sections of tests/suites/vendor-engines-advisories.sh (D4/D5), not
#      duplicated here - this suite consumes their OUTPUT (a hand-built
#      fixture data/advisories.db in the exact row shape they write) rather
#      than re-proving the importer itself.
#
# NOT this suite's job: apk/Alpine (tests/suites/image-e2e.sh, IMG-06) or
# rpm (IMG-12, unbuilt).
#
# No network: image scanning is offline by construction (docs/DESIGN.md
# §1), and this suite never puts curl/wget/aws on PATH at all.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SCOURSH_INSTALL_ROOT=$ROOT
# shellcheck source=modules/image/engine.sh
source "$ROOT/modules/image/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$ROOT/tests/fixtures/image/mkustar.sh"

W=$SCOURSH_SCRATCH/image-debian
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- A. image_distro_ecosystem_resolve: debian/ubuntu --\n'
# =============================================================================

t_case 'debian: a bare major VERSION_ID resolves to Debian:N, never a point release'
cat >"$W/os-release-debian12" <<'EOF'
ID=debian
VERSION_ID=12
EOF
image_distro_ecosystem_resolve "$W/os-release-debian12"
_rc=$?
assert_eq 0 "$_rc" 'resolves'
assert_eq 'Debian:12' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'the OSV.dev Debian namespace is MAJOR-ONLY - FAILS under a reading that kept a point-release suffix (e.g. Debian:12.5), which data/advisories.db never carries a row under'

t_case 'debian: a VERSION_ID carrying a point-release digit still resolves on its LEADING major run'
cat >"$W/os-release-debian12-point" <<'EOF'
ID=debian
VERSION_ID=12.5
EOF
image_distro_ecosystem_resolve "$W/os-release-debian12-point"
assert_eq 'Debian:12' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'the trailing .5 is dropped - matching only the leading digit run rather than requiring the whole field to be one bare integer'

t_case 'debian: a different major resolves to a DIFFERENT ecosystem key'
cat >"$W/os-release-debian11" <<'EOF'
ID=debian
VERSION_ID=11
EOF
image_distro_ecosystem_resolve "$W/os-release-debian11"
assert_eq 'Debian:11' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'Debian:11 != Debian:12 - FAILS under any reading that collapses every Debian image onto one fixed key'

t_case 'debian: an unparseable VERSION_ID refuses, never guesses'
cat >"$W/os-release-debian-bad" <<'EOF'
ID=debian
VERSION_ID=bookworm
EOF
_rc=0
image_distro_ecosystem_resolve "$W/os-release-debian-bad" || _rc=$?
assert_eq 1 "$_rc" 'refused - "bookworm" carries no leading digit run to build an OSV.dev ecosystem key from'
assert_eq os_release_version_unparseable "$_IMAGE_DISTRO_REASON" 'the specific reason'
assert_eq '' "$_IMAGE_DISTRO_ECOSYSTEM" 'and no ecosystem is guessed'

t_case 'ubuntu: a major.minor VERSION_ID resolves to Ubuntu:XX.YY, identically shaped to alpine'"'"'s own key'
cat >"$W/os-release-ubuntu2204" <<'EOF'
ID=ubuntu
VERSION_ID=22.04
EOF
image_distro_ecosystem_resolve "$W/os-release-ubuntu2204"
_rc=$?
assert_eq 0 "$_rc" 'resolves'
assert_eq 'Ubuntu:22.04' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'VERSION_ID is already the exact ecosystem-key shape on a real Ubuntu image, so no reformatting beyond extraction is needed'

t_case 'ubuntu: a different release resolves to a DIFFERENT ecosystem key'
cat >"$W/os-release-ubuntu2004" <<'EOF'
ID=ubuntu
VERSION_ID=20.04
EOF
image_distro_ecosystem_resolve "$W/os-release-ubuntu2004"
assert_eq 'Ubuntu:20.04' "$_IMAGE_DISTRO_ECOSYSTEM" 'Ubuntu:20.04 != Ubuntu:22.04'

t_case 'ubuntu: an unparseable VERSION_ID refuses, never guesses'
cat >"$W/os-release-ubuntu-bad" <<'EOF'
ID=ubuntu
VERSION_ID=jammy
EOF
_rc=0
image_distro_ecosystem_resolve "$W/os-release-ubuntu-bad" || _rc=$?
assert_eq 1 "$_rc" 'refused - "jammy" carries no major.minor'
assert_eq os_release_version_unparseable "$_IMAGE_DISTRO_REASON" 'the specific reason'

# =============================================================================
printf -- '\n-- B/C/D. end to end: scan.sh image against synthetic Debian/Ubuntu images --\n'
# =============================================================================

# `_mkimg NAME OS_RELEASE DPKG_STATUS` - a one-layer docker-save tarball
# carrying etc/os-release and (when non-empty) var/lib/dpkg/status, built at
# test time exactly the way tests/suites/image-e2e.sh's own `_mkimg` is
# (mkustar.sh's own header explains why). An empty DPKG_STATUS omits the
# member entirely, for section D's "no dpkg database at all" case.
_mkimg() {
  local name=$1 osrelease=$2 dpkgstatus=$3
  local tar=$W/$name.tar
  local l=$W/$name-layer.tar
  ustar_begin "$l"
  ustar_add "$l" 'etc/' 5 '' ''
  ustar_add "$l" 'etc/os-release' 0 '' "$osrelease"
  if [[ -n $dpkgstatus ]]; then
    ustar_add "$l" 'var/' 5 '' ''
    ustar_add "$l" 'var/lib/' 5 '' ''
    ustar_add "$l" 'var/lib/dpkg/' 5 '' ''
    ustar_add "$l" 'var/lib/dpkg/status' 0 '' "$dpkgstatus"
  fi
  ustar_end "$l"
  ustar_begin "$tar"
  ustar_add "$tar" 'cfg.json' 0 '' '{"architecture":"amd64","os":"linux"}'
  ustar_add "$tar" 'l0/' 5 '' ''
  ustar_add_file "$tar" 'l0/layer.tar' "$l"
  ustar_add "$tar" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/'"$name"':v1"],"Layers":["l0/layer.tar"]}]'
  ustar_end "$tar"
  printf '%s' "$tar"
}

# `_image_scan RUNDIR ADVISORIES_DB -- ARGS...` - a real `scan.sh image`
# subprocess, mirroring tests/suites/image-e2e.sh's own identical helper.
_image_scan() {
  local rundir=$1 db=$2
  shift 2
  [[ $1 == -- ]] && shift
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$ROOT SCOURSH_SCA_ADVISORIES_DB=$db \
    bash "$ROOT/scan.sh" image --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

DEBIAN_OSREL='ID=debian
VERSION_ID=12
'
# `libssl3` is the BINARY package; `Source: openssl` is a DIFFERENT name -
# the Source:-vs-Package: trap, deliberately exercised so this suite fails if
# the lookup ever fell back to the binary name.
DPKG_VULN='Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.11-1~deb12u2
Depends: libc6 (>= 2.34)
Description: Secure Sockets Layer toolkit - shared libraries
 libssl3 is part of the OpenSSL project'"'"'s implementation.
'
DPKG_FIXED='Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.11-1~deb12u3
Depends: libc6 (>= 2.34)
Description: Secure Sockets Layer toolkit - shared libraries
 libssl3 is part of the OpenSSL project'"'"'s implementation.
'

FIXDB=$W/advisories.db
cat >"$FIXDB" <<'EOF'
# scoursh image-debian test fixture advisories.db - NOT the real database.
# generated: 1970-01-01T00:00:00Z
Debian:12	openssl	3.0.11-1~deb12u2	SCOURSH-FIXTURE-CVE-DEB-1	high	3.0.11-1~deb12u3
Ubuntu:22.04	openssl	3.0.2-0ubuntu1.14	SCOURSH-FIXTURE-CVE-UBU-1	high	3.0.2-0ubuntu1.15
EOF

# -- C: the advisory-db exit-4 gate, for a real resolved Debian ecosystem --

VULN_IMG=$(_mkimg imgdeb-vuln "$DEBIAN_OSREL" "$DPKG_VULN")
IMG_ID=scoursh-img09-debian-e2e

t_case 'gate FIRES: a real Debian image resolves Debian:12, and an empty fixture db has NO rows for it - exit 4'
EMPTY_DB=$W/empty-advisories.db
printf '# empty\n' >"$EMPTY_DB"
_image_scan "$W/run-nodb" "$EMPTY_DB" -- --image "$IMG_ID-nodb" --source "$VULN_IMG"
assert_eq "$SCOURSH_EXIT_INPUT" "$_RC" \
  'exit 4 (SCOURSH_EXIT_INPUT), mirroring the alpine gate tests/suites/image-advisories.sh section C already pins'
assert_contains "$(_slurp "$W/run-nodb/run.json")" 'reason=no_advisories_db_for_ecosystem' \
  'the declared reduction fires - FAILS if debian bypassed the SAME gate mechanism alpine uses'

t_case 'gate does NOT fire: the fixture db HAS rows for Debian:12 - exit 0'
_image_scan "$W/run-withdb" "$FIXDB" -- --image "$IMG_ID" --source "$VULN_IMG"
assert_eq 0 "$_RC" 'exit 0 - the fixture db genuinely covers Debian:12'
assert_not_contains "$(_slurp "$W/run-withdb/findings.jsonl")" 'IMAGE-COV-NO_ADVISORY_DB-01' \
  'no coverage-gap finding this time - the ecosystem IS known'

# -- B: the real finding, keyed on the SOURCE package name --

t_case 'run 1 (vulnerable): IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 fires, keyed on the SOURCE package (openssl), not the binary (libssl3)'
RUN1_JSON=$(_slurp "$W/run-withdb/run.json")
RUN1_FINDINGS=$(_slurp "$W/run-withdb/findings.jsonl")
assert_contains "$RUN1_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' 'checks_run names the dpkg package check'
assert_contains "$RUN1_FINDINGS" '"check_id":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-02"' 'a real finding was emitted'
assert_contains "$RUN1_FINDINGS" '"module":"image"' 'under module image'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'loc_package=openssl' \
  'the SOURCE name, not the binary - FAILS if the lookup (or the emitted location) ever used libssl3 instead of its Source: fallback'
assert_not_contains "$RUN1_FINDINGS" 'loc_package=libssl3' \
  'the binary name never appears as the finding'"'"'s own package identity'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'loc_advisory_id=SCOURSH-FIXTURE-CVE-DEB-1' 'and the right advisory'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'binary_package: libssl3' \
  'the binary package IS still recorded, in the evidence - traceability without corrupting the fingerprint identity'
assert_contains "$RUN1_FINDINGS" '"location":{"image_id":"'"$IMG_ID"'","ecosystem":"Debian:12","package":"openssl","advisory_id":"SCOURSH-FIXTURE-CVE-DEB-1"' \
  'the JSON location object leads with EXACTLY these four keys, in this order, mirroring apk'"'"'s own IMG-06 assertion - image_id/ecosystem/package/advisory_id, NOT the version'

t_case 'the finding round-trips through every report format'
assert_contains "$(_slurp "$W/run-withdb/report.md")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' 'report.md lists it'
SARIF1=$(_slurp "$W/run-withdb/report.sarif")
assert_contains "$SARIF1" '"ruleId":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-02"' 'report.sarif names the check as its ruleId'

t_case 'run 2, SAME --image id, package upgraded to its fixed version: quiet for the package check'
FIXED_IMG=$(_mkimg imgdeb-fixed "$DEBIAN_OSREL" "$DPKG_FIXED")
_image_scan "$W/run2" "$FIXDB" -- --image "$IMG_ID" --source "$FIXED_IMG"
assert_eq 0 "$_RC" 'exit 0'
RUN2_JSON=$(_slurp "$W/run2/run.json")
RUN2_FINDINGS=$(_slurp "$W/run2/findings.jsonl")
assert_not_contains "$RUN2_FINDINGS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' \
  'openssl@3.0.11-1~deb12u3 is AT the fixed version - quiet this run, not merely "not new" - FAILS under a comparator that cannot order the tilde correctly'
assert_contains "$RUN2_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' \
  'checks_run STILL names the package check - it executed and found nothing, a different fact from "did not run"'

t_case 'the run-over-run DIFF reads the patched CVE as fixed, never unknown+new - the whole point of the image-id cell'
assert_contains "$RUN2_JSON" '"fixed"' 'run.json carries at least one fixed-classified finding this run'
REPORT2=$(_slurp "$W/run2/report.md")
assert_contains "$REPORT2" 'Fixed since last scan' \
  'report.md renders the fixed-since-last-scan section for this run - FAILS if diff_classify_run never ran, or the (check,cell) coverage did not match run 1'
assert_contains "$REPORT2" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' 'and names the specific check under it'

# -- D: a resolved, covered ecosystem with NO dpkg database at all --

t_case 'a resolved, covered Debian ecosystem with NO var/lib/dpkg/status in any layer reports IMAGE-COV-UNKNOWN_DISTRO-01 with manager=dpkg, never apk'
NODPKG_IMG=$(_mkimg imgdeb-nodpkg "$DEBIAN_OSREL" '')
_image_scan "$W/run-nodpkg" "$FIXDB" -- --image "$IMG_ID-nodpkg" --source "$NODPKG_IMG"
assert_eq 0 "$_RC" 'exit 0 - an unreadable/absent package database is a declared reduction, not a fatal error'
RUN_NODPKG_JSON=$(_slurp "$W/run-nodpkg/run.json")
assert_contains "$RUN_NODPKG_JSON" 'reason=no_package_db_found' 'the declared reduction fires'
assert_contains "$(_slurp "$W/run-nodpkg/findings.jsonl")" '"check_id":"IMAGE-COV-UNKNOWN_DISTRO-01"' \
  'a real finding was emitted'
assert_contains "$(_slurp "$W/run-nodpkg/findings.fields")" 'manager: dpkg' \
  'the finding'"'"'s evidence names dpkg as the missing manager - FAILS if image_report_unknown_distro'"'"'s IMG-09 widening defaulted every caller to apk'"'"'s own wording'
assert_not_contains "$(_slurp "$W/run-nodpkg/findings.jsonl")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02' \
  'and no package finding, since none could be enumerated at all'

# -- Ubuntu: one lighter end-to-end pass, proving the SAME wiring path --

UBUNTU_OSREL='ID=ubuntu
VERSION_ID=22.04
'
DPKG_UBUNTU_VULN='Package: libssl3
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.2-0ubuntu1.14
Description: Secure Sockets Layer toolkit - shared libraries
'
UBUNTU_IMG=$(_mkimg imgubu-vuln "$UBUNTU_OSREL" "$DPKG_UBUNTU_VULN")
UBUNTU_ID=scoursh-img09-ubuntu-e2e

t_case 'ubuntu: end to end through the SAME dpkg wiring - IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 fires, keyed Ubuntu:22.04/openssl'
_image_scan "$W/run-ubuntu" "$FIXDB" -- --image "$UBUNTU_ID" --source "$UBUNTU_IMG"
assert_eq 0 "$_RC" 'exit 0'
RUN_UBUNTU_FINDINGS=$(_slurp "$W/run-ubuntu/findings.jsonl")
assert_contains "$RUN_UBUNTU_FINDINGS" '"check_id":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-02"' 'a real finding was emitted'
assert_contains "$RUN_UBUNTU_FINDINGS" '"location":{"image_id":"'"$UBUNTU_ID"'","ecosystem":"Ubuntu:22.04","package":"openssl","advisory_id":"SCOURSH-FIXTURE-CVE-UBU-1"' \
  'ubuntu resolves its OWN ecosystem key and matches its own fixture row - FAILS if debian and ubuntu were dispatched to the same branch and collided'

t_summary image-debian
