#!/usr/bin/env bash
# tests/suites/image-rpm-e2e.sh - the last rpm ticket (data/scoursh-image-
# scan-design/report.md §2.1's rpm row, §2.3's advisory-ecosystem-namespace
# row, and §5.3's IMG-12 row): completes the rpm (RHEL/Fedora) slice END TO
# END - the Red Hat advisory ecosystem PLUS wiring IMG-12's rpm enumerator
# and the rpmvercmp comparator into the real vulnerable-package finding
# path, mirroring what tests/suites/image-debian.sh (IMG-09) already proved
# for dpkg and tests/suites/image-e2e.sh (IMG-06) proved for apk.
#
# What this suite proves, and what it is NOT for:
#
#   A. `image_distro_ecosystem_resolve` (modules/image/engine.sh), unit
#      level: EVERY one of `ID=rhel`/`centos`/`rocky`/`almalinux`/`fedora`
#      resolves to the single FLAT `Red Hat` ecosystem key, regardless of
#      `VERSION_ID` (UNLIKE alpine/debian/ubuntu, whose ecosystem key is
#      built FROM the release) - and a missing /etc/os-release still
#      refuses with `no_os_release`, the identical declared-reduction shape
#      every other distro uses.
#   B. End to end, through real `scan.sh image` subprocesses against a
#      synthetic RHEL-shaped docker-archive fixture carrying a real
#      `var/lib/rpm/rpmdb.sqlite` (built at test time with `sqlite3`, never
#      a committed binary blob - the identical discipline
#      tests/suites/image-rpm.sh's own header already establishes): an
#      EPOCH-carrying vulnerable rpm package fires
#      `IMAGE-PKG-VULNERABLE_OS_PACKAGE-03`, is quiet once the installed
#      NEVRA reaches the fixed EVR (epoch-aware - a lexical/lax comparator
#      would get this wrong, report.md §2.4), and the run-over-run diff
#      (same operator-declared --image id, report.md §3.4) reads the
#      patched CVE as `fixed`, never `unknown`+`new`.
#   C. The advisory-db exit-4 gate (IMG-03's mechanism, reused unchanged)
#      fires correctly for a resolved `Red Hat` ecosystem the fixture db
#      does not cover, and does not fire when it does.
#   D. THE HONESTY CONTRACT (the brief's own words: "a binary-format/no-
#      sqlite3 DB yields the declared reduction not a silent clean"): a
#      resolved, covered Red Hat ecosystem with NO rpm database at all
#      reports `IMAGE-COV-UNKNOWN_DISTRO-01` with `manager=rpm` and
#      `detail=no_package_db_found`; the SAME ecosystem with a REAL,
#      readable sqlite rpm database but `sqlite3` absent from the scanning
#      host's PATH reports the SAME check with
#      `detail=rpm_db_binary_format` and its own detail-aware wording -
#      NEVER exit 0 with zero findings and no explanation, which is
#      indistinguishable from "this image has no vulnerabilities".
#
# NOT this suite's job: apk/Alpine (tests/suites/image-e2e.sh, IMG-06),
# dpkg/Debian-Ubuntu (tests/suites/image-debian.sh, IMG-09), rpm
# ENUMERATION unit tests (tests/suites/image-rpm.sh, IMG-12) or the
# rpmvercmp comparator's own differential proof
# (tests/suites/image-rpm-version.sh) - this suite consumes both as already-
# proven building blocks and proves only the WIRING between them and the
# Red Hat advisory ecosystem this ticket adds.
# `veng_advisories_redhat` (tools/vendor-engines.sh) is exercised as its own
# dedicated section of tests/suites/vendor-engines-advisories.sh (D6), not
# duplicated here - this suite consumes its OUTPUT (a hand-built fixture
# data/advisories.db in the exact row shape it writes) rather than
# re-proving the importer itself.
#
# No network: image scanning is offline by construction (docs/DESIGN.md
# §1), and this suite never puts curl/wget/aws on PATH at all. `sqlite3` is
# used only to BUILD this suite's own local fixtures at test time, exactly
# as tests/suites/image-rpm.sh's own header states, and section D's
# no-sqlite3 case simulates absence by restricting PATH rather than by
# uninstalling anything.
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

command -v sqlite3 >/dev/null 2>&1 || {
  printf 'tests/suites/image-rpm-e2e.sh: sqlite3 is not on PATH; this suite builds its own rpm-database fixtures with it and cannot run without it\n' >&2
  exit 1
}

W=$SCOURSH_SCRATCH/image-rpm-e2e
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# A full-enough userland to run a real `scan.sh image` subprocess (tar is
# the one this list's siblings in tests/suites/vendor-engines-advisories.sh
# never needed), with `sqlite3` DELIBERATELY absent - section D's
# `requires-cmd: sqlite3` gate, simulated by restricting PATH rather than by
# uninstalling anything, the identical discipline
# tests/suites/image-rpm.sh's own section C already uses at the unit level.
NO_SQLITE_PATH=$W/no-sqlite-path
mkdir -p "$NO_SQLITE_PATH"
for tool in bash sh cat sort mkdir rmdir dirname basename pwd printf true false \
  grep rg sed awk date mv cp rm ln wc cut tr find xargs mktemp look tar \
  uname id chmod stat readlink head tail env sleep tee sha256sum shasum openssl; do
  src=$(command -v "$tool" 2>/dev/null) || continue
  ln -sf "$src" "$NO_SQLITE_PATH/$tool"
done

# =============================================================================
printf -- '\n-- A. image_distro_ecosystem_resolve: rhel/centos/rocky/almalinux/fedora --\n'
# =============================================================================

for _id in rhel centos rocky almalinux fedora; do
  t_case "$_id: resolves to the single FLAT 'Red Hat' ecosystem key"
  cat >"$W/os-release-$_id" <<EOF
ID=$_id
VERSION_ID=9
EOF
  image_distro_ecosystem_resolve "$W/os-release-$_id"
  _rc=$?
  assert_eq 0 "$_rc" "$_id resolves"
  assert_eq 'Red Hat' "$_IMAGE_DISTRO_ECOSYSTEM" \
    "FAILS under a reading that built a per-release key (e.g. 'Red Hat:9') the way alpine/debian/ubuntu do - OSV.dev's own Red Hat namespace carries no such suffix (report.md §2.3)"
done

t_case 'VERSION_ID plays NO role in the ecosystem key: two different RHEL major versions resolve to the IDENTICAL ecosystem'
cat >"$W/os-release-rhel8" <<'EOF'
ID=rhel
VERSION_ID=8.6
EOF
cat >"$W/os-release-rhel9" <<'EOF'
ID=rhel
VERSION_ID=9.2
EOF
image_distro_ecosystem_resolve "$W/os-release-rhel8"
ECO8=$_IMAGE_DISTRO_ECOSYSTEM
image_distro_ecosystem_resolve "$W/os-release-rhel9"
ECO9=$_IMAGE_DISTRO_ECOSYSTEM
assert_eq 'Red Hat' "$ECO8" 'rhel 8.6 resolves to Red Hat'
assert_eq 'Red Hat' "$ECO9" 'rhel 9.2 resolves to Red Hat too'
assert_eq "$ECO8" "$ECO9" \
  'FAILS under any reading that varies the ecosystem key by RHEL release - the version differentiation instead lives inside each installed package'"'"'s own RELEASE field (e.g. .el8 vs .el9), compared by rpm_version.sh'"'"'s rpmvercmp, never in the ecosystem string itself'

t_case 'rhel: an ABSENT VERSION_ID still resolves - unlike alpine/debian/ubuntu, Red Hat needs no release to build its ecosystem key'
cat >"$W/os-release-rhel-norel" <<'EOF'
ID=rhel
EOF
image_distro_ecosystem_resolve "$W/os-release-rhel-norel"
_rc=$?
assert_eq 0 "$_rc" \
  'resolves cleanly with no VERSION_ID at all - FAILS under a reading that required a parseable release before building the key, which is right for the three per-release distros but not for this flat one'
assert_eq 'Red Hat' "$_IMAGE_DISTRO_ECOSYSTEM" 'still Red Hat'

t_case 'no /etc/os-release at all: refuses with no_os_release, the identical declared reduction every other distro uses'
_rc=0
image_distro_ecosystem_resolve "$W/does-not-exist" || _rc=$?
assert_eq 1 "$_rc" 'refused'
assert_eq no_os_release "$_IMAGE_DISTRO_REASON" 'the specific reason'
assert_eq '' "$_IMAGE_DISTRO_ECOSYSTEM" 'and no ecosystem is guessed'

t_case 'an unrecognised ID (not rhel/centos/rocky/almalinux/fedora, and not alpine/debian/ubuntu) refuses as distro_not_yet_supported'
cat >"$W/os-release-suse" <<'EOF'
ID=opensuse-leap
VERSION_ID=15.5
EOF
_rc=0
image_distro_ecosystem_resolve "$W/os-release-suse" || _rc=$?
assert_eq 1 "$_rc" 'refused'
assert_eq distro_not_yet_supported "$_IMAGE_DISTRO_REASON" 'the specific reason - this module does not silently fold an unrelated rpm-based distro into Red Hat'

# =============================================================================
printf -- '\n-- B/C/D. end to end: scan.sh image against a synthetic RHEL image --\n'
# =============================================================================

# `_mk_rpmdb VAR ROW...` - a fresh sqlite database at $W/<VAR>.sqlite, built
# with rpm.sh's own "plain NEVRA" reader schema (name, epoch, version,
# release, arch) - tests/suites/image-rpm.sh's own section A fixture shape,
# never the real two-column native schema (that file's own section F is
# what proves the real schema is deliberately UNREADABLE by this project).
_mk_rpmdb() {
  local __var=$1
  shift
  local path=$W/$__var.sqlite
  rm -f -- "$path"
  sqlite3 "$path" "CREATE TABLE Packages (name TEXT, epoch TEXT, version TEXT, release TEXT, arch TEXT);"
  local row
  for row in "$@"; do
    sqlite3 "$path" "$row"
  done
  printf -v "$__var" '%s' "$path"
}

# `_mkimg NAME OS_RELEASE RPMDB_SQLITE_PATH` - a one-layer docker-save
# tarball carrying etc/os-release and (when RPMDB_SQLITE_PATH is non-empty)
# a real sqlite database at var/lib/rpm/rpmdb.sqlite, embedded byte-for-byte
# via ustar_add_file (mkustar.sh's own header explains why a binary member
# needs that entry point rather than ustar_add's text-only one). An empty
# RPMDB_SQLITE_PATH omits the member entirely, for section D's "no rpm
# database at all" case.
_mkimg() {
  local name=$1 osrelease=$2 rpmdb=$3
  local tar=$W/$name.tar
  local l=$W/$name-layer.tar
  ustar_begin "$l"
  ustar_add "$l" 'etc/' 5 '' ''
  ustar_add "$l" 'etc/os-release' 0 '' "$osrelease"
  if [[ -n $rpmdb ]]; then
    ustar_add "$l" 'var/' 5 '' ''
    ustar_add "$l" 'var/lib/' 5 '' ''
    ustar_add "$l" 'var/lib/rpm/' 5 '' ''
    ustar_add_file "$l" 'var/lib/rpm/rpmdb.sqlite' "$rpmdb"
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

# `_image_scan RUNDIR ADVISORIES_DB [PATH_OVERRIDE] -- ARGS...` - a real
# `scan.sh image` subprocess, mirroring tests/suites/image-debian.sh's own
# identical helper. PATH_OVERRIDE, when non-empty, replaces PATH entirely
# (section D's no-sqlite3 case); left empty it inherits this suite's own
# real PATH (section B/C's ordinary sqlite3-present case).
_image_scan() {
  local rundir=$1 db=$2 pathoverride=$3
  shift 3
  [[ $1 == -- ]] && shift
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$ROOT SCOURSH_SCA_ADVISORIES_DB=$db \
    PATH="${pathoverride:-$PATH}" \
    bash "$ROOT/scan.sh" image --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

RHEL_OSREL='ID=rhel
VERSION_ID=8.6
'

# `openssl-libs` carries an EPOCH (1) in both the installed and fixed EVR -
# report.md §2.4's whole reason this ticket needs its own comparator rather
# than reusing modules/sca/semver.sh: an epoch-BLIND comparator has no way
# to represent this field at all, and a naive string comparison of
# "1:1.1.1k-9.el8" against "1:1.1.1k-9.el8_6" happens to get the RIGHT
# answer lexically here by coincidence, which is exactly why
# tests/suites/image-rpm-version.sh's own differential corpus - not this
# suite - is where the comparator's correctness is actually proven; this
# suite only proves the epoch VALUE survives the enumerate -> join -> lookup
# -> compare -> emit pipeline intact.
RPM_VULN_ROW="INSERT INTO Packages VALUES ('openssl-libs','1','1.1.1k','9.el8','x86_64');"
RPM_FIXED_ROW="INSERT INTO Packages VALUES ('openssl-libs','1','1.1.1k','9.el8_6','x86_64');"

FIXDB=$W/advisories.db
cat >"$FIXDB" <<'EOF'
# scoursh image-rpm-e2e test fixture advisories.db - NOT the real database.
# generated: 1970-01-01T00:00:00Z
Red Hat	openssl-libs	1:1.1.1k-9.el8	SCOURSH-FIXTURE-CVE-RH-1	high	1:1.1.1k-9.el8_6
EOF

_mk_rpmdb VULN_RPMDB "$RPM_VULN_ROW"
_mk_rpmdb FIXED_RPMDB "$RPM_FIXED_ROW"

VULN_IMG=$(_mkimg imgrpm-vuln "$RHEL_OSREL" "$VULN_RPMDB")
IMG_ID=scoursh-img-rpm-e2e

# -- C: the advisory-db exit-4 gate, for a real resolved Red Hat ecosystem --

t_case 'gate FIRES: a real RHEL image resolves Red Hat, and an empty fixture db has no rows for it - exit 4'
EMPTY_DB=$W/empty-advisories.db
printf '# empty\n' >"$EMPTY_DB"
_image_scan "$W/run-nodb" "$EMPTY_DB" '' -- --image "$IMG_ID-nodb" --source "$VULN_IMG"
assert_eq "$SCOURSH_EXIT_INPUT" "$_RC" \
  'exit 4 (SCOURSH_EXIT_INPUT), mirroring the alpine/debian gates tests/suites/image-advisories.sh and tests/suites/image-debian.sh already pin'
assert_contains "$(_slurp "$W/run-nodb/run.json")" 'reason=no_advisories_db_for_ecosystem' \
  'the declared reduction fires - FAILS if redhat bypassed the SAME gate mechanism every other ecosystem uses'

t_case 'gate does NOT fire: the fixture db HAS rows for Red Hat - exit 0'
_image_scan "$W/run-withdb" "$FIXDB" '' -- --image "$IMG_ID" --source "$VULN_IMG"
assert_eq 0 "$_RC" 'exit 0 - the fixture db genuinely covers Red Hat'
assert_not_contains "$(_slurp "$W/run-withdb/findings.jsonl")" 'IMAGE-COV-NO_ADVISORY_DB-01' \
  'no coverage-gap finding this time - the ecosystem IS known'

# -- B: the real finding, epoch and all --

t_case 'run 1 (vulnerable): IMAGE-PKG-VULNERABLE_OS_PACKAGE-03 fires, with the EPOCH carried through end to end'
RUN1_JSON=$(_slurp "$W/run-withdb/run.json")
RUN1_FINDINGS=$(_slurp "$W/run-withdb/findings.jsonl")
assert_contains "$RUN1_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' 'checks_run names the rpm package check'
assert_contains "$RUN1_FINDINGS" '"check_id":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-03"' 'a real finding was emitted'
assert_contains "$RUN1_FINDINGS" '"module":"image"' 'under module image'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'loc_package=openssl-libs' 'the plain rpm package name'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'loc_version=1:1.1.1k-9.el8' \
  'the joined EVR string, EPOCH included - FAILS if _rpm_evr_join dropped the epoch, or if it were silently defaulted to 0'
assert_contains "$(_slurp "$W/run-withdb/findings.fields")" 'loc_advisory_id=SCOURSH-FIXTURE-CVE-RH-1' 'and the right advisory'
assert_contains "$RUN1_FINDINGS" '"location":{"image_id":"'"$IMG_ID"'","ecosystem":"Red Hat","package":"openssl-libs","advisory_id":"SCOURSH-FIXTURE-CVE-RH-1"' \
  'the JSON location object leads with EXACTLY these four keys, in this order, mirroring apk/dpkg'"'"'s own IMG-06/IMG-09 assertions - image_id/ecosystem/package/advisory_id, NOT the version'

t_case 'the finding round-trips through every report format'
assert_contains "$(_slurp "$W/run-withdb/report.md")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' 'report.md lists it'
SARIF1=$(_slurp "$W/run-withdb/report.sarif")
assert_contains "$SARIF1" '"ruleId":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-03"' 'report.sarif names the check as its ruleId'

t_case 'run 2, SAME --image id, package upgraded to its fixed release (.el8 -> .el8_6): quiet for the package check'
FIXED_IMG=$(_mkimg imgrpm-fixed "$RHEL_OSREL" "$FIXED_RPMDB")
_image_scan "$W/run2" "$FIXDB" '' -- --image "$IMG_ID" --source "$FIXED_IMG"
assert_eq 0 "$_RC" 'exit 0'
RUN2_JSON=$(_slurp "$W/run2/run.json")
RUN2_FINDINGS=$(_slurp "$W/run2/findings.jsonl")
assert_not_contains "$RUN2_FINDINGS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' \
  'openssl-libs@1:1.1.1k-9.el8_6 is AT the fixed version - quiet this run, not merely "not new" - FAILS under a comparator that cannot order the release-field segment correctly (rpm_version.sh'"'"'s own rpmvercmp)'
assert_contains "$RUN2_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' \
  'checks_run STILL names the package check - it executed and found nothing, a different fact from "did not run" (report.md §4.2 honesty)'

t_case 'the run-over-run DIFF reads the patched CVE as fixed, never unknown+new (report.md §3.4, the whole point of the image-id cell)'
assert_contains "$RUN2_JSON" '"fixed"' 'run.json carries at least one fixed-classified finding this run'
REPORT2=$(_slurp "$W/run2/report.md")
assert_contains "$REPORT2" 'Fixed since last scan' \
  'report.md renders the fixed-since-last-scan section for this run - FAILS if diff_classify_run never ran, or the (check,cell) coverage did not match run 1'
assert_contains "$REPORT2" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' 'and names the specific check under it'

# -- D: THE HONESTY CONTRACT - no rpm database, and an unreadable one, are
#       both declared reductions, never a silent clean scan --

t_case 'a resolved, covered Red Hat ecosystem with NO rpm database in any layer reports IMAGE-COV-UNKNOWN_DISTRO-01 with manager=rpm, detail=no_package_db_found'
NORPM_IMG=$(_mkimg imgrpm-norpm "$RHEL_OSREL" '')
_image_scan "$W/run-norpm" "$FIXDB" '' -- --image "$IMG_ID-norpm" --source "$NORPM_IMG"
assert_eq 0 "$_RC" 'exit 0 - an unreadable/absent package database is a declared reduction, not a fatal error'
RUN_NORPM_JSON=$(_slurp "$W/run-norpm/run.json")
assert_contains "$RUN_NORPM_JSON" 'reason=no_package_db_found' 'the declared reduction fires'
assert_contains "$(_slurp "$W/run-norpm/findings.jsonl")" '"check_id":"IMAGE-COV-UNKNOWN_DISTRO-01"' 'a real finding was emitted'
assert_contains "$(_slurp "$W/run-norpm/findings.fields")" 'manager: rpm' \
  'the finding'"'"'s evidence names rpm as the missing manager - FAILS if image_report_unknown_distro defaulted this caller to apk'"'"'s or dpkg'"'"'s own wording'
assert_not_contains "$(_slurp "$W/run-norpm/findings.jsonl")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' \
  'and no package finding, since none could be enumerated at all'

t_case 'a resolved, covered Red Hat ecosystem with a REAL rpm database but sqlite3 ABSENT from PATH reports the SAME check with detail=rpm_db_binary_format, and NEVER a silent clean scan'
_image_scan "$W/run-nosqlite" "$FIXDB" "$NO_SQLITE_PATH" -- --image "$IMG_ID-nosqlite" --source "$VULN_IMG"
assert_eq 0 "$_RC" 'exit 0 - a missing sqlite3 on the scanning host is a declared limitation (requires-cmd: sqlite3, modules/image/checks-rpm.rules), not a fatal error'
RUN_NOSQLITE_JSON=$(_slurp "$W/run-nosqlite/run.json")
assert_contains "$RUN_NOSQLITE_JSON" 'reason=rpm_db_binary_format' \
  'the DISTINCT declared reason - FAILS if this collapsed to no_package_db_found, which would misreport "a database exists but I could not read it" as "there is nothing here" (report.md §4.3)'
NOSQLITE_FINDINGS=$(_slurp "$W/run-nosqlite/findings.jsonl")
assert_contains "$NOSQLITE_FINDINGS" '"check_id":"IMAGE-COV-UNKNOWN_DISTRO-01"' 'the same coverage check as the no-database case'
assert_contains "$NOSQLITE_FINDINGS" 'not text-readable' \
  'the DETAIL-AWARE title (modules/image/engine.sh'"'"'s image_report_unknown_distro) - FAILS if this reused the generic "no rpm package database in any layer" wording, which is false here: a real database genuinely exists in this image'
assert_contains "$(_slurp "$W/run-nosqlite/findings.fields")" 'manager: rpm' 'still names rpm as the manager'
assert_not_contains "$NOSQLITE_FINDINGS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-03' \
  'and, above all, NO vulnerable-package finding and NO silent absence of one either - the coverage finding is what tells the operator this run examined nothing, which is the entire honesty contract this section exists to prove'

t_summary image-rpm-e2e
