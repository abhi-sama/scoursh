#!/usr/bin/env bash
# tests/suites/image-e2e.sh - IMG-06 (data/scoursh-image-scan-design/
# report.md §4.1/§4.2/§4.3, and §3.4's coverage-cell decision): the
# END-TO-END Alpine slice - IMG-04's apk enumerator, IMG-05's version
# comparator, and IMG-03's advisory-ecosystem plumbing wired together into
# real `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` findings, plus the two remaining
# v1 coverage checks (`IMAGE-COV-UNKNOWN_DISTRO-01`,
# `IMAGE-COV-LAYER_UNREADABLE-01`) and the distro-agnostic
# `IMAGE-CFG-RUNS_AS_ROOT-01` config-blob check. This is the ticket that
# COMPLETES the Alpine v1 image scanner - `scan.sh image` now actually
# reports vulnerable apk packages.
#
# What this suite proves, and what it is NOT for:
#
#   A. `modules/image/distro/apk.sh`'s `apk_scan_installed`/
#      `_apk_row_still_vulnerable`, unit-level: the comparator-based match
#      against `fixed_versions` (never an exact-version lookup - see that
#      function's own header for why this deliberately departs from
#      docs/FOUNDATION.md tension 25's exact-match resolution), quiet at/
#      above the fixed version, and the `_APK_SCAN_SKIPPED` roll-up for an
#      unparseable installed version.
#   B. `modules/image/config.sh`'s `_image_user_is_root`/
#      `image_config_user_get`, unit-level: absent/root/non-root `User`
#      shapes, for both a docker-archive (config is a member of the OUTER
#      tar) and an oci-layout (config is already a blob on disk).
#   C. End to end, through two real `scan.sh image` subprocesses against the
#      SAME operator-declared image id: a vulnerable apk package fires
#      `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` and round-trips through every
#      report format (findings.jsonl/json, report.md/html, SARIF,
#      agent-fix.json); a second scan of the SAME image id with the package
#      upgraded to its fixed version is quiet for that check AND reads the
#      first run's finding as `fixed` in the run-over-run diff - never
#      `unknown`+`new` - which is report.md §3.4's whole point for choosing
#      the operator-declared image id as the coverage cell rather than the
#      volatile digest/tag. The same two runs also prove
#      `IMAGE-CFG-RUNS_AS_ROOT-01` fires on the first (root-config) image
#      and is quiet on the second (non-root-config) one.
#
# NOT this suite's job: dpkg/rpm (Stage 2, IMG-07 onward) - explicitly out
# of scope for this ticket, per the brief.
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

W=$SCOURSH_SCRATCH/image-e2e
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

FIXDB=$W/advisories.db
cat >"$FIXDB" <<'EOF'
# scoursh image-e2e test fixture advisories.db - NOT the real database.
# generated: 1970-01-01T00:00:00Z
Alpine:v3.18	openssl	3.1.4-r1	SCOURSH-FIXTURE-CVE-1	high	3.1.4-r2
EOF

# =============================================================================
printf -- '\n-- A. apk_scan_installed / _apk_row_still_vulnerable (unit-level) --\n'
# =============================================================================

APKFILE=$W/installed
cat >"$APKFILE" <<'EOF'
P:musl
V:1.2.4-r2

P:busybox
V:1.36.1-r15

P:openssl
V:3.1.4-r1

EOF

occurrence_reset_all
D=$W/unit-run
rm -rf -- "${D:?}"
run_init "$D"
D=$SCOURSH_RUN_DIR

t_case 'a package below the fixed_versions threshold is reported vulnerable'
_apk_row_still_vulnerable '3.1.4-r1' '3.1.4-r2'
assert_eq 0 $? '3.1.4-r1 < 3.1.4-r2 (apk pkgrel is NUMERIC, not lexical - FAILS under any string comparison that reads r1 > r2 the way it would read "10" < "2")'

t_case 'a package AT the fixed version is quiet'
_rc=0
_apk_row_still_vulnerable '3.1.4-r2' '3.1.4-r2' || _rc=$?
assert_eq 1 "$_rc" 'equal versions are never "still vulnerable" - FAILS under a naive <= reading'

t_case 'a package ABOVE the fixed version is quiet'
_rc=0
_apk_row_still_vulnerable '3.1.4-r10' '3.1.4-r2' || _rc=$?
assert_eq 1 "$_rc" '3.1.4-r10 > 3.1.4-r2 numerically - FAILS under the exact lexical-pkgrel bug report.md §2.4 measured semver.sh making (r10 < r2 as strings)'

t_case 'an empty fixed_versions field is treated as still-vulnerable, never a silent skip'
_apk_row_still_vulnerable '9.9.9' ''
assert_eq 0 $? 'no published fix means "not known safe", mirroring modules/sca/engine.sh own accept_risk convention for an unfixed advisory'

t_case 'apk_scan_installed: end to end against the fixture apk db and advisories.db'
apk_scan_installed "$APKFILE" e2e-unit 'Alpine:v3.18' "$FIXDB"
assert_eq 0 $? 'returns 0 - the apk database was readable'
assert_eq 0 "$_APK_SCAN_SKIPPED" 'every installed package here has a well-formed version, so nothing was skipped'
findings_merge "$D"
FIELDS=$(_slurp "$D/findings.fields")
assert_contains "$FIELDS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'the vulnerable openssl@3.1.4-r1 package produced a real finding'
assert_contains "$FIELDS" 'loc_package=openssl' 'naming the right package'
assert_contains "$FIELDS" 'loc_advisory_id=SCOURSH-FIXTURE-CVE-1' 'and the right advisory'
assert_not_contains "$FIELDS" 'loc_package=musl' \
  'musl carries no advisory in the fixture db - FAILS under a reading that flags every enumerated package regardless of a match'
assert_not_contains "$FIELDS" 'loc_package=busybox' 'neither does busybox'

t_case 'a package with no comparable version is counted, never silently dropped'
cat >"$W/installed-badversion" <<'EOF'
P:openssl
V:not-a-version

EOF
apk_scan_installed "$W/installed-badversion" e2e-unit2 'Alpine:v3.18' "$FIXDB"
assert_eq 0 $? 'returns 0 - the file itself was readable'
assert_eq 1 "$_APK_SCAN_SKIPPED" 'the one package with an unorderable version is counted'

t_case 'a genuinely absent apk database is a real refusal, not zero packages'
_rc=0
apk_scan_installed "$W/definitely-absent-installed" e2e-unit3 'Alpine:v3.18' "$FIXDB" || _rc=$?
assert_eq 1 "$_rc" 'FAILS if this were conflated with "the file parsed to zero packages"'
assert_eq no_package_db_found "$_APK_INSTALLED_REASON" 'the specific, distinguishable reason'

# `run_init` (lib/core.sh) exports SCOURSH_RUN_ID/SCOURSH_RUN_DIR into THIS
# process's environment, and `: "${SCOURSH_RUN_ID:=...}"` only derives a
# fresh id when the variable is unset OR EMPTY - so a real `scan.sh`
# subprocess launched later in this same script (section C below) would
# otherwise INHERIT "unit-run" as its own run id instead of deriving one
# from its own `--out` directory, which is exactly what corrupts the
# run-over-run diff section C depends on (two runs sharing one run id write
# and read the same state/<id>.json regardless of which --out they used).
# Cleared to empty, mirroring tests/suites/image.sh's own end-of-file reset,
# rather than `unset`, since `:=` treats an empty value the same as unset.
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# =============================================================================
printf -- '\n-- B. image_config_user_get / _image_user_is_root (unit-level) --\n'
# =============================================================================

t_case '_image_user_is_root: absent, root, 0, and their :group forms are all root'
for u in '' root 0 'root:root' '0:0'; do
  _image_user_is_root "$u"
  assert_eq 0 $? "'$u' is root"
done

t_case '_image_user_is_root: a real non-root user is not'
for u in appuser 1000 '1000:1000' 'nobody:nogroup'; do
  _rc=0
  _image_user_is_root "$u" || _rc=$?
  assert_eq 1 "$_rc" "'$u' is NOT root - FAILS under a reading that treats any non-empty value as safe without checking it"
done

CFGDIR=$W/cfgblob
rm -rf -- "${CFGDIR:?}"
mkdir -p "$CFGDIR"
# image_docker_archive_open refuses a manifest that names zero layers
# (manifest_names_no_layers) - a real image always has at least one, so an
# empty dummy layer is the minimum shape this function will actually open.
EMPTYLAYER=$W/empty-layer.tar
ustar_begin "$EMPTYLAYER"
ustar_end "$EMPTYLAYER"
CFGTAR=$W/cfgblob.tar
ustar_begin "$CFGTAR"
ustar_add "$CFGTAR" 'cfg.json' 0 '' '{"architecture":"amd64","config":{"User":"appuser"}}'
ustar_add "$CFGTAR" 'l0/' 5 '' ''
ustar_add_file "$CFGTAR" 'l0/layer.tar' "$EMPTYLAYER"
ustar_add "$CFGTAR" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/cfgblob:v1"],"Layers":["l0/layer.tar"]}]'
ustar_end "$CFGTAR"

t_case 'image_config_user_get reads config.User out of a real docker-archive config member'
image_docker_archive_open "$CFGTAR" ''
assert_eq 0 $? 'the (layerless) archive opens'
_rc=0
image_config_user_get docker-archive "$CFGTAR" "$CFGDIR" || _rc=$?
assert_eq 0 "$_rc" 'the config blob was readable'
assert_eq appuser "$_IMAGE_CONFIG_USER" \
  "reads the nested config.User field - FAILS if the path were flattened as a bare 'User' rather than \$'\\x1f'-joined 'config\\x1fUser'"

t_case 'image_config_user_get: a config blob with no "config" object at all resolves to an EMPTY user, not an error'
CFGTAR2=$W/cfgblob-nouser.tar
ustar_begin "$CFGTAR2"
ustar_add "$CFGTAR2" 'cfg.json' 0 '' '{"architecture":"amd64"}'
ustar_add "$CFGTAR2" 'l0/' 5 '' ''
ustar_add_file "$CFGTAR2" 'l0/layer.tar' "$EMPTYLAYER"
ustar_add "$CFGTAR2" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/cfgblob2:v1"],"Layers":["l0/layer.tar"]}]'
ustar_end "$CFGTAR2"
image_docker_archive_open "$CFGTAR2" ''
CFGDIR2=$W/cfgblob2
rm -rf -- "${CFGDIR2:?}"
mkdir -p "$CFGDIR2"
_rc=0
image_config_user_get docker-archive "$CFGTAR2" "$CFGDIR2" || _rc=$?
assert_eq 0 "$_rc" 'a MISSING key is not a read failure - image_json_leaf own "absent leaf" contract'
assert_eq '' "$_IMAGE_CONFIG_USER" 'and the value is empty, which _image_user_is_root already treats as root'

# =============================================================================
printf -- '\n-- C. end to end: two real scan.sh image runs, same --image id --\n'
# =============================================================================

# `_mkimg NAME OS_RELEASE APK_DB CFG_JSON` - a one-layer docker-save tarball
# carrying all three metadata paths this ticket's own scan.sh flow reads,
# built at test time exactly the way tests/suites/image-advisories.sh's own
# `_mkimg` is (mkustar.sh's own header explains why: determinism, and this
# suite needs a real Alpine-shaped apk database and config blob that do not
# belong among tests/fixtures/image/'s committed, cross-ticket fixtures).
_mkimg() {
  local name=$1 osrelease=$2 apkdb=$3 cfg=$4
  local tar=$W/$name.tar
  local l=$W/$name-layer.tar
  ustar_begin "$l"
  ustar_add "$l" 'etc/' 5 '' ''
  ustar_add "$l" 'etc/os-release' 0 '' "$osrelease"
  ustar_add "$l" 'lib/' 5 '' ''
  ustar_add "$l" 'lib/apk/' 5 '' ''
  ustar_add "$l" 'lib/apk/db/' 5 '' ''
  ustar_add "$l" 'lib/apk/db/installed' 0 '' "$apkdb"
  ustar_end "$l"
  ustar_begin "$tar"
  ustar_add "$tar" 'cfg.json' 0 '' "$cfg"
  ustar_add "$tar" 'l0/' 5 '' ''
  ustar_add_file "$tar" 'l0/layer.tar' "$l"
  ustar_add "$tar" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/'"$name"':v1"],"Layers":["l0/layer.tar"]}]'
  ustar_end "$tar"
  printf '%s' "$tar"
}

OSREL='ID=alpine
VERSION_ID=3.18.4
'
APKDB_VULN='P:musl
V:1.2.4-r2

P:busybox
V:1.36.1-r15

P:openssl
V:3.1.4-r1

'
APKDB_FIXED='P:musl
V:1.2.4-r2

P:busybox
V:1.36.1-r15

P:openssl
V:3.1.4-r2

'
CFG_ROOT='{"architecture":"amd64","os":"linux"}'
CFG_NONROOT='{"architecture":"amd64","os":"linux","config":{"User":"appuser"}}'

VULN_IMG=$(_mkimg img06vuln "$OSREL" "$APKDB_VULN" "$CFG_ROOT")
FIXED_IMG=$(_mkimg img06fixed "$OSREL" "$APKDB_FIXED" "$CFG_NONROOT")
IMG_ID=scoursh-img06-e2e

# `_image_scan RUNDIR ADVISORIES_DB -- ARGS...` - a real `scan.sh image`
# subprocess, SCOURSH_SCA_ADVISORIES_DB pointed at a per-case scratch file,
# mirroring tests/suites/image-advisories.sh's own helper exactly.
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

t_case 'run 1 (vulnerable): exit 0, IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 fires, and IMAGE-CFG-RUNS_AS_ROOT-01 fires too (no config.User at all)'
_image_scan "$W/run1" "$FIXDB" -- --image "$IMG_ID" --source "$VULN_IMG"
assert_eq 0 "$_RC" 'a run with a real vulnerable finding still exits 0 with no --fail-on given'
RUN1_JSON=$(_slurp "$W/run1/run.json")
RUN1_FINDINGS=$(_slurp "$W/run1/findings.jsonl")
assert_contains "$RUN1_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' 'checks_run names the package check'
assert_contains "$RUN1_FINDINGS" '"check_id":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-01"' 'a real finding was emitted'
assert_contains "$RUN1_FINDINGS" '"module":"image"' 'under module image'
assert_not_contains "$RUN1_FINDINGS" 'IMAGE-COV-UNKNOWN_DISTRO-01' \
  'the apk database WAS present and readable this time - FAILS if the enumerator refused it'

t_case 'the finding location carries image_id/ecosystem/package/advisory_id - NOT the version (report.md §3.4)'
# The location object may carry a trailing "line" key too - report.md's
# module has no source file of its own, so report_locations (lib/report.sh)
# writes a generated locations/image.txt artifact and back-fills loc_line
# with THAT file's own line number, purely for SARIF's required
# artifactLocation/startLine (image.sh's own synthetic-finding test already
# pins this). The assertion below checks the location object's PREFIX
# (image_id/ecosystem/package/advisory_id, in that order) rather than an
# exact whole-object match, so it does not depend on whether that key is
# present.
assert_contains "$RUN1_FINDINGS" '"location":{"image_id":"'"$IMG_ID"'","ecosystem":"Alpine:v3.18","package":"openssl","advisory_id":"SCOURSH-FIXTURE-CVE-1"' \
  'the JSON location object leads with EXACTLY these four keys, in this order - FAILS if loc_version were part of the fingerprint profile (lib/findings.sh _fp_components_for), which would make a package bump alone read as a brand-new finding'
assert_contains "$(_slurp "$W/run1/findings.fields")" 'loc_version=3.1.4-r1' \
  'the installed version IS still recorded on the finding (informational, not part of the fingerprint) - mirroring modules/sca/engine.sh own loc_version convention exactly'

t_case 'the finding round-trips through every report format (report_all already ran as part of the real scan.sh image dispatch, with no --format given)'
assert_contains "$(_slurp "$W/run1/findings.json")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' 'findings.json carries it'
assert_contains "$(_slurp "$W/run1/report.md")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' 'report.md lists it'
assert_contains "$(_slurp "$W/run1/report.html")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' 'report.html lists it'
SARIF1=$(_slurp "$W/run1/report.sarif")
assert_contains "$SARIF1" '"ruleId":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-01"' 'report.sarif names the check as its ruleId'
assert_contains "$SARIF1" 'locations/image.txt' \
  'the artifactLocation points at report_locations own generated artifact, mirroring image.sh own synthetic-finding assertion'

# `--format agent` is opt-in and never in the default list (report_agent's
# own header), so report_agent is called directly here on run1's own
# directory - the identical shape tests/suites/image.sh's own synthetic
# finding test uses - rather than re-running scan.sh with an extra flag.
report_agent "$W/run1"
AGENT1=$(_slurp "$W/run1/agent-fix.json")
assert_contains "$AGENT1" '"check":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-01"' 'agent-fix.json names the check'
assert_contains "$AGENT1" '"mod":"image"' 'and its module'

t_case 'run.json names an image (RUNS_AS_ROOT) finding too - both checks are real for this image'
assert_contains "$RUN1_JSON" 'IMAGE-CFG-RUNS_AS_ROOT-01' 'checks_run names it'
assert_contains "$RUN1_FINDINGS" '"check_id":"IMAGE-CFG-RUNS_AS_ROOT-01"' \
  "this fixture's cfg.json declares no config object at all, so User is absent - _image_user_is_root treats that as root"

t_case 'run 2, SAME --image id, package upgraded to its fixed version and User now non-root: quiet for both checks this run'
_image_scan "$W/run2" "$FIXDB" -- --image "$IMG_ID" --source "$FIXED_IMG"
assert_eq 0 "$_RC" 'exit 0'
RUN2_JSON=$(_slurp "$W/run2/run.json")
RUN2_FINDINGS=$(_slurp "$W/run2/findings.jsonl")
assert_not_contains "$RUN2_FINDINGS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'openssl@3.1.4-r2 is AT the fixed version - quiet this run, not merely "not new"'
assert_not_contains "$RUN2_FINDINGS" 'IMAGE-CFG-RUNS_AS_ROOT-01' \
  "this image's cfg.json now declares config.User=appuser - quiet this run"
assert_contains "$RUN2_JSON" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'checks_run STILL names the package check - it executed and found nothing, which is a different fact from "did not run" (report.md §4.2 honesty)'

t_case 'the run-over-run DIFF reads the patched CVE as fixed, never unknown+new (report.md §3.4 - the whole point of the image-id cell)'
assert_contains "$RUN2_JSON" '"fixed"' \
  'run.json carries at least one fixed-classified finding this run - FAILS under a naive digest/tag-keyed cell, where the id never changed but nothing here would even be comparable to run 1'
REPORT2=$(_slurp "$W/run2/report.md")
assert_contains "$REPORT2" 'Fixed since last scan' \
  'report.md renders the fixed-since-last-scan section for this run - FAILS if diff_classify_run never ran, or if the (check,cell) coverage IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 wrote for this image id did not match run 1s own cell'
assert_contains "$REPORT2" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'and names the specific check under it'

t_summary image-e2e
