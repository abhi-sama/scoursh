#!/usr/bin/env bash
# tests/suites/image-langdeps.sh - IMG-11 (data/scoursh-image-scan-design/
# report.md §2.2, §4.1's IMAGE-LANGDEP-* row and §5.3's IMG-11 row):
# language dependencies inside the image rootfs, found by reusing the
# existing `modules/sca/` tree-walkers against a bounded, declared
# extraction of this image's own conventional manifest locations.
#
# What this suite proves, and what it is NOT for:
#
#   A. `image_langdeps_candidate_paths` (modules/image/langdeps.sh): the
#      whole declared IMAGE_LANGDEPS_DIRS x IMAGE_LANGDEPS_FILENAMES cross
#      product, bounded and deterministic - never a full rootfs listing.
#   B. `image_langdeps_scan`, unit-level against a real opened docker-archive
#      fixture carrying a vulnerable requirements.txt at a declared
#      candidate location (`app/requirements.txt`): the reused SCA walker
#      really does fire, and the finding it produces lands as
#      `IMAGE-LANGDEP-VULNERABLE_DEP-01`/`module=image`/`cell=<image id>` -
#      NEVER `module=sca`/`cell=$SCOURSH_PATH_ROOT`, report.md §2.2's caveat
#      2 - with `path` correctly IN-IMAGE-relative
#      (`app/requirements.txt`, not a host scratch path).
#   C. Honesty (report.md §2.2's own words, "never a silent clean"):
#      `IMAGE-COV-LANGDEPS_NOT_SCANNED-01` fires with `detail=
#      no_advisories_db` when data/advisories.db is missing/unreadable, and
#      with `detail=no_manifests_found` when the image opens fine but no
#      manifest sits at any declared candidate path - and neither case ever
#      also emits `IMAGE-LANGDEP-VULNERABLE_DEP-01`.
#   D. `modules/image/checks-langdeps.rules` parses under the real record
#      loader with no diagnostics and registers exactly the two check ids
#      this ticket owns.
#   E. End to end, through a real `scan.sh image` subprocess: the finding
#      round-trips through every report format (findings.jsonl/json,
#      report.md/html, SARIF, agent-fix.json), and NO `"module":"sca"` byte
#      ever reaches this run's real output - the whole point of the
#      shadow-run re-emission modules/image/langdeps.sh's own header
#      describes.
#
# NOT this suite's job: modules/sca/'s own walkers, parsers and lookups are
# tested by tests/suites/sca.sh and its siblings; this suite treats them as
# already correct and tests only the acquisition bound, the re-emission, and
# the honesty this ticket adds on top.
#
# No network: image scanning is offline by construction (docs/DESIGN.md §1),
# and this suite never puts curl/wget/aws on PATH at all.
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
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$ROOT/tests/fixtures/image/mkustar.sh"

W=$SCOURSH_SCRATCH/image-langdeps
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- A. image_langdeps_candidate_paths: the bounded, declared cross product --\n'
# =============================================================================

t_case 'the cross product size is exactly DIRS x FILENAMES'
_paths=$(image_langdeps_candidate_paths)
_n=$(printf '%s\n' "$_paths" | grep -c .)
_want=$(( ${#IMAGE_LANGDEPS_DIRS[@]} * ${#IMAGE_LANGDEPS_FILENAMES[@]} ))
assert_eq "$_want" "$_n" \
  "exactly ${#IMAGE_LANGDEPS_DIRS[@]} declared dirs times ${#IMAGE_LANGDEPS_FILENAMES[@]} declared filenames - FAILS if a future edit widens either array without this test being re-derived, which is the point: the bound is measured, not asserted as a fixed number"

t_case 'the root-directory candidates carry no leading slash and no doubled slash'
assert_contains "$_paths" $'\npackage-lock.json\n' \
  'the empty-dir entry joins as the bare filename, never "/package-lock.json"'
assert_not_contains "$_paths" '//' 'no candidate carries a doubled slash'

t_case 'a conventional app-directory candidate is present'
assert_contains "$_paths" 'app/requirements.txt' \
  'the app/ directory times requirements.txt is one real candidate this module will ask for'

t_case 'a non-conventional, non-declared location is genuinely absent from the candidate set'
assert_not_contains "$_paths" 'home/myapp/backend/package-lock.json' \
  'the bound is a real bound, not merely documented - a deeply nested, non-conventional path is out of scope by construction'

# =============================================================================
printf -- '\n-- B. image_langdeps_scan: a real vulnerable requirements.txt at a declared location --\n'
# =============================================================================

FIXDB=$W/advisories.db
cat >"$FIXDB" <<'EOF'
# scoursh image-langdeps test fixture advisories.db - NOT the real database.
# generated: 1970-01-01T00:00:00Z
pypi	flask	0.12.0	SCOURSH-FIXTURE-PY-1	high	0.12.2
EOF
export SCOURSH_SCA_ADVISORIES_DB=$FIXDB

# A one-layer docker-save tarball carrying a vulnerable requirements.txt at
# `app/requirements.txt` - one of section A's own declared candidates.
LANGDIR=$W/langdir
rm -rf -- "${LANGDIR:?}"
mkdir -p "$LANGDIR"
LAYER=$W/langdeps-layer.tar
ustar_begin "$LAYER"
ustar_add "$LAYER" 'app/' 5 '' ''
ustar_add "$LAYER" 'app/requirements.txt' 0 '' 'flask==0.12.0
'
ustar_end "$LAYER"
IMGTAR=$W/langdeps-image.tar
ustar_begin "$IMGTAR"
ustar_add "$IMGTAR" 'cfg0.json' 0 '' '{"architecture":"amd64","os":"linux"}'
ustar_add "$IMGTAR" 'l0/' 5 '' ''
ustar_add_file "$IMGTAR" 'l0/layer.tar' "$LAYER"
ustar_add "$IMGTAR" 'manifest.json' 0 '' '[{"Config":"cfg0.json","RepoTags":["fixture/langdeps:v1"],"Layers":["l0/layer.tar"]}]'
ustar_end "$IMGTAR"

occurrence_reset_all
D=$W/unit-run
rm -rf -- "${D:?}"
run_init "$D"
D=$SCOURSH_RUN_DIR
IMG_ID=scoursh-img11-unit

image_docker_archive_open "$IMGTAR" ''
assert_eq 0 $? 'the fixture archive opens'

t_case 'image_langdeps_scan finds the vulnerable requirements.txt and emits IMAGE-LANGDEP-VULNERABLE_DEP-01'
image_langdeps_scan docker-archive "$IMGTAR" "$IMG_ID"
assert_eq 0 $? 'the scan itself always returns 0 - a partial/complete result is reported through findings and coverage facts, never a nonzero status'
findings_merge "$D"
FIELDS=$(_slurp "$D/findings.fields")
assert_contains "$FIELDS" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'the vulnerable flask@0.12.0 dependency produced a real finding'
assert_contains "$FIELDS" 'module=image' 'under module=image - NEVER module=sca (report.md §2.2 caveat 2)'
assert_not_contains "$FIELDS" 'module=sca' \
  'no raw module=sca finding from the reused SCA walkers ever reaches this run real shard - FAILS if the shadow-run redirection were skipped'
assert_contains "$FIELDS" "cell=$IMG_ID" "the cell is this image's own operator-declared id, never a host path-root"
assert_contains "$FIELDS" "loc_image_id=$IMG_ID" 'loc_image_id is set for the fingerprint profile'
assert_contains "$FIELDS" 'loc_ecosystem=pypi' 'the ecosystem the reused SCA walker resolved'
assert_contains "$FIELDS" 'loc_package=flask' 'the vulnerable package name'
assert_contains "$FIELDS" 'loc_advisory_id=SCOURSH-FIXTURE-PY-1' 'and the matched advisory id'
assert_contains "$FIELDS" 'path=app/requirements.txt' \
  "the finding's path is the IN-IMAGE relative path - FAILS if it instead carried the host scratch destroot's own absolute path"
assert_not_contains "$FIELDS" "$SCOURSH_SCRATCH" \
  "no host scratch path leaks into the finding at all - FAILS if the destroot's own mktemp path were left in any field"

t_case 'checks_run names the check - it executed and found something, not merely "did not run"'
assert_contains "$(_slurp "$D/meta/checks_run")" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' \
  'run_record checks_run fired regardless of the match count, mirroring every other IMAGE-* driver in this module'

# =============================================================================
printf -- '\n-- C. honesty: a rootfs with no language manifests is a declared reduction, never a silent clean --\n'
# =============================================================================

t_case 'a missing/unreadable advisories.db: IMAGE-COV-LANGDEPS_NOT_SCANNED-01 fires with detail=no_advisories_db, never a silent clean'
occurrence_reset_all
D2=$W/unit-run-nodb
rm -rf -- "${D2:?}"
run_init "$D2"
D2=$SCOURSH_RUN_DIR
export SCOURSH_SCA_ADVISORIES_DB=$W/does-not-exist.db
image_langdeps_scan docker-archive "$IMGTAR" scoursh-img11-nodb
assert_eq 0 $? 'a missing advisory database is a declared reduction, never a fatal error'
findings_merge "$D2"
FIELDS2=$(_slurp "$D2/findings.fields")
assert_contains "$FIELDS2" 'IMAGE-COV-LANGDEPS_NOT_SCANNED-01' 'the honesty check fired'
assert_contains "$FIELDS2" 'no_advisories_db' 'naming the specific, distinguishable reason'
assert_not_contains "$FIELDS2" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' \
  'no vulnerable-dependency finding - the manifest was never even looked up against anything'
export SCOURSH_SCA_ADVISORIES_DB=$FIXDB

t_case 'an image with no manifest at any declared candidate location: IMAGE-COV-LANGDEPS_NOT_SCANNED-01 fires with detail=no_manifests_found'
EMPTYLAYER=$W/empty-layer.tar
ustar_begin "$EMPTYLAYER"
ustar_add "$EMPTYLAYER" 'etc/' 5 '' ''
ustar_add "$EMPTYLAYER" 'etc/fixture-marker' 0 '' 'no manifest anywhere in this image
'
ustar_end "$EMPTYLAYER"
NOMANI_TAR=$W/nomanifest-image.tar
ustar_begin "$NOMANI_TAR"
ustar_add "$NOMANI_TAR" 'cfg0.json' 0 '' '{"architecture":"amd64","os":"linux"}'
ustar_add "$NOMANI_TAR" 'l0/' 5 '' ''
ustar_add_file "$NOMANI_TAR" 'l0/layer.tar' "$EMPTYLAYER"
ustar_add "$NOMANI_TAR" 'manifest.json' 0 '' '[{"Config":"cfg0.json","RepoTags":["fixture/nomanifest:v1"],"Layers":["l0/layer.tar"]}]'
ustar_end "$NOMANI_TAR"

occurrence_reset_all
D3=$W/unit-run-nomanifest
rm -rf -- "${D3:?}"
run_init "$D3"
D3=$SCOURSH_RUN_DIR
image_docker_archive_open "$NOMANI_TAR" ''
assert_eq 0 $? 'the no-manifest fixture archive opens'
image_langdeps_scan docker-archive "$NOMANI_TAR" scoursh-img11-nomanifest
assert_eq 0 $? 'no manifest anywhere is a declared reduction, never a fatal error'
findings_merge "$D3"
FIELDS3=$(_slurp "$D3/findings.fields")
assert_contains "$FIELDS3" 'IMAGE-COV-LANGDEPS_NOT_SCANNED-01' 'the honesty check fired'
assert_contains "$FIELDS3" 'no_manifests_found' \
  'naming the DIFFERENT reason from the no-database case - FAILS if both reasons collapsed onto one generic detail'
assert_not_contains "$FIELDS3" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'no vulnerable-dependency finding - there was nothing to look at'

# =============================================================================
printf -- '\n-- D. modules/image/checks-langdeps.rules registers cleanly --\n'
# =============================================================================

t_case 'modules/image/checks-langdeps.rules parses clean under the real record loader'
records_reset_diagnostics
_load_rc=0
records_load "$ROOT/modules/image/checks-langdeps.rules" script-check langdepschecks || _load_rc=$?
assert_eq 0 "$_load_rc" 'records_load returns 0 - no schema/format errors'
assert_eq 0 "$RECORDS_ERRORS" \
  'modules/image/checks-langdeps.rules has 0 record-format diagnostics'

t_case 'it registers exactly the two check ids this ticket owns, and no other'
assert_eq 2 "$(records_count langdepschecks)" 'exactly two records in the file'
assert_eq 'IMAGE-LANGDEP-VULNERABLE_DEP-01' "$(records_id langdepschecks 0)" 'the first record'
assert_eq 'IMAGE-COV-LANGDEPS_NOT_SCANNED-01' "$(records_id langdepschecks 1)" 'the second record'

# `run_init` (lib/core.sh) exports SCOURSH_RUN_ID/SCOURSH_RUN_DIR into THIS
# process's environment, so a real `scan.sh` subprocess launched below must
# not inherit either - mirroring tests/suites/image-e2e.sh's own identical
# reset, for the identical reason.
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# =============================================================================
printf -- '\n-- E. end to end: a real scan.sh image subprocess, full report round-trip --\n'
# =============================================================================

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

E2E_IMG_ID=scoursh-img11-e2e

t_case 'a real scan.sh image run: exit 0, IMAGE-LANGDEP-VULNERABLE_DEP-01 fires'
_image_scan "$W/e2e-run" "$FIXDB" -- --image "$E2E_IMG_ID" --source "$IMGTAR"
assert_eq 0 "$_RC" 'a run with a real vulnerable language-dependency finding still exits 0 with no --fail-on given'
E2E_JSON=$(_slurp "$W/e2e-run/run.json")
E2E_FINDINGS=$(_slurp "$W/e2e-run/findings.jsonl")
assert_contains "$E2E_JSON" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'checks_run names the check'
assert_contains "$E2E_FINDINGS" '"check_id":"IMAGE-LANGDEP-VULNERABLE_DEP-01"' 'a real finding was emitted'
assert_contains "$E2E_FINDINGS" '"module":"image"' 'under module image'
assert_not_contains "$E2E_FINDINGS" '"module":"sca"' \
  'no raw module=sca finding ever reaches the real run output through the real scan.sh image CLI path either'

t_case 'the finding location carries image_id/ecosystem/package/advisory_id, mirroring IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 (report.md §3.4)'
assert_contains "$E2E_FINDINGS" '"location":{"image_id":"'"$E2E_IMG_ID"'","ecosystem":"pypi","package":"flask","advisory_id":"SCOURSH-FIXTURE-PY-1"' \
  'the JSON location object leads with EXACTLY these four keys, in this order - the same frozen `image` fingerprint profile IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 already uses (lib/findings.sh _fp_components_for image), reused unchanged rather than needing a format-version bump'

t_case 'the finding round-trips through every report format'
assert_contains "$(_slurp "$W/e2e-run/findings.json")" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'findings.json carries it'
assert_contains "$(_slurp "$W/e2e-run/report.md")" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'report.md lists it'
assert_contains "$(_slurp "$W/e2e-run/report.html")" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'report.html lists it'
E2E_SARIF=$(_slurp "$W/e2e-run/report.sarif")
assert_contains "$E2E_SARIF" '"ruleId":"IMAGE-LANGDEP-VULNERABLE_DEP-01"' 'report.sarif names the check as its ruleId'

report_agent "$W/e2e-run"
E2E_AGENT=$(_slurp "$W/e2e-run/agent-fix.json")
assert_contains "$E2E_AGENT" '"check":"IMAGE-LANGDEP-VULNERABLE_DEP-01"' 'agent-fix.json names the check'
assert_contains "$E2E_AGENT" '"mod":"image"' 'and its module'

t_case 'a real scan.sh image run against an image with no manifest anywhere: quiet for the vulnerable-dep check, honest about why'
_image_scan "$W/e2e-run-nomanifest" "$FIXDB" -- --image scoursh-img11-e2e-nomanifest --source "$NOMANI_TAR"
assert_eq 0 "$_RC" 'exit 0'
NOMANI_FINDINGS=$(_slurp "$W/e2e-run-nomanifest/findings.jsonl")
assert_not_contains "$NOMANI_FINDINGS" 'IMAGE-LANGDEP-VULNERABLE_DEP-01' 'no vulnerable-dependency finding - there was nothing to examine'
assert_contains "$NOMANI_FINDINGS" '"check_id":"IMAGE-COV-LANGDEPS_NOT_SCANNED-01"' \
  'the honesty check fired instead of a silent clean scan'
assert_contains "$NOMANI_FINDINGS" 'no_manifests_found' 'naming the specific reason'

t_summary image-langdeps
