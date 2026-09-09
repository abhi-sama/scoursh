#!/usr/bin/env bash
# tests/suites/image-advisories.sh - IMG-03 (data/scoursh-image-scan-design/
# report.md §2.3/§4.1/§4.3): distro-release detection from /etc/os-release,
# the data/advisories.db advisory-ecosystem reuse, and the
# IMAGE-COV-NO_ADVISORY_DB-01 exit-4 gate this ticket adds on top of IMG-02's
# acquire.sh.
#
# What this suite proves, and what it is NOT for:
#
#   A. image_os_release_parse / image_distro_ecosystem_resolve
#      (modules/image/engine.sh), unit-level: quoted/unquoted os-release
#      values, a missing ID line, an unparseable VERSION_ID, and a
#      recognised-but-not-yet-supported distro ID all resolve to the reasons
#      run.sh actually reads - never a guess (report.md §4.3's explicit
#      warning against guessing "latest").
#   B. image_ecosystem_known / image_advisories_db_path
#      (modules/image/engine.sh), unit-level: BOTH directions of the gate
#      predicate against a small, hand-built scratch data/advisories.db -
#      present for the resolved release, absent for a sibling release.
#   C. modules/image/run.sh, end to end through a real `scan.sh image`
#      subprocess against a synthetic docker-archive fixture built at test
#      time (tests/fixtures/image/mkustar.sh, the same tool
#      tests/suites/image-acquire.sh's own hostile fixtures use) carrying a
#      real /etc/os-release: the exit-4 gate fires when data/advisories.db
#      has no rows for the resolved ecosystem, and does NOT fire (falling
#      through to the still-true "no distro enumerator yet" reduction, exit
#      0) when it does - both directions, as the ticket brief requires.
#      A THIRD image with no os-release at all proves the
#      `distro_release_unknown` reduction, still exit 0, and that the
#      advisory-db gate is never reached without a resolved ecosystem.
#
# NOT this suite's job: apk enumeration (IMG-04) and the version comparator
# (IMG-05) do not exist, and no case here claims otherwise - a run that
# resolves an ecosystem the database DOES cover still emits zero package
# findings, and that is exactly what section C's "does-not-fire" case
# asserts.
#
# No network: image scanning is offline by construction (docs/DESIGN.md §1),
# and this suite never puts curl/wget/aws on PATH at all.
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
# shellcheck source=modules/image/engine.sh
source "$ROOT/modules/image/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$ROOT/tests/fixtures/image/mkustar.sh"

W=$SCOURSH_SCRATCH/image-advisories
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- A. image_os_release_parse / image_distro_ecosystem_resolve --\n'
# =============================================================================

t_case 'a quoted ID and VERSION_ID parse, with the surrounding quotes stripped'
cat >"$W/os-release-quoted" <<'EOF'
NAME="Alpine Linux"
ID=alpine
VERSION_ID="3.18.4"
PRETTY_NAME="Alpine Linux v3.18"
EOF
_rc=0
image_os_release_parse "$W/os-release-quoted" || _rc=$?
assert_eq 0 "$_rc" 'parsing succeeds - ID was present'
assert_eq alpine "$_IMAGE_OS_RELEASE_ID" 'ID is read'
assert_eq '3.18.4' "$_IMAGE_OS_RELEASE_VERSION_ID" \
  'VERSION_ID is read with its surrounding double quotes stripped, not left in as literal bytes - FAILS under a reader that treats the whole RHS as the value'

t_case 'an unquoted VERSION_ID (equally legal under os-release(5)) parses the same way'
cat >"$W/os-release-unquoted" <<'EOF'
ID=alpine
VERSION_ID=3.19.1
EOF
image_os_release_parse "$W/os-release-unquoted"
assert_eq '3.19.1' "$_IMAGE_OS_RELEASE_VERSION_ID" 'no quotes to strip, value unchanged'

t_case 'comments and a blank line are ignored, never mistaken for a KEY=VALUE line'
cat >"$W/os-release-comments" <<'EOF'
# a comment line, deliberately shaped like KEY=VALUE below it would be a bug to match
ID=alpine

VERSION_ID=3.18.0
EOF
image_os_release_parse "$W/os-release-comments"
assert_eq alpine "$_IMAGE_OS_RELEASE_ID" 'the real ID line is still read past the comment and the blank line'

t_case 'a missing file is a miss, not a crash'
_rc=0
image_os_release_parse "$W/definitely-absent-os-release" || _rc=$?
assert_eq 1 "$_rc" 'returns 1 rather than dying under set -e'
assert_eq '' "$_IMAGE_OS_RELEASE_ID" 'and leaves no stale value behind'

t_case 'a file with no ID line at all is treated the same as absent'
printf 'VERSION_ID=1.0\n' >"$W/os-release-noid"
_rc=0
image_os_release_parse "$W/os-release-noid" || _rc=$?
assert_eq 1 "$_rc" \
  'no ID means no distro was named at all - FAILS under a reader that treats a present-but-empty ID differently from an absent file'

t_case 'image_distro_ecosystem_resolve: alpine + a full patch VERSION_ID resolves to the MAJOR.MINOR ecosystem key, never the exact patch version'
image_distro_ecosystem_resolve "$W/os-release-quoted"
_rc=$?
assert_eq 0 "$_rc" 'resolves'
assert_eq 'Alpine:v3.18' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'the patch component (the trailing .4 in 3.18.4) is dropped - report.md §2.3: OSV.dev keys Alpine advisories per RELEASE (major.minor), never per exact patch build, so a comparator that kept the patch would never match a real db row'

t_case 'a different Alpine minor version resolves to a DIFFERENT ecosystem key'
image_distro_ecosystem_resolve "$W/os-release-unquoted"
assert_eq 'Alpine:v3.19' "$_IMAGE_DISTRO_ECOSYSTEM" \
  'Alpine:v3.18 != Alpine:v3.19 (report.md §4.3) - FAILS under any reading that collapses every Alpine image onto one fixed key'

t_case 'no /etc/os-release at all: no_os_release, never a guess'
_rc=0
image_distro_ecosystem_resolve "$W/definitely-absent-os-release" || _rc=$?
assert_eq 1 "$_rc" 'refused'
assert_eq no_os_release "$_IMAGE_DISTRO_REASON" 'the specific, distinguishable reason'
assert_eq '' "$_IMAGE_DISTRO_ECOSYSTEM" 'and no ecosystem is guessed - report.md §4.3 is explicit that guessing "latest" produces a false NEGATIVE on an older image, the direction that reads as a pass'

t_case 'ID present but recognised as a distro this module cannot yet map: distro_not_yet_supported, still no guess'
cat >"$W/os-release-debian" <<'EOF'
ID=debian
VERSION_ID=12
EOF
_rc=0
image_distro_ecosystem_resolve "$W/os-release-debian" || _rc=$?
assert_eq 1 "$_rc" 'refused - v1 is Alpine-only (report.md D2)'
assert_eq distro_not_yet_supported "$_IMAGE_DISTRO_REASON" \
  'a DIFFERENT, more specific reason than no_os_release - FAILS if a real, parseable os-release for an unsupported distro were folded into the same bucket as a missing file, which would tell an operator to go looking for a file that is actually right there'

t_case 'alpine ID with an unparseable VERSION_ID: os_release_version_unparseable, still no guess'
cat >"$W/os-release-badversion" <<'EOF'
ID=alpine
VERSION_ID=edge
EOF
_rc=0
image_distro_ecosystem_resolve "$W/os-release-badversion" || _rc=$?
assert_eq 1 "$_rc" 'refused - "edge" carries no major.minor to build an OSV.dev ecosystem key from'
assert_eq os_release_version_unparseable "$_IMAGE_DISTRO_REASON" 'the specific reason'

# =============================================================================
printf -- '\n-- B. image_ecosystem_known / image_advisories_db_path --\n'
# =============================================================================

FIXDB=$W/advisories.db
cat >"$FIXDB" <<EOF
# scoursh image-advisories test fixture advisories.db - NOT the real database.
# generated: 1970-01-01T00:00:00Z
Alpine:v3.18	openssl	3.1.4-r1	SCOURSH-FIXTURE-CVE-1	high	3.1.4-r2
Alpine:v3.18	openssl	3.1.4-r2	SCOURSH-FIXTURE-CVE-1	high	3.1.4-r2
npm	left-pad-fixture	1.0.0	SCOURSH-FIXTURE-GHSA-1	medium	1.0.1
EOF

t_case 'image_advisories_db_path honours the SAME SCOURSH_SCA_ADVISORIES_DB override modules/sca/ reads'
assert_eq "$FIXDB" "$(SCOURSH_SCA_ADVISORIES_DB=$FIXDB image_advisories_db_path)" \
  'the env var name is reused verbatim - FAILS if this module invented its own override name, which would make a test (or an operator) redirect one module and not the other'

t_case 'image_ecosystem_known: fires FALSE (known) for the ecosystem the fixture db covers'
_rc=0
image_ecosystem_known 'Alpine:v3.18' "$FIXDB" || _rc=$?
assert_eq 0 "$_rc" 'Alpine:v3.18 has rows - the gate must NOT fire for this release'

t_case 'image_ecosystem_known: fires TRUE (unknown) for a sibling release the fixture db does NOT cover'
_rc=0
image_ecosystem_known 'Alpine:v3.19' "$FIXDB" || _rc=$?
assert_eq 1 "$_rc" \
  'Alpine:v3.19 has no row even though Alpine:v3.18 does - the gate MUST fire, since a db that covers one release says nothing about a sibling one (report.md §4.3)'

t_case 'image_ecosystem_known: an entirely absent db file is also "unknown", never a crash'
_rc=0
image_ecosystem_known 'Alpine:v3.18' "$W/definitely-absent.db" || _rc=$?
assert_eq 1 "$_rc" 'db_lookup_exact returns 1 for an unreadable file, and this function passes that straight through'

# =============================================================================
printf -- '\n-- C. end to end: scan.sh image against a synthetic alpine-shaped image --\n'
# =============================================================================

# `_mkimg NAME OS_RELEASE_CONTENT` - a one-layer docker-save tarball, built at
# test time exactly the way tests/suites/image-acquire.sh's own hostile
# fixtures are (mkustar.sh's own header explains why: determinism, and this
# suite needs a shape - a real, parseable /etc/os-release naming a specific
# distro release - that is specific to THIS ticket and does not belong among
# tests/fixtures/image/'s committed, cross-ticket fixtures).  An empty
# OS_RELEASE_CONTENT omits the member entirely, for the "no os-release at
# all" case.
_mkimg() {
  local name=$1 osrelease=$2
  local tar=$W/$name.tar
  local l=$W/$name-layer.tar
  ustar_begin "$l"
  if [[ -n $osrelease ]]; then
    ustar_add "$l" 'etc/' 5 '' ''
    ustar_add "$l" 'etc/os-release' 0 '' "$osrelease"
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

ALPINE_318_IMG=$(_mkimg alpine318 'ID=alpine
VERSION_ID=3.18.4
')
NOOS_IMG=$(_mkimg noosrelease '')

# `_image_scan RUNDIR ADVISORIES_DB -- ARGS...` - a real `scan.sh image`
# subprocess, SCOURSH_SCA_ADVISORIES_DB pointed at a per-case scratch file so
# this suite never touches this repository's own (absent) data/advisories.db.
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

t_case 'the gate FIRES: a real image resolves Alpine:v3.18, and the fixture db has NO rows for it - exit 4'
EMPTY_DB=$W/empty-advisories.db
printf '# empty\n' >"$EMPTY_DB"
_image_scan "$W/run-nodb" "$EMPTY_DB" -- --image alpine318 --source "$ALPINE_318_IMG"
assert_eq "$SCOURSH_EXIT_INPUT" "$_RC" \
  'exit 4 (SCOURSH_EXIT_INPUT), mirroring modules/sca/run.sh'"'"'s own no-advisory-db gate verbatim'
RUN_NODB_JSON=$(_slurp "$W/run-nodb/run.json")
assert_contains "$RUN_NODB_JSON" 'IMAGE-COV-NO_ADVISORY_DB-01' \
  'checks_run names the check - FAILS if run_record checks_run were never called'
assert_contains "$(_slurp "$W/run-nodb/findings.jsonl")" '"check_id":"IMAGE-COV-NO_ADVISORY_DB-01"' \
  'and a REAL finding was emitted (findings.jsonl, written unconditionally by report_all) - not merely logged, and not merely named in checks_run with no finding behind it'
assert_contains "$(_slurp "$W/run-nodb/findings.jsonl")" '"cell":"alpine318"' \
  'the finding'"'"'s cell is the operator'"'"'s own stable --image id (rules/RULE-FORMAT.md §9.5.1), matching the image-id coverage-scope this module has used since IMG-01'
assert_contains "$RUN_NODB_JSON" 'reason=no_advisories_db_for_ecosystem image=alpine318 ecosystem=Alpine:v3.18' \
  'the reduction names both the image id and the SPECIFIC resolved ecosystem - not a generic "no database at all" claim, since data/advisories.db can genuinely exist and simply not cover this release'
assert_not_contains "$RUN_NODB_JSON" 'reason=no_distro_enumerator_on_disk_yet' \
  'the OLDER, still-true-once-a-db-exists reduction must NOT also fire on this path - the gate is a real branch, not an addition'

t_case 'the gate does NOT fire: the fixture db HAS rows for Alpine:v3.18 - exit 0, and the still-true "no enumerator" reduction fires instead'
_image_scan "$W/run-withdb" "$FIXDB" -- --image alpine318 --source "$ALPINE_318_IMG"
assert_eq 0 "$_RC" \
  'exit 0 - FAILS if the gate fired anyway (fixture db genuinely covers Alpine:v3.18), and FAILS under "resolving an ecosystem the db covers is itself enough to claim a scan happened", since IMG-04/IMG-05 do not exist yet'
RUN_WITHDB_JSON=$(_slurp "$W/run-withdb/run.json")
# NOTE: run.json's own "checks_selected" fact names IMAGE-COV-NO_ADVISORY_DB-01
# on every run once it is registered (modules/image/checks-advisories.rules),
# whether or not it actually fires - checks_selected is "eligible under this
# profile/intensity", checks_run is "actually executed". The assertions below
# therefore check findings.jsonl and checks_run specifically, never the whole
# run.json blob for the bare check id string.
assert_not_contains "$(_slurp "$W/run-withdb/findings.jsonl")" 'IMAGE-COV-NO_ADVISORY_DB-01' \
  'no coverage-gap finding this time - the ecosystem IS known'
assert_contains "$RUN_WITHDB_JSON" 'reason=no_distro_enumerator_on_disk_yet image=alpine318 ecosystem=Alpine:v3.18' \
  'the run is still honest that nothing was actually matched against a package - IMG-04 (apk enumeration) and IMG-05 (the comparator) are still absent from disk'
assert_contains "$RUN_WITHDB_JSON" '"checks_run": []' \
  'checks_run stays empty on this path too - a resolved, covered ecosystem is not itself a check that ran'

t_case 'no /etc/os-release at all: distro_release_unknown, exit 0, and the advisory-db gate is never reached'
_image_scan "$W/run-noos" "$FIXDB" -- --image noosrelease --source "$NOOS_IMG"
assert_eq 0 "$_RC" 'exit 0 - an unresolvable distro release is a declared reduction, not a fatal error'
RUN_NOOS_JSON=$(_slurp "$W/run-noos/run.json")
assert_contains "$RUN_NOOS_JSON" 'reason=distro_release_unknown image=noosrelease detail=no_os_release' \
  'the declared reduction the brief names verbatim, carrying the specific detail'
assert_not_contains "$(_slurp "$W/run-noos/findings.jsonl")" 'IMAGE-COV-NO_ADVISORY_DB-01' \
  'the advisory-db gate never ran at all - FAILS under a reading that falls through to "no rows for an empty ecosystem string", which would be a different, misleading claim'
assert_contains "$RUN_NOOS_JSON" '"checks_run": []' \
  'checks_run stays empty - the check is SELECTABLE (registered) but nothing here EXECUTED it'
assert_not_contains "$RUN_NOOS_JSON" 'reason=no_distro_enumerator_on_disk_yet' \
  'and neither does the "ecosystem known, no enumerator" reduction - there is no ecosystem to be known'
assert_contains "$RUN_NOOS_JSON" 'absence of a test, not the absence of a problem' \
  'and the coverage_gap still states the docs/DESIGN.md §15 warning in the artifact itself'

t_case 'checks-advisories.rules really is loaded: the module check-registry gate no longer fires "no registry on disk"'
assert_not_contains "$RUN_NOOS_JSON" 'no_check_registry_on_disk_yet' \
  'IMG-03 registers IMAGE-COV-NO_ADVISORY_DB-01 in modules/image/checks-advisories.rules - FAILS if the file were missing, malformed, or outside the checks_registry_load glob'

t_summary image-advisories
