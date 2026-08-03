#!/usr/bin/env bash
# tests/suites/sca.sh - modules/sca/{engine.sh,run.sh}: npm lockfile parsing
# (package-lock.json v1/v2/v3, yarn.lock, pnpm-lock.yaml) and the
# data/advisories.db exact-match lookup (docs/DESIGN.md §13 step 4,
# docs/FOUNDATION.md tension 25).
#
# Covers this ticket's acceptance criteria:
#   - `scan_dispatch sca` no longer no-ops for a fixture repo containing an
#     npm lockfile with a known-vulnerable pinned dependency
#   - direct vs transitive, and no-fixed-version (accept-risk), are both
#     distinguished in the emitted finding(s)
#   - SCA-COV-UNKNOWN_VERSION-01 fires exactly once per run when applicable,
#     never per package
#   - all three lockfile parsers (package-lock.json v1 AND v2/v3, yarn.lock,
#     pnpm-lock.yaml) extract the right (name, version, direct|transitive)
#
# None of this depends on a real, production-scale data/advisories.db:
# tools/vendor-engines.sh (the only script that populates one) is never run
# in this repo/CI (AGENTS.md), so every case here points
# SCOURSH_SCA_ADVISORIES_DB at the small, committed
# tests/fixtures/sca/advisories.db instead.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sca/engine.sh
source "$ROOT/modules/sca/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIXTURES=$ROOT/tests/fixtures/sca
DB=$FIXTURES/advisories.db
W=$SCOURSH_SCRATCH/sca-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- name normalisation (docs/FOUNDATION.md tension 25): npm is verbatim --\n'
# =============================================================================
t_case 'npm normalisation is the identity function, scope included'
assert_eq 'lodash' "$(sca_npm_normalize_name lodash)" 'unscoped name unchanged'
assert_eq '@scope/pkg' "$(sca_npm_normalize_name '@scope/pkg')" 'scoped name unchanged, scope kept'

# =============================================================================
printf -- '\n-- package-lock.json v2/v3: name/version/direct-or-transitive --\n'
# =============================================================================
t_case 'v2/v3: format is detected from the top-level "packages" key'
assert_eq v2v3 "$(_sca_npm_lock_format "$FIXTURES/npm-lock/package-lock.json")" \
  'a lockfile with "packages" is classified v2v3'
assert_eq v1 "$(_sca_npm_lock_format "$FIXTURES/npm-lock-v1/package-lock.json")" \
  'a lockfile with no "packages" key (only "dependencies") is classified v1 - fails if format detection defaulted the wrong way'

V2V3_OUT=$(sca_parse_package_lock "$FIXTURES/npm-lock/package-lock.json")
t_case 'v2/v3: a root dependency, installed at the top slot, is direct'
assert_contains "$V2V3_OUT" $'@scope/pkg\x1f1.0.0\x1fdirect' \
  '@scope/pkg is direct - listed in the root packages[""].dependencies map'
assert_contains "$V2V3_OUT" $'left-pad\x1f1.3.0\x1fdirect' \
  'left-pad is direct - also listed in the root dependencies map'

t_case 'v2/v3: a top-slot package NOT in the root dependency map is transitive (hoisting)'
assert_contains "$V2V3_OUT" $'lodash\x1f4.17.99\x1ftransitive' \
  'lodash occupies a top node_modules/ slot but is absent from packages[""].dependencies - hoisted, not direct'

t_case 'v2/v3: a nested node_modules/ entry is always transitive'
assert_contains "$V2V3_OUT" $'nested-thing\x1f9.9.9\x1ftransitive' \
  'node_modules/left-pad/node_modules/nested-thing (two node_modules/ segments) is transitive regardless of name'
assert_contains "$V2V3_OUT" $'minimist\x1f9.9.9\x1ftransitive' \
  'the SECOND minimist occurrence (nested under left-pad) is transitive even though a top-level minimist@1.2.5 also exists'
assert_contains "$V2V3_OUT" $'minimist\x1f1.2.5\x1ftransitive' \
  'the top-level minimist@1.2.5 is transitive too - never listed in the root dependency map'

# =============================================================================
printf -- '\n-- package-lock.json v1: recursive dependencies, package.json fallback --\n'
# =============================================================================
t_case 'v1: sca_npm_direct_deps reads the sibling package.json'
DIRECT_V1=$(sca_npm_direct_deps "$FIXTURES/npm-lock-v1")
assert_eq lodash "$DIRECT_V1" 'only "lodash" is declared in the v1 fixture package.json'

V1_OUT=$(sca_parse_package_lock "$FIXTURES/npm-lock-v1/package-lock.json")
t_case 'v1: a top-level entry present in package.json is direct'
assert_contains "$V1_OUT" $'lodash\x1f4.17.15\x1fdirect' \
  'lodash is a top-level dependencies entry AND is in package.json - direct'

t_case 'v1: a top-level entry ABSENT from package.json is transitive (a hoisted dep occupying the top slot)'
assert_contains "$V1_OUT" $'left-pad\x1f1.3.0\x1ftransitive' \
  'left-pad sits at the TOP of the v1 dependencies map but package.json never declares it - fails if the top-slot heuristic were used unconditionally instead of deferring to package.json'

t_case 'v1: a nested (recursively un-hoisted) entry is always transitive'
assert_contains "$V1_OUT" $'minimist\x1f1.2.5\x1ftransitive' \
  'minimist sits inside lodash'"'"'s own nested "dependencies" map'

# =============================================================================
printf -- '\n-- yarn.lock: header parsing and the package.json / graph fallback --\n'
# =============================================================================
YARN_OUT=$(sca_parse_yarn_lock "$FIXTURES/yarn/yarn.lock")
t_case 'yarn.lock: a package.json dependency is direct'
assert_contains "$YARN_OUT" $'lodash\x1f4.17.15\x1fdirect' \
  'lodash is declared in the yarn fixture package.json'
t_case 'yarn.lock: a package only reachable via another entry'"'"'s dependencies: sub-block is transitive'
assert_contains "$YARN_OUT" $'minimist\x1f1.2.5\x1ftransitive' \
  'minimist is not in package.json and is referenced by lodash'"'"'s own dependencies: block'

# =============================================================================
printf -- '\n-- pnpm-lock.yaml: importers direct-dependency set --\n'
# =============================================================================
PNPM_DIRECT=$(_sca_pnpm_importers_direct_deps "$FIXTURES/pnpm/pnpm-lock.yaml")
t_case 'pnpm: importers -> . -> dependencies is read as the direct set'
assert_eq lodash "$PNPM_DIRECT" 'the fixture pnpm-lock.yaml importers block declares only lodash'

PNPM_OUT=$(sca_parse_pnpm_lock "$FIXTURES/pnpm/pnpm-lock.yaml")
t_case 'pnpm-lock.yaml: an importer dependency is direct, everything else is transitive'
assert_contains "$PNPM_OUT" $'lodash\x1f4.17.15\x1fdirect' 'lodash is direct'
assert_contains "$PNPM_OUT" $'minimist\x1f1.2.5\x1ftransitive' \
  'minimist appears only under packages:, never under importers: - transitive'

# =============================================================================
printf -- '\n-- data/advisories.db exact-match lookup (docs/FOUNDATION.md tension 25) --\n'
# =============================================================================
t_case 'sca_lookup_exact: an exact (ecosystem, package, version) hit'
LOOKUP_HIT=$(sca_lookup_exact npm lodash 4.17.15 "$DB")
assert_contains "$LOOKUP_HIT" 'SCA-FIXTURE-ADVISORY-002' 'the exact-match row for lodash@4.17.15 is returned'

t_case 'sca_lookup_exact: no row for this exact version - miss, not a crash'
assert_status 1 'lookup of an unlisted lodash version fails cleanly (rc 1, no match)' \
  sca_lookup_exact npm lodash 4.17.16 "$DB"

t_case 'sca_package_known: true when ANY version of the package is tracked'
assert_status 0 'lodash is known at some version, even though 4.17.16 itself is not' \
  sca_package_known npm lodash "$DB"
t_case 'sca_package_known: false when the package has no advisories.db rows at all'
assert_status 1 'a package the fixture db never mentions is NOT "known" - this is the unknown-version roll-up'"'"'s own precondition, not "not vulnerable"' \
  sca_package_known npm totally-untracked-package "$DB"

# =============================================================================
printf -- '\n-- sca_scan_tree: full npm-lock fixture against the fixture db --\n'
# =============================================================================
RUNDIR=$W/run-npm-lock
rm -rf "$RUNDIR"
run_init "$RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/npm-lock")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/npm-lock")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/npm-lock"
findings_merge "$RUNDIR"

_sca_findings() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\x1f%s\x1f%s\n' "${_DF[check_id]}" "${_DF[title]}" "${_DF[evidence]}"
  done <"$rundir/findings.fields"
}
SCA_FINDINGS=$(_sca_findings "$RUNDIR")

t_case 'AC: scan_dispatch sca no longer no-ops - it finds the known-vulnerable pinned dependency'
assert_contains "$SCA_FINDINGS" 'SCA-NPM-VULNERABLE_DEP-01' \
  'at least one SCA-NPM-VULNERABLE_DEP-01 finding was emitted for the fixture repo'

t_case 'AC: direct vs transitive is distinguished in the emitted finding evidence'
assert_contains "$SCA_FINDINGS" 'dependency_type: direct' 'a direct dependency finding carries dependency_type: direct'
assert_contains "$SCA_FINDINGS" 'dependency_type: transitive' 'a transitive dependency finding carries dependency_type: transitive'

t_case 'AC: a no-fixed-version advisory is flagged as an accept-risk candidate'
assert_contains "$SCA_FINDINGS" 'accept_risk_candidate: true' \
  'left-pad@1.3.0 (SCA-FIXTURE-ADVISORY-004, empty fixed_versions in the db) is flagged accept_risk_candidate: true'
assert_contains "$SCA_FINDINGS" 'fixed_versions: none published' \
  'the empty fixed_versions db field renders as "none published", not a silently-blank/misaligned field (regression: bash `read` with a literal-tab IFS collapses an empty middle TSV field and shifts every field after it - see _sca_emit_finding'"'"'s own comment)'
assert_contains "$SCA_FINDINGS" 'accept_risk_candidate: false' \
  'a dependency WITH a fixed version (e.g. @scope/pkg) is NOT flagged as accept-risk - proves the flag is not stuck on one constant value'

t_case 'AC: SCA-COV-UNKNOWN_VERSION-01 fires exactly ONCE, not per package'
_UNKNOWN_COUNT=$(printf '%s\n' "$SCA_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$_UNKNOWN_COUNT" \
  'exactly one roll-up finding - fails if lodash@4.17.99 and minimist@9.9.9 (both: package known, exact pinned version unmatched) each produced their own finding instead of one aggregate'
assert_contains "$SCA_FINDINGS" 'SCA: 2 pinned dependency version' \
  'the roll-up title states the correct aggregate count (2: lodash@4.17.99 and minimist@9.9.9)'

t_case 'a package with NO advisories.db rows at all does not appear in the roll-up or as a finding'
assert_not_contains "$SCA_FINDINGS" 'nested-thing' \
  'nested-thing has no db rows whatsoever (sca_package_known is false for it) - absence is silent, not an unknown-version count'

t_case 'run.json: checks_run records both check ids actually executed'
assert_contains "$(cat "$RUNDIR/meta/checks_run" 2>/dev/null)" 'SCA-NPM-VULNERABLE_DEP-01' \
  'SCA-NPM-VULNERABLE_DEP-01 is recorded as run'
assert_contains "$(cat "$RUNDIR/meta/checks_run" 2>/dev/null)" 'SCA-COV-UNKNOWN_VERSION-01' \
  'SCA-COV-UNKNOWN_VERSION-01 is recorded as run (only because the roll-up actually fired this run)'

t_case 'run.json: the unknown-version coverage_gap is recorded with the ecosystem breakdown'
assert_contains "$(cat "$RUNDIR/meta/coverage_gap" 2>/dev/null)" 'ecosystem=npm count=2' \
  'the coverage_gap fact carries the same count the roll-up finding'"'"'s title states'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- data/advisories.db absent: an honest coverage_reduction, never a crash --\n'
# =============================================================================
RUNDIR2=$W/run-no-db
rm -rf "$RUNDIR2"
run_init "$RUNDIR2"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/npm-lock")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/npm-lock")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$W/does-not-exist.db

t_case 'sca_scan_tree with no readable db records coverage_reduction and does not die'
assert_status 0 'a missing advisories.db is a declared reduction, not a fatal error' \
  sca_scan_tree "$FIXTURES/npm-lock"
sca_scan_tree "$FIXTURES/npm-lock" >/dev/null 2>&1 || true
assert_contains "$(cat "$RUNDIR2/meta/coverage_reduction" 2>/dev/null)" 'no_advisories_db_on_disk' \
  'the honest reason is recorded in run.json (via meta/coverage_reduction)'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- end-to-end: a real scan.sh subprocess, scan_dispatch sca no longer a no-op --\n'
# =============================================================================
t_case 'scan.sh sca --path against the fixture repo exits 0 and reports the vulnerable dependency'
E2E_RUNDIR=$W/run-e2e
rm -rf "$E2E_RUNDIR"
assert_status 0 'a real subprocess against the npm-lock fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/npm-lock" --out "$E2E_RUNDIR"
E2E_RUNJSON=$(cat "$E2E_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_RUNJSON" '"SCA-NPM-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the check actually executed through the real scan.sh entry point (scan_dispatch sca), not just when the module is sourced standalone'
assert_contains "$E2E_RUNJSON" '"sca":4' \
  'run.json by_module counts 4 live findings for sca - the fixture'"'"'s 3 distinct-version vulnerable rows plus the one roll-up'

t_summary 'sca' || FAILED=1
exit "${FAILED:-0}"
