#!/usr/bin/env bash
# tests/suites/sca.sh - modules/sca/{engine.sh,run.sh}: npm lockfile parsing
# (package-lock.json v1/v2/v3, yarn.lock, pnpm-lock.yaml), Ruby/RubyGems
# lockfile parsing (Gemfile.lock), and the data/advisories.db exact-match
# lookup (docs/DESIGN.md §13 step 4, docs/FOUNDATION.md tension 25).
#
# Covers the npm ticket's acceptance criteria:
#   - `scan_dispatch sca` no longer no-ops for a fixture repo containing an
#     npm lockfile with a known-vulnerable pinned dependency
#   - direct vs transitive, and no-fixed-version (accept-risk), are both
#     distinguished in the emitted finding(s)
#   - SCA-COV-UNKNOWN_VERSION-01 fires exactly once per run when applicable,
#     never per package
#   - all three lockfile parsers (package-lock.json v1 AND v2/v3, yarn.lock,
#     pnpm-lock.yaml) extract the right (name, version, direct|transitive)
#
# ...and this ticket's (Ruby) own acceptance criteria:
#   - a fixture Gemfile.lock with a known-vulnerable pinned gem reports it
#     under SCA-RUBY-VULNERABLE_DEP-01
#   - a mixed-case gem name normalises to lowercase before the db lookup and
#     still resolves to its advisory
#   - direct (top-level DEPENDENCIES) vs transitive (GEM/specs only) is
#     classified correctly per gem
#   - a gem whose advisory carries no fixed version is flagged accept-risk,
#     not skipped and not mismatched
#   - a gem known to the db but at an unmatched exact version contributes to
#     the SHARED SCA-COV-UNKNOWN_VERSION-01 roll-up - proven both in
#     isolation and, in the mixed-ecosystems case below, combined with an
#     npm-side unknown-version gem in the SAME roll-up finding
#
# None of this depends on a real, production-scale data/advisories.db:
# tools/vendor-engines.sh (the only script that populates one) is never run
# in this repo/CI (AGENTS.md), so every case here points
# SCOURSH_SCA_ADVISORIES_DB at the small, committed
# tests/fixtures/sca/advisories.db instead (now carrying both npm and
# RubyGems fixture rows).
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
printf -- '\n-- Gemfile.lock: DEPENDENCIES set, specs parsing, direct-or-transitive --\n'
# =============================================================================
t_case 'Gemfile.lock: _sca_gemfile_dependencies_set reads the top-level DEPENDENCIES stanza'
RUBY_DIRECT=$(_sca_gemfile_dependencies_set "$FIXTURES/ruby/Gemfile.lock")
assert_contains "$RUBY_DIRECT" 'RailsAddon' 'RailsAddon is declared in the fixture'"'"'s DEPENDENCIES stanza'
assert_contains "$RUBY_DIRECT" 'puma' 'puma is declared in the fixture'"'"'s DEPENDENCIES stanza'
assert_not_contains "$RUBY_DIRECT" 'rack' \
  'rack is never listed in DEPENDENCIES - only reachable as RailsAddon'"'"'s own specs: annotation'

RUBY_OUT=$(sca_parse_gemfile_lock "$FIXTURES/ruby/Gemfile.lock")
t_case 'Gemfile.lock: a DEPENDENCIES entry is direct, exact case preserved pre-normalisation'
assert_contains "$RUBY_OUT" $'RailsAddon\x1f2.0.0\x1fdirect' \
  'RailsAddon is direct - listed verbatim (mixed case) in DEPENDENCIES'
assert_contains "$RUBY_OUT" $'puma\x1f5.6.4\x1fdirect' 'puma is direct'

t_case 'Gemfile.lock: a specs-only entry (never in DEPENDENCIES) is transitive'
assert_contains "$RUBY_OUT" $'rack\x1f2.2.3\x1ftransitive' \
  'rack is only ever a specs: entry and RailsAddon'"'"'s own dependency annotation, never in DEPENDENCIES'
assert_contains "$RUBY_OUT" $'nokogiri\x1f1.13.8\x1ftransitive' 'nokogiri is transitive'
assert_contains "$RUBY_OUT" $'mini_portile2\x1f2.8.1\x1ftransitive' \
  'mini_portile2 is transitive - fails if the 6-space nested annotation line under nokogiri were mistaken for a second specs: entry'

# =============================================================================
printf -- '\n-- name normalisation (docs/FOUNDATION.md tension 25): RubyGems is lowercased --\n'
# =============================================================================
t_case 'RubyGems normalisation lowercases the name (unlike npm'"'"'s identity function)'
assert_eq railsaddon "$(sca_ruby_normalize_name RailsAddon)" 'mixed-case gem name is lowercased'
assert_eq puma "$(sca_ruby_normalize_name puma)" 'an already-lowercase name is unaffected'

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

t_case 'sca_lookup_exact: the same exact-match path works for RubyGems, keyed on the normalised (lowercase) name'
RUBY_LOOKUP_HIT=$(sca_lookup_exact RubyGems railsaddon 2.0.0 "$DB")
assert_contains "$RUBY_LOOKUP_HIT" 'SCA-FIXTURE-RUBY-001' \
  'the exact-match row for railsaddon@2.0.0 is returned once the mixed-case DEPENDENCIES name is normalised to lowercase'
t_case 'sca_lookup_exact: the raw (un-normalised) mixed-case name does NOT match - proves normalisation is load-bearing, not incidental'
assert_status 1 'a lookup using the raw "RailsAddon" spelling misses, because data/advisories.db stores the lowercase key' \
  sca_lookup_exact RubyGems RailsAddon 2.0.0 "$DB"
t_case 'sca_package_known: RubyGems, package known at a different version'
assert_status 0 'mini_portile2 is known at 2.9.0 in the fixture db, even though 2.8.1 (the fixture'"'"'s pinned version) is not' \
  sca_package_known RubyGems mini_portile2 "$DB"
t_case 'sca_package_known: RubyGems, a package the db never mentions at all'
assert_status 1 'nokogiri has no data/advisories.db rows whatsoever' \
  sca_package_known RubyGems nokogiri "$DB"

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
printf -- '\n-- sca_scan_tree: full Gemfile.lock fixture against the fixture db --\n'
# =============================================================================
RUBY_RUNDIR=$W/run-ruby
rm -rf "$RUBY_RUNDIR"
run_init "$RUBY_RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/ruby")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/ruby")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/ruby"
findings_merge "$RUBY_RUNDIR"
RUBY_FINDINGS=$(_sca_findings "$RUBY_RUNDIR")

t_case 'AC: a fixture Gemfile.lock with a known-vulnerable pinned gem reports it under SCA-RUBY-VULNERABLE_DEP-01'
assert_contains "$RUBY_FINDINGS" 'SCA-RUBY-VULNERABLE_DEP-01' \
  'at least one SCA-RUBY-VULNERABLE_DEP-01 finding was emitted for the ruby fixture'

t_case 'AC: a mixed-case gem name (RailsAddon) normalises to lowercase and still resolves to its advisory'
assert_contains "$RUBY_FINDINGS" 'railsaddon@2.0.0 is vulnerable (SCA-FIXTURE-RUBY-001)' \
  'the finding title carries the lowercase-normalised package name matched against the db, proving RailsAddon -> railsaddon -> SCA-FIXTURE-RUBY-001 round-tripped'

t_case 'AC: direct vs transitive is classified from DEPENDENCIES vs GEM/specs-only, per dependency'
assert_contains "$RUBY_FINDINGS" 'dependency: railsaddon@2.0.0\ndependency_type: direct' \
  'railsaddon is direct - listed in the fixture'"'"'s top-level DEPENDENCIES stanza'
assert_contains "$RUBY_FINDINGS" 'dependency: rack@2.2.3\ndependency_type: transitive' \
  'rack is transitive - only a GEM/specs entry (and RailsAddon'"'"'s own dependency annotation), never in DEPENDENCIES'

t_case 'AC: a gem with no fixed/pinned version in its advisory is flagged accept-risk, not skipped or mismatched'
assert_contains "$RUBY_FINDINGS" 'dependency: puma@5.6.4\ndependency_type: direct\nlockfile: Gemfile.lock\nadvisory: SCA-FIXTURE-RUBY-002 (critical)\nfixed_versions: none published\naccept_risk_candidate: true' \
  'puma@5.6.4 (SCA-FIXTURE-RUBY-002, empty fixed_versions in the db) is reported - not silently skipped - and flagged accept_risk_candidate: true'

t_case 'AC: contributes to the SHARED SCA-COV-UNKNOWN_VERSION-01 roll-up (RubyGems side, in isolation)'
RUBY_UNKNOWN_COUNT=$(printf '%s\n' "$RUBY_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$RUBY_UNKNOWN_COUNT" \
  'exactly one roll-up finding for the ruby-only fixture (mini_portile2@2.8.1: package known at 2.9.0, exact version unmatched)'
assert_contains "$RUBY_FINDINGS" 'SCA: 1 pinned dependency version' \
  'the roll-up title states the correct count (1: mini_portile2)'
assert_contains "$RUBY_FINDINGS" 'RubyGems: 1' 'the roll-up breakdown names the RubyGems ecosystem'

t_case 'a gem with NO advisories.db rows at all (nokogiri) does not appear in the roll-up or as a finding'
assert_not_contains "$RUBY_FINDINGS" 'nokogiri' \
  'nokogiri has no db rows whatsoever (sca_package_known is false for it) - absence is silent, not an unknown-version count'

t_case 'run.json: checks_run records SCA-RUBY-VULNERABLE_DEP-01 and the shared roll-up check'
assert_contains "$(cat "$RUBY_RUNDIR/meta/checks_run" 2>/dev/null)" 'SCA-RUBY-VULNERABLE_DEP-01' \
  'SCA-RUBY-VULNERABLE_DEP-01 is recorded as run'
assert_contains "$(cat "$RUBY_RUNDIR/meta/checks_run" 2>/dev/null)" 'SCA-COV-UNKNOWN_VERSION-01' \
  'SCA-COV-UNKNOWN_VERSION-01 is recorded as run'

t_case 'run.json: the unknown-version coverage_gap is recorded under the RubyGems ecosystem'
assert_contains "$(cat "$RUBY_RUNDIR/meta/coverage_gap" 2>/dev/null)" 'ecosystem=RubyGems count=1' \
  'the coverage_gap fact carries the same count the roll-up finding'"'"'s title states'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- sca_scan_tree: mixed npm + Ruby root - one SHARED SCA-COV-UNKNOWN_VERSION-01 --\n'
# =============================================================================
# tests/fixtures/sca/mixed-ecosystems/ carries BOTH a package-lock.json
# (lodash pinned at 4.17.99 - known package, unmatched exact version) and a
# Gemfile.lock (mini_portile2 pinned at 2.8.1 - same shape).  This is the
# AC's own "shared roll-up" case made concrete: one sca_scan_tree call over
# one root must produce exactly ONE SCA-COV-UNKNOWN_VERSION-01 finding whose
# breakdown mentions BOTH ecosystems, not two competing findings that would
# collide on one fingerprint (module=sca, check_id=SCA-COV-UNKNOWN_VERSION-01,
# and no ecosystem/package/advisory_id component - see sca_scan_tree's own
# header comment in modules/sca/engine.sh) and have findings_merge's dedup
# silently drop one ecosystem's count.
MIXED_RUNDIR=$W/run-mixed
rm -rf "$MIXED_RUNDIR"
run_init "$MIXED_RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/mixed-ecosystems")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/mixed-ecosystems")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/mixed-ecosystems"
findings_merge "$MIXED_RUNDIR"
MIXED_FINDINGS=$(_sca_findings "$MIXED_RUNDIR")

t_case 'AC: one root with both an npm lockfile and a Gemfile.lock produces exactly ONE roll-up finding'
MIXED_UNKNOWN_COUNT=$(printf '%s\n' "$MIXED_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$MIXED_UNKNOWN_COUNT" \
  'exactly one SCA-COV-UNKNOWN_VERSION-01 finding - fails if npm and RubyGems each produced their own (which would also silently collide on one fingerprint and lose data in findings_merge'"'"'s dedup)'

t_case 'AC: the single roll-up breakdown combines BOTH ecosystems'"'"' counts'
assert_contains "$MIXED_FINDINGS" 'SCA: 2 pinned dependency version' \
  'the roll-up title sums both ecosystems'"'"' unknown-version counts (1 npm + 1 RubyGems = 2)'
assert_contains "$MIXED_FINDINGS" 'npm: 1' 'the breakdown names npm'"'"'s own count'
assert_contains "$MIXED_FINDINGS" 'RubyGems: 1' 'the breakdown names RubyGems'"'"'s own count'

t_case 'run.json: coverage_gap carries one fact per ecosystem, both from the same run'
MIXED_GAP=$(cat "$MIXED_RUNDIR/meta/coverage_gap" 2>/dev/null)
assert_contains "$MIXED_GAP" 'ecosystem=npm count=1' 'npm'"'"'s own coverage_gap fact is recorded'
assert_contains "$MIXED_GAP" 'ecosystem=RubyGems count=1' 'RubyGems'"'"'s own coverage_gap fact is recorded'

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

# =============================================================================
# Python: requirements.txt, poetry.lock, Pipfile.lock (docs/DESIGN.md §13
# step 4's Python slice, docs/FOUNDATION.md tension 25).
#
# Covers this ticket's own acceptance criteria:
#   - a known-vulnerable pinned dependency is reported for each of
#     requirements.txt, poetry.lock, and Pipfile.lock, against the same
#     fixture-scale advisories.db
#   - PEP 503 normalisation (lowercase, `-`/`_`/`.` runs collapsed to one
#     `-`) is proven with a raw form that differs from its normalised form
#   - direct vs transitive is determined from poetry.lock/Pipfile.lock
#     themselves (or their sibling manifest); requirements.txt always
#     reports `unknown`, never a guess
#   - a no-fixed-version advisory is flagged accept-risk; an unresolved
#     version (unmatched pin, or no pin at all) feeds SCA-COV-UNKNOWN_VERSION-01
#   - npm's own section 1-9 functions/fixtures/assertions above are
#     untouched by anything below this point
# =============================================================================

# =============================================================================
printf -- '\n-- PyPI name normalisation (docs/FOUNDATION.md tension 25): PEP 503 --\n'
# =============================================================================
t_case 'PEP 503: lowercase, with runs of -/_/. collapsed to a single -'
assert_eq 'flask-login' "$(sca_pypi_normalize_name Flask_Login)" \
  'raw "Flask_Login" (mixed case, underscore) normalises to "flask-login" - proves normalisation actually runs, not just a lowercase-only pass'
assert_eq 'django-rest-framework' "$(sca_pypi_normalize_name 'Django.REST_Framework')" \
  'mixed "." and "_" runs both collapse to a single "-", and case folds too'
assert_ne 'Flask_Login' "$(sca_pypi_normalize_name Flask_Login)" \
  'the raw and normalised forms differ for this fixture name - the exact case this AC requires a test to prove'

# =============================================================================
printf -- '\n-- requirements.txt: flat pins, unresolved specifiers, stated "unknown" limitation --\n'
# =============================================================================
REQ_OUT=$(sca_parse_requirements_txt "$FIXTURES/python-requirements/requirements.txt")
t_case 'requirements.txt: a `==`-pinned requirement is extracted with its exact version'
assert_contains "$REQ_OUT" $'Flask_Login\x1f1.2.3\x1funknown' \
  'Flask_Login==1.2.3 is read as name=Flask_Login version=1.2.3 (normalisation happens at lookup time, not in the parser)'

t_case 'requirements.txt: a range specifier (no exact pin) still yields a row, with an empty version field'
assert_contains "$REQ_OUT" $'numpy\x1f\x1funknown' \
  'numpy>=1.10 has no exact version to extract - the empty version field is what lets the caller still ask sca_package_known about it'

t_case 'requirements.txt: an extras marker and a trailing environment marker are both stripped'
assert_contains "$REQ_OUT" $'some-pkg\x1f9.9.9\x1funknown' \
  'some-pkg[extra]==9.9.9 ; python_version >= "3.8" reduces to name=some-pkg version=9.9.9'

t_case 'requirements.txt: a `-r` option line and a VCS URL requirement are skipped, not misparsed'
assert_not_contains "$REQ_OUT" 'base.txt' 'the -r base.txt option line produced no row'
assert_not_contains "$REQ_OUT" 'vcspkg' 'the git+ VCS requirement (no static version) produced no row'

t_case 'AC: direct/transitive is always literal "unknown" for requirements.txt - never guessed'
assert_not_contains "$REQ_OUT" 'direct' 'no row claims "direct"'
assert_not_contains "$REQ_OUT" $'\x1ftransitive' 'no row claims "transitive"'

# =============================================================================
printf -- '\n-- poetry.lock: sibling pyproject.toml direct set, [package.dependencies] graph fallback --\n'
# =============================================================================
t_case 'poetry.lock: sca_poetry_pyproject_direct_deps reads [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies], excluding "python"'
PYPROJECT_DIRECT=$(sca_poetry_pyproject_direct_deps "$FIXTURES/python-poetry/pyproject.toml")
assert_contains "$PYPROJECT_DIRECT" 'requests' 'requests is declared under [tool.poetry.dependencies]'
assert_contains "$PYPROJECT_DIRECT" 'pytest' 'pytest is declared under [tool.poetry.group.dev.dependencies]'
assert_not_contains "$PYPROJECT_DIRECT" 'python' 'the "python" interpreter-constraint key is excluded - never a real PyPI package'

POETRY_OUT=$(sca_parse_poetry_lock "$FIXTURES/python-poetry/poetry.lock")
t_case 'poetry.lock: a pyproject.toml-declared dependency is direct'
assert_contains "$POETRY_OUT" $'requests\x1f2.6.0\x1fdirect' 'requests is direct - declared in the sibling pyproject.toml'
t_case 'poetry.lock: a dependency absent from pyproject.toml is transitive'
assert_contains "$POETRY_OUT" $'urllib3\x1f1.24.1\x1ftransitive' 'urllib3 is only referenced inside requests'"'"' own [package.dependencies] - transitive'
assert_contains "$POETRY_OUT" $'certifi\x1f2019.11.28\x1ftransitive' 'certifi is likewise only referenced, not declared - transitive'

t_case 'poetry.lock: with NO sibling pyproject.toml, falls back to the "referenced by nobody else" graph heuristic'
POETRY_FALLBACK_OUT=$(sca_parse_poetry_lock "$FIXTURES/python-poetry-no-manifest/poetry.lock")
assert_contains "$POETRY_FALLBACK_OUT" $'click\x1f8.0.0\x1fdirect' \
  'click is never named in any [package.dependencies] table - direct under the graph-only fallback'
assert_contains "$POETRY_FALLBACK_OUT" $'colorama\x1f0.4.4\x1ftransitive' \
  'colorama is referenced by click'"'"'s own [package.dependencies] - transitive under the graph-only fallback, fails if the fallback were "everything is direct" instead'

# =============================================================================
printf -- '\n-- Pipfile.lock: flat default/develop maps, sibling Pipfile as the only direct-set source --\n'
# =============================================================================
t_case 'Pipfile.lock: sca_pipfile_direct_deps reads [packages] and [dev-packages]'
PIPFILE_DIRECT=$(sca_pipfile_direct_deps "$FIXTURES/python-pipenv/Pipfile")
assert_contains "$PIPFILE_DIRECT" 'django' 'django is declared under [packages]'
assert_contains "$PIPFILE_DIRECT" 'pytest' 'pytest is declared under [dev-packages]'

PIPFILE_LOCK_OUT=$(sca_parse_pipfile_lock "$FIXTURES/python-pipenv/Pipfile.lock")
t_case 'Pipfile.lock: a Pipfile-declared dependency in "default" is direct'
assert_contains "$PIPFILE_LOCK_OUT" $'django\x1f1.11.1\x1fdirect' 'django is direct - declared in the sibling Pipfile'
t_case 'Pipfile.lock: a "default" entry absent from Pipfile is transitive - Pipfile.lock itself has no dependency graph to fall back on'
assert_contains "$PIPFILE_LOCK_OUT" $'pytz\x1f2016.10\x1ftransitive' \
  'pytz sits in the flat "default" map alongside django but is never declared in Pipfile - transitive'
t_case 'Pipfile.lock: a "develop" entry declared in [dev-packages] is direct too'
assert_contains "$PIPFILE_LOCK_OUT" $'pytest\x1f6.2.5\x1fdirect' 'pytest is direct - declared under [dev-packages], regardless of which JSON section it resolved into'

# =============================================================================
printf -- '\n-- sca_scan_python_tree: full fixture-scale runs against the fixture db --\n'
# =============================================================================
_sca_py_run_case() {
  local dirname=$1 rundir=$W/run-py-$1
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/$dirname")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/$dirname")
  export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  export SCOURSH_SCA_ADVISORIES_DB=$DB
  sca_scan_python_tree "$FIXTURES/$dirname"
  findings_merge "$rundir"
  _sca_findings "$rundir"
  unset SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID SCOURSH_SCA_ADVISORIES_DB
}

PY_REQ_FINDINGS=$(_sca_py_run_case python-requirements)
t_case 'AC: requirements.txt - a known-vulnerable pinned dependency is reported'
assert_contains "$PY_REQ_FINDINGS" 'SCA-PY-VULNERABLE_DEP-01' 'at least one SCA-PY-VULNERABLE_DEP-01 finding was emitted'
assert_contains "$PY_REQ_FINDINGS" 'flask-login@1.2.3' \
  'the finding is keyed on the NORMALISED name (flask-login), even though the file spells it Flask_Login'
assert_contains "$PY_REQ_FINDINGS" 'dependency_type: unknown' 'the requirements.txt-sourced finding carries the stated "unknown" direct/transitive status'
t_case 'AC: an unresolved requirements.txt specifier (numpy>=1.10, package known) contributes to the roll-up'
assert_contains "$PY_REQ_FINDINGS" 'SCA-COV-UNKNOWN_VERSION-01' 'the roll-up fired for the pypi ecosystem'
assert_contains "$PY_REQ_FINDINGS" 'SCA: 1 pinned dependency version' 'exactly one unresolved case (numpy) is counted'
assert_not_contains "$PY_REQ_FINDINGS" 'totally-unknown-py-package' \
  'a package with NO advisories.db rows at all (unlike numpy) is silently absent, not counted as unknown-version'

PY_POETRY_FINDINGS=$(_sca_py_run_case python-poetry)
t_case 'AC: poetry.lock - direct AND transitive vulnerable pinned dependencies are both reported'
assert_contains "$PY_POETRY_FINDINGS" 'requests@2.6.0' 'the direct dependency requests@2.6.0 is reported vulnerable'
assert_contains "$PY_POETRY_FINDINGS" 'dependency_type: direct' 'requests carries dependency_type: direct'
assert_contains "$PY_POETRY_FINDINGS" 'urllib3@1.24.1' 'the transitive dependency urllib3@1.24.1 is reported vulnerable'
assert_contains "$PY_POETRY_FINDINGS" 'dependency_type: transitive' 'urllib3 carries dependency_type: transitive'
t_case 'AC: a no-fixed-version pypi advisory is flagged accept-risk (urllib3), a fixed one is not (requests)'
assert_contains "$PY_POETRY_FINDINGS" 'accept_risk_candidate: true' 'urllib3 (empty fixed_versions in the fixture db) is accept-risk'
assert_contains "$PY_POETRY_FINDINGS" 'fixed_versions: none published' 'the empty fixed_versions field renders as "none published"'
assert_contains "$PY_POETRY_FINDINGS" 'accept_risk_candidate: false' 'requests (has a fixed version) is NOT accept-risk'
t_case 'poetry.lock: an unmatched-but-known pinned version (certifi) feeds the roll-up'
assert_contains "$PY_POETRY_FINDINGS" 'SCA-COV-UNKNOWN_VERSION-01' 'the roll-up fired'
assert_contains "$PY_POETRY_FINDINGS" 'SCA: 1 pinned dependency version' 'exactly one unresolved case (certifi@2019.11.28) is counted'

PY_PIPENV_FINDINGS=$(_sca_py_run_case python-pipenv)
t_case 'AC: Pipfile.lock - direct AND transitive vulnerable pinned dependencies are both reported'
assert_contains "$PY_PIPENV_FINDINGS" 'django@1.11.1' 'the direct dependency django@1.11.1 is reported vulnerable'
assert_contains "$PY_PIPENV_FINDINGS" 'dependency_type: direct' 'django carries dependency_type: direct'
assert_contains "$PY_PIPENV_FINDINGS" 'pytz@2016.10' 'the transitive dependency pytz@2016.10 is reported vulnerable'
assert_contains "$PY_PIPENV_FINDINGS" 'dependency_type: transitive' 'pytz carries dependency_type: transitive'

t_case 'run.json: checks_run records SCA-PY-VULNERABLE_DEP-01 through the real _sca_run_module ordering'
E2E_PY_RUNDIR=$W/run-py-e2e
rm -rf "$E2E_PY_RUNDIR"
assert_status 0 'a real scan.sh subprocess against the poetry.lock fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/python-poetry" --out "$E2E_PY_RUNDIR"
E2E_PY_RUNJSON=$(cat "$E2E_PY_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_PY_RUNJSON" '"SCA-PY-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the Python check actually executed through scan_dispatch sca (_sca_run_module -> _sca_py_run), not just when sca_scan_python_tree is called standalone'
assert_contains "$E2E_PY_RUNJSON" '"sca":3' \
  'run.json by_module counts 3 live findings for sca on this fixture - requests + urllib3 (vulnerable) plus the one roll-up'

t_case 'run.json: the module-level coverage_reduction facts (db-absent/single-worker/gate) are recorded exactly ONCE, not duplicated by the Python pass'
_SINGLE_WORKER_COUNT=$(printf '%s' "$E2E_PY_RUNJSON" | grep -o 'single_worker_no_parallel_scan_yet' | wc -l | tr -d ' ')
assert_eq 1 "$_SINGLE_WORKER_COUNT" \
  'exactly one occurrence - fails if sca_scan_python_tree independently re-recorded the module-level fact npm'"'"'s pass already owns'

# =============================================================================
printf -- '\n-- end-to-end: Ruby (Gemfile.lock), through the real scan.sh entry point --\n'
# =============================================================================
t_case 'scan.sh sca --path against the Ruby fixture exits 0 and reports the vulnerable gem'
E2E_RUBY_RUNDIR=$W/run-e2e-ruby
rm -rf "$E2E_RUBY_RUNDIR"
assert_status 0 'a real subprocess against the ruby fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/ruby" --out "$E2E_RUBY_RUNDIR"
E2E_RUBY_RUNJSON=$(cat "$E2E_RUBY_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_RUBY_RUNJSON" '"SCA-RUBY-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the check actually executed through the real scan.sh entry point (scan_dispatch sca), not just when the module is sourced standalone'
assert_contains "$E2E_RUBY_RUNJSON" '"sca":4' \
  'run.json by_module counts 4 live findings for sca - the ruby fixture'"'"'s 3 vulnerable gems plus the one roll-up'

t_summary 'sca' || FAILED=1
exit "${FAILED:-0}"
