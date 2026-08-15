#!/usr/bin/env bash
# tests/suites/sca.sh - modules/sca/{engine.sh,php_engine.sh,go_engine.sh,run.sh}:
# npm lockfile parsing (package-lock.json v1/v2/v3, yarn.lock,
# pnpm-lock.yaml), Python requirements.txt/poetry.lock/Pipfile.lock parsing,
# Ruby/RubyGems lockfile parsing (Gemfile.lock), Java build-manifest parsing
# (pom.xml, build.gradle), PHP/Composer lockfile parsing (composer.lock,
# cross-referenced against composer.json), Go module-file parsing
# (go.mod/go.sum), and the data/advisories.db exact-match lookup shared
# across ecosystems (docs/DESIGN.md §13 step 4, docs/FOUNDATION.md
# tension 25).
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
# ...the Python ticket's own acceptance criteria (requirements.txt,
# poetry.lock, Pipfile.lock - see that section's own header comment below for
# the detail) - and the Ruby ticket's own acceptance criteria:
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
# ...the Java ticket's own acceptance criteria:
#   - a fixture pom.xml and a fixture build.gradle, each with a
#     known-vulnerable pinned dependency, both report it under
#     SCA-JAVA-VULNERABLE_DEP-01
#   - pom.xml's top-level <dependencies> only - dependencyManagement,
#     profiles, and plugin dependencies are excluded, per that parser's own
#     header
#   - both build.gradle declaration shapes this ticket supports
#     (`implementation "g:a:v"` and the group:/name:/version: map form) are
#     parsed; a version-catalog accessor or a computed/interpolated value is
#     a stated, documented gap, not a silent miss
#   - a Maven coordinate known to the db but at an unmatched exact version
#     contributes to the SHARED SCA-COV-UNKNOWN_VERSION-01 roll-up
#
# ...the PHP/Composer ticket's own acceptance criteria:
#   - a known-vulnerable pinned package from a fixture composer.lock is
#     reported via `scan_dispatch sca`, tagged SCA-PHP-VULNERABLE_DEP-01
#   - a mixed-case package name is normalised to lowercase before lookup
#   - direct-vs-transitive is reported per package when a fixture
#     composer.json is present, and "unknown" when it is absent
#   - a pinned package with no fixed version in advisories.db is accept-risk,
#     not dropped
#   - an unresolved/unknown-version composer package contributes to the
#     SAME shared SCA-COV-UNKNOWN_VERSION-01 roll-up npm contributes to -
#     never a second, composer-only roll-up finding in the same run
#
# ...and the Go ticket's own acceptance criteria, in its own section below
# ("-- Go: ... --" onward):
#   - a fixture Go project reports SCA-GO-VULNERABLE_DEP-01 for a
#     known-vulnerable pinned dependency declared in go.mod/go.sum
#   - a /vN module suffix is RETAINED and a +incompatible version suffix is
#     STRIPPED before lookup, pinned against the naive (unstripped) reading
#   - direct vs transitive is read from go.mod's own `// indirect` marker
#     when go.mod is present, and honestly reported "unknown" when only
#     go.sum is available
#   - a dependency with no fixed version is flagged accept-risk
#   Go's roll-up is deliberately its OWN SCA-COV-UNKNOWN_VERSION-01 finding
#   rather than the shared one npm/Ruby/PHP feed - see sca_go_scan_tree's own
#   header for that stated limitation, which is why the Go section asserts
#   exactly one roll-up per Go-only scan rather than a merged breakdown.
#
# None of this depends on a real, production-scale data/advisories.db:
# tools/vendor-engines.sh (the only script that populates one) is never run
# in this repo/CI (AGENTS.md), so every case here points
# SCOURSH_SCA_ADVISORIES_DB at the small, committed
# tests/fixtures/sca/advisories.db instead (now carrying npm, pypi,
# RubyGems, composer, maven, and Go fixture rows).
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sca/engine.sh
source "$ROOT/modules/sca/engine.sh"
# Sourced explicitly too, even though engine.sh already pulls this in
# (guarded, see both files' own headers) - self-documenting about which
# ecosystems this suite covers, same convention modules/sca/run.sh uses.
# shellcheck source=modules/sca/php_engine.sh
source "$ROOT/modules/sca/php_engine.sh"
# go_engine.sh is a separate file, not part of engine.sh - it must be sourced
# for the Go section below to see sca_go_normalize_module/_sca_go_parse_mod/
# sca_go_scan_tree at all.
# shellcheck source=modules/sca/go_engine.sh
source "$ROOT/modules/sca/go_engine.sh"
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
printf -- '\n-- data/advisories.db absent: sca_scan_tree degrades, never crashes --\n'
# =============================================================================
# This section used to assert that sca_scan_tree ITSELF recorded the
# `no_advisories_db_on_disk` reason.  It no longer does, deliberately: that
# announcement is the module's (sca_report_no_advisories_db, called once by
# modules/sca/run.sh and asserted in the "no advisory database" section near
# the end of this file), because a per-walk announcement can be made twice
# and still account for only half the ecosystems - which is exactly what
# shipped.  What this walk still owes its caller is what is asserted here: it
# degrades cleanly and emits nothing of its own.
RUNDIR2=$W/run-no-db
rm -rf "$RUNDIR2"
run_init "$RUNDIR2"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/npm-lock")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/npm-lock")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$W/does-not-exist.db

t_case 'sca_scan_tree with no readable db returns cleanly and does not die'
assert_status 0 'a missing advisories.db is a declared reduction, not a fatal error' \
  sca_scan_tree "$FIXTURES/npm-lock"
sca_scan_tree "$FIXTURES/npm-lock" >/dev/null 2>&1 || true
assert_eq '' "$(cat "$RUNDIR2/meta/coverage_reduction" 2>/dev/null)" \
  'and records no reason of its own - fails under the shipped reading, where this walk announced one and sca_go_scan_tree announced a second, so every sca run carried the same fact twice'
assert_file_absent "$RUNDIR2/findings.jsonl" \
  'and emits no finding, since it examined nothing'

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
printf -- '\n-- name normalisation (docs/FOUNDATION.md tension 25): Maven is groupId:artifactId --\n'
# =============================================================================
t_case 'Maven normalisation joins groupId and artifactId with a single colon'
assert_eq 'org.apache.commons:commons-collections4' \
  "$(sca_maven_normalize_name org.apache.commons commons-collections4)" \
  'groupId and artifactId are joined verbatim, no case-folding (Maven coordinates are case-sensitive)'
assert_eq 'com.fixture:no-fix-lib' "$(sca_maven_normalize_name com.fixture no-fix-lib)" \
  'a second, differently-shaped groupId/artifactId pair normalises the same way - proves the join is not a one-off constant'

# =============================================================================
printf -- '\n-- pom.xml: top-level <dependencies> only, exclusions/dependencyManagement excluded --\n'
# =============================================================================
POM_OUT=$(_sca_parse_pom_xml "$FIXTURES/maven/pom.xml")

t_case 'pom.xml: a top-level dependency is captured, name normalised to groupId:artifactId'
assert_contains "$POM_OUT" $'org.apache.commons:commons-collections4\x1f4.0\x1funknown' \
  'commons-collections4@4.0 is captured from the top-level <dependencies> block'

t_case 'pom.xml: dependency_type is the literal "unknown", never guessed as direct/transitive'
assert_not_contains "$POM_OUT" $'\x1fdirect' 'no pom.xml row is ever marked "direct"'
assert_not_contains "$POM_OUT" $'\x1ftransitive' 'no pom.xml row is ever marked "transitive"'

t_case 'pom.xml: <dependencyManagement>'"'"'s own nested <dependencies> is NOT a real dependency'
assert_not_contains "$POM_OUT" 'be-captured-managed-only' \
  'dependencyManagement only pins a version for a child that references it - it never adds a dependency on its own, and its <dependencies> sits one level deeper than the eligible top-level one'

t_case 'pom.xml: an <exclusion>'"'"'s groupId/artifactId is never mistaken for its own <dependency>'"'"'s'
assert_not_contains "$POM_OUT" 'be-captured-exclusion' \
  'exclusions sit two levels deeper than a dependency'"'"'s own immediate children'

t_case 'pom.xml: an unresolved Maven property version is passed through literally, not guessed'
assert_contains "$POM_OUT" $'org.fixture:property-version-lib\x1f${property.version}\x1funknown' \
  'the raw, un-substituted "${property.version}" string is what a lookup would use - a documented, stated gap, not a crash'

# =============================================================================
printf -- '\n-- build.gradle: both supported declaration shapes, catalog/computed versions are a documented gap --\n'
# =============================================================================
GRADLE_OUT=$(_sca_parse_build_gradle "$FIXTURES/gradle/build.gradle")

t_case 'build.gradle: shape 1 - implementation "group:artifact:version"'
assert_contains "$GRADLE_OUT" $'com.fasterxml.jackson.core:jackson-databind\x1f2.9.8\x1fdirect' \
  'the quoted-string shape is parsed and normalised to groupId:artifactId'

t_case 'build.gradle: shape 2 - implementation group: '"'"'g'"'"', name: '"'"'a'"'"', version: '"'"'v'"'"''
assert_contains "$GRADLE_OUT" $'org.yaml:snakeyaml\x1f1.26\x1fdirect' \
  'the map-argument shape is parsed and normalised to groupId:artifactId'

t_case 'build.gradle: every captured row is "direct" - build.gradle carries no transitive graph at all'
assert_not_contains "$GRADLE_OUT" $'\x1funknown' 'gradle rows are never "unknown"'
assert_not_contains "$GRADLE_OUT" $'\x1ftransitive' 'gradle rows are never "transitive"'

t_case 'build.gradle: a version-catalog accessor is a documented gap, silently skipped'
assert_not_contains "$GRADLE_OUT" 'someCatalogEntry' \
  'implementation(libs.someCatalogEntry) matches neither supported shape and is not mis-parsed as a dependency'

t_case 'build.gradle: a computed/interpolated version is a documented gap, silently skipped'
assert_not_contains "$GRADLE_OUT" 'another-lib' \
  'implementation "org.yaml:another-lib:$snakeVersion" is detected as $-bearing and discarded rather than treated as a literal version'

# =============================================================================
printf -- '\n-- sca_scan_java_tree: pom.xml fixture against the fixture db --\n'
# =============================================================================
RUNDIR_MVN=$W/run-maven
rm -rf "$RUNDIR_MVN"
run_init "$RUNDIR_MVN"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/maven")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/maven")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_java_tree "$FIXTURES/maven"
findings_merge "$RUNDIR_MVN"
MVN_FINDINGS=$(_sca_findings "$RUNDIR_MVN")

t_case 'AC: a fixture pom.xml with a known-vulnerable pinned dependency returns SCA-JAVA-VULNERABLE_DEP-01'
assert_contains "$MVN_FINDINGS" 'SCA-JAVA-VULNERABLE_DEP-01' \
  'at least one SCA-JAVA-VULNERABLE_DEP-01 finding was emitted for the fixture pom.xml'
assert_contains "$MVN_FINDINGS" 'SCA-FIXTURE-ADVISORY-006' \
  'the finding references the fixture advisories table'"'"'s own advisory id (commons-collections4@4.0)'

t_case 'AC: a pom.xml dependency with no fixed version is flagged accept-risk, not silently dropped'
assert_contains "$MVN_FINDINGS" 'accept_risk_candidate: true' \
  'com.fixture:no-fix-lib@2.0.0 (SCA-FIXTURE-ADVISORY-007, empty fixed_versions) is flagged accept_risk_candidate: true'
assert_contains "$MVN_FINDINGS" 'accept_risk_candidate: false' \
  'commons-collections4@4.0 (a fixed version IS published) is not flagged accept-risk'

t_case 'AC: pom.xml dependencies are marked "unknown", never guessed as direct/transitive'
assert_contains "$MVN_FINDINGS" 'dependency_type: unknown' \
  'every pom.xml-derived finding carries dependency_type: unknown'
assert_not_contains "$MVN_FINDINGS" 'dependency_type: direct' 'no pom.xml finding is ever marked direct'
assert_not_contains "$MVN_FINDINGS" 'dependency_type: transitive' 'no pom.xml finding is ever marked transitive'

t_case 'AC: an unresolvable pinned version contributes to the shared SCA-COV-UNKNOWN_VERSION-01 roll-up'
assert_contains "$MVN_FINDINGS" 'SCA-COV-UNKNOWN_VERSION-01' \
  'org.fixture:unknown-version-lib@5.5.5 (package known at a different version, 1.0.0) triggers the roll-up'
assert_contains "$MVN_FINDINGS" 'by ecosystem: maven: 1' \
  'the roll-up breaks down by ecosystem - maven: 1 for this run'

t_case 'a package the fixture db never mentions at all does not appear in the roll-up or as a finding'
assert_not_contains "$MVN_FINDINGS" 'property-version-lib' \
  'org.fixture:property-version-lib is not in the fixture db at any version - sca_package_known is false, so it contributes nothing (not even to the roll-up)'
assert_not_contains "$MVN_FINDINGS" 'clean-lib' \
  'com.fixture:clean-lib is not in the fixture db at any version'

t_case 'run.json: checks_run records SCA-JAVA-VULNERABLE_DEP-01 and the roll-up check'
assert_contains "$(cat "$RUNDIR_MVN/meta/checks_run" 2>/dev/null)" 'SCA-JAVA-VULNERABLE_DEP-01' \
  'SCA-JAVA-VULNERABLE_DEP-01 is recorded as run'
assert_contains "$(cat "$RUNDIR_MVN/meta/checks_run" 2>/dev/null)" 'SCA-COV-UNKNOWN_VERSION-01' \
  'SCA-COV-UNKNOWN_VERSION-01 is recorded as run (the roll-up fired this run)'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- sca_scan_java_tree: build.gradle fixture, both declaration shapes --\n'
# =============================================================================
RUNDIR_GRADLE=$W/run-gradle
rm -rf "$RUNDIR_GRADLE"
run_init "$RUNDIR_GRADLE"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/gradle")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/gradle")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_java_tree "$FIXTURES/gradle"
findings_merge "$RUNDIR_GRADLE"
GRADLE_FINDINGS=$(_sca_findings "$RUNDIR_GRADLE")

t_case 'AC: a fixture build.gradle with both supported shapes returns matching findings'
assert_contains "$GRADLE_FINDINGS" 'SCA-FIXTURE-ADVISORY-009' \
  'shape 1 (implementation "group:artifact:version") matches jackson-databind@2.9.8'
assert_contains "$GRADLE_FINDINGS" 'SCA-FIXTURE-ADVISORY-010' \
  'shape 2 (implementation group:/name:/version:) matches org.yaml:snakeyaml@1.26'

t_case 'AC: a build.gradle dependency with no fixed version is flagged accept-risk, not silently dropped'
assert_contains "$GRADLE_FINDINGS" 'accept_risk_candidate: true' \
  'com.fixture:no-fix-gradle-lib@3.0.0 has no fixed version published'
assert_contains "$GRADLE_FINDINGS" 'accept_risk_candidate: false' \
  'jackson-databind@2.9.8 (a fixed version IS published) is not flagged accept-risk'

t_case 'build.gradle findings are always "direct" - build.gradle carries no transitive graph'
assert_contains "$GRADLE_FINDINGS" 'dependency_type: direct' 'every build.gradle finding is direct'
assert_not_contains "$GRADLE_FINDINGS" 'dependency_type: unknown' 'never "unknown" for build.gradle'
assert_not_contains "$GRADLE_FINDINGS" 'dependency_type: transitive' 'never "transitive" for build.gradle'

t_case 'a build.gradle dependency absent from the fixture db is silently absent, not a finding'
assert_not_contains "$GRADLE_FINDINGS" 'clean-gradle-lib' 'com.fixture:clean-gradle-lib is not in the fixture db'

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

# =============================================================================
printf -- '\n-- end-to-end: a real scan.sh subprocess against the pom.xml and build.gradle fixtures --\n'
# =============================================================================
t_case 'scan.sh sca --path against the pom.xml fixture exits 0 and reports via SCA-JAVA-VULNERABLE_DEP-01'
E2E_MVN_RUNDIR=$W/run-e2e-maven
rm -rf "$E2E_MVN_RUNDIR"
assert_status 0 'a real subprocess against the maven fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/maven" --out "$E2E_MVN_RUNDIR"
E2E_MVN_RUNJSON=$(cat "$E2E_MVN_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_MVN_RUNJSON" '"SCA-JAVA-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the check actually executed through the real scan.sh entry point (scan_dispatch sca), not just when the module is sourced standalone'
assert_contains "$E2E_MVN_RUNJSON" '"sca":3' \
  'run.json by_module counts 3 live findings for sca - 2 vulnerable pom.xml dependencies plus the one roll-up'

t_case 'scan.sh sca --path against the build.gradle fixture exits 0 and reports via SCA-JAVA-VULNERABLE_DEP-01'
E2E_GRADLE_RUNDIR=$W/run-e2e-gradle
rm -rf "$E2E_GRADLE_RUNDIR"
assert_status 0 'a real subprocess against the gradle fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/gradle" --out "$E2E_GRADLE_RUNDIR"
E2E_GRADLE_RUNJSON=$(cat "$E2E_GRADLE_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_GRADLE_RUNJSON" '"SCA-JAVA-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the check actually executed through the real scan.sh entry point'
assert_contains "$E2E_GRADLE_RUNJSON" '"sca":3' \
  'run.json by_module counts 3 live findings for sca - both supported shapes'"'"' vulnerable dependencies plus no-fix-gradle-lib'

# =============================================================================
printf -- '\n-- name normalisation (docs/FOUNDATION.md tension 25): Composer is lowercase --\n'
# =============================================================================
t_case 'composer normalisation lowercases, unlike npm'"'"'s identity function'
assert_eq 'acme/widget' "$(sca_composer_normalize_name 'acme/widget')" 'an already-lowercase name is unchanged'
assert_eq 'acme/mixedcase' "$(sca_composer_normalize_name 'Acme/MixedCase')" \
  'AC: a mixed-case package name normalises to lowercase - fails if normalisation were the npm-style identity function instead'

# =============================================================================
printf -- '\n-- composer.json: require/require-dev cross-reference --\n'
# =============================================================================
t_case 'sca_composer_direct_deps reads the sibling composer.json'"'"'s require AND require-dev'
COMPOSER_DIRECT=$(sca_composer_direct_deps "$FIXTURES/composer")
assert_contains "$COMPOSER_DIRECT" 'acme/widget' 'acme/widget is declared in composer.json'"'"'s require'
assert_contains "$COMPOSER_DIRECT" 'acme/mixedcase' 'the require key is already-lowercase acme/mixedcase'
assert_contains "$COMPOSER_DIRECT" 'acme/dev-tool' 'acme/dev-tool is declared in composer.json'"'"'s require-dev'
assert_contains "$COMPOSER_DIRECT" 'php' 'a platform entry (php) is read too - it simply never matches anything in composer.lock'"'"'s own packages array'

t_case 'sca_composer_direct_deps prints nothing (not an error) when composer.json is absent'
assert_eq '' "$(sca_composer_direct_deps "$FIXTURES/composer-no-manifest")" \
  'no composer.json sibling in the no-manifest fixture directory'

# =============================================================================
printf -- '\n-- composer.lock: name/version/direct-transitive-unknown --\n'
# =============================================================================
COMPOSER_OUT=$(sca_parse_composer_lock "$FIXTURES/composer/composer.lock")
t_case 'composer.lock: a package required directly in composer.json is direct'
assert_contains "$COMPOSER_OUT" $'acme/widget\x1f1.2.3\x1fdirect' \
  'acme/widget is in composer.json'"'"'s require'
assert_contains "$COMPOSER_OUT" $'acme/dev-tool\x1f2.5.0\x1fdirect' \
  'acme/dev-tool sits in packages-dev and is in composer.json'"'"'s require-dev - direct, not "unknown" or mis-tagged from the dev split'

t_case 'composer.lock: a package present but never required directly is transitive'
assert_contains "$COMPOSER_OUT" $'acme/widget-support\x1f0.9.0\x1ftransitive' \
  'acme/widget-support is in the packages array but not in composer.json at all'
assert_contains "$COMPOSER_OUT" $'acme/legacy-lib\x1f0.1.0\x1ftransitive' \
  'acme/legacy-lib is resolved-in but not directly required'

t_case 'AC: direct/transitive classification is normalisation-aware even though the emitted name stays raw/verbatim'
assert_contains "$COMPOSER_OUT" $'Acme/MixedCase\x1f3.0.0\x1fdirect' \
  'composer.json requires the lowercase "acme/mixedcase"; composer.lock spells the same package "Acme/MixedCase" - the RAW (unnormalised) name is preserved in the row, but classified direct because the comparison itself normalises both sides first'

t_case 'AC: with no sibling composer.json, every package is honestly "unknown", never guessed'
COMPOSER_UNKNOWN_OUT=$(sca_parse_composer_lock "$FIXTURES/composer-no-manifest/composer.lock")
assert_contains "$COMPOSER_UNKNOWN_OUT" $'acme/widget\x1f1.2.3\x1funknown' \
  'acme/widget would be direct under the composer/ fixture (which HAS a composer.json) - here, with no composer.json at all, it must be "unknown", not silently defaulted to direct or transitive'
assert_not_contains "$COMPOSER_UNKNOWN_OUT" 'direct' \
  'no row in the no-manifest fixture output is ever tagged direct'
assert_not_contains "$COMPOSER_UNKNOWN_OUT" 'transitive' \
  'no row in the no-manifest fixture output is ever tagged transitive either - "unknown" is the ONLY status possible with no composer.json'

# =============================================================================
printf -- '\n-- sca_scan_tree: full composer.lock fixture against the fixture db --\n'
# =============================================================================
RUNDIR3=$W/run-composer
rm -rf "$RUNDIR3"
run_init "$RUNDIR3"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/composer")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/composer")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/composer"
findings_merge "$RUNDIR3"
COMPOSER_FINDINGS=$(_sca_findings "$RUNDIR3")

t_case 'AC: a known-vulnerable pinned package from composer.lock is reported, tagged SCA-PHP-VULNERABLE_DEP-01'
assert_contains "$COMPOSER_FINDINGS" 'SCA-PHP-VULNERABLE_DEP-01' \
  'at least one SCA-PHP-VULNERABLE_DEP-01 finding was emitted for the fixture repo - fails if the check id were left as the shared npm one'
assert_contains "$COMPOSER_FINDINGS" 'acme/widget@1.2.3 is vulnerable (SCA-FIXTURE-ADVISORY-101)' \
  'the pinned acme/widget@1.2.3 row matches the fixture db exactly'

t_case 'AC: the mixed-case package is matched too - proves normalisation happens before the lookup, not just before classification'
assert_contains "$COMPOSER_FINDINGS" 'acme/mixedcase@3.0.0 is vulnerable (SCA-FIXTURE-ADVISORY-102)' \
  'db row is stored lowercase (acme/mixedcase); composer.lock spelled it Acme/MixedCase - a miss here means normalisation was skipped before sca_lookup_exact'

t_case 'AC: direct vs transitive is distinguished in the composer finding evidence too'
assert_contains "$COMPOSER_FINDINGS" 'dependency_type: direct' 'acme/widget and acme/mixedcase are both direct'
assert_contains "$COMPOSER_FINDINGS" 'dependency_type: transitive' 'acme/legacy-lib is transitive'

t_case 'AC: a pinned package with no fixed version in advisories.db is accept-risk, not dropped'
assert_contains "$COMPOSER_FINDINGS" 'acme/legacy-lib@0.1.0 is vulnerable (SCA-FIXTURE-ADVISORY-103)' \
  'the no-fixed-version package still produced a finding - "dropping it" would mean this line is simply absent'
assert_contains "$COMPOSER_FINDINGS" 'accept_risk_candidate: true' \
  'acme/legacy-lib (empty fixed_versions in the fixture db) is flagged accept_risk_candidate: true'

t_case 'AC: an unresolved/unknown-version composer package contributes to the SHARED roll-up, not a second one'
_COMPOSER_ROLLUP_COUNT=$(printf '%s\n' "$COMPOSER_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$_COMPOSER_ROLLUP_COUNT" \
  'exactly one roll-up finding for this run - not one for npm-shaped code and a second, composer-only one'
assert_contains "$COMPOSER_FINDINGS" 'by ecosystem: composer: 1' \
  'acme/unknown-version-pkg@9.9.9 (package known at some other version, exact pin unmatched) is the sole contributor here'

t_case 'a composer package with NO advisories.db rows at all does not appear in the roll-up or as a finding'
assert_not_contains "$COMPOSER_FINDINGS" 'untracked-pkg' \
  'acme/untracked-pkg has no db rows whatsoever - absence is silent, not an unknown-version count'
assert_not_contains "$COMPOSER_FINDINGS" 'widget-support' \
  'acme/widget-support also has no db rows - transitive-but-clean, no finding of any kind'

t_case 'run.json: checks_run records SCA-PHP-VULNERABLE_DEP-01'
assert_contains "$(cat "$RUNDIR3/meta/checks_run" 2>/dev/null)" 'SCA-PHP-VULNERABLE_DEP-01' \
  'SCA-PHP-VULNERABLE_DEP-01 is recorded as run for a repo containing a composer.lock'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- sca_scan_tree: composer.lock with NO sibling composer.json --\n'
# =============================================================================
RUNDIR4=$W/run-composer-no-manifest
rm -rf "$RUNDIR4"
run_init "$RUNDIR4"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/composer-no-manifest")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/composer-no-manifest")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/composer-no-manifest"
findings_merge "$RUNDIR4"
NO_MANIFEST_FINDINGS=$(_sca_findings "$RUNDIR4")

t_case 'AC: direct/transitive status is honestly "unknown" end-to-end when composer.json is absent'
assert_contains "$NO_MANIFEST_FINDINGS" 'SCA-PHP-VULNERABLE_DEP-01' \
  'the vulnerable pinned package is still reported - "unknown" status does not suppress the finding'
assert_contains "$NO_MANIFEST_FINDINGS" 'dependency_type: unknown' \
  'with no composer.json sibling, dependency_type is unknown, not defaulted to direct or transitive'
assert_not_contains "$NO_MANIFEST_FINDINGS" 'dependency_type: direct' \
  'never guessed as direct with no composer.json present'
assert_not_contains "$NO_MANIFEST_FINDINGS" 'dependency_type: transitive' \
  'never guessed as transitive with no composer.json present either'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- sca_scan_tree: npm AND composer in the SAME repo - one shared roll-up, not two --\n'
# =============================================================================
# tests/fixtures/sca/mixed-ecosystems-php/ is a SEPARATE fixture directory
# from tests/fixtures/sca/mixed-ecosystems/ (the npm+Ruby pairing tested
# above): both a package-lock.json and a composer.lock landing in the SAME
# mixed-ecosystems/ directory as the npm+Ruby case's own Gemfile.lock would
# make that earlier case's assertions (exactly 2 pinned/npm:1/RubyGems:1)
# false the moment a third ecosystem's unknown-version count joined the same
# roll-up - so this ticket's own npm+composer pairing gets its own directory
# instead of silently widening the npm+Ruby fixture's scope.
RUNDIR5=$W/run-mixed-ecosystems-php
rm -rf "$RUNDIR5"
run_init "$RUNDIR5"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/mixed-ecosystems-php")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/mixed-ecosystems-php")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_scan_tree "$FIXTURES/mixed-ecosystems-php"
findings_merge "$RUNDIR5"
MIXED_FINDINGS=$(_sca_findings "$RUNDIR5")

t_case 'AC: an unknown-version case from EACH ecosystem in one run still produces exactly one roll-up finding'
_MIXED_ROLLUP_COUNT=$(printf '%s\n' "$MIXED_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$_MIXED_ROLLUP_COUNT" \
  'the fixture has an npm lockfile (lodash@4.17.99, unmatched) AND a composer.lock (acme/unknown-version-pkg@9.9.9, unmatched) - this must still be ONE finding, not one per ecosystem, which is exactly the failure mode a naive per-ecosystem sca_scan_tree split would reintroduce'
assert_contains "$MIXED_FINDINGS" 'by ecosystem: composer: 1, npm: 1' \
  'the single roll-up'"'"'s evidence breaks the count down by ecosystem, LC_ALL=C sorted (composer before npm) - proves both ecosystems fed the SAME finding rather than each producing its own'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- end-to-end: a real scan.sh subprocess against a composer.lock fixture --\n'
# =============================================================================
t_case 'scan.sh sca --path against the composer fixture exits 0 and reports the vulnerable dependency'
E2E_COMPOSER_RUNDIR=$W/run-e2e-composer
rm -rf "$E2E_COMPOSER_RUNDIR"
assert_status 0 'a real subprocess against the composer fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/composer" --out "$E2E_COMPOSER_RUNDIR"
E2E_COMPOSER_RUNJSON=$(cat "$E2E_COMPOSER_RUNDIR/run.json" 2>/dev/null)
assert_contains "$E2E_COMPOSER_RUNJSON" '"SCA-PHP-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows SCA-PHP-VULNERABLE_DEP-01 actually executed through the real scan.sh entry point (scan_dispatch sca), not just when the module is sourced standalone'
assert_contains "$E2E_COMPOSER_RUNJSON" '"sca":4' \
  'run.json by_module counts 4 live findings for sca - 3 vulnerable composer packages (acme/widget, acme/mixedcase, acme/legacy-lib) plus the one roll-up'

# =============================================================================
printf -- '\n-- Go: name normalisation (docs/FOUNDATION.md tension 25'"'"'s frozen Go row) --\n'
# =============================================================================
t_case 'Go module normalisation RETAINS a /vN major-version suffix'
assert_eq 'github.com/vulnerable/incompatible/v3' \
  "$(sca_go_normalize_module 'github.com/vulnerable/incompatible/v3')" \
  'the /vN suffix must be retained, not stripped - a module path with no /vN passes through unchanged either way, so this only proves the RETAIN half'
assert_eq 'github.com/pkg/errors' "$(sca_go_normalize_module 'github.com/pkg/errors')" \
  'a module path with no /vN suffix is unaffected'

t_case 'Go version normalisation STRIPS a +incompatible suffix'
assert_eq 'v3.2.1' "$(sca_go_normalize_version 'v3.2.1+incompatible')" \
  'the +incompatible suffix must be stripped before lookup'
assert_eq 'v0.9.1' "$(sca_go_normalize_version 'v0.9.1')" \
  'a version with no +incompatible suffix passes through unchanged'

t_case 'AC: normalisation is required, not cosmetic - the naive (unstripped) reading misses the exact advisory row'
assert_status 1 'looking up the RAW pinned version with +incompatible still attached misses entirely' \
  sca_lookup_exact Go 'github.com/vulnerable/incompatible/v3' 'v3.2.1+incompatible' "$DB"
assert_status 0 'the normalized version (the same module@version, +incompatible stripped) matches the same db row' \
  sca_lookup_exact Go 'github.com/vulnerable/incompatible/v3' 'v3.2.1' "$DB"

t_case 'AC: the OTHER naive misreading - stripping /vN instead of retaining it - also misses'
assert_status 1 'looking up the module path WITHOUT its /v3 suffix misses too - proves /vN must be retained' \
  sca_lookup_exact Go 'github.com/vulnerable/incompatible' 'v3.2.1' "$DB"

# =============================================================================
printf -- '\n-- Go: go.mod parsing - require lines, block form, and // indirect --\n'
# =============================================================================
GOMOD_OUT=$(_sca_go_parse_mod "$FIXTURES/go-mod/go.mod")
t_case 'go.mod: a bare require line (no "// indirect") is direct'
assert_contains "$GOMOD_OUT" $'github.com/pkg/errors\x1fv0.9.1\x1fdirect' \
  'github.com/pkg/errors carries no // indirect comment - direct'
assert_contains "$GOMOD_OUT" $'github.com/no-fix/pkg\x1fv1.0.0\x1fdirect' \
  'github.com/no-fix/pkg carries no // indirect comment - direct'
assert_contains "$GOMOD_OUT" $'github.com/unknown-version/pkg\x1fv1.0.0\x1fdirect' \
  'github.com/unknown-version/pkg carries no // indirect comment - direct'

t_case 'go.mod: a "// indirect" require line is transitive, and its RAW (unnormalised) version is what the parser prints'
assert_contains "$GOMOD_OUT" $'github.com/vulnerable/incompatible/v3\x1fv3.2.1+incompatible\x1ftransitive' \
  'the parser prints the pinned version exactly as go.mod wrote it (+incompatible still attached) - normalisation is the caller'"'"'s job (sca_go_scan_tree), not the parser'"'"'s, so this fails if the parser normalised prematurely'

# =============================================================================
printf -- '\n-- Go: go.sum parsing - no direct/transitive signal, module-zip/go.mod dedup --\n'
# =============================================================================
GOSUM_OUT=$(_sca_go_parse_sum "$FIXTURES/go-sum-only/go.sum")
t_case 'go.sum: every entry is reported "unknown" - go.sum alone carries no direct/transitive signal'
assert_contains "$GOSUM_OUT" $'github.com/pkg/errors\x1fv0.9.1\x1funknown' 'pkg/errors is unknown from go.sum alone'
assert_contains "$GOSUM_OUT" $'github.com/only-in-sum/pkg\x1fv2.0.0\x1funknown' 'only-in-sum/pkg is unknown from go.sum alone'

t_case 'go.sum: the module-zip hash line and its own "/go.mod" hash line dedupe to ONE row'
_GOSUM_ERRORS_COUNT=$(printf '%s\n' "$GOSUM_OUT" | grep -c '^github.com/pkg/errors' || true)
assert_eq 1 "$_GOSUM_ERRORS_COUNT" \
  'pkg/errors appears TWICE in go.sum (the module hash line and its "v0.9.1/go.mod" sibling) but must dedupe to one parsed row - fails if the "/go.mod" suffix were left attached to the version, which would also silently corrupt the lookup version'

# =============================================================================
printf -- '\n-- Go: sca_go_scan_tree with go.mod present - direct/transitive, accept-risk, go.mod precedence --\n'
# =============================================================================
GO_RUNDIR=$W/run-go-mod
rm -rf "$GO_RUNDIR"
run_init "$GO_RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/go-mod")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/go-mod")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_go_scan_tree "$FIXTURES/go-mod"
findings_merge "$GO_RUNDIR"
GO_FINDINGS=$(_sca_findings "$GO_RUNDIR")

t_case 'AC: scan_dispatch sca reports SCA-GO-VULNERABLE_DEP-01 for a known-vulnerable pinned Go dependency'
assert_contains "$GO_FINDINGS" 'SCA-GO-VULNERABLE_DEP-01' \
  'at least one SCA-GO-VULNERABLE_DEP-01 finding was emitted for the go-mod fixture'

t_case 'AC: direct vs transitive is read from go.mod'"'"'s own "// indirect" marker'
assert_contains "$GO_FINDINGS" 'dependency_type: direct' 'a direct dependency finding carries dependency_type: direct'
assert_contains "$GO_FINDINGS" 'dependency_type: transitive' \
  'the "// indirect" dependency (github.com/vulnerable/incompatible/v3) carries dependency_type: transitive'

t_case 'AC: normalisation is visible in the evidence, not a silent rewrite of what was pinned'
assert_contains "$GO_FINDINGS" 'pinned_version: v3.2.1+incompatible (normalized to v3.2.1 for lookup' \
  'the finding for the /vN + +incompatible dependency states both the raw pinned version and the normalized lookup version'

t_case 'AC: a no-fixed-version advisory is flagged as an accept-risk candidate'
assert_contains "$GO_FINDINGS" 'accept_risk_candidate: true' \
  'github.com/no-fix/pkg@v1.0.0 (SCA-FIXTURE-ADVISORY-008, empty fixed_versions) is flagged accept_risk_candidate: true'
assert_contains "$GO_FINDINGS" 'fixed_versions: none published' \
  'the empty fixed_versions db field renders as "none published"'
assert_contains "$GO_FINDINGS" 'accept_risk_candidate: false' \
  'a dependency WITH a fixed version is NOT flagged as accept-risk - proves the flag is not stuck on one constant value'

t_case 'go.mod precedence: go.sum-only entries are NOT scanned when go.mod is present in the same directory'
assert_not_contains "$GO_FINDINGS" 'only-in-sum' \
  'github.com/only-in-sum/pkg@v9.9.9 exists in the go-mod fixture'"'"'s own go.sum but NOT in its go.mod - go.mod, not go.sum, is authoritative when both are present, so this must be absent entirely'

t_case 'AC: a pinned version the db does not know about at all rolls up to SCA-COV-UNKNOWN_VERSION-01, not silently dropped or per-package noise'
_GO_UNKNOWN_COUNT=$(printf '%s\n' "$GO_FINDINGS" | grep -c '^SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$_GO_UNKNOWN_COUNT" \
  'exactly one roll-up finding - github.com/unknown-version/pkg@v1.0.0 is a known package (db has it at v9.9.9) pinned at an unmatched exact version'
assert_contains "$GO_FINDINGS" 'SCA: 1 pinned dependency version' \
  'the roll-up title states the correct count (1: only unknown-version/pkg)'

t_case 'run.json: checks_run records SCA-GO-VULNERABLE_DEP-01 as run'
assert_contains "$(cat "$GO_RUNDIR/meta/checks_run" 2>/dev/null)" 'SCA-GO-VULNERABLE_DEP-01' \
  'SCA-GO-VULNERABLE_DEP-01 is recorded as run'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- Go: sca_go_scan_tree with ONLY go.sum - honest "unknown", never guessed --\n'
# =============================================================================
GO_SUM_RUNDIR=$W/run-go-sum-only
rm -rf "$GO_SUM_RUNDIR"
run_init "$GO_SUM_RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/go-sum-only")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/go-sum-only")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$DB

sca_go_scan_tree "$FIXTURES/go-sum-only"
findings_merge "$GO_SUM_RUNDIR"
GO_SUM_FINDINGS=$(_sca_findings "$GO_SUM_RUNDIR")

t_case 'AC: with no go.mod, a vulnerable pinned dependency from go.sum alone is still reported'
assert_contains "$GO_SUM_FINDINGS" 'SCA-GO-VULNERABLE_DEP-01' \
  'github.com/pkg/errors@v0.9.1 is found via go.sum alone'

t_case 'AC: with no go.mod present, dependency_type is honestly "unknown", never guessed direct or transitive'
assert_contains "$GO_SUM_FINDINGS" 'dependency_type: unknown' \
  'go.sum alone carries no direct/transitive signal, so the finding must say unknown rather than pick one'
assert_not_contains "$GO_SUM_FINDINGS" 'dependency_type: direct' \
  'no go.mod exists in this fixture directory - nothing here may be labeled direct'
assert_not_contains "$GO_SUM_FINDINGS" 'dependency_type: transitive' \
  'no go.mod exists in this fixture directory - nothing here may be labeled transitive'

t_case 'a package with NO advisories.db rows at all does not appear in the roll-up or as a finding'
assert_not_contains "$GO_SUM_FINDINGS" 'only-in-sum' \
  'github.com/only-in-sum/pkg has no db rows whatsoever (sca_package_known is false for it) - absence is silent, not an unknown-version count'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- Go: data/advisories.db absent - an honest coverage_reduction, never a crash --\n'
# =============================================================================
GO_RUNDIR3=$W/run-go-no-db
rm -rf "$GO_RUNDIR3"
run_init "$GO_RUNDIR3"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/go-mod")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/go-mod")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$W/does-not-exist-go.db

t_case 'sca_go_scan_tree with no readable db returns cleanly and does not die'
assert_status 0 'a missing advisories.db is a declared reduction, not a fatal error' \
  sca_go_scan_tree "$FIXTURES/go-mod"
sca_go_scan_tree "$FIXTURES/go-mod" >/dev/null 2>&1 || true
# Same change of ownership as the sca_scan_tree section above: this walk used
# to record `no_advisories_db_on_disk ecosystem=Go`, which - together with
# sca_scan_tree's own - is why a plain `scan.sh sca` announced the fact twice
# and still left Python and Java unaccounted for.
assert_eq '' "$(cat "$GO_RUNDIR3/meta/coverage_reduction" 2>/dev/null)" \
  'no Go-specific db-absent reason - fails under the shipped reading, where this walk announced its own alongside sca_scan_tree'"'"'s'

unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- Go: end-to-end - a real scan.sh subprocess, scan_dispatch sca picks up Go too --\n'
# =============================================================================
t_case 'scan.sh sca --path against the Go fixture exits 0 and reports the vulnerable dependency'
GO_E2E_RUNDIR=$W/run-go-e2e
rm -rf "$GO_E2E_RUNDIR"
assert_status 0 'a real subprocess against the go-mod fixture, with the fixture db, exits clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/go-mod" --out "$GO_E2E_RUNDIR"
GO_E2E_RUNJSON=$(cat "$GO_E2E_RUNDIR/run.json" 2>/dev/null)
assert_contains "$GO_E2E_RUNJSON" '"SCA-GO-VULNERABLE_DEP-01"' \
  'checks_run in run.json shows the Go check actually executed through the real scan.sh entry point (scan_dispatch sca -> _sca_go_run), not just when go_engine.sh is sourced standalone'
assert_contains "$GO_E2E_RUNJSON" '"sca":4' \
  'run.json by_module counts 4 live findings for sca - 3 vulnerable Go dependencies plus the one unknown-version roll-up'

# =============================================================================
printf -- '\n-- end-to-end: --fail-on really gates an sca-only run (regression) --\n'
# =============================================================================
# `_sca_run_module` (modules/sca/run.sh) used to run
# findings_merge -> derive_findings -> report_all with NO gate call between
# the last two, unlike modules/sast/run.sh and modules/iac/run.sh, which both
# call sast_evaluate_gate there.  The gate was therefore never evaluated on an
# sca-only run: `scan.sh sca --fail-on critical` exited 0 with two critical
# findings on the report and run.json recorded `"gate": "not-evaluated"`, so a
# CI job gating on dependency findings was permanently green.  Every assertion
# in this section fails under that reading.
#
# Both directions are pinned deliberately, because the naive fix for each is
# the other's bug: a gate hardwired to fail satisfies the npm-lock case below
# while breaking every clean run, and the module's real defect - a gate that
# never runs at all - satisfies the python-requirements case while letting the
# npm-lock one through.  Only a gate that is actually evaluated, against the
# run's real severities, satisfies both.
t_case 'scan.sh sca --fail-on critical exits 1 (SCOURSH_EXIT_GATE) when the run carries critical findings'
GATE_E2E_RUNDIR=$W/run-gate-e2e
rm -rf "$GATE_E2E_RUNDIR"
assert_status 1 'a real subprocess over the npm-lock fixture (left-pad 1.3.0 and minimist 1.2.5 are both critical rows in the fixture db) trips the gate instead of exiting clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/npm-lock" --fail-on critical --out "$GATE_E2E_RUNDIR"
GATE_E2E_RUNJSON=$(cat "$GATE_E2E_RUNDIR/run.json" 2>/dev/null)
assert_contains "$GATE_E2E_RUNJSON" '"gate": "fail"' \
  'run.json records the gate as failing rather than "not-evaluated" - the gate was genuinely evaluated on an sca-only run, not skipped'
assert_contains "$GATE_E2E_RUNJSON" '"gated_findings": 2' \
  'both critical findings are counted by the gate, so the failure is the severity filter doing its job rather than an unrelated error'
assert_contains "$GATE_E2E_RUNJSON" '"critical":2' \
  'the run really did carry two critical findings, which is what the gate is reacting to'
assert_not_contains "$GATE_E2E_RUNJSON" 'gate_evaluation_not_yet_wired' \
  'the coverage_reduction disclosing an unwired gate is gone, because it no longer describes this module'

t_case 'the same gate PASSES when no finding reaches the threshold - the fix evaluates the gate rather than hardwiring a failure'
GATE_PASS_RUNDIR=$W/run-gate-pass
rm -rf "$GATE_PASS_RUNDIR"
assert_status 0 'the python-requirements fixture tops out at high severity, so --fail-on critical leaves it clean' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/python-requirements" --fail-on critical --out "$GATE_PASS_RUNDIR"
GATE_PASS_RUNJSON=$(cat "$GATE_PASS_RUNDIR/run.json" 2>/dev/null)
assert_contains "$GATE_PASS_RUNJSON" '"gate": "pass"' \
  'run.json records an evaluated, passing gate - NOT "not-evaluated", which is what an unwired gate would still report here'
assert_contains "$GATE_PASS_RUNJSON" '"gated_findings": 0' \
  'nothing met the critical threshold, so the gate counted nothing'

t_case 'the same fixture DOES trip the gate at the threshold its findings actually reach'
GATE_HIGH_RUNDIR=$W/run-gate-high
rm -rf "$GATE_HIGH_RUNDIR"
assert_status 1 'lowering the bar to --fail-on high makes the python-requirements run fail, proving the threshold is read from the flag and not fixed' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/python-requirements" --fail-on high --out "$GATE_HIGH_RUNDIR"
GATE_HIGH_RUNJSON=$(cat "$GATE_HIGH_RUNDIR/run.json" 2>/dev/null)
assert_contains "$GATE_HIGH_RUNJSON" '"gate": "fail"' \
  'the high-severity flask-login finding trips a --fail-on high gate on the very fixture that stayed clean at --fail-on critical'

t_case 'an sca run with no --fail-on at all is still "not-evaluated" - the gate is opt-in, and the fix does not change that'
GATE_NONE_RUNDIR=$W/run-gate-none
rm -rf "$GATE_NONE_RUNDIR"
assert_status 0 'the npm-lock fixture without --fail-on exits clean despite its critical findings' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/npm-lock" --out "$GATE_NONE_RUNDIR"
GATE_NONE_RUNJSON=$(cat "$GATE_NONE_RUNDIR/run.json" 2>/dev/null)
assert_contains "$GATE_NONE_RUNJSON" '"gate": "not-evaluated"' \
  'with --fail-on defaulting to none, the gate reports not-evaluated exactly as sast and iac runs do'

# =============================================================================
printf -- '\n-- no advisory database: a scan that never looked must not read as clean --\n'
# =============================================================================
# `data/advisories.db` does not exist in this repository (tools/vendor-engines.sh
# populates it on a networked box and is never run here), so the shipped
# behaviour below IS what an operator gets by default:
#
#   scan.sh sca --path <knowingly vulnerable project>   ->   exit 0
#   run.json: "checks_run": [], zero findings, "_No findings._" in report.md
#
# "It did not look" was indistinguishable from "it looked and found nothing",
# which for a security scanner is the worst class of defect there is.  Every
# assertion in this section fails under that shipped reading.
#
# The exit code is docs/FOUNDATION.md tension 14's `4` (missing required
# input), NOT a new code and NOT `5`: tension 14's own precedence list is
# frozen, `5` is reserved for UNPLANNED incompleteness (breaker, budget,
# mid-flight abort), and its "Required inputs are per module" table already
# assigns `4` to exactly this shape - a module explicitly selected whose
# required input is absent, the same rule that gives `dast` exit 4 for a
# missing scope.conf and (tension 20) `--paranoid` exit 4 for an absent
# observer.  The register's own row for the `all` case - "a module whose
# inputs are absent is skipped with a run.json reason", declared, no
# exit-code effect - is pinned separately below, because the naive fix for
# each direction is the other's bug.
NODB=$W/no-such-advisories.db
rm -f "$NODB"

t_case 'AC: scan.sh sca with no advisory database exits 4, not 0'
NODB_RUNDIR=$W/run-nodb-sca
rm -rf "$NODB_RUNDIR"
assert_status 4 'a run that could not check a single dependency exits SCOURSH_EXIT_INPUT - fails under the shipped reading, where the same run exits 0 and is byte-indistinguishable to CI from a clean dependency scan' \
  env SCOURSH_SCA_ADVISORIES_DB="$NODB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/npm-lock" --out "$NODB_RUNDIR"

t_case 'the run still writes its full report set, so exit 4 is a verdict rather than an abort'
assert_file_exists "$NODB_RUNDIR/run.json" 'run.json is written before the exit code is returned - fails under a die()-based reading, which exits 4 with no report at all'
assert_file_exists "$NODB_RUNDIR/report.md" 'report.md is written too'
NODB_RUNJSON=$(cat "$NODB_RUNDIR/run.json" 2>/dev/null)

t_case 'AC: the missing database is announced exactly ONCE for the whole run'
# grep -o, never grep -c: run.json puts a whole array on ONE line, so a
# line count reports 1 whether the reason was recorded once or twice and the
# assertion would pass under the very reading it exists to reject.
NODB_REASONS=$(printf '%s\n' "$NODB_RUNJSON" | grep -o 'no_advisories_db_on_disk' | wc -l | tr -d ' ')
assert_eq 1 "$NODB_REASONS" \
  'exactly one no_advisories_db_on_disk record - fails under the shipped reading, which announces it TWICE (once bare from the shared npm/RubyGems/Composer walk and once with ecosystem=Go from the Go walk) on every sca run whatever ecosystems are present'

t_case 'AC: that one record names EVERY ecosystem that could not be scanned'
assert_contains "$NODB_RUNJSON" 'reason=no_advisories_db_on_disk ecosystems=Go,RubyGems,composer,maven,npm,pypi' \
  'all six docs/DESIGN.md §6.5 ecosystems are named in one record, LC_ALL=C sorted - fails under the shipped reading, where npm/RubyGems/Composer and Go each announce their own and the Python and Java walks return silently, accounting for nothing'

t_case 'AC: checks_run is no longer empty - the coverage check itself ran'
assert_contains "$NODB_RUNJSON" '"SCA-COV-NO_ADVISORY_DB-01"' \
  'the run records the coverage check it actually executed - fails under the shipped reading, where checks_run is [] and an operator has no evidence the module did anything at all'

t_case 'AC: the report itself says dependency scanning did not run'
NODB_REPORT=$(cat "$NODB_RUNDIR/report.md" 2>/dev/null)
assert_not_contains "$NODB_REPORT" '_No findings._' \
  'the findings section no longer reads "_No findings._" - fails under the shipped reading, which is exactly the sentence that misleads a human reader'
assert_contains "$NODB_REPORT" 'SCA-COV-NO_ADVISORY_DB-01' \
  'the coverage finding is on the report, not only in run.json metadata'
assert_contains "$NODB_REPORT" 'no advisory database' \
  'the finding title states the cause in prose'

t_case 'the coverage finding reports zero dependencies checked rather than zero findings'
NODB_FINDINGS=$(cat "$NODB_RUNDIR/findings.jsonl" 2>/dev/null)
assert_contains "$NODB_FINDINGS" 'SCA-COV-NO_ADVISORY_DB-01' 'the finding is emitted'
assert_contains "$NODB_FINDINGS" 'tools/vendor-engines.sh' \
  'its remediation names the operator-run tool that populates the database, so the reader knows what to do next'

t_case 'AC (other direction): scan.sh all does NOT exit 4 for the same absent database'
NODB_ALL_RUNDIR=$W/run-nodb-all
rm -rf "$NODB_ALL_RUNDIR"
assert_status 0 'docs/FOUNDATION.md tension 14 classes "a module skipped under all for absent inputs" as a DECLARED reduction with no exit-code effect - fails under the naive fix, which makes every missing module input exit 4 regardless of whether the operator selected that module' \
  env SCOURSH_SCA_ADVISORIES_DB="$NODB" bash "$ROOT/scan.sh" all --path "$FIXTURES/npm-lock" --out "$NODB_ALL_RUNDIR"
NODB_ALL_RUNJSON=$(cat "$NODB_ALL_RUNDIR/run.json" 2>/dev/null)
assert_contains "$NODB_ALL_RUNJSON" 'reason=no_advisories_db_on_disk ecosystems=' \
  'the skip is still recorded with its reason under `all` - declared, not silent'
assert_contains "$NODB_ALL_RUNJSON" '"SCA-COV-NO_ADVISORY_DB-01"' \
  'and the coverage finding is still emitted, so `all` reports the blind spot even though it does not change the exit code'

t_case 'AC (other direction): a db that IS present produces no coverage finding and no exit 4'
DB_PRESENT_RUNDIR=$W/run-db-present
rm -rf "$DB_PRESENT_RUNDIR"
assert_status 0 'the same command with the fixture db exits 0 - fails under a hardwired reading that emits the coverage finding or the exit code unconditionally' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/npm-lock" --out "$DB_PRESENT_RUNDIR"
DB_PRESENT_RUNJSON=$(cat "$DB_PRESENT_RUNDIR/run.json" 2>/dev/null)
assert_not_contains "$DB_PRESENT_RUNJSON" 'SCA-COV-NO_ADVISORY_DB-01' \
  'no coverage finding when there was nothing to report'
assert_not_contains "$DB_PRESENT_RUNJSON" 'no_advisories_db_on_disk' \
  'and no db-absent reason either'

t_case 'each ecosystem walk called STANDALONE with no db stays silent - the announcement belongs to the module, and is why it can be made once'
SILENT_RUNDIR=$W/run-nodb-standalone
rm -rf "$SILENT_RUNDIR"
run_init "$SILENT_RUNDIR"
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/npm-lock")
SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/npm-lock")
export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
export SCOURSH_SCA_ADVISORIES_DB=$NODB
assert_status 0 'sca_scan_tree with no readable db is still a declared reduction, not a fatal error' \
  sca_scan_tree "$FIXTURES/npm-lock"
assert_status 0 'sca_go_scan_tree likewise' \
  sca_go_scan_tree "$FIXTURES/go-mod"
sca_scan_tree "$FIXTURES/npm-lock" >/dev/null 2>&1 || true
sca_go_scan_tree "$FIXTURES/go-mod" >/dev/null 2>&1 || true
sca_scan_python_tree "$FIXTURES/python-requirements" >/dev/null 2>&1 || true
sca_scan_java_tree "$FIXTURES/maven" >/dev/null 2>&1 || true
assert_eq '' "$(cat "$SILENT_RUNDIR/meta/coverage_reduction" 2>/dev/null)" \
  'no walk records a db-absent reason of its own - fails under the shipped reading, where sca_scan_tree and sca_go_scan_tree each announce one, which is precisely why the module-level run announced it twice'
unset SCOURSH_SCA_ADVISORIES_DB SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID

# =============================================================================
printf -- '\n-- the unknown-version roll-up: ONE per run, and its counts add up --\n'
# =============================================================================
# tests/fixtures/sca/mixed-four-ecosystems/ carries one unknown-version case in
# each of the four ecosystem-scan ENTRY POINTS the module has - npm
# (sca_scan_tree), pypi (sca_scan_python_tree), maven (sca_scan_java_tree) and
# Go (sca_go_scan_tree) - so the true total is 4.
#
# Shipped behaviour, measured before this change: run.json recorded all four
# coverage_gap facts, and the report carried ONE roll-up finding reading
# "SCA: 1 pinned dependency version(s) ... by ecosystem: Go: 1".  Each walk
# emitted its own SCA-COV-UNKNOWN_VERSION-01, all four hashed to the identical
# fingerprint (the SCA location profile is ecosystem/package/advisory_id and a
# roll-up populates none of them), and findings_merge's dedup kept exactly one
# - so three quarters of the real coverage gap was dropped silently and the
# operator was told a smaller number than the truth.
#
# The fix is at the EMISSION layer, not the fingerprint layer: the roll-up is
# one per run by construction, so the four walks now accumulate into one shared
# table that the module flushes once.  Its fingerprint is therefore UNCHANGED,
# which is pinned below against a digest computed from raw bytes.
MIXED4=$FIXTURES/mixed-four-ecosystems
MIXED4_RUNDIR=$W/run-mixed-four
rm -rf "$MIXED4_RUNDIR"
assert_status 0 'the four-ecosystem fixture scans clean of gated findings' \
  env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$MIXED4" --out "$MIXED4_RUNDIR"
MIXED4_FINDINGS=$(cat "$MIXED4_RUNDIR/findings.jsonl" 2>/dev/null)
MIXED4_RUNJSON=$(cat "$MIXED4_RUNDIR/run.json" 2>/dev/null)

t_case 'AC: four ecosystems with unknown-version dependencies produce exactly one roll-up'
MIXED4_ROLLUPS=$(printf '%s\n' "$MIXED4_FINDINGS" | grep -c 'SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$MIXED4_ROLLUPS" \
  'one roll-up finding survives - true under the shipped reading too, but only because three of the four were silently deduplicated away rather than never emitted'

t_case 'AC: the roll-up count is the TRUTH across every ecosystem, not one walk'"'"'s share'
assert_contains "$MIXED4_FINDINGS" 'SCA: 4 pinned dependency version(s)' \
  'the title states 4 (npm 1 + pypi 1 + maven 1 + Go 1) - fails under the shipped reading, whose surviving roll-up states 1 because the other three walks'"'"' counts were dropped by the fingerprint collision'

t_case 'AC: the breakdown names every contributing ecosystem, LC_ALL=C sorted'
assert_contains "$MIXED4_FINDINGS" 'by ecosystem: Go: 1, maven: 1, npm: 1, pypi: 1' \
  'all four ecosystems appear in one breakdown - fails under the shipped reading, whose survivor reads "by ecosystem: Go: 1" alone'

t_case 'AC: the coverage_gap facts and the roll-up finding now agree'
for _eco in Go maven npm pypi; do
  assert_contains "$MIXED4_RUNJSON" "reason=unknown_version ecosystem=$_eco count=1" \
    "run.json still records $_eco's own coverage_gap fact"
done
MIXED4_GAP_TOTAL=$(printf '%s\n' "$MIXED4_RUNJSON" | grep -o 'reason=unknown_version ecosystem=[^ ]* count=1' | wc -l | tr -d ' ')
assert_eq 4 "$MIXED4_GAP_TOTAL" \
  'four coverage_gap facts, and the finding above states 4 - fails under the shipped reading, where run.json said four and the report said one, and nothing reconciled them'

t_case 'the roll-up fingerprint is UNCHANGED by this fix (rules/RULE-FORMAT.md §14 item 3)'
# Pick the roll-up's own line explicitly rather than the first finding in the
# file: the fixture happens to emit only the roll-up today, and an assertion
# that silently depends on that would start checking a different finding's
# fingerprint the moment the fixture gains a vulnerable dependency.
MIXED4_FP=$(printf '%s\n' "$MIXED4_FINDINGS" | grep 'SCA-COV-UNKNOWN_VERSION-01' \
  | sed -n 's/.*"fingerprint": *"\([0-9a-f]*\)".*/\1/p' | head -1)
EXPECTED_ROLLUP_FP=$(printf 'fp/1\0sca\0SCA-COV-UNKNOWN_VERSION-01\0\0\0' | sha256_of)
assert_eq "$EXPECTED_ROLLUP_FP" "$MIXED4_FP" \
  'the roll-up still hashes fp/1 + sca + check id + three EMPTY SCA location components, asserted against a digest computed from raw bytes rather than through fingerprint_compute - fails under the rejected alternative fix (adding the ecosystem to the roll-up fingerprint), which would change finding identity, invalidate every baseline entry for this check, and cost a format_version bump'
assert_eq 'a4688098bdb845ce8da891fb7fbed9d9c31cd359e3fe66e811bd3134731fd997' "$MIXED4_FP" \
  'and it is byte-for-byte the value the shipped code produced before this change, measured on the same fixture db - so no state/ migration and no fp_schema bump are owed'

t_case 'a single-ecosystem run is unaffected: still one roll-up, still that ecosystem'"'"'s own count'
SINGLE_RUNDIR=$W/run-single-eco
rm -rf "$SINGLE_RUNDIR"
env SCOURSH_SCA_ADVISORIES_DB="$DB" bash "$ROOT/scan.sh" sca --path "$FIXTURES/python-requirements" --out "$SINGLE_RUNDIR" >/dev/null 2>&1 || true
SINGLE_FINDINGS=$(cat "$SINGLE_RUNDIR/findings.jsonl" 2>/dev/null)
SINGLE_ROLLUPS=$(printf '%s\n' "$SINGLE_FINDINGS" | grep -c 'SCA-COV-UNKNOWN_VERSION-01' || true)
assert_eq 1 "$SINGLE_ROLLUPS" 'exactly one roll-up for a pypi-only tree'
assert_contains "$SINGLE_FINDINGS" 'by ecosystem: pypi: 1' \
  'and it reports pypi'"'"'s own real count - fails if the shared accumulator leaked a count from an earlier run or dropped this one'

t_summary 'sca' || FAILED=1
exit "${FAILED:-0}"
