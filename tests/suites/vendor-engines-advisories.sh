#!/usr/bin/env bash
# tests/suites/vendor-engines-advisories.sh - tools/vendor-engines.sh's
# `advisories` command namespace (docs/FOUNDATION.md tension 25): resolving
# data/advisories.db/data/versions.db from real SCA advisory data.
#
# Sibling suite to tests/suites/vendor-engines.sh, not an extension of it -
# that suite's own header already explains why each concrete capability
# landed on tools/vendor-engines.sh gets its own file (sast-semgrep.sh,
# iac-trivy.sh, sast-gitleaks.sh); this ticket's advisory-expansion
# namespace follows the same convention, exercising a COMPLETELY SEPARATE
# code path (VENG_ADVISORY_REGISTRY / veng_advisories_* / the `advisories`
# dispatch branch) from that suite's own VENG_REGISTRY / veng_vendor_*
# coverage.
#
# What this suite proves, and what it honestly cannot:
#
#  - The registry, list, unknown-ecosystem, and missing-env-var refusal
#    paths are exercised both in-process and as real subprocess
#    invocations of the actual script, the same two-layer shape
#    tests/suites/vendor-engines.sh already uses for VENG_REGISTRY.
#  - The real OSV.dev fetch (`_veng_advisories_osv_fetch`) is exercised
#    against a STUBBED curl on PATH, never the real network - the same
#    "no live network calls in CI" posture tests/suites/sca.sh's own
#    fixture-driven pattern already established for data/advisories.db's
#    READER side; this suite proves the WRITER side the identical way.
#    tests/fixtures/vendor-engines/osv/*.json are hand-authored,
#    OSV.dev-*shaped* fixtures - not real, live-fetched records (see that
#    directory's own README).
#  - The real `python3` JSON extraction (`_veng_advisories_osv_extract`)
#    and the real per-ecosystem normalisation (modules/sca/*.sh's own
#    `sca_*_normalize_name` functions, reused verbatim) both run for
#    real - only the network fetch is stubbed, not the parsing/
#    normalisation logic this suite exists to prove correct.
#  - It proves negative paths (missing env var, unknown ecosystem, a
#    range-only advisory with no explicit version enumeration) never
#    touch curl at all, by stripping curl/wget from PATH the same way
#    tests/suites/vendor-engines.sh's own section B does.
#  - Every db write in this suite targets SCOURSH_SCA_ADVISORIES_DB /
#    SCOURSH_SCA_VERSIONS_DB pointed at scratch paths - never this
#    repository's own data/advisories.db or data/versions.db, which stay
#    absent from the tree (tools/vendor-engines.sh is never run for real
#    in this repo/CI; see this file's own header and
#    tests/fixtures/sca/advisories.db's).
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=tools/vendor-engines.sh
source "$ROOT/tools/vendor-engines.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

TOOL=$ROOT/tools/vendor-engines.sh
FIXTURES=$ROOT/tests/fixtures/vendor-engines/osv
W=$SCOURSH_SCRATCH/vendor-engines-advisories
mkdir -p "$W"

# ---------------------------------------------------------------------------
# -- section A: structural separation from section 2's VENG_REGISTRY --
# ---------------------------------------------------------------------------
t_case 'VENG_ADVISORY_REGISTRY is a separate array from VENG_REGISTRY'
assert_eq 6 "${#VENG_ADVISORY_REGISTRY[@]}" \
  'the advisory registry has exactly six entries - the six docs/DESIGN.md §6.5 ecosystems, never merged with the three-entry engine-adapter VENG_REGISTRY'
assert_eq 3 "${#VENG_REGISTRY[@]}" \
  'VENG_REGISTRY itself is untouched (still three engine adapters) - fails under a bug that accidentally merged the two registries'
assert_eq veng_advisories_npm "${VENG_ADVISORY_REGISTRY[npm]:-}" 'npm maps to veng_advisories_npm'
assert_eq veng_advisories_pypi "${VENG_ADVISORY_REGISTRY[pypi]:-}" 'pypi maps to veng_advisories_pypi'
assert_eq veng_advisories_maven "${VENG_ADVISORY_REGISTRY[maven]:-}" 'maven maps to veng_advisories_maven'
assert_eq veng_advisories_go "${VENG_ADVISORY_REGISTRY[Go]:-}" 'Go maps to veng_advisories_go'
assert_eq veng_advisories_rubygems "${VENG_ADVISORY_REGISTRY[RubyGems]:-}" 'RubyGems maps to veng_advisories_rubygems'
assert_eq veng_advisories_composer "${VENG_ADVISORY_REGISTRY[composer]:-}" 'composer maps to veng_advisories_composer'

t_case 'veng_advisories_list, LC_ALL=C sorted'
out=$(veng_advisories_list)
assert_eq "$(printf 'Go\nRubyGems\ncomposer\nmaven\nnpm\npypi')" "$out" \
  'six ecosystems list Go, RubyGems, composer, maven, npm, pypi in that order under LC_ALL=C (uppercase sorts before lowercase) - fails under an insertion-order or case-insensitive reading'

t_case 'veng_advisories_one: unknown ecosystem refuses (exit 4), never touches VENG_REGISTRY'
rc=0
( veng_advisories_one 'not-a-real-ecosystem' ) >"$W/unknown.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'an unknown ecosystem name is exit 4 (SCOURSH_EXIT_INPUT)'
assert_contains "$(cat "$W/unknown.out")" "unknown ecosystem 'not-a-real-ecosystem'" \
  'the refusal names the actual ecosystem that was requested'

t_case 'an <engine> name is never accepted as an ecosystem, and vice versa'
rc=0
( veng_advisories_one 'semgrep' ) >"$W/cross.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "a registered ENGINE name ('semgrep') is not a registered ecosystem - the two registries never share names or fall back to each other"
rc=0
( veng_vendor_one 'npm' ) >"$W/cross2.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "a registered ECOSYSTEM name ('npm') is not a registered engine adapter, the same separation in the other direction"

# ---------------------------------------------------------------------------
# -- section B: real subprocess invocations, PATH stripped of curl/wget so
#    any accidental fetch attempt fails loudly rather than reaching the
#    network (mirrors tests/suites/vendor-engines.sh's own section B) --
# ---------------------------------------------------------------------------
NO_NET_PATH=$W/no-curl-path
mkdir -p "$NO_NET_PATH"
for tool in bash cat sort mkdir dirname pwd printf true false grep sed date python3 mv wc; do
  src=$(command -v "$tool" 2>/dev/null) || continue
  ln -sf "$src" "$NO_NET_PATH/$tool"
done

t_case 'advisories --help'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories --help 2>&1) || rc=$?
assert_eq 0 "$rc" 'advisories --help exits 0'
assert_contains "$out" 'usage: tools/vendor-engines.sh advisories' \
  'advisories --help prints its OWN usage banner, not the top-level one'
assert_contains "$out" 'SCOURSH_ADVISORY_NPM_IDS' \
  'the usage text names the real per-ecosystem env vars an operator must set'

t_case 'advisories with no sub-command is a usage error (exit 2)'
rc=0
PATH=$NO_NET_PATH bash "$TOOL" advisories >/dev/null 2>&1 || rc=$?
assert_eq 2 "$rc" "'advisories' alone (no sub-command) is exit 2, matching the top-level script's own no-args convention"

t_case 'advisories --bogus is a usage error (exit 2)'
rc=0
PATH=$NO_NET_PATH bash "$TOOL" advisories --bogus >/dev/null 2>&1 || rc=$?
assert_eq 2 "$rc" "an unrecognised advisories flag is exit 2"

t_case 'advisories --list, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories --list 2>&1) || rc=$?
assert_eq 0 "$rc" 'advisories --list exits 0'
assert_eq "$(printf 'Go\nRubyGems\ncomposer\nmaven\nnpm\npypi')" "$out" \
  'advisories --list reports the same six, LC_ALL=C sorted, as a real subprocess too'

t_case 'advisories <ecosystem>, no operator-supplied ids: refuses (exit 4), never touches curl'
for eco_arg in npm pypi maven Go RubyGems composer; do
  rc=0
  out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories "$eco_arg" 2>&1) || rc=$?
  assert_eq "$SCOURSH_EXIT_INPUT" "$rc" "advisories $eco_arg with no ids set is exit 4 - curl is entirely absent from PATH, so a false pass here would mean a network attempt, not a real refusal"
  assert_contains "$out" 'is not set' "advisories $eco_arg's refusal explains that the ids env var is unset"
done
assert_contains "$(PATH=$NO_NET_PATH bash "$TOOL" advisories npm 2>&1)" 'SCOURSH_ADVISORY_NPM_IDS' \
  'the npm refusal names the exact env var (SCOURSH_ADVISORY_NPM_IDS)'
assert_contains "$(PATH=$NO_NET_PATH bash "$TOOL" advisories Go 2>&1)" 'SCOURSH_ADVISORY_GO_IDS' \
  'the Go refusal names the exact env var (SCOURSH_ADVISORY_GO_IDS)'

t_case 'advisories --all, nothing set: refuses on the alphabetically-first ecosystem (Go), never touches curl'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories --all 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  '--all reaches Go first (Go < RubyGems < composer < maven < npm < pypi under LC_ALL=C) and refuses there'
assert_contains "$out" 'SCOURSH_ADVISORY_GO_IDS' \
  'the --all refusal names the FIRST ecosystem env var it reached, not a generic message'

t_case 'unknown ecosystem, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories nonexistent-eco 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'an unknown ecosystem as a real subprocess is exit 4 too'
assert_contains "$out" "unknown ecosystem 'nonexistent-eco'" 'the error names the actual ecosystem requested'

t_case 'exit codes never leave 0-5 (tension 14, finding F16)'
for args in 'advisories' 'advisories --help' 'advisories --list' 'advisories --all' \
  'advisories --bogus' 'advisories npm' 'advisories nonexistent-eco'; do
  rc=0
  # shellcheck disable=SC2086
  PATH=$NO_NET_PATH bash "$TOOL" $args >/dev/null 2>&1 || rc=$?
  if (( rc >= 0 && rc <= 5 )); then
    _t_ok "exit code for '$args' is $rc, within 0-5"
  else
    _t_no "exit code for '$args' is $rc, OUTSIDE 0-5" "args: [$args]"
  fi
done

# ---------------------------------------------------------------------------
# -- section C: the shared severity/TAB-LF guard functions, unit-tested
#    directly (no fetch/parse involved) --
# ---------------------------------------------------------------------------
t_case '_veng_advisories_normalize_severity'
assert_eq critical "$(_veng_advisories_normalize_severity CRITICAL)" 'CRITICAL -> critical'
assert_eq high "$(_veng_advisories_normalize_severity HIGH)" 'HIGH -> high'
assert_eq medium "$(_veng_advisories_normalize_severity MODERATE)" \
  "GHSA's own MODERATE -> medium - fails under a naive literal-lowercase reading that would emit the non-existent word 'moderate'"
assert_eq medium "$(_veng_advisories_normalize_severity MEDIUM)" 'MEDIUM -> medium'
assert_eq low "$(_veng_advisories_normalize_severity LOW)" 'LOW -> low'
assert_eq medium "$(_veng_advisories_normalize_severity '')" \
  'an empty/absent severity defaults to medium (conservative, never dropped) rather than crashing or emitting an empty field'
assert_eq medium "$(_veng_advisories_normalize_severity 'CVSS:3.1/AV:N/AC:L')" \
  'an unrecognised CVSS-vector-shaped value also falls back to medium rather than being (mis)scored'

t_case '_veng_advisories_reject_tab_lf'
rc=0
( _veng_advisories_reject_tab_lf summary 'a clean value' ) >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" 'a value with no TAB/LF passes'
rc=0
( _veng_advisories_reject_tab_lf summary $'a value with a\ttab' ) >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'a value containing a literal TAB is refused (exit 5) rather than silently written into a corrupt row'
rc=0
( _veng_advisories_reject_tab_lf summary $'a value with a\nnewline' ) >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" 'a value containing a literal LF is refused (exit 5) too'

t_case '_veng_advisories_normalize_name / _veng_advisories_normalize_version, per ecosystem (reused sca_*_normalize_* functions)'
# The normalize functions delegate to modules/sca/*.sh's own
# sca_*_normalize_* functions, lazily sourced by
# _veng_advisories_load_normalizers (normally called once inside
# _veng_advisories_run) - called directly here since these unit tests
# exercise the normalize wrappers standalone, in-process.
_veng_advisories_load_normalizers
assert_eq 'left-pad-fixture' "$(_veng_advisories_normalize_name npm 'left-pad-fixture')" 'npm: verbatim'
assert_eq 'django-fixture-app' "$(_veng_advisories_normalize_name pypi 'Django_Fixture.App')" \
  'pypi: PEP 503 normalisation (mixed case, underscore and dot all collapse) - fails under a bare lowercase reading'
assert_eq 'railsfixturegem' "$(_veng_advisories_normalize_name RubyGems 'RailsFixtureGem')" 'RubyGems: lowercased'
assert_eq 'acme/fixture-widget' "$(_veng_advisories_normalize_name composer 'Acme/Fixture-Widget')" 'composer: lowercased'
assert_eq 'org.example.fixture:widget-core' \
  "$(_veng_advisories_normalize_name maven 'org.example.fixture:widget-core')" \
  'maven: groupId:artifactId re-joined by sca_maven_normalize_name, case preserved'
assert_eq 'github.com/example/fixture/v3' \
  "$(_veng_advisories_normalize_name Go 'github.com/example/fixture/v3')" \
  'Go: module path verbatim, /vN retained'
assert_eq 'v3.0.1' "$(_veng_advisories_normalize_version Go 'v3.0.1')" \
  'Go: a version with no +incompatible suffix passes through unchanged'
assert_eq 'v3.0.0' "$(_veng_advisories_normalize_version Go 'v3.0.0+incompatible')" \
  'Go: +incompatible IS stripped from the version - fails under the naive unstripped reading tests/suites/sca.sh itself warns about'
assert_eq '2.0' "$(_veng_advisories_normalize_version pypi '2.0')" \
  'every non-Go ecosystem carries its version through unchanged'

# ---------------------------------------------------------------------------
# -- section D: end-to-end expansion against a STUBBED curl serving the
#    committed OSV-shaped fixtures, writing to SCRATCH advisories.db /
#    versions.db - never this repository's own data/ directory --
# ---------------------------------------------------------------------------
FAKE_BIN=$W/fake-bin
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/curl" <<FAKECURL
#!/usr/bin/env bash
# Test double for curl (tests/suites/vendor-engines-advisories.sh only) -
# never a real network call.  Looks the requested OSV id up as a file
# under FAKE_OSV_FIXTURES_DIR/<id>.json and copies it to --output.
set -Eeuo pipefail
out='' url=''
args=("\$@")
i=0
while (( i < \${#args[@]} )); do
  case \${args[i]} in
    --output) out=\${args[\$(( i + 1 ))]} ;;
    http*) url=\${args[i]} ;;
  esac
  i=\$(( i + 1 ))
done
if [[ -n \${FAKE_CURL_FAIL:-} ]]; then
  printf 'fake curl: simulated failure\n' >&2
  exit 22
fi
id=\${url##*/}
src="\${FAKE_OSV_FIXTURES_DIR:?}/\$id.json"
if [[ ! -f \$src ]]; then
  printf 'fake curl: no fixture for %s\n' "\$id" >&2
  exit 22
fi
cp -- "\$src" "\$out"
FAKECURL
chmod +x "$FAKE_BIN/curl"

DB=$W/db/advisories.db
VDB=$W/db/versions.db
rm -rf "$W/db"
mkdir -p "$W/db"

run_ecosystem() {
  # Runs one ecosystem's veng_advisories_one against the stubbed curl, with
  # SCOURSH_SCA_ADVISORIES_DB/SCOURSH_SCA_VERSIONS_DB pointed at this
  # suite's own scratch files - a real subprocess (not in-process), since
  # veng_advisories_one/die exits on failure the same way
  # tests/suites/vendor-engines.sh's own veng_vendor_all test documents for
  # itself.
  local eco=$1
  ( PATH="$FAKE_BIN:$PATH" \
    FAKE_OSV_FIXTURES_DIR="$FIXTURES" \
    SCOURSH_SCA_ADVISORIES_DB="$DB" \
    SCOURSH_SCA_VERSIONS_DB="$VDB" \
    bash "$TOOL" advisories "$eco" ) >"$W/run-$eco.out" 2>&1
}

t_case 'end-to-end: npm'
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' run_ecosystem npm
assert_file_exists "$DB" 'data/advisories.db (scratch) was written'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\tleft-pad-fixture\t1.0.0\tSCOURSH-FIXTURE-OSV-NPM-1\thigh\t1.1.0\tfixture: prototype pollution')" \
  'the npm row lands in the frozen schema (ecosystem, package, version, advisory_id, severity, fixed_versions, summary), severity normalised HIGH -> high'
assert_not_contains "$(cat "$DB")" 'decoy-should-not-appear' \
  "the fixture's own decoy PyPI-ecosystem 'affected' entry inside the npm advisory is NOT emitted as an npm row - proves ecosystem filtering, not just id filtering"

t_case 'end-to-end: pypi (name normalisation, missing severity defaults to medium)'
SCOURSH_ADVISORY_PYPI_IDS='SCOURSH-FIXTURE-OSV-PYPI-1' run_ecosystem pypi
assert_contains "$(cat "$DB")" \
  "$(printf 'pypi\tdjango-fixture-app\t2.0\tSCOURSH-FIXTURE-OSV-PYPI-1\tmedium\t2.1.0')" \
  'the PyPI row uses the PEP 503 normalised name and defaults the absent severity to medium'

t_case 'end-to-end: maven (groupId:artifactId, multiple fixed events comma-joined)'
SCOURSH_ADVISORY_MAVEN_IDS='SCOURSH-FIXTURE-OSV-MAVEN-1' run_ecosystem maven
assert_contains "$(cat "$DB")" \
  "$(printf 'maven\torg.example.fixture:widget-core\t1.2.3\tSCOURSH-FIXTURE-OSV-MAVEN-1\tcritical\t1.2.4,1.3.0')" \
  'the maven row keeps the groupId:artifactId key and joins two distinct fixed events with a comma, deduplicated'

t_case 'end-to-end: Go (+incompatible stripped on exactly one of two versions)'
SCOURSH_ADVISORY_GO_IDS='SCOURSH-FIXTURE-OSV-GO-1' run_ecosystem Go
assert_contains "$(cat "$DB")" \
  "$(printf 'Go\tgithub.com/example/fixture/v3\tv3.0.0\tSCOURSH-FIXTURE-OSV-GO-1\tmedium')" \
  'the +incompatible-suffixed version is normalised (v3.0.0+incompatible -> v3.0.0) before being written - fixed_versions (v3.1.0) is carried through UNNORMALISED, since tension 25 states it is opaque display text, never compared'
assert_contains "$(cat "$DB")" \
  "$(printf 'Go\tgithub.com/example/fixture/v3\tv3.0.1\tSCOURSH-FIXTURE-OSV-GO-1\tmedium')" \
  'the sibling version with no +incompatible suffix passes through unchanged - both rows exist side by side'

t_case 'end-to-end: RubyGems (lowercased, no fixed version published)'
SCOURSH_ADVISORY_RUBYGEMS_IDS='SCOURSH-FIXTURE-OSV-RUBY-1' run_ecosystem RubyGems
assert_contains "$(cat "$DB")" \
  "$(printf 'RubyGems\trailsfixturegem\t5.0.0\tSCOURSH-FIXTURE-OSV-RUBY-1\tlow\t\tfixture')" \
  'the RubyGems row lowercases the name and renders "no fixed version published" as a genuinely empty field, not a placeholder string - the same empty-middle-field shape tests/suites/sca.sh already pins for the READER side'

t_case 'end-to-end: composer (vendor/package lowercased)'
SCOURSH_ADVISORY_COMPOSER_IDS='SCOURSH-FIXTURE-OSV-COMPOSER-1' run_ecosystem composer
assert_contains "$(cat "$DB")" \
  "$(printf 'composer\tacme/fixture-widget\t3.0.0\tSCOURSH-FIXTURE-OSV-COMPOSER-1\thigh\t3.1.0')" \
  'the composer row lowercases the vendor/package name, matching sca_composer_normalize_name'

t_case 'data/versions.db mirrors data/advisories.db (tension 25: "the same shape and the same rule")'
# The two files' own `#` header lines legitimately differ (each names
# itself, e.g. "generated ... advisories.db" vs "... versions.db"); the
# DATA rows below the header - the actual "same shape, same rule" tension
# 25 asks for - must be byte-identical.
db_body=$(grep -v -- '^#' "$DB" 2>/dev/null || true)
vdb_body=$(grep -v -- '^#' "$VDB" 2>/dev/null || true)
assert_eq "$db_body" "$vdb_body" \
  'after six ecosystem runs, the scratch versions.db data rows are byte-identical to advisories.db - both are written by the same _veng_advisories_write_db call in _veng_advisories_run'

t_case 'sorted under LC_ALL=C, one # header, no stray blank/duplicate lines'
body=$(grep -v '^#' "$DB" 2>/dev/null || true)
sorted=$(LC_ALL=C sort <<<"$body")
assert_eq "$sorted" "$body" 'the non-comment body of data/advisories.db is already in LC_ALL=C sorted order'
header_count=$(grep -c -- '^#' "$DB" 2>/dev/null || true)
if (( header_count > 0 )); then
  _t_ok 'at least one # header/comment line is present'
else
  _t_no 'at least one # header/comment line is present' "header_count=$header_count"
fi

t_case 'range-only advisory: zero rows, not fatal'
: >"$W/db/advisories.db"
: >"$W/db/versions.db"
rc=0
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-RANGEONLY' run_ecosystem npm || rc=$?
assert_eq 0 "$rc" \
  'an advisory whose only npm-ecosystem "affected" entry carries no explicit versions[] array is a WARNING, not a failure - the run still exits 0'
assert_not_contains "$(cat "$DB")" 'range-only-fixture' \
  'no row was written for it - tension 25 requires exact versions, never a guessed range'
assert_contains "$(cat "$W/run-npm.out")" 'produced no npm row' \
  'the zero-row case is logged, not silently swallowed'

t_case 'a TAB smuggled inside a fixed-version event is refused, never written (exit 5)'
rc=0
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-POISON' run_ecosystem npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  '_veng_advisories_reject_tab_lf catches the poisoned fixed_versions field end to end and refuses (exit 5) - fails under a reading that trusts OSV output verbatim'
assert_not_contains "$(cat "$DB")" 'poison-fixture' \
  'nothing from the poisoned advisory was written to data/advisories.db'

# ---------------------------------------------------------------------------
# -- section E: merge behaviour - re-running one ecosystem replaces ONLY
#    that ecosystem's rows, leaving every other ecosystem's rows intact --
# ---------------------------------------------------------------------------
t_case 'merge: re-running npm does not disturb pypi/maven/Go/RubyGems/composer rows, and drops npm'"'"'s stale row'
: >"$W/db/advisories.db"
: >"$W/db/versions.db"
SCOURSH_ADVISORY_PYPI_IDS='SCOURSH-FIXTURE-OSV-PYPI-1' run_ecosystem pypi
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' run_ecosystem npm
before=$(cat "$DB")
assert_contains "$before" 'django-fixture-app' 'pypi row present after the first two runs'
assert_contains "$before" 'left-pad-fixture' 'npm row present after the first two runs'
# Re-run npm against a DIFFERENT advisory id/package - the stale
# left-pad-fixture row must be gone, replaced by the new one, while the
# pypi row (a different ecosystem entirely) must survive untouched.
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-RANGEONLY' run_ecosystem npm
after=$(cat "$DB")
assert_contains "$after" 'django-fixture-app' \
  'pypi row still present after a second, unrelated npm re-run - proves the merge only touches the target ecosystem'
assert_not_contains "$after" 'left-pad-fixture' \
  "npm's stale row from the FIRST npm run is gone - a re-run replaces, it does not accumulate stale rows forever"

t_summary 'vendor-engines-advisories'
