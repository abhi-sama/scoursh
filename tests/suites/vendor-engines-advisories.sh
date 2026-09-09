#!/usr/bin/env bash
# tests/suites/vendor-engines-advisories.sh - tools/vendor-engines.sh's
# `advisories` command namespace (docs/FOUNDATION.md tension 25): resolving
# data/advisories.db/data/versions.db from real SCA advisory data - and
# (section D2) data/versions.db's OWN `banner` namespace
# (docs/VERSIONS-DB.md §3-§5), the known-vulnerable-version catalogue for a
# banner-matched product with no SCA-ecosystem manifest at all.
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
# A full-enough userland for lib/core.sh's own baseline (grep sed awk sort tr
# cut find xargs mktemp date, plus a SHA-256 provider) and for a real bulk
# import, with curl and wget DELIBERATELY absent: every test that runs under
# this PATH is one where reaching the network would be a defect, so a pass
# proves the code path never tried rather than that it tried and was refused.
for tool in bash sh cat sort mkdir rmdir dirname basename pwd printf true false \
  grep sed awk date python3 mv cp rm ln wc cut tr find xargs mktemp look \
  uname id chmod stat readlink head tail env sleep tee sha256sum shasum openssl; do
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
  'advisories --bogus' 'advisories npm' 'advisories nonexistent-eco' \
  'advisories banner' 'advisories bulk banner --accept-unverified'; do
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
# docs/FOUNDATION.md tension 25's summary-normalisation amendment: the two
# advisory-keyed summary side tables, pointed at scratch paths for the
# identical reason DB/VDB are - without this override,
# _veng_advisories_write_summaries_db would fall back to
# $VENG_DIR/data/advisory-summaries.db (the REAL repository path), and this
# suite would write into the checked-out tree it runs from.
SDB=$W/db/advisory-summaries.db
VSDB=$W/db/version-summaries.db
rm -rf "$W/db"
mkdir -p "$W/db"

run_ecosystem() {
  # Runs one ecosystem's veng_advisories_one against the stubbed curl, with
  # SCOURSH_SCA_ADVISORIES_DB/SCOURSH_SCA_VERSIONS_DB (and their two summary
  # side-table siblings) pointed at this suite's own scratch files - a real
  # subprocess (not in-process), since veng_advisories_one/die exits on
  # failure the same way tests/suites/vendor-engines.sh's own
  # veng_vendor_all test documents for itself.
  local eco=$1
  ( PATH="$FAKE_BIN:$PATH" \
    FAKE_OSV_FIXTURES_DIR="$FIXTURES" \
    SCOURSH_SCA_ADVISORIES_DB="$DB" \
    SCOURSH_SCA_VERSIONS_DB="$VDB" \
    SCOURSH_SCA_SUMMARIES_DB="$SDB" \
    SCOURSH_DAST_VERSION_SUMMARIES_DB="$VSDB" \
    bash "$TOOL" advisories "$eco" ) >"$W/run-$eco.out" 2>&1
}

t_case 'end-to-end: npm (docs/FOUNDATION.md tension 25 npm-range amendment)'
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' run_ecosystem npm
assert_file_exists "$DB" 'data/advisories.db (scratch) was written'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\tleft-pad-fixture\t1.0.0\t\texact\tSCOURSH-FIXTURE-OSV-NPM-1\thigh\t1.1.0')" \
  'the frozen npm-range schema (ecosystem, package, introduced, bound, bound_kind, advisory_id, severity, fixed_versions) - an OSV-enumerated versions[] entry becomes a bound_kind=exact row, bound empty. `summary` is no longer inline (Change 2) - severity normalised HIGH -> high'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\tleft-pad-fixture\t1.0.1\t\texact\tSCOURSH-FIXTURE-OSV-NPM-1')" \
  'the second enumerated version gets its own exact-kind row'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\tleft-pad-fixture\t1.0.2\t\texact\tSCOURSH-FIXTURE-OSV-NPM-1')" \
  'and the third'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\tleft-pad-fixture\t0\t1.1.0\tfixed\tSCOURSH-FIXTURE-OSV-NPM-1\thigh\t1.1.0')" \
  'the fixture'"'"'s own ranges[] entry - introduced "0", fixed "1.1.0" - is ALSO written, as a bound_kind=fixed interval row, not skipped: this is the amendment'"'"'s whole point (§7 Slices 1+2 of the feasibility scout report), closing the gap the shipped importer left open even after tension 25'"'"'s original RESOLUTION called for exactly this'
assert_not_contains "$(cat "$DB")" 'fixture:' \
  'no summary text of any kind is inline in data/advisories.db'
assert_contains "$(cat "$SDB")" 'fixture: prototype pollution' \
  'the summary lives in the advisory-keyed side table instead (Change 2)'
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
assert_contains "$(LC_ALL=C grep -- $'^RubyGems\trailsfixturegem\t' "$DB")" \
  "$(printf 'RubyGems\trailsfixturegem\t5.0.0\tSCOURSH-FIXTURE-OSV-RUBY-1\tlow\t')" \
  'the RubyGems row lowercases the name and renders "no fixed version published" as a genuinely empty TRAILING field (row ends right after the empty fixed_versions field, `summary` no longer inline per Change 2), not a placeholder string - the same empty-middle-field shape tests/suites/sca.sh already pins for the READER side'
assert_contains "$(cat "$SDB")" 'fixture' \
  'the RubyGems advisory'"'"'s own summary lives in the side table too - Change 2 is not npm-specific'

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

t_case 'range-only npm advisory: ONE interval row, not zero (docs/FOUNDATION.md tension 25 npm-range amendment)'
: >"$W/db/advisories.db"
: >"$W/db/versions.db"
: >"$W/db/advisory-summaries.db"
: >"$W/db/version-summaries.db"
rc=0
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-RANGEONLY' run_ecosystem npm || rc=$?
assert_eq 0 "$rc" \
  'an advisory whose only npm-ecosystem "affected" entry carries no explicit versions[] array is not a failure - the run still exits 0'
assert_contains "$(cat "$DB")" \
  "$(printf 'npm\trange-only-fixture\t0\t2.0.0\tfixed\tSCOURSH-FIXTURE-OSV-NPM-RANGEONLY\thigh\t2.0.0')" \
  'a row IS written for it now - the fixture'"'"'s ranges[] entry (introduced 0, fixed 2.0.0) becomes a bound_kind=fixed interval row, closing exactly the gap the pre-amendment importer left (tension 25'"'"'s original RESOLUTION always intended range resolution; the shipped importer never implemented it for npm until this amendment)'
assert_contains "$(cat "$W/run-npm.out")" '-> 1 npm row' \
  'the row is logged as produced, not silently swallowed - contrast with the OTHER five ecosystems, which still log "produced no ... row" for a genuinely range-only advisory (unaffected by this amendment)'

t_case 'a TAB smuggled inside a fixed-version event is refused, never written (exit 5)'
rc=0
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-POISON' run_ecosystem npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  '_veng_advisories_reject_tab_lf catches the poisoned fixed_versions field end to end and refuses (exit 5) - fails under a reading that trusts OSV output verbatim'
assert_not_contains "$(cat "$DB")" 'poison-fixture' \
  'nothing from the poisoned advisory was written to data/advisories.db'

# ---------------------------------------------------------------------------
# -- section D2: the `banner` namespace (docs/VERSIONS-DB.md §3-§5;
#    docs/FOUNDATION.md tension 25's own "its own, separate banner-matching
#    product catalog" gap).  Deliberately NOT one of VENG_ADVISORY_REGISTRY's
#    six SCA ecosystems - see veng_advisories_banner's own header comment in
#    tools/vendor-engines.sh for why - so this is its own parallel story
#    rather than a seventh row in section D above.
# ---------------------------------------------------------------------------
run_banner() {
  # Same shape as run_ecosystem above, reached through its own `banner`
  # case in veng_advisories_main rather than veng_advisories_one.
  ( PATH="$FAKE_BIN:$PATH" \
    FAKE_OSV_FIXTURES_DIR="$FIXTURES" \
    SCOURSH_SCA_ADVISORIES_DB="$DB" \
    SCOURSH_SCA_VERSIONS_DB="$VDB" \
    SCOURSH_SCA_SUMMARIES_DB="$SDB" \
    SCOURSH_DAST_VERSION_SUMMARIES_DB="$VSDB" \
    bash "$TOOL" advisories banner ) >"$W/run-banner.out" 2>&1
}

t_case 'veng_advisories_banner is not one of VENG_ADVISORY_REGISTRY'"'"'s six entries'
assert_eq 6 "${#VENG_ADVISORY_REGISTRY[@]}" \
  'the registry still holds exactly six entries - adding banner support must never grow it'
rc=0
( veng_advisories_one banner ) >"$W/banner-not-registered.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "veng_advisories_one (the registry-dispatch path) refuses 'banner' - it is reached only through advisories_main's own explicit 'banner' case, never VENG_ADVISORY_REGISTRY"
assert_contains "$(cat "$W/banner-not-registered.out")" "unknown ecosystem 'banner'" \
  'the refusal names banner, proving it genuinely is not in the registry rather than silently matching by accident'

t_case '_veng_advisories_osv_ecosystem: banner is the "*" wildcard sentinel, never a real OSV ecosystem string'
assert_eq '*' "$(_veng_advisories_osv_ecosystem banner)" \
  'this is what tells the shared extractor (section 3) to skip the ecosystem filter entirely for banner'

t_case '_veng_advisories_env_var: banner mirrors the SCOURSH_ADVISORY_<NAME>_IDS shape'
assert_eq 'SCOURSH_ADVISORY_BANNER_IDS' "$(_veng_advisories_env_var banner)" \
  'the env var name follows the identical pattern every SCA ecosystem already uses'

t_case '_veng_advisories_normalize_severity: the banner-only "high" default (docs/VERSIONS-DB.md §3), never disturbing the SCA default'
assert_eq high "$(_veng_advisories_normalize_severity '' high)" \
  'an absent severity, with the banner default requested, lands on high'
assert_eq medium "$(_veng_advisories_normalize_severity '')" \
  'the SAME call with no default argument still lands on medium - adding a banner-only default must not change any SCA call site'
assert_eq critical "$(_veng_advisories_normalize_severity CRITICAL high)" \
  'a RECOGNISED severity is unaffected by the default argument either way'

t_case '_veng_advisories_normalize_name: banner dispatches to banner_normalize_product, never an sca_* function'
_veng_advisories_load_banner_normalizer
assert_eq 'nginx-fixture' "$(_veng_advisories_normalize_name banner 'Nginx-Fixture')" \
  'reuses banner_normalize_product (modules/dast/passive/banner_engine.sh) verbatim - the same function modules/dast/passive/banner.sh reads with'
assert_eq 'apache-http-server-fixture' "$(_veng_advisories_normalize_name banner 'Apache HTTP Server (Fixture)')" \
  'punctuation and whitespace all collapse to single dashes, matching docs/VERSIONS-DB.md §4'

t_case 'advisories banner, no operator-supplied ids: refuses (exit 4), never touches curl'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories banner 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'advisories banner with no ids set is exit 4 - curl is entirely absent from PATH'
assert_contains "$out" 'SCOURSH_ADVISORY_BANNER_IDS' \
  'the refusal names the exact env var, mirroring every SCA ecosystem refusal'

t_case 'advisories bulk banner: refused (exit 4) - banner has no OSV.dev bulk-export ecosystem, and no bulk path'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories bulk banner --accept-unverified 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "bulk stays scoped to VENG_ADVISORY_REGISTRY's six SCA ecosystems - 'banner' is refused there exactly like any other unknown ecosystem, never silently accepted"
assert_contains "$out" "unknown ecosystem 'banner'" 'the bulk refusal names banner directly'

t_case 'advisories --list / --all are unaffected by banner'
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories --list 2>&1)
assert_not_contains "$out" banner \
  '--list still reports only the six SCA ecosystems - banner is a separate command, never a seventh list entry, and so is never swept into --all or bulk --all either'

t_case 'end-to-end: banner - OSV-ecosystem wildcard match, product-key normalisation, dedup across ecosystems, missing-severity default, data/versions.db ONLY'
: >"$W/db/advisories.db"
: >"$W/db/versions.db"
# Both operator-supplied ids in ONE run, the same shape a real operator uses
# (SCOURSH_ADVISORY_BANNER_IDS names every id for this catalogue at once) -
# exactly like every SCA ecosystem end-to-end test above.  Running banner
# TWICE, once per id, would not accumulate: like every other ecosystem
# (proven below in section E), a second run REPLACES the whole 'banner'
# namespace rather than adding to it - that replace behaviour is its own
# test further down, not this one.
SCOURSH_ADVISORY_BANNER_IDS='SCOURSH-FIXTURE-OSV-BANNER-1,SCOURSH-FIXTURE-OSV-BANNER-NOSEV' run_banner
assert_eq '' "$(cat "$DB" 2>/dev/null || true)" \
  'data/advisories.db (scratch) was left completely untouched (still empty, from this test'"'"'s own reset above) - banner never writes there'
assert_file_exists "$VDB" 'data/versions.db (scratch) was written'
assert_contains "$(cat "$VDB")" \
  "$(printf 'banner\tnginx-fixture\t1.18.0\tSCOURSH-FIXTURE-OSV-BANNER-1\tcritical\t1.19.0')" \
  'the banner row lands under the literal "banner" ecosystem with the product key normalised (Nginx-Fixture -> nginx-fixture) - `summary` no longer inline (Change 2 applies to every namespace, not only the six SCA ecosystems)'
assert_contains "$(cat "$VSDB")" 'fixture: request smuggling in Nginx-Fixture' \
  'the banner advisory'"'"'s own summary lives in the version-summaries side table instead'
line_count=$(grep -c -F 'SCOURSH-FIXTURE-OSV-BANNER-1' "$VDB")
assert_eq 1 "$line_count" \
  'the fixture carries TWO affected[] entries (Debian, Alpine) for the identical product+version+fix - both are admitted by the wildcard, but the writer dedupes them into exactly ONE row, never two'
assert_contains "$(cat "$VDB")" \
  "$(printf 'banner\tapache-http-server-fixture\t2.4.49\tSCOURSH-FIXTURE-OSV-BANNER-NOSEV\thigh\t')" \
  'no severity anywhere in this second OSV record (no database_specific.severity, no per-affected override) - the banner-only default (high, docs/VERSIONS-DB.md §3) applies, distinct from every SCA row default (medium)'
assert_contains "$(cat "$VSDB")" 'fixture: unspecified-severity banner product issue' \
  'and its summary is in the side table too'

t_case 'merge: re-running banner replaces the WHOLE banner namespace (like any other ecosystem), and never disturbs an unrelated SCA ecosystem'
SCOURSH_ADVISORY_BANNER_IDS='SCOURSH-FIXTURE-OSV-BANNER-1' run_banner
after_replace=$(cat "$VDB")
assert_contains "$after_replace" 'nginx-fixture' 'the re-run'"'"'s own id is present'
assert_not_contains "$after_replace" 'apache-http-server-fixture' \
  "a second 'advisories banner' run REPLACES the banner namespace rather than accumulating - the same per-ecosystem semantics section E proves for npm - so the first run's other id is gone, not merged"
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' run_ecosystem npm
after_npm=$(cat "$VDB")
assert_contains "$after_npm" 'nginx-fixture' \
  'the banner row survives an unrelated npm run - _veng_advisories_write_db replaces only the ecosystem it was called with (npm), never touching banner rows'
assert_contains "$after_npm" 'left-pad-fixture' 'and the npm row landed as normal'
assert_not_contains "$(cat "$DB")" banner \
  'data/advisories.db (scratch) STILL carries no banner row even after other ecosystems have since written real rows to it - banner never reaches this file at all'

# ---------------------------------------------------------------------------
# -- section D3: the `alpine` namespace (IMG-03, data/scoursh-image-scan-
#    design/report.md §2.3/§4.1) - a SEVENTH advisory importer, but the
#    ONE whose own row carries a PREFIX-matched, per-row ecosystem key
#    rather than a fixed one, and the only one besides the six SCA
#    ecosystems that writes data/advisories.db at all (banner does not).
#    Deliberately NOT one of VENG_ADVISORY_REGISTRY's six entries either -
#    see veng_advisories_alpine's own header comment in
#    tools/vendor-engines.sh for why.
# ---------------------------------------------------------------------------
run_alpine() {
  # Same shape as run_banner above, reached through its own `alpine` case
  # in veng_advisories_main rather than veng_advisories_one.
  ( PATH="$FAKE_BIN:$PATH" \
    FAKE_OSV_FIXTURES_DIR="$FIXTURES" \
    SCOURSH_SCA_ADVISORIES_DB="$DB" \
    SCOURSH_SCA_VERSIONS_DB="$VDB" \
    SCOURSH_SCA_SUMMARIES_DB="$SDB" \
    SCOURSH_DAST_VERSION_SUMMARIES_DB="$VSDB" \
    bash "$TOOL" advisories alpine ) >"$W/run-alpine.out" 2>&1
}

t_case 'veng_advisories_alpine is not one of VENG_ADVISORY_REGISTRY'"'"'s six entries'
assert_eq 6 "${#VENG_ADVISORY_REGISTRY[@]}" \
  'the registry still holds exactly six entries - adding alpine support must never grow it'
rc=0
( veng_advisories_one alpine ) >"$W/alpine-not-registered.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "veng_advisories_one (the registry-dispatch path) refuses 'alpine' - it is reached only through advisories_main's own explicit 'alpine' case, never VENG_ADVISORY_REGISTRY"
assert_contains "$(cat "$W/alpine-not-registered.out")" "unknown ecosystem 'alpine'" \
  'the refusal names alpine, proving it genuinely is not in the registry rather than silently matching by accident'

t_case '_veng_advisories_osv_ecosystem: alpine is the "Alpine:*" PREFIX sentinel, never the bare "*" wildcard banner uses'
assert_eq 'Alpine:*' "$(_veng_advisories_osv_ecosystem alpine)" \
  'a distinct sentinel from banner own "*" - FAILS if alpine were wired to the bare wildcard, which would also admit a Debian- or RubyGems-tagged affected[] entry'

t_case '_veng_advisories_env_var: alpine mirrors the SCOURSH_ADVISORY_<NAME>_IDS shape'
assert_eq 'SCOURSH_ADVISORY_ALPINE_IDS' "$(_veng_advisories_env_var alpine)" \
  'the env var name follows the identical pattern every SCA ecosystem and banner already use'

t_case '_veng_advisories_normalize_name: alpine is a verbatim pass-through, never an sca_* function'
assert_eq 'openssl' "$(_veng_advisories_normalize_name alpine openssl)" \
  'apk package names carry no normalisation convention the way npm/PyPI/Composer names do (report.md §2.1)'
assert_eq 'Mixed-Case' "$(_veng_advisories_normalize_name alpine 'Mixed-Case')" \
  'and nothing is lower-cased or punctuation-collapsed either, unlike banner_normalize_product'

t_case 'advisories alpine, no operator-supplied ids: refuses (exit 4), never touches curl'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories alpine 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'advisories alpine with no ids set is exit 4 - curl is entirely absent from PATH'
assert_contains "$out" 'SCOURSH_ADVISORY_ALPINE_IDS' \
  'the refusal names the exact env var, mirroring every SCA ecosystem and banner refusal'

t_case 'advisories bulk alpine: refused (exit 4) - alpine is scoped to VENG_ADVISORY_REGISTRY'"'"'s six SCA ecosystems, and has no bulk path'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories bulk alpine --accept-unverified 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "bulk refuses 'alpine' exactly like any other unknown ecosystem, never silently accepted - IMG-03's own scope is single-advisory import only"
assert_contains "$out" "unknown ecosystem 'alpine'" 'the bulk refusal names alpine directly'

t_case 'advisories --list / --all are unaffected by alpine'
out=$(PATH=$NO_NET_PATH bash "$TOOL" advisories --list 2>&1)
assert_not_contains "$out" alpine \
  '--list still reports only the six SCA ecosystems - alpine is a separate command, never a seventh list entry, and so is never swept into --all or bulk --all either'

t_case 'end-to-end: alpine - ONE advisory spanning TWO Alpine releases writes TWO rows, and a same-package Debian entry is excluded'
: >"$W/db/advisories.db"
: >"$W/db/versions.db"
SCOURSH_ADVISORY_ALPINE_IDS='SCOURSH-FIXTURE-OSV-ALPINE-1' run_alpine
assert_file_exists "$DB" 'data/advisories.db (scratch) was written - UNLIKE banner, alpine writes here (report.md §2.3: this IS the exact-row shape modules/image/ reads)'
DB_AFTER_1=$(cat "$DB")
assert_contains "$DB_AFTER_1" \
  "$(printf 'Alpine:v3.18\topenssl\t3.1.4-r1\tSCOURSH-FIXTURE-OSV-ALPINE-1\thigh\t3.1.4-r2')" \
  'the Alpine:v3.18 row, in the EXISTING exact-row shape the brief names (ecosystem/package/version/advisory_id/severity/fixed_versions) - FAILS if the row carried a seventh, un-frozen field, or if the release-specific fixed version were dropped'
assert_contains "$DB_AFTER_1" \
  "$(printf 'Alpine:v3.19\topenssl\t3.1.4-r0\tSCOURSH-FIXTURE-OSV-ALPINE-1\thigh\t3.1.5-r0')" \
  'the SAME advisory ALSO wrote an Alpine:v3.19 row, with its OWN fixed version (3.1.5-r0, not v3.18'"'"'s 3.1.4-r2) - FAILS under any reading that keeps only the first affected[] entry it sees, or that collapses two releases onto one row'
assert_not_contains "$DB_AFTER_1" 'Debian' \
  'the Debian-tagged affected[] entry for the SAME package produced no row at all - FAILS if "Alpine:*" were wired to the bare "*" wildcard instead of a real Alpine: prefix match'
line_count=$(grep -c -F 'SCOURSH-FIXTURE-OSV-ALPINE-1' "$DB")
assert_eq 2 "$line_count" \
  'exactly two rows for this advisory (v3.18 and v3.19), never three - the Debian entry contributed none'
assert_eq "$(grep -v '^#' <<<"$DB_AFTER_1")" "$(grep -v '^#' "$VDB")" \
  'data/versions.db carries the byte-identical DATA rows (the two files'"'"' own `#` header lines legitimately differ - each names its own basename) - tension 25/VERSIONS-DB.md §2'"'"'s "same shape, same rule" reuse applies to alpine too, unlike banner'
assert_contains "$(cat "$VSDB")" 'fixture: openssl heap overflow' \
  'the summary lives in the version-summaries side table, mirroring every other namespace'
assert_contains "$(cat "$SDB")" 'fixture: openssl heap overflow' \
  'and in the advisory-summaries side table too, since alpine (unlike banner) writes data/advisories.db'

t_case 'both directions of the exit-4 gate this ticket adds are pinned against a real image_ecosystem_known-shaped lookup'
rc=0
db_lookup_exact "$(printf 'Alpine:v3.18\t')" "$DB" >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" \
  'Alpine:v3.18 IS covered after the run above - the gate must NOT fire for this release (fires-when-present half)'
rc=0
db_lookup_exact "$(printf 'Alpine:v3.20\t')" "$DB" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" \
  'Alpine:v3.20 has no row at all - the gate MUST fire for an unvendored release (fires-when-absent half) - modules/image/engine.sh'"'"'s image_ecosystem_known is this exact db_lookup_exact prefix test'

t_case 'merge: re-running alpine replaces the WHOLE Alpine: namespace across EVERY release, and never disturbs an unrelated SCA ecosystem'
SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' run_ecosystem npm
SCOURSH_ADVISORY_ALPINE_IDS='SCOURSH-FIXTURE-OSV-ALPINE-2' run_alpine
after_replace=$(cat "$DB")
assert_contains "$after_replace" 'busybox' "alpine-2's own package is present"
assert_not_contains "$after_replace" 'openssl' \
  "a second 'advisories alpine' run REPLACES the WHOLE Alpine: namespace rather than accumulating - so BOTH of the first run's rows (v3.18 AND v3.19) are gone, not merged, even though this run only named v3.18"
assert_not_contains "$after_replace" 'Alpine:v3.19' \
  'specifically: the v3.19 row from the FIRST run is gone even though the SECOND run never touched v3.19 at all - proving the replace-scope is the whole Alpine: PREFIX, not the one release the new rows happen to name'
assert_contains "$after_replace" 'left-pad-fixture' \
  "the npm row written BEFORE this alpine run survives untouched - _veng_advisories_write_db_prefix's own prefix filter leaves every non-'Alpine:' row alone"
assert_contains "$(cat "$VDB")" 'busybox' 'data/versions.db was replaced the same way'
assert_not_contains "$(cat "$VDB")" 'openssl' 'and also lost the stale v3.18/v3.19 openssl rows'

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

# ===========================================================================
# BULK IMPORT (tools/vendor-engines.sh advisories bulk)
# ===========================================================================
# The single-advisory path above resolves ONE operator-supplied OSV id at a
# time, which cannot populate a useful database: knowing which advisory ids
# to fetch is the thing a dependency scanner is supposed to TELL the
# operator.  The `bulk` sub-namespace imports a whole ecosystem's published
# OSV export in one command.
#
# Every assertion below is offline.  Two shapes are exercised:
#
#  - `--archive PATH`, which reaches no network code at all (curl is absent
#    from PATH for those cases, so a false pass would be a network attempt,
#    not a real import), against an archive this suite builds at test time
#    from the hand-authored, OSV-shaped fixtures under
#    tests/fixtures/vendor-engines/osv-bulk/ with python3's own zipfile
#    module.
#  - the network path, against a STUBBED curl serving that same archive -
#    the identical posture section D already uses for the single-advisory
#    fetch.
#
# The archive is BUILT rather than committed as a binary so every byte of
# the fixture data stays reviewable as text, and so the deliberately broken
# archives (truncated, bad member, poisoned member) are visibly derived from
# the good one rather than being opaque blobs.
# ---------------------------------------------------------------------------

BULK_FIXTURES=$ROOT/tests/fixtures/vendor-engines/osv-bulk
BULK_BAD=$ROOT/tests/fixtures/vendor-engines/osv-bulk-bad
BULK_W=$W/bulk
mkdir -p "$BULK_W/zips"

# bulk_make_zip OUTZIP SRCDIR [EXTRA_FILE...] - builds an all.zip-shaped
# archive (flat members, one JSON per advisory) with python3's zipfile.
bulk_make_zip() {
  local out=$1 src=$2
  shift 2
  python3 - "$out" "$src" "$@" <<'PY'
import os
import sys
import zipfile

out, src = sys.argv[1], sys.argv[2]
extra = sys.argv[3:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name in sorted(os.listdir(src)):
        if name.endswith(".json"):
            z.write(os.path.join(src, name), name)
    for path in extra:
        z.write(path, os.path.basename(path))
PY
}

bulk_make_zip "$BULK_W/zips/npm.zip" "$BULK_FIXTURES/npm"
bulk_make_zip "$BULK_W/zips/PyPI.zip" "$BULK_FIXTURES/PyPI"
bulk_make_zip "$BULK_W/zips/Maven.zip" "$BULK_FIXTURES/Maven"
bulk_make_zip "$BULK_W/zips/Go.zip" "$BULK_FIXTURES/Go"
bulk_make_zip "$BULK_W/zips/RubyGems.zip" "$BULK_FIXTURES/RubyGems"
bulk_make_zip "$BULK_W/zips/Packagist.zip" "$BULK_FIXTURES/Packagist"
bulk_make_zip "$BULK_W/zips/npm-malformed.zip" "$BULK_FIXTURES/npm" "$BULK_BAD/malformed-json.json"
bulk_make_zip "$BULK_W/zips/npm-poison.zip" "$BULK_FIXTURES/npm" "$BULK_BAD/poison-tab.json"

# An archive whose ONLY member is the range-only advisory: structurally
# perfect, and it yields zero exact-version rows.
mkdir -p "$BULK_W/only-rangeonly"
cp -- "$BULK_FIXTURES/npm/SCOURSH-FIXTURE-OSV-BULK-NPM-3.json" "$BULK_W/only-rangeonly/"
bulk_make_zip "$BULK_W/zips/npm-zero-rows.zip" "$BULK_W/only-rangeonly"

# A truncated download: the central directory lives at the END of a zip, so
# chopping the tail is exactly what a silently-truncated transfer produces.
python3 - "$BULK_W/zips/npm.zip" "$BULK_W/zips/npm-truncated.zip" <<'PY'
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as fh:
    data = fh.read()
with open(dst, "wb") as fh:
    fh.write(data[: len(data) // 2])
PY
printf 'not a zip at all\n' >"$BULK_W/zips/not-a-zip.zip"

NPM_ZIP=$BULK_W/zips/npm.zip
NPM_ZIP_SHA=$(sha256_of <"$NPM_ZIP")
BAD_SHA='0000000000000000000000000000000000000000000000000000000000000000'

BDB=$BULK_W/advisories.db
BVDB=$BULK_W/versions.db
# docs/FOUNDATION.md tension 25's summary-normalisation amendment - the bulk
# section's own scratch summary side tables, mirroring BDB/BVDB, for the
# identical reason SDB/VSDB exist above (without an explicit override these
# fall back to the REAL $VENG_DIR/data/*-summaries.db paths).
BSDB=$BULK_W/advisory-summaries.db
BVSDB=$BULK_W/version-summaries.db
bulk_reset_db() {
  rm -f "$BDB" "$BVDB" "$BSDB" "$BVSDB"
}

# bulk_run [ARGS...] - one real subprocess of the bulk importer with curl
# ENTIRELY ABSENT from PATH, writing to this suite's own scratch db paths.
# Output lands in $BULK_W/last.out; the exit status is returned.
bulk_run() {
  local rc=0
  ( PATH="$NO_NET_PATH" \
    SCOURSH_SCA_ADVISORIES_DB="$BDB" \
    SCOURSH_SCA_VERSIONS_DB="$BVDB" \
    SCOURSH_SCA_SUMMARIES_DB="$BSDB" \
    SCOURSH_DAST_VERSION_SUMMARIES_DB="$BVSDB" \
    bash "$TOOL" advisories bulk "$@" ) >"$BULK_W/last.out" 2>&1 || rc=$?
  return "$rc"
}

# bulk_run_net [ARGS...] - the same, but with a STUBBED curl on PATH that
# serves the built fixture archives instead of reaching the network.
bulk_run_net() {
  local rc=0
  ( PATH="$FAKE_BULK_BIN:$NO_NET_PATH" \
    FAKE_BULK_ZIP_DIR="$BULK_W/zips" \
    SCOURSH_SCA_ADVISORIES_DB="$BDB" \
    SCOURSH_SCA_VERSIONS_DB="$BVDB" \
    SCOURSH_SCA_SUMMARIES_DB="$BSDB" \
    SCOURSH_DAST_VERSION_SUMMARIES_DB="$BVSDB" \
    bash "$TOOL" advisories bulk "$@" ) >"$BULK_W/last.out" 2>&1 || rc=$?
  return "$rc"
}

FAKE_BULK_BIN=$BULK_W/fake-bin
mkdir -p "$FAKE_BULK_BIN"
cat >"$FAKE_BULK_BIN/curl" <<'FAKEBULKCURL'
#!/usr/bin/env bash
# Test double for curl (tests/suites/vendor-engines-advisories.sh, bulk
# sections only) - never a real network call.  Serves
# .../<ECOSYSTEM>/all.zip out of FAKE_BULK_ZIP_DIR/<ECOSYSTEM>.zip.
set -Eeuo pipefail
out='' url=''
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  case ${args[i]} in
    --output) out=${args[$(( i + 1 ))]} ;;
    http*) url=${args[i]} ;;
  esac
  i=$(( i + 1 ))
done
if [[ -n ${FAKE_CURL_FAIL:-} ]]; then
  printf 'fake curl: simulated failure\n' >&2
  exit 22
fi
rest=${url%/all.zip}
eco=${rest##*/}
src="${FAKE_BULK_ZIP_DIR:?}/$eco.zip"
if [[ ! -f $src ]]; then
  printf 'fake curl: no fixture archive for %s\n' "$eco" >&2
  exit 22
fi
cp -- "$src" "$out"
FAKEBULKCURL
chmod +x "$FAKE_BULK_BIN/curl"

# ---------------------------------------------------------------------------
# -- section F: the bulk command surface and its integrity gate.  curl is
#    absent from PATH for every case here, so a pass proves the refusal
#    happened BEFORE any network attempt rather than instead of one --
# ---------------------------------------------------------------------------
t_case 'advisories bulk --help'
rc=0
bulk_run --help || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'advisories bulk --help exits 0'
assert_contains "$out" 'usage: tools/vendor-engines.sh advisories bulk' \
  'bulk --help prints its OWN usage banner, not the advisories one or the top-level one'
assert_contains "$out" '--accept-unverified' \
  'the usage text names the explicit acknowledgement an unpinned bulk import requires'
assert_contains "$out" '--sha256' 'the usage text names the pinning option'
assert_contains "$out" '--archive' 'the usage text names the local-archive option'

t_case 'advisories bulk with no ecosystem is a usage error (exit 2)'
rc=0
bulk_run || rc=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$rc" "'advisories bulk' alone names no ecosystem and is exit 2"

t_case 'advisories bulk --bogus is a usage error (exit 2)'
rc=0
bulk_run --bogus npm || rc=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$rc" 'an unrecognised bulk flag is exit 2'

t_case 'advisories bulk <ecosystem> UNPINNED, without the explicit acknowledgement: refuses (exit 4)'
rc=0
bulk_run npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'an unpinned bulk import refuses by default - fails under the reading that silently drops the integrity requirement to make bulk work'
assert_contains "$out" 'refusing an unverified bulk import' 'the refusal says what it is refusing and why'
assert_contains "$out" '--sha256' 'the refusal names the pinning option the operator can use instead'
assert_contains "$out" '--accept-unverified' 'the refusal names the explicit acknowledgement that unblocks it'
assert_file_absent "$BDB" 'nothing was written: the refusal happens before any fetch or any db write'

t_case 'a pinned bulk import needs no acknowledgement, and an acknowledged one needs no pin'
# Both are proven for real further down (sections G and I); here only the
# ARGUMENT gate is exercised.  curl is absent from PATH, so both of these
# still fail - the point is that they fail on the MISSING TOOL rather than
# on the integrity gate, which the distinct refusal wording discriminates.
rc=0
bulk_run --sha256 "$BAD_SHA" npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_not_contains "$out" 'refusing an unverified bulk import' \
  '--sha256 alone satisfies the integrity gate: this run gets past it and fails later, on the absent curl'
assert_contains "$out" 'missing required command' 'and that later failure is the missing fetch tool, proving the gate was passed rather than skipped'
rc=0
bulk_run --accept-unverified npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_not_contains "$out" 'refusing an unverified bulk import' \
  '--accept-unverified alone satisfies the integrity gate the same way'
assert_contains "$out" 'missing required command' 'and reaches the same later failure'

t_case 'advisories bulk: unknown ecosystem refuses (exit 4)'
rc=0
bulk_run --accept-unverified not-a-real-ecosystem || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'an unknown ecosystem is exit 4 in the bulk namespace too'
assert_contains "$(cat "$BULK_W/last.out")" 'not-a-real-ecosystem' 'the refusal names the ecosystem requested'

t_case 'advisories bulk: a registered ENGINE name is still not an ecosystem'
rc=0
bulk_run --accept-unverified semgrep || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  "'semgrep' is a VENG_REGISTRY engine, never an ecosystem - the bulk namespace keeps the two registries separate exactly as the single-advisory namespace does"

t_case 'advisories bulk --all --archive is refused (exit 2): one archive is one ecosystem'
rc=0
bulk_run --all --archive "$NPM_ZIP" --accept-unverified || rc=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$rc" \
  'a single local archive cannot supply six ecosystems, so the combination is refused rather than silently importing one ecosystem six times'

t_case 'advisories bulk --all --sha256 is refused (exit 2): one digest cannot pin six artifacts'
rc=0
bulk_run --all --sha256 "$NPM_ZIP_SHA" || rc=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$rc" \
  'a single digest cannot pin six separate artifacts, so the combination is refused rather than verifying one and trusting five'

t_case 'advisories bulk --archive with a missing file refuses (exit 4), writes nothing'
rc=0
bulk_run --archive "$BULK_W/zips/does-not-exist.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'an unreadable archive path is exit 4'
assert_file_absent "$BDB" 'no db was created by a refused import'

t_case 'advisories bulk: a flag missing its value is a usage error (exit 2)'
for bad in '--sha256' '--archive'; do
  rc=0
  bulk_run "$bad" || rc=$?
  assert_eq "$SCOURSH_EXIT_USAGE" "$rc" "$bad with no value is exit 2 rather than consuming the next argument silently"
done

t_case 'bulk exit codes never leave 0-5 (tension 14, finding F16)'
for args in 'bulk' 'bulk --help' 'bulk npm' 'bulk --bogus' 'bulk --all' \
  'bulk --accept-unverified nonexistent-eco' 'bulk --archive /nope --accept-unverified npm'; do
  rc=0
  # shellcheck disable=SC2086
  ( PATH=$NO_NET_PATH SCOURSH_SCA_ADVISORIES_DB="$BDB" SCOURSH_SCA_VERSIONS_DB="$BVDB" \
    SCOURSH_SCA_SUMMARIES_DB="$BSDB" SCOURSH_DAST_VERSION_SUMMARIES_DB="$BVSDB" \
    bash "$TOOL" advisories $args ) >/dev/null 2>&1 || rc=$?
  if (( rc >= 0 && rc <= 5 )); then
    _t_ok "exit code for 'advisories $args' is $rc, within 0-5"
  else
    _t_no "exit code for 'advisories $args' is $rc, OUTSIDE 0-5" "args: [$args]"
  fi
done

# ---------------------------------------------------------------------------
# -- section G: a real end-to-end bulk import from a local archive, with NO
#    network code reachable at all (curl absent from PATH) --
# ---------------------------------------------------------------------------
t_case 'bulk import from a local archive: rows written, integrity grade stated'
bulk_reset_db
rc=0
bulk_run --archive "$NPM_ZIP" --accept-unverified npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'an acknowledged local-archive import of npm exits 0'
assert_file_exists "$BDB" 'the database was written'
assert_contains "$out" 'integrity: unpinned-local-archive' \
  'the run states plainly which integrity grade it achieved, rather than leaving the operator to guess'
assert_contains "$out" "artifact sha256: $NPM_ZIP_SHA" \
  'the digest of what WAS imported is computed and reported even when nothing pinned it, so a later operator can tell exactly what they got'
assert_contains "$out" 'content was NOT verified' \
  'the unpinned grade says out loud what it does not guarantee'

t_case 'bulk import: every enumerated affected version becomes one exact-kind row (docs/FOUNDATION.md tension 25 npm-range amendment)'
db=$(cat "$BDB")
assert_contains "$db" "$(printf 'npm\tbulk-fixture-alpha\t1.0.0\t\texact\tSCOURSH-FIXTURE-OSV-BULK-NPM-1\thigh\t1.1.0')" \
  'the frozen npm-range schema (ecosystem, package, introduced, bound, bound_kind, advisory_id, severity, fixed_versions) is written verbatim, severity normalised HIGH -> high, bound empty and bound_kind=exact for an OSV-enumerated version - `summary` no longer lives in this row at all (Change 2)'
assert_contains "$db" "$(printf 'npm\tbulk-fixture-alpha\t1.0.1\t\texact\tSCOURSH-FIXTURE-OSV-BULK-NPM-1')" \
  'the second enumerated version of the same advisory gets its own exact-kind row (pre-expansion, tension 25)'
assert_contains "$db" "$(printf 'npm\t@bulk-scope/beta\t2.0.0\t\texact\tSCOURSH-FIXTURE-OSV-BULK-NPM-2\tcritical')" \
  'a scoped npm name is carried verbatim, scope included (tension 25 frozen table)'
assert_contains "$db" "$(printf 'npm\tbulk-fixture-gamma\t3.0.0\t\texact\tSCOURSH-FIXTURE-OSV-BULK-NPM-4\tmedium')" \
  'an advisory with no severity at all defaults to medium rather than being dropped'
assert_contains "$(cat "$BSDB")" 'fixture: bulk-fixture-gamma leaks a token in its debug log.' \
  'the summary falls back to the first line of the details field when no summary field exists - and now lives in the advisory-keyed side table (Change 2), not inline in advisories.db'
assert_not_contains "$(cat "$BSDB")" 'A second line the summary fallback must not carry' \
  'only the FIRST line of details is used - a multi-line summary would be an LF inside a frozen-schema field'
assert_not_contains "$db" 'fixture:' \
  'no summary text of any kind leaked into data/advisories.db itself'

t_case 'bulk import (docs/FOUNDATION.md tension 25 npm-range amendment): a range-only advisory becomes ONE interval row, never skipped for npm'
assert_contains "$(cat "$BDB")" "$(printf 'npm\tbulk-fixture-rangeonly\t1.0.0\t1.4.0\tfixed\tSCOURSH-FIXTURE-OSV-BULK-NPM-3\thigh\t1.4.0')" \
  'the range-only advisory - no versions[] array published - is represented as a semver interval row instead of being dropped; this is the whole point of the amendment: closing the gap tension 25'"'"'s own resolution intended but the shipped importer never implemented'
assert_contains "$(cat "$BULK_W/last.out")" 'range_only_skipped=0' \
  'nothing is skipped for npm any more - contrast with every other ecosystem, which still counts and skips a range-only entry (section G'"'"'s pypi/maven/Go/RubyGems/composer cases elsewhere in this file are unaffected)'
assert_contains "$(cat "$BULK_W/last.out")" 'rows_range=5' \
  'five range rows total: one per advisory (NPM-1..5), each contributing exactly one ranges[] interval'

t_case 'bulk import: a decoy affected entry for another ecosystem is skipped and counted'
assert_not_contains "$(cat "$BDB")" 'bulk-decoy-should-not-appear' \
  "the PyPI 'affected' entry inside an npm-ecosystem import is not emitted as an npm row"
assert_contains "$(cat "$BULK_W/last.out")" 'other_ecosystem_skipped=1' \
  'the cross-ecosystem skip is counted too rather than being invisible'

t_case 'bulk import: the run reports what it actually imported'
out=$(cat "$BULK_W/last.out")
assert_contains "$out" 'advisories_read=5' 'every member of the archive is accounted for'
assert_contains "$out" 'rows=12' \
  '7 exact-kind rows (2+2+0+2+1, unchanged from before this amendment) plus 5 range rows (one ranges[] interval per advisory) = 12'
body=$(LC_ALL=C sed -e '/^#/d' -e '/^$/d' "$BDB")
assert_eq 12 "$(printf '%s\n' "$body" | wc -l | tr -d ' ')" \
  'the row count in the file matches the count the run reported - a reported number that the file does not back is exactly the silent-coverage-gap shape'

t_case 'bulk import: the database records its own provenance'
hdr=$(LC_ALL=C sed -n '/^#/p' "$BDB")
assert_contains "$hdr" 'ecosystem=npm' 'the provenance line names the ecosystem it covers'
assert_contains "$hdr" 'grade=unpinned-local-archive' 'it records the integrity grade that produced these rows'
assert_contains "$hdr" "sha256=$NPM_ZIP_SHA" 'it records the digest of the artifact those rows came from'
assert_contains "$hdr" 'rows=12' 'it records the row count'
assert_contains "$hdr" 'range_only_skipped=0' 'it records the (now zero, for npm) skip count'

t_case 'bulk import: versions.db is written with the identical body (tension 25)'
assert_file_exists "$BVDB" 'data/versions.db (scratch) was written too'
assert_eq "$(LC_ALL=C sed -e '/^#/d' "$BDB")" "$(LC_ALL=C sed -e '/^#/d' "$BVDB")" \
  'the two files carry byte-identical data rows, the same "same shape and same rule" the single-advisory path already honours'

t_case 'bulk import: a pinned artifact is verified, and states so'
bulk_reset_db
rc=0
bulk_run --archive "$NPM_ZIP" --sha256 "$NPM_ZIP_SHA" npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'a correctly pinned local archive imports with no acknowledgement flag at all'
assert_contains "$out" 'integrity: pinned-sha256' 'the run reports the strongest grade it actually achieved'
assert_contains "$(cat "$BDB")" 'bulk-fixture-alpha' 'the pinned path imports the same rows as the unpinned one'

t_case 'bulk import: a WRONG pin refuses (exit 5) and leaves the existing database untouched'
before=$(cat "$BDB")
rc=0
bulk_run --archive "$NPM_ZIP" --sha256 "$BAD_SHA" npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'a digest mismatch is exit 5 - fails under a reading that warns and imports anyway'
assert_contains "$(cat "$BULK_W/last.out")" "$BAD_SHA" 'the refusal names the expected digest'
assert_eq "$before" "$(cat "$BDB")" \
  'the database is byte-identical to what it was before the refused import - the write is transactional, so a refusal never half-replaces an ecosystem'

t_case 'bulk import: a TRUNCATED archive refuses (exit 5), database untouched'
before=$(cat "$BDB")
rc=0
bulk_run --archive "$BULK_W/zips/npm-truncated.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  "a silently-truncated download is refused: a zip's central directory lives at its end, so a short read cannot open at all - fails under a reading that imports whatever members it managed to read"
assert_eq "$before" "$(cat "$BDB")" 'the database is unchanged by the refused import'

t_case 'bulk import: a file that is not an archive at all refuses (exit 5)'
rc=0
bulk_run --archive "$BULK_W/zips/not-a-zip.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" 'a non-archive artifact (an error page, a redirect body) is refused rather than parsed as zero advisories'

t_case 'bulk import: ONE malformed member fails the WHOLE ecosystem, rather than importing the rest'
before=$(cat "$BDB")
rc=0
bulk_run --archive "$BULK_W/zips/npm-malformed.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'a member that does not parse is exit 5 - fails under the reading that skips it and reports the remaining rows as a complete ecosystem, which is the silent-partial-coverage shape this repository has shipped before'
assert_eq "$before" "$(cat "$BDB")" 'and the previously good database is left exactly as it was'
assert_contains "$(cat "$BULK_W/last.out")" 'malformed-json.json' 'the refusal names the member that failed'

t_case 'bulk import: a TAB smuggled into a member is refused (exit 5), nothing written'
before=$(cat "$BDB")
rc=0
bulk_run --archive "$BULK_W/zips/npm-poison.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'the frozen schema forbids a TAB inside any field, and OSV text is untrusted target-adjacent content - fails under a reading that trusts the upstream export verbatim'
assert_eq "$before" "$(cat "$BDB")" 'the database is unchanged'
assert_not_contains "$(cat "$BDB")" 'bulk-fixture-poison' 'no row from the poisoned member reached the database'

t_case 'bulk import (docs/FOUNDATION.md tension 25 npm-range amendment): the same "range-only" archive that used to yield zero rows now yields ONE, for npm'
rc=0
bulk_run --archive "$BULK_W/zips/npm-zero-rows.zip" --accept-unverified npm || rc=$?
assert_eq 0 "$rc" \
  'the amendment'"'"'s whole point: an archive whose only member is a range-only advisory (SCOURSH-FIXTURE-OSV-BULK-NPM-3, no versions[]) used to produce zero rows and refuse - it now produces one interval row and succeeds, for npm only'
assert_contains "$(cat "$BDB")" 'bulk-fixture-rangeonly' 'the range row is present'

t_case 'bulk import: a structurally perfect archive that yields ZERO rows is STILL refused (exit 5) for an ecosystem the amendment does not touch'
# Runs the SAME archive - it names only an npm-ecosystem affected entry - as
# a PYPI import instead: every entry is skipped as "other ecosystem", so this
# exercises the zero-rows refusal path on a code path this ticket left
# completely unchanged (pypi/maven/Go/RubyGems/composer all still skip a
# range-only OR wrong-ecosystem entry and refuse on zero rows).
bulk_reset_db
before=$(cat "$BDB" 2>/dev/null || true)
rc=0
bulk_run --archive "$BULK_W/zips/npm-zero-rows.zip" --accept-unverified pypi || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'an import that produces no rows refuses rather than replacing the ecosystem rows with nothing - fails under the reading that treats an empty result as a successful import, which would quietly turn every dependency in that ecosystem clean'
assert_eq "$before" "$(cat "$BDB" 2>/dev/null || true)" 'and the previous (absent) rows survive untouched'
assert_contains "$(cat "$BULK_W/last.out")" 'ZERO' 'the refusal says exactly what was wrong'

t_case 'bulk import: re-importing one ecosystem replaces only its own rows and its own provenance'
bulk_reset_db
bulk_run --archive "$BULK_W/zips/PyPI.zip" --accept-unverified pypi
bulk_run --archive "$NPM_ZIP" --accept-unverified npm
both=$(cat "$BDB")
assert_contains "$both" 'bulk-fixture-django' 'the pypi rows are present (PEP 503 normalised)'
assert_contains "$both" 'bulk-fixture-alpha' 'the npm rows are present'
assert_eq 2 "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB" | wc -l | tr -d ' ')" \
  'two provenance lines, one per imported ecosystem - the header states per-ecosystem coverage rather than one global claim'
bulk_run --archive "$BULK_W/zips/Go.zip" --accept-unverified Go
after=$(cat "$BDB")
assert_contains "$after" 'bulk-fixture-django' 'a third ecosystem import leaves pypi alone'
assert_contains "$after" 'bulk-fixture-alpha' 'and leaves npm alone'
assert_eq 3 "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB" | wc -l | tr -d ' ')" 'three provenance lines now'

t_case 'a single-advisory import of an ecosystem RETIRES that ecosystem bulk provenance claim'
( PATH="$FAKE_BIN:$NO_NET_PATH" FAKE_OSV_FIXTURES_DIR="$FIXTURES" \
  SCOURSH_ADVISORY_NPM_IDS='SCOURSH-FIXTURE-OSV-NPM-1' \
  SCOURSH_SCA_ADVISORIES_DB="$BDB" SCOURSH_SCA_VERSIONS_DB="$BVDB" \
  SCOURSH_SCA_SUMMARIES_DB="$BSDB" SCOURSH_DAST_VERSION_SUMMARIES_DB="$BVSDB" \
  bash "$TOOL" advisories npm ) >"$BULK_W/retire.out" 2>&1
assert_not_contains "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB")" 'ecosystem=npm' \
  'replacing npm rows with a one-advisory import drops the stale "this ecosystem was bulk imported" claim - fails under a reading that leaves the old provenance line describing rows that no longer exist'
assert_contains "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB")" 'ecosystem=pypi' \
  'the other ecosystems keep theirs'

# ---------------------------------------------------------------------------
# -- section H: the sort order, proven through the READER's own code path --
# ---------------------------------------------------------------------------
t_case 'bulk import: the body is LC_ALL=C sorted, in the order only LC_ALL=C produces'
bulk_reset_db
bulk_run --archive "$NPM_ZIP" --accept-unverified npm
body=$(LC_ALL=C sed -e '/^#/d' -e '/^$/d' "$BDB")
assert_eq "$(LC_ALL=C sort <<<"$body")" "$body" 'the body is already in LC_ALL=C order'
first_pkg=$(printf '%s\n' "$body" | LC_ALL=C sed -n '1p' | cut -f 2)
assert_eq '@bulk-scope/beta' "$first_pkg" \
  "'@bulk-scope/beta' sorts FIRST because '@' is 0x40 and 'b' is 0x62 - it fails under any punctuation-folding collation, which would sort it as 'bulkscopebeta' and put it last, and under that ordering db_lookup_exact's binary search misses rows that are really in the file"

t_case 'the reader finds every written row through sca_lookup_range itself, not by inspection (docs/FOUNDATION.md tension 25 npm-range amendment)'
# Proving the sort by eyeballing the file is exactly the mistake tension 25
# warns about: the thing that matters is whether the READER's own lookup
# finds the row. This DB is npm-only (bulk_reset_db + a single npm import
# above), so every row is a range row now - sca_lookup_range
# (modules/sca/engine.sh), routing through lib/core.sh's db_lookup_prefix,
# replaces sca_lookup_exact for this section entirely.
#
# The probe version used for each row is that row's OWN `introduced` field
# (the third TAB column) - for a bound_kind=exact row this is a trivial
# byte match; for a bound_kind=fixed row, semver_in_range_v's own intro
# check is `[[ -n $intro && $intro != 0 ]]`, so introduced="0" skips the
# lower bound entirely and introduced=X compares X to X (equal, passes),
# and every fixture range'"'"'s bound is strictly above its own introduced -
# so a row probed with its own introduced value always matches ITSELF,
# regardless of kind. This is what makes "does the reader find every row"
# checkable without hand-computing which OTHER rows a given probe version
# might also match (several probes below deliberately DO match more than
# one row - see the "two advisories" case).
_veng_advisories_load_normalizers
missed=0
while IFS=$'\t' read -r eco pkg intro _rest; do
  [[ -n $eco ]] || continue
  if ! sca_lookup_range "$pkg" "$intro" "$BDB" >/dev/null; then
    missed=$(( missed + 1 ))
    printf '    MISSED: %s %s %s\n' "$eco" "$pkg" "$intro" >&2
  fi
done <<<"$body"
assert_eq 0 "$missed" \
  'every one of the 12 generated rows (7 exact-kind + 5 range) is found by the reader own lookup primitive, probed with its own introduced value - a wrong sort order makes look silently miss rows that are visibly present in the file'

t_case 'the reader finds every row under BOTH lookup backends (look and the grep fallback)'
missed=0
# SC2030/SC2031: forcing SCOURSH_CAP_LOOK inside a subshell is the point of
# this case (it drives db_lookup_prefix down its grep -F fallback, which -
# unlike db_lookup_exact's own -m 1 fallback - must return every matching
# row, per db_lookup_prefix's own header), and it must NOT leak back into
# the surrounding suite, which goes on to exercise the look path on the
# same file.
# shellcheck disable=SC2030
while IFS=$'\t' read -r eco pkg intro _rest; do
  [[ -n $eco ]] || continue
  if ! ( SCOURSH_CAP_LOOK=none; sca_lookup_range "$pkg" "$intro" "$BDB" >/dev/null ); then
    missed=$(( missed + 1 ))
  fi
done <<<"$body"
assert_eq 0 "$missed" \
  "the grep -F fallback path (no -m 1) finds them too, so a host without look reads the same database"

t_case 'a version outside every fixture interval for the package is NOT found'
rc=0
sca_lookup_range bulk-fixture-alpha 9.9.9 "$BDB" >/dev/null || rc=$?
assert_ne 0 "$rc" 'an unwritten version, above every fixture range and unequal to every exact row, misses - so a passing lookup above is evidence rather than a lookup that matches everything'
rc=0
sca_lookup_range bulk-fixture-rangeonly 9.9.9 "$BDB" >/dev/null || rc=$?
assert_ne 0 "$rc" 'and a version above the range-only advisory'"'"'s own [1.0.0,1.4.0) interval misses too'

t_case 'a version INSIDE the range-only advisory'"'"'s interval IS found, even though OSV never enumerated it explicitly'
IN_RANGE_HIT=$(sca_lookup_range bulk-fixture-rangeonly 1.2.0 "$BDB")
assert_contains "$IN_RANGE_HIT" 'SCOURSH-FIXTURE-OSV-BULK-NPM-3' \
  '1.2.0 was never an explicit OSV versions[] entry for this advisory - it is only representable because the amendment stores the interval [1.0.0,1.4.0) rather than dropping it (the pre-amendment behaviour this whole ticket exists to fix)'

t_case 'two advisories for one package@version both come back through the reader (look only)'
# shellcheck disable=SC2031
if [[ ${SCOURSH_CAP_LOOK:-none} == look ]]; then
  HITS_1_0_1=$(sca_lookup_range bulk-fixture-alpha 1.0.1 "$BDB")
  DISTINCT_ADV=$(printf '%s\n' "$HITS_1_0_1" | cut -f1 | LC_ALL=C sort -u | wc -l | tr -d ' ')
  assert_eq 2 "$DISTINCT_ADV" \
    'NPM-1 and NPM-5 both name bulk-fixture-alpha 1.0.1 (NPM-1 as an explicit exact-kind row AND inside its own [0,1.1.0) range; NPM-5 as an exact-kind row AND inside its own [1.0.1,1.2.0) range) - both advisory ids appear, a sort that grouped them apart would return only one'
  assert_contains "$HITS_1_0_1" 'SCOURSH-FIXTURE-OSV-BULK-NPM-1' 'NPM-1 is among the hits'
  assert_contains "$HITS_1_0_1" 'SCOURSH-FIXTURE-OSV-BULK-NPM-5' 'NPM-5 is among the hits'
else
  printf '  SKIP  look is absent on this host; the multi-row half of tension 25 lookup asymmetry cannot be exercised here\n'
fi

t_case 'a deliberately mis-sorted copy of the same rows FAILS the same lookups (look only)'
# shellcheck disable=SC2031
if [[ ${SCOURSH_CAP_LOOK:-none} == look ]]; then
  MIS=$BULK_W/mis-sorted.db
  { LC_ALL=C sed -n '/^#/p' "$BDB"; LC_ALL=C sort -r <<<"$body"; } >"$MIS"
  found=0
  while IFS=$'\t' read -r eco pkg intro _rest; do
    [[ -n $eco ]] || continue
    if sca_lookup_range "$pkg" "$intro" "$MIS" >/dev/null; then
      found=$(( found + 1 ))
    fi
  done <<<"$body"
  if (( found < 12 )); then
    _t_ok "a reverse-sorted copy of the identical rows loses $(( 12 - found )) of 12 lookups, so the LC_ALL=C sort is load-bearing rather than incidental"
  else
    _t_no 'a reverse-sorted copy of the identical rows loses at least one lookup' "found=$found of 12"
  fi
else
  printf '  SKIP  look is absent on this host; the binary-search half of the sort requirement cannot be exercised here\n'
fi

# ---------------------------------------------------------------------------
# -- section I: the network path, against a STUBBED curl --
# ---------------------------------------------------------------------------
t_case 'bulk import over the network: acknowledged, transport-only grade'
bulk_reset_db
rc=0
bulk_run_net --accept-unverified npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'an acknowledged network bulk import of npm exits 0'
assert_contains "$out" 'integrity: unpinned-transport-only' \
  'the network grade is named separately from the local-archive one, because what was verified differs'
assert_contains "$out" "artifact sha256: $NPM_ZIP_SHA" 'the digest of what was fetched is recorded'
assert_contains "$out" 'osv-vulnerabilities.storage.googleapis.com' \
  'the exact artifact URL is printed, so the operator can see what was reached'
assert_contains "$(cat "$BDB")" 'bulk-fixture-alpha' 'and the rows landed'

t_case 'bulk import over the network: pinned, and verified through veng_fetch itself'
bulk_reset_db
rc=0
bulk_run_net --sha256 "$NPM_ZIP_SHA" npm || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'a correctly pinned network import exits 0 with no acknowledgement flag'
assert_contains "$out" 'checksum verified' \
  'the pinned network path goes through veng_fetch, the existing download-and-verify primitive, rather than a second parallel fetch that reimplements verification'
assert_contains "$out" 'integrity: pinned-sha256' 'and reports the pinned grade'

t_case 'bulk import over the network: a wrong pin refuses (exit 5) and imports nothing'
bulk_reset_db
rc=0
bulk_run_net --sha256 "$BAD_SHA" npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" 'a mismatched pin on the network path is exit 5'
assert_file_absent "$BDB" 'nothing was imported'

t_case 'bulk import over the network: a failed download is exit 5, not a silent empty import'
bulk_reset_db
rc=0
( PATH="$FAKE_BULK_BIN:$NO_NET_PATH" FAKE_BULK_ZIP_DIR="$BULK_W/zips" FAKE_CURL_FAIL=1 \
  SCOURSH_SCA_ADVISORIES_DB="$BDB" SCOURSH_SCA_VERSIONS_DB="$BVDB" \
  SCOURSH_SCA_SUMMARIES_DB="$BSDB" SCOURSH_DAST_VERSION_SUMMARIES_DB="$BVSDB" \
  bash "$TOOL" advisories bulk --accept-unverified npm ) >"$BULK_W/last.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" 'a failed fetch is exit 5'
assert_file_absent "$BDB" 'and writes no database, rather than an empty one that reports every project clean'

t_case 'bulk --all imports all six ecosystems in one command'
bulk_reset_db
rc=0
bulk_run_net --all --accept-unverified || rc=$?
out=$(cat "$BULK_W/last.out")
assert_eq 0 "$rc" 'bulk --all over the six ecosystems exits 0'
db=$(cat "$BDB")
assert_contains "$db" "$(printf 'npm\tbulk-fixture-alpha')" 'npm rows'
assert_contains "$db" "$(printf 'pypi\tbulk-fixture-django')" 'pypi rows, PEP 503 normalised'
assert_contains "$db" "$(printf 'maven\torg.example.bulk:widget-core')" 'maven rows, groupId:artifactId'
assert_contains "$db" "$(printf 'Go\tgithub.com/example/bulk/v3\tv3.0.0\t')" \
  'Go rows with +incompatible stripped from the version key, /vN retained in the module path'
assert_contains "$db" "$(printf 'RubyGems\tbulkfixturegem')" 'RubyGems rows, lowercased'
assert_contains "$db" "$(printf 'composer\tacme/bulk-widget')" 'composer rows, lowercased (Packagist upstream, composer in the frozen schema)'
assert_eq 6 "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB" | wc -l | tr -d ' ')" 'one provenance line per ecosystem'
body=$(LC_ALL=C sed -e '/^#/d' -e '/^$/d' "$BDB")
assert_eq "$(LC_ALL=C sort <<<"$body")" "$body" 'the six ecosystems are sorted TOGETHER under LC_ALL=C, not concatenated per ecosystem'

t_case 'bulk --all is honest when one ecosystem fails: the others land, the run still fails'
bulk_reset_db
mv -- "$BULK_W/zips/Maven.zip" "$BULK_W/zips/Maven.zip.hidden"
rc=0
bulk_run_net --all --accept-unverified || rc=$?
out=$(cat "$BULK_W/last.out")
mv -- "$BULK_W/zips/Maven.zip.hidden" "$BULK_W/zips/Maven.zip"
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'one failed ecosystem fails the whole run - fails under the reading that exits 0 because five of six worked, which is exactly a database silently covering less than it claims'
assert_contains "$out" 'FAILED' 'the summary marks the failed ecosystem'
assert_contains "$out" 'maven' 'and names it'
assert_contains "$(cat "$BDB")" 'bulk-fixture-alpha' 'the ecosystems that DID import are still written, rather than discarded'
assert_not_contains "$(LC_ALL=C sed -n '/^# bulk:/p' "$BDB")" 'ecosystem=maven' \
  'and no provenance line claims coverage for the ecosystem that failed'

# ---------------------------------------------------------------------------
# -- section J: the whole point of the ticket, end to end.  A real
#    `scan.sh sca` subprocess against a vulnerable fixture project, before
#    and after the bulk import, with nothing else changed --
# ---------------------------------------------------------------------------
DEMO=$ROOT/tests/fixtures/vendor-engines/bulk-demo-project

# This case used to assert exit 0 here, on the reading that "the module is
# finished and working, it simply has nothing to match against".  That was
# true of the module and false of the RUN: exit 0 with zero findings is
# byte-indistinguishable, to CI, from a clean dependency scan of a project
# that is knowingly vulnerable.  A separate ticket fixed that, and this case
# now pins the honest half of the before/after pair - the run refuses rather
# than reporting, and the value of the bulk import below is unchanged.
t_case 'BEFORE: with no advisory database, a real scan.sh sca refuses instead of reporting the vulnerable project clean'
E2E_BEFORE=$BULK_W/e2e-before
rm -rf "$E2E_BEFORE"
assert_status "$SCOURSH_EXIT_INPUT" 'exit 4 (missing required input) - fails under the reading this case used to carry, where the same run exited 0 and looked exactly like a clean scan' \
  env SCOURSH_SCA_ADVISORIES_DB="$BULK_W/absent-advisories.db" bash "$ROOT/scan.sh" sca \
  --path "$DEMO" --out "$E2E_BEFORE"
before_json=$(cat "$E2E_BEFORE/run.json" 2>/dev/null)
assert_not_contains "$before_json" 'SCA-NPM-VULNERABLE_DEP-01' \
  'still zero vulnerable-dependency findings against a knowingly vulnerable project - which is what the bulk import below exists to change'
assert_contains "$before_json" 'no_advisories_db_on_disk' \
  'and the run records WHY it found nothing'
assert_contains "$before_json" 'SCA-COV-NO_ADVISORY_DB-01' \
  'and carries the coverage finding that says so on the report itself, not only in run.json metadata'

t_case 'AFTER: the same scan against the same project, pointed at a bulk-imported database, reports the vulnerabilities (docs/FOUNDATION.md tension 25 npm-range amendment)'
bulk_reset_db
bulk_run --archive "$NPM_ZIP" --sha256 "$NPM_ZIP_SHA" npm
E2E_AFTER=$BULK_W/e2e-after
rm -rf "$E2E_AFTER"
assert_status 0 'the scan exits 0' \
  env SCOURSH_SCA_ADVISORIES_DB="$BDB" SCOURSH_SCA_SUMMARIES_DB="$BSDB" bash "$ROOT/scan.sh" sca \
  --path "$DEMO" --out "$E2E_AFTER"
after_json=$(cat "$E2E_AFTER/run.json" 2>/dev/null)
assert_contains "$after_json" 'SCA-NPM-VULNERABLE_DEP-01' \
  'the vulnerable-dependency check now actually executes and fires, through the real scan.sh entry point, against a database built by one bulk command'
findings=$(cat "$E2E_AFTER/findings.jsonl" 2>/dev/null || true)
assert_contains "$findings" 'SCOURSH-FIXTURE-OSV-BULK-NPM-1' \
  'the advisory id carried through the whole pipeline: OSV export -> bulk import -> frozen TSV -> reader lookup -> finding'
assert_contains "$findings" 'SCOURSH-FIXTURE-OSV-BULK-NPM-2' 'both vulnerable dependencies are reported, not just the first'
assert_contains "$after_json" '"sca":2' \
  'bulk-fixture-alpha@1.0.0 (NPM-1) and @bulk-scope/beta@2.0.0 (NPM-2) both fall inside their own fixed-kind range - two vulnerable findings. bulk-fixture-gamma@3.5.0, which used to feed the unknown-version roll-up (a THIRD live finding, pre-amendment), is now a genuine range MISS: NPM-4'"'"'s own interval is [0,3.1.0) and 3.5.0 is above that bound, so this is a real "not affected" verdict and npm no longer contributes to that roll-up at all - see modules/sca/engine.sh'"'"'s npm walk comment'
assert_not_contains "$findings" 'bulk-fixture-gamma' \
  'bulk-fixture-gamma is genuinely not affected at 3.5.0 - no finding of any kind, not even a roll-up contribution'
assert_not_contains "$findings" 'bulk-fixture-clean' \
  'the dependency that appears in no advisory is not reported - the database discriminates rather than matching everything'

t_summary 'vendor-engines-advisories'
