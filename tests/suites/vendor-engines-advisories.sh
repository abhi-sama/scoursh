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
bulk_reset_db() {
  rm -f "$BDB" "$BVDB"
}

# bulk_run [ARGS...] - one real subprocess of the bulk importer with curl
# ENTIRELY ABSENT from PATH, writing to this suite's own scratch db paths.
# Output lands in $BULK_W/last.out; the exit status is returned.
bulk_run() {
  local rc=0
  ( PATH="$NO_NET_PATH" \
    SCOURSH_SCA_ADVISORIES_DB="$BDB" \
    SCOURSH_SCA_VERSIONS_DB="$BVDB" \
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

t_case 'bulk import: every enumerated affected version becomes one exact-version row'
db=$(cat "$BDB")
assert_contains "$db" "$(printf 'npm\tbulk-fixture-alpha\t1.0.0\tSCOURSH-FIXTURE-OSV-BULK-NPM-1\thigh\t1.1.0\tfixture: prototype pollution in bulk-fixture-alpha')" \
  'the frozen 7-field schema is written verbatim, severity normalised HIGH -> high'
assert_contains "$db" "$(printf 'npm\tbulk-fixture-alpha\t1.0.1\tSCOURSH-FIXTURE-OSV-BULK-NPM-1\thigh')" \
  'the second enumerated version of the same advisory gets its own row (pre-expansion, tension 25)'
assert_contains "$db" "$(printf 'npm\t@bulk-scope/beta\t2.0.0\tSCOURSH-FIXTURE-OSV-BULK-NPM-2\tcritical')" \
  'a scoped npm name is carried verbatim, scope included (tension 25 frozen table)'
assert_contains "$db" "$(printf 'npm\tbulk-fixture-gamma\t3.0.0\tSCOURSH-FIXTURE-OSV-BULK-NPM-4\tmedium')" \
  'an advisory with no severity at all defaults to medium rather than being dropped'
assert_contains "$db" 'fixture: bulk-fixture-gamma leaks a token in its debug log.' \
  'the summary falls back to the first line of the details field when no summary field exists'
assert_not_contains "$db" 'A second line the summary fallback must not carry' \
  'only the FIRST line of details is used - a multi-line summary would be an LF inside a frozen-schema field'

t_case 'bulk import: a range-only advisory is skipped and COUNTED, never guessed at'
assert_not_contains "$(cat "$BDB")" 'bulk-fixture-rangeonly' \
  'no row is invented for an advisory with no enumerated versions - tension 25 puts range arithmetic on the networked box, and OSV published none here'
assert_contains "$(cat "$BULK_W/last.out")" 'range_only_skipped=1' \
  'the skipped advisory is reported as a count, so a database that covers less than the ecosystem does is never silently smaller'

t_case 'bulk import: a decoy affected entry for another ecosystem is skipped and counted'
assert_not_contains "$(cat "$BDB")" 'bulk-decoy-should-not-appear' \
  "the PyPI 'affected' entry inside an npm-ecosystem import is not emitted as an npm row"
assert_contains "$(cat "$BULK_W/last.out")" 'other_ecosystem_skipped=1' \
  'the cross-ecosystem skip is counted too rather than being invisible'

t_case 'bulk import: the run reports what it actually imported'
out=$(cat "$BULK_W/last.out")
assert_contains "$out" 'advisories_read=5' 'every member of the archive is accounted for'
assert_contains "$out" 'rows=7' \
  '7 exact-version rows from 5 advisories - 2 + 2 + 0 (range-only) + 2 + 1'
body=$(LC_ALL=C sed -e '/^#/d' -e '/^$/d' "$BDB")
assert_eq 7 "$(printf '%s\n' "$body" | wc -l | tr -d ' ')" \
  'the row count in the file matches the count the run reported - a reported number that the file does not back is exactly the silent-coverage-gap shape'

t_case 'bulk import: the database records its own provenance'
hdr=$(LC_ALL=C sed -n '/^#/p' "$BDB")
assert_contains "$hdr" 'ecosystem=npm' 'the provenance line names the ecosystem it covers'
assert_contains "$hdr" 'grade=unpinned-local-archive' 'it records the integrity grade that produced these rows'
assert_contains "$hdr" "sha256=$NPM_ZIP_SHA" 'it records the digest of the artifact those rows came from'
assert_contains "$hdr" 'rows=7' 'it records the row count'
assert_contains "$hdr" 'range_only_skipped=1' 'it records what it could NOT express, next to what it could'

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

t_case 'bulk import: a structurally perfect archive that yields ZERO rows is refused (exit 5)'
before=$(cat "$BDB")
rc=0
bulk_run --archive "$BULK_W/zips/npm-zero-rows.zip" --accept-unverified npm || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'an import that produces no rows refuses rather than replacing the ecosystem rows with nothing - fails under the reading that treats an empty result as a successful import, which would quietly turn every dependency in that ecosystem clean'
assert_eq "$before" "$(cat "$BDB")" 'and the previous rows survive untouched'
assert_contains "$(cat "$BULK_W/last.out")" 'ZERO exact-version rows' 'the refusal says exactly what was wrong'

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

t_case 'the reader finds every written row through db_lookup_exact itself, not by inspection'
# Proving the sort by eyeballing the file is exactly the mistake tension 25
# warns about: the thing that matters is whether the READER's own lookup
# finds the row.  This runs sca_lookup_exact (modules/sca/engine.sh), which
# routes through lib/core.sh's db_lookup_exact, against the generated file.
_veng_advisories_load_normalizers
missed=0
while IFS=$'\t' read -r eco pkg ver _rest; do
  [[ -n $eco ]] || continue
  if ! sca_lookup_exact "$eco" "$pkg" "$ver" "$BDB" >/dev/null; then
    missed=$(( missed + 1 ))
    printf '    MISSED: %s %s %s\n' "$eco" "$pkg" "$ver" >&2
  fi
done <<<"$body"
assert_eq 0 "$missed" \
  'every one of the 7 generated rows is found by the reader own lookup primitive - a wrong sort order makes look silently miss rows that are visibly present in the file'

t_case 'the reader finds every row under BOTH lookup backends (look and the grep fallback)'
missed=0
# SC2030/SC2031: forcing SCOURSH_CAP_LOOK inside a subshell is the point of
# this case (it drives db_lookup_exact down its grep -F fallback), and it
# must NOT leak back into the surrounding suite, which goes on to exercise
# the look path on the same file.
# shellcheck disable=SC2030
while IFS=$'\t' read -r eco pkg ver _rest; do
  [[ -n $eco ]] || continue
  if ! ( SCOURSH_CAP_LOOK=none; sca_lookup_exact "$eco" "$pkg" "$ver" "$BDB" >/dev/null ); then
    missed=$(( missed + 1 ))
  fi
done <<<"$body"
assert_eq 0 "$missed" \
  "the grep -F fallback path finds them too, so a host without look reads the same database (tension 25's own frozen asymmetry is about how MANY rows come back, never about which exist)"

t_case 'a version that was never written is NOT found (the lookup is exact, not a prefix guess)'
rc=0
sca_lookup_exact npm bulk-fixture-alpha 9.9.9 "$BDB" >/dev/null || rc=$?
assert_ne 0 "$rc" 'an unwritten version misses, so a passing lookup above is evidence rather than a lookup that matches everything'
rc=0
sca_lookup_exact npm bulk-fixture-rangeonly 1.2.0 "$BDB" >/dev/null || rc=$?
assert_ne 0 "$rc" 'and the range-only advisory really is absent from the reader path, not merely from a visual scan of the file'

t_case 'two advisories for one package@version both come back through the reader (look only)'
# shellcheck disable=SC2031
if [[ ${SCOURSH_CAP_LOOK:-none} == look ]]; then
  hits=$(sca_lookup_exact npm bulk-fixture-alpha 1.0.1 "$BDB" | wc -l | tr -d ' ')
  assert_eq 2 "$hits" \
    'NPM-1 and NPM-5 both name bulk-fixture-alpha 1.0.1, and look returns both rows - a sort that grouped them apart would return one'
else
  printf '  SKIP  look is absent on this host; the multi-row half of tension 25 lookup asymmetry cannot be exercised here\n'
fi

t_case 'a deliberately mis-sorted copy of the same rows FAILS the same lookups (look only)'
# shellcheck disable=SC2031
if [[ ${SCOURSH_CAP_LOOK:-none} == look ]]; then
  MIS=$BULK_W/mis-sorted.db
  { LC_ALL=C sed -n '/^#/p' "$BDB"; LC_ALL=C sort -r <<<"$body"; } >"$MIS"
  found=0
  while IFS=$'\t' read -r eco pkg ver _rest; do
    [[ -n $eco ]] || continue
    if sca_lookup_exact "$eco" "$pkg" "$ver" "$MIS" >/dev/null; then
      found=$(( found + 1 ))
    fi
  done <<<"$body"
  if (( found < 7 )); then
    _t_ok "a reverse-sorted copy of the identical rows loses $(( 7 - found )) of 7 lookups, so the LC_ALL=C sort is load-bearing rather than incidental"
  else
    _t_no 'a reverse-sorted copy of the identical rows loses at least one lookup' "found=$found of 7"
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

t_case 'BEFORE: with no advisory database, a real scan.sh sca reports the vulnerable project clean'
E2E_BEFORE=$BULK_W/e2e-before
rm -rf "$E2E_BEFORE"
assert_status 0 'the scan itself succeeds - the module is finished and working, it simply has nothing to match against' \
  env SCOURSH_SCA_ADVISORIES_DB="$BULK_W/absent-advisories.db" bash "$ROOT/scan.sh" sca \
  --path "$DEMO" --out "$E2E_BEFORE"
before_json=$(cat "$E2E_BEFORE/run.json" 2>/dev/null)
assert_not_contains "$before_json" 'SCA-NPM-VULNERABLE_DEP-01' \
  'zero vulnerable-dependency findings against a knowingly vulnerable project: the exact defect this ticket exists to fix'
assert_contains "$before_json" 'no_advisories_db_on_disk' \
  'and the run does at least record WHY it found nothing'

t_case 'AFTER: the same scan against the same project, pointed at a bulk-imported database, reports the vulnerabilities'
bulk_reset_db
bulk_run --archive "$NPM_ZIP" --sha256 "$NPM_ZIP_SHA" npm
E2E_AFTER=$BULK_W/e2e-after
rm -rf "$E2E_AFTER"
assert_status 0 'the scan exits 0' \
  env SCOURSH_SCA_ADVISORIES_DB="$BDB" bash "$ROOT/scan.sh" sca \
  --path "$DEMO" --out "$E2E_AFTER"
after_json=$(cat "$E2E_AFTER/run.json" 2>/dev/null)
assert_contains "$after_json" 'SCA-NPM-VULNERABLE_DEP-01' \
  'the vulnerable-dependency check now actually executes and fires, through the real scan.sh entry point, against a database built by one bulk command'
findings=$(cat "$E2E_AFTER/findings.jsonl" 2>/dev/null || true)
assert_contains "$findings" 'SCOURSH-FIXTURE-OSV-BULK-NPM-1' \
  'the advisory id carried through the whole pipeline: OSV export -> bulk import -> frozen TSV -> reader lookup -> finding'
assert_contains "$findings" 'SCOURSH-FIXTURE-OSV-BULK-NPM-2' 'both vulnerable dependencies are reported, not just the first'
assert_contains "$after_json" '"sca":3' \
  'two vulnerable dependencies plus the one unknown-version roll-up for the known package pinned at an untracked version'
assert_not_contains "$findings" 'bulk-fixture-clean' \
  'the dependency that appears in no advisory is not reported - the database discriminates rather than matching everything'

t_summary 'vendor-engines-advisories'
