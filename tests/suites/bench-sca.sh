#!/usr/bin/env bash
# tests/suites/bench-sca.sh - the B5 SCA leg: bench/lib/sca_advisories.sh,
# the four bench/tools/*.sh SCA adapters, and the scorer against a small
# hand-checked truth/results pair.
#
# HERMETIC BY CONSTRUCTION, exactly like tests/suites/bench.sh's own header
# states for the harness generally: nothing here runs a real scanner, queries
# api.osv.dev, or touches the network. Every adapter is exercised through its
# own `_normalise` function against a committed fixture under
# tests/fixtures/bench/ - a REAL, trimmed-but-unedited excerpt of that tool's
# own output against this leg's actual corpus (bench/corpora/_samples/
# sca-lockfiles-26/root/npm-lodash-vuln), captured while building this leg,
# not hand-typed. Section D's scorer check is a tiny hand-authored 4-case
# fixture, the same "small enough to verify by arithmetic" discipline
# tests/suites/bench.sh's own section E documents for its SAST equivalent.
#
# SC2016: prose and markdown code spans quote shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

BENCH=$ROOT/bench
FIX=$ROOT/tests/fixtures/bench
W=$SCOURSH_SCRATCH/bench-sca-suite
rm -rf "$W"
mkdir -p "$W"

US=$'\x1f'

# shellcheck source=bench/lib/json.sh
source "$BENCH/lib/json.sh"
# shellcheck source=bench/lib/normalise.sh
source "$BENCH/lib/normalise.sh"
# shellcheck source=bench/lib/truth.sh
source "$BENCH/lib/truth.sh"
# shellcheck source=bench/lib/score.sh
source "$BENCH/lib/score.sh"
# shellcheck source=bench/lib/sca_advisories.sh
source "$BENCH/lib/sca_advisories.sh"

vis() { printf '%s' "${1//$US/|}"; }

# assert_cond MSG CMD... - assert a command SUCCEEDS, run in THIS shell (the
# same helper tests/suites/bench.sh defines for itself, for the identical
# reason: `declare -F` is a question about this shell's own function table,
# which a subshell-running assert_status cannot answer).
assert_cond() {
  local msg=$1
  shift
  local rc=0
  "$@" || rc=$?
  assert_eq 0 "$rc" "$msg"
}

# ===========================================================================
printf -- '\n-- A. bench/lib/sca_advisories.sh reads bench/sca-advisories.lock --\n'
# ===========================================================================

t_case 'sca_advisories_load parses the real committed bench/sca-advisories.lock'
assert_cond 'sca_advisories_load returns 0' sca_advisories_load "$BENCH/sca-advisories.lock"

t_case 'every ecosystem this leg claims has at least one pinned advisory'
for eco in npm PyPI Go; do
  n=0
  for id in "${BENCH_SCA_ADV_IDS[@]}"; do
    [[ $(sca_advisory_field "$id" ecosystem) == "$eco" ]] && n=$(( n + 1 ))
  done
  assert_ne 0 "$n" "at least one $eco advisory is pinned"
done

t_case 'a record missing a required key is refused, not silently dropped'
bad=$W/bad.lock
{
  printf 'id: missing-fixed\n'
  printf 'ecosystem: npm\n'
  printf 'package: example\n'
  printf 'vuln-version: 1.0.0\n'
  printf 'osv-id: GHSA-0000-0000-0000\n'
  printf 'severity: HIGH\n'
} >"$bad"
rc=0
sca_advisories_load "$bad" 2>/dev/null || rc=$?
assert_ne 0 "$rc" 'a record with no fixed-version is refused (return 2), not read as an empty field'
sca_advisories_load "$BENCH/sca-advisories.lock" >/dev/null

t_case 'every pinned osv-id is syntactically a real OSV/GHSA/PYSEC/GO id, never a placeholder'
bad_ids=''
for id in "${BENCH_SCA_ADV_IDS[@]}"; do
  osv_id=$(sca_advisory_field "$id" osv-id)
  case $osv_id in
    GHSA-* | PYSEC-* | GO-*) ;;
    *) bad_ids+="$id($osv_id) " ;;
  esac
done
assert_eq '' "$bad_ids" 'no pinned advisory carries an id outside OSV'"'"'s own three-prefix namespace'

# ===========================================================================
printf -- '\n-- B. bench/fetch-sca-corpus.sh writes a truth line per case, real:true/false paired --\n'
# ===========================================================================

t_case 'the corpus category function matches every SCA adapter'
# shellcheck source=/dev/null
. <(sed -n '/^_category()/,/^}/p' "$BENCH/fetch-sca-corpus.sh")
assert_eq 'sca-npm' "$(_category npm)" 'npm -> sca-npm'
assert_eq 'sca-pypi' "$(_category PyPI)" 'PyPI -> sca-pypi'
assert_eq 'sca-go' "$(_category Go)" 'Go -> sca-go'

if [[ -r $BENCH/corpora/_samples/sca-lockfiles-26/truth ]]; then
  t_case 'the built corpus truth file pairs one real:true case with one real:false case per advisory'
  truth_load "$BENCH/corpora/_samples/sca-lockfiles-26/truth"
  assert_eq "$(( ${#BENCH_SCA_ADV_IDS[@]} * 2 ))" "${#BENCH_TRUTH_CASES[@]}" \
    'every pinned advisory contributes exactly two cases (a recall-only corpus cannot measure a false-positive rate)'
  for id in "${BENCH_SCA_ADV_IDS[@]}"; do
    assert_eq 'true' "${BENCH_TRUTH_REAL[$id-vuln]:-MISSING}" "$id-vuln is the real case"
    assert_eq 'false' "${BENCH_TRUTH_REAL[$id-patched]:-MISSING}" "$id-patched is the sanitized-trap counterpart"
    assert_eq "${BENCH_TRUTH_FILE[$id-vuln]:-}" "$id-vuln" 'truth `file` names the CASE DIRECTORY, matching every SCA adapter'"'"'s own normalisation'
  done
else
  printf 'SKIPPED: bench/corpora/_samples/sca-lockfiles-26 not built here (run bench/fetch-sca-corpus.sh first) - this section only checks the fetched corpus when present\n'
fi

# ===========================================================================
printf -- '\n-- C. the four SCA tool adapters, against REAL committed tool output --\n'
# ===========================================================================

# shellcheck source=bench/tools/scoursh-sca.sh
source "$BENCH/tools/scoursh-sca.sh"
# shellcheck source=bench/tools/grype.sh
source "$BENCH/tools/grype.sh"
# shellcheck source=bench/tools/osv-scanner.sh
source "$BENCH/tools/osv-scanner.sh"
# shellcheck source=bench/tools/trivy-fs.sh
source "$BENCH/tools/trivy-fs.sh"

t_case 'every SCA adapter implements the whole bench/run-tool.sh contract'
for _t in scoursh-sca grype osv-scanner trivy-fs; do
  for _fn in _available _version _run _normalise _scope; do
    assert_cond "${_t}${_fn} is defined" declare -F "${_t}${_fn}"
  done
  scope=$("${_t}_scope")
  assert_ne '' "$scope" "${_t}_scope names at least one category"
  assert_contains "$scope" 'sca-npm' "${_t} claims sca-npm"
done

t_case 'the scoursh-sca adapter emits a record for a real finding, keyed on the case directory name'
mkdir -p "$W/raw-scoursh-sca/cases/npm-lodash-vuln"
cp "$FIX/scoursh-sca-findings-vuln-sample.jsonl" "$W/raw-scoursh-sca/cases/npm-lodash-vuln/findings.jsonl"
recs=$(scoursh-sca_normalise "$W/raw-scoursh-sca" '/nonexistent-root')
assert_eq 1 "$(printf '%s\n' "$recs" | grep -c .)" 'exactly one record - the fixture has one finding'
assert_contains "$recs" "npm-lodash-vuln${US}${US}GHSA-p6mc-m468-83gw${US}high${US}npm:lodash" \
  'file is the case DIRECTORY name (never the manifest filename), cwe carries the OSV advisory id for strict/identity matching'

t_case 'the scoursh-sca adapter emits NOTHING for a coverage-only rollup - a miss stays a miss'
mkdir -p "$W/raw-scoursh-sca/cases/go-hashicorp-vault-vuln"
cp "$FIX/scoursh-sca-findings-miss-sample.jsonl" "$W/raw-scoursh-sca/cases/go-hashicorp-vault-vuln/findings.jsonl"
recs2=$(scoursh-sca_normalise "$W/raw-scoursh-sca" '/nonexistent-root')
# recs2 covers BOTH case dirs now (normalise walks every case under raw/cases/)
assert_eq 1 "$(printf '%s\n' "$recs2" | grep -c .)" \
  'still exactly one record total - SCA-COV-UNKNOWN_VERSION-01 (no ecosystem/package/advisory_id) produces no record, so the vault case contributes zero and stays a false negative rather than a phantom hit'
assert_not_contains "$recs2" 'go-hashicorp-vault-vuln' 'the coverage-only case never appears as a hit'

t_case 'the grype adapter emits one record per (finding, id) pair - the vulnerability id AND every related-CVE alias'
mkdir -p "$W/raw-grype"
cp "$FIX/grype-sample.json" "$W/raw-grype/grype.json"
recs=$(grype_normalise "$W/raw-grype" '/nonexistent-root')
assert_contains "$recs" "npm-lodash-vuln${US}${US}GHSA-p6mc-m468-83gw${US}high${US}lodash" \
  'the GHSA id this leg'"'"'s ground truth is pinned to is present as its own record'
assert_contains "$recs" "npm-lodash-vuln${US}${US}CVE-2020-8203${US}high${US}lodash" \
  'the CVE alias (relatedVulnerabilities[].id in real grype output) is ALSO its own record - this is what lets strict/identity matching credit a tool that reports the CVE instead of the GHSA id'

t_case 'the osv-scanner adapter bands a numeric max_severity onto the common scale, never passes the score through raw'
mkdir -p "$W/raw-osv-scanner"
cp "$FIX/osv-scanner-sample.json" "$W/raw-osv-scanner/osv-scanner.json"
# The fixture's `source.path` is the portable placeholder `/fixture-root/...`
# (rewritten from this leg's own real, absolute capture path before
# committing - the same "do not embed an operator's home directory" rule
# bench/run-tool.sh's --portable-paths applies to a committed RESULT, applied
# here to a committed FIXTURE instead), so `root` must match it exactly.
recs=$(osv-scanner_normalise "$W/raw-osv-scanner" '/fixture-root')
assert_contains "$recs" "npm-lodash-vuln${US}${US}GHSA-p6mc-m468-83gw${US}high${US}lodash" \
  'the pinned advisory'"'"'s group (max_severity 7.4 in the fixture) bands to `high` (CVSS 7.0-8.9), never `7.4` or `"7.4"` passed through raw'
assert_contains "$recs" "npm-lodash-vuln${US}${US}CVE-2020-8203${US}high${US}lodash" \
  'its CVE alias is ALSO its own record, same as every other id in the group'
assert_contains "$recs" "npm-lodash-vuln${US}${US}GHSA-29mw-wpgm-hmr9${US}medium${US}lodash" \
  'a second, unrelated group in the same fixture bands its own max_severity (5.3) to `medium` (CVSS 4.0-6.9) independently'

t_case 'the trivy-fs adapter reads both VulnerabilityID and every VendorIDs entry'
mkdir -p "$W/raw-trivy-fs"
cp "$FIX/trivy-fs-sample.json" "$W/raw-trivy-fs/trivy.json"
recs=$(trivy-fs_normalise "$W/raw-trivy-fs" '/nonexistent-root')
assert_contains "$recs" "npm-lodash-vuln${US}${US}CVE-2020-8203${US}high${US}lodash" \
  'the primary VulnerabilityID (a CVE for this finding) is present'
assert_contains "$recs" "npm-lodash-vuln${US}${US}GHSA-p6mc-m468-83gw${US}high${US}lodash" \
  'and the VendorIDs GHSA cross-reference is ALSO present, as its own record'

# ===========================================================================
printf -- '\n-- D. the scorer against a tiny hand-checked SCA fixture --\n'
# ===========================================================================
# Four cases, two advisories, one per ecosystem, worked out by hand so a
# reader can verify the confusion matrix by arithmetic - the same discipline
# tests/suites/bench.sh's own section E documents for its SAST fixture.
#
#   pkg-a-vuln   (sca-npm, real=true,  id=GHSA-AAAA)
#   pkg-a-fixed  (sca-npm, real=false)
#   pkg-b-vuln   (sca-pypi, real=true, id=GHSA-BBBB)
#   pkg-b-fixed  (sca-pypi, real=false)
#
# toolX reports GHSA-AAAA on pkg-a-vuln (a true positive, strict AND loose),
# and ALSO reports an unrelated finding on pkg-a-fixed (a loose false
# positive, but NOT a strict one - the id does not match) - the exact shape
# this leg's real run measured for every specialist tool (see the leg's own
# results README: general-purpose SCA scanners report every KNOWN
# vulnerability for a version, so "any finding" is a poor match rule for a
# package with more than one historical advisory).  toolX reports nothing at
# all for sca-pypi, so pkg-b-vuln is a false negative in both modes.
truth_fx=$W/truth-fixture
{
  printf 'pkg-a-vuln%spkg-a-vuln%ssca-npm%sGHSA-AAAA%strue\n' "$US" "$US" "$US" "$US"
  printf 'pkg-a-fixed%spkg-a-fixed%ssca-npm%s%sfalse\n' "$US" "$US" "$US" "$US"
  printf 'pkg-b-vuln%spkg-b-vuln%ssca-pypi%sGHSA-BBBB%strue\n' "$US" "$US" "$US" "$US"
  printf 'pkg-b-fixed%spkg-b-fixed%ssca-pypi%s%sfalse\n' "$US" "$US" "$US" "$US"
} >"$truth_fx"

results_fx=$W/results-fixture
mkdir -p "$results_fx/toolX"
{
  bench_record 'pkg-a-vuln' '' 'GHSA-AAAA' high 'npm:pkg-a'
  bench_record 'pkg-a-fixed' '' 'GHSA-ZZZZ' medium 'npm:pkg-a'
} | bench_records_to_jsonl toolX '1.0.0' sca-fixture >"$results_fx/toolX/normalised.jsonl"
{
  printf 'claims-categories: sca-npm sca-pypi\n'
  printf 'version: 1.0.0\n'
} >"$results_fx/toolX/MANIFEST"

sh_out=$W/scorecard.md
bash "$BENCH/score.sh" --truth "$truth_fx" --results "$results_fx" --format md >"$sh_out"
sc=$(cat "$sh_out")

t_case 'loose mode: sca-npm is TP=1 FN=0 FP=1 TN=0 (pkg-a-fixed'"'"'s unrelated finding is a loose false positive)'
assert_contains "$sc" 'toolX | sca-npm | 1 | 0 | 1 | 0 |' "$(vis "$sc" >/dev/null; echo loose sca-npm row)"

t_case 'strict mode: sca-npm is TP=1 FN=0 FP=0 TN=1 (GHSA-ZZZZ does not match GHSA-AAAA, so pkg-a-fixed is a true negative under identity matching)'
assert_contains "$sc" 'toolX | sca-npm | 1 | 0 | 0 | 1 |' 'strict sca-npm row'

t_case 'sca-pypi is TP=0 FN=1 in both modes - toolX reported nothing there'
assert_contains "$sc" 'toolX | sca-pypi | 0 | 1 | 0 | 1 |' 'sca-pypi row (identical loose and strict, since there is no finding to (mis)match)'

t_case 'strict and loose DISAGREE on sca-npm and AGREE on sca-pypi - both are asserted, not just one'
assert_contains "$sc" 'toolX | 1 of 2 | sca-npm' 'the agreement table names sca-npm as the disagreeing category'

# ===========================================================================
printf -- '\n-- E. isolation: the SCA leg files obey the same rules as the rest of bench/ --\n'
# ===========================================================================

t_case 'none of the four SCA adapter files source a scanner library'
hits=''
for f in "$BENCH/tools/scoursh-sca.sh" "$BENCH/tools/grype.sh" "$BENCH/tools/osv-scanner.sh" "$BENCH/tools/trivy-fs.sh" "$BENCH/lib/sca_advisories.sh" "$BENCH/fetch-sca-corpus.sh"; do
  grep -nE '^[[:space:]]*(source|\.)[[:space:]]+.*(\$ROOT|\.\./\.\.)/lib/' "$f" >/dev/null 2>&1 && hits+="$(basename "$f") "
done
assert_eq '' "$hits" 'no source edge from the SCA leg into lib/'

t_case 'only bench/fetch-sca-corpus.sh, among the SCA leg'"'"'s own files, reaches the network'
hits=''
for f in "$BENCH/tools/scoursh-sca.sh" "$BENCH/tools/grype.sh" "$BENCH/tools/osv-scanner.sh" "$BENCH/tools/trivy-fs.sh" "$BENCH/lib/sca_advisories.sh"; do
  grep -nE '(^|[^[:alnum:]_])(curl|wget|git (clone|fetch|ls-remote))([^[:alnum:]_]|$)' "$f" >/dev/null 2>&1 && hits+="$(basename "$f") "
done
assert_eq '' "$hits" 'the adapters call the TOOL, never the network directly - the tool itself may reach the network (grype/osv-scanner/trivy-fs are not egress-restricted), but this shell code does not'

t_case 'the corpus and results directories obey the existing bench/ conventions'
assert_file_exists "$BENCH/sca-advisories.lock" 'the pinned advisory manifest is committed'
assert_file_absent "$BENCH/corpora/.gitkeep" 'bench/corpora/ stays gitignored - nothing this leg fetches is tracked there'

printf '\nOK\n'
