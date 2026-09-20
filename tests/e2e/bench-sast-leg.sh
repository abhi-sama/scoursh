#!/usr/bin/env bash
# tests/e2e/bench-sast-leg.sh - end-to-end proof for the B4 SAST leg: real
# scoursh, real Semgrep at BOTH declared gate configurations, and the B3
# scorer, run over a real (small, fast) sample of the pinned OWASP Benchmark
# corpus - then the scorecard is checked for the SHAPE the B4 leg promises,
# not for a specific score.
#
# NOT part of tests/run-tests.sh's default suite list, for the same reason
# tests/e2e/dast-target-smoke.sh is not: it needs the corpus fetched
# (bench/fetch-corpus.sh owasp-benchmark - the one network-touching step in
# all of bench/, per bench/README.md) and a real `semgrep` binary on PATH,
# neither of which an air-gapped test host has. It skips cleanly, rather than
# failing, when either is absent - "did not run" and "ran and passed" must
# stay two different, visible facts here as much as anywhere else in this
# project. Run it by hand:
#
#   bench/fetch-corpus.sh owasp-benchmark   # once; the only network step
#   bash tests/e2e/bench-sast-leg.sh
#
# WHAT THIS DOES AND DOES NOT PIN. tests/suites/bench.sh (the default,
# hermetic suite) already proves the harness's LIBRARIES against fixed,
# hand-checked, or committed-real-output fixtures - that is where a specific
# TP/FN/FP/TN belongs, and it is bounded, reproducible arithmetic that never
# depends on a corpus fetch. This file proves the opposite half: that
# `bench/run-tool.sh` and `bench/score.sh`, wired together, running REAL
# scoursh and REAL Semgrep at both gate configurations against a REAL sample
# of the pinned corpus, produce the table B4's methodology promises - every
# tool row present with its own version/commit/gate, no-coverage cells never
# silently zeroed, strict/loose agreement reported, and Youden J printed with
# its coin-flip baseline. A sample this small (single digits of cases per
# category) is not asserted on for a specific recall number: at n=6 a single
# case flips a rate by double digits, so a number-exact assertion here would
# be pinning sampling noise, not the pipeline. The full-corpus numbers this
# leg actually produces are committed, separately, under
# bench/results/b4-sast-owasp-full/.
#
# The two Semgrep gate rows (bench/tools/semgrep-default.sh and
# bench/tools/semgrep.sh) are exactly what this file exists to exercise
# together: tests/suites/bench.sh section H tests each adapter's contract in
# isolation against a committed fixture, but neither proves the two produce
# genuinely different, genuinely gate-labelled columns when actually run back
# to back - which is the B4 methodology's rule R5 in the flesh.
#
# SC2016: assertion prose quotes shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BENCH=$ROOT/bench
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

CORPUS_DIR=$BENCH/corpora/owasp-benchmark
if [[ ! -d $CORPUS_DIR ]]; then
  printf 'SKIPPED: %s not fetched - run: bench/fetch-corpus.sh owasp-benchmark\n' "$CORPUS_DIR"
  exit 0
fi
if ! command -v semgrep >/dev/null 2>&1; then
  printf 'SKIPPED: no semgrep on PATH\n'
  exit 0
fi

# A tmp dir of our own, never $SCOURSH_SCRATCH: bench/ is a separate harness
# that sources nothing under lib/ (tests/suites/bench.sh section G), so this
# file does not either, and lib/core.sh's scratch dir is exactly the thing
# that separation excludes.
W=$(mktemp -d "${TMPDIR:-/tmp}/bench-sast-leg.XXXXXX")
trap 'rm -rf "${W:?}"' EXIT

SAMPLE=e2e-sast-leg
# Small on purpose (§ header above): two categories, three real plus three
# sanitized-trap cases each - twelve files total, so scoursh's ~38s fixed
# startup dominates and the whole run stays well inside a couple of minutes,
# while both tools still see at least one real and one trap case per
# category to score against.
env BENCH_CORPORA_DIR="$BENCH/corpora" \
  bash "$BENCH/make-sample.sh" owasp-benchmark "$SAMPLE" \
  --per-class 3 --categories 'sqli hash' \
  >"$W/make-sample.out" 2>&1 || {
  cat "$W/make-sample.out" >&2
  printf 'FAIL: bench/make-sample.sh could not build the sample\n'
  exit 1
}

OUT=$W/results
mkdir -p "$OUT"

t_case 'scoursh runs against the sample and exits cleanly'
assert_status 0 'bench/run-tool.sh --tool scoursh' \
  bash "$BENCH/run-tool.sh" --tool scoursh --sample "$SAMPLE" --out "$OUT"

t_case 'Semgrep at its documented default (p/default) runs against the sample'
assert_status 0 'bench/run-tool.sh --tool semgrep-default' \
  bash "$BENCH/run-tool.sh" --tool semgrep-default --sample "$SAMPLE" --out "$OUT"

t_case 'Semgrep at its maximum free ruleset runs against the sample'
assert_status 0 'bench/run-tool.sh --tool semgrep' \
  bash "$BENCH/run-tool.sh" --tool semgrep --sample "$SAMPLE" --out "$OUT"

t_case 'the two Semgrep gate rows recorded genuinely different `gate:` lines'
_gd=$(sed -n 's/^gate: //p' "$OUT/semgrep-default/MANIFEST")
_gm=$(sed -n 's/^gate: //p' "$OUT/semgrep/MANIFEST")
assert_ne "$_gd" "$_gm" \
  'a reader must never have to infer which ruleset a run used (R5) - and here the two really do differ, not just in tool id'
assert_contains "$_gd" 'p/default' 'the documented-default row names p/default'
assert_contains "$_gm" 'p/security-audit' 'the maximum-ruleset row names its broader config'

TRUTH=$BENCH/corpora/_samples/$SAMPLE/truth
SCORE_MD=$W/scorecard.md
SCORE_JSON=$W/scorecard.json

t_case 'the scorer runs over all three tool rows and exits cleanly'
assert_status 0 'bench/score.sh --format md' \
  bash "$BENCH/score.sh" --truth "$TRUTH" --results "$OUT" --format md --out "$SCORE_MD"
bash "$BENCH/score.sh" --truth "$TRUTH" --results "$OUT" --format json --out "$SCORE_JSON"

_md=$(cat "$SCORE_MD")

t_case 'all three tool rows are present, each with its own version and corpus commit'
assert_contains "$_md" '| scoursh | `0.1.0-dev' 'scoursh row, version-stamped (never a bare version nobody can re-run against)'
assert_contains "$_md" '| semgrep-default | `1.176' 'the documented-default Semgrep row'
assert_contains "$_md" '| semgrep | `1.176' 'the maximum-ruleset Semgrep row'
assert_contains "$_md" '20cbf3d11123347e47ed89541e6942836def53f7' 'every row is pinned to the corpus commit this sample was built from'

t_case 'both categories score for all three tools - no unintended no-coverage cell'
# The literal TABLE MARKER, not the substring `no coverage` - the scorecard's
# own boilerplate footer always carries the prose "A `no coverage` cell is
# not a zero" regardless of whether any row actually rendered one, so an
# unqualified substring check would fail on every scorecard this harness ever
# produces, footer included.
assert_not_contains "$_md" '*no coverage*' \
  'sqli and hash are claimed by every tool in this run; a no-coverage table cell here would mean a scope declaration regressed, not a real result'

t_case 'Youden J is printed with its coin-flip baseline stated beside it'
assert_contains "$_md" 'Youden J = TPR - FPR' 'the formula'
assert_contains "$_md" 'J = 0.000 is a coin flip' 'recall alone is not a result - the B4 methodology rule R3'

t_case 'the corpus aggregate names exactly the categories scored, and is labelled as not an overall score'
assert_contains "$_md" '2 of 2' 'both claimed categories fed the aggregate'
assert_contains "$_md" 'It is not comparable with any other corpus, and it is not an overall score.' \
  'a two-category, twelve-file sample must never be mistaken for the B4 headline number'

t_case 'the strict/loose CWE-matching agreement is reported for every tool'
assert_contains "$_md" '## Strict/loose agreement' 'the section renders'
for _tool in scoursh semgrep-default semgrep; do
  assert_contains "$_md" "| $_tool |" "$_tool has an agreement row"
done

if command -v python3 >/dev/null 2>&1; then
  t_case 'the JSON scorecard parses under a conforming parser'
  assert_status 0 'python3 -m json.tool accepts it' python3 -m json.tool "$SCORE_JSON"
else
  printf 'SKIPPED: no python3 - the conforming-parser check did not run\n'
fi

t_summary bench-sast-leg
