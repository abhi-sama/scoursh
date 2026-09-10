#!/usr/bin/env bash
# tests/suites/bench-b6-labels.sh - the B6 leg: line-granularity scoring, and
# the three hand-authored label sets that are its ground truth.
#
# HERMETIC BY CONSTRUCTION, and the constraint is sharper here than in
# tests/suites/bench.sh.  The B6 corpora - TerraGoat, kubernetes-goat,
# leaky-repo - are fetched into the gitignored bench/corpora/ and are NOT
# present in a fresh checkout, so nothing in this file may read one.  Every
# scoring assertion runs against a tiny hand-authored fixture built in the
# scratch directory with its expected matrix worked out in the comment beside
# it, and every LABEL assertion is a structural property of the label file
# itself: uniqueness, well-formedness, non-overlap, and a rationale on every
# case.  What a label SAYS about a resource is not checkable without the
# corpus and is not claimed to be - that is what the rationale beside each case
# is for, and what a reviewer spot-checks.
#
# WHY THE STRUCTURAL PROPERTIES ARE WORTH A TEST AT ALL.  Two of them are the
# difference between a score and a wrong score, silently:
#
#   * OVERLAPPING RANGES in one file would let a single finding flag two cases,
#     which inflates recall and FPR together and shows up in no total.
#   * A DUPLICATE CASE ID is refused by truth_load, so it fails loudly - but a
#     case with NO rationale comment above it fails silently, by being a
#     label nobody can audit, which is the one thing these files exist to
#     prevent.
#
# SC2016: prose and markdown code spans quote shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh is sourced ONLY for its scratch directory - bench/ never sources
# anything under lib/, which tests/suites/bench.sh section G asserts.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

BENCH=$ROOT/bench
W=$SCOURSH_SCRATCH/bench-b6-suite
rm -rf "$W"
mkdir -p "$W"

US=$'\x1f'

# assert_cond MSG CMD... - assert a command SUCCEEDS, run in THIS shell.
#
# tests/lib/assert.sh's `assert_status` runs its command in a SUBSHELL, which
# is right for a status check and wrong whenever the command must also
# populate this shell's arrays.  tests/suites/bench.sh defines the same helper
# for the same reason.
assert_cond() {
  local msg=$1
  shift
  local rc=0
  "$@" || rc=$?
  assert_eq 0 "$rc" "$msg"
}

# shellcheck source=bench/lib/json.sh
source "$BENCH/lib/json.sh"
# shellcheck source=bench/lib/normalise.sh
source "$BENCH/lib/normalise.sh"
# shellcheck source=bench/lib/truth.sh
source "$BENCH/lib/truth.sh"
# shellcheck source=bench/lib/score.sh
source "$BENCH/lib/score.sh"

cwe_classes_load "$BENCH/cwe-classes.conf"

rec() { printf '%s%s%s%s%s%s%s%s%s%s%s\n' "$1" "$US" "$2" "$US" "$3" "$US" "$4" "$US" "$5" "$US" "$6"; }

# ===========================================================================
printf -- '\n-- A. the truth format grew a sixth field, and the old shape still parses --\n'
# ===========================================================================

# A FIVE-FIELD ROW MUST STILL LOAD UNCHANGED.  Every truth file bench/ has
# produced so far - every OWASP Benchmark sample, and therefore the committed
# B4 scorecards - is five fields, so a sixth variable that swallowed the fifth
# would silently invalidate a landed leg.
{
  printf '%s%s%s%s%s%s%s%s%s\n' 'c1' "$US" 'a.java' "$US" 'sqli' "$US" '89' "$US" 'true'
  printf '%s%s%s%s%s%s%s%s%s\n' 'c2' "$US" 'b.java' "$US" 'sqli' "$US" '89' "$US" 'false'
} >"$W/five-field"
assert_status 0 'a five-field truth file still loads' truth_load "$W/five-field"
truth_load "$W/five-field"
assert_eq 'true' "${BENCH_TRUTH_REAL[c1]}" '`real` is the bare word, not `true<US>…` - a five-variable read over a six-field row would have made it the latter'
assert_eq '' "${BENCH_TRUTH_LINE[c1]:-}" 'and the absent sixth field is empty, not unset-and-unbound'

{
  rec r1 f.tf terraform-aws '' true 10-20
  rec r2 f.tf terraform-aws '' false 30
} >"$W/six-field"
truth_load "$W/six-field"
assert_eq '10-20' "${BENCH_TRUTH_LINE[r1]}" 'a range is kept verbatim'
assert_eq '30' "${BENCH_TRUTH_LINE[r2]}" 'and a bare line number is a range of one'

t_case 'a malformed range is REFUSED, not dropped to empty'
# Dropping it would demote the row to file-level matching under --match line,
# which credits every tool for every other case in the same file - an
# inflation no total in the scorecard reveals.
rec bad f.tf terraform-aws '' true '10..20' >"$W/bad-range"
assert_status 2 'a `10..20` range is exit 2' truth_load "$W/bad-range"
rec bad2 f.tf terraform-aws '' true 'x' >"$W/bad-range2"
assert_status 2 'a non-numeric range is exit 2' truth_load "$W/bad-range2"

# ===========================================================================
printf -- '\n-- B. line granularity, worked out by hand --\n'
# ===========================================================================

# THE FIXTURE, and every expected cell computed in this comment so a reader
# verifies the scorer by arithmetic rather than by trusting it.
#
#   one file, main.tf, four cases that do not overlap:
#     A  lines  1-10   real     tool reports 4   -> inside A
#     B  lines 11-20   real     tool reports nothing in 11-20
#     C  lines 21-30   clean    tool reports 25  -> inside C
#     D  lines 31-40   clean    tool reports nothing
#
#   line granularity : TP=1 (A)  FN=1 (B)  FP=1 (C)  TN=1 (D)
#   file granularity : the tool reported SOMETHING in main.tf, so every case
#                      in it is flagged: TP=2  FN=0  FP=2  TN=0
#
# The second row is the whole reason --match exists: on a corpus with many
# cases per file, file granularity turns one finding into a clean sweep.
{
  rec A main.tf terraform-aws '' true 1-10
  rec B main.tf terraform-aws '' true 11-20
  rec C main.tf terraform-aws '' false 21-30
  rec D main.tf terraform-aws '' false 31-40
} >"$W/gran-truth"
{
  printf '{"tool":"t","version":"v","corpus":"c","file":"main.tf","line":4,"cwe":null,"severity":"high","rule_id":"R1"}\n'
  printf '{"tool":"t","version":"v","corpus":"c","file":"main.tf","line":25,"cwe":null,"severity":"high","rule_id":"R2"}\n'
} >"$W/gran.jsonl"

truth_load "$W/gran-truth"
findings_load "$W/gran.jsonl" any

score_category terraform-aws loose line 0
t_case 'line granularity scores each case from its OWN range'
assert_eq 1 "$BENCH_TP" 'TP: only case A contains a finding'
assert_eq 1 "$BENCH_FN" 'FN: case B contains none'
assert_eq 1 "$BENCH_FP" 'FP: case C contains one and is labelled clean'
assert_eq 1 "$BENCH_TN" 'TN: case D contains none'

score_category terraform-aws loose file 0
t_case 'file granularity is the reading --match line exists to replace, and this pins the difference'
assert_eq 2 "$BENCH_TP" 'TP: BOTH real cases, because the tool reported something somewhere in the file'
assert_eq 0 "$BENCH_FN" 'FN: none - the sweep leaves nothing unflagged'
assert_eq 2 "$BENCH_FP" 'FP: BOTH clean cases too'
assert_eq 0 "$BENCH_TN" 'TN: none.  One finding, four cases flagged.'

t_case 'the window widens a range on both sides, and a big enough one reaches into the NEXT case'
# This is why --line-window defaults to 0, and the arithmetic is the argument.
# Case B is 11-20.  With a window of w its range becomes [11-w, 20+w].  The two
# findings are at line 4 (inside case A) and line 25 (inside case C).
#
#   w = 4  ->  B spans [7, 24].  Neither 4 nor 25 is in it.   TP = 1 (A only)
#   w = 5  ->  B spans [6, 25].  25 IS in it - and 25 is case C's finding.
#              TP = 2, and the second one is B being credited for something
#              that happened in a different labelled case.
#
# A window is not free padding: past a certain size it merges neighbours, and
# the ranges in the B6 label sets are real extents rather than anchors, so they
# need none.
score_category terraform-aws loose line 4
assert_eq 1 "$BENCH_TP" 'a window of 4 leaves each case scored from its own findings'
score_category terraform-aws loose line 5
assert_eq 2 "$BENCH_TP" "a window of 5 makes case B swallow the finding that belongs to case C - the hazard, measured"

t_case 'a finding with NO line matches no range, and is counted rather than dropped'
printf '{"tool":"t","version":"v","corpus":"c","file":"main.tf","line":null,"cwe":null,"severity":"high","rule_id":"R3"}\n' >"$W/noline.jsonl"
findings_load "$W/noline.jsonl" any
assert_eq 1 "$BENCH_FINDING_COUNT" 'the record is kept'
assert_eq 1 "$BENCH_FINDING_NO_LINE" 'and counted as line-less, which is what the scorecard reports'
score_category terraform-aws loose line 0
assert_eq 0 "$BENCH_TP" 'it flags nothing under line granularity'
score_category terraform-aws loose file 0
assert_eq 2 "$BENCH_TP" 'while under file granularity it flags the whole file - the two readings really do differ for it'

# ===========================================================================
printf -- '\n-- C. strict matching under line granularity, and the no-CWE case --\n'
# ===========================================================================

# Same shape as section B, but with CWEs, so strict has something to consult:
#   E  1-10  real  cwe 89   tool reports 89 at line 4      -> strict hit
#   F 11-20  real  cwe 327  tool reports 22 at line 15     -> loose hit, strict miss
{
  rec E s.java sqli 89 true 1-10
  rec F s.java crypto 327 true 11-20
} >"$W/strict-truth"
{
  printf '{"tool":"t","version":"v","corpus":"c","file":"s.java","line":4,"cwe":"89","severity":"high","rule_id":"R1"}\n'
  printf '{"tool":"t","version":"v","corpus":"c","file":"s.java","line":15,"cwe":"22","severity":"high","rule_id":"R2"}\n'
} >"$W/strict.jsonl"
truth_load "$W/strict-truth"
findings_load "$W/strict.jsonl" any

score_category sqli strict line 0
assert_eq 1 "$BENCH_TP" 'strict + line: the CWE matches inside the range'
score_category crypto loose line 0
assert_eq 1 "$BENCH_TP" 'loose + line: the finding is inside the range'
score_category crypto strict line 0
assert_eq 0 "$BENCH_TP" 'strict + line: CWE-22 is not in CWE-327 class, so the same finding does not count'

t_case 'a class MEMBER still matches under line granularity'
printf '{"tool":"t","version":"v","corpus":"c","file":"s.java","line":15,"cwe":"326","severity":"high","rule_id":"R3"}\n' >"$W/strict2.jsonl"
findings_load "$W/strict2.jsonl" any
score_category crypto strict line 0
assert_eq 1 "$BENCH_TP" 'CWE-326 and CWE-327 share a class in bench/cwe-classes.conf'

t_case 'a category whose truth carries NO cwe is reported as such, never as zeros'
# This is the whole B6 IaC and secrets situation: the labels are per-resource
# and per-credential and carry no CWE, so strict is undefined for them.  A row
# of zeros would read as "every tool missed every case", which is the single
# most misleading thing this scorer could print.
truth_load "$W/gran-truth"
assert_status 1 'terraform-aws in the B6-shaped fixture carries no CWE' truth_category_has_cwe terraform-aws
truth_load "$W/strict-truth"
assert_status 0 'sqli in the CWE-bearing fixture does' truth_category_has_cwe sqli

# ===========================================================================
printf -- '\n-- D. findings_unscored: how much of a tool the labels declined to judge --\n'
# ===========================================================================

# THIS NUMBER IS PUBLISHED, NOT DIAGNOSTIC.  A partial label set neither
# credits nor penalises a finding outside it, which is right - and it is also
# the one place a benchmark could shrink a tool's exposure by labelling only
# where it does well.  Reporting the size of the unjudged remainder is what
# makes that visible.
truth_load "$W/gran-truth"
{
  printf '{"tool":"t","version":"v","corpus":"c","file":"main.tf","line":4,"cwe":null,"severity":"high","rule_id":"R1"}\n'
  printf '{"tool":"t","version":"v","corpus":"c","file":"main.tf","line":99,"cwe":null,"severity":"high","rule_id":"R2"}\n'
  printf '{"tool":"t","version":"v","corpus":"c","file":"other.tf","line":1,"cwe":null,"severity":"high","rule_id":"R3"}\n'
} >"$W/unscored.jsonl"
findings_load "$W/unscored.jsonl" any
findings_unscored
assert_eq 2 "$BENCH_FINDING_UNSCORED" 'line 99 is past every range in main.tf, and other.tf carries no case at all'

# ===========================================================================
printf -- '\n-- E. bench/score.sh refuses --match line without ranges --\n'
# ===========================================================================

t_case 'a truth file with no ranges under --match line is exit 2, not silently demoted'
# Silent demotion would print the INFLATED file-granularity numbers under a
# heading naming a granularity they were not computed at.
mkdir -p "$W/res/toolX"
cp "$W/gran.jsonl" "$W/res/toolX/normalised.jsonl"
printf 'claims-categories: sqli\n' >"$W/res/toolX/MANIFEST"
assert_status 2 'no range on any case is a refusal' \
  bash "$BENCH/score.sh" --truth "$W/five-field" --results "$W/res" --match line
assert_status 2 'a bad --match value is a refusal' \
  bash "$BENCH/score.sh" --truth "$W/gran-truth" --results "$W/res" --match resource
assert_status 2 'a negative --line-window is a refusal' \
  bash "$BENCH/score.sh" --truth "$W/gran-truth" --results "$W/res" --match line --line-window -1

t_case 'the default granularity is `file`, so every landed leg scores as it did before'
out=$(bash "$BENCH/score.sh" --truth "$W/five-field" --results "$W/res" --format md)
assert_contains "$out" 'Matching granularity: `file`' 'the default is stated in the scorecard rather than left to be assumed'

t_case 'a line-granularity scorecard states its granularity AND its window'
printf 'claims-categories: terraform-aws\n' >"$W/res/toolX/MANIFEST"
out=$(bash "$BENCH/score.sh" --truth "$W/gran-truth" --results "$W/res" --match line --format md)
assert_contains "$out" 'Matching granularity: `line`' 'named'
assert_contains "$out" 'window 0' 'and the window, because a window silently >0 changes every number'
assert_contains "$out" 'no CWE in truth' 'and the strict column says why it is empty rather than printing zeros'
assert_contains "$out" 'outside every labelled range' 'and the unjudged remainder is a published column'

t_case 'the JSON renderer marks the no-CWE case structurally, not in prose'
out=$(bash "$BENCH/score.sh" --truth "$W/gran-truth" --results "$W/res" --match line --format json)
assert_contains "$out" '"coverage": "no_cwe_in_truth"' 'a consumer can tell it from a scored cell without reading English'
assert_contains "$out" '"match": "line"' 'and the granularity travels with the numbers'
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$out" >"$W/sc.json"
  assert_status 0 'and the document parses under a conforming parser' \
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$W/sc.json"
fi

# ===========================================================================
printf -- '\n-- F. the three committed label sets --\n'
# ===========================================================================

# STRUCTURAL PROPERTIES ONLY - see this file's header for why.  These run
# against the label files themselves, which ARE committed, and never against a
# corpus, which is not.
LABELS=$ROOT/bench/labels
for lf in terragoat-aws kubernetes-goat leaky-repo; do
  f=$LABELS/$lf.truth
  t_case "bench/labels/$lf.truth loads, and every case carries a range"
  assert_file_exists "$f" 'the label file is committed - it IS the ground truth'
  assert_status 0 "$lf loads" truth_load "$f"
  truth_load "$f"
  n_rangeless=0
  for c in "${BENCH_TRUTH_CASES[@]}"; do
    [[ -n ${BENCH_TRUTH_LINE[$c]:-} ]] || n_rangeless=$(( n_rangeless + 1 ))
  done
  assert_eq 0 "$n_rangeless" 'every case has a line range, which is what --match line requires'

  t_case "bench/labels/$lf.truth has BOTH real and clean cases"
  nreal=0 nclean=0
  for c in "${BENCH_TRUTH_CASES[@]}"; do
    if [[ ${BENCH_TRUTH_REAL[$c]} == true ]]; then nreal=$(( nreal + 1 )); else nclean=$(( nclean + 1 )); fi
  done
  # A label set with no clean cases makes FPR - and therefore Youden J -
  # unmeasurable, and leaves recall as the only number, which a rule that
  # flags everything scores 100% on.
  assert_cond 'at least one genuinely-misconfigured case' test "$nreal" -gt 0
  assert_cond 'at least one correctly-configured case, or FPR is not measurable' test "$nclean" -gt 0

  t_case "bench/labels/$lf.truth: no two ranges in one file overlap"
  # An overlap lets ONE finding flag TWO cases, inflating recall and FPR
  # together in a way no total in the scorecard reveals.
  overlaps=$(
    awk -F"$US" '
      /^#/ || NF < 6 { next }
      {
        split($6, r, "-")
        s = r[1] + 0; e = (r[2] == "" ? s : r[2] + 0)
        printf "%s\t%d\t%d\t%s\n", $2, s, e, $1
      }
    ' "$f" | LC_ALL=C sort -t$'\t' -k1,1 -k2,2n | awk -F'\t' '
      $1 == pf && $2 <= pe { printf "%s:%s/%s ", $1, pc, $4 }
      { pf = $1; pe = $3; pc = $4 }
    '
  )
  assert_eq '' "$overlaps" 'overlapping ranges in one file'

  t_case "bench/labels/$lf.truth: every case has a rationale comment above it"
  # A label nobody can audit is the one thing these files exist to prevent, and
  # unlike a duplicate id it fails SILENTLY - truth_load accepts it happily.
  norationale=$(
    awk -F"$US" '
      /^#/ { c = 1; next }
      NF >= 6 { if (!c) printf "%s ", $1; c = 0; next }
      { c = 0 }
    ' "$f"
  )
  assert_eq '' "$norationale" 'case(s) with no comment line immediately above them'
done

t_case 'the label sets carry no CWE, which is a decision the scorer has to see'
for lf in terragoat-aws kubernetes-goat leaky-repo; do
  truth_load "$LABELS/$lf.truth"
  for cat in "${BENCH_TRUTH_CATS[@]}"; do
    assert_status 1 "$lf/$cat carries no ground-truth CWE, so strict renders as an explicit cell" \
      truth_category_has_cwe "$cat"
  done
done

t_case 'each label set declares exactly one category, and it is the one its corpus.lock row names'
declare -A want=( [terragoat-aws]=terraform-aws [kubernetes-goat]=kubernetes [leaky-repo]=secrets )
for lf in terragoat-aws kubernetes-goat leaky-repo; do
  truth_load "$LABELS/$lf.truth"
  assert_eq 1 "${#BENCH_TRUTH_CATS[@]}" "$lf declares one category"
  assert_eq "${want[$lf]}" "${BENCH_TRUTH_CATS[0]}" "$lf's category matches bench/corpus.lock"
done

# ===========================================================================
printf -- '\n-- G. the B6 adapters, and the committed results --\n'
# ===========================================================================

t_case 'every B6 adapter defines the five contract functions under the id run-tool.sh dispatches on'
# bench/run-tool.sh calls "${tool}_available" with the tool id VERBATIM, hyphens
# included - so an adapter whose file is `trivy-config.sh` but whose functions
# are `trivy_config_*` is refused at run time with `command not found`, which
# run-tool.sh reports as "tool not available here".  Measured: three of these
# five shipped that way first and every one of them was refused.
for tool in scoursh-iac scoursh-secrets checkov kics trivy-config gitleaks trufflehog; do
  assert_file_exists "$BENCH/tools/$tool.sh" "bench/tools/$tool.sh exists"
  ( # a subshell per adapter: they are meant to be sourced one at a time
    # shellcheck source=/dev/null
    source "$BENCH/tools/$tool.sh"
    for fn in available version scope run normalise; do
      declare -F "${tool}_${fn}" >/dev/null ||
        { printf 'MISSING %s_%s\n' "$tool" "$fn"; exit 1; }
    done
  ) >"$W/fn-$tool.txt" 2>&1
  assert_eq 0 $? "$tool defines all five under its own hyphenated id"
done

t_case 'every B6 tool has a gate line in run-tool.sh, so no MANIFEST reads `unrecorded`'
# R5: a manifest that omits the configuration lets a later reader assume
# whichever one flatters the conclusion they already hold.
gates=$(sed -n '/^_gate_line()/,/^}/p' "$BENCH/run-tool.sh")
for tool in scoursh-iac scoursh-secrets checkov kics trivy-config gitleaks trufflehog; do
  assert_contains "$gates" "$tool)" "_gate_line has a row for $tool"
done

t_case 'the committed B6 results carry a MANIFEST, a normalised stream and a scorecard'
for d in b6-iac-terragoat-aws b6-iac-kubernetes-goat b6-secrets-leaky-repo; do
  assert_file_exists "$ROOT/bench/results/$d/README.md" "$d states what it is"
  assert_file_exists "$ROOT/bench/results/$d/scorecard-all-findings.md" "$d has a rendered scorecard"
  assert_file_exists "$ROOT/bench/results/$d/scorecard-all-findings.json" "$d has the machine-readable one"
done

t_case 'every committed B6 MANIFEST names a version AND a pinned corpus commit'
# bench/README.md rule 3: no number without both.
bad=''
while IFS= read -r m; do
  grep -q '^version: .' "$m" || bad+="${m#"$ROOT/"}(version) "
  grep -qE '^corpus-commit: [0-9a-f]{40}$' "$m" || bad+="${m#"$ROOT/"}(commit) "
  grep -q '^gate: ' "$m" || bad+="${m#"$ROOT/"}(gate) "
done < <(find "$ROOT/bench/results" -path '*b6-*' -name MANIFEST)
assert_eq '' "$bad" 'MANIFEST(s) missing a version, a 40-hex corpus commit, or a gate line'

t_case 'no committed B6 normalised record carries a secret value'
# The secrets adapters deliberately emit the rule id and the line and nothing
# else: Gitleaks reports the matched bytes in `Secret`/`Match` and TruffleHog in
# `Raw`/`Redacted`, and the normalised stream is committed to this repository.
# The raw output beside it is what an auditor reads; see that leg's README.
leaks=''
for f in "$ROOT"/bench/results/b6-secrets-leaky-repo/*/normalised.jsonl; do
  [[ -e $f ]] || continue
  grep -qE '"(Secret|Raw|Redacted|Match)"' "$f" && leaks+="${f#"$ROOT/"} "
done
assert_eq '' "$leaks" 'a normalised record echoing a matched-secret field from a tool'"'"'s own JSON' 

t_case 'the JSON scorecards parse under a conforming parser'
if command -v python3 >/dev/null 2>&1; then
  for d in b6-iac-terragoat-aws b6-iac-kubernetes-goat b6-secrets-leaky-repo; do
    assert_status 0 "$d/scorecard-all-findings.json parses" \
      python3 -c 'import json,sys; json.load(open(sys.argv[1]))' \
      "$ROOT/bench/results/$d/scorecard-all-findings.json"
  done
else
  printf 'SKIPPED: no python3 for the JSON conformance check\n'
fi

t_summary bench-b6-labels
