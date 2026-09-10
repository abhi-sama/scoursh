#!/usr/bin/env bash
# tests/suites/bench.sh - the detection-benchmark harness under bench/.
#
# HERMETIC BY CONSTRUCTION.  Nothing here runs a scanner, invokes semgrep,
# fetches a corpus, or touches the network.  Every input is either a committed
# fixture under tests/fixtures/bench/ - real, unedited output from the tools
# themselves - or a tiny hand-authored one built in the scratch directory.
# That is not a convenience: `bench/fetch-corpus.sh` is the only file in the
# harness that reaches the network and the suite must be runnable on the
# air-gapped host scoursh is designed for.
#
# THE HAND-CHECKED SCORING FIXTURE (section E) IS SMALL ON PURPOSE.  Eight
# cases across three categories, with every expected TP/FN/FP/TN worked out in
# the comment beside the assertion, so a reader can verify the scorer by
# arithmetic rather than by trusting it.  A scorer tested only against a real
# corpus is tested against numbers nobody can check.
#
# SC2016: prose and markdown code spans quote shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh is sourced ONLY for its scratch directory - the harness itself
# never sources anything under lib/, which section G asserts.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

BENCH=$ROOT/bench
FIX=$ROOT/tests/fixtures/bench
W=$SCOURSH_SCRATCH/bench-suite
rm -rf "$W"
mkdir -p "$W"

US=$'\x1f'

# The three libraries under test.  Sourced directly, which is also the proof
# they are usable without any scanner file beyond this suite's own scratch
# dependency.
# shellcheck source=bench/lib/json.sh
source "$BENCH/lib/json.sh"
# shellcheck source=bench/lib/normalise.sh
source "$BENCH/lib/normalise.sh"
# shellcheck source=bench/lib/corpus.sh
source "$BENCH/lib/corpus.sh"
# shellcheck source=bench/lib/truth.sh
source "$BENCH/lib/truth.sh"
# shellcheck source=bench/lib/score.sh
source "$BENCH/lib/score.sh"

# vis - render 0x1f as a visible pipe so an assertion message is readable.
vis() { printf '%s' "${1//$US/|}"; }

# assert_cond MSG CMD... - assert a command SUCCEEDS, run in THIS shell.
#
# tests/lib/assert.sh's own `assert_true` takes a STATUS rather than a
# condition, and `assert_status` runs its command in a SUBSHELL - which is the
# wrong tool for `declare -F`, where the question is about this shell's own
# function table.  This runs the condition in-process and converts it.
assert_cond() {
  local msg=$1
  shift
  local rc=0
  "$@" || rc=$?
  assert_eq 0 "$rc" "$msg"
}

# ===========================================================================
printf -- '\n-- A. the JSON reader --\n'
# ===========================================================================

t_case 'a leaf carries its JSON TYPE, so a null and the string "null" differ'
flat=$(printf '%s' '{"a":null,"b":"null","c":0,"d":false}' | bench_json_flatten)
assert_contains "$flat" "a${US}z${US}" 'a JSON null flattens with type z'
assert_contains "$flat" "b${US}s${US}null" 'the string "null" flattens with type s and its text'
assert_contains "$flat" "c${US}n${US}0" 'a number flattens with type n'
assert_contains "$flat" "d${US}b${US}false" 'a boolean flattens with type b'

t_case 'a JSON null and an EMPTY STRING flatten to the same value and differ only by type'
flat2=$(printf '%s' '{"a":null,"e":""}' | bench_json_flatten)
bench_flat_read <<<"$flat2"
assert_eq "${BENCH_FLAT[a]}" "${BENCH_FLAT[e]}" 'their VALUES are byte-identical, so no value-based reader can ever separate them'
assert_ne "${BENCH_FLAT_TYPE[a]}" "${BENCH_FLAT_TYPE[e]}" 'only the type column does - which is why it exists'
assert_eq '' "$(bench_flat_str a)" 'flat_str declines the null'
assert_eq '' "$(bench_flat_str e)" 'and returns the empty string for the empty string'

t_case 'a type-blind numeric read would hand a STRING to a numeric comparison'
bench_flat_read <<<"$flat"
assert_eq '' "$(bench_flat_num b)" 'bench_flat_num refuses the string "null" - FAILS under an implementation that returns the value whatever its type, which would then be compared as a number'
assert_eq 'null' "$(bench_flat_str b)" 'while flat_str returns it, because it really is a string'
assert_eq '0' "$(bench_flat_num c)" 'the number 0 IS returned, not treated as absent - an emptiness test would drop every legitimate zero'

t_case 'nested objects and arrays give indexed paths'
flat=$(printf '%s' '{"r":[{"p":"x.java","s":{"line":42}},{"p":"y.java"}]}' | bench_json_flatten)
assert_contains "$flat" "r/0/p${US}s${US}x.java" 'first array element'
assert_contains "$flat" "r/0/s/line${US}n${US}42" 'nested object under an array element'
assert_contains "$flat" "r/1/p${US}s${US}y.java" 'second array element'

t_case 'an EMPTY container is still a leaf - "reported nothing" is not "wrote nothing"'
flat=$(printf '%s' '{"findings":[],"meta":{}}' | bench_json_flatten)
assert_contains "$flat" "findings${US}a${US}" 'an empty array emits a leaf'
assert_contains "$flat" "meta${US}o${US}" 'an empty object emits a leaf'

t_case 'string escapes are unescaped, including \u and a surrogate pair'
flat=$(printf '%s' '{"q":"a\"b","bs":"a\\b","t":"a\tb","u":"caf\u00e9","cjk":"\u4e2d","emo":"\ud83d\ude00","lit":"\u00e9 and a literal é"}' | bench_json_flatten)
assert_contains "$flat" 'q'"$US"'s'"$US"'a"b' 'an escaped quote survives'
assert_contains "$flat" 'bs'"$US"'s'"$US"'a\b' 'an escaped backslash survives'
assert_contains "$flat" "u${US}s${US}café" '\\u00e9 decodes to the two UTF-8 bytes of é'
assert_contains "$flat" "cjk${US}s${US}中" '\\u4e2d decodes to the three UTF-8 bytes of 中'
assert_contains "$flat" "emo${US}s${US}😀" 'a surrogate PAIR \\ud83d\\ude00 recombines into ONE scalar - the input is escaped rather than literal on purpose, because a literal emoji never enters the \\u path at all and would pass under an implementation that ignores the low half'
assert_contains "$flat" "lit${US}s${US}é and a literal é" 'an escape and a literal in one string both survive'

t_case 'a 0x1f inside a value cannot forge a column'
flat=$(printf '%s' "{\"a\":\"x${US}y\"}" | bench_json_flatten)
assert_eq "a${US}s${US}xy" "$flat" 'the separator byte is stripped from the value, so the record still has exactly three columns'

t_case 'a top-level ARRAY document parses (the gitleaks output shape)'
flat=$(printf '%s' '[{"R":"a"},{"R":"b"}]' | bench_json_flatten)
assert_contains "$flat" "0/R${US}s${US}a" 'index 0'
assert_contains "$flat" "1/R${US}s${US}b" 'index 1'

t_case 'bench_flat_read survives a TOP-LEVEL empty array/object without crashing'
# `[]` at the document root is the same "wrote nothing" vs "found nothing"
# shape section A pins for a NESTED empty container, but here the emitted
# leaf's own path is EMPTY (bench_json_flatten's root marker) - and bash
# refuses an empty string as an associative-array subscript on EITHER side
# of an assignment, quoted or not (`declare -gA a=(); x=''; a[$x]=v` and
# `a["$x"]=v` are both `bad array subscript`, measured directly rather than
# assumed).  A caller normalising a tool run that found literally nothing in
# one file - the ordinary shape of a benchmark corpus's own sanitized-trap
# half - hits this on every such file, so this has to survive rather than
# merely produce the right leaf text.
flat=$(printf '%s' '[]' | bench_json_flatten)
assert_cond 'bench_flat_read does not abort under set -e on a root-level empty array' bash -c '
  set -Eeuo pipefail
  source "'"$BENCH"'/lib/json.sh"
  source "'"$BENCH"'/lib/normalise.sh"
  bench_flat_read <<<"$1"
' _ "$flat"
flat2=$(printf '%s' '{}' | bench_json_flatten)
assert_cond 'and the identical root-level empty OBJECT shape' bash -c '
  set -Eeuo pipefail
  source "'"$BENCH"'/lib/json.sh"
  source "'"$BENCH"'/lib/normalise.sh"
  bench_flat_read <<<"$1"
' _ "$flat2"

t_case 'bench_json_string escapes what RFC 8259 requires and nothing else'
assert_eq 'a\"b' "$(bench_json_string 'a"b')" 'a quote is escaped'
assert_eq 'a\\b' "$(bench_json_string 'a\b')" 'a backslash is escaped'
assert_eq 'x\u0001y' "$(bench_json_string "$(printf 'x\001y')")" 'a bare C0 control becomes \u00XX - a raw one would make the line unparseable'
assert_eq 'café' "$(bench_json_string 'café')" 'UTF-8 above 0x7f passes through untouched'

# ===========================================================================
printf -- '\n-- B. CWE normalisation and equivalence classes --\n'
# ===========================================================================

t_case 'every spelling a real tool uses reduces to the bare number'
assert_eq '89' "$(bench_cwe_number '89')" 'bare'
assert_eq '89' "$(bench_cwe_number 'CWE-89')" 'scoursh finding JSON'
assert_eq '22' "$(bench_cwe_number "CWE-22: Improper Limitation of a Pathname ('Path Traversal')")" 'semgrep metadata entry'
assert_eq '327' "$(bench_cwe_number 'cwe-327')" 'lowercased'
assert_eq '' "$(bench_cwe_number 'none')" 'a string carrying no CWE yields empty, NOT 0 - class 0 would strict-match every CWE-less case against every other'
assert_eq '' "$(bench_cwe_number '')" 'and so does the empty string'

t_case 'the shipped class table loads and a listed CWE maps to its class'
cwe_classes_load "$BENCH/cwe-classes.conf"
assert_eq "$(cwe_class 327)" "$(cwe_class 326)" '326 and 327 are one class'
assert_eq "$(cwe_class 327)" "$(cwe_class 328)" '328 joins them'
assert_eq "$(cwe_class 330)" "$(cwe_class 338)" '330 and 338 are one class'
assert_eq "$(cwe_class 22)" "$(cwe_class 36)" '22 and 36 are one class'

t_case 'an UNLISTED CWE is its own singleton, and does not collide with another'
assert_eq '89' "$(cwe_class 89)" 'an unlisted CWE maps to itself'
assert_ne "$(cwe_class 89)" "$(cwe_class 90)" 'two unlisted CWEs stay distinct - FAILS under an implementation that folds every unknown into one bucket'
assert_ne "$(cwe_class 89)" "$(cwe_class 327)" 'and an unlisted one never joins a listed class'

t_case 'a CWE in TWO classes is refused, not silently resolved by file order'
printf '1 2\n2 3\n' >"$W/bad-classes.conf"
assert_status 2 'a CWE appearing in two classes is exit 2' cwe_classes_load "$W/bad-classes.conf"
cwe_classes_load "$BENCH/cwe-classes.conf"   # restore for later sections

# ===========================================================================
printf -- '\n-- C. the corpus lock reader --\n'
# ===========================================================================

t_case 'the shipped lock file loads and every corpus carries a full pin'
corpus_load "$BENCH/corpus.lock"
assert_cond 'at least the two B2 corpora are declared' test "${#BENCH_CORPUS_IDS[@]}" -ge 2
for _c in "${BENCH_CORPUS_IDS[@]}"; do
  _sha=$(corpus_field "$_c" commit)
  assert_eq 40 "${#_sha}" "corpus $_c is pinned to a 40-character sha"
  assert_eq '' "${_sha//[0-9a-f]/}" "corpus $_c's pin is all lower-case hex - a branch name or an abbreviation leaves residue here"
  assert_ne '' "$(corpus_field "$_c" licence)" "corpus $_c states a licence"
done

t_case 'a repeated key accumulates and a two-space continuation line appends'
_note=$(corpus_field owasp-benchmark note)
assert_contains "$_note" 'machine-readable' 'the multi-line note survived its two-space continuation lines'
assert_contains "$_note" 'GPL-2.0' 'and the SECOND note record is kept too, not overwritten by the first'

t_case 'a BRANCH NAME where a sha belongs is refused - a moving target that looks pinned'
cat >"$W/branch.lock" <<'EOF'
id: x
repo: https://example.invalid/x.git
commit: master
licence: MIT
ground-truth: none
categories: y
EOF
assert_status 2 'a non-sha commit is exit 2' corpus_load "$W/branch.lock"

t_case 'an ABBREVIATED sha is refused too - it is ambiguous over a repository lifetime'
sed 's/^commit: master/commit: 20cbf3d/' "$W/branch.lock" >"$W/abbrev.lock"
assert_status 2 'a 7-hex commit is exit 2' corpus_load "$W/abbrev.lock"

t_case 'an UNSTATED licence is refused rather than assumed permissive'
sed -e 's/^commit: master/commit: 20cbf3d11123347e47ed89541e6942836def53f7/' \
    -e 's/^licence: MIT/licence: unstated/' "$W/branch.lock" >"$W/unstated.lock"
assert_status 2 'an unstated licence is exit 2' corpus_load "$W/unstated.lock"

t_case 'a record not opening with id: is refused rather than folded into its predecessor'
printf 'repo: https://example.invalid/x.git\n' >"$W/noid.lock"
assert_status 2 'a record with no id is exit 2' corpus_load "$W/noid.lock"

t_case 'a missing REQUIRED key is refused - a corpus with no ground-truth row would score as all-miss'
sed '/^ground-truth: /d' "$W/branch.lock" |
  sed 's/^commit: master/commit: 20cbf3d11123347e47ed89541e6942836def53f7/' >"$W/nogt.lock"
assert_status 2 'a missing ground-truth key is exit 2' corpus_load "$W/nogt.lock"

# ===========================================================================
printf -- '\n-- D. the ground-truth reader --\n'
# ===========================================================================

mk_truth() { printf '%s\n' "$@" >"$W/truth"; }

t_case 'a well-formed truth file loads with its categories sorted'
mk_truth \
  "c1${US}f1.java${US}beta${US}89${US}true" \
  "c2${US}f2.java${US}alpha${US}327${US}false"
truth_load "$W/truth"
assert_eq 2 "${#BENCH_TRUTH_CASES[@]}" 'both cases loaded'
assert_eq 'alpha beta' "${BENCH_TRUTH_CATS[*]}" 'categories are LC_ALL=C sorted, so a scorecard row order does not depend on file order'
assert_eq 'f1.java' "${BENCH_TRUTH_FILE[c1]}" 'the file column is kept verbatim'

t_case 'a `real` column that is neither true nor false is REFUSED, never defaulted'
mk_truth "c1${US}f1.java${US}alpha${US}89${US}maybe"
assert_status 2 'an unlabelled case is exit 2 - defaulting it either way silently invents a case, and both directions are hidden by the totals' truth_load "$W/truth"

t_case 'a duplicate case id is refused'
mk_truth "c1${US}f1.java${US}alpha${US}89${US}true" "c1${US}f2.java${US}alpha${US}89${US}false"
assert_status 2 'a repeated case id is exit 2' truth_load "$W/truth"

t_case 'the OWASP adapter skips the header by its COMMENT, not by a line count'
cat >"$W/owasp.csv" <<'EOF'
# test name, category, real vulnerability, cwe, Benchmark version: 1.2
# a second comment line a count-based skip would turn into a case
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,sqli,false,89
EOF
got=$(truth_from_owasp "$W/owasp.csv" 'src/')
assert_eq 2 "$(printf '%s\n' "$got" | wc -l | tr -d ' ')" 'exactly two cases - a line-count skip would emit a third named "# a second comment line"'
assert_contains "$got" "BenchmarkTest00001${US}src/BenchmarkTest00001.java${US}pathtraver${US}22${US}true" 'the path is prefix + case + .java'

t_case 'the OWASP adapter filters to the requested categories'
got=$(truth_from_owasp "$W/owasp.csv" 'src/' sqli)
assert_eq 1 "$(printf '%s\n' "$got" | wc -l | tr -d ' ')" 'only the sqli case survives'
assert_contains "$got" 'BenchmarkTest00002' 'and it is the right one'

# ===========================================================================
printf -- '\n-- E. the scorer, against a hand-checked fixture --\n'
# ===========================================================================
#
# Three categories, eight cases, every expected count worked out by hand.
#
#   alpha (CWE 327)   a1 f1 real   a2 f2 real   a3 f3 trap   a4 f4 trap
#   beta  (CWE  89)   b1 f5 real   b2 f6 trap
#   gamma (CWE  79)   g1 f7 real   g2 f8 trap
#
#   toolA claims alpha beta          (gamma -> a NO-COVERAGE cell)
#   toolB claims alpha beta gamma
#
#   toolA reports  f1 cwe 326 high     -> alpha, IN 327's class
#                  f3 cwe  89 low      -> alpha, NOT in 327's class
#                  f5 cwe  89 critical -> beta,  IS 89
#   toolB reports  f2 cwe 327 high     -> alpha
#
# So for toolA/alpha:
#   loose  : f1 flagged (TP), f2 not (FN), f3 flagged (FP), f4 not (TN)
#            = 1/1/1/1 -> recall .500  FPR .500  precision .500  J +0.000
#   strict : f3's CWE 89 is not in 327's class, so it is NOT flagged
#            = 1/1/0/2 -> recall .500  FPR .000  precision 1.000 J +0.500
# That difference is the point: it is a real strict/loose disagreement, so a
# scorer that quietly implemented one mode twice fails here.

RES=$W/results
mkdir -p "$RES/toolA" "$RES/toolB"

mk_truth \
  "a1${US}f1${US}alpha${US}327${US}true" \
  "a2${US}f2${US}alpha${US}327${US}true" \
  "a3${US}f3${US}alpha${US}327${US}false" \
  "a4${US}f4${US}alpha${US}327${US}false" \
  "b1${US}f5${US}beta${US}89${US}true" \
  "b2${US}f6${US}beta${US}89${US}false" \
  "g1${US}f7${US}gamma${US}79${US}true" \
  "g2${US}f8${US}gamma${US}79${US}false"
cp "$W/truth" "$W/truth-fixture"

{
  bench_record f1 10 326 high 'A-crypto'
  bench_record f3 11 89 low 'A-sqli'
  bench_record f5 12 89 critical 'A-sqli'
} | bench_records_to_jsonl toolA 9.9.9 fixture >"$RES/toolA/normalised.jsonl"
{
  bench_record f2 20 327 high 'B-crypto'
} | bench_records_to_jsonl toolB 8.8.8 fixture >"$RES/toolB/normalised.jsonl"

cat >"$RES/toolA/MANIFEST" <<'EOF'
tool: toolA
version: 9.9.9
corpus: fixture
corpus-commit: 0000000000000000000000000000000000000000
claims-categories: alpha beta
EOF
cat >"$RES/toolB/MANIFEST" <<'EOF'
tool: toolB
version: 8.8.8
corpus: fixture
corpus-commit: 0000000000000000000000000000000000000000
claims-categories: alpha beta gamma
EOF

truth_load "$W/truth-fixture"
cwe_classes_load "$BENCH/cwe-classes.conf"

t_case 'toolA / alpha / LOOSE is 1 TP, 1 FN, 1 FP, 1 TN'
findings_load "$RES/toolA/normalised.jsonl" any
score_category alpha loose
assert_eq '1 1 1 1' "$BENCH_TP $BENCH_FN $BENCH_FP $BENCH_TN" 'hand-checked: f1 TP, f2 FN, f3 FP, f4 TN'
assert_eq '0.500' "$(rate "$BENCH_TP" $(( BENCH_TP + BENCH_FN )))" 'recall = 1/2'
assert_eq '0.500' "$(rate "$BENCH_FP" $(( BENCH_FP + BENCH_TN )))" 'FPR = 1/2'
assert_eq '0.500' "$(rate "$BENCH_TP" $(( BENCH_TP + BENCH_FP )))" 'precision = 1/2'
assert_eq '+0.000' "$(youden 0.500 0.500)" 'J = TPR - FPR = 0.000, which the renderer labels a coin flip'

t_case 'toolA / alpha / STRICT is 1 TP, 1 FN, 0 FP, 2 TN - the CWE really is consulted'
score_category alpha strict
assert_eq '1 1 0 2' "$BENCH_TP $BENCH_FN $BENCH_FP $BENCH_TN" "f3's CWE 89 is outside 327's class, so strict does not flag it - FAILS if strict is a second copy of loose"
assert_eq '+0.500' "$(youden 0.500 0.000)" 'J rises to +0.500 under strict'

t_case 'a class MEMBER matches: toolA reported 326 against a case labelled 327'
score_category alpha strict
assert_eq 1 "$BENCH_TP" 'the equivalence class is what makes this a hit - FAILS under exact-CWE-equality matching'

t_case 'toolA / beta is a clean 1/0/0/1 in both modes'
for _m in loose strict; do
  score_category beta "$_m"
  assert_eq '1 0 0 1' "$BENCH_TP $BENCH_FN $BENCH_FP $BENCH_TN" "beta under $_m"
done

t_case 'an UNDEFINED precision renders n/a, never 0.000'
findings_load "$RES/toolB/normalised.jsonl" any
score_category gamma loose
assert_eq '0 1 0 1' "$BENCH_TP $BENCH_FN $BENCH_FP $BENCH_TN" 'toolB reported nothing in gamma'
assert_eq 'n/a' "$(rate "$BENCH_TP" $(( BENCH_TP + BENCH_FP )))" '0/0 is n/a: 0.000 would say the tool reported findings and every one was wrong'
assert_eq 'n/a' "$(youden n/a 0.000)" 'and J is n/a when either input is'

t_case 'the SEVERITY filter drops a record before counting, and says how many'
findings_load "$RES/toolA/normalised.jsonl" high
assert_eq 2 "$BENCH_FINDING_COUNT" 'the high and critical records are kept'
assert_eq 1 "$BENCH_FINDING_DROPPED" 'the `low` record is dropped and COUNTED as dropped, not silently discarded'
score_category alpha loose
assert_eq '1 1 0 2' "$BENCH_TP $BENCH_FN $BENCH_FP $BENCH_TN" "the dropped low-severity f3 finding stops being a false positive - which is why R5 requires publishing BOTH columns"

# ===========================================================================
printf -- '\n-- F. the scorecard renderer --\n'
# ===========================================================================

SCORE_MD=$W/score.md
bash "$BENCH/score.sh" --truth "$W/truth-fixture" --results "$RES" \
  --classes "$BENCH/cwe-classes.conf" --format md >"$SCORE_MD"

t_case 'the NO-COVERAGE cell renders explicitly, and is not a zero'
assert_contains "$(grep '^| toolA | gamma |' "$SCORE_MD")" 'no coverage' \
  'toolA does not claim gamma, so its gamma row says so'
assert_not_contains "$(grep '^| toolA | gamma |' "$SCORE_MD")" '0.000' \
  'and carries no 0.000 anywhere - a zero would accuse the tool of failing at something it never claimed'
_n=$(grep -c '^| toolA | gamma |' "$SCORE_MD" || true)
assert_eq 2 "$_n" 'the row is PRESENT in BOTH the loose and the strict table rather than omitted - omitting it would leave a reader to assume the renderer lost a number'

t_case 'a CLAIMED category still renders real numbers for the same tool'
assert_contains "$(grep '^| toolA | alpha |' "$SCORE_MD" | head -1)" '| 1 | 1 | 1 | 1 |' \
  'the loose alpha row carries the hand-checked matrix'

t_case 'the aggregate counts the no-coverage categories and says what it spans'
agg=$(grep '^| toolA | 2 of 3 |' "$SCORE_MD" | head -1)
assert_ne '' "$agg" 'toolA aggregates over the 2 categories it claims, of the 3 the corpus has'
assert_contains "$agg" '| 1 |' 'and reports 1 category with no coverage'
assert_contains "$(cat "$SCORE_MD")" 'It is not comparable with any other corpus, and it is not an overall score.' \
  'the aggregate is labelled, so it can never be quoted as an overall score'

t_case 'Youden J is present and is labelled as a coin flip at zero'
_md=$(cat "$SCORE_MD")
assert_contains "$_md" 'Youden J = TPR - FPR' 'the formula is stated'
assert_contains "$_md" 'J = 0.000 is a coin flip' 'and the baseline is stated beside it - recall alone would read the ldapi shape as a perfect score'

t_case 'the strict/loose agreement check reports the DISAGREEMENT this fixture contains'
row=$(grep '^| toolA | ' "$SCORE_MD" | grep 'of 2' | head -1)
assert_contains "$row" 'alpha' 'alpha is named as disagreeing - the fixture was built so it does, so a scorer computing one mode twice cannot pass here'

t_case 'the tool table carries a version and a corpus commit for every tool'
_md=$(cat "$SCORE_MD")
assert_contains "$_md" '| toolA | `9.9.9` | `0000000000000000000000000000000000000000` |' 'toolA'
assert_contains "$_md" '| toolB | `8.8.8` | `0000000000000000000000000000000000000000` |' 'toolB'

t_case 'the scorecard states what it is NOT, in the document itself'
_md=$(cat "$SCORE_MD")
assert_contains "$_md" 'It is **not** an overall score' 'no single overall score'
assert_contains "$_md" 'is **not** a zero' 'no-coverage is not a zero'
assert_contains "$_md" "own test fixtures" 'and the fixture-bias rule is restated where a reader of the numbers will see it'

SCORE_JSON=$W/score.json
bash "$BENCH/score.sh" --truth "$W/truth-fixture" --results "$RES" \
  --classes "$BENCH/cwe-classes.conf" --format json >"$SCORE_JSON"

t_case 'the JSON renderer marks a no-coverage cell structurally, not in prose'
assert_contains "$(tr -d ' \n' <"$SCORE_JSON")" '"gamma":{"coverage":"none"}' \
  'a consumer can tell a scope boundary from a failure without reading prose'
assert_contains "$(tr -d ' \n' <"$SCORE_JSON")" '"coverage":"scored"' \
  'and a scored cell is marked too, rather than being the absence of a marker'

t_case 'no JSON number carries a leading + - it is not RFC 8259 and jq will not catch it'
assert_not_contains "$(cat "$SCORE_JSON")" ': +' \
  'a signed number is valid in the markdown table and invalid in JSON; jq accepts it, a conforming parser rejects the whole document'

t_case 'an undefined ratio is JSON null, never 0'
assert_contains "$(tr -d ' \n' <"$SCORE_JSON")" '"precision":null' \
  'toolB/gamma has no findings at all, so its precision is null'

# A conforming parser, when one is on the box.  Reported as SKIPPED rather
# than passed when it is not: this suite must run on a host with no python3,
# and a silent pass there is exactly the "it did not look" result the project
# forbids everywhere else.
if command -v python3 >/dev/null 2>&1; then
  t_case 'the whole JSON document parses under a CONFORMING parser'
  assert_status 0 'python3 -m json.tool accepts the scorecard' \
    python3 -m json.tool "$SCORE_JSON"
else
  printf 'SKIPPED: no python3 on this host - the conforming-parser check did not run\n'
fi

t_case 'a bad --min-severity or --format is refused rather than defaulted'
assert_status 2 'an unknown severity is exit 2' \
  bash "$BENCH/score.sh" --truth "$W/truth-fixture" --results "$RES" --min-severity urgent
assert_status 2 'an unknown format is exit 2' \
  bash "$BENCH/score.sh" --truth "$W/truth-fixture" --results "$RES" --format xml

t_case 'a missing or unreadable --truth is refused, not scored as an empty case list'
assert_status 2 'an unreadable truth file is exit 2 - an empty case list would render as "every tool found nothing", which is a plausible-looking benchmark result' \
  bash "$BENCH/score.sh" --truth "$W/no-such-truth" --results "$RES"

t_case 'a corpus with no machine-readable ground truth cannot be sampled at all'
# The stub corpus directory is CREATED first, on purpose.  Without it
# make-sample.sh stops earlier, at "corpus not fetched", which is also exit 2 -
# so a status-only assertion would pass without ever reaching the refusal under
# test.
mkdir -p "$W/corpora-stub/terragoat"
_ms_out=$(env BENCH_CORPORA_DIR="$W/corpora-stub" bash "$BENCH/make-sample.sh" terragoat x 2>&1 || true)
_ms_rc=0
env BENCH_CORPORA_DIR="$W/corpora-stub" bash "$BENCH/make-sample.sh" terragoat x >/dev/null 2>&1 || _ms_rc=$?
assert_eq 2 "$_ms_rc" 'make-sample.sh refuses a `ground-truth: none` corpus'
assert_contains "$_ms_out" 'only `csv:` corpora can be sampled' \
  'and it is THAT refusal rather than "corpus not fetched", which shares the exit code - the refusal is where a truth file would be MANUFACTURED, so a coverage-only corpus can never acquire a recall score'
assert_not_contains "$_ms_out" 'corpus not fetched' 'the earlier guard was passed, so this case really reaches the ground-truth check'

t_case 'a results directory with no normalised output is refused, not scored as empty'
mkdir -p "$W/empty-results"
assert_status 2 'no <tool>/normalised.jsonl is exit 2 - an empty scorecard would read as "every tool found nothing"' \
  bash "$BENCH/score.sh" --truth "$W/truth-fixture" --results "$W/empty-results"

# ===========================================================================
printf -- '\n-- G. bench/ is a SEPARATE HARNESS, in both directions --\n'
# ===========================================================================

t_case 'nothing in the scanner runtime references bench/'
hits=''
while IFS= read -r f; do
  grep -l 'bench/' "$f" >/dev/null 2>&1 && hits+="$f "
done < <(find "$ROOT/lib" "$ROOT/modules" -type f -name '*.sh'; printf '%s\n' "$ROOT/scan.sh")
assert_eq '' "$hits" 'lib/, modules/ and scan.sh must not mention bench/ - the harness orchestrates other tools and may use the network, which the scanner may not'

t_case 'nothing in bench/ sources a scanner library'
hits=''
while IFS= read -r f; do
  grep -nE '^[[:space:]]*(source|\.)[[:space:]]+.*(\$ROOT|\.\./\.\.)/lib/' "$f" >/dev/null 2>&1 && hits+="$f "
done < <(find "$ROOT/bench" -type f -name '*.sh')
assert_eq '' "$hits" 'a source edge from bench/ into lib/ would put benchmark code on the scan path source graph that tests/lint-source-graph.sh measures'

t_case 'bench/ ships no scanner record file the rule linter would have to own'
assert_file_absent "$ROOT/bench/checks.rules" 'bench/ has no §9.5 check registry'
assert_eq '' "$(find "$ROOT/bench" -name '*.rules' -type f)" 'and no .rules file at all - bench/corpus.lock uses the record SHAPE without claiming the extension rules/RULE-FORMAT.md §9 governs'

t_case 'only bench/fetch-corpus.sh and bench/fetch-sca-corpus.sh reach the network'
netusers=''
while IFS= read -r f; do
  case $(basename "$f") in fetch-corpus.sh | fetch-sca-corpus.sh) continue ;; esac
  grep -nE '(^|[^[:alnum:]_])(curl|wget|git (clone|fetch|ls-remote))([^[:alnum:]_]|$)' "$f" >/dev/null 2>&1 &&
    netusers+="$(basename "$f") "
done < <(find "$ROOT/bench" -type f -name '*.sh')
assert_eq '' "$netusers" 'every other bench/ script is offline, so a measurement run needs no network once a corpus is fetched - bench/fetch-sca-corpus.sh is the second exception, and only a live RE-VERIFICATION of an already-pinned advisory (its own header explains why the corpus itself needs no network to build); --offline skips even that'

t_case 'the corpora directory is gitignored, so no corpus content can be committed'
assert_file_exists "$ROOT/bench/.gitignore" 'bench/.gitignore exists'
assert_contains "$(cat "$ROOT/bench/.gitignore")" 'corpora/' 'and ignores corpora/ - OWASP Benchmark is GPL-2.0 and this tree is Apache-2.0'

t_case 'no COMMITTED result carries a local absolute path'
# The pattern requires the home-shaped path to START a token - at line start,
# or after a quote, an equals or a space.  An unanchored `/home/` matches
# `https://www3.ntu.edu.sg/home/...`, a rule's own reference URL sitting in
# Semgrep's raw output, and a check that cries wolf on every committed result
# is a check someone will delete.
leaks=''
if [[ -d $ROOT/bench/results ]]; then
  while IFS= read -r f; do
    grep -lE '(^|["'"'"'= ])/(Users|home|root)/' "$f" >/dev/null 2>&1 && leaks+="${f#"$ROOT/"} "
  done < <(find "$ROOT/bench/results" -type f)
fi
assert_eq '' "$leaks" 'a committed result must not embed an operator home directory - bench/run-tool.sh --portable-paths rewrites the scan-root and bench/ prefixes to <SCAN_ROOT> and <BENCH>, and this is what catches a result committed without it'

t_case 'the README states the must-not-publish rules, which are the point of the harness'
readme=$(cat "$ROOT/bench/README.md")
assert_contains "$readme" 'test fixtures' 'no fixture-measured numbers'
assert_contains "$readme" 'overall score' 'no single overall score'
assert_contains "$readme" 'version' 'no version-less numbers'

# ===========================================================================
printf -- '\n-- H. the tool adapters, against REAL committed tool output --\n'
# ===========================================================================

# shellcheck source=bench/tools/semgrep.sh
source "$BENCH/tools/semgrep.sh"
# shellcheck source=bench/tools/scoursh.sh
source "$BENCH/tools/scoursh.sh"
# shellcheck source=bench/tools/semgrep-default.sh
source "$BENCH/tools/semgrep-default.sh"

t_case 'the semgrep adapter maps real semgrep JSON into the normalised shape'
mkdir -p "$W/raw-semgrep"
cp "$FIX/semgrep-sample.json" "$W/raw-semgrep/semgrep.json"
recs=$(semgrep_normalise "$W/raw-semgrep" '/nonexistent-root')
assert_eq 6 "$(printf '%s\n' "$recs" | grep -c .)" 'one record per finding in the fixture'
assert_contains "$recs" "BenchmarkTest00001.java${US}72${US}22${US}high${US}java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal" \
  "a CWE-22 ERROR finding: the CWE is reduced from semgrep's prose spelling and ERROR maps to high"
assert_contains "$recs" "${US}326${US}medium${US}" 'a WARNING maps to medium on the common scale'
assert_contains "$recs" "${US}89${US}" 'the SQL-injection CWE survives the prose spelling'

t_case 'the semgrep adapter emits a record for a finding with NO cwe at all'
python3 - "$W/raw-semgrep/semgrep.json" <<'PY' 2>/dev/null || printf 'SKIPPED: no python3\n'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
r = json.loads(json.dumps(d['results'][0]))
r['extra']['metadata'].pop('cwe', None)
r['path'] = 'nocwe.java'
d['results'].append(r)
json.dump(d, open(p, 'w'))
PY
if [[ -s $W/raw-semgrep/semgrep.json ]]; then
  recs=$(semgrep_normalise "$W/raw-semgrep" '/nonexistent-root')
  assert_contains "$recs" "nocwe.java${US}" \
    'a CWE-less finding is still a record - dropping it would make the tool look cleaner than it is under LOOSE matching, which is exactly where a CWE-less finding counts'
fi

t_case 'the scoursh adapter strips run.json path_root, so file matches the ground truth'
mkdir -p "$W/raw-scoursh/run"
cp "$FIX/scoursh-findings-sample.jsonl" "$W/raw-scoursh/run/findings.jsonl"
cp "$FIX/scoursh-run-sample.json" "$W/raw-scoursh/run/run.json"
recs=$(scoursh_normalise "$W/raw-scoursh" '/nonexistent-root')
# The EXPECTED record is derived from the fixture by an independent reader -
# plain `sed`, not bench/lib/json.sh - for two reasons.  It cannot drift from
# the fixture the way a transcribed literal can; and it keeps the check id out
# of this file's text, which matters because `tools/gen-status.sh` attributes a
# rule pack to the first `tests/**/*.sh` suite naming any of its ids, in
# LC_ALL=C order.  A benchmark suite carrying `SAST-CRY-…` sorts ahead of
# `tests/suites/report.sh` and would take over crypto.rules' "exercised by"
# cell in three published status blocks - a true statement by the generator's
# own rule, and a misleading one to a reader, since nothing here exercises that
# pack.
_fx_line1=$(head -1 "$FIX/scoursh-findings-sample.jsonl")
_fx_rule=$(printf '%s' "$_fx_line1" | sed -n 's/.*"check_id":"\([^"]*\)".*/\1/p')
_fx_sev=$(printf '%s' "$_fx_line1" | sed -n 's/.*"severity":"\([^"]*\)".*/\1/p')
_fx_cwe=$(printf '%s' "$_fx_line1" | sed -n 's/.*"cwe":"CWE-\([0-9]*\)".*/\1/p')
_fx_path=$(printf '%s' "$_fx_line1" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
_fx_line=$(printf '%s' "$_fx_line1" | sed -n 's/.*"line":\([0-9]*\).*/\1/p')
_fx_root=$(sed -n 's/.*"path_root": *"\([^"]*\)".*/\1/p' "$FIX/scoursh-run-sample.json")
_fx_rel=${_fx_path#"$_fx_root"/}

assert_ne '' "$_fx_rule" 'the independent reader found a check id in the fixture'
assert_ne "$_fx_rel" "$_fx_path" 'and the fixture really does carry a path_root prefix to strip, so this case can fail'
assert_contains "$recs" "${_fx_rel}${US}${_fx_line}${US}${_fx_cwe}${US}${_fx_sev}${US}${_fx_rule}" \
  "the reported path is scan-root-relative, NOT the git-toplevel-relative path scoursh emits - keeping the prefix yields zero matches, which reads as 'this tool found nothing' rather than as an error"
assert_not_contains "$recs" 'bench/corpora' 'the path_root prefix is gone'

t_case 'without run.json the adapter still emits records rather than dying'
rm -f "$W/raw-scoursh/run/run.json"
recs=$(scoursh_normalise "$W/raw-scoursh" '/nonexistent-root')
assert_eq 3 "$(printf '%s\n' "$recs" | grep -c .)" 'every finding is still normalised'
assert_contains "$recs" 'bench/corpora' 'though the prefix is then kept, because nothing recorded what to strip - visible in the output rather than silently mismatched'

t_case 'scoursh severities pass through the common scale and an unknown one degrades to info'
assert_eq 'critical' "$(_scoursh_severity critical)" 'critical'
assert_eq 'info' "$(_scoursh_severity wibble)" 'an unrecognised severity becomes info rather than widening the scale every other adapter maps onto'

t_case 'every adapter implements the whole contract'
for _t in scoursh semgrep semgrep-default; do
  for _fn in _available _version _run _normalise _scope; do
    assert_cond "${_t}${_fn} is defined" declare -F "${_t}${_fn}"
  done
  assert_ne '' "$(${_t}_scope)" "${_t}_scope names at least one category - an adapter with no declared scope would silently be scored on everything"
done

t_case 'semgrep-default runs the DOCUMENTED DEFAULT ruleset, semgrep.sh the MAXIMUM free one - two columns, never one env flip a reader has to notice'
assert_eq 'p/default' "$BENCH_SEMGREP_CONFIG" \
  'sourcing bench/tools/semgrep-default.sh sets BENCH_SEMGREP_CONFIG before semgrep.sh applies its own ${:-} default - a load-order swap here would silently collapse both gate configurations onto one'
assert_cond 'semgrep-default is a distinct tool id, not an alias' \
  declare -F 'semgrep-default_run'

t_case 'records_to_jsonl produces one parseable JSON object per record'
out=$(bench_record 'a"b.java' 7 89 high 'r,1' | bench_records_to_jsonl t v c)
assert_eq 1 "$(printf '%s\n' "$out" | grep -c .)" 'one line'
assert_contains "$out" '"file":"a\"b.java"' 'a quote in a path is escaped by the ONE json writer, not by each adapter'
assert_contains "$out" '"line":7' 'line is a JSON number, not a string - a quoted one would sort 10 before 9'
assert_contains "$out" '"rule_id":"r,1"' 'a comma in a rule id survives'

t_case 'a record with no line number carries JSON null, not 0'
out=$(bench_record 'x.java' '' 89 high r | bench_records_to_jsonl t v c)
assert_contains "$out" '"line":null' 'null and not 0 - line 0 does not exist and would be indistinguishable from a real first line'

t_case 'a record with no CWE carries JSON null, not an empty string'
out=$(bench_record 'x.java' 3 '' high r | bench_records_to_jsonl t v c)
assert_contains "$out" '"cwe":null' 'a CWE-less finding is explicit about it'

t_case 'the _json_field reader survives a key-shaped run of bytes inside a value'
# A key-shaped run of bytes inside an EARLIER value, correctly escaped.  Note
# what this does and does not pin: it pins that the reader gets the right
# answer, and it does NOT pin the `[{,]` anchor, because no WELL-FORMED line
# can distinguish the two readings - an escaped lookalike is `\"file\":`,
# which is not the `"file":` an unanchored match searches for either.  That
# was checked by mutation rather than assumed, and the anchor's real
# justification is recorded in bench/lib/score.sh beside it.
line='{"tool":"t","version":"v","corpus":"c,\"file\":\"fake.java\"","file":"real.java","line":1,"cwe":null,"severity":"high","rule_id":"r"}'
assert_eq 'real.java' "$(_json_field "$line" file)" \
  'the file is read from the file FIELD even with an escaped lookalike ahead of it'
assert_eq 'c,"file":"fake.java"' "$(_json_field "$line" corpus)" \
  'and the value carrying the lookalike round-trips intact, escapes undone'

t_summary bench
