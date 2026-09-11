#!/usr/bin/env bash
# tests/suites/bench-dast.sh - the B7 DAST leg: bench/tools/scoursh-dast.sh,
# bench/tools/zap.sh, bench/labels/dast-juiceshop.truth, and the scorer
# against a small hand-checked truth/results pair.
#
# HERMETIC BY CONSTRUCTION, exactly like tests/suites/bench.sh's own header
# states for the harness generally, and tests/suites/bench-sca.sh's own for
# the SCA leg specifically: nothing here starts a container, drives ZAP's
# API, or runs `scan.sh dast`. Every adapter is exercised through its own
# `_normalise` function against a committed fixture under tests/fixtures/bench/
# - a REAL, trimmed excerpt of that tool's own output against THIS leg's
# actual target (one record per distinct check_id for scoursh, one alert per
# distinct alert name for ZAP - captured while building
# bench/results/b7-dast-juiceshop/, not hand-typed).
#
# shellcheck disable=SC2016
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

BENCH=$ROOT/bench
FIX=$ROOT/tests/fixtures/bench
W=$SCOURSH_SCRATCH/bench-dast-suite
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
BENCH_SCOURSH_ROOT=$ROOT
# shellcheck source=bench/tools/scoursh-dast.sh
source "$BENCH/tools/scoursh-dast.sh"
# shellcheck source=bench/tools/zap.sh
source "$BENCH/tools/zap.sh"

assert_cond() {
  local msg=$1
  shift
  local rc=0
  "$@" || rc=$?
  assert_eq 0 "$rc" "$msg"
}

# ===========================================================================
printf -- '\n-- A. the adapter contract, both directions --\n'
# ===========================================================================

t_case 'both DAST adapters implement the whole five-function contract'
for _fn in _available _version _run _normalise _scope; do
  assert_cond "scoursh-dast${_fn} is defined" declare -F "scoursh-dast${_fn}"
  assert_cond "zap${_fn} is defined" declare -F "zap${_fn}"
done

t_case 'both adapters declare a scope, and it is the same set (they were scored on one shared corpus)'
s1=$(scoursh-dast_scope | LC_ALL=C sort | tr '\n' ' ')
s2=$(zap_scope | LC_ALL=C sort | tr '\n' ' ')
assert_ne '' "$s1" 'scoursh-dast claims at least one category'
assert_eq "$s1" "$s2" 'the two adapters this leg scored claim the identical category set - a mismatch here would mean the scorecard silently scored one tool on a category the other never competed in'

t_case 'neither DAST adapter is driven through bench/run-tool.sh - both refuse cleanly with no raw output'
mkdir -p "$W/empty-raw"
rc=0
scoursh-dast_run "$W/empty-raw" || rc=$?
assert_ne 0 "$rc" 'scoursh-dast_run refuses when findings.jsonl is absent, rather than silently reporting zero findings'
rc=0
zap_run "$W/empty-raw" || rc=$?
assert_ne 0 "$rc" 'zap_run refuses when alerts.json is absent, rather than silently reporting zero findings'

# ===========================================================================
printf -- '\n-- B. scoursh-dast_normalise, against real committed scoursh dast output --\n'
# ===========================================================================

mkdir -p "$W/raw-scoursh/run"
cp "$FIX/scoursh-dast-findings-sample.jsonl" "$W/raw-scoursh/run/findings.jsonl"

t_case 'scoursh-dast_run accepts a directory that DOES carry findings.jsonl'
assert_cond 'scoursh-dast_run returns 0' scoursh-dast_run "$W/raw-scoursh"

t_case 'the normaliser maps location.path_template to file, never location.path'
recs=$(scoursh-dast_normalise "$W/raw-scoursh")
assert_eq 6 "$(printf '%s\n' "$recs" | grep -c .)" 'one record per finding - unlike the SAST adapter, scoursh DAST findings carry a single CWE string, so no per-alias fan-out applies'
assert_contains "$recs" "/chunk-PX7UKXVL.js${US}${US}942${US}medium${US}DAST-CORS-WILDCARD-01" \
  'a CWE-942 CORS finding: the CWE- prefix is stripped to a bare number and the path is the URL PATH TEMPLATE, not a filesystem path'

t_case 'a critical finding survives the severity pass-through unchanged'
assert_contains "$recs" "${US}347${US}critical${US}DAST-JWT-SIG_NOT_VERIFIED-01" \
  'critical is a valid common-scale rung and is not degraded to info'

t_case 'CWE- prefix stripping matches bench_cwe_number on every fixture row, independently re-derived'
while IFS= read -r line; do
  [[ -n $line ]] || continue
  cwe_field=$(printf '%s' "$line" | sed -n 's/.*"cwe":"\(CWE-[0-9]*\)".*/\1/p')
  [[ -n $cwe_field ]] || continue
  want=$(bench_cwe_number "$cwe_field")
  assert_contains "$recs" "${US}${want}${US}" "bench_cwe_number($cwe_field)=$want appears in the normalised output"
done <"$FIX/scoursh-dast-findings-sample.jsonl"

t_case 'a check_id with no matching path_template (empty location) is dropped, never emitted with an empty file'
assert_not_contains "$recs" "${US}${US}${US}" 'no record carries a completely empty file field'

# ===========================================================================
printf -- '\n-- C. zap_normalise, against real committed ZAP alert output --\n'
# ===========================================================================

mkdir -p "$W/raw-zap"
cp "$FIX/zap-alerts-sample.json" "$W/raw-zap/alerts.json"

t_case 'zap_run accepts a directory that DOES carry alerts.json'
assert_cond 'zap_run returns 0' zap_run "$W/raw-zap"

t_case 'the normaliser strips scheme+host+query, leaving only the URL PATH'
recs=$(zap_normalise "$W/raw-zap")
assert_not_contains "$recs" '172.17.0.2' 'the internal bridge IP scoursh-dast.sh/zap.sh both dast adapters normalise AWAY - only the path survives'
assert_not_contains "$recs" 'http:' 'no scheme survives either'

t_case 'the Cross-Domain Misconfiguration alert maps to CWE-264, NOT scoursh own CWE-942 for the same defect'
assert_contains "$recs" "${US}264${US}medium${US}10098" \
  "ZAP's own cweid for its CORS-wildcard-equivalent check is 264 (Permissions/Privileges/Access Control), a real taxonomy disagreement with scoursh's 942 that this leg's own README documents rather than papers over - a test asserting 942 here would be WRONG about what ZAP actually reports"

t_case 'an Informational-risk alert maps to the common scale info rung, never a fabricated critical'
python3 -c "
import json
d=json.load(open('$W/raw-zap/alerts.json'))
d['alerts'][0]['risk']='Informational'
d['alerts'][0]['cweid']='0'
d['alerts'][0]['url']='http://x/y'
json.dump(d, open('$W/raw-zap/alerts.json','w'))
"
recs2=$(zap_normalise "$W/raw-zap")
assert_contains "$recs2" "/y${US}${US}${US}info${US}" 'Informational maps to info, never to a rung ZAP itself did not assign (cweid 0 also means "none" and is blanked, same as -1)'

t_case 'a plugin with cweid -1 (ZAP own "no CWE mapped" sentinel) carries an EMPTY cwe field, never -1 itself'
python3 -c "
import json
d=json.load(open('$W/raw-zap/alerts.json'))
d['alerts'][0]['cweid']='-1'
d['alerts'][0]['url']='http://x/nocwe'
json.dump(d, open('$W/raw-zap/alerts.json','w'))
"
recs3=$(zap_normalise "$W/raw-zap")
assert_contains "$recs3" "/nocwe${US}${US}${US}" 'the cwe field between the two 0x1f separators is empty, so bench/lib/normalise.sh writes JSON null rather than a fabricated CWE-(-1)'
assert_not_contains "$recs3" "${US}-1${US}" 'the literal sentinel -1 never reaches the internal record'

# ===========================================================================
printf -- '\n-- D. bench/labels/dast-juiceshop.truth, structurally --\n'
# ===========================================================================

TRUTH=$BENCH/labels/dast-juiceshop.truth

t_case 'the real committed truth file parses'
assert_cond 'truth_load returns 0' truth_load "$TRUTH"

t_case 'it has exactly 20 cases: 14 real, 6 negative controls'
assert_eq 20 "${#BENCH_TRUTH_CASES[@]}" 'case count'
nreal=0 nfalse=0
for c in "${BENCH_TRUTH_CASES[@]}"; do
  if [[ ${BENCH_TRUTH_REAL[$c]} == true ]]; then nreal=$(( nreal + 1 )); else nfalse=$(( nfalse + 1 )); fi
done
assert_eq 14 "$nreal" 'real cases'
assert_eq 6 "$nfalse" 'negative-control cases'

t_case 'every case file is a URL PATH - no scheme, no host, no query string'
bad=''
for c in "${BENCH_TRUTH_CASES[@]}"; do
  f=${BENCH_TRUTH_FILE[$c]}
  [[ $f == /* ]] || bad+="$c(not-absolute-path) "
  [[ $f == *'://'* ]] && bad+="$c(has-scheme) "
  [[ $f == *'?'* ]] && bad+="$c(has-query) "
done
assert_eq '' "$bad" 'no case violates the URL-path-only convention both adapters normalise to'

t_case 'every category this file uses is claimed by BOTH scored adapters'
for c in "${BENCH_TRUTH_CASES[@]}"; do
  cat=${BENCH_TRUTH_CAT[$c]}
  assert_contains " $s1 " " $cat " "truth category '$cat' (case $c) is in scoursh-dast's claimed scope"
done

t_case 'no two cases in the SAME category share the same file - a shared (category,file) pair would let one finding double-flag two cases'
dupe=''
for c in "${BENCH_TRUTH_CASES[@]}"; do
  for c2 in "${BENCH_TRUTH_CASES[@]}"; do
    [[ $c < $c2 ]] || continue
    if [[ ${BENCH_TRUTH_CAT[$c]} == "${BENCH_TRUTH_CAT[$c2]}" && ${BENCH_TRUTH_FILE[$c]} == "${BENCH_TRUTH_FILE[$c2]}" ]]; then
      dupe+="$c/$c2 "
    fi
  done
done
assert_eq '' "$dupe" 'no (category, file) collision'

t_case 'the sqli category carries both a real case and negative controls (the one category with a genuine positive AND a trap)'
real_sqli=0 false_sqli=0
for c in "${BENCH_TRUTH_CASES[@]}"; do
  [[ ${BENCH_TRUTH_CAT[$c]} == sqli ]] || continue
  if [[ ${BENCH_TRUTH_REAL[$c]} == true ]]; then real_sqli=$(( real_sqli + 1 )); else false_sqli=$(( false_sqli + 1 )); fi
done
assert_eq 1 "$real_sqli" 'exactly one real sqli case (the hand-verified login bypass)'
assert_eq 2 "$false_sqli" 'two clean negative controls'

# ===========================================================================
printf -- '\n-- E. the scorer, against a tiny hand-authored truth/results pair --\n'
# ===========================================================================

# Four cases, arithmetic small enough to verify by hand: two real (one a
# tool finds, one it misses), two traps (one it wrongly flags, one clean).
tmini=$W/mini.truth
{
  printf '%s\n' "hit${US}/a${US}cat${US}89${US}true"
  printf '%s\n' "miss${US}/b${US}cat${US}89${US}true"
  printf '%s\n' "fp${US}/c${US}cat${US}89${US}false"
  printf '%s\n' "clean${US}/d${US}cat${US}89${US}false"
} >"$tmini"

rmini=$W/mini-results
mkdir -p "$rmini/t/raw"
{
  bench_record /a '' 89 high rule1
  bench_record /c '' 89 high rule1
} | bench_records_to_jsonl t 1.0 minicorpus >"$rmini/t/normalised.jsonl"

t_case 'score_category on the hand-authored pair: TP=1 FN=1 FP=1 TN=1'
truth_load "$tmini"
findings_load "$rmini/t/normalised.jsonl" any
score_category cat loose file
assert_eq 1 "$BENCH_TP" 'TP'
assert_eq 1 "$BENCH_FN" 'FN'
assert_eq 1 "$BENCH_FP" 'FP'
assert_eq 1 "$BENCH_TN" 'TN'
assert_eq '+0.000' "$(youden "$(rate "$BENCH_TP" $(( BENCH_TP + BENCH_FN )))" "$(rate "$BENCH_FP" $(( BENCH_FP + BENCH_TN )))")" \
  'J = 0.5 - 0.5 = 0.000, a coin flip - verified by hand arithmetic, not trusted from the scorer'

# ===========================================================================
printf -- '\n-- F. the real committed b7 scorecard is internally consistent --\n'
# ===========================================================================

RESDIR=$ROOT/bench/results/b7-dast-juiceshop
t_case 'the committed scorecard files exist and are non-empty'
for f in scorecard-all-findings.md scorecard-all-findings.json scorecard-high-and-critical.md; do
  assert_file_exists "$RESDIR/$f" "$f exists"
  assert_ne 0 "$(wc -c <"$RESDIR/$f" | tr -d ' ')" "$f is non-empty"
done

t_case 're-scoring the committed b7 results against the committed truth reproduces the committed aggregate'
out=$(bash "$BENCH/score.sh" --truth "$BENCH/labels/dast-juiceshop.truth" --results "$RESDIR" --format md)
assert_contains "$out" '+0.047' 'scoursh-dast loose aggregate J, re-derived fresh'
assert_contains "$out" '+0.214' 'scoursh-dast strict aggregate J, re-derived fresh'
assert_contains "$out" '+0.024' 'zap loose aggregate J, re-derived fresh'

# ===========================================================================
printf -- '\n-- G. no COMMITTED b7 output carries a local absolute path --\n'
# ===========================================================================

t_case 'the committed b7 results embed no operator home directory'
leaks=''
while IFS= read -r f; do
  grep -lE '(^|["'"'"'= ])/(Users|home|root)/' "$f" >/dev/null 2>&1 && leaks+="${f#"$ROOT/"} "
done < <(find "$RESDIR" -type f)
assert_eq '' "$leaks" 'a leaked home directory here means the scoursh-dast raw copy step forgot to scrub the scratch-run prefix'

t_summary bench-dast
