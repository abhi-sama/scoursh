#!/usr/bin/env bash
# tests/suites/sast-secrets-source.sh - ENV_ASSIGNMENT must not interpret
# source references as dotenv literals. Exercises the real scan.sh path with
# React/Next-shaped source AND the existing assignment-form positive controls.
# Fails under the former unscoped rule (object properties / default arguments)
# and under an inert secrets pack (the literal and matrix positives disappear).
# All credentials in the fixtures are synthetic and authenticate nothing.
#
# shellcheck shell=bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sast-secrets-source
mkdir -p "$W/input" "$W/home"
# Keep the CLI's writable state outside the checkout as well as its report.
# Config/data are the real checkout inputs, through the supported home layout.
ln -s "$ROOT/config" "$W/home/config"
ln -s "$ROOT/data" "$W/home/data"
cp -R "$ROOT/tests/fixtures/sast-env-assignment-source" "$W/input/source"
cp -R "$ROOT/tests/fixtures/sast-secret-forms" "$W/input/forms"
# TypeScript/JavaScript module variants use the same language syntax.
for ext in mts cts; do cp "$W/input/source/client.ts" "$W/input/source/client.$ext"; done
for ext in mjs cjs; do cp "$W/input/source/client.js" "$W/input/source/client.$ext"; done
ENV_ID=SAST-SEC-ENV_ASSIGNMENT-01
API_ID=SAST-SEC-GENERIC_API_KEY-01

# Isolate paths from the checkout's git root so locations match the copied
# input tree. No scanner internals or rule packs are replaced for this run.
rc=0
SCOURSH_HOME="$W/home" bash "$ROOT/scan.sh" sast --path "$W/input" --out "$W/run" --format json --jobs 1 \
  >"$W/scan.out" 2>"$W/scan.err" || rc=$?
t_case 'the real SAST CLI completes'
assert_eq 0 "$rc" 'scan.sh succeeds; a failed scan cannot satisfy silence assertions'
assert_file_exists "$W/run/findings.jsonl" 'the mandatory findings output exists'
if [[ $rc != 0 || ! -f $W/run/findings.fields ]]; then
  cat "$W/scan.err" >&2
  t_summary sast-secrets-source
  exit 1
fi

while IFS= read -r record; do
  [[ -n $record ]] || continue
  finding_decode "$record"
  printf '%s:%s\t%s\n' "${_DF[loc_path]}" "${_DF[loc_line]}" "${_DF[check_id]}"
done <"$W/run/findings.fields" >"$W/hits"

# Read tags from the fixtures themselves: adding a case adds an assertion,
# with no hardcoded count or inventory to drift away from the input tree.
for kind in source forms; do
  for f in "$W/input/$kind"/*; do
    [[ -f $f ]] || continue
    awk -v path="$kind/${f##*/}" '
      match($0, /\[\[[PNG][0-9]+\]\]/) {
        tag = substr($0, RSTART + 2, RLENGTH - 4)
        print tag "\t" path ":" NR
      }
    ' "$f"
  done
done >"$W/tags"

hit_ids() {
  awk -F '\t' -v loc="$1" '$1 == loc { print $2 }' "$W/hits"
}

source_neg=0 matrix_pos=0 source_pos=0
while IFS=$'\t' read -r tag loc; do
  ids=$(hit_ids "$loc")
  case $loc:$tag in
    source/*:N*)
      source_neg=$(( source_neg + 1 ))
      t_case "$tag $loc: a source expression is not a hardcoded credential"
      assert_not_contains "$ids" 'SAST-SEC-' \
        "$loc stays quiet on references, JSX props, templates and defaults"
      ;;
    source/*:P*)
      source_pos=$(( source_pos + 1 ))
      t_case "$tag $loc: literal TypeScript API key still fires"
      assert_contains "$ids" "$API_ID" 'GENERIC_API_KEY still catches the planted literal'
      ;;
    forms/*:P*)
      matrix_pos=$(( matrix_pos + 1 ))
      t_case "$tag $loc: the existing true-positive matrix still fires"
      assert_contains "$ids" 'SAST-SEC-' "$tag remains detected through scan.sh"
      ;;
  esac
done <"$W/tags"

t_case 'the positive and negative controls were actually exercised'
assert_true "$(( source_neg > 0 && source_pos > 0 && matrix_pos > 0 ? 0 : 1 ))" \
  "exercised $source_neg source negatives, $source_pos source positives, $matrix_pos matrix positives"
t_case 'the unquoted configuration rule never reports any source line'
source_env=$(awk -F '\t' -v id="$ENV_ID" '$1 ~ /^source\// && $2 == id { print }' "$W/hits")
assert_eq '' "$source_env" 'ENV_ASSIGNMENT has no source findings, including untagged lines'

t_summary sast-secrets-source
