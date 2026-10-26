#!/usr/bin/env bash
# Owns: every native audit safe/unsafe pair. The registry supplies the roster;
# a missing pair or an inert rule is a failure, not a count maintained by hand.
# shellcheck shell=bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/iac/parse.sh
source "$ROOT/modules/iac/parse.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
F=$ROOT/tests/fixtures/precision
W=$SCOURSH_SCRATCH/static-precision
mkdir -p "$W"
checks_registry_load sast "$ROOT"
checks_registry_load iac "$ROOT"
# Keep distinct sets: checks_registry_load resets its list on each call.
CHECKS_REGISTRY_SETS=()
for pack in "$ROOT"/modules/sast/rules/*.rules "$ROOT"/modules/iac/*.rules; do
  [[ ${pack##*/} != secrets.rules ]] || continue
  set=precision${#CHECKS_REGISTRY_SETS[@]}
  records_load "$pack" pattern-rule "$set" >/dev/null
  CHECKS_REGISTRY_SETS+=("$set")
done
sast_index_checks
declare -A exercised=()
while IFS=$'\t' read -r id rel; do
  [[ -n $id ]] || continue
  [[ -z ${PRECISION_MODULE:-} || $id == "$PRECISION_MODULE"-* ]] || continue
  exercised[$id]=1
  read -r set idx <<<"${_SAST_CHECK_LOC[$id]}"
  t_case "$id: local safe proof, unsafe sibling retained"
  for kind in negative positive mixed; do
    file=$F/$kind/$rel
    if [[ $kind == mixed ]]; then
      file=$W/mixed
      # Independent functions prevent the safe setup from actually making the
      # second case safe (e.g. a null-prototype receiver or fixed request map).
      case $rel in
        *.py)
          printf 'def safe_case():\n' >"$file"
          sed 's/^/    /' "$F/negative/$rel" >>"$file"
          printf '\ndef unsafe_case():\n' >>"$file"
          sed 's/^/    /' "$F/positive/$rel" >>"$file"
          ;;
        *.js|*.ts|*.jsx|*.tsx)
          printf 'function safe_case() {\n' >"$file"
          cat "$F/negative/$rel" >>"$file"
          printf '\n}\nfunction unsafe_case() {\n' >>"$file"
          cat "$F/positive/$rel" >>"$file"
          printf '\n}\n' >>"$file"
          ;;
        *.go)
          # One package/import binding can serve both uses in a real Go file.
          # Repeating its import would manufacture a second import finding.
          awk 'BEGIN{print "package main"} /^package /{next} /^import /{if(seen[$0]++)next} {print}' \
            "$F/negative/$rel" "$F/positive/$rel" >"$file"
          ;;
        *)
          cat "$F/negative/$rel" >"$file"
          case $rel in *.yaml|*.yml) printf '\n---\n' >>"$file" ;; *) printf '\n' >>"$file" ;; esac
          cat "$F/positive/$rel" >>"$file"
          ;;
      esac
    fi
    assert_file_exists "$file" "$kind input exists"
    rm -rf "$W/run"
    run_init "$W/run"
    occurrence_reset_unit "$rel"
    SCOURSH_RUN_ID=precision
    SCOURSH_PATH_ROOT=precision
    SCOURSH_SCAN_ROOT_ID=precision
    export SCOURSH_RUN_ID SCOURSH_SCAN_ROOT_ID
    SCOURSH_SAST_MAX_MATCHES_PER_FILE=200
    SCOURSH_IAC_MAX_MATCHES_PER_FILE=200
    case $id in
      SAST-*) sast_scan_file "$set" "$idx" "$rel" "$file" ;;
      IAC-*) iac_scan_file "$set" "$idx" "$rel" "$file" ;;
    esac
    findings_merge "$W/run"
    detected=0
    while IFS= read -r row; do
      [[ -n $row ]] || continue
      finding_decode "$row"
      # A transparent policy/source-trust review is not an asserted exploitable
      # vulnerability. The safe control may retain that informational review.
      if [[ ${_DF[base_severity]} != info ]]; then detected=$(( detected + 1 )); fi
    done <"$W/run/findings.fields"
    if [[ $kind == negative ]]; then
      assert_eq 0 "$detected" 'safe input is not reported as a vulnerability'
    else
      assert_eq 1 "$detected" 'unsafe input still raises the rule'
    fi
  done
done <"$F/cases.tsv"
for id in "${!_SAST_CHECK_LOC[@]}"; do
  [[ -z ${PRECISION_MODULE:-} || $id == "$PRECISION_MODULE"-* ]] || continue
  assert_eq 1 "${exercised[$id]:-0}" "$id has safe, unsafe and mixed regression inputs"
done
t_case 'the raw-match limit bounds precision analysis, including safe candidates'
read -r set idx <<<"${_SAST_CHECK_LOC[SAST-PY-EVAL_EXEC-01]}"
for mode in safe unsafe; do
  file=$W/capped.py
  if [[ $mode == safe ]]; then
    printf 'eval("one")\neval("two")\neval("three")\n' >"$file"
  else
    printf 'eval(request.body)\neval(request.body)\neval(request.body)\n' >"$file"
  fi
  cap=$(( $(awk 'END{print NR}' "$file") - 1 ))
  SCOURSH_SAST_MAX_MATCHES_PER_FILE=$cap
  rm -rf "$W/run"
  run_init "$W/run"
  occurrence_reset_unit capped.py
  sast_scan_file "$set" "$idx" capped.py "$file"
  findings_merge "$W/run"
  assert_contains "$(cat "$W/run/meta/truncated_matches")" "max=$cap" 'safe suppression cannot hide overflow or process the remaining raw hits'
  actual=0
  while IFS= read -r row; do
    finding_decode "$row"
    if [[ ${_DF[base_severity]} != info ]]; then actual=$(( actual + 1 )); fi
  done <"$W/run/findings.fields"
  if [[ $mode == safe ]]; then
    assert_eq 0 "$actual" 'overflow is metadata, not a vulnerability on fixed expressions'
  else
    assert_eq "$cap" "$actual" 'all unsafe candidates up to the raw limit remain detected'
  fi
done
t_summary static-precision
