#!/usr/bin/env bash
# bench/lib/sca_advisories.sh - read bench/sca-advisories.lock.
#
# A deliberately SEPARATE reader from bench/lib/corpus.sh, not a reuse of
# corpus_load: that function's own validation tail requires `repo`/`commit`/
# `licence`/`ground-truth`/`categories` and a 40-hex commit sha, which is the
# git-clone corpus shape bench/corpus.lock uses and bench/sca-advisories.lock
# deliberately is not (see that file's own header for why - there is no
# single third-party "SCA benchmark" repository to pin a commit against).
# The parsing LOOP below is the same blank-line-separated `key: value` block
# shape for the same reason corpus.sh's is; only the required-key check at
# the end differs.
#
# shellcheck shell=bash

# SC2034: BENCH_SCA_ADV/BENCH_SCA_ADV_IDS are this file's published outputs.
# shellcheck disable=SC2034
[[ -n ${BENCH_SCA_ADVISORIES_SOURCED:-} ]] && return 0
BENCH_SCA_ADVISORIES_SOURCED=1

# sca_advisories_load FILE
#
# Populates:
#   BENCH_SCA_ADV_IDS  - array, in file order
#   BENCH_SCA_ADV       - assoc, keyed `<id>/<key>`; `note` accumulates
#                          newline-separated on repeat, exactly like
#                          bench/lib/corpus.sh's `note`.
sca_advisories_load() {
  local file=$1 line key val id='' lastkey='' lineno=0
  [[ -r $file ]] || { printf 'bench: cannot read sca advisories lock: %s\n' "$file" >&2; return 2; }

  BENCH_SCA_ADV_IDS=()
  unset BENCH_SCA_ADV
  declare -gA BENCH_SCA_ADV=()

  while IFS= read -r line || [[ -n $line ]]; do
    lineno=$(( lineno + 1 ))
    [[ ${line:0:1} == '#' ]] && continue
    if [[ -z $line ]]; then id=''; lastkey=''; continue; fi

    if [[ $line == '  '* ]]; then
      if [[ -z $id || -z $lastkey ]]; then
        printf 'bench: %s:%d: continuation line with no preceding key\n' "$file" "$lineno" >&2
        return 2
      fi
      BENCH_SCA_ADV[$id/$lastkey]="${BENCH_SCA_ADV[$id/$lastkey]} ${line#  }"
      continue
    fi

    if [[ $line != *": "* && $line != *":" ]]; then
      printf 'bench: %s:%d: not a `key: value` line: %s\n' "$file" "$lineno" "$line" >&2
      return 2
    fi
    key=${line%%:*}
    val=${line#*: }
    [[ $line == *":" ]] && val=''

    if [[ -z $id ]]; then
      if [[ $key != id ]]; then
        printf 'bench: %s:%d: a record must open with `id:`, not `%s:`\n' "$file" "$lineno" "$key" >&2
        return 2
      fi
      id=$val
      BENCH_SCA_ADV_IDS+=("$id")
      BENCH_SCA_ADV[$id/id]=$val
      lastkey=id
      continue
    fi

    if [[ -n ${BENCH_SCA_ADV[$id/$key]:-} ]]; then
      BENCH_SCA_ADV[$id/$key]="${BENCH_SCA_ADV[$id/$key]}"$'\n'"$val"
    else
      BENCH_SCA_ADV[$id/$key]=$val
    fi
    lastkey=$key
  done <"$file"

  local want c
  for c in "${BENCH_SCA_ADV_IDS[@]}"; do
    for want in ecosystem package vuln-version fixed-version osv-id severity; do
      if [[ -z ${BENCH_SCA_ADV[$c/$want]:-} ]]; then
        printf 'bench: sca advisory `%s` is missing the required key `%s`\n' "$c" "$want" >&2
        return 2
      fi
    done
  done
  return 0
}

# sca_advisory_field ID KEY - print one field, empty if absent.
sca_advisory_field() { printf '%s' "${BENCH_SCA_ADV[$1/$2]:-}"; }
