#!/usr/bin/env bash
# bench/lib/corpus.sh - read bench/corpus.lock.
#
# The lock file uses the same blank-line-separated `key: value` block-record
# shape rules/RULE-FORMAT.md freezes for the scanner, so this reader is
# deliberately small and deliberately its OWN: bench/ does not source
# lib/records.sh, for the reason bench/lib/json.sh's header gives.
#
# Values carry no escaping - the bytes after the first ": " to end of line are
# the value - and a line whose first byte is `#` is a whole-line comment.  A
# continuation line (two leading spaces) appends to the previous key with a
# single space, which is what lets a `note` run to several lines.
#
# shellcheck shell=bash

# SC2016: the diagnostics quote record keys (`id:`, `key: value`) literally.
# SC2034: BENCH_CORPUS/BENCH_CORPUS_IDS are this file's published outputs.
# shellcheck disable=SC2016,SC2034
[[ -n ${BENCH_CORPUS_SOURCED:-} ]] && return 0
BENCH_CORPUS_SOURCED=1

# corpus_load FILE
#
# Populates two globals:
#   BENCH_CORPUS_IDS   - array, in file order
#   BENCH_CORPUS       - assoc, keyed `<id>/<key>`; a repeated key (`note`)
#                        accumulates newline-separated.
#
# Returns 2 on a malformed file rather than skipping the bad record: a lock
# file that silently drops a corpus produces a benchmark that silently
# measured fewer things than it claims, which is the failure this whole
# harness exists to make impossible.
corpus_load() {
  local file=$1 line key val id='' lastkey='' lineno=0
  [[ -r $file ]] || { printf 'bench: cannot read corpus lock: %s\n' "$file" >&2; return 2; }

  BENCH_CORPUS_IDS=()
  unset BENCH_CORPUS
  declare -gA BENCH_CORPUS=()

  while IFS= read -r line || [[ -n $line ]]; do
    lineno=$(( lineno + 1 ))
    [[ ${line:0:1} == '#' ]] && continue
    if [[ -z $line ]]; then id=''; lastkey=''; continue; fi

    # A continuation line: exactly two leading spaces, appended to the
    # previous key.  Checked BEFORE the `key: value` split, because a
    # continuation whose prose happens to contain ": " would otherwise be
    # read as a new key and silently truncate the note.
    if [[ $line == '  '* ]]; then
      if [[ -z $id || -z $lastkey ]]; then
        printf 'bench: %s:%d: continuation line with no preceding key\n' "$file" "$lineno" >&2
        return 2
      fi
      BENCH_CORPUS[$id/$lastkey]="${BENCH_CORPUS[$id/$lastkey]} ${line#  }"
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
      BENCH_CORPUS_IDS+=("$id")
      BENCH_CORPUS[$id/id]=$val
      lastkey=id
      continue
    fi

    if [[ -n ${BENCH_CORPUS[$id/$key]:-} ]]; then
      BENCH_CORPUS[$id/$key]="${BENCH_CORPUS[$id/$key]}"$'\n'"$val"
    else
      BENCH_CORPUS[$id/$key]=$val
    fi
    lastkey=$key
  done <"$file"

  local want c
  for c in "${BENCH_CORPUS_IDS[@]}"; do
    for want in repo commit licence ground-truth categories; do
      if [[ -z ${BENCH_CORPUS[$c/$want]:-} ]]; then
        printf 'bench: corpus `%s` is missing the required key `%s`\n' "$c" "$want" >&2
        return 2
      fi
    done
    # A pin has to be a real, full sha.  An abbreviated one is ambiguous
    # across a repository's lifetime and a branch name is not a pin at all -
    # both would make the corpus a moving target while LOOKING pinned, which
    # is worse than an unpinned corpus that says so.
    if [[ ! ${BENCH_CORPUS[$c/commit]} =~ ^[0-9a-f]{40}$ ]]; then
      printf 'bench: corpus `%s` commit is not a full 40-hex sha: %s\n' \
        "$c" "${BENCH_CORPUS[$c/commit]}" >&2
      return 2
    fi
    if [[ ${BENCH_CORPUS[$c/licence]} == unstated ]]; then
      printf 'bench: corpus `%s` has an unstated licence and must not be used\n' "$c" >&2
      return 2
    fi
  done
  return 0
}

# corpus_field ID KEY - print one field, empty if absent.
corpus_field() { printf '%s' "${BENCH_CORPUS[$1/$2]:-}"; }

# corpus_has ID - 0 if the lock file declares this corpus.
corpus_has() { [[ -n ${BENCH_CORPUS[$1/id]:-} ]]; }
