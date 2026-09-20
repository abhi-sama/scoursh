#!/usr/bin/env bash
# bench/fetch-corpus.sh - fetch a corpus pinned in bench/corpus.lock.
#
#   bench/fetch-corpus.sh --list
#   bench/fetch-corpus.sh owasp-benchmark
#   bench/fetch-corpus.sh --all
#
# THIS IS THE ONLY FILE IN bench/ THAT TOUCHES THE NETWORK, and it is never
# called by a measurement run, by the scanner, or by the test suite - exactly
# the quarantine tools/vendor-engines.sh sits behind on the scanner side.
# Fetch once, then every `bench/run-tool.sh` and `bench/score.sh` invocation
# is offline.
#
# scoursh's own no-egress rule is NOT weakened by this: the constraint binds
# the tool under test, not the test rig.  bench/ is
# not on the scan path and nothing under lib/, modules/ or scan.sh references
# it - `tests/suites/bench.sh` section G asserts that in both directions.
#
# WHAT "FETCHED" MEANS HERE.  A shallow clone pinned to the sha in the lock
# file, verified AFTER checkout by reading HEAD back.  `git clone --depth 1`
# cannot clone a sha directly on every server, so this inits, fetches the one
# object, and checks it out - which also fails loudly if the sha has been
# garbage-collected, rather than silently landing on a branch tip.
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=bench/lib/corpus.sh
source "$BENCH_ROOT/lib/corpus.sh"

LOCK=${BENCH_CORPUS_LOCK:-$BENCH_ROOT/corpus.lock}
DEST_ROOT=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}

usage() {
  cat <<'EOF'
bench/fetch-corpus.sh - fetch a corpus pinned in bench/corpus.lock

  --list          what the lock file declares, with licence and ground truth
  --all           fetch every corpus
  <id>            fetch one corpus by its lock-file id

Corpora land in bench/corpora/<id>/ , which is gitignored: no corpus content
is ever committed to this repository.  See the licence paragraph at the top of
bench/corpus.lock for why that is a licence requirement and not only a size
one.
EOF
}

fetch_one() {
  local id=$1
  corpus_has "$id" || { printf 'bench: no such corpus in %s: %s\n' "$LOCK" "$id" >&2; return 2; }

  local repo commit sparse dest
  repo=$(corpus_field "$id" repo)
  commit=$(corpus_field "$id" commit)
  sparse=$(corpus_field "$id" sparse)
  dest=$DEST_ROOT/$id

  if [[ -d $dest/.git ]]; then
    local have
    have=$(git -C "$dest" rev-parse HEAD 2>/dev/null || printf 'unknown')
    if [[ $have == "$commit" ]]; then
      printf 'bench: %s already at %s\n' "$id" "$commit"
      return 0
    fi
    printf 'bench: %s is at %s, want %s - refetching\n' "$id" "$have" "$commit" >&2
    rm -rf "${dest:?}"
  fi

  mkdir -p "$dest"
  git -C "$dest" init --quiet
  git -C "$dest" remote add origin "$repo"
  if [[ -n $sparse ]]; then
    git -C "$dest" config core.sparseCheckout true
    git -C "$dest" sparse-checkout init --cone
    # CONE mode, and the ground-truth file needs no rule of its own: cone
    # mode always materialises the files in the repository ROOT, which is
    # where `expectedresults-1.2.csv` lives.  A non-cone `sparse-checkout add
    # /` is rejected outright ("specify directories rather than patterns"),
    # and the naive fix - dropping cone mode - would leave the root files out
    # and deliver a corpus of cases with no labels, which scores as "every
    # case is a miss" rather than as an error.
    git -C "$dest" sparse-checkout set "$sparse"
  fi
  printf 'bench: fetching %s @ %s\n' "$id" "$commit" >&2
  git -C "$dest" fetch --quiet --depth 1 origin "$commit"
  git -C "$dest" checkout --quiet FETCH_HEAD

  local got
  got=$(git -C "$dest" rev-parse HEAD)
  if [[ $got != "$commit" ]]; then
    printf 'bench: %s checked out %s but the lock pins %s - refusing\n' "$id" "$got" "$commit" >&2
    return 2
  fi
  printf 'bench: %s ready at %s (%s)\n' "$id" "$dest" "$commit"
}

main() {
  corpus_load "$LOCK" || return $?
  case ${1:-} in
    '' | -h | --help) usage; return 0 ;;
    --list)
      local id
      for id in "${BENCH_CORPUS_IDS[@]}"; do
        printf '%-18s %-12s ground-truth=%-32s categories=%s\n' \
          "$id" "$(corpus_field "$id" licence)" \
          "$(corpus_field "$id" ground-truth)" "$(corpus_field "$id" categories)"
      done
      return 0
      ;;
    --all)
      local id rc=0
      for id in "${BENCH_CORPUS_IDS[@]}"; do fetch_one "$id" || rc=$?; done
      return "$rc"
      ;;
    -*) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    *) fetch_one "$1" ;;
  esac
}

main "$@"
