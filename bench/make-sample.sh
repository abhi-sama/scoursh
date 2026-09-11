#!/usr/bin/env bash
# bench/make-sample.sh - build a deterministic, balanced sample of a fetched
# corpus, plus its ground-truth file.
#
#   bench/make-sample.sh owasp-benchmark sast-192 \
#       --per-class 12 --categories 'sqli cmdi ldapi pathtraver crypto hash weakrand xss'
#
# WHY A SAMPLE AT ALL.  The full OWASP Benchmark is 2,740 cases and scoursh
# costs ~0.3 s/file on top of a ~38 s fixed startup, so a full run is ~20
# minutes per tool per gate configuration.  That is the right cost for the B4
# measurement leg; it is the wrong cost for proving the harness works, which
# is what this file exists for.
#
# WHY IT IS BALANCED AND DETERMINISTIC, which are two separate requirements:
#
#   BALANCED - equal numbers of real cases and sanitized traps per category,
#   so no category can dominate the aggregate and so the false-positive rate
#   has the same denominator as recall.  An unbalanced sample makes Youden J
#   a statement about the sample's composition rather than about the tool.
#
#   DETERMINISTIC - selection is the first N by `LC_ALL=C sort` of the case
#   id, never a random draw and never filesystem order.  A benchmark whose
#   sample changes between runs cannot be re-derived by a reader, and it also
#   makes "the score moved" ambiguous
#   between "the tool changed" and "the sample did".
#
# The sample directory is written under bench/corpora/, which is gitignored:
# it holds corpus content and is never committed (bench/corpus.lock's licence
# paragraph).  The ground-truth file it writes is derived from the corpus's
# own labels and is written there for the same reason.
#
# SC2016: prose and markdown code spans quote shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=bench/lib/corpus.sh
source "$BENCH_ROOT/lib/corpus.sh"
# shellcheck source=bench/lib/truth.sh
source "$BENCH_ROOT/lib/truth.sh"

LOCK=${BENCH_CORPUS_LOCK:-$BENCH_ROOT/corpus.lock}
DEST_ROOT=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}

usage() {
  cat <<'EOF'
bench/make-sample.sh CORPUS-ID SAMPLE-NAME [--per-class N] [--categories 'a b c']

Builds bench/corpora/_samples/SAMPLE-NAME/ :
  root/    the sampled case files, at their original relative paths
  truth    the ground-truth records for exactly those cases
  MANIFEST what was sampled, from which pinned commit, and how

--per-class N   how many REAL and how many TRAP cases per category (default 12)
--categories    space-separated; default is every category in the corpus
EOF
}

main() {
  local corpus=${1:-} name=${2:-} per_class=12 categories=''
  [[ -z $corpus || -z $name || $corpus == -h || $corpus == --help ]] && { usage; return 0; }
  shift 2
  while (( $# > 0 )); do
    case $1 in
      --per-class) per_class=$2; shift 2 ;;
      --categories) categories=$2; shift 2 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done
  [[ $per_class =~ ^[0-9]+$ ]] || { printf 'bench: --per-class must be a number\n' >&2; return 2; }

  corpus_load "$LOCK" || return $?
  corpus_has "$corpus" || { printf 'bench: no such corpus: %s\n' "$corpus" >&2; return 2; }

  local src commit gt sparse
  src=$DEST_ROOT/$corpus
  [[ -d $src ]] || {
    printf 'bench: corpus not fetched: %s (run bench/fetch-corpus.sh %s)\n' "$src" "$corpus" >&2
    return 2
  }
  commit=$(corpus_field "$corpus" commit)
  gt=$(corpus_field "$corpus" ground-truth)
  sparse=$(corpus_field "$corpus" sparse)

  case $gt in
    csv:*) ;;
    *)
      # A corpus with no machine-readable ground truth cannot be SAMPLED into
      # a balanced set, because "balanced" is a statement about labels this
      # corpus does not have.  Refusing here is what keeps a coverage-only
      # corpus (TerraGoat) from silently acquiring a recall score.
      printf 'bench: corpus %s has ground-truth `%s`; only `csv:` corpora can be sampled\n' \
        "$corpus" "$gt" >&2
      return 2
      ;;
  esac

  local csv=$src/${gt#csv:}
  [[ -r $csv ]] || { printf 'bench: ground truth not found: %s\n' "$csv" >&2; return 2; }

  [[ -n $categories ]] || categories=$(corpus_field "$corpus" categories)

  local out=$DEST_ROOT/_samples/$name
  rm -rf "${out:?}"
  mkdir -p "$out/root"

  # All labels for the requested categories, then per (category, real) the
  # first `per_class` by case id.
  local all=$out/.all-truth
  # shellcheck disable=SC2086
  truth_from_owasp "$csv" "${sparse:+$sparse/}" $categories >"$all"

  local cat real picked=0 kept=$out/truth
  : >"$kept"
  local cats
  # LC_ALL=C so the category order in the manifest is stable across userlands.
  mapfile -t cats < <(cut -d"$BENCH_TRUTH_US" -f3 "$all" | LC_ALL=C sort -u)
  for cat in "${cats[@]}"; do
    for real in true false; do
      local n=0 line c f ccat cwe creal
      while IFS= read -r line; do
        IFS=$BENCH_TRUTH_US read -r c f ccat cwe creal <<<"$line"
        [[ $ccat == "$cat" && $creal == "$real" ]] || continue
        (( n < per_class )) || break
        printf '%s\n' "$line" >>"$kept"
        n=$(( n + 1 ))
        picked=$(( picked + 1 ))
      done < <(LC_ALL=C sort "$all")
      if (( n < per_class )); then
        printf 'bench: category %s has only %d `real=%s` case(s), wanted %d\n' \
          "$cat" "$n" "$real" "$per_class" >&2
      fi
    done
  done
  rm -f "$all"

  # Copy exactly the selected files, preserving their relative path so a
  # finding's `file` matches the truth's `file` byte for byte.
  local c f
  while IFS= read -r line; do
    IFS=$BENCH_TRUTH_US read -r c f _ _ _ <<<"$line"
    [[ -r $src/$f ]] || { printf 'bench: case file missing from corpus: %s\n' "$f" >&2; return 2; }
    mkdir -p "$out/root/$(dirname "$f")"
    cp "$src/$f" "$out/root/$f"
  done <"$kept"

  {
    printf 'sample: %s\n' "$name"
    printf 'corpus: %s\n' "$corpus"
    printf 'commit: %s\n' "$commit"
    printf 'licence: %s\n' "$(corpus_field "$corpus" licence)"
    printf 'per-class: %s\n' "$per_class"
    printf 'categories: %s\n' "$categories"
    printf 'cases: %s\n' "$picked"
    printf 'real-cases: %s\n' "$(cut -d"$BENCH_TRUTH_US" -f5 "$kept" | grep -c '^true$' || true)"
    printf 'trap-cases: %s\n' "$(cut -d"$BENCH_TRUTH_US" -f5 "$kept" | grep -c '^false$' || true)"
    printf 'selection: first N by LC_ALL=C sort of the case id - deterministic, never random\n'
  } >"$out/MANIFEST"

  printf 'bench: sample %s built: %d case(s) under %s\n' "$name" "$picked" "$out"
  cat "$out/MANIFEST"
}

main "$@"
