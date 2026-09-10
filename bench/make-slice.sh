#!/usr/bin/env bash
# bench/make-slice.sh - materialise a SCAN ROOT that is a subset of a fetched
# corpus, so every tool in a leg is pointed at exactly the same surface.
#
#   bench/make-slice.sh kubernetes-goat k8s-scenarios \
#       --from scenarios --exclude metadata-db
#
# WHY THIS EXISTS.  A scan root that contains material the LABEL SET excludes
# is not neutral.  Every finding a tool reports there is unjudged - neither
# credited nor penalised - so it inflates the "outside every labelled range"
# column with output nobody ever intended to score, and it leaves a reader
# unable to tell "the labeller declined to judge this" from "no labeller could
# have judged this".  Making the scan surface equal the labelled surface is
# what removes that ambiguity, and recording the slice in a MANIFEST is what
# lets a reader see the surface rather than infer it.
#
# The worked case is kubernetes-goat.  `scenarios/metadata-db/` is a Helm
# chart whose templates are unrendered Go templates - `metadata.name: {{
# include ... }}` is not a Kubernetes manifest until `helm template` has run -
# so the kubernetes-goat label set excludes it, and the slice excludes it to
# match.  Measured, and worth recording because the obvious guess is wrong:
# excluding it changes NO tool's finding count on this corpus (Checkov 3.3.10
# reports the same 253 failed checks with and without it).  The exclusion is
# justified by the labels alone, and this file does not claim otherwise.
#
# WHAT MAKES IT A NORMALISATION RATHER THAN A TUNING KNOB, which is the only
# thing that matters here:
#
#   * The slice is applied ONCE and every tool in the leg is pointed at the
#     result.  It cannot advantage one tool over another because no tool sees
#     a different tree.
#   * Its exact arguments are recorded in the slice's own MANIFEST, which the
#     leg's result directory carries.
#   * It only ever REMOVES paths.  There is no way to add, edit or reorder
#     corpus content with it.
#   * The exclusion has to be justified against the LABEL SET, not against a
#     result.  Excluding a path the labels DO score would silently shrink the
#     denominator, and that is the misuse to watch for in review.
#
# The slice lands under bench/corpora/_slices/, which is inside the gitignored
# bench/corpora/ - it holds corpus content and is never committed.
#
# SC2016: prose quotes record and shell syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=bench/lib/corpus.sh
source "$BENCH_ROOT/lib/corpus.sh"

LOCK=${BENCH_CORPUS_LOCK:-$BENCH_ROOT/corpus.lock}
DEST_ROOT=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}

usage() {
  cat <<'USAGE'
bench/make-slice.sh CORPUS-ID SLICE-NAME [--from SUBDIR] [--exclude PATH ...]

Builds bench/corpora/_slices/SLICE-NAME/ :
  root/      the corpus subtree, minus every --exclude path
  MANIFEST   which corpus, which pinned commit, and the exact slice arguments

--from SUBDIR    start from this path inside the corpus (default: its root)
--exclude PATH   drop this path, relative to the --from subtree.  Repeatable.
USAGE
}

main() {
  local corpus=${1:-} name=${2:-} from='' 
  local excludes=()
  [[ -z $corpus || -z $name || $corpus == -h || $corpus == --help ]] && { usage; return 0; }
  shift 2
  while (( $# > 0 )); do
    case $1 in
      --from) from=$2; shift 2 ;;
      --exclude) excludes+=("$2"); shift 2 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done

  corpus_load "$LOCK" || return $?
  corpus_has "$corpus" || { printf 'bench: no such corpus: %s\n' "$corpus" >&2; return 2; }

  local src=$DEST_ROOT/$corpus
  [[ -d $src ]] || {
    printf 'bench: corpus not fetched: %s (run bench/fetch-corpus.sh %s)\n' "$src" "$corpus" >&2
    return 2
  }
  local base=$src${from:+/$from}
  [[ -d $base ]] || { printf 'bench: no such subtree: %s\n' "$base" >&2; return 2; }

  local out=$DEST_ROOT/_slices/$name
  # `${out:?}` so an empty expansion can never make this `rm -rf /`.
  rm -rf "${out:?}"
  mkdir -p "$out/root"

  # Copy the subtree, then delete the excluded paths from the COPY.  Doing it
  # in that order rather than filtering during the walk keeps this readable and
  # keeps the corpus itself untouched - nothing here ever writes under $src.
  ( cd -- "$base" && tar cf - . ) | ( cd -- "$out/root" && tar xf - )

  local e
  for e in ${excludes[@]+"${excludes[@]}"}; do
    case $e in
      /* | *..*)
        # An absolute or parent-relative exclude could delete outside the
        # slice.  Refused rather than sanitised, because a silently-rewritten
        # path is a path the MANIFEST no longer describes.
        printf 'bench: --exclude must be a relative path with no `..`: %s\n' "$e" >&2
        return 2
        ;;
    esac
    [[ -e $out/root/$e ]] || {
      printf 'bench: --exclude names nothing in the slice: %s\n' "$e" >&2
      return 2
    }
    rm -rf "${out:?}/root/${e:?}"
  done

  {
    printf 'slice: %s\n' "$name"
    printf 'corpus: %s\n' "$corpus"
    printf 'commit: %s\n' "$(corpus_field "$corpus" commit)"
    printf 'licence: %s\n' "$(corpus_field "$corpus" licence)"
    printf 'from: %s\n' "${from:-<corpus root>}"
    if (( ${#excludes[@]} )); then
      for e in "${excludes[@]}"; do printf 'exclude: %s\n' "$e"; done
    else
      printf 'exclude: <none>\n'
    fi
    printf 'files: %s\n' "$(find "$out/root" -type f | wc -l | tr -d ' ')"
    printf 'note: a slice only ever REMOVES paths, it is applied once and every tool\n'
    printf '  in the leg is pointed at this same root, and each exclusion is justified\n'
    printf '  against the label set - see the header of bench/make-slice.sh.\n'
  } >"$out/MANIFEST"

  printf 'bench: slice %s built at %s\n' "$name" "$out/root"
  cat "$out/MANIFEST"
}

main "$@"
