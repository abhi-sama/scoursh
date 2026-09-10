#!/usr/bin/env bash
# bench/run-tool.sh - run one tool against one corpus, preserving its raw
# output verbatim and emitting the normalised records beside it.
#
#   bench/run-tool.sh --tool scoursh --sample sast-192 --out bench/results/smoke
#   bench/run-tool.sh --tool semgrep --root /abs/path --corpus my-corpus --out …
#   bench/run-tool.sh --list-tools
#
# Writes, under <out>/<tool>/ :
#   raw/            the tool's own output, byte for byte, plus its stderr and
#                   its exit code
#   normalised.jsonl the harness's record shape
#   MANIFEST        tool version, corpus id and pinned commit, gate config,
#                   wall clock, and the scope this tool CLAIMS
#
# THE RAW OUTPUT IS THE POINT, not a debugging convenience.  The scout report's
# rule R7 - "the whole thing must be re-runnable by a stranger" - is what the
# numbers already shipping in docs/COMPARISON.md fail, and raw output is the
# half of it a reader cannot reconstruct.  A normalised record is this
# harness's INTERPRETATION of what a tool said; keeping the tool's own words
# beside it is what lets a reader who distrusts the interpretation check it.
#
# RUNTIME IS RECORDED AS A WALL CLOCK AND A FILE COUNT, never as a rate.
# scoursh's cost is ~38 s of fixed startup plus ~0.3 s/file (the scout report,
# §3.3), so a single total on a small corpus is almost entirely startup and
# every such comparison is wrong in scoursh's disfavour.  Publishing `a + b·n`
# needs both numbers from at least two corpus sizes, which is why this file
# records the inputs to that fit rather than a ratio it cannot honestly
# compute from one run.
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BENCH_LIB_DIR=$BENCH_ROOT/lib
# shellcheck source=bench/lib/normalise.sh
source "$BENCH_LIB_DIR/normalise.sh"
# shellcheck source=bench/lib/corpus.sh
source "$BENCH_LIB_DIR/corpus.sh"

LOCK=${BENCH_CORPUS_LOCK:-$BENCH_ROOT/corpus.lock}
CORPORA=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}

usage() {
  cat <<'EOF'
bench/run-tool.sh --tool NAME (--sample NAME | --root DIR --corpus ID) --out DIR

  --tool NAME     an adapter under bench/tools/ (see --list-tools)
  --sample NAME   a sample built by bench/make-sample.sh; supplies the scan
                  root, the corpus id and the pinned commit together
  --root DIR      scan this directory instead
  --corpus ID     the corpus id to record when using --root
  --out DIR       where to write <tool>/{raw,normalised.jsonl,MANIFEST}
  --portable-paths  rewrite the absolute scan-root prefix to <SCAN_ROOT>
                  everywhere under <out>/<tool>/ once the run is finished.
                  Use it for a result that will be COMMITTED.
  --list-tools    the adapters present
EOF
}

list_tools() {
  local f
  for f in "$BENCH_ROOT"/tools/*.sh; do
    [[ -e $f ]] || continue
    printf '%s\n' "$(basename "$f" .sh)"
  done
}

main() {
  local tool='' sample='' root='' corpus='' out='' portable=0
  while (( $# > 0 )); do
    case $1 in
      --tool) tool=$2; shift 2 ;;
      --sample) sample=$2; shift 2 ;;
      --root) root=$2; shift 2 ;;
      --corpus) corpus=$2; shift 2 ;;
      --out) out=$2; shift 2 ;;
      --portable-paths) portable=1; shift ;;
      --list-tools) list_tools; return 0 ;;
      -h | --help) usage; return 0 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done
  [[ -n $tool && -n $out ]] || { usage >&2; return 2; }

  local adapter=$BENCH_ROOT/tools/$tool.sh
  [[ -r $adapter ]] || { printf 'bench: no adapter for tool: %s\n' "$tool" >&2; return 2; }
  # shellcheck source=/dev/null
  source "$adapter"

  local commit='' truth=''
  if [[ -n $sample ]]; then
    local sdir=$CORPORA/_samples/$sample
    [[ -d $sdir ]] || {
      printf 'bench: no such sample: %s (run bench/make-sample.sh)\n' "$sample" >&2
      return 2
    }
    root=$sdir/root
    truth=$sdir/truth
    corpus=$sample
    commit=$(sed -n 's/^commit: //p' "$sdir/MANIFEST")
  fi
  [[ -n $root && -d $root ]] || { printf 'bench: --root must be a directory: %s\n' "$root" >&2; return 2; }
  [[ -n $corpus ]] || { printf 'bench: --corpus is required with --root\n' >&2; return 2; }
  root=$(cd -- "$root" && pwd -P)

  if [[ -z $commit ]] && corpus_load "$LOCK" 2>/dev/null && corpus_has "$corpus"; then
    commit=$(corpus_field "$corpus" commit)
  fi

  "${tool}_available" || {
    # An absent tool is REFUSED, never recorded as a run that found nothing.
    # "semgrep is not installed" and "semgrep found nothing" are different
    # facts and only one of them is a benchmark result; emitting an empty
    # normalised.jsonl here would make the second indistinguishable from the
    # first for every reader downstream.
    printf 'bench: tool not available here: %s\n' "$tool" >&2
    return 2
  }

  local version
  version=$("${tool}_version")

  local dest=$out/$tool
  rm -rf "${dest:?}"
  mkdir -p "$dest/raw"

  local nfiles
  nfiles=$(find "$root" -type f | wc -l | tr -d ' ')

  local t0 t1 rc=0
  t0=$(date +%s)
  "${tool}_run" "$dest/raw" "$root" || rc=$?
  t1=$(date +%s)
  if (( rc != 0 )); then
    printf 'bench: %s run failed (rc=%d); raw output kept at %s\n' "$tool" "$rc" "$dest/raw" >&2
    return "$rc"
  fi

  "${tool}_normalise" "$dest/raw" "$root" |
    bench_records_to_jsonl "$tool" "$version" "$corpus" >"$dest/normalised.jsonl"

  {
    printf 'tool: %s\n' "$tool"
    printf 'version: %s\n' "$version"
    printf 'corpus: %s\n' "$corpus"
    printf 'corpus-commit: %s\n' "${commit:-unpinned}"
    printf 'scan-root: %s\n' "$root"
    printf 'files-scanned: %s\n' "$nfiles"
    printf 'wall-clock-seconds: %s\n' "$(( t1 - t0 ))"
    printf 'records: %s\n' "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')"
    printf 'claims-categories: %s\n' "$("${tool}_scope" | tr '\n' ' ' | sed 's/ $//')"
    [[ -n $truth ]] && printf 'ground-truth: %s\n' "$truth"
    printf 'gate: %s\n' "$(_gate_line "$tool")"
    printf 'note: runtime is a WALL CLOCK over %s file(s), not a rate - see the\n' "$nfiles"
    printf '  header of bench/run-tool.sh for why a single total on a small corpus\n'
    printf '  is mostly fixed startup cost.\n'
  } >"$dest/MANIFEST"

  if (( portable )); then _portable_paths "$dest" "$root"; fi

  printf 'bench: %s @ %s -> %s (%s record(s), %ds)\n' \
    "$tool" "$version" "$dest/normalised.jsonl" \
    "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')" "$(( t1 - t0 ))"
}

# _portable_paths DEST ROOT - rewrite the absolute scan root to <SCAN_ROOT>.
#
# WHY A COMMITTED RESULT IS NOT BYTE-VERBATIM, stated here rather than left for
# a reader to notice.  Every tool echoes back the path it was given, so a raw
# output captured on a real machine embeds that machine's absolute scan root -
# which, for anything committed to a public repository, is an operator's home
# directory.  This rewrite is the ONE transformation applied, it is purely
# mechanical (one prefix, one token), and the MANIFEST records that it
# happened, so a reader is never left to wonder whether anything else was
# edited.  Without `--portable-paths` nothing is touched at all.
#
# It runs AFTER normalisation, deliberately: the normalisers resolve paths
# against the real scan root, and rewriting first would leave them resolving
# against a token that is not a prefix of anything.
_portable_paths() {
  local dest=$1 root=$2 f
  # TWO prefixes, longest first.  The scan root is itself usually under
  # bench/, so rewriting bench/ first would leave `<BENCH>/corpora/_samples/…`
  # behind and the scan-root rule would then match nothing - the tokens would
  # be inconsistent between files rather than absent, which is worse than
  # either alone.  The second rule is what catches the paths that live OUTSIDE
  # the scan root and still name the operator's home: the ground-truth file
  # and the output directory.
  while IFS= read -r f; do
    LC_ALL=C sed -i.bak \
      -e "s|${root//|/\\|}|<SCAN_ROOT>|g" \
      -e "s|${BENCH_ROOT//|/\\|}|<BENCH>|g" "$f" && rm -f "$f.bak"
  done < <(find "$dest" -type f ! -name '*.bak')
  printf 'portable-paths: the scan-root prefix was replaced by <SCAN_ROOT> and the bench/ prefix by <BENCH>; no other edit was made\n' \
    >>"$dest/MANIFEST"
}

# The exact configuration each tool was run at, recorded rather than implied.
# R5 again: "gate configuration must be declared, symmetric, and never tuned
# against the corpus" - a manifest that omits it lets a later reader assume
# whichever configuration flatters the conclusion they already hold.
_gate_line() {
  case $1 in
    scoursh) printf 'scan.sh sast --format json (defaults: --profile-scan full --min-confidence low; NOT --use-engines)' ;;
    semgrep | semgrep-default) printf 'semgrep --config %s --no-git-ignore --metrics=off' "$BENCH_SEMGREP_CONFIG" ;;
    *) printf 'unrecorded - add a row to _gate_line in bench/run-tool.sh' ;;
  esac
}

main "$@"
