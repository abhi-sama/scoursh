#!/usr/bin/env bash
# bench/score.sh - score one or more tools' normalised output against a
# corpus's ground truth, and render the scorecard.
#
#   bench/score.sh --truth bench/corpora/_samples/sast-192/truth \
#                  --results bench/results/smoke-owasp-sast-192 \
#                  --min-severity any --format md
#
# Reads <results>/<tool>/normalised.jsonl for every tool directory present,
# and <results>/<tool>/MANIFEST for that tool's version and claimed scope.
#
# WHAT IT REFUSES TO DO, and why each refusal is the deliverable rather than a
# limitation:
#
#   * It never emits a single number spanning two corpora or two category
#     families.  The scout report's §7.3 forbids an "overall score" because
#     the scope differences make it meaningless and because it is the first
#     thing an unfriendly reader attacks.  The per-corpus aggregate it DOES
#     emit is labelled with exactly which categories went into it and how many
#     were excluded as no-coverage.
#   * It never converts a no-coverage cell into a zero.  See the scope-gating
#     paragraph in bench/lib/score.sh.
#   * It never invents a ground truth.  `--truth` is required and an unreadable
#     one is exit 2, never an empty case list scored as "every tool found
#     nothing".  A corpus whose lock-file row says `ground-truth: none` has no
#     truth file for `bench/make-sample.sh` to produce, which is where that
#     refusal actually happens - this file simply has nothing to be given.
#
# SC2016: prose and markdown code spans quote shell/record syntax literally.
# shellcheck disable=SC2016
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BENCH_LIB_DIR=$BENCH_ROOT/lib
# shellcheck source=bench/lib/truth.sh
source "$BENCH_LIB_DIR/truth.sh"
# shellcheck source=bench/lib/score.sh
source "$BENCH_LIB_DIR/score.sh"

usage() {
  cat <<'EOF'
bench/score.sh --truth FILE --results DIR [options]

  --truth FILE        ground-truth records (bench/lib/truth.sh format)
  --results DIR       a directory of <tool>/normalised.jsonl
  --classes FILE      CWE equivalence classes (default bench/cwe-classes.conf)
  --match file|line   how a finding is matched to a case (default file).
                      `line` requires every case to carry a line range and
                      scores a case only from findings inside its own range -
                      use it for a corpus with several cases per file.
  --line-window N     widen each case's range by N lines on both sides
                      (default 0; --match line only)
  --min-severity S    any|info|low|medium|high|critical   (default any)
  --format md|json    (default md)
  --out FILE          write there instead of stdout
EOF
}

# tool_claims TOOL - the categories a tool claims, from its run MANIFEST if
# one is present, else from its adapter.
#
# The MANIFEST is preferred BECAUSE it is a record of what the tool claimed AT
# RUN TIME.  Re-asking the adapter would let a later edit to `<tool>_scope`
# silently restate an old run's scope, which is the same class of error as
# publishing a number without its version.
tool_claims() {
  local results=$1 tool=$2 line
  if [[ -r $results/$tool/MANIFEST ]]; then
    line=$(sed -n 's/^claims-categories: //p' "$results/$tool/MANIFEST" | head -1)
    [[ -n $line ]] && { printf '%s' "$line"; return 0; }
  fi
  if [[ -r $BENCH_ROOT/tools/$tool.sh ]]; then
    # shellcheck source=/dev/null
    source "$BENCH_ROOT/tools/$tool.sh"
    if declare -F "${tool}_scope" >/dev/null; then
      "${tool}_scope" | tr '\n' ' ' | sed 's/ $//'
      return 0
    fi
  fi
  printf ''
}

tool_version_of() {
  local results=$1 tool=$2 v=''
  [[ -r $results/$tool/MANIFEST ]] &&
    v=$(sed -n 's/^version: //p' "$results/$tool/MANIFEST" | head -1)
  printf '%s' "${v:-unknown}"
}

tool_corpus_commit() {
  local results=$1 tool=$2 v=''
  [[ -r $results/$tool/MANIFEST ]] &&
    v=$(sed -n 's/^corpus-commit: //p' "$results/$tool/MANIFEST" | head -1)
  printf '%s' "${v:-unpinned}"
}

main() {
  local truth='' results='' classes=$BENCH_ROOT/cwe-classes.conf
  local minsev=any format=md out=''
  BENCH_MATCH='file'
  BENCH_WINDOW='0'
  while (( $# > 0 )); do
    case $1 in
      --truth) truth=$2; shift 2 ;;
      --results) results=$2; shift 2 ;;
      --classes) classes=$2; shift 2 ;;
      --match) BENCH_MATCH=$2; shift 2 ;;
      --line-window) BENCH_WINDOW=$2; shift 2 ;;
      --min-severity) minsev=$2; shift 2 ;;
      --format) format=$2; shift 2 ;;
      --out) out=$2; shift 2 ;;
      -h | --help) usage; return 0 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done
  [[ -n $truth && -n $results ]] || { usage >&2; return 2; }
  case $minsev in any | info | low | medium | high | critical) ;;
    *) printf 'bench: --min-severity must be any|info|low|medium|high|critical\n' >&2; return 2 ;;
  esac
  case $format in md | json) ;;
    *) printf 'bench: --format must be md or json\n' >&2; return 2 ;;
  esac
  case $BENCH_MATCH in file | line) ;;
    *) printf 'bench: --match must be file or line\n' >&2; return 2 ;;
  esac
  [[ $BENCH_WINDOW =~ ^[0-9]+$ ]] ||
    { printf 'bench: --line-window must be a non-negative integer\n' >&2; return 2; }

  truth_load "$truth" || return $?
  cwe_classes_load "$classes" || return $?

  # `--match line` over a truth file whose cases carry no range is REFUSED, not
  # quietly demoted to file matching.  Demoting it would report a number under
  # a heading that names a granularity it was not computed at, and the number
  # would be the INFLATED one - every case in a file credited by any finding in
  # it - which is exactly the error `--match line` exists to prevent.
  if [[ $BENCH_MATCH == line ]]; then
    local _c _missing=0
    for _c in "${BENCH_TRUTH_CASES[@]}"; do
      [[ -n ${BENCH_TRUTH_LINE[$_c]:-} ]] || _missing=$(( _missing + 1 ))
    done
    if (( _missing > 0 )); then
      printf 'bench: --match line needs a line range on every case; %d of %d have none in %s\n' \
        "$_missing" "${#BENCH_TRUTH_CASES[@]}" "$truth" >&2
      return 2
    fi
  fi

  local tools=() d
  for d in "$results"/*/; do
    [[ -r ${d}normalised.jsonl ]] || continue
    tools+=("$(basename "$d")")
  done
  (( ${#tools[@]} > 0 )) || {
    printf 'bench: no <tool>/normalised.jsonl under %s\n' "$results" >&2
    return 2
  }
  mapfile -t tools < <(printf '%s\n' "${tools[@]}" | LC_ALL=C sort)

  if [[ -n $out ]]; then
    render_"$format" "$results" "$minsev" "${tools[@]}" >"$out"
    printf 'bench: scorecard written to %s\n' "$out"
  else
    render_"$format" "$results" "$minsev" "${tools[@]}"
  fi
}

# ---------------------------------------------------------------------------
# The markdown renderer.
# ---------------------------------------------------------------------------
render_md() {
  local results=$1 minsev=$2
  shift 2
  local tools=("$@") tool cat mode

  printf '# Detection scorecard\n\n'
  printf 'Corpus categories: `%s`\n\n' "${BENCH_TRUTH_CATS[*]}"
  printf 'Cases: %d (%d real, %d sanitized trap)\n\n' \
    "${#BENCH_TRUTH_CASES[@]}" \
    "$(_count_real true)" "$(_count_real false)"
  printf 'Severity filter: `%s`. CWE equivalence classes: `%s`.\n\n' \
    "$minsev" "$(basename "$BENCH_ROOT")/cwe-classes.conf"
  if [[ $BENCH_MATCH == line ]]; then
    printf 'Matching granularity: `line` - a case is flagged only by a finding inside its\n'
    printf 'own recorded line range (window %s). Ranges within one file do not overlap.\n\n' "$BENCH_WINDOW"
  else
    printf 'Matching granularity: `file` - a case is flagged by any finding in its file.\n\n'
  fi
  printf 'Youden J = TPR - FPR. **J = 0.000 is a coin flip.**\n\n'

  printf '## Tools\n\n'
  printf '| tool | version | corpus commit | claims |\n|---|---|---|---|\n'
  for tool in "${tools[@]}"; do
    printf '| %s | `%s` | `%s` | %s |\n' "$tool" \
      "$(tool_version_of "$results" "$tool")" \
      "$(tool_corpus_commit "$results" "$tool")" \
      "$(tool_claims "$results" "$tool")"
  done
  printf '\n'

  _volume_md "$results" "$minsev" "${tools[@]}"

  for mode in loose strict; do
    printf '## Per category - %s CWE matching\n\n' "$mode"
    printf '| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |\n'
    printf '|---|---|---|---|---|---|---|---|---|---|\n'
    for tool in "${tools[@]}"; do
      local claims
      claims=" $(tool_claims "$results" "$tool") "
      findings_load "$results/$tool/normalised.jsonl" "$minsev" || return $?
      for cat in "${BENCH_TRUTH_CATS[@]}"; do
        if [[ $claims != *" $cat "* ]]; then
          # THE NO-COVERAGE CELL.  Rendered, never omitted and never zeroed -
          # the scout report's rule R4.  Omitting the row would leave a reader
          # to assume the tool competed and the renderer lost the number;
          # zeroing it would accuse the tool of failing at something it never
          # claimed.
          printf '| %s | %s | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |\n' \
            "$tool" "$cat"
          continue
        fi
        if [[ $mode == strict ]] && ! truth_category_has_cwe "$cat"; then
          # NOT a row of zeros.  No case in this category carries a
          # ground-truth CWE, so nothing here CAN strict-match; printing
          # 0/0/0 would read as "every tool missed every case", which is a
          # claim about the tools rather than about the labels.
          printf '| %s | %s | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |\n' \
            "$tool" "$cat"
          continue
        fi
        score_category "$cat" "$mode" "$BENCH_MATCH" "$BENCH_WINDOW"
        _row "$tool" "$cat"
      done
    done
    printf '\n'
    _aggregate_md "$results" "$minsev" "$mode" "${tools[@]}"
  done

  _agreement_md "$results" "$minsev" "${tools[@]}"

  printf '\n## What this scorecard is not\n\n'
  cat <<'EOF'
- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
EOF
}

# THE FINDING-VOLUME TABLE IS NOT THE CONFUSION MATRIX AND MUST NOT BE READ AS
# ONE.  It counts RECORDS, where every number in the matrix counts CASES - a
# tool that reports one defect five times moves this table and moves nothing
# else.  It is here for two things the matrix genuinely cannot show.  `no line`
# is a record that cannot match any range, so under `line` granularity it is
# invisible to scoring, and a tool whose adapter quietly stopped emitting lines
# would otherwise read as a tool that stopped finding things.  `outside every
# labelled range` is how much of a tool's output the LABEL SET declined to
# judge - the one number that would let a benchmark shrink a tool's exposure by
# labelling only where it does well, so it is published rather than inferred.
_volume_md() {
  local results=$1 minsev=$2
  shift 2
  local tools=("$@") tool
  printf '## Finding volume (records, not cases)\n\n'
  printf '| tool | records kept | dropped by severity | no line |'
  [[ $BENCH_MATCH == line ]] && printf ' outside every labelled range |'
  # `printf --` and not a bare `printf`: the separator row starts with `-`, and
  # bash's builtin printf parses a leading `---|` as options.  Measured here -
  # it aborted the renderer mid-table with `invalid option`.
  printf -- '\n|---|---|---|---|'
  [[ $BENCH_MATCH == line ]] && printf -- '---|'
  printf '\n'
  for tool in "${tools[@]}"; do
    findings_load "$results/$tool/normalised.jsonl" "$minsev" || return $?
    printf '| %s | %d | %d | %d |' "$tool" \
      "$BENCH_FINDING_COUNT" "$BENCH_FINDING_DROPPED" "$BENCH_FINDING_NO_LINE"
    if [[ $BENCH_MATCH == line ]]; then
      findings_unscored
      printf ' %d |' "$BENCH_FINDING_UNSCORED"
    fi
    printf '\n'
  done
  printf '\n'
  printf 'These are RECORD counts. Every number in the tables below counts CASES, so a\n'
  printf 'tool reporting one defect five times moves this table and nothing else.\n\n'
}

_count_real() {
  local want=$1 c n=0
  for c in "${BENCH_TRUTH_CASES[@]}"; do
    [[ ${BENCH_TRUTH_REAL[$c]} == "$want" ]] && n=$(( n + 1 ))
  done
  printf '%d' "$n"
}

_row() {
  local tool=$1 cat=$2 tpr fpr prec j
  tpr=$(rate "$BENCH_TP" "$(( BENCH_TP + BENCH_FN ))")
  fpr=$(rate "$BENCH_FP" "$(( BENCH_FP + BENCH_TN ))")
  prec=$(rate "$BENCH_TP" "$(( BENCH_TP + BENCH_FP ))")
  j=$(youden "$tpr" "$fpr")
  printf '| %s | %s | %d | %d | %d | %d | %s | %s | %s | %s |\n' \
    "$tool" "$cat" "$BENCH_TP" "$BENCH_FN" "$BENCH_FP" "$BENCH_TN" \
    "$tpr" "$fpr" "$prec" "$j"
}

_aggregate_md() {
  local results=$1 minsev=$2 mode=$3
  shift 3
  local tools=("$@") tool cat
  printf '### Corpus aggregate - %s (claimed categories only)\n\n' "$mode"
  printf '| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |\n'
  printf '|---|---|---|---|---|---|---|---|---|---|---|\n'
  for tool in "${tools[@]}"; do
    local claims scored=0 nocov=0 nocwe=0
    local tp=0 fn=0 fp=0 tn=0
    claims=" $(tool_claims "$results" "$tool") "
    findings_load "$results/$tool/normalised.jsonl" "$minsev" || return $?
    for cat in "${BENCH_TRUTH_CATS[@]}"; do
      if [[ $claims != *" $cat "* ]]; then nocov=$(( nocov + 1 )); continue; fi
      if [[ $mode == strict ]] && ! truth_category_has_cwe "$cat"; then
        nocwe=$(( nocwe + 1 )); continue
      fi
      score_category "$cat" "$mode" "$BENCH_MATCH" "$BENCH_WINDOW"
      scored=$(( scored + 1 ))
      tp=$(( tp + BENCH_TP )); fn=$(( fn + BENCH_FN ))
      fp=$(( fp + BENCH_FP )); tn=$(( tn + BENCH_TN ))
    done
    local tpr fpr prec j
    tpr=$(rate "$tp" "$(( tp + fn ))")
    fpr=$(rate "$fp" "$(( fp + tn ))")
    prec=$(rate "$tp" "$(( tp + fp ))")
    j=$(youden "$tpr" "$fpr")
    printf '| %s | %d of %d | %d | %d | %d | %d | %d | %s | %s | %s | %s |\n' \
      "$tool" "$scored" "${#BENCH_TRUTH_CATS[@]}" "$nocov" \
      "$tp" "$fn" "$fp" "$tn" "$tpr" "$fpr" "$prec" "$j"
    (( nocwe > 0 )) && _AGG_NOCWE=$nocwe
  done
  printf '\n'
  printf 'This aggregate spans one corpus and the categories each tool CLAIMS.\n'
  printf 'It is not comparable with any other corpus, and it is not an overall score.\n'
  if [[ $mode == strict && -n ${_AGG_NOCWE:-} ]]; then
    printf '%s categor(y/ies) carry no ground-truth CWE and are excluded from this strict\n' "$_AGG_NOCWE"
    printf 'aggregate rather than counted as misses - see the per-category table above.\n'
  fi
  printf '\n'
}

# The strict/loose agreement check.  Reported every run, because the scout
# report's §3.1 could only state its headline result BECAUSE the two agreed -
# a ranking that holds under only one of them is a ranking about the scoring
# method.
_agreement_md() {
  local results=$1 minsev=$2
  shift 2
  local tools=("$@") tool cat
  printf '## Strict/loose agreement\n\n'
  printf '| tool | categories where strict and loose agree | disagreeing categories |\n|---|---|---|\n'
  for tool in "${tools[@]}"; do
    local claims agree=0 total=0 nocwe=0 diff=''
    claims=" $(tool_claims "$results" "$tool") "
    findings_load "$results/$tool/normalised.jsonl" "$minsev" || return $?
    for cat in "${BENCH_TRUTH_CATS[@]}"; do
      [[ $claims == *" $cat "* ]] || continue
      if ! truth_category_has_cwe "$cat"; then
        # A category with no ground-truth CWE cannot disagree, because strict
        # is not defined for it.  Counting it as agreement would inflate the
        # "N of M agree" fraction with categories where the check did not run.
        nocwe=$(( nocwe + 1 ))
        continue
      fi
      total=$(( total + 1 ))
      # TP and FP alone decide agreement: the case counts are fixed per
      # category, so TP+FN and FP+TN are constants and the other two cells are
      # determined by these.
      score_category "$cat" loose "$BENCH_MATCH" "$BENCH_WINDOW"
      local lt=$BENCH_TP lf=$BENCH_FP
      score_category "$cat" strict "$BENCH_MATCH" "$BENCH_WINDOW"
      if (( lt == BENCH_TP && lf == BENCH_FP )); then
        agree=$(( agree + 1 ))
      else
        diff+="$cat "
      fi
    done
    printf '| %s | %d of %d | %s |\n' "$tool" "$agree" "$total" \
      "$(if (( total == 0 )); then printf 'n/a - no category here carries a ground-truth CWE'; else printf '%s' "${diff:-none}"; fi)"
  done
  printf '\n'
  if (( nocwe > 0 )); then
    printf '%d categor(y/ies) are excluded from this check because no case in them carries a\n' "$nocwe"
    printf 'ground-truth CWE, so strict matching is undefined there rather than failing.\n\n' 
  fi
}

# ---------------------------------------------------------------------------
# The JSON renderer - the same numbers, for a consumer rather than a reader.
# ---------------------------------------------------------------------------
render_json() {
  local results=$1 minsev=$2
  shift 2
  local tools=("$@") tool cat mode first_t=1 first_c=1

  printf '{\n'
  printf '  "cases": %d,\n' "${#BENCH_TRUTH_CASES[@]}"
  printf '  "real_cases": %d,\n' "$(_count_real true)"
  printf '  "trap_cases": %d,\n' "$(_count_real false)"
  printf '  "min_severity": "%s",\n' "$minsev"
  printf '  "match": "%s",\n' "$BENCH_MATCH"
  printf '  "line_window": %s,\n' "$BENCH_WINDOW"
  printf '  "categories": ['
  first_c=1
  for cat in "${BENCH_TRUTH_CATS[@]}"; do
    (( first_c )) || printf ', '
    first_c=0
    printf '"%s"' "$cat"
  done
  printf '],\n'
  printf '  "tools": {\n'
  for tool in "${tools[@]}"; do
    (( first_t )) || printf ',\n'
    first_t=0
    local claims
    claims=" $(tool_claims "$results" "$tool") "
    printf '    "%s": {\n' "$tool"
    printf '      "version": "%s",\n' "$(tool_version_of "$results" "$tool")"
    printf '      "corpus_commit": "%s",\n' "$(tool_corpus_commit "$results" "$tool")"
    printf '      "claims": "%s",\n' "$(tool_claims "$results" "$tool")"
    findings_load "$results/$tool/normalised.jsonl" "$minsev" || return $?
    printf '      "findings_kept": %d,\n' "$BENCH_FINDING_COUNT"
    printf '      "findings_dropped_by_severity": %d,\n' "$BENCH_FINDING_DROPPED"
    printf '      "findings_without_a_line": %d,\n' "$BENCH_FINDING_NO_LINE"
    if [[ $BENCH_MATCH == line ]]; then
      findings_unscored
      printf '      "findings_outside_every_labelled_range": %d,\n' "$BENCH_FINDING_UNSCORED"
    fi
    local first_m=1
    for mode in loose strict; do
      (( first_m )) || printf ',\n'
      first_m=0
      printf '      "%s": {\n' "$mode"
      first_c=1
      for cat in "${BENCH_TRUTH_CATS[@]}"; do
        (( first_c )) || printf ',\n'
        first_c=0
        if [[ $claims != *" $cat "* ]]; then
          # `"coverage": "none"` and NOT a zeroed matrix.  A consumer that
          # averages these must be able to tell a scope boundary from a
          # failure without reading prose.
          printf '        "%s": {"coverage": "none"}' "$cat"
          continue
        fi
        if [[ $mode == strict ]] && ! truth_category_has_cwe "$cat"; then
          printf '        "%s": {"coverage": "no_cwe_in_truth"}' "$cat"
          continue
        fi
        score_category "$cat" "$mode" "$BENCH_MATCH" "$BENCH_WINDOW"
        local tpr fpr prec j
        tpr=$(rate "$BENCH_TP" "$(( BENCH_TP + BENCH_FN ))")
        fpr=$(rate "$BENCH_FP" "$(( BENCH_FP + BENCH_TN ))")
        prec=$(rate "$BENCH_TP" "$(( BENCH_TP + BENCH_FP ))")
        j=$(youden "$tpr" "$fpr")
        printf '        "%s": {"coverage": "scored", "tp": %d, "fn": %d, "fp": %d, "tn": %d, "recall": %s, "fpr": %s, "precision": %s, "youden_j": %s}' \
          "$cat" "$BENCH_TP" "$BENCH_FN" "$BENCH_FP" "$BENCH_TN" \
          "$(_jnum "$tpr")" "$(_jnum "$fpr")" "$(_jnum "$prec")" "$(_jnum "$j")"
      done
      printf '\n      }'
    done
    printf '\n    }'
  done
  printf '\n  }\n}\n'
}

# An undefined ratio is JSON `null`, never 0 - see `rate` in bench/lib/score.sh.
#
# THE LEADING `+` IS STRIPPED HERE AND ONLY HERE.  `youden` signs its output
# because a signed J is what makes "below a coin flip" visible at a glance in
# the markdown table - but RFC 8259 §6 does not admit a leading `+` on a
# number, so `"youden_j": +0.000` is not JSON.  It is not a loud failure
# either: `jq` accepts it, so a check written with jq alone certifies the file
# green while a conforming parser (python's `json`, Go's `encoding/json`)
# rejects the whole document.  Measured that way, in that order.
_jnum() {
  [[ $1 == n/a ]] && { printf 'null'; return 0; }
  printf '%s' "${1#+}"
}

main "$@"
