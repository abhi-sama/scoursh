#!/usr/bin/env bash
# bench/lib/score.sh - the B3 scorer.
#
# THE COUNTING UNIT IS THE CASE, never the finding.  A ground-truth case is
# FLAGGED by a tool when that tool reported at least one finding in the case's
# file (the scout report's §5.2, "one file per test case" row).  Finding count
# is deliberately not a metric here: a tool that reports the same defect three
# times is not three times better, and a table that rewards it is measuring
# verbosity.  This is also what makes bench/lib/normalise.sh's one-record-per-
# CWE expansion free of consequence.
#
# TWO MATCHING MODES, BOTH ALWAYS COMPUTED:
#
#   loose   the tool reported ANY finding in the case's file
#   strict  the tool reported a finding in the case's file whose CWE is in the
#           same equivalence class as the case's own CWE
#
# Both, every time, and the agreement between them REPORTED - because that
# agreement is what proves a ranking is not an artifact of the scoring method.
# The scout report's §3.1 checked it and found the two identical for both
# tools, which is the only reason its headline result can be stated at all.
#
# THE CONFUSION MATRIX IS REPORTED IN FULL AND THE HEADLINE IS YOUDEN J.
# Recall alone is meaningless: a rule that flags every file scores 100% on it.
# The scout report's `ldapi` row is exactly that failure passing as a win -
# 12/12 real cases AND 12/12 sanitized traps, perfect recall with zero
# discriminating power.  J = TPR - FPR is 0.000 for a coin flip, and the
# renderer prints that reminder beside every J it emits.
#
# SCOPE GATING IS EXPLICIT AND IS NOT INFERRED FROM THE RESULTS.  A tool is
# scored in a category only if its adapter's `<tool>_scope` CLAIMS it.  A
# category it does not claim renders as a labelled `no coverage` cell and is
# excluded from that tool's aggregate - never as a zero.  A zero says "this
# tool looked and failed"; a no-coverage cell says "this tool never
# competed".  Folding the second into the first is the failure scoursh's own
# honesty contract exists to prevent, and doing it in the benchmark that
# judges scoursh would be indefensible.
#
# shellcheck shell=bash

# SC2016: the diagnostics below quote key names and shell syntax literally.
# SC2034: BENCH_TP/FN/FP/TN and BENCH_FINDING_* are this file's published
# outputs - every consumer is bench/score.sh, which shellcheck does not follow
# from here.
# shellcheck disable=SC2016,SC2034
[[ -n ${BENCH_SCORE_SOURCED:-} ]] && return 0
BENCH_SCORE_SOURCED=1

# ---------------------------------------------------------------------------
# cwe_classes_load FILE
# ---------------------------------------------------------------------------
# Builds BENCH_CWE_CLASS: cwe -> the class's canonical representative (its
# numerically smallest member).  A CWE absent from the table maps to itself,
# which is the singleton rule bench/cwe-classes.conf documents.
cwe_classes_load() {
  local file=$1 line n rep members
  unset BENCH_CWE_CLASS
  declare -gA BENCH_CWE_CLASS=()
  [[ -r $file ]] || { printf 'bench: cannot read CWE classes: %s\n' "$file" >&2; return 2; }
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}
    # shellcheck disable=SC2086
    set -- $line
    (( $# > 0 )) || continue
    members=$(printf '%s\n' "$@" | LC_ALL=C sort -n)
    rep=$(printf '%s\n' "$members" | head -1)
    for n in "$@"; do
      [[ $n =~ ^[0-9]+$ ]] || {
        printf 'bench: %s: not a CWE number: %s\n' "$file" "$n" >&2
        return 2
      }
      if [[ -n ${BENCH_CWE_CLASS[$n]:-} && ${BENCH_CWE_CLASS[$n]} != "$rep" ]]; then
        # One CWE in two classes makes strict matching depend on file order,
        # which is a silent, load-order-dependent score.
        printf 'bench: %s: CWE %s appears in two classes (%s and %s)\n' \
          "$file" "$n" "${BENCH_CWE_CLASS[$n]}" "$rep" >&2
        return 2
      fi
      BENCH_CWE_CLASS[$n]=$rep
    done
  done <"$file"
  return 0
}

# cwe_class N -> the class representative for N (N itself if unclassed).
cwe_class() {
  local n=$1
  [[ -n $n ]] || { printf ''; return 0; }
  printf '%s' "${BENCH_CWE_CLASS[$n]:-$n}"
}

# ---------------------------------------------------------------------------
# findings_load FILE MIN_SEVERITY
# ---------------------------------------------------------------------------
# Reads a normalised.jsonl into:
#   BENCH_HIT[file]        set when the tool reported anything in that file
#   BENCH_HIT_CWE[file]    space-wrapped set of CWE CLASS representatives
#   BENCH_FINDING_COUNT    records kept after the severity filter
#   BENCH_FINDING_DROPPED  records dropped by it
#
# MIN_SEVERITY is `any` or one of the common scale's rungs; a record below it
# is dropped BEFORE any counting, which is how the ALL-findings and the
# high+critical columns are the same code path rather than two.
findings_load() {
  local file=$1 min=${2:-any}
  unset BENCH_HIT BENCH_HIT_CWE
  declare -gA BENCH_HIT=() BENCH_HIT_CWE=()
  BENCH_FINDING_COUNT=0
  BENCH_FINDING_DROPPED=0
  [[ -r $file ]] || { printf 'bench: cannot read findings: %s\n' "$file" >&2; return 2; }

  local line f c s cls
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    f=$(_json_field "$line" file)
    s=$(_json_field "$line" severity)
    c=$(_json_field "$line" cwe)
    if ! _severity_at_least "$s" "$min"; then
      BENCH_FINDING_DROPPED=$(( BENCH_FINDING_DROPPED + 1 ))
      continue
    fi
    BENCH_FINDING_COUNT=$(( BENCH_FINDING_COUNT + 1 ))
    BENCH_HIT[$f]=1
    if [[ -n $c ]]; then
      cls=$(cwe_class "$c")
      [[ ${BENCH_HIT_CWE[$f]:-} == *" $cls "* ]] || BENCH_HIT_CWE[$f]="${BENCH_HIT_CWE[$f]:- } $cls "
    fi
  done <"$file"
  return 0
}

# _json_field LINE KEY - one scalar out of a normalised record.
#
# This reads the harness's OWN output, whose shape is fixed by
# bench_records_to_jsonl one function away - not arbitrary third-party JSON,
# which is what bench/lib/json.sh exists for.  Every value is either a quoted
# string with the five RFC 8259 escapes or a bare number/null, so a targeted
# extraction is correct here and is two orders of magnitude faster than a
# flatten per line over a corpus-sized file.
_json_field() {
  local line=$1 key=$2 rest v
  # The key is matched only where a `{` or `,` precedes it.
  #
  # Stated precisely, because it is easy to over-claim: for a WELL-FORMED
  # record the anchor is redundant, and demonstrably so - a key-shaped run of
  # bytes inside a value arrives with its quotes escaped (`\"file\":`), which
  # is not the byte sequence `"file":` being searched for, so an unanchored
  # match cannot find it either.  `tests/suites/bench.sh` records that it tried
  # to build a well-formed line where the two readings differ and could not.
  # The anchor earns its place against a MALFORMED line instead - a
  # hand-edited normalised.jsonl, a truncated write - where it fails to find
  # the field rather than silently reading a lookalike, and a missing field is
  # visible where a wrong path is not.
  rest=${line#*[{,]\""$key"\":}
  [[ $rest == "$line" ]] && { printf ''; return 0; }
  if [[ ${rest:0:1} == '"' ]]; then
    rest=${rest:1}
    v=''
    while [[ -n $rest ]]; do
      # SC1003: `'\'` really is one literal backslash - inside single quotes
      # a backslash is not an escape - and that is the character being matched.
      # shellcheck disable=SC1003
      case ${rest:0:1} in
        '\') v+=${rest:0:2}; rest=${rest:2} ;;
        '"') break ;;
        *) v+=${rest:0:1}; rest=${rest:1} ;;
      esac
    done
    v=${v//\\n/$'\n'}; v=${v//\\t/$'\t'}; v=${v//\\r/$'\r'}
    v=${v//\\\"/\"}; v=${v//\\\\/\\}
    printf '%s' "$v"
  else
    v=${rest%%,*}; v=${v%%\}*}
    [[ $v == null ]] && v=''
    printf '%s' "$v"
  fi
}

# The common scale, low to high.  `any` accepts everything.
_severity_rank() {
  case $1 in
    info) printf '0' ;; low) printf '1' ;; medium) printf '2' ;;
    high) printf '3' ;; critical) printf '4' ;;
    *) printf '0' ;;
  esac
}
_severity_at_least() {
  [[ $2 == any ]] && return 0
  (( $(_severity_rank "$1") >= $(_severity_rank "$2") ))
}

# ---------------------------------------------------------------------------
# score_category CATEGORY MODE
# ---------------------------------------------------------------------------
# Requires truth_load and findings_load to have run.  Sets BENCH_TP/FN/FP/TN.
# MODE is `loose` or `strict`.
score_category() {
  local cat=$1 mode=$2
  BENCH_TP=0 BENCH_FN=0 BENCH_FP=0 BENCH_TN=0
  local c f flagged want
  for c in "${BENCH_TRUTH_CASES[@]}"; do
    [[ ${BENCH_TRUTH_CAT[$c]} == "$cat" ]] || continue
    f=${BENCH_TRUTH_FILE[$c]}
    flagged=0
    if [[ -n ${BENCH_HIT[$f]:-} ]]; then
      if [[ $mode == loose ]]; then
        flagged=1
      else
        want=$(cwe_class "${BENCH_TRUTH_CWE[$c]}")
        # A case with NO ground-truth CWE can never strict-match.  Treating an
        # empty class as a wildcard would make strict matching silently equal
        # loose matching for every such case, which is the direction that
        # inflates the strict number and destroys the agreement check.
        [[ -n $want && ${BENCH_HIT_CWE[$f]:-} == *" $want "* ]] && flagged=1
      fi
    fi
    if [[ ${BENCH_TRUTH_REAL[$c]} == true ]]; then
      if (( flagged )); then BENCH_TP=$(( BENCH_TP + 1 )); else BENCH_FN=$(( BENCH_FN + 1 )); fi
    else
      if (( flagged )); then BENCH_FP=$(( BENCH_FP + 1 )); else BENCH_TN=$(( BENCH_TN + 1 )); fi
    fi
  done
}

# ---------------------------------------------------------------------------
# rate NUM DEN -> a 3-decimal ratio, or `n/a` when the denominator is 0.
# ---------------------------------------------------------------------------
# `n/a` and not `0.000`.  A precision of 0.000 says the tool reported findings
# and every one was wrong; an undefined precision says it reported none at
# all.  Rendering the second as the first is a false accusation the reader
# cannot detect, and it is exactly the shape of error this whole harness is
# built to avoid.
rate() {
  local num=$1 den=$2
  (( den == 0 )) && { printf 'n/a'; return 0; }
  awk -v n="$num" -v d="$den" 'BEGIN { printf "%.3f", n / d }'
}

# youden TPR FPR -> J, or n/a if either input is undefined.
youden() {
  local tpr=$1 fpr=$2
  [[ $tpr == n/a || $fpr == n/a ]] && { printf 'n/a'; return 0; }
  awk -v a="$tpr" -v b="$fpr" 'BEGIN { printf "%+.3f", a - b }'
}
