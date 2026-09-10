#!/usr/bin/env bash
# bench/lib/truth.sh - the benchmark's own ground-truth record format, and
# the adapters that produce it from a corpus's native labelling.
#
# THE FORMAT.  One case per line, five 0x1f-separated fields:
#
#     <case><US><file><US><category><US><cwe><US><real>
#
#   case      the corpus's own identifier for the case
#   file      the case's path, RELATIVE TO THE SCAN ROOT the tools are pointed
#             at - the same string a normalised finding's `file` carries, or
#             nothing will ever match
#   category  the scoring category (`sqli`, `terraform-aws`, ...)
#   cwe       the case's true CWE as a bare number, or empty
#   real      `true` if the case really is vulnerable, `false` if it is a
#             deliberate sanitized trap
#
# THE `real: false` ROWS ARE NOT PADDING AND MUST NOT BE DROPPED.  They are
# the only thing that makes a false-positive rate measurable, and therefore
# the only thing that makes Youden J measurable.  A benchmark run over the
# `real: true` rows alone reports recall, and recall alone is a metric a rule
# that flags every file scores 100% on - which is exactly the `ldapi` result
# the scout report's §3.1 caught (12/12 real AND 12/12 traps, reading as a
# perfect score while having zero discriminating power).
#
# 0x1f rather than a tab, for the reason bench/lib/json.sh's header gives: a
# `cwe` field is legitimately empty and a tab-separated reader would silently
# shift every later column left on exactly those rows.
#
# shellcheck shell=bash

# SC2016: the diagnostics below quote key names and shell syntax literally.
# SC2034: BENCH_TRUTH_* are this file's published outputs - bench/score.sh and
# bench/lib/score.sh read them, and shellcheck does not follow that direction.
# shellcheck disable=SC2016,SC2034
[[ -n ${BENCH_TRUTH_SOURCED:-} ]] && return 0
BENCH_TRUTH_SOURCED=1

BENCH_TRUTH_US=$'\x1f'

# ---------------------------------------------------------------------------
# truth_load FILE
# ---------------------------------------------------------------------------
# Populates:
#   BENCH_TRUTH_CASES   array of case ids, in file order
#   BENCH_TRUTH_FILE    assoc case -> file
#   BENCH_TRUTH_CAT     assoc case -> category
#   BENCH_TRUTH_CWE     assoc case -> cwe
#   BENCH_TRUTH_REAL    assoc case -> true|false
#   BENCH_TRUTH_CATS    array of distinct categories, LC_ALL=C sorted
truth_load() {
  local file=$1 line c f cat cwe real lineno=0
  [[ -r $file ]] || { printf 'bench: cannot read ground truth: %s\n' "$file" >&2; return 2; }

  BENCH_TRUTH_CASES=()
  unset BENCH_TRUTH_FILE BENCH_TRUTH_CAT BENCH_TRUTH_CWE BENCH_TRUTH_REAL
  declare -gA BENCH_TRUTH_FILE=() BENCH_TRUTH_CAT=() BENCH_TRUTH_CWE=() BENCH_TRUTH_REAL=()

  while IFS= read -r line || [[ -n $line ]]; do
    lineno=$(( lineno + 1 ))
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    IFS=$BENCH_TRUTH_US read -r c f cat cwe real <<<"$line"
    if [[ -z $c || -z $f || -z $cat ]]; then
      printf 'bench: %s:%d: malformed ground-truth row\n' "$file" "$lineno" >&2
      return 2
    fi
    case $real in
      true | false) ;;
      *)
        # A row whose `real` column is anything else is REFUSED rather than
        # defaulted.  Defaulting it either way silently converts an unlabelled
        # case into a scored one, and both directions are wrong in a way the
        # totals hide: `true` inflates recall's denominator, `false` invents a
        # trap the corpus never authored.
        printf 'bench: %s:%d: `real` must be true or false, got: %s\n' "$file" "$lineno" "$real" >&2
        return 2
        ;;
    esac
    if [[ -n ${BENCH_TRUTH_FILE[$c]:-} ]]; then
      printf 'bench: %s:%d: duplicate case id: %s\n' "$file" "$lineno" "$c" >&2
      return 2
    fi
    BENCH_TRUTH_CASES+=("$c")
    BENCH_TRUTH_FILE[$c]=$f
    BENCH_TRUTH_CAT[$c]=$cat
    BENCH_TRUTH_CWE[$c]=$cwe
    BENCH_TRUTH_REAL[$c]=$real
  done <"$file"

  mapfile -t BENCH_TRUTH_CATS < <(
    local k
    for k in "${BENCH_TRUTH_CASES[@]}"; do printf '%s\n' "${BENCH_TRUTH_CAT[$k]}"; done |
      LC_ALL=C sort -u
  )
  return 0
}

# ---------------------------------------------------------------------------
# truth_from_owasp CSV PREFIX [CATEGORY ...]
# ---------------------------------------------------------------------------
# The OWASP Benchmark adapter.  `expectedresults-1.2.csv` is
#
#     # test name, category, real vulnerability, cwe, Benchmark version: ...
#     BenchmarkTest00001,pathtraver,true,22
#
# PREFIX is prepended to `<case>.java` to make the scan-root-relative path.
# With no CATEGORY arguments every category is emitted; with some, only those.
#
# The header line is skipped by its leading `#`, not by a line count: the file
# ships one comment line today and a second one would silently become a case
# named `# test name` under a count-based skip.
truth_from_owasp() {
  local csv=$1 prefix=$2
  shift 2
  local want=" $* "
  [[ -r $csv ]] || { printf 'bench: cannot read OWASP results csv: %s\n' "$csv" >&2; return 2; }

  local line c cat real cwe
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}                       # the file is CRLF in some tags
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    IFS=, read -r c cat real cwe _ <<<"$line"
    [[ -n $c && -n $cat ]] || continue
    if (( $# > 0 )) && [[ $want != *" $cat "* ]]; then continue; fi
    printf '%s%s%s%s%s%s%s%s%s\n' \
      "$c" "$BENCH_TRUTH_US" "$prefix$c.java" "$BENCH_TRUTH_US" \
      "$cat" "$BENCH_TRUTH_US" "$cwe" "$BENCH_TRUTH_US" "$real"
  done <"$csv"
}
