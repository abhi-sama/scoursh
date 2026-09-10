#!/usr/bin/env bash
# bench/lib/normalise.sh - the normalised finding record, and the shared
# helpers every per-tool adapter under bench/tools/ builds on.
#
# THE NORMALISED RECORD.  One JSON object per line:
#
#   {"tool":…, "version":…, "corpus":…, "file":…, "line":…,
#    "cwe":…, "severity":…, "rule_id":…}
#
# Written as JSONL rather than one JSON document because a real corpus run
# produces tens of thousands of these and a reader must be able to stream
# them, and because a truncated JSONL file is still readable up to the
# truncation - a truncated JSON array is not readable at all.
#
# ADAPTERS DO NOT BUILD JSON.  A `<tool>_normalise` emits INTERNAL records -
# five 0x1f-separated fields, `file<US>line<US>cwe<US>severity<US>rule_id` -
# and `bench_records_to_jsonl` turns those into the shape above.  Two reasons,
# both practical:
#
#   * The JSON assembly, and therefore the escaping, has ONE implementation to
#     get right rather than one per tool.  A per-adapter `printf '{"file":"%s"'`
#     is how a path containing a quote silently produces an unparseable line
#     that every downstream reader skips - a finding that vanishes without an
#     error, which is the exact failure class this harness exists to measure.
#   * The mapping a per-tool adapter actually owns - which of the tool's
#     fields is the CWE, how its severity ladder maps onto the common one - is
#     then testable directly, without the test having to parse JSON to see it.
#
# ONE RECORD PER (FINDING, CWE), AND WHY THAT DOES NOT DOUBLE-COUNT.  A tool
# may declare several CWEs for one finding (Semgrep's `metadata.cwe` is an
# array).  An adapter emits one record per declared CWE, because the scoring
# question is "did this tool flag this case with a CWE in the class", which is
# a question about the SET.  It cannot inflate any published number: the
# confusion matrix counts CASES, never findings - a case is flagged or it is
# not, however many records point at it (bench/lib/score.sh, "the counting
# unit is the case").
#
# THE COMMON SEVERITY SCALE is `critical high medium low info`, and every
# adapter maps onto exactly it.  The scale exists because the scout report's
# rule R5 requires publishing both an ALL-findings and a HIGH+CRITICAL-only
# column: a tool that reports informational findings must not be punished for
# it in a recall table, and that comparison is impossible while each tool is
# scored on its own private ladder.
#
# shellcheck shell=bash

[[ -n ${BENCH_NORMALISE_SOURCED:-} ]] && return 0
BENCH_NORMALISE_SOURCED=1

BENCH_LIB_DIR=${BENCH_LIB_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)}
# shellcheck source=bench/lib/json.sh
source "$BENCH_LIB_DIR/json.sh"

BENCH_NORM_US=$'\x1f'

# ---------------------------------------------------------------------------
# bench_cwe_number STRING -> the bare CWE number, or empty.
# ---------------------------------------------------------------------------
# Tools spell a CWE at least four ways and every one of them appears in the
# outputs this harness reads:
#
#     89                                   scoursh's rule files, bare
#     CWE-89                               scoursh's finding JSON
#     CWE-89: Improper Neutralization …    Semgrep's metadata.cwe entries
#     cwe-89                               lowercased by some emitters
#
# Reducing them all to `89` is what lets one equivalence-class table serve
# every tool.  A string carrying no CWE at all yields empty, which the strict
# matcher treats as "no class claimed" - never as class 0, which would make
# every CWE-less finding strict-match every CWE-less case.
bench_cwe_number() {
  local s=$1
  s=${s#[Cc][Ww][Ee]}
  s=${s#[-_ :]}
  s=${s%%[!0-9]*}
  [[ $s =~ ^[0-9]+$ ]] || { printf ''; return 0; }
  printf '%s' "$((10#$s))"
}

# ---------------------------------------------------------------------------
# bench_record FILE LINE CWE SEVERITY RULE_ID -> one internal record line.
# ---------------------------------------------------------------------------
# Any 0x1f inside a field is stripped, so tool-authored text cannot forge a
# column - the same discipline modules/dast/passive/markup_engine.sh applies
# to target-derived text.
bench_record() {
  local f=${1//$BENCH_NORM_US/} l=${2//$BENCH_NORM_US/} c=${3//$BENCH_NORM_US/}
  local s=${4//$BENCH_NORM_US/} r=${5//$BENCH_NORM_US/}
  printf '%s%s%s%s%s%s%s%s%s\n' \
    "$f" "$BENCH_NORM_US" "$l" "$BENCH_NORM_US" "$c" "$BENCH_NORM_US" \
    "$s" "$BENCH_NORM_US" "$r"
}

# ---------------------------------------------------------------------------
# bench_records_to_jsonl TOOL VERSION CORPUS  - stdin: internal records.
# ---------------------------------------------------------------------------
bench_records_to_jsonl() {
  local tool=$1 version=$2 corpus=$3
  local line f l c s r
  local jt jv jc
  jt=$(bench_json_string "$tool"); jv=$(bench_json_string "$version")
  jc=$(bench_json_string "$corpus")
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    IFS=$BENCH_NORM_US read -r f l c s r <<<"$line"
    # `line` is a NUMBER in the output and `null` when the tool gave none.
    # Quoting it instead would make `"line":""` and `"line":"0"` two different
    # spellings of "unknown", and a consumer comparing line numbers would then
    # be comparing strings - which sorts 10 before 9.
    local jline='null'
    [[ $l =~ ^[0-9]+$ ]] && jline=$l
    printf '{"tool":"%s","version":"%s","corpus":"%s","file":"%s","line":%s,"cwe":%s,"severity":"%s","rule_id":"%s"}\n' \
      "$jt" "$jv" "$jc" \
      "$(bench_json_string "$f")" \
      "$jline" \
      "$(if [[ -n $c ]]; then printf '"%s"' "$(bench_json_string "$c")"; else printf 'null'; fi)" \
      "$(bench_json_string "$s")" \
      "$(bench_json_string "$r")"
  done
}

# ---------------------------------------------------------------------------
# bench_relpath PATH SCAN_ROOT - PATH made relative to SCAN_ROOT.
# ---------------------------------------------------------------------------
# A normalised `file` is ALWAYS relative to the scan root the harness pointed
# the tool at, and matching it against the ground truth is the whole reason
# every number exists.  Getting this wrong does not produce an error - it
# produces zero matches, which reads as "this tool found nothing", which is a
# perfectly plausible benchmark result.  That is why each adapter converts
# explicitly rather than trusting the tool's own spelling: Semgrep echoes back
# whatever path it was given (absolute if invoked absolutely), and scoursh
# reports paths relative to the GIT TOPLEVEL of the scan root rather than to
# the scan root itself (AGENTS.md, "the scan root is a defined term"), so a
# corpus sitting inside any git repository comes back with an extra prefix.
bench_relpath() {
  local p=$1 root=$2
  root=${root%/}
  [[ -n $root && $p == "$root"/* ]] && p=${p#"$root"/}
  p=${p#./}
  printf '%s' "$p"
}

# ---------------------------------------------------------------------------
# bench_flat_get PREFIX KEY - read one leaf out of a flattened-JSON block.
# ---------------------------------------------------------------------------
# Adapters read a flattened document (bench/lib/json.sh) into the assoc array
# `BENCH_FLAT`, keyed by path, with the TYPE kept alongside in
# `BENCH_FLAT_TYPE`.  These two accessors exist so no adapter has to remember
# that a string `"null"` and a JSON null share a path.
bench_flat_read() {
  unset BENCH_FLAT BENCH_FLAT_TYPE
  declare -gA BENCH_FLAT=() BENCH_FLAT_TYPE=()
  local line path type value
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    IFS=$BENCH_NORM_US read -r path type value <<<"$line"
    # An EMPTY path is bench_json_flatten's own marker for "the whole
    # document was an empty container" (`[]` or `{}` at the top level, its
    # header's own §"o/a rows" paragraph) - never a real leaf a caller could
    # look up by name, since every actual field lives at a NON-empty path
    # (`findings/0/...`). Bash cannot use an empty string as an associative-
    # array subscript on either side (`arr[$x]=v` and `arr[$x]` both refuse
    # it, quoted or not, when `$x` expands to zero bytes - measured, not
    # assumed: `declare -gA a=(); x=''; a[$x]=v` is `bad array subscript`
    # even as `a["$x"]=v`), so recording it here would abort the whole read
    # under `set -e` on precisely the "this tool reported nothing" case a
    # benchmark corpus's own sanitized-trap/patched half is built to
    # exercise. Skipping it costs nothing: no caller reads the empty path,
    # and the absence of any OTHER entry already means what it always meant.
    [[ -n $path ]] || continue
    BENCH_FLAT[$path]=$value
    BENCH_FLAT_TYPE[$path]=$type
  done
}

# bench_flat_str PATH -> the value, only if it is a JSON STRING.
bench_flat_str() {
  [[ ${BENCH_FLAT_TYPE[$1]:-} == s ]] || { printf ''; return 0; }
  printf '%s' "${BENCH_FLAT[$1]}"
}

# bench_flat_num PATH -> the value, only if it is a JSON NUMBER.
bench_flat_num() {
  [[ ${BENCH_FLAT_TYPE[$1]:-} == n ]] || { printf ''; return 0; }
  printf '%s' "${BENCH_FLAT[$1]}"
}
