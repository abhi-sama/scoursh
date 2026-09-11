#!/usr/bin/env bash
# bench/tools/scoursh.sh - the scoursh adapter.
#
# THE ADAPTER CONTRACT, which every file in this directory implements:
#
#   <tool>_available            0 if the tool can be run here
#   <tool>_version              its version string, on stdout
#   <tool>_run RAW_DIR ROOT CAT run it, writing raw output under RAW_DIR
#   <tool>_normalise RAW_DIR ROOT  raw output -> internal records on stdout
#   <tool>_scope                the scoring categories this tool CLAIMS
#
# `<tool>_scope` is not decoration and is not derived from the results: it is
# the explicit "did not compete" cell.  A category
# a tool does not claim gets a labelled no-coverage cell in the scorecard,
# never a silent zero folded into an average - and a zero and a no-coverage
# cell are different claims about the world, one of which is a failure and one
# of which is a scope boundary.
#
# THE RUN IS DELIBERATELY THE DEFAULT GATE AND DELIBERATELY NOT --use-engines.
# `--profile-scan full --min-confidence low` are scan.sh's own defaults, so
# this is scoursh as an operator gets it.  `--use-engines` is excluded because
# scoursh's semgrep/gitleaks/trivy adapters make it WRAP the tools it is being
# compared against: a scoursh-with-engines column against Semgrep is Semgrep
# versus Semgrep plus scoursh's startup cost, which is an integration
# measurement wearing a detection table's clothes.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SCOURSH_SOURCED:-} ]] && return 0
BENCH_TOOL_SCOURSH_SOURCED=1

# The scanner under test is this repository unless the caller points
# elsewhere - which is what lets the harness score a released scoursh against
# the working tree's.
BENCH_SCOURSH_ROOT=${BENCH_SCOURSH_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}

scoursh_available() { [[ -x $BENCH_SCOURSH_ROOT/scan.sh || -r $BENCH_SCOURSH_ROOT/scan.sh ]]; }

scoursh_version() {
  local v=''
  [[ -r $BENCH_SCOURSH_ROOT/VERSION ]] && IFS= read -r v <"$BENCH_SCOURSH_ROOT/VERSION"
  local sha=''
  sha=$(git -C "$BENCH_SCOURSH_ROOT" rev-parse --short=12 HEAD 2>/dev/null) || sha=''
  # The version AND the commit, because `0.1.0-dev` is not a version anyone
  # can re-run against - "no version-less numbers"
  # is not satisfied by a version string that names 140 different trees.
  printf '%s' "${v:-unknown}${sha:++$sha}"
}

# THIS ADAPTER RUNS `scan.sh sast`, SO IT CLAIMS SAST CATEGORIES AND NOTHING
# ELSE.  It named `terraform-aws` when it was the only scoursh adapter here,
# which was a claim `scan.sh sast` could not honour: the terraform rules live
# in `modules/iac/` and a `sast` run never loads them, so the claim would have
# scored scoursh at zero on an IaC corpus while looking like a real attempt.
# `bench/tools/scoursh-iac.sh` runs `scan.sh iac` and carries that claim now.
#
# The SAST category names are OWASP Benchmark's, because that is the corpus
# supplying the labels.
scoursh_scope() {
  printf '%s\n' sqli cmdi ldapi pathtraver crypto hash weakrand xss
}

scoursh_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  # `|| rc=$?` rather than a bare call: scan.sh's exit code is a FINDING
  # verdict as well as an error signal (docs/FOUNDATION.md tension 14 - 1
  # means findings at or above the gate), so treating non-zero as failure here
  # would discard every run that found something, which is every interesting
  # run.  Only 2-5 are real errors, and the caller decides.
  (
    cd "$BENCH_SCOURSH_ROOT" &&
      bash scan.sh sast --path "$root" --out "$raw/run" --format json
  ) >"$raw/stdout.txt" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *)
      printf 'bench: scoursh exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
      return "$rc"
      ;;
  esac
}

scoursh_normalise() {
  local raw=$1 root=$2
  local jsonl=$raw/run/findings.jsonl
  [[ -r $jsonl ]] || { printf 'bench: no scoursh findings.jsonl under %s\n' "$raw" >&2; return 2; }

  # scoursh reports `location.path` relative to the SCAN ROOT, which is the
  # git toplevel of the resolved --path when there is one (AGENTS.md, "the
  # scan root is a defined term").  A corpus checked out inside any git
  # repository therefore comes back with an extra prefix, and that prefix is
  # exactly what `run.json`'s `path_root` records.  Stripping it is what makes
  # the reported path relative to the directory the harness actually pointed
  # at - and getting it wrong yields zero matches, which reads as a clean
  # "this tool found nothing" rather than as an error.
  local path_root=''
  if [[ -r $raw/run/run.json ]]; then
    path_root=$(
      bench_json_flatten <"$raw/run/run.json" |
        while IFS=$BENCH_NORM_US read -r p t v; do
          [[ $p == path_root && $t == s ]] && { printf '%s' "$v"; break; }
        done
    )
  fi
  [[ $path_root == '.' ]] && path_root=''

  # One awk pass over the whole file rather than one per line: findings.jsonl
  # is a stream of top-level objects, so it is wrapped into an array first,
  # which also gives every finding an index to key its leaves on.
  local flat
  flat=$(
    {
      printf '['
      awk 'NF { if (n++) printf ","; printf "%s", $0 }' "$jsonl"
      printf ']'
    } | bench_json_flatten
  )
  bench_flat_read <<<"$flat"

  local i=0 p file line cwe sev rule
  while :; do
    p="$i/check_id"
    [[ -n ${BENCH_FLAT_TYPE[$p]:-} ]] || break
    rule=$(bench_flat_str "$i/check_id")
    file=$(bench_flat_str "$i/location/path")
    line=$(bench_flat_num "$i/location/line")
    cwe=$(bench_cwe_number "$(bench_flat_str "$i/cwe")")
    sev=$(_scoursh_severity "$(bench_flat_str "$i/severity")")
    if [[ -n $path_root && $file == "$path_root"/* ]]; then file=${file#"$path_root"/}; fi
    file=$(bench_relpath "$file" "$root")
    bench_record "$file" "$line" "$cwe" "$sev" "$rule"
    i=$(( i + 1 ))
  done
}

# scoursh's own severity ladder already IS the common scale, so this is an
# identity with a guard rather than a mapping.  The guard is the point: a
# severity scoursh grows later must not silently arrive as itself and quietly
# widen the scale every other adapter maps onto.
_scoursh_severity() {
  case $1 in
    critical | high | medium | low | info) printf '%s' "$1" ;;
    *) printf 'info' ;;
  esac
}
