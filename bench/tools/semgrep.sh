#!/usr/bin/env bash
# bench/tools/semgrep.sh - the Semgrep CE adapter.
#
# Implements the adapter contract documented in bench/tools/scoursh.sh.
#
# THE RULESET IS DECLARED AND IS NOT THE DEFAULT.  `p/security-audit` plus
# `p/owasp-top-ten` is Semgrep's maximum free security ruleset, which is the
# (b) half of a two-column comparison - every tool is run at its documented
# default AND at its maximum free ruleset, and both columns are published.
# Semgrep's numbers move a lot between `p/default` and these two, and hiding
# which was used is how a benchmark gets accused of rigging.  Which one THIS
# run used is recorded in the run manifest, never left to be inferred.
#
# BENCH_SEMGREP_CONFIG overrides it, so the default column is the same adapter
# with a different declared value rather than a second, subtly different
# adapter.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SEMGREP_SOURCED:-} ]] && return 0
BENCH_TOOL_SEMGREP_SOURCED=1

BENCH_SEMGREP_CONFIG=${BENCH_SEMGREP_CONFIG:-p/security-audit p/owasp-top-ten}

semgrep_available() { command -v semgrep >/dev/null 2>&1; }

semgrep_version() {
  local v
  v=$(semgrep --version 2>/dev/null | head -1) || v=''
  printf '%s' "${v:-unknown}"
}

# Semgrep CE ships rules for every SAST category in this corpus.  It claims no
# `terraform-aws` cell here NOT because Semgrep cannot read Terraform - it can
# - but because this harness runs it with a ruleset selected for application
# code; a category a tool was not actually configured to compete in is a
# no-coverage cell, and pretending otherwise would score the harness's own
# configuration choice as the tool's detection gap.
semgrep_scope() {
  printf '%s\n' sqli cmdi ldapi pathtraver crypto hash weakrand xss
}

semgrep_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local cfg=() c
  for c in $BENCH_SEMGREP_CONFIG; do cfg+=(--config "$c"); done
  local rc=0
  # `--no-git-ignore` because the corpus may sit inside a repository whose
  # .gitignore excludes it - bench/corpora/ is gitignored in THIS one, so
  # without this flag Semgrep scans nothing and reports a clean result.
  # `--metrics=off` because a benchmark harness must not phone home about the
  # corpus it is measuring.
  semgrep "${cfg[@]}" --json --no-git-ignore --metrics=off --quiet "$root" \
    >"$raw/semgrep.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *)
      printf 'bench: semgrep exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
      return "$rc"
      ;;
  esac
}

semgrep_normalise() {
  local raw=$1 root=$2
  local js=$raw/semgrep.json
  [[ -r $js ]] || { printf 'bench: no semgrep.json under %s\n' "$raw" >&2; return 2; }

  bench_flat_read < <(bench_json_flatten <"$js")

  local i=0 file line sev rule cwe k n
  while :; do
    [[ -n ${BENCH_FLAT_TYPE[results/$i/check_id]:-} ]] || break
    rule=$(bench_flat_str "results/$i/check_id")
    file=$(bench_relpath "$(bench_flat_str "results/$i/path")" "$root")
    line=$(bench_flat_num "results/$i/start/line")
    sev=$(_semgrep_severity "$(bench_flat_str "results/$i/extra/severity")")

    # `metadata.cwe` is an ARRAY, and a finding routinely declares more than
    # one.  One record per declared CWE - see bench/lib/normalise.sh, "one
    # record per (finding, CWE)", including why that cannot double-count.
    n=0
    while :; do
      k="results/$i/extra/metadata/cwe/$n"
      [[ ${BENCH_FLAT_TYPE[$k]:-} == s ]] || break
      cwe=$(bench_cwe_number "$(bench_flat_str "$k")")
      bench_record "$file" "$line" "$cwe" "$sev" "$rule"
      n=$(( n + 1 ))
    done
    if (( n == 0 )); then
      # Some rules carry `metadata.cwe` as a bare STRING rather than an array,
      # and a reader that only handles the array form drops those findings
      # entirely - silently, and in the direction that reads as a lower
      # false-positive rate for the tool being measured.
      if [[ ${BENCH_FLAT_TYPE[results/$i/extra/metadata/cwe]:-} == s ]]; then
        cwe=$(bench_cwe_number "$(bench_flat_str "results/$i/extra/metadata/cwe")")
        bench_record "$file" "$line" "$cwe" "$sev" "$rule"
      else
        # No CWE at all: still a finding, and still counted.  Emitting nothing
        # here would make a tool look cleaner than it is under LOOSE matching,
        # which is the matching a CWE-less finding is precisely relevant to.
        bench_record "$file" "$line" '' "$sev" "$rule"
      fi
    fi
    i=$(( i + 1 ))
  done
}

# Semgrep's ladder is ERROR/WARNING/INFO (its own SARIF converter maps ERROR
# to `error`).  There is no Semgrep severity above ERROR, so nothing maps to
# `critical` - which is a real asymmetry between the tools and is why the
# scorecard publishes the ALL-findings column beside the high+critical one
# rather than only the latter.
_semgrep_severity() {
  case $1 in
    ERROR | error) printf 'high' ;;
    WARNING | warning) printf 'medium' ;;
    INFO | info) printf 'info' ;;
    '') printf 'info' ;;
    *) printf 'info' ;;
  esac
}
