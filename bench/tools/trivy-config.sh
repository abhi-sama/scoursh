#!/usr/bin/env bash
# bench/tools/trivy-config.sh - Trivy's misconfiguration scanner, IaC.
#
# NAMED `trivy-config`, NOT `trivy`.  `trivy` is four scanners behind one
# binary - `image`, `fs`, `config`, `repo` - answering four different
# questions, and a benchmark row headed `trivy` would not say which one ran.
# The name is the gate, and the leg that eventually scores `trivy image` will
# add its own adapter beside this one rather than a flag inside it.
#
# GATE: `trivy config --format json --skip-check-update ROOT`, its documented
# default check set (the Rego policies compiled into the binary), no
# `--severity` filter, no `--config-check`, nothing tuned against the corpus.
# `--skip-check-update` is the harness's own rule, not Trivy's default: a
# measurement run must not fetch a check bundle mid-benchmark, because the
# result would then depend on the minute it was run.  Its absence is also why
# no `--offline-scan` appears here - that flag belongs to the vulnerability
# scanners and `trivy config` rejects it outright, measured on 0.74.0.
#
# CONFLICT DISCLOSURE.  scoursh ships `modules/iac/adapters/trivy/`, so
# `scoursh --use-engines` would WRAP this tool.  The scoursh column in this leg
# is `bench/tools/scoursh-iac.sh`, which is explicitly not `--use-engines`, so
# the two columns are independent.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_TRIVY_CONFIG_SOURCED:-} ]] && return 0
BENCH_TOOL_TRIVY_CONFIG_SOURCED=1

trivy_config_available() { command -v trivy >/dev/null 2>&1; }

trivy_config_version() { trivy --version 2>/dev/null | head -1 | sed 's/^Version: //' | tr -d '\r'; }

trivy_config_scope() { printf '%s\n' terraform-aws kubernetes; }

trivy_config_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  trivy config --format json --skip-check-update "$root" \
    >"$raw/trivy.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  (( rc == 0 )) || {
    printf 'bench: trivy config exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
    return 2
  }
}

# Trivy nests findings TWO levels: a top-level `Results` array, one entry per
# scanned file, each with its own `Misconfigurations` array.  The file name is
# on the OUTER entry (`Target`) and the line on the inner one
# (`CauseMetadata.StartLine`), so a normaliser reading only the inner objects
# has findings with no file.
trivy_config_normalise() {
  local raw=$1 root=$2
  local f=$raw/trivy.json
  [[ -r $f ]] || { printf 'bench: no trivy.json under %s\n' "$raw" >&2; return 2; }

  local flat
  flat=$(bench_json_flatten <"$f") || return 2
  bench_flat_read <<<"$flat"

  local i=0 j p target file line sev rule status
  while :; do
    [[ -n ${BENCH_FLAT_TYPE[Results/$i/Target]:-} ]] || break
    target=$(bench_flat_str "Results/$i/Target")
    j=0
    while :; do
      p="Results/$i/Misconfigurations/$j/ID"
      [[ -n ${BENCH_FLAT_TYPE[$p]:-} ]] || break
      status=$(bench_flat_str "Results/$i/Misconfigurations/$j/Status")
      # Only FAIL is a finding.  `--include-non-failures` is not passed, but
      # guarding on Status here means a future caller that passes it does not
      # silently turn every PASSED check into a reported one.
      if [[ $status == FAIL || -z $status ]]; then
        rule=$(bench_flat_str "$p")
        line=$(bench_flat_num "Results/$i/Misconfigurations/$j/CauseMetadata/StartLine")
        [[ $line == 0 ]] && line=''
        sev=$(_trivy_config_severity "$(bench_flat_str "Results/$i/Misconfigurations/$j/Severity")")
        file=$(bench_relpath "$target" "$root")
        # No CWE: Trivy's misconfiguration checks carry an AVD id and a
        # provider/service pair, not a CWE.  Empty matches loosely and never
        # strictly, which is the honest treatment - see bench/tools/checkov.sh.
        bench_record "$file" "$line" '' "$sev" "$rule"
      fi
      j=$(( j + 1 ))
    done
    i=$(( i + 1 ))
  done
}

# Trivy's ladder is the common scale in upper case, and it DOES ship CRITICAL -
# unlike this harness's Semgrep adapter, which caps at high because Semgrep's
# own ladder stops at ERROR.  Capping Trivy at high would invent a difference
# the tool does not have.
_trivy_config_severity() {
  case $1 in
    CRITICAL) printf 'critical' ;;
    HIGH) printf 'high' ;;
    MEDIUM) printf 'medium' ;;
    LOW) printf 'low' ;;
    UNKNOWN | '') printf 'info' ;;
    *) printf 'info' ;;
  esac
}

# The hyphenated names bench/run-tool.sh dispatches on - see the note at the
# foot of bench/tools/scoursh-iac.sh.
trivy-config_available() { trivy_config_available; }
trivy-config_version() { trivy_config_version; }
trivy-config_scope() { trivy_config_scope; }
trivy-config_run() { trivy_config_run "$@"; }
trivy-config_normalise() { trivy_config_normalise "$@"; }
