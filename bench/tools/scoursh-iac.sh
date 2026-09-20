#!/usr/bin/env bash
# bench/tools/scoursh-iac.sh - scoursh's IaC module.
#
# A SEPARATE ADAPTER FROM bench/tools/scoursh.sh, not a flag on it.  That file
# runs `scan.sh sast`; this one runs `scan.sh iac`.  They are different
# subcommands over different rule sets answering different questions, and the
# adapter contract's `<tool>_scope` is a per-adapter claim - one file claiming
# both would have to claim every SAST category AND every IaC category on every
# run, which is the silent-zero failure the scope gate exists to prevent.
#
# THE RUN IS THE DEFAULT GATE AND DELIBERATELY NOT --use-engines, for the
# reason bench/tools/scoursh.sh's header gives at length: scoursh ships a trivy
# adapter, so a scoursh --use-engines column against Trivy is Trivy versus
# Trivy plus scoursh's startup cost.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SCOURSH_IAC_SOURCED:-} ]] && return 0
BENCH_TOOL_SCOURSH_IAC_SOURCED=1

BENCH_SCOURSH_ROOT=${BENCH_SCOURSH_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}

scoursh_iac_available() { [[ -r $BENCH_SCOURSH_ROOT/scan.sh ]]; }

scoursh_iac_version() {
  local v='' sha=''
  [[ -r $BENCH_SCOURSH_ROOT/VERSION ]] && IFS= read -r v <"$BENCH_SCOURSH_ROOT/VERSION"
  sha=$(git -C "$BENCH_SCOURSH_ROOT" rev-parse --short=12 HEAD 2>/dev/null) || sha=''
  printf '%s' "${v:-unknown}${sha:++$sha}"
}

# The two IaC categories this leg scores.  `terraform-aws` rather than `iac`
# for bench/corpus.lock's own reason - for IaC, "same category" has to mean
# "same cloud" - and `kubernetes` separately, because a pack for one says
# nothing about the other.
scoursh_iac_scope() { printf '%s\n' terraform-aws kubernetes; }

scoursh_iac_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  # `|| rc=$?` rather than a bare call: scan.sh's exit code is a FINDING
  # verdict as well as an error signal (docs/FOUNDATION.md tension 14), so
  # treating non-zero as failure discards every run that found something.
  (
    cd "$BENCH_SCOURSH_ROOT" &&
      bash scan.sh iac --path "$root" --out "$raw/run" --format json
  ) >"$raw/stdout.txt" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *) printf 'bench: scoursh iac exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2; return "$rc" ;;
  esac
}

scoursh_iac_normalise() { _scoursh_normalise_run "$1" "$2"; }

# Shared with bench/tools/scoursh-secrets.sh.  Both read the same
# findings.jsonl written by the same emitter, so a second copy of this would be
# a second chance to get run.json's path_root stripping wrong - and getting it
# wrong yields zero matches, which reads as "this tool found nothing" rather
# than as an error.
_scoursh_normalise_run() {
  local raw=$1 root=$2
  local jsonl=$raw/run/findings.jsonl
  [[ -r $jsonl ]] || { printf 'bench: no scoursh findings.jsonl under %s\n' "$raw" >&2; return 2; }

  # scoursh reports location.path relative to the SCAN ROOT, which is the git
  # toplevel of the resolved --path when there is one.  A corpus checked out as
  # its own git repository therefore comes back with an extra prefix, and that
  # prefix is what run.json's path_root records.
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
    sev=$(_scoursh_iac_severity "$(bench_flat_str "$i/severity")")
    if [[ -n $path_root && $file == "$path_root"/* ]]; then file=${file#"$path_root"/}; fi
    file=$(bench_relpath "$file" "$root")
    bench_record "$file" "$line" "$cwe" "$sev" "$rule"
    i=$(( i + 1 ))
  done
}

# scoursh's ladder already IS the common scale, so this is an identity with a
# guard.  The guard is the point: a severity scoursh grows later must not
# silently arrive as itself and widen the scale every other adapter maps onto.
_scoursh_iac_severity() {
  case $1 in
    critical | high | medium | low | info) printf '%s' "$1" ;;
    *) printf 'info' ;;
  esac
}

# THE ADAPTER CONTRACT IS KEYED ON THE TOOL ID, HYPHENS AND ALL.
# bench/run-tool.sh calls `"${tool}_available"`, and the tool id is this file's
# basename - so the functions bash actually dispatches to are the hyphenated
# ones.  The underscore-named definitions above are what a peer adapter can
# source and call by name (bench/tools/scoursh-secrets.sh does exactly that),
# and these five lines are the bridge.  bench/tools/semgrep-default.sh
# established the same shape.
scoursh-iac_available() { scoursh_iac_available; }
scoursh-iac_version() { scoursh_iac_version; }
scoursh-iac_scope() { scoursh_iac_scope; }
scoursh-iac_run() { scoursh_iac_run "$@"; }
scoursh-iac_normalise() { scoursh_iac_normalise "$@"; }
