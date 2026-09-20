#!/usr/bin/env bash
# bench/tools/scoursh-secrets.sh - scoursh's secrets detection.
#
# THERE IS NO SECRETS-ONLY MODE, AND THE OUTPUT IS DELIBERATELY NOT FILTERED
# TO ONE.  scoursh ships `modules/sast/rules/secrets.rules` inside the SAST
# module and `scan.sh` has no per-check selection flag, so `scan.sh sast` is
# what an operator actually runs to find a committed credential - and it is
# what this adapter runs, unfiltered.
#
# Post-filtering the records to the `SAST-SEC-*` family was the obvious
# alternative and is rejected on one measured ground: it would remove any
# non-secrets finding that landed inside a labelled range, and a labelled range
# in this corpus is either a planted credential or a NEGATIVE CONTROL.  Dropping
# records can therefore only lower scoursh's false-positive count, never raise
# it - a filter that can only flatter the tool being benchmarked is not a gate
# configuration, it is a thumb on the scale.  Gitleaks and TruffleHog are
# secrets-only tools and need no equivalent, so the asymmetry runs against
# scoursh, which is the safe direction.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SCOURSH_SECRETS_SOURCED:-} ]] && return 0
BENCH_TOOL_SCOURSH_SECRETS_SOURCED=1

BENCH_SCOURSH_ROOT=${BENCH_SCOURSH_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}
# shellcheck source=bench/tools/scoursh-iac.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/scoursh-iac.sh"

scoursh_secrets_available() { [[ -r $BENCH_SCOURSH_ROOT/scan.sh ]]; }
scoursh_secrets_version() { scoursh_iac_version; }
scoursh_secrets_scope() { printf '%s\n' secrets; }

scoursh_secrets_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  # NOT --history.  Gitleaks is run as `gitleaks dir` and TruffleHog as
  # `trufflehog filesystem`, both of which read the WORKING TREE; scoursh's
  # `--history` replays the same pack across git history instead, which is a
  # different surface with a different answer.  Comparing one tool's history
  # scan against another's working-tree scan measures the surface, not the
  # detector.
  (
    cd "$BENCH_SCOURSH_ROOT" &&
      bash scan.sh sast --path "$root" --out "$raw/run" --format json
  ) >"$raw/stdout.txt" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *) printf 'bench: scoursh sast exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2; return "$rc" ;;
  esac
}

scoursh_secrets_normalise() { _scoursh_normalise_run "$1" "$2"; }

# The hyphenated names bench/run-tool.sh dispatches on - see the note at the
# foot of bench/tools/scoursh-iac.sh.
scoursh-secrets_available() { scoursh_secrets_available; }
scoursh-secrets_version() { scoursh_secrets_version; }
scoursh-secrets_scope() { scoursh_secrets_scope; }
scoursh-secrets_run() { scoursh_secrets_run "$@"; }
scoursh-secrets_normalise() { scoursh_secrets_normalise "$@"; }
