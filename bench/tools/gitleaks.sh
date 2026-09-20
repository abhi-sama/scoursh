#!/usr/bin/env bash
# bench/tools/gitleaks.sh - Gitleaks, secrets.
#
# GATE: `gitleaks dir --exit-code 0 --report-format json ROOT`, its own default
# rule set (no `--config`, no `--enable-rule`, no `--baseline-path`), scanning
# the WORKING TREE.
#
# `dir` AND NOT `git`, DELIBERATELY.  `gitleaks git` walks history, which is a
# strictly larger surface than the working tree and is not what the other two
# tools in this leg read - scoursh's history mode is a separate subcommand this
# leg does not run, and `trufflehog filesystem` reads the tree.  Comparing one
# tool's history scan against another's tree scan measures the surface rather
# than the detector.  (`gitleaks dir` skips `.git/` itself, measured; TruffleHog
# does not, which is why its adapter excludes it explicitly - see
# bench/tools/trufflehog.sh.)
#
# `--exit-code 0` because Gitleaks' own default is to exit 1 when it finds a
# leak, which is the normal and desirable outcome for a secrets scanner and not
# an error.  This is the same reasoning scoursh's own gitleaks ADAPTER records
# in modules/sast/adapters/gitleaks/adapter.sh.
#
# NO SEVERITY.  A Gitleaks finding carries a rule id, an entropy score and the
# matched bytes, and no severity of any kind - so every record here lands at
# `medium` by adapter convention and the B6 secrets leg publishes only the
# all-findings column.  Same situation as Checkov CE in the IaC leg, same
# treatment, stated for the same reason: a `--min-severity high` column would
# report Gitleaks at zero recall, which would be a fact about its JSON.
#
# CONFLICT DISCLOSURE.  scoursh ships `modules/sast/adapters/gitleaks/`, so
# `scoursh --use-engines` would WRAP this tool.  The scoursh column in this leg
# is `bench/tools/scoursh-secrets.sh`, which is explicitly not `--use-engines`.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_GITLEAKS_SOURCED:-} ]] && return 0
BENCH_TOOL_GITLEAKS_SOURCED=1

gitleaks_available() { command -v gitleaks >/dev/null 2>&1; }

gitleaks_version() { gitleaks version 2>/dev/null | head -1 | tr -d '\r'; }

gitleaks_scope() { printf '%s\n' secrets; }

gitleaks_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  gitleaks dir --no-banner --exit-code 0 \
    --report-format json --report-path "$raw/gitleaks.json" "$root" \
    >"$raw/stdout.txt" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  (( rc == 0 )) || {
    printf 'bench: gitleaks exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
    return 2
  }
}

# Gitleaks writes a BARE TOP-LEVEL JSON ARRAY, not an object with a results
# key - the same shape scoursh's own gitleaks adapter had to handle - so the
# flattened paths start at an index rather than at a key name.
#
# A ZERO-FINDING RUN WRITES `[]`, WHICH FLATTENS TO ONE EMPTY-ARRAY LEAF.  That
# is a real result and not an error, so the loop simply finds no `0/RuleID` and
# emits nothing.
gitleaks_normalise() {
  local raw=$1 root=$2
  local f=$raw/gitleaks.json
  [[ -r $f ]] || { printf 'bench: no gitleaks.json under %s\n' "$raw" >&2; return 2; }

  local flat
  flat=$(bench_json_flatten <"$f") || return 2
  bench_flat_read <<<"$flat"

  local i=0 rule file line
  while :; do
    [[ -n ${BENCH_FLAT_TYPE[$i/RuleID]:-} ]] || break
    rule=$(bench_flat_str "$i/RuleID")
    file=$(bench_relpath "$(bench_flat_str "$i/File")" "$root")
    line=$(bench_flat_num "$i/StartLine")
    # THE SECRET ITSELF IS NEVER COPIED INTO A RECORD.  Gitleaks reports the
    # matched bytes in `Secret` and `Match`, and the normalised stream is
    # committed - so carrying either would put a credential into this
    # repository.  The rule id and the line are what scoring needs; the raw
    # output beside it is what an auditor needs, and that is why the raw file
    # is preserved rather than the record widened.
    bench_record "$file" "$line" '' 'medium' "$rule"
    i=$(( i + 1 ))
  done
}
