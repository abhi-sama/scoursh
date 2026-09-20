#!/usr/bin/env bash
# tests/lib/hubsum.sh - the shellcheck -x hub-fan-out walker, shared between
# tests/lint-source-graph.sh (which caps it) and tests/run-tests.sh's
# `--shard` file-list planner (which uses it as a per-file COST PROXY).
#
# This is a straight extraction, not a rewrite: the walk, the memoisation and
# the hub set are byte-identical to what tests/lint-source-graph.sh carried
# before this split, so the lint's own long-standing measurements (the
# exponential cliff between 6 and 8 copies, the cap derivation, ...) are
# still describing this exact code. See that file's own header for the full
# rationale; this file only holds the mechanism, not the policy (the cap
# itself, and what counts as an "entry point", stay there).
#
# ONE DEFINITION, so a future change to what shellcheck -x actually follows
# (the directive syntax, the /dev/null exemption, the cycle rule) cannot
# drift between the two callers - which is exactly the `redaction.rules` /
# `secrets.rules` shape this codebase has already paid for once (AGENTS.md,
# "redact-secrets is enforced by PROVENANCE").
#
# shellcheck shell=bash

HUBSUM_HUBS=(lib/core.sh lib/records.sh lib/findings.sh lib/http.sh lib/config.sh)
# Far above any real entry point's true expansion count (the worst one on
# record, dast-methods.sh at baseline, was 116) - guards a walker bug turning
# into a hang, never a real graph.
HUBSUM_VISIT_GUARD=200000

declare -A HUBSUM_KIDS_CACHE   # relpath -> newline-separated child relpaths, memoised once
declare -A HUBSUM_KIDS_DONE    # relpath -> 1 once HUBSUM_KIDS_CACHE is populated
declare -A HUBSUM_COUNTS       # relpath -> expansion count, reset per entry point
HUBSUM_VISITS=0

hubsum_is_hub() {
  local rel=$1 h
  for h in "${HUBSUM_HUBS[@]}"; do
    [[ $rel == "$h" ]] && return 0
  done
  return 1
}

# Parse one file's followed source= edges, memoised in HUBSUM_KIDS_CACHE.
# Mirrors shellcheck -x itself: a `# shellcheck source=<path>` directive
# applies to the NEXT source/`.` line, tolerating comment lines in between,
# and is dropped the moment a real code line intervenes. $2, if given, is the
# root every relative target resolves against (default: the caller's cwd).
hubsum_parse_file() {
  local rel=$1 root=${2:-.} path
  path=$root/$1
  [[ -n ${HUBSUM_KIDS_DONE[$rel]+_} ]] && return 0
  HUBSUM_KIDS_DONE[$rel]=1
  [[ -f $path ]] || { HUBSUM_KIDS_CACHE[$rel]=''; return 0; }

  local line pending='' kids='' trimmed target cand candrel
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line =~ ^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+source=([^[:space:]]+) ]]; then
      pending=${BASH_REMATCH[1]}
      continue
    fi
    if [[ $line =~ ^[[:space:]]*(source|\.)[[:space:]]+[^[:space:]] ]]; then
      if [[ -n $pending && $pending != /dev/null ]]; then
        target=$pending
        target=${target#./}
        if [[ $target == /* ]]; then
          cand=$target
          candrel=${cand#"$root"/}
        else
          cand=$root/$target
          candrel=$target
        fi
        [[ -f $cand ]] && kids+="$candrel"$'\n'
      fi
      pending=''
      continue
    fi
    trimmed=${line#"${line%%[![:space:]]*}"}
    if [[ -n $trimmed && ${trimmed:0:1} != '#' ]]; then
      pending=''
    fi
  done < "$path"
  HUBSUM_KIDS_CACHE[$rel]=$kids
}

# Depth-first walk with a per-path cycle guard (":"-delimited stack): a file
# already on the current path is counted once more but not re-descended
# into, since the runtime SCOURSH_*_SOURCED guards make repeated sourcing a
# no-op anyway.
hubsum_walk() {
  local rel=$1 stack=$2 root=${3:-.}
  HUBSUM_VISITS=$((HUBSUM_VISITS + 1))
  if (( HUBSUM_VISITS > HUBSUM_VISIT_GUARD )); then
    printf 'hubsum: ABORT - visit guard (%d) exceeded, likely a cycle bug in the walker itself\n' \
      "$HUBSUM_VISIT_GUARD" >&2
    exit 2
  fi
  HUBSUM_COUNTS[$rel]=$(( ${HUBSUM_COUNTS[$rel]:-0} + 1 ))
  case ":$stack:" in
    *":$rel:"*) return 0 ;;
  esac
  hubsum_parse_file "$rel" "$root"
  local newstack="$stack:$rel" kid
  while IFS= read -r kid; do
    [[ -n $kid ]] || continue
    hubsum_walk "$kid" "$newstack" "$root"
  done <<<"${HUBSUM_KIDS_CACHE[$rel]}"
}

# hubsum_for ENTRY_RELPATH [ROOT]  - prints the hub sum on stdout.
# ROOT defaults to the caller's cwd, matching hubsum_walk/hubsum_parse_file's
# own default, so an ordinary call from a script already `cd`'d to the repo
# root (as both current callers are) needs no second argument.
hubsum_for() {
  local entry=$1 root=${2:-.} h sum=0
  HUBSUM_COUNTS=()
  HUBSUM_VISITS=0
  hubsum_walk "$entry" '' "$root"
  for h in "${HUBSUM_HUBS[@]}"; do
    sum=$(( sum + ${HUBSUM_COUNTS[$h]:-0} ))
  done
  printf '%d' "$sum"
}
