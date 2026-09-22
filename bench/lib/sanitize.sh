#!/usr/bin/env bash
# bench/lib/sanitize.sh - remove non-redistributable fields from benchmark
# output after it has been normalised.
#
# Semgrep's result `extra.message` and `extra.metadata` reproduce text from
# the selected rule.  The harness needs metadata.cwe while normalising, but it
# must not retain either field in an output that may be committed publicly.
# Call this only AFTER the adapter has written normalised.jsonl.

[[ -n ${BENCH_SANITIZE_SOURCED:-} ]] && return 0
BENCH_SANITIZE_SOURCED=1

# bench_sanitize_semgrep_raw FILE
#
# Rewrite FILE atomically.  A malformed Semgrep result is refused: announcing
# a sanitised artifact while leaving the original bytes in place would be a
# more serious failure than stopping the capture.
bench_sanitize_semgrep_raw() {
  local js=$1 tmp
  [[ -r $js ]] || {
    printf 'bench: no readable semgrep JSON to sanitise: %s\n' "$js" >&2
    return 2
  }
  command -v jq >/dev/null 2>&1 || {
    printf 'bench: jq is required to sanitise Semgrep output\n' >&2
    return 2
  }
  tmp=$(mktemp "${js}.sanitised.XXXXXX") || return 2
  if ! jq '
    if (.results | type) != "array" then
      error("Semgrep JSON has no results array")
    else
      .results |= map(.extra |= del(.message, .metadata))
    end
  ' "$js" >"$tmp"; then
    rm -f -- "$tmp"
    printf 'bench: failed to sanitise Semgrep output: %s\n' "$js" >&2
    return 2
  fi
  mv -- "$tmp" "$js"
}
