#!/usr/bin/env bash
# tests/lint-docs-build.sh - docs/build.html exists and is genuinely static.
#
# The command builder (docs/build.html) is a hard-constrained page: pure
# static HTML/CSS/JS, no build step, no external CDN, no network call of any
# kind, and it never executes anything - it only composes a command STRING
# and offers a copy button.  A rule enforced only by a comment asking nicely
# is not enforced, so this scans the shipped file for the concrete substrings
# that would violate that contract: an external resource reference, an
# externally-sourced script tag, or any of the browser network APIs a page
# could use to phone home.
#
# An optional ROOT argument points the lint at a different tree (mirroring
# tests/lint-no-ai.sh's own shape), so a future self-test can prove both
# directions without mutating this repository.
#
# shellcheck shell=bash

set -Eeuo pipefail
SELF_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$SELF_ROOT/lib/core.sh"

ROOT=$(cd -- "${1:-$SELF_ROOT}" && pwd -P)
PAGE=$ROOT/docs/build.html

printf '== docs/build.html exists and is self-contained (no network, no execution) ==\n'

if [[ ! -f $PAGE ]]; then
  printf 'lint-docs-build: FAILED - %s does not exist\n' "$PAGE" >&2
  exit 1
fi

FAILED=0
HITS=$SCOURSH_SCRATCH/docs-build-hits

# Substring, human label.  Any one hit means the page can either reach an
# external resource/network or hand a viewer a live network primitive - both
# are forbidden by docs/build.html's own hard constraints.
declare -a CHECKS=(
  'http://|an external http:// reference'
  'https://|an external https:// reference'
  '<script src=|an externally-sourced <script src=...> tag'
  'fetch(|a fetch( call'
  'XMLHttpRequest|an XMLHttpRequest call'
  'WebSocket|a WebSocket connection'
)

check_entry() {
  local pat=$1 label=$2
  if scan_match "$HITS" -F -e "$pat" -- "$PAGE"; then
    FAILED=1
    printf '  FAIL  %s contains %s:\n' "${PAGE#"$ROOT"/}" "$label" >&2
    sed 's/^/          /' "$HITS" >&2
  else
    printf '  ok    no %s\n' "$label"
  fi
}

entry=""
for entry in "${CHECKS[@]}"; do
  check_entry "${entry%%|*}" "${entry#*|}"
done

printf '\n'
if (( FAILED )); then
  printf 'lint-docs-build: FAILED\n'
  exit 1
fi
printf 'lint-docs-build: clean\n'
