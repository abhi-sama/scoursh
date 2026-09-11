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

printf '\n== inline field-shape warnings exist, and the --target wording mirrors lib/config.sh ==\n'

# The real incident this page's warnings exist for: an operator pasted a
# base-url into --target and the (then-unpreflighted) scan.sh scanned for
# three hours before refusing. These are POSITIVE presence checks - unlike
# CHECKS above - proving the non-blocking, inline validation table actually
# ships, not just that the page avoids network primitives.
if scan_match "$HITS" -F -e 'FIELD_VALIDATORS' -- "$PAGE"; then
  printf '  ok    a FIELD_VALIDATORS table (the inline, non-blocking field-shape warnings) is present\n'
else
  FAILED=1
  printf '  FAIL  %s has no FIELD_VALIDATORS table - the inline field-shape warnings do not exist\n' "${PAGE#"$ROOT"/}" >&2
fi

# Pull the shared wording fragment straight out of lib/config.sh's own
# _scope_target_not_found_message rather than hardcoding a second copy of
# it here, so this check breaks loudly (rather than silently going stale)
# the moment the CLI's own wording changes without the page following it.
CONFIG_SH=$ROOT/lib/config.sh
CLI_MSG_FRAGMENT='wants the ID a target is declared UNDER in'
if ! scan_match "$SCOURSH_SCRATCH/docs-build-cli-msg" -F -e "$CLI_MSG_FRAGMENT" -- "$CONFIG_SH"; then
  FAILED=1
  printf '  FAIL  lib/config.sh no longer contains the expected --target refusal wording fragment (%s) - cannot verify the page agrees with it\n' "$CLI_MSG_FRAGMENT" >&2
elif scan_match "$HITS" -F -e "$CLI_MSG_FRAGMENT" -- "$PAGE"; then
  printf '  ok    the inline --target warning wording matches lib/config.sh'"'"'s _scope_target_not_found_message\n'
else
  FAILED=1
  printf '  FAIL  %s does not contain the CLI'"'"'s own --target refusal wording (%s) - the inline warning has drifted from lib/config.sh\n' "${PAGE#"$ROOT"/}" "$CLI_MSG_FRAGMENT" >&2
fi

if scan_match "$HITS" -F -e 'targetAffirmMismatch' -- "$PAGE"; then
  printf '  ok    a --target/--i-own-target equality check (targetAffirmMismatch) is present\n'
else
  FAILED=1
  printf '  FAIL  %s has no --target/--i-own-target equality check\n' "${PAGE#"$ROOT"/}" >&2
fi

printf '\n'
if (( FAILED )); then
  printf 'lint-docs-build: FAILED\n'
  exit 1
fi
printf 'lint-docs-build: clean\n'
