#!/usr/bin/env bash
# tools/daily-suite/gnu-leg.sh - the half of tools/daily-suite.sh that runs
# INSIDE the Linux container (tools/daily-suite/gnu.dockerfile).
#
#   Usage: gnu-leg.sh <output-directory>
#
# It is never run on the host.  tools/daily-suite.sh bind-mounts the checkout
# and this run's result directory at their OWN absolute host paths - see that
# file's docker-run comment for why (a `git worktree` checkout's `.git` is a
# file holding absolute paths, and a leg whose scan root differs from the other
# leg's computes different repository-relative paths for every finding).
#
# It mirrors the host leg's discipline in the other direction.  The host asserts
# the userland is genuinely BSD before trusting a result; this asserts it is
# genuinely GNU, because an image that silently came up busybox - or with the
# suite's tools missing - would make the cross-userland comparison meaningless
# while still going green.  docs/FOUNDATION.md tension 24 is a register of facts
# that differ between the two userlands; a leg that cannot say which one it ran
# on is not evidence about either.
#
# shellcheck shell=bash

set -Eeuo pipefail

OUT=${1:?usage: gnu-leg.sh <output-directory>}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"

gl_fail() {
  printf 'GNU-userland assertion FAILED: %s\n' "$1" >&2
  # tools/daily-suite.sh reads this as a failed leg; the 0-5 contract
  # (docs/FOUNDATION.md tension 14) applies here too.  4 is "the environment is
  # unusable", which is what a wrong userland is.
  exit 4
}

# A VERSION INTERROGATION, not a pattern match: the binary is invoked through a
# variable so the command position never reads `grep`, which tests/lint-shell.sh
# forbids outside lib/core.sh's scan_match wrapper (tension 4 rule 2).
gl_version() {
  local bin=$1 out
  out=$( { "$bin" --version 2>&1 || true; } | head -n 1)
  printf '%s' "$out"
}

gl_assert_gnu_userland() {
  local sys bin ver maj min

  sys=$(uname -s)
  if [[ $sys != Linux ]]; then
    gl_fail "uname -s is '$sys', expected Linux - this script only runs inside the container"
  fi

  bin=$(command -v grep) || gl_fail 'grep is not on PATH'
  ver=$(gl_version "$bin")
  case $ver in
    *BSD*) gl_fail "grep at $bin reports '$ver' - that is a BSD grep, not GNU" ;;
  esac
  case $ver in
    *'GNU grep'*) : ;;
    *) gl_fail "grep at $bin reports '$ver', which is not GNU grep (busybox would look like this)" ;;
  esac
  GL_USERLAND=$ver

  bin=$(command -v find) || gl_fail 'find is not on PATH'
  case $(gl_version "$bin") in
    *'GNU findutils'*) : ;;
    *) gl_fail "find at $bin does not report GNU findutils" ;;
  esac

  bin=$(command -v sed) || gl_fail 'sed is not on PATH'
  case $(gl_version "$bin") in
    *'GNU sed'*) : ;;
    *) gl_fail "sed at $bin does not report GNU sed" ;;
  esac

  read -r maj min < <(bash -c 'printf "%s %s\n" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"')
  if (( maj < 4 || (maj == 4 && min < 2) )); then
    gl_fail "bash is $maj.$min, below scoursh's frozen 4.2 minimum"
  fi

  # Two tools the suite needs that a slimmer image would silently omit, turning
  # real coverage into a skipped check rather than a failure.
  command -v shellcheck >/dev/null 2>&1 ||
    gl_fail 'shellcheck is missing from the image, so the suite would skip its final linter'
  command -v look >/dev/null 2>&1 ||
    gl_fail "look is missing from the image, and lib/core.sh's db_lookup_exact needs it"

  printf 'GNU userland confirmed: %s / bash %s.%s\n' "$GL_USERLAND" "$maj" "$min"
}

GL_USERLAND=''
gl_assert_gnu_userland

# tests/run-tests.sh already runs every suite and linter SERIALLY, one process
# each.  Do not fan these out.
bash tests/run-tests.sh

# The fixture scan, normalised the same way the host leg normalises its own, so
# the two can be diffed byte for byte.  The run timestamp is the only value that
# legitimately differs between two runs.
rm -rf /tmp/gnu-fixture-run
bash tests/e2e/fixture-scan.sh /tmp/gnu-fixture-run >"$OUT/gnu-fixture.log" 2>&1
sed -e 's/"first_seen":"[^"]*"/"first_seen":"T"/g' \
  -e 's/"last_seen":"[^"]*"/"last_seen":"T"/g' \
  -- /tmp/gnu-fixture-run/findings.jsonl >"$OUT/gnu-findings.jsonl"

printf 'GNU leg complete: %s findings normalised\n' "$(wc -l <"$OUT/gnu-findings.jsonl")"
