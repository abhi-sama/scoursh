#!/usr/bin/env bash
# tests/run-tests.sh - the whole suite, or one named suite.
#
#   tests/run-tests.sh                 # everything, including the linters
#   tests/run-tests.sh records         # one suite
#   tests/run-tests.sh --list          # what is available
#
# Each suite runs in its own process, because lib/core.sh installs traps, sets
# shell options, and owns a scratch directory: a suite that shared a shell with
# another would not be testing what the tool actually does.

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"

SUITES=(records core config findings report http e2e scan exit-code-matrix)
LINTERS=(lint-rules lint-shell lint-aws-readonly)

if [[ ${1:-} == --list ]]; then
  printf 'suites:  %s\n' "${SUITES[*]}"
  printf 'linters: %s\n' "${LINTERS[*]}"
  exit 0
fi

failed=()
run_one() {
  local kind=$1 name=$2 path=$3
  printf '\n=== %s: %s ===\n' "$kind" "$name"
  if bash "$path"; then
    printf -- '--- %s passed\n' "$name"
  else
    printf -- '--- %s FAILED\n' "$name"
    failed+=("$name")
  fi
}

if [[ -n ${1:-} ]]; then
  want=$1
  if [[ -f tests/suites/$want.sh ]]; then
    run_one suite "$want" "tests/suites/$want.sh"
  elif [[ -f tests/$want.sh ]]; then
    run_one linter "$want" "tests/$want.sh"
  else
    printf 'no such suite or linter: %s\n' "$want" >&2
    printf 'available: %s %s\n' "${SUITES[*]}" "${LINTERS[*]}" >&2
    exit 2
  fi
else
  for s in "${SUITES[@]}"; do
    run_one suite "$s" "tests/suites/$s.sh"
  done
  for l in "${LINTERS[@]}"; do
    run_one linter "$l" "tests/$l.sh"
  done
  # ShellCheck is optional: an air-gapped host may not have it, and the suite
  # must still be runnable there.  CI installs it.
  if command -v shellcheck >/dev/null 2>&1; then
    printf '\n=== linter: shellcheck ===\n'
    sc_dirs=()
    for d in lib tests tools modules aws; do [[ -d $d ]] && sc_dirs+=("$d"); done
    [[ -f scan.sh ]] && sc_dirs+=(scan.sh)
    if find "${sc_dirs[@]+"${sc_dirs[@]}"}" -name '*.sh' -type f \
      | LC_ALL=C sort \
      | xargs shellcheck -x -s bash; then
      printf -- '--- shellcheck passed\n'
    else
      printf -- '--- shellcheck FAILED\n'
      failed+=(shellcheck)
    fi
  else
    printf '\n=== linter: shellcheck (SKIPPED - not installed) ===\n'
  fi
fi

printf '\n'
if (( ${#failed[@]} > 0 )); then
  printf 'FAILED: %s\n' "${failed[*]}"
  exit 1
fi
printf 'all green\n'
