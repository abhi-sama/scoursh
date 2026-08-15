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
#
# SC2016: the shellcheck stage's xargs/sh -c batch command is deliberately
# single-quoted so its variables expand in the child process, not here.
# shellcheck disable=SC2016

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"

SUITES=(records core config checks findings report http e2e scan sast sast-history sca iac dast exit-code-matrix gate-mutation-proof ci-smoke netns paranoid vendor-engines vendor-engines-advisories engines sast-semgrep iac-trivy sast-gitleaks awscli aws-lint aws-fixtures lint-no-ai-selftest dast35-lint)
LINTERS=(lint-rules lint-shell lint-aws-readonly lint-status lint-no-ai)

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

    # A single serial shellcheck process is the slowest thing in this suite by
    # a wide margin while every other core sits idle.  Fan the files out
    # across the host's own core count instead of a hardcoded number, so this
    # still works on a four-core laptop: `nproc` (GNU), then `getconf
    # _NPROCESSORS_ONLN` (POSIX, present on both GNU and BSD userlands), then
    # `sysctl -n hw.ncpu` (BSD/macOS without that getconf knob), falling back
    # to a fixed 4 if none of those resolve.
    sc_jobs=
    if command -v nproc >/dev/null 2>&1; then
      sc_jobs=$(nproc 2>/dev/null) || sc_jobs=
    fi
    if [[ ! $sc_jobs =~ ^[0-9]+$ ]] || (( sc_jobs < 1 )); then
      sc_jobs=
      if command -v getconf >/dev/null 2>&1; then
        sc_jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null) || sc_jobs=
      fi
    fi
    if [[ ! $sc_jobs =~ ^[0-9]+$ ]] || (( sc_jobs < 1 )); then
      sc_jobs=
      if command -v sysctl >/dev/null 2>&1; then
        sc_jobs=$(sysctl -n hw.ncpu 2>/dev/null) || sc_jobs=
      fi
    fi
    if [[ ! $sc_jobs =~ ^[0-9]+$ ]] || (( sc_jobs < 1 )); then
      sc_jobs=4
    fi

    sc_file_list=()
    while IFS= read -r sc_f; do
      sc_file_list+=("$sc_f")
    done < <(find "${sc_dirs[@]+"${sc_dirs[@]}"}" -name '*.sh' -type f | LC_ALL=C sort)
    sc_total=${#sc_file_list[@]}

    if (( sc_total == 0 )); then
      sc_status=0
    else
      # One batch per core: it saturates every core in a single wave and
      # still amortises -x's re-resolution of shared `source`d files across
      # several files per process, instead of paying that cost once per file
      # the way `-n 1` would.  See the PR description for the measured
      # comparison against other batch shapes on this tree.
      sc_batch=$(( (sc_total + sc_jobs - 1) / sc_jobs ))
      (( sc_batch < 1 )) && sc_batch=1

      sc_shard_dir=$(mktemp -d)
      trap 'rm -rf "$sc_shard_dir"' EXIT
      export SC_SHARD_DIR=$sc_shard_dir

      # Each batch writes to its OWN file rather than shared stdout: appends
      # above PIPE_BUF interleave (tension 17 - the same reason scan workers
      # write to their own shard files, not a shared findings.jsonl), and a
      # multi-line source snippet in a finding is well above that limit.
      # `-x` is unchanged: it still follows every `source`, per batch.
      #
      # xargs -P's own aggregate exit status is what `if` branches on here -
      # 123 if any invocation exited 1-125, so a failure in any ONE batch,
      # first or last, still fails the stage.  Nothing here re-derives success
      # from output content or discards an individual invocation's status.
      if printf '%s\n' "${sc_file_list[@]}" \
        | xargs -P "$sc_jobs" -n "$sc_batch" sh -c \
          'shellcheck -x -s bash "$@" >"$(mktemp "$SC_SHARD_DIR/shard-XXXXXX")" 2>&1' _; then
        sc_status=0
      else
        sc_status=$?
      fi

      for sc_shard in "$sc_shard_dir"/shard-*; do
        if [[ -e $sc_shard ]]; then
          cat -- "$sc_shard"
        fi
      done
      rm -rf "$sc_shard_dir"
      trap - EXIT
      unset SC_SHARD_DIR
    fi

    if (( sc_status == 0 )); then
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
