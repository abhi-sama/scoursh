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

SUITES=(records core config checks findings report http e2e scan sast sast-secrets-forms sast-history sca iac dast dast-auth dast-crawl dast-sqli dast-jwt exit-code-matrix gate-mutation-proof ci-smoke netns paranoid vendor-engines vendor-engines-advisories engines sast-semgrep iac-trivy sast-gitleaks awscli aws-lint aws-fixtures lint-no-ai-selftest dast35-lint daily-suite color)
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
  # must still be runnable there.  CI installs it, and so does tools/daily-suite.sh's GNU leg
  # (its BSD leg expects it installed on the machine already) - see docs/CI-RUNBOOK.md.
  # --- shellcheck concurrency helpers -------------------------------------
  #
  # A single serial shellcheck process is the slowest thing in this suite by
  # a wide margin while every other core sits idle.  A first pass
  # parallelised purely by core count and kernel-panicked a 64GB/18-core Mac
  # twice: `shellcheck -x` on this tree measures at up to 2.2GB resident for
  # a single invocation (844MB without -x), and -P 18 held 176GB of RSS
  # across concurrent processes at the moment of the crash.  macOS has no
  # per-process memory ceiling to fall back on - `ulimit -v`/`-d`/`-m`/`-s`
  # are all rejected outright there - and shellcheck's own GHC runtime
  # ignores `+RTS -M` in the shipped binary ("Most RTS options are disabled.
  # Link with -rtsopts to enable them."), so a watchdog that samples RSS and
  # kills an offending process is the only ceiling available on this
  # platform, not an optional extra.  GitHub Actions runners are ephemeral
  # and a failed job costs nothing there, so CI keeps a fixed, un-watched
  # 2-way parallel run; the memory-derived cap and the watchdog below apply
  # only to a contributor's own machine.
  _sc_mem_total_gb() {
    if [[ -r /proc/meminfo ]]; then
      local key val kb
      while IFS=: read -r key val; do
        if [[ $key == MemTotal ]]; then
          kb=${val//[!0-9]/}
          if [[ $kb =~ ^[0-9]+$ ]]; then
            printf '%s\n' "$(( kb / 1024 / 1024 ))"
            return 0
          fi
        fi
      done < /proc/meminfo
    fi
    if command -v sysctl >/dev/null 2>&1; then
      local bytes
      bytes=$(sysctl -n hw.memsize 2>/dev/null) || bytes=
      if [[ $bytes =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$(( bytes / 1024 / 1024 / 1024 ))"
        return 0
      fi
    fi
    printf '8\n'
  }

  # Prefers AVAILABLE memory over total so a loaded machine gets a smaller
  # job count; prints nothing and returns non-zero when neither /proc/meminfo
  # nor vm_stat is readable, and the caller falls back to _sc_mem_total_gb.
  _sc_mem_avail_gb() {
    if [[ -r /proc/meminfo ]]; then
      local key val kb
      while IFS=: read -r key val; do
        if [[ $key == MemAvailable ]]; then
          kb=${val//[!0-9]/}
          if [[ $kb =~ ^[0-9]+$ ]]; then
            printf '%s\n' "$(( kb / 1024 / 1024 ))"
            return 0
          fi
        fi
      done < /proc/meminfo
      return 1
    fi
    if command -v vm_stat >/dev/null 2>&1 && command -v sysctl >/dev/null 2>&1; then
      local page_size free_pages key val
      page_size=$(sysctl -n hw.pagesize 2>/dev/null) || page_size=
      [[ $page_size =~ ^[0-9]+$ ]] || page_size=4096
      free_pages=
      while IFS=: read -r key val; do
        val=${val//[!0-9]/}
        case $key in
          "Pages free") free_pages=$val ;;
        esac
      done < <(vm_stat 2>/dev/null)
      # "Pages free" ONLY, deliberately NOT "+ Pages inactive": inactive
      # pages are reclaimable but not immediately so, and on this exact
      # host, counting them inflated this figure by ~19GB versus true free
      # memory (26.84GB computed vs 7.95GB actually free, measured while
      # under real concurrent pressure from unrelated processes) - which
      # meant the free-memory floor built on this number effectively never
      # fired, because it was comparing against a number that stayed high
      # long after the host was in real trouble.  "Pages free" alone is
      # also the exact formula a separate, hand-verified emergency guard
      # used to twice catch genuine pressure this reformulated figure
      # would have missed, so it is not a guess - it is the one formula
      # already proven to protect this host under real conditions.
      if [[ $free_pages =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$(( free_pages * page_size / 1024 / 1024 / 1024 ))"
        return 0
      fi
    fi
    return 1
  }

  # `nproc` (GNU), then `getconf _NPROCESSORS_ONLN` (POSIX, present on both
  # GNU and BSD userlands), then `sysctl -n hw.ncpu` (BSD/macOS without that
  # getconf knob), falling back to 4.  Used only as a ceiling on the
  # memory-derived job count below, never as the driver.
  _sc_detect_cores() {
    local n
    if command -v nproc >/dev/null 2>&1; then
      n=$(nproc 2>/dev/null) || n=
      if [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 )); then printf '%s\n' "$n"; return 0; fi
    fi
    if command -v getconf >/dev/null 2>&1; then
      n=$(getconf _NPROCESSORS_ONLN 2>/dev/null) || n=
      if [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 )); then printf '%s\n' "$n"; return 0; fi
    fi
    if command -v sysctl >/dev/null 2>&1; then
      n=$(sysctl -n hw.ncpu 2>/dev/null) || n=
      if [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 )); then printf '%s\n' "$n"; return 0; fi
    fi
    printf '4\n'
  }

  if command -v shellcheck >/dev/null 2>&1; then
    printf '\n=== linter: shellcheck ===\n'
    sc_dirs=()
    for d in lib tests tools modules aws; do [[ -d $d ]] && sc_dirs+=("$d"); done
    [[ -f scan.sh ]] && sc_dirs+=(scan.sh)

    sc_file_list=()
    while IFS= read -r sc_f; do
      sc_file_list+=("$sc_f")
    done < <(find "${sc_dirs[@]+"${sc_dirs[@]}"}" -name '*.sh' -type f | LC_ALL=C sort)
    sc_total=${#sc_file_list[@]}

    if (( sc_total == 0 )); then
      sc_status=0
    elif [[ ${GITHUB_ACTIONS:-} == true ]]; then
      # CI: ephemeral runner, a failed job is harmless - keep a fixed 2-way
      # batch (the prior core-count-derived batching, pinned rather than
      # host-detected), no memory cap, no watchdog.
      sc_jobs=2
      sc_batch=$(( (sc_total + sc_jobs - 1) / sc_jobs ))
      (( sc_batch < 1 )) && sc_batch=1

      sc_shard_dir=$(mktemp -d)
      trap 'rm -rf "$sc_shard_dir"' EXIT
      export SC_SHARD_DIR=$sc_shard_dir

      # Each batch writes to its OWN file rather than shared stdout: appends
      # above PIPE_BUF interleave (tension 17 - the same reason scan workers
      # write to their own shard files, not a shared findings.jsonl).
      # `-x` is unchanged: it still follows every `source`, per batch.
      #
      # xargs -P's own aggregate exit status is what `if` branches on here -
      # 123 if any invocation exited 1-125, so a failure in any ONE batch,
      # first or last, still fails the stage.  Nothing here re-derives
      # success from output content or discards an individual invocation's
      # status.
      # shellcheck disable=SC2016
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
    else
      # Local: cap concurrency by memory, not core count, and run one file
      # per shellcheck invocation so a watchdog kill - or a plain finding -
      # is always attributable to exactly one file.  `budget_gb` is the
      # ceiling watched per process; `SCOURSH_SHELLCHECK_MEM_BUDGET_GB`
      # overrides the default of 12.  `jobs` is (available-or-total GB / 2) /
      # budget_gb - reserving half of memory for the OS and everything else
      # already running - clamped to [1, detected core count].
      #
      # The default is 12, not the 3 a first pass used, because -x's cost is
      # dominated by how deep a file's own `source` graph goes, not by file
      # size: lib/engines.sh (104 lines, sources nothing) peaks under 100MB,
      # but scan.sh (1011 lines, sourcing six lib/*.sh files that source
      # further) measured 8.2-9.3GB resident across repeated clean runs on
      # this tree, and modules/sca/run.sh measured 8.9GB - every
      # tests/suites/*.sh file that sources lib/core.sh plus its own module
      # lands in the same range.  A 3GB budget killed seven such files
      # outright as false failures in testing, not real findings; 12 leaves
      # real headroom above the ~9GB measured worst case rather than
      # trusting a single sample.
      sc_budget_gb=${SCOURSH_SHELLCHECK_MEM_BUDGET_GB:-12}
      if [[ ! $sc_budget_gb =~ ^[0-9]+$ ]] || (( sc_budget_gb < 1 )); then
        sc_budget_gb=12
      fi

      sc_base_gb=$(_sc_mem_avail_gb) || sc_base_gb=$(_sc_mem_total_gb)
      if [[ ! $sc_base_gb =~ ^[0-9]+$ ]] || (( sc_base_gb < 1 )); then
        sc_base_gb=8
      fi

      # A per-process budget alone bounds one runaway process, but not
      # several processes that are each individually within budget while
      # collectively starving the host: `jobs` is sized from a one-time
      # snapshot of available memory, and if something ELSE on the machine
      # grows during a long run, that snapshot goes stale.  A live
      # free-memory floor is the same second layer a hand-rolled emergency
      # guard on this exact host was proven to need during this ticket's own
      # testing - it fired on the free-memory floor, not the per-process
      # cap, on a process that was still under its own budget.
      # `SCOURSH_SHELLCHECK_FREE_FLOOR_GB` overrides the default of 4.
      sc_free_floor_gb=${SCOURSH_SHELLCHECK_FREE_FLOOR_GB:-4}
      if [[ ! $sc_free_floor_gb =~ ^[0-9]+$ ]] || (( sc_free_floor_gb < 1 )); then
        sc_free_floor_gb=4
      fi

      sc_cores=$(_sc_detect_cores)

      sc_usable_gb=$(( sc_base_gb / 2 ))
      (( sc_usable_gb < 1 )) && sc_usable_gb=1
      sc_jobs=$(( sc_usable_gb / sc_budget_gb ))
      (( sc_jobs < 1 )) && sc_jobs=1
      (( sc_jobs > sc_cores )) && sc_jobs=$sc_cores

      printf 'shellcheck: %s files, %s parallel (%sGB/process budget, %sGB usable of %sGB, %s cores detected)\n' \
        "$sc_total" "$sc_jobs" "$sc_budget_gb" "$sc_usable_gb" "$sc_base_gb" "$sc_cores"

      sc_shard_dir=$(mktemp -d)
      trap 'rm -rf "$sc_shard_dir"' EXIT

      sc_budget_kb=$(( sc_budget_gb * 1024 * 1024 ))
      sc_have_ps=0
      command -v ps >/dev/null 2>&1 && sc_have_ps=1

      declare -A sc_pid_file=()
      declare -A sc_active=()
      declare -A sc_still_running=()
      declare -A sc_self_killed=()
      sc_next=0
      sc_status=0
      sc_watch_msgs=()

      _sc_launch_one() {
        local f=${sc_file_list[sc_next]} shard idx
        idx=$(printf '%05d' "$sc_next")
        shard=$(mktemp "$sc_shard_dir/shard-${idx}-XXXXXX")
        shellcheck -x -s bash -- "$f" >"$shard" 2>&1 &
        local pid=$!
        sc_pid_file[$pid]=$f
        sc_active[$pid]=1
        sc_next=$(( sc_next + 1 ))
      }

      while (( sc_next < sc_total )) && (( ${#sc_active[@]} < sc_jobs )); do
        _sc_launch_one
      done

      # No `wait -n` here: it needs bash >= 4.3 and this project's frozen
      # minimum is 4.2 (AGENTS.md).  `jobs -p -r` (a plain bash builtin, well
      # inside that minimum) lists still-running background PIDs instead, and
      # a completed-but-unreaped pid drops out of it even before `wait`
      # collects its exit status.
      while (( ${#sc_active[@]} > 0 )); do
        sleep 0.4

        if (( sc_have_ps )); then
          sc_biggest_pid=
          sc_biggest_rss=0
          for pid in "${!sc_active[@]}"; do
            kill -0 "$pid" 2>/dev/null || continue
            sc_rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null)
            sc_rss_kb=${sc_rss_kb//[!0-9]/}
            [[ $sc_rss_kb =~ ^[0-9]+$ ]] || continue
            if (( sc_rss_kb > sc_biggest_rss )); then
              sc_biggest_rss=$sc_rss_kb
              sc_biggest_pid=$pid
            fi
            if (( sc_rss_kb > sc_budget_kb )); then
              kill -TERM "$pid" 2>/dev/null || true
              sleep 0.2
              kill -KILL "$pid" 2>/dev/null || true
              sc_self_killed[$pid]=1
              sc_watch_msgs+=("shellcheck: watchdog killed pid $pid (${sc_pid_file[$pid]}) - exceeded the ${sc_budget_gb}GB memory budget")
              [[ $sc_biggest_pid == "$pid" ]] && sc_biggest_pid=
            fi
          done

          # Second, independent layer: even when every process is within
          # its own per-process budget, several of them together can still
          # starve the host if something ELSE running on the machine grew
          # after `jobs` was sized.  Free memory is the thing that actually
          # protects the host, so watch it directly rather than trusting the
          # one-time snapshot to stay true - and kill only the single
          # biggest offender, not everything, so a transient dip does not
          # fail the whole stage over one file's neighbours.
          if [[ -n $sc_biggest_pid ]]; then
            sc_free_now_gb=$(_sc_mem_avail_gb) || sc_free_now_gb=
            if [[ $sc_free_now_gb =~ ^[0-9]+$ ]] && (( sc_free_now_gb < sc_free_floor_gb )); then
              kill -TERM "$sc_biggest_pid" 2>/dev/null || true
              sleep 0.2
              kill -KILL "$sc_biggest_pid" 2>/dev/null || true
              sc_self_killed[$sc_biggest_pid]=1
              sc_watch_msgs+=("shellcheck: watchdog killed pid $sc_biggest_pid (${sc_pid_file[$sc_biggest_pid]}, its own RSS was under budget) - free memory dropped to ${sc_free_now_gb}GB, below the ${sc_free_floor_gb}GB floor")
            fi
          fi
        fi

        sc_still_running=()
        while IFS= read -r sc_rpid; do
          [[ -n $sc_rpid ]] && sc_still_running[$sc_rpid]=1
        done < <(jobs -p -r)

        for pid in "${!sc_active[@]}"; do
          if [[ -z ${sc_still_running[$pid]:-} ]]; then
            # `wait` on its own line is the LAST command in a simple list,
            # so under `set -e` a non-zero exit here (a real finding, or the
            # watchdog's kill above) would abort the whole stage instead of
            # being recorded and continuing to the next file.  Folding it
            # into an `||` exempts it, the same "part of an AND-OR list"
            # carve-out `(( ... )) && ...` below already relies on.
            sc_pid_exit=0
            wait "$pid" 2>/dev/null || sc_pid_exit=$?
            if (( sc_pid_exit != 0 )); then
              sc_status=1
              # Attribute a signal death to its file even when nothing in
              # this script did the killing - a host-level OOM killer, an
              # operator's own `kill`, or some other watcher can take the
              # linter's own process out from under us, and the failure
              # must still name the file rather than surface as a bare
              # non-zero exit with no explanation.  128+n is the shell's
              # own convention for "died from signal n" (bash manual
              # section "Exit Status"); our own watchdog kill above already
              # logs its own message, so this only fires for a death THIS
              # script did not cause.
              if (( sc_pid_exit > 128 )) && [[ -z ${sc_self_killed[$pid]:-} ]]; then
                sc_watch_msgs+=("shellcheck: ${sc_pid_file[$pid]} was killed (signal $(( sc_pid_exit - 128 ))) by something other than this stage's own watchdog - not a shellcheck finding, but the stage still fails since that file was never actually checked")
              fi
            fi
            unset "sc_active[$pid]"
            if (( sc_next < sc_total )); then
              _sc_launch_one
            fi
          fi
        done
      done

      for sc_shard in "$sc_shard_dir"/shard-*; do
        if [[ -e $sc_shard ]]; then
          cat -- "$sc_shard"
        fi
      done
      if (( ${#sc_watch_msgs[@]} > 0 )); then
        for sc_msg in "${sc_watch_msgs[@]}"; do
          printf '%s\n' "$sc_msg" >&2
        done
        sc_status=1
      fi

      rm -rf "$sc_shard_dir"
      trap - EXIT
      unset -f _sc_launch_one
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
