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

SUITES=(records core config checks findings report http e2e scan sast sast-history sca iac dast dast-auth dast-cookies dast-crawl dast-discovery dast-headers dast-leakage dast-markup dast-ratelimit dast-transport dast-sqli dast-ldapi dast-xss dast-openredirect dast-jwt dast-authz exit-code-matrix gate-mutation-proof ci-smoke netns paranoid vendor-engines vendor-engines-advisories engines sast-semgrep iac-trivy sast-gitleaks awscli aws-lint aws-fixtures lint-no-ai-selftest dast35-lint daily-suite run-tests-stage color)
LINTERS=(lint-rules lint-shell lint-aws-readonly lint-status lint-no-ai)
# The whole-tree shellcheck run is a STAGE, not a suite and not a linter file:
# it has no tests/*.sh of its own, it is the last thing a full run does, and it
# is the slowest thing in the suite by a wide margin.  Run it alone with
# `tests/run-tests.sh shellcheck`, so it can be iterated on without paying for
# the other 50 checks first - which is exactly what nobody could do while it
# was unable to finish at all.  (Note the wrapping: a comment line that BEGINS
# with the word `shellcheck` is parsed as a directive and is an SC1072 error,
# so prose about it must never start a line with it.)
STAGES=(shellcheck)

if [[ ${1:-} == --list ]]; then
  printf 'suites:  %s\n' "${SUITES[*]}"
  printf 'linters: %s\n' "${LINTERS[*]}"
  printf 'stages:  %s\n' "${STAGES[*]}"
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

# ===========================================================================
# The whole-tree shellcheck stage.
# ===========================================================================
# `sc_stage` reports through the global `SC_STAGE_STATUS` - 0 when every file
# was CHECKED and every one of them was clean, 1 otherwise - and ALWAYS returns
# 0 itself.  That shape is deliberate and is the whole reason this function can
# be strict:
#
#   * Calling it as `sc_stage || failed+=(shellcheck)` would put it in an
#     `A || B` list, and bash then disables `errexit` for its ENTIRE BODY, not
#     just for the call ("If a compound command or shell function executes in a
#     context where -e is being ignored, none of the commands executed within
#     the compound command or function body will be affected by the -e
#     setting" - bash manual, "The Set Builtin").  This code ran at top level
#     with `errexit` live before it was a function; that spelling would have
#     silently stripped the strictness, and would have made the `EXIT` trap's
#     own "an unexpected non-zero exit" arm unreachable - a trap documenting a
#     protection that cannot fire.
#   * Calling it as `sc_stage; sc_rc=$?` does not work either: a function
#     returning non-zero as a plain command IS an errexit abort, so the runner
#     would die before the assignment on any run where shellcheck reports
#     anything.  Measured, both ways.
#
# So: always return 0, carry the verdict in a variable, and let the body run
# under the same `set -Eeuo pipefail` the rest of this file does.
#
# It prints its own verdict line - and it prints one on EVERY exit path,
# including the ones that do not reach the bottom of this function: a `set -E`
# abort, an operator's ^C, and a host-level SIGTERM all used to end the stage
# after nothing but its header, which reads exactly like a stage that had
# nothing to say.  The verdict is therefore emitted from a trap with a
# once-only guard, never only from the straight-line path.
#
# It also distinguishes a file that was CHECKED AND CLEAN from a file that
# could not be checked at all (killed by the watchdog below, killed by
# something else on the host, or refused by shellcheck itself).  An
# unmeasurable file is never rounded up to a pass: it is named, counted, and
# fails the stage, because "shellcheck said nothing about this file" and
# "shellcheck found nothing wrong with this file" are different facts and only
# the second one is evidence.
SC_STAGE_STATUS=0
sc_stage() {
  SC_STAGE_STATUS=0
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

    # --- the verdict, on every exit path ------------------------------------
    #
    # `sc_unchecked` names files this stage could not get a result for, as
    # opposed to files it checked and found clean; `sc_findings` is the plain
    # "shellcheck reported something" case.  Both fail the stage, and they are
    # reported separately because only one of them is a defect in the tree.
    sc_verdict_done=0
    sc_unchecked=()
    sc_findings=()
    sc_shard_dir=

    _sc_verdict() {
      local rc=$1 detail=${2:-}
      (( sc_verdict_done )) && return 0
      sc_verdict_done=1
      if (( ${#sc_unchecked[@]} > 0 )); then
        printf 'shellcheck: %s of %s file(s) could NOT be checked - unmeasured, not clean:\n' \
          "${#sc_unchecked[@]}" "${sc_total:-?}" >&2
        local u
        for u in "${sc_unchecked[@]}"; do printf '  - %s\n' "$u" >&2; done
      fi
      if (( ${#sc_findings[@]} > 0 )); then
        printf 'shellcheck: %s of %s file(s) were checked and reported findings (above): %s\n' \
          "${#sc_findings[@]}" "${sc_total:-?}" "${sc_findings[*]}" >&2
      fi
      if (( rc == 0 )); then
        printf -- '--- shellcheck passed\n'
      else
        printf -- '--- shellcheck FAILED%s\n' "${detail:+ ($detail)}"
      fi
      return 0
    }

    # A `set -e` abort, a ^C and a SIGTERM all end this function without
    # reaching its own verdict line.  Without these traps that produces a
    # stage that printed its header and nothing else, which is indistinguishable
    # from a clean one to anyone reading the log - the exact failure this
    # ticket was filed for.  bash does not run an EXIT trap for an untrapped
    # SIGINT/SIGTERM, so those two are trapped explicitly rather than left to
    # EXIT to catch.
    _sc_abort_verdict() {
      local sig=$1
      [[ -n $sc_shard_dir ]] && rm -rf "$sc_shard_dir"
      _sc_verdict 1 "the stage itself ended on $sig before it could reach a verdict - no file's result from this run can be trusted"
      return 0
    }
    trap '_sc_abort_verdict "an unexpected non-zero exit"' EXIT
    trap '_sc_abort_verdict SIGINT; exit 130' INT
    trap '_sc_abort_verdict SIGTERM; exit 143' TERM

    # The file list is normally the whole tree.  SCOURSH_SHELLCHECK_FILE_LIST
    # is a TEST SEAM (tests/suites/run-tests-stage.sh drives this stage over a
    # two-file fixture with a stub `shellcheck`, which is the only way to
    # exercise the watchdog and the abort paths in seconds instead of minutes).
    # It is never set by a real run, and it is deliberately NOT a way to
    # exclude files: a real run still checks every *.sh in the tree.
    if [[ -n ${SCOURSH_SHELLCHECK_FILE_LIST:-} && -r ${SCOURSH_SHELLCHECK_FILE_LIST:-} ]]; then
      sc_file_list=()
      while IFS= read -r sc_f; do
        [[ -n $sc_f ]] && sc_file_list+=("$sc_f")
      done < "$SCOURSH_SHELLCHECK_FILE_LIST"
      printf 'shellcheck: file list overridden by SCOURSH_SHELLCHECK_FILE_LIST (%s)\n' \
        "$SCOURSH_SHELLCHECK_FILE_LIST"
    else
      sc_dirs=()
      for d in lib tests tools modules aws; do [[ -d $d ]] && sc_dirs+=("$d"); done
      [[ -f scan.sh ]] && sc_dirs+=(scan.sh)

      sc_file_list=()
      while IFS= read -r sc_f; do
        sc_file_list+=("$sc_f")
      done < <(find "${sc_dirs[@]+"${sc_dirs[@]}"}" -name '*.sh' -type f | LC_ALL=C sort)
    fi
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

      # No `trap ... EXIT` here: the stage-wide traps installed above already
      # remove $sc_shard_dir, and re-arming EXIT would drop the verdict trap.
      sc_shard_dir=$(mktemp -d)
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
      sc_shard_dir=
      unset SC_SHARD_DIR
      # Batched, so a finding cannot be attributed to one file here; the
      # per-file attribution the local path gives is not available on CI and
      # is not faked.  `sc_status` alone carries the verdict on this path.
      if (( sc_status != 0 )); then
        sc_findings=("(batched - see the output above)")
      fi
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

      # No `trap ... EXIT` here either - see the CI branch's note above.
      sc_shard_dir=$(mktemp -d)

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
              # Spelled as an `if`, not `[[ ... ]] && sc_biggest_pid=`.  The
              # ticket that rewrote this stage carried a hypothesis that the
              # `&&` spelling aborted the script under `set -e` when the test
              # was false, which would explain a stage that printed only its
              # header.  MEASURED, and REFUTED: bash exempts a whole `A && B`
              # list from `set -e` when A itself fails, at top level and
              # inside a loop or an `if` body alike, so it never fired.  The
              # `if` stays because it is clearer, not because it fixes
              # anything - the missing verdict line is fixed by the traps
              # above, which cover the abort paths that DO exist.
              if [[ $sc_biggest_pid == "$pid" ]]; then sc_biggest_pid=; fi
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
              # Exit 1 is the only status that means "this file WAS checked
              # and shellcheck has something to say about it".  Everything
              # else means the file was never actually checked, and those two
              # outcomes are kept apart here rather than merged into one
              # non-zero: shellcheck's own exit 2 is "could not process this
              # file", 126/127 are the shell's "could not run the linter at
              # all", and 128+n is "died from signal n" (bash manual, "Exit
              # Status") - our own watchdog's kill, a host-level OOM killer,
              # or an operator's `kill`.  Rounding any of them up to a clean
              # result is the single most expensive way for this stage to be
              # wrong, because an unmeasured file looks exactly like a clean
              # one in the output.
              if (( sc_pid_exit == 1 )); then
                sc_findings+=("${sc_pid_file[$pid]}")
              elif [[ -n ${sc_self_killed[$pid]:-} ]]; then
                sc_unchecked+=("${sc_pid_file[$pid]} (killed by this stage's own watchdog - see the message below)")
              elif (( sc_pid_exit > 128 )); then
                sc_unchecked+=("${sc_pid_file[$pid]} (died from signal $(( sc_pid_exit - 128 )), not this stage's doing)")
                sc_watch_msgs+=("shellcheck: ${sc_pid_file[$pid]} was killed (signal $(( sc_pid_exit - 128 ))) by something other than this stage's own watchdog - not a shellcheck finding, but the stage still fails since that file was never actually checked")
              else
                sc_unchecked+=("${sc_pid_file[$pid]} (shellcheck exited $sc_pid_exit - it never produced a result for this file)")
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
      sc_shard_dir=
      unset -f _sc_launch_one
    fi

    # A file that could not be checked fails the stage on its own, even when
    # nothing that DID get checked reported anything.
    if (( ${#sc_unchecked[@]} > 0 )); then
      sc_status=1
    fi
    _sc_verdict "$sc_status"
    trap - EXIT INT TERM
    SC_STAGE_STATUS=$sc_status
    return 0
  else
    printf '\n=== linter: shellcheck (SKIPPED - not installed) ===\n'
    return 0
  fi
}

if [[ -n ${1:-} ]]; then
  want=$1
  if [[ -f tests/suites/$want.sh ]]; then
    run_one suite "$want" "tests/suites/$want.sh"
  elif [[ -f tests/$want.sh ]]; then
    run_one linter "$want" "tests/$want.sh"
  elif [[ " ${STAGES[*]} " == *" $want "* ]]; then
    # A plain call, never `sc_stage || ...` - see sc_stage's own header for why
    # the `||` spelling would disable `errexit` for the whole stage body.
    sc_stage
    if (( SC_STAGE_STATUS != 0 )); then failed+=(shellcheck); fi
  else
    printf 'no such suite, linter or stage: %s\n' "$want" >&2
    printf 'available: %s %s %s\n' "${SUITES[*]}" "${LINTERS[*]}" "${STAGES[*]}" >&2
    exit 2
  fi
else
  for s in "${SUITES[@]}"; do
    run_one suite "$s" "tests/suites/$s.sh"
  done
  for l in "${LINTERS[@]}"; do
    run_one linter "$l" "tests/$l.sh"
  done
  sc_stage
  if (( SC_STAGE_STATUS != 0 )); then failed+=(shellcheck); fi
fi

printf '\n'
if (( ${#failed[@]} > 0 )); then
  printf 'FAILED: %s\n' "${failed[*]}"
  exit 1
fi
printf 'all green\n'
