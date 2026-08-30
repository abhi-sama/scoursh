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

SUITES=(records core config checks findings report http e2e scan sast sast-secrets-forms sast-history sca iac dast dast-auth dast-cookies dast-crawl dast-cors dast-discovery dast-headers dast-leakage dast-markup dast-methods dast-ratelimit dast-transport dast-sqli dast-pathtraversal dast-cmdi dast-ldapi dast-xss dast-openredirect dast-jwt dast-graphql dast-authz dast-banner exit-code-matrix gate-mutation-proof ci-smoke netns paranoid vendor-engines vendor-engines-advisories engines sast-semgrep iac-trivy sast-gitleaks awscli aws-lint aws-fixtures lint-no-ai-selftest dast35-lint lint-rules-paths daily-suite run-tests-stage color secret-redaction)
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
SC_STAGE_SKIPPED=0
SC_STAGE_NOT_INSTALLED=0
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

  # AVAILABLE memory: what this host can hand out right now WITHOUT swapping.
  # Prints nothing and returns non-zero when neither /proc/meminfo nor vm_stat
  # is readable, and the caller falls back to _sc_mem_total_gb.
  #
  # On Linux that is `MemAvailable`, which the kernel computes for exactly this
  # question.  macOS publishes no equivalent, so it is summed here from the
  # page classes the Darwin VM will reclaim on demand:
  #
  #     free + inactive + purgeable + speculative
  #
  # THIS FUNCTION USED TO RETURN `Pages free` ALONE, AND THAT IS THE ROOT OF
  # THE DEFECT THIS TICKET WAS FILED FOR.  `Pages free` is the FREE LIST, which
  # Darwin deliberately holds near a low-water mark and refills lazily by
  # reclaiming inactive pages; it is not a measure of available memory and does
  # not grow with the size of the machine.  Measured on a 64GB/18-core host with
  # nothing else of consequence running: `Pages free` reported 6GB while
  # 36GB was genuinely available - a 6x understatement - and it stayed pinned
  # near 6GB no matter how much memory was actually free.  Every number
  # downstream inherited that error, which is why an 8GB host, a 27GB host and
  # this 64GB host all failed the stage in the same way: the arithmetic was
  # wrong on every host rather than any host being too small.
  #
  # The comment this replaces argued for `Pages free` on the grounds that
  # including inactive pages made the stage's absolute free-memory floor "never
  # fire".  That observation was real and the conclusion drawn from it was
  # backwards: it is evidence that an ABSOLUTE floor is the broken part (see
  # the floor's own note below, where it is now derived from host size), not a
  # reason to deliberately understate available memory so that a broken floor
  # trips.  Understating the measurement to make a bad threshold fire is
  # fixing a thermometer by holding a match to it - and what it actually bought
  # was a watchdog that killed a healthy 1.09GB process on a host with 36GB
  # free, which is reproduced as section G of tests/suites/run-tests-stage.sh.
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
      local page_size key val avail_pages=0 got=0
      page_size=$(sysctl -n hw.pagesize 2>/dev/null) || page_size=
      [[ $page_size =~ ^[0-9]+$ ]] || page_size=4096
      while IFS=: read -r key val; do
        val=${val//[!0-9]/}
        [[ $val =~ ^[0-9]+$ ]] || continue
        case $key in
          "Pages free"|"Pages inactive"|"Pages purgeable"|"Pages speculative")
            avail_pages=$(( avail_pages + val ))
            got=1
            ;;
        esac
      done < <(vm_stat 2>/dev/null)
      if (( got )); then
        printf '%s\n' "$(( avail_pages * page_size / 1024 / 1024 / 1024 ))"
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
    sc_skipped=()
    sc_watch_msgs=()
    sc_shard_dir=

    # Three outcomes, three roll-ups, because they need three different
    # responses from whoever reads the log:
    #
    #   findings   the tree has a defect - fix the file.            FAILS
    #   unchecked  this stage failed to get a result it should
    #              have got - a defect in the stage or in the host.  FAILS
    #   skipped    this file demonstrably needs more memory than
    #              this host has to give.  Named, counted, and
    #              carried into the runner's own last line, so a
    #              partial run can never be read as a complete
    #              one - but NOT a failure, because "this machine
    #              is too small for this file" is a fact about the
    #              machine, the same class as `shellcheck` not
    #              being installed at all.                          PASSES
    #
    # Collapsing `skipped` into `unchecked` is what made the stage unable to
    # exit 0 on any host; collapsing it into silence is the false green
    # acceptance criterion 5 forbids.  It is neither.
    _sc_verdict() {
      local rc=$1 detail=${2:-}
      (( sc_verdict_done )) && return 0
      sc_verdict_done=1
      # WHY THE KILL MESSAGES ARE FLUSHED HERE AND NOT WHERE THEY ARE MADE.
      # This function is what the EXIT/INT/TERM traps call, so it is the only
      # place that runs on EVERY exit path.  These messages used to be printed
      # inline once both passes had finished, which meant an abort anywhere
      # before that point threw away the entire explanation for every kill the
      # run had already made.  That is not hypothetical: the pre-fix stage was
      # measured on this tree reporting 9 unmeasured files, each annotated
      # "see the message below", with no message below - the `ps` race above
      # had aborted the stage first.  The two facts that make a kill
      # actionable are WHICH file and WHICH cause, and losing them is exactly
      # the unattributable kill this ticket calls the defect rather than a
      # symptom.  They are printed before the roll-ups so that a reader who
      # sees a file named as unmeasured has already read why.
      if (( ${#sc_watch_msgs[@]} > 0 )); then
        local m
        for m in "${sc_watch_msgs[@]}"; do printf '%s\n' "$m" >&2; done
      fi
      if (( ${#sc_unchecked[@]} > 0 )); then
        printf 'shellcheck: %s of %s file(s) could NOT be checked - unmeasured, not clean:\n' \
          "${#sc_unchecked[@]}" "${sc_total:-?}" >&2
        local u
        for u in "${sc_unchecked[@]}"; do printf '  - %s\n' "$u" >&2; done
      fi
      if (( ${#sc_skipped[@]} > 0 )); then
        printf 'shellcheck: %s of %s file(s) SKIPPED - this host does not have the memory to check them:\n' \
          "${#sc_skipped[@]}" "${sc_total:-?}" >&2
        local s
        for s in "${sc_skipped[@]}"; do printf '  - %s\n' "$s" >&2; done
        printf 'shellcheck: those file(s) were NOT checked.  Re-run on a larger host, or raise the headroom, to cover them.\n' >&2
      fi
      if (( ${#sc_findings[@]} > 0 )); then
        printf 'shellcheck: %s of %s file(s) were checked and reported findings (above): %s\n' \
          "${#sc_findings[@]}" "${sc_total:-?}" "${sc_findings[*]}" >&2
      fi
      if (( rc == 0 )); then
        if (( ${#sc_skipped[@]} > 0 )); then
          printf -- '--- shellcheck passed (%s of %s checked, %s SKIPPED - host too small, see above)\n' \
            "$(( ${sc_total:-0} - ${#sc_skipped[@]} ))" "${sc_total:-?}" "${#sc_skipped[@]}"
        else
          printf -- '--- shellcheck passed (%s of %s file(s) checked)\n' "${sc_total:-0}" "${sc_total:-?}"
        fi
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
      # is always attributable to exactly one file.
      #
      # THE MEMORY MODEL, AND WHY THE PREVIOUS ONE COULD NOT REACH A VERDICT
      # ON ANY HOST.  `shellcheck -x` cost on this tree is dominated by how
      # deep a file's own `source` graph goes, not by file size, and the
      # spread is enormous.  Measured here with /usr/bin/time -l, one file
      # per invocation, watchdog out of the way:
      #
      #     tests/suites/dast-cookies.sh   12.99 GB
      #     tests/suites/dast-jwt.sh       12.96 GB
      #     scan.sh                         4.74 GB
      #     modules/sca/run.sh              3.46 GB
      #     lib/engines.sh                  0.11 GB
      #
      # A 118x spread is why ONE number could not do this job.  The old model
      # had a single `budget_gb`, defaulting to 12, serving as both the
      # per-process kill threshold AND the divisor that sized concurrency,
      # and it was wrong in three independent, compounding ways:
      #
      #   1. It divided a wrongly-measured availability figure (see
      #      _sc_mem_avail_gb above - `Pages free`, 6GB reported where 36GB
      #      was available) by 2 and then by 12.  On any host with under
      #      24GB of correctly-measured headroom that yields 0, clamped up
      #      to 1 - so the "memory-derived" job count was in practice the
      #      constant 1 on every machine anyone has run this on, and the
      #      log line reporting it was noise.
      #   2. When headroom was BELOW the budget it clamped the job count and
      #      left the budget alone, promising one process 12GB on a host
      #      with 3GB to give.  The clamp hid the contradiction rather than
      #      reporting it.
      #   3. 12 is BELOW the 12.99GB measured worst case, so even with (1)
      #      and (2) fixed the two heaviest files in the tree would still be
      #      killed as false failures.  The 8.42-9.87GB figure the previous
      #      note relied on is stale; the tree has grown since it was taken.
      #
      # The replacement separates the two jobs that number was doing, and
      # keeps ONE stateable invariant in every pass:
      #
      #     jobs * budget <= headroom
      #
      # so the stage can never commit more memory than it has established the
      # host can give, whatever lands concurrently.
      #
      #     total     physical RAM
      #     avail     obtainable now without swapping (_sc_mem_avail_gb)
      #     reserve   left for the OS and everything else = max(2, total/8)
      #     headroom  = max(avail - reserve, 1)
      #
      # PASS 1 plans against a TYPICAL footprint (`step_gb`, 5GB - above
      # scan.sh's 4.74GB, so the whole body of the tree clears it) and runs
      # wide.  A file that exceeds it is NOT a failure: it is DEFERRED.
      # PASS 2 re-runs only the deferred files against the RUNAWAY trip point
      # (`budget_gb`, 20GB - 1.5x the 12.99GB worst case, so a genuine
      # runaway is still caught but no legitimate file is), necessarily
      # narrow.  Both budgets are clamped down to `headroom`, which is what
      # makes (2) above impossible to reproduce.
      #
      # Why this is right on a small host as well as a large one:
      #
      #   8GB host, 6GB available:  reserve 2, headroom 4.
      #     pass 1: budget min(5,4)=4,  jobs min(4/4,cores)=1  -> 4 <= 4
      #     pass 2: budget min(20,4)=4, jobs 1                 -> 4 <= 4
      #     The 12.99GB files cannot fit in 4GB on this host at all, so they
      #     are reported as SKIPPED, by name, with that reason - never as a
      #     silent kill and never rounded up to clean.
      #  27GB host, 20GB available: reserve 3, headroom 17.
      #     pass 1: budget 5,  jobs min(17/5,cores)=3          -> 15 <= 17
      #     pass 2: budget 17, jobs 1                          -> 17 <= 17
      #     12.99 <= 17, so every file is measured.
      #  64GB host, 36GB available: reserve 8, headroom 28.
      #     pass 1: budget 5,  jobs min(28/5,cores)=5          -> 25 <= 28
      #     pass 2: budget 20, jobs 1                          -> 20 <= 28
      #     Every file is measured.  This is the host it was developed on.
      #
      # SCOURSH_SHELLCHECK_MEM_BUDGET_GB and SCOURSH_SHELLCHECK_STEP_GB
      # override the two defaults; SCOURSH_SHELLCHECK_FREE_FLOOR_GB overrides
      # the derived pressure floor.  All three are for testing and for a host
      # whose shape these defaults get wrong, not for routine use.
      sc_budget_gb=${SCOURSH_SHELLCHECK_MEM_BUDGET_GB:-20}
      if [[ ! $sc_budget_gb =~ ^[0-9]+$ ]] || (( sc_budget_gb < 1 )); then
        sc_budget_gb=20
      fi
      sc_step_gb=${SCOURSH_SHELLCHECK_STEP_GB:-5}
      if [[ ! $sc_step_gb =~ ^[0-9]+$ ]] || (( sc_step_gb < 1 )); then
        sc_step_gb=5
      fi
      (( sc_step_gb > sc_budget_gb )) && sc_step_gb=$sc_budget_gb

      # SCOURSH_SHELLCHECK_FORCE_{TOTAL,AVAIL}_GB are TEST SEAMS, in the same
      # shape as lib/http.sh's SCOURSH_HTTP_RESOLVE and lib/paranoid.sh's
      # SCOURSH_PARANOID_FORCE_BACKEND: they let this arithmetic be driven
      # over an 8GB, a 27GB and a 64GB host from one machine, which is what
      # makes "it is right on both a small and a large host" a measured claim
      # rather than a claim about whichever host happened to run it.  A real
      # run leaves them unset and reads the host.
      sc_total_gb=${SCOURSH_SHELLCHECK_FORCE_TOTAL_GB:-}
      if [[ ! $sc_total_gb =~ ^[0-9]+$ ]] || (( sc_total_gb < 1 )); then
        sc_total_gb=$(_sc_mem_total_gb)
      fi
      if [[ ! $sc_total_gb =~ ^[0-9]+$ ]] || (( sc_total_gb < 1 )); then
        sc_total_gb=8
      fi
      sc_avail_gb=${SCOURSH_SHELLCHECK_FORCE_AVAIL_GB:-}
      if [[ ! $sc_avail_gb =~ ^[0-9]+$ ]] || (( sc_avail_gb < 1 )); then
        sc_avail_gb=$(_sc_mem_avail_gb) || sc_avail_gb=$(( sc_total_gb / 2 ))
      fi
      if [[ ! $sc_avail_gb =~ ^[0-9]+$ ]] || (( sc_avail_gb < 1 )); then
        sc_avail_gb=$(( sc_total_gb / 2 ))
        (( sc_avail_gb < 1 )) && sc_avail_gb=1
      fi
      # Available can legitimately exceed total on neither platform; if a
      # parse goes wrong it must not manufacture headroom.
      (( sc_avail_gb > sc_total_gb )) && sc_avail_gb=$sc_total_gb

      sc_reserve_gb=$(( sc_total_gb / 8 ))
      (( sc_reserve_gb < 2 )) && sc_reserve_gb=2
      sc_headroom_gb=$(( sc_avail_gb - sc_reserve_gb ))
      (( sc_headroom_gb < 1 )) && sc_headroom_gb=1

      # A per-process budget alone bounds one runaway process, but not
      # several processes that are each individually within budget while
      # something ELSE on the machine grows after the plan was made.  The
      # floor is the live second layer for that, and it is now derived from
      # host size (`reserve`) rather than being the absolute 4GB constant it
      # was: 4GB is half of an 8GB machine and 6% of a 64GB one, so as a
      # constant it could only ever be right on one size of host.  Compared,
      # crucially, against correctly-measured AVAILABLE memory - against the
      # old `Pages free` it fired on every poll on every host, which is the
      # unattributable kill this ticket names.
      sc_free_floor_gb=${SCOURSH_SHELLCHECK_FREE_FLOOR_GB:-$sc_reserve_gb}
      if [[ ! $sc_free_floor_gb =~ ^[0-9]+$ ]] || (( sc_free_floor_gb < 1 )); then
        sc_free_floor_gb=$sc_reserve_gb
      fi

      sc_cores=$(_sc_detect_cores)

      printf 'shellcheck: %s files; host %sGB total, %sGB available, %sGB reserved -> %sGB headroom, %s cores\n' \
        "$sc_total" "$sc_total_gb" "$sc_avail_gb" "$sc_reserve_gb" "$sc_headroom_gb" "$sc_cores"

      # No `trap ... EXIT` here either - see the CI branch's note above.
      sc_shard_dir=$(mktemp -d)

      sc_have_ps=0
      command -v ps >/dev/null 2>&1 && sc_have_ps=1

      sc_status=0
      # sc_watch_msgs / sc_skipped are initialised beside sc_unchecked above,
      # before the traps are armed, because _sc_verdict now reads all three
      # and an abort can reach it before this point.
      sc_shard_seq=0

      # _sc_run_pass BUDGET_GB JOBS RETRY_LABEL
      #
      # Runs every path in `sc_queue` at JOBS concurrency, allowing each
      # process BUDGET_GB before the watchdog takes it, and files each
      # outcome under the reason it actually had:
      #
      #   sc_findings      checked, and shellcheck had something to say
      #   sc_pass_over     exceeded THIS pass's budget - the file's own doing
      #   sc_pass_pressure killed because the HOST came under pressure while
      #                    this file was merely the largest thing running -
      #                    NOT the file's doing, so the caller retries it
      #   sc_unchecked     any other way of failing to produce a result
      #
      # Keeping `over` and `pressure` apart is acceptance criterion 3, and it
      # is the whole difference between an actionable message and the
      # unattributable kill this ticket was filed for: under the old stage
      # both arms ended up in one "killed by this stage's own watchdog"
      # bucket, so a reader could not tell "this file needs more memory than
      # it was given" from "something unrelated on this machine grew".
      _sc_run_pass() {
        local pass_budget_gb=$1 pass_jobs=$2 pass_label=$3
        local pass_budget_kb=$(( pass_budget_gb * 1024 * 1024 ))
        # TEST SEAM.  The real budgets are whole GB and a stub `shellcheck`
        # uses a few MB, so the OVER-BUDGET arm below is unreachable from a
        # test without a finer-grained knob - and an arm no test can reach is
        # how the two kill causes stayed indistinguishable for as long as they
        # did.  Never set by a real run.
        if [[ ${SCOURSH_SHELLCHECK_BUDGET_KB:-} =~ ^[0-9]+$ ]]; then
          pass_budget_kb=$SCOURSH_SHELLCHECK_BUDGET_KB
        fi
        local pass_total=${#sc_queue[@]} pass_next=0
        local pid f shard idx rss_kb biggest_pid biggest_rss rpid pid_exit now_gb

        declare -A pass_pid_file=()
        declare -A pass_active=()
        declare -A pass_running=()
        declare -A pass_over_kill=()
        declare -A pass_pressure_kill=()

        sc_pass_over=()
        sc_pass_pressure=()

        (( pass_total == 0 )) && return 0

        _sc_launch_one() {
          f=${sc_queue[pass_next]}
          idx=$(printf '%05d' "$sc_shard_seq")
          shard=$(mktemp "$sc_shard_dir/shard-${idx}-XXXXXX")
          shellcheck -x -s bash -- "$f" >"$shard" 2>&1 &
          pid=$!
          pass_pid_file[$pid]=$f
          pass_active[$pid]=1
          pass_next=$(( pass_next + 1 ))
          sc_shard_seq=$(( sc_shard_seq + 1 ))
        }

        while (( pass_next < pass_total )) && (( ${#pass_active[@]} < pass_jobs )); do
          _sc_launch_one
        done

        # No `wait -n` here: it needs bash >= 4.3 and this project's frozen
        # minimum is 4.2 (AGENTS.md).  `jobs -p -r` (a plain bash builtin,
        # well inside that minimum) lists still-running background PIDs
        # instead, and a completed-but-unreaped pid drops out of it even
        # before `wait` collects its exit status.
        while (( ${#pass_active[@]} > 0 )); do
          sleep 0.4

          if (( sc_have_ps )); then
            biggest_pid=
            biggest_rss=0
            for pid in "${!pass_active[@]}"; do
              kill -0 "$pid" 2>/dev/null || continue
              # `|| rss_kb=` is NOT belt-and-braces, it is the fix for the
              # "prints nothing at all" face of this ticket.  A bare
              # `rss_kb=$(ps ...)` is a simple assignment whose exit status is
              # the command substitution's, so when `ps` exits 1 the
              # assignment exits 1 and `set -e` tears the whole stage down -
              # past the watchdog roll-up, past the verdict, leaving a log
              # that ends at the header.
              #
              # It is a RACE, which is why it never showed in this suite: the
              # `kill -0` above proves the process was alive a few
              # microseconds ago, not that it is alive now, and a shellcheck
              # that finishes in that window makes `ps` fail.  Six stub files
              # never lose that race; 130 real ones lose it almost every run.
              # Reproduced on this tree before the fix - 9 of 130 files
              # unmeasured and the stage ending on "an unexpected non-zero
              # exit before it could reach a verdict", with none of the 9
              # watchdog messages that would have explained them ever
              # printed.  Section K drives the race directly.
              rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null) || rss_kb=
              rss_kb=${rss_kb//[!0-9]/}
              [[ $rss_kb =~ ^[0-9]+$ ]] || continue
              if (( rss_kb > biggest_rss )); then
                biggest_rss=$rss_kb
                biggest_pid=$pid
              fi
              if (( rss_kb > pass_budget_kb )); then
                kill -TERM "$pid" 2>/dev/null || true
                sleep 0.2
                kill -KILL "$pid" 2>/dev/null || true
                pass_over_kill[$pid]=$(( rss_kb / 1024 / 1024 ))
                # Spelled as an `if`, not `[[ ... ]] && biggest_pid=`.  The
                # ticket that rewrote this stage carried a hypothesis that
                # the `&&` spelling aborted the script under `set -e` when
                # the test was false, which would explain a stage that
                # printed only its header.  MEASURED, and REFUTED: bash
                # exempts a whole `A && B` list from `set -e` when A itself
                # fails, at top level and inside a loop or an `if` body
                # alike, so it never fired.  The `if` stays because it is
                # clearer, not because it fixes anything.
                if [[ $biggest_pid == "$pid" ]]; then biggest_pid=; fi
              fi
            done

            # Second, independent layer: even when every process is within
            # its own budget, several together can still starve the host if
            # something ELSE on the machine grew after the plan was made.
            # Kill only the single biggest offender, not everything, so a
            # transient dip does not take out a whole pass - and record it
            # as PRESSURE, so the caller retries it rather than blaming it.
            if [[ -n $biggest_pid ]]; then
              now_gb=$(_sc_mem_avail_gb) || now_gb=
              if [[ $now_gb =~ ^[0-9]+$ ]] && (( now_gb < sc_free_floor_gb )); then
                kill -TERM "$biggest_pid" 2>/dev/null || true
                sleep 0.2
                kill -KILL "$biggest_pid" 2>/dev/null || true
                pass_pressure_kill[$biggest_pid]=$now_gb
              fi
            fi
          fi

          pass_running=()
          while IFS= read -r rpid; do
            [[ -n $rpid ]] && pass_running[$rpid]=1
          done < <(jobs -p -r)

          for pid in "${!pass_active[@]}"; do
            if [[ -z ${pass_running[$pid]:-} ]]; then
              # `wait` on its own line is the LAST command in a simple list,
              # so under `set -e` a non-zero exit here (a real finding, or
              # the watchdog's kill above) would abort the whole stage
              # instead of being recorded and continuing to the next file.
              # Folding it into an `||` exempts it.
              pid_exit=0
              wait "$pid" 2>/dev/null || pid_exit=$?
              if (( pid_exit != 0 )); then
                # Exit 1 is the only status that means "this file WAS checked
                # and shellcheck has something to say about it".  Everything
                # else means the file was never actually checked, and those
                # outcomes are kept apart rather than merged into one
                # non-zero: shellcheck's own exit 2 is "could not process
                # this file", 126/127 are the shell's "could not run the
                # linter at all", and 128+n is "died from signal n" (bash
                # manual, "Exit Status").  Rounding any of them up to a clean
                # result is the single most expensive way for this stage to
                # be wrong, because an unmeasured file looks exactly like a
                # clean one in the output.
                if (( pid_exit == 1 )); then
                  sc_status=1
                  sc_findings+=("${pass_pid_file[$pid]}")
                elif [[ -n ${pass_over_kill[$pid]:-} ]]; then
                  sc_pass_over+=("${pass_pid_file[$pid]}")
                  sc_watch_msgs+=("shellcheck: OVER BUDGET - ${pass_pid_file[$pid]} reached ~${pass_over_kill[$pid]}GB resident, past the ${pass_budget_gb}GB allowed in the $pass_label pass, and was killed.  Cause: this one file, not host memory pressure.")
                elif [[ -n ${pass_pressure_kill[$pid]:-} ]]; then
                  sc_pass_pressure+=("${pass_pid_file[$pid]}")
                  sc_watch_msgs+=("shellcheck: HOST MEMORY PRESSURE - available memory fell to ${pass_pressure_kill[$pid]}GB, under the ${sc_free_floor_gb}GB floor, while ${pass_pid_file[$pid]} was the largest process running.  It was killed as the biggest offender; its own RSS was within the ${pass_budget_gb}GB budget, so this is the host's doing and not this file's.")
                elif (( pid_exit > 128 )); then
                  sc_status=1
                  sc_unchecked+=("${pass_pid_file[$pid]} (died from signal $(( pid_exit - 128 )), not this stage's doing)")
                  sc_watch_msgs+=("shellcheck: ${pass_pid_file[$pid]} was killed (signal $(( pid_exit - 128 ))) by something other than this stage's own watchdog - not a shellcheck finding, but the stage still fails since that file was never actually checked")
                else
                  sc_status=1
                  sc_unchecked+=("${pass_pid_file[$pid]} (shellcheck exited $pid_exit - it never produced a result for this file)")
                fi
              fi
              unset "pass_active[$pid]"
              if (( pass_next < pass_total )); then
                _sc_launch_one
              fi
            fi
          done
        done
        return 0
      }

      # --- pass 1: the whole tree, planned against a typical footprint ------
      sc_pass1_budget_gb=$sc_step_gb
      (( sc_pass1_budget_gb > sc_headroom_gb )) && sc_pass1_budget_gb=$sc_headroom_gb
      sc_pass1_jobs=$(( sc_headroom_gb / sc_pass1_budget_gb ))
      (( sc_pass1_jobs < 1 )) && sc_pass1_jobs=1
      (( sc_pass1_jobs > sc_cores )) && sc_pass1_jobs=$sc_cores
      (( sc_pass1_jobs > sc_total )) && sc_pass1_jobs=$sc_total

      printf 'shellcheck: pass 1 - %s file(s), %s parallel x %sGB = %sGB of %sGB headroom\n' \
        "$sc_total" "$sc_pass1_jobs" "$sc_pass1_budget_gb" \
        "$(( sc_pass1_jobs * sc_pass1_budget_gb ))" "$sc_headroom_gb"

      sc_queue=("${sc_file_list[@]}")
      _sc_run_pass "$sc_pass1_budget_gb" "$sc_pass1_jobs" "first"

      # --- pass 2: only what pass 1 could not fit, against the real ceiling -
      #
      # Both categories come back here.  An OVER-BUDGET file gets the full
      # runaway budget, which is what it needed all along.  A PRESSURE file
      # was never the problem, so it is simply re-run - that retry is what
      # turns the "19 of 128 files went unmeasured" face of this ticket into
      # zero unmeasured files, because a transient dip no longer costs a
      # file its result.
      sc_pass2_budget_gb=$sc_budget_gb
      (( sc_pass2_budget_gb > sc_headroom_gb )) && sc_pass2_budget_gb=$sc_headroom_gb
      sc_queue=("${sc_pass_over[@]+"${sc_pass_over[@]}"}" "${sc_pass_pressure[@]+"${sc_pass_pressure[@]}"}")

      if (( ${#sc_queue[@]} > 0 )); then
        if (( sc_pass2_budget_gb <= sc_pass1_budget_gb )); then
          # Nothing to gain: this host's headroom is already fully committed
          # to one process, so a second pass would run at the same ceiling
          # and be killed at the same point.  Say so, by name, rather than
          # burning the time and reporting the same kill twice.
          for sc_f in "${sc_queue[@]}"; do
            sc_skipped+=("$sc_f (needs more than the ${sc_pass1_budget_gb}GB this host's ${sc_headroom_gb}GB headroom can give one process)")
          done
          sc_queue=()
        else
          sc_pass2_jobs=$(( sc_headroom_gb / sc_pass2_budget_gb ))
          (( sc_pass2_jobs < 1 )) && sc_pass2_jobs=1
          (( sc_pass2_jobs > sc_cores )) && sc_pass2_jobs=$sc_cores
          (( sc_pass2_jobs > ${#sc_queue[@]} )) && sc_pass2_jobs=${#sc_queue[@]}

          # When pass 2 is serial anyway, the invariant is `1 * budget <=
          # headroom`, so the whole headroom is the largest budget that is
          # still safe - and every file here has ALREADY proven it needs more
          # than the nominal budget.  Leaving headroom unused at that point
          # buys nothing and costs a file its result: measured on this tree,
          # tests/suites/dast-methods.sh exceeded the 20GB nominal budget on a
          # host with 26GB of headroom, and was reported skipped with 6GB
          # sitting idle.
          #
          # This is also what stops the default going stale the way the
          # previous 12GB one did.  A fixed number chosen as a multiple of
          # today's worst case is a number that will be wrong again the next
          # time the tree grows - and being wrong in the LOW direction kills
          # legitimate files.  The nominal budget still decides the PLAN (how
          # many jobs), which is what it is good for; the final serial pass
          # then uses everything the invariant allows, so it tracks the host
          # instead of a stale constant.
          if (( sc_pass2_jobs == 1 )) && (( sc_headroom_gb > sc_pass2_budget_gb )); then
            sc_pass2_budget_gb=$sc_headroom_gb
          fi

          printf 'shellcheck: pass 2 - %s file(s) pass 1 could not fit, %s parallel x %sGB = %sGB of %sGB headroom\n' \
            "${#sc_queue[@]}" "$sc_pass2_jobs" "$sc_pass2_budget_gb" \
            "$(( sc_pass2_jobs * sc_pass2_budget_gb ))" "$sc_headroom_gb"

          _sc_run_pass "$sc_pass2_budget_gb" "$sc_pass2_jobs" "second"

          # Whatever pass 2 still could not fit genuinely does not fit on
          # this host.  That is a host capability limit, reported by name
          # with its reason - never a silent omission, and never rounded up
          # to a clean result.
          for sc_f in "${sc_pass_over[@]+"${sc_pass_over[@]}"}"; do
            sc_skipped+=("$sc_f (needs more than ${sc_pass2_budget_gb}GB, the most this host's ${sc_headroom_gb}GB headroom allows one process)")
          done
          # A file killed for host pressure TWICE has had its retry.  That is
          # a real failure of this stage to measure it, not a host size
          # limit, so it fails rather than being filed as a clean skip.
          for sc_f in "${sc_pass_pressure[@]+"${sc_pass_pressure[@]}"}"; do
            sc_status=1
            sc_unchecked+=("$sc_f (killed for host memory pressure in both passes - its retry did not help; something else on this machine is competing for memory)")
          done
        fi
      fi

      for sc_shard in "$sc_shard_dir"/shard-*; do
        if [[ -e $sc_shard ]]; then
          cat -- "$sc_shard"
        fi
      done

      rm -rf "$sc_shard_dir"
      sc_shard_dir=
      unset -f _sc_launch_one _sc_run_pass
    fi

    # A file that could not be checked fails the stage on its own, even when
    # nothing that DID get checked reported anything.
    if (( ${#sc_unchecked[@]} > 0 )); then
      sc_status=1
    fi
    _sc_verdict "$sc_status"
    trap - EXIT INT TERM
    SC_STAGE_STATUS=$sc_status
    SC_STAGE_SKIPPED=${#sc_skipped[@]}
    return 0
  else
    printf '\n=== linter: shellcheck (SKIPPED - not installed) ===\n'
    SC_STAGE_SKIPPED=0
    SC_STAGE_NOT_INSTALLED=1
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
# `all green` is the LAST line anyone reads, so anything that makes this run
# less than complete has to be on it.  A run that skipped files this host
# could not check, or that never had `shellcheck` to run at all, is a real
# pass of everything it did do and is not the same fact as a full pass -
# leaving the bare line to stand for both is the false green this stage was
# filed for, one level up.
if (( SC_STAGE_NOT_INSTALLED )); then
  printf 'all green (shellcheck is not installed on this host, so the whole-tree stage did not run)\n'
elif (( SC_STAGE_SKIPPED > 0 )); then
  printf 'all green (NOT a full pass: the shellcheck stage skipped %s file(s) this host lacks the memory to check - named above)\n' \
    "$SC_STAGE_SKIPPED"
else
  printf 'all green\n'
fi
