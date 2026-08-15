#!/usr/bin/env bash
# tools/daily-suite.sh - run scoursh's whole test suite on the operator's own
# machine, once a day, and leave a durable dated result behind.
#
# Owns:
#   docs/CI-RUNBOOK.md          (what runs, how to schedule it, how to read it)
#   docs/FOUNDATION.md tension 24 ("one capability layer" - the GNU/BSD
#                                  cross-userland guarantee this script is now
#                                  the only thing checking)
#
# WHY THIS EXISTS.  scoursh used to run `tests/run-tests.sh` on GitHub Actions,
# on an ubuntu-latest (GNU) leg and a macos-latest (BSD) leg, and diff the two
# legs' findings byte-for-byte.  GitHub Actions has been switched off for this
# repository entirely, so there is no hosted CI and there is no pull-request
# status check any more.  This script is the replacement, and the difference
# that matters is that NOTHING ELSE WILL TELL YOU when it fails: there is no red
# tick on a PR.  Every design decision below follows from that.
#
#   * The result is durable and dated.  A daily check whose output scrolls past
#     in a terminal nobody was watching is not a check.
#   * "The run did not happen" is a DISTINCT, non-green outcome from "the run
#     happened and passed" (`--status`).  A silent absence must never read as
#     success, which is the failure mode a cron job that quietly stopped firing
#     produces, and the one a green-by-default status file would hide.
#   * A partial run is not a pass.  If the GNU leg cannot run, the verdict is
#     PASS-PARTIAL and the exit status is 5 (SCOURSH_EXIT_INCOMPLETE), because
#     tension 24's guarantee genuinely was not checked on that run.
#
# THE USERLAND TRAP THIS SCRIPT EXISTS TO AVOID.  On a developer's interactive
# PATH, `grep` on this class of machine can resolve to ugrep and `find` to bfs -
# neither of which is BSD, and neither of which exists on any real macOS target.
# The suite would go GREEN while testing the wrong tools, silently destroying
# the only reason a BSD leg exists.  docs/FOUNDATION.md tension 24 is a register
# of shell facts that genuinely differ between GNU and BSD, every one of them
# found by RUNNING the command rather than by reasoning about it, and AGENTS.md
# cites measured behaviour of BSD grep 2.6.0-FreeBSD specifically - the grep at
# /usr/bin/grep.  So this script pins the system paths ahead of everything else
# and then PROVES the userland is BSD (`--check-userland`), aborting with a
# clear message rather than producing a result that tested the wrong tools.
#
# NOT A SCAN-TIME SCRIPT.  Nothing under lib/, modules/, or scan.sh sources or
# execs this file; an operator (or launchd on the operator's behalf) runs it,
# the same way tools/dast-test-target.sh and tools/vendor-engines.sh are run by
# hand and never during a scan.  `docker` here drives the operator's own daemon
# to get a Linux userland; it is not a network call config/scope.conf's gate has
# any business mediating (tension 19 authorizes scan TARGETS), which is the same
# boundary tools/dast-test-target.sh's own header draws.
#
# shellcheck shell=bash
#
# SC2016: the single-quoted `${BASH_VERSINFO[...]}` and `$BASH_VERSION` strings
# are deliberately not expanded HERE - they are the program text handed to a
# DIFFERENT bash via `-c`, which is the whole point of asking that bash what
# version it is.  Expanding them in this shell would report this shell's
# version for every candidate.
# shellcheck disable=SC2016

# ---------------------------------------------------------------------------
# 0. Bash floor, before anything else.
#
# /bin/bash on macOS is 3.2.57, below this project's frozen 4.2 minimum (no
# associative arrays).  Under launchd the PATH is minimal, so `#!/usr/bin/env
# bash` genuinely does land on 3.2 there.  Running the rest of this file - or
# tests/run-tests.sh - under 3.2 produces a scatter of confusing syntax errors
# instead of one clear message, so a modern bash is resolved explicitly and
# re-exec'd into.  Everything in this block must itself be 3.2-compatible.
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'tools/daily-suite.sh: must be run with bash, not sh\n' >&2
  exit 4
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
  { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
  if [ "${SCOURSH_DAILY_REEXEC:-0}" = 1 ]; then
    printf 'tools/daily-suite.sh: re-exec landed on bash %s, still below the frozen 4.2 minimum\n' \
      "$BASH_VERSION" >&2
    exit 4
  fi
  # SCOURSH_BASH is authoritative here too: if it is set and too old, that is an
  # error to report, never a reason to quietly pick a different interpreter.
  # ds_resolve_bash() below applies the same rule to the bash the SUITE runs
  # under; this block is only about the one this FILE runs under.
  _ds_modern=''
  for _ds_c in "${SCOURSH_BASH:-}" /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do
    [ -n "$_ds_c" ] || continue
    [ -x "$_ds_c" ] || continue
    _ds_v=$("$_ds_c" -c 'printf "%s.%s" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"' 2>/dev/null) || continue
    case $_ds_v in
      [5-9].* | [1-9][0-9].* | 4.[2-9] | 4.[1-9][0-9]) _ds_modern=$_ds_c; break ;;
    esac
    if [ -n "${SCOURSH_BASH:-}" ] && [ "$_ds_c" = "${SCOURSH_BASH:-}" ]; then
      printf 'tools/daily-suite.sh: SCOURSH_BASH=%s is bash %s, below the frozen 4.2 minimum\n' \
        "$_ds_c" "$_ds_v" >&2
      exit 4
    fi
  done
  if [ -z "$_ds_modern" ]; then
    printf 'tools/daily-suite.sh: this is bash %s, below scoursh'"'"'s frozen 4.2 minimum,\n' "$BASH_VERSION" >&2
    printf '  and no bash >= 4.2 was found at $SCOURSH_BASH, /opt/homebrew/bin/bash or /usr/local/bin/bash.\n' >&2
    printf '  Install one (on macOS: brew install bash) or export SCOURSH_BASH=/path/to/bash.\n' >&2
    exit 4
  fi
  SCOURSH_DAILY_REEXEC=1
  export SCOURSH_DAILY_REEXEC
  exec "$_ds_modern" "$0" "$@"
fi

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# 1. Pin the system userland BEFORE anything reads PATH.
#
# lib/core.sh binds its pattern engine at source time, so the pin has to happen
# above the `source` below or core.sh itself could bind a ugrep that this
# script is about to reject.  SCOURSH_SYSTEM_PATH is a real operator knob (a
# macOS layout that keeps its system tools elsewhere would set it) and it is
# also the injection point tests/suites/daily-suite.sh uses to prove the
# userland assertion actually bites - the same swappable-hook idiom
# lib/http.sh's SCOURSH_HTTP_RESOLVE and lib/paranoid.sh's
# SCOURSH_PARANOID_FORCE_BACKEND already use.
# ---------------------------------------------------------------------------
SCOURSH_SYSTEM_PATH=${SCOURSH_SYSTEM_PATH:-/usr/bin:/bin:/usr/sbin:/sbin}
PATH=$SCOURSH_SYSTEM_PATH:$PATH
export PATH SCOURSH_SYSTEM_PATH

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"

readonly DS_LAUNCHD_LABEL='sh.scoursh.daily-suite'
readonly DS_STATUS_SCHEMA=1

# Where results live.  $HOME is resolved at runtime, never baked in: this file
# ships to any operator on any machine (docs/DESIGN.md §1).
if [[ $(uname -s) == Darwin ]]; then
  DS_DEFAULT_DIR=$HOME/Library/Logs/scoursh
else
  DS_DEFAULT_DIR=$HOME/.local/state/scoursh
fi
DS_RESULTS_DIR=${SCOURSH_DAILY_DIR:-$DS_DEFAULT_DIR}

# How old the latest result may be before `--status` calls it STALE.  A daily
# schedule plus a comfortable margin for a long run and a laptop that was asleep.
DS_MAX_AGE_HOURS=${SCOURSH_DAILY_MAX_AGE_HOURS:-36}

DS_GNU_MODE=auto
DS_NOTIFY=1
DS_LAUNCHD_HOUR=3
DS_LAUNCHD_MINUTE=30

# Run state, kept as globals so the EXIT trap can finalise a run that was
# killed halfway through.
DS_RUN_STARTED=0
DS_RUN_DIR=''
DS_STAMP=''
DS_STARTED_ISO=''
DS_STARTED_EPOCH=0
DS_BSD_RESULT=PENDING
DS_BSD_NOTE=''
DS_GNU_RESULT=PENDING
DS_GNU_NOTE=''
DS_COMPARE_RESULT=PENDING
DS_COMPARE_NOTE=''
DS_USERLAND=''
DS_BASH_BIN=''
DS_COMMIT=''

ds_usage() {
  cat <<EOF
tools/daily-suite.sh - run the whole scoursh suite locally and record the result.

  tools/daily-suite.sh [--gnu auto|require|off] [--results-dir DIR] [--no-notify]
        Run every suite and linter, serially, on the BSD userland, and (by
        default, if docker is usable) again inside a Linux container for the
        GNU userland; diff the two legs' findings; write a dated result.

  tools/daily-suite.sh --status [--max-age-hours N]
        Report the latest result.  Exits 0 only for a fresh PASS.  A missing,
        stale, or unfinished result is reported as such and never as a pass.

  tools/daily-suite.sh --check-userland
        Assert this machine's userland really is BSD, and print what it found.

  tools/daily-suite.sh --print-launchd [--hour H] [--minute M]
        Print a user LaunchAgent plist for the daily schedule, on stdout.
        Installing it is a documented operator step - see docs/CI-RUNBOOK.md.

  tools/daily-suite.sh --help

Exit status (docs/FOUNDATION.md tension 14 - nothing outside 0-5):
  0  everything asked for ran and passed
  1  a suite, a linter, or the cross-userland comparison failed
  2  usage error
  4  the environment is unusable (not BSD, no bash >= 4.2, no repository)
  5  the run did not cover everything it was asked to (a leg was skipped, or
     the run was interrupted); also --status for a missing/stale/unfinished
     result

Environment:
  SCOURSH_DAILY_DIR            results directory (default $DS_DEFAULT_DIR)
  SCOURSH_DAILY_MAX_AGE_HOURS  --status staleness threshold (default 36)
  SCOURSH_SYSTEM_PATH          the system userland to pin ahead of PATH
                               (default /usr/bin:/bin:/usr/sbin:/sbin)
  SCOURSH_BASH                 an explicit bash >= 4.2 to run the suite with
  SCOURSH_DAILY_GNU_IMAGE      docker image tag for the GNU leg (default is
                               derived from the shipped dockerfile's digest)
EOF
}

# ---------------------------------------------------------------------------
# 2. The userland assertion.
# ---------------------------------------------------------------------------

# Prints the first line a tool answers `--version` with, or its usage error.
# This is a VERSION INTERROGATION, not a pattern match: every real match in this
# repository goes through lib/core.sh's scan_match (tension 4 rule 2).  The
# binary is invoked through a variable so the command position never reads
# `grep`, which is both what tests/lint-shell.sh forbids and what would
# misdescribe what is happening here.
ds_tool_version() {
  local bin=$1 out
  out=$( { "$bin" --version 2>&1 || true; } | head -n 1)
  printf '%s' "$out"
}

# True when BIN sits directly in one of the colon-separated directories in the
# pinned system path.
ds_in_system_path() {
  local dir=${1%/*} entry
  local -a entries=()
  IFS=: read -r -a entries <<<"$SCOURSH_SYSTEM_PATH"
  for entry in "${entries[@]+"${entries[@]}"}"; do
    [[ -n $entry ]] || continue
    if [[ ${entry%/} == "$dir" ]]; then return 0; fi
  done
  return 1
}

# Aborts (exit 4) unless the userland on PATH really is BSD.  Sets DS_USERLAND.
ds_assert_bsd_userland() {
  local sys tool bin ver

  sys=$(uname -s)
  if [[ $sys != Darwin ]]; then
    die "$SCOURSH_EXIT_INPUT" \
      "this machine reports uname -s = '$sys'; the BSD leg only means anything on Darwin (macOS)"
  fi

  # Every core tool must come from the pinned system path.  A tool resolving
  # anywhere else means the pin did not take, or the pinned directories do not
  # actually hold that tool - either way the answer this run produces would be
  # about some other userland.
  for tool in grep find sed awk; do
    bin=$(command -v "$tool") ||
      die "$SCOURSH_EXIT_INPUT" "'$tool' is not on PATH at all (PATH=$PATH)"
    if ! ds_in_system_path "$bin"; then
      die "$SCOURSH_EXIT_INPUT" \
        "'$tool' resolves to $bin, which is outside the pinned system path ($SCOURSH_SYSTEM_PATH). A GNU or drop-in replacement has shadowed the system tool; the suite would test the wrong userland."
    fi
  done

  # The version string, which is what tells a BSD tool from a drop-in that
  # merely lives in the right place.
  bin=$(command -v grep)
  ver=$(ds_tool_version "$bin")
  case $ver in
    *'GNU grep'*)
      die "$SCOURSH_EXIT_INPUT" \
        "grep at $bin reports '$ver' - that is GNU grep, not BSD grep. AGENTS.md's measured shell facts are BSD grep 2.6.0-FreeBSD's; a GNU grep here makes this leg test a userland scoursh does not ship on."
      ;;
  esac
  case $ver in
    *'BSD grep'*) : ;;
    *)
      die "$SCOURSH_EXIT_INPUT" \
        "grep at $bin reports '$ver', which is not BSD grep. ugrep, ripgrep and GNU grep have all shadowed the system grep on this class of machine; the suite would go green while testing the wrong tools."
      ;;
  esac
  DS_USERLAND=$ver

  # BSD find and BSD sed have no --version and answer with a usage error, so a
  # tool that answers one is not the BSD tool.  bfs is the drop-in that has
  # actually turned up here.
  bin=$(command -v find)
  case $(ds_tool_version "$bin") in
    *GNU* | *bfs*)
      die "$SCOURSH_EXIT_INPUT" \
        "find at $bin answers --version, so it is GNU findutils or bfs, not BSD find"
      ;;
  esac
  bin=$(command -v sed)
  case $(ds_tool_version "$bin") in
    *GNU*)
      die "$SCOURSH_EXIT_INPUT" "sed at $bin reports GNU sed, not BSD sed"
      ;;
  esac
}

ds_report_userland() {
  local tool bin
  printf 'userland (pinned system path: %s)\n' "$SCOURSH_SYSTEM_PATH"
  printf '  uname   : %s %s\n' "$(uname -s)" "$(uname -m)"
  for tool in grep find sed awk; do
    bin=$(command -v "$tool" || printf 'ABSENT')
    printf '  %-7s : %-16s %s\n' "$tool" "$bin" "$(ds_tool_version "$bin")"
  done
  printf '  bash    : %s %s\n' "$DS_BASH_BIN" "$("$DS_BASH_BIN" -c 'printf %s "$BASH_VERSION"')"
  # The bash a bare `bash` lands on matters as much as the resolved one:
  # tests/run-tests.sh spawns every suite that way.  See ds_shim_bash.
  printf '  bash on PATH : %s %s\n' \
    "$(command -v bash)" "$(bash -c 'printf %s "$BASH_VERSION"')"
}

# ---------------------------------------------------------------------------
# 3. Resolving the bash the suite runs under.
# ---------------------------------------------------------------------------
ds_bash_is_modern() {
  local candidate=$1 ver maj min
  [[ -n $candidate && -x $candidate ]] || return 1
  ver=$("$candidate" -c 'printf "%s %s" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"' 2>/dev/null) || return 1
  maj=${ver% *}
  min=${ver#* }
  [[ $maj =~ ^[0-9]+$ && $min =~ ^[0-9]+$ ]] || return 1
  (( maj > 4 || (maj == 4 && min >= 2) ))
}

ds_resolve_bash() {
  local candidate

  # SCOURSH_BASH is AUTHORITATIVE, not merely first in a preference list.  An
  # operator who names a bash has usually done so because the default choice was
  # wrong on their machine; quietly falling back to a different one when theirs
  # turns out to be too old would run the suite under an interpreter nobody
  # asked for and report a result about it.
  if [[ -n ${SCOURSH_BASH:-} ]]; then
    if ds_bash_is_modern "$SCOURSH_BASH"; then
      DS_BASH_BIN=$SCOURSH_BASH
      return 0
    fi
    die "$SCOURSH_EXIT_INPUT" \
      "SCOURSH_BASH=$SCOURSH_BASH is not an executable bash >= 4.2 (this project's frozen minimum; macOS's own /bin/bash is 3.2.57 and has no associative arrays). Point it at a newer bash or unset it to let this script look for one."
  fi

  for candidate in "$BASH" /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if ds_bash_is_modern "$candidate"; then
      DS_BASH_BIN=$candidate
      return 0
    fi
  done
  die "$SCOURSH_EXIT_INPUT" \
    "no bash >= 4.2 found (macOS ships 3.2.57, which has no associative arrays). Install one (brew install bash) or export SCOURSH_BASH=/path/to/bash."
}

# Puts the resolved bash - and ONLY the resolved bash - ahead of the pinned
# system path.
#
# Pinning /usr/bin ahead of PATH is what stops ugrep and bfs shadowing the BSD
# tools, but it also pins /bin/bash, which is 3.2.57 on macOS.  tests/run-tests.sh
# launches every suite and linter as a bare `bash "$path"`, so without this every
# one of them dies with "bash >= 4.2 required" - measured, on the first real
# end-to-end run of this script, not reasoned about.
#
# A one-entry shim directory is the narrow fix.  Prepending the resolved bash's
# OWN directory instead would put /opt/homebrew/bin (or a Nix profile) back in
# front of /usr/bin and hand the grep shadow its win back, which is the bug this
# script exists to prevent.
#
# TWO THINGS HERE ARE LOAD-BEARING, both measured on a real run rather than
# reasoned about:
#
#   * The directory is per-PID.  lib/core.sh EXPORTS SCOURSH_SCRATCH so that
#     `xargs -P` workers share the parent's scratch directory, which means a
#     nested invocation of this script - and tests/suites/daily-suite.sh runs
#     several - inherits the SAME scratch directory as the run that spawned it.
#     With one fixed shim path, the nested run's `ln -sf` overwrote the outer
#     run's shim.
#   * The link target is dereferenced first.  A nested invocation's own $BASH IS
#     the outer shim, so linking to it unresolved pointed the shim at itself:
#     every suite and linter spawned afterwards died with "Too many levels of
#     symbolic links", from a run that had been perfectly healthy until the last
#     suite ran.
ds_deref() {
  local p=$1 target dir hops=0
  while [[ -L $p ]] && (( hops < 16 )); do
    target=$(readlink -- "$p") || break
    case $target in
      /*) p=$target ;;
      *)
        dir=${p%/*}
        p=$dir/$target
        ;;
    esac
    hops=$(( hops + 1 ))
  done
  printf '%s' "$p"
}

# Runs a command with this script's own run state cleared out of its
# environment.
#
# THIS IS NOT HYGIENE, IT IS CORRECTNESS.  lib/core.sh exports SCOURSH_SCRATCH
# (and, once a run is under way, SCOURSH_RUN_DIR/ID/TIMESTAMP), and this script
# sources lib/core.sh for `die` and the exit-code constants.  A suite launched
# without clearing them inherits a scratch directory it did NOT create, so
# `scratch_is_owned_here` is false inside it - and tests/suites/core.sh asserts
# the opposite, because a human running tests/run-tests.sh directly gets a
# process that owns its own scratch directory.  Measured: `core` failed exactly
# one assertion, "the creating process IS the owner", on a run where nothing was
# wrong with lib/core.sh at all.  The suite has to see the environment a person
# running it by hand would see, or it is testing this runner rather than scoursh.
ds_run_clean_env() {
  env -u SCOURSH_SCRATCH -u SCOURSH_SCRATCH_OWNER \
    -u SCOURSH_RUN_DIR -u SCOURSH_RUN_ID -u SCOURSH_RUN_TIMESTAMP \
    -u SCOURSH_WORKER_ID -u SCOURSH_SIGNALLED \
    "$@"
}

ds_shim_bash() {
  local shim=$SCOURSH_SCRATCH/bash-shim-$$ target
  target=$(ds_deref "$DS_BASH_BIN")
  mkdir -p "$shim"
  rm -f "$shim/bash"
  ln -s "$target" "$shim/bash"
  PATH=$shim:$PATH
  export PATH
}

# ---------------------------------------------------------------------------
# 4. The durable result.
#
# STATUS is one line, overwritten in place, and is the file `--status` reads.
# It is written with verdict=INCOMPLETE the moment a run starts, so a run that
# is killed, times out, or has its machine shut down leaves INCOMPLETE behind
# rather than the previous run's PASS.  That is the whole "a silent absence
# must never read as success" mechanism: there is no state in which a stale or
# unfinished run reports green.
# ---------------------------------------------------------------------------
ds_status_write() {
  local verdict=$1 finished_iso=$2 finished_epoch=$3
  local tmp=$DS_RESULTS_DIR/.STATUS.$$
  {
    printf 'schema=%s verdict=%s started=%s started_epoch=%s finished=%s finished_epoch=%s' \
      "$DS_STATUS_SCHEMA" "$verdict" "$DS_STARTED_ISO" "$DS_STARTED_EPOCH" \
      "$finished_iso" "$finished_epoch"
    printf ' bsd=%s gnu=%s compare=%s run=%s\n' \
      "$DS_BSD_RESULT" "$DS_GNU_RESULT" "$DS_COMPARE_RESULT" "$DS_RUN_DIR"
  } >"$tmp"
  mv -f "$tmp" "$DS_RESULTS_DIR/STATUS"
}

ds_summary_write() {
  local verdict=$1 finished_iso=$2
  local summary=$DS_RUN_DIR/summary.txt
  {
    printf 'scoursh daily suite\n'
    printf '===================\n\n'
    printf 'verdict     : %s\n' "$verdict"
    printf 'started     : %s\n' "$DS_STARTED_ISO"
    printf 'finished    : %s\n' "${finished_iso:-(did not finish)}"
    printf 'repository  : %s\n' "$ROOT"
    printf 'commit      : %s\n' "${DS_COMMIT:-unknown}"
    printf 'userland    : %s\n' "${DS_USERLAND:-not established}"
    printf 'bash        : %s\n' "${DS_BASH_BIN:-not resolved}"
    printf '\nlegs\n----\n'
    printf '  bsd     : %-8s %s\n' "$DS_BSD_RESULT" "$DS_BSD_NOTE"
    printf '  gnu     : %-8s %s\n' "$DS_GNU_RESULT" "$DS_GNU_NOTE"
    printf '  compare : %-8s %s\n' "$DS_COMPARE_RESULT" "$DS_COMPARE_NOTE"
    printf '\nchecks that ran\n---------------\n'
    if [[ -s $DS_RUN_DIR/checks.txt ]]; then
      cat "$DS_RUN_DIR/checks.txt"
    else
      printf '  (none recorded - the run did not get as far as running any)\n'
    fi
    if [[ $verdict != PASS ]]; then
      printf '\nfailure detail\n--------------\n'
      ds_failure_detail
    fi
    printf '\nfull logs: %s\n' "$DS_RUN_DIR"
  } >"$summary"
}

# The tail of whichever leg failed, so the summary alone is usually enough to
# tell what broke without opening the logs.
ds_failure_detail() {
  local leg log
  for leg in bsd gnu; do
    log=$DS_RUN_DIR/$leg-suite.log
    [[ -s $log ]] || continue
    case $leg in
      bsd) [[ $DS_BSD_RESULT == FAIL ]] || continue ;;
      gnu) [[ $DS_GNU_RESULT == FAIL ]] || continue ;;
    esac
    printf '  --- last 60 lines of %s-suite.log ---\n' "$leg"
    tail -n 60 "$log" | while IFS= read -r line; do printf '  %s\n' "$line"; done
  done
  if [[ $DS_COMPARE_RESULT == FAIL && -s $DS_RUN_DIR/compare.diff ]]; then
    printf '  --- cross-userland findings differ (compare.diff, first 60 lines) ---\n'
    head -n 60 "$DS_RUN_DIR/compare.diff" | while IFS= read -r line; do printf '  %s\n' "$line"; done
  fi
  if [[ -n $DS_BSD_NOTE$DS_GNU_NOTE$DS_COMPARE_NOTE ]]; then
    printf '  --- notes ---\n'
    if [[ -n $DS_BSD_NOTE ]]; then printf '  bsd     : %s\n' "$DS_BSD_NOTE"; fi
    if [[ -n $DS_GNU_NOTE ]]; then printf '  gnu     : %s\n' "$DS_GNU_NOTE"; fi
    if [[ -n $DS_COMPARE_NOTE ]]; then printf '  compare : %s\n' "$DS_COMPARE_NOTE"; fi
  fi
  return 0
}

# Best effort, and deliberately never able to change the outcome: a desktop
# notification is the difference between a failure the operator sees today and
# one they find next week, but a machine without osascript must still get a
# correct exit status and a correct result file.
ds_notify() {
  local verdict=$1
  (( DS_NOTIFY )) || return 0
  if [[ $verdict == PASS ]]; then return 0; fi
  command -v osascript >/dev/null 2>&1 || return 0
  osascript -e "display notification \"verdict: $verdict - see $DS_RESULTS_DIR/STATUS\" with title \"scoursh daily suite\"" \
    >/dev/null 2>&1 || true
  return 0
}

# Installed OVER lib/core.sh's own EXIT trap, and calls it, rather than
# replacing it: core_cleanup is what erases the scratch directory, and it is
# already guarded on scratch-dir ownership (tension 4 rule 5) so calling it
# from here is safe.
ds_on_exit() {
  local rc=$?
  if (( DS_RUN_STARTED )); then
    local verdict=INCOMPLETE finished_iso='' finished_epoch=0
    if [[ -n ${DS_VERDICT:-} ]]; then
      verdict=$DS_VERDICT
      finished_iso=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
      finished_epoch=$(date '+%s')
    else
      # Killed, or died before reaching the verdict.  Whatever leg was in
      # flight is not a pass.
      if [[ $DS_BSD_RESULT == PENDING ]]; then DS_BSD_RESULT=INTERRUPTED; fi
      if [[ $DS_GNU_RESULT == PENDING ]]; then DS_GNU_RESULT=INTERRUPTED; fi
      if [[ $DS_COMPARE_RESULT == PENDING ]]; then DS_COMPARE_RESULT=INTERRUPTED; fi
    fi
    ds_summary_write "$verdict" "$finished_iso" || true
    ds_status_write "$verdict" "$finished_iso" "$finished_epoch" || true
    ds_notify "$verdict" || true
  fi
  core_cleanup || true
  return "$rc"
}

# ---------------------------------------------------------------------------
# 5. Reading a result back (`--status`).
# ---------------------------------------------------------------------------
ds_status_field() {
  local line=$1 key=$2 rest
  case " $line " in
    *" $key="*)
      rest=${line#*"$key="}
      printf '%s' "${rest%% *}"
      ;;
  esac
}

ds_status_report() {
  local status=$DS_RESULTS_DIR/STATUS line verdict finished_epoch run age_h now

  if [[ ! -f $status ]]; then
    printf 'scoursh daily suite: NEVER RUN\n'
    printf '  no result file at %s\n' "$status"
    printf '  Either the schedule was never installed, or it has never fired.\n'
    printf '  Install it: see docs/CI-RUNBOOK.md ("Installing the daily schedule").\n'
    return "$SCOURSH_EXIT_INCOMPLETE"
  fi

  IFS= read -r line <"$status" || line=''
  verdict=$(ds_status_field "$line" verdict)
  finished_epoch=$(ds_status_field "$line" finished_epoch)
  run=$(ds_status_field "$line" run)
  [[ $finished_epoch =~ ^[0-9]+$ ]] || finished_epoch=0
  now=$(date '+%s')
  age_h=$(( (now - finished_epoch) / 3600 ))

  case $verdict in
    INCOMPLETE)
      printf 'scoursh daily suite: DID NOT FINISH\n'
      printf '  started %s and never reached a verdict - killed, timed out, or the machine slept.\n' \
        "$(ds_status_field "$line" started)"
      printf '  run: %s\n' "$run"
      return "$SCOURSH_EXIT_INCOMPLETE"
      ;;
    PASS | PASS-PARTIAL | FAIL) ;;
    *)
      printf 'scoursh daily suite: UNREADABLE RESULT\n'
      printf '  %s does not carry a verdict this version understands: %s\n' "$status" "$line"
      return "$SCOURSH_EXIT_INCOMPLETE"
      ;;
  esac

  if (( finished_epoch == 0 || age_h > DS_MAX_AGE_HOURS )); then
    printf 'scoursh daily suite: STALE (last verdict %s, %sh old, threshold %sh)\n' \
      "$verdict" "$age_h" "$DS_MAX_AGE_HOURS"
    printf '  A result older than the schedule means the schedule is not firing.\n'
    printf '  An old PASS is NOT a pass: nothing has checked this repository since then.\n'
    printf '  run: %s\n' "$run"
    return "$SCOURSH_EXIT_INCOMPLETE"
  fi

  printf 'scoursh daily suite: %s (%sh old)\n' "$verdict" "$age_h"
  printf '  %s\n' "$line"
  if [[ -s $run/summary.txt ]]; then
    printf '  summary: %s/summary.txt\n' "$run"
  fi
  case $verdict in
    PASS) return "$SCOURSH_EXIT_OK" ;;
    PASS-PARTIAL) return "$SCOURSH_EXIT_INCOMPLETE" ;;
    *) return "$SCOURSH_EXIT_GATE" ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. The launchd agent.
#
# Printed rather than installed: the plist has to carry THIS checkout's path
# and THIS machine's bash, and a shipped file may not carry either
# (docs/DESIGN.md §1).  Generating it at install time from the operator's real
# checkout is what keeps the repository target-agnostic.
# ---------------------------------------------------------------------------
ds_xml_escape() {
  local s=$1
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "$s"
}

ds_print_launchd() {
  ds_resolve_bash
  local out=$DS_RESULTS_DIR
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$DS_LAUNCHD_LABEL</string>

  <!-- The bash and the checkout are resolved from the machine this was
       generated on.  Regenerate the plist if either moves. -->
  <key>ProgramArguments</key>
  <array>
    <string>$(ds_xml_escape "$DS_BASH_BIN")</string>
    <string>$(ds_xml_escape "$ROOT/tools/daily-suite.sh")</string>
  </array>

  <key>WorkingDirectory</key>
  <string>$(ds_xml_escape "$ROOT")</string>

  <!-- launchd starts with a minimal PATH.  The system userland comes first for
       the same reason the script pins it (BSD grep, not ugrep); the Homebrew
       and /usr/local directories follow so bash, shellcheck and docker are
       reachable. -->
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>$(ds_xml_escape "$SCOURSH_SYSTEM_PATH"):/opt/homebrew/bin:/usr/local/bin</string>
    <key>SCOURSH_DAILY_DIR</key>
    <string>$(ds_xml_escape "$out")</string>
  </dict>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$DS_LAUNCHD_HOUR</integer>
    <key>Minute</key><integer>$DS_LAUNCHD_MINUTE</integer>
  </dict>

  <!-- Deliberately false: loading the agent must not kick off a full suite run
       on the spot.  A missed daily slot is picked up at the next one, and
       \`--status\` is what makes a missed run visible. -->
  <key>RunAtLoad</key>
  <false/>

  <key>StandardOutPath</key>
  <string>$(ds_xml_escape "$out/launchd.out.log")</string>
  <key>StandardErrorPath</key>
  <string>$(ds_xml_escape "$out/launchd.err.log")</string>

  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
EOF
}

# ---------------------------------------------------------------------------
# 7. The two legs.
# ---------------------------------------------------------------------------

# Records `name<TAB>status` for every suite/linter the log shows running, and
# prints the space-separated names of the ones that failed.  Parsed with bash
# pattern matching rather than a pipeline, so the "no bare grep" rule
# (tension 4 rule 2) is honoured by not needing an exception.
ds_record_checks() {
  local leg=$1 log=$2 line name failed=''
  [[ -s $log ]] || return 0
  while IFS= read -r line; do
    case $line in
      '--- '*' passed')
        name=${line#--- }
        name=${name% passed}
        printf '  %-28s %-6s %s\n' "$name" PASS "$leg" >>"$DS_RUN_DIR/checks.txt"
        ;;
      '--- '*' FAILED')
        name=${line#--- }
        name=${name% FAILED}
        printf '  %-28s %-6s %s\n' "$name" FAIL "$leg" >>"$DS_RUN_DIR/checks.txt"
        failed+="${failed:+ }$name"
        ;;
    esac
  done <"$log"
  printf '%s' "$failed"
}

ds_run_bsd_leg() {
  local log=$DS_RUN_DIR/bsd-suite.log rc=0 failed

  printf '\n== BSD leg: %s ==\n' "$DS_USERLAND"
  # tests/run-tests.sh already runs every suite and linter SERIALLY, one process
  # each.  Do not fan these out: parallel batches starve each other on a single
  # workstation, which is measured, not theoretical.
  ds_run_clean_env "$DS_BASH_BIN" "$ROOT/tests/run-tests.sh" 2>&1 | tee "$log" || rc=$?
  failed=$(ds_record_checks bsd "$log")

  if (( rc == 0 )); then
    DS_BSD_RESULT=PASS
  else
    DS_BSD_RESULT=FAIL
    DS_BSD_NOTE="tests/run-tests.sh exited $rc${failed:+ (failed: $failed)}"
    return 0
  fi

  # The fixture scan, normalised, for the cross-userland comparison.
  local fixture=$DS_RUN_DIR/bsd-fixture-run
  rm -rf "$fixture"
  if ! ds_run_clean_env "$DS_BASH_BIN" "$ROOT/tests/e2e/fixture-scan.sh" "$fixture" \
    >"$DS_RUN_DIR/bsd-fixture.log" 2>&1; then
    DS_BSD_RESULT=FAIL
    DS_BSD_NOTE='the suite passed but tests/e2e/fixture-scan.sh failed'
    return 0
  fi
  ds_normalise_findings "$fixture/findings.jsonl" "$DS_RUN_DIR/bsd-findings.jsonl"
  return 0
}

# The run timestamp is the only value that legitimately differs between two
# runs of the fixture scan; everything else must be byte-identical across
# userlands, which is what the comparison below asserts.
ds_normalise_findings() {
  local src=$1 dst=$2
  sed -e 's/"first_seen":"[^"]*"/"first_seen":"T"/g' \
    -e 's/"last_seen":"[^"]*"/"last_seen":"T"/g' \
    -- "$src" >"$dst"
}

ds_gnu_image_tag() {
  local digest
  if [[ -n ${SCOURSH_DAILY_GNU_IMAGE:-} ]]; then
    printf '%s' "$SCOURSH_DAILY_GNU_IMAGE"
    return 0
  fi
  # Tagging by the dockerfile's own digest makes "the image is absent" mean
  # exactly "this dockerfile has never been built here", so an edit to the
  # dockerfile rebuilds and an unchanged one never touches the network.
  # `cat |` rather than a `<` redirect, matching tools/vendor-engines.sh's own
  # call sites.  The digest helper reads stdin only (tension 9), and
  # tests/lint-shell.sh enforces that by refusing anything after its name that
  # could be an argument - a `<` redirect included, and this very comment if it
  # named the function with a word after it.
  # shellcheck disable=SC2002
  digest=$(cat -- "$ROOT/tools/daily-suite/gnu.dockerfile" | sha256_of)
  printf 'scoursh-daily-gnu:%s' "${digest:0:12}"
}

# The `-v` arguments needed so git works inside the container, or none when the
# checkout is an ordinary clone whose `.git` directory is already inside it.
ds_gnu_git_mount() {
  local common
  common=$(git -C "$ROOT" rev-parse --git-common-dir 2>/dev/null) || return 0
  [[ -n $common ]] || return 0
  case $common in
    /*) : ;;
    *) common=$ROOT/$common ;;
  esac
  [[ -d $common ]] || return 0
  # An ordinary clone keeps it under the checkout, which is already mounted.
  if [[ $common == "$ROOT"/* ]]; then return 0; fi
  # `--mount`, not `-v ...:ro`.  Measured on Docker Desktop for macOS: a bind
  # whose source and destination are the SAME absolute path is silently not
  # mounted when the `:ro` suffix form is used - the destination simply does not
  # exist inside the container, with no error from `docker run` - while the
  # identical read-only bind expressed as `--mount` works.  A silent no-mount
  # here would put the leg straight back to "git does not resolve", which is the
  # failure this function exists to prevent.
  printf -- '--mount\ntype=bind,src=%s,dst=%s,readonly\n' "$common" "$common"
}

ds_run_gnu_leg() {
  local mode=$DS_GNU_MODE image rc=0 log=$DS_RUN_DIR/gnu-suite.log failed
  local -a gitmount=()
  while IFS= read -r _m; do
    [[ -n $_m ]] && gitmount+=("$_m")
  done < <(ds_gnu_git_mount)

  if [[ $mode == off ]]; then
    DS_GNU_RESULT=SKIPPED
    DS_GNU_NOTE='--gnu off: the operator asked for the BSD leg only, so tension 24 was not checked this run'
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    if [[ $mode == require ]]; then
      die "$SCOURSH_EXIT_INPUT" \
        '--gnu require was given but docker is absent or its daemon is not reachable'
    fi
    DS_GNU_RESULT=SKIPPED
    DS_GNU_NOTE='docker is absent or its daemon is not running, so the GNU userland was not tested this run'
    return 0
  fi

  image=$(ds_gnu_image_tag)
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf '\n== GNU leg: building %s (first build for this dockerfile; needs network) ==\n' "$image"
    if ! docker build -t "$image" -f "$ROOT/tools/daily-suite/gnu.dockerfile" \
      "$ROOT/tools/daily-suite" >"$DS_RUN_DIR/gnu-build.log" 2>&1; then
      if [[ $mode == require ]]; then
        die "$SCOURSH_EXIT_INPUT" "--gnu require was given but the image build failed; see $DS_RUN_DIR/gnu-build.log"
      fi
      DS_GNU_RESULT=SKIPPED
      DS_GNU_NOTE="the GNU image could not be built (see gnu-build.log), so the GNU userland was not tested this run"
      return 0
    fi
  fi

  printf '\n== GNU leg: %s ==\n' "$image"
  # --user is what keeps the container from leaving root-owned files in the
  # operator's own checkout, which they could then not delete.  HOME is
  # redirected because that uid has no passwd entry inside the image.
  #
  # The checkout is mounted at its OWN absolute path rather than at some /w, and
  # so is the git directory when it lives elsewhere.  Both are measured
  # requirements, not tidiness:
  #
  #   * A `git worktree` checkout's `.git` is a FILE holding an absolute
  #     `gitdir:` path into the MAIN repository, which is outside the mount.
  #     Without it, `git rev-parse --show-toplevel` fails inside the container,
  #     lib/core.sh falls back to the resolved --path as the scan root, and
  #     every finding's repository-relative loc_path is computed from a
  #     different root than the BSD leg used.  Measured: `sast` and `iac` failed
  #     15 assertions comparing `check_id@loc_path` pairs, with nothing wrong in
  #     either rule pack.
  #   * The gitdir also records an absolute path BACK to the worktree, so the
  #     mount point has to match the host path for git to accept the pair.
  #     Mounting at the host path makes the two legs agree by construction
  #     instead of by coincidence, which is the whole point of comparing them.
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -v "$ROOT:$ROOT" \
    -v "$DS_RUN_DIR:$DS_RUN_DIR" \
    "${gitmount[@]+"${gitmount[@]}"}" \
    -w "$ROOT" \
    "$image" bash "$ROOT/tools/daily-suite/gnu-leg.sh" "$DS_RUN_DIR" 2>&1 | tee "$log" || rc=$?

  failed=$(ds_record_checks gnu "$log")
  if (( rc == 0 )); then
    DS_GNU_RESULT=PASS
  else
    DS_GNU_RESULT=FAIL
    DS_GNU_NOTE="the GNU leg exited $rc${failed:+ (failed: $failed)}"
  fi
  return 0
}

ds_compare_legs() {
  local bsd=$DS_RUN_DIR/bsd-findings.jsonl gnu=$DS_RUN_DIR/gnu-findings.jsonl

  if [[ $DS_BSD_RESULT != PASS || $DS_GNU_RESULT != PASS ]]; then
    DS_COMPARE_RESULT=SKIPPED
    DS_COMPARE_NOTE='both legs must pass before their findings can be compared'
    return 0
  fi
  if [[ ! -s $bsd || ! -s $gnu ]]; then
    DS_COMPARE_RESULT=SKIPPED
    DS_COMPARE_NOTE='one of the legs produced no normalised findings to compare'
    return 0
  fi
  # tension 24's actual requirement: not merely that the suite passes on both
  # userlands, but that they produce the same findings, fingerprints and bytes.
  if diff -u "$bsd" "$gnu" >"$DS_RUN_DIR/compare.diff" 2>&1; then
    DS_COMPARE_RESULT=PASS
    rm -f "$DS_RUN_DIR/compare.diff"
  else
    DS_COMPARE_RESULT=FAIL
    DS_COMPARE_NOTE='findings differ between the BSD and GNU userlands - see compare.diff'
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 8. The run.
# ---------------------------------------------------------------------------
ds_run() {
  local now

  [[ -f $ROOT/tests/run-tests.sh ]] ||
    die "$SCOURSH_EXIT_INPUT" "$ROOT does not look like a scoursh checkout (no tests/run-tests.sh)"

  mkdir -p "$DS_RESULTS_DIR/runs"
  DS_STARTED_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  DS_STARTED_EPOCH=$(date '+%s')
  DS_STAMP=${DS_STARTED_ISO//:/}
  DS_RUN_DIR=$DS_RESULTS_DIR/runs/$DS_STAMP
  mkdir -p "$DS_RUN_DIR"
  : >"$DS_RUN_DIR/checks.txt"

  # From here on an interrupted run leaves verdict=INCOMPLETE behind.
  DS_RUN_STARTED=1
  trap ds_on_exit EXIT
  ds_status_write INCOMPLETE '' 0

  ds_assert_bsd_userland
  ds_resolve_bash
  ds_shim_bash
  DS_COMMIT=$(git -C "$ROOT" describe --always --dirty 2>/dev/null || printf 'unknown')
  ds_report_userland | tee "$DS_RUN_DIR/userland.txt"

  ds_run_bsd_leg
  ds_run_gnu_leg
  ds_compare_legs

  if [[ $DS_BSD_RESULT == FAIL || $DS_GNU_RESULT == FAIL || $DS_COMPARE_RESULT == FAIL ]]; then
    DS_VERDICT=FAIL
  elif [[ $DS_GNU_RESULT == SKIPPED || $DS_COMPARE_RESULT == SKIPPED ]]; then
    DS_VERDICT=PASS-PARTIAL
  else
    DS_VERDICT=PASS
  fi

  now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  printf '\n'
  printf 'verdict: %s   bsd=%s gnu=%s compare=%s\n' \
    "$DS_VERDICT" "$DS_BSD_RESULT" "$DS_GNU_RESULT" "$DS_COMPARE_RESULT"
  printf 'result : %s/summary.txt\n' "$DS_RUN_DIR"
  printf 'status : %s/STATUS\n' "$DS_RESULTS_DIR"
  printf 'at     : %s\n' "$now"

  case $DS_VERDICT in
    PASS) return "$SCOURSH_EXIT_OK" ;;
    PASS-PARTIAL) return "$SCOURSH_EXIT_INCOMPLETE" ;;
    *) return "$SCOURSH_EXIT_GATE" ;;
  esac
}

# ---------------------------------------------------------------------------
# 9. Entry point.
# ---------------------------------------------------------------------------
ds_main() {
  local action=run

  while (( $# > 0 )); do
    case $1 in
      --help | -h)
        ds_usage
        return "$SCOURSH_EXIT_OK"
        ;;
      --status) action=status ;;
      --check-userland) action=check-userland ;;
      --print-launchd) action=print-launchd ;;
      --no-notify) DS_NOTIFY=0 ;;
      --gnu)
        shift || true
        case ${1:-} in
          auto | require | off) DS_GNU_MODE=$1 ;;
          *) die "$SCOURSH_EXIT_USAGE" "--gnu takes auto, require or off (got '${1:-}')" ;;
        esac
        ;;
      --results-dir)
        shift || true
        [[ -n ${1:-} ]] || die "$SCOURSH_EXIT_USAGE" '--results-dir needs a directory'
        DS_RESULTS_DIR=$1
        ;;
      --max-age-hours)
        shift || true
        [[ ${1:-} =~ ^[0-9]+$ ]] || die "$SCOURSH_EXIT_USAGE" '--max-age-hours needs a whole number'
        DS_MAX_AGE_HOURS=$1
        ;;
      --hour)
        shift || true
        [[ ${1:-} =~ ^([0-9]|1[0-9]|2[0-3])$ ]] || die "$SCOURSH_EXIT_USAGE" '--hour needs 0-23'
        DS_LAUNCHD_HOUR=$1
        ;;
      --minute)
        shift || true
        [[ ${1:-} =~ ^([0-9]|[1-5][0-9])$ ]] || die "$SCOURSH_EXIT_USAGE" '--minute needs 0-59'
        DS_LAUNCHD_MINUTE=$1
        ;;
      *) die "$SCOURSH_EXIT_USAGE" "unknown argument: '$1'" ;;
    esac
    shift || true
  done

  case $action in
    status) ds_status_report ;;
    check-userland)
      ds_assert_bsd_userland
      ds_resolve_bash
      ds_shim_bash
      ds_report_userland
      ;;
    print-launchd) ds_print_launchd ;;
    run) ds_run ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  # A non-zero exit here is a REPORTED OUTCOME, not an internal error: FAIL,
  # STALE and PASS-PARTIAL are all things this tool exists to say.  Letting them
  # reach lib/core.sh's ERR trap printed "error scoursh: command failed
  # (status 5) at ...daily-suite.sh:NNN" underneath a perfectly clear STALE
  # report, which reads like the tool broke rather than like the answer it is.
  # `|| DS_RC=$?` also keeps errexit out of the whole call chain, the same
  # discipline `die` uses when it clears the ERR trap before exiting.
  DS_RC=0
  ds_main "$@" || DS_RC=$?
  trap - ERR
  exit "$DS_RC"
fi
