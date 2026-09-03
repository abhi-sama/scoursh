#!/usr/bin/env bash
# lib/guide.sh - guided interactive mode: the prompt gate, the signal trap,
# and the menu primitives (GUIDE-01).
#
# Owns:
#   docs/STEP-GUIDE-PLAN.md   GUIDE-01's own row is the ticket-level
#                             authority for this file's scope.  Guided mode
#                             is deliberately NOT one of docs/DESIGN.md §13's
#                             ten numbered build steps (see that plan's
#                             "Relationship to the ten-step build order"),
#                             so this file carries no docs/DESIGN.md §
#                             reference and no docs/FOUNDATION.md tension.
#
# THIS TICKET SHIPS PLUMBING ONLY.  No `--guided` flag, no `scan_main`
# routing, no menu screen, no scan is wired to any of this yet (GUIDE-02
# onward).  Every function here is exercised directly by
# tests/suites/guide.sh until a later ticket calls it for real.
#
# WHY THIS EXISTS: `scan.sh` is a CI tool, and `select`/`read` are exactly
# the two builtins that can silently hang a pipeline if gated wrong.
# `docs/STEP-GUIDE-PLAN.md`'s "select, measured rather than assumed" section
# recorded ten edges of `select`/`read` behaviour, measured (not assumed) on
# bash 5.3.9 and cross-checked on bash 3.2.57 (macOS's own /bin/bash), that a
# naive implementation gets wrong in the direction that either hangs or
# silently mis-answers a menu.  This file is where all ten edges are
# absorbed once, so no future screen (GUIDE-03 onward) has to re-derive them.
#
# THE FIVE-CONDITION GATE (`guide_may_prompt`): prompting is gated
# CONJUNCTIVELY - asked for, stdin is a terminal, stderr is a terminal, no
# non-interactive environment marker is set, and `SCOURSH_NO_PROMPT` is
# unset - and the environment layer can only ever turn prompting OFF, never
# on.  Both stdin AND stderr are checked because `select` writes its menu
# and `PS3` prompt to stderr, not stdout (measured, see the plan doc); a gate
# on `-t 1` would be checking the wrong stream, and a gate on stdin alone
# lets a run whose stderr goes to a logfile block on a menu nobody can see.
# `guide_may_prompt` takes "was this asked for" as its own first argument
# rather than computing it, because that answer depends on argv (`--guided`
# given, or zero arguments) - a fact only the CLI parser has, and parsing
# argv is explicitly GUIDE-02's job, not this file's.
#
# NO TIMEOUT, ANYWHERE.  `select` cannot time out, and a `read -t` fallback
# was considered and rejected in the plan: it would make the same answers
# produce a different scan depending on typing speed, which breaks
# determinism outright.  The terminal gate plus "guided mode never runs
# unattended" is the control instead.
#
# THE SIGNAL TRAP.  `lib/core.sh` arms `trap 'core_on_signal INT' INT` (and
# TERM, and HUP) at source time, and `core_on_signal` unconditionally exits
# `SCOURSH_EXIT_INCOMPLETE` (5) - correct for an interrupted SCAN, and wrong
# for an abandoned QUESTIONNAIRE: nothing ran, so "incomplete run" is a lie a
# wrapper doing `scan.sh --guided || alert` would read as a failed scan.
# Every blocking prompt in this file (`guide_menu`, `guide_ask`,
# `guide_confirm`) therefore installs its own guided-scope `INT`/`TERM` trap
# before it can block, and restores `core_on_signal` before returning control
# on any path that does not itself exit the process.  Only INT and TERM are
# overridden - HUP is deliberately left bound to `core_on_signal`, matching
# the plan's own wording.  This is measured behaviour, not a hypothetical:
# tests/suites/guide.sh reproduces the SIG$sig -> exit 5 defect against the
# UNGUARDED `core_on_signal` shape first, then shows a prompt guarded by this
# file's trap exiting 0 for the identical interruption.
#
# EOF AT ANY PROMPT IS EXIT 2, never a silent fall-through and never the
# generic uncaught-error path.  A bare `select` at EOF trips this project's
# ERR trap as its own failing command (measured: reproduced with this
# project's real trap shape, `select` fails with status 1 citing itself as
# `BASH_COMMAND`) UNLESS at least one more statement runs after it before the
# function would otherwise return - which is why every `select`/`read` call
# below is followed by real logic, never left as the last statement of its
# function.  A bare `read` at EOF is worse: it returns 1 immediately, as the
# LAST command of a one-line prompt, and aborts on the spot under this
# project's mandatory `set -Eeuo pipefail` unless it sits in a tested
# context - so every prompt read here is written
# `if ! IFS= read -r ... ; then <handle it> ; fi`, never bare.
#
# SCOURSH_GUIDE_FORCE_TTY IS TEST-ONLY.  It is a swappable-hook override in
# the same idiom as `lib/http.sh`'s `SCOURSH_HTTP_TRANSPORT` and
# `lib/paranoid.sh`'s `SCOURSH_PARANOID_FORCE_BACKEND`: it exists so
# tests/suites/guide.sh can drive `guide_may_prompt` and the menu primitives
# from a scripted, non-tty input stream without a real pty.  It forces ONLY
# the two terminal checks (`-t 0`, `-t 2`) - never the non-interactive
# environment-marker probe and never `SCOURSH_NO_PROMPT` - so that a test
# proving "the environment marker refuses even when the terminal check would
# pass" is actually exercising that marker, not merely re-proving the
# terminal gate.  Stated here in the same breath as the other two hooks so
# it does not quietly end up set in somebody's real CI configuration: it is
# not a supported way to force guided mode on in a pipeline, and
# `SCOURSH_NO_PROMPT` remains the one and only documented way to force it
# off.
#
# shellcheck shell=bash
#
# SC2329: `guide_may_prompt`, `guide_menu`, `guide_ask`, `guide_confirm` and
# `_guide_shquote` are this ticket's public surface for a scan_main routing
# layer that does not exist yet (GUIDE-02 onward); until that lands, the
# only caller in this project's own source graph is tests/suites/guide.sh,
# which shellcheck's `-x` follow does not traverse from this file's own
# check. `_guide_trap_install`/`_guide_trap_restore`/`_guide_on_cancel` are
# reached only through the three prompt primitives above and through the
# INT/TERM trap itself, neither of which is a literal call shellcheck's
# static graph can follow.
#
# SC2034: GUIDE_MENU_REPLY, GUIDE_MENU_CHOICE and GUIDE_ASK_REPLY are the
# deliberate SET-A-VARIABLE output of guide_menu/guide_ask (see those
# functions' own comments for why - the short version is that a caller
# reading them via `$(...)` would swallow this file's own `die`), read only
# by a future scan_main routing layer (GUIDE-02 onward) and by
# tests/suites/guide.sh - neither of which is a caller shellcheck's `-x`
# follow from scan.sh reaches yet, since scan.sh does not call any of this
# file's functions until that later ticket lands.
# shellcheck disable=SC2329,SC2034

if [[ -n ${SCOURSH_GUIDE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_GUIDE_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# ---------------------------------------------------------------------------
# 1. The prompt gate
# ---------------------------------------------------------------------------

# The full non-interactive environment probe list (docs/STEP-GUIDE-PLAN.md,
# "When it prompts, and every case where it must not", condition 4).  `CI`
# alone is not enough - Jenkins does not set it by default - and a runner
# that allocates a pty (`docker run -t`, an `expect`/`script` wrapper)
# satisfies the two terminal checks, so this list is what actually stops
# guided mode running unattended in that shape.
readonly -a _GUIDE_ENV_MARKERS=(
  CI CONTINUOUS_INTEGRATION BUILD_NUMBER JENKINS_URL TEAMCITY_VERSION
  GITHUB_ACTIONS GITLAB_CI BUILDKITE TF_BUILD
)

# See the SCOURSH_GUIDE_FORCE_TTY header note above: TEST-ONLY, forces only
# the terminal checks.
_guide_stdin_is_tty() {
  if [[ -n ${SCOURSH_GUIDE_FORCE_TTY:-} ]]; then
    [[ $SCOURSH_GUIDE_FORCE_TTY == true ]]
  else
    [[ -t 0 ]]
  fi
}

_guide_stderr_is_tty() {
  if [[ -n ${SCOURSH_GUIDE_FORCE_TTY:-} ]]; then
    [[ $SCOURSH_GUIDE_FORCE_TTY == true ]]
  else
    [[ -t 2 ]]
  fi
}

# `guide_may_prompt REQUESTED` - the five-condition rule, evaluated in the
# plan's own order.  REQUESTED is `true` when `--guided` was given or the
# operator typed a bare `scan.sh` (a fact only the CLI parser has); anything
# else is treated as "not requested", the safe default.  Returns 0 only when
# every condition holds; never dies, never blocks, never prints - the CALLER
# decides what a refusal means (silent no-op for an unrequested guided mode,
# a loud exit-2 usage error naming the reason for a requested-but-ineligible
# one, per the plan's own "fail loudly and immediately" rule), because that
# decision needs the CLI context this file deliberately does not have.
guide_may_prompt() {
  local requested=${1:-false}
  [[ $requested == true ]] || return 1
  _guide_stdin_is_tty || return 1
  _guide_stderr_is_tty || return 1
  local marker
  for marker in "${_GUIDE_ENV_MARKERS[@]+"${_GUIDE_ENV_MARKERS[@]}"}"; do
    [[ -z ${!marker:-} ]] || return 1
  done
  [[ -z ${SCOURSH_NO_PROMPT:-} ]] || return 1
  return 0
}

# `guide_ineligible_reason` - names the FIRST condition (in the plan's own
# order) of `guide_may_prompt`'s five-condition gate that is currently
# failing, in one sentence fragment scan_main's own exit-2 usage message can
# interpolate ("fail loudly and immediately ... naming the concrete reason",
# docs/STEP-GUIDE-PLAN.md GUIDE-02).  Deliberately a SEPARATE function from
# `guide_may_prompt` rather than a second return value: that function's own
# header states it "never prints", and this one's whole job is printing, so
# splitting them keeps both contracts honest.  A caller reaches for this only
# after `guide_may_prompt true` has already returned non-zero - condition 1
# ("asked for") is therefore not re-diagnosed here, since a caller that got
# this far already knows it was asked for.  Re-checks `_guide_stdin_is_tty`/
# `_guide_stderr_is_tty` (never a raw `[[ -t 0 ]]`) so the
# SCOURSH_GUIDE_FORCE_TTY test hook applies here exactly as it does to the
# gate itself.
guide_ineligible_reason() {
  _guide_stdin_is_tty || { printf '%s' 'standard input is not a terminal'; return 0; }
  _guide_stderr_is_tty || { printf '%s' 'standard error is not a terminal'; return 0; }
  local marker
  for marker in "${_GUIDE_ENV_MARKERS[@]+"${_GUIDE_ENV_MARKERS[@]}"}"; do
    if [[ -n ${!marker:-} ]]; then
      printf "'%s' is set in the environment" "$marker"
      return 0
    fi
  done
  if [[ -n ${SCOURSH_NO_PROMPT:-} ]]; then
    printf '%s' 'SCOURSH_NO_PROMPT is set'
    return 0
  fi
  printf '%s' 'guided mode is not available'
}

# ---------------------------------------------------------------------------
# 2. The guided-scope INT/TERM trap
# ---------------------------------------------------------------------------

_guide_on_cancel() {
  printf '%s\n' 'Cancelled.  Nothing was scanned.' >&2
  exit "$SCOURSH_EXIT_OK"
}

_guide_trap_install() {
  trap '_guide_on_cancel' INT
  trap '_guide_on_cancel' TERM
}

# Restores lib/core.sh's own traps, exactly as `core_install_traps` armed
# them.  Only called on a return path that does NOT itself exit the process
# (the EOF and unusable-answer-cap paths below call `die`, which exits
# directly - restoring the trap first would matter only if something after
# `die` could still run, and nothing does).
_guide_trap_restore() {
  trap 'core_on_signal INT' INT
  trap 'core_on_signal TERM' TERM
}

# ---------------------------------------------------------------------------
# 3. Menu primitives
# ---------------------------------------------------------------------------

# `guide_menu PROMPT ITEM...` - a single-choice menu built on the `select`
# builtin, absorbing every edge measured in docs/STEP-GUIDE-PLAN.md's
# "select, measured rather than assumed" section.  Sets GUIDE_MENU_REPLY (the
# 1-based index `select` itself assigned to `REPLY`) and GUIDE_MENU_CHOICE
# (the chosen item's text) on success; never prints them, so a caller that
# wants to map an index back to something other than its label text (G3's
# "the answer is recorded by target id, never by position") is free to.
#
# It SETS variables rather than printing one for the same reason
# `worker_id_set`/`run_fact_first_set` do (lib/core.sh): this function must
# be able to call `die` for real, and `die` inside a `$(...)` command
# substitution only kills that subshell (lib/core.sh's `core_capture`
# comment documents this at length) - so `GUIDE_MENU_REPLY=$(guide_menu ...)`
# would silently swallow the EOF/unusable-cap abort this function exists to
# make loud.
GUIDE_MENU_REPLY=''
GUIDE_MENU_CHOICE=''
guide_menu() {
  local prompt=$1
  shift
  # Edge 8: a zero-item `select` exits 0 with the body never running and the
  # variable unset, printing no menu at all - silently continuing on an
  # empty menu is a worse failure than refusing outright, so this is checked
  # before `select` ever runs rather than left to that behaviour.
  (( $# > 0 )) || die "$SCOURSH_EXIT_INCOMPLETE" "guide_menu: called with no items"
  local -a items=("$@")
  _guide_trap_install
  # Edge 7: layout is column-major and reflowed to COLUMNS, and an item-count
  # cap does not control it - measured non-monotonic with item width, item
  # count AND COLUMNS.  COLUMNS=1 forces exactly one item per line
  # deterministically, regardless of width (measured, both bash versions).
  # `local COLUMNS=1` shadows for the duration of this function only and
  # restores whatever the caller had (including "unset") on return - no
  # manual save/restore needed.
  local COLUMNS=1
  local PS3=$prompt
  local choice attempts=0
  GUIDE_MENU_REPLY=''
  GUIDE_MENU_CHOICE=''
  while :; do
    # Edge 3: a blank line redisplays the list without ever entering this
    # loop body - `select`'s own behaviour, invisible to us, so Enter is
    # inert and every advance costs a specific digit.
    select choice in "${items[@]+"${items[@]}"}"; do
      break
    done
    # Edge 6: the choice variable is UNSET after real EOF but set to the
    # empty string after an invalid choice, and REPLY is empty in both
    # cases - so `${choice-}`/`${REPLY-}` defaulting is mandatory here, and
    # "was choice ever assigned" (unset vs set-empty) is the only way to
    # tell EOF apart from an invalid answer.  Edge 5: at EOF `select`'s own
    # exit status is 1, which is why it must never be the last statement
    # executed in this function - every branch below runs a real statement
    # (an assignment, `die`, `break`) immediately after it.
    if [[ -z ${choice+set} ]]; then
      die "$SCOURSH_EXIT_USAGE" "input ended before the scan was configured; nothing ran"
    fi
    if [[ -n $choice ]]; then
      GUIDE_MENU_REPLY=${REPLY-}
      GUIDE_MENU_CHOICE=$choice
      break
    fi
    # Edge 4: invalid or out-of-range input DOES enter the loop body, with
    # choice forced to the empty string and REPLY holding the raw token - an
    # empty choice with a non-empty REPLY is exactly that case (never
    # reached for a genuine blank Enter, which edge 3 already handled inside
    # `select` itself), and it is unusable rather than fatal: re-prompt, up
    # to a bound.
    attempts=$(( attempts + 1 ))
    if (( attempts >= 10 )); then
      die "$SCOURSH_EXIT_USAGE" "too many unusable answers; nothing ran"
    fi
  done
  _guide_trap_restore
  return 0
}

# `guide_ask PROMPT [DEFAULT]` - free-text input.  PROMPT is used verbatim as
# the `read -p` text (a caller that wants "[default]" shown types it into
# PROMPT itself, since only the caller knows the right wording for its own
# screen); an empty typed line yields DEFAULT (empty string when none was
# given).  Sets GUIDE_ASK_REPLY.
GUIDE_ASK_REPLY=''
guide_ask() {
  local prompt=$1 default=${2-} answer=''
  _guide_trap_install
  # Edge 10: a bare `read` at EOF returns 1 immediately and, unguarded,
  # aborts on the spot under this project's `set -Eeuo pipefail` - so this
  # is always the condition of an `if`, never a bare statement.
  if ! IFS= read -r -p "$prompt" answer; then
    die "$SCOURSH_EXIT_USAGE" "input ended before the scan was configured; nothing ran"
  fi
  if [[ -z $answer ]]; then
    GUIDE_ASK_REPLY=$default
  else
    GUIDE_ASK_REPLY=$answer
  fi
  _guide_trap_restore
  return 0
}

# `guide_confirm PROMPT EXPECTED` - a typed-string confirmation (edge 9:
# `REPLY`-shaped free text via `read -r`, not `select`).  Returns 0 when the
# typed line matches EXPECTED byte-for-byte, 1 otherwise - a non-matching
# answer is a legitimate "no" (G4/G6's "type X to continue, or anything else
# to cancel/keep the conservative limits"), never an error.  Only real EOF is
# exit 2: a wrapper doing `scan.sh --guided </dev/null` must fail loud rather
# than being silently answered "no" by nothing.
guide_confirm() {
  local prompt=$1 expected=$2 answer=''
  _guide_trap_install
  if ! IFS= read -r -p "$prompt" answer; then
    die "$SCOURSH_EXIT_USAGE" "input ended before the scan was configured; nothing ran"
  fi
  _guide_trap_restore
  [[ $answer == "$expected" ]]
}

# ---------------------------------------------------------------------------
# 4. Shell quoting for the printed/recorded command
# ---------------------------------------------------------------------------

# `_guide_shquote VALUE` - hand-rolled single-quote wrapping, deliberately
# NOT `printf %q`: bash's `%q` diverges into `$'...'` ANSI-C-quoted forms for
# control characters, which is a different (if equally safe) dialect from
# the plain POSIX single-quoting the rest of this project's printed/recorded
# commands use, and mixing the two in one rendered command line is the kind
# of inconsistency a reviewer has to stop and think about.  A value made
# entirely of bytes that are never special to the shell is printed bare;
# anything else is wrapped in single quotes, with each embedded `'` closed,
# escaped, and reopened (`'\''`) - the standard, safe POSIX idiom.
_guide_shquote() {
  local v=$1
  if [[ $v =~ ^[A-Za-z0-9_./:,=@%+-]+$ ]]; then
    printf '%s' "$v"
    return 0
  fi
  local out="'" i ch
  for (( i = 0; i < ${#v}; i++ )); do
    ch=${v:i:1}
    if [[ $ch == "'" ]]; then
      out+="'\\''"
    else
      out+=$ch
    fi
  done
  out+="'"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 5. The settable-flag registry (docs/STEP-GUIDE-PLAN.md GUIDE-02)
# ---------------------------------------------------------------------------

# GUIDE_SETTABLE_FLAGS is the single source of truth for "every flag NAME a
# real guided-mode prompt writes into scan.sh's SCAN_FLAGS", the shell form of
# the plan's own "Flag equivalence" table.  GUIDE-02 wires no prompt at all
# (its own row: "no menus"; that is GUIDE-03 onward) - `--guided` and
# `--print-command` are inputs TO the guided flow, not flags a prompt inside
# it sets, so this starts empty rather than seeded with those two.  Every
# later GUIDE-0x ticket that lands a real prompt (G1's scan type, G2's
# --path/--lang/--history, G3's --target, ...) appends the flag name it sets
# HERE, in the SAME change that wires the prompt.
#
# tests/suites/scan.sh's own case walks this array against `_SCAN_FLAG_KIND`
# (declared in scan.sh, which sources this file, so both are in scope by the
# time that test runs) and fails loudly on any entry with no matching
# `<scope>:<flag>` key - this is what makes "a prompt's flag must already be
# legal for the parser" STRUCTURAL rather than a convention a future ticket
# has to remember unassisted.  A `for` loop over an empty array runs zero
# iterations and asserts nothing yet, which is the correct, honest state of
# this check before any prompt exists - not a weaker version of the check,
# just an earlier one.
readonly -a GUIDE_SETTABLE_FLAGS=()
