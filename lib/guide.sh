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
#
# Section 6 (GUIDE-04, the DAST branch) is in the identical position:
# `guide_dast_configure` and its own GUIDE_DAST_* output globals have no
# caller in scan_main yet either (G1/G2's menu entry point is GUIDE-03's job,
# not this ticket's - see that section's own header), so the same two SC
# codes apply to it for the same reason, and are not re-disabled per
# function below.
# shellcheck disable=SC2329,SC2034

if [[ -n ${SCOURSH_GUIDE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_GUIDE_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"
# docs/STEP-GUIDE-PLAN.md GUIDE-04: the DAST branch (section 6 below) needs
# lib/http.sh directly - `http_scope_load`/`http_url_normalize`/
# `http_resolve_host` to read config/scope.conf the identical way the real
# gate does (so the menu and the gate can never disagree about which targets
# exist), and `_http_limit_ceiling_set` to read DAST-32's own ceiling
# constants rather than typing them as prose (this ticket's own acceptance
# criterion).  `modules/dast/ratelimit.sh` already calls that same private
# function cross-file, so this is not a new pattern.
# shellcheck source=lib/http.sh
source "${BASH_SOURCE[0]%/*}/http.sh"
# ...and lib/checks.sh, for `CHECKS_INTENSITY_DEFAULT`/`CHECKS_INTENSITIES`
# (G5's own three menu items, in that array's order) - the single source of
# truth `scan_validate_flag_value`'s `intensity` case already defers to,
# rather than a second hardcoded `passive|safe|active` list here.
# shellcheck source=lib/checks.sh
source "${BASH_SOURCE[0]%/*}/checks.sh"

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
#
# docs/STEP-GUIDE-PLAN.md GUIDE-03 is the first ticket to land a real prompt:
# G2 (the local-surface follow-ups) sets `path`, `lang` and `history`, and G8
# (the CI gate) sets `fail-on` - see scan.sh's own "guided menu flow" section
# for where each is set.  `guided`/`print-command` stay off this list on
# purpose (GUIDE-02's own header comment): they are inputs TO the flow, never
# outputs a prompt inside it writes.  GUIDE-04 (section 6 below) appends the
# six names its own G3/G5/G6 prompts set: `target` (G3), `intensity` (G5), and
# `i-own-target`/`requests-per-second`/`request-budget`/`allow-intrusive` (G6,
# all four reached only past a matched affirmation).  Every one of them
# already has a matching `[dast:...]`/`[all:...]` entry in scan.sh's
# `_SCAN_FLAG_KIND` - `requests-per-second`/`request-budget` are GUIDE-04's
# own addition there, added in the same change as these prompts, per this
# array's own contract above.
readonly -a GUIDE_SETTABLE_FLAGS=(
  path lang history fail-on
  target intensity i-own-target requests-per-second request-budget allow-intrusive
)

# ---------------------------------------------------------------------------
# 6. The DAST branch and the affirmation (docs/STEP-GUIDE-PLAN.md GUIDE-04)
# ---------------------------------------------------------------------------
#
# Steps G3 (the target menu), G5 (intensity) and G6 (the limits router, the
# affirmation, and each raised limit as its own menu).  G1/G2 (the scan-type
# menu and the local-surface follow-ups) and G4/G9 (writing a new
# config/scope.conf record; the final review screen) are explicitly NOT this
# ticket's scope - GUIDE-03, GUIDE-05 and GUIDE-06 respectively - so nothing
# here is wired into scan_main yet, exactly as GUIDE-01's own primitives
# were not until GUIDE-02 landed.  `guide_dast_configure` is this section's
# one public entry point, for whichever later ticket's own G1/G2 flow ends
# up calling it once a `dast`/`all`-with-DAST scan type is chosen.
#
# NUMBERS ARE NEVER TYPED AS PROSE.  Every ceiling this section's screens
# state (the conservative rate, the conservative budget) is read from
# `_http_limit_ceiling_set`, the exact function DAST-32's own clamp reads
# (`_http_effective_rps_milli_set`/`_http_effective_limit_set`, lib/http.sh) -
# never hand-copied as a literal `4` or `5000`.  This is the ticket's own
# stated reason: typing the number as prose is "the most likely way this
# whole design quietly becomes theatre" the moment DAST-32's own ceiling
# changes and this file's screens do not.
_guide_dast_rps_ceiling() {
  _http_limit_ceiling_set requests-per-second
  printf '%s' "$_HTTP_LIMIT_CEIL"
}
_guide_dast_budget_ceiling() {
  _http_limit_ceiling_set request-budget
  printf '%s' "$_HTTP_LIMIT_CEIL"
}

# `lib/http.sh`'s rate limiter has no literal "unbounded" sentinel.
# docs/STEP-GUIDE-PLAN.md's own "Flag equivalence" table says the rate
# prompt's "No limit" choice is `--requests-per-second 0`, but that is not
# what the shipped DAST-01 limiter does - measured against lib/http.sh rather
# than assumed: `_http_rps_milli_set`/`_http_decimal_is_zero` refuse a
# genuinely-zero rate outright ("permits no requests at all"), on the
# reasoning (that function's own comment) that waiting forever for a token
# which can never arrive would look like a hang.  Emitting a literal `0`
# here would turn the safest-reading menu item into a dead run, which is
# worse than the plan's own wording, not a faithful implementation of it.
# `_http_rps_milli_set` refuses only an integer part longer than 9 digits, so
# this is the limiter's own maximum REPRESENTABLE rate - schema-legal
# (`^(0|[1-9][0-9]*)(\.[0-9]+)?$`), and for any real target indistinguishable
# from "as fast as the target answers", which is the menu's own wording.
_GUIDE_DAST_RPS_UNLIMITED=999999999

# ---------------------------------------------------------------------------
# 6a. G3 - the DAST target
# ---------------------------------------------------------------------------
#
# Read straight out of config/scope.conf through `http_scope_load` (which
# itself calls `config_scope_load` and then runs every base-url/extra-host
# through `http_url_normalize`, the identical pipeline a real request goes
# through) rather than the raw record fields, so the menu and the gate can
# never disagree about which targets exist or what tuple each one matches -
# this ticket's own row states that requirement in those words.  There is
# deliberately no free-text URL box anywhere in this flow: a typed URL here
# would be a second scope source, exactly the raw-URL bypass docs/DESIGN.md
# §7 forbids.

# Populated by `_guide_dast_targets_collect`: one entry per DISTINCT target
# id, in config/scope.conf's own order, first-occurrence-wins (a target with
# `extra-host` records adds more rows to `_HTTP_SCOPE_ID` than it has ids,
# since http_scope_load emits one row per host under one id - this collapses
# those back to one menu line per id, showing that id's own base-url tuple).
declare -a _GUIDE_DAST_TARGET_IDS=() _GUIDE_DAST_TARGET_TUPLES=()
_guide_dast_targets_collect() {
  http_scope_load
  _GUIDE_DAST_TARGET_IDS=()
  _GUIDE_DAST_TARGET_TUPLES=()
  local i n=${#_HTTP_SCOPE_ID[@]} id existing found
  for (( i = 0; i < n; i++ )); do
    id=${_HTTP_SCOPE_ID[i]}
    found=false
    for existing in "${_GUIDE_DAST_TARGET_IDS[@]+"${_GUIDE_DAST_TARGET_IDS[@]}"}"; do
      [[ $existing == "$id" ]] && { found=true; break; }
    done
    $found && continue
    _GUIDE_DAST_TARGET_IDS+=("$id")
    _GUIDE_DAST_TARGET_TUPLES+=("${_HTTP_SCOPE_SCHEME[i]}://${_HTTP_SCOPE_HOST[i]}:${_HTTP_SCOPE_PORT[i]}")
  done
  return 0
}

_guide_dast_target_empty_banner() {
  {
    printf '\n'
    printf '%s\n' '  scoursh ships with no target of any kind, and there is no demo host to'
    printf '%s\n' '  point it at.  DAST only ever talks to a host you have explicitly'
    printf '%s\n' "  authorised in config/scope.conf - that file is the tool's authorisation"
    printf '%s\n' '  record, and this menu cannot create scan permission any other way.'
    printf '\n'
  } >&2
}

_guide_dast_target_banner() {
  {
    printf '\n'
    printf '%s\n' '  DAST only ever talks to a host you have authorised in config/scope.conf.'
    printf '%s\n' "  That file is the tool's authorisation record.  This menu cannot override"
    printf '%s\n' '  it: answering a question here never grants permission to scan anything.'
    printf '\n'
    printf '%s\n' 'Which target?'
    printf '\n'
  } >&2
}

# G4 (writing a new config/scope.conf record) is GUIDE-05's ticket, not
# this one - so picking "Authorise a new target" here is a fixed menu item
# whose module is not built, per this plan's own "Menu items on fixed
# menus" rule: labelled and refused with one line if picked, rather than
# dropped from the menu (renumbering would mean "answer 3" meant different
# things on different checkouts).  It returns to the SAME menu rather than
# exiting, matching G1's own "picking 4 or 5 ... returns here" precedent for
# an unbuilt module.
_guide_dast_authorise_not_built() {
  {
    printf '\n'
    printf '%s\n' '  Authorising a new target from this menu is not built in this version of'
    printf '%s\n' '  scoursh yet (docs/STEP-GUIDE-PLAN.md GUIDE-05).  Nothing was written to'
    printf '%s\n' '  config/scope.conf, and nothing was scanned.'
    printf '\n'
    printf '%s\n' '  To authorise a target today, add a scope-target record to'
    printf '%s\n' '  config/scope.conf by hand - see config/scope.conf.example and'
    printf '%s\n' '  rules/RULE-FORMAT.md for the record shape.'
    printf '\n'
  } >&2
}

# `guide_dast_target_menu` - sets GUIDE_DAST_TARGET and returns 0 on a real
# selection.  Returns 1 for "Back" (to whichever menu called this one - G1,
# once GUIDE-03 lands); never for "Quit", which exits the process directly
# via `_guide_on_cancel`, the same "Cancelled.  Nothing was scanned." exit 0
# every other quit path in this flow uses.
GUIDE_DAST_TARGET=''
guide_dast_target_menu() {
  _guide_dast_targets_collect

  if (( ${#_GUIDE_DAST_TARGET_IDS[@]} == 0 )); then
    _guide_dast_target_empty_banner
    guide_menu 'pick a number> ' 'Authorise a target now' 'Back' 'Quit'
    case $GUIDE_MENU_REPLY in
      1)
        _guide_dast_authorise_not_built
        guide_dast_target_menu
        return $?
        ;;
      2) return 1 ;;
      3) _guide_on_cancel ;;
    esac
    return 0
  fi

  _guide_dast_target_banner
  local -a items=()
  local i n=${#_GUIDE_DAST_TARGET_IDS[@]}
  for (( i = 0; i < n; i++ )); do
    items+=("${_GUIDE_DAST_TARGET_IDS[i]}    ${_GUIDE_DAST_TARGET_TUPLES[i]}")
  done
  items+=('Authorise a new target - writes a record into config/scope.conf' 'Back')
  guide_menu 'pick a number> ' "${items[@]+"${items[@]}"}"

  if (( GUIDE_MENU_REPLY == n + 1 )); then
    _guide_dast_authorise_not_built
    guide_dast_target_menu
    return $?
  elif (( GUIDE_MENU_REPLY == n + 2 )); then
    return 1
  fi
  GUIDE_DAST_TARGET=${_GUIDE_DAST_TARGET_IDS[GUIDE_MENU_REPLY - 1]}
  return 0
}

# ---------------------------------------------------------------------------
# 6b. G5 - DAST intensity
# ---------------------------------------------------------------------------
#
# Item order is `CHECKS_INTENSITIES` (lib/checks.sh) verbatim - passive,
# safe, active - the same single source of truth `scan_validate_flag_value`
# already defers to for what a legal `--intensity` value is, so this menu
# can never offer a choice the parser would then refuse.
GUIDE_DAST_INTENSITY=''
guide_dast_intensity_menu() {
  local target=$1
  {
    printf '\n'
    printf "How hard should the scan push '%s'?\n" "$target"
    printf '\n'
  } >&2
  local -a items=(
    'passive - read only: headers, cookies, TLS, markup, served JavaScript; nothing is injected (default)'
    "safe    - passive, plus content discovery and HTTP method enumeration (puts hundreds of 404s into the target's logs)"
    'active  - safe, plus injection probes (SQLi, XSS, SSTI, traversal, ...) into every parameter found (a target owner will read this as an attack)'
  )
  {
    printf '\n'
    printf '%s\n' '  Detection only at every level: scoursh sends no destructive payload and'
    printf '%s\n' '  does no credential brute forcing at any intensity, and cannot be told to.'
    printf '\n'
    printf '%s\n' '  2 and 3 require you to affirm you are authorised for this host.  Permission'
    printf '%s\n' '  to browse a host, or to port-scan it, is not permission to send it'
    printf '%s\n' '  injection payloads.'
    printf '\n'
  } >&2
  guide_menu 'pick a number> ' "${items[@]+"${items[@]}"}"
  GUIDE_DAST_INTENSITY=${CHECKS_INTENSITIES[GUIDE_MENU_REPLY - 1]}
  return 0
}

# ---------------------------------------------------------------------------
# 6c. G6 - the limits router, the affirmation, and each raised limit
# ---------------------------------------------------------------------------
#
# THE ROUTER IS FLOW CONTROL, NOT A SCREEN OF ITS OWN.  `passive` (G5's own
# item 1, the default) needs nothing raised, so `guide_dast_limits_flow`
# asks NOTHING at all in that case - no affirmation, no rate/budget menus,
# no side-effecting-checks question - which is exactly what makes this
# plan's own acceptance test true: a scripted run that picks item 1 at every
# fixed menu (G3's first target, G5's `passive`) never reaches this
# function's own prompts, so the composed argv contains no `--i-own-target`,
# no `--allow-intrusive` and no raised limit, structurally rather than by a
# rule this code has to remember to honour.
#
# `safe`/`active` route to the affirmation screen.  A MATCHED affirmation
# unlocks - never selects - the rate menu, then the budget menu, then (only
# when the chosen intensity is `active`) the side-effecting-checks question;
# each of those three still opens on its OWN conservative value at item 1,
# per this ticket's own "second correction" - jumping straight from a
# matched affirmation into three prompts pre-filled with the RAISED values
# would let three Enters produce a 5x/4x/10x run with no further decision,
# which is precisely the click-through the affirmation exists to prevent,
# one keystroke after it.  An UNMATCHED affirmation reverts the intensity to
# `passive` (GUIDE_DAST_INTENSITY is overwritten here) and asks nothing
# else - there is deliberately no retry loop: a second attempt turns a
# deliberate act back into a click-through, and the failure direction (keep
# the conservative limits) is safe.

_guide_dast_affirmation_banner() {
  local target=$1 base_url addr operator
  http_scope_load
  base_url=$(config_scope_field "$target" base-url)
  if http_url_normalize "$base_url"; then
    addr=$(http_resolve_host "$_HN_HOST" 2>/dev/null) || addr='(could not be resolved)'
  else
    addr='(could not be resolved)'
  fi
  operator=${SCOURSH_OPERATOR:-$(id -un 2>/dev/null)}
  [[ -n $operator ]] || operator='(unknown)'
  {
    printf '\n'
    printf -- '-------------------------------------------------------------------\n'
    printf " Raising the limits for target '%s'\n" "$target"
    printf '\n'
    printf ' Base URL     %s\n' "$base_url"
    printf ' Resolves to  %s\n' "$addr"
    printf ' From         this machine, as user %s\n' "$operator"
    printf '\n'
    printf '%s\n' ' Above the conservative limits, scoursh sends traffic a target owner will'
    printf '%s\n' ' read as an attack: injection payloads in every parameter it found, and'
    printf '%s\n' ' hundreds of requests for paths that probably do not exist.'
    printf '\n'
    printf '%s\n' " That traffic is attributable to you.  It leaves this machine's IP address,"
    printf '%s\n' " it carries a User-Agent naming this tool, and it lands in the target's logs"
    printf '%s\n' ' next to your source address.'
    printf '\n'
    printf '%s\n' ' It can also take the target down.  A host that is small, slow or shared can'
    printf '%s\n' ' stop serving real users while this runs.'
    printf '\n'
    printf '%s\n' ' Only continue if you own this host, or you hold written permission from'
    printf '%s\n' ' whoever does that covers active security testing.'
    printf '\n'
    printf '%s\n' ' Being able to reach a host is not permission.  A robots.txt or a'
    printf '%s\n' ' security.txt file is not permission.  A bug bounty page is not permission'
    printf '%s\n' ' unless it names this host and this kind of testing.'
    printf '\n'
    printf '%s\n' ' This does NOT remove the request budget - it is always finite, and this'
    printf '%s\n' " run's budget still stops it after a fixed number of requests, whatever is"
    printf '%s\n' ' still queued.'
    printf '%s\n' ' This does NOT disable the failure-rate circuit breaker.'
    printf '%s\n' ' This does NOT let scoursh talk to any host outside config/scope.conf.'
    printf '%s\n' ' This does NOT send a destructive payload at any setting - every probe is'
    printf '%s\n' ' detection-only.'
    printf '%s\n' ' This does NOT turn on side-effecting checks by itself; that is asked'
    printf '%s\n' " separately, below, only when you chose 'active'."
    printf '\n'
    printf ' Type the target name  %s  to continue, or anything else to keep\n' "$target"
    printf '%s\n' ' the conservative limits.'
    printf '\n'
  } >&2
}

GUIDE_DAST_REQUESTS_PER_SECOND=''
guide_dast_rate_menu() {
  local target=$1 ceil
  ceil=$(_guide_dast_rps_ceiling)
  {
    printf '\n'
    printf "Requests per second against '%s'\n" "$target"
    printf '\n'
  } >&2
  local -a items=(
    "$ceil        - the conservative default (default)"
    '20'
    '50'
    'No limit - send as fast as the target answers'
  )
  {
    printf '\n'
    printf '%s\n' "'No limit' can take a small or shared host offline.  The total request"
    printf '%s\n' 'budget and the failure breaker still apply either way.'
    printf '\n'
  } >&2
  guide_menu 'pick a number> ' "${items[@]+"${items[@]}"}"
  case $GUIDE_MENU_REPLY in
    1) GUIDE_DAST_REQUESTS_PER_SECOND=$ceil ;;
    2) GUIDE_DAST_REQUESTS_PER_SECOND=20 ;;
    3) GUIDE_DAST_REQUESTS_PER_SECOND=50 ;;
    4) GUIDE_DAST_REQUESTS_PER_SECOND=$_GUIDE_DAST_RPS_UNLIMITED ;;
  esac
  return 0
}

# Item 2 (the operator's own config/scanner.conf value) appears only when
# that file actually sets `request-budget` to something OTHER than the
# conservative default item 1 already offers - "sets a different value",
# this ticket's own wording - so an unedited install (or one that merely
# copies config/scanner.conf.example's own `request-budget: 20000`, if that
# happens to equal the ceiling) never shows a redundant third line
# restating item 1's own number under a different label.
GUIDE_DAST_REQUEST_BUDGET=''
guide_dast_budget_menu() {
  local target=$1 ceil file_val=''
  ceil=$(_guide_dast_budget_ceiling)
  config_scanner_load
  if (( CONFIG_SCANNER_LOADED )) && records_has scanner 0 request-budget; then
    file_val=$(records_field scanner 0 request-budget)
    [[ $file_val == "$ceil" ]] && file_val=''
  fi
  {
    printf '\n'
    printf "Total request budget for '%s'\n" "$target"
    printf '\n'
    printf '%s\n' 'scoursh stops the run once it has sent this many requests, whatever is still'
    printf '%s\n' 'queued.  There is always a budget.  It cannot be removed - it is what bounds'
    printf '%s\n' 'a crawler loop or a mistake in a parameter list.'
    printf '\n'
  } >&2
  local -a items=("$ceil    - the conservative default (default)")
  local -a values=("$ceil")
  if [[ -n $file_val ]]; then
    items+=("$file_val   - the value in your config/scanner.conf")
    values+=("$file_val")
  fi
  items+=('100000')
  values+=('100000')
  guide_menu 'pick a number> ' "${items[@]+"${items[@]}"}"
  GUIDE_DAST_REQUEST_BUDGET=${values[GUIDE_MENU_REPLY - 1]}
  return 0
}

GUIDE_DAST_ALLOW_INTRUSIVE=false
guide_dast_intrusive_menu() {
  local target=$1
  {
    printf '\n'
    printf "Side-effecting checks against '%s'?\n" "$target"
    printf '\n'
    printf '%s\n' 'These are off by default because their effects leave the target:'
    printf '\n'
    printf '%s\n' '  - user enumeration through login, signup and password-reset responses,'
    printf '%s\n' '    which on a real identity provider CREATES ACCOUNTS and SENDS EMAIL OR SMS'
    printf '%s\n' '    to real people'
    printf '%s\n' '  - a deliberate burst to test whether rate limiting exists at all'
    printf '\n'
    printf '%s\n' 'Owning a host does not always mean you may do this to its users.'
    printf '\n'
  } >&2
  guide_menu 'pick a number> ' 'No - skip them (default)' 'Yes - run them'
  if [[ $GUIDE_MENU_REPLY == 2 ]]; then
    GUIDE_DAST_ALLOW_INTRUSIVE=true
  else
    GUIDE_DAST_ALLOW_INTRUSIVE=false
  fi
  return 0
}

# `guide_dast_limits_flow TARGET INTENSITY` - the router described above.
# Always sets all four GUIDE_DAST_I_OWN_TARGET/REQUESTS_PER_SECOND/
# REQUEST_BUDGET/ALLOW_INTRUSIVE (clearing them first), and may overwrite
# GUIDE_DAST_INTENSITY itself (the unmatched-affirmation revert-to-passive
# case).  Never returns non-zero: an unmatched affirmation is a legitimate,
# safe outcome, not a failure this function reports on behalf of its caller.
guide_dast_limits_flow() {
  local target=$1 intensity=$2
  GUIDE_DAST_INTENSITY=$intensity
  GUIDE_DAST_I_OWN_TARGET=''
  GUIDE_DAST_REQUESTS_PER_SECOND=''
  GUIDE_DAST_REQUEST_BUDGET=''
  GUIDE_DAST_ALLOW_INTRUSIVE=false

  [[ $intensity == "$CHECKS_INTENSITY_DEFAULT" ]] && return 0

  _guide_dast_affirmation_banner "$target"
  if ! guide_confirm '> ' "$target"; then
    GUIDE_DAST_INTENSITY=$CHECKS_INTENSITY_DEFAULT
    return 0
  fi

  GUIDE_DAST_I_OWN_TARGET=$target
  guide_dast_rate_menu "$target"
  guide_dast_budget_menu "$target"
  if [[ $intensity == active ]]; then
    guide_dast_intrusive_menu "$target"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 6d. The orchestrator and the composed argv
# ---------------------------------------------------------------------------
#
# `guide_dast_configure` - G3 then G5 then G6, in order.  Returns 1 only for
# G3's own "Back" (no target was chosen, so there is nothing to configure);
# every other path - including an unmatched affirmation - returns 0, because
# by then a target and an intensity (possibly reverted to passive) are both
# real answers.  `guide_dast_argv_build` turns the five GUIDE_DAST_* outputs
# into GUIDE_DAST_ARGV, an array a future G9/G6-review-screen caller appends
# to `dast`'s composed argv verbatim - never through `$(...)`, since GUIDE-01
# established that pattern for exactly this class of "a caller must be able
# to read a real array/exit status, not a subshell's copy of one" output.
GUIDE_DAST_ARGV=()
guide_dast_argv_build() {
  GUIDE_DAST_ARGV=(--target "$GUIDE_DAST_TARGET")
  [[ $GUIDE_DAST_INTENSITY == "$CHECKS_INTENSITY_DEFAULT" ]] \
    || GUIDE_DAST_ARGV+=(--intensity "$GUIDE_DAST_INTENSITY")
  [[ -z $GUIDE_DAST_I_OWN_TARGET ]] || GUIDE_DAST_ARGV+=(--i-own-target "$GUIDE_DAST_I_OWN_TARGET")
  [[ -z $GUIDE_DAST_REQUESTS_PER_SECOND ]] \
    || GUIDE_DAST_ARGV+=(--requests-per-second "$GUIDE_DAST_REQUESTS_PER_SECOND")
  [[ -z $GUIDE_DAST_REQUEST_BUDGET ]] \
    || GUIDE_DAST_ARGV+=(--request-budget "$GUIDE_DAST_REQUEST_BUDGET")
  [[ $GUIDE_DAST_ALLOW_INTRUSIVE != true ]] || GUIDE_DAST_ARGV+=(--allow-intrusive)
  return 0
}

guide_dast_configure() {
  guide_dast_target_menu || return 1
  guide_dast_intensity_menu "$GUIDE_DAST_TARGET"
  guide_dast_limits_flow "$GUIDE_DAST_TARGET" "$GUIDE_DAST_INTENSITY"
  guide_dast_argv_build
  return 0
}
