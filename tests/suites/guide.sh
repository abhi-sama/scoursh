#!/usr/bin/env bash
# tests/suites/guide.sh - lib/guide.sh (GUIDE-01): the prompt gate, the
# signal trap, and the menu primitives.
#
# docs/STEP-GUIDE-PLAN.md's own GUIDE-01 row is explicit that this suite must
# prove the REFUSALS, not only the happy path: piped stdin, each
# non-interactive environment marker, `SCOURSH_NO_PROMPT`, EOF mid-flow, and
# SIGINT mid-flow must each exit non-zero (or 0 for the cancel path) WITHOUT
# BLOCKING, and none of them may create a run directory.  A guided-mode gate
# that only proves it prompts when it should is worthless; the value is
# proving it never blocks a pipeline.  Every case below that pins a reading
# names the reading it fails under, per AGENTS.md's testing rule.
#
# REGRESSION PROOF FOR THE SIGINT HANDLING (AGENTS.md: "a fix ... never
# observed to fail is not known to work"): section G below first reproduces
# the documented pre-existing defect - SIGINT delivered to a process blocked
# in a bare `select` under `lib/core.sh`'s own `core_on_signal` trap exits 5
# (docs/STEP-GUIDE-PLAN.md, "Ctrl-C at a prompt must exit 0 ... measured with
# a replica of that exact trap shape") - and only then shows `guide_menu`'s
# own guided-scope trap producing exit 0 for the identical interruption.
#
# WHY A python3 WRAPPER: bash gives a backgrounded ("asynchronous") command
# SIGINT/SIGQUIT pre-set to SIG_IGN before it ever execs, and refuses to let
# that process's own `trap` command override a disposition that was already
# ignored on entry ("Signals ignored upon entry to the shell cannot be
# trapped or reset" - the bash manual's own wording).  A test driver
# invoking the target under test via a plain `cmd &` therefore cannot ever
# deliver a working SIGINT to it, at all, regardless of what lib/guide.sh
# does - measured directly while building this suite: a bare `bash script &`
# child ignored SIGINT even though it ran `trap 'echo GOT' INT` first, and
# `kill -INT` on it was silently swallowed.  `tests/suites/e2e.sh` and
# `tests/suites/exit-code-matrix.sh`'s own existing background-signal tests
# sidestep this by using SIGTERM, which carries no such special-cased
# ignore-in-background rule - not an option here, since Ctrl-C is SIGINT by
# definition and the whole point of this section is SIGINT's distinct exit-0
# behaviour.  `python3` (already a test-time dependency elsewhere in this
# tree - tests/suites/e2e.sh, tests/suites/report.sh, ...) resets SIGINT to
# its default disposition and `exec`s the real target in its place, which
# survives the following `exec` into bash exactly as measured; nothing here
# runs python3 as part of a scan, only as this suite's own signal-delivery
# harness.  Absent, this ONE section is SKIPPED - stated plainly, never
# silently passed - and every other section in this file still runs.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/guide.sh
source "$ROOT/lib/guide.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/guide
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Every environment-marker-shaped variable this file's tests must control,
# so a real CI runner's own CI=true/GITHUB_ACTIONS=true (this suite may
# genuinely be running under one) never leaks into a "should allow" case.
_GUIDE_TEST_CONTROLLED_VARS=(
  "${_GUIDE_ENV_MARKERS[@]}" SCOURSH_NO_PROMPT SCOURSH_GUIDE_FORCE_TTY
)

# `_guide_test_prompt REQUESTED [VAR=VALUE...]` - calls guide_may_prompt in a
# clean environment (every controlled var unset) with the given overrides
# applied, so each case states exactly what it turns on rather than
# inheriting whatever this suite happened to start with.
_guide_test_prompt() {
  local requested=$1
  shift
  local v
  for v in "${_GUIDE_TEST_CONTROLLED_VARS[@]}"; do unset "$v" 2>/dev/null || true; done
  local kv name value
  for kv in "$@"; do
    name=${kv%%=*}
    value=${kv#*=}
    export "$name=$value"
  done
  guide_may_prompt "$requested"
}

# Asserts a subprocess exits with WANT and that it created no run directory:
# SCOURSH_RUN_DIR is only ever set by run_init (lib/core.sh), which nothing
# in lib/guide.sh calls, so its absence inside the very subprocess that ran
# CMD is the direct proof, and the scratch CWD gaining no reports/-shaped
# directory is the same claim checked from outside the subprocess too.
assert_no_run_dir_and_status() {
  local want=$1 msg=$2
  shift 2
  local cwd
  cwd=$(mktemp -d "$W/rundir-check.XXXXXX")
  local rc=0
  ( cd "$cwd" && "$@" ) >"$cwd/out" 2>"$cwd/err" || rc=$?
  assert_eq "$want" "$rc" "$msg"
  assert_file_absent "$cwd/reports" "$msg (no reports/ directory materialised)"
}

# ---------------------------------------------------------------------------
printf '\n-- _guide_shquote --\n'
# ---------------------------------------------------------------------------
# Round-tripped through `eval` so this proves the QUOTING is actually safe,
# not merely that it produces some output.
_shquote_roundtrip() {
  local input=$1 quoted roundtrip
  quoted=$(_guide_shquote "$input")
  eval "roundtrip=$quoted"
  [[ $roundtrip == "$input" ]]
}

t_case 'a bare alphanumeric/path-shaped value is printed unquoted'
assert_eq 'staging-api' "$(_guide_shquote 'staging-api')" 'no quotes added for the safe charset'
assert_eq 'https://staging-api.internal:443/' \
  "$(_guide_shquote 'https://staging-api.internal:443/')" 'a URL is in the safe charset too'

t_case 'anything outside the safe charset is single-quote wrapped'
assert_eq "'has space'" "$(_guide_shquote 'has space')" 'a space forces quoting'
assert_eq "'a'\\''b'\\''c'" "$(_guide_shquote "a'b'c")" \
  "embedded single quotes are closed/escaped/reopened as '\\''"

t_case 'round-trips through eval for a battery of hostile values - FAILS under any escaping bug'
for v in "staging-api" "it's a test" "a'b'c" "has space" '$(rm -rf /)' "" "'" "''" \
  'back`tick`' 'new
line' $'\t tab'; do
  assert_true "$(_shquote_roundtrip "$v" && echo 0 || echo 1)" \
    "round-trip holds for [${v:0:30}]"
done

t_case 'a value containing a literal & is quoted, not treated as an alternation'
assert_true "$(_shquote_roundtrip 'a&b' && echo 0 || echo 1)" 'round-trips'
assert_eq "'a&b'" "$(_guide_shquote 'a&b')" '& is outside the safe charset, so the whole value is wrapped'

# ---------------------------------------------------------------------------
printf '\n-- guide_may_prompt: the five-condition rule --\n'
# ---------------------------------------------------------------------------

t_case 'all five conditions satisfied: requested, forced tty, no markers, no SCOURSH_NO_PROMPT'
assert_status 0 'allowed - this is the ONE happy-path case in this section' \
  _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true

t_case 'condition 1: not requested refuses even with everything else eligible'
assert_status 1 'refused - --guided was not given and $# was not 0' \
  _guide_test_prompt false SCOURSH_GUIDE_FORCE_TTY=true

t_case 'condition 2/3: stdin is genuinely piped (not forced) - refuses'
rc=0
printf '' | ( unset "${_GUIDE_TEST_CONTROLLED_VARS[@]}" 2>/dev/null
  guide_may_prompt true ) >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" 'FAILS if the real -t 0 check is bypassed or replaced by something permissive'

t_case 'condition 2/3: SCOURSH_GUIDE_FORCE_TTY forces the terminal check true'
assert_status 0 'a genuinely piped stdin becomes irrelevant once forced' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"
    unset "${_GUIDE_ENV_MARKERS[@]}" SCOURSH_NO_PROMPT 2>/dev/null
    SCOURSH_GUIDE_FORCE_TTY=true guide_may_prompt true' < /dev/null

t_case 'condition 4: each non-interactive environment marker refuses on its own - FAILS if any marker is missing from the probe list'
for marker in "${_GUIDE_ENV_MARKERS[@]}"; do
  assert_status 1 "\`$marker\` set refuses even with a forced terminal" \
    _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true "$marker=1"
done

t_case 'condition 4: an UNRELATED environment variable does not refuse - proves the probe is the named list, not "anything set"'
assert_status 0 'an arbitrary env var is not treated as a CI marker' \
  _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true 'SOME_UNRELATED_VAR=1'

t_case 'condition 5: SCOURSH_NO_PROMPT refuses even with a forced terminal and no markers'
assert_status 1 'the one documented always-off switch' \
  _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true 'SCOURSH_NO_PROMPT=1'

t_case 'SCOURSH_GUIDE_FORCE_TTY forces ONLY the terminal check - never the marker or SCOURSH_NO_PROMPT checks'
assert_status 1 'FAILS if FORCE_TTY were wrongly treated as "force the whole gate on" - CI marker must still win' \
  _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true 'CI=true'
assert_status 1 'same proof for SCOURSH_NO_PROMPT specifically' \
  _guide_test_prompt true SCOURSH_GUIDE_FORCE_TTY=true 'SCOURSH_NO_PROMPT=1'

t_case 'guide_may_prompt never blocks and never creates a run directory'
assert_no_run_dir_and_status 1 'a refusal is instant and leaves no trace' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_may_prompt false'

# ---------------------------------------------------------------------------
printf '\n-- guide_menu --\n'
# ---------------------------------------------------------------------------

t_case 'a valid choice sets GUIDE_MENU_REPLY (the 1-based index) and GUIDE_MENU_CHOICE (the label)'
guide_menu 'pick> ' aa bb < <(printf '2\n')
assert_eq 2 "$GUIDE_MENU_REPLY" 'REPLY is the numeric token select itself assigned'
assert_eq bb "$GUIDE_MENU_CHOICE" 'CHOICE is the matching item text'

t_case 'edge 3: a blank line redisplays the list without counting as an unusable answer'
guide_menu 'pick> ' aa bb < <(printf '\n\n1\n')
assert_eq 1 "$GUIDE_MENU_REPLY" 'two blank lines followed by a valid choice still succeeds - FAILS if blank Enter were miscounted toward the unusable cap'

t_case 'edge 4: an invalid/out-of-range answer is unusable and re-prompts rather than dying'
guide_menu 'pick> ' aa bb < <(printf 'zz\n9\n1\n')
assert_eq 1 "$GUIDE_MENU_REPLY" 'two unusable answers followed by a valid one still succeeds'

t_case 'an empty item list dies rather than silently continuing (edge 8, guarded before select ever runs)'
assert_status "$SCOURSH_EXIT_INCOMPLETE" 'guide_menu with zero items refuses' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_menu "pick> "' < /dev/null

t_case 'EOF mid-menu is exit 2 with the documented message, not a blocking hang or an ERR-trap crash'
assert_no_run_dir_and_status "$SCOURSH_EXIT_USAGE" \
  'EOF immediately: exit 2, no run directory - FAILS under a bare unguarded select, which this project measured exiting 1 via the ERR trap instead' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_menu "pick> " aa bb' < /dev/null
err=$(bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_menu "pick> " aa bb' < /dev/null 2>&1 1>/dev/null || true)
assert_contains "$err" 'input ended before the scan was configured; nothing ran' \
  'the documented EOF message is present verbatim'

t_case '10 consecutive unusable answers caps out at exit 2, without EVER hitting real EOF - proves the cap fires on its own'
assert_no_run_dir_and_status "$SCOURSH_EXIT_USAGE" \
  'a source that never runs dry but never answers usefully is still refused, not looped on forever' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"
    guide_menu "pick> " aa bb' \
  < <(i=0; while (( i < 1000 )); do printf 'zz\n'; i=$(( i + 1 )); done)

t_case '9 unusable answers followed by a valid one still succeeds - FAILS if the cap threshold were off by one in either direction'
guide_menu 'pick> ' aa bb < <(i=0; while (( i < 9 )); do printf 'zz\n'; i=$(( i + 1 )); done; printf '1\n')
assert_eq 1 "$GUIDE_MENU_REPLY" 'the cap is a ceiling, not a hair-trigger'

t_case 'COLUMNS=1 is set for the duration and restored to UNSET afterward, when it started unset'
out=$(bash -c 'source "'"$ROOT"'/lib/guide.sh"
  unset COLUMNS
  guide_menu "pick> " aa bb < <(printf "1\n") >/dev/null 2>&1
  if [[ -v COLUMNS ]]; then echo "SET:[$COLUMNS]"; else echo "UNSET"; fi')
assert_eq UNSET "$out" 'FAILS if the restore left COLUMNS set to empty-string instead of truly unset'

t_case 'COLUMNS is restored to its PRIOR value when the caller had one set'
out=$(bash -c 'source "'"$ROOT"'/lib/guide.sh"
  export COLUMNS=137
  guide_menu "pick> " aa bb < <(printf "1\n") >/dev/null 2>&1
  echo "$COLUMNS"')
assert_eq 137 "$out" "a caller's own COLUMNS survives a guide_menu call untouched"

t_case 'guide_menu never blocks and never creates a run directory on any refusal path'
assert_no_run_dir_and_status "$SCOURSH_EXIT_INCOMPLETE" 'the empty-item-list guard leaves no trace' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_menu "pick> "'

# ---------------------------------------------------------------------------
printf '\n-- guide_ask --\n'
# ---------------------------------------------------------------------------

t_case 'a blank line yields the default'
guide_ask 'Path [.]: ' '.' < <(printf '\n')
assert_eq '.' "$GUIDE_ASK_REPLY" 'default substituted for empty input'

t_case 'a typed answer overrides the default'
guide_ask 'Path [.]: ' '.' < <(printf 'src/app\n')
assert_eq 'src/app' "$GUIDE_ASK_REPLY" 'typed value wins'

t_case 'no default given and a blank line yields the empty string'
guide_ask 'Free text: ' < <(printf '\n')
assert_eq '' "$GUIDE_ASK_REPLY" 'default of default is empty'

t_case 'EOF is exit 2 with the documented message, never a blocking hang'
assert_no_run_dir_and_status "$SCOURSH_EXIT_USAGE" 'EOF on a free-text prompt refuses cleanly' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_ask "P: " "d"' < /dev/null
err=$(bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_ask "P: " "d"' < /dev/null 2>&1 1>/dev/null || true)
assert_contains "$err" 'input ended before the scan was configured; nothing ran' \
  'same EOF message as guide_menu - one vocabulary for "nothing ran"'

# ---------------------------------------------------------------------------
printf '\n-- guide_confirm --\n'
# ---------------------------------------------------------------------------

t_case 'a matching typed line returns 0 (true)'
assert_true "$(guide_confirm 'Type staging-api> ' 'staging-api' < <(printf 'staging-api\n') && echo 0 || echo 1)" \
  'exact match confirms'

t_case 'ANY non-matching typed line returns 1 (false) WITHOUT dying - this is a legitimate "no", not an error'
assert_true "$(guide_confirm 'Type staging-api> ' 'staging-api' < <(printf 'nope\n') && echo 1 || echo 0)" \
  'FAILS if a wrong answer were treated as fatal instead of a normal decline'
assert_true "$(guide_confirm 'Type staging-api> ' 'staging-api' < <(printf '\n') && echo 1 || echo 0)" \
  'a blank line is also just a non-match, not a default-accept'
assert_true "$(guide_confirm 'Type staging-api> ' 'staging-api' < <(printf 'staging-api-2\n') && echo 1 || echo 0)" \
  'a near-miss (extra trailing bytes) is still a non-match - exact byte equality only'

t_case 'no retry loop: a single wrong answer settles it (matches the design - "there is no retry loop")'
rc=0
( guide_confirm 'Type X> ' 'X' < <(printf 'zzz\nX\n') ) || rc=$?
assert_eq 1 "$rc" 'the second, would-be-correct line is never read - only one answer is consumed'

t_case 'EOF is exit 2 with the documented message, never a blocking hang'
assert_no_run_dir_and_status "$SCOURSH_EXIT_USAGE" 'EOF on a confirm prompt refuses cleanly' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_confirm "P: " "x"' < /dev/null

# ---------------------------------------------------------------------------
printf '\n-- SIGINT mid-flow --\n'
# ---------------------------------------------------------------------------
# See this file's own header for why a python3 wrapper is what actually
# delivers a working SIGINT to a backgrounded child at all.

if ! command -v python3 >/dev/null 2>&1; then
  printf -- '\n-- SKIPPED: no python3 on this host, so the real-SIGINT cases below did NOT run --\n'
else
  _GUIDE_SIGWRAP=$W/sigwrap.py
  cat >"$_GUIDE_SIGWRAP" <<'PY'
import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])
PY

  # `_guide_sigint_run SCRIPT` - starts SCRIPT (a small bash script that
  # prints READY to stderr once it is genuinely blocked on stdin, reading
  # from a read-write FIFO it holds open itself so it can never see a
  # spurious EOF - lib/core.sh's own msleep uses the identical idiom, for
  # the identical reason), waits for READY, sends SIGINT, and prints the
  # exit status.  Bounded throughout: never a bare `wait` that could hang
  # the suite forever if a regression reintroduces the blocking defect.
  _guide_sigint_run() {
    local script=$1 errfile=$2
    python3 "$_GUIDE_SIGWRAP" bash "$script" "$ROOT" >"$W/sigrun.out" 2>"$errfile" &
    local pid=$!
    local i
    for i in $(seq 1 50); do
      grep -q READY "$errfile" 2>/dev/null && break
      sleep 0.1
    done
    if ! grep -q READY "$errfile" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      printf '%s' 'NEVER_READY'
      return 0
    fi
    kill -INT "$pid"
    local rc=''
    for i in $(seq 1 25); do
      if ! kill -0 "$pid" 2>/dev/null; then
        # `wait`'s own exit status is the child's, and a bare (unguarded)
        # nonzero status here trips this suite's own ERR trap (lib/core.sh
        # is sourced by every script under test) even though a real
        # statement follows it - the `|| rc=$?` form is a TESTED context, so
        # it captures the same value without the diagnostic noise.
        rc=0
        wait "$pid" 2>/dev/null || rc=$?
        break
      fi
      sleep 0.2
    done
    if [[ -z $rc ]]; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      printf '%s' 'TIMED_OUT_STILL_BLOCKED'
      return 0
    fi
    printf '%s' "$rc"
  }

  # Each script's fifo is named per-PID ($$), not a shared literal: all three
  # scripts inherit the SAME exported SCOURSH_SCRATCH from this suite
  # process (a fresh child only creates its own when none is inherited -
  # lib/core.sh's scratch_init), and a child never OWNS that inherited
  # directory (scratch_is_owned_here checks pid), so it never cleans up its
  # own fifo on exit.  A shared literal name collided across runs
  # (`mkfifo: File exists`) before this was per-PID - the exact class of bug
  # lib/core.sh's own msleep/mutex code already names this pattern for.
  cat >"$W/baseline.sh" <<'EOF'
#!/usr/bin/env bash
ROOT=$1
source "$ROOT/lib/core.sh"
fifo=$SCOURSH_SCRATCH/blockfifo.$$
mkfifo "$fifo"
exec {fd}<>"$fifo"
printf 'READY\n' >&2
select x in aa bb; do break; done <&"$fd"
printf 'UNREACHABLE\n' >&2
EOF

  cat >"$W/menu.sh" <<'EOF'
#!/usr/bin/env bash
ROOT=$1
source "$ROOT/lib/guide.sh"
fifo=$SCOURSH_SCRATCH/blockfifo.$$
mkfifo "$fifo"
exec {fd}<>"$fifo"
printf 'READY\n' >&2
guide_menu 'pick> ' aa bb <&"$fd"
printf 'UNREACHABLE\n' >&2
EOF

  cat >"$W/ask.sh" <<'EOF'
#!/usr/bin/env bash
ROOT=$1
source "$ROOT/lib/guide.sh"
fifo=$SCOURSH_SCRATCH/blockfifo.$$
mkfifo "$fifo"
exec {fd}<>"$fifo"
printf 'READY\n' >&2
guide_ask 'Path: ' '.' <&"$fd"
printf 'UNREACHABLE\n' >&2
EOF

  t_case 'REPRODUCE THE DEFECT FIRST: a bare select under core_on_signal exits 5 on SIGINT'
  rc=$(_guide_sigint_run "$W/baseline.sh" "$W/baseline.err")
  assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
    'the pre-existing behaviour docs/STEP-GUIDE-PLAN.md measured: "SIGINT delivered while select is waiting produces exit 5" - proves this suite''s harness really can deliver a working SIGINT before trusting the fix below'

  t_case 'THE FIX: guide_menu blocked on the identical input exits 0, with the cancellation message'
  rc=$(_guide_sigint_run "$W/menu.sh" "$W/menu.err")
  assert_eq "$SCOURSH_EXIT_OK" "$rc" 'FAILS under the unguarded core_on_signal path proven above'
  assert_contains "$(cat "$W/menu.err")" 'Cancelled.  Nothing was scanned.' \
    'the documented cancellation message is printed'
  assert_not_contains "$(cat "$W/menu.err")" 'UNREACHABLE' \
    'guide_menu never returns control to its caller on this path'

  t_case 'guide_ask blocked on a read exits 0 on SIGINT, not 2 and not 5'
  rc=$(_guide_sigint_run "$W/ask.sh" "$W/ask.err")
  assert_eq "$SCOURSH_EXIT_OK" "$rc" 'the guided-scope trap covers guide_ask too, not only guide_menu'

  t_case 'no run directory is created by a SIGINT-cancelled prompt'
  assert_file_absent "$W/reports" 'nothing in this whole section ever calls run_init'
fi

t_summary guide
