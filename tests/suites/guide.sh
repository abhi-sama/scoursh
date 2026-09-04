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

# =============================================================================
printf '\n== docs/STEP-GUIDE-PLAN.md GUIDE-04: the DAST branch and the affirmation ==\n'
# =============================================================================
# G3 (target), G5 (intensity) and G6 (the limits router, the affirmation, and
# each raised limit as its own menu).  `_guide_dast_with_root` shadows
# SCOURSH_INSTALL_ROOT with `local` for the duration of one call - never a
# subshell, which would discard every GUIDE_DAST_* output write this file's
# own header comment warns a `$(...)` wrapper would swallow.
_guide_dast_with_root() {
  local SCOURSH_INSTALL_ROOT=$1
  shift
  "$@"
}

DW=$W/dast
mkdir -p "$DW/two-targets/config" "$DW/no-targets/config" "$DW/with-scanner-conf/config"

cat >"$DW/two-targets/config/scope.conf" <<'EOF'
id: staging-api
base-url: https://STAGING-API.fixture.example
allow-subdomains: false
allow-private-addresses: false

id: staging-web
base-url: https://staging-web.fixture.example:8443
allow-subdomains: false
allow-private-addresses: false
EOF

cp "$DW/two-targets/config/scope.conf" "$DW/with-scanner-conf/config/scope.conf"
cat >"$DW/with-scanner-conf/config/scanner.conf" <<'EOF'
id: scanner
request-budget: 20000
EOF

printf '\n-- G3: guide_dast_target_menu --\n'

t_case 'a well-formed multi-target scope.conf: item 1 selects the first id'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '1\n') 2>&1) || true
_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '1\n') 2>/dev/null
assert_eq staging-api "$GUIDE_DAST_TARGET" 'GUIDE_DAST_TARGET is the first configured id'

t_case 'the displayed tuple is the NORMALISED scheme://host:port, not the raw base-url string'
assert_contains "$out" 'staging-api    https://staging-api.fixture.example:443' \
  'FAILS if the raw (uppercase-host) base-url were printed verbatim instead of the http_url_normalize output - the plan requires the normalised tuple specifically so the menu and the gate can never disagree'
assert_contains "$out" 'staging-web    https://staging-web.fixture.example:8443' \
  'a non-default port survives normalisation into the displayed tuple'

t_case 'item 2 selects the second id'
_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '2\n') 2>/dev/null
assert_eq staging-web "$GUIDE_DAST_TARGET" 'GUIDE_DAST_TARGET is the second configured id'

t_case '"Back" (the last-but-one item) returns 1 rather than selecting a target'
rc=0
_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '4\n') 2>/dev/null || rc=$?
assert_eq 1 "$rc" 'FAILS if Back were treated as a selection'

t_case '"Authorise a new target" (GUIDE-05, not built here) refuses with one line and loops back to the same menu'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '3\n4\n') 2>&1) || true
rc=0
_guide_dast_with_root "$DW/two-targets" guide_dast_target_menu < <(printf '3\n4\n') 2>/dev/null || rc=$?
assert_contains "$out" 'not built in this version of' \
  'the refusal explains that authorising a target is not built yet'
assert_contains "$out" 'Which target?' \
  'FAILS if the refusal did not loop back to redisplay the SAME target menu (the second answer, "4" = Back, only makes sense against a second, real menu prompt)'
assert_eq 1 "$rc" 'the loop-back menu still honours a real "Back" answered after the refusal'

t_case 'a scope.conf naming no targets at all collapses to the "authorise / back / quit" menu'
out=$(_guide_dast_with_root "$DW/no-targets" guide_dast_target_menu < <(printf '2\n') 2>&1) || true
assert_contains "$out" 'no target of any kind' \
  'states plainly that scoursh ships with no target and no demo host'
rc=0
_guide_dast_with_root "$DW/no-targets" guide_dast_target_menu < <(printf '2\n') 2>/dev/null || rc=$?
assert_eq 1 "$rc" '"Back" on the empty-scope-conf menu also returns 1'

t_case '"Quit" on the empty-scope-conf menu exits 0 with the cancellation message and creates no run directory'
assert_status "$SCOURSH_EXIT_OK" 'FAILS if Quit propagated a non-zero exit or blocked' \
  bash -c 'source "'"$ROOT"'/lib/guide.sh"; SCOURSH_INSTALL_ROOT="'"$DW"'/no-targets"; guide_dast_target_menu' \
  < <(printf '3\n')
err=$(bash -c 'source "'"$ROOT"'/lib/guide.sh"; SCOURSH_INSTALL_ROOT="'"$DW"'/no-targets"; guide_dast_target_menu' \
  < <(printf '3\n') 2>&1 1>/dev/null)
assert_contains "$err" 'Cancelled.  Nothing was scanned.' 'the shared cancellation message, not a bespoke one'
assert_file_absent "$DW/no-targets/reports" 'no run directory materialised from Quit'

printf '\n-- G5: guide_dast_intensity_menu --\n'

t_case 'item order is CHECKS_INTENSITIES verbatim: 1=passive, 2=safe, 3=active'
guide_dast_intensity_menu staging-api < <(printf '1\n') 2>/dev/null
assert_eq passive "$GUIDE_DAST_INTENSITY" 'item 1 is passive'
guide_dast_intensity_menu staging-api < <(printf '2\n') 2>/dev/null
assert_eq safe "$GUIDE_DAST_INTENSITY" 'item 2 is safe'
guide_dast_intensity_menu staging-api < <(printf '3\n') 2>/dev/null
assert_eq active "$GUIDE_DAST_INTENSITY" 'item 3 is active'

t_case 'the target name is interpolated into the intensity prompt'
out=$(guide_dast_intensity_menu 'my-target-xyz' < <(printf '1\n') 2>&1)
assert_contains "$out" "push 'my-target-xyz'" 'FAILS if the target were hardcoded or omitted'

printf '\n-- G6: the limits router - passive asks NOTHING, structurally --\n'

t_case 'intensity=passive: guide_dast_limits_flow reads no further input and raises nothing'
guide_dast_limits_flow staging-api passive < /dev/null
assert_eq passive "$GUIDE_DAST_INTENSITY" 'intensity is unchanged'
assert_eq '' "$GUIDE_DAST_I_OWN_TARGET" 'no affirmation was ever asked'
assert_eq '' "$GUIDE_DAST_REQUESTS_PER_SECOND" 'no rate menu ran'
assert_eq '' "$GUIDE_DAST_REQUEST_BUDGET" 'no budget menu ran'
assert_eq false "$GUIDE_DAST_ALLOW_INTRUSIVE" 'no side-effecting-checks question ran'

printf '\n-- G6: the affirmation - numbers are interpolated from the same constants DAST-32 reads --\n'

_http_limit_ceiling_set requests-per-second
RPS_CEIL=$_HTTP_LIMIT_CEIL
_http_limit_ceiling_set request-budget
BUDGET_CEIL=$_HTTP_LIMIT_CEIL

t_case 'the rate menu offers the LIVE ceiling as its conservative default item, not a typed literal'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_rate_menu staging-api < <(printf '1\n') 2>&1)
assert_contains "$out" "1) $RPS_CEIL " \
  "FAILS if this were prose (\"4\") rather than \$(_guide_dast_rps_ceiling) - the ceiling read here is $RPS_CEIL"
_guide_dast_with_root "$DW/two-targets" guide_dast_rate_menu staging-api < <(printf '1\n') 2>/dev/null
assert_eq "$RPS_CEIL" "$GUIDE_DAST_REQUESTS_PER_SECOND" 'item 1 resolves to the live ceiling value'

t_case 'the budget menu offers the LIVE ceiling too'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_budget_menu staging-api < <(printf '1\n') 2>&1)
assert_contains "$out" "1) $BUDGET_CEIL " \
  "FAILS if this were prose (\"5000\") rather than \$(_guide_dast_budget_ceiling) - the ceiling read here is $BUDGET_CEIL"
_guide_dast_with_root "$DW/two-targets" guide_dast_budget_menu staging-api < <(printf '1\n') 2>/dev/null
assert_eq "$BUDGET_CEIL" "$GUIDE_DAST_REQUEST_BUDGET" 'item 1 resolves to the live ceiling value'

t_case '"No limit" (rate item 4) never emits a literal 0'
_guide_dast_with_root "$DW/two-targets" guide_dast_rate_menu staging-api < <(printf '4\n') 2>/dev/null
assert_eq "$_GUIDE_DAST_RPS_UNLIMITED" "$GUIDE_DAST_REQUESTS_PER_SECOND" \
  "FAILS if this were literal 0 - lib/http.sh's own _http_rps_milli_set/_http_decimal_is_zero refuse a genuinely-zero rate outright (\"permits no requests at all\"), so 0 here would turn the safest-reading menu choice into a dead run"
assert_ne 0 "$GUIDE_DAST_REQUESTS_PER_SECOND" 'never literal zero'

t_case "the budget menu's config/scanner.conf item appears only when the file sets a value different from the ceiling"
out=$(_guide_dast_with_root "$DW/with-scanner-conf" guide_dast_budget_menu staging-api < <(printf '2\n') 2>&1)
assert_contains "$out" '20000   - the value in your config/scanner.conf' \
  "the file's own request-budget: 20000 is offered as item 2"
_guide_dast_with_root "$DW/with-scanner-conf" guide_dast_budget_menu staging-api < <(printf '2\n') 2>/dev/null
assert_eq 20000 "$GUIDE_DAST_REQUEST_BUDGET" 'item 2 resolves to the file value'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_budget_menu staging-api < <(printf '2\n') 2>&1)
assert_not_contains "$out" 'your config/scanner.conf' \
  'no scanner.conf at all: the dynamic item is absent, and item 2 is the fixed 100000 choice'

t_case 'the intrusive-checks question defaults to No (item 1) and Yes is item 2'
guide_dast_intrusive_menu staging-api < <(printf '1\n') 2>/dev/null
assert_eq false "$GUIDE_DAST_ALLOW_INTRUSIVE" 'item 1 is No'
guide_dast_intrusive_menu staging-api < <(printf '2\n') 2>/dev/null
assert_eq true "$GUIDE_DAST_ALLOW_INTRUSIVE" 'item 2 is Yes'

t_case 'the affirmation trailing lines state what raising the limits does NOT do (this ticket''s own deliverable, not decoration)'
out=$(_guide_dast_with_root "$DW/two-targets" guide_dast_limits_flow staging-api active \
  < <(printf 'nope\n') 2>&1)
assert_contains "$out" 'This does NOT remove the request budget' 'the budget stays finite'
assert_contains "$out" 'This does NOT disable the failure-rate circuit breaker' 'the breaker stays on'
assert_contains "$out" 'This does NOT let scoursh talk to any host outside config/scope.conf' 'the scope gate is unaffected'
assert_contains "$out" 'This does NOT send a destructive payload' 'detection-only, unconditionally'
assert_contains "$out" 'This does NOT turn on side-effecting checks' 'that is a separate question'

printf '\n-- G6: guide_dast_limits_flow - the matched/unmatched affirmation router --\n'

t_case 'an UNMATCHED affirmation reverts intensity to passive and asks nothing further - no retry loop'
_guide_dast_with_root "$DW/two-targets" guide_dast_limits_flow staging-api active < <(printf 'nope\n') 2>/dev/null
assert_eq passive "$GUIDE_DAST_INTENSITY" 'FAILS if a second attempt at the affirmation were offered instead of reverting'
assert_eq '' "$GUIDE_DAST_I_OWN_TARGET" 'no affirmation was recorded'
assert_eq '' "$GUIDE_DAST_REQUESTS_PER_SECOND" 'the rate menu never ran'
assert_eq '' "$GUIDE_DAST_REQUEST_BUDGET" 'the budget menu never ran'
assert_eq false "$GUIDE_DAST_ALLOW_INTRUSIVE" 'the intrusive-checks question never ran'

t_case 'a MATCHED affirmation at intensity=safe unlocks the rate and budget menus but never the intrusive question'
_guide_dast_with_root "$DW/two-targets" guide_dast_limits_flow staging-api safe \
  < <(printf 'staging-api\n1\n1\n') 2>/dev/null
assert_eq safe "$GUIDE_DAST_INTENSITY" 'intensity is unchanged on a match'
assert_eq staging-api "$GUIDE_DAST_I_OWN_TARGET" 'the affirmation is recorded'
assert_eq "$RPS_CEIL" "$GUIDE_DAST_REQUESTS_PER_SECOND" 'the rate menu ran (item 1: the live ceiling)'
assert_eq "$BUDGET_CEIL" "$GUIDE_DAST_REQUEST_BUDGET" 'the budget menu ran (item 1: the live ceiling)'
assert_eq false "$GUIDE_DAST_ALLOW_INTRUSIVE" "FAILS if the intrusive question ran at intensity=safe - the plan requires it 'only when intensity is active'"

t_case 'a MATCHED affirmation at intensity=active additionally asks the intrusive-checks question'
_guide_dast_with_root "$DW/two-targets" guide_dast_limits_flow staging-api active \
  < <(printf 'staging-api\n1\n1\n2\n') 2>/dev/null
assert_eq true "$GUIDE_DAST_ALLOW_INTRUSIVE" 'the fourth answer (item 2 = Yes) reached the intrusive question'

printf '\n-- guide_dast_configure: the whole G3->G5->G6 flow, and the acceptance test named in the plan --\n'

t_case "THE ACCEPTANCE TEST: picking item 1 at every FIXED menu (target #1, then passive) produces an argv with no --i-own-target, no --allow-intrusive and no raised limit"
_guide_dast_with_root "$DW/two-targets" guide_dast_configure < <(printf '1\n1\n') 2>/dev/null
assert_eq '--target staging-api' "${GUIDE_DAST_ARGV[*]}" \
  'FAILS if any raised flag leaked through on the path of least resistance - the whole point of the router (section 6c) is that G6 asks nothing at all when intensity stays passive'
assert_not_contains "${GUIDE_DAST_ARGV[*]}" '--i-own-target' 'no affirmation flag'
assert_not_contains "${GUIDE_DAST_ARGV[*]}" '--allow-intrusive' 'no intrusive flag'
assert_not_contains "${GUIDE_DAST_ARGV[*]}" '--requests-per-second' 'no rate flag'
assert_not_contains "${GUIDE_DAST_ARGV[*]}" '--request-budget' 'no budget flag'
assert_not_contains "${GUIDE_DAST_ARGV[*]}" '--intensity' 'passive is the default and is never spelled out'

t_case 'a fully raised, affirmed, intrusive run composes every flag exactly once, in a scan_parse_args-legal shape'
_guide_dast_with_root "$DW/two-targets" guide_dast_configure \
  < <(printf '1\n3\nstaging-api\n2\n1\n2\n') 2>/dev/null
assert_eq '--target staging-api --intensity active --i-own-target staging-api --requests-per-second 20 --request-budget 5000 --allow-intrusive' \
  "${GUIDE_DAST_ARGV[*]}" 'the exact composed argv for target 1, intensity active, matched affirmation, rate item 2, budget item 1, intrusive yes'
# The round-trip of this exact argv through scan_parse_args/_scan_check_affirmation
# is asserted in tests/suites/scan.sh instead (scan_parse_args lives in scan.sh,
# which this suite deliberately does not source - it tests lib/guide.sh alone).

t_case "guide_dast_configure returns 1 on G3's own Back, before ever reaching G5"
rc=0
_guide_dast_with_root "$DW/two-targets" guide_dast_configure < <(printf '4\n') 2>/dev/null || rc=$?
assert_eq 1 "$rc" 'FAILS if G5 (intensity) were reached after Back at G3'
# ---------------------------------------------------------------------------
# guide_g4_authorize_target (docs/STEP-GUIDE-PLAN.md GUIDE-05, step G4) - the
# interactive screen.  The pure half it delegates to (id derivation, record
# rendering, the append-only writer) is tested directly, with no terminal
# I/O at all, in tests/suites/guide-scope.sh; this section drives only the
# prompting - what gets asked, in what order, and what a cancel/EOF/mismatch
# does - each case named for the reading it fails under, per AGENTS.md.
# ---------------------------------------------------------------------------
printf '\n-- guide_g4_authorize_target --\n'

G4W=$SCOURSH_SCRATCH/guide-g4
mkdir -p "$G4W"

# No test here ever resolves a real name: pub.fixture.example is a stand-in
# public host, internal.fixture.example a stand-in that resolves private.
_g4_test_resolve() {
  case $1 in
    pub.fixture.example) printf '93.184.216.34' ;;
    internal.fixture.example) printf '127.0.0.1' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_g4_test_resolve

t_case 'happy path: a public host is written, confirmed by its own hostname'
happy=$G4W/happy.conf
rc=0
guide_g4_authorize_target "$happy" \
  < <(printf 'https://pub.fixture.example/\npub.fixture.example\n') \
  >"$G4W/happy.out" 2>"$G4W/happy.err" || rc=$?
assert_eq '0' "$rc" 'a correct confirmation succeeds'
assert_eq 'pub-fixture-example-443' "$GUIDE_G4_TARGET_ID" \
  'FAILS if the id derivation is not wired through: dots and the port colon become dashes'
records_clear scope
config_scope_load "$happy"
assert_eq '1' "$(records_count scope)" 'exactly one record was written'
assert_eq 'https://pub.fixture.example/' "$(records_field scope 0 base-url)" \
  'base-url is written verbatim, the exact bytes typed at the first prompt'
assert_eq 'false' "$(records_field_or scope 0 allow-subdomains false)" 'allow-subdomains is always false'
assert_eq 'false' "$(records_field_or scope 0 allow-private-addresses false)" \
  'a public host never sets allow-private-addresses'

t_case 'a blank URL cancels cleanly - return 1, nothing written'
blank=$G4W/blank.conf
rc=0
guide_g4_authorize_target "$blank" < <(printf '\n') >/dev/null 2>&1 || rc=$?
assert_eq '1' "$rc" 'a blank answer is a clean cancel, never fatal'
assert_file_absent "$blank" 'no file is created for a cancelled authorisation'

t_case 'a URL that does not parse cancels cleanly'
malformed=$G4W/malformed.conf
rc=0
guide_g4_authorize_target "$malformed" < <(printf 'not-a-url-at-all\n') >/dev/null 2>&1 || rc=$?
assert_eq '1' "$rc" 'an unparseable URL is refused, not fatal'
assert_file_absent "$malformed" 'nothing is written'

t_case 'a confirmation that does not match the host name cancels, and writes nothing'
mismatch=$G4W/mismatch.conf
rc=0
guide_g4_authorize_target "$mismatch" \
  < <(printf 'https://pub.fixture.example/\nnope\n') >/dev/null 2>&1 || rc=$?
assert_eq '1' "$rc" \
  'FAILS if a non-matching confirmation is treated as yes: G4 is "the most dangerous screen in the whole design"'
assert_file_absent "$mismatch" 'a mismatched confirmation writes nothing'

t_case 'EOF at the very first prompt is exit 2, never a silent abort'
# guide_ask's own EOF path calls `die`, which is a real `exit` - calling
# guide_g4_authorize_target directly in THIS process would kill the whole
# suite before `|| rc=$?` ever ran, exactly like guide_ask/guide_confirm's
# own EOF cases above; a subprocess is what lets the exit be observed.
eofcase=$G4W/eof.conf
rc=0
bash -c 'source "'"$ROOT"'/lib/guide.sh"; guide_g4_authorize_target "$1"' _ "$eofcase" \
  </dev/null >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$rc" 'guide_ask''s own EOF handling applies here too'
assert_file_absent "$eofcase" 'nothing is written on EOF'

t_case 'a hostname that resolves private is offered the literal instead, and accepting it may set allow-private-addresses'
privoffer=$G4W/privoffer.conf
rc=0
guide_g4_authorize_target "$privoffer" \
  < <(printf 'https://internal.fixture.example/\nhttps://127.0.0.1/\nyes\n127.0.0.1\n') \
  >"$G4W/privoffer.out" 2>"$G4W/privoffer.err" || rc=$?
assert_eq '0' "$rc" 'accepting the literal substitution and then the private-address confirmation succeeds'
assert_eq 't-127-0-0-1-443' "$GUIDE_G4_TARGET_ID" \
  'the WRITTEN target is the literal, never the original hostname'
records_clear scope
config_scope_load "$privoffer"
assert_eq 'https://127.0.0.1/' "$(records_field scope 0 base-url)" \
  'FAILS if the original hostname URL is written instead of the retyped literal (docs/STEP-GUIDE-PLAN.md G4 correction 4)'
assert_eq 'true' "$(records_field_or scope 0 allow-private-addresses false)" \
  'the operator explicitly typed yes to allow it'

t_case 'declining the literal-retype offer cancels cleanly - a hostname is NEVER written with allow-private-addresses'
privdecline=$G4W/privdecline.conf
rc=0
guide_g4_authorize_target "$privdecline" \
  < <(printf 'https://internal.fixture.example/\n\n') >/dev/null 2>&1 || rc=$?
assert_eq '1' "$rc" 'a blank answer to the retype offer is a clean cancel'
assert_file_absent "$privdecline" 'nothing is written'

t_case 'a literal typed directly, with the private-address question declined, still writes - just with allow-private-addresses: false'
privliteral=$G4W/privliteral.conf
rc=0
guide_g4_authorize_target "$privliteral" \
  < <(printf 'https://127.0.0.1:9443/\nno\n127.0.0.1\n') \
  >/dev/null 2>"$G4W/privliteral.err" || rc=$?
assert_eq '0' "$rc" 'declining allow-private-addresses does not cancel the whole write'
records_clear scope
config_scope_load "$privliteral"
assert_eq 'false' "$(records_field_or scope 0 allow-private-addresses false)" \
  'FAILS if a declined confirmation is read as yes'

t_case 'a collision with an id already in the file is disambiguated with -2, end to end'
collide=$G4W/collide.conf
cat >"$collide" <<'EOF'
id: pub-fixture-example-443
base-url: https://pub.fixture.example
allow-subdomains: false
allow-private-addresses: false
EOF
rc=0
guide_g4_authorize_target "$collide" \
  < <(printf 'https://pub.fixture.example/other\npub.fixture.example\n') \
  >/dev/null 2>&1 || rc=$?
assert_eq '0' "$rc" 'a coincidental id collision is disambiguated, not refused'
assert_eq 'pub-fixture-example-443-2' "$GUIDE_G4_TARGET_ID" \
  'FAILS if the -2 disambiguation is not reached from the interactive path'

t_summary guide
