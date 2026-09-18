#!/usr/bin/env bash
# tests/suites/run-tests-stage.sh - the whole-tree `shellcheck` STAGE inside
# tests/run-tests.sh, as opposed to the suites and linters it also runs.
#
# WHY THIS SUITE EXISTS.  The stage is the last thing a full run does and the
# slowest thing in it by a wide margin, so for a long time nobody could iterate
# on it: it could not finish at all.  `shellcheck -x` inlines every `source`
# statically, and this tree's diamond-shaped source graph re-expanded
# lib/http.sh and lib/core.sh up to 29 times for a single entry point, which
# blew past the stage's own per-process watchdog budget.  While that stood,
# `tests/run-tests.sh` could never exit 0, so "merge when the suite is green"
# was unachievable and every ticket had to hand-reason about which failure was
# theirs.  Two of the stage's own properties are what stop that recurring, and
# both are asserted here, in the direction that fails:
#
#   1. It prints a VERDICT LINE on every exit path.  A stage that ends after
#      nothing but its header - which is what a `set -E` abort, a ^C or a
#      SIGTERM used to produce - is indistinguishable in a log from a stage
#      that ran and had nothing to say.  Section D kills a real run mid-stage
#      and requires the verdict anyway; it fails against the pre-fix stage,
#      which printed nothing.
#   2. A file it could NOT check is reported distinctly from a file it checked
#      and found clean, and never rounds up to a pass.  Sections B and C pin
#      both directions, because the naive reading of each is the other's bug:
#      merge them and an unmeasured file reads as evidence of cleanliness,
#      which is the single most expensive way for a linter to be wrong.
#
# HOW IT RUNS IN SECONDS.  Every case drives the REAL tests/run-tests.sh as a
# real subprocess, with:
#
#   * a STUB `shellcheck` first on PATH, so no real analysis happens and the
#     per-file exit status is whatever the case wants to test;
#   * `tests/run-tests.sh shellcheck`, the named stage target, so the ~50
#     suites and linters do not run (this file included - without it, this
#     suite would recurse);
#   * SCOURSH_SHELLCHECK_FILE_LIST pointing at a two-file fixture list, so the
#     stage does not walk the real tree.  It is used PURELY as a test seam
#     here (an unsharded `tests/run-tests.sh shellcheck`, which is what every
#     case up to the `--shard` section below drives, still checks every *.sh
#     file when it is left unset) - the `--shard` section further down in
#     this file exercises this SAME variable's other, real caller: a sharded
#     run setting it itself, internally, to hand `sc_stage` exactly the files
#     that shard owns.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

RUNNER=$ROOT/tests/run-tests.sh
W=$SCOURSH_SCRATCH/run-tests-stage
rm -rf "$W"; mkdir -p "$W/bin" "$W/tree"

# Two fixture files.  Their CONTENT is irrelevant - the stub decides every
# verdict - but they must exist, because the stage runs `shellcheck` on real
# paths and a case that passed only because the file was missing would prove
# nothing.
printf '#!/usr/bin/env bash\ntrue\n' > "$W/tree/alpha.sh"
printf '#!/usr/bin/env bash\ntrue\n' > "$W/tree/beta.sh"
printf '%s\n%s\n' "$W/tree/alpha.sh" "$W/tree/beta.sh" > "$W/filelist"

# The stub.  STUB_PLAN is a space-separated `basename:action` list; the action
# is either an exit status to return, or `sleep` (stay alive, so the watchdog
# and the signal cases have a live process to act on).  Anything unlisted
# exits 0.
cat > "$W/bin/shellcheck" <<'STUB'
#!/usr/bin/env bash
# The stage probes `shellcheck --version` once, to record it next to the
# verdict.  That probe carries no file and must not be counted as one: it is
# what made section M's argc probe read 7 invocations for 6 files.
for a in "$@"; do
  if [ "$a" = --version ]; then
    printf 'ShellCheck - shell script analysis tool\nversion: 0.0.0-stub\n'
    exit 0
  fi
done
f=
nf=0
skip=0
for a in "$@"; do
  # `-s bash` takes a VALUE, and counting that value as a file is how the
  # first draft of section M's argc probe read every one-file invocation as
  # carrying two.
  if [[ $skip == 1 ]]; then skip=0; continue; fi
  case $a in
    -s) skip=1 ;;
    -*|--) ;;
    *) f=$a; nf=$((nf + 1)) ;;
  esac
done
b=${f##*/}
# One line per invocation recording how many FILES it was handed.  Section K
# reads this: "one file per shellcheck invocation" is a property of the CALL,
# and nothing in the stage's own output can distinguish it from a batch.
[[ -n ${STUB_ARGC_LOG:-} ]] && printf '%s\n' "$nf" >>"$STUB_ARGC_LOG"
for entry in ${STUB_PLAN:-}; do
  name=${entry%%:*}; action=${entry#*:}
  if [[ $name == "$b" ]]; then
    if [[ $action == sleep ]]; then
      printf 'stub: holding %s\n' "$b"
      : > "${STUB_ALIVE:-/dev/null}"
      sleep 30
      exit 0
    fi
    printf 'stub: %s exits %s\n' "$b" "$action"
    exit "$action"
  fi
done
exit 0
STUB
chmod +x "$W/bin/shellcheck"

# Runs the real runner's stage with the stub in front of PATH.  Captures
# combined output (the verdict goes to stdout, the roll-ups to stderr) and the
# exit status, and never lets a non-zero status abort this suite.
#
# GITHUB_ACTIONS IS CLEARED ON EVERY ONE OF THESE INVOCATIONS, AND THAT IS
# LOAD-BEARING RATHER THAN TIDINESS.  The stage has two paths - the
# memory-derived, watchdog-guarded model a contributor gets, and the
# no-watchdog/no-skip model a hosted runner gets - and it picks between them
# by reading GITHUB_ACTIONS.  Everything from here to section J tests the
# FIRST of those, so when this suite itself runs ON CI it would otherwise
# silently drive the SECOND and assert the first one's contract against it.
# That is not hypothetical: it is why `macos-latest` exited 1 on run
# 33677872951 with 13 failures in this file while the stage it was testing
# was working correctly.  Section K below drives the CI path deliberately,
# with GITHUB_ACTIONS set, so neither path is left untested.
_stage() {
  local out status=0
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS='' \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

# ===========================================================================
printf '== A: every file checked and clean -> passed ==\n'
# ===========================================================================
STUB_PLAN='' _stage
assert_eq 0 "$STAGE_STATUS" 'a clean stage exits 0'
assert_contains "$STAGE_OUT" '--- shellcheck passed' 'and says so in a verdict line'
assert_not_contains "$STAGE_OUT" 'could NOT be checked' \
  'and claims nothing was unmeasurable - FAILS if a clean file is filed under the unmeasured roll-up'
assert_contains "$STAGE_OUT" 'SCOURSH_SHELLCHECK_FILE_LIST' \
  'the stage states that its file list was overridden, so a run driven by the test seam can never be mistaken for a whole-tree run'

# ===========================================================================
printf '== B: a file CHECKED with findings -> FAILED, and it is not called unmeasurable ==\n'
# ===========================================================================
# An exit status of 1 from shellcheck is "I looked at this file and I have
# something to say".  (This sentence deliberately does not START with the word
# `shellcheck`: a comment line that does is parsed as a DIRECTIVE - SC1072.)
STUB_PLAN='beta.sh:1' _stage
assert_ne 0 "$STAGE_STATUS" 'a stage with findings exits non-zero'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' 'and prints the FAILED verdict'
assert_contains "$STAGE_OUT" 'checked and reported findings' \
  'and reports it as a CHECKED file with findings'
assert_not_contains "$STAGE_OUT" 'could NOT be checked' \
  'and NOT as an unmeasurable one - FAILS under collapsing every non-zero exit into one bucket, which would make a real finding look like a linter that never ran'

# ===========================================================================
printf '== C: a file that could NOT be checked is reported distinctly ==\n'
# ===========================================================================
# An exit status of 2 is "I could not process this file at all".  It produces no
# result, so it must never round up to a pass, and it must not be filed as a
# finding either: nobody can fix a finding that was never made.
STUB_PLAN='beta.sh:2' _stage
assert_ne 0 "$STAGE_STATUS" 'an unmeasurable file fails the stage on its own'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' 'and the verdict line says so'
assert_contains "$STAGE_OUT" 'could NOT be checked' \
  'and it is reported as unmeasured, not clean - FAILS under treating "shellcheck said nothing" as "shellcheck found nothing"'
assert_contains "$STAGE_OUT" 'beta.sh' 'and the roll-up names the file'
assert_not_contains "$STAGE_OUT" 'checked and reported findings' \
  'and does NOT claim a finding was reported for it'

# ===========================================================================
printf '== C2: a HOST-PRESSURE kill names that cause, and is not a finding ==\n'
# ===========================================================================
# The free-memory floor is the cheaper of the stage's two kill paths to drive
# deterministically: set the floor absurdly high and the biggest live process
# is killed on the first sample, without this test having to allocate gigabytes
# to trip the per-process budget.
#
# The stage's two kill causes MUST be distinguishable in the output, which is
# this ticket's acceptance criterion 3 - an unattributable kill is the defect,
# not merely a symptom of it.  This case pins the HOST-PRESSURE arm; section H
# pins the OVER-BUDGET arm, and each asserts the other's wording is ABSENT, so
# neither can be satisfied by a stage that prints one generic message for both.
# The pre-fix stage printed `watchdog killed pid N (file)` for both causes and
# fails both halves.
C2_ALIVE=$W/alive-c2
rm -f "$C2_ALIVE"
C2_OUT=$(PATH=$W/bin:$PATH \
      GITHUB_ACTIONS='' \
      SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
      SCOURSH_SHELLCHECK_FREE_FLOOR_GB=9999999 \
      STUB_PLAN='beta.sh:sleep' STUB_ALIVE=$C2_ALIVE \
      bash "$RUNNER" shellcheck 2>&1) || true
if command -v ps >/dev/null 2>&1; then
  assert_contains "$C2_OUT" '--- shellcheck FAILED' 'a watchdog kill still reaches a verdict line'
  assert_contains "$C2_OUT" 'could NOT be checked' \
    'and the killed file is reported as unmeasured - FAILS under recording it as a shellcheck finding, which would send someone hunting for a defect in a file that was never analysed'
  assert_contains "$C2_OUT" 'HOST MEMORY PRESSURE' \
    'and the message names HOST MEMORY PRESSURE as the cause - FAILS under one generic "watchdog killed" line for both causes, which is the unattributable kill this ticket was filed for'
  assert_not_contains "$C2_OUT" 'OVER BUDGET' \
    'and does NOT blame the file for exceeding its own budget, which it did not - FAILS under attributing every kill to the file that happened to be running'
  assert_contains "$C2_OUT" 'not this file' \
    'and says in so many words that the file was not the cause'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== D: a stage killed mid-run STILL prints a verdict line ==\n'
# ===========================================================================
# This is the case this whole rework was filed for.  A `set -E` abort, a ^C and
# a SIGTERM all end the stage without reaching its own verdict line, and bash
# does not run an EXIT trap for an untrapped SIGTERM - so the pre-fix stage
# printed its header and then nothing at all, which reads in a log exactly like
# a stage that ran and was happy.  SIGTERM is used here because it is the one
# of the three that can be delivered from outside, deterministically.
D_ALIVE=$W/alive-d
rm -f "$D_ALIVE"
D_OUT=$W/d.out
: > "$D_OUT"
PATH=$W/bin:$PATH \
  GITHUB_ACTIONS='' \
  SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
  STUB_PLAN='alpha.sh:sleep' STUB_ALIVE=$D_ALIVE \
  bash "$RUNNER" shellcheck >"$D_OUT" 2>&1 &
D_PID=$!

# Wait for the stage to be genuinely INSIDE the run before signalling it:
# signalling too early would kill it before the header and the case would pass
# for the wrong reason.
D_WAITED=0
while [[ ! -e $D_ALIVE ]] && (( D_WAITED < 150 )); do
  sleep 0.1
  D_WAITED=$(( D_WAITED + 1 ))
done
assert_file_exists "$D_ALIVE" 'the stage really did start checking before the signal was sent'

kill -TERM "$D_PID" 2>/dev/null || true
D_STATUS=0
wait "$D_PID" 2>/dev/null || D_STATUS=$?
D_TEXT=$(cat "$D_OUT")
pkill -f "$W/bin/shellcheck" 2>/dev/null || true

assert_contains "$D_TEXT" '--- shellcheck FAILED' \
  'a SIGTERMed stage still prints a verdict line - FAILS against a stage whose verdict sits only on the straight-line path, which printed its header and nothing else'
assert_contains "$D_TEXT" 'SIGTERM' \
  'and the verdict says the stage ended on a signal rather than reaching a real result'
assert_ne 0 "$D_STATUS" 'and the run exits non-zero'

# ===========================================================================
printf '== E: the stage is reachable on its own, and an unknown name still fails ==\n'
# ===========================================================================
assert_contains "$(bash "$RUNNER" --list)" 'stages:  shellcheck' \
  '--list names the stage, so `tests/run-tests.sh shellcheck` is discoverable rather than folklore'
E_STATUS=0
bash "$RUNNER" no-such-thing-at-all >/dev/null 2>&1 || E_STATUS=$?
assert_eq 2 "$E_STATUS" 'an unknown name is still a usage error, not a silently skipped stage'

# ===========================================================================
printf '== F: errexit is LIVE inside the stage body ==\n'
# ===========================================================================
# The stage used to be top-level code under `set -Eeuo pipefail`; turning it
# into a function risked losing that, because bash disables errexit for the
# WHOLE BODY of a function invoked in an `A || B` list - not just for the call
# (bash manual, "The Set Builtin").  So `sc_stage` is invoked as a plain
# command and reports through SC_STAGE_STATUS.
#
# This case proves the strictness is really there, by breaking something the
# stage has no `||` guard on: a stub `mktemp` that always fails, so
# `sc_shard_dir=$(mktemp -d)` returns non-zero.  Shipped, that aborts the
# runner and the EXIT trap still names what happened.  Under the `||` call
# site it does NOT abort - measured: the stage carries on with an empty
# $sc_shard_dir, reports both files as "checked and reported findings" when
# neither was ever checked (an AC5 violation manufactured out of thin air),
# and the runner then prints `all green` and exits 0.
mkdir -p "$W/bin-mktemp"
cp "$W/bin/shellcheck" "$W/bin-mktemp/shellcheck"
printf '#!/usr/bin/env bash\nexit 1\n' > "$W/bin-mktemp/mktemp"
chmod +x "$W/bin-mktemp/mktemp"

F_STATUS=0
F_OUT=$(PATH=$W/bin-mktemp:$PATH \
        GITHUB_ACTIONS='' \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        bash "$RUNNER" shellcheck 2>&1) || F_STATUS=$?

assert_ne 0 "$F_STATUS" \
  'an unexpected internal non-zero aborts the runner - FAILS under `sc_stage || failed+=(...)`, which disables errexit for the whole body and lets the run finish `all green` with exit 0'
assert_contains "$F_OUT" '--- shellcheck FAILED' 'and a verdict line is still printed'
assert_contains "$F_OUT" 'an unexpected non-zero exit' \
  'and the EXIT trap arm for it is REACHABLE and names the cause - FAILS under the `||` spelling, where that arm can never fire and the trap documents a protection that does not exist'
assert_not_contains "$F_OUT" 'checked and reported findings' \
  'and no file is claimed to have been checked - FAILS under the `||` spelling, which reported findings against two files shellcheck never ran on'

# ===========================================================================
printf '== G: available memory is AVAILABLE memory, not the free list ==\n'
# ===========================================================================
# THE ROOT CAUSE.  The stage used to read macOS `Pages free` as "available
# memory".  That is the FREE LIST, which Darwin holds near a low-water mark and
# refills lazily by reclaiming inactive pages - it does not grow with the size
# of the machine.  Measured on the 64GB host this was fixed on: 6GB reported
# where 36GB was genuinely available, and it stayed pinned near 6GB.  Every
# number downstream inherited that 6x understatement, which is why an 8GB, a
# 27GB and a 64GB host all failed in the same way.
#
# Driven here through a stub `vm_stat` so the numbers are fixed rather than
# whatever this machine happens to be doing.  The stub reports 1GB free but
# 20GB inactive, 1GB purgeable and 2GB speculative - all reclaimable on demand
# - so the honest answer is 24GB and the old reading's answer is 1GB.
if [[ -r /proc/meminfo ]]; then
  printf 'SKIPPED (Linux: this host has /proc/meminfo, so MemAvailable is read and vm_stat is never consulted)\n'
else
  mkdir -p "$W/bin-vm"
  cp "$W/bin/shellcheck" "$W/bin-vm/shellcheck"
  # 16384-byte pages: 65536 pages = 1GB.
  cat > "$W/bin-vm/vm_stat" <<'VMSTAT'
#!/usr/bin/env bash
cat <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                    65536.
Pages active:                                1000000.
Pages inactive:                              1310720.
Pages speculative:                            131072.
Pages throttled:                                   0.
Pages wired down:                             200000.
Pages purgeable:                               65536.
EOF
VMSTAT
  chmod +x "$W/bin-vm/vm_stat"

  G_OUT=$(PATH=$W/bin-vm:$PATH \
          GITHUB_ACTIONS='' \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=64 \
          STUB_PLAN='' bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$G_OUT" '24GB available' \
    'free + inactive + purgeable + speculative is reported as available - FAILS under the shipped `Pages free` reading, which reports 1GB here and understated a real 64GB host by 6x'
  assert_not_contains "$G_OUT" '1GB available' \
    'and the free list alone is NOT what gets reported'
fi

# ===========================================================================
printf '== H: an OVER-BUDGET kill names the FILE as the cause ==\n'
# ===========================================================================
# The other half of acceptance criterion 3, and the mirror of section C2.  The
# real budgets are whole GB and a stub uses a few MB, so SCOURSH_SHELLCHECK_
# BUDGET_KB is the seam that makes this arm reachable in a test at all; it is
# never set by a real run.  Every process exceeds a 100KB budget, in both
# passes, so both files end up over budget and neither is ever a finding.
if command -v ps >/dev/null 2>&1; then
  H_OUT=$(PATH=$W/bin:$PATH \
          GITHUB_ACTIONS='' \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_BUDGET_KB=100 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-h \
          bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$H_OUT" 'OVER BUDGET' \
    'the message names OVER BUDGET as the cause - FAILS under one generic kill message shared with host pressure'
  assert_contains "$H_OUT" 'not host memory pressure' \
    'and says explicitly that host pressure was NOT the cause, so the two are never confused'
  assert_not_contains "$H_OUT" 'HOST MEMORY PRESSURE' \
    'and does NOT claim host pressure - FAILS under a stage that attributes every kill to whichever cause it checks first'
  assert_not_contains "$H_OUT" 'checked and reported findings' \
    'and a killed file is never filed as a shellcheck finding'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== I: a file too big for this host is SKIPPED by name, and still exits 0 ==\n'
# ===========================================================================
# Acceptance criterion 5, and the ticket's own title.  A file this host cannot
# supply the memory for is a fact about the MACHINE, the same class as
# `shellcheck` not being installed - so it must be named, counted and carried
# into the run's last line, but it must NOT fail the stage, because a stage
# that can never exit 0 is the thing this ticket was filed to end.  Both
# directions matter and each is the other's bug: report it as a failure and
# `pnpm test` can never pass on a small host; report it as nothing and 19
# unmeasured files read as 19 clean ones.
if command -v ps >/dev/null 2>&1; then
  I_STATUS=0
  I_OUT=$(PATH=$W/bin:$PATH \
          GITHUB_ACTIONS='' \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_BUDGET_KB=100 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-i \
          bash "$RUNNER" shellcheck 2>&1) || I_STATUS=$?
  assert_eq 0 "$I_STATUS" \
    'a host-capacity skip does NOT fail the stage - FAILS under the shipped stage, where an unmeasurable file always fails and so `tests/run-tests.sh` could never exit 0 on any host'
  assert_contains "$I_OUT" 'SKIPPED' 'and the skip is announced'
  assert_contains "$I_OUT" 'alpha.sh' 'and every skipped file is named'
  assert_contains "$I_OUT" 'beta.sh' 'and every skipped file is named'
  assert_contains "$I_OUT" 'were NOT checked' \
    'and the stage states plainly that they were not checked - FAILS under a silent omission, which is the false green criterion 5 forbids'
  assert_contains "$I_OUT" '--- shellcheck passed' 'the verdict line is a pass'
  assert_contains "$I_OUT" 'host too small' 'but it carries the reason on the verdict line itself'
  assert_contains "$I_OUT" 'NOT a full pass' \
    "and the run's LAST line refuses to say a bare \`all green\` - FAILS under printing \`all green\` for a run that skipped files, which is the same false green one level up"
  assert_not_contains "$I_OUT" 'could NOT be checked' \
    'and a host-size skip is not filed under the unmeasured roll-up, which is for results this stage should have got and did not'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== J: jobs x budget <= headroom, on an 8GB, a 27GB and a 64GB host ==\n'
# ===========================================================================
# Acceptance criterion 2: "a fix that only works on the machine you tested is
# not a fix".  SCOURSH_SHELLCHECK_FORCE_{TOTAL,AVAIL}_GB drive the arithmetic
# over three host shapes from this one machine, and the invariant is checked by
# PARSING the numbers the stage prints rather than by matching a fixed string -
# so it cannot be satisfied by a stage that prints a plausible line and then
# runs something else.
#
# The shipped arithmetic fails this: it divided by 2 and then by a fixed 12GB
# budget, which yields 0 (clamped to 1 job) on every host under 24GB of
# headroom, while leaving the budget at 12GB - promising one process 12GB on a
# host with 3GB to give.  On the 8GB row below that is a 4x overcommit.
_j_host() {
  local total=$1 avail=$2 want_reserve=$3 want_headroom=$4 out line
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS='' \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=$total \
        SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=$avail \
        STUB_PLAN='' bash "$RUNNER" shellcheck 2>&1) || true

  assert_contains "$out" "host ${total}GB total, ${avail}GB available, ${want_reserve}GB reserved -> ${want_headroom}GB headroom" \
    "${total}GB host: reserve is max(2, total/8) = ${want_reserve}GB and headroom is ${want_headroom}GB"

  # Every pass line must satisfy jobs x budget <= headroom.
  local seen=0
  while IFS= read -r line; do
    [[ $line == *"parallel x"* ]] || continue
    seen=$(( seen + 1 ))
    local jobs budget commit headroom
    jobs=$(printf '%s\n' "$line" | sed -n 's/.*, \([0-9]*\) parallel x.*/\1/p')
    budget=$(printf '%s\n' "$line" | sed -n 's/.*parallel x \([0-9]*\)GB.*/\1/p')
    commit=$(printf '%s\n' "$line" | sed -n 's/.*= \([0-9]*\)GB of.*/\1/p')
    headroom=$(printf '%s\n' "$line" | sed -n 's/.*of \([0-9]*\)GB headroom.*/\1/p')
    assert_eq "$commit" "$(( jobs * budget ))" \
      "${total}GB host: the committed total the stage prints really is jobs x budget"
    if (( commit <= headroom )); then
      _t_ok "${total}GB host: ${jobs} x ${budget}GB = ${commit}GB fits in ${headroom}GB headroom"
    else
      _t_no "${total}GB host: ${jobs} x ${budget}GB = ${commit}GB OVERCOMMITS ${headroom}GB headroom"
    fi
  done <<< "$out"
  if (( seen > 0 )); then
    _t_ok "${total}GB host: the stage printed its plan rather than running an unstated one"
  else
    _t_no "${total}GB host: no pass plan was printed at all"
  fi
}
#        total avail reserve headroom
_j_host      8     6       2        4
_j_host     27    20       3       17
_j_host     64    36       8       28

# ===========================================================================
printf '== K: a process that exits under the watchdog does not abort the stage ==\n'
# ===========================================================================
# THE "PRINTS NOTHING AT ALL" FACE of this ticket, and the one that survived
# the memory-model rewrite because it is not a memory bug at all.
#
# The watchdog samples `ps -o rss= -p $pid` for each live process.  Written as
# a bare assignment, `rss_kb=$(ps ...)` takes the command substitution's exit
# status as its own, so when the process has exited in the microseconds since
# the `kill -0` liveness check above it, `ps` exits 1, the assignment exits 1,
# and `set -e` tears the stage down - past the watchdog roll-up, past the
# verdict, leaving a log that ends at the header.  It is a RACE, so a run of
# two stub files that both sleep never loses it and a run of 130 real files
# loses it almost every time: measured on this tree at 9 of 130 files
# unmeasured, each annotated "see the message below" with no message below,
# and the stage ending on "an unexpected non-zero exit before it could reach
# a verdict".
#
# Driven here by a stub `ps` that ALWAYS fails, which is the same status the
# race produces and needs no timing luck to hit.  Under the bare-assignment
# spelling this case gets the header and the abort verdict and nothing else;
# under `|| rss_kb=` the sample is skipped, the stage runs to completion, and
# both files are reported checked.
if command -v ps >/dev/null 2>&1; then
  mkdir -p "$W/bin-ps"
  cp "$W/bin/shellcheck" "$W/bin-ps/shellcheck"
  # Exits 1 with no output, exactly as the real `ps` does for a dead pid.
  printf '#!/usr/bin/env bash\nexit 1\n' > "$W/bin-ps/ps"
  chmod +x "$W/bin-ps/ps"

  K_STATUS=0
  K_OUT=$(PATH=$W/bin-ps:$PATH \
          GITHUB_ACTIONS='' \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-k \
          bash "$RUNNER" shellcheck 2>&1) || K_STATUS=$?

  assert_eq 0 "$K_STATUS" \
    'the stage survives a failing ps sample and exits 0 - FAILS under the bare `rss_kb=$(ps ...)` spelling, where set -e aborts the whole stage'
  assert_not_contains "$K_OUT" 'unexpected non-zero exit' \
    'and does NOT end on the abort trap - FAILS under the shipped spelling, which is how a run of the real tree ended with 9 files unmeasured and no explanation for any of them'
  assert_contains "$K_OUT" '--- shellcheck passed' \
    'and reaches a real verdict line rather than stopping after the header'
  assert_contains "$K_OUT" '2 of 2 file(s) checked' \
    'and both files are actually checked - a lost ps sample must cost the stage its watchdog for one tick, never a file its result'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== L: kill attribution survives an abort, because the verdict prints it ==\n'
# ===========================================================================
# Acceptance criteria 3 and 4 together.  Knowing WHICH file and WHICH cause is
# what makes a kill actionable, and those messages used to be printed inline
# only after both passes had finished - so any abort before that point threw
# away the explanation for every kill already made, which is precisely what
# left 9 files annotated "see the message below" with nothing below.  They are
# emitted from _sc_verdict instead, the one function the EXIT/INT/TERM traps
# all call, so no exit path can lose them.
#
# Driven by the free-floor seam (a real kill), with the stage then aborted by
# a SIGTERM from outside - the same shape section D uses for the verdict line.
if command -v ps >/dev/null 2>&1; then
  L_ALIVE=$W/alive-l
  rm -f "$L_ALIVE"
  L_OUT=$(PATH=$W/bin:$PATH \
          GITHUB_ACTIONS='' \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_FREE_FLOOR_GB=999999 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$L_ALIVE \
          bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$L_OUT" 'HOST MEMORY PRESSURE' \
    'the cause of every kill reaches the output'
  assert_contains "$L_OUT" 'alpha.sh' \
    'and names the file it killed - FAILS under a message that reports only a pid, which nobody can act on'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== M: the CI path checks ONE FILE PER INVOCATION, and never SKIPS ==\n'
# ===========================================================================
# Everything above drives the memory-model path a contributor gets.  This
# section drives the OTHER one - the branch the stage takes when
# GITHUB_ACTIONS is set - because it had no coverage at all, and what it did
# instead was hand `(files + 1) / 2` files to a SINGLE `shellcheck -x`
# process: 85 of them at the tree size current when this was written.
# `shellcheck` holds every file it is given, plus each one's whole `-x`
# closure, in one heap, so that process's peak is the SUM over its batch
# rather than the MAX over it.  That killed the `ubuntu-latest` job outright
# (exit 143, "The runner has received a shutdown signal", no stage output at
# all) and made `macos-latest` swap for 41m45s to finish the same work.
#
# Two properties are asserted, and the first is the one that CANNOT be seen in
# the stage's own output - a batched run and a per-file run print the same
# verdict, which is why this needed a probe inside the stub rather than a
# string match on stdout.
_stage_ci() {
  local out status=0
  : > "$W/argc.log"
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS=true \
        STUB_ARGC_LOG=$W/argc.log \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist-ci \
        bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

# SIX files, not the two the rest of this suite uses, and that is the whole
# point of the fixture.  The batched shape computed `(files + jobs - 1) / jobs`
# per invocation, so at TWO files it produced `(2 + 1) / 2 = 1` file per
# invocation - byte-for-byte the behaviour this section exists to require.
# A first draft of this section used the shared two-file list and its two
# central assertions passed against the batched branch as happily as against
# the fixed one, which is a test that pins nothing.  At six files the old
# shape produces 2 invocations of 3 files and the new one 6 of 1, so the two
# readings are finally distinguishable.
: > "$W/filelist-ci"
for _ci_n in 1 2 3 4 5 6; do
  printf '#!/usr/bin/env bash\ntrue\n' > "$W/tree/ci$_ci_n.sh"
  printf '%s\n' "$W/tree/ci$_ci_n.sh" >> "$W/filelist-ci"
done

STUB_PLAN='' _stage_ci
assert_eq 0 "$STAGE_STATUS" 'a clean CI-path stage exits 0'
assert_contains "$STAGE_OUT" '1 file per invocation' \
  'and says how it batched, so a log reader can tell which shape ran'
assert_contains "$STAGE_OUT" 'shellcheck: 0.0.0-stub' \
  'and records the shellcheck VERSION next to the verdict - findings are not version-stable (0.9.0 reports SC2119/SC2120 where 0.11.0 reports nothing), and a CI run once reported 56 findings no local run could reproduce with no way to see why from the log'
CI_INVOCATIONS=$(wc -l <"$W/argc.log" | tr -d ' ')
CI_MAXARGC=$(sort -rn <"$W/argc.log" | head -1)
assert_eq 6 "$CI_INVOCATIONS" \
  'six files produce SIX shellcheck invocations - FAILS under the batched shape this replaces, which produced two invocations carrying three files each'
assert_eq 1 "$CI_MAXARGC" \
  'and no invocation is handed more than ONE file - FAILS under the batched shape, whose peak memory is the SUM over its batch rather than the MAX over the tree, which is what took the ubuntu-latest runner down'

# THE DECLARED HANDOFF BANNER.  This CI-path stage call reads the REAL
# tests/shellcheck-heavy-files.txt (SCOURSH_SHELLCHECK_HEAVY_FILES_LIST is not
# overridden here), so it exercises the real, checked-in list rather than a
# fixture stand-in - the banner names the count and every file, unconditionally,
# because the exclusion happened upstream in `_shard_build_plan` and this is
# the one place left that can still say so out loud.
_heavy_n=$(awk '!/^[[:space:]]*($|#)/{n++} END{print n+0}' "$ROOT/tests/shellcheck-heavy-files.txt")
assert_contains "$STAGE_OUT" "shellcheck: $_heavy_n file(s) handed off to the daily suite" \
  'the CI-path stage names the declared handoff count on every run - a silent exclusion here would read exactly like a file that was simply never discovered'
assert_contains "$STAGE_OUT" 'tests/shellcheck-heavy-files.txt' \
  'and points at the one named place the list lives, rather than leaving a reader to search for it'
assert_contains "$STAGE_OUT" '  - scan.sh' \
  'and names at least one real handed-off file - never phrased as though it passed here'
assert_contains "$STAGE_OUT" '  - tests/suites/dast-methods.sh' \
  'and another - the banner lists every file, not merely the count'

# Per-file attribution, which the batched shape explicitly could not do: it
# reported `(batched - see the output above)` in place of a filename.
STUB_PLAN='ci4.sh:1' _stage_ci
assert_eq 1 "$STAGE_STATUS" 'a CI-path finding fails the stage'
assert_contains "$STAGE_OUT" 'ci4.sh' \
  'and the failing file is named - FAILS under the batched shape, which could only say "(batched - see the output above)"'
assert_not_contains "$STAGE_OUT" 'batched' \
  'and no placeholder stands in for a filename'

# `shellcheck` exit 2 is "I could not process this file", which is a different
# fact from a finding and must not be rounded up to one.
STUB_PLAN='ci2.sh:2' _stage_ci
assert_eq 1 "$STAGE_STATUS" 'a CI-path file that could not be processed fails the stage'
assert_contains "$STAGE_OUT" 'could NOT be checked' \
  'and is reported as unmeasured rather than as a finding'
assert_contains "$STAGE_OUT" 'ci2.sh' 'and is named'

# THE PROPERTY THAT MAKES A GREEN CI RUN MEAN SOMETHING.  On a contributor's
# machine "this host is too small for this file" is a legitimate answer and
# the stage SKIPS by name and still passes.  On CI the runner IS the target,
# so there is no such answer: every file must produce a result, and the CI
# path has no skip path at all to reach.
assert_not_contains "$STAGE_OUT" 'SKIPPED' \
  'the CI path never reports a file as SKIPPED - a hosted runner being too small is a failure to report, not a file to quietly drop'

# The plan arithmetic, driven over the two runner shapes this workflow
# actually targets, the same way section J drives the local model over an 8GB,
# a 27GB and a 64GB host.  Written as comments these were just claims; the
# first draft of this branch used the LOCAL path's 5GB step and came out at 3
# jobs on the 16GB shape - 3 x the tree's 5.75GB worst file is 17.25GB against
# 16GB of RAM, which is the batching defect again in miniature.
_stage_ci_host() {   # $1 total GB, $2 available GB
  local out status=0
  : > "$W/argc.log"
  out=$(PATH=$W/bin:$PATH         GITHUB_ACTIONS=true         STUB_ARGC_LOG=$W/argc.log         SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist-ci         SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=$1         SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=$2         bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

STUB_PLAN='' _stage_ci_host 16 15
assert_contains "$STAGE_OUT" '2GB reserved -> 13GB headroom'   'ubuntu-latest shape (16GB total, 15GB available): reserve is max(2, total/8) = 2GB and headroom is 13GB'
assert_contains "$STAGE_OUT" '2 parallel x 1 file per invocation (6GB planned per file, a resident-memory watchdog enforces it - no ulimit, no fixed hard cap)'   'and 13GB of headroom divides by the 6GB TYPICAL planning figure - 13/6 plans TWO jobs, more throughput than the old ulimit-based model ever allowed (which had to divide by an inflated 10GB enforced ceiling to stay safe, so it never planned more than one job on this exact shape) - because a typical-footprint pass with a real second pass behind it can plan wide without risking a false rejection the way one fixed hard ceiling did'

STUB_PLAN='' _stage_ci_host 7 5
assert_contains "$STAGE_OUT" '2GB reserved -> 3GB headroom'   'macos-latest shape (7GB total, 5GB available): reserve 2GB, headroom 3GB'
assert_contains "$STAGE_OUT" '1 parallel x 1 file per invocation'   'and 3GB of headroom plans exactly ONE job rather than zero - a runner smaller than one file still has to check every file, so the floor is 1 and never a skip'

# ===========================================================================
printf '== M2: the CI path bounds REAL resident memory, never virtual address space ==\n'
# ===========================================================================
# WHAT THIS REPLACES.  The CI path used to bind a `ulimit -v` (RLIMIT_AS)
# around each invocation - virtual ADDRESS SPACE, not real memory.  Measured
# directly against this project's own pinned 0.11.0 shellcheck binary (a real
# Linux build, not only the BSD host's Homebrew one): GHC's RTS reserves
# address space in an amount that scales with how much memory the HOST
# appears to have, not with the file being checked, so a ceiling low enough to
# protect a real runner's ~15GB of physical memory rejected eight real files
# outright - each failing to even START its own analysis - despite none of
# them needing anywhere near that much RESIDENT memory. Raising the ceiling
# enough to admit those eight files would have meant admitting a ceiling that
# no longer protects the runner at all, which is the contradiction this
# rework closes by changing WHAT is measured (resident memory, sampled
# externally) rather than by re-tuning the old ceiling's number.
#
# The replacement is the SAME watchdog (`_sc_run_pass`, shared with the local
# path above) rather than a second, CI-specific implementation - so this
# section proves the WIRING and the CI-specific POLICY on top of it (no
# skip, ever), not the watchdog's own kill mechanics, which sections C2, H,
# I, J and K above already pin directly.
_stage_ci_watchdog() {   # $1 total GB, $2 available GB, $3 STUB_PLAN, plus any
                         # SCOURSH_SHELLCHECK_* overrides the caller exported
  local out status=0
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS=true \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist-ci \
        SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=$1 \
        SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=$2 \
        STUB_PLAN=$3 \
        STUB_ALIVE=$W/alive-m2 \
        bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

if command -v ps >/dev/null 2>&1; then
  # OVER BUDGET: the file's own doing, in BOTH passes (the tiny forced KB
  # budget applies uniformly, so pass 2's bigger headroom cannot rescue it
  # either) - the CI equivalent of section I's host-capacity SKIP, except CI
  # has no skip outcome to fall back to, so this must FAIL rather than pass.
  rm -f "$W/alive-m2"
  SCOURSH_SHELLCHECK_BUDGET_KB=100 _stage_ci_watchdog 16 15 'ci1.sh:sleep'
  assert_eq 1 "$STAGE_STATUS" \
    'a file that exceeds its resident-memory budget in every pass FAILS the CI stage - this project has no reported-and-continue outcome for it, the same "the runner IS the target" policy an already-unchecked CI file always had'
  assert_contains "$STAGE_OUT" 'ci1.sh' 'and the failing file is named'
  assert_contains "$STAGE_OUT" 'OVER BUDGET' \
    'and the message names OVER BUDGET as the cause, exactly as the local path already does - FAILS under a stage that reports one generic kill message for CI'
  assert_contains "$STAGE_OUT" 'SCOURSH_SHELLCHECK_CI_WORST_GB' \
    'and names the knob to raise it with, rather than leaving a reader to rediscover it by reading this file'
  assert_not_contains "$STAGE_OUT" 'SKIPPED' \
    'and is NEVER reported as a host-capacity skip - CI has no such outcome, unlike the local path section I already pins'

  # HOST PRESSURE: NOT the file's own doing, and CI still has no skip to file
  # it under - it FAILS, unlike the local path's own equivalent (section N),
  # which can legitimately pass a pressure kill through as a host-size skip
  # once no bigger budget is left to retry at.
  rm -f "$W/alive-m2"
  SCOURSH_SHELLCHECK_FREE_FLOOR_GB=9999999 _stage_ci_watchdog 16 15 'ci1.sh:sleep'
  assert_eq 1 "$STAGE_STATUS" \
    'a host-pressure kill on CI FAILS the stage too - FAILS under filing it as a host-size skip, which reports a file the stage never measured as a clean pass on the one path where the runner really is the target'
  assert_contains "$STAGE_OUT" 'HOST MEMORY PRESSURE' \
    'and the message names HOST MEMORY PRESSURE as the cause, not OVER BUDGET - the two causes stay apart on CI exactly as they do locally'
  assert_not_contains "$STAGE_OUT" 'SKIPPED' \
    'and is NEVER reported as a host-capacity skip on CI, regardless of which of the two causes the kill actually had'

  # Still one invocation per file, never a batch, under the new mechanism.
  : > "$W/argc.log"
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS=true \
        STUB_ARGC_LOG=$W/argc.log \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist-ci \
        SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=16 \
        SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=15 \
        STUB_PLAN='' bash "$RUNNER" shellcheck 2>&1) || true
  assert_eq 6 "$(wc -l <"$W/argc.log" | tr -d ' ')" \
    'six files still produce SIX shellcheck invocations under the watchdog-based CI path, not a batch of six'
  assert_eq 1 "$(sort -rn <"$W/argc.log" | head -1)" \
    'and no invocation is handed more than ONE file under the watchdog-based CI path either'
else
  printf 'SKIPPED (no ps on this host, so the CI path runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== N: on a host too small for a SECOND pass, the two kill causes stay apart ==\n'
# ===========================================================================
# Pass 2 only exists when it can offer a BIGGER budget than pass 1.  On a host
# whose whole headroom is already committed to one process there is nothing to
# retry into, and the stage short-circuits.  That branch used to file every
# deferred file under `skipped` - including the ones killed for HOST PRESSURE,
# which had just been reported as "its own RSS was within the budget, so this
# is the host's doing and not this file's".  The stage therefore contradicted
# itself one line later with "needs more than the 1GB this host's headroom can
# give one process", and - the expensive half - turned a stage that FAILED to
# measure a file into a PASS.
#
# This is not a hypothetical small host: `macos-latest` is 7GB total with
# about 3GB available, so reserve 2 leaves headroom 1 and pass 1's budget is
# already the whole of it.  Section C2 above failed there and only there, on
# both a pre-change and a post-change CI run, because on any host with real
# headroom pass 2 exists and the post-pass-2 split already handled this.
#
# Both directions are driven, because the naive fix for each is the other's
# bug: file everything as `unchecked` and a genuinely-too-small host can never
# report a clean pass again; file everything as `skipped` and a stage that
# failed to measure a file reports success.
_stage_small_host() {   # $1 free-floor GB (9999999 forces PRESSURE), $2 budget KB
  local out status=0
  out=$(PATH=$W/bin:$PATH \
        GITHUB_ACTIONS='' \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        SCOURSH_SHELLCHECK_FREE_FLOOR_GB=$1 \
        SCOURSH_SHELLCHECK_BUDGET_KB=$2 \
        SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=7 \
        SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=3 \
        STUB_PLAN='alpha.sh:sleep beta.sh:sleep' \
        bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

# HOST PRESSURE on a host with no second pass: unmeasured, and it FAILS.
_stage_small_host 9999999 ''
assert_contains "$STAGE_OUT" '1GB headroom' \
  'the macos-latest shape really does leave pass 1 holding the whole headroom, so the short-circuit branch is the one under test'
assert_eq 1 "$STAGE_STATUS" \
  'a host-pressure kill with no larger budget to retry at FAILS the stage - FAILS under filing it as a host-size skip, which reports a file the stage never measured as a clean pass'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' \
  'and reaches the FAILED verdict line'
assert_contains "$STAGE_OUT" 'could NOT be checked' \
  'and is reported as unmeasured'
assert_not_contains "$STAGE_OUT" 'SKIPPED - this host does not have the memory' \
  'and is NOT reported as a host-capacity skip - the stage had just said its RSS was within budget, so claiming it needs more memory contradicts its own kill message'

# OVER BUDGET on the same host: that IS a capacity limit, and it still passes.
_stage_small_host 1 100
assert_eq 0 "$STAGE_STATUS" \
  'an over-budget kill on the same too-small host still PASSES - FAILS under filing every deferred file as unchecked, which would leave a genuinely small host unable to report a clean run at all'
assert_contains "$STAGE_OUT" 'SKIPPED' \
  'and is reported as a host-capacity skip'
assert_contains "$STAGE_OUT" 'can give one process' \
  'naming the budget it could not be given'
assert_not_contains "$STAGE_OUT" 'could NOT be checked' \
  'and is NOT filed as unmeasured, which is for results this stage should have got and did not'

# ===========================================================================
printf '== N2: SCOURSH_SHELLCHECK_SKIP_IS_FATAL - a skip that daily-suite.sh cannot afford to be quiet about ==\n'
# ===========================================================================
# The identical too-small-host shape as the OVER BUDGET case directly above -
# same host, same file, same cause, and the local path's ordinary answer is
# still a clean SKIPPED pass, because a laptop really can be too small for a
# file. tools/daily-suite.sh's own dedicated heavy-file pass cannot accept
# that answer for a file this project has DECLARED heavy (see
# tests/shellcheck-heavy-files.txt): "the container was too small" has to be
# exactly as fatal as CI's own "the runner was too small" is, or the daily
# suite would be a quieter version of the very gap the CI handoff exists to
# close. SCOURSH_SHELLCHECK_SKIP_IS_FATAL=1 is what tools/daily-suite/gnu-leg.sh
# sets for that one dedicated call, and only for it - this section proves it
# flips the verdict without inventing a second skip mechanism.
status=0
out=$(PATH=$W/bin:$PATH \
      GITHUB_ACTIONS='' \
      SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
      SCOURSH_SHELLCHECK_FREE_FLOOR_GB=1 \
      SCOURSH_SHELLCHECK_BUDGET_KB=100 \
      SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=7 \
      SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=3 \
      SCOURSH_SHELLCHECK_SKIP_IS_FATAL=1 \
      STUB_PLAN='alpha.sh:sleep beta.sh:sleep' \
      bash "$RUNNER" shellcheck 2>&1) || status=$?
STAGE_OUT=$out
STAGE_STATUS=$status
assert_ne 0 "$STAGE_STATUS" \
  'with SCOURSH_SHELLCHECK_SKIP_IS_FATAL=1, the SAME host-capacity skip that passes by default now FAILS the stage - FAILS under a knob that only decorates the message without changing the exit status'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' \
  'and reaches the FAILED verdict line, exactly as visibly as an ordinary unchecked file does'
assert_contains "$STAGE_OUT" 'SKIPPED - this host does not have the memory' \
  'and the roll-up still names the real cause (a host-capacity skip, not a finding) - the flag changes the VERDICT, never the diagnosis'
status=0

# The unset default: an ordinary run with nothing set behaves exactly as
# section I already pinned - SKIPPED still passes. Re-asserted here, right
# next to the fatal case, so the two are read as a pair rather than trusting
# that section I's own result still holds by the time a reader reaches this
# one.
_stage_small_host 1 100
assert_eq 0 "$STAGE_STATUS" \
  'with SCOURSH_SHELLCHECK_SKIP_IS_FATAL unset, the identical skip still PASSES - the ordinary contributor path is unchanged by this knob existing at all'

# =============================================================================
printf '\n-- --shard I/N: a wall-clock split that is provably not a filter --\n'
# =============================================================================
# `--shard` exists to let CI run the same work on N runners instead of one.
# The whole safety of that rests on ONE property - the union of the N shards
# is the full work list, each item in exactly one shard - because every way of
# getting it wrong makes CI FASTER AND GREENER while testing less, which is
# the single most expensive direction for this mechanism to fail in.  A shard
# that silently dropped a suite would show `all green` on every leg.
#
# So this section asserts the partition ITSELF, by reconstruction, rather than
# asserting any particular assignment: it concatenates every shard's own
# `--list` and requires it to equal the unsharded list exactly, sorted (no
# item missing) AND by count (no item twice).  That is checked over several N,
# including N=1 (which must be the full run by construction) and an N larger
# than any CI matrix would use.
#
# THE WORK LIST NOW INCLUDES ONE ITEM PER SHELLCHECK FILE, not one item for
# the whole tree - see tests/run-tests.sh's own `--shard` header for why (the
# short version: a whole-tree stage pinned to one shard was the pole on CI run
# 35167252242, while nineteen other jobs sat idle). Every property this
# section already proved for suites and linters has to hold for `file:<path>`
# items too, which is why the reconstruction loop below needs no changes at
# all to cover them - it never looks at what KIND of item a line names.

_shard_list() { bash "$RUNNER" --shard "$1" --list; }

SHARD_FULL=$(bash "$RUNNER" --shard 1/1 --list)
SHARD_FULL_N=$(printf '%s\n' "$SHARD_FULL" | wc -l | tr -d ' ')

t_case '--shard 1/1 is the full work list, so a shard can never be a way to run less'
# Counted against tests/run-tests.sh's OWN arrays for suites and linters, and
# against an INDEPENDENT `find` over the same directories `_sc_discover_files`
# walks for the shellcheck file list, rather than a number typed here - either
# one going stale (a suite registered, a new top-level *.sh file landing)
# would otherwise silently fall out of step with what this assertion expects.
# A single `stages: shellcheck` name no longer accounts for the file-list
# dimension at all - see the header note above - so it is deliberately left
# out of this sum rather than added to it.
SHARD_DECLARED_SL_N=$(bash "$RUNNER" --list \
  | awk -F': *' '/^(suites|linters): /{n+=split($2,a," ")} END{print n}')
# Only directories that EXIST are passed to `find` - exactly the
# `[[ -d $d ]]` guard `_sc_discover_files` itself applies - because `aws/`
# does not exist in this checkout yet (step 6 is unstarted) and a bare `find`
# naming a missing path exits non-zero (both GNU find and a `bfs` shadowing
# it on PATH do), which under `pipefail` silently poisons this whole
# assignment's exit status even though the file COUNT it captured is correct.
_sl_declared_dirs=()
for _d in lib tests tools modules aws; do [[ -d "$ROOT/$_d" ]] && _sl_declared_dirs+=("$_d"); done
SHARD_DECLARED_FILE_N=$(cd "$ROOT" && find "${_sl_declared_dirs[@]}" -name '*.sh' -type f 2>/dev/null | wc -l | tr -d ' ')
[[ -f "$ROOT/scan.sh" ]] && SHARD_DECLARED_FILE_N=$(( SHARD_DECLARED_FILE_N + 1 ))
# tests/shellcheck-heavy-files.txt names files `_shard_build_plan`
# deliberately excludes from every shard's file-item plan - see that
# function's own header in tests/run-tests.sh. Read the same way
# tests/run-tests.sh's own `_sc_load_heavy_files` does (blank lines and `#`
# comments ignored), rather than a count typed here, so this assertion tracks
# the real list rather than a snapshot of it.
SHARD_DECLARED_HEAVY_N=$(awk '!/^[[:space:]]*($|#)/{n++} END{print n+0}' "$ROOT/tests/shellcheck-heavy-files.txt")
assert_eq "$(( SHARD_DECLARED_SL_N + SHARD_DECLARED_FILE_N - SHARD_DECLARED_HEAVY_N ))" "$SHARD_FULL_N" \
  '--shard 1/1 lists exactly as many work items as SUITES + LINTERS declares, plus one per real *.sh file under lib/tests/tools/modules/aws (+ scan.sh), MINUS the declared CI handoff (tests/shellcheck-heavy-files.txt), which --shard deliberately excludes from every shard - FAILS if the shard path enumerates the full run from a second, drifting list of its own, stops being one item per file, or stops excluding the declared handoff'
assert_eq 1 "$( (( SHARD_FULL_N > 100 )) && printf 1 || printf 0 )" \
  "and that is the real, whole array rather than a filtered remnant (got $SHARD_FULL_N items)"

t_case 'the CI handoff (tests/shellcheck-heavy-files.txt) is a true partition: every heavy file is a real, discoverable *.sh file, and none of them appear in --shard'"'"'s file-item plan at any N'
# The union-completeness proof this ticket's own brief demands: CI's checked
# set (SHARD_FULL's own `file` lines) plus the daily suite's checked set
# (tests/shellcheck-heavy-files.txt) must equal the FULL, unfiltered tree
# walk exactly - no file in neither, and no file the shard plan silently
# still owns despite being declared handed off.
_heavy_list=$ROOT/tests/shellcheck-heavy-files.txt
assert_file_exists "$_heavy_list" 'the CI handoff list exists at the one named place both consumers read'
_heavy_paths=()
while IFS= read -r _hp; do
  [[ -z $_hp || $_hp == \#* ]] && continue
  _heavy_paths+=("$_hp")
done < "$_heavy_list"
assert_eq 1 "$( (( ${#_heavy_paths[@]} > 0 )) && printf 1 || printf 0 )" \
  'the handoff list names at least one file, so this section is not vacuously true'
_full_tree=$(cd "$ROOT" && find "${_sl_declared_dirs[@]}" -name '*.sh' -type f 2>/dev/null | LC_ALL=C sort)
[[ -f "$ROOT/scan.sh" ]] && _full_tree=$(printf '%s\nscan.sh\n' "$_full_tree" | LC_ALL=C sort)
_shard_full_files=$(printf '%s\n' "$SHARD_FULL" | awk '$1=="file"{print $2}' | LC_ALL=C sort)
for _hp in "${_heavy_paths[@]}"; do
  assert_eq 1 "$( (( $(grep -Fxc "$_hp" <<<"$_full_tree") > 0 )) && printf 1 || printf 0 )" \
    "declared heavy file $_hp is a real file under the tree --shard's own discovery walks - a stale entry would silently mean this file is checked NOWHERE"
  # An EXACT line match, never assert_not_contains's plain substring test:
  # "scan.sh" is itself a substring of the unrelated, non-heavy
  # tests/e2e/fixture-scan.sh, which a substring check would misread as a
  # leak.
  assert_eq 0 "$(grep -Fxc "$_hp" <<<"$_shard_full_files")" \
    "declared heavy file $_hp never appears in --shard's file-item plan at N=1 - a leak here would mean CI still attempts a file it claims to have handed off"
done
_union_files=$(printf '%s\n%s\n' "$_shard_full_files" "$(printf '%s\n' "${_heavy_paths[@]}")" | LC_ALL=C sort -u)
assert_eq "$_full_tree" "$_union_files" \
  'CI'"'"'s own file-item plan UNION the declared heavy list reconstructs the full, unfiltered tree exactly - the load-bearing union-completeness proof: every *.sh file is claimed by CI or by the declared handoff, never by neither and never by both'

t_case '--print-heavy-files is the ONE reader of tests/shellcheck-heavy-files.txt'"'"'s comment/blank-line convention - tools/daily-suite/gnu-leg.sh builds its own SCOURSH_SHELLCHECK_FILE_LIST from this, never from the raw commented file'
# SCOURSH_SHELLCHECK_FILE_LIST itself supports no comment syntax (only a
# truly-blank line is skipped), so pointing it directly at the human-authored
# tests/shellcheck-heavy-files.txt reads every prose `#` line as a bogus
# extra file - measured directly: a 16-file pass inflated to 70. This
# case pins that --print-heavy-files' output is exactly the clean list, with
# no comment or blank line surviving into it.
_print_heavy_out=$(bash "$RUNNER" --print-heavy-files)
assert_eq "$(printf '%s\n' "${_heavy_paths[@]}")" "$_print_heavy_out" \
  '--print-heavy-files emits exactly the declared heavy paths, one per line, in file order - no comment, no blank line, nothing extra'
assert_not_contains "$_print_heavy_out" '#' \
  'and never leaks a comment-line byte into what is meant to be a plain, machine-consumable list'

# EVERY TEST BELOW THAT DOES NOT SPECIFICALLY WANT REAL HUB-SUM WEIGHTING USES
# THIS OVERRIDE, exported for the rest of this section.  A `file:<path>` item
# never falls back to the flat default with no weights file at all - it
# always carries its own real hub-sum weight (tests/run-tests.sh's
# `_sc_file_weight_seconds`, which calls tests/lib/hubsum.sh's real,
# ~50-second whole-tree walk) - so leaving every subsequent `_shard_list` call
# unoverridden would multiply that cost by however many times this section
# calls it, which is minutes for the reconstruction loop below alone and
# HOURS for the degenerate one-item-per-shard case further down. None of the
# STRUCTURAL properties this section proves (completeness, no duplicates,
# degeneration to round-robin, weight causing separation) depend on which
# real numbers the weights happen to be - LPT visits every item exactly once
# regardless of the weight values, so a bug that dropped or doubled an item
# would still be caught under controlled weights. Building this from
# SHARD_FULL's OWN file lines (rather than re-deriving the file list a second
# time) is what keeps this fixture itself from becoming a second, drifting
# enumeration.
SHARD_DEFAULT_SECONDS=$(sed -n 's/^SHARD_DEFAULT_WEIGHT_SECONDS=\([0-9][0-9]*\)$/\1/p' "$RUNNER")
assert_ne '' "$SHARD_DEFAULT_SECONDS" \
  'could not read SHARD_DEFAULT_WEIGHT_SECONDS out of tests/run-tests.sh - this fixture pins every file back to it, and guessing the number would test nothing'
_ALL_DEFAULT=$W/weights-all-default.tsv
printf '%s\n' "$SHARD_FULL" \
  | awk -v d="$SHARD_DEFAULT_SECONDS" '$1=="file"{printf "file:%s\t%s\n", $2, d}' > "$_ALL_DEFAULT"
export SCOURSH_SHARD_WEIGHTS_FILE=$_ALL_DEFAULT

for _n in 1 2 3 4 5 8 13; do
  t_case "the union of all $_n shards is exactly the full work list, with nothing dropped and nothing run twice"
  _union=''
  _rc_all=0
  for _i in $(seq 1 "$_n"); do
    _one=$(_shard_list "$_i/$_n") || _rc_all=1
    [[ -n $_one ]] && _union+=$_one$'\n'
  done
  assert_eq 0 "$_rc_all" \
    "every one of the $_n shards exits 0 - FAILS under a shard_work whose status is 'did the LAST item belong to me', which aborts N-1 of every N shards under set -Eeuo pipefail before a single suite starts"
  _union=${_union%$'\n'}
  assert_eq "$(printf '%s\n' "$SHARD_FULL" | LC_ALL=C sort)" "$(printf '%s\n' "$_union" | LC_ALL=C sort)" \
    "the $_n shards reconstruct the full list exactly - FAILS if any shard drops an item (CI goes green having tested less) or claims one twice"
  assert_eq "$SHARD_FULL_N" "$(printf '%s\n' "$_union" | wc -l | tr -d ' ')" \
    "and the item COUNT matches too - the sorted compare alone cannot see a duplicate, so this is the half that catches an item assigned to two shards"
done

t_case 'with every item at the same (default) weight, the split degrades to the old round-robin ordering - so a from-scratch checkout with no cost data behaves exactly as before'
# The first three work items of a 3-shard split must be the first three items
# of the full list, one per shard.  Under contiguous blocks shard 1 would hold
# the first THIRD of the list and shards 2 and 3 would hold none of item 2 or
# 3, so this fails under that reading rather than merely differing from it.
# Uses the section-wide `_ALL_DEFAULT` override (already exported above)
# rather than a missing-file seam: a `file:<path>` item never falls back to
# the flat default on its own (see that override's own note), so forcing
# every item in the plan - suite, linter AND file alike - back to the same
# number is what actually reproduces "no real cost data anywhere" now.
_full_1=$(printf '%s\n' "$SHARD_FULL" | sed -n 1p)
_full_2=$(printf '%s\n' "$SHARD_FULL" | sed -n 2p)
_full_3=$(printf '%s\n' "$SHARD_FULL" | sed -n 3p)
assert_eq "$_full_1" "$(_shard_list 1/3 | sed -n 1p)" \
  'shard 1 of 3 leads with work item 1'
assert_eq "$_full_2" "$(_shard_list 2/3 | sed -n 1p)" \
  'shard 2 of 3 leads with work item 2 - FAILS under a contiguous split, where item 2 is still shard 1'"'"'s'
assert_eq "$_full_3" "$(_shard_list 3/3 | sed -n 1p)" \
  'shard 3 of 3 leads with work item 3 - same reading, third shard'

t_case 'the split is WEIGHT-AWARE, not index-based - two items that would tie onto the same shard under plain round-robin are separated once a cost table says one of them is expensive'
# `records` (work item 1) and `config` (work item 3) are BOTH odd-numbered
# 1-indexed positions an N=2 round-robin deal puts on the same shard (index 0
# and index 2, both even 0-indexed, i.e. both idx%2==0) - which is exactly the
# shape CI run 35064153768 was filed over: a positional deal cannot tell two
# expensive items apart from two cheap ones and may cluster them anyway. A
# fixture cost table makes both of them the two heaviest items in the array;
# if the split is really weight-aware they land on DIFFERENT shards despite
# sharing that position parity, where the old idx%N scheme could only ever
# put them together.  Built ON TOP of `_ALL_DEFAULT` (every file still pinned
# to the flat default) rather than replacing it, so this stays a two-item
# override and not a second real hub-sum pass.
_W2=$W/weights-two-heavy.tsv
cat "$_ALL_DEFAULT" > "$_W2"
printf 'suite:records\t100000\nsuite:config\t100000\n' >> "$_W2"
# `grep -c` exits 1 on a zero count (tension 4: never call it bare), and that
# status IS a bare assignment's own under `set -e` - guard each with `|| true`
# so "not on this shard" (a legitimate, expected outcome half the time here)
# does not abort the suite.
_w2_records=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W2 _shard_list 1/2 | grep -c '^suite records ') || true
_w2_records2=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W2 _shard_list 2/2 | grep -c '^suite records ') || true
_w2_config1=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W2 _shard_list 1/2 | grep -c '^suite config ') || true
_w2_config2=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W2 _shard_list 2/2 | grep -c '^suite config ') || true
assert_eq 1 "$(( _w2_records + _w2_records2 ))" 'records is assigned to exactly one of the two shards'
assert_eq 1 "$(( _w2_config1 + _w2_config2 ))" 'config is assigned to exactly one of the two shards'
assert_ne "$_w2_records" "$_w2_config1" \
  'records and config land on DIFFERENT shards once weighted heavy - FAILS under an index-based scheme, which cannot see the fixture cost table at all and would still tie them by position'

# =============================================================================
printf '\n-- the shellcheck stage'"'"'s FILE LIST is sharded, not pinned to one shard --\n'
# =============================================================================
# This is the property CI run 35167252242 was filed over: pinning the WHOLE
# stage to one shard (`stage:shellcheck` as a single item) made that shard the
# pole while nineteen others sat idle. The old test here asserted the OPPOSITE
# of what this section proves - "lands in exactly one shard" - because that
# used to be correct and is now the defect this ticket removed.

t_case 'the shellcheck stage'"'"'s files are spread across MULTIPLE shards, not pinned to one'
# Capture to a variable BEFORE grepping it, rather than piping straight into
# `grep -q`: `-q` exits the instant it finds its first match, closing the
# pipe, and under `set -o pipefail` the upstream `_shard_list` subshell then
# dying of SIGPIPE (141) - not grep's own 0 - becomes the PIPELINE's exit
# status, so `if _shard_list ... | grep -q ...` reads false even when grep
# genuinely matched. Measured: with ~85 `^file ` lines per shard, grep found
# one almost immediately every time, so this was not a rare race - it failed
# on every real shard, every run, deterministically. `grep -c` (used for the
# suite/config split below) drains its whole input and is unaffected; only a
# quiet-mode early exit racing pipefail causes this.
_file_owning_shards=0
for _i in 1 2 3 4; do
  _shard_out=$(_shard_list "$_i/4")
  if grep -q '^file ' <<<"$_shard_out"; then _file_owning_shards=$(( _file_owning_shards + 1 )); fi
done
assert_eq 4 "$_file_owning_shards" \
  'all four shards own at least one shellcheck file - FAILS under the old one-shard-owns-the-whole-stage shape, which is exactly the pole this ticket removes (with 336-odd real files and 4 shards, every shard getting at least one is the expected shape, not a coincidence)'
assert_not_contains "$(_shard_list 1/4)" 'stage shellcheck' \
  'and no shard prints the old monolithic `stage shellcheck` line any more - the stage is now reached only through its own per-file items'

t_case 'the split is WEIGHT-AWARE for FILES too - two files that would tie onto the same shard under plain round-robin are separated once a cost table says one of them is expensive'
# The exact `records`/`config` shape above, replayed for `file:<path>` keys:
# mechanically this is the SAME `_shard_weight_of`/`_shard_build_plan` code
# path (it does not branch on kind once an explicit override row exists), but
# it is worth pinning independently rather than trusting that by inspection -
# a future change that special-cased `file:` handling in the assignment loop
# itself (rather than only in the DEFAULT-weight fallback, which is the only
# place this ticket actually added a branch) would not be caught by the
# suite-only version of this test. Any two real files will do; the two
# lightest-sounding names in the tree are picked so this reads as arbitrary
# rather than as if the CHOICE of file mattered.
_HEAVY_A=tests/lib/assert.sh
_HEAVY_B=lib/records.sh
_W3=$W/weights-two-heavy-files.tsv
cat "$_ALL_DEFAULT" > "$_W3"
printf 'file:%s\t100000\nfile:%s\t100000\n' "$_HEAVY_A" "$_HEAVY_B" >> "$_W3"
_w3_a1=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W3 _shard_list 1/2 | grep -c "^file $_HEAVY_A ") || true
_w3_a2=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W3 _shard_list 2/2 | grep -c "^file $_HEAVY_A ") || true
_w3_b1=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W3 _shard_list 1/2 | grep -c "^file $_HEAVY_B ") || true
_w3_b2=$(SCOURSH_SHARD_WEIGHTS_FILE=$_W3 _shard_list 2/2 | grep -c "^file $_HEAVY_B ") || true
assert_eq 1 "$(( _w3_a1 + _w3_a2 ))" "$_HEAVY_A is assigned to exactly one of the two shards"
assert_eq 1 "$(( _w3_b1 + _w3_b2 ))" "$_HEAVY_B is assigned to exactly one of the two shards"
assert_ne "$_w3_a1" "$_w3_b1" \
  "$_HEAVY_A and $_HEAVY_B land on DIFFERENT shards once weighted heavy - FAILS under a scheme that only ever balances suite/linter items and drops files into the rotation positionally"

t_case 'the DEFAULT file weight is real signal, not a placeholder - a heavily-nested file outweighs a leaf file, with no override at all'
# The one assertion in this whole file that exercises tests/lib/hubsum.sh for
# REAL rather than through the `_ALL_DEFAULT`/`_W3` overrides above - kept to
# exactly two single-file hub-sum walks (a fraction of a second each) rather
# than a whole-tree pass, since that is all this claim needs: a file with a
# real source-graph fan-out outweighs a file with none. tests/lib/assert.sh
# sources nothing (hub sum 0); lib/http.sh sources lib/config.sh and
# lib/findings.sh, both of which reach the hub chain (hub sum > 0 - the exact
# fan-out number is deliberately not pinned here, since it is a fact about the
# tree's OWN source graph on a given day and tests/lint-source-graph.sh's own
# suite already pins the walker's correctness in detail; this case only needs
# the two to differ in the right direction).
# shellcheck source=tests/lib/hubsum.sh
source "$ROOT/tests/lib/hubsum.sh"
_hub_leaf=$(hubsum_for tests/lib/assert.sh "$ROOT")
_hub_nested=$(hubsum_for lib/http.sh "$ROOT")
assert_eq 0 "$_hub_leaf" 'tests/lib/assert.sh, which sources nothing, has hub sum 0'
assert_eq 1 "$( (( _hub_nested > _hub_leaf )) && printf 1 || printf 0 )" \
  "lib/http.sh's hub sum ($_hub_nested) is real, measured signal that exceeds a leaf file's (0) - this is the DEFAULT weight tests/run-tests.sh's \`_sc_file_weight_seconds\` builds on, not a hardcoded list of today's heaviest files"

t_case 'a malformed or out-of-range --shard is refused with exit 2, never silently treated as "run everything"'
for _bad in 0/3 4/3 abc 1/0 '' 3; do
  _rc=0
  bash "$RUNNER" --shard "$_bad" --list >/dev/null 2>&1 || _rc=$?
  assert_eq 2 "$_rc" \
    "--shard '$_bad' exits 2 - FAILS under a permissive parse, which would run the FULL suite on every CI leg and read as a passing matrix that is really N duplicate runs"
done

t_case '--shard cannot be combined with a named suite: a slice of a full run and one suite are different requests'
_rc=0
bash "$RUNNER" --shard 1/2 scan >/dev/null 2>&1 || _rc=$?
assert_eq 2 "$_rc" \
  'exit 2 rather than quietly ignoring one of the two - FAILS under a parse that drops --shard and runs the named suite, which a CI matrix would report as N green legs having each run one suite'

t_case 'a shard REALLY RUNS its items rather than only listing them, and its verdict line refuses to claim a full pass'
# The direction a "the list looks right" assertion cannot reach: a shard_work
# whose output never reaches the run loop exits 0 having run NOTHING, and every
# list-shaped assertion above still passes.
#
# N is the work-item COUNT, so every shard owns exactly one item, and the one
# that owns `color` (a real suite, and the cheapest in the array) runs that and
# nothing else - which is what keeps this case fast rather than drifting onto
# an expensive suite.  It doubles as the degenerate-maximum case, where N
# equals the list length and a shard is a single item.
#
# WHICH SHARD NUMBER owns `color` is found by asking the split itself, never
# assumed from `color`'s position in the declared array: the weighted split
# (unlike the old idx%N one) does not promise position i lands on shard i, so
# a hardcoded index here would silently start testing the wrong shard the
# moment the real cost table changes.  SHARD_FULL_N now includes one item per
# file shellcheck scans (500-odd total rather than the ~215 suites+linters alone),
# so this search loop runs that many `_shard_list` calls - still fast, since
# it inherits the section-wide `_ALL_DEFAULT` override rather than paying for
# a real hub-sum walk on every single one of them.
_color_shard=''
for _ci in $(seq 1 "$SHARD_FULL_N"); do
  if _shard_list "$_ci/$SHARD_FULL_N" | grep -q '^suite color '; then
    _color_shard=$_ci
    break
  fi
done
assert_ne '' "$_color_shard" 'the cheap `color` suite is assigned to exactly one shard at N=item-count'
_run_out=$(cd "$ROOT" && bash "$RUNNER" --shard "$_color_shard/$SHARD_FULL_N" 2>&1) || true
assert_eq 1 "$(printf '%s\n' "$_run_out" | grep -c '^=== suite: ')" \
  'that shard ran exactly ONE suite - confirms N=item-count really is one item per shard, so the timing of this case cannot drift onto an expensive suite later'
_shard_of=$SHARD_FULL_N
assert_contains "$_run_out" '=== suite: color ===' \
  'the shard that owns `color` actually ran it - FAILS under a shard_work whose output is never fed to the run loop, which would exit 0 having run nothing'
assert_contains "$_run_out" "=== shard $_color_shard of $_shard_of ===" \
  'and says which slice it is, so a log is attributable to a matrix leg'
assert_contains "$_run_out" 'NOT a full pass on its own' \
  'and its closing verdict refuses to read as a full pass - FAILS under the bare `all green` line, which is what a CI matrix with one silently-dead leg would otherwise show on every surviving leg'

t_case 'an UNSHARDED run prints the bare `all green`, so the shard note can never leak into a real full pass'
# Driven through the named-suite path with the cheapest real suite in the
# array, so this costs a second rather than the hour a true full run does, and
# still exercises the same closing verdict block every run reaches.
_plain_out=$(cd "$ROOT" && bash "$RUNNER" color 2>&1) || true
assert_contains "$_plain_out" 'all green' 'an unsharded run reaches the verdict line'
assert_not_contains "$_plain_out" 'NOT a full pass' \
  'and carries NO shard note - FAILS under a note keyed on "was --shard parsed at all", which would caveat every ordinary run'

unset SCOURSH_SHARD_WEIGHTS_FILE

t_summary run-tests-stage
