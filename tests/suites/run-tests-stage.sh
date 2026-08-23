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
#     stage does not walk the real tree.  That variable is a test seam and
#     nothing else: a real run has it unset and still checks every *.sh file.
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
f=
for a in "$@"; do case $a in -*|--) ;; *) f=$a ;; esac; done
b=${f##*/}
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
_stage() {
  local out status=0
  out=$(PATH=$W/bin:$PATH \
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
printf '== C2: the watchdog kill is an unmeasured file, not a finding ==\n'
# ===========================================================================
# The free-memory floor is the cheaper of the stage's two kill paths to drive
# deterministically: set the floor absurdly high and the biggest live process
# is killed on the first sample, without this test having to allocate gigabytes
# to trip the per-process budget.  Same kill, same bookkeeping.
C2_ALIVE=$W/alive-c2
rm -f "$C2_ALIVE"
C2_OUT=$(PATH=$W/bin:$PATH \
      SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
      SCOURSH_SHELLCHECK_FREE_FLOOR_GB=9999999 \
      STUB_PLAN='beta.sh:sleep' STUB_ALIVE=$C2_ALIVE \
      bash "$RUNNER" shellcheck 2>&1) || true
if command -v ps >/dev/null 2>&1; then
  assert_contains "$C2_OUT" '--- shellcheck FAILED' 'a watchdog kill still reaches a verdict line'
  assert_contains "$C2_OUT" 'could NOT be checked' \
    'and the killed file is reported as unmeasured - FAILS under recording it as a shellcheck finding, which would send someone hunting for a defect in a file that was never analysed'
  assert_contains "$C2_OUT" 'watchdog killed' 'and the watchdog states why it killed'
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

t_summary run-tests-stage
