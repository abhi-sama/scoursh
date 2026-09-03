#!/usr/bin/env bash
# tests/suites/state-classify.sh - docs/STEP7-STATE-PLAN.md STATE-03: the
# classification engine (new/recurring/fixed/unknown + diff_usable).
#
# docs/FOUNDATION.md tension 12's four-row table and its two guards
# (fp_schema mismatch, scan_root_id mismatch), and tension 11 stage 5
# (diff_usable governs the gate only, never a status).  This suite exercises
# `lib/findings.sh`'s section 17 functions directly - pure, no scan_main, no
# scan.sh diff, no report - the same isolation `tests/suites/findings.sh`'s
# own tension-6 section already tests `classify_derived` at.
#
# Section A pins the plain four-row table with no guard active.  Section B
# pins the two guards and diff_usable in isolation.  Section C is tension
# 12's own eight-row fixture matrix, each case naming the reading it fails
# under per this project's testing rule - several deliberately plant a
# coverage entry a naive/rejected reading WOULD accept, so the guard (not a
# coincidental absence) is what is actually under test.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/state-classify
rm -rf "$W"
mkdir -p "$W"

_new_repo() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email 'test@example.com'
  git -C "$dir" config user.name 'test'
}

HAVE_GIT=0
command -v git >/dev/null 2>&1 && HAVE_GIT=1

# ---------------------------------------------------------------------------
printf -- '-- section A: the plain four-row table (guard=usable) --\n'
# ---------------------------------------------------------------------------

t_case 'row: present prior, present this run -> recurring'
PRIOR=$W/a-prior-fps
printf 'fpShared\n' >"$PRIOR"
out=$(findings_classify_present fpShared usable path-root "$PRIOR")
assert_eq recurring "$out" \
  'fails under an implementation that never consults prior state at all and always answers new'

t_case 'row: absent prior, present this run -> new'
out=$(findings_classify_present fpNeverSeen usable path-root "$PRIOR")
assert_eq new "$out" \
  'fails under a match that is not exact (e.g. prefix/substring) and spuriously matches fpShared'

t_case 'row: present prior, (C,K) covered, absent this run -> fixed (the whole point)'
COV=$W/a-covered-now
printf 'SAST-A-01\t.\n' >"$COV"
out=$(findings_classify_absent SAST-A-01 . path-root usable "$COV")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under an implementation that never infers fixed from absence at all (permanently unknown)'

t_case 'row: present prior, (C,K) NOT covered (same check, different cell), absent this run -> unknown'
# The (check, cell) pair, not the bare check id, is what must be covered:
# CHECK ran, but over a DIFFERENT cell than the prior finding's own.
printf 'SAST-A-01\tother-cell\n' >"$COV"
out=$(findings_classify_absent SAST-A-01 . path-root usable "$COV")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under check-id-only coverage, which would see SAST-A-01 ran (in a different cell) and call it fixed'
assert_eq 'not-covered-this-run' "${out#*$'\t'}" 'and the reason is recorded'

t_case 'row: present prior, (C,K) not covered at all (no entry for the check), absent this run -> unknown'
: >"$COV"
out=$(findings_classify_absent SAST-A-01 . path-root usable "$COV")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under a coverage test that treats an EMPTY covered-now file as "everything covered" (vacuous true)'

# ---------------------------------------------------------------------------
printf -- '\n-- section B: the two guards, and diff_usable --\n'
# ---------------------------------------------------------------------------

t_case 'findings_classify_guard: matching fp_schema and scan_root_id -> usable'
# argument order: THIS_FP_SCHEMA THIS_SCAN_ROOT_ID THIS_HAS_PATH_ROOT PRIOR_FP_SCHEMA PRIOR_SCAN_ROOT_ID
g=$(findings_classify_guard fp/1 git-remote:x true fp/1 git-remote:x)
assert_eq usable "$g" 'fails under a guard that fires on a match it should let straight through'

t_case 'findings_classify_guard: no prior state (empty PRIOR_FP_SCHEMA) -> no_prior_state'
g=$(findings_classify_guard fp/1 git-remote:x true '' '')
assert_eq no_prior_state "$g" \
  'fails under treating an absent prior fp_schema the same as a present-but-different one'

t_case 'findings_classify_guard: fp_schema differs -> fp_schema_mismatch, regardless of scan_root_id'
g=$(findings_classify_guard fp/2 git-remote:x true fp/1 git-remote:x)
assert_eq fp_schema_mismatch "$g" 'fails under checking scan_root_id before fp_schema'

t_case 'findings_classify_guard: scan_root_id differs, this run HAS path-root findings -> scan_root_id_mismatch'
g=$(findings_classify_guard fp/1 git-remote:x true fp/1 git-remote:y)
assert_eq scan_root_id_mismatch "$g" 'fails under ignoring scan_root_id entirely'

t_case 'findings_classify_guard: scan_root_id differs, this run has NO path-root findings -> usable'
# tension 12: "the gate is scoped to path-root cells and to nothing else" -
# a DAST/cloud/posture-only run cannot be invalidated by a scan_root_id it
# does not depend on.
g=$(findings_classify_guard fp/1 git-remote:x false fp/1 git-remote:y)
assert_eq usable "$g" \
  'fails under an unconditional scan_root_id compare that ignores whether this run touched a path-root cell at all'

t_case 'findings_diff_usable'
assert_eq true "$(findings_diff_usable usable)" 'usable is diff_usable'
assert_eq false "$(findings_diff_usable no_prior_state)" \
  'fails under treating a first run as diff_usable (tension 11 stage 5: no prior state -> diff_usable=false)'
assert_eq false "$(findings_diff_usable fp_schema_mismatch)" 'an fp_schema mismatch is not diff_usable'
assert_eq false "$(findings_diff_usable scan_root_id_mismatch)" 'nor a scan_root_id mismatch'

t_case 'diff_usable never overrides status: a first run classifies new, not unknown'
# tension 11 stage 5's withdrawn-earlier-draft note, made concrete: guard is
# no_prior_state (diff_usable=false) and the finding is still `new`.
g=no_prior_state
out=$(findings_classify_present fpX "$g" path-root "$W/a-prior-fps")
assert_eq new "$out" \
  'fails under conflating diff_usable=false with status=unknown for a finding this run actually found'

t_case 'fp_schema mismatch: treats the WHOLE prior set as empty - present this run is new even if the fingerprint IS in the prior file'
printf 'fpMatchesButSchemaMoved\n' >"$W/b-prior-fps"
out=$(findings_classify_present fpMatchesButSchemaMoved fp_schema_mismatch path-root "$W/b-prior-fps")
assert_eq new "$out" \
  'fails under matching the fingerprint anyway, ignoring the guard (a real risk: the lookup loop is a separate step from the guard check)'

t_case 'fp_schema mismatch: a prior finding persists unknown, NEVER fixed, even when (C,K) IS covered this run'
COV=$W/b-covered-now
printf 'SAST-A-01\t.\n' >"$COV"   # deliberately covered, to prove the guard - not coincidental absence - is what blocks fixed
out=$(findings_classify_absent SAST-A-01 . path-root fp_schema_mismatch "$COV")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under checking coverage before the guard: FOUNDATION.md tension 12 - "the table would have persisted the entire backlog as fixed"'
assert_eq fp_schema_mismatch "${out#*$'\t'}" 'and the reason is recorded'

t_case 'scan_root_id mismatch: a NON-path-root prior finding (target scope) classifies NORMALLY despite the mismatch'
COV=$W/c-covered-now
printf 'DAST-XSS-01\tstaging\n' >"$COV"
out=$(findings_classify_absent DAST-XSS-01 staging target scan_root_id_mismatch "$COV")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under an overly-broad guard that excludes every scope on a scan_root_id mismatch, not only path-root (tension 12: "the rest are classified normally")'

t_case 'scan_root_id mismatch: a path-root prior finding is unknown even when (C,K) IS covered this run'
COV=$W/d-covered-now
printf 'SAST-A-01\t.\n' >"$COV"   # same trap as the fp_schema case above
out=$(findings_classify_absent SAST-A-01 . path-root scan_root_id_mismatch "$COV")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under a naive cell-string compare that matches "." to "." across two genuinely different scan roots'
assert_eq scan_root_id_mismatch "${out#*$'\t'}" 'and the reason is recorded'

t_case 'scan_root_id mismatch: a present path-root finding this run is new even if its fingerprint matches a prior one'
printf 'fpCoincidence\n' >"$W/e-prior-fps"
out=$(findings_classify_present fpCoincidence scan_root_id_mismatch path-root "$W/e-prior-fps")
assert_eq new "$out" \
  'fails under matching by fingerprint alone, ignoring that the whole path-root prior subset is excluded under this guard'

t_case 'findings_rule_digest_changed'
assert_eq true "$(findings_rule_digest_changed digestA digestB)" 'a real change is reported'
assert_eq false "$(findings_rule_digest_changed digestA digestA)" 'an unchanged digest is not'
assert_eq false "$(findings_rule_digest_changed '' digestA)" \
  'fails under flagging every check on a first run, where there is no prior digest to compare against at all'

if (( ! HAVE_GIT )); then
  _t_ok 'git unavailable, the eight-row fixture matrix (section C) is skipped'
  t_summary state-classify
  exit $?
fi

# ---------------------------------------------------------------------------
printf -- '\n-- section C: tension 12'"'"'s eight-row fixture matrix --\n'
# ---------------------------------------------------------------------------

t_case 'row 1: full scan, then sast-only -> zero non-SAST findings fixed'
# Fails under module-blind coverage: a bare diff with no per-check coverage
# tracking at all would see the DAST finding absent this run and, knowing
# only "a scan just ran", call it fixed.
COV=$W/row1-covered-now
printf 'SAST-A-01\t.\n' >"$COV"   # only SAST ran this time
out=$(findings_classify_absent DAST-XSS-01 staging target usable "$COV")
assert_eq unknown "${out%%$'\t'*}" 'the DAST finding is unknown, not fixed, after an sast-only run'

t_case 'row 2: all-region cloud scan, then --regions us-east-1 -> zero eu-west-1 findings fixed'
# Fails under check-id-only coverage: the check DID run this run (in
# us-east-1), so a scheme that covers the bare check id regardless of cell
# would call the eu-west-1 finding fixed.
COV=$W/row2-covered-now
printf 'CLOUD-EC2-SG_OPEN-01\t123456789012/us-east-1\n' >"$COV"
out=$(findings_classify_absent CLOUD-EC2-SG_OPEN-01 '123456789012/eu-west-1' account-region usable "$COV")
assert_eq unknown "${out%%$'\t'*}" 'the eu-west-1 finding is unknown, not fixed'

t_case 'row 3: two-target DAST scan, then one --target -> zero other-target findings fixed'
# Fails under check-id-only coverage, identically to row 2.
COV=$W/row3-covered-now
printf 'DAST-XSS-01\ttarget-a\n' >"$COV"
out=$(findings_classify_absent DAST-XSS-01 target-b target usable "$COV")
assert_eq unknown "${out%%$'\t'*}" 'the other target'"'"'s finding is unknown, not fixed'

t_case 'row 4: non-git tree, --path /srv/app then --path /srv/app/frontend -> zero backend findings fixed'
# Fails under a path-root cell that collapses each scan root to "." without
# comparing scan_root_id: both invocations below independently compute cell
# "." for their own resolved path, and a naive reader would see the SAME
# cell string and (if the check happens to be recorded as covered, as
# planted below) call the backend finding fixed.
APP=$W/row4/app
rm -rf "$APP"
mkdir -p "$APP/frontend"
root_backend=$(scan_root_id_of "$APP")
cell_backend=$(path_root_cell "$APP")
root_frontend=$(scan_root_id_of "$APP/frontend")
cell_frontend=$(path_root_cell "$APP/frontend")
assert_eq '.' "$cell_backend" 'sanity: the backend scan itself is rooted at "."'
assert_eq '.' "$cell_frontend" 'sanity: the frontend-only scan is ALSO rooted at "." - the exact collision this row guards'
assert_ne "$root_backend" "$root_frontend" 'sanity: the two scan roots have different ids (two different absolute paths, neither a git repo)'
guard=$(findings_classify_guard fp/1 "$root_frontend" true fp/1 "$root_backend")
assert_eq scan_root_id_mismatch "$guard" 'the mismatch is detected'
COV=$W/row4-covered-now
printf 'SAST-BACKEND-01\t.\n' >"$COV"   # planted: a naive cell-string-only reader would call this covered
out=$(findings_classify_absent SAST-BACKEND-01 "$cell_backend" path-root "$guard" "$COV")
assert_eq unknown "${out%%$'\t'*}" 'the backend finding stays unknown; the guard, not coincidental absence, is what blocks fixed'

t_case 'row 5: --path /repo then --path /repo/vendor/libfoo (nested repo) -> zero superproject findings fixed'
# Fails identically to row 4, for the git-nested-repo construction: both
# scans again collapse to cell ".", this time distinguished only by two
# DIFFERENT git remotes.
SUPER=$W/row5/super
rm -rf "$SUPER"
_new_repo "$SUPER"
git -C "$SUPER" remote add origin https://example.invalid/org/proj.git
LIBFOO="$SUPER/vendor/libfoo"
_new_repo "$LIBFOO"
git -C "$LIBFOO" remote add origin https://example.invalid/org/libfoo.git
root_super=$(scan_root_id_of "$SUPER")
root_libfoo=$(scan_root_id_of "$LIBFOO")
cell_super=$(path_root_cell "$SUPER")
cell_libfoo=$(path_root_cell "$LIBFOO")
assert_eq '.' "$cell_super" 'sanity: the superproject scan is rooted at "."'
assert_eq '.' "$cell_libfoo" 'sanity: the nested-repo-only scan is ALSO rooted at "."'
assert_ne "$root_super" "$root_libfoo" 'sanity: two different git remotes give two different ids'
guard=$(findings_classify_guard fp/1 "$root_libfoo" true fp/1 "$root_super")
assert_eq scan_root_id_mismatch "$guard" 'the mismatch is detected'
COV=$W/row5-covered-now
printf 'SAST-SUPER-01\t.\n' >"$COV"   # planted, same trap as row 4
out=$(findings_classify_absent SAST-SUPER-01 "$cell_super" path-root "$guard" "$COV")
assert_eq unknown "${out%%$'\t'*}" 'the superproject finding stays unknown'

t_case 'row 6: cd /repo && scan --path . versus cd /repo/src && scan --path /repo -> identical cell, recurring'
# Fails under a cwd-derived or --path-derived root instead of the git
# toplevel: were scan_root computed from cwd or from the literal --path
# string rather than always resolving to the git toplevel, the two
# invocations below would disagree and this finding would wrongly reclassify
# from recurring to new on a run that changed nothing but its own cwd.
REPO=$W/row6/repo
_new_repo "$REPO"
mkdir -p "$REPO/src"
git -C "$REPO" remote add origin https://example.invalid/org/cwd.git
id1=$(cd "$REPO" && scan_root_id_of .)
cell1=$(cd "$REPO" && path_root_cell .)
id2=$(cd "$REPO/src" && scan_root_id_of "$REPO")
cell2=$(cd "$REPO/src" && path_root_cell "$REPO")
assert_eq "$id1" "$id2" 'sanity: scan_root_id is cwd-independent'
assert_eq '.' "$cell1" 'sanity: cell is "."'
assert_eq "$cell1" "$cell2" 'sanity: so is the cell'
guard=$(findings_classify_guard fp/1 "$id2" true fp/1 "$id1")
assert_eq usable "$guard" 'no mismatch: the two invocations agree'
printf 'fpRow6\n' >"$W/row6-prior-fps"
out=$(findings_classify_present fpRow6 "$guard" path-root "$W/row6-prior-fps")
assert_eq recurring "$out" 'the finding recurs; cwd never entered the classification'

t_case 'row 7: same git repo cloned to two different absolute paths -> identical cells, recurring'
# Fails under embedding the checkout path in the cell or in scan_root_id:
# two independent checkouts of the SAME remote, at two different absolute
# scratch paths, must agree - the ordinary two-CI-runner-workspaces shape.
C1=$W/row7/checkout-one
C2=$W/row7/checkout-two-a-longer-name
rm -rf "$C1" "$C2"
_new_repo "$C1"
git -C "$C1" remote add origin https://example.invalid/org/portable.git
_new_repo "$C2"
git -C "$C2" remote add origin https://example.invalid/org/portable.git
id1=$(scan_root_id_of "$C1")
id2=$(scan_root_id_of "$C2")
assert_ne "$C1" "$C2" 'sanity: the two checkouts really are at different absolute paths'
assert_eq "$id1" "$id2" 'sanity: scan_root_id agrees regardless (it is remote-url-based, not path-based)'
guard=$(findings_classify_guard fp/1 "$id2" true fp/1 "$id1")
assert_eq usable "$guard" 'no mismatch across the two checkouts'
printf 'fpRow7\n' >"$W/row7-prior-fps"
out=$(findings_classify_present fpRow7 "$guard" path-root "$W/row7-prior-fps")
assert_eq recurring "$out" 'the finding recurs across the two checkouts'

t_case 'row 8: full clone, --depth 1 clone, and --single-branch clone of a repo with an orphan branch -> one scan_root_id, recurring'
# Fails under any object-graph identity (a root-commit recipe): per
# AGENTS.md's own measured transcript, the root-commit recipe returns
# nothing for the full clone's ref set, the shallow clone's grafted TIP for
# the shallow clone, and a DIFFERENT sha again for the single-branch clone -
# three different answers for one repository.  scan_root_id_of reads
# `remote.origin.url` (a real `git clone` always sets it to the source),
# never the object graph, so all three must agree here.
SRC=$W/row8/src
rm -rf "$SRC"
_new_repo "$SRC"
: >"$SRC/f.txt"
git -C "$SRC" add f.txt
git -C "$SRC" commit -q -m init
git -C "$SRC" checkout -q --orphan orphan-branch
git -C "$SRC" commit -q --allow-empty -m orphan
git -C "$SRC" checkout -q main

FULL=$W/row8/full
SHALLOW=$W/row8/shallow
SINGLE=$W/row8/single
rm -rf "$FULL" "$SHALLOW" "$SINGLE"
# All three clone from the identical file:// URL, deliberately - `git
# clone` records whatever spelling of the source it was given as
# `remote.origin.url` verbatim (a bare local path clone and a file:// clone
# of the SAME repository get two DIFFERENT recorded urls), and the url
# spelling is not what this row is testing.  Only the file:// form actually
# produces a shallow clone at all: `git clone --depth 1` against a bare
# local path silently ignores the flag (git says so itself).
git clone -q "file://$SRC" "$FULL" 2>/dev/null
git clone -q --depth 1 "file://$SRC" "$SHALLOW" 2>/dev/null
git clone -q --single-branch --branch main "file://$SRC" "$SINGLE" 2>/dev/null

assert_true "$(git -C "$SHALLOW" rev-parse --is-shallow-repository)" 'sanity: the shallow clone really is shallow'

id_full=$(scan_root_id_of "$FULL")
id_shallow=$(scan_root_id_of "$SHALLOW")
id_single=$(scan_root_id_of "$SINGLE")
assert_eq "$id_full" "$id_shallow" 'the full and shallow clones share one scan_root_id'
assert_eq "$id_full" "$id_single" 'so does the single-branch clone'

guard_shallow=$(findings_classify_guard fp/1 "$id_shallow" true fp/1 "$id_full")
guard_single=$(findings_classify_guard fp/1 "$id_single" true fp/1 "$id_full")
assert_eq usable "$guard_shallow" 'no mismatch: full versus shallow'
assert_eq usable "$guard_single" 'no mismatch: full versus single-branch'
printf 'fpRow8\n' >"$W/row8-prior-fps"
out=$(findings_classify_present fpRow8 "$guard_shallow" path-root "$W/row8-prior-fps")
assert_eq recurring "$out" 'recurring against the shallow clone'
out=$(findings_classify_present fpRow8 "$guard_single" path-root "$W/row8-prior-fps")
assert_eq recurring "$out" 'recurring against the single-branch clone'

t_summary state-classify
