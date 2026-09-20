#!/usr/bin/env bash
# tests/suites/state-history-classify.sh - docs/STEP7-STATE-PLAN.md STATE-04:
# the SAST-HIST-* per-finding history boundary refinement, tension 13's
# second layer composed with tension 12/STATE-03's first.
#
# Layer 1 (STATE-03's (check, cell) coverage test on path-root) is unchanged
# and runs FIRST: an uncovered cell is `unknown` without ever consulting this
# rule.  Layer 2, added here, applies only inside an already-covered cell,
# only for a SAST-HIST-* check: a prior finding whose own
# `oldest_reaching_commit_time` is at or after this run's resolved
# `history_boundary.oldest_commit_time` was inside the range this run
# actually walked, so its absence is real (`fixed`); before it, this run
# could not have seen it whatever the config said (`unknown`).  This layer
# can only narrow a layer-1 `fixed` down to `unknown`, never the reverse.
#
# docs/FOUNDATION.md tension 13's own eight-row fixture table, and where each
# row is proven:
#
#   1  one blob, many commits -> one finding, not one per commit
#        tests/suites/findings.sh: 'two DIFFERENT blobs at one path both
#        take occurrence 0' section (fingerprint/occurrence identity, which
#        this ticket does not touch)
#   2  blob still reachable after working-tree removal -> not fixed
#        tests/suites/sast-history.sh: 'history scan finds the secret that
#        only ever exists in a now-superseded commit' /
#        'the working-tree scan ... does not find it' - history.sh's own
#        discovery is working-tree-independent by construction, so the
#        SAME finding recurs (findings_classify_present's present/present
#        row) rather than ever reaching findings_classify_absent at all
#   3  window narrowed -> unknown                          -- SECTION B, here
#   4  window constant, commit dates advance past cutoff -> unknown
#                                                            -- SECTION B, here
#   5  blob purged, boundary NOT moved -> fixed             -- SECTION B, here
#   6  blob purged, boundary HAS moved, finding's own time still
#      at or after the new boundary -> fixed (the trap)     -- SECTION C, here
#   7  five byte-identical secrets in one blob -> five fingerprints
#        tests/suites/findings.sh: '_fp_components_for history' /
#        tests/suites/sast.sh's sibling occurrence tests (identity, not
#        classification)
#   8  one blob reachable at three paths -> one set of ordinals
#        tests/suites/findings.sh: 'one blob reachable at two paths yields
#        ONE set of ordinals'
#
# Rows 1, 2, 7 and 8 are about `history.sh`'s own finding IDENTITY
# (fingerprint/occurrence), which STATE-04 does not touch and which the
# suites above already pin; this suite carries rows 3-6, the ones that
# belong to classification, plus a direction proof no row in the table
# states explicitly: layer 2 can only turn a layer-1 `fixed` into
# `unknown`, never the reverse (docs/STEP7-STATE-PLAN.md STATE-04's own
# acceptance line).
#
# Section A: layer ordering and the never-promotes-unknown direction proof.
# Section B: rows 3, 4 and 5 - the ordinary boundary-recession/no-recession
#            shapes.
# Section C: row 6, the trap - plus the rejected "boundary folded into the
#            cell" reading, built and shown to fail this exact case.
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

W=$SCOURSH_SCRATCH/state-history-classify
rm -rf "$W"
mkdir -p "$W"

HIST_CHECK=SAST-HIST-AWSKEY-01
ORDINARY_CHECK=SAST-SEC-AWS_AKID-01

COV=$W/covered-now
printf '%s\t.\n' "$HIST_CHECK" >"$COV"
UNCOVERED=$W/uncovered-now
: >"$UNCOVERED"

# Two timestamps, ordered, in the sortable ISO8601 form the codebase already
# relies on for lexical comparison (`_contributor_covered` above this suite's
# own target function uses the identical `>`/`==` idiom).
OLD=2023-01-01T00:00:00Z
NEW=2024-06-01T00:00:00Z

# ---------------------------------------------------------------------------
printf -- '-- section A: layer ordering and the never-promotes-unknown direction --\n'
# ---------------------------------------------------------------------------

t_case 'layer 1 first: an UNCOVERED cell is unknown even when the boundary args would satisfy layer 2'
# oldest_reaching_commit_time (NEW) is at-or-after this run's boundary (OLD),
# which is exactly the condition that lets layer 2 pass through to fixed -
# but the (check, cell) pair itself was never covered this run, so layer 1
# must decide first and layer 2 must never be consulted at all.
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$UNCOVERED" "$NEW" "$OLD")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under an implementation that checks the boundary before coverage, or instead of it'
assert_eq 'not-covered-this-run' "${out#*$'\t'}" \
  'the reason names the real cause (coverage), not the boundary this case never reached'

t_case 'the fp_schema guard stays unknown even when the boundary args would satisfy layer 2'
out=$(findings_classify_absent "$HIST_CHECK" . path-root fp_schema_mismatch "$COV" "$NEW" "$OLD")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under a layer 2 that runs regardless of the guard and overrides it back to fixed'
assert_eq fp_schema_mismatch "${out#*$'\t'}" 'and the guard reason, not a boundary reason, is recorded'

t_case 'the scan_root_id guard (path-root scope) stays unknown even when the boundary args would satisfy layer 2'
out=$(findings_classify_absent "$HIST_CHECK" . path-root scan_root_id_mismatch "$COV" "$NEW" "$OLD")
assert_eq unknown "${out%%$'\t'*}" 'fails under layer 2 running ahead of an unresolved scan_root_id guard'

t_case 'a NON-history check ignores the boundary arguments entirely, even when they would fail layer 2'
# prior_oldest (OLD) is BEFORE this run's boundary (NEW) - the shape that
# downgrades a SAST-HIST-* finding to unknown - but this check id is not in
# the SAST-HIST-* family, so the two trailing arguments must be inert.
printf '%s\t.\n' "$ORDINARY_CHECK" >"$W/ordinary-covered"
out=$(findings_classify_absent "$ORDINARY_CHECK" . path-root usable "$W/ordinary-covered" "$OLD" "$NEW")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under a layer 2 keyed on argument presence alone rather than on the SAST-HIST-* check id'

t_case 'omitted boundary arguments leave layer 2 a no-op: a covered SAST-HIST-* finding is still fixed'
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under a layer 2 that treats missing/empty times as "boundary receded" rather than as "nothing to compare"'

# ---------------------------------------------------------------------------
printf -- '\n-- section B: tension 13 rows 3, 4 and 5 --\n'
# ---------------------------------------------------------------------------

t_case 'row 3: history-window-days narrowed, so this run''s boundary moved past the finding -> unknown'
# The finding's own oldest_reaching_commit_time (OLD) predates the new,
# narrower boundary (NEW) this run actually walked.
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV" "$OLD" "$NEW")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under a settings-blind reading that reports fixed once the (check, cell) pair ran at all'
assert_eq history_boundary_receded "${out#*$'\t'}" 'and the reason names the boundary, not a coverage gap'

t_case 'row 4: window setting held CONSTANT, but the resolved boundary still advanced past the finding -> unknown'
# Nothing here compares configured settings at all - the function has no such
# parameter - so it cannot regress to "settings equal -> fully covered".  The
# only input is the RESOLVED boundary this run actually reached, which is
# what a rolling window advances on every run with no config change.
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV" "$OLD" "$NEW")
assert_eq unknown "${out%%$'\t'*}" \
  'fails under comparing history-window-days/history-max-commits equality instead of the resolved boundary'

t_case 'row 5: blob purged; this run''s boundary did NOT move -> fixed'
# The boundary is unchanged from the run that originally saw the finding, so
# its own oldest_reaching_commit_time is still at-or-after it.
SAME=$NEW
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV" "$SAME" "$SAME")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under a rule that simply disables fixed for the whole SAST-HIST-* family'

# ---------------------------------------------------------------------------
printf -- '\n-- section C: tension 13 row 6, the trap --\n'
# ---------------------------------------------------------------------------

t_case 'row 6: blob purged; boundary HAS moved forward; the finding''s own time is still at or after it -> fixed'
# The ordinary shape on any active repository: a rolling boundary moves on
# essentially every run, yet this particular finding's blob was still inside
# the range this run walked, so its absence really is remediation.
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV" "$NEW" "$OLD")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under a rule that treats ANY boundary movement as disqualifying, rather than comparing per finding'

t_case 'row 6, equality: the finding''s own time equals the new boundary exactly -> still fixed ("at or after")'
out=$(findings_classify_absent "$HIST_CHECK" . path-root usable "$COV" "$NEW" "$NEW")
assert_eq fixed "${out%%$'\t'*}" \
  'fails under a strict-greater-than comparison, which tension 13''s own "at or after" wording rejects'

t_case 'row 6, the rejected reading: folding the boundary into the CELL fails this exact case'
# The trap tension 13 names explicitly: an implementation that makes the
# boundary part of the (check, cell) pair's identity, instead of a value
# compared beside it, sees two different cell strings across the two runs
# and so fails layer 1's own coverage test - never even reaching a time
# comparison - even though the finding is genuinely fixed.
prior_cell="${HIST_CHECK}@${OLD}"
this_run_boundary_cell="${HIST_CHECK}@${NEW}"
rejected_cov=$W/rejected-cov-cell
printf '%s\t%s\n' "$HIST_CHECK" "$this_run_boundary_cell" >"$rejected_cov"
out=$(findings_classify_absent "$HIST_CHECK" "$prior_cell" path-root usable "$rejected_cov")
assert_eq unknown "${out%%$'\t'*}" \
  'demonstrates the rejected reading: a boundary-in-cell implementation gives unknown on row 6, which is wrong'
# The real implementation above, called with the SAME plain cell across both
# runs and the boundary compared as a value, gave fixed for the identical
# scenario - proving the two readings genuinely disagree on this case, which
# is what makes it "the one that matters most" (tension 13's own words).

t_summary state-history-classify
