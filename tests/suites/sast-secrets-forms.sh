#!/usr/bin/env bash
# tests/suites/sast-secrets-forms.sh - the assignment-form matrix for
# modules/sast/rules/secrets.rules.
#
# The defect this pins: an uppercase, double-quoted, seven-byte credential
# assignment in a .env file was invisible to the scanner.  For a secrets
# scanner a false negative is the product silently failing at its one job, so
# the coverage question is settled by MEASUREMENT against planted controls -
# tests/fixtures/sast-secret-forms/ - and never by reading a regex.
#
# The controls, and what each asserts:
#
#   [[Pnn]]  a positive control.  The shipped pack MUST report a SAST-SEC-*
#            finding on that exact line.  A miss is a false negative.
#   [[Nnn]]  a negative control.  The shipped pack MUST stay quiet.  A hit is
#            noise, and a pack that flags every KEY=value line trains
#            operators to ignore the tool - the same outcome as missing the
#            secret.
#   [[Gnn]]  a control for a STATED architectural gap (a value on a different
#            line from its keyword).  Deliberately asserted neither way; see
#            section E, which pins the gap itself so it cannot be silently
#            assumed covered.
#
# Section B is what makes this a regression suite rather than a snapshot: it
# scans the same tree with the pack AS IT STOOD BEFORE THE FIX and asserts
# each newly-covered form was MISSED then.  That is "seen failing before,
# passing after" re-proved on every run.  It also catches the opposite defect,
# which a "stays quiet" assertion cannot: if the shipped pack ever goes inert,
# section A fails loudly instead of passing by silence.
#
# docs/SECRETS-FORM-MATRIX.md records the full before/after table and the
# reasoning for which forms are covered and which are deliberately not.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIXTURES=$ROOT/tests/fixtures/sast-secret-forms
SHIPPED=$ROOT/modules/sast/rules/secrets.rules
# The commit immediately before this ticket's rule change.  Resolved here, not
# hardcoded into a claim: section B reports SKIPPED (never a silent pass) when
# this object is not in the local history, which is the honest outcome in a
# shallow clone - see tests/suites/netns.sh for the same idiom.
PREFIX_COMMIT=a656663

W=$SCOURSH_SCRATCH/sast-secrets-forms
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scan the control tree with one pack and print "relpath:line<TAB>check_id"
# for every finding.
#
# The fixture directory is passed as a DIRECTORY, exactly as docs/DESIGN.md
# §5's `--path DIR` grammar requires, so loc_path resolves against the real
# scan root (the git toplevel) the way a real invocation does.
# ---------------------------------------------------------------------------
scan_with() {
  local rules=$1 rundir=$2 line
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=secrets-forms
  SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_SAST_MAX_MATCHES_PER_FILE=500
  CHECKS_REGISTRY_SETS=(sfset)
  records_load "$rules" pattern-rule sfset >/dev/null
  sast_index_checks
  local -a ids=()
  local n i
  n=$(records_count sfset)
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id sfset "$i")"); done
  sast_scan_tree "$FIXTURES" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s:%s\t%s\n' "${_DF[loc_path]}" "${_DF[loc_line]}" "${_DF[check_id]}"
  done <"$rundir/findings.fields"
}

# The tag map: every [[Pnn]]/[[Nnn]]/[[Gnn]] tag in the tree, as
# "TAG<TAB>scan-root-relative-path:line".  Built by reading the fixtures, so a
# control added to the tree is asserted without editing this file.
build_tag_map() {
  local prefix f ln rest tag
  prefix=$(git -C "$FIXTURES" rev-parse --show-prefix 2>/dev/null || printf '')
  for f in "$FIXTURES"/*; do
    [[ -f $f ]] || continue
    # grep exits 1 on no-match, which is the normal case for README.md, and
    # under `set -e` that would take the whole loop with it (AGENTS.md,
    # tension 4).  This is a fixture-reading helper rather than a scan, so it
    # is not a scan_match caller; the guard is what keeps it honest.
    while IFS=: read -r ln rest; do
      [[ -n $ln ]] || continue
      # Extract the tag by MATCHING it, never by stripping to the first
      # `[[`: a control line may legitimately contain a bash `[[` of its own
      # before its tag (N24 does), and a prefix-strip silently yields a
      # garbage tag that is then neither P nor N nor G - so the control drops
      # out of the suite unasserted while everything still reports green.
      # That is the exact failure this suite exists to prevent, in the suite
      # itself.  The count guard below is the second half of the defence.
      tag=$(printf '%s' "$rest" | grep -oE '\[\[[PNG][0-9]+\]\]' | head -1 | tr -d '[]')
      [[ -n $tag ]] || continue
      printf '%s\t%s%s:%s\n' "$tag" "$prefix" "$(basename -- "$f")" "$ln"
    done < <({ grep -nE '\[\[[PNG][0-9]+\]\]' "$f" 2>/dev/null || true; })
  done | LC_ALL=C sort
}

# "did the scan report anything at all on this line"
hit_on() {
  local hits=$1 loc=$2
  cut -f1 "$hits" | LC_ALL=C grep -qxF "$loc"
}

# assert_true takes a VALUE (0 or "true"), never a condition string, so every
# predicate below is evaluated here and its status passed in.
truth() {
  if "$@"; then printf 0; else printf 1; fi
}

checks_on() {
  local hits=$1 loc=$2
  awk -F'\t' -v l="$loc" '$1 == l { print $2 }' "$hits" | LC_ALL=C sort -u | paste -sd, -
}

build_tag_map >"$W/tags"
scan_with "$SHIPPED" "$W/run-new" >"$W/hits-new" || true

_n_pos=$(LC_ALL=C grep -c '^P' "$W/tags" || true)
_n_neg=$(LC_ALL=C grep -c '^N' "$W/tags" || true)
_n_gap=$(LC_ALL=C grep -c '^G' "$W/tags" || true)
printf -- '\n-- control tree: %s positive, %s negative, %s gap --\n' \
  "$_n_pos" "$_n_neg" "$_n_gap"

# =============================================================================
printf -- '\n-- 0. the control tree is fully wired into this suite --\n'
# =============================================================================
# Every assertion below iterates the tag map, so a control the map fails to
# parse is not a failure - it is SILENCE, and silence reads as green.  Count
# the tags in the fixture files directly, independently of build_tag_map, and
# require the two to agree.  Without this, dropping a control is indetectable.
_raw_tags=$(cat "$FIXTURES"/* 2>/dev/null | grep -oE '\[\[[PNG][0-9]+\]\]' | wc -l | tr -d ' ')
t_case 'no planted control is silently dropped by the tag parser'
assert_eq "$_raw_tags" "$(( _n_pos + _n_neg + _n_gap ))" \
  'every [[Pnn]]/[[Nnn]]/[[Gnn]] tag in the fixture tree reached the tag map - fails if a control line the parser mishandles drops out unasserted, which would look identical to passing'

# =============================================================================
printf -- '\n-- A. positive controls: every planted credential is reported --\n'
# =============================================================================
# One assertion per control, named by the form it stands for, so a regression
# names the shape that broke rather than a count.
while IFS=$'\t' read -r tag loc; do
  [[ $tag == P* ]] || continue
  t_case "$tag: the planted credential at $loc is reported"
  if hit_on "$W/hits-new" "$loc"; then
    _ck=$(checks_on "$W/hits-new" "$loc")
    assert_contains "$_ck" 'SAST-SEC-' \
      "$tag reported by $_ck - a miss here is a FALSE NEGATIVE, the failure mode this suite exists for"
  else
    assert_true false \
      "$tag at $loc is NOT reported - false negative; the operator reads a clean report and believes it"
  fi
done <"$W/tags"

# =============================================================================
printf -- '\n-- B. the same controls under the PRE-FIX pack: seen failing --\n'
# =============================================================================
# Without this section, section A pins a snapshot rather than a fix: every
# assertion there would pass just as well against a pack that had always been
# correct, so nothing would show the defect was real.  Here the newly-covered
# forms are asserted MISSED by the pack as it stood at PREFIX_COMMIT.
if git -C "$ROOT" cat-file -e "$PREFIX_COMMIT:modules/sast/rules/secrets.rules" 2>/dev/null; then
  git -C "$ROOT" show "$PREFIX_COMMIT:modules/sast/rules/secrets.rules" >"$W/secrets.pre-fix.rules"
  scan_with "$W/secrets.pre-fix.rules" "$W/run-old" >"$W/hits-old" || true

  _newly=0
  _already=0
  while IFS=$'\t' read -r tag loc; do
    [[ $tag == P* ]] || continue
    if hit_on "$W/hits-old" "$loc"; then
      _already=$(( _already + 1 ))
      continue
    fi
    _newly=$(( _newly + 1 ))
    t_case "$tag: newly covered - missed before the fix, found after"
    assert_true "$(truth hit_on "$W/hits-new" "$loc")" \
      "$tag was MISSED at $PREFIX_COMMIT and is found now"
  done <"$W/tags"

  # The counts themselves are the headline docs/SECRETS-FORM-MATRIX.md
  # records, so they are asserted rather than printed: a change that quietly
  # narrows coverage back down fails here even if every individual case above
  # were somehow satisfied.
  t_case 'the pre-fix pack really did miss most of the matrix'
  _newly_ok=1; (( _newly > 0 )) && _newly_ok=0
  assert_true "$_newly_ok" \
    "$_newly of $_n_pos positive controls are NEWLY covered - fails if the pre-fix pack already caught everything, i.e. if there were no defect to fix"
  assert_eq 7 "$_already" \
    "the pre-fix pack caught exactly 7 of $_n_pos - the measured before-figure in docs/SECRETS-FORM-MATRIX.md"
  assert_eq "$_n_pos" "$(( _newly + _already ))" \
    'every positive control is accounted for as either newly covered or already covered'

  # The two independent reasons the reported miss (P15) failed, each proved
  # separately.  Fixing either alone would still have missed it, so a test
  # that only checks P15 would pass against a half-fix.
  t_case 'the reported miss failed for BOTH reasons, not one'
  _p04=$(awk -F'\t' '$1 == "P04" { print $2 }' "$W/tags")
  _p09=$(awk -F'\t' '$1 == "P09" { print $2 }' "$W/tags")
  _p04_miss=0; hit_on "$W/hits-old" "$_p04" && _p04_miss=1
  assert_true "$_p04_miss" \
    'P04 (uppercase identifier, long value) was missed before - proves the case half of the defect, and fails if only the length floor had been wrong'
  _p09_miss=0; hit_on "$W/hits-old" "$_p09" && _p09_miss=1
  assert_true "$_p09_miss" \
    'P09 (lowercase identifier, unquoted value) was missed before - proves the quoting half independently of case'
else
  printf '  SKIPPED  the pre-fix pack (%s) is not in this clone'"'"'s history;\n' "$PREFIX_COMMIT"
  printf '           the before/after halves of this suite could NOT be checked.\n'
  printf '           This is a skip, not a pass - section A above still ran.\n'
fi

# =============================================================================
printf -- '\n-- C. negative controls: benign assignments are not flagged --\n'
# =============================================================================
# Precision is a cost, not an afterthought.  Each of these is a shape that
# looks like a credential assignment and is a reference, a template, a path, a
# policy name, a length, or a placeholder.
while IFS=$'\t' read -r tag loc; do
  [[ $tag == N* ]] || continue
  t_case "$tag: the benign assignment at $loc is not flagged"
  if hit_on "$W/hits-new" "$loc"; then
    assert_true false \
      "$tag at $loc was flagged by $(checks_on "$W/hits-new" "$loc") - noise; a pack that flags this trains operators to ignore the tool"
  else
    assert_true true "$tag stays quiet"
  fi
done <"$W/tags"

# =============================================================================
printf -- '\n-- D. no cross-fire, and no noise on this repository --\n'
# =============================================================================
# secrets.rules ships NO `files:` glob, so it reads every file in whatever tree
# it is pointed at.  That makes tests/fixtures/clean/ - the shared tree every
# pack asserts silence over (AGENTS.md, "cross-fire") - the case that matters
# most for this pack, and it is asserted directly rather than assumed.
_clean=$ROOT/tests/fixtures/clean
if [[ -d $_clean ]]; then
  _saved=$FIXTURES
  FIXTURES=$_clean
  scan_with "$SHIPPED" "$W/run-clean" >"$W/hits-clean" || true
  FIXTURES=$_saved
  t_case 'the widened pack starts no cross-fire on the shared clean tree'
  assert_eq 0 "$(wc -l <"$W/hits-clean" | tr -d ' ')" \
    'zero findings across tests/fixtures/clean - fails if a widened pattern turned the shared clean tree into a false positive against every other pack'
fi

# The pack must not match its own documentation.  The engine has no comment
# awareness anywhere, so a rule header that SPELLS the hazard it describes is
# itself a match - a defect this ticket actually hit and fixed.
_saved=$FIXTURES
FIXTURES=$ROOT/modules/sast/rules
scan_with "$SHIPPED" "$W/run-self" >"$W/hits-self" || true
FIXTURES=$_saved
t_case 'the pack does not report its own rule files'
assert_eq 0 "$(wc -l <"$W/hits-self" | tr -d ' ')" \
  'zero findings across modules/sast/rules - fails if a rule header spells a credential-shaped example instead of describing it'

# =============================================================================
printf -- '\n-- E. the line-oriented gap is real and stays visible --\n'
# =============================================================================
# rules/RULE-FORMAT.md §8.2 freezes matching as line-oriented ("a pattern can
# never match across a newline"), so a value on a different line from its
# keyword is unreachable by ANY pattern rule.  Asserting the gap - rather than
# leaving it unmentioned - is what stops a later reader assuming it is covered,
# and what makes closing it a deliberate register change rather than an
# accident.
_g_missed=0
_g_total=0
while IFS=$'\t' read -r tag loc; do
  [[ $tag == G* ]] || continue
  _g_total=$(( _g_total + 1 ))
  hit_on "$W/hits-new" "$loc" || _g_missed=$(( _g_missed + 1 ))
done <"$W/tags"
t_case 'the multi-line gap is pinned as a gap, not silently assumed covered'
_g_any=1; (( _g_total > 0 )) && _g_any=0
assert_true "$_g_any" \
  'the control tree carries at least one multi-line gap control - fails if the gap stopped being documented'
assert_eq "$_g_total" "$_g_missed" \
  'every multi-line control is UNREPORTED, which is the stated architectural limit; if this ever fails the gap closed and rules/RULE-FORMAT.md §8.2 needs revisiting, not this assertion deleting'

# =============================================================================
printf -- '\n-- F. the shared precision guard has not drifted between rules --\n'
# =============================================================================
# The four assignment rules share one ~14-line `context-deny` block: the same
# references, template syntaxes, name-about-a-credential suffixes and
# placeholders have to be denied for a password, an api key, a secret and a
# bare env assignment alike.  rules/RULE-FORMAT.md has no include mechanism -
# values carry no escaping and a record is a flat key/value block - so that
# block is necessarily DUPLICATED rather than shared, and duplication drifts.
#
# The realistic failure is not a typo: it is a later ticket adding one deny
# line to the rule it was debugging and not to its three siblings, so the same
# benign shape is quiet under `password` and noisy under `token`.  Nothing
# else in the suite would catch that - the control tree would have to happen
# to carry that exact shape under all four keywords.  So compare the blocks
# directly.
# Each rule's block is flattened onto ONE line before `sort -u`, because
# `sort -u` dedupes LINES: emitted as multiple lines, four DIFFERING blocks
# still collapse to one set of shared lines and the count stays 1 whatever
# happens - an assertion that cannot fail.  Measured, not theorised: the first
# draft did exactly that and passed against a deliberately perturbed block.
_nrules=$(LC_ALL=C grep -c '^id: SAST-SEC-\(GENERIC_API_KEY\|GENERIC_PASSWORD\|GENERIC_SECRET\|ENV_ASSIGNMENT\)-01$' "$SHIPPED" || true)
t_case 'the drift guard is looking at all four rules'
assert_eq 4 "$_nrules" \
  'all four assignment rules were found by the extractor below - fails if a rename made the drift guard vacuous by matching nothing'

_blocks=$(awk '
  /^id: SAST-SEC-(GENERIC_API_KEY|GENERIC_PASSWORD|GENERIC_SECRET|ENV_ASSIGNMENT)-01$/ { inrule = 1; n = 0; blk = ""; next }
  inrule && /^context-deny: / { n++; if (n <= 14) blk = blk $0 "\036" }
  inrule && /^context-window: / { if (blk != "") print blk; inrule = 0 }
' "$SHIPPED" | LC_ALL=C sort -u | LC_ALL=C grep -c . || true)

t_case 'the shared deny block is byte-identical across all four assignment rules'
assert_eq 1 "$_blocks" \
  'the four rules share ONE deny block - fails if a later change adds or edits a deny line in one rule and not its siblings, which would make the same benign shape quiet under one keyword and noisy under another'

t_summary sast-secrets-forms
