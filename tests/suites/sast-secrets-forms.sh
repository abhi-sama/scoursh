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

FIXTURES_SRC=$ROOT/tests/fixtures/sast-secret-forms
FP_SRC=$ROOT/tests/fixtures/sast-secret-fp
SHIPPED=$ROOT/modules/sast/rules/secrets.rules
# The commit immediately before this ticket's rule change.  Resolved here, not
# hardcoded into a claim: section B reports SKIPPED (never a silent pass) when
# this object is not in the local history, which is the honest outcome in a
# shallow clone - see tests/suites/netns.sh for the same idiom.
PREFIX_COMMIT=a656663

W=$SCOURSH_SCRATCH/sast-secrets-forms
rm -rf "$W"
mkdir -p "$W"
# Canonical, so a scanned path and its scan root agree (macOS TMPDIR sits
# behind the /var -> /private/var symlink, and the walk strips the scan root
# as a literal prefix).
W=$(cd -- "$W" && pwd -P)

# The control trees live under tests/, which the keyword records exclude as a
# NON-PRODUCTION path (SAST-SEC-NONPROD_CREDENTIAL-01 reports those paths at
# `low` instead).  This suite measures the production records, so it scans
# COPIES placed outside any repository, where every path is an ordinary
# application path; section G scans the same tree under a tests/ directory to
# pin the path policy itself.  Scanning in place would silently turn every
# section below into a test of the non-production record.
FIXTURES=$W/app
cp -R "$FIXTURES_SRC" "$FIXTURES"

# ---------------------------------------------------------------------------
# Scan the control tree with one pack and print "relpath:line<TAB>check_id"
# for every finding.
#
# The fixture directory is passed as a DIRECTORY, exactly as docs/DESIGN.md
# §5's `--path DIR` grammar requires, so loc_path resolves against the real
# scan root (the git toplevel) the way a real invocation does.
# ---------------------------------------------------------------------------
scan_with() {
  local rules=$1 rundir=$2 dir=${3:-$FIXTURES} line
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=secrets-forms
  SCOURSH_PATH_ROOT=$(path_root_cell "$dir")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$dir")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_SAST_MAX_MATCHES_PER_FILE=500
  CHECKS_REGISTRY_SETS=(sfset)
  records_load "$rules" pattern-rule sfset >/dev/null
  sast_index_checks
  local -a ids=()
  local n i
  n=$(records_count sfset)
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id sfset "$i")"); done
  sast_scan_tree "$dir" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s:%s\t%s\t%s\n' "${_DF[loc_path]}" "${_DF[loc_line]}" "${_DF[check_id]}" "${_DF[severity]}"
  done <"$rundir/findings.fields"
}

# The tag map: every [[Pnn]]/[[Nnn]]/[[Gnn]] tag in the tree, as
# "TAG<TAB>scan-root-relative-path:line".  Built by reading the fixtures, so a
# control added to the tree is asserted without editing this file.
build_tag_map() {
  local dir=${1:-$FIXTURES} prefix=${2-} f rel ln rest tag
  if [[ $# -lt 2 ]]; then
    prefix=$(git -C "$dir" rev-parse --show-prefix 2>/dev/null || printf '')
  fi
  while IFS= read -r f; do
    rel=${f#"$dir"/}
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
      tag=$(printf '%s' "$rest" | grep -oE '\[\[[PNGQR][0-9]+\]\]' | head -1 | tr -d '[]')
      [[ -n $tag ]] || continue
      printf '%s\t%s%s:%s\n' "$tag" "$prefix" "$rel" "$ln"
    done < <({ grep -nE '\[\[[PNGQR][0-9]+\]\]' "$f" 2>/dev/null || true; })
  done < <(find "$dir" -type f | LC_ALL=C sort) | LC_ALL=C sort
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
_raw_tags=$(cat "$FIXTURES_SRC"/* 2>/dev/null | grep -oE '\[\[[PNG][0-9]+\]\]' | wc -l | tr -d ' ')
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
# Most secrets rules apply to every file; ENV_ASSIGNMENT alone excludes JS/TS
# source, whose unquoted expressions do not establish literal credentials.
# That makes tests/fixtures/clean/ - the shared tree every pack asserts silence over (AGENTS.md, "cross-fire") - the case that matters
# most for this pack, and it is asserted directly rather than assumed.
_clean=$ROOT/tests/fixtures/clean
if [[ -d $_clean ]]; then
  cp -R "$_clean" "$W/clean"
  scan_with "$SHIPPED" "$W/run-clean" "$W/clean" >"$W/hits-clean" || true
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
printf -- '\n-- F. the shared precision guards and path lists have not drifted --\n'
# =============================================================================
# The four assignment rules share one guard block: the same references,
# template syntaxes, name-about-a-credential suffixes and placeholders have to
# be denied for a password, an api key, a secret and a bare env assignment
# alike.  rules/RULE-FORMAT.md has no include mechanism - values carry no
# escaping and a record is a flat key/value block - so that block is
# necessarily DUPLICATED rather than shared, and duplication drifts.
#
# The realistic failure is not a typo: it is a later ticket adding one guard
# line to the rule it was debugging and not to its three siblings, so the same
# benign shape is quiet under `password` and noisy under `token`.  Nothing
# else in the suite would catch that - the control tree would have to happen
# to carry that exact shape under all four keywords.  So compare the blocks
# directly.
#
# A guard is a `context-deny` or a `match-deny` line.  The SHARED block is the
# set of guard lines all four rules carry; each rule may add only its own
# documented extras on top: the digit guard on the secret and API-key rules
# (an issued value carries a digit), two password-only guards (lowercase
# words joined by separators, and the well-known defaults that
# SAST-SEC-DEFAULT_PASSWORD-01 reports instead), and the unquoted-only
# reference guards on ENV_ASSIGNMENT.  Drift in either direction moves an
# extras count: a line added to one rule raises that rule's count, and a line
# dropped from one rule shrinks the shared block and raises the other three.
_rec_lines() {
  awk -v want="$1" -v key="$2" '
    /^id: / { inrule = ($0 == "id: " want) }
    inrule && /^$/ { inrule = 0 }
    inrule && index($0, key ": ") == 1 { print substr($0, length(key) + 3) }
  ' "$SHIPPED"
}
_guards() { { _rec_lines "$1" context-deny | sed 's/^/C /'; _rec_lines "$1" match-deny | sed 's/^/M /'; }; }
_KW=(SAST-SEC-GENERIC_API_KEY-01 SAST-SEC-GENERIC_SECRET-01 SAST-SEC-GENERIC_PASSWORD-01 SAST-SEC-ENV_ASSIGNMENT-01)
_nrules=$(LC_ALL=C grep -c '^id: SAST-SEC-\(GENERIC_API_KEY\|GENERIC_PASSWORD\|GENERIC_SECRET\|ENV_ASSIGNMENT\)-01$' "$SHIPPED" || true)
t_case 'the drift guard is looking at all four rules'
assert_eq 4 "$_nrules" \
  'all four assignment rules were found by the extractor below - fails if a rename made the drift guard vacuous by matching nothing'

for _id in "${_KW[@]}"; do _guards "$_id" | LC_ALL=C sort -u >"$W/guards.$_id"; done
cp "$W/guards.${_KW[0]}" "$W/guards.shared"
for _id in "${_KW[@]:1}"; do
  LC_ALL=C comm -12 "$W/guards.shared" "$W/guards.$_id" >"$W/guards.tmp"
  mv "$W/guards.tmp" "$W/guards.shared"
done
# The size of the common policy block: 8 line-scoped context-denies and 15
# match-scoped guards.  Asserted as a number so a block that silently shrank
# to nothing (every rule edited the same wrong way) cannot pass as agreement.
SHARED_GUARDS=23
t_case 'the shared guard block has its expected size'
assert_eq "$SHARED_GUARDS" "$(wc -l <"$W/guards.shared" | tr -d ' ')" \
  'all four rules share exactly the documented guard block - fails if a guard was dropped from one rule (the shared set shrinks) or the block was edited in all four without updating this count'

_extras() { LC_ALL=C comm -23 "$W/guards.$1" "$W/guards.shared" | wc -l | tr -d ' '; }
t_case 'each rule carries exactly its own documented extras on top of the shared block'
assert_eq 1 "$(_extras SAST-SEC-GENERIC_API_KEY-01)" 'GENERIC_API_KEY adds only the digit guard'
assert_eq 1 "$(_extras SAST-SEC-GENERIC_SECRET-01)" 'GENERIC_SECRET adds only the digit guard'
assert_eq 2 "$(_extras SAST-SEC-GENERIC_PASSWORD-01)" 'GENERIC_PASSWORD adds only the lowercase-words guard and the defaults guard'
assert_eq 10 "$(_extras SAST-SEC-ENV_ASSIGNMENT-01)" 'ENV_ASSIGNMENT adds only its ten unquoted-value guards'
assert_eq "$(LC_ALL=C comm -23 "$W/guards.SAST-SEC-GENERIC_API_KEY-01" "$W/guards.shared")" \
  "$(LC_ALL=C comm -23 "$W/guards.SAST-SEC-GENERIC_SECRET-01" "$W/guards.shared")" \
  'the secret and API-key rules carry the SAME extra (the digit guard), byte for byte'

# Order matters too: the shared lines appear in the same order in every rule,
# so a reviewer reading one record has read all four.  Each rule's shared
# subsequence is flattened onto ONE line before `sort -u`, because `sort -u`
# dedupes LINES: emitted as multiple lines, four DIFFERING blocks still
# collapse to one set of shared lines and the count stays 1 whatever happens.
_ordered=$(for _id in "${_KW[@]}"; do
  _guards "$_id" | LC_ALL=C grep -Fxf "$W/guards.shared" | paste -sd $'\036' -
done | LC_ALL=C sort -u | LC_ALL=C grep -c . || true)
t_case 'the shared guard block appears in the same order in all four rules'
assert_eq 1 "$_ordered" \
  'one ordering of the shared block across the four rules - fails if a guard was moved in one rule only'

# The two shared path lists: localisation catalogues, then non-production
# paths.  The keyword rules and SAST-SEC-DEFAULT_PASSWORD-01 carry them
# byte-identically; SAST-SEC-NONPROD_CREDENTIAL-01 claims exactly the
# non-production half as its `files:` and excludes exactly the localisation
# half, so every path is reported by one side and never both.
# ENV_ASSIGNMENT alone also excludes JavaScript/TypeScript source, where an
# unquoted object property or default argument is a reference (the six
# language globs at the head of its list); every other entry is shared.
_JSTS='*.js *.jsx *.[cm]js *.ts *.tsx *.[cm]ts'
_shared_excludes() {
  if [[ $1 == SAST-SEC-ENV_ASSIGNMENT-01 ]]; then
    _rec_lines "$1" exclude-files | tail -n +7
  else
    _rec_lines "$1" exclude-files
  fi
}
t_case 'ENV_ASSIGNMENT carries exactly the JS/TS source globs on top of the shared list'
assert_eq "$_JSTS" "$(_rec_lines SAST-SEC-ENV_ASSIGNMENT-01 exclude-files | head -6 | paste -sd' ' -)" \
  'the six language globs, first - fails if one was dropped or another rule-specific path was added'
_PATHREC=("${_KW[@]}" SAST-SEC-DEFAULT_PASSWORD-01)
_lists=$(for _id in "${_PATHREC[@]}"; do _shared_excludes "$_id" | paste -sd $'\036' -; done | LC_ALL=C sort -u | LC_ALL=C grep -c . || true)
t_case 'the keyword rules share one exclude-files list'
assert_eq 1 "$_lists" \
  'the five keyword rules exclude the same paths, in the same order - fails if one rule stopped excluding a test or locale path its siblings exclude'
t_case 'SAST-SEC-NONPROD_CREDENTIAL-01 claims exactly the paths the keyword rules exclude'
assert_eq "$(_rec_lines SAST-SEC-GENERIC_SECRET-01 exclude-files)" \
  "$(_rec_lines SAST-SEC-NONPROD_CREDENTIAL-01 exclude-files; _rec_lines SAST-SEC-NONPROD_CREDENTIAL-01 files)" \
  'its exclude-files (the locale half) followed by its files (the non-production half) is the keyword rules list - fails if a test path is excluded from the keyword rules and claimed by nothing, which is a silent false negative'
assert_eq "($(_rec_lines SAST-SEC-GENERIC_PASSWORD-01 pattern)|$(_rec_lines SAST-SEC-GENERIC_API_KEY-01 pattern)|$(_rec_lines SAST-SEC-GENERIC_SECRET-01 pattern)|$(_rec_lines SAST-SEC-ENV_ASSIGNMENT-01 pattern))" \
  "$(_rec_lines SAST-SEC-NONPROD_CREDENTIAL-01 pattern)" \
  'its pattern is the union of the four keyword patterns, verbatim - fails if one keyword pattern changed and the non-production record kept the old one'
_guards SAST-SEC-NONPROD_CREDENTIAL-01 | LC_ALL=C sort -u >"$W/guards.nonprod"
assert_eq 0 "$(LC_ALL=C comm -23 "$W/guards.shared" "$W/guards.nonprod" | wc -l | tr -d ' ')" \
  'it carries every shared guard - fails if it reports a reference shape on a test path that the keyword rules deny everywhere else'

t_case 'severity policy: keyword matches never read as CRITICAL'
for _id in "${_KW[@]}" SAST-SEC-JWT-01; do
  assert_eq high "$(_rec_lines "$_id" severity-ceiling)" \
    "$_id carries severity-ceiling: high - fails if the rubric's sensitive_data step can raise a medium-confidence keyword match to critical again"
done
assert_eq medium "$(_rec_lines SAST-SEC-DEFAULT_PASSWORD-01 severity-ceiling)" 'a well-known default password is capped at medium'
assert_eq low "$(_rec_lines SAST-SEC-NONPROD_CREDENTIAL-01 severity-ceiling)" 'a test, docs, example or CI literal is capped at low'

# =============================================================================
printf -- '\n-- G. the non-production path policy --\n'
# =============================================================================
# The same control tree, placed under tests/: every planted credential must
# still be reported - so the path policy is never a silent false negative -
# but only by SAST-SEC-NONPROD_CREDENTIAL-01, at low, and every negative
# control must stay quiet there too.  And in the application copy scanned
# above, that record must never appear.
mkdir -p "$W/np/tests"
cp -R "$FIXTURES_SRC" "$W/np/tests/forms"
build_tag_map "$W/np/tests/forms" tests/forms/ >"$W/tags-np"
scan_with "$SHIPPED" "$W/run-np" "$W/np" >"$W/hits-np" || true
while IFS=$'\t' read -r tag loc; do
  case $tag in
    P*)
      t_case "$tag under tests/: reported, by the non-production record only"
      assert_eq 'SAST-SEC-NONPROD_CREDENTIAL-01' "$(checks_on "$W/hits-np" "$loc")" \
        "$tag at $loc - fails if a test-path credential is dropped (a false negative) or still reported by a production record (a duplicate)"
      ;;
    N*)
      t_case "$tag under tests/: still quiet"
      assert_eq '' "$(checks_on "$W/hits-np" "$loc")" \
        "$tag at $loc - fails if the non-production record is looser than the production records it stands in for"
      ;;
  esac
done <"$W/tags-np"
t_case 'every non-production finding is low'
assert_eq '' "$(awk -F'\t' '$3 != "low"' "$W/hits-np" | head -3)" \
  'no finding under tests/ is above low - fails if the severity ceiling on the non-production record is lost'
t_case 'the application copy never reports through the non-production record'
assert_eq 0 "$(awk -F'\t' '$2 == "SAST-SEC-NONPROD_CREDENTIAL-01"' "$W/hits-new" | wc -l | tr -d ' ')" \
  'an ordinary application path is reported by the production records - fails if the non-production globs match ordinary paths'

# =============================================================================
printf -- '\n-- H. false positives measured on real repositories stay gone --\n'
# =============================================================================
# tests/fixtures/sast-secret-fp/ carries verbatim shapes this pack reported as
# CRITICAL hardcoded credentials on real public repositories (names, enums,
# module paths, validator tags, references, i18n strings, PEM helpers, public
# JWTs), plus real credentials its line-wide guards silently dropped.  Each is
# asserted against the shipped pack AND against the pack as it stood before the
# fix (FP_PREFIX_COMMIT), so "flagged before, quiet now" is measured on every
# run rather than claimed:
#   [[Nnn]] flagged before, quiet now     [[Qnn]] quiet before and now
#   [[Pnn]] reported before and now       [[Rnn]] missed before, reported now
FP_PREFIX_COMMIT=703bd14
cp -R "$FP_SRC" "$W/fp"
build_tag_map "$W/fp" '' >"$W/tags-fp"
scan_with "$SHIPPED" "$W/run-fp" "$W/fp" >"$W/hits-fp" || true
_fp_before=0
if git -C "$ROOT" cat-file -e "$FP_PREFIX_COMMIT:modules/sast/rules/secrets.rules" 2>/dev/null; then
  git -C "$ROOT" show "$FP_PREFIX_COMMIT:modules/sast/rules/secrets.rules" >"$W/secrets.fp-before.rules"
  scan_with "$W/secrets.fp-before.rules" "$W/run-fp-old" "$W/fp" >"$W/hits-fp-old" || true
  _fp_before=1
else
  printf '  SKIPPED  the pre-fix pack (%s) is not in this clone'"'"'s history;\n' "$FP_PREFIX_COMMIT"
  printf '           the "before" half of section H could NOT be checked.\n'
fi
t_case 'the false-positive control tree is wired in'
_fp_raw=$(find "$FP_SRC" -type f -exec cat {} + | grep -oE '\[\[[PNQR][0-9]+\]\]' | wc -l | tr -d ' ')
assert_eq "$_fp_raw" "$(wc -l <"$W/tags-fp" | tr -d ' ')" \
  'every tag in tests/fixtures/sast-secret-fp reached the tag map'
while IFS=$'\t' read -r tag loc; do
  case $tag in
    N* | Q*)
      t_case "$tag: $loc is not reported"
      assert_eq '' "$(checks_on "$W/hits-fp" "$loc")" "$tag at $loc stays quiet"
      ;;
    P* | R*)
      t_case "$tag: $loc is reported"
      assert_true "$(truth hit_on "$W/hits-fp" "$loc")" \
        "$tag at $loc is reported - a miss is a false negative"
      ;;
  esac
  (( _fp_before )) || continue
  case $tag in
    N* | P*)
      assert_true "$(truth hit_on "$W/hits-fp-old" "$loc")" "$tag was reported by the pack before the fix" ;;
    Q* | R*)
      assert_true "$(truth sh -c '! cut -f1 "$1" | LC_ALL=C grep -qxF "$2"' _ "$W/hits-fp-old" "$loc")" \
        "$tag was NOT reported by the pack before the fix" ;;
  esac
done <"$W/tags-fp"
_fp_loc() { awk -F'\t' -v t="$1" '$1 == t { print $2 }' "$W/tags-fp"; }
_fp_sev() { awk -F'\t' -v l="$(_fp_loc "$1")" '$1 == l { print $2 "/" $3 }' "$W/hits-fp"; }
t_case 'a well-known default password moves to SAST-SEC-DEFAULT_PASSWORD-01 at medium'
assert_eq 'SAST-SEC-DEFAULT_PASSWORD-01/medium' "$(_fp_sev P03)" 'unquoted POSTGRES_PASSWORD=secret'
assert_eq 'SAST-SEC-DEFAULT_PASSWORD-01/medium' "$(_fp_sev P04)" 'quoted db_password="password"'
t_case 'severity: keyword findings stop at high, provider shapes stay critical'
assert_eq 'SAST-SEC-ENV_ASSIGNMENT-01/high' "$(_fp_sev P05)" 'an unquoted token literal is high, not critical'
assert_eq 'SAST-SEC-JWT-01/high' "$(_fp_sev P06)" 'a signed JWT is high, not critical'
assert_eq 'SAST-SEC-AWS_AKID-01/critical' "$(_fp_sev R06)" 'an ABIA bearer-token id is now matched, at critical'

# =============================================================================
printf -- '\n-- I. framework build output is not walked --\n'
# =============================================================================
# `.next/static/chunks/` holds a generated copy of the source; reporting it is
# a duplicate of the source finding, or a match inside minified vendor code.
# Measured before the fix: the same line was reported under `.next/` and
# skipped under `dist/`.  `coverage/` stays walked on purpose, since it is
# also a real source package name.
_bt=$W/buildtree
for _d in src .next/static/chunks .nuxt/dist .svelte-kit/output .output/server .vercel/output \
  .turbo/cache .angular/cache storybook-static dist coverage; do
  mkdir -p "$_bt/$_d"
  printf 'const session = { token: "s3cr3tT0kenV4lue0000" };\n' >"$_bt/$_d/app.js"
done
scan_with "$SHIPPED" "$W/run-build" "$_bt" >"$W/hits-build" || true
t_case 'framework build directories are skipped like dist/ and build/'
assert_eq 'coverage/app.js:1 src/app.js:1' "$(cut -f1 "$W/hits-build" | LC_ALL=C sort -u | paste -sd' ' -)" \
  'only the source copy and coverage/ are reported - fails if .next/.nuxt/.svelte-kit/.output/.vercel/.turbo/.angular/storybook-static are walked again, or if the source copy stopped being reported'
unset _bt _d

# =============================================================================
printf -- '\n-- J. a reused --out starts from an empty run --\n'
# =============================================================================
# Measured before the fix: scan a file holding a credential, delete the
# credential, scan again into the same --out, and the finding was still
# reported (status `recurring`) because findings_merge globbed the first run's
# shards back in.  A real scan.sh subprocess, against a secrets-only install
# root and an isolated SCOURSH_HOME so nothing touches this checkout's state/.
_jr=$W/root-secrets-only
mkdir -p "$_jr"
for _e in lib modules rules data tools VERSION scan.sh; do cp -R "$ROOT/$_e" "$_jr/$_e"; done
find "$_jr/modules/sast/rules" -name '*.rules' ! -name secrets.rules -delete
_jr=$(cd -- "$_jr" && pwd -P)
_jt=$W/reuse-tree
mkdir -p "$_jt"
printf 'API_TOKEN=s3cr3tT0kenV4lue0000\n' >"$_jt/app.env"
_jo=$W/reuse-out
_jscan() {
  env SCOURSH_INSTALL_ROOT="$_jr" SCOURSH_HOME="$W/reuse-home" \
    bash "$_jr/scan.sh" "$@" >/dev/null 2>&1 || true
}
_jscan sast --path "$_jt" --out "$_jo" --format json
mkdir -p "$_jo/inventory"
printf '{"seeded": true}\n' >"$_jo/inventory/endpoints.json"
t_case 'the first scan reports the credential'
assert_contains "$(cat "$_jo/findings.jsonl" 2>/dev/null)" 'SAST-SEC-ENV_ASSIGNMENT-01' 'sanity: the credential is found'
printf 'API_TOKEN_FILE=/run/secrets/api_token\n' >"$_jt/app.env"
_jscan sast --path "$_jt" --out "$_jo" --format json
t_case 'the second scan into the same --out does not replay the removed credential'
assert_not_contains "$(cat "$_jo/findings.jsonl" 2>/dev/null)" 'SAST-SEC-ENV_ASSIGNMENT-01' \
  'the credential that is gone from the tree is not reported - fails if the earlier run'"'"'s shards are merged back in'
assert_eq 1 "$(grep -c . "$_jo/meta/started_at" 2>/dev/null || echo 0)" \
  'the run facts are this run'"'"'s alone - fails if meta/ kept the earlier run'"'"'s lines'
assert_contains "$(cat "$_jo/inventory/endpoints.json" 2>/dev/null)" 'seeded' \
  'an operator-seeded inventory file in --out is kept'
t_case 'report --from DIR --out DIR still regenerates in place'
_jstart=$(head -1 "$_jo/meta/started_at" 2>/dev/null || true)
_jscan report --from "$_jo" --out "$_jo" --format md
assert_file_exists "$_jo/report.md" 'report.md is regenerated'
assert_file_exists "$_jo/findings.fields" 'the run it regenerates from keeps its findings - fails if the reset reached the report command'
assert_eq "$_jstart" "$(head -1 "$_jo/meta/started_at" 2>/dev/null || true)" \
  'and keeps its own run facts'
unset _jr _jt _jo _e _jstart

t_summary sast-secrets-forms
