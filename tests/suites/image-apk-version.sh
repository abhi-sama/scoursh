#!/usr/bin/env bash
# tests/suites/image-apk-version.sh - IMG-05: the apk version comparator, held to the bar
# `modules/sca/semver.sh` set for itself - differential-tested against a
# reference, 0 mismatches or it does not ship.
#
# The bar is met TWICE OVER, because the two halves fail differently and
# neither subsumes the other:
#
#   A. Against a COMMITTED, provenance-annotated corpus of known orderings
#      (tests/fixtures/image/apk-version-corpus.tsv) - 101 hand-checked rows
#      covering every grammar feature apk-tools' own version format defines.
#      This half is what can catch a misreading of the SPEC, because
#      each row's expected ordering was decided from apk-tools' documented
#      grammar rather than from this implementation.  Its limit is its size.
#
#   D. Against an INDEPENDENT Python reference over a generated ~30,000-pair
#      sweep, the same scale and the same shape as `tests/suites/
#      sca-semver.sh`'s own differential.  The reference is written in its
#      own idiom - a regex tokenizer and a tuple comparison, not a
#      transliteration of the bash character scanner - so the two are not
#      the same bug wearing two languages.  This half is what catches an
#      IMPLEMENTATION slip at a scale no hand-written corpus reaches.  Its
#      limit is that it shares this ticket's reading of the spec, which is
#      exactly what half A is for.
#
# WHAT NEITHER HALF PROVES, stated plainly because a reader will otherwise
# assume it: no row here was harvested by running `apk version -t`.  scoursh
# is egress-restricted and the development host has no apk-tools, so both
# references are spec-derived.  The live differential on a networked box is
# named as follow-up hardening in the comparator's own header and in the
# corpus file's, in the same shape as the GNU-tar cross-check
# `tools/daily-suite.sh` defers - a stated gap with a named discharge.
#
# Section B restates every specific measured mismatch as its own
# regression, each naming the reading it FAILS under, per AGENTS.md's rule
# that a test agreeing with both the correct and the rejected reading pins
# nothing.  Section C pins the malformed-input contract AND the field-order
# rule - the comparator's one deliberate divergence from apk-tools, argued in
# full in its own header.  Section E pins the order-theoretic properties
# (totality, antisymmetry, transitivity) that a per-pair corpus cannot
# express, and which apk-tools' own preorder does not have.  Section F pins
# the source-graph leaf property.
#
# MEASURED, not claimed: five deliberate mutations of the comparator were each
# watched taking this suite red, so "seen failing before, passing after" is a
# measurement here rather than a sentence in a commit message.  Comparing the
# pkgrel lexically (semver.sh's own defect) -> 8 failures; inverting the
# field-order rule -> 19; giving the pre-release suffixes positive ranks so
# rule 2b never fires -> 4; dropping the leading-zero fractional rule -> 4;
# and replacing the width-exact digit comparison with `$(( 10#... ))` -> 3.
# A later change that takes any of those counts to 0 has removed a test, not
# fixed one.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh's scratch_init runs at source time and is what sets/exports
# SCOURSH_SCRATCH when no parent run has already handed one down.
# modules/image/distro/apk_version.sh is a deliberate leaf with no lib/
# sourcing of its own (see section F), so this suite needs core directly -
# the identical arrangement tests/suites/sca-semver.sh uses.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=modules/image/distro/apk_version.sh
source "$ROOT/modules/image/distro/apk_version.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/image-apk-version
rm -rf "$W"
mkdir -p "$W"

CORPUS=$ROOT/tests/fixtures/image/apk-version-corpus.tsv

# cmp_p A B -> prints -1|0|1 (or `?`), for the assert_eq cases.  The fork is
# the test harness's, never production's: every real call site uses the
# variable-setting apk_version_cmp_v, per this repository's own rule that a
# side-effecting function called as $(f) loses its writes to the subshell.
cmp_p() { apk_version_cmp "$1" "$2" || true; }

# ---------------------------------------------------------------------------
printf -- '\n-- A. differential against the committed corpus --\n'
# ---------------------------------------------------------------------------
t_case 'the committed corpus exists and every non-comment row carries four TAB-separated columns'
assert_file_exists "$CORPUS" 'the differential corpus is committed, not generated at run time - a generated corpus can only ever agree with the generator'
corpus_rows=$(awk -F'\t' '!/^#/ && NF { n++ } END { print n + 0 }' "$CORPUS")
corpus_bad=$(awk -F'\t' '!/^#/ && NF && NF != 4 { n++ } END { print n + 0 }' "$CORPUS")
assert_eq 0 "$corpus_bad" 'every data row has exactly four columns (A, op, B, why) - a three-column row would silently read the next field as the expectation'
if (( corpus_rows >= 100 )); then
  _t_ok "$corpus_rows hand-checked rows"
else
  _t_no 'at least 100 corpus rows' "only $corpus_rows"
fi

t_case 'the corpus covers every grammar feature and every measured mismatch case'
# Asserted on the corpus FILE rather than on the comparator, because the
# failure this catches is a later ticket quietly deleting the row that
# disqualified semver.sh - which no comparator assertion would notice.
CORPUS_TEXT=$(cat "$CORPUS")
for needed in \
  '1.2.3-r4	<	1.2.3-r10' \
  '1.2.3_alpha1	<	1.2.3' \
  '1.2.3	<	1.2.3_git20240101' \
  '1.2.10	>	1.2.9' \
  '1.0_rc	<	1.0' \
  '1.0	<	1.0_cvs' \
  '1.2.3	<	1.2.3a' \
  '1.01	<	1.1' \
  '1.0	<	1.0-r0' \
  '1.0-r5	<	1.0.1-r0' \
  '1.0_git-r0	<	1.0_git1-r0'
do
  assert_contains "$CORPUS_TEXT" "$needed" "the corpus still carries the row: ${needed//$'\t'/ }"
done

t_case 'apk_version_cmp_v agrees with the committed corpus on every row, in BOTH directions, with 0 mismatches'
mismatches=0
checked=0
unorderable=0
while IFS=$'\t' read -r a op b why; do
  [[ -n $a && ${a:0:1} != '#' ]] || continue
  case $op in
    '<') expected=-1 ;;
    '=') expected=0 ;;
    '>') expected=1 ;;
    *)   mismatches=$(( mismatches + 1 )); printf '    BAD OP: %s\n' "$op" >&2; continue ;;
  esac
  checked=$(( checked + 1 ))
  if ! apk_version_cmp_v "$a" "$b"; then
    unorderable=$(( unorderable + 1 ))
    printf '    UNORDERABLE: %s %s %s (%s)\n' "$a" "$op" "$b" "$why" >&2
    continue
  fi
  if [[ $_APKV_CMP != "$expected" ]]; then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$a" "$b" "$_APKV_CMP" "$expected" "$why" >&2
  fi
  # The MIRROR of the same row.  Without it a comparator that ignored its
  # second argument entirely could still agree with a corpus whose rows all
  # happened to point one way.
  apk_version_cmp_v "$b" "$a"
  if (( _APKV_CMP != -expected )); then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MIRROR MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$b" "$a" "$_APKV_CMP" "$(( -expected ))" "$why" >&2
  fi
done <"$CORPUS"
assert_eq "$corpus_rows" "$checked" 'every committed row was actually exercised, not silently skipped by the reader'
assert_eq 0 "$unorderable" 'no committed row is rejected as malformed - the corpus is all legal apk versions'
assert_eq 0 "$mismatches" \
  "0 mismatches over $checked committed rows and their $checked mirrors - the measured-correctness bar modules/sca/semver.sh sets for itself; the first 10 of any mismatch are printed above"

t_case 'every distinct version in the corpus compares EQUAL to itself'
# Reflexivity is not implied by the rows: a corpus of ordered pairs is
# satisfied by a comparator that gets equality wrong everywhere it is not
# asked, and `=` rows alone only cover the ones a human thought to write.
refl_bad=0
refl_n=0
while IFS= read -r v; do
  [[ -n $v ]] || continue
  refl_n=$(( refl_n + 1 ))
  apk_version_cmp_v "$v" "$v" || { refl_bad=$(( refl_bad + 1 )); continue; }
  (( _APKV_CMP == 0 )) || { refl_bad=$(( refl_bad + 1 )); printf '    NOT REFLEXIVE: %s\n' "$v" >&2; }
done < <(awk -F'\t' '!/^#/ && NF == 4 { print $1; print $3 }' "$CORPUS" | LC_ALL=C sort -u)
assert_eq 0 "$refl_bad" "all $refl_n distinct corpus versions compare equal to themselves"

# ---------------------------------------------------------------------------
printf -- '\n-- B. the specific measured mismatch cases, each naming the reading it fails under --\n'
# ---------------------------------------------------------------------------
t_case 'the pkgrel compares NUMERICALLY: 1.2.3-r4 < 1.2.3-r10'
assert_eq -1 "$(cmp_p 1.2.3-r4 1.2.3-r10)" \
  'FAILS under modules/sca/semver.sh, which splits on the first "-" and compares the prerelease strings "r4" > "r10" LEXICALLY - the false-NEGATIVE direction measured here, where an advisory fixed in -r10 reports a vulnerable -r4 package SAFE'
assert_eq 1 "$(cmp_p 1.2.3-r10 1.2.3-r4)" 'and the reverse direction agrees'
assert_eq -1 "$(cmp_p 1.2.3-r9 1.2.3-r10)" 'and one digit lower, where a lexical read fails identically'

t_case 'this comparator and modules/sca/semver.sh genuinely DISAGREE on that pair, so the new file is load-bearing'
# The point of IMG-05 is that reuse was ruled out by measurement.  Asserting
# the disagreement rather than only the correct answer is what would fail if
# a later ticket "simplified" this file into a semver.sh wrapper - which
# would still pass every other case in this section that semver happens to
# get right.
# shellcheck source=modules/sca/semver.sh
source "$ROOT/modules/sca/semver.sh"
semver_cmp_v 1.2.3-r4 1.2.3-r10
assert_eq 1 "$_SV_CMP" 'semver_cmp_v still answers 1 (A greater) on this pair, exactly as measured earlier in this file - if this ever changes, re-verify the mismatch before touching this comparator'
apk_version_cmp_v 1.2.3-r4 1.2.3-r10
assert_eq -1 "$_APKV_CMP" 'and apk_version_cmp_v answers -1, the true apk ordering - the two comparators are not interchangeable and must not be merged'

t_case 'a pre-release suffix sorts BELOW the bare release: 1.2.3_alpha1 < 1.2.3'
assert_eq -1 "$(cmp_p 1.2.3_alpha1 1.2.3)" \
  'FAILS under a comparator that decides a type mismatch by "the longer token stream wins" alone - that reading puts 1.2.3_alpha1 ABOVE 1.2.3, which is the release/pre-release order backwards'
assert_eq -1 "$(cmp_p 1.2.3_rc1-r4 1.2.3-r0)" 'and a pre-release with a HIGH pkgrel still loses to the release with a low one'

t_case 'a post-release suffix sorts ABOVE the bare release: 1.2.3 < 1.2.3_git20240101'
assert_eq -1 "$(cmp_p 1.2.3 1.2.3_git20240101)" \
  'FAILS under a comparator that treats EVERY _suffix as a pre-release the way SemVer treats every "-" suffix - apk splits its suffix table, and cvs/svn/git/hg/p sort above the bare version'
assert_eq -1 "$(cmp_p 1.2.3_rc1 1.2.3_git1)" 'and a pre-release suffix is below a post-release one on the same version'

t_case 'dotted components compare NUMERICALLY, not lexically: 1.2.10 > 1.2.9'
assert_eq 1 "$(cmp_p 1.2.10 1.2.9)" 'FAILS under a byte comparison, which reads "1" < "9" and gets this backwards'
assert_eq -1 "$(cmp_p 1.9.0 1.10.0)" 'and the same at the minor component'
assert_eq -1 "$(cmp_p 9.0.0 10.0.0)" 'and at the major'

t_case 'the suffix ordering chain holds end to end: alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p'
CHAIN=(1.0_alpha 1.0_beta 1.0_pre 1.0_rc 1.0 1.0_cvs 1.0_svn 1.0_git 1.0_hg 1.0_p)
chain_bad=0
for (( i = 0; i < ${#CHAIN[@]} - 1; i++ )); do
  apk_version_cmp_v "${CHAIN[i]}" "${CHAIN[i+1]}"
  if (( _APKV_CMP != -1 )); then
    chain_bad=$(( chain_bad + 1 ))
    printf '    CHAIN STEP FAILED: %s should be < %s (got %s)\n' "${CHAIN[i]}" "${CHAIN[i+1]}" "$_APKV_CMP" >&2
  fi
done
assert_eq 0 "$chain_bad" 'every adjacent step of apk-tools'"'"' own suffix ordering, including BOTH boundaries with the bare version'

t_case 'equal versions tie, in every shape the grammar allows'
assert_eq 0 "$(cmp_p 1.2.3-r4 1.2.3-r4)" 'with a pkgrel'
assert_eq 0 "$(cmp_p 1.2.3a_alpha1_git5-r7 1.2.3a_alpha1_git5-r7)" 'with every grammar feature at once'
assert_eq 0 "$(cmp_p 1.2.3-r04 1.2.3-r4)" 'a leading zero in the pkgrel is not significant - it is a plain integer'

t_case 'apk is NOT semver: a trailing .0 is a real, GREATER component'
assert_eq -1 "$(cmp_p 1.0 1.0.0)" \
  'FAILS under SemVer 2.0.0, where a missing component is an implicit zero and these two are EQUAL - this is the case that makes merging this comparator with modules/sca/semver.sh impossible rather than merely inadvisable'
assert_eq -1 "$(cmp_p 1.2 1.2.1)" 'and a shorter version is below a longer one that shares its prefix'

t_case 'the optional letter sorts above the bare version and below the next upstream release'
assert_eq -1 "$(cmp_p 1.2.3 1.2.3a)" 'a letter is a later release of the same version'
assert_eq -1 "$(cmp_p 1.2.3a 1.2.3b)" 'and two letters compare by code point'
assert_eq -1 "$(cmp_p 1.2.3a 1.2.4)" 'but a letter never outranks an upstream bump'

t_case 'an ABSENT pkgrel is not -r0 (the row the live differential should scrutinise first)'
# SC2016: the single quotes are deliberate - the message names `apk version
# -t` literally, and nothing in it is an expansion.
# shellcheck disable=SC2016
assert_eq -1 "$(cmp_p 1.0 1.0-r0)" \
  'apk decides this structurally - the stream that ended is the lower one - rather than by synthesising a pkgrel of 0; documented as spec-derived in the comparator header, and one of the two rows the deferred `apk version -t` differential owes a second opinion on'
assert_eq -1 "$(cmp_p 1.0_git 1.0_git0)" 'the identical structural rule one token further in, on a suffix number'

t_case 'a leading zero AFTER a dot makes the component a fraction: 1.01 < 1.1'
assert_eq -1 "$(cmp_p 1.01 1.1)" \
  'FAILS under a plain integer comparison, which reads both components as 1 and calls them EQUAL; apk-tools compares a zero-led component as a fraction.  This is the second of the two spec-derived rows the deferred live differential owes a second opinion on'
assert_eq 0 "$(cmp_p 01.0 1.0)" 'the LEADING component is exempt - it is a plain integer, so a leading zero there changes nothing'

# ---------------------------------------------------------------------------
printf -- '\n-- C. malformed input is UNORDERABLE, deterministically, and never a crash --\n'
# ---------------------------------------------------------------------------
t_case 'apk_version_valid accepts every shape the grammar allows'
for good in 1 1.0 1.2.3 1.2.3a 1.2.3-r0 1.2.3_alpha 1.2.3_alpha1 1.2.3_git20240101 \
            1.2.3a_alpha1_git5-r7 0 20240705-r0 1.2.3_p1_p2
do
  assert_status 0 "accepts $good" apk_version_valid "$good"
done

t_case 'apk_version_valid rejects everything outside it, including the shapes a corrupt or hostile apk DB would carry'
for bad in '' 'x1.0' '1.0-' '1.0-r' '1.0_' '1.0_foo' '1.0.' '.1.0' '1.0 ' '1.0-r1-r2' \
           '1.0_alpha-r1x' '1.2a.3' '1.0+build' '1.0~1' '1:2.0' 'latest'
do
  assert_status 1 "rejects '$bad'" apk_version_valid "$bad"
done

t_case 'an unorderable version returns rc 1 and NEVER an ordering - the failure a caller must not read as "equal"'
# All three silent alternatives - "equal", "less", "greater" - render an
# unreadable version identically to a version that was read and found safe.
# IMG-06's caller owes a coverage_reduction on rc 1; this pins that there is
# something for it to branch on.
# Called directly rather than through assert_status, which runs its command
# in a SUBSHELL - the reason a caller must branch on would be discarded with
# it, and the assertion would then pass against a comparator that set no
# reason at all.
rc=0; apk_version_cmp_v '1.0_foo' '1.0' || rc=$?
assert_eq 1 "$rc" 'a malformed left operand is refused'
assert_eq 'invalid_version_a' "$_APKV_REASON" 'and the side that was unreadable is named'
assert_eq 0 "$_APKV_CMP" 'and no ordering is left behind for a caller to misread as "equal"'
rc=0; apk_version_cmp_v '1.0' '1.0_foo' || rc=$?
assert_eq 1 "$rc" 'a malformed right operand is refused'
assert_eq 'invalid_version_b' "$_APKV_REASON" 'and named on that side too'
rc=0; apk_version_cmp_v 'latest' 'latest' || rc=$?
assert_eq 1 "$rc" 'two malformed operands are refused rather than compared with each other'
assert_eq '?' "$(cmp_p '1.0_foo' '1.0')" 'the printing form emits "?" rather than a number, so a harness cannot mistake a refusal for an ordering'

t_case 'two WELL-FORMED versions are ALWAYS ordered - a refusal always means an unreadable input'
# The naive structural tie-break falls through to EQUAL here, which is what
# apk-tools itself does; this file applies the field-order rule instead,
# because EQUAL means "not below" means "reported safe" - the same
# disqualifying direction measured elsewhere in this suite.  Asserted on
# the ORDERING rather than only on the return status, so "it did not
# refuse" cannot be satisfied by a path that answered EQUAL.
for structural in '1.0-r5 1.0.1-r0' '1.0-r5 1.0a-r0' '1.0_git-r0 1.0_git1-r0' '1.0_git_p-r0 1.0_git1-r0' '1.0-r0 1.0.0-r0'; do
  # shellcheck disable=SC2086
  set -- $structural
  rc=0; apk_version_cmp_v "$1" "$2" || rc=$?
  assert_eq 0 "$rc" "orders $1 against $2 - both are well formed, so neither is ever refused"
  assert_eq -1 "$_APKV_CMP" "and answers LESS rather than EQUAL: the side that reached a LATER field of the grammar passed the earlier one with no content.  FAILS under apk-tools' own fall-through-to-EQUAL, which reads as 'not below' and so as 'not vulnerable'"
  apk_version_cmp_v "$2" "$1"
  assert_eq 1 "$_APKV_CMP" 'and the mirror agrees, so the ordering does not depend on which way round the caller asked'
done

t_case 'a successful comparison clears _APKV_REASON, so a stale reason cannot be read as a fresh refusal'
apk_version_cmp_v '1.0_foo' '1.0' || true
apk_version_cmp_v '1.0' '1.0'
assert_eq '' "$_APKV_REASON" 'the reason from the previous refusal does not survive into the next successful call'

t_case 'a hostile digit run does not wrap, and does not fork'
# $(( 10#$run )) silently wraps at 64 bits, so a corrupt or hostile package
# database could make a very low version compare very high.  The comparator
# compares stripped LENGTH first and bytes second, which is exact at any
# width.  Both operands below exceed 2^64 by orders of magnitude.
# The operands are chosen to differ by exactly 2^64 (18446744073709551616),
# so `$(( 10#$run ))` maps them onto the SAME value - a comparator built on
# arithmetic evaluation cannot tell them apart, and the second pair it orders
# backwards outright.
assert_eq -1 "$(cmp_p "1.1" "1.18446744073709551617")" \
  'FAILS under 64-bit arithmetic evaluation, which wraps the right operand back onto 1 and calls the two EQUAL'
assert_eq 1 "$(cmp_p "1.18446744073709551617" "1.2")" \
  'and FAILS backwards under the same reading, which wraps the left operand onto 1 and reports it BELOW 1.2 - a wrapped digit run does not merely lose precision, it inverts the ordering'
assert_eq -1 "$(cmp_p "1.0-r1" "1.0-r18446744073709551617")" 'the same at the pkgrel'
assert_eq 1 "$(cmp_p "1.100000000000000000000000000000" "1.99999999999999999999999999999")" \
  'and a longer stripped digit run is always the larger number, whatever its width'

t_case 'a version carrying shell metacharacters is refused rather than evaluated'
# Evidence-grade caution: these strings arrive from a scanned image's package
# database (tension 10's "untrusted target output", one step more exposed
# than an OSV-supplied string).  A crash here would be an unhandled abort
# mid-scan; an evaluation would be far worse.
# SC2016: not expanding these is the entire point - they are hostile VERSION
# STRINGS the comparator must refuse, and expanding one here would run it in
# the suite instead of passing it in as data.
# shellcheck disable=SC2016
for hostile in '1.0$(touch '"$W"'/pwned)' '1.0`id`' '1.0;id' '1.0&&id' '$((1+1)).0' '1.0*'; do
  assert_status 1 "refuses '$hostile'" apk_version_valid "$hostile"
done
assert_file_absent "$W/pwned" 'and nothing was executed while deciding that'

# ---------------------------------------------------------------------------
printf -- '\n-- D. differential against an independent Python reference, ~30,000 generated pairs --\n'
# ---------------------------------------------------------------------------
require_cmd python3

python3 - "$W/corpus.txt" "$W/pairs.txt" <<'PY'
import itertools
import re
import sys

corpus_path, pairs_path = sys.argv[1], sys.argv[2]

# --- An INDEPENDENT reference implementation of apk-tools' version ordering.
# Written in its own idiom - a regex tokenizer plus Python tuple comparison -
# rather than transliterated from modules/image/distro/apk_version.sh's
# character scanner, so a slip in one is unlikely to be mirrored in the
# other.  It shares this ticket's reading of the SPEC, which is what the
# committed corpus in section A exists to check separately. ---

# Position in the grammar's field order; higher means "advanced further",
# which means "absent at the earlier field", which means LOWER.
FIELD = {'d': 1, 'z': 1, 'l': 2, 'x': 3, 's': 4, 'r': 5, 'E': 6}

SUFFIX_RANK = {
    'alpha': -4, 'beta': -3, 'pre': -2, 'rc': -1,
    'cvs': 1, 'svn': 2, 'git': 3, 'hg': 4, 'p': 5,
}

# Longest-alternative-first, so `pre` is never lexed as `p` + `re`.
GRAMMAR = re.compile(
    r'''\A
    (?P<head>\d+)
    (?P<dotted>(?:\.\d+)*)
    (?P<letter>[a-z]?)
    (?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)
    (?:-r(?P<rev>\d+))?
    \Z''',
    re.VERBOSE,
)
SUFFIX_RE = re.compile(r'_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)')


def lex(version):
    """Return a list of (kind, value) tokens, or None when unorderable."""
    m = GRAMMAR.match(version)
    if m is None:
        return None
    tokens = [('d', m.group('head'))]
    tokens += [('z', part) for part in m.group('dotted').split('.') if part]
    if m.group('letter'):
        tokens.append(('l', ord(m.group('letter'))))
    for name, number in SUFFIX_RE.findall(m.group('suffixes')):
        tokens.append(('s', SUFFIX_RANK[name]))
        if number:
            tokens.append(('x', number))
    if m.group('rev') is not None:
        tokens.append(('r', m.group('rev')))
    tokens.append(('E', 0))
    return tokens


def value_key(kind, value):
    """Map one token value onto something Python's own ordering handles."""
    if kind == 'z':
        return value  # decided by the caller: integer or fraction
    if kind in ('d', 'x', 'r'):
        return int(value)
    return value  # 'l' and 's' are already integers


def cmp_values(kind, a, b):
    if kind == 'z':
        # A zero-led component on EITHER side makes both fractions: pad right
        # with zeros and compare as strings.  Otherwise plain integers.
        if (len(a) > 1 and a[0] == '0') or (len(b) > 1 and b[0] == '0'):
            width = max(len(a), len(b))
            a, b = a.ljust(width, '0'), b.ljust(width, '0')
            return (a > b) - (a < b)
        a, b = int(a), int(b)
        return (a > b) - (a < b)
    a, b = value_key(kind, a), value_key(kind, b)
    return (a > b) - (a < b)


def ref_cmp(va, vb):
    ta, tb = lex(va), lex(vb)
    if ta is None or tb is None:
        return None
    for (ka, xa), (kb, xb) in zip(ta, tb):
        if ka != kb or ka == 'E':
            break
        decided = cmp_values(ka, xa, xb)
        if decided:
            return decided
    else:  # pragma: no cover - both streams always carry a trailing 'E'
        return 0
    # Structural tie-break, apk's own: a pre-release suffix loses, then the
    # stream that has ended loses, then the two are equal.
    if ka == kb:
        return 0
    if ka == 's' and xa < 0:
        return -1
    if kb == 's' and xb < 0:
        return 1
    # Rule 2c, the field-order rule: whichever side has advanced FURTHER
    # through the grammar passed the earlier field with no content, so it is
    # the lower version.  apk-tools itself falls through to EQUAL here; the
    # divergence is the shipped contract, and section C is where it is argued
    # against named cases rather than merely mirrored here.
    return (FIELD[ka] < FIELD[kb]) - (FIELD[ka] > FIELD[kb])


# --- The generated sweep: a systematic cross-product over every grammar
# feature, at roughly the 30,000-pair scale modules/sca/semver.sh's own
# differential reached on real npm data. ---
corpus = set()
SUFFIXES = ['', '_alpha', '_alpha1', '_alpha2', '_beta', '_beta1', '_pre',
            '_pre1', '_rc', '_rc1', '_rc2', '_cvs', '_svn', '_git',
            '_git1', '_git20240101', '_hg', '_p', '_p1', '_alpha1_git5']
for head in ('0', '1', '2', '10'):
    for dotted in ('', '.0', '.01', '.1', '.9', '.10', '.2.3', '.2.10'):
        for letter in ('', 'a', 'b'):
            for rev in ('', '-r0', '-r4', '-r10'):
                corpus.add(head + dotted + letter + rev)
for suffix in SUFFIXES:
    for base in ('1.2.3', '1.0'):
        for rev in ('', '-r0', '-r10'):
            corpus.add(base + suffix + rev)

corpus = sorted(corpus)
with open(corpus_path, 'w', encoding='utf-8') as fh:
    for v in corpus:
        assert lex(v) is not None, 'generated an unorderable version: %r' % v
        fh.write(v + '\n')

pairs = 0
with open(pairs_path, 'w', encoding='utf-8') as fh:
    for a, b in itertools.combinations(corpus, 2):
        fh.write('%s\t%s\t%d\n' % (a, b, ref_cmp(a, b)))
        pairs += 1

sys.stderr.write('image-apk-version: generated %d version(s), %d pair(s)\n'
                 % (len(corpus), pairs))
PY

t_case 'the generated sweep reaches the scale modules/sca/semver.sh'"'"'s own differential set'
sweep_versions=$(wc -l <"$W/corpus.txt" | tr -d ' ')
sweep_pairs=$(wc -l <"$W/pairs.txt" | tr -d ' ')
if (( sweep_pairs >= 25000 )); then
  _t_ok "$sweep_versions distinct version(s), $sweep_pairs pair(s)"
else
  _t_no 'at least 25,000 generated pairs' "only $sweep_pairs"
fi

t_case 'apk_version_cmp_v agrees with the independent Python reference on every generated pair, 0 mismatches'
sweep_mismatch=0
sweep_checked=0
while IFS=$'\t' read -r a b expected; do
  [[ -n $a ]] || continue
  sweep_checked=$(( sweep_checked + 1 ))
  if ! apk_version_cmp_v "$a" "$b"; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    REFUSED A WELL-FORMED PAIR: cmp(%s, %s)\n' "$a" "$b" >&2
    continue
  fi
  if [[ $_APKV_CMP != "$expected" ]]; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    MISMATCH: cmp(%s, %s) bash=%s reference=%s\n' "$a" "$b" "$_APKV_CMP" "$expected" >&2
  fi
done <"$W/pairs.txt"
assert_eq "$sweep_pairs" "$sweep_checked" 'every generated pair was actually exercised, not silently skipped'
assert_eq 0 "$sweep_mismatch" \
  "0 mismatches over $sweep_checked generated pairs against an independent Python reference - modules/sca/semver.sh's own bar (0/30,000), reached offline; the first 10 of any mismatch are printed above"

# ---------------------------------------------------------------------------
printf -- '\n-- E. order-theoretic properties a per-pair corpus cannot express --\n'
# ---------------------------------------------------------------------------
# A comparator can agree with every row of a corpus and still not be an
# ordering - it only has to be right on the pairs someone wrote down.  These
# are the properties that make it safe for the "is the installed version below
# the fixed-in version" question IMG-06 will ask, and they are also what the
# field-order rule (section C) exists to deliver: apk-tools' own comparison
# is a PREORDER and fails the transitivity case below by construction
# (`1.0-r0 = 1.0.0` and `1.0-r1 = 1.0.0` while `1.0-r0 < 1.0-r1`).
readarray -t ORDER < <(LC_ALL=C sort -u "$W/corpus.txt")

t_case 'totality: every pair from the sweep vocabulary is ordered, and always as one of -1, 0, 1'
# Section D's differential already puts EVERY pair through the comparator and
# counts a refusal as a mismatch, so exhaustive coverage of totality is
# already paid for there; this case samples the same vocabulary and exists to
# state the property under its own name, and to check the RANGE of the answer
# rather than only its agreement with the reference.
total_bad=0
total_refused=0
for (( i = 0; i < ${#ORDER[@]}; i++ )); do
  for (( j = 0; j < ${#ORDER[@]}; j += 11 )); do
    if apk_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; then
      case $_APKV_CMP in -1|0|1) ;; *) total_bad=$(( total_bad + 1 )) ;; esac
    else
      total_refused=$(( total_refused + 1 ))
      (( total_refused > 5 )) || printf '    REFUSED: %s vs %s\n' "${ORDER[i]}" "${ORDER[j]}" >&2
    fi
  done
done
assert_eq 0 "$total_refused" 'no pair of well-formed versions is ever refused - the field-order rule makes the comparison total, so a refusal in production always means an unreadable input rather than an undecidable one'
assert_eq 0 "$total_bad" 'and no pair yields a value outside {-1, 0, 1}'

t_case 'antisymmetry: cmp(A,B) is always the negation of cmp(B,A)'
# Strided rather than exhaustive: the property is structural, so a systematic
# sample across the whole vocabulary catches it, and the exhaustive pass costs
# a second full N-squared walk on top of section D's.
anti_bad=0
anti_n=0
for (( i = 0; i < ${#ORDER[@]}; i++ )); do
  for (( j = i + 1; j < ${#ORDER[@]}; j += 5 )); do
    anti_n=$(( anti_n + 1 ))
    apk_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; forward=$_APKV_CMP
    apk_version_cmp_v "${ORDER[j]}" "${ORDER[i]}"; back=$_APKV_CMP
    (( forward == -back )) && continue
    anti_bad=$(( anti_bad + 1 ))
    (( anti_bad > 5 )) || printf '    ASYMMETRIC: cmp(%s,%s)=%s but cmp(%s,%s)=%s\n' \
      "${ORDER[i]}" "${ORDER[j]}" "$forward" "${ORDER[j]}" "${ORDER[i]}" "$back" >&2
  done
done
assert_eq 0 "$anti_bad" "over $anti_n pairs - FAILS under any structural tie-break that is not itself symmetric - the exact shape of bug that makes 'installed < fixed' and 'fixed > installed' disagree"

# _apkv_sort VERSION... - insertion sort by binary search, no fork, and it
# exercises the comparator in exactly the "is A below B" shape IMG-06 uses.
_apkv_sort() {
  local -a in=("$@") out=()
  local x lo hi mid
  for x in "${in[@]}"; do
    lo=0; hi=${#out[@]}
    while (( lo < hi )); do
      mid=$(( (lo + hi) / 2 ))
      apk_version_cmp_v "${out[mid]}" "$x"
      if (( _APKV_CMP <= 0 )); then lo=$(( mid + 1 )); else hi=$mid; fi
    done
    out=("${out[@]:0:lo}" "$x" "${out[@]:lo}")
  done
  _APKV_SORTED=("${out[@]}")
}

t_case 'transitivity: sorting the sweep vocabulary is stable under re-sorting'
# A non-transitive comparator produces an order that depends on the initial
# arrangement, which no per-pair corpus can detect.  This is the case that
# would go red if the field-order rule were ever replaced by apk-tools' own
# fall-through-to-EQUAL, whose `=` is not transitive.
_apkv_sort "${ORDER[@]}"
sorted_fwd="${_APKV_SORTED[*]}"
readarray -t REV < <(printf '%s\n' "${ORDER[@]}" | LC_ALL=C sort -r)
_apkv_sort "${REV[@]}"
sorted_rev="${_APKV_SORTED[*]}"
assert_eq "$sorted_fwd" "$sorted_rev" \
  'the same vocabulary sorted from two different starting arrangements yields the same sequence'

t_case 'the sorted sequence is non-decreasing under the comparator itself'
seq_bad=0
for (( i = 0; i < ${#_APKV_SORTED[@]} - 1; i++ )); do
  apk_version_cmp_v "${_APKV_SORTED[i]}" "${_APKV_SORTED[i+1]}"
  (( _APKV_CMP <= 0 )) || {
    seq_bad=$(( seq_bad + 1 ))
    printf '    OUT OF ORDER: %s then %s\n' "${_APKV_SORTED[i]}" "${_APKV_SORTED[i+1]}" >&2
  }
done
assert_eq 0 "$seq_bad" 'every adjacent pair of the sorted sequence is <= its successor'

# ---------------------------------------------------------------------------
printf -- '\n-- F. the comparator is a source-graph LEAF, and stays one --\n'
# ---------------------------------------------------------------------------
t_case 'sourcing modules/image/distro/apk_version.sh alone defines the comparator and nothing else'
# AGENTS.md's "the memory model": `shellcheck -x` re-expands every source
# edge it follows and does not memoise, so one edge added to a leaf is paid
# for once per consumer.  modules/dast/passive/response_engine.sh's own
# suite asserts the identical property the identical way - on functions that
# must be UNDEFINED, not on the file's text - so restoring an edge goes red
# immediately instead of surfacing later as a slow linter.
leaf_out=$(
  bash --norc -c '
    set -Eeuo pipefail
    source "$1/modules/image/distro/apk_version.sh"
    declare -F apk_version_cmp_v >/dev/null || { echo MISSING_CMP; exit 0; }
    declare -F apk_version_valid >/dev/null || { echo MISSING_VALID; exit 0; }
    for leaked in scan_match finding_emit run_record http_request config_scanner_list apk_installed_enumerate; do
      declare -F "$leaked" >/dev/null && echo "LEAKED:$leaked"
    done
    echo LEAF_OK
  ' _ "$ROOT" 2>&1
)
assert_contains 'LEAF_OK' "$leaf_out" 'the file sources nothing: no lib/ function, and not even its own sibling modules/image/distro/apk.sh, is defined after sourcing it'
assert_not_contains 'LEAKED:' "$leaf_out" 'nothing leaked in through a source edge'
assert_not_contains 'MISSING_' "$leaf_out" 'and both public entry points are defined'

t_case 'the file is idempotent under a second source, like every other guarded module here'
# SC2016: the `$1`/`$_APKV_CMP` are for the CHILD shell to expand, which is
# what makes this a real second process rather than a string built here.
# shellcheck disable=SC2016
assert_status 0 're-sourcing is a no-op rather than a redefinition' \
  bash --norc -c 'set -Eeuo pipefail; source "$1/modules/image/distro/apk_version.sh"; source "$1/modules/image/distro/apk_version.sh"; apk_version_cmp_v 1.0 1.0; [[ $_APKV_CMP == 0 ]]' _ "$ROOT"

t_summary image-apk-version
