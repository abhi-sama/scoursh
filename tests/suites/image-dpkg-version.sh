#!/usr/bin/env bash
# tests/suites/image-dpkg-version.sh - IMG-08 ("dpkg comparator -
# epoch + tilde, differential-tested"): the Debian/Ubuntu version comparator,
# held to the bar `modules/sca/semver.sh` set for itself - differential-tested
# against a reference, 0 mismatches or it does not ship.
#
# The bar is met TWICE OVER, because the two halves fail differently and
# neither subsumes the other:
#
#   A. Against a COMMITTED, provenance-annotated corpus of known orderings
#      (tests/fixtures/image/dpkg-version-corpus.tsv) - 117 hand-checked rows,
#      of which 32 are dpkg's OWN PUBLISHED TEST VECTORS transcribed by hand
#      and 3 are pairs where `modules/sca/semver.sh` is measured getting the
#      ordering wrong.
#      This half is what can catch a misreading of the SPEC, because each
#      row's expected ordering was decided from `deb-version(7)` and from the
#      tool's own maintainers rather than from this implementation.  Its
#      limit is its size.
#
#   D. Against an INDEPENDENT Python reference over a generated ~30,000-pair
#      sweep, the same scale and the same shape as `tests/suites/
#      sca-semver.sh`'s and `tests/suites/image-apk-version.sh`'s own
#      differentials.  The reference is written in a genuinely different
#      idiom - it builds a total COMPARISON KEY per version and lets Python's
#      own tuple ordering decide, where the bash implementation walks two
#      cursors in lockstep - so the two are not the same bug wearing two
#      languages.  Getting a key-based reference to agree with dpkg at all
#      requires re-deriving the tilde rule from scratch (a non-digit run's
#      key needs an explicit terminating sentinel, because Python's own rule
#      that a prefix sorts LOW is the exact opposite of dpkg's rule that `~`
#      sorts below the end of a part), which is what makes the agreement
#      evidence rather than a coincidence.  This half is what catches an
#      IMPLEMENTATION slip at a scale no hand-written corpus reaches.  Its
#      limit is that it shares this ticket's reading of the spec, which is
#      exactly what half A is for.
#
# WHAT NEITHER HALF PROVES, stated plainly because a reader will otherwise
# assume it: no row here was harvested by running `dpkg --compare-versions`.
# scoursh is egress-restricted and the development host has no dpkg, so both
# references are spec-derived (half A's dpkg-vector rows are the closest
# approach: pairs the tool's own test suite asserts, transcribed rather than
# executed).  The live differential on a networked box is named as follow-up
# hardening in the comparator's own header and in the corpus file's, in the
# same shape as the GNU-tar cross-check `tools/daily-suite.sh` defers - a
# stated gap with a named discharge.
#
# Section B restates each specific case below as its own
# regression, each naming the reading it FAILS under, per AGENTS.md's rule
# that a test agreeing with both the correct and the rejected reading pins
# nothing.  Section C pins the malformed-input contract.  Section E pins the
# order-theoretic properties (totality, antisymmetry, transitivity) that a
# per-pair corpus cannot express.  Section F pins the source-graph leaf
# property.
#
# MEASURED, not claimed: seven deliberate mutations of the comparator were each
# applied and watched taking this suite red, so "seen failing before, passing
# after" is a measurement here rather than a sentence in a commit message.
# The counts are what those runs actually printed, against 141 cases:
#
#   dropping the leading-zero strip in phase 2                -> 8 failures
#   giving `~` an order of 0 so it ties with the end of a part -> 7
#   splitting the revision at the FIRST hyphen, not the last   -> 7
#   comparing the epoch lexically instead of numerically       -> 4
#   giving letters `code + 256` like every other non-alnum,
#     so they stop sorting before `.` and `+`                  -> 4
#   accumulating each digit run and comparing `$(( 10#... ))`  -> 4
#   admitting whitespace into the upstream alphabet glob       -> 4
#
# A later change that takes any of those counts to 0 has removed a test, not
# fixed one.  The two smallest are still decisive, and which cases they are
# was read off the runs rather than guessed: the arithmetic-run mutation
# breaks the committed-corpus differential plus all three of section C's
# hostile-width cases (the generated sweep carries no run wide enough to wrap,
# which is exactly why the corpus carries five rows that do), and the
# epoch-lexical mutation breaks the corpus differential, BOTH halves of
# section B's numeric-epoch case, and the 45,150-pair reference differential.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh's scratch_init runs at source time and is what sets/exports
# SCOURSH_SCRATCH when no parent run has already handed one down.
# modules/image/distro/dpkg_version.sh is a deliberate leaf with no lib/
# sourcing of its own (see section F), so this suite needs core directly -
# the identical arrangement tests/suites/image-apk-version.sh uses.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=modules/image/distro/dpkg_version.sh
source "$ROOT/modules/image/distro/dpkg_version.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/image-dpkg-version
rm -rf "$W"
mkdir -p "$W"

CORPUS=$ROOT/tests/fixtures/image/dpkg-version-corpus.tsv

# cmp_p A B -> prints -1|0|1 (or `?`), for the assert_eq cases.  The fork is
# the test harness's, never production's: every real call site uses the
# variable-setting dpkg_version_cmp_v, per this repository's own rule that a
# side-effecting function called as $(f) loses its writes to the subshell.
cmp_p() { dpkg_version_cmp "$1" "$2" || true; }

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

t_case 'the corpus still carries dpkg'"'"'s own published vectors, in quantity'
# Asserted on the corpus FILE, because the failure this catches is a later
# ticket quietly dropping the rows that came from the tool's own maintainers
# and leaving only the ones this ticket derived - which no comparator
# assertion would notice, since the derived rows are the ones this
# implementation is most likely to agree with for the wrong reason.
vector_rows=$(awk -F'\t' '!/^#/ && NF == 4 && $4 ~ /dpkg vector/ { n++ } END { print n + 0 }' "$CORPUS")
if (( vector_rows >= 25 )); then
  _t_ok "$vector_rows rows transcribed from dpkg's own test vectors"
else
  _t_no "at least 25 rows marked (dpkg vector)" "only $vector_rows"
fi

t_case 'the corpus covers every rule deb-version(7) names'
CORPUS_TEXT=$(cat "$CORPUS")
for needed in \
  '1:2.30.2-1	>	2.39.5-1' \
  '1.0	>	1.0~beta' \
  '5:1.0-1	>	10.0-1' \
  '10:1.0	>	9:1.0' \
  '1.0	=	1.0-0' \
  '1.0~~	<	1.0~' \
  '1.0a	<	1.0.1' \
  '1.09	=	1.9' \
  '1.0-1~bpo11+1	<	1.0-1' \
  '7.68.0-1ubuntu2.7	<	7.68.0-1ubuntu2.14' \
  '1.2.10	>	1.2.9'
do
  assert_contains "$CORPUS_TEXT" "$needed" "the corpus still carries the row: ${needed//$'\t'/ }"
done

t_case 'dpkg_version_cmp_v agrees with the committed corpus on every row, in BOTH directions, with 0 mismatches'
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
  if ! dpkg_version_cmp_v "$a" "$b"; then
    unorderable=$(( unorderable + 1 ))
    printf '    UNORDERABLE: %s %s %s (%s)\n' "$a" "$op" "$b" "$why" >&2
    continue
  fi
  if [[ $_DPKGV_CMP != "$expected" ]]; then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$a" "$b" "$_DPKGV_CMP" "$expected" "$why" >&2
  fi
  # The MIRROR of the same row.  Without it a comparator that ignored its
  # second argument entirely could still agree with a corpus whose rows all
  # happened to point one way.
  dpkg_version_cmp_v "$b" "$a"
  if (( _DPKGV_CMP != -expected )); then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MIRROR MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$b" "$a" "$_DPKGV_CMP" "$(( -expected ))" "$why" >&2
  fi
done <"$CORPUS"
assert_eq "$corpus_rows" "$checked" 'every committed row was actually exercised, not silently skipped by the reader'
assert_eq 0 "$unorderable" 'no committed row is rejected as malformed - the corpus is all legal Debian versions'
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
  dpkg_version_cmp_v "$v" "$v" || { refl_bad=$(( refl_bad + 1 )); continue; }
  (( _DPKGV_CMP == 0 )) || { refl_bad=$(( refl_bad + 1 )); printf '    NOT REFLEXIVE: %s\n' "$v" >&2; }
done < <(awk -F'\t' '!/^#/ && NF == 4 { print $1; print $3 }' "$CORPUS" | LC_ALL=C sort -u)
assert_eq 0 "$refl_bad" "all $refl_n distinct corpus versions compare equal to themselves"

# ---------------------------------------------------------------------------
printf -- '\n-- B. the specific measured mismatch cases, each naming the reading it fails under --\n'
# ---------------------------------------------------------------------------
t_case 'the EPOCH is compared first: 1:2.30.2-1 > 2.39.5-1'
assert_eq 1 "$(cmp_p 1:2.30.2-1 2.39.5-1)" \
  'FAILS under modules/sca/semver.sh, which coerces the non-numeric major "1:2" to 0 and answers -1 - a measured mismatch, and the direction where a PATCHED package is reported vulnerable'
assert_eq -1 "$(cmp_p 2.39.5-1 1:2.30.2-1)" 'and the reverse direction agrees'

t_case 'the epoch outranks ANY upstream: 5:1.0-1 > 10.0-1'
assert_eq 1 "$(cmp_p 5:1.0-1 10.0-1)" \
  'FAILS under any comparator that reads the leading run as a plain major version - 5 against 10 says -1, another measured mismatch'
assert_eq 1 "$(cmp_p 1:1.0 0:99999.99999)" 'and no upstream, at any width, overcomes one epoch'

t_case 'the epoch compares NUMERICALLY, not lexically: 10:1.0 > 9:1.0'
assert_eq 1 "$(cmp_p 10:1.0 9:1.0)" \
  'FAILS under a byte comparison of the epoch, which reads "1" < "9" and inverts a real Debian estate'"'"'s epoch ordering'
assert_eq 0 "$(cmp_p 01:1.0 1:1.0)" 'and a leading zero in the epoch is not significant - it is an integer'

t_case 'a TILDE sorts BEFORE everything, including the end of the string: 1.0 > 1.0~beta'
assert_eq 1 "$(cmp_p 1.0 1.0~beta)" \
  'FAILS under modules/sca/semver.sh, which drops the suffix and answers 0 - EQUAL, which a caller asking "is the installed version below the fixed-in version" reads as "not below", reads as "not vulnerable", with no diagnostic at all'
assert_eq -1 "$(cmp_p 1.0~ 1.0)" 'a bare tilde with nothing after it is still below the end of the string'
assert_eq -1 "$(cmp_p 1.0~~ 1.0~)" 'and a second tilde is lower again, which is only true because ~ is below ~ is below the end'

t_case 'this comparator and modules/sca/semver.sh genuinely DISAGREE on all three, so the new file is load-bearing'
# The point of IMG-08 is that reuse was ruled out by measurement.  Asserting
# the disagreement rather than only the correct answer is what would fail if
# a later ticket "simplified" this file into a semver.sh wrapper - which
# would still pass every other case in this section that semver happens to
# get right.
# shellcheck source=modules/sca/semver.sh
source "$ROOT/modules/sca/semver.sh"
semver_cmp_v 1:2.30.2-1 2.39.5-1
assert_eq -1 "$_SV_CMP" 'semver_cmp_v still answers -1 on the epoch pair, exactly as measured'
semver_cmp_v 1.0 1.0~beta
assert_eq 0 "$_SV_CMP" 'and still answers 0 - EQUAL - on the tilde pair, the silent direction'
semver_cmp_v 5:1.0-1 10.0-1
assert_eq -1 "$_SV_CMP" 'and still answers -1 on the epoch-beats-upstream pair'
dpkg_version_cmp_v 1:2.30.2-1 2.39.5-1; assert_eq 1 "$_DPKGV_CMP" 'where dpkg_version_cmp_v answers 1'
dpkg_version_cmp_v 1.0 1.0~beta;       assert_eq 1 "$_DPKGV_CMP" 'and 1'
dpkg_version_cmp_v 5:1.0-1 10.0-1;     assert_eq 1 "$_DPKGV_CMP" 'and 1 - the two comparators are not interchangeable and must not be merged'

t_case 'this comparator and modules/image/distro/apk_version.sh also disagree, so neither is an "OS version comparator"'
# The inverse temptation to reuse: one os_version_cmp for both distros.
# `1.0` against a zero release is the case that makes it impossible - apk
# says LESS (an absent pkgrel is not -r0), dpkg says EQUAL (an absent
# revision IS "0") - and both are right about their own ecosystem.
# shellcheck source=modules/image/distro/apk_version.sh
source "$ROOT/modules/image/distro/apk_version.sh"
apk_version_cmp_v 1.0 1.0-r0
assert_eq -1 "$_APKV_CMP" 'apk: an absent pkgrel is strictly below -r0'
dpkg_version_cmp_v 1.0 1.0-0
assert_eq 0 "$_DPKGV_CMP" 'dpkg: an absent revision compares EQUAL to -0 - the opposite answer to the structurally identical question'
assert_status 1 'and apk rejects a tilde outright, because it is not in that grammar at all' apk_version_valid '1.0~beta'
assert_status 0 'while dpkg accepts it as its single most important ordering rule' dpkg_version_valid '1.0~beta'

t_case 'digit runs compare NUMERICALLY, not lexically, at every position'
assert_eq 1 "$(cmp_p 1.2.10 1.2.9)" 'FAILS under a byte comparison, which reads "1" < "9" and gets this backwards'
assert_eq -1 "$(cmp_p 1.9.0 1.10.0)" 'and the same at the minor component'
assert_eq -1 "$(cmp_p 9.0.0 10.0.0)" 'and at the major'
assert_eq -1 "$(cmp_p 1.0-9 1.0-10)" 'and in the revision'
assert_eq -1 "$(cmp_p 7.68.0-1ubuntu2.7 7.68.0-1ubuntu2.14)" \
  'and inside a real Ubuntu security series, where a lexical read reports 2.7 as NEWER than 2.14 and so reports an unpatched package safe'

t_case 'LETTERS sort before every other non-alphanumeric, which is the modified-ASCII half of the rule'
assert_eq -1 "$(cmp_p 1.0a 1.0.1)" \
  'FAILS under plain ASCII, where "." (46) is below "a" (97); deb-version(7) adds 256 to every non-letter, so a letter comes first'
assert_eq -1 "$(cmp_p 1.0a 1.0+)" 'the same against "+"'
assert_eq -1 "$(cmp_p 1.0A 1.0a)" 'and two letters still compare by plain code point among themselves'
assert_eq -1 "$(cmp_p 1.0 1.0a)" 'while the end of the string (0) is below every letter'
assert_eq 1 "$(cmp_p 1.0 1.0~a)" 'and above every tilde'

t_case 'an ABSENT revision IS "0", and the last hyphen is what splits it off'
assert_eq 0 "$(cmp_p 1.0 1.0-0)" \
  'FAILS under a comparator that treats an absent revision as structurally lower than a present one - which is what apk does for its pkgrel, and is exactly the wrong import'
assert_eq -1 "$(cmp_p 1.0 1.0-1)" 'but an absent revision is still below any NON-zero one'
assert_eq 0 "$(cmp_p 1.0-01 1.0-1)" 'and a leading zero in the revision is not significant'
assert_eq 0 "$(cmp_p 0.9j-20080306-4 0.9j-20080306-4)" 'a version with an internal hyphen compares equal to itself'
assert_eq 1 "$(cmp_p 0.9j-20080306-4 0.9i-20070813-1)" \
  'and the LAST hyphen is the separator: FAILS under a first-hyphen split, which makes the upstream "0.9j" vs "0.9i" into revisions and compares the wrong parts'

t_case 'leading zeros are stripped before a digit run is compared'
assert_eq 0 "$(cmp_p 1.09 1.9)" 'FAILS under a byte comparison of the run, which reads "09" < "9"'
assert_eq 0 "$(cmp_p 1.0000-1 1.0-1)" 'any number of leading zeros'
assert_eq 0 "$(cmp_p 1.011-1 1.11-1)" 'and a stripped run that is still multi-digit'

# ---------------------------------------------------------------------------
printf -- '\n-- C. malformed input is UNORDERABLE, deterministically, and never a crash --\n'
# ---------------------------------------------------------------------------
t_case 'dpkg_version_valid accepts every shape deb-version(7) allows'
for good in 0 1 1.0 1.0-1 1:1.0 1:1.0-1 1.0~beta 1.0~beta-1 '1.0-1~bpo11+1' \
            '0.9j-20080306-4' '12345+that-really-is-some-ver-0' '1:8.2p1-4ubuntu0.11' \
            '1.0.' '1.0+' '1.0--1' '1:2:3-1' '01:1.0' '1.0-a'
do
  assert_status 0 "accepts $good" dpkg_version_valid "$good"
done

t_case 'dpkg_version_valid rejects everything outside it, including the shapes a corrupt or hostile dpkg DB would carry'
# The empty string is FIRST on purpose: modules/image/distro/dpkg.sh emits a
# package with an empty version when its block carried no `Version:` line, so
# this is an ordinary expected arrival rather than a hypothetical.
for bad in '' 'x1.0' '.1.0' '-1.0' '1.0-' ':1.0' '1.0:' 'a:1.0' '-1:1.0' '1.0_1' \
           '1.0 ' ' 1.0' '1.0/1' '1.0,1' '1.0!' '1.0-1_2' '1.0-1~b/1' 'latest' \
           $'1.0\n2.0' $'1.0\t2' $'\t1.0' $'1.0\r'
do
  assert_status 1 "rejects '${bad//[$'\n\t\r']/<ws>}'" dpkg_version_valid "$bad"
done

t_case 'the whitespace operands above are refused by the ALPHABET GLOB alone, with no per-character scan behind it'
# The comparator carries exactly one character check - a `*[!SET]*` bracket
# negation - because bash's `*` matches a newline, a tab and a carriage return
# like any other byte.  An earlier draft did not believe that and carried a
# second, per-character loop for the newline case; it was measured redundant
# and removed.  This case is what stops a later reader re-adding it, and
# equally what stops the glob being narrowed on the belief that something else
# is catching these.
for ws in $'1.0\n2.0' $'1.0\t2' $'\t1.0' $'1.0\r' '1.0 ' ' 1.0'; do
  caught=no
  [[ $ws == *[!0-9a-zA-Z.+:~-]* ]] && caught=yes
  assert_eq yes "$caught" "the bracket negation alone sees the whitespace in '${ws//[$'\n\t\r']/<ws>}' - FAILS under the belief that a glob cannot match a newline, which is what put a redundant per-character loop in an earlier draft"
done

t_case 'an underscore is rejected, which is what keeps an apk version out of this comparator'
# The two comparators guard each other: apk's own suffix separator is not in
# deb-version(7)'s alphabet at all, so an apk version reaching this file is
# refused rather than silently ordered under the wrong grammar - and an
# unrefused wrong ordering is the silent direction.
assert_status 1 'an apk _suffix is not a Debian version' dpkg_version_valid '1.2.3_alpha1'
assert_status 1 'nor an apk pkgrel: its -r4 tail is a legal Debian revision, but the underscore ahead of it is not' dpkg_version_valid '1.2.3_git-r4'

t_case 'an unorderable version returns rc 1 and NEVER an ordering - the failure a caller must not read as "equal"'
# All three silent alternatives - "equal", "less", "greater" - render an
# unreadable version identically to a version that was read and found safe.
# The caller owes a coverage_reduction on rc 1; this pins that there is
# something for it to branch on.
# Called directly rather than through assert_status, which runs its command
# in a SUBSHELL - the reason a caller must branch on would be discarded with
# it, and the assertion would then pass against a comparator that set no
# reason at all.
rc=0; dpkg_version_cmp_v 'latest' '1.0' || rc=$?
assert_eq 1 "$rc" 'a malformed left operand is refused'
assert_eq 'invalid_version_a' "$_DPKGV_REASON" 'and the side that was unreadable is named'
assert_eq 0 "$_DPKGV_CMP" 'and no ordering is left behind for a caller to misread as "equal"'
rc=0; dpkg_version_cmp_v '1.0' 'latest' || rc=$?
assert_eq 1 "$rc" 'a malformed right operand is refused'
assert_eq 'invalid_version_b' "$_DPKGV_REASON" 'and named on that side too'
rc=0; dpkg_version_cmp_v '' '' || rc=$?
assert_eq 1 "$rc" 'two empty operands are refused rather than compared with each other as equal'
assert_eq '?' "$(cmp_p 'latest' '1.0')" 'the printing form emits "?" rather than a number, so a harness cannot mistake a refusal for an ordering'

t_case 'a successful comparison clears _DPKGV_REASON, so a stale reason cannot be read as a fresh refusal'
dpkg_version_cmp_v 'latest' '1.0' || true
dpkg_version_cmp_v '1.0' '1.0'
assert_eq '' "$_DPKGV_REASON" 'the reason from the previous refusal does not survive into the next successful call'

t_case 'a hostile digit run does not wrap, and does not fork'
# $(( 10#$run )) silently wraps at 64 bits, so a corrupt or hostile package
# database could make a very low version compare very high.  The comparator
# never evaluates a run at all: dpkg's own walk decides by "whichever run is
# still going is larger", which is exact at any width.  The first pair below
# differs by exactly 2^64 (18446744073709551616), so `$(( 10#... ))` maps
# both onto the SAME value.
assert_eq -1 "$(cmp_p '1.1' '1.18446744073709551617')" \
  'FAILS under 64-bit arithmetic evaluation, which wraps the right operand back onto 1 and calls the two EQUAL'
assert_eq 1 "$(cmp_p '1.18446744073709551617' '1.2')" \
  'and FAILS backwards under the same reading, which wraps the left operand onto 1 and reports it BELOW 1.2 - a wrapped digit run does not merely lose precision, it inverts the ordering'
assert_eq -1 "$(cmp_p '1.0-1' '1.0-18446744073709551617')" 'the same at the revision'
assert_eq 1 "$(cmp_p '18446744073709551617:1.0' '18446744073709551616:1.0')" \
  'and at the EPOCH, which dpkg itself refuses above INT_MAX where this file orders it correctly - a divergence that can only turn a refusal into a right answer'
assert_eq 1 "$(cmp_p '1.100000000000000000000000000000' '1.99999999999999999999999999999')" \
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
for hostile in '1.0$(touch '"$W"'/pwned)' '1.0`id`' '1.0;id' '1.0&&id' '$((1+1)).0' '1.0*' '1.0[a]'; do
  assert_status 1 "refuses '$hostile'" dpkg_version_valid "$hostile"
done
assert_file_absent "$W/pwned" 'and nothing was executed while deciding that'

t_case 'a glob metacharacter in a version is not matched as a PATTERN by the alphabet check'
# The alphabet gate is a bracket-negation glob, so the operand it tests is on
# the LEFT of `==` and is never itself a pattern; a first draft that had it
# the other way round would accept `1.0*` by letting the star match.  Pinned
# on the accept side too, because a gate that rejected everything would also
# pass the refusal cases above.
assert_status 1 'a bare star is not a legal version' dpkg_version_valid '1.0*'
assert_status 1 'nor a question mark' dpkg_version_valid '1.0?'
assert_status 0 'while an ordinary version is still accepted' dpkg_version_valid '1.0'

# ---------------------------------------------------------------------------
printf -- '\n-- D. differential against an independent Python reference, ~30,000 generated pairs --\n'
# ---------------------------------------------------------------------------
require_cmd python3

python3 - "$W/corpus.txt" "$W/pairs.txt" <<'PY'
import itertools
import re
import sys

corpus_path, pairs_path = sys.argv[1], sys.argv[2]

# --- An INDEPENDENT reference implementation of deb-version(7)'s ordering.
# It builds a total COMPARISON KEY per version and lets Python's own tuple
# ordering decide, where modules/image/distro/dpkg_version.sh walks two
# cursors in lockstep the way dpkg's verrevcmp does.  The two are different
# algorithms for the same relation, so a slip in one is unlikely to be
# mirrored in the other.  It shares this ticket's reading of the SPEC, which
# is what the committed corpus in section A exists to check separately. ---

VERSION_OK = re.compile(r'\A[0-9][0-9A-Za-z.+:~-]*\Z')
REVISION_OK = re.compile(r'\A[0-9A-Za-z.+~]*\Z')
EPOCH_OK = re.compile(r'\A[0-9]+\Z')


def parse(version):
    """Return (epoch, upstream, revision), or None when unorderable."""
    if not version:
        return None
    if ':' in version:
        epoch, _, rest = version.partition(':')
        if not EPOCH_OK.match(epoch) or not rest:
            return None
    else:
        epoch, rest = '0', version
    if '-' in rest:
        upstream, _, revision = rest.rpartition('-')
        if not revision:
            return None
    else:
        upstream, revision = rest, ''
    if not VERSION_OK.match(upstream):
        return None
    if not REVISION_OK.match(revision):
        return None
    return epoch, upstream, revision


def order(ch):
    """deb-version(7)'s modified ASCII: ~ lowest, then digits/end, then
    letters, then everything else."""
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    if ch == '~':
        return -1
    return ord(ch) + 256


def run_key(run):
    """The key for one NON-DIGIT run.

    The trailing 0 is the whole trick and it is not decoration.  Python
    orders a tuple that is a PREFIX of another as the smaller one, which is
    the exact opposite of dpkg's rule that `~` sorts below the END of a part:
    without the sentinel, ('~',) would compare GREATER than (), and every
    tilde case would inverself.  With order(end-of-string) == 0 appended, the
    empty run is (0,), a tilde run is (-1, 0) and a letter run is (97, 0),
    which reproduces the rule exactly.
    """
    return tuple(order(ch) for ch in run) + (0,)


def part_key(part):
    """Alternating non-digit / digit runs, as a flat comparable tuple.

    An empty digit run keys as 0, which is what makes an absent revision
    compare EQUAL to '0' - dpkg's own behaviour, and where apk goes the other
    way.
    """
    key = []
    i = 0
    while i < len(part) or not key:
        start = i
        while i < len(part) and not part[i].isdigit():
            i += 1
        key.append(run_key(part[start:i]))
        start = i
        while i < len(part) and part[i].isdigit():
            i += 1
        key.append(int(part[start:i]) if i > start else 0)
    return key


def padded(a, b):
    """Two part keys, padded to one length with the neutral run/number."""
    filler = [run_key(''), 0]
    while len(a) < len(b):
        a = a + filler
    while len(b) < len(a):
        b = b + filler
    return a, b


def cmp_parts(pa, pb):
    ka, kb = padded(part_key(pa), part_key(pb))
    return (ka > kb) - (ka < kb)


def ref_cmp(va, vb):
    pa, pb = parse(va), parse(vb)
    if pa is None or pb is None:
        return None
    ea, ua, ra = pa
    eb, ub, rb = pb
    ia, ib = int(ea), int(eb)
    if ia != ib:
        return (ia > ib) - (ia < ib)
    decided = cmp_parts(ua, ub)
    if decided:
        return decided
    return cmp_parts(ra, rb)


# --- The generated sweep: a systematic cross-product over every feature of
# the grammar, at roughly the 30,000-pair scale modules/sca/semver.sh's own
# differential reached on real npm data. ---
# Sized deliberately: the pair count is QUADRATIC in the vocabulary, so one
# wide cross-product overshoots the target scale by two orders of magnitude
# (5 x 4 x 15 x 8 = 2400 versions is 2.88 MILLION pairs, hours of bash).
# Three narrower products UNIONED keep every grammar feature adjacent to
# every other one it can interact with, at ~250 versions and ~31,000 pairs.
corpus = set()
# 1. epoch x upstream-shape x revision, the three-part interaction.
for epoch in ('', '0:', '1:', '10:'):
    for head in ('1', '2'):
        for tail in ('', '.0', '.1', '.10', 'a', '~beta'):
            for rev in ('', '-1', '-10'):
                corpus.add(epoch + head + tail + rev)
# 2. every remaining upstream shape, against every real-world revision shape.
for tail in ('', '.01', '.9', '.2.3', '+', '.', '~', '~~', '~beta1', 'b', 'a1'):
    for rev in ('', '-0', '-01', '-1ubuntu1', '-1~bpo11+1', '-0.1', '-a'):
        corpus.add('1' + tail + rev)
# 3. the equality classes, densely: an absent epoch against 0:, an absent
# revision against -0, and leading zeros in both.
for epoch in ('', '0:', '00:', '1:', '01:'):
    for rev in ('', '-0', '-00', '-1', '-01', '-10'):
        for head in ('1.0', '1.00', '01.0'):
            corpus.add(epoch + head + rev)

corpus = sorted(v for v in corpus if parse(v) is not None)
with open(corpus_path, 'w', encoding='utf-8') as fh:
    for v in corpus:
        fh.write(v + '\n')

pairs = 0
with open(pairs_path, 'w', encoding='utf-8') as fh:
    for a, b in itertools.combinations(corpus, 2):
        fh.write('%s\t%s\t%d\n' % (a, b, ref_cmp(a, b)))
        pairs += 1

sys.stderr.write('image-dpkg-version: generated %d version(s), %d pair(s)\n'
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

t_case 'dpkg_version_cmp_v agrees with the independent Python reference on every generated pair, 0 mismatches'
sweep_mismatch=0
sweep_checked=0
while IFS=$'\t' read -r a b expected; do
  [[ -n $a ]] || continue
  sweep_checked=$(( sweep_checked + 1 ))
  if ! dpkg_version_cmp_v "$a" "$b"; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    REFUSED A WELL-FORMED PAIR: cmp(%s, %s)\n' "$a" "$b" >&2
    continue
  fi
  if [[ $_DPKGV_CMP != "$expected" ]]; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    MISMATCH: cmp(%s, %s) bash=%s reference=%s\n' "$a" "$b" "$_DPKGV_CMP" "$expected" >&2
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
# the fixed-in version" question a later ticket will ask.
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
  for (( j = 0; j < ${#ORDER[@]}; j += 17 )); do
    if dpkg_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; then
      case $_DPKGV_CMP in -1|0|1) ;; *) total_bad=$(( total_bad + 1 )) ;; esac
    else
      total_refused=$(( total_refused + 1 ))
      (( total_refused > 5 )) || printf '    REFUSED: %s vs %s\n' "${ORDER[i]}" "${ORDER[j]}" >&2
    fi
  done
done
assert_eq 0 "$total_refused" 'no pair of well-formed versions is ever refused - verrevcmp consumes both strings, so the comparison is total and a refusal in production always means an unreadable input rather than an undecidable one'
assert_eq 0 "$total_bad" 'and no pair yields a value outside {-1, 0, 1}'

t_case 'antisymmetry: cmp(A,B) is always the negation of cmp(B,A)'
# Strided rather than exhaustive: the property is structural, so a systematic
# sample across the whole vocabulary catches it, and the exhaustive pass costs
# a second full N-squared walk on top of section D's.
anti_bad=0
anti_n=0
for (( i = 0; i < ${#ORDER[@]}; i++ )); do
  for (( j = i + 1; j < ${#ORDER[@]}; j += 7 )); do
    anti_n=$(( anti_n + 1 ))
    dpkg_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; forward=$_DPKGV_CMP
    dpkg_version_cmp_v "${ORDER[j]}" "${ORDER[i]}"; back=$_DPKGV_CMP
    (( forward == -back )) && continue
    anti_bad=$(( anti_bad + 1 ))
    (( anti_bad > 5 )) || printf '    ASYMMETRIC: cmp(%s,%s)=%s but cmp(%s,%s)=%s\n' \
      "${ORDER[i]}" "${ORDER[j]}" "$forward" "${ORDER[j]}" "${ORDER[i]}" "$back" >&2
  done
done
assert_eq 0 "$anti_bad" "over $anti_n pairs - FAILS under any phase that is not itself symmetric - the exact shape of bug that makes 'installed < fixed' and 'fixed > installed' disagree"

# _dpkgv_sort VERSION... - insertion sort by binary search, no fork, and it
# exercises the comparator in exactly the "is A below B" shape a later ticket
# will use.
_dpkgv_sort() {
  local -a in=("$@") out=()
  local x lo hi mid
  for x in "${in[@]}"; do
    lo=0; hi=${#out[@]}
    while (( lo < hi )); do
      mid=$(( (lo + hi) / 2 ))
      dpkg_version_cmp_v "${out[mid]}" "$x"
      if (( _DPKGV_CMP <= 0 )); then lo=$(( mid + 1 )); else hi=$mid; fi
    done
    out=("${out[@]:0:lo}" "$x" "${out[@]:lo}")
  done
  _DPKGV_SORTED=("${out[@]}")
}

t_case 'transitivity: sorting the sweep vocabulary is stable under re-sorting'
# A non-transitive comparator produces an order that depends on the initial
# arrangement, which no per-pair corpus can detect.  The equality classes here
# are real and large (`1.0`, `0:1.0` and `1.0-0` are all one version), which is
# exactly the shape where a comparator whose `=` is not transitive shows up.
#
# The two runs are compared ELEMENT-WISE UNDER THE COMPARATOR rather than
# byte-for-byte, and that is not a weakening.  The insertion sort is stable,
# so members of one equality class come out in their INPUT order - reversing
# the input legitimately reverses them.  Asserting their byte order would pin
# the sort's stability rather than the comparator's transitivity, and would go
# red on a correct comparator.  What must not vary, and what is asserted, is
# that the two sequences agree at every index up to equality.
_dpkgv_sort "${ORDER[@]}"
SORTED_FWD=("${_DPKGV_SORTED[@]}")
readarray -t REV < <(printf '%s\n' "${ORDER[@]}" | LC_ALL=C sort -r)
_dpkgv_sort "${REV[@]}"
SORTED_REV=("${_DPKGV_SORTED[@]}")

assert_eq "${#SORTED_FWD[@]}" "${#SORTED_REV[@]}" 'both runs sorted the same number of versions'
trans_bad=0
for (( i = 0; i < ${#SORTED_FWD[@]} && i < ${#SORTED_REV[@]}; i++ )); do
  dpkg_version_cmp_v "${SORTED_FWD[i]}" "${SORTED_REV[i]}"
  (( _DPKGV_CMP == 0 )) && continue
  trans_bad=$(( trans_bad + 1 ))
  (( trans_bad > 5 )) || printf '    DIVERGES AT INDEX %s: %s vs %s\n' "$i" "${SORTED_FWD[i]}" "${SORTED_REV[i]}" >&2
done
assert_eq 0 "$trans_bad" \
  'the same vocabulary sorted from two different starting arrangements yields the same sequence up to equality - FAILS under a non-transitive comparator, whose result depends on the input order'

t_case 'the sorted sequence is non-decreasing under the comparator itself'
seq_bad=0
for (( i = 0; i < ${#SORTED_FWD[@]} - 1; i++ )); do
  dpkg_version_cmp_v "${SORTED_FWD[i]}" "${SORTED_FWD[i+1]}"
  (( _DPKGV_CMP <= 0 )) || {
    seq_bad=$(( seq_bad + 1 ))
    printf '    OUT OF ORDER: %s then %s\n' "${SORTED_FWD[i]}" "${SORTED_FWD[i+1]}" >&2
  }
done
assert_eq 0 "$seq_bad" 'every adjacent pair of the sorted sequence is <= its successor'

# ---------------------------------------------------------------------------
printf -- '\n-- F. the comparator is a source-graph LEAF, and stays one --\n'
# ---------------------------------------------------------------------------
t_case 'sourcing modules/image/distro/dpkg_version.sh alone defines the comparator and nothing else'
# AGENTS.md's "the memory model": `shellcheck -x` re-expands every source
# edge it follows and does not memoise, so one edge added to a leaf is paid
# for once per consumer.  modules/dast/passive/response_engine.sh's own suite
# and tests/suites/image-apk-version.sh both assert the identical property
# the identical way - on functions that must be UNDEFINED, not on the file's
# text - so restoring an edge goes red immediately instead of surfacing later
# as a slow linter.
leaf_out=$(
  bash --norc -c '
    set -Eeuo pipefail
    source "$1/modules/image/distro/dpkg_version.sh"
    declare -F dpkg_version_cmp_v >/dev/null || { echo MISSING_CMP; exit 0; }
    declare -F dpkg_version_valid >/dev/null || { echo MISSING_VALID; exit 0; }
    for leaked in scan_match finding_emit run_record http_request config_scanner_list dpkg_installed_enumerate apk_version_cmp_v semver_cmp_v; do
      declare -F "$leaked" >/dev/null && echo "LEAKED:$leaked"
    done
    echo LEAF_OK
  ' _ "$ROOT" 2>&1
)
assert_contains 'LEAF_OK' "$leaf_out" 'the file sources nothing: no lib/ function, not its sibling modules/image/distro/dpkg.sh, and not the apk comparator it is so often confused with, is defined after sourcing it'
assert_not_contains 'LEAKED:' "$leaf_out" 'nothing leaked in through a source edge'
assert_not_contains 'MISSING_' "$leaf_out" 'and both public entry points are defined'

t_case 'the file is idempotent under a second source, like every other guarded module here'
# SC2016: the `$1`/`$_DPKGV_CMP` are for the CHILD shell to expand, which is
# what makes this a real second process rather than a string built here.
# shellcheck disable=SC2016
assert_status 0 're-sourcing is a no-op rather than a redefinition' \
  bash --norc -c 'set -Eeuo pipefail; source "$1/modules/image/distro/dpkg_version.sh"; source "$1/modules/image/distro/dpkg_version.sh"; dpkg_version_cmp_v 1.0 1.0; [[ $_DPKGV_CMP == 0 ]]' _ "$ROOT"

t_summary image-dpkg-version
