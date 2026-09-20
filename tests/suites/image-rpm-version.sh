#!/usr/bin/env bash
# tests/suites/image-rpm-version.sh - the rpm (RHEL/Fedora) VERSION
# COMPARATOR, the second ticket of the rpm sub-chain IMG-12's enumerator
# opened - the acknowledged blocker of the three, whose
# difficulty ranking "apk << dpkg < rpm" puts this comparator last and
# hardest (IMG-13 and IMG-14 are the docs and
# correlation tickets, so this one carries no plan number of its own).  It is
# held to the bar `modules/sca/semver.sh` set for itself - differential-tested
# against a reference, 0 mismatches or it does not ship.
#
# The bar is met TWICE OVER, because the two halves fail differently and
# neither subsumes the other:
#
#   A. Against a COMMITTED, provenance-annotated corpus of known orderings
#      (tests/fixtures/image/rpm-version-corpus.tsv) - 133 hand-checked rows,
#      of which 61 are rpm's OWN PUBLISHED TEST VECTORS (librpm's
#      `rpmvercmp.at`) transcribed by hand and 3 are pairs
#      measured to have `modules/sca/semver.sh` get wrong.  This half is what can catch a
#      misreading of the SPEC, because each row's expected ordering was
#      decided from rpm's documented algorithm and from the tool's own
#      maintainers rather than from this implementation.  Its limit is its
#      size.
#
#   D. Against an INDEPENDENT Python reference over a generated ~30,000-pair
#      sweep, the same scale and the same shape as `tests/suites/
#      sca-semver.sh`'s, `tests/suites/image-apk-version.sh`'s and
#      `tests/suites/image-dpkg-version.sh`'s own differentials.  The
#      reference is written in a genuinely different idiom - it TOKENIZES
#      each version whole and builds a total comparison KEY, letting Python's
#      own tuple ordering decide, where the bash implementation walks two
#      cursors in lockstep the way `rpmvercmp` does and never materialises a
#      token list at all.  Getting a key-based reference to agree with rpm
#      requires re-deriving the tilde and caret rules from scratch (both are
#      statements about how a token ranks against the END OF THE TOKEN LIST,
#      which a key must encode as an explicit terminating sentinel ranked
#      BETWEEN them - `~` below the end, `^` above it), which is what makes
#      the agreement evidence rather than a coincidence.  This half is what
#      catches an IMPLEMENTATION slip at a scale no hand-written corpus
#      reaches.  Its limit is that it shares this ticket's reading of the
#      spec, which is exactly what half A is for.
#
# WHAT NEITHER HALF PROVES, stated plainly because a reader will otherwise
# assume it: no row here was harvested by running `rpmdev-vercmp` or `rpm`.
# scoursh is egress-restricted and the development host has neither binary,
# so both references are spec-derived (half A's rpm-vector rows are the
# closest approach: pairs the tool's own test suite asserts, transcribed
# rather than executed).  The live differential on a networked box is named
# as follow-up hardening in the comparator's own header and in the corpus
# file's, in the same shape as the GNU-tar cross-check `tools/daily-suite.sh`
# defers - a stated gap with a named discharge.
#
# Section B restates every specific case named above, plus the
# classic `rpmvercmp` reference vectors, each naming the reading it FAILS
# under, per AGENTS.md's rule that a test agreeing with both the correct and
# the rejected reading pins nothing.  Section C pins the malformed-input
# contract and the three deliberate strictnesses.  Section E pins the
# order-theoretic properties (totality, antisymmetry, transitivity) that a
# per-pair corpus cannot express.  Section F pins the source-graph leaf
# property.
#
# MEASURED, not claimed: eight deliberate mutations of the comparator were
# each applied to a pristine copy and watched taking this suite red, so "seen
# failing before, passing after" is a measurement here rather than a sentence
# in a commit message.  The counts are what those runs actually printed,
# against 202 cases on macOS/bash 5.3:
#
#   giving `~` no special case, so it becomes an ordinary separator        -> 10 failures
#   testing the caret's non-caret case BEFORE its end-of-string case       ->  7
#   resolving a digit-vs-letter alignment by bytes instead of by kind      ->  6
#   dropping the leading-zero strip before the digit-run comparison        ->  5
#   giving `^` no special case, so it becomes an ordinary separator        ->  4
#   comparing the epoch lexically instead of numerically                   ->  4
#   accumulating each digit run and comparing `$(( 10#... ))`              ->  4
#   comparing segments with `[[ < ]]` (collation) instead of by code point ->  2
#
# A later change that takes any of those counts to 0 has removed a test, not
# fixed one.  Which cases the four smallest break was read off those runs
# rather than guessed, because it is not guessable:
#
#   - the epoch-lexical mutation breaks BOTH differentials plus both halves
#     of section B's numeric-epoch case;
#   - the arithmetic-run mutation breaks the committed-corpus differential
#     plus three of section C's five hostile-width cases, and NOT the
#     generated sweep, which carries no run wide enough to wrap - which is
#     exactly why the corpus carries five rows that do;
#   - the no-caret mutation breaks both differentials plus the two section-B
#     caret cases whose answer does not survive treating `^` as a separator
#     (a BARE caret, and a caret segment that is numerically larger than the
#     ordinary segment it must still lose to);
#   - and the collation mutation is INVISIBLE to everything on this macOS
#     host except section B's own FORCED-LOCALE case, whose two UTF-8
#     assertions are exactly its two failures (its LC_ALL=C assertion
#     correctly still passes, which is what shows the case is discriminating
#     on the locale rather than on the pair).  Every other case here,
#     including both differentials and the corpus's own two case-ordering
#     rows (`1.0A < 1.0a`, `1.0Z < 1.0a`), passes under the mutation, because
#     this host's `[[ < ]]` is already byte-ordered; those two rows are what
#     catch it on the GNU/UTF-8 leg of `tools/daily-suite.sh` instead.  A
#     count of 2 on this host is the honest number, not a weak test - the
#     forced locale is what makes the bug reproducible here at all.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh's scratch_init runs at source time and is what sets/exports
# SCOURSH_SCRATCH when no parent run has already handed one down.
# modules/image/distro/rpm_version.sh is a deliberate leaf with no lib/
# sourcing of its own (see section F), so this suite needs core directly -
# the identical arrangement tests/suites/image-{apk,dpkg}-version.sh use.
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=modules/image/distro/rpm_version.sh
source "$ROOT/modules/image/distro/rpm_version.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/image-rpm-version
rm -rf "$W"
mkdir -p "$W"

CORPUS=$ROOT/tests/fixtures/image/rpm-version-corpus.tsv

# cmp_p A B -> prints -1|0|1 (or `?`), for the assert_eq cases.  The fork is
# the test harness's, never production's: every real call site uses the
# variable-setting rpm_version_cmp_v, per this repository's own rule that a
# side-effecting function called as $(f) loses its writes to the subshell.
cmp_p() { rpm_version_cmp "$1" "$2" || true; }

# _rpmv_locale_probe A B - prints the ordering, for the cases that must run
# under a specific locale.  It exists so the locale can be set as a COMMAND
# PREFIX on a command substitution rather than exported into a `( ... )`
# group: nothing then leaks into the rest of the suite, and the answer comes
# back as a value rather than as an exit status a `&&`/`||` chain would have
# to interpret.
_rpmv_locale_probe() {
  rpm_version_cmp_v "$1" "$2" || { printf '?'; return 0; }
  printf '%s' "$_RPMV_CMP"
}

# _rpmv_alphabet_probe VALUE - prints `caught` when the comparator's own
# alphabet gate, spelled out here character for character exactly as the
# comparator spells it, sees an out-of-alphabet byte in VALUE.
_rpmv_alphabet_probe() {
  if [[ $1 == *[!0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._+~^]* ]]; then
    printf 'caught'
  else
    printf 'missed'
  fi
}

# ---------------------------------------------------------------------------
printf -- '\n-- A. differential against the committed corpus --\n'
# ---------------------------------------------------------------------------
t_case 'the committed corpus exists and every non-comment row carries four TAB-separated columns'
assert_file_exists "$CORPUS" 'the differential corpus is committed, not generated at run time - a generated corpus can only ever agree with the generator'
corpus_rows=$(awk -F'\t' '!/^#/ && NF { n++ } END { print n + 0 }' "$CORPUS")
corpus_bad=$(awk -F'\t' '!/^#/ && NF && NF != 4 { n++ } END { print n + 0 }' "$CORPUS")
assert_eq 0 "$corpus_bad" 'every data row has exactly four columns (A, op, B, why) - a three-column row would silently read the next field as the expectation'
if (( corpus_rows >= 120 )); then
  _t_ok "$corpus_rows hand-checked rows"
else
  _t_no 'at least 120 corpus rows' "only $corpus_rows"
fi

t_case 'the corpus still carries rpm'"'"'s own published vectors, in quantity'
# Asserted on the corpus FILE, because the failure this catches is a later
# ticket quietly dropping the rows that came from the tool's own maintainers
# and leaving only the ones this ticket derived - which no comparator
# assertion would notice, since the derived rows are the ones this
# implementation is most likely to agree with for the wrong reason.
vector_rows=$(awk -F'\t' '!/^#/ && NF == 4 && $4 ~ /rpm vector/ { n++ } END { print n + 0 }' "$CORPUS")
if (( vector_rows >= 50 )); then
  _t_ok "$vector_rows rows transcribed from rpm's own rpmvercmp.at vectors"
else
  _t_no "at least 50 rows marked (rpm vector)" "only $vector_rows"
fi

t_case 'the corpus covers every rule the brief and rpmvercmp name'
CORPUS_TEXT=$(cat "$CORPUS")
for needed in \
  '1.0	>	1.0~rc1' \
  '1.0^20230101	>	1.0' \
  '2:1.0-1	>	3.0-1' \
  '1.0010	>	1.9' \
  '1.05	=	1.5' \
  '5.5p2	<	5.6p1' \
  '1a	<	1.0' \
  '10:1.0	>	9:1.0' \
  '1.0^git1	<	1.01' \
  '1.0^git1	>	1.0~rc1' \
  '2.0	=	2_0' \
  '1.0	<	1.0-1'
do
  assert_contains "$CORPUS_TEXT" "$needed" "the corpus still carries the row: ${needed//$'\t'/ }"
done

t_case 'rpm_version_cmp_v agrees with the committed corpus on every row, in BOTH directions, with 0 mismatches'
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
  if ! rpm_version_cmp_v "$a" "$b"; then
    unorderable=$(( unorderable + 1 ))
    printf '    UNORDERABLE: %s %s %s (%s)\n' "$a" "$op" "$b" "$why" >&2
    continue
  fi
  if [[ $_RPMV_CMP != "$expected" ]]; then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$a" "$b" "$_RPMV_CMP" "$expected" "$why" >&2
  fi
  # The MIRROR of the same row.  Without it a comparator that ignored its
  # second argument entirely could still agree with a corpus whose rows all
  # happened to point one way.
  rpm_version_cmp_v "$b" "$a"
  if (( _RPMV_CMP != -expected )); then
    mismatches=$(( mismatches + 1 ))
    (( mismatches > 10 )) || printf '    MIRROR MISMATCH: cmp(%s, %s) got=%s want=%s [%s]\n' "$b" "$a" "$_RPMV_CMP" "$(( -expected ))" "$why" >&2
  fi
done <"$CORPUS"
assert_eq "$corpus_rows" "$checked" 'every committed row was actually exercised, not silently skipped by the reader'
assert_eq 0 "$unorderable" 'no committed row is rejected as malformed - the corpus is all legal rpm versions'
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
  rpm_version_cmp_v "$v" "$v" || { refl_bad=$(( refl_bad + 1 )); continue; }
  (( _RPMV_CMP == 0 )) || { refl_bad=$(( refl_bad + 1 )); printf '    NOT REFLEXIVE: %s\n' "$v" >&2; }
done < <(awk -F'\t' '!/^#/ && NF == 4 { print $1; print $3 }' "$CORPUS" | LC_ALL=C sort -u)
assert_eq 0 "$refl_bad" "all $refl_n distinct corpus versions compare equal to themselves"

# ---------------------------------------------------------------------------
printf -- '\n-- B. the specific cases the brief and rpmvercmp name, each naming the reading it fails under --\n'
# ---------------------------------------------------------------------------
t_case 'the TILDE sorts BEFORE everything, including the end of the string: 1.0 > 1.0~rc1'
assert_eq 1 "$(cmp_p 1.0 1.0~rc1)" \
  'FAILS under modules/sca/semver.sh, which drops the suffix and answers 0 - EQUAL, which a caller asking "is the installed version below the fixed-in version" reads as "not below", reads as "not vulnerable", with no diagnostic at all'
assert_eq -1 "$(cmp_p 1.0~ 1.0)" 'a bare tilde with nothing after it is still below the end of the string - FAILS under any reading that compares what FOLLOWS the tilde rather than the tilde itself'
assert_eq -1 "$(cmp_p 1.0~~ 1.0~)" 'and a second tilde is lower again, which is only true because ~ ranks below ~ ranks below the end'
assert_eq -1 "$(cmp_p 1.0~1 1.0)" 'a tilde demotes a NUMERIC suffix too - FAILS under a reading that only special-cases an alphabetic pre-release tag'
assert_eq 1 "$(cmp_p 2.0~rc1 1.0)" 'and the tilde never reaches across a difference the earlier segments already decided'

t_case 'the CARET sorts AFTER the version it follows: 1.0^20230101 > 1.0'
assert_eq 1 "$(cmp_p 1.0^20230101 1.0)" \
  'FAILS under modules/sca/semver.sh, which answers 0; and FAILS under the belief that ^ is "a tilde pointing the other way in every respect", which would make it lose to the bare version exactly as ~ does'
assert_eq 1 "$(cmp_p 1.0^ 1.0)" 'a bare caret with nothing after it is already above the end of the string'
assert_eq -1 "$(cmp_p '1.0^git1' 1.0.1)" \
  'but a caret segment loses to an ORDINARY following segment - FAILS under a reading that tests the non-caret side BEFORE the ended side, which is the single most likely way to transcribe this rule wrong'
assert_eq -1 "$(cmp_p '1.0^git1' 1.01)" '(rpm vector) and loses to the next version number, whatever the caret segment contains'
assert_eq -1 "$(cmp_p '1.0^2' 1.0.1)" 'even when the caret segment is numerically the larger of the two'

t_case 'a caret outranks a tilde on the same base version, and both are decided before anything after them'
assert_eq 1 "$(cmp_p '1.0^git1' '1.0~rc1')" \
  'a post-release snapshot outranks a pre-release - FAILS under any reading that gives ~ and ^ the same rank and then compares the segments that follow, which would order "git1" against "rc1" alphabetically and answer -1'
assert_eq -1 "$(cmp_p '1.0~rc1^git1' 1.0)" 'a snapshot OF a pre-release is still below the release, because the tilde is reached first'
assert_eq 1 "$(cmp_p '1.0^git1~pre' 1.0)" 'while a pre-release OF a snapshot is still above it, for the mirror-image reason'

t_case 'the EPOCH is compared first, and NUMERICALLY: 2:1.0-1 > 3.0-1'
assert_eq 1 "$(cmp_p 2:1.0-1 3.0-1)" \
  'FAILS under modules/sca/semver.sh, which coerces the non-numeric major "2:1" to 0 and answers -1 - a measured mismatch, and the direction where a PATCHED package is reported vulnerable'
assert_eq 1 "$(cmp_p 10:1.0 9:1.0)" \
  'FAILS under a byte comparison of the epoch, which reads "1" < "9" and inverts a real RHEL estate'"'"'s epoch ordering'
assert_eq 0 "$(cmp_p 01:1.0 1:1.0)" 'a leading zero in the epoch is not significant - it is an integer'
assert_eq 0 "$(cmp_p 0:1.0 1.0)" 'and an ABSENT epoch IS epoch 0, not a missing field'
assert_eq 1 "$(cmp_p 1:1.0 0:99999.99999)" 'no version, at any width, overcomes one epoch'
assert_eq 1 "$(cmp_p '1:1.0~rc1' 0:1.0)" 'an epoch outranks even the tilde rule, which is only reached on an epoch tie'

t_case 'a DIGIT segment outranks a LETTER segment when the two align: 1a < 1.0'
assert_eq -1 "$(cmp_p 1a 1.0)" \
  'FAILS under a byte comparison of the two segments, which reads "a"(97) > "0"(48) and answers 1 - the alignment rule is about the KIND of the run, not its contents'
assert_eq 1 "$(cmp_p 8 xyz.4)" '(rpm vector) whatever the two runs contain, and whatever their lengths'
assert_eq 1 "$(cmp_p 2 xyz.4)" '(rpm vector) including when the numeric run is a single low digit'
assert_eq -1 "$(cmp_p 1.9z 1.10)" 'so the rule can invert what a "longer segment wins" reading would say'
assert_eq 1 "$(cmp_p 6.0.rc1 6.0)" \
  '(rpm vector) but a side with characters LEFT OVER still wins outright - FAILS under a reading that applies the digit-beats-letter rule when the other side has nothing left to align against'

t_case 'the classic rpmvercmp reference vectors on leading zeros and run width'
assert_eq 1 "$(cmp_p 1.0010 1.9)" \
  '(brief) the LONGER stripped run wins: "0010" strips to "10", which beats "9" - FAILS under a byte comparison, which reads "0" < "9"'
assert_eq 0 "$(cmp_p 1.05 1.5)" '(brief) and a stripped run that is a single digit - FAILS under any reading that keeps the zeros'
assert_eq 0 "$(cmp_p 10.0001 10.1)" '(rpm vector) the same at four digits of padding'
assert_eq -1 "$(cmp_p 10.0001 10.0039)" '(rpm vector) once stripped, the runs still compare numerically'
assert_eq -1 "$(cmp_p 5.5p2 5.6p1)" '(brief, rpm vector) an earlier segment decides before a later one is reached'
assert_eq -1 "$(cmp_p 5.5p1 5.5p10)" '(rpm vector) FAILS under a byte comparison, which reads p10 < p2 and so reads p10 < p1 too'
assert_eq -1 "$(cmp_p 4.999.9 5.0)" '(rpm vector) the leading segment decides however long the rest is'
assert_eq 1 "$(cmp_p 10b2 10a1)" '(rpm vector) two letter runs compare by byte, and decide before the digits after them'

t_case 'a segment comparison is by CODE POINT, not by the locale'"'"'s collation'
# rpm's own comparison is strcmp - byte order, where every uppercase letter
# is below every lowercase one.  bash's `[[ $x < $y ]]` uses LC_COLLATE
# instead, which under a UTF-8 locale interleaves the cases.  The locale is
# forced here rather than inherited so the case is decisive on THIS host and
# not only under the GNU leg of tools/daily-suite.sh.
# The locale is set inside a command SUBSTITUTION rather than around the
# whole case, so nothing here can leak a locale into the rest of the suite,
# and the answer comes back as a value an ordinary assert_eq can read.
utf8_cmp=$( LC_ALL=en_US.UTF-8 LC_COLLATE=en_US.UTF-8 LANG=en_US.UTF-8 \
            _rpmv_locale_probe 1.0A 1.0a )
assert_eq -1 "$utf8_cmp" \
  'uppercase sorts below lowercase under a UTF-8 locale, as strcmp does - FAILS under a bash string-comparison of the two segments, which uses LC_COLLATE and interleaves the cases on any glibc host even while passing on this one'
c_cmp=$( LC_ALL=C _rpmv_locale_probe 1.0A 1.0a )
assert_eq -1 "$c_cmp" 'and the same answer under LC_ALL=C - the two are not allowed to differ'
utf8_z=$( LC_ALL=en_US.UTF-8 LC_COLLATE=en_US.UTF-8 LANG=en_US.UTF-8 \
          _rpmv_locale_probe 1.0Z 1.0a )
assert_eq -1 "$utf8_z" 'and every uppercase letter is below every lowercase one, which is the half a collation order does not preserve'

t_case 'a separator is a separator: . _ + and anything else outside ~ ^ carry no weight'
assert_eq 0 "$(cmp_p 2.0 2_0)" '(rpm vector) FAILS under any reading that gives "_" a rank of its own - which is what apk does, where "_" introduces a suffix with an ordering table'
assert_eq 0 "$(cmp_p a+ a_)" '(rpm vector) two different separators are indistinguishable'
assert_eq 0 "$(cmp_p + _)" '(rpm vector) a version made only of separators compares equal to any other such'
assert_eq 0 "$(cmp_p 1.0 1.0.)" 'a trailing separator adds nothing, because it is skipped BEFORE the end-of-string test'
assert_eq 0 "$(cmp_p 1.0 1..0)" 'and a doubled separator collapses to one'

t_case 'the RELEASE is a separate field, compared last and by the same algorithm'
assert_eq -1 "$(cmp_p 1.0-1 1.0-2)" 'the release decides when the version ties'
assert_eq -1 "$(cmp_p 1.0-1 1.0-10)" 'FAILS under a byte comparison of the release, which reads "10" < "2"'
assert_eq -1 "$(cmp_p 1.0 1.0-1)" 'an ABSENT release orders below any present one'
assert_eq 1 "$(cmp_p 2.0-1 1.0-99)" 'and the VERSION decides before the release is ever looked at'
assert_eq -1 "$(cmp_p '1.0-1~bp1' 1.0-1)" 'the tilde rule holds inside the release, which is what makes a rebuild sort below the build'
assert_eq 1 "$(cmp_p '1.0-1^git1' 1.0-1)" 'and so does the caret rule'

t_case 'this comparator and modules/sca/semver.sh genuinely DISAGREE on all three §2.4 cases, so the new file is load-bearing'
# The point of this ticket is that reuse was ruled out by measurement.  Asserting
# the disagreement rather than only the correct answer is what would fail if
# a later ticket "simplified" this file into a semver.sh wrapper - which
# would still pass every other case in this section that semver happens to
# get right.
# shellcheck source=modules/sca/semver.sh
source "$ROOT/modules/sca/semver.sh"
semver_cmp_v 1.0 1.0~rc1
assert_eq 0 "$_SV_CMP" 'semver_cmp_v still answers 0 - EQUAL - on the tilde pair, exactly as measured earlier, and that is the silent direction'
semver_cmp_v 1.0^20230101 1.0
assert_eq 0 "$_SV_CMP" 'and still answers 0 on the caret pair'
semver_cmp_v 2:1.0-1 3.0-1
assert_eq -1 "$_SV_CMP" 'and still answers -1 on the epoch pair'
rpm_version_cmp_v 1.0 1.0~rc1;        assert_eq 1 "$_RPMV_CMP" 'where rpm_version_cmp_v answers 1'
rpm_version_cmp_v 1.0^20230101 1.0;   assert_eq 1 "$_RPMV_CMP" 'and 1'
rpm_version_cmp_v 2:1.0-1 3.0-1;      assert_eq 1 "$_RPMV_CMP" 'and 1 - the two comparators are not interchangeable and must not be merged'

t_case 'this comparator and both sibling OS comparators also disagree, so none of the three is an "OS version comparator"'
# The inverse temptation to reuse: one os_version_cmp for every distro.  The
# caret is the case that makes it impossible for rpm specifically - it is
# not in either sibling grammar at all - and `2_0` is the case that makes it
# impossible in the other direction, since all three accept it and two of
# them mean something different by it.
# shellcheck source=modules/image/distro/apk_version.sh
source "$ROOT/modules/image/distro/apk_version.sh"
# shellcheck source=modules/image/distro/dpkg_version.sh
source "$ROOT/modules/image/distro/dpkg_version.sh"
assert_status 1 'dpkg rejects a caret outright - it is not in deb-version(7)'"'"'s alphabet' dpkg_version_valid '1.0^git1'
assert_status 1 'and apk rejects it too' apk_version_valid '1.0^git1'
assert_status 0 'while rpm accepts it as one of its two ordering rules' rpm_version_valid '1.0^git1'
assert_status 1 'dpkg rejects an underscore, which rpm treats as an ordinary separator' dpkg_version_valid '2_0'
assert_status 1 'and apk rejects "2_0" too, because "_0" is not one of its suffix keywords' apk_version_valid '2_0'
assert_status 0 'while rpm accepts it - "_" is just another separator there' rpm_version_valid '2_0'
rpm_version_cmp_v 2_0 2.0
assert_eq 0 "$_RPMV_CMP" 'rpm: "_" and "." are the same separator, so these are one version'
# `1.0_alpha1` is the sharpest case of the three, because BOTH comparators
# accept it and they answer OPPOSITE things about the same bytes: apk reads
# `_alpha1` as a pre-release suffix from its own ordering table, while rpm
# has no such table and reads the `_` as a plain separator, leaving an
# ordinary trailing segment that wins by being there at all.  A merged
# comparator cannot be right for both.
apk_version_cmp_v 1.0_alpha1 1.0
assert_eq -1 "$_APKV_CMP" 'apk: "_alpha1" is a PRE-release suffix, so the version sorts BELOW 1.0'
rpm_version_cmp_v 1.0_alpha1 1.0
assert_eq 1 "$_RPMV_CMP" 'rpm: the "_" is a separator, so "alpha1" is a trailing segment and the version sorts ABOVE 1.0 - the same bytes, the opposite answer'

# ---------------------------------------------------------------------------
printf -- '\n-- C. malformed input is UNORDERABLE, deterministically, and never a crash --\n'
# ---------------------------------------------------------------------------
t_case 'rpm_version_valid accepts every shape rpm allows'
# Note what is NOT here that would be in the dpkg suite: rpm has no
# "must start with a digit" rule, so `xyz10` and even a bare `a` are legal
# versions and appear in rpm's own test vectors.
for good in 0 1 1.0 1.0-1 1:1.0 1:1.0-1 '1.0~rc1' '1.0^git1' '1.0~rc1^git1' \
            '1.0^git1~pre' xyz10 a '2_0' 'a+' '+' '_' '1.0.' '01:1.0' \
            'latest' '1.0-a' '1:4.18.0-513.5.1.el8_9' '1.0+git~1^2'
do
  assert_status 0 "accepts $good" rpm_version_valid "$good"
done

t_case 'rpm_version_valid rejects everything outside it, including the shapes a corrupt or hostile rpm DB would carry'
# The empty string is FIRST on purpose: modules/image/distro/rpm.sh reads its
# columns out of a sqlite database whose rows it does not author, so an empty
# field is an ordinary expected arrival rather than a hypothetical.
for bad in '' ':1.0' '1.0-' '1:' 'a:1.0' '-1:1.0' '1.0:' '1.0-1-2' \
           '1.0 ' ' 1.0' '1.0 1' '1.0/1' '1.0,1' '1.0!' '1.0-1/2' '1.0-1 2' \
           $'1.0\n2.0' $'1.0\t2' $'\t1.0' $'1.0\r' $'1.1.\xc3\xa9' $'\xff'
do
  assert_status 1 "rejects '${bad//[$'\n\t\r']/<ws>}'" rpm_version_valid "$bad"
done

t_case 'the whitespace and non-ASCII operands above are refused by the ALPHABET GLOB alone, with no per-character scan behind it'
# The comparator carries exactly one character check - a `*[!SET]*` bracket
# negation whose set is spelled out CHARACTER BY CHARACTER rather than as a
# range, because a bracket RANGE is resolved by the locale's collation and
# `[a-z]` can admit an uppercase or a non-ASCII letter under a UTF-8 locale.
# bash's `*` matches a newline, a tab and a carriage return like any other
# byte, so no second scan is needed behind it.  This case is what stops the
# set being rewritten as a range on the belief that the two are equivalent,
# and equally what stops a redundant per-character loop being re-added.
for ws in $'1.0\n2.0' $'1.0\t2' $'\t1.0' $'1.0\r' '1.0 ' ' 1.0' $'1.1.\xc3\xa9'; do
  assert_eq caught "$(_rpmv_alphabet_probe "$ws")" \
    "the bracket negation alone sees the out-of-alphabet byte in '${ws//[$'\n\t\r']/<ws>}'"
done
utf8_caught=$( LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 _rpmv_alphabet_probe $'1.1.\xc3\xa9' )
assert_eq caught "$utf8_caught" \
  'and the gate still sees the non-ASCII byte under a UTF-8 locale - FAILS if the set is ever rewritten as a [0-9a-zA-Z] RANGE, whose membership is collation-defined'

t_case 'a NON-ASCII byte is REFUSED where rpm itself answers 0 - strictness 1, in the refusal direction'
# rpm's `risalnum` is ASCII-only, so a UTF-8 character is skipped as a
# separator and rpm's own vector file asserts `1.1.<alpha>` EQUAL to
# `1.1.<beta>` under a comment calling that an "arguably buggy behavior ...
# included here to document current behavior".  Reproducing it would make two
# genuinely different versions indistinguishable, which is the silent
# direction; refusing is what a caller can see and report.
alpha=$'1.1.\xce\xb1'
beta=$'1.1.\xce\xb2'
assert_status 1 'the alpha-suffixed version is refused rather than ordered' rpm_version_valid "$alpha"
assert_status 1 'and so is the beta-suffixed one' rpm_version_valid "$beta"
rc=0; rpm_version_cmp_v "$alpha" "$beta" || rc=$?
assert_eq 1 "$rc" 'so the pair rpm calls EQUAL is refused here instead - a divergence that can only turn an answer into a coverage_reduction, never a finding into silence'
assert_eq 0 "$_RPMV_CMP" 'and no ordering is left behind for a caller to misread'

t_case 'a colon that is not a well-formed epoch separator is refused - strictness 3, where rpm folds it into the version'
assert_status 1 'rpm reads "a:1.0" as a version literally containing a colon; this file refuses it' rpm_version_valid 'a:1.0'
assert_status 1 'rpm reads ":1.0" as epoch 0; this file refuses an empty epoch' rpm_version_valid ':1.0'
assert_status 1 'and a negative epoch is refused, because "-" is not a digit' rpm_version_valid '-1:1.0'
assert_status 0 'while a well-formed epoch is of course accepted' rpm_version_valid '12:1.0'

t_case 'an unorderable version returns rc 1 and NEVER an ordering - the failure a caller must not read as "equal"'
# All three silent alternatives - "equal", "less", "greater" - render an
# unreadable version identically to a version that was read and found safe.
# The caller owes a coverage_reduction on rc 1; this pins that there is
# something for it to branch on.
# Called directly rather than through assert_status, which runs its command
# in a SUBSHELL - the reason a caller must branch on would be discarded with
# it, and the assertion would then pass against a comparator that set no
# reason at all.
rc=0; rpm_version_cmp_v '1.0 1' '1.0' || rc=$?
assert_eq 1 "$rc" 'a malformed left operand is refused'
assert_eq 'invalid_version_a' "$_RPMV_REASON" 'and the side that was unreadable is named'
assert_eq 0 "$_RPMV_CMP" 'and no ordering is left behind for a caller to misread as "equal"'
rc=0; rpm_version_cmp_v '1.0' '1.0 1' || rc=$?
assert_eq 1 "$rc" 'a malformed right operand is refused'
assert_eq 'invalid_version_b' "$_RPMV_REASON" 'and named on that side too'
rc=0; rpm_version_cmp_v '' '' || rc=$?
assert_eq 1 "$rc" 'two empty operands are refused rather than compared with each other as equal'
assert_eq '?' "$(cmp_p '1.0 1' '1.0')" 'the printing form emits "?" rather than a number, so a harness cannot mistake a refusal for an ordering'

t_case 'a successful comparison clears _RPMV_REASON, so a stale reason cannot be read as a fresh refusal'
rpm_version_cmp_v '1.0 1' '1.0' || true
rpm_version_cmp_v '1.0' '1.0'
assert_eq '' "$_RPMV_REASON" 'the reason from the previous refusal does not survive into the next successful call'

t_case 'a hostile digit run does not wrap, and does not fork'
# $(( 10#$run )) silently wraps at 64 bits, so a corrupt or hostile package
# database could make a very low version compare very high.  The comparator
# never evaluates a run at all: rpm's own walk decides by "strip the zeros,
# then the longer run is larger", which is exact at any width.  The first
# pair below differs by exactly 2^64 (18446744073709551616), so
# `$(( 10#... ))` maps both onto the SAME value.
assert_eq -1 "$(cmp_p '1.1' '1.18446744073709551617')" \
  'FAILS under 64-bit arithmetic evaluation, which wraps the right operand back onto 1 and calls the two EQUAL'
assert_eq 1 "$(cmp_p '1.18446744073709551617' '1.2')" \
  'and FAILS backwards under the same reading, which wraps the left operand onto 1 and reports it BELOW 1.2 - a wrapped digit run does not merely lose precision, it inverts the ordering'
assert_eq -1 "$(cmp_p '1.0-1' '1.0-18446744073709551617')" 'the same at the release'
assert_eq 1 "$(cmp_p '18446744073709551617:1.0' '18446744073709551616:1.0')" \
  'and at the EPOCH, which rpm itself stores in a 32-bit tag and cannot represent above UINT32_MAX - a divergence that can only turn a refusal into a right answer'
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
for hostile in '1.0$(touch '"$W"'/pwned)' '1.0`id`' '1.0;id' '1.0&&id' '$((1+1)).0' '1.0*' '1.0[a]' '1.0?'; do
  assert_status 1 "refuses '$hostile'" rpm_version_valid "$hostile"
done
assert_file_absent "$W/pwned" 'and nothing was executed while deciding that'

t_case 'a glob metacharacter in a version is not matched as a PATTERN by the alphabet check'
# The alphabet gate is a bracket-negation glob, so the operand it tests is on
# the LEFT of `!=` and is never itself a pattern; a first draft that had it
# the other way round would accept `1.0*` by letting the star match.  Pinned
# on the accept side too, because a gate that rejected everything would also
# pass the refusal cases above.
assert_status 1 'a bare star is not a legal version' rpm_version_valid '1.0*'
assert_status 1 'nor a question mark' rpm_version_valid '1.0?'
assert_status 0 'while an ordinary version is still accepted' rpm_version_valid '1.0'

# ---------------------------------------------------------------------------
printf -- '\n-- C2. the FIELD form, for the three columns modules/image/distro/rpm.sh returns --\n'
# ---------------------------------------------------------------------------
t_case 'rpm_evr_cmp_v agrees with the string form wherever both accept the input'
# The two entry points must never disagree on an input both accept, because
# a later ticket will reach for whichever is closer to hand and a divergence
# would make the finding depend on that choice.  Asserted over the whole
# committed corpus rather than a sample.
evr_bad=0
evr_n=0
while IFS=$'\t' read -r a op b why; do
  [[ -n $a && ${a:0:1} != '#' ]] || continue
  rpm_version_cmp_v "$a" "$b" || continue
  want=$_RPMV_CMP
  _rpmv_parse "$a"; ea=$_RPMV_EPOCH; va=$_RPMV_VERSION; ra=$_RPMV_RELEASE
  _rpmv_parse "$b"; eb=$_RPMV_EPOCH; vb=$_RPMV_VERSION; rb=$_RPMV_RELEASE
  evr_n=$(( evr_n + 1 ))
  if ! rpm_evr_cmp_v "$ea" "$va" "$ra" "$eb" "$vb" "$rb"; then
    evr_bad=$(( evr_bad + 1 ))
    printf '    FIELD FORM REFUSED: (%s,%s,%s) vs (%s,%s,%s)\n' "$ea" "$va" "$ra" "$eb" "$vb" "$rb" >&2
    continue
  fi
  [[ $_RPMV_CMP == "$want" ]] || {
    evr_bad=$(( evr_bad + 1 ))
    (( evr_bad > 10 )) || printf '    FIELD/STRING DISAGREE: %s vs %s field=%s string=%s\n' "$a" "$b" "$_RPMV_CMP" "$want" >&2
  }
done <"$CORPUS"
assert_eq 0 "$evr_bad" "the two entry points agree on all $evr_n committed rows"

t_case 'an ABSENT epoch or release field is accepted where the equivalent malformed STRING is refused'
# modules/image/distro/rpm.sh's RPM_INSTALLED_EPOCHS is "commonly the empty
# string" - most rpm packages carry no epoch at all - so an empty FIELD is
# an ordinary arrival, while the string `:1.0` that would encode it is a
# dangling separator and is malformed.  Collapsing the two in either
# direction loses one of the facts.
# Called directly rather than through assert_status, which runs its command
# in a SUBSHELL - the ordering it sets would be discarded with it, and the
# following assert_eq would then be reading a value left over from an earlier
# call rather than this one's.  That is not hypothetical: the first draft of
# this case did exactly that and reported three failures whose cause was the
# harness, not the comparator.
rc=0; rpm_evr_cmp_v '' '1.0' '1' 0 '1.0' '1' || rc=$?
assert_eq 0 "$rc" 'an empty epoch field is accepted'
assert_eq 0 "$_RPMV_CMP" 'and is epoch 0, ordering identically to an explicit 0'
assert_status 1 'while the string ":1.0-1" that would encode it is refused' rpm_version_valid ':1.0-1'
rc=0; rpm_evr_cmp_v 0 '1.0' '' 0 '1.0' '1' || rc=$?
assert_eq 0 "$rc" 'an empty release field is accepted'
assert_eq -1 "$_RPMV_CMP" 'and orders below a present one - the same answer the string form gives for "1.0" against "1.0-1"'
assert_status 1 'while the string "1.0-" that would encode it is refused' rpm_version_valid '1.0-'
rc=0; rpm_evr_cmp_v 0 '1.0' '' 0 '1.0' '' || rc=$?
assert_eq 0 "$rc" 'two absent release fields are accepted'
assert_eq 0 "$_RPMV_CMP" 'and are EQUAL, not merely both-unorderable'

t_case 'the field form refuses a malformed field, on the right side as well as the left'
rc=0; rpm_evr_cmp_v 'x' '1.0' '1' 0 '1.0' '1' || rc=$?
assert_eq 1 "$rc" 'a non-numeric epoch is refused'
assert_eq 'invalid_version_a' "$_RPMV_REASON" 'and named'
rc=0; rpm_evr_cmp_v 0 '1.0' '1' 0 '' '1' || rc=$?
assert_eq 1 "$rc" 'an empty VERSION field is refused - unlike an empty epoch or release, it is not an absent field'
assert_eq 'invalid_version_b' "$_RPMV_REASON" 'and named on the right side'
rc=0; rpm_evr_cmp_v 0 '1.0' '1 2' 0 '1.0' '1' || rc=$?
assert_eq 1 "$rc" 'an out-of-alphabet release field is refused'
assert_eq 'invalid_version_a' "$_RPMV_REASON" 'and named'

t_case 'a caller that passes too few fields is answered, never aborted by an unbound variable'
# This file is sourced into runs with `set -Eeuo pipefail`, so reading a
# missing sixth argument positionally would take the WHOLE SCAN down on what
# is only a caller bug.  Every operand is read with a `-` default instead, so
# the arity error surfaces as this function's ordinary refusal.  Asserted in
# a real subprocess under `set -u`, because a lenient read in this shell
# would not reproduce it.
#
# The two arities below answer DIFFERENTLY, and that asymmetry is real rather
# than a gap: an absent RELEASE field is legal (it orders below every present
# one), so a five-argument call is indistinguishable from a six-argument call
# whose last field is empty and is correctly ORDERED; an absent VERSION field
# is not legal, so a four-argument call is REFUSED and names its side.
# SC2016: the child expands these, which is what makes it a real second
# process rather than a string built here.
# shellcheck disable=SC2016
arity5=$(
  bash --norc -c '
    set -Eeuo pipefail
    source "$1/modules/image/distro/rpm_version.sh"
    rc=0; rpm_evr_cmp_v 0 "1.0" "1" 0 "1.0" || rc=$?
    printf "rc=%s cmp=%s" "$rc" "$_RPMV_CMP"
  ' _ "$ROOT" 2>&1
)
assert_eq 'rc=0 cmp=1' "$arity5" \
  'a five-argument call reads its missing release as an ABSENT field and orders "1.0-1" above "1.0" - FAILS under a positional read of the sixth argument, which aborts the process under set -u and prints an unbound-variable error here instead of a comparison'
arity4=$(
  bash --norc -c '
    set -Eeuo pipefail
    source "$1/modules/image/distro/rpm_version.sh"
    rc=0; rpm_evr_cmp_v 0 "1.0" "1" 0 || rc=$?
    printf "rc=%s reason=%s" "$rc" "${_RPMV_REASON:-none}"
  ' _ "$ROOT" 2>&1
)
assert_eq 'rc=1 reason=invalid_version_b' "$arity4" \
  'while a four-argument call, whose missing field is the VERSION rather than the release, is REFUSED and names its side - the arity error becomes this function'"'"'s ordinary refusal rather than a crash'

# ---------------------------------------------------------------------------
printf -- '\n-- D. differential against an independent Python reference, ~30,000 generated pairs --\n'
# ---------------------------------------------------------------------------
require_cmd python3

python3 - "$W/corpus.txt" "$W/pairs.txt" <<'PY'
import itertools
import re
import sys

corpus_path, pairs_path = sys.argv[1], sys.argv[2]

# --- An INDEPENDENT reference implementation of rpm's `rpmvercmp` ordering.
# It TOKENIZES each version whole and builds a total comparison KEY, letting
# Python's own tuple ordering decide, where modules/image/distro/
# rpm_version.sh walks two cursors in lockstep the way rpmvercmp does and
# never materialises a token list.  The two are different algorithms for the
# same relation, so a slip in one is unlikely to be mirrored in the other.
# It shares this ticket's reading of the SPEC, which is what the committed
# corpus in section A exists to check separately. ---

FIELD_OK = re.compile(r'\A[0-9A-Za-z._+~^]+\Z')
EPOCH_OK = re.compile(r'\A[0-9]+\Z')

# The rank of a token, and - the whole trick - of the END OF THE TOKEN LIST.
# rpm's tilde and caret rules are both statements about how a token ranks
# against the end of a part, and they point OPPOSITE ways: `~` sorts below
# the end, `^` sorts above it.  A key-based reference has to encode that as
# an explicit terminating sentinel ranked BETWEEN the two, which is a
# genuinely different derivation from the cursor walk's "check tilde before
# the end-of-string test, and check the ended side first for caret".
TILDE, END, CARET, SEGMENT = 0, 1, 2, 3
ALPHA, NUMERIC = 0, 1   # a NUMERIC segment outranks an ALPHA one


def parse(evr):
    """Return (epoch, version, release), or None when unorderable."""
    if not evr:
        return None
    if ':' in evr:
        epoch, _, rest = evr.partition(':')
        if not EPOCH_OK.match(epoch) or not rest:
            return None
    else:
        epoch, rest = '0', evr
    if '-' in rest:
        version, _, release = rest.rpartition('-')
        if not release or not FIELD_OK.match(release):
            return None
    else:
        version, release = rest, ''
    if not FIELD_OK.match(version):
        return None
    return epoch, version, release


def part_key(part):
    """Tokenize one part into a comparable list, terminated by END.

    Separators - every character that is not ASCII-alphanumeric and not `~`
    or `^` - are dropped outright, because rpm skips them without ever
    comparing them.  That is why `2_0` keys identically to `2.0`.
    """
    key = []
    i = 0
    n = len(part)
    while i < n:
        ch = part[i]
        if ch == '~':
            key.append((TILDE,))
            i += 1
        elif ch == '^':
            key.append((CARET,))
            i += 1
        elif ch.isdigit():
            start = i
            while i < n and part[i].isdigit():
                i += 1
            key.append((SEGMENT, NUMERIC, int(part[start:i])))
        elif ch.isalpha():
            start = i
            while i < n and part[i].isalpha():
                i += 1
            key.append((SEGMENT, ALPHA, part[start:i]))
        else:
            i += 1
    key.append((END,))
    return key


def ref_cmp(a, b):
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    ka = (int(pa[0]), part_key(pa[1]), part_key(pa[2]))
    kb = (int(pb[0]), part_key(pb[1]), part_key(pb[2]))
    return (ka > kb) - (ka < kb)


# --- The generated sweep: a systematic cross-product over every feature of
# the grammar, at roughly the 30,000-pair scale modules/sca/semver.sh's own
# differential reached on real npm data. ---
# Sized deliberately: the pair count is QUADRATIC in the vocabulary, so one
# wide cross-product overshoots the target scale by two orders of magnitude.
# Three narrower products UNIONED keep every grammar feature adjacent to
# every other one it can interact with, at ~250 versions and ~31,000 pairs.
corpus = set()
# 1. epoch x version-shape x release, the three-part interaction.
for epoch in ('', '0:', '1:', '10:'):
    for head in ('1', '2'):
        for tail in ('', '.0', '.1', '.10', 'a', '~rc1', '^git1'):
            for rel in ('', '-1', '-10'):
                corpus.add(epoch + head + tail + rel)
# 2. every remaining version shape, against every real-world release shape.
for tail in ('', '.01', '.9', '.2.3', '+', '.', '_', '~', '~~', '^', '^^',
             '~rc1^git1', '^git1~pre', 'b', 'a1', '0a'):
    for rel in ('', '-0', '-01', '-1.el8', '-1~bp1', '-1^g1', '-a'):
        corpus.add('1' + tail + rel)
# 3. the equality classes, densely: an absent epoch against 0:, leading
# zeros in the epoch, the version and the release, and separator aliasing.
for epoch in ('', '0:', '00:', '1:', '01:'):
    for rel in ('', '-0', '-00', '-1', '-01', '-10'):
        for head in ('1.0', '1.00', '01.0', '1_0'):
            corpus.add(epoch + head + rel)

corpus = sorted(v for v in corpus if parse(v) is not None)
with open(corpus_path, 'w', encoding='utf-8') as fh:
    for v in corpus:
        fh.write(v + '\n')

pairs = 0
with open(pairs_path, 'w', encoding='utf-8') as fh:
    for a, b in itertools.combinations(corpus, 2):
        fh.write('%s\t%s\t%d\n' % (a, b, ref_cmp(a, b)))
        pairs += 1

sys.stderr.write('image-rpm-version: generated %d version(s), %d pair(s)\n'
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

t_case 'the generated sweep really does exercise the tilde, the caret and both together'
# A sweep that quietly stopped emitting the two rules this comparator exists
# for would still report 0 mismatches, and the count assertion above would
# still pass.  Asserted on the generated vocabulary, not on the generator.
SWEEP_TEXT=$(cat "$W/corpus.txt")
assert_contains "$SWEEP_TEXT" '~rc1' 'the sweep carries tilde versions'
assert_contains "$SWEEP_TEXT" '^git1' 'and caret versions'
assert_contains "$SWEEP_TEXT" '~rc1^git1' 'and a caret inside a tilde suffix'
assert_contains "$SWEEP_TEXT" '^git1~pre' 'and a tilde inside a caret suffix'
assert_contains "$SWEEP_TEXT" '-1~bp1' 'and a tilde inside the release'
assert_contains "$SWEEP_TEXT" '-1^g1' 'and a caret inside the release'

t_case 'rpm_version_cmp_v agrees with the independent Python reference on every generated pair, 0 mismatches'
sweep_mismatch=0
sweep_checked=0
while IFS=$'\t' read -r a b expected; do
  [[ -n $a ]] || continue
  sweep_checked=$(( sweep_checked + 1 ))
  if ! rpm_version_cmp_v "$a" "$b"; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    REFUSED A WELL-FORMED PAIR: cmp(%s, %s)\n' "$a" "$b" >&2
    continue
  fi
  if [[ $_RPMV_CMP != "$expected" ]]; then
    sweep_mismatch=$(( sweep_mismatch + 1 ))
    (( sweep_mismatch > 10 )) || printf '    MISMATCH: cmp(%s, %s) bash=%s reference=%s\n' "$a" "$b" "$_RPMV_CMP" "$expected" >&2
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
    if rpm_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; then
      case $_RPMV_CMP in -1|0|1) ;; *) total_bad=$(( total_bad + 1 )) ;; esac
    else
      total_refused=$(( total_refused + 1 ))
      (( total_refused > 5 )) || printf '    REFUSED: %s vs %s\n' "${ORDER[i]}" "${ORDER[j]}" >&2
    fi
  done
done
assert_eq 0 "$total_refused" 'no pair of well-formed versions is ever refused - the walk consumes both strings, so the comparison is total and a refusal in production always means an unreadable input rather than an undecidable one'
assert_eq 0 "$total_bad" 'and no pair yields a value outside {-1, 0, 1}'

t_case 'antisymmetry: cmp(A,B) is always the negation of cmp(B,A)'
# Strided rather than exhaustive: the property is structural, so a systematic
# sample across the whole vocabulary catches it, and the exhaustive pass costs
# a second full N-squared walk on top of section D's.  It is the property most
# at risk here, because the caret rule's four tests are the one place in the
# algorithm that is written asymmetrically.
anti_bad=0
anti_n=0
for (( i = 0; i < ${#ORDER[@]}; i++ )); do
  for (( j = i + 1; j < ${#ORDER[@]}; j += 7 )); do
    anti_n=$(( anti_n + 1 ))
    rpm_version_cmp_v "${ORDER[i]}" "${ORDER[j]}"; forward=$_RPMV_CMP
    rpm_version_cmp_v "${ORDER[j]}" "${ORDER[i]}"; back=$_RPMV_CMP
    (( forward == -back )) && continue
    anti_bad=$(( anti_bad + 1 ))
    (( anti_bad > 5 )) || printf '    ASYMMETRIC: cmp(%s,%s)=%s but cmp(%s,%s)=%s\n' \
      "${ORDER[i]}" "${ORDER[j]}" "$forward" "${ORDER[j]}" "${ORDER[i]}" "$back" >&2
  done
done
assert_eq 0 "$anti_bad" "over $anti_n pairs - FAILS under any phase that is not itself symmetric, and the caret rule's four ordered tests are exactly that shape - the bug that makes 'installed < fixed' and 'fixed > installed' disagree"

# _rpmv_sort VERSION... - insertion sort by binary search, no fork, and it
# exercises the comparator in exactly the "is A below B" shape a later ticket
# will use.
_rpmv_sort() {
  local -a in=("$@") out=()
  local x lo hi mid
  for x in "${in[@]}"; do
    lo=0; hi=${#out[@]}
    while (( lo < hi )); do
      mid=$(( (lo + hi) / 2 ))
      rpm_version_cmp_v "${out[mid]}" "$x"
      if (( _RPMV_CMP <= 0 )); then lo=$(( mid + 1 )); else hi=$mid; fi
    done
    out=("${out[@]:0:lo}" "$x" "${out[@]:lo}")
  done
  _RPMV_SORTED=("${out[@]}")
}

t_case 'transitivity: sorting the sweep vocabulary is stable under re-sorting'
# A non-transitive comparator produces an order that depends on the initial
# arrangement, which no per-pair corpus can detect.  The equality classes here
# are real and large (`1.0`, `0:1.0`, `1_0` and `01.0` are all one version),
# which is exactly the shape where a comparator whose `=` is not transitive
# shows up.
#
# The two runs are compared ELEMENT-WISE UNDER THE COMPARATOR rather than
# byte-for-byte, and that is not a weakening.  The insertion sort is stable,
# so members of one equality class come out in their INPUT order - reversing
# the input legitimately reverses them.  Asserting their byte order would pin
# the sort's stability rather than the comparator's transitivity, and would go
# red on a correct comparator.  What must not vary, and what is asserted, is
# that the two sequences agree at every index up to equality.
_rpmv_sort "${ORDER[@]}"
SORTED_FWD=("${_RPMV_SORTED[@]}")
readarray -t REV < <(printf '%s\n' "${ORDER[@]}" | LC_ALL=C sort -r)
_rpmv_sort "${REV[@]}"
SORTED_REV=("${_RPMV_SORTED[@]}")

assert_eq "${#SORTED_FWD[@]}" "${#SORTED_REV[@]}" 'both runs sorted the same number of versions'
trans_bad=0
for (( i = 0; i < ${#SORTED_FWD[@]} && i < ${#SORTED_REV[@]}; i++ )); do
  rpm_version_cmp_v "${SORTED_FWD[i]}" "${SORTED_REV[i]}"
  (( _RPMV_CMP == 0 )) && continue
  trans_bad=$(( trans_bad + 1 ))
  (( trans_bad > 5 )) || printf '    DIVERGES AT INDEX %s: %s vs %s\n' "$i" "${SORTED_FWD[i]}" "${SORTED_REV[i]}" >&2
done
assert_eq 0 "$trans_bad" \
  'the same vocabulary sorted from two different starting arrangements yields the same sequence up to equality - FAILS under a non-transitive comparator, whose result depends on the input order'

t_case 'the sorted sequence is non-decreasing under the comparator itself'
seq_bad=0
for (( i = 0; i < ${#SORTED_FWD[@]} - 1; i++ )); do
  rpm_version_cmp_v "${SORTED_FWD[i]}" "${SORTED_FWD[i+1]}"
  (( _RPMV_CMP <= 0 )) || {
    seq_bad=$(( seq_bad + 1 ))
    printf '    OUT OF ORDER: %s then %s\n' "${SORTED_FWD[i]}" "${SORTED_FWD[i+1]}" >&2
  }
done
assert_eq 0 "$seq_bad" 'every adjacent pair of the sorted sequence is <= its successor'

# ---------------------------------------------------------------------------
printf -- '\n-- F. the comparator is a source-graph LEAF, and stays one --\n'
# ---------------------------------------------------------------------------
t_case 'sourcing modules/image/distro/rpm_version.sh alone defines the comparator and nothing else'
# AGENTS.md's "the memory model": `shellcheck -x` re-expands every source
# edge it follows and does not memoise, so one edge added to a leaf is paid
# for once per consumer.  modules/dast/passive/response_engine.sh's own suite
# and tests/suites/image-{apk,dpkg}-version.sh all assert the identical
# property the identical way - on functions that must be UNDEFINED, not on
# the file's text - so restoring an edge goes red immediately instead of
# surfacing later as a slow linter.
leaf_out=$(
  bash --norc -c '
    set -Eeuo pipefail
    source "$1/modules/image/distro/rpm_version.sh"
    declare -F rpm_version_cmp_v >/dev/null || { echo MISSING_CMP; exit 0; }
    declare -F rpm_evr_cmp_v >/dev/null || { echo MISSING_EVR; exit 0; }
    declare -F rpm_version_valid >/dev/null || { echo MISSING_VALID; exit 0; }
    for leaked in scan_match finding_emit run_record http_request config_scanner_list rpm_installed_enumerate apk_version_cmp_v dpkg_version_cmp_v semver_cmp_v; do
      declare -F "$leaked" >/dev/null && echo "LEAKED:$leaked"
    done
    echo LEAF_OK
  ' _ "$ROOT" 2>&1
)
assert_contains 'LEAF_OK' "$leaf_out" 'the file sources nothing: no lib/ function, not its sibling modules/image/distro/rpm.sh, and neither of the two comparators it is most likely to be confused with, is defined after sourcing it'
assert_not_contains 'LEAKED:' "$leaf_out" 'nothing leaked in through a source edge'
assert_not_contains 'MISSING_' "$leaf_out" 'and all three public entry points are defined'

t_case 'the file is idempotent under a second source, like every other guarded module here'
# SC2016: the `$1`/`$_RPMV_CMP` are for the CHILD shell to expand, which is
# what makes this a real second process rather than a string built here.
# shellcheck disable=SC2016
assert_status 0 're-sourcing is a no-op rather than a redefinition' \
  bash --norc -c 'set -Eeuo pipefail; source "$1/modules/image/distro/rpm_version.sh"; source "$1/modules/image/distro/rpm_version.sh"; rpm_version_cmp_v 1.0 1.0; [[ $_RPMV_CMP == 0 ]]' _ "$ROOT"

t_summary image-rpm-version
