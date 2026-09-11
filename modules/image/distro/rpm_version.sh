#!/usr/bin/env bash
# modules/image/distro/rpm_version.sh - the rpm (RHEL/Fedora/openSUSE)
# VERSION COMPARATOR, the second ticket of the rpm sub-chain IMG-12's
# enumerator opened - measured to be the hardest of apk/dpkg/rpm's three
# version-comparator problems (IMG-13 and IMG-14 are the docs and
# correlation tickets, so this one carries no plan number of its own).
#
# WHAT THIS FILE IS.  A total ordering over rpm package version strings, in
# pure bash: no fork, no `sort -V`, no external command, and no arithmetic on
# an untrusted digit run.  It is the piece a later ticket needs to decide
# whether an installed `(epoch, version, release)` read by
# `modules/image/distro/rpm.sh` is below an advisory's fixed-in version.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No advisory lookup, no
# `data/advisories.db` read, no finding, no `run_record`, no coverage
# reduction, and no `modules/image/run.sh` wiring - all of that is the next
# ticket.  Like `modules/image/distro/apk_version.sh` (IMG-05),
# `modules/image/distro/dpkg_version.sh` (IMG-08) and `modules/sca/semver.sh`
# before it, this is a LEAF: it sources nothing, so it adds no edge to the
# `shellcheck -x` source graph `tests/lint-source-graph.sh` caps (AGENTS.md,
# "the memory model").  Keep it that way.
#
# ---------------------------------------------------------------------------
# WHY THIS IS NOT `modules/sca/semver.sh`, AND NOT EITHER SIBLING COMPARATOR
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh` is npm-only by explicit, measured decision - its own
# header records 1.66% divergence against real PEP 440, "a false-NEGATIVE
# divergence, the exact direction tension 25 calls disqualifying", as the
# reason it never generalised into a shared `version_cmp`.
#
# The same standard was applied to OS versions, measuring the
# shipped comparator at 5 correct / 7 WRONG out of 12.  Three of those seven
# are rpm's, and they are this file's reason to exist:
#
#     MISMATCH  1.0           vs  1.0~rc1   semver= 0  true= 1
#     MISMATCH  1.0^20230101  vs  1.0       semver= 0  true= 1
#     MISMATCH  2:1.0-1       vs  3.0-1     semver=-1  true= 1
#
# Two of those three answer `0` - EQUAL - which a caller asking "is the
# installed version below the fixed-in version" reads as "not below", reads
# as "not vulnerable", and reports with no diagnostic at all.  That is the
# silent direction, and it is why reuse is ruled out by the project's own
# frozen standard, measured the same way that standard was originally set.
#
# The inverse temptation - ONE `os_version_cmp` for all three distros - is
# just as wrong, and rpm is where it breaks worst.  The three grammars
# disagree on cases each considers ordinary:
#
#     1.0 vs 1.0-r0 / 1.0-0     apk: LESS (an absent pkgrel is not -r0)
#                               dpkg: EQUAL (an absent revision IS "0")
#                               rpm: not the same question at all - release
#                                    is a separate FIELD, not a suffix
#     1.0^git1                  rpm: sorts ABOVE 1.0 (the caret rule)
#                               dpkg: `^` is not in its alphabet at all
#                               apk: likewise not in its grammar
#     2_0 vs 2.0                rpm: EQUAL - `_` is just another separator
#                               dpkg: `_` is illegal, the version is refused
#                               apk: `_` introduces a pre/post-release suffix
#                                    with its own ordering table
#     1.0a vs 1.0.1             rpm: LESS - a numeric segment beats an alpha
#                                    one whenever the two align
#                               dpkg: LESS too, but for an unrelated reason
#                                    (its modified ASCII puts letters below
#                                    every other non-alphanumeric); the two
#                                    rules diverge elsewhere, so the shared
#                                    answer here is a coincidence
#
# so a merged comparator is necessarily wrong for at least two of its three
# callers.  Three distros, three files, by measurement rather than by
# preference.
#
# ---------------------------------------------------------------------------
# THE GRAMMAR
# ---------------------------------------------------------------------------
# An rpm package version is an EVR triple:
#
#     [epoch:]version[-release]
#
#   epoch     an unsigned integer, default 0 when absent.  Compared FIRST,
#             and NUMERICALLY - which is the whole reason
#             `2:1.0-1 > 3.0-1`: epoch 2 beats epoch 0 without ever looking
#             at 1.0 against 3.0.
#   version   rpm's own allowed alphabet is alphanumerics plus `.`, `_`,
#             `+`, `~` and `^` (rpm validates exactly this set on a spec
#             file's Version: and Release: fields).  Unlike a Debian
#             version it need NOT start with a digit: `xyz10` is a legal rpm
#             version and appears in rpm's own test vectors.
#   release   the same alphabet.  It is a SEPARATE FIELD rather than a
#             suffix, which is why `modules/image/distro/rpm.sh` returns it
#             in its own parallel array and why `rpm_evr_cmp_v` below exists
#             beside the string form.
#
# `-` is the version/release separator and is NOT legal inside either part,
# so under this file's alphabet check the "split at the LAST hyphen" rule rpm
# itself uses and a "split at the first hyphen" rule accept exactly the same
# strings.  The last-hyphen split is kept anyway, because it is rpm's, and
# because keeping the rule the reference keeps costs nothing.
#
# ---------------------------------------------------------------------------
# THE ALGORITHM: rpmvercmp
# ---------------------------------------------------------------------------
# Both the version and the release are ordered by `rpmvercmp`, transcribed
# here from rpm's documented algorithm.  It walks the two strings in
# lockstep:
#
#   0. IDENTICAL STRINGS are equal, checked before anything else.
#   1. SKIP SEPARATORS.  Advance each cursor past every character that is
#      not alphanumeric and not `~` or `^`.  So `.`, `_`, `+` and any other
#      byte are pure separators with no ordering weight of their own, which
#      is why `2_0 == 2.0` and `+ == _`.
#   2. THE TILDE RULE.  If either cursor is at `~`, the side that is NOT at
#      a `~` is GREATER.  This is checked BEFORE the end-of-string test, so
#      `~` sorts below everything INCLUDING the empty string:
#      `1.0~rc1 < 1.0`.  Both cursors then advance past the `~`.
#   3. THE CARET RULE.  If either cursor is at `^`, the side that has ENDED
#      is LESSER (`1.0 < 1.0^20230101`); otherwise the side that is NOT at a
#      `^` is GREATER (`1.0^git1 < 1.0.1`).  Both cursors then advance.
#      Tilde and caret are the same idea pointing opposite ways: a `~`
#      demotes what follows below the bare version, a `^` promotes it above
#      the bare version but below the next real segment.
#   4. If either side has now ENDED, leave the loop.
#   5. SEGMENT.  Take a maximal run of DIGITS if the left cursor is at a
#      digit, otherwise a maximal run of LETTERS - and take the same KIND of
#      run on the right, which may therefore be EMPTY.
#      - An empty run on the right means the two sides are of different
#        kinds.  A NUMERIC segment then wins and an ALPHA segment loses:
#        `1a < 1.0`, `xyz.4 < 8`.
#      - Two numeric runs: strip leading zeros, then the LONGER stripped run
#        is the larger number (`1.0010 > 1.9`), and equal lengths fall to a
#        byte comparison (`1.05 == 1.5` once the zeros are gone).
#      - Two alpha runs: a plain byte comparison (`10a2 < 10b2`).
#      Both cursors advance past their run and the loop repeats.
#   6. When the loop ends, whichever side still has characters left is
#      GREATER; if both are exhausted they are EQUAL.
#
# The whole EVR comparison is then: epoch numerically, then `rpmvercmp` on
# the versions, then `rpmvercmp` on the releases; first non-zero wins.
#
# THE TWO RULES THIS FILE EXISTS FOR both fail in the direction that reads as
# a clean scan.  `1.0~rc1` is a PRE-release, so a comparator that ranks it at
# or above `1.0` reports a release candidate as already carrying `1.0`'s
# fixes.  `1.0^20230101` is a POST-release snapshot, so a comparator that
# ranks it at or below `1.0` reports a build made after a fix as still
# needing it - noisier, but it is the same defect wearing the other sign, and
# a comparator that gets one right by accident usually gets the other wrong.
#
# NO ARITHMETIC ON UNTRUSTED DIGITS.  A version string comes out of a scanned
# image's package database and is untrusted text (tension 10's "untrusted
# target output", one step more exposed than an OSV-supplied string).
# `$(( 10#$run ))` on a 400-digit run silently wraps at 64 bits, so a hostile
# or corrupt database could make a low version compare high.  rpm's own
# algorithm never needs the VALUE of a run - "strip the zeros, then the
# longer run is larger, else compare bytes" is exact at any width - and this
# file keeps that property, comparing the EPOCH the same way
# (`_rpmv_cmp_digits`).  The only values ever fed to `(( ))` are cursor
# indices and character orders minted from this file's own table.
#
# NO LOCALE DEPENDENCE, AND NO RANGE EXPRESSIONS.  rpm's segment comparison
# is `strcmp`, i.e. BYTE order, where every uppercase letter sorts below
# every lowercase one.  bash's `[[ $x < $y ]]` uses the COLLATION order
# instead, which under a UTF-8 locale interleaves the cases and inverts
# `1.0A < 1.0a`.  Segments are therefore compared through `_RPMV_ORD`, a
# code-point table built once at source time, and characters are classified
# through `_RPMV_CLASS` rather than through a `[0-9a-zA-Z]` bracket RANGE,
# whose members are themselves collation-defined.  The one glob in this file
# - the alphabet gate in `_rpmv_field_ok` - spells its set out character by
# character for the same reason: a set with no `-` in it forms no range, so
# it means the same thing under every locale.  `tools/daily-suite.sh` runs
# this suite under two userlands precisely to catch this class of drift.
#
# FORK-FREE BY CONSTRUCTION.  `rpm_version_cmp_v` SETS `_RPMV_CMP` rather
# than printing it - the `occurrence_next`/`worker_id_set` idiom AGENTS.md
# mandates, because a side-effecting function called as `$(f)` runs in a
# subshell and its writes are discarded.  `rpm_version_cmp` (printing) is
# kept only for the differential harness, exactly as `semver_cmp`,
# `apk_version_cmp` and `dpkg_version_cmp` are.
#
# ---------------------------------------------------------------------------
# MALFORMED INPUT IS UNORDERABLE, NOT "EQUAL" AND NOT "LESS"
# ---------------------------------------------------------------------------
# Anything outside the grammar above - an empty string, an empty or
# non-numeric epoch, an empty version, an empty release after a trailing
# `-`, an out-of-alphabet byte - makes the version UNORDERABLE.
# `rpm_version_cmp_v` then returns rc 1 and sets `_RPMV_REASON` to
# `invalid_version_a` or `invalid_version_b`, leaving `_RPMV_CMP` at 0; it
# never invents an ordering.  This matters more than it looks: the two silent
# alternatives are "call it equal" and "call it less", and BOTH render an
# unreadable version identically to a version that was read and found safe.
# A caller owes a `coverage_reduction` on rc 1, never a silent skip - and
# `modules/image/distro/rpm.sh` reads its fields out of a sqlite database
# whose rows it does not author, so an unorderable input is an ordinary,
# expected arrival here rather than a corrupt-database edge case.
#
# TWO WELL-FORMED VERSIONS ARE ALWAYS ORDERED.  `_rpmv_vercmp` is total by
# construction - it consumes both strings - so unlike `apk_version.sh` this
# file needs no field-order rule and has NO divergence from the reference
# tool's own ordering on anything it accepts.  `invalid_version_a` and
# `invalid_version_b` are the only two reasons it can report.
#
# ---------------------------------------------------------------------------
# THE THREE DELIBERATE STRICTNESSES, ALL IN THE FAIL-SAFE DIRECTION
# ---------------------------------------------------------------------------
# `rpmvercmp` itself never fails: it accepts any byte string and returns an
# ordering for it.  This file REFUSES in three places where rpm answers, and
# nowhere does it answer where rpm refuses - so no strictness here can turn a
# finding into silence.  Each is a REFUSAL a caller must report, not a
# different ordering it might act on.
#
#   1. NON-ASCII BYTES.  rpm's `risalnum` is ASCII-only, so a UTF-8 character
#      is skipped as a separator and `1.1.<alpha>` compares EQUAL to
#      `1.1.<beta>`.  rpm's own test suite carries those rows expressly to
#      document "arguably buggy behaviors".  Reproducing a documented bug
#      would make two genuinely different versions indistinguishable, which
#      is the silent direction; this file refuses the byte instead.
#   2. AN OUT-OF-ALPHABET ASCII BYTE.  rpm orders `1.0/1` or `1.0 1` by
#      treating the stray byte as a separator.  Neither can appear in a
#      version rpm itself would have built, so its presence means the field
#      was not read correctly - which this scanner should report as
#      unreadable rather than quietly normalise.
#   3. A MALFORMED EPOCH.  rpm's own `parseEVR` recognises an epoch only when
#      a leading digit run is immediately followed by `:`, and silently folds
#      every other colon into the version.  So `a:1.0` is, to rpm, a version
#      literally containing a colon.  This file refuses any colon that is not
#      a well-formed epoch separator, and refuses an empty epoch, where rpm
#      reads `:1.0` as epoch 0.
#
# A HUGE EPOCH is the one place this file is LOOSER, and it is loose in the
# safe direction too: rpm stores an epoch in a 32-bit tag and cannot
# represent one above UINT32_MAX, where this file orders it width-exactly and
# correctly.  That can only turn a refusal into a right answer.
#
# ---------------------------------------------------------------------------
# THE OFFLINE-CORPUS LIMIT, AND THE FOLLOW-UP HARDENING THIS OWES
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh`'s bar is "differential-tested against a reference,
# 0 mismatches".  `tests/suites/image-rpm-version.sh` meets it twice over -
# against a committed, provenance-annotated corpus of known orderings
# (`tests/fixtures/image/rpm-version-corpus.tsv`) and against an independent
# Python reference over a generated sweep - but BOTH references are derived
# from rpm's documented `rpmvercmp` algorithm and from rpm's own published
# test vectors (librpm's `rpmvercmp.at`) rather than harvested by running the
# tool.  scoursh is egress-restricted and no `rpm` or `rpmdev-vercmp` binary
# exists on the development host, so nothing was fetched and nothing was
# executed to produce a row.
#
# The follow-up hardening is therefore: on a networked box with rpm
# installed, replay the committed corpus through
# `rpmdev-vercmp '<A>' '<B>'` (or `rpm --eval '%{lua:...rpm.vercmp...}'`),
# harvest real `(epoch, version, release)` triples from a Fedora and a RHEL
# package index, and extend the corpus with whatever it disagrees on.  The
# corpus file's `<`/`=`/`>` column is deliberately the same vocabulary
# `apk-version-corpus.tsv` and `dpkg-version-corpus.tsv` use and maps
# one-for-one onto `rpmdev-vercmp`'s own exit codes (11 = A newer, 12 = B
# newer, 0 = equal), so that run is a direct column diff rather than a
# translation.  This is the same shape as the GNU-tar cross-check
# `tools/daily-suite.sh` already defers - a stated gap with a named
# discharge, not an unmeasured claim.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_RPM_VERSION_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_RPM_VERSION_SOURCED=1

# ---------------------------------------------------------------------------
# 1. The character tables
# ---------------------------------------------------------------------------

# `_RPMV_CLASS[c]` is `d` for an ASCII digit and `a` for an ASCII letter, and
# is UNSET for everything else - which is exactly rpm's `risdigit`/`risalpha`
# /`risalnum`, and is deliberately NOT a `[0-9a-zA-Z]` bracket range, whose
# membership is collation-defined and so locale-dependent.
#
# `_RPMV_ORD[c]` is the character's code point, used for the byte-order
# segment comparison rpm's own `strcmp` performs.  bash's `[[ $x < $y ]]`
# would use COLLATION instead, which under a UTF-8 locale interleaves the
# cases and inverts `1.0A < 1.0a`; the table is what keeps this file's answer
# identical under both userlands `tools/daily-suite.sh` runs.
declare -A _RPMV_CLASS
declare -A _RPMV_ORD
_rpmv_build_tables() {
  local c code
  for c in 0 1 2 3 4 5 6 7 8 9; do
    _RPMV_CLASS[$c]=d
    printf -v code '%d' "'$c"
    _RPMV_ORD[$c]=$code
  done
  for c in {a..z} {A..Z}; do
    _RPMV_CLASS[$c]=a
    printf -v code '%d' "'$c"
    _RPMV_ORD[$c]=$code
  done
}
_rpmv_build_tables
unset -f _rpmv_build_tables

# ---------------------------------------------------------------------------
# 2. Parsing and validation
# ---------------------------------------------------------------------------

# _rpmv_field_ok FIELD - rc 0 when FIELD is a non-empty string drawn only
# from rpm's own version/release alphabet (alphanumerics plus `. _ + ~ ^`),
# rc 1 otherwise.
#
# The set is spelled out character by character rather than as `[0-9a-zA-Z]`
# because a bracket RANGE is resolved by the locale's collation, so `[a-z]`
# can admit an uppercase letter - or a non-ASCII one - under a UTF-8 locale.
# A set containing no `-` forms no range at all and therefore means the same
# thing everywhere.  A `-` is absent from the set on purpose: it is the
# version/release SEPARATOR and is illegal inside either part.
#
# One glob is the whole of the character validation, with no per-character
# scan behind it, because bash's `*` matches ANY byte including a newline, a
# tab and a carriage return - so a value carrying one still presents an
# out-of-alphabet character to the bracket negation and is refused.  That is
# measured rather than assumed; `tests/suites/image-rpm-version.sh` section C
# keeps the whitespace operands so a later "simplification" cannot quietly
# reopen the hole.
_rpmv_field_ok() {
  [[ -n $1 ]] || return 1
  [[ $1 != *[!0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._+~^]* ]]
}

# _rpmv_parse EVR - splits `[epoch:]version[-release]` into `_RPMV_EPOCH`,
# `_RPMV_VERSION` and `_RPMV_RELEASE` and returns 0, or returns 1 leaving all
# three unspecified when EVR is not a legal rpm version string.
#
# `_RPMV_RELEASE` is the EMPTY STRING when no release is present, which is
# how rpm treats it too: `rpmvercmp("", "")` is 0 and `rpmvercmp("", "1")` is
# -1, so an absent release orders below any present one and equal to another
# absent one, with no special case needed anywhere below.  A TRAILING hyphen
# is a different thing entirely and is refused - it is a malformed string,
# not an absent field.
#
# The order of the two splits is rpm's own and is not interchangeable: the
# epoch comes off at the FIRST `:`, and the release at the LAST `-`.
_rpmv_parse() {
  local v=$1 rest ep rel ver

  [[ -n $v ]] || return 1

  # 2a. Epoch, at the FIRST colon.  Both halves must be non-empty and the
  # epoch must be digits only - which is also what rejects a negative epoch,
  # since `-` is not a digit.  rpm itself is looser here (it folds a colon it
  # does not recognise as an epoch separator into the version); see the
  # header's strictness 3 for why this file refuses instead.
  if [[ $v == *:* ]]; then
    ep=${v%%:*}
    rest=${v#*:}
    [[ -n $ep && -n $rest ]] || return 1
    [[ $ep != *[!0123456789]* ]] || return 1
  else
    ep=0
    rest=$v
  fi

  # 2b. Release, at the LAST hyphen.  A trailing hyphen leaves an empty
  # release, which is a malformed string rather than an absent field.
  if [[ $rest == *-* ]]; then
    rel=${rest##*-}
    ver=${rest%-*}
    [[ -n $rel ]] || return 1
    _rpmv_field_ok "$rel" || return 1
  else
    rel=''
    ver=$rest
  fi

  # 2c. The version.  Unlike a Debian version it need NOT start with a
  # digit: `xyz10` is legal and appears in rpm's own test vectors.
  _rpmv_field_ok "$ver" || return 1

  _RPMV_EPOCH=$ep
  _RPMV_VERSION=$ver
  _RPMV_RELEASE=$rel
  return 0
}

# ---------------------------------------------------------------------------
# 3. Comparison
# ---------------------------------------------------------------------------

# _rpmv_cmp_digits A B - sets _RPMV_R to -1/0/1 comparing two digit runs as
# INTEGERS, at any width and with no arithmetic evaluation.  Leading zeros
# are stripped, then the longer stripped run is the larger number, and equal
# lengths fall to a byte comparison through `_rpmv_cmp_bytes`.  Both runs
# must be non-empty digit strings.  Used for the EPOCH and, through
# `_rpmv_vercmp`, for every numeric segment.
_rpmv_cmp_digits() {
  local a=$1 b=$2
  while (( ${#a} > 1 )) && [[ $a == 0* ]]; do a=${a#0}; done
  while (( ${#b} > 1 )) && [[ $b == 0* ]]; do b=${b#0}; done
  if (( ${#a} != ${#b} )); then
    if (( ${#a} < ${#b} )); then _RPMV_R=-1; else _RPMV_R=1; fi
    return 0
  fi
  _rpmv_cmp_bytes "$a" "$b"
}

# _rpmv_cmp_bytes A B - sets _RPMV_R to -1/0/1, comparing two strings the way
# `strcmp` does: byte by byte by CODE POINT, then by length.  Both operands
# are alphanumeric runs drawn from `_RPMV_ORD`, so every character has an
# entry; the `-0` default exists only so a table gap could never expand to
# the empty string inside `(( ))`.
#
# This exists instead of `[[ $a < $b ]]` because that comparison uses the
# locale's COLLATION order, under which `A` and `a` interleave and
# `1.0A < 1.0a` inverts - a divergence from rpm that would appear on one of
# the two userlands `tools/daily-suite.sh` runs and not the other.
_rpmv_cmp_bytes() {
  local a=$1 b=$2 n=${#1} m=${#2} k=0 oa ob
  if (( m < n )); then n=$m; fi
  while (( k < n )); do
    oa=${_RPMV_ORD[${a:k:1}]-0}
    ob=${_RPMV_ORD[${b:k:1}]-0}
    if (( oa != ob )); then
      if (( oa < ob )); then _RPMV_R=-1; else _RPMV_R=1; fi
      return 0
    fi
    k=$(( k + 1 ))
  done
  if (( ${#a} != ${#b} )); then
    if (( ${#a} < ${#b} )); then _RPMV_R=-1; else _RPMV_R=1; fi
    return 0
  fi
  _RPMV_R=0
  return 0
}

# _rpmv_vercmp A B - sets _RPMV_R to -1/0/1 for one PART of an rpm version
# (a version, or a release).  This is `rpmvercmp`, transcribed from the
# algorithm the header documents, with two index cursors in place of the two
# pointers rpm walks.
#
# Termination: every iteration of the outer loop either returns, breaks, or
# advances BOTH cursors past at least one character (a `~`/`^` pair, or a
# segment whose left-hand run is non-empty by construction - the left cursor
# is at an alphanumeric by the time step 5 is reached, so its run is at least
# one character long).
_rpmv_vercmp() {
  local a=$1 b=$2

  # Identical strings are equal, checked before the walk - rpm's own first
  # line, and what makes reflexivity structural rather than emergent.
  if [[ $a == "$b" ]]; then _RPMV_R=0; return 0; fi

  local na=${#a} nb=${#b}
  local i=0 j=0
  local ca cb kind si sj sega segb

  while (( i < na || j < nb )); do
    # Step 1: skip separators - everything that is neither alphanumeric nor
    # `~` nor `^`.  `.`, `_` and `+` carry no ordering weight of their own,
    # which is why `2_0 == 2.0` and `+ == _`.
    while (( i < na )); do
      ca=${a:i:1}
      if [[ -n ${_RPMV_CLASS[$ca]-} || $ca == '~' || $ca == '^' ]]; then break; fi
      i=$(( i + 1 ))
    done
    while (( j < nb )); do
      cb=${b:j:1}
      if [[ -n ${_RPMV_CLASS[$cb]-} || $cb == '~' || $cb == '^' ]]; then break; fi
      j=$(( j + 1 ))
    done

    if (( i < na )); then ca=${a:i:1}; else ca=''; fi
    if (( j < nb )); then cb=${b:j:1}; else cb=''; fi

    # Step 2: the tilde rule, checked BEFORE the end-of-string test, which is
    # the whole of `1.0~rc1 < 1.0`.
    if [[ $ca == '~' || $cb == '~' ]]; then
      if [[ $ca != '~' ]]; then _RPMV_R=1; return 0; fi
      if [[ $cb != '~' ]]; then _RPMV_R=-1; return 0; fi
      i=$(( i + 1 )); j=$(( j + 1 )); continue
    fi

    # Step 3: the caret rule.  The ENDED side loses first - that is what
    # makes `1.0 < 1.0^20230101` - and only then does a non-caret side win,
    # which is what makes `1.0^git1 < 1.0.1`.  Swapping those two tests is
    # the single most likely way to get this rule wrong, and it inverts
    # exactly the `1.0^20230101` vs `1.0` case measured above.
    if [[ $ca == '^' || $cb == '^' ]]; then
      if [[ -z $ca ]]; then _RPMV_R=-1; return 0; fi
      if [[ -z $cb ]]; then _RPMV_R=1; return 0; fi
      if [[ $ca != '^' ]]; then _RPMV_R=1; return 0; fi
      if [[ $cb != '^' ]]; then _RPMV_R=-1; return 0; fi
      i=$(( i + 1 )); j=$(( j + 1 )); continue
    fi

    # Step 4: if either side has run out, leave the loop and let step 6
    # decide.
    [[ -n $ca && -n $cb ]] || break

    # Step 5: the segment.  The KIND is taken from the LEFT cursor, and the
    # right-hand run is taken of that same kind - so it may be EMPTY, which
    # is how a numeric segment comes to be compared against an alpha one.
    kind=${_RPMV_CLASS[$ca]}
    si=$i; sj=$j
    if [[ $kind == d ]]; then
      while (( si < na )) && [[ ${_RPMV_CLASS[${a:si:1}]-} == d ]]; do si=$(( si + 1 )); done
      while (( sj < nb )) && [[ ${_RPMV_CLASS[${b:sj:1}]-} == d ]]; do sj=$(( sj + 1 )); done
    else
      while (( si < na )) && [[ ${_RPMV_CLASS[${a:si:1}]-} == a ]]; do si=$(( si + 1 )); done
      while (( sj < nb )) && [[ ${_RPMV_CLASS[${b:sj:1}]-} == a ]]; do sj=$(( sj + 1 )); done
    fi

    # A run of length zero on the right means the two sides are of different
    # kinds.  A NUMERIC segment is always newer than an ALPHA one, so the
    # answer depends on which kind the LEFT side took: `1.0 > 1a`, and
    # `8 > xyz.4`.
    if (( sj == j )); then
      if [[ $kind == d ]]; then _RPMV_R=1; else _RPMV_R=-1; fi
      return 0
    fi

    sega=${a:i:si-i}
    segb=${b:j:sj-j}
    if [[ $kind == d ]]; then
      _rpmv_cmp_digits "$sega" "$segb"
    else
      _rpmv_cmp_bytes "$sega" "$segb"
    fi
    if (( _RPMV_R != 0 )); then return 0; fi

    i=$si
    j=$sj
  done

  # Step 6: whichever side still has characters left is greater.  Reached
  # either by the `break` above - in which case both cursors have already
  # skipped their separators, so a trailing `.` on one side alone is not
  # "characters left" - or by the loop condition going false with both sides
  # exhausted.
  if (( i >= na && j >= nb )); then _RPMV_R=0
  elif (( i >= na )); then _RPMV_R=-1
  else _RPMV_R=1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. Public interface
# ---------------------------------------------------------------------------

# rpm_version_valid EVR - rc 0 when EVR is a legal `[epoch:]version[-release]`
# string, rc 1 when it is not.  Callers that want to report an unreadable
# version WITHOUT ordering it use this.
rpm_version_valid() {
  _rpmv_parse "$1"
}

# rpm_version_cmp_v A B - sets _RPMV_CMP to -1 (A<B), 0 (A==B) or 1 (A>B)
# and returns 0.  Returns 1 WITHOUT ordering - leaving _RPMV_CMP at 0, which
# a caller must never read as "equal" - and sets _RPMV_REASON to one of:
#
#   invalid_version_a / invalid_version_b   that side is not a legal rpm
#                                           version string
#
# Two WELL-FORMED versions are always ordered, so a refusal always means an
# unreadable input rather than "I could not decide".  This is the fork-free
# production entry point for the string form.
rpm_version_cmp_v() {
  _RPMV_CMP=0
  _RPMV_REASON=''
  local ea va ra eb vb rb

  if ! _rpmv_parse "$1"; then _RPMV_REASON=invalid_version_a; return 1; fi
  ea=$_RPMV_EPOCH; va=$_RPMV_VERSION; ra=$_RPMV_RELEASE
  if ! _rpmv_parse "$2"; then _RPMV_REASON=invalid_version_b; return 1; fi
  eb=$_RPMV_EPOCH; vb=$_RPMV_VERSION; rb=$_RPMV_RELEASE

  _rpmv_evr_cmp "$ea" "$va" "$ra" "$eb" "$vb" "$rb"
  _RPMV_CMP=$_RPMV_R
  return 0
}

# _rpmv_evr_cmp EA VA RA EB VB RB - sets _RPMV_R, comparing two already-parsed
# triples.  Epoch first and NUMERICALLY, then the versions, then the
# releases; the first non-zero result wins.  The measured `2:1.0-1 >
# 3.0-1` case above never reaches the version comparison at all.
_rpmv_evr_cmp() {
  _rpmv_cmp_digits "$1" "$4"
  if (( _RPMV_R != 0 )); then return 0; fi
  _rpmv_vercmp "$2" "$5"
  if (( _RPMV_R != 0 )); then return 0; fi
  _rpmv_vercmp "$3" "$6"
  return 0
}

# rpm_evr_cmp_v EA VA RA EB VB RB - the FIELD form, for a caller holding the
# three columns separately.  `modules/image/distro/rpm.sh` returns exactly
# that shape - five parallel arrays, one of which is `RPM_INSTALLED_EPOCHS`
# and is "commonly the empty string", since most rpm packages carry no epoch
# at all - so joining those fields into a string only to split them again
# here would be a lossy round trip for no gain.
#
# The two forms differ in ONE place, deliberately.  An EMPTY EPOCH or an
# EMPTY RELEASE is an ABSENT FIELD here and is accepted: epoch 0, and a
# release that orders below every present one.  In the STRING form the same
# two shapes are `:1.0` and `1.0-`, which are malformed STRINGS and are
# refused.  The distinction is real - a database column that is NULL and a
# version string with a dangling separator are different facts - and
# collapsing it in either direction loses one of them.
#
# Sets _RPMV_CMP and _RPMV_REASON exactly as rpm_version_cmp_v does, and
# reports `invalid_version_a`/`invalid_version_b` for a non-numeric epoch, an
# empty or out-of-alphabet version, or an out-of-alphabet release.
rpm_evr_cmp_v() {
  _RPMV_CMP=0
  _RPMV_REASON=''
  # Every operand is read with a `-` default rather than positionally: this
  # file is sourced into runs under `set -u`, where a caller that passed five
  # arguments instead of six would abort the whole scan on `$6` rather than
  # get the refusal this function exists to give.  A missing VERSION then
  # arrives as the empty string, which _rpmv_field_ok refuses like any other
  # unreadable field.
  local ea=${1:-0} va=${2-} ra=${3-} eb=${4:-0} vb=${5-} rb=${6-}

  if [[ $ea == *[!0123456789]* ]] || ! _rpmv_field_ok "$va" \
     || { [[ -n $ra ]] && ! _rpmv_field_ok "$ra"; }; then
    _RPMV_REASON=invalid_version_a
    return 1
  fi
  if [[ $eb == *[!0123456789]* ]] || ! _rpmv_field_ok "$vb" \
     || { [[ -n $rb ]] && ! _rpmv_field_ok "$rb"; }; then
    _RPMV_REASON=invalid_version_b
    return 1
  fi

  _rpmv_evr_cmp "$ea" "$va" "$ra" "$eb" "$vb" "$rb"
  _RPMV_CMP=$_RPMV_R
  return 0
}

# rpm_version_cmp A B - prints `-1`, `0` or `1`, or prints `?` and returns 1
# when either side is unorderable.  Kept for the differential harness only,
# exactly as `modules/sca/semver.sh` keeps `semver_cmp` and the two sibling
# comparators keep theirs; production callers use rpm_version_cmp_v or
# rpm_evr_cmp_v.
rpm_version_cmp() {
  if rpm_version_cmp_v "$1" "$2"; then
    printf '%s' "$_RPMV_CMP"
    return 0
  fi
  printf '?'
  return 1
}
