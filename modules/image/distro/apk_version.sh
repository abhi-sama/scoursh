#!/usr/bin/env bash
# modules/image/distro/apk_version.sh - the apk-tools VERSION COMPARATOR
# (IMG-05).
#
# WHAT THIS FILE IS.  A total ordering over Alpine/apk package version
# strings, in pure bash: no fork, no `sort -V`, no external command, and no
# arithmetic on an untrusted digit run.  It is the piece IMG-06 needs to
# decide whether an installed `V:` version read by
# `modules/image/distro/apk.sh` is below an advisory's fixed-in version.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No advisory lookup, no
# `data/advisories.db` read, no finding, no `run_record`, no coverage
# reduction, and no `modules/image/run.sh` wiring - all of that is IMG-06.
# Like `modules/image/distro/apk.sh` and `modules/sca/semver.sh` before it,
# this is a LEAF: it sources nothing, so it adds no edge to the
# `shellcheck -x` source graph `tests/lint-source-graph.sh` caps (AGENTS.md,
# "the memory model").  Keep it that way.
#
# ---------------------------------------------------------------------------
# WHY THIS IS NOT `modules/sca/semver.sh`, AND WHY IT MUST NOT BECOME IT
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh` is npm-only by explicit, measured decision - its
# own header records 1.66% divergence against real PEP 440, "a false-NEGATIVE
# divergence, the exact direction tension 25 calls disqualifying", as the
# reason it never generalised into a shared `version_cmp`.
#
# The same standard was applied to OS versions and measured the
# shipped comparator at 5 correct / 7 WRONG out of 12, including:
#
#     MISMATCH  1.2.3-r4  vs  1.2.3-r10   semver= 1   true=-1
#
# `_sv_split` splits on the FIRST `-`, so `1.2.3-r4`'s release becomes the
# prerelease string `r4` and is compared LEXICALLY against `r10`: "r4" > "r10"
# because "4" > "1".  If an advisory's fixed-in version is `-r10`, an
# actually-vulnerable `-r4` package is reported SAFE.  That is a false
# negative - silent, and the exact direction the project's frozen standard
# already rules disqualifying.  Reuse is therefore ruled out by the project's
# own rule, not by preference, and this comparator is its own file.
#
# The inverse temptation is just as wrong: do NOT later "unify" the two into
# one `version_cmp`.  apk and SemVer disagree on cases both consider ordinary
# (`1.0` vs `1.0.0` is EQUAL under SemVer and LESS under apk; `_git` sorts
# ABOVE the bare version where every SemVer prerelease sorts below), so a
# merged comparator is necessarily wrong for one of its two callers.
#
# ---------------------------------------------------------------------------
# THE GRAMMAR, AND THE ALGORITHM
# ---------------------------------------------------------------------------
# apk-tools' documented version grammar:
#
#     NUM ( '.' NUM )*  [ letter ]  ( '_' suffix [ NUM ] )*  [ '-r' NUM ]
#
# with the suffix ordering
#
#     alpha < beta < pre < rc < (no suffix) < cvs < svn < git < hg < p
#
# apk has no epoch in practice, which is why it is the easy distro; the
# remaining work ranks apk << dpkg < rpm.
#
# A version is LEXED into a token stream, and two streams are then walked in
# lockstep.  The tokens are:
#
#     d   the leading numeric component
#     z   a subsequent dotted numeric component (leading zeros are
#         significant here - see FRACTIONAL COMPONENTS below)
#     l   the single optional lowercase letter, valued by its code point
#     s   a suffix, valued by its RANK (negative for a pre-release suffix,
#         positive for a post-release one - see below)
#     x   the optional number attached to a suffix
#     r   the `-rN` pkgrel
#     E   end of stream (every stream carries exactly one, last)
#
# The walk, which is apk's own:
#
#   1. While the two streams' token TYPES agree and the type is not `E`,
#      compare the two VALUES.  The first difference decides the ordering.
#   2. On a type MISMATCH (or on both streams reaching `E`), the values are
#      already known equal and the ordering is decided STRUCTURALLY:
#        a. both at `E`                -> EQUAL
#        b. either side's next token is a PRE-RELEASE suffix (rank < 0)
#           -> that side is LESS
#        c. otherwise the side whose next token sits in a LATER FIELD of the
#           grammar is LESS (see THE FIELD-ORDER RULE below)
#
# Rule 2b is the load-bearing one and it is why suffix ranks are signed.
# `1.2.3_alpha1` and `1.2.3` agree on every token up to the point where one
# stream ends and the other has a suffix; without 2b, rule 2c would fire and
# report `1.2.3` as the SMALLER of the two - backwards, and backwards in the
# direction that reads as a clean scan.
#
# THE FIELD-ORDER RULE (2c), which is where a naive implementation goes wrong
# and where this file's one deliberate divergence from apk-tools lives.
# The grammar's fields run in a fixed order:
#
#     components  ->  letter  ->  suffixes  ->  pkgrel  ->  (end)
#         1            2         3 (num) / 4 (name)   5        6
#
# When two streams' types differ at the same index, each side has ADVANCED to
# a different field.  The side sitting in the LATER field has already passed
# the earlier one WITHOUT CONTENT - it is the absent value there - and an
# absent field sorts low.  So the higher field number is the LOWER version.
# That single principle covers every structural case, and rule 2b is its one
# documented exception (an absent pre-release suffix outranks a present one,
# which is what "pre-release" means).
#
# Worked, in both the obvious and the non-obvious direction:
#
#     1.0        <  1.0.1      end(6) beats components(1): 1.0 has no third
#                              component at all
#     1.0        <  1.0a       end(6) beats letter(2)
#     1.0        <  1.0-r0     end(6) beats pkgrel(5) - an absent pkgrel is
#                              NOT `-r0`
#     1.0        <  1.0_git    end(6) beats suffix-name(4), a POST-release
#                              suffix, so 2b does not fire
#     1.0        >  1.0_alpha  rule 2b, the exception
#     1.0-r5     <  1.0.1-r0   pkgrel(5) beats components(1): a pkgrel is a
#                              packaging-only bump, so a side that has reached
#                              it has no upstream content left to offer
#     1.0-r5     <  1.0a-r0    pkgrel(5) beats letter(2), same argument
#     1.0_git-r0 <  1.0_git1-r0  pkgrel(5) beats suffix-number(3), which is
#                              what makes `_git` < `_git1` survive a pkgrel
#                              on both sides
#     1.0_git_p  <  1.0_git1   suffix-name(4) beats suffix-number(3): the
#                              side starting a NEW suffix has finished the
#                              current one
#
# THE DIVERGENCE.  apk-tools' own comparison does NOT do this: its structural
# tie-break falls through to EQUAL whenever neither side has ended and
# neither is a pre-release suffix, which makes `apk version -t` answer `=`
# for `1.0-r5` against `1.0.1-r0`.  Its comparison is therefore a preorder
# rather than an order (`1.0-r0 = 1.0.0` and `1.0-r1 = 1.0.0` while
# `1.0-r0 < 1.0-r1`), which is survivable for a package manager comparing
# two builds of one package and is NOT survivable here:
#
#   EQUAL is the FALSE-NEGATIVE direction.  IMG-06 asks "is the installed
#   version below the advisory's fixed-in version"; EQUAL means "not below",
#   means "not vulnerable", reported with no diagnostic at all - the exact
#   failure shape that disqualified semver.sh above.
#
# The divergence is also one-directional, which is what makes it safe to
# ship: every pair it decides is a pair apk called EQUAL, and EQUAL already
# means "not below" means "reported safe".  So this rule can only ever turn a
# silent SAFE into a reported finding - a false positive at worst, never a
# false negative.  That is the trade this project already makes everywhere
# else ("a false positive: noisy, survivable").
#
# The live `apk version -t` differential named below WILL flag these pairs.
# That is expected.  Confirm each flagged pair is a genuine field-order case
# and leave it; do NOT "fix" it by restoring EQUAL.
#
# FRACTIONAL COMPONENTS.  A dotted component after the first whose digit run
# carries a leading zero is compared as a FRACTION rather than as an integer:
# `1.01 < 1.1`, because `.01` is a smaller fraction than `.1`.  This is
# apk-tools' own rule for its `DIGIT_OR_ZERO` token, and it is the ONE place
# in this file where a spec-derived reading could not be settled against the
# tool offline - see THE OFFLINE-CORPUS LIMIT below.  It cannot fire on the
# LEADING component, which is a plain integer.
#
# MALFORMED INPUT IS UNORDERABLE, NOT "EQUAL" AND NOT "LESS".  Anything the
# grammar above does not accept - an empty string, a leading letter, a `-r`
# with no digits, an unknown `_suffix`, trailing junk - makes the version
# UNORDERABLE.  `apk_version_cmp_v` then returns rc 1 and sets
# `_APKV_REASON` to `invalid_version_a` or `invalid_version_b`, leaving
# `_APKV_CMP` at 0; it never invents an ordering.  This matters more than it
# looks: the two silent alternatives are "call it equal" and "call it less",
# and BOTH render an unreadable version identically to a version that was
# read and found safe.  IMG-06's caller owes a `coverage_reduction` on rc 1,
# never a silent skip.  A WELL-FORMED version is never refused: rule 2c
# above makes the ordering total, so `invalid_version_a`/`invalid_version_b`
# are the only two reasons this file can report.
#
# NO ARITHMETIC ON UNTRUSTED DIGITS.  A version string comes out of a
# scanned image's package database and is untrusted text (the same caution
# `modules/sca/semver.sh`'s header raises for OSV-supplied strings, one step
# more exposed).  `$(( 10#$run ))` on a 400-digit run silently wraps at 64
# bits, so a hostile or corrupt database could make a low version compare
# high.  Digit runs are therefore compared by STRIPPED LENGTH first and
# lexically second (`_apkv_cmp_digits`), which is exact at any width and
# forks nothing.  The only values this file feeds to `(( ))` are suffix
# ranks and letter code points, both minted from its own tables.
#
# FORK-FREE BY CONSTRUCTION.  `apk_version_cmp_v` SETS `_APKV_CMP` rather
# than printing it - the `occurrence_next`/`worker_id_set` idiom AGENTS.md
# mandates, because a side-effecting function called as `$(f)` runs in a
# subshell and its writes are discarded.  `apk_version_cmp` (printing) is
# kept only for the differential harness, exactly as `semver_cmp` is.
#
# ---------------------------------------------------------------------------
# THE OFFLINE-CORPUS LIMIT, AND THE FOLLOW-UP HARDENING THIS OWES
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh`'s bar is "differential-tested against a reference,
# 0 mismatches".  `tests/suites/image-apk-version.sh` meets it twice over -
# against a committed, provenance-annotated corpus of known orderings
# (`tests/fixtures/image/apk-version-corpus.tsv`) and against an independent
# Python reference over a generated sweep - but BOTH references are derived
# from apk-tools' documented algorithm rather than harvested from the tool.
# scoursh is egress-restricted and no `apk` binary exists on the development
# host, so `apk version -t` could not be run and no live corpus was fetched.
#
# The follow-up hardening is therefore: on a networked box with apk-tools
# installed, harvest real Alpine version pairs, differential this comparator
# against `apk version -t`, and extend the committed corpus with whatever it
# disagrees on.  The corpus file's own `<`/`=`/`>` column is deliberately
# `apk version -t`'s output vocabulary so that run is a direct diff.  This is
# the same shape as the GNU-tar cross-check `tools/daily-suite.sh` already
# defers - a stated gap with a named discharge, not an unmeasured claim.
# The fractional-component rule and `1.0 < 1.0-r0` (an absent pkgrel is NOT
# `-r0`) are the two rows that run should scrutinise first.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_APK_VERSION_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_APK_VERSION_SOURCED=1

# ---------------------------------------------------------------------------
# 1. Lexer
# ---------------------------------------------------------------------------

# _apkv_lex VERSION - fills _APKV_T (token types) and _APKV_V (token values)
# and returns 0, or returns 1 leaving both arrays undefined-for-use when
# VERSION does not match the grammar.  A successful stream always ends with
# one `E` token, which is what lets the comparison walk index both streams
# without a bounds test.
_apkv_lex() {
  local v=$1
  _APKV_T=()
  _APKV_V=()
  local n=${#v} i=0 c run rank

  # 1a. The leading numeric component is mandatory.
  run=''
  while (( i < n )); do
    c=${v:i:1}
    [[ $c == [0-9] ]] || break
    run+=$c
    i=$(( i + 1 ))
  done
  [[ -n $run ]] || return 1
  _APKV_T+=(d)
  _APKV_V+=("$run")

  # 1b. Zero or more further dotted components.  Each is `z`, the token whose
  # leading zeros are significant.
  while (( i < n )) && [[ ${v:i:1} == . ]]; do
    i=$(( i + 1 ))
    run=''
    while (( i < n )); do
      c=${v:i:1}
      [[ $c == [0-9] ]] || break
      run+=$c
      i=$(( i + 1 ))
    done
    [[ -n $run ]] || return 1
    _APKV_T+=(z)
    _APKV_V+=("$run")
  done

  # 1c. At most one lowercase letter, and only here - after the last digit
  # component and before any suffix.  Placing it in its own step rather than
  # in a general "next character decides" dispatch is what makes `1.2a.3`
  # invalid rather than silently accepted.
  if (( i < n )) && [[ ${v:i:1} == [a-z] ]]; then
    _APKV_T+=(l)
    printf -v c '%d' "'${v:i:1}"
    _APKV_V+=("$c")
    i=$(( i + 1 ))
  fi

  # 1d. Zero or more `_suffix[NUM]`.  The arms are ordered longest-prefix
  # first: `pre` MUST precede `p`, or `_pre` lexes as suffix `p` followed by
  # the junk `re` and the whole version is rejected.
  while (( i < n )) && [[ ${v:i:1} == _ ]]; do
    i=$(( i + 1 ))
    case ${v:i} in
      alpha*) rank=-4; i=$(( i + 5 )) ;;
      beta*)  rank=-3; i=$(( i + 4 )) ;;
      pre*)   rank=-2; i=$(( i + 3 )) ;;
      rc*)    rank=-1; i=$(( i + 2 )) ;;
      cvs*)   rank=1;  i=$(( i + 3 )) ;;
      svn*)   rank=2;  i=$(( i + 3 )) ;;
      git*)   rank=3;  i=$(( i + 3 )) ;;
      hg*)    rank=4;  i=$(( i + 2 )) ;;
      p*)     rank=5;  i=$(( i + 1 )) ;;
      *)      return 1 ;;
    esac
    _APKV_T+=(s)
    _APKV_V+=("$rank")

    # The suffix number is OPTIONAL and is emitted only when present.  No
    # implicit `x` token valued 0 is synthesised for a bare suffix: apk
    # distinguishes `_git` from `_git0` structurally (rule 2c puts the bare
    # one lower), and inventing the token here would collapse them.
    run=''
    while (( i < n )); do
      c=${v:i:1}
      [[ $c == [0-9] ]] || break
      run+=$c
      i=$(( i + 1 ))
    done
    if [[ -n $run ]]; then
      _APKV_T+=(x)
      _APKV_V+=("$run")
    fi
  done

  # 1e. At most one `-rNUM`, last.
  if (( i < n )) && [[ ${v:i:2} == -r ]]; then
    i=$(( i + 2 ))
    run=''
    while (( i < n )); do
      c=${v:i:1}
      [[ $c == [0-9] ]] || break
      run+=$c
      i=$(( i + 1 ))
    done
    [[ -n $run ]] || return 1
    _APKV_T+=(r)
    _APKV_V+=("$run")
  fi

  # 1f. Anything left over is junk, and junk is unorderable rather than
  # ignorable - a truncated or hostile `V:` line must not silently compare
  # as its own longest valid prefix.
  (( i == n )) || return 1

  _APKV_T+=(E)
  _APKV_V+=(0)
  return 0
}

# ---------------------------------------------------------------------------
# 2. Value comparison, per token type
# ---------------------------------------------------------------------------

# _apkv_cmp_digits A B - sets _APKV_R to -1/0/1 comparing two digit runs as
# INTEGERS, at any width and with no arithmetic evaluation.  Leading zeros
# are stripped, then the longer stripped run is the larger number, and equal
# lengths fall to a plain byte comparison (digits collate in ascending order
# in every locale, so this needs no LC_ALL pin).
_apkv_cmp_digits() {
  local a=$1 b=$2
  while (( ${#a} > 1 )) && [[ $a == 0* ]]; do a=${a#0}; done
  while (( ${#b} > 1 )) && [[ $b == 0* ]]; do b=${b#0}; done
  if (( ${#a} != ${#b} )); then
    if (( ${#a} < ${#b} )); then _APKV_R=-1; else _APKV_R=1; fi
    return 0
  fi
  if [[ $a < $b ]]; then _APKV_R=-1
  elif [[ $a > $b ]]; then _APKV_R=1
  else _APKV_R=0
  fi
  return 0
}

# _apkv_cmp_fractional A B - sets _APKV_R comparing two digit runs as the
# FRACTIONAL parts they are: right-pad the shorter with zeros, then compare
# byte-wise.  `01` vs `1` becomes `01` vs `10` - less, which is what makes
# `1.01 < 1.1`.
_apkv_cmp_fractional() {
  local a=$1 b=$2
  # SC2324: `a+=0` is a deliberate STRING append here - zero-padding the
  # shorter fraction on the right - not an attempted increment.
  # shellcheck disable=SC2324
  while (( ${#a} < ${#b} )); do a+=0; done
  # shellcheck disable=SC2324
  while (( ${#b} < ${#a} )); do b+=0; done
  if [[ $a < $b ]]; then _APKV_R=-1
  elif [[ $a > $b ]]; then _APKV_R=1
  else _APKV_R=0
  fi
  return 0
}

# _apkv_cmp_token TYPE A B - sets _APKV_R for one aligned token pair.
_apkv_cmp_token() {
  local t=$1 a=$2 b=$3
  case $t in
    z)
      # Fractional iff EITHER side carries a leading zero; a pair of plain
      # runs stays an ordinary integer comparison, so `1.2.10 > 1.2.9`.
      if { (( ${#a} > 1 )) && [[ $a == 0* ]]; } || { (( ${#b} > 1 )) && [[ $b == 0* ]]; }; then
        _apkv_cmp_fractional "$a" "$b"
      else
        _apkv_cmp_digits "$a" "$b"
      fi
      ;;
    d|x|r)
      _apkv_cmp_digits "$a" "$b"
      ;;
    l|s)
      # Both are small integers minted by this file's own tables (a code
      # point, a suffix rank), so arithmetic is safe here and nowhere else.
      if (( a < b )); then _APKV_R=-1
      elif (( a > b )); then _APKV_R=1
      else _APKV_R=0
      fi
      ;;
    *)
      _APKV_R=0
      ;;
  esac
  return 0
}

# _apkv_field_of TYPE - sets _APKV_FIELD to the token's position in the
# grammar's field order.  A HIGHER number means the stream has advanced
# FURTHER, which means it passed every earlier field with no content, which
# makes it the LOWER version.  `d` and `z` share a field because they are the
# same field (the dotted components); `x` sits below `s` because a stream
# still reading the current suffix's number has not yet moved on to the next
# suffix name.
_apkv_field_of() {
  case $1 in
    d|z) _APKV_FIELD=1 ;;
    l)   _APKV_FIELD=2 ;;
    x)   _APKV_FIELD=3 ;;
    s)   _APKV_FIELD=4 ;;
    r)   _APKV_FIELD=5 ;;
    *)   _APKV_FIELD=6 ;;   # E
  esac
  return 0
}

# ---------------------------------------------------------------------------
# 3. Public interface
# ---------------------------------------------------------------------------

# apk_version_valid VERSION - rc 0 when VERSION matches the apk grammar,
# rc 1 when it does not.  Callers that want to report an unreadable version
# WITHOUT ordering it (IMG-06's coverage_reduction path) use this.
apk_version_valid() {
  _apkv_lex "$1"
}

# apk_version_cmp_v A B - sets _APKV_CMP to -1 (A<B), 0 (A==B) or 1 (A>B)
# and returns 0.  Returns 1 WITHOUT ordering - leaving _APKV_CMP at 0, which
# a caller must never read as "equal" - and sets _APKV_REASON to one of:
#
#   invalid_version_a / invalid_version_b   that side does not match the
#                                           grammar at all
#
# Two WELL-FORMED versions are always ordered - rule 2c makes the comparison
# total - so a refusal always means an unreadable input, never "I could not
# decide".  This is the fork-free production entry point.
apk_version_cmp_v() {
  _APKV_CMP=0
  _APKV_REASON=''
  local -a TA VA TB VB

  # The guarded expansion form is the tension-24 house style (bash 4.2 errors
  # on an unguarded whole-array expansion of an empty array under `set -u`,
  # and tension 24's frozen minimum is 4.2).  A successful
  # lex never produces an empty stream - it always ends with `E` - but a
  # blanket rule is worth more than a per-site argument, and
  # tests/lint-shell.sh enforces it.
  if ! _apkv_lex "$1"; then _APKV_REASON=invalid_version_a; return 1; fi
  TA=("${_APKV_T[@]+"${_APKV_T[@]}"}"); VA=("${_APKV_V[@]+"${_APKV_V[@]}"}")
  if ! _apkv_lex "$2"; then _APKV_REASON=invalid_version_b; return 1; fi
  TB=("${_APKV_T[@]+"${_APKV_T[@]}"}"); VB=("${_APKV_V[@]+"${_APKV_V[@]}"}")

  local i=0 na=${#TA[@]} nb=${#TB[@]}
  while (( i < na && i < nb )); do
    [[ ${TA[i]} == "${TB[i]}" ]] || break
    [[ ${TA[i]} != E ]] || break
    _apkv_cmp_token "${TA[i]}" "${VA[i]}" "${VB[i]}"
    if (( _APKV_R != 0 )); then _APKV_CMP=$_APKV_R; return 0; fi
    i=$(( i + 1 ))
  done

  # Every stream ends with `E`, so `i` is always in range for both here.
  local ta=${TA[i]} tb=${TB[i]}
  if [[ $ta == "$tb" ]]; then _APKV_CMP=0; return 0; fi
  if [[ $ta == s ]] && (( VA[i] < 0 )); then _APKV_CMP=-1; return 0; fi
  if [[ $tb == s ]] && (( VB[i] < 0 )); then _APKV_CMP=1; return 0; fi
  # Rule 2c, the field-order rule: the side whose next token sits in a LATER
  # field of the grammar passed the earlier field with no content, and an
  # absent field sorts low.  See THE FIELD-ORDER RULE in this file's header
  # for the worked cases and for why this diverges from apk-tools' own
  # fall-through-to-EQUAL in the one safe direction.
  _apkv_field_of "$ta"; local fa=$_APKV_FIELD
  _apkv_field_of "$tb"; local fb=$_APKV_FIELD
  if (( fa > fb )); then _APKV_CMP=-1
  elif (( fa < fb )); then _APKV_CMP=1
  else _APKV_CMP=0
  fi
  return 0
}

# apk_version_cmp A B - prints `-1`, `0` or `1`, or prints `?` and returns 1
# when either side is unorderable.  Kept for the differential harness only,
# exactly as `modules/sca/semver.sh` keeps `semver_cmp`; production callers
# use apk_version_cmp_v.
apk_version_cmp() {
  if apk_version_cmp_v "$1" "$2"; then
    printf '%s' "$_APKV_CMP"
    return 0
  fi
  printf '?'
  return 1
}
