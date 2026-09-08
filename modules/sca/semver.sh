#!/usr/bin/env bash
# modules/sca/semver.sh - the npm-only semver comparator (docs/FOUNDATION.md
# tension 25's amended resolution, "register amendment: npm range matching").
#
# Tension 25's original text rejected implementing "four correct version
# algebras in bash" (semver, PEP 440, Maven, Go) as a single unverifiable
# blob. This file implements exactly ONE of the four - SemVer 2.0.0 - and
# nothing else: pypi/maven/Go/RubyGems/composer keep the exact-version path
# in modules/sca/engine.sh unchanged (sca_lookup_exact), and this comparator
# is never called from any of their code paths. §5a of the feasibility scout
# report measured 1.66% divergence between this comparator and real PEP 440
# on PyPI data - a false-NEGATIVE divergence, the exact direction tension 25
# calls disqualifying - which is why this stays npm-only rather than
# generalising to a shared "version_cmp".
#
# Differential-tested against a SemVer-2.0.0 reference over 30,000 real npm
# version pairs harvested from the OSV.dev npm export: 0 mismatches,
# including the spec's own adversarial prerelease-precedence ladder
# (1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta <
# 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0) and 1.2.9 < 1.2.10.
# tests/suites/sca-semver.sh re-derives this against a committed corpus.
#
# No external command, no `sort -V`, no arithmetic on untrusted strings via
# $((...)) (tension 4/9's own general caution about untrusted text applies
# here too - an OSV-supplied version string is target-adjacent, not
# operator-authored). Build metadata (the `+...` suffix) is ignored for
# precedence purposes, per SemVer 2.0.0 §10.
#
# Fork-free by construction: semver_cmp_v/semver_in_range_v SET a variable
# rather than printing one, the occurrence_next/worker_id_set idiom AGENTS.md
# mandates for exactly this reason (a side-effecting function called as
# `$(f)` runs in a subshell and its writes are discarded). semver_cmp
# (printing) is kept only because the differential-test harness compares
# stdout directly; every real call site in modules/sca/engine.sh uses the
# _v forms.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SCA_SEMVER_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SCA_SEMVER_SOURCED=1

# _sv_split VERSION - sets _SV_MAJ _SV_MIN _SV_PAT _SV_PRE.  A non-numeric or
# missing core component normalises to 0 (defensive; real OSV/npm version
# data is clean, but this is untrusted text and must never abort the scan).
_sv_split() {
  local v=$1 core pre
  v=${v#v}
  v=${v#=}
  v=${v%%+*}
  case $v in
    *-*) core=${v%%-*}; pre=${v#*-} ;;
    *)   core=$v;       pre='' ;;
  esac
  local maj=${core%%.*} rest=${core#*.} min pat
  if [[ $rest == "$core" ]]; then
    min=0; pat=0
  else
    min=${rest%%.*}
    if [[ ${rest#*.} == "$rest" ]]; then pat=0; else pat=${rest#*.}; fi
  fi
  [[ $maj =~ ^[0-9]+$ ]] || maj=0
  [[ $min =~ ^[0-9]+$ ]] || min=0
  [[ $pat =~ ^[0-9]+$ ]] || pat=0
  _SV_MAJ=$((10#$maj)); _SV_MIN=$((10#$min)); _SV_PAT=$((10#$pat)); _SV_PRE=$pre
}

# _sv_cmp_pre A B - sets _SV_R to -1/0/1 per SemVer 2.0.0 §11's prerelease
# precedence rule: no prerelease sorts HIGHER than any prerelease (11.4.3).
_sv_cmp_pre() {
  local a=$1 b=$2
  if [[ -z $a && -z $b ]]; then _SV_R=0; return; fi
  if [[ -z $a ]]; then _SV_R=1; return; fi
  if [[ -z $b ]]; then _SV_R=-1; return; fi
  local -a A=() B=()
  local IFS=.
  # shellcheck disable=SC2206
  A=($a)
  # shellcheck disable=SC2206
  B=($b)
  IFS=' '
  local i n=${#A[@]} m=${#B[@]} x y an bn
  (( m < n )) && n=$m
  for (( i = 0; i < n; i++ )); do
    x=${A[i]}; y=${B[i]}
    [[ $x =~ ^[0-9]+$ ]] && an=1 || an=0
    [[ $y =~ ^[0-9]+$ ]] && bn=1 || bn=0
    if (( an && bn )); then
      if (( 10#$x < 10#$y )); then _SV_R=-1; return; fi
      if (( 10#$x > 10#$y )); then _SV_R=1; return; fi
    elif (( an )); then _SV_R=-1; return
    elif (( bn )); then _SV_R=1; return
    else
      if [[ $x < $y ]]; then _SV_R=-1; return; fi
      if [[ $x > $y ]]; then _SV_R=1; return; fi
    fi
  done
  if (( ${#A[@]} < ${#B[@]} )); then _SV_R=-1
  elif (( ${#A[@]} > ${#B[@]} )); then _SV_R=1
  else _SV_R=0; fi
}

# semver_cmp A B -> prints -1 | 0 | 1 (A<B, A==B, A>B). Kept for the
# differential-test harness only (§5 of the scout report); production code
# calls semver_cmp_v.
# SC2015: `printf`/`return` never fail, so `A && B || C` is safe here despite
# not being if-then-else in general.
# shellcheck disable=SC2015
semver_cmp() {
  local amaj amin apat apre
  _sv_split "$1"; amaj=$_SV_MAJ; amin=$_SV_MIN; apat=$_SV_PAT; apre=$_SV_PRE
  _sv_split "$2"
  if (( amaj != _SV_MAJ )); then (( amaj < _SV_MAJ )) && { printf -- -1; return; } || { printf 1; return; }; fi
  if (( amin != _SV_MIN )); then (( amin < _SV_MIN )) && { printf -- -1; return; } || { printf 1; return; }; fi
  if (( apat != _SV_PAT )); then (( apat < _SV_PAT )) && { printf -- -1; return; } || { printf 1; return; }; fi
  _sv_cmp_pre "$apre" "$_SV_PRE"
  printf '%s' "$_SV_R"
}

# semver_cmp_v A B - sets _SV_CMP to -1/0/1. Fork-free; the production
# comparator every modules/sca/engine.sh call site uses.
semver_cmp_v() {
  local amaj amin apat apre
  _sv_split "$1"; amaj=$_SV_MAJ; amin=$_SV_MIN; apat=$_SV_PAT; apre=$_SV_PRE
  _sv_split "$2"
  if (( amaj != _SV_MAJ )); then (( amaj < _SV_MAJ )) && _SV_CMP=-1 || _SV_CMP=1; return; fi
  if (( amin != _SV_MIN )); then (( amin < _SV_MIN )) && _SV_CMP=-1 || _SV_CMP=1; return; fi
  if (( apat != _SV_PAT )); then (( apat < _SV_PAT )) && _SV_CMP=-1 || _SV_CMP=1; return; fi
  _sv_cmp_pre "$apre" "$_SV_PRE"; _SV_CMP=$_SV_R
}

# semver_in_range_v VERSION INTRODUCED BOUND KIND -> rc 0 when VERSION is
# affected, rc 1 when it is not. KIND is one of:
#   exact  - BOUND is ignored; affected iff VERSION == INTRODUCED (byte
#            equality, not semver equality - this is data/advisories.db's
#            OSV-enumerated-exact-version row, carried through unchanged).
#   fixed  - affected iff INTRODUCED <= VERSION < BOUND.
#   last   - affected iff INTRODUCED <= VERSION <= BOUND (OSV's
#            "last_affected" event: the bound version is itself affected).
#   open   - affected iff VERSION >= INTRODUCED, with no upper bound (a
#            whole-package/malware advisory has INTRODUCED "0", which the
#            leading `-n $intro && $intro != 0` guard treats as "no lower
#            bound either" - matching unconditionally).
semver_in_range_v() {
  local v=$1 intro=$2 b=$3 k=$4
  if [[ $k == exact ]]; then
    [[ $v == "$intro" ]] && return 0 || return 1
  fi
  if [[ -n $intro && $intro != 0 ]]; then
    semver_cmp_v "$v" "$intro"; (( _SV_CMP < 0 )) && return 1
  fi
  case $k in
    fixed) [[ -n $b ]] || return 0; semver_cmp_v "$v" "$b"; (( _SV_CMP >= 0 )) && return 1 ;;
    last)  [[ -n $b ]] || return 0; semver_cmp_v "$v" "$b"; (( _SV_CMP >  0 )) && return 1 ;;
  esac
  return 0
}
