#!/usr/bin/env bash
# tests/lib/assert.sh - the assertion vocabulary.
#
# Every assertion states what it expected and what it got, because a test that
# only says "failed" costs more to debug than it saved to write.
#
# shellcheck shell=bash

T_PASS=0
T_FAIL=0
T_NAME=''

t_case() {
  T_NAME=$1
}

_t_ok() {
  T_PASS=$(( T_PASS + 1 ))
  printf '  ok   %s\n' "$1"
}

_t_no() {
  T_FAIL=$(( T_FAIL + 1 ))
  printf '  FAIL [%s] %s\n' "${T_NAME:-?}" "$1"
  shift
  local l
  for l in "$@"; do printf '         %s\n' "$l"; done
}

assert_eq() {
  local want=$1 got=$2 msg=$3
  if [[ $want == "$got" ]]; then
    _t_ok "$msg"
  else
    _t_no "$msg" "expected: [$want]" "actual:   [$got]"
  fi
}

assert_ne() {
  local a=$1 b=$2 msg=$3
  if [[ $a != "$b" ]]; then
    _t_ok "$msg"
  else
    _t_no "$msg" "both values are [$a] but they must differ"
  fi
}

assert_true() {
  if [[ $1 == 0 || $1 == true ]]; then _t_ok "$2"; else _t_no "$2" "condition was false ($1)"; fi
}

assert_contains() {
  local haystack=$1 needle=$2 msg=$3
  if [[ $haystack == *"$needle"* ]]; then
    _t_ok "$msg"
  else
    _t_no "$msg" "expected to contain: [$needle]" "in: [${haystack:0:400}]"
  fi
}

assert_not_contains() {
  local haystack=$1 needle=$2 msg=$3
  if [[ $haystack != *"$needle"* ]]; then
    _t_ok "$msg"
  else
    _t_no "$msg" "expected NOT to contain: [$needle]"
  fi
}

assert_file_exists() {
  if [[ -e $1 ]]; then _t_ok "$2"; else _t_no "$2" "no such path: $1"; fi
}

assert_file_absent() {
  if [[ ! -e $1 ]]; then _t_ok "$2"; else _t_no "$2" "path still exists: $1"; fi
}

# Runs a command in a subshell and asserts its exit status.
assert_status() {
  local want=$1
  shift
  local msg=$1
  shift
  local rc=0
  ( "$@" ) >/dev/null 2>&1 || rc=$?
  assert_eq "$want" "$rc" "$msg"
}

t_summary() {
  printf '\n%s: %s passed, %s failed\n' "$1" "$T_PASS" "$T_FAIL"
  (( T_FAIL == 0 ))
}
