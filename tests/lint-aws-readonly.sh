#!/usr/bin/env bash
# tests/lint-aws-readonly.sh - the read-only AWS lint, docs/FOUNDATION.md
# tension 23.
#
# It lints INVOCATIONS, not prose.  The §8.1 sketch - grep the live scripts for
# a mutating verb - fails on nearly every correct script, because `create`,
# `attach`, `authoriz` and `update` all appear in genuinely read-only operation
# names (`organizations describe-create-account-status`,
# `iam list-attached-role-policies`, `iam get-account-authorization-details`,
# `eks describe-update`) and in remediation strings and variable names.  A
# control that cries wolf is removed, and its removal looks like a cleanup
# commit.
#
# The four checks:
#   1. every `aws` invocation is via aws_ro;
#   2. the literal <operation> argument of each aws_ro call matches the frozen
#      read-only prefix allowlist;
#   3. an aws_ro call whose operation is a variable is permitted only when that
#      variable is assigned from a `readonly` array of literals declared in the
#      same file, and every literal in that array is checked;
#   4. tests/aws-readonly-allow.txt entries that no longer appear in the code
#      are a failure, so the exception list cannot rot into a blanket
#      permission.
#
# Comments, remediation strings and variable names are never examined, so the
# lint has no false positives by construction.
#
# STATUS AT §13 STEP 1: lib/awscli.sh and aws/live/ arrive at the start of §13
# step 6.  Nothing exists for this lint to examine yet, so it passes over an
# empty set - and says so, rather than reporting a green it did not earn.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell and AWS syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
cd "$ROOT"

READONLY_PREFIXES='^(describe|list|get|search|lookup|select|head|batch-get|preview|estimate|simulate)(-|$)'
ALLOW_FILE=tests/aws-readonly-allow.txt

FAILED=0
HITS=$SCOURSH_SCRATCH/aws-hits
report() {
  FAILED=1
  printf '%s\n' "$*" >&2
}

aws_files() {
  local dirs=() d
  for d in lib modules aws tools; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  find "${dirs[@]}" -type f -name '*.sh' | LC_ALL=C sort
}

files=$(aws_files)
if [[ -z $files ]]; then
  printf 'lint-aws-readonly: no shell files to examine\n'
fi

count=0
bare=0
calls=0

while IFS= read -r f; do
  [[ -n $f ]] || continue
  rel=${f#./}
  count=$(( count + 1 ))
  [[ $rel == lib/awscli.sh ]] && continue

  # Check 1: a bare `aws` at command position anywhere but the chokepoint.
  if scan_match "$HITS" -e '(^|[;&|(])[[:space:]]*aws[[:space:]]' -- "$rel"; then
    bare=1
    report "$rel: a bare 'aws' invocation; every AWS call goes through aws_ro in lib/awscli.sh"
    cat "$HITS" >&2
  fi

  # Checks 2 and 3: the operation argument of each aws_ro call.
  if scan_match "$HITS" -e 'aws_ro[[:space:]]' -- "$rel"; then
    while IFS= read -r hit; do
      [[ -n $hit ]] || continue
      calls=$(( calls + 1 ))
      # `aws_ro <service> <operation> ...` - take the second word after aws_ro.
      op=${hit#*aws_ro }
      op=${op#* }
      op=${op%% *}
      op=${op%\"}
      op=${op#\"}
      case $op in
        '$'*)
          # Check 3: a variable operation is permitted only from a readonly
          # array of literals declared in the same file.
          name=${op#\$}
          name=${name#\{}
          name=${name%%[\[\}]*}
          if ! scan_match "$SCOURSH_SCRATCH/aws-decl" \
            -e "readonly[[:space:]]+(-a[[:space:]]+)?$name=" -- "$rel"; then
            report "$rel: aws_ro operation '\$$name' is not assigned from a readonly array of literals in this file"
          fi
          ;;
        *)
          if [[ ! $op =~ $READONLY_PREFIXES ]]; then
            svc=${hit#*aws_ro }
            svc=${svc%% *}
            if [[ -f $ALLOW_FILE ]] && scan_match "$SCOURSH_SCRATCH/aws-allow" \
              -e "^${svc}[[:space:]]+${op}\$" -- "$ALLOW_FILE"; then
              : # covered by the reviewed exception file
            else
              report "$rel: aws_ro operation '$op' is not read-only and is not in $ALLOW_FILE"
            fi
          fi
          ;;
      esac
    done <"$HITS"
  fi
done <<<"$files"

# Check 4: an exception that no longer appears in the code would rot into a
# blanket permission.
if [[ -f $ALLOW_FILE ]]; then
  while IFS= read -r entry; do
    entry=${entry%%#*}
    [[ -n ${entry// /} ]] || continue
    svc=${entry%% *}
    op=${entry##* }
    seen=0
    while IFS= read -r f; do
      [[ -n $f ]] || continue
      if scan_match "$HITS" -e "aws_ro[[:space:]]+${svc}[[:space:]]+${op}" -- "${f#./}"; then
        seen=1
      fi
    done <<<"$files"
    (( seen )) || report "$ALLOW_FILE: '$svc $op' appears in no code and must be removed"
  done <"$ALLOW_FILE"
else
  printf '  --  %s absent; it is seeded at §13 step 6 with `sts assume-role`\n' "$ALLOW_FILE"
fi

printf '  --  examined %s shell files, %s aws_ro call sites\n' "$count" "$calls"
if (( bare == 0 && calls == 0 )); then
  printf '  --  lib/awscli.sh and aws/live/ arrive at §13 step 6; nothing to enforce yet\n'
fi

printf '\n'
if (( FAILED )); then
  printf 'lint-aws-readonly: FAILED\n'
  exit 1
fi
printf 'lint-aws-readonly: clean\n'
