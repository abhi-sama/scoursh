#!/usr/bin/env bash
# modules/cloud/aws/regions.sh - single-account region iteration, and
# multi-account iteration via --assume-role
# (docs/DESIGN.md §8.1's `regions.sh` bullet; docs/STEP6-CLOUD-PLAN.md
# CLOUD-02, both halves).
#
# docs/DESIGN.md §8.1 states the requirement this file exists for:
#
#   "Most services are regional, so a truthful audit iterates every enabled
#    region (`account get-regions` / EC2 `describe-regions`), not just the
#    default."
#
# THE DEFAULT IS THEREFORE "EVERY ENABLED REGION", NOT "THE AMBIENT ONE", and
# that is the load-bearing decision in this file.  A scanner that quietly
# audited `AWS_REGION` alone and reported clean would be reporting clean for
# every region it never opened a connection to - the overstated coverage
# docs/DESIGN.md §15 forbids, and the exact failure shape lib/awscli.sh's own
# outcome vocabulary was added to close one layer down.  An operator who wants
# one region says so with `--regions`, and that narrowing is RECORDED.
#
# MULTI-ACCOUNT (docs/STEP6-CLOUD-PLAN.md D3's deferred half, this ticket).
# §8.1's own wording is "Optionally iterate accounts via --assume-role across
# an Org (read-only role in each)."  Section 5 below is that: the flag names
# ONE role ARN whose ACCOUNT segment is a TEMPLATE, rewritten per member
# account resolved from `organizations list-accounts` and assumed through the
# chokepoint's own `sts` `assume-role` operation.  SINGLE-ACCOUNT BEHAVIOUR (no
# --assume-role) IS COMPLETELY UNCHANGED - sections 1-4 below are untouched by
# this ticket, and `modules/cloud/aws/run.sh` reaches section 5 only when the
# operator passed the flag.
#
# A NOTE ON THIS FILE'S OWN COMMENTS, worth reading before writing another one:
# tests/lint-aws-readonly.sh has no comment awareness at all (the identical
# lesson `modules/iac/cloudformation.rules`'s own header already records for
# the pattern engine), so PROSE naming the chokepoint's function immediately
# followed by two literal words - the shape a real invocation of it takes - is
# matched as though it were one.  Measured while writing this section: writing
# that shape in a docstring turned this file's own comments into two of the
# lint's reported "call sites", each parsed into a bogus, punctuation-mangled
# operation name that was then reported as refused.  Describe the hazard; do
# not spell the invocation shape.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_REGIONS_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_REGIONS_SOURCED=1

# -x back-edge cut: modules/cloud/aws/engine.sh is already inlined elsewhere in
# every entry point that reaches this file, and shellcheck -x re-expands EVERY
# source edge it follows rather than memoising.  Cutting this one loses no
# checking and is what keeps the linter's hub sum bounded - see
# tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's "the memory model".
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/engine.sh"

# ---------------------------------------------------------------------------
# 1. Published state
# ---------------------------------------------------------------------------
# `cloud_regions_resolve` sets all four of these and nothing else reads AWS to
# answer the same question twice.
#
#   _CLOUD_REGIONS         the resolved region list, one per element
#   _CLOUD_REGIONS_SOURCE  how it was resolved (the vocabulary below)
#   _CLOUD_REGIONS_REASON  the machine-readable reason, empty on success
#   _CLOUD_REGIONS_DETAIL  a human sentence for the coverage record, empty on
#                          success
#
# The `source` vocabulary is frozen here so a reader of run.json never has to
# guess what produced the list:
#
#   flag        the operator named the regions explicitly (`--regions a,b`)
#   enumerated  read from the account itself (the default, and `--regions all`)
#   none        nothing resolved; `_CLOUD_REGIONS` is empty and the reason says
#               why.  This is a COVERAGE LOSS, never an empty success.
declare -ga _CLOUD_REGIONS=()
_CLOUD_REGIONS_SOURCE=none
_CLOUD_REGIONS_REASON=''
_CLOUD_REGIONS_DETAIL=''

# ---------------------------------------------------------------------------
# 2. Region-name validation
# ---------------------------------------------------------------------------
# `cloud_region_name_valid NAME` - the shape AWS actually uses for a region id:
# lowercase letters and digits in hyphen-separated groups, at least three of
# them (`us-east-1`, `ap-southeast-4`, `eu-central-1`, `us-gov-west-1`,
# `cn-north-1`).  Anchored at both ends.
#
# IT IS AN INPUT GUARD, NOT A CATALOG.  A hardcoded list of the regions that
# existed when this file was written would refuse every region AWS has opened
# since, which is a silent coverage loss on exactly the newest infrastructure -
# so the test is on the SHAPE.  What the shape does buy is real: `--regions`
# text reaches `aws_ro` as an argument and lands in a `run_record` line and in
# a coverage cell, so an unvalidated value could carry a newline and forge a
# second record, or carry a leading `-` and be read by the CLI as a flag.
cloud_region_name_valid() {
  [[ $1 =~ ^[a-z][a-z0-9]+(-[a-z0-9]+){2,}$ ]]
}

# ---------------------------------------------------------------------------
# 3. Enumeration
# ---------------------------------------------------------------------------
# `_cloud_regions_from_ec2 OUTFILE` - `ec2 describe-regions`, which by default
# returns the regions ENABLED for the calling account, and appends each
# `Regions[n].RegionName` to `_CLOUD_REGIONS`.
#
# `--all-regions` is deliberately NOT passed.  With it the response also
# carries every opt-in region the account has NOT enabled, and iterating those
# spends a real API call per service per region to collect an `OptInRequired`
# refusal that this module would then have to record as a coverage loss - a
# loss invented by the scanner rather than observed.  "Enabled" is the set
# §8.1 asks for.
_cloud_regions_from_ec2() {
  local out=$1 rc=0
  # THE CALL IS SPELLED DIRECTLY, WITH A PLAIN REDIRECT, RATHER THAN THROUGH
  # THE `aws_ro_into` WRAPPER - and never through a command substitution, which
  # `lib/awscli.sh`'s own header forbids at length (the outcome globals would be
  # set in a subshell that then exits).  The redirect is one of the two
  # spellings that header blesses, and it is the one chosen here for a reason
  # beyond taste: `tests/lint-aws-readonly.sh`'s checks 2 and 3 find a call site
  # by matching the chokepoint's name followed by whitespace, then read the
  # operation off the words after it - so the wrapper's own name, which has a
  # suffix where that whitespace would be, is invisible to them.  Measured: the
  # lint reported zero call sites against this very file while it made two.
  # Nothing is UNSAFE about the wrapper (it reaches the chokepoint, which
  # enforces the read-only prefix at RUNTIME - tension 23's stated reason for
  # putting the guarantee there rather than in the lint), but a call site the
  # lint cannot see is a call site nobody is checking statically.  Teaching the
  # lint about the two wrappers belongs to CLOUD-03, the ticket that owns that
  # file; until then this module spells its calls the way the lint reads them.
  #
  # A SECOND HAZARD, MEASURED HERE THE EXPENSIVE WAY: that lint has no comment
  # awareness whatsoever, so prose in THIS block that spelled the chokepoint's
  # name followed by a space was itself matched as a call site, and the lint
  # failed on three "operations" it had read out of an English sentence.  It is
  # the identical lesson `modules/iac/cloudformation.rules` already records for
  # the pattern engine: describe the hazard, do not spell it.
  aws_ro ec2 describe-regions >"$out" || rc=$?
  (( rc == 0 )) || return 1
  local path type val name
  while IFS=$'\t' read -r path type val; do
    # The STRUCTURAL path, never a substring match on the response bytes: a
    # region name reached any other way (a tag value, an ARN inside an
    # unrelated field) is response CONTENT and is not a region this account has
    # enabled.  `cloud_json_flatten` joins path segments with US (0x1f), so
    # `Regions<US>0<US>RegionName` is the leaf wanted and nothing a string's
    # own contents can ever become.
    [[ $type == s ]] || continue
    [[ $path == Regions$'\x1f'*$'\x1f'RegionName ]] || continue
    name=$(cloud_json_unescape "$val")
    cloud_region_name_valid "$name" || continue
    _CLOUD_REGIONS+=("$name")
  done < <(cloud_json_flatten <"$out")
  (( ${#_CLOUD_REGIONS[@]} > 0 ))
}

# `_cloud_regions_from_account OUTFILE` - the FALLBACK §8.1 names first,
# `account list-regions`, filtered to the two statuses that mean "this account
# can use it".
#
# WHY IT IS THE FALLBACK AND NOT THE PRIMARY, even though §8.1's prose lists it
# first: `ec2:DescribeRegions` is in every read-only managed policy an operator
# is likely to be running under (`SecurityAudit`, `ViewOnlyAccess`,
# `ReadOnlyAccess`), while `account:ListRegions` is a newer, separately-granted
# permission that a long-standing read-only role frequently lacks.  Leading
# with the one more likely to be denied would make the ordinary run pay an
# AccessDenied before succeeding.  Trying it second is still worth the call:
# an account whose ec2 read is denied but whose account read is not would
# otherwise resolve no regions at all.
_cloud_regions_from_account() {
  local out=$1 rc=0
  # The direct-redirect spelling, for the reason `_cloud_regions_from_ec2`
  # above records at length: `tests/lint-aws-readonly.sh` cannot see a call
  # made through either wrapper.
  aws_ro account list-regions \
    --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT >"$out" || rc=$?
  (( rc == 0 )) || return 1
  local path type val name
  while IFS=$'\t' read -r path type val; do
    [[ $type == s ]] || continue
    [[ $path == Regions$'\x1f'*$'\x1f'RegionName ]] || continue
    name=$(cloud_json_unescape "$val")
    cloud_region_name_valid "$name" || continue
    _CLOUD_REGIONS+=("$name")
  done < <(cloud_json_flatten <"$out")
  (( ${#_CLOUD_REGIONS[@]} > 0 ))
}

# `_cloud_regions_note_truncation OUTCOME OPERATION` - a SUCCESSFUL enumeration
# whose outcome is `truncated` produced a SHORT region list, and a short list
# read as a complete one is this module's worst failure: every region the
# scanner never learned about is then reported neither clean nor uncovered, it
# is simply absent from the run.  lib/awscli.sh returns 0 for `truncated`
# because the data it did return is valid, so the status alone cannot carry
# this - the outcome has to be read.  The regions that WERE resolved are kept
# and used (a partial audit beats none); what changes is that the caller now
# has a non-empty `_CLOUD_REGIONS_REASON` to record.
_cloud_regions_note_truncation() {
  local outcome=$1 op=$2
  [[ $outcome == truncated ]] || return 0
  aws_ro_reduction_reason_set _CLOUD_REGIONS_REASON "$outcome"
  _CLOUD_REGIONS_DETAIL="'$op' returned a TRUNCATED response, so the ${#_CLOUD_REGIONS[@]} region(s) resolved are an incomplete list of this account's enabled regions - any region missing from it was not scanned and is not reported on either way"
  return 0
}

# ---------------------------------------------------------------------------
# 4. cloud_regions_resolve
# ---------------------------------------------------------------------------
# `cloud_regions_resolve [--regions VALUE]` - fills the four published globals
# above.  Returns 0 when at least one region resolved, 1 otherwise; a caller
# reads `_CLOUD_REGIONS_REASON` on the 1 and owes a `coverage_reduction`.
#
# A SETTER, NEVER CALLED THROUGH `$(...)`: `aws_ro` inside it sets the
# lib/awscli.sh outcome globals (`SCOURSH_AWS_RO_OUTCOME` and friends), and a
# command substitution would set them in a subshell that then exits - so the
# caller would read the values from before the call and an `access_denied`
# would present as an empty region list with an untouched outcome.  That is
# precisely the honesty gap lib/awscli.sh section 2 exists to close,
# reintroduced by the calling convention; its own `aws_ro_into` header states
# the same rule.
#
# AN EXPLICIT `--regions` LIST IS NOT VALIDATED AGAINST THE ACCOUNT, and that
# is a decision rather than an oversight.  Checking it would cost an
# enumeration call the operator's own narrowing was meant to avoid, and would
# refuse a region that is genuinely enabled but that `ec2 describe-regions` was
# denied on - turning a permission gap into a refusal of the operator's stated
# intent.  A region name that is not enabled simply produces per-service
# `region_not_enabled` outcomes, which lib/awscli.sh already classifies and
# which a service script records as the coverage loss it is.  The names are
# still SHAPE-validated (section 2), because they reach an argv and a run
# record.
cloud_regions_resolve() {
  local want=''
  while (( $# > 0 )); do
    case $1 in
      --regions) want=${2:-}; shift 2 ;;
      *) shift ;;
    esac
  done

  _CLOUD_REGIONS=()
  _CLOUD_REGIONS_SOURCE=none
  _CLOUD_REGIONS_REASON=''
  _CLOUD_REGIONS_DETAIL=''

  if [[ -n $want && $want != all ]]; then
    local part
    # `read -a` with an explicit IFS rather than an unquoted `for part in
    # $want`: splitting on commas is wanted, PATHNAME EXPANSION is not, and an
    # unquoted expansion is one switch for both (AGENTS.md's
    # `markup_tokens_have` lesson - a `--regions '*'` would otherwise expand
    # against the scanner's own cwd).
    local -a parts=()
    IFS=',' read -r -a parts <<<"$want"
    for part in "${parts[@]+"${parts[@]}"}"; do
      [[ -n $part ]] || continue
      if ! cloud_region_name_valid "$part"; then
        _CLOUD_REGIONS=()
        _CLOUD_REGIONS_REASON=regions_flag_malformed
        _CLOUD_REGIONS_DETAIL="--regions named '$part', which is not an AWS region id (expected a shape like us-east-1)"
        return 1
      fi
      _CLOUD_REGIONS+=("$part")
    done
    if (( ${#_CLOUD_REGIONS[@]} == 0 )); then
      _CLOUD_REGIONS_REASON=regions_flag_empty
      _CLOUD_REGIONS_DETAIL='--regions was given with no region names in it'
      return 1
    fi
    _CLOUD_REGIONS_SOURCE=flag
    return 0
  fi

  # Enumerate.  `mktemp` rather than a name built from `$$`/`$BASHPID`: every
  # scratch path here is spelled `${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/...`, and
  # a pid-derived name is one a local user can predict and pre-create as a
  # symlink that this process then writes THROUGH (CWE-377 via CWE-59) - the
  # defect DAST-08 shipped and corrected, recorded in AGENTS.md.
  local tmp rc_ec2=0 rc_acct=0 ec2_outcome='' acct_outcome=''
  tmp=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-regions.XXXXXX")
  chmod 600 -- "$tmp" 2>/dev/null || true

  _cloud_regions_from_ec2 "$tmp" || rc_ec2=$?
  ec2_outcome=${SCOURSH_AWS_RO_OUTCOME:-error}
  if (( rc_ec2 == 0 )); then
    rm -f -- "$tmp"
    _CLOUD_REGIONS_SOURCE=enumerated
    _cloud_regions_note_truncation "$ec2_outcome" 'ec2 describe-regions'
    return 0
  fi

  _CLOUD_REGIONS=()
  _cloud_regions_from_account "$tmp" || rc_acct=$?
  acct_outcome=${SCOURSH_AWS_RO_OUTCOME:-error}
  rm -f -- "$tmp"
  if (( rc_acct == 0 )); then
    _CLOUD_REGIONS_SOURCE=enumerated
    _cloud_regions_note_truncation "$acct_outcome" 'account list-regions'
    return 0
  fi

  _CLOUD_REGIONS=()
  # The reason carries lib/awscli.sh's OWN classification of the FIRST attempt,
  # through its own `aws_ro_reduction_reason_set`, rather than a string minted
  # here: a second vocabulary for the same failure is a second thing to keep in
  # step, and this one is already the machine-readable half a caller records.
  # Both outcomes are named in the detail, because "ec2 was denied and account
  # was denied" and "ec2 was denied and account does not exist in this
  # partition" are different facts about what to fix.
  aws_ro_reduction_reason_set _CLOUD_REGIONS_REASON "$ec2_outcome"
  _CLOUD_REGIONS_DETAIL="no region could be enumerated: 'ec2 describe-regions' returned $ec2_outcome and the 'account list-regions' fallback returned $acct_outcome"
  return 1
}

# ---------------------------------------------------------------------------
# 5. Multi-account iteration via --assume-role (docs/STEP6-CLOUD-PLAN.md D3's
#    deferred half, CLOUD-02 remainder)
# ---------------------------------------------------------------------------
# Published state, the account-list analogue of section 1's region globals:
#
#   _CLOUD_ORG_ACCOUNTS         ACTIVE member account ids, LC_ALL=C sorted and
#                                de-duplicated
#   _CLOUD_ORG_ACCOUNTS_REASON  the machine-readable reason, empty on success
#   _CLOUD_ORG_ACCOUNTS_DETAIL  a human sentence for the coverage record
declare -ga _CLOUD_ORG_ACCOUNTS=()
_CLOUD_ORG_ACCOUNTS_REASON=''
_CLOUD_ORG_ACCOUNTS_DETAIL=''

# `cloud_assume_role_arn_for VARNAME ACCOUNT_ID TEMPLATE_ARN` - rewrites the
# account-id field of TEMPLATE_ARN to ACCOUNT_ID, keeping the partition and
# the role path/name unchanged.  A SETTER, for the reason `cloud_json_leaf`'s
# own header gives one file up: a caller composing this straight into
# `aws_ro sts assume-role --role-arn "$(...)"` would be one edit away from the
# subshell hazard the whole module is written against.
#
# ARN shape for an IAM role: `arn:PARTITION:iam::ACCOUNT:role/PATH` - IAM ARNs
# carry no region field, so splitting on ':' gives exactly SIX parts and the
# fifth is the account.  A role name cannot itself contain ':' (IAM constrains
# it to `[\w+=,.@-]`), so the sixth part (the resource) is never split
# further.  scan.sh's own `assume-role) [[ $val == arn:*:role/* ]]` shape
# check is looser than this - it admits a string that matches that glob but
# splits into fewer than six colon-parts (e.g. `arn:aws:role/x`, missing the
# empty service/region fields) - so THIS is the stricter check that actually
# gates whether the template can be used, and a caller must check the return
# status rather than trust scan.sh's parse-time validation alone.
cloud_assume_role_arn_for() {
  local __var=$1 __account=$2 __template=$3
  local -a __parts=()
  IFS=':' read -r -a __parts <<<"$__template"
  if (( ${#__parts[@]} != 6 )); then
    printf -v "$__var" '%s' ''
    return 1
  fi
  printf -v "$__var" '%s:%s:%s:%s:%s:%s' \
    "${__parts[0]}" "${__parts[1]}" "${__parts[2]}" "${__parts[3]}" "$__account" "${__parts[5]}"
}

# `_cloud_org_accounts_note_truncation OUTCOME` - the account-list analogue of
# `_cloud_regions_note_truncation`: a SUCCESSFUL enumeration whose outcome is
# `truncated` produced a SHORT account list, and the accounts that WERE
# resolved are kept and used (a partial audit beats none) while the caller
# gets a non-empty `_CLOUD_ORG_ACCOUNTS_REASON` to record.
_cloud_org_accounts_note_truncation() {
  local outcome=$1
  [[ $outcome == truncated ]] || return 0
  aws_ro_reduction_reason_set _CLOUD_ORG_ACCOUNTS_REASON "$outcome"
  _CLOUD_ORG_ACCOUNTS_DETAIL="'organizations list-accounts' returned a TRUNCATED response, so the account list resolved is an incomplete list of this organization's member accounts - any account missing from it was not scanned and is not reported on either way"
  return 0
}

# `cloud_org_accounts_resolve` - `organizations list-accounts`, kept to ACTIVE
# accounts only.  A SUSPENDED or PENDING_CLOSURE account is not scannable (its
# APIs refuse outright), so admitting one here would spend an assume-role call
# per account just to collect a refusal this function already knows is
# coming - the identical "a loss invented by the scanner rather than observed"
# reasoning `_cloud_regions_from_ec2`'s own header gives for `--all-regions`.
#
# `--starting-token` (never `--next-token`): `aws_ro_paged`'s own header draws
# the line on which flag a caller passes - `--starting-token` for an operation
# the CLI has a REGISTERED PAGINATOR for, and `organizations list-accounts` is
# one of the ordinary `NextToken`-shaped list operations every AWS CLI release
# has paginated automatically since Organizations first shipped a CLI surface;
# passing the raw `--next-token` to a paginated command is rejected by the CLI
# itself as an unrecognised argument.
#
# EACH PAGE'S ARRAY INDICES ARE READ, ACCUMULATED AND FLUSHED WITHIN THAT
# PAGE, NEVER ACROSS PAGES.  `cloud_json_flatten`'s path for account N of a
# page is `Accounts<US>N<US>Id` - N restarts at 0 on every page, so combining
# two pages' `Id`/`Status` maps in one associative array keyed on N alone
# would let page 2's account 0 silently overwrite page 1's account 0 in the
# map, DROPPING page 1's account entirely rather than merely mis-labelling it.
# Flushing to `_CLOUD_ORG_ACCOUNTS` before moving to the next page's `local -A`
# (which re-executes and clears both maps each loop iteration) avoids the
# collision by construction rather than by namespacing the key.
cloud_org_accounts_resolve() {
  _CLOUD_ORG_ACCOUNTS=()
  _CLOUD_ORG_ACCOUNTS_REASON=''
  _CLOUD_ORG_ACCOUNTS_DETAIL=''

  local dir rc=0
  dir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-org-accounts.XXXXXX")
  aws_ro_paged "$dir" --starting-token organizations list-accounts || rc=$?
  local outcome=${SCOURSH_AWS_RO_OUTCOME:-error}
  if (( rc != 0 )); then
    rm -rf -- "$dir"
    aws_ro_reduction_reason_set _CLOUD_ORG_ACCOUNTS_REASON "$outcome"
    _CLOUD_ORG_ACCOUNTS_DETAIL="'organizations list-accounts' returned $outcome, so no member account could be enumerated"
    return 1
  fi
  _cloud_org_accounts_note_truncation "$outcome"

  local page path type val idx acct
  local -a raw=()
  for page in "$dir"/page-*.json; do
    [[ -f $page ]] || continue
    local -A id_by_idx=() status_by_idx=()
    while IFS=$'\t' read -r path type val; do
      [[ $type == s ]] || continue
      case $path in
        Accounts$'\x1f'*$'\x1f'Id)
          idx=${path#Accounts$'\x1f'}; idx=${idx%%$'\x1f'*}
          id_by_idx[$idx]=$(cloud_json_unescape "$val")
          ;;
        Accounts$'\x1f'*$'\x1f'Status)
          idx=${path#Accounts$'\x1f'}; idx=${idx%%$'\x1f'*}
          status_by_idx[$idx]=$(cloud_json_unescape "$val")
          ;;
        *) continue ;;
      esac
    done < <(cloud_json_flatten <"$page")
    for idx in "${!id_by_idx[@]}"; do
      [[ ${status_by_idx[$idx]:-} == ACTIVE ]] || continue
      acct=${id_by_idx[$idx]}
      [[ $acct =~ ^[0-9]{12}$ ]] || continue
      raw+=("$acct")
    done
  done
  rm -rf -- "$dir"

  if (( ${#raw[@]} > 0 )); then
    # LC_ALL=C sort -u: a fixed, reproducible order (the same reason
    # `docs/INVENTORY-FORMAT.md`'s own consumers sort - tension 5's finding
    # `occurrence` ordinal and this run's own `checks_run` order both derive
    # from visitation order) and de-duplicated, since one account CAN appear
    # on two pages of a response observed mid-pagination-boundary-shift.
    while IFS= read -r acct; do
      [[ -n $acct ]] && _CLOUD_ORG_ACCOUNTS+=("$acct")
    done < <(printf '%s\n' "${raw[@]}" | LC_ALL=C sort -u)
  fi

  if (( ${#_CLOUD_ORG_ACCOUNTS[@]} == 0 )); then
    _CLOUD_ORG_ACCOUNTS_REASON=org_no_active_accounts
    _CLOUD_ORG_ACCOUNTS_DETAIL="'organizations list-accounts' returned no ACTIVE account"
    return 1
  fi
  return 0
}

# `cloud_assume_role ACCOUNT_ID TEMPLATE_ARN` - assumes the read-only role in
# ACCOUNT_ID (built from TEMPLATE_ARN via `cloud_assume_role_arn_for`) and
# makes the resulting session credentials AMBIENT for every `aws_ro` call that
# follows, through lib/awscli.sh's own `aws_ro_use_credentials` - the
# multi-account analogue of `aws_ro_use_profile`/`aws_ro_use_region`.
#
# THE CALL SITE IS SPELLED DIRECTLY (`aws_ro sts assume-role ...`), never
# through a variable or a wrapper, for the identical reason
# `_cloud_regions_from_ec2`'s own header gives at length: tests/lint-aws-readonly.sh
# reads the literal operation word following the chokepoint's function and its
# service argument.  `sts assume-role` is the one operation in this file that
# is NOT covered by the frozen read-only prefix - it needs its own
# tests/aws-readonly-allow.txt entry (tension 23 item 4), which this ticket is
# the one that seeds.
#
# A SETTER, for the by-now-standard reason: `aws_ro` sets lib/awscli.sh's
# outcome globals, and a `$(...)` around this call would set them in a
# subshell that then exits, reintroducing the exact honesty gap
# `aws_ro_account_id_set`'s own header is written against.
cloud_assume_role() {
  local __account=$1 __template=$2
  local __role_arn=''
  if ! cloud_assume_role_arn_for __role_arn "$__account" "$__template"; then
    _CLOUD_ORG_ACCOUNTS_REASON=cli_usage
    _CLOUD_ORG_ACCOUNTS_DETAIL="--assume-role '$__template' does not split into the six ':'-separated fields an IAM role ARN has, so no role ARN could be built for account $__account"
    return 1
  fi

  local __out __rc=0
  __out=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-assume.XXXXXX")
  chmod 600 -- "$__out" 2>/dev/null || true
  aws_ro sts assume-role --role-arn "$__role_arn" \
    --role-session-name "scoursh-scan-$$" >"$__out" || __rc=$?
  local __outcome=${SCOURSH_AWS_RO_OUTCOME:-error}
  if (( __rc != 0 )); then
    rm -f -- "$__out"
    aws_ro_reduction_reason_set _CLOUD_ORG_ACCOUNTS_REASON "$__outcome"
    _CLOUD_ORG_ACCOUNTS_DETAIL="'sts assume-role' for account $__account ($__role_arn) returned $__outcome"
    return 1
  fi

  local __akid='' __secret='' __token=''
  cloud_json_leaf __akid "$__out" $'Credentials\x1fAccessKeyId'
  cloud_json_leaf __secret "$__out" $'Credentials\x1fSecretAccessKey'
  cloud_json_leaf __token "$__out" $'Credentials\x1fSessionToken'
  rm -f -- "$__out"
  if [[ -z $__akid || -z $__secret || -z $__token ]]; then
    _CLOUD_ORG_ACCOUNTS_REASON=error
    _CLOUD_ORG_ACCOUNTS_DETAIL="'sts assume-role' for account $__account returned a 200 whose body carried no usable Credentials"
    return 1
  fi
  aws_ro_use_credentials "$__akid" "$__secret" "$__token"

  # lib/awscli.sh's response cache is keyed in part on SCOURSH_AWS_ACCOUNT_ID,
  # which at this point still holds the CALLER's id (or is empty) - not the
  # account just assumed into.  Leaving it stale would let two DIFFERENT
  # accounts' identical (service, region, operation, args) calls collide on
  # one cache entry: `ec2 describe-regions` takes no arguments at all and is
  # called for every account in the sweep, so this is a measured hazard, not
  # a hypothetical one.  `aws_ro_identity_forget` clears the memoisation AND
  # the cache, which is what forces the re-resolve below to be a REAL API
  # call rather than the memoised early return `aws_ro_account_id_set`
  # otherwise takes - and confirming the resolved identity also catches a
  # trust policy that assumed cleanly but landed somewhere other than the
  # account this function built the role ARN for.
  aws_ro_identity_forget
  local __resolved='' __idrc=0
  aws_ro_account_id_set __resolved || __idrc=$?
  if (( __idrc != 0 )) || [[ $__resolved != "$__account" ]]; then
    local __idoutcome=${SCOURSH_AWS_RO_OUTCOME:-error}
    aws_ro_use_credentials
    aws_ro_identity_forget
    aws_ro_reduction_reason_set _CLOUD_ORG_ACCOUNTS_REASON "$__idoutcome"
    _CLOUD_ORG_ACCOUNTS_DETAIL="the assumed session for account $__account resolved to '${__resolved:-no identity ($__idoutcome)}' via sts get-caller-identity, not the requested account - refusing to scan under a session that does not match"
    return 1
  fi
  return 0
}

# `cloud_assume_role_clear` - drop the ambient assumed-role session and the
# identity it resolved, back to whatever ambient (--profile/environment)
# credentials the CALLER holds.  `modules/cloud/aws/run.sh`'s multi-account
# loop calls this BEFORE every `cloud_assume_role` attempt, not only after
# one - a role-ARN template that fails to build (`cloud_assume_role_arn_for`)
# or an assume that fails before `aws_ro_use_credentials` is ever reached
# would otherwise leave the PREVIOUS account's session ambient for whatever
# `cloud_assume_role` call comes next, and a role assumed into one account
# routinely cannot itself assume a role in a different one - so every attempt
# starts from a clean, known state rather than depending on how the previous
# one failed.  It is also called once after the whole sweep, so nothing after
# the loop ever runs under a stale assumed session.
#
# Both halves are required: `aws_ro_use_credentials` with no arguments clears
# the session credentials themselves, and `aws_ro_identity_forget` clears the
# memoised account id AND the response cache - lib/awscli.sh's own header
# explains why the cache half is load-bearing rather than tidiness (a `sts
# get-caller-identity` under the new principal hashes identically to the old
# one's cache key and would otherwise be served the previous account's cached
# identity straight back).
cloud_assume_role_clear() {
  aws_ro_use_credentials
  aws_ro_identity_forget
  return 0
}
