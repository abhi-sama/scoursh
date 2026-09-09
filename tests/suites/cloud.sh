#!/usr/bin/env bash
# tests/suites/cloud.sh - modules/cloud/aws/: the `scan_dispatch cloud` entry
# point, the D1 authorization model, single-account region iteration, and the
# honesty records a run that ships no service script owes its reader
# (docs/STEP6-CLOUD-PLAN.md P3, docs/DESIGN.md §8, §13 step 6).
#
# The five things this suite exists to pin, because each has a plausible wrong
# reading that would ship silently:
#
#   1. A run with NO service script scans nothing and SAYS SO.  A cloud scan
#      under a least-privilege role fails invisibly - an empty result and a
#      denied result render identically - so the assertions are made on
#      run.json and on the report, the surfaces a consumer actually reads,
#      never only on an internal record.
#   2. THE AUTHORIZATION MODEL IS OPTIONAL BUT NOT INERT.  `--i-own-account`
#      is refused (exit 2) on a mismatch and accepted on a match; a mechanism
#      that only ever returns 0 passes every "it did not refuse" assertion ever
#      written, so both directions are pinned.
#   3. `--assume-role` REFUSES rather than being ignored (D3, single-account
#      only).  The failing reading here is exit 0 with a one-account scan, which
#      reads as a complete multi-account audit.
#   4. `--profile` REACHES THE CLI.  It has been parsed since step 2 and read by
#      nothing; the assertion is on the stub's own recorded ARGV, never on the
#      run record, because a run that merely BELIEVES it used a profile is
#      exactly what the pre-fix code produced.
#   5. UNRESOLVABLE CREDENTIALS ARE EXIT 4 ON `cloud` AND EXIT 0 ON `all`
#      (docs/FOUNDATION.md tension 14's per-module required-inputs table, both
#      rows).  The naive fix for each direction is the other's bug, so both are
#      asserted.
#
# NO NETWORK AND NO AWS ACCOUNT.  Every case runs against a routed stub `aws`
# written by this file, which serves a canned response per (service,
# operation) and appends its own ARGV to a log.  tests/lib/aws-fixtures.sh's
# harness is deliberately NOT reused: its stub serves ONE canned response for
# every call regardless of service or operation, and this module's very first
# action is two DIFFERENT calls in one run (`sts get-caller-identity` then `ec2
# describe-regions`), which that stub cannot express.  A routed replacement for
# it is its own ticket (P2 in docs/STEP6-CLOUD-PLAN.md's own dispatch plan);
# this local stub is deliberately minimal so that ticket is not pre-empted.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a stub root can never leak into the next
#   case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/cloud/aws/regions.sh sources
# modules/cloud/aws/engine.sh, which is therefore already inlined in this
# file's own source graph, and shellcheck re-expands EVERY source edge it
# follows.  Cutting this one loses no checking and is what keeps the linter's
# memory bounded - see the shellcheck stage in tests/run-tests.sh, and
# docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/regions.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh resolves every loaded file's
# path via realpath and strips $SCOURSH_INSTALL_ROOT as a literal prefix, so a
# fixture root reached through macOS's /var -> /private/var $TMPDIR symlink
# would make the strip fail (see tests/suites/dast.sh, which documents the
# same fact).
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# The routed stub `aws`.
# ---------------------------------------------------------------------------
# Routes on `(service, operation)` and appends its whole ARGV, one line per
# call, to $AWS_STUB_LOG.  A missing response file is a REFUSAL with a
# realistic AWS error shape rather than an empty success, so a case that
# forgets to provide one fails loudly instead of silently exercising the
# "clean account" path this whole module exists to distinguish from a real one.
STUBDIR=$W/stub
mkdir -p "$STUBDIR/bin" "$STUBDIR/resp"
cat >"$STUBDIR/bin/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  printf 'aws-cli/2.15.0 Python/3.11.6 Darwin/24.0.0 exe/x86_64.stub\n'
  exit 0
fi
svc=$1
op=$2
[[ -n ${AWS_STUB_LOG:-} ]] && printf '%s\n' "$*" >>"$AWS_STUB_LOG"
f=$AWS_STUB_DIR/$svc.$op.json
if [[ -r $f ]]; then
  cat -- "$f"
  exit 0
fi
if [[ -r $AWS_STUB_DIR/$svc.$op.err ]]; then
  cat -- "$AWS_STUB_DIR/$svc.$op.err" >&2
  exit 254
fi
printf 'An error occurred (AccessDenied) when calling the %s operation: stub has no response for %s %s\n' \
  "$op" "$svc" "$op" >&2
exit 254
STUB
chmod +x "$STUBDIR/bin/aws"

# A pretty-printed body, exactly as the real CLI's `--output json` produces
# one.  THE LINE SHAPE IS LOad-BEARING and a compact one-line body is the wrong
# fixture: lib/awscli.sh's `aws_ro_account_id_set` reads the identity document
# LINE BY LINE, matching a trimmed line that STARTS with the quoted key, so a
# single-line document yields "returned no Account field" - a real property of
# the reader that a compact fixture would hide, measured while writing this
# suite.
cat >"$STUBDIR/resp/sts.get-caller-identity.json" <<'J'
{
    "UserId": "AIDAEXAMPLEFIXTURE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/scoursh-fixture"
}
J
cat >"$STUBDIR/resp/ec2.describe-regions.json" <<'J'
{
    "Regions": [
        {
            "Endpoint": "ec2.eu-west-2.amazonaws.com",
            "RegionName": "eu-west-2",
            "OptInStatus": "opt-in-not-required"
        },
        {
            "Endpoint": "ec2.us-east-1.amazonaws.com",
            "RegionName": "us-east-1",
            "OptInStatus": "opt-in-not-required"
        }
    ]
}
J

# A second stub whose every call fails the way a machine with no credentials
# fails - no error CODE at all, only the CLI's own message, which is the shape
# lib/awscli.sh classifies as `no_credentials` off the message rather than a
# code.
NOCRED=$W/nocred/bin
mkdir -p "$NOCRED"
cat >"$NOCRED/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  printf 'aws-cli/2.15.0 Python/3.11.6 Darwin/24.0.0 exe/x86_64.stub\n'
  exit 0
fi
# Logs its ARGV like the routed stub does, so "it stopped after ONE failed
# call" is a MEASUREMENT of what was attempted rather than an inference from a
# return value - a module that swept all thirty services against dead
# credentials and then returned the same status would satisfy any assertion
# made on the status alone.
[[ -n ${AWS_STUB_LOG:-} ]] && printf '%s\n' "$*" >>"$AWS_STUB_LOG"
printf 'Unable to locate credentials. You can configure credentials by running "aws configure".\n' >&2
exit 253
STUB
chmod +x "$NOCRED/aws"

# `_run_cloud OUTDIR LOGFILE STUBBIN -- ARGS...` - one real `scan.sh`
# subprocess.  A real subprocess, not a sourced call, for the reason
# tests/suites/dast.sh gives for its own: the CLI parser, the dispatch arm and
# the exit-code precedence table are three separate mechanisms this suite is
# asserting the interaction of, and only a subprocess exercises all three.
# Sets `_RC` rather than returning, so a non-zero status never trips the
# suite's own `set -e`.
#
# EACH INVOCATION GETS ITS OWN `SCOURSH_AWS_CACHE_DIR`, AND WITHOUT THAT THIS
# SUITE TESTS THE WRONG THING.  `SCOURSH_SCRATCH` is EXPORTED (lib/core.sh,
# deliberately, so `xargs -P` workers share their parent's), and
# lib/awscli.sh's response cache defaults to `$SCOURSH_SCRATCH/awscache` - so
# every `scan.sh` subprocess this suite starts inherits ONE cache directory
# from the suite process.  Its key is `sha256(service|region|account|op|args)`,
# which is BYTE-IDENTICAL for `sts get-caller-identity` across two cases whose
# stub `aws` differs, so the no-credentials case was served the working stub's
# cached identity and reported a healthy account under a binary that cannot
# resolve one.  Measured here: exit 0 where the contract says 4, with the
# credential-failure branch never entered at all.  That is not a defect in the
# cache - in a real run two identical calls genuinely do have one answer, which
# is the whole point of tension 16 - it is a property of a harness whose
# response varies under a fixed key, and it is the same hazard
# tests/lib/aws-fixtures.sh's own `aws_fixture_response_set` header records
# from the other side.
_run_cloud() {
  local out=$1 log=$2 bin=$3
  shift 4   # drop the literal `--`
  _RC=0
  rm -rf "$out"
  : >"$log"
  AWS_STUB_DIR=$STUBDIR/resp AWS_STUB_LOG=$log PATH="$bin:$PATH" \
    SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") \
    bash "$ROOT/scan.sh" "$@" --out "$out" >"$out.stdout" 2>&1 || _RC=$?
  return 0
}

_json_at() {
  python3 - "$1" "$2" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cur = doc
for part in sys.argv[2].split('.'):
    if part.isdigit() and isinstance(cur, list):
        cur = cur[int(part)]
    else:
        cur = cur.get(part) if isinstance(cur, dict) else None
    if cur is None:
        break
# Compact separators, so an assertion can spell the expected JSON the way it
# reads rather than having to reproduce json.dumps' default spacing.
print('' if cur is None else (json.dumps(cur, separators=(',', ':')) if isinstance(cur, (list, dict)) else cur))
PY
}

# ===========================================================================
# A. The pure engine - the service table, the cell and the JSON reader.
# ===========================================================================
t_case 'A. engine'

assert_true "$( (( ${#_CLOUD_SERVICES[@]} > 0 )) && echo 0 || echo 1 )" \
  '_CLOUD_SERVICES is non-empty'

# Every row is `<script>:<global|regional>`.  A row with a third scope word, or
# with none, would be silently skipped by run.sh's walk (it matches neither
# arm), so the service would never run and nothing would say so - the exact
# silent-coverage-loss shape this module is written against.
_bad_scope=''
_bad_path=''
for _spec in "${_CLOUD_SERVICES[@]}"; do
  case ${_spec##*:} in
    global | regional) ;;
    *) _bad_scope+="$_spec " ;;
  esac
  [[ ${_spec%%:*} == live/*.sh ]] || _bad_path+="$_spec "
done
assert_eq '' "$_bad_scope" 'every _CLOUD_SERVICES row declares global or regional'
assert_eq '' "$_bad_path" 'every _CLOUD_SERVICES row names a live/<service>.sh script'

# No duplicate script.  A duplicated row would source the same service twice
# per cell, doubling its API cost and minting a second `occurrence` ordinal for
# every finding it produced (docs/FOUNDATION.md tension 5), which splits one
# resource's finding identity in two.
_dupes=$(printf '%s\n' "${_CLOUD_SERVICES[@]}" | cut -d: -f1 | LC_ALL=C sort | uniq -d | tr '\n' ' ')
assert_eq '' "$_dupes" '_CLOUD_SERVICES names each service script exactly once'

# `modules/cloud/posture/` is deliberately absent from the table: a posture
# check's coverage scope is `scope-key`, not `account-region`
# (rules/RULE-FORMAT.md §9.5.1), so it cannot share the cell run.sh's loop
# writes.  Asserted rather than left to the comment, because the failing
# reading - adding a posture row "for completeness" - would write a cell of the
# wrong KIND under an id whose registry record declares the other, and
# lib/state.sh validates the value's shape rather than cross-checking it.
assert_not_contains "${_CLOUD_SERVICES[*]}" 'posture/' \
  'no posture script is in the service table (its coverage scope is scope-key, not account-region)'

assert_eq '123456789012/us-east-1' "$(cloud_cell 123456789012 us-east-1)" \
  'cloud_cell spells a regional cell <account>/<region> (rules/RULE-FORMAT.md §9.5.1)'
assert_eq '123456789012/global' "$(cloud_cell 123456789012 global)" \
  'cloud_cell spells a global cell <account>/global'
assert_eq '123456789012/global' "$(cloud_cell 123456789012)" \
  'cloud_cell defaults an omitted region to global rather than to an empty cell'

# The JSON reader agrees, leaf for leaf, with lib/state.sh's - which is what
# makes "a byte-identical copy" a checkable claim rather than a comment.  The
# failing reading is a well-meaning "improvement" to one of the two copies:
# they would then disagree about a document neither author looked at, and this
# module's own service scripts would be reading AWS responses through a parser
# no other suite covers.
# shellcheck source=/dev/null
( source "$ROOT/lib/state.sh"
  _doc='{"a":{"b":[1,"x\ty",true,null]},"c":"d"}'
  _mine=$(printf '%s' "$_doc" | cloud_json_flatten)
  _theirs=$(printf '%s' "$_doc" | _state_json_flatten)
  if [[ $_mine == "$_theirs" ]]; then
    printf '  ok   cloud_json_flatten agrees leaf-for-leaf with lib/state.sh _state_json_flatten\n'
  else
    printf '  FAIL [A. engine] cloud_json_flatten diverged from _state_json_flatten\n'
    printf '         mine:   [%s]\n' "$_mine"
    printf '         theirs: [%s]\n' "$_theirs"
    exit 1
  fi
) || { T_FAIL=$(( T_FAIL + 1 )); }
T_PASS=$(( T_PASS + 1 ))

printf '{"Regions":[{"RegionName":"us-east-1"}]}' >"$W/r.json"
cloud_json_leaf _leaf "$W/r.json" "Regions"$'\x1f'"0"$'\x1f'"RegionName"
assert_eq 'us-east-1' "$_leaf" 'cloud_json_leaf reads a leaf at a structural US-joined path'
_leaf=sentinel
cloud_json_leaf _leaf "$W/r.json" 'Nope' || true
assert_eq '' "$_leaf" 'cloud_json_leaf empties its variable for an absent leaf rather than leaving a stale value'

# ===========================================================================
# B. Region-name validation.
# ===========================================================================
t_case 'B. region names'

for _r in us-east-1 eu-west-2 ap-southeast-4 us-gov-west-1 cn-north-1 il-central-1; do
  assert_status 0 "cloud_region_name_valid accepts $_r" cloud_region_name_valid "$_r"
done
# The refusals matter more than the acceptances, and each names a real hazard
# rather than a typo: an unvalidated `--regions` value reaches an `aws` ARGV, a
# `run_record` line and a coverage cell.
assert_status 1 'cloud_region_name_valid refuses an empty name' cloud_region_name_valid ''
assert_status 1 'cloud_region_name_valid refuses a leading dash (the CLI would read it as a flag)' \
  cloud_region_name_valid --profile
assert_status 1 'cloud_region_name_valid refuses a two-segment name' cloud_region_name_valid us-east
assert_status 1 'cloud_region_name_valid refuses uppercase' cloud_region_name_valid US-EAST-1
assert_status 1 'cloud_region_name_valid refuses a glob (an unquoted expansion would hit the scanner cwd)' \
  cloud_region_name_valid '*'
_nl=$'us-east-1\nregions: forged'
assert_status 1 'cloud_region_name_valid refuses an embedded newline (it would forge a second run record)' \
  cloud_region_name_valid "$_nl"

# ===========================================================================
# C. cloud_regions_resolve - the flag paths, with no AWS call at all.
# ===========================================================================
t_case 'C. regions from --regions'

cloud_regions_resolve --regions 'us-east-1,eu-west-2'
assert_eq '2' "${#_CLOUD_REGIONS[@]}" 'an explicit --regions list resolves every name in it'
assert_eq 'us-east-1 eu-west-2' "${_CLOUD_REGIONS[*]}" 'and keeps the operator-given order'
assert_eq 'flag' "$_CLOUD_REGIONS_SOURCE" 'and records the source as `flag`, not `enumerated`'
assert_eq '' "$_CLOUD_REGIONS_REASON" 'and records no coverage reason for a clean explicit list'

_rc=0; cloud_regions_resolve --regions 'us-east-1,NOT A REGION' || _rc=$?
assert_eq '1' "$_rc" 'a malformed name in --regions fails the resolve'
assert_eq '0' "${#_CLOUD_REGIONS[@]}" 'and resolves NO region rather than silently keeping the valid half - a partial list would be scanned and reported as if it were what was asked for'
assert_eq 'regions_flag_malformed' "$_CLOUD_REGIONS_REASON" 'and names the reason'

# ===========================================================================
# D. The full dispatch: no --live.
# ===========================================================================
t_case 'D. no --live'

_run_cloud "$W/out-nolive" "$W/log-nolive" "$STUBDIR/bin" -- cloud
assert_eq '0' "$_RC" '`scan.sh cloud` with no --live exits 0'
assert_eq '' "$(cat "$W/log-nolive")" \
  'and makes NO aws call at all - asserted on the stub call LOG, never on a return value, because "it did not dial" must not be satisfiable by a path that dialled and then returned 0'
_red=$(cat "$W/out-nolive/meta/coverage_reduction")
assert_contains "$_red" 'reason=no_live_flag' 'and records reason=no_live_flag'
assert_not_contains "$_red" 'reason=not_yet_built' \
  'and no longer records scan.sh dispatch reason=not_yet_built - the module is real now, and leaving that line would keep telling an operator the command does nothing'
assert_contains "$(cat "$W/out-nolive/meta/coverage_gap")" 'the absence of a test' \
  'and states the gap in the words a report reader sees'
assert_contains "$(cat "$W/out-nolive/report.md")" 'cloud examined no AWS account' \
  'and the gap reaches report.md, the surface a consumer actually reads'

# ===========================================================================
# E. The full dispatch: --live against the stub.
# ===========================================================================
t_case 'E. --live'

_run_cloud "$W/out-live" "$W/log-live" "$STUBDIR/bin" -- cloud --live
assert_eq '0' "$_RC" '`scan.sh cloud --live` against a resolvable identity exits 0'
_log=$(cat "$W/log-live")
assert_contains "$_log" 'sts get-caller-identity' 'it resolves the caller identity'
assert_contains "$_log" 'ec2 describe-regions' 'and enumerates the account regions'
# IDENTITY FIRST, before anything else (D1 step 1).  Asserted on the ORDER in
# the call log: resolving it later would mean a service script had already run
# against an account the run had not yet named, so run.json's own account id
# would be attached to findings gathered before it was known.
assert_eq 'sts get-caller-identity --output json' "$(head -1 "$W/log-live")" \
  'and `sts get-caller-identity` is the FIRST aws call of the run, before any region or service work'

_j=$W/out-live/run.json
assert_eq '123456789012' "$(_json_at "$_j" cloud.account_id)" 'run.json records the resolved account id'
assert_eq 'arn:aws:iam::123456789012:user/scoursh-fixture' "$(_json_at "$_j" cloud.caller_arn)" \
  'run.json records the caller ARN'
assert_eq 'enumerated' "$(_json_at "$_j" cloud.regions_source)" 'run.json records how the region list was resolved'
assert_eq '2' "$(_json_at "$_j" cloud.regions_planned)" 'run.json records the planned region count'
assert_eq '["eu-west-2","us-east-1"]' "$(_json_at "$_j" regions)" \
  'run.json regions[] is finally populated - it was rendered from meta/regions since step 1 and written by nothing'
assert_not_contains "$(_json_at "$_j" regions)" 'global' \
  'and `global` is NOT in it: that array answers "which AWS regions did this run visit", and global is not a region'

# The echo-back (D1 step 3) goes to STDERR, before the first service call.  The
# failing reading is recording the account in run.json alone: an operator
# watching a run they may still want to interrupt never sees a file written at
# the end of it.
assert_contains "$(cat "$W/out-live.stdout")" 'cloud: scanning AWS account 123456789012' \
  'and the resolved account is echoed to the operator before the sweep begins'

_notes=$(cat "$W/out-live/meta/notes")
assert_contains "$_notes" 'cell=123456789012/global' 'the global cell is written'
assert_contains "$_notes" 'cell=123456789012/us-east-1' 'and one cell per enabled region'
assert_contains "$_notes" 'cell=123456789012/eu-west-2' 'and the second region too'
assert_contains "$_notes" 'coverage-scope=account-region' \
  'and every cell declares the account-region coverage scope (docs/FOUNDATION.md tension 12)'

_red=$(cat "$W/out-live/meta/coverage_reduction")
# CLOUD-05 landed modules/cloud/aws/live/s3.sh, so the walk now INVOKES a
# service and this run takes the third arm of the roll-up rather than the
# first: a script is present, it ran, and against this suite`s stub - which
# answers AccessDenied to every call it has no route for - it covered no
# check.  `reason=no_service_scripts_on_disk_yet` is still written by the
# module and is still the right reason for a tree with an empty live/
# directory; it is simply no longer the reason THIS tree produces.  Both arms
# stay pinned, here and in tests/suites/cloud-s3.sh, because the naive edit
# when the next service lands is to delete whichever one stopped matching.
assert_contains "$_red" 'reason=no_check_covered_by_any_service' \
  'a run whose only present service script covered nothing records exactly that reason'
assert_contains "$_red" 'services_present=1' 'and says how many of the catalog are on disk'
assert_contains "$_red" 'aws_api_access_denied' \
  'and the denied S3 call underneath it is itself a declared reduction, never silence'
assert_contains "$(cat "$W/out-live/meta/coverage_gap")" 'cloud covered nothing in account 123456789012' \
  'and the gap names the account rather than being generic'

# `--regions` narrows for real, and the narrowing is recorded.  The failing
# reading is a flag that is parsed and ignored - which is what `--regions` did
# before this ticket, and which reports a one-region audit as a whole-account
# one.
_run_cloud "$W/out-one" "$W/log-one" "$STUBDIR/bin" -- cloud --live --regions us-east-1
assert_eq '0' "$_RC" '`--regions us-east-1` exits 0'
assert_eq '1' "$(_json_at "$W/out-one/run.json" cloud.regions_planned)" 'and plans exactly one region'
assert_eq 'flag' "$(_json_at "$W/out-one/run.json" cloud.regions_source)" 'and records that the operator chose it'
assert_not_contains "$(cat "$W/log-one")" 'describe-regions' \
  'and skips the enumeration call entirely - an explicit list is not validated against the account (see cloud_regions_resolve for why)'

# ===========================================================================
# E2. The posture phase (docs/STEP6-CLOUD-PLAN.md POSTURE-01; D5, ACCEPTED:
#     posture is a PHASE of `scan.sh cloud`, not a subcommand).
# ===========================================================================
t_case 'E2. posture phase'

# ABSENT is a DECLARED SKIP, never exit 4.  `--live` against the stub above
# already resolves an identity and reaches the service walk with no
# config/posture.conf anywhere near this fixture root, so `out-live` (E's own
# run, above) already covers the absent case - re-asserted here on its own
# meta files so a future edit to E cannot silently stop covering it.
_red=$(cat "$W/out-live/meta/coverage_reduction")
assert_contains "$_red" 'reason=no_posture_conf' \
  'a cloud --live run with no config/posture.conf records the posture-phase declared skip'
assert_contains "$_red" 'phase=posture' 'tagged as the posture phase, not a generic reduction'

# PRESENT is read and validated, not evaluated - the failing reading here is
# either treating a readable file as an error (it must not exit 4) or silently
# saying nothing about it (an operator who wrote real expectations deserves to
# know none of them was checked against anything yet).
cat >"$W/posture-present.conf" <<'PC'
id: fixture-sso-expected
check: POSTURE-FIXTURE-CHECK-01
scope-key: 123456789012
expect: present
notes: a fixture expectation, not a real check id - POSTURE-02/03/04 have not
  landed yet.
PC

SCOURSH_CLOUD_POSTURE_CONF="$W/posture-present.conf" \
  _run_cloud "$W/out-posture-present" "$W/log-posture-present" "$STUBDIR/bin" -- cloud --live
assert_eq '0' "$_RC" \
  '`scan.sh cloud --live` with a config/posture.conf present reads it without error'
# The posture phase itself makes no aws call of its own - it reads a local
# file only.  Asserted COMPARATIVELY against `out-live` (E's own run, with no
# config/posture.conf) rather than against a hardcoded call count: a fixed
# count would silently start asserting something else - how many AWS calls
# the module's OTHER, unrelated service scripts happen to make - the moment a
# real one lands (as modules/cloud/aws/live/s3.sh has, CLOUD-05), and would
# then need editing for a reason that has nothing to do with this phase.  Two
# otherwise-identical `cloud --live` runs, one with config/posture.conf and
# one without, must produce byte-identical aws call logs.
assert_eq "$(cat "$W/log-live")" "$(cat "$W/log-posture-present")" \
  'and a run with config/posture.conf present issues the EXACT SAME aws calls as one without it - the posture phase changed nothing about what was dialled'
_red=$(cat "$W/out-posture-present/meta/coverage_reduction")
assert_contains "$_red" 'reason=no_posture_checks_on_disk_yet' \
  'and records that it was read but nothing evaluated it - modules/cloud/posture/ ships no check yet'
assert_contains "$_red" 'phase=posture' 'tagged as the posture phase'
assert_contains "$_red" 'expectations=1' \
  'and counts the one expectation this fixture file declares'
assert_not_contains "$_red" 'reason=no_posture_conf' \
  'and does NOT also claim the file is absent - the naive fix for each direction is the other`s bug'

# A malformed config/posture.conf is NEVER silently treated as absent
# (rules/RULE-FORMAT.md §11) - it dies exit 4, exactly like every other
# config/*.conf this repository loads through config_load_or_die.
cat >"$W/posture-broken.conf" <<'PC'
id: fixture-sso-expected
check: POSTURE-FIXTURE-CHECK-01
expect: bogus-not-a-real-value
PC
SCOURSH_CLOUD_POSTURE_CONF="$W/posture-broken.conf" \
  _run_cloud "$W/out-posture-broken" "$W/log-posture-broken" "$STUBDIR/bin" -- cloud --live
assert_eq '4' "$_RC" \
  'a config/posture.conf that exists but fails schema validation (here: missing required scope-key, and an invalid expect enum) is exit 4, never treated as if it were absent'

# ===========================================================================
# F. --profile
# ===========================================================================
t_case 'F. --profile'

_run_cloud "$W/out-prof" "$W/log-prof" "$STUBDIR/bin" -- cloud --live --profile staging
assert_eq '0' "$_RC" '`--profile staging` exits 0'
# ASSERTED ON THE STUB'S OWN ARGV, never on the run record.  `--profile` has
# been parsed since step 2 and read by NOTHING, so before this ticket a run
# recorded the profile the operator asked for and then used whatever ambient
# credentials resolved.  A run that merely BELIEVES it used a profile is
# exactly what that produced, and a record-only assertion passes under it.
assert_contains "$(cat "$W/log-prof")" '--profile staging' \
  'and the profile reaches the aws CLI ARGV through lib/awscli.sh, on the identity call itself'
assert_eq 'staging' "$(_json_at "$W/out-prof/run.json" cloud.profile)" 'and run.json records it'

# ===========================================================================
# G. The authorization model (docs/STEP6-CLOUD-PLAN.md D1).
# ===========================================================================
t_case 'G. --i-own-account'

# BOTH DIRECTIONS.  A mechanism that only ever returns 0 satisfies every "it
# did not refuse" assertion ever written, so the match case is what proves the
# refusal is a real comparison rather than a dead branch.
_run_cloud "$W/out-aff-bad" "$W/log-aff-bad" "$STUBDIR/bin" -- cloud --live --i-own-account 999999999999
assert_eq '2' "$_RC" 'a --i-own-account that does not match the resolved account is exit 2 (a wrong invocation, not a scope violation)'
_out=$(cat "$W/out-aff-bad.stdout")
assert_contains "$_out" '999999999999' 'and the message names the account the operator claimed'
assert_contains "$_out" '123456789012' 'and the account the credentials actually resolved to - naming only one leaves the operator guessing which is wrong'

_run_cloud "$W/out-aff-ok" "$W/log-aff-ok" "$STUBDIR/bin" -- cloud --live --i-own-account 123456789012
assert_eq '0' "$_RC" 'a matching --i-own-account proceeds'
assert_eq '123456789012' "$(_json_at "$W/out-aff-ok/run.json" cloud.account_affirmed)" \
  'and run.json records WHICH account was affirmed, not merely that one was'

# The affirmation is checked before the region enumeration, so a wrong-account
# invocation costs one API call rather than one plus an enumeration.
assert_not_contains "$(cat "$W/log-aff-bad")" 'describe-regions' \
  'and a mismatch stops before the region enumeration rather than after it'

# An affirmation naming an account this run will never contact affirms nothing,
# exactly as `--i-own-target` with no `--target` does.  Caught at PARSE time
# (scan.sh's `_scan_check_affirmation`), so it costs no run directory.
_RC=0
( bash "$ROOT/scan.sh" cloud --i-own-account 123456789012 --out "$W/out-aff-nolive" ) >"$W/aff-nolive.out" 2>&1 || _RC=$?
assert_eq '2' "$_RC" '`--i-own-account` with no `--live` is exit 2 - it would sit in run.json looking like an affirmation that was honoured'

# ===========================================================================
# H. --assume-role (docs/STEP6-CLOUD-PLAN.md D3).
# ===========================================================================
t_case 'H. --assume-role'

_run_cloud "$W/out-ar" "$W/log-ar" "$STUBDIR/bin" -- cloud --live --assume-role arn:aws:iam::1:role/ro
assert_eq '2' "$_RC" '--assume-role is REFUSED (exit 2), never silently ignored'
assert_contains "$(cat "$W/out-ar.stdout")" 'not implemented in this version' \
  'and says so plainly'
assert_eq '' "$(cat "$W/log-ar")" \
  'and makes no aws call at all - the failing reading here is exit 0 with a one-account scan, which reads as a complete multi-account audit'

# Refused with no --live too: accepting it silently on the one invocation that
# was going to do nothing anyway would leave the operator believing the flag is
# supported.
_run_cloud "$W/out-ar2" "$W/log-ar2" "$STUBDIR/bin" -- cloud --assume-role arn:aws:iam::1:role/ro
assert_eq '2' "$_RC" 'and it is refused without --live as well'

# ===========================================================================
# I. Unresolvable credentials (docs/FOUNDATION.md tension 14, both rows).
# ===========================================================================
t_case 'I. no credentials'

_run_cloud "$W/out-nc" "$W/log-nc" "$NOCRED" -- cloud --live
assert_eq '4' "$_RC" \
  '`scan.sh cloud --live` with unresolvable credentials is exit 4 - resolvable AWS credentials are this module`s required input (tension 14`s per-module table)'
_red=$(cat "$W/out-nc/meta/coverage_reduction")
assert_contains "$_red" 'detail=identity_unresolved' 'and records that the identity never resolved'
assert_contains "$_red" 'reason=aws_api_no_credentials' \
  'with lib/awscli.sh`s OWN classification of the failure rather than a second vocabulary minted here'
assert_contains "$(cat "$W/out-nc/meta/coverage_gap")" 'This is NOT a clean account' \
  'and the gap says so in the words a report reader sees - an AccessDenied and an account with nothing wrong in it render identically otherwise'
assert_eq '1' "$(wc -l <"$W/log-nc" | tr -d '[:space:]')" \
  'and it stops after the ONE failed identity call rather than sweeping every service against credentials it knows are dead'

# THE OTHER ROW OF THE SAME TABLE, and the naive fix for each direction is the
# other`s bug: under `all`, "a module whose inputs are absent is skipped with a
# run.json reason", so the exit code is untouched because the other modules did
# do what they were asked.
_RC=0
rm -rf "$W/out-all"
PATH="$NOCRED:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/out-all \
  bash "$ROOT/scan.sh" all --live --path "$ROOT/tests/fixtures/clean" \
  --out "$W/out-all" >"$W/out-all.stdout" 2>&1 || _RC=$?
assert_eq '0' "$_RC" 'the same unresolvable credentials under `scan.sh all --live` are exit 0 - a declared skip, not an error'
assert_contains "$(cat "$W/out-all/meta/coverage_reduction")" 'detail=identity_unresolved' \
  'and the reason is still recorded there'

# ===========================================================================
# J. The report`s own not-built markers.
# ===========================================================================
t_case 'J. report markers'

_md=$(cat "$W/out-live/report-audit.md" 2>/dev/null || true)
_html=$(cat "$W/out-live/report-audit.html" 2>/dev/null || cat "$W/out-live/report.html")
assert_not_contains "$_html" 'modules/cloud/ does not exist on disk yet' \
  'lib/report.sh no longer claims modules/cloud/ does not exist - it does, and a stale claim in the audit report is exactly the doc rot this project`s own process rule exists to prevent'
# The phrase this used to look for - "ships no service script yet" - came from
# modules/cloud/aws/run.sh`s own coverage_gap, on the roll-up arm taken when
# NO service script is on disk.  CLOUD-05 landed the first one, so this run
# takes the third arm instead.  Both halves are asserted: the current sentence
# must be there AND the superseded one must be gone, because a report that
# carried both would be telling a reader two different things about the same
# run and neither assertion alone would notice.
assert_contains "$_html" 'service script invocation(s) ran' \
  'and states the real, current limit instead - a script ran and covered nothing, rather than none existing'
assert_not_contains "$_html" 'ships no service script yet' \
  'and the pre-CLOUD-05 sentence is gone rather than left standing beside it'
: "${_md:=}"

t_summary cloud
