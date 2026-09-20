#!/usr/bin/env bash
# tests/suites/cloud-acm.sh - modules/cloud/aws/live/acm.sh: the §8.1 ACM
# read-only certificate-expiry check (docs/STEP6-CLOUD-PLAN.md CLOUD-10).
#
# Mirrors tests/suites/cloud-sns.sh's own shape - see tests/suites/
# cloud-s3.sh's header for the full five-point reasoning this suite family
# shares. SPECIFIC to this suite: expiry is a function of NOT_AFTER and NOW,
# and `SCOURSH_CLOUD_ACM_NOW` is the deterministic override
# acm.sh's own header documents - AGENTS.md's DAST-07 "expiry takes now as an
# argument" lesson, applied here.  Every case in this suite pins `NOW` at a
# fixed epoch (2023-11-14T22:13:20Z, 1700000000) so the suite's own outcome
# never depends on the day it happens to run.
#
# NO NETWORK AND NO AWS ACCOUNT: every case runs against tests/lib/aws-
# fixtures.sh's routed stub, serving tests/fixtures/aws/cloud-acm/.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: see tests/suites/cloud-s3.sh's identical note.
# shellcheck source=/dev/null
source "$ROOT/modules/cloud/aws/live/acm_engine.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cloud-acm
rm -rf "$W"
mkdir -p "$W/bin"
W=$(cd -- "$W" && pwd -P)

# `awk -F'\x1f'` does NOT reliably parse the hex escape as the real byte
# (measured: BSD/macOS awk 20200816 treats it as a literal no-op and leaves
# the whole line as ONE field, so every `$2 == ...` compare is silently
# false) - the fix is a shell variable holding the ACTUAL byte, passed to
# `-F"$SEP"`, never the hex-escape spelling in the -F argument itself.
SEP=$'\x1f'
FIX=$ROOT/tests/fixtures/aws/cloud-acm
NOW=1700000000
EXPIRING=arn:aws:acm:eu-west-2:123456789012:certificate/scoursh-fixture-expiring-cert
OK=arn:aws:acm:eu-west-2:123456789012:certificate/scoursh-fixture-ok-cert
DENY=arn:aws:acm:eu-west-2:123456789012:certificate/scoursh-fixture-denied-cert
PENDING=arn:aws:acm:eu-west-2:123456789012:certificate/scoursh-fixture-pending-cert
EXPIRED=arn:aws:acm:eu-west-2:123456789012:certificate/scoursh-fixture-expired-cert

aws_fixture_stub_install "$W/bin"

_routes_default() {
  local omit=${1:-}
  aws_fixture_route_reset
  aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
  aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
  aws_fixture_route_add acm list-certificates   "$FIX/list-certificates.json"

  if [[ $omit != describe-certificate ]]; then
    aws_fixture_route_add_for acm describe-certificate "$EXPIRING" "$FIX/describe-certificate.expiring.json"
    aws_fixture_route_add_for acm describe-certificate "$OK"       "$FIX/describe-certificate.ok.json"
    aws_fixture_route_add_for acm describe-certificate "$DENY"     "$FIX/describe-certificate.denied.err"
    aws_fixture_route_add_for acm describe-certificate "$PENDING"  "$FIX/describe-certificate.pending.json"
    aws_fixture_route_add_for acm describe-certificate "$EXPIRED"  "$FIX/describe-certificate.expired.json"
  fi
}

_run_cloud() {
  local out=$1
  shift
  _RC=0
  rm -rf "$out"
  PATH="$W/bin:$PATH" SCOURSH_AWS_CACHE_DIR=$W/cache/$(basename "$out") SCOURSH_CLOUD_ACM_NOW=$NOW \
    bash "$ROOT/scan.sh" cloud --live "$@" --out "$out" >"$out.log" 2>&1 || _RC=$?
  return 0
}

_json() {
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
print('' if cur is None else (json.dumps(cur, separators=(',', ':')) if isinstance(cur, (list, dict)) else cur))
PY
}

_findings_table() {
  python3 - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    loc = f.get('location') or {}
    print('\x1f'.join([
        f.get('check_id', ''),
        loc.get('resource_key', '') or '',
        loc.get('region', '') or '',
        f.get('cell') or '',
        ','.join(f.get('cis') or []),
        loc.get('account_id', '') or '',
    ]))
PY
}

_ids_for_arn() {
  local table=$1 arn=$2
  printf '%s\n' "$table" | awk -F"$SEP" -v a="$arn" '$2 == a { print $1 }' | LC_ALL=C sort
}

# ===========================================================================
# A. The classifiers, against fixtures with a FIXED now, no scan at all.
# ===========================================================================
t_case 'A. classifiers'

acm_doc_load "$FIX/describe-certificate.expiring.json"
_na='' _rc=0
acm_cert_not_after_set _na || _rc=1
assert_true "$_rc" 'A1 NotAfter is read'
assert_eq '1700864000' "$_na" 'A2 the fractional .0 suffix is truncated to a plain integer'
assert_true "$(acm_cert_is_expiring "$_na" "$NOW" && echo 0 || echo 1)" 'A3 10 days out is inside the 30-day window'

acm_doc_load "$FIX/describe-certificate.ok.json"
acm_cert_not_after_set _na
assert_true "$(acm_cert_is_expiring "$_na" "$NOW" && echo 1 || echo 0)" 'A4 200 days out is NOT inside the 30-day window'

acm_doc_load "$FIX/describe-certificate.expired.json"
acm_cert_not_after_set _na
assert_true "$(acm_cert_is_expiring "$_na" "$NOW" && echo 0 || echo 1)" 'A5 an already-past NotAfter is expiring too (negative remainder <= threshold)'
_days=$(acm_days_until_expiry "$_na" "$NOW")
assert_true "$(( _days < 0 ? 0 : 1 ))" 'A6 acm_days_until_expiry reports a negative day count for an expired cert'

# Exactly at the 30-day boundary fires; one second past it does not - proves
# the comparison is on SECONDS, never on the day-truncated output (a cert
# 29 days 23 hours out must not be rounded down to "30 days" and missed).
_boundary_now=$(( 1700864000 - 30*86400 ))
assert_true "$(acm_cert_is_expiring 1700864000 "$_boundary_now" && echo 0 || echo 1)" 'A7 exactly 30 days out fires'
assert_true "$(acm_cert_is_expiring 1700864000 "$(( _boundary_now - 1 ))" && echo 1 || echo 0)" 'A8 30 days and 1 second out does not fire'

# ===========================================================================
# B. One scan, five certificates: fires on expiring/expired, quiet on ok,
#    pending is not applicable at all.
# ===========================================================================
t_case 'B. both directions in one run'

_routes_default
_run_cloud "$W/run-b"
assert_eq '0' "$_RC" 'B1 a cloud --live run over the fixture account exits 0'
assert_file_exists "$W/run-b/findings.jsonl" 'B2 findings.jsonl was written'

TBL=$(_findings_table "$W/run-b/findings.jsonl")
EXPIRING_IDS=$(_ids_for_arn "$TBL" "$EXPIRING")
OK_IDS=$(_ids_for_arn "$TBL" "$OK")
EXPIRED_IDS=$(_ids_for_arn "$TBL" "$EXPIRED")
PENDING_IDS=$(_ids_for_arn "$TBL" "$PENDING")

assert_contains "$EXPIRING_IDS" 'CLOUD-ACM-EXPIRING-01' 'B3 a certificate 10 days from expiry fires'
assert_contains "$EXPIRED_IDS" 'CLOUD-ACM-EXPIRING-01' 'B4 an already-expired certificate fires too (ONE check id, not a second)'
assert_eq '' "$OK_IDS" 'B5 a certificate 200 days from expiry, in the SAME run, produces no finding'
assert_eq '' "$PENDING_IDS" 'B6 a PENDING_VALIDATION certificate (no real expiry yet) produces no finding'

# ===========================================================================
# C. ARN, region, account, cell - and NO cis (an honest absence).
# ===========================================================================
t_case 'C. finding citation'

_row=$(printf '%s\n' "$TBL" | awk -F"$SEP" '$1 == "CLOUD-ACM-EXPIRING-01" && $2 ~ /expiring-cert/ { print; exit }')
IFS=$'\x1f' read -r _c_id _c_arn _c_region _c_cell _c_cis _c_account <<<"$_row"

assert_eq "$EXPIRING" "$_c_arn" 'C1 the finding cites the certificate ARN'
assert_eq '123456789012' "$_c_account" 'C2 the finding cites the account id'
assert_eq 'eu-west-2' "$_c_region" 'C3 the finding cites the region'
assert_eq "123456789012/eu-west-2" "$_c_cell" 'C4 the cell agrees with the region for a regional service'
assert_eq '' "$_c_cis" 'C5 the finding carries NO cis value - CIS AWS Foundations Benchmark v3.0.0 has no ACM section (1.19 is about IAM-stored certificates, a different service)'

# ===========================================================================
# D. Honesty: a denied call is a reduction, never silence.
# ===========================================================================
t_case 'D. honesty accounting'

RUNJSON=$W/run-b/run.json
REDUCTIONS=$(_json "$RUNJSON" coverage_reduction)
CHECKS_RUN=$(_json "$RUNJSON" checks_run)

assert_contains "$CHECKS_RUN" 'CLOUD-ACM-EXPIRING-01' \
  'D1 a check that answered for SOME certificates is in checks_run'
assert_contains "$REDUCTIONS" 'aws_api_access_denied' \
  'D2 the AccessDenied on the denied certificate is recorded as a coverage_reduction'
assert_contains "$REDUCTIONS" 'certs_unanswered=1' \
  'D3 the reduction says how many certificates did not answer'

_routes_default describe-certificate
aws_fixture_route_add acm describe-certificate "$FIX/describe-certificate.denied.err"
_run_cloud "$W/run-d"
CR2=$(_json "$W/run-d/run.json" checks_run)
RED2=$(_json "$W/run-d/run.json" coverage_reduction)
assert_not_contains "$CR2" 'CLOUD-ACM-' \
  'D4 a check denied for every certificate is absent from checks_run entirely'
assert_contains "$RED2" 'check=CLOUD-ACM-EXPIRING-01' \
  'D5 ... and it has its own coverage_reduction saying so'

aws_fixture_route_reset
aws_fixture_route_add sts get-caller-identity "$FIX/sts.get-caller-identity.json"
aws_fixture_route_add ec2 describe-regions    "$FIX/ec2.describe-regions.json"
aws_fixture_route_add acm list-certificates   "$FIX/describe-certificate.denied.err"
_run_cloud "$W/run-denied"
CR3=$(_json "$W/run-denied/run.json" checks_run)
assert_not_contains "$CR3" 'CLOUD-ACM-' 'D6 a denied list-certificates credits no check at all'
assert_contains "$(_json "$W/run-denied/run.json" coverage_gap)" 'certificate list' \
  'D7 ... and the coverage_gap says the certificate list could not be read'

# ===========================================================================
# E. Round-trip: coverage cell, state, and every report format.
# ===========================================================================
t_case 'E. round-trip'

RUN_ID=$(_json "$RUNJSON" run_id)
assert_ne '' "$RUN_ID" 'E1 run.json carries the run id'
STATE_FILE=$ROOT/state/$RUN_ID.json
assert_file_exists "$STATE_FILE" 'E2 the run persisted a state snapshot'
COVER=$(python3 - "$STATE_FILE" <<'PYCOVER'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for cid, entry in sorted((doc.get('covered_checks') or {}).items()):
    if cid.startswith('CLOUD-ACM-'):
        out.append('%s %s %s' % (cid, entry.get('scope'), ','.join(entry.get('cells') or [])))
print('\n'.join(out))
PYCOVER
)
assert_contains "$COVER" 'CLOUD-ACM-EXPIRING-01 account-region 123456789012/eu-west-2' \
  'E3 the run wrote a real account-region coverage cell for the region actually visited'

assert_file_exists "$W/run-b/report.md" 'E4 report.md written'
_MD=$(cat "$W/run-b/report.md")
assert_contains "$_MD" "$EXPIRING" 'E5 report.md names the certificate ARN'

_routes_default
_run_cloud "$W/run-sarif" --format sarif
assert_file_exists "$W/run-sarif/report.sarif" 'E6 --format sarif writes report.sarif'
_SARIF=$(cat "$W/run-sarif/report.sarif")
assert_contains "$_SARIF" 'CLOUD-ACM-EXPIRING-01' 'E7 the SARIF run names the check as a rule'
assert_contains "$_SARIF" "$EXPIRING" 'E8 the SARIF result names the resource'

t_summary cloud-acm
