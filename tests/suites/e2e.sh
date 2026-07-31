#!/usr/bin/env bash
# tests/suites/e2e.sh - the end-to-end path, and finding F12.
#
# Runs tests/e2e/fixture-scan.sh for real and asserts the properties §13 step 1
# is defined by: valid JSON, a self-contained HTML report, a run.json, one
# finding of every shape, and byte-reproducible output.
#
# shellcheck shell=bash
#
# SC2016: assertion prose mentions shell variables literally.
# shellcheck disable=SC2016,SC2015

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

R1=$SCOURSH_SCRATCH/e2e1
R2=$SCOURSH_SCRATCH/e2e2
rm -rf "$R1" "$R2"

# ---------------------------------------------------------------------------
printf '\n-- the fixture scan runs end to end --\n'
# ---------------------------------------------------------------------------
t_case 'the harness completes'
if bash "$ROOT/tests/e2e/fixture-scan.sh" "$R1" >/dev/null 2>"$SCOURSH_SCRATCH/e2e.err"; then
  _t_ok 'tests/e2e/fixture-scan.sh exits 0'
else
  _t_no 'tests/e2e/fixture-scan.sh exits 0' "$(cat "$SCOURSH_SCRATCH/e2e.err")"
fi

t_case 'every artifact is written'
for f in findings.json findings.jsonl report.html report.md run.json; do
  assert_file_exists "$R1/$f" "$f"
done

t_case 'one finding of every fingerprint profile in tension 5 frozen table'
J=$(cat "$R1/findings.jsonl")
for m in '"module":"sast"' '"module":"sca"' '"module":"dast"' '"module":"cloud"' \
  '"module":"posture"' '"module":"derived"'; do
  assert_contains "$J" "$m" "a finding with $m"
done
assert_contains "$J" '"check_id":"SAST-HIST-AWS_SECRET-01"' 'a history finding, keyed on the blob'
assert_contains "$J" '"blob_sha"' 'whose location tuple starts with blob_sha'
assert_contains "$J" '"path_template":"/users/{id}/profile"' 'a DAST finding with a templated path'
assert_contains "$J" '"correlation"' 'a derived finding keyed on its correlation value only'

t_case 'three byte-identical matches in one file are three findings'
n=$(/usr/bin/grep -c '"check_id":"SAST-PY-EVAL-01"' "$R1/findings.jsonl" || true)
assert_eq 3 "$n" 'the occurrence discriminator keeps distinct call sites apart'

t_case 'two distinct secrets in one file are two findings with two digests'
n=$(/usr/bin/grep -c '"check_id":"SAST-SEC-AWS_SECRET-01"' "$R1/findings.jsonl" || true)
assert_eq 2 "$n" 'two findings'
d=$(/usr/bin/grep -o '<redacted:AWS_SECRET:[0-9a-f]*>' "$R1/findings.jsonl" | LC_ALL=C sort -u | wc -l | tr -d ' ')
assert_eq 2 "$d" 'and two distinct redaction digests, so a reader can tell them apart'

t_case 'the composite fires and its contributors are retained'
assert_contains "$J" '"check_id":"COMPOSITE-FIXTURE-CHAIN"' 'the composite is present'
assert_contains "$J" '"derived_into":["COMPOSITE-FIXTURE-CHAIN"]' 'a contributor carries the back-reference'
assert_contains "$J" '"cell":null' 'a derived finding persists cell as JSON null'

t_case 'the clean fixture stays quiet'
# The false-positive guard: the same rules over the clean tree must fire nothing.
# Files are enumerated explicitly rather than passing `-r`: that flag means
# --recursive to grep and --replace to ripgrep, so one engine would have
# silently searched a replacement string instead of a tree.
hits=0
while IFS= read -r pat; do
  [[ -n $pat ]] || continue
  while IFS= read -r cf; do
    [[ -n $cf ]] || continue
    if scan_match "$SCOURSH_SCRATCH/cl" -e "$pat" -- "$cf"; then
      hits=$(( hits + 1 ))
    fi
  done <<<"$(find "$ROOT/tests/fixtures/clean" -type f | LC_ALL=C sort)"
done <<<"$(/usr/bin/grep '^pattern: ' "$ROOT/tests/fixtures/rules/fixture.rules" | sed 's/^pattern: //')"
assert_eq 0 "$hits" 'no seeded rule fires on the clean fixture'

# ---------------------------------------------------------------------------
printf '\n-- JSON and HTML validity --\n'
# ---------------------------------------------------------------------------
t_case 'schema validity'
if command -v python3 >/dev/null 2>&1; then
  python3 - "$R1" <<'PY' && _t_ok 'findings.json, findings.jsonl and run.json all parse' \
    || _t_no 'findings.json, findings.jsonl and run.json all parse' 'see above'
import json, sys, os
d = sys.argv[1]
doc = json.load(open(os.path.join(d, 'findings.json')))
assert doc['fp_schema'] == 'fp/1', doc['fp_schema']
n = 0
for line in open(os.path.join(d, 'findings.jsonl')):
    line = line.strip()
    if line:
        f = json.loads(line)
        # tension 7: the field is check_id and no emitter writes a field named id
        assert 'id' not in f, 'a field named "id" was emitted'
        assert f['check_id'], 'check_id missing'
        assert len(f['fingerprint']) == 64, 'fingerprint is not 64 hex characters'
        n += 1
assert n == len(doc['findings']), 'jsonl and json disagree on the finding count'
run = json.load(open(os.path.join(d, 'run.json')))
assert run['counts']['total'] == n, 'run.json count disagrees with findings.jsonl'
PY
else
  _t_ok 'python3 unavailable, JSON validation skipped'
fi

t_case 'the HTML report is genuinely self-contained'
H=$(cat "$R1/report.html")
assert_not_contains "$H" '<script' 'no script element'
assert_contains "$H" 'Content-Security-Policy' 'the CSP is present'
assert_not_contains "$H" 'http://' 'no external reference'
assert_not_contains "$H" 'https://' 'no external reference'
assert_not_contains "$H" 'url(' 'no CSS url()'
assert_contains "$H" '&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;' 'hostile evidence is escaped'

t_case 'no raw secret from the fixture reaches any output'
# PEMBODYMARKER* are the body lines of a MULTI-LINE private key.  They are the
# case a single-line pseudo-PEM cannot distinguish: the matcher is line-oriented,
# so a rule written to swallow the block redacts only the header and writes every
# base64 body line out in the clear.
for s in wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  PEMBODYMARKERONE PEMBODYMARKERTWO; do
  for f in findings.json findings.jsonl report.html report.md run.json; do
    if /usr/bin/grep -q -F "$s" "$R1/$f" 2>/dev/null; then
      _t_no "no raw secret in $f" "found $s"
    else
      _t_ok "no raw secret in $f"
    fi
  done
done

# ---------------------------------------------------------------------------
printf '\n-- tension 17: byte-reproducible output --\n'
# ---------------------------------------------------------------------------
t_case 'two identical scans produce byte-identical findings'
bash "$ROOT/tests/e2e/fixture-scan.sh" "$R2" >/dev/null 2>&1
# One run timestamp is shared by every finding of a run, so normalising that
# single value is all that is needed to compare two runs byte for byte.
norm() { sed -e 's/"first_seen":"[^"]*"/"first_seen":"T"/g' -e 's/"last_seen":"[^"]*"/"last_seen":"T"/g' "$1"; }
assert_eq "$(norm "$R1/findings.jsonl")" "$(norm "$R2/findings.jsonl")" \
  'sorted by (module, check_id, fingerprint) under LC_ALL=C, so scheduling cannot change the bytes'

# ---------------------------------------------------------------------------
printf '\n-- finding F12: shards and the unit journal survive an interruption --\n'
# ---------------------------------------------------------------------------
# Finding shards and the unit journal used to live in $SCRATCH and be retained
# only under --keep-shards, while the EXIT trap erases $SCRATCH on SIGTERM -
# which is the signal tension 18's own resume test uses.  Resume therefore could
# not read the shards it is defined to read.
t_case 'shards and units live in the run directory, not the scratch directory'
assert_file_exists "$R1/shards" 'reports/<run>/shards/'
assert_file_exists "$R1/units" 'reports/<run>/units/'
assert_file_absent "$SCOURSH_SCRATCH/findings" 'nothing under $SCRATCH/findings/'

t_case 'a SIGTERM leaves the shards intact and erases only the scratch directory'
R3=$SCOURSH_SCRATCH/e2e3
rm -rf "$R3"
cat >"$SCOURSH_SCRATCH/longrun.sh" <<SH
source "$ROOT/lib/report.sh"
run_init "$R3"
finding_new
finding_set check_id SAST-A-B-01
finding_set module sast
finding_set title t
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path a.py
finding_set cell .
finding_set_match m
finding_set remediation r
finding_emit
printf '{"unit_key":"abc","state":"done"}\n' >"$R3/units/\$BASHPID.jsonl"
printf '%s\n' "\$SCOURSH_SCRATCH" >"$R3/scratchpath"
printf 'ready\n' >"$R3/ready"
while :; do sleep 1; done
SH
env -u SCOURSH_SCRATCH -u SCOURSH_SCRATCH_OWNER bash "$SCOURSH_SCRATCH/longrun.sh" >/dev/null 2>&1 &
child=$!
waited=0
while [[ ! -f $R3/ready ]] && (( waited < 100 )); do
  msleep 100
  waited=$(( waited + 1 ))
done
kill -TERM "$child" 2>/dev/null || true
wait "$child" 2>/dev/null || true
child_scratch=$(cat "$R3/scratchpath" 2>/dev/null || printf '')
nshards=$(find "$R3/shards" -name '*.fields' 2>/dev/null | wc -l | tr -d ' ')
assert_eq 1 "$nshards" 'the finding shard survives the SIGTERM (it would have been erased from $SCRATCH)'
assert_file_exists "$R3/units" 'and so does the unit journal'
assert_eq 1 "$(find "$R3/units" -name '*.jsonl' | wc -l | tr -d ' ')" 'with its record intact'
assert_file_absent "$child_scratch" 'while the scratch directory - genuinely transient data - is erased'
assert_contains "$(cat "$R3/meta/incomplete_reason" 2>/dev/null || printf '')" 'SIGTERM' \
  'and the interruption is recorded as an incomplete_reason, which is the exit-5 predicate'

t_summary e2e
