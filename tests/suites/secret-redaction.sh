#!/usr/bin/env bash
# tests/suites/secret-redaction.sh - a secrets check never writes the credential
# it matched (docs/FOUNDATION.md tension 9).
#
# The defect this suite exists for: `redact()` masks by SHAPE, from
# rules/redaction.rules, which is a list maintained independently of the
# secrets checks in modules/*/rules/*.rules.  When a secrets check matched a
# shape the redaction list did not happen to carry - a generic quoted
# `password = "..."` literal, an uppercase `API_KEY = "..."` - the raw matched
# bytes were written in the clear into findings.jsonl, findings.json,
# findings.fields, report.md, report.html and the per-worker shards, with
# `redact-secrets: true` in force.  Measured before the fix: two planted
# canaries, five files each.
#
# The fix is PROVENANCE, not another pattern: a finding produced by a check
# whose whole purpose is finding a credential never carries that credential as
# evidence, whatever rules/redaction.rules happens to contain.  So the
# assertions here are written against the property ("this value is absent from
# every byte the run wrote"), never against a particular pattern being present,
# because a pattern assertion would go green again the next time the two lists
# drift.
#
# Every case that pins a decision names the reading it FAILS under, because a
# test that passes under both readings pins nothing.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is the intended reporting shape.
# SC2016: assertion prose mentions shell variables literally.
# shellcheck disable=SC2015,SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/secret-redaction
mkdir -p "$W"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"
attribution_load "$ROOT/tests/fixtures/config/scope.conf"

FIX=$ROOT/tests/fixtures/secret-redaction
# The planted positive controls.  Both are fake canaries committed under
# tests/fixtures/secret-redaction/; see that directory's README.md.
CANARY_PW=scourshFakeCanaryPw01
CANARY_AK=scourshFakeCanaryAk01

# Sets SCOURSH_RUN_DIR in the CURRENT shell - assigning it from a command
# substitution would call run_init in a subshell and throw it away.
new_run() {
  rm -rf "${W:?}/run.$1"
  SCOURSH_RUN_DIR=''
  SCOURSH_RUN_ID=''
  occurrence_reset_all
  run_init "$W/run.$1"
}

# Every byte of a finished run directory, as one string.  Deliberately a
# RECURSIVE walk of whatever the run wrote rather than a list of the file names
# this suite happens to know about: the acceptance criterion is "no output
# path", and enumerating paths by hand is how the two-lists defect happened in
# the first place.  A file added by a later step is covered the day it appears.
run_dir_bytes() {
  local d=$1 f
  while IFS= read -r f; do
    [[ -f $f ]] || continue
    cat -- "$f"
    printf '\n'
  done < <(find "$d" -type f | sort)
}

# ---------------------------------------------------------------------------
# A. End to end through the real scan.sh, redaction ON (the shipped default).
#    This is the reproduction, turned into a regression test.
# ---------------------------------------------------------------------------
t_case 'A. end-to-end: no output path carries the matched credential'

E2E=$W/e2e
rm -rf "$E2E"
e2e_rc=0
( cd "$ROOT" && bash scan.sh sast --path "$FIX" --format json,sarif,html,md --out "$E2E" ) \
  >"$W/e2e.out" 2>"$W/e2e.err" || e2e_rc=$?
assert_eq 0 "$e2e_rc" 'the scan itself succeeds'

e2e_bytes=$(run_dir_bytes "$E2E")

# The five files the leak was measured in, named individually so a regression
# reports WHICH format broke rather than only that something did.
for f in findings.jsonl findings.json findings.fields report.md report.html run.json; do
  body=''
  [[ -f $E2E/$f ]] && body=$(cat "$E2E/$f")
  assert_not_contains "$body" "$CANARY_PW" "$f carries no cleartext password match"
  assert_not_contains "$body" "$CANARY_AK" "$f carries no cleartext API-key match"
done

# And the whole tree, including the per-worker shards under shards/, which are
# real files on disk that outlive the merge whenever --keep-shards is given.
assert_not_contains "$e2e_bytes" "$CANARY_PW" 'no file anywhere in the run dir carries the password match'
assert_not_contains "$e2e_bytes" "$CANARY_AK" 'no file anywhere in the run dir carries the API-key match'

assert_not_contains "$(cat "$W/e2e.out")" "$CANARY_PW" 'stdout carries no cleartext match'
assert_not_contains "$(cat "$W/e2e.err")" "$CANARY_PW" 'stderr carries no cleartext match'

t_case 'A2. --verbose is not a way around the redaction'
# Fails under a fix applied to the emitters only: a diagnostic path that echoes
# a finding would still print the credential.
V=$W/verbose
rm -rf "$V"
v_rc=0
( cd "$ROOT" && bash scan.sh sast --path "$FIX" --verbose --format json,html,md --out "$V" ) \
  >"$W/v.out" 2>"$W/v.err" || v_rc=$?
assert_eq 0 "$v_rc" 'the verbose scan itself succeeds'
assert_not_contains "$(cat "$W/v.out")" "$CANARY_PW" 'verbose stdout carries no cleartext match'
assert_not_contains "$(cat "$W/v.err")" "$CANARY_PW" 'verbose stderr carries no cleartext match'
assert_not_contains "$(run_dir_bytes "$V")" "$CANARY_PW" 'the verbose run dir carries no cleartext match'

# ---------------------------------------------------------------------------
# B. The report is still USABLE after redaction (acceptance criterion 3).
#    A leak "fixed" by dropping the finding is not a fix.
# ---------------------------------------------------------------------------
t_case 'B. the finding survives redaction and stays actionable'

jsonl=$(cat "$E2E/findings.jsonl")
assert_contains "$jsonl" 'SAST-SEC-GENERIC_PASSWORD-01' 'the password finding is still reported'
assert_contains "$jsonl" 'SAST-SEC-GENERIC_API_KEY-01' 'the API-key finding is still reported'
assert_contains "$jsonl" 'creds.py' 'the file is still named'
assert_contains "$jsonl" '"line":5' 'the line number is still reported'
assert_contains "$jsonl" 'Hardcoded password literal' 'the rule title is still reported'
assert_contains "$jsonl" 'rotate the credential' 'the remediation is still reported'
# The digest is what makes a redacted report usable: it tells two secrets apart
# and recognises one secret across findings.  Fails under a fix that writes a
# fixed string such as `<redacted>`.
ev_pw=$(grep -o '"evidence":"[^"]*"' "$E2E/findings.jsonl" | sed -n '1p')
ev_ak=$(grep -o '"evidence":"[^"]*"' "$E2E/findings.jsonl" | sed -n '2p')
assert_ne "$ev_pw" "$ev_ak" 'two different secrets do not redact to the same evidence string'
assert_contains "$(cat "$E2E/report.md")" 'redacted:' 'report.md shows a redaction placeholder, not a blank'

# ---------------------------------------------------------------------------
# C. finding_set_secret_match: the setter that carries raw credential bytes.
# ---------------------------------------------------------------------------
t_case 'C. finding_set_secret_match never lets the raw bytes into evidence'

SCOURSH_REDACT_SECRETS=true
finding_new
finding_set_secret_match "password = \"$CANARY_PW\""
assert_not_contains "$(finding_get evidence)" "$CANARY_PW" 'the raw match is absent from evidence'
assert_contains "$(finding_get evidence)" '<redacted:' 'and a placeholder is there instead'

# Identity must be untouched: modules/sast/adapters/gitleaks/adapter.sh dedups
# a gitleaks finding against a native secrets.rules finding by comparing
# loc_match_digest, so a digest that changed shape here would silently defeat
# that dedup.  Fails under a fix that digests the MASKED evidence instead of
# the raw bytes.
finding_new
finding_set_match "password = \"$CANARY_PW\""
d_plain=$(finding_get loc_match_digest)
finding_new
finding_set_secret_match "password = \"$CANARY_PW\""
d_secret=$(finding_get loc_match_digest)
assert_eq "$d_plain" "$d_secret" 'loc_match_digest is byte-identical to finding_set_match on the same text'

finding_new
finding_set_secret_match "password = \"$CANARY_PW\""
ev_a=$(finding_get evidence)
finding_new
finding_set_secret_match "password = \"$CANARY_PW\""
ev_b=$(finding_get evidence)
finding_new
finding_set_secret_match "password = \"$CANARY_AK\""
ev_c=$(finding_get evidence)
assert_eq "$ev_a" "$ev_b" 'the same secret redacts to the same placeholder in two findings'
assert_ne "$ev_a" "$ev_c" 'two distinct secrets redact to distinct placeholders'

# ---------------------------------------------------------------------------
# D. The chokepoint backstop.  A future emitter that reaches for the ordinary
#    finding_set_evidence with a secrets-family check id is still masked, by
#    finding_emit, because that is the one point every finding passes through.
# ---------------------------------------------------------------------------
t_case 'D. finding_emit masks a secrets-family finding the emitter forgot'
# Fails under a fix applied only at the call sites that exist today - which is
# exactly the shape of the defect being fixed, one level up.
new_run backstop
finding_new
finding_set check_id SAST-SEC-GENERIC_PASSWORD-01
finding_set module sast
finding_set title 'Hardcoded password literal'
finding_set base_severity high
finding_set cwe CWE-798
finding_set owasp A07:2025
finding_set loc_path creds.py
finding_set loc_line 5
finding_set cell "$W"
finding_set logical_kind file
finding_set logical_fqn creds.py:5
finding_set_match "password = \"$CANARY_PW\""
finding_set_evidence "password = \"$CANARY_PW\""   # the forgetful emitter
finding_emit
findings_merge "$SCOURSH_RUN_DIR"
assert_not_contains "$(run_dir_bytes "$SCOURSH_RUN_DIR")" "$CANARY_PW" \
  'the backstop masked it anyway, in every file the run wrote'

t_case 'D2. the backstop leaves an already-redacted evidence string alone'
# Fails under a backstop that masks unconditionally: it would double-wrap a
# placeholder redact() had already produced, changing evidence a reader relies
# on and churning nothing useful.
new_run idempotent
finding_new
finding_set check_id SAST-SEC-JWT-01
finding_set module sast
finding_set title 'Hardcoded JSON Web Token'
finding_set base_severity high
finding_set cwe CWE-798
finding_set owasp A07:2025
finding_set loc_path t.py
finding_set loc_line 1
finding_set cell "$W"
finding_set logical_kind file
finding_set logical_fqn t.py:1
finding_set_match 'eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2ln'
finding_set_evidence 'eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2ln'
before=$(finding_get evidence)
finding_emit
assert_contains "$before" '<redacted:JWT:' 'redact() had already masked the JWT at the setter'
assert_eq "$before" "$(finding_get evidence)" 'and finding_emit left that placeholder untouched'

# ---------------------------------------------------------------------------
# E. A NON-secret finding is not collaterally redacted.
# ---------------------------------------------------------------------------
t_case 'E. a non-secrets check keeps its evidence verbatim'
# Fails under a fix that masks every finding, or one keyed on the
# `sensitive_data` field - which lib/paranoid.sh and lib/http.sh also set on
# findings whose evidence is a destination address, not a credential.
new_run nonsecret
finding_new
finding_set check_id SAST-INJ-OS_COMMAND-01
finding_set module sast
finding_set title 'OS command injection'
finding_set base_severity high
finding_set cwe CWE-78
finding_set owasp A03:2021
finding_set loc_path app.py
finding_set loc_line 9
finding_set cell "$W"
finding_set logical_kind file
finding_set logical_fqn app.py:9
finding_set_match 'os.system(cmd)'
finding_set_evidence 'os.system(cmd)'
finding_emit
assert_eq 'os.system(cmd)' "$(finding_get evidence)" 'the injection evidence is untouched'

t_case 'E2. a paranoid egress finding keeps its destination in the clear'
# The same reading, on the field the naive fix would key off.  A masked
# `addr=... port=...` would make the detector unusable and buys nothing: that
# evidence is a destination, not a credential.
new_run egress
finding_new
finding_set check_id PARANOID-EGRESS-VIOLATION
finding_set module dast
finding_set title 'paranoid mode observed a connection outside the run allowlist'
finding_set base_severity critical
finding_set cwe CWE-918
finding_set owasp A10:2021
finding_set sensitive_data true
finding_set cell "$W"
finding_set loc_target unattributed
finding_set loc_method CONNECT
finding_set loc_path_template '198.51.100.7:443'
finding_set_evidence 'addr=198.51.100.7 port=443 backend=lsof family_root=1234'
finding_emit
assert_contains "$(finding_get evidence)" '198.51.100.7' 'the observed destination survives'

# ---------------------------------------------------------------------------
# F. redact-secrets: false.  A DECLARED cleartext mode, not an accident.
# ---------------------------------------------------------------------------
t_case 'F. with redaction off the match is written in the clear, and the report says so'
OFF=$W/off
rm -rf "$OFF"
off_rc=0
( cd "$ROOT" && SCOURSH_CONFIG_REDACT_SECRETS=false \
    bash scan.sh sast --path "$FIX" --format json,html,md --out "$OFF" ) \
  >"$W/off.out" 2>"$W/off.err" || off_rc=$?
assert_eq 0 "$off_rc" 'the unredacted scan succeeds'
# Fails under a fix that masks unconditionally: `redact-secrets` would then be
# a control with only one setting, and an operator who needs the literal bytes
# (rotating a credential they must first identify) has no way to ask for them.
assert_contains "$(cat "$OFF/findings.jsonl")" "$CANARY_PW" 'the cleartext match IS present, deliberately'
assert_contains "$(cat "$OFF/run.json")" '"redact_secrets": false' 'run.json records the choice'
# Each format's own wording, quoted as it is actually emitted - a case-folded
# assertion would keep passing if one banner were dropped and the other's text
# happened to appear elsewhere in the page.
assert_contains "$(cat "$OFF/report.md")" 'redaction is disabled for this run' 'report.md warns the reader'
assert_contains "$(cat "$OFF/report.html")" 'Redaction is DISABLED for this run' 'report.html warns the reader'

# ---------------------------------------------------------------------------
# G. `sast --history` is a SECOND emitter, and a distinct output path.
# ---------------------------------------------------------------------------
t_case 'G. a credential found in git history is not written in the clear either'
# modules/sast/history.sh mints its own SAST-HIST-* ids through its own emitter,
# so a fix applied to modules/sast/engine.sh alone leaves this path leaking -
# the reading this case fails under.  It matters more than the working-tree one,
# not less: a SAST-HIST-* finding reports a credential that is already committed
# and already has to be treated as compromised, and its report is the artifact
# most likely to be pasted into a ticket.
HREPO=$W/hist-repo
rm -rf "$HREPO"
mkdir -p "$HREPO"
git -C "$HREPO" init -q
git -C "$HREPO" config user.email scoursh@example.invalid
git -C "$HREPO" config user.name scoursh-test
printf 'print("hello")\n' >"$HREPO/app.py"
git -C "$HREPO" add app.py
git -C "$HREPO" -c commit.gpgsign=false commit -q -m 'first'
# The canary is committed and then removed, so it exists ONLY in history - which
# is the whole point of the SAST-HIST-* family (tension 13).
printf '# FAKE canary, not a credential.\npassword = "%s"\n' "$CANARY_PW" >>"$HREPO/app.py"
git -C "$HREPO" add app.py
git -C "$HREPO" -c commit.gpgsign=false commit -q -m 'second'
git -C "$HREPO" rm -q --cached app.py >/dev/null
printf 'print("hello")\n' >"$HREPO/app.py"
git -C "$HREPO" add app.py
git -C "$HREPO" -c commit.gpgsign=false commit -q -m 'third'

H=$W/hist-out
rm -rf "$H"
h_rc=0
( cd "$ROOT" && bash scan.sh sast --path "$HREPO" --history --format json,html,md --out "$H" ) \
  >"$W/h.out" 2>"$W/h.err" || h_rc=$?
assert_eq 0 "$h_rc" 'the history scan itself succeeds'
# Guard against the case passing for the wrong reason - a run that found nothing
# leaks nothing, and would satisfy the absence assertion below on its own.
assert_contains "$(cat "$H/findings.jsonl")" 'SAST-HIST-' 'the history walk actually found the committed credential'
assert_not_contains "$(run_dir_bytes "$H")" "$CANARY_PW" 'and no file the history run wrote carries it in the clear'
assert_not_contains "$(cat "$W/h.out")$(cat "$W/h.err")" "$CANARY_PW" 'nor its stdout or stderr'

t_summary secret-redaction
