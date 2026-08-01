#!/usr/bin/env bash
# tests/suites/report.sh - lib/report.sh.
#
# tension 10's hostile-evidence fixture, the no-egress properties of the HTML
# report, and run.json's load-bearing content.
#
# shellcheck shell=bash
#
# SC2016: assertion prose mentions shell and HTML syntax literally.
# shellcheck disable=SC2016,SC2015

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

D=$SCOURSH_SCRATCH/rpt
rm -rf "$D"
run_init "$D"
D=$SCOURSH_RUN_DIR

# The tension 10 hostile-evidence fixture, in one string: a script-closing tag
# and an image with an event handler, a raw ANSI sequence, a raw newline,
# invalid UTF-8, and a run of five backticks.
HOSTILE=$(printf '</script><img src=x onerror=alert(1)>\033[31mANSI\033[0m raw\nnewline \xC3\050 bad ```````fence')

finding_new
finding_set check_id DAST-XSS-REFLECT-01
finding_set module dast
finding_set title 'Unescaped reflection'
finding_set base_severity high
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /users/9/p
finding_set loc_param_location query
finding_set loc_param_name q
finding_set cell t1
finding_set remediation 'Escape it.'
finding_set_evidence "$HOSTILE"
finding_emit

finding_new
finding_set check_id SAST-SEC-K-01
finding_set module sast
finding_set title 'Hardcoded key'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path app.py
finding_set loc_line 3
finding_set cell .
finding_set_match 'k'
finding_set_evidence 'AWS_SECRET_ACCESS_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
finding_set remediation 'Rotate it.'
finding_emit

findings_merge "$D"
# Suppress the CRITICAL one deliberately: the counting half of tension 11 step 9
# can only be tested by a suppressed finding whose severity would otherwise show
# up in the live totals.
while IFS= read -r _line; do
  finding_decode "$_line"
  [[ ${_DF[severity]} == critical ]] && break
done <"$D/findings.fields"
SUPPRESSED_FP=${_DF[fingerprint]}
SUPPRESSED_CHECK=${_DF[check_id]}
findings_mark_suppressed "$D" "$SUPPRESSED_FP" 'accepted: tracked in a ticket'
run_record coverage_gap 'no SAST route inventory was available to this run'
report_all "$D"

H=$(cat "$D/report.html")
M=$(cat "$D/report.md")

# ---------------------------------------------------------------------------
printf '\n-- the four artifacts exist --\n'
# ---------------------------------------------------------------------------
t_case 'outputs'
for f in findings.json findings.jsonl report.html report.md run.json; do
  assert_file_exists "$D/$f" "$f is written"
done

# ---------------------------------------------------------------------------
printf '\n-- tension 10: escaping on the way out --\n'
# ---------------------------------------------------------------------------
t_case 'JSON'
if command -v python3 >/dev/null 2>&1; then
  python3 -c "import json,sys; json.load(open('$D/findings.json'))" 2>/dev/null \
    && _t_ok 'findings.json parses' || _t_no 'findings.json parses' 'invalid JSON'
  n=$(python3 -c "
import json
n=0
for line in open('$D/findings.jsonl'):
    line=line.strip()
    if line:
        json.loads(line); n+=1
print(n)" 2>/dev/null || printf 'ERR')
  assert_eq 2 "$n" 'findings.jsonl has exactly one parseable line per finding'
  python3 -c "import json; json.load(open('$D/run.json'))" 2>/dev/null \
    && _t_ok 'run.json parses' || _t_no 'run.json parses' 'invalid JSON'
else
  _t_ok 'python3 unavailable, JSON schema validation skipped'
fi

t_case 'HTML'
assert_not_contains "$H" '<script' 'the report contains NO <script> element at all'
assert_contains "$H" 'Content-Security-Policy' 'the CSP meta tag is present'
assert_contains "$H" "default-src 'none'" 'default-src none'
assert_contains "$H" 'img-src data:' 'images may only be data: URIs'
assert_contains "$H" '&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;' \
  'the XSS payload is escaped into a text node'
assert_not_contains "$H" '<img src=x' 'and no unescaped tag reaches the document'
assert_not_contains "$H" 'http://' 'no external http reference'
assert_not_contains "$H" 'https://' 'no external https reference'
assert_not_contains "$H" '@import' 'no CSS import'
assert_not_contains "$H" 'url(' 'no CSS url() that could fetch an asset'
assert_contains "$H" '<details' 'interactivity is <details>/<summary>, which needs no script'
assert_contains "$H" 'accepted: tracked in a ticket' 'the suppression reason is rendered'
assert_contains "$H" 'Accepted risk' 'suppressed findings render in their own section, not deleted'
assert_contains "$H" 'no SAST route inventory' 'coverage_gap reaches the limitations section (tension 21)'

t_case 'no raw control characters reach the HTML'
# The ANSI sequence would otherwise be able to rewrite a terminal when the file
# is catted, and would survive into any downstream consumer.
assert_not_contains "$H" "$(printf '\033')" 'no ESC byte in the HTML'
assert_not_contains "$M" "$(printf '\033')" 'no ESC byte in the Markdown'

t_case 'Markdown'
assert_contains "$M" '````````' 'the fence is one backtick longer than the seven-run in the evidence'
assert_contains "$M" '# scoursh scan report' 'the report renders'

# ---------------------------------------------------------------------------
printf '\n-- tension 11 step 9: accepted risk is separated, and counted separately --\n'
# ---------------------------------------------------------------------------
# report_html did this and report_md did not: it printed every finding,
# suppressed or not, into one `## Findings` list with identical formatting and
# no reason, so a reader could not tell an accepted risk from a live critical.
md_section() {                    # the body of the `## <name>` section
  sed -n "/^## $1\$/,/^## /p" "$D/report.md"
}
t_case 'Markdown separates accepted risk from live findings'
assert_contains "$M" '## Accepted risk' 'report.md has an accepted-risk section'
assert_not_contains "$(md_section Findings)" "$SUPPRESSED_CHECK" \
  'the suppressed finding is NOT in the live findings section'
assert_contains "$(md_section 'Accepted risk (1)')" "$SUPPRESSED_CHECK" \
  'it is in the accepted-risk section instead'
assert_contains "$(md_section 'Accepted risk (1)')" 'accepted: tracked in a ticket' \
  'with the reason that was recorded, which the reader needs to judge it'

t_case 'an accepted critical does not inflate the live severity counts'
R2=$(cat "$D/run.json")
assert_contains "$R2" '"critical":0' \
  'run.json by_severity counts LIVE findings only (the only critical here is accepted)'
assert_contains "$R2" '"suppressed_by_severity"' 'and the accepted set is broken out on its own'
assert_contains "$H" '<div class="n">0</div><div class="l">critical</div>' \
  'the HTML critical tile counts live findings only'

t_case 'redaction reaches every format'
for f in findings.json findings.jsonl report.html report.md run.json; do
  if /usr/bin/grep -q -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$D/$f" 2>/dev/null; then
    _t_no "no raw secret in $f" 'the key is present in the output'
  else
    _t_ok "no raw secret in $f"
  fi
done

# ---------------------------------------------------------------------------
printf '\n-- run.json is load-bearing, not decorative --\n'
# ---------------------------------------------------------------------------
t_case 'run.json content'
R=$(cat "$D/run.json")
for k in tool_version fp_schema uk_schema run_id started_at completed_at duration_seconds \
  scan_root_id redact_secrets capabilities counts skipped_checks coverage_gap \
  coverage_reduction incomplete_reason gate gated_findings diff_usable; do
  assert_contains "$R" "\"$k\"" "run.json carries $k"
done
assert_contains "$R" '"msleep"' 'the capability probe results are recorded'
assert_contains "$R" '"shred"' 'including whether shred exists on this host'
assert_contains "$R" '"no SAST route inventory was available to this run"' 'coverage_gap is recorded'
assert_contains "$R" '"suppressed": 1' 'suppressed findings are counted separately'

t_case 'a report generated without redaction is visibly identifiable'
D2=$SCOURSH_SCRATCH/rpt2
rm -rf "$D2"
SCOURSH_RUN_DIR=''
SCOURSH_RUN_ID=''
run_init "$D2"
D2=$SCOURSH_RUN_DIR
SCOURSH_REDACT_SECRETS=false
finding_new
finding_set check_id SAST-SEC-K-01
finding_set module sast
finding_set title x
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path a.py
finding_set cell .
finding_set_match k
finding_set_evidence 'plain'
finding_set remediation r
finding_emit
findings_merge "$D2"
report_all "$D2"
assert_contains "$(cat "$D2/report.html")" 'Redaction is DISABLED' \
  'the HTML leads with a banner, because such a report must not be circulated'
assert_contains "$(cat "$D2/report.md")" 'redaction is disabled' 'and so does the Markdown'
assert_contains "$(cat "$D2/run.json")" '"redact_secrets": false' 'and run.json records it'
SCOURSH_REDACT_SECRETS=true

t_summary report
