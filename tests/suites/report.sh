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
  printf '  NOTICE python3 is not on PATH: JSON well-formedness validation did NOT run.  This is a SKIP, not a pass.\n'
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

# ===========================================================================
# docs/STEP5-DAST-PLAN.md DAST-33/34: the authorisation record in run.json,
# and the unrestricted-run banner in the reports a human opens.
# ===========================================================================
printf '\n-- DAST-33: run.json renders the audit facts, not just the meta files --\n'

# Asserted against run.json ITSELF, never against reports/<run>/meta/<key>.
# That distinction is the entire ticket: `run_record use_engines` has been
# writing meta/use_engines since the semgrep adapter landed and nothing
# rendered it, and both suites covering it asserted against the meta FILE - so
# a fact that never reached the consumer surface read as fully covered.
D3=$SCOURSH_SCRATCH/rpt-authz
rm -rf "$D3"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D3"
D3=$SCOURSH_RUN_DIR

t_case 'an unaffirmed run still renders a complete authorization object'
run_record use_engines false
run_record authorization_affirmed false
run_record authorization_source none
run_record authorization_scope_target fixture-target
run_record authorization_intensity passive
run_record authorization_intrusive false
run_record authorization_authed false
run_record authorization_scope_conf_sha256 abc123
run_record limits_clamped 'request-budget:20000->5000 reason=no_owner_affirmation source=default'
run_record limits_enforced 'scope-gate:config/scope.conf'
report_run_json "$D3"
J3=$(cat "$D3/run.json")
assert_contains "$J3" '"use_engines": false' \
  'run.json renders use_engines - FAILS in the state this ticket found the tool in, where scan.sh recorded the flag and report_run_json never rendered it, leaving the only shipped audit flag half-recorded'
assert_contains "$J3" '"authorization": {' 'run.json carries an authorization object'
assert_contains "$J3" '"affirmed": false' \
  'an UNAFFIRMED run records the object too, rather than omitting it - FAILS under "only record it when something was affirmed", which makes an absent key ambiguous between "nothing was affirmed" and "this version does not record it"'
assert_contains "$J3" '"affirmation_source": "none"' \
  'and names the route explicitly, so a reviewer can tell a flag pasted into a CI file from a human answering at a terminal'
assert_contains "$J3" '"scope_conf_sha256": "abc123"' \
  'and ties the run to the exact authorisation-file state, so "was this host authorised at the time" stays answerable from the run plus that file'"'"'s git history'
assert_contains "$J3" 'request-budget:20000->5000 reason=no_owner_affirmation source=default' \
  'the clamp that actually bit is rendered as a DELTA with its resolution layer - FAILS under a boolean "unrestricted: true", which tells a later reader nothing about what traffic was authorised'
assert_contains "$J3" '"limits_enforced": ["scope-gate:config/scope.conf"]' \
  'and what stayed ON is rendered too, because the usual question after an incident is what the tool could not have done'
assert_contains "$J3" '"gate":' 'and the keys after the object are still present, i.e. the JSON was not truncated by the new block'

t_case 'the rendered run.json is still valid JSON with the object in it'
if command -v python3 >/dev/null 2>&1; then
  rc=0
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$D3/run.json" || rc=$?
  assert_eq 0 "$rc" \
    'run.json parses as JSON with the nested authorization object present - FAILS on a stray or missing comma in the nested block, which no string-containment assertion above would catch'
else
  printf '  NOTICE python3 is not on PATH: this JSON parse check did NOT run.  This is a SKIP, not a pass.\n'
fi

t_case 'an affirmed run renders the deltas it was granted'
D4=$SCOURSH_SCRATCH/rpt-authz-affirmed
rm -rf "$D4"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D4"
D4=$SCOURSH_RUN_DIR
run_record use_engines true
run_record authorization_affirmed true
run_record authorization_source flag
run_record authorization_target fixture-target
run_record authorization_scope_target fixture-target
run_record authorization_at '2026-08-15T00:00:00Z'
run_record authorization_intensity active
run_record authorization_intrusive true
run_record authorization_authed true
run_record limits_relaxed 'intensity-ceiling:passive->active'
run_record limits_relaxed 'request-budget:5000->20000'
run_record limits_enforced 'payloads:detection-only'
report_run_json "$D4"
J4=$(cat "$D4/run.json")
assert_contains "$J4" '"use_engines": true' 'use_engines renders true when the flag was given'
assert_contains "$J4" '"affirmed": true' 'the affirmation is recorded'
assert_contains "$J4" '"affirmation_source": "flag"' 'and the route it came by'
assert_contains "$J4" '"affirmed_at": "2026-08-15T00:00:00Z"' 'and when'
assert_contains "$J4" '"intensity": "active"' 'and the intensity it ran at'
assert_contains "$J4" '"intrusive": true' \
  'and whether side-effecting checks were on - FAILS if intrusive and authed are treated as run flags rather than authorisation facts, which leaves the record unable to distinguish an authenticated active scan from an unauthenticated crawl'
assert_contains "$J4" '"authed": true' 'and whether it was authenticated'
assert_contains "$J4" 'intensity-ceiling:passive->active' 'the intensity delta is rendered'
assert_contains "$J4" 'request-budget:5000->20000' 'and the budget delta'
assert_eq '' "$(printf '%s' "$J4" | grep -o '"operator": "[^"]\+"' || true)" \
  'and NO operator identity is attached when SCOURSH_OPERATOR is unset - FAILS if it is harvested from `id -un` and the hostname, which quietly attaches a username and machine name to an artifact frequently handed to a third party'

# =============================================================================
printf '\n-- docs/STEP-GUIDE-PLAN.md GUIDE-06: run.json'"'"'s config object --\n'
# =============================================================================
# scan.sh's `_scan_record_config` is the writer (one `config_value_<key>`/
# `config_source_<key>` meta-fact pair per scanner.conf key, plus the two
# sha256 facts); `_report_config_json` here is the only reader.  These cases
# drive the reader directly against hand-written meta facts, the same way the
# authorization-object cases above do, rather than through a real scan.sh
# invocation - the ROUND-TRIP claim itself (that two different routes to the
# SAME flags render the SAME object) is tests/suites/scan.sh's own
# load-bearing case; this file's job is only "the renderer renders what was
# recorded, completely and correctly".
D7=$SCOURSH_SCRATCH/rpt-config
rm -rf "$D7"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D7"
D7=$SCOURSH_RUN_DIR
run_record config_scanner_conf_sha256 def456
run_record config_scope_conf_sha256 abc123
run_record config_value_jobs 4
run_record config_source_jobs default
run_record config_value_fail-on medium
run_record config_source_fail-on cli
run_record config_value_requests-per-second 20
run_record config_source_requests-per-second cli
run_record config_value_formats json
run_record config_value_formats html
run_record config_source_formats file
report_run_json "$D7"
J7=$(cat "$D7/run.json")

t_case 'the config object is present, with both sha256 digests'
assert_contains "$J7" '"config": {' 'run.json carries a config object'
assert_contains "$J7" '"scanner_conf_sha256": "def456"' \
  'ties the run to the exact config/scanner.conf bytes - FAILS under "the argv alone is reproducible", which the plan explicitly rejects: the same argv against a different scanner.conf is a materially different scan'
assert_contains "$J7" '"scope_conf_sha256": "abc123"' 'and to config/scope.conf too, alongside authorization'"'"'s own copy of the same digest'

t_case 'a recorded key renders its value AND its resolution source'
assert_contains "$J7" '"jobs": {"value": "4", "source": "default"}' \
  'a default-sourced key renders both fields'
assert_contains "$J7" '"fail-on": {"value": "medium", "source": "cli"}' \
  'a CLI-sourced key too - FAILS under recording the value alone, which is exactly the gap the plan names: "the SAME printed command therefore produces a materially different scan on a different machine" is only detectable if the SOURCE is visible, not only the value'
assert_contains "$J7" '"requests-per-second": {"value": "20", "source": "cli"}' \
  'the one key GUIDE-04 already gave a CLI flag renders identically to any other'

t_case 'a key never recorded for this run still renders, as an honest empty value/source pair'
assert_contains "$J7" '"http-timeout": {"value": "", "source": ""}' \
  'FAILS under a key silently dropped from the object, which would make "every scanner key" a claim this run.json cannot back up - an absent key is ambiguous between "resolved to empty" and "this version forgot to ask"'

t_case 'a list-cardinality key (formats) renders as a JSON array, in RECORDED order'
assert_contains "$J7" '"formats": {"value": ["json","html"], "source": "file"}' \
  'FAILS if a repeatable key were flattened to a single scalar the way every other key is'

t_case 'a list key never recorded renders as an empty array, not a missing key or a null'
assert_contains "$J7" '"paranoid-allow": {"value": [], "source": ""}' \
  'the same honesty rule as the scalar case above, applied to the list shape'

t_case 'keys render in one fixed, alphabetically-sorted order - byte order is part of the reproducibility claim'
assert_contains "$J7" '"circuit-breaker-failures"' 'spot check: an early key in the sort order is present'
CFG_BLOCK=$(sed -n '/^  "config": {$/,/^  },$/p' "$D7/run.json")
JOBS_POS=$(printf '%s' "$CFG_BLOCK" | grep -n '"jobs":' | head -1 | cut -d: -f1)
FAILON_POS=$(printf '%s' "$CFG_BLOCK" | grep -n '"fail-on":' | head -1 | cut -d: -f1)
assert_eq 1 "$(( FAILON_POS < JOBS_POS ))" \
  '"fail-on" sorts before "jobs" (LC_ALL=C) - FAILS under an unsorted or recording-order rendering, which would make the SAME resolved settings produce two different-looking (though logically equal) config objects depending on which key happened to resolve first'

t_case 'the rendered run.json (config object included) is still valid JSON'
if command -v python3 >/dev/null 2>&1; then
  rc=0
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$D7/run.json" || rc=$?
  assert_eq 0 "$rc" \
    'FAILS on a stray or missing comma anywhere in the config object, which no string-containment assertion above would catch'
else
  printf '  NOTICE python3 is not on PATH: this JSON parse check did NOT run.  This is a SKIP, not a pass.\n'
fi

printf '\n-- DAST-34: an unrestricted run says so where a human will read it --\n'

t_case 'the markdown and HTML reports both banner the relaxations'
findings_merge "$D4"
report_all "$D4"
MD4=$(cat "$D4/report.md")
HT4=$(cat "$D4/report.html")
assert_contains "$MD4" 'This run was UNRESTRICTED' \
  'report.md leads with the banner - FAILS under "run.json is the audit surface, the report is for findings", which leaves the reader of the report unable to tell a target that handles load from a scanner told to ignore its own limits'
assert_contains "$MD4" 'request-budget:5000->20000' 'and names what was lifted, not merely that something was'
assert_contains "$HT4" 'This run was UNRESTRICTED' 'and so does report.html'
assert_contains "$HT4" 'is not evidence about the target' \
  'and both state the specific consequence: an ABSENCE of availability findings from an unrestricted run is not evidence (docs/DESIGN.md §15)'
assert_contains "$MD4" 'unrestricted run' \
  'and it also appears in the limitations section, which is where §15 requires a run to name its blind spots'
assert_contains "$HT4" '<strong>unrestricted run</strong>' 'same, in HTML'
assert_not_contains "$HT4" '<script' \
  'and the HTML report still contains no <script> element at all (docs/FOUNDATION.md tension 10) - the banner is plain text through the same escaping path as every other untrusted string'

t_case 'the banner fires on RELAXATION, never on the affirmation alone'
D5=$SCOURSH_SCRATCH/rpt-authz-keyonly
rm -rf "$D5"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D5"
D5=$SCOURSH_RUN_DIR
run_record authorization_affirmed true
run_record authorization_source flag
run_record authorization_scope_target fixture-target
report_all "$D5"
assert_not_contains "$(cat "$D5/report.md")" 'This run was UNRESTRICTED' \
  'an affirmed run that relaxed NOTHING gets no banner - FAILS under "banner whenever affirmed", which announces an unrestricted run that did not happen and teaches a reader to ignore the banner (the affirmation is a key, not a switch: --i-own-target alone changes no limit)'
assert_not_contains "$(cat "$D5/report.html")" 'This run was UNRESTRICTED' 'same, in HTML'

t_case 'a relaxation string is escaped like any other untrusted value'
D6=$SCOURSH_SCRATCH/rpt-authz-hostile
rm -rf "$D6"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D6"
D6=$SCOURSH_RUN_DIR
run_record authorization_scope_target '<img src=x onerror=alert(1)>'
run_record limits_relaxed 'request-budget:5000-><script>alert(1)</script>'
report_all "$D6"
HT6=$(cat "$D6/report.html")
assert_not_contains "$HT6" '<script>alert(1)</script>' \
  'a relaxation line composed from an operator-supplied --target id is escaped in the HTML banner - FAILS under "we wrote this string ourselves, so it is trusted", which is how an operator-controlled value reaches a report unescaped'
assert_contains "$HT6" '&lt;script&gt;' 'and it is rendered escaped rather than dropped, so the reader still sees what was recorded'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# ===========================================================================
# scoursh-spa-no-params-loud: zero discovered injection parameters (the
# single-page-app / API-behind-JavaScript case) is loud where a human reads
# results, not only a per-phase coverage_gap buried at the bottom of the
# report.
# ===========================================================================
printf '\n-- zero discovered parameters: the injection suite says so loudly, at the top --\n'

t_case 'zero parameters on every injection probe renders the full "nothing was injected" banner'
D9=$SCOURSH_SCRATCH/rpt-zero-params
rm -rf "$D9"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D9"
D9=$SCOURSH_RUN_DIR
run_record coverage_reduction 'module=dast reason=no_parameter_inventory target=t1 - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so SQL injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters.'
run_record coverage_reduction 'module=dast reason=no_parameter_inventory target=t1 - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so reflected XSS had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters.'
run_record coverage_reduction 'module=dast reason=no_parameter_inventory target=t1 - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so server-side template injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters.'
report_all "$D9"
MD9=$(cat "$D9/report.md")
HT9=$(cat "$D9/report.html")
assert_contains "$MD9" 'No injection test was actually sent' \
  'report.md leads with the loud zero-parameter banner - FAILS against current code, which only writes each phase'"'"'s own coverage_gap into the bottom-of-report Limitations section'
assert_contains "$MD9" 'this is NOT a clean result' \
  'the wording distinguishes "not tested" from "not vulnerable", the acceptance criterion this ticket exists for'
assert_contains "$MD9" 'config/discovery.conf' 'and names the concrete, verified way to supply the missing surface'
assert_contains "$MD9" 'openapi-path' 'naming the actual config/discovery.conf keys, not an invented flag'
assert_contains "$HT9" 'No injection test was actually sent' 'report.html carries the same banner'
assert_contains "$HT9" 'config/discovery.conf' 'and the same actionable pointer'
assert_not_contains "$HT9" '<script' 'the banner is plain text, no <script> anywhere in the report (tension 10)'

t_case 'a run with real discovered parameters does NOT show the zero-parameter banner'
D10=$SCOURSH_SCRATCH/rpt-real-params
rm -rf "$D10"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D10"
D10=$SCOURSH_RUN_DIR
run_record checks_run DAST-INJ-SQLI_ERROR-01
run_record checks_run DAST-INJ-XSS_REFLECTED_HTML-01
report_all "$D10"
assert_not_contains "$(cat "$D10/report.md")" 'No injection test was actually sent' \
  'a run whose injection checks actually ran against real parameters gets no banner'
assert_not_contains "$(cat "$D10/report.html")" 'No injection test was actually sent' 'same, in HTML'

t_case 'a partial-coverage run reports the truth, not a blanket claim'
D11=$SCOURSH_SCRATCH/rpt-partial-params
rm -rf "$D11"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D11"
D11=$SCOURSH_RUN_DIR
run_record coverage_reduction 'module=dast reason=no_parameter_inventory target=t1 - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so command injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters.'
run_record checks_run DAST-INJ-SQLI_ERROR-01
run_record checks_run DAST-INJ-SQLI_BOOLEAN-01
report_all "$D11"
MD11=$(cat "$D11/report.md")
assert_contains "$MD11" 'Partial injection coverage' \
  'a run that tested SOME parameters and missed others says so - FAILS under a blanket "nothing was tested" claim, which would misdescribe a run that has real injection findings'
assert_not_contains "$MD11" 'No injection test was actually sent' \
  'the full "nothing at all" wording must not also appear - the two claims are mutually exclusive'
assert_contains "$MD11" '1 of the discovered-parameter probes' 'and the count is the real, recorded one - one phase had zero parameters'
assert_contains "$MD11" '2 check(s)' 'against the real number that DID run - two distinct DAST-INJ-* ids in checks_run'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# ===========================================================================
# IMPORT-06: structured surface provenance in run.json - the endpoint/
# parameter surface broken down by `source`, as JSON keys a consumer can read
# rather than the `notes[]` prose (`spec_endpoints=N spec_kinds=[...]`)
# `modules/dast/crawl.sh` already wrote before this ticket, which is kept
# unchanged and NOT asserted against here.
# ===========================================================================
printf '\n-- IMPORT-06: structured surface provenance --\n'

t_case 'run.json renders per-source endpoint/parameter counts as structured keys, summed across every target this run recorded'
D12=$SCOURSH_SCRATCH/rpt-surface
rm -rf "$D12"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D12"
D12=$SCOURSH_RUN_DIR
# Two targets' worth of crawl.sh facts for the SAME source (openapi) - the
# honest total is their SUM, never just the first-seen line's value.
run_record dast_surface_endpoints_by_source "openapi"$'\x1f'"40"
run_record dast_surface_endpoints_by_source "openapi"$'\x1f'"2"
run_record dast_surface_endpoints_by_source "crawl"$'\x1f'"3"
run_record dast_surface_parameters_by_source "openapi"$'\x1f'"210"
run_record dast_surface_parameters_by_source "crawl"$'\x1f'"7"
report_all "$D12"
J12=$(cat "$D12/run.json")
assert_contains "$J12" '"dast_surface": {' 'run.json carries a dast_surface object'
assert_contains "$J12" '"endpoints_total": 45' \
  'the total SUMS every target'"'"'s contribution for a repeated source (40+2) plus the other source (3) - FAILS under a reader that keeps only the first-seen line per key (_meta_first), which would report 43'
assert_contains "$J12" '"endpoints_by_source": {"crawl":3,"openapi":42}' \
  'per-source counts are summed across targets AND rendered key-sorted (LC_ALL=C), matching the by_module object'"'"'s own convention, so two runs discovering the identical surface produce byte-identical JSON'
assert_contains "$J12" '"parameters_total": 217' 'and the same summing for parameters'
assert_contains "$J12" '"parameters_by_source": {"crawl":7,"openapi":210}' 'per-source parameter counts, sorted the same way'

t_case 'the rendered run.json is still valid JSON with the dast_surface object in it'
if command -v python3 >/dev/null 2>&1; then
  rc=0
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$D12/run.json" || rc=$?
  if [[ $rc -eq 0 ]]; then
    _t_ok 'run.json parses with dast_surface present'
  else
    _t_no 'run.json parses with dast_surface present' 'invalid JSON - FAILS on a stray or missing comma around the new object'
  fi
fi

t_case 'report.md renders a structured surface line a reader can see without scraping notes[]'
MD12=$(cat "$D12/report.md")
assert_contains "$MD12" 'surface: 45 endpoint(s)' 'the total endpoint count is rendered as prose'
assert_contains "$MD12" '3 from the static crawl' 'naming the crawl-sourced share'
assert_contains "$MD12" '42 from an openapi spec you supplied' \
  'and the openapi-sourced share, matching the ticket'"'"'s own acceptance criterion wording'
assert_contains "$MD12" '217 parameter(s)' 'and the parameter total alongside it'
HT12=$(cat "$D12/report.html")
assert_contains "$HT12" 'surface: 45 endpoint(s)' 'report.html carries the identical summary'
assert_not_contains "$HT12" '<script' 'still no <script> anywhere in the report (tension 10)'

t_case 'a run with no discovered surface renders no surface line at all'
assert_not_contains "$MD9" 'surface:' \
  'FAILS if the summary unconditionally prints a "surface: 0 endpoint(s)" line, which would misreport a run this ticket does not touch (the zero-parameter-banner fixture above, which never recorded any dast_surface_* fact) as one where the concept applies'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# ===========================================================================
printf -- '\n-- report-audit.html: the scoursh-audit-report coverage report --\n'
# ===========================================================================
# Captain decisions (scoursh-audit-report ticket):
#   1. ALONGSIDE - a NEW report-audit.html, report.html unchanged.
#   2. FULL not-covered detail - every not-run check listed by id, with its
#      own reason, never a count alone.
#   3. checks_run semantics fixed FIRST (modules/sast/engine.sh's
#      sast_record_checks_run, tested directly in tests/suites/sast.sh and
#      tests/suites/iac.sh) - this suite tests the RENDERER reading that
#      honest data, not the semantics fix itself.
#
# SCOURSH_INSTALL_ROOT is set to the real repo root so `checks_registry_load`
# resolves REAL check ids/titles (modules/sast/rules/secrets.rules,
# crypto.rules, python.rules, javascript.rules) - this is what proves the
# renderer against real run data rather than invented fixture ids.
D13=$SCOURSH_SCRATCH/rpt-audit
rm -rf "$D13"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D13"
D13=$SCOURSH_RUN_DIR
SCOURSH_INSTALL_ROOT=$ROOT

# A hostile evidence payload on the one finding that DOES fire, reusing the
# same tension-10 vectors report.html's own suite already proves against
# (script-close, an onerror image, and a run of backticks that would break a
# naive fenced-code-block escape). The FIRING check is deliberately NOT a
# secrets-family id (`finding_check_is_secret_family`, lib/findings.sh):
# tension 9's `_finding_secret_backstop` redacts evidence at `finding_emit`
# for any check matching `*-SEC-*`/`*SECRET*`/`*API_KEY*`/... REGARDLESS of
# which setter was called, so a hostile payload set on e.g.
# SAST-SEC-AWS_AKID-01 would be replaced with a `<redacted:SECRET:...>`
# placeholder before this test ever saw it - the correct, intended behaviour
# of that backstop, and the wrong check id to use for proving THIS report's
# own escaping path. SAST-CRY-HARDCODED_IV-01 (crypto family, not secrets)
# is unaffected by it.
HOSTILE13=$(printf '</script><img src=x onerror=alert(7)>``````fence')
finding_new
finding_set check_id SAST-CRY-HARDCODED_IV-01
finding_set module sast
finding_set title 'Hardcoded initialization vector or salt'
finding_set base_severity medium
finding_set cwe CWE-329
finding_set owasp A04:2025
finding_set loc_path app.py
finding_set loc_line 9
finding_set cell .
finding_set_match 'iv = "0102030405060708090a0b0c0d0e0f10"'
finding_set_evidence "$HOSTILE13"
finding_set remediation 'Generate the IV fresh per operation.'
finding_emit
findings_merge "$D13"

# The honest per-check bookkeeping a real scan.sh sast run would leave behind
# (this suite tests the RENDERER; tests/suites/sast.sh proves the ENGINE
# writes exactly this shape). Four real ids, one per bucket:
#   SAST-CRY-HARDCODED_IV-01 found    (the finding above)
#   SAST-SEC-AWS_AKID-01     clean    (selected, ran, nothing fired)
#   SAST-PY-EVAL_EXEC-01     not run  (filtered out before dispatch)
#   SAST-JS-EVAL-01          not run  (evaluated as not applicable - the
#                                       checks_run semantics fix's own
#                                       no_matching_files reduction shape)
run_record checks_selected SAST-CRY-HARDCODED_IV-01
run_record checks_selected SAST-SEC-AWS_AKID-01
run_record checks_selected SAST-JS-EVAL-01
run_record checks_run SAST-CRY-HARDCODED_IV-01
run_record checks_run SAST-SEC-AWS_AKID-01
run_record skipped_checks 'check=SAST-PY-EVAL_EXEC-01 skipped_by=profile-scan=quick'
run_record coverage_reduction 'module=sast reason=no_matching_files checks=[SAST-JS-EVAL-01] - none of the files under this scan root matched this check'"'"'s files: glob, so its pattern was never evaluated. It is NOT covered by this run.'

report_all "$D13"

t_case 'report-audit.html is opt-in: report_all with the default format list does NOT write it'
assert_file_absent "$D13/report-audit.html" \
  'SCOURSH_FORMATS was never set, so the default json,sarif,html,md list applies - fails if audit were ever added to the default list, which would make it non-opt-in'

t_case 'captain decision 1: report.html is byte-for-byte unaffected by the audit report existing'
H13_BEFORE=$(cat "$D13/report.html")
SCOURSH_FORMATS=json,sarif,html,md,audit report_all "$D13"
assert_file_exists "$D13/report-audit.html" 'requesting the audit format writes report-audit.html'
assert_eq "$H13_BEFORE" "$(cat "$D13/report.html")" \
  'report.html renders identically whether or not audit was also requested - fails if report_audit shared any state or CSS/markup with report_html'

A13=$(cat "$D13/report-audit.html")

t_case 'no <script>, and the CSP/self-contained posture report.html already proves, holds here too'
assert_not_contains "$A13" '<script' 'no script element anywhere in report-audit.html'
assert_contains "$A13" 'Content-Security-Policy' 'the CSP meta tag is present'
assert_contains "$A13" "default-src 'none'" 'default-src none'
assert_not_contains "$A13" 'http://' 'no external http reference'
assert_not_contains "$A13" 'https://' 'no external https reference'

t_case 'XSS-safe escaping: the hostile evidence on the one real finding is escaped into a text node, and never appears raw'
assert_contains "$A13" '&lt;/script&gt;&lt;img src=x onerror=alert(7)&gt;' \
  'the hostile evidence is HTML-escaped - fails if report_audit re-derived evidence instead of reading it through the real finding_decode/html_escape path this file also uses for report.html'
assert_not_contains "$A13" '<img src=x onerror' 'and no live onerror-bearing tag reaches the document'
assert_not_contains "$A13" '</script><img' 'and no live script-closing sequence reaches the document either'

t_case 'coverage matrix: the four real ids land in exactly the four states the design calls for'
assert_contains "$A13" '<table class="matrix">' 'the coverage matrix table renders'
assert_contains "$A13" '<td class="num">4</td><td class="num">2</td><td class="num"><span class="cellnum">1</span><span class="cellsub">1 issue(s)</span></td><td class="num">1</td><td class="num">2</td><td class="num">0</td>' \
  'sast row reads reg=4 (2 selected+run, 1 selected-not-applicable, 1 skipped) ran=2 found=1 check with 1 issue clean=1 not-run=2 unaccounted=0 - fails under a reader that folds the not-applicable id into "unaccounted" instead of "not run", which would report unacc=1 here instead of 0'
assert_contains "$A13" '<span class="strength strong">strong</span>' \
  'SAST is now labelled strong-strength ran (the checks_run semantics fix), not weak'

t_case 'scoursh-report-ux: plain-language column headers replace the terse reg/ran/unacc labels'
assert_contains "$A13" 'Checks available' 'the reg column has a plain-language heading'
assert_contains "$A13" 'Checks run' 'so does the ran column'
assert_contains "$A13" 'Skipped (reason given)' 'the not-run column names what it means, not "not run"'
assert_contains "$A13" 'Not covered' 'and the unaccounted column reads "not covered", not "unacc"'
assert_contains "$A13" '<abbr title=' 'headers carry a hover tooltip with the fuller definition'

t_case 'scoursh-report-ux: a check-count and a finding-count are never presented as one bare number'
assert_contains "$A13" '<span class="cellnum">1</span><span class="cellsub">1 issue(s)</span>' \
  'the coverage matrix cell shows both the distinct-check count and the individual-finding count - fails if it collapsed back to a bare number, which is what read as a contradiction against report.html'"'"'s own per-finding counts for the same category'
assert_contains "$A13" 'checks with findings' 'the assurance-summary tile keeps its check-count label'
assert_contains "$A13" 'tilesub">1 individual finding(s)</div>' \
  'and states the individual-finding total right next to it, rather than leaving the reader to reconcile it against a different tile'

t_case 'scoursh-report-ux: a genuinely plain-English one-line summary is generated per category'
assert_contains "$A13" '<h3>In plain terms</h3>' 'the plain-terms section renders'
assert_contains "$A13" 'Of 4 possible code checks, 2 ran (1 check(s) found 1 issue(s), 1 clean), 2 were skipped with a reason.' \
  'the generated sentence states both the check count and the finding count, and never claims the unaccounted bucket is 0 by silence'
assert_contains "$A13" 'class="plainline"' \
  'the identical sentence also appears at the top of the category'"'"'s own section, where a reader who jumped straight there via a nav pill still sees it'

t_case 'captain decision 2: FULL not-covered detail - both not-run reasons are listed BY ID, never only a count'
assert_contains "$A13" '<td class="id">SAST-PY-EVAL_EXEC-01</td>' 'the profile-filtered check is named'
assert_contains "$A13" 'Use of eval() or exec() on request-derived data' \
  'with its real registry title, so a quiet/absent check still says what it looks for'
assert_contains "$A13" 'profile-scan=quick' 'and its own real skipped_by reason, not a generic label'
assert_contains "$A13" '<td class="id">SAST-JS-EVAL-01</td>' 'the not-applicable check is ALSO named'
assert_contains "$A13" 'reason=no_matching_files' \
  'with the real coverage_reduction reason token naming it - the same convention modules/dast/passive/headers.sh already established for its own not-applicable checks'
assert_not_contains "$A13" '<span class="tag gap">Unaccounted</span>' \
  'the Unaccounted block does not render at all here - every registered check has a named reason, so there is nothing in that bucket to warn about'

t_case 'found and clean checks render with their real registry titles'
assert_contains "$A13" '<code>SAST-CRY-HARDCODED_IV-01</code>' 'the fired check is named in the Found issues group'
assert_contains "$A13" 'Hardcoded initialization vector or salt' 'with its real registry title'
assert_contains "$A13" '<td class="id">SAST-SEC-AWS_AKID-01</td>' 'the clean check is named in the Clean table'
assert_contains "$A13" 'Hardcoded AWS access key id' 'with ITS real registry title too'

t_case 'the DAST/IaC/SCA/Cloud sections still render for a sast-only run, declaring they did not run'
assert_contains "$A13" 'id="cat-dast"' 'the DAST section exists'
assert_contains "$A13" 'id="cat-cloud"' 'the Cloud / AWS section exists'
assert_contains "$A13" 'This category did not run.' 'and at least one of them says so plainly'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID='' SCOURSH_FORMATS=''

# ===========================================================================
# scoursh-report-ux: report.html groups live findings by category (SAST/SCA/
# IaC/DAST/AWS) with a jump-link chip per category, and a CSS-only (:has(),
# no JavaScript) severity filter that targets the exact `data-sev` attribute
# `_html_one_finding` already sets on every `details.f`.
# ===========================================================================
printf -- '\n-- report.html: category grouping + severity filter --\n'
D14=$SCOURSH_SCRATCH/rpt-groups
rm -rf "$D14"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D14"
D14=$SCOURSH_RUN_DIR

finding_new
finding_set check_id SAST-GRP-01
finding_set module sast
finding_set title 'sast finding'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set loc_path a.py
finding_set cell .
finding_set_match x
finding_set_evidence e
finding_set remediation r
finding_emit

finding_new
finding_set check_id IAC-GRP-01
finding_set module iac
finding_set title 'iac finding'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path b.tf
finding_set cell .
finding_set_match x
finding_set_evidence e
finding_set remediation r
finding_emit

finding_new
finding_set check_id SCA-GRP-01
finding_set module sca
finding_set title 'sca finding'
finding_set base_severity medium
finding_set cwe none
finding_set owasp none
finding_set loc_ecosystem npm
finding_set loc_package example
finding_set loc_advisory_id FIXTURE-GRP
finding_set path package-lock.json
finding_set cell .
finding_set_evidence e
finding_emit

finding_new
finding_set check_id DAST-GRP-01
finding_set module dast
finding_set title 'dast finding one'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_target t1
finding_set loc_method GET
finding_set path /p
finding_set cell t1
finding_set_evidence e
finding_set remediation r
finding_emit

finding_new
finding_set check_id DAST-GRP-02
finding_set module dast
finding_set title 'dast finding two'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_target t1
finding_set loc_method GET
finding_set path /q
finding_set cell t1
finding_set_evidence e
finding_set remediation r
finding_emit

findings_merge "$D14"
report_all "$D14"
H14=$(cat "$D14/report.html")

t_case 'category chips: one per present module, each carrying its own real finding count'
assert_contains "$H14" 'class="catnav"' 'the quick-jump chip row renders'
assert_contains "$H14" '<a class="catpill" href="#mod-sast">SAST <span class="c">1</span></a>' 'SAST chip carries its own finding count'
assert_contains "$H14" '<a class="catpill" href="#mod-sca">SCA <span class="c">1</span></a>' 'SCA chip too'
assert_contains "$H14" '<a class="catpill" href="#mod-iac">IaC <span class="c">1</span></a>' 'IaC chip too'
assert_contains "$H14" '<a class="catpill" href="#mod-dast">DAST <span class="c">2</span></a>' \
  'the DAST chip counts BOTH of its findings, not the number of distinct checks - the same check-vs-finding distinction report-audit.html now states explicitly'

t_case 'findings are grouped under their own category, in canonical order regardless of emission order'
assert_contains "$H14" 'id="mod-sast"' 'a SAST group exists'
assert_contains "$H14" 'id="mod-sca"' 'an SCA group exists'
assert_contains "$H14" 'id="mod-iac"' 'an IaC group exists'
assert_contains "$H14" 'id="mod-dast"' 'a DAST group exists'
SAST_POS=$(grep -bo 'id="mod-sast"' <<<"$H14" | head -1 | cut -d: -f1)
SCA_POS=$(grep -bo 'id="mod-sca"' <<<"$H14" | head -1 | cut -d: -f1)
IAC_POS=$(grep -bo 'id="mod-iac"' <<<"$H14" | head -1 | cut -d: -f1)
DAST_POS=$(grep -bo 'id="mod-dast"' <<<"$H14" | head -1 | cut -d: -f1)
ORDER_OK=false
if (( SAST_POS < SCA_POS && SCA_POS < IAC_POS && IAC_POS < DAST_POS )); then ORDER_OK=true; fi
assert_true "$ORDER_OK" \
  'renders SAST, then SCA, then IaC, then DAST, however the underlying findings.fields ordered them - fails under "render in findings.fields order", which would make the section order depend on incidental merge/sort behaviour'

t_case 'each category group shows its own severity breakdown'
assert_contains "$H14" '<div class="sevbreak"><span class="sev critical">1 critical</span></div>' \
  'the SAST group states its one critical finding'
assert_contains "$H14" '<div class="sevbreak"><span class="sev low">2 low</span></div>' \
  'the DAST group states both of its findings are low, not just a bare count'

t_case 'the severity filter is CSS-only and targets the exact data-sev attribute every finding already carries'
assert_contains "$H14" 'id="sv-all"' 'the "All" filter option exists'
assert_contains "$H14" 'id="sv-crit"' 'the critical filter radio exists'
assert_contains "$H14" 'id="sv-high"' 'the high+ filter radio exists'
assert_contains "$H14" 'id="sv-med"' 'the medium+ filter radio exists'
assert_contains "$H14" 'id="sv-low"' 'the low+ filter radio exists'
assert_contains "$H14" 'body:has(#sv-crit:checked) details.f:not([data-sev="critical"])' \
  'the hide rule targets details.f[data-sev], the exact attribute _html_one_finding already sets on every finding - no JavaScript is involved anywhere'
assert_contains "$H14" 'data-sev="critical"' 'and the SAST finding really does carry that attribute'
assert_contains "$H14" 'data-sev="low"' 'as does a DAST one'
assert_not_contains "$H14" '<script' 'still no <script> element anywhere, even with the filter added'

t_case 'no horizontal page overflow: wide tables scroll in their own container, not the page'
assert_contains "$H14" '<div class="scroll"><table><tr><th>module</th>' \
  'the by-module table is wrapped in a horizontally-scrollable box rather than left free to overflow the page'
assert_contains "$H14" '.scroll { overflow-x: auto;' 'and the CSS backing that box is actually shipped'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary report
