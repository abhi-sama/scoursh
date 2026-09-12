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
  'SCOURSH_FORMATS was never set, so the default json,sarif,html,md,agent list applies - fails if audit were ever added to the default list, which would make it non-opt-in'

t_case 'agent-fix.json IS written with no --format given: it is a first-class deliverable, in the default list'
assert_file_exists "$D13/agent-fix.json" \
  'SCOURSH_FORMATS was never set, so the default json,sarif,html,md,agent list applies - fails if agent were ever dropped from the default list'

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

printf -- '\n-- HONESTY FIX: the audit report'"'"'s per-category "did not run" fallback uses abort_reason too --\n'
# Same fixture shape as above (SAST-only coverage, D13'"'"'s own real ids and
# registry), but with meta/abort_reason also recorded - the DAST/Cloud
# sections above never had ANY coverage_reduction line naming them either, so
# they fell back to the uninformative "No coverage was recorded for it."
# text. When the run actually aborted before dispatching them, that fallback
# is exactly the honesty gap this ticket exists to close.
run_record abort_reason 'exit=3 scope gate refused GET https://bad-target.example: destination not in scope.conf'
SCOURSH_FORMATS=json,sarif,html,md,audit report_all "$D13"
A13B=$(cat "$D13/report-audit.html")

t_case 'a category with no coverage_reduction of its own states the captured abort reason instead of a generic fallback'
assert_contains "$A13B" 'id="cat-dast"' 'the DAST section still exists'
assert_contains "$A13B" 'The run aborted before it could be dispatched: exit=3 scope gate refused' \
  'names the real abort reason - FAILS if the generic "No coverage was recorded for it." text were shown despite a recorded reason'

t_case 'a category that DOES have its own coverage_reduction line keeps naming that reason, not the run-level abort'
assert_contains "$A13B" 'reason=no_matching_files' \
  'the SAST-JS-EVAL-01 not-applicable reason from earlier in this fixture is unaffected by abort_reason existing elsewhere in the same run'

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

# ===========================================================================
# docs/STEP10-SARIF-PLAN.md Track B - COMPLIANCE-01 (the OWASP category label
# table and its expansion) and COMPLIANCE-02 (the OWASP compliance view in
# report.md and report.html).
# ===========================================================================
printf -- '\n-- COMPLIANCE-01: the OWASP category label table and its expansion --\n'

t_case 'a known id expands to its published Top 10 2021 category label'
assert_eq 'Broken Access Control' "$(owasp_category_label A01:2021)" \
  'A01:2021 is the OWASP Top 10 2021 label data/owasp-categories.conf carries'
assert_eq 'known' "$(owasp_category_known A01:2021)" 'and its state is `known`'

t_case '`none` is a legal value, counted separately from an unknown id - never a table lookup'
assert_eq 'Not categorised' "$(owasp_category_label none)" \
  '`none` expands directly, per §9.6.6 - it is never looked up in the table'
assert_eq 'none' "$(owasp_category_known none)" \
  'and its state is the distinct literal `none`, not `unknown`'

t_case 'an id with no row degrades visibly - never blank, never an invented label'
UNKNOWN_LABEL=$(owasp_category_label A99:2099)
assert_contains "$UNKNOWN_LABEL" 'A99:2099' \
  'the bare id survives into the rendered label - FAILS under a blank expansion, which would be indistinguishable from a rendering bug'
assert_ne '' "$UNKNOWN_LABEL" 'never blank'
assert_ne 'Not categorised' "$UNKNOWN_LABEL" \
  'and never confused with `none` - a category the table has never heard of is a different fact from "not categorised"'
assert_eq 'unknown' "$(owasp_category_known A99:2099)" \
  'its state is `unknown`, distinct from both `known` and the `none` literal'

# ===========================================================================
# docs/STEP10-SARIF-PLAN.md Track B - COMPLIANCE-03 (data/cis-mappings: the
# format, the vendored table, and its id -> label loader/lookup).  This
# ticket lands the table and renders nothing - there is no report section to
# test here, only the loader/lookup functions COMPLIANCE-04 will consume.
# ===========================================================================
printf -- '\n-- COMPLIANCE-03: data/cis-mappings, the CIS control label table --\n'

t_case 'a known id expands to its published CIS v3.0.0 short title'
assert_eq "Ensure no 'root' user account access key exists" "$(cis_control_label 1.4)" \
  '1.4 is the CIS AWS Foundations Benchmark v3.0.0 title data/cis-mappings carries'
assert_eq 'known' "$(cis_control_known 1.4)" 'and its state is `known`'

t_case 'the benchmark name and version are present on the table, and are exposed'
assert_eq 'CIS Amazon Web Services Foundations Benchmark' "$(cis_benchmark_name)" \
  'the benchmark name is carried as data on the first record (rules/RULE-FORMAT.md §9.6.7)'
assert_eq '3.0.0' "$(cis_benchmark_version)" \
  'the benchmark version is carried as data on the first record, per the captain'"'"'s D4 decision'

t_case 'an id with no row degrades visibly - never blank, never an invented label'
UNKNOWN_CIS_LABEL=$(cis_control_label 99.99)
assert_contains "$UNKNOWN_CIS_LABEL" '99.99' \
  'the bare id survives into the rendered label - FAILS under a blank expansion, which would be indistinguishable from a rendering bug'
assert_ne '' "$UNKNOWN_CIS_LABEL" 'never blank'
assert_eq 'unknown' "$(cis_control_known 99.99)" \
  'its state is `unknown`, distinct from `known`'

t_case 'every id in the shipped table is unique, and the table parses/validates cleanly'
records_reset_diagnostics
if records_load "$ROOT/data/cis-mappings" cis-mapping cistbl >/dev/null 2>&1 \
  && records_validate cistbl >/dev/null 2>&1; then
  _t_ok 'data/cis-mappings parses and validates with no duplicate-id (E019) or id-form (E027) diagnostics'
else
  _t_no 'data/cis-mappings parses and validates cleanly' \
    "${RECORDS_DIAGNOSTICS[*]+"${RECORDS_DIAGNOSTICS[*]}"}"
fi
CIS_N=$(records_count cistbl)
assert_ne 0 "$CIS_N" 'the shipped table carries at least one control'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

printf -- '\n-- COMPLIANCE-02: the OWASP compliance view in report.md and report.html --\n'
# A fixture registry (tests/fixtures/checks-registry), not the real, growing
# catalog: this proves the three-way honesty split against KNOWN registry
# contents rather than coupling the test to today's snapshot of every shipped
# rule pack.  Its owasp values are fixed: A01:2021 (DAST-AUTHZ-OBJREF-01),
# A03:2021 (SAST-GEN-DEMO_QUICK-01, DAST-INJ-SQLI-01), A05:2021
# (DAST-HDR-CSP-01, DAST-HDR-HSTS-01), none (SAST-GEN-DEMO_FULL-01,
# DAST-DISC-CRAWL-01) - every OTHER OWASP Top 10 2021 id, A02/A04/A06/A07/
# A08/A09/A10, has ZERO checks in this fixture, so any one of them is a
# deterministic "out of scope" case.
D15=$SCOURSH_SCRATCH/rpt-owasp-compliance
rm -rf "$D15"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
SCOURSH_INSTALL_ROOT=$ROOT/tests/fixtures/checks-registry
run_init "$D15"
D15=$SCOURSH_RUN_DIR

# A03:2021 - a live finding: the "findings" bucket, grouped by category.
finding_new
finding_set check_id DAST-INJ-SQLI-01
finding_set module dast
finding_set title 'SQL injection via request parameter'
finding_set base_severity critical
finding_set cwe CWE-89
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /search
finding_set loc_param_location query
finding_set loc_param_name q
finding_set cell t1
finding_set remediation 'Use parameterised queries.'
finding_set_evidence 'q=1 OR 1=1'
finding_emit

# `none` - a live finding mapping to no OWASP category: its own tail section.
finding_new
finding_set check_id SAST-GEN-DEMO_FULL-01
finding_set module sast
finding_set title 'Fixture full-only rule'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path app.py
finding_set loc_line 4
finding_set cell .
finding_set_match 'demo_noop()'
finding_set remediation 'No fix required; this is a fixture.'
finding_emit

findings_merge "$D15"

# A05:2021 - assessed this run, no findings: the "clean" bucket.  Only ONE of
# its two registry checks needs to have run for the whole category to read
# assessed.
run_record checks_run DAST-HDR-CSP-01

# A01:2021 - filtered out of THIS run by the tension-15 chain: the "filtered"
# bucket, distinct from both "clean" and "out of scope".
run_record skipped_checks 'check=DAST-AUTHZ-OBJREF-01 skipped_by=intensity=passive'

report_all "$D15"
MD15=$(cat "$D15/report.md")
HT15=$(cat "$D15/report.html")

t_case 'report.md has an OWASP Top 10 compliance section, where it had none before'
assert_contains "$MD15" '## OWASP Top 10 compliance' 'the section heading is present'
assert_contains "$MD15" 'A01:2021' 'and every category id renders, including one with no live finding'

t_case 'report.md groups the findings themselves under their category, not merely a count'
assert_contains "$MD15" '### A03:2021 - Injection' 'A03:2021 carries its published label'
assert_contains "$MD15" 'DAST-INJ-SQLI-01' \
  'and the live finding'"'"'s own check id appears under that heading - FAILS under a summary that only counts'

t_case 'a category with a check that ran and found nothing reads assessed, not silently clean'
assert_contains "$MD15" '### A05:2021 - Security Misconfiguration' 'A05:2021 carries its published label'
assert_contains "$MD15" 'Assessed this run - no findings.' \
  'FAILS if this bucket were indistinguishable from "out of scope" or "filtered"'

t_case 'a category filtered out of this run by --profile-scan/--intensity renders that fact, not "clean"'
assert_contains "$MD15" '### A01:2021 - Broken Access Control' 'A01:2021 carries its published label'
assert_contains "$MD15" 'excluded from this run (intensity=passive)' \
  'names the real skipped_by reason - FAILS if a filtered category read the same as an assessed-clean one'

t_case 'a category with no check anywhere in this build targets it renders "out of scope", never a fabricated clean bill'
assert_contains "$MD15" '### A09:2021 - Security Logging and Monitoring Failures' 'A09:2021 carries its published label'
assert_contains "$MD15" 'No check in this build of scoursh targets this category yet.' \
  'FAILS if a category with zero registry checks read identically to one that was assessed and found nothing'

t_case 'a live finding mapping to `none` renders in its own, separately labelled section'
assert_contains "$MD15" '### none - Not categorised' 'the section exists'
assert_contains "$MD15" 'SAST-GEN-DEMO_FULL-01' 'and the finding itself appears under it'

t_case 'report.html carries the equivalent compliance section'
assert_contains "$HT15" 'id="owasp-compliance"' 'the section anchor exists'
assert_contains "$HT15" 'OWASP Top 10 compliance' 'with its heading'
assert_contains "$HT15" 'Broken Access Control' 'and every category label renders, not only the bare id'
assert_contains "$HT15" 'Security Logging and Monitoring Failures' 'including a category with no live finding at all'
assert_not_contains "$HT15" '<script' 'still no <script> element anywhere (tension 10)'

t_case 'the existing "By OWASP category" count table gains the label column, and keeps counting'
assert_contains "$HT15" '<th>category</th><th>label</th><th>findings</th>' \
  'the header names both the raw id and the label, side by side'
assert_contains "$HT15" '<td>A03:2021</td><td>Injection</td>' \
  'FAILS if the count table were replaced instead of kept, per this ticket'"'"'s own instruction'

printf -- '\n-- COMPLIANCE-04: the CIS compliance view in report.md and report.html --\n'
# A dedicated fixture registry (tests/fixtures/checks-registry/modules/cloud/
# aws/live/checks.rules, sibling to the DAST one COMPLIANCE-02 uses above),
# under the SAME SCOURSH_INSTALL_ROOT still in effect from that block. Its
# `cis:` values are real CIS AWS Foundations Benchmark v3.0.0 ids
# (data/cis-mappings, already loaded and memoized by the COMPLIANCE-03 case
# earlier in this file while SCOURSH_INSTALL_ROOT was still $ROOT - real
# labels and the real benchmark version therefore resolve here too, exactly
# as COMPLIANCE-02's A03:2021 "Injection" label does above), so this proves
# real labels grouping real findings rather than only the degrade-visibly
# path: 2.1.4 (findings), 2.1.1 (clean), 1.6 (not applicable to the account -
# a fixture CLOUD-S3-* check named in a coverage_reduction, never in
# checks_run), 1.8 (filtered by --profile-scan/--intensity), and 1.5 (out of
# scope - no fixture check anywhere cites it).
DCIS=$SCOURSH_SCRATCH/rpt-cis-compliance
rm -rf "$DCIS"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DCIS"
DCIS=$SCOURSH_RUN_DIR

# 2.1.4 - a live finding: the "findings" bucket, grouped by control.
finding_new
finding_set check_id CLOUD-S3-CIS_FIXTURE_PUBLIC-01
finding_set module cloud
finding_set title 'S3 bucket ACL grants read access to a public grantee group (fixture)'
finding_set base_severity high
finding_set cwe CWE-732
finding_set owasp A01:2021
finding_add cis 2.1.4
finding_set loc_account_id 111122223333
finding_set loc_region global
finding_set loc_resource_key arn:aws:s3:::fixture-bucket
finding_set loc_sub_key acl
finding_set cell 111122223333/global
finding_set remediation 'Remove the public grant.'
finding_set_evidence 'Grantee: AllUsers, Permission: READ'
finding_emit

findings_merge "$DCIS"

# 2.1.1 - assessed this run, no findings: the "clean" bucket.
run_record checks_run CLOUD-S3-CIS_FIXTURE_LOGGING-01

# 1.6 - the check ran but found no matching resource in the scanned account:
# the "not applicable" bucket, distinct from both "clean" and "out of scope".
# The exact prose modules/cloud/aws/live/s3.sh's own per-account roll-up
# emits (`_s3_record_coverage`'s singular, unbracketed `check=<id>` shape,
# not the bracketed `checks=[...]` list `_report_coverage_state` already
# reads for OTHER modules) - proving COMPLIANCE-04 reads the shape the
# module that unblocked it actually produces.
run_record coverage_reduction 'module=cloud reason=no_bucket_examined service=s3 check=CLOUD-S3-CIS_FIXTURE_MFA-01 account=111122223333 buckets_total=0 buckets_examined=0 - this check answered for NO bucket in the account and is therefore NOT recorded in checks_run.'

# 1.8 - filtered out of THIS run by the tension-15 chain: the "filtered"
# bucket, distinct from "not applicable" and "clean".
run_record skipped_checks 'check=CLOUD-S3-CIS_FIXTURE_PWPOLICY-01 skipped_by=intensity=passive'

report_all "$DCIS"
MDCIS=$(cat "$DCIS/report.md")
HTCIS=$(cat "$DCIS/report.html")

t_case 'report.md has a CIS compliance section, where it had none before'
assert_contains "$MDCIS" '## CIS compliance' 'the section heading is present'
assert_contains "$MDCIS" 'CIS Amazon Web Services Foundations Benchmark 3.0.0' \
  'and it states the benchmark name and version at the head of the section'

t_case 'report.md groups the findings themselves under their real control id, not merely a count'
assert_contains "$MDCIS" "### 2.1.4 - Ensure that S3 Buckets are configured with 'Block public access' setting" \
  '2.1.4 carries its published v3.0.0 title'
assert_contains "$MDCIS" 'CLOUD-S3-CIS_FIXTURE_PUBLIC-01' \
  'and the live finding'"'"'s own check id appears under that heading - FAILS under a summary that only counts'

t_case 'a control with a check that ran and found nothing reads assessed, not silently clean'
assert_contains "$MDCIS" '### 2.1.1 - Ensure S3 Bucket Policy is set to deny HTTP requests' \
  '2.1.1 carries its published title'
assert_contains "$MDCIS" 'Assessed this run - no findings.' \
  'FAILS if this bucket were indistinguishable from "out of scope" or "not applicable"'

t_case 'a control whose check ran but found no matching resource in the account renders that fact, never as clean'
assert_contains "$MDCIS" "### 1.6 - Ensure hardware MFA is enabled for the 'root' user account" \
  '1.6 carries its published title'
assert_contains "$MDCIS" 'no matching resource in the scanned account this run (no_bucket_examined)' \
  'names the real coverage_reduction reason - FAILS if a not-applicable control read the same as an assessed-clean one'

t_case 'a control filtered out of this run by --profile-scan/--intensity renders that fact, distinct from "not applicable"'
assert_contains "$MDCIS" '### 1.8 - Ensure IAM password policy requires minimum length of 14 or greater' \
  '1.8 carries its published title'
assert_contains "$MDCIS" 'excluded from this run (intensity=passive)' \
  'names the real skipped_by reason - FAILS if a filtered control read the same as a not-applicable one'

t_case 'a control with no check anywhere in this build targets it renders "out of scope", never a fabricated clean bill'
assert_contains "$MDCIS" "### 1.5 - Ensure MFA is enabled for the 'root' user account" \
  '1.5 carries its published title'
assert_contains "$MDCIS" 'No check in this build of scoursh targets this control yet.' \
  'FAILS if a control with zero registry checks read identically to one that was assessed and found nothing'

t_case 'report.html carries the equivalent CIS compliance section'
assert_contains "$HTCIS" 'id="cis-compliance"' 'the section anchor exists'
assert_contains "$HTCIS" 'CIS compliance' 'with its heading'
assert_contains "$HTCIS" 'CIS Amazon Web Services Foundations Benchmark' 'and states the benchmark name'
assert_contains "$HTCIS" "Ensure that S3 Buckets are configured with &#39;Block public access&#39; setting" \
  'and every control label renders, escaped, not only the bare id'
assert_contains "$HTCIS" "Ensure hardware MFA is enabled for the &#39;root&#39; user account" \
  'including the not-applicable control'
assert_not_contains "$HTCIS" '<script' 'still no <script> element anywhere (tension 10)'

printf -- '\n-- HONESTY FIX: meta/abort_reason and the OWASP/CIS not_run bucket --\n'
# A run that terminated early (lib/core.sh die(), usage/scope/input exit
# codes) now records WHY in its own `abort_reason` meta field, separate from
# `incomplete_reason` (that field's emptiness is exactly the exit-5 predicate,
# docs/FOUNDATION.md tension 14) - a scope/usage/input abort must never read
# as an incomplete run.
#
# PERFORMANCE FIX: a run with an empty `meta/checks_run` - which every one of
# these fixtures has, since none of them ever calls `run_record checks_run`
# - is now known, cheaply (one `[[ -s ]]` test), to have dispatched ZERO
# checks; `report_count` skips the ~9-10s OWASP/CIS registry walk entirely in
# that case (`_RPT_COMPLIANCE_SKIPPED`) rather than paying it to learn what a
# `[[ -s ]]` test already answered - "did anything run" is no for every
# category. The compliance sections below therefore render ONE honest
# statement instead of the old per-category table (which needed the walk to
# tell "checks exist but didn't run" apart from "no check exists"), and
# deliberately do NOT claim a category HAS registered checks that merely
# didn't run - a claim the skipped walk is the only way to make truthfully.
DABORT=$SCOURSH_SCRATCH/rpt-abort-reason
rm -rf "$DABORT"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DABORT"
DABORT=$SCOURSH_RUN_DIR
run_record abort_reason 'exit=3 scope gate refused GET https://bad-target.example: destination not in scope.conf'
report_all "$DABORT"
MDA=$(cat "$DABORT/report.md")
HTA=$(cat "$DABORT/report.html")
JSA=$(cat "$DABORT/run.json")

t_case 'run.json records abort_reason verbatim, as its own field, separate from incomplete_reason'
assert_contains "$JSA" '"abort_reason"' 'the field exists'
assert_contains "$JSA" 'scope gate refused GET https://bad-target.example' \
  'and carries the real reason, byte for byte'
assert_contains "$JSA" '"incomplete_reason": []' \
  'and incomplete_reason stays EMPTY - FAILS if an abort reason were folded into the exit-5 field'

t_case 'the OWASP section states the abort reason instead of the per-category table, in report.md'
assert_contains "$MDA" '## OWASP Top 10 compliance' 'the section heading is still present'
assert_contains "$MDA" 'This scan aborted before any category could be assessed: exit=3 scope gate refused' \
  'names the real abort reason - FAILS if the honest fallback text were shown despite a recorded reason'
assert_not_contains "$MDA" '### A01:2021' \
  'and no per-category heading appears - FAILS if the expensive registry walk still ran'

t_case 'and in report.html'
assert_contains "$HTA" 'This scan aborted before any category could be assessed: exit=3 scope gate refused' \
  'the HTML compliance view renders the same reason'
assert_not_contains "$HTA" 'id="owasp-A01:2021"' \
  'and no per-category group renders there either'

t_case 'the CIS section states the same abort reason, in both formats'
assert_contains "$MDA" '## CIS compliance' 'the section heading is still present'
assert_contains "$MDA" 'This scan aborted before any control could be assessed: exit=3 scope gate refused' \
  'report.md names the real abort reason for CIS too'
assert_contains "$HTA" 'This scan aborted before any control could be assessed: exit=3 scope gate refused' \
  'report.html does the same'

t_case 'neither compliance section reads as clean or as "checks exist but did not run"'
assert_not_contains "$MDA" 'Assessed this run - no findings' \
  'FAILS if an aborted run with no coverage at all could still render a category/control as clean'
assert_not_contains "$MDA" 'Checks for this' \
  'and the skipped walk never claims a specific category/control HAS registered checks - that claim needs the walk this path exists to avoid'
assert_not_contains "$HTA" 'assessed - no findings' \
  'report.html carries the same guarantee'

t_case 'the Limitations section also states the run aborted, in both formats'
assert_contains "$MDA" '**run aborted**: exit=3 scope gate refused' 'report.md'
assert_contains "$HTA" '<strong>run aborted</strong>: exit=3 scope gate refused' 'report.html'

printf -- '\n-- OMISSION A FIX: the abort is stated ABOVE the counts, not only in OWASP/CIS/Limitations --\n'
# Before this fix an aborted report.md opened with `# scoursh scan report`,
# then straight into `- findings: 0 live, 0 accepted risk (0 total)`, an
# all-zero "Since last scan" block and severity table, and `## Findings` ->
# `_No findings._` - the abort was disclosed only much further down, in the
# OWASP/CIS sections and "Limitations and coverage". A reader who reads the
# top of the file and stops, or screenshots it, would take away a clean
# result from a run that never started. `_md_abort_banner`/
# `_html_abort_banner` (lib/report.sh) are additive - none of the assertions
# above are affected - and sit before every count. Split on the exact text
# every count line is introduced by, so this FAILS if the banner were ever
# moved below either marker, not merely absent.
MDA_ABOVE_COUNTS=${MDA%%- findings:*}
t_case 'report.md states the abort before the findings-count line'
assert_contains "$MDA_ABOVE_COUNTS" 'THIS RUN DID NOT COMPLETE' \
  'FAILS if the banner is missing, or rendered only below the counts'
assert_contains "$MDA_ABOVE_COUNTS" 'exit=3 scope gate refused GET https://bad-target.example' \
  'and it carries the real abort_reason, not a generic placeholder'

HTA_ABOVE_COUNTS=${HTA%%live findings*}
t_case 'report.html states the abort before the "N live findings" summary line'
assert_contains "$HTA_ABOVE_COUNTS" 'THIS RUN DID NOT COMPLETE' \
  'FAILS if the banner is missing, or rendered only below the summary paragraph'
assert_contains "$HTA_ABOVE_COUNTS" 'exit=3 scope gate refused GET https://bad-target.example' \
  'and it carries the real abort_reason there too'

t_case 'the abort banner never removes the lower-down disclosures - it is additive'
assert_contains "$MDA" 'This scan aborted before any category could be assessed' \
  'the OWASP section still states the abort, unchanged by the new banner'
assert_contains "$MDA" '**run aborted**: exit=3 scope gate refused' \
  'and so does the Limitations section'

printf -- '\n-- and the honest fallback survives when nothing was actually captured --\n'
DNOABORT=$SCOURSH_SCRATCH/rpt-no-abort-reason
rm -rf "$DNOABORT"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DNOABORT"
DNOABORT=$SCOURSH_RUN_DIR
report_all "$DNOABORT"
MDN=$(cat "$DNOABORT/report.md")
HTN=$(cat "$DNOABORT/report.html")

t_case 'no checks_run and no abort_reason keeps an honest fallback text, never a fabricated reason'
assert_contains "$MDN" 'no reason was recorded' \
  'FAILS if the fallback text were removed even when nothing was actually captured - a check simply not selected must not read like an abort'
assert_not_contains "$MDN" 'This scan aborted before any' \
  'and no fabricated abort claim appears in report.md where none was recorded'
assert_contains "$HTN" 'no reason recorded' \
  'and report.html keeps the same honest fallback'
assert_not_contains "$HTN" 'This scan aborted before any' \
  'and no fabricated abort claim appears in report.html where none was recorded'
assert_not_contains "$MDN" 'THIS RUN DID NOT COMPLETE' \
  'the top-of-report abort banner is never fabricated either, in report.md'
assert_not_contains "$HTN" 'THIS RUN DID NOT COMPLETE' \
  'or in report.html'

printf -- '\n-- and a PARTIAL abort (some modules ran, one then aborted) still gets the full per-category walk --\n'
# A combined `scan.sh all` where earlier modules completed (so checks_run is
# non-empty) and a later one then aborts must NOT take the fast path above -
# the categories the completed modules covered are real information the
# skip must never discard. Reuses the DABORT fixture's own abort_reason.
DPARTIAL=$SCOURSH_SCRATCH/rpt-partial-abort
rm -rf "$DPARTIAL"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DPARTIAL"
DPARTIAL=$SCOURSH_RUN_DIR
run_record checks_run DAST-AUTHZ-OBJREF-01
run_record abort_reason 'exit=3 scope gate refused GET https://bad-target.example: destination not in scope.conf'
report_all "$DPARTIAL"
MDP=$(cat "$DPARTIAL/report.md")

t_case 'a partial run (some checks_run, then an abort) still renders the per-category table, not the fast-path summary'
assert_contains "$MDP" '### A01:2021 - Broken Access Control' \
  'FAILS if a non-empty checks_run were ever routed onto the zero-coverage fast path'
assert_not_contains "$MDP" 'This scan aborted before any category could be assessed' \
  'the fast-path sentence must never appear once at least one check genuinely ran'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
SCOURSH_INSTALL_ROOT=$ROOT

# =============================================================================
printf -- '\n-- REGRESSION: report_agent must run on the die() abort path too --\n'
# =============================================================================
# `die()` (lib/core.sh) exits the process directly, and its own abort-refresh
# path (`run_json_refresh_incomplete`) used to re-render only run.json,
# report.md and report.html - `report_agent`, the ONLY writer of
# agent-fix.json, is reached exclusively via `report_all`'s
# `_report_render_formats`, which never runs once `die()` has fired. So on
# ANY aborted run (exit 2/3/4/5) NO agent-fix.json was written at all, even
# though `meta/abort_reason`/`meta/incomplete_reason` were correctly
# recorded. Unlike the fixtures above (which fabricate `abort_reason` by hand
# and call `report_all` directly - a fine way to test the RENDERER, but one
# that never goes anywhere near the actual bug), this drives the real `die()`
# call the same way tests/suites/state-coverage.sh's STATE-02 case does, so
# it exercises `run_json_refresh_incomplete` itself. FAILS under the pre-fix
# writer list (`report_run_json report_md report_html`) with agent-fix.json
# absent entirely; passes once `report_agent` is added to it.
DAGENTABORT=$SCOURSH_SCRATCH/rpt-agent-abort
rm -rf "$DAGENTABORT"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DAGENTABORT"
DAGENTABORT=$SCOURSH_RUN_DIR
(
  die "$SCOURSH_EXIT_SCOPE" \
    'scope gate refused GET https://bad-target.example: destination not in scope.conf'
) || true

t_case 'a fully pre-dispatch die() abort still writes agent-fix.json'
assert_file_exists "$DAGENTABORT/agent-fix.json" \
  'agent-fix.json exists after a die() abort with zero checks dispatched - FAILS if report_agent is never reached from the abort path'
AGJ=$(cat "$DAGENTABORT/agent-fix.json")
assert_contains "$AGJ" '"scoursh_agent":1' \
  'the document is the real report_agent shape, not a stub or a copy of run.json'
assert_contains "$AGJ" 'exit=3 scope gate refused GET https://bad-target.example' \
  "run.abort_reason carries the die() message verbatim, code-prefixed exactly as run.json's own abort_reason records it"
assert_contains "$AGJ" '"checks_run": []' \
  'run.checks_run is empty - no module ever dispatched a check (case (c): refused before anything ran)'
assert_contains "$AGJ" '"findings":[]' \
  'findings is empty - there is nothing in findings.fields for a pre-dispatch abort to have read'

t_case 'the abort is unmistakable to a machine reader - never rendered as a clean or complete result'
assert_not_contains "$AGJ" '"abort_reason": []' \
  'FAILS if abort_reason were empty despite the recorded die() call - that is exactly "never ran" collapsing into "clean", the ambiguity this fix exists to remove'

printf -- '\n-- and a PARTIAL die() abort (one check already ran) reports that finding alongside the abort --\n'
# case (b): some coverage exists before the abort, so a consumer must be able
# to tell this apart from BOTH a clean run (no abort_reason at all) and a
# full pre-dispatch refusal (checks_run empty) - by run.checks_run being
# non-empty here, exactly as docs/AGENT-FORMAT.md §4a now states.
DAGENTPARTIAL=$SCOURSH_SCRATCH/rpt-agent-abort-partial
rm -rf "$DAGENTPARTIAL"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DAGENTPARTIAL"
DAGENTPARTIAL=$SCOURSH_RUN_DIR
finding_new
finding_set check_id SAST-SEC-HARDCODED_PASSWORD-01
finding_set module sast
finding_set title 'Hardcoded password'
finding_set base_severity high
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path src/config.py
finding_set loc_line 12
finding_set cell .
finding_emit
findings_merge "$DAGENTPARTIAL"
run_record checks_run SAST-SEC-HARDCODED_PASSWORD-01
(
  die "$SCOURSH_EXIT_SCOPE" \
    'scope gate refused GET https://bad-target.example: destination not in scope.conf'
) || true

AGP=$(cat "$DAGENTPARTIAL/agent-fix.json")
t_case 'a partial die() abort reports BOTH the completed finding and the abort - neither discards the other'
assert_contains "$AGP" 'SAST-SEC-HARDCODED_PASSWORD-01' \
  'the finding from the module that completed before the abort is still present in findings[]'
assert_contains "$AGP" 'exit=3 scope gate refused GET https://bad-target.example' \
  'and the abort reason is present alongside it - FAILS if a partial abort were ever rendered as a clean, complete result'
assert_not_contains "$AGP" '"checks_run": []' \
  'run.checks_run is non-empty here - the field that tells case (b) (ran partially, then aborted) apart from case (c) (refused before anything ran)'

printf -- '\n-- REGRESSION: the die() abort path must honour --format, and findings.jsonl is mandatory even on abort --\n'
# =============================================================================
# `run_json_refresh_incomplete` (lib/core.sh) used to loop over
# `report_run_json report_md report_html report_agent` with NO
# `SCOURSH_FORMATS` gate at all - an aborted run under `--format md` still
# wrote report.html and agent-fix.json, silently ignoring the operator's
# explicit --format on exactly the path a CI step is most likely to assert
# "only the artifacts --format implies exist" against. And `findings.jsonl`
# was never written on ANY abort at all, because `findings_write_jsonl` is
# only ever reached through `_report_render_formats` (lib/report.sh), which
# the abort path never called - `report --from` requires findings.jsonl
# (`_scan_require_report_source`, scan.sh) and so could never read an
# aborted run's own directory back. FAILS under the pre-fix loop: report.html
# and agent-fix.json both present under --format md, and findings.jsonl
# absent under every format including the default.
DFMTABORT=$SCOURSH_SCRATCH/rpt-format-abort-md
rm -rf "$DFMTABORT"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DFMTABORT"
DFMTABORT=$SCOURSH_RUN_DIR
(
  SCOURSH_FORMATS=md
  die "$SCOURSH_EXIT_SCOPE" \
    'scope gate refused GET https://bad-target.example: destination not in scope.conf'
) || true

t_case 'an aborted run under --format md writes only the mandatory records plus report.md'
assert_file_exists "$DFMTABORT/run.json" 'run.json is mandatory, --format notwithstanding'
assert_file_exists "$DFMTABORT/findings.jsonl" \
  'findings.jsonl is mandatory too - FAILS pre-fix, where it was never written on any abort'
assert_file_exists "$DFMTABORT/report.md" 'report.md is written - it is the one format actually named'
assert_file_absent "$DFMTABORT/report.html" \
  'report.html must NOT be written - FAILS pre-fix, where the abort path ignored --format entirely and always wrote it'
assert_file_absent "$DFMTABORT/agent-fix.json" \
  'agent-fix.json must NOT be written either, for the identical reason'
assert_file_absent "$DFMTABORT/report.sarif" 'report.sarif must NOT be written - sarif was never named'
assert_file_absent "$DFMTABORT/findings.json" 'findings.json must NOT be written - json was never named'

printf -- '\n-- and a DEFAULT-format abort (no --format given) still writes the full default list --\n'
DFMTDEFAULT=$SCOURSH_SCRATCH/rpt-format-abort-default
rm -rf "$DFMTDEFAULT"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID='' SCOURSH_FORMATS=''
run_init "$DFMTDEFAULT"
DFMTDEFAULT=$SCOURSH_RUN_DIR
(
  die "$SCOURSH_EXIT_SCOPE" \
    'scope gate refused GET https://bad-target.example: destination not in scope.conf'
) || true

t_case 'a default-format abort writes every default-list artifact, findings.jsonl included'
assert_file_exists "$DFMTDEFAULT/run.json" 'run.json'
assert_file_exists "$DFMTDEFAULT/findings.jsonl" 'findings.jsonl'
assert_file_exists "$DFMTDEFAULT/findings.json" 'findings.json (json is in the default list)'
assert_file_exists "$DFMTDEFAULT/report.md" 'report.md'
assert_file_exists "$DFMTDEFAULT/report.html" 'report.html'
assert_file_exists "$DFMTDEFAULT/report.sarif" 'report.sarif (sarif is in the default list)'
assert_file_exists "$DFMTDEFAULT/agent-fix.json" 'agent-fix.json (agent is in the default list)'
assert_file_absent "$DFMTDEFAULT/report-audit.html" \
  'report-audit.html stays opt-in even under a default-list abort - audit is never in the default list'

t_case 'a mandatory but empty findings.jsonl on abort is never confused with a genuine clean scan'
FJA=$(cat "$DFMTDEFAULT/findings.jsonl")
assert_eq '' "$FJA" \
  'empty is the correct content for a pre-dispatch abort - nothing was ever merged into findings.fields'
JDA=$(cat "$DFMTDEFAULT/run.json")
assert_contains "$JDA" 'scope gate refused GET https://bad-target.example' \
  "a consumer tells the two apart via run.json's own abort_reason, which is unconditional and non-empty here"

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
SCOURSH_INSTALL_ROOT=$ROOT

# =============================================================================
printf '\n-- report --from DIR (report_regenerate_from): byte-identical regeneration --\n'
# =============================================================================
# "A live scan into DIR, then report --from DIR" - D15 is built the exact way
# every earlier fixture in this file already is (finding_new/finding_emit,
# findings_merge, report_all): there is no scanner module in this test
# process, and there does not need to be one. report_regenerate_from's own
# contract is "reuse the exact same rendering path a live scan uses", so
# proving it against report_all's own output, built the same way this whole
# suite already builds it, IS the real test.
D15=$SCOURSH_SCRATCH/rpt-regen-orig
rm -rf "$D15"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D15"
D15=$SCOURSH_RUN_DIR
SCOURSH_REDACT_SECRETS=false
SCOURSH_DIFF_GUARD=usable

finding_new
finding_set check_id SAST-SEC-REGEN-01
finding_set module sast
finding_set title 'Hardcoded key (regen fixture)'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path app.py
finding_set loc_line 9
finding_set cell .
finding_set_match 'k'
finding_set_evidence 'SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
finding_set remediation 'Rotate it.'
finding_emit

finding_new
finding_set check_id DAST-GRP-REGEN-01
finding_set module dast
finding_set title 'dast regen finding'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_target t1
finding_set loc_method GET
finding_set path /regen
finding_set cell t1
finding_set_evidence e
finding_set remediation r
finding_emit

findings_merge "$D15"
run_record coverage_reduction 'module=sca reason=fixture'
run_record checks_run SAST-SEC-REGEN-01
run_record checks_run DAST-GRP-REGEN-01
SCOURSH_FORMATS=json,sarif,html,md,audit
report_all "$D15"
unset SCOURSH_FORMATS

t_case 'report_regenerate_from produces byte-identical report.md/report.html/report-audit.html/findings.jsonl/findings.json/run.json'
D16=$SCOURSH_SCRATCH/rpt-regen-copy
rm -rf "$D16"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D16"
D16=$SCOURSH_RUN_DIR
# Deliberately WRONG, to prove report_regenerate_from restores the
# ORIGINAL run's own values rather than leaving this invocation's: if it did
# not, the comparisons below would fail on the redaction banner and the
# run_id line instead of passing.
SCOURSH_REDACT_SECRETS=true
SCOURSH_DIFF_GUARD=scan_root_id_mismatch
SCOURSH_FORMATS=json,sarif,html,md,audit
report_regenerate_from "$D15" "$D16"
unset SCOURSH_FORMATS

for f in report.md report.html report-audit.html findings.jsonl findings.json run.json; do
  if cmp -s "$D15/$f" "$D16/$f"; then
    _t_ok "$f is byte-identical between the original run and its regeneration"
  else
    # AGENTS.md "things measured on this codebase": `head -5` on a `diff`
    # producing MORE than 5 lines closes the pipe early, so `diff` gets
    # SIGPIPE - under `pipefail`, inside `$(...)`, that is a real failure
    # `|| true` must absorb, not the failing assertion's own signal.
    DIFF_OUT=$(diff "$D15/$f" "$D16/$f" | head -5) || true
    _t_no "$f is byte-identical between the original run and its regeneration" "$DIFF_OUT"
  fi
done

t_case 'report.sarif is byte-identical apart from the invocations[].endTimeUtc render-time stamp'
# report_sarif's own header (_sarif_print_invocations) documents this: the
# field mirrors "now" via a live now_iso() call made INSIDE report_sarif
# itself - the identical, already-documented limitation report_run_json's
# own completed_at has, which report_regenerate_from solves for run.json by
# copying it rather than recomputing it (see that function's own header for
# why). report.sarif is never copied that way: --format sarif may not even
# have been part of the original run, so it has to be genuinely re-rendered
# here. Strip just the one volatile field before comparing everything else.
NORM15=$(sed -E 's/"endTimeUtc":"[^"]*"/"endTimeUtc":"NOW"/' "$D15/report.sarif")
NORM16=$(sed -E 's/"endTimeUtc":"[^"]*"/"endTimeUtc":"NOW"/' "$D16/report.sarif")
assert_eq "$NORM15" "$NORM16" \
  'report.sarif matches byte-for-byte once the live render timestamp is normalised'

t_case "report_regenerate_from re-exports run_id/redact_secrets/diff_guard from the copied run.json, never from this invocation's own environment"
assert_contains "$(cat "$D16/report.md")" "- run: \`$(basename -- "$D15")\`" \
  "report.md names the ORIGINAL run's own run_id, not the regeneration output directory's basename"
assert_contains "$(cat "$D16/report.md")" 'WARNING - redaction is disabled' \
  "the redaction banner still fires - FAILS if report_regenerate_from left this invocation's own SCOURSH_REDACT_SECRETS=true (deliberately set above) in place instead of restoring the original run's false"
assert_not_contains "$(cat "$D16/run.json")" 'scan_root_id_mismatch' \
  "run.json was copied byte-for-byte from the original rather than reflecting this invocation's own (deliberately different) diff_guard"

t_case "report_regenerate_from with --out identical to --from is a safe in-place regeneration, never a destructive copy-over-itself - even when the two paths are spelled differently but resolve to the same directory"
D17=$SCOURSH_SCRATCH/rpt-regen-inplace
rm -rf "$D17"
cp -R "$D15" "$D17"
SCOURSH_RUN_DIR=$D17
SCOURSH_RUN_ID=$(basename -- "$D17")
SCOURSH_FORMATS=json,sarif,html,md,audit
# The trailing slash on the --from side is deliberate: it is the SAME
# directory as $D17, spelled differently, so this only stays a safe no-op
# if report_regenerate_from resolves BOTH sides before comparing them -
# comparing the raw strings would read them as different and delete
# rundir/meta right before reading it back from the identical path.
report_regenerate_from "$D17/" "$D17"
unset SCOURSH_FORMATS
assert_file_exists "$D17/findings.fields" \
  'findings.fields still exists after an in-place regeneration - FAILS if the rm -rf guard fired against its own source directory'
if cmp -s "$D15/report.md" "$D17/report.md"; then
  _t_ok 'an in-place regeneration reproduces the identical report.md'
else
  DIFF_OUT=$(diff "$D15/report.md" "$D17/report.md" | head -5) || true
  _t_no 'an in-place regeneration reproduces the identical report.md' "$DIFF_OUT"
fi

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary report
