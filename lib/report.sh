#!/usr/bin/env bash
# lib/report.sh - the emitters: JSON, the self-contained HTML report, Markdown,
# and the run.json scan-metadata record.
#
# Owns:
#   docs/DESIGN.md   §4 (lib/report.sh)
#   docs/FOUNDATION.md tension 10 (escaping on the way out; the CSP)
#   docs/FOUNDATION.md tension 11 step 9 (suppressed findings render separately)
#   docs/FOUNDATION.md tension 21 (coverage_gap rendered in the limitations section)
#   cross-cutting consequence 6 (run.json is load-bearing, not decorative)
#
# SARIF 2.1.0 and the compliance-mapping report are §13 step 10 and are not here.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_REPORT_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_REPORT_SOURCED=1

# shellcheck source=lib/findings.sh
source "${BASH_SOURCE[0]%/*}/findings.sh"

# ---------------------------------------------------------------------------
# 1. Counting
# ---------------------------------------------------------------------------
# tension 11 step 9: suppressed findings "render in a separate collapsed
# 'accepted risk' section with their reason, and are counted SEPARATELY in every
# summary".  So every _RPT_* map below counts LIVE findings only, and the
# accepted set has its own breakdown.  Counting them together let an accepted
# critical keep inflating the critical count, which misrepresents risk state -
# the one thing a security report may not do.
declare -A _RPT_SEV=()
declare -A _RPT_MODULE=()
declare -A _RPT_STATUS=()
declare -A _RPT_OWASP=()
declare -A _RPT_SEV_SUP=()
_RPT_TOTAL=0
_RPT_SUPPRESSED=0
_RPT_LIVE=0

report_count() {
  local rundir=${1:-$SCOURSH_RUN_DIR} line
  _RPT_SEV=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)
  _RPT_SEV_SUP=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)
  _RPT_MODULE=()
  _RPT_STATUS=([new]=0 [recurring]=0 [fixed]=0 [unknown]=0)
  _RPT_OWASP=()
  _RPT_TOTAL=0
  _RPT_SUPPRESSED=0
  _RPT_LIVE=0
  [[ -s $rundir/findings.fields ]] || return 0
  local sev mod st ow
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    _RPT_TOTAL=$(( _RPT_TOTAL + 1 ))
    sev=${_DF[severity]:-info}
    if [[ ${_DF[suppressed]:-false} == true ]]; then
      _RPT_SUPPRESSED=$(( _RPT_SUPPRESSED + 1 ))
      _RPT_SEV_SUP[$sev]=$(( ${_RPT_SEV_SUP[$sev]:-0} + 1 ))
      continue
    fi
    _RPT_LIVE=$(( _RPT_LIVE + 1 ))
    mod=${_DF[module]:-unknown}
    st=${_DF[status]:-new}
    ow=${_DF[owasp]:-none}
    _RPT_SEV[$sev]=$(( ${_RPT_SEV[$sev]:-0} + 1 ))
    _RPT_MODULE[$mod]=$(( ${_RPT_MODULE[$mod]:-0} + 1 ))
    _RPT_STATUS[$st]=$(( ${_RPT_STATUS[$st]:-0} + 1 ))
    _RPT_OWASP[$ow]=$(( ${_RPT_OWASP[$ow]:-0} + 1 ))
  done <"$rundir/findings.fields"
}

# ---------------------------------------------------------------------------
# 2. run.json (docs/DESIGN.md §4, cross-cutting consequence 6)
# ---------------------------------------------------------------------------
# Load-bearing, not decorative: skipped_checks with reasons, coverage_gap
# entries, coverage_reduction, incomplete_reason, the capability probe results,
# and the counts.  §15's honesty requirement is implemented through this file,
# and `incomplete_reason` being non-empty is exactly the exit-5 predicate
# (tension 14).
#
# `checks_selected` (tension 15, `lib/checks.sh`) vs `checks_run` (AGENTS.md
# "Build order and where we are", `records_register_checks`): the former is
# every check the run's filter chain selected as eligible BEFORE dispatch;
# the latter is every check some module actually loaded and executed.  A
# selected check is not yet a run one - a module may still skip it for its
# own reason (a missing `requires-cmd`, an unmet `requires-identities`) - so
# the two arrays are kept distinct rather than merged into one that would
# overclaim for every check on the wrong side of that gap.
report_run_json() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  report_count "$rundir"
  local started ended dur=0 started_epoch
  started=$(_meta_first "$rundir" started_at)
  started_epoch=$(_meta_first "$rundir" started_epoch)
  ended=$(now_iso)
  if [[ $started_epoch =~ ^[0-9]+$ ]]; then
    dur=$(( $(now_epoch) - started_epoch ))
  fi
  {
    printf '{\n'
    printf '  "tool": "scoursh",\n'
    printf '  "tool_version": %s,\n' "$(json_string "$(scoursh_version)")"
    printf '  "fp_schema": %s,\n' "$(json_string "$FP_SCHEMA")"
    printf '  "uk_schema": %s,\n' "$(json_string "$UK_SCHEMA")"
    printf '  "run_id": %s,\n' "$(json_string "${SCOURSH_RUN_ID:-}")"
    printf '  "started_at": %s,\n' "$(json_string "$started")"
    printf '  "completed_at": %s,\n' "$(json_string "$ended")"
    printf '  "duration_seconds": %s,\n' "$(json_number "$dur")"
    printf '  "scan_root_id": %s,\n' "$(json_string "${SCOURSH_SCAN_ROOT_ID:-}")"
    printf '  "path_root": %s,\n' "$(json_string "${SCOURSH_PATH_ROOT:-}")"
    printf '  "redact_secrets": %s,\n' "$(json_bool "$SCOURSH_REDACT_SECRETS")"
    printf '  "capabilities": {\n'
    printf '    "sha256": %s,\n' "$(json_string "$SCOURSH_CAP_SHA256")"
    printf '    "stat": %s,\n' "$(json_string "$SCOURSH_CAP_STAT")"
    printf '    "realpath": %s,\n' "$(json_string "$SCOURSH_CAP_REALPATH")"
    printf '    "clock": %s,\n' "$(json_string "$SCOURSH_CAP_CLOCK")"
    printf '    "clock_subsecond": %s,\n' "$(json_bool "$(( SCOURSH_CLOCK_NS ))")"
    printf '    "msleep": %s,\n' "$(json_string "$SCOURSH_CAP_MSLEEP")"
    printf '    "shred": %s,\n' "$(json_string "$SCOURSH_CAP_SHRED")"
    printf '    "look": %s,\n' "$(json_string "$SCOURSH_CAP_LOOK")"
    printf '    "pattern_engine": %s,\n' "$(json_string "$SCOURSH_ENGINE")"
    printf '    "pcre": %s,\n' "$(json_string "${SCOURSH_CAP_PCRE:-unprobed}")"
    printf '    "bash": %s\n' "$(json_string "${BASH_VERSION:-unknown}")"
    printf '  },\n'
    printf '  "counts": {\n'
    printf '    "total": %s,\n' "$(json_number "$_RPT_TOTAL")"
    printf '    "live": %s,\n' "$(json_number "$_RPT_LIVE")"
    printf '    "suppressed": %s,\n' "$(json_number "$_RPT_SUPPRESSED")"
    printf '    "by_severity": {'
    local first=1 k
    for k in critical high medium low info; do
      (( first )) || printf ','
      first=0
      printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_SEV[$k]:-0}")"
    done
    printf '},\n'
    printf '    "suppressed_by_severity": {'
    first=1
    for k in critical high medium low info; do
      (( first )) || printf ','
      first=0
      printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_SEV_SUP[$k]:-0}")"
    done
    printf '},\n'
    printf '    "by_status": {'
    first=1
    for k in new recurring fixed unknown; do
      (( first )) || printf ','
      first=0
      printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_STATUS[$k]:-0}")"
    done
    printf '},\n'
    printf '    "by_module": {'
    first=1
    if (( ${#_RPT_MODULE[@]} > 0 )); then
      while IFS= read -r k; do
        [[ -n $k ]] || continue
        (( first )) || printf ','
        first=0
        printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_MODULE[$k]}")"
      done <<<"$(printf '%s\n' "${!_RPT_MODULE[@]}" | LC_ALL=C sort)"
    fi
    printf '}\n'
    printf '  },\n'
    _meta_array_unique "$rundir" targets 'targets'
    _meta_array_unique "$rundir" regions 'regions'
    _meta_array_unique "$rundir" checks_run 'checks_run'
    _meta_array_unique "$rundir" checks_selected 'checks_selected'
    _meta_array "$rundir" skipped_checks 'skipped_checks'
    _meta_array "$rundir" coverage_gap 'coverage_gap'
    _meta_array "$rundir" coverage_reduction 'coverage_reduction'
    _meta_array "$rundir" incomplete_reason 'incomplete_reason'
    _meta_array "$rundir" notes 'notes'
    printf '  "gate": %s,\n' "$(json_string "${SCOURSH_GATE_RESULT:-not-evaluated}")"
    printf '  "gated_findings": %s,\n' "$(json_number "${SCOURSH_GATED_FINDINGS:-0}")"
    printf '  "diff_usable": %s\n' "$(json_bool "${SCOURSH_DIFF_USABLE:-false}")"
    printf '}\n'
  } >"$rundir/run.json"
}

_meta_first() {
  local rundir=$1 key=$2 v=''
  [[ -r $rundir/meta/$key ]] || { printf '%s' ''; return 0; }
  IFS= read -r v <"$rundir/meta/$key" || true
  printf '%s' "$v"
}

# As _meta_array, but deduped and sorted: a loader may legitimately run more
# than once in a process, and a repeated target or check id is noise rather than
# information.
_meta_array_unique() {
  local rundir=$1 key=$2 label=$3 line first=1
  printf '  %s: [' "$(json_string "$label")"
  if [[ -r $rundir/meta/$key ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s' "$(json_string "$line")"
    done <<<"$(LC_ALL=C sort -u "$rundir/meta/$key")"
  fi
  printf '],\n'
}

_meta_array() {
  local rundir=$1 key=$2 label=$3 line first=1
  printf '  %s: [' "$(json_string "$label")"
  if [[ -r $rundir/meta/$key ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s' "$(json_string "$line")"
    done <"$rundir/meta/$key"
  fi
  printf '],\n'
}

# ---------------------------------------------------------------------------
# 3. Markdown
# ---------------------------------------------------------------------------
# SC2016 fires on every Markdown code span below; the backticks are literal
# output, not command substitution.
# shellcheck disable=SC2016
report_md() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  report_count "$rundir"
  {
    printf '# scoursh scan report\n\n'
    printf -- '- run: `%s`\n' "${SCOURSH_RUN_ID:-}"
    printf -- '- tool version: `%s`\n' "$(scoursh_version)"
    printf -- '- fingerprint schema: `%s`\n' "$FP_SCHEMA"
    printf -- '- findings: %s live, %s accepted risk (%s total)\n\n' \
      "$_RPT_LIVE" "$_RPT_SUPPRESSED" "$_RPT_TOTAL"
    if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
      printf '> **WARNING - redaction is disabled for this run.** This report may contain\n'
      printf '> live credentials and must not be circulated.\n\n'
    fi
    printf '## Severity\n\n| severity | live | accepted risk |\n|---|---|---|\n'
    local k
    for k in critical high medium low info; do
      printf '| %s | %s | %s |\n' "$k" "${_RPT_SEV[$k]:-0}" "${_RPT_SEV_SUP[$k]:-0}"
    done
    printf '\n## Findings\n\n'
    if [[ -s $rundir/findings.fields ]]; then
      _md_findings "$rundir" live
    else
      printf '_No findings._\n\n'
    fi
    # Suppressed findings render in their OWN section with their reason, never
    # inline with live ones (tension 11 step 9).  report_html did this; the
    # Markdown emitter printed both into one list with identical formatting, so
    # a reader could not tell an accepted risk from a live critical.
    if (( _RPT_SUPPRESSED > 0 )); then
      printf '## Accepted risk (%s)\n\n' "$_RPT_SUPPRESSED"
      printf 'These are suppressed by `config/baseline.json` and are excluded from the\n'
      printf 'counts above and from the CI gate. They are still reported, never deleted.\n\n'
      _md_findings "$rundir" suppressed
    fi
    _md_limitations "$rundir"
  } >"$rundir/report.md"
}

# `_md_findings RUNDIR live|suppressed`
#
# SC2016 fires on every Markdown code span below; the backticks are literal
# output, not command substitution.
# shellcheck disable=SC2016
_md_findings() {
  local rundir=$1 want=$2 line fence is_sup
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    is_sup=${_DF[suppressed]:-false}
    if [[ $want == live ]]; then
      [[ $is_sup == true ]] && continue
    else
      [[ $is_sup == true ]] || continue
    fi
    printf '### %s - %s\n\n' "${_DF[check_id]}" "${_DF[title]}"
    printf -- '- severity: **%s** (base %s), confidence %s, status %s\n' \
      "${_DF[severity]}" "${_DF[base_severity]}" "${_DF[confidence]}" "${_DF[status]}"
    printf -- '- %s / %s · `%s`\n' "${_DF[cwe]}" "${_DF[owasp]}" "${_DF[_cvss_vector]:-}"
    printf -- '- location: `%s`\n' "$(_location_summary)"
    printf -- '- fingerprint: `%s`\n' "${_DF[fingerprint]}"
    if [[ $is_sup == true ]]; then
      printf -- '- **accepted risk**: %s\n' "${_DF[suppressed_by]:-no reason recorded}"
    fi
    printf '\n'
    if [[ -n ${_DF[evidence]:-} ]]; then
      # A fence one backtick longer than the longest run in the content, so
      # evidence cannot break out of the code block (tension 10).
      fence=$(md_fence_for "${_DF[evidence]}")
      printf '%s\n%s\n%s\n\n' "$fence" "${_DF[evidence]}" "$fence"
    fi
    if [[ -n ${_DF[remediation]:-} ]]; then
      printf '%s\n\n' "${_DF[remediation]}"
    fi
  done <"$rundir/findings.fields"
}

_md_limitations() {
  local rundir=$1 line any=0
  printf '## Limitations and coverage\n\n'
  if [[ -r $rundir/meta/coverage_reduction ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- declared reduced coverage: %s\n' "$line"
    done <"$rundir/meta/coverage_reduction"
  fi
  if [[ -r $rundir/meta/skipped_checks ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- skipped: %s\n' "$line"
    done <"$rundir/meta/skipped_checks"
  fi
  if [[ -r $rundir/meta/coverage_gap ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- coverage gap: %s\n' "$line"
    done <"$rundir/meta/coverage_gap"
  fi
  if [[ -r $rundir/meta/incomplete_reason ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- **incomplete run**: %s\n' "$line"
    done <"$rundir/meta/incomplete_reason"
  fi
  (( any )) || printf -- '- None recorded for this run.\n'
  printf '\n'
}

_location_summary() {
  local out=''
  # blob BEFORE path: a SAST-HIST-* finding carries a path for navigation, but
  # its identity is the blob (tension 13), and showing only the path would read
  # as a working-tree finding - which is the one thing history findings are not.
  if [[ -n ${_DF[loc_blob_sha]:-} ]]; then
    out="blob ${_DF[loc_blob_sha]:0:12}"
    [[ -n ${_DF[loc_path]:-} ]] && out="$out (${_DF[loc_path]})"
  elif [[ -n ${_DF[loc_path]:-} ]]; then
    out=${_DF[loc_path]}
    [[ -n ${_DF[loc_line]:-} ]] && out="$out:${_DF[loc_line]}"
  elif [[ -n ${_DF[loc_resource_key]:-} ]]; then
    out="${_DF[loc_account_id]:-}/${_DF[loc_region]:-} ${_DF[loc_resource_key]}"
  elif [[ -n ${_DF[loc_target]:-} ]]; then
    out="${_DF[loc_target]} ${_DF[loc_method]:-} ${_DF[loc_path_template]:-}"
    [[ -n ${_DF[loc_param_name]:-} ]] && out="$out #${_DF[loc_param_name]}"
  elif [[ -n ${_DF[loc_control_id]:-} ]]; then
    out="${_DF[loc_control_id]} @ ${_DF[loc_scope_key]:-}"
  elif [[ -n ${_DF[loc_package]:-} ]]; then
    out="${_DF[loc_ecosystem]:-}:${_DF[loc_package]} ${_DF[loc_advisory_id]:-}"
  elif [[ -n ${_DF[loc_correlation]:-} ]]; then
    out="correlation ${_DF[loc_correlation]}"
  fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 4. HTML (tension 10)
# ---------------------------------------------------------------------------
# Self-contained: inline CSS, no CDN, no external asset of any kind, because a
# report that fetches a font is egress (docs/DESIGN.md §2).
#
# The document contains NO <script> element at all; interactivity is
# <details>/<summary>, which needs none.  It carries a strict inline CSP so that
# even a defect in the escaping below cannot execute script or make a network
# request - which is what makes the HTML report genuinely honour the no-egress
# model rather than merely not shipping a CDN link.
#
# Evidence is placed only in TEXT NODES, never in an attribute, never inside
# <script> or <style>.
report_html() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  report_count "$rundir"
  {
    _html_head
    _html_summary
    _html_findings "$rundir"
    _html_limitations "$rundir"
    _html_foot
  } >"$rundir/report.html"
}

_html_head() {
  cat <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>scoursh scan report</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #16181d; --muted: #5b6270; --line: #d9dde5;
  --card: #f7f8fa; --accent: #274b8f;
  --critical: #8a1220; --high: #a44608; --medium: #8a6d09; --low: #35566f; --info: #5b6270;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e6e8ec; --muted: #9aa2b1; --line: #2b3038;
    --card: #1b1e24; --accent: #8fb0ee;
    --critical: #ff8b98; --high: #ffb27a; --medium: #ecd07a; --low: #a8c8dd; --info: #9aa2b1;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; text-transform: uppercase;
     letter-spacing: .08em; color: var(--muted); font-weight: 600; }
.sub { color: var(--muted); margin: 0 0 2rem; font-size: .9rem; }
.sub code { color: var(--fg); }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85em; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr)); gap: .6rem; }
.tile { border: 1px solid var(--line); border-radius: .5rem; padding: .7rem .8rem; background: var(--card); }
.tile .n { font-size: 1.5rem; font-weight: 650; line-height: 1.1; }
.tile .l { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.tile.critical .n { color: var(--critical); }
.tile.high .n { color: var(--high); }
.tile.medium .n { color: var(--medium); }
.tile.low .n { color: var(--low); }
.tile.info .n { color: var(--info); }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .35rem .6rem .35rem 0; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
details.f { border: 1px solid var(--line); border-left-width: 3px; border-radius: .4rem;
            margin: .5rem 0; background: var(--card); }
details.f > summary { cursor: pointer; padding: .6rem .8rem; list-style: none; }
details.f > summary::-webkit-details-marker { display: none; }
details.f[data-sev="critical"] { border-left-color: var(--critical); }
details.f[data-sev="high"] { border-left-color: var(--high); }
details.f[data-sev="medium"] { border-left-color: var(--medium); }
details.f[data-sev="low"] { border-left-color: var(--low); }
details.f[data-sev="info"] { border-left-color: var(--info); }
.sev { font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
       padding: .1rem .4rem; border: 1px solid currentColor; border-radius: .25rem; }
.sev.critical { color: var(--critical); }
.sev.high { color: var(--high); }
.sev.medium { color: var(--medium); }
.sev.low { color: var(--low); }
.sev.info { color: var(--info); }
.loc { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       font-size: .78rem; margin-left: .5rem; word-break: break-all; }
.body { padding: 0 .8rem .8rem; border-top: 1px solid var(--line); }
.meta { color: var(--muted); font-size: .82rem; margin: .6rem 0; word-break: break-all; }
pre.ev { background: var(--bg); border: 1px solid var(--line); border-radius: .35rem;
         padding: .6rem .7rem; overflow-x: auto; margin: .6rem 0; white-space: pre-wrap;
         word-break: break-word; }
.rem { margin: .6rem 0 0; white-space: pre-wrap; }
.banner { border: 1px solid var(--critical); color: var(--critical); border-radius: .4rem;
          padding: .7rem .9rem; margin: 0 0 1.5rem; font-weight: 600; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .8rem; }
</style>
</head>
<body>
<main>
HTML
}

_html_summary() {
  printf '<h1>scoursh scan report</h1>\n'
  printf '<p class="sub">run <code>%s</code> · tool <code>%s</code> · fingerprint schema <code>%s</code> · %s live findings, %s accepted risk</p>\n' \
    "$(html_escape "${SCOURSH_RUN_ID:-}")" "$(html_escape "$(scoursh_version)")" \
    "$(html_escape "$FP_SCHEMA")" "$_RPT_LIVE" "$_RPT_SUPPRESSED"
  if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
    printf '<p class="banner">Redaction is DISABLED for this run. This report may contain live credentials and must not be circulated.</p>\n'
  fi
  printf '<h2>Severity</h2>\n<div class="tiles">\n'
  local k
  for k in critical high medium low info; do
    printf '<div class="tile %s"><div class="n">%s</div><div class="l">%s</div></div>\n' \
      "$k" "${_RPT_SEV[$k]:-0}" "$k"
  done
  printf '</div>\n'
  if (( _RPT_SUPPRESSED > 0 )); then
    printf '<p class="sub">Counts above are LIVE findings. Accepted risk is counted separately:'
    for k in critical high medium low info; do
      (( ${_RPT_SEV_SUP[$k]:-0} > 0 )) && printf ' %s&nbsp;%s' "${_RPT_SEV_SUP[$k]}" "$k"
    done
    printf '.</p>\n'
  fi
  printf '<h2>Since the last scan</h2>\n<div class="tiles">\n'
  for k in new recurring fixed unknown; do
    printf '<div class="tile"><div class="n">%s</div><div class="l">%s</div></div>\n' \
      "${_RPT_STATUS[$k]:-0}" "$k"
  done
  printf '</div>\n'
  if (( ${#_RPT_MODULE[@]} > 0 )); then
    printf '<h2>By module</h2>\n<table><tr><th>module</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$k")" "${_RPT_MODULE[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_MODULE[@]}" | LC_ALL=C sort)"
    printf '</table>\n'
  fi
  if (( ${#_RPT_OWASP[@]} > 0 )); then
    printf '<h2>By OWASP category</h2>\n<table><tr><th>category</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$k")" "${_RPT_OWASP[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_OWASP[@]}" | LC_ALL=C sort)"
    printf '</table>\n'
  fi
}

_html_findings() {
  local rundir=$1 line
  printf '<h2>Findings</h2>\n'
  if [[ ! -s $rundir/findings.fields ]]; then
    printf '<p class="empty">No findings.</p>\n'
    return 0
  fi
  local wrote=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[suppressed]:-false} == true ]] && continue
    _html_one_finding
    wrote=1
  done <"$rundir/findings.fields"
  (( wrote )) || printf '<p class="empty">Every finding this run is an accepted risk; see below.</p>\n'

  # Suppressed findings render in a separate collapsed "accepted risk" section
  # with their reason, and are counted separately (tension 11 step 9).  They are
  # never deleted.
  if (( _RPT_SUPPRESSED > 0 )); then
    printf '<h2>Accepted risk (%s)</h2>\n' "$_RPT_SUPPRESSED"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      [[ ${_DF[suppressed]:-false} == true ]] || continue
      _html_one_finding
    done <"$rundir/findings.fields"
  fi
}

_html_one_finding() {
  local sev=${_DF[severity]:-info} loc
  loc=$(_location_summary)
  # The location belongs in the COLLAPSED line, not only inside it: repeated
  # byte-identical matches of one check are distinct findings with distinct
  # fingerprints (tension 5), and a list that renders them as three identical
  # rows reads as a duplication bug.
  printf '<details class="f" data-sev="%s"><summary><span class="sev %s">%s</span> <strong>%s</strong> - %s<span class="loc">%s</span></summary>\n' \
    "$(html_escape "$sev")" "$(html_escape "$sev")" "$(html_escape "$sev")" \
    "$(html_escape "${_DF[check_id]}")" "$(html_escape "${_DF[title]}")" \
    "$(html_escape "$loc")"
  printf '<div class="body">\n'
  printf '<p class="meta">%s · %s · confidence %s · status %s · base severity %s</p>\n' \
    "$(html_escape "${_DF[cwe]:-none}")" "$(html_escape "${_DF[owasp]:-none}")" \
    "$(html_escape "${_DF[confidence]:-medium}")" "$(html_escape "${_DF[status]:-new}")" \
    "$(html_escape "${_DF[base_severity]:-}")"
  printf '<p class="meta">location: %s</p>\n' "$(html_escape "$loc")"
  printf '<p class="meta">CVSS: %s (%s)</p>\n' \
    "$(html_escape "${_DF[_cvss_vector]:-}")" "$(html_escape "${_DF[_cvss_score]:-}")"
  printf '<p class="meta">fingerprint: %s</p>\n' "$(html_escape "${_DF[fingerprint]}")"
  if [[ -n ${_DF[suppressed_by]:-} ]]; then
    printf '<p class="meta">accepted risk: %s</p>\n' "$(html_escape "${_DF[suppressed_by]}")"
  fi
  if [[ -n ${_DF[contributors]:-} ]]; then
    printf '<p class="meta">contributing findings: %s</p>\n' \
      "$(html_escape "${_DF[contributors]//$'\n'/, }")"
  fi
  if [[ -n ${_DF[derived_into]:-} ]]; then
    printf '<p class="meta">rolls up into: %s</p>\n' \
      "$(html_escape "${_DF[derived_into]//$'\n'/, }")"
  fi
  if [[ -n ${_DF[evidence]:-} ]]; then
    printf '<pre class="ev">%s</pre>\n' "$(html_escape "${_DF[evidence]}")"
  fi
  if [[ -n ${_DF[remediation]:-} ]]; then
    printf '<p class="rem">%s</p>\n' "$(html_escape "${_DF[remediation]}")"
  fi
  printf '</div>\n</details>\n'
}

_html_limitations() {
  local rundir=$1 line any=0
  printf '<h2>Limitations and coverage</h2>\n<ul>\n'
  if [[ -r $rundir/meta/coverage_gap ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li>coverage gap: %s</li>\n' "$(html_escape "$line")"
    done <"$rundir/meta/coverage_gap"
  fi
  if [[ -r $rundir/meta/coverage_reduction ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li>declared reduced coverage: %s</li>\n' "$(html_escape "$line")"
    done <"$rundir/meta/coverage_reduction"
  fi
  if [[ -r $rundir/meta/skipped_checks ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li>skipped: %s</li>\n' "$(html_escape "$line")"
    done <"$rundir/meta/skipped_checks"
  fi
  if [[ -r $rundir/meta/incomplete_reason ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li><strong>incomplete run</strong>: %s</li>\n' "$(html_escape "$line")"
    done <"$rundir/meta/incomplete_reason"
  fi
  (( any )) || printf '<li>None recorded for this run.</li>\n'
  printf '</ul>\n'
}

_html_foot() {
  printf '<footer>Generated by scoursh %s. This report is self-contained: no external assets, no scripts, no network requests.</footer>\n' \
    "$(html_escape "$(scoursh_version)")"
  printf '</main>\n</body>\n</html>\n'
}

# ---------------------------------------------------------------------------
# 5. Everything
# ---------------------------------------------------------------------------
report_all() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  findings_write_jsonl "$rundir"
  findings_write_json "$rundir"
  report_md "$rundir"
  report_html "$rundir"
  report_run_json "$rundir"
}
