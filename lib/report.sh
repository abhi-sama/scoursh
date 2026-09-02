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
    # `use_engines` (docs/ADAPTERS.md) is a SCALAR bool, not an array: scan.sh
    # records exactly one value per run.  Rendering it here closes a real,
    # already-shipped gap - `run_record use_engines` has been writing
    # meta/use_engines since the semgrep adapter landed, and nothing rendered
    # it, so the tool's only audit flag was half-recorded and both suites that
    # cover it asserted against the meta FILE rather than run.json.  Defaults
    # to false rather than being omitted, so a consumer never has to
    # distinguish "not given" from "this version does not record it".
    printf '  "use_engines": %s,\n' "$(json_bool "$(_meta_first "$rundir" use_engines)")"
    _report_authorization_json "$rundir"
    printf '  "gate": %s,\n' "$(json_string "${SCOURSH_GATE_RESULT:-not-evaluated}")"
    printf '  "gated_findings": %s,\n' "$(json_number "${SCOURSH_GATED_FINDINGS:-0}")"
    printf '  "diff_usable": %s\n' "$(json_bool "${SCOURSH_DIFF_USABLE:-false}")"
    printf '}\n'
  } >"$rundir/run.json"
}

# The run's authorisation object (docs/STEP5-DAST-PLAN.md DAST-33).
#
# Rendered on EVERY run, not only a DAST one, and every field is present even
# when it is empty.  An absent key would be ambiguous between "nothing was
# affirmed" and "this version does not record it" - and the second reading is
# exactly what the `use_engines` gap above already cost this tool once.  A
# `sast` run therefore renders `affirmed: false, affirmation_source: "none"`
# and an empty scope target, which is a true and complete statement about it.
#
# `limits_relaxed` records the DELTA, from-value to to-value, never a boolean:
# "unrestricted: true" tells a later reader nothing about what traffic was
# authorised, whereas the delta reconstructs the traffic profile.
# `limits_clamped` is the unaffirmed run's mirror of it, carrying the
# resolution layer the refused value came from.  `limits_enforced` records
# what was NOT relaxed, because the usual question after an incident is what
# the tool could not have done.
_report_authorization_json() {
  local rundir=$1 src
  src=$(_meta_first "$rundir" authorization_source)
  [[ -n $src ]] || src=none
  printf '  "authorization": {\n'
  printf '    "scope_target": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_scope_target)")"
  printf '    "scope_conf_sha256": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_scope_conf_sha256)")"
  printf '    "affirmed": %s,\n' "$(json_bool "$(_meta_first "$rundir" authorization_affirmed)")"
  # Defaults to `none` rather than the empty string, because a run that never
  # reached the authorisation step at all (any non-DAST command) genuinely made
  # no affirmation, and `none` says that where `""` reads as a field somebody
  # forgot to fill in.  The vocabulary is `flag`, `none`, and - reserved for
  # the guided mode - `interactive-guided`.
  printf '    "affirmation_source": %s,\n' "$(json_string "$src")"
  printf '    "affirmation_target": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_target)")"
  printf '    "affirmed_at": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_at)")"
  # Recorded only when SCOURSH_OPERATOR was set, never harvested from `id -un`
  # and the hostname: run.json is frequently handed to a third party alongside
  # a report, and attaching a username and machine name to every run is a
  # privacy cost the audit requirement does not need.
  printf '    "operator": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_operator)")"
  printf '    "intensity": %s,\n' "$(json_string "$(_meta_first "$rundir" authorization_intensity)")"
  printf '    "intrusive": %s,\n' "$(json_bool "$(_meta_first "$rundir" authorization_intrusive)")"
  printf '    "authed": %s,\n' "$(json_bool "$(_meta_first "$rundir" authorization_authed)")"
  _meta_array "$rundir" limits_relaxed 'limits_relaxed' '    '
  _meta_array "$rundir" limits_clamped 'limits_clamped' '    '
  _meta_array "$rundir" limits_enforced 'limits_enforced' '    ' 1
  printf '  },\n'
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

# `_meta_array RUNDIR KEY LABEL [INDENT] [LAST]` - INDENT and LAST exist only
# so the same renderer can be reused INSIDE a nested object (the authorisation
# object above), where the indent is deeper and the final member carries no
# trailing comma.  Both default to the top-level shape every existing call
# already relies on.
_meta_array() {
  local rundir=$1 key=$2 label=$3 indent=${4:-} last=${5:-0} line first=1
  [[ -n $indent ]] || indent='  '
  printf '%s%s: [' "$indent" "$(json_string "$label")"
  if [[ -r $rundir/meta/$key ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s' "$(json_string "$line")"
    done <"$rundir/meta/$key"
  fi
  if (( last )); then
    printf ']\n'
  else
    printf '],\n'
  fi
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
    _md_unrestricted_banner "$rundir"
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

# DAST-34's report half.  The banner is plain text through the ordinary
# escaping path in both emitters, because evidence is untrusted and the HTML
# report contains no <script> at all (docs/FOUNDATION.md tension 10) - and a
# relaxation string is composed from an operator-supplied `--target` id, so it
# is no more trusted than any other operator input.
#
# It renders when limits were RELAXED, not when an affirmation was made: the
# affirmation is a key rather than a switch, so `--i-own-target` on its own
# changed nothing and a banner for it would announce something that did not
# happen.
# SC2016: the Markdown code spans below are literal output, not command
# substitution - the same note report_md itself already carries.
# shellcheck disable=SC2016
_md_unrestricted_banner() {
  local rundir=$1 line any=0
  [[ -r $rundir/meta/limits_relaxed ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    if (( ! any )); then
      any=1
      printf '> **This run was UNRESTRICTED.** Its conservative limits were lifted by an\n'
      printf '> `--i-own-target` affirmation for `%s`, so an ABSENCE of availability or\n' \
        "$(_meta_first "$rundir" authorization_scope_target)"
      printf '> throttling findings below is not evidence about the target: it may only mean\n'
      printf '> the scanner was told to ignore its own limits. What was lifted:\n>\n'
    fi
    printf '> - `%s`\n' "$line"
  done <"$rundir/meta/limits_relaxed"
  (( any )) && printf '\n'
  return 0
}

# SC2016: as above - literal Markdown code spans, never substitution.
# shellcheck disable=SC2016
_md_limitations() {
  local rundir=$1 line any=0
  printf '## Limitations and coverage\n\n'
  if [[ -r $rundir/meta/limits_relaxed ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- **unrestricted run** (`--i-own-target`): %s\n' "$line"
    done <"$rundir/meta/limits_relaxed"
  fi
  if [[ -r $rundir/meta/limits_clamped ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- limit clamped to the conservative default for an unaffirmed run: %s\n' "$line"
    done <"$rundir/meta/limits_clamped"
  fi
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
    _html_summary "$rundir"
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
/* The unrestricted-run banner (DAST-34) is a <div> holding a <p> and a <ul>,
   because a list of the limits that were lifted cannot legally sit inside the
   <p> the redaction banner uses. These two rules keep the box reading as one
   block rather than as a paragraph followed by an unrelated list. */
.banner p { margin: 0; }
.banner ul { margin: .5rem 0 0; padding-left: 1.3rem; font-weight: 400; }
.banner code { background: none; color: inherit; padding: 0; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .8rem; }
nav.toc { border: 1px solid var(--line); border-radius: .5rem; padding: .7rem 1rem;
          margin: 0 0 2rem; background: var(--card); }
nav.toc p { margin: 0 0 .35rem; font-size: .72rem; text-transform: uppercase;
            letter-spacing: .07em; color: var(--muted); font-weight: 600; }
nav.toc ul { margin: 0; padding: 0; list-style: none; display: flex; flex-wrap: wrap; gap: .4rem .9rem; }
nav.toc a, .top-link, .permalink { color: var(--accent); text-decoration: none; }
nav.toc a:hover, .top-link:hover, .permalink:hover { text-decoration: underline; }
.permalink { margin-left: .4rem; opacity: .5; font-weight: 400; }
.permalink:hover { opacity: 1; }
h2 { scroll-margin-top: 1rem; }
details.f { scroll-margin-top: 1rem; }
.top-link { display: inline-block; margin-top: .75rem; font-size: .82rem; }
</style>
</head>
<body>
<main>
HTML
}

_html_summary() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  printf '<h1 id="top">scoursh scan report</h1>\n'
  printf '<p class="sub">run <code>%s</code> · tool <code>%s</code> · fingerprint schema <code>%s</code> · %s live findings, %s accepted risk</p>\n' \
    "$(html_escape "${SCOURSH_RUN_ID:-}")" "$(html_escape "$(scoursh_version)")" \
    "$(html_escape "$FP_SCHEMA")" "$_RPT_LIVE" "$_RPT_SUPPRESSED"
  if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
    printf '<p class="banner">Redaction is DISABLED for this run. This report may contain live credentials and must not be circulated.</p>\n'
  fi
  _html_unrestricted_banner "$rundir"
  printf '<nav class="toc"><p>On this page</p><ul>\n'
  printf '<li><a href="#severity">Severity</a></li>\n'
  printf '<li><a href="#since-last-scan">Since the last scan</a></li>\n'
  (( ${#_RPT_MODULE[@]} > 0 )) && printf '<li><a href="#by-module">By module</a></li>\n'
  (( ${#_RPT_OWASP[@]} > 0 )) && printf '<li><a href="#by-owasp">By OWASP category</a></li>\n'
  printf '<li><a href="#findings">Findings (%s)</a></li>\n' "$_RPT_LIVE"
  (( _RPT_SUPPRESSED > 0 )) && printf '<li><a href="#accepted-risk">Accepted risk (%s)</a></li>\n' "$_RPT_SUPPRESSED"
  printf '<li><a href="#limitations">Limitations and coverage</a></li>\n'
  printf '</ul></nav>\n'
  printf '<h2 id="severity">Severity</h2>\n<div class="tiles">\n'
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
  printf '<h2 id="since-last-scan">Since the last scan</h2>\n<div class="tiles">\n'
  for k in new recurring fixed unknown; do
    printf '<div class="tile"><div class="n">%s</div><div class="l">%s</div></div>\n' \
      "${_RPT_STATUS[$k]:-0}" "$k"
  done
  printf '</div>\n'
  if (( ${#_RPT_MODULE[@]} > 0 )); then
    printf '<h2 id="by-module">By module</h2>\n<table><tr><th>module</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$k")" "${_RPT_MODULE[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_MODULE[@]}" | LC_ALL=C sort)"
    printf '</table>\n'
  fi
  if (( ${#_RPT_OWASP[@]} > 0 )); then
    printf '<h2 id="by-owasp">By OWASP category</h2>\n<table><tr><th>category</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$k")" "${_RPT_OWASP[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_OWASP[@]}" | LC_ALL=C sort)"
    printf '</table>\n'
  fi
}

_html_findings() {
  local rundir=$1 line
  printf '<h2 id="findings">Findings</h2>\n'
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
    printf '<h2 id="accepted-risk">Accepted risk (%s)</h2>\n' "$_RPT_SUPPRESSED"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      [[ ${_DF[suppressed]:-false} == true ]] || continue
      _html_one_finding
    done <"$rundir/findings.fields"
  fi
}

_html_one_finding() {
  local sev=${_DF[severity]:-info} loc fp_id
  loc=$(_location_summary)
  # The fingerprint is already the finding's own stable identity (tension 5:
  # never a line number, so it survives reindentation) - reused directly as
  # the anchor id so a link to one finding stays valid across re-runs whose
  # content did not change.
  fp_id="f-$(html_escape "${_DF[fingerprint]}")"
  # The location belongs in the COLLAPSED line, not only inside it: repeated
  # byte-identical matches of one check are distinct findings with distinct
  # fingerprints (tension 5), and a list that renders them as three identical
  # rows reads as a duplication bug.
  printf '<details class="f" id="%s" data-sev="%s"><summary><span class="sev %s">%s</span> <strong>%s</strong> - %s<span class="loc">%s</span><a class="permalink" href="#%s" title="Permalink to this finding">#</a></summary>\n' \
    "$fp_id" "$(html_escape "$sev")" "$(html_escape "$sev")" "$(html_escape "$sev")" \
    "$(html_escape "${_DF[check_id]}")" "$(html_escape "${_DF[title]}")" \
    "$(html_escape "$loc")" "$fp_id"
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

# The HTML half of DAST-34's banner.  Plain text through html_escape, in a
# TEXT NODE, never an attribute and never inside <script> or <style> - the same
# path every other untrusted string in this file takes (tension 10).  It reuses
# the existing `.banner` class rather than adding a style, so a report has one
# visual vocabulary for "read this before you read the findings".
_html_unrestricted_banner() {
  local rundir=$1 line any=0
  [[ -r $rundir/meta/limits_relaxed ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    if (( ! any )); then
      any=1
      printf '<div class="banner"><p>This run was UNRESTRICTED. Its conservative limits were lifted by an <code>--i-own-target</code> affirmation for %s, so an ABSENCE of availability or throttling findings below is not evidence about the target: it may only mean the scanner was told to ignore its own limits. What was lifted:</p>\n<ul>\n' \
        "$(html_escape "$(_meta_first "$rundir" authorization_scope_target)")"
    fi
    printf '<li>%s</li>\n' "$(html_escape "$line")"
  done <"$rundir/meta/limits_relaxed"
  (( any )) && printf '</ul></div>\n'
  return 0
}

_html_limitations() {
  local rundir=$1 line any=0
  printf '<h2 id="limitations">Limitations and coverage</h2>\n<ul>\n'
  if [[ -r $rundir/meta/limits_relaxed ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li><strong>unrestricted run</strong> (<code>--i-own-target</code>): %s</li>\n' \
        "$(html_escape "$line")"
    done <"$rundir/meta/limits_relaxed"
  fi
  if [[ -r $rundir/meta/limits_clamped ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li>limit clamped to the conservative default for an unaffirmed run: %s</li>\n' \
        "$(html_escape "$line")"
    done <"$rundir/meta/limits_clamped"
  fi
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
  printf '<p><a class="top-link" href="#top">&uarr; Back to top</a></p>\n'
  printf '<footer>Generated by scoursh %s. This report is self-contained: no external assets, no scripts, no network requests.</footer>\n' \
    "$(html_escape "$(scoursh_version)")"
  printf '</main>\n</body>\n</html>\n'
}

# ---------------------------------------------------------------------------
# 5. Generated location artifacts (tension 22 option 3, SARIF-02)
# ---------------------------------------------------------------------------
# `reports/<run>/locations/<module>.txt`: one line per finding whose profile
# carries no real, currently-resolvable file - docs/STEP10-SARIF-PLAN.md's
# four-case location table, case 3's fallback and case 4.  The line is the
# finding's own logical identity (SARIF-01's `logical_fqn`), so the file
# reads on its own and a future SARIF-04 click-through lands on a line that
# describes the resource in question, never a source file the finding is not
# about.
#
# The assigned line NUMBER is written back onto the finding's own `loc_line`
# - exactly the field SARIF-04's own mapping table already sends to
# `region.startLine` - so that ticket needs no case-3/4-specific location
# logic of its own; it can treat every profile identically once this has run.
#
# Case 1 (a real working-tree file: SAST native/adapters, IaC/adapters,
# containers) and case 2 (sca, whose own `path` field already names a real,
# committed lockfile) are untouched: no artifact line, no loc_line write.
# Case 3 (`SAST-HIST-*`) is a genuine filesystem test at write time - see
# `_locations_history_resolves` - never an assumption that a historical path
# still exists.
#
# Runs from `report_all`, BEFORE `findings_write_jsonl`/`findings_write_json`/
# `report_md`/`report_html`, and rewrites `findings.fields` in place - the
# same read-decode-mutate-reencode-rewrite shape `findings_mark_suppressed`
# already uses - so every one of those emitters, called after it, sees the
# write-back without re-deriving it.
#
# Written UNCONDITIONALLY by `report_all`, never gated on `--format sarif`:
# it is a real, cheap artifact of the run, and gating it would make the
# (still unbuilt) SARIF emitter's own behaviour depend on a file some OTHER
# format's flag decided to write.
#
# Ordering is exactly the order `findings.fields` is already in when this
# runs - (module, check_id, fingerprint) under `LC_ALL=C`, `findings_merge`'s
# own order, undisturbed by `derive_findings`' later re-sort - so two runs
# over the same input assign the same line to the same finding and produce
# byte-identical location files, with no second sort needed here.  A
# run-to-run reorder would churn every `startLine` SARIF-04 will read, even
# though `partialFingerprints` stays stable (tension 5).
report_locations() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  [[ -s $rundir/findings.fields ]] || return 0

  # `report_all` - and therefore this - runs once per module dispatched in
  # one run directory (`scan.sh all` calls modules/sast/run.sh's own
  # report_all, then modules/sca/run.sh's, then modules/iac/run.sh's, ...,
  # each after `findings_merge` has rebuilt findings.fields from EVERY
  # shard emitted so far - so a later call sees an earlier call's findings
  # again, not just its own).  `_loc_seen` truncates a module's artifact
  # file the FIRST time this call touches it, so every call is a full,
  # idempotent regeneration from the current findings.fields snapshot -
  # the same truncate-then-rebuild discipline findings_write_jsonl and
  # report_md/report_html already use - rather than an unbounded append
  # that would duplicate every earlier pass's lines and strand loc_line
  # pointing at the wrong row once the file had grown past it.
  local -A _loc_n=() _loc_seen=()
  local tmp=$SCOURSH_SCRATCH/locations.$$ line
  : >"$tmp"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    local mod=${_DF[module]:-} check=${_DF[check_id]:-} write=0 fallback=0
    case $mod in
      dast | cloud | posture | derived) write=1 ;;
      sast)
        if [[ $check == SAST-HIST-* ]] \
          && ! _locations_history_resolves "${_DF[loc_path]:-}"; then
          write=1
          fallback=1
        fi
        ;;
    esac
    if (( write )); then
      if [[ -z ${_loc_seen[$mod]:-} ]]; then
        _loc_seen[$mod]=1
        : >"$rundir/locations/$mod.txt"
      fi
      local n=$(( ${_loc_n[$mod]:-0} + 1 ))
      _loc_n[$mod]=$n
      if (( fallback )); then
        printf '%s (blob=%s commit=%s)\n' \
          "${_DF[logical_fqn]:-}" "${_DF[loc_blob_sha]:-}" "${_DF[commit]:-}" \
          >>"$rundir/locations/$mod.txt"
      else
        printf '%s\n' "${_DF[logical_fqn]:-}" >>"$rundir/locations/$mod.txt"
      fi
      _DF[loc_line]=$n
    fi
    _reencode_decoded >>"$tmp"
    printf '\n' >>"$tmp"
  done <"$rundir/findings.fields"
  mv "$tmp" "$rundir/findings.fields"
}

# Case 3's filesystem test: true only when `loc_path` still resolves to a
# real file under THIS run's scan root.  `SCOURSH_SCAN_ROOT_PATH` is exported
# by `scan.sh` alongside `SCOURSH_SCAN_ROOT_ID`/`SCOURSH_PATH_ROOT`, for the
# `sast`, `sca`, `iac` and `all` commands - the only commands that can ever
# emit a `SAST-HIST-*` finding in the first place.  Unset (a direct
# `report_locations`/`report_all` call outside `scan_main`, or a run with no
# `--path` at all) is treated as "cannot resolve": claiming a path resolves
# without knowing where the scan root is would be exactly the fabrication
# tension 22 forbids, so the safer default is the fallback artifact.
_locations_history_resolves() {
  local relpath=$1 root=${SCOURSH_SCAN_ROOT_PATH:-}
  [[ -n $root && -n $relpath ]] || return 1
  [[ -f $root/$relpath ]]
}

# ---------------------------------------------------------------------------
# 6. Everything
# ---------------------------------------------------------------------------
# `report_all [RUNDIR]` writes every artifact this run's resolved --format
# list selects (docs/DESIGN.md §5: `--format json,sarif,html,md`), plus two
# records this project treats as mandatory rather than format-selectable,
# neither of which is even in that four-value enum
# (`_scan_validate_csv`/`_scanner_validate_list_item`, scan.sh and
# lib/config.sh):
#
#   - `findings.jsonl` - docs/DESIGN.md §3's directory layout calls it out as
#     "reports/ timestamped output dirs (findings.jsonl per run)", a bullet
#     separate from and prior to the --format one; it is the incremental,
#     resumable ledger a later stage reads back (`_scan_require_prior_run`
#     accepts either it or run.json as proof of "a prior run directory").
#   - `run.json` - docs/DESIGN.md §4: "every run writes run.json"; it carries
#     the run's own identity and coverage_reduction facts that tension 12's
#     diff classifier and the CI baseline gate both depend on existing
#     unconditionally, whatever an operator asked `--format` for.
#
# `SCOURSH_FORMATS` is the CSV scan.sh resolves via config_scanner_list and
# exports before dispatch.  A caller that never sets it - every direct
# report_all call in this test suite, none of which goes through scan_main -
# gets the identical "every format" default `_scanner_default_list formats`
# already documents (lib/config.sh), so this function's own fallback and that
# documented default can never quietly diverge into two different answers to
# "what happens when nobody asked".
report_all() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  local _rpt_formats_csv=${SCOURSH_FORMATS:-json,sarif,html,md}
  local -a _rpt_fmt=()
  IFS=',' read -r -a _rpt_fmt <<<"$_rpt_formats_csv"
  local -A _rpt_want=()
  local _rpt_f
  for _rpt_f in "${_rpt_fmt[@]+"${_rpt_fmt[@]}"}"; do
    [[ -n $_rpt_f ]] && _rpt_want[$_rpt_f]=1
  done

  # Unconditional, per its own header comment above: it runs whatever
  # --format asked for, so every later emitter in this function sees the
  # loc_line write-back.
  report_locations "$rundir"
  findings_write_jsonl "$rundir"
  [[ -z ${_rpt_want[json]:-} ]] || findings_write_json "$rundir"
  [[ -z ${_rpt_want[md]:-} ]] || report_md "$rundir"
  [[ -z ${_rpt_want[html]:-} ]] || report_html "$rundir"
  # sarif: accepted by the CLI parser, no emitter exists yet
  # (docs/DESIGN.md §13 step 10; ROADMAP.md "Not yet started") - requesting
  # it selects nothing here, same as it always has, and that gap is tracked
  # on the roadmap rather than papered over with an emitter this ticket does
  # not own.
  report_run_json "$rundir"
}
