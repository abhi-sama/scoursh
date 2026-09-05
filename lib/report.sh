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
# SARIF 2.1.0 (docs/STEP10-SARIF-PLAN.md Track A) lives here as of SARIF-03/04;
# the compliance-mapping report (Track B) is still §13 step 10 and not here.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_REPORT_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_REPORT_SOURCED=1

# shellcheck source=lib/findings.sh
source "${BASH_SOURCE[0]%/*}/findings.sh"
# SARIF-03's tool.driver.rules[] needs checks_registry_load
# (lib/checks.sh), sourced here so a standalone lib/report.sh consumer (this
# file's own test suites) has it without a second wiring step - every real
# caller already has it too, since scan.sh sources both directly and every
# modules/*/run.sh reaches modules/dast/engine.sh -> lib/checks.sh before
# report_all ever runs.
# -x back-edge cut: an entry point that reaches BOTH this file and a DAST
# module (modules/dast/engine.sh has its own real edge to lib/checks.sh)
# would otherwise re-expand lib/checks.sh's own dependency chain a second
# time - exactly the diamond shape tests/lint-source-graph.sh's hub-sum cap
# exists to catch, and it did: tests/suites/dast-methods.sh went from 17 to
# 19 (cap 17) with this edge real. The runtime `source` on the next line is
# unaffected (its SCOURSH_CHECKS_SOURCED guard makes a repeat a no-op
# either way); only shellcheck -x's static follow is cut. Verified this
# loses no real checking for the entry points that need lib/checks.sh's
# declarations from THIS edge specifically - tests/suites/report.sh,
# sarif-locations.sh and sarif-rules.sh, none of which reach lib/checks.sh
# any other way - by shellchecking each standalone before and after.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/checks.sh"

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
_RPT_DAST_ZP_PHASES=0
_RPT_DAST_INJ_TESTED=0

# `_report_dast_injection_gap_state RUNDIR` - the counts behind the SPA/
# zero-parameter banner (`_md_zero_injection_banner`/`_html_zero_injection_banner`
# below): how many of this run's parameter-injection probes
# (modules/dast/active/{sqli,xss,ssti,cmdi,pathtraversal,ldapi,nosqli,
# protopollution,crlf,openredirect}.sh) found zero discovered request
# parameters on their target, and how many distinct `DAST-INJ-*` checks (the
# same family's own check-id namespace) DID run against a real one. Both are
# read from facts those scripts already record - this adds no new run.json
# field and changes nothing about what a check does, only what a reader is
# told and where.
#
# `reason=no_parameter_inventory` is deliberately the ONLY string matched.
# `reason=no_endpoint_inventory` is a distinct, separately-recorded reason
# shared with non-injection phases (passive/cookies.sh, passive/banner.sh,
# passive/cors.sh, active/hosthdr.sh, active/methods.sh, authz.sh,
# graphql.sh) that operate on endpoints rather than discovered PARAMETERS and
# run correctly against a thin endpoint surface - folding those in would flag
# an ordinary passive-only run that never needed a parameter at all.
_report_dast_injection_gap_state() {
  local rundir=$1 line
  _RPT_DAST_ZP_PHASES=0
  _RPT_DAST_INJ_TESTED=0
  if [[ -r $rundir/meta/coverage_reduction ]]; then
    while IFS= read -r line; do
      [[ $line == *'module=dast reason=no_parameter_inventory'* ]] || continue
      _RPT_DAST_ZP_PHASES=$(( _RPT_DAST_ZP_PHASES + 1 ))
    done <"$rundir/meta/coverage_reduction"
  fi
  if (( _RPT_DAST_ZP_PHASES > 0 )) && [[ -r $rundir/meta/checks_run ]]; then
    local -A seen=()
    while IFS= read -r line; do
      [[ -n $line && $line == DAST-INJ-* && -z ${seen[$line]:-} ]] || continue
      seen[$line]=1
      _RPT_DAST_INJ_TESTED=$(( _RPT_DAST_INJ_TESTED + 1 ))
    done <"$rundir/meta/checks_run"
  fi
}

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
  _report_dast_injection_gap_state "$rundir"
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

  # docs/STEP7-STATE-PLAN.md STATE-06: `fixed`/`unknown` never appear as a
  # LIVE finding above - they are prior findings ABSENT this run, so there is
  # nothing in findings.fields to have counted them from.  `lib/diff.sh`
  # writes their count into this small, separate ledger instead
  # (meta/diff_absent: one `status \t reason \t ...` line per prior finding
  # this run did not reproduce).  `meta/diff_present` is its mirror for the
  # standalone `diff` command, which has no findings.fields of its own at all
  # (it performs no scan) and so supplies new/recurring the identical way.
  local ledger_line st2
  if [[ -r $rundir/meta/diff_present ]]; then
    while IFS= read -r ledger_line; do
      [[ -n $ledger_line ]] || continue
      st2=${ledger_line%%$'\x1f'*}
      _RPT_STATUS[$st2]=$(( ${_RPT_STATUS[$st2]:-0} + 1 ))
    done <"$rundir/meta/diff_present"
  fi
  if [[ -r $rundir/meta/diff_absent ]]; then
    while IFS= read -r ledger_line; do
      [[ -n $ledger_line ]] || continue
      st2=${ledger_line%%$'\x1f'*}
      _RPT_STATUS[$st2]=$(( ${_RPT_STATUS[$st2]:-0} + 1 ))
    done <"$rundir/meta/diff_absent"
  fi
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
    _report_config_json "$rundir"
    printf '  "gate": %s,\n' "$(json_string "${SCOURSH_GATE_RESULT:-not-evaluated}")"
    printf '  "gated_findings": %s,\n' "$(json_number "${SCOURSH_GATED_FINDINGS:-0}")"
    printf '  "diff_usable": %s,\n' "$(json_bool "${SCOURSH_DIFF_USABLE:-false}")"
    _meta_array_unique "$rundir" rule_changed_checks 'rule_changed_checks'
    # docs/STEP7-STATE-PLAN.md STATE-06: which of fp_schema/scan_root_id
    # changed, when the guard fired - `diff_usable` alone answers "may the
    # gate trust this", never "why not", and an operator staring at a
    # permanently-unusable diff needs the second question answered too
    # (tension 12's own "recorded in run.json so an operator ... can see
    # why").  `not-evaluated` is the honest value for a run that never
    # reached classification at all (docs/DESIGN.md §5's `report` command,
    # still a stub - STATE-06's own scope is `diff` and automatic
    # classification only).
    printf '  "diff_guard": %s,\n' "$(json_string "${SCOURSH_DIFF_GUARD:-not-evaluated}")"
    _report_baseline_json "$rundir"
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

# The run's config record (docs/STEP-GUIDE-PLAN.md GUIDE-06, "What is
# recorded for audit", item 2).  Rendered on EVERY run, unlike `authorization`
# above: every command resolves config/scanner.conf, whether or not it ever
# reaches a network.
#
# `_REPORT_CONFIG_KEYS` is the single, alphabetically-sorted (LC_ALL=C) list
# of every scanner.conf key, so the rendered object's key order - and
# therefore its bytes - is deterministic across two runs that resolved the
# same settings, which is exactly what docs/STEP-GUIDE-PLAN.md GUIDE-06's own
# load-bearing round-trip test needs: two runs configured by different routes
# (a scripted guided answer stream, and the rendered command typed directly)
# but resolving the identical settings must produce a byte-identical `config`
# object.  scan.sh's `_scan_record_config` is the writer; this is the only
# reader, so the two can never drift on which keys exist.
readonly -a _REPORT_CONFIG_KEYS=(
  circuit-breaker-failures circuit-breaker-window contact evidence-max-bytes
  fail-on formats history-max-commits history-window-days http-timeout jobs
  lock-stale-seconds max-matches-per-file max-redirects min-confidence
  mutex-timeout-seconds paranoid-allow recommended-header redact-secrets
  request-budget requests-per-second scratch-dir state-retain-runs
  tls-expiry-warn-days
)

_report_config_is_list_key() {
  case $1 in
    formats | paranoid-allow | recommended-header) return 0 ;;
    *) return 1 ;;
  esac
}

_report_config_json() {
  local rundir=$1 key first=1 line first2
  printf '  "config": {\n'
  printf '    "scanner_conf_sha256": %s,\n' "$(json_string "$(_meta_first "$rundir" config_scanner_conf_sha256)")"
  printf '    "scope_conf_sha256": %s,\n' "$(json_string "$(_meta_first "$rundir" config_scope_conf_sha256)")"
  printf '    "settings": {\n'
  for key in "${_REPORT_CONFIG_KEYS[@]+"${_REPORT_CONFIG_KEYS[@]}"}"; do
    (( first )) || printf ',\n'
    first=0
    printf '      %s: {"value": ' "$(json_string "$key")"
    if _report_config_is_list_key "$key"; then
      printf '['
      first2=1
      if [[ -r $rundir/meta/config_value_$key ]]; then
        while IFS= read -r line; do
          [[ -n $line ]] || continue
          (( first2 )) || printf ','
          first2=0
          printf '%s' "$(json_string "$line")"
        done <"$rundir/meta/config_value_$key"
      fi
      printf ']'
    else
      printf '%s' "$(json_string "$(_meta_first "$rundir" "config_value_$key")")"
    fi
    printf ', "source": %s}' "$(json_string "$(_meta_first "$rundir" "config_source_$key")")"
  done
  printf '\n    }\n'
  printf '  },\n'
}

# The run's baseline-suppression object (docs/STEP7-STATE-PLAN.md STATE-07;
# tension 11 stages 6 and 9).  Rendered on EVERY run, not only one that
# actually used a baseline, for the identical reason `_report_authorization_json`
# above always renders: an absent key would be ambiguous between "no baseline
# configured" and "this version does not record it".  `lib/diff.sh`'s
# `baseline_apply` writes these five meta files fresh on every call (it is
# called once per module for `scan.sh all`, over the SAME growing
# findings.fields, and only the LAST call's counts are authoritative - its own
# header states why they are truncated rather than appended), so a run that
# never reached it at all (any command besides sast/iac/sca/dast/all) reads
# every field here as its honest empty default.
#
# `stale` (tension 11: "an entry that matched nothing this run is reported as
# stale ... so the list shrinks under normal use") and `expired` (tension 11:
# "after that date the entry stops suppressing and the report says so") are
# each rendered as their own object per entry, never a bare fingerprint
# string, because the `reason` (and, for an expired entry, the `expires`
# date) is exactly what an operator needs to decide whether to prune it -
# `_meta_array`'s plain-string rendering is the wrong shape for that reason,
# not reused here.
_report_baseline_json() {
  local rundir=$1
  printf '  "baseline": {\n'
  printf '    "used": %s,\n' "$(json_bool "$(_meta_first "$rundir" baseline_used)")"
  printf '    "file": %s,\n' "$(json_string "$(_meta_first "$rundir" baseline_file)")"
  printf '    "entries": %s,\n' "$(json_number "$(_meta_first "$rundir" baseline_entries)")"
  local first=1 fp reason expires
  printf '    "stale": ['
  if [[ -r $rundir/meta/baseline_stale ]]; then
    while IFS=$'\x1f' read -r fp reason; do
      [[ -n $fp ]] || continue
      (( first )) || printf ','
      first=0
      printf '\n      {"fingerprint":%s,"reason":%s}' "$(json_string "$fp")" "$(json_string "$reason")"
    done <"$rundir/meta/baseline_stale"
  fi
  (( first )) || printf '\n    '
  printf '],\n'
  first=1
  printf '    "expired": ['
  if [[ -r $rundir/meta/baseline_expired ]]; then
    while IFS=$'\x1f' read -r fp reason expires; do
      [[ -n $fp ]] || continue
      (( first )) || printf ','
      first=0
      printf '\n      {"fingerprint":%s,"reason":%s,"expires":%s}' \
        "$(json_string "$fp")" "$(json_string "$reason")" "$(json_string "$expires")"
    done <"$rundir/meta/baseline_expired"
  fi
  (( first )) || printf '\n    '
  printf ']\n'
  printf '  }\n'
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
    _md_zero_injection_banner
    _md_diff_delta "$rundir"
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

# `_md_diff_delta RUNDIR` - docs/STEP7-STATE-PLAN.md STATE-06; tension 11
# stage 9 ("the report leads with this delta").  Reads `_RPT_STATUS`
# (`report_count`, already called by `report_md`/`report_html` before this)
# for the four counts and `$rundir/meta/diff_absent` for the per-finding
# fixed/unknown listing; `SCOURSH_DIFF_GUARD`/`SCOURSH_DIFF_USABLE` are
# `lib/diff.sh`'s own exported result of this run's classification.
#
# The one sentence this function exists to make unmistakable, per this
# ticket's own acceptance criterion: `fixed` means this run looked and found
# nothing there any more; `unknown` ("not assessed this run") means this run
# never looked, so nothing was verified either way.  Rendering both under one
# undifferentiated heading is exactly the blur tension 12 was written to
# prevent, so they are always two headings, never one.
# SC2016: the Markdown code spans below are literal output, not command
# substitution.
# shellcheck disable=SC2016
_md_diff_delta() {
  local rundir=$1
  printf '## Since last scan\n\n'
  if [[ ${SCOURSH_DIFF_GUARD:-not-evaluated} != usable ]]; then
    case ${SCOURSH_DIFF_GUARD:-not-evaluated} in
      no_prior_state)
        printf '> This is the first recorded run - everything below is `new`.\n\n' ;;
      fp_schema_mismatch)
        printf '> **The fingerprint schema changed since the prior run.** Prior findings are\n'
        printf '> carried forward as `not assessed this run`, never `fixed`, and a baseline\n'
        printf '> rebuild is required.\n\n' ;;
      scan_root_id_mismatch)
        printf '> **The scan root identity changed since the prior run** for path-scoped\n'
        printf '> findings (SAST/SCA/IaC/history). Those prior findings are carried forward as\n'
        printf '> `not assessed this run`, never `fixed`, and a baseline rebuild is required\n'
        printf '> for them.\n\n' ;;
      *)
        printf '> Prior state is not usable for classification (`%s`).\n\n' "${SCOURSH_DIFF_GUARD:-not-evaluated}" ;;
    esac
  fi
  printf -- '- **%s** new\n' "${_RPT_STATUS[new]:-0}"
  printf -- '- **%s** recurring\n' "${_RPT_STATUS[recurring]:-0}"
  printf -- '- **%s** fixed\n' "${_RPT_STATUS[fixed]:-0}"
  printf -- '- **%s** not assessed this run\n\n' "${_RPT_STATUS[unknown]:-0}"
  _md_diff_ledger "$rundir/meta/diff_absent" fixed \
    'Fixed since last scan' \
    'Reported in a prior run and absent from this one, in a check and location this run actually covered - remediation is verified.' \
    '| check | cell | severity | first seen |' '|---|---|---|---|' false
  _md_diff_ledger "$rundir/meta/diff_absent" unknown \
    'Not assessed this run' \
    'Reported in a prior run, but this run did not cover their check and location - so status is **unknown, not verified fixed**. Appearing here is not evidence of remediation; it means this run never looked.' \
    '| check | cell | severity | first seen | reason |' '|---|---|---|---|---|' true
}

# `_md_diff_ledger LEDGER_FILE WANT_STATUS HEADING BLURB TABLE_HEADER
#                  TABLE_RULE SHOW_REASON`
# SC2016: the Markdown code spans below are literal output, not command
# substitution.
# shellcheck disable=SC2016
_md_diff_ledger() {
  local ledger=$1 want=$2 heading=$3 blurb=$4 thead=$5 trule=$6 show_reason=$7
  [[ -r $ledger ]] || return 0
  local status reason check cell severity first_seen fp any=0
  while IFS=$'\x1f' read -r status reason check cell severity first_seen fp; do
    [[ $status == "$want" ]] || continue
    any=1
    break
  done <"$ledger"
  (( any )) || return 0
  printf '### %s\n\n%s\n\n' "$heading" "$blurb"
  printf '%s\n%s\n' "$thead" "$trule"
  while IFS=$'\x1f' read -r status reason check cell severity first_seen fp; do
    [[ $status == "$want" ]] || continue
    if [[ $show_reason == true ]]; then
      printf '| `%s` | `%s` | %s | %s | %s |\n' "$check" "${cell:--}" "$severity" "$first_seen" \
        "${reason:-not-covered-this-run}"
    else
      printf '| `%s` | `%s` | %s | %s |\n' "$check" "${cell:--}" "$severity" "$first_seen"
    fi
  done <"$ledger"
  printf '\n'
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

# `_md_zero_injection_banner` - the human-readable, top-of-report half of the
# SPA/API-behind-JavaScript gap: a target whose crawl found endpoints but zero
# discovered request PARAMETERS gets every injection probe (SQL injection,
# XSS, SSTI, command/path/LDAP/NoSQL injection, CRLF, open redirect, prototype
# pollution) reporting a clean severity table for a reason that has nothing to
# do with the target's security. Each probe already records its own
# `coverage_reduction`/`coverage_gap` (docs/FOUNDATION.md tension 21), but
# those only reach run.json and the bottom-of-report Limitations section
# (`_md_limitations`) - this restates the same, already-true fact where a
# reader sees it BEFORE the severity table, in `_md_unrestricted_banner`'s own
# blockquote style. Uses only integers computed by
# `_report_dast_injection_gap_state` (via `report_count`, already called by
# every caller of this file's own `report_md`/`report_html`), so nothing here
# needs escaping.
#
# Two distinct messages, never one, because a run that tested SOME parameters
# is not the same claim as a run that tested NONE - see the acceptance
# criterion this exists for: "a partial-coverage run reports the truth, not a
# blanket claim".
# SC2016: the Markdown code spans below are literal output, not command
# substitution - the same note report_md itself already carries.
# shellcheck disable=SC2016
_md_zero_injection_banner() {
  (( ${_RPT_DAST_ZP_PHASES:-0} > 0 )) || return 0
  if (( ${_RPT_DAST_INJ_TESTED:-0} == 0 )); then
    printf '> **No injection test was actually sent - this is NOT a clean result.**\n'
    printf '> %s discovered-parameter probe(s) in this run (SQL injection, XSS, command\n' \
      "$_RPT_DAST_ZP_PHASES"
    printf '> injection, path/LDAP/NoSQL injection, SSTI, CRLF, open redirect, prototype\n'
    printf '> pollution) found ZERO request parameters on this target and sent no payload\n'
    printf '> at all. A quiet severity table below means these checks never ran, not that\n'
    printf '> they ran and found nothing - the common cause is a single-page application\n'
    printf '> whose real API is reached only by in-browser JavaScript, invisible to the\n'
    printf '> static crawler (docs/DESIGN.md §7.5). To fix: point `config/discovery.conf`\n'
    printf '> at an OpenAPI spec, GraphQL schema, Postman collection, or HAR capture of\n'
    printf '> real traffic for this target (the\n'
    printf '> `openapi-path`/`graphql-schema-path`/`postman-path`/`har-path` keys,\n'
    printf '> `rules/RULE-FORMAT.md` §9.6.3), then re-run.\n\n'
  else
    printf '> **Partial injection coverage.** %s of the discovered-parameter probes in\n' \
      "$_RPT_DAST_ZP_PHASES"
    printf '> this run found zero parameters to test on this target, while %s check(s)\n' \
      "$_RPT_DAST_INJ_TESTED"
    printf '> ran against real ones. The severity table below reflects only what was\n'
    printf '> actually tested - see "Limitations and coverage" for exactly which probes\n'
    printf '> were skipped and why, and consider supplying `config/discovery.conf`\n'
    printf '> (OpenAPI/GraphQL/Postman/HAR) to close the gap.\n\n'
  fi
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
  # docs/STEP7-STATE-PLAN.md STATE-07; tension 11 "an entry that matched
  # nothing this run is reported as stale ... so the list shrinks under
  # normal use" and "after that date the entry stops suppressing and the
  # report says so".  A stale entry is ALSO what makes tension 11's "a
  # baselined finding that gets fixed is still reported fixed, with a note to
  # prune the entry" true in the report a human reads, not only in run.json.
  local fp reason expires
  if [[ -r $rundir/meta/baseline_stale ]]; then
    while IFS=$'\x1f' read -r fp reason; do
      [[ -n $fp ]] || continue
      any=1
      printf -- '- baseline entry matched nothing this run, consider removing it: `%s`%s\n' \
        "$fp" "${reason:+ (reason: $reason)}"
    done <"$rundir/meta/baseline_stale"
  fi
  if [[ -r $rundir/meta/baseline_expired ]]; then
    while IFS=$'\x1f' read -r fp reason expires; do
      [[ -n $fp ]] || continue
      any=1
      printf -- '- baseline entry expired on %s and no longer suppresses its finding: `%s`%s\n' \
        "$expires" "$fp" "${reason:+ (reason: $reason)}"
    done <"$rundir/meta/baseline_expired"
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

# docs/STEP7-STATE-PLAN.md STATE-06.  Mirrors `_md_diff_delta`'s own guard
# banner (lib/report.sh section 3) - see that function's comment for the
# reasoning; escaped through `html_escape` on principle even though every
# value here is this tool's own internal vocabulary, never target-derived.
_html_diff_guard_banner() {
  local guard=${SCOURSH_DIFF_GUARD:-not-evaluated}
  [[ $guard != usable ]] || return 0
  local msg
  case $guard in
    no_prior_state)
      msg='This is the first recorded run - everything below is <code>new</code>.' ;;
    fp_schema_mismatch)
      msg='<strong>The fingerprint schema changed since the prior run.</strong> Prior findings are carried forward as <code>not assessed this run</code>, never <code>fixed</code>, and a baseline rebuild is required.' ;;
    scan_root_id_mismatch)
      msg='<strong>The scan root identity changed since the prior run</strong> for path-scoped findings (SAST/SCA/IaC/history). Those prior findings are carried forward as <code>not assessed this run</code>, never <code>fixed</code>, and a baseline rebuild is required for them.' ;;
    *)
      msg="Prior state is not usable for classification (<code>$(html_escape "$guard")</code>)." ;;
  esac
  printf '<p class="sub">%s</p>\n' "$msg"
}

# `_html_diff_delta RUNDIR` - the fixed/unknown listing, tables mirroring
# `_md_diff_ledger`'s own two headings.  Read straight from
# `$rundir/meta/diff_absent`; every value is escaped even though none of it
# is target-derived (tension 10's discipline applied uniformly rather than
# selectively).
_html_diff_delta() {
  local rundir=$1
  local ledger=$rundir/meta/diff_absent
  [[ -r $ledger ]] || return 0
  local status reason check cell severity first_seen fp any_fixed=0 any_unknown=0
  while IFS=$'\x1f' read -r status reason check cell severity first_seen fp; do
    [[ $status == fixed ]] && any_fixed=1
    [[ $status == unknown ]] && any_unknown=1
  done <"$ledger"
  if (( any_fixed )); then
    printf '<h3>Fixed since last scan</h3>\n'
    printf '<p class="sub">Reported in a prior run and absent from this one, in a check and location this run actually covered - remediation is verified.</p>\n'
    printf '<table><tr><th>check</th><th>cell</th><th>severity</th><th>first seen</th></tr>\n'
    while IFS=$'\x1f' read -r status reason check cell severity first_seen fp; do
      [[ $status == fixed ]] || continue
      printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$check")" "$(html_escape "${cell:--}")" "$(html_escape "$severity")" \
        "$(html_escape "$first_seen")"
    done <"$ledger"
    printf '</table>\n'
  fi
  if (( any_unknown )); then
    printf '<h3>Not assessed this run</h3>\n'
    printf '<p class="sub">Reported in a prior run, but this run did not cover their check and location - so status is <strong>unknown, not verified fixed</strong>. Appearing here is not evidence of remediation; it means this run never looked.</p>\n'
    printf '<table><tr><th>check</th><th>cell</th><th>severity</th><th>first seen</th><th>reason</th></tr>\n'
    while IFS=$'\x1f' read -r status reason check cell severity first_seen fp; do
      [[ $status == unknown ]] || continue
      printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$check")" "$(html_escape "${cell:--}")" "$(html_escape "$severity")" \
        "$(html_escape "$first_seen")" "$(html_escape "${reason:-not-covered-this-run}")"
    done <"$ledger"
    printf '</table>\n'
  fi
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
  _html_zero_injection_banner
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
  printf '<h2 id="since-last-scan">Since the last scan</h2>\n'
  _html_diff_guard_banner
  printf '<div class="tiles">\n'
  for k in new recurring fixed unknown; do
    printf '<div class="tile"><div class="n">%s</div><div class="l">%s</div></div>\n' \
      "${_RPT_STATUS[$k]:-0}" "$k"
  done
  printf '</div>\n'
  _html_diff_delta "$rundir"
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

# The HTML twin of `_md_zero_injection_banner` - same condition, same two
# messages, same reused `.banner` class, and the same "read this before the
# severity table" placement `_html_unrestricted_banner` already established.
# The two integers it prints come only from `_report_dast_injection_gap_state`
# (via `report_count`), so nothing here is target-derived and nothing needs
# `html_escape`.
_html_zero_injection_banner() {
  (( ${_RPT_DAST_ZP_PHASES:-0} > 0 )) || return 0
  if (( ${_RPT_DAST_INJ_TESTED:-0} == 0 )); then
    printf '<div class="banner"><p><strong>No injection test was actually sent - this is NOT a clean result.</strong> %s discovered-parameter probe(s) in this run (SQL injection, XSS, command injection, path/LDAP/NoSQL injection, SSTI, CRLF, open redirect, prototype pollution) found ZERO request parameters on this target and sent no payload at all. A quiet severity table below means these checks never ran, not that they ran and found nothing - the common cause is a single-page application whose real API is reached only by in-browser JavaScript, invisible to the static crawler (docs/DESIGN.md &sect;7.5). To fix: point <code>config/discovery.conf</code> at an OpenAPI spec, GraphQL schema, Postman collection, or HAR capture of real traffic for this target (the <code>openapi-path</code>/<code>graphql-schema-path</code>/<code>postman-path</code>/<code>har-path</code> keys, <code>rules/RULE-FORMAT.md</code> &sect;9.6.3), then re-run.</p></div>\n' \
      "$_RPT_DAST_ZP_PHASES"
  else
    printf '<div class="banner"><p><strong>Partial injection coverage.</strong> %s of the discovered-parameter probes in this run found zero parameters to test on this target, while %s check(s) ran against real ones. The severity table below reflects only what was actually tested - see "Limitations and coverage" for exactly which probes were skipped and why, and consider supplying <code>config/discovery.conf</code> (OpenAPI/GraphQL/Postman/HAR) to close the gap.</p></div>\n' \
      "$_RPT_DAST_ZP_PHASES" "$_RPT_DAST_INJ_TESTED"
  fi
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
  # docs/STEP7-STATE-PLAN.md STATE-07 - see _md_limitations's own comment on
  # this identical pair of blocks for the tension-11 wording both mirror.
  local fp reason expires
  if [[ -r $rundir/meta/baseline_stale ]]; then
    while IFS=$'\x1f' read -r fp reason; do
      [[ -n $fp ]] || continue
      any=1
      printf '<li>baseline entry matched nothing this run, consider removing it: <code>%s</code>%s</li>\n' \
        "$(html_escape "$fp")" "$([[ -n $reason ]] && printf ' (reason: %s)' "$(html_escape "$reason")")"
    done <"$rundir/meta/baseline_stale"
  fi
  if [[ -r $rundir/meta/baseline_expired ]]; then
    while IFS=$'\x1f' read -r fp reason expires; do
      [[ -n $fp ]] || continue
      any=1
      printf '<li>baseline entry expired on %s and no longer suppresses its finding: <code>%s</code>%s</li>\n' \
        "$(html_escape "$expires")" "$(html_escape "$fp")" \
        "$([[ -n $reason ]] && printf ' (reason: %s)' "$(html_escape "$reason")")"
    done <"$rundir/meta/baseline_expired"
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
# 5a. SARIF 2.1.0 (docs/STEP10-SARIF-PLAN.md SARIF-03; docs/DESIGN.md §4;
#     docs/FOUNDATION.md tension 22)
# ---------------------------------------------------------------------------
# The static half of the document only: `$schema`/`version`, `tool.driver`
# (`name`, `version`, `informationUri`, `rules[]`), `artifacts[]`,
# `invocations[]`, and `results: []`.  SARIF-04 owns the per-finding mapping
# into `results[]`.
#
# `tool.driver.rules[]` is tension 22's "the full loaded check registry, keyed
# by check_id" - but three id families a finding can legitimately carry have
# no on-disk record at all (SARIF-03's own "trap"): SCA ids (`modules/sca/`
# ships no `*.rules` file by design - a table lookup, not a pattern-rule
# engine), adapter ids (`<engine>:<engine's own rule id>`, minted at runtime
# by `<engine>_normalize`, docs/ADAPTERS.md §6), and derived/composite ids
# (`rules/derived.rules` is deliberately unseeded, findings F5/F20).  A SARIF
# consumer rejects a `result.ruleId` with no matching `reportingDescriptor`,
# so `rules[]` also has to cover every check id THIS RUN's findings actually
# carry, not only what `checks_registry_load` found on disk - even though
# `results[]` itself stays empty until SARIF-04.  For the three ungoverned
# families the descriptor is SYNTHESISED from the finding's own fields (id,
# `name` from `title`, `help.text` from `remediation`,
# `defaultConfiguration.level` from `base_severity`) and carries
# `properties.descriptorSource: "synthesised"`, so the difference from a
# registry-backed descriptor is visible in the document rather than hidden.
# A registry-backed descriptor is never marked this way.

# `severity`/`base_severity` -> SARIF `level`.  SARIF 2.1.0 has four levels;
# scoursh has five severities, so this necessarily collapses two pairs
# (critical/high -> error, low/info -> note) - `info` is deliberately NOT
# `none`, because `none` means "this rule did not evaluate to a problem",
# which is not what an `info` finding says.  SARIF-04's `result.level`
# mapping is the same table; this is `reportingDescriptor.defaultConfiguration
# .level`, the check's own BASE severity rather than a per-result one.
_sarif_level_for() {
  case ${1:-} in
    critical | high) printf 'error' ;;
    medium) printf 'warning' ;;
    low | info) printf 'note' ;;
    *) printf 'note' ;;
  esac
}

# Populates the global _SARIF_REG_LOC[check_id]="set idx" map from every
# on-disk `*.rules` file `checks_registry_load` finds under sast/sca/iac/dast/
# cloud (posture nests under `modules/cloud/`, so its own checks.rules is
# covered by the `cloud` call; rules/derived.rules and rules/redaction.rules
# live outside modules/ entirely and are never loaded here - the former is
# deliberately unseeded, the latter's ids are never a finding's check_id).
# Called DIRECTLY, never through $(...): checks_registry_load's own die() on a
# malformed registry file must abort the run, exactly as it does for the
# module-level callers in modules/*/run.sh, and a die() inside a command
# substitution does not reliably do that (checks.sh's own comment on
# CHECKS_REGISTRY_SETS).  Each call resets CHECKS_REGISTRY_SETS, so results
# are accumulated into _SARIF_REG_LOC across the five module calls rather than
# read from that global once at the end.
declare -A _SARIF_REG_LOC=()
_sarif_build_registry() {
  _SARIF_REG_LOC=()
  local module set idx n cid
  for module in sast sca iac dast cloud; do
    checks_registry_load "$module" "_sarif_reg_$module"
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      n=$(records_count "$set")
      for (( idx = 0; idx < n; idx++ )); do
        cid=$(records_id "$set" "$idx")
        [[ -n $cid ]] || continue
        _SARIF_REG_LOC[$cid]="$set $idx"
      done
    done
  done
}

# Populates the globals _SARIF_FIND_TITLE/_SARIF_FIND_REMEDIATION/
# _SARIF_FIND_BASESEV[check_id], one entry per DISTINCT check_id this run's
# findings.fields carries, from the FIRST finding of that check_id in file
# order.  This is what makes a synthesised descriptor possible at all for the
# three ungoverned families: their only source of a title/remediation/
# severity is the finding itself, since no record exists for them.
declare -A _SARIF_FIND_TITLE=()
declare -A _SARIF_FIND_REMEDIATION=()
declare -A _SARIF_FIND_BASESEV=()
_sarif_index_findings() {
  local rundir=$1 line cid
  _SARIF_FIND_TITLE=()
  _SARIF_FIND_REMEDIATION=()
  _SARIF_FIND_BASESEV=()
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    cid=${_DF[check_id]:-}
    [[ -n $cid ]] || continue
    [[ -n ${_SARIF_FIND_TITLE[$cid]+set} ]] && continue
    _SARIF_FIND_TITLE[$cid]=${_DF[title]:-}
    _SARIF_FIND_REMEDIATION[$cid]=${_DF[remediation]:-}
    _SARIF_FIND_BASESEV[$cid]=${_DF[base_severity]:-}
  done <"$rundir/findings.fields"
}

# One reportingDescriptor for a registry-backed check id (`set idx` into
# lib/records.sh).  Carries the check's own remediation, references, cwe,
# owasp, cis and rule_digest - never `properties.descriptorSource`, which is
# reserved for the synthesised case so its presence alone marks the
# difference.
_sarif_descriptor_registry() {  # set idx
  local set=$1 idx=$2 cid title sev cwe owasp remediation digest
  cid=$(records_id "$set" "$idx")
  title=$(records_field "$set" "$idx" title)
  sev=$(records_field "$set" "$idx" severity)
  cwe=$(records_field_or "$set" "$idx" cwe none)
  owasp=$(records_field_or "$set" "$idx" owasp none)
  remediation=$(records_field "$set" "$idx" remediation)
  digest=$(records_digest "$set" "$idx")

  local help=$remediation uri='' ref refs
  refs=$(records_list "$set" "$idx" references)
  if [[ -n $refs ]]; then
    help+=$'\n\nReferences:'
    while IFS= read -r ref; do
      [[ -n $ref ]] || continue
      help+=$'\n- '"$ref"
      if [[ -z $uri && $ref =~ ^https?:// ]]; then
        uri=$ref
      fi
    done <<<"$refs"
  fi

  printf '{'
  printf '"id":%s' "$(json_string "$cid")"
  printf ',"name":%s' "$(json_string "$title")"
  printf ',"help":{"text":%s}' "$(json_string "$help")"
  [[ -z $uri ]] || printf ',"helpUri":%s' "$(json_string "$uri")"
  printf ',"defaultConfiguration":{"level":%s}' "$(json_string "$(_sarif_level_for "$sev")")"
  printf ',"properties":{'
  printf '"ruleDigest":%s' "$(json_string "$digest")"
  printf ',"tags":['
  local tfirst=1 cisv cislist
  if [[ $cwe != none ]]; then
    printf '%s' "$(json_string "external/cwe/$cwe")"
    tfirst=0
  fi
  if [[ $owasp != none ]]; then
    (( tfirst )) || printf ','
    printf '%s' "$(json_string "external/owasp/$owasp")"
    tfirst=0
  fi
  cislist=$(records_list "$set" "$idx" cis)
  if [[ -n $cislist ]]; then
    while IFS= read -r cisv; do
      [[ -n $cisv ]] || continue
      (( tfirst )) || printf ','
      printf '%s' "$(json_string "external/cis/$cisv")"
      tfirst=0
    done <<<"$cislist"
  fi
  printf ']'
  printf '}'
  printf '}'
}

# One reportingDescriptor synthesised from a finding, for a check id in one of
# the three families no *.rules record covers.  Exactly the fields the plan
# names - id, name, help, defaultConfiguration.level - and nothing a registry
# record would otherwise supply (no cwe/owasp/cis tags, no rule_digest): there
# is no check record to take them from, and inventing them would be exactly
# the fabrication tension 22 forbids elsewhere in this file.
_sarif_descriptor_synth() {  # check_id
  local cid=$1
  printf '{'
  printf '"id":%s' "$(json_string "$cid")"
  printf ',"name":%s' "$(json_string "${_SARIF_FIND_TITLE[$cid]:-}")"
  printf ',"help":{"text":%s}' "$(json_string "${_SARIF_FIND_REMEDIATION[$cid]:-}")"
  printf ',"defaultConfiguration":{"level":%s}' \
    "$(json_string "$(_sarif_level_for "${_SARIF_FIND_BASESEV[$cid]:-}")")"
  printf ',"properties":{"descriptorSource":"synthesised"}'
  printf '}'
}

# Prints `tool.driver.rules[]` directly to stdout (never captured through
# $(...) - see _sarif_build_registry's own comment on why).  Requires
# _sarif_build_registry and _sarif_index_findings to have already run for this
# rundir.  The id set is the union of the on-disk registry and this run's
# findings, sorted LC_ALL=C for a deterministic, byte-reproducible document -
# the same discipline every other emitter in this file follows.
_sarif_print_rules() {
  local ids cid loc set idx first=1
  ids=$(
    { for cid in "${!_SARIF_REG_LOC[@]}"; do printf '%s\n' "$cid"; done
      for cid in "${!_SARIF_FIND_TITLE[@]}"; do printf '%s\n' "$cid"; done
    } | LC_ALL=C sort -u
  )
  printf '['
  while IFS= read -r cid; do
    [[ -n $cid ]] || continue
    (( first )) || printf ','
    first=0
    if [[ -n ${_SARIF_REG_LOC[$cid]:-} ]]; then
      loc=${_SARIF_REG_LOC[$cid]}
      set=${loc% *}
      idx=${loc##* }
      _sarif_descriptor_registry "$set" "$idx"
    else
      _sarif_descriptor_synth "$cid"
    fi
  done <<<"$ids"
  printf ']'
}

# `runs[0].artifacts[]` - tension 22: the SARIF-02 generated location artifact
# "is included in the SARIF artifacts array".  One entry per
# `locations/<module>.txt` this run actually wrote (report_locations creates a
# module's file only the first time it has a finding needing the fallback), a
# real file `report_sarif`'s own writer creates alongside, so a relative URI
# resolves against the SARIF document's own location.  Never lists a real
# working-tree source file (case 1) or an SCA lockfile (case 2): those already
# exist independent of this run, and tension 22's artifacts-array requirement
# names the GENERATED artifact specifically.
_sarif_print_artifacts() {
  local rundir=$1 f base first=1
  printf '['
  if [[ -d $rundir/locations ]]; then
    while IFS= read -r f; do
      [[ -n $f ]] || continue
      base=${f#"$rundir"/}
      (( first )) || printf ','
      first=0
      printf '{"location":{"uri":%s}}' "$(json_string "$base")"
    done < <(find "$rundir/locations" -maxdepth 1 -type f -name '*.txt' 2>/dev/null | LC_ALL=C sort)
  fi
  printf ']'
}

# True (0) when this run recorded at least one `incomplete_reason` line - the
# same non-empty-incomplete_reason test report.sh's own header already names
# as "exactly the exit-5 predicate".  `invocations[0].executionSuccessful` is
# about whether the TOOL completed, not about a --fail-on gate verdict, so
# this is the honest signal for it independent of call-stack position.
_sarif_run_incomplete() {
  local rundir=$1 line
  [[ -r $rundir/meta/incomplete_reason ]] || return 1
  while IFS= read -r line; do
    [[ -n $line ]] && return 0
  done <"$rundir/meta/incomplete_reason"
  return 1
}

# ---------------------------------------------------------------------------
# 5b. SARIF 2.1.0 results[] (docs/STEP10-SARIF-PLAN.md SARIF-04)
# ---------------------------------------------------------------------------
# The per-finding mapping. The field-by-field table and the four-case
# location table in docs/STEP10-SARIF-PLAN.md ARE the specification; this
# section implements them and does not re-derive them. Every finding is read
# through finding_decode (never a hand-rolled parse of findings.fields),
# exactly as findings_write_json and every other emitter in this file already
# do - which is also what keeps this emitter inside the redaction guarantee,
# since finding_emit is the single chokepoint every finding passes through
# and _finding_secret_backstop has already run by then.
#
# Deliberately does NOT emit `security-severity`: cvss_vector_of takes
# exposure/auth/sensitive_data/confidence and NONE of them is a severity, so
# the CVSS score scoursh computes is an audit trail for how the rubric moved
# severity, not an independent score - a critical and an info finding with
# identical rubric facts carry the SAME cvss score. Publishing that as
# `security-severity` would have GitHub code scanning (which reads that
# property and IGNORES result.level) display a severity that contradicts
# result.level, run.json, the HTML report and the --fail-on gate. severity
# maps to result.level instead (five-to-four, _sarif_level_for, reused
# unchanged from SARIF-03's rule-level mapping - same table, same function),
# and cvss is carried in result.properties for audit only.

# The four-case location table. Sets _SARIF_LOC_URI (never empty for a
# well-formed finding) and _SARIF_LOC_LINE (empty string when the profile
# carries no line at all - sca, case 2 - so the caller omits `region`
# entirely rather than defaulting it to 1).
#
# Case 1 (path profile: sast native/adapters, iac, iac adapters, containers)
# and the resolving half of case 3 (history) both point at the real,
# scan-root-relative loc_path with loc_line untouched. Case 2 (sca) points at
# the finding's own `path` field (the lockfile), which is NOT loc_path and
# NOT a fingerprint component (tension 5/25: adding it to the sca profile
# would change every shipped SCA check id's fingerprint) - and carries no
# line at all. The non-resolving half of case 3, and case 4 (dast, cloud,
# posture, derived) point at report_locations' own generated artifact,
# `locations/<module>.txt`, with loc_line the line SARIF-02 already wrote
# back onto the finding - so this function needs no line bookkeeping of its
# own, only the URI decision the table describes.
#
# The case-3 test is the exact same filesystem test report_locations already
# made when it decided whether to write the fallback line
# (_locations_history_resolves): re-running it here, rather than trusting a
# separate marker, is what keeps this function correct even if a caller
# invokes report_sarif without SCOURSH_SCAN_ROOT_PATH having been exported
# the same way report_locations saw it - both then agree the path "cannot be
# resolved" and both choose the same fallback, per that function's own
# fabrication-avoiding default.
declare -g _SARIF_LOC_URI='' _SARIF_LOC_LINE=''
_sarif_result_location() {
  local module=${_DF[module]:-} check_id=${_DF[check_id]:-} profile
  _SARIF_LOC_URI=''
  _SARIF_LOC_LINE=''
  profile=$(_fp_profile_for "$module" "$check_id") || profile=''
  case $profile in
    sca)
      _SARIF_LOC_URI=${_DF[path]:-}
      ;;
    history)
      if _locations_history_resolves "${_DF[loc_path]:-}"; then
        _SARIF_LOC_URI=${_DF[loc_path]:-}
      else
        _SARIF_LOC_URI="locations/$module.txt"
      fi
      _SARIF_LOC_LINE=${_DF[loc_line]:-}
      ;;
    dast | cloud | posture | derived)
      _SARIF_LOC_URI="locations/$module.txt"
      _SARIF_LOC_LINE=${_DF[loc_line]:-}
      ;;
    *)
      # The path profile (sast native/adapters, iac, containers), and the
      # fallback for a module _fp_profile_for does not recognise: the
      # safest reading is still "a real file", never a fabricated one.
      _SARIF_LOC_URI=${_DF[loc_path]:-}
      _SARIF_LOC_LINE=${_DF[loc_line]:-}
      ;;
  esac
}

# `evidence` -> message.text continuation, or region.snippet.text (the
# mapping table's own wording). When the location carries a region (a real
# line to attach a snippet to), evidence becomes that region's snippet and
# message.text stays the bare title; when it does not (sca, case 2, which
# has no region at all), evidence is appended to message.text as a
# continuation instead, since there is nowhere else to put it. Must run
# AFTER _sarif_result_location, which decides which of the two applies.
declare -g _SARIF_MSG_TEXT='' _SARIF_MSG_SNIPPET=''
_sarif_message_for() {
  _SARIF_MSG_TEXT=${_DF[title]:-}
  _SARIF_MSG_SNIPPET=''
  local ev=${_DF[evidence]:-}
  [[ -n $ev ]] || return 0
  if [[ -n $_SARIF_LOC_LINE ]]; then
    _SARIF_MSG_SNIPPET=$ev
  else
    _SARIF_MSG_TEXT+=$'\n\n'"$ev"
  fi
}

# The severity-provenance gap (docs/STEP10-SARIF-PLAN.md SARIF-04, "the
# honest fix"): data/advisories.db carries no marker distinguishing a
# genuinely medium-rated advisory from OSV's no-severity-published fallback,
# which _veng_advisories_normalize_severity also defaults to "medium" - so
# the two are byte-indistinguishable in the db row this run reads, and
# result.properties.severityProvenance is never emitted for ANY sca finding
# rather than guess. Recorded once per RUN DIRECTORY (never a bare
# once-per-process flag: report_sarif runs once per module under
# `scan.sh all` against the SAME rundir, where firing once is correct, but a
# test process that calls report_all against several different rundirs in
# one process must see it recorded independently for each one it is true
# for) and only when it could actually matter - an sca finding whose
# base_severity is exactly "medium", the one value both a real advisory and
# the fallback can produce.
declare -gA _SARIF_SCA_GAP_RECORDED=()
_sarif_maybe_record_sca_severity_gap() {
  local rundir=$1
  [[ -z ${_SARIF_SCA_GAP_RECORDED[$rundir]:-} ]] || return 0
  _SARIF_SCA_GAP_RECORDED[$rundir]=1
  run_record coverage_reduction \
    'module=sca reason=sarif_severity_provenance_unavailable - data/advisories.db does not record whether a medium severity came from a real advisory or the unscored fallback default, so report.sarif never emits result.properties.severityProvenance for an SCA finding'
}

# One `result` object for the finding currently decoded into _DF. Requires
# _DF to already hold a decoded finding (finding_decode); does not adopt it
# into _F, since nothing here needs the current-finding API.
_sarif_print_one_result() {
  local rundir=$1
  local cid=${_DF[check_id]:-} level
  level=$(_sarif_level_for "${_DF[severity]:-}")

  _sarif_result_location
  _sarif_message_for

  printf '{'
  printf '"ruleId":%s' "$(json_string "$cid")"
  printf ',"level":%s' "$(json_string "$level")"
  printf ',"message":{"text":%s}' "$(json_string "$_SARIF_MSG_TEXT")"
  printf ',"locations":[{'
  printf '"physicalLocation":{"artifactLocation":{"uri":%s}' "$(json_string "$_SARIF_LOC_URI")"
  if [[ -n $_SARIF_LOC_LINE ]]; then
    printf ',"region":{"startLine":%s' "$(json_number "$_SARIF_LOC_LINE")"
    [[ -z $_SARIF_MSG_SNIPPET ]] || printf ',"snippet":{"text":%s}' "$(json_string "$_SARIF_MSG_SNIPPET")"
    printf '}'
  fi
  printf '}'
  printf ',"logicalLocations":[{"kind":%s,"fullyQualifiedName":%s}]' \
    "$(json_string "${_DF[logical_kind]:-}")" "$(json_string "${_DF[logical_fqn]:-}")"
  printf '}]'
  printf ',"partialFingerprints":{"scourshFingerprint/v1":%s}' "$(json_string "${_DF[fingerprint]:-}")"
  printf ',"properties":{'
  printf '"module":%s' "$(json_string "${_DF[module]:-}")"
  printf ',"status":%s' "$(json_string "${_DF[status]:-}")"
  printf ',"confidence":%s' "$(json_string "${_DF[confidence]:-}")"
  printf ',"baseSeverity":%s' "$(json_string "${_DF[base_severity]:-}")"
  printf ',"cvss":{"vector":%s,"score":%s}' \
    "$(json_string "${_DF[_cvss_vector]:-}")" "$(json_number "${_DF[_cvss_score]:-}")"
  if [[ -n ${_DF[cell]+set} ]]; then
    printf ',"cell":%s' "$(json_string "${_DF[cell]}")"
  else
    printf ',"cell":null'
  fi
  printf ',"firstSeen":%s' "$(json_string "${_DF[first_seen]:-}")"
  printf ',"lastSeen":%s' "$(json_string "${_DF[last_seen]:-}")"
  printf '}'
  if [[ ${_DF[suppressed]:-} == true ]]; then
    printf ',"suppressions":[{"kind":"external","justification":%s}]' \
      "$(json_string "${_DF[suppressed_by]:-}")"
  fi
  printf '}'

  if [[ ${_DF[module]:-} == sca && ${_DF[base_severity]:-} == medium ]]; then
    _sarif_maybe_record_sca_severity_gap "$rundir"
  fi
}

# `runs[0].results[]`, in the same (module, check_id, fingerprint) order
# findings.fields is already sorted in - findings_merge's own order,
# unaffected by anything this function does - so two runs over the same
# fixture produce a byte-identical results[] array, matching every other
# emitter in this file.
_sarif_print_results() {
  local rundir=$1 line first=1
  printf '['
  if [[ -s $rundir/findings.fields ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      (( first )) || printf ','
      first=0
      _sarif_print_one_result "$rundir"
    done <"$rundir/findings.fields"
  fi
  printf ']'
}

# `runs[0].invocations[0]` - startTimeUtc/endTimeUtc mirror run.json's own
# started_at and "now" (report_run_json's identical reading).
# executionSuccessful/exitCode are necessarily a snapshot at THIS report_all
# call, same limitation run.json's own `gate` field already carries and
# documents (scan.sh sets SCOURSH_GATE_RESULT only after every module's own
# report_all has already run - see scan.sh's own comment on that ordering):
# --fail-on gate failures and required-input failures (exit 1 and 4) are not
# yet visible here, so only the incomplete-run case (exit 5) is distinguished
# from a clean 0.  A later ticket that reorders report_all relative to gate
# evaluation makes this exact, without changing this function's shape.
_sarif_print_invocations() {
  local rundir=$1 started ended success=true exitcode=$SCOURSH_EXIT_OK
  started=$(_meta_first "$rundir" started_at)
  ended=$(now_iso)
  if _sarif_run_incomplete "$rundir"; then
    success=false
    exitcode=$SCOURSH_EXIT_INCOMPLETE
  fi
  printf '[{'
  printf '"startTimeUtc":%s' "$(json_string "$started")"
  printf ',"endTimeUtc":%s' "$(json_string "$ended")"
  printf ',"executionSuccessful":%s' "$(json_bool "$success")"
  printf ',"exitCode":%s' "$(json_number "$exitcode")"
  printf '}]'
}

# `report_sarif [RUNDIR]` - the full SARIF 2.1.0 document: document,
# tool.driver (name/version/informationUri/rules[] - SARIF-03), artifacts[]
# and invocations[] (SARIF-03), and results[] (SARIF-04, section 5b above).
# `informationUri` is this project's own
# canonical repository URL (README.md's own clone instructions cite the same
# string) - a static string naming the tool, never fetched by anything, so it
# is not egress and is not a scan target (tests/lint-shell.sh's DAST-35 "no
# bundled scan target" checks are not in play for it).
#
# _sarif_build_registry runs DIRECTLY, before the { ... } block below even
# opens, and never through $(...) - see its own comment.  Everything after
# that point prints straight into the redirected block, matching this file's
# own convention (report_run_json, report_md, report_html all write this way)
# rather than assembling giant strings through nested command substitution.
# SC2016 fires on the literal JSON key "$schema" below; report_md's own
# header disables the identical false positive for the same reason.
# shellcheck disable=SC2016
report_sarif() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  _sarif_build_registry
  _sarif_index_findings "$rundir"
  {
    printf '{\n'
    printf '  "$schema": %s,\n' \
      "$(json_string 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json')"
    printf '  "version": "2.1.0",\n'
    printf '  "runs": [\n'
    printf '    {\n'
    printf '      "tool": {\n'
    printf '        "driver": {\n'
    printf '          "name": "scoursh",\n'
    printf '          "version": %s,\n' "$(json_string "$(scoursh_version)")"
    printf '          "informationUri": %s,\n' "$(json_string 'https://github.com/abhi-sama/scoursh')"
    printf '          "rules": '
    _sarif_print_rules
    printf '\n        }\n'
    printf '      },\n'
    printf '      "artifacts": '
    _sarif_print_artifacts "$rundir"
    printf ',\n'
    printf '      "results": '
    _sarif_print_results "$rundir"
    printf ',\n'
    printf '      "invocations": '
    _sarif_print_invocations "$rundir"
    printf '\n    }\n'
    printf '  ]\n'
    printf '}\n'
  } >"$rundir/report.sarif"
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
  # docs/STEP10-SARIF-PLAN.md SARIF-03/04: report_sarif writes the full
  # SARIF-2.1.0 document (tool.driver/rules[]/artifacts[]/invocations[], and
  # results[] mapped from this run's own findings).
  [[ -z ${_rpt_want[sarif]:-} ]] || report_sarif "$rundir"
  report_run_json "$rundir"
}
