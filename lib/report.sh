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
# 0a. The scanner module set this file renders across every emitter (JSON,
#     Markdown, HTML, report-audit.html, SARIF).  Was ten separately-typed
#     `sast sca iac dast cloud` literals; a module added to the scan surface
#     (NET-01) now changes here once instead of at every call site.
# ---------------------------------------------------------------------------
declare -ga _RPT_MODULES=(sast sca iac dast cloud network image)

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
# COMPLIANCE-04: per-control live-finding counts.  Unlike `_RPT_OWASP`, `cis`
# is optional and REPEATABLE (rules/RULE-FORMAT.md §9.1/§9.5: one check may
# cite several controls, and most checks cite none at all) - so this counts
# occurrences across a newline-joined `_DF[cis]` list rather than one value
# per finding, and a finding with no `cis` value contributes to no key here
# at all (there is no `none` sentinel for `cis`, unlike `owasp`).
declare -A _RPT_CIS=()
declare -A _RPT_SEV_SUP=()
# Set by `report_count` when `meta/checks_run` is empty - true exactly when
# NO check executed this run (an abort before dispatch, or a filter chain
# that selected nothing) - and the OWASP/CIS per-category registry walk
# (`_report_owasp_state`/`_report_cis_state`, ~9-10s against the real
# catalog) was skipped as a result. The compliance renderers below read this
# to print one honest "no coverage" statement instead of the per-category
# table; see `report_count`'s own comment for why skipping is safe exactly
# in this case and nowhere else.
_RPT_COMPLIANCE_SKIPPED=0
_RPT_TOTAL=0
_RPT_SUPPRESSED=0
_RPT_LIVE=0
_RPT_DAST_ZP_PHASES=0
_RPT_DAST_INJ_TESTED=0
declare -A _RPT_DAST_SURFACE_EP_SRC=()
declare -A _RPT_DAST_SURFACE_PAR_SRC=()
_RPT_DAST_SURFACE_EP_TOTAL=0
_RPT_DAST_SURFACE_PAR_TOTAL=0

# `_report_dast_surface_state RUNDIR` - IMPORT-06: the structured surface-
# provenance counts `modules/dast/crawl.sh`'s `_crawl_record_surface_provenance`
# writes, one `source<US>count` line per (target, source) pair. Summed here
# rather than read once, because a multi-target run appends one block per
# target and the honest total is every target's contribution together - the
# same reasoning `_RPT_MODULE` already applies to per-module finding counts.
_report_dast_surface_state() {
  local rundir=$1 line src count
  _RPT_DAST_SURFACE_EP_SRC=()
  _RPT_DAST_SURFACE_PAR_SRC=()
  _RPT_DAST_SURFACE_EP_TOTAL=0
  _RPT_DAST_SURFACE_PAR_TOTAL=0
  if [[ -r $rundir/meta/dast_surface_endpoints_by_source ]]; then
    while IFS=$'\x1f' read -r src count; do
      [[ -n $src && $count =~ ^[0-9]+$ ]] || continue
      _RPT_DAST_SURFACE_EP_SRC[$src]=$(( ${_RPT_DAST_SURFACE_EP_SRC[$src]:-0} + count ))
      _RPT_DAST_SURFACE_EP_TOTAL=$(( _RPT_DAST_SURFACE_EP_TOTAL + count ))
    done <"$rundir/meta/dast_surface_endpoints_by_source"
  fi
  if [[ -r $rundir/meta/dast_surface_parameters_by_source ]]; then
    while IFS=$'\x1f' read -r src count; do
      [[ -n $src && $count =~ ^[0-9]+$ ]] || continue
      _RPT_DAST_SURFACE_PAR_SRC[$src]=$(( ${_RPT_DAST_SURFACE_PAR_SRC[$src]:-0} + count ))
      _RPT_DAST_SURFACE_PAR_TOTAL=$(( _RPT_DAST_SURFACE_PAR_TOTAL + count ))
    done <"$rundir/meta/dast_surface_parameters_by_source"
  fi
}

# `_dast_surface_source_label SOURCE` - the human-readable half of a
# `docs/INVENTORY-FORMAT.md` §2/§3 `source` value, shared by the Markdown and
# HTML renderers below so the two prose forms cannot drift on wording.
_dast_surface_source_label() {
  case $1 in
    openapi) printf 'an openapi spec you supplied' ;;
    postman) printf 'a postman collection you supplied' ;;
    har) printf 'a HAR capture you supplied' ;;
    graphql) printf 'a GraphQL schema you supplied' ;;
    crawl) printf 'the static crawl' ;;
    imported) printf 'a cross-module inventory import' ;;
    *) printf 'source %s' "$1" ;;
  esac
}

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

# report_registries_dump OUTFILE - serialises the OWASP/CIS check-metadata
# registry (`_report_checkmeta_registry_load` above) as `declare -p` output,
# so a PARENT process can `source` it back after this one exits.
#
# This exists for `lib/core.sh`'s `run_json_refresh_incomplete`: on an abort,
# that function calls `report_run_json`/`report_md`/`report_html`/
# `report_agent` each in its OWN subshell (deliberately, so a failure inside
# one cannot cost the others, and so an internal `die` inside the expensive
# registry walk can only ever exit that subshell rather than replace the
# original abort's exit code - see that function's own header comment). A
# bash subshell inherits the parent's variables at fork time but can never
# write them back, so the `SCOURSH_INSTALL_ROOT`-keyed memo each of those four
# writers populates via `report_count` was being rebuilt from scratch in
# every one of them - repeating an already-expensive full-registry parse
# (every `*.rules` file in the tool re-parsed and re-validated) for a run
# that executed zero checks. Dumping it here after the FIRST writer, and
# having the parent `source` the dump before forking the next one, lets the
# rest inherit an already-warm cache - without moving the (dying-capable)
# walk itself out of subshell containment.
#
# `report_sarif` and `report_audit` deliberately do NOT participate in this
# dump/restore chain, even though `_sarif_build_registry` shares the same
# `_report_checkmeta_registry_load` walk and memo flag
# (`_RPT_CHECKMETA_LOADED_ROOT`): unlike the OWASP/CIS category state, SARIF's
# `rules[]` descriptors are built from `lib/records.sh`'s own raw parsed
# record state (`_REC_ORDER`/`_REC_L`/`_REC_DIGEST`, populated by
# `checks_registry_load`/`records_load`), which this dump does not - and
# safely cannot cheaply - carry across a subshell boundary. Restoring only
# the memo flag would make a LATER subshell's `_report_checkmeta_registry_load`
# believe the walk already ran and short-circuit, leaving those record-level
# arrays empty in that subshell even though the flag says otherwise - which
# manifested as an `unbound variable` abort deep in `records_digest` and,
# worse, a `report.sarif` whose `rules[]` was silently missing the tool's
# whole catalog. `run_json_refresh_incomplete` resets the memo flags before
# calling either function, forcing each its own complete, self-consistent
# walk exactly as it always performs on a normal (non-abort) run - the same
# cost `report_sarif` and `report_audit` already pay whenever `--format`
# selects them, abort or not.
report_registries_dump() {
  local out=$1
  declare -p _RPTOW_CHECK_OWASP _RPTCIS_CHECK_CIS _RPTOW_REGISTRY_LOADED_ROOT \
    _RPTCIS_REGISTRY_LOADED_ROOT _RPT_CHECKMETA_LOADED_ROOT >"$out" 2>/dev/null || true
}

report_count() {
  local rundir=${1:-$SCOURSH_RUN_DIR} line
  _RPT_SEV=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)
  _RPT_SEV_SUP=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)
  _RPT_MODULE=()
  _RPT_STATUS=([new]=0 [recurring]=0 [fixed]=0 [unknown]=0)
  _RPT_OWASP=()
  _RPT_CIS=()
  _RPT_TOTAL=0
  _RPT_SUPPRESSED=0
  _RPT_LIVE=0
  _report_dast_injection_gap_state "$rundir"
  _report_dast_surface_state "$rundir"
  # `_report_owasp_state`/`_report_cis_state` walk the tool's WHOLE check
  # catalog (~9-10s against the real, on-disk *.rules tree - the cost
  # `_report_checkmeta_registry_load`'s own header measures) purely to learn,
  # for every category, which of its checks ran versus were merely
  # registered. `meta/checks_run` (checks_record_run_selection) is written by
  # every check some module actually executed, so an EMPTY/absent file means
  # this run dispatched zero checks - an abort before any module ran
  # (die() at exit 2/3/4, never reaching a module) or a filter chain that
  # selected nothing - and in that state every category's answer to "did any
  # of its checks run" is trivially no, without walking a single *.rules
  # file to find out. Skipping the walk there is what takes an aborted run
  # from ~16.9s to ~0.25s.
  #
  # This is NOT "skip whenever there are zero findings": a real, fully-run
  # scan that legitimately found nothing also has zero findings, and there
  # the per-category distinction (assessed-and-clean vs out-of-scope vs
  # filtered) is real information the walk is the only way to produce - so
  # the gate is on checks_run, never on the finding count. A combined
  # `scan.sh all` where sast/sca/iac complete and dast then aborts still has
  # a non-empty checks_run (from the modules that DID run) and still gets
  # the full walk, correctly showing sast/sca/iac categories as
  # assessed/clean and dast's own as not-run with the recorded abort reason.
  #
  # `_RPT_COMPLIANCE_SKIPPED` tells `_md_owasp_compliance`/`_html_owasp_compliance`
  # and their CIS twins to render one honest "no checks ran" statement
  # instead of a per-category table computed from arrays that were never
  # populated - the constraint being that an unpopulated `_RPTOW_RAN` must
  # never be silently read as "assessed, nothing found" (which is what the
  # existing not_run/out_of_scope buckets would compute it as, wrongly, if
  # the renderers were left untouched here).
  if [[ -s $rundir/meta/checks_run ]]; then
    _RPT_COMPLIANCE_SKIPPED=0
    _report_owasp_state "$rundir"
    _report_cis_state "$rundir"
  else
    _RPT_COMPLIANCE_SKIPPED=1
    _RPTOW_REG_HAS=() ; _RPTOW_RAN=() ; _RPTOW_FILTERED_SET=() ; _RPTOW_LINES=()
    _RPTCIS_REG_HAS=() ; _RPTCIS_RAN=() ; _RPTCIS_FILTERED_SET=() ; _RPTCIS_NAPP_SET=() ; _RPTCIS_LINES=()
  fi
  [[ -s $rundir/findings.fields ]] || return 0
  local sev mod st ow cislist cid
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
    cislist=${_DF[cis]:-}
    if [[ -n $cislist ]]; then
      while IFS= read -r cid; do
        [[ -n $cid ]] || continue
        _RPT_CIS[$cid]=$(( ${_RPT_CIS[$cid]:-0} + 1 ))
      done <<<"$cislist"
    fi
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
# 1a. OWASP Top 10 compliance view (docs/STEP10-SARIF-PLAN.md Track B,
#     COMPLIANCE-01 / COMPLIANCE-02)
# ---------------------------------------------------------------------------
# COMPLIANCE-01: rules/RULE-FORMAT.md §9.1's `owasp` field row promises "the
# report expands it to the full label"; nothing implemented that until this
# section.  `data/owasp-categories.conf` (§9.6.6) is the vendored table, read
# from disk exactly as `data/severity-rubric.conf` is (lib/findings.sh
# section 8) rather than compiled into a `case`, for the identical reason:
# reviewable and diffable against the published standard.
declare -gA _OWASP_LABEL=()
_OWASP_LABEL_LOADED=0

# The path argument exists for the fixture harness and test suites, exactly
# as rubric_load's does; shellcheck's SC2120 disagreement across versions is
# the same one documented on rubric_load, so it is silenced the same way.
# shellcheck disable=SC2120
owasp_categories_load() {
  # `${SCOURSH_INSTALL_ROOT:-}`, not a bare reference: `report_count` no
  # longer unconditionally calls `_report_owasp_state` (the walk this
  # function used to always be warmed by first, incidentally, from a
  # scenario where the caller HAD set a real install root) whenever a run
  # dispatched zero checks - see report_count's own comment - so a caller
  # reaching this function directly (the compliance renderers' own header
  # prose need a label table regardless of whether the per-category walk
  # ran) can now be the FIRST call in a process where SCOURSH_INSTALL_ROOT
  # is unset, and an unguarded reference is a `set -u` abort rather than the
  # honest "no table available" this function already handles below.
  local path=${1:-${SCOURSH_INSTALL_ROOT:-}/data/owasp-categories.conf}
  _OWASP_LABEL=()
  _OWASP_LABEL_LOADED=1
  [[ -r $path ]] || return 0
  records_load "$path" owasp-category owasplbl \
    || die "$SCOURSH_EXIT_INPUT" "data/owasp-categories.conf failed to parse"
  local n i id cat
  n=$(records_count owasplbl)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id owasplbl "$i")
    cat=$(records_field owasplbl "$i" category)
    _OWASP_LABEL[$id]=$cat
  done
}

# owasp_category_label ID - expands an `owasp` field value to its published
# category name.  `none` is a legal, non-missing value (a check that
# genuinely maps to no OWASP category) and always expands to "Not
# categorised" - never looked up in the table, per §9.6.6's own text.  An id
# with no row (a different edition's id, or one this table has simply never
# been given a row for) renders as the bare id plus a fixed, visible reason:
# never blank, never an invented label, so a reader scanning the report
# cannot mistake "this table has never heard of this category" for "this
# category was assessed and is clean".
owasp_category_label() {
  local id=${1:-none}
  (( _OWASP_LABEL_LOADED )) || owasp_categories_load
  if [[ $id == none ]]; then
    printf '%s' 'Not categorised'
    return 0
  fi
  if [[ -n ${_OWASP_LABEL[$id]+set} ]]; then
    printf '%s' "${_OWASP_LABEL[$id]}"
    return 0
  fi
  printf '%s (no published label on file for this id)' "$id"
}

# owasp_category_known ID - `known` (has a table row), `none` (the fixed
# "not categorised" literal) or `unknown` (matches E026 but has no row).
# Callers use this rather than re-deriving it from owasp_category_label's
# output, which is prose meant for a report and not meant to be parsed back.
owasp_category_known() {
  local id=${1:-none}
  (( _OWASP_LABEL_LOADED )) || owasp_categories_load
  if [[ $id == none ]]; then
    printf 'none'
  elif [[ -n ${_OWASP_LABEL[$id]+set} ]]; then
    printf 'known'
  else
    printf 'unknown'
  fi
}

# ---------------------------------------------------------------------------
# 1b. CIS control label table (docs/STEP10-SARIF-PLAN.md Track B,
#     COMPLIANCE-03)
# ---------------------------------------------------------------------------
# COMPLIANCE-03 lands the FORMAT and the TABLE (rules/RULE-FORMAT.md §9.6.7,
# data/cis-mappings, docs/CIS-MAPPINGS.md) and the id -> label loader/lookup
# below; it renders NOTHING.  Nothing in report_all/report_md/report_html
# calls any function in this section - that is COMPLIANCE-04's job, blocked
# on modules/cloud/ existing so there is a real cis-carrying finding to build
# the view against (docs/STEP10-SARIF-PLAN.md's own COMPLIANCE-03/
# COMPLIANCE-04 rows).  This mirrors exactly how COMPLIANCE-01's
# owasp_category_label/owasp_category_known above landed ahead of
# COMPLIANCE-02's report sections.
#
# `data/cis-mappings` is an id -> label REFERENCE table, never a source of
# control ids (the captain's D4 decision; docs/CIS-MAPPINGS.md §1): a check's
# `cis` field is authored on the check record itself, and this table only
# expands an id already on a finding into its published short title.
declare -gA _CIS_LABEL=()
declare -g _CIS_LABEL_LOADED=0
declare -g _CIS_BENCHMARK_NAME='' _CIS_BENCHMARK_VERSION=''
# `_CIS_ORDER` - the ids in ON-DISK record order (docs/CIS-MAPPINGS.md §5:
# "keeping the file sorted by id"), preserved as an INDEXED array rather than
# re-derived from `_CIS_LABEL`'s keys. A `cis` id is dotted-decimal
# (`^[0-9]+(\.[0-9]+)+$`, §9.6.7), never zero-padded, so a plain `LC_ALL=C`
# sort - the trick `_owasp_render_order` relies on, because every OWASP id
# IS zero-padded - would put `1.10` ahead of `1.2`: COMPLIANCE-04's own render
# order uses this array for that reason, never a re-sort of `_CIS_LABEL`.
declare -ga _CIS_ORDER=()

# The path argument exists for the fixture harness and test suites, exactly
# as owasp_categories_load's does; shellcheck's SC2120 disagreement across
# versions is the same one documented there, so it is silenced the same way.
# shellcheck disable=SC2120
cis_mappings_load() {
  # See owasp_categories_load's own comment: `${SCOURSH_INSTALL_ROOT:-}`,
  # never a bare reference, for the identical reason.
  local path=${1:-${SCOURSH_INSTALL_ROOT:-}/data/cis-mappings}
  _CIS_LABEL=()
  _CIS_ORDER=()
  _CIS_BENCHMARK_NAME=''
  _CIS_BENCHMARK_VERSION=''
  _CIS_LABEL_LOADED=1
  [[ -r $path ]] || return 0
  records_load "$path" cis-mapping cismap \
    || die "$SCOURSH_EXIT_INPUT" "data/cis-mappings failed to parse"
  local n i id ttl
  n=$(records_count cismap)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id cismap "$i")
    ttl=$(records_field cismap "$i" title)
    _CIS_LABEL[$id]=$ttl
    _CIS_ORDER+=("$id")
  done
  # benchmark/benchmark-version are meaningful only on the first record
  # (rules/RULE-FORMAT.md §9.6.7, docs/CIS-MAPPINGS.md §3), exactly as
  # format-version is.
  if (( n > 0 )); then
    _CIS_BENCHMARK_NAME=$(records_field_or cismap 0 benchmark '')
    _CIS_BENCHMARK_VERSION=$(records_field_or cismap 0 benchmark-version '')
  fi
}

# cis_control_label ID - expands a `cis` field value to its published short
# title.  An id with no row (a control this table has not yet been given a
# row for, per docs/CIS-MAPPINGS.md §4's stated gaps) renders as the bare id
# plus a fixed, visible reason: never blank, never an invented title - the
# identical degrade-visibly shape owasp_category_label uses for an unknown
# `owasp` id.
cis_control_label() {
  local id=${1:-}
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  if [[ -n ${_CIS_LABEL[$id]+set} ]]; then
    printf '%s' "${_CIS_LABEL[$id]}"
    return 0
  fi
  printf '%s (no published label on file for this id)' "$id"
}

# cis_control_known ID - `known` (has a table row) or `unknown` (this table
# has never been given a row for it).  Unlike owasp_category_known, there is
# no `none` literal here: `cis` carries no fixed "not applicable" sentinel
# (rules/RULE-FORMAT.md §9.1/§9.2/§9.5), it is simply absent from a record
# that cites no CIS control.
cis_control_known() {
  local id=${1:-}
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  if [[ -n ${_CIS_LABEL[$id]+set} ]]; then
    printf 'known'
  else
    printf 'unknown'
  fi
}

# cis_benchmark_name / cis_benchmark_version - the benchmark name/version
# data/cis-mappings' first record carries (docs/CIS-MAPPINGS.md §3).  Exposed
# now so COMPLIANCE-04 can state them at the head of its report section
# without re-deriving the first-record-only convention itself; empty when the
# table is absent or carries no rows.
cis_benchmark_name() {
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  printf '%s' "$_CIS_BENCHMARK_NAME"
}

cis_benchmark_version() {
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  printf '%s' "$_CIS_BENCHMARK_VERSION"
}

# COMPLIANCE-02: the check_id -> owasp registry map, across every module that
# ships an on-disk *.rules registry (sast/iac/dast/cloud; sca ships none, by
# design - modules/sca/run.sh's own header - and simply contributes nothing
# here, exactly as it contributes nothing to `_sarif_build_registry`/
# `_report_coverage_registry_load`, the two existing precedents this mirrors).
# Memoized on $SCOURSH_INSTALL_ROOT for the identical reason
# `_report_coverage_registry_load` above is: every *.rules file's content is
# fixed for the life of a process, and `scan.sh all` calls report_all once per
# module.
declare -gA _RPTOW_CHECK_OWASP=()
declare -g _RPTOW_REGISTRY_LOADED_ROOT=''
_report_owasp_registry_load() {
  _report_checkmeta_registry_load
}

# _report_checkmeta_registry_load - the SHARED walk behind both
# `_report_owasp_registry_load` and `_report_cis_registry_load` below.
#
# Before this, each of those independently called `checks_registry_load` (and
# so `records_load`/`records_validate`) across every one of `_RPT_MODULES`'
# on-disk `*.rules` files - the single most expensive step in producing a
# report, since it re-parses and re-validates the tool's ENTIRE check catalog
# from disk. Both walks read the identical set of files and differ only in
# which field they pull off each record (`owasp` vs `cis`), so doing it twice
# doubled that cost for no reason: measured on this tree, one such walk costs
# ~9-10s, so `report_count`'s combined owasp+cis state cost ~19s per call
# before this change. This function performs that walk exactly ONCE and
# populates both `_RPTOW_CHECK_OWASP` and `_RPTCIS_CHECK_CIS` from the same
# pass, under one shared memoization flag - `_report_owasp_registry_load` and
# `_report_cis_registry_load` are kept as thin wrappers so neither caller
# needed to change. `_sarif_build_registry` is now a third such thin wrapper
# (see its own comment), for the identical reason.
#
# `checks_registry_load` is called DIRECTLY below, never through `$(...)`:
# its own `die()` on a malformed registry file must abort the run, and a
# `die()` inside a command substitution does not reliably do that
# (lib/checks.sh's own comment on `CHECKS_REGISTRY_SETS`).
declare -g _RPT_CHECKMETA_LOADED_ROOT=''
_report_checkmeta_registry_load() {
  if [[ -n ${_RPT_CHECKMETA_LOADED_ROOT:-} && ${_RPT_CHECKMETA_LOADED_ROOT} == "${SCOURSH_INSTALL_ROOT:-}" ]]; then
    return 0
  fi
  local -a _rptmeta_saved_sets=("${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}")
  _RPTOW_CHECK_OWASP=()
  _RPTCIS_CHECK_CIS=()
  # `_SARIF_REG_LOC` (id -> "set idx") used to be built by `_sarif_build_registry`'s
  # own, entirely SEPARATE full catalog walk (its own `checks_registry_load`
  # call per module, re-parsing and re-validating every *.rules file this
  # function has ALREADY just parsed and validated moments before) - measured
  # costing as much again as this walk itself (~10-18s on this tree), because
  # `report_sarif` is in the default `--format` list and so ran on every
  # ordinary scan. Populated here instead, in the SAME pass, for free;
  # `_sarif_build_registry` is now a thin wrapper that only calls this
  # function (memoized exactly as `_RPTOW_CHECK_OWASP`/`_RPTCIS_CHECK_CIS`
  # are) rather than reloading anything.
  _SARIF_REG_LOC=()
  local m set n i id ow v cislist
  for m in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    checks_registry_load "$m" "_rptmetareg_$m"
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      # `records_count`/`records_id`/`records_field_or`/`records_list`
      # (lib/records.sh) each print to stdout, so calling them the ordinary
      # way - `x=$(records_id "$set" "$i")` - forks once per call. This loop
      # runs 4 such calls for every check record in the tool's WHOLE catalog
      # (hundreds of records across all `_RPT_MODULES`), which measurably
      # dominated the difference between this function's own load+validate
      # cost and its total wall time. The `_into` variants below (added for
      # exactly this loop) write into a fixed scratch variable instead of
      # printing - no fork, same result - see their own header in
      # lib/records.sh for why a nameref isn't used (bash 4.2 has none).
      records_count_into "$set"
      n=$_RECORDS_COUNT_V
      for (( i = 0; i < n; i++ )); do
        records_id_into "$set" "$i"
        id=$_RECORDS_ID_V
        [[ -n $id ]] || continue
        _SARIF_REG_LOC[$id]="$set $i"
        records_field_or_into "$set" "$i" owasp none
        ow=$_RECORDS_FIELD_V
        _RPTOW_CHECK_OWASP[$id]=$ow
        records_list_into "$set" "$i" cis
        cislist=$_RECORDS_LIST_V
        [[ -n $cislist ]] || continue
        while IFS= read -r v; do
          [[ -n $v ]] || continue
          if [[ -n ${_RPTCIS_CHECK_CIS[$id]:-} ]]; then
            _RPTCIS_CHECK_CIS[$id]+=$'\n'"$v"
          else
            _RPTCIS_CHECK_CIS[$id]=$v
          fi
        done <<<"$cislist"
      done
    done
  done
  CHECKS_REGISTRY_SETS=("${_rptmeta_saved_sets[@]+"${_rptmeta_saved_sets[@]}"}")
  _RPTOW_REGISTRY_LOADED_ROOT=${SCOURSH_INSTALL_ROOT:-}
  _RPTCIS_REGISTRY_LOADED_ROOT=${SCOURSH_INSTALL_ROOT:-}
  _RPT_CHECKMETA_LOADED_ROOT=${SCOURSH_INSTALL_ROOT:-}
}

# _report_owasp_state RUNDIR - the per-run facts a compliance view needs to
# tell three things apart that a bare finding count cannot (Appendix B; this
# ticket's own acceptance criteria): a category that is in scope and
# genuinely produced no finding, a category no check in this build targets
# at all, and a category whose checks exist but were filtered out of THIS
# run by the tension-15 chain (--profile-scan/--intensity/--allow-intrusive).
# All three are read from facts already written - `meta/checks_run` and
# `meta/skipped_checks` (`check=<id> skipped_by=<reason>`,
# lib/checks.sh:checks_record_run_selection) - rather than a fourth counter
# invented for this view, and rather than a hardcoded per-category tier
# transcribed from Appendix B's own prose: Appendix B was written before
# DAST-28 seeded two A04 checks, so a hardcoded "A04 is out of scope" reads
# as correct against the design doc and false against the shipped registry -
# this view answers from the registry as it stands today, and Appendix B's
# own prose is quoted separately, as what it is: the tool's own documented
# design-level coverage claim, not a live measurement.
declare -gA _RPTOW_REG_HAS=() _RPTOW_RAN=() _RPTOW_FILTERED_SET=() _RPTOW_LINES=()
_report_owasp_state() {
  local rundir=$1
  (( _OWASP_LABEL_LOADED )) || owasp_categories_load
  _report_owasp_registry_load
  _RPTOW_REG_HAS=() ; _RPTOW_RAN=() ; _RPTOW_FILTERED_SET=() ; _RPTOW_LINES=()

  local cid ow
  for cid in "${!_RPTOW_CHECK_OWASP[@]}"; do
    ow=${_RPTOW_CHECK_OWASP[$cid]}
    [[ $ow == none ]] || _RPTOW_REG_HAS[$ow]=1
  done

  local -A ran_ids=()
  if [[ -r $rundir/meta/checks_run ]]; then
    while IFS= read -r cid; do
      [[ -n $cid ]] || continue
      ran_ids[$cid]=1
    done <"$rundir/meta/checks_run"
  fi
  # A bare `"${!ran_ids[@]}"` (never the `${arr[@]+alt}` guard idiom used for
  # an INDEXED array elsewhere in this file) is what a genuinely empty
  # associative array needs here: nested inside that guard, `${!ran_ids[@]}`
  # on an empty associative array does not expand to zero words the way a
  # bare indexed-array all-elements expansion does - it yields one spurious
  # empty-string element, and `${_RPTOW_CHECK_OWASP[$cid]}` with `cid=''` is
  # itself a bash "bad array subscript" error on an associative array (unlike
  # a numeric one), not a harmless empty read. Measured directly by
  # reproducing it.
  #
  # The prose above deliberately DESCRIBES that indexed-array expansion rather
  # than spelling it: tests/lint-shell.sh's bash-4.2 array-guard check greps
  # every line of this file, comments included, so a comment that quoted the
  # unguarded form reported this file as carrying one - the same self-match
  # this project already recorded for a rule pack whose header spelled the
  # credential shape it was describing (AGENTS.md, modules/sast/rules/
  # secrets.rules). Describe the hazard, do not spell it.
  for cid in "${!ran_ids[@]}"; do
    [[ -n $cid ]] || continue
    ow=${_RPTOW_CHECK_OWASP[$cid]:-}
    [[ -n $ow && $ow != none ]] || continue
    _RPTOW_RAN[$ow]=1
  done

  # `check=<id> skipped_by=<reason>` - only a category with NO check that ran
  # is ever offered a "filtered" reason, so a category with a mix of a
  # filtered check and a run one always reads as assessed (`_RPTOW_RAN`),
  # never as filtered - the run genuinely did look at that category.
  if [[ -r $rundir/meta/skipped_checks ]]; then
    local line skid reason
    while IFS= read -r line; do
      [[ $line =~ ^check=([^\ ]+)\ skipped_by=(.*)$ ]] || continue
      skid=${BASH_REMATCH[1]}
      reason=${BASH_REMATCH[2]}
      ow=${_RPTOW_CHECK_OWASP[$skid]:-}
      [[ -n $ow && $ow != none ]] || continue
      _RPTOW_FILTERED_SET["$ow|$reason"]=1
    done <"$rundir/meta/skipped_checks"
  fi

  if [[ -s $rundir/findings.fields ]]; then
    local fline fow
    while IFS= read -r fline; do
      [[ -n $fline ]] || continue
      finding_decode "$fline"
      [[ ${_DF[suppressed]:-false} == true ]] && continue
      fow=${_DF[owasp]:-none}
      if [[ -n ${_RPTOW_LINES[$fow]:-} ]]; then
        _RPTOW_LINES[$fow]+=$'\n'"$fline"
      else
        _RPTOW_LINES[$fow]=$fline
      fi
    done <"$rundir/findings.fields"
  fi
}

# _owasp_bucket ID - one of `findings` / `clean` / `out_of_scope` /
# `filtered` / `not_run`, in that priority order.  `_RPT_OWASP` (report_count,
# already run before this is ever consulted) supplies the live count.
_owasp_bucket() {
  local id=$1 count=${_RPT_OWASP[$1]:-0}
  if (( count > 0 )); then
    printf 'findings'
  elif [[ -z ${_RPTOW_REG_HAS[$id]:-} ]]; then
    printf 'out_of_scope'
  elif [[ -n ${_RPTOW_RAN[$id]:-} ]]; then
    printf 'clean'
  else
    local k
    for k in "${!_RPTOW_FILTERED_SET[@]}"; do
      [[ -n $k ]] || continue
      if [[ $k == "$id|"* ]]; then
        printf 'filtered'
        return 0
      fi
    done
    printf 'not_run'
  fi
}

# _owasp_filtered_reasons ID - the distinct `skipped_by` reasons behind the
# `filtered` bucket above, comma-joined, `LC_ALL=C` sorted for determinism
# across two runs of the same fixture.
_owasp_filtered_reasons() {
  local id=$1 k reason out='' list
  list=$(
    for k in "${!_RPTOW_FILTERED_SET[@]}"; do
      [[ -n $k ]] || continue
      [[ $k == "$id|"* ]] && printf '%s\n' "${k#"$id|"}"
    done | LC_ALL=C sort -u
  )
  while IFS= read -r reason; do
    [[ -n $reason ]] || continue
    if [[ -n $out ]]; then out+=", $reason"; else out=$reason; fi
  done <<<"$list"
  printf '%s' "$out"
}

# _owasp_render_order - every id `data/owasp-categories.conf` has a row for,
# `LC_ALL=C` sorted (which is also correct numeric-id order: `A01:2021` <
# `A02:2021` < ... < `A10:2021` lexically, since both fields are zero-padded),
# followed by any id this run's own findings carry that the table has NEVER
# heard of (drift, or a future edition) - never dropped, never reordered in
# ahead of the canonical set. `none` is never in this list; callers render it,
# if at all, as their own final, separately-labelled section.
_owasp_render_order() {
  (( _OWASP_LABEL_LOADED )) || owasp_categories_load
  local k
  if (( ${#_OWASP_LABEL[@]} > 0 )); then
    printf '%s\n' "${!_OWASP_LABEL[@]}" | LC_ALL=C sort
  fi
  local -a extra=()
  for k in "${!_RPT_OWASP[@]}"; do
    [[ -n $k ]] || continue
    [[ $k == none ]] && continue
    [[ -n ${_OWASP_LABEL[$k]+set} ]] && continue
    extra+=("$k")
  done
  if (( ${#extra[@]} > 0 )); then
    # Length-guarded already, so the `+` idiom adds nothing at runtime; it is
    # written anyway because tests/lint-shell.sh's check is a per-line grep
    # that cannot see the enclosing `if`, and an exemption it cannot express
    # is a check that stays red for a correct file.
    printf '%s\n' "${extra[@]+"${extra[@]}"}" | LC_ALL=C sort -u
  fi
}

# ---------------------------------------------------------------------------
# 1c. CIS compliance view state (docs/STEP10-SARIF-PLAN.md Track B,
#     COMPLIANCE-04)
# ---------------------------------------------------------------------------
# Mirrors section 1a's OWASP registry/state/bucket/render-order mechanics
# (COMPLIANCE-02), with the one structural difference `cis` forces: it is
# `optional, repeatable` (rules/RULE-FORMAT.md §9.1/§9.5) rather than
# `required, single` like `owasp`, so ONE check can cite SEVERAL controls, and
# most checks - the vast majority of SAST/SCA/IaC/DAST checks, which have
# nothing to do with an AWS benchmark - cite NONE. There is therefore no `none`
# bucket to render here (unlike OWASP's own tail section): a finding with no
# `cis` value simply belongs to no control group, which is the ordinary case,
# not a fact worth a heading of its own.
#
# The check_id -> cis registry map, across every module that ships an on-disk
# *.rules registry.  Memoized on $SCOURSH_INSTALL_ROOT for the identical
# reason `_report_owasp_registry_load` is.  Built as check_id -> a
# NEWLINE-JOINED list of cis ids (mirroring `finding_add`'s own join for the
# repeatable `cis` field), never a single scalar, because a check can cite
# more than one control.
declare -gA _RPTCIS_CHECK_CIS=()
declare -g _RPTCIS_REGISTRY_LOADED_ROOT=''
_report_cis_registry_load() {
  _report_checkmeta_registry_load
}

# _report_cis_state RUNDIR - the per-run facts the view needs to tell FOUR
# things apart that a bare finding count cannot: a control assessed and
# genuinely clean, a control no check in this build targets at all, a control
# whose checks exist but were excluded from THIS run by the tension-15 chain,
# and a control whose checks ran this build but found no resource of the
# relevant kind IN THE SCANNED ACCOUNT to examine - the ticket's own third
# mandatory honesty state, that a per-category OWASP view has no equivalent
# of, because "no resource of this kind exists in the account" is a fact only
# a cloud/posture check can produce.
#
# That fourth state - `_RPTCIS_NAPP_SET`, "not applicable to the scanned
# account" - is read from `meta/coverage_reduction`, the same file
# `_report_coverage_state` already mines for its own "evaluated as not
# applicable" set (`checks=[A B C]`), extended here to ALSO recognise the
# singular `check=<id>` shape `modules/cloud/aws/live/s3.sh`'s own per-account
# roll-up emits (`_s3_record_coverage`: "this check answered for NO bucket in
# the account and is therefore NOT recorded in checks_run") - a check id
# named this way is, by construction, never also in `checks_run`, so there is
# no ambiguity to resolve between the two facts. A check already credited in
# `checks_run` (because it ran successfully for some OTHER account/region/
# bucket in the same run) always reads as assessed for its control instead,
# exactly as `_owasp_bucket`'s own priority order already treats a
# partially-covered OWASP category as assessed rather than filtered.
declare -gA _RPTCIS_REG_HAS=() _RPTCIS_RAN=() _RPTCIS_FILTERED_SET=() _RPTCIS_NAPP_SET=() _RPTCIS_LINES=()
_report_cis_state() {
  local rundir=$1
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  _report_cis_registry_load
  _RPTCIS_REG_HAS=() ; _RPTCIS_RAN=() ; _RPTCIS_FILTERED_SET=() ; _RPTCIS_NAPP_SET=() ; _RPTCIS_LINES=()

  local cid cislist cis_id
  for cid in "${!_RPTCIS_CHECK_CIS[@]}"; do
    while IFS= read -r cis_id; do
      [[ -n $cis_id ]] || continue
      _RPTCIS_REG_HAS[$cis_id]=1
    done <<<"${_RPTCIS_CHECK_CIS[$cid]}"
  done

  local -A ran_ids=()
  if [[ -r $rundir/meta/checks_run ]]; then
    while IFS= read -r cid; do
      [[ -n $cid ]] || continue
      ran_ids[$cid]=1
    done <"$rundir/meta/checks_run"
  fi
  # See `_report_owasp_state`'s own comment on why this loop uses a bare
  # `"${!ran_ids[@]}"` rather than the `${arr[@]+alt}` guard idiom: the same
  # empty-associative-array hazard applies here verbatim.
  for cid in "${!ran_ids[@]}"; do
    [[ -n $cid ]] || continue
    cislist=${_RPTCIS_CHECK_CIS[$cid]:-}
    [[ -n $cislist ]] || continue
    while IFS= read -r cis_id; do
      [[ -n $cis_id ]] || continue
      _RPTCIS_RAN[$cis_id]=1
    done <<<"$cislist"
  done

  if [[ -r $rundir/meta/skipped_checks ]]; then
    local line skid reason
    while IFS= read -r line; do
      [[ $line =~ ^check=([^\ ]+)\ skipped_by=(.*)$ ]] || continue
      skid=${BASH_REMATCH[1]}
      reason=${BASH_REMATCH[2]}
      cislist=${_RPTCIS_CHECK_CIS[$skid]:-}
      [[ -n $cislist ]] || continue
      while IFS= read -r cis_id; do
        [[ -n $cis_id ]] || continue
        _RPTCIS_FILTERED_SET["$cis_id|$reason"]=1
      done <<<"$cislist"
    done <"$rundir/meta/skipped_checks"
  fi

  # "not applicable to the scanned account": a check id named either inside a
  # coverage_reduction's `checks=[A B C]` list (the shared, cross-module
  # shape `_report_coverage_state` already reads) or its singular `check=<id>`
  # shape (`modules/cloud/aws/live/s3.sh`'s own per-account roll-up). Literal
  # substring matching is safe for both: `check=` never matches inside
  # `checks=` (the sixth byte differs, `s` vs `=`), so the two extractions
  # cannot collide.
  if [[ -r $rundir/meta/coverage_reduction ]]; then
    local crline crreason crids crid crsingle
    while IFS= read -r crline; do
      [[ -n $crline ]] || continue
      crreason=$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' <<<"$crline")
      crids=$(sed -n 's/.*checks=\[\([^]]*\)\].*/\1/p' <<<"$crline")
      for crid in $crids; do
        [[ -n $crid ]] || continue
        cislist=${_RPTCIS_CHECK_CIS[$crid]:-}
        [[ -n $cislist ]] || continue
        while IFS= read -r cis_id; do
          [[ -n $cis_id ]] || continue
          _RPTCIS_NAPP_SET["$cis_id|${crreason:-not_applicable}"]=1
        done <<<"$cislist"
      done
      crsingle=$(sed -n 's/.*check=\([^ ]*\).*/\1/p' <<<"$crline")
      [[ -n $crsingle ]] || continue
      cislist=${_RPTCIS_CHECK_CIS[$crsingle]:-}
      [[ -n $cislist ]] || continue
      while IFS= read -r cis_id; do
        [[ -n $cis_id ]] || continue
        _RPTCIS_NAPP_SET["$cis_id|${crreason:-not_applicable}"]=1
      done <<<"$cislist"
    done <"$rundir/meta/coverage_reduction"
  fi

  if [[ -s $rundir/findings.fields ]]; then
    local fline flist
    while IFS= read -r fline; do
      [[ -n $fline ]] || continue
      finding_decode "$fline"
      [[ ${_DF[suppressed]:-false} == true ]] && continue
      flist=${_DF[cis]:-}
      [[ -n $flist ]] || continue
      while IFS= read -r cis_id; do
        [[ -n $cis_id ]] || continue
        if [[ -n ${_RPTCIS_LINES[$cis_id]:-} ]]; then
          _RPTCIS_LINES[$cis_id]+=$'\n'"$fline"
        else
          _RPTCIS_LINES[$cis_id]=$fline
        fi
      done <<<"$flist"
    done <"$rundir/findings.fields"
  fi
}

# _cis_bucket ID - one of `findings` / `clean` / `out_of_scope` /
# `not_applicable` / `filtered` / `not_run`, in that priority order - the
# ticket's mandatory three (`clean`/`out_of_scope`/`not_applicable`) plus the
# two extra states `_owasp_bucket` already renders, kept for shape parity.
_cis_bucket() {
  local id=$1 count=${_RPT_CIS[$1]:-0}
  if (( count > 0 )); then
    printf 'findings'
  elif [[ -z ${_RPTCIS_REG_HAS[$id]:-} ]]; then
    printf 'out_of_scope'
  elif [[ -n ${_RPTCIS_RAN[$id]:-} ]]; then
    printf 'clean'
  else
    local k
    for k in "${!_RPTCIS_NAPP_SET[@]}"; do
      [[ -n $k ]] || continue
      if [[ $k == "$id|"* ]]; then
        printf 'not_applicable'
        return 0
      fi
    done
    for k in "${!_RPTCIS_FILTERED_SET[@]}"; do
      [[ -n $k ]] || continue
      if [[ $k == "$id|"* ]]; then
        printf 'filtered'
        return 0
      fi
    done
    printf 'not_run'
  fi
}

# _cis_not_applicable_reasons ID / _cis_filtered_reasons ID - the distinct
# reasons behind the `not_applicable`/`filtered` buckets above, comma-joined,
# `LC_ALL=C` sorted for determinism - mirrors `_owasp_filtered_reasons`
# exactly, once per set.
_cis_not_applicable_reasons() {
  local id=$1 k reason out='' list
  list=$(
    for k in "${!_RPTCIS_NAPP_SET[@]}"; do
      [[ -n $k ]] || continue
      [[ $k == "$id|"* ]] && printf '%s\n' "${k#"$id|"}"
    done | LC_ALL=C sort -u
  )
  while IFS= read -r reason; do
    [[ -n $reason ]] || continue
    if [[ -n $out ]]; then out+=", $reason"; else out=$reason; fi
  done <<<"$list"
  printf '%s' "$out"
}

_cis_filtered_reasons() {
  local id=$1 k reason out='' list
  list=$(
    for k in "${!_RPTCIS_FILTERED_SET[@]}"; do
      [[ -n $k ]] || continue
      [[ $k == "$id|"* ]] && printf '%s\n' "${k#"$id|"}"
    done | LC_ALL=C sort -u
  )
  while IFS= read -r reason; do
    [[ -n $reason ]] || continue
    if [[ -n $out ]]; then out+=", $reason"; else out=$reason; fi
  done <<<"$list"
  printf '%s' "$out"
}

# _cis_render_order - every id `data/cis-mappings` has a row for, in ON-DISK
# (natural benchmark-numbering) order via `_CIS_ORDER` - never a `LC_ALL=C`
# re-sort, which `_CIS_ORDER`'s own declaration comment explains is wrong for
# a dotted-decimal id that is not zero-padded - followed by any id this run's
# own findings or registry carry that the table has NEVER heard of (drift, or
# a future benchmark edition), `LC_ALL=C` sorted among themselves and never
# reordered ahead of the canonical set, exactly as `_owasp_render_order`'s own
# tail does.
_cis_render_order() {
  (( _CIS_LABEL_LOADED )) || cis_mappings_load
  local k
  if (( ${#_CIS_ORDER[@]} > 0 )); then
    printf '%s\n' "${_CIS_ORDER[@]+"${_CIS_ORDER[@]}"}"
  fi
  local -a extra=()
  local -A seen=()
  for k in "${!_RPT_CIS[@]}" "${!_RPTCIS_REG_HAS[@]}"; do
    [[ -n $k ]] || continue
    [[ -n ${_CIS_LABEL[$k]+set} ]] && continue
    [[ -n ${seen[$k]:-} ]] && continue
    seen[$k]=1
    extra+=("$k")
  done
  if (( ${#extra[@]} > 0 )); then
    # Length-guarded already; written as the `+` idiom anyway for the same
    # tests/lint-shell.sh reason `_owasp_render_order`'s own comment gives.
    printf '%s\n' "${extra[@]+"${extra[@]}"}" | LC_ALL=C sort -u
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
    # `abort_reason` (lib/core.sh's die()) is deliberately NOT folded into
    # `incomplete_reason`: that field's emptiness is exactly the exit-5
    # predicate (tension 14, this file's own header above), and a usage/scope/
    # input abort (exit 2/3/4) must never read as an incomplete (exit 5) run.
    # It carries no exit-code meaning of its own - only the reason a run that
    # terminated early is what it is, for the OWASP/CIS `not_run` bucket and
    # the Limitations section to render instead of "no reason recorded".
    _meta_array "$rundir" abort_reason 'abort_reason'
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
    _report_dast_surface_json "$rundir"
  _report_cloud_json "$rundir"
    _report_baseline_json "$rundir"
    printf '}\n'
  } >"$rundir/run.json"
}

# The run's CLOUD authorization/scope object (docs/STEP6-CLOUD-PLAN.md D1's
# "record cloud_account_id, cloud_caller_arn, cloud_profile,
# cloud_regions_planned into run.json - the _scan_record_authorization
# analogue").
#
# It is a SEPARATE object rather than four more keys inside `authorization`,
# because that object's own fields are DAST's - a scope target, a scope.conf
# digest, an intensity, an intrusive flag - and every one of them is
# meaningless for a cloud run.  Folding these in would leave a consumer unable
# to tell "this run affirmed nothing because it was a cloud run" from "this run
# affirmed nothing because the operator omitted the flag".
#
# Rendered on EVERY run, not only a cloud one, for the identical reason
# `_report_authorization_json` and `_report_dast_surface_json` above always
# render: an absent key is ambiguous between "no account was scanned" and "this
# version does not record it". A non-cloud run's own empty/zero defaults are a
# true and complete statement about it.
#
# `account_affirmed` is the OPTIONAL `--i-own-account` value, and it is a
# STRING rather than a bool on purpose: what an auditor needs from it is WHICH
# account the operator claimed, which is exactly the field a mismatch would
# have been refused on. An empty string means the flag was not given.
#
# `regions_planned` renders as JSON `null` on a run that never dispatched
# cloud, and as a NUMBER (including `0`) on one that did - `json_number` maps
# the absent meta value to `null` and that asymmetry is wanted here, unlike in
# `dast_surface` above where a zero default is the right answer.  "This run
# never planned any region" and "the cloud module ran and could not resolve a
# single enabled region" are different facts, and the second one is a real,
# recorded coverage loss a consumer must not read as the first.
_report_cloud_json() {
  local rundir=$1
  printf '  "cloud": {\n'
  printf '    "account_id": %s,\n' "$(json_string "$(_meta_first "$rundir" cloud_account_id)")"
  printf '    "caller_arn": %s,\n' "$(json_string "$(_meta_first "$rundir" cloud_caller_arn)")"
  printf '    "profile": %s,\n' "$(json_string "$(_meta_first "$rundir" cloud_profile)")"
  printf '    "account_affirmed": %s,\n' "$(json_string "$(_meta_first "$rundir" cloud_account_affirmed)")"
  printf '    "regions_source": %s,\n' "$(json_string "$(_meta_first "$rundir" cloud_regions_source)")"
  printf '    "regions_planned": %s\n' "$(json_number "$(_meta_first "$rundir" cloud_regions_planned)")"
  printf '  },\n'
}

# The run's DAST surface-provenance object (IMPORT-06, docs/DESIGN.md §15's
# honesty standard applied to run.json rather than only to `notes[]` prose).
# Rendered on EVERY run, not only a DAST one, for the identical reason
# `_report_authorization_json` and `_report_baseline_json` above always
# render: an absent key would be ambiguous between "no surface discovered"
# and "this version does not record it". A non-DAST run's own zero/empty
# defaults are a true and complete statement about it.
#
# `endpoints_by_source`/`parameters_by_source` are rendered key-sorted
# (`LC_ALL=C`), matching `report_run_json`'s own `by_module` object, so two
# runs that discovered the identical surface produce byte-identical JSON
# regardless of bash's own associative-array iteration order.
_report_dast_surface_json() {
  local rundir=$1 first=1 k
  printf '  "dast_surface": {\n'
  printf '    "endpoints_total": %s,\n' "$(json_number "${_RPT_DAST_SURFACE_EP_TOTAL:-0}")"
  printf '    "endpoints_by_source": {'
  if (( ${#_RPT_DAST_SURFACE_EP_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_DAST_SURFACE_EP_SRC[$k]}")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_EP_SRC[@]}" | LC_ALL=C sort)"
  fi
  printf '},\n'
  printf '    "parameters_total": %s,\n' "$(json_number "${_RPT_DAST_SURFACE_PAR_TOTAL:-0}")"
  printf '    "parameters_by_source": {'
  first=1
  if (( ${#_RPT_DAST_SURFACE_PAR_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      (( first )) || printf ','
      first=0
      printf '%s:%s' "$(json_string "$k")" "$(json_number "${_RPT_DAST_SURFACE_PAR_SRC[$k]}")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_PAR_SRC[@]}" | LC_ALL=C sort)"
  fi
  printf '}\n'
  printf '  },\n'
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

# `_run_abort_reason RUNDIR` - the human-readable reason this run's process
# actually terminated early via `die()` (lib/core.sh), when one was captured.
# Empty, with status 0, when nothing was: a check simply not selected by a
# filter or profile is not an abort, and callers must keep the honest "no
# reason was recorded" text for that case rather than borrow this one.
# Reads only the FIRST line: a run practically dies exactly once, and
# `meta/abort_reason` is append-only in the same shape every other run-level
# fact is, so a stray second line (a worker's own abort, folded in after the
# owning process already recorded its own) is not this function's job to
# join - the OWASP/CIS `not_run` bucket wants one sentence, not a list.
_run_abort_reason() {
  _meta_first "$1" abort_reason
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
# `_md_abort_banner RUNDIR` - an aborted run's counts are all zero (0 live
# findings, an all-zero severity table, an empty "Since last scan" block),
# which reads exactly like a clean scan to anyone who reads the top of the
# file and stops, or screenshots it. The OWASP/CIS sections and
# `_md_limitations` already disclose the abort in full further down; this is
# ADDITIVE, placed before every count in the report so the reader cannot miss
# it. `_run_abort_reason` reads the identical `meta/abort_reason` record
# die() itself wrote (lib/core.sh), so this can never disagree with the
# lower-down disclosures.
_md_abort_banner() {
  local rundir=$1 abort_reason
  abort_reason=$(_run_abort_reason "$rundir")
  [[ -n $abort_reason ]] || return 0
  printf '> **THIS RUN DID NOT COMPLETE.** %s\n>\n' "$abort_reason"
  printf '> Every count below reflects only what ran before the abort - it is not a\n'
  printf '> clean result. See "Limitations and coverage" below for the full detail.\n\n'
}

report_md() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  report_count "$rundir"
  {
    printf '# scoursh scan report\n\n'
    _md_abort_banner "$rundir"
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
    _md_surface_summary
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
    _md_owasp_compliance "$rundir"
    _md_cis_compliance "$rundir"
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

# `_md_compliance_no_coverage RUNDIR NOUN` - the shared "no checks ran at
# all" statement `_md_owasp_compliance`/`_md_cis_compliance` print in place
# of their usual per-category/per-control table when `report_count` set
# `_RPT_COMPLIANCE_SKIPPED` (meta/checks_run empty: an abort before dispatch,
# or a filter chain that selected nothing). NOUN is "category" or "control",
# so the one sentence reads naturally in both callers.
#
# Deliberately does NOT say "assessed, no findings" (that would be the
# "clean" bucket, and nothing was assessed) and deliberately does NOT say
# "checks exist for this category but did not run" (that claim needs the
# registry walk this path exists to skip, so it is never made here) - it
# states only what is actually known: no check ran, and why, when a reason
# was recorded.
_md_compliance_no_coverage() {
  local rundir=$1 noun=$2 abort_reason
  abort_reason=$(_run_abort_reason "$rundir")
  if [[ -n $abort_reason ]]; then
    printf 'This scan aborted before any %s could be assessed: %s\n\n' "$noun" "$abort_reason"
  else
    printf 'No checks ran this scan, so no %s could be assessed; no reason was recorded.\n\n' "$noun"
  fi
}

# `_md_owasp_compliance RUNDIR` - COMPLIANCE-02: report.md has no OWASP
# section at all today; this adds one. Groups the findings themselves by
# category (never merely counts them - `_html_summary`'s existing
# `_RPT_OWASP` table already does that), and renders, per category, one of
# three honestly distinct facts a bare "no findings" cannot tell apart:
# assessed-and-clean, out-of-scope-by-design (no check anywhere in this
# build targets it), or excluded from THIS run by --profile-scan/--intensity
# (`_owasp_bucket`, section 1a above - built from `checks_run` and
# `skipped_checks`, already written, never a hardcoded per-category tier).
# SC2016: the Markdown code spans below are literal output, not command
# substitution.
# shellcheck disable=SC2016
_md_owasp_compliance() {
  local rundir=$1
  printf '## OWASP Top 10 compliance\n\n'
  printf '> docs/DESIGN.md Appendix B'\''s own honest summary: "strong automated\n'
  printf '> coverage of the testable Top 10, explicit and labeled gaps on A04/A08/A09\n'
  printf '> and the manual-review portion of A01 - not a substitute for a human pentest\n'
  printf '> or an ASVS audit." That is the tool'\''s documented design-level claim. The\n'
  printf '> table below is this run'\''s own status per category, measured from this\n'
  printf '> run'\''s `checks_run`/`skipped_checks` records rather than copied from that\n'
  printf '> prose, and will differ from it as coverage grows.\n\n'
  if (( _RPT_COMPLIANCE_SKIPPED )); then
    _md_compliance_no_coverage "$rundir" category
    return 0
  fi
  local id label count bucket line
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    label=$(owasp_category_label "$id")
    count=${_RPT_OWASP[$id]:-0}
    bucket=$(_owasp_bucket "$id")
    printf '### %s - %s\n\n' "$id" "$label"
    case $bucket in
      findings)
        printf -- '- **%s** live finding(s) this run\n\n' "$count"
        printf '| check | title | severity | status |\n|---|---|---|---|\n'
        while IFS= read -r line; do
          [[ -n $line ]] || continue
          finding_decode "$line"
          printf '| `%s` | %s | %s | %s |\n' \
            "${_DF[check_id]}" "${_DF[title]}" "${_DF[severity]}" "${_DF[status]}"
        done <<<"${_RPTOW_LINES[$id]:-}"
        printf '\nSee [Findings](#findings) above for full detail and remediation.\n\n'
        ;;
      clean)
        printf 'Assessed this run - no findings.\n\n' ;;
      out_of_scope)
        printf 'No check in this build of scoursh targets this category yet.\n\n' ;;
      filtered)
        printf 'Checks for this category exist but were excluded from this run (%s).\n\n' \
          "$(_owasp_filtered_reasons "$id")" ;;
      not_run)
        local abort_reason
        abort_reason=$(_run_abort_reason "$rundir")
        if [[ -n $abort_reason ]]; then
          printf 'Checks for this category exist but did not run this scan: %s\n\n' "$abort_reason"
        else
          printf 'Checks for this category exist but did not run this scan; no reason was recorded.\n\n'
        fi
        ;;
    esac
  done <<<"$(_owasp_render_order)"
  if (( ${_RPT_OWASP[none]:-0} > 0 )); then
    printf '### none - Not categorised\n\n'
    printf -- '- **%s** live finding(s) this run map to no OWASP category\n\n' "${_RPT_OWASP[none]}"
    printf '| check | title | severity | status |\n|---|---|---|---|\n'
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      printf '| `%s` | %s | %s | %s |\n' \
        "${_DF[check_id]}" "${_DF[title]}" "${_DF[severity]}" "${_DF[status]}"
    done <<<"${_RPTOW_LINES[none]:-}"
    printf '\n'
  fi
}

# `_md_cis_compliance RUNDIR` - COMPLIANCE-04: report.md's CIS twin of
# `_md_owasp_compliance` above; see that function's own header and section 1c
# for the design this mirrors. States the benchmark name and version at the
# head of the section (docs/DESIGN.md §4's CIS half), then groups the
# findings themselves by control id, expanded to its published title through
# `cis_control_label` (COMPLIANCE-03). There is no `none`-mapped tail section
# here, unlike the OWASP view: `cis` carries no such sentinel, and a finding
# with no `cis` value simply belongs to no control group - the ordinary case
# for every non-cloud/posture check in this build.
# SC2016: the Markdown code spans below are literal output, not command
# substitution.
# shellcheck disable=SC2016
_md_cis_compliance() {
  local rundir=$1
  printf '## CIS compliance\n\n'
  local bname bver
  bname=$(cis_benchmark_name)
  bver=$(cis_benchmark_version)
  if [[ -n $bname ]]; then
    printf '> This run'\''s status against **%s%s**, per control, measured from this\n' \
      "$bname" "${bver:+ $bver}"
    printf '> run'\''s `checks_run`/`skipped_checks`/`coverage_reduction` records.  A\n'
    printf '> control assessed and clean, a control this build has no check for yet, and\n'
    printf '> a control whose check ran but found no matching resource in the scanned\n'
    printf '> account are three different facts and render as three different things\n'
    printf '> below - see `docs/CIS-MAPPINGS.md` for what this table covers today and its\n'
    printf '> stated gaps.\n\n'
  else
    printf '> No CIS control label table (`data/cis-mappings`) is available in this\n'
    printf '> build, so control ids on findings below render unexpanded.\n\n'
  fi
  if (( _RPT_COMPLIANCE_SKIPPED )); then
    _md_compliance_no_coverage "$rundir" control
    return 0
  fi
  local id label count bucket line
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    label=$(cis_control_label "$id")
    count=${_RPT_CIS[$id]:-0}
    bucket=$(_cis_bucket "$id")
    printf '### %s - %s\n\n' "$id" "$label"
    case $bucket in
      findings)
        printf -- '- **%s** live finding(s) this run\n\n' "$count"
        printf '| check | title | severity | status |\n|---|---|---|---|\n'
        while IFS= read -r line; do
          [[ -n $line ]] || continue
          finding_decode "$line"
          printf '| `%s` | %s | %s | %s |\n' \
            "${_DF[check_id]}" "${_DF[title]}" "${_DF[severity]}" "${_DF[status]}"
        done <<<"${_RPTCIS_LINES[$id]:-}"
        printf '\nSee [Findings](#findings) above for full detail and remediation.\n\n'
        ;;
      clean)
        printf 'Assessed this run - no findings.\n\n' ;;
      out_of_scope)
        printf 'No check in this build of scoursh targets this control yet.\n\n' ;;
      not_applicable)
        printf 'This control'\''s check(s) ran but found no matching resource in the scanned account this run (%s).\n\n' \
          "$(_cis_not_applicable_reasons "$id")" ;;
      filtered)
        printf 'Checks for this control exist but were excluded from this run (%s).\n\n' \
          "$(_cis_filtered_reasons "$id")" ;;
      not_run)
        local abort_reason
        abort_reason=$(_run_abort_reason "$rundir")
        if [[ -n $abort_reason ]]; then
          printf 'Checks for this control exist but did not run this scan: %s\n\n' "$abort_reason"
        else
          printf 'Checks for this control exist but did not run this scan; no reason was recorded.\n\n'
        fi
        ;;
    esac
  done <<<"$(_cis_render_order)"
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

# `_md_surface_summary` - IMPORT-06's own acceptance criterion: a reader sees
# "surface: N endpoints (M from an openapi spec you supplied)" as a rendered
# line rather than having to substring-scrape the `notes[]` prose `crawl.sh`
# already writes (kept unchanged). Reads only `_RPT_DAST_SURFACE_EP_TOTAL`/
# `_RPT_DAST_SURFACE_PAR_TOTAL` and the two per-source maps
# (`report_count`, via `_report_dast_surface_state`) - integers and the fixed
# `source` vocabulary's own labels - so nothing here needs escaping.
_md_surface_summary() {
  (( ${_RPT_DAST_SURFACE_EP_TOTAL:-0} > 0 || ${_RPT_DAST_SURFACE_PAR_TOTAL:-0} > 0 )) || return 0
  local k v first ep_break='' par_break=''
  first=1
  if (( ${#_RPT_DAST_SURFACE_EP_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      v=${_RPT_DAST_SURFACE_EP_SRC[$k]:-0}
      (( first )) || ep_break+=', '
      first=0
      ep_break+="$v from $(_dast_surface_source_label "$k")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_EP_SRC[@]}" | LC_ALL=C sort)"
  fi
  first=1
  if (( ${#_RPT_DAST_SURFACE_PAR_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      v=${_RPT_DAST_SURFACE_PAR_SRC[$k]:-0}
      (( first )) || par_break+=', '
      first=0
      par_break+="$v from $(_dast_surface_source_label "$k")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_PAR_SRC[@]}" | LC_ALL=C sort)"
  fi
  printf -- '- surface: %s endpoint(s)%s, %s parameter(s)%s\n\n' \
    "${_RPT_DAST_SURFACE_EP_TOTAL:-0}" "${ep_break:+ ($ep_break)}" \
    "${_RPT_DAST_SURFACE_PAR_TOTAL:-0}" "${par_break:+ ($par_break)}"
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
  if [[ -r $rundir/meta/abort_reason ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf -- '- **run aborted**: %s\n' "$line"
    done <"$rundir/meta/abort_reason"
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
    _html_owasp_compliance "$rundir"
    _html_cis_compliance "$rundir"
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
/* scoursh-report-ux: wide tables/content scroll in their own box rather than
   the page - no horizontal page overflow on a narrow viewport. */
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
/* Category quick-jump chips at the top of the Findings section. */
.catnav { display: flex; flex-wrap: wrap; gap: .4rem; margin: 0 0 1.5rem; }
.catpill { display: inline-flex; align-items: center; gap: .35rem; text-decoration: none;
  border: 1px solid var(--line); background: var(--card); border-radius: 2rem;
  padding: .25rem .7rem; font-size: .82rem; color: var(--fg); }
.catpill:hover { border-color: var(--accent); }
.catpill .c { color: var(--muted); font-variant-numeric: tabular-nums; font-size: .76rem; }
/* One collapsible group per category (SAST/SCA/IaC/DAST/AWS). */
details.modgrp { border: 1px solid var(--line); border-radius: .5rem; margin: 0 0 1.1rem;
  background: var(--card); scroll-margin-top: 1rem; }
details.modgrp > summary { cursor: pointer; padding: .7rem .9rem; list-style: none;
  display: flex; align-items: center; flex-wrap: wrap; gap: .5rem; }
details.modgrp > summary::-webkit-details-marker { display: none; }
details.modgrp > summary::before { content: "\25B8"; color: var(--muted); font-size: .8rem;
  transition: transform .12s ease; display: inline-block; }
details.modgrp[open] > summary::before { transform: rotate(90deg); }
.modlabel { font-weight: 650; font-size: 1.02rem; }
.modbody { padding: .1rem .9rem .9rem; border-top: 1px solid var(--line); }
.sevbreak { display: flex; flex-wrap: wrap; gap: .35rem; margin: .7rem 0 .9rem; }
.sevbreak .sev { padding: .15rem .5rem; }
/* Severity filter - CSS-only (:has()), same no-JS mechanism report-audit.html
   uses. The radios live inside .filter, next to their own labels, so both the
   highlight rule and the hide/show rule work regardless of how deep .filter
   sits in the document (a plain "~" sibling combinator would not reach past
   the intervening <main>). */
.filter { display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; margin: 1rem 0 1.5rem; }
.filter .lbl { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); font-weight: 650; margin-right: .2rem; }
.filter input { position: absolute; opacity: 0; width: 0; height: 0; }
.filter label { border: 1px solid var(--line); background: var(--card); border-radius: 2rem;
  padding: .18rem .6rem; font-size: .8rem; cursor: pointer; user-select: none; }
.filter label:hover { border-color: var(--accent); }
.filter:has(#sv-all:checked) label[for="sv-all"],
.filter:has(#sv-crit:checked) label[for="sv-crit"],
.filter:has(#sv-high:checked) label[for="sv-high"],
.filter:has(#sv-med:checked) label[for="sv-med"],
.filter:has(#sv-low:checked) label[for="sv-low"] {
  background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600;
}
@media (prefers-color-scheme: dark) {
  .filter:has(#sv-all:checked) label[for="sv-all"],
  .filter:has(#sv-crit:checked) label[for="sv-crit"],
  .filter:has(#sv-high:checked) label[for="sv-high"],
  .filter:has(#sv-med:checked) label[for="sv-med"],
  .filter:has(#sv-low:checked) label[for="sv-low"] { color: #111318; }
}
.filterhint { font-size: .74rem; color: var(--muted); margin-left: .2rem; }
body:has(#sv-crit:checked) details.f:not([data-sev="critical"]),
body:has(#sv-high:checked) details.f:not([data-sev="critical"]):not([data-sev="high"]),
body:has(#sv-med:checked)  details.f:not([data-sev="critical"]):not([data-sev="high"]):not([data-sev="medium"]),
body:has(#sv-low:checked)  details.f[data-sev="info"] { display: none; }
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

# `_html_abort_banner RUNDIR` - the HTML twin of `_md_abort_banner` above;
# see that function's own header for why this has to sit above every count.
# Reuses the existing `.banner` style (a critical-colored box the redaction
# and unrestricted-run banners already use) rather than inventing a new one.
_html_abort_banner() {
  local rundir=$1 abort_reason
  abort_reason=$(_run_abort_reason "$rundir")
  [[ -n $abort_reason ]] || return 0
  printf '<p class="banner">THIS RUN DID NOT COMPLETE: %s Every count below reflects only what ran before the abort - it is not a clean result. See <a href="#limitations">Limitations and coverage</a> below for the full detail.</p>\n' \
    "$(html_escape "$abort_reason")"
}

_html_summary() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  printf '<h1 id="top">scoursh scan report</h1>\n'
  _html_abort_banner "$rundir"
  printf '<p class="sub">run <code>%s</code> · tool <code>%s</code> · fingerprint schema <code>%s</code> · %s live findings, %s accepted risk</p>\n' \
    "$(html_escape "${SCOURSH_RUN_ID:-}")" "$(html_escape "$(scoursh_version)")" \
    "$(html_escape "$FP_SCHEMA")" "$_RPT_LIVE" "$_RPT_SUPPRESSED"
  if [[ $SCOURSH_REDACT_SECRETS != true ]]; then
    printf '<p class="banner">Redaction is DISABLED for this run. This report may contain live credentials and must not be circulated.</p>\n'
  fi
  _html_unrestricted_banner "$rundir"
  _html_zero_injection_banner
  _html_surface_summary
  printf '<nav class="toc"><p>On this page</p><ul>\n'
  printf '<li><a href="#severity">Severity</a></li>\n'
  printf '<li><a href="#since-last-scan">Since the last scan</a></li>\n'
  (( ${#_RPT_MODULE[@]} > 0 )) && printf '<li><a href="#by-module">By module</a></li>\n'
  (( ${#_RPT_OWASP[@]} > 0 )) && printf '<li><a href="#by-owasp">By OWASP category</a></li>\n'
  printf '<li><a href="#findings">Findings (%s)</a></li>\n' "$_RPT_LIVE"
  (( _RPT_SUPPRESSED > 0 )) && printf '<li><a href="#accepted-risk">Accepted risk (%s)</a></li>\n' "$_RPT_SUPPRESSED"
  printf '<li><a href="#owasp-compliance">OWASP Top 10 compliance</a></li>\n'
  printf '<li><a href="#cis-compliance">CIS compliance</a></li>\n'
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
    printf '<h2 id="by-module">By module</h2>\n<div class="scroll"><table><tr><th>module</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$k")" "${_RPT_MODULE[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_MODULE[@]}" | LC_ALL=C sort)"
    printf '</table></div>\n'
  fi
  if (( ${#_RPT_OWASP[@]} > 0 )); then
    printf '<h2 id="by-owasp">By OWASP category</h2>\n<div class="scroll"><table><tr><th>category</th><th>label</th><th>findings</th></tr>\n'
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$k")" "$(html_escape "$(owasp_category_label "$k")")" "${_RPT_OWASP[$k]}"
    done <<<"$(printf '%s\n' "${!_RPT_OWASP[@]}" | LC_ALL=C sort)"
    printf '</table></div>\n'
  fi
}

# `_RPT_CAT_LABEL`/`_RPT_CAT_ORDER` - report.html's own category vocabulary for
# grouping findings, deliberately a SEPARATE declaration from report-audit.html's
# `_RPTC_CAT_LABEL` (lib/report.sh section 4a) even though the labels agree:
# the two reports share no markup or state by design (captain decision,
# scoursh-audit-report ticket), and report.html must render correctly on its
# own even if report-audit.html's array shape ever changes. `derived` is a
# real `module` value (tension 6 composite findings) with no report-audit.html
# analogue - `cloud` is spelled here to match the finding module value; the
# UI label says "AWS" per the captain's own naming.
#
# THIS MAP IS KEYED BY THE FINDING'S OWN `module` FIELD VALUE
# (lib/findings.sh `_fp_profile_for`'s spelling: `net`, not `_RPT_MODULES`'s
# `network` scan.sh subcommand spelling - the two are different vocabularies
# for different jobs, `_RPTC_CAT_LABEL`'s own header two lines up already
# makes the identical distinction for the checks/coverage side).  `[net]` was
# absent until NET-09 emitted the first `module: net` finding to expose the
# gap, and adding the label alone is NOT enough - `_html_findings`'s own
# `order`/`rest` split below puts a module in `rest` (its "never drop an
# unrecognised value" fallback path) ONLY when `_RPT_CAT_LABEL` has NO entry
# for it; once a label exists the module MUST also appear in `_RPT_CAT_ORDER`
# or it satisfies neither branch and is silently dropped from the render
# entirely - measured directly: adding `[net]='Network'` here alone made a
# real `module: net` finding vanish from the findings section (while still
# appearing in `findings.jsonl`/`findings.json`/report.md, which read
# `findings.fields` directly rather than through this split), the opposite
# of what the label change intended.
declare -A _RPT_CAT_LABEL=( [sast]='SAST' [sca]='SCA' [iac]='IaC' [dast]='DAST' [cloud]='AWS' [net]='Network' [derived]='Correlated' )
# Deliberately its OWN literal list, never `_RPT_MODULES` (that array is
# spelled `network`, the scan.sh subcommand name - checked above) plus
# `derived`: every key `_RPT_CAT_LABEL` above defines needs a matching entry
# here, in the finding-module spelling, or it is silently dropped rather than
# rendered - see that map's own header for the failure this measured.
_RPT_CAT_ORDER=(sast sca iac dast cloud net derived)

# `_html_findings_category MODULE LINES COUNT` - one collapsible group of
# findings for a single category, with its own severity breakdown. `LINES` is
# a newline-joined set of findings.fields rows already filtered to this
# module and to live (non-suppressed) findings by the caller - never
# re-decoded from findings.jsonl (tension 10's "escape on the way out"
# discipline needs one path in, `finding_decode`, not two).
_html_findings_category() {
  local mod=$1 lines=$2 count=$3 label line sev
  label=${_RPT_CAT_LABEL[$mod]:-$mod}
  local -A sevcount=( [critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0 )
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    sev=${_DF[severity]:-info}
    sevcount[$sev]=$(( ${sevcount[$sev]:-0} + 1 ))
  done <<<"$lines"
  printf '<details class="modgrp" id="mod-%s" open><summary><span class="modlabel">%s</span><span class="count">%s finding(s)</span></summary>\n' \
    "$(html_escape "$mod")" "$(html_escape "$label")" "$count"
  printf '<div class="modbody">\n<div class="sevbreak">'
  local k
  for k in critical high medium low info; do
    (( ${sevcount[$k]:-0} > 0 )) && printf '<span class="sev %s">%s %s</span>' \
      "$(html_escape "$k")" "${sevcount[$k]}" "$(html_escape "$k")"
  done
  printf '</div>\n'
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    _html_one_finding
  done <<<"$lines"
  printf '</div>\n</details>\n'
}

# `_html_findings RUNDIR` - live findings grouped by category (SAST/SCA/IaC/
# DAST/AWS), each its own collapsible group with a jump-link chip in the
# `.catnav` row above them, plus the severity filter widget
# (`.filter`/`:has()`, no JavaScript - see `_html_head`'s own comment on why
# the radios live inside `.filter` rather than at the top of `<body>`).
# Grouping is computed in ONE pass over `findings.fields` here rather than
# reusing `_RPT_MODULE` (report_count's per-module total): that map has no
# per-finding LINE to render from, only a count, so a second read is needed
# either way - this keeps it local to the renderer that needs the lines.
_html_findings() {
  local rundir=$1 line mod
  printf '<h2 id="findings">Findings</h2>\n'
  if [[ ! -s $rundir/findings.fields ]]; then
    printf '<p class="empty">No findings.</p>\n'
    _html_accepted_risk "$rundir"
    return 0
  fi
  local -A _rptf_lines=() _rptf_count=()
  local -a _rptf_seen=()
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[suppressed]:-false} == true ]] && continue
    mod=${_DF[module]:-unknown}
    [[ -n ${_rptf_count[$mod]:-} ]] || _rptf_seen+=("$mod")
    _rptf_count[$mod]=$(( ${_rptf_count[$mod]:-0} + 1 ))
    if [[ -n ${_rptf_lines[$mod]:-} ]]; then
      _rptf_lines[$mod]+=$'\n'"$line"
    else
      _rptf_lines[$mod]=$line
    fi
  done <"$rundir/findings.fields"

  if (( ${#_rptf_seen[@]} == 0 )); then
    printf '<p class="empty">Every finding this run is an accepted risk; see below.</p>\n'
    _html_accepted_risk "$rundir"
    return 0
  fi

  # Canonical category order first, then any module value outside that
  # vocabulary (LC_ALL=C sorted), so an unexpected `module` value is still
  # rendered - never silently dropped - without disturbing the fixed order
  # every reader of this report learns to expect.
  local -a order=() rest=()
  local c
  for c in "${_RPT_CAT_ORDER[@]+"${_RPT_CAT_ORDER[@]}"}"; do
    [[ -n ${_rptf_count[$c]:-} ]] && order+=("$c")
  done
  for c in "${_rptf_seen[@]+"${_rptf_seen[@]}"}"; do
    [[ -n ${_RPT_CAT_LABEL[$c]:-} ]] || rest+=("$c")
  done
  if (( ${#rest[@]} > 0 )); then
    local extra
    while IFS= read -r extra; do
      [[ -n $extra ]] && order+=("$extra")
    done <<<"$(printf '%s\n' "${rest[@]+"${rest[@]}"}" | LC_ALL=C sort -u)"
  fi

  printf '<div class="catnav">\n'
  for c in "${order[@]+"${order[@]}"}"; do
    printf '<a class="catpill" href="#mod-%s">%s <span class="c">%s</span></a>\n' \
      "$(html_escape "$c")" "$(html_escape "${_RPT_CAT_LABEL[$c]:-$c}")" "${_rptf_count[$c]}"
  done
  printf '</div>\n'

  printf '<div class="filter"><span class="lbl">Severity filter</span>\n'
  printf '<input type="radio" name="sv" id="sv-all" class="fsv" checked><label for="sv-all">All</label>\n'
  printf '<input type="radio" name="sv" id="sv-crit" class="fsv"><label for="sv-crit">Critical</label>\n'
  printf '<input type="radio" name="sv" id="sv-high" class="fsv"><label for="sv-high">High+</label>\n'
  printf '<input type="radio" name="sv" id="sv-med" class="fsv"><label for="sv-med">Medium+</label>\n'
  printf '<input type="radio" name="sv" id="sv-low" class="fsv"><label for="sv-low">Low+</label>\n'
  printf '<span class="filterhint">hides findings below the selected severity &mdash; no JavaScript</span>\n'
  printf '</div>\n'

  for c in "${order[@]+"${order[@]}"}"; do
    _html_findings_category "$c" "${_rptf_lines[$c]}" "${_rptf_count[$c]}"
  done

  _html_accepted_risk "$rundir"
}

# `_html_owasp_compliance RUNDIR` - COMPLIANCE-02's HTML twin of
# `_md_owasp_compliance`; see that function's own header for the design this
# mirrors. Each category is a collapsible group carrying its own status
# (findings/clean/out-of-scope/filtered/not-run); a `findings` group links
# into the existing per-finding anchors (`_html_one_finding`'s `f-<fp>` ids)
# rather than re-rendering full evidence/remediation a second time, keeping
# this section a compact index rather than a duplicate of "Findings" above.
#
# `_html_compliance_no_coverage RUNDIR NOUN` - the HTML twin of
# `_md_compliance_no_coverage`, printed instead of the per-category/
# per-control group list when `report_count` set `_RPT_COMPLIANCE_SKIPPED`.
# See that function's own header for why: nothing here is "clean", and
# nothing here claims a category/control has checks that merely "did not
# run" - that claim needs the registry walk this path skips.
_html_compliance_no_coverage() {
  local rundir=$1 noun=$2 abort_reason
  abort_reason=$(_run_abort_reason "$rundir")
  if [[ -n $abort_reason ]]; then
    printf '<p class="sub notrun">This scan aborted before any %s could be assessed: %s</p>\n' \
      "$(html_escape "$noun")" "$(html_escape "$abort_reason")"
  else
    printf '<p class="sub notrun">No checks ran this scan, so no %s could be assessed - no reason recorded.</p>\n' \
      "$(html_escape "$noun")"
  fi
}
_html_owasp_compliance() {
  local rundir=$1
  printf '<h2 id="owasp-compliance">OWASP Top 10 compliance</h2>\n'
  printf '<p class="sub">docs/DESIGN.md Appendix B&#39;s own honest summary: &quot;strong automated coverage of the testable Top 10, explicit and labeled gaps on A04/A08/A09 and the manual-review portion of A01 - not a substitute for a human pentest or an ASVS audit.&quot; That is the tool&#39;s documented design-level claim. The table below is this run&#39;s own status per category, measured from this run&#39;s <code>checks_run</code>/<code>skipped_checks</code> records rather than copied from that prose, and will differ from it as coverage grows.</p>\n'
  if (( _RPT_COMPLIANCE_SKIPPED )); then
    _html_compliance_no_coverage "$rundir" category
    return 0
  fi
  local id label count bucket line status_class status_text reasons abort_reason
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    label=$(owasp_category_label "$id")
    count=${_RPT_OWASP[$id]:-0}
    bucket=$(_owasp_bucket "$id")
    case $bucket in
      findings) status_class=findings; status_text="$count finding(s)" ;;
      clean) status_class=clean; status_text='assessed - no findings' ;;
      out_of_scope) status_class=outofscope; status_text='out of scope - no check targets this category yet' ;;
      filtered)
        reasons=$(_owasp_filtered_reasons "$id")
        status_class=filtered; status_text="excluded from this run ($reasons)" ;;
      not_run)
        abort_reason=$(_run_abort_reason "$rundir")
        status_class=notrun
        if [[ -n $abort_reason ]]; then
          status_text="did not run this scan: $abort_reason"
        else
          status_text='did not run this scan - no reason recorded'
        fi
        ;;
    esac
    printf '<details class="modgrp" id="owasp-%s"><summary><span class="modlabel">%s - %s</span><span class="count owstat-%s">%s</span></summary>\n' \
      "$(html_escape "$id")" "$(html_escape "$id")" "$(html_escape "$label")" \
      "$(html_escape "$status_class")" "$(html_escape "$status_text")"
    printf '<div class="modbody">\n'
    if [[ $bucket == findings ]]; then
      printf '<ul>\n'
      while IFS= read -r line; do
        [[ -n $line ]] || continue
        finding_decode "$line"
        printf '<li><a href="#f-%s"><code>%s</code></a> %s - <span class="sev %s">%s</span>, %s</li>\n' \
          "$(html_escape "${_DF[fingerprint]}")" "$(html_escape "${_DF[check_id]}")" \
          "$(html_escape "${_DF[title]}")" "$(html_escape "${_DF[severity]}")" \
          "$(html_escape "${_DF[severity]}")" "$(html_escape "${_DF[status]}")"
      done <<<"${_RPTOW_LINES[$id]:-}"
      printf '</ul>\n'
    fi
    printf '</div>\n</details>\n'
  done <<<"$(_owasp_render_order)"
  if (( ${_RPT_OWASP[none]:-0} > 0 )); then
    printf '<details class="modgrp" id="owasp-none"><summary><span class="modlabel">none - Not categorised</span><span class="count">%s</span></summary>\n<div class="modbody">\n<ul>\n' \
      "${_RPT_OWASP[none]}"
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      printf '<li><a href="#f-%s"><code>%s</code></a> %s - <span class="sev %s">%s</span>, %s</li>\n' \
        "$(html_escape "${_DF[fingerprint]}")" "$(html_escape "${_DF[check_id]}")" \
        "$(html_escape "${_DF[title]}")" "$(html_escape "${_DF[severity]}")" \
        "$(html_escape "${_DF[severity]}")" "$(html_escape "${_DF[status]}")"
    done <<<"${_RPTOW_LINES[none]:-}"
    printf '</ul>\n</div>\n</details>\n'
  fi
}

# `_html_cis_compliance RUNDIR` - COMPLIANCE-04's HTML twin of
# `_md_cis_compliance`; see that function's own header and section 1c for the
# design this mirrors. Each control is a collapsible group carrying its own
# status (findings/clean/out-of-scope/not-applicable/filtered/not-run); a
# `findings` group links into the existing per-finding anchors
# (`_html_one_finding`'s `f-<fp>` ids) rather than re-rendering full
# evidence/remediation a second time, exactly as the OWASP view does. There is
# no `none`-mapped tail section here - see `_md_cis_compliance`'s own comment
# on why `cis` needs none.
_html_cis_compliance() {
  local rundir=$1
  printf '<h2 id="cis-compliance">CIS compliance</h2>\n'
  local bname bver
  bname=$(cis_benchmark_name)
  bver=$(cis_benchmark_version)
  if [[ -n $bname ]]; then
    printf '<p class="sub">This run&#39;s status against <strong>%s%s</strong>, per control, measured from this run&#39;s <code>checks_run</code>/<code>skipped_checks</code>/<code>coverage_reduction</code> records. A control assessed and clean, a control this build has no check for yet, and a control whose check ran but found no matching resource in the scanned account are three different facts and render as three different things below - see <code>docs/CIS-MAPPINGS.md</code> for what this table covers today and its stated gaps.</p>\n' \
      "$(html_escape "$bname")" "$(html_escape "${bver:+ $bver}")"
  else
    printf '<p class="sub">No CIS control label table (<code>data/cis-mappings</code>) is available in this build, so control ids on findings below render unexpanded.</p>\n'
  fi
  if (( _RPT_COMPLIANCE_SKIPPED )); then
    _html_compliance_no_coverage "$rundir" control
    return 0
  fi
  local id label count bucket line status_class status_text reasons abort_reason
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    label=$(cis_control_label "$id")
    count=${_RPT_CIS[$id]:-0}
    bucket=$(_cis_bucket "$id")
    case $bucket in
      findings) status_class=findings; status_text="$count finding(s)" ;;
      clean) status_class=clean; status_text='assessed - no findings' ;;
      out_of_scope) status_class=outofscope; status_text='out of scope - no check targets this control yet' ;;
      not_applicable)
        reasons=$(_cis_not_applicable_reasons "$id")
        status_class=notapplicable; status_text="no matching resource in the scanned account ($reasons)" ;;
      filtered)
        reasons=$(_cis_filtered_reasons "$id")
        status_class=filtered; status_text="excluded from this run ($reasons)" ;;
      not_run)
        abort_reason=$(_run_abort_reason "$rundir")
        status_class=notrun
        if [[ -n $abort_reason ]]; then
          status_text="did not run this scan: $abort_reason"
        else
          status_text='did not run this scan - no reason recorded'
        fi
        ;;
    esac
    printf '<details class="modgrp" id="cis-%s"><summary><span class="modlabel">%s - %s</span><span class="count cisstat-%s">%s</span></summary>\n' \
      "$(html_escape "$id")" "$(html_escape "$id")" "$(html_escape "$label")" \
      "$(html_escape "$status_class")" "$(html_escape "$status_text")"
    printf '<div class="modbody">\n'
    if [[ $bucket == findings ]]; then
      printf '<ul>\n'
      while IFS= read -r line; do
        [[ -n $line ]] || continue
        finding_decode "$line"
        printf '<li><a href="#f-%s"><code>%s</code></a> %s - <span class="sev %s">%s</span>, %s</li>\n' \
          "$(html_escape "${_DF[fingerprint]}")" "$(html_escape "${_DF[check_id]}")" \
          "$(html_escape "${_DF[title]}")" "$(html_escape "${_DF[severity]}")" \
          "$(html_escape "${_DF[severity]}")" "$(html_escape "${_DF[status]}")"
      done <<<"${_RPTCIS_LINES[$id]:-}"
      printf '</ul>\n'
    fi
    printf '</div>\n</details>\n'
  done <<<"$(_cis_render_order)"
}

# Suppressed findings render in a separate collapsed "accepted risk" section
# with their reason, and are counted separately (tension 11 step 9). They are
# never deleted, and never grouped by category - an accepted risk is read as
# its own small, deliberately flat list, not folded into the per-category
# groups above it.
_html_accepted_risk() {
  local rundir=$1 line
  (( _RPT_SUPPRESSED > 0 )) || return 0
  printf '<h2 id="accepted-risk">Accepted risk (%s)</h2>\n' "$_RPT_SUPPRESSED"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[suppressed]:-false} == true ]] || continue
    _html_one_finding
  done <"$rundir/findings.fields"
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

# The HTML twin of `_md_surface_summary` - same integers, same source labels
# (`_dast_surface_source_label`), rendered as a plain paragraph rather than a
# `.banner` (this is a fact about coverage, not a warning). The integers are
# never target-derived, but the label IS, for its fallback `*)` arm: an
# endpoint's `source` field is not validated against the closed vocabulary at
# import time (only a parameter's `location` and a header name are,
# IMPORT-05), so a foreign `endpoints.json` (tension 21 - a hand-written or
# cross-module producer) could in principle carry an arbitrary string there.
# `html_escape` applies to the composed label for that reason, uniformly,
# even though the five known values never need it (docs/FOUNDATION.md
# tension 10's "escape on the way out" discipline applied without exception).
_html_surface_summary() {
  (( ${_RPT_DAST_SURFACE_EP_TOTAL:-0} > 0 || ${_RPT_DAST_SURFACE_PAR_TOTAL:-0} > 0 )) || return 0
  local k v first ep_break='' par_break=''
  first=1
  if (( ${#_RPT_DAST_SURFACE_EP_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      v=${_RPT_DAST_SURFACE_EP_SRC[$k]:-0}
      (( first )) || ep_break+=', '
      first=0
      ep_break+="$v from $(html_escape "$(_dast_surface_source_label "$k")")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_EP_SRC[@]}" | LC_ALL=C sort)"
  fi
  first=1
  if (( ${#_RPT_DAST_SURFACE_PAR_SRC[@]} > 0 )); then
    while IFS= read -r k; do
      [[ -n $k ]] || continue
      v=${_RPT_DAST_SURFACE_PAR_SRC[$k]:-0}
      (( first )) || par_break+=', '
      first=0
      par_break+="$v from $(html_escape "$(_dast_surface_source_label "$k")")"
    done <<<"$(printf '%s\n' "${!_RPT_DAST_SURFACE_PAR_SRC[@]}" | LC_ALL=C sort)"
  fi
  printf '<p class="sub">surface: %s endpoint(s)%s, %s parameter(s)%s</p>\n' \
    "${_RPT_DAST_SURFACE_EP_TOTAL:-0}" "${ep_break:+ ($ep_break)}" \
    "${_RPT_DAST_SURFACE_PAR_TOTAL:-0}" "${par_break:+ ($par_break)}"
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
  if [[ -r $rundir/meta/abort_reason ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      any=1
      printf '<li><strong>run aborted</strong>: %s</li>\n' "$(html_escape "$line")"
    done <"$rundir/meta/abort_reason"
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
# 4a. Audit-grade coverage report (report-audit.html) - the scoursh-audit-report
#     ticket.  Captain decision: ship ALONGSIDE report.html, never replacing
#     or editing it - a separate self-contained page, its own <style>, no
#     shared markup or CSS classes with the one above.
#
#     Every REGISTERED check lands in exactly one of four states per category
#     (sast/sca/iac/dast/cloud): it found something, it ran and found
#     nothing, it did not run and the run says why, or it is unaccounted -
#     registered, not run, no reason recorded.  The fourth bucket is never
#     folded into "clean": doing so is exactly the overstated coverage
#     docs/DESIGN.md §15 forbids.  Captain decision: FULL not-covered detail
#     - every not-run check is listed by id with its reason, never a count
#     alone.
#
#     "Ran" now means the SAME thing in every category, per the companion
#     checks_run-semantics fix above (modules/sast/engine.sh's
#     sast_record_checks_run, called from modules/sast/run.sh and
#     modules/iac/run.sh right after their own tree walk returns): a check is
#     `run` only once something it applies to was actually inspected - a
#     check whose `files:` glob matched zero files this run is a declared
#     `coverage_reduction reason=no_matching_files checks=[...]`, never a
#     silent `checks_run` entry.  modules/dast/passive/headers.sh's own
#     `_HDRF_EVAL` established the identical contract earlier; this report
#     states the exact file:line predicate per category rather than trusting
#     the reader to already know it.
#
#     SCA ships no on-disk `*.rules` registry at all (a table lookup against
#     data/advisories.db, not a pattern engine - modules/sca/run.sh's own
#     header), so it has no true denominator; this report falls back to
#     "what ran" for it rather than ever claiming a coverage fraction it
#     cannot know - the identical fallback the design scout's prototype used.
# ---------------------------------------------------------------------------
declare -A _RPTC_CAT_LABEL=( [sast]='SAST' [sca]='SCA' [iac]='IaC' [dast]='DAST' [cloud]='Cloud / AWS' [network]='Network' [image]='Image' )
declare -A _RPTC_CAT_DESCR=(
  [sast]='Static analysis of source code - pattern rule packs over the scan root.'
  [sca]='Dependency composition analysis - lockfile parsing against the vendored advisory table.'
  [iac]='Infrastructure-as-code - pattern rule packs over Terraform, CloudFormation, Kubernetes, Helm, Docker.'
  [dast]='Dynamic analysis - live probes against an authorised target in config/scope.conf.'
  [cloud]='Live read-only AWS configuration review plus posture checks.'
  [network]='Service-posture scanning over the declared listener set config/scope.conf names for an authorised target - never a port sweep or host discovery.'
  [image]='Built container image scanning - offline installed-package enumeration and CVE matching against an operator-supplied docker-save tarball or OCI image layout; no registry pull.'
)
# The plain-English noun `_rptc_plain_summary` uses in place of the bare
# category label - "web checks" reads more naturally than "DAST checks" to a
# reader who does not already know what DAST stands for (scoursh-report-ux,
# the captain's own "Of 92 possible web checks ..." phrasing). Falls back to
# "<LABEL> checks" for any category added later without an entry here.
declare -A _RPTC_CAT_NOUN=(
  [sast]='code checks' [sca]='dependency checks' [iac]='infrastructure checks'
  [dast]='web checks' [cloud]='AWS checks' [network]='network checks'
  [image]='image checks'
)
# strong/medium/weak/none - the per-category semantic strength of "ran" this
# report states as a first-class field rather than a footnote.
# `cloud` moved from `none` to `strong` when modules/cloud/ landed
# (CLOUD-04, the dispatch entry point).  The field names the PREDICATE a category uses
# to decide a check was covered, not how many checks it currently has: cloud's
# predicate is now a real one - a check id reaches `checks_run` only after the
# `aws_ro` call it depends on returned an ANSWER (`ok` or `not_found`), never
# after a call that was denied, throttled or truncated, because
# lib/awscli.sh's `aws_ro_outcome_is_coverage_loss` separates those and a
# service script owes a coverage_reduction for each.  It was strong AND
# vacuous when this field was added (no service script shipped yet) and is
# strong AND populated now that all 30 services have landed - the strength
# describes the predicate a check uses, not how many checks currently exist,
# so the field did not need to change when the module filled in around it.
# The `Checks available` / `Checks run` columns beside it are computed from
# the registry rather than typed here.
# `network` (NET-04) was added the identical way CLOUD-04 added `cloud`, for
# the identical reason: the predicate is a fact about the MECHANISM
# (evaluated over a live listener, like DAST's), not about how many phase
# scripts existed at the time it was added - and the module's full phase set
# has since landed too.
declare -A _RPTC_RANSEM=( [sast]=strong [iac]=strong [sca]=medium [dast]=strong [cloud]=strong [network]=strong [image]=strong )
# SC2016: the backticks below are literal prose (code-span-style quoting of
# `run`/`files:`), not command substitution.
# shellcheck disable=SC2016
declare -A _RPTC_RANSEM_TEXT=(
  [sast]='Recorded AFTER the tree walk (sast_record_checks_run, modules/sast/engine.sh, called from modules/sast/run.sh once sast_scan_tree returns): a check is `run` only once its `files:` glob matched >=1 file in this tree and its pattern was actually evaluated against it. A check with zero matching files is a declared coverage_reduction, listed by id below, never a silent checks_run entry.'
  [iac]='Recorded AFTER the tree walk (the same sast_record_checks_run, called from modules/iac/run.sh once iac_scan_tree returns) - byte-identical predicate to SAST, since both share one engine.'
  [sca]='Recorded when at least one manifest of that ecosystem was located and walked (e.g. modules/sca/engine.sh), before its package loop. It ships no on-disk check registry, so this report cannot state a coverage fraction for it - only what ran.'
  [dast]='Recorded AFTER evaluation, gated on at least one response or request the check was applicable to actually happening (e.g. modules/dast/passive/headers.sh:_HDRF_EVAL). This is the category the other two were brought up to match.'
  [cloud]='Recorded AFTER the AWS call the check depends on returned an ANSWER - `ok` or `not_found` in lib/awscli.sh section 2s outcome vocabulary. A call that was denied, throttled, truncated or made against a region the account has not enabled is a declared coverage_reduction, listed below, never a silent checks_run entry: for a cloud scan an AccessDenied looks exactly like an account with nothing wrong in it, which is why this category classifies every failure rather than returning a status. modules/cloud/aws/live/ ships all 30 docs/DESIGN.md §8.1 services (docs/STEP6-CLOUD-PLAN.md CLOUD-05 through CLOUD-34); a --live run examines every enabled service in every enabled region and records any it could not examine as a coverage reduction rather than folding it into a clean pass. The posture/ phase (§8.7, POSTURE-02 through POSTURE-04) has not landed - only its config schema has - so it is a declared skip today.'
  [network]='Recorded AFTER evaluation, gated on at least one connection or response the check was applicable to actually happening - the identical predicate DAST uses, one transport layer down (a plain TCP connect via lib/nettransport.sh in place of an HTTP request). modules/network/ ships its full phase set (see AGENTS.md'"'"'s "Network module (NET)" section): three-state reachability verification, banner/HTTP service and version disclosure, TLS posture on non-web ports, and plaintext/STARTTLS transport posture, all gated by the same scope chokepoint and --i-own-target affirmation dast uses.'
  [image]='Recorded AFTER a package database found in an image layer was actually looked up against data/advisories.db - a table lookup, never a live probe. modules/image/ ships its full acquire -> enumerate -> compare pipeline for apk, dpkg and rpm packages (see AGENTS.md'"'"'s "Container image scanning (the IMAGE module)" section), plus language-dependency extraction and the config-blob checks; a run resolves the declared --image id and records anything it could not examine (e.g. a missing sqlite3 for rpm) as a coverage reduction rather than a clean pass.'
)

_rptc_prefix_grep() {
  # Emits the matching lines of FILE for CATEGORY's id prefix(es). `cloud`
  # is the one category with two (docs/DESIGN.md §13's CLOUD-*/POSTURE-*
  # split, both step-6 work) - kept as one egrep alternation rather than two
  # separate greps so a caller never has to know that.  `network` (NET-04) is
  # the one category whose SCAN_COMMANDS/_RPT_MODULES token does NOT equal
  # its own check-id prefix: rules/RULE-FORMAT.md §9.1.1 (NET-02) reserves
  # `NET-`, never `NETWORK-`, so the default `${cat^^}-` mapping every other
  # category relies on would silently match nothing for this one.
  local cat=$1 file=$2
  [[ -r $file ]] || return 0
  case $cat in
    cloud) grep -E '^(CLOUD-|POSTURE-)' "$file" 2>/dev/null || true ;;
    network) grep '^NET-' "$file" 2>/dev/null || true ;;
    *) grep "^${cat^^}-" "$file" 2>/dev/null || true ;;
  esac
}

# _report_coverage_registry_load - loads every module's on-disk check
# registry (title:/severity: only) into `_RPTC_TITLE`/`_RPTC_SEV`, keyed by
# check id, so a QUIET check can still say what it looks for (design
# decision 3 in the report design: "a category with zero findings still
# shows what it verified"). Reuses checks_registry_load (lib/checks.sh)
# rather than a second registry reader - it is the one function that already
# honours the frozen record format's multi-line prose fields and validates
# each file, exactly as scan.sh's own dispatch does.
#
# CHECKS_REGISTRY_SETS is a global `checks_registry_load` REPLACES on every
# call (its own header), so the caller's own in-flight set (the currently
# dispatching module's registry, mid-run) is saved and restored around this -
# report_all/report_audit run at the END of a module's own *_run_module
# function, after that module's own use of CHECKS_REGISTRY_SETS is done, but
# saving/restoring costs nothing and removes any dependency on that ordering
# staying true.
#
# Memoized on `SCOURSH_INSTALL_ROOT`: `scan.sh all` calls report_all once per
# module (five times in one process, per docs/DESIGN.md's own dispatch
# order), and every *.rules file's own registry content is fixed for the
# life of a process, so reloading and re-validating ~180 checks on every one
# of those five calls is pure waste - keyed on the install root rather than
# an unconditional once-per-process flag so a test suite that legitimately
# points `SCOURSH_INSTALL_ROOT` at a different fixture registry between
# cases (tests/suites/sast.sh's own ROOT_REAL_REGISTRY/ROOT_JS_REGISTRY
# pattern) still reloads when it should.
declare -g _RPTC_REGISTRY_LOADED_ROOT=''
_report_coverage_registry_load() {
  if [[ -n ${_RPTC_REGISTRY_LOADED_ROOT:-} && ${_RPTC_REGISTRY_LOADED_ROOT} == "${SCOURSH_INSTALL_ROOT:-}" ]]; then
    return 0
  fi
  local -a _rptc_saved_sets=("${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}")
  declare -gA _RPTC_TITLE=() _RPTC_SEV=()
  local m set n i id
  for m in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    checks_registry_load "$m" "_rptcreg_$m"
    for set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
      n=$(records_count "$set")
      for (( i = 0; i < n; i++ )); do
        id=$(records_id "$set" "$i")
        _RPTC_TITLE[$id]=$(records_field "$set" "$i" title)
        _RPTC_SEV[$id]=$(records_field "$set" "$i" severity)
      done
    done
  done
  CHECKS_REGISTRY_SETS=("${_rptc_saved_sets[@]+"${_rptc_saved_sets[@]}"}")
  _RPTC_REGISTRY_LOADED_ROOT=${SCOURSH_INSTALL_ROOT:-}
}

# _report_coverage_state RUNDIR - the per-category set arithmetic (design
# decision: pure set arithmetic over meta/, ported from the design scout's
# verified prototype). Populates every `_RPTC_*` array below; called once by
# report_audit before any rendering.
_report_coverage_state() {
  local rundir=$1
  declare -gA _RPTC_REG=() _RPTC_RAN=() _RPTC_FIRED=() _RPTC_CLEAN=() _RPTC_SKIP=() _RPTC_NOTRUN=() _RPTC_UNACC=() _RPTC_NAPP=()
  declare -gA _RPTC_RAN_SET=() _RPTC_FIRED_SET=() _RPTC_CLEAN_SET=() _RPTC_SKIP_ROWS=() _RPTC_NAPP_SET=() _RPTC_UNACC_SET=()
  declare -gA _RPTC_NAPP_REASON=() _RPTC_FIRED_LINES=() _RPTC_FIRED_COUNT=()
  # `_RPTC_FIRED[$c]` counts distinct CHECKS with a finding; `_RPTC_FIRED_FINDINGS[$c]`
  # counts the individual FINDINGS those checks produced - genuinely different
  # numbers whenever one check fires more than once (a CORS-wildcard check
  # flagging thirteen URLs is 1 check, 13 findings). Rendering only the first
  # of the two ("5 found") next to report.html's own per-finding count ("17")
  # for the identical category reads as a contradiction rather than two units
  # of the same honest fact - scoursh-report-ux keeps both numbers visible
  # everywhere this report states a "found" count.
  declare -gA _RPTC_FIRED_FINDINGS=()
  _RPTC_TOT_REG=0; _RPTC_TOT_RAN=0; _RPTC_TOT_FIRED=0; _RPTC_TOT_FIRED_FINDINGS=0
  _RPTC_TOT_CLEAN=0; _RPTC_TOT_SKIP=0; _RPTC_TOT_UNACC=0

  local t=$SCOURSH_SCRATCH/rpt-audit.$$
  rm -rf "$t"
  mkdir -p "$t"

  LC_ALL=C sort -u "$rundir/meta/checks_run" 2>/dev/null >"$t/ran" || : >"$t/ran"
  LC_ALL=C sort -u "$rundir/meta/checks_selected" 2>/dev/null >"$t/selected" || : >"$t/selected"
  # `check=<id> skipped_by=<reason>` (lib/checks.sh:353) - structured and
  # parseable, unlike coverage_reduction's own key=value-plus-prose shape
  # (§3.1's own "two format warnings" - never one parser for both).
  sed -n 's/^check=\([^ ]*\) skipped_by=\(.*\)$/\1\t\2/p' "$rundir/meta/skipped_checks" 2>/dev/null \
    | LC_ALL=C sort -u >"$t/skipped" || : >"$t/skipped"
  cut -f1 "$t/skipped" 2>/dev/null | LC_ALL=C sort -u >"$t/skipped_ids" || : >"$t/skipped_ids"

  # ids named inside a coverage_reduction's own `checks=[A B C]` list - the
  # "evaluated as not applicable to this target/tree" set. Every reduction
  # naming such a list is scanned (not only this fix's own `no_matching_files`
  # one), so a DAST `headers_check_not_applicable` reduction is picked up the
  # same way; the FIRST reduction naming a given id wins its reason, so a
  # reader always sees one concrete sentence rather than none.
  : >"$t/napp"
  if [[ -r $rundir/meta/coverage_reduction ]]; then
    local _crline _crmod _crreason _crids _crid
    while IFS= read -r _crline; do
      [[ -n $_crline ]] || continue
      _crids=$(sed -n 's/.*checks=\[\([^]]*\)\].*/\1/p' <<<"$_crline")
      [[ -n $_crids ]] || continue
      _crmod=$(sed -n 's/^module=\([^ ]*\).*/\1/p' <<<"$_crline")
      _crreason=$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' <<<"$_crline")
      for _crid in $_crids; do
        [[ -n $_crid ]] || continue
        printf '%s\n' "$_crid" >>"$t/napp"
        [[ -n ${_RPTC_NAPP_REASON[$_crid]:-} ]] \
          || _RPTC_NAPP_REASON[$_crid]="module=${_crmod:-?} reason=${_crreason:-?}"
      done
    done <"$rundir/meta/coverage_reduction"
  fi
  LC_ALL=C sort -u "$t/napp" -o "$t/napp"

  # Findings: read `findings.fields` through the real `finding_decode`
  # (lib/findings.sh) - never a re-parse of findings.jsonl. The design
  # scout's own first draft parsed JSON with a `sed` alternation BSD sed does
  # not support and silently produced empty evidence on every finding; the
  # sidecar format is TAB-separated key=value with defined escaping and is
  # what every other renderer in this file already consumes.
  : >"$t/fired"
  if [[ -s $rundir/findings.fields ]]; then
    local _fline _fid
    while IFS= read -r _fline; do
      [[ -n $_fline ]] || continue
      finding_decode "$_fline"
      _fid=${_DF[check_id]:-}
      [[ -n $_fid ]] || continue
      printf '%s\n' "$_fid" >>"$t/fired"
      _RPTC_FIRED_COUNT[$_fid]=$(( ${_RPTC_FIRED_COUNT[$_fid]:-0} + 1 ))
      if [[ -n ${_RPTC_FIRED_LINES[$_fid]:-} ]]; then
        _RPTC_FIRED_LINES[$_fid]+=$'\n'"$_fline"
      else
        _RPTC_FIRED_LINES[$_fid]=$_fline
      fi
    done <"$rundir/findings.fields"
  fi
  # A second, UN-deduped copy, taken before the sort -u below collapses
  # `$t/fired` to one line per check id: this one line-per-finding file is
  # what lets the per-category loop count individual findings separately
  # from distinct checks.
  cp "$t/fired" "$t/fired_raw"
  LC_ALL=C sort -u "$t/fired" -o "$t/fired"

  local c sel skp ran fired fired_findings napp reg clean notrun unacc regall acct
  for c in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    sel=$(_rptc_prefix_grep "$c" "$t/selected" | grep -c . || true); sel=${sel:-0}
    skp=$(_rptc_prefix_grep "$c" "$t/skipped_ids" | grep -c . || true); skp=${skp:-0}
    ran=$(_rptc_prefix_grep "$c" "$t/ran" | grep -c . || true); ran=${ran:-0}
    fired=$(_rptc_prefix_grep "$c" "$t/fired" | grep -c . || true); fired=${fired:-0}
    fired_findings=$(_rptc_prefix_grep "$c" "$t/fired_raw" | grep -c . || true); fired_findings=${fired_findings:-0}
    napp=$(_rptc_prefix_grep "$c" "$t/napp" | grep -c . || true); napp=${napp:-0}
    reg=$(( sel + skp ))
    # SCA has no on-disk registry (modules/sca/run.sh's own header): its
    # denominator is the set of ids its bash actually mints, so the row never
    # claims a coverage fraction it cannot know.
    (( reg == 0 && ran > 0 )) && reg=$ran
    clean=$(( ran - fired )); (( clean < 0 )) && clean=0
    # "not run, reason given" is BOTH buckets the category section below lists
    # in full detail - filtered-out-before-dispatch (skp) AND
    # evaluated-as-not-applicable (napp) - never skp alone: a check napp
    # explains is not unaccounted, and counting it as unaccounted here would
    # contradict the very row this report's own "Not run" table renders for
    # it two sections down.
    notrun=$(( skp + napp ))
    unacc=$(( reg - ran - notrun )); (( unacc < 0 )) && unacc=0
    _RPTC_REG[$c]=$reg; _RPTC_RAN[$c]=$ran; _RPTC_FIRED[$c]=$fired
    _RPTC_FIRED_FINDINGS[$c]=$fired_findings
    _RPTC_CLEAN[$c]=$clean; _RPTC_SKIP[$c]=$skp; _RPTC_NOTRUN[$c]=$notrun
    _RPTC_UNACC[$c]=$unacc; _RPTC_NAPP[$c]=$napp
    _RPTC_TOT_REG=$(( _RPTC_TOT_REG + reg )); _RPTC_TOT_RAN=$(( _RPTC_TOT_RAN + ran ))
    _RPTC_TOT_FIRED=$(( _RPTC_TOT_FIRED + fired ))
    _RPTC_TOT_FIRED_FINDINGS=$(( _RPTC_TOT_FIRED_FINDINGS + fired_findings ))
    _RPTC_TOT_CLEAN=$(( _RPTC_TOT_CLEAN + clean ))
    _RPTC_TOT_SKIP=$(( _RPTC_TOT_SKIP + notrun )); _RPTC_TOT_UNACC=$(( _RPTC_TOT_UNACC + unacc ))

    _RPTC_RAN_SET[$c]=$(_rptc_prefix_grep "$c" "$t/ran")
    _RPTC_FIRED_SET[$c]=$(_rptc_prefix_grep "$c" "$t/fired")
    _RPTC_SKIP_ROWS[$c]=$(_rptc_prefix_grep "$c" "$t/skipped")
    _RPTC_NAPP_SET[$c]=$(_rptc_prefix_grep "$c" "$t/napp")
    _RPTC_CLEAN_SET[$c]=$(comm -23 <(printf '%s\n' "${_RPTC_RAN_SET[$c]}" | grep . || true) \
                                    <(printf '%s\n' "${_RPTC_FIRED_SET[$c]}" | grep . || true) 2>/dev/null || true)

    regall=$(cat <(_rptc_prefix_grep "$c" "$t/selected") <(_rptc_prefix_grep "$c" "$t/skipped_ids") \
              | grep . | LC_ALL=C sort -u || true)
    acct=$(cat <(printf '%s\n' "${_RPTC_RAN_SET[$c]}") <(_rptc_prefix_grep "$c" "$t/skipped_ids") \
               <(printf '%s\n' "${_RPTC_NAPP_SET[$c]}") | grep . | LC_ALL=C sort -u || true)
    _RPTC_UNACC_SET[$c]=$(comm -23 <(printf '%s\n' "$regall" | grep . || true) \
                                    <(printf '%s\n' "$acct" | grep . || true) 2>/dev/null || true)
  done

  rm -rf "$t"
}

# Highest severity actually OBSERVED across a check's own findings, never the
# registry's declared `severity:` - the two legitimately differ (the rubric,
# lib/findings.sh §8, adjusts base severity per finding) and a group header
# showing `low` above a `medium` finding reads as a rendering bug (design
# decision 4).
_rptc_group_severity() {
  local id=$1 line sev best=info
  local -A rank=( [critical]=5 [high]=4 [medium]=3 [low]=2 [info]=1 )
  [[ -n ${_RPTC_FIRED_LINES[$id]:-} ]] || { printf '%s' info; return 0; }
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    sev=${_DF[severity]:-info}
    if (( ${rank[$sev]:-0} > ${rank[$best]:-0} )); then
      best=$sev
    fi
  done <<<"${_RPTC_FIRED_LINES[$id]}"
  printf '%s' "$best"
}

# `_rptc_plain_summary CATEGORY` - a genuinely plain-English, one-line reading
# of the same integers the coverage matrix (`_html_audit_summary`) renders
# per category - the captain's own worked example ("Of 92 possible web
# checks, 34 ran (5 found problems, 29 clean), 10 were skipped with a reason,
# and 48 were not covered - don't assume those are fine."). Reads only the
# `_RPTC_*` counts `_report_coverage_state` already computed - no new facts,
# so this can never say something the matrix does not already say, only say
# it in words a non-expert can follow without first learning what "reg" or
# "unacc" mean. Deliberately generated rather than hand-written per category,
# so it reads correctly regardless of how the real counts split (a parallel
# investigation may later shrink DAST's own 48 - this function makes no
# assumption about which bucket is large).
_rptc_plain_summary() {
  local c=$1 noun reg ran fired fired_findings clean notrun unacc out
  noun=${_RPTC_CAT_NOUN[$c]:-${_RPTC_CAT_LABEL[$c]:-$c} checks}
  reg=${_RPTC_REG[$c]:-0}; ran=${_RPTC_RAN[$c]:-0}; fired=${_RPTC_FIRED[$c]:-0}
  fired_findings=${_RPTC_FIRED_FINDINGS[$c]:-0}
  clean=${_RPTC_CLEAN[$c]:-0}; notrun=${_RPTC_NOTRUN[$c]:-0}; unacc=${_RPTC_UNACC[$c]:-0}
  out="Of $reg possible $noun, $ran ran"
  # `$fired` (distinct checks with a finding) and `$fired_findings` (the
  # individual findings those checks produced) are genuinely different
  # numbers whenever one check fires more than once - state both, always,
  # rather than only when they happen to differ: a reader should never have
  # to wonder which number a bare "N found problems" was.
  (( ran > 0 )) && out+=" ($fired check(s) found $fired_findings issue(s), $clean clean)"
  local -a clauses=()
  (( notrun > 0 )) && clauses+=("$notrun were skipped with a reason")
  (( unacc > 0 )) && clauses+=("$unacc were not covered - don't assume those are fine")
  local n=${#clauses[@]} j
  for (( j = 0; j < n; j++ )); do
    if (( j == n - 1 && n > 1 )); then
      out+=", and ${clauses[j]}"
    else
      out+=", ${clauses[j]}"
    fi
  done
  out+='.'
  printf '%s' "$out"
}

_html_audit_head() {
  cat <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>scoursh coverage &amp; assurance report</title>
<style>
:root{
  color-scheme: light dark;
  --bg:#fbfbfc; --fg:#16181d; --muted:#5b6270; --faint:#868d9b; --line:#dce0e7;
  --card:#fff; --card2:#f4f6f9; --accent:#274b8f; --accent-bg:#eaf0fb;
  --critical:#8a1220; --high:#a44608; --medium:#8a6d09; --low:#35566f; --info:#5b6270;
  --pass:#1f6b45; --pass-bg:#e6f4ec;
  --skip:#8a6d09; --skip-bg:#fbf3dc;
  --gap:#6b4fa8; --gap-bg:#efe9fa;
  --unk:#767d8b;
  --radius:.55rem;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#111318; --fg:#e6e8ec; --muted:#9aa2b1; --faint:#79808e; --line:#2b3038;
    --card:#191c22; --card2:#1f232a; --accent:#8fb0ee; --accent-bg:#1b2434;
    --critical:#ff8b98; --high:#ffb27a; --medium:#ecd07a; --low:#a8c8dd; --info:#9aa2b1;
    --pass:#6bd6a0; --pass-bg:#16281f;
    --skip:#ecd07a; --skip-bg:#2a2517;
    --gap:#c0a8f0; --gap-bg:#221c33;
    --unk:#8a919f;
  }
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-text-size-adjust:100%}
main{max-width:74rem;margin:0 auto;padding:0 1.25rem 5rem}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
a{color:var(--accent)}
h1{font-size:1.5rem;margin:0 0 .3rem;letter-spacing:-.015em}
h2{font-size:1rem;margin:0 0 1rem;text-transform:uppercase;letter-spacing:.08em;
   color:var(--muted);font-weight:650}
h3{font-size:.95rem;margin:1.6rem 0 .6rem;font-weight:650}
p{margin:.5rem 0}
.sub{color:var(--muted);font-size:.88rem;margin:0}
.topbar{position:sticky;top:0;z-index:50;background:var(--bg);
  border-bottom:1px solid var(--line);padding:.55rem 0;margin-bottom:1.5rem}
.topbar .in{max-width:74rem;margin:0 auto;padding:0 1.25rem;
  display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}
.brand{font-weight:700;letter-spacing:-.01em;margin-right:.5rem;white-space:nowrap}
.pill{display:inline-flex;align-items:center;gap:.4rem;text-decoration:none;
  border:1px solid var(--line);background:var(--card);border-radius:2rem;
  padding:.2rem .65rem;font-size:.8rem;color:var(--fg);white-space:nowrap}
.pill:hover{border-color:var(--accent);background:var(--accent-bg)}
.pill .c{font-variant-numeric:tabular-nums;color:var(--muted);font-size:.75rem}
.pill.off{opacity:.5}
.masthead{padding:1.5rem 0 .5rem}
.runmeta{display:flex;flex-wrap:wrap;gap:.35rem .5rem;margin:.9rem 0 0}
.kv{background:var(--card2);border:1px solid var(--line);border-radius:.35rem;
  padding:.18rem .5rem;font-size:.78rem;color:var(--muted)}
.kv b{color:var(--fg);font-weight:600;font-family:ui-monospace,Menlo,monospace}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:1.1rem 1.2rem;margin:1.5rem 0}
.note{border-left:3px solid var(--accent);background:var(--accent-bg);
  border-radius:.35rem;padding:.7rem .9rem;font-size:.87rem;margin:.9rem 0}
.warn{border-left:3px solid var(--high);background:var(--card2);
  border-radius:.35rem;padding:.7rem .9rem;font-size:.87rem;margin:.9rem 0}
/* scoursh-report-ux: plain-language column headers (hover for the fuller
   definition) and the generated one-line-per-category summary. */
abbr[title]{text-decoration:underline dotted;-webkit-text-decoration-style:dotted;
  text-underline-offset:.15em;cursor:help}
ul.plain{margin:.6rem 0 0;padding-left:1.2rem}
ul.plain li{margin:.5rem 0;font-size:.88rem}
.plainline{color:var(--fg);font-size:.92rem;background:var(--card2);
  border-radius:.4rem;padding:.55rem .8rem;margin:.7rem 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));gap:.65rem}
.tile{border:1px solid var(--line);border-radius:.45rem;padding:.7rem .8rem;background:var(--card2)}
.tile .n{font-size:1.65rem;font-weight:680;line-height:1.05;font-variant-numeric:tabular-nums}
.tile .l{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:.15rem}
.tile .tilesub{font-size:.7rem;color:var(--muted);margin-top:.3rem}
.tile.crit .n{color:var(--critical)} .tile.pass .n{color:var(--pass)}
.tile.skip .n{color:var(--skip)} .tile.gap .n{color:var(--gap)}
.matrix{width:100%;border-collapse:collapse;font-size:.87rem}
.matrix th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);font-weight:650;padding:.5rem .7rem;border-bottom:1px solid var(--line)}
.matrix td{padding:.6rem .7rem;border-bottom:1px solid var(--line);vertical-align:middle}
.matrix tr:last-child td{border-bottom:none}
.matrix td.num{font-variant-numeric:tabular-nums;text-align:right;min-width:3.5rem}
.cellnum{display:block}
.cellsub{display:block;font-size:.68rem;font-weight:400;color:var(--muted);white-space:nowrap}
.matrix a.cat{font-weight:650;text-decoration:none}
.bar{display:flex;height:.85rem;border-radius:.2rem;overflow:hidden;
  background:var(--card2);border:1px solid var(--line);min-width:9rem}
.bar span{display:block}
.bar .b-fired{background:var(--critical)}
.bar .b-clean{background:var(--pass)}
.bar .b-skip{background:var(--skip)}
.bar .b-unacc{background:repeating-linear-gradient(45deg,var(--unk),var(--unk) 3px,transparent 3px,transparent 6px);
  border-left:1px solid var(--unk)}
.legend{display:flex;flex-wrap:wrap;gap:.3rem .9rem;font-size:.76rem;color:var(--muted);margin-top:.8rem}
.legend i{display:inline-block;width:.65rem;height:.65rem;border-radius:.15rem;margin-right:.3rem;vertical-align:-1px}
.legend .l-fired i{background:var(--critical)} .legend .l-clean i{background:var(--pass)}
.legend .l-skip i{background:var(--skip)}
.legend .l-unacc i{background:repeating-linear-gradient(45deg,var(--unk),var(--unk) 2px,transparent 2px,transparent 4px);border:1px solid var(--unk)}
.strength{display:inline-block;font-size:.66rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.06em;padding:.1rem .4rem;border-radius:.25rem;border:1px solid currentColor}
.strength.strong{color:var(--pass)} .strength.medium{color:var(--medium)}
.strength.weak{color:var(--high)} .strength.none{color:var(--muted)}
.cat{margin:3rem 0 0;scroll-margin-top:4rem}
.cat > header{border-bottom:2px solid var(--line);padding-bottom:.7rem;margin-bottom:1rem}
.cat h2{font-size:1.15rem;text-transform:none;letter-spacing:-.01em;color:var(--fg);margin:0}
.cat .desc{color:var(--muted);font-size:.87rem;margin:.3rem 0 0}
.notbuilt{color:var(--muted);font-style:italic}
details.grp{border:1px solid var(--line);border-radius:.45rem;margin:.6rem 0;background:var(--card)}
details.grp > summary{cursor:pointer;padding:.6rem .85rem;list-style:none;
  display:flex;align-items:center;gap:.5rem;font-size:.9rem}
details.grp > summary::-webkit-details-marker{display:none}
details.grp > summary::before{content:"\25B8";color:var(--muted);font-size:.75rem;
  transition:transform .12s ease;display:inline-block}
details.grp[open] > summary::before{transform:rotate(90deg)}
details.grp > summary:hover{background:var(--card2)}
details.grp .inner{padding:.2rem .85rem .85rem;border-top:1px solid var(--line)}
.count{margin-left:auto;font-variant-numeric:tabular-nums;color:var(--muted);font-size:.8rem}
.tag{font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:.1rem .4rem;border-radius:.25rem}
.tag.pass{color:var(--pass);background:var(--pass-bg)}
.tag.fired{color:var(--critical);background:var(--card2)}
.tag.skip{color:var(--skip);background:var(--skip-bg)}
.tag.gap{color:var(--gap);background:var(--gap-bg)}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table.checks{width:100%;border-collapse:collapse;font-size:.84rem;min-width:34rem}
table.checks th{text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);font-weight:650;padding:.4rem .6rem .4rem 0;border-bottom:1px solid var(--line)}
table.checks td{padding:.35rem .6rem .35rem 0;border-bottom:1px solid var(--line);vertical-align:top}
table.checks tr:last-child td{border-bottom:none}
table.checks td.id{font-family:ui-monospace,Menlo,monospace;font-size:.79rem;white-space:nowrap}
table.checks td.why{color:var(--muted);font-size:.8rem}
details.chk{border-bottom:1px solid var(--line);margin:0}
details.chk:last-child{border-bottom:none}
details.chk > summary{cursor:pointer;padding:.5rem .2rem;list-style:none;
  display:flex;align-items:center;gap:.5rem;font-size:.86rem;flex-wrap:wrap}
details.chk > summary::-webkit-details-marker{display:none}
details.chk > summary::before{content:"\25B8";color:var(--muted);font-size:.7rem;
  transition:transform .12s ease;display:inline-block;flex:0 0 auto}
details.chk[open] > summary::before{transform:rotate(90deg)}
details.chk > summary:hover{background:var(--card2)}
details.chk > summary code{font-weight:650}
.chkbody{padding:.1rem 0 .7rem 1.1rem}
details.f{border:1px solid var(--line);border-left-width:3px;border-radius:.4rem;
  margin:.45rem 0;background:var(--card)}
details.f > summary{cursor:pointer;padding:.55rem .8rem;list-style:none}
details.f > summary::-webkit-details-marker{display:none}
details.f[data-sev="critical"]{border-left-color:var(--critical)}
details.f[data-sev="high"]{border-left-color:var(--high)}
details.f[data-sev="medium"]{border-left-color:var(--medium)}
details.f[data-sev="low"]{border-left-color:var(--low)}
details.f[data-sev="info"]{border-left-color:var(--info)}
.sev{font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  padding:.1rem .4rem;border:1px solid currentColor;border-radius:.25rem}
.sev.critical{color:var(--critical)} .sev.high{color:var(--high)}
.sev.medium{color:var(--medium)} .sev.low{color:var(--low)} .sev.info{color:var(--info)}
.loc{color:var(--muted);font-family:ui-monospace,Menlo,monospace;font-size:.76rem;
  margin-left:.4rem;word-break:break-all}
.fbody{padding:0 .8rem .8rem;border-top:1px solid var(--line)}
.meta{color:var(--muted);font-size:.8rem;margin:.5rem 0;word-break:break-word}
pre.ev{background:var(--bg);border:1px solid var(--line);border-radius:.3rem;
  padding:.55rem .65rem;overflow-x:auto;margin:.5rem 0;white-space:pre-wrap;word-break:break-word;
  font-size:.79rem;max-height:22rem}
ul.prose{margin:.4rem 0;padding-left:1.1rem}
ul.prose li{margin:.35rem 0;font-size:.85rem;color:var(--fg)}
ul.prose li .why{color:var(--muted)}
.reason{font-family:ui-monospace,Menlo,monospace;font-size:.78rem;color:var(--gap)}
.filter{display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin:.9rem 0 0}
.filter .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
  font-weight:650;margin-right:.2rem}
.filter input{position:absolute;opacity:0;width:0;height:0}
.filter label{border:1px solid var(--line);background:var(--card);border-radius:2rem;
  padding:.18rem .6rem;font-size:.78rem;cursor:pointer;user-select:none}
.filter label:hover{border-color:var(--accent)}
#sv-all:checked   ~ .filter label[for="sv-all"],
#sv-crit:checked  ~ .filter label[for="sv-crit"],
#sv-high:checked  ~ .filter label[for="sv-high"],
#sv-med:checked   ~ .filter label[for="sv-med"],
#sv-low:checked   ~ .filter label[for="sv-low"]{
  background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
@media (prefers-color-scheme: dark){
  #sv-all:checked ~ .filter label[for="sv-all"],
  #sv-crit:checked ~ .filter label[for="sv-crit"],
  #sv-high:checked ~ .filter label[for="sv-high"],
  #sv-med:checked ~ .filter label[for="sv-med"],
  #sv-low:checked ~ .filter label[for="sv-low"]{color:#111318}
}
body:has(#sv-crit:checked) details.f:not([data-sev="critical"]),
body:has(#sv-high:checked) details.f:not([data-sev="critical"]):not([data-sev="high"]),
body:has(#sv-med:checked)  details.f:not([data-sev="critical"]):not([data-sev="high"]):not([data-sev="medium"]),
body:has(#sv-low:checked)  details.f[data-sev="info"]{display:none}
.filterhint{font-size:.74rem;color:var(--faint);margin-left:.4rem}
footer{margin-top:3.5rem;padding-top:1rem;border-top:1px solid var(--line);
  color:var(--muted);font-size:.8rem}
@media print{
  .topbar,.filter{display:none}
  details.grp,details.f{break-inside:avoid}
  details.grp[open] .inner,details.f .fbody{display:block}
  body{background:#fff}
}
</style>
</head>
<body>
HTML
  printf '<input type="radio" name="sv" id="sv-all" class="fsv" checked>\n'
  printf '<input type="radio" name="sv" id="sv-crit" class="fsv">\n'
  printf '<input type="radio" name="sv" id="sv-high" class="fsv">\n'
  printf '<input type="radio" name="sv" id="sv-med" class="fsv">\n'
  printf '<input type="radio" name="sv" id="sv-low" class="fsv">\n'
}

_html_audit_nav() {
  local c ran fired off
  printf '<div class="topbar"><div class="in"><span class="brand">scoursh</span>\n'
  printf '<a class="pill" href="#summary">Summary</a>\n'
  for c in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    ran=${_RPTC_RAN[$c]:-0}
    fired=${_RPTC_FIRED[$c]:-0}
    off=''; [[ $ran == 0 && $fired == 0 ]] && off=' off'
    printf '<a class="pill%s" href="#cat-%s">%s <span class="c">%s ran &middot; %s found</span></a>\n' \
      "$off" "$c" "$(html_escape "${_RPTC_CAT_LABEL[$c]}")" "$ran" "$fired"
  done
  printf '<a class="pill" href="#limitations">Limitations</a>\n'
  printf '</div></div>\n<main>\n'
}

_html_audit_summary() {
  local rundir=$1
  local run_id started command targets path_root toolv duration intensity authed
  # `${SCOURSH_RUN_ID:-...}`, never a bare `basename "$rundir"`: report_md
  # and report_html already read the identity this way (lib/report.sh
  # above), and the two agree with the directory's own basename only
  # because run_init sets SCOURSH_RUN_ID from it by default. `report --from`
  # (report_regenerate_from) re-exports the ORIGINAL run's own id into a
  # DIFFERENT output directory (its own fresh --out basename), which a bare
  # basename read here would silently show instead - the one place this
  # report disagreed with report.md/report.html about whose run it was
  # describing.
  run_id=${SCOURSH_RUN_ID:-$(basename "$rundir")}
  started=$(_meta_first "$rundir" started_at)
  # `command=$SCAN_COMMAND` (scan.sh's own `run_record notes`) is one line
  # among possibly several in meta/notes; sed on a possibly-absent file can
  # exit non-zero, and under this file's own `set -Eeuo pipefail` an
  # unguarded `var=$(cmd)` assignment aborts the whole report on that alone
  # (AGENTS.md's own "measured, not assumed" rule) - `|| true` is required,
  # not decorative.
  command=$( { sed -n 's/^command=//p' "$rundir/meta/notes" 2>/dev/null || true; } | head -n1 || true)
  targets=$(LC_ALL=C sort -u "$rundir/meta/targets" 2>/dev/null | paste -sd', ' - || true)
  # path_root is a run PARAMETER (SCOURSH_PATH_ROOT), never a meta/ fact -
  # report_run_json's own "path_root" JSON field reads the identical
  # variable (lib/report.sh above) rather than a file, for the same reason.
  path_root=${SCOURSH_PATH_ROOT:-}
  toolv=$(scoursh_version)
  # duration_seconds is likewise computed at report_run_json emission time,
  # never stored as a meta/ fact - best-effort read of a run.json this
  # process may have already written (report_all calls report_audit before
  # report_run_json, so on this run's FIRST report_all call there is no
  # run.json yet and this is correctly empty).
  duration=$(sed -n 's/.*"duration_seconds": *\([0-9]*\).*/\1/p' "$rundir/run.json" 2>/dev/null | head -n1 || true)
  intensity=$(_meta_first "$rundir" authorization_intensity)
  authed=$(_meta_first "$rundir" authorization_authed)

  printf '<div class="masthead">\n<h1>Coverage &amp; assurance report</h1>\n'
  printf '<p class="sub">What this scan checked, what it verified clean, and what it did not look at.</p>\n'
  printf '<div class="runmeta">\n'
  printf '<span class="kv">run <b>%s</b></span>\n' "$(html_escape "$run_id")"
  [[ -n $command ]] && printf '<span class="kv">command <b>%s</b></span>\n' "$(html_escape "$command")"
  [[ -n $path_root ]] && printf '<span class="kv">scan root <b>%s</b></span>\n' "$(html_escape "$path_root")"
  [[ -n $targets ]] && printf '<span class="kv">target <b>%s</b></span>\n' "$(html_escape "$targets")"
  [[ -n $intensity ]] && printf '<span class="kv">intensity <b>%s</b></span>\n' "$(html_escape "$intensity")"
  [[ -n $authed ]] && printf '<span class="kv">authenticated <b>%s</b></span>\n' "$(html_escape "$authed")"
  [[ -n $duration ]] && printf '<span class="kv">duration <b>%ss</b></span>\n' "$(html_escape "$duration")"
  printf '<span class="kv">tool <b>%s</b></span>\n' "$(html_escape "$toolv")"
  printf '</div>\n</div>\n'

  local nfind ngap nred
  nfind=$(wc -l <"$rundir/findings.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
  ngap=$(grep -c . "$rundir/meta/coverage_gap" 2>/dev/null || true); ngap=${ngap:-0}
  nred=$(grep -c . "$rundir/meta/coverage_reduction" 2>/dev/null || true); nred=${nred:-0}

  printf '<section id="summary" class="panel">\n<h2>Assurance summary</h2>\n<div class="tiles">\n'
  printf '<div class="tile"><div class="n">%s</div><div class="l">checks registered</div></div>\n' "$_RPTC_TOT_REG"
  printf '<div class="tile"><div class="n">%s</div><div class="l">checks ran</div></div>\n' "$_RPTC_TOT_RAN"
  printf '<div class="tile pass"><div class="n">%s</div><div class="l">ran, nothing found</div></div>\n' "$_RPTC_TOT_CLEAN"
  # Two numbers, deliberately: `$_RPTC_TOT_FIRED` distinct checks-with-a-
  # finding, `$_RPTC_TOT_FIRED_FINDINGS` the individual findings behind them
  # (one check firing on many locations makes these genuinely different -
  # see `_RPTC_FIRED_FINDINGS`'s own comment in `_report_coverage_state`).
  # report.html's own tally ("$nfind findings", below) is the second number,
  # never the first - showing only the check count here made the two reports
  # read as disagreeing about the same run.
  printf '<div class="tile crit"><div class="n">%s</div><div class="l">checks with findings</div><div class="tilesub">%s individual finding(s)</div></div>\n' \
    "$_RPTC_TOT_FIRED" "$_RPTC_TOT_FIRED_FINDINGS"
  printf '<div class="tile skip"><div class="n">%s</div><div class="l">not run (reason given)</div></div>\n' "$_RPTC_TOT_SKIP"
  printf '<div class="tile gap"><div class="n">%s</div><div class="l">unaccounted</div></div>\n' "$_RPTC_TOT_UNACC"
  printf '</div>\n'

  printf '<div class="note"><strong>How to read this.</strong> Every check lands in exactly one of four buckets per category: it <em>found a problem</em>, it <em>ran and came back clean</em>, it <em>was skipped with a reason on record</em>, or it is <em>not covered</em> - registered, but never run, with no reason given. That last bucket is never folded into "clean": doing so would be exactly the overstated coverage <code>docs/DESIGN.md</code> &sect;15 forbids. Hover any column heading below for what it counts, or read the plain-English line under each category.</div>\n'

  printf '<h3>Coverage by category</h3>\n<div class="scroll">\n'
  printf '<table class="matrix"><tr><th>Category</th><th>Coverage</th>'
  printf '<th class="num"><abbr title="How many checks are registered for this category">Checks available</abbr></th>'
  printf '<th class="num"><abbr title="Checks that were actually run this scan">Checks run</abbr></th>'
  printf '<th class="num"><abbr title="Checks that ran and found at least one issue. The smaller number under it is how many individual findings those checks produced - one check can fire on many locations, e.g. a CORS check flagging 13 different URLs">Found problems</abbr></th>'
  printf '<th class="num"><abbr title="Checks that ran and found nothing">Ran, all clear</abbr></th>'
  printf '<th class="num"><abbr title="Checks that did not run this scan, with a documented reason why">Skipped (reason given)</abbr></th>'
  printf '<th class="num"><abbr title="Registered but not run, and no reason was recorded for it - do not assume these are fine">Not covered</abbr></th>'
  printf '<th><abbr title="How strictly this category defines &quot;ran&quot; - see that category&#39;s own section below">Coverage strength</abbr></th></tr>\n'
  local c reg ran fired fired_findings clean notrun unacc
  for c in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    reg=${_RPTC_REG[$c]:-0}; ran=${_RPTC_RAN[$c]:-0}; fired=${_RPTC_FIRED[$c]:-0}
    fired_findings=${_RPTC_FIRED_FINDINGS[$c]:-0}
    clean=${_RPTC_CLEAN[$c]:-0}; notrun=${_RPTC_NOTRUN[$c]:-0}; unacc=${_RPTC_UNACC[$c]:-0}
    printf '<tr><td><a class="cat" href="#cat-%s">%s</a></td><td>' "$c" "$(html_escape "${_RPTC_CAT_LABEL[$c]}")"
    if (( reg > 0 )); then
      printf '<div class="bar">'
      local pair cls n
      for pair in "b-fired:$fired" "b-clean:$clean" "b-skip:$notrun" "b-unacc:$unacc"; do
        cls=${pair%%:*}; n=${pair#*:}
        (( n > 0 )) && printf '<span class="%s" style="flex:%s"></span>' "$cls" "$n"
      done
      printf '</div>'
    else
      printf '<span class="notbuilt">not built</span>'
    fi
    printf '</td><td class="num">%s</td>' "$reg"
    printf '<td class="num">%s</td>' "$ran"
    # Two numbers, always, never one alone: `$fired` distinct checks versus
    # `$fired_findings` individual findings - collapsing this to a single
    # bare number is exactly what read as a contradiction against
    # report.html's own per-finding counts for the same category.
    printf '<td class="num"><span class="cellnum">%s</span><span class="cellsub">%s issue(s)</span></td>' \
      "$fired" "$fired_findings"
    printf '<td class="num">%s</td>' "$clean"
    printf '<td class="num">%s</td>' "$notrun"
    printf '<td class="num">%s</td>' "$unacc"
    printf '<td><span class="strength %s">%s</span></td></tr>\n' \
      "${_RPTC_RANSEM[$c]}" "$(html_escape "${_RPTC_RANSEM[$c]}")"
  done
  printf '</table>\n</div>\n'
  printf '<div class="legend"><span class="l-fired"><i></i>found issues</span><span class="l-clean"><i></i>ran, nothing found</span><span class="l-skip"><i></i>not run, reason recorded</span><span class="l-unacc"><i></i>unaccounted</span></div>\n'
  printf '<div class="warn"><strong>&ldquo;Ran&rdquo; is not one thing.</strong> The strength column above is load-bearing: it names the exact predicate this run used to decide a check was covered. Treat a weak- or medium-strength clean count with the caveat printed in that category&rsquo;s own section below.</div>\n'

  printf '<h3>In plain terms</h3>\n<ul class="plain">\n'
  local any_plain=0
  for c in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
    (( ${_RPTC_REG[$c]:-0} > 0 )) || continue
    any_plain=1
    printf '<li><strong>%s:</strong> %s</li>\n' \
      "$(html_escape "${_RPTC_CAT_LABEL[$c]}")" "$(html_escape "$(_rptc_plain_summary "$c")")"
  done
  (( any_plain )) || printf '<li class="sub">No category in this run has anything registered yet.</li>\n'
  printf '</ul>\n'

  printf '<h3>Findings and declared limits</h3>\n<div class="tiles">\n'
  printf '<div class="tile crit"><div class="n">%s</div><div class="l"><abbr title="Every individual finding across every category - not the number of distinct checks that fired">findings</abbr></div></div>\n' "$nfind"
  printf '<div class="tile gap"><div class="n">%s</div><div class="l">coverage gaps</div></div>\n' "$ngap"
  printf '<div class="tile skip"><div class="n">%s</div><div class="l">declared reductions</div></div>\n' "$nred"
  printf '</div>\n</section>\n'

  printf '<div class="filter"><span class="lbl">Severity filter</span>'
  printf '<label for="sv-all">All</label><label for="sv-crit">Critical</label>'
  printf '<label for="sv-high">High+</label><label for="sv-med">Medium+</label><label for="sv-low">Low+</label>'
  printf '<span class="filterhint">applies to every finding below &mdash; no JavaScript</span></div>\n'
}

# One finding, in the shape §4.4 (XSS-safe escaping) requires: every
# interpolated value is target-derived and goes through html_escape into a
# text node only; `data-sev` takes only this tool's own closed severity
# vocabulary. Reuses `_location_summary` (already defined above) rather than
# a second location renderer.
_html_audit_one_finding() {
  local line=$1
  finding_decode "$line"
  local sev=${_DF[severity]:-info} loc
  loc=$(_location_summary)
  printf '<details class="f" data-sev="%s"><summary><span class="sev %s">%s</span> <strong>%s</strong> &mdash; %s<span class="loc">%s</span></summary>\n' \
    "$(html_escape "$sev")" "$(html_escape "$sev")" "$(html_escape "$sev")" \
    "$(html_escape "${_DF[check_id]:-}")" "$(html_escape "${_DF[title]:-}")" \
    "$(html_escape "$loc")"
  printf '<div class="fbody">\n'
  printf '<p class="meta">%s &middot; %s &middot; confidence %s &middot; status %s &middot; CVSS %s</p>\n' \
    "$(html_escape "${_DF[cwe]:-none}")" "$(html_escape "${_DF[owasp]:-none}")" \
    "$(html_escape "${_DF[confidence]:-medium}")" "$(html_escape "${_DF[status]:-new}")" \
    "$(html_escape "${_DF[_cvss_score]:-—}")"
  [[ -n ${_DF[evidence]:-} ]] && printf '<pre class="ev">%s</pre>\n' "$(html_escape "${_DF[evidence]}")"
  [[ -n ${_DF[remediation]:-} ]] && printf '<p class="meta">%s</p>\n' "$(html_escape "${_DF[remediation]}")"
  printf '<p class="meta">fingerprint <code>%s</code></p>\n' "$(html_escape "${_DF[fingerprint]:-}")"
  printf '</div></details>\n'
}

_html_audit_category() {
  local rundir=$1 c=$2
  local p_reg=${_RPTC_REG[$c]:-0} p_ran=${_RPTC_RAN[$c]:-0}
  printf '<section class="cat" id="cat-%s">\n<header>\n' "$c"
  printf '<h2>%s</h2>\n<p class="desc">%s</p>\n</header>\n' \
    "$(html_escape "${_RPTC_CAT_LABEL[$c]}")" "$(html_escape "${_RPTC_CAT_DESCR[$c]}")"

  if (( p_reg == 0 && p_ran == 0 )); then
    printf '<div class="warn"><strong>This category did not run.</strong> '
    local red abort_reason
    red=$(grep "module=$c " "$rundir/meta/coverage_reduction" 2>/dev/null || true)
    abort_reason=$(_run_abort_reason "$rundir")
    if [[ -n $red ]]; then
      printf 'The run recorded:</div>\n<ul class="prose">\n'
      while IFS= read -r l; do [[ -n $l ]] && printf '<li>%s</li>\n' "$(html_escape "$l")"; done <<<"$red"
      printf '</ul>\n'
    elif [[ -n $abort_reason ]]; then
      # HONESTY FIX (record-abort-reason): a module with no coverage_reduction
      # of its own most often means the run terminated (lib/core.sh die())
      # before it was ever dispatched, not that nothing is known - state the
      # captured reason rather than the uninformative "no coverage recorded".
      printf 'The run aborted before it could be dispatched: %s</div>\n' "$(html_escape "$abort_reason")"
    else
      printf 'No coverage was recorded for it.</div>\n'
    fi
    printf '</section>\n'
    return 0
  fi

  printf '<p class="plainline">%s</p>\n' "$(html_escape "$(_rptc_plain_summary "$c")")"

  printf '<div class="note"><span class="strength %s">%s</span> &nbsp;<strong>What &ldquo;ran&rdquo; means here:</strong> %s</div>\n' \
    "${_RPTC_RANSEM[$c]}" "$(html_escape "${_RPTC_RANSEM[$c]}")" "$(html_escape "${_RPTC_RANSEM_TEXT[$c]}")"

  # -- 1. Found issues, grouped by check --
  local fired_ids n id nf openattr gsev
  fired_ids=${_RPTC_FIRED_SET[$c]}
  n=$(printf '%s\n' "$fired_ids" | grep -c . || true); [[ -z $fired_ids ]] && n=0
  printf '<details class="grp" open><summary><span class="tag fired">Found issues</span> Checks that reported a finding<span class="count">%s check(s)</span></summary><div class="inner">\n' "$n"
  if (( n > 0 )); then
    while IFS= read -r id; do
      [[ -n $id ]] || continue
      nf=${_RPTC_FIRED_COUNT[$id]:-0}
      openattr=''; (( nf <= 3 )) && openattr=' open'
      gsev=$(_rptc_group_severity "$id")
      printf '<details class="chk"%s><summary><span class="sev %s">%s</span> <code>%s</code> &mdash; %s<span class="count">%s finding(s)</span></summary><div class="chkbody">\n' \
        "$openattr" "$(html_escape "$gsev")" "$(html_escape "$gsev")" \
        "$(html_escape "$id")" "$(html_escape "${_RPTC_TITLE[$id]:-—}")" "$nf"
      while IFS= read -r fl; do
        [[ -n $fl ]] && _html_audit_one_finding "$fl"
      done <<<"${_RPTC_FIRED_LINES[$id]:-}"
      printf '</div></details>\n'
    done <<<"$fired_ids"
  else
    printf '<p class="sub">No check in this category reported a finding.</p>\n'
  fi
  printf '</div></details>\n'

  # -- 2. Clean: ran, found nothing --
  local clean_ids
  clean_ids=${_RPTC_CLEAN_SET[$c]}
  n=$(printf '%s\n' "$clean_ids" | grep -c . || true); [[ -z $clean_ids ]] && n=0
  printf '<details class="grp"><summary><span class="tag pass">Clean</span> Checks that ran and reported nothing<span class="count">%s check(s)</span></summary><div class="inner">\n' "$n"
  if (( n > 0 )); then
    printf '<p class="sub">Read this list with the strength badge above: it is the evidence that this scan looked for these specific conditions.</p>\n'
    printf '<div class="scroll"><table class="checks"><tr><th>check</th><th>what it looks for</th><th>severity if found</th></tr>\n'
    while IFS= read -r id; do
      [[ -n $id ]] || continue
      printf '<tr><td class="id">%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$id")" "$(html_escape "${_RPTC_TITLE[$id]:-—}")" "$(html_escape "${_RPTC_SEV[$id]:-—}")"
    done <<<"$clean_ids"
    printf '</table></div>\n'
  else
    printf '<p class="sub">None.</p>\n'
  fi
  printf '</div></details>\n'

  # -- 3. Not run, FULL DETAIL (captain decision: every check, its own reason,
  #    never a count alone) --
  local skip_rows napp_ids ns nn why
  skip_rows=${_RPTC_SKIP_ROWS[$c]}
  napp_ids=${_RPTC_NAPP_SET[$c]}
  ns=$(printf '%s\n' "$skip_rows" | grep -c . || true); [[ -z $skip_rows ]] && ns=0
  nn=$(printf '%s\n' "$napp_ids" | grep -c . || true); [[ -z $napp_ids ]] && nn=0
  printf '<details class="grp" open><summary><span class="tag skip">Not run</span> Checks that did not run, with the reason recorded<span class="count">%s check(s)</span></summary><div class="inner">\n' "$(( ns + nn ))"
  if (( ns > 0 )); then
    printf '<h3>Filtered out before dispatch</h3>\n'
    printf '<p class="sub">Dropped by the check-selection chain (lib/checks.sh) - an intensity/profile filter, a missing requires-cmd/requires-config, or an explicit exclude.</p>\n'
    printf '<div class="scroll"><table class="checks"><tr><th>check</th><th>what it looks for</th><th>dropped by</th></tr>\n'
    while IFS=$'\t' read -r id why; do
      [[ -n $id ]] || continue
      printf '<tr><td class="id">%s</td><td>%s</td><td class="why"><span class="reason">%s</span></td></tr>\n' \
        "$(html_escape "$id")" "$(html_escape "${_RPTC_TITLE[$id]:-—}")" "$(html_escape "$why")"
    done <<<"$skip_rows"
    printf '</table></div>\n'
  fi
  if (( nn > 0 )); then
    printf '<h3>Evaluated as not applicable, or ran with nothing this check applies to</h3>\n'
    printf '<p class="sub">Selected and dispatched, but nothing this run inspected was something they apply to - a missing input, an intensity gate, or (for sast/iac) a files: glob with no match in this tree. Each row below carries the exact declared reason. They are <strong>not covered</strong>; their silence is the absence of a test.</p>\n'
    printf '<div class="scroll"><table class="checks"><tr><th>check</th><th>what it looks for</th><th>reason</th></tr>\n'
    while IFS= read -r id; do
      [[ -n $id ]] || continue
      printf '<tr><td class="id">%s</td><td>%s</td><td class="why"><span class="reason">%s</span></td></tr>\n' \
        "$(html_escape "$id")" "$(html_escape "${_RPTC_TITLE[$id]:-—}")" \
        "$(html_escape "${_RPTC_NAPP_REASON[$id]:-not applicable}")"
    done <<<"$napp_ids"
    printf '</table></div>\n'
  fi
  (( ns + nn == 0 )) && printf '<p class="sub">None &mdash; every registered check in this category was dispatched.</p>\n'
  printf '</div></details>\n'

  # -- 4. Unaccounted --
  local unacc_ids
  unacc_ids=${_RPTC_UNACC_SET[$c]}
  n=$(printf '%s\n' "$unacc_ids" | grep -c . || true); [[ -z $unacc_ids ]] && n=0
  if (( n > 0 )); then
    printf '<details class="grp" open><summary><span class="tag gap">Unaccounted</span> Registered, not run, and no per-check reason recorded<span class="count">%s check(s)</span></summary><div class="inner">\n' "$n"
    printf '<div class="warn">These checks were selected for this run and never executed, and the run recorded no reason naming them. A prose coverage record below may explain them as a group, but nothing ties that prose to these ids. <strong>Do not read their silence as a clean result.</strong> This is the one bucket an auditor should push back on.</div>\n'
    printf '<div class="scroll"><table class="checks"><tr><th>check</th><th>what it looks for</th><th>severity if found</th></tr>\n'
    while IFS= read -r id; do
      [[ -n $id ]] || continue
      printf '<tr><td class="id">%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$id")" "$(html_escape "${_RPTC_TITLE[$id]:-—}")" "$(html_escape "${_RPTC_SEV[$id]:-—}")"
    done <<<"$unacc_ids"
    printf '</table></div>\n</div></details>\n'
  fi

  # -- 5. Declared reductions + gaps for this category --
  local red gap nr ng
  red=$(grep "module=$c" "$rundir/meta/coverage_reduction" 2>/dev/null || true)
  nr=$(printf '%s\n' "$red" | grep -c . || true); [[ -z $red ]] && nr=0
  gap=$(grep "^${c}[ :/]" "$rundir/meta/coverage_gap" 2>/dev/null || true)
  ng=$(printf '%s\n' "$gap" | grep -c . || true); [[ -z $gap ]] && ng=0
  if (( nr + ng > 0 )); then
    printf '<details class="grp"><summary><span class="tag gap">Coverage record</span> What this category declared it did not cover<span class="count">%s entr(ies)</span></summary><div class="inner">\n' "$(( nr + ng ))"
    if (( nr > 0 )); then
      printf '<h3>Declared reductions</h3>\n<ul class="prose">\n'
      local l r rest
      while IFS= read -r l; do
        [[ -n $l ]] || continue
        r=$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' <<<"$l")
        rest=${l#*reason=}; rest=${rest#* }
        printf '<li><span class="reason">%s</span> <span class="why">%s</span></li>\n' \
          "$(html_escape "${r:-—}")" "$(html_escape "$rest")"
      done <<<"$red"
      printf '</ul>\n'
    fi
    if (( ng > 0 )); then
      printf '<h3>Coverage gaps</h3>\n<ul class="prose">\n'
      while IFS= read -r l; do
        [[ -n $l ]] && printf '<li>%s</li>\n' "$(html_escape "$l")"
      done <<<"$gap"
      printf '</ul>\n'
    fi
    printf '</div></details>\n'
  fi
  printf '</section>\n'
}

_html_audit_limitations() {
  local rundir=$1
  printf '<section class="cat" id="limitations"><header><h2>Run-level limitations</h2>\n'
  printf '<p class="desc">Facts about this run as a whole, not attributable to one category.</p></header>\n'
  printf '<ul class="prose">\n'
  local any=0 k l
  for k in limits_relaxed limits_clamped incomplete_reason abort_reason; do
    [[ -r $rundir/meta/$k ]] || continue
    while IFS= read -r l; do
      [[ -n $l ]] || continue
      any=1
      printf '<li><span class="reason">%s</span> %s</li>\n' "$(html_escape "$k")" "$(html_escape "$l")"
    done <"$rundir/meta/$k"
  done
  if [[ -r $rundir/meta/coverage_gap ]]; then
    while IFS= read -r l; do
      [[ -n $l ]] || continue
      case $l in sast*|sca*|iac*|dast*|cloud*) continue ;; esac
      any=1; printf '<li>%s</li>\n' "$(html_escape "$l")"
    done <"$rundir/meta/coverage_gap"
  fi
  (( any )) || printf '<li class="sub">None recorded for this run.</li>\n'
  printf '</ul>\n</section>\n'
}

_html_audit_foot() {
  # `${SCOURSH_RUN_ID:-...}`, never a bare `basename "$1"` - see
  # _html_audit_summary's own identical fix and comment above.
  printf '<footer>Generated by scoursh %s from run <code>%s</code>. Self-contained: no external assets, no scripts, no network requests at view time.</footer>\n' \
    "$(html_escape "$(scoursh_version)")" "$(html_escape "${SCOURSH_RUN_ID:-$(basename "$1")}")"
  printf '</main>\n</body>\n</html>\n'
}

# report_audit RUNDIR - the entry point, gated behind `--format audit` (opt-in,
# never in the default format list - captain decision: ship alongside
# report.html without changing its own default behaviour). Writes
# report-audit.html unconditionally alongside whatever else report_all wrote.
report_audit() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  _report_coverage_registry_load
  _report_coverage_state "$rundir"
  {
    _html_audit_head
    _html_audit_nav
    _html_audit_summary "$rundir"
    local c
    for c in "${_RPT_MODULES[@]+"${_RPT_MODULES[@]}"}"; do
      _html_audit_category "$rundir" "$c"
    done
    _html_audit_limitations "$rundir"
    _html_audit_foot "$rundir"
  } >"$rundir/report-audit.html"
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
      dast | cloud | posture | derived | image) write=1 ;;
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
# on-disk `*.rules` file under sast/sca/iac/dast/cloud (posture nests under
# `modules/cloud/`, so its own checks.rules is covered by the `cloud` call;
# rules/derived.rules and rules/redaction.rules live outside modules/
# entirely and are never loaded here - the former is deliberately unseeded,
# the latter's ids are never a finding's check_id).
#
# This USED to be its own, entirely separate full-catalog walk - the exact
# same `checks_registry_load` + per-module/per-record loop
# `_report_checkmeta_registry_load` (section 1a) already performs for the
# OWASP/CIS state - re-parsing and re-validating every `*.rules` file a
# SECOND time from disk under a second set-name prefix. Measured costing as
# much again as that walk (~10-18s on this tree's ~319-record catalog), and
# paid on every ordinary scan because `sarif` is in the default `--format`
# list. `_report_checkmeta_registry_load` now populates `_SARIF_REG_LOC` in
# its own single pass instead (see that function's own comment); this is a
# thin wrapper so no caller below needed to change, and is exactly as cheap
# to call again as `_report_owasp_registry_load` already is - memoized on
# `SCOURSH_INSTALL_ROOT`, a no-op once any of the three views has run once
# in this process.
declare -A _SARIF_REG_LOC=()
_sarif_build_registry() {
  _report_checkmeta_registry_load
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
# posture, derived, image) point at report_locations' own generated artifact,
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
    dast | cloud | posture | derived | image)
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
# 5b. `--format agent` - a compact, schema-projected findings file for a
#     downstream AI fixing agent (docs/AGENT-FORMAT.md is the normative
#     contract; this is the implementation).
# ---------------------------------------------------------------------------
# Captain-decided shape (docs/AGENT-FORMAT.md §1): compact JSON, written to
# `reports/<run>/agent-fix.json`, a first-class deliverable and part of the
# default format list (an explicit `--format` list still wins and can omit
# it).  The token saving is the SCHEMA PROJECTION - dropping every field a
# fixing agent never reads (fingerprint, cvss, first_seen/last_seen,
# rule_digest, contributors/derived_into/related, endpoint_hosts, cell,
# logical.kind, exposure/auth/sensitive_data, suppressed_by) and promoting
# whatever is byte-identical across a check's own findings into a shared
# `checks{}` catalogue - never a bespoke encoding.  A ran-clean check is
# EXCLUDED from `checks{}` (it never appears in `findings[]` either, so there
# is nothing to catalogue); the `run` header's `checks_run`/`coverage_gap`/
# `coverage_reduction` carry that fact instead, verbatim, so "did not check"
# can never read as "clean" (docs/DESIGN.md §15).
#
# Two passes over the SAME findings.fields `_md_findings`/`_finding_json`
# already read, exactly as docs/AGENT-FORMAT.md's own feasibility prototype
# proved: pass 1 (`_agent_pass1`) decides which per-check fields are
# byte-identical across every one of that check's LIVE findings; pass 2
# (`_agent_print_findings`) emits.  Needs no check registry access - which
# matters because SCA ships no `*.rules` at all and an adapter's check id is
# minted at runtime, so a registry-driven catalogue would have a hole exactly
# there.
declare -gA _AGENT_SEEN=() _AGENT_TITLE=() _AGENT_REM=() _AGENT_SEV=() \
  _AGENT_CWE=() _AGENT_OWASP=() _AGENT_REFS=() _AGENT_CIS=() _AGENT_VARY=()
_AGENT_BUF=''

_agent_pass1() {
  local rundir=$1 line c
  _AGENT_SEEN=(); _AGENT_TITLE=(); _AGENT_REM=(); _AGENT_SEV=()
  _AGENT_CWE=(); _AGENT_OWASP=(); _AGENT_REFS=(); _AGENT_CIS=(); _AGENT_VARY=()
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[suppressed]:-false} == true ]] && continue
    c=${_DF[check_id]:-}
    [[ -n $c ]] || continue
    if [[ -z ${_AGENT_SEEN[$c]:-} ]]; then
      _AGENT_SEEN[$c]=1
      _AGENT_TITLE[$c]=${_DF[title]:-}
      _AGENT_REM[$c]=${_DF[remediation]:-}
      _AGENT_SEV[$c]=${_DF[severity]:-}
      _AGENT_CWE[$c]=${_DF[cwe]:-}
      _AGENT_OWASP[$c]=${_DF[owasp]:-}
      _AGENT_REFS[$c]=${_DF[references]:-}
      _AGENT_CIS[$c]=${_DF[cis]:-}
    else
      [[ ${_AGENT_TITLE[$c]} == "${_DF[title]:-}" ]] || _AGENT_VARY[$c.title]=1
      [[ ${_AGENT_REM[$c]} == "${_DF[remediation]:-}" ]] || _AGENT_VARY[$c.rem]=1
      [[ ${_AGENT_SEV[$c]} == "${_DF[severity]:-}" ]] || _AGENT_VARY[$c.sev]=1
      [[ ${_AGENT_CWE[$c]} == "${_DF[cwe]:-}" ]] || _AGENT_VARY[$c.cwe]=1
      [[ ${_AGENT_OWASP[$c]} == "${_DF[owasp]:-}" ]] || _AGENT_VARY[$c.owasp]=1
      [[ ${_AGENT_REFS[$c]} == "${_DF[references]:-}" ]] || _AGENT_VARY[$c.refs]=1
      [[ ${_AGENT_CIS[$c]} == "${_DF[cis]:-}" ]] || _AGENT_VARY[$c.cis]=1
    fi
  done <"$rundir/findings.fields"
}

# _agent_obj_begin / _agent_kv_str / _agent_kv_list / _agent_kv_raw - a small
# sparse-object accumulator.  Every one of the three setters OMITS the key
# entirely on an empty value (docs/AGENT-FORMAT.md §2.1: "empty values are
# omitted, not emitted as ""/[]"), which is what makes a leading-comma-free
# accumulator simpler here than the printf-with-a-`first`-flag idiom the rest
# of this file uses: a dozen conditionally-present fields would otherwise need
# a dozen independent `first` flags.  Never used for the `run` header, which
# has the OPPOSITE contract (every field always present, `[]` for an empty
# array) - that header is built with plain printf, reusing `_meta_array`/
# `_meta_array_unique` directly, exactly as report_run_json does.
_agent_obj_begin() { _AGENT_BUF=''; }

_agent_kv_str() {
  local k=$1 v=$2
  [[ -n $v ]] || return 0
  [[ -z $_AGENT_BUF ]] || _AGENT_BUF+=','
  _AGENT_BUF+="$(json_string "$k"):$(json_string "$v")"
}

# KEY VALUE, where VALUE is LF-joined (finding_add's own join character for a
# repeatable field, e.g. `references`/`cis`) or comma-joined (SCA's own
# `fix_fixed_versions`, translated to LF by the one caller that needs it).
_agent_kv_list() {
  local k=$1 v=$2 arr='' first=1 line
  [[ -n $v ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    (( first )) || arr+=','
    first=0
    arr+="$(json_string "$line")"
  done <<<"$v"
  [[ -n $arr ]] || return 0
  [[ -z $_AGENT_BUF ]] || _AGENT_BUF+=','
  _AGENT_BUF+="$(json_string "$k"):[$arr]"
}

# KEY RAW - RAW is already-valid JSON (a number, a bool, a nested object).
_agent_kv_raw() {
  local k=$1 v=$2
  [[ -n $v ]] || return 0
  [[ -z $_AGENT_BUF ]] || _AGENT_BUF+=','
  _AGENT_BUF+="$(json_string "$k"):$v"
}

# `SCOURSH_SCA_SEMVER_SOURCED` idiom (modules/sca/semver.sh's own top-of-file
# guard): lazily sources the ONE comparator this codebase has proven
# (docs/FOUNDATION.md tension 25), so a caller that reaches report_agent
# without modules/sca/engine.sh ever having been sourced in this process -
# `scan.sh report --from DIR`, or a test that sources lib/report.sh alone -
# still gets a working `semver_cmp_v` rather than a bare "command not found".
_agent_sca_semver_ensure() {
  [[ -n ${SCOURSH_SCA_SEMVER_SOURCED:-} ]] && return 0
  # shellcheck source=modules/sca/semver.sh
  source "$SCOURSH_INSTALL_ROOT/modules/sca/semver.sh"
}

# _agent_sca_fix_to ECOSYSTEM INSTALLED FIXED_CSV - the smallest published
# fixed version >= INSTALLED (docs/AGENT-FORMAT.md §3: `django@1.11` +
# `2.1.10,2.2.3,1.11.22` -> `1.11.22`, the same branch, not `2.1.10`).
#
# `semver_cmp_v` is proven ONLY for npm (modules/sca/semver.sh's own header:
# "never called from any of [pypi/maven/Go/RubyGems/composer]'s code paths" -
# a 1.66% divergence was measured against real PEP 440).  Reusing it for a
# non-npm ecosystem here would be exactly the kind of invented-precision
# tension 25 forbids, so a non-npm ecosystem falls back to the advisory's
# OWN first-listed fixed version - a real published fact, never a guess at an
# ordering scoursh cannot verify - and `fix_all` always carries every option
# so the fixer can choose a different one.
_agent_sca_fix_to() {
  local eco=$1 installed=$2 csv=$3 best='' cand
  if [[ $eco == npm ]]; then
    _agent_sca_semver_ensure
    local IFS=,
    # shellcheck disable=SC2206
    local -a cands=($csv)
    IFS=$' \t\n'
    for cand in "${cands[@]+"${cands[@]}"}"; do
      [[ -n $cand ]] || continue
      semver_cmp_v "$cand" "$installed"
      (( _SV_CMP < 0 )) && continue
      if [[ -z $best ]]; then
        best=$cand
      else
        semver_cmp_v "$cand" "$best"
        (( _SV_CMP < 0 )) && best=$cand
      fi
    done
    if [[ -n $best ]]; then
      printf '%s' "$best"
      return 0
    fi
  fi
  printf '%s' "${csv%%,*}"
}

# _agent_sca_fix_cmd ECOSYSTEM PACKAGE TO - the frozen per-ecosystem template
# (docs/AGENT-FORMAT.md §3).  Empty TO (no fix_to could be derived - never
# reached in practice, since a non-empty FIXED_CSV always yields at least the
# first-listed fallback) yields an empty command rather than a broken one.
_agent_sca_fix_cmd() {
  local eco=$1 pkg=$2 to=$3
  [[ -n $to ]] || { printf ''; return 0; }
  case $eco in
    npm) printf 'npm install %s@%s' "$pkg" "$to" ;;
    pypi) printf "pip install '%s==%s'" "$pkg" "$to" ;;
    RubyGems) printf 'bundle update %s --conservative' "$pkg" ;;
    composer) printf 'composer require %s:%s' "$pkg" "$to" ;;
    maven) printf '<version>%s</version>' "$to" ;;
    Go) printf 'go get %s@%s && go mod tidy' "$pkg" "$to" ;;
    *) printf '' ;;
  esac
}

# A cloud `fix-cli` template's `%RESOURCE%` placeholder is filled from the
# finding's own `loc_resource_key`, which every modules/cloud/aws/live/*.sh
# emitter sets to the resource's full ARN (s3_engine.sh:425 and its
# siblings). Stripping to the trailing colon-segment is correct for the ONLY
# shape a fix-cli template references today - an S3 bucket ARN
# (`arn:aws:s3:::name`), which carries no embedded `/` - and is NOT a general
# ARN-to-resource-name parser: a future fix-cli on a resource type whose bare
# name is not simply the ARN's trailing segment (an IAM role `role/name`, for
# example) must not reuse this unchanged.
_agent_cloud_resource_of() { printf '%s' "${1##*:}"; }

# The fix scaffold for the CURRENTLY-DECODED finding (_DF).  Sets globals
# rather than printing (the occurrence_next/worker_id_set idiom, AGENTS.md
# "Things measured on this codebase"): a side-effecting function called as
# `$(f)` runs in a subshell and its writes are discarded.
_AGENT_FIXABILITY=manual
_AGENT_FIX_KIND=''
_AGENT_FIX_FIND=''
_AGENT_FIX_REPLACE=''
_AGENT_FIX_SNIPPET=''
_AGENT_FIX_TO=''
_AGENT_FIX_ALL=''
_AGENT_FIX_CMD=''
_AGENT_FIX_CLI=''
_AGENT_FIX_WRITES=''
_agent_compute_fix() {
  _AGENT_FIXABILITY=manual
  _AGENT_FIX_KIND=''; _AGENT_FIX_FIND=''; _AGENT_FIX_REPLACE=''; _AGENT_FIX_SNIPPET=''
  _AGENT_FIX_TO=''; _AGENT_FIX_ALL=''; _AGENT_FIX_CMD=''; _AGENT_FIX_CLI=''; _AGENT_FIX_WRITES=''

  local mod=${_DF[module]:-}

  # SCA: fully derivable offline from fix_fixed_versions/dep_type, which
  # modules/sca/{engine,go_engine}.sh set at emit time from the SAME
  # data/advisories.db row the finding already matched - never re-parsed
  # from `evidence` (docs/AGENT-FORMAT.md's own trap warning applies equally
  # here, even though SCA's evidence is not redacted: the row is the source
  # of truth, and evidence is free text for a human, not a machine field).
  if [[ $mod == sca ]]; then
    local fixed=${_DF[fix_fixed_versions]:-}
    if [[ -z $fixed ]]; then
      _AGENT_FIXABILITY=blocked
      return 0
    fi
    local dep=${_DF[dep_type]:-unknown}
    if [[ $dep == direct ]]; then _AGENT_FIXABILITY=auto; else _AGENT_FIXABILITY=assisted; fi
    _AGENT_FIX_KIND='dep-upgrade'
    _AGENT_FIX_ALL=${fixed//,/$'\n'}
    _AGENT_FIX_TO=$(_agent_sca_fix_to "${_DF[loc_ecosystem]:-}" "${_DF[loc_version]:-}" "$fixed")
    _AGENT_FIX_CMD=$(_agent_sca_fix_cmd "${_DF[loc_ecosystem]:-}" "${_DF[loc_package]:-}" "$_AGENT_FIX_TO")
    return 0
  fi

  # CLOUD: a rule-authored `fix-cli` (§9.5 script-check schema) is a WRITE,
  # so it is ALWAYS `assisted` and ALWAYS carries `fix_writes: true` - never
  # `auto`, whatever the check - because scoursh is read-only end to end and
  # this is a suggestion for a human to review, never a command scoursh will
  # run itself (captain decision).
  if [[ $mod == cloud && -n ${_DF[fix_cli]:-} ]]; then
    _AGENT_FIXABILITY=assisted
    _AGENT_FIX_KIND=cloud-cli
    _AGENT_FIX_CLI=${_DF[fix_cli]//%RESOURCE%/$(_agent_cloud_resource_of "${_DF[loc_resource_key]:-}")}
    _AGENT_FIX_WRITES=true
    return 0
  fi

  # SAST / IaC: a rule-authored fix-kind (§9.1.4).  Absent on most checks by
  # design - docs/AGENT-FORMAT.md §3 catalogues which of the 91 SAST/IaC
  # checks carry one and why the rest are `manual` - and a secret-family
  # check can never reach this with one set at all
  # (finding_from_record's own die() guard).
  case ${_DF[fix_kind]:-} in
    replace)
      _AGENT_FIXABILITY=auto
      _AGENT_FIX_KIND=replace
      _AGENT_FIX_FIND=${_DF[fix_find]:-}
      _AGENT_FIX_REPLACE=${_DF[fix_replace]:-}
      ;;
    replace-tpl)
      _AGENT_FIXABILITY=assisted
      _AGENT_FIX_KIND=replace-tpl
      _AGENT_FIX_FIND=${_DF[fix_find]:-}
      _AGENT_FIX_REPLACE=${_DF[fix_replace]:-}
      ;;
    insert-near)
      _AGENT_FIXABILITY=assisted
      _AGENT_FIX_KIND=insert-near
      _AGENT_FIX_FIND=${_DF[fix_find]:-}
      _AGENT_FIX_SNIPPET=${_DF[fix_snippet]:-}
      ;;
    *)
      _AGENT_FIXABILITY=manual
      ;;
  esac
}

_agent_print_finding() {
  local c=${_DF[check_id]:-}
  _agent_compute_fix
  _agent_obj_begin
  _agent_kv_str id "${_DF[fingerprint]:0:12}"
  _agent_kv_str check "$c"
  _agent_kv_str mod "${_DF[module]:-}"
  [[ -z ${_AGENT_VARY[$c.sev]:-} ]] || _agent_kv_str sev "${_DF[severity]:-}"
  _agent_kv_str conf "${_DF[confidence]:-}"
  _agent_kv_str status "${_DF[status]:-}"
  _agent_kv_str loc "${_DF[logical_fqn]:-}"
  _agent_kv_str advisory "${_DF[loc_advisory_id]:-}"
  _agent_kv_str dep_type "${_DF[dep_type]:-}"
  [[ -z ${_AGENT_VARY[$c.cwe]:-} ]] || _agent_kv_str cwe "${_DF[cwe]:-}"
  [[ -z ${_AGENT_VARY[$c.owasp]:-} ]] || _agent_kv_str owasp "${_DF[owasp]:-}"
  [[ -z ${_AGENT_VARY[$c.refs]:-} ]] || _agent_kv_list refs "${_DF[references]:-}"
  [[ -z ${_AGENT_VARY[$c.cis]:-} ]] || _agent_kv_list cis "${_DF[cis]:-}"
  [[ -z ${_AGENT_VARY[$c.title]:-} ]] || _agent_kv_str title "${_DF[title]:-}"
  _agent_kv_str evidence "${_DF[evidence]:-}"
  [[ -z ${_AGENT_VARY[$c.rem]:-} ]] || _agent_kv_str remediation "${_DF[remediation]:-}"
  _agent_kv_str fixability "$_AGENT_FIXABILITY"
  # `fix_*` is present ONLY for auto/assisted (docs/AGENT-FORMAT.md §3's
  # table): a manual/blocked finding carries NO fix_* key at all, never an
  # empty `fix_kind: ""`, which would read as "there is a fix".
  if [[ $_AGENT_FIXABILITY == auto || $_AGENT_FIXABILITY == assisted ]]; then
    _agent_kv_str fix_kind "$_AGENT_FIX_KIND"
    _agent_kv_str fix_find "$_AGENT_FIX_FIND"
    _agent_kv_str fix_replace "$_AGENT_FIX_REPLACE"
    _agent_kv_str fix_snippet "$_AGENT_FIX_SNIPPET"
    _agent_kv_str fix_to "$_AGENT_FIX_TO"
    _agent_kv_list fix_all "$_AGENT_FIX_ALL"
    _agent_kv_str fix_cmd "$_AGENT_FIX_CMD"
    _agent_kv_str fix_cli "$_AGENT_FIX_CLI"
    if [[ -n $_AGENT_FIX_WRITES ]]; then
      _agent_kv_raw fix_writes true
      _agent_kv_str fix_note \
        'suggested, human-review, do NOT auto-run - scoursh is read-only and never executes this'
    fi
  fi
  printf '{%s}' "$_AGENT_BUF"
}

_agent_print_findings() {
  local rundir=$1 line first=1
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[suppressed]:-false} == true ]] && continue
    (( first )) || printf ','
    first=0
    _agent_print_finding
  done <"$rundir/findings.fields"
}

_agent_print_check_obj() {
  local c=$1
  _agent_obj_begin
  [[ -n ${_AGENT_VARY[$c.title]:-} ]] || _agent_kv_str title "${_AGENT_TITLE[$c]}"
  [[ -n ${_AGENT_VARY[$c.rem]:-} ]] || _agent_kv_str remediation "${_AGENT_REM[$c]}"
  [[ -n ${_AGENT_VARY[$c.sev]:-} ]] || _agent_kv_str sev "${_AGENT_SEV[$c]}"
  [[ -n ${_AGENT_VARY[$c.cwe]:-} ]] || _agent_kv_str cwe "${_AGENT_CWE[$c]}"
  [[ -n ${_AGENT_VARY[$c.owasp]:-} ]] || _agent_kv_str owasp "${_AGENT_OWASP[$c]}"
  [[ -n ${_AGENT_VARY[$c.refs]:-} ]] || _agent_kv_list refs "${_AGENT_REFS[$c]}"
  [[ -n ${_AGENT_VARY[$c.cis]:-} ]] || _agent_kv_list cis "${_AGENT_CIS[$c]}"
  printf '{%s}' "$_AGENT_BUF"
}

_agent_print_checks() {
  local c first=1
  (( ${#_AGENT_SEEN[@]} > 0 )) || return 0
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    (( first )) || printf ','
    first=0
    printf '%s:' "$(json_string "$c")"
    _agent_print_check_obj "$c"
  done <<<"$(printf '%s\n' "${!_AGENT_SEEN[@]}" | LC_ALL=C sort)"
}

# The ONE table mapping a check id's namespace prefix (rules/RULE-FORMAT.md
# §9.1.1's own MODULE token) to the module name this honesty header uses for
# it.  `_agent_module_of_check` and `_agent_all_modules` both read this same
# array, so the id-classification side and the not-run universe can never
# drift apart the way they once did - a fixed prefix set used to run only six
# of these eight modules, so `network`/`image` could appear in
# `modules_reported` but could never appear in `modules_not_run` (a real gap
# in the field that exists to stop "did not check" reading as "clean").
# Adding a ninth module needs exactly one new entry here, in both functions
# at once.
#
# The `net`/`image` spelling (not `network`) matches the finding-level
# `module` field a NET-*/IMAGE-* check itself sets (`finding_set module net`
# in modules/network/*_engine.sh; `finding_set module image` in
# modules/image/*.sh) and, for `net`, deliberately does NOT match
# `_RPT_MODULES`/`SCAN_COMMANDS`'s own `network` token - that second spelling
# names the CLI subcommand and the report-audit.html category, a different
# axis from this header's per-check module classification, and the two have
# used different tokens since NET-01 shipped. Changing `net` to `network`
# here would be a breaking change to the honesty header's ALREADY-SHIPPED
# output for a real `scan.sh network` run, not merely a doc fix.
declare -ga _AGENT_MODULE_PREFIXES=(
  'SAST-:sast'
  'SCA-:sca'
  'IAC-:iac'
  'DAST-:dast'
  'CLOUD-:cloud'
  'POSTURE-:posture'
  'NET-:net'
  'IMAGE-:image'
)

# `check_id` -> `module`, by id-namespace prefix - used ONLY to compute the
# `run` header's `modules_reported`/`modules_not_run`, from `meta/checks_run`
# (never from `findings.fields`'s own `module` field, which is silent for a
# module that ran and found nothing).  An id this cannot classify (an adapter
# id like `trivy:AVD-...`, which carries no module prefix at all) is simply
# skipped: the native engine that ran alongside every adapter already
# contributes a classifiable id of its own, so nothing is lost.
_agent_module_of_check() {
  local id=$1 entry prefix
  for entry in "${_AGENT_MODULE_PREFIXES[@]}"; do
    prefix=${entry%%:*}
    case $id in
      "$prefix"*) printf '%s' "${entry#*:}"; return 0 ;;
    esac
  done
  return 1
}

# The full not-run universe, in `_AGENT_MODULE_PREFIXES`'s own order - the
# complete set `modules_not_run` subtracts `_agent_modules_reported` from.
_agent_all_modules() {
  local entry
  for entry in "${_AGENT_MODULE_PREFIXES[@]}"; do
    printf '%s\n' "${entry#*:}"
  done
}

_agent_modules_reported() {
  local rundir=$1 line m
  local -A seen=()
  if [[ -r $rundir/meta/checks_run ]]; then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      m=$(_agent_module_of_check "$line") || continue
      seen[$m]=1
    done <"$rundir/meta/checks_run"
  fi
  (( ${#seen[@]} > 0 )) || return 0
  printf '%s\n' "${!seen[@]}" | LC_ALL=C sort -u
}

_agent_modules_not_run() {
  local rundir=$1 m line
  local -A rep=()
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    rep[$line]=1
  done <<<"$(_agent_modules_reported "$rundir")"
  while IFS= read -r m; do
    [[ -n $m ]] || continue
    [[ -n ${rep[$m]:-} ]] || printf '%s\n' "$m"
  done <<<"$(_agent_all_modules)"
}

_agent_print_str_array() {  # LABEL LIST(newline-separated) - always present
  local label=$1 list=$2 line first=1
  printf '%s:[' "$(json_string "$label")"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    (( first )) || printf ','
    first=0
    printf '%s' "$(json_string "$line")"
  done <<<"$list"
  printf '],'
}

# The `run` header (docs/AGENT-FORMAT.md §2.4): emitted FIRST, before
# `checks`/`findings`, and every field always present - the opposite
# omit-if-empty contract `_agent_kv_*` gives the rest of the document,
# because an ABSENT header field here is exactly the ambiguity §15 forbids
# ("did not check" reading as "clean"). Reuses `_meta_array`/
# `_meta_array_unique` directly, the same functions report_run_json's own
# header uses for the identical facts, so this can never drift from what
# run.json itself says.
_agent_run_header() {
  local rundir=$1
  printf '{'
  printf '"run_id":%s,' "$(json_string "${SCOURSH_RUN_ID:-}")"
  _agent_print_str_array modules_reported "$(_agent_modules_reported "$rundir")"
  _agent_print_str_array modules_not_run "$(_agent_modules_not_run "$rundir")"
  _meta_array_unique "$rundir" checks_run 'checks_run' ''
  _meta_array "$rundir" skipped_checks 'skipped_checks' ''
  _meta_array "$rundir" coverage_gap 'coverage_gap' ''
  _meta_array "$rundir" coverage_reduction 'coverage_reduction' ''
  _meta_array "$rundir" incomplete_reason 'incomplete_reason' ''
  _meta_array "$rundir" abort_reason 'abort_reason' ''
  printf '"status_counts":{"new":%s,"recurring":%s,"fixed":%s,"unknown":%s},' \
    "$(json_number "${_RPT_STATUS[new]:-0}")" "$(json_number "${_RPT_STATUS[recurring]:-0}")" \
    "$(json_number "${_RPT_STATUS[fixed]:-0}")" "$(json_number "${_RPT_STATUS[unknown]:-0}")"
  printf '"gate":%s,' "$(json_string "${SCOURSH_GATE_RESULT:-not-evaluated}")"
  printf '"diff_usable":%s,' "$(json_bool "${SCOURSH_DIFF_USABLE:-false}")"
  printf '"redact_secrets":%s' "$(json_bool "${SCOURSH_REDACT_SECRETS:-true}")"
  printf '}'
}

# `report_agent [RUNDIR]` - the entry point, gated behind `--format agent`
# (in the default list; an explicit `--format` list still wins). Writes
# `agent-fix.json` unconditionally alongside whatever else report_all wrote;
# never gates or replaces any other format.
report_agent() {
  local rundir=${1:-$SCOURSH_RUN_DIR}
  report_count "$rundir"
  _agent_pass1 "$rundir"
  {
    printf '{'
    printf '"scoursh_agent":1,'
    printf '"_note":%s,' \
      "$(json_string 'each finding inherits checks[<check>]; per-finding keys override')"
    printf '"run":'
    _agent_run_header "$rundir"
    printf ',"checks":{'
    _agent_print_checks
    printf '},"findings":['
    _agent_print_findings "$rundir"
    printf ']}\n'
  } >"$rundir/agent-fix.json"
}

# ---------------------------------------------------------------------------
# 6. Everything
# ---------------------------------------------------------------------------
# `report_all [RUNDIR]` writes every artifact this run's resolved --format
# list selects (docs/DESIGN.md §5's `--format json,sarif,html,md`, since
# extended with `agent` (report_agent, §5b above - a first-class deliverable,
# in the default list) and `audit` (report_audit, §4a above - opt-in, never
# in the default list)), plus two records this project treats as mandatory
# rather than format-selectable, neither of which is even in that enum
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
#
# `_report_format_wanted NAME` - true (0) iff format NAME is selected by
# `SCOURSH_FORMATS` (or its documented default).  The single source of truth
# for "what does `--format` mean", shared by the normal path below AND by the
# abort path's own gate (`run_json_refresh_incomplete`, lib/core.sh) so the
# two can never drift the way they did before that fix: the abort path used
# to ignore `SCOURSH_FORMATS` entirely and always write report.html and
# agent-fix.json regardless of what `--format` asked for.
_report_format_wanted() {
  local _rfw_want=$1
  local _rfw_csv=${SCOURSH_FORMATS:-json,sarif,html,md,agent}
  local -a _rfw_fmt=()
  IFS=',' read -r -a _rfw_fmt <<<"$_rfw_csv"
  local _rfw_f
  for _rfw_f in "${_rfw_fmt[@]+"${_rfw_fmt[@]}"}"; do
    [[ $_rfw_f == "$_rfw_want" ]] && return 0
  done
  return 1
}

# Factored out of report_all so `scan.sh report --from DIR`
# (report_regenerate_from, below) can call the identical set of emitters
# without also repeating report_all's other two steps - report_locations and
# report_run_json - which report_regenerate_from's own header explains it
# must not repeat.  This is the ONE place `--format` is turned into which
# emitters run; report_all and report_regenerate_from both call it rather
# than each keeping their own copy of that logic.
_report_render_formats() {
  local rundir=${1:-$SCOURSH_RUN_DIR}

  findings_write_jsonl "$rundir"
  ! _report_format_wanted json || findings_write_json "$rundir"
  ! _report_format_wanted md   || report_md "$rundir"
  ! _report_format_wanted html || report_html "$rundir"
  # docs/STEP10-SARIF-PLAN.md SARIF-03/04: report_sarif writes the full
  # SARIF-2.1.0 document (tool.driver/rules[]/artifacts[]/invocations[], and
  # results[] mapped from this run's own findings).
  ! _report_format_wanted sarif || report_sarif "$rundir"
  # `audit` is a fifth, OPT-IN format value (never in the default list
  # above): report_audit writes report-audit.html ALONGSIDE report.html,
  # never replacing or editing it (captain decision, scoursh-audit-report
  # ticket) - an audit-grade per-category coverage report with full
  # not-covered detail, §4a above.
  ! _report_format_wanted audit || report_audit "$rundir"
  # `agent` is in the default list above (a first-class deliverable):
  # report_agent writes reports/<run>/agent-fix.json, a compact,
  # schema-projected findings file for a downstream AI fixing agent
  # (docs/AGENT-FORMAT.md), never gating or replacing any other format.
  ! _report_format_wanted agent || report_agent "$rundir"
}

report_all() {
  local rundir=${1:-$SCOURSH_RUN_DIR}

  # Unconditional, per its own header comment above: it runs whatever
  # --format asked for, so every later emitter sees the loc_line write-back.
  report_locations "$rundir"
  _report_render_formats "$rundir"
  report_run_json "$rundir"
}

# ---------------------------------------------------------------------------
# `report --from DIR` (docs/DESIGN.md §5's `report` grammar; ROADMAP.md step
# 7's "report --from DIR" entry) - regenerate report artifacts from a PRIOR
# run's own findings, without running any scanner module.
# ---------------------------------------------------------------------------
# Every real run leaves two kinds of record behind: the two MANDATORY,
# machine-generated files that document what happened - findings.jsonl and
# run.json (AGENTS.md "findings.jsonl and run.json are mandatory per-run
# records") - and the two files report_all's own renderer functions actually
# READ to produce report.md/report.html/report.sarif/report-audit.html:
# findings.fields (findings_merge's persisted record - never findings.jsonl,
# which is itself generated FROM it) and meta/ (report_count, report_md,
# report_html, report_sarif and report_audit all read individual meta/<key>
# facts directly; none of them reads run.json). scan.sh's own
# `_scan_require_report_source` validates DIR holds all four before this is
# ever called; this function's job is to feed the renderer the SECOND pair,
# straight from DIR, so "reuse the exact same rendering path" means
# something rather than a second, JSON-based reimplementation of
# report_md/report_html/report_sarif/report_audit's own logic.
#
# Two of report_all's own steps are deliberately NOT repeated here:
#
# - `report_locations` re-tests every SAST-HIST-* finding's path against
#   $SCOURSH_SCAN_ROOT_PATH, LIVE, at render time (docs/FOUNDATION.md tension
#   22 option 3) - a real filesystem check this command has no --path to
#   perform. findings.fields (copied byte-for-byte below) already carries
#   whatever that check decided during the ORIGINAL run; re-running it here
#   with $SCOURSH_SCAN_ROOT_PATH unset would silently flip an original
#   "resolves" verdict to "cannot resolve" for exactly the findings whose
#   original resolution succeeded. That is a real, narrow, and DOCUMENTED
#   gap - this command never claims to re-verify a scan root that may not
#   even exist any more on this host - rather than a silent wrong answer:
#   per `_locations_history_resolves`'s own comment, "cannot resolve" is
#   already the safer of the two readings whenever it is unclear.
# - `report_run_json` recomputes several fields a live scan's own case-block
#   in scan.sh sets straight into an exported variable and never
#   `run_record`s at all - scan_root_id, path_root, gate, gated_findings,
#   diff_usable. Calling it here, with no module dispatched and no --path
#   given, would silently REPLACE the original run's real values with empty
#   defaults - exactly the "did not check collapses into clean" failure this
#   ticket's own honesty requirement forbids. run.json is copied
#   byte-for-byte below instead: the only way to carry forward a field this
#   feature has no other route to.
#
# report_md and report_html separately read three fields straight from the
# environment rather than from meta/ - run_id, redact_secrets, diff_guard -
# re-exported below from the ORIGINAL run's own run.json so those banners
# agree with what that file says, rather than with this invocation's own
# scanner.conf (redact-secrets) or its own fresh --out directory's basename.
#
# `run.json` itself is copied LAST, AFTER _report_render_formats runs, never
# before: a live scan's own report_all calls report_audit (inside
# _report_render_formats) BEFORE report_run_json ever writes run.json for
# the first time, so report_audit's own "duration" line is correctly absent
# on that first render - copying run.json in ahead of time would show a
# duration for a render that, at the point the original ever produced it,
# had none yet.
report_regenerate_from() {
  local from=$1 rundir=${2:-$SCOURSH_RUN_DIR}
  local resolved rundir_resolved
  resolved=$(realpath_of "$from")
  # Resolved on THIS side too, never compared against the raw, possibly
  # symlink-relative `$rundir` as handed in: every real caller reaches this
  # through run_init, which already stores a realpath - but comparing an
  # unresolved form against a resolved one can read two spellings of the
  # SAME directory as different, and then the `rm -rf` below deletes the
  # very source the following `cp` reads from.
  rundir_resolved=$(realpath_of "$rundir")

  SCOURSH_RUN_ID=$(_report_from_field "$resolved/run.json" run_id)
  SCOURSH_REDACT_SECRETS=$(_report_from_field "$resolved/run.json" redact_secrets)
  SCOURSH_DIFF_GUARD=$(_report_from_field "$resolved/run.json" diff_guard)
  # `report_agent`'s honesty header (--format agent, docs/AGENT-FORMAT.md)
  # reads these from the environment exactly as report_run_json does, and a
  # live scan is the only caller that otherwise sets them - re-exported here
  # for the identical reason SCOURSH_DIFF_GUARD already is: A14's byte-identity
  # requirement means this command must reproduce the ORIGINAL run's gate and
  # diff_usable, never this invocation's own unset defaults.
  SCOURSH_GATE_RESULT=$(_report_from_field "$resolved/run.json" gate)
  SCOURSH_DIFF_USABLE=$(_report_from_field "$resolved/run.json" diff_usable)
  export SCOURSH_RUN_ID SCOURSH_REDACT_SECRETS SCOURSH_DIFF_GUARD \
    SCOURSH_GATE_RESULT SCOURSH_DIFF_USABLE

  # `--out` pointed at the same directory as `--from`: it is already this
  # run's own findings.fields/meta/locations/run.json, so there is nothing
  # to copy - and copying would mean deleting rundir/meta right before
  # reading it back from the identical path.
  if [[ $resolved != "$rundir_resolved" ]]; then
    rm -rf -- "$rundir/meta" "$rundir/locations"
    cp -R -- "$resolved/meta" "$rundir/meta"
    cp -- "$resolved/findings.fields" "$rundir/findings.fields"
    # `locations/<module>.txt` (report_locations' own generated artifact,
    # tension 22 option 3): report_sarif's artifacts[] lists one entry per
    # file actually present under this directory (_sarif_print_artifacts),
    # so an original run whose findings needed the fallback has to arrive
    # with the SAME files already in place - report_locations itself is not
    # re-run here (see this function's own header for why), so nothing else
    # would ever create them.
    mkdir -p -- "$rundir/locations"
    if [[ -d $resolved/locations ]]; then
      cp -R -- "$resolved/locations/." "$rundir/locations/"
    fi
  fi

  _report_render_formats "$rundir"

  [[ $resolved == "$rundir_resolved" ]] || cp -- "$resolved/run.json" "$rundir/run.json"
}

# Extracts one top-level scalar VALUE - a string, bool or number - from a
# scoursh-authored run.json: one `"key": value` pair per line, per
# report_run_json's own fixed layout. Never a general JSON parser
# (docs/FOUNDATION.md tension 25's reasoning applies here too: this reads a
# format only this tool writes, in one fixed shape, not arbitrary JSON). A
# quoted string value is unquoted; every key this is ever called for
# (run_id, redact_secrets, diff_guard) holds a plain identifier or bool with
# nothing in it that JSON string escaping would touch.
_report_from_field() {
  local file=$1 key=$2 line
  line=$(grep -m1 "^[[:space:]]*\"$key\":" -- "$file") || { printf ''; return 0; }
  line=${line#*: }
  line=${line%,}
  line=${line#\"}
  line=${line%\"}
  printf '%s' "$line"
}
