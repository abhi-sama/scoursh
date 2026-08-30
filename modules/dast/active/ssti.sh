#!/usr/bin/env bash
# modules/dast/active/ssti.sh - the §7.3 SERVER-SIDE TEMPLATE INJECTION phase
# (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-18, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the request composer, the response-signal helpers), which
# every §7.3 probe reuses; this file is the SSTI-specific part: the vendored
# per-engine expression set and the single detection technique (the EVALUATED
# arithmetic result appearing in the response body).
#
# THE ENGINE SYNTAXES THIS PROBE COVERS, one check id per family
# (modules/dast/active/checks.rules), one payload row per family
# (modules/dast/payloads/ssti-expressions.txt):
#
#   braces  `{{ ... }}`  DAST-INJ-SSTI_BRACES-01  Jinja2, Django, Twig,
#                                                 Nunjucks, Liquid
#   dollar  `${ ... }`   DAST-INJ-SSTI_DOLLAR-01  FreeMarker, Jakarta/JSP EL,
#                                                 Spring EL (SpEL), Mako, and
#                                                 server-side JavaScript
#                                                 template literals
#   erb     `<%= ... %>` DAST-INJ-SSTI_ERB-01     Ruby ERB/Erubi, Node EJS,
#                                                 classic ASP and ASP.NET
#   smarty  `{ ... }`    DAST-INJ-SSTI_SMARTY-01  Smarty and the single-brace
#                                                 PHP engines modelled on it
#
# Four check ids rather than one because the DAST location profile (target,
# method, path_template, param_location, param_name) carries NO component
# naming the engine, so a single id would make a Jinja2 hit and a FreeMarker
# hit on the same parameter collide on one fingerprint and findings_merge would
# silently keep whichever sorted first - the identical argument this file's own
# checks.rules already records for the three SQLi techniques.
#
# WHAT IS DELIBERATELY NOT COVERED, so the boundary is not rediscovered:
# Apache Velocity, whose VTL references are not expressions - `${29*31}` is
# rendered literally and arithmetic needs a `#set(...)` DIRECTIVE, which
# assigns template-context state and so sits outside this ticket's
# "arithmetic expression only" contract; Thymeleaf's `__${...}__` preprocessing
# form; and blind/time-based SSTI, which has no reflection channel at all.
# Each is a named gap rather than a silent absence.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Every payload is one multiplication of two small integers
# wrapped in one engine's delimiters: it reads no file, spawns no process,
# traverses no object graph, reaches no class loader, and mutates nothing - not
# even template-local state. Confirmation stops at "the server did the sum";
# this probe never escalates a confirmed evaluation into the code execution it
# usually implies, and the finding's remediation says so rather than the probe
# proving it.
#
# THE SIGNAL IS THE RESULT, NEVER THE REFLECTION. Almost every parameter on
# almost every application reflects something, so a probe that flagged mere
# reflection is a false-positive generator, and the reflected-but-escaped case
# is the half that fails in the direction that reads as a pass - the same
# lesson active/xss.sh's landing note records. Each payload is flanked by the
# literal sentinel `sstiqzx` and the signature is that sentinel wrapped around
# the PRODUCT, so an unevaluated echo can never match it. The invariant that
# makes it airtight is that the digit `8` occurs in every signature and in no
# payload, so no delete/reorder/re-encode/partial-strip of what was sent can
# manufacture the result; tests/suites/dast-ssti.sh asserts that row by row
# against the shipped file rather than trusting this paragraph.
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test": no parameter inventory, an uninjectable location, a missing
# payload file, a deselected check, or a family that never got sent at all are
# each recorded as a coverage_gap/coverage_reduction the report renders,
# exactly as modules/dast/active/pathtraversal.sh does for its own gaps. In
# particular `checks_run` records ONLY the family ids whose payload actually
# went out over at least one parameter (lib/records.sh's own definition, and
# DAST-29's `check_not_executed` lesson applied here), and every shipped family
# id missing from that set gets a named reduction.
#
# THE INVENTORY IS READ DIRECTLY FROM THE RUN DIRECTORY, NOT FROM THE EXPORT
# ALONE. modules/dast/run.sh reads the inventory and exports
# SCOURSH_DAST_ENDPOINTS/SCOURSH_DAST_PARAMETERS BEFORE the phase loop starts,
# so on a first run - the ordinary case - both are EMPTY: crawl.sh writes
# reports/<run>/inventory/{endpoints,parameters}.json a few phases later in
# that same loop, and nothing re-reads the export afterwards. A phase that
# trusted the export alone would therefore see no surface on exactly the run
# that has just discovered one. This phase does not repeat that defect: it
# falls back to the run directory's own artifacts, the identical pattern
# active/pathtraversal.sh (DAST-17) and passive/headers.sh already use. Fixing
# the export itself belongs to modules/dast/run.sh and is filed as its own
# ticket, not changed here.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes template/parameter syntax
#   literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run attaches
# nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# `_ssti_read_lines_file FILE` - prints the file's non-comment, non-blank lines.
# Returns 1 when the file is unreadable, so a caller degrades gracefully.
_ssti_read_lines_file() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# `_ssti_check_id_for_family FAMILY` - the check id that owns FAMILY. Returns 1
# for a family this build ships no record for, which the caller records rather
# than sending an unattributable payload: a finding whose check_id does not
# exist in modules/dast/active/checks.rules is unfilterable by tension 15 and
# uncountable by tension 12's coverage.
_ssti_check_id_for_family() {
  case $1 in
    braces) printf 'DAST-INJ-SSTI_BRACES-01' ;;
    dollar) printf 'DAST-INJ-SSTI_DOLLAR-01' ;;
    erb)    printf 'DAST-INJ-SSTI_ERB-01' ;;
    smarty) printf 'DAST-INJ-SSTI_SMARTY-01' ;;
    *)      return 1 ;;
  esac
}

# The human phrase the finding's title and evidence name the family by. Kept
# beside the id map so the two cannot drift.
_ssti_family_label() {
  case $1 in
    braces) printf 'double-brace {{ ... }} (Jinja2, Django, Twig, Nunjucks, Liquid)' ;;
    dollar) printf 'dollar-brace ${ ... } (FreeMarker, Jakarta/JSP EL, Spring EL, Mako)' ;;
    erb)    printf 'ERB-style <%%= ... %%> (Ruby ERB, Node EJS, classic ASP/ASP.NET)' ;;
    smarty) printf 'single-brace { ... } (Smarty and Smarty-like PHP engines)' ;;
    *)      printf '%s' "$1" ;;
  esac
}

# `_ssti_read_payloads_file FILE` - loads `<family><TAB><payload><TAB><ERE
# signature>` rows into the parallel `_SSTI_FAMILY`/`_SSTI_PAYLOAD`/`_SSTI_SIG`
# arrays, in file order. A row naming a family this build has no check id for is
# collected into `_SSTI_UNKNOWN_FAMILIES` and NOT loaded. Returns 1 when the
# file is unreadable or carries no usable row.
_ssti_read_payloads_file() {
  local f=$1 fam payload sig
  _SSTI_FAMILY=() _SSTI_PAYLOAD=() _SSTI_SIG=() _SSTI_UNKNOWN_FAMILIES=''
  [[ -r $f ]] || return 1
  while IFS=$'\t' read -r fam payload sig; do
    [[ -n $fam && -n $payload && -n $sig ]] || continue
    if ! _ssti_check_id_for_family "$fam" >/dev/null; then
      [[ $'\n'$_SSTI_UNKNOWN_FAMILIES$'\n' == *$'\n'"$fam"$'\n'* ]] \
        || _SSTI_UNKNOWN_FAMILIES+="$fam"$'\n'
      continue
    fi
    _SSTI_FAMILY+=("$fam")
    _SSTI_PAYLOAD+=("$payload")
    _SSTI_SIG+=("$sig")
  done < <(_ssti_read_lines_file "$f")
  (( ${#_SSTI_FAMILY[@]} > 0 ))
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`.
_ssti_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_ssti_family_selected FAMILY` - tension-15 per-check selection for one
# family, consulted only if dast_check_selected exists (guarded like every peer
# probe, so this file does not hard-depend on it and a direct-engine suite with
# no modules/dast/engine.sh in the process still probes). Unset or empty
# SCOURSH_SELECTED_CHECKS means ALL SELECTED, which is that function's own
# documented contract.
_ssti_family_selected() {
  local id
  id=$(_ssti_check_id_for_family "$1") || return 1
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$id"
}

# `_ssti_note_executed FAMILY` - records that FAMILY's payload really went out,
# which is what `checks_run` is written from. A family that was skipped by
# selection, or never reached because an earlier family already confirmed on
# every parameter, must not appear there: lib/records.sh defines checks_run
# expressly so a reader can tell "this check ran and found nothing" from "this
# check never executed", and DAST-29's own H3 defect was exactly this field
# being written from the passes ENTERED rather than the ids that ran.
_ssti_note_executed() {
  [[ $'\n'$_SSTI_EXECUTED$'\n' == *$'\n'"$1"$'\n'* ]] || _SSTI_EXECUTED+="$1"$'\n'
}

# `_ssti_probe_param INDEX` - sends each loaded payload into parameter INDEX in
# file order and returns 0 on the FIRST response whose body carries that
# payload's own evaluated signature; `_SSTI_HIT_FAMILY`/`_SSTI_HIT_PAYLOAD`/
# `_SSTI_HIT_SIG` are set to the winning row. Returns 1 when nothing evaluated.
#
# ONE FINDING PER (endpoint, parameter): the first confirmed family wins and
# the remaining families are not sent. An application renders through one
# template engine, so continuing would spend requests to learn nothing, which
# is active/pathtraversal.sh's own bound reasoning ("once it is proven, sending
# the rest is only more of the same with nothing new to report") applied here.
# The families that WERE sent before the hit are still recorded as executed.
_ssti_probe_param() {
  local i=$1 k fam payload sig
  for (( k = 0; k < ${#_SSTI_FAMILY[@]}; k++ )); do
    fam=${_SSTI_FAMILY[$k]}; payload=${_SSTI_PAYLOAD[$k]}; sig=${_SSTI_SIG[$k]}
    _ssti_family_selected "$fam" || continue
    inject_send "$i" "$payload" || continue
    _ssti_note_executed "$fam"
    if inject_body_has_signature "$_INJ_BODY" "$sig"; then
      _SSTI_HIT_FAMILY=$fam
      _SSTI_HIT_PAYLOAD=$payload
      _SSTI_HIT_SIG=$sig
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
_ssti_emit() {
  local i=$1 fam=$2 payload=$3 sig=$4
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path authv=none check label
  check=$(_ssti_check_id_for_family "$fam") || return 0
  label=$(_ssti_family_label "$fam")
  path=$(_ssti_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "Server-side template injection ($label) via request parameter"
  finding_set base_severity critical
  finding_set confidence high
  finding_set cwe CWE-1336
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never concatenate request-derived data into a template SOURCE string. Render a fixed, developer-authored template and pass the user value in as a CONTEXT VARIABLE, so the engine treats it as data rather than as syntax to compile. Where user-authored templates are a product requirement, render them in the engine sandbox its documentation provides (Jinja2 SandboxedEnvironment, Twig SandboxExtension, FreeMarker TemplateClassResolver.SAFE_RESOLVER, Liquid) with a deny-by-default allow-list of exposed objects and methods, and treat that sandbox as a defence in depth rather than a boundary - template injection in an unsandboxed engine is normally a direct path to remote code execution.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "parameter '$name' ($loc) of $method $path was sent the arithmetic template expression '$payload' and the response body came back carrying /$sig/ - the EVALUATED product, not the expression - which means the server compiled request-derived text as $label template syntax. The signature is the sentinel wrapped around the result and shares no digit with what was sent, so an unevaluated echo of the input cannot produce it: this is evaluation, not reflection. Detection stopped here; nothing beyond one multiplication was executed and no data was read or written."
  finding_emit
  return 0
}

_dast_ssti_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/ssti.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_SSTI_PAYLOAD_DIR overrides the location
  # so an operator can vendor a custom set (the same swappable-seam idiom
  # active/sqli.sh's SCOURSH_DAST_SQLI_PAYLOAD_DIR uses) and so the
  # graceful-degradation branch is testable against an empty directory; unset,
  # it is the shipped set.
  local pdir=${SCOURSH_DAST_SSTI_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  declare -ga _SSTI_FAMILY=() _SSTI_PAYLOAD=() _SSTI_SIG=()
  declare -g _SSTI_UNKNOWN_FAMILIES='' _SSTI_EXECUTED=''
  _ssti_read_payloads_file "$pdir/ssti-expressions.txt" || true

  local fam
  while IFS= read -r fam; do
    [[ -n $fam ]] || continue
    run_record coverage_reduction "module=dast reason=ssti_unknown_payload_family family=$fam target=$target - modules/dast/payloads/ssti-expressions.txt carries a row for template-engine family '$fam' that this build ships no check id for (modules/dast/active/checks.rules), so it was NOT sent: a finding under an unregistered check id is invisible to the --profile-scan/--intensity filter chain and to coverage."
  done <<<"$_SSTI_UNKNOWN_FAMILIES"

  if (( ${#_SSTI_FAMILY[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=ssti_payloads_missing target=$target - the template-expression file (modules/dast/payloads/ssti-expressions.txt) is absent, empty, or carries no usable row, so server-side template injection did not run. This is a coverage reduction, not a clean result."
    run_record coverage_gap "dast ssti: no template-expression payloads are available on target '$target', so no template-injection probe was sent. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  # tension-15 per-check selection, per family. A run whose filter chain
  # excluded EVERY family sends nothing at all and says so, rather than
  # entering the parameter loop to skip each row one at a time.
  local k selected=0
  for (( k = 0; k < ${#_SSTI_FAMILY[@]}; k++ )); do
    if _ssti_family_selected "${_SSTI_FAMILY[$k]}"; then
      selected=$(( selected + 1 ))
    else
      run_record coverage_reduction "module=dast reason=check_not_selected check=$(_ssti_check_id_for_family "${_SSTI_FAMILY[$k]}") target=$target - excluded by --profile-scan/--intensity/--allow-intrusive filtering, so the ${_SSTI_FAMILY[$k]} template-engine family was not probed."
    fi
  done
  if (( selected == 0 )); then
    run_record coverage_gap "dast ssti: every template-engine family was excluded by the check filter on target '$target', so no template-injection probe was sent."
    return 0
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE - see
  # this file's own header for why.
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  local pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi

  inject_inventory_load "$epf" "$pf"
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so server-side template injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast ssti: target '$target' has no known request parameters (query/body/JSON/header/path), so no template-injection probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained at least one session this run; otherwise the probe runs against
  # the public surface and attaches nothing.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=ssti target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_body tested=0 uninjectable=0 found=0 noisy=0
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    if [[ $loc == graphql ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_val=$(inject_benign_value "$i")
    if ! inject_send "$i" "$base_val"; then
      # An uninjectable location (a path parameter with no template slot) or a
      # transport failure on the baseline: nothing to test against.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_body=$_INJ_BODY
    tested=$(( tested + 1 ))

    # A baseline that ALREADY carries an evaluated signature means this
    # endpoint's ordinary response happens to contain the sentinel-wrapped
    # product (a synthetic fixture, or a page echoing an earlier probe), so the
    # signal would not be attributable to this request. It is skipped and
    # counted rather than reported: the signature has to be absent from the
    # baseline and present only after injection to mean anything - the same
    # rule active/pathtraversal.sh applies to its marker signatures.
    local baseline_noisy=0 s
    for (( s = 0; s < ${#_SSTI_SIG[@]}; s++ )); do
      if inject_body_has_signature "$base_body" "${_SSTI_SIG[$s]}"; then
        baseline_noisy=1
        break
      fi
    done
    if (( baseline_noisy )); then
      noisy=$(( noisy + 1 ))
      continue
    fi

    if _ssti_probe_param "$i"; then
      _ssti_emit "$i" "$_SSTI_HIT_FAMILY" "$_SSTI_HIT_PAYLOAD" "$_SSTI_HIT_SIG"
      found=$(( found + 1 ))
    fi
  done

  # checks_run carries ONLY the family ids whose payload actually went out over
  # at least one parameter, and every shipped family missing from that set gets
  # a named reduction. Writing all four unconditionally would claim four checks
  # ran on a run where selection, an early confirmation, or an inventory of
  # nothing but uninjectable locations meant some never executed.
  local id
  for (( k = 0; k < ${#_SSTI_FAMILY[@]}; k++ )); do
    fam=${_SSTI_FAMILY[$k]}
    id=$(_ssti_check_id_for_family "$fam") || continue
    if [[ $'\n'$_SSTI_EXECUTED$'\n' == *$'\n'"$fam"$'\n'* ]]; then
      run_record checks_run "$id"
    else
      run_record coverage_reduction "module=dast reason=ssti_family_not_applicable check=$id family=$fam target=$target - no request carrying the $fam template syntax was sent this run (the check filter excluded it, every parameter was uninjectable or noisy, or an earlier family already confirmed evaluation on each parameter tested), so this engine family was NOT assessed and its absence from the findings is not a clean result for it."
    fi
  done

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast ssti: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for template injection. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=ssti_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for template injection here."
  fi
  if (( noisy > 0 )); then
    run_record coverage_reduction "module=dast reason=ssti_noisy_baseline target=$target count=$noisy - $noisy parameter(s) returned a BASELINE response that already carried an evaluated signature, so an injected result could not have been attributed to the request; they were skipped rather than reported and were NOT assessed."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast ssti: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no template-injection test was sent."
  fi

  log_info "dast ssti: target '$target' - tested $tested of $_INJ_N parameter(s) for server-side template injection, $found confirmed"
  return 0
}

_dast_ssti_phase
