#!/usr/bin/env bash
# modules/dast/active/pathtraversal.sh - the §7.3 PATH-TRAVERSAL phase
# (docs/DESIGN.md §7.3: "request known-safe read-only markers ... and detect
# its signature; report access, don't harvest contents";
# docs/STEP5-DAST-PLAN.md DAST-17, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the request composer, the response-signal helpers), which
# every §7.3 probe reuses; this file is the path-traversal-specific part: the
# vendored directory-climb templates + marker files, and the single detection
# technique (a signature match, not error/boolean/time differentials).
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Detection-only, read-only, and REPORT ACCESS - DO NOT
# HARVEST CONTENTS: the probe never sends a write, and the finding's evidence
# names the marker and the (escaped) signature that matched, never the file's
# actual bytes. Every marker/template pair lives in modules/dast/payloads/ so
# it is auditable; a missing payload file degrades this check to a recorded
# coverage_reduction and never errors (docs/DESIGN.md §15).
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test": no parameter inventory, an uninjectable location, or a
# missing payload file are each recorded as a coverage_gap/coverage_reduction
# the report renders, exactly as modules/dast/active/sqli.sh does for its own
# gaps.
#
# THE INVENTORY IS READ DIRECTLY FROM THE RUN DIRECTORY, NOT FROM THE EXPORT
# ALONE. modules/dast/run.sh reads the inventory and exports
# SCOURSH_DAST_ENDPOINTS/SCOURSH_DAST_PARAMETERS BEFORE the phase loop starts,
# so on a first run - the ordinary case - both are EMPTY: crawl.sh writes
# reports/<run>/inventory/{endpoints,parameters}.json a few phases later in
# that same loop, and nothing re-reads the export afterwards. A phase that
# trusted the export alone would therefore see no surface on exactly the run
# that has just discovered one - the same pre-existing defect AGENTS.md
# records against active/sqli.sh today. This phase does not repeat it: it
# falls back to the run directory's own artifacts, the identical pattern
# modules/dast/passive/headers.sh already established for its own endpoint
# read. Fixing the export itself belongs to modules/dast/run.sh and is filed
# as its own ticket, not changed here.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes parameter/path syntax
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

# `_pt_read_lines_file FILE` - prints the file's non-comment, non-blank lines.
# Prints nothing and returns 0 when the file is unreadable, so a caller
# degrades gracefully by branching on the resulting empty array rather than on
# this function's own exit status - it is always called from inside a process
# substitution (`< <(...)`), and a genuine `return 1` there fires
# lib/core.sh's ERR trap even on this designed degradation path.
_pt_read_lines_file() {
  local f=$1 line
  [[ -r $f ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# `_pt_read_markers_file FILE` - loads `<relative-path><TAB><ERE signature>`
# lines into the parallel `_PT_MARKER_PATH`/`_PT_MARKER_SIG` arrays. Returns 1
# when the file is unreadable or carries no usable row.
_pt_read_markers_file() {
  local f=$1 rel sig
  _PT_MARKER_PATH=() _PT_MARKER_SIG=()
  [[ -r $f ]] || return 1
  while IFS=$'\t' read -r rel sig; do
    [[ -n $rel && -n $sig ]] || continue
    _PT_MARKER_PATH+=("$rel")
    _PT_MARKER_SIG+=("$sig")
  done < <(_pt_read_lines_file "$f")
  (( ${#_PT_MARKER_PATH[@]} > 0 ))
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`.
_pt_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_pt_probe_param INDEX BASE_VAL` - tries every (template, marker) pair on
# parameter INDEX, in order, and returns 0 on the FIRST response whose body
# matches that marker's own signature - `_PT_HIT_MARKER`/`_PT_HIT_SIG` are set
# to the winning pair. Returns 1 when nothing matched. One finding per
# (endpoint, parameter) pair: the first confirmed marker wins and the rest are
# never tried (docs/DESIGN.md §15's own bound reasoning applied here - once
# access is proven, sending the remaining combinations would only be more
# read access with nothing new to report).
_pt_probe_param() {
  local i=$1 base_val=$2 tmpl m rel sig payload
  for tmpl in "${_PT_TEMPLATES[@]+"${_PT_TEMPLATES[@]}"}"; do
    for (( m = 0; m < ${#_PT_MARKER_PATH[@]}; m++ )); do
      rel=${_PT_MARKER_PATH[$m]}; sig=${_PT_MARKER_SIG[$m]}
      payload=${tmpl//%M/$rel}
      inject_send "$i" "$payload" || continue
      if inject_body_has_signature "$_INJ_BODY" "$sig"; then
        _PT_HIT_MARKER=$rel
        _PT_HIT_SIG=$sig
        return 0
      fi
    done
  done
  return 1
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
_pt_emit() {
  local i=$1 marker=$2 sig=$3
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path authv=none
  path=$(_pt_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user

  finding_new
  finding_set check_id DAST-INJ-PATH_TRAVERSAL-01
  finding_set module dast
  finding_set title 'Path traversal via request parameter'
  finding_set base_severity high
  finding_set confidence high
  finding_set cwe CWE-22
  finding_set owasp A01:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Resolve every request-derived filename against a fixed base directory using the platform canonical-path check, and reject the request when the resolved path escapes that directory, rather than filtering "../" substrings. Prefer an indirect reference (an id looked up in a server-side allowlist or database) over accepting a path or filename from the client at all, and run the process under an account with no read access outside the intended content directory.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "a traversal value sent through parameter '$name' ($loc) of $method $path aimed at the benign marker file '$marker' produced a response whose body matched that marker's known-content signature /$sig/, which means the application read a file outside its intended directory. Detection only: the response was checked for the signature and discarded, and no file contents are included in this evidence."
  finding_emit
  return 0
}

_dast_pathtraversal_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/pathtraversal.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_PATHTRAVERSAL_PAYLOAD_DIR overrides the
  # location so an operator can vendor a custom set (the same swappable-seam
  # idiom active/sqli.sh's SCOURSH_DAST_SQLI_PAYLOAD_DIR uses) and so the
  # graceful-degradation branch is testable against an empty directory;
  # unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_PATHTRAVERSAL_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  declare -ga _PT_TEMPLATES=()
  local line
  while IFS= read -r line; do _PT_TEMPLATES+=("$line"); done < <(_pt_read_lines_file "$pdir/pathtraversal-sequences.txt")
  declare -ga _PT_MARKER_PATH=() _PT_MARKER_SIG=()
  _pt_read_markers_file "$pdir/pathtraversal-markers.txt" || true

  if (( ${#_PT_TEMPLATES[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=pathtraversal_payloads_missing target=$target - the directory-climb template file (modules/dast/payloads/pathtraversal-sequences.txt) is absent or empty, so path traversal did not run. This is a coverage reduction, not a clean result."
  fi
  if (( ${#_PT_MARKER_PATH[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=pathtraversal_markers_missing target=$target - the marker file (modules/dast/payloads/pathtraversal-markers.txt) is absent, empty, or carries no usable row, so path traversal had no signature to detect. This is a coverage reduction, not a clean result."
  fi
  if (( ${#_PT_TEMPLATES[@]} == 0 || ${#_PT_MARKER_PATH[@]} == 0 )); then
    run_record coverage_gap "dast pathtraversal: no directory-climb templates or no marker files are available on target '$target', so no path-traversal probe was sent. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  # tension-15 per-check selection: consulted only if dast_check_selected
  # exists (guarded like every peer probe), so this file does not hard-depend
  # on it.
  if declare -F dast_check_selected >/dev/null && ! dast_check_selected DAST-INJ-PATH_TRAVERSAL-01; then
    run_record coverage_reduction "module=dast reason=check_not_selected check=DAST-INJ-PATH_TRAVERSAL-01 target=$target - excluded by --profile-scan/--intensity/--allow-intrusive filtering."
    return 0
  fi

  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE - see
  # this file's own header for why. Falls back to the run directory's own
  # artifacts, the same shape modules/dast/passive/headers.sh already uses for
  # its endpoint file.
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  local pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi

  inject_inventory_load "$epf" "$pf" pathtraversal
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so path traversal had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast pathtraversal: target '$target' has no known request parameters (query/body/JSON/header/path), so no path-traversal probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
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
      run_record notes "module=dast phase=pathtraversal target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_body tested=0 uninjectable=0 found=0
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

    # A baseline that already carries a marker's signature is noisy for this
    # parameter (the endpoint's normal, benign response happens to look like a
    # marker file - a synthetic or templated test fixture, most likely), so it
    # is skipped rather than reported: the signal has to be absent from the
    # baseline and present only after injection to mean anything.
    local baseline_noisy=0 mk
    for (( mk = 0; mk < ${#_PT_MARKER_SIG[@]}; mk++ )); do
      if inject_body_has_signature "$base_body" "${_PT_MARKER_SIG[$mk]}"; then
        baseline_noisy=1
        break
      fi
    done
    (( baseline_noisy )) && continue

    if _pt_probe_param "$i" "$base_val"; then
      _pt_emit "$i" "$_PT_HIT_MARKER" "$_PT_HIT_SIG"
      found=$(( found + 1 ))
    fi
  done

  # checks_run records the check only when it actually loaded and executed
  # over at least one parameter (AGENTS.md's own definition), which is the
  # honest input modules/dast/run.sh's coverage roll-up reads.
  (( tested > 0 )) && run_record checks_run DAST-INJ-PATH_TRAVERSAL-01

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast pathtraversal: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for path traversal. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=pathtraversal_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for path traversal here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast pathtraversal: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no path-traversal test was sent."
  fi

  log_info "dast pathtraversal: target '$target' - tested $tested of $_INJ_N parameter(s) for path traversal, $found confirmed"
  return 0
}

_dast_pathtraversal_phase
