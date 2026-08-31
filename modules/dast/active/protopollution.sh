#!/usr/bin/env bash
# modules/dast/active/protopollution.sh - the §7.3 prototype-pollution PHASE:
# submit `__proto__`/`constructor.prototype`-shaped JSON parameter values and
# detect a behavioural change that indicates the value reached
# Object.prototype on a JavaScript backend (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-25, tier 4).
#
# This is a PHASE SCRIPT, exactly like modules/dast/active/nosqli.sh and
# active/crlf.sh: modules/dast/engine.sh's `dast_run_phase` reaches it with a
# plain `source` (at tier `active`, so it does not run below `--intensity
# active`), so it inherits the whole run context and anything it emits lands
# in this process's shard. Per that function's contract it carries NO
# sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh
# (the inventory reader, the request composer, the response signals), which
# every §7.3 probe reuses; this file is the prototype-pollution-specific
# part: the two techniques and their vendored payloads.
#
# TWO TECHNIQUES, DETECTION VIA DIFFERENTIAL, NO DESTRUCTIVE PAYLOAD (the
# ticket's own wording, restated by docs/DESIGN.md §7.3 and the DAST-36
# amendment for DAST-14..DAST-25):
#
#   (a) error-based - a `__proto__`/`constructor.prototype`-shaped value
#       provokes a JS runtime or merge-library error signature (a write onto
#       a frozen Object.prototype property, a recursive-merge stack
#       overflow, ...) that a SHAPE-MATCHED CONTROL value - identical
#       nesting depth, an ordinary key instead of the special one - does
#       not. The control is what isolates the special key as the cause
#       rather than "this endpoint errors on any nested object", which the
#       pollute payload alone could never distinguish.
#
#   (b) marker-reflection - a `__proto__`/`constructor.prototype`-shaped
#       value carries a unique, per-run-random property name and value.
#       Object.prototype (and anything built with `for...in`/spread/
#       `Object.assign` semantics that walk INHERITED enumerable
#       properties, unlike JSON.stringify's own-properties-only walk) is
#       process-wide and outlives one request, so a SEPARATE, entirely
#       benign follow-up request to the SAME endpoint - one that never sent
#       the marker itself - is asked whether that exact marker now appears
#       in ITS response. Reproduced with a second, independent marker before
#       being reported, exactly as modules/dast/active/nosqli.sh confirms its
#       own boolean technique on retest. This is the stronger, more directly
#       confirmed signal of the two: it demonstrates actual persistent,
#       cross-request contamination of shared process state, not merely an
#       error text.
#
# NEITHER TECHNIQUE WRITES ANYTHING A TARGET WOULD CONSIDER DATA. The pollute
# value's leaf is an ordinary string (a literal `1`, or this run's own random
# marker); nothing here targets a database row, a file, or an account -
# Object.prototype is in-process JS runtime state, and observing that a
# later, unrelated request can read back a value THIS run itself planted is
# the whole of what technique (b) does. See
# modules/dast/payloads/protopollution-payloads.txt and
# modules/dast/payloads/protopollution-error-pairs.txt for the vendored
# templates and the full non-destructive reasoning
# (modules/dast/payloads/README.md).
#
# HONESTY. A clean result here must never read as "tested and safe" when it
# is "could not test": no parameter inventory, an uninjectable (graphql)
# location, or a missing payload file are each recorded as a
# coverage_gap/coverage_reduction the report renders, exactly as
# modules/dast/active/nosqli.sh does for its own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence/remediation prose quotes JS property syntax
# (__proto__, constructor.prototype, Object.prototype) literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run
# attaches nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# `_pp_read_payload_file FILE` - prints the file's payload lines (dropping
# whole-line `#` comments and blanks). Returns 1 when the file is unreadable,
# so a caller degrades the technique rather than erroring. Same helper, same
# contract, as every sibling probe's own `_*_read_payload_file`.
_pp_read_payload_file() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`. Same helper, same contract, as sibling probes' `_*_path_of`.
_pp_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_pp_marker_set` - this run's own per-attempt random marker: a property
# NAME (`_PP_MARKER_KEY`) and a property VALUE (`_PP_MARKER_VALUE`), mixing
# $RANDOM with $$ exactly as modules/dast/active/crlf.sh's own
# `_crlf_marker_set` does. Called fresh for every attempt (never reused
# across templates or across the confirm retest), so a hit can only be
# explained by THIS attempt's own poisoning request - a uniqueness label, not
# a secret.
_pp_marker_set() {
  local hex=''
  printf -v hex '%04x%04x%04x' "$(( RANDOM ))" "$(( RANDOM ))" "$(( RANDOM ^ $$ ))"
  _PP_MARKER_KEY="scourshpp${hex}"
  _PP_MARKER_VALUE="scoursh-pp-leak-${hex}"
}

# ---------------------------------------------------------------------------
# Technique (a): error-based differential
# ---------------------------------------------------------------------------
# If the baseline response already shows one of the error signatures the
# endpoint is noisy and the technique is unreliable for it, so it is skipped
# rather than reported - the same discipline
# modules/dast/active/nosqli.sh's `_nosqli_try_error` applies.
_pp_try_error() {
  local i=$1 base_body=$2 k pollute control sig hit poison_body
  for sig in "${_PP_ERR_SIGS[@]+"${_PP_ERR_SIGS[@]}"}"; do
    inject_body_has_signature "$base_body" "$sig" && return 0
  done
  for (( k = 0; k < ${#_PP_ERR_POLLUTE[@]}; k++ )); do
    pollute=${_PP_ERR_POLLUTE[$k]}
    control=${_PP_ERR_CONTROL[$k]}
    inject_send "$i" "$pollute" || continue
    poison_body=$_INJ_BODY
    hit=''
    for sig in "${_PP_ERR_SIGS[@]+"${_PP_ERR_SIGS[@]}"}"; do
      if inject_body_has_signature "$poison_body" "$sig"; then
        hit=$sig
        break
      fi
    done
    [[ -n $hit ]] || continue
    # The control is the SAME nesting depth with an ordinary key: if it
    # reproduces the identical signature, the error is a property of nested
    # objects in general on this parameter, not of the special key, and this
    # is not a prototype-pollution signal.
    inject_send "$i" "$control" || continue
    if ! inject_body_has_signature "$_INJ_BODY" "$hit"; then
      _pp_emit "$i" error "$hit"
      return 0
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Technique (b): marker-reflection (cross-request behavioural differential)
# ---------------------------------------------------------------------------
# `_pp_reflected_signal INDEX BASE_VAL TEMPLATE` - 0 when a poisoning request
# built from TEMPLATE (this attempt's own fresh marker) is followed by a
# SEPARATE, purely benign request to the SAME parameter, and that benign
# follow-up's response contains the marker VALUE. The follow-up itself never
# sends the marker anywhere, so its presence in the follow-up's own response
# can only be explained by state the poisoning request left behind.
_pp_reflected_signal() {
  local i=$1 base_val=$2 tmpl=$3 v
  _pp_marker_set
  v=${tmpl//%K/$_PP_MARKER_KEY}
  v=${v//%V/$_PP_MARKER_VALUE}
  inject_send "$i" "$v" || return 1
  inject_send "$i" "$base_val" || return 1
  [[ $_INJ_BODY == *"$_PP_MARKER_VALUE"* ]]
}

_pp_try_reflected() {
  local i=$1 base_val=$2 tmpl
  for tmpl in "${_PP_MARKER_TEMPLATES[@]+"${_PP_MARKER_TEMPLATES[@]}"}"; do
    if _pp_reflected_signal "$i" "$base_val" "$tmpl"; then
      # Confirm with a SECOND, independent marker before flagging - a
      # one-off coincidence (an echo endpoint, request-id logging) is not
      # cross-request contamination reproduced twice with two different
      # random values.
      if _pp_reflected_signal "$i" "$base_val" "$tmpl"; then
        _pp_emit "$i" reflected "$tmpl"
        return 0
      fi
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh); the TECHNIQUE is not part of
# identity, which is exactly why the two techniques are two check ids rather
# than one - so an error and a reflected finding on the same parameter are
# two findings, not a fingerprint collision the merge would silently dedupe.
# CWE-1321 ("Improper Filtering of Special Elements") is MITRE's dedicated id
# for this class (the `__proto__`/`constructor.prototype` special-element
# case), distinct from the generic injection CWEs sibling probes use.
_pp_emit() {
  local i=$1 technique=$2 detail=$3
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title base conf evi authv=none
  path=$(_pp_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $technique in
    error)
      check=DAST-INJ-PROTOPOLLUTION_ERROR-01; base=high; conf=high
      title='Prototype pollution (error-based) via __proto__/constructor.prototype request parameter'
      evi="parameter '$name' ($loc) of $method $path returned a JavaScript runtime/merge-library error signature (matching /$detail/) when sent a __proto__- or constructor.prototype-shaped JSON value, but did NOT reproduce that signature for a shape-matched control value (the identical nesting depth, an ordinary key in place of the special one) - isolating the special key, not merely a nested object, as the cause. This is the signature of an unguarded recursive merge/assign/clone reaching Object.prototype." ;;
    reflected)
      check=DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01; base=critical; conf=high
      title='Prototype pollution confirmed - a __proto__/constructor.prototype-injected property leaked into a later, unrelated response'
      evi="parameter '$name' ($loc) of $method $path was sent a __proto__/constructor.prototype-shaped value carrying a unique, per-run-random marker; a SEPARATE, entirely benign follow-up request to the same endpoint - one that never itself sent the marker - then returned that exact marker value in its own response. Reproduced with a second, independent marker before being reported. Only this run's own poisoning request can have put that value where a later, unrelated request could read it back, which means request-derived data reached and persisted in Object.prototype (or an equivalently shared, long-lived object), affecting every subsequent request this process serves." ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe CWE-1321
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never pass request-derived data straight into a recursive merge, assign, extend, or deep-clone function (a hand-rolled deep merge, or a library such as lodash before it patched this class of bug). Reject or strip the keys __proto__, constructor, and prototype from every level of any object built from request data before it reaches a merge, and prefer JSON.parse with a reviver that drops those keys over a naive parse-then-merge. Build request-derived option/config objects with Object.create(null) so they carry no prototype chain to pollute, and call Object.freeze(Object.prototype) at process startup as a defence in depth so an overlooked merge path fails closed instead of silently succeeding.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

_dast_protopollution_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/protopollution.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_PROTOPOLLUTION_PAYLOAD_DIR overrides
  # the location so an operator can vendor a custom set (the same
  # swappable-seam idiom every sibling probe's own payload-dir override
  # uses) and so the graceful-degradation branch is testable against an
  # empty directory; unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_PROTOPOLLUTION_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  local line pv cv

  _PP_MARKER_TEMPLATES=()
  while IFS= read -r line; do _PP_MARKER_TEMPLATES+=("$line"); done \
    < <(_pp_read_payload_file "$pdir/protopollution-payloads.txt" || true)

  _PP_ERR_SIGS=()
  while IFS= read -r line; do _PP_ERR_SIGS+=("$line"); done \
    < <(_pp_read_payload_file "$pdir/protopollution-error-signatures.txt" || true)

  _PP_ERR_POLLUTE=() _PP_ERR_CONTROL=()
  while IFS=$'\t' read -r pv cv; do
    [[ -n $pv && -n $cv ]] || continue
    _PP_ERR_POLLUTE+=("$pv"); _PP_ERR_CONTROL+=("$cv")
  done < <(_pp_read_payload_file "$pdir/protopollution-error-pairs.txt" || true)

  local do_error=1 do_reflected=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it. Consulted only if that function exists (guarded exactly as
  # every sibling probe guards it), so this file does not hard-depend on it:
  # absent, everything the tier already permitted runs.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-PROTOPOLLUTION_ERROR-01 || do_error=0
    dast_check_selected DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 || do_reflected=0
  fi

  if (( ${#_PP_ERR_POLLUTE[@]} == 0 || ${#_PP_ERR_SIGS[@]} == 0 )); then
    do_error=0
    run_record coverage_reduction "module=dast reason=protopollution_payloads_missing technique=error target=$target - the prototype-pollution error-pair or signature payload file under modules/dast/payloads/ is absent or empty, so that technique did not run. This is a coverage reduction, not a clean result."
  fi
  if (( ${#_PP_MARKER_TEMPLATES[@]} == 0 )); then
    do_reflected=0
    run_record coverage_reduction "module=dast reason=protopollution_payloads_missing technique=reflected target=$target - modules/dast/payloads/protopollution-payloads.txt is absent or empty, so the marker-reflection technique did not run."
  fi
  if (( do_error == 0 && do_reflected == 0 )); then
    run_record coverage_gap "dast protopollution: no prototype-pollution payloads are available on target '$target', so no technique ran. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  # modules/dast/run.sh resolves SCOURSH_DAST_ENDPOINTS/SCOURSH_DAST_PARAMETERS
  # BEFORE the phase loop starts while modules/dast/crawl.sh writes them
  # several phases LATER in that same loop, so on the ordinary run the
  # exports are empty on exactly the run that has just discovered a surface.
  # The run-directory artifact is read as a fallback, the same fix every
  # sibling probe applies for itself.
  local epf=${SCOURSH_DAST_ENDPOINTS:-} pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi
  inject_inventory_load "$epf" "$pf" protopollution
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so prototype-pollution probing had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast protopollution: target '$target' has no known request parameters (query/body/JSON/header/path), so no prototype-pollution probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
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
      run_record notes "module=dast phase=protopollution target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_body tested=0 uninjectable=0
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    # graphql is a structured operation body, not a scalar this probe
    # substitutes one field of - an honest "cannot test", never "tested and
    # clean".
    if [[ $loc == graphql ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_val=$(inject_benign_value "$i")
    if ! inject_send "$i" "$base_val"; then
      # An uninjectable location (a path parameter with no template slot) or
      # a transport failure on the baseline: nothing to differentiate
      # against, and no follow-up request this probe could trust.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_body=$_INJ_BODY
    tested=$(( tested + 1 ))

    (( do_error )) && _pp_try_error "$i" "$base_body"
    (( do_reflected )) && _pp_try_reflected "$i" "$base_val"
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up
  # reads - recorded only for techniques that actually ran over at least one
  # parameter, so a run with a parameter surface but no coverage is not
  # reported as covered.
  if (( tested > 0 )); then
    (( do_error )) && run_record checks_run DAST-INJ-PROTOPOLLUTION_ERROR-01
    (( do_reflected )) && run_record checks_run DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast protopollution: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for prototype pollution. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=protopollution_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation, a path segment with no template slot this probe could substitute, or an endpoint whose baseline request failed at the transport; they were not tested for prototype pollution here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast protopollution: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no prototype-pollution test was sent."
  fi

  log_info "dast protopollution: target '$target' - tested $tested of $_INJ_N parameter(s) for prototype pollution (error=$do_error reflected=$do_reflected)"
  return 0
}

_dast_protopollution_phase
