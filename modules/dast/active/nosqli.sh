#!/usr/bin/env bash
# modules/dast/active/nosqli.sh - the §7.3 NoSQL-injection PHASE:
# operator/object injection and a syntax-error/boolean response differential
# (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-21, tier 4).
#
# This is a PHASE SCRIPT, exactly like modules/dast/active/ldapi.sh and
# active/sqli.sh: modules/dast/engine.sh's `dast_run_phase` reaches it with a
# plain `source` (at tier `active`, so it does not run below `--intensity
# active`), so it inherits the whole run context and anything it emits lands
# in this process's shard. Per that function's contract it carries NO
# sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh
# (the inventory reader, the request composer, the response signals), which
# every §7.3 probe reuses; this file is the NoSQL-specific part: the two
# techniques and their vendored payloads.
#
# TWO TECHNIQUES, MATCHING §7.3's OWN WORDING ("operator/object injection
# ... and syntax-error differentials; boolean/response-diff detection"):
#   (a) error-based - a syntax-breaking value (an unbalanced quote/brace, a
#       bare `$`-operator key) provokes a NoSQL driver/ODM error, or a JS
#       parse/runtime error from a `$where` expression, that the benign
#       baseline did not produce;
#   (b) boolean-based - an always-matching injected condition behaves like
#       the benign baseline while an otherwise-impossible one does not,
#       confirmed on retest. This covers BOTH shapes §7.3 names: a `$where`
#       JS string-context tautology (AND-based, mirroring
#       sqli-boolean-pairs.txt's safety discipline - narrows nothing, never
#       an OR-true that widens the result set) for an app that concatenates
#       the value into a predicate, and a standalone comparison-operator
#       object literal (e.g. `{"$gte":""}`) that replaces the parameter's
#       value outright, for an app that deserialises the raw parameter
#       string as a query/filter fragment. See
#       modules/dast/payloads/nosqli-boolean-pairs.txt's own header for the
#       full reasoning on both shapes.
#
# There is deliberately NO time-based technique, the same reasoning
# active/ldapi.sh states for LDAP: MongoDB's `$where` runs arbitrary JS and
# COULD in principle sleep, but no comparison-operator object literal (the
# other half of this probe, and the shape most real-world NoSQL APIs expose
# to a request parameter) has one, and inventing a JS-`sleep`-only technique
# here would test a narrower surface than the other two while claiming parity
# with them - overstated coverage docs/DESIGN.md §15 forbids. Two techniques,
# not three, and this file says so rather than silently running fewer than it
# claims.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Detection-only. Every payload is a QUERY/read - a broken
# expression, a wildcard-shaped comparison operator, an always/never-matching
# clause - never a write operator (`$set`, `$unset`, `$push`, `$pull`,
# `$inc`, `$rename`, `update`/`remove`/`delete`/`drop`), and never
# exfiltration beyond the minimal evidence that confirms the signal. Every
# payload is read-only and lives in modules/dast/payloads/ so it is auditable
# (docs/DESIGN.md §7.3 "Payloads live in payloads/"); a missing payload file
# degrades that one technique to a recorded coverage_reduction and never
# errors (docs/DESIGN.md §15).
#
# HONESTY. A clean result here must never read as "tested and safe" when it
# is "could not test": no parameter inventory, an uninjectable location, or a
# missing payload file are each recorded as a coverage_gap/coverage_reduction
# the report renders, exactly as modules/dast/active/ldapi.sh does for its
# own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence/remediation prose quotes NoSQL operator and
# parameter syntax ($where, $ne, {"$gte":""}, ...) literally.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run
# attaches nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# `_nosqli_read_payload_file FILE` - prints the file's payload lines
# (dropping whole-line `#` comments and blanks). Prints nothing and returns 0
# when the file is unreadable, so a caller degrades the technique by branching
# on the resulting empty array rather than on this function's own exit status
# - it is always called from inside a process substitution (`< <(...)`), and a
# genuine `return 1` there fires lib/core.sh's ERR trap even on this designed
# degradation path.
_nosqli_read_payload_file() {
  local f=$1 line
  [[ -r $f ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`.
_nosqli_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_nosqli_similar STATUS_A SIGLEN_A STATUS_B SIGLEN_B` - two responses are
# "the same" when the status matches and the payload-stripped body lengths
# are within tolerance (inject_len_similar).
_nosqli_similar() {
  [[ $1 == "$3" ]] || return 1
  inject_len_similar "$2" "$4"
}

# ---------------------------------------------------------------------------
# Technique (a): error-based
# ---------------------------------------------------------------------------
# A NoSQL driver/ODM/JS error signature that appears in an injected response
# but NOT in the benign baseline is the signal. If the baseline ALREADY shows
# a signature the endpoint is noisy and the technique is unreliable for it,
# so it is skipped rather than reported. Emits at most one finding per
# parameter.
_nosqli_try_error() {
  local i=$1 base_val=$2 base_body=$3 tmpl v sig
  for sig in "${_NOSQLI_ERR_SIGS[@]+"${_NOSQLI_ERR_SIGS[@]}"}"; do
    inject_body_has_signature "$base_body" "$sig" && return 0
  done
  for tmpl in "${_NOSQLI_ERR_PAYLOADS[@]+"${_NOSQLI_ERR_PAYLOADS[@]}"}"; do
    v=${tmpl//%B/$base_val}
    inject_send "$i" "$v" || continue
    for sig in "${_NOSQLI_ERR_SIGS[@]+"${_NOSQLI_ERR_SIGS[@]}"}"; do
      if inject_body_has_signature "$_INJ_BODY" "$sig"; then
        _nosqli_emit "$i" error "$sig"
        return 0
      fi
    done
  done
  return 0
}

# ---------------------------------------------------------------------------
# Technique (b): boolean-based (response differential)
# ---------------------------------------------------------------------------
# `_nosqli_bool_signal INDEX VT VF BASE_STATUS BASE_SIG` - 0 when the
# always-match payload behaves like the benign baseline, the never-match
# payload differs from the baseline, and the two differ from each other.
# Sends two requests.
_nosqli_bool_signal() {
  local i=$1 vt=$2 vf=$3 base_status=$4 base_sig=$5 st sf sig_t sig_f
  inject_send "$i" "$vt" || return 1
  st=$_INJ_STATUS; inject_body_sig "$_INJ_BODY" "$vt"; sig_t=$_INJ_SIG_LEN
  inject_send "$i" "$vf" || return 1
  sf=$_INJ_STATUS; inject_body_sig "$_INJ_BODY" "$vf"; sig_f=$_INJ_SIG_LEN
  _nosqli_similar "$st" "$sig_t" "$base_status" "$base_sig" || return 1   # true ~ baseline
  _nosqli_similar "$sf" "$sig_f" "$base_status" "$base_sig" && return 1   # false must differ from baseline
  _nosqli_similar "$st" "$sig_t" "$sf" "$sig_f" && return 1               # true must differ from false
  return 0
}

_nosqli_try_boolean() {
  local i=$1 base_val=$2 base_status=$3 base_sig=$4 k vt vf
  for (( k = 0; k < ${#_NOSQLI_BOOL_TRUE[@]}; k++ )); do
    vt=${_NOSQLI_BOOL_TRUE[$k]//%B/$base_val}
    vf=${_NOSQLI_BOOL_FALSE[$k]//%B/$base_val}
    if _nosqli_bool_signal "$i" "$vt" "$vf" "$base_status" "$base_sig"; then
      # Confirm on a retest before flagging (a one-off content difference is
      # jitter, not a differential).
      if _nosqli_bool_signal "$i" "$vt" "$vf" "$base_status" "$base_sig"; then
        _nosqli_emit "$i" boolean ''
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
# than one - so an error and a boolean finding on the same parameter are two
# findings, not a fingerprint collision the merge would silently dedupe.
_nosqli_emit() {
  local i=$1 technique=$2 detail=$3
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title base conf evi authv=none
  path=$(_nosqli_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $technique in
    error)
      check=DAST-INJ-NOSQLI_ERROR-01; base=high; conf=high
      title='NoSQL injection (error-based) via request parameter'
      evi="a NoSQL driver, ODM, or \$where JS runtime error surfaced when parameter '$name' ($loc) of $method $path received a syntax-breaking value but not for the benign baseline; the error matched the signature /$detail/, which means request-derived data reaches a NoSQL query or a \$where expression without escaping" ;;
    boolean)
      check=DAST-INJ-NOSQLI_BOOLEAN-01; base=critical; conf=medium
      title='NoSQL injection (operator/object injection, boolean-based) via request parameter'
      evi="parameter '$name' ($loc) of $method $path returned the baseline response for an always-matching injected condition (a \$where tautology or a comparison-operator object literal) and a materially different response for an otherwise-identical never-matching one, reproduced on retest - a boolean NoSQL-injection differential" ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe CWE-943
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never build a NoSQL query, `$where` expression, or filter object directly from request-derived data. Use the driver'"'"'s parameterised query builder so a request value is always bound as a literal, never as an operator key or JS fragment; reject a request parameter outright when the field expects a scalar and the received value is an object/array (an operator-injection object literal like `{"$ne":null}` arriving where a string is expected); and disable `$where`/server-side JS evaluation entirely unless a specific query genuinely requires it.'
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

_dast_nosqli_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/nosqli.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_NOSQLI_PAYLOAD_DIR overrides the
  # location so an operator can vendor a custom set (the same swappable-seam
  # idiom lib/http.sh's transport/resolver hooks use) and so the graceful-
  # degradation branch is testable against an empty directory; unset, it is
  # the shipped set.
  local pdir=${SCOURSH_DAST_NOSQLI_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}

  # Load the vendored payloads, degrading each technique independently when
  # its file is absent (a broken install, or a deliberately trimmed one).
  local line
  _NOSQLI_ERR_SIGS=() _NOSQLI_ERR_PAYLOADS=() _NOSQLI_BOOL_TRUE=() _NOSQLI_BOOL_FALSE=()
  while IFS= read -r line; do _NOSQLI_ERR_SIGS+=("$line"); done < <(_nosqli_read_payload_file "$pdir/nosqli-error-signatures.txt")
  while IFS= read -r line; do _NOSQLI_ERR_PAYLOADS+=("$line"); done < <(_nosqli_read_payload_file "$pdir/nosqli-error-payloads.txt")
  local tt ft
  while IFS=$'\t' read -r tt ft; do
    [[ -n $tt && -n $ft ]] || continue
    _NOSQLI_BOOL_TRUE+=("$tt"); _NOSQLI_BOOL_FALSE+=("$ft")
  done < <(_nosqli_read_payload_file "$pdir/nosqli-boolean-pairs.txt")

  local do_error=1 do_boolean=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it. Consulted only if that function exists (guarded like the auth
  # wiring), so this file does not hard-depend on it: absent, everything the
  # tier already permitted runs, which is the same "empty means all selected"
  # fallback a direct-engine test relies on.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-NOSQLI_ERROR-01 || do_error=0
    dast_check_selected DAST-INJ-NOSQLI_BOOLEAN-01 || do_boolean=0
  fi
  if (( ${#_NOSQLI_ERR_PAYLOADS[@]} == 0 || ${#_NOSQLI_ERR_SIGS[@]} == 0 )); then
    do_error=0
    run_record coverage_reduction "module=dast reason=nosqli_payloads_missing technique=error target=$target - the error-based NoSQL-injection payload or signature file under modules/dast/payloads/ is absent or empty, so that technique did not run. This is a coverage reduction, not a clean result."
  fi
  if (( ${#_NOSQLI_BOOL_TRUE[@]} == 0 )); then
    do_boolean=0
    run_record coverage_reduction "module=dast reason=nosqli_payloads_missing technique=boolean target=$target - the boolean-pair payload file under modules/dast/payloads/ is absent or empty, so that technique did not run."
  fi
  if (( do_error == 0 && do_boolean == 0 )); then
    run_record coverage_gap "dast nosqli: no NoSQL-injection payloads are available on target '$target', so no technique ran. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  inject_inventory_load '' '' nosqli
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so NoSQL injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast nosqli: target '$target' has no known request parameters (query/body/JSON/header/path), so no NoSQL-injection probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
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
      run_record notes "module=dast phase=nosqli target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_status base_body base_sig tested=0 uninjectable=0
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    if [[ $loc == graphql ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_val=$(inject_benign_value "$i")
    if ! inject_send "$i" "$base_val"; then
      # An uninjectable location (a path parameter with no template slot) or
      # a transport failure on the baseline: nothing to differentiate
      # against.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_status=$_INJ_STATUS
    base_body=$_INJ_BODY
    inject_body_sig "$base_body" "$base_val"; base_sig=$_INJ_SIG_LEN
    tested=$(( tested + 1 ))

    (( do_error )) && _nosqli_try_error "$i" "$base_val" "$base_body"
    (( do_boolean )) && _nosqli_try_boolean "$i" "$base_val" "$base_status" "$base_sig"
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up
  # reads - recorded only for techniques that actually ran over at least one
  # parameter, so a run with a parameter surface but no coverage is not
  # reported as covered.
  if (( tested > 0 )); then
    (( do_error )) && run_record checks_run DAST-INJ-NOSQLI_ERROR-01
    (( do_boolean )) && run_record checks_run DAST-INJ-NOSQLI_BOOLEAN-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast nosqli: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for NoSQL injection. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=nosqli_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for NoSQL injection here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast nosqli: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no NoSQL-injection test was sent."
  fi

  log_info "dast nosqli: target '$target' - tested $tested of $_INJ_N parameter(s) for NoSQL injection (error=$do_error boolean=$do_boolean)"
  return 0
}

_dast_nosqli_phase
