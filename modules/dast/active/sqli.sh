#!/usr/bin/env bash
# modules/dast/active/sqli.sh - the §7.3 SQL-injection PHASE (error-based,
# boolean-based, and time-based blind) (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-14, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the request composer, the response signals), which every
# §7.3 probe reuses; this file is the SQLi-specific part: the three techniques
# and their vendored payloads.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Detection-only. No data modification, no destructive
# payload, no exfiltration beyond the minimal evidence that confirms the signal:
#   (a) error-based - a syntax-breaking value provokes a DB error signature that
#       the benign baseline did not;
#   (b) boolean-based - an always-true condition behaves like the baseline while
#       an otherwise-identical always-false one does not, confirmed on retest;
#   (c) time-based blind - a bounded sleep payload delays the response past a
#       threshold, reproduced on retest, over the baseline latency floor.
# Every payload is read-only and lives in modules/dast/payloads/ so it is
# auditable (docs/DESIGN.md §7.3 "Payloads live in payloads/"); a missing payload
# file degrades that one technique to a recorded coverage_reduction and never
# errors (docs/DESIGN.md §15).
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test": no parameter inventory, an uninjectable location, or a
# missing payload file are each recorded as a coverage_gap/coverage_reduction the
# report renders, exactly as modules/dast/auth.sh and crawl.sh do for their own
# gaps.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run attaches
# nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# `_sqli_read_payload_file FILE` - prints the file's payload lines (dropping
# whole-line `#` comments and blanks). Returns 1 when the file is unreadable, so
# a caller degrades the technique rather than erroring.
_sqli_read_payload_file() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`.
_sqli_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_sqli_similar STATUS_A SIGLEN_A STATUS_B SIGLEN_B` - two responses are "the
# same" when the status matches and the payload-stripped body lengths are within
# tolerance (inject_len_similar).
_sqli_similar() {
  [[ $1 == "$3" ]] || return 1
  inject_len_similar "$2" "$4"
}

# ---------------------------------------------------------------------------
# Technique (a): error-based
# ---------------------------------------------------------------------------
# A DB error signature that appears in an injected response but NOT in the
# benign baseline is the signal. If the baseline ALREADY shows a signature the
# endpoint is noisy and the technique is unreliable for it, so it is skipped
# rather than reported. Emits at most one finding per parameter.
_sqli_try_error() {
  local i=$1 base_val=$2 base_body=$3 tmpl v sig
  for sig in "${_SQLI_ERR_SIGS[@]+"${_SQLI_ERR_SIGS[@]}"}"; do
    inject_body_has_signature "$base_body" "$sig" && return 0
  done
  for tmpl in "${_SQLI_ERR_PAYLOADS[@]+"${_SQLI_ERR_PAYLOADS[@]}"}"; do
    v=${tmpl//%B/$base_val}
    inject_send "$i" "$v" || continue
    for sig in "${_SQLI_ERR_SIGS[@]+"${_SQLI_ERR_SIGS[@]}"}"; do
      if inject_body_has_signature "$_INJ_BODY" "$sig"; then
        _sqli_emit "$i" error "$sig"
        return 0
      fi
    done
  done
  return 0
}

# ---------------------------------------------------------------------------
# Technique (b): boolean-based
# ---------------------------------------------------------------------------
# `_sqli_bool_signal INDEX VT VF BASE_STATUS BASE_SIG` - 0 when the true payload
# behaves like the baseline, the false payload differs from the baseline, and
# the two differ from each other. Sends two requests.
_sqli_bool_signal() {
  local i=$1 vt=$2 vf=$3 base_status=$4 base_sig=$5 st sf sig_t sig_f
  inject_send "$i" "$vt" || return 1
  st=$_INJ_STATUS; inject_body_sig "$_INJ_BODY" "$vt"; sig_t=$_INJ_SIG_LEN
  inject_send "$i" "$vf" || return 1
  sf=$_INJ_STATUS; inject_body_sig "$_INJ_BODY" "$vf"; sig_f=$_INJ_SIG_LEN
  _sqli_similar "$st" "$sig_t" "$base_status" "$base_sig" || return 1   # true ~ baseline
  _sqli_similar "$sf" "$sig_f" "$base_status" "$base_sig" && return 1   # false must differ from baseline
  _sqli_similar "$st" "$sig_t" "$sf" "$sig_f" && return 1              # true must differ from false
  return 0
}

_sqli_try_boolean() {
  local i=$1 base_val=$2 base_status=$3 base_sig=$4 k vt vf
  for (( k = 0; k < ${#_SQLI_BOOL_TRUE[@]}; k++ )); do
    vt=${_SQLI_BOOL_TRUE[$k]//%B/$base_val}
    vf=${_SQLI_BOOL_FALSE[$k]//%B/$base_val}
    if _sqli_bool_signal "$i" "$vt" "$vf" "$base_status" "$base_sig"; then
      # Confirm on a retest before flagging (a one-off content difference is
      # jitter, not a differential).
      if _sqli_bool_signal "$i" "$vt" "$vf" "$base_status" "$base_sig"; then
        _sqli_emit "$i" boolean ''
        return 0
      fi
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Technique (c): time-based blind
# ---------------------------------------------------------------------------
# The signal is a latency DELTA over the baseline floor, not an absolute time:
# a naturally slow endpoint delays the baseline too, and only the injected sleep
# moves the delta. The baseline floor is the MINIMUM of two benign samples
# (the DAST-01 throttle inside http_request only ever ADDS delay, so the minimum
# is the closest estimate of real server time), and the injected time is the
# minimum of two samples for the same reason. Re-tests before flagging
# (docs/DESIGN.md §7.3 "time-based checks re-test to reduce false positives from
# jitter").
_sqli_try_time() {
  local i=$1 base_val=$2 base_e1=$3 tmpl v e1 e2 mininj min_base thr n=$_SQLI_SLEEP_N
  inject_send "$i" "$base_val" || return 0
  min_base=$base_e1
  (( _INJ_ELAPSED_NS < min_base )) && min_base=$_INJ_ELAPSED_NS
  thr=$(( n * 1000000000 / 2 ))   # half the injected sleep, in nanoseconds
  for tmpl in "${_SQLI_TIME_PAYLOADS[@]+"${_SQLI_TIME_PAYLOADS[@]}"}"; do
    v=${tmpl//%B/$base_val}; v=${v//%N/$n}
    inject_send "$i" "$v" || continue
    e1=$_INJ_ELAPSED_NS
    (( e1 - min_base >= thr )) || continue
    inject_send "$i" "$v" || continue
    e2=$_INJ_ELAPSED_NS
    mininj=$e1; (( e2 < mininj )) && mininj=$e2
    if (( mininj - min_base >= thr )); then
      _sqli_emit "$i" time "${n}s"
      return 0
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh); the TECHNIQUE is not part of
# identity, which is exactly why the three techniques are three check ids rather
# than one - so a boolean and a time finding on the same parameter are two
# findings, not a fingerprint collision the merge would silently dedupe.
_sqli_emit() {
  local i=$1 technique=$2 detail=$3
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title base conf evi authv=none
  path=$(_sqli_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $technique in
    error)
      check=DAST-INJ-SQLI_ERROR-01; base=high; conf=high
      title='SQL injection (error-based) via request parameter'
      evi="a database error surfaced when parameter '$name' ($loc) of $method $path received a syntax-breaking value but not for the benign baseline; the driver error matched the signature /$detail/, which means request-derived data reaches SQL text unparameterised" ;;
    boolean)
      check=DAST-INJ-SQLI_BOOLEAN-01; base=critical; conf=medium
      title='SQL injection (boolean-based) via request parameter'
      evi="parameter '$name' ($loc) of $method $path returned the baseline response for an always-true injected condition and a materially different response for an otherwise-identical always-false one, reproduced on retest - a boolean SQL-injection differential" ;;
    time)
      check=DAST-INJ-SQLI_TIME-01; base=critical; conf=medium
      title='SQL injection (time-based blind) via request parameter'
      evi="parameter '$name' ($loc) of $method $path delayed the response by about $detail when sent a bounded SQL sleep payload, reproduced on retest and absent from the baseline latency - a time-based blind SQL injection" ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe CWE-89
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Use parameterised queries (prepared statements) or an ORM that binds request-derived values, so a request parameter can never be interpolated into SQL text. Add server-side input validation, run the application under a least-privilege database account, and return a generic error so a driver message never reaches the client.'
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

_dast_sqli_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/sqli.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_SQLI_PAYLOAD_DIR overrides the location
  # so an operator can vendor a custom set (the same swappable-seam idiom
  # lib/http.sh's transport/resolver hooks use) and so the graceful-degradation
  # branch is testable against an empty directory; unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_SQLI_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  _SQLI_SLEEP_N=${SCOURSH_DAST_SQLI_SLEEP:-3}
  [[ $_SQLI_SLEEP_N =~ ^[0-9]+$ ]] || _SQLI_SLEEP_N=3
  (( _SQLI_SLEEP_N < 1 )) && _SQLI_SLEEP_N=1
  (( _SQLI_SLEEP_N > 10 )) && _SQLI_SLEEP_N=10

  # Load the vendored payloads, degrading each technique independently when its
  # file is absent (a broken install, or a deliberately trimmed one).
  local line
  _SQLI_ERR_SIGS=() _SQLI_ERR_PAYLOADS=() _SQLI_BOOL_TRUE=() _SQLI_BOOL_FALSE=() _SQLI_TIME_PAYLOADS=()
  while IFS= read -r line; do _SQLI_ERR_SIGS+=("$line"); done < <(_sqli_read_payload_file "$pdir/sqli-error-signatures.txt")
  while IFS= read -r line; do _SQLI_ERR_PAYLOADS+=("$line"); done < <(_sqli_read_payload_file "$pdir/sqli-error-payloads.txt")
  while IFS= read -r line; do _SQLI_TIME_PAYLOADS+=("$line"); done < <(_sqli_read_payload_file "$pdir/sqli-time-payloads.txt")
  local tt ft
  while IFS=$'\t' read -r tt ft; do
    [[ -n $tt && -n $ft ]] || continue
    _SQLI_BOOL_TRUE+=("$tt"); _SQLI_BOOL_FALSE+=("$ft")
  done < <(_sqli_read_payload_file "$pdir/sqli-boolean-pairs.txt")

  local do_error=1 do_boolean=1 do_time=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it, and it now EXISTS - so a technique the operator filtered out
  # genuinely sends no payload, which is the whole point of gating an OUTBOUND
  # probe on the check set rather than only the report on it.
  #
  # The `declare -F` guard is KEPT deliberately: tests/suites/dast-sqli.sh
  # sources this file with no modules/dast/engine.sh in the process, and an
  # unguarded call there would be exit 127 - non-zero, so all three techniques
  # would read as deselected and the phase would go inert while the suite
  # stayed green.  Absent reader means all selected, exactly as an absent list
  # does.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-SQLI_ERROR-01 || do_error=0
    dast_check_selected DAST-INJ-SQLI_BOOLEAN-01 || do_boolean=0
    dast_check_selected DAST-INJ-SQLI_TIME-01 || do_time=0
  fi
  if (( ${#_SQLI_ERR_PAYLOADS[@]} == 0 || ${#_SQLI_ERR_SIGS[@]} == 0 )); then
    do_error=0
    run_record coverage_reduction "module=dast reason=sqli_payloads_missing technique=error target=$target - the error-based SQLi payload or signature file under modules/dast/payloads/ is absent or empty, so that technique did not run. This is a coverage reduction, not a clean result."
  fi
  if (( ${#_SQLI_BOOL_TRUE[@]} == 0 )); then
    do_boolean=0
    run_record coverage_reduction "module=dast reason=sqli_payloads_missing technique=boolean target=$target - the boolean-pair payload file under modules/dast/payloads/ is absent or empty, so that technique did not run."
  fi
  if (( ${#_SQLI_TIME_PAYLOADS[@]} == 0 )); then
    do_time=0
    run_record coverage_reduction "module=dast reason=sqli_payloads_missing technique=time target=$target - the time-based payload file under modules/dast/payloads/ is absent or empty, so that technique did not run."
  fi
  if (( do_error == 0 && do_boolean == 0 && do_time == 0 )); then
    run_record coverage_gap "dast sqli: no SQL-injection payloads are available on target '$target', so no technique ran. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  inject_inventory_load
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so SQL injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast sqli: target '$target' has no known request parameters (query/body/JSON/header/path), so no SQL-injection probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained at least one session this run; otherwise the probe runs against the
  # public surface and attaches nothing.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=sqli target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_status base_body base_e base_sig tested=0 uninjectable=0
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    if [[ $loc == graphql ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_val=$(inject_benign_value "$i")
    if ! inject_send "$i" "$base_val"; then
      # An uninjectable location (a path parameter with no template slot) or a
      # transport failure on the baseline: nothing to differentiate against.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    base_status=$_INJ_STATUS
    base_body=$_INJ_BODY
    base_e=$_INJ_ELAPSED_NS
    inject_body_sig "$base_body" "$base_val"; base_sig=$_INJ_SIG_LEN
    tested=$(( tested + 1 ))

    (( do_error )) && _sqli_try_error "$i" "$base_val" "$base_body"
    (( do_boolean )) && _sqli_try_boolean "$i" "$base_val" "$base_status" "$base_sig"
    (( do_time )) && _sqli_try_time "$i" "$base_val" "$base_e"
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up reads -
  # recorded only for techniques that actually ran over at least one parameter,
  # so a run with a parameter surface but no coverage is not reported as covered.
  if (( tested > 0 )); then
    (( do_error )) && run_record checks_run DAST-INJ-SQLI_ERROR-01
    (( do_boolean )) && run_record checks_run DAST-INJ-SQLI_BOOLEAN-01
    (( do_time )) && run_record checks_run DAST-INJ-SQLI_TIME-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast sqli: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for SQL injection. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=sqli_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for SQL injection here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast sqli: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no SQL-injection test was sent."
  fi

  log_info "dast sqli: target '$target' - tested $tested of $_INJ_N parameter(s) for SQL injection (error=$do_error boolean=$do_boolean time=$do_time)"
  return 0
}

_dast_sqli_phase
