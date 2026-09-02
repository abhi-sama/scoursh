#!/usr/bin/env bash
# modules/dast/active/cmdi.sh - the §7.3 OS command-injection PHASE, BOUNDED
# TIME-BASED (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-16, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the request composer, the timed send), which every §7.3
# probe reuses; this file is the command-injection-specific part: the vendored
# time-delay payloads and the latency-delta signal.
#
# WHY TIME-BASED ONLY (docs/DESIGN.md §7.3; this ticket's own scope). A blind
# command injection has no reliable in-band signal: command output is rarely
# reflected, and an error page is indistinguishable from ordinary input
# rejection. A bounded, injected DELAY is the one signal that is both universal
# (every shell can sleep) and unambiguous (the benign baseline does not sleep),
# so it is the technique this probe implements.
#
# BOUNDED IS LOAD-BEARING, AND WHY THAT IS SAFE. The delay this probe induces is
# the only cost it imposes on the target. `_CMDI_SLEEP_N` is clamped into 1..10
# seconds (default 3) BEFORE it is ever substituted into a payload, and every
# vendored payload is a single fixed `sleep`/`timeout`/`Start-Sleep` of exactly
# that many seconds - no loop, no amplification, no nested or unbounded wait (see
# modules/dast/payloads/cmdi-time-payloads.txt). A parameter is retested at most
# once. So the worst a run can do is delay an authorised target by a few seconds
# per parameter - a probe can never become a denial-of-service, which is exactly
# the non-destructive posture §7.3 (and the DAST-36 amendment) require.
#
# NON-DESTRUCTIVE, RESTATED. Detection-only. A sleep reads nothing, writes
# nothing, and exfiltrates nothing; it only makes the response arrive late, which
# is the signal. No payload runs a second command that touches the filesystem,
# the network, or process state.
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test": no parameter inventory, an uninjectable location, or a
# missing payload file are each recorded as a coverage_gap/coverage_reduction the
# report renders, exactly as modules/dast/active/sqli.sh does for its own gaps.
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

# `_cmdi_read_payload_file FILE` - prints the file's payload lines (dropping
# whole-line `#` comments and blanks). Prints nothing and returns 0 when the
# file is unreadable, so a caller degrades the technique by branching on the
# resulting empty array rather than on this function's own exit status - it is
# always called from inside a process substitution (`< <(...)`), and a genuine
# `return 1` there fires lib/core.sh's ERR trap even on this designed
# degradation path. One payload per line (modules/dast/payloads/README.md).
_cmdi_read_payload_file() {
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
_cmdi_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# ---------------------------------------------------------------------------
# Time-based blind command injection
# ---------------------------------------------------------------------------
# The signal is a latency DELTA over the baseline floor, not an absolute time: a
# naturally slow endpoint delays the baseline too, and only the injected sleep
# moves the delta. The baseline floor is the MINIMUM of two benign samples (the
# DAST-01 throttle inside http_request only ever ADDS delay, so the minimum is
# the closest estimate of real server time), and the injected time is the minimum
# of two samples for the same reason. Re-tests before flagging (docs/DESIGN.md
# §7.3 "time-based checks re-test to reduce false positives from jitter").
_cmdi_try_time() {
  local i=$1 base_val=$2 base_e1=$3 tmpl v e1 e2 mininj min_base thr n=$_CMDI_SLEEP_N
  inject_send "$i" "$base_val" || return 0
  min_base=$base_e1
  (( _INJ_ELAPSED_NS < min_base )) && min_base=$_INJ_ELAPSED_NS
  thr=$(( n * 1000000000 / 2 ))   # half the injected sleep, in nanoseconds
  for tmpl in "${_CMDI_TIME_PAYLOADS[@]+"${_CMDI_TIME_PAYLOADS[@]}"}"; do
    v=${tmpl//%B/$base_val}; v=${v//%N/$n}
    inject_send "$i" "$v" || continue
    e1=$_INJ_ELAPSED_NS
    (( e1 - min_base >= thr )) || continue
    inject_send "$i" "$v" || continue
    e2=$_INJ_ELAPSED_NS
    mininj=$e1; (( e2 < mininj )) && mininj=$e2
    if (( mininj - min_base >= thr )); then
      _cmdi_emit "$i" "${n}s"
      return 0
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh). One check id for this probe:
# DAST-INJ-CMDI_TIME-01. A command-injection time finding and a SQL-injection
# time finding on the SAME parameter are two findings, not a collision, because
# the check id is part of the fingerprint - which is exactly why each probe owns
# its own id under the shared `INJ` family.
_cmdi_emit() {
  local i=$1 detail=$2
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path evi authv=none
  path=$(_cmdi_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  evi="parameter '$name' ($loc) of $method $path delayed the response by about $detail when sent a bounded OS shell sleep payload, reproduced on retest and absent from the baseline latency - a time-based blind OS command injection, meaning request-derived data reaches a shell command line unescaped"

  finding_new
  finding_set check_id DAST-INJ-CMDI_TIME-01
  finding_set module dast
  finding_set title 'OS command injection (time-based blind) via request parameter'
  finding_set base_severity critical
  finding_set confidence medium
  finding_set cwe CWE-78
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Never pass request-derived data to a shell. Avoid shell interpreters (system/exec-with-a-shell/backticks) entirely; call the target program directly with an argument vector so no field is re-parsed by a shell. Where a shell is unavoidable, use a strict allow-list of permitted values rather than escaping, and run under a least-privilege account.'
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

_dast_cmdi_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/cmdi.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored payloads. SCOURSH_DAST_CMDI_PAYLOAD_DIR overrides the location
  # so an operator can vendor a custom set (the same swappable-seam idiom
  # lib/http.sh's transport/resolver hooks use) and so the graceful-degradation
  # branch is testable against an empty directory; unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_CMDI_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  # The bounded sleep, clamped into 1..10 seconds BEFORE substitution. This is
  # the DoS bound the ticket calls load-bearing: no payload can delay a target
  # for longer than this many seconds, whatever the operator sets.
  _CMDI_SLEEP_N=${SCOURSH_DAST_CMDI_SLEEP:-3}
  [[ $_CMDI_SLEEP_N =~ ^[0-9]+$ ]] || _CMDI_SLEEP_N=3
  (( _CMDI_SLEEP_N < 1 )) && _CMDI_SLEEP_N=1
  (( _CMDI_SLEEP_N > 10 )) && _CMDI_SLEEP_N=10

  # Load the vendored payloads, degrading the technique when its file is absent
  # (a broken install, or a deliberately trimmed one).
  local line
  _CMDI_TIME_PAYLOADS=()
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    _CMDI_TIME_PAYLOADS+=("$line")
  done < <(_cmdi_read_payload_file "$pdir/cmdi-time-payloads.txt")

  local do_time=1
  # tension-15 per-check selection: consulted only if dast_check_selected exists
  # (guarded like the auth wiring), so this file does not hard-depend on it -
  # absent, everything the tier already permitted runs (the "empty means all
  # selected" fallback a direct-engine test relies on).
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-CMDI_TIME-01 || do_time=0
  fi
  if (( ${#_CMDI_TIME_PAYLOADS[@]} == 0 )); then
    do_time=0
    run_record coverage_reduction "module=dast reason=cmdi_payloads_missing technique=time target=$target - the time-based command-injection payload file under modules/dast/payloads/ is absent or empty, so that technique did not run. This is a coverage reduction, not a clean result."
  fi
  if (( do_time == 0 )); then
    run_record coverage_gap "dast cmdi: no command-injection payloads are available (or the check was deselected) on target '$target', so no probe ran. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  inject_inventory_load '' '' cmdi
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so command injection had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast cmdi: target '$target' has no known request parameters (query/body/JSON/header/path), so no command-injection probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
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
      run_record notes "module=dast phase=cmdi target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc base_val base_e tested=0 uninjectable=0
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
    base_e=$_INJ_ELAPSED_NS
    tested=$(( tested + 1 ))
    _cmdi_try_time "$i" "$base_val" "$base_e"
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), the honest input modules/dast/run.sh's roll-up reads - recorded
  # only when the technique actually ran over at least one parameter, so a run
  # with a parameter surface but no coverage is not reported as covered.
  if (( tested > 0 )); then
    run_record checks_run DAST-INJ-CMDI_TIME-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast cmdi: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for command injection. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=cmdi_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for command injection here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast cmdi: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every baseline request failed), so no command-injection test was sent."
  fi

  log_info "dast cmdi: target '$target' - tested $tested of $_INJ_N parameter(s) for time-based command injection (sleep=${_CMDI_SLEEP_N}s)"
  return 0
}

_dast_cmdi_phase
