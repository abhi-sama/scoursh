#!/usr/bin/env bash
# modules/dast/auth.sh - the §7.0 session-acquisition PHASE
# (docs/DESIGN.md §7.0; docs/STEP5-DAST-PLAN.md DAST-03).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# therefore carries NO sourced-once guard - one run can legitimately reach the
# same phase twice (a second scope target, a second `scan_main` in one process)
# and a guard would silently make the second one a no-op.  The pure functions
# live in modules/dast/auth_engine.sh, which does have one; this file is the
# part that DOES something.
#
# WHAT THIS PHASE OWES ITS READER.  It is the first DAST phase to exist, so it
# is also the first that can leave a run looking like it tested something it did
# not.  Every path below that ends without a session records WHY, as a
# `coverage_reduction` (the machine-readable declared reduction) and, where a
# human needs the sentence, as a `coverage_gap` that lib/report.sh renders into
# the limitations section of run.json, report.md and report.html.  A scan that
# quietly loses its session and reports no findings is the dishonesty
# docs/DESIGN.md §15 exists to forbid, and this file is where it would start.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/auth_engine.sh"

_dast_auth_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local authed=${SCOURSH_DAST_AUTHED:-false}
  local intrusive=${SCOURSH_DAST_ALLOW_INTRUSIVE:-false}
  local label rc conf responses=0 ok=0 failed=0
  local -a labels=()

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/auth.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # --authed is what asks for an authenticated scan, and without it this phase
  # sends nothing at all: acquiring a session nobody asked for would put a
  # credential on the wire on a run whose whole point was to read what the
  # target already volunteers.  It is still RECORDED, because "no authenticated
  # check ran" is a fact about this run's coverage rather than a non-event.
  if [[ $authed != true ]]; then
    run_record coverage_reduction "module=dast reason=authed_not_requested target=$target - --authed was not given, so no session was acquired and every check that needs one is skipped. No credential was sent."
    return 0
  fi

  conf=$(dast_auth_conf_path)
  if ! dast_auth_load; then
    # docs/FOUNDATION.md tension 14 classes "a check skipped for an absent
    # requires-config" as a DECLARED reduction, so an --authed run with no
    # config/auth.conf is not an error - it is a run that cannot do the
    # authenticated half and says so.  rules/RULE-FORMAT.md §9.5's own
    # `requires-config` wording is identical: "Absent means the check is skipped
    # with a run.json reason, not an error."
    run_record coverage_reduction "module=dast reason=auth_config_absent target=$target file=$conf - --authed was requested but there is no config/auth.conf, so no identity could be authenticated."
    run_record coverage_gap "dast auth: --authed was requested for target '$target' but $conf does not exist, so no session was acquired and every authenticated check is skipped. Nothing here tested authenticated behaviour; a clean result is the absence of a test, not the absence of a problem. See rules/RULE-FORMAT.md §9.6.2 for the file's format."
    dast_auth_enum_gap "$target" 0
    return 0
  fi

  dast_auth_labels_set "$target"
  labels=("${_DAST_AUTH_LABELS[@]+"${_DAST_AUTH_LABELS[@]}"}")
  if (( ${#labels[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_identity_for_target target=$target file=$conf - config/auth.conf exists but declares no identity whose id begins '$target.', so no session was acquired."
    run_record coverage_gap "dast auth: $conf declares no identity for target '$target' (an id is '<target-id>.<label>', rules/RULE-FORMAT.md §9.6.2), so every authenticated check on it is skipped."
    dast_auth_enum_gap "$target" 0
    return 0
  fi

  for label in "${labels[@]+"${labels[@]}"}"; do
    rc=0
    dast_auth_acquire "$target" "$label" || rc=$?
    responses=$(( responses + ${_DAST_AUTH_RESPONSE_COUNT:-0} ))
    if (( rc == 0 )); then
      ok=$(( ok + 1 ))
      # The MODE and the identity, never the credential and never the token.
      run_record notes "module=dast phase=auth target=$target identity=$label mode=${_DAST_AUTH_MODE:-} state=authenticated"
    else
      failed=$(( failed + 1 ))
      run_record coverage_reduction "module=dast reason=auth_failed target=$target identity=$label mode=${_DAST_AUTH_MODE:-} - $_DAST_AUTH_FAIL_REASON. Every check needing this identity is skipped with that reason rather than run unauthenticated."
      run_record coverage_gap "dast auth: identity '$target.$label' could not be authenticated ($_DAST_AUTH_FAIL_REASON), so the authenticated checks that depend on it did not run. Their silence in this report is a missing test, not a passing one."
    fi
    # The config-derived half of §7.4's user-enumeration checks, over the
    # responses this run ALREADY received.  It sends nothing, so it runs whether
    # the login succeeded or failed - a rejected login is in fact the more
    # likely place for an account-state disclosure to appear.
    dast_auth_enum_scan "$target" "$label" "${_DAST_AUTH_LOGIN_PATH:-/}"
  done

  dast_auth_enum_gap "$target" "$responses"

  if [[ $intrusive == true ]]; then
    # --allow-intrusive is accepted by scan.sh's parser today and this phase
    # still does not probe.  Saying so is the point: an operator who opted in
    # and sees no enumeration finding must not read that as "the opt-in check
    # ran and found nothing".
    run_record coverage_reduction "module=dast reason=live_enumeration_probe_not_implemented target=$target - --allow-intrusive was given, but the LIVE user-enumeration probe (docs/DESIGN.md §7.4's opt-in half) is not built yet; only the config-derived half ran, and it sends no request of its own."
  fi

  # DAST-29 (`authz.sh`) needs TWO live sessions to detect cross-user access
  # (rules/RULE-FORMAT.md §9.5's `requires-identities`).  The plumbing for it is
  # `dast_auth_authenticated_labels_set`, built here rather than there, and the
  # shortfall is recorded now rather than discovered by a cross-user check
  # reporting a clean result it had no second identity to obtain.
  dast_auth_authenticated_labels_set "$target"
  if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} < 2 )); then
    run_record coverage_gap "dast auth: target '$target' has ${#_DAST_AUTH_AUTHED_LABELS[@]} authenticated identity(ies) of ${#labels[@]} configured. Cross-user access-control checks (IDOR and excessive data exposure, docs/DESIGN.md §7.4) need TWO, because they work by asking for identity B's object as identity A; with fewer they cannot run at all."
  fi

  log_info "dast auth: target '$target' - $ok of ${#labels[@]} configured identity(ies) authenticated, $failed failed"
  return 0
}

_dast_auth_phase
