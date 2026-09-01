#!/usr/bin/env bash
# ADR pointer: this file's scope pre-check is converged onto
# modules/dast/engine.sh section 3b's `dast_endpoint_keep` - see the ADR
# block at the top of modules/dast/crawl.sh for the decision and the
# alternatives, including why this file KEEPS its own bespoke
# coverage_reduction wording (a single chosen burst endpoint, not an
# N-row roll-up) rather than calling `dast_scope_record_skips`.
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - one run can legitimately reach the same phase
# twice (a second scope target, a second `scan_main` in one process) and a guard
# would silently make the second one a no-op.  The pure half - the header
# family, the burst arithmetic and the verdict - lives in
# modules/dast/ratelimit_engine.sh, which does have one.
#
# WHAT THIS FILE OWNS IS THE FOUR GATES, IN THIS ORDER, AND EVERY ONE OF THEM
# REFUSES BY RECORDING A COVERAGE GAP RATHER THAN BY RETURNING QUIETLY.  An
# absent finding from this check must never read as "the target throttles":
# docs/DESIGN.md §15 requires a scan to name its blind spots rather than
# overstate coverage, and a burst probe has more ways to be meaningless than
# any other check in the module.
#
#   1. THE AFFIRMATION (DAST-32), AND IT MUST NAME THIS TARGET.
#      docs/STEP5-DAST-PLAN.md's DAST-28 amendment: "Under the conservative
#      ceilings a burst probe cannot establish either a positive or a true
#      negative: it would report 'no missing-throttling finding' from a scanner
#      that was itself throttled below any plausible threshold.  On an
#      unaffirmed run DAST-28 does not execute, and emits a `coverage_gap`
#      naming the scanner's own rate ceiling as the reason."  This is the only
#      check in the module that cannot run at all without `--i-own-target`.
#      The affirmation is read from lib/http.sh's own `_http_affirmation_set` -
#      the per-run record, never an environment variable, for the reason that
#      function's header gives - and the TARGET it names is compared, because
#      `--i-own-target` is a key rather than a switch: an operator who owns
#      target A has said nothing about target B, and a run that scoped both
#      must not burst the one they did not affirm.
#
#   2. THE SCANNER'S OWN RATE MUST ACTUALLY BE RAISED.  The affirmation LIFTS
#      the 4/s ceiling; it does not raise the rate.  An operator who affirms
#      but leaves `requests-per-second` at its default gets a fifty-request
#      "burst" trickled out over twelve seconds, which no throttle worth having
#      would notice - the same silent false negative gate 1 exists to close,
#      one step further in.  So the effective rate is compared against the
#      conservative ceiling and a run at or below it records the gap and sends
#      nothing.  This is a strengthening of the amendment rather than a
#      restatement of it, and it is stated here because the amendment's own
#      argument requires it.
#
#   3. THE BUDGET MUST FUND A BURST WORTH SENDING.  Sized from lib/http.sh's
#      own counter (`http_budget_remaining_set`), never from a second budget of
#      this check's own - docs/STEP5-DAST-PLAN.md's DAST-28 row is explicit
#      that it "must draw down the *same* per-run request budget DAST-01 owns,
#      since this is the one check §7.4 flags as intentionally multi-request",
#      and this ticket's own brief adds the reason: "a burst probe that had its
#      own budget would double-spend the ceiling the whole tier depends on."
#      Because every request goes through `http_request`, the draw-down is not
#      something this file has to remember to do - it is what the chokepoint
#      does with any request - and what this file adds is refusing to spend
#      more than half of what is left, so the probe can never be the phase that
#      exhausts the run.
#
#   4. THERE MUST BE AN IDEMPOTENT ENDPOINT.  GET only, one endpoint, from the
#      crawl inventory or the operator's own `base-url`.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/ratelimit_engine.sh
source "${BASH_SOURCE[0]%/*}/ratelimit_engine.sh"

# tension 15's check-set filter, when an outer `scan.sh` established one.  The
# same three-line shape modules/dast/passive/headers.sh uses, and for the same
# reason: standalone (tests, a direct source) there is no filter and every
# check is selected.
_rate_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# `_rate_pick_endpoint TARGET ENDPOINTS_FILE BASE_URL` - sets `_RATE_URL` and
# `_RATE_PATH` to the ONE idempotent endpoint this burst is sent to, or empty.
#
# THE PREFERENCE IS THE INVERSE OF modules/dast/passive/headers.sh's, AND THE
# INVERSION IS DELIBERATE.  That phase puts the operator's own `base-url` first
# because a security header is a property of the front door and the base-url is
# the one URL that exists on every run.  A rate limit is not: the front door of
# a real deployment is routinely a static document served by a CDN or a
# reverse proxy that never reaches the application at all, so bursting it
# measures the CDN's throttling and reports the answer against the
# application's.  An endpoint the crawler or a specification actually named is
# the application's surface, so it is preferred, and the `base-url` is the
# fallback for a run that has no inventory yet.
#
# Both branches go through `hdr_endpoints_load`, which is already GET-only,
# deduped by path template and LC_ALL=C sorted - so the chosen endpoint is
# deterministic across runs, which is what keeps this finding's fingerprint
# from churning every time the crawl reorders.
_rate_pick_endpoint() {
  local target=$1 epf=$2 base=$3
  _RATE_URL='' _RATE_PATH=''

  hdr_endpoints_load "$epf" "$target" ''
  if (( _HDR_N > 0 )); then
    _RATE_URL=${_HDR_URL[0]}
    _RATE_PATH=${_HDR_PATH[0]}
    _RATE_SOURCE='inventory'
    return 0
  fi

  [[ -n $base ]] || return 1
  hdr_endpoints_load '' "$target" "$base"
  (( _HDR_N > 0 )) || return 1
  _RATE_URL=${_HDR_URL[0]}
  _RATE_PATH=${_HDR_PATH[0]}
  _RATE_SOURCE='base-url'
  return 0
}

_dast_ratelimit_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/ratelimit.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # ---- gate 1: the own-your-target affirmation, for THIS target -----------
  _http_affirmation_set
  if [[ ${_HTTP_AFFIRMED:-false} != true ]]; then
    run_record coverage_reduction "module=dast reason=burst_probe_requires_owner_affirmation check=ratelimit target=$target - the missing-throttling probe is the one check that intentionally sends several requests (docs/DESIGN.md §7.4), and without '--i-own-target' this run is held to a conservative 4 requests/second against a host this tool cannot vouch for. A burst sent at that rate could establish neither a positive nor a true negative, so none was sent."
    run_record coverage_gap "dast ratelimit: the missing-throttling burst probe did NOT run on target '$target', because this run carries no '--i-own-target' affirmation and is therefore held to the scanner's own conservative rate ceiling of 4 requests/second (docs/STEP5-DAST-PLAN.md, 'Safety defaults and authorisation'). At that rate a burst proves nothing either way. The absence of a throttling finding here is the absence of a test, not evidence that this target rate-limits."
    return 0
  fi
  if [[ -n ${_HTTP_AFFIRMED_TARGET:-} && ${_HTTP_AFFIRMED_TARGET} != "$target" ]]; then
    run_record coverage_reduction "module=dast reason=affirmation_names_another_target check=ratelimit target=$target affirmed=${_HTTP_AFFIRMED_TARGET} - '--i-own-target' is a key rather than a switch, and it names '${_HTTP_AFFIRMED_TARGET}'. Owning one target says nothing about another, so no burst was sent to '$target'."
    run_record coverage_gap "dast ratelimit: the burst probe did NOT run on target '$target' - this run's '--i-own-target' affirmation names '${_HTTP_AFFIRMED_TARGET}' instead, and an affirmation is scoped to the target it names. Re-run with '--i-own-target $target' if you own this one too."
    return 0
  fi

  # ---- gate 2: the affirmation lifted the ceiling; did anyone raise the rate?
  # `_HTTP_EFF_RPS_MILLI` is milli-requests per second and the conservative
  # ceiling is 4/s, i.e. 4000.  Strictly-greater, not >=: a run left AT the
  # ceiling is exactly the run this gate exists to catch.
  _http_effective_rps_milli_set
  local eff_rps_milli=$_HTTP_EFF_RPS_MILLI
  if (( eff_rps_milli <= 4000 )); then
    run_record coverage_reduction "module=dast reason=burst_rate_not_raised check=ratelimit target=$target rate=$(_http_rps_render "$eff_rps_milli") - this run IS affirmed, but 'requests-per-second' is still $(_http_rps_render "$eff_rps_milli"), at or below the 4/s the affirmation exists to lift. The scanner would have been the bottleneck rather than the target, so no burst was sent."
    run_record coverage_gap "dast ratelimit: the burst probe did NOT run on target '$target'. The '--i-own-target' affirmation LIFTS the 4 requests/second ceiling; it does not raise the rate, and this run is still configured at $(_http_rps_render "$eff_rps_milli") requests/second. A burst throttled by the scanner itself cannot show whether the target throttles. Raise 'requests-per-second' in config/scanner.conf (rules/RULE-FORMAT.md §9.6.1) to a rate you are willing to send at this target."
    return 0
  fi

  # ---- gate 3: the shared per-run request budget ---------------------------
  if ! rate_burst_size; then
    run_record coverage_reduction "module=dast reason=burst_budget_insufficient check=ratelimit target=$target remaining=${_RATE_BUDGET_REMAINING:-unknown} - $_RATE_BURST_WHY"
    run_record coverage_gap "dast ratelimit: the burst probe did NOT run on target '$target'. $_RATE_BURST_WHY Raise 'request-budget' in config/scanner.conf, or narrow the scan, if you want this check covered."
    return 0
  fi
  local burst=$_RATE_BURST_N

  # ---- gate 4: an idempotent endpoint --------------------------------------
  # SCOURSH_DAST_ENDPOINTS is now always the fixed
  # `$SCOURSH_RUN_DIR/inventory/endpoints.json` path (modules/dast/run.sh),
  # published unconditionally whether or not crawl.sh has written it yet - so
  # reading it alone is now enough; the per-file fallback to the run
  # directory's own artifact (the general fix that landed instead) is no
  # longer needed.
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  local base=''
  if declare -F config_scope_field_or >/dev/null; then
    base=$(config_scope_field_or "$target" base-url '' 2>/dev/null || printf '')
  fi

  if ! _rate_pick_endpoint "$target" "$epf" "$base"; then
    run_record coverage_reduction "module=dast reason=no_idempotent_endpoint check=ratelimit target=$target - neither an endpoint inventory (docs/INVENTORY-FORMAT.md) nor a base-url in config/scope.conf offered a GET endpoint to burst, so no request was sent."
    run_record coverage_gap "dast ratelimit: target '$target' offered no idempotent (GET) endpoint, so the missing-throttling burst probe had nowhere to run. Supply an OpenAPI/HAR specification or let the crawl phase run first."
    return 0
  fi
  local url=$_RATE_URL path=$_RATE_PATH

  # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - modules/dast/
  # engine.sh section 3b (`dast_endpoint_keep`) is the ONE place this decision
  # is made now, rather than a local copy of `http_gate_url` here.
  # `http_request` gates FATALLY (exit 3), which is right for a URL the
  # operator configured and wrong for one lifted out of an inventory another
  # module wrote: one bad row must not abort the run, let alone fifty times
  # over inside a burst.  Everything that survives this is still requested
  # through `http_request`, which re-gates it and every redirect hop.
  #
  # This is still ONE endpoint, not a loop over an inventory - the shared
  # counter/reason accumulator is reset around this single call so a stale
  # count from an earlier phase in the same process can never leak in, and the
  # coverage message stays this file's OWN grain ("the one endpoint chosen for
  # the burst"), not the shared helper's "N inventory rows dropped" wording.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi
  # `endpoint_in_scope`, not the obvious `kept` - `shellcheck -x` inlines
  # every sourced file into one namespace, and lib/http.sh declares two
  # unrelated functions' own `local -a kept=()`, which then trips SC2178
  # ("used as an array but is now assigned a string") against a scalar of the
  # same name in a different function in a different file - the same
  # cross-file collision tests/suites/dast-sqli.sh's own `_sqli_now` names.
  # Distinct names are the fix; a suppression would hide the same warning if
  # it ever became real here.
  local endpoint_in_scope=1
  if declare -F dast_endpoint_keep >/dev/null; then
    dast_endpoint_keep "$url" "$target" || endpoint_in_scope=0
  fi
  if (( ! endpoint_in_scope )); then
    run_record coverage_reduction "module=dast reason=burst_endpoint_out_of_scope check=ratelimit target=$target - the chosen endpoint is not authorised by config/scope.conf (${_DAST_SCOPE_REASONS:-declined by the scope gate}) and was not requested."
    run_record coverage_gap "dast ratelimit: the endpoint chosen for the burst probe on target '$target' is not in config/scope.conf, so nothing was sent and the check is uncovered."
    return 0
  fi

  local want_throttle=0 want_retry=0
  _rate_selected DAST-RATE-NO_THROTTLE-01 && want_throttle=1
  _rate_selected DAST-RATE-NO_RETRY_AFTER-01 && want_retry=1
  if (( ! want_throttle && ! want_retry )); then
    return 0
  fi

  log_info "dast ratelimit: target '$target' - bursting $burst GET(s) at $url (budget: ${_RATE_BUDGET_REMAINING} of ${_RATE_BUDGET_TOTAL} request(s) remaining, this probe spends at most half)"

  rate_burst_run "$target" "$url" "$burst"
  rate_verdict
  rate_observed_rate

  local sent=$_RATE_SENT rate=$_RATE_OBSERVED_RPS
  local base_evi
  base_evi="$sent GET request(s) to this endpoint in ${_RATE_ELAPSED_MS}ms (an observed $rate requests/second; the scanner's own configured rate is $(_http_rps_render "$eff_rps_milli")/s, and the burst is capped at $_RATE_BURST_HARD_CAP requests and at half the remaining per-run budget)."

  if (( _RATE_UNREACHABLE > 0 )); then
    run_record coverage_reduction "module=dast reason=burst_requests_unreachable check=ratelimit target=$target count=$_RATE_UNREACHABLE of $sent - some burst requests returned no usable response, so the observed rate understates what the target was actually asked for."
  fi

  case $_RATE_VERDICT in
    no_throttle)
      # checks_run is the set of checks that LOADED AND EXECUTED.  The
      # no-throttle check executed; the Retry-After check had no 429 to look
      # at, so it is reported as inapplicable rather than as tested.
      (( want_throttle )) && run_record checks_run 'DAST-RATE-NO_THROTTLE-01'
      if (( want_throttle )); then
        rate_emit_finding DAST-RATE-NO_THROTTLE-01 medium \
          'No request throttling on an idempotent endpoint' \
          "$target" "$url" "$path" \
          "the target accepted all $base_evi No response carried a 429 status, a Retry-After, or any RateLimit/X-RateLimit header, so nothing in the exchange indicates a rate limit exists on this endpoint. Statuses observed: ${_RATE_STATUSES:-none}." \
          'Apply a rate limit to this endpoint at the edge (reverse proxy, API gateway or WAF) and, where the limit is per-principal rather than per-IP, in the application as well. Answer an exceeded limit with 429 and a Retry-After a client can honour, and publish the RateLimit-Limit/RateLimit-Remaining/RateLimit-Reset fields so a well-behaved client can back off before it is refused. Rate limiting is the control that bounds credential stuffing, enumeration and resource exhaustion against an endpoint that is otherwise behaving correctly.'
      fi
      (( want_retry )) && run_record coverage_reduction "module=dast reason=ratelimit_check_not_applicable check=DAST-RATE-NO_RETRY_AFTER-01 target=$target - the target returned no 429 during the burst, so there was no throttling response whose back-off signal could be inspected. That check is NOT covered on this target."
      ;;
    no_retry_after)
      (( want_throttle )) && run_record checks_run 'DAST-RATE-NO_THROTTLE-01'
      (( want_retry )) && run_record checks_run 'DAST-RATE-NO_RETRY_AFTER-01'
      if (( want_retry )); then
        local ra_note='carried no Retry-After header at all'
        [[ -n $_RATE_RETRY_AFTER ]] \
          && ra_note="carried a Retry-After of '$(hdr_safe_text "$_RATE_RETRY_AFTER" 80)', which is neither a delta-seconds value nor an HTTP-date and so cannot be honoured (RFC 9110 §10.2.3)"
        rate_emit_finding DAST-RATE-NO_RETRY_AFTER-01 low \
          'Rate limit signalled without a usable back-off (429 with no Retry-After)' \
          "$target" "$url" "$path" \
          "the target throttled at request $_RATE_THROTTLED_AT of $base_evi The 429 response $ra_note. A client has no way to know when to retry, so the usual behaviour is an immediate retry, which sustains exactly the load the limit was imposed to shed." \
          'Send a Retry-After header on every 429, as either a delta-seconds value or an HTTP-date (RFC 9110 §10.2.3), so a client knows when the limit resets. Publishing RateLimit-Limit/RateLimit-Remaining/RateLimit-Reset alongside it lets a well-behaved client slow down before it is refused at all.'
      fi
      ;;
    throttled)
      (( want_throttle )) && run_record checks_run 'DAST-RATE-NO_THROTTLE-01'
      (( want_retry )) && run_record checks_run 'DAST-RATE-NO_RETRY_AFTER-01'
      log_info "dast ratelimit: target '$target' throttled at request $_RATE_THROTTLED_AT with a usable Retry-After; no finding"
      ;;
    advertised)
      # NOT a finding, and this is the reading that matters most in this file.
      # The target published rate-limit headers on a response, which means it
      # HAS a limiter that this bounded burst simply did not reach.  Reporting
      # a missing control against a target that documents the control on every
      # response would make this check fire on every correctly-configured API
      # in the world.
      (( want_throttle )) && run_record checks_run 'DAST-RATE-NO_THROTTLE-01'
      (( want_retry )) && run_record coverage_reduction "module=dast reason=ratelimit_check_not_applicable check=DAST-RATE-NO_RETRY_AFTER-01 target=$target - the target advertises a rate limit but did not refuse any request in this bounded burst, so there was no 429 whose back-off signal could be inspected."
      run_record notes "module=dast phase=ratelimit target=$target verdict=advertised signals=[${_RATE_SIGNALS_SEEN}] - the target publishes rate-limit headers but did not refuse any of the $sent request(s) in this bounded burst, so it has a limiter this probe did not reach. No finding."
      ;;
    *)
      run_record coverage_reduction "module=dast reason=burst_inconclusive check=ratelimit target=$target sent=$sent unreachable=$_RATE_UNREACHABLE - no usable response came back from the burst, so neither the presence nor the absence of throttling was established."
      run_record coverage_gap "dast ratelimit: the burst probe on target '$target' got no usable response from $sent request(s), so its throttling was not tested. This is a coverage gap, not a clean result."
      ;;
  esac

  return 0
}

_dast_ratelimit_phase
