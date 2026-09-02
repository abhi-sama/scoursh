#!/usr/bin/env bash
# tests/suites/dast-ratelimit.sh - modules/dast/ratelimit.sh and
# modules/dast/ratelimit_engine.sh: the §7.4 missing-throttling burst probe
# (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-28, tier 5).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and every case is driven from
# RECORDED RESPONSES - a table of response heads this file writes, replayed
# into lib/http.sh's own capture sink exactly as curl's `-D` would write them
# (docs/DESIGN.md §12: "DAST logic is testable with no live target").  It runs
# on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.  The readings pinned here:
#
#   1. an UNAFFIRMED run sends NOTHING AT ALL and says why, naming the
#      scanner's own 4/s ceiling (docs/STEP5-DAST-PLAN.md's DAST-28 amendment).
#      Asserted on a REQUEST LOG, never on a return value.
#   2. `--i-own-target` is a KEY, not a switch: an affirmation naming target A
#      does not license a burst against target B.
#   3. the affirmation LIFTS the rate ceiling and does not RAISE the rate, so an
#      affirmed run still at 4/s sends nothing either - the same silent false
#      negative one step further in.
#   4. the burst draws down lib/http.sh's OWN per-run budget counter, and spends
#      at most half of what is left, so it can never be the phase that exhausts
#      the run.
#   5. the hard cap cannot be RAISED by the operator seam, only lowered - and
#      the hard cap, the floor and the budget share are not reachable from the
#      PROCESS ENVIRONMENT at all (CWE-15), which a `: "${VAR:=N}"` default
#      would have made them.
#   6. rate-limit headers WITHOUT a 429 mean the target has a limiter this burst
#      did not reach - NOT a missing-throttling finding.  The opposite direction
#      (no headers and no 429 IS a finding) is pinned in the same section, so
#      neither half can be satisfied by breaking the other.
#   7. the burst STOPS at the first 429 and does not stop for anything else.
#   8. 503 is NOT throttling: a target that collapses under the burst must not
#      be reported as one that defends itself - pinned both at the
#      `rate_status_is_throttle` predicate (section A) AND end to end through
#      the phase against the `rl-503` fixture (section F), because a bare
#      `Retry-After` on a 503 satisfies the OTHER predicate,
#      `rate_signal_scan`, and reaches the identical `advertised` clean
#      result through a different door (see reading 11).
#   9. a 429 with no usable Retry-After is its own, separate check id, because
#      the DAST fingerprint carries no component naming the defect.
#  10. an inventory endpoint is preferred over the operator's base-url - the
#      inverse of headers.sh's preference, and deliberately so.
#  11. `retry-after` is excluded from `rate_signal_scan` on a 5xx status - it is
#      the one rate-limit header this file's own comment names as "also sent
#      on a 503" - while every other family member and a Retry-After on a
#      non-5xx status are untouched, so a real limiter that announces itself
#      pre-emptively still reads as `advertised`.
#
# shellcheck shell=bash
#
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# SC2034: SCOURSH_HTTP_RESOLVE / SCOURSH_HTTP_TRANSPORT are lib/http.sh's own
#   documented swappable hooks; this file is their only assignment and
#   lib/http.sh is their only reader.
# SC2154: `_before` is set by `http_budget_remaining_set`, which SETS a caller-
#   named variable rather than printing one (see its own header for why).
# shellcheck disable=SC2030,SC2031,SC2034,SC2154

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in modules/dast/passive/headers_engine.sh ->
# lib/http.sh -> lib/config.sh + lib/findings.sh -> lib/records.sh ->
# lib/core.sh, which bootstraps the scratch dir and the traps.
# shellcheck source=modules/dast/ratelimit_engine.sh
source "$ROOT/modules/dast/ratelimit_engine.sh"
# This file's own scope pre-check now lives in modules/dast/engine.sh section
# 3b (`dast_endpoint_keep` and friends) rather than a local copy of
# `http_gate_url` - sourced for real here (measured cost is in the same
# ballpark as tests/suites/dast-headers.sh's own +~2 GB, well inside the 50 GB
# per-process budget - see docs/CI-RUNBOOK.md's "the memory model") so section
# E's out-of-scope case below exercises the real predicate.
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-ratelimit-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope and resolver.
# ---------------------------------------------------------------------------
# Five targets, one per response shape, so a case never has to reconfigure a
# transport mid-run:
#   rl-open       every response 200 with NO rate-limit header anywhere.
#   rl-429        200 until request 5, then 429 with a usable Retry-After.
#   rl-429-bare   the same, but the 429 carries no Retry-After at all.
#   rl-429-junk   the same, but Retry-After is a value no client can parse.
#   rl-adv        always 200, but every response advertises X-RateLimit-*.
#   rl-503        always 503 - the "collapse is not throttling" case.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: rl-open
base-url: https://open.fixture.example/
notes: Fixture target for tests/suites/dast-ratelimit.sh. Never dialled: both
  the resolver and the transport are stubbed.

id: rl-429
base-url: https://t429.fixture.example/
notes: Fixture target that throttles partway through a burst.

id: rl-429-bare
base-url: https://bare429.fixture.example/
notes: Fixture target that throttles with no Retry-After.

id: rl-429-junk
base-url: https://junk429.fixture.example/
notes: Fixture target that throttles with an unparseable Retry-After.

id: rl-adv
base-url: https://adv.fixture.example/
notes: Fixture target that advertises a rate limit it never enforces here.

id: rl-503
base-url: https://down.fixture.example/
notes: Fixture target that answers 503 to everything.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

_rl_resolve() {
  case $1 in
    open.fixture.example | t429.fixture.example | bare429.fixture.example \
      | junk429.fixture.example | adv.fixture.example | down.fixture.example)
      printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_rl_resolve

# `_scanner RPS BUDGET` - the run's own limits.  A very high rate keeps the
# token bucket from real-sleeping through a fifty-request burst; the cases that
# care about the rate GATE set it deliberately low instead.
_scanner() {
  cat >"$W/scanner.conf" <<EOF
id: scanner
requests-per-second: $1
request-budget: $2
circuit-breaker-failures: 100000
EOF
  config_scanner_load "$W/scanner.conf"
}
_scanner 5000 20000

# ---------------------------------------------------------------------------
# The recorded responses and the request log.
# ---------------------------------------------------------------------------
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }
_req_count() { [[ -s $REQ_LOG ]] && wc -l <"$REQ_LOG" | tr -d ' ' || printf '0'; }

# How many requests this host has already received in the current case, so the
# "throttles at request 5" targets can answer differently over a burst.
_seen_for() {
  local host=$1 n=0 line
  while IFS= read -r line; do
    [[ $line == *" $host "* ]] && n=$(( n + 1 ))
  done <"$REQ_LOG"
  printf '%s' "$n"
}

_rl_transport() {
  local method=$1 host=$3 path=$5
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local status=200 head seen
  seen=$(_seen_for "$host")
  case $host in
    open.fixture.example)
      head=$'Content-Type: text/html\r\nServer: fixture\r\n' ;;
    adv.fixture.example)
      # A limiter that ANNOUNCES itself on every response and never refuses one
      # inside this bounded burst.  Reading this as "no throttling" is the
      # false positive section F pins.
      head=$'Content-Type: application/json\r\nX-RateLimit-Limit: 5000\r\nX-RateLimit-Remaining: 4900\r\nX-RateLimit-Reset: 60\r\n' ;;
    down.fixture.example)
      status=503
      head=$'Content-Type: text/html\r\nRetry-After: 120\r\n' ;;
    t429.fixture.example)
      if (( seen >= 4 )); then
        status=429
        head=$'Content-Type: text/plain\r\nRetry-After: 30\r\n'
      else
        head=$'Content-Type: text/html\r\n'
      fi ;;
    bare429.fixture.example)
      if (( seen >= 4 )); then
        status=429
        head=$'Content-Type: text/plain\r\n'
      else
        head=$'Content-Type: text/html\r\n'
      fi ;;
    junk429.fixture.example)
      if (( seen >= 4 )); then
        status=429
        head=$'Content-Type: text/plain\r\nRetry-After: soon\r\n'
      else
        head=$'Content-Type: text/html\r\n'
      fi ;;
    *) head=$'Content-Type: text/html\r\n' ;;
  esac
  printf '%s %s %s\n' "$method" "$host" "$path" >>"$REQ_LOG"
  if [[ -n $hdrsout ]]; then
    printf 'HTTP/1.1 %s X\r\n%s\r\n' "$status" "$head" >>"$hdrsout"
  fi
  printf '%s\n%s\n%s\n' "$status" '' 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_rl_transport

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
# `_new_run NAME [AFFIRM_TARGET]` - a fresh run directory, a fresh limiter
# state directory (so each case starts with a full budget and a full bucket),
# and the affirmation record scan.sh would have written at parse time.  An
# empty AFFIRM_TARGET means NO affirmation at all.
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  rm -rf "$SCOURSH_SCRATCH/http-limits"
  unset _HTTP_LIMIT_DIR
  if [[ -n ${2:-} ]]; then
    run_record authorization_affirmed true
    run_record authorization_target "$2"
  fi
  occurrence_reset_all
  _req_reset
}

_meta() { run_facts "$1" 2>/dev/null || printf ''; }

_count_check() {
  local check=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && { n=$(( n + 1 )); break; }
      done
    done <"$f"
  done
  printf '%s' "$n"
}

# The remaining per-run budget, straight off lib/http.sh's own counter file.
_budget_left() {
  local v=''
  [[ -r $SCOURSH_SCRATCH/http-limits/budget.state ]] \
    && IFS= read -r v <"$SCOURSH_SCRATCH/http-limits/budget.state"
  printf '%s' "${v:-unopened}"
}

# `_phase TARGET [ENDPOINTS_FILE]` - run the phase exactly as
# `dast_run_phase` would: publish the target and source the script, which calls
# `_dast_ratelimit_phase` at its own bottom.
_phase() {
  SCOURSH_DAST_TARGET=$1
  SCOURSH_DAST_ENDPOINTS=${2:-}
  export SCOURSH_DAST_TARGET SCOURSH_DAST_ENDPOINTS
  # shellcheck source=modules/dast/ratelimit.sh
  source "$ROOT/modules/dast/ratelimit.sh"
}

# `_inv NAME TARGET URL...` writes a docs/INVENTORY-FORMAT.md endpoints.json
# and prints its path.
_inv() {
  local name=$1 target=$2; shift 2
  local f=$W/$name.endpoints.json u i=0 rows=''
  for u in "$@"; do
    rows+="${rows:+,}"$'\n'"  { \"id\": \"ep$i\", \"target\": \"$target\", \"method\": \"GET\", \"url\": \"$u\", \"path\": \"$(hdr_path_of "$u")\" }"
    i=$(( i + 1 ))
  done
  printf '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [%s\n] }\n' "$rows" >"$f"
  printf '%s' "$f"
}

# ===========================================================================
printf '== A. the rate-limit vocabulary ==\n'
# ===========================================================================
t_case '429 is throttling and 503 is not'
assert_true "$(rate_status_is_throttle 429 && printf 0 || printf 1)" \
  '429 is the throttling status (RFC 6585 §4)'
assert_true "$(rate_status_is_throttle 503 && printf 1 || printf 0)" \
  '503 is NOT throttling - FAILS under the reading that any refusal under load counts, which would turn a target that COLLAPSES under the burst into a clean bill of health for the control being tested'
assert_true "$(rate_status_is_throttle 200 && printf 1 || printf 0)" \
  '200 is not throttling'

t_case 'Retry-After usability'
assert_true "$(rate_retry_after_is_usable '30' && printf 0 || printf 1)" \
  'delta-seconds is usable (RFC 9110 §10.2.3)'
assert_true "$(rate_retry_after_is_usable 'Wed, 21 Oct 2015 07:28:00 GMT' && printf 0 || printf 1)" \
  'an HTTP-date is usable too - FAILS under a digits-only reading, which would report a correctly-behaving server'
assert_true "$(rate_retry_after_is_usable 'soon' && printf 1 || printf 0)" \
  'a token a client cannot parse is NOT usable'
assert_true "$(rate_retry_after_is_usable '' && printf 1 || printf 0)" \
  'an empty value is not usable'

t_case 'the header family covers the de-facto spellings'
_fam=$(rate_signal_headers)
assert_contains "$_fam" 'retry-after' 'the RFC back-off header is in the family'
assert_contains "$_fam" 'ratelimit-limit' 'the IETF RateLimit family is in it'
assert_contains "$_fam" 'x-ratelimit-remaining' \
  'the de-facto X-RateLimit spelling is in it - FAILS under an RFC-only reading, which would report "no rate limiting" against a target that says otherwise on every response'
assert_contains "$_fam" 'x-rate-limit-reset' 'the hyphenated de-facto spelling is in it too'

t_case 'rate_signal_scan excludes a bare Retry-After from a 5xx, and only that'
# `retry-after` is this file's own header names as "the only [signal header]
# that is also sent on a 503" - a target falling over under load can carry it
# with no limiter behind it at all, so counting it as a signal reaches
# rate_verdict's `advertised` case (a clean result) for a target that
# COLLAPSED, through the OTHER predicate than rate_status_is_throttle - the
# exact reading that predicate's own header says must never happen.
_cap=$W/predicate.head
printf 'HTTP/1.1 503 X\r\nRetry-After: 120\r\n\r\n' >"$_cap"
hdr_parse_capture "$_cap"
assert_true "$(rate_signal_scan 503 && printf 1 || printf 0)" \
  'a bare Retry-After on a 503 is NOT a signal - FAILS under the reading that any Retry-After means a limiter, which reports a target that collapsed under the burst as one that defends itself'
printf 'HTTP/1.1 200 X\r\nRetry-After: 120\r\n\r\n' >"$_cap"
hdr_parse_capture "$_cap"
assert_true "$(rate_signal_scan 200 && printf 0 || printf 1)" \
  'the identical Retry-After on a 200 (a limiter announcing itself pre-emptively) IS still a signal - FAILS under a reading that drops retry-after everywhere, which would silence a real advertised limiter too'
printf 'HTTP/1.1 503 X\r\nX-RateLimit-Limit: 10\r\n\r\n' >"$_cap"
hdr_parse_capture "$_cap"
assert_true "$(rate_signal_scan 503 && printf 0 || printf 1)" \
  'an X-RateLimit-* header on a 5xx is untouched by the exclusion - only retry-after is ambiguous with a plain failure, and narrowing the fix to it alone is what this case pins'

# ===========================================================================
printf '\n== B. sizing the burst against lib/http.sh own budget ==\n'
# ===========================================================================
t_case 'a large budget gives the hard cap'
_new_run size-big rl-open
rate_burst_size
assert_eq "$_RATE_BURST_HARD_CAP" "$_RATE_BURST_N" \
  'a run with budget to spare bursts at the hard cap and no further'

t_case 'the budget share bounds the burst below the cap'
_new_run size-share rl-open
_scanner 5000 60
rate_burst_size
assert_eq '30' "$_RATE_BURST_N" \
  'with 60 requests left the probe takes 30 - FAILS under the reading that the remaining budget is all available, which would let this one phase end the run for every phase after it'

t_case 'a budget too small for a meaningful burst refuses'
_new_run size-floor rl-open
_scanner 5000 15
# NEVER through `$( )`: `rate_burst_size` SETS variables, and a setter called in
# a command substitution runs in a subshell whose writes are discarded - the
# exact mistake AGENTS.md records for `occurrence_next`.  Measured here: the
# first draft read the PREVIOUS case's 30 and passed the refusal assertion for
# the wrong reason.
_rc=0; rate_burst_size || _rc=$?
assert_eq '1' "$_rc" 'a share of 7 is below the floor of 10, so the probe refuses'
assert_eq '0' "$_RATE_BURST_N" 'and asks for no requests at all'
assert_contains "$_RATE_BURST_WHY" 'below the' \
  'and says why, naming the floor'

t_case 'the operator seam lowers the cap and cannot raise it'
_new_run size-seam rl-open
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=20 rate_burst_size
assert_eq '20' "$_RATE_BURST_N" 'an operator asking for fewer requests gets fewer'
SCOURSH_DAST_RATELIMIT_BURST=500 rate_burst_size
assert_eq "$_RATE_BURST_HARD_CAP" "$_RATE_BURST_N" \
  'an operator asking for 500 gets the hard cap - FAILS under the reading that the seam is a plain override, which is the one shape of knob a traffic-sending tool must not offer'
_rc=0; SCOURSH_DAST_RATELIMIT_BURST=abc rate_burst_size || _rc=$?
assert_eq '1' "$_rc" 'a malformed seam value refuses rather than silently substituting the maximum'
assert_eq '0' "$_RATE_BURST_N" 'and asks for no requests'

# `_cap_probe BUDGET` - `_RATE_BURST_N` as resolved in a FRESH PROCESS, so
# whatever the caller exported is in the environment at the moment the engine is
# sourced.  It has to be a subprocess: this suite sourced the engine at its own
# top, and the engine's sourced-once guard means a later assignment in THIS
# shell would not exercise the defaulting at all - the test would pass without
# testing anything.
_cap_probe() {
  bash -c '
    set -Eeuo pipefail
    cd -- "$1"
    # shellcheck source=/dev/null
    source modules/dast/ratelimit_engine.sh
    printf "id: scanner\nrequests-per-second: 5000\nrequest-budget: %s\ncircuit-breaker-failures: 100000\n" "$2" >"$3"
    config_scanner_load "$3"
    rate_burst_size || true
    printf "%s\n" "$_RATE_BURST_N"
  ' _ "$ROOT" "$1" "$W/cap-probe.conf" 2>/dev/null | tail -1
}

t_case 'the hard cap and the budget share are NOT reachable from the environment'
# CWE-15.  `_RATE_BURST_HARD_CAP`, `_RATE_BURST_MIN` and `_RATE_BUDGET_DIVISOR`
# are the §7.4 "strictly capped" bound and the "spends at most half" bound, and
# both are safety limits on how much traffic this tool sends at a host.  Written
# with `: "${VAR:=N}"` they are DEFAULTS, which any environment that can start
# the process may replace - the exact control surface AGENTS.md records
# DAST-32's own affirmation refusing to be ("an env var is settable by anything
# that can start the process, and binding callers whose command line nobody
# parsed is the ceiling's entire job").  They are plain assignments for that
# reason, and the operator seam that IS documented
# (`SCOURSH_DAST_RATELIMIT_BURST`, pinned above) can still only lower.
assert_eq '50' "$(_cap_probe 20000)" \
  'a default run resolves the documented hard cap of 50'
assert_eq '50' "$(_RATE_BURST_HARD_CAP=5000 _cap_probe 20000)" \
  'exporting _RATE_BURST_HARD_CAP=5000 does NOT raise it - FAILS under a colon-default-assignment form of that bound, where the environment silently replaces the one number §7.4 calls the hard cap and the probe sends 5000 requests at the host'
assert_eq '30' "$(_RATE_BUDGET_DIVISOR=1 _cap_probe 60)" \
  'exporting _RATE_BUDGET_DIVISOR=1 does NOT let the probe spend the whole remaining budget - FAILS under the defaulted form, where it takes all 60 and lib/http.sh budget refusal (fatal, exit 5) then ends the run for every phase and target after it'
assert_eq '0' "$(_RATE_BURST_MIN=1 _cap_probe 15)" \
  'exporting _RATE_BURST_MIN=1 does NOT lower the floor below which a burst means nothing - FAILS under the defaulted form, which would report a clean result from a 7-request "burst"'

# ===========================================================================
printf '\n== C. the four gates, each proven on the REQUEST LOG ==\n'
# ===========================================================================
t_case 'gate 1: an unaffirmed run sends nothing at all'
_new_run gate-unaffirmed
_scanner 5000 20000
_phase rl-open
assert_eq '0' "$(_req_count)" \
  'NOT ONE request is sent without --i-own-target - FAILS under the reading that the affirmation only relaxes limits, which is exactly the silent false negative docs/STEP5-DAST-PLAN.md DAST-28 amendment closes'
assert_contains "$(_meta coverage_gap)" '4 requests/second' \
  'and the gap names the scanner own rate ceiling as the reason, as the amendment requires'
assert_contains "$(_meta coverage_reduction)" 'burst_probe_requires_owner_affirmation' \
  'the reduction carries a machine-readable reason'
assert_eq '0' "$(_count_check DAST-RATE-NO_THROTTLE-01)" 'and no finding is emitted'

t_case 'gate 1b: an affirmation is a key, not a switch'
_new_run gate-other-target rl-adv
_scanner 5000 20000
_phase rl-open
assert_eq '0' "$(_req_count)" \
  'an affirmation naming rl-adv does not license a burst against rl-open - FAILS under the reading that any affirmation unlocks every target'
assert_contains "$(_meta coverage_gap)" "names 'rl-adv'" \
  'and the gap names the target that WAS affirmed'

t_case 'gate 2: affirmed but the rate was never raised'
_new_run gate-rate rl-open
_scanner 4 20000
_phase rl-open
assert_eq '0' "$(_req_count)" \
  'an affirmed run still at 4/s sends nothing - FAILS under the reading that the affirmation itself is enough, which leaves the scanner as the bottleneck and the negative result meaningless'
assert_contains "$(_meta coverage_gap)" 'requests-per-second' \
  'and the gap names the key the operator has to change'
assert_contains "$(_meta coverage_reduction)" 'burst_rate_not_raised' \
  'with its own machine-readable reason, distinct from the affirmation one'

t_case 'gate 3: the shared budget cannot fund a burst'
_new_run gate-budget rl-open
_scanner 5000 15
_phase rl-open
assert_eq '0' "$(_req_count)" 'a budget of 15 funds no meaningful burst, so none is sent'
assert_contains "$(_meta coverage_reduction)" 'burst_budget_insufficient' \
  'and the reduction says so'

t_case 'gate 4: no idempotent endpoint'
# `config/scope.conf` REQUIRES `base-url` (rules/RULE-FORMAT.md §9.4), so a
# phase reached through a valid scope file always has one and this branch is
# unreachable that way - `config_scope_field_or` also dies (exit 5) on an id
# the scope file does not carry, so driving the case with an invented target
# would test that refusal instead of this one.  The branch is reached the way a
# standalone caller reaches it: with no base-url resolvable at all.
_saved_csfo=$(declare -f config_scope_field_or)
config_scope_field_or() { printf ''; }
_new_run gate-endpoint rl-open
_scanner 5000 20000
_phase rl-open
eval "$_saved_csfo"
assert_eq '0' "$(_req_count)" 'a target with no base-url and no inventory offers nothing to burst'
assert_contains "$(_meta coverage_reduction)" 'no_idempotent_endpoint' \
  'and the reduction names the missing input'

# ===========================================================================
printf '\n== D. the missing-throttling finding ==\n'
# ===========================================================================
t_case 'a target with no throttle at all is a finding'
_new_run open rl-open
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=12 _phase rl-open
assert_eq '12' "$(_req_count)" 'the whole burst is sent, because "no 429 in N" is only true of N'
assert_eq '1' "$(_count_check DAST-RATE-NO_THROTTLE-01)" \
  'ONE missing-throttling finding - FAILS under a per-request emit, which would report one misconfiguration twelve times'
assert_eq '0' "$(_count_check DAST-RATE-NO_RETRY_AFTER-01)" \
  'and no back-off finding, because there was no 429 to inspect'
assert_contains "$(_meta checks_run)" 'DAST-RATE-NO_THROTTLE-01' \
  'the check that executed is in checks_run'
assert_contains "$(_meta coverage_reduction)" 'ratelimit_check_not_applicable' \
  'and the one that could not be evaluated is reported inapplicable, never rounded up to tested'

t_case 'the burst draws down lib/http.sh own per-run budget'
_new_run budget-drawdown rl-open
_scanner 5000 20000
# The counter is READ from lib/http.sh rather than assumed: this run is
# affirmed, so the 5000 DAST ceiling is lifted and the effective budget is the
# configured 20000 - hardcoding either number would make this case a test of
# the ceiling rather than of the draw-down.
http_budget_remaining_set _before
SCOURSH_DAST_RATELIMIT_BURST=12 _phase rl-open
assert_eq "$(( _before - 12 ))" "$(_budget_left)" \
  'twelve burst requests left the SHARED counter exactly twelve lower - FAILS under a probe with a budget of its own, which is the double-spend this ticket amendment exists to prevent'
assert_ne "$_before" "$(_budget_left)" \
  'and the shared counter really moved, so the probe is not spending from somewhere else'

# ===========================================================================
printf '\n== E. choosing the endpoint ==\n'
# ===========================================================================
t_case 'an inventory endpoint is preferred over the base-url'
_new_run pick-inv rl-open
_scanner 5000 20000
_EPF=$(_inv open rl-open 'https://open.fixture.example/api/orders')
SCOURSH_DAST_RATELIMIT_BURST=10 _phase rl-open "$_EPF"
assert_contains "$(cat "$REQ_LOG")" '/api/orders' \
  'the crawled application endpoint is bursted - FAILS under headers.sh own base-url-first preference, which here measures the CDN in front of the site root rather than the application'
assert_not_contains "$(cat "$REQ_LOG")" 'GET open.fixture.example /
' 'and the site root is not touched'

t_case 'with no inventory the base-url is the fallback'
_new_run pick-base rl-open
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=10 _phase rl-open
assert_contains "$(cat "$REQ_LOG")" 'open.fixture.example /' \
  'the operator own base-url is used when the crawl has produced nothing yet'

t_case 'an out-of-scope inventory row is refused, not fatal'
_new_run pick-oos rl-open
_scanner 5000 20000
_EPF=$(_inv oos rl-open 'https://elsewhere.invalid/api/orders')
SCOURSH_DAST_RATELIMIT_BURST=10 _phase rl-open "$_EPF"
assert_eq '0' "$(_req_count)" 'nothing is requested'
assert_contains "$(_meta coverage_reduction)" 'burst_endpoint_out_of_scope' \
  'and the run continues with a recorded reduction - FAILS if the URL is handed straight to http_request, which gates fatally (exit 3) and would abort the whole run on one bad inventory row'

# ---------------------------------------------------------------------------
# WITHOUT the shared pre-check, the same inventory kills the whole run.
# ---------------------------------------------------------------------------
MUT=$W/mutation.sh
cat >"$MUT" <<'EOM'
set -Eeuo pipefail
ROOT=$1 W=$2 INV=$3 SCOPE=$4 LOG=$5
source "$ROOT/modules/dast/engine.sh"
source "$ROOT/modules/dast/ratelimit_engine.sh"
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
config_scanner_load "$W/scanner.conf"
_m_resolve() { printf '93.184.216.34'; }
SCOURSH_HTTP_RESOLVE=_m_resolve
_m_transport() {
  printf '%s %s://%s%s\n' "$1" "$2" "$3" "$5" >>"$LOG"
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '200\n\ntext/html\n'
}
SCOURSH_HTTP_TRANSPORT=_m_transport
dast_endpoint_keep() { return 0; }
run_init "$W/run.mutation"
run_record authorization_affirmed true
run_record authorization_target rl-open
SCOURSH_DAST_TARGET=rl-open
export SCOURSH_DAST_TARGET
SCOURSH_DAST_ENDPOINTS=$INV
export SCOURSH_DAST_ENDPOINTS
source "$ROOT/modules/dast/ratelimit.sh"
EOM
OOSINV=$(_inv oosmut rl-open 'https://elsewhere.invalid/api/orders')
MUT_LOG=$W/mutation-requests.log
: >"$MUT_LOG"
MUT_RC=0
bash "$MUT" "$ROOT" "$W" "$OOSINV" "$SCOPE" "$MUT_LOG" >"$W/mutation.out" 2>&1 || MUT_RC=$?

t_case 'WITHOUT the pre-check the same inventory kills the whole run'
assert_eq 3 "$MUT_RC" \
  'the mutated phase exits SCOURSH_EXIT_SCOPE (3) - reproduced rather than described, proving the pre-check above is load-bearing'
assert_not_contains "$(cat "$MUT_LOG")" 'elsewhere.invalid' \
  'and it never even reached the unauthorised host'

# ===========================================================================
printf '\n== F. a limiter that announces itself is NOT a finding ==\n'
# ===========================================================================
# The pair below is the one a naive implementation collapses, in either
# direction, and each collapse is the other bug: fold `advertised` into
# `no_throttle` and every correctly rate-limited API is a finding; fold
# `no_throttle` into `advertised` and the check never fires.  Both halves are
# asserted here so neither can be satisfied by breaking the other.
t_case 'rate-limit headers without a 429 mean a limiter this burst did not reach'
_new_run advertised rl-adv
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=12 _phase rl-adv
assert_eq '12' "$(_req_count)" 'the burst runs to completion, because no 429 stopped it'
assert_eq '0' "$(_count_check DAST-RATE-NO_THROTTLE-01)" \
  'and NO missing-throttling finding is emitted - FAILS under the reading that only a 429 counts as throttling, which would fire this check against every correctly-configured API'
assert_contains "$(_meta notes)" 'verdict=advertised' \
  'the verdict is recorded rather than left silent'

t_case 'the other half: no headers and no 429 IS still a finding'
_new_run advertised-inverse rl-open
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=12 _phase rl-open
assert_eq '1' "$(_count_check DAST-RATE-NO_THROTTLE-01)" \
  'the check still fires on a target that advertises nothing - FAILS if the fix for the case above was widened into "never report anything"'

t_case 'end to end: a target that COLLAPSES (503) is never verdict=advertised'
# The `rl-503` target and the `down.fixture.example` transport arm above
# (always 503, always carrying Retry-After: 120) existed before this ticket
# with no case ever driving `_phase rl-503` - so the unit-level pin above was
# the only place this reading was ever checked, and the phase's own
# `advertised` notes sentence ("... so it has a limiter this probe did not
# reach") was reachable against a target that never once answered 2xx.  This
# case drives the real phase, through the real gates, exactly as
# dast_run_phase would.
_new_run collapse rl-503
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=12 _phase rl-503
assert_eq '12' "$(_req_count)" \
  'the whole burst runs: 503 is not a 429, so nothing stops it early'
assert_not_contains "$(_meta notes)" 'verdict=advertised' \
  'the target that collapsed on every request is never reported as one that defends itself - FAILS under the pre-fix reading, where the fixture own Retry-After: 120 satisfied rate_signal_scan on all twelve responses'
assert_eq '1' "$(_count_check DAST-RATE-NO_THROTTLE-01)" \
  'the missing-throttling finding fires instead: a target that never said 429, RateLimit-*, or a Retry-After untainted by a bare 5xx has demonstrated no throttling control on this endpoint'

# ===========================================================================
printf '\n== G. a target that DOES throttle ==\n'
# ===========================================================================
t_case 'the burst stops at the first 429'
_new_run throttled rl-429
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=30 _phase rl-429
assert_eq '5' "$(_req_count)" \
  'five requests: four accepted and the fifth refused - FAILS under a fixed-length burst, which would keep hammering a host that has just asked for less, ignoring the very control it came to verify'
assert_eq '0' "$(_count_check DAST-RATE-NO_THROTTLE-01)" 'and no missing-throttling finding'
assert_eq '0' "$(_count_check DAST-RATE-NO_RETRY_AFTER-01)" \
  'and no back-off finding either, because the 429 carried a usable Retry-After'

t_case 'a 429 with no Retry-After is its own finding'
_new_run bare429 rl-429-bare
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=30 _phase rl-429-bare
assert_eq '5' "$(_req_count)" 'it still stops at the 429'
assert_eq '1' "$(_count_check DAST-RATE-NO_RETRY_AFTER-01)" \
  'the back-off finding is emitted under its OWN check id - FAILS under one shared id, which the DAST fingerprint (no component names the defect) would dedupe against the missing-throttling finding'
assert_eq '0' "$(_count_check DAST-RATE-NO_THROTTLE-01)" \
  'and the target is not also reported as having no throttle at all, which would be false'

t_case 'a 429 with an unparseable Retry-After counts as no back-off'
_new_run junk429 rl-429-junk
_scanner 5000 20000
SCOURSH_DAST_RATELIMIT_BURST=30 _phase rl-429-junk
assert_eq '1' "$(_count_check DAST-RATE-NO_RETRY_AFTER-01)" \
  "a Retry-After of 'soon' is worse than an absent one, because a client that parses it gets zero and retries immediately - FAILS under a presence-only check"

# ===========================================================================
printf '\n== H. the registry and the phase agree ==\n'
# ===========================================================================
t_case 'registry agreement'
# modules/dast/checks.rules is the catalog tension 12 and tension 15 read.  It
# is SHARED with the other tier-5 tickets, so the ids are counted over THIS
# script own records - the ones whose `script:` is `ratelimit.sh` - exactly as
# tests/suites/dast-headers.sh does for its shared tier-2 file, so a peer
# appending its own block cannot make this look like a defect here.
declare -A REG_SCRIPT=() REG_TAG=() REG_SCOPE=() REG_CWE=()
_cur_id=''
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *': '* ]] || continue
  _key=${line%%': '*}; _val=${line#*': '}
  case $_key in
    id) _cur_id=$_val ;;
    script) REG_SCRIPT[$_cur_id]=$_val ;;
    cwe) REG_CWE[$_cur_id]=$_val ;;
    'coverage-scope') REG_SCOPE[$_cur_id]=$_val ;;
    tags) [[ -z ${REG_TAG[$_cur_id]:-} ]] && REG_TAG[$_cur_id]=$_val ;;
  esac
done <"$ROOT/modules/dast/checks.rules"

_reg_ids=''
for _id in "${!REG_SCRIPT[@]}"; do
  [[ ${REG_SCRIPT[$_id]} == 'ratelimit.sh' ]] && _reg_ids+="$_id "
done
assert_eq '2' "$(printf '%s' "$_reg_ids" | wc -w | tr -d ' ')" \
  'the registry declares exactly the two ids this phase can emit - FAILS if either grows without the other'
for _id in DAST-RATE-NO_THROTTLE-01 DAST-RATE-NO_RETRY_AFTER-01; do
  assert_eq 'ratelimit.sh' "${REG_SCRIPT[$_id]:-<absent>}" "$_id: the registry names this phase script"
  assert_eq 'active' "${REG_TAG[$_id]:-<absent>}" \
    "$_id: the type tag is 'active', matching modules/dast/engine.sh own ratelimit.sh:active phase-table floor - FAILS if the two gates disagree, which tension 15 forbids"
  assert_eq 'target' "${REG_SCOPE[$_id]:-<absent>}" "$_id: DAST cell is the scope target (§9.5.1)"
  assert_eq 'CWE-770' "${REG_CWE[$_id]:-<absent>}" "$_id: CWE-770, allocation without limits or throttling"
done

t_case 'the phase table registers this script at the active tier'
assert_contains "$(cat "$ROOT/modules/dast/engine.sh")" "'ratelimit.sh:active'" \
  'modules/dast/engine.sh reaches this phase through dast_run_phase, so scan_dispatch dast runs it'

# ===========================================================================
printf '\n== dast-ratelimit: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
