#!/usr/bin/env bash
# modules/dast/ratelimit_engine.sh - the §7.4 missing-throttling burst probe's
# PURE half (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-28, tier 5).
#
# docs/DESIGN.md §7.4 states this check in one sentence: "Send a bounded burst
# (respecting a hard cap) to an idempotent endpoint and flag the absence of
# `429`/rate-limit headers / back-off. Strictly capped and skippable; this is
# the one check that intentionally sends several requests, so it honors an
# explicit per-run budget."  Every clause of that sentence is a constraint this
# file implements rather than a description of it:
#
#   "bounded burst ... hard cap"  `_RATE_BURST_HARD_CAP` below, which nothing
#                                 raises - the documented environment seam can
#                                 only lower it (`rate_burst_size`).
#   "idempotent endpoint"         GET only, and one endpoint per target; the
#                                 phase script chooses it and never submits a
#                                 form or re-sends a discovered POST.
#   "absence of 429/rate-limit
#    headers / back-off"          `rate_signal_scan` - a 429 status, ANY member
#                                 of the vendored rate-limit header family, or a
#                                 `Retry-After`.  Any one of the three is a
#                                 throttle, so a target that advertises a limit
#                                 it did not reach inside the burst is NOT a
#                                 finding (`rate_verdict`).
#   "honors an explicit per-run
#    budget"                      the burst is sized from lib/http.sh's OWN
#                                 counter via `http_budget_remaining_set`, and
#                                 spends at most half of what is left.
#
# THE ONE BEHAVIOURAL AMENDMENT DAST-28 CARRIES, AND WHY IT IS AN AMENDMENT
# RATHER THAN A DESIGN CHOICE MADE HERE.  docs/STEP5-DAST-PLAN.md's
# "Amendments to DAST-01 through DAST-30" says of this ticket: "Under the
# conservative ceilings a burst probe cannot establish either a positive or a
# true negative: it would report 'no missing-throttling finding' from a scanner
# that was itself throttled below any plausible threshold.  On an unaffirmed run
# DAST-28 does not execute, and emits a `coverage_gap` naming the scanner's own
# rate ceiling as the reason."  The gate is enforced in the PHASE
# (modules/dast/ratelimit.sh), because that is where the target and the run
# record are; what lives here is the arithmetic and the verdict, so both halves
# are testable without a target.
#
# THIS FILE ISSUES NO TRAFFIC OF ITS OWN BEYOND `http_request` (tension 19).
# There is exactly one call site, in `rate_burst_run`, and it goes through the
# chokepoint like every other - so the burst is still rate-limited by DAST-01's
# token bucket, still charged to DAST-01's budget, still watched by DAST-01's
# circuit breaker, and still scope-gated on every hop.  A "burst" here therefore
# means "as fast as the run's own configured rate permits", never "as fast as
# the machine can send", and the evidence states the rate that was actually
# achieved so a reader can judge the probe rather than trust it.
#
# NON-DESTRUCTIVE, DETECTION-ONLY.  Every request is a bare GET of a URL the
# inventory or the operator's own `base-url` already named, with no parameter
# added, no body, and no credential attached; response bodies are discarded and
# never reach an artifact.  The one thing this check does that no other does is
# send the same safe request several times, which is the property §7.4 gates
# behind the affirmation.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_RATELIMIT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_RATELIMIT_ENGINE_SOURCED=1

# modules/dast/passive/headers_engine.sh is LIFTED, not forked, for four things
# this check needs byte-identically: `hdr_parse_capture` (the last-hop
# response-header reader - see its own note on why a whole-file match reads the
# WRONG response when the capture sink has accumulated redirect hops),
# `hdr_present`/`hdr_value`, `hdr_safe_text`, and `hdr_endpoints_load` (the
# docs/INVENTORY-FORMAT.md reader, deduped by path template and sorted).
# AGENTS.md states the rule this follows: "a peer that needs the same response
# reader should LIFT it deliberately rather than fork it."  A second copy would
# be a second answer to "which hop's headers are these", and this check's whole
# verdict is a statement about response headers.  Sourcing it also pulls in
# lib/http.sh and modules/dast/crawl_engine.sh through its own guarded sources,
# so this file needs neither directly.
#
# THIS IS THE ONE CONSUMER THAT STILL NAMES headers_engine.sh RATHER THAN THE
# LEAF passive/response_engine.sh, AND THAT IS DELIBERATE.  All four of those
# now live in `response_engine.sh` in substance (`hdr_endpoints_load` is a
# thin wrapper there over `resp_endpoints_load` - see that file's own ADR
# block), but `hdr_endpoints_load` the NAME, and its `_HDR_*` globals, are
# still `headers_engine.sh`'s to keep this file's call site unchanged.  This
# file genuinely uses both the reader and the chooser, so it sources the file
# that has both names and gets the reader through headers_engine.sh's own
# edge.  A future peer that needs the READER ALONE should source
# `passive/response_engine.sh` instead of copying this line.
# shellcheck source=modules/dast/passive/headers_engine.sh
source "${BASH_SOURCE[0]%/*}/passive/headers_engine.sh"

# ---------------------------------------------------------------------------
# 0. The bounds, and which of them anything may move
# ---------------------------------------------------------------------------
# THE HARD CAP.  §7.4's "respecting a hard cap" and "strictly capped" are one
# number, and it is this one.  Fifty requests is chosen rather than derived:
# it is comfortably above the per-minute allowance of every common throttling
# default (nginx `limit_req` is usually authored in the single digits per
# second, API gateways in the tens per minute), so a target with any throttle
# at all should answer inside it - and it is small enough that the probe costs
# 1% of the affirmed request budget's ceiling.  NOTHING RAISES IT: the
# environment seam below is clamped to it, and there is deliberately no
# config/scanner.conf key, both because §9.6.1 is frozen (adding one moves
# lib/records.sh and tests/lint-rules.sh together, §14 item 2) and because a
# knob whose only use is sending MORE traffic to a host is the one shape of
# knob this module does not offer.  The shape used instead is this module's
# existing one - a documented environment seam that can only narrow - exactly
# as SCOURSH_DAST_RECOMMENDED_HEADERS_FILE and SCOURSH_DAST_SQLI_PAYLOAD_DIR
# already do for their own bounds.
#
# THE THREE BOUNDS IN THIS SECTION ARE PLAIN ASSIGNMENTS, NOT `: "${VAR:=N}"`
# DEFAULTS, AND THAT IS A SECURITY PROPERTY RATHER THAN A STYLE (CWE-15).
# Written as defaults they are settable from the process environment, so
# `_RATE_BURST_HARD_CAP=5000 scan.sh dast ...` would raise the one number §7.4
# calls "strictly capped" - and `_RATE_BUDGET_DIVISOR=1` would let this probe
# spend the entire remaining per-run budget, whose exhaustion refusal is fatal
# (exit 5), ending the run for every phase and target after it.  That is the
# exact control surface AGENTS.md records DAST-32's own affirmation refusing to
# be: "an env var is settable by anything that can start the process, and
# binding callers whose command line nobody parsed is the ceiling's entire
# job."  A knob whose only effect is sending MORE traffic at a host reaches the
# operator through the command line or not at all.  Pinned in section B of
# tests/suites/dast-ratelimit.sh, in a subprocess, because the sourced-once
# guard means an assignment in an already-sourced shell would test nothing.
_RATE_BURST_HARD_CAP=50

# THE FLOOR.  Below this many requests the probe cannot say anything true: a
# handful of accepted requests is not evidence a target has no throttle, and
# reporting one would be the same overstated coverage docs/DESIGN.md §15
# forbids.  A run whose remaining budget cannot fund this many records a gap
# and sends nothing at all, rather than sending a few and guessing.  A plain
# assignment for the reason the hard cap above gives: lowering this floor from
# the environment buys a clean-looking result out of a burst too short to have
# earned one.
_RATE_BURST_MIN=10

# THE OPERATOR SEAM, clamped to the hard cap above.  Present so an operator
# scanning a target they know throttles at a low threshold can spend less, not
# so anyone can spend more.
: "${SCOURSH_DAST_RATELIMIT_BURST:=$_RATE_BURST_HARD_CAP}"

# THE BUDGET SHARE.  At most this fraction (as a divisor) of the budget still
# unspent when the probe starts.  Halving it is what keeps this check from
# being the thing that exhausts the run: lib/http.sh's budget refusal is fatal
# (exit 5, "the run stopped here rather than sending more traffic"), so a probe
# that sized itself to the whole remainder would end the run for every phase
# and every target after it.  See `http_budget_remaining_set`'s own header for
# why the number it reports is a READ and not a reservation.  A plain
# assignment for the reason the hard cap above gives - a `1` from the
# environment turns "at most half" into "all of it", which is the double-spend
# this ticket's own amendment exists to prevent.
_RATE_BUDGET_DIVISOR=2

# ---------------------------------------------------------------------------
# 1. The rate-limit header family (vendored, read from this file, never fetched)
# ---------------------------------------------------------------------------
# `rate_signal_headers` - the lowercase field names whose PRESENCE means the
# target is telling a client about a rate limit.  Three families, and all three
# are needed rather than one:
#
#   retry-after            RFC 9110 §10.2.3.  The back-off signal §7.4 names
#                          explicitly, and the only one that is also sent on a
#                          503 - which is why `rate_signal_scan` below excludes
#                          it from the scan on a 5xx response rather than
#                          reading it as a limiter's own signal.
#   ratelimit-*            RFC 9745-era IETF `RateLimit` header fields
#                          (`ratelimit`, `ratelimit-policy`, and the older
#                          draft's split `limit`/`remaining`/`reset` triple).
#   x-ratelimit-*,
#   x-rate-limit-*         The de-facto spellings that predate the RFC and are
#                          what most gateways actually emit today.  Omitting
#                          them would report "no rate limiting" against a
#                          target that says otherwise on every response.
#
# Matched by PRESENCE, never by value: a `x-ratelimit-remaining: 0` and a
# `x-ratelimit-remaining: 4999` are both a target that has a limiter, which is
# the only question this check asks of a header.
rate_signal_headers() {
  printf '%s\n' \
    retry-after \
    ratelimit \
    ratelimit-limit \
    ratelimit-remaining \
    ratelimit-reset \
    ratelimit-policy \
    x-ratelimit-limit \
    x-ratelimit-remaining \
    x-ratelimit-reset \
    x-rate-limit-limit \
    x-rate-limit-remaining \
    x-rate-limit-reset
}

# `rate_signal_scan [STATUS]` - reads the headers `hdr_parse_capture` last
# published and sets `_RATE_SIGNALS` to the LC_ALL=C-sorted, comma-joined list
# of rate-limit field names this response carried, or empty.  Deterministic
# order, because the list reaches a finding's evidence and an evidence
# sentence that reorders between runs is a diff nobody asked for.
#
# `retry-after` IS EXCLUDED FROM THE SCAN WHEN `STATUS` IS A 5xx, and that
# exclusion is the reading DAST-28's own QA pass found unpinned.
# `rate_status_is_throttle`'s own header already states the target design
# position - "a 503 under load is the target falling over, not the target
# defending itself" - and a bare `retry-after` on a 5xx is that same collapse,
# not a limiter: this file's own header on the header family names
# `retry-after` as "the only one that is also sent on a 503", so a
# `Retry-After: 120` next to a 503 reached `rate_verdict` as an `advertised`
# signal and reported a target that COLLAPSED under the burst as one that
# defends itself - the exact reading `rate_status_is_throttle`'s header says
# must never happen, just reached through the OTHER predicate instead of that
# one.  The `ratelimit-*`/`x-ratelimit-*` families carry no such ambiguity -
# nothing serves them from a generic error page - so only `retry-after` is
# excluded, and only on a 5xx; a 200 (or any non-5xx) carrying it is untouched,
# which is what keeps a real limiter's own `Retry-After` still reading as
# `advertised`.  Pinned in both directions in tests/suites/dast-ratelimit.sh
# section A2, and end-to-end through the phase in section H2 (the `rl-503`
# fixture, previously written but never driven by any case).
rate_signal_scan() {
  local status=${1:-} n
  local -a found=()
  _RATE_SIGNALS=''
  while IFS= read -r n; do
    [[ $n == retry-after && $status == 5* ]] && continue
    hdr_present "$n" && found+=("$n")
  done < <(rate_signal_headers | LC_ALL=C sort)
  (( ${#found[@]} > 0 )) || return 1
  # Guarded expansion even though the line above proves the array is non-empty.
  # tension 24 freezes bash 4.2 as the minimum, where expanding an EMPTY array
  # unguarded is an unbound-variable error under `set -u`, and
  # tests/lint-shell.sh enforces the guarded form repository-wide rather than
  # reasoning about reachability at each site.  (That lint is a text match, so
  # this note deliberately describes the unguarded form rather than spelling
  # it - the same trap AGENTS.md records for prose that starts a shellcheck
  # directive.)
  _RATE_SIGNALS=$(printf '%s,' "${found[@]+"${found[@]}"}")
  _RATE_SIGNALS=${_RATE_SIGNALS%,}
  return 0
}

# `rate_status_is_throttle STATUS` - 0 for a status that IS the target
# throttling.  429 (RFC 6585 §4) is the answer; 503 deliberately is NOT.
#
# THE 503 EXCLUSION IS THE READING THIS FUNCTION EXISTS TO PIN, and it fails in
# the direction that reads as a pass.  A 503 under load is the target falling
# over, not the target defending itself, and counting it as throttling would
# turn "this endpoint collapses when you ask for it fifty times" - the worse
# outcome - into a clean bill of health for the very control being tested.
# lib/http.sh's own breaker draws the same line from the other side: a 5xx is a
# failure it counts and a 429 is not (`_http_status_is_failure`), so a target
# that 503s under this burst opens the circuit breaker and stops the run rather
# than being reported as throttled.
rate_status_is_throttle() {
  [[ $1 == 429 ]]
}

# `rate_retry_after_is_usable VALUE` - 0 when the value is something a client
# can actually back off on: RFC 9110 §10.2.3 allows delta-seconds OR an
# HTTP-date, so both are accepted and anything else is not.  A `Retry-After`
# whose value is neither is worse than an absent one, because a client that
# parses it gets zero and retries immediately.
rate_retry_after_is_usable() {
  local v=$1
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  [[ -n $v ]] || return 1
  [[ $v =~ ^[0-9]+$ ]] && return 0
  # An IMF-fixdate / obs-date always carries a three-letter month, which is the
  # cheapest whole-string test that no bare token passes; the exact date is not
  # re-validated here, because this check is "did the server offer a back-off a
  # client can use", not "is this timestamp well-formed to the byte".
  [[ $v =~ (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ]] && [[ $v =~ [0-9]{4} ]]
}

# ---------------------------------------------------------------------------
# 2. Sizing the burst against lib/http.sh's own budget counter
# ---------------------------------------------------------------------------
# `rate_burst_size` - sets `_RATE_BURST_N` (0 when the probe must not run) and
# `_RATE_BURST_WHY` (the sentence the phase records).  Also publishes
# `_RATE_BUDGET_REMAINING` and `_RATE_BUDGET_TOTAL` so the phase can state them.
#
# The order of the three bounds is not arbitrary.  The operator's own request
# is taken first and clamped to the hard cap (never above it, whatever was
# asked for), then the budget share is applied, then the floor decides whether
# what is left is worth sending at all.  Applying the floor before the budget
# share would let a run with 12 requests left send 12 and leave nothing for any
# later phase; applying the cap after the budget share would let a huge budget
# lift the cap, which is exactly what "hard" means it must not do.
rate_burst_size() {
  local want cap remaining share
  _RATE_BURST_N=0
  _RATE_BURST_WHY=''

  http_budget_remaining_set remaining
  _RATE_BUDGET_REMAINING=$remaining
  _RATE_BUDGET_TOTAL=$_HTTP_BUDGET_TOTAL

  want=$SCOURSH_DAST_RATELIMIT_BURST
  if ! [[ $want =~ ^[0-9]+$ ]] || (( want <= 0 )); then
    # A malformed seam value is refused rather than silently replaced with the
    # cap: the operator asked for something, and quietly sending the maximum
    # instead is the one substitution a traffic-sending knob must never make.
    _RATE_BURST_WHY="SCOURSH_DAST_RATELIMIT_BURST is '$want', which is not a positive whole number of requests; the burst probe did not run rather than substitute a request count the operator did not ask for."
    return 1
  fi
  cap=$want
  (( cap > _RATE_BURST_HARD_CAP )) && cap=$_RATE_BURST_HARD_CAP

  share=$(( remaining / _RATE_BUDGET_DIVISOR ))
  (( cap > share )) && cap=$share

  if (( cap < _RATE_BURST_MIN )); then
    _RATE_BURST_WHY="the per-run request budget has $remaining of $_RATE_BUDGET_TOTAL request(s) left, and this probe spends at most half of what remains so it can never be the phase that exhausts the run - which leaves room for $cap request(s), below the $_RATE_BURST_MIN needed for a burst to mean anything. No burst was sent."
    return 1
  fi

  _RATE_BURST_N=$cap
  return 0
}

# ---------------------------------------------------------------------------
# 3. The burst
# ---------------------------------------------------------------------------
# `rate_burst_run TARGET URL N` - send up to N GETs of URL through
# `http_request` and publish what came back:
#
#   _RATE_SENT             requests actually issued
#   _RATE_THROTTLED_AT     1-based index of the first 429, or 0
#   _RATE_SIGNAL_AT        1-based index of the first response carrying a
#                          rate-limit header, or 0
#   _RATE_SIGNALS_SEEN     the comma-joined field names, from that response
#   _RATE_RETRY_AFTER      the `Retry-After` value on the throttling response
#   _RATE_STATUSES         comma-joined distinct statuses, in first-seen order
#   _RATE_UNREACHABLE      requests that returned no usable response
#   _RATE_ELAPSED_MS       wall clock across the burst
#
# IT STOPS AT THE FIRST 429, and that is a deliberate asymmetry rather than an
# optimisation.  Once the target has said "too many", every further request is
# traffic that can only confirm what is already known, against a host that has
# just asked for less - so continuing would be the tool ignoring the very
# control it came to verify.  The negative case has no such early exit: "no 429
# in N requests" is only true of N, so the full burst is what earns it.
#
# It never attaches a credential and never sends a body, so nothing here can
# leak one; the response body is discarded outright and only the header capture
# is read, through the same last-hop reader every other DAST check uses.
rate_burst_run() {
  local target=$1 url=$2 n=$3
  local i status started ended cap_hdrs

  _RATE_SENT=0 _RATE_THROTTLED_AT=0 _RATE_SIGNAL_AT=0
  _RATE_SIGNALS_SEEN='' _RATE_RETRY_AFTER='' _RATE_STATUSES=''
  _RATE_UNREACHABLE=0 _RATE_ELAPSED_MS=0

  # `.` is deliberately NOT the fallback: with no scratch dir this would drop a
  # capture file into the CURRENT WORKING DIRECTORY, which under a scan is the
  # operator's own tree.  The same fallback modules/dast/passive/cookies.sh
  # already uses, and lib/core.sh's `umask 077` covers the mode either way.
  cap_hdrs=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/dast-ratelimit.$$.head
  started=$(now_epoch_ns)

  for (( i = 1; i <= n; i++ )); do
    : >"$cap_hdrs"
    http_request_capture '' "$cap_hdrs"
    if ! http_request GET "$url" 5 "$target"; then
      # No usable response: counted, and the burst continues, because a single
      # transport failure inside a burst is ordinary and lib/http.sh's own
      # circuit breaker is what decides when enough of them means stop.
      _RATE_UNREACHABLE=$(( _RATE_UNREACHABLE + 1 ))
      _RATE_SENT=$(( _RATE_SENT + 1 ))
      continue
    fi
    _RATE_SENT=$(( _RATE_SENT + 1 ))
    status=${_HTTP_LAST_STATUS:-}
    _rate_status_note "$status"

    if hdr_parse_capture "$cap_hdrs"; then
      if rate_signal_scan "$status" && (( _RATE_SIGNAL_AT == 0 )); then
        _RATE_SIGNAL_AT=$i
        _RATE_SIGNALS_SEEN=$_RATE_SIGNALS
      fi
      if rate_status_is_throttle "$status"; then
        _RATE_THROTTLED_AT=$i
        hdr_value retry-after
        _RATE_RETRY_AFTER=$_HDR_V
        break
      fi
    elif rate_status_is_throttle "$status"; then
      # A 429 whose headers could not be read at all is still a 429.
      _RATE_THROTTLED_AT=$i
      break
    fi
  done

  ended=$(now_epoch_ns)
  _RATE_ELAPSED_MS=$(( (ended - started) / 1000000 ))
  (( _RATE_ELAPSED_MS >= 0 )) || _RATE_ELAPSED_MS=0
  rm -f "$cap_hdrs"
  return 0
}

# Append STATUS to `_RATE_STATUSES` the first time it is seen, preserving
# first-seen order so the evidence reads as a summary of the burst rather than
# as a set.
_rate_status_note() {
  local s=$1
  [[ -n $s ]] || return 0
  case ",$_RATE_STATUSES," in
    *",$s,"*) return 0 ;;
  esac
  _RATE_STATUSES="${_RATE_STATUSES:+$_RATE_STATUSES,}$s"
  return 0
}

# ---------------------------------------------------------------------------
# 4. The verdict
# ---------------------------------------------------------------------------
# `rate_verdict` - reads the accumulators `rate_burst_run` published and sets
# `_RATE_VERDICT` to exactly one of:
#
#   no_throttle       N requests completed, no 429 and no rate-limit header on
#                     any of them.  This is the finding §7.4 asks for.
#   no_retry_after    the target DID throttle, but the 429 carried no usable
#                     `Retry-After`, so a client has no back-off to honour.
#   throttled         the target throttled and said how to back off.  Clean.
#   advertised        no 429, but the target published rate-limit headers, so it
#                     HAS a limiter this burst simply did not reach.  Clean, and
#                     the reading that matters: treating it as `no_throttle`
#                     would report a missing control against a target that
#                     documents the control on every response.
#   inconclusive      nothing usable came back at all.
#
# `advertised` and `no_throttle` are the pair a naive implementation collapses,
# in either direction, and each collapse is the other's bug: fold `advertised`
# into `no_throttle` and every rate-limited API in the world is a finding; fold
# `no_throttle` into `advertised` and the check never fires.  Both directions
# are pinned in tests/suites/dast-ratelimit.sh.
rate_verdict() {
  _RATE_VERDICT=inconclusive
  (( _RATE_SENT > _RATE_UNREACHABLE )) || return 0
  if (( _RATE_THROTTLED_AT > 0 )); then
    if rate_retry_after_is_usable "$_RATE_RETRY_AFTER"; then
      _RATE_VERDICT=throttled
    else
      _RATE_VERDICT=no_retry_after
    fi
    return 0
  fi
  if (( _RATE_SIGNAL_AT > 0 )); then
    _RATE_VERDICT=advertised
    return 0
  fi
  _RATE_VERDICT=no_throttle
  return 0
}

# `rate_observed_rate` - the requests per second the burst ACTUALLY achieved,
# to three decimals, into `_RATE_OBSERVED_RPS`.
#
# It is in the evidence of every finding this check emits, and that is an
# honesty requirement rather than a detail.  The probe is throttled by the
# scanner's own limiter, so "fifty requests produced no 429" means nothing
# without the rate they were sent at - a reader who cannot see it cannot tell a
# real negative from a scanner that trickled the burst out over a minute.
rate_observed_rate() {
  local ms=$_RATE_ELAPSED_MS n=$_RATE_SENT milli
  if (( ms <= 0 )); then
    _RATE_OBSERVED_RPS='unmeasurable'
    return 0
  fi
  milli=$(( n * 1000 * 1000 / ms ))
  printf -v _RATE_OBSERVED_RPS '%s.%03d' $(( milli / 1000 )) $(( milli % 1000 ))
  return 0
}

# ---------------------------------------------------------------------------
# 5. Emitting a finding
# ---------------------------------------------------------------------------
# One helper, so both check ids carry the identical DAST location profile
# (tension 5: target, method, path_template, param_location, param_name).  The
# burst is not parameterised - it re-sends the same URL - so `param_location`
# and `param_name` are empty, exactly as the header checks leave them: the
# defect is a property of the endpoint, not of an input to it.
#
# TWO CHECK IDS RATHER THAN ONE, for the reason modules/dast/active/checks.rules
# already records for the SQLi family: the DAST fingerprint carries no component
# naming the DEFECT, so "no throttling at all" and "throttles but never says how
# to back off" on the same endpoint would collide and dedupe to one finding -
# and they are different defects with different remediations and different
# severities.
#
# Evidence goes through `finding_set_evidence` so it is redacted, truncated and
# control-stripped (tension 9/10); no response body is ever read, so nothing
# target-authored reaches it beyond the header field NAMES and a `Retry-After`
# value, both bounded by `hdr_safe_text`.
rate_emit_finding() {
  local check_id=$1 severity=$2 title=$3 target=$4 url=$5 path=$6
  local evidence=$7 remediation=$8

  finding_new
  finding_set check_id "$check_id"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence medium
  finding_set cwe CWE-770
  finding_set owasp A04:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method GET
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location ''
  finding_set loc_param_name ''
  finding_set url "$url"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
