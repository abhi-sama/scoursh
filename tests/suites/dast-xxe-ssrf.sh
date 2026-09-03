#!/usr/bin/env bash
# tests/suites/dast-xxe-ssrf.sh - modules/dast/active/xxe_ssrf.sh and its
# shared modules/dast/active/inject_engine.sh: XXE / SSRF detection via
# safe, in-scope sentinels only (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-20, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"). The suite runs on a host with no
# network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and
# the rejected reading pins nothing.
#
#   1. An INTERNAL entity's random marker reflected back is
#      DAST-INJ-XXE_ENTITY-01 - no network, no sentinel needed. A parser that
#      never reflects it (a control endpoint) must not flag.
#   2. An EXTERNAL entity naming the in-scope sentinel is
#      DAST-INJ-XXE_SSRF-01 only when the response carries a content
#      signature this run independently fetched from that exact sentinel URL
#      moments earlier - never on mere byte-length change, and never when
#      that signature was ALREADY present in the endpoint's own baseline
#      (a noisy control).
#   3. The identical sentinel URL sent as a PLAIN parameter value (no XML at
#      all) is DAST-INJ-SSRF_PARAM-01 under the same content-signature rule,
#      and it fires on a GET endpoint exactly as it does on a POST one -
#      this technique is method-independent, unlike the two XML techniques.
#   4. XML body-override techniques (1 and 2) run ONLY against POST/PUT/PATCH
#      endpoints; a GET-only endpoint receives no XML request at all, but its
#      parameters are still reachable by technique 3.
#   5. The sentinel is drawn ONLY from config/scope.conf's base-url or one of
#      the target's own extra-host entries - never invented, never an
#      operator-supplied arbitrary host - and falls back to the target's own
#      base-url (self-referential) when no extra-host is declared.
#   6. Every skip path (no sentinel, no oracle, wrong method, noisy baseline,
#      uninjectable parameter, deselected check) records a NAMED reason, and
#      checks_run carries only the ids that really executed.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes XML/parameter syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut (modules/dast/active/inject_engine.sh): this file already reaches that
# target through another edge, so following it here only re-expands the
# lib/ hub chain a second time - which is what peak RSS is made of. See
# docs/CI-RUNBOOK.md, "the memory model".
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# The REAL dast_check_selected (modules/dast/engine.sh section 3a), rather
# than a stub of it - see tests/suites/dast-ssti.sh's identical comment for
# why this is sourced rather than restated.
#
# -x back-edge cut: modules/dast/engine.sh sources modules/sast/engine.sh and
# lib/checks.sh on top of the lib/http.sh diamond this file already carries
# through inject_engine.sh (AGENTS.md, "a DIAMOND in a perfectly acyclic
# graph"). The directive is static only - the real function is still sourced
# and still runs; it is checked as its own entry point in the whole-tree
# stage.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/lib/bounded-read.sh
source "$ROOT/tests/lib/bounded-read.sh"

W=$SCOURSH_SCRATCH/dast-xxe-ssrf-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope: a target with an `extra-host` declared, so the sentinel picked is
# the STRONGER cross-host variant (case 5's "preferred" half; the
# self-referential fallback is its own case near the end of this file).
# ---------------------------------------------------------------------------
XS_BASE_HOST=xs.fixture.example
XS_SENTINEL_HOST=sentinel.fixture.example
SCOPE=$W/scope.conf
# A QUOTED heredoc with the literal domains written out (rather than
# interpolating $XS_BASE_HOST/$XS_SENTINEL_HOST) so DAST-35's static,
# no-egress lint (tests/lint-shell.sh) can see the reserved-example-domain
# text directly in this shipped file, exactly as every sibling §7.3 suite's
# scope fixture does.
cat >"$SCOPE" <<'EOF'
id: xs-fixture
base-url: https://xs.fixture.example/
extra-host: sentinel.fixture.example
notes: Fixture target for tests/suites/dast-xxe-ssrf.sh. Never dialled: both
  the resolver and the transport are stubbed. The extra-host is this run's
  operator-declared SSRF sentinel (docs/DESIGN.md §7.3).
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_xs_resolve() {
  case $1 in
    "$XS_BASE_HOST") printf '203.0.113.10' ;;
    "$XS_SENTINEL_HOST") printf '203.0.113.11' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_xs_resolve

# ---------------------------------------------------------------------------
# The oracle content. Deliberately 59 bytes: >= _XS_ORACLE_MIN_BYTES(32) and
# short enough that _xs_oracle_fetch's slice-from-the-middle window (offset
# blen/4, length 96) always resets to offset 0 and so yields the WHOLE body
# as the signature - which is what lets this fixture treat "the sentinel's
# content" and "the oracle signature" as the same string without duplicating
# the implementation's own offset arithmetic here.
# ---------------------------------------------------------------------------
ORACLE_BODY=$(printf 'XS-ORACLE-CONTENT-%040d' 7)

# ---------------------------------------------------------------------------
# The mock target and the mock sentinel, in one transport stub.
# ---------------------------------------------------------------------------
#   /upload          POST, 0 params - VULNERABLE to both XML techniques: an
#                     internal entity's value is reflected verbatim, and an
#                     external entity naming the sentinel is "fetched"
#                     (its response echoes the oracle content).
#   /formsafe        POST, 0 params - control: a hardened parser, reflects
#                     neither an internal entity's value nor an external
#                     fetch's content.
#   /formnoisy       POST, 0 params - control: EVERY response (baseline
#                     included) already carries the oracle content, so
#                     DAST-INJ-XXE_SSRF-01 must not attribute it to the probe.
#   /fetch           GET, param `url` (query) - VULNERABLE to
#                     DAST-INJ-SSRF_PARAM-01: reflects the oracle content
#                     when `url` names the sentinel. GET, like every other
#                     technique-3-only fixture below, so techniques 1/2
#                     (POST/PUT/PATCH only) never touch it - only /upload,
#                     /formsafe and /formnoisy are POST.
#   /preview         GET, param `target_url` (query) - a SECOND SSRF sink,
#                     proving technique 3 finds more than one endpoint.
#   /echofetch       GET, param `q` (query) - control: echoes the RAW
#                     parameter STRING back, never fetched content.
#   /noisyfetch      GET, param `n` (query) - control: every response
#                     already carries the oracle content (noisy baseline).
#   /cleanfetch      GET, param `safe` (query) - control: never anything.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }
_req_total() { local n=0; while IFS= read -r _; do n=$(( n + 1 )); done <"$REQ_LOG"; printf '%s' "$n"; }

_xs_transport() {
  local method=$1 host=$3 path=$5
  local body=${_HTTP_TX_BODY:-}
  local status=200 out='<html><body>ok</body></html>'

  if [[ $host == "$XS_SENTINEL_HOST" ]]; then
    out=$ORACLE_BODY
  else
    case $path in
      /upload)
        if [[ $body == *"SYSTEM \"https://$XS_SENTINEL_HOST/\""* ]]; then
          out="<result>$ORACLE_BODY</result>"
        elif [[ $body == *'<!ENTITY x "'* ]]; then
          local marker=${body#*'<!ENTITY x "'}
          marker=${marker%%'"'*}
          out="<result>$marker</result>"
        fi
        ;;
      /formsafe)
        out='<result>nothing to see here</result>'
        ;;
      /formnoisy)
        out="<result>boilerplate $ORACLE_BODY footer, on every response</result>"
        ;;
      /fetch\?*)
        if [[ $path == *"https%3A%2F%2F$XS_SENTINEL_HOST%2F"* ]]; then
          out="<result>$ORACLE_BODY</result>"
        fi
        ;;
      /preview\?*)
        if [[ $path == *"https%3A%2F%2F$XS_SENTINEL_HOST%2F"* ]]; then
          out="<result>$ORACLE_BODY</result>"
        fi
        ;;
      /echofetch\?*)
        out="<result>you searched: $(printf '%s' "$path" | tr -d '\n')</result>"
        ;;
      /noisyfetch\?*)
        out="<result>always has $ORACLE_BODY in it</result>"
        ;;
      /cleanfetch\?*)
        out='<result>clean</result>'
        ;;
    esac
  fi
  printf '%s %s %s\n' "$method" "$host" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_xs_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  local dir=$1
  mkdir -p "$dir"
  cat >"$dir/endpoints.json" <<EOF
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_upload",     "target": "xs-fixture", "method": "POST", "url": "https://$XS_BASE_HOST/upload",     "path": "/upload" },
  { "id": "ep_formsafe",   "target": "xs-fixture", "method": "POST", "url": "https://$XS_BASE_HOST/formsafe",   "path": "/formsafe" },
  { "id": "ep_formnoisy",  "target": "xs-fixture", "method": "POST", "url": "https://$XS_BASE_HOST/formnoisy",  "path": "/formnoisy" },
  { "id": "ep_fetch",      "target": "xs-fixture", "method": "GET",  "url": "https://$XS_BASE_HOST/fetch",      "path": "/fetch" },
  { "id": "ep_preview",    "target": "xs-fixture", "method": "GET",  "url": "https://$XS_BASE_HOST/preview",    "path": "/preview" },
  { "id": "ep_echofetch",  "target": "xs-fixture", "method": "GET",  "url": "https://$XS_BASE_HOST/echofetch",  "path": "/echofetch" },
  { "id": "ep_noisyfetch", "target": "xs-fixture", "method": "GET",  "url": "https://$XS_BASE_HOST/noisyfetch", "path": "/noisyfetch" },
  { "id": "ep_cleanfetch", "target": "xs-fixture", "method": "GET",  "url": "https://$XS_BASE_HOST/cleanfetch", "path": "/cleanfetch" }
] }
EOF
  cat >"$dir/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_fetch",      "target": "xs-fixture", "name": "url",        "location": "query", "example": "1" },
  { "id": "p2", "endpoint_id": "ep_preview",    "target": "xs-fixture", "name": "target_url", "location": "query", "example": "1" },
  { "id": "p3", "endpoint_id": "ep_echofetch",  "target": "xs-fixture", "name": "q",          "location": "query", "example": "hello" },
  { "id": "p4", "endpoint_id": "ep_noisyfetch", "target": "xs-fixture", "name": "n",          "location": "query", "example": "1" },
  { "id": "p5", "endpoint_id": "ep_cleanfetch", "target": "xs-fixture", "name": "safe",       "location": "query", "example": "ok" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target xs-fixture
  occurrence_reset_all
  _req_reset
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

# `_count_finding CHECK PARAM` counts findings whose `check_id` AND
# `loc_param_name` fields both match exactly (lib/findings.sh's `.fields`
# shard format: one finding per line, TAB-delimited `key=value` fields).
_count_finding() {
  local check=$1 param=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_param_name=$param" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

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

# ---------------------------------------------------------------------------
# Boot: source the phase against a throwaway, empty-inventory run - a
# harmless no-op that records a gap - exactly as every sibling §7.3 suite
# does (the phase script runs itself at source time; dast_run_phase is what
# invokes it for real).
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=xs-fixture
SCOURSH_DAST_CELL=xs-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/xxe_ssrf.sh
source "$ROOT/modules/dast/active/xxe_ssrf.sh"

# ===========================================================================
printf '== dast xxe_ssrf: internal-entity reflection (DAST-INJ-XXE_ENTITY-01) ==\n'
# ===========================================================================
_write_full_inventory "$W/inv-main"
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_dast_xxe_ssrf_phase

assert_eq 1 "$(_count_finding DAST-INJ-XXE_ENTITY-01 '(xml-entity-internal)')" \
  "exactly one internal-entity finding, on /upload - FAILS if the marker match is never checked, or if the probe fires more than once per endpoint"

# ===========================================================================
printf '== dast xxe_ssrf: a hardened parser (control) never flags DAST-INJ-XXE_ENTITY-01 ==\n'
# ===========================================================================
# /formsafe never reflects the internal entity's value, so it must not
# appear as a second finding above, and there must be no finding at all
# attributable to it.
assert_eq 1 "$(_count_check DAST-INJ-XXE_ENTITY-01)" \
  "the entity check fired exactly once total, not once per endpoint tested - FAILS if /formsafe (which reflects nothing) is wrongly flagged too"

# ===========================================================================
printf '== dast xxe_ssrf: external-entity SSRF confirmation (DAST-INJ-XXE_SSRF-01) ==\n'
# ===========================================================================
assert_eq 1 "$(_count_check DAST-INJ-XXE_SSRF-01)" \
  "exactly one XXE-driven-SSRF finding, on /upload, whose external entity names the in-scope sentinel and whose response reflects the sentinel's own independently-fetched content - FAILS if the probe never fetches an oracle, or accepts any byte change as a signal"
assert_eq 1 "$(_count_finding DAST-INJ-XXE_SSRF-01 '(xml-entity-external)')" \
  "the finding is located at the external-entity param name, distinct from the internal-entity finding's own location"

# ===========================================================================
printf '== dast xxe_ssrf: a noisy baseline (control) suppresses DAST-INJ-XXE_SSRF-01 ==\n'
# ===========================================================================
# /formnoisy's every response - baseline included - already carries the
# oracle's own content, so a "match" after injection cannot be attributed to
# the request. This is asserted by the total count above already being 1
# (not 2): if the noisy check were skipped, /formnoisy would add a second
# hit here.
REQ_UPLOAD_LIKE=$(grep -cE ' /(upload|formsafe|formnoisy)$' "$REQ_LOG" || true)
assert_eq 8 "$REQ_UPLOAD_LIKE" \
  "/upload and /formsafe each get 3 requests (baseline + internal-entity + external-entity); /formnoisy gets only 2 (baseline + internal-entity) because its baseline is ALREADY noisy, so the probe skips the external-entity send entirely rather than spending a request whose result could never be attributed - 3+3+2=8. And NOTHING else: the five technique-3-only fixtures below are all GET and so never receive one - FAILS if the probe skips a baseline, sends more than one XML variant per technique where the baseline was clean, still sends the external-entity probe after a noisy baseline, or runs the XML techniques against a GET endpoint"
REQ_FORMNOISY=$(grep -cE ' /formnoisy$' "$REQ_LOG" || true)
assert_eq 2 "$REQ_FORMNOISY" \
  "/formnoisy gets EXACTLY 2 requests (baseline + internal-entity), never 3 - FAILS if the external-entity probe is sent anyway after the baseline already proved noisy, which would waste a request the run can never attribute"

# ===========================================================================
printf '== dast xxe_ssrf: per-parameter SSRF (DAST-INJ-SSRF_PARAM-01), method-agnostic ==\n'
# ===========================================================================
assert_eq 1 "$(_count_finding DAST-INJ-SSRF_PARAM-01 url)" \
  "the POST endpoint's 'url' parameter is confirmed - FAILS if the sentinel URL is never tried as a parameter value"
assert_eq 1 "$(_count_finding DAST-INJ-SSRF_PARAM-01 target_url)" \
  "the GET endpoint's 'target_url' parameter is ALSO confirmed - technique 3 is not restricted to POST/PUT/PATCH the way techniques 1 and 2 are, which is the whole reason /preview exists as a GET fixture"
assert_eq 0 "$(_count_finding DAST-INJ-SSRF_PARAM-01 q)" \
  "NO finding on 'q': /echofetch reflects the raw parameter STRING back, never fetched content - FAILS if reflection of the payload text alone is read as a signal"
assert_eq 0 "$(_count_finding DAST-INJ-SSRF_PARAM-01 n)" \
  "NO finding on 'n': the oracle signature is present on the BASELINE too (a noisy parameter) - FAILS if the probe flags without comparing to a clean baseline first"
assert_eq 0 "$(_count_finding DAST-INJ-SSRF_PARAM-01 safe)" \
  "the control parameter 'safe' yields no finding - FAILS if any probe flags a non-vulnerable parameter"

# sanity: /preview (GET-only) WAS requested at all, by technique 3.
REQ_PREVIEW_ANY=$(grep -cE '/preview' "$REQ_LOG" || true)
assert_ne 0 "$REQ_PREVIEW_ANY" "sanity: /preview WAS requested at all (by technique 3)"

# ===========================================================================
printf '== dast xxe_ssrf: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-XXE_ENTITY-01' "checks_run records the internal-entity technique, which really executed"
assert_contains "$CR" 'DAST-INJ-XXE_SSRF-01' "checks_run records the external-entity technique, which really executed"
assert_contains "$CR" 'DAST-INJ-SSRF_PARAM-01' "checks_run records the per-parameter technique, which really executed"

# ===========================================================================
printf '== dast xxe_ssrf: no inventory at all degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_xxe_ssrf_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, xxe_ssrf emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known endpoint or parameter' \
  "no inventory records a coverage_gap the report renders"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
assert_eq 0 "$(_req_total)" "no inventory means no request was sent at all, not even an oracle fetch"
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json

# ===========================================================================
printf '== dast xxe_ssrf: per-check selection (tension 15) ==\n'
# ===========================================================================
# Only the internal-entity check is selected: the other two must not run,
# and their absence from checks_run must be a NAMED reduction, not silence.
_new_run selected
SCOURSH_SELECTED_CHECKS=$'DAST-INJ-XXE_ENTITY-01\n'
export SCOURSH_SELECTED_CHECKS
_dast_xxe_ssrf_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-XXE_ENTITY-01' 'the selected technique still runs'
assert_not_contains "$CR" 'DAST-INJ-XXE_SSRF-01' \
  'checks_run does NOT name a technique the filter chain excluded - FAILS under a reading that writes all three ids unconditionally'
assert_not_contains "$CR" 'DAST-INJ-SSRF_PARAM-01' \
  'the deselected per-parameter technique is likewise absent from checks_run'
RED=$(run_facts coverage_reduction)
assert_contains "$RED" 'reason=check_not_selected check=DAST-INJ-XXE_SSRF-01' \
  'a deselected technique records a named coverage_reduction'
assert_contains "$RED" 'reason=check_not_selected check=DAST-INJ-SSRF_PARAM-01' \
  'so does the other deselected technique'
assert_eq 1 "$(_count_check DAST-INJ-XXE_ENTITY-01)" 'the selected technique still finds its vulnerable endpoint'
assert_eq 0 "$(grep -cE '/(fetch|preview)' "$REQ_LOG" || true)" \
  'a deselected per-parameter technique sends NO request to its own endpoints at all - asserted on the request log, because a probe that dialled the target and then declined to report is exactly what per-check selection exists to prevent'

# Every technique deselected: nothing is sent at all and the run says so.
_new_run noneselected
SCOURSH_SELECTED_CHECKS=$'DAST-DISC-BACKUP-01\n'
_dast_xxe_ssrf_phase
assert_eq 0 "$(_req_total)" \
  'with every technique excluded the probe sends ZERO requests, including no oracle fetch'
assert_contains "$(run_facts coverage_gap)" 'every XXE/SSRF technique was excluded' \
  'an all-excluded run records a coverage_gap rather than looking like a clean scan'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" 'checks_run is empty when nothing executed'

# THE OTHER DIRECTION: dast_check_selected ABSENT from the process must read
# as permissive, exactly as every sibling §7.3 probe requires (see
# tests/suites/dast-ssti.sh's identical case for the full argument).
_new_run guardabsent
SCOURSH_SELECTED_CHECKS=$'DAST-DISC-BACKUP-01\n'
_xs_saved_sel=$(declare -f dast_check_selected)
unset -f dast_check_selected
_dast_xxe_ssrf_phase
assert_eq 1 "$(_count_check DAST-INJ-XXE_ENTITY-01)" \
  'with dast_check_selected ABSENT the phase still probes and still finds - FAILS under a fail-closed guard or an unguarded call, either of which silently makes every direct-engine run of this phase inert while looking exactly like a clean scan'
eval "$_xs_saved_sel"
unset SCOURSH_SELECTED_CHECKS

# ===========================================================================
printf '== dast xxe_ssrf: SCOPE ENFORCEMENT - only declared hosts are ever named ==\n'
# ===========================================================================
_new_run scopecheck
_dast_xxe_ssrf_phase
HOSTS_TALKED_TO=$(awk '{print $2}' "$REQ_LOG" | LC_ALL=C sort -u)
assert_eq "$XS_SENTINEL_HOST"$'\n'"$XS_BASE_HOST" "$HOSTS_TALKED_TO" \
  "every request this run made was to the target's own base-url host or to its declared extra-host - FAILS if any third host is ever contacted, which would mean a payload named something the operator never authorised"

# ===========================================================================
printf '== dast xxe_ssrf: with no extra-host declared, the sentinel is the target itself ==\n'
# ===========================================================================
SELF_SCOPE=$W/scope-self.conf
cat >"$SELF_SCOPE" <<'EOF'
id: xs-self-fixture
base-url: https://self.fixture.example/
notes: No extra-host declared - the sentinel must fall back to this target's
  own base-url (self-referential, still fully in scope).
EOF
http_scope_load "$SELF_SCOPE"
_xs_sentinel_set xs-self-fixture
assert_eq 'https://self.fixture.example/' "$_XS_SENTINEL_URL" \
  "with no extra-host declared, the sentinel falls back to the target's own base-url - FAILS if the probe requires an extra-host and cannot run at all on the ordinary scope.conf that declares none"
assert_eq 1 "$_XS_SENTINEL_IS_SELF" "the self-referential case is recorded as such"
# Restore the main fixture scope for anything sourced after this point.
http_scope_load "$SCOPE"


# ===========================================================================
printf '== dast xxe_ssrf: the ORACLE FETCH body read is bounded AT READ TIME, never after a full slurp ==\n'
# ===========================================================================
# Regression for the ticket ("Bound the same slurp-then-truncate body reads in
# other DAST body-capture call sites"): `_xs_oracle_fetch` used to
# `read -r -d ''` the WHOLE captured sentinel response into a bash variable
# with NO cap at all afterward - worse than the plain "trim after a full
# slurp" shape modules/dast/active/discovery.sh's own `_discovery_probe`
# fixed, since even the after-the-fact trim never ran here. It now reuses
# inject_engine.sh's own `_INJ_MAX_BODY_BYTES` cap via `read -N`, exactly as
# `_xs_send_xml`'s own `_XS_BODY` already did (see the next section).
#
# Proof shape mirrors tests/suites/dast-discovery.sh's own huge-body case: a
# 256 MiB sentinel response (1024x the default 256 KiB cap) is served, and
# the whole call is timed against an 800ms ceiling - measured well under
# 200ms fixed, 1.7+ seconds unbounded for the identical fixture on this host.
XS_HUGE_MARKER=$W/xs-huge-producer-finished
XS_HUGEFILE=$W/xs-huge-oracle-body.raw
if [[ ! -f $XS_HUGEFILE ]]; then
  hs='a'
  for _ in $(seq 1 28); do hs+=$hs; done
  printf '%s' "$hs" >"$XS_HUGEFILE"
  unset hs
fi

_xs_huge_oracle_transport() {
  local method=$1 host=$3 path=$5
  printf '%s %s\n' "$method" "$host" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $host == "$XS_SENTINEL_HOST" ]]; then
      # Served through a FIFO, so the PRODUCER'S own progress reports whether
      # the whole body was read - see tests/lib/bounded-read.sh.
      bounded_read_serve_fifo "$_HTTP_TX_BODY_OUT" "$XS_HUGEFILE" "$XS_HUGE_MARKER"
    else
      printf 'unexpected host' >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '200\n\n%s\n' 'text/html'
}

_new_run xshuge
SCOURSH_HTTP_TRANSPORT=_xs_huge_oracle_transport
_XS_ORACLE_DONE=0 _XS_ORACLE_OK=0 _XS_ORACLE_SIG='' _XS_ORACLE_REASON=''
_XS_ORACLE_MIN_BYTES=32
_XS_ORACLE_SIG_LEN=96
_XS_SENTINEL_URL="https://$XS_SENTINEL_HOST/"
xshuge_rc=0
_xs_oracle_fetch xs-fixture || xshuge_rc=$?
xshuge_finished=1
bounded_read_producer_finished "$XS_HUGE_MARKER" || xshuge_finished=0
bounded_read_reap
SCOURSH_HTTP_TRANSPORT=_xs_transport

assert_eq 0 "$xshuge_rc" 'the oracle fetch itself succeeds for a large-but-reachable sentinel response'
assert_eq 1 "$_XS_ORACLE_OK" 'and reports itself usable'
assert_eq 0 "$xshuge_finished" \
  "the producer serving the 256 MiB sentinel response was still parked mid-write when the oracle fetch returned, so the body was never read whole - FAILS under the un-bounded \`read -d ''\` this replaces, which drains the pipe to EOF before the signature can be sliced out of it. This used to be a 1220ms-on-CI wall-clock ceiling calibrated on one machine; see tests/lib/bounded-read.sh"

# ===========================================================================
printf '== dast xxe_ssrf: the XML-technique _XS_BODY read is bounded AT READ TIME, never after a full slurp ==\n'
# ===========================================================================
# `_xs_send_xml`'s own read used to slurp the whole captured body and only
# THEN trim it to `_INJ_MAX_BODY_BYTES` - the same pre-fix shape
# discovery.sh's ticket closed there. Driven directly against `_xs_send_xml`
# (TARGET EPID XML), the function this suite's own DAST-INJ-XXE_ENTITY-01 and
# DAST-INJ-XXE_SSRF-01 cases exercise only through the full phase.
declare -gA _INJ_EP_METHOD=([xshugeep]=POST) _INJ_EP_URL=([xshugeep]="https://$XS_BASE_HOST/probe") _INJ_EP_PATH=([xshugeep]='')
_INJ_N=0

_xs_huge_body_transport() {
  local method=$1 host=$3 path=$5
  printf '%s %s\n' "$method" "$host" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $host == "$XS_BASE_HOST" ]]; then
      bounded_read_serve_fifo "$_HTTP_TX_BODY_OUT" "$XS_HUGEFILE" "$XS_HUGE_MARKER"
    else
      printf 'unexpected host' >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '200\n\n%s\n' 'text/html'
}

SCOURSH_HTTP_TRANSPORT=_xs_huge_body_transport
xsbody_rc=0
_xs_send_xml xs-fixture xshugeep '<x/>' || xsbody_rc=$?
xsbody_finished=1
bounded_read_producer_finished "$XS_HUGE_MARKER" || xsbody_finished=0
bounded_read_reap
SCOURSH_HTTP_TRANSPORT=_xs_transport

assert_eq 0 "$xsbody_rc" '_xs_send_xml itself succeeds for a large-but-reachable body'
assert_eq "$_INJ_MAX_BODY_BYTES" "${#_XS_BODY}" \
  "a 256 MiB response leaves _XS_BODY holding exactly the ${_INJ_MAX_BODY_BYTES}-byte cap - FAILS if the cap is applied to what is RETAINED after a full read rather than to what is READ"
assert_eq 0 "$xsbody_finished" \
  "the producer serving the 256 MiB body was still parked mid-write when _xs_send_xml returned, so the body was never read whole - FAILS under the un-bounded \`read -d ''\` this replaces. This used to be a 1215ms-on-CI wall-clock ceiling calibrated on one machine; see tests/lib/bounded-read.sh"

t_summary dast-xxe-ssrf
