#!/usr/bin/env bash
# tests/suites/dast-scope-precheck.sh - the shared in-scope pre-check every DAST
# inventory consumer applies before `http_request`
# (modules/dast/engine.sh section 3b; docs/FOUNDATION.md tensions 19 and 21).
#
# THE DEFECT THIS PINS, IN ONE SENTENCE. `http_request` gates the URL it is
# handed FATALLY - `die "$SCOURSH_EXIT_SCOPE"`, exit 3, aborting the whole run -
# because a caller is assumed to have reached it with a URL it believes is
# authorised. That assumption holds for an operator-configured `base-url` and
# does NOT hold for a URL lifted out of `reports/<run>/inventory/endpoints.json`,
# which tension 21 makes a cross-module artifact that `crawl.sh`, SAST route
# extraction and `modules/cloud/aws/live/apigw.sh` may each write and that an
# operator may supply by hand. Before this ticket, a single out-of-scope row in
# that file turned an ordinary `scan.sh dast` run into an exit-3 abort rather
# than a skipped endpoint plus a recorded reason.
#
# NOTHING HERE TOUCHES THE NETWORK. Both `SCOURSH_HTTP_RESOLVE` and
# `SCOURSH_HTTP_TRANSPORT` are stubbed, exactly as tests/suites/dast-methods.sh
# and tests/suites/dast-cookies.sh stub them; the suite runs on a host with no
# network and no Docker via `tests/run-tests.sh dast-scope-precheck`.
#
# EVERY CLAIM ABOUT WHAT WAS OR WAS NOT SENT IS ASSERTED ON THE REQUEST LOG,
# never on a return value. "It refused" must not be satisfiable by a phase that
# sent the request and then returned non-zero - which is the shape a first draft
# of a check like this reaches for.
#
# The readings each case is written to FAIL under, per this repository's testing
# rule that a test passing under both the correct and the rejected reading pins
# nothing:
#
#   1. NO PRE-CHECK AT ALL (the pre-fix code). Section C runs the phase in a
#      real subprocess with the pre-check neutralised and asserts the process
#      dies with exit 3 having sent NOTHING to the unauthorised host - the
#      failure this ticket exists to remove, reproduced rather than described.
#      If that section ever reports 0 alongside section B, the pre-check has
#      stopped being load-bearing.
#   2. THE PRE-CHECK REPLACING THE GATE. Section D asserts `http_request` STILL
#      dies on an out-of-scope URL handed to it directly. Deleting that half is
#      the other failure mode AGENTS.md documents: the pre-check decides only
#      whether a URL is worth asking for, and nothing else re-checks a redirect
#      the target chose.
#   3. A SILENT DROP. Section B asserts the `coverage_reduction` is recorded and
#      carries the row COUNT. A phase that quietly drops out-of-scope rows
#      reports "tested and clean" for endpoints it never asked about, which is
#      the overstated coverage docs/DESIGN.md §15 forbids and is invisible from
#      a request-count assertion alone.
#   4. A FAIL-CLOSED `declare -F` FALLBACK. Section A asserts that with no
#      `http_gate_url` in the process the pre-check ALLOWS. Inverting it makes
#      every direct-engine suite in tests/suites/ inert while every "stays
#      quiet" assertion in them still passes green - the worst available
#      failure, because it reads as coverage.
#   5. THE REASON READ AFTER THE LOOP. Section A asserts the recorded reason
#      names the out-of-scope host after a LATER successful gate call.
#      `http_gate_url` clears `_HTTP_GATE_REASON` at entry on every call, so a
#      roll-up reading it afterwards degrades to a generic fallback on exactly
#      the ordinary case where the last row was fine.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell and URL syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# SC2034: SCOURSH_HTTP_RESOLVE and SCOURSH_HTTP_TRANSPORT are lib/http.sh's own
#   documented swappable seams, read there and nowhere here. They read as unused
#   BECAUSE of the `-x` back-edge cuts below - which is the trap AGENTS.md
#   records for cutting an edge (`tests/suites/core.sh` minted a fresh SC2034
#   the same way). The cuts are kept and the finding silenced with this reason
#   rather than the reverse: with the edges followed, `shellcheck -x` on this
#   one file measured 34 GB resident and had not finished after 11 minutes -
#   above the stage's per-process budget at the time (20 GB; since raised to
#   50 GB, see docs/CI-RUNBOOK.md's "memory model") and would have been
#   killed as a false failure. Cutting the edge is still the right call
#   regardless of where the budget sits: it eliminates real duplicate
#   inlining rather than merely tolerating a bigger ceiling. With them cut
#   it is 7.4 s and 2.2 GB, measured on the same host.
# shellcheck disable=SC2016,SC2030,SC2031,SC2034

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/dast/active/inject_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-scope-precheck-workspace
rm -rf "$W"; mkdir -p "$W"

# ===========================================================================
printf '== A. the shared helper, modules/dast/engine.sh section 3b ==\n'
# ===========================================================================

SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOS'
id: scope-fixture
base-url: https://inscope.fixture.example/
notes: Fixture target for tests/suites/dast-scope-precheck.sh. Never dialled -
  both the resolver and the transport are stubbed.
EOS
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
cat >"$W/scanner.conf" <<'EOS'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOS
config_scanner_load "$W/scanner.conf"

_sp_resolve() {
  case $1 in
    inscope.fixture.example) printf '93.184.216.34' ;;
    elsewhere.fixture.example) printf '93.184.216.35' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_sp_resolve

IN_URL=https://inscope.fixture.example/api/orders
OUT_URL=https://elsewhere.fixture.example/api/orders

t_case 'the predicate: an in-scope URL is kept, an out-of-scope one is not'
if dast_endpoint_in_scope "$IN_URL" scope-fixture; then
  _t_ok 'the authorised URL passes the pre-check'
else
  _t_no 'the authorised URL passes the pre-check' "reason: ${_DAST_SCOPE_REASON:-}"
fi
if dast_endpoint_in_scope "$OUT_URL" scope-fixture; then
  _t_no 'a URL on a host with no config/scope.conf entry is refused' \
    'the pre-check allowed an unauthorised host, so it is not a pre-check at all'
else
  _t_ok 'a URL on a host with no config/scope.conf entry is refused'
fi
assert_contains "${_DAST_SCOPE_REASON:-}" 'elsewhere.fixture.example' \
  'the refusal carries the scope gate OWN reason, naming the host - FAILS under discarding _HTTP_GATE_REASON and substituting a generic sentence, which leaves an operator unable to tell an unauthorised host from a DNS failure from a malformed row'

t_case 'the predicate is NON-fatal: the caller keeps running after a refusal'
# The whole point. `http_request` would have ended the process here.
dast_endpoint_in_scope "$OUT_URL" scope-fixture || true
_t_ok 'a refusal returned to the caller instead of ending the process'

# --- reading 4: the permissive absent-gate fallback ------------------------
t_case 'with no http_gate_url reachable the pre-check ALLOWS'
# Asserted in a subprocess that never sources lib/http.sh, because that is the
# real shape of the situation - every direct-engine suite in tests/suites/
# sources a phase script with no transport in the process.
NOGATE=$W/nogate.sh
cat >"$NOGATE" <<'EOG'
set -Eeuo pipefail
ROOT=$1
source "$ROOT/modules/dast/engine.sh"
if declare -F http_gate_url >/dev/null; then
  printf 'PRECONDITION-FAILED lib/http.sh was loaded after all\n'
  exit 2
fi
if dast_endpoint_in_scope 'https://anything.example/x' some-target; then
  printf 'ALLOWED\n'
else
  printf 'REFUSED\n'
fi
EOG
NOGATE_OUT=$(bash "$NOGATE" "$ROOT" 2>&1 || true)
assert_eq 'ALLOWED' "$NOGATE_OUT" \
  'the pre-check is permissive when no scope gate is loaded - FAILS under a fail-CLOSED default (and under an UNGUARDED call, which is `command not found`, exit 127, hence "refused"), either of which makes every direct-engine suite inert while every "stays quiet" assertion in them still passes green. Nothing is made unsafe by it: with no lib/http.sh there is no http_request either, so nothing can send the URL it just waved through.'

# --- reading 5: the reason is captured at refusal time ----------------------
t_case 'a later SUCCESSFUL gate call does not erase the recorded reason'
dast_scope_skips_reset
dast_endpoint_keep "$OUT_URL" scope-fixture || true
dast_endpoint_keep "$IN_URL" scope-fixture || true     # succeeds, clears _HTTP_GATE_REASON
assert_eq 1 "$_DAST_SCOPE_SKIPPED" 'exactly one row was dropped'
assert_contains "$_DAST_SCOPE_REASONS" 'elsewhere.fixture.example' \
  'the accumulated reason still names the refused host after a later success - FAILS under reading _HTTP_GATE_REASON once at the END of the loop, which http_gate_url clears at ENTRY on every call, so the ordinary case (the last row was fine) reports the generic fallback and the operator never learns why the row was declined'

t_case 'two refusals on the same host are ONE reason, not two'
dast_scope_skips_reset
dast_endpoint_keep "$OUT_URL" scope-fixture || true
dast_endpoint_keep 'https://elsewhere.fixture.example/other' scope-fixture || true
assert_eq 2 "$_DAST_SCOPE_SKIPPED" 'both rows are counted'
NREASONS=$(printf '%s' "$_DAST_SCOPE_REASONS" | tr ';' '\n' | grep -c . || true)
assert_eq 1 "$NREASONS" \
  'the distinct reasons are deduped - FAILS under appending unconditionally, which repeats one sentence once per row and makes a wide inventory unreadable'

t_case 'the accumulator is reset per phase, never inherited'
dast_scope_skips_reset
assert_eq 0 "$_DAST_SCOPE_SKIPPED" 'a reset zeroes the count'
assert_eq '' "$_DAST_SCOPE_REASONS" 'and clears the reasons'

t_case 'an untrusted gate reason cannot forge a second run.json record'
# The reason interpolates a host lifted out of an artifact this scanner did not
# author, and it is written into a run fact, one record per line.
SAFE=$(dast_scope_safe_text "one"$'\n'"two"$'\t'"three")
assert_not_contains "$SAFE" $'\n' \
  'a newline in the reason is flattened - FAILS under interpolating it raw, which lets a hand-written inventory row split one coverage_reduction into two records'
assert_not_contains "$SAFE" $'\t' 'and a tab, which is the shard field separator'
assert_contains "$SAFE" 'one two three' 'and the text itself survives'

# ===========================================================================
printf '== B. end to end: one in-scope row, one out-of-scope row ==\n'
# ===========================================================================
# `active/methods.sh` is the consumer driven here because it is one of the two
# the ticket names, and because it reaches the inventory through
# `inject_inventory_load` - the single door a dozen phase scripts share, so a
# pass here is a pass for every probe behind it.

REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

# The transport contract is `METHOD SCHEME HOST PORT PATH ADDR [BODYOUT]
# [HDRSOUT]` (lib/http.sh's own `_http_transport_default`), so the URL is
# recomposed here rather than read off argument 2 - which is the SCHEME, and a
# log built from it would make every assertion below vacuously true.
_sp_transport() {
  local method=$1 scheme=$2 host=$3 port=$4 path=$5
  printf '%s %s://%s%s\n' "$method" "$scheme" "$host" "$path" >>"$REQ_LOG"
  local status=405 ctype='text/plain' hdr=''
  case "$method$path" in
    OPTIONS/api/orders) status=200; hdr='Allow: GET, HEAD, OPTIONS\r\n' ;;
    *) status=405 ;;
  esac
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    { printf 'HTTP/1.1 %s X\r\n' "$status"
      printf 'Content-Type: %s\r\n' "$ctype"
      [[ -n $hdr ]] && printf '%b' "$hdr"
      printf '\r\n'
    } >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '%s\n%s\n%s\n' "$status" '' "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_sp_transport

MIXED_INV=$W/endpoints-mixed.json
cat >"$MIXED_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_in",  "target": "scope-fixture", "method": "GET", "url": "https://inscope.fixture.example/api/orders",   "path": "/api/orders" },
  { "id": "ep_out", "target": "scope-fixture", "method": "GET", "url": "https://elsewhere.fixture.example/api/orders", "path": "/api/orders" }
] }
EOS

_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target scope-fixture
  occurrence_reset_all
  _req_reset
  SCOURSH_DAST_TARGET=scope-fixture
  SCOURSH_DAST_CELL=scope-fixture
  SCOURSH_DAST_AUTHED=false
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
}

_new_run mixed
SCOURSH_DAST_METHOD_ENDPOINTS=$MIXED_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
rc=0
# -x back-edge cut: modules/dast/active/methods.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh" || rc=$?

t_case 'the phase completes rather than aborting the run'
assert_eq 0 "$rc" \
  'a mixed inventory leaves the phase with status 0 - FAILS under handing every inventory URL straight to http_request, which dies SCOURSH_EXIT_SCOPE (3) on the out-of-scope row and takes the whole scan with it'

t_case 'the out-of-scope URL is never requested'
LOG=$(cat "$REQ_LOG")
assert_not_contains "$LOG" 'elsewhere.fixture.example' \
  'no request was sent to the unauthorised host - asserted on the REQUEST LOG rather than on a return value, because "it refused" must not be satisfiable by a phase that sent the request and then returned non-zero'

t_case 'the in-scope URL beside it IS still requested'
assert_contains "$LOG" 'inscope.fixture.example/api/orders' \
  'the authorised endpoint was tested - FAILS under a pre-check that drops the whole inventory on the first bad row, which trades an abort for a silent no-op and is the same lost coverage in a quieter form'

t_case 'exactly one endpoint was requested'
# The phase may send OPTIONS and then TRACE to the same URL, so the count that
# discriminates is DISTINCT urls, not lines.
NURL=$(awk '{print $2}' "$REQ_LOG" | sort -u | grep -c . || true)
assert_eq 1 "$NURL" \
  'one distinct URL was dialled, not two - FAILS under a pre-check applied to only one of the two paths a URL reaches a request by'

t_case 'the dropped row is RECORDED, never silent'
RED=$(run_facts coverage_reduction)
assert_contains "$RED" 'reason=inventory_endpoint_out_of_scope' \
  'the run records why the row was not tested - FAILS under dropping out-of-scope rows quietly, which reports "tested and clean" for an endpoint that was never asked and is the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$RED" 'count=1' \
  'and it carries how many rows were dropped, so a reader can tell one bad row from an inventory that is entirely out of scope'
assert_contains "$RED" 'phase=methods' \
  'and names the phase that dropped them - FAILS under leaving every consumer on the shared default, which would attribute passive/cookies.sh dropped rows to a generic inject'
assert_contains "$RED" 'target=scope-fixture' 'and the coverage cell it happened in'
assert_contains "$RED" 'elsewhere.fixture.example' \
  'and the gate own reason, so the operator can act on it'

t_case 'a wholly in-scope inventory records NO such reduction'
# The other direction. Without this, "the reduction is present" is satisfied
# equally well by a phase that emits it unconditionally, which would make every
# clean run look partial.
CLEAN_INV=$W/endpoints-clean.json
cat >"$CLEAN_INV" <<'EOS'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_in", "target": "scope-fixture", "method": "GET", "url": "https://inscope.fixture.example/api/orders", "path": "/api/orders" }
] }
EOS
_new_run clean
SCOURSH_DAST_METHOD_ENDPOINTS=$CLEAN_INV
export SCOURSH_DAST_METHOD_ENDPOINTS
rc=0
# -x back-edge cut: modules/dast/active/methods.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/methods.sh" || rc=$?
assert_eq 0 "$rc" 'the clean run completes too'
assert_not_contains "$(run_facts coverage_reduction)" 'inventory_endpoint_out_of_scope' \
  'nothing is recorded when nothing was dropped - FAILS under emitting the reduction unconditionally, which makes every fully in-scope run report a coverage loss it did not have'
assert_contains "$(cat "$REQ_LOG")" 'inscope.fixture.example' 'and it still tested the endpoint'

# --- the other named consumer ----------------------------------------------
t_case 'passive/cookies.sh gets the same treatment, from the same shared door'
_new_run cookies
SCOURSH_DAST_COOKIE_ENDPOINTS=$MIXED_INV
export SCOURSH_DAST_COOKIE_ENDPOINTS
rc=0
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh" || rc=$?
assert_eq 0 "$rc" \
  'the cookie phase completes on a mixed inventory - FAILS on the pre-fix code, where it died exit 3 on the out-of-scope row'
assert_not_contains "$(cat "$REQ_LOG")" 'elsewhere.fixture.example' \
  'and never dialled the unauthorised host'
assert_contains "$(run_facts coverage_reduction)" 'phase=cookies' \
  'and recorded the drop under its own phase name'
unset SCOURSH_DAST_COOKIE_ENDPOINTS

# ===========================================================================
printf '== C. reading 1: the pre-fix code, reproduced ==\n'
# ===========================================================================
# THE MUTATION. The phase is run in a REAL SUBPROCESS with the pre-check
# neutralised - `dast_endpoint_keep` shadowed by a version that keeps
# everything, which is byte-for-byte the behaviour before this ticket - and the
# process is asserted to die with exit 3.
#
# A subprocess rather than an in-process call because the failure being
# reproduced is `die`, which ends the process: catching it in this shell is not
# possible, and pretending to would be testing something else.
MUT=$W/mutation.sh
cat >"$MUT" <<'EOM'
set -Eeuo pipefail
ROOT=$1 W=$2 INV=$3 SCOPE=$4 LOG=$5
source "$ROOT/modules/dast/active/inject_engine.sh"
source "$ROOT/modules/dast/engine.sh"
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
config_scanner_load "$W/scanner.conf"
_sp_resolve() {
  case $1 in
    inscope.fixture.example) printf '93.184.216.34' ;;
    elsewhere.fixture.example) printf '93.184.216.35' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_sp_resolve
_sp_transport() {
  printf '%s %s://%s%s\n' "$1" "$2" "$3" "$5" >>"$LOG"
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    printf 'HTTP/1.1 405 X\r\nContent-Type: text/plain\r\n\r\n' >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '405\n\ntext/plain\n'
}
SCOURSH_HTTP_TRANSPORT=_sp_transport
# THE MUTATION ITSELF: the pre-check keeps every row, which is what the code did
# before modules/dast/engine.sh section 3b existed.
dast_endpoint_keep() { return 0; }
run_init "$W/run.mutation"
run_record authorization_affirmed true
run_record authorization_target scope-fixture
SCOURSH_DAST_TARGET=scope-fixture
SCOURSH_DAST_CELL=scope-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_METHOD_ENDPOINTS=$INV
export SCOURSH_DAST_METHOD_ENDPOINTS
source "$ROOT/modules/dast/active/methods.sh"
EOM

MUT_LOG=$W/mutation-requests.log
: >"$MUT_LOG"
# `|| MUT_RC=$?` rather than `set +e` around a bare call: `set +e` is forbidden
# repository-wide (tests/lint-shell.sh, tension 4 rule 1), and under
# `set -Eeuo pipefail` a non-zero subprocess outside a condition aborts the
# WHOLE FILE - which would end this suite here having printed no failure, the
# "a skipped suite is never a pass" hazard tests/suites/dast-graphql.sh already
# measured.
MUT_RC=0
bash "$MUT" "$ROOT" "$W" "$MIXED_INV" "$SCOPE" "$MUT_LOG" >"$W/mutation.out" 2>&1 || MUT_RC=$?

t_case 'WITHOUT the pre-check the same inventory kills the whole run'
assert_eq 3 "$MUT_RC" \
  'the mutated phase exits SCOURSH_EXIT_SCOPE (3) - this is the defect the ticket exists to remove, reproduced rather than described. If this case ever reports 0 alongside section B, the pre-check has stopped being load-bearing and section B is passing for some other reason.'

t_case 'and it never even reached the unauthorised host'
assert_not_contains "$(cat "$MUT_LOG")" 'elsewhere.fixture.example' \
  'the gate inside http_request refuses BEFORE the transport, which is why the pre-fix failure is fail-CLOSED (safe, never a bypass) and still fatal - it kills the run over one row of a file the scanner did not author'

# ===========================================================================
printf '== D. reading 2: http_request STILL re-gates ==\n'
# ===========================================================================
# The pre-check is not the gate, and deleting the gate is the other failure
# mode. A URL that never went through the pre-check - a redirect the target
# chose, a future caller that forgets - must still be refused, fatally, by
# http_request itself.
GATE=$W/gate.sh
cat >"$GATE" <<'EOG'
set -Eeuo pipefail
ROOT=$1 W=$2 SCOPE=$3
source "$ROOT/lib/http.sh"
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
config_scanner_load "$W/scanner.conf"
_g_resolve() { printf '93.184.216.35'; }
SCOURSH_HTTP_RESOLVE=_g_resolve
_g_transport() { printf 'SENT\n' >&2; printf '200\n\ntext/plain\n'; }
SCOURSH_HTTP_TRANSPORT=_g_transport
run_init "$W/run.gate"
http_request GET 'https://elsewhere.fixture.example/api/orders' 0 scope-fixture
EOG
GATE_RC=0
bash "$GATE" "$ROOT" "$W" "$SCOPE" >"$W/gate.out" 2>&1 || GATE_RC=$?

t_case 'http_request itself still dies on an out-of-scope URL'
assert_eq 3 "$GATE_RC" \
  'the chokepoint gate is untouched by this ticket - FAILS if the pre-check were made the ONLY check, which would leave a redirect the target chose, and any future caller that forgets the pre-check, ungated'
assert_not_contains "$(cat "$W/gate.out")" 'SENT' \
  'and it refuses BEFORE the transport, so nothing left the machine'

t_summary dast-scope-precheck
