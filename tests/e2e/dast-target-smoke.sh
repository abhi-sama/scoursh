#!/usr/bin/env bash
# tests/e2e/dast-target-smoke.sh - end-to-end smoke test for Crewban-22's
# local DAST test target: proves the target is reachable, that lib/http.sh's
# scope gate (docs/FOUNDATION.md tension 19) really allows exactly the
# authorized host and refuses everything else, and that the two test
# identities tools/dast-test-identities.sh provisions are distinct and have
# a real cross-user broken-access-control case to bite on.
#
# NOT part of tests/run-tests.sh's default suite list: it needs Docker and
# real network access to pull an image, which an air-gapped CI/test host
# will not have (docs/DESIGN.md §1's no-egress rule is about scoursh's own
# runtime, not this kind of one-time operator/dev tooling - see
# tools/dast-test-target.sh's own header). Run it by hand:
#
#   bash tests/e2e/dast-target-smoke.sh
#
# WHAT THIS DOES NOT DO: "run the DAST module" - modules/dast/ does not
# exist yet (docs/STEP5-DAST-PLAN.md: blocked on §13 steps 3/4). What it
# runs instead is lib/http.sh's http_request/http_gate_url directly - the
# actual chokepoint any future DAST module is required to route every
# request through - against the real target, which is the closest honest
# proxy available today for "the DAST layer can reach this target through
# the gate and nothing else."
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"
# shellcheck source=tools/dast-test-target/http.sh
source "$ROOT/tools/dast-test-target/http.sh"

require_cmd docker

SCOPE_FILE=$ROOT/tools/dast-test-target/scope.conf
UNAUTHORIZED_URL="http://127.0.0.1:$(( DTT_PORT + 1 ))/"

# ---------------------------------------------------------------------------
printf -- '-- the target starts and serves --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-target.sh start exits 0'
if bash "$ROOT/tools/dast-test-target.sh" start >"$SCOURSH_SCRATCH/dtt-start.out" 2>&1; then
  _t_ok 'target start succeeded'
else
  cat "$SCOURSH_SCRATCH/dtt-start.out" >&2
  _t_no 'target start succeeded' "see stderr above"
fi

t_case 'the container answers a direct request'
VERSION_OUT=$(dtt_call GET /rest/admin/application-version)
VERSION_STATUS=${VERSION_OUT%%$'\n'*}
assert_eq 200 "$VERSION_STATUS" "GET /rest/admin/application-version returns 200"

# ---------------------------------------------------------------------------
printf -- '\n-- the scope gate allows exactly the authorized target --\n'
# ---------------------------------------------------------------------------
http_scope_load "$SCOPE_FILE"

t_case 'the gate allows the authorized target'
if http_gate_url "$DTT_URL" dast-test-target; then
  _t_ok "http_gate_url allows $DTT_URL"
else
  _t_no "http_gate_url allows $DTT_URL" "reason: ${_HTTP_GATE_REASON:-unknown}"
fi

t_case 'the gate still refuses everything else'
if http_gate_url "$UNAUTHORIZED_URL" dast-test-target; then
  _t_no "http_gate_url refuses $UNAUTHORIZED_URL" 'the gate allowed an unauthorized port'
else
  _t_ok "http_gate_url refuses $UNAUTHORIZED_URL"
fi
assert_contains "${_HTTP_GATE_REASON:-}" 'no entry in config/scope.conf' \
  'the refusal reason names the real cause (no scope.conf entry), not an accident'

t_case 'the gate refuses an entirely unrelated host the same way'
if http_gate_url 'http://example.invalid/' dast-test-target; then
  _t_no 'http_gate_url refuses example.invalid' 'the gate allowed an arbitrary internet host'
else
  _t_ok 'http_gate_url refuses example.invalid'
fi

# ---------------------------------------------------------------------------
printf -- '\n-- http_request: the real chokepoint reaches the authorized target and only it --\n'
# ---------------------------------------------------------------------------
t_case 'http_request succeeds against the authorized target'
assert_status 0 'http_request GET against the authorized target exits 0' bash -c "
  source '$ROOT/lib/http.sh'
  http_scope_load '$SCOPE_FILE'
  http_request GET '${DTT_URL}/rest/admin/application-version' 0 dast-test-target
"

t_case 'http_request refuses (exit 3, SCOURSH_EXIT_SCOPE) an unauthorized host'
assert_status 3 'http_request against an unauthorized host exits 3' bash -c "
  source '$ROOT/lib/http.sh'
  http_scope_load '$SCOPE_FILE'
  http_request GET '$UNAUTHORIZED_URL' 0 dast-test-target
"

# ---------------------------------------------------------------------------
printf -- '\n-- the two identities are distinct and have a cross-user case to bite on --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-identities.sh provisions two identities'
IDENTITIES_OUT=$(bash "$ROOT/tools/dast-test-identities.sh")
EMAIL_A=$(awk '$1=="a"{print $2}' <<<"$IDENTITIES_OUT")
SECRET_A=$(awk '$1=="a"{print $3}' <<<"$IDENTITIES_OUT")
EMAIL_B=$(awk '$1=="b"{print $2}' <<<"$IDENTITIES_OUT")
SECRET_B=$(awk '$1=="b"{print $3}' <<<"$IDENTITIES_OUT")
if [[ -n $EMAIL_A && -n $SECRET_A && -n $EMAIL_B && -n $SECRET_B ]]; then
  _t_ok 'both identities report an email and a secret-file path'
else
  _t_no 'both identities report an email and a secret-file path' "got: [$IDENTITIES_OUT]"
fi

t_case 'the two identities are actually distinct'
assert_ne "$EMAIL_A" "$EMAIL_B" 'identity A and B have different emails'
assert_ne "$SECRET_A" "$SECRET_B" 'identity A and B have different secret-files'

t_case 'each secret-file is a 600-permission file, per rules/RULE-FORMAT.md §9.6.2'
assert_eq '600' "$(stat_mode "$SECRET_A")" "identity A's secret-file is mode 600"
assert_eq '600' "$(stat_mode "$SECRET_B")" "identity B's secret-file is mode 600"

# `read` returns non-zero at EOF even when it successfully read the (final,
# newline-less) line - lib/core.sh's own scratch_is_owned_here hits the same
# thing reading its .owner marker, hence the same `|| true` there.
IFS= read -r PASSWORD_A <"$SECRET_A" || true
IFS= read -r PASSWORD_B <"$SECRET_B" || true

t_case 'both identities can log in, each getting a distinct session'
LOGIN_A=$(dtt_login "$EMAIL_A" "$PASSWORD_A")
LOGIN_B=$(dtt_login "$EMAIL_B" "$PASSWORD_B")
TOKEN_A=${LOGIN_A%% *}
BID_A=${LOGIN_A##* }
TOKEN_B=${LOGIN_B%% *}
BID_B=${LOGIN_B##* }
assert_ne "$TOKEN_A" "$TOKEN_B" 'identity A and B get different session tokens'
assert_ne "$BID_A" "$BID_B" "identity A and B own different baskets ($BID_A vs $BID_B)"

t_case "the cross-user access attempt has something to bite on: A's token reads B's basket"
CROSS_OUT=$(dtt_call GET "/rest/basket/$BID_B" "$TOKEN_A")
CROSS_STATUS=${CROSS_OUT%%$'\n'*}
CROSS_BODY=${CROSS_OUT#*$'\n'}
assert_eq 200 "$CROSS_STATUS" "identity A's token reading identity B's basket ($BID_B) returns 200, not 401/403"
assert_contains "$CROSS_BODY" "\"id\":$BID_B" \
  "the response really is B's basket ($BID_B), not an empty/generic body - this is the broken-access-control case DAST-29 (authz.sh) will assert against once it exists"

t_case 'the same broken-access-control case holds in the other direction'
CROSS_OUT_2=$(dtt_call GET "/rest/basket/$BID_A" "$TOKEN_B")
CROSS_STATUS_2=${CROSS_OUT_2%%$'\n'*}
assert_eq 200 "$CROSS_STATUS_2" "identity B's token reading identity A's basket ($BID_A) also returns 200"

# ---------------------------------------------------------------------------
printf -- '\n-- the target stops cleanly --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-target.sh --stop leaves nothing running'
bash "$ROOT/tools/dast-test-target.sh" --stop >/dev/null
REMAINING=$(docker ps -a --filter "name=^/${DTT_CONTAINER}\$" --format '{{.Names}}')
assert_eq '' "$REMAINING" 'no container named scoursh-dast-test-target remains after --stop'

t_summary 'dast-target-smoke'
