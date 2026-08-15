#!/usr/bin/env bash
# tests/e2e/dast-crawl-target.sh - modules/dast/crawl.sh (DAST-04) against the
# REAL local DAST test target: the pinned OWASP Juice Shop container
# tools/dast-test-target.sh manages, authorized by
# tools/dast-test-target/scope.conf and docs/DAST-TEST-TARGET-AUTHORIZATION.md.
#
# NOT part of tests/run-tests.sh's default suite list, for the same reason
# tests/e2e/dast-target-smoke.sh is not: it needs Docker and a real network to
# pull an image.  tests/suites/dast-crawl.sh is the deterministic, no-network
# proof of the same behaviours against a stubbed transport; this file is the
# separate question of whether any of that survives contact with a real
# server.  Run it by hand:
#
#     bash tests/e2e/dast-crawl-target.sh
#
# WHY THIS TARGET IS THE RIGHT ONE, AND WHY A THIN RESULT IS THE PASS
# CONDITION.  Juice Shop is an Angular application: its routes are built by
# JavaScript at runtime and its API is reached by XHR, so a static crawler can
# see almost none of it.  That makes it an honest test of BOTH halves of this
# ticket - the crawler, and the client-rendered coverage gap the crawler is
# required to declare rather than paper over.  This file therefore asserts a
# SMALL discovered surface and asserts that the run SAID SO; a change that made
# the numbers below larger by guessing at routes would be the failure
# docs/DESIGN.md §15 names, not an improvement.  The counts are printed rather
# than pinned to an exact number, because they are a property of the pinned
# image's index document, not of this repository.
#
# THE SCOPE-GATE PROOF HERE IS NOT A FIXTURE.  Juice Shop's own root document
# links to two genuinely third-party hosts (a font CDN).  So the live question
# "does a real page's off-target link produce a request to it" has a real
# answer available, and section C below reads it off a REQUEST LOG rather than
# off a return value.  The log is produced by a transport wrapper that logs and
# then DELEGATES to lib/http.sh's own default transport, so every request in
# this file is a real one; the wrapper observes the traffic, it does not
# replace it.  Section C also asserts that the root page really does still
# carry those links, because an assertion that "the off-target host was never
# requested" is vacuous the day the target stops linking to one.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes URL, flag and JSON syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"

require_cmd docker

W=$SCOURSH_SCRATCH/dast-crawl-target
mkdir -p "$W"

# A foreign host used ONLY inside a specification fixture this file generates,
# to prove the spec's own host is never adopted as a scan target.  It is an RFC
# 2606 reserved example domain, so it is not a real endpoint and cannot become
# one - the same rule tests/lint-shell.sh's DAST-35 checks enforce for shipped
# base-url records.
FOREIGN_HOST=api.example.com

# ---------------------------------------------------------------------------
printf -- '-- the target starts and serves --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-target.sh start exits 0'
if bash "$ROOT/tools/dast-test-target.sh" start >"$W/start.out" 2>&1; then
  _t_ok 'target start succeeded'
else
  cat "$W/start.out" >&2
  _t_no 'target start succeeded' 'see stderr above'
fi

# A fixture install root: the real tree's code, and the AUTHORIZED scope file
# as its config/scope.conf.  The repository deliberately ships no
# config/scope.conf at all (DAST-35), so a run has to be given one, and the one
# it is given here is the only file in this tree authorized to name a live host.
FIX=$W/root
mkdir -p "$FIX/config"
for e in lib modules rules data tools VERSION scan.sh; do
  [[ -e $ROOT/$e ]] && ln -sfn "$ROOT/$e" "$FIX/$e"
done
cp "$ROOT/tools/dast-test-target/scope.conf" "$FIX/config/scope.conf"

# The observing transport.  It logs `METHOD HOST PATH` and then calls
# lib/http.sh's own `_http_transport_default` with the identical arguments, so
# what is measured is the real request path and the log is a faithful record of
# every request the crawler actually caused.
cat >"$W/transport" <<TEOF
#!/usr/bin/env bash
set -Eeuo pipefail
source "$ROOT/lib/http.sh"
printf '%s %s %s\n' "\$1" "\$3" "\$5" >>"\$CRAWL_REQ_LOG"
_http_transport_default "\$@"
TEOF
chmod 0755 "$W/transport"

REQLOG=$W/requests.log

# `_crawl_run RUNDIR [ARGS...]` - one real `scan.sh dast` subprocess against the
# live target, with the observing transport bound.  Sets _RC.
_crawl_run() {
  local rundir=$1
  shift
  : >"$REQLOG"
  _RC=0
  SCOURSH_INSTALL_ROOT=$FIX \
    SCOURSH_HTTP_TRANSPORT=$W/transport \
    CRAWL_REQ_LOG=$REQLOG \
    bash "$ROOT/scan.sh" dast \
      --target dast-test-target --i-own-target dast-test-target \
      --out "$rundir" "$@" >"$rundir.log" 2>&1 || _RC=$?
  return 0
}

# ---------------------------------------------------------------------------
printf -- '\n-- A. an unauthenticated crawl of the real target --\n'
# ---------------------------------------------------------------------------
t_case 'a real scan.sh dast run against the live target'
_crawl_run "$W/run-nospec"
if (( _RC != 0 )); then tail -40 "$W/run-nospec.log" >&2; fi
assert_eq 0 "$_RC" 'the run exits 0 against a live target'
assert_file_exists "$W/run-nospec/inventory/endpoints.json" 'endpoints.json was written'
assert_file_exists "$W/run-nospec/inventory/parameters.json" 'parameters.json was written'

EP=$(cat "$W/run-nospec/inventory/endpoints.json")
PAR=$(cat "$W/run-nospec/inventory/parameters.json")
N_EP=$(grep -c '"source":' <<<"$EP" || true)
N_REQ=$(wc -l <"$REQLOG" | tr -d ' ')

printf -- '\n   WHAT THE CRAWL ACTUALLY DISCOVERED (reported, not asserted):\n'
printf -- '     endpoints: %s   requests issued: %s\n' "$N_EP" "$N_REQ"
grep -oE '"path": "[^"]*"' <<<"$EP" | sed 's/^/     /' || true
printf -- '\n'

t_case 'the discovered surface is small, and that is the correct result'
_rc=0; (( N_EP > 0 )) || _rc=1
assert_true "$_rc" \
  'the crawl found at least the root - FAILS if the crawl reached nothing at all, which would make every other case here vacuous'
_rc=0; (( N_EP < 60 )) || _rc=1
assert_true "$_rc" \
  'the crawl found a SMALL surface on an application with far more routes than this - this is the client-rendered gap being real, and a later change that inflates this number by guessing routes is the overstated coverage docs/DESIGN.md §15 forbids'

# ---------------------------------------------------------------------------
printf -- '\n-- B. the client-rendered gap reaches run.json and the report --\n'
# ---------------------------------------------------------------------------
RUNJSON=$(cat "$W/run-nospec/run.json")
t_case 'run.json carries the gap for this real SPA'
assert_contains "$RUNJSON" 'no_specification_supplied' \
  'the machine-readable reason is in run.json - FAILS under "docs/DESIGN.md §7.5 states the limitation", which docs/STEP5-DAST-PLAN.md rejects as sufficient for this ticket'
assert_contains "$RUNJSON" 'client-rendered' \
  'and the sentence a human reads names the limitation'

t_case 'the run RECOGNISED the target as client-rendered, rather than only warning generically'
assert_contains "$RUNJSON" 'spa_shaped=1' \
  'spa_shaped=1 was measured off this real Angular application - FAILS if the shape probe never fires on a real SPA, which would leave the strong wording unearned'

t_case 'the markdown report states it where a human reads'
MD=$(cat "$W/run-nospec/report.md")
assert_contains "$MD" 'client-rendered' \
  'report.md names the limitation - FAILS under "run.json is the audit surface", which leaves the report reader believing the endpoint list is the application'

t_case 'the HTML report carries it, and still contains no script tag at all'
HTML=$(cat "$W/run-nospec/report.html")
assert_contains "$HTML" 'client-rendered' 'report.html names the limitation'
assert_not_contains "$HTML" '<script' \
  'the HTML report contains no script tag, with target-derived text in it (docs/FOUNDATION.md tension 10)'

# ---------------------------------------------------------------------------
printf -- '\n-- C. the scope gate holds during a real crawl --\n'
# ---------------------------------------------------------------------------
# This is the live counterpart of tests/suites/dast-crawl.sh's stubbed case,
# and its evidence is the REQUEST LOG the observing transport wrote.
t_case 'the real root document really does carry an off-target link'
http_scope_load "$FIX/config/scope.conf"
BODY=$W/root-body.txt
http_request GET "$DTT_URL/" 5 dast-test-target "$BODY" >/dev/null 2>&1 || true
ROOTDOC=$(cat "$BODY" 2>/dev/null || printf '')
assert_contains "$ROOTDOC" 'fonts.googleapis.com' \
  'the target page links to a third-party host - this guards the next case from going vacuous the day the target stops linking to one'

t_case 'no request was ever issued to that off-target host'
LOG=$(cat "$REQLOG")
assert_not_contains "$LOG" 'fonts.googleapis.com' \
  'the off-target host appears nowhere in the log of requests the transport was ASKED to make - FAILS if a discovered link is handed to http_request without a pre-check, and it is asserted on the request log rather than on a return value'
assert_not_contains "$LOG" 'fonts.gstatic.com' \
  'nor the second one'

t_case 'and every request went to the authorised host only'
OFF_HOSTS=$(awk '{print $2}' "$REQLOG" | sort -u | grep -v '^127\.0\.0\.1$' || true)
assert_eq '' "$OFF_HOSTS" \
  'the set of hosts requested during the crawl minus the authorised one is empty'

t_case 'and no off-target host reached the inventory either'
assert_not_contains "$EP" 'fonts.googleapis.com' 'endpoints.json holds no third-party host'
assert_not_contains "$PAR" 'fonts.googleapis.com' 'parameters.json holds no third-party host'

# ---------------------------------------------------------------------------
printf -- '\n-- D. a specification closes the gap, without moving the target --\n'
# ---------------------------------------------------------------------------
# The spec is GENERATED here rather than committed: its paths are specific to
# this one test target, and docs/DESIGN.md §1 keeps target-specific values out
# of shipped files.  Its `servers[].url` deliberately names a FOREIGN host, so
# the run has an opportunity to follow a config file off-target and must not
# take it.
cat >"$W/openapi.json" <<EOF
{
  "openapi": "3.0.0",
  "info": {"title": "test target api", "version": "1"},
  "servers": [{"url": "https://$FOREIGN_HOST"}],
  "paths": {
    "/rest/admin/application-version": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/rest/products/search": {
      "get": {
        "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/api/Feedbacks": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}
EOF
cat >"$FIX/config/discovery.conf" <<EOF
id: dast-test-target
openapi-path: $W/openapi.json
crawl-depth: 2
EOF

t_case 'a run with a specification supplied'
_crawl_run "$W/run-spec"
if (( _RC != 0 )); then tail -40 "$W/run-spec.log" >&2; fi
assert_eq 0 "$_RC" 'the run exits 0'
EP2=$(cat "$W/run-spec/inventory/endpoints.json")
PAR2=$(cat "$W/run-spec/inventory/parameters.json")
RUNJSON2=$(cat "$W/run-spec/run.json")

t_case 'the specification contributed endpoints a crawler could never reach'
assert_contains "$EP2" '/rest/products/search' \
  'a path no page links to is in the inventory - this is docs/DESIGN.md §7.5 calling a spec the preferred input, made concrete'
assert_contains "$EP2" '/api/Feedbacks' 'and another'
assert_contains "$PAR2" '"q"' 'and the spec-declared query parameter is in parameters.json'

t_case "the specification's own host was NEVER adopted as a target"
assert_not_contains "$EP2" "$FOREIGN_HOST" \
  "the spec's servers[].url host appears nowhere in the inventory - FAILS under \"the spec knows where the API is, use it\", which turns a config file into a way past the scope gate"
assert_not_contains "$(cat "$REQLOG")" "$FOREIGN_HOST" \
  'and no request was issued to it'
assert_contains "$EP2" 'http://127.0.0.1:3400/rest/products/search' \
  "the spec's PATH was taken and joined to the operator's own --target instead"

t_case 'the client-rendered gap is now ABSENT, because a spec closed it'
assert_not_contains "$RUNJSON2" 'no_specification_supplied' \
  'the gap is not recorded when a spec was supplied - FAILS if the gap is printed unconditionally, in which case section B asserting its presence proves nothing at all'

N_EP2=$(grep -c '"source":' <<<"$EP2" || true)
printf -- '\n   WITH A SPEC: %s endpoints (vs %s without)\n\n' "$N_EP2" "$N_EP"
t_case 'and the surface is larger than the crawl alone found'
_rc=0; (( N_EP2 > N_EP )) || _rc=1
assert_true "$_rc" \
  'a spec strictly adds surface - FAILS if spec ingestion overwrites the crawl rather than merging with it'

t_summary dast-crawl-target
