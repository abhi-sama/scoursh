#!/usr/bin/env bash
# tests/suites/dast-leakage.sh - modules/dast/passive/leakage.sh and
# modules/dast/passive/leakage_engine.sh: the §7.1 information-disclosure family
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-10, tier 2).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and the whole suite is driven
# from RECORDED RESPONSES - a table of head/body pairs this file writes,
# replayed into lib/http.sh's own capture sinks exactly as curl would write them
# (docs/DESIGN.md §12: "DAST logic is testable with no live target").  It runs on
# a host with no network and no Docker.
#
# THE SUITE'S CENTRAL JOB IS THE FIVE NEGATIVE FIXTURES, one per family, each of
# which a NAIVE over-broad implementation flags and this one does not.  Section
# C below is built so that the difference itself is the assertion: for every
# family it runs the naive reading inline, asserts that the naive reading DOES
# fire on the fixture, and then asserts the shipped implementation does not.  A
# test that only asserted "no finding" would pass equally well against a check
# that had been broken into silence, which pins nothing.  The five:
#
#   1. STACK TRACE       a framework-branded 404 page ("Error 404 ... Powered by
#                        Django 4.2 ... if you think this is an error").  Naive:
#                        the body mentions error/exception/a framework name.
#   2. PROXY HEADER      `Via: 1.1 varnish` and `X-Served-By: cache-lhr7364-LHR`
#                        - a proxy PRODUCT name and a public CDN edge POP code.
#                        Naive: the header name alone is the finding.
#   3. EMAIL             a published `mailto:` contact link, an `info@` role
#                        alias, and `logo@2x.png` in an `srcset`.  Naive: an
#                        `x@y.z` regex over the body.
#   4. JS CONFIG         a Stripe PUBLISHABLE key, a Google browser API key and
#                        a `UA-` analytics id - three values that are public by
#                        design.  Naive: a `key`-ish name with a string literal.
#   5. THIRD-PARTY       a relative `/static/app.js`, an absolute self-link, and
#                        the site's OWN cdn subdomain.  Naive: any absolute URL
#                        is a third party.
#
# The other readings pinned here, each by a case that fails under the reading it
# names:
#
#   6. a `mailto:` address published on ONE page is subtracted from a DIFFERENT
#      page's HTML comment - the subtraction is per-target, not per-line.
#   7. only the FINAL hop's headers count (the capture sink accumulates hops).
#   8. a minified single-line bundle is CHUNKED, not truncated at the line cap -
#      a naive line-cap read inspects 4 KiB of a 900 KiB bundle and calls the
#      rest clean.
#   9. a family no fetched response was applicable to is recorded as NOT
#      covered, and never reads as clean.
#  10. the third-party family is INFORMATIONAL severity, and stays so.
#  11. an out-of-scope inventory URL is skipped, never handed to `http_request`
#      (which would abort the whole run with exit 3).
#  12. the shell catalog and modules/dast/passive/checks-leakage.rules agree, field by
#      field, on every one of the five ids.
#  13. a candidate secret's VALUE never reaches the finding evidence.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header, URL and JS syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut: modules/dast/passive/leakage_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/leakage_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-leakage-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
# Two targets:
#   leak-fixture  the main surface.  Its `/` is DELIBERATELY INERT - the phase
#                 always requests the operator's base-url, so a per-case
#                 inventory only sees what its own path adds.
#   leak-binary   every response is an image with no textual body, which is what
#                 the "a family no response was applicable to is NOT covered"
#                 case needs.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: leak-fixture
base-url: https://leak.fixture.example/
notes: Fixture target for tests/suites/dast-leakage.sh. Never dialled: both the
  resolver and the transport are stubbed.

id: leak-binary
base-url: https://binary.fixture.example/
notes: Fixture target whose every response is a binary body, for the
  family-not-applicable coverage case.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32 ceiling
# does not clamp the rate to 4/s and the throttle never real-sleeps.
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_leak_resolve() {
  case $1 in
    leak.fixture.example | binary.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_leak_resolve

# ===========================================================================
# The recorded responses.
# ===========================================================================
# `_head <host> <path>` prints the RAW response head exactly as curl's `-D`
# writes it; `_body <host> <path>` prints the response body.  Nothing is
# invented at read time.

_head() {
  local host=$1 path=$2
  case $host$path in
    leak.fixture.example/proxied)
      # POSITIVE for family 2: an RFC 1918 literal and a Kubernetes service DNS
      # name, in two different infrastructure headers.
      printf '%s' $'Content-Type: text/html\r\nX-Backend-Server: 10.0.3.14:8080\r\nVia: 1.1 app-07.svc.cluster.local\r\n' ;;
    leak.fixture.example/cdnedge)
      # NEGATIVE for family 2: a proxy PRODUCT name and a public CDN edge POP
      # code.  Both are dotless tokens; neither names anything internal.
      printf '%s' $'Content-Type: text/html\r\nVia: 1.1 varnish\r\nX-Served-By: cache-lhr7364-LHR\r\nX-Cache-Server: cache-fra-eddf8230058\r\n' ;;
    leak.fixture.example/app.js | leak.fixture.example/public.js | leak.fixture.example/bundle.js)
      printf '%s' $'Content-Type: application/javascript\r\n' ;;
    leak.fixture.example/api.json)
      printf '%s' $'Content-Type: application/json\r\n' ;;
    binary.fixture.example*)
      printf '%s' $'Content-Type: image/png\r\n' ;;
    *)
      printf '%s' $'Content-Type: text/html; charset=utf-8\r\n' ;;
  esac
}

_body() {
  local host=$1 path=$2
  if [[ $host == binary.fixture.example ]]; then
    # A binary body: no textual family applies to it.
    printf '\x89PNG\x0d\x0a\x1a\x0a fixture bytes\n'
    return 0
  fi
  case $path in
    /)
      # DELIBERATELY INERT.  Relative URLs only, no address, no config, no
      # trace - so a per-case inventory sees only what its own path adds.
      printf '%s\n' '<!doctype html><html><head><title>Fixture</title>' \
        '<link rel="stylesheet" href="/static/site.css">' \
        '</head><body><h1>Fixture</h1><p>Nothing to see.</p>' \
        '<script src="/static/app.js"></script></body></html>' ;;
    /trace)
      # POSITIVE for family 1: a real Python traceback, with the banner AND
      # file:line frames.
      printf '%s\n' '<!doctype html><html><body><pre>' \
        'Traceback (most recent call last):' \
        '  File "/srv/app/views.py", line 118, in dispatch' \
        '    return handler(request)' \
        '  File "/srv/app/orders.py", line 42, in show' \
        '    raise KeyError(order_id)' \
        'KeyError: 9001' \
        '</pre></body></html>' ;;
    /trace-jvm)
      printf '%s\n' 'java.lang.NullPointerException' \
        '	at com.example.svc.OrderService.load(OrderService.java:214)' \
        '	at com.example.web.Controller.get(Controller.java:88)' ;;
    /notfound)
      # NEGATIVE for family 1.  A framework-branded 404: it says "Error", it
      # says "error", it names a framework AND a version.  It carries no frame.
      printf '%s\n' '<!doctype html><html><body>' \
        '<h1>Error 404 - Page not found</h1>' \
        '<p>The page you requested could not be found. If you think this is an' \
        ' error, please try again later.</p>' \
        '<footer>Powered by Django 4.2 - exception handling by our error page' \
        ' stack</footer></body></html>' ;;
    /contact)
      # NEGATIVE for family 3.  Three shapes a naive regex flags and this check
      # must not: an INDIVIDUAL address the site publishes on purpose as a
      # `mailto:` link, a role alias in page copy, and a retina image asset
      # whose filename matches every naive email regex ever written.
      #
      # The published address is deliberately an individual (`jane.doe@`) and
      # NOT a role alias: a role alias would be excluded by the role rule
      # anyway, so using one here would let the mailto: subtraction be broken
      # without any assertion noticing.
      printf '%s\n' '<!doctype html><html><body>' \
        '<img srcset="/img/logo@2x.png 2x" src="/img/logo.png" alt="Logo">' \
        '<p>Contact <a href="mailto:jane.doe@leak.fixture.example">our support' \
        ' team</a>, or email info@leak.fixture.example for anything else.</p>' \
        '</body></html>' ;;
    /profile)
      # POSITIVE for family 3, and the cross-response mailto: subtraction: it
      # names two individual addresses that are NOT published anywhere, AND
      # repeats - as plain text, not as a link - the individual address
      # /contact publishes as a `mailto:`.  Only the first two are reportable.
      printf '%s\n' '<!doctype html><html><body>' \
        '<!-- TODO: ping dba.oncall@leak.fixture.example about the slow query -->' \
        '<p>Escalations also go to jane.doe@leak.fixture.example.</p>' \
        '<script>window.__OWNER__ = {"ownerEmail":"j.smith@leak.fixture.example"};</script>' \
        '</body></html>' ;;
    /public.js)
      # NEGATIVE for family 4.  Three values that are PUBLIC BY DESIGN: a Stripe
      # publishable key, a Google browser API key, and an analytics id.
      printf '%s\n' 'window.CFG = {' \
        '  stripePublishableKey: "pk_live_51H8sMkFakeFixtureValue0000",' \
        '  mapsApiKey: "AIzaSyDfixtureValueNotARealKey0000000",' \
        '  measurementId: "G-ABCDEF1234",' \
        '  trackingId: "UA-123456-1",' \
        '  clientId: "482910384.apps.example",' \
        '  sentryDsn: "https://abcdef0123456789@ingest.telemetry.example/42"' \
        '};' ;;
    /app.js)
      # POSITIVE for family 4: a never-client-safe key name with a real literal,
      # a vendor-declared secret value shape, and an internal service URL.
      printf '%s\n' 'window.__CFG__ = {' \
        '  apiSecret: "s3cr3t-f9a1c4d7e2b8",' \
        '  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",' \
        '  internalApiBase: "http://10.0.3.14:8080/v1",' \
        '  publishableKey: "pk_test_fixtureValue00000"' \
        '};' ;;
    /api.json)
      printf '%s\n' '{"ok":true,"connectionString":"postgres://svc:h0rr1blePassw0rd@db.internal:5432/app"}' ;;
    /cdn)
      # NEGATIVE for family 5: a relative path, an absolute SELF link, and the
      # site's OWN cdn subdomain.  None of these is a third party.
      printf '%s\n' '<!doctype html><html><head>' \
        '<script src="/static/app.js"></script>' \
        '<script src="https://leak.fixture.example/static/vendor.js"></script>' \
        '<script src="//cdn.leak.fixture.example/bundle.js"></script>' \
        '<link rel="canonical" href="https://leak.fixture.example/cdn">' \
        '</head><body>ok</body></html>' ;;
    /vendor)
      # POSITIVE for family 5.
      printf '%s\n' '<!doctype html><html><head>' \
        '<script src="https://ajax.thirdparty.example/jquery.min.js"></script>' \
        '<script src="https://tags.analytics-vendor.example/t.js"></script>' \
        '<link rel="stylesheet" href="https://fonts.typeface-vendor.example/css">' \
        '<script src="/static/app.js"></script>' \
        '</head><body>ok</body></html>' ;;
    /bundle.js)
      # ONE ENORMOUS LINE, with the disclosure past the per-line byte cap.  A
      # reader that truncated the line instead of chunking it would inspect the
      # first 4 KiB and call the rest clean.
      local pad='' i
      for (( i = 0; i < 400; i++ )); do
        pad+='function f'"$i"'(){return "harmless padding value '"$i"'";}'
      done
      printf '%s\n' "$pad"'var q={dbPassword:"pr0ductionPassw0rd!"};' ;;
    /redirect-final)
      printf '%s\n' '<!doctype html><html><body>landed</body></html>' ;;
    *)
      printf '%s\n' '<!doctype html><html><body>generic</body></html>' ;;
  esac
}

REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

_leak_transport() {
  local method=$1 host=$3 path=$5
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local status=200 location='' ctype head

  if [[ $host == leak.fixture.example && $path == /redirect ]]; then
    status=302
    location='https://leak.fixture.example/redirect-final'
    # The REDIRECT hop carries the infrastructure header.  The landing page does
    # not.  A reader matching across the whole accumulated capture would find it
    # here and report it as the delivered page's.
    head=$'Content-Type: text/html\r\nLocation: https://leak.fixture.example/redirect-final\r\nX-Backend-Server: 10.9.9.9\r\n'
  else
    head=$(_head "$host" "$path")
  fi

  ctype=''
  case $head in
    *'Content-Type: application/javascript'*) ctype='application/javascript' ;;
    *'Content-Type: application/json'*) ctype='application/json' ;;
    *'Content-Type: image/png'*) ctype='image/png' ;;
    *'Content-Type: text/html'*) ctype='text/html' ;;
  esac

  printf '%s %s %s\n' "$method" "$host" "$path" >>"$REQ_LOG"
  if [[ -n $hdrsout ]]; then
    printf 'HTTP/1.1 %s OK\r\n%s\r\n' "$status" "$head" >>"$hdrsout"
  fi
  if [[ -n $bodyout ]]; then
    if [[ $status == 302 ]]; then
      : >"$bodyout"
    else
      _body "$host" "$path" >"$bodyout"
    fi
  fi
  printf '%s\n%s\n%s\n' "$status" "$location" "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_leak_transport

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target "${2:-leak-fixture}"
  occurrence_reset_all
  _req_reset
}

# `_inv NAME TARGET URL...` writes an endpoints.json naming each URL and prints
# its path.  The shape is docs/INVENTORY-FORMAT.md's, written the way a
# conformant producer other than crawl.sh might.
_inv() {
  local name=$1 target=$2; shift 2
  local f=$W/$name.endpoints.json u i=0 rows=''
  for u in "$@"; do
    rows+="${rows:+,}"$'\n'"  { \"id\": \"ep$i\", \"target\": \"$target\", \"method\": \"GET\", \"url\": \"$u\", \"path\": \"$(leak_path_of "$u")\" }"
    i=$(( i + 1 ))
  done
  printf '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [%s\n] }\n' "$rows" >"$f"
  printf '%s' "$f"
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

# The value of one field of the FIRST finding for a check id.
#
# The locals are `_v` / `_hit` rather than the obvious `out` / `cur`: this file
# sources leakage_engine.sh, which uses both of those names as ARRAYS, and
# `shellcheck -x` follows the source and reports SC2178/SC2128 for the collision.
_field_of() {
  local check=$1 want=$2 f line fld _hit='' _v=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      _hit='' _v=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && _hit=1
        [[ $fld == "$want="* ]] && _v=${fld#"$want="}
      done
      [[ -n $_hit ]] && { printf '%s' "$_v"; return 0; }
    done <"$f"
  done
  printf ''
}

# Every value of one field, across all findings for a check id, newline joined.
_fields_of_all() {
  local check=$1 want=$2 f line fld _hit _v
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      _hit='' _v=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && _hit=1
        [[ $fld == "$want="* ]] && _v=${fld#"$want="}
      done
      [[ -n $_hit ]] && printf '%s\n' "$_v"
    done <"$f"
  done
}

_meta() { run_facts "$1" 2>/dev/null || printf ''; }

# `_run_case NAME TARGET [URL...]` - a fresh run, an inventory of the given
# URLs, and one invocation of the phase.
_run_case() {
  local name=$1 target=$2; shift 2
  _new_run "$name" "$target"
  if (( $# > 0 )); then
    SCOURSH_DAST_ENDPOINTS=$(_inv "$name" "$target" "$@")
  else
    SCOURSH_DAST_ENDPOINTS=''
  fi
  SCOURSH_DAST_TARGET=$target
  SCOURSH_DAST_CELL=$target
  SCOURSH_DAST_INTENSITY=passive
  SCOURSH_DAST_AUTHED=false
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL \
    SCOURSH_DAST_INTENSITY SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
  unset SCOURSH_SELECTED_CHECKS
  _dast_leakage_phase
}

# ===========================================================================
printf '== A. the engine: the body reader ==\n'
# ===========================================================================
t_case 'body-reader'
BF=$W/body.txt
printf 'line one\nline two\n' >"$BF"
# Called DIRECTLY, never through `$(...)`: this function publishes its result in
# globals, and a side-effecting function called in a command substitution runs in
# a subshell whose writes are discarded (AGENTS.md, "Things measured on this
# codebase").  Only the RETURN CODE cases below may use a substitution.
_rc=0; leak_body_read "$BF" || _rc=$?
assert_eq 0 "$_rc" 'a readable, non-empty body is read'
assert_eq 2 "$_LEAK_NLINES" 'both lines are available to the families'

: >"$BF"
_rc=0; leak_body_read "$BF" || _rc=$?
assert_ne 0 "$_rc" \
  'an EMPTY body returns non-zero rather than reporting a body with nothing in it - the caller needs to tell "no body" from "a body that disclosed nothing"'

_rc=0; leak_body_read "$W/does-not-exist" || _rc=$?
assert_ne 0 "$_rc" 'an absent capture returns non-zero'

# READING 8: a minified bundle is one enormous line and must be CHUNKED.
t_case 'body-reader-chunking'
python_free_pad=''
for _i in $(seq 1 300); do python_free_pad+='0123456789abcdef'; done
printf '%sSENTINEL_PAST_THE_LINE_CAP\n' "$python_free_pad" >"$BF"
leak_body_read "$BF"
_found=0
for _n in "${_LEAK_LINES[@]}"; do
  [[ $_n == *SENTINEL_PAST_THE_LINE_CAP* ]] && _found=1
done
assert_eq 1 "$_found" \
  'a token past the per-line byte cap is still inspected, because a long line is CHUNKED - FAILS under a truncating reader, which would read 4 KiB of a 900 KiB bundle and report the other 99% clean'
assert_true "$(( _LEAK_NLINES > 1 ? 0 : 1 ))" \
  'the one long line became several chunks'

t_case 'ctype-kind'
assert_eq html "$(leak_ctype_kind 'text/html; charset=utf-8')" 'an HTML document'
assert_eq js "$(leak_ctype_kind 'application/javascript')" 'served JavaScript'
assert_eq json "$(leak_ctype_kind 'application/vnd.api+json')" 'a +json suffix type is JSON'
assert_eq other "$(leak_ctype_kind 'image/png')" 'an image is not a textual body'
assert_eq other "$(leak_ctype_kind '')" 'an absent Content-Type is not assumed textual'

# ===========================================================================
printf '== B. the engine: each family in isolation ==\n'
# ===========================================================================
t_case 'family-1-stack-frames'
assert_true "$(leak_stack_frame_in 'Traceback (most recent call last):' && printf 0 || printf 1)" \
  'the Python traceback banner is a frame'
assert_true "$(leak_stack_frame_in '  File "/srv/app/views.py", line 118, in dispatch' && printf 0 || printf 1)" \
  'a Python file:line frame'
leak_stack_frame_in '	at com.example.svc.OrderService.load(OrderService.java:214)'
assert_eq jvm "$_LEAK_STACK_KIND" 'a JVM frame is recognised and labelled'
leak_stack_frame_in '    at Object.handler (/srv/app/routes.js:12:9)'
assert_eq node "$_LEAK_STACK_KIND" 'a V8 frame carries both a line AND a column'
leak_stack_frame_in '#0 /var/www/html/index.php(42): App\Kernel->handle()'
assert_eq php "$_LEAK_STACK_KIND" 'an xdebug frame'
leak_stack_frame_in '/app/controllers/orders_controller.rb:42:in `show'"'"''
assert_eq ruby "$_LEAK_STACK_KIND" 'a Ruby frame'
leak_stack_frame_in '   at App.Svc.Load() in C:\src\Svc.cs:line 42'
assert_eq dotnet "$_LEAK_STACK_KIND" 'a .NET frame'
leak_stack_frame_in 'goroutine 41 [running]:'
assert_eq go "$_LEAK_STACK_KIND" 'a Go panic header'
leak_stack_frame_in 'Werkzeug Debugger'
assert_eq debugger "$_LEAK_STACK_KIND" \
  'an INTERACTIVE debugger banner is the one deliberate non-file:line shape, because it is worse than a trace'

t_case 'family-2-internal-identity'
assert_true "$(leak_internal_identity_in '10.0.3.14:8080' && printf 0 || printf 1)" \
  'an RFC 1918 10/8 literal is an internal identity - the commonest real case, and the one lib/http.sh own deny list does NOT carry'
assert_true "$(leak_internal_identity_in '172.16.4.9' && printf 0 || printf 1)" '172.16/12'
assert_true "$(leak_internal_identity_in '192.168.1.7' && printf 0 || printf 1)" '192.168/16'
assert_true "$(leak_internal_identity_in '127.0.0.1' && printf 0 || printf 1)" 'loopback'
assert_true "$(leak_internal_identity_in '169.254.169.254' && printf 0 || printf 1)" 'link-local, the cloud metadata address'
assert_true "$(leak_internal_identity_in '1.1 app-07.svc.cluster.local' && printf 0 || printf 1)" \
  'a Kubernetes service DNS name is an internal identity'
assert_true "$(leak_internal_identity_in '172.32.4.9' && printf 1 || printf 0)" \
  '172.32 is OUTSIDE RFC 1918 and is a public address - FAILS under a naive `172.` prefix test'
assert_true "$(leak_internal_identity_in '203.0.113.9' && printf 1 || printf 0)" \
  'a public literal is not an internal identity'

t_case 'family-3-email-shapes'
leak_emails_reset
leak_emails_scan 'reach j.smith@leak.fixture.example today' /x
leak_emails_finish
assert_eq 1 "${#_LEAK_EMAILS[@]}" 'an individual address is reportable'
assert_eq 'j.smith@leak.fixture.example' "${_LEAK_EMAILS[0]}" 'and is normalised to lowercase'

leak_emails_reset
leak_emails_scan 'two here: a.one@leak.fixture.example and b.two@leak.fixture.example.' /x
leak_emails_finish
assert_eq 2 "${#_LEAK_EMAILS[@]}" \
  'several addresses on ONE line are all found - FAILS under a single `=~` evaluation, which returns one match per call'

t_case 'family-4-js-shapes'
leak_js_reset
leak_js_config_in '  apiSecret: "s3cr3t-f9a1c4d7e2b8",' /x
assert_eq 1 "${#_LEAK_JSCFG[@]}" 'a never-client-safe key name with a real literal is reported'
leak_js_reset
leak_js_config_in '  apiSecret: "",' /x
assert_eq 0 "${#_LEAK_JSCFG[@]}" 'an EMPTY value behind the same key is not a credential'
leak_js_reset
leak_js_config_in '  apiSecret: "${API_SECRET}",' /x
assert_eq 0 "${#_LEAK_JSCFG[@]}" \
  'a template hole a build step never filled is not a credential - FAILS under "the key name alone is the finding"'
leak_js_reset
leak_js_config_in '  someLabel: "AKIAIOSFODNN7EXAMPLE",' /x
assert_eq 1 "${#_LEAK_JSCFG[@]}" \
  'a vendor-declared secret VALUE shape is reported whatever the key is called'
leak_js_reset
leak_js_config_in '  base: "http://10.0.3.14:8080/v1",' /x
assert_eq 1 "${#_LEAK_JSCFG[@]}" 'an internal service URL committed into the bundle is client-config leakage'
leak_js_reset
leak_js_config_in '  base: "https://api.leak.fixture.example/v1",' /x
assert_eq 0 "${#_LEAK_JSCFG[@]}" 'a PUBLIC service URL is ordinary and is not reported'

t_case 'family-5-same-site'
assert_true "$(leak_same_site cdn.leak.fixture.example leak.fixture.example && printf 0 || printf 1)" \
  "a site's own cdn subdomain shares its registrable domain"
assert_true "$(leak_same_site leak.fixture.example leak.fixture.example && printf 0 || printf 1)" \
  'the response host itself'
assert_true "$(leak_same_site ajax.thirdparty.example leak.fixture.example && printf 1 || printf 0)" \
  'a genuinely different registrable domain is a third party'

# ===========================================================================
printf '== C. THE FIVE NEGATIVE FIXTURES: each naive reading fires, this one does not ==\n'
# ===========================================================================
# Every case below asserts BOTH halves.  Asserting only "no finding" would pass
# equally well against a check broken into silence, which pins nothing.

t_case 'negative-1-branded-404'
BRANDED='<h1>Error 404 - Page not found</h1><p>If you think this is an error, try again.</p><footer>Powered by Django 4.2 - exception handling by our error page stack</footer>'
# The naive reading, run inline so the difference itself is the assertion.
_naive_trace() {
  local t=${1,,}
  [[ $t == *error* || $t == *exception* || $t == *stack* || $t == *django* || $t == *traceback* ]]
}
assert_true "$(_naive_trace "$BRANDED" && printf 0 || printf 1)" \
  'the NAIVE reading (body mentions error/exception/stack/a framework name) DOES fire on a framework-branded 404'
assert_true "$(leak_stack_frame_in "$BRANDED" && printf 1 || printf 0)" \
  'the shipped check does NOT - it requires a STRUCTURED FRAME (a source file plus a line number) or a debugger banner, and a branded 404 carries neither'
assert_true "$(leak_stack_frame_in '  File "/srv/app/views.py", line 118, in dispatch' && printf 0 || printf 1)" \
  'and the check is not merely inert: a real frame still fires'

t_case 'negative-2-cdn-pop-code'
_naive_proxy() { [[ -n $1 ]]; }   # "the header is present, therefore it leaks"
for _v in '1.1 varnish' 'cache-lhr7364-LHR' 'cache-fra-eddf8230058'; do
  assert_true "$(_naive_proxy "$_v" && printf 0 || printf 1)" \
    "the NAIVE reading (the header name alone is the finding) DOES fire on '$_v'"
  assert_true "$(leak_internal_identity_in "$_v" && printf 1 || printf 0)" \
    "the shipped check does NOT: '$_v' is a proxy product name or a public CDN edge POP code, and a dotless token is genuinely ambiguous - only an unroutable address or a reserved-internal DNS suffix is reported"
done
assert_true "$(leak_internal_identity_in '1.1 app-07.svc.cluster.local' && printf 0 || printf 1)" \
  'and the check is not merely inert: a real internal identity still fires'

t_case 'negative-3-published-contact-and-srcset'
COPY='<img srcset="/img/logo@2x.png 2x"><p>Contact <a href="mailto:jane.doe@leak.fixture.example">our team</a>, or email info@leak.fixture.example.</p>'
_naive_email() {
  # The regex every naive implementation writes.
  [[ $1 =~ [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,} ]]
}
assert_true "$(_naive_email "$COPY" && printf 0 || printf 1)" \
  'the NAIVE x@y.z regex DOES fire on the published contact copy'
leak_emails_reset
leak_emails_scan "$COPY" /contact
leak_emails_finish
assert_eq 0 "${#_LEAK_EMAILS[@]}" \
  'the shipped check reports NONE of the three: `jane.doe@` is published as a mailto: link (deliberate publication), `info@` is an RFC 2142 role alias, and `logo@2x.png` is a filename rather than a domain'
assert_eq 1 "${_LEAK_EMAILS_PUBLISHED:-0}" \
  'the published address is COUNTED as subtracted rather than silently dropped, so the finding can say so'
leak_emails_reset
leak_emails_scan '<!-- ping dba.oncall@leak.fixture.example -->' /profile
leak_emails_finish
assert_eq 1 "${#_LEAK_EMAILS[@]}" \
  'and the check is not merely inert: an individual address in a comment still fires'

t_case 'negative-4-public-by-design-keys'
PUBLIC_JS='stripePublishableKey: "pk_live_51H8sMkFakeFixtureValue0000", mapsApiKey: "AIzaSyDfixtureValueNotARealKey0000000", trackingId: "UA-123456-1"'
_naive_js() {
  local low=${1,,}
  [[ $low == *key* || $low == *token* || $low == *id:* ]]
}
assert_true "$(_naive_js "$PUBLIC_JS" && printf 0 || printf 1)" \
  'the NAIVE reading (a key-ish name with a string literal) DOES fire on the three public-by-design values'
leak_js_reset
leak_js_config_in "$PUBLIC_JS" /public.js
assert_eq 0 "${#_LEAK_JSCFG[@]}" \
  'the shipped check reports NONE: a Stripe PUBLISHABLE key, a Google browser API key and an analytics id are documented as browser-safe and the application cannot work without shipping them'
assert_true "$(( _LEAK_JSCFG_PUBLIC >= 3 ? 0 : 1 ))" \
  'they are COUNTED as allow-listed rather than silently ignored, so the finding can say how many were subtracted'
leak_js_reset
leak_js_config_in 'apiSecret: "s3cr3t-f9a1c4d7e2b8"' /app.js
assert_eq 1 "${#_LEAK_JSCFG[@]}" \
  'and the check is not merely inert: a real secret in the same shape still fires'

t_case 'negative-5-self-hosted-assets'
SELF_HTML='<script src="/static/app.js"></script><script src="https://leak.fixture.example/static/vendor.js"></script><script src="//cdn.leak.fixture.example/bundle.js"></script>'
_naive_origin() { [[ $1 == *'://'* || $1 == *'//'* ]]; }
assert_true "$(_naive_origin "$SELF_HTML" && printf 0 || printf 1)" \
  'the NAIVE reading (any absolute URL is a third party) DOES fire on a page that loads only its own assets'
leak_origins_reset
leak_origins_in "$SELF_HTML" leak.fixture.example
assert_eq 0 "${#_LEAK_ORIGINS[@]}" \
  "the shipped check reports NONE: a relative path is same-origin by construction, and the absolute self-link and the site's own cdn subdomain share its registrable domain"
leak_origins_reset
leak_origins_in '<script src="https://ajax.thirdparty.example/j.js"></script>' leak.fixture.example
assert_eq 1 "${#_LEAK_ORIGINS[@]}" \
  'and the check is not merely inert: a genuine third party still fires'

# ===========================================================================
printf '== D. the phase, end to end against recorded responses ==\n'
# ===========================================================================
# A phase script has no sourced-once guard and runs its phase function at source
# time (that is how dast_run_phase invokes it), so it is sourced once here
# against a throwaway run with no inventory - a run that still fetches the
# inert base URL - and then re-invoked per case below.
SCOURSH_DAST_TARGET=leak-fixture
SCOURSH_DAST_CELL=leak-fixture
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED SCOURSH_DAST_ENDPOINTS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/passive/leakage.sh
source "$ROOT/modules/dast/passive/leakage.sh"

t_case 'phase-inert-baseline'
_run_case inert leak-fixture
_n=0
for _c in "${_LEAK_CHECK_IDS[@]}"; do
  _n=$(( _n + $(_count_check "$_c") ))
done
assert_eq 0 "$_n" \
  'the inert base-url response produces NO finding of any family - which is what makes every per-case assertion below about that case own path'
assert_contains "$(_meta checks_run)" DAST-LEAK-STACK_TRACE-01 \
  'but the families that WERE applicable are still recorded as run - a clean result on a tested response is different from an untested one'

t_case 'phase-family-1-trace'
_run_case trace leak-fixture https://leak.fixture.example/trace https://leak.fixture.example/notfound
assert_eq 1 "$(_count_check DAST-LEAK-STACK_TRACE-01)" \
  'exactly ONE stack-trace finding across the traceback page AND the branded 404 - the 404 is not reported'
assert_eq /trace "$(_field_of DAST-LEAK-STACK_TRACE-01 loc_path_template)" \
  'and it is located at the page that actually carried the frame'
assert_contains "$(_field_of DAST-LEAK-STACK_TRACE-01 evidence)" 'python' \
  'the evidence names the runtime whose frame shape matched'
assert_eq medium "$(_field_of DAST-LEAK-STACK_TRACE-01 base_severity)" 'severity per the catalog'
assert_eq CWE-209 "$(_field_of DAST-LEAK-STACK_TRACE-01 cwe)" 'CWE-209, error message containing sensitive information'

t_case 'phase-family-1-per-path'
_run_case trace2 leak-fixture https://leak.fixture.example/trace https://leak.fixture.example/trace-jvm
assert_eq 2 "$(_count_check DAST-LEAK-STACK_TRACE-01)" \
  'TWO traces on two paths are TWO findings - a trace is a property of one handler, not of the application, so the operator gets one item per place to fix'

t_case 'phase-family-2-proxy-header'
_run_case proxy leak-fixture https://leak.fixture.example/proxied https://leak.fixture.example/cdnedge
assert_eq 1 "$(_count_check DAST-LEAK-PROXY_HEADER-01)" \
  'one infrastructure-header finding: the internally-addressed response is reported and the CDN-fronted one is not'
assert_eq /proxied "$(_field_of DAST-LEAK-PROXY_HEADER-01 loc_path_template)" \
  'located at the response that carried the internal identity'
_EV=$(_field_of DAST-LEAK-PROXY_HEADER-01 evidence)
assert_contains "$_EV" '10.0.3.14' \
  'the evidence names the internal address in the X-Backend-Server header'
assert_contains "$_EV" 'app-07.svc.cluster.local' \
  'AND the internal DNS name in the Via header on the same response - FAILS under a first-match-wins loop, which would report one of the two places the operator must unset it and leave the other in place'

t_case 'phase-family-2-cdn-only-is-clean'
_run_case cdnedge leak-fixture https://leak.fixture.example/cdnedge
assert_eq 0 "$(_count_check DAST-LEAK-PROXY_HEADER-01)" \
  'a target fronted ONLY by a public CDN produces no infrastructure finding - FAILS under "the header name is the finding", which would flag every CDN customer on the internet'
assert_contains "$(_meta checks_run)" DAST-LEAK-PROXY_HEADER-01 \
  'and the check is still recorded as RUN, so the clean result is a tested one'

# READING 7: only the final hop counts.
t_case 'phase-final-hop-only'
_run_case redirect leak-fixture https://leak.fixture.example/redirect
assert_eq 0 "$(_count_check DAST-LEAK-PROXY_HEADER-01)" \
  'an infrastructure header set on the REDIRECT hop is not reported as the delivered page - FAILS under a whole-capture match, since the capture sink accumulates every hop by design'

t_case 'phase-family-3-email'
_run_case email leak-fixture https://leak.fixture.example/contact https://leak.fixture.example/profile
assert_eq 1 "$(_count_check DAST-LEAK-EMAIL-01)" 'one roll-up finding for the target'
_EV=$(_field_of DAST-LEAK-EMAIL-01 evidence)
assert_contains "$_EV" 'dba.oncall@leak.fixture.example' 'the address hidden in an HTML comment is reported'
assert_contains "$_EV" 'j.smith@leak.fixture.example' 'the address in an embedded JSON blob is reported'
assert_not_contains "$_EV" 'info@leak.fixture.example' 'the role alias is not'
assert_not_contains "$_EV" 'logo@2x.png' 'and neither is the retina image asset'
# READING 6: the mailto subtraction is per TARGET, not per line or per response.
assert_not_contains "$_EV" 'jane.doe@leak.fixture.example' \
  'an INDIVIDUAL address published as a mailto: link on /contact is subtracted from its plain-text mention on a DIFFERENT page - FAILS under a per-line or per-response subtraction, which meets the second page before the contact link half the time. The address is deliberately not a role alias, so the role rule cannot satisfy this assertion instead.'
assert_eq low "$(_field_of DAST-LEAK-EMAIL-01 base_severity)" 'severity per the catalog'

t_case 'phase-family-4-js-config'
_run_case js leak-fixture https://leak.fixture.example/app.js https://leak.fixture.example/public.js
assert_eq 1 "$(_count_check DAST-LEAK-JS_CONFIG-01)" \
  'one finding, at the bundle that carried the credentials - the public-by-design bundle produces none'
assert_eq /app.js "$(_field_of DAST-LEAK-JS_CONFIG-01 loc_path_template)" 'located at that bundle'
_EV=$(_field_of DAST-LEAK-JS_CONFIG-01 evidence)
assert_contains "$_EV" 'apiSecret' 'the never-client-safe key name is named'
assert_contains "$_EV" 'AWS access key id' 'the vendor-declared secret shape is named'
assert_contains "$_EV" 'internal service URL' 'the internal service URL is named'
# READING 13: the value never reaches the report.
assert_not_contains "$_EV" 's3cr3t-f9a1c4d7e2b8' \
  'the candidate secret VALUE is NOT in the evidence - a finding that quotes a credential has copied it into this report, the shard file and the operator scrollback'
assert_not_contains "$_EV" 'AKIAIOSFODNN7EXAMPLE' 'nor is the access key id itself'
assert_contains "$_EV" 'value length' 'the length is given instead, which locates it without disclosing it'
assert_eq high "$(_field_of DAST-LEAK-JS_CONFIG-01 base_severity)" 'a shipped credential is a high-severity finding'
assert_eq true "$(_field_of DAST-LEAK-JS_CONFIG-01 sensitive_data)" 'and is marked as carrying sensitive data'

t_case 'phase-family-4-public-bundle-alone'
_run_case jspub leak-fixture https://leak.fixture.example/public.js
assert_eq 0 "$(_count_check DAST-LEAK-JS_CONFIG-01)" \
  'a bundle carrying ONLY public-by-design values produces no finding - FAILS under a key-name-shaped naive check'
assert_contains "$(_meta checks_run)" DAST-LEAK-JS_CONFIG-01 'and the family is still recorded as run'

# READING 8, end to end: the disclosure sits past the per-line byte cap.
t_case 'phase-family-4-minified-bundle'
_run_case jsmin leak-fixture https://leak.fixture.example/bundle.js
assert_eq 1 "$(_count_check DAST-LEAK-JS_CONFIG-01)" \
  'a credential past the per-line byte cap of a single-line minified bundle is still found - FAILS under a truncating body reader, which inspects the first chunk and calls the rest clean'

t_case 'phase-family-5-third-party'
_run_case origins leak-fixture https://leak.fixture.example/vendor https://leak.fixture.example/cdn
assert_eq 1 "$(_count_check DAST-LEAK-THIRD_PARTY_ORIGIN-01)" 'one informational inventory finding'
# READING 10.
assert_eq info "$(_field_of DAST-LEAK-THIRD_PARTY_ORIGIN-01 base_severity)" \
  'the third-party origin family is INFORMATIONAL severity, which is this ticket own acceptance criterion'
_EV=$(_field_of DAST-LEAK-THIRD_PARTY_ORIGIN-01 evidence)
assert_contains "$_EV" 'ajax.thirdparty.example' 'a genuine third-party script origin is inventoried'
assert_contains "$_EV" 'tags.analytics-vendor.example' 'and so is the analytics vendor'
assert_not_contains "$_EV" 'cdn.leak.fixture.example' \
  "the site's OWN cdn subdomain is NOT listed - FAILS under any-absolute-URL, which is the naive reading"

t_case 'phase-family-5-self-hosted-only'
_run_case selfhost leak-fixture https://leak.fixture.example/cdn
assert_eq 0 "$(_count_check DAST-LEAK-THIRD_PARTY_ORIGIN-01)" \
  'a page loading only its own assets produces no third-party finding at all'

# ===========================================================================
printf '== E. coverage honesty: an unevaluated family never reads as clean ==\n'
# ===========================================================================
t_case 'coverage-family-not-applicable'
_run_case binary leak-binary
_RED=$(_meta coverage_reduction)
assert_contains "$_RED" 'leakage_family_not_applicable' \
  'a run whose every response was a binary body records that the body-reading families were NOT evaluated'
assert_contains "$_RED" 'DAST-LEAK-JS_CONFIG-01' 'and names the client-config family specifically'
assert_contains "$_RED" 'DAST-LEAK-STACK_TRACE-01' 'and the stack-trace family'
assert_not_contains "$(_meta checks_run)" DAST-LEAK-JS_CONFIG-01 \
  'and does NOT report it in checks_run - a family no response was applicable to covered nothing, and reporting it as covered is the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$(_meta checks_run)" DAST-LEAK-PROXY_HEADER-01 \
  'while the header-only family, which needs no body, IS covered on that same run'

t_case 'coverage-no-endpoint'
_new_run noep leak-fixture
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_TARGET=leak-fixture
SCOURSH_DAST_CELL=leak-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
# A target with no base-url at all: nothing to ask for.
config_scope_load "$SCOPE"
_saved_base=$(config_scope_field_or leak-fixture base-url '')
assert_ne '' "$_saved_base" 'the fixture target does have a base-url (guard for the case below)'

t_case 'coverage-out-of-scope-url-is-skipped'
# READING 11: an inventory URL the gate declines must be SKIPPED, never handed
# to http_request - which gates fatally and would abort the whole run.
_run_case oos leak-fixture https://not-authorised.fixture.example/x https://leak.fixture.example/trace
assert_eq 1 "$(_count_check DAST-LEAK-STACK_TRACE-01)" \
  'the in-scope URL is still inspected: an out-of-scope inventory row does not abort the run'
assert_not_contains "$(cat "$REQ_LOG")" 'not-authorised.fixture.example' \
  'and no request was ever sent to the unauthorised host - asserted on the REQUEST LOG, not on a return value'
assert_contains "$(_meta coverage_reduction)" 'leakage_endpoint_out_of_scope' \
  'the skipped URL is recorded rather than silently dropped'

t_case 'coverage-non-get-endpoint'
_NG=$W/nonget.endpoints.json
cat >"$_NG" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e0", "target": "leak-fixture", "method": "POST", "url": "https://leak.fixture.example/checkout", "path": "/checkout" }
] }
EOF
_new_run nonget leak-fixture
SCOURSH_DAST_ENDPOINTS=$_NG
SCOURSH_DAST_TARGET=leak-fixture
SCOURSH_DAST_CELL=leak-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
unset SCOURSH_SELECTED_CHECKS
_dast_leakage_phase
assert_not_contains "$(cat "$REQ_LOG")" '/checkout' \
  'a discovered POST is NEVER re-sent: doing so to read its response would change target state, which §7.1 forbids at the passive tier'
assert_contains "$(_meta coverage_reduction)" 'leakage_non_get_endpoint_skipped' \
  'and it is counted and declared, not silently dropped'

# ===========================================================================
printf '== F. the shell catalog and checks.rules agree ==\n'
# ===========================================================================
# READING 12.  The registry is what tension 12 computes coverage over and
# tension 15 filters; the shell catalog is what a finding actually carries.  Two
# copies, on purpose - so they are asserted equal here rather than hoped equal.
t_case 'catalog-registry-agreement'
RULES=$ROOT/modules/dast/passive/checks-leakage.rules
_rule_field() {
  # `_cur_id`, not `cur`: leakage_engine.sh uses `cur` as an associative array
  # and `shellcheck -x` follows the source into it.
  local want_id=$1 key=$2 _cur_id='' line val=''
  while IFS= read -r line; do
    [[ ${line:0:1} == '#' ]] && continue
    if [[ $line == 'id: '* ]]; then _cur_id=${line#id: }; continue; fi
    [[ $_cur_id == "$want_id" ]] || continue
    if [[ $line == "$key: "* ]]; then val=${line#"$key": }; printf '%s' "$val"; return 0; fi
  done <"$RULES"
  printf ''
}
for _c in "${_LEAK_CHECK_IDS[@]}"; do
  _leak_catalog "$_c"
  assert_eq "$_LKC_SEV" "$(_rule_field "$_c" severity)" "severity agrees for $_c"
  assert_eq "$_LKC_CONF" "$(_rule_field "$_c" confidence)" "confidence agrees for $_c"
  assert_eq "$_LKC_CWE" "$(_rule_field "$_c" cwe)" "cwe agrees for $_c"
  assert_eq "$_LKC_OWASP" "$(_rule_field "$_c" owasp)" "owasp agrees for $_c"
  assert_eq "$_LKC_TITLE" "$(_rule_field "$_c" title)" "title agrees for $_c"
  assert_eq 'passive/leakage.sh' "$(_rule_field "$_c" script)" "$_c names this phase script"
  assert_eq 'target' "$(_rule_field "$_c" coverage-scope)" "$_c uses DAST's own coverage cell"
done
assert_eq info "$(_rule_field DAST-LEAK-THIRD_PARTY_ORIGIN-01 severity)" \
  'the registry ALSO records the third-party family as informational, so the two copies cannot drift on this ticket own acceptance criterion'

t_case 'peer-blocks-intact'
# This case originally read the ONE shared modules/dast/passive/checks.rules and
# asserted the peers' records were still in it, turning "take both sides of the
# merge conflict" from an instruction into a checked property.  That registry is
# now split one file per owning phase script (rules/RULE-FORMAT.md §9's
# `checks-<name>.rules` row), so there is no shared file to append to and no
# merge conflict to resolve - the hazard this case was written against is gone.
#
# The GUARANTEE it was really buying is not, so the case is re-aimed rather than
# deleted: the peers' checks must still be discoverable, which after the split is
# a property of the DIRECTORY and no longer of any single file.  It is asserted
# over every record file in the directory, discovered by the same `*.rules` glob
# shape checks_registry_load itself uses, so it holds however the directory is
# arranged and would have passed unchanged both before the split and after it.
# Reading a fixed filename is what made the original brittle; this reads none.
# (The glob rather than checks_registry_load itself: this suite does not source
# lib/checks.sh, and adding that edge would grow what `shellcheck -x` inlines
# here for no gain the glob does not already give.)
_LEAK_PEER_REG=''
for _s in "$ROOT"/modules/dast/passive/*.rules; do
  [[ -f $_s ]] || continue
  while IFS= read -r _line; do
    [[ $_line == 'id: '* ]] && _LEAK_PEER_REG+="${_line#id: } "
  done <"$_s"
done
# Non-empty first: every assertion below is a substring test, so a registry that
# failed to load would make them all fail for a reason none of them names.
assert_ne '' "$_LEAK_PEER_REG" 'the passive registry directory yielded records at all'
for _c in DAST-COOKIE-NO_SECURE-01 DAST-COOKIE-NO_HTTPONLY-01 \
  DAST-HDR-CSP_MISSING-01 DAST-HDR-HSTS_MISSING-01 DAST-HDR-RECOMMENDED_MISSING-01; do
  assert_contains "$_LEAK_PEER_REG" "$_c" \
    "the peer record $_c is still discoverable after the per-owner split - fails if a split dropped a peer's file, which no single-file read would notice"
done
# And this ticket's own records are in the same registry, from their own file -
# without this the case above is satisfied by a registry that loaded every file
# EXCEPT checks-leakage.rules.
assert_contains "$_LEAK_PEER_REG" 'DAST-LEAK-STACK_TRACE-01' \
  "this phase's own records load from checks-leakage.rules alongside the peers"

# ===========================================================================
printf '\n== dast-leakage: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
