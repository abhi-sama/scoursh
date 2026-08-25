#!/usr/bin/env bash
# tests/suites/dast-cookies.sh - modules/dast/passive/cookies.sh and its parser
# modules/dast/passive/cookie_engine.sh: `Secure`, `HttpOnly` and `SameSite` per
# cookie (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-06, tier 2).
#
# NOTHING HERE TOUCHES THE NETWORK. Every response is RECORDED: the whole suite
# runs against a stubbed SCOURSH_HTTP_TRANSPORT that writes canned headers into
# the capture file lib/http.sh hands it, with SCOURSH_HTTP_RESOLVE stubbed too
# (docs/DESIGN.md §12: "DAST logic is testable with no live target"). It runs on
# a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing. The five parsing hazards this ticket exists to
# get right each have a case whose rejected reading is a real, shipped bug:
#
#   1. A comma inside `Expires` must not split the header. Under the generic
#      RFC 7230 "comma separates list members" reading - which is right for
#      `Accept` and wrong for `Set-Cookie` - a perfectly-flagged cookie loses its
#      attributes and a phantom second cookie appears out of the date.
#   2. A `;` inside a quoted cookie-value must not split the header. The rejected
#      reading here is not merely lossy: a value of `"light; Secure; dark"` makes
#      a naive splitter see a `Secure` attribute the server never sent, so a
#      cookie that IS missing `Secure` is reported as having it - a false
#      negative on the finding, which is the direction that reads as a pass.
#   3. Attribute names are case-insensitive and unordered.
#   4. `Secure`/`HttpOnly` are set by PRESENCE, so `HttpOnly=false` is HttpOnly.
#   5. `SameSite` ABSENT and `SameSite` EXPLICITLY WEAK are two check ids, and
#      an unrecognised value is neither folded into `absent` nor dropped.
#
# It also pins the things that make the phase a phase rather than a parser: it
# never sends a non-GET request (docs/DESIGN.md §7.1 "No mutation of state"), it
# reads the endpoint inventory rather than crawling, every request goes through
# `http_request`, and every way of covering nothing is a recorded gap rather than
# a clean-looking result.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes cookie-attribute syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/core.sh (scratch dir, traps, the pattern
# engine binding scan_match needs) via lib/findings.sh.
# -x back-edge cut: modules/dast/passive/cookie_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookie_engine.sh"
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

# This suite DOES source modules/dast/engine.sh above, so `dast_check_selected`
# is real here and the cookies phase will consult it.  Clear the list explicitly
# rather than relying on the caller's environment: every case below asserts on
# what the phase inspects, and an inherited SCOURSH_SELECTED_CHECKS would filter
# checks out from under them.  Unset means "all selected" (modules/dast/
# engine.sh section 3a), which is what these cases assume.
unset SCOURSH_SELECTED_CHECKS

W=$SCOURSH_SCRATCH/dast-cookies-workspace
rm -rf "$W"; mkdir -p "$W"

# ===========================================================================
printf '== A. the parser: cookie_engine.sh in isolation ==\n'
# ===========================================================================
# Every case here is a pure function call. No run directory, no transport, no
# finding - just the grammar.

# --- hazard 1: the comma in Expires ---------------------------------------
t_case 'an Expires date comma does not split the header'
cookie_parse 'sid=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/; Secure; HttpOnly; SameSite=Lax'
assert_eq 'sid' "$_COOKIE_NAME" \
  'the cookie name is read from the pair before the first `;`, not from a comma-separated field'
assert_eq 1 "$_COOKIE_SECURE" \
  'Secure is still found AFTER an Expires date containing a comma - FAILS under the generic RFC 7230 "a comma separates list members" reading, which is correct for Accept and specifically wrong for Set-Cookie (RFC 6265 §3), and which drops every attribute after the date'
assert_eq 1 "$_COOKIE_HTTPONLY" \
  'HttpOnly is still found after the comma-bearing Expires - same rejected reading'
assert_eq 'lax' "$_COOKIE_SAMESITE_STATE" \
  'SameSite is still found after the comma-bearing Expires - same rejected reading'
assert_eq '/' "$_COOKIE_PATH" 'Path is read from its own attribute'

t_case 'a comma in the cookie VALUE does not split it either'
cookie_parse 'list=a,b,c; Secure; HttpOnly; SameSite=Strict'
assert_eq 'list' "$_COOKIE_NAME" 'a comma-bearing cookie value is one cookie'
assert_eq 'strict' "$_COOKIE_SAMESITE_STATE" \
  'attributes after a comma-bearing value are still read - FAILS under comma splitting'

# --- hazard 2: the quoted semicolon ----------------------------------------
t_case 'a `;` inside a quoted cookie-value does not split the header'
cookie_parse 'pref="light; Secure; dark"; HttpOnly'
assert_eq 'pref' "$_COOKIE_NAME" 'the name is still `pref`'
assert_eq 0 "$_COOKIE_SECURE" \
  'the word Secure INSIDE the quoted value is not an attribute - FAILS under a naive `;` split, which manufactures a Secure attribute the server never sent and so reports a cookie that IS missing Secure as having it: a false negative, the direction that reads as a pass'
assert_eq 1 "$_COOKIE_HTTPONLY" \
  'the real HttpOnly attribute after the closing quote IS found'

t_case 'a quoted value with an inner `;` keeps the attributes that follow it'
cookie_parse 'q="a; b"; Secure; SameSite=None'
assert_eq 1 "$_COOKIE_SECURE" 'Secure after a quoted inner `;` is found'
assert_eq 'none' "$_COOKIE_SAMESITE_STATE" 'SameSite after a quoted inner `;` is found'

# --- hazard 3: case and order ----------------------------------------------
t_case 'attribute names are case-insensitive and order-independent'
cookie_parse 'a=1; SameSite=Strict; Secure; HttpOnly'
A_SEC=$_COOKIE_SECURE; A_HO=$_COOKIE_HTTPONLY; A_SS=$_COOKIE_SAMESITE_STATE
cookie_parse 'a=1; HTTPONLY; secure; samesite=STRICT'
assert_eq "$A_SEC" "$_COOKIE_SECURE" \
  'lowercase `secure` sets the same flag as `Secure` - FAILS under case-sensitive attribute matching (RFC 6265 §5.2 matches case-insensitively)'
assert_eq "$A_HO" "$_COOKIE_HTTPONLY" \
  'uppercase `HTTPONLY` sets the same flag as `HttpOnly` - same rejected reading'
assert_eq "$A_SS" "$_COOKIE_SAMESITE_STATE" \
  'a reordered, recased attribute list analyses identically - FAILS under any positional assumption about where SameSite sits'

# --- hazard 4: presence, not value -----------------------------------------
t_case 'Secure and HttpOnly are set by PRESENCE, not by their value'
cookie_parse 'a=1; HttpOnly=false; Secure=0'
assert_eq 1 "$_COOKIE_HTTPONLY" \
  '`HttpOnly=false` is an HttpOnly cookie in every browser (RFC 6265 §5.2.5 discards the attribute-value) - FAILS under reading the value, which reports a flag as missing on a cookie that has it'
assert_eq 1 "$_COOKIE_SECURE" \
  '`Secure=0` is a Secure cookie (RFC 6265 §5.2.5) - same rejected reading'

# --- hazard 5: the SameSite state machine ----------------------------------
t_case 'SameSite: absent, strict, lax, none, unrecognised are five distinct states'
cookie_parse 'a=1'
assert_eq 'absent' "$_COOKIE_SAMESITE_STATE" 'no SameSite attribute at all is `absent`'
assert_eq '' "$_COOKIE_SAMESITE_RAW" 'and it carries no raw value'
cookie_parse 'a=1; SameSite=Lax'
assert_eq 'lax' "$_COOKIE_SAMESITE_STATE" '`Lax` is recognised'
cookie_parse 'a=1; SameSite=None'
assert_eq 'none' "$_COOKIE_SAMESITE_STATE" '`None` is recognised'
cookie_parse 'a=1; SameSite=Bogus'
assert_eq 'unrecognised' "$_COOKIE_SAMESITE_STATE" \
  'a value no browser knows is `unrecognised` and NOT `absent` - FAILS under folding an unparseable value into the absent case, which would tell the operator the server stated no policy when it stated an unusable one, and so recommend the wrong fix'
assert_eq 'Bogus' "$_COOKIE_SAMESITE_RAW" \
  'and the raw value is kept verbatim so the finding can quote what the server actually sent'
cookie_parse 'a=1; SameSite='
assert_eq 'unrecognised' "$_COOKIE_SAMESITE_STATE" \
  'an EMPTY SameSite= is `unrecognised`, not `absent` - the attribute was sent'
cookie_parse 'a=1; SameSite="Strict"'
assert_eq 'strict' "$_COOKIE_SAMESITE_STATE" \
  'a quoted SameSite value is unquoted before comparison - FAILS under a literal comparison, which reports a correctly-configured cookie as weak'

# --- malformed and edge shapes ---------------------------------------------
t_case 'a header that sets no cookie is rejected rather than reported nameless'
if cookie_parse 'deleted; Secure'; then
  _t_no 'no-pair Set-Cookie' 'a value with no `name=value` pair must return 1'
else
  _t_ok 'a Set-Cookie whose first part has no `=` returns 1 (no browser stores it), rather than emitting a finding about a nameless cookie'
fi
assert_eq '' "$_COOKIE_NAME" 'and leaves the name empty'

t_case 'a first part that happens to be spelled like an attribute IS the cookie'
# `Set-Cookie: Path=/; Secure` really does set a cookie NAMED `Path` in every
# browser - RFC 6265 §5.2 only starts reading attributes AFTER the cookie-pair.
# Pinned so a later "helpfully" skip-known-attribute-names change is caught:
# that reading silently drops a real, oddly-named cookie from the report.
cookie_parse 'Path=/; Secure'
assert_eq 'Path' "$_COOKIE_NAME" \
  'the first part is always the cookie-pair, whatever it is named - FAILS under treating a known attribute name in first position as an attribute, which drops a real cookie'
assert_eq 1 "$_COOKIE_SECURE" 'and the trailing Secure is still an attribute'

t_case 'a colon inside the cookie value survives extraction'
cookie_parse 't=a:b:c; Secure'
assert_eq 't' "$_COOKIE_NAME" 'the name is `t`'

t_case 'empty attribute segments are dropped, not counted'
cookie_split_attrs 'a=1;; Secure'
assert_eq 2 "${#_COOKIE_ATTRS[@]}" \
  '`a=1;; Secure` is two attributes - FAILS under a bare IFS split, which yields an empty third part that is then analysed as an attribute'

t_case 'the session-name hint recognises conventional names and does not gate anything'
# `if/then/else`, not `A && _t_ok ... || _t_no ...` (SC2015): in the `&&`/`||`
# spelling `_t_no` also runs whenever `_t_ok` itself exits non-zero, so a
# passing case could record a failure as well as a pass.  The negative case
# below already had this shape; all three now match.
if cookie_looks_session JSESSIONID; then _t_ok 'JSESSIONID reads as a session cookie name'; else _t_no 'session hint' 'JSESSIONID should match'; fi
if cookie_looks_session csrftoken; then _t_ok 'csrftoken reads as a session-class cookie name'; else _t_no 'session hint' 'csrftoken should match'; fi
if cookie_looks_session theme; then _t_no 'session hint' '`theme` must not match'; else
  _t_ok '`theme` does not read as a session cookie name'; fi

# ===========================================================================
printf '== B. extraction from a raw capture file ==\n'
# ===========================================================================
HDR=$W/headers.txt

t_case 'multiple Set-Cookie headers, across redirect hops, are separate cookies'
# lib/http.sh's header capture ACCUMULATES every hop, so this is exactly the
# shape a 302 login produces: the session cookie is set on the hop that
# redirects, not on the one that finally answers 200.
cat >"$HDR" <<'EOF'
HTTP/1.1 302 Found
Location: /home
Set-Cookie: sid=abc; Path=/
Set-Cookie: csrf=zzz; Path=/; Secure

HTTP/1.1 200 OK
Content-Type: text/html
set-cookie: theme=dark; Max-Age=100
EOF
mapfile -t EXTRACTED < <(cookie_extract_set_cookie "$HDR")
assert_eq 3 "${#EXTRACTED[@]}" \
  'all three Set-Cookie headers are extracted, including the two on the redirect hop and the lowercase one - FAILS under reading only the final hop, which is where a 302 login sets nothing'
assert_contains "${EXTRACTED[0]}" 'sid=abc' 'the first hop cookie is first'
assert_contains "${EXTRACTED[2]}" 'theme=dark' 'a lowercase `set-cookie:` is matched too'
assert_not_contains "${EXTRACTED[0]}" 'Set-Cookie' \
  'the header NAME is stripped, leaving only the value'

t_case 'a response that sets no cookie returns 1 and does not abort the run'
cat >"$HDR" <<'EOF'
HTTP/1.1 200 OK
Content-Type: text/html
EOF
if cookie_extract_set_cookie "$HDR" >/dev/null; then
  _t_no 'no-cookie response' 'must return 1 when there is no Set-Cookie'
else
  _t_ok 'no Set-Cookie returns 1 - the ORDINARY case, and it must not take the run down under `set -Eeuo pipefail` (docs/FOUNDATION.md tension 4 rule 2: grep exits 1 on no-match)'
fi

t_case 'a comma-bearing header is ONE Set-Cookie value, never two'
# THIS is the layer the comma hazard actually lives at. Splitting a Set-Cookie
# header on `,` is the generic RFC 7230 list rule, it is what a folded-header
# reader does, and RFC 6265 §3 forbids it for exactly the reason visible here:
# the comma is INSIDE one attribute.
cat >"$HDR" <<'XEOF'
HTTP/1.1 200 OK
Set-Cookie: sid=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Secure; HttpOnly; SameSite=Lax
XEOF
mapfile -t EXTRACTED < <(cookie_extract_set_cookie "$HDR")
assert_eq 1 "${#EXTRACTED[@]}" \
  'one header line is one cookie - FAILS under splitting the header on `,`, which turns a single correctly-flagged cookie into two and invents a phantom cookie out of the expiry date'
assert_contains "${EXTRACTED[0]}" 'SameSite=Lax' \
  'and the attributes AFTER the comma stay attached to it - FAILS under the same reading, which strands them on the phantom'
cookie_parse "${EXTRACTED[0]}"
assert_eq 'sid' "$_COOKIE_NAME" 'the one cookie is `sid`'

t_case 'two comma-bearing headers are two cookies, one each'
cat >"$HDR" <<'XEOF'
HTTP/1.1 200 OK
Set-Cookie: a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT
Set-Cookie: b=2; Expires=Fri, 02 Jan 1970 00:00:00 GMT
XEOF
mapfile -t EXTRACTED < <(cookie_extract_set_cookie "$HDR")
assert_eq 2 "${#EXTRACTED[@]}" \
  'two header lines are exactly two cookies - FAILS under comma splitting, which reports four'
NAMES_SEEN=''
for v in "${EXTRACTED[@]}"; do cookie_parse "$v" && NAMES_SEEN+="$_COOKIE_NAME "; done
assert_eq 'a b ' "$NAMES_SEEN" \
  'and their names are `a` and `b`. (This assertion is a guard, not the comma pin: a date fragment carries no `=` so cookie_parse already rejects it - the COUNT above is what catches the split, and it does, measured.)'

t_case 'a Set-Cookie with a colon in its value is not truncated at the colon'
cat >"$HDR" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: t=12:34:56; Secure
EOF
mapfile -t EXTRACTED < <(cookie_extract_set_cookie "$HDR")
assert_eq 't=12:34:56; Secure' "${EXTRACTED[0]}" \
  'only the FIRST colon (the header separator) is stripped - FAILS under a greedy `##*:`, which eats the value up to its last colon and loses the attributes with it'

t_case 'a Set-Cookie with no cookie-pair is not extracted at all'
cat >"$HDR" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: ; Path=/
Set-Cookie: real=1
EOF
mapfile -t EXTRACTED < <(cookie_extract_set_cookie "$HDR")
assert_eq 1 "${#EXTRACTED[@]}" 'only the header that actually sets a cookie is extracted'

t_case 'an unreadable capture file returns 1 rather than erroring'
if cookie_extract_set_cookie "$W/does-not-exist"; then
  _t_no 'absent capture' 'must return 1'
else
  _t_ok 'an absent capture file returns 1 (a transport failure leaves nothing to read), never a hard error'
fi

# ===========================================================================
printf '== C. the phase, against recorded responses ==\n'
# ===========================================================================
# Scope, resolver and scanner limits, exactly as tests/suites/dast-sqli.sh sets
# them: a rate high enough that the DAST-32 ceiling never real-sleeps, and the
# affirmation the ceiling reads.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: cookie-fixture
base-url: https://cookies.fixture.example/
notes: Fixture target for tests/suites/dast-cookies.sh. Never dialled: both the
  resolver and the transport are stubbed.
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

_ck_resolve() { case $1 in cookies.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_ck_resolve

# The mock target. One endpoint per cookie shape; the recorded response headers
# are written into the capture file lib/http.sh passes as _HTTP_TX_HEADERS_OUT,
# which is the same file the phase then reads - so the phase is exercised through
# the real capture path, not through a hand-fed string.
REQ_LOG=$W/requests.log
# The REQUEST headers lib/http.sh was about to send, one `METHOD PATH<TAB>NAME:
# VALUE` line each. They are logged separately from REQ_LOG so a request-count
# assertion is never perturbed by a header, and they are read from
# `_HTTP_TX_HEADERS` - section 9a's own outbound context, the array the real
# curl config is built from - rather than from anything the phase told the test,
# so "the credential was attached" is asserted at the transport boundary. That
# distinction is the whole point of section E below: the defect it pins left the
# phase reporting `authenticated_pass=1` while the wire carried nothing.
REQ_HDR_LOG=$W/request-headers.log
_req_reset() { : >"$REQ_LOG"; : >"$REQ_HDR_LOG"; }

_ck_transport() {
  local method=$1 path=$5
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  local _h
  for _h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    printf '%s %s\t%s\n' "$method" "$path" "$_h" >>"$REQ_HDR_LOG"
  done
  local -a sc=()
  case $path in
    /)         sc=('sid=abc; Path=/') ;;
    /good)     sc=('ok=1; Path=/; Secure; HttpOnly; SameSite=Lax') ;;
    /none)     sc=('x=1; Path=/; Secure; HttpOnly; SameSite=None') ;;
    /nonebare) sc=('y=1; Path=/; HttpOnly; SameSite=None') ;;
    /weird)    sc=('w=1; Path=/; Secure; HttpOnly; SameSite=Wat') ;;
    /expires)  sc=('e=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/; Secure; HttpOnly; SameSite=Strict') ;;
    /quoted)   sc=('pref="light; Secure; dark"; Path=/; HttpOnly; SameSite=Lax') ;;
    /multi)    sc=('m1=1; Path=/; Secure; HttpOnly; SameSite=Lax' 'm2=2; Path=/') ;;
    /dup)      sc=('sid=abc; Path=/') ;;
    /bare)     sc=() ;;
    /fail)     return 1 ;;
  esac
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    { printf 'HTTP/1.1 200 OK\n'
      printf 'Content-Type: text/html\n'
      local c
      for c in "${sc[@]+"${sc[@]}"}"; do printf 'Set-Cookie: %s\n' "$c"; done
      printf '\n'
    } >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '200\n\ntext/html\n'
}
SCOURSH_HTTP_TRANSPORT=_ck_transport

_write_inventory() {
  cat >"$1"
}

FULL_INV=$W/endpoints.json
cat >"$FULL_INV" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_root",    "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/",         "path": "/" },
  { "id": "ep_good",    "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/good",     "path": "/good" },
  { "id": "ep_none",    "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/none",     "path": "/none" },
  { "id": "ep_nonebar", "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/nonebare", "path": "/nonebare" },
  { "id": "ep_weird",   "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/weird",    "path": "/weird" },
  { "id": "ep_expires", "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/expires",  "path": "/expires" },
  { "id": "ep_quoted",  "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/quoted",   "path": "/quoted" },
  { "id": "ep_multi",   "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/multi",    "path": "/multi" },
  { "id": "ep_dup",     "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/dup",      "path": "/dup" },
  { "id": "ep_bare",    "target": "cookie-fixture", "method": "GET",  "url": "https://cookies.fixture.example/bare",     "path": "/bare" },
  { "id": "ep_login",   "target": "cookie-fixture", "method": "POST", "url": "https://cookies.fixture.example/login",    "path": "/login" }
] }
EOF

_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target cookie-fixture
  occurrence_reset_all
  _req_reset
  # Quoted, because `cookie-fixture` unquoted reads as the arithmetic
  # expression `cookie - fixture` and shellcheck says so (SC2100).  The quotes
  # are the fix rather than a suppression: they state that this is a literal
  # string, which is what every other target/cell value in this tree is.
  SCOURSH_DAST_TARGET='cookie-fixture'
  SCOURSH_DAST_CELL='cookie-fixture'
  SCOURSH_DAST_AUTHED=false
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
}

# `_count CHECK NAME` - findings whose check_id AND loc_param_name both match
# exactly. The shard `.fields` format is one finding per line, TAB-delimited
# `key=value` (lib/findings.sh's `_finding_fields`).
_count() {
  local check=$1 name=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      local okc=0 okn=0
      while IFS= read -r fld; do
        [[ $fld == "check_id=$check" ]] && okc=1
        [[ $fld == "loc_param_name=$name" ]] && okn=1
      done < <(printf '%s' "$line" | tr '\t' '\n')
      (( okc && okn )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# Every cookie name that appears in any finding this run, sorted and deduped -
# used to prove that no PHANTOM cookie was invented out of a date or a quoted
# value.
_names() {
  local f line fld out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      while IFS= read -r fld; do
        [[ $fld == loc_param_name=* ]] && out+="${fld#loc_param_name=}"$'\n'
      done < <(printf '%s' "$line" | tr '\t' '\n')
    done <"$f"
  done
  printf '%s' "$out" | LC_ALL=C sort -u | tr '\n' ' '
}

_meta_text() { run_facts "$1" 2>/dev/null || true; }

# --- the main pass ---------------------------------------------------------
_new_run main
SCOURSH_DAST_COOKIE_ENDPOINTS=$FULL_INV
export SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"

t_case 'a cookie with no attributes at all yields all three findings'
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 sid)" 'sid is reported missing Secure'
assert_eq 1 "$(_count DAST-COOKIE-NO_HTTPONLY-01 sid)" 'sid is reported missing HttpOnly'
assert_eq 1 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 sid)" 'sid is reported with SameSite absent'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_WEAK-01 sid)" \
  'and NOT also as explicitly weak - FAILS under one SameSite check id, which cannot tell the two states apart'

t_case 'a fully-flagged cookie yields nothing'
assert_eq 0 "$(_count DAST-COOKIE-NO_SECURE-01 ok)" 'ok=1; Secure; HttpOnly; SameSite=Lax is clean on Secure'
assert_eq 0 "$(_count DAST-COOKIE-NO_HTTPONLY-01 ok)" 'clean on HttpOnly'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 ok)" 'clean on SameSite absent'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_WEAK-01 ok)" 'clean on SameSite weak'

t_case 'an explicit SameSite=None is WEAK, never ABSENT'
assert_eq 1 "$(_count DAST-COOKIE-SAMESITE_WEAK-01 x)" 'SameSite=None is reported weak'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 x)" \
  'and NOT as absent - FAILS under collapsing the two states into one check, which would tell the operator the server stated no policy when it deliberately stated the permissive one'

t_case 'an unrecognised SameSite value is WEAK, and quotes the value it saw'
assert_eq 1 "$(_count DAST-COOKIE-SAMESITE_WEAK-01 w)" 'SameSite=Wat is reported weak'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 w)" \
  'and NOT as absent - FAILS under folding an unparseable value into the absent case'
assert_contains "$(cat "$SCOURSH_RUN_DIR"/shards/*.fields)" 'SameSite=Wat' \
  'the finding quotes the exact value the server sent, so the operator can fix the typo'

t_case 'SameSite=None with no Secure is called out as a functional defect too'
assert_eq 1 "$(_count DAST-COOKIE-SAMESITE_WEAK-01 y)" 'the weak finding fires'
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 y)" 'and the missing Secure fires independently'
assert_contains "$(cat "$SCOURSH_RUN_DIR"/shards/*.fields)" 'browsers reject outright' \
  'and the evidence says the browser DROPS a None cookie without Secure, which is a different consequence from "unprotected"'

t_case 'end to end: an Expires comma does not cost the cookie its attributes'
assert_eq 0 "$(_count DAST-COOKIE-NO_SECURE-01 e)" \
  'the fully-flagged cookie whose Expires carries a comma is clean - FAILS under comma splitting, which loses every attribute after the date and reports three findings on a correctly-configured cookie'
assert_eq 0 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 e)" 'and clean on SameSite'

t_case 'end to end: no phantom cookie is invented from a date or a quoted value'
NAMES=$(_names)
assert_not_contains "$NAMES" '09 Jun 2021 10' \
  'no finding names a cookie made out of the Expires date. (A guard against a parser that invents a name from a valueless fragment; the comma split itself is pinned by the extraction-count case above and by the two clean-cookie assertions here, both measured failing under it.)'
assert_not_contains "$NAMES" 'Expires' 'no finding names a cookie called Expires'
assert_not_contains "$NAMES" 'dark' 'no finding names a cookie made out of a quoted value'

t_case 'end to end: a quoted `Secure` inside a value is not read as the attribute'
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 pref)" \
  'pref="light; Secure; dark" IS reported missing Secure - FAILS under a naive `;` split, which sees the quoted word as the attribute and silently passes a vulnerable cookie'

t_case 'two cookies in one response are two cookies'
assert_eq 0 "$(_count DAST-COOKIE-NO_SECURE-01 m1)" 'the flagged one is clean'
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 m2)" 'the unflagged one is reported'
assert_eq 1 "$(_count DAST-COOKIE-SAMESITE_ABSENT-01 m2)" 'and on SameSite too'

t_case 'the same cookie set on two paths is ONE finding per issue, not two'
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 sid)" \
  '`sid` is set identically at / and at /dup and is reported once - FAILS under fingerprint-only dedup, which carries path_template and would report one cookie issued once as one finding per page that serves it'

t_case 'a passive check never sends a non-GET request'
assert_not_contains "$(cat "$REQ_LOG")" '/login' \
  'the POST endpoint in the inventory is NOT dialled - FAILS under "request every endpoint the crawler found", which is a state change and is docs/DESIGN.md §7.1'"'"'s "No mutation of state"'
assert_not_contains "$(cat "$REQ_LOG")" 'POST ' 'no POST is sent at all'
assert_contains "$(cat "$REQ_LOG")" 'GET /good' 'GET endpoints ARE dialled'

t_case 'the non-GET omission is DECLARED, not silent'
assert_contains "$(_meta_text coverage_reduction)" 'cookies_non_get_endpoints_not_dialled' \
  'a reader is told the login POST was skipped - FAILS under skipping it silently, which lets this check'"'"'s silence read as "the session cookie is fine"'

t_case 'the checks that ran are recorded as run'
CR=$(_meta_text checks_run)
assert_contains "$CR" 'DAST-COOKIE-NO_SECURE-01' 'NO_SECURE is in checks_run'
assert_contains "$CR" 'DAST-COOKIE-SAMESITE_WEAK-01' 'SAMESITE_WEAK is in checks_run'

t_case 'an unauthenticated-only pass says so'
assert_contains "$(_meta_text coverage_reduction)" 'cookies_unauthenticated_only' \
  'the run states that no authenticated response was inspected - FAILS under staying quiet, which lets a run that never saw a session cookie read as one that found nothing wrong with it'

t_case 'the findings carry CWE, OWASP and remediation'
SH=$(cat "$SCOURSH_RUN_DIR"/shards/*.fields)
assert_contains "$SH" 'cwe=CWE-614' 'missing Secure is CWE-614'
assert_contains "$SH" 'cwe=CWE-1004' 'missing HttpOnly is CWE-1004'
assert_contains "$SH" 'cwe=CWE-1275' 'the SameSite checks are CWE-1275'
assert_contains "$SH" 'owasp=A05:2021' 'the flag checks map to A05'
assert_contains "$SH" 'owasp=A01:2021' 'the SameSite checks map to A01'
assert_contains "$SH" 'loc_param_location=cookie' \
  'the location is the frozen `cookie` value from docs/INVENTORY-FORMAT.md §3, not a new vocabulary'
assert_contains "$SH" 'remediation=' 'every finding carries remediation text'

t_case 'a response that sets no cookie is neither a finding nor an error'
assert_eq 0 "$(_count DAST-COOKIE-NO_SECURE-01 '')" 'no nameless finding is emitted'
assert_contains "$(cat "$REQ_LOG")" 'GET /bare' 'the cookie-less endpoint was still requested'

# --- degradation: no inventory ---------------------------------------------
t_case 'no endpoint inventory is a recorded gap, not a clean result and not an error'
_new_run noinv
SCOURSH_DAST_COOKIE_ENDPOINTS=$W/absent-inventory.json
export SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
assert_contains "$(_meta_text coverage_gap)" 'no known endpoint' \
  'the report says nothing was tested - FAILS under returning quietly, which produces a report with no cookie findings and no reason'
assert_contains "$(_meta_text coverage_reduction)" 'no_endpoint_inventory' 'and records the machine-readable reason'
assert_eq '' "$(cat "$REQ_LOG")" 'and sends no request at all'
CR=$(_meta_text checks_run)
assert_not_contains "$CR" 'DAST-COOKIE-NO_SECURE-01' \
  'and does NOT record the check as run - FAILS under recording coverage for a check that inspected nothing, which is what makes a gap invisible in tension 12'"'"'s (check, cell) coverage'

# --- degradation: the cap ---------------------------------------------------
t_case 'the per-phase endpoint cap is a recorded coverage bound'
_new_run cap
SCOURSH_DAST_COOKIE_ENDPOINTS=$FULL_INV
SCOURSH_DAST_COOKIE_MAX_ENDPOINTS=2
export SCOURSH_DAST_COOKIE_ENDPOINTS SCOURSH_DAST_COOKIE_MAX_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
_reqcount() { local n=0 l; while IFS= read -r l; do [[ -n $l ]] && n=$(( n + 1 )); done <"$REQ_LOG"; printf '%s' "$n"; }
assert_eq 2 "$(_reqcount)" 'exactly the cap is requested'
assert_contains "$(_meta_text coverage_gap)" 'exceeded the per-phase cap' \
  'the truncation is stated - FAILS under silently testing a prefix of the surface and reporting the same verdict'
unset SCOURSH_DAST_COOKIE_MAX_ENDPOINTS

t_case 'the endpoint walk is deterministic under the cap'
CAP1=$(cat "$REQ_LOG")
_new_run cap2
SCOURSH_DAST_COOKIE_ENDPOINTS=$FULL_INV
SCOURSH_DAST_COOKIE_MAX_ENDPOINTS=2
export SCOURSH_DAST_COOKIE_ENDPOINTS SCOURSH_DAST_COOKIE_MAX_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
assert_eq "$CAP1" "$(cat "$REQ_LOG")" \
  'two runs over the identical surface request the identical endpoints - FAILS under iterating the endpoint map in bash associative-array (hash) order, which makes WHICH endpoints a capped run inspects unpredictable and the output non-reproducible'
unset SCOURSH_DAST_COOKIE_MAX_ENDPOINTS

# --- degradation: only non-GET endpoints ------------------------------------
t_case 'a surface with only non-GET endpoints is a gap, not silence'
POST_ONLY=$W/post-only.json
cat >"$POST_ONLY" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_login", "target": "cookie-fixture", "method": "POST", "url": "https://cookies.fixture.example/login", "path": "/login" }
] }
EOF
_new_run postonly
SCOURSH_DAST_COOKIE_ENDPOINTS=$POST_ONLY
export SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
assert_eq '' "$(cat "$REQ_LOG")" 'no request is sent'
assert_contains "$(_meta_text coverage_reduction)" 'cookies_no_get_endpoint' 'and the reason is recorded'
assert_contains "$(_meta_text coverage_gap)" 'coverage gap' 'and a human-readable gap is written'

# --- degradation: a transport failure ---------------------------------------
t_case 'a failing endpoint is recorded and does not stop the rest'
FAILINV=$W/fail.json
cat >"$FAILINV" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_fail", "target": "cookie-fixture", "method": "GET", "url": "https://cookies.fixture.example/fail", "path": "/fail" },
  { "id": "ep_root", "target": "cookie-fixture", "method": "GET", "url": "https://cookies.fixture.example/",     "path": "/" }
] }
EOF
_new_run failcase
SCOURSH_DAST_COOKIE_ENDPOINTS=$FAILINV
export SCOURSH_DAST_COOKIE_ENDPOINTS
# shellcheck source=modules/dast/passive/cookies.sh
source "$ROOT/modules/dast/passive/cookies.sh"
assert_eq 1 "$(_count DAST-COOKIE-NO_SECURE-01 sid)" \
  'the endpoint after the failing one is still inspected - FAILS under aborting the phase on the first transport failure'
assert_contains "$(_meta_text coverage_reduction)" 'cookies_request_failed' 'and the failure is recorded'

# ===========================================================================
printf '== E. the authenticated pass actually carries the credential ==\n'
# ===========================================================================
# A session cookie is frequently issued ONLY on an authenticated response, so an
# authenticated pass that quietly sends nothing does not merely lose coverage -
# it reports the LOGGED-OUT cookie surface as if it were the logged-in one, and
# the run records `authenticated_pass=1` while it does so. That was the shipped
# behaviour: the branch guarded on `dast_auth_cookie_header_set`, a name that
# does not exist (the real one is `_dast_auth_cookie_header_set`, private), so
# `declare -F` was false, the branch was skipped in silence, and the whole suite
# stayed green because nothing here looked at the wire.
#
# EVERY ASSERTION BELOW READS `_HTTP_TX_HEADERS` AT THE TRANSPORT BOUNDARY,
# never a note the phase wrote about itself - a phase that believes it
# authenticated is exactly what the defect produced.
#
# A `bearer` identity is used for two reasons. It acquires with ZERO network
# (the operator already handed us the token), so this stays a recorded-response
# suite; and it is the mode a cookie-only attachment sends NOTHING for, which is
# the second defect in the same block and the majority shape for an API.
#
# -x back-edge cut: modules/dast/auth_engine.sh
# is already inlined elsewhere in this file's own source graph (every
# modules/dast/passive/cookies.sh source above reaches it), and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - this suite is the file closest
# to the shellcheck stage's ceiling, see tests/run-tests.sh and
# docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/auth_engine.sh"

AUTH_CONF=$W/auth.conf
: >"$AUTH_CONF"
chmod 600 "$AUTH_CONF"
printf 'id: cookie-fixture.op\nmode: bearer\ntoken: t0ken-c\n' >"$AUTH_CONF"

# TWO GET endpoints, deliberately. One would pass under attaching the credential
# once per phase, which is the second half of this fix: lib/http.sh consumes its
# per-request context at entry (section 9a) and resets it, so an attachment made
# above the loop rides only the first URL. Sorted under LC_ALL=C the phase walks
# /good then /none, so /none is the one that goes out anonymous under that
# reading.
AUTH_INV=$W/endpoints-auth.json
cat >"$AUTH_INV" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_good", "target": "cookie-fixture", "method": "GET", "url": "https://cookies.fixture.example/good", "path": "/good" },
  { "id": "ep_none", "target": "cookie-fixture", "method": "GET", "url": "https://cookies.fixture.example/none", "path": "/none" }
] }
EOF

t_case 'under --authed, every request this phase issues carries the session'
_new_run authed
dast_auth_load "$AUTH_CONF"
dast_auth_acquire cookie-fixture op
assert_eq authenticated "$_DAST_AUTH_STATE" \
  'the fixture identity is authenticated with no request sent, so this section stays a recorded-response test'
_req_reset
SCOURSH_DAST_AUTHED=true
SCOURSH_DAST_COOKIE_ENDPOINTS=$AUTH_INV
export SCOURSH_DAST_AUTHED SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"

HDRS=$(cat "$REQ_HDR_LOG")
assert_contains "$HDRS" 'GET /good	Authorization: Bearer t0ken-c' \
  'the first endpoint carries the identity - FAILS under the shipped reading, which guarded on `dast_auth_cookie_header_set`, a function that does not exist, so `declare -F` silently skipped the whole branch and the pass went out anonymous while still recording authenticated_pass=1; and FAILS again under attaching only a Cookie header, which sends nothing at all for a bearer identity'
assert_contains "$HDRS" 'GET /none	Authorization: Bearer t0ken-c' \
  'and so does the SECOND endpoint - FAILS under attaching the credential ONCE above the loop, since lib/http.sh consumes its per-request context at entry, so every request after the first goes out anonymous and its logged-out cookie surface is reported as the logged-in one'

t_case 'an authenticated run does NOT claim it was unauthenticated-only'
assert_contains "$(_meta_text notes)" 'authenticated_pass=1' \
  'the run records that it made an authenticated pass'
assert_not_contains "$(_meta_text coverage_reduction)" 'cookies_unauthenticated_only' \
  'and the unauthenticated-only reduction is NOT recorded - FAILS under recording it unconditionally, which would tell an operator who did authenticate that the run did not'
assert_not_contains "$(_meta_text coverage_reduction)" 'cookies_auth_not_attached' \
  'and no request is reported as having lost its credential - FAILS under a phase that counts an attach failure it did not have, which would understate a pass that really was authenticated'

t_case 'without --authed the same surface sends no credential at all'
_new_run unauthed
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_COOKIE_ENDPOINTS=$AUTH_INV
export SCOURSH_DAST_AUTHED SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
assert_not_contains "$(cat "$REQ_HDR_LOG")" 'Authorization:' \
  'a run that did not ask to authenticate sends no credential - FAILS under attaching whatever session happens to be in the store, which would put a credential on the wire the operator never asked this run to use'
assert_contains "$(_meta_text coverage_reduction)" 'cookies_unauthenticated_only' \
  'and it says so, so its cookie findings are not read as the logged-in surface'
unset SCOURSH_DAST_COOKIE_ENDPOINTS

t_case 'a session that could not be attached is recorded, and the wire really is anonymous'
# `dast_auth_apply` CAN refuse: auth_engine.sh section 8 returns 1 without
# attaching anything when the identity is no longer authenticated, which is a
# state that can change between the label scan above the loop and any one
# request inside it. The phase still issues the request, so that response is the
# logged-out surface - and a run holding an `authenticated_pass=1` note with
# nothing to contradict it is the same class of defect as the one this section
# exists for, one layer down.
#
# The refusal is produced by STUBBING `dast_auth_apply`, not by corrupting the
# session store, because `dast_auth_authenticated_labels_set` reads that same
# state: every real way of making the apply fail also empties the label list,
# and then the branch is never entered and the counter can never be reached.
_new_run authfail
_AUTH_APPLY_REAL=$(declare -f dast_auth_apply)
dast_auth_apply() { return 1; }
SCOURSH_DAST_AUTHED=true
SCOURSH_DAST_COOKIE_ENDPOINTS=$AUTH_INV
export SCOURSH_DAST_AUTHED SCOURSH_DAST_COOKIE_ENDPOINTS
# -x back-edge cut: modules/dast/passive/cookies.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/cookies.sh"
assert_not_contains "$(cat "$REQ_HDR_LOG")" 'Authorization:' \
  'no credential reached the wire, which is what makes the record below a true statement rather than defensive boilerplate'
AUTHFAIL_RED=$(_meta_text coverage_reduction)
assert_contains "$AUTHFAIL_RED" 'cookies_auth_not_attached' \
  'and the run says so - FAILS under `dast_auth_apply ... || true`, which swallows the refusal and leaves authenticated_pass=1 as the only thing the run says about a pass that in fact sent no credential'
assert_contains "$AUTHFAIL_RED" 'count=2' \
  'counted per REQUEST, not once per phase - FAILS under a flag set on the first refusal, which understates how much of the reported surface is really the logged-out one'
eval "$_AUTH_APPLY_REAL"
unset SCOURSH_DAST_COOKIE_ENDPOINTS

# ===========================================================================
printf '== D. registration ==\n'
# ===========================================================================
t_case 'the phase table reaches this script, and only at passive or above'
FOUND=0
for spec in "${_DAST_PHASES[@]}"; do
  [[ $spec == 'passive/cookies.sh:passive' ]] && FOUND=1
done
assert_eq 1 "$FOUND" \
  'modules/dast/engine.sh names passive/cookies.sh at tier passive, so scan_dispatch dast runs it'

SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'passive/cookies.sh:passive' passive cookie-fixture >/dev/null 2>&1 || true
assert_eq 1 "$_DAST_PHASE_PRESENT" \
  'dast_run_phase now finds the script on disk - FAILS while the file is absent, which is the state every DAST-0x row starts in'

t_case 'every check id this phase emits is in the registry'
SCOURSH_INSTALL_ROOT=$ROOT checks_registry_load dast DASTCK
REG=''
for s in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
  n=$(records_count "$s")
  for (( ri = 0; ri < n; ri++ )); do
    REG+=$(records_id "$s" "$ri")
    REG+=' '
  done
done
for id in DAST-COOKIE-NO_SECURE-01 DAST-COOKIE-NO_HTTPONLY-01 \
          DAST-COOKIE-SAMESITE_ABSENT-01 DAST-COOKIE-SAMESITE_WEAK-01; do
  assert_contains "$REG" "$id" \
    "$id is registered in modules/dast/passive/checks.rules - FAILS if a check is emitted with no registry record, which leaves tension 12 unable to compute coverage for it and tension 15 unable to filter it"
done

t_summary dast-cookies
