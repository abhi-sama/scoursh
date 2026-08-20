#!/usr/bin/env bash
# tests/suites/dast-headers.sh - modules/dast/passive/headers.sh and
# modules/dast/passive/headers_engine.sh: the §7.1 security-header family
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-05, tier 2).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and the whole suite is driven
# from RECORDED RESPONSES - a table of header blocks this file writes, replayed
# into lib/http.sh's own capture sink exactly as curl would write them
# (docs/DESIGN.md §12: "DAST logic is testable with no live target", §7.1: "one
# file per family so each is independently testable against a recorded
# response").  It runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.  The readings pinned here:
#
#   1. only the FINAL hop's headers count.  The capture sink accumulates every
#      hop, so a redirect that sets HSTS and lands on a page that does not must
#      still be reported as missing HSTS.
#   2. `unsafe-inline` beside a nonce or hash is IGNORED by browsers, so it is
#      not a finding; beside neither, it is.
#   3. `default-src` is the fallback for an absent `script-src`.
#   4. `data:` in `img-src` is not flagged; in `script-src` it is.
#   5. `frame-ancestors *` is NOT framing protection, even though the directive
#      is present.
#   6. `Referrer-Policy` is the LAST RECOGNISED token, and an absent header is
#      not a leak - it goes to the roll-up.
#   7. HSTS is not evaluated at all on a plaintext response.
#   8. CSP-absence and framing are DOCUMENT-only; nosniff is not.
#   9. one finding per check per target, with the affected/tested count in the
#      evidence - not one finding per endpoint.
#  10. an out-of-scope inventory URL is skipped, never handed to `http_request`
#      (which would abort the whole run with exit 3).
#  11. every bound and every gap is recorded; nothing truncates silently.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes CSP and header syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# shellcheck source=modules/dast/passive/headers_engine.sh
source "$ROOT/modules/dast/passive/headers_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-headers-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
# Three targets, because three different facts need three different front doors:
#   hdr-fixture   `/` is a FULLY HARDENED response, so a per-check case sees only
#                 what its own inventory adds (the base-url is always requested).
#   hdr-bare      every path is a response with NO security header at all, which
#                 is what the "everything missing" and roll-up cases need.
#   hdr-plain     the same, over http://, for the "HSTS is not evaluated on a
#                 plaintext response" case.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: hdr-fixture
base-url: https://hdr.fixture.example/
notes: Fixture target for tests/suites/dast-headers.sh. Never dialled: both the
  resolver and the transport are stubbed.

id: hdr-bare
base-url: https://bare.fixture.example/
notes: Fixture target whose every response carries no security header at all.

id: hdr-plain
base-url: http://plain.fixture.example/
notes: Fixture target over plaintext, for the HSTS applicability case.
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

_hdr_resolve() {
  case $1 in
    hdr.fixture.example | bare.fixture.example | plain.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_hdr_resolve

# ---------------------------------------------------------------------------
# The recorded responses.
# ---------------------------------------------------------------------------
# `_resp <host> <path>` prints the RAW response head exactly as curl's `-D`
# writes it, CRLF and all, which is what lib/http.sh's capture sink holds.  The
# transport below replays it into the sink; nothing is invented at read time.
HARDENED=$'Content-Type: text/html; charset=utf-8\r\nContent-Security-Policy: default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nPermissions-Policy: geolocation=()\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Embedder-Policy: require-corp\r\nX-Permitted-Cross-Domain-Policies: none\r\n'

_resp() {
  local host=$1 path=$2
  if [[ $host != hdr.fixture.example ]]; then
    # hdr-bare and hdr-plain: an HTML response with nothing on it at all.
    printf '%s' $'Content-Type: text/html; charset=utf-8\r\nServer: fixture\r\n'
    return 0
  fi
  case $path in
    /unsafe)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /nonce)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: script-src \'self\' \'nonce-r4nd0m\' \'unsafe-inline\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /inherit)
      # No script-src at all: the unsafe source is only reachable through CSP's
      # own default-src fallback.
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\' \'unsafe-inline\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /scriptdata)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; script-src \'self\' data:; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /imgdata)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; script-src \'self\'; img-src \'self\' data:; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /wild)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; script-src \'self\' *.cdn.example; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /pathwild)
      # A wildcard in the PATH, not the domain: must NOT be flagged.
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; script-src \'self\' https://cdn.example/assets/*; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /hstsweak)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=300\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /hstsbad)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: includeSubDomains\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /xfoallow)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Frame-Options: ALLOW-FROM https://partner.example\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /faany)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors *\r\nStrict-Transport-Security: max-age=31536000\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /leaky)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: unsafe-url\r\n' ;;
    /refok)
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: unsafe-url, strict-origin-when-cross-origin\r\n' ;;
    /dualcsp)
      # TWO policies.  A browser enforces the intersection, so the permissive
      # first one is narrowed to nothing by the second.
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: script-src \'self\' \'unsafe-inline\' *\r\nContent-Security-Policy: script-src \'self\'; frame-ancestors \'none\'\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n' ;;
    /json)
      # No CSP and no framing header, and NOT a document: only nosniff applies.
      printf '%s' $'Content-Type: application/json\r\nStrict-Transport-Security: max-age=31536000\r\n' ;;
    /final)
      # The landing page of the redirect below: NO HSTS.
      printf '%s' $'Content-Type: text/html\r\nContent-Security-Policy: default-src \'self\'; frame-ancestors \'none\'\r\nX-Content-Type-Options: nosniff\r\n' ;;
    *) printf '%s' "$HARDENED" ;;
  esac
}

REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

_hdr_transport() {
  local method=$1 host=$3 path=$5
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local status=200 location='' ctype head
  if [[ $host == hdr.fixture.example && $path == /redirect ]]; then
    status=302
    location="https://hdr.fixture.example/final"
    # The redirect hop DOES carry HSTS.  The landing page does not.  A reader
    # that matched across the whole accumulated capture would find it here.
    head=$'Content-Type: text/html\r\nLocation: https://hdr.fixture.example/final\r\nStrict-Transport-Security: max-age=31536000\r\n'
  else
    head=$(_resp "$host" "$path")
  fi
  ctype=''
  case $head in
    *"Content-Type: application/json"*) ctype='application/json' ;;
    *"Content-Type: text/html"*) ctype='text/html' ;;
  esac
  printf '%s %s %s\n' "$method" "$host" "$path" >>"$REQ_LOG"
  if [[ -n $hdrsout ]]; then
    printf 'HTTP/1.1 %s OK\r\n%s\r\n' "$status" "$head" >>"$hdrsout"
  fi
  printf '%s\n%s\n%s\n' "$status" "$location" "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_hdr_transport

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target "${2:-hdr-fixture}"
  occurrence_reset_all
  _req_reset
}

# `_inv NAME URL...` writes an endpoints.json naming each URL, and prints its
# path.  The shape is docs/INVENTORY-FORMAT.md's, written the way a conformant
# producer other than crawl.sh might - so the reader is exercised through the
# frozen flattener rather than against crawl.sh's exact bytes.
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

# The value of one field of the (single) finding for a check id.
_field_of() {
  local check=$1 want=$2 f line fld hit='' out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      hit='' out=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hit=1
        [[ $fld == "$want="* ]] && out=${fld#"$want="}
      done
      [[ -n $hit ]] && { printf '%s' "$out"; return 0; }
    done <"$f"
  done
  printf ''
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
  _dast_headers_phase
}

# ---------------------------------------------------------------------------
# Load the phase's functions.  A phase script has no sourced-once guard and runs
# _dast_headers_phase at source time (that is how dast_run_phase invokes it), so
# it is sourced once here against a throwaway run with no inventory - a run that
# still fetches the base URL - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=hdr-fixture
SCOURSH_DAST_CELL=hdr-fixture
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED SCOURSH_DAST_ENDPOINTS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/passive/headers.sh
source "$ROOT/modules/dast/passive/headers.sh"

# ===========================================================================
printf '== A. the engine: the response reader ==\n'
# ===========================================================================
t_case 'reader'
CAP=$W/cap.hdr
printf 'HTTP/1.1 302 Found\r\nStrict-Transport-Security: max-age=31536000\r\nLocation: /final\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 200 "$_HDR_STATUS" \
  'the reader reports the FINAL hop status, not the redirect - FAILS if it stops at the first status line'
assert_true "$(hdr_present x-content-type-options && printf 0 || printf 1)" \
  'a header on the final hop is present'
assert_true "$(hdr_present strict-transport-security && printf 1 || printf 0)" \
  'HSTS set only on the REDIRECT hop is NOT reported as present on the final response - FAILS under a whole-file grep, which is the whole reason this reader exists'

printf 'HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n' >"$CAP"
hdr_parse_capture "$CAP"
assert_eq 2 "${_HDR_COUNT[set-cookie]}" \
  'a repeated field is counted, not overwritten - the HSTS_MALFORMED duplicate case depends on it'

: >"$CAP"
assert_true "$(hdr_parse_capture "$CAP" && printf 1 || printf 0)" \
  'an empty capture returns non-zero rather than reporting a response with no headers'

# ===========================================================================
printf '== A. the engine: CSP, HSTS and Referrer-Policy parsing ==\n'
# ===========================================================================
t_case 'parsers'
hdr_csp_load "script-src 'self'; SCRIPT-SRC 'unsafe-inline'"
assert_eq "'self'" "${_HDR_CSP_DIR[script-src]}" \
  'a duplicate CSP directive keeps the FIRST, per CSP3 §2.2 - FAILS under a last-wins reading, which would report a policy no browser enforces'

hdr_csp_load "default-src 'self' 'unsafe-inline'"
hdr_csp_effective script-src
assert_eq default-src "$_HDR_CSP_VIA" \
  'an absent script-src falls back to default-src - FAILS if the fallback is skipped, which misses the commonest real shape of this defect'

assert_true "$(hdr_csp_has_nonce_or_hash "'self' 'nonce-abc' 'unsafe-inline'" && printf 0 || printf 1)" \
  "a nonce in the source list is recognised"
assert_true "$(hdr_csp_has_nonce_or_hash "'self' 'unsafe-inline'" && printf 1 || printf 0)" \
  'a list with neither nonce nor hash is recognised as such'

assert_true "$(hdr_csp_wildcard_in "'self' https://cdn.example/assets/*" && printf 1 || printf 0)" \
  'a wildcard in the PATH is not a domain wildcard - FAILS under a bare substring test for *'
hdr_csp_wildcard_in "'self' *.cdn.example" && :
assert_eq '*.cdn.example' "$_HDR_CSP_WILDCARD" \
  'a wildcard in the domain portion is found and named'

assert_true "$(hdr_csp_data_in "'self' data:" && printf 0 || printf 1)" 'data: is found as a whole token'
assert_true "$(hdr_csp_data_in "'self' https://mydata:8080" && printf 1 || printf 0)" \
  'a host that merely ends in "data:" is not the data: scheme - FAILS under a substring test'

hdr_hsts_parse 'max-age=31536000; includeSubDomains'
assert_eq ok "$_HDR_HSTS_STATE" 'a well-formed HSTS parses'
assert_eq 1 "$_HDR_HSTS_SUBDOMAINS" 'includeSubDomains is case-insensitive'
hdr_hsts_parse 'includeSubDomains'
assert_eq no_max_age "$_HDR_HSTS_STATE" \
  'HSTS with no max-age is MALFORMED, not merely weak - FAILS if the two are folded together, which is what docs/DESIGN.md §7.1 asks to keep apart'
hdr_hsts_parse 'max-age=abc'
assert_eq bad_max_age "$_HDR_HSTS_STATE" 'a non-numeric max-age is malformed'
hdr_hsts_parse 'max-age="31536000"'
assert_eq 31536000 "$_HDR_HSTS_MAXAGE" 'a quoted-string max-age is accepted, per RFC 6797'

hdr_referrer_effective 'unsafe-url, strict-origin-when-cross-origin'
assert_eq strict-origin-when-cross-origin "$_HDR_REF_TOKEN" \
  'the LAST recognised Referrer-Policy token wins - FAILS under a first-token reading, which flags a site that correctly lists a legacy fallback first'
hdr_referrer_effective 'no-referrer, not-a-policy'
assert_eq no-referrer "$_HDR_REF_TOKEN" \
  'an UNRECOGNISED trailing token is skipped, not adopted - FAILS under a plain last-token reading'
assert_true "$(hdr_referrer_leaks_full_url origin-when-cross-origin && printf 1 || printf 0)" \
  'origin-when-cross-origin sends only the origin and is NOT flagged - FAILS under "anything but strict-origin is leaky"'
assert_true "$(hdr_referrer_leaks_full_url no-referrer-when-downgrade && printf 0 || printf 1)" \
  'no-referrer-when-downgrade sends the full URL to every cross-origin HTTPS destination and IS flagged'

assert_true "$(hdr_is_document 'text/html; charset=utf-8' && printf 0 || printf 1)" 'text/html is a document'
assert_true "$(hdr_is_document 'application/json' && printf 1 || printf 0)" 'application/json is not'

# ===========================================================================
printf '== B. a target with nothing set fires the absence checks ==\n'
# ===========================================================================
t_case 'bare target'
_run_case bare hdr-bare
for c in DAST-HDR-CSP_MISSING-01 DAST-HDR-HSTS_MISSING-01 DAST-HDR-CLICKJACKING-01 \
  DAST-HDR-NOSNIFF_MISSING-01 DAST-HDR-RECOMMENDED_MISSING-01; do
  assert_eq 1 "$(_count_check "$c")" "$c fires once on a target with no security header at all"
done
assert_eq 0 "$(_count_check DAST-HDR-REFERRER_LEAKY-01)" \
  'an ABSENT Referrer-Policy is NOT a leak finding - it belongs to the roll-up - FAILS under "absent means leaky"'
assert_contains "$(_field_of DAST-HDR-RECOMMENDED_MISSING-01 evidence)" 'permissions-policy' \
  'the roll-up names the headers that were not set'
assert_contains "$(_field_of DAST-HDR-RECOMMENDED_MISSING-01 evidence)" 'referrer-policy' \
  'Referrer-Policy absence is reported by the roll-up'
assert_contains "$(_meta checks_run)" 'DAST-HDR-CSP_MISSING-01' \
  'a check that ran is recorded in checks_run, which is what modules/dast/run.sh reads for coverage'

# ===========================================================================
printf '== C. a fully hardened target fires nothing ==\n'
# ===========================================================================
t_case 'hardened target'
_run_case hardened hdr-fixture
for c in "${_HDR_CHECK_IDS[@]+"${_HDR_CHECK_IDS[@]}"}"; do
  assert_eq 0 "$(_count_check "$c")" "$c stays quiet against a fully hardened response"
done

# ===========================================================================
printf '== D. CSP content checks ==\n'
# ===========================================================================
t_case 'csp content'
_run_case unsafe hdr-fixture https://hdr.fixture.example/unsafe
assert_eq 1 "$(_count_check DAST-HDR-CSP_UNSAFE-01)" \
  "script-src with 'unsafe-inline' and 'unsafe-eval' is flagged"

_run_case nonce hdr-fixture https://hdr.fixture.example/nonce
assert_eq 0 "$(_count_check DAST-HDR-CSP_UNSAFE-01)" \
  "'unsafe-inline' BESIDE a nonce is ignored by every CSP2+ browser and is NOT flagged - FAILS under a bare search for the literal 'unsafe-inline'"

_run_case inherit hdr-fixture https://hdr.fixture.example/inherit
assert_eq 1 "$(_count_check DAST-HDR-CSP_UNSAFE-01)" \
  "'unsafe-inline' reachable only through the default-src fallback IS flagged - FAILS if only a literal script-src is consulted"

_run_case scriptdata hdr-fixture https://hdr.fixture.example/scriptdata
assert_eq 1 "$(_count_check DAST-HDR-CSP_DATA_SOURCE-01)" 'data: in script-src is flagged'
_run_case imgdata hdr-fixture https://hdr.fixture.example/imgdata
assert_eq 0 "$(_count_check DAST-HDR-CSP_DATA_SOURCE-01)" \
  'data: in img-src is ordinary and is NOT flagged - FAILS under "data: anywhere in the policy"'

_run_case wild hdr-fixture https://hdr.fixture.example/wild
assert_eq 1 "$(_count_check DAST-HDR-CSP_WILDCARD-01)" 'a wildcard domain in script-src is flagged'
_run_case pathwild hdr-fixture https://hdr.fixture.example/pathwild
assert_eq 0 "$(_count_check DAST-HDR-CSP_WILDCARD-01)" \
  'a wildcard in the PATH portion is NOT flagged - FAILS under a substring test for *'

# Two CSP headers on one response: the browser enforces their INTERSECTION, so
# a permissive first header says nothing about what is actually allowed.
_run_case dualcsp hdr-fixture https://hdr.fixture.example/dualcsp
assert_eq 0 "$(_count_check DAST-HDR-CSP_UNSAFE-01)" \
  "a permissive FIRST of two CSP headers is not a finding, because a browser enforces the intersection of both - FAILS under 'take the first policy and analyse it', which reports a source the combined policy blocks"
assert_eq 0 "$(_count_check DAST-HDR-CSP_WILDCARD-01)" \
  'and the wildcard in that same first policy is likewise not reported'
assert_contains "$(_meta coverage_reduction)" 'headers_multiple_csp_headers' \
  'the declined analysis is DECLARED, so a quiet result is not read as a clean policy'

# ===========================================================================
printf '== E. HSTS: missing, weak and malformed are three findings ==\n'
# ===========================================================================
t_case 'hsts'
_run_case hstsweak hdr-fixture https://hdr.fixture.example/hstsweak
assert_eq 1 "$(_count_check DAST-HDR-HSTS_WEAK-01)" 'max-age=300 is weak'
assert_eq 0 "$(_count_check DAST-HDR-HSTS_MALFORMED-01)" 'a weak max-age is not also malformed'
assert_eq 0 "$(_count_check DAST-HDR-HSTS_MISSING-01)" 'a weak max-age is not also missing'

_run_case hstsbad hdr-fixture https://hdr.fixture.example/hstsbad
assert_eq 1 "$(_count_check DAST-HDR-HSTS_MALFORMED-01)" \
  'HSTS with no max-age is MALFORMED - FAILS under a reading that treats any present header as configured'
assert_eq 0 "$(_count_check DAST-HDR-HSTS_WEAK-01)" 'a malformed header is not also reported as weak'

_run_case plain hdr-plain
assert_eq 0 "$(_count_check DAST-HDR-HSTS_MISSING-01)" \
  'HSTS is NOT evaluated on a plaintext response (RFC 6797 §7.2 has the browser ignore it) - FAILS under "every response needs HSTS"'
assert_contains "$(_meta coverage_reduction)" 'headers_check_not_applicable' \
  'a check no tested response was applicable to is declared as NOT COVERED, never silently omitted'
assert_true "$([[ $(_meta checks_run) == *DAST-HDR-HSTS_MISSING-01* ]] && printf 1 || printf 0)" \
  'an inapplicable check is NOT recorded in checks_run - FAILS under "the phase ran, so the check is covered", which is the overstated coverage §15 forbids'

_run_case redirect hdr-fixture https://hdr.fixture.example/redirect
assert_eq 1 "$(_count_check DAST-HDR-HSTS_MISSING-01)" \
  'HSTS present only on a REDIRECT hop does not protect the page that was delivered - FAILS under a whole-capture-file read, which the accumulating sink makes the natural mistake'

# ===========================================================================
printf '== F. clickjacking ==\n'
# ===========================================================================
t_case 'clickjacking'
_run_case xfoallow hdr-fixture https://hdr.fixture.example/xfoallow
assert_eq 1 "$(_count_check DAST-HDR-CLICKJACKING-01)" \
  'X-Frame-Options: ALLOW-FROM is honoured by no current browser and is flagged - FAILS under "the header is present, so it is protected"'
_run_case faany hdr-fixture https://hdr.fixture.example/faany
assert_eq 1 "$(_count_check DAST-HDR-CLICKJACKING-01)" \
  "frame-ancestors * permits every origin AND overrides the X-Frame-Options: DENY sent beside it - FAILS under 'frame-ancestors is present, so it is protected'"

# ===========================================================================
printf '== G. Referrer-Policy, and the document-only gate ==\n'
# ===========================================================================
t_case 'referrer and content-type'
_run_case leaky hdr-fixture https://hdr.fixture.example/leaky
assert_eq 1 "$(_count_check DAST-HDR-REFERRER_LEAKY-01)" 'unsafe-url is flagged'
_run_case refok hdr-fixture https://hdr.fixture.example/refok
assert_eq 0 "$(_count_check DAST-HDR-REFERRER_LEAKY-01)" \
  'a leaky token followed by a safe one is not a finding, because the browser applies the last recognised token'

_run_case json hdr-fixture https://hdr.fixture.example/json
assert_eq 1 "$(_count_check DAST-HDR-NOSNIFF_MISSING-01)" \
  'nosniff is checked on a JSON response too - FAILS if the document gate is applied to every check'
assert_eq 0 "$(_count_check DAST-HDR-CSP_MISSING-01)" \
  'CSP absence is NOT reported for a JSON response - FAILS under "every response needs a CSP", which buries the report in noise'
assert_eq 0 "$(_count_check DAST-HDR-CLICKJACKING-01)" \
  'framing protection is NOT reported for a JSON response, which cannot be framed as a document'

# ===========================================================================
printf '== H. one finding per check per target, with the count in evidence ==\n'
# ===========================================================================
t_case 'aggregation'
_run_case agg hdr-bare https://bare.fixture.example/a https://bare.fixture.example/b \
  https://bare.fixture.example/c
assert_eq 1 "$(_count_check DAST-HDR-CSP_MISSING-01)" \
  'four affected endpoints yield ONE finding, not four - FAILS under a per-endpoint emit, which reports one misconfiguration four times'
assert_contains "$(_field_of DAST-HDR-CSP_MISSING-01 evidence)" 'Observed on 4 of the 4' \
  'the evidence states how many of how many responses exhibited it, so "1 of 10" and "10 of 10" are distinguishable'
assert_eq '/' "$(_field_of DAST-HDR-CSP_MISSING-01 loc_path_template)" \
  "the finding is located at the operator's own base-url, which is first in the deterministic order - FAILS under an inventory-order walk, whose location churns whenever the crawl reorders"

# ===========================================================================
printf '== I. what is requested, and what is not ==\n'
# ===========================================================================
t_case 'request discipline'
# A POST endpoint must never be requested: re-sending it to read its headers is
# a state change, which §7.1 forbids at the passive tier.
POSTINV=$W/post.endpoints.json
cat >"$POSTINV" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e1", "target": "hdr-bare", "method": "POST", "url": "https://bare.fixture.example/submit", "path": "/submit" },
  { "id": "e2", "target": "hdr-bare", "method": "GET",  "url": "https://bare.fixture.example/read",   "path": "/read" }
] }
EOF
_new_run post hdr-bare
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=$POSTINV
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
_dast_headers_phase
assert_true "$([[ $(cat "$REQ_LOG") == *"/submit"* ]] && printf 1 || printf 0)" \
  'a discovered POST endpoint is NEVER requested - FAILS if the phase re-sends it as a GET to read its headers, or at all'
assert_contains "$(_meta coverage_reduction)" 'headers_non_get_endpoint_skipped' \
  'the skipped POST is DECLARED, not silently dropped'

# An out-of-scope inventory URL is skipped, and the run continues.  Handing it
# straight to http_request would abort the whole run with exit 3, which is
# exactly what the pre-check exists to prevent (modules/dast/crawl.sh's own
# `_crawl_in_scope` reasoning).
OOSINV=$W/oos.endpoints.json
cat >"$OOSINV" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e1", "target": "hdr-bare", "method": "GET", "url": "https://not-authorised.invalid/x", "path": "/x" },
  { "id": "e2", "target": "hdr-bare", "method": "GET", "url": "https://bare.fixture.example/ok",  "path": "/ok" }
] }
EOF
_new_run oos hdr-bare
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=$OOSINV
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
rc=0
_dast_headers_phase || rc=$?
assert_eq 0 "$rc" \
  'an out-of-scope URL in the inventory does not abort the run - FAILS if a discovered URL is handed straight to http_request, whose gate is fatal'
assert_true "$([[ $(cat "$REQ_LOG") == *not-authorised* ]] && printf 1 || printf 0)" \
  'and no request is sent to it - asserted on the REQUEST LOG, not on a return value'
assert_contains "$(_meta coverage_reduction)" 'headers_endpoint_out_of_scope' \
  'the refused URL is declared'

# Two URLs that differ only in a volatile path segment are ONE handler.
_run_case dedupe hdr-bare https://bare.fixture.example/order/1 https://bare.fixture.example/order/2
n=0
while IFS= read -r _l; do [[ -n $_l ]] && n=$(( n + 1 )); done <"$REQ_LOG"
assert_eq 2 "$n" \
  '/order/1 and /order/2 are one path template and cost one request (plus the base-url) - FAILS under a per-URL walk, which spends the request budget re-learning one fact'

# The per-run endpoint cap.
_HDR_MAX_ENDPOINTS=3
_run_case cap hdr-bare https://bare.fixture.example/p1 https://bare.fixture.example/p2 \
  https://bare.fixture.example/p3 https://bare.fixture.example/p4
assert_contains "$(_meta coverage_gap)" 'were NOT fetched (cap 3)' \
  'the endpoint cap is DECLARED when it bites - a bound that truncates silently is indistinguishable from a surface that was really that small'
_HDR_MAX_ENDPOINTS=10

# ===========================================================================
printf '== J. honest degradation ==\n'
# ===========================================================================
t_case 'degradation'
# No inventory AND no base-url: nothing to request, and the run says so.
cat >"$W/scope-nobase.conf" <<'EOF'
id: hdr-fixture
base-url: https://hdr.fixture.example/
notes: reloaded below

id: hdr-bare
base-url: https://bare.fixture.example/
notes: reloaded below

id: hdr-plain
base-url: http://plain.fixture.example/
notes: reloaded below
EOF
_new_run nourl hdr-bare
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
# `config_scope_field_or` is what supplies the base-url; with it unavailable the
# phase has nothing at all, which is the state this case pins.
_hdr_saved_scope_fn=$(declare -f config_scope_field_or)
config_scope_field_or() { printf ''; }
_dast_headers_phase
eval "$_hdr_saved_scope_fn"
assert_contains "$(_meta coverage_gap)" 'offered no URL to request' \
  'no inventory and no base-url is a recorded coverage GAP, never a clean report'
assert_eq 0 "$(_count_check DAST-HDR-CSP_MISSING-01)" 'and no finding is invented from nothing'

# The configurable roll-up list, absent.
_new_run norec hdr-bare
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
SCOURSH_DAST_RECOMMENDED_HEADERS_FILE=$W/nope.txt _dast_headers_phase
assert_eq 0 "$(_count_check DAST-HDR-RECOMMENDED_MISSING-01)" \
  'an unreadable recommended-header list skips that ONE check rather than erroring'
assert_contains "$(_meta coverage_reduction)" 'recommended_header_list_unavailable' \
  'and the reduction is declared'
assert_eq 1 "$(_count_check DAST-HDR-CSP_MISSING-01)" 'while every other check still runs'

# The roll-up list is operator-configurable.
printf 'X-Made-Up-Header\ncontent-security-policy\n' >"$W/custom-rec.txt"
_new_run customrec hdr-bare
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
SCOURSH_DAST_RECOMMENDED_HEADERS_FILE=$W/custom-rec.txt _dast_headers_phase
assert_contains "$(_field_of DAST-HDR-RECOMMENDED_MISSING-01 evidence)" 'x-made-up-header' \
  'the roll-up reports the headers the OPERATOR listed - it is configurable, per docs/DESIGN.md §7.1'
assert_true "$([[ $(_field_of DAST-HDR-RECOMMENDED_MISSING-01 evidence) == *content-security-policy* ]] && printf 1 || printf 0)" \
  'a header that already has its own check id is dropped from the list rather than reported twice'
assert_contains "$(_meta notes)" 'recommended_list_ignored' \
  'and the operator is told which of their entries was ignored, rather than it being silently discarded'

# The run directory's own inventory is used when the export is empty, which is
# the ordinary case: modules/dast/run.sh exports the path BEFORE crawl.sh writes
# the file.
_new_run rundir hdr-bare
mkdir -p "$SCOURSH_RUN_DIR/inventory"
cat >"$SCOURSH_RUN_DIR/inventory/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e1", "target": "hdr-bare", "method": "GET", "url": "https://bare.fixture.example/late", "path": "/late" }
] }
EOF
SCOURSH_DAST_TARGET=hdr-bare SCOURSH_DAST_CELL=hdr-bare SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_ENDPOINTS
_dast_headers_phase
assert_true "$([[ $(cat "$REQ_LOG") == *"/late"* ]] && printf 0 || printf 1)" \
  "the run directory's own inventory is read when SCOURSH_DAST_ENDPOINTS is empty - FAILS under a reading that trusts the export alone, which is empty on every first run because crawl.sh writes the file later in the same loop"

# ===========================================================================
printf '== K. the registry and the emitted finding agree ==\n'
# ===========================================================================
t_case 'registry agreement'
# modules/dast/passive/checks.rules is the catalog tension 12 and tension 15
# read; `_hdr_catalog` is what a finding carries.  They are two copies, so they
# are asserted equal here rather than assumed so.
#
# THE FILE IS SHARED WITH THE OTHER TIER-2 TICKETS, so the id count below is
# taken over THIS phase's own records only - the ones whose `script:` is
# `passive/headers.sh`.  Counting every `id:` in the file instead makes this
# assertion fail the moment a peer appends its block (measured: it read 15
# against DAST-06's four `DAST-COOKIE-*` records landing alongside these
# eleven), which would make a correct, append-only merge look like a defect in
# this phase.  `tests/suites/dast-cookies.sh` asks the same question per id for
# the same reason.
_reg_ids=''
_key='' _val='' _cur_id=''
declare -A REG_SEV=() REG_CWE=() REG_OWASP=() REG_TITLE=() REG_SCRIPT=() REG_TAG=()
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *': '* ]] || continue
  _key=${line%%': '*}; _val=${line#*': '}
  case $_key in
    id) _cur_id=$_val ;;
    title) REG_TITLE[$_cur_id]=$_val ;;
    severity) REG_SEV[$_cur_id]=$_val ;;
    cwe) REG_CWE[$_cur_id]=$_val ;;
    owasp) REG_OWASP[$_cur_id]=$_val ;;
    script) REG_SCRIPT[$_cur_id]=$_val ;;
    tags) [[ -z ${REG_TAG[$_cur_id]:-} ]] && REG_TAG[$_cur_id]=$_val ;;
  esac
done <"$ROOT/modules/dast/passive/checks.rules"

for _id in "${!REG_SCRIPT[@]}"; do
  [[ ${REG_SCRIPT[$_id]} == 'passive/headers.sh' ]] && _reg_ids+="$_id "
done

assert_eq "${#_HDR_CHECK_IDS[@]}" "$(printf '%s' "$_reg_ids" | wc -w | tr -d ' ')" \
  "the registry declares exactly the ids the phase can emit - FAILS if either grows without the other (counted over this script's own records, since the file is shared with its tier-2 peers)"
for c in "${_HDR_CHECK_IDS[@]+"${_HDR_CHECK_IDS[@]}"}"; do
  _hdr_catalog "$c"
  assert_eq "${REG_TITLE[$c]:-<absent>}" "$_HDRC_TITLE" "$c: title agrees with the registry"
  assert_eq "${REG_SEV[$c]:-<absent>}" "$_HDRC_SEV" "$c: severity agrees with the registry"
  assert_eq "${REG_CWE[$c]:-<absent>}" "$_HDRC_CWE" "$c: CWE agrees with the registry"
  assert_eq "${REG_OWASP[$c]:-<absent>}" "$_HDRC_OWASP" "$c: OWASP mapping agrees with the registry"
  assert_eq 'passive/headers.sh' "${REG_SCRIPT[$c]:-<absent>}" "$c: the registry names this phase script"
  assert_eq 'passive' "${REG_TAG[$c]:-<absent>}" \
    "$c: the type tag is 'passive', matching the phase table's own floor - FAILS if the two gates disagree, which tension 15 forbids"
done

# ===========================================================================
printf '\n== dast-headers: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
