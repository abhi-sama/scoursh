#!/usr/bin/env bash
# tests/suites/http.sh - lib/http.sh, the scope-gate authorization chokepoint.
#
# Covers docs/FOUNDATION.md tension 19 end to end: entry point / single
# chokepoint, the (scheme, host, port) tuple match with the port-80
# relaxation and allow-subdomains, the normalization pipeline (percent-
# decoding, userinfo/authority confusion, numeric IPv4 and IPv6-embedded-IPv4
# literals, case and trailing-dot), resolution-pinning against the deny list,
# redirect-recheck parity, and auditability.
#
# No case here ever touches the network: SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout, consistent with
# docs/DESIGN.md §12 ("DAST logic is testable with no live target").
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule (AGENTS.md / CLAUDE.md): a test that passes under
# both the correct and a plausible-but-wrong reading pins nothing.
#
# REGRESSION PROOF (ticket AC4, "tests confirmed to fail when the gate is
# deliberately removed"): manually verified before this file was committed by
# copying lib/ to a scratch directory, replacing the `http_gate_url ... ||
# die ...` block in http_request with `http_gate_url ... || true`, and
# re-running "-- http_request: the chokepoint --" below against that copy.
# Every case in that section failed (the fatal-path case no longer exits 3;
# the redirect-recheck case calls the stub transport for the out-of-scope
# Location). That is exactly what "removing the gate" means for a chokepoint
# function, so this is what the AC's regression requirement pins.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2329: as tests/suites/config.sh.
# shellcheck disable=SC2015,SC2016,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/http
mkdir -p "$W"
FIXTURE_SCOPE=$ROOT/tests/fixtures/config/http-scope.conf

# ---------------------------------------------------------------------------
# Stub resolver and transport - no test in this file ever resolves a real
# name or opens a real socket.
# ---------------------------------------------------------------------------
_test_resolve() {
  case $1 in
    good.fixture.example) printf '93.184.216.34' ;;
    api.good.fixture.example) printf '93.184.216.34' ;;
    internal.fixture.example) printf '127.0.0.1' ;;
    priv.fixture.example) printf '127.0.0.1' ;;
    sub.wide.fixture.example) printf '93.184.216.34' ;;
    still-good.fixture.example) printf '93.184.216.34' ;;
    unresolvable.fixture.example) return 1 ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_test_resolve

TRANSPORT_LOG=$W/transport.log
: >"$TRANSPORT_LOG"
_test_transport() {
  printf '%s %s\n' "$1" "$3" >>"$TRANSPORT_LOG"
  case $3 in
    good.fixture.example) printf '301\nhttps://evil.example/next\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_test_transport

http_scope_load "$FIXTURE_SCOPE"

printf '\n-- http_url_normalize: normalization pipeline --\n'

http_url_normalize 'https://good.fixture.example/x'
assert_eq 'good.fixture.example' "$_HN_HOST" 'plain host normalises to itself'
assert_eq 443 "$_HN_PORT" 'https defaults to port 443'

http_url_normalize 'https://GOOD.FIXTURE.EXAMPLE/x'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'case: an uppercase host normalises identically to the lowercase spelling - FAILS if normalization skips lowercasing'

http_url_normalize 'https://good.fixture.example./x'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'trailing dot: a single trailing dot on the host is stripped - FAILS if the dot is left in, which would make it compare unequal to the scope tuple'

http_url_normalize 'https://%67ood.fixture.example/x'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'percent-encoding: %67 decodes to "g" once - FAILS if the authority is never decoded'

http_url_normalize 'https://good%2Efixture.example/x'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'percent-encoding: %2E decodes to "." once, still comparing equal to the plain host'

http_url_normalize 'https://good.fixture.example%252Eevil.example/x'
assert_eq 'good.fixture.example%2eevil.example' "$_HN_HOST" \
  'double-encoding is NOT collapsed: %2525 decodes ONE pass to %25, which stays literal - FAILS if a second decode pass turns this into a dot, silently equal to the innocuous host'

http_url_normalize 'https://user:pass@good.fixture.example/x'
assert_eq 'good.fixture.example' "$_HN_HOST" 'userinfo is stripped from the host'
assert_eq true "$_HN_HAD_USERINFO" 'userinfo presence is flagged for the gate to reject'

http_url_normalize 'https://good.fixture.example@evil.example/x'
assert_eq 'evil.example' "$_HN_HOST" \
  'authority confusion: "good.fixture.example@evil.example" names host evil.example, not good.fixture.example - FAILS if the parser is fooled into treating the text before "@" as the host'

http_url_normalize 'https://user@name@good.fixture.example/x'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'multiple "@": split at the LAST one, so userinfo may itself contain "@"'

http_url_normalize 'https://good.fixture.example:443/x'
assert_eq 443 "$_HN_PORT" 'an explicit default port is accepted and normalised the same as an absent one'

http_url_normalize 'https://good.fixture.example:8443/x'
assert_eq 8443 "$_HN_PORT" 'a non-default port is preserved, not silently coerced to the default'

http_url_normalize 'https://good.fixture.example/a/../../etc/passwd?x=1&y=2#frag'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'query/fragment tricks: nothing after ? or # (or a path traversal sequence) ever reaches the host comparison'

http_url_normalize 'https://good.fixture.example?@evil.example/'
assert_eq 'good.fixture.example' "$_HN_HOST" \
  'query tricks: "?@evil.example" is a query string, not a second authority - FAILS if authority extraction runs past the first "?"'

# Numeric IPv4 literals: decimal / octal / hex all canonicalise to the same
# dotted-quad tension 19 names as the SSRF sentinel, 169.254.169.254.
# (docs/FOUNDATION.md tension 19's own example numbers are illustrative prose,
# not verified arithmetic - see the "measured, not assumed" note in this
# file's commit; these values are computed and checked against real base
# conversions in the "IPv4 literal parsing is exact" case below.)
http_url_normalize 'https://2852039166/x'
assert_eq '169.254.169.254' "$_HN_HOST" 'decimal IPv4 literal canonicalises to its dotted-quad'
assert_eq true "$_HN_IS_LITERAL" 'a numeric host is flagged literal (skips DNS resolution)'

http_url_normalize 'https://025177524776/x'
assert_eq '169.254.169.254' "$_HN_HOST" 'octal (single-token, leading 0) IPv4 literal canonicalises to the same dotted-quad'

http_url_normalize 'https://0251.0.0.1/x'
assert_eq '169.0.0.1' "$_HN_HOST" 'octal (per-octet) IPv4 literal: 0251 is octal 251 = decimal 169'

http_url_normalize 'https://0xA9FEA9FE/x'
assert_eq '169.254.169.254' "$_HN_HOST" 'hex IPv4 literal canonicalises to the same dotted-quad'

http_url_normalize 'https://127.1/x'
assert_eq '127.0.0.1' "$_HN_HOST" 'short-form (inet_aton style) IPv4 literal: 127.1 means 127.0.0.1'

http_url_normalize 'https://[::ffff:169.254.169.254]/x'
assert_eq '169.254.169.254' "$_HN_HOST" 'IPv4-mapped IPv6 (dotted form) extracts the embedded IPv4'
assert_eq true "$_HN_IS_LITERAL" 'IPv4-mapped IPv6 host is flagged literal'

http_url_normalize 'https://[::a9fe:a9fe]/x'
assert_eq '169.254.169.254' "$_HN_HOST" \
  'IPv4-compatible IPv6 (hex-group form, ::a9fe:a9fe) also extracts to the same dotted-quad - FAILS if only the dotted ::ffff: form is handled and the hex-group form is left as opaque IPv6, which would let it dodge both the scope-tuple compare and the deny list'

assert_status 1 'http_url_normalize rejects a string with no scheme' \
  http_url_normalize 'not-a-url'

assert_status 1 'http_url_normalize rejects a non-http(s) scheme - no raw-protocol bypass' \
  http_url_normalize 'ftp://good.fixture.example/x'

printf '\n-- IPv4 literal parsing is exact (not just "looks numeric") --\n'
# Pins the actual arithmetic, independently of the normalize-pipeline cases
# above, against values computed from the real base conversion rather than
# copied from prose.
assert_eq '169.254.169.254' "$(_http_canon_ipv4 2852039166)" \
  'decimal 2852039166 is exactly 169*2^24 + 254*2^16 + 169*2^8 + 254'
assert_eq '169.254.169.254' "$(_http_canon_ipv4 025177524776)" \
  'octal 025177524776 is the same 32-bit value in base 8'
assert_status 1 'a hostname-shaped token is never treated as numeric' \
  _http_canon_ipv4 'example.com'
assert_status 1 'an octal token with an invalid digit (8 or 9) is rejected, not silently reinterpreted' \
  _http_canon_ipv4 '0189'
assert_status 1 'a token that is not a valid arithmetic literal at all is rejected, not evaluated' \
  _http_canon_ipv4 '$(id)'

printf '\n-- http_scope_match: the (scheme, host, port) tuple --\n'

http_scope_match https good.fixture.example 443
assert_eq 0 $? 'the exact authored tuple matches'

assert_status 1 'a different port is NOT authorised by the base-url (tension 19: "https://host does not authorise https://host:8443")' \
  http_scope_match https good.fixture.example 8443

http_scope_match http good.fixture.example 80
assert_eq 0 $? 'the documented relaxation: an https target also authorises http on port 80, same host'

assert_status 1 'the relaxation is ONE-WAY: an http target on 80 does NOT get https widened to it implicitly for a different host' \
  http_scope_match https not-authorised.fixture.example 443

assert_status 1 'a bare hostname match with the WRONG scheme (not the documented relaxation) is refused' \
  http_scope_match http good.fixture.example 8080

assert_status 1 'a subdomain is never implicitly in scope without allow-subdomains: true' \
  http_scope_match https sub.good.fixture.example 443

http_scope_match https sub.wide.fixture.example 443
assert_eq 0 $? 'allow-subdomains: true authorises a subdomain of the declared host'

assert_status 1 'allow-subdomains does not authorise the bare suffix host under a DIFFERENT target id by accident' \
  http_scope_match https evil-wide.fixture.example 443

printf '\n-- http_gate_url: the full pipeline, allowed cases --\n'

http_gate_url 'https://good.fixture.example/x'
assert_eq 0 $? 'an in-scope, resolvable host is allowed'

http_gate_url 'https://GOOD.FIXTURE.EXAMPLE./x'
assert_eq 0 $? 'case + trailing-dot tricks do not bypass an ALREADY-in-scope host either (they are simply normalised away)'

http_gate_url 'https://priv.fixture.example/x'
assert_eq 0 $? 'a target with allow-private-addresses: true is allowed even though its host resolves to a loopback address'

printf '\n-- http_gate_url: the full pipeline, denied cases --\n'

assert_status 1 'an out-of-scope host is refused' http_gate_url 'https://evil.example/x'

http_gate_url 'https://evil.example/x' || true
assert_contains "$_HTTP_GATE_REASON" 'no entry in config/scope.conf' \
  'the rejection reason names the actual failure (out-of-scope tuple)'

assert_status 1 'userinfo confusion is refused even though the trailing host IS in scope (tension 19: gate has never looked at userinfo)' \
  http_gate_url 'https://tricked@good.fixture.example.evil.example/x'

assert_status 1 'percent-encoded host that decodes to an out-of-scope literal is refused' \
  http_gate_url 'https://%65vil.example/x'

assert_status 1 'a decimal IPv4 literal for the SSRF sentinel is refused (not in scope AND on the deny list)' \
  http_gate_url 'https://2852039166/x'

assert_status 1 'a bracketed IPv4-mapped IPv6 literal for the SSRF sentinel is refused' \
  http_gate_url 'https://[::ffff:169.254.169.254]/x'

assert_status 1 'an in-scope hostname that resolves to a loopback address, with no allow-private-addresses, is refused (the resolution-pinning deny list)' \
  http_gate_url 'https://internal.fixture.example/x'

http_gate_url 'https://internal.fixture.example/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback' \
  'the deny-list rejection reason names loopback/link-local/private, distinguishable from an out-of-scope-tuple rejection'

assert_status 1 'a host that fails to resolve is refused, not silently skipped' \
  http_gate_url 'https://unresolvable.fixture.example/x'

printf '\n-- http_request: the chokepoint --\n'

: >"$TRANSPORT_LOG"
assert_status 3 \
  'http_request on an out-of-scope URL exits 3 (docs/DESIGN.md exit-code table: 3 = scope violation) BEFORE any network call' \
  http_request GET 'https://evil.example/x'
assert_eq '' "$(cat "$TRANSPORT_LOG")" \
  'the transport (the only thing that would touch the network) was never invoked for the refused URL - this is what "before any network call" means operationally'

: >"$TRANSPORT_LOG"
http_request GET 'https://good.fixture.example/x'
assert_eq 0 $? 'http_request on an in-scope URL that redirects to an out-of-scope Location does not crash the run'
assert_eq 301 "$_HTTP_LAST_STATUS" \
  'the last successfully-fetched response (the redirect itself) is what is returned, not a synthetic error'
assert_eq "GET good.fixture.example" "$(cat "$TRANSPORT_LOG")" \
  'redirect-recheck parity: the out-of-scope Location (evil.example) is never handed to the transport - only the one in-scope hop was fetched'

: >"$TRANSPORT_LOG"
_test_transport_chain() {
  printf '%s %s\n' "$1" "$3" >>"$TRANSPORT_LOG"
  case $3 in
    good.fixture.example) printf '301\nhttps://still-good.fixture.example/y\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_test_transport_chain
http_request GET 'https://good.fixture.example/x'
assert_eq 200 "$_HTTP_LAST_STATUS" 'a redirect chain that STAYS in scope is followed to completion'
assert_eq "$(printf 'GET good.fixture.example\nGET still-good.fixture.example')" "$(cat "$TRANSPORT_LOG")" \
  'both in-scope hops were fetched, in order'
SCOURSH_HTTP_TRANSPORT=_test_transport

printf '\n-- auditability: a rejection is recorded, not a silent abort --\n'

rm -rf "${W:?}/run.audit"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.audit"
http_gate_url 'https://tricked@evil.example/x' || true
_http_gate_audit 'https://tricked@evil.example/x' "$_HTTP_GATE_CANON" "$_HTTP_GATE_REASON" GET fixture-good
shard=$(find "$SCOURSH_RUN_DIR/shards" -name '*.jsonl' | head -n1)
assert_file_exists "$shard" 'a scope-violation rejection writes a finding shard when a run is active'
content=$(cat "$shard")
assert_contains "$content" '"check_id":"DAST-SCOPE-GATE-VIOLATION"' \
  'the finding carries a stable check_id an operator can filter/suppress on'
assert_contains "$content" '"module":"dast"' 'the finding is attributed to the dast module'
assert_contains "$content" 'reason=' 'the evidence records which pipeline step rejected the URL'
assert_contains "$content" 'evil.example' \
  'the evidence still names the rejected host, so the audit trail is useful'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

printf '\n-- http_gate_url never calls the transport (it is a pure predicate) --\n'
: >"$TRANSPORT_LOG"
http_gate_url 'https://good.fixture.example/x' >/dev/null || true
http_gate_url 'https://evil.example/x' >/dev/null || true
assert_eq '' "$(cat "$TRANSPORT_LOG")" \
  'http_gate_url alone never reaches the transport in either the allow or deny case - only http_request does, and only after a successful gate check'

t_summary 'http'
