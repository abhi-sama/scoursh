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
# IMPORTANT: the fatal-path case deliberately targets
# api.good.fixture.example, an out-of-scope host that the stub resolver
# (_test_resolve below) DOES resolve successfully - not evil.example, which
# the stub resolver cannot resolve. A round of review (see this file's git
# history) caught that using an unresolvable out-of-scope host let a removed
# gate hide behind a second, unrelated `die` in http_request's DNS-resolution
# step: with the gate's own `die` deleted, execution fell through to
# `http_resolve_host`, which failed for evil.example and died with the SAME
# exit code (3, SCOURSH_EXIT_SCOPE) the gate itself would have used - so the
# "exits 3" assertion kept passing even with the gate deleted, and the
# transport-log-is-empty assertion also kept passing "by accident" (the
# request never got far enough to resolve, gate or no gate). Neither
# assertion actually pinned the gate. Using a host the stub CAN resolve
# closes that hole: with the gate intact, http_scope_match still refuses it
# (it is not good.fixture.example and fixture-good does not set
# allow-subdomains: true) and http_request dies with exit 3 before resolving
# or calling the transport; with the gate's `die` deleted, execution falls
# through, resolves successfully, and reaches the stub transport (exit 0,
# transport log non-empty) - a result these assertions correctly fail on.
#
# ADVERSARIAL SUITE ADDENDUM (crewban ticket "Adversarial test suite: attempt
# to defeat the scope.conf gate"): the cases below marked "Adversarial:" add
# coverage the sections above left as a real gap, each verified the same way
# - copy lib/ to a scratch dir, break ONE specific mechanism, confirm the
# targeted case (and only cases that actually exercise that mechanism) fail:
#
#  1. Deny-list-disabled mutation (forced `denied=1` unconditionally inside
#     http_gate_url's resolution-pinning check, so nothing is ever refused
#     for resolving to a denied address): every "octal/hex/IPv4-mapped/
#     hex-group literal for the SSRF sentinel" case FAILED, along with both
#     hostname-resolves-to-169.254.169.254 cases and the redirect-Location-
#     resolves-to-the-sentinel case. This same mutation left the PRE-EXISTING
#     decimal-literal and bracketed-::ffff:-literal cases passing, which is
#     what exposed that those two (as originally written) are actually
#     rejected by the out-of-scope-tuple check, not the deny list - neither
#     address had a matching scope.conf entry, so the deny list was never
#     reached. That is why tests/fixtures/config/http-scope.conf now
#     authorises the sentinel address directly as `fixture-literal-denied`:
#     every literal-form deny-list case below targets THAT address (an
#     authorised-but-denied tuple) specifically so the deny list, not the
#     tuple compare, is what is actually under test, confirmed by asserting
#     the loopback/link-local/private reason string rather than exit status
#     alone.
#  2. Redirect-recheck-as-raw-host-string-compare mutation (the hop loop
#     rejects a Location only if its UNDECODED host exactly equals a fixed
#     literal bad-host list, never running normalize/decode/deny-list on it -
#     literally "just compare the new host string", the shortcut tension 19
#     names by name): the percent-encoded-Location case FAILED (the encoded
#     form never equals the literal bad string, so the naive check fails
#     open), which is exactly the bypass decoding-before-comparison exists to
#     close.
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
    metadata.fixture.example) printf '169.254.169.254' ;;
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

assert_status 1 'a decimal IPv4 literal for the SSRF sentinel, with no matching scope entry, is refused (out-of-scope tuple - it does not even reach the deny list yet)' \
  http_gate_url 'https://2852039166/x'

# Adversarial, and a genuine gap the cases above leave open: EVERY literal-IP
# SSRF-sentinel case above is rejected by the out-of-scope-TUPLE check
# (there is no scope.conf entry for that address), so none of them actually
# reach the resolution-pinning deny-list code at all - confirmed by
# mutation: with the deny-list check in http_gate_url disabled outright,
# every case above still correctly returns 1, because the tuple mismatch
# alone is sufficient. That means those cases do not pin "the deny list
# still refuses a literal SSRF address" the way internal.fixture.example
# and metadata.fixture.example pin it for a HOSTNAME (both are declared IN
# SCOPE and rejected only by resolution-pinning). tests/fixtures/config/
# http-scope.conf's fixture-literal-denied target closes that gap: it
# authorises https://169.254.169.254/ directly (an operator's honest
# mistake, or a copy-pasted base-url that later turned out to be a metadata
# endpoint), so a request against that SAME address now MATCHES the scope
# tuple and must be caught by the deny list instead - and, because
# normalization canonicalises every numeric spelling to the identical
# dotted-quad before either compare runs, decimal/octal/hex/IPv6-embedded
# spellings of that address all resolve to the one scope tuple and all must
# be independently caught by the deny list.
assert_status 1 'a decimal literal for an ADDRESS THAT IS ITSELF THE AUTHORISED SCOPE TARGET is still refused by the deny list - FAILS if the deny-list check is skipped once the tuple already matched' \
  http_gate_url 'https://169.254.169.254/x'
http_gate_url 'https://169.254.169.254/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback/link-local/private' \
  'the rejection is the deny-list reason, not "no entry in config/scope.conf" - proving this request DID match the scope tuple and was still refused'

assert_status 1 'the SAME authorised-but-denied address, spelled as an octal IPv4 literal, is refused end-to-end via http_gate_url - FAILS if the gate deny-list check only recognises the decimal literal form' \
  http_gate_url 'https://025177524776/x'
http_gate_url 'https://025177524776/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback/link-local/private' \
  'the octal spelling also gets the deny-list reason, not an out-of-scope-tuple reason - proving normalisation canonicalised it to the same authorised-but-denied tuple before either compare ran'

assert_status 1 'the SAME authorised-but-denied address, spelled as a hex IPv4 literal, is refused end-to-end via http_gate_url - FAILS if the gate deny-list check only recognises the decimal literal form' \
  http_gate_url 'https://0xA9FEA9FE/x'

assert_status 1 'a bracketed IPv4-mapped IPv6 literal for the SSRF sentinel is refused' \
  http_gate_url 'https://[::ffff:169.254.169.254]/x'
http_gate_url 'https://[::ffff:169.254.169.254]/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback/link-local/private' \
  'the IPv4-mapped IPv6 spelling also gets the deny-list reason, matching the authorised-but-denied tuple rather than being rejected as merely out of scope'

# Adversarial: the dotted "::ffff:a.b.c.d" spelling is refused above, but
# tension 19 names a SECOND IPv6-embedded-IPv4 shape - the hex-group form
# "::a9fe:a9fe" - as an independent bypass ("FAILS if only the dotted ::ffff:
# form is handled and the hex-group form is left as opaque IPv6", per the
# normalize-layer case earlier in this file). An implementation that wired
# only the dotted form into the scope-tuple/deny-list compare (plausible,
# since it is the more common spelling in the wild) would pass every case
# above and still let this exact address through under the hex-group
# spelling - and because it now targets the SAME authorised-but-denied
# fixture-literal-denied tuple, a bug that skipped the deny list once a
# tuple matched, or a bug that failed to extract this second embedded-IPv4
# shape at all (falling back to treating it as opaque IPv6, which would
# never match the tuple and would be rejected as merely out-of-scope
# instead), are both distinguishable via the reason-string assertion below.
assert_status 1 'a bracketed IPv4-compatible (hex-group) IPv6 literal for the SSRF sentinel is refused end-to-end via http_gate_url - FAILS if only the dotted "::ffff:" spelling reaches the gate deny-list check' \
  http_gate_url 'https://[::a9fe:a9fe]/x'
http_gate_url 'https://[::a9fe:a9fe]/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback/link-local/private' \
  'the hex-group IPv6 spelling also gets the deny-list reason - FAILS if the hex-group form is left as opaque IPv6 (never matches the fixture-literal-denied tuple, so it would be rejected as merely out-of-scope instead, which proves the extraction itself, not just the deny list, was skipped)'

assert_status 1 'an in-scope hostname that resolves to a loopback address, with no allow-private-addresses, is refused (the resolution-pinning deny list)' \
  http_gate_url 'https://internal.fixture.example/x'

http_gate_url 'https://internal.fixture.example/x' || true
assert_contains "$_HTTP_GATE_REASON" 'loopback' \
  'the deny-list rejection reason names loopback/link-local/private, distinguishable from an out-of-scope-tuple rejection'

# Adversarial: tension 19's own bypass-class list names "a hostname resolving
# to 169.254.169.254" as a DISTINCT case from a literal spelling of the same
# address - the SSRF concern §7.3 raises is specifically an in-scope,
# innocuous-looking hostname whose DNS answer is the cloud metadata endpoint,
# not an attacker typing the address directly. metadata.fixture.example is
# declared in scope (tests/fixtures/config/http-scope.conf) with no
# allow-private-addresses, so this pins the deny list catching a RESOLVED
# address, not merely a literal one - a gate that deny-lists literals but
# trusts whatever DNS returns for an already-in-scope name would pass every
# other case in this file and still exfiltrate credentials here.
assert_status 1 'an in-scope hostname that RESOLVES to the cloud metadata sentinel 169.254.169.254 is refused - FAILS if the deny list is only checked against literal hosts and not against a resolved address' \
  http_gate_url 'https://metadata.fixture.example/x'

http_gate_url 'https://metadata.fixture.example/x' || true
assert_contains "$_HTTP_GATE_REASON" "'metadata.fixture.example' resolves to '169.254.169.254'" \
  'the rejection reason names the HOSTNAME resolving to the address, distinct wording from a literal-IP case (where host and addr are the same value) - proving the deny-list hit came from the DNS-resolution path (is_literal=false), not the literal-IPv4 branch'

assert_status 1 'a host that fails to resolve is refused, not silently skipped' \
  http_gate_url 'https://unresolvable.fixture.example/x'

printf '\n-- http_request: the chokepoint --\n'

: >"$TRANSPORT_LOG"
# api.good.fixture.example, NOT evil.example: it is out-of-scope (fixture-good
# only declares good.fixture.example / internal.fixture.example /
# still-good.fixture.example, and does not set allow-subdomains: true) but IS
# resolvable in the stub resolver above, so a deleted gate falls through to a
# successful resolve-and-fetch (exit 0, transport called) rather than masking
# itself behind the unrelated DNS-failure `die`, which also exits 3. See the
# file-header "REGRESSION PROOF" note for why this choice matters.
assert_status 3 \
  'http_request on an out-of-scope URL exits 3 (docs/DESIGN.md exit-code table: 3 = scope violation) BEFORE any network call' \
  http_request GET 'https://api.good.fixture.example/x'
assert_eq '' "$(cat "$TRANSPORT_LOG")" \
  'the transport (the only thing that would touch the network) was never invoked for the refused URL - this is what "before any network call" means operationally, and is exactly what a deleted gate would fail here (it would reach the transport)'

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

# Adversarial: redirect-recheck parity (docs/FOUNDATION.md tension 19,
# "Redirect-recheck parity") requires the manual redirect loop to re-run the
# FULL normalization + gate pipeline on every Location header, not a cheap
# "compare the new host string" shortcut. The plain-hostname redirect case
# above (good.fixture.example -> https://evil.example/next) would pass even
# under that cheap shortcut, because a bare hostname compare and a full gate
# re-run agree on it. Tension 19 explicitly names "a redirect Location that
# itself carries one of the encoding bypasses above" as the case that tells
# the two apart: a host-string-only recheck would decode nothing, see an
# opaque, not-literally-"evil.example" string, and could easily let it
# through where a full pipeline run would decode/canonicalize and reject it
# exactly as the initial-URL cases above do.
: >"$TRANSPORT_LOG"
_test_transport_redirect_encoded() {
  printf '%s %s\n' "$1" "$3" >>"$TRANSPORT_LOG"
  case $3 in
    good.fixture.example) printf '301\nhttps://%%65vil.example/next\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_test_transport_redirect_encoded
http_request GET 'https://good.fixture.example/x'
assert_eq 0 $? 'a redirect Location whose host is percent-encoded (decodes to an out-of-scope host) does not crash the run'
assert_eq 301 "$_HTTP_LAST_STATUS" 'the redirect is not followed, so the redirect response itself is what is returned'
assert_eq "GET good.fixture.example" "$(cat "$TRANSPORT_LOG")" \
  'redirect-recheck parity, encoding case: the percent-encoded out-of-scope Location is never handed to the transport - FAILS if the redirect recheck only string-compares the raw, still-encoded Location against the scope host instead of running it through the same normalize pipeline the initial URL got'
SCOURSH_HTTP_TRANSPORT=_test_transport

# This case must land on an IN-SCOPE hostname whose resolution is
# deny-listed (metadata.fixture.example, added to
# tests/fixtures/config/http-scope.conf for exactly this), not an
# out-of-scope literal: a Location naming an out-of-scope host - literal or
# not - is already rejected by the scope-tuple compare alone, same as the
# plain evil.example redirect case above, and would not distinguish "the
# redirect recheck re-runs resolution-pinning" from "the redirect recheck
# only re-runs the tuple compare". Landing on an ALREADY-in-scope hostname
# that then fails the deny list is the only way to isolate that the
# redirect loop's gate re-run goes all the way through resolution, not just
# through the tuple match.
: >"$TRANSPORT_LOG"
_test_transport_redirect_denylist() {
  printf '%s %s\n' "$1" "$3" >>"$TRANSPORT_LOG"
  case $3 in
    good.fixture.example) printf '301\nhttps://metadata.fixture.example/next\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_test_transport_redirect_denylist
http_request GET 'https://good.fixture.example/x'
assert_eq 0 $? 'a redirect Location naming an in-scope hostname that resolves to the cloud metadata sentinel does not crash the run'
assert_eq 301 "$_HTTP_LAST_STATUS" 'the redirect is not followed'
assert_eq "GET good.fixture.example" "$(cat "$TRANSPORT_LOG")" \
  'redirect-recheck parity, deny-list case: a Location naming an ALREADY-in-scope hostname that resolves to 169.254.169.254 is still never handed to the transport - FAILS if the redirect recheck re-runs only the scope-tuple compare on redirected hops and skips resolution-pinning, since the tuple compare alone would pass this Location (the hostname genuinely is in scope.conf)'
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

# ===========================================================================
# docs/FOUNDATION.md tension 16: the rate limiter, the per-run request budget
# and the circuit breaker, all enforced at the http_request chokepoint.
# ===========================================================================
# These cases MEASURE behaviour - wall-clock elapsed time, exit status, and
# whether the stub transport was reached - rather than reading the limiter's
# own counters back.  A limiter asserted against its internal state passes
# just as happily when it never sleeps, which is the specific defect
# docs/FOUNDATION.md tension 24 / finding F14 already cost this repository
# once (`read -t </dev/null` returns at EOF instantly and does not sleep).
#
# The cross-process cases are the ones that pin tension 16 itself.  Each runs
# a FRESH bash process, exactly what `xargs -P "$JOBS"` produces, so any
# state the limiter, budget or breaker kept in a shell variable is invisible
# to it: `--jobs 8` would then admit 8x the request rate, an 8x budget, and a
# breaker that never trips because each worker only ever sees its own share
# of the failures.  Every cross-process case below names that reading as the
# one it fails under, and each was confirmed to fail before the state files
# existed (see this ticket's evidence).
printf '\n-- tension 16: the shared rate limiter (measured, not asserted) --\n'

LIMIT_DIR=$SCOURSH_SCRATCH/http-limits
_limits_reset() { rm -rf "${LIMIT_DIR:?}"; }

_now_ms() {
  local ns
  ns=$(now_epoch_ns)
  printf '%s' $(( ns / 1000000 ))
}

# A floor, never a ceiling: an upper bound on elapsed time would be a race
# against machine load, and the defect being pinned (no delay at all, or a
# per-process bucket that N workers each get a private copy of) always shows
# up as elapsed time that is too SMALL.
assert_at_least_ms() {
  local floor=$1 got=$2 msg=$3
  if (( got >= floor )); then
    _t_ok "$msg (measured ${got}ms, floor ${floor}ms)"
  else
    _t_no "$msg" "expected at least: [${floor}ms]" "measured: [${got}ms]"
  fi
}

# still-good.fixture.example is in scope under target fixture-good and, unlike
# good.fixture.example, the stub transport answers it 200 with no redirect, so
# every request below costs exactly one token.
RATE_URL='https://still-good.fixture.example/ok'

_limits_reset
: >"$TRANSPORT_LOG"
T0=$(_now_ms)
for _i in 1 2 3 4 5; do http_request GET "$RATE_URL" >/dev/null; done
T1=$(_now_ms)
assert_at_least_ms 950 $(( T1 - T0 )) \
  'the limiter genuinely DELAYS: 5 requests at the default 4/s take at least (5-1)/4 = 1.0s of wall clock - FAILS if http_request has no limiter at all, and FAILS under a limiter that computes a wait and never actually sleeps (finding F14 shows an exit-status probe cannot tell those apart, so this is measured)'
assert_eq 5 "$(wc -l <"$TRANSPORT_LOG" | tr -d ' ')" \
  'and all five requests really were issued - the elapsed time above is a throttle, not five refusals'

_limits_reset
: >"$TRANSPORT_LOG"
export SCOURSH_CONFIG_REQUESTS_PER_SECOND=100
T0=$(_now_ms)
for _i in 1 2 3 4 5; do http_request GET "$RATE_URL" >/dev/null; done
T1=$(_now_ms)
unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
assert_at_least_ms 950 $(( T1 - T0 )) \
  'a requests-per-second of 100 is clamped to the conservative ceiling of 4/s before the limiter ever sees it, so the same 5 requests still take 1.0s - FAILS if the limiter reads the operator value straight out of config (100/s would finish in ~40ms), which is the ceiling docs/STEP5-DAST-PLAN.md puts at the chokepoint rather than in a module'

printf '\n-- tension 16: the per-run request budget --\n'

# The budget ceiling is the one conservative default that diverges from the
# frozen rules/RULE-FORMAT.md §9.6.1 schema default (20000), so it is checked
# directly: proving it end to end would cost 5000 real requests.
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set request-budget 2>/dev/null
assert_eq 5000 "$_HTTP_EFF_LIMIT" \
  'the effective per-run budget is the conservative 5000, not the §9.6.1 schema default of 20000 - FAILS if the budget reads config_scanner_value without the module ceiling applied'

export SCOURSH_CONFIG_REQUEST_BUDGET=100000
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set request-budget 2>/dev/null
unset SCOURSH_CONFIG_REQUEST_BUDGET
assert_eq 5000 "$_HTTP_EFF_LIMIT" \
  'raising the configured budget far above the ceiling does not raise the effective one - the budget is a tunable that can only be lowered without an affirmation, and is never an off switch (docs/STEP5-DAST-PLAN.md: "the number is raisable; the existence of a finite budget is not")'

_limits_reset
: >"$TRANSPORT_LOG"
rm -rf "${W:?}/run.budget"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.budget"
export SCOURSH_CONFIG_REQUEST_BUDGET=3
rc=0
budget_err=$( ( for _i in 1 2 3 4; do http_request GET "$RATE_URL" >/dev/null; done ) 2>&1 >/dev/null ) || rc=$?
assert_eq 5 "$rc" \
  'the run stops at the budget ceiling with exit 5 (docs/FOUNDATION.md tension 14: "per-run request budget exhausted" is an incomplete run) - FAILS if the budget is absent, in which case all four requests succeed and the run exits 0'
assert_eq 3 "$(wc -l <"$TRANSPORT_LOG" | tr -d ' ')" \
  'exactly the budgeted three requests reached the transport; the fourth was stopped before the network, not after it'
assert_contains "$budget_err" 'budget' \
  'the run says WHY it stopped rather than silently returning fewer results'
assert_contains "$(cat "$SCOURSH_RUN_DIR/meta/incomplete_reason" 2>/dev/null || printf '')" 'budget' \
  'and it is recorded durably as the run incomplete_reason, so a report consumer can tell a budget-truncated run from a clean one - FAILS if the budget just returns early instead of dying through die 5'
unset SCOURSH_CONFIG_REQUEST_BUDGET
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

printf '\n-- tension 16: the circuit breaker --\n'

# Status is chosen by PATH so a single transport stub can serve both the
# failing and the succeeding request in one interleaved sequence.
_test_transport_by_path() {
  printf '%s %s\n' "$1" "$3" >>"$TRANSPORT_LOG"
  case $5 in
    /fail) printf '503\n\n' ;;
    *) printf '200\n\n' ;;
  esac
}

_limits_reset
: >"$TRANSPORT_LOG"
SCOURSH_HTTP_TRANSPORT=_test_transport_by_path
# Lowering the threshold is a tunable in the SAFE direction (a more sensitive
# breaker), which is why the ceiling clamps only upwards.  It keeps this case
# to four requests instead of nineteen.
export SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES=3
rc=0
http_request GET 'https://still-good.fixture.example/fail' >/dev/null || rc=$?
assert_eq 0 "$rc" 'one 5xx is recorded, not fatal'
rc=0
http_request GET 'https://still-good.fixture.example/fail' >/dev/null || rc=$?
assert_eq 0 "$rc" 'two 5xx responses, still below the configured threshold of 3, do not abort the run'
rc=0
http_request GET 'https://still-good.fixture.example/ok' >/dev/null || rc=$?
assert_eq 0 "$rc" 'a successful request interleaved between the failures is served normally'
rc=0
( http_request GET 'https://still-good.fixture.example/fail' >/dev/null ) || rc=$?
assert_eq 5 "$rc" \
  'the THIRD failure inside the window trips the breaker and exits 5, even though a success was interleaved before it - FAILS under a consecutive-failures reading, where the interleaved success resets the counter and this request is only failure number one. docs/FOUNDATION.md tension 16 freezes a ROLLING WINDOW ("the rolling window counters"), and docs/STEP5-DAST-PLAN.md states it as "10 failures in a 60s window"'

TRANSPORT_BEFORE=$(cat "$TRANSPORT_LOG")
rc=0
( http_request GET 'https://still-good.fixture.example/ok' >/dev/null ) || rc=$?
assert_eq 5 "$rc" \
  'once the breaker is open every later request in the run exits 5, including one that would have succeeded - tension 16 makes the abort flag a fan-out signal every worker checks BEFORE every request, not a per-caller return value'
assert_eq "$TRANSPORT_BEFORE" "$(cat "$TRANSPORT_LOG")" \
  'and that request never reached the transport - the breaker stops traffic, it does not merely report it'
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES
SCOURSH_HTTP_TRANSPORT=_test_transport

printf '\n-- tension 16: the state is SHARED ACROSS PROCESSES, not per-worker --\n'

# A fresh bash process per worker, which is what `xargs -P` gives: it inherits
# SCOURSH_SCRATCH (and nothing else that matters) through the environment, so
# file-backed state is shared and variable-backed state is not.  It never
# creates or erases a scratch directory of its own, because scratch_init
# returns early when it inherits one and SCOURSH_SCRATCH_OWNER is deliberately
# not exported (docs/FOUNDATION.md tension 4 rule 5, finding F13).
cat >"$W/limit-worker.sh" <<'WORKER_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
W_ROOT=$1 W_SCOPE=$2 W_URL=$3 W_COUNT=$4 W_LOG=$5
# shellcheck source=/dev/null
source "$W_ROOT/lib/http.sh"
_w_resolve() {
  case $1 in
    *.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_w_resolve
_w_transport() {
  printf '%s %s\n' "$1" "$3" >>"$W_LOG"
  case $5 in
    /fail) printf '503\n\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_w_transport
http_scope_load "$W_SCOPE"
for (( w_i = 0; w_i < W_COUNT; w_i++ )); do
  http_request GET "$W_URL" 0 fixture-good >/dev/null
done
WORKER_EOF

_limits_reset
: >"$W/wA.log"
: >"$W/wB.log"
T0=$(_now_ms)
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" 5 "$W/wA.log" &
PA=$!
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" 5 "$W/wB.log" &
PB=$!
rcA=0; wait "$PA" || rcA=$?
rcB=0; wait "$PB" || rcB=$?
T1=$(_now_ms)
assert_eq 0 "$rcA" 'the first concurrent worker process completed its requests'
assert_eq 0 "$rcB" 'the second concurrent worker process completed its requests'
assert_eq 10 "$(cat "$W/wA.log" "$W/wB.log" | wc -l | tr -d ' ')" \
  'ten requests were issued in total, five from each of two independent processes'
assert_at_least_ms 2000 $(( T1 - T0 )) \
  'TWO CONCURRENT PROCESSES SHARE ONE BUCKET: 10 requests through one 4/s bucket take at least (10-1)/4 = 2.25s no matter how many workers issue them - FAILS under per-process limiter state, where each worker runs its own 5-request 4/s bucket in parallel and the pair finishes in about 1.0s. This is the assertion tension 16 exists for: with a shell-variable bucket, --jobs 8 means 8x the request rate against a live target'

_limits_reset
: >"$W/wA.log"
: >"$W/wB.log"
export SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES=3
rcA=0
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" 'https://still-good.fixture.example/fail' 2 "$W/wA.log" || rcA=$?
assert_eq 0 "$rcA" 'the first worker process records two failures, below the threshold, and exits cleanly'
rcB=0
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" 'https://still-good.fixture.example/fail' 1 "$W/wB.log" || rcB=$?
assert_eq 5 "$rcB" \
  'a SECOND, INDEPENDENT process issuing the third failure trips the breaker and exits 5 - FAILS under per-process breaker state, where this process starts its count at zero, sees one failure, and never trips. That is tension 16 exactly: "eight workers each below threshold keep hammering a target that is comprehensively down"'
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES

_limits_reset
: >"$W/wA.log"
: >"$W/wB.log"
export SCOURSH_CONFIG_REQUEST_BUDGET=3
rcA=0
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" 2 "$W/wA.log" || rcA=$?
assert_eq 0 "$rcA" 'the first worker process spends two of the three budgeted requests and exits cleanly'
rcB=0
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" 2 "$W/wB.log" || rcB=$?
assert_eq 5 "$rcB" \
  'a SECOND, INDEPENDENT process draws down the SAME budget and exits 5 on the fourth request of the run - FAILS under per-process budget state, where each worker gets its own budget of 3 and both exit 0, which is tension 16'"'"'s "the per-run request budget is multiplied by 8"'
assert_eq 1 "$(wc -l <"$W/wB.log" | tr -d ' ')" \
  'and the second process issued exactly the one request the budget had left before being stopped'
unset SCOURSH_CONFIG_REQUEST_BUDGET

_limits_reset

# ===========================================================================
# The adversarial-review round on the tension-16 controls.
#
# Every case below reproduces a defect that the section above did NOT catch,
# and each was watched failing against the code as it stood before the fix
# beside it landed.  They are grouped here rather than merged into the
# sections above so the "what did the first round miss" answer stays legible.
# ===========================================================================

printf '\n-- an absurd circuit-breaker-window cannot switch the breaker off --\n'

# The window was clamped UP only (a floor of 60, because a SHORTER window is a
# weaker breaker), with no upper bound at all, so a schema-valid value wider
# than a 64-bit integer reached `cutoff=$(( now - window ))`.  Bash wraps the
# oversized literal, the cutoff lands in the FUTURE, every stored failure
# stamp prunes as out-of-window on every call, the count never reaches the
# threshold, and the breaker never opens - the one input the length-safe
# comparison was built for and the only one of the four it did not cover.
_limits_reset
export SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW=10000000000000000000
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set circuit-breaker-window 2>/dev/null
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW
assert_eq 86400 "$_HTTP_EFF_LIMIT" \
  'the breaker window is bounded from ABOVE as well as below: 60 is a floor, 86400 (a day) is the maximum, and any value beyond that is indistinguishable from a window that never expires - FAILS under an upper bound of "none", which is what let a config value reach the cutoff arithmetic unbounded'

_limits_reset
export SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW=5
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set circuit-breaker-window 2>/dev/null
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW
assert_eq 60 "$_HTTP_EFF_LIMIT" \
  'and adding that maximum did not disturb the floor: a window shorter than 60s is still raised to 60s, because a shorter window counts fewer failures towards the same threshold and is the weaker breaker'

_limits_reset
: >"$TRANSPORT_LOG"
SCOURSH_HTTP_TRANSPORT=_test_transport_by_path
export SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES=2
# 10^19, above the signed-64-bit maximum of 9223372036854775807, and valid
# against rules/RULE-FORMAT.md 9.6.1's `^(0|[1-9][0-9]*)$` shape for this key.
export SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW=10000000000000000000
rc=0
( http_request GET 'https://still-good.fixture.example/fail' >/dev/null ) || rc=$?
assert_eq 0 "$rc" 'the first failure under an absurd window is recorded, not fatal'
rc=0
( http_request GET 'https://still-good.fixture.example/fail' >/dev/null ) || rc=$?
assert_eq 5 "$rc" \
  'a circuit-breaker-window ABOVE the 64-bit range still trips the breaker at the configured threshold - FAILS while the window is clamped upwards only, where the oversized literal wraps, the rolling-window cutoff lands in the future, every stored failure stamp is pruned on every call, and one schema-valid config value silently disables the breaker entirely'
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW
SCOURSH_HTTP_TRANSPORT=_test_transport

printf '\n-- exit 5 and run.json can never disagree about a truncated run --\n'

# The consumer surface is run.json, not the meta record.  On budget exhaustion
# the run died with exit 5 without ever reaching the report writers, so in a
# combined scan the run directory kept the run.json an EARLIER module had
# already written: an empty incomplete_reason and a computed gate verdict, on
# a run the exit code calls truncated.  docs/FOUNDATION.md tension 14 makes a
# non-empty incomplete_reason exactly the exit-5 predicate, so the two must
# never be able to disagree.
cat >"$W/truncated-run.sh" <<'TRUNC_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
T_ROOT=$1 T_RUNDIR=$2 T_SCOPE=$3
# shellcheck source=/dev/null
source "$T_ROOT/lib/report.sh"
# shellcheck source=/dev/null
source "$T_ROOT/lib/http.sh"
_t_resolve() { case $1 in *.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_t_resolve
_t_transport() { printf '200\n\n'; }
SCOURSH_HTTP_TRANSPORT=_t_transport
http_scope_load "$T_SCOPE"
run_init "$T_RUNDIR"
# An earlier module of a combined scan finished and wrote the reports, exactly
# as modules/sast/run.sh, modules/sca/run.sh and modules/iac/run.sh each do.
report_all "$SCOURSH_RUN_DIR"
# A later module then runs out of request budget partway through.
for _t_i in 1 2 3 4 5; do
  http_request GET 'https://still-good.fixture.example/ok' 0 fixture-good >/dev/null
done
TRUNC_EOF

rm -rf "${W:?}/run.truncated"
rc=0
env -u SCOURSH_SCRATCH SCOURSH_CONFIG_REQUEST_BUDGET=3 \
  bash "$W/truncated-run.sh" "$ROOT" "$W/run.truncated" "$FIXTURE_SCOPE" >/dev/null 2>&1 || rc=$?
assert_eq 5 "$rc" 'the budget-truncated run really does exit 5'
assert_file_exists "$W/run.truncated/run.json" \
  'the run directory still carries the run.json an earlier module wrote'
trunc_json=$(cat "$W/run.truncated/run.json" 2>/dev/null || printf '')
assert_not_contains "$trunc_json" '"incomplete_reason": [],' \
  'WHENEVER the exit code is 5, run.json - the consumer surface, not the internal meta record - carries a non-empty incomplete_reason - FAILS while the abort exits the process without re-running the report writers, which leaves the previous module report_all in place claiming a complete run while the exit code says truncated (docs/FOUNDATION.md tension 14: run.json always records every condition that held)'
assert_contains "$trunc_json" 'budget' \
  'and run.json names the budget as the reason, so a report consumer can tell a truncated run from a clean one without reading the exit code out of band'
assert_contains "$(cat "$W/run.truncated/report.md" 2>/dev/null || printf '')" 'incomplete run' \
  'the markdown report the earlier module wrote is refreshed too, so the human-readable surface does not keep claiming a complete run either'
assert_contains "$(cat "$W/run.truncated/report.html" 2>/dev/null || printf '')" 'incomplete run' \
  'and so is the HTML one'

printf '\n-- K CONCURRENT worker processes race on one budget and one breaker --\n'

# The cross-process cases above run their two workers SEQUENTIALLY, so they
# prove the state is file-backed but can never observe a lost update: a
# refuter deleted BOTH mutex acquire/release pairs from lib/http.sh in a
# scratch copy and the whole suite still passed.  These cases race K workers
# on the same counters through a start barrier, so an unguarded
# read-modify-write really does lose updates, and each names that reading.
# Releases every worker at ONE wall-clock instant, and is the whole reason
# these cases can see a lost update at all.
#
# Process startup (sourcing lib/) costs far longer than an unguarded
# read-modify-write window is wide, so workers left to start on their own
# stagger themselves into an accidental serialisation and an unguarded counter
# still looks correct.  A `while [[ ! -e $go ]]; do msleep 20; done` barrier is
# not enough either: each poll forks a sleep, so the workers wake up spread
# over tens of milliseconds, which is still an eternity next to that window.
# Measured with that barrier alone, removing the mutex was caught in only 4
# runs out of 6.
#
# So the release is a DEADLINE rather than a flag: the parent writes an
# absolute epoch-millisecond time into the go file, every worker sleeps until
# 40ms before it and then spins on the clock, and they cross the line together.
# The spin is bounded by those 40ms, reads $EPOCHREALTIME directly so it costs
# no fork, and is skipped entirely on a shell that does not have it.
cat >"$W/race-barrier.sh" <<'BARRIER_EOF'
# shellcheck shell=bash
_race_barrier() {
  local ready=$1 go=$2 at='' now spins=0 us
  : >"$ready/$BASHPID"
  while :; do
    if [[ -s $go ]]; then
      IFS= read -r at <"$go" || at=''
      [[ $at =~ ^[0-9]+$ ]] && break
    fi
    msleep 20
    spins=$(( spins + 1 ))
    (( spins < 1500 )) || return 1
  done
  now=$(now_epoch_ns)
  now=$(( now / 1000000 ))
  if (( at - 40 > now )); then msleep $(( at - 40 - now )); fi
  if [[ -n ${EPOCHREALTIME:-} && $EPOCHREALTIME =~ ^[0-9]+\.[0-9]+$ ]]; then
    while :; do
      us=${EPOCHREALTIME%.*}${EPOCHREALTIME#*.}
      (( 10#$us / 1000 >= at )) && break
    done
  fi
  return 0
}
BARRIER_EOF

cat >"$W/race-worker.sh" <<'RACE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
W_ROOT=$1 W_SCOPE=$2 W_URL=$3 W_COUNT=$4 W_LOG=$5 W_READY=$6 W_GO=$7
# shellcheck source=/dev/null
source "$W_ROOT/lib/http.sh"
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/race-barrier.sh"
_w_resolve() {
  case $1 in
    *.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_w_resolve
_w_transport() {
  printf '%s %s\n' "$1" "$3" >>"$W_LOG"
  case $5 in
    /fail) printf '503\n\n' ;;
    *) printf '200\n\n' ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_w_transport
http_scope_load "$W_SCOPE"
_race_barrier "$W_READY" "$W_GO"
for (( w_i = 0; w_i < W_COUNT; w_i++ )); do
  http_request GET "$W_URL" 0 fixture-good >/dev/null
done
RACE_EOF

# A worker that already has its failing response in hand and is recording it,
# which is the only part of a request that touches the breaker counter.  It
# takes the same mutex through the same function a real 5xx does, and skipping
# the transport is deliberate: the rate limiter would otherwise space these
# calls 250ms apart, and a race whose participants are handed to the shared
# counter one at a time is not a race.
cat >"$W/brk-worker.sh" <<'BRK_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
W_ROOT=$1 W_TH=$2 W_READY=$3 W_GO=$4
# shellcheck source=/dev/null
source "$W_ROOT/lib/http.sh"
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/race-barrier.sh"
_race_barrier "$W_READY" "$W_GO"
_http_breaker_record_failure fixture-good "$W_TH" 60
BRK_EOF

RACE_K=12
# The worker count for the breaker counter race.  It is not bounded by the
# conservative failure-threshold ceiling of 10, because these workers pass the
# threshold to `_http_breaker_record_failure` directly rather than resolving it
# from config, so the threshold can sit ABOVE the worker count.
BRK_K=16
BRK_TH=$(( BRK_K + 1 ))

_race_ready_count() {
  local -a f=("$W"/ready/*)
  local n=0 p
  for p in "${f[@]}"; do
    [[ -e $p ]] || continue
    n=$(( n + 1 ))
  done
  printf '%s' "$n"
}

# `_race_release K` - wait for K workers to report ready, then set the deadline.
_race_release() {
  local k=$1 spins=0 t
  while (( $(_race_ready_count) < k )); do
    msleep 20
    spins=$(( spins + 1 ))
    (( spins < 1500 )) || break
  done
  t=$(now_epoch_ns)
  printf '%s\n' $(( t / 1000000 + 400 )) >"$W/go"
}

_race_reset() {
  rm -rf "${W:?}/ready"
  mkdir -p "$W/ready"
  rm -f "${W:?}/go"
}

# `_race_run URL PER_WORKER` - K workers, all released at once, all waited on.
_race_run() {
  local url=$1 per=$2 k pid
  local -a pids=()
  _race_reset
  rm -f "${W:?}"/race-*.log
  for (( k = 0; k < RACE_K; k++ )); do
    bash "$W/race-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$url" "$per" \
      "$W/race-$k.log" "$W/ready" "$W/go" &
    pids+=($!)
  done
  _race_release "$RACE_K"
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done
}

_race_total() {
  local -a f=("$W"/race-*.log)
  local n=0 p line
  for p in "${f[@]}"; do
    [[ -e $p ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      n=$(( n + 1 ))
    done <"$p"
  done
  printf '%s' "$n"
}

_limits_reset
export SCOURSH_CONFIG_REQUEST_BUDGET=7
_race_run "$RATE_URL" 3
unset SCOURSH_CONFIG_REQUEST_BUDGET
assert_eq 7 "$(_race_total)" \
  "$RACE_K CONCURRENT worker processes released together against a per-run budget of 7 send EXACTLY 7 requests, out of the 36 they are between them trying to send - FAILS with the budget counter's mutex removed, where every worker reads the same remaining count in the same instant, every one of them writes the same decrement, and the run spends one unit of budget for each worker that raced instead of one for each request"

# The breaker counter is raced with a threshold ABOVE the worker count, and the
# assertion is on WHETHER THE BREAKER OPENS rather than on how much traffic it
# let through.
#
# That is deliberate, and the traffic form was tried first and rejected on
# measurement.  Asserting "exactly the threshold reached the transport" is
# two-sided under an unguarded counter: lost updates send too many, but
# concurrent whole-line rewrites of the state file can also make one worker
# read a count that opens the breaker EARLY, so the broken run lands on the
# right number by coincidence.  Measured, that coincidence happened in 2 runs
# out of 8 - a test that certifies the defect green a quarter of the time pins
# nothing.  Recording exactly threshold-minus-one failures and then asking
# whether the next one opens the breaker is one-sided instead: a lost update
# can only leave the count SHORT, and a short count cannot open it.
_limits_reset
_race_reset
brk_pids=()
for (( brk_k = 0; brk_k < BRK_K; brk_k++ )); do
  bash "$W/brk-worker.sh" "$ROOT" "$BRK_TH" "$W/ready" "$W/go" &
  brk_pids+=($!)
done
_race_release "$BRK_K"
brk_ok=0
for brk_pid in "${brk_pids[@]}"; do
  brk_rc=0
  wait "$brk_pid" || brk_rc=$?
  if (( brk_rc == 0 )); then brk_ok=$(( brk_ok + 1 )); fi
done
assert_eq "$BRK_K" "$brk_ok" \
  "all $BRK_K concurrent workers record their failure and none of them opens a breaker whose threshold is $BRK_TH"
brk_rc=0
( _http_breaker_record_failure fixture-good "$BRK_TH" 60 ) >/dev/null 2>&1 || brk_rc=$?
assert_eq 5 "$brk_rc" \
  "the very next failure is the ${BRK_TH}th and opens the breaker, which is only true if all $BRK_K concurrent workers' failures were actually counted - FAILS with the breaker counter's mutex removed, where their read-modify-writes overwrite each other, the rolling count is short by however many raced, and the breaker never opens: tension 16's \"eight workers each below threshold keep hammering a target that is comprehensively down\""
: >"$TRANSPORT_LOG"
brk_rc=0
( http_request GET 'https://still-good.fixture.example/ok' >/dev/null ) || brk_rc=$?
assert_eq 5 "$brk_rc" \
  'and the run really is stopped afterwards: the next request to that target is refused'
assert_eq '' "$(cat "$TRANSPORT_LOG")" \
  'without reaching the transport'

printf '\n-- a worker already queued for a token stops when the breaker opens --\n'

# The abort flag was checked BEFORE the throttle wait and never again, so
# every worker already parked for a token when the breaker opened still sent
# its request: threshold plus workers-minus-one requests to a target that is
# comprehensively down, not threshold.  The asymmetry is the evidence it was
# an oversight - the BUDGET check sits inside the retry loop and is
# re-evaluated after every sleep, so the budget is exact.
cat >"$W/open-breaker.sh" <<'OPEN_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
O_ROOT=$1
# shellcheck source=/dev/null
source "$O_ROOT/lib/http.sh"
# A second worker that already has its failing response in hand and is
# recording it.  Threshold 1, so this failure opens the breaker and writes the
# fan-out abort flag, exactly as any worker crossing the threshold would.
_http_breaker_record_failure fixture-good 1 60
OPEN_EOF

_limits_reset
: >"$W/wA.log"
# 0.5 requests/second, so the SECOND request of the parked worker waits two
# full seconds for its token: a wide, deterministic window to open the breaker
# underneath it.  Lowering the rate is a tunable in the safe direction, which
# is why the ceiling clamps it downwards only.
export SCOURSH_CONFIG_REQUESTS_PER_SECOND=0.5
bash "$W/limit-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" 2 "$W/wA.log" &
PARKED=$!
msleep 700
rcOpen=0
bash "$W/open-breaker.sh" "$ROOT" >/dev/null 2>&1 || rcOpen=$?
rcParked=0
wait "$PARKED" || rcParked=$?
unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
assert_eq 5 "$rcOpen" 'the second process opens the breaker and exits 5'
assert_eq 1 "$(wc -l <"$W/wA.log" | tr -d ' ')" \
  'a worker already parked in a throttle wait when the breaker opens sends NOTHING further - FAILS while the abort flag is checked only before the wait, where every worker queued for a token during the window in which the breaker opens still reaches the transport, so a comprehensively-down target receives threshold plus workers-minus-one requests instead of threshold'
assert_eq 5 "$rcParked" \
  'and the parked worker exits 5 rather than completing, so its truncated coverage is stated rather than silent'

printf '\n-- the clamp warns only when the OPERATOR raised something --\n'

# The request-budget schema default is 20000 and the DAST ceiling is 5000, so
# the clamp warned on every single run, including one with no config file at
# all, and blamed a value the operator never wrote.
_limits_reset
_http_effective_limit_set request-budget 2>"$W/clamp.log"
assert_eq 5000 "$_HTTP_EFF_LIMIT" \
  'the effective budget is still the conservative 5000 even when the resolved value is the schema default'
assert_eq '' "$(cat "$W/clamp.log")" \
  'and the clamp prints NO warning when the value it clamped is the built-in schema default, i.e. when no operator ever asked for it - FAILS while the clamp warns on any difference between resolved and effective, which fires on every run of an unconfigured install and names a config nobody wrote'

_limits_reset
export SCOURSH_CONFIG_REQUEST_BUDGET=100000
_http_effective_limit_set request-budget 2>"$W/clamp.log"
unset SCOURSH_CONFIG_REQUEST_BUDGET
clamp_out=$(cat "$W/clamp.log")
assert_eq 5000 "$_HTTP_EFF_LIMIT" 'a raised budget is still clamped to the ceiling'
assert_contains "$clamp_out" '100000' \
  'a budget the operator actually raised DOES warn, and names the value that was refused - FAILS if suppressing the default-value warning also suppressed the one case the warning exists for'

printf '\n-- a very slow rate is not refused as if it were zero --\n'

_rate_refusal() {
  local rc=0 out
  out=$( ( _http_effective_rps_milli_set ) 2>&1 >/dev/null ) || rc=$?
  printf '%s\n%s' "$rc" "$out"
}

export SCOURSH_CONFIG_REQUESTS_PER_SECOND=0
rate_msg=$(_rate_refusal)
unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
assert_contains "$rate_msg" 'permits no requests at all' \
  'a genuinely zero rate is still refused as permitting no requests at all'

export SCOURSH_CONFIG_REQUESTS_PER_SECOND=0.0005
rate_msg=$(_rate_refusal)
unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
assert_not_contains "$rate_msg" 'permits no requests at all' \
  'a POSITIVE rate below the limiter resolution is not described as permitting no requests at all - FAILS while the rate is truncated to three decimal places before the zero test, which calls a deliberately very slow rate zero and then tells the operator to send MORE traffic'
assert_contains "$rate_msg" '0.001' \
  'and the refusal names the precision floor and the smallest supported rate, so the operator can act on it'

printf '\n-- a refusal prints ONE message, not a second crash-shaped line --\n'

# `die` inside a command substitution runs in a subshell, where clearing the
# ERR trap only clears the subshell's; the parent's trap then fires on the
# failed assignment and prints a "command failed" diagnostic after the real
# message.  scan.sh already carries an explicit guard and a long comment about
# exactly this, and the limit resolutions added four more such sites per
# request.  They SET variables now, which removes the second line and the four
# forks together.
cat >"$W/one-message.sh" <<'ONE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
M_ROOT=$1 M_SCOPE=$2
# shellcheck source=/dev/null
source "$M_ROOT/lib/http.sh"
_m_resolve() { case $1 in *.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_m_resolve
_m_transport() { printf '200\n\n'; }
SCOURSH_HTTP_TRANSPORT=_m_transport
http_scope_load "$M_SCOPE"
http_request GET 'https://still-good.fixture.example/ok' 0 fixture-good >/dev/null
ONE_EOF

one_out=$(env -u SCOURSH_SCRATCH SCOURSH_CONFIG_REQUESTS_PER_SECOND=0 \
  bash "$W/one-message.sh" "$ROOT" "$FIXTURE_SCOPE" 2>&1 >/dev/null || printf '')
assert_contains "$one_out" 'permits no requests at all' \
  'an unusable rate is refused with its real message'
assert_not_contains "$one_out" 'command failed' \
  'and NOTHING else - a refusal prints one message, never a second crash-shaped diagnostic naming an internal assignment - FAILS while the limit resolutions are read through $(...), where the die runs in a subshell whose cleared ERR trap is not the parent one'

printf '\n-- a coarse clock is stated, not silently four times slower --\n'

# On a host with no sub-second clock the capacity-one bucket can only refill
# at a second boundary, so the effective rate becomes one per second rather
# than the configured four.  The direction is safe; the silence is not.
cat >"$W/coarse-clock.sh" <<'CLOCK_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
C_ROOT=$1
# shellcheck source=/dev/null
source "$C_ROOT/lib/http.sh"
_http_limit_dir_set
CLOCK_EOF

clock_out=$(env -u SCOURSH_SCRATCH SCOURSH_CAPS_PROBED='' SCOURSH_CAP_CLOCK=seconds SCOURSH_CLOCK_NS=0 \
  bash "$W/coarse-clock.sh" "$ROOT" 2>&1 >/dev/null || printf '')
assert_contains "$clock_out" 'whole seconds' \
  'the limiter warns once at start when the host has no sub-second clock, because the capacity-one bucket can then only refill on a second boundary and the effective rate silently drops to one per second - FAILS while the fallback is undisclosed, which leaves a four-times-slower run with no stated cause'

printf '\n-- several scope targets on ONE host are disclosed, not hidden --\n'

# tension 16 freezes "one bucket per scope target", so N scope targets that
# resolve to the same address each get their own full rate and that one host
# receives N times the configured rate.  Two hostnames behind one load
# balancer are two natural scope entries, so this is an ordinary
# configuration rather than an exotic one.  The keying is the register's, and
# is kept; what changes is that the run says so, at the moment it is true,
# rather than leaving the operator-facing risk statement silent on the unsafe
# direction.
_limits_reset
: >"$TRANSPORT_LOG"
rm -rf "${W:?}/run.sharedaddr"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.sharedaddr"
http_request GET 'https://still-good.fixture.example/ok' 0 fixture-good >/dev/null 2>"$W/sa1.log"
http_request GET 'https://sub.wide.fixture.example/ok' 0 fixture-wide >/dev/null 2>"$W/sa2.log"
shared_warn=$(cat "$W/sa2.log")
assert_contains "$shared_warn" '93.184.216.34' \
  'when a second scope target resolves to an address a first one is already rate-limited against, the run warns and names the shared address - FAILS while per-target bucket keying is left undisclosed, where one host quietly receives N times the configured rate for N scope entries pointing at it'
assert_contains "$shared_warn" 'fixture-wide' \
  'and names the targets that share it, so the operator can see which entries are multiplying the rate'
shared_gap=$(cat "$SCOURSH_RUN_DIR/meta/coverage_gap" 2>/dev/null || printf '')
assert_contains "$shared_gap" '93.184.216.34' \
  'and it is recorded as a run-level coverage_gap, so run.json carries the disclosure rather than only a terminal that has scrolled'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

_limits_reset

t_summary 'http'
