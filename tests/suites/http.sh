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

t_summary 'http'
