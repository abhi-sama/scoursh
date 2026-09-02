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
# ADVERSARIAL SUITE ADDENDUM (PR #9, "Adversarial test suite: attempt
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

# ---------------------------------------------------------------------------
# The one DAST-32 case that has to run BEFORE anything issues a request.
# ---------------------------------------------------------------------------
# Its subject is the DEFAULT resolution layer, and the reading it rejects -
# "any value above the ceiling is fatal" - makes an install with no config file
# at all unable to send a single request, because request-budget's §9.6.1
# default of 20000 is itself above the 5000 DAST ceiling.  Under that reading
# every http_request case below aborts the whole suite process before reaching
# the DAST-32 section at the end of this file, so the failure would be an
# aborted run rather than a named assertion.  Placed here, it is the FIRST
# thing to go red, which is what makes it a pin rather than a casualty.
t_case 'an unedited install resolves the budget without dying'
default_rc=0
default_eff=$( ( _http_effective_limit_set request-budget \
  && printf '%s' "$_HTTP_EFF_LIMIT" ) 2>/dev/null ) || default_rc=$?
assert_eq 0 "$default_rc" \
  'resolving request-budget with NO config file at all is not fatal - FAILS under "any resolved value above the ceiling is a usage error", where the §9.6.1 default of 20000 exceeds the 5000 DAST ceiling and a fresh clone therefore cannot send one request without an affirmation, which is exactly the "affirm reflexively to make the tool work" outcome docs/STEP5-DAST-PLAN.md rejects'
assert_eq 5000 "$default_eff" \
  'and the default is silently clamped to the conservative ceiling, because warning here would be blaming the operator for a config they never wrote'

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
assert_eq 'https://good.fixture.example:443/x' "$_HTTP_LAST_URL" \
  '_HTTP_LAST_URL on the "redirect not followed, gate declined" early return names the hop that actually produced the returned response, never the rejected Location - FAILS under code with no _HTTP_LAST_URL (empty), and would also fail under a naive "publish whatever http_gate_url last computed" implementation, since the rejected-Location gate call at that point has already overwritten _HTTP_GATE_CANON with the evil.example candidate'

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
# The ticket case: a redirect that crosses ORIGIN, landing on a response
# `_HTTP_LAST_URL` must name - not the URL this call was first asked to
# fetch.  Before lib/http.sh published this, a caller resolving a relative
# reference on the delivered document (markup.sh's SRI/tabnabbing/CSRF
# checks, cors.sh, leakage.sh) had only the requested URL available and
# resolved against the WRONG origin on exactly this shape of redirect.
assert_eq 'https://still-good.fixture.example:443/y' "$_HTTP_LAST_URL" \
  '_HTTP_LAST_URL is the LANDING URL of a cross-origin redirect chain that stayed in scope, not the URL originally requested - FAILS under current code, where _HTTP_LAST_URL does not exist at all (empty/unbound)'
assert_ne 'https://good.fixture.example:443/x' "$_HTTP_LAST_URL" \
  '_HTTP_LAST_URL is NOT the originally-requested URL once a redirect has moved the response to a different origin - the naive "just use the URL the caller passed in" reading this ticket exists to replace'
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

# The clamp is measured through a config FILE value, not an env var, and that
# is not incidental: docs/STEP5-DAST-PLAN.md's DAST-32 clamp policy is
# ASYMMETRIC, and only the file/default half clamps.  An env or CLI value above
# the ceiling is a usage error instead, which the "-- DAST-32 --" section below
# pins separately.  Writing this case with an env var (as it was, before the
# affirmation existed) would now be asserting the clamp on the one resolution
# layer that no longer clamps.
cat >"$W/scanner-fast.conf" <<'EOF'
id: scanner
requests-per-second: 100
EOF
# `$W/scanner-absent.conf` is deliberately never created: `config_scanner_load`
# treats an absent file as "every key resolves through env/default", which is
# how each case below returns the loader to its unconfigured state without
# leaking a fixture into the next one.
_limits_reset
: >"$TRANSPORT_LOG"
config_scanner_load "$W/scanner-fast.conf"
T0=$(_now_ms)
for _i in 1 2 3 4 5; do http_request GET "$RATE_URL" >/dev/null; done
T1=$(_now_ms)
config_scanner_load "$W/scanner-absent.conf"
assert_at_least_ms 950 $(( T1 - T0 )) \
  'a config-FILE requests-per-second of 100 is clamped to the conservative ceiling of 4/s before the limiter ever sees it, so the same 5 requests still take 1.0s - FAILS if the limiter reads the operator value straight out of config (100/s would finish in ~40ms), which is the ceiling docs/STEP5-DAST-PLAN.md puts at the chokepoint rather than in a module'

printf '\n-- tension 16: the per-run request budget --\n'

# The budget ceiling is the one conservative default that diverges from the
# frozen rules/RULE-FORMAT.md §9.6.1 schema default (20000), so it is checked
# directly: proving it end to end would cost 5000 real requests.
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set request-budget 2>/dev/null
assert_eq 5000 "$_HTTP_EFF_LIMIT" \
  'the effective per-run budget is the conservative 5000, not the §9.6.1 schema default of 20000 - FAILS if the budget reads config_scanner_value without the module ceiling applied'

cat >"$W/scanner-bigbudget.conf" <<'EOF'
id: scanner
request-budget: 100000
EOF
config_scanner_load "$W/scanner-bigbudget.conf"
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set request-budget 2>/dev/null
config_scanner_load "$W/scanner-absent.conf"
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

# THE HANDOFF IS A RENDEZVOUS, NEVER A WALL CLOCK, and that is this case's own
# hard-won lesson rather than a style preference.
#
# It used to be `msleep 700` in the parent: fork the worker, sleep, then open
# the breaker, ASSUMING that within those 700ms the worker had started bash,
# sourced lib/http.sh, parsed the scope file, sent its first request and parked
# for the second.  Under CPU contention - which is the ordinary condition when
# a parallel fleet runs this suite - that assumption is simply false.  Measured
# on an 18-core host with 72 spinner processes: 11 failures in 20 runs of this
# case alone, and EVERY ONE of them with `wA.log` EMPTY.  Empty means the
# worker had not yet reached its first `_http_abort_check` when the flag was
# written, saw it, and correctly refused to send anything at all.
#
# So the race was the TEST's, not the breaker's, and the log tells the two
# apart with no ambiguity: 2 lines is the product defect this case exists to
# catch (the flag read only before the wait), 1 line is correct, 0 lines is the
# test having lost its own race.  Widening the 700ms would only have moved the
# window; the window is the bug.
#
# The worker now announces on a FIFO that it is INSIDE the throttle's sleep,
# blocks on a second FIFO until the parent has opened the breaker, and only
# then lets that sleep run out.  That places the flag's appearance strictly
# between the pre-throttle abort check and the post-sleep one, which is the
# only window in which this assertion tests anything - and it is the window the
# wall clock was trying, and failing, to hit.  No elapsed time anywhere in the
# case decides its outcome.
cat >"$W/parked-worker.sh" <<'PARKED_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
P_ROOT=$1 P_SCOPE=$2 P_URL=$3 P_LOG=$4 P_PARKED=$5 P_GO=$6
# shellcheck source=/dev/null
source "$P_ROOT/lib/http.sh"
_p_resolve() { case $1 in *.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_p_resolve
_p_transport() { printf '%s %s\n' "$1" "$3" >>"$P_LOG"; printf '200\n\n'; }
SCOURSH_HTTP_TRANSPORT=_p_transport

# The real msleep is RENAMED, not reimplemented, so the throttle still sleeps
# through the product's own code (finding F14's FIFO read included) rather
# than through a stand-in this file invented.
_p_msleep_src=$(declare -f msleep)
eval "${_p_msleep_src/#msleep/_p_real_msleep}"

# Opened read-write, so the open itself never blocks and a parent that died
# cannot wedge this worker; read with a timeout, so a worker that never
# reaches the park fails the case rather than hanging the suite.  Neither is a
# tolerance: no outcome of this case depends on either number.
exec {P_GOFD}<>"$P_GO"

# Armed for the SECOND request only.  `mutex_acquire` also calls msleep when
# it finds the lock held, and a contended mutex during the FIRST request would
# otherwise be mistaken for the throttle's own park.
P_ARMED=0
msleep() {
  if (( P_ARMED )); then
    P_ARMED=0
    printf 'parked\n' >"$P_PARKED"
    read -r -t 60 -u "$P_GOFD" _ || true
    # The flag is on disk by the time this returns, so what remains of the
    # throttle's wait cannot change the outcome - only that the loop takes its
    # post-sleep branch at all, which it does either way.  A 1ms real sleep
    # keeps the product's sleep in the path without paying the deliberately
    # long token interval below.
    _p_real_msleep 1
    return 0
  fi
  _p_real_msleep "$@"
}

http_scope_load "$P_SCOPE"
http_request GET "$P_URL" 0 fixture-good >/dev/null
P_ARMED=1
http_request GET "$P_URL" 0 fixture-good >/dev/null
PARKED_EOF

_limits_reset
: >"$W/wA.log"
rm -f "$W/parked.fifo" "$W/go.fifo"
mkfifo "$W/parked.fifo" "$W/go.fifo"
# Both ends are held open read-write by the parent for the whole case, so
# neither side's open() can block on the other not having arrived yet.
exec {PARKEDFD}<>"$W/parked.fifo"
exec {GOFD}<>"$W/go.fifo"
# 0.1 requests/second, so the second request's token is ten seconds away.  The
# number is NOT a timing margin for the handoff - the rendezvous is what
# guarantees the park is entered before the breaker opens.  It is there so the
# bucket is unambiguously empty when the second request reads it: at a fast
# rate a worker descheduled between its two requests could refill the bucket
# and be granted a token without ever parking, which is the same wall-clock
# assumption in a new place.  Lowering the rate is a tunable in the safe
# direction, which is why the ceiling clamps it downwards only.
export SCOURSH_CONFIG_REQUESTS_PER_SECOND=0.1
bash "$W/parked-worker.sh" "$ROOT" "$FIXTURE_SCOPE" "$RATE_URL" \
  "$W/wA.log" "$W/parked.fifo" "$W/go.fifo" &
PARKED=$!
read -r -t 60 -u "$PARKEDFD" _ || true
rcOpen=0
bash "$W/open-breaker.sh" "$ROOT" >/dev/null 2>&1 || rcOpen=$?
printf 'go\n' >&"$GOFD"
rcParked=0
wait "$PARKED" || rcParked=$?
unset SCOURSH_CONFIG_REQUESTS_PER_SECOND
exec {PARKEDFD}>&-
exec {GOFD}>&-
assert_eq 5 "$rcOpen" 'the second process opens the breaker and exits 5'
assert_eq 1 "$(wc -l <"$W/wA.log" | tr -d ' ')" \
  'a worker already parked in a throttle wait when the breaker opens sends NOTHING further - FAILS with 2 while the abort flag is checked only before the wait, where every worker queued for a token during the window in which the breaker opens still reaches the transport, so a comprehensively-down target receives threshold plus workers-minus-one requests instead of threshold; a 0 here would mean the rendezvous above broke and the worker never reached its first request, which is a defect in this case rather than in the breaker'
assert_eq 5 "$rcParked" \
  'and the parked worker exits 5 rather than completing, so its truncated coverage is stated rather than silent'

# ===========================================================================
printf '\n-- section 11b: the IN-FLIGHT ceiling, measured on observed simultaneous connections --\n'
# ===========================================================================
# These cases assert on how many connections were OPEN AT ONCE, never on a
# return value, because "it refused" must not be satisfiable by a path that
# opened the connections and then returned 0.  The observation is made inside
# the stub transport - the only interval in which a connection to the target
# exists - by planting a marker directory, counting how many markers exist at
# that instant, and holding the marker until every worker has arrived or a
# bounded number of ticks has passed.  The maximum over every sample any
# worker took is the run's observed concurrency.
#
# A rate limiter cannot be substituted for this measurement and that is the
# whole point of the ticket: the shared bucket already spaces requests 250ms
# apart at the default 4/s, and a transport that holds its connection for
# longer than that puts several of them in flight simultaneously while the
# average rate stays under the ceiling.  Every case below is therefore run
# with a transport that HOLDS, because a transport that returns instantly
# cannot tell a bounded run from an unbounded one.
#
# The counting is per WORKER file rather than one shared log, so no assertion
# here can be decided by two processes interleaving their appends.

INFLIGHT_MARKERS=$W/inflight-markers

cat >"$W/inflight-worker.sh" <<'INFLIGHT_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
I_LIB=$1 I_SCOPE=$2 I_URL=$3 I_MARK=$4 I_LOG=$5 I_READY=$6 I_GO=$7 I_K=$8 I_N=$9
# shellcheck source=/dev/null
source "$I_LIB/lib/http.sh"
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/race-barrier.sh"
_i_resolve() { case $1 in *.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_i_resolve

_i_marker_count() {
  local -a f=("$I_MARK"/*)
  local n=0 p
  for p in "${f[@]}"; do
    if [[ -e $p ]]; then n=$(( n + 1 )); fi
  done
  printf '%s' "$n"
}

# Sampling on EVERY tick rather than only at plant time is what makes the
# maximum a real maximum: the worker that planted first would otherwise report
# 1 however many joined it afterwards, and the run would look bounded whatever
# it did.
_i_transport() {
  local m spins=0
  m=$(mktemp -d "$I_MARK/m.XXXXXX")
  printf '%s\n' "$(_i_marker_count)" >>"$I_LOG"
  while (( $(_i_marker_count) < I_K )); do
    msleep 25
    printf '%s\n' "$(_i_marker_count)" >>"$I_LOG"
    spins=$(( spins + 1 ))
    if (( spins >= 32 )); then break; fi
  done
  rmdir "$m"
  printf '200\n\n'
}
SCOURSH_HTTP_TRANSPORT=_i_transport
http_scope_load "$I_SCOPE"
_race_barrier "$I_READY" "$I_GO"
for (( i_i = 0; i_i < I_N; i_i++ )); do
  http_request GET "$I_URL" 0 fixture-good >/dev/null
done
INFLIGHT_EOF

# `_inflight_run LIBROOT K PER` - K fresh worker processes, released together
# through the same deadline barrier the budget/breaker races use, each issuing
# PER requests.  Sets `_INFLIGHT_MAX` (the largest simultaneous-connection
# count any worker observed), `_INFLIGHT_SAMPLES` and `_INFLIGHT_FAILED`.
_inflight_run() {
  local lib=$1 k=$2 per=$3 i pid rc p line
  local -a pids=() logs=()
  rm -rf "${INFLIGHT_MARKERS:?}"
  mkdir -p "$INFLIGHT_MARKERS"
  rm -f "${W:?}"/inflight-*.log
  _race_reset
  _limits_reset
  for (( i = 0; i < k; i++ )); do
    bash "$W/inflight-worker.sh" "$lib" "$FIXTURE_SCOPE" "$RATE_URL" \
      "$INFLIGHT_MARKERS" "$W/inflight-$i.log" "$W/ready" "$W/go" "$k" "$per" &
    pids+=($!)
  done
  _race_release "$k"
  _INFLIGHT_FAILED=0
  for pid in "${pids[@]}"; do
    rc=0
    wait "$pid" || rc=$?
    if (( rc != 0 )); then _INFLIGHT_FAILED=$(( _INFLIGHT_FAILED + 1 )); fi
  done
  _INFLIGHT_MAX=0
  _INFLIGHT_SAMPLES=0
  logs=("$W"/inflight-*.log)
  for p in "${logs[@]}"; do
    [[ -e $p ]] || continue
    while IFS= read -r line; do
      [[ $line =~ ^[0-9]+$ ]] || continue
      _INFLIGHT_SAMPLES=$(( _INFLIGHT_SAMPLES + 1 ))
      if (( line > _INFLIGHT_MAX )); then _INFLIGHT_MAX=$line; fi
    done <"$p"
  done
  return 0
}

t_case 'the ceiling bites: 3 worker processes, jobs 1'
export SCOURSH_CONFIG_JOBS=1
_inflight_run "$ROOT" 3 1
unset SCOURSH_CONFIG_JOBS
assert_eq 1 "$_INFLIGHT_MAX" \
  'THREE CONCURRENT WORKER PROCESSES SHARE ONE IN-FLIGHT SLOT: at no instant were two connections open at once - FAILS under a per-process counter, where each of the three workers holds its own private slot and `--jobs N` means N times the ceiling, which is the exact failure docs/FOUNDATION.md tension 16 exists for; and FAILS under no counter at all, which is what docs/STEP5-DAST-PLAN.md'"'"'s concurrency row said was enforced by nothing'
assert_eq 0 "$_INFLIGHT_FAILED" \
  'and all three workers completed rather than timing out - a ceiling that bites by wedging the run is not a ceiling'
inflight_ok=false
if (( _INFLIGHT_SAMPLES >= 3 )); then inflight_ok=true; fi
assert_true "$inflight_ok" \
  'and all three requests really reached the transport, so the bound above is a throttle rather than three refusals'

# The refutation, run rather than asserted.  A `_INFLIGHT_MAX` of 1 above is
# only evidence if the same fixture reports more than 1 when the slot is not
# taken, and the identical shape of vacuity tests/suites/gate-mutation-proof.sh
# exists for applies here: without this, a fixture whose workers happened never
# to overlap would certify an absent semaphore green.
INFLIGHT_LIB=$W/mut-inflight
INFLIGHT_OLD='    _http_inflight_acquire "$bucket" "$inflight_max"'
INFLIGHT_NEW='    : # MUTATED by tests/suites/http.sh: the in-flight slot is not taken'

t_case 'the in-flight mutation guard'
inflight_n=$(grep -c -F -- "$INFLIGHT_OLD" "$ROOT/lib/http.sh" 2>/dev/null || true)
assert_eq 1 "$inflight_n" \
  'exactly one occurrence of the acquire call in the REAL source - fails loudly if a refactor changed its text, rather than silently mutating nothing and certifying a stale proof green'

rm -rf "${INFLIGHT_LIB:?}"
mkdir -p "$INFLIGHT_LIB/lib"
cp "$ROOT"/lib/*.sh "$INFLIGHT_LIB/lib/"
inflight_content=$(cat "$INFLIGHT_LIB/lib/http.sh")
inflight_content=${inflight_content/"$INFLIGHT_OLD"/"$INFLIGHT_NEW"}
printf '%s\n' "$inflight_content" >"$INFLIGHT_LIB/lib/http.sh"
inflight_n=$(grep -c -F -- "$INFLIGHT_OLD" "$INFLIGHT_LIB/lib/http.sh" 2>/dev/null || true)
assert_eq 0 "$inflight_n" 'the scratch copy no longer takes an in-flight slot'

t_case 'and the same fixture DOES observe three at once with the slot removed'
export SCOURSH_CONFIG_JOBS=1
_inflight_run "$INFLIGHT_LIB" 3 1
unset SCOURSH_CONFIG_JOBS
assert_eq 3 "$_INFLIGHT_MAX" \
  'with `_http_inflight_acquire` removed, the identical three workers put THREE connections on the target at once while the 4/s rate limiter is untouched and still satisfied - which is the defect this section exists to close, and is what makes the assertion above a measurement rather than a coincidence'

t_case 'the ceiling is the resolved number, not a constant, and does not over-serialise'
export SCOURSH_CONFIG_JOBS=2
_inflight_run "$ROOT" 4 1
unset SCOURSH_CONFIG_JOBS
assert_eq 2 "$_INFLIGHT_MAX" \
  'four workers under jobs 2 reach EXACTLY two simultaneous connections - a 4 here means the ceiling did not bite, and a 1 means it serialised a run that was authorised to open two, which is the opposite bug and the one a "safer is always better" fix introduces'
assert_eq 0 "$_INFLIGHT_FAILED" \
  'and every worker finished: a run at or below its own ceiling never deadlocks and never times out waiting for a slot'
inflight_ok=false
if (( _INFLIGHT_SAMPLES >= 4 )); then inflight_ok=true; fi
assert_true "$inflight_ok" \
  'and all four requests were issued'

printf '\n-- section 11b: `jobs` is clamped by DAST-32'"'"'s asymmetric policy, like every other limit --\n'

_jobs_probe() {
  local rc=0 out
  out=$( ( _http_effective_limit_set jobs ) 2>&1 >/dev/null ) || rc=$?
  printf '%s\n%s' "$rc" "$out"
}

_limits_reset
config_scanner_load "$W/scanner-absent.conf"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
rm -rf "${W:?}/run.jobs"
run_init "$W/run.jobs"

t_case 'an unedited install resolves 4 and warns about nothing'
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set jobs 2>"$W/jobs-clamp.log"
assert_eq 4 "$_HTTP_EFF_LIMIT" 'the effective in-flight ceiling on an unedited install is the §9.6.1 default of 4'
assert_eq '' "$(cat "$W/jobs-clamp.log")" \
  'and nothing is warned about, because the ceiling equals the shipped default - FAILS if the concurrency ceiling is set below `jobs`'"'"' own default, which would clamp and scold on every run of an install nobody configured'

t_case 'an explicit over-ceiling jobs value exits 2 rather than being silently lowered'
export SCOURSH_CONFIG_JOBS=16
jobs_probe=$(_jobs_probe)
unset SCOURSH_CONFIG_JOBS
assert_eq 2 "${jobs_probe%%$'\n'*}" \
  'a jobs value of 16 in the environment exits 2 - FAILS under a SYMMETRIC clamp, which would run 4 connections while the operator believes they asked for 16, and this codebase treats an explicit invocation as authoritative or fatal, never rewritten'
assert_contains "${jobs_probe#*$'\n'}" '--i-own-target' \
  'and the refusal names the flag that resolves it'

t_case 'a FILE value above the ceiling is clamped and warned about instead'
cat >"$W/scanner-bigjobs.conf" <<'EOF'
id: scanner
jobs: 16
EOF
config_scanner_load "$W/scanner-bigjobs.conf"
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set jobs 2>"$W/jobs-clamp.log"
config_scanner_load "$W/scanner-absent.conf"
jobs_clamp=$(cat "$W/jobs-clamp.log")
assert_eq 4 "$_HTTP_EFF_LIMIT" 'a raised file value is clamped to the conservative ceiling'
assert_contains "$jobs_clamp" '16' \
  'and the warning names the value that was refused - FAILS under a uniformly fatal policy, which would make an operator affirm reflexively just to run an install whose config file they inherited'

t_case 'the affirmation raises the concurrency ceiling and cannot remove it'
run_record authorization_affirmed true
run_record authorization_target fixture-good
export SCOURSH_CONFIG_JOBS=16
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set jobs 2>/dev/null
unset SCOURSH_CONFIG_JOBS
assert_eq 16 "$_HTTP_EFF_LIMIT" \
  'with the per-run affirmation record present, the same explicit value that exited 2 above is honoured - FAILS if the concurrency ceiling is unconditional, in which case it is the one limit --i-own-target does not reach, contradicting docs/STEP5-DAST-PLAN.md'"'"'s own "requests per second, DAST concurrency" row'
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set jobs 2>/dev/null
inflight_ok=false
if (( _HTTP_EFF_LIMIT >= 1 )); then inflight_ok=true; fi
assert_true "$inflight_ok" \
  'and there is no value of `jobs` that means unbounded: the §9.6.1 shape is a positive integer, so "no concurrency bound" is unrepresentable here exactly as "no budget" is'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
_limits_reset

printf '\n-- section 11b: a slot is reclaimed on age AND non-liveness, never on either alone --\n'

# Both halves are load-bearing and each naive fix is the other'"'"'s bug, so both
# are pinned.  Age alone takes a slot back from a live worker whose request is
# merely slow, which puts two processes over the ceiling - the one outcome the
# semaphore exists to prevent.  Liveness alone frees a slot in the window
# between a worker recording it and that worker becoming observable, making the
# answer depend on scheduling.

# `_inflight_plant PID NONCE AGE_SECONDS` - one held slot, written straight
# into the state file, so the reclaim rule can be exercised without having to
# kill a real worker at exactly the right instant.
_inflight_plant() {
  local pid=$1 nonce=$2 age=$3 now
  _http_limit_dir_set
  now=$(now_epoch)
  printf '%s %s %s\n' "$pid" "$nonce" "$(( now - age ))" >"$_HTTP_LIMIT_DIR/inflight.state"
}

# A pid that is certainly dead: started and reaped here, so nothing else in
# this process tree can be holding it at the moment it is used.
bash -c 'exit 0' &
DEAD_PID=$!
wait "$DEAD_PID" || true

_limits_reset
_inflight_plant "$DEAD_PID" 'ghost.1' 999
rc=0
( _http_inflight_acquire fixture-good 1 ) >/dev/null 2>&1 || rc=$?
t_case 'a slot whose worker is gone AND whose entry is stale is reclaimed'
assert_eq 0 "$rc" \
  'a run whose only slot was leaked by a killed worker recovers rather than stalling for the rest of its life - FAILS with no reclaim path at all, which turns one SIGTERM into a permanently narrower run'

_limits_reset
_inflight_plant "$$" 'live.1' 999
rc=0
( SCOURSH_MUTEX_TIMEOUT_SECONDS=1 _http_inflight_acquire fixture-good 1 ) >/dev/null 2>&1 || rc=$?
t_case 'a STALE slot held by a process that is still alive is NOT reclaimed'
assert_eq 5 "$rc" \
  'the acquire waits and then fails loud rather than taking the slot - FAILS under a reclaim on AGE ALONE, which takes a slot back from a live worker whose request is merely slower than the staleness threshold and so puts two processes over the ceiling, which is the single outcome this semaphore exists to prevent'
assert_contains "$(cat "$_HTTP_LIMIT_DIR/inflight.state")" 'live.1' \
  'and the live holder'"'"'s slot is still recorded afterwards, so nothing was stolen from it'

_limits_reset
_inflight_plant "$DEAD_PID" 'fresh-ghost.1' 0
rc=0
( SCOURSH_MUTEX_TIMEOUT_SECONDS=1 _http_inflight_acquire fixture-good 1 ) >/dev/null 2>&1 || rc=$?
t_case 'a FRESH slot whose pid is not alive is NOT reclaimed either'
assert_eq 5 "$rc" \
  'age is required as well as non-liveness - FAILS under a reclaim on LIVENESS ALONE, which frees a slot in the microseconds between a worker recording it and that worker becoming observable, making the ceiling depend on scheduling rather than on the number'

printf '\n-- section 11b: a release gives back the slot it took, and only that one --\n'

_limits_reset
_inflight_plant "$BASHPID" 'someone-else.7' 0
_HTTP_INFLIGHT_NONCE='mine.1'
_http_inflight_release
t_case 'the release is identity-bound rather than pid-keyed'
assert_contains "$(cat "$_HTTP_LIMIT_DIR/inflight.state")" 'someone-else.7' \
  'a release whose nonce is absent from the file removes NOTHING, even though the file'"'"'s one entry carries this very process id - FAILS under a pid-keyed release, which would hand back a slot this call never took and let two processes past the ceiling, and which is exactly what a pid alone cannot distinguish after a pid is recycled'

_limits_reset
: >"$TRANSPORT_LOG"
for _i in 1 2 3; do http_request GET "$RATE_URL" >/dev/null; done
t_case 'an ordinary request leaves no slot behind'
assert_eq '' "$(cat "$_HTTP_LIMIT_DIR/inflight.state" 2>/dev/null || printf '')" \
  'three completed requests leave the in-flight file empty - FAILS if the release is skipped on any path, in which case a long run narrows itself one slot per request until it stalls'
assert_eq 3 "$(wc -l <"$TRANSPORT_LOG" | tr -d ' ')" \
  'and all three were actually sent, so the empty file above is a released slot rather than a request that never happened'

_limits_reset
config_scanner_load "$W/scanner-absent.conf"

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
config_scanner_load "$W/scanner-bigbudget.conf"
_http_effective_limit_set request-budget 2>"$W/clamp.log"
config_scanner_load "$W/scanner-absent.conf"
clamp_out=$(cat "$W/clamp.log")
assert_eq 5000 "$_HTTP_EFF_LIMIT" 'a raised budget is still clamped to the ceiling'
assert_contains "$clamp_out" '100000' \
  'a budget the operator actually raised in config/scanner.conf DOES warn, and names the value that was refused - FAILS if suppressing the default-value warning also suppressed the one case the warning exists for'

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

# ===========================================================================
# docs/STEP5-DAST-PLAN.md DAST-31: the identifying User-Agent
# ===========================================================================
# The point of a UA test is not the string, it is that the string cannot be
# suppressed.  Every case below therefore asserts on what the TRANSPORT was
# handed, and the last two assert on what no setting can remove.
printf '\n-- DAST-31: the identifying User-Agent --\n'

_limits_reset
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
config_scanner_load "$W/scanner-absent.conf"

t_case 'the no-contact form still identifies the tool'
_HTTP_UA=MISSING
_http_user_agent_set
assert_contains "$_HTTP_UA" "scoursh/$(scoursh_version)" \
  'with no contact configured anywhere the UA still carries the scoursh/<version> product token - FAILS under "an unconfigured install sends curl'"'"'s own default UA", which is the state this ticket found lib/http.sh in and is what leaves a target owner with no way to identify the tool'
assert_contains "$_HTTP_UA" 'no operator contact configured' \
  'and it says the contact is missing rather than silently omitting it, so an owner can tell a policy from an oversight'

t_case 'a configured contact reaches the User-Agent'
cat >"$W/scanner-contact.conf" <<'EOF'
id: scanner
contact: security@operator.example
EOF
config_scanner_load "$W/scanner-contact.conf"
_HTTP_UA=MISSING
_http_user_agent_set
assert_eq "scoursh/$(scoursh_version) (+security@operator.example)" "$_HTTP_UA" \
  'the configured contact is rendered in the documented `scoursh/<version> (+<contact>)` form - FAILS if `contact` is added to the schema but never read by the transport, which is the shape of a config key that exists only in documentation'
config_scanner_load "$W/scanner-absent.conf"

t_case 'the run record carries the CLI layer of the contact chain'
rm -rf "${W:?}/run.ua"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.ua"
run_record contact 'https://operator.example/security'
run_record user_agent_suffix 'operator-ci/2.1'
_HTTP_UA=MISSING
_http_user_agent_set
assert_eq "scoursh/$(scoursh_version) (+https://operator.example/security) operator-ci/2.1" "$_HTTP_UA" \
  'the per-run record supplies both halves, which is the ONLY route --contact and --user-agent-suffix have into this file (lib/http.sh cannot see SCAN_FLAGS) - FAILS if the transport reads config_scanner_value alone, in which case --contact on the command line is accepted by the parser and then silently ignored by every request'

t_case 'the product-token prefix is never displaceable'
assert_eq "scoursh/" "${_HTTP_UA:0:8}" \
  'the suffix APPENDS: the UA still BEGINS with the scoursh product token even with a suffix set - FAILS under an implementation where --user-agent-suffix replaces or prefixes the identity, which is the WAF-evasion reading this flag will be asked for'

t_case 'a header-injecting contact is dropped, not concatenated'
# Written straight into the meta file rather than through run_record, because
# run_record APPENDS and run_fact_first_set reads the FIRST line: appending here
# would leave the previous case's valid contact in place and this whole case
# would pass without ever exercising the guard.
printf '%s\n' "evil$(printf '\r')X-Injected: yes" >"$SCOURSH_RUN_DIR/meta/contact"
: >"$SCOURSH_RUN_DIR/meta/user_agent_suffix"
_HTTP_UA=MISSING
_http_user_agent_set 2>/dev/null
assert_not_contains "$_HTTP_UA" 'X-Injected' \
  'a CR in the recorded contact never reaches the User-Agent - FAILS under "scan.sh already validated it", which trusts a file under a directory the operator can edit to compose an HTTP header'
assert_contains "$_HTTP_UA" 'no operator contact configured' \
  'and the run degrades to the no-contact form rather than aborting: a malformed contact costs identification, which is not worth failing an authorised scan over'
: >"$SCOURSH_RUN_DIR/meta/contact"
: >"$SCOURSH_RUN_DIR/meta/user_agent_suffix"

t_case 'every real request actually carries it'
# The transport stub records the argv it was handed; the default transport is
# the only place -A is composed, so this asserts the composition point rather
# than the string.
assert_contains "$(declare -f _http_transport_default)" '-A "$_HTTP_UA"' \
  'the default transport passes the composed UA to curl via -A - FAILS if a second curl invocation is ever added without one, which is the only way an unidentified request can leave this tool'
assert_eq 1 "$(declare -f _http_transport_default | grep -c 'curl ' || true)" \
  'and there is exactly ONE curl invocation in the transport, so "every request is identified" is a structural fact rather than a convention'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

# ===========================================================================
# docs/STEP5-DAST-PLAN.md DAST-32: the asymmetric clamp and the affirmation
# ===========================================================================
printf '\n-- DAST-32: the asymmetric clamp policy --\n'

# The two halves are tested in BOTH directions, because each half's naive
# implementation is the other half's bug: clamp everything and an operator's
# explicit number is silently rewritten; refuse everything and an unedited
# config file cannot run a scan without an affirmation, which turns the
# affirmation into something people pass reflexively.
_limits_reset
config_scanner_load "$W/scanner-absent.conf"

t_case 'an explicit ENV value above the ceiling is a usage error, not a clamp'
_clamp_probe() {
  local rc=0 out
  out=$( ( _http_effective_limit_set request-budget ) 2>&1 >/dev/null ) || rc=$?
  printf '%s\n%s' "$rc" "$out"
}
export SCOURSH_CONFIG_REQUEST_BUDGET=100000
probe=$(_clamp_probe)
unset SCOURSH_CONFIG_REQUEST_BUDGET
assert_eq 2 "${probe%%$'\n'*}" \
  'a request-budget of 100000 in the environment exits 2 rather than being clamped to 5000 - FAILS under a SYMMETRIC clamp that quietly runs at a different number than the operator asked for, which contradicts this codebase'"'"'s own rule that an invocation is authoritative or fatal, never rewritten (lib/config.sh already dies 2 for a bad CLI/env value and 4 for a bad file value, for the same reason)'
assert_contains "${probe#*$'\n'}" '--i-own-target' \
  'and the refusal names the flag that resolves it, so the operator is not left guessing which of two dozen flags applies'
assert_contains "${probe#*$'\n'}" 'SCOURSH_CONFIG_REQUEST_BUDGET' \
  'and it names the environment variable it actually read, distinguishing an inherited CI variable from a flag someone typed'

t_case 'a FILE value above the ceiling clamps, with a warning and a durable delta'
_limits_reset
rm -rf "${W:?}/run.clamp"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.clamp"
config_scanner_load "$W/scanner-bigbudget.conf"
# Run the resolution INSIDE a status-capturing subshell rather than bare.  A
# uniformly-fatal policy - the reading this case exists to reject - would `die`
# here, and a bare call would take the whole suite process with it: the case
# would "fail" as an aborted run rather than as a named assertion, which is not
# a pin.  Everything asserted afterwards is a FILE (the warning log, the run's
# own meta records), so it survives the subshell that produced it.
clamp_rc=0
clamp_eff=$( ( _http_effective_limit_set request-budget \
  && _http_limit_delta_record request-budget 5000 "$_HTTP_EFF_LIMIT" \
  && printf '%s' "$_HTTP_EFF_LIMIT" ) 2>"$W/clamp2.log" ) || clamp_rc=$?
assert_eq 0 "$clamp_rc" \
  'a config-FILE value above the ceiling does NOT abort the run - FAILS under a uniformly-fatal policy, which would make an operator affirm ownership just to run any scan at all and reduce the affirmation to something you pass to make the tool work'
assert_eq 5000 "$clamp_eff" \
  'and it is clamped to the conservative ceiling instead'
assert_contains "$(cat "$W/clamp2.log")" '100000' \
  'the clamp warns once and names the value it refused'
assert_contains "$(cat "$SCOURSH_RUN_DIR/meta/limits_clamped" 2>/dev/null || printf '')" \
  'request-budget:100000->5000 reason=no_owner_affirmation source=file' \
  'and the delta is recorded durably with the resolution layer it came from - FAILS if the clamp only warns on stderr, which is not an artifact a reader has a month later (docs/STEP5-DAST-PLAN.md: "an unaffirmed run records the clamps that bit in the same shape")'
config_scanner_load "$W/scanner-absent.conf"

t_case 'the affirmation is what lifts the ceiling, and only for the relaxable bounds'
_limits_reset
run_record authorization_affirmed true
run_record authorization_target fixture-good
export SCOURSH_CONFIG_REQUEST_BUDGET=100000
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set request-budget 2>/dev/null
unset SCOURSH_CONFIG_REQUEST_BUDGET
assert_eq 100000 "$_HTTP_EFF_LIMIT" \
  'with the per-run affirmation record present, the SAME explicit value that exited 2 above is honoured - FAILS if the ceiling is unconditional, in which case --i-own-target is a flag that changes nothing'

export SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW=5
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set circuit-breaker-window 2>/dev/null
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW
assert_eq 60 "$_HTTP_EFF_LIMIT" \
  'but an affirmed run STILL cannot shorten the breaker window below 60s - FAILS under "the affirmation lifts every ceiling", which reaches "the breaker never trips" by a different route than the disable switch docs/STEP5-DAST-PLAN.md refuses to offer ("threshold raisable, disabling never offered")'

export SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW=10000000000000000000
_HTTP_EFF_LIMIT=MISSING
_http_effective_limit_set circuit-breaker-window 2>/dev/null
unset SCOURSH_CONFIG_CIRCUIT_BREAKER_WINDOW
assert_eq 86400 "$_HTTP_EFF_LIMIT" \
  'and an affirmed run still cannot widen it past a day - FAILS under the same reading; this bound is arithmetic rather than safety (it is what keeps `now - window` inside a 64-bit integer) and no statement about who owns a host can make a wrapped integer mean what it says'

t_case 'an affirmation does not survive into the next run'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
rm -rf "${W:?}/run.unaffirmed"
run_init "$W/run.unaffirmed"
_limits_reset
export SCOURSH_CONFIG_REQUEST_BUDGET=100000
probe=$(_clamp_probe)
unset SCOURSH_CONFIG_REQUEST_BUDGET
assert_eq 2 "${probe%%$'\n'*}" \
  'a NEW run in the same process, with no affirmation record of its own, is back to exit 2 - FAILS if the affirmation is memoised in a shell variable, which is the "no persisted affirmation" non-goal arrived at by accident instead of by design'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_case 'the affirmation is not settable from the environment'
_limits_reset
rm -rf "${W:?}/run.envaffirm"
run_init "$W/run.envaffirm"
export SCOURSH_CONFIG_REQUEST_BUDGET=100000
export SCOURSH_AUTHORIZATION_AFFIRMED=true SCOURSH_I_OWN_TARGET=fixture-good
probe=$(_clamp_probe)
unset SCOURSH_CONFIG_REQUEST_BUDGET SCOURSH_AUTHORIZATION_AFFIRMED SCOURSH_I_OWN_TARGET
assert_eq 2 "${probe%%$'\n'*}" \
  'no environment variable affirms ownership - FAILS if the affirmation is ever read from the environment, which is settable by anything that can start the process and would defeat the whole reason the ceiling binds callers whose command line nobody parsed'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_case 'http_limits_record states what stayed enforced, not only what was lifted'
_limits_reset
rm -rf "${W:?}/run.record"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$W/run.record"
config_scanner_load "$W/scanner-absent.conf"
http_limits_record 2>/dev/null
enforced=$(cat "$SCOURSH_RUN_DIR/meta/limits_enforced" 2>/dev/null || printf '')
assert_contains "$enforced" 'request-budget:5000 (finite, never removable)' \
  'an unaffirmed run records the budget it kept'
assert_contains "$enforced" 'scope-gate:config/scope.conf' \
  'and that the scope gate is not among the things any affirmation relaxes - FAILS if the record lists only relaxations, which leaves a reader reasoning about what the tool could NOT have done from its version number'
assert_contains "$enforced" 'never removable' \
  'and that the identifying User-Agent is not removable either'
assert_file_absent "$SCOURSH_RUN_DIR/meta/limits_relaxed" \
  'an unaffirmed run with an unedited config relaxes NOTHING, so the relaxed record is absent rather than empty - FAILS if the ceiling is recorded as a relaxation of itself'
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

_limits_reset
config_scanner_load "$W/scanner-absent.conf"

# =============================================================================
printf -- '\n-- DAST-03: the per-request context (headers, body, response capture) --\n'
# =============================================================================
# lib/http.sh section 9a.  These are properties of the CHOKEPOINT, not of any
# module: a caller composing its own request would be the second path to the
# network tension 19 exists to make impossible, so the ability to send a header
# and a body has to live here and has to be tested here.

_limits_reset
config_scanner_load "$W/scanner-absent.conf"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

CTX_LOG=$W/ctx.log

# The value of KEY in the LAST request block of $CTX_LOG.  Last, not first: a
# redirect case logs two blocks and every assertion below is about the hop that
# was FOLLOWED, so a first-match reader would report the original request and
# pass an implementation that resent everything.
_ctx_last() {
  local key=$1 line out=''
  while IFS= read -r line; do
    case $line in "$key "*) out=${line#"$key "} ;; esac
  done <"$CTX_LOG"
  printf '%s' "$out"
}

# The header lines of the LAST request block alone.
_ctx_last_headers() {
  local line out=''
  while IFS= read -r line; do
    case $line in
      '--- '*) out='' ;;
      'H '*) out+="$line"$'\n' ;;
    esac
  done <"$CTX_LOG"
  printf '%s' "$out"
}

_ctx_transport() {
  local method=$1 scheme=$2 host=$3 port=$4 path=$5
  {
    printf -- '--- %s %s://%s:%s%s\n' "$method" "$scheme" "$host" "$port" "$path"
    local h
    for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do printf 'H %s\n' "$h"; done
    printf 'HASBODY %s\n' "${_HTTP_TX_HAS_BODY:-false}"
    printf 'B %s\n' "${_HTTP_TX_BODY:-}"
  } >>"$CTX_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then printf 'the-response-body' >"$_HTTP_TX_BODY_OUT"; fi
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    printf 'HTTP/1.1 200 OK\nSet-Cookie: s=1\n\n' >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '200\n\n'
}

t_case 'a header and a body attached by the caller reach the transport'
: >"$CTX_LOG"
SCOURSH_HTTP_TRANSPORT=_ctx_transport
http_request_header Authorization 'Bearer sekrit'
http_request_body '{"a":1}'
http_request POST 'https://good.fixture.example/login'
assert_contains "$(cat "$CTX_LOG")" 'H Authorization: Bearer sekrit' \
  'the header reaches the transport - fails if the context is accepted and dropped, which is a silently unauthenticated request'
assert_contains "$(cat "$CTX_LOG")" 'B {"a":1}' 'and so does the body'

t_case 'the context is consumed by ONE request and never rides along on the next'
: >"$CTX_LOG"
http_request GET 'https://good.fixture.example/other'
assert_not_contains "$(cat "$CTX_LOG")" 'Authorization' \
  'the second request carries no header from the first - FAILS if the context is cleared at the END of http_request rather than consumed at its start, in which case any path that dies in between (a gate refusal, an exhausted budget, an opened breaker) leaves a credential attached to whatever request comes next'
assert_eq 'false' "$(_ctx_last HASBODY)" 'and no body either'

t_case 'the response body and headers are captured, at mode 600'
: >"$CTX_LOG"
http_request_capture "$W/cap.body" "$W/cap.hdr"
http_request GET 'https://good.fixture.example/x'
assert_eq 'the-response-body' "$(cat "$W/cap.body")" 'the response body is captured'
assert_contains "$(cat "$W/cap.hdr")" 'Set-Cookie: s=1' 'and the raw response headers with it'
assert_eq '600' "$(stat_mode "$W/cap.body")" \
  'the body capture is 600 - fails under the process umask alone; a login response is where the token is, and it must not be world-readable for even one hop'
assert_eq '600' "$(stat_mode "$W/cap.hdr")" 'and so is the header capture'

t_case 'a header value containing CR or LF is refused, not truncated'
_hdr_probe() {
  local rc=0
  bash -c "
    source '$ROOT/lib/http.sh'
    http_request_header X-Test 'one
two'
  " >/dev/null 2>&1 || rc=$?
  printf '%s' "$rc"
}
assert_eq 4 "$(_hdr_probe)" \
  'a newline in a header value exits 4 - FAILS under "strip it and carry on", which silently sends a request the operator did not write, and under "send it anyway", which is request splitting'

# =============================================================================
printf -- '\n-- DAST-03: a redirect does not carry a credential or a body with it --\n'
# =============================================================================

_redir_transport() {
  local method=$1 host=$3 path=$5
  {
    printf -- '--- %s %s%s\n' "$method" "$host" "$path"
    local h
    for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do printf 'H %s\n' "$h"; done
    printf 'HASBODY %s\n' "${_HTTP_TX_HAS_BODY:-false}"
  } >>"$CTX_LOG"
  case $path in
    /login) printf '302\nhttps://good.fixture.example/landed\n' ;;
    /crossorigin) printf '302\nhttps://sub.wide.fixture.example/landed\n' ;;
    /keepmethod) printf '307\nhttps://good.fixture.example/landed\n' ;;
    *) printf '200\n\n' ;;
  esac
}

t_case 'a 302 after a POST is re-issued as GET, with the body dropped'
: >"$CTX_LOG"
SCOURSH_HTTP_TRANSPORT=_redir_transport
http_request_header Content-Type 'application/x-www-form-urlencoded'
http_request_body 'username=u&password=p'
http_request POST 'https://good.fixture.example/login'
assert_contains "$(cat "$CTX_LOG")" '--- GET good.fixture.example/landed' \
  'the followed hop is a GET - FAILS if the redirect loop replays the original method, which re-POSTs the credential to a path the SCANNED TARGET chose (RFC 7231 §6.4.3, and what every browser and curl -L do)'
assert_eq 'false' "$(_ctx_last HASBODY)" \
  'and the body is not resent'
assert_not_contains "$(_ctx_last_headers)" 'Content-Type' \
  'nor the entity headers that described it'

t_case 'a 307 DOES preserve the method and the body, because that is what it is for'
: >"$CTX_LOG"
http_request_header Content-Type 'application/json'
http_request_body '{"k":1}'
http_request POST 'https://good.fixture.example/keepmethod'
assert_contains "$(cat "$CTX_LOG")" '--- POST good.fixture.example/landed' \
  'a 307 hop keeps POST - FAILS under "downgrade every 3xx to GET", which breaks the one status code that exists specifically to prevent that'
assert_eq 'true' "$(_ctx_last HASBODY)" 'and keeps the body'

t_case 'a redirect that crosses ORIGIN drops the credential, even when both origins are in scope'
: >"$CTX_LOG"
http_request_header Authorization 'Bearer for-good-fixture-only'
http_request GET 'https://good.fixture.example/crossorigin'
assert_contains "$(cat "$CTX_LOG")" '--- GET sub.wide.fixture.example/landed' \
  'the hop is followed, because both origins really are authorised'
assert_not_contains "$(_ctx_last_headers)" 'Authorization' \
  'and the Authorization header is NOT resent - FAILS under "the scope gate already approved both hosts, so carry on", which confuses "this tool may talk to that host" with "this credential belongs to that host" and hands host B a token the operator issued for host A'

SCOURSH_HTTP_TRANSPORT=_t_transport
_limits_reset
config_scanner_load "$W/scanner-absent.conf"

# =============================================================================
printf -- '\n-- DAST-03 / tension 9: the credential never reaches curl'"'"'s argv --\n'
# =============================================================================
# The one case in this file that runs the REAL transport, against a stub `curl`
# on PATH.  Everything else stubs SCOURSH_HTTP_TRANSPORT, which is exactly the
# wrong layer for this assertion: what is being tested is how
# `_http_transport_default` INVOKES curl, so a stub that replaces it proves
# nothing.  Nothing leaves the machine - the stub is a shell script.

t_case 'a header value and a request body reach curl over stdin, never as arguments'
STUB=$W/curlstub
mkdir -p "$STUB"
ARGV_OUT=$W/curl.argv
STDIN_OUT=$W/curl.stdin
cat >"$STUB/curl" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$SCOURSH_STUB_ARGV"
cat >"$SCOURSH_STUB_STDIN"
hdr=''
prev=''
for a in "$@"; do
  [[ $prev == -D ]] && hdr=$a
  prev=$a
done
[[ -n $hdr ]] && printf 'HTTP/1.1 200 OK\r\n\r\n' >"$hdr"
exit 0
STUBEOF
chmod 755 "$STUB/curl"

CREDENTIAL='s3cr3t-token-value-never-in-argv'
BODYSECRET='password=another-s3cr3t-value'
# The subshell is the POINT, not an accident: this is the only case in this file
# that unsets SCOURSH_HTTP_TRANSPORT and puts a stub `curl` on PATH, and both
# must be confined to it or every later case in the suite would silently run
# against the stub instead of the fixture transport.  SC2030/SC2031 warn that
# the changes might be lost, which is exactly what is wanted here - nothing is
# read back through a variable.  What the assertions read is the two FILES the
# stub writes, and a file outlives the subshell that produced it.
# shellcheck disable=SC2030,SC2031
(
  unset SCOURSH_HTTP_TRANSPORT
  export SCOURSH_STUB_ARGV=$ARGV_OUT SCOURSH_STUB_STDIN=$STDIN_OUT
  PATH="$STUB:$PATH"
  http_request_header Authorization "Bearer $CREDENTIAL"
  http_request_body "$BODYSECRET"
  http_request POST 'https://good.fixture.example/login'
) >/dev/null 2>&1
ARGV=$(cat "$ARGV_OUT")
STDIN_SEEN=$(cat "$STDIN_OUT")
assert_not_contains "$ARGV" "$CREDENTIAL" \
  'the token is NOT in curl'"'"'s argv - FAILS under the obvious `-H "Authorization: Bearer $t"` spelling, which puts the credential in `ps` output for every user on the host (docs/FOUNDATION.md tension 9 handling rule 1)'
assert_not_contains "$ARGV" 'another-s3cr3t-value' \
  'and neither is the request body - FAILS under `--data "$body"`, the same exposure by a different flag'
assert_contains "$STDIN_SEEN" "$CREDENTIAL" \
  'it reached curl over stdin instead, as a config directive - fails if the header is dropped entirely, in which case the request is silently unauthenticated'
assert_contains "$STDIN_SEEN" 'another-s3cr3t-value' 'and so did the body'
assert_contains "$ARGV" '-K' 'curl really was told to read that config'
assert_file_absent "$W/curl.cfg" \
  'and no config FILE was written - FAILS under "write the header to a 600 temp file and pass -K <path>", which is argv-safe but puts the credential on disk (tension 9 handling rule 2)'

t_case 'a request with no header and no body still uses the SAME single curl invocation'
: >"$ARGV_OUT"
# Same deliberate confinement as the case above, for the same reason.
# shellcheck disable=SC2030,SC2031
(
  unset SCOURSH_HTTP_TRANSPORT
  export SCOURSH_STUB_ARGV=$ARGV_OUT SCOURSH_STUB_STDIN=$STDIN_OUT
  PATH="$STUB:$PATH"
  http_request GET 'https://good.fixture.example/plain'
) >/dev/null 2>&1
assert_contains "$(cat "$ARGV_OUT")" '-K' \
  'the plain path takes the identical command line - FAILS under a second, header-free curl branch, which is the first place a request with no identifying User-Agent could appear (the "exactly ONE curl invocation" case above is what keeps that structural)'

t_summary 'http'
