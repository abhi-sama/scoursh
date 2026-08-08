#!/usr/bin/env bash
# tests/suites/http.sh - lib/http.sh, the destination-allowlist chokepoint.
#
# Pins docs/FOUNDATION.md tension 19's rejected alternative directly: matching
# by HOST ALONE "silently authorises every port on the host", so every
# positive case here is paired with a same-host, wrong-port or wrong-scheme
# negative that must still be denied.  A suite that only checked the positive
# case would pass under the rejected reading too, and pin nothing.
#
# The live network path (http_request actually reaching an allowed host and
# aborting before reaching a denied one) is covered here without any fixture
# server: the abort case never opens a socket, so exit 3 is asserted directly,
# and the allowed case is exercised end-to-end by tests/suites/update-advisories.sh
# against a real loopback fixture server, which is where a live fetch belongs.
#
# shellcheck shell=bash
#
# SC2016: assertion prose mentions shell/URL syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/http
mkdir -p "$W"

# ---------------------------------------------------------------------------
printf '\n-- URL splitting --\n'
# ---------------------------------------------------------------------------
t_case 'scheme/host/port'
assert_eq $'https\texample.com\t443' "$(_http_split_url 'https://example.com/app')" \
  'https defaults to port 443 when absent'
assert_eq $'http\texample.com\t80' "$(_http_split_url 'http://example.com')" \
  'http defaults to port 80 when absent, and a bare host with no path is fine'
assert_eq $'https\texample.com\t8443' "$(_http_split_url 'https://example.com:8443/x?y#z')" \
  'an explicit port overrides the scheme default; path/query/fragment are stripped'
assert_eq $'https\texample.com\t443' "$(_http_split_url 'https://EXAMPLE.COM./app')" \
  'host is lowercased and a trailing dot is stripped'

t_case 'rejected shapes'
assert_status 1 '_http_split_url returns non-zero on ftp://' _http_split_url 'ftp://example.com/x'
assert_status 1 '_http_split_url returns non-zero on a bare host with no scheme' _http_split_url 'example.com'
assert_status 1 '_http_split_url returns non-zero on embedded credentials (never expected here)' \
  _http_split_url 'https://user:pass@example.com/'
assert_status 1 '_http_split_url returns non-zero on a non-numeric port' _http_split_url 'https://example.com:abc/'

# ---------------------------------------------------------------------------
printf '\n-- scope.conf loading: the tension 19 tuple, not a bare host --\n'
# ---------------------------------------------------------------------------
cat >"$W/scope1.conf" <<'EOF'
id: target-a
base-url: https://target.example/app
extra-host: alt.example:8080
allow-subdomains: false
EOF

http_reset_allowlist
http_allow_scope_hosts "$W/scope1.conf"

t_case 'exact tuple admitted'
assert_true "$(http_url_allowed 'https://target.example/anything' && echo 0 || echo 1)" \
  'the authored (https, target.example, 443) tuple is allowed'

t_case 'tension 19 rejected-alternative guards: same host, wrong port/scheme is DENIED'
assert_true "$(http_url_allowed 'https://target.example:9999/' && echo 1 || echo 0)" \
  'a different port on an authorised host is NOT authorised (this is what host-only matching gets wrong)'
assert_true "$(http_url_allowed 'http://target.example/' && echo 1 || echo 0)" \
  'a different scheme on an authorised host is NOT authorised'

t_case 'extra-host carries its own port, on the base target scheme'
assert_true "$(http_url_allowed 'https://alt.example:8080/' && echo 0 || echo 1)" \
  'extra-host host:port is admitted on the base-url scheme'
assert_true "$(http_url_allowed 'https://alt.example/' && echo 1 || echo 0)" \
  'extra-host is NOT admitted on its own default port when an explicit port was authored'

t_case 'never in scope'
assert_true "$(http_url_allowed 'https://evil.example/' && echo 1 || echo 0)" \
  'an unlisted host is denied'

t_case 'subdomains are never implicit'
assert_true "$(http_url_allowed 'https://sub.target.example/' && echo 1 || echo 0)" \
  'allow-subdomains defaults to false, so a subdomain of an authorised host is still denied'

cat >"$W/scope2.conf" <<'EOF'
id: target-b
base-url: https://wide.example/
allow-subdomains: true
EOF
http_reset_allowlist
http_allow_scope_hosts "$W/scope2.conf"

t_case 'allow-subdomains: true opts a target in explicitly'
assert_true "$(http_url_allowed 'https://api.wide.example/' && echo 0 || echo 1)" \
  'a subdomain is admitted once allow-subdomains is true'
assert_true "$(http_url_allowed 'https://api.wide.example:9999/' && echo 1 || echo 0)" \
  'subdomain admission still respects the tuple: wrong port is still denied'
assert_true "$(http_url_allowed 'https://notwide.example/' && echo 1 || echo 0)" \
  'suffix matching is on the DOT boundary: a host that merely ends in the base string is not a subdomain of it'

# ---------------------------------------------------------------------------
printf '\n-- the update endpoint: a single configured host, no subdomain wildcard --\n'
# ---------------------------------------------------------------------------
cat >"$W/scanner1.conf" <<'EOF'
id: scanner
advisory-update-url: https://updates.example.org/scoursh/advisories
EOF
http_reset_allowlist
http_allow_update_endpoint "$W/scanner1.conf"

t_case 'the configured update host is admitted, category is update-channel'
assert_true "$(http_url_allowed 'https://updates.example.org/scoursh/advisories/npm.tsv' && echo 0 || echo 1)" \
  'the configured update endpoint is allowed'
assert_eq update-channel "$(http_url_category 'https://updates.example.org/x')" \
  'the admitted tuple is labelled update-channel, not scope'
assert_true "$(http_url_allowed 'https://sub.updates.example.org/x' && echo 1 || echo 0)" \
  'the update endpoint never gets subdomain matching, unlike an operator scope target'
assert_eq 'https://updates.example.org/scoursh/advisories' "$(http_update_url)" \
  'http_update_url returns the configured base URL verbatim'

t_case 'an absent key leaves the update channel unconfigured, not guessed'
cat >"$W/scanner2.conf" <<'EOF'
id: scanner
EOF
http_reset_allowlist
http_allow_update_endpoint "$W/scanner2.conf"
assert_eq '' "$(http_update_url)" 'no advisory-update-url means no update destination is admitted'
assert_true "$(http_url_allowed 'https://updates.example.org/x' && echo 1 || echo 0)" \
  'with the key absent, even the host from the other fixture is denied'

t_case 'a malformed advisory-update-url is a hard configuration error, not a silent skip'
cat >"$W/scanner3.conf" <<'EOF'
id: scanner
advisory-update-url: not-a-url
EOF
assert_status 4 'http_allow_update_endpoint dies (exit 4, missing/bad required input) on a malformed URL' \
  http_allow_update_endpoint "$W/scanner3.conf"

# ---------------------------------------------------------------------------
printf '\n-- scope and update-channel allowlists are independent per caller --\n'
# ---------------------------------------------------------------------------
http_reset_allowlist
http_allow_scope_hosts "$W/scope1.conf"

t_case 'a caller that only allows scope hosts cannot reach the update endpoint'
assert_true "$(http_url_allowed 'https://updates.example.org/x' && echo 1 || echo 0)" \
  'update endpoint is denied when only http_allow_scope_hosts was called - least privilege per caller'

http_reset_allowlist
http_allow_update_endpoint "$W/scanner1.conf"

t_case 'a caller that only allows the update endpoint cannot reach a DAST target'
assert_true "$(http_url_allowed 'https://target.example/' && echo 1 || echo 0)" \
  'scope host is denied when only http_allow_update_endpoint was called'

# ---------------------------------------------------------------------------
printf '\n-- http_request: the chokepoint aborts before ever touching the network --\n'
# ---------------------------------------------------------------------------
http_reset_allowlist
http_allow_scope_hosts "$W/scope1.conf"

t_case 'an out-of-allowlist destination aborts with exit 3 (SCOURSH_EXIT_SCOPE)'
assert_status 3 'http_request refuses a host absent from the allowlist' \
  http_request GET 'https://evil.example/steal'

t_case 'a same-host wrong-port destination aborts with exit 3 too'
assert_status 3 'http_request refuses the right host on the wrong port' \
  http_request GET 'https://target.example:9999/'

t_case 'a malformed URL is refused before any curl invocation'
assert_status 3 'http_request refuses a non-http(s) URL' \
  http_request GET 'ftp://target.example/'

t_case 'an unsupported method is a usage error, not a scope decision'
assert_status 2 'http_request refuses a non-GET/HEAD method (SCOURSH_EXIT_USAGE)' \
  http_request POST 'https://target.example/'

t_summary 'lib/http.sh'
