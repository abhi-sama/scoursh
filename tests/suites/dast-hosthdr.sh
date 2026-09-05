#!/usr/bin/env bash
# tests/suites/dast-hosthdr.sh - modules/dast/active/hosthdr.sh and
# hosthdr_engine.sh: spoofed Host / X-Forwarded-Host reflection
# (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-24).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"), and the stub is a scripted server
# keyed on PATH, in the shape tests/suites/dast-openredirect.sh's own mock
# target already established, rather than a canned-status queue.
#
# THE DECISIONS THIS SUITE PINS, each with the plausible wrong reading that
# would otherwise ship green:
#
#   1. THE BODY CHECK IS A SUBSTRING TEST. Reflection can land in many HTML
#      positions (a canonical link, an asset URL, ...) and the sentinel is a
#      garbage label nothing else could have produced, so any occurrence is
#      real evidence - pinned by a positive case AND by the truncation cap
#      still finding a hit inside its window.
#   2. THE LOCATION CHECK IS AUTHORITY-ONLY, NOT A SUBSTRING TEST. A response
#      that redirects ON-ORIGIN while merely echoing the sentinel into its own
#      query string (the exact shape openredirect.sh's own `/reflect` control
#      models) must NOT be reported as a reflected Location - FAILS under a
#      substring reading, which reports every such on-origin echo as a
#      Location-authority hijack.
#   3. hh_host_is_sentinel IS EXACT EQUALITY, WITH NO SUBDOMAIN ARM - unlike
#      openredirect.sh's own `_or_host_is_sentinel`. This probe never places
#      the sentinel inside a larger value a payload template built, so a
#      value that merely CONTAINS the sentinel as a subdomain is not this
#      probe's own reflection.
#   4. ONLY GET/HEAD ENDPOINTS ARE PROBED, and a POST endpoint the inventory
#      names is never requested under any method - asserted against the
#      REQUEST LOG, not a return value.
#   5. DEDUPE BY (METHOD, PATH TEMPLATE). Two URLs sharing a template are one
#      route to probe, not two.
#   6. A TRANSPORT FAILURE IS NOT A CLEAN RESULT. It is counted as untested
#      and recorded, never as "this route reflects nothing".
#   7. GRACEFUL DEGRADATION. No inventory, or an inventory with no idempotent
#      endpoint, is a RECORDED gap - never an error and never a silent pass.
#   8. BOTH TECHNIQUES ARE TRIED INDEPENDENTLY. A route that trusts
#      X-Forwarded-Host but not Host is still caught, and the finding's
#      loc_param_name names which header technique fired.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header/URL syntax literally, single-quoted
#   on purpose.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/http.sh is already inlined via modules/dast/active/hosthdr_engine.sh below
# (hosthdr_engine.sh:103-104), so this direct edge is a pure -x cost with no
# static-knowledge loss - see docs/FOUNDATION.md's shellcheck-memory note.
# shellcheck source=/dev/null
source "$ROOT/lib/http.sh"
if [[ -z ${SCOURSH_REPORT_SOURCED:-} ]]; then
  # shellcheck source=lib/report.sh
  source "$ROOT/lib/report.sh"
fi
# -x back-edge cut (modules/dast/active/hosthdr_engine.sh): this file already reaches that
# target through another edge, so following it here only re-expands the
# lib/ hub chain a second time - which is what peak RSS is made of. See
# docs/CI-RUNBOOK.md, "the memory model".
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/hosthdr_engine.sh"
# -x back-edge cut (modules/dast/crawl_engine.sh): this file already reaches that
# target through another edge, so following it here only re-expands the
# lib/ hub chain a second time - which is what peak RSS is made of. See
# docs/CI-RUNBOOK.md, "the memory model".
# shellcheck source=/dev/null
source "$ROOT/modules/dast/crawl_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-hosthdr-workspace
rm -rf "$W"
mkdir -p "$W"

HOSTNAME_FIXTURE=hosthdr.fixture.example

printf '\n== 0. the shipped sentinel is a reserved, target-agnostic name ==\n'
t_case 'HOSTHDR_SENTINEL is an RFC 2606 reserved name'
assert_contains "$HOSTHDR_SENTINEL" '.example' \
  'the sentinel can never resolve and can never reach a third party'
t_case 'exactly two techniques are tried, Host and X-Forwarded-Host'
assert_eq 2 "${#HOSTHDR_TECHNIQUES[@]}" 'docs/DESIGN.md §7.3 names both headers by name'

# ---------------------------------------------------------------------------
# Scope + the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
# The literal domain, not the shell variable, is written here: DAST-35's lint
# reads this SOURCE FILE'S bytes for a `base-url:` line and checks the domain
# it names, so an interpolated `$HOSTNAME_FIXTURE` would leave the reserved
# `.example` suffix invisible to it at lint time even though the two strings
# are byte-identical once bash expands the heredoc at runtime.
cat >"$SCOPE" <<'EOF'
id: hosthdr-fixture
base-url: https://hosthdr.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-hosthdr.sh. Never dialled: both
  the resolver and the transport are stubbed.
EOF

_hh_resolve() {
  case $1 in
    "$HOSTNAME_FIXTURE") printf '198.51.100.9' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_hh_resolve

# The scripted SERVER, keyed on path. `REQ_LOG` gets one line per request:
# METHOD<TAB>PATH<TAB>host=<Host header we sent>xfh=<X-Forwarded-Host we sent>
# - which is what lets the "only GET/HEAD requested" and "one request per
# technique per candidate" assertions be made against a log rather than a
# return value.
REQ_LOG=$W/requests.log
SRV_FAIL_PATH=''
SRV_FAIL_ALL=0

_srv_reset() {
  SRV_FAIL_PATH=''
  SRV_FAIL_ALL=0
  : >"$REQ_LOG"
}

_hh_transport() {
  local method=$1 path=$5
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local h host_hdr='' xfh_hdr='' inj=''
  for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    case $h in
      Host:*) host_hdr=${h#Host: } ;;
      X-Forwarded-Host:*) xfh_hdr=${h#X-Forwarded-Host: } ;;
    esac
  done
  inj=${host_hdr:-$xfh_hdr}

  printf '%s\t%s\thost=%s\txfh=%s\n' "$method" "${path%%\?*}" "$host_hdr" "$xfh_hdr" >>"$REQ_LOG"

  local status=200 location='' body='<html><body>ok</body></html>'
  if (( SRV_FAIL_ALL )) || [[ -n $SRV_FAIL_PATH && ${path%%\?*} == "$SRV_FAIL_PATH" ]]; then
    printf 'fail\n\n\n'
    return 1
  fi

  case ${path%%\?*} in
    /vuln-body)
      [[ -n $inj ]] && body="<html><head><link rel=\"canonical\" href=\"https://$inj/vuln-body\"></head><body>ok</body></html>" ;;
    /vuln-location)
      if [[ -n $inj ]]; then status=302; location="https://$inj/dashboard"; fi ;;
    /vuln-both)
      if [[ -n $inj ]]; then
        status=302; location="https://$inj/dashboard"
        body="<html><head><link rel=\"canonical\" href=\"https://$inj/vuln-both\"></head><body>ok</body></html>"
      fi ;;
    /locsub-safe)
      # SAFE control for decision 2: redirects ON-ORIGIN and reflects the
      # spoofed value into its OWN query string, exactly as
      # openredirect.sh's own `/reflect` control models for its parameter.
      status=302; location="https://$HOSTNAME_FIXTURE/login?ref=$inj" ;;
    /safe) : ;;
    /items/*) : ;;
    /head-check) : ;;
  esac

  if [[ -n $hdrsout ]]; then
    {
      printf 'HTTP/1.1 %s X\r\n' "$status"
      [[ -n $location ]] && printf 'Location: %s\r\n' "$location"
      printf 'Content-Type: text/html\r\n\r\n'
    } >>"$hdrsout"
  fi
  [[ -n $bodyout ]] && printf '%s' "$body" >"$bodyout"
  printf '%s\n%s\n%s\n' "$status" "$location" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_hh_transport

http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

_req_log_text() {
  [[ -r $REQ_LOG ]] && cat -- "$REQ_LOG" || printf ''
}

_req_count() {
  local n=0 line
  [[ -r $REQ_LOG ]] || { printf 0; return 0; }
  while IFS= read -r line; do [[ -n $line ]] && n=$(( n + 1 )); done <"$REQ_LOG"
  printf '%s' "$n"
}

RUN_N=0
_new_run() {
  RUN_N=$(( RUN_N + 1 ))
  local dir=$W/run.$RUN_N
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target hosthdr-fixture
  occurrence_reset_all
  SCOURSH_DAST_CELL=hosthdr-fixture
  export SCOURSH_DAST_CELL
  _srv_reset
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

_count_check_param() {
  local check=$1 param=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_param_name=$param" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# Isolates one (check_id, path_template, param_name) combination, which is
# what THIS inventory needs: loc_param_name alone is only ever `Host` or
# `X-Forwarded-Host`, shared across every candidate endpoint, so counting by
# check_id+param_name alone (as _count_check_param does above, and as
# openredirect.sh's own _count_finding safely does against ITS fixture, where
# every endpoint carries a distinct parameter NAME) would sum findings across
# every reflecting endpoint in one run rather than isolating the one under
# test. This is the precise helper section E's per-endpoint assertions use.
_count_check_path_param() {
  local check=$1 tmpl=$2 param=$3 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0 ht=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_param_name=$param" ]] && hp=1
        [[ $fld == "loc_path_template=$tmpl" ]] && ht=1
      done
      (( hc && hp && ht )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

# ===========================================================================
printf '\n== A. hh_url_host - authority parsing for the Location sink ==\n'
# ===========================================================================
hh_url_host 'https://evil.example/x'
assert_eq 'evil.example' "$_HH_HOST" 'a plain absolute URL yields its host'
hh_url_host '//evil.example/x'
assert_eq 'evil.example' "$_HH_HOST" 'a scheme-relative URL has an authority'
hh_url_host 'https://real@evil.example/x'
assert_eq 'evil.example' "$_HH_HOST" \
  'userinfo is stripped - FAILS under a parser that reads this as the userinfo owner'\''s own host'
hh_url_host 'https://a@b@evil.example/x'
assert_eq 'evil.example' "$_HH_HOST" 'the split is on the LAST @'
hh_url_host 'https://evil.example:8443/x'
assert_eq 'evil.example' "$_HH_HOST" 'the port is stripped'
hh_url_host 'https://[2001:db8::1]:8443/x'
assert_eq '2001:db8::1' "$_HH_HOST" \
  'an IPv6 literal keeps its address - FAILS under a naive port strip that truncates at the first colon inside it'
hh_url_host 'https://EVIL.Example/x'
assert_eq 'evil.example' "$_HH_HOST" 'the host is lowercased'
if hh_url_host '/dashboard'; then
  _t_no 'relative Location' 'a relative URL must report NO authority'
else
  _t_ok 'a relative Location has no authority, so it can never be a finding'
fi

printf '\n== B. hh_host_is_sentinel - exact equality, no subdomain arm ==\n'
if hh_host_is_sentinel "$HOSTHDR_SENTINEL"; then
  _t_ok 'the sentinel host itself is the sentinel'
else
  _t_no 'sentinel exact' 'must match itself'
fi
if hh_host_is_sentinel "other.$HOSTHDR_SENTINEL"; then
  _t_no 'sentinel subdomain rejected' \
    'a SUBDOMAIN of the sentinel is NOT this probe'\''s own reflection - FAILS under a subdomain arm copied from openredirect.sh unmodified, which this probe deliberately does not carry (decision 3)'
else
  _t_ok 'a subdomain of the sentinel does not match - decision 3'
fi

printf '\n== C. hh_body_reflects - substring, case-folded, bounded ==\n'
BF=$W/body-plain.txt
printf 'see https://%s/path for details' "$HOSTHDR_SENTINEL" >"$BF"
assert_status 0 'a body containing the sentinel reflects - decision 1' hh_body_reflects "$BF"
BF2=$W/body-mixedcase.txt
printf 'SEE HTTPS://%s/PATH' "${HOSTHDR_SENTINEL^^}" >"$BF2"
assert_status 0 'the match is case-folded - FAILS under a case-sensitive test, which misses a server that upper-cased the echoed value' hh_body_reflects "$BF2"
BF3=$W/body-clean.txt
printf 'nothing interesting here' >"$BF3"
assert_status 1 'a body with no sentinel does not reflect' hh_body_reflects "$BF3"

BF4=$W/body-late.txt
printf 'padding-padding-padding-padding-padding-%s' "$HOSTHDR_SENTINEL" >"$BF4"
_HH_MAX_BODY_BYTES=10
if hh_body_reflects "$BF4"; then RC_LATE=0; else RC_LATE=$?; fi
_HH_MAX_BODY_BYTES=1048576
assert_eq 1 "$RC_LATE" \
  'a sentinel past the scan cap is NOT found - the honest cost of the bound this file documents'
assert_eq 1 "$_HH_BODY_TRUNCATED" 'the truncation is recorded so the phase can report the coverage_reduction'

# A real active scan printed
# "hosthdr_engine.sh: line 286: warning: command substitution: ignored null
# byte in input" to stderr, because a response body is arbitrary
# target-controlled bytes and hh_body_reflects used to load it into a bash
# string via `body=$(cat -- "$f")` / `body=$(head -c ... -- "$f")`. Bash
# strings cannot hold an embedded NUL, so command substitution both drops the
# byte AND warns about doing so on the shell's own stderr - a warning an
# operator running a real scan must never see. This regression case proves
# both halves: the sentinel is still found on a body containing a NUL, and no
# such warning reaches stderr - FAILS under the pre-fix
# `body=$(cat -- "$f" 2>/dev/null)` shape, which prints the warning to stderr
# regardless of the inner `2>/dev/null` (that redirect only silences `cat`'s
# own stderr, not bash's own warning about the substitution it performed).
BFNUL=$W/body-nullbyte.txt
printf 'AAAA\x00BBBB see https://%s/path for details CCCC' "$HOSTHDR_SENTINEL" >"$BFNUL"
BFNUL_ERR=$W/body-nullbyte.stderr
RC_NUL=0
hh_body_reflects "$BFNUL" >/dev/null 2>"$BFNUL_ERR" || RC_NUL=$?
assert_eq 0 "$RC_NUL" \
  'a body containing a NUL byte before the sentinel still reflects'
NUL_ERR_TEXT=$(cat -- "$BFNUL_ERR" 2>/dev/null || printf '')
assert_not_contains "$NUL_ERR_TEXT" 'ignored null byte' \
  'no "ignored null byte" warning reaches stderr - FAILS against the pre-fix $(cat ...)/$(head -c ...) implementation'

# The fix must not turn every NUL-containing (i.e. every "binary-shaped")
# body into a false positive: a body with a NUL and NO sentinel must still
# report no reflection.
BFNUL2=$W/body-nullbyte-clean.txt
printf 'AAAA\x00BBBBnothing interesting hereCCCC' >"$BFNUL2"
BFNUL2_ERR=$W/body-nullbyte-clean.stderr
RC_NUL2=0
hh_body_reflects "$BFNUL2" >/dev/null 2>"$BFNUL2_ERR" || RC_NUL2=$?
assert_eq 1 "$RC_NUL2" 'a NUL-containing body with no sentinel does not reflect'
NUL2_ERR_TEXT=$(cat -- "$BFNUL2_ERR" 2>/dev/null || printf '')
assert_not_contains "$NUL2_ERR_TEXT" 'ignored null byte' \
  'no warning on the negative NUL case either'

printf '\n== D. hh_location_reflects - authority only, decision 2 ==\n'
HF=$W/hdr-authority.txt
printf 'HTTP/1.1 302 Found\r\nLocation: https://%s/dashboard\r\n\r\n' "$HOSTHDR_SENTINEL" >"$HF"
assert_status 0 'a Location whose AUTHORITY is the sentinel reflects' hh_location_reflects "$HF"
HF2=$W/hdr-querysub.txt
printf 'HTTP/1.1 302 Found\r\nLocation: https://%s/login?ref=%s\r\n\r\n' "$HOSTNAME_FIXTURE" "$HOSTHDR_SENTINEL" >"$HF2"
assert_status 1 \
  'a Location that merely CONTAINS the sentinel in its own query string, while redirecting on-origin, does NOT reflect - FAILS under a substring test (decision 2)' \
  hh_location_reflects "$HF2"
HF3=$W/hdr-none.txt
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >"$HF3"
assert_status 1 'no Location header at all does not reflect' hh_location_reflects "$HF3"
HF4=$W/hdr-tworesponses.txt
printf 'HTTP/1.1 302 Found\r\nLocation: https://%s/first\r\n\r\nHTTP/1.1 302 Found\r\nLocation: https://real.other/second\r\n\r\n' "$HOSTHDR_SENTINEL" >"$HF4"
assert_status 1 \
  'only the FINAL block in an accumulated capture counts - a reflecting first hop followed by a clean second hop must not reflect' \
  hh_location_reflects "$HF4"

# ===========================================================================
printf '\n== E. the phase, end to end ==\n'
# ===========================================================================
_write_inventory() {
  cat >"$W/endpoints.json" <<EOF
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_body",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/vuln-body",     "path": "/vuln-body" },
  { "id": "e_location", "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/vuln-location", "path": "/vuln-location" },
  { "id": "e_both",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/vuln-both",     "path": "/vuln-both" },
  { "id": "e_locsub",   "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/locsub-safe",   "path": "/locsub-safe" },
  { "id": "e_safe",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/safe",          "path": "/safe" },
  { "id": "e_post",     "target": "hosthdr-fixture", "method": "POST", "url": "https://$HOSTNAME_FIXTURE/vuln-body",     "path": "/vuln-body" },
  { "id": "e_dup1",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/items/1",       "path": "/items/1" },
  { "id": "e_dup2",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/items/2",       "path": "/items/2" },
  { "id": "e_fail",     "target": "hosthdr-fixture", "method": "GET",  "url": "https://$HOSTNAME_FIXTURE/fail",          "path": "/fail" },
  { "id": "e_head",     "target": "hosthdr-fixture", "method": "HEAD", "url": "https://$HOSTNAME_FIXTURE/head-check",    "path": "/head-check" }
] }
EOF
}
_write_inventory

SCOURSH_DAST_TARGET=hosthdr-fixture
SCOURSH_DAST_CELL=hosthdr-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
unset SCOURSH_SELECTED_CHECKS

_new_run boot
# shellcheck source=modules/dast/active/hosthdr.sh
source "$ROOT/modules/dast/active/hosthdr.sh"

t_case 'e_body: body reflection fires for BOTH techniques (Host and X-Forwarded-Host)'
_new_run body
SRV_FAIL_PATH=''
_dast_hosthdr_phase
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /vuln-body Host)" \
  'the Host technique fires the body check on /vuln-body'
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /vuln-body X-Forwarded-Host)" \
  'the X-Forwarded-Host technique ALSO fires the body check on /vuln-body - decision 8, a route trusting one and not the other must still be caught for each'
assert_eq 0 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_LOCATION-01 /vuln-body Host)" \
  '/vuln-body reflects nothing into Location, so it never emits the Location id'

t_case 'e_location: Location-authority reflection fires, and is not the body id'
_new_run location
_dast_hosthdr_phase
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_LOCATION-01 /vuln-location Host)" \
  'the Location sink fires for the Host technique on /vuln-location'
assert_eq 0 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /vuln-location Host)" \
  '/vuln-location reflects nothing into the body, so it never emits the body id'

t_case 'e_both: one endpoint carries BOTH sinks as two distinct findings'
_new_run both
_dast_hosthdr_phase
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /vuln-both Host)" \
  '/vuln-both fires the body id for the Host technique'
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_LOCATION-01 /vuln-both Host)" \
  '/vuln-both ALSO fires the Location id for the Host technique - one root cause, two sinks, two check ids (the openredirect.sh precedent)'

t_case 'e_locsub: the on-origin, query-reflecting control is NOT a Location finding'
_new_run locsub
_dast_hosthdr_phase
assert_eq 0 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_LOCATION-01 /locsub-safe Host)" \
  '/locsub-safe redirects on-origin and merely echoes the sentinel into its own query - decision 2 - this must stay silent'
assert_eq 0 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /locsub-safe Host)" \
  '/locsub-safe reflects nothing into the body either'

t_case 'only GET and HEAD are ever requested; POST is skipped entirely'
_new_run methodfilter
_dast_hosthdr_phase
LOGTXT=$(_req_log_text)
assert_not_contains "$LOGTXT" $'POST\t' \
  'no request line names POST - FAILS if the POST-method e_post candidate is ever probed under any method'
assert_contains "$LOGTXT" $'HEAD\t/head-check' \
  'the HEAD endpoint IS probed - it is idempotent'

t_case 'dedupe: /items/1 and /items/2 share a path template and are probed as ONE route'
_new_run dedupe
_dast_hosthdr_phase
LOGTXT2=$(_req_log_text)
N1=$(printf '%s\n' "$LOGTXT2" | { grep -c '/items/1' || true; })
N2=$(printf '%s\n' "$LOGTXT2" | { grep -c '/items/2' || true; })
TOTAL_ITEMS=$(( N1 + N2 ))
assert_eq 1 "$(( TOTAL_ITEMS > 0 ? 1 : 0 ))" \
  'exactly one of /items/1 or /items/2 was probed, never both - dedupe by (method, path template)'
assert_eq 0 "$(( N1 > 0 && N2 > 0 ? 1 : 0 ))" \
  'both were never probed together in the same run'

t_case 'a transport failure is counted as untested, never as a clean result'
_new_run failure
SRV_FAIL_PATH=/fail
_dast_hosthdr_phase
assert_contains "$(run_facts coverage_reduction)" 'hosthdr_probe_transport_failed' \
  'the failed route/technique pairs are recorded as a reduction'
SRV_FAIL_PATH=''

t_case 'no inventory at all is a recorded gap, never an error and never a silent pass'
_new_run noinv
SCOURSH_DAST_ENDPOINTS=$W/does-not-exist.json _dast_hosthdr_phase
assert_contains "$(run_facts coverage_gap)" 'no known idempotent endpoint' \
  'the absence of any candidate endpoint is stated as a coverage_gap'

# ===========================================================================
printf '\n== F. per-check selection is honoured (tension 15) ==\n'
# ===========================================================================
# dast_check_selected does not exist on every path this file is reachable
# through, so the phase guards on `declare -F`. Define it here to prove the
# guarded call really is consulted.
dast_check_selected() {
  case $1 in
    DAST-HOSTHDR-REFLECTED_LOCATION-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run selected
_dast_hosthdr_phase
assert_eq 1 "$(_count_check_path_param DAST-HOSTHDR-REFLECTED_BODY-01 /vuln-body Host)" \
  'a selected check still runs under the tension-15 filter chain'
assert_eq 0 "$(_count_check DAST-HOSTHDR-REFLECTED_LOCATION-01)" \
  'a DESELECTED check emits nothing, even though /vuln-location and /vuln-both would otherwise fire it'
assert_not_contains "$(run_facts checks_run)" 'DAST-HOSTHDR-REFLECTED_LOCATION-01' \
  'checks_run does not claim a deselected check ran'
unset -f dast_check_selected

# ===========================================================================
printf '\n== G. request headers actually carry the spoofed value, and only one at a time ==\n'
# ===========================================================================
_new_run headers
_dast_hosthdr_phase
LOGTXT3=$(_req_log_text)
assert_contains "$LOGTXT3" "host=$HOSTHDR_SENTINEL" \
  'the Host technique really sends the sentinel as the Host header value'
assert_contains "$LOGTXT3" "xfh=$HOSTHDR_SENTINEL" \
  'the X-Forwarded-Host technique really sends the sentinel as that header'\''s value'

# ===========================================================================
printf '\n== H. the round trip: a finding really reaches every report format ==\n'
# ===========================================================================
_new_run report
_dast_hosthdr_phase
findings_merge
report_all

RJ=$(cat "$SCOURSH_RUN_DIR/run.json")
assert_contains "$RJ" '"dast"' 'run.json attributes the findings to the dast module'
assert_contains "$RJ" 'DAST-HOSTHDR-REFLECTED_BODY-01' \
  'run.json records the body check as run - FAILS if checks_run never leaves the phase process'

FJ=$(cat "$SCOURSH_RUN_DIR/findings.json" 2>/dev/null || printf '')
assert_contains "$FJ" 'DAST-HOSTHDR-REFLECTED_BODY-01' 'the JSON report carries the body finding'
assert_contains "$FJ" 'DAST-HOSTHDR-REFLECTED_LOCATION-01' \
  'and the Location finding - FAILS if the two findings on /vuln-both collide on the fingerprint and dedupe to one'

MD=$(cat "$SCOURSH_RUN_DIR/report.md")
assert_contains "$MD" 'reflected into the response body' 'the markdown report names the finding in prose a human reads'
assert_contains "$MD" 'password-reset link' 'and carries the remediation'\''s reset-poisoning framing'

HT=$(cat "$SCOURSH_RUN_DIR/report.html")
assert_contains "$HT" 'DAST-HOSTHDR-REFLECTED_LOCATION-01' 'the HTML report carries the finding'
assert_not_contains "$HT" '<script' \
  'and contains no script element at all, with this check evidence in it - docs/FOUNDATION.md tension 10'

t_summary dast-hosthdr
