#!/usr/bin/env bash
# tests/suites/dast-openredirect.sh - modules/dast/active/openredirect.sh: the
# §7.3 open-redirect probe (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md
# DAST-19, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and every response is a RECORDED
# one composed by the mock below (docs/DESIGN.md §12: "DAST logic is testable
# with no live target"). The suite runs on a host with no network and no Docker.
#
# Each case that pins a decision NAMES THE READING IT FAILS UNDER, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing and is worse than no test.
#
#   1. the signal is the AUTHORITY of the Location URL, never a substring of it:
#      a target that reflects the payload into a query string while redirecting
#      on-origin is NOT flagged.
#   2. userinfo is stripped at the LAST `@`, so `https://<site>@<sentinel>/` is
#      a finding - the case a prefix allow-list lets through and a naive parser
#      reads as the site's own host.
#   3. a subdomain OF the sentinel is the sentinel's; a host merely CONTAINING
#      the sentinel as a left-hand label is the target's. Both directions.
#   4. the scheme-relative, single-slash and backslash payload forms are parsed
#      the way a browser parses them, not more strictly.
#   5. the redirect is DETECTED and never FOLLOWED - no request leaves the
#      target's origin and the gate is never asked about the sentinel.
#   6. Location and meta-refresh are two check ids, so both fire on one
#      parameter rather than deduping to one.
#   7. the candidate filter matches `returnUrl` from the entry `returnurl`, and
#      catches a differently-named parameter by its URL-shaped example.
#   8. no parameter surface / no candidate / missing payloads each degrade to a
#      recorded coverage gap, never a clean-looking result and never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes URL and parameter syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut: modules/dast/active/inject_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-openredirect-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
HOSTNAME_FIXTURE=or.fixture.example
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: or-fixture
base-url: https://or.fixture.example/
notes: Fixture target for tests/suites/dast-openredirect.sh. Never dialled:
  both the resolver and the transport are stubbed.
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

# The resolver answers for the fixture host and NOTHING else. A probe that ever
# tried to follow a redirect to the sentinel would land here first.
_or_resolve() { case $1 in or.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_or_resolve

# ---------------------------------------------------------------------------
# Percent-decoding, so the mock decides on the value the "application" sees.
# ---------------------------------------------------------------------------
# inject_engine.sh percent-encodes the payload into the query string, exactly as
# a real client would; the mock therefore decodes it rather than matching
# encoded bytes, which would make every assertion below a statement about
# inject_urlencode instead of about the probe.
_pctdec() {
  local s=$1 out='' i c hx
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    if [[ $c == '%' && ${s:i+1:2} =~ ^[0-9A-Fa-f]{2}$ ]]; then
      hx=${s:i+1:2}
      printf -v c '\\x%s' "$hx"
      printf -v c '%b' "$c"
      out+=$c
      i=$(( i + 2 ))
    elif [[ $c == '+' ]]; then
      out+=' '
    else
      out+=$c
    fi
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# Every endpoint below models ONE redirect-filter behaviour that really exists
# in the wild, and the controls model the two safe behaviours that a careless
# detector reports as findings.
#
#   /redir      next       VULNERABLE, no filter at all: reflects any absolute
#                          URL straight into Location.
#   /schemerel  goto       VULNERABLE, but rejects anything containing ':' - so
#                          only the SCHEME-RELATIVE payload gets through.
#   /prefix     url        VULNERABLE via USERINFO: accepts a value that starts
#                          with the site's own origin, which
#                          `https://<site>@<sentinel>/` does.
#   /subdom     dest       VULNERABLE via a TARGET-PREFIXED SUBDOMAIN: same
#                          prefix filter, but it also rejects '@', so only
#                          `https://<site>.<sentinel>/` gets through.
#   /post       returnUrl  VULNERABLE through a BODY field, and named in the
#                          camelCase spelling the vendored list holds normalised.
#   /example    zzz        VULNERABLE, and named nothing like a redirect - it is
#                          reached only by the URL-shaped-example rule.
#   /meta       link       VULNERABLE via a META REFRESH; 200, no Location.
#   /both       redirect   VULNERABLE via BOTH sinks on one response.
#   /reflect    return     SAFE control: redirects ON-ORIGIN and reflects the
#                          payload into its own query string.
#   /mirror     back       SAFE control: redirects to a host of its OWN that
#                          merely begins with the sentinel's label.
#   /relative   to         SAFE control: a relative Location.
#   /notcand    flavour    Not a candidate at all - never probed.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

_or_transport() {
  local method=$1 host=$3 path=$5
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local body=${_HTTP_TX_BODY:-}
  local qs=${path#*\?} v='' status=200 location='' out='<html><body>ok</body></html>'
  [[ $qs == "$path" ]] && qs=''
  # The one injected field (the mock's endpoints each carry exactly one), from
  # the query string or, for /post, the urlencoded body.
  local surface=$qs
  [[ $path == /post* ]] && surface=$body
  v=${surface#*=}
  v=${v%%&*}
  v=$(_pctdec "$v")

  local origin="https://$HOSTNAME_FIXTURE"
  case ${path%%\?*} in
    /redir)
      if [[ $v == http://* || $v == https://* ]]; then status=302; location=$v; fi ;;
    /schemerel)
      # Rejects anything with a scheme; `//host/` has none.
      if [[ $v != *:* && $v == //* ]]; then status=302; location=$v; fi ;;
    /prefix)
      # Accepts the site's own origin as a prefix, and ONLY the userinfo form
      # gets past it: the `<origin>.` subdomain form is rejected here so that
      # this endpoint isolates the userinfo class. Without that exclusion the
      # subdomain payload also satisfies the filter, and the assertion below
      # would still pass with the userinfo split removed entirely - i.e. it
      # would pin nothing, which is measured: dropping `${authority##*@}` left
      # this case green until the exclusion was added.
      if [[ $v == "$origin"* && $v != "$origin".* ]]; then status=302; location=$v; fi ;;
    /subdom)
      if [[ $v == "$origin"* && $v != *@* ]]; then status=302; location=$v; fi ;;
    /post)
      if [[ $v == http://* || $v == https://* ]]; then status=302; location=$v; fi ;;
    /example)
      if [[ $v == http://* || $v == https://* ]]; then status=302; location=$v; fi ;;
    /meta)
      out="<html><head><meta http-equiv=\"refresh\" content=\"0; url=$v\"></head><body>go</body></html>" ;;
    /both)
      if [[ $v == http://* || $v == https://* ]]; then
        status=302; location=$v
        out="<html><head><META HTTP-EQUIV='REFRESH' CONTENT='0;URL=$v'></head><body>go</body></html>"
      fi ;;
    /reflect)
      # SAFE: always on-origin, with the payload echoed into its own query.
      status=302; location="$origin/login?return=$v" ;;
    /mirror)
      # SAFE: a host the TARGET owns whose leftmost label happens to be the
      # sentinel's name. The payload's own authority is lifted out first (the
      # whole payload would otherwise drag its path in and leave the sentinel
      # as the authority, which would make this endpoint genuinely vulnerable
      # and the control meaningless).
      local mh=${v#*//}; mh=${mh%%/*}; mh=${mh##*@}
      status=302; location="https://$mh.$HOSTNAME_FIXTURE/" ;;
    /relative)
      status=302; location='/dashboard' ;;
  esac

  printf '%s %s %s\n' "$method" "$host" "${path%%\?*}" >>"$REQ_LOG"
  if [[ -n $hdrsout ]]; then
    {
      printf 'HTTP/1.1 %s Found\r\n' "$status"
      [[ -n $location ]] && printf 'Location: %s\r\n' "$location"
      printf 'Content-Type: text/html\r\n\r\n'
    } >>"$hdrsout"
  fi
  [[ -n $bodyout ]] && printf '%s' "$out" >"$bodyout"
  printf '%s\n%s\n%s\n' "$status" "$location" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_or_transport

# ---------------------------------------------------------------------------
# Inventory (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_redir",     "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/redir",     "path": "/redir" },
  { "id": "e_schemerel", "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/schemerel", "path": "/schemerel" },
  { "id": "e_prefix",    "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/prefix",    "path": "/prefix" },
  { "id": "e_subdom",    "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/subdom",    "path": "/subdom" },
  { "id": "e_post",      "target": "or-fixture", "method": "POST", "url": "https://or.fixture.example/post",      "path": "/post" },
  { "id": "e_example",   "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/example",   "path": "/example" },
  { "id": "e_meta",      "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/meta",      "path": "/meta" },
  { "id": "e_both",      "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/both",      "path": "/both" },
  { "id": "e_reflect",   "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/reflect",   "path": "/reflect" },
  { "id": "e_mirror",    "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/mirror",    "path": "/mirror" },
  { "id": "e_relative",  "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/relative",  "path": "/relative" },
  { "id": "e_notcand",   "target": "or-fixture", "method": "GET",  "url": "https://or.fixture.example/notcand",   "path": "/notcand" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "q1",  "endpoint_id": "e_redir",     "target": "or-fixture", "name": "next",      "location": "query", "example": "/home" },
  { "id": "q2",  "endpoint_id": "e_schemerel", "target": "or-fixture", "name": "goto",      "location": "query", "example": "/home" },
  { "id": "q3",  "endpoint_id": "e_prefix",    "target": "or-fixture", "name": "url",       "location": "query", "example": "/home" },
  { "id": "q4",  "endpoint_id": "e_subdom",    "target": "or-fixture", "name": "dest",      "location": "query", "example": "/home" },
  { "id": "q5",  "endpoint_id": "e_post",      "target": "or-fixture", "name": "returnUrl", "location": "body",  "example": "/home" },
  { "id": "q6",  "endpoint_id": "e_example",   "target": "or-fixture", "name": "zzz",       "location": "query", "example": "https://partner.example/landing" },
  { "id": "q7",  "endpoint_id": "e_meta",      "target": "or-fixture", "name": "link",      "location": "query", "example": "/home" },
  { "id": "q8",  "endpoint_id": "e_both",      "target": "or-fixture", "name": "redirect",  "location": "query", "example": "/home" },
  { "id": "q9",  "endpoint_id": "e_reflect",   "target": "or-fixture", "name": "return",    "location": "query", "example": "/home" },
  { "id": "q10", "endpoint_id": "e_mirror",    "target": "or-fixture", "name": "back",      "location": "query", "example": "/home" },
  { "id": "q11", "endpoint_id": "e_relative",  "target": "or-fixture", "name": "to",        "location": "query", "example": "/home" },
  { "id": "q12", "endpoint_id": "e_notcand",   "target": "or-fixture", "name": "flavour",   "location": "query", "example": "vanilla" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and shard readers (the shape tests/suites/dast-sqli.sh
# established: one finding per line, fields TAB-delimited as `key=value`).
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target or-fixture
  occurrence_reset_all
  _req_reset
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

_count_finding() {
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

_count_param() {
  local param=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "loc_param_name=$param" ]] && { n=$(( n + 1 )); break; }
      done
    done <"$f"
  done
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Load the phase's functions. A phase script has no sourced-once guard and runs
# its phase function at source time (that is how dast_run_phase invokes it), so
# it is sourced once here against a throwaway run with no inventory - a harmless
# no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=or-fixture
SCOURSH_DAST_CELL=or-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/openredirect.sh
source "$ROOT/modules/dast/active/openredirect.sh"

# ===========================================================================
printf '== dast openredirect: URL authority parsing (the whole probe rests here) ==\n'
# ===========================================================================
_OR_SENTINEL=scoursh-or-deadbeef.invalid

_or_url_host 'https://evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" 'a plain absolute URL yields its host'
_or_url_host '//evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" \
  'a SCHEME-RELATIVE URL has an authority - FAILS under a parser that requires a scheme, which would report the off-origin `//host/` redirect as safe'
_or_url_host 'https:/evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" \
  'a SINGLE-SLASH scheme is normalised the way a browser normalises it - FAILS under a parser stricter than the client that will follow the redirect'
_or_url_host '/\evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" \
  'a BACKSLASH after the leading slash is folded to a slash (WHATWG URL) - FAILS under a parser that reads `/\host` as a local path'
_or_url_host 'https://or.fixture.example@evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" \
  'USERINFO is stripped, so the host is what follows the @ - FAILS under a parser that ignores userinfo, which reads this as the site own host and reports a real open redirect as clean'
_or_url_host 'https://a@b@evil.example/x'
assert_eq 'evil.example' "$_OR_HOST" \
  'the split is on the LAST @, per WHATWG URL - FAILS under a first-@ split, which yields `b@evil.example`'
_or_url_host 'https://evil.example:8443/x'
assert_eq 'evil.example' "$_OR_HOST" 'the port is stripped from the authority'
_or_url_host 'https://[2001:db8::1]:8443/x'
assert_eq '2001:db8::1' "$_OR_HOST" \
  'an IPv6 literal keeps its address and loses its port - FAILS under a naive `${a%%:*}` port strip, which truncates at the first colon INSIDE the address'
_or_url_host 'https://EVIL.Example/x'
assert_eq 'evil.example' "$_OR_HOST" 'the host is lowercased (a hostname is case-insensitive)'

if _or_url_host '/dashboard'; then
  _t_no 'relative Location' 'a relative URL must report NO authority'
else
  _t_ok 'a RELATIVE Location has no authority, so it can never be a finding - FAILS under a parser that invents one'
fi
if _or_url_host 'mailto:someone@evil.example'; then
  _t_no 'opaque scheme' 'mailto: has no authority'
else
  _t_ok 'an opaque `mailto:` URL has no authority - FAILS under a parser that splits on @ before checking for one'
fi

# The sentinel-ownership test, both directions.
if _or_host_is_sentinel 'scoursh-or-deadbeef.invalid'; then
  _t_ok 'the sentinel host itself is the sentinel'
else
  _t_no 'sentinel exact' 'must match itself'
fi
if _or_host_is_sentinel 'or.fixture.example.scoursh-or-deadbeef.invalid'; then
  _t_ok 'a SUBDOMAIN of the sentinel belongs to the sentinel - FAILS under exact-equality only, which makes the target-prefixed-subdomain payload undetectable'
else
  _t_no 'sentinel subdomain' 'a subdomain of the sentinel is the sentinel'
fi
if _or_host_is_sentinel 'scoursh-or-deadbeef.invalid.or.fixture.example'; then
  _t_no 'sentinel mirror' 'a host that merely CONTAINS the sentinel as a left-hand label is the TARGET own host'
else
  _t_ok 'a host containing the sentinel as a leftmost LABEL is NOT the sentinel - FAILS under a substring test, which would flag the target own hostname'
fi

# ===========================================================================
printf '== dast openredirect: the sentinel is reserved, random, and unguessable-by-accident ==\n'
# ===========================================================================
_or_sentinel_set; S1=$_OR_SENTINEL
_or_sentinel_set; S2=$_OR_SENTINEL
assert_contains "$S1" '.invalid' \
  'the sentinel lives under the RFC 6761 .invalid TLD, which is guaranteed never to resolve - FAILS the moment a real, registrable domain is used as a sentinel, which would make the tool target-specific and make an accidentally-followed redirect reach somebody'
if [[ $S1 == "$S2" ]]; then
  _t_no 'sentinel randomness' 'two sentinels in one process must differ'
else
  _t_ok 'the sentinel is fresh per call - FAILS under a constant, which would let a cached page or a previous scan supply the Location this probe reads as its own proof'
fi

# ===========================================================================
printf '== dast openredirect: the probe fires on every real filter-bypass class ==\n'
# ===========================================================================
SCOURSH_DAST_INTENSITY=active
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_INTENSITY SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
unset SCOURSH_SELECTED_CHECKS

_write_inventory
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
STDERR=$W/main.stderr
_dast_openredirect_phase 2>"$STDERR"

assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 next)" \
  'the unfiltered endpoint is flagged from its Location header'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 goto)" \
  'an endpoint that accepts ONLY the scheme-relative form is still flagged - FAILS if the `//host/` payload was dropped as "not a URL"'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 url)" \
  'a prefix allow-list defeated by USERINFO is flagged - FAILS if the parser reads `https://site@sentinel/` as the site own host, the false negative that reads as a pass'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 dest)" \
  'a prefix allow-list defeated by a TARGET-PREFIXED SUBDOMAIN is flagged - FAILS under exact host equality against the sentinel'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 returnUrl)" \
  'a BODY parameter is probed, and `returnUrl` matches the vendored entry `returnurl` - FAILS if only query strings are injected, or if the name match is case- and separator-sensitive'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 zzz)" \
  'a parameter named nothing like a redirect is still probed when its observed EXAMPLE is an absolute URL - FAILS if the name list is the only candidate rule'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_META-01 link)" \
  'a meta-refresh with no Location header at all is flagged under its own check id - FAILS if the probe only ever reads response headers'

# --- the controls: three ways to be safe, none of them a finding -----------
assert_eq 0 "$(_count_param return)" \
  'an ON-ORIGIN redirect that merely REFLECTS the payload into its own query string is NOT flagged - FAILS under a substring match on the Location value, which is the single commonest false positive in this check'
assert_eq 0 "$(_count_param back)" \
  'a redirect to a host the TARGET owns whose leftmost label is the sentinel is NOT flagged - FAILS under a substring or prefix test on the host'
assert_eq 0 "$(_count_param to)" \
  'a RELATIVE Location is NOT flagged - FAILS if a redirect with no authority is treated as off-origin'
assert_eq 0 "$(_count_param flavour)" \
  'a parameter that is neither redirect-named nor URL-shaped is never probed and never flagged'

# ===========================================================================
printf '== dast openredirect: the redirect is DETECTED and never FOLLOWED ==\n'
# ===========================================================================
# Two independent observations, because each alone is satisfiable by the bug.
# (a) no request ever left the target origin; (b) lib/http.sh never had to
# REFUSE a hop - a probe that asked to follow would leave the gate's own
# "redirect not followed" warning behind even though no packet moved.
BADHOST=0
while IFS=' ' read -r _ h _; do
  [[ -n $h ]] || continue
  [[ $h == "$HOSTNAME_FIXTURE" ]] || BADHOST=1
done <"$REQ_LOG"
assert_eq 0 "$BADHOST" \
  'every request went to the authorised target host and none to the sentinel - FAILS if the probe follows the redirect it just detected'
assert_not_contains "$(cat "$STDERR")" 'redirect not followed' \
  'the scope gate was never even ASKED about the sentinel - FAILS if _INJ_MAX_REDIRECTS is left at the engine default, in which case http_request offers the hop to the gate and logs its refusal (a bug the request log alone cannot see)'
assert_not_contains "$(cat "$REQ_LOG")" '.invalid' \
  'no request was addressed to a .invalid host'

# ===========================================================================
printf '== dast openredirect: two sinks on one parameter are two findings ==\n'
# ===========================================================================
# The DAST fingerprint is (target, method, path_template, param_location,
# param_name) and carries nothing naming the SINK, so one check id would make
# these collide and findings_merge would keep one.
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 redirect)" \
  'the Location sink fires on the both-sinks endpoint'
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_META-01 redirect)" \
  'the meta-refresh sink ALSO fires on the same parameter - FAILS under a single shared check id (fingerprint collision) and FAILS under control flow that breaks out after the first sink'
assert_eq 2 "$(_count_param redirect)" \
  'exactly two findings on that one parameter, no more and no fewer'

# ===========================================================================
printf '== dast openredirect: findings carry the mandated metadata ==\n'
# ===========================================================================
TEXT=$(_shard_text)
assert_contains "$TEXT" 'cwe=CWE-601' 'findings carry CWE-601 (URL redirection to untrusted site)'
assert_contains "$TEXT" 'owasp=A01:2021' 'findings carry the OWASP A01:2021 mapping'
assert_contains "$TEXT" 'module=dast' 'findings are attributed to the dast module'
assert_contains "$TEXT" 'cell=or-fixture' "the DAST coverage cell is the scope target id"
assert_contains "$TEXT" 'remediation=' 'findings carry remediation text'
assert_contains "$TEXT" "$_OR_SENTINEL" \
  'the evidence names the single-use sentinel that proves the destination came from this request'

CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-OPENREDIR_HEADER-01' \
  'checks_run records the header check that executed over a parameter, so modules/dast/run.sh honesty roll-up does not report covered-nothing'
assert_contains "$CR" 'DAST-INJ-OPENREDIR_META-01' 'checks_run records the meta check'
assert_contains "$(run_facts coverage_reduction)" 'openredirect_parameter_not_redirect_shaped' \
  'the parameters this probe declined to test are a RECORDED coverage reduction with a count - FAILS if a parameter that was never probed is allowed to read as one that came back clean'

# ===========================================================================
printf '== dast openredirect: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_openredirect_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  'with no inventory the probe emits NO finding - a clean result with nothing tested is the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  'no parameter surface records a coverage_gap the report renders'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run is EMPTY when nothing was tested - recording it here would overstate coverage'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast openredirect: a surface with no redirect-shaped parameter ==\n'
# ===========================================================================
cat >"$W/none-endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_n", "target": "or-fixture", "method": "GET", "url": "https://or.fixture.example/n", "path": "/n" }
] }
EOF
cat >"$W/none-parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "n1", "endpoint_id": "e_n", "target": "or-fixture", "name": "flavour", "location": "query", "example": "vanilla" }
] }
EOF
_new_run nocand
SCOURSH_DAST_ENDPOINTS=$W/none-endpoints.json
SCOURSH_DAST_PARAMETERS=$W/none-parameters.json
_dast_openredirect_phase
assert_eq 0 "$(wc -l <"$REQ_LOG" | tr -d ' ')" \
  'a surface with no redirect-shaped parameter sends NO request at all'
assert_contains "$(run_facts coverage_gap)" 'none of them was a redirect-influencing parameter' \
  'and it says so in a coverage_gap - FAILS if "we probed nothing" is allowed to render as "we found nothing"'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run stays empty when no candidate parameter existed'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast openredirect: missing payloads degrade to a recorded gap ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_write_inventory
_new_run degrade
rc=0
SCOURSH_DAST_OPENREDIRECT_PAYLOAD_DIR=$W/empty-payloads _dast_openredirect_phase || rc=$?
assert_eq 0 "$rc" \
  'an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'no payloads means no finding is emitted'
assert_contains "$(run_facts coverage_reduction)" 'openredirect_payloads_missing' \
  'the absent payload file is a recorded coverage_reduction, not a silent skip'
assert_contains "$(run_facts coverage_gap)" 'no open-redirect payloads are available' \
  'with no payloads a coverage_gap says so - a clean result here is not a clean bill of health'

# A payload file present but the NAME list gone: the probe still runs on the
# URL-shaped-example rule and records the narrower reduction.
mkdir -p "$W/partial-payloads"
cp "$ROOT/modules/dast/payloads/openredirect-payloads.txt" "$W/partial-payloads/"
_new_run partial
SCOURSH_DAST_OPENREDIRECT_PAYLOAD_DIR=$W/partial-payloads _dast_openredirect_phase
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 zzz)" \
  'without the name list the URL-shaped-example rule still finds the vulnerable parameter - a missing data file degrades only what it owns'
assert_eq 0 "$(_count_param next)" \
  'and the name-only candidates are NOT probed - FAILS if the missing list silently falls back to probing everything'
assert_contains "$(run_facts coverage_reduction)" 'openredirect_param_names_missing' \
  'the missing name list is recorded as its own coverage_reduction'

# ===========================================================================
printf '== dast openredirect: per-check selection is honoured ==\n'
# ===========================================================================
# `dast_check_selected` does not exist on every path this file is reachable
# through, so the probe guards on `declare -F`. Define it here to prove the
# guarded call really is consulted.
dast_check_selected() {
  case $1 in
    DAST-INJ-OPENREDIR_META-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run selected
_write_inventory
_dast_openredirect_phase
assert_eq 1 "$(_count_finding DAST-INJ-OPENREDIR_HEADER-01 next)" \
  'a selected check still runs under the tension-15 filter chain'
assert_eq 0 "$(_count_finding DAST-INJ-OPENREDIR_META-01 link)" \
  'a DESELECTED check emits nothing - FAILS if the probe ignores SCOURSH_SELECTED_CHECKS and reports a check the run excluded'
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-OPENREDIR_META-01' \
  'checks_run does not claim a deselected check ran'
unset -f dast_check_selected

# ===========================================================================
printf '== dast openredirect: the vendored payloads are safe and target-agnostic ==\n'
# ===========================================================================
PF=$ROOT/modules/dast/payloads/openredirect-payloads.txt
NOSENT=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *%S* ]] || NOSENT=1
done <"$PF"
assert_eq 0 "$NOSENT" \
  'every vendored payload carries the %S sentinel placeholder - FAILS the moment a payload names a fixed host, which would both break detection and bake a scan target into a shipped file (§1)'
if grep -Eq '^[^#]*(\.com|\.net|\.org|\.io|\.co\.uk)([/:]|$)' "$PF"; then
  _t_no 'payload target-agnostic' 'a vendored payload names a registrable domain'
else
  _t_ok 'no vendored payload names a registrable domain - FAILS if a real host is baked in, which DAST-35 lint and docs/DESIGN.md §1 both forbid'
fi
if grep -Eiq '^[^#]*(javascript:|data:)' "$PF"; then
  _t_no 'payload non-destructive' 'a vendored payload carries a script-executing scheme'
else
  _t_ok 'no vendored payload carries a javascript:/data: scheme - this probe detects a redirect, it does not attempt XSS (DAST-15 own scope)'
fi

# ===========================================================================
printf '== inject_engine: the two opt-in knobs leave every other probe alone ==\n'
# ===========================================================================
# The header capture and the redirect override are OPT-IN and default to the
# behaviour every §7.3 probe written before them already had.
if ( unset _INJ_WANT_HEADERS _INJ_MAX_REDIRECTS
     unset SCOURSH_DAST_INJECT_ENGINE_SOURCED
     # -x back-edge cut: modules/dast/active/inject_engine.sh
     # is already inlined elsewhere in this file's own source graph, and shellcheck
     # re-expands EVERY source edge it follows.  Cutting this one loses no checking
     # and is what keeps the linter's memory bounded - see the shellcheck stage in
     # tests/run-tests.sh, and docs/CI-RUNBOOK.md.
     # shellcheck source=/dev/null
     source "$ROOT/modules/dast/active/inject_engine.sh"
     [[ ${_INJ_WANT_HEADERS} == 0 && -z ${_INJ_MAX_REDIRECTS} ]] ); then
  _t_ok 'inject_engine defaults are header-capture OFF and the redirect count unchanged - FAILS if this ticket changed what active/sqli.sh does'
else
  _t_no 'inject_engine defaults' 'the new knobs must default to the pre-existing behaviour'
fi

t_summary dast-openredirect
