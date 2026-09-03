#!/usr/bin/env bash
# tests/suites/dast-inject-engine.sh - modules/dast/active/inject_engine.sh's
# `inject_send`: the shared request/response primitive behind essentially
# every §7.3 injection probe (sqli, xss, cmdi, pathtraversal, ssti, nosqli,
# ldapi, crlf, protopollution, and xxe/ssrf's parameter technique all call
# it), so a defect here has the widest blast radius of any DAST body-capture
# call site.
#
# Regression for the ticket ("Bound the same slurp-then-truncate body reads in
# other DAST body-capture call sites"), a follow-up to the
# modules/dast/active/discovery.sh fix: `inject_send` used to `read -r -d ''`
# the WHOLE captured response body (and, separately, the whole captured
# response header block) into a bash variable and only THEN trim the body to
# `_INJ_MAX_BODY_BYTES` - the header read had no cap applied at all, ever -
# so a target answering with a multi-hundred-MB response materialised it in
# full in this process before any cap could apply. `read -r -N CAP` stops
# reading once the cap is reached, whatever else remains on disk - the
# identical fix shape `_discovery_probe` already applies to its own single
# caller, applied here to every §7.3 injection probe at once.
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target").
#
# `inject_send` is driven directly here, by populating its own documented
# `_INJ_*` per-candidate arrays (the same arrays `inject_inventory_load`
# populates from an endpoints/parameters.json pair) rather than through a
# phase script and an inventory fixture - a white-box unit test of the shared
# primitive itself, mirroring how the discovery.sh ticket tested
# `_discovery_probe` directly rather than through `scan.sh dast`.
#
# shellcheck shell=bash
#
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-inject-engine-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope and scanner config - ceilings set high so DAST-32's clamp and DAST-01's
# real throttle sleep never interfere with this suite's own timing assertions.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: inj-fixture
base-url: https://inj.fixture.example/
notes: Fixture target for tests/suites/dast-inject-engine.sh. Never dialled -
  both the resolver and the transport are stubbed for the whole suite.
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

_inj_resolve() {
  case $1 in
    inj.fixture.example) printf '203.0.113.9' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_inj_resolve

# `_inj_set_candidate METHOD LOC` - populates a single candidate at index 0,
# the same arrays `inject_inventory_load` populates from JSON. `query` and
# `header` are the two locations this suite needs.
_inj_set_candidate() {
  local method=$1 loc=$2
  _INJ_N=1
  _INJ_TARGET=(inj-fixture)
  _INJ_METHOD=("$method")
  _INJ_URL=(https://inj.fixture.example/probe)
  _INJ_PATH=('')
  _INJ_NAME=(q)
  _INJ_LOCATION=("$loc")
  _INJ_EXAMPLE=(1)
  _INJ_EPID=(ep1)
}

REQ_LOG=$W/requests.log

# ===========================================================================
printf '== dast inject_engine: the response BODY read is bounded AT READ TIME, never after a full slurp ==\n'
# ===========================================================================
# Proof shape mirrors tests/suites/dast-discovery.sh's own huge-body case
# exactly: a 256 MiB body (1024x the default 256 KiB _INJ_MAX_BODY_BYTES cap)
# is served, and BOTH the reported length and the actual variable content are
# asserted at exactly the cap, with the whole call timed against a ceiling
# calibrated the same way that suite's own comment describes (measured
# directly on this host, through this exact harness: the fixed `-N` read
# finishes in well under 200ms; the un-bounded `read -d ''` this replaces
# takes 1.7+ seconds for the identical 256 MiB body).
HUGEFILE=$W/huge-body.raw
if [[ ! -f $HUGEFILE ]]; then
  hs='a'
  for _ in $(seq 1 28); do hs+=$hs; done
  printf '%s' "$hs" >"$HUGEFILE"
  unset hs
fi

_inj_huge_body_transport() {
  local method=$1 path=$5
  local status=404
  case $path in
    /probe*) status=200 ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $path == /probe* ]]; then
      cp -- "$HUGEFILE" "$_HTTP_TX_BODY_OUT"
    else
      printf 'not found' >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '%s\n\n%s\n' "$status" 'text/html'
}

# ---------------------------------------------------------------------------
# THE TIME CEILING BELOW IS CALIBRATED ON THIS HOST, NOT AN ABSOLUTE CONSTANT.
#
# The body case asserts that the read is bounded AT READ TIME by timing it,
# and an absolute millisecond ceiling cannot be right on two machines an order
# of magnitude apart in CPU and I/O.  The 800ms constant this replaces was
# calibrated on a contributor's Mac; on `macos-latest` this case measured
# 801ms and failed the whole job by one millisecond (run 33677872951) with the
# property under test entirely intact.  A ceiling that fails on a slow machine
# for being slow is testing the machine.
#
# So the ceiling is derived here from the cost of the shape the fix REPLACED,
# measured on whatever host is running: copy the fixture into place and slurp
# the whole of it with the un-bounded `read -d ''` the engine used to use.
# The bounded read pays the copy and then reads a fixed 256 KiB cap, so it
# lands far under half that figure; the un-bounded read pays the copy AND the
# slurp, so it cannot - which is what keeps this assertion failing under the
# implementation it exists to reject, on a fast host and a slow one alike.
# The 800ms floor keeps the ceiling from ever becoming TIGHTER than the
# constant it replaces.
_prefix_slurp_cost_ms() {   # $1 fixture -> ms for `cp` plus a full un-bounded slurp
  local src=$1 dst=$W/timing-calibration.raw t0 t1 _slurped
  t0=$(now_epoch_ns)
  cp -- "$src" "$dst"
  # The pre-fix shape, verbatim: no `-N`, so this reads to EOF.  `read` exits
  # non-zero at EOF, which is the normal case here and not a failure.
  IFS= read -r -d '' _slurped <"$dst" || true
  t1=$(now_epoch_ns)
  rm -f -- "$dst"
  printf '%s' "$(( (t1 - t0) / 1000000 ))"
}
_bounded_read_ceiling_ms() {  # $1 fixture -> half the pre-fix cost, never under 800
  local c
  c=$(( $(_prefix_slurp_cost_ms "$1") / 2 ))
  (( c < 800 )) && c=800
  printf '%s' "$c"
}

_inj_set_candidate GET query
SCOURSH_HTTP_TRANSPORT=_inj_huge_body_transport
t0=$(now_epoch_ns)
huge_rc=0
inject_send 0 'x' || huge_rc=$?
t1=$(now_epoch_ns)
huge_ms=$(( (t1 - t0) / 1000000 ))

assert_eq 0 "$huge_rc" 'inject_send itself succeeds for a large-but-reachable body'
assert_eq "$_INJ_MAX_BODY_BYTES" "${#_INJ_BODY}" \
  "a 256 MiB body (1024x the cap) leaves _INJ_BODY holding exactly the ${_INJ_MAX_BODY_BYTES}-byte cap - FAILS if the cap is applied to what is RETAINED after a full read rather than to what is READ"
huge_ceiling_ms=$(_bounded_read_ceiling_ms "$HUGEFILE")
assert_true "$([[ $huge_ms -lt $huge_ceiling_ms ]] && echo 0 || echo 1)" \
  "inject_send completed in ${huge_ms}ms for a 256 MiB body, inside this host's own ${huge_ceiling_ms}ms ceiling - FAILS under the un-bounded \`read -d ''\` this replaces, which must slurp the whole body before trimming it and so cannot come in under half its own measured cost"

# ===========================================================================
printf '== dast inject_engine: the response HEADER read (opt-in via _INJ_WANT_HEADERS) is ALSO bounded AT READ TIME ==\n'
# ===========================================================================
# This read previously carried NO cap at all, not even an after-the-fact trim
# - worse than the body's own pre-fix shape. DAST-19 (active/openredirect.sh)
# is the one probe that turns _INJ_WANT_HEADERS on today, for its Location
# signal; a target answering with an oversized or pathologically repeated
# header block would otherwise be slurped whole here on every probe that
# reads it.
HUGEHDRFILE=$W/huge-headers.raw
if [[ ! -f $HUGEHDRFILE ]]; then
  # ~5 MiB of header lines (80x the default 64 KiB _INJ_MAX_HEADERS_BYTES
  # cap), built via string doubling rather than a per-line loop - measured
  # faster for the same size, the identical technique
  # tests/suites/dast-discovery.sh's own huge-body fixture uses, per this
  # repository's own "fixture SETUP, not the code under test" convention.
  hdrline=$'X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n'
  hs=$hdrline
  for _ in $(seq 1 16); do hs+=$hs; done
  {
    printf 'HTTP/1.1 200 OK\r\n'
    printf '%s' "$hs"
    printf '\r\n'
  } >"$HUGEHDRFILE"
  unset hdrline hs
fi

_inj_huge_headers_transport() {
  local method=$1 path=$5
  local status=404
  case $path in
    /probe*) status=200 ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    printf 'ok' >"$_HTTP_TX_BODY_OUT"
  fi
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    cp -- "$HUGEHDRFILE" "$_HTTP_TX_HEADERS_OUT"
  fi
  printf '%s\n\n%s\n' "$status" 'text/html'
}

_inj_set_candidate GET query
_INJ_WANT_HEADERS=1
SCOURSH_HTTP_TRANSPORT=_inj_huge_headers_transport
t0=$(now_epoch_ns)
hdr_rc=0
inject_send 0 'x' || hdr_rc=$?
t1=$(now_epoch_ns)
hdr_ms=$(( (t1 - t0) / 1000000 ))
_INJ_WANT_HEADERS=0

assert_eq 0 "$hdr_rc" 'inject_send succeeds for a large header block'
assert_eq "$_INJ_MAX_HEADERS_BYTES" "${#_INJ_HEADERS}" \
  "a ~4 MiB header block (64x the cap) leaves _INJ_HEADERS holding exactly the ${_INJ_MAX_HEADERS_BYTES}-byte cap - FAILS if the read has no cap at all (the pre-fix shape) or if the cap were only applied after a full slurp"
assert_true "$([[ $hdr_ms -lt 800 ]] && echo 0 || echo 1)" \
  "inject_send completed in ${hdr_ms}ms for the oversized header block - an unbounded \`read -d ''\` over the same fixture is measured well past this ceiling on this host"

# ===========================================================================
printf '== dast inject_engine: an embedded NUL byte in the body does not abort inject_send ==\n'
# ===========================================================================
# bash variables cannot hold a NUL byte under EITHER reading (see
# discovery.sh's identical note) - what must hold under the fix is that the
# read still completes cleanly under this suite's own `set -Eeuo pipefail`
# and the reported length never exceeds the cap.
NULBODY=$W/nul-body.raw
printf 'abc\x00def\x00ghi' >"$NULBODY"
_inj_nul_transport() {
  local method=$1 path=$5
  local status=404
  case $path in
    /probe*) status=200 ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $path == /probe* ]]; then
      cp -- "$NULBODY" "$_HTTP_TX_BODY_OUT"
    else
      printf 'not found' >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '%s\n\n%s\n' "$status" 'text/html'
}
_inj_set_candidate GET query
SCOURSH_HTTP_TRANSPORT=_inj_nul_transport
nul_rc=0
inject_send 0 'x' || nul_rc=$?
assert_eq 0 "$nul_rc" \
  'a body carrying embedded NUL bytes does not abort inject_send - FAILS if the bounded read chokes on a NUL rather than just losing it'
assert_true "$([[ ${#_INJ_BODY} -le $_INJ_MAX_BODY_BYTES ]] && echo 0 || echo 1)" \
  "_INJ_BODY (${#_INJ_BODY} bytes) still never exceeds the cap for a body containing embedded NULs"

t_summary 'dast-inject-engine'
