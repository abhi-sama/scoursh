#!/usr/bin/env bash
# tests/suites/dast-banner.sh - modules/dast/passive/banner.sh and
# banner_engine.sh: server/framework disclosure, version disclosure, and
# out-of-date components matched against the vendored data/versions.db
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-09).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and the transport serves
# RECORDED responses from tests/fixtures/dast/banner/ (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"), so this suite runs on a host with no
# network and no Docker, exactly like tests/suites/dast-jwt.sh.  The vulnerable-
# version list is a FIXTURE database whose every product name is invented: a
# real claim about a real product's real version is a fact this repository
# cannot verify offline, and inventing one would be the same mistake as
# hardcoding an unverified checksum.
#
# The decisions this suite pins, each with a plausible wrong reading that would
# otherwise ship green:
#
#   1. A parenthesised platform comment (`Apache/2.4.41 (Ubuntu)`) is NOT a
#      product; a naive whitespace split reports `ubuntu` and puts a row nothing
#      can match into the report.
#   2. A header whose VALUE is a bare version takes its product from the header
#      NAME (`X-AspNet-Version: 4.0.30319`), except on `Via`, where the leading
#      bare version is the protocol's.
#   3. `<META NAME="generator">` is found: a case-sensitive glob misses the
#      uppercase spelling, which reads in the report as "no generator tag".
#   4. `Drupal 9`'s bare major IS a version in a generator string and is NOT one
#      in a bundle filename (`bootstrap4`); each reading is the other's bug.
#   5. A CDN path carries the version one level ABOVE the file
#      (`/cdn/bootstrap@4.3.1/dist/css/bootstrap.css`); a basename-only reader
#      finds no version and the out-of-date check never gets a key.
#   6. A content hash (`bundle.4f3a1c.js`) is not a version.
#   7. `banner` rows and SCA-ecosystem rows share one file: a lookup that
#      ignored field 1 would match an npm advisory against a web server banner.
#   8. Two advisories on one exact version are ONE finding carrying both ids -
#      the DAST fingerprint has no advisory component, so a finding per row
#      would be two identical fingerprints and findings_merge would keep one.
#   9. An absent list and a list with no `banner` rows are DIFFERENT states, and
#      neither is an error: the two disclosure checks still run.
#  10. A non-GET endpoint is never requested - §7.1 is "no mutation of state".
#  11. One `Server` header across ten endpoints is ONE finding, at a
#      deterministic path, not ten.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header, meta-tag and filename syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031
#
# WHY EVERY `source .../banner.sh` BELOW CARRIES `# shellcheck source=/dev/null`,
# AND WHY THAT IS NOT LAZINESS.  This suite sources the phase script five times,
# once per scenario, which is the only way to exercise a phase `dast_run_phase`
# reaches by `source` (a subshell would discard the findings - lib/core.sh's
# `worker_id_set` lesson).  `shellcheck -x` follows `source` STATICALLY and has
# no "already inlined" notion, so five sources of banner.sh means five full
# inlinings of banner.sh + banner_engine.sh + crawl_engine.sh + lib/http.sh +
# lib/core.sh + lib/findings.sh.  Measured on this file: 31 minutes and 3.6GB
# resident and still climbing, against roughly 30 seconds for a normal file -
# the same runaway AGENTS.md records for the modules/sca source cycle, and
# enough to trip tests/run-tests.sh's shellcheck watchdog, whose kill reads as a
# stage failure rather than as a slow file.
# NOTHING IS LOST BY CUTTING IT: banner.sh is its own entry in the stage's file
# list and is statically checked there, in full, exactly once.  The four
# `# shellcheck source=` directives at the top of this file are the graph this
# suite really needs walked, and they stay.

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=modules/dast/passive/banner_engine.sh
source "$ROOT/modules/dast/passive/banner_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-banner-workspace
rm -rf "$W"
mkdir -p "$W"

FIXDB=$ROOT/tests/fixtures/dast/versions.db
FIXDIR=$ROOT/tests/fixtures/dast/banner

# ---------------------------------------------------------------------------
# Scope + the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: banner-fixture
base-url: https://banner.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-banner.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF

_banner_resolve() {
  case $1 in
    banner.fixture.example) printf '192.0.2.10' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_banner_resolve

REQ_LOG=$W/requests.log
: >"$REQ_LOG"

# The scripted SERVER: it replays a RECORDED response per path.  SRV_CASE picks
# which recording set is served, so a case is "this target answered like this",
# never "this function computed a finding".
SRV_CASE=basic
_banner_transport() {
  local method=$1 path=$5 bodyout=${7:-} hdrsout=${8:-}
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  local rec=$FIXDIR/$SRV_CASE${path//\//_}
  [[ -f $rec.headers ]] || rec=$FIXDIR/$SRV_CASE._default
  [[ -f $rec.headers ]] || return 1
  [[ -n $hdrsout ]] && cat -- "$rec.headers" >>"$hdrsout"
  if [[ -n $bodyout ]]; then
    if [[ -f $rec.body ]]; then cat -- "$rec.body" >"$bodyout"; else : >"$bodyout"; fi
  fi
  printf '200\n\ntext/html\n'
}
SCOURSH_HTTP_TRANSPORT=_banner_transport

http_scope_load "$SCOPE"

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  SCOURSH_DAST_CELL=banner-fixture
  export SCOURSH_DAST_CELL
  : >"$REQ_LOG"
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_count_lines() {
  local n=0 line
  while IFS= read -r line; do [[ -n $line ]] && n=$(( n + 1 )); done <<<"$1"
  printf '%s' "$n"
}

# `_count_check TEXT ID` - how many emitted findings carry check id ID.  A
# shard's `.fields` line is TAB-separated `key=value` pairs, one line per
# finding, so the match is anchored on the TAB that ends the field: without it
# `DAST-BANNER-SERVER_DISCLOSURE-01` would also count a hypothetical
# `...-011`, and the count this suite reads is the whole point of the case.
_count_check() {
  local text=$1 id=$2 n=0 line
  while IFS= read -r line; do
    [[ $line == *"check_id=$id"$'\t'* || $line == *"check_id=$id" ]] && n=$(( n + 1 ))
  done <<<"$text"
  printf '%s' "$n"
}

# ===========================================================================
# A. Pure extraction (no network, no findings)
# ===========================================================================
printf '\n== A. product/version extraction ==\n'

t_case 'the product key is normalised, not merely lowercased'
assert_eq 'microsoft-iis' "$(banner_normalize_product 'Microsoft-IIS')" 'Microsoft-IIS -> microsoft-iis'
assert_eq 'asp-net' "$(banner_normalize_product 'ASP.NET')" 'ASP.NET -> asp-net - fails if punctuation is kept or dropped instead of collapsed'
assert_eq 'jquery' "$(banner_normalize_product 'jQuery ')" 'a trailing separator never becomes a trailing dash in the key'

t_case 'a version needs two dotted components, and keeps its qualifier'
assert_true "$(banner_is_version '1.18.0' && printf 0 || printf 1)" '1.18.0 is a version'
assert_true "$(banner_is_version '1.2.3-beta1' && printf 0 || printf 1)" '1.2.3-beta1 keeps its qualifier - fails under a digits-and-dots-only regex'
assert_true "$(banner_is_version '4' && printf 1 || printf 0)" 'a bare integer is not a version here'
assert_true "$(banner_is_version 'bootstrap4' && printf 1 || printf 0)" 'a name ending in a digit is not a version'

t_case 'a parenthesised platform comment is not a product'
OUT=$(banner_products_from_header Server 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f')
assert_contains "$OUT" "apache"$'\t'"2.4.41" 'Apache and its version are read'
assert_contains "$OUT" "openssl"$'\t'"1.1.1f" 'a second product in the same header is read too'
assert_not_contains "$OUT" 'ubuntu' 'the distribution comment is NOT reported as a product - fails under a plain whitespace split'

t_case 'a bare-version header value takes its product from the header name'
assert_eq "aspnet"$'\t'"4.0.30319" "$(banner_products_from_header X-AspNet-Version '4.0.30319')" 'X-AspNet-Version: 4.0.30319 -> aspnet 4.0.30319 - fails if a bare version is dropped, and fails if the version is read as the product name'

t_case 'Via'"'"'s leading version is the protocol version, not a product version'
assert_eq "varnish"$'\t' "$(banner_products_from_header Via '1.1 varnish')" 'Via: 1.1 varnish -> varnish with NO version - fails if the hop protocol version is attributed to the intermediary'

t_case 'a name-only header is a name-only disclosure'
assert_eq "nginx"$'\t' "$(banner_products_from_header Server 'nginx')" 'Server: nginx discloses a name and no version'

t_case 'the generator meta tag is found in either case, and a bare major counts'
META=$W/meta.html
cat >"$META" <<'EOF'
<html><head>
<meta name="generator" content="WordPress 5.8.1" />
<META NAME="generator" CONTENT="Drupal 9 (https://www.drupal.org)">
</head></html>
EOF
OUT=$(banner_products_from_meta "$META")
assert_contains "$OUT" "wordpress"$'\t'"5.8.1" 'the lowercase tag is read'
assert_contains "$OUT" "drupal"$'\t'"9" 'the UPPERCASE tag is read too, and Drupal 9 is drupal at version 9 - fails under a case-sensitive match, and fails again if the bare major lands in the product key as drupal-9'

t_case 'a versioned bundle filename is read; a content hash is not a version'
BUN=$W/bundles.html
cat >"$BUN" <<'EOF'
<script src="/static/jquery-3.4.1.min.js"></script>
<script src="/a/angular.1.7.2.js"></script>
<link rel=stylesheet href="/cdn/bootstrap@4.3.1/dist/css/bootstrap.css">
<script src="/react-dom.production.min.16.8.0.js"></script>
<script src="/app.js"></script>
<script src="/bundle.4f3a1c.js"></script>
EOF
OUT=$(banner_products_from_bundles "$BUN")
assert_contains "$OUT" "jquery"$'\t'"3.4.1" 'jquery-3.4.1.min.js -> jquery 3.4.1'
assert_contains "$OUT" "angular"$'\t'"1.7.2" 'a dot-separated version is read'
assert_contains "$OUT" "bootstrap"$'\t'"4.3.1" 'the version one path segment ABOVE the file is read - fails for a basename-only reader'
assert_contains "$OUT" "react-dom"$'\t'"16.8.0" 'the min/production suffix words are stripped from the key, and only from the bundle channel'
assert_not_contains "$OUT" '4f3a1c' 'a content hash is not reported as a version'
assert_eq 4 "$(_count_lines "$OUT")" 'app.js contributes nothing, so exactly four bundles are reported'

t_case 'the header capture is read as fields, and the last hop wins'
HDR=$W/h.headers
printf 'HTTP/1.1 302 Found\r\nServer: hop-one\r\nLocation: /next\r\nHTTP/1.1 200 OK\r\nServer: hop-two\r\n\r\n' >"$HDR"
assert_eq 'hop-two' "$(banner_header_value "$HDR" SERVER)" 'the final hop is what a client sees - fails if the first value wins'
assert_not_contains "$(banner_header_each "$HDR")" 'Found' 'a status line carries no field name and is not parsed as one'

# ===========================================================================
# B. The vendored list (data/versions.db)
# ===========================================================================
printf '\n== B. the vendored known-vulnerable list ==\n'

t_case 'absent, no-banner-rows and present are three distinct states'
SCOURSH_DAST_VERSIONS_DB=$W/nope.db
banner_db_state
assert_eq absent "$_BANNER_DB_STATE" 'a missing file is absent'
ONLYSCA=$W/onlysca.db
printf '# generated: 2026-01-01T00:00:00Z\nnpm\tfoo\t1.0.0\tX\thigh\t\ts\n' >"$ONLYSCA"
SCOURSH_DAST_VERSIONS_DB=$ONLYSCA
banner_db_state
assert_eq no_banner_rows "$_BANNER_DB_STATE" 'a populated SCA half with no banner rows is NOT "absent" - fails if the two are collapsed, which lets a half-populated file read as a missing one'
SCOURSH_DAST_VERSIONS_DB=$FIXDB
banner_db_state
assert_eq present "$_BANNER_DB_STATE" 'the fixture list is present'
assert_eq '2026-08-19T00:00:00Z' "$_BANNER_DB_GENERATED" 'the generation stamp is read, so the report can date its own vulnerability data'

t_case 'two advisories on one exact version are ONE result carrying both ids'
banner_db_match fixtureserver 1.2.3
assert_contains "$_BANNER_ADVISORIES" 'FIXTURE-2026-0001' 'the first advisory id is carried'
assert_contains "$_BANNER_ADVISORIES" 'FIXTURE-2026-0002' 'the second one is carried in the SAME result - fails if the lookup returns per-row, which would emit two findings with one fingerprint'
assert_eq critical "$_BANNER_SEVERITY" 'the highest severity across the matched rows wins - fails if the first row wins'
assert_contains "$_BANNER_FIXED" '1.2.4' 'fixed_versions is carried through as display text'

t_case 'an unusable severity does not silence the row'
banner_db_match fixturelib 4.0.0
assert_eq high "$_BANNER_SEVERITY" 'a severity value outside the five names falls back to high - fails if an unrecognised value is trusted, or drops the row'

t_case 'the lookup is namespaced: an npm row never matches a banner'
assert_true "$(banner_db_match fixtureserver 1.2.5 && printf 1 || printf 0)" 'an unlisted version does not match'
OUT=$(db_lookup_exact "npm"$'\t'"fixtureserver"$'\t'"1.2.3"$'\t' "$FIXDB" || true)
assert_contains "$OUT" 'FIXTURE-NPM-0001' 'the fixture really does carry an npm row for the same package@version'
banner_db_match fixtureserver 1.2.3
assert_not_contains "$_BANNER_ADVISORIES" 'FIXTURE-NPM-0001' 'the banner lookup never returns it - fails if field 1 is ignored, which would report an npm advisory against a web server'

t_case 'the namespace still holds on a host with no `look`'
# db_lookup_exact falls back to `LC_ALL=C grep -F -m 1` where `look` is absent
# (tension 25), and THAT matcher finds the prefix ANYWHERE in a line rather than
# only at its start - so on such a host a prefix that omitted the namespace
# would match `<eco><TAB>fixtureserver<TAB>1.2.3<TAB>` inside an SCA row.  The
# fixture is built so this is REACHABLE rather than theoretical: `Go` sorts
# BEFORE `banner` under LC_ALL=C (uppercase G is 0x47, lowercase b is 0x62), so
# the Go row for the same package@version is the FIRST line `grep -F -m 1` would
# return.  Both halves of the defence are exercised: the namespaced prefix, and
# the per-row `banner` check in banner_db_match.
CAP_SAVE=${SCOURSH_CAP_LOOK:-}
SCOURSH_CAP_LOOK=none
banner_db_match fixtureserver 1.2.3
assert_contains "$_BANNER_ADVISORIES" 'FIXTURE-2026' 'a banner row is still found through the grep fallback'
assert_not_contains "$_BANNER_ADVISORIES" 'FIXTURE-GO-0001' 'and the Go row that sorts ahead of it is not - fails if either the prefix or the per-row namespace check is dropped, which on a look-less host reports an SCA advisory against a web server banner'
assert_not_contains "$_BANNER_ADVISORIES" 'FIXTURE-NPM-0001' 'nor is the npm row for the same package@version'
SCOURSH_CAP_LOOK=$CAP_SAVE

t_case 'known-product and known-version are different questions'
assert_true "$(banner_db_known knownclean && printf 0 || printf 1)" 'the list knows this product'
assert_true "$(banner_db_match knownclean 1.0.0 && printf 1 || printf 0)" 'but not this version of it'
assert_true "$(banner_db_known neverheardof && printf 1 || printf 0)" 'and it has never heard of this one at all - the distinction the coverage roll-up reports'

# ===========================================================================
# C. The phase, driven from recorded responses
# ===========================================================================
printf '\n== C. the phase over recorded responses ==\n'

_write_inventory() {
  local file=$1
  mkdir -p "${file%/*}"
  cat >"$file" <<'EOF'
{
  "schema": "scoursh.inventory.endpoints/1",
  "endpoints": [
    { "id": "aaaaaaaaaaaa", "target": "banner-fixture", "method": "GET",
      "url": "https://banner.fixture.example/", "host": "banner.fixture.example",
      "path": "/", "source": "crawl", "depth": 0, "status": "200", "content_type": "text/html" },
    { "id": "bbbbbbbbbbbb", "target": "banner-fixture", "method": "GET",
      "url": "https://banner.fixture.example/about", "host": "banner.fixture.example",
      "path": "/about", "source": "crawl", "depth": 1, "status": "200", "content_type": "text/html" },
    { "id": "cccccccccccc", "target": "banner-fixture", "method": "POST",
      "url": "https://banner.fixture.example/order", "host": "banner.fixture.example",
      "path": "/order", "source": "crawl", "depth": 1, "status": "200", "content_type": "" }
  ]
}
EOF
}

_phase_env() {
  SCOURSH_DAST_TARGET=banner-fixture
  SCOURSH_DAST_CELL=banner-fixture
  SCOURSH_DAST_INTENSITY=passive
  SCOURSH_DAST_AUTHED=false
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  SCOURSH_DAST_ENDPOINTS=${1:-}
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
    SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE SCOURSH_DAST_ENDPOINTS
}

INV=$W/inv/endpoints.json
_write_inventory "$INV"

t_case 'no endpoint inventory: a recorded gap and no request at all'
_fresh_run
SCOURSH_DAST_VERSIONS_DB=$FIXDB
_phase_env ''
# shellcheck source=/dev/null  # cut the edge - see the header note
source "$ROOT/modules/dast/passive/banner.sh"
assert_contains "$(run_facts coverage_reduction)" 'reason=no_endpoint_inventory' 'the missing surface is a declared reduction'
assert_contains "$(run_facts coverage_gap)" 'absence of a test' 'and a human-readable gap - fails under silence, which reads as a clean banner posture'
assert_eq 0 "$(_count_lines "$(cat "$REQ_LOG")")" 'nothing was requested'

t_case 'end to end: header, generator tag and bundle all reported, once each'
_fresh_run
SCOURSH_DAST_VERSIONS_DB=$FIXDB
SRV_CASE=basic
_phase_env "$INV"
# shellcheck source=/dev/null  # cut the edge - see the header note
source "$ROOT/modules/dast/passive/banner.sh"
FIND=$(_shard_text)
assert_contains "$FIND" 'DAST-BANNER-VERSION_DISCLOSURE-01' 'a version disclosure is emitted'
assert_contains "$FIND" 'DAST-BANNER-SERVER_DISCLOSURE-01' 'a name-only header disclosure is emitted'
assert_contains "$FIND" 'wordpress' 'the generator tag reached a finding'
assert_contains "$FIND" 'jquery' 'the bundle filename reached a finding'
assert_eq 1 "$(_count_check "$FIND" DAST-BANNER-SERVER_DISCLOSURE-01)" 'one Server header across two endpoints is ONE finding - fails if the dedup keys on the path, which reports the same misconfiguration once per page'

t_case 'a non-GET endpoint is never requested'
assert_not_contains "$(cat "$REQ_LOG")" '/order' 'the POST endpoint in the inventory was not dialled - §7.1 is "no mutation of state"'
assert_contains "$(run_facts coverage_reduction)" 'reason=banner_non_idempotent_endpoint' 'and what was skipped is reported rather than swallowed'

t_case 'a listed version is reported as out of date, with both advisory ids'
assert_contains "$FIND" 'DAST-BANNER-OUTDATED_COMPONENT-01' 'the vendored list produced an out-of-date finding'
assert_contains "$FIND" 'FIXTURE-2026-0001' 'the first advisory id is in the evidence'
assert_contains "$FIND" 'FIXTURE-2026-0002' 'and the second, in the SAME finding'
assert_eq 1 "$(_count_check "$FIND" DAST-BANNER-OUTDATED_COMPONENT-01)" 'one finding, not one per advisory row - fails under a per-row emit, whose two identical fingerprints findings_merge would silently collapse'
assert_contains "$FIND" '2026-08-19T00:00:00Z' 'the finding dates the vulnerability data it used'

t_case 'a product the list has never heard of is a coverage record, not silence'
assert_contains "$(run_facts coverage_reduction)" 'reason=versions_db_product_unknown' 'the unknown-product roll-up is recorded - fails if "not listed" is reported as "not vulnerable"'

t_case 'checks_run records what actually executed'
assert_contains "$(run_facts checks_run)" 'DAST-BANNER-OUTDATED_COMPONENT-01' 'the out-of-date check ran'
assert_contains "$(run_facts checks_run)" 'DAST-BANNER-VERSION_DISCLOSURE-01' 'and so did version disclosure'

t_case 'no banner rows in the list: that ONE sub-check degrades, the others run'
_fresh_run
SCOURSH_DAST_VERSIONS_DB=$ONLYSCA
SRV_CASE=basic
_phase_env "$INV"
# shellcheck source=/dev/null  # cut the edge - see the header note
source "$ROOT/modules/dast/passive/banner.sh"
FIND=$(_shard_text)
assert_contains "$(run_facts coverage_reduction)" 'reason=versions_db_no_banner_rows' 'the missing data is declared'
assert_not_contains "$FIND" 'DAST-BANNER-OUTDATED_COMPONENT-01' 'and no out-of-date finding is invented from a list that has none'
assert_contains "$FIND" 'DAST-BANNER-VERSION_DISCLOSURE-01' 'while version disclosure still runs - fails if a missing database degrades the whole phase'
assert_not_contains "$(run_facts checks_run)" 'DAST-BANNER-OUTDATED_COMPONENT-01' 'and the check that did not run is not claimed as covered'

t_case 'an absent list is its own reason, and is not an error'
_fresh_run
SCOURSH_DAST_VERSIONS_DB=$W/nope.db
SRV_CASE=basic
_phase_env "$INV"
# shellcheck source=/dev/null  # cut the edge - see the header note
source "$ROOT/modules/dast/passive/banner.sh"
assert_contains "$(run_facts coverage_reduction)" 'reason=versions_db_absent' 'absent is reported as absent, not as no_banner_rows'
assert_contains "$(_shard_text)" 'DAST-BANNER-VERSION_DISCLOSURE-01' 'the disclosure checks are unaffected'

t_case 'a target that discloses nothing produces no finding and no false comfort'
_fresh_run
SCOURSH_DAST_VERSIONS_DB=$FIXDB
SRV_CASE=quiet
_phase_env "$INV"
# shellcheck source=/dev/null  # cut the edge - see the header note
source "$ROOT/modules/dast/passive/banner.sh"
FIND=$(_shard_text)
assert_not_contains "$FIND" 'DAST-BANNER-' 'a quiet target yields no banner finding at all - fails if any channel reports on an empty response'
assert_contains "$(run_facts checks_run)" 'DAST-BANNER-SERVER_DISCLOSURE-01' 'and the check is still recorded as covered, because it really did look'

t_case 'every request went through the chokepoint and stayed in scope'
assert_contains "$(cat "$REQ_LOG")" 'GET /' 'the transport - reached only via http_request - saw the requests'
OUTOF=$(http_gate_url 'https://elsewhere.example/' banner-fixture 2>/dev/null && printf yes || printf no)
assert_eq no "$OUTOF" 'the scope gate still refuses a host outside config/scope.conf'

t_summary 'dast-banner'
