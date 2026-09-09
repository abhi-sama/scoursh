#!/usr/bin/env bash
# tests/suites/network-outdated.sh - NET-11: the version->vulnerability
# lookup for network banners, `NET-SVC-OUTDATED_COMPONENT-01`
# (data/scoursh-network-scan-design/report.md §3.2 item 1, §3.4, §5.1, the
# NET-11 row in its §7 staged plan; depends on NET-07's banner.sh, MERGED
# #239, which produces the version string this check looks up).
#
# This check lands INSIDE modules/network/banner.sh (NET-07's own phase
# script), not as a new phase - see that file's own header for why. This
# suite therefore exercises the SAME phase tests/suites/network-banner.sh
# exercises, reusing its own test seam (SCOURSH_NET_PROBE/
# SCOURSH_NET_BANNER_PROBE, the resolve stub, the `scan.sh network`
# subprocess shape) verbatim, and focuses only on what THIS ticket adds:
#
#   1. An open listener whose banner discloses a product@version with an
#      EXACT data/versions.db `banner`-namespace row fires
#      NET-SVC-OUTDATED_COMPONENT-01, alongside NET-SVC-BANNER_DISCLOSURE-01.
#   2. A disclosed version that is NOT in the vendored list (current, or
#      simply unknown to it) stays quiet on the outdated check while the
#      disclosure check still fires - a clean result is not the same as the
#      check never having run.
#   3. This is an EXACT match, never range arithmetic: a version one patch
#      release away from a listed one does not fire.
#   4. EVERY NET-SVC-OUTDATED_COMPONENT-01 finding carries confidence=medium
#      (never high) AND states the banner/backport limitation in its own
#      remediation field (report.md §3.4) - not merely as a comment in this
#      source tree.
#   5. A missing or banner-less data/versions.db degrades ONE named,
#      counted reduction; disclosure is unaffected.
#   6. The finding round-trips through every report format.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a fixture root can never leak into the
#   next case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=/dev/null
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/network-outdated
rm -rf "$W"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

FIXDB=$ROOT/tests/fixtures/dast/versions.db

# ---------------------------------------------------------------------------
# Fixture install root.
# ---------------------------------------------------------------------------
# NOT tests/suites/network-banner.sh's own `_fixture_root` (which copies
# `data/` verbatim): THIS checkout's own data/versions.db and
# data/advisories.db are a real, ~280MB-each tools/vendor-engines.sh output
# (measured - not the small/absent state a fresh clone has), and every case
# below pins its own data/versions.db via SCOURSH_DAST_VERSIONS_DB anyway
# (banner_db_path, modules/dast/passive/banner_engine.sh, prefers that
# override over the install root's own file), so the real db is never read
# regardless. Copying it into every fixture root here would cost real
# minutes and hundreds of MB per case for a file no case ever consults -
# excluded, with everything else `data/` genuinely needs at runtime
# (severity-rubric.conf, feeding `_banner_severity_max`'s
# `severity_rank` lookup; owasp-categories.conf; cis-mappings) still copied.
_fixture_root() {
  local dir=$1 e f
  mkdir -p "$dir/config"
  for e in lib modules rules tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
  mkdir -p "$dir/data"
  for f in "$ROOT"/data/*; do
    case ${f##*/} in
      versions.db | advisories.db) continue ;;
    esac
    cp -RL "$f" "$dir/data/${f##*/}" 2>/dev/null || true
  done
}

# outdated.fixture.invalid is RFC 2606-reserved and resolves to a TEST-NET-3
# (RFC 5737) literal this suite never dials - both SCOURSH_NET_PROBE and
# SCOURSH_NET_BANNER_PROBE below replace the whole real-socket path.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  outdated.fixture.invalid) printf '203.0.113.70' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"

# `SCOURSH_NET_PROBE` (lib/nettransport.sh) - every declared listener in
# this suite's fixtures is `open`, since the classification step
# (NET-06/reachability.sh's own primitive) is pinned separately by
# tests/suites/network-reachability.sh and tests/suites/network-banner.sh;
# this suite has nothing new to say about it.
NET_PROBE_STUB=$W/net-probe-stub
cat >"$NET_PROBE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'open\n'
STUBEOF
chmod 0755 "$NET_PROBE_STUB"

# `SCOURSH_NET_BANNER_PROBE` (lib/nettransport.sh, NET-07) - a scripted
# banner keyed on port alone, the same "recorded response" idiom
# tests/suites/network-banner.sh's own stub uses. Every product/version pair
# below is `fixtureserver`, whose fixture rows in tests/fixtures/dast/
# versions.db are exact: 1.2.3 and 1.2.4 are listed, nothing else is.
NET_BANNER_STUB=$W/net-banner-stub
cat >"$NET_BANNER_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $2 in
  2200) printf '220 fixtureserver 1.2.3 ready\r\n' >"$4" ;;    # exact vendored hit
  2201) printf '220 fixtureserver 9.9.9 ready\r\n' >"$4" ;;    # not in the list at all
  2202) printf '220 fixtureserver 1.2.30 ready\r\n' >"$4" ;;   # ONE patch release off 1.2.3 - not exact
  2203) printf '220 unversionedwidget ready\r\n' >"$4" ;;      # a name with no version disclosed
  *) : ;;
esac
STUBEOF
chmod 0755 "$NET_BANNER_STUB"

# `_net_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh network`
# subprocess, tests/suites/network-banner.sh's own helper: banner.sh's own
# phase tier is `passive`, so neither `--intensity` nor `--i-own-target` is
# needed for this check to run at the plain default.
_net_scan() {
  local rundir=$1 root=$2 target=''
  shift 2
  local -a args=("$@")
  local i
  for (( i = 0; i < ${#args[@]}; i++ )); do
    if [[ ${args[i]} == --target ]]; then target=${args[i+1]}; fi
  done
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$root SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
    SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_BANNER_PROBE=$NET_BANNER_STUB \
    bash "$ROOT/scan.sh" network --out "$rundir" \
    --target "$target" "${args[@]}" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

FIX=$W/root
_fixture_root "$FIX"
cat >"$FIX/config/scope.conf" <<'EOF'
id: net-outdated
base-url: https://outdated.fixture.invalid/
extra-host: outdated.fixture.invalid:2200
extra-host: outdated.fixture.invalid:2201
extra-host: outdated.fixture.invalid:2202
extra-host: outdated.fixture.invalid:2203
allow-subdomains: false
EOF

# =============================================================================
printf '\n-- an exact data/versions.db banner-namespace hit fires NET-SVC-OUTDATED_COMPONENT-01 --\n'
# =============================================================================

t_case 'a listener disclosing a known-vulnerable exact version fires both the disclosure and outdated checks'
SCOURSH_DAST_VERSIONS_DB=$FIXDB _net_scan "$W/run-vuln" "$FIX" --target net-outdated
assert_eq 0 "$_RC" 'scan.sh network --target net-outdated exits 0 at the DEFAULT intensity'

RUN_VULN_JSONL=$(_slurp "$W/run-vuln/findings.jsonl")
assert_contains "$RUN_VULN_JSONL" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'the disclosure check still fires alongside the outdated one'
assert_contains "$RUN_VULN_JSONL" '"check_id":"NET-SVC-OUTDATED_COMPONENT-01"' \
  'the outdated-component check fires on the exact fixtureserver/1.2.3 versions.db match - FAILS under any "close enough" heuristic reading, since this is an EXACT table lookup (report.md §3.4)'
assert_contains "$RUN_VULN_JSONL" '"location":{"target":"net-outdated","host":"outdated.fixture.invalid","port":"2200","transport":"https"}' \
  'the outdated finding names the actual disclosing listener, under the net fingerprint profile (target host port transport)'

RUN_VULN_SHARD=$(cat -- "$W/run-vuln"/shards/*.fields 2>/dev/null)
t_case 'the outdated finding is confidence=medium, never high - report.md §3.4s backport caveat'
assert_contains "$RUN_VULN_SHARD" 'check_id=NET-SVC-OUTDATED_COMPONENT-01' 'sanity: the finding is present in the shard'
# Each shard line is ONE finding: tab-separated key=value fields
# (lib/findings.sh _finding_fields), never one key per line - grep the ONE
# line naming this check id rather than an awk paragraph-mode range, which
# would silently match nothing (or every finding) against this format.
OUTDATED_LINE=$(grep 'check_id=NET-SVC-OUTDATED_COMPONENT-01' <<<"$RUN_VULN_SHARD" | head -n1)
assert_contains "$OUTDATED_LINE" 'confidence=medium' \
  'FAILS if this finding were ever emitted at confidence=high: a banner-read version cannot see a distributions own backported fix, so high confidence would overstate what this check can actually establish'
assert_contains "$OUTDATED_LINE" 'remediation=' 'the finding carries a remediation field at all'
assert_contains "$OUTDATED_LINE" 'backport' \
  'the per-finding remediation states the banner/backport limitation IN WORDS (report.md §3.4) - FAILS if that caveat lived only in this source trees comments and never reached the finding a reader actually sees'
assert_contains "$OUTDATED_LINE" 'openssh' \
  'the remediation names the projects own worked backport example (Debian/RHEL openssh), matching modules/network/checks-banner.rules own record'

RUN_VULN_JSON=$(_slurp "$W/run-vuln/run.json")
t_case 'checks_run records both ids for a successfully-probed, disclosing listener'
assert_contains "$RUN_VULN_JSON" 'NET-SVC-BANNER_DISCLOSURE-01' 'disclosure id recorded as run'
assert_contains "$RUN_VULN_JSON" 'NET-SVC-OUTDATED_COMPONENT-01' 'outdated-component id recorded as run'

t_case 'checks-banner.rules registers the new id under coverage-scope target, tags passive, confidence medium'
RULES_FILE=$(_slurp "$ROOT/modules/network/checks-banner.rules")
assert_contains "$RULES_FILE" 'id: NET-SVC-OUTDATED_COMPONENT-01' 'the check id is registered'
OUTDATED_RECORD=$(awk '/^id: NET-SVC-OUTDATED_COMPONENT-01$/,0' <<<"$RULES_FILE")
assert_contains "$OUTDATED_RECORD" 'confidence: medium' 'the registry record itself is confidence: medium'
assert_contains "$OUTDATED_RECORD" 'tags: passive' \
  'the record is tagged passive, matching modules/network/engine.sh'"'"'s own banner.sh:passive phase-table floor - FAILS if this check were mistakenly tagged safe-active like NET-09s HTTP-channel sibling, which sends a real request this one does not'
assert_contains "$OUTDATED_RECORD" 'coverage-scope: target' 'coverage-scope: target - FAILS the linter'"'"'s E079 otherwise'

# =============================================================================
printf '\n-- a disclosed version with no exact versions.db row stays quiet on the outdated check --\n'
# =============================================================================

t_case 'fixtureserver 9.9.9 is not in the fixture versions.db at all, so the outdated check runs and finds nothing'
SCOURSH_DAST_VERSIONS_DB=$FIXDB _net_scan "$W/run-clean" "$FIX" --target net-outdated
assert_eq 0 "$_RC" 'exits 0'
RUN_CLEAN_JSONL=$(_slurp "$W/run-clean/findings.jsonl")
assert_contains "$RUN_CLEAN_JSONL" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'the disclosure still fires for the unlisted-version listener too'
CLEAN_2201=$(grep '"port":"2201"' <<<"$RUN_CLEAN_JSONL" | grep OUTDATED || true)
assert_eq '' "$CLEAN_2201" \
  'no outdated-component finding names port 2201 - FAILS under any heuristic that treats "known product, unknown version" as a hit'
RUN_CLEAN_JSON=$(_slurp "$W/run-clean/run.json")
assert_contains "$RUN_CLEAN_JSON" 'NET-SVC-OUTDATED_COMPONENT-01' \
  'the outdated check id is still recorded as RUN across this target (port 2200 IS an exact hit in the same run) - a clean result on one listener is not the same as the check never having executed'

# =============================================================================
printf '\n-- report.md §3.4: an exact table lookup, not range arithmetic --\n'
# =============================================================================

t_case 'fixtureserver 1.2.30 (one patch release off the listed 1.2.3/1.2.4) does not fire the outdated check'
RUN_VULN_JSONL_ALL=$(_slurp "$W/run-vuln/findings.jsonl")
NEAR_2202=$(grep '"port":"2202"' <<<"$RUN_VULN_JSONL_ALL" | grep OUTDATED || true)
assert_eq '' "$NEAR_2202" \
  'no outdated-component finding names port 2202 - FAILS under any "close to a known-bad version" comparison, which report.md §3.4 explicitly forbids: this is an EXACT product+version table lookup only, never range/prefix/semver-distance arithmetic'
assert_contains "$RUN_VULN_JSONL_ALL" '"port":"2202"' \
  'port 2202 still disclosed (the disclosure check has no versions.db dependency at all) - proves the listener was genuinely read, not skipped'

# =============================================================================
printf '\n-- a name-only disclosure (no version) has nothing to look up --\n'
# =============================================================================

t_case 'a bare product name with no version disclosed produces no outdated-component finding'
NAMEONLY_2203=$(grep '"port":"2203"' <<<"$RUN_VULN_JSONL_ALL" | grep OUTDATED || true)
assert_eq '' "$NAMEONLY_2203" \
  'no outdated finding for port 2203 - there is no version to match against data/versions.db'

# =============================================================================
printf '\n-- report.md §5.2 rule 2 / §3.4: a missing versions.db is a named, counted reduction, disclosure unaffected --\n'
# =============================================================================

t_case 'with no usable data/versions.db, the outdated check is a named coverage_reduction and disclosure still fires'
NODB=$W/nonexistent-versions.db
rm -f "$NODB"
SCOURSH_DAST_VERSIONS_DB=$NODB _net_scan "$W/run-nodb" "$FIX" --target net-outdated
assert_eq 0 "$_RC" 'exits 0 - a missing vendored list is a coverage fact, never an error'
NODB_JSON=$(_slurp "$W/run-nodb/run.json")
assert_contains "$NODB_JSON" 'reason=versions_db_absent' \
  'the named reason appears - FAILS if a missing list silently produced zero findings, which reads identically to "scoursh looked and found nothing"'
assert_contains "$NODB_JSON" 'checks=[NET-SVC-OUTDATED_COMPONENT-01]' \
  'the reduction names this check id specifically, not only a generic module note'
NODB_JSONL=$(_slurp "$W/run-nodb/findings.jsonl")
assert_contains "$NODB_JSONL" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'disclosure is unaffected by the missing vendored list - it needs no data at all'
assert_not_contains "$NODB_JSONL" 'NET-SVC-OUTDATED_COMPONENT-01' \
  'no outdated finding was fabricated with no usable list to check against'
assert_not_contains "$NODB_JSON" 'reason=check_not_executed_no_reason_recorded' \
  'the honesty backstop (modules/network/run.sh _net_record_unaccounted) does not ALSO flag this check as selected-but-unexplained - FAILS if the versions_db_absent reduction above were not spelled checks=[...] (plural, bracketed), which is the one substring that backstop recognises'

# =============================================================================
printf '\n-- a data/versions.db with no banner rows degrades identically to an absent one --\n'
# =============================================================================

EMPTYDB=$W/empty-versions.db
cat >"$EMPTYDB" <<'EOF'
# generated: 2026-01-01T00:00:00Z
npm	somepkg	1.0.0	FIXTURE-NPM-9999	high		an SCA-namespace row only, no banner rows at all
EOF
t_case 'a versions.db with SCA rows but no banner rows records versions_db_no_banner_rows, not versions_db_absent'
SCOURSH_DAST_VERSIONS_DB=$EMPTYDB _net_scan "$W/run-emptydb" "$FIX" --target net-outdated
assert_eq 0 "$_RC" 'exits 0'
EMPTYDB_JSON=$(_slurp "$W/run-emptydb/run.json")
assert_contains "$EMPTYDB_JSON" 'reason=versions_db_no_banner_rows checks=[NET-SVC-OUTDATED_COMPONENT-01]' \
  'the distinct reason fires - FAILS if a database someone generated (for a different ecosystem entirely) read identically to no database at all'
EMPTYDB_JSONL=$(_slurp "$W/run-emptydb/findings.jsonl")
assert_not_contains "$EMPTYDB_JSONL" 'NET-SVC-OUTDATED_COMPONENT-01' 'no outdated finding was fabricated'
assert_contains "$EMPTYDB_JSONL" 'NET-SVC-BANNER_DISCLOSURE-01' 'disclosure still fires'

# =============================================================================
printf '\n-- findings round-trip into every report format via the real scan.sh network path --\n'
# =============================================================================

t_case 'the outdated finding round-trips into findings.json, report.md, report.html, report.sarif and the agent format'
SCOURSH_DAST_VERSIONS_DB=$FIXDB _net_scan "$W/run-fmt" "$FIX" \
  --target net-outdated --format json,md,html,sarif,agent
assert_eq 0 "$_RC" 'a run requesting every format still exits 0'

FMT_JSON=$(_slurp "$W/run-fmt/findings.json")
assert_contains "$FMT_JSON" '"check_id":"NET-SVC-OUTDATED_COMPONENT-01"' \
  'findings.json (the --format json emitter) carries the finding'
FMT_MD=$(_slurp "$W/run-fmt/report.md")
assert_contains "$FMT_MD" 'NET-SVC-OUTDATED_COMPONENT-01' 'report.md names the check id'
FMT_HTML=$(_slurp "$W/run-fmt/report.html")
assert_contains "$FMT_HTML" 'NET-SVC-OUTDATED_COMPONENT-01' \
  'report.html names the check id too - FAILS if the network category were missing from _RPT_MODULES or the NET- prefix grep (lib/report.sh _rptc_prefix_grep)'
FMT_SARIF=$(_slurp "$W/run-fmt/report.sarif")
assert_contains "$FMT_SARIF" '"id":"NET-SVC-OUTDATED_COMPONENT-01"' \
  'the SARIF rule registry names the check - FAILS if modules/network/checks-banner.rules were not discovered by the SARIF registry builder (it globs every *.rules under modules/network/)'
AGENT_JSON=$(_slurp "$W/run-fmt/agent-fix.json")
assert_contains "$AGENT_JSON" '"scoursh_agent":1' 'agent-fix.json was written'
assert_contains "$AGENT_JSON" 'NET-SVC-OUTDATED_COMPONENT-01' \
  'the finding round-trips into the agent format too'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-outdated'
