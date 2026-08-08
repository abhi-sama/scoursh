#!/usr/bin/env bash
# tests/suites/update-advisories.sh - tools/update-advisories.sh, the explicit
# update channel for data/advisories.db (docs/FOUNDATION.md tensions 25, 27).
#
# This is the one suite that exercises a real fetch over a real loopback
# socket through lib/http.sh, because "the update script actually fetches and
# writes a valid database" is exactly the property being pinned, and a suite
# that only asserted the shape of a pre-written fixture would not prove the
# network path works at all.
#
# Skipped with a notice, not failed, when python3 is unavailable: it serves
# the test fixture only, and is not a runtime dependency of the shipped tool.
# Same footing as tests/run-tests.sh's shellcheck skip.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

if ! command -v python3 >/dev/null 2>&1; then
  printf 'update-advisories: SKIPPED - python3 not installed (serves the test fixture only)\n'
  exit 0
fi

W=$SCOURSH_SCRATCH/update-advisories
mkdir -p "$W/fixture"

SRV_PID=''
_cleanup_srv() {
  [[ -n $SRV_PID ]] && kill "$SRV_PID" 2>/dev/null
  core_cleanup
}
trap _cleanup_srv EXIT

cat >"$W/fixture/npm.tsv" <<'EOF'
# fixture npm advisories for the test suite
npm	left-pad	1.0.0	GHSA-test-0001	high	1.0.1,1.0.2	Test fixture advisory for left-pad
npm	lodash	4.17.15	GHSA-test-0002	medium	4.17.21	Test fixture advisory for lodash
EOF
cat >"$W/fixture/pypi.tsv" <<'EOF'
pypi	flask	0.12	GHSA-test-0003	low	1.0	Test fixture advisory for flask
EOF
for eco in maven go rubygems composer cargo; do
  printf '# no fixture data for %s\n' "$eco" >"$W/fixture/$eco.tsv"
done

PORT=$(( 20000 + (BASHPID % 10000) ))
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$W/fixture" \
  >"$W/server.log" 2>&1 &
SRV_PID=$!

t_case 'the fixture server comes up'
ready=0
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://127.0.0.1:$PORT/npm.tsv"; then
    ready=1
    break
  fi
  sleep 0.1
done
assert_true "$(( ready ? 0 : 1 ))" 'the loopback fixture server answers within 3s'
(( ready )) || { t_summary 'update-advisories'; exit 1; }

cat >"$W/scanner.conf" <<EOF
id: scanner
advisory-update-url: http://127.0.0.1:$PORT
EOF

# ---------------------------------------------------------------------------
printf '\n-- the real round trip: fetch, validate, merge, write --\n'
# ---------------------------------------------------------------------------
t_case 'a full run against every ecosystem succeeds'
rc=0
out=$(bash "$ROOT/tools/update-advisories.sh" --config "$W/scanner.conf" --out "$W/advisories.db" 2>&1) || rc=$?
assert_eq 0 "$rc" 'update-advisories.sh exits 0 on a healthy fetch'
assert_contains "$out" 'category: update-channel' \
  'the fetch went through lib/http.sh, categorised as update-channel'
assert_file_exists "$W/advisories.db" 'data/advisories.db was written'

body=$(tail -n +2 "$W/advisories.db")
t_case 'the header line carries a generation timestamp and the source'
header=$(head -n 1 "$W/advisories.db")
assert_contains "$header" 'generated_at=' 'the header records generated_at'
assert_contains "$header" "source=http://127.0.0.1:$PORT" 'the header records the source update endpoint'

t_case 'the frozen schema (tension 25): seven tab-separated fields, sorted under LC_ALL=C'
assert_contains "$body" $'npm\tleft-pad\t1.0.0\tGHSA-test-0001\thigh\t1.0.1,1.0.2\tTest fixture advisory for left-pad' \
  'the npm left-pad row is present verbatim'
sorted=$(LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3 <<<"$body")
assert_eq "$sorted" "$body" 'the merged body is already sorted by (ecosystem, package, version) under LC_ALL=C'

t_case 'the frozen lookup mechanism (tension 25) finds an exact record'
hit=$(grep -F -m 1 $'npm\tlodash\t4.17.15\t' "$W/advisories.db" || true)
assert_contains "$hit" 'GHSA-test-0002' 'grep -F prefix lookup finds the lodash advisory by (ecosystem, package, version)'

# ---------------------------------------------------------------------------
printf '\n-- failure paths: no partial or wrong output on error --\n'
# ---------------------------------------------------------------------------
t_case 'no advisory-update-url configured is a hard, clean failure'
cat >"$W/scanner-empty.conf" <<'EOF'
id: scanner
EOF
rc=0
bash "$ROOT/tools/update-advisories.sh" --config "$W/scanner-empty.conf" \
  --out "$W/should-not-exist.db" >/dev/null 2>&1 || rc=$?
assert_eq 4 "$rc" 'an unconfigured update endpoint dies with SCOURSH_EXIT_INPUT (4), not a guess'
assert_file_absent "$W/should-not-exist.db" 'no output file is written when the endpoint is unconfigured'

t_case 'a misrouted feed (wrong ecosystem field) is refused rather than merged'
printf 'pypi\tbadrow\t1.0\tGHSA-x\thigh\t1.1\tmisrouted row claiming pypi inside npm.tsv\n' \
  >>"$W/fixture/npm.tsv"
rc=0
bash "$ROOT/tools/update-advisories.sh" --config "$W/scanner.conf" --ecosystem npm \
  --out "$W/should-not-exist2.db" >/dev/null 2>&1 || rc=$?
assert_eq 5 "$rc" 'a misrouted feed dies with SCOURSH_EXIT_INCOMPLETE (5)'
assert_file_absent "$W/should-not-exist2.db" 'no output file is written when a fetched feed fails validation'

t_case 'an unreachable update host fails rather than silently skipping'
printf 'id: scanner\nadvisory-update-url: http://127.0.0.1:%s\n' "$(( PORT + 1 ))" \
  >"$W/scanner-unreachable.conf"
rc=0
bash "$ROOT/tools/update-advisories.sh" --config "$W/scanner-unreachable.conf" \
  --ecosystem npm --out "$W/should-not-exist3.db" >/dev/null 2>&1 || rc=$?
assert_eq 5 "$rc" 'a connection failure dies with SCOURSH_EXIT_INCOMPLETE (5), not a silent empty database'
assert_file_absent "$W/should-not-exist3.db" 'no output file is written when the fetch itself fails'

t_summary 'update-advisories'
