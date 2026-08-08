#!/usr/bin/env bash
# tests/lint-egress.sh - the corrected egress model, enforced mechanically.
#
#   docs/FOUNDATION.md tension 19 (scope-gate semantics)
#   docs/FOUNDATION.md tension 27 (the "air-gapped" premise was wrong)
#   docs/adr/0001-egress-model-correction.md
#
# Two checks, both about DESTINATION, matching the model's own framing (a
# rule enforced by verb is not enforceable - a GET can carry a payload in its
# query string just as well as a POST):
#
#   1. No scan-path code can reach a non-allowlisted destination: every
#      curl/wget/nc/openssl-s_client invocation outside lib/http.sh - the one
#      chokepoint that is allowed to speak to the network directly - is a
#      hidden call the destination allowlist never sees.
#   2. tools/update-advisories.sh is unreachable from the scan path: no
#      lib/, modules/, or scan.sh file may reference the script by name or
#      call the function (http_allow_update_endpoint) that grants it its one
#      destination.  A scan's rules must not change mid-run (§2), which is
#      only true if nothing on the scan path can reach the update channel.
#
# An optional ROOT argument points the lint at a different tree, so
# tests/suites/lint-egress-selftest.sh can prove both directions (planted violation
# fails, removing it passes) without mutating this repository.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
SELF_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$SELF_ROOT/lib/core.sh"

ROOT=$(cd -- "${1:-$SELF_ROOT}" && pwd -P)
cd "$ROOT"

FAILED=0
HITS=$SCOURSH_SCRATCH/egress-hits
report() {
  FAILED=1
  printf '%s\n' "$@" >&2
}

# Files a scan can execute: lib/, modules/, aws/, and scan.sh itself, once it
# exists.  tools/ is deliberately EXCLUDED here - tools/update-advisories.sh
# is checked separately, below, for going through lib/http.sh like everything
# else; it is not part of "the scan path" a running scan can reach.
scan_path_files() {
  local dirs=() d
  for d in lib modules aws; do [[ -d $d ]] && dirs+=("$d"); done
  {
    if (( ${#dirs[@]} > 0 )); then find "${dirs[@]}" -type f -name '*.sh'; fi
    if [[ -f scan.sh ]]; then printf '%s\n' scan.sh; fi
  } | LC_ALL=C sort -u
}

# Files that must never bare-curl: the scan path plus tools/, since
# tools/update-advisories.sh is exactly as bound to the chokepoint as any
# scan-path script - it just calls a different http_allow_* function.
network_capable_files() {
  local dirs=() d
  for d in lib modules aws tools; do [[ -d $d ]] && dirs+=("$d"); done
  {
    if (( ${#dirs[@]} > 0 )); then find "${dirs[@]}" -type f -name '*.sh'; fi
    if [[ -f scan.sh ]]; then printf '%s\n' scan.sh; fi
  } | LC_ALL=C sort -u
}

printf '== check 1: every network call goes through lib/http.sh ==\n'

count=0
bare=0
while IFS= read -r f; do
  [[ -n $f ]] || continue
  rel=${f#./}
  count=$(( count + 1 ))
  [[ $rel == lib/http.sh ]] && continue
  if scan_match "$HITS" -e '(^|[;&|(])[[:space:]]*(curl|wget|nc|ncat)[[:space:]]' -- "$rel"; then
    bare=1
    report "$rel: a bare network-tool invocation; every curl-based call goes through lib/http.sh"
    cat "$HITS" >&2
  fi
  if scan_match "$HITS" -e '(^|[;&|(])[[:space:]]*openssl[[:space:]]+s_client' -- "$rel"; then
    bare=1
    report "$rel: a bare 'openssl s_client' invocation outside lib/http.sh"
    cat "$HITS" >&2
  fi
done <<<"$(network_capable_files)"

if (( count == 0 )); then
  printf '  --  no lib/modules/aws/tools shell files to examine yet\n'
elif (( bare == 0 )); then
  printf '  ok  every network-capable invocation among %s files is inside lib/http.sh\n' "$count"
fi

printf '\n== check 2: tools/update-advisories.sh is unreachable from the scan path ==\n'

scount=0
reach=0
while IFS= read -r f; do
  [[ -n $f ]] || continue
  scount=$(( scount + 1 ))
  rel=${f#./}
  # lib/http.sh DEFINES http_allow_update_endpoint (that is its whole job as
  # the chokepoint); the property being checked is that nothing else CALLS it.
  [[ $rel == lib/http.sh ]] && continue
  if scan_match "$HITS" -e 'update-advisories' -- "$rel"; then
    reach=1
    report "$rel: references 'update-advisories' - the update channel must never be reachable from the scan path"
    cat "$HITS" >&2
  fi
  if scan_match "$HITS" -e 'http_allow_update_endpoint' -- "$rel"; then
    reach=1
    report "$rel: calls http_allow_update_endpoint - only tools/update-advisories.sh may grant itself that destination"
    cat "$HITS" >&2
  fi
done <<<"$(scan_path_files)"

if (( scount == 0 )); then
  printf '  --  no lib/modules/aws/scan.sh shell files to examine yet\n'
elif (( reach == 0 )); then
  printf '  ok  the update channel is unreachable from %s scan-path files\n' "$scount"
fi

printf '\n'
if (( FAILED )); then
  printf 'lint-egress: FAILED\n'
  exit 1
fi
printf 'lint-egress: clean\n'
