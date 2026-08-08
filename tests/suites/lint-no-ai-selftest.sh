#!/usr/bin/env bash
# tests/suites/lint-no-ai.sh - proves tests/lint-no-ai.sh both directions.
#
# Same shape as tests/suites/lint-egress.sh: plant each of the three signals
# tests/lint-no-ai.sh claims to catch (provider hostname, SDK name, API-key
# env var) in a throwaway fixture tree, assert failure, remove, assert a pass.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/env syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$SCOURSH_SCRATCH/lint-no-ai-fixture
rm -rf "$FIX"
mkdir -p "$FIX/lib" "$FIX/modules/sast"
printf '#!/usr/bin/env bash\n:\n' >"$FIX/lib/core.sh"
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"

lint() { bash "$ROOT/tests/lint-no-ai.sh" "$FIX" >/dev/null 2>&1; }

t_case 'baseline fixture is clean'
assert_status 0 'a fixture with no AI signal passes' lint

t_case 'a provider hostname fails the lint'
printf '#!/usr/bin/env bash\nENDPOINT="https://api.openai.com/v1/chat/completions"\n' >"$FIX/modules/sast/scan.sh"
assert_status 1 'a hardcoded provider hostname is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 'removing the hostname restores a clean pass' lint

t_case 'a provider SDK name fails the lint'
printf '#!/usr/bin/env bash\n# python3 -c "import anthropic"\n' >"$FIX/modules/sast/scan.sh"
assert_status 1 'a provider SDK reference is caught, even inside a comment' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 'removing the SDK reference restores a clean pass' lint

t_case 'a model-provider API-key env var fails the lint'
printf 'export ANTHROPIC_API_KEY=sk-fake\n' >"$FIX/lib/core.sh"
assert_status 1 'a provider API-key env var is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/lib/core.sh"
assert_status 0 'removing the env var restores a clean pass' lint

t_case 'documentation prose about the rule is not itself a violation'
mkdir -p "$FIX/docs"
printf '# no AI/LLM: no ANTHROPIC_API_KEY, no api.openai.com, ever\n' >"$FIX/docs/NOTES.md"
assert_status 0 'a .md file discussing the rule does not trip the lint' lint
rm -rf "$FIX/docs"

rm -rf "$FIX"
t_summary 'lint-no-ai self-test'
