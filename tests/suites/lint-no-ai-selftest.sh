#!/usr/bin/env bash
# tests/suites/lint-no-ai-selftest.sh - proves tests/lint-no-ai.sh both directions.
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

# CI run 35092825749: `cohere` matched inside the ordinary word "coherent"
# in a scan.sh prose comment.  Word-boundary matching (tests/lint-no-ai.sh's
# _bounded_pattern) must reject the substring while still catching the real
# SDK reference.
t_case 'a bare substring inside an unrelated word does not fail the lint'
printf '#!/usr/bin/env bash\n# the input is coherent, checked at run time\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 '"coherent" does not trip the cohere SDK pattern' lint
# `anthropic` has the identical hazard - "philanthropic"/"misanthropic" both
# contain it as a substring - caught by the same audit, not by CI.
printf '#!/usr/bin/env bash\n# a philanthropic and misanthropic pair of words\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 '"philanthropic"/"misanthropic" do not trip the anthropic SDK pattern' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 'fixture is clean again' lint

t_case 'the real cohere SDK reference is still caught after the word-boundary fix'
printf '#!/usr/bin/env bash\n# python3 -c "import cohere"\n' >"$FIX/modules/sast/scan.sh"
assert_status 1 'a standalone cohere import is still caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 'removing it restores a clean pass' lint

t_case 'a scoped SDK package name is still caught with no leading boundary'
printf '#!/usr/bin/env bash\n# "@anthropic-ai/sdk"\n' >"$FIX/modules/sast/scan.sh"
assert_status 1 'a real @anthropic-ai/sdk reference is caught' lint
printf '#!/usr/bin/env bash\n:\n' >"$FIX/modules/sast/scan.sh"
assert_status 0 'removing it restores a clean pass' lint

rm -rf "$FIX"

# CI run 35092825749's second, independent bug: the CI job pipes the whole
# suite run through `tee suite.log` into the checkout root, so this
# generated/log artifact sat inside the very tree tests/lint-no-ai.sh walks
# and ended up scanning its own report.  A plain mkdir'd fixture (like $FIX
# above) is never a git working tree, so it cannot exercise this path; these
# cases build a throwaway git repo instead, exactly like a real checkout.
GITFIX=$SCOURSH_SCRATCH/lint-no-ai-fixture-git
rm -rf "$GITFIX"
mkdir -p "$GITFIX/lib"
(
  cd "$GITFIX"
  git init -q
  printf '#!/usr/bin/env bash\n:\n' >lib/core.sh
  printf 'generated.log\n' >.gitignore
  git add lib/core.sh .gitignore
)
lint_git() { bash "$ROOT/tests/lint-no-ai.sh" "$GITFIX" >/dev/null 2>&1; }

t_case 'a clean git-tracked fixture passes'
assert_status 0 'a fixture with no AI signal, inside a real git repo, passes' lint_git

t_case 'a gitignored, untracked artifact does not fail the lint'
printf 'ANTHROPIC_API_KEY=sk-fake\n' >"$GITFIX/generated.log"
assert_status 0 'a real signal inside an untracked, .gitignore-matched file is excluded' lint_git
rm -f "$GITFIX/generated.log"
assert_status 0 'removing it changes nothing - it was never scanned' lint_git

t_case 'the identical signal in a tracked file still fails the lint'
printf 'ANTHROPIC_API_KEY=sk-fake\n' >"$GITFIX/lib/core.sh"
(cd "$GITFIX" && git add lib/core.sh)
assert_status 1 'a tracked file is not exempt, only the ignored artifact was' lint_git

rm -rf "$GITFIX"

t_summary 'lint-no-ai self-test'
