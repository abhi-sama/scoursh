#!/usr/bin/env bash
# tests/lint-no-ai.sh - no AI/LLM call anywhere in the shipped tool.
#
# The operator's rule is "no AI in the shipped tool," and a rule enforced only
# by a comment asking nicely is not enforced.  This scans the shipped tree for
# three independent signals, any one of which means an AI/LLM provider is
# reachable from the code: a provider hostname, a provider SDK/package name,
# or a model-provider API-key-shaped environment variable.
#
# SELF-REFERENCE, handled deliberately.  This file's own pattern list
# necessarily contains the literal strings it looks for (`openai.com`,
# `ANTHROPIC_API_KEY`, ...), and so does this repository's documentation,
# which discusses the very rule this lint enforces.  Neither is a violation:
# this script excludes itself and every `docs/*.md` / `*.md` file from the
# scan, since the property that matters is CODE that can call a model
# provider, not prose that talks about not doing that.
#
# An optional ROOT argument points the lint at a different tree, so
# tests/suites/lint-no-ai-selftest.sh can prove both directions (planted
# violation fails, removing it passes) without mutating this repository.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/env syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
SELF_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$SELF_ROOT/lib/core.sh"

ROOT=$(cd -- "${1:-$SELF_ROOT}" && pwd -P)
cd "$ROOT"

FAILED=0
HITS=$SCOURSH_SCRATCH/no-ai-hits
report() {
  FAILED=1
  printf '%s\n' "$@" >&2
}

# Every shipped file: the whole tree except .git, and except documentation
# (*.md anywhere, which is prose ABOUT this rule, not code that could violate
# it) and this linter's own two files (this script and its self-test suite,
# which both have to name what they look for in order to test/implement it).
shipped_files() {
  find . \
    -path ./.git -prune -o \
    -name '*.md' -prune -o \
    -path './tests/lint-no-ai.sh' -prune -o \
    -path './tests/suites/lint-no-ai-selftest.sh' -prune -o \
    -type f -print \
    | LC_ALL=C sort
}

# Provider hostnames a shipped scanner has no legitimate reason to contact.
# Matched as a substring of a domain, so a subdomain (`gateway.openai.com`)
# still trips it.
HOSTNAMES=(
  'api.openai.com' 'api.anthropic.com' 'generativelanguage.googleapis.com'
  'api.cohere.ai' 'api.mistral.ai' 'openrouter.ai' 'api.together.ai'
  'api.perplexity.ai' 'api.groq.com' 'bedrock-runtime' 'sagemaker-runtime'
  'aiplatform.googleapis.com' 'huggingface.co'
)

# SDK / package names: an import, a require, or a dependency manifest entry.
SDK_NAMES=(
  'anthropic' 'openai' 'langchain' 'llama-index' 'llama_index'
  'google-generativeai' 'google.generativeai' 'cohere' 'mistralai'
  'ai21' 'boto3.*bedrock' '@anthropic-ai' '@google/generative-ai'
)

# Model-provider API-key-shaped environment variables.
ENV_PATTERNS=(
  'OPENAI_API_KEY' 'ANTHROPIC_API_KEY' 'GOOGLE_API_KEY' 'GEMINI_API_KEY'
  'COHERE_API_KEY' 'MISTRAL_API_KEY' 'TOGETHER_API_KEY' 'GROQ_API_KEY'
  'PERPLEXITY_API_KEY' 'HUGGINGFACE_API_KEY' 'HF_API_KEY' 'REPLICATE_API_TOKEN'
)

files=$(shipped_files)
count=0
if [[ -n $files ]]; then
  count=$(wc -l <<<"$files")
  count=${count// /}
fi

_check_group() {
  local label=$1
  shift
  local pat found=0 f rel
  for pat in "$@"; do
    while IFS= read -r f; do
      [[ -n $f ]] || continue
      rel=${f#./}
      if scan_match "$HITS" -e "$pat" -- "$rel"; then
        found=1
        report "$rel: $label match '$pat' - no AI/LLM provider may be reachable from the shipped tool"
        cat "$HITS" >&2
      fi
    done <<<"$files"
  done
  return "$found"
}

printf '== no AI/LLM provider hostname, SDK name, or API-key env var in the shipped tool ==\n'

hit=0
_check_group 'provider hostname' "${HOSTNAMES[@]}" || hit=1
_check_group 'provider SDK/package name' "${SDK_NAMES[@]}" || hit=1
_check_group 'provider API-key environment variable' "${ENV_PATTERNS[@]}" || hit=1

if (( count == 0 )); then
  printf '  --  no shipped files to examine\n'
elif (( hit == 0 )); then
  printf '  ok  no AI/LLM signal found across %s shipped files\n' "$count"
fi

printf '\n'
if (( FAILED )); then
  printf 'lint-no-ai: FAILED\n'
  exit 1
fi
printf 'lint-no-ai: clean\n'
