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
# TWO FALSE-POSITIVE CLASSES, both measured on CI run 35092825749 in one
# failure (`scan.sh` and `suite.log`, both for pattern 'cohere'), and both
# fixed here rather than by naming the one file/token that surfaced them:
#
# 1. BARE SUBSTRING MATCH. A provider token that is also an ordinary English
#    word or a substring of one trips on prose, not code: `cohere` matched
#    inside "coherent" at scan.sh:2067. Every pattern below is matched with
#    `_bounded_pattern`, which puts a `\b` word boundary on whichever side
#    starts or ends on a word character ([A-Za-z0-9_]) - `cohere` and
#    `anthropic` (a substring of "philanthropic"/"misanthropic") both need
#    it; a side that already starts or ends on punctuation (`@anthropic-ai`,
#    the `boto3.*bedrock` wildcard) is left unbounded there, because forcing
#    a boundary onto a punctuation edge would refuse to match the realistic
#    on-disk form (an npm scope name is never preceded by a word character).
#    `\b` is measured elsewhere in this repository (AGENTS.md, "Things
#    measured on this codebase") to behave identically under `rg`'s default
#    engine and BSD/GNU `grep -E`, which is what scan_match's two engines
#    need.
#
# 2. THE LINT SCANNING ITS OWN OUTPUT. The CI job pipes the whole test run
#    through `tee suite.log` (.github/workflows/ci.yml), which writes
#    suite.log into the checkout root - inside the very tree this script
#    walks - and, because tee flushes as the run proceeds, suite.log already
#    contains this script's own just-printed "cohere" finding for scan.sh by
#    the time the scan reaches "suite.log" later in its sorted file list, so
#    the lint matches its own report about itself. suite.log is untracked
#    and `.gitignore`'d, exactly like every other build/log/run artifact
#    (`reports/`, `state/`, the two vendored SCA databases, ...) - none of
#    those are "the shipped tool", so `shipped_files()` below subtracts
#    whatever `git ls-files --others --ignored` reports for ROOT, rather
#    than naming suite.log (or any other one artifact) by path. A ROOT that
#    is not itself a git working tree (this file's own self-test fixture)
#    has nothing to subtract and scans exactly as before.
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

# Every other untracked, `.gitignore`'d path under ROOT - suite.log,
# reports/, state/, the two vendored SCA databases, whatever the ignore
# rules name today or name later - as a set `shipped_files` subtracts from
# its candidate list (class 2 in this file's own header above). Empty
# (never an error) when ROOT is not a git working tree at all, which is the
# self-test fixture's own shape: a plain, ungitted throwaway tree has no
# ignore rules to consult, so nothing is subtracted and it scans exactly as
# it always has.
_generated_files() {
  _have git || return 0
  git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  git -C "$ROOT" ls-files --others --ignored --exclude-standard 2>/dev/null || true
}

# Every shipped file: the whole tree except .git, documentation (*.md
# anywhere, which is prose ABOUT this rule, not code that could violate it),
# this linter's own two files (this script and its self-test suite, which
# both have to name what they look for in order to test/implement it), and
# every path `_generated_files` reports.
#
# The two vendored SCA databases (data/advisories.db, data/versions.db) are
# ALSO pruned explicitly by path here, belt-and-suspenders alongside
# `_generated_files`: they are real package names, not code, and OSV's own
# npm corpus alone names dozens of real and malicious packages containing
# "anthropic"/"openai"/... as a substring (`spring-ai-anthropic`, a real
# Maven artifact; `anthropic-toolkit`, a real MAL-* typosquat listing) -
# scanning them made an ordinary first run (build the database per the
# README, then run this suite to confirm the install worked) fail on a
# security lint that has nothing to do with the change, since the match is
# in third-party advisory PROSE this scanner looks up, not anything scoursh
# itself can call.
shipped_files() {
  local candidates generated
  candidates=$(find . \
    -path ./.git -prune -o \
    -name '*.md' -prune -o \
    -path './tests/lint-no-ai.sh' -prune -o \
    -path './tests/suites/lint-no-ai-selftest.sh' -prune -o \
    -path './data/advisories.db' -prune -o \
    -path './data/versions.db' -prune -o \
    -type f -print \
    | sed 's|^\./||' | LC_ALL=C sort)
  generated=$(_generated_files | LC_ALL=C sort)
  if [[ -n $generated ]]; then
    comm -23 <(printf '%s\n' "$candidates") <(printf '%s\n' "$generated")
  else
    printf '%s\n' "$candidates"
  fi
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

# Wraps PAT in a `\b` word boundary on whichever side starts/ends on a word
# character ([A-Za-z0-9_]), so a bare-word token like `cohere` or `anthropic`
# cannot match inside "coherent" or "philanthropic". A side that already
# starts/ends on punctuation (`@anthropic-ai`, the `.*` in
# `boto3.*bedrock`) is left unbounded there on purpose: a leading `\b`
# immediately before a non-word character can only ever be satisfied when
# preceded by a word character, so `\b@anthropic-ai` would refuse to match
# the realistic on-disk form (an npm scope name preceded by a quote,
# whitespace, or line start - never a letter/digit/underscore).
_bounded_pattern() {
  local pat=$1 pre='' post=''
  [[ ${pat:0:1} =~ [A-Za-z0-9_] ]] && pre='\b'
  [[ ${pat: -1} =~ [A-Za-z0-9_] ]] && post='\b'
  printf '%s%s%s' "$pre" "$pat" "$post"
}

_check_group() {
  local label=$1
  shift
  local pat bpat found=0 f rel
  for pat in "$@"; do
    bpat=$(_bounded_pattern "$pat")
    while IFS= read -r f; do
      [[ -n $f ]] || continue
      rel=${f#./}
      if scan_match "$HITS" -e "$bpat" -- "$rel"; then
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
