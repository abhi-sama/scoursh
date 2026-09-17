#!/usr/bin/env bash
# tests/suites/lint-shell-selftest.sh - proves tests/lint-shell.sh's "no smart
# quotes" check (SC1112) both directions, and closes the exact regression PR
# #322 shipped: the guard is required to STILL FIRE on a real smart quote,
# and to be structurally incapable of matching its own source, neither of
# which the previous `$'\uHHHH'`-built pattern proved (see the long comment
# above `_smart_quote_utf8_char` in tests/lint-shell.sh for the failure this
# replaces - CI run 35154597539, shard 7, both userlands).
#
# Same shape as tests/suites/dast35-lint.sh: a disposable fixture tree under
# $W, never the real repository, plus tests/lint-shell.sh's optional
# SCAN_ROOT argument to point it there.
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

LINT_SHELL_SRC=$ROOT/tests/lint-shell.sh
W=$SCOURSH_SCRATCH/lint-shell-selftest
rm -rf "$W"
mkdir -p "$W"

lint() {
  bash "$LINT_SHELL_SRC" "$1"
}

# A minimal, otherwise-clean fixture tree - the same baseline
# tests/suites/dast35-lint.sh's fixture_base() establishes, so every OTHER
# check in tests/lint-shell.sh (DAST-35, tension 4/9/19/24/26/27, GUIDE-02)
# passes quietly and a failure here can only be the smart-quote check.
fixture_base() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir/config" "$dir/tools/dast-test-target" "$dir/lib" "$dir/rules"
  : >"$dir/scan.sh"
  printf '%s\n' \
    'id: example-target' \
    'base-url: https://target.example/app' \
    'allow-subdomains: false' \
    'notes: fixture' \
    >"$dir/config/scope.conf.example"
  printf '%s\n' \
    'id: dast-test-target' \
    'base-url: http://127.0.0.1:3400/' \
    'allow-subdomains: false' \
    'allow-private-addresses: true' \
    'notes: fixture, mirrors the real tools/dast-test-target/scope.conf' \
    >"$dir/tools/dast-test-target/scope.conf"
}

# Writes one REAL smart-quote byte sequence into a fixture .sh file, from a
# plain DECIMAL codepoint via Python's chr() - the one write path in this
# whole suite that must not itself go through any `\uHHHH`-shaped text (the
# exact mechanism under test), and decimal sidesteps it structurally rather
# than trusting a shell layer not to reinterpret one.
_plant_smart_quote() {
  local path=$1 codepoint=$2
  python3 - "$path" "$codepoint" <<'PY'
import sys
path, cp = sys.argv[1], int(sys.argv[2])
with open(path, "w", encoding="utf-8") as f:
    f.write("#!/usr/bin/env bash\n")
    f.write(f":  # a developer{chr(cp)}s stray curly quote\n")
PY
}

# ---------------------------------------------------------------------------
printf '\n-- the guard still fires on a real smart quote (requirement 3) --\n'
# ---------------------------------------------------------------------------
FC=$W/fires
fixture_base "$FC"

t_case 'a clean fixture tree with no smart quote passes'
assert_status 0 'clean baseline fixture' lint "$FC"

t_case 'planting a real U+2019 in a tracked .sh file fails the lint'
# FAILS under the reading "the pattern only matters on paper" - a guard that
# has never been observed catching the thing it exists for is decoration,
# not a control (AGENTS.md's own standing rule, and the exact gap that let
# PR #322's version reach `dev` unproven).
_plant_smart_quote "$FC/lib/possessive.sh" 8217
assert_status 1 'a real curly apostrophe is caught' lint "$FC"
out=$(lint "$FC" 2>&1 || true)
assert_contains "$out" 'no U+2018/2019/201C/201D smart quote' 'the failure names the smart-quote check'
assert_contains "$out" 'lib/possessive.sh' 'the failure names the offending file'

t_case 'removing the planted file restores a clean pass'
rm -f "$FC/lib/possessive.sh"
assert_status 0 'the tree is clean again' lint "$FC"

t_case 'each of the four codepoints (U+2018 U+2019 U+201C U+201D) is caught individually'
for cp in 8216 8217 8220 8221; do
  _plant_smart_quote "$FC/lib/one.sh" "$cp"
  assert_status 1 "codepoint $cp alone is caught" lint "$FC"
done
rm -f "$FC/lib/one.sh"
assert_status 0 'clean again after the per-codepoint sweep' lint "$FC"

t_case 'an ordinary ASCII apostrophe/quote never trips the check'
printf '%s\n' '#!/usr/bin/env bash' ": # it's just a plain \"quote\", ASCII only" \
  >"$FC/lib/ascii-quotes.sh"
assert_status 0 'ASCII apostrophes and double quotes are not smart quotes' lint "$FC"
rm -f "$FC/lib/ascii-quotes.sh"

# ---------------------------------------------------------------------------
printf '\n-- the guard cannot match its own source (requirement 2) --\n'
# ---------------------------------------------------------------------------
FS=$W/self-match
fixture_base "$FS"

t_case 'scanning a byte-identical copy of the real tests/lint-shell.sh does not self-match'
# This is the regression PR #322 actually shipped: the pattern-defining line
# itself was a hit. Copy the REAL, CURRENT file - not a paraphrase - into the
# fixture tree's tests/ dir, which the smart-quote check's own all_files()
# lister covers, exactly as it covers the real tests/lint-shell.sh in the
# real repository. tests/ is deliberately used here rather than lib/: it is
# NOT in engine_files()'s scope, so this fixture isolates the smart-quote
# check alone rather than also tripping the tension-19/GUIDE-02 checks this
# file's own prose about /dev/tcp and guide_isolation_files legitimately (and
# unrelatedly) matches once treated as engine content - a pre-existing,
# unrelated fact about this file, not a smart-quote regression.
mkdir -p "$FS/tests"
cp "$LINT_SHELL_SRC" "$FS/tests/lint-shell-copy.sh"
out=$(lint "$FS" 2>&1 || true)
assert_contains "$out" "ok  no U+2018/2019/201C/201D smart quote" 'the smart-quote check itself still reports ok'
assert_not_contains "$out" 'tests/lint-shell-copy.sh' 'the copy of the real guard is never named as a smart-quote violation'
rm -rf "$FS/tests"

t_case 'the real source carries no literal $'"'"'\uHHHH'"'"' ANSI-C escape'
# PR #322's whole failure mode started here: a `$'\uHHHH'` escape whose
# UNEXPANDED text spells the very substring the resulting pattern searches
# for. The fix removes the construct entirely rather than tuning it, so this
# structural grep - not a behavioural probe - is what pins that it can never
# come back by accident.
if grep -qE '\$'"'"'\\+u[0-9A-Fa-f]{4}' "$LINT_SHELL_SRC"; then
  found=1
else
  found=0
fi
assert_eq 0 "$found" 'no $'"'"'\uHHHH'"'"' ANSI-C escape anywhere in tests/lint-shell.sh'

t_case 'the codepoint-encoding helper builds byte-identical output under two independent bash builds'
# Isolates _smart_quote_utf8_char from the rest of the file (which cannot run
# under bash 3.2 at all - lib/core.sh's own tension-24 floor refuses to
# source under anything below 4.2) and re-runs it under whatever /bin/bash
# this host ships, proving the fix depends on plain printf(1) octal/%b
# conversions rather than any bash-version-specific Unicode-escape support.
# Skips gracefully where the host has no second bash to compare against.
FN=$SCOURSH_SCRATCH/lint-shell-selftest-fn.sh
sed -n '/^_smart_quote_utf8_char() {/,/^}/p' "$LINT_SHELL_SRC" >"$FN"
current_bytes=$(bash -c '
  source "$1"
  printf "%s" "($(_smart_quote_utf8_char 8216)|$(_smart_quote_utf8_char 8217)|$(_smart_quote_utf8_char 8220)|$(_smart_quote_utf8_char 8221))"
' _ "$FN" | xxd -p)
if [[ -x /bin/bash && /bin/bash != "$(command -v bash)" ]]; then
  other_bytes=$(/bin/bash -c '
    source "$1"
    printf "%s" "($(_smart_quote_utf8_char 8216)|$(_smart_quote_utf8_char 8217)|$(_smart_quote_utf8_char 8220)|$(_smart_quote_utf8_char 8221))"
  ' _ "$FN" | xxd -p)
  assert_eq "$current_bytes" "$other_bytes" '/bin/bash and the default bash produce byte-identical patterns'
else
  printf '  skip  no second bash build available to cross-check on this host\n'
fi
rm -f "$FN"

rm -rf "$W"
t_summary 'lint-shell smart-quote self-test'
