#!/usr/bin/env bash
# tests/suites/config.sh - lib/config.sh, the operator config loader.
#
# Covers: the CLI > env > file > default precedence chain for
# config/scanner.conf, fail-loud validation at every level (never a silent
# fallback to the next level or to the default), the generic
# load-or-die/load-if-present primitives, and the config/scope.conf §7 gate
# (docs/DESIGN.md §7: "No entry -> exit 3"; docs/FOUNDATION.md tension 14:
# "a missing scope.conf is exit 4 only for dast").
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule: a test that passes under both the correct and a
# plausible-but-wrong reading pins nothing.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is the intended reporting shape.
# SC2016: assertion prose mentions shell variables literally.
# SC2030/SC2031: `export VAR=val; fn` inside `$(...)` or a helper passed to
#   assert_status is DELIBERATELY subshell-scoped, so one precedence probe's
#   override can never leak into the next.
# SC2329: every `_bad_*` helper below is invoked indirectly, as an argument
#   to assert_status, which shellcheck's static call graph does not follow.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/config.sh
source "$ROOT/lib/config.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/cfg
mkdir -p "$W"

# ---------------------------------------------------------------------------
printf '\n-- generic load-or-die / load-if-present --\n'
# ---------------------------------------------------------------------------
cat >"$W/scope-ok.conf" <<'EOF'
id: fixture-target
base-url: https://app.fixture.invalid/
notes: ok fixture
EOF
cat >"$W/scope-bad.conf" <<'EOF'
id: fixture-target
base-url: https://app.fixture.invalid/
allow-subdomains: maybe
EOF

t_case 'config_load_if_present'
assert_status 1 'an absent file returns 1 and does not die' \
  config_load_if_present "$W/does-not-exist.conf" scope-target zzz
assert_status 0 'a present, valid file returns 0' \
  config_load_if_present "$W/scope-ok.conf" scope-target zzz

t_case 'config_load_or_die'
assert_status 4 'a missing file dies exit 4 (missing required input) - fails under "usage error" (2) or "scope violation" (3), neither of which fits a config file the invocation never named' \
  config_load_or_die "$W/does-not-exist.conf" scope-target zzz
assert_status 4 'a file that fails schema validation (allow-subdomains: maybe is not true/false) dies exit 4, the same code an unusable file gets whether the problem is syntax or schema' \
  config_load_or_die "$W/scope-bad.conf" scope-target zzz

# ---------------------------------------------------------------------------
printf '\n-- config/scanner.conf: absent file == documented defaults --\n'
# ---------------------------------------------------------------------------
t_case 'config_scanner_load on an absent file'
config_scanner_load "$W/no-such-scanner.conf"
assert_eq 0 "$CONFIG_SCANNER_LOADED" 'CONFIG_SCANNER_LOADED is 0: no die, no synthesized record'
assert_eq 4 "$(config_scanner_value jobs)" 'jobs falls all the way to its §9.6.1 default of 4'
assert_eq none "$(config_scanner_value fail-on)" 'fail-on defaults to none'
assert_eq low "$(config_scanner_value min-confidence)" 'min-confidence defaults to low'
assert_eq true "$(config_scanner_value redact-secrets)" 'redact-secrets defaults to true'
assert_eq 'json
sarif
html
md' "$(config_scanner_list formats)" 'formats defaults to all four, in the documented order'
assert_eq '' "$(config_scanner_list paranoid-allow)" 'paranoid-allow defaults to empty'

# ---------------------------------------------------------------------------
printf '\n-- precedence: default < file < env < cli, one level at a time --\n'
# ---------------------------------------------------------------------------
cat >"$W/scanner.conf" <<'EOF'
id: scanner
jobs: 8
fail-on: high
formats: json
EOF
config_scanner_load "$W/scanner.conf"
assert_eq 1 "$CONFIG_SCANNER_LOADED" 'a present, valid scanner.conf loads'

t_case 'level 1: file overrides default'
assert_eq 8 "$(config_scanner_value jobs)" \
  'jobs reads 8 from the file - fails under "file is never consulted, only env/cli/default"'
assert_eq high "$(config_scanner_value fail-on)" 'fail-on reads high from the file'
assert_eq json "$(config_scanner_list formats)" \
  'formats reads its single file entry - fails under "repeatable keys never resolve past the default list"'

t_case 'level 2: env overrides file'
val=$(export SCOURSH_CONFIG_JOBS=16; config_scanner_value jobs)
assert_eq 16 "$val" \
  'SCOURSH_CONFIG_JOBS=16 beats the file''s jobs: 8 - fails under "file always wins once present" (the frozen order is CLI > env > FILE > default, so a present file must still lose to env)'
val=$(export SCOURSH_CONFIG_FORMATS=sarif,md; config_scanner_list formats)
assert_eq 'sarif
md' "$val" 'SCOURSH_CONFIG_FORMATS overrides the file''s formats: json'
# An explicitly EMPTY env var is "not given" and falls through to the file,
# not to the default - fails under "any exported var counts as given".
val=$(export SCOURSH_CONFIG_JOBS=''; config_scanner_value jobs)
assert_eq 8 "$val" 'SCOURSH_CONFIG_JOBS="" is treated as unset and falls through to the file value'

t_case 'level 3: cli overrides env (and file, and default)'
val=$(export SCOURSH_CONFIG_JOBS=16; config_scanner_value jobs 32)
assert_eq 32 "$val" \
  'an explicit CLI value of 32 beats both env (16) and file (8) - fails under "env always wins once exported"'
val=$(export SCOURSH_CONFIG_FORMATS=sarif; config_scanner_list formats 'html,md')
assert_eq 'html
md' "$val" 'a CLI-supplied format list beats env and file'

t_case 'precedence is per-key, not global'
assert_eq low "$(config_scanner_value min-confidence)" \
  'min-confidence is untouched by any override made to jobs/fail-on/formats above'

# ---------------------------------------------------------------------------
printf '\n-- fail loud, never fall through, at every level --\n'
# ---------------------------------------------------------------------------
cat >"$W/scanner-badval.conf" <<'EOF'
id: scanner
jobs: not-a-number
EOF

t_case 'a malformed FILE value dies 4 and does not fall back to the default'
_bad_file_jobs() {
  config_scanner_load "$W/scanner-badval.conf"
  config_scanner_value jobs
}
assert_status 4 'jobs: not-a-number in scanner.conf dies exit 4 - fails under "an invalid file value silently uses the default (4) instead"' \
  _bad_file_jobs

t_case 'a malformed ENV value dies 2 and does not fall back to the file or default'
_bad_env_jobs() {
  config_scanner_load "$W/scanner.conf"
  export SCOURSH_CONFIG_JOBS=abc
  config_scanner_value jobs
}
assert_status 2 'SCOURSH_CONFIG_JOBS=abc dies exit 2 (usage error) - fails under "an invalid env value silently uses the file value (8) instead"' \
  _bad_env_jobs

t_case 'a malformed CLI value dies 2 and does not fall back to env, file, or default'
_bad_cli_jobs() {
  config_scanner_load "$W/scanner.conf"
  export SCOURSH_CONFIG_JOBS=16
  config_scanner_value jobs not-a-number
}
assert_status 2 'an explicit but invalid CLI value dies exit 2 - fails under "an invalid CLI value silently uses env (16) instead"' \
  _bad_cli_jobs

t_case 'a malformed list entry dies, at the level it came from'
_bad_file_formats() {
  printf 'id: scanner\nformats: xml\n' >"$W/scanner-badlist.conf"
  config_scanner_load "$W/scanner-badlist.conf"
  config_scanner_list formats
}
assert_status 4 'formats: xml in the file is not one of json/sarif/html/md - dies exit 4' \
  _bad_file_formats
_bad_cli_formats() {
  config_scanner_load "$W/scanner.conf"
  config_scanner_list formats 'json,xml'
}
assert_status 2 'a CLI-supplied "xml" format dies exit 2, not exit 4 - fails under "list validation always reports the file''s exit code regardless of source"' \
  _bad_cli_formats

t_case 'redact-secrets and fail-on enums'
_bad_redact() {
  printf 'id: scanner\nredact-secrets: sometimes\n' >"$W/scanner-badbool.conf"
  config_scanner_load "$W/scanner-badbool.conf"
  config_scanner_value redact-secrets
}
assert_status 4 'redact-secrets: sometimes is neither true nor false' _bad_redact

# ---------------------------------------------------------------------------
printf '\n-- config/scope.conf: the §7 gate --\n'
# ---------------------------------------------------------------------------
FIXTURE_SCOPE=$ROOT/tests/fixtures/config/scope.conf

t_case 'a target that exists resolves to its record'
# config_scope_require is called DIRECTLY, never through $(...): it loads
# config/scope.conf as a side effect, and capturing it via command
# substitution would run that load inside a subshell and discard the
# populated record set the moment the subshell exits (the same class of bug
# lib/core.sh's run_init comment warns about).
config_scope_require fixture-target "$FIXTURE_SCOPE"
idx=$(records_index_of_id scope fixture-target)
assert_eq fixture-target "$(records_id scope "$idx")" \
  'the "scope" record set is populated in the CURRENT shell, not thrown away in a subshell'
assert_eq 'https://app.fixture.invalid/' "$(config_scope_field fixture-target base-url)" \
  'config_scope_field reads the resolved target''s base-url'
assert_eq false "$(config_scope_field_or fixture-wide allow-private-addresses false)" \
  'config_scope_field_or returns the documented default when the key is absent from the record'

t_case 'a target that does not exist is exit 3, never exit 4'
assert_status 3 '"--target no-such-target" with a present, valid scope.conf dies exit 3 (scope violation) - fails under "any scope.conf problem is exit 4"; docs/DESIGN.md §7 requires exactly 3 here, because 3 is the code that must never be masked' \
  config_scope_require no-such-target "$FIXTURE_SCOPE"

t_case 'a wholly missing scope.conf is exit 4, never exit 3'
assert_status 4 'dast needs config/scope.conf to exist at all before the gate can even be asked a question - fails under "no file also means no entry, so it is exit 3 too" (docs/FOUNDATION.md tension 14: missing scope.conf is exit 4 only for dast)' \
  config_scope_require fixture-target "$W/does-not-exist-scope.conf"

t_case 'a malformed scope.conf is exit 4, never silently treated as empty'
cat >"$W/scope-malformed.conf" <<'EOF'
id: fixture-target
base-url: https://app.fixture.invalid/
allow-subdomains: maybe
EOF
assert_status 4 'allow-subdomains: maybe fails schema validation, so the gate refuses rather than silently seeing zero targets (which would report exit 3, hiding a broken config file behind the same code an operator typo produces)' \
  config_scope_require fixture-target "$W/scope-malformed.conf"

t_case 'CONFIG_SCOPE_LOADED gates the field accessors'
CONFIG_SCOPE_LOADED=0
assert_status 5 'config_scope_field before any load/require dies exit 5 (internal/incomplete), not a confusing "target not found"' \
  config_scope_field fixture-target base-url

t_summary 'config' || FAILED=1
exit "${FAILED:-0}"
