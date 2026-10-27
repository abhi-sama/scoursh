#!/usr/bin/env bash
# Owns: dependency identity/applicability regressions from the precision audit.
# Each negative is paired with the effective vulnerable coordinate it must keep.
# shellcheck shell=bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sca/go_engine.sh
source "$ROOT/modules/sca/go_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
F=$ROOT/tests/fixtures/sca-precision
W=$SCOURSH_SCRATCH/sca-precision
mkdir -p "$W"
t_case 'npm alias: lookup target identity, classify directness by installation slot'
assert_eq $'is-number\x1f4.0.0\x1fdirect' "$(_sca_parse_npm_lock_v2v3 "$F/npm-alias/package-lock.json")" 'safe alias target is not looked up as lodash'
assert_eq $'lodash\x1f4.0.0\x1fdirect' "$(_sca_parse_npm_lock_v2v3 "$F/npm-positive/package-lock.json")" 'ordinary vulnerable package remains visible'
sed 's/"is-number"/"lodash"/;s/node_modules\/lodash/node_modules\/friendly/;s/"lodash":/"friendly":/;s/"name": "lodash",/"name": "lodash",/' "$F/npm-alias/package-lock.json" >"$W/alias.json"
assert_eq $'lodash\x1f4.0.0\x1fdirect' "$(_sca_parse_npm_lock_v2v3 "$W/alias.json")" 'vulnerable target cannot hide behind safe alias'
t_case 'Go: apply version-specific replacement rather than pre-replace pin'
assert_eq $'github.com/pkg/errors\x1fv0.9.2\x1fdirect' "$(_sca_go_parse_mod "$F/go-replace/go.mod")" 'patched replacement replaces vulnerable pin'
assert_eq $'github.com/pkg/errors\x1fv0.9.1\x1fdirect' "$(_sca_go_parse_mod "$F/go-positive/go.mod")" 'unreplaced vulnerable pin remains visible'
cat >"$W/go.mod" <<'EOF'
module local.invalid/app
require github.com/pkg/errors v0.9.2
replace (
 github.com/pkg/errors => github.com/pkg/errors v0.9.1
)
EOF
assert_eq $'github.com/pkg/errors\x1fv0.9.1\x1fdirect' "$(_sca_go_parse_mod "$W/go.mod")" 'wildcard downgrade remains vulnerable'
cat >>"$W/go.mod" <<'EOF'
replace github.com/pkg/errors v0.9.2 => ./local-copy
EOF
assert_eq '' "$(_sca_go_parse_mod "$W/go.mod")" 'unknown local replacement never claims old registry version is installed'
t_case 'requirements: impossible marker, never the scanning host interpreter'
assert_eq '' "$(sca_parse_requirements_txt "$F/python-false-marker/requirements.txt")" 'no Python version is less than zero'
assert_eq $'requests\x1f2.6.0\x1funknown' "$(sca_parse_requirements_txt "$F/python-positive/requirements.txt")" 'unconditional pin remains visible'
printf '%s\n' 'requests==2.6.0; python_version < "0" or sys_platform == "win32"' >"$W/requirements.txt"
assert_contains "$(sca_parse_requirements_txt "$W/requirements.txt")" requests 'possible OR branch is retained on every scanning host'
assert_contains "$(sca_parse_requirements_txt "$W/requirements.txt" true)" 'or sys_platform' 'the scan path preserves the condition instead of claiming unconditional installation'
t_case 'Gradle: string-aware block comments, active dependency preserved'
assert_eq '' "$(_sca_parse_build_gradle "$F/gradle-block-comment/build.gradle")" 'removed dependency is not installed'
assert_eq $'org.yaml:snakeyaml\x1f1.26\x1fdirect' "$(_sca_parse_build_gradle "$F/java-positive/build.gradle")" 'active dependency still emitted'
printf '%s\n' '/* old */ implementation "org.yaml:snakeyaml:1.26" // live' >"$W/build.gradle"
assert_contains "$(_sca_parse_build_gradle "$W/build.gradle")" snakeyaml 'live suffix after block comment retained'
cat >"$W/build.gradle" <<'EOF'
def documentation = """
 implementation "org.yaml:snakeyaml:1.26"
"""
EOF
assert_eq '' "$(_sca_parse_build_gradle "$W/build.gradle")" 'multiline string content is not a dependency declaration'
t_case 'Composer: indentation is formatting, not dependency identity'
assert_eq $'acme/widget\x1f1.2.3\x1funknown' "$(sca_parse_composer_lock "$F/php-positive/composer.lock")" 'two-space JSON retains vulnerable package'
assert_eq $'acme/widget\x1f1.2.3\x1funknown' "$(sca_parse_composer_lock "$F/php-canonical-positive/composer.lock")" 'four-space writer layout remains visible'
cat >"$W/composer.lock" <<'EOF'
{
  "packages": [
    {
      "name": "acme/widget",
      "version": "1.2.3",
      "extra": {
        "packages": [
          {
            "name": "not-a-dependency",
            "version": "1.2.3"
          }
        ]
      }
    }
  ]
}
EOF
assert_eq $'acme/widget\x1f1.2.3\x1funknown' "$(sca_parse_composer_lock "$W/composer.lock")" 'nested metadata cannot redefine the root indentation or invent dependencies'
t_summary sca-precision
