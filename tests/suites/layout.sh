#!/usr/bin/env bash
# tests/suites/layout.sh - installed-copy user-state layout resolution.
#
# shellcheck shell=bash

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/layout
rm -rf "$W"
mkdir -p "$W"

t_case 'a checkout keeps every historical in-tree location'
CLONE_PATHS=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u XDG_STATE_HOME \
  bash "$ROOT/scan.sh" paths)
assert_contains "$CLONE_PATHS" "config: $ROOT/config" 'clone config remains in its install root'
assert_contains "$CLONE_PATHS" "data: $ROOT/data" 'clone generated data remains in its install root'
assert_contains "$CLONE_PATHS" "state: $ROOT/state" 'clone state remains in its install root'
assert_contains "$CLONE_PATHS" "reports: $ROOT/reports" 'clone reports remain in its install root'

PKG=$W/installed
mkdir -p "$PKG"
for part in scan.sh VERSION lib modules rules data config; do
  cp -R "$ROOT/$part" "$PKG/$part"
done
: >"$PKG/.scoursh-packaged"
PKG=$(cd -- "$PKG" && pwd -P)

XDG_CONFIG=$W/xdg/config
XDG_DATA=$W/xdg/data
XDG_STATE=$W/xdg/state
TEST_HOME=$W/home

t_case 'the release marker selects XDG locations and paths reports them'
INSTALLED_PATHS=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash "$PKG/scan.sh" paths)
assert_contains "$INSTALLED_PATHS" "install: $PKG" 'paths retains the immutable install location'
assert_contains "$INSTALLED_PATHS" "config: $XDG_CONFIG/scoursh" 'marker resolves config through XDG_CONFIG_HOME'
assert_contains "$INSTALLED_PATHS" "data: $XDG_DATA/scoursh" 'marker resolves data through XDG_DATA_HOME'
assert_contains "$INSTALLED_PATHS" "state: $XDG_STATE/scoursh/state" 'marker resolves state through XDG_STATE_HOME'
assert_contains "$INSTALLED_PATHS" "reports: $XDG_STATE/scoursh/reports" 'marker resolves reports through XDG_STATE_HOME'

t_case 'SCOURSH_HOME collapses all mutable locations below one root'
SINGLE=$W/single-root
SINGLE_PATHS=$(env -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" SCOURSH_HOME="$SINGLE" \
  XDG_CONFIG_HOME="$XDG_CONFIG/ignored" XDG_DATA_HOME="$XDG_DATA/ignored" \
  XDG_STATE_HOME="$XDG_STATE/ignored" bash "$PKG/scan.sh" paths)
assert_contains "$SINGLE_PATHS" "config: $SINGLE/config" 'SCOURSH_HOME owns config'
assert_contains "$SINGLE_PATHS" "data: $SINGLE/data" 'SCOURSH_HOME owns generated data'
assert_contains "$SINGLE_PATHS" "state: $SINGLE/state" 'SCOURSH_HOME owns state'
assert_contains "$SINGLE_PATHS" "reports: $SINGLE/reports" 'SCOURSH_HOME owns reports'

t_case 'advisory DB lookup prefers user data, falls back to packaged data, and keeps an explicit override'
printf '# packaged fixture\n' >"$PKG/data/advisories.db"
# The child shell, not this test process, expands $1 to the package root.
# shellcheck disable=SC2016
DB_FALLBACK=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash -c \
  'source "$1/lib/core.sh"; source "$1/modules/sca/engine.sh"; sca_advisories_db_path' _ "$PKG")
assert_eq "$PKG/data/advisories.db" "$DB_FALLBACK" 'packaged advisory DB is used when user data is absent'
mkdir -p "$XDG_DATA/scoursh"
printf '# user fixture\n' >"$XDG_DATA/scoursh/advisories.db"
# shellcheck disable=SC2016
DB_USER=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash -c \
  'source "$1/lib/core.sh"; source "$1/modules/sca/engine.sh"; sca_advisories_db_path' _ "$PKG")
assert_eq "$XDG_DATA/scoursh/advisories.db" "$DB_USER" 'user advisory DB wins over packaged fallback'
# shellcheck disable=SC2016
DB_OVERRIDE=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" SCOURSH_SCA_ADVISORIES_DB="$W/override.db" \
  bash -c 'source "$1/lib/core.sh"; source "$1/modules/sca/engine.sh"; sca_advisories_db_path' _ "$PKG")
assert_eq "$W/override.db" "$DB_OVERRIDE" 'per-file advisory override beats the resolved data directory'

t_case 'engine assets use package fallback until installed user data is present'
# The reader must keep finding an existing package-local vendor until an
# installed copy has user-owned assets; the writer always names that user
# location so a read-only package is never modified.
# shellcheck disable=SC2016
ENGINE_FALLBACK=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash -c \
  'source "$1/lib/core.sh"; scoursh_engine_dir sast semgrep' _ "$PKG")
assert_eq "$PKG/modules/sast/adapters/semgrep" "$ENGINE_FALLBACK" \
  'an installed reader falls back to the package adapter when no user engine exists'
# shellcheck disable=SC2016
ENGINE_WRITE=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash -c \
  'source "$1/lib/core.sh"; scoursh_engine_dir_for_write sast semgrep' _ "$PKG")
assert_eq "$XDG_DATA/scoursh/engines/sast/semgrep" "$ENGINE_WRITE" \
  'an installed writer selects user data, never the package adapter'
mkdir -p "$XDG_DATA/scoursh/engines/sast/semgrep"
# shellcheck disable=SC2016
ENGINE_USER=$(env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" bash -c \
  'source "$1/lib/core.sh"; scoursh_engine_dir sast semgrep' _ "$PKG")
assert_eq "$ENGINE_WRITE" "$ENGINE_USER" \
  'once user engine storage exists, reader and writer resolve the identical directory'

t_case 'a read-only installed root writes SAST state and reports only to writable XDG locations'
TARGET=$W/target
mkdir -p "$TARGET"
printf 'answer = 42\n' >"$TARGET/clean.py"
chmod -R a-w "$PKG"
RUN_RC=0
env -u SCOURSH_HOME -u SCOURSH_INSTALL_ROOT HOME="$TEST_HOME" XDG_CONFIG_HOME="$XDG_CONFIG" \
  XDG_DATA_HOME="$XDG_DATA" XDG_STATE_HOME="$XDG_STATE" \
  bash "$PKG/scan.sh" sast --path "$TARGET" >"$W/sast.out" 2>&1 || RUN_RC=$?
assert_eq 0 "$RUN_RC" 'SAST completes from a read-only packaged install'
assert_true "$(if [[ -n $(find "$XDG_STATE/scoursh/reports" -name run.json -type f -print -quit) ]]; then printf 0; else printf 1; fi)" \
  'report run.json is written below XDG state'
assert_true "$(if [[ -n $(find "$XDG_STATE/scoursh/state" -name latest.json -type f -print -quit) ]]; then printf 0; else printf 1; fi)" \
  'persistent diff state is written below XDG state'

t_summary 'layout'
