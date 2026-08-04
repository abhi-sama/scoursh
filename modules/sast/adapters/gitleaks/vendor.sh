#!/usr/bin/env bash
# modules/sast/adapters/gitleaks/vendor.sh - populates this adapter's own
# bin/ and rules/ (docs/ADAPTERS.md §4) from the network.
#
# Owns: docs/ADAPTERS.md §2's consequence for adapter code, applied to the
# ONE file per adapter that is an intentional, documented exception to it -
# mirrors modules/sast/adapters/semgrep/vendor.sh's own shape exactly.
#
# RUN BY tools/vendor-engines.sh ONLY, BY HAND, ON A NETWORKED BOX
# (docs/DESIGN.md §9/§13 step 9; tools/vendor-engines.sh's own header).
# This file is sourced by `veng_vendor_gitleaks` (tools/vendor-engines.sh's
# own registry entry for `gitleaks`, added by this ticket) - never by
# scan.sh, never by anything under lib/ or modules/ at scan time.  It is
# still linted like every other file under modules/ (tests/lint-shell.sh's
# `engine_files` glob does not carve out adapters/), so the ONLY function it
# may use to reach the network is `veng_fetch` (exported by
# tools/vendor-engines.sh) - this file itself contains no
# curl/wget/nc/openssl-s_client token, satisfying that check by construction
# rather than by an added exemption.
#
# WHAT THIS DOES NOT DO: guess, hardcode, or "best-effort" a checksum for
# the artifact it fetches - the identical OWASP A08 (software/data integrity
# failures) reasoning modules/sast/adapters/semgrep/vendor.sh's own header
# already states, applied to gitleaks' release binary and its own default
# ruleset instead.  The operator running this BY HAND, ON A NETWORKED BOX,
# supplies the exact version and the sha256 they independently copied from
# gitleaks' own published release notes; this script verifies the download
# against THAT value and refuses to install anything that does not match.
#
# shellcheck shell=bash

# gitleaks_vendor - the function tools/vendor-engines.sh's VENG_REGISTRY[gitleaks]
# entry calls.  Reads its inputs from the environment rather than argv
# (SCOURSH_GITLEAKS_VERSION / SCOURSH_GITLEAKS_URL / SCOURSH_GITLEAKS_SHA256 /
# SCOURSH_GITLEAKS_RULES_URL / SCOURSH_GITLEAKS_RULES_SHA256) - the identical
# "operator-supplied, not guessed" shape semgrep_vendor already uses, and
# none of these five are secrets (tension 9 does not apply to a public
# release URL or a public checksum).
gitleaks_vendor() {
  local version=${SCOURSH_GITLEAKS_VERSION:-}
  local url=${SCOURSH_GITLEAKS_URL:-}
  local sha256=${SCOURSH_GITLEAKS_SHA256:-}
  local rules_url=${SCOURSH_GITLEAKS_RULES_URL:-}
  local rules_sha256=${SCOURSH_GITLEAKS_RULES_SHA256:-}

  if [[ -z $version || -z $url || -z $sha256 || -z $rules_url || -z $rules_sha256 ]]; then
    log_error 'vendor-engines: gitleaks needs SCOURSH_GITLEAKS_VERSION, SCOURSH_GITLEAKS_URL,'
    log_error '  SCOURSH_GITLEAKS_SHA256, SCOURSH_GITLEAKS_RULES_URL and SCOURSH_GITLEAKS_RULES_SHA256'
    log_error '  all set - copy the version, the platform binary URL, and both sha256 digests'
    log_error '  from gitleaks'\''s own published release notes (https://github.com/gitleaks/gitleaks/releases)'
    log_error '  and its own default gitleaks.toml.'
    log_error '  This script never guesses or hardcodes a checksum (see this file'\''s own header).'
    die "$SCOURSH_EXIT_INPUT" 'gitleaks vendoring: required SCOURSH_GITLEAKS_* values are not set'
  fi

  local adapter_dir
  adapter_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  local bin_dir=$adapter_dir/bin
  local rules_dir=$adapter_dir/rules
  mkdir -p "$bin_dir" "$rules_dir"

  log_info "vendor-engines: fetching gitleaks $version binary"
  veng_fetch "$url" "$bin_dir/gitleaks" "$sha256"
  chmod +x "$bin_dir/gitleaks"

  log_info 'vendor-engines: fetching gitleaks offline ruleset (gitleaks.toml)'
  veng_fetch "$rules_url" "$rules_dir/gitleaks.toml" "$rules_sha256"

  log_info "vendor-engines: gitleaks $version vendored into ${adapter_dir#"$SCOURSH_INSTALL_ROOT"/}"
  log_info '  commit modules/sast/adapters/gitleaks/bin and .../rules to git; every real scan'
  log_info '  from here on runs fully offline against exactly these bytes.'
}
