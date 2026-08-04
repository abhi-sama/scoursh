#!/usr/bin/env bash
# modules/sast/adapters/semgrep/vendor.sh - populates this adapter's own
# bin/ and rules/ (docs/ADAPTERS.md §4) from the network.
#
# Owns: docs/ADAPTERS.md §2's consequence for adapter code, applied to the
# ONE file per adapter that is an intentional, documented exception to it.
#
# RUN BY tools/vendor-engines.sh ONLY, BY HAND, ON A NETWORKED BOX
# (docs/DESIGN.md §9/§13 step 9; tools/vendor-engines.sh's own header).
# This file is sourced by `veng_vendor_semgrep` (tools/vendor-engines.sh's
# own registry entry for `semgrep`, added by this ticket) - never by
# scan.sh, never by anything under lib/ or modules/ at scan time.  It is
# still linted like every other file under modules/ (tests/lint-shell.sh's
# `engine_files` glob does not carve out adapters/), so the ONLY function it
# may use to reach the network is `veng_fetch` (exported by
# tools/vendor-engines.sh, the sole exempted "no bypass" caller of
# curl/wget) - this file itself contains no curl/wget/nc/openssl-s_client
# token, satisfying that check by construction rather than by an added
# exemption.
#
# WHAT THIS DOES NOT DO: guess, hardcode, or "best-effort" a checksum for
# the artifact it fetches.  AGENTS.md's own history section records three
# separate incidents of an invented, unverifiable fact (a commit sha) being
# written into this repository's own docs and shipping anyway; hardcoding a
# semgrep release checksum here that nobody has actually verified against
# the real upstream release notes would be the same mistake in a security-
# sensitive, integrity-verification context (OWASP A08: software/data
# integrity failures - an unverified artifact is not meaningfully different
# from an unsigned one).  The operator running this BY HAND, ON A NETWORKED
# BOX, supplies the exact version and the sha256 they independently copied
# from semgrep's own published release notes; this script verifies the
# download against THAT value and refuses to install anything that does not
# match, rather than trusting whatever bytes arrived.
#
# shellcheck shell=bash

# semgrep_vendor - the function tools/vendor-engines.sh's VENG_REGISTRY[semgrep]
# entry calls.  Reads its inputs from the environment rather than argv
# (SCOURSH_SEMGREP_VERSION / SCOURSH_SEMGREP_URL / SCOURSH_SEMGREP_SHA256),
# the same "operator-supplied, not guessed" shape tools/run-in-netns.sh and
# lib/paranoid.sh already use for their own swappable/operator-set values -
# none of these three are secrets (tension 9 does not apply to a public
# release URL or a public checksum), so an env var is the right shape, not
# a violation of "a secret is never a command-line argument".
semgrep_vendor() {
  local version=${SCOURSH_SEMGREP_VERSION:-}
  local url=${SCOURSH_SEMGREP_URL:-}
  local sha256=${SCOURSH_SEMGREP_SHA256:-}
  local rules_url=${SCOURSH_SEMGREP_RULES_URL:-}
  local rules_sha256=${SCOURSH_SEMGREP_RULES_SHA256:-}

  if [[ -z $version || -z $url || -z $sha256 || -z $rules_url || -z $rules_sha256 ]]; then
    log_error 'vendor-engines: semgrep needs SCOURSH_SEMGREP_VERSION, SCOURSH_SEMGREP_URL,'
    log_error '  SCOURSH_SEMGREP_SHA256, SCOURSH_SEMGREP_RULES_URL and SCOURSH_SEMGREP_RULES_SHA256'
    log_error '  all set - copy the version, the platform binary URL, and both sha256 digests'
    log_error '  from semgrep'\''s own published release notes (https://github.com/semgrep/semgrep/releases).'
    log_error '  This script never guesses or hardcodes a checksum (see this file'\''s own header).'
    die "$SCOURSH_EXIT_INPUT" 'semgrep vendoring: required SCOURSH_SEMGREP_* values are not set'
  fi

  local adapter_dir
  adapter_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  local bin_dir=$adapter_dir/bin
  local rules_dir=$adapter_dir/rules
  mkdir -p "$bin_dir" "$rules_dir"

  log_info "vendor-engines: fetching semgrep $version binary"
  veng_fetch "$url" "$bin_dir/semgrep" "$sha256"
  chmod +x "$bin_dir/semgrep"

  log_info 'vendor-engines: fetching semgrep offline ruleset'
  veng_fetch "$rules_url" "$rules_dir/semgrep-rules.yml" "$rules_sha256"

  log_info "vendor-engines: semgrep $version vendored into ${adapter_dir#"$SCOURSH_INSTALL_ROOT"/}"
  log_info '  commit modules/sast/adapters/semgrep/bin and .../rules to git; every real scan'
  log_info '  from here on runs fully offline against exactly these bytes.'
}
