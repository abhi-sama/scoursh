#!/usr/bin/env bash
# modules/iac/adapters/trivy/vendor.sh - populates this adapter's own bin/
# (docs/ADAPTERS.md §4) from the network.  UNLIKE
# modules/sast/adapters/semgrep/vendor.sh, there is no rules/ to populate:
# trivy's misconfiguration checks are compiled into the binary itself
# (adapter.sh's own header explains why `trivy config` was chosen over
# `checkov`/`tfsec`), so vendoring this adapter is exactly ONE artifact.
#
# Owns: docs/ADAPTERS.md §2's consequence for adapter code, applied to the
# ONE file per adapter that is an intentional, documented exception to it.
#
# RUN BY tools/vendor-engines.sh ONLY, BY HAND, ON A NETWORKED BOX
# (docs/DESIGN.md §9/§13 step 9; tools/vendor-engines.sh's own header).
# This file is sourced by `veng_vendor_trivy` (tools/vendor-engines.sh's own
# registry entry for `trivy`, added by this ticket) - never by scan.sh,
# never by anything under lib/ or modules/ at scan time.  It is still linted
# like every other file under modules/ (tests/lint-shell.sh's `engine_files`
# glob does not carve out adapters/), so the ONLY function it may use to
# reach the network is `veng_fetch` (exported by tools/vendor-engines.sh,
# the sole exempted "no bypass" caller of curl/wget) - this file itself
# contains no curl/wget/nc/openssl-s_client token, satisfying that check by
# construction rather than by an added exemption.
#
# WHAT THIS DOES NOT DO: guess, hardcode, or "best-effort" a checksum for
# the artifact it fetches - identical policy to
# modules/sast/adapters/semgrep/vendor.sh's own header (OWASP A08:
# software/data integrity failures).  The operator running this BY HAND, ON
# A NETWORKED BOX, supplies the exact platform binary URL and the sha256
# they independently copied from trivy's own published release notes
# (https://github.com/aquasecurity/trivy/releases); this script verifies
# the download against THAT value and refuses to install anything that does
# not match.
#
# A REAL trivy release ships its binary inside a per-platform .tar.gz
# archive, not as a bare executable.  This script deliberately does NOT
# extract one: `veng_fetch` (tools/vendor-engines.sh) downloads and
# checksum-verifies exactly the bytes at SCOURSH_TRIVY_URL and nothing
# else, the same "operator supplies the exact right URL for their platform"
# contract modules/sast/adapters/semgrep/vendor.sh already uses for
# semgrep's own binary.  An operator vendoring the real tool points
# SCOURSH_TRIVY_URL at the already-extracted `trivy` executable (extracted
# and re-hosted, or a direct binary release/build for their platform) and
# supplies ITS sha256, not the surrounding archive's - adding tar
# extraction here would be a second, unverified transformation of the
# fetched bytes between the checksum check and the file this adapter trusts
# as `bin/trivy`, which is exactly the class of gap OWASP A08 warns about.
#
# shellcheck shell=bash

# trivy_vendor - the function tools/vendor-engines.sh's VENG_REGISTRY[trivy]
# entry calls.  Reads its inputs from the environment rather than argv
# (SCOURSH_TRIVY_VERSION / SCOURSH_TRIVY_URL / SCOURSH_TRIVY_SHA256), the
# same "operator-supplied, not guessed" shape
# modules/sast/adapters/semgrep/vendor.sh's own semgrep_vendor already uses
# (none of these three are secrets - tension 9 does not apply to a public
# release URL or a public checksum).
trivy_vendor() {
  local version=${SCOURSH_TRIVY_VERSION:-}
  local url=${SCOURSH_TRIVY_URL:-}
  local sha256=${SCOURSH_TRIVY_SHA256:-}

  if [[ -z $version || -z $url || -z $sha256 ]]; then
    log_error 'vendor-engines: trivy needs SCOURSH_TRIVY_VERSION, SCOURSH_TRIVY_URL and'
    log_error '  SCOURSH_TRIVY_SHA256 all set - copy the version and the platform binary'
    log_error '  URL/sha256 from trivy'\''s own published release notes'
    log_error '  (https://github.com/aquasecurity/trivy/releases).  SCOURSH_TRIVY_URL must'
    log_error '  point at the already-extracted trivy executable, not the surrounding'
    log_error '  .tar.gz release archive - this script never extracts an archive (see this'
    log_error '  file'\''s own header).  This script never guesses or hardcodes a checksum'
    log_error '  (see this file'\''s own header).'
    die "$SCOURSH_EXIT_INPUT" 'trivy vendoring: required SCOURSH_TRIVY_* values are not set'
  fi

  local adapter_dir
  adapter_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  local bin_dir=$adapter_dir/bin
  mkdir -p "$bin_dir"

  log_info "vendor-engines: fetching trivy $version binary"
  veng_fetch "$url" "$bin_dir/trivy" "$sha256"
  chmod +x "$bin_dir/trivy"

  log_info "vendor-engines: trivy $version vendored into ${adapter_dir#"$SCOURSH_INSTALL_ROOT"/}"
  log_info '  commit modules/iac/adapters/trivy/bin to git; every real scan from here'
  log_info '  on runs fully offline against exactly these bytes.  No rules/ directory'
  log_info '  is vendored - trivy'\''s misconfiguration checks are compiled into the'
  log_info '  binary itself.'
}
