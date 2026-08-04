#!/usr/bin/env bash
# tools/vendor-engines.sh - THE ONLY SCRIPT IN THIS REPOSITORY PERMITTED TO
# TOUCH THE NETWORK.
#
# Owns:
#   docs/DESIGN.md    §9 ("Engine-boosted (opt-in)"), §13 step 9
#   docs/FOUNDATION.md tension 19 ("no bypass" - lists this file as the one
#                      documented exception, alongside lib/http.sh)
#   docs/FOUNDATION.md tension 25 (data/advisories.db pre-expansion - a
#                      SEPARATE responsibility of this same script; see
#                      section 3 below for the boundary this ticket draws)
#   docs/FOUNDATION.md tension 27 (this scaffold's own design decisions)
#   docs/ADAPTERS.md   (the adapter directory convention and interface
#                      contract this script populates on disk)
#
# WHAT THIS IS.  An operator runs this script BY HAND, ONCE, ON A NETWORKED
# BOX, to populate `modules/<module>/adapters/<engine>/bin/` and `.../rules/`
# with a vendored engine binary and its local ruleset (docs/DESIGN.md §9's
# "drop vendored offline engines into adapters/ ... commit the binaries +
# local rule DBs, then the scanner uses them offline forever").  The result
# is committed to git.  From that point on, every real scan runs on an
# air-gapped host and never invokes this script again.
#
# WHAT THIS IS NOT.
#   - It is NEVER called during a scan.  `scan.sh`, every `lib/*.sh`, and
#     every `modules/**/*.sh` file must not source, exec, or otherwise
#     reference this script - tests/lint-shell.sh's "no wiring of
#     tools/vendor-engines.sh into the scan-time dispatch path" check
#     (added by this same ticket) fails the build if any of them do.
#   - It is not an adapter itself, and it never runs a vendored engine
#     against scan targets.  `modules/<module>/adapters/<engine>/adapter.sh`
#     (docs/ADAPTERS.md §5) does that, fully offline, at scan time; this
#     script's only job is getting the binary and ruleset onto disk in the
#     first place.
#   - It is exempt from lib/http.sh's scope-gate chokepoint (tension 19) on
#     purpose: the URLs it fetches are the vendored ENGINE's own upstream
#     release/ruleset location, which has nothing to do with
#     config/scope.conf's authorized SCAN TARGETS.  Routing a `semgrep`
#     release download through the scope gate would be a category error,
#     not an extra safety check - the gate exists to authorize what the
#     scanner is allowed to point ITS SCANS at, and this script never scans
#     anything.
#
# CURRENT SCOPE UPDATE (this ticket, the first concrete adapter): the
# scaffold ticket referenced just above shipped this file with an EMPTY
# registry, exactly as its own "CURRENT SCOPE" paragraph (preserved below
# for history) describes.  This ticket is the "future single-engine-adapter
# ticket" that paragraph anticipates: it adds ONE registry entry
# (`semgrep`, section 2), the `veng_fetch` helper every `vendor.sh` is
# restricted to (section 2a), and `modules/sast/adapters/semgrep/` itself -
# in the SAME change, per that paragraph's own instruction.  This script is
# still not forked per engine: a second adapter ticket adds one more
# registry line and one more fetch function here, not a second dispatcher.
#
# ORIGINAL "CURRENT SCOPE" (this ticket - docs/FOUNDATION.md tension 27's
# "scaffold, not per-engine logic" boundary).  This script ships as a real,
# runnable dispatcher with an EMPTY engine registry (section 2): it has
# structurally correct usage, listing, and error paths, and zero adapters to
# actually vendor, because zero adapters exist anywhere in the repository
# (docs/ADAPTERS.md §1).  A future single-engine-adapter ticket
# (docs/ADAPTERS.md §3) adds its own fetch function here AND its own
# `modules/<module>/adapters/<engine>/` directory in the same change - this
# script is not forked per engine, the same "one file, more registry
# entries" shape modules/sca/run.sh already established for SCA ecosystems.
#
# OUT OF SCOPE (this ticket does not implement this - stated so it is not
# silently dropped).  docs/FOUNDATION.md tension 25 already commits this
# same script to a SECOND, unrelated responsibility: resolving
# data/advisories.db's and data/versions.db's advisory ranges against each
# ecosystem's real published version list and writing one exact-version row
# per affected version.  That "expansion logic" is real, already designed,
# and genuinely belongs in this file per tension 25's own text - but it is
# SCA/advisories work, not an engine adapter, and implementing it needs real
# per-ecosystem tooling (npm, pip, a Maven/Gradle resolver, ...) this ticket
# has no fixture-testable way to exercise offline. It is intentionally not
# started here; a `veng_advisories` command namespace analogous to
# section 2 below is the natural place for it to land, kept separate from
# the adapter registry so the two responsibilities never entangle.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

# A test suite sources this file to reach individual functions (usage text,
# the registry lookup, argument parsing) without running the network-fetch
# path - the same dual-mode idiom tools/run-in-netns.sh and scan.sh use for
# the same reason.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  VENG_MAIN=1
else
  VENG_MAIN=0
fi

VENG_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$VENG_DIR/lib/core.sh"

# ---------------------------------------------------------------------------
# 1. Usage
# ---------------------------------------------------------------------------
veng_usage() {
  cat <<'EOF'
usage: tools/vendor-engines.sh <command>

Populates modules/<module>/adapters/<engine>/bin/ and .../rules/ with a
vendored, offline engine binary and local ruleset (docs/ADAPTERS.md), by
fetching from the network.  Run this BY HAND, ONCE, ON A NETWORKED BOX; the
result is committed to git and every real scan then runs fully offline.

This script is never invoked by scan.sh or by any file under lib/ or
modules/ - see this file's own header for why, and
tests/lint-shell.sh for the check that enforces it.

Commands:
  --list            list every registered engine adapter (currently: none -
                     docs/ADAPTERS.md §1, zero adapters have shipped yet)
  --all             vendor every registered engine adapter (a no-op today,
                     since none are registered)
  <engine>          vendor one registered engine adapter by name
  -h, --help        print this message and exit 0

Every command other than --help fails loudly (see EXIT CODES) rather than
guessing, per docs/FOUNDATION.md tension 14's 0-5 exit contract.

EXIT CODES: 0 ok, 2 bad usage, 4 unknown/unregistered engine or missing
tooling, 5 the fetch itself failed.  Never anything outside 0-5.
EOF
}

# ---------------------------------------------------------------------------
# 2a. veng_fetch - the ONLY function a vendor.sh may use to reach the
#     network (docs/ADAPTERS.md §2; modules/sast/adapters/semgrep/vendor.sh
#     is the first caller).  Downloads URL to DEST and verifies it against
#     an EXPECTED sha256 the caller supplies - never a hardcoded or guessed
#     one (OWASP A08: an unverified artifact is not meaningfully different
#     from an unsigned one; see vendor.sh's own header for the fuller
#     argument).  Refuses to leave a mismatched file in place: DEST is
#     removed on a checksum failure so a partial or wrong download can never
#     be mistaken for a successfully vendored artifact.
# ---------------------------------------------------------------------------
veng_fetch() {
  local url=$1 dest=$2 expected_sha256=$3
  [[ -n $url && -n $dest && -n $expected_sha256 ]] \
    || die "$SCOURSH_EXIT_INPUT" 'veng_fetch: URL, DEST and EXPECTED_SHA256 are all required'
  require_cmd curl
  log_info "vendor-engines: fetching $url"
  curl --fail --location --show-error --silent --output "$dest" -- "$url" \
    || die "$SCOURSH_EXIT_INCOMPLETE" "veng_fetch: download failed: $url"
  local got_sha256
  got_sha256=$(cat -- "$dest" | sha256_of)
  if [[ $got_sha256 != "$expected_sha256" ]]; then
    rm -f "$dest"
    die "$SCOURSH_EXIT_INCOMPLETE" \
      "veng_fetch: checksum mismatch for $url (expected $expected_sha256, got $got_sha256) - refusing to vendor an unverified artifact"
  fi
  log_info "vendor-engines: checksum verified for $(basename -- "$dest")"
}

# ---------------------------------------------------------------------------
# 2. The engine registry
# ---------------------------------------------------------------------------
# Maps a registered engine name to the bash function that vendors it.  A
# concrete adapter ticket adds exactly one line here (and the function it
# names, doing the real fetch-and-verify work) in the SAME change that adds
# its own modules/<module>/adapters/<engine>/ directory - see this file's
# own header, "CURRENT SCOPE", and docs/ADAPTERS.md §3/§9.
#
# Iterating over an associative array is well-defined in bash 4.2+ (the
# frozen minimum, tension 24) and needs no special-casing here, unlike a
# plain positional array under `set -u` (tension 24's empty-array-expansion
# note) - an associative array's `${!VENG_REGISTRY[@]}` on an empty array
# expands to nothing without error, which is exactly what let this script
# ship correct with zero entries before this ticket, and is exactly why a
# new entry needs no companion change to veng_list/veng_vendor_all below.
declare -A VENG_REGISTRY=(
  [semgrep]=veng_vendor_semgrep
)

# veng_vendor_semgrep - the semgrep registry entry.  Delegates to
# modules/sast/adapters/semgrep/vendor.sh's own `semgrep_vendor`, sourced
# HERE rather than at this file's top level, so a `--list`/`--help`
# invocation with no adapter directory on disk yet never fails just to
# populate a registry - the same "load what a command actually needs, when
# it needs it" shape veng_vendor_one already applies to every entry.
veng_vendor_semgrep() {
  local vendor_sh="$VENG_DIR/modules/sast/adapters/semgrep/vendor.sh"
  [[ -f $vendor_sh ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "vendor-engines: $vendor_sh is missing - modules/sast/adapters/semgrep/ should ship it"
  # shellcheck source=modules/sast/adapters/semgrep/vendor.sh
  source "$vendor_sh"
  semgrep_vendor
}

veng_list() {
  if (( ${#VENG_REGISTRY[@]} == 0 )); then
    printf 'no engine adapters registered (docs/ADAPTERS.md %s)\n' \
      'shows zero adapters shipped as of this repository state'
    return 0
  fi
  local name
  for name in "${!VENG_REGISTRY[@]}"; do
    printf '%s\n' "$name"
  done | LC_ALL=C sort
}

veng_vendor_one() {
  local engine=$1
  [[ -n ${VENG_REGISTRY[$engine]:-} ]] \
    || die "$SCOURSH_EXIT_INPUT" \
      "unknown engine '$engine' - none are registered yet (docs/ADAPTERS.md §1); run '--list' to see the current registry"
  log_info "vendor-engines: vendoring '$engine'"
  "${VENG_REGISTRY[$engine]}"
}

veng_vendor_all() {
  if (( ${#VENG_REGISTRY[@]} == 0 )); then
    log_info 'vendor-engines: no engine adapters registered - nothing to vendor'
    return 0
  fi
  local name
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    veng_vendor_one "$name"
  done < <(veng_list)
}

# ---------------------------------------------------------------------------
# 3. Main
# ---------------------------------------------------------------------------
veng_main() {
  (( $# > 0 )) || { veng_usage >&2; die "$SCOURSH_EXIT_USAGE" 'no command given'; }

  case $1 in
    -h | --help)
      veng_usage
      exit "$SCOURSH_EXIT_OK"
      ;;
    --list)
      veng_list
      ;;
    --all)
      veng_vendor_all
      ;;
    --*)
      veng_usage >&2
      die "$SCOURSH_EXIT_USAGE" "unknown flag: '$1'"
      ;;
    *)
      veng_vendor_one "$1"
      ;;
  esac
}

if (( VENG_MAIN )); then
  veng_main "$@"
fi
