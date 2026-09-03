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
# is committed to git.  From that point on, every real scan of source,
# dependencies, or IaC (scoursh is egress-restricted, not air-gapped -
# docs/FOUNDATION.md tension 28 - but those three modules make zero network
# calls of their own) needs no network access and never invokes this script
# again.
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
# CURRENT SCOPE UPDATE (the first concrete adapter ticket, semgrep): the
# scaffold ticket referenced just above shipped this file with an EMPTY
# registry, exactly as its own "CURRENT SCOPE" paragraph (preserved below
# for history) describes.  That ticket was the "future single-engine-adapter
# ticket" this paragraph anticipates: it added ONE registry entry
# (`semgrep`, section 2), the `veng_fetch` helper every `vendor.sh` is
# restricted to (section 2a), and `modules/sast/adapters/semgrep/` itself -
# in the SAME change, per that paragraph's own instruction.
#
# CURRENT SCOPE UPDATE (this ticket, the second concrete adapter, and the
# first for a module other than sast): adds a SECOND registry entry
# (`trivy` -> `veng_vendor_trivy`, section 2) and `modules/iac/adapters/trivy/`
# itself, in the SAME change, proving the "one more registry line and one
# more fetch function, not a second dispatcher" claim below for real rather
# than leaving it a prediction about a hypothetical future ticket.
# `veng_fetch` (section 2a) is reused completely unchanged.
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
# CURRENT SCOPE UPDATE (this ticket - the SECOND responsibility, previously
# out of scope, is now implemented): docs/FOUNDATION.md tension 25 commits
# this script to resolving data/advisories.db's and data/versions.db's
# advisory ranges against each ecosystem's real published version list and
# writing one exact-version row per affected version.  This ticket adds
# that as `veng_advisories` (section 3 below) - a command namespace kept
# COMPLETELY SEPARATE from section 2's VENG_REGISTRY/veng_vendor_one/
# veng_vendor_all/veng_list, its own associative array
# (VENG_ADVISORY_REGISTRY), and its own dispatch branch in veng_main, so
# the two responsibilities never share a code path.  It covers all six
# docs/DESIGN.md §6.5 ecosystems (npm, PyPI, Maven, Go, RubyGems,
# Composer), resolves each via OSV.dev (the real, cross-ecosystem
# vulnerability database `govulncheck`/`pip-audit`/`osv-scanner` are
# themselves built on - a single consistent API rather than six bespoke
# integrations), and never guesses or hardcodes which advisory to resolve:
# every id comes from an operator-supplied `SCOURSH_ADVISORY_<ECOSYSTEM>_IDS`
# env var, the identical "operator supplies the fact, this script only
# fetches/transforms it" discipline modules/sast/adapters/semgrep/vendor.sh's
# own header already committed this file to (see AGENTS.md's own history of
# invented-fact incidents for why that discipline exists).  See section 3's
# own header comment for the JSON-parsing and name-normalisation design.
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
  --list            list every registered engine adapter
  --all             vendor every registered engine adapter
  <engine>          vendor one registered engine adapter by name
  advisories ...    resolve SCA advisory data into data/advisories.db and
                     data/versions.db (docs/FOUNDATION.md tension 25) - a
                     SEPARATE command namespace, never an <engine> name; run
                     'advisories --help' for its own usage.  'advisories
                     bulk <ecosystem>' imports a whole ecosystem at once and
                     is the command that populates a usable database.
  -h, --help        print this message and exit 0

Every command other than --help fails loudly (see EXIT CODES) rather than
guessing, per docs/FOUNDATION.md tension 14's 0-5 exit contract.

EXIT CODES: 0 ok, 2 bad usage, 4 unknown/unregistered engine or ecosystem, or
missing tooling/input, 5 the fetch itself failed.  Never anything outside 0-5.
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
  [trivy]=veng_vendor_trivy
  [gitleaks]=veng_vendor_gitleaks
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

# veng_vendor_trivy - the trivy registry entry (the second concrete
# adapter, the first for a module other than sast).  Delegates to
# modules/iac/adapters/trivy/vendor.sh's own `trivy_vendor`, loaded lazily
# for the identical reason veng_vendor_semgrep loads its own vendor.sh
# lazily above.
veng_vendor_trivy() {
  local vendor_sh="$VENG_DIR/modules/iac/adapters/trivy/vendor.sh"
  [[ -f $vendor_sh ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "vendor-engines: $vendor_sh is missing - modules/iac/adapters/trivy/ should ship it"
  # shellcheck source=modules/iac/adapters/trivy/vendor.sh
  source "$vendor_sh"
  trivy_vendor
}

# veng_vendor_gitleaks - the gitleaks registry entry (this ticket, the
# third concrete adapter).  Delegates to
# modules/sast/adapters/gitleaks/vendor.sh's own `gitleaks_vendor`, loaded
# the identical lazy, per-invocation way veng_vendor_semgrep already does.
veng_vendor_gitleaks() {
  local vendor_sh="$VENG_DIR/modules/sast/adapters/gitleaks/vendor.sh"
  [[ -f $vendor_sh ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "vendor-engines: $vendor_sh is missing - modules/sast/adapters/gitleaks/ should ship it"
  # shellcheck source=modules/sast/adapters/gitleaks/vendor.sh
  source "$vendor_sh"
  gitleaks_vendor
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
# 3. Advisory/version-range expansion (docs/FOUNDATION.md tension 25) - a
#    SECOND, UNRELATED responsibility this script owns (this file's own
#    header, "CURRENT SCOPE UPDATE (this ticket ...)").  Resolves each
#    ecosystem's real advisory data into pre-expanded, exact-version rows
#    for data/advisories.db and data/versions.db (tension 25's frozen TSV
#    schema: `ecosystem\tpackage\tversion\tadvisory_id\tseverity\t
#    fixed_versions\tsummary`, sorted under LC_ALL=C), so the scanner's own
#    SCA matching step (modules/sca/), which makes zero network calls of its
#    own, stays an exact string lookup with no version algebra of its own.
#
#    KEPT COMPLETELY SEPARATE from section 2 above: a different associative
#    array (VENG_ADVISORY_REGISTRY, not VENG_REGISTRY), a different set of
#    functions (veng_advisories_*, never veng_vendor_one/veng_vendor_all/
#    veng_list), and its own `advisories` branch in veng_main below - so
#    adapter vendoring and advisory expansion never share a code path, and
#    an `advisories` argument can never be misread as an <engine> name (or
#    vice versa).
#
#    REAL ECOSYSTEM TOOLING USED: OSV.dev (https://osv.dev), the
#    cross-ecosystem, open-source vulnerability database that aggregates
#    GHSA (npm, Maven, RubyGems, Composer/Packagist), PYSEC (PyPI) and the
#    Go vulnerability database - the same data `govulncheck`/`pip-audit`/
#    `osv-scanner` are themselves built on.  Crucially, OSV's schema
#    already carries a per-advisory `affected[].versions` array - the
#    EXACT, ecosystem-tool-computed version enumeration tension 25 asks
#    for - so this script performs no range arithmetic of its own; it
#    only fetches and reshapes what OSV already resolved.  An advisory
#    entry with no explicit `versions` array (a range-only entry, common
#    on ecosystems OSV cannot fully enumerate) is skipped with a logged
#    reason rather than guessed at, the same "stated, not hidden" cost
#    discipline docs/FOUNDATION.md already uses throughout (e.g.
#    modules/sca/go_engine.sh's `replace`/`exclude` gap).
#
#    ADVISORY IDS ARE ALWAYS OPERATOR-SUPPLIED, never guessed or hardcoded
#    (SCOURSH_ADVISORY_<ECOSYSTEM>_IDS, comma/space-separated OSV ids) -
#    the identical discipline modules/sast/adapters/semgrep/vendor.sh's own
#    header already commits this file to for a release URL/checksum, and
#    for the same reason (AGENTS.md's own history of invented, unverifiable
#    facts shipping into this repository).
#
#    JSON PARSING: OSV's response is the one place this script reaches for
#    `python3`'s stdlib `json` module rather than a hand-rolled bash/grep
#    JSON parser.  This mirrors tension 25's own argument one level up: a
#    hand-rolled parser here is exactly the "large amount of code whose
#    bugs are invisible" tension 25 rejects for version algebra.  This
#    script already runs on a networked, operator-controlled box with real
#    tooling (curl, npm, pip, ...) - python3 is near-universal on such a
#    box - and is used NOWHERE in the egress-restricted scan-time path;
#    tests/lint-shell.sh's dispatch-wiring check (tension 27) still covers
#    this file unchanged.
#
#    NAME NORMALISATION reuses modules/sca/engine.sh's, php_engine.sh's and
#    go_engine.sh's own `sca_*_normalize_name`/`sca_go_normalize_version`
#    functions verbatim (lazily sourced by
#    _veng_advisories_load_normalizers below, never re-implemented here) -
#    the writer and the reader of data/advisories.db MUST apply byte-
#    identical normalisation (tension 25: "an exact lookup is only as good
#    as its key"), and a second implementation here would be exactly the
#    "ad hoc parser, subtly different" drift docs/FOUNDATION.md tension 24
#    already warns about for a different capability.
# ---------------------------------------------------------------------------

VENG_ADVISORIES_DB=${SCOURSH_SCA_ADVISORIES_DB:-$VENG_DIR/data/advisories.db}
VENG_VERSIONS_DB=${SCOURSH_SCA_VERSIONS_DB:-$VENG_DIR/data/versions.db}

# The six docs/DESIGN.md §6.5 ecosystems, keyed by the SAME literal
# ecosystem string modules/sca/*.sh's own `sca_lookup_exact`/
# `sca_package_known` call sites already use (verified against those call
# sites directly, not re-derived): npm, pypi, maven, Go, RubyGems, composer.
declare -A VENG_ADVISORY_REGISTRY=(
  [npm]=veng_advisories_npm
  [pypi]=veng_advisories_pypi
  [maven]=veng_advisories_maven
  [Go]=veng_advisories_go
  [RubyGems]=veng_advisories_rubygems
  [composer]=veng_advisories_composer
)

veng_advisories_usage() {
  cat <<'EOF'
usage: tools/vendor-engines.sh advisories <command>

Resolves real SCA advisory data (docs/DESIGN.md §6.5's six ecosystems) via
OSV.dev (https://osv.dev) into pre-expanded, exact-version rows for
data/advisories.db and data/versions.db (docs/FOUNDATION.md tension 25's
frozen TSV schema) - and, separately, data/versions.db's OWN `banner`
namespace (docs/VERSIONS-DB.md §3-§5), the known-vulnerable-version catalogue
modules/dast/passive/banner.sh reads for a banner-matched product with no
SCA-ecosystem manifest at all (a bare web server, a TLS library, a CMS).  Run
this BY HAND, ON A NETWORKED BOX, the same as every other command this script
provides - see this file's own header.

A SEPARATE command namespace from --list/--all/<engine> above: it never
touches VENG_REGISTRY, and an ecosystem name here is never mistaken for a
registered engine adapter name, or vice versa.

Commands:
  --list              list the six supported SCA ecosystems (never includes
                       'banner' - see below)
  --all               expand every SCA ecosystem (each one's own
                       SCOURSH_ADVISORY_<ECOSYSTEM>_IDS must be set)
  <ecosystem>          expand one SCA ecosystem (npm, pypi, maven, Go,
                       RubyGems, composer)
  banner              expand data/versions.db's own 'banner' namespace from
                       SCOURSH_ADVISORY_BANNER_IDS - the docs/VERSIONS-DB.md
                       §5 importer.  Writes data/versions.db only, never
                       data/advisories.db, and is deliberately not part of
                       --list/--all/'bulk --all' (see veng_advisories_banner's
                       own header for why).
  bulk ...            import a WHOLE SCA ecosystem's published OSV.dev export
                       in one command, instead of naming advisory ids one at a
                       time; run 'advisories bulk --help' for its own usage,
                       including how artifact integrity is handled.  This is
                       the command that populates a usable database.  Scoped
                       to the six SCA ecosystems; 'banner' has no bulk path.
  -h, --help          print this message and exit 0

Every SCA ecosystem reads its advisory ids from an operator-supplied env var -
SCOURSH_ADVISORY_NPM_IDS, SCOURSH_ADVISORY_PYPI_IDS,
SCOURSH_ADVISORY_MAVEN_IDS, SCOURSH_ADVISORY_GO_IDS,
SCOURSH_ADVISORY_RUBYGEMS_IDS, SCOURSH_ADVISORY_COMPOSER_IDS - and 'banner'
reads SCOURSH_ADVISORY_BANNER_IDS, the identical shape.  Each is a
comma/space-separated list of real OSV.dev advisory ids (e.g.
"GHSA-xxxx-xxxx-xxxx", "CVE-2021-41773") the operator identified from that
ecosystem's (or product's) own advisory source.  This script never guesses or
hardcodes which advisory to resolve (see this file's own header).

EXIT CODES: 0 ok, 2 bad usage, 4 unknown ecosystem or missing ids/tooling,
5 the fetch itself failed.  Never anything outside 0-5.
EOF
}

_VENG_ADVISORIES_NORMALIZERS_LOADED=0

# _veng_advisories_load_normalizers - lazily sources the three SCA engine
# files that own the frozen per-ecosystem name normalisation (see this
# section's own header), so a plain `advisories --list`/`--help` never
# pays that cost or fails just because modules/sca/ is absent - the same
# "load what a command actually needs, when it needs it" shape
# veng_vendor_semgrep already applies to its own vendor.sh.
_veng_advisories_load_normalizers() {
  (( _VENG_ADVISORIES_NORMALIZERS_LOADED )) && return 0
  local f
  for f in modules/sca/engine.sh modules/sca/php_engine.sh modules/sca/go_engine.sh; do
    [[ -f "$VENG_DIR/$f" ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
      "vendor-engines: advisories: $VENG_DIR/$f is missing - modules/sca/ should ship it"
    # shellcheck disable=SC1090
    source "$VENG_DIR/$f"
  done
  _VENG_ADVISORIES_NORMALIZERS_LOADED=1
}

_VENG_ADVISORIES_BANNER_NORMALIZER_LOADED=0

# _veng_advisories_load_banner_normalizer - lazily sources
# modules/dast/passive/banner_engine.sh for `banner_normalize_product`, the
# ONE frozen data/versions.db `banner`-namespace product-key rule
# (docs/VERSIONS-DB.md §4).  Kept as its own loader, separate from
# _veng_advisories_load_normalizers above: the banner catalogue is a
# different namespace with a different frozen function in a different
# module, and a plain `advisories --list`/`--help` (or a run that only
# touches the six SCA ecosystems) must not source modules/dast/ or pay that
# cost.  banner_engine.sh's own sourced-once guard makes this idempotent
# with a real `scan.sh dast` process too, on the rare box that runs both.
_veng_advisories_load_banner_normalizer() {
  (( _VENG_ADVISORIES_BANNER_NORMALIZER_LOADED )) && return 0
  local f=modules/dast/passive/banner_engine.sh
  [[ -f "$VENG_DIR/$f" ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "vendor-engines: advisories: $VENG_DIR/$f is missing - modules/dast/ should ship it"
  # shellcheck disable=SC1090
  source "$VENG_DIR/$f"
  _VENG_ADVISORIES_BANNER_NORMALIZER_LOADED=1
}

# _veng_advisories_osv_ecosystem DB_ECOSYSTEM - this project's own frozen
# ecosystem string (as used in data/advisories.db and by
# sca_lookup_exact/sca_package_known) -> OSV.dev's own `affected[].
# package.ecosystem` string for the same ecosystem.  The two vocabularies
# differ in exactly two spots (PyPI, Composer/Packagist); both sides are
# named explicitly here rather than assumed identical.
#
# `banner` (docs/VERSIONS-DB.md's OTHER data/versions.db namespace, never
# one of the six docs/DESIGN.md §6.5 SCA ecosystems above) maps to the
# sentinel `*`: a banner-matched product - a bare web server, a TLS
# library, a CMS with no SCA-ecosystem manifest at all - has no single OSV
# ecosystem string to filter `affected[].package.ecosystem` against the way
# an npm or PyPI advisory does, so `_veng_advisories_osv_extract_py`'s one
# record walk (section 3) reads `*` as "match every affected[] entry that
# names a package, regardless of ecosystem" rather than adding a second
# extractor.
_veng_advisories_osv_ecosystem() {
  case $1 in
    npm) printf 'npm' ;;
    pypi) printf 'PyPI' ;;
    maven) printf 'Maven' ;;
    Go) printf 'Go' ;;
    RubyGems) printf 'RubyGems' ;;
    composer) printf 'Packagist' ;;
    banner) printf '*' ;;
    *) die "$SCOURSH_EXIT_INPUT" "advisories: unknown ecosystem '$1'" ;;
  esac
}

# _veng_advisories_env_var DB_ECOSYSTEM - the operator-supplied advisory-id
# env var name for this ecosystem (see veng_advisories_usage above).
# `banner` mirrors the same SCOURSH_ADVISORY_<NAME>_IDS shape as the six SCA
# ecosystems, per docs/VERSIONS-DB.md §5's importer requirement.
_veng_advisories_env_var() {
  case $1 in
    npm) printf 'SCOURSH_ADVISORY_NPM_IDS' ;;
    pypi) printf 'SCOURSH_ADVISORY_PYPI_IDS' ;;
    maven) printf 'SCOURSH_ADVISORY_MAVEN_IDS' ;;
    Go) printf 'SCOURSH_ADVISORY_GO_IDS' ;;
    RubyGems) printf 'SCOURSH_ADVISORY_RUBYGEMS_IDS' ;;
    composer) printf 'SCOURSH_ADVISORY_COMPOSER_IDS' ;;
    banner) printf 'SCOURSH_ADVISORY_BANNER_IDS' ;;
    *) die "$SCOURSH_EXIT_INPUT" "advisories: unknown ecosystem '$1'" ;;
  esac
}

# _veng_advisories_normalize_name DB_ECOSYSTEM RAW_NAME - dispatches to the
# frozen sca_*_normalize_name function for this ecosystem (this section's
# own header explains why these are reused, never re-implemented).  Maven's
# OSV package name already arrives as "groupId:artifactId"; it is split
# once here so sca_maven_normalize_name (the single frozen join point,
# modules/sca/engine.sh) still owns the actual join.
#
# `banner` dispatches to `banner_normalize_product`
# (modules/dast/passive/banner_engine.sh), the ONE frozen product-key rule
# docs/VERSIONS-DB.md §4 defines and modules/dast/passive/banner.sh reads
# with - never re-implemented here, for the identical writer/reader-drift
# reason the six sca_*_normalize_name calls above are reused verbatim.
_veng_advisories_normalize_name() {
  local db_eco=$1 raw=$2
  case $db_eco in
    npm) sca_npm_normalize_name "$raw" ;;
    pypi) sca_pypi_normalize_name "$raw" ;;
    RubyGems) sca_ruby_normalize_name "$raw" ;;
    composer) sca_composer_normalize_name "$raw" ;;
    maven)
      local group=${raw%%:*} artifact=${raw#*:}
      sca_maven_normalize_name "$group" "$artifact"
      ;;
    Go) sca_go_normalize_module "$raw" ;;
    banner)
      _veng_advisories_load_banner_normalizer
      banner_normalize_product "$raw"
      ;;
    *) die "$SCOURSH_EXIT_INPUT" "advisories: unknown ecosystem '$db_eco'" ;;
  esac
}

# _veng_advisories_normalize_version DB_ECOSYSTEM RAW_VERSION - only Go's
# frozen rule strips anything (a trailing "+incompatible"); every other
# ecosystem's version is carried through verbatim, matching tension 25's
# own per-ecosystem table.
_veng_advisories_normalize_version() {
  local db_eco=$1 raw=$2
  case $db_eco in
    Go) sca_go_normalize_version "$raw" ;;
    *) printf '%s' "$raw" ;;
  esac
}

# _veng_advisories_normalize_severity RAW [DEFAULT] - maps OSV's own
# severity vocabulary (GHSA-backed sources use CRITICAL/HIGH/MODERATE/LOW;
# PYSEC and the Go database frequently supply none at all, relying on a CVSS
# vector this script does not attempt to score - a stated, not hidden,
# limitation) onto this project's frozen five-word rubric (lib/records.sh
# severity_rank/severity_name: info/low/medium/high/critical).  Empty or
# unrecognised input maps to DEFAULT, which is "medium" unless the caller
# names another - a deliberately conservative fallback rather than silently
# dropping the row (an absent severity is not evidence of low risk).
#
# DEFAULT exists because the fallback itself is per-namespace, not global:
# docs/VERSIONS-DB.md §3 freezes the `banner` row's own default at "high"
# ("a row with none lands on high"), distinct from data/advisories.db's SCA
# rows - veng_advisories_banner passes "high" explicitly; every SCA
# ecosystem call site leaves DEFAULT unset and keeps "medium".
_veng_advisories_normalize_severity() {
  local raw=${1^^} default=${2:-medium}
  case $raw in
    CRITICAL) printf 'critical' ;;
    HIGH) printf 'high' ;;
    MODERATE | MEDIUM) printf 'medium' ;;
    LOW) printf 'low' ;;
    *) printf '%s' "$default" ;;
  esac
}

# _veng_advisories_reject_tab_lf FIELD_NAME VALUE - the frozen
# data/advisories.db schema (tension 25) forbids a TAB or an LF inside any
# field; OSV's own text fields are untrusted target-adjacent content (the
# same "evidence is untrusted" posture docs/FOUNDATION.md already takes
# elsewhere), so this fails loudly rather than silently writing a
# corrupted, field-shifted row.
_veng_advisories_reject_tab_lf() {
  local field=$1 value=$2
  [[ $value != *$'\t'* && $value != *$'\n'* ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "advisories: $field contains a TAB or LF byte - refusing to write a corrupt data/advisories.db row (tension 25's frozen schema forbids this)"
}

# _veng_advisories_osv_fetch OSV_ID OUTFILE - the ONE network call this
# section makes: a plain, unauthenticated GET against OSV.dev's public
# vulnerability-by-id endpoint.  Uses curl directly (this file is one of
# the two tension-19 "no bypass" exemptions - see this file's own header
# and tests/lint-shell.sh) rather than veng_fetch, which is a
# download-and-verify-a-BINARY primitive (an expected sha256 makes no
# sense for volatile, non-integrity-critical advisory JSON).
_veng_advisories_osv_fetch() {
  local id=$1 outfile=$2
  require_cmd curl
  log_info "vendor-engines: advisories: fetching $id from OSV.dev"
  curl --fail --location --show-error --silent \
    --output "$outfile" -- "https://api.osv.dev/v1/vulns/$id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" "advisories: fetch failed for '$id'"
}

# _veng_advisories_osv_extract JSONFILE OSV_ECOSYSTEM - prints one raw,
# UNNORMALISED line per exact affected version this advisory names for
# OSV_ECOSYSTEM: name<US>version<US>advisory_id<US>severity<US>
# fixed_versions<US>summary, where <US> is 0x1f (ASCII unit separator),
# NEVER a TAB.  An `affected` entry naming a different ecosystem is
# skipped; one naming this ecosystem but carrying no explicit `versions`
# array (range-only) is skipped too - both silently as far as this
# function is concerned, but the caller (_veng_advisories_expand_one) logs
# a per-advisory count so a zero-row expansion is never invisible.
#
# A THIN WRAPPER over _veng_advisories_osv_extract_py (section 3a), which
# owns the single copy of the OSV record walk.  The bulk importer reads the
# SAME records out of an archive rather than one file at a time, and a
# second walk written for it would be writer-versus-writer drift of exactly
# the kind this section's own header already refuses for normalisation.
#
# WHY 0x1f AND NOT A TAB (measured, not assumed, tension 25's own
# `_sca_emit_finding` comment in modules/sca/engine.sh already documents
# the general form of this bug): a `name`/`summary`/`fixed_versions` field
# straight out of OSV is UNTRUSTED target-adjacent content and may itself
# contain a literal TAB or LF (this suite's own
# SCOURSH-FIXTURE-OSV-NPM-POISON.json fixture proves it with a poisoned
# `fixed` event) - exactly the byte
# _veng_advisories_reject_tab_lf exists to catch and refuse.  If the
# inter-process transport between this python process and the bash caller
# ALSO used a TAB as the field separator, a genuinely embedded TAB inside
# one field would be indistinguishable from a real field boundary by the
# time bash re-splits the line, and the guard would never see the byte it
# is supposed to catch - the value would already have been silently
# torn apart first.  0x1f is neither IFS whitespace (so an empty field
# between two 0x1f bytes does not collapse under `read`, the same
# "translate to \x1f first" fix `_sca_emit_finding` already applies) nor a
# byte real advisory prose is expected to contain.
_veng_advisories_osv_extract() {
  local jsonfile=$1 osv_ecosystem=$2
  _veng_advisories_osv_extract_py file "$jsonfile" "$osv_ecosystem" ''
}

# _veng_advisories_osv_extract_py MODE INPUT OSV_ECOSYSTEM STATSFILE - the
# ONE OSV record walk in this file.  MODE is `file` (INPUT is a single
# advisory's JSON, the single-advisory path above) or `archive` (INPUT is an
# OSV bulk export zip, section 3a below); the per-record logic either mode
# applies is identical by construction, because there is only one copy of
# it.  STATSFILE, when non-empty, receives `key=value` counters the caller
# reports to the operator; the row format on stdout is the same in both
# modes.
#
# ARCHIVE MODE'S REFUSALS, and what each one actually proves:
#   - `zipfile.ZipFile()` failing means the artifact is not a zip, or is
#     TRUNCATED: a zip's central directory sits at the END of the file, so a
#     short or interrupted transfer cannot be opened at all.  That is a real
#     structural guarantee against silent truncation, and it is not a
#     guarantee about authorship - see section 3a's integrity note.
#   - `ZipFile.read()` verifies each member's stored CRC32, so a corrupted
#     member is refused rather than parsed.
#   - a member that is not valid JSON, or that carries no advisory id, fails
#     the WHOLE import.  Skipping it and importing the rest would produce a
#     database that silently covers less than it claims, which is the exact
#     failure mode this data exists to prevent.
#   - members are never extracted to disk, and a traversing member name is
#     refused anyway rather than relying on that fact staying true.
# Progress is printed to stderr as members are read, so a full ecosystem
# (tens of thousands of advisories) never looks hung.
_veng_advisories_osv_extract_py() {
  local mode=$1 input=$2 osv_ecosystem=$3 statsfile=$4
  require_cmd python3
  python3 - "$mode" "$input" "$osv_ecosystem" "$statsfile" <<'PY'
import json
import sys
import zipfile

mode, path, eco, stats_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
US = "\x1f"

STATS = {
    "advisories_read": 0,
    "rows_extracted": 0,
    "range_only_skipped": 0,
    "versioned_entries": 0,
    "other_ecosystem_skipped": 0,
}


def fail(msg):
    sys.stderr.write("advisories: extract: " + msg + "\n")
    sys.exit(1)


def clean(s):
    # Collapses embedded tabs/newlines/runs of whitespace to a single
    # space - the frozen schema forbids a raw TAB or LF inside a field
    # (tension 25).  Applied to every field EXCEPT fixed_versions (see
    # below): the bash caller re-validates all of them rather than
    # trusting this alone.
    return " ".join(str(s).split())


def rows_for(data):
    vuln_id = clean(data.get("id", "") or "")

    summary = data.get("summary") or ""
    if not summary:
        details = data.get("details") or ""
        summary = details.splitlines()[0] if details else ""
    summary = clean(summary)

    top_severity = ""
    ds = data.get("database_specific") or {}
    if isinstance(ds, dict):
        top_severity = ds.get("severity") or ""

    out = []
    for affected in data.get("affected", []) or []:
        pkg = affected.get("package") or {}
        # eco == "*" is the banner-namespace sentinel
        # (_veng_advisories_osv_ecosystem's own "banner" case): a
        # banner-matched product has no single OSV ecosystem string to
        # filter on the way an npm/PyPI/... advisory does, so every
        # affected[] entry that names a package is taken regardless of its
        # own ecosystem field.
        if eco != "*" and pkg.get("ecosystem") != eco:
            STATS["other_ecosystem_skipped"] += 1
            continue
        name = clean(pkg.get("name") or "")
        if not name:
            continue

        severity = top_severity
        if not severity:
            ads = affected.get("database_specific") or {}
            if isinstance(ads, dict):
                severity = ads.get("severity") or ""

        fixed = []
        for rng in affected.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                f = ev.get("fixed")
                if f and f not in fixed:
                    fixed.append(f)
        # NOT cleaned: tension 25 states fixed_versions is "carried as
        # opaque display text and never compared" - a raw TAB/LF smuggled
        # inside one of OSV's own `fixed` event strings must reach the bash
        # caller's own guard intact so it can be refused, rather than being
        # silently normalised away here first.
        fixed_str = ",".join(fixed)

        versions = affected.get("versions") or []
        if not versions:
            # A range-only entry.  tension 25 puts range arithmetic on the
            # networked box using the ECOSYSTEM's own resolved version
            # list, never on a guess made here, so this is counted and
            # reported rather than approximated.
            STATS["range_only_skipped"] += 1
            continue
        # Counted in the same unit as range_only_skipped (per affected
        # PACKAGE entry, not per advisory and not per row): one advisory
        # can list many affected packages, and one package can list many
        # exact versions, so neither range_only_skipped nor rows_extracted
        # is a sound denominator for "what fraction of this ecosystem's
        # advisories are missing" on its own, so this is counted separately -
        # the bash caller can then report an honest coverage percentage
        # instead of one that can exceed 100%.
        STATS["versioned_entries"] += 1
        for version in versions:
            v = clean(version)
            if not v:
                continue
            out.append(
                US.join([name, v, vuln_id, clean(severity), fixed_str, summary])
            )
    return out


def emit(data):
    STATS["advisories_read"] += 1
    for row in rows_for(data):
        print(row)
        STATS["rows_extracted"] += 1


if mode == "file":
    with open(path, "r", encoding="utf-8") as fh:
        emit(json.load(fh))
elif mode == "archive":
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        fail(
            "archive is unreadable, not a zip, or truncated (%s): %s"
            % (type(exc).__name__, path)
        )
    with zf:
        names = sorted(n for n in zf.namelist() if n.endswith(".json"))
        if not names:
            fail("archive holds no .json advisory member at all: " + path)
        total = len(names)
        sys.stderr.write(
            "advisories: bulk: archive holds %d advisory member(s)\n" % total
        )
        sys.stderr.flush()
        done = 0
        for name in names:
            if name.startswith("/") or ".." in name.split("/"):
                fail("refusing an archive member with a traversing name: " + name)
            try:
                raw = zf.read(name)
            except Exception as exc:
                fail(
                    "member failed its stored CRC or could not be read (%s): %s"
                    % (type(exc).__name__, name)
                )
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                fail(
                    "member is not valid OSV JSON (%s): %s"
                    % (type(exc).__name__, name)
                )
            if not isinstance(data, dict) or not (data.get("id") or ""):
                fail("member carries no advisory id: " + name)
            emit(data)
            done += 1
            if done % 2000 == 0 or done == total:
                sys.stderr.write(
                    "advisories: bulk: %d/%d advisories read\n" % (done, total)
                )
                sys.stderr.flush()
else:
    fail("unknown extract mode: " + mode)

if stats_path:
    with open(stats_path, "w", encoding="utf-8") as fh:
        for key in sorted(STATS):
            fh.write("%s=%d\n" % (key, STATS[key]))
PY
}

# _veng_advisories_expand_one DB_ECOSYSTEM OSV_ID OUTFILE - fetches one
# advisory, extracts and normalises every exact-version row it names for
# DB_ECOSYSTEM, and appends each as a frozen-schema TSV line (still missing
# the leading ecosystem field - the caller's merge step adds that once,
# per output row, rather than threading it through every helper) to
# OUTFILE.
_veng_advisories_expand_one() {
  local db_eco=$1 osv_id=$2 outfile=$3
  local osv_eco raw_json
  osv_eco=$(_veng_advisories_osv_ecosystem "$db_eco")
  raw_json=$SCOURSH_SCRATCH/advisories/${osv_id//\//_}.json
  mkdir -p "$(dirname -- "$raw_json")"
  _veng_advisories_osv_fetch "$osv_id" "$raw_json"

  local name version advisory_id severity fixed summary
  local norm_name norm_version norm_sev
  local emitted=0 raw_line
  while IFS= read -r raw_line || [[ -n $raw_line ]]; do
    [[ -n $raw_line ]] || continue
    # Split on 0x1f, never a TAB - see _veng_advisories_osv_extract's own
    # header for why (both the empty-field `read` collapse bug
    # _sca_emit_finding already documents, and so a genuinely embedded
    # TAB/LF inside a field survives to reach
    # _veng_advisories_reject_tab_lf below intact).
    IFS=$'\x1f' read -r name version advisory_id severity fixed summary <<<"$raw_line"
    [[ -n $name ]] || continue
    norm_name=$(_veng_advisories_normalize_name "$db_eco" "$name")
    norm_version=$(_veng_advisories_normalize_version "$db_eco" "$version")
    if [[ $db_eco == banner ]]; then
      # docs/VERSIONS-DB.md §3's own frozen default for this namespace.
      norm_sev=$(_veng_advisories_normalize_severity "$severity" high)
    else
      norm_sev=$(_veng_advisories_normalize_severity "$severity")
    fi
    _veng_advisories_reject_tab_lf package "$norm_name"
    _veng_advisories_reject_tab_lf version "$norm_version"
    _veng_advisories_reject_tab_lf advisory_id "$advisory_id"
    _veng_advisories_reject_tab_lf fixed_versions "$fixed"
    _veng_advisories_reject_tab_lf summary "$summary"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$db_eco" "$norm_name" "$norm_version" "$advisory_id" "$norm_sev" "$fixed" "$summary" \
      >>"$outfile"
    emitted=$(( emitted + 1 ))
  done < <(_veng_advisories_osv_extract "$raw_json" "$osv_eco")

  if (( emitted == 0 )); then
    log_warn "vendor-engines: advisories: $osv_id produced no $db_eco row(s) - no matching-ecosystem 'affected' entry, or no explicit affected-version list published (tension 25 requires exact versions, never a guessed range)"
  else
    log_info "vendor-engines: advisories: $osv_id -> $emitted $db_eco row(s)"
  fi
}

# _veng_advisories_write_db DB DB_ECOSYSTEM NEW_ROWS [PROVENANCE] - replaces
# every existing DB_ECOSYSTEM row in DB with the rows in NEW_ROWS, leaving
# every OTHER ecosystem's rows untouched, then rewrites DB sorted under
# LC_ALL=C with a fresh `#` header (tension 25: "sorted... under LC_ALL=C,
# with a `#` header line" - db_lookup_exact's own `look`/`grep -F` lookup,
# lib/core.sh, requires the file sorted; a leading `#` byte (0x23) sorts
# before every real ecosystem's first letter under LC_ALL=C, so a header
# line never disturbs that requirement, the same shape
# tests/fixtures/sca/advisories.db already uses).
#
# THE ONE WRITER for both the single-advisory path and the bulk importer
# (section 3a), so the two can never diverge on schema, sort order or header
# shape.  Filtering moved from a `while read` bash loop to a single `awk`
# pass when the bulk path landed: the bash loop was O(rows) SHELL
# iterations, which is fine for a handful of hand-listed advisories and
# unusable for a real ecosystem's hundreds of thousands.  It is still not
# `grep` (tension 4 rule 2's "no bare grep/rg outside the wrapper"), and awk
# is already this repository's field-splitting tool of choice elsewhere.
# `sort` is given TMPDIR inside the scratch directory so a full-ecosystem
# external sort spills where the run's own cleanup can reach it.
#
# PROVENANCE, when supplied, is a single `# bulk: ecosystem=<eco> ...`
# comment line recording where this ecosystem's rows came from and what was
# verified about them.  Other ecosystems' provenance lines are carried
# forward unchanged; THIS ecosystem's previous line is always dropped,
# whether or not a replacement is supplied, because a provenance claim
# describing rows that have just been replaced is worse than none - it
# would tell an operator the database covers an ecosystem in a way it no
# longer does.
_veng_advisories_write_db() {
  local db=$1 db_eco=$2 new_rows=$3 provenance=${4:-}
  mkdir -p "$(dirname -- "$db")"
  mkdir -p "$SCOURSH_SCRATCH/advisories"
  local body=$SCOURSH_SCRATCH/advisories/body.$$.tsv
  local keep=$SCOURSH_SCRATCH/advisories/keep-bulk.$$.txt
  : >"$body"
  : >"$keep"
  if [[ -r $db ]]; then
    awk -v eco="$db_eco" -v keep="$keep" '
      /^#/ {
        if ($0 ~ /^# bulk: ecosystem=/) {
          f = $0
          sub(/^# bulk: ecosystem=/, "", f)
          sub(/ .*$/, "", f)
          if (f != eco) print $0 > keep
        }
        next
      }
      $0 == "" { next }
      { split($0, a, "\t"); if (a[1] != eco) print }
    ' "$db" >"$body"
  fi
  cat -- "$new_rows" >>"$body"
  if [[ -n $provenance ]]; then
    printf '%s\n' "$provenance" >>"$keep"
  fi

  local tmp=$SCOURSH_SCRATCH/advisories/db.$$.tsv
  {
    printf '# scoursh %s - generated by tools/vendor-engines.sh advisories (docs/FOUNDATION.md tension 25)\n' "$(basename -- "$db")"
    printf '# generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# source: OSV.dev (https://osv.dev), per-ecosystem provenance on the `# bulk:` lines below where present\n'
    LC_ALL=C sort -u -- "$keep"
    TMPDIR=$SCOURSH_SCRATCH LC_ALL=C sort -u -- "$body"
  } >"$tmp"
  mv -f -- "$tmp" "$db"
  local rows
  rows=$(wc -l <"$body")
  log_info "vendor-engines: advisories: wrote $rows total row(s) to ${db#"$VENG_DIR"/}"
}

# _veng_advisories_run DB_ECOSYSTEM - the per-ecosystem driver every
# veng_advisories_<ecosystem> function below delegates to: reads the
# operator-supplied id list, expands each advisory, then writes the result
# into BOTH data/advisories.db and data/versions.db - tension 25's own
# text ("data/versions.db ... uses the same shape and the same rule")
# gives both files an identical schema and an identical write path here.
# Scoped to the six docs/DESIGN.md §6.5 SCA ecosystems only:
# veng_advisories_banner (below) is the versions.db-only `banner` namespace's
# own driver, deliberately NOT this one, since modules/sca/ never reads a
# `banner` row out of data/advisories.db.
_veng_advisories_run() {
  local db_eco=$1
  _veng_advisories_load_normalizers

  local env_var
  env_var=$(_veng_advisories_env_var "$db_eco")
  local ids=${!env_var:-}
  [[ -n $ids ]] || die "$SCOURSH_EXIT_INPUT" \
    "advisories: $env_var is not set - supply one or more real OSV.dev advisory ids (comma/space separated) you identified from $db_eco's own advisory source (https://osv.dev), e.g. $env_var='GHSA-xxxx-xxxx-xxxx'. This script never guesses or hardcodes an advisory id (see this file's own header)."

  local -a id_list=()
  IFS=$', \t' read -ra id_list <<<"$ids"
  (( ${#id_list[@]} > 0 )) || die "$SCOURSH_EXIT_INPUT" "advisories: $env_var is set but names no ids"

  local rows_new=$SCOURSH_SCRATCH/advisories/rows.$db_eco.tsv
  mkdir -p "$(dirname -- "$rows_new")"
  : >"$rows_new"

  local id
  for id in "${id_list[@]+"${id_list[@]}"}"; do
    [[ -n $id ]] || continue
    _veng_advisories_expand_one "$db_eco" "$id" "$rows_new"
  done

  _veng_advisories_write_db "$VENG_ADVISORIES_DB" "$db_eco" "$rows_new"
  _veng_advisories_write_db "$VENG_VERSIONS_DB" "$db_eco" "$rows_new"
}

veng_advisories_npm()      { _veng_advisories_run npm; }
veng_advisories_pypi()     { _veng_advisories_run pypi; }
veng_advisories_maven()    { _veng_advisories_run maven; }
veng_advisories_go()       { _veng_advisories_run Go; }
veng_advisories_rubygems() { _veng_advisories_run RubyGems; }
veng_advisories_composer() { _veng_advisories_run composer; }

# veng_advisories_banner - the same per-ecosystem shape as _veng_advisories_run
# above (operator-supplied ids -> fetch -> extract -> normalise -> write),
# applied to data/versions.db's OTHER namespace: the `banner` catalogue
# docs/VERSIONS-DB.md §3 defines for a banner-matched product (a bare web
# server, a TLS library, a CMS - anything with no SCA-ecosystem manifest at
# all).  docs/FOUNDATION.md tension 25 named this an open, hand-maintained
# gap; this closes it.
#
# Deliberately NOT folded into _veng_advisories_run/VENG_ADVISORY_REGISTRY:
#
#   - it reads SCOURSH_ADVISORY_BANNER_IDS (via _veng_advisories_env_var's own
#     "banner" case), the identical comma/space-separated-OSV-id shape every
#     SCOURSH_ADVISORY_<ECOSYSTEM>_IDS var already uses, but "banner" is not
#     one of docs/DESIGN.md §6.5's six SCA ecosystems, so it is reached from
#     its own `banner` case in veng_advisories_main rather than
#     VENG_ADVISORY_REGISTRY - joining that registry would also pull it into
#     `advisories --list`/`--all` and `advisories bulk --all`, and OSV.dev
#     publishes no per-ecosystem bulk-export zip for a synthetic "banner"
#     ecosystem for the bulk path to fetch.
#   - the product KEY is normalised through banner_normalize_product
#     (_veng_advisories_normalize_name's own "banner" case, section 3 above),
#     never one of the sca_*_normalize_name functions - a different frozen
#     rule, in a different module, for a different namespace.
#   - rows land in data/versions.db ONLY, under the literal ecosystem
#     `banner` - never data/advisories.db, which docs/VERSIONS-DB.md §2's own
#     table reserves for the six SCA ecosystems modules/sca/ actually reads
#     there.  Writing a `banner` row into data/advisories.db too would cost
#     nothing structurally (_veng_advisories_write_db is ecosystem-scoped
#     either way) but would misstate what that file is for no reader's
#     benefit.
veng_advisories_banner() {
  _veng_advisories_load_banner_normalizer

  local env_var
  env_var=$(_veng_advisories_env_var banner)
  local ids=${!env_var:-}
  [[ -n $ids ]] || die "$SCOURSH_EXIT_INPUT" \
    "advisories: $env_var is not set - supply one or more real OSV.dev advisory ids (comma/space separated) for the banner-matched products your estate runs (a bare web server, a TLS library, a CMS - anything with no SCA-ecosystem manifest), e.g. $env_var='CVE-2021-41773'. This script never guesses or hardcodes an advisory id (see this file's own header)."

  local -a id_list=()
  IFS=$', \t' read -ra id_list <<<"$ids"
  (( ${#id_list[@]} > 0 )) || die "$SCOURSH_EXIT_INPUT" "advisories: $env_var is set but names no ids"

  local rows_new=$SCOURSH_SCRATCH/advisories/rows.banner.tsv
  mkdir -p "$(dirname -- "$rows_new")"
  : >"$rows_new"

  local id
  for id in "${id_list[@]+"${id_list[@]}"}"; do
    [[ -n $id ]] || continue
    _veng_advisories_expand_one banner "$id" "$rows_new"
  done

  _veng_advisories_write_db "$VENG_VERSIONS_DB" banner "$rows_new"
}

veng_advisories_list() {
  local name
  for name in "${!VENG_ADVISORY_REGISTRY[@]}"; do
    printf '%s\n' "$name"
  done | LC_ALL=C sort
}

veng_advisories_one() {
  local eco=$1
  [[ -n ${VENG_ADVISORY_REGISTRY[$eco]:-} ]] \
    || die "$SCOURSH_EXIT_INPUT" \
      "advisories: unknown ecosystem '$eco' - run 'advisories --list' to see the six docs/DESIGN.md §6.5 ecosystems"
  log_info "vendor-engines: advisories: expanding '$eco'"
  "${VENG_ADVISORY_REGISTRY[$eco]}"
}

veng_advisories_all() {
  local name
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    veng_advisories_one "$name"
  done < <(veng_advisories_list)
}

# ---------------------------------------------------------------------------
# 3a. BULK ecosystem import (`advisories bulk`)
# ---------------------------------------------------------------------------
# WHY THIS EXISTS.  Section 3 above resolves ONE operator-supplied OSV id at
# a time.  That is the right shape for "the operator already knows which
# advisory matters", and it is the wrong shape for populating a database at
# all: knowing which advisory ids exist for an ecosystem is precisely the
# thing a dependency scanner is supposed to TELL the operator.  With no
# data/advisories.db on disk, `scan.sh sca` reports every project clean
# (modules/sca/ records a `no_advisories_db_on_disk` coverage_reduction and
# emits nothing), so a finished, tested SCA module sits behind a database
# that in practice nobody can build.  This section imports a whole
# ecosystem's published OSV export in one command, per ecosystem or for all
# six.
#
# WHAT IT FETCHES.  OSV.dev publishes a per-ecosystem bulk export at
# `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`,
# one JSON record per advisory in the identical schema section 3's
# single-advisory endpoint returns - so the record walk, the normalisation,
# the frozen TSV schema and the writer are all REUSED here unchanged rather
# than re-implemented (`_veng_advisories_osv_extract_py`,
# `_veng_advisories_normalize_*`, `_veng_advisories_write_db`).  The
# ecosystem path component is `_veng_advisories_osv_ecosystem`'s own mapping,
# not a second copy of it.  No range arithmetic happens here either: exactly
# as in section 3, only OSV's own enumerated `affected[].versions` become
# rows, and a range-only advisory is counted and reported, never guessed at
# (tension 25).
#
# INTEGRITY: THE DESIGN TENSION, AND WHAT THIS RESOLUTION DOES AND DOES NOT
# GUARANTEE.  Every other download in this file goes through `veng_fetch`
# (section 2a), which REQUIRES the caller to supply an expected sha256,
# because an unverified artifact is not meaningfully different from an
# unsigned one and this file never guesses or hardcodes a checksum.  A bulk
# export is rebuilt upstream continuously, so there is no stable digest an
# operator could know in advance and the existing pattern does not transfer
# unchanged.  Silently dropping the check to make bulk work would be the
# worst of the available answers, so instead this section states an explicit
# grade for every import and refuses to proceed unpinned without the
# operator saying so:
#
#   pinned-sha256            The operator supplied `--sha256`.  A network
#                            fetch goes through `veng_fetch` VERBATIM (same
#                            download-and-verify primitive, same refusal,
#                            same removal of a mismatched file), and a local
#                            `--archive` is compared against the same digest.
#                            GUARANTEES the bytes imported are exactly the
#                            bytes the operator named.  It does NOT say those
#                            bytes are authentic, only that they are the ones
#                            already decided on - which is what makes an
#                            import reproducible and reviewable.
#   unpinned-transport-only  A network fetch with no digest.  Requires
#                            `--accept-unverified`.  curl is pinned to
#                            `--proto '=https' --proto-redir '=https'
#                            --tlsv1.2`, so the TRANSPORT is authenticated
#                            (the host's certificate chain, including across
#                            redirects) and cannot silently downgrade to
#                            cleartext.  That authenticates the SERVER, not
#                            the CONTENT: it says nothing about whether
#                            upstream published what it should have, and it
#                            is strictly weaker than a pin.
#   unpinned-local-archive   An operator-supplied `--archive`, no digest.
#                            Requires `--accept-unverified`.  This file
#                            verified NOTHING about the content; the operator
#                            chose the bytes.  Reaches no network code at
#                            all.
#
# In every grade the sha256 of what was ACTUALLY imported is computed,
# printed, and written into the database's own header, so a later operator
# can tell exactly what they got, diff two snapshots, and pass that same
# digest back as `--sha256` to pin the next import.  An unpinned import
# without `--accept-unverified` is refused outright rather than warned
# about, because a warning in a log an operator does not read is not a
# decision they made.
#
# WHAT IS ALWAYS CHECKED, REGARDLESS OF GRADE, and is not authenticity:
# the artifact must open as a zip (a truncated transfer cannot, since the
# central directory sits at the file's END), every member must pass its
# stored CRC32, every member must be valid OSV JSON carrying an advisory id,
# the archive must hold at least one member, and the import must produce at
# least one row.  Any one of those failing fails the WHOLE ecosystem, and
# the database is written only after all of them pass, so a refusal can
# never leave an ecosystem half-imported.  See
# `_veng_advisories_osv_extract_py`'s own header for the per-refusal detail.
#
# SCALE.  A real ecosystem is tens of thousands of advisories and hundreds
# of thousands of exact-version rows, so nothing here may be per-row shell
# work.  The pipeline is: one `python3` pass over the archive (one record in
# memory at a time) emitting raw rows to a file; one `awk` pass to collect
# the DISTINCT raw package names, versions and severities; one bash loop per
# DISTINCT VALUE - not per row - through the frozen normalisation functions,
# written with the loop's stdout redirected so it costs no subprocess at
# all; one `awk` pass to join the three maps onto the rows and enforce the
# frozen schema; one `sort -u`.  Every stage is linear, streams through
# files rather than shell variables, and reports progress.
VENG_BULK_BASE_URL='https://osv-vulnerabilities.storage.googleapis.com'

VENG_BULK_ARCHIVE=''
VENG_BULK_SHA256=''
VENG_BULK_ACCEPT=0

veng_bulk_usage() {
  cat <<'EOF'
usage: tools/vendor-engines.sh advisories bulk [options] <ecosystem>
       tools/vendor-engines.sh advisories bulk [options] --all

Imports a whole ecosystem's published OSV.dev export
(https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip) into
data/advisories.db and data/versions.db in ONE command, pre-expanded to one
row per exact affected version (docs/FOUNDATION.md tension 25).  Run this BY
HAND, ON A NETWORKED BOX, like every other command in this script.

Ecosystems are the same six 'advisories --list' reports.

Options:
  --sha256 HEX          verify the artifact against this sha256 and refuse on
                         mismatch.  The strongest grade, and the only one
                         that needs no acknowledgement.  Take HEX from the
                         'artifact sha256:' line of an earlier import, or
                         from your own out-of-band record.
  --archive PATH        import an already-downloaded export instead of
                         fetching one.  Makes no network call at all; use it
                         on a box that downloads separately, or with an
                         internal mirror.
  --accept-unverified   acknowledge an import whose CONTENT this script did
                         not verify (no --sha256).  Required for an unpinned
                         import; see below for exactly what is and is not
                         guaranteed then.
  --all                 import every ecosystem.  Cannot be combined with
                         --archive (one archive is one ecosystem) or with
                         --sha256 (one digest cannot pin six artifacts).
  -h, --help            print this message and exit 0

INTEGRITY.  Every import prints the grade it achieved and the sha256 of what
it actually imported, and records both in the database header:

  pinned-sha256            the bytes are exactly the ones you named.
  unpinned-transport-only  fetched over HTTPS with a TLS 1.2 floor and no
                           redirect downgrade, so the SERVER is
                           authenticated; the CONTENT was not verified.
  unpinned-local-archive   you supplied the bytes; this script verified
                           nothing about them.

Regardless of grade, the archive must open as a zip (which a truncated
download cannot), every member must pass its stored CRC and parse as OSV
JSON, and the import must yield at least one row.  Any failure aborts that
ecosystem WITHOUT touching the database, so an ecosystem is never left half
imported; with --all, the ecosystems that succeeded are kept, the failures
are listed, and the run still exits non-zero.

EXIT CODES: 0 ok, 2 bad usage, 4 unknown ecosystem, missing acknowledgement,
missing tooling or unreadable archive, 5 the fetch, the integrity check or
the import itself failed.  Never anything outside 0-5.
EOF
}

# _veng_bulk_url DB_ECOSYSTEM - the upstream export URL, built from
# _veng_advisories_osv_ecosystem's own frozen mapping (npm/PyPI/Maven/Go/
# RubyGems/Packagist) rather than a second copy of it.
_veng_bulk_url() {
  local osv_eco
  osv_eco=$(_veng_advisories_osv_ecosystem "$1")
  printf '%s/%s/all.zip' "$VENG_BULK_BASE_URL" "$osv_eco"
}

# _veng_bulk_acquire DB_ECOSYSTEM - puts the artifact on disk and settles its
# integrity grade, reporting both.  Sets _VENG_BULK_ARTIFACT,
# _VENG_BULK_GRADE, _VENG_BULK_SOURCE and _VENG_BULK_SHA256_GOT.
_veng_bulk_acquire() {
  local db_eco=$1
  local dir=$SCOURSH_SCRATCH/advisories/bulk
  mkdir -p "$dir"

  if [[ -n $VENG_BULK_ARCHIVE ]]; then
    [[ -r $VENG_BULK_ARCHIVE ]] || die "$SCOURSH_EXIT_INPUT" \
      "advisories: bulk: --archive '$VENG_BULK_ARCHIVE' is not a readable file"
    _VENG_BULK_ARTIFACT=$VENG_BULK_ARCHIVE
    _VENG_BULK_SOURCE="local archive $VENG_BULK_ARCHIVE"
    _VENG_BULK_SHA256_GOT=$(cat -- "$VENG_BULK_ARCHIVE" | sha256_of)
    if [[ -n $VENG_BULK_SHA256 ]]; then
      [[ $_VENG_BULK_SHA256_GOT == "$VENG_BULK_SHA256" ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
        "advisories: bulk: checksum mismatch for $VENG_BULK_ARCHIVE (expected $VENG_BULK_SHA256, got $_VENG_BULK_SHA256_GOT) - refusing to import an artifact that is not the one you pinned"
      _VENG_BULK_GRADE=pinned-sha256
    else
      _VENG_BULK_GRADE=unpinned-local-archive
    fi
    return 0
  fi

  local url dest
  url=$(_veng_bulk_url "$db_eco")
  dest=$dir/$db_eco.zip
  rm -f -- "$dest"
  if [[ -n $VENG_BULK_SHA256 ]]; then
    # veng_fetch VERBATIM: the pinned path reuses the existing
    # download-and-verify primitive rather than forking a second one, so
    # there is exactly one implementation of "download, then refuse unless
    # the bytes match".
    veng_fetch "$url" "$dest" "$VENG_BULK_SHA256"
    _VENG_BULK_GRADE=pinned-sha256
  else
    # The unpinned path has ONLY the transport to rely on, so it insists on
    # it: HTTPS with a TLS 1.2 floor, and redirects that cannot leave HTTPS.
    # (veng_fetch above does not add these because a pinned artifact is
    # verified by its digest whatever route it took, and because changing
    # veng_fetch's own flags would change every adapter's vendoring path for
    # a reason that does not apply to them.)
    require_cmd curl
    log_info "vendor-engines: advisories: bulk: fetching $url"
    curl --fail --location --show-error --silent \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --output "$dest" -- "$url" \
      || die "$SCOURSH_EXIT_INCOMPLETE" "advisories: bulk: download failed: $url"
    _VENG_BULK_GRADE=unpinned-transport-only
  fi
  _VENG_BULK_ARTIFACT=$dest
  _VENG_BULK_SOURCE=$url
  _VENG_BULK_SHA256_GOT=$(cat -- "$dest" | sha256_of)
}

# _veng_bulk_normalize_rows DB_ECOSYSTEM RAWFILE OUTFILE - turns the
# extractor's raw 0x1f-separated rows into frozen-schema TSV rows.
#
# The normalisation itself is the SAME `_veng_advisories_normalize_*`
# dispatch the single-advisory path uses (which is in turn
# modules/sca/*.sh's own frozen functions, never a re-implementation), but
# it is applied once per DISTINCT raw value rather than once per row: an
# ecosystem has hundreds of thousands of rows and only tens of thousands of
# distinct package names, and normalisation depends on nothing but the
# value.  The loops write through a redirected stdout instead of a command
# substitution, so normalising a whole ecosystem costs ZERO subprocesses.
#
# The final awk pass enforces the frozen schema at scale, in place of the
# per-field `_veng_advisories_reject_tab_lf` calls the single-advisory path
# makes: an LF inside any OSV field breaks the 0x1f transport into a line
# with the wrong field count, and a TAB inside any field makes the assembled
# row split into more than 7 TAB fields.  Same rule, same refusal, one pass
# instead of three subprocesses per row.
_veng_bulk_normalize_rows() {
  local db_eco=$1 raw=$2 out=$3
  local dir=$SCOURSH_SCRATCH/advisories/bulk
  mkdir -p "$dir"
  local us=$'\x1f'
  local names_raw=$dir/names.raw vers_raw=$dir/vers.raw sevs_raw=$dir/sevs.raw
  local names_map=$dir/names.map vers_map=$dir/vers.map sevs_map=$dir/sevs.map
  local errfile=$dir/join.err raw_value
  : >"$errfile"

  awk -F"$us" '{ print $1 }' "$raw" | LC_ALL=C sort -u >"$names_raw"
  awk -F"$us" '{ print $2 }' "$raw" | LC_ALL=C sort -u >"$vers_raw"
  awk -F"$us" '{ print $4 }' "$raw" | LC_ALL=C sort -u >"$sevs_raw"

  local distinct_names
  distinct_names=$(wc -l <"$names_raw")
  distinct_names=${distinct_names//[[:space:]]/}
  log_info "vendor-engines: advisories: bulk: normalising $distinct_names distinct package name(s) through the frozen $db_eco rules"

  while IFS= read -r raw_value; do
    printf '%s\t' "$raw_value"
    _veng_advisories_normalize_name "$db_eco" "$raw_value"
    printf '\n'
  done <"$names_raw" >"$names_map"

  while IFS= read -r raw_value; do
    printf '%s\t' "$raw_value"
    _veng_advisories_normalize_version "$db_eco" "$raw_value"
    printf '\n'
  done <"$vers_raw" >"$vers_map"

  while IFS= read -r raw_value; do
    printf '%s\t' "$raw_value"
    _veng_advisories_normalize_severity "$raw_value"
    printf '\n'
  done <"$sevs_raw" >"$sevs_map"

  awk -F"$us" -v OFS=$'\t' -v eco="$db_eco" -v errf="$errfile" \
    -v nmap="$names_map" -v vmap="$vers_map" -v smap="$sevs_map" '
    function bail(msg) { print msg > errf; close(errf); exit 1 }
    function mapline(dest, line,   i) {
      i = index(line, "\t")
      dest[substr(line, 1, i - 1)] = substr(line, i + 1)
    }
    FILENAME == nmap { mapline(NAME, $0); next }
    FILENAME == vmap { mapline(VER, $0); next }
    FILENAME == smap { mapline(SEV, $0); next }
    {
      if (NF != 6) {
        bail("row " FNR " carries " NF " field(s) where 6 are expected - an LF inside an OSV field does exactly this, and the frozen schema forbids one")
      }
      if (!($1 in NAME) || !($2 in VER) || !($4 in SEV)) {
        bail("row " FNR " has no normalisation entry for one of its fields: " $1 " / " $2)
      }
      row = eco OFS NAME[$1] OFS VER[$2] OFS $3 OFS SEV[$4] OFS $5 OFS $6
      if (split(row, parts, "\t") != 7) {
        bail("row " FNR " assembles into more than 7 TAB-separated fields - a TAB inside an OSV field, which the frozen schema forbids")
      }
      print row
    }
  ' "$names_map" "$vers_map" "$sevs_map" "$raw" >"$out" || {
    local why=''
    [[ -s $errfile ]] && why=$(cat -- "$errfile")
    die "$SCOURSH_EXIT_INCOMPLETE" \
      "advisories: bulk: refusing to write a corrupt data/advisories.db row (tension 25's frozen schema): ${why:-the row transform failed}"
  }
}

# _veng_bulk_one DB_ECOSYSTEM - one ecosystem, end to end and transactional:
# nothing reaches data/advisories.db until every stage has succeeded.
_veng_bulk_one() {
  local db_eco=$1
  [[ -n ${VENG_ADVISORY_REGISTRY[$db_eco]:-} ]] \
    || die "$SCOURSH_EXIT_INPUT" \
      "advisories: bulk: unknown ecosystem '$db_eco' - run 'advisories --list' to see the six docs/DESIGN.md §6.5 ecosystems"
  _veng_advisories_load_normalizers

  local dir=$SCOURSH_SCRATCH/advisories/bulk
  mkdir -p "$dir"
  local raw=$dir/rows.$db_eco.raw
  local tsv=$dir/rows.$db_eco.tsv
  local stats=$dir/stats.$db_eco.txt
  local summary=$dir/summary.$db_eco.txt
  : >"$raw"
  : >"$tsv"
  : >"$stats"
  : >"$summary"

  log_info "vendor-engines: advisories: bulk: importing '$db_eco'"
  _veng_bulk_acquire "$db_eco"
  log_info "vendor-engines: advisories: bulk: $db_eco: integrity: $_VENG_BULK_GRADE"
  case $_VENG_BULK_GRADE in
    pinned-sha256)
      log_info "vendor-engines: advisories: bulk: $db_eco: the artifact matched the operator-supplied digest byte for byte"
      ;;
    unpinned-transport-only)
      log_warn "vendor-engines: advisories: bulk: $db_eco: the HTTPS transport was verified (TLS 1.2 floor, no redirect downgrade) but the artifact content was NOT verified - re-run with --sha256 $_VENG_BULK_SHA256_GOT to pin exactly this artifact"
      ;;
    unpinned-local-archive)
      log_warn "vendor-engines: advisories: bulk: $db_eco: this is an operator-supplied archive and its content was NOT verified by this script - re-run with --sha256 $_VENG_BULK_SHA256_GOT to pin exactly these bytes"
      ;;
  esac
  log_info "vendor-engines: advisories: bulk: $db_eco: artifact sha256: $_VENG_BULK_SHA256_GOT"
  log_info "vendor-engines: advisories: bulk: $db_eco: artifact source: $_VENG_BULK_SOURCE"

  local osv_eco
  osv_eco=$(_veng_advisories_osv_ecosystem "$db_eco")
  _veng_advisories_osv_extract_py archive "$_VENG_BULK_ARTIFACT" "$osv_eco" "$stats" >"$raw" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "advisories: bulk: $db_eco: the export failed validation and NOTHING was written (see the reason above)"

  local advisories_read=0 rows_extracted=0 range_only_skipped=0 versioned_entries=0 other_ecosystem_skipped=0
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    case $line in
      advisories_read=*) advisories_read=${line#*=} ;;
      rows_extracted=*) rows_extracted=${line#*=} ;;
      range_only_skipped=*) range_only_skipped=${line#*=} ;;
      versioned_entries=*) versioned_entries=${line#*=} ;;
      other_ecosystem_skipped=*) other_ecosystem_skipped=${line#*=} ;;
    esac
  done <"$stats"

  _veng_bulk_normalize_rows "$db_eco" "$raw" "$tsv"
  LC_ALL=C sort -u -- "$tsv" >"$tsv.sorted"
  mv -f -- "$tsv.sorted" "$tsv"

  local rows
  rows=$(wc -l <"$tsv")
  rows=${rows//[[:space:]]/}
  (( rows > 0 )) || die "$SCOURSH_EXIT_INCOMPLETE" \
    "advisories: bulk: $db_eco: the export produced ZERO exact-version rows ($advisories_read advisory record(s) read, $range_only_skipped of them range-only) - refusing to replace this ecosystem's rows with nothing, which would quietly turn every $db_eco dependency clean"
  if (( rows != rows_extracted )); then
    log_info "vendor-engines: advisories: bulk: $db_eco: $(( rows_extracted - rows )) duplicate row(s) collapsed"
  fi

  local provenance
  provenance=$(printf '# bulk: ecosystem=%s grade=%s sha256=%s advisories_read=%s rows=%s range_only_skipped=%s other_ecosystem_skipped=%s generated=%s source=%s' \
    "$db_eco" "$_VENG_BULK_GRADE" "$_VENG_BULK_SHA256_GOT" "$advisories_read" "$rows" \
    "$range_only_skipped" "$other_ecosystem_skipped" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_VENG_BULK_SOURCE")
  _veng_advisories_reject_tab_lf provenance "$provenance"

  _veng_advisories_write_db "$VENG_ADVISORIES_DB" "$db_eco" "$tsv" "$provenance"
  _veng_advisories_write_db "$VENG_VERSIONS_DB" "$db_eco" "$tsv" "$provenance"

  # A raw skip COUNT does not tell a first-time operator how much of the
  # ecosystem they actually got - measured here: npm's own OSV.dev export is
  # 90%+ range-only (GHSA npm advisories overwhelmingly ship as a semver
  # range rather than an explicit version list), so "207444 skipped" reads
  # as a footnote where "90% of npm's affected-package entries are NOT in
  # this database" reads as the caveat it is.
  #
  # The denominator is versioned_entries, NOT advisories_read: one OSV
  # advisory can list many affected PACKAGES (each independently range-only
  # or versioned), so range_only_skipped and advisories_read are counted in
  # different units and range_only_skipped can legitimately exceed
  # advisories_read - measured on Go, where one advisory can list dozens of
  # affected module variants (advisories_read=9048 but
  # range_only_skipped=13804, a skip/read ratio that reads as "152%" and is
  # simply wrong).  versioned_entries is counted in the SAME unit as
  # range_only_skipped (per affected-package entry), so this ratio is
  # mathematically bounded to [0,100] regardless of how many packages one
  # advisory names.  Integer percent, no bc dependency, consistent with
  # every other percentage this script prints.
  local skip_pct=0
  local skip_denominator=$(( range_only_skipped + versioned_entries ))
  (( skip_denominator > 0 )) && skip_pct=$(( range_only_skipped * 100 / skip_denominator ))

  printf 'grade=%s advisories_read=%s rows=%s range_only_skipped=%s (%s%%) other_ecosystem_skipped=%s\n' \
    "$_VENG_BULK_GRADE" "$advisories_read" "$rows" "$range_only_skipped" "$skip_pct" "$other_ecosystem_skipped" \
    >"$summary"
  log_info "vendor-engines: advisories: bulk: $db_eco: imported: advisories_read=$advisories_read rows=$rows range_only_skipped=$range_only_skipped ($skip_pct% of affected packages) other_ecosystem_skipped=$other_ecosystem_skipped"
  if (( range_only_skipped > 0 )); then
    log_warn "vendor-engines: advisories: bulk: $db_eco: $range_only_skipped affected-package entr(y/ies) ($skip_pct% of the $skip_denominator this export named for $db_eco) published no explicit affected-version list and are NOT represented in the database - this ecosystem's coverage is smaller than that by exactly that much (tension 25 requires exact versions, never a guessed range)"
  fi
  if (( skip_pct >= 50 )); then
    log_warn "vendor-engines: advisories: bulk: $db_eco: MORE THAN HALF of the affected packages $db_eco's OSV.dev export names are range-only and absent from this database - a scan against $db_eco dependencies will miss most real-world CVEs in this ecosystem even with a freshly-built database; this is a known limitation of $db_eco's own OSV.dev export, not a failed import"
  fi
}

# _veng_bulk_all - every ecosystem, each one transactional and independent.
# A failing ecosystem does NOT discard the ones that already succeeded (they
# are real coverage, and their own provenance lines say what they are), and
# it does NOT let the run report success either: a partially-imported
# database that exits 0 is exactly the silently-covers-less-than-it-claims
# shape this data exists to prevent.
_veng_bulk_all() {
  local dir=$SCOURSH_SCRATCH/advisories/bulk
  mkdir -p "$dir"
  local report=$dir/all-report.txt
  : >"$report"
  local failed=0 eco rc detail
  while IFS= read -r eco; do
    [[ -n $eco ]] || continue
    rc=0
    ( _veng_bulk_one "$eco" ) || rc=$?
    if (( rc == 0 )); then
      detail=$(cat -- "$dir/summary.$eco.txt" 2>/dev/null || printf '')
      printf '  %-10s OK      %s\n' "$eco" "$detail" >>"$report"
    else
      failed=1
      printf '  %-10s FAILED  (exit %s, nothing written for this ecosystem - see the log above)\n' \
        "$eco" "$rc" >>"$report"
    fi
  done < <(veng_advisories_list)

  printf 'vendor-engines: advisories: bulk: per-ecosystem result:\n' >&2
  cat -- "$report" >&2
  if (( failed )); then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'advisories: bulk: at least one ecosystem failed to import - the database covers only the ecosystems marked OK above'
  fi
}

veng_bulk_main() {
  local want_all=0 eco=''
  VENG_BULK_ARCHIVE=''
  VENG_BULK_SHA256=''
  VENG_BULK_ACCEPT=0

  while (( $# > 0 )); do
    case $1 in
      -h | --help)
        veng_bulk_usage
        exit "$SCOURSH_EXIT_OK"
        ;;
      --all) want_all=1 ;;
      --accept-unverified) VENG_BULK_ACCEPT=1 ;;
      --sha256)
        (( $# >= 2 )) || { veng_bulk_usage >&2; die "$SCOURSH_EXIT_USAGE" 'advisories: bulk: --sha256 needs a value'; }
        VENG_BULK_SHA256=$2
        shift
        ;;
      --archive)
        (( $# >= 2 )) || { veng_bulk_usage >&2; die "$SCOURSH_EXIT_USAGE" 'advisories: bulk: --archive needs a value'; }
        VENG_BULK_ARCHIVE=$2
        shift
        ;;
      --*)
        veng_bulk_usage >&2
        die "$SCOURSH_EXIT_USAGE" "advisories: bulk: unknown flag: '$1'"
        ;;
      *)
        [[ -z $eco ]] || { veng_bulk_usage >&2; die "$SCOURSH_EXIT_USAGE" "advisories: bulk: more than one ecosystem given ('$eco' and '$1')"; }
        eco=$1
        ;;
    esac
    shift
  done

  if (( want_all )) && [[ -n $eco ]]; then
    veng_bulk_usage >&2
    die "$SCOURSH_EXIT_USAGE" "advisories: bulk: --all and an ecosystem name ('$eco') are mutually exclusive"
  fi
  if (( ! want_all )) && [[ -z $eco ]]; then
    veng_bulk_usage >&2
    die "$SCOURSH_EXIT_USAGE" 'advisories: bulk: name an ecosystem, or pass --all'
  fi
  if (( want_all )) && [[ -n $VENG_BULK_ARCHIVE ]]; then
    veng_bulk_usage >&2
    die "$SCOURSH_EXIT_USAGE" \
      'advisories: bulk: --all and --archive are mutually exclusive - one archive is one ecosystem export, and importing it six times would file the same advisories under five ecosystems that never published them'
  fi
  if (( want_all )) && [[ -n $VENG_BULK_SHA256 ]]; then
    veng_bulk_usage >&2
    die "$SCOURSH_EXIT_USAGE" \
      'advisories: bulk: --all and --sha256 are mutually exclusive - one digest cannot pin six separate artifacts, and accepting it would verify one while silently trusting five'
  fi

  # The integrity gate, ahead of every fetch, every read and every write.
  if [[ -z $VENG_BULK_SHA256 ]] && (( ! VENG_BULK_ACCEPT )); then
    die "$SCOURSH_EXIT_INPUT" \
      "advisories: bulk: refusing an unverified bulk import. A bulk export is rebuilt upstream continuously, so there is no published digest to check it against by default. Either pin the artifact you mean with --sha256 <hex> (the strongest grade, and reproducible), or acknowledge explicitly with --accept-unverified, which imports over a verified HTTPS transport - or from an archive you supplied - WITHOUT verifying the content, and records the sha256 of whatever it got so you can pin it next time."
  fi

  if (( want_all )); then
    _veng_bulk_all
  else
    _veng_bulk_one "$eco"
  fi
}

veng_advisories_main() {
  (( $# > 0 )) || { veng_advisories_usage >&2; die "$SCOURSH_EXIT_USAGE" 'advisories: no command given'; }

  case $1 in
    -h | --help)
      veng_advisories_usage
      exit "$SCOURSH_EXIT_OK"
      ;;
    --list)
      veng_advisories_list
      ;;
    --all)
      veng_advisories_all
      ;;
    bulk)
      shift
      veng_bulk_main "$@"
      ;;
    banner)
      # A named command, not routed through veng_advisories_one/
      # VENG_ADVISORY_REGISTRY - see veng_advisories_banner's own header for
      # why "banner" is deliberately not one of the six SCA ecosystems.
      veng_advisories_banner
      ;;
    --*)
      veng_advisories_usage >&2
      die "$SCOURSH_EXIT_USAGE" "advisories: unknown flag: '$1'"
      ;;
    *)
      veng_advisories_one "$1"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 4. Main
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
    advisories)
      shift
      veng_advisories_main "$@"
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
