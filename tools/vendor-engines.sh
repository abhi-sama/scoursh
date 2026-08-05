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
                     'advisories --help' for its own usage
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
#    fixed_versions\tsummary`, sorted under LC_ALL=C), so the air-gapped
#    scanner's own SCA matching step (modules/sca/) stays an exact string
#    lookup with no version algebra of its own.
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
#    box - and is used NOWHERE in the air-gapped scan-time path;
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
frozen TSV schema).  Run this BY HAND, ON A NETWORKED BOX, the same as
every other command this script provides - see this file's own header.

A SEPARATE command namespace from --list/--all/<engine> above: it never
touches VENG_REGISTRY, and an ecosystem name here is never mistaken for a
registered engine adapter name, or vice versa.

Commands:
  --list              list the six supported ecosystems
  --all               expand every ecosystem (each one's own
                       SCOURSH_ADVISORY_<ECOSYSTEM>_IDS must be set)
  <ecosystem>          expand one ecosystem (npm, pypi, maven, Go,
                       RubyGems, composer)
  -h, --help          print this message and exit 0

Every ecosystem reads its advisory ids from an operator-supplied env var -
SCOURSH_ADVISORY_NPM_IDS, SCOURSH_ADVISORY_PYPI_IDS,
SCOURSH_ADVISORY_MAVEN_IDS, SCOURSH_ADVISORY_GO_IDS,
SCOURSH_ADVISORY_RUBYGEMS_IDS, SCOURSH_ADVISORY_COMPOSER_IDS - a
comma/space-separated list of real OSV.dev advisory ids (e.g.
"GHSA-xxxx-xxxx-xxxx") the operator identified from that ecosystem's own
advisory source.  This script never guesses or hardcodes which advisory to
resolve (see this file's own header).

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

# _veng_advisories_osv_ecosystem DB_ECOSYSTEM - this project's own frozen
# ecosystem string (as used in data/advisories.db and by
# sca_lookup_exact/sca_package_known) -> OSV.dev's own `affected[].
# package.ecosystem` string for the same ecosystem.  The two vocabularies
# differ in exactly two spots (PyPI, Composer/Packagist); both sides are
# named explicitly here rather than assumed identical.
_veng_advisories_osv_ecosystem() {
  case $1 in
    npm) printf 'npm' ;;
    pypi) printf 'PyPI' ;;
    maven) printf 'Maven' ;;
    Go) printf 'Go' ;;
    RubyGems) printf 'RubyGems' ;;
    composer) printf 'Packagist' ;;
    *) die "$SCOURSH_EXIT_INPUT" "advisories: unknown ecosystem '$1'" ;;
  esac
}

# _veng_advisories_env_var DB_ECOSYSTEM - the operator-supplied advisory-id
# env var name for this ecosystem (see veng_advisories_usage above).
_veng_advisories_env_var() {
  case $1 in
    npm) printf 'SCOURSH_ADVISORY_NPM_IDS' ;;
    pypi) printf 'SCOURSH_ADVISORY_PYPI_IDS' ;;
    maven) printf 'SCOURSH_ADVISORY_MAVEN_IDS' ;;
    Go) printf 'SCOURSH_ADVISORY_GO_IDS' ;;
    RubyGems) printf 'SCOURSH_ADVISORY_RUBYGEMS_IDS' ;;
    composer) printf 'SCOURSH_ADVISORY_COMPOSER_IDS' ;;
    *) die "$SCOURSH_EXIT_INPUT" "advisories: unknown ecosystem '$1'" ;;
  esac
}

# _veng_advisories_normalize_name DB_ECOSYSTEM RAW_NAME - dispatches to the
# frozen sca_*_normalize_name function for this ecosystem (this section's
# own header explains why these are reused, never re-implemented).  Maven's
# OSV package name already arrives as "groupId:artifactId"; it is split
# once here so sca_maven_normalize_name (the single frozen join point,
# modules/sca/engine.sh) still owns the actual join.
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

# _veng_advisories_normalize_severity RAW - maps OSV's own severity
# vocabulary (GHSA-backed sources use CRITICAL/HIGH/MODERATE/LOW; PYSEC and
# the Go database frequently supply none at all, relying on a CVSS vector
# this script does not attempt to score - a stated, not hidden, limitation)
# onto this project's frozen five-word rubric (lib/records.sh
# severity_rank/severity_name: info/low/medium/high/critical).  Empty or
# unrecognised input maps to "medium" - a deliberately conservative
# default rather than silently dropping the row (an absent severity is not
# evidence of low risk).
_veng_advisories_normalize_severity() {
  local raw=${1^^}
  case $raw in
    CRITICAL) printf 'critical' ;;
    HIGH) printf 'high' ;;
    MODERATE | MEDIUM) printf 'medium' ;;
    LOW) printf 'low' ;;
    *) printf 'medium' ;;
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
  require_cmd python3
  python3 - "$jsonfile" "$osv_ecosystem" <<'PY'
import json
import sys

path, eco = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

vuln_id = data.get("id", "")
US = "\x1f"


def clean(s):
    # Collapses embedded tabs/newlines/runs of whitespace to a single
    # space - the frozen schema forbids a raw TAB or LF inside a field
    # (tension 25).  Applied to every field EXCEPT fixed_versions (see
    # below): the bash caller re-validates all of them with
    # _veng_advisories_reject_tab_lf rather than trusting this alone.
    return " ".join(str(s).split())


summary = data.get("summary") or ""
if not summary:
    details = data.get("details") or ""
    summary = details.splitlines()[0] if details else ""
summary = clean(summary)

top_severity = ""
ds = data.get("database_specific") or {}
if isinstance(ds, dict):
    top_severity = ds.get("severity") or ""

for affected in data.get("affected", []) or []:
    pkg = affected.get("package") or {}
    if pkg.get("ecosystem") != eco:
        continue
    name = pkg.get("name") or ""
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
    # NOT cleaned: tension 25 states fixed_versions is "carried as opaque
    # display text and never compared" - a raw TAB/LF smuggled inside one
    # of OSV's own `fixed` event strings must reach
    # _veng_advisories_reject_tab_lf intact so the bash caller can refuse
    # it, rather than being silently normalised away here first.
    fixed_str = ",".join(fixed)

    for version in affected.get("versions") or []:
        row = US.join(
            [clean(name), clean(version), clean(vuln_id), clean(severity), fixed_str, summary]
        )
        print(row)
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
    norm_sev=$(_veng_advisories_normalize_severity "$severity")
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

# _veng_advisories_write_db DB DB_ECOSYSTEM NEW_ROWS - replaces every
# existing DB_ECOSYSTEM row in DB with the rows in NEW_ROWS, leaving every
# OTHER ecosystem's rows untouched, then rewrites DB sorted under LC_ALL=C
# with a fresh `#` header (tension 25: "sorted... under LC_ALL=C, with a
# `#` header line" - db_lookup_exact's own `look`/`grep -F` lookup,
# lib/core.sh, requires the file sorted; a leading `#` byte sorts before
# every real ecosystem's first letter under LC_ALL=C, so a header line
# never disturbs that requirement, the same shape
# tests/fixtures/sca/advisories.db already uses).  Filtering is done in
# pure bash, deliberately not `grep`, per tension 4 rule 2's "no bare
# grep/rg outside the wrapper" - this is plain line selection, not the
# rule-matching engine, so scan_match does not apply either, but avoiding
# grep here keeps this file simple to audit against that rule by eye.
_veng_advisories_write_db() {
  local db=$1 db_eco=$2 new_rows=$3
  mkdir -p "$(dirname -- "$db")"
  local body=$SCOURSH_SCRATCH/advisories/body.$$.tsv
  : >"$body"
  local line
  if [[ -r $db ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      [[ -z $line ]] && continue
      [[ $line == '#'* ]] && continue
      [[ $line == "$db_eco"$'\t'* ]] && continue
      printf '%s\n' "$line" >>"$body"
    done <"$db"
  fi
  cat -- "$new_rows" >>"$body"

  local tmp=$SCOURSH_SCRATCH/advisories/db.$$.tsv
  {
    printf '# scoursh %s - generated by tools/vendor-engines.sh advisories (docs/FOUNDATION.md tension 25)\n' "$(basename -- "$db")"
    printf '# generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# source: OSV.dev (https://osv.dev), advisory ids operator-supplied via SCOURSH_ADVISORY_<ECOSYSTEM>_IDS\n'
    LC_ALL=C sort -u -- "$body"
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
# versions.db's OWN, separate banner-matching product catalog (services
# with no SCA-ecosystem manifest at all, e.g. a bare web server or TLS
# library) is a stated gap, not silently assumed covered - see this
# ticket's own hand-off comment.
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
