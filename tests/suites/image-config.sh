#!/usr/bin/env bash
# tests/suites/image-config.sh - IMG-10 ("root user, exposed
# ports, mutable base tag"): the two remaining distro-agnostic image
# CONFIG-BLOB checks - `IMAGE-CFG-EXPOSED_PORTS-01` and
# `IMAGE-CFG-MUTABLE_BASE_REF-01` - on top of IMG-06's already-tested
# `IMAGE-CFG-RUNS_AS_ROOT-01` (tests/suites/image-e2e.sh section B/C, not
# repeated here).
#
# What this suite proves, and what it is NOT for:
#
#   A. `modules/image/config.sh`'s `image_json_object_keys`, unit-level: the
#      SECOND, purpose-built JSON walker this ticket adds (that file's own
#      header explains why it is not a sixth copy of `image_json_flatten`) -
#      it must enumerate an object's keys regardless of whether each key's
#      OWN value is scalar, non-empty, or (the shape image_json_flatten
#      cannot see at all) a structurally EMPTY object; must not bleed a
#      same-named key at the WRONG structural depth into the wanted path;
#      must print nothing (never error) for an absent path or a present-but-
#      empty object; and must fail (rc=1, no finding) rather than hang on
#      genuinely malformed JSON - the config blob is attacker-controlled
#      content exactly like a layer is (modules/image/acquire.sh's own
#      header).
#   B. `_image_base_ref_is_pinned`, unit-level: a `@sha256:<64 hex>` suffix
#      is pinned; a bare tag, an empty string, and a digest-shaped string
#      too short to be a real sha256 are not.
#   C. `image_config_exposed_ports_get`/`image_config_base_ref_get`,
#      unit-level, against a real docker-archive config member: the nested
#      `config.ExposedPorts`/`config.Labels."org.opencontainers.image.base
#      .name"` paths, and the "key absent entirely" case for each.
#   D. End to end, through three real `scan.sh image` subprocesses: a
#      config with two exposed ports and a mutable-tag base label fires
#      both checks and round-trips through every report format; a config
#      with no exposed ports and a digest-PINNED base label is quiet for
#      both, with `checks_run` still naming them - the honesty rule that
#      it looked and found nothing, a different fact from "did not run";
#      and a config with NEITHER field at all is quiet for both, with the
#      base-ref check recording a declared `base_reference_not_recorded`
#      coverage_reduction rather than guessing - the brief's own "honesty
#      over a fabricated finding".
#
# NOT this suite's job: `IMAGE-CFG-RUNS_AS_ROOT-01` (tests/suites/
# image-e2e.sh already covers it end to end), any distro/package-manager
# check (image-apk.sh/image-dpkg.sh/image-advisories.sh), and anything
# under a rootfs walk (out of IMG-10's own scope - the brief's own words,
# "NOT a rootfs walk... that is IMG-11").
#
# No network: image scanning is offline by construction (docs/DESIGN.md
# §1), and this suite never puts curl/wget/aws on PATH at all.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SCOURSH_INSTALL_ROOT=$ROOT
# shellcheck source=modules/image/engine.sh
source "$ROOT/modules/image/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$ROOT/tests/fixtures/image/mkustar.sh"

W=$SCOURSH_SCRATCH/image-config
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- A. image_json_object_keys (unit-level) --\n'
# =============================================================================

DOC=$W/doc.json
cat >"$DOC" <<'EOF'
{"architecture":"amd64","config":{"User":"appuser","ExposedPorts":{"80/tcp":{},"443/udp":{}},"Labels":{"org.opencontainers.image.base.name":"alpine:3.18","other":"x"}}}
EOF

t_case 'enumerates keys of a nested object whose values are all EMPTY objects'
GOT=$(image_json_object_keys "$DOC" "config"$'\x1f'"ExposedPorts")
assert_eq $'80/tcp\n443/udp' "$GOT" \
  'FAILS under image_json_flatten alone: {} values emit no leaf row at all, so a reader built only on scalar-leaf extraction would report zero ports on an image that declares two'

t_case 'a present-but-empty object at the wanted path prints nothing, and is not an error'
DOC2=$W/doc-empty.json
printf '%s' '{"config":{"ExposedPorts":{}}}' >"$DOC2"
GOT=$(image_json_object_keys "$DOC2" "config"$'\x1f'"ExposedPorts")
assert_eq '' "$GOT" 'zero declared ports is a real, ordinary state - not a parse failure'

t_case 'an absent path prints nothing and returns 0 - the ordinary case (Docker omitempty drops the key)'
_rc=0
GOT=$(image_json_object_keys "$DOC" "config"$'\x1f'"Volumes") || _rc=$?
assert_eq 0 "$_rc" 'a missing key is not a refusal'
assert_eq '' "$GOT" 'and nothing was printed for it'

t_case 'a same-named key at the WRONG structural depth does not bleed into the wanted path'
DOC3=$W/doc-shadow.json
printf '%s' '{"ExposedPorts":{"9999/tcp":{}},"config":{"ExposedPorts":{"80/tcp":{}}}}' >"$DOC3"
GOT=$(image_json_object_keys "$DOC3" "config"$'\x1f'"ExposedPorts")
assert_eq '80/tcp' "$GOT" \
  'FAILS under a reading that matches on the KEY NAME alone rather than the full structural path - the top-level ExposedPorts (port 9999) must never appear'

t_case 'the document ROOT enumerates fine too (path == "")'
GOT=$(image_json_object_keys "$DOC" '')
assert_eq $'architecture\nconfig' "$GOT" 'both top-level keys, in document order'

t_case 'genuinely malformed JSON fails (rc=1) rather than hanging or reporting an empty (clean-looking) result'
DOC4=$W/doc-truncated.json
printf '%s' '{"config":{"ExposedPorts":' >"$DOC4"
_rc=0
image_json_object_keys "$DOC4" "config"$'\x1f'"ExposedPorts" >/dev/null 2>"$W/err" || _rc=$?
assert_eq 1 "$_rc" \
  'FAILS under a reading that reads past the end of a truncated document silently - a malformed config must never render as "this image declares zero ports"'
assert_contains "$(_slurp "$W/err")" '__JSON_ERROR__' 'and the awk-level error reason is on stderr, mirroring image_json_flatten own contract'

# =============================================================================
printf -- '\n-- B. _image_base_ref_is_pinned (unit-level) --\n'
# =============================================================================

t_case 'a real @sha256:<64 hex> suffix is pinned'
_image_base_ref_is_pinned "docker.io/library/alpine@sha256:$(printf 'a%.0s' $(seq 1 64))"
assert_eq 0 $? 'a genuine content digest is the ONLY thing this check accepts as immutable'

t_case 'a bare tag is NOT pinned'
_rc=0
_image_base_ref_is_pinned 'alpine:latest' || _rc=$?
assert_eq 1 "$_rc" 'a mutable tag - FAILS under a reading that treats the mere presence of a colon as a digest'

t_case 'a bare tag with no colon at all is NOT pinned'
_rc=0
_image_base_ref_is_pinned 'alpine' || _rc=$?
assert_eq 1 "$_rc" 'defaults to :latest, which is exactly as mutable'

t_case 'an empty reference is NOT pinned (the caller special-cases empty separately, before ever reaching here)'
_rc=0
_image_base_ref_is_pinned '' || _rc=$?
assert_eq 1 "$_rc" 'no false "pinned" on an empty string'

t_case 'a digest-shaped suffix too short to be a real sha256 is NOT pinned'
_rc=0
_image_base_ref_is_pinned 'alpine@sha256:deadbeef' || _rc=$?
assert_eq 1 "$_rc" \
  'FAILS under a reading that accepts any @algo:hex shape regardless of length - this is the SAME digest grammar acquire.sh _image_oci_blob_path already enforces ([0-9a-f]{32,})'

# =============================================================================
printf -- '\n-- C. image_config_exposed_ports_get / image_config_base_ref_get (unit-level) --\n'
# =============================================================================

EMPTYLAYER=$W/empty-layer.tar
ustar_begin "$EMPTYLAYER"
ustar_end "$EMPTYLAYER"

_mkcfgtar() {
  local name=$1 cfg=$2
  local tar=$W/$name.tar
  ustar_begin "$tar"
  ustar_add "$tar" 'cfg.json' 0 '' "$cfg"
  ustar_add "$tar" 'l0/' 5 '' ''
  ustar_add_file "$tar" 'l0/layer.tar' "$EMPTYLAYER"
  ustar_add "$tar" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/'"$name"':v1"],"Layers":["l0/layer.tar"]}]'
  ustar_end "$tar"
  printf '%s' "$tar"
}

CFG_PORTS='{"architecture":"amd64","config":{"ExposedPorts":{"8080/tcp":{},"53/udp":{}}}}'
TAR1=$(_mkcfgtar cfgports "$CFG_PORTS")
image_docker_archive_open "$TAR1" ''
CFGDIR1=$W/cfgdir1
rm -rf -- "${CFGDIR1:?}"
mkdir -p "$CFGDIR1"

t_case 'image_config_exposed_ports_get reads config.ExposedPorts out of a real docker-archive config member'
_rc=0
image_config_exposed_ports_get docker-archive "$TAR1" "$CFGDIR1" || _rc=$?
assert_eq 0 "$_rc" 'the config blob was readable'
GOT=$(printf '%s\n' "${_IMAGE_CONFIG_EXPOSED_PORTS[@]}" | LC_ALL=C sort)
assert_eq $'53/udp\n8080/tcp' "$GOT" 'both ports, unescaped, regardless of document order'

CFG_NOPORTS='{"architecture":"amd64","config":{"User":"appuser"}}'
TAR2=$(_mkcfgtar cfgnoports "$CFG_NOPORTS")
image_docker_archive_open "$TAR2" ''
CFGDIR2=$W/cfgdir2
rm -rf -- "${CFGDIR2:?}"
mkdir -p "$CFGDIR2"

t_case 'image_config_exposed_ports_get: no ExposedPorts key at all resolves to an EMPTY array, not an error'
_rc=0
image_config_exposed_ports_get docker-archive "$TAR2" "$CFGDIR2" || _rc=$?
assert_eq 0 "$_rc" 'a missing key is not a read failure'
assert_eq 0 "${#_IMAGE_CONFIG_EXPOSED_PORTS[@]}" 'and the array is empty'

CFG_BASE='{"architecture":"amd64","config":{"Labels":{"org.opencontainers.image.base.name":"registry.example.com/base:1.4"}}}'
TAR3=$(_mkcfgtar cfgbase "$CFG_BASE")
image_docker_archive_open "$TAR3" ''
CFGDIR3=$W/cfgdir3
rm -rf -- "${CFGDIR3:?}"
mkdir -p "$CFGDIR3"

t_case 'image_config_base_ref_get reads the OCI base.name label out of config.Labels'
_rc=0
image_config_base_ref_get docker-archive "$TAR3" "$CFGDIR3" || _rc=$?
assert_eq 0 "$_rc" 'the config blob was readable'
assert_eq 'registry.example.com/base:1.4' "$_IMAGE_CONFIG_BASE_REF" \
  "FAILS if the nested path were flattened wrong - it is config\\x1fLabels\\x1forg.opencontainers.image.base.name, not a bare 'base.name'"

t_case 'image_config_base_ref_get: no Labels/base.name at all resolves to EMPTY, not an error'
_rc=0
image_config_base_ref_get docker-archive "$TAR2" "$CFGDIR2" || _rc=$?
assert_eq 0 "$_rc" 'a missing label is not a read failure'
assert_eq '' "$_IMAGE_CONFIG_BASE_REF" 'and the value is empty'

# =============================================================================
printf -- '\n-- D. end to end: three real scan.sh image runs --\n'
# =============================================================================

_mkimg() {
  local name=$1 cfg=$2
  local tar=$W/$name.tar
  local l=$W/$name-layer.tar
  ustar_begin "$l"
  ustar_end "$l"
  ustar_begin "$tar"
  ustar_add "$tar" 'cfg.json' 0 '' "$cfg"
  ustar_add "$tar" 'l0/' 5 '' ''
  ustar_add_file "$tar" 'l0/layer.tar' "$l"
  ustar_add "$tar" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/'"$name"':v1"],"Layers":["l0/layer.tar"]}]'
  ustar_end "$tar"
  printf '%s' "$tar"
}

_image_scan() {
  local rundir=$1
  shift
  [[ $1 == -- ]] && shift
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$ROOT SCOURSH_SCA_ADVISORIES_DB=$W/no-such-advisories.db \
    bash "$ROOT/scan.sh" image --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

# Run 1: two exposed ports, base ref pinned by a mutable tag only.
CFG_DIRTY='{"architecture":"amd64","config":{"ExposedPorts":{"22/tcp":{},"80/tcp":{}},"Labels":{"org.opencontainers.image.base.name":"alpine:latest"}}}'
IMG1=$(_mkimg img10dirty "$CFG_DIRTY")

t_case 'run 1: IMAGE-CFG-EXPOSED_PORTS-01 and IMAGE-CFG-MUTABLE_BASE_REF-01 both fire'
_image_scan "$W/run1" --image scoursh-img10-e2e-1 --source "$IMG1"
assert_eq 0 "$_RC" 'a run with two real config findings and no --fail-on still exits 0'
RUN1_JSON=$(_slurp "$W/run1/run.json")
RUN1_FIELDS=$(_slurp "$W/run1/findings.fields")
assert_contains "$RUN1_JSON" 'IMAGE-CFG-EXPOSED_PORTS-01' 'checks_run names the ports check'
assert_contains "$RUN1_JSON" 'IMAGE-CFG-MUTABLE_BASE_REF-01' 'checks_run names the base-ref check'
assert_contains "$RUN1_FIELDS" 'check_id=IMAGE-CFG-EXPOSED_PORTS-01' 'a real ports finding was emitted'
assert_contains "$RUN1_FIELDS" 'check_id=IMAGE-CFG-MUTABLE_BASE_REF-01' 'and a real base-ref finding'

t_case "the ports finding's evidence lists both ports, sorted - stable across a JSON-encoder reorder"
assert_contains "$RUN1_FIELDS" '22/tcp,80/tcp' \
  'FAILS under a reading that leaves the ports in document/object-iteration order, which JSON gives no guarantee about'

t_case 'both findings round-trip through every report format'
assert_contains "$(_slurp "$W/run1/findings.json")" 'IMAGE-CFG-EXPOSED_PORTS-01' 'findings.json carries the ports check'
assert_contains "$(_slurp "$W/run1/report.md")" 'IMAGE-CFG-MUTABLE_BASE_REF-01' 'report.md lists the base-ref check'
assert_contains "$(_slurp "$W/run1/report.html")" 'IMAGE-CFG-EXPOSED_PORTS-01' 'report.html lists the ports check'
SARIF1=$(_slurp "$W/run1/report.sarif")
assert_contains "$SARIF1" '"ruleId":"IMAGE-CFG-MUTABLE_BASE_REF-01"' 'report.sarif names the base-ref check as its ruleId'
report_agent "$W/run1"
AGENT1=$(_slurp "$W/run1/agent-fix.json")
assert_contains "$AGENT1" '"check":"IMAGE-CFG-EXPOSED_PORTS-01"' 'agent-fix.json names the ports check'
assert_contains "$AGENT1" '"check":"IMAGE-CFG-MUTABLE_BASE_REF-01"' 'and the base-ref check'

# Run 2: no exposed ports, base ref pinned by a real digest.
CFG_CLEAN='{"architecture":"amd64","config":{"Labels":{"org.opencontainers.image.base.name":"alpine@sha256:'"$(printf 'b%.0s' $(seq 1 64))"'"}}}'
IMG2=$(_mkimg img10clean "$CFG_CLEAN")

t_case 'run 2: a digest-pinned base and no exposed ports - quiet for both checks, but checks_run still names them'
_image_scan "$W/run2" --image scoursh-img10-e2e-2 --source "$IMG2"
assert_eq 0 "$_RC" 'exit 0'
RUN2_JSON=$(_slurp "$W/run2/run.json")
RUN2_FIELDS=$(_slurp "$W/run2/findings.fields")
assert_not_contains "$RUN2_FIELDS" 'check_id=IMAGE-CFG-EXPOSED_PORTS-01' 'no ExposedPorts key at all - nothing to report'
assert_not_contains "$RUN2_FIELDS" 'check_id=IMAGE-CFG-MUTABLE_BASE_REF-01' \
  'the base image IS pinned by a real digest - quiet, not merely "not new"'
assert_contains "$RUN2_JSON" 'IMAGE-CFG-EXPOSED_PORTS-01' \
  'checks_run STILL names the ports check - it executed and found nothing, a different fact from "did not run"'
assert_contains "$RUN2_JSON" 'IMAGE-CFG-MUTABLE_BASE_REF-01' 'and still names the base-ref check too'

# Run 3: neither ExposedPorts nor the base.name label at all.
CFG_BARE='{"architecture":"amd64","config":{"User":"appuser"}}'
IMG3=$(_mkimg img10bare "$CFG_BARE")

t_case 'run 3: no base.name label at all - a DECLARED coverage limitation, never a guessed finding'
_image_scan "$W/run3" --image scoursh-img10-e2e-3 --source "$IMG3"
assert_eq 0 "$_RC" 'exit 0'
RUN3_JSON=$(_slurp "$W/run3/run.json")
RUN3_FIELDS=$(_slurp "$W/run3/findings.fields")
assert_not_contains "$RUN3_FIELDS" 'check_id=IMAGE-CFG-MUTABLE_BASE_REF-01' \
  'FAILS under a reading that treats "no label" the same as "an unpinned reference" and fabricates a finding - the brief is explicit: honesty over a fabricated finding'
assert_contains "$RUN3_JSON" 'reason=base_reference_not_recorded' \
  'the limitation is DECLARED - a coverage_reduction naming exactly why nothing could be said, not silence'
assert_contains "$RUN3_JSON" 'IMAGE-CFG-MUTABLE_BASE_REF-01' 'checks_run still names it - it executed and could not determine an answer, which is a third distinct fact from both "found a problem" and "found nothing"'

t_summary image-config
