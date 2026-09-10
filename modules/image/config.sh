#!/usr/bin/env bash
# modules/image/config.sh - the container-image module's CONFIG-BLOB checks
# (IMG-06's `IMAGE-CFG-RUNS_AS_ROOT-01`; IMG-10 adds
# `IMAGE-CFG-EXPOSED_PORTS-01` and `IMAGE-CFG-MUTABLE_BASE_REF-01` -
# data/scoursh-image-scan-design/report.md §4.1's IMAGE-CFG-* row and
# §5.3's IMG-10 row: "root user, exposed ports, mutable base tag").
#
# WHAT THIS FILE IS.  Three checks, all driven from the image's own CONFIG
# blob (never a Dockerfile, never a layer):
#
#   IMAGE-CFG-RUNS_AS_ROOT-01 (IMG-06) - `config.User` is absent or root.
#   Report.md §4.1 calls this "the built-artifact counterpart to
#   `IAC-DOCKER-ROOT_USER-01`", and §4.4 explains why it is not redundant
#   with it: `IAC-DOCKER-ROOT_USER-01` reads ONE Dockerfile's own `USER`
#   instruction; this check reads the EFFECTIVE user baked into the merged
#   config across every base layer, which is what the container runtime
#   will actually run as - a base image, a multi-stage copy, or a build arg
#   can all change that without a single line in the Dockerfile a source
#   linter ever sees changing at all.
#
#   IMAGE-CFG-EXPOSED_PORTS-01 (IMG-10) - `config.ExposedPorts` lists one or
#   more ports.  Informational: the built-artifact counterpart to reviewing
#   a Dockerfile's `EXPOSE` lines, which `modules/iac/dockerfile.rules`
#   never checked (report.md §5.3's own IMG-10 row).
#
#   IMAGE-CFG-MUTABLE_BASE_REF-01 (IMG-10) - the image's own record of its
#   base image (see section 3 below) names that base by a mutable TAG
#   rather than an immutable digest.  The built-artifact counterpart to
#   `IAC-DOCKER-LATEST_TAG-01`/`IAC-DOCKER-UNPINNED_DIGEST-01`, and the
#   SAME honesty discipline every other coverage-aware check in this module
#   applies: when the image does not reliably RECORD its base reference at
#   all (the common case - see section 3), this is a declared
#   `coverage_reduction`, never a guess rendered as a clean pass.
#
# WHY THEY ARE DISTRO-AGNOSTIC AND RUN UNCONDITIONALLY.  Unlike
# `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` (modules/image/distro/apk.sh), none
# of the three needs an os-release, an advisory database or a package
# manager - the config blob exists for every OCI/docker image regardless of
# distro. modules/image/run.sh therefore calls all three as soon as
# `image_open` succeeds, before (and independent of) the
# os-release/ecosystem/apk branch below it - an image whose distro this
# module cannot yet identify (v1 is Alpine-only, report.md D2) still gets
# them.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_CONFIG_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_CONFIG_SOURCED=1

# `_image_user_is_root USER` - true when USER (the OCI/docker image config's
# own `config.User` string, docker image spec / OCI image spec) names root or
# names nobody at all.  Per both specs `User` may be `user`, `user:group`,
# `uid`, or `uid:gid`; an EMPTY or ABSENT value means the container runs as
# whatever the base image's own default is, which for the overwhelming
# majority of base images (and for a Dockerfile with no `USER` instruction at
# all, `IAC-DOCKER-ROOT_USER-01`'s own trigger) is root - so absence is
# treated as root here too, never as "unknown, so skip it": a scanner that
# only flagged an EXPLICIT `USER root` would miss the common case entirely,
# which is the direction that reads as a pass.
_image_user_is_root() {
  local user=$1
  [[ -z $user || $user == root || $user == root:* || $user == 0 || $user == 0:* ]]
}

# `image_config_user_get KIND ARCHIVE DESTROOT` - resolves the image's own
# `config.User` field into `_IMAGE_CONFIG_USER`.  A SETTER, never a `$(f)`
# printer, for the same subshell-discard reason every other setter in this
# module states (AGENTS.md, "Things measured on this codebase").
#
# Returns 0 with `_IMAGE_CONFIG_USER` set (possibly empty - an image whose
# config genuinely carries no `User` key is a real, common state, not a
# parse failure) when the config blob itself was readable; returns 1 with
# `_IMAGE_REFUSE_REASON` set (image_config_blob_read's own reason) when it
# was not - the caller (modules/image/run.sh) turns THAT into the
# `image_config_unreadable` coverage_reduction (report.md §4.3), never a
# silent skip and never a guess at whether the image runs as root.
_IMAGE_CONFIG_USER=''
image_config_user_get() {
  local kind=$1 archive=$2 destroot=$3
  _IMAGE_CONFIG_USER=''

  image_config_blob_read "$kind" "$archive" "$destroot" || return 1

  # The docker/OCI image config schema nests the runtime config one level
  # down: {"config": {"User": "...", ...}, "rootfs": {...}, ...}. A config
  # blob with no "config" object at all, or one with no "User" key inside
  # it, is not a parse failure - image_json_leaf's own miss-is-not-an-error
  # contract applies, and _image_user_is_root already treats an absent User
  # as root.
  image_json_leaf _IMAGE_CONFIG_USER "$_IMAGE_CONFIG_PATH" "config"$'\x1f'"User" \
    || _IMAGE_CONFIG_USER=''
  return 0
}

# `image_check_root_user KIND ARCHIVE IMAGE_ID` - the whole check: resolve
# the config blob's User, record the check as run, and emit
# `IMAGE-CFG-RUNS_AS_ROOT-01` when it names root (or is absent).  Owns its
# own scratch directory, released unconditionally - the identical
# acquire-then-erase shape modules/image/run.sh's own os-release block
# already uses.
image_check_root_user() {
  local kind=$1 archive=$2 image_id=$3
  local cfgdir rc=0

  run_record checks_run IMAGE-CFG-RUNS_AS_ROOT-01

  cfgdir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/scoursh-image-config.XXXXXX")
  chmod 700 "$cfgdir" 2>/dev/null || true

  image_config_user_get "$kind" "$archive" "$cfgdir" || rc=$?
  if (( rc != 0 )); then
    local reason=${_IMAGE_REFUSE_REASON:-config_blob_unreadable}
    log_warn "image: could not read the config blob for image '$image_id' ($reason) - the runtime USER could not be determined"
    run_record coverage_reduction "module=image reason=image_config_unreadable image=$image_id detail=$reason"
    run_record coverage_gap "image scanning could not read the config for image '$image_id': its runtime USER could not be determined ($reason). A clean result here is the absence of a test, not the absence of a problem."
    erase_dir "$cfgdir"
    return 0
  fi
  erase_dir "$cfgdir"

  _image_user_is_root "$_IMAGE_CONFIG_USER" || return 0

  finding_new
  finding_set check_id IMAGE-CFG-RUNS_AS_ROOT-01
  finding_set module image
  finding_set title "Image config declares no non-root USER - the effective runtime user is root"
  finding_set base_severity medium
  finding_set confidence high
  finding_set cwe CWE-250
  finding_set owasp A04:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set logical_kind image
  finding_set logical_fqn "image $image_id: config.User"
  finding_set remediation "Add (or fix) a non-root USER in the Dockerfile that built this image's final stage, or in whichever base image sets it, then rebuild and re-scan. A base-image bump alone can change the effective user without any Dockerfile line changing, so re-check this after any FROM tag/digest bump too."
  local shown=${_IMAGE_CONFIG_USER:-<absent>}
  finding_set_evidence "image: $image_id
config.User: $shown
effective_user: root"
  finding_emit
}

# ===========================================================================
# IMG-10 section 2: `image_json_object_keys` - a SECOND, DISTINCT JSON
# reader, and why it is not the "fifth different parser" acquire.sh's own
# header forbids.
# ===========================================================================
#
# `modules/image/acquire.sh`'s `image_json_flatten` is byte-identical BY
# POLICY to four sibling copies elsewhere in this tree (lib/state.sh,
# modules/cloud/aws/engine.sh, modules/dast/crawl_engine.sh, and the engine
# adapters), and its contract is "print one line per SCALAR leaf" - see that
# file's own section 1 header. An object whose value is itself an EMPTY
# object emits NOTHING under that contract: `value()`'s `{` branch returns
# the instant the next byte is `}`, because there is no scalar to report.
#
# That is exactly the docker/OCI image-config shape for `config.ExposedPorts`
# (Go's `map[Port]struct{}`, i.e. `{"80/tcp":{},"443/tcp":{}}`) - the port
# numbers live ENTIRELY in the KEYS, and every value is a structurally empty
# object, so `image_json_flatten`'s leaf rows can never report them, no
# matter how many ports a real image declares: zero and five exposed ports
# produce the identical (empty) set of leaf rows under `config\x1fExposedPorts`.
#
# Enumerating a JSON object's own KEYS, independent of what each key's value
# is, is a genuinely different task from reporting a scalar LEAF - not a
# sixth copy of the same parser with subtly different bugs, which is what
# acquire.sh's header actually guards against for the leaf-extraction task
# (the one every other module in this tree also needs, and where a divergent
# copy would silently read a different byte out of the SAME kind of document
# in different places). No other module in this tree needs object-key
# enumeration today, so this walker lives here, next to its one caller,
# rather than acquiring a sixth `lib/`-hub edge for a need nothing else has.
#
# It reuses the identical string/whitespace-scanning primitives
# (skipws/readstr) `image_json_flatten` has, for the identical correctness
# reason: an ExposedPorts key can legally contain a `}`, a `,` or a `"` byte
# sequence (escaped) with no relation to JSON structure, so a textual grep
# for the shape would be exactly the "read a digest out of a field it never
# meant to" trap acquire.sh's own header describes for a different field.
# And it carries the identical `fail()`-on-malformed-syntax discipline
# `image_json_flatten`'s `value()` has (an unexpected byte where a `"` or a
# `:` was required aborts the parse rather than looping past the end of the
# document) - the config blob is attacker-controlled content exactly like a
# layer is (acquire.sh's own header, section 10), and a malformed one must
# fail loudly, not spin.
#
# `image_json_object_keys FILE PATH` - prints, one per line, the immediate
# child KEY of the JSON object found at the US-joined structural PATH in
# FILE (`""` for the document root) - RAW, still JSON-escaped exactly as
# `image_json_flatten`'s own object keys are (never unescaped here; the one
# caller below unescapes each line itself, mirroring how `image_json_leaf`
# only ever unescapes a `type == s` VALUE, never a key). Prints nothing, and
# returns 0, when PATH names a key whose value is not itself an object (an
# absent ExposedPorts is the ordinary case - Docker's `omitempty` drops the
# key entirely rather than writing `{}`, so "the object at PATH has zero
# keys" and "PATH does not exist at all" are the same observable outcome and
# neither is a parse failure) or when the document does not contain PATH at
# all. Returns 1 on genuinely malformed JSON (the awk program's own `fail()`,
# mirroring `image_json_flatten <file || echo malformed` at every existing
# call site in this module).
image_json_object_keys() {
  local file=$1 want=$2
  [[ -r $file ]] || return 1
  awk -v want="$want" '
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    function readstr(  s, c) {
      i++
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    # skip() consumes exactly one JSON value at the current position without
    # emitting anything, mirroring value()s own object/array recursion in
    # image_json_flatten but with no emit() calls at all - used both to move
    # past a member of the TARGET object (once its key has been printed) and
    # to move past every object/array not on the path to the target.
    function skip(   c, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "\"") { readstr(); return }
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) { if (c == ",") { i++; skipws(); c = substr(doc, i, 1) } }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          skip()
          first = 0
        }
        return
      }
      if (c == "[") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) { if (c == ",") { i++; skipws(); c = substr(doc, i, 1) } }
          if (c == "]") { i++; return }
          skip()
          first = 0
        }
        return
      }
      if (readtok() == "") fail("unparseable value at byte " i)
    }
    # walk(path) is positioned at the START of the value named by PATH (the
    # document root for path==""). When path == want, and that value is an
    # object, this PRINTS every one of its immediate keys (never recursing
    # further - enumerating IS the answer, not a step toward a deeper one)
    # and skip()s each ones own value. Every other object/array is walked
    # structurally, purely to keep path tracking correct, and emits nothing.
    function walk(path,   c, k, idx, first, childpath) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (path == want) {
        if (c == "{") {
          i++
          first = 1
          while (1) {
            skipws()
            c = substr(doc, i, 1)
            if (c == "}") { i++; return }
            if (!first) { if (c == ",") { i++; skipws(); c = substr(doc, i, 1) } }
            if (c == "}") { i++; return }
            if (c != "\"") fail("object key is not a string at byte " i)
            k = readstr()
            skipws()
            if (substr(doc, i, 1) != ":") fail("expected : after object key")
            i++
            print k
            skip()
            first = 0
          }
        }
        # The wanted path names a real leaf/array rather than an object -
        # nothing to enumerate. Consume it so a caller wrapping this in a
        # larger document read never desyncs, and print nothing.
        skip()
        return
      }
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) { if (c == ",") { i++; skipws(); c = substr(doc, i, 1) } }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          childpath = (path == "" ? k : path SEP k)
          walk(childpath)
          first = 0
        }
        return
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) { if (c == ",") { i++; skipws(); c = substr(doc, i, 1) } }
          if (c == "]") { i++; return }
          childpath = (path == "" ? idx : path SEP idx)
          walk(childpath)
          idx++
          first = 0
        }
        return
      }
      skip()
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      walk("")
    }
  ' <"$file"
}

# ===========================================================================
# IMG-10 section 3: `IMAGE-CFG-EXPOSED_PORTS-01`
# ===========================================================================
#
# `image_config_exposed_ports_get KIND ARCHIVE DESTROOT` - resolves the
# config blob's `config.ExposedPorts` object keys into
# `_IMAGE_CONFIG_EXPOSED_PORTS` (an array, unescaped, in the document's own
# order - see `image_check_exposed_ports` for why the CHECK sorts them
# before they ever reach a finding). Same return-value contract as
# `image_config_user_get`: 0 with the array possibly empty (no ExposedPorts
# key at all is the ordinary case, Docker's own `omitempty`) when the config
# blob itself was readable; 1 with `_IMAGE_REFUSE_REASON` set when it was
# not.
declare -ga _IMAGE_CONFIG_EXPOSED_PORTS=()
image_config_exposed_ports_get() {
  local kind=$1 archive=$2 destroot=$3
  _IMAGE_CONFIG_EXPOSED_PORTS=()

  image_config_blob_read "$kind" "$archive" "$destroot" || return 1

  local raw
  while IFS= read -r raw; do
    [[ -n $raw ]] || continue
    _IMAGE_CONFIG_EXPOSED_PORTS+=("$(image_json_unescape "$raw")")
  done < <(image_json_object_keys "$_IMAGE_CONFIG_PATH" "config"$'\x1f'"ExposedPorts")
  return 0
}

# `image_check_exposed_ports KIND ARCHIVE IMAGE_ID` - the whole check.
# Mirrors `image_check_root_user`'s shape exactly (its own scratch
# directory, released unconditionally; the same `image_config_unreadable`
# coverage_reduction/gap on a refusal).
#
# ONE finding listing every declared port, never one finding per port: the
# ports are one fact about one image config, the same "report the whole set
# once" call `passive/headers.sh` makes for a security-header roll-up
# (AGENTS.md, "One finding per check per target, located deterministically"),
# and per-port findings would also collide - the `image` fingerprint profile
# carries no per-port component (lib/findings.sh's frozen table), so N
# separate emits for one image would all hash to the SAME fingerprint and
# `findings_merge`'s dedup would silently keep one.
#
# The port list is `LC_ALL=C sort`ed before it reaches the finding: JSON
# object key order carries no meaning (RFC 8259 has none to give), and two
# runs of the identical unchanged image could see it reordered by nothing
# more than which JSON encoder produced the config - sorting is what keeps
# the evidence text (and so `loc_match_digest`-free but still
# operator-diffed) stable across such a reorder, never a claim about the
# image itself.
image_check_exposed_ports() {
  local kind=$1 archive=$2 image_id=$3
  local cfgdir rc=0

  run_record checks_run IMAGE-CFG-EXPOSED_PORTS-01

  cfgdir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/scoursh-image-config.XXXXXX")
  chmod 700 "$cfgdir" 2>/dev/null || true

  image_config_exposed_ports_get "$kind" "$archive" "$cfgdir" || rc=$?
  if (( rc != 0 )); then
    local reason=${_IMAGE_REFUSE_REASON:-config_blob_unreadable}
    log_warn "image: could not read the config blob for image '$image_id' ($reason) - its exposed ports could not be determined"
    run_record coverage_reduction "module=image reason=image_config_unreadable image=$image_id detail=$reason"
    run_record coverage_gap "image scanning could not read the config for image '$image_id': its exposed ports could not be determined ($reason). A clean result here is the absence of a test, not the absence of a problem."
    erase_dir "$cfgdir"
    return 0
  fi
  erase_dir "$cfgdir"

  (( ${#_IMAGE_CONFIG_EXPOSED_PORTS[@]} > 0 )) || return 0

  local -a ports=()
  while IFS= read -r raw; do
    [[ -n $raw ]] || continue
    ports+=("$raw")
  done < <(printf '%s\n' "${_IMAGE_CONFIG_EXPOSED_PORTS[@]+"${_IMAGE_CONFIG_EXPOSED_PORTS[@]}"}" | LC_ALL=C sort -u)
  local ports_line
  ports_line=$(IFS=,; printf '%s' "${ports[*]}")

  finding_new
  finding_set check_id IMAGE-CFG-EXPOSED_PORTS-01
  finding_set module image
  finding_set title "Image config declares one or more exposed network ports"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set logical_kind image
  finding_set logical_fqn "image $image_id: config.ExposedPorts"
  finding_set remediation "Review whether every port below genuinely needs to be reachable from this container's default network. An unused EXPOSE (or its built-artifact equivalent here) documents intent but does not by itself open anything - the actual exposure is decided by how the container is run (-p/--publish, a Kubernetes Service, ...); treat this as an attack-surface inventory to cross-check against that runtime configuration, not as a vulnerability on its own."
  finding_set_evidence "image: $image_id
config.ExposedPorts: $ports_line
count: ${#ports[@]}"
  finding_emit
}

# ===========================================================================
# IMG-10 section 4: `IMAGE-CFG-MUTABLE_BASE_REF-01`
# ===========================================================================
#
# WHERE A BASE IMAGE REFERENCE CAN BE READ FROM A BUILT ARTIFACT, AND WHY
# THAT IS THE HALF OF THIS CHECK WORTH STATING FIRST.  Unlike `config.User`
# and `config.ExposedPorts`, a docker/OCI image config carries NO required
# field naming the image it was built FROM - `docker build`'s classic
# (non-buildkit) path leaves no trace of it at all, and even a buildkit
# build only records it when the annotation is not itself stripped by a
# later `docker save`/registry round-trip. The one place it CAN legitimately
# appear is the OCI image-spec's own pre-defined annotation pair,
# `org.opencontainers.image.base.name` (the base image's own reference) and
# `.base.digest` (its resolved digest) - image-spec 1.1's "Base Image"
# annotations, which buildkit writes into the CONFIG's own `Labels` map
# (not the manifest) when provenance is requested at build time.
#
# So the honest design here, per this ticket's own brief, is NOT "assume
# every image records its base and flag whichever tag string turns up" -
# most images this module will ever see do not carry this label at all,
# because it is opt-in and buildkit-specific. It is: read
# `config.Labels["org.opencontainers.image.base.name"]` when present, judge
# ONLY that; when absent (or when it holds buildkit's own documented
# `unknown` placeholder, written when a multi-stage build references an
# earlier build stage rather than a real registry image and so has no real
# base reference to name), record a DECLARED coverage limitation - never a
# finding, and never silence either, since a clean scan and "this module
# could not tell" are different facts an operator needs told apart
# (report.md §4.2's honesty discipline, applied to a general limitation of
# built-artifact base-reference recording rather than to one image's own
# unreadable bytes).
#
# `_image_base_ref_is_pinned REF` - true when REF names its base by an
# immutable content digest (`...@sha256:<hex>`) rather than a mutable tag.
# The `[a-z0-9]+:[0-9a-f]{32,}` shape is the SAME digest grammar
# `modules/image/acquire.sh`'s `_image_oci_blob_path` already enforces for
# an OCI blob digest - one algorithm-and-length rule for "this is a real
# content digest", not a second, looser guess at the shape.
_image_base_ref_is_pinned() {
  local ref=$1
  [[ $ref =~ @[a-z0-9]+:[0-9a-f]{32,}$ ]]
}

# `image_config_base_ref_get KIND ARCHIVE DESTROOT` - resolves
# `config.Labels."org.opencontainers.image.base.name"` into
# `_IMAGE_CONFIG_BASE_REF` (possibly empty - a config with no such label is
# the ordinary case, not a parse failure). Same return-value contract as
# `image_config_user_get`.
_IMAGE_CONFIG_BASE_REF=''
image_config_base_ref_get() {
  local kind=$1 archive=$2 destroot=$3
  _IMAGE_CONFIG_BASE_REF=''

  image_config_blob_read "$kind" "$archive" "$destroot" || return 1

  image_json_leaf _IMAGE_CONFIG_BASE_REF "$_IMAGE_CONFIG_PATH" \
    "config"$'\x1f'"Labels"$'\x1f'"org.opencontainers.image.base.name" \
    || _IMAGE_CONFIG_BASE_REF=''
  return 0
}

# `image_check_mutable_base_ref KIND ARCHIVE IMAGE_ID` - the whole check.
# Mirrors `image_check_root_user`'s shape for the config-read/refusal half;
# see this section's own header above for the absent-label branch, which is
# a DECLARED limitation (report.md brief: "honesty over a fabricated
# finding"), not the same `image_config_unreadable` reason the read failure
# branch uses - the two are different facts (the blob could not be read at
# all, versus it was read fine and simply carries no base-image record).
image_check_mutable_base_ref() {
  local kind=$1 archive=$2 image_id=$3
  local cfgdir rc=0

  run_record checks_run IMAGE-CFG-MUTABLE_BASE_REF-01

  cfgdir=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/scoursh-image-config.XXXXXX")
  chmod 700 "$cfgdir" 2>/dev/null || true

  image_config_base_ref_get "$kind" "$archive" "$cfgdir" || rc=$?
  if (( rc != 0 )); then
    local reason=${_IMAGE_REFUSE_REASON:-config_blob_unreadable}
    log_warn "image: could not read the config blob for image '$image_id' ($reason) - its base image reference could not be determined"
    run_record coverage_reduction "module=image reason=image_config_unreadable image=$image_id detail=$reason"
    run_record coverage_gap "image scanning could not read the config for image '$image_id': its base image reference could not be determined ($reason). A clean result here is the absence of a test, not the absence of a problem."
    erase_dir "$cfgdir"
    return 0
  fi
  erase_dir "$cfgdir"

  local ref=$_IMAGE_CONFIG_BASE_REF
  if [[ -z $ref || $ref == unknown ]]; then
    run_record coverage_reduction "module=image reason=base_reference_not_recorded image=$image_id"
    run_record coverage_gap "image scanning could not determine image '$image_id''s base image reference: its config carries no org.opencontainers.image.base.name label (only set by build tools, e.g. buildkit, that opt into OCI base-image provenance annotations - most images do not). This is a stated limitation of built-artifact scanning, never a clean result about this image's base pinning."
    return 0
  fi

  _image_base_ref_is_pinned "$ref" && return 0

  finding_new
  finding_set check_id IMAGE-CFG-MUTABLE_BASE_REF-01
  finding_set module image
  finding_set title "Image's recorded base image reference is a mutable tag, not a content digest"
  finding_set base_severity low
  finding_set confidence high
  finding_set cwe CWE-829
  finding_set owasp A08:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set logical_kind image
  finding_set logical_fqn "image $image_id: config.Labels.org.opencontainers.image.base.name"
  finding_set remediation "Rebuild from the base image's own @sha256:<digest> reference rather than a mutable tag (docker pull <ref> && docker inspect --format '{{index .RepoDigests 0}}' <ref>, or read the digest off the registry), so a later repoint of the tag cannot silently change what this image was built from on the next rebuild. This is the built-artifact counterpart to IAC-DOCKER-UNPINNED_DIGEST-01/IAC-DOCKER-LATEST_TAG-01 - fixing the Dockerfile's own FROM line is what prevents this on the NEXT build; this finding is about the image already built."
  finding_set_evidence "image: $image_id
config.Labels.org.opencontainers.image.base.name: $ref"
  finding_emit
}
