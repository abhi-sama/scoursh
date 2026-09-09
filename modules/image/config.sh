#!/usr/bin/env bash
# modules/image/config.sh - the container-image module's CONFIG-BLOB check
# (IMG-06, data/scoursh-image-scan-design/report.md §4.1's IMAGE-CFG-* row).
#
# WHAT THIS FILE IS.  `IMAGE-CFG-RUNS_AS_ROOT-01`: the image's CONFIG blob
# (not a Dockerfile, not any layer) carries no `User`, or an explicitly-root
# one.  Report.md §4.1 calls this "the built-artifact counterpart to
# `IAC-DOCKER-ROOT_USER-01`", and §4.4 explains exactly what that means and
# why it is not redundant with it: `IAC-DOCKER-ROOT_USER-01` reads ONE
# Dockerfile's own `USER` instruction; this check reads the EFFECTIVE user
# baked into the merged config across every base layer, which is what the
# container runtime will actually run as - a base image, a multi-stage copy,
# or a build arg can all change that without a single line in the Dockerfile
# a source linter ever sees changing at all.
#
# WHY IT IS DISTRO-AGNOSTIC AND RUNS UNCONDITIONALLY.  Unlike
# `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` (modules/image/distro/apk.sh), this
# check needs no os-release, no advisory database and no package manager at
# all - the config blob exists for every OCI/docker image regardless of
# distro. modules/image/run.sh therefore calls this as soon as `image_open`
# succeeds, before (and independent of) the os-release/ecosystem/apk branch
# below it - an image whose distro this module cannot yet identify (v1 is
# Alpine-only, report.md D2) still gets this check.
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
