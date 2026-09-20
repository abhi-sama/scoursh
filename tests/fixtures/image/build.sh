#!/usr/bin/env bash
# tests/fixtures/image/build.sh - regenerate this directory's COMMITTED,
# benign image fixtures (IMG-02).
#
# Run it from anywhere; it writes only inside its own directory:
#
#     bash tests/fixtures/image/build.sh
#
# Nothing in tests/ calls this at test time - the fixtures it writes are
# committed, so a suite reads the same bytes a reviewer read. It exists so
# those bytes are REPRODUCIBLE and so their shape is legible as source rather
# than as an opaque tarball. The hostile archives live in
# tests/suites/image-acquire.sh instead and are built in scratch on every run;
# tests/fixtures/image/mkustar.sh's own header says why they are not committed.
#
# WHAT IS BUILT, AND WHAT EACH ONE IS FOR:
#
#   docker-archive/one-image.tar
#     The ordinary docker-archive shape: `manifest.json` as a
#     top-level ARRAY with one entry, a config blob, three layers. The layers
#     carry a package-database path that is WRITTEN, then WHITED OUT, then
#     WRITTEN AGAIN, which is the case that separates "later wins" from a
#     backwards walk with an early exit - both readings agree on a file
#     written once, so a fixture with only that shape pins nothing.
#
#   docker-archive/two-images.tar
#     Two entries in one manifest.json, each with its own RepoTags. The
#     `reference` selector's positive case, and the refusal case (opening it
#     with no reference at all).
#
#   oci-layout/
#     The other supported archive shape: `oci-layout`, `index.json` with ONE manifest
#     carrying an `org.opencontainers.image.ref.name` annotation, and blobs
#     under `blobs/sha256/`. Its layers carry a DIFFERENT metadata path from
#     the docker-archive fixture's, so a test that read the wrong fixture
#     cannot accidentally pass.
#
# THE BLOB DIGESTS ARE NOT REAL SHA-256 SUMS OF THEIR CONTENT, and that is
# deliberate rather than sloppy: nothing in modules/image/acquire.sh verifies
# a blob against its digest (content-digest verification is a real thing an
# image scanner could do and is not IMG-02's scope), so a fixture whose
# digests were genuine would silently imply a check that does not exist. They
# are fixed hex strings of the right SHAPE, which is what the code does read -
# `_image_oci_blob_path` requires `^[a-z0-9]+:[0-9a-f]{32,}$`.
#
# shellcheck shell=bash

set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$HERE/mkustar.sh"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-image-fixture.XXXXXX")
trap 'rm -rf -- "${WORK:?}"' EXIT

# ---------------------------------------------------------------------------
# Layer tarballs, built first because a docker-save archive nests them.
# ---------------------------------------------------------------------------
# Layer 0: a base with an os-release and an apk database.
L0=$WORK/l0.tar
ustar_begin "$L0"
ustar_add "$L0" 'etc/' 5 '' ''
ustar_add "$L0" 'etc/os-release' 0 '' 'NAME="Fixture Linux"
ID=fixturelinux
VERSION_ID=1.0
'
ustar_add "$L0" 'lib/' 5 '' ''
ustar_add "$L0" 'lib/apk/' 5 '' ''
ustar_add "$L0" 'lib/apk/db/' 5 '' ''
ustar_add "$L0" 'lib/apk/db/installed' 0 '' 'LAYER-0-APK-DB
'
ustar_end "$L0"

# Layer 1: deletes layer 0's apk database with an OCI whiteout, and adds a
# file of its own. This is the layer that makes a backwards walk wrong.
L1=$WORK/l1.tar
ustar_begin "$L1"
ustar_add "$L1" 'lib/' 5 '' ''
ustar_add "$L1" 'lib/apk/' 5 '' ''
ustar_add "$L1" 'lib/apk/db/' 5 '' ''
ustar_add "$L1" 'lib/apk/db/.wh.installed' 0 '' ''
ustar_add "$L1" 'etc/' 5 '' ''
ustar_add "$L1" 'etc/fixture-marker' 0 '' 'LAYER-1
'
ustar_end "$L1"

# Layer 2: writes the apk database back. The final image therefore HAS it,
# with layer 2's content - which a walk that stopped at the whiteout would
# report as absent, and a backwards walk would report as layer 0's.
L2=$WORK/l2.tar
ustar_begin "$L2"
ustar_add "$L2" 'lib/' 5 '' ''
ustar_add "$L2" 'lib/apk/' 5 '' ''
ustar_add "$L2" 'lib/apk/db/' 5 '' ''
ustar_add "$L2" 'lib/apk/db/installed' 0 '' 'LAYER-2-APK-DB
'
ustar_end "$L2"

# A second image's single layer, for the two-image archive.
L9=$WORK/l9.tar
ustar_begin "$L9"
ustar_add "$L9" 'var/' 5 '' ''
ustar_add "$L9" 'var/lib/' 5 '' ''
ustar_add "$L9" 'var/lib/dpkg/' 5 '' ''
ustar_add "$L9" 'var/lib/dpkg/status' 0 '' 'SECOND-IMAGE-DPKG-DB
'
ustar_end "$L9"

# ---------------------------------------------------------------------------
# docker-archive/one-image.tar (shape A, one image, three layers)
# ---------------------------------------------------------------------------
mkdir -p "$HERE/docker-archive"
A=$HERE/docker-archive/one-image.tar
ustar_begin "$A"
ustar_add "$A" 'cfg0.json' 0 '' '{"architecture":"amd64","os":"linux"}'
ustar_add "$A" 'l0/' 5 '' ''
ustar_add_file "$A" 'l0/layer.tar' "$L0"
ustar_add "$A" 'l1/' 5 '' ''
ustar_add_file "$A" 'l1/layer.tar' "$L1"
ustar_add "$A" 'l2/' 5 '' ''
ustar_add_file "$A" 'l2/layer.tar' "$L2"
ustar_add "$A" 'manifest.json' 0 '' '[{"Config":"cfg0.json","RepoTags":["fixture/one:v1"],"Layers":["l0/layer.tar","l1/layer.tar","l2/layer.tar"]}]'
ustar_end "$A"

# ---------------------------------------------------------------------------
# docker-archive/two-images.tar (shape A, two images in one archive)
# ---------------------------------------------------------------------------
B=$HERE/docker-archive/two-images.tar
ustar_begin "$B"
ustar_add "$B" 'cfg0.json' 0 '' '{"architecture":"amd64","os":"linux"}'
ustar_add "$B" 'cfg9.json' 0 '' '{"architecture":"arm64","os":"linux"}'
ustar_add "$B" 'l0/' 5 '' ''
ustar_add_file "$B" 'l0/layer.tar' "$L0"
ustar_add "$B" 'l9/' 5 '' ''
ustar_add_file "$B" 'l9/layer.tar' "$L9"
ustar_add "$B" 'manifest.json' 0 '' '[{"Config":"cfg0.json","RepoTags":["fixture/first:v1"],"Layers":["l0/layer.tar"]},{"Config":"cfg9.json","RepoTags":["fixture/second:v1"],"Layers":["l9/layer.tar"]}]'
ustar_end "$B"

# ---------------------------------------------------------------------------
# oci-layout/ (shape B)
# ---------------------------------------------------------------------------
# Digests are shape-valid placeholders, never real sums - see this file's
# header for why that is deliberate.
OCI=$HERE/oci-layout
rm -rf -- "${OCI:?}"
mkdir -p "$OCI/blobs/sha256"
MAN_D=1111111111111111111111111111111111111111111111111111111111111111
CFG_D=2222222222222222222222222222222222222222222222222222222222222222
LAY0_D=3333333333333333333333333333333333333333333333333333333333333333
LAY1_D=4444444444444444444444444444444444444444444444444444444444444444

printf '%s' '{"imageLayoutVersion":"1.0.0"}' >"$OCI/oci-layout"
printf '%s' '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:'"$MAN_D"'","size":481,"annotations":{"org.opencontainers.image.ref.name":"fixture/oci:v1"}}]}' >"$OCI/index.json"
printf '%s' '{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:'"$CFG_D"'","size":37},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:'"$LAY0_D"'","size":1},{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:'"$LAY1_D"'","size":1}]}' >"$OCI/blobs/sha256/$MAN_D"
printf '%s' '{"architecture":"amd64","os":"linux"}' >"$OCI/blobs/sha256/$CFG_D"

# OCI layer 0: a dpkg database and an os-release.
OL0=$OCI/blobs/sha256/$LAY0_D
ustar_begin "$OL0"
ustar_add "$OL0" 'etc/' 5 '' ''
ustar_add "$OL0" 'etc/os-release' 0 '' 'NAME="Fixture OCI"
ID=fixtureoci
VERSION_ID=2.0
'
ustar_add "$OL0" 'var/' 5 '' ''
ustar_add "$OL0" 'var/lib/' 5 '' ''
ustar_add "$OL0" 'var/lib/dpkg/' 5 '' ''
ustar_add "$OL0" 'var/lib/dpkg/status' 0 '' 'OCI-LAYER-0-DPKG-DB
'
ustar_end "$OL0"

# OCI layer 1: an opaque whiteout over var/lib, which clears the dpkg
# database layer 0 contributed. The final image therefore does NOT carry it -
# the case a reading that only looks for `var/lib/dpkg/.wh.status` gets wrong.
OL1=$OCI/blobs/sha256/$LAY1_D
ustar_begin "$OL1"
ustar_add "$OL1" 'var/' 5 '' ''
ustar_add "$OL1" 'var/lib/' 5 '' ''
ustar_add "$OL1" 'var/lib/.wh..wh..opq' 0 '' ''
ustar_end "$OL1"

printf 'built:\n'
printf '  %s\n' "$A" "$B" "$OCI"
