#!/usr/bin/env bash
# tools/build-macos-bash.sh - build the separately distributed, universal
# Bash used by the macOS companion release asset.
#
# This intentionally accepts an already-downloaded upstream tarball. A scan
# never fetches anything, and a release build verifies this exact byte stream
# before it is unpacked. The companion archive and its GPL material are made
# by tools/package-macos-bash.sh.
#
# Usage:
#   tools/build-macos-bash.sh [--verify-reproducible] bash-5.3.tar.gz OUTPUT
#
# --verify-reproducible performs a second, independent universal build and
# refuses unless its bytes are identical to OUTPUT. Release CI always uses it,
# so the build log is an explicit reproducibility record rather than a claim
# inferred from the compiler flags.

set -Eeuo pipefail

BMB_VERSION=5.3
BMB_SOURCE_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba
BMB_WORK=''

bmb_cleanup() {
  if [[ -n ${BMB_WORK:-} && -d $BMB_WORK ]]; then
    rm -rf -- "$BMB_WORK"
  fi
}
trap bmb_cleanup EXIT

bmb_usage() {
  cat <<'EOF'
usage: tools/build-macos-bash.sh [--verify-reproducible] bash-5.3.tar.gz OUTPUT

Builds a universal arm64+x86_64 Bash 5.3 at OUTPUT. SOURCE must be the
unmodified upstream bash-5.3.tar.gz with the documented SHA-256. The source
is verified before extraction. --verify-reproducible builds it twice and
refuses unless the two universal binaries are byte-identical.
EOF
}

bmb_die() {
  printf 'build-macos-bash: %s\n' "$*" >&2
  exit 4
}

bmb_sha256() {
  local file=$1 got
  # This runs before the host check and must be usable under stock /bin/bash
  # 3.2, before lib/core.sh can be sourced. OpenSSL is present on supported
  # macOS releases and avoids a direct shasum/sha256sum portability split.
  command -v openssl >/dev/null 2>&1 \
    || bmb_die 'needs openssl to verify the upstream source'
  got=$(openssl dgst -sha256 < "$file") || return 1
  got=${got##*[[:space:]]}
  [[ $got =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  printf '%s' "$got"
}

# bmb_verify_universal OUTPUT - use lipo's file-first verification grammar.
# Apple lipo's advertised multi-architecture spelling is inconsistent across
# toolchain releases: macOS 26's implementation accepts exactly one arch per
# -verify_arch invocation. Verify each required slice independently instead.
# Keep this separate from the build so its command contract is testable on
# non-macOS hosts with a strict lipo stub.
bmb_verify_universal() {
  local output=$1 arch
  for arch in x86_64 arm64; do
    lipo "$output" -verify_arch "$arch" \
      || bmb_die "universal output is missing the required $arch architecture slice"
  done
}

# bmb_build_universal PREFIX OUTPUT - build fresh source and build trees below
# PREFIX, then join their slices at OUTPUT. PREFIX differs between the two
# reproducibility passes so no object, generated header, or configured Makefile
# can be reused accidentally.
bmb_build_universal() {
  local prefix=$1 output=$2 source arm x86 cpus
  source=$prefix/bash-$BMB_VERSION
  mkdir -p -- "$prefix"
  tar -xzf "$BMB_TARBALL" -C "$prefix"
  [[ -x $source/configure ]] || bmb_die "source archive did not unpack bash-$BMB_VERSION/configure"

  cpus=$(sysctl -n hw.ncpu 2>/dev/null || printf '2')
  [[ $cpus =~ ^[1-9][0-9]*$ ]] || cpus=2

  bmb_build_slice "$source" "$prefix/build-arm64" arm64 '' 11.0 "$cpus"
  bmb_build_slice "$source" "$prefix/build-x86_64" x86_64 x86_64-apple-darwin 10.13 "$cpus"
  arm=$prefix/build-arm64/bash
  x86=$prefix/build-x86_64/bash
  [[ -x $arm && -x $x86 ]] || bmb_die 'one or both architecture builds did not produce bash'

  lipo -create "$arm" "$x86" -output "$output"
  chmod 755 "$output"
  bmb_verify_universal "$output"
}

# bmb_build_slice SOURCE BUILDDIR ARCH HOST-OR-EMPTY DEPLOYMENT JOBS
bmb_build_slice() {
  local source=$1 builddir=$2 arch=$3 host=$4 deployment=$5 jobs=$6 started elapsed
  started=$(date +%s)
  mkdir -p -- "$builddir"
  (
    cd -- "$builddir"
    export MACOSX_DEPLOYMENT_TARGET=$deployment
    export CC="clang -arch $arch"
    export CFLAGS="-O2 -arch $arch"
    export LDFLAGS="-arch $arch"
    if [[ -n $host ]]; then
      "$source/configure" "--host=$host" \
        --without-bash-malloc --disable-nls --disable-readline --disable-history \
        --disable-bang-history --enable-progcomp --with-curses=no
    else
      "$source/configure" \
        --without-bash-malloc --disable-nls --disable-readline --disable-history \
        --disable-bang-history --enable-progcomp --with-curses=no
    fi
    make -j "$jobs" bash
  )
  elapsed=$(( $(date +%s) - started ))
  printf 'build-macos-bash: %s slice (deployment target %s) built in %ss\n' \
    "$arch" "$deployment" "$elapsed"
}

bmb_check_linkage() {
  local output=$1 arch dep deps
  # A universal otool listing has one filename heading for each slice. Query
  # them separately so neither heading can be mistaken for a dependency.
  for arch in arm64 x86_64; do
    deps=$(otool -L -arch "$arch" "$output" | sed '1d; s/^[[:space:]]*\([^[:space:]]*\).*/\1/')
    [[ -n $deps ]] || bmb_die "otool reported no dynamic dependencies for $arch"
    while IFS= read -r dep; do
      case $dep in
        /usr/lib/libSystem.B.dylib | /usr/lib/libiconv.2.dylib) ;;
        *) bmb_die "unexpected $arch dynamic dependency: $dep" ;;
      esac
    done <<<"$deps"
  done
  # `lipo` retains the linker-generated per-slice ad-hoc code directories,
  # but macOS's `codesign --verify` does not treat that fat binary as a
  # separately signed code object. We deliberately do not re-sign it: the
  # companion is unsigned and must not imply Developer ID signing. Verify the
  # embedded linker metadata instead, as measured for this recipe.
  local signing
  signing=$(codesign -dv --verbose=2 "$output" 2>&1) \
    || bmb_die 'could not inspect linker-generated code-signing metadata'
  [[ $signing == *'Signature=adhoc'* && $signing == *'linker-signed'* ]] \
    || bmb_die 'universal output lacks the expected linker-generated ad-hoc metadata'
}

bmb_main() {
  local verify=false
  case ${1:-} in
    -h | --help) bmb_usage; return 0 ;;
    --verify-reproducible) verify=true; shift ;;
  esac
  if (( $# != 2 )); then
    bmb_usage >&2
    bmb_die 'expected bash-5.3.tar.gz and OUTPUT'
  fi
  BMB_TARBALL=$1
  local output=$2 got parent second
  [[ -f $BMB_TARBALL ]] || bmb_die "source tarball does not exist: $BMB_TARBALL"
  got=$(bmb_sha256 "$BMB_TARBALL") || bmb_die "could not hash source tarball: $BMB_TARBALL"
  [[ $got == "$BMB_SOURCE_SHA256" ]] \
    || bmb_die "SHA-256 mismatch for $BMB_TARBALL (got $got, want $BMB_SOURCE_SHA256)"

  [[ $(uname -s) == Darwin ]] || bmb_die 'must run on macOS: it needs Apple clang, lipo, otool, and codesign'
  local tool
  for tool in clang lipo otool codesign make tar; do
    command -v "$tool" >/dev/null 2>&1 || bmb_die "needs $tool on PATH"
  done

  parent=$(dirname -- "$output")
  mkdir -p -- "$parent"
  parent=$(cd -- "$parent" && pwd -P)
  output=$parent/$(basename -- "$output")
  BMB_WORK=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-macos-bash.XXXXXX")

  bmb_build_universal "$BMB_WORK/first" "$output"
  bmb_check_linkage "$output"
  if [[ $verify == true ]]; then
    second=$BMB_WORK/bash-second
    bmb_build_universal "$BMB_WORK/second" "$second"
    bmb_check_linkage "$second"
    cmp -s "$output" "$second" \
      || bmb_die 'reproducibility check failed: independent universal builds differ'
    printf 'build-macos-bash: reproducibility: PASS (independent universal builds are byte-identical)\n'
  else
    printf 'build-macos-bash: reproducibility: not checked (pass --verify-reproducible to prove it)\n'
  fi
  printf 'build-macos-bash: built %s\n' "$output"
  lipo -info "$output"
  otool -L "$output"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  bmb_main "$@"
fi
