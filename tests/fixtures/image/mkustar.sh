#!/usr/bin/env bash
# tests/fixtures/image/mkustar.sh - a pure-bash POSIX ustar writer, used to
# build this directory's fixture archives and, at test time, the HOSTILE ones
# tests/suites/image-acquire.sh needs.
#
# WHY THIS EXISTS AT ALL, WHEN `tar -cf` IS RIGHT THERE.  Two reasons, and the
# second is the load-bearing one:
#
#   1. Determinism.  Every fixture archive here has to be byte-reproducible
#      from a script a reviewer can read, on both userlands
#      tools/daily-suite.sh runs.  `tar -cf` bakes in uid/gid/mtime and its
#      own idea of member ordering, and bsdtar and GNU tar disagree about
#      several of them.
#   2. **A hostile archive cannot be built with `tar -cf`, by design.**  The
#      three escapes report.md §1.5 requires this module to refuse - a `..`
#      component, an absolute name, and a symlink whose target leaves the
#      extraction root - are exactly what a well-behaved `tar -cf` refuses to
#      WRITE.  Measured here (bsdtar 3.5.3): `tar -cf` will not put `../x` in
#      an archive, and GNU tar strips the leading `/` off an absolute name
#      with a warning.  So a suite that built its hostile fixtures with `tar`
#      would be testing archives that are not hostile, would pass, and would
#      pin nothing - the exact "a test that passes under both readings" shape
#      AGENTS.md's testing rule exists to prevent.  Writing the headers by
#      hand is the only way to produce the input the control is FOR.
#
# HOSTILE ARCHIVES ARE BUILT AT TEST TIME AND ARE NOT COMMITTED.  A tarball
# carrying `../../victim/canary.txt` is a footgun sitting in a repository -
# someone eventually extracts it by hand to see what it is.  The generator is
# committed instead, which is strictly more informative: the escape is legible
# as source rather than opaque as bytes.  The BENIGN fixtures are committed,
# because they are what the acquisition tests read and a committed fixture is
# one fewer moving part in them; `--rebuild` below regenerates them in place.
#
# Format: POSIX.1-1988 ustar (512-byte header + 512-byte-padded data, two zero
# blocks to end).  Names are capped at 100 bytes - the `prefix` field is not
# used, so a fixture path must stay short.  That is a fixture-writer's
# constraint, not a limitation of anything scoursh reads: it is `tar` that
# reads these back, and it handles every extension.
#
# shellcheck shell=bash

set -Eeuo pipefail

# `_ustar_pad STRING WIDTH` - STRING followed by NUL padding to WIDTH bytes.
_ustar_pad() {
  local s=$1 w=$2 i=${#1}
  printf '%s' "$s"
  while (( i < w )); do printf '\0'; i=$(( i + 1 )); done
}

# `_ustar_oct VALUE WIDTH` - ustar's zero-padded octal, NUL-terminated.
_ustar_oct() { printf '%0*o\0' "$(( $2 - 1 ))" "$1"; }

# `_ustar_header ARCHIVE NAME TYPEFLAG LINKNAME SIZE` - the 512-byte header.
# Split out from ustar_add because a nested layer tarball has to be appended
# BYTE FOR BYTE from a file: a tar contains NUL bytes, and a command
# substitution drops them silently (bash warns, and the archive it builds is
# quietly corrupt - measured while writing these fixtures, which is why
# ustar_add_file exists at all).
_ustar_header() {
  local out=$1 name=$2 type=$3 link=$4 size=$5
  local chk hdr
  hdr=$(mktemp) || return 1
  {
    _ustar_pad "$name" 100
    _ustar_oct 0644 8
    _ustar_oct 0 8
    _ustar_oct 0 8
    _ustar_oct "$size" 12
    _ustar_oct 0 12
    printf '        '
    printf '%s' "$type"
    _ustar_pad "$link" 100
    printf 'ustar\0'
    printf '00'
    _ustar_pad '' 32
    _ustar_pad '' 32
    _ustar_oct 0 8
    _ustar_oct 0 8
    _ustar_pad '' 155
    _ustar_pad '' 12
  } >"$hdr"
  # The ustar checksum is the unsigned sum of every header byte with the
  # checksum field itself read as eight spaces - which is why it is written as
  # spaces above and only replaced afterwards.
  chk=$(od -An -tu1 -v "$hdr" | awk '{for (i = 1; i <= NF; i++) s += $i} END {print s + 0}')
  {
    head -c 148 "$hdr"
    printf '%06o\0 ' "$chk"
    tail -c +157 "$hdr"
  } >>"$out"
  rm -f -- "${hdr:?}"
  return 0
}

# `_ustar_pad_data ARCHIVE SIZE` - NUL-pad the just-written data to a 512-byte
# boundary.
_ustar_pad_data() {
  local out=$1 size=$2 rem i
  rem=$(( (512 - size % 512) % 512 ))
  for (( i = 0; i < rem; i++ )); do printf '\0' >>"$out"; done
}

# `ustar_add ARCHIVE NAME TYPEFLAG LINKNAME CONTENT`
#   TYPEFLAG: 0 regular, 5 directory, 2 symlink, 1 hardlink.
# A directory's NAME must carry its own trailing `/` - that trailing slash is
# what modules/image/acquire.sh's parent-is-a-directory check reads, so a
# fixture that omitted it would be testing a different archive than it looks
# like it is.  CONTENT is text; use ustar_add_file for anything binary.
ustar_add() {
  local out=$1 name=$2 type=$3 link=$4 content=$5
  local size=${#content}
  _ustar_header "$out" "$name" "$type" "$link" "$size" || return 1
  if (( size > 0 )); then
    printf '%s' "$content" >>"$out"
    _ustar_pad_data "$out" "$size"
  fi
  return 0
}

# `ustar_add_file ARCHIVE NAME FILE` - a regular member whose content is FILE,
# copied byte for byte.  This is how a nested layer tarball goes into a
# docker-save archive.
ustar_add_file() {
  local out=$1 name=$2 file=$3 size
  size=$(wc -c <"$file")
  size=${size//[[:space:]]/}
  _ustar_header "$out" "$name" 0 '' "$size" || return 1
  cat -- "$file" >>"$out"
  _ustar_pad_data "$out" "$size"
  return 0
}

# Two 512-byte zero blocks, the end-of-archive marker.
ustar_end() {
  local out=$1 i
  for (( i = 0; i < 1024; i++ )); do printf '\0' >>"$out"; done
}

ustar_begin() { : >"$1"; }
