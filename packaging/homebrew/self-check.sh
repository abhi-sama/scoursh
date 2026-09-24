#!/bin/sh
# Validate the Homebrew formula against a release-shaped local archive.
# Usage: packaging/homebrew/self-check.sh /absolute/path/scoursh-X.Y.Z.tar.gz

set -eu

say() {
  printf '%s\n' "$*" >&2
}

die() {
  say "homebrew self-check: $*"
  exit 2
}

if ! command -v brew >/dev/null 2>&1; then
  say "homebrew self-check: brew is not installed; skipping formula validation."
  exit 0
fi

[ "$#" -eq 1 ] || die "usage: $0 /absolute/path/scoursh-X.Y.Z.tar.gz"
[ -f "$1" ] || die "release tarball does not exist: $1"

case $1 in
  /*) archive=$1 ;;
  *) archive=$(cd -P "$(dirname "$1")" && pwd -P)/$(basename "$1") ;;
esac

version_member=$(tar -tzf "$archive" | awk -F/ 'NF == 2 && $2 == "VERSION" { print; exit }')
[ -n "$version_member" ] || die "release tarball has no top-level VERSION file"
version=$(tar -xOzf "$archive" "$version_member" | tr -d '\r\n')
case $version in
  ''|*[!0-9A-Za-z.+-]*) die "unsafe VERSION in release tarball: $version" ;;
esac

marker_member=$(tar -tzf "$archive" | awk -F/ 'NF == 2 && $2 == ".scoursh-packaged" { print; exit }')
[ -n "$marker_member" ] || die "release tarball is missing .scoursh-packaged"

if command -v shasum >/dev/null 2>&1; then
  sha256=$(shasum -a 256 "$archive" | awk '{ print $1 }')
elif command -v sha256sum >/dev/null 2>&1; then
  sha256=$(sha256sum "$archive" | awk '{ print $1 }')
else
  die "need shasum or sha256sum to hash the release tarball"
fi

brew list --versions scoursh >/dev/null 2>&1 \
  && die "scoursh is already installed; uninstall it before this isolated check"

root=$(cd -P "$(dirname "$0")/../.." && pwd -P)
template=$root/packaging/homebrew/scoursh.rb
[ -f "$template" ] || die "formula template not found: $template"

work=$(mktemp -d "${TMPDIR:-/tmp}/scoursh-homebrew.XXXXXX")
installed=0
tap_active=0
tap_name=scoursh-formula-check-$$/tap
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$installed" -eq 1 ]; then
    brew uninstall --force "$tap_name/scoursh" >/dev/null 2>&1 || status=1
  fi
  if [ "$tap_active" -eq 1 ]; then
    brew untap --force "$tap_name" >/dev/null 2>&1 || status=1
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

local_archive=$work/scoursh-$version.tar.gz
ln -s "$archive" "$local_archive"
escaped_archive=$(printf '%s' "$local_archive" | sed 's/[&|\\]/\\&/g')
formula=$work/scoursh.rb
sed \
  -e "s|https://github.com/abhi-sama/scoursh/releases/download/v@VERSION@/scoursh-@VERSION@.tar.gz|file://$escaped_archive|" \
  -e "s/@SHA256@/$sha256/" \
  "$template" >"$formula"

tap_dir=$work/tap
mkdir -p "$tap_dir/Formula"
cp "$formula" "$tap_dir/Formula/scoursh.rb"
git -C "$tap_dir" init -q
git -C "$tap_dir" add Formula/scoursh.rb
git -C "$tap_dir" -c user.name='scoursh formula check' \
  -c user.email='scoursh-formula-check@localhost' commit -qm 'formula check'
brew tap "$tap_name" "$tap_dir"
tap_active=1
formula_name=$tap_name/scoursh

say "homebrew self-check: auditing formula"
brew audit --strict --new --formula "$formula_name"
say "homebrew self-check: installing from local release tarball"
brew install --build-from-source --formula "$formula_name"
installed=1
say "homebrew self-check: running formula test"
brew test "$formula_name"
say "homebrew self-check: passed"
