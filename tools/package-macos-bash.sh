#!/usr/bin/env bash
# tools/package-macos-bash.sh - make the GPL-compliant macOS Bash companion
# release material after tools/build-macos-bash.sh has built the binary.
#
# The platform-neutral scoursh tarball deliberately stays untouched. This
# produces a second archive with the same scoursh-VERSION/ prefix, so users
# extract it over the neutral archive and scan.sh discovers libexec/bash.

set -Eeuo pipefail

PMB_SOURCE_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba
PMB_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

pmb_usage() {
  cat <<'EOF'
usage: tools/package-macos-bash.sh bash-5.3.tar.gz BASH VERSION OUTDIR

Writes OUTDIR/scoursh-VERSION-macos-bash.tar.gz, bash-5.3.tar.gz,
build-macos-bash.sh, and macos-bash-SHA256SUMS. The companion archive carries
libexec/bash, Bash's COPYING, and README-bash.txt under scoursh-VERSION/.
EOF
}

pmb_die() {
  printf 'package-macos-bash: %s\n' "$*" >&2
  exit 4
}

pmb_sha256() {
  python3 - "$1" <<'PY'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], 'rb') as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b''):
        h.update(chunk)
print(h.hexdigest())
PY
}

pmb_main() {
  case ${1:-} in
    -h | --help) pmb_usage; return 0 ;;
  esac
  if (( $# != 4 )); then
    pmb_usage >&2
    pmb_die 'expected bash-5.3.tar.gz, BASH, VERSION, and OUTDIR'
  fi
  local source=$1 binary=$2 version=$3 outdir=$4 got source_dir
  [[ -f $source ]] || pmb_die "source tarball does not exist: $source"
  [[ -f $binary && -x $binary ]] || pmb_die "Bash binary is missing or not executable: $binary"
  [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] \
    || pmb_die "'$version' is not a MAJOR.MINOR.PATCH[-PRERELEASE] version"
  command -v python3 >/dev/null 2>&1 || pmb_die 'needs python3'
  got=$(pmb_sha256 "$source") || pmb_die "could not hash source tarball: $source"
  [[ $got == "$PMB_SOURCE_SHA256" ]] \
    || pmb_die "SHA-256 mismatch for $source (got $got, want $PMB_SOURCE_SHA256)"

  source_dir=$(cd -- "$(dirname -- "$source")" && pwd -P)
  source=$source_dir/$(basename -- "$source")
  mkdir -p -- "$outdir"
  outdir=$(cd -- "$outdir" && pwd -P)
  local asset=scoursh-$version-macos-bash.tar.gz
  local source_asset=bash-5.3.tar.gz build_asset=build-macos-bash.sh sums=macos-bash-SHA256SUMS
  python3 - "$source" "$binary" "$outdir/$asset" "$version" <<'PY'
import gzip, io, sys, tarfile

source, binary, output, version = sys.argv[1:]
copying_name = 'bash-5.3/COPYING'
with tarfile.open(source, 'r:gz') as upstream:
    try:
        copying = upstream.extractfile(copying_name).read()
    except (KeyError, AttributeError):
        raise SystemExit('package-macos-bash: upstream source lacks %s' % copying_name)
with open(binary, 'rb') as fh:
    bash = fh.read()

readme = '''Bundled Bash for macOS\n\nThis archive is a companion to scoursh-%s.tar.gz. Extract the normal scoursh\nrelease first, then extract this archive into the same directory. It supplies\nlibexec/bash, a universal Bash 5.3 binary that lets scoursh run on stock macOS,\nwhose /bin/bash is 3.2 and does not meet scoursh's Bash >= 4.2 requirement.\n\nBash is separate from scoursh and is licensed under GPLv3 or later. COPYING is\nBash's license text. The matching unmodified bash-5.3.tar.gz and\nbuild-macos-bash.sh are release assets alongside this archive, at no charge.\n\nInstall with curl and tar in Terminal: Finder extraction can apply macOS's\nquarantine attribute to this unsigned command-line binary, while curl and\ntar -xzf do not. The binary is not notarized.\n''' % version

prefix = 'scoursh-%s' % version
entries = [
    ('libexec/bash', bash, 0o755),
    ('COPYING', copying, 0o644),
    ('README-bash.txt', readme.encode(), 0o644),
]
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as archive:
    root = tarfile.TarInfo(prefix)
    root.type, root.mode, root.mtime = tarfile.DIRTYPE, 0o755, 0
    root.uid = root.gid = 0; root.uname = root.gname = ''
    archive.addfile(root)
    libexec = tarfile.TarInfo(prefix + '/libexec')
    libexec.type, libexec.mode, libexec.mtime = tarfile.DIRTYPE, 0o755, 0
    libexec.uid = libexec.gid = 0; libexec.uname = libexec.gname = ''
    archive.addfile(libexec)
    for name, data, mode in entries:
        item = tarfile.TarInfo(prefix + '/' + name)
        item.size, item.mode, item.mtime = len(data), mode, 0
        item.uid = item.gid = 0; item.uname = item.gname = ''
        archive.addfile(item, io.BytesIO(data))
with open(output, 'wb') as fh:
    with gzip.GzipFile(filename='', mode='wb', fileobj=fh, compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())
PY
  # In release CI SOURCE already lives at OUTDIR/bash-5.3.tar.gz. Do not ask
  # install to copy a file over itself: BSD and GNU install both reject it.
  if [[ $source != "$outdir/$source_asset" ]]; then
    install -m 644 -- "$source" "$outdir/$source_asset"
  fi
  install -m 755 -- "$PMB_ROOT/tools/build-macos-bash.sh" "$outdir/$build_asset"
  python3 - "$outdir" "$sums" "$asset" "$source_asset" "$build_asset" <<'PY'
import hashlib, os, sys
outdir, sums, *names = sys.argv[1:]
lines = []
for name in names:
    h = hashlib.sha256()
    with open(os.path.join(outdir, name), 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    lines.append('%s  %s\n' % (h.hexdigest(), name))
with open(os.path.join(outdir, sums), 'w') as fh:
    fh.writelines(lines)
PY
  chmod 644 "$outdir/$asset" "$outdir/$source_asset" "$outdir/$sums"
  printf 'package-macos-bash: built %s\n' "$outdir/$asset"
  printf 'package-macos-bash: wrote %s (asset, upstream source, build script)\n' "$outdir/$sums"
}

pmb_main "$@"
