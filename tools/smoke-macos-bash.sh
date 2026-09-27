#!/usr/bin/env bash
# tools/smoke-macos-bash.sh - release gate for the macOS Bash companion asset.
#
# The platform-neutral tarball is extracted twice. One copy is the reference,
# run with the built Bash supplied through SCOURSH_BASH. The other receives
# the companion archive, is made read-only, and starts under /bin/bash with a
# fake PATH/bash that exits 99. scan.sh must re-exec its adjacent libexec/bash
# before PATH is consulted, and the normalized findings must match reference.

set -Eeuo pipefail

SMB_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$SMB_ROOT/lib/core.sh"

SMB_WORK=''
smb_cleanup() {
  if [[ -n ${SMB_WORK:-} && -d $SMB_WORK ]]; then
    chmod -R u+w "$SMB_WORK" 2>/dev/null || true
    rm -rf -- "$SMB_WORK" 2>/dev/null || true
  fi
  core_cleanup
}
trap smb_cleanup EXIT

smb_usage() {
  cat <<'EOF'
usage: tools/smoke-macos-bash.sh TARBALL MACOS_BASH_TARBALL [VERSION]

Extracts the platform-neutral release and its macOS Bash companion as read-only
installed copies. It proves scan.sh uses libexec/bash without SCOURSH_BASH or a
working PATH/bash, then compares normalized SAST findings to the neutral copy.
EOF
}

smb_die() {
  printf 'smoke-macos-bash: %s\n' "$*" >&2
  exit "$SCOURSH_EXIT_GATE"
}

smb_sha_matches() {
  local sums=$1 name=$2 asset=$3
  python3 - "$sums" "$name" "$asset" <<'PY'
import hashlib, sys
sums, name, asset = sys.argv[1:]
wants = [line.split()[0] for line in open(sums) if line.split() and line.split()[-1].lstrip('*') == name]
h = hashlib.sha256()
with open(asset, 'rb') as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b''):
        h.update(chunk)
sys.exit(0 if len(wants) == 1 and wants[0] == h.hexdigest() else 1)
PY
}

smb_run() { # OUT HOME PATH_PREFIX EXTRA_ENV... -- COMMAND...
  local out=$1 home=$2 path_prefix=$3
  shift 3
  local -a envv=(HOME="$home" PATH="$path_prefix:/usr/bin:/bin:/usr/sbin:/sbin" TMPDIR="$SMB_WORK/tmp")
  while [[ ${1:-} != -- ]]; do envv+=("$1"); shift; done
  shift
  SMB_RC=0
  (cd -- "$SMB_WORK/cwd" && env -i "${envv[@]+"${envv[@]}"}" "$@") >"$out" 2>&1 || SMB_RC=$?
}

smb_find_run() {
  local reports=$1 out
  out=$(find "$reports" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | LC_ALL=C sort || true)
  [[ $(printf '%s\n' "$out" | sed '/^$/d' | wc -l | tr -d ' ') == 1 ]] || return 1
  printf '%s' "$out"
}

smb_main() {
  case ${1:-} in
    -h | --help) smb_usage; return 0 ;;
  esac
  if (( $# < 2 || $# > 3 )); then
    smb_usage >&2
    die "$SCOURSH_EXIT_USAGE" 'smoke-macos-bash: expected TARBALL MACOS_BASH_TARBALL [VERSION]'
  fi
  local tarball=$1 companion=$2 version=${3:-} base cbase sums prefix ref bundled binary
  [[ -f $tarball ]] || die "$SCOURSH_EXIT_INPUT" "smoke-macos-bash: no such platform tarball: $tarball"
  [[ -f $companion ]] || die "$SCOURSH_EXIT_INPUT" "smoke-macos-bash: no such macOS companion: $companion"
  base=$(basename -- "$tarball")
  cbase=$(basename -- "$companion")
  if [[ -z $version ]]; then
    [[ $base =~ ^scoursh-(.+)\.tar\.gz$ ]] || die "$SCOURSH_EXIT_USAGE" "smoke-macos-bash: cannot infer version from $base"
    version=${BASH_REMATCH[1]}
  fi
  [[ $base == "scoursh-$version.tar.gz" && $cbase == "scoursh-$version-macos-bash.tar.gz" ]] \
    || die "$SCOURSH_EXIT_USAGE" 'smoke-macos-bash: asset names do not match one VERSION'
  sums=$(dirname -- "$companion")/macos-bash-SHA256SUMS
  [[ -f $sums ]] || die "$SCOURSH_EXIT_INPUT" "smoke-macos-bash: missing $sums"
  smb_sha_matches "$sums" "$cbase" "$companion" || smb_die 'companion SHA-256 does not match macos-bash-SHA256SUMS'

  prefix=scoursh-$version
  SMB_WORK=$(mktemp -d "$SCOURSH_SCRATCH/macos-bash-smoke.XXXXXX")
  mkdir -p -- "$SMB_WORK"/{reference,bundled,ref-home,bundled-home,trap,tmp,cwd,fixture}
  printf '#!/bin/sh\necho invoked >>"%s"\nexit 99\n' "$SMB_WORK/fake-bash.log" >"$SMB_WORK/trap/bash"
  chmod 755 "$SMB_WORK/trap/bash"
  printf 'import os\nos.system(input())\n' >"$SMB_WORK/fixture/app.py"

  tar -xzf "$tarball" -C "$SMB_WORK/reference" || smb_die 'cannot extract the platform tarball'
  tar -xzf "$tarball" -C "$SMB_WORK/bundled" || smb_die 'cannot extract the platform tarball for overlay'
  tar -xzf "$companion" -C "$SMB_WORK/bundled" || smb_die 'cannot extract the macOS companion tarball'
  ref=$SMB_WORK/reference/$prefix
  bundled=$SMB_WORK/bundled/$prefix
  binary=$bundled/libexec/bash
  [[ -x $binary ]] || smb_die 'companion archive did not provide executable libexec/bash'
  [[ -f $bundled/COPYING && -f $bundled/README-bash.txt ]] || smb_die 'companion archive is missing COPYING or README-bash.txt'
  (cd -- "$bundled" && find . -print | LC_ALL=C sort) >"$SMB_WORK/bundled-before"
  chmod -R a-w "$ref" "$bundled"

  # The reference is the original platform-neutral archive re-execed through
  # the same built binary explicitly. The candidate run immediately below
  # deliberately removes that override.
  smb_run "$SMB_WORK/reference.out" "$SMB_WORK/ref-home" "$SMB_WORK/trap" \
    "SCOURSH_BASH=$binary" -- /bin/bash "$ref/scan.sh" sast --path "$SMB_WORK/fixture" --jobs 4
  (( SMB_RC == 0 )) || { tail -n 30 "$SMB_WORK/reference.out" >&2 || true; smb_die "reference scan exited $SMB_RC"; }
  smb_run "$SMB_WORK/bundled.out" "$SMB_WORK/bundled-home" "$SMB_WORK/trap" \
    -- /bin/bash "$bundled/scan.sh" sast --path "$SMB_WORK/fixture" --jobs 4
  (( SMB_RC == 0 )) || { tail -n 30 "$SMB_WORK/bundled.out" >&2 || true; smb_die "bundled scan exited $SMB_RC"; }
  [[ ! -s $SMB_WORK/fake-bash.log ]] || smb_die 'PATH/bash was invoked; scan.sh did not stay on the bundled Bash path'

  local ref_run bundled_run
  ref_run=$(smb_find_run "$SMB_WORK/ref-home/.local/state/scoursh/reports") || smb_die 'reference scan did not produce exactly one report directory'
  bundled_run=$(smb_find_run "$SMB_WORK/bundled-home/.local/state/scoursh/reports") || smb_die 'bundled scan did not produce exactly one report directory'
  if ! python3 - "$ref_run/findings.jsonl" "$bundled_run/findings.jsonl" <<'PY'
import json, sys
def stable(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            item = json.loads(line)
            for key in ('first_seen', 'last_seen', 'status'):
                item.pop(key, None)
            rows.append(item)
    return sorted(rows, key=lambda item: item['fingerprint'])
sys.exit(0 if stable(sys.argv[1]) == stable(sys.argv[2]) else 1)
PY
  then
    smb_die 'bundled and platform-neutral scans emitted different normalized findings'
  fi
  (cd -- "$bundled" && find . -print | LC_ALL=C sort) >"$SMB_WORK/bundled-after"
  cmp -s "$SMB_WORK/bundled-before" "$SMB_WORK/bundled-after" \
    || smb_die 'the read-only bundled install tree changed during the scan'
  printf 'smoke-macos-bash: PASS - bundled Bash ran with no SCOURSH_BASH and no usable PATH/bash; findings match\n'
}

smb_main "$@"
