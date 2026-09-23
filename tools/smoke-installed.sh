#!/usr/bin/env bash
# tools/smoke-installed.sh - the release gate: prove a built tarball works as a
# READ-ONLY, SYMLINKED, INSTALLED copy of scoursh.
#
#   tools/smoke-installed.sh TARBALL [VERSION]
#
# TARBALL is what tools/build-release.sh wrote; its SHA256SUMS must sit beside
# it.  VERSION defaults to the one in the tarball's name.  Every check below is
# a failure mode a packaged scoursh has actually had (packaging plan §2, E1-E4)
# or would silently have if the build regressed, so the gate is strict: any
# check that does not hold fails the release, and nothing is ever skipped.
#
#   1. SHA256SUMS matches the tarball byte for byte.
#   2. The tarball extracts to exactly one scoursh-VERSION/ root carrying the
#      generated install marker and bin/ links, and nothing developer-only
#      (tests/, bench/).
#   3. The extracted tree is made READ-ONLY and entered through a two-level
#      symlink chain on PATH (PATH/scoursh -> ROOT/bin/scoursh -> ../scan.sh),
#      which is what brew, install.sh, and a hand-made ~/.local/bin link all
#      produce (E1: a symlinked entry point used to lose its own lib/).
#   4. `scoursh --version` prints exactly `scoursh VERSION`.
#   5. `scoursh paths` names the extracted tree as the install root and puts
#      state and reports OUTSIDE it, under the (scratch) HOME - an installed
#      copy must never write into its own install root (E3, and E4: on macOS
#      Homebrew the Cellar IS writable, so writes there succeed and are then
#      deleted by the next `brew upgrade`).
#   6. `scoursh-vendor --help` resolves its libraries through its own link.
#   7. A real `scoursh sast` scan of a one-line fixture exits 0, writes a run
#      directory under the reported reports dir whose findings.jsonl carries
#      SAST-INJ-OS_COMMAND-01, and writes state/latest.json under the reported
#      state dir.
#   8. The install tree is byte-for-byte the same path set afterwards.  This
#      is checked separately from the read-only bits because root ignores
#      them: a runner or container running as root would otherwise let an
#      install-root write pass unnoticed.
#
# Each scoursh invocation runs under `env -i` with only HOME, PATH, TMPDIR and
# (if the caller set it) SCOURSH_BASH, so no SCOURSH_*, XDG_* or scratch
# variable leaking from the caller can make a broken layout look healthy.
#
# The gate makes no network call: the fixture scan is sast, which reads only
# local files.  Exit codes: 0 every check held, 1 a check failed (the gate
# refused), 2 usage, 4 missing input (tarball, SHA256SUMS, python3).

set -Eeuo pipefail

SMK_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$SMK_ROOT/lib/core.sh"

SMK_WORK=''
SMK_FAILED=0

# The extracted tree is deliberately made unwritable, and core_cleanup's
# `rm -rf` cannot delete a read-only directory's entries, so write permission
# is restored before the scratch directory is erased.
#
# SMK_WORK is a fresh mktemp directory rather than a fixed name under the
# scratch dir, because a caller that runs the gate several times in one process
# (tests/suites/build-release.sh) shares that scratch dir with every run: a
# fixed name would leave one run's reports/ behind for the next to count.
_smk_cleanup() {
  if [[ -n $SMK_WORK && -d $SMK_WORK ]]; then
    chmod -R u+w "$SMK_WORK" 2>/dev/null || true
    rm -rf -- "$SMK_WORK" 2>/dev/null || true
  fi
  core_cleanup
}
trap _smk_cleanup EXIT

smk_usage() {
  cat <<'EOF'
usage: tools/smoke-installed.sh TARBALL [VERSION]

Extracts TARBALL (built by tools/build-release.sh; SHA256SUMS must sit beside
it) into a read-only directory, links its entry point onto a scratch PATH, and
proves --version, paths, and a real sast scan all work from that installed
layout.  Exit 0 only if every check held.
EOF
}

smk_ok() { printf '  ok    %s\n' "$*"; }

# A failed check is recorded and the gate carries on where later checks still
# mean something, so one run reports every broken property rather than the
# first.  `smk_fatal` is for a failure that makes the remaining checks
# meaningless (nothing extracted, no entry point).
smk_fail() {
  SMK_FAILED=1
  printf '  FAIL  %s\n' "$*" >&2
}
smk_fatal() {
  smk_fail "$*"
  printf 'smoke-installed: FAILED - the release gate refuses this tarball\n' >&2
  exit "$SCOURSH_EXIT_GATE"
}

# `smk_run OUTFILE CMD...` - runs an installed entry point under a scrubbed
# environment, from a scratch working directory; stdout+stderr go to OUTFILE.
# Sets SMK_RC rather than printing it (a `$(...)` caller would lose it).
SMK_RC=0
smk_run() {
  local out=$1
  shift
  local -a envv=(HOME="$SMK_WORK/home" PATH="$SMK_WORK/bin:$PATH" TMPDIR="$SMK_WORK/tmp")
  [[ -n ${SCOURSH_BASH:-} ]] && envv+=(SCOURSH_BASH="$SCOURSH_BASH")
  SMK_RC=0
  (cd -- "$SMK_WORK/cwd" && env -i "${envv[@]+"${envv[@]}"}" "$@") >"$out" 2>&1 || SMK_RC=$?
}

smk_show() {
  local f=$1
  [[ -s $f ]] || return 0
  printf '        --- last lines of output ---\n' >&2
  tail -n 15 -- "$f" | sed 's/^/        | /' >&2
}

# `smk_path_value FILE KEY` - the value of a `KEY: value` line from
# `scoursh paths`, or empty.
smk_path_value() {
  local f=$1 key=$2 line
  while IFS= read -r line; do
    if [[ $line == "$key: "* ]]; then
      printf '%s' "${line#"$key: "}"
      return 0
    fi
  done <"$f"
  return 0
}

# `smk_is_within PATH DIR` - true when PATH is DIR or lies beneath it.  Both
# are compared as given; callers pass physical (pwd -P) paths.
smk_is_within() {
  local p=${1%/} d=${2%/}
  [[ $p == "$d" || $p == "$d"/* ]]
}

# `smk_physical PATH` - PATH with every symlinked directory component
# resolved, or PATH unchanged when it does not exist yet.  macOS's /tmp ->
# /private/tmp is exactly the kind of difference that would make a textual
# "is it inside HOME" comparison lie.
smk_physical() {
  local p=$1
  if [[ -d $p ]]; then
    (cd -- "$p" && pwd -P)
  else
    printf '%s' "$p"
  fi
}

smk_main() {
  case ${1:-} in
    -h | --help) smk_usage; return 0 ;;
  esac
  if (( $# < 1 || $# > 2 )); then
    smk_usage >&2
    die "$SCOURSH_EXIT_USAGE" 'smoke-installed: expected TARBALL [VERSION]'
  fi
  local tarball=$1 version=${2:-}
  [[ -f $tarball ]] || die "$SCOURSH_EXIT_INPUT" "smoke-installed: no such tarball: $tarball"
  tarball=$(cd -- "$(dirname -- "$tarball")" && pwd -P)/$(basename -- "$tarball")
  local base=${tarball##*/}
  if [[ -z $version ]]; then
    [[ $base =~ ^scoursh-(.+)\.tar\.gz$ ]] \
      || die "$SCOURSH_EXIT_USAGE" "smoke-installed: cannot infer VERSION from '$base'; pass it explicitly"
    version=${BASH_REMATCH[1]}
  fi
  [[ $base == "scoursh-$version.tar.gz" ]] \
    || die "$SCOURSH_EXIT_USAGE" "smoke-installed: '$base' is not named scoursh-$version.tar.gz"
  local sums=${tarball%/*}/SHA256SUMS
  [[ -f $sums ]] || die "$SCOURSH_EXIT_INPUT" "smoke-installed: no SHA256SUMS beside $tarball"
  require_cmd python3

  printf 'smoke-installed: %s (as version %s)\n' "$tarball" "$version"

  # --- 1. checksum ----------------------------------------------------------
  # python3's hashlib, not sha256sum/shasum: tools/ is held to tension 24's
  # one-capability-layer rule, and this needs no fallback chain.
  if python3 - "$sums" "$base" "$tarball" <<'PY'
import hashlib, sys
sums, base, path = sys.argv[1:4]
want = [l.split()[0] for l in open(sums) if l.strip() and l.split()[-1].lstrip("*") == base]
h = hashlib.sha256()
with open(path, "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
sys.exit(0 if len(want) == 1 and want[0] == h.hexdigest() else 1)
PY
  then
    smk_ok "SHA256SUMS matches $base"
  else
    smk_fatal "SHA256SUMS has no single matching line for $base"
  fi

  # --- 2. extract and inspect the layout -------------------------------------
  SMK_WORK=$(mktemp -d "$SCOURSH_SCRATCH/smoke.XXXXXX")
  mkdir -p -- "$SMK_WORK"/{root,home,bin,tmp,cwd,fixture}
  SMK_WORK=$(cd -- "$SMK_WORK" && pwd -P)
  local listing=$SMK_WORK/listing
  tar -tzf "$tarball" >"$listing" || smk_fatal "tar cannot list $base"
  local entry
  while IFS= read -r entry; do
    if [[ $entry == /* || $entry == ../* || $entry == */../* || $entry != "scoursh-$version"/* && $entry != "scoursh-$version" ]]; then
      smk_fatal "unexpected tarball entry '$entry' (everything must sit under scoursh-$version/)"
    fi
  done <"$listing"
  tar -xzf "$tarball" -C "$SMK_WORK/root" || smk_fatal "tar cannot extract $base"
  local inst=$SMK_WORK/root/scoursh-$version
  [[ -d $inst ]] || smk_fatal "no scoursh-$version/ directory after extraction"
  inst=$(cd -- "$inst" && pwd -P)

  if [[ -f $inst/.scoursh-packaged ]]; then
    smk_ok 'install marker .scoursh-packaged present'
  else
    smk_fail 'install marker .scoursh-packaged is missing'
  fi
  local link
  for link in scoursh scoursh-vendor scoursh-sandbox scoursh-netns; do
    if [[ -L $inst/bin/$link && -e $inst/bin/$link ]]; then :; else
      smk_fail "bin/$link is missing or dangling"
    fi
  done
  local d
  for d in tests bench state reports; do
    [[ ! -e $inst/$d ]] || smk_fail "developer or run-output directory '$d/' is in the tarball"
  done
  (( SMK_FAILED )) || smk_ok 'layout: bin/ links resolve; no tests/, bench/, state/, reports/'

  # --- 3. read-only install, entered through a symlink chain -----------------
  local before=$SMK_WORK/tree-before after=$SMK_WORK/tree-after
  (cd -- "$inst" && find . -print | LC_ALL=C sort) >"$before"
  chmod -R a-w "$inst"
  ln -s -- "$inst/bin/scoursh" "$SMK_WORK/bin/scoursh"
  ln -s -- "$inst/bin/scoursh-vendor" "$SMK_WORK/bin/scoursh-vendor"
  smk_ok "install root made read-only: $inst"

  # --- 4. --version -----------------------------------------------------------
  local out=$SMK_WORK/out-version got=''
  smk_run "$out" scoursh --version
  IFS= read -r got <"$out" || true
  if (( SMK_RC == 0 )) && [[ $got == "scoursh $version" ]]; then
    smk_ok "scoursh --version -> $got"
  else
    smk_fail "scoursh --version: exit $SMK_RC, printed '$got' (want 'scoursh $version')"
    smk_show "$out"
    smk_fatal 'the installed entry point does not run; no later check can mean anything'
  fi

  # --- 5. paths ---------------------------------------------------------------
  out=$SMK_WORK/out-paths
  smk_run "$out" scoursh paths
  local p_inst p_state p_reports home
  home=$SMK_WORK/home
  p_inst=$(smk_path_value "$out" install)
  p_state=$(smk_path_value "$out" state)
  p_reports=$(smk_path_value "$out" reports)
  if (( SMK_RC != 0 )); then
    smk_fail "scoursh paths exited $SMK_RC"
    smk_show "$out"
  elif [[ -z $p_inst || -z $p_state || -z $p_reports ]]; then
    smk_fail 'scoursh paths did not print install:, state: and reports: lines'
    smk_show "$out"
  else
    if [[ $(smk_physical "$p_inst") == "$inst" ]]; then
      smk_ok "paths: install -> $p_inst"
    else
      smk_fail "paths: install is '$p_inst', want the extracted tree '$inst'"
    fi
    local key val
    for key in state reports; do
      val=$p_state
      [[ $key == reports ]] && val=$p_reports
      if smk_is_within "$val" "$inst"; then
        smk_fail "paths: $key '$val' is INSIDE the read-only install root - the installed-copy layout resolver (packaging plan §3 C3) is missing or not honouring .scoursh-packaged"
      elif ! smk_is_within "$val" "$home"; then
        smk_fail "paths: $key '$val' is outside the install root but not under HOME ($home)"
      else
        smk_ok "paths: $key -> $val (outside the install root, under HOME)"
      fi
    done
  fi

  # --- 6. the second entry point ---------------------------------------------
  out=$SMK_WORK/out-vendor
  smk_run "$out" scoursh-vendor --help
  if (( SMK_RC == 0 )); then
    smk_ok 'scoursh-vendor --help resolves through its link'
  else
    smk_fail "scoursh-vendor --help exited $SMK_RC"
    smk_show "$out"
  fi

  # --- 7. a real sast scan ----------------------------------------------------
  # One line that sast's injection pack reports as SAST-INJ-OS_COMMAND-01.
  printf 'import os\nos.system(input())\n' >"$SMK_WORK/fixture/app.py"
  out=$SMK_WORK/out-sast
  smk_run "$out" scoursh sast --path "$SMK_WORK/fixture"
  if (( SMK_RC != 0 )); then
    smk_fail "scoursh sast exited $SMK_RC (want 0)"
    smk_show "$out"
  else
    smk_ok 'scoursh sast --path <fixture> exited 0'
    local -a runs=()
    local r
    if [[ -n $p_reports && -d $p_reports ]]; then
      for r in "$p_reports"/*/; do
        [[ -d $r ]] && runs+=("${r%/}")
      done
    fi
    if (( ${#runs[@]} != 1 )); then
      smk_fail "expected exactly one run directory under reports '$p_reports', found ${#runs[@]}"
    elif [[ ! -s ${runs[0]}/findings.jsonl ]]; then
      smk_fail "no findings.jsonl in ${runs[0]}"
    # No `-F`: scan_match binds `grep -E`, and GNU grep rejects a second
    # matcher; the id carries no ERE metacharacter, so the match is exact.
    elif scan_match "$SMK_WORK/hits" -e 'SAST-INJ-OS_COMMAND-01' -- "${runs[0]}/findings.jsonl"; then
      smk_ok "findings.jsonl carries SAST-INJ-OS_COMMAND-01 (${runs[0]})"
    else
      smk_fail "findings.jsonl in ${runs[0]} lacks SAST-INJ-OS_COMMAND-01"
    fi
    if [[ -n $p_state && -s $p_state/latest.json ]]; then
      smk_ok "state written: $p_state/latest.json"
    else
      smk_fail "no state/latest.json under the reported state dir '$p_state'"
    fi
  fi

  # --- 8. the install tree is untouched ---------------------------------------
  chmod -R u+w "$inst"
  (cd -- "$inst" && find . -print | LC_ALL=C sort) >"$after"
  if cmp -s -- "$before" "$after"; then
    smk_ok 'install tree unchanged by the run'
  else
    smk_fail 'the run changed the install tree:'
    diff -- "$before" "$after" | sed 's/^/        /' >&2 || true
  fi

  if (( SMK_FAILED )); then
    printf 'smoke-installed: FAILED - the release gate refuses this tarball\n' >&2
    exit "$SCOURSH_EXIT_GATE"
  fi
  printf 'smoke-installed: PASS - %s works as a read-only installed copy\n' "$base"
}

smk_main "$@"
