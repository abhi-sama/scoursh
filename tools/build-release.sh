#!/usr/bin/env bash
# tools/build-release.sh - build scoursh's reproducible release tarball.
#
#   tools/build-release.sh [--ref REF] VERSION OUTDIR
#
# Writes OUTDIR/scoursh-VERSION.tar.gz and OUTDIR/SHA256SUMS.  This is the ONE
# artifact every distribution channel is built from (the GitHub Release asset
# itself, and later the Homebrew formula and the OCI image), so three
# properties are load-bearing rather than tidy:
#
# 1. AN EXPLICIT ALLOWLIST, never "the whole tree".  RELEASE_PATHS below names
#    every path that ships; anything not named does not.  The content comes
#    from `git archive REF`, so only COMMITTED bytes can ship: an untracked
#    `data/advisories.db` (~1 GB, operator-built), a `state/` or `reports/`
#    directory, a vendored engine binary sitting in a checkout - none of them
#    can reach a release by accident, whatever the working tree holds.  A
#    second, independent check (`_br_python`'s FORBIDDEN list) refuses the
#    build outright if a forbidden shape reaches the archive anyway, e.g. a
#    later commit that starts TRACKING a vendored engine: the captain's
#    decision is that engines are pinned upstream and never re-hosted, and
#    semgrep's registry rules are not redistributable at all.  An allowlisted
#    path that no longer exists at REF is a hard error rather than a silent
#    omission - a rename must not quietly drop a file out of a release.
#
# 2. REPRODUCIBLE.  Entries are sorted by name; every entry's mtime is
#    SOURCE_DATE_EPOCH (default: REF's own commit time); uid/gid are 0 with
#    empty owner names; modes are normalised to 0755/0644; the gzip header
#    carries no name and a zero timestamp (`gzip -n`'s contract).  The tar and
#    gzip streams are written by python3's stdlib rather than by `tar`/`gzip`,
#    because GNU tar and bsdtar disagree on both option spelling (`--sort` is
#    GNU-only) and output bytes: this way the same REF produces the same
#    sha256 on a Linux runner and on a Mac, which is what lets anyone rebuild
#    a release at its tag and compare checksums.
#
# 3. IT IS AN INSTALL, NOT A CHECKOUT.  Two things are GENERATED into the
#    tarball and never committed:
#      .scoursh-packaged   the installed-copy marker.  Its PRESENCE in the
#                          install root is the whole contract: it tells
#                          scoursh's layout resolver (packaging plan §3 C3) to
#                          keep user state (config, data, state, reports) out
#                          of the install root.  Its content is informational.
#      bin/scoursh, bin/scoursh-vendor, bin/scoursh-sandbox, bin/scoursh-netns
#                          relative symlinks to scan.sh and the three
#                          user-facing tools/ scripts, so a package manager can
#                          link bin/* onto PATH.  All four entry points resolve
#                          their own real location through symlink chains.
#
# The build never touches the network and never runs the scanner.  Proving the
# built tarball actually works as a read-only installed copy is
# tools/smoke-installed.sh's job - the release gate runs both.
#
# Exit codes (docs/FOUNDATION.md tension 14's vocabulary): 0 built, 2 usage,
# 4 bad input (VERSION mismatch, missing allowlisted path, forbidden content,
# no python3/git), 5 an unexpected internal failure.

set -Eeuo pipefail

BR_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$BR_ROOT/lib/core.sh"

# The allowlist.  A directory entry ships every COMMITTED file beneath it;
# `config/*.example` is expanded against REF's own tree below (never against
# the working tree, whose config/ holds an operator's real, secret-bearing
# files).  Deliberately excluded: tests/, bench/, AGENTS.md, CLAUDE.md,
# CONTRIBUTING.md, ROADMAP.md, package.json, .github/, and every tools/ script
# that is developer-only (daily-suite, dast-test-*, gen-status, this build and
# its smoke test).
BR_RELEASE_PATHS=(
  LICENSE
  README.md
  VERSION
  scan.sh
  lib
  modules
  rules
  data
  docs
  tools/vendor-engines.sh
  tools/run-sandboxed.sh
  tools/run-in-netns.sh
)

br_usage() {
  cat <<'EOF'
usage: tools/build-release.sh [--ref REF] VERSION OUTDIR

Builds OUTDIR/scoursh-VERSION.tar.gz (reproducible, from an explicit allowlist
of committed files at REF, default HEAD) and OUTDIR/SHA256SUMS.

VERSION must equal the VERSION file at REF.  SOURCE_DATE_EPOCH, if set,
overrides the entry timestamp (default: REF's commit time).
EOF
}

br_main() {
  local ref=HEAD
  local -a pos=()
  while (( $# > 0 )); do
    case $1 in
      -h | --help) br_usage; return 0 ;;
      --ref)
        (( $# >= 2 )) || { br_usage >&2; die "$SCOURSH_EXIT_USAGE" 'build-release: --ref needs a value'; }
        ref=$2
        shift 2
        ;;
      --) shift; pos+=("$@"); break ;;
      -*) br_usage >&2; die "$SCOURSH_EXIT_USAGE" "build-release: unknown option '$1'" ;;
      *) pos+=("$1"); shift ;;
    esac
  done
  if (( ${#pos[@]} != 2 )); then
    br_usage >&2
    die "$SCOURSH_EXIT_USAGE" 'build-release: expected exactly VERSION and OUTDIR'
  fi
  local version=${pos[0]} outdir=${pos[1]}

  # SemVer 2.0.0 core plus an optional pre-release; no build metadata, since a
  # `+` in an asset name is a URL-encoding hazard for no gain here.
  [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] \
    || die "$SCOURSH_EXIT_USAGE" "build-release: '$version' is not a MAJOR.MINOR.PATCH[-PRERELEASE] version"

  require_cmd git
  require_cmd python3
  cd -- "$BR_ROOT"

  local commit
  commit=$(git rev-parse --verify --quiet "$ref^{commit}") \
    || die "$SCOURSH_EXIT_INPUT" "build-release: '$ref' does not name a commit in $BR_ROOT"

  # A tarball named 1.0.0 whose `scoursh --version` says anything else would be
  # a lie in the one place a user checks, so the VERSION file at REF must agree.
  local ref_version=''
  ref_version=$(git show "$commit:VERSION" 2>/dev/null) \
    || die "$SCOURSH_EXIT_INPUT" "build-release: VERSION is missing at $commit"
  ref_version=${ref_version%$'\n'}
  [[ $ref_version == "$version" ]] \
    || die "$SCOURSH_EXIT_INPUT" "build-release: VERSION at $commit is '$ref_version', not '$version' - bump VERSION and commit before building"

  # Expand the allowlist against REF's tree, and refuse any entry REF lacks.
  local -a paths=() examples=()
  local p
  for p in "${BR_RELEASE_PATHS[@]+"${BR_RELEASE_PATHS[@]}"}"; do
    git cat-file -e "$commit:$p" 2>/dev/null \
      || die "$SCOURSH_EXIT_INPUT" "build-release: allowlisted path '$p' does not exist at $commit - update BR_RELEASE_PATHS in tools/build-release.sh"
    paths+=("$p")
  done
  while IFS= read -r p; do
    [[ $p == config/*.example ]] && examples+=("$p")
  done < <(git ls-tree --name-only "$commit" -- config/)
  (( ${#examples[@]} > 0 )) \
    || die "$SCOURSH_EXIT_INPUT" "build-release: no config/*.example files at $commit"
  paths+=("${examples[@]+"${examples[@]}"}")

  local epoch=${SOURCE_DATE_EPOCH:-}
  if [[ -z $epoch ]]; then
    epoch=$(git log -1 --format=%ct "$commit")
  fi
  [[ $epoch =~ ^[0-9]+$ ]] || die "$SCOURSH_EXIT_USAGE" "build-release: SOURCE_DATE_EPOCH '$epoch' is not an integer"

  mkdir -p -- "$outdir"
  outdir=$(cd -- "$outdir" && pwd -P)
  local src=$SCOURSH_SCRATCH/build-release-src.tar
  local name=scoursh-$version.tar.gz
  git archive --format=tar "$commit" -- "${paths[@]+"${paths[@]}"}" >"$src"

  # A dirty working tree does not change what ships (only REF's committed
  # bytes do), but an operator who edited lib/ and expected the edit in the
  # tarball deserves to hear that it is not there.
  if [[ -n $(git status --porcelain -- "${paths[@]+"${paths[@]}"}" 2>/dev/null) ]]; then
    log_warn "build-release: the working tree has uncommitted changes under allowlisted paths; they are NOT in the tarball (built from $commit)"
  fi

  local summary
  summary=$(_br_python "$src" "$outdir" "$version" "$epoch") \
    || die "$SCOURSH_EXIT_INPUT" "build-release: refused to build $name (see the message above)"

  local sha=${summary%% *}
  printf '%s  %s\n' "$sha" "$name" >"$outdir/SHA256SUMS"
  # lib/core.sh sets a 077 umask for its own scratch files; these two are
  # public release assets.
  chmod 644 "$outdir/$name" "$outdir/SHA256SUMS"
  if [[ -n ${GITHUB_OUTPUT:-} ]]; then
    {
      printf 'tarball=%s\n' "$outdir/$name"
      printf 'sha256=%s\n' "$sha"
      printf 'version=%s\n' "$version"
    } >>"$GITHUB_OUTPUT"
  fi
  printf 'built %s\n' "$outdir/$name"
  printf '  commit  %s\n' "$commit"
  printf '  epoch   %s\n' "$epoch"
  printf '  entries %s\n' "${summary#* }"
  printf '  sha256  %s\n' "$sha"
}

# `_br_python SRC_TAR OUTDIR VERSION EPOCH` - reads git archive's tar stream,
# enforces the forbidden-content rules, adds the generated entries, and writes
# OUTDIR/scoursh-VERSION.tar.gz deterministically (via a temp file and a
# rename, so a failed build never leaves a half-written tarball behind).
# Prints "<sha256> <entry count>" on success; prints a reason to stderr and
# exits non-zero on a refusal.
_br_python() {
  python3 - "$@" <<'PY'
import gzip, hashlib, io, os, re, sys, tarfile

src, outdir, version, epoch = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
prefix = "scoursh-%s" % version
name = "%s.tar.gz" % prefix

# Shapes that must never ship, whatever the allowlist says (see the header).
FORBIDDEN = [
    (re.compile(r"^modules/[^/]+/adapters/[^/]+/(bin|rules)(/|$)"),
     "a vendored engine binary or ruleset (engines are pinned upstream, never re-hosted)"),
    (re.compile(r"\.db$"), "a generated database (advisory/version data is operator-built)"),
    (re.compile(r"^(tests|bench|state|reports)(/|$)"), "test, benchmark, or run-output content"),
    (re.compile(r"(^|/)\.scoursh-packaged$"), "a committed install marker (it is generated here, never committed)"),
    (re.compile(r"^config/(?!.*\.example$)"), "an operator config file (only config/*.example ships)"),
]

GENERATED_LINKS = {
    "bin/scoursh": "../scan.sh",
    "bin/scoursh-vendor": "../tools/vendor-engines.sh",
    "bin/scoursh-sandbox": "../tools/run-sandboxed.sh",
    "bin/scoursh-netns": "../tools/run-in-netns.sh",
}
MARKER = ("scoursh %s packaged install marker, written by tools/build-release.sh.\n"
          "Its presence tells scoursh this is an installed copy, not a checkout:\n"
          "user state (config, data, state, reports) lives outside this directory.\n"
          "Run `scoursh paths` to see where.\n") % version

def fail(msg):
    sys.stderr.write("build-release: %s\n" % msg)
    sys.exit(1)

files = {}   # relpath -> (kind, payload, mode)
with tarfile.open(src, "r:") as tin:
    for m in tin.getmembers():
        if m.type in (tarfile.XGLTYPE, tarfile.XHDTYPE):
            continue
        rel = m.name.rstrip("/")
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            fail("unsafe path in git archive output: %r" % m.name)
        if m.isdir():
            continue          # directories are regenerated below
        for rx, why in FORBIDDEN:
            if rx.search(rel):
                fail("refusing to ship %s: %s" % (rel, why))
        if m.issym():
            target = m.linkname
            resolved = os.path.normpath(os.path.join(os.path.dirname(rel), target))
            if target.startswith("/") or resolved.startswith(".."):
                fail("refusing to ship %s: symlink escapes the tree (-> %s)" % (rel, target))
            files[rel] = ("sym", target, 0o777)
        elif m.isfile():
            data = tin.extractfile(m).read()
            files[rel] = ("file", data, 0o755 if m.mode & 0o100 else 0o644)
        else:
            fail("unsupported entry type in git archive output: %s" % rel)

for required in ("scan.sh", "VERSION", "LICENSE", "lib/core.sh"):
    if required not in files:
        fail("the archive is missing %s" % required)
for link, target in GENERATED_LINKS.items():
    if link in files:
        fail("%s is generated here and must not also be committed" % link)
    if os.path.normpath(os.path.join("bin", target)) not in files:
        fail("%s would dangle: %s is not in the archive" % (link, target))
    files[link] = ("sym", target, 0o777)
files[".scoursh-packaged"] = ("file", MARKER.encode(), 0o644)

dirs = set()
for rel in files:
    parts = rel.split("/")[:-1]
    for i in range(1, len(parts) + 1):
        dirs.add("/".join(parts[:i]))

entries = [(d, ("dir", None, 0o755)) for d in dirs] + list(files.items())
entries.sort(key=lambda e: e[0].encode())   # byte order: a parent sorts before its children

def info(rel, kind, mode):
    ti = tarfile.TarInfo(prefix if rel == "" else "%s/%s" % (prefix, rel))
    ti.mode, ti.mtime = mode, epoch
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.type = {"dir": tarfile.DIRTYPE, "file": tarfile.REGTYPE, "sym": tarfile.SYMTYPE}[kind]
    return ti

raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tout:
    tout.addfile(info("", "dir", 0o755))
    for rel, (kind, payload, mode) in entries:
        ti = info(rel, kind, mode)
        if kind == "file":
            ti.size = len(payload)
            tout.addfile(ti, io.BytesIO(payload))
        else:
            if kind == "sym":
                ti.linkname = payload
            tout.addfile(ti)

tmp = os.path.join(outdir, ".%s.tmp" % name)
with open(tmp, "wb") as fh:
    # filename="" and mtime=0 are `gzip -n`: no name, no timestamp in the header.
    with gzip.GzipFile(filename="", mode="wb", fileobj=fh, compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())
os.replace(tmp, os.path.join(outdir, name))

h = hashlib.sha256()
with open(os.path.join(outdir, name), "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
print("%s %d" % (h.hexdigest(), len(entries) + 1))
PY
}

br_main "$@"
