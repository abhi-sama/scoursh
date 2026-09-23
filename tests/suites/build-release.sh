#!/usr/bin/env bash
# tests/suites/build-release.sh - tools/build-release.sh (the reproducible
# release tarball) and tools/smoke-installed.sh (the release gate).
#
# Each section names the reading it fails under:
#
#   A. input refusals - a build that accepted a VERSION disagreeing with the
#      VERSION file would ship a tarball whose `--version` lies.
#   B. contents - an allowlist that leaked tests/, an operator config, or a
#      developer tool, or that dropped the install marker or a bin/ link.
#   C. reproducibility - a build that stamped wall-clock time, the builder's
#      uid, or unsorted entries (two builds of one commit would differ).
#   D. only COMMITTED bytes ship - a build that walked the working tree would
#      ship an untracked advisory DB, a vendored engine, or config/scope.conf;
#      a build that trusted the allowlist alone would ship a tracked engine
#      binary; a build that skipped a missing path would silently shrink.
#   E. the gate against the real tarball - see that section for how it reads
#      the installed-layout resolver (packaging plan §3 C3) landing or not.
#   F. gate mutations - a gate whose checks were vacuous would pass a tarball
#      with a wrong checksum, a lying VERSION, a missing library, no marker,
#      or an entry outside its root.
#
# Nothing here reaches the network.  Every build writes into scratch; the one
# repository mutation it needs (section D) happens in a throwaway clone.
#
# Check ids are deliberately never spelled in this file: tools/gen-status.sh
# attributes a rule pack to the first suite naming one of its ids, and this
# file sorts early (see AGENTS.md's bench/ notes).
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

BUILD=$ROOT/tools/build-release.sh
GATE=$ROOT/tools/smoke-installed.sh
W=$SCOURSH_SCRATCH/build-release-suite
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

V=$(git -C "$ROOT" show HEAD:VERSION)
V=${V%$'\n'}
EPOCH=$(git -C "$ROOT" log -1 --format=%ct HEAD)
NAME=scoursh-$V.tar.gz

# `_run OUT CMD...` - sets RC; stdout+stderr land in OUT.
RC=0
_run() {
  local out=$1
  shift
  RC=0
  ( "$@" ) >"$out" 2>&1 || RC=$?
}

# `_inspect TARBALL` - one fact per line about every entry, for assertions.
_inspect() {
  python3 - "$1" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as t:
    for m in t.getmembers():
        kind = "d" if m.isdir() else "l" if m.issym() else "f" if m.isfile() else "?"
        print("%s %s %o %d %d %r %r %d %s" % (kind, m.name, m.mode, m.uid, m.gid,
              m.uname, m.gname, m.mtime, m.linkname))
PY
}

# ---------------------------------------------------------------------------
printf '== A. input refusals ==\n'
t_case 'input refusals'
assert_status 2 'no arguments is a usage error' bash "$BUILD"
assert_status 2 'a non-semver VERSION is a usage error' bash "$BUILD" 1.0 "$W/a"
_run "$W/a.out" bash "$BUILD" 99.0.0 "$W/a"
assert_eq 4 "$RC" 'a VERSION that disagrees with the VERSION file is refused (exit 4)'
assert_contains "$(cat "$W/a.out")" 'bump VERSION' 'the refusal says to bump VERSION'
assert_file_absent "$W/a/scoursh-99.0.0.tar.gz" 'and no tarball is written'
assert_status 4 'an unknown --ref is refused (exit 4)' bash "$BUILD" --ref no-such-ref-xyz "$V" "$W/a"

# ---------------------------------------------------------------------------
printf '== B. contents ==\n'
t_case 'contents'
_run "$W/b.out" bash "$BUILD" "$V" "$W/b"
assert_eq 0 "$RC" "tools/build-release.sh $V exits 0"
TB=$W/b/$NAME
assert_file_exists "$TB" "$NAME is written"
sums=$(cat "$W/b/SHA256SUMS")
if [[ $sums =~ ^[0-9a-f]{64}\ \ $NAME$ ]]; then
  _t_ok 'SHA256SUMS is one "<sha256>  <name>" line (sha256sum -c / shasum -a 256 -c format)'
else
  _t_no 'SHA256SUMS is one "<sha256>  <name>" line' "got: [$sums]"
fi
assert_contains "$(cat "$W/b.out")" "sha256  ${sums%% *}" 'the build prints the same sha256 it recorded'

_inspect "$TB" >"$W/b.facts"
facts=$(cat "$W/b.facts")
names=$(awk '{print $2}' "$W/b.facts")
P=scoursh-$V
for want in "$P/scan.sh" "$P/VERSION" "$P/LICENSE" "$P/README.md" "$P/.scoursh-packaged" \
  "$P/lib/core.sh" "$P/rules/redaction.rules" "$P/data/cis-mappings" \
  "$P/data/aws-readonly-allow.txt" "$P/config/scope.conf.example" \
  "$P/tools/vendor-engines.sh" "$P/tools/run-sandboxed.sh" "$P/tools/run-in-netns.sh" \
  "$P/docs/USAGE.md"; do
  assert_contains $'\n'"$names"$'\n' $'\n'"$want"$'\n' "ships $want"
done
for pair in scoursh:../scan.sh scoursh-vendor:../tools/vendor-engines.sh \
  scoursh-sandbox:../tools/run-sandboxed.sh scoursh-netns:../tools/run-in-netns.sh; do
  assert_contains "$facts" "l $P/bin/${pair%%:*} 777 0 0 '' '' $EPOCH ${pair#*:}" \
    "bin/${pair%%:*} is a relative link to ${pair#*:}"
done
for bad in tests bench .github AGENTS.md CLAUDE.md CONTRIBUTING.md ROADMAP.md package.json \
  tools/daily-suite.sh tools/gen-status.sh tools/build-release.sh tools/smoke-installed.sh \
  tools/dast-test-target.sh config/scope.conf state reports; do
  if [[ $'\n'"$names" == *$'\n'"$P/$bad"$'\n'* || $'\n'"$names" == *$'\n'"$P/$bad/"* ]]; then
    _t_no "does not ship $bad" "found $P/$bad in the tarball"
  else
    _t_ok "does not ship $bad"
  fi
done
outside=$(awk -v p="$P" '$2 != p && index($2, p "/") != 1' "$W/b.facts")
assert_eq '' "$outside" "every entry sits under $P/"
assert_contains "$facts" "f $P/scan.sh 755 " 'scan.sh keeps its executable bit (0755)'
assert_contains "$facts" "f $P/lib/core.sh 644 " 'a library is 0644'
odd=$(awk -v e="$EPOCH" '$4 != 0 || $5 != 0 || $6 != "'"''"'" || $7 != "'"''"'" || $8 != e || ($3 != 755 && $3 != 644 && $3 != 777)' "$W/b.facts")
assert_eq '' "$odd" 'every entry: uid/gid 0, empty owner names, mtime = commit time, mode 0755/0644 (links 0777)'
if awk '{print $2}' "$W/b.facts" | LC_ALL=C sort -c >/dev/null 2>&1; then
  _t_ok 'entries are in byte order'
else
  _t_no 'entries are in byte order' "$(awk '{print $2}' "$W/b.facts" | LC_ALL=C sort -c 2>&1 || true)"
fi

# ---------------------------------------------------------------------------
printf '== C. reproducibility ==\n'
t_case 'reproducibility'
_run "$W/c1.out" bash "$BUILD" "$V" "$W/c1"
_run "$W/c2.out" bash "$BUILD" --ref HEAD "$V" "$W/c2"
if cmp -s "$TB" "$W/c1/$NAME" && cmp -s "$TB" "$W/c2/$NAME"; then
  _t_ok 'three builds of one commit are byte-identical (default ref and --ref HEAD)'
else
  _t_no 'three builds of one commit are byte-identical'
fi
_run "$W/c3.out" env SOURCE_DATE_EPOCH=1000000000 bash "$BUILD" "$V" "$W/c3"
assert_eq 0 "$RC" 'a SOURCE_DATE_EPOCH override builds'
assert_ne "$(cat "$W/b/SHA256SUMS")" "$(cat "$W/c3/SHA256SUMS")" 'and changes the sha256 (the epoch really reaches the entries)'
assert_contains "$(_inspect "$W/c3/$NAME")" " 1000000000 " 'entries carry the overridden mtime'
gz_head=$(python3 -c 'import sys; b=open(sys.argv[1],"rb").read(10); print(b[3], int.from_bytes(b[4:8],"little"))' "$TB")
assert_eq '0 0' "$gz_head" 'the gzip header has no FNAME flag and a zero mtime (gzip -n)'

# ---------------------------------------------------------------------------
printf '== D. only committed bytes ship ==\n'
t_case 'committed bytes only'
CL=$W/clone
git init -q "$CL"
git -C "$CL" fetch -q --depth 1 "file://$ROOT" HEAD
git -C "$CL" checkout -q FETCH_HEAD
# The build and the core library under test are this checkout's, whatever HEAD
# holds; neither is in the allowlist, so being untracked in the clone is fine.
cp "$BUILD" "$CL/tools/build-release.sh"
_gitc() { git -C "$CL" -c user.name=suite -c user.email=suite@example.invalid "$@"; }

printf 'not a real db\n' >"$CL/data/advisories.db"
mkdir -p "$CL/modules/sast/adapters/gitleaks/bin" "$CL/state" "$CL/reports/r1"
printf '#!/bin/sh\n' >"$CL/modules/sast/adapters/gitleaks/bin/gitleaks"
printf 'id: real-target\n' >"$CL/config/scope.conf"
printf '{}\n' >"$CL/state/latest.json"
_run "$W/d1.out" bash "$CL/tools/build-release.sh" "$V" "$W/d1"
assert_eq 0 "$RC" 'a checkout with untracked run output, DBs, engines and config still builds'
d1=$(_inspect "$W/d1/$NAME" | awk '{print $2}')
for bad in data/advisories.db modules/sast/adapters/gitleaks/bin config/scope.conf state reports; do
  # Whole-entry match: a substring test would find config/scope.conf inside
  # config/scope.conf.example and fail on correct behaviour.
  if [[ $'\n'"$d1"$'\n' == *$'\n'"$P/$bad"$'\n'* || $'\n'"$d1" == *$'\n'"$P/$bad/"* ]]; then
    _t_no "untracked $bad does not ship" "found $P/$bad in the tarball"
  else
    _t_ok "untracked $bad does not ship"
  fi
done
if cmp -s "$TB" "$W/d1/$NAME"; then
  _t_ok 'and the tarball is byte-identical to the clean build (untracked bytes cannot perturb it)'
else
  _t_no 'untracked files perturbed the tarball bytes'
fi

rm -rf "${CL:?}/state" "${CL:?}/reports" "$CL/data/advisories.db" "$CL/config/scope.conf"
_gitc add -f modules/sast/adapters/gitleaks/bin/gitleaks
_gitc commit -qm 'track a vendored engine (suite only)'
_run "$W/d2.out" bash "$CL/tools/build-release.sh" "$V" "$W/d2"
assert_eq 4 "$RC" 'a COMMITTED vendored engine binary is refused (exit 4)'
assert_contains "$(cat "$W/d2.out")" 'vendored engine' 'and the refusal names why'
assert_file_absent "$W/d2/$NAME" 'no tarball is left behind'

_gitc rm -q -r modules/sast/adapters/gitleaks/bin docs
_gitc commit -qm 'drop an allowlisted path (suite only)'
_run "$W/d3.out" bash "$CL/tools/build-release.sh" "$V" "$W/d3"
assert_eq 4 "$RC" 'an allowlisted path missing at REF is refused, never silently skipped'
assert_contains "$(cat "$W/d3.out")" "'docs' does not exist" 'and the refusal names the path'

_run "$W/d4.out" bash "$CL/tools/build-release.sh" --ref HEAD~2 "$V" "$W/d4"
assert_eq 0 "$RC" '--ref builds an older commit regardless of what HEAD holds'
if cmp -s "$TB" "$W/d4/$NAME"; then
  _t_ok '--ref HEAD~2 reproduces the original tarball byte for byte'
else
  _t_no '--ref HEAD~2 should reproduce the original tarball byte for byte'
fi
rm -rf "${CL:?}"

# ---------------------------------------------------------------------------
printf '== E. the gate against the real tarball ==\n'
t_case 'gate: real tarball'
# The gate is strict: a packaged copy whose state or reports resolve INSIDE its
# own install root fails it.  Until the installed-layout resolver (packaging
# plan §3 C3) lands, that is exactly what this tree does - so the gate MUST
# refuse, for that reason and no other.  Once C3 has landed (detected by the
# variable its design names, SCOURSH_STATE_DIR, appearing in lib/core.sh),
# the refusal branch is no longer accepted and the gate must PASS outright.
_run "$W/e.out" bash "$GATE" "$TB"
e=$(cat "$W/e.out")
if scan_match "$W/e.hits" -F -e SCOURSH_STATE_DIR -- "$ROOT/lib/core.sh"; then
  c3=landed
else
  c3=absent
fi
if (( RC == 0 )); then
  assert_contains "$e" 'smoke-installed: PASS' 'the gate passes the real tarball as a read-only installed copy'
  assert_contains "$e" 'findings.jsonl carries' 'including a real sast scan from the installed layout'
elif [[ $c3 == landed ]]; then
  _t_no 'the gate must PASS once the installed-layout resolver has landed' "exit $RC" "${e: -1200}"
else
  printf '  NOTICE the installed-layout resolver (plan §3 C3) has not landed: asserting the gate\n'
  printf '         refuses this tree for exactly that reason.  A full PASS is expected once it lands.\n'
  assert_eq 1 "$RC" 'the gate refuses (exit 1)'
  assert_contains "$e" "scoursh --version -> scoursh $V" 'the symlinked, read-only entry point still runs --version'
  assert_contains "$e" 'is INSIDE the read-only install root' 'the refusal is the install-root state/reports check'
  assert_contains "$e" 'scoursh-vendor --help resolves through its link' 'the second entry point resolves through its link'
  assert_contains "$e" 'install tree unchanged by the run' 'nothing was written into the install tree'
  assert_not_contains "$e" 'SHA256SUMS has no single' 'the checksum held'
  assert_not_contains "$e" 'does not run' 'the entry point was never the failure'
fi

# ---------------------------------------------------------------------------
printf '== F. gate mutations ==\n'
t_case 'gate: mutations'
assert_status 2 'the gate with no arguments is a usage error' bash "$GATE"
mkdir -p "$W/f0"
cp "$TB" "$W/f0/$NAME"
assert_status 4 'a tarball with no SHA256SUMS beside it is refused (exit 4)' bash "$GATE" "$W/f0/$NAME"

# `_mutant DIR KIND` - repacks the real tarball into DIR with one defect and a
# CORRECT SHA256SUMS for the mutant (so only the intended check can fire).
_mutant() {
  local dir=$1 kind=$2
  mkdir -p "$dir"
  python3 - "$TB" "$dir/$NAME" "$P" "$kind" <<'PY'
import hashlib, io, os, sys, tarfile
src, dst, prefix, kind = sys.argv[1:5]
with tarfile.open(src, "r:gz") as tin, tarfile.open(dst, "w:gz") as tout:
    for m in tin.getmembers():
        data = tin.extractfile(m).read() if m.isfile() else None
        if kind == "no-report" and m.name == prefix + "/lib/report.sh":
            continue
        if kind == "no-marker" and m.name == prefix + "/.scoursh-packaged":
            continue
        if kind == "lying-version" and m.name == prefix + "/VERSION":
            data = b"6.6.6\n"; m.size = len(data)
        tout.addfile(m, io.BytesIO(data) if data is not None else None)
    if kind == "outside":
        ti = tarfile.TarInfo("stray.txt"); ti.size = 0
        tout.addfile(ti, io.BytesIO(b""))
h = hashlib.sha256(open(dst, "rb").read()).hexdigest()
open(os.path.join(os.path.dirname(dst), "SHA256SUMS"), "w").write("%s  %s\n" % (h, os.path.basename(dst)))
PY
}

_mutant "$W/f1" none
printf '%064d  %s\n' 0 "$NAME" >"$W/f1/SHA256SUMS"
_run "$W/f1.out" bash "$GATE" "$W/f1/$NAME"
assert_eq 1 "$RC" 'a wrong SHA256SUMS fails the gate'
assert_contains "$(cat "$W/f1.out")" 'SHA256SUMS has no single matching line' 'at the checksum check'

_mutant "$W/f2" lying-version
_run "$W/f2.out" bash "$GATE" "$W/f2/$NAME"
assert_eq 1 "$RC" 'a tarball whose VERSION disagrees with its name fails the gate'
assert_contains "$(cat "$W/f2.out")" "printed 'scoursh 6.6.6'" 'at the --version check'

_mutant "$W/f3" no-report
_run "$W/f3.out" bash "$GATE" "$W/f3/$NAME"
assert_eq 1 "$RC" 'a tarball missing a library fails the gate'
assert_contains "$(cat "$W/f3.out")" 'the installed entry point does not run' 'because the entry point cannot start'

_mutant "$W/f4" outside
_run "$W/f4.out" bash "$GATE" "$W/f4/$NAME"
assert_eq 1 "$RC" 'a tarball with an entry outside scoursh-VERSION/ fails the gate'
assert_contains "$(cat "$W/f4.out")" "unexpected tarball entry 'stray.txt'" 'naming the stray entry'

_mutant "$W/f5" no-marker
_run "$W/f5.out" bash "$GATE" "$W/f5/$NAME"
assert_eq 1 "$RC" 'a tarball without the install marker fails the gate'
assert_contains "$(cat "$W/f5.out")" 'install marker .scoursh-packaged is missing' 'at the marker check'

rm -rf "${W:?}"
t_summary 'build-release'
