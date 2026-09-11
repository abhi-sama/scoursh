#!/usr/bin/env python3
"""tests/lib/build_page_crosscheck.py - walks docs/build.html's own
SURFACES/REQUIRED/FIELD_DEFS/COMMAND_GROUPS/GLOBAL_GROUPS tables
(tests/lib/build_page_model.py) against scan.sh's real CLI grammar
(tests/lib/scan_flag_model.py) and reports every disagreement in both
directions: a flag/surface/required-flag docs/build.html offers that scan.sh
does not actually accept (the "never invent a flag" hard constraint), and a
flag/surface scan.sh accepts that docs/build.html silently omits (a
coverage gap the page's own ground-truth claim would otherwise hide).

This is the structural half of the build-commands suite; the other half
(tests/suites/build-commands.sh) actually invokes scan.sh with a handful of
representative composed commands to prove they are accepted, not merely
grammatically present in the map.

Usage:
  build_page_crosscheck.py <docs/build.html> <scan.sh>

Exit status: 0 if every table agrees, 1 otherwise (each disagreement is
printed to stdout as its own FAIL line first).
"""

import sys

import build_page_model
import scan_flag_model

_KIND_TO_SCAN = {
    'bool': 'bool',
    'text': 'value',
    'number': 'value',
    'select': 'value',
    'multiset': 'value',
}


def main():
    if len(sys.argv) != 3:
        print("usage: build_page_crosscheck.py <docs/build.html> <scan.sh>", file=sys.stderr)
        return 2

    page = build_page_model.load_model(sys.argv[1])
    real = scan_flag_model.load_model(sys.argv[2])

    failures = []

    def fail(msg):
        failures.append(msg)
        print("  FAIL  %s" % msg)

    def ok(msg):
        print("  ok    %s" % msg)

    # 1. Surfaces: the page's own SURFACES list must be exactly scan.sh's
    #    real SCAN_COMMANDS - not a subset (an invented surface), not a
    #    superset (a stale one scan.sh no longer supports).
    page_surfaces = set(page['surfaces'])
    real_surfaces = set(real['commands'])
    if page_surfaces == real_surfaces:
        ok("SURFACES matches scan.sh's SCAN_COMMANDS exactly (%d surfaces)" % len(real_surfaces))
    else:
        for extra in sorted(page_surfaces - real_surfaces):
            fail("docs/build.html offers surface %r, which scan.sh's SCAN_COMMANDS does not have" % extra)
        for missing in sorted(real_surfaces - page_surfaces):
            fail("scan.sh's SCAN_COMMANDS has surface %r, which docs/build.html does not offer" % missing)

    # 2. Required flags: must agree exactly, command by command.
    if page['required'] == real['required']:
        ok("REQUIRED matches scan.sh's _SCAN_REQUIRED_FLAG exactly")
    else:
        cmds = set(page['required']) | set(real['required'])
        for cmd in sorted(cmds):
            p = page['required'].get(cmd)
            r = real['required'].get(cmd)
            if p != r:
                fail("required flag for %r: docs/build.html says %r, scan.sh says %r" % (cmd, p, r))

    # 3. Every page (surface, flag) must exist in scan.sh with a matching
    #    kind - the direction that catches an invented or stale flag.
    before = len(failures)
    for surface, flags in sorted(page['command_groups'].items()):
        real_for_surface = real['flag_kind'].get(surface, {})
        for flag in flags:
            page_kind = page['field_defs'].get(flag, {}).get('kind')
            if page_kind is None:
                fail("docs/build.html's %s command group uses flag %r with no FIELD_DEFS entry" % (surface, flag))
                continue
            expected = _KIND_TO_SCAN.get(page_kind)
            if expected is None:
                fail("docs/build.html's FIELD_DEFS[%r] has unrecognised kind %r" % (flag, page_kind))
                continue
            real_kind = real_for_surface.get(flag)
            if real_kind is None:
                fail("docs/build.html offers --%s on `scan.sh %s`, but scan.sh's _SCAN_FLAG_KIND has no [%s:%s] entry"
                     % (flag, surface, surface, flag))
            elif real_kind != expected:
                fail("--%s on `scan.sh %s`: docs/build.html models it as %r (-> %r), scan.sh's _SCAN_FLAG_KIND says %r"
                     % (flag, surface, page_kind, expected, real_kind))
    if len(failures) == before:
        ok("every docs/build.html per-surface flag exists in scan.sh with a matching kind")

    # 4. Same, for the global flag set.
    real_global = real['flag_kind'].get('global', {})
    before = len(failures)
    for flag in page['global_flags']:
        page_kind = page['field_defs'].get(flag, {}).get('kind')
        if page_kind is None:
            fail("docs/build.html's global flag group uses flag %r with no FIELD_DEFS entry" % flag)
            continue
        expected = _KIND_TO_SCAN.get(page_kind)
        if expected is None:
            fail("docs/build.html's FIELD_DEFS[%r] has unrecognised kind %r" % (flag, page_kind))
            continue
        real_kind = real_global.get(flag)
        if real_kind is None:
            fail("docs/build.html offers global flag --%s, but scan.sh's _SCAN_FLAG_KIND has no [global:%s] entry" % (flag, flag))
        elif real_kind != expected:
            fail("global flag --%s: docs/build.html models it as %r (-> %r), scan.sh's _SCAN_FLAG_KIND says %r"
                 % (flag, page_kind, expected, real_kind))
    if len(failures) == before:
        ok("every docs/build.html global flag exists in scan.sh with a matching kind")

    # 5. The reverse direction: every REAL per-surface and global flag must
    #    appear somewhere on the page for that surface, so a scan.sh flag
    #    the page silently omits is caught rather than assumed covered.
    for surface in sorted(real_surfaces):
        page_flags = set(page['command_groups'].get(surface, [])) | set(page['global_flags'])
        for flag, kind in sorted(real['flag_kind'].get(surface, {}).items()):
            if flag not in page_flags:
                fail("scan.sh accepts --%s on `scan.sh %s` (_SCAN_FLAG_KIND[%s:%s]=%s), but docs/build.html does not offer it there"
                     % (flag, surface, surface, flag, kind))
    for flag, kind in sorted(real_global.items()):
        if flag not in page['global_flags']:
            fail("scan.sh accepts global flag --%s (_SCAN_FLAG_KIND[global:%s]=%s), but docs/build.html does not offer it" % (flag, flag, kind))
    if not any(f.startswith("scan.sh accepts") for f in failures):
        ok("every scan.sh flag (per-surface and global) is offered somewhere on the page for its surface")

    print()
    if failures:
        print("build-page-crosscheck: FAILED (%d disagreement(s))" % len(failures))
        return 1
    print("build-page-crosscheck: clean - docs/build.html's tables agree with scan.sh's real grammar")
    return 0


if __name__ == '__main__':
    sys.exit(main())
