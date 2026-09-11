#!/usr/bin/env python3
"""tests/lib/scan_flag_model.py - extracts scan.sh's real CLI grammar
(SCAN_COMMANDS, _SCAN_FLAG_KIND, _SCAN_REQUIRED_FLAG) as plain Python/JSON
data, so a test can compare docs/build.html's own ground-truth tables
(tests/lib/build_page_model.py) against the actual source rather than a
second, hand-typed copy of the same facts.

Deliberately a small, targeted regex reader over scan.sh's own two
`declare -A` associative-array literals and one plain array - not a bash
parser - because those three declarations are the WHOLE of scan.sh's own
frozen flag grammar (scan_flag_kind's own comment: "Command-specific first,
falling back to global"), and nothing else in the file needs to be read for
this purpose.

Usage:
  scan_flag_model.py <scan.sh>          # prints the model as JSON
"""

import json
import re
import sys


def load_model(path):
    """Reads scan.sh at `path` and returns:
      commands:  [command, ...]                          (SCAN_COMMANDS)
      flag_kind: {scope: {flag: "bool"|"value"}}          (scope is a
                 command name or the literal "global")
      required:  {command: required flag name}
    """
    text = open(path, encoding='utf-8').read()

    m = re.search(r'\bSCAN_COMMANDS=\(([^)]*)\)', text)
    if not m:
        raise ValueError("%s: SCAN_COMMANDS=(...) not found" % path)
    commands = m.group(1).split()

    fm = re.search(r'declare -A _SCAN_FLAG_KIND=\((.*?)\n\)\n', text, re.S)
    if not fm:
        raise ValueError("%s: declare -A _SCAN_FLAG_KIND=(...) block not found" % path)
    flag_kind = {}
    for entry in re.finditer(r'\[([A-Za-z0-9_-]+):([A-Za-z0-9_-]+)\]=(\w+)', fm.group(1)):
        scope, flag, kind = entry.groups()
        flag_kind.setdefault(scope, {})[flag] = kind

    rm = re.search(r'declare -A _SCAN_REQUIRED_FLAG=\((.*?)\n\)\n', text, re.S)
    if not rm:
        raise ValueError("%s: declare -A _SCAN_REQUIRED_FLAG=(...) block not found" % path)
    required = {}
    for entry in re.finditer(r'\[([A-Za-z0-9_-]+)\]=([A-Za-z0-9_-]+)', rm.group(1)):
        cmd, flag = entry.groups()
        required[cmd] = flag

    return {'commands': commands, 'flag_kind': flag_kind, 'required': required}


def main():
    if len(sys.argv) != 2:
        print("usage: scan_flag_model.py <scan.sh>", file=sys.stderr)
        return 2
    print(json.dumps(load_model(sys.argv[1]), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
