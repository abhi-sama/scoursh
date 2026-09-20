#!/usr/bin/env python3
"""tests/lib/build_page_model.py - extracts docs/build.html's own JS ground-
truth tables (SURFACES, REQUIRED, FIELD_DEFS, COMMAND_GROUPS, GLOBAL_GROUPS)
as plain Python/JSON data, so a test can compare them against scan.sh's real
grammar (tests/lib/scan_flag_model.py) instead of a second, hand-typed copy
of the same facts that could silently drift from either.

Deliberately NOT a general JavaScript parser - the same "purpose-built,
never a general parser" discipline this project's other JSON/record readers
already follow (modules/sca/engine.sh's _sca_json_walk, tests/lib/
sarif_validate.py's own header). It supports exactly the constrained literal
shape docs/build.html's own tables are written in: nested {..}/[..] object
and array literals, double- or single-quoted strings, bare identifier keys,
and both `NAME["key"] = <lit>;` and `NAME.key = <lit>;` follow-on
reassignment forms. No JS expression, comment, template string, or number
arithmetic is supported, because none of these tables use one.

Usage:
  build_page_model.py <docs/build.html>          # prints the model as JSON
"""

import json
import re
import sys


def tokenize(s):
    toks = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in ' \t\r\n':
            i += 1
            continue
        if c in '{}[]:,':
            toks.append((c, c))
            i += 1
            continue
        if c in '"\'':
            q = c
            j = i + 1
            buf = []
            while j < n and s[j] != q:
                if s[j] == '\\' and j + 1 < n:
                    buf.append(s[j + 1])
                    j += 2
                else:
                    buf.append(s[j])
                    j += 1
            toks.append(('str', ''.join(buf)))
            i = j + 1
            continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (s[j].isalnum() or s[j] in '_$'):
                j += 1
            toks.append(('id', s[i:j]))
            i = j
            continue
        if c.isdigit() or (c == '-' and i + 1 < n and s[i + 1].isdigit()):
            j = i + 1
            while j < n and (s[j].isdigit() or s[j] == '.'):
                j += 1
            toks.append(('num', s[i:j]))
            i = j
            continue
        raise ValueError("unexpected character %r at offset %d" % (c, i))
    return toks


class _Parser:
    def __init__(self, toks):
        self.toks = toks
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def advance(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse_value(self):
        kind, val = self.peek()
        if kind == '{':
            return self.parse_object()
        if kind == '[':
            return self.parse_array()
        if kind in ('str', 'num', 'id'):
            self.advance()
            return val
        raise ValueError("unexpected token %r at position %d" % (self.peek(), self.pos))

    def parse_object(self):
        self.advance()  # {
        obj = {}
        while self.peek()[0] != '}':
            kkind, key = self.advance()
            if kkind not in ('str', 'id'):
                raise ValueError("bad object key %r" % ((kkind, key),))
            ckind, _ = self.advance()
            if ckind != ':':
                raise ValueError("expected ':' after key %r, got %r" % (key, ckind))
            obj[key] = self.parse_value()
            if self.peek()[0] == ',':
                self.advance()
        self.advance()  # }
        return obj

    def parse_array(self):
        self.advance()  # [
        arr = []
        while self.peek()[0] != ']':
            arr.append(self.parse_value())
            if self.peek()[0] == ',':
                self.advance()
        self.advance()  # ]
        return arr


def parse_literal(text):
    return _Parser(tokenize(text)).parse_value()


def _extract_balanced(script, start):
    """`start` points at the opening `{` or `[` right after an `=`. Returns
    the substring through its matching close, tracking quoted strings so a
    bracket byte inside one is never mistaken for real nesting."""
    open_ch = script[start]
    close_ch = {'{': '}', '[': ']'}[open_ch]
    depth = 0
    i = start
    n = len(script)
    in_str = None
    while i < n:
        c = script[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in '"\'':
            in_str = c
            i += 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return script[start:i + 1]
        i += 1
    raise ValueError("unbalanced literal starting at offset %d" % start)


def _find_statements(script, name, allow_reassignment=True):
    """Returns a list of (key, value) pairs: (None, value) for the initial
    `var NAME = <lit>;`, plus one (key, value) pair for every later
    `NAME["key"] = <lit>;` or `NAME.key = <lit>;` reassignment, in source
    order."""
    results = []
    m = re.search(r'\bvar\s+' + re.escape(name) + r'\s*=\s*', script)
    if not m:
        raise ValueError("no `var %s = ...` statement found" % name)
    results.append((None, parse_literal(_extract_balanced(script, m.end()))))
    if allow_reassignment:
        for m2 in re.finditer(re.escape(name) + r'\[("(?:[^"\\]|\\.)*")\]\s*=\s*', script):
            key = parse_literal(m2.group(1))
            results.append((key, parse_literal(_extract_balanced(script, m2.end()))))
        for m3 in re.finditer(re.escape(name) + r'\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*', script):
            key = m3.group(1)
            results.append((key, parse_literal(_extract_balanced(script, m3.end()))))
    return results


def load_model(path):
    """Reads docs/build.html at `path` and returns the extracted model:
      surfaces:       [surface id, ...]
      required:       {surface: required flag name}
      field_defs:     {flag: {"kind": "text"|"number"|"select"|"bool"|"multiset"}}
      command_groups: {surface: [flag, ...]}  (surface-specific flags only)
      global_flags:   [flag, ...]             (apply to every surface)
    """
    html = open(path, encoding='utf-8').read()
    m = re.search(r'<script>(.*)</script>', html, re.S)
    if not m:
        raise ValueError("%s: no <script> block found" % path)
    script = m.group(1)

    surfaces_val = _find_statements(script, 'SURFACES', allow_reassignment=False)[0][1]
    surfaces = [o['id'] for o in surfaces_val]

    required = _find_statements(script, 'REQUIRED', allow_reassignment=False)[0][1]

    field_defs = {}
    for key, val in _find_statements(script, 'FIELD_DEFS'):
        if key is None:
            field_defs.update(val)
        else:
            field_defs[key] = val

    command_groups_val = _find_statements(script, 'COMMAND_GROUPS', allow_reassignment=False)[0][1]
    command_groups = {}
    for surf, groups in command_groups_val.items():
        flags = []
        for g in groups:
            flags.extend(g['flags'])
        command_groups[surf] = flags

    global_groups_val = _find_statements(script, 'GLOBAL_GROUPS', allow_reassignment=False)[0][1]
    global_flags = []
    for g in global_groups_val:
        global_flags.extend(g['flags'])

    return {
        'surfaces': surfaces,
        'required': required,
        'field_defs': {k: {'kind': v.get('kind')} for k, v in field_defs.items()},
        'command_groups': command_groups,
        'global_flags': global_flags,
    }


def main():
    if len(sys.argv) != 2:
        print("usage: build_page_model.py <docs/build.html>", file=sys.stderr)
        return 2
    print(json.dumps(load_model(sys.argv[1]), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
