#!/usr/bin/env python3
"""tests/lib/sarif_validate.py - validates a SARIF (or any JSON) document
against tests/fixtures/sarif/sarif-schema-2.1.0.json, and optionally asserts
docs/FOUNDATION.md tension 22's own extra condition.

Deliberately NOT a general JSON Schema implementation, and not built on the
`jsonschema` PyPI package - see tests/fixtures/sarif/README.md for why that
dependency would reintroduce the exact skip-as-pass failure this validator
exists to close. This supports exactly the draft-04/07 keywords the vendored
SARIF schema actually uses: `type` (a string or a list of strings), `enum`,
`$ref` (local "#/definitions/<name>" only - the only shape this schema uses),
`properties`, `additionalProperties` (bool or a schema), `required`, `items`
(a single schema - this schema never uses tuple-form items), `minItems`,
`maxItems`, `uniqueItems`, `minimum`, `maximum`, `pattern`, `anyOf`, `oneOf`.
`format` is read and ignored: draft-07 treats it as an annotation unless an
implementation opts into asserting it, and this one does not, exactly like
every mainstream default-mode JSON Schema validator.

Usage:
  sarif_validate.py <schema.json> <document.json>
  sarif_validate.py <schema.json> <document.json> --check-locations <rundir> <scanroot>

The second form additionally asserts, for every `runs[*].results[*]`, that
`locations[0].physicalLocation.artifactLocation.uri` is non-empty and
resolves to a real file under RUNDIR or under SCANROOT - the strengthened
requirement tension 22's RESOLUTION states explicitly a schema pass alone
cannot make ("Omitting `locations` produces SARIF that a schema validator may
accept but that real code-scanning ingesters reject"; a `uri` can just as
easily be a syntactically fine string naming nothing at all, which passes
`type: string` the same as a real path does).

Exit 0: valid (both checks, when --check-locations is given). Exit 1: at
least one violation - printed to stderr, each line prefixed SCHEMA or
LOCATION so a caller can tell which half failed. Exit 2: usage error.
"""
import json
import os
import re
import sys

MAX_ERRORS = 200
_REF_RE = re.compile(r'^#/definitions/([A-Za-z0-9_]+)$')


class SchemaShapeError(Exception):
    """The vendored schema itself uses a construct this validator does not
    support - a bug in the validator's scope, not a document-under-test
    finding."""


def _resolve_ref(ref, schema):
    m = _REF_RE.match(ref)
    if not m:
        raise SchemaShapeError('unsupported $ref shape: %r' % (ref,))
    name = m.group(1)
    try:
        return schema['definitions'][name]
    except KeyError:
        raise SchemaShapeError('$ref to undefined definition: %r' % (ref,))


def _type_ok(value, type_name):
    if type_name == 'integer':
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == 'number':
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == 'boolean':
        return isinstance(value, bool)
    if type_name == 'null':
        return value is None
    if type_name == 'string':
        return isinstance(value, str)
    if type_name == 'array':
        return isinstance(value, list)
    if type_name == 'object':
        return isinstance(value, dict)
    raise SchemaShapeError('unsupported type keyword value: %r' % (type_name,))


def _trunc(value):
    s = repr(value)
    return s if len(s) <= 160 else s[:157] + '...'


def _validate(value, node, schema, path, errors):
    if len(errors) >= MAX_ERRORS:
        return

    if '$ref' in node:
        # This schema never puts a validation keyword alongside $ref (checked
        # against the vendored file at write time), so resolving and
        # recursing is the whole story - no sibling keywords to merge in.
        _validate(value, _resolve_ref(node['$ref'], schema), schema, path, errors)
        return

    t = node.get('type')
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(value, tt) for tt in types):
            errors.append('SCHEMA %s: expected type %s, got %s: %s' %
                           (path, types, type(value).__name__, _trunc(value)))
            return  # further structural checks on the wrong shape are noise

    if 'enum' in node and value not in node['enum']:
        errors.append('SCHEMA %s: %s is not one of %s' % (path, _trunc(value), node['enum']))

    if isinstance(value, str) and 'pattern' in node:
        if re.search(node['pattern'], value) is None:
            errors.append('SCHEMA %s: %s does not match pattern %r' %
                           (path, _trunc(value), node['pattern']))

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in node and value < node['minimum']:
            errors.append('SCHEMA %s: %s < minimum %s' % (path, value, node['minimum']))
        if 'maximum' in node and value > node['maximum']:
            errors.append('SCHEMA %s: %s > maximum %s' % (path, value, node['maximum']))

    if isinstance(value, list):
        if 'minItems' in node and len(value) < node['minItems']:
            errors.append('SCHEMA %s: %d items < minItems %d' % (path, len(value), node['minItems']))
        if 'maxItems' in node and len(value) > node['maxItems']:
            errors.append('SCHEMA %s: %d items > maxItems %d' % (path, len(value), node['maxItems']))
        if node.get('uniqueItems'):
            seen = []
            for v in value:
                if v in seen:
                    errors.append('SCHEMA %s: duplicate item where uniqueItems is required: %s' %
                                   (path, _trunc(v)))
                    break
                seen.append(v)
        items_schema = node.get('items')
        if items_schema is not None:
            for i, item in enumerate(value):
                _validate(item, items_schema, schema, '%s[%d]' % (path, i), errors)

    if isinstance(value, dict):
        for key in node.get('required', []):
            if key not in value:
                errors.append('SCHEMA %s: missing required property %r' % (path, key))
        props = node.get('properties', {})
        ap = node.get('additionalProperties', True)
        for key, v in value.items():
            if key in props:
                _validate(v, props[key], schema, '%s/%s' % (path, key), errors)
            elif ap is False:
                errors.append('SCHEMA %s: additional property %r is not allowed' % (path, key))
            elif isinstance(ap, dict):
                _validate(v, ap, schema, '%s/%s' % (path, key), errors)
            # ap is True (or absent): no constraint on this property's value

    for combinator, want_exactly_one in (('anyOf', False), ('oneOf', True)):
        subs = node.get(combinator)
        if subs is None:
            continue
        matches = 0
        for sub in subs:
            sub_errors = []
            _validate(value, sub, schema, path, sub_errors)
            if not sub_errors:
                matches += 1
        if want_exactly_one:
            if matches != 1:
                errors.append('SCHEMA %s: matches %d of the %d oneOf alternatives, want exactly 1' %
                               (path, matches, len(subs)))
        elif matches == 0:
            errors.append('SCHEMA %s: does not match any of the %d anyOf alternatives' %
                           (path, len(subs)))


def validate_schema(document, schema):
    errors = []
    _validate(document, schema, schema, '$', errors)
    return errors


def validate_locations(document, rundir, scanroot):
    """tension 22's extra condition: every result's physical location URI is
    non-empty and resolves to a real file under rundir or scanroot. Does its
    own defensive key lookups rather than assuming the schema check already
    ran - a caller may invoke this alone, deliberately, in a test proving
    this half rejects independently of schema validity (a syntactically fine
    but non-existent path is still `type: string`, so the schema check alone
    passes it)."""
    errors = []
    runs = document.get('runs') if isinstance(document, dict) else None
    if not isinstance(runs, list):
        errors.append('LOCATION $: no runs[] array to check locations in')
        return errors
    for ri, run in enumerate(runs):
        results = run.get('results') if isinstance(run, dict) else None
        if not isinstance(results, list):
            continue
        for i, result in enumerate(results):
            path = '$/runs[%d]/results[%d]' % (ri, i)
            locations = result.get('locations') if isinstance(result, dict) else None
            if not locations:
                errors.append('LOCATION %s: no locations[] at all' % path)
                continue
            phys = locations[0].get('physicalLocation') if isinstance(locations[0], dict) else None
            artifact = phys.get('artifactLocation') if isinstance(phys, dict) else None
            uri = artifact.get('uri') if isinstance(artifact, dict) else None
            if not uri:
                errors.append('LOCATION %s: locations[0].physicalLocation.artifactLocation.uri is empty or absent' % path)
                continue
            under_rundir = os.path.exists(os.path.join(rundir, uri))
            under_scanroot = os.path.exists(os.path.join(scanroot, uri))
            if not (under_rundir or under_scanroot):
                errors.append(
                    'LOCATION %s: uri %r resolves under neither the run directory (%s) nor the scanned tree (%s)' %
                    (path, uri, rundir, scanroot))
    return errors


def main(argv):
    if len(argv) not in (3, 6) or (len(argv) == 6 and argv[3] != '--check-locations'):
        sys.stderr.write(
            'usage: sarif_validate.py <schema.json> <document.json> '
            '[--check-locations <rundir> <scanroot>]\n')
        return 2

    schema_path, doc_path = argv[1], argv[2]
    try:
        with open(schema_path) as f:
            schema = json.load(f)
        with open(doc_path) as f:
            document = json.load(f)
    except (OSError, ValueError) as e:
        sys.stderr.write('sarif_validate.py: %s\n' % (e,))
        return 2

    try:
        errors = validate_schema(document, schema)
    except SchemaShapeError as e:
        sys.stderr.write('sarif_validate.py: %s\n' % (e,))
        return 2

    if len(argv) == 6:
        errors += validate_locations(document, argv[4], argv[5])

    if errors:
        for e in errors[:MAX_ERRORS]:
            sys.stderr.write(e + '\n')
        if len(errors) > MAX_ERRORS:
            sys.stderr.write('... and %d more\n' % (len(errors) - MAX_ERRORS))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
