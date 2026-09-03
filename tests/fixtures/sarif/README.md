# The vendored SARIF 2.1.0 schema

`sarif-schema-2.1.0.json` is the OASIS Static Analysis Results Format (SARIF)
Version 2.1.0 JSON Schema, committed here so `tests/suites/sarif-schema.sh`
can validate `report.sarif` against it with no network access at test time -
the same vendored-data-file discipline `data/versions.db` and
`data/severity-rubric.conf` already follow, and the reason it lives under
`tests/fixtures/` rather than `data/`: it is test-time-only, never read by
`lib/` or `modules/` at scan time.

## Provenance

- **Source:** `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
  - This is OASIS's own hosted copy of the errata01 (corrected) revision of
    the SARIF v2.1.0 Committee Specification - the standards body's own
    artifact, not a third-party mirror.
  - The `oasis-tcs/sarif-spec` GitHub repository's `master` branch (the URL
    `lib/report.sh`'s `report_sarif` cites in the emitted document's own
    `$schema` field) no longer exists - the repository's default branch is
    now `main`, and the `Schemata/` path used at the time `report_sarif` was
    written 404s. The OASIS-hosted copy above is unaffected by that rename
    and is the more authoritative source in any case: it is the standards
    body's own publication rather than a working-repository snapshot.
  - Retrieved 2026-09-03.
- **sha256:** `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`

## Refresh procedure

SARIF 2.1.0 is a ratified, closed standard - there is no "2.1.1" to track,
and this file should essentially never need to change. If OASIS ever
publishes a further errata revision:

```sh
curl -sL -o tests/fixtures/sarif/sarif-schema-2.1.0.json \
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata0N/os/schemas/sarif-schema-2.1.0.json'
shasum -a 256 tests/fixtures/sarif/sarif-schema-2.1.0.json
```

Update the sha256 and the retrieval date above in the same change, and rerun
`tests/run-tests.sh sarif-schema` to confirm `report.sarif` still validates.
This is a manual, reviewed step (mirroring `docs/VERSIONS-DB.md` §5's `banner`
namespace procedure) - `tools/vendor-engines.sh` is the only script permitted
to reach the network, and this file is not one of the things it vendors.

## Why the validator is hand-rolled rather than `pip install jsonschema`

`tests/lib/sarif_validate.py` implements a small, purpose-built subset of
JSON Schema draft-04/07 - exactly the keywords this one vendored schema
actually uses (`type`, `enum`, `$ref`, `properties`, `additionalProperties`,
`required`, `items`, `minItems`, `maxItems`, `uniqueItems`, `minimum`,
`maximum`, `pattern`, `anyOf`, `oneOf`; `format` is read and ignored, which is
spec-legal - draft-07 treats `format` as an annotation unless an
implementation opts into asserting it) rather than depending on the
`jsonschema` PyPI package.

This is deliberate, not a shortcut: `jsonschema` is not part of the Python
standard library and is not installed by default even on a host that has
`python3` (measured on this project's own macOS dev host: `python3 -c "import
jsonschema"` fails out of the box). Depending on it would make "python3 is
present" stop being sufficient to actually run the validation, silently
reintroducing the skip-as-pass failure `docs/STEP10-SARIF-PLAN.md` SARIF-05
exists to close - on almost every host, not the rare one. Using only the
standard library's `json` module keeps the existing, already-conditional
"python3 present or reported skip" contract intact instead of adding a
second, harder-to-satisfy condition underneath it.
