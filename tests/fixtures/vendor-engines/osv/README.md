# tests/fixtures/vendor-engines/osv/

Hand-authored, OSV.dev-*shaped* fixture responses for
`tests/suites/vendor-engines-advisories.sh` - **not** real, live-fetched
OSV.dev records. Every advisory id, package name and version below is
synthetic (an `SCOURSH-FIXTURE-OSV-*` id, never a real `GHSA-`/`PYSEC-`/`GO-`
id), the same "hand-authored, NOT the real database" convention
`tests/fixtures/sca/advisories.db` already documents for itself.

Each file's name is `<id>.json`, matching exactly what
`tools/vendor-engines.sh`'s `_veng_advisories_osv_fetch` requests
(`https://api.osv.dev/v1/vulns/<id>`) - the test suite's fake `curl` looks
the id up here instead of reaching the network.
