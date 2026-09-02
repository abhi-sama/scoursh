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

`SCOURSH-FIXTURE-OSV-BANNER-1.json` and `SCOURSH-FIXTURE-OSV-BANNER-NOSEV.json`
are for `veng_advisories_banner` (data/versions.db's `banner` namespace,
docs/VERSIONS-DB.md), not one of the six docs/DESIGN.md §6.5 SCA ecosystems.
Both deliberately carry `affected[]` entries under an ecosystem string that is
none of the six (`Debian`, `Alpine`) or with no `package.ecosystem` field at
all, to prove the banner path's OSV-ecosystem wildcard (`*`,
`_veng_advisories_osv_ecosystem`'s "banner" case) takes every entry that names
a package rather than filtering the way the six SCA ecosystems do.
`-NOSEV` also carries no severity anywhere, to prove the banner-only default
(docs/VERSIONS-DB.md §3: "a row with none lands on `high`") rather than the
SCA rows' own `medium` default.
