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

`SCOURSH-FIXTURE-OSV-ALPINE-1.json` and `SCOURSH-FIXTURE-OSV-ALPINE-2.json`
are for `veng_advisories_alpine` (data/advisories.db and data/versions.db's
`Alpine:vX.Y` namespace, IMG-03). `-ALPINE-1` carries THREE `affected[]`
entries: `Alpine:v3.18` and `Alpine:v3.19` (two DIFFERENT releases, each with
its own `fixed` version, for the SAME package - proving one import can
legitimately produce rows for more than one Alpine release) plus a `Debian`
entry for the identical package, which must be SKIPPED - proving the
`Alpine:*` sentinel (`_veng_advisories_osv_ecosystem`'s "alpine" case) is a
PREFIX match on `Alpine:`, never the `*` wildcard `banner` uses. `-ALPINE-2`
names a different package under `Alpine:v3.18` only, for the
replace-the-whole-namespace test.

`SCOURSH-FIXTURE-OSV-DEBIAN-1.json` and `SCOURSH-FIXTURE-OSV-DEBIAN-2.json`
are for `veng_advisories_debian` (data/advisories.db and data/versions.db's
`Debian:N` namespace, IMG-09) - Debian's sibling to the two `-ALPINE-*`
fixtures above. `-DEBIAN-1` carries THREE `affected[]` entries: `Debian:11`
and `Debian:12` (two DIFFERENT releases, each with its own `fixed` version,
for the SAME source package `openssl` - proving one import can legitimately
produce rows for more than one Debian release) plus an `Alpine:v3.18` entry
for the identical package, which must be SKIPPED - proving the `Debian:*`
sentinel is a PREFIX match on `Debian:`, not the bare `*` wildcard `banner`
uses and not `Alpine:*`'s own, different prefix. `-DEBIAN-2` names a
different source package (`bash`) under `Debian:12` only, for the
replace-the-whole-namespace test.

`SCOURSH-FIXTURE-OSV-UBUNTU-1.json` is for `veng_advisories_ubuntu`
(data/advisories.db and data/versions.db's `Ubuntu:XX.YY` namespace, IMG-09).
It carries THREE `affected[]` entries: `Ubuntu:20.04` and `Ubuntu:22.04` (two
DIFFERENT releases, each with its own `fixed` version, for the SAME source
package `openssl`) plus a `Debian:12` entry for the identical package, which
must be SKIPPED - proving the `Ubuntu:*` sentinel does not also admit
`Debian:*`'s own rows, even though both are per-release distro sentinels
sharing the same `eco.endswith(':*')` extraction path.

`SCOURSH-FIXTURE-OSV-REDHAT-1.json` and `SCOURSH-FIXTURE-OSV-REDHAT-2.json`
are for `veng_advisories_redhat` (data/advisories.db and data/versions.db's
`Red Hat` namespace, the last rpm ticket) - UNLIKE its three distro siblings
above, `Red Hat` is a single FLAT ecosystem string with no per-release
variant, so `-REDHAT-1` carries only ONE `Red Hat` entry (`openssl-libs`,
with an EPOCH in both its installed and fixed version - `1:1.1.1k-9.el8` /
`1:1.1.1k-9.el8_6` - proving the epoch-aware rpmvercmp comparator is what
orders it, never a lexical/semver comparison) plus a `Debian:12` entry for a
different-but-similarly-named package (`openssl`), which must be SKIPPED -
proving the exact-match branch (`_veng_advisories_osv_ecosystem`'s `'Red
Hat'` case) never falls back to a prefix or wildcard match. `-REDHAT-2`
names a different package (`bash`, no epoch - the ordinary rpm case) for the
replace-the-whole-namespace test.
