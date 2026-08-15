# tests/fixtures/vendor-engines/osv-bulk/

Hand-authored, OSV.dev-*shaped* fixture records for the BULK import path
(`tools/vendor-engines.sh advisories bulk`), the sibling of
`../osv/`'s single-advisory fixtures. Same rule as that directory: these are
**not** real, live-fetched OSV.dev records. Every advisory id, package name and
version is synthetic (`SCOURSH-FIXTURE-OSV-BULK-*`, never a real
`GHSA-`/`PYSEC-`/`GO-` id).

The directory layout mirrors the real upstream bucket
(`https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`), so
the sub-directory names are OSV's OWN ecosystem spellings - `npm`, `PyPI`,
`Maven`, `Go`, `RubyGems`, `Packagist` - not this project's own frozen
`data/advisories.db` ecosystem strings (`pypi`, `maven`, `composer`). The two
vocabularies differ in exactly the spots
`_veng_advisories_osv_ecosystem` already names.

`tests/suites/vendor-engines-advisories.sh` zips each of these directories with
`python3`'s own `zipfile` module at test time, producing an archive shaped like
the real `all.zip`, and feeds it to the import path either as a local
`--archive` (no network code reached at all) or through a stubbed `curl` on
PATH. No test in this repository ever fetches the real archive.

`../osv-bulk-bad/` holds the deliberately broken members used to prove the
refusal paths: a member that is not valid JSON, and a member smuggling a
literal TAB into a `fixed` event.

What each npm fixture is for:

| file | proves |
|---|---|
| `npm/...-NPM-1.json` | the ordinary case: two enumerated affected versions, one fixed version |
| `npm/...-NPM-2.json` | a scoped (`@scope/name`) package, and a decoy PyPI `affected` entry inside an npm-ecosystem import that must never be emitted |
| `npm/...-NPM-3.json` | a range-only advisory: no `versions[]`, so it is skipped and COUNTED, never guessed at (tension 25) |
| `npm/...-NPM-4.json` | no severity at all (defaults to `medium`) and a `details`-only summary fallback |
| `npm/...-NPM-5.json` | a SECOND advisory naming the same package@version as `-NPM-1`, so a lookup through the reader's own path returns two distinct rows rather than collapsing them |
