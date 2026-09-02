# `data/versions.db` - the vendored known-vulnerable version list

This document is normative and self-contained, in the same way `docs/INVENTORY-FORMAT.md` is for the run
inventory and `docs/ADAPTERS.md` is for engine adapters.
It defines the file the DAST banner check (`modules/dast/passive/banner.sh`, `docs/DESIGN.md` §7.1) reads
to decide whether a version it discovered on a running endpoint is known to be vulnerable.

`docs/FOUNDATION.md` tension 25 is the decision this implements.
Read that first if you are changing anything here: it is the reason the scanner performs **no version
comparison and no range arithmetic at all**, and the reason this file is a table rather than a rule pack.

## 1. Why the file exists, and why it is offline

`docs/DESIGN.md` §7.1 requires the banner check to flag **out-of-date components** "without any internet
lookup".
That is not a convenience: `scoursh` is egress-restricted by destination (`docs/adr/0001-egress-model-correction.md`),
so the only outbound traffic a scan may make is to a host the operator authorised in `config/scope.conf`.
A version check that called an advisory API would be a second, unauthorised destination, and it would put
the scanner's correctness at the mercy of a service the operator never approved.

So the vulnerability data is **vendored**: resolved on a networked box, written to disk, and read by the
scan as a table lookup.
A scan never fetches it, never refreshes it, and never notices that it is stale on its own - which is why
§5 below exists.

## 2. The file, and the two namespaces in it

`data/versions.db` is the frozen tension-25 TSV, byte-for-byte the same schema as `data/advisories.db`:

```
ecosystem \t package \t version \t advisory_id \t severity \t fixed_versions \t summary
```

Sorted by the first three fields under `LC_ALL=C`, with `#` comment lines at the top.
No field may contain a TAB or an LF.
Lookup is `db_lookup_exact` (`lib/core.sh`) - `LC_ALL=C look` on a prefix, falling back to
`grep -F -m 1` where `look` is absent - and nothing else ever reads the file.

The first field is a **namespace**, and this file carries two kinds of row:

| Field 1 | Rows | Written by | Read by |
|---|---|---|---|
| an SCA ecosystem (`npm`, `pypi`, `maven`, `Go`, `RubyGems`, `composer`) | one per exact affected package version | `tools/vendor-engines.sh advisories` | nothing today - `modules/sca/` reads `data/advisories.db`, and `tools/vendor-engines.sh` writes both files from one call (tension 25's "the same shape and the same rule") |
| the literal `banner` | one per exact affected **product** version | an operator, per §5 | `modules/dast/passive/banner_engine.sh` |

The two coexist safely and that is by construction, not by luck.
`tools/vendor-engines.sh`'s single writer (`_veng_advisories_write_db`) replaces only the rows whose first
field equals the ecosystem it is writing and carries every other row through untouched, so refreshing npm
cannot delete the banner catalogue and vendoring a banner row cannot delete npm's.
`banner` also sorts before every ecosystem name under `LC_ALL=C`, so adding banner rows never disturbs the
sort the lookup depends on.

## 3. The `banner` row, field by field

| Field | Value |
|---|---|
| `ecosystem` | the literal `banner`. |
| `package` | the **product key**, normalised per §4. This is what a discovered banner is reduced to before the lookup. |
| `version` | the exact version string, verbatim as the product publishes it (`1.18.0`, `2.4.49`, `5.8.1`). One row per affected version - never a range, never a wildcard. |
| `advisory_id` | the advisory this row comes from (`CVE-2021-41773`, `GHSA-xxxx-xxxx-xxxx`). One row per (product, version, advisory): two advisories affecting one version are two rows. |
| `severity` | one of `info`, `low`, `medium`, `high`, `critical`. The finding's base severity; `lib/findings.sh`'s rubric adjusts it from there. An unrecognised value is ignored rather than trusted, and a row with none lands on `high`. |
| `fixed_versions` | comma-separated, opaque display text, never compared. Empty is legal. |
| `summary` | one line of prose. No TAB, no LF. Empty is legal. |

There is deliberately **no CWE, no CVSS vector and no reference URL** in a row.
The check's own `checks.rules` record carries the CWE and the OWASP category, and a row that carried its
own would be a second, drifting source for the same fact.

## 4. The product key is frozen

An exact lookup is only as good as its key, so the normalisation is frozen here and implemented in exactly
one place, `banner_normalize_product` in `modules/dast/passive/banner_engine.sh`:

> Lowercase.
> Every run of characters outside `[a-z0-9]` collapses to a single `-`.
> Leading and trailing `-` are stripped.

| Banner text | Key |
|---|---|
| `nginx/1.18.0` | `nginx` |
| `Apache/2.4.49 (Unix)` | `apache` |
| `Microsoft-IIS/10.0` | `microsoft-iis` |
| `ASP.NET` | `asp-net` |
| `X-AspNet-Version: 4.0.30319` | `aspnet` (the header name reduced: `x-` prefix and `-version` suffix dropped) |
| `<meta name="generator" content="WordPress 5.8.1">` | `wordpress` |
| `/static/jquery-3.4.1.min.js` | `jquery` |

Two consequences worth stating, because both have bitten this class of table before:

- The key is **not** a CPE and not a vendor/product pair.
  A banner names one string and this table is keyed on that string; mapping it to a CPE would be an
  inference the scanner has no data to make.
- A product whose banner text differs from its key by more than case and punctuation - a rebranded name, a
  distribution's own spelling - will simply not match.
  That is a miss, and a miss is reported: a discovered product with no row of any version in this file is
  counted into a `versions_db_product_unknown` coverage record, so "the list has never heard of this
  component" never renders as "this component is fine".

## 5. How the list is refreshed, and by whom

**A list nobody can refresh becomes wrong quietly, so the refresh path is part of the format.**

The refresh is an **operator action on a networked box**.
It is never part of a scan, and no code path in `modules/` or `lib/` writes this file.

**The importer**: `tools/vendor-engines.sh advisories banner` resolves an operator-supplied
`SCOURSH_ADVISORY_BANNER_IDS` (comma/space-separated OSV.dev advisory ids, e.g. `CVE-2021-41773`) the
identical way every SCA ecosystem's own `SCOURSH_ADVISORY_<ECOSYSTEM>_IDS` does, and writes the result
into `data/versions.db`'s `banner` namespace **only** - never `data/advisories.db`, which
`modules/sca/` reads and which has no use for a row with no SCA ecosystem.
The product key is normalised through `banner_normalize_product` (§4) - the same frozen function
`modules/dast/passive/banner.sh` reads with, sourced rather than re-implemented, so the writer and the
reader can never drift apart.
It is deliberately **not** one of `VENG_ADVISORY_REGISTRY`'s six SCA ecosystems: it is reached from its
own `banner` command (`tools/vendor-engines.sh advisories banner`), it is not swept into
`advisories --list`/`--all`, and it has no `advisories bulk` path, because OSV.dev publishes no
per-ecosystem bulk-export archive for a synthetic "banner" ecosystem.
Because a banner-matched product carries no single OSV ecosystem string the way an npm or PyPI
advisory does, the importer takes every `affected[]` entry that names a package, regardless of its own
`ecosystem` field (`tools/vendor-engines.sh`'s own `_veng_advisories_osv_ecosystem` "banner" case, the
wildcard sentinel `*`) - so a CVE tracked under `Debian`, `Alpine`, or with no ecosystem field at all is
still picked up.
A missing severity on a `banner` row defaults to **`high`**, not the SCA rows' `medium` default: a
deliberately more conservative fallback for a directly-exploitable, internet-facing product, frozen in
§3 above.

Run it, on a networked box:

```sh
SCOURSH_ADVISORY_BANNER_IDS='CVE-2021-41773,CVE-2021-44228' tools/vendor-engines.sh advisories banner
```

`tests/suites/vendor-engines-advisories.sh` (section D2) is the fixture-driven proof, against
hand-authored, OSV.dev-*shaped* fixtures under `tests/fixtures/vendor-engines/osv/` - never a live
fetch, the same posture that suite already established for the six SCA ecosystems.

Verify: `bash tests/run-tests.sh dast-banner` still passes, and a run against a target you know is
affected reports `DAST-BANNER-OUTDATED_COMPONENT-01`.

**A stale list produces false negatives, not false positives**, which is the failure mode that hides.
That asymmetry is why the generation stamp is reported in the finding text and why a run with no banner
rows at all records a `coverage_reduction` naming the missing data rather than a clean result.

## 6. What a missing or empty list does

Never an error, always a recorded reduction (`docs/DESIGN.md` §15):

| State | `modules/dast/passive/banner.sh` behaviour |
|---|---|
| file absent or unreadable | `coverage_reduction reason=versions_db_absent`; the two disclosure checks still run. |
| file present, no `banner` row | `coverage_reduction reason=versions_db_no_banner_rows`; the two disclosure checks still run. This is the state of a fresh clone. |
| file present with `banner` rows | the out-of-date check runs; the `# generated:` stamp is recorded in `run.json` and in every finding's evidence. |
| a discovered product with no row of any version | counted into one `coverage_reduction reason=versions_db_product_unknown` roll-up, never one record per product. |

`SCOURSH_DAST_VERSIONS_DB` overrides the path, which is how the test suite points at
`tests/fixtures/dast/versions.db` instead of the shipped file.
It is a test seam, not a supported way to run a scan against someone else's database.
