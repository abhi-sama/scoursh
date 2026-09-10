# SCA leg (B5) — pinned lockfile corpus, 26 cases

**This is a real measurement, not a smoke test.** Four tools ran over the
identical 26-case corpus: scoursh, Trivy `fs --scanners vuln`, Grype and
OSV-Scanner. The scout report's own §7.1 prediction — "genuine parity on
package-level recall" for SCA — is confirmed for two of three ecosystems and
refuted for the third, for reasons this document states plainly rather than
averaging away. Read this whole file before citing a number from it: the
headline result depends on which of the two matching modes (§4 below) is
being quoted, and quoting the wrong one inverts the story.

---

## 1. What was run

| | |
|---|---|
| Corpus | `bench/sca-advisories.lock` → `bench/fetch-sca-corpus.sh` → 26 cases (13 real npm/PyPI/Go advisories, each paired with its patched counterpart) |
| Categories | `sca-npm` (6 advisories), `sca-pypi` (4 advisories), `sca-go` (3 advisories) |
| scoursh | `0.1.0-dev+1710274dbf30`, `scan.sh sca --format json`, defaults, **no `--use-engines`**, one invocation per case directory (see §5) |
| Trivy | `0.74.0`, `fs --scanners vuln --format json --skip-db-update --skip-java-db-update` (see §6 for why `--skip-db-update`) |
| Grype | `0.118.0`, `dir:<root> -o json`, default local DB state |
| OSV-Scanner | `2.5.1`, `scan source --format json --lockfile <each manifest>` (see §6 for why not a directory scan) |
| Host | one macOS machine, one run each, 2026-09-10 |

Every advisory in the corpus was resolved **live against `api.osv.dev`** on
2026-09-10 and is pinned with its exact vulnerable version, its exact fixed
version, its OSV canonical id, its CVE alias (where one exists), and its
`database_specific.severity` — see `bench/sca-advisories.lock`'s own header
for the full field list and `bench/fetch-sca-corpus.sh` for how the corpus is
rebuilt from it (`--offline` skips the re-verification and builds from the
pin alone).

## 2. Prerequisite: `data/advisories.db`

scoursh's SCA module needs a populated `data/advisories.db` before it can
match anything — an absent one is a required-input refusal (`scan.sh` exit
4), never a clean empty run (AGENTS.md's tension-14 entry). It is built,
by hand, on a networked box, and is itself gitignored, so nothing here
commits it. This leg populated three ecosystems — the three the corpus
covers — via:

```sh
bash tools/vendor-engines.sh advisories bulk --accept-unverified npm
bash tools/vendor-engines.sh advisories bulk --accept-unverified pypi
bash tools/vendor-engines.sh advisories bulk --accept-unverified Go
```

| Ecosystem | Advisories read | Rows written | Wall clock | Notes |
|---|---|---|---|---|
| npm | 228,915 | 269,350 | 16.7 s | |
| pypi | 25,367 | 1,278,017 | 24.4 s | 7,075 range-only advisories (23%) skipped — tension 25 requires an exact version list |
| Go | 9,135 | **187** | 10.5 s | **13,901 range-only advisories (98%) skipped** — the importer's own words: "will miss most real-world CVEs in this ecosystem" |

Resulting `data/advisories.db` (npm + pypi + Go only): **86 MB** on disk (86 MB
`data/versions.db` alongside it, same rows). Every row's provenance —
integrity grade, source URL, per-ecosystem counts — is in the file's own
header; `grade=unpinned-transport-only` because this run used
`--accept-unverified` (no operator-supplied `--sha256`), the same grade the
scout report's own §4.3 measurement used.

**This database is not committed and is not reproducible from this repository
alone** — it is a live snapshot of OSV.dev's bulk export on 2026-09-10, and a
re-run on a different day gets different (larger) numbers. That is expected
and is the point: `tools/vendor-engines.sh` explicitly refuses to pretend
otherwise.

## 3. The DB-size / egress column (§4.3/§5.3)

The distinguishing metric the scout report's §4.5 asked for, measured rather
than asserted:

| Tool | Local DB before first finding | Egress per run |
|---|---|---|
| **scoursh** | 86 MB (npm+pypi+Go only; ~270–400 MB for all six per the scout report's own estimate) | **zero** — reads `data/advisories.db` only; the file itself is built by a separate, quarantined, by-hand step (`tools/vendor-engines.sh`), never at scan time |
| Trivy | 1.3 GB (`trivy.db`, this host's cache) | one OCI pull per DB refresh (`mirror.gcr.io/aquasec/trivy-db:2`); **this run used a cached DB and pulled nothing** — see §6 |
| Grype | 2.0 GB (`~/Library/Caches/grype`) | one archive pull per DB refresh; this run used the already-cached DB |
| OSV-Scanner | **0 bytes local** | **one live query to `api.osv.dev` per run** (no `--offline-vulnerabilities`/`--download-offline-databases` given) — the opposite shape from the other three: no local footprint, but egress on every single invocation |

scoursh's local footprint is **~15–23× smaller** than Trivy's or Grype's for
the three ecosystems this leg populated, and it is the only one of the four
that makes zero network calls once that footprint exists. Run under
`--paranoid` (not done for this leg — see `docs/FOUNDATION.md` tension 20),
this is a provable, not merely claimed, zero-egress guarantee; no competitor
here can make the same claim about its own detection pass.

## 4. Two matching modes, and only one of them is the right question for SCA

`bench/lib/score.sh` computes **loose** ("the tool reported *anything* in
this case's manifest") and **strict** ("...with an identity — OSV id or CVE
alias — matching the pinned advisory") every run, exactly as it does for the
SAST leg. For SAST, strict means "the right CWE"; here, the ground-truth
`cwe` field (`bench/lib/truth.sh`'s format) is repurposed to carry the
pinned advisory's **OSV canonical id** instead of a CWE number, and every
adapter emits one record per id the tool's own output associates with a
finding (`bench/tools/grype.sh`'s own header explains why — a tool may
report the CVE alias instead of the GHSA id for the identical vulnerability,
and crediting only one spelling would undercount a tool for a
naming-convention difference that has nothing to do with detection).

**Loose matching is structurally the wrong question for SCA, and the numbers
show it directly.** Every general-purpose SCA scanner reports **every known
vulnerability** for a given package version — lodash 4.17.15 alone carries
six distinct GHSA advisories across Grype's own database. Patching *one* of
them (the corpus's own `-patched` case, pinned to the version that fixes only
the ONE advisory this leg selected) does not make the file clean of the
*other five*. The loose scorecard's own FP rates make this concrete:

```
grype        sca-npm   TP=6 FN=0 FP=3 TN=3   FPR=0.500
grype        sca-pypi  TP=4 FN=0 FP=3 TN=1   FPR=0.750
grype        sca-go    TP=3 FN=0 FP=3 TN=0   FPR=1.000
```

Grype, Trivy and OSV-Scanner **all three** produce *exactly* these numbers
under loose matching, because "did the file get flagged at all" is
answering "does this version have ANY known issue", not "did the tool find
THIS advisory" — and every patched version in this corpus, chosen to fix one
specific vulnerability, still legitimately has others. A loose-matching
recall/FPR table for SCA therefore measures the corpus's own richness of
prior vulnerabilities, not the tool. **Strict (identity) matching is the
metric this leg treats as primary**, and it is what §5 below reports.

This is a leg-specific, measured discovery, not a general property of the
harness inherited unchanged from SAST: OWASP Benchmark's SAST cases are
single-issue by construction (a test case is deliberately either vulnerable
to ONE thing or a sanitized trap), so loose and strict matching diverge only
when a tool misattributes a CWE — they do not structurally diverge on every
single case the way they do here.

## 5. Results — strict (identity) matching, the primary metric for this leg

| Category | Grype | OSV-Scanner | Trivy `fs` | **scoursh** |
|---|---|---|---|---|
| `sca-npm` (6 advisories) | 6/6 (100%) | 6/6 (100%) | 6/6 (100%) | **6/6 (100%)** |
| `sca-pypi` (4 advisories) | 4/4 (100%) | 4/4 (100%) | 4/4 (100%) | **4/4 (100%)** |
| `sca-go` (3 advisories) | 3/3 (100%) | 3/3 (100%) | 3/3 (100%) | **0/3 (0%)** |
| **Aggregate recall** | 13/13 (1.000) | 13/13 (1.000) | 13/13 (1.000) | **10/13 (0.769)** |
| **Aggregate precision** | 1.000 | 1.000 | 1.000 | **1.000** |
| **Aggregate Youden J** | +1.000 | +1.000 | +1.000 | **+0.769** |

**scoursh: zero false positives across all 26 cases, in every category, under
both matching modes.** Every one of its 10 true positives correctly names the
pinned advisory id; it never once flagged a patched case. The scout report's
prediction is confirmed exactly for npm and PyPI — **perfect parity with all
three specialists** — and the aggregate is pulled down entirely by a
structural gap in Go coverage, explained in full in §7. This is not a subtle
statistical result: it is 13 of 13 non-Go cases correct and 0 of 3 Go cases
detected, for two independently identifiable and already-partly-documented
reasons.

Full tables (all four tools, all three categories, both severity columns,
the strict/loose agreement table) are in `scorecard-all-findings.md` and
`scorecard-high-and-critical.md`; the same data is in
`scorecard-all-findings.json` for a consumer.

## 6. Three environment-specific tool quirks, and how each was resolved

None of these are claims about the tools in general — they are what this
particular host, on this particular day, actually did, recorded so a
re-run elsewhere is not surprised by a different failure mode.

**OSV-Scanner's own directory recursion (`scan source -r <root>`) found
nothing on this host.** `osv-scanner scan source --format json -r <root>`
(and every variant tried: an absolute path, `--include-git-root`) logged
`Starting filesystem walk for root: /` — not the given root — and
`0 Extract calls` over a directory this session had just confirmed held 26
real lockfiles, ending in `No package sources found`. Explicit
`--lockfile <path>` arguments (`osv-scanner scan source --lockfile a
--lockfile b ...`) bypass that walker entirely and were confirmed working
against the identical files. `bench/tools/osv-scanner.sh` enumerates the
three manifest basenames this corpus ships and passes each as its own
`--lockfile` flag; its own header records the full account for whoever
next runs `-r` and finds it does not reproduce.

**A fresh `trivy fs --scanners vuln` (no skip flags) hung past several
minutes** at `[vulndb] Downloading artifact... repo=mirror.gcr.io/aquasec/trivy-db:2`,
while a direct reachability check to the same host returned in well under a
second at the same time — not a blanket egress failure, and Trivy's own
`config`-only IaC path (no DB needed) already ran sub-second in the scout
report's own pilot. `--skip-db-update --skip-java-db-update` against the
already-cached DB (dated on disk to **2026-09-08, two days before this leg's
run**) worked immediately. **This means Trivy is measured here against a
database that was not freshly pulled at run time** — the opposite of the
egress cost §3's column exists to quantify for the other three tools, stated
here rather than left for a reader to infer from a flag in a manifest.

**`bench/lib/normalise.sh`'s `bench_flat_read` could not process a tool run
that found literally nothing in one file.** `bench_json_flatten`
deliberately emits a root-level marker record for a bare `[]`/`{}` document
(`bench/lib/json.sh`'s own header: "without them ... 'the tool reported an
empty result set' becomes indistinguishable from 'the tool wrote no output
at all'"), and that marker's `path` is the empty string — which bash refuses
as an associative-array subscript on *either* side of an assignment, quoted
or not (confirmed directly: `declare -gA a=(); x=''; a[$x]=v` and
`a["$x"]=v` are both `bad array subscript`). Every prior bench/ adapter
happened to always see at least one real finding somewhere in its corpus, so
this was latent rather than fixed. It is exactly what an SCA benchmark's own
"patched" half is built to exercise — a file with zero findings is the
*expected*, common case here, not an edge case — so this leg hit it
immediately and fixed it at the source (`bench_flat_read` now skips the
empty-path marker; nothing downstream ever read it), with a regression test
in `tests/suites/bench.sh` covering both the empty-array and empty-object
shapes under `set -e`, the exact condition that was aborting the run.

## 7. Why scoursh's Go recall is 0/3 — two separate, both-real reasons

**Two of the three Go cases (`go-x-text`, `go-gorilla-websocket`) cannot be
matched no matter how the run is configured**, because their pinned
advisories publish only a SEMVER range, never an explicit affected-version
list, and `tools/vendor-engines.sh`'s own exact-version-only import
(`docs/FOUNDATION.md` tension 25) drops those rows entirely — confirmed
directly against the freshly built `data/advisories.db` (`grep` for either
module: zero rows). This is the same, already-self-reported gap the importer
prints at build time (§2's table: "98% ... will miss most real-world CVEs in
this ecosystem"), not a new defect; `bench/sca-advisories.lock`'s own notes
for these two cases record the same confirmation with a timestamp.

**The third (`go-hashicorp-vault`) is a genuine, previously-undetected
scoursh bug, deliberately kept in the corpus rather than swapped out.** It
was chosen *specifically* because its advisory (GHSA-9v3w-w2jh-4hff,
CVE-2023-3462) **does** survive the exact-version import — confirmed present
in `data/advisories.db` as `Go	github.com/hashicorp/vault	1.14.0	GHSA-9v3w-w2jh-4hff	medium	1.14.1`
— so this case was meant to prove the matching logic works when the row
exists. It does not: `modules/sca/go_engine.sh`'s `_sca_go_mod_require_line`
reads a `go.mod` `require` line's version VERBATIM, which Go's own tooling
always writes with a leading `v` (`v1.14.0`), and
`sca_go_normalize_version` strips only a trailing `+incompatible` suffix —
never the leading `v`. The database row it must match against was written
from OSV's own raw `versions` field for this specific advisory, which
happens to spell the same version **without** the `v` (`"1.14.0"`, confirmed
by querying `https://api.osv.dev/v1/vulns/GHSA-9v3w-w2jh-4hff` directly — its
`ranges` block for the same version ALSO omits the `v`). The lookup is
therefore `v1.14.0` against a table keyed on `1.14.0`: a guaranteed miss for
*any* real `go.mod`, since Go's own syntax requires the `v` prefix Go module
versions always carry it. `scan.sh sca`'s own output for this case is
`SCA-COV-UNKNOWN_VERSION-01` ("package known, exact version unmatched") —
the coverage-honesty mechanism correctly reports "unknown" rather than
silently reading as clean, but the underlying match still fails.

This is reported here, not fixed here: this PR is the SCA **measurement**
leg (B5), scoped to running and scoring the benchmark, and
`modules/sca/go_engine.sh` is scanner code the benchmark is measuring, not
part of this leg's own deliverable. The fix is small and well-scoped for a
follow-up (strip a leading `v` in `sca_go_normalize_version`, mirroring what
it already does for the trailing `+incompatible` suffix, with the same
both-directions test discipline every fix in this codebase's history uses) —
filing it as scoursh's own ticket, not this leg's, keeps the benchmark
honest about what it measured versus what it repaired.

## 8. Files

| Path | What |
|---|---|
| `SAMPLE-MANIFEST` | how the corpus was built (mirrors `bench/corpora/_samples/sca-lockfiles-26/MANIFEST`) |
| `<tool>/raw/` | the tool's own output, byte for byte (paths rewritten — see below) |
| `<tool>/normalised.jsonl` | the harness's record shape |
| `<tool>/MANIFEST` | version, corpus commit (n/a — see `bench/sca-advisories.lock`), gate, claimed scope, wall clock |
| `scorecard-all-findings.md` / `.json` | every finding, both matching modes, both aggregate tables |
| `scorecard-high-and-critical.md` | the `--min-severity high` column |

Every raw output has exactly one mechanical edit: the absolute scan-root
prefix rewritten to `<SCAN_ROOT>`, the `bench/` prefix to `<BENCH>`, and —
new for this leg, after Grype's own `descriptor.db.location` field was
measured leaking an operator home directory that is neither of the other two
prefixes — any remaining `$HOME` prefix rewritten to `<HOME>`
(`bench/run-tool.sh`'s `_portable_paths`, now three rules instead of two).
Every MANIFEST records that this happened. Nothing else was edited.

## 9. How to reproduce

```sh
# Prerequisite - by hand, on a networked box, per §2 above:
bash tools/vendor-engines.sh advisories bulk --accept-unverified npm
bash tools/vendor-engines.sh advisories bulk --accept-unverified pypi
bash tools/vendor-engines.sh advisories bulk --accept-unverified Go

# Corpus - re-verifies every pinned advisory live; --offline skips that:
bash bench/fetch-sca-corpus.sh

# One run per tool (scoursh-sca takes ~15 minutes: one scan.sh invocation
# per case directory - see §6's normalise-bug entry for why not one pass):
bash bench/run-tool.sh --tool scoursh-sca --sample sca-lockfiles-26 --out <dir> --portable-paths
bash bench/run-tool.sh --tool grype        --sample sca-lockfiles-26 --out <dir> --portable-paths
bash bench/run-tool.sh --tool trivy-fs     --sample sca-lockfiles-26 --out <dir> --portable-paths
bash bench/run-tool.sh --tool osv-scanner  --sample sca-lockfiles-26 --out <dir> --portable-paths

bash bench/score.sh --truth bench/corpora/_samples/sca-lockfiles-26/truth --results <dir> --format md
```

Only the first two blocks need the network (the advisories DB build, and the
corpus's live re-verification — itself skippable with `--offline`).

## 10. What this leg does not claim

Per `bench/README.md`'s must-not-publish rules, restated for what is specific
here:

- **No overall SCA score.** Every number above is per-category or a
  per-corpus aggregate naming exactly which categories it spans.
- **No claim about ecosystems this corpus does not cover.** Maven, RubyGems
  and Composer are untested here; `docs/DESIGN.md` §6.5 names all six.
- **The Go result is a real, reported miss — not evidence Go SCA "doesn't
  work".** §7 draws the line precisely: one structural DB-coverage gap
  (already self-reported by the importer) and one genuine, narrowly-scoped
  normalisation bug, neither of which touches npm or PyPI.
- **Trivy's numbers here used a cached, not freshly-pulled, database** (§6).
  A re-run that successfully refreshes it may differ, and the DB-size figure
  in §3 is this leg's own measurement of that cache, not of a guaranteed-fresh
  pull.
- **26 cases is a real but modest corpus.** It is large enough to show a
  structural pattern (perfect precision, category-scoped recall gaps) but not
  large enough to bound a recall estimate the way OWASP Benchmark's 2,740
  cases can for SAST.
