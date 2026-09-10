# `bench/` — the detection benchmark harness

A rig for measuring scoursh's detection against other tools on **neutral,
pinned, third-party corpora**, and for scoring the result honestly.

This directory is tickets **B1 (harness)**, **B2 (corpus manifest)** and
**B3 (scorer)** of the benchmark plan, plus the **B4 (SAST leg)** and
**B5 (SCA leg)** measurements built on top of them. The remaining
per-category legs (B6 IaC/secrets, …) and the published page (B9) are
follow-ups; **no number produced here is published anywhere in `docs/` yet,
and that is deliberate.**

---

## What `bench/` is not

It is **not part of the scanner.** Nothing under `lib/`, `modules/` or
`scan.sh` references it, and nothing here sources a scanner library —
`tests/suites/bench.sh` section G asserts both directions.

That separation is what lets the harness use the network at all. scoursh is
egress-restricted; the harness orchestrating Semgrep, Trivy, Grype and
OSV-Scanner is not, because **the constraint binds the tool under test, not
the test rig.** Those tools need the network to work at all. Even so, only two
files here ever reach it — `bench/fetch-corpus.sh` (git-cloned corpora) and
`bench/fetch-sca-corpus.sh` (the SCA leg's own corpus, built from
`bench/sca-advisories.lock` and re-verified live against OSV.dev by default;
`--offline` skips even that and builds from the pin alone). Fetch a corpus
once and every measurement run afterwards is offline, which is also the only
way the suite can run on the air-gapped host scoursh is designed for.
`tests/suites/bench.sh` section G's network-isolation check names both files
by basename; `tests/suites/bench-sca.sh` section E re-asserts it for the SCA
leg's own files specifically.

**The SCA leg (B5) additionally needs `data/advisories.db` populated** before
`bench/tools/scoursh-sca.sh` can produce anything but coverage-reduction
noise — that database is scoursh's own required input for `scan.sh sca`
(AGENTS.md's tension-14 entry), it is gitignored, and building it is a
separate, documented, by-hand step
(`tools/vendor-engines.sh advisories bulk <ecosystem>`) that this harness
never runs on its own. See `bench/results/sca-lockfiles-26/README.md` for
the exact snapshot this leg's committed results were measured against.

---

## Running it

```sh
# 1. Fetch a corpus.  The ONLY step that touches the network.
bench/fetch-corpus.sh --list
bench/fetch-corpus.sh owasp-benchmark

# 2. Build a balanced, deterministic sample (optional; the full corpus works too).
bench/make-sample.sh owasp-benchmark sast-192 --per-class 12 \
  --categories 'sqli cmdi ldapi pathtraver crypto hash weakrand xss'

# 3. Run each tool.  Raw output is preserved verbatim beside the normalised form.
#    Add --portable-paths for a result you intend to COMMIT: it rewrites the
#    absolute scan-root prefix to <SCAN_ROOT> and the bench/ prefix to <BENCH>,
#    so a committed artefact does not embed an operator's home directory.
bench/run-tool.sh --tool scoursh --sample sast-192 --out bench/results/my-run
bench/run-tool.sh --tool semgrep --sample sast-192 --out bench/results/my-run

# 4. Score.  Both CWE matching modes, always; both severity columns, separately.
bench/score.sh --truth bench/corpora/_samples/sast-192/truth \
               --results bench/results/my-run --format md
bench/score.sh --truth bench/corpora/_samples/sast-192/truth \
               --results bench/results/my-run --min-severity high --format json
```

`bench/run-tool.sh --list-tools` shows the adapters present.

The SCA leg (B5) follows the identical four-step shape, substituting its own
fetch script and corpus id - see `bench/results/sca-lockfiles-26/README.md`
for the exact commands used and why they differ where they do (one
`scoursh-sca` invocation per case directory; `osv-scanner` needs explicit
`--lockfile` arguments rather than a directory scan; `trivy-fs` runs against
a cached, not freshly pulled, vulnerability database on this host).

---

## Layout

| Path | What it is |
|---|---|
| `corpus.lock` | every git-cloned corpus, pinned by **full 40-hex commit**, with its licence and how its ground truth is obtained |
| `sca-advisories.lock` | the SCA leg's own pin: real OSV.dev advisories, resolved live and recorded with a timestamp (no git commit to pin, since there is no single third-party SCA benchmark repository - see its own header) |
| `cwe-classes.conf` | the CWE equivalence classes STRICT matching uses, published up front |
| `labels/` | **hand-authored ground truth**, committed - the corpora that ship none of their own |
| `fetch-corpus.sh` | fetches a git-cloned corpus (owasp-benchmark, terragoat, kubernetes-goat, leaky-repo) |
| `fetch-sca-corpus.sh` | builds the SCA leg's lockfile corpus from `sca-advisories.lock` |
| `make-sample.sh` | a balanced, deterministic sample of a fetched (git-cloned) corpus |
| `make-slice.sh` | a scan root that is a subset of a fetched corpus, so every tool sees one surface |
| `run-tool.sh` | run one tool, preserve raw output, emit normalised records |
| `score.sh` | the scorecard renderer (markdown or JSON) |
| `lib/json.sh` | a depth- and string-aware JSON flattener |
| `lib/normalise.sh` | the normalised record shape and its one JSON writer |
| `lib/corpus.sh`, `lib/truth.sh` | the lock-file and ground-truth readers |
| `lib/sca_advisories.sh` | the `sca-advisories.lock` reader (a separate, simpler format - see its own header) |
| `lib/score.sh` | the confusion matrix, the matching modes, the ratios |
| `tools/<tool>.sh` | one adapter per tool - `scoursh`/`semgrep` (SAST, B4), `scoursh-sca`/`grype`/`osv-scanner`/`trivy-fs` (SCA, B5) |
| `corpora/` | fetched/built corpora — **gitignored, never committed** |
| `results/` | committed run outputs |

### The normalised record

One JSON object per line:

```json
{"tool":"semgrep","version":"1.176.0","corpus":"sast-192",
 "file":"src/…/BenchmarkTest00001.java","line":72,
 "cwe":"22","severity":"high","rule_id":"java.lang.security.…"}
```

`severity` is the common scale `critical high medium low info`. `line` and
`cwe` are `null` when the tool gave none — never `0`, never `""`.

### Adding a tool

Write `bench/tools/<name>.sh` implementing five functions —
`<name>_available`, `<name>_version`, `<name>_run`, `<name>_normalise`,
`<name>_scope` — and add a row to `_gate_line` in `bench/run-tool.sh` so the
configuration it was run at is recorded rather than implied. The contract is
documented at the top of `bench/tools/scoursh.sh`.

`<name>_scope` is the important one: it declares which categories the tool
**claims**, and a category it does not claim renders as an explicit
`no coverage` cell rather than as a zero.

### Ground truth a corpus does not ship: `bench/labels/`

A `corpus.lock` row whose `ground-truth` reads `labels:<file>` names a file
under `bench/labels/` rather than a file inside the corpus. That file is
ground truth **this project authored**, and it is committed for the reason the
whole harness exists: a benchmark whose labels nobody can inspect is not a
benchmark. Three exist today, one per B6 corpus.

Each carries, in its own header, the rules every call was made under, and a
short rationale beside **every single case**. `tests/suites/bench-b6-labels.sh`
enforces the structural half of that - a range on every case, no two ranges
overlapping within a file, both `real` and clean cases present, and a comment
line above every record. What a label SAYS about a resource is not checkable
without the corpus and is not claimed to be; that is what the rationale is for,
and what a reviewer spot-checks.

Two rules bind a hand-authored label set, and both are in each file's header:

- **No tool's output of any kind may be consulted to produce it** (methodology
  rule R2). It is the one property a reader cannot verify from the file, which
  is why the labelling rules are written down so every call can be re-derived
  independently.
- **A call that is genuinely arguable is marked BORDERLINE and re-scored both
  ways in the leg's README.** A reader who disagrees can then see exactly what
  the disagreement is worth.

### Matching granularity: `--match file` and `--match line`

The scout report's §5.2 gives two corpus shapes and they need different
matching. `--match file` is the default and is the "one file per test case" row
- OWASP Benchmark, Juliet. `--match line` is the "multiple defects per file"
row: a truth row then carries a sixth field, its case's line range, and a case
is flagged only by a finding inside that range.

The difference is not cosmetic. TerraGoat's `rds.tf` declares nine separate
clusters; under file granularity one finding anywhere in it scores nine true
positives. The granularity is chosen by the caller and printed in the
scorecard, never inferred from whether the truth happens to carry ranges - and
`--match line` over a truth file with no ranges is exit 2 rather than a silent
demotion to the inflated reading.

`--line-window` defaults to **0**, because the B6 ranges are real extents rather
than anchors. A window large enough to matter starts merging neighbouring
cases; `tests/suites/bench-b6-labels.sh` pins that with the arithmetic.

### Adding a corpus

Add a record to `corpus.lock` with a full 40-hex `commit`, an SPDX `licence`,
and a `ground-truth` field. A corpus with `ground-truth: none` can be used for
coverage metrics but never for recall: `bench/make-sample.sh` refuses to sample
it, so no truth file is ever produced for it and there is nothing to hand
`bench/score.sh --truth`. The refusal is at the point a truth file would be
manufactured, not at the point one would be read.

**Do not commit corpus content.** `bench/corpora/` is gitignored. OWASP
Benchmark is GPL-2.0 and this repository is Apache-2.0, so vendoring even its
ground-truth CSV would put GPL-2.0 material in an Apache-2.0 tree.

---

## What must not be published

These four rules are the reason this harness exists, and every one of them
comes from a defect already found in `docs/COMPARISON.md`. They bind anything
derived from a `bench/` run.

1. **No number measured on any tool's own test fixtures.** A tool's rules were
   authored against its own cases, so a high score there measures "still
   passes its own cases", not "finds vulnerabilities it has never seen". This
   is not a theoretical risk: the same two tools on the same class of task
   invert their ranking between scoursh's fixtures and a neutral corpus, and
   the gap is worth roughly seventy percentage points of recall. Nothing in
   `bench/` will score `tests/fixtures/`.

2. **No single overall score across categories.** The scope differences make
   it meaningless and it is the first thing an unfriendly reader attacks.
   `bench/score.sh` emits per-category rows and a **per-corpus** aggregate
   that names exactly which categories it spans and how many were excluded as
   no-coverage. It will not combine two corpora into one number.

3. **No number without its tool version and corpus commit hash.** Every
   `MANIFEST` records both, and the scorecard's tool table reprints them.
   `0.1.0-dev` alone is not a version anyone can re-run against, which is why
   the scoursh adapter appends the commit.

4. **No runtime comparison on a corpus small enough for the fixed cost to
   dominate.** scoursh costs roughly 38 s of startup plus ~0.3 s/file, so a
   total on a small corpus is mostly startup and every such comparison is
   wrong in scoursh's disfavour. Publish `t = a + b·n` with both coefficients
   measured across at least two corpus sizes, or publish nothing.

Two more rules govern how a result is *read* rather than whether it may be
published:

- **A `no coverage` cell is not a zero.** A zero says the tool looked and
  failed; a no-coverage cell says it never claimed the category. Folding the
  second into the first is precisely the failure scoursh's own honesty
  contract exists to prevent, and doing it in the benchmark that judges
  scoursh would be indefensible.
- **Recall alone is not a result.** A rule that flags every file scores 100%
  on it. Lead with **Youden J = TPR − FPR**, and print `J = 0.000 is a coin
  flip` beside it. The scorer does both, every run, and also reports whether
  strict and loose CWE matching agreed — because a ranking that holds under
  only one of them is a fact about the scoring method, not about the tools.

---

## Smoke result

`bench/results/smoke-owasp-sast-192/` holds one end-to-end proof that the
harness and the scorer work: scoursh and Semgrep over a 192-case OWASP
Benchmark sample (96 real, 96 sanitized traps), with each tool's raw output,
its normalised records, its manifest, and the rendered scorecard. Its own
`README.md` states what it is and is not.

It is a **smoke test of the rig**, not a benchmark result: one sample, one
gate configuration per tool, one machine, one run.

## B4 SAST leg

`bench/results/b4-sast-owasp-full/` is the B4 leg: scoursh plus Semgrep at
**both** its documented-default (`p/default`) and maximum-free-ruleset gate
configurations, over the **full, unfiltered 2,740-case** OWASP Benchmark
corpus. It is real, committed, reproducible data - the headline numbers,
per-category diagnosis, and what could not be measured here (Bandit, gosec,
and a NIST Juliet slice, each with its own stated reason) are in that
directory's own `README.md`.

**It is not published anywhere in `docs/`.** That is ticket B9, deliberately
kept separate so a launch page is composed once, from every landed leg, rather
than assembled piecemeal as each leg lands.

---

## B5: the SCA leg

`bench/results/sca-lockfiles-26/` holds the SCA leg's own real measurement:
scoursh, Trivy `fs`, Grype and OSV-Scanner over a 26-case pinned lockfile
corpus (13 real npm/PyPI/Go advisories, each paired with its patched
counterpart), with raw output, normalised records, manifests, and the
rendered scorecard for every tool. **Its own `README.md` is the primary
account of this leg** - the exact `data/advisories.db` snapshot it was
measured against, the DB-size/egress-before-first-finding columns, three
environment-specific tool quirks discovered while building it (and how each
was resolved), and why loose ("any finding in this file") matching is a poor
fit for SCA specifically, unlike SAST. Read it before citing a number from
this leg anywhere.

**It is not published anywhere in `docs/` either** - the same B9 deliberate
deferral as the B4 leg above.

---

## B6 IaC and secrets legs

Three directories, one ticket:

| Result | Corpus | Tools | Ground truth |
|---|---|---|---|
| `bench/results/b6-iac-terragoat-aws/` | TerraGoat, `terraform/aws` | scoursh, Checkov, KICS, Trivy | `bench/labels/terragoat-aws.truth` - 71 cases |
| `bench/results/b6-iac-kubernetes-goat/` | kubernetes-goat `scenarios/` | scoursh, Checkov, KICS, Trivy | `bench/labels/kubernetes-goat.truth` - 35 cases |
| `bench/results/b6-secrets-leaky-repo/` | leaky-repo | scoursh, Gitleaks, TruffleHog | `bench/labels/leaky-repo.truth` - 82 cases |

Each directory's own `README.md` is the authority for its numbers, its framing
and what it is weak evidence for. Three facts are worth carrying here because
they bind anything derived from the set:

- **The three legs do not agree, and that is the useful part.** The same four
  IaC tools scored the same way rank scoursh last on Terraform and second of
  four on Kubernetes; the secrets leg ranks it first. A single "IaC" or
  "secrets" number across corpora would hide all of that, which is why
  `bench/score.sh` refuses to compute one.
- **Only the all-findings column is published for these legs**, and the reason
  is a property of the tools rather than a choice: Checkov CE, Gitleaks and
  TruffleHog each ship **no severity at all**, so a `--min-severity high` column
  would compare one tool's real severities against a placeholder for the others
  and report them at zero recall. Each leg's README states the measurement.
- **Strict CWE matching is not defined for any of them.** The labels are
  per-resource and per-credential and carry no CWE, and the scorer renders that
  as an explicit `no CWE in truth` cell rather than a row of zeros. Inventing a
  rule-id-to-CWE mapping per tool would have put an unauditable dial between the
  corpus and the result.

- **A secrets leg's raw output is committed REDACTED**, which is the one place
  the "raw output verbatim" rule bends and it bends for a measured reason:
  committing it unredacted was refused by GitHub push protection, correctly.
  `bench/run-tool.sh --redact-secret-values` replaces the matched credential
  with a `<redacted:N-bytes>` placeholder, leaves every other field alone,
  records itself in the MANIFEST, and FAILS THE RUN rather than writing that
  record if the redaction did not actually happen.

**SecretBench is an explicit not-measured cell** - it needs a Google Cloud
account, a signed data-protection agreement and per-email access granted by its
authors, none of which a benchmark run can satisfy. See
`bench/results/b6-secrets-leaky-repo/README.md`.

---

## B8: honesty + egress metrics

`bench/results/b8-honesty-egress/` holds the scout report's §5.3
coverage-honesty metric (computed over every scoursh `run.json` already
committed by B4/B5/B6 - 31 of 31 runs, 100% of unrun-but-selected checks
declared with a reason, zero undeclared gaps), a zero-egress proof of
`sast`/`sca`/`iac` under both the kernel-enforced macOS Seatbelt sandbox
(`tools/run-sandboxed.sh`, no `--scope-conf`) and the `--paranoid` detector,
and a footprint table (installed size, peak process memory,
DB-size-before-first-finding, egress-after-setup) across the tool roster.
`bench/tools/coverage-honesty.py` is the metric's own script - re-runnable
against any future leg's `bench/results/` tree with no arguments beyond the
results root.

**B7 (DAST) has not landed** - it needs an operator Docker-memory bump
(scout report §4.4) - and B8 records that as a stated not-measured gap
wherever a metric would otherwise need a DAST number, never a fabricated
value. See that directory's own `README.md` for the full account, including
a real environmental interaction it found (`--paranoid`'s process-family
enumeration degrades, but still reports correctly, when run nested inside
the Seatbelt sandbox).

**It is not published anywhere in `docs/` either** - the same B9 deliberate
deferral as every other landed leg.
