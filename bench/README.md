# `bench/` — the detection benchmark harness

A rig for measuring scoursh's detection against other tools on **neutral,
pinned, third-party corpora**, and for scoring the result honestly.

This directory is tickets **B1 (harness)**, **B2 (corpus manifest)** and
**B3 (scorer)** of the benchmark plan. The per-category measurement legs
(B4 SAST, B5 SCA, …) and the published page (B9) are follow-ups; **no number
produced here is published anywhere in `docs/` yet, and that is deliberate.**

---

## What `bench/` is not

It is **not part of the scanner.** Nothing under `lib/`, `modules/` or
`scan.sh` references it, and nothing here sources a scanner library —
`tests/suites/bench.sh` section G asserts both directions.

That separation is what lets the harness use the network at all. scoursh is
egress-restricted; the harness orchestrating Semgrep, Trivy, Grype and
OSV-Scanner is not, because **the constraint binds the tool under test, not
the test rig.** Those tools need the network to work at all. Even so, only
one file here ever reaches it — `bench/fetch-corpus.sh`. Fetch a corpus once
and every measurement run afterwards is offline, which is also the only way
the suite can run on the air-gapped host scoursh is designed for.

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

---

## Layout

| Path | What it is |
|---|---|
| `corpus.lock` | every corpus, pinned by **full 40-hex commit**, with its licence and how its ground truth is obtained |
| `cwe-classes.conf` | the CWE equivalence classes STRICT matching uses, published up front |
| `fetch-corpus.sh` | the one network-touching script |
| `make-sample.sh` | a balanced, deterministic sample of a fetched corpus |
| `run-tool.sh` | run one tool, preserve raw output, emit normalised records |
| `score.sh` | the scorecard renderer (markdown or JSON) |
| `lib/json.sh` | a depth- and string-aware JSON flattener |
| `lib/normalise.sh` | the normalised record shape and its one JSON writer |
| `lib/corpus.sh`, `lib/truth.sh` | the lock-file and ground-truth readers |
| `lib/score.sh` | the confusion matrix, the matching modes, the ratios |
| `tools/<tool>.sh` | one adapter per tool |
| `corpora/` | fetched corpora — **gitignored, never committed** |
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
gate configuration per tool, one machine, one run. The B4 leg is what produces
publishable SAST numbers.
