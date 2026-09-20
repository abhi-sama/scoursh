# Smoke result — OWASP Benchmark, 192-case SAST sample

**This is a smoke test of the harness, not a benchmark result.** It exists to
prove that `bench/run-tool.sh` and `bench/score.sh` work end to end on real
tool output. Nothing in it is published, and nothing in it should be quoted as
a detection number for either tool. The B4 leg — the full 2,740-case corpus,
both gate configurations per tool, more than one tool per family — is what
produces publishable SAST numbers.

## What was run

| | |
|---|---|
| Corpus | `OWASP-Benchmark/BenchmarkJava` @ `20cbf3d11123347e47ed89541e6942836def53f7` (GPL-2.0) |
| Sample | 192 cases: 8 categories × 12 real × 12 sanitized traps — exactly balanced |
| Selection | first N by `LC_ALL=C` sort of the case id — deterministic, never random |
| scoursh | `0.1.0-dev+803503f3d515`, `scan.sh sast --format json`, defaults, **no `--use-engines`** |
| Semgrep | `1.176.0`, `--config p/security-audit --config p/owasp-top-ten` |
| Host | one macOS machine, one run each |

Each tool's directory holds its **raw output**, its **normalised records**,
and a **MANIFEST** naming its version, the corpus commit, the exact gate it
was run at, and the categories it claims.

## Files

| Path | What |
|---|---|
| `SAMPLE-MANIFEST` | how the sample was built |
| `<tool>/raw/` | the tool's own output |
| `<tool>/normalised.jsonl` | the harness's record shape |
| `<tool>/MANIFEST` | version, corpus commit, gate, claimed scope, wall clock |
| `scorecard-all-findings.md` / `.json` | every finding counted |
| `scorecard-high-and-critical.md` | the `--min-severity high` column |

The raw outputs are the tools' own, with **one** mechanical change: the
absolute scan-root prefix was rewritten to `<SCAN_ROOT>` and the `bench/`
prefix to `<BENCH>`, so a committed artefact does not embed an operator's home
directory. Each MANIFEST records that this happened. Nothing else was edited.

## How to reproduce

```sh
bench/fetch-corpus.sh owasp-benchmark
bench/make-sample.sh owasp-benchmark sast-192 --per-class 12 \
  --categories 'sqli cmdi ldapi pathtraver crypto hash weakrand xss'
bench/run-tool.sh --tool semgrep --sample sast-192 --out <dir> --portable-paths
bench/run-tool.sh --tool scoursh --sample sast-192 --out <dir> --portable-paths
bench/score.sh --truth bench/corpora/_samples/sast-192/truth --results <dir> --format md
```

Only the first line needs the network.

## Reading it honestly

Three things this result already shows, all of which are properties of the
**harness** rather than claims about either tool:

- **Strict and loose CWE matching agreed for both tools, in all 8 categories.**
  The scorecard reports that agreement every run. It matters because a ranking
  that holds under only one matching mode is a fact about the scoring method,
  not about the tools.
- **`ldapi` is the diagnostic row.** One tool flagged 12 of 12 real cases *and*
  12 of 12 sanitized traps there. That is perfect recall with zero
  discriminating power — a recall-only table would read it as a flawless
  score, which is exactly why the scorecard leads with Youden J and prints
  `J = 0.000 is a coin flip` beside it.
- **The runtime numbers in the manifests are wall clocks over 192 files, not
  rates,** and must not be compared. scoursh's cost is dominated by a fixed
  startup on a corpus this small; see rule 4 in `bench/README.md`.

Every category here is claimed by both tools, so this sample happens to
contain no `no coverage` cell. That mechanism is exercised by
`tests/suites/bench.sh` section F instead, against a fixture built so a tool
does *not* claim one of the corpus's categories.
