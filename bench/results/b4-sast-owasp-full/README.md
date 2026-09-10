# B4 SAST leg — full OWASP Benchmark corpus (2,740 cases)

**This is the B4 leg deliverable, not a smoke test.** It supersedes nothing in
`bench/results/smoke-owasp-sast-192/` (that result stays as the harness's own
proof-of-rig), and it is not published anywhere in `docs/` - that is ticket
B9, deliberately separate, per `bench/README.md`'s "what must not be
published" rules and the scout report's §7.3.

## What was run

| | |
|---|---|
| Corpus | `OWASP-Benchmark/BenchmarkJava` @ `20cbf3d11123347e47ed89541e6942836def53f7` (GPL-2.0) |
| Cases | **all 2,740** - every category (`sqli cmdi ldapi pathtraver crypto hash weakrand xss trustbound securecookie xpathi`), every real and sanitized-trap case, none excluded |
| scoursh | `0.1.0-dev+8b637cae9ce6`, `scan.sh sast --format json`, defaults (`--profile-scan full --min-confidence low`), **not `--use-engines`** - the fair baseline the scout report's §6.1 requires |
| Semgrep (documented default) | `1.176.0`, `--config p/default` |
| Semgrep (maximum free ruleset) | `1.176.0`, `--config p/security-audit --config p/owasp-top-ten` |
| Host | one macOS machine, one run each |

`SAMPLE-MANIFEST` was produced by `bench/make-sample.sh` with `--per-class
999` - a number chosen because it exceeds every category's real case count
(the largest, `sqli`, has 504), so nothing was excluded and every category
kept exactly the counts the corpus itself has. It is the **full corpus**,
sampled through the same tool as a matter of reuse, not a stratified subset -
`cases: 2740` in that file is the corpus's own total.

### The two Semgrep gate configurations, per methodology rule R5

`bench/README.md`'s rule 3 and the scout report's §5.1 R5 require every tool
run at **(a) its documented default** and **(b) its maximum free ruleset**,
both published, so a reader is never left to infer which one produced a
number. `--config auto` was tried first as the literal reading of "documented
default" and rejected, measured: it refuses to run under `--metrics=off`
("Cannot create auto config when metrics are off"), and metrics-off is this
harness's own non-negotiable rule - a benchmark must not phone home about the
corpus it is measuring. `p/default` is Semgrep's documented, metrics-independent
starter ruleset and is what `bench/tools/semgrep-default.sh` runs instead; the
existing `bench/tools/semgrep.sh` is unchanged and remains the maximum-ruleset
column. Each run's own `MANIFEST` carries its exact `gate:` line - never left
to be inferred from the tool id.

scoursh has one gate here, not two, and that is a decision already made and
stated in the scout report's §6.1: scoursh's rule set is fixed (it ships no
alternate "maximum" pack), and `--use-engines` would make scoursh *wrap* the
very Semgrep/Gitleaks/Trivy adapters it is being benchmarked against - a
scoursh-with-engines column is Semgrep versus Semgrep plus scoursh's own
startup cost, an integration measurement wearing a detection table's clothes.
It is excluded from this leg entirely, not run at any severity.

## Files

| Path | What |
|---|---|
| `SAMPLE-MANIFEST` | how the corpus set was built (see above - it is the full 2,740) |
| `<tool>/raw/` | the tool's own output, byte for byte |
| `<tool>/normalised.jsonl` | the harness's record shape |
| `<tool>/MANIFEST` | version, corpus commit, exact gate, claimed scope, wall clock |
| `scorecard-all-findings.md` / `.json` | every finding counted (`--min-severity any`) |
| `scorecard-high-and-critical.md` | the `--min-severity high` column |

Raw outputs carry one mechanical change (`--portable-paths`): the absolute
scan-root prefix is rewritten to `<SCAN_ROOT>` and the `bench/` prefix to
`<BENCH>`, recorded in each MANIFEST. Nothing else was edited.

## How to reproduce

```sh
bench/fetch-corpus.sh owasp-benchmark
bench/make-sample.sh owasp-benchmark sast-full --per-class 999 \
  --categories 'sqli cmdi ldapi pathtraver crypto hash weakrand xss trustbound securecookie xpathi'
bench/run-tool.sh --tool scoursh         --sample sast-full --out <dir> --portable-paths
bench/run-tool.sh --tool semgrep-default --sample sast-full --out <dir> --portable-paths
bench/run-tool.sh --tool semgrep         --sample sast-full --out <dir> --portable-paths
bench/score.sh --truth bench/corpora/_samples/sast-full/truth --results <dir> --format md
bench/score.sh --truth bench/corpora/_samples/sast-full/truth --results <dir> --format md --min-severity high
```

Only the first line needs the network. `scoursh`'s run over 2,740 files took
~400s wall clock (the ~38s fixed startup the scout report's §3.3 measured,
plus ~0.13s/file here - a lower marginal rate than the 0.2-0.4s/file measured
against a smaller sample, consistent with the fixed cost being the dominant
term at small n); each Semgrep gate took ~15s.

## The headline numbers, read scope-first (§7.2 framing)

**Scope first, because a number the reader already predicted cannot embarrass
anyone.** scoursh ships 8 relevant checks across the categories this corpus
covers (`docs/DESIGN.md` §15: the native tier is declared **pattern/linter-grade**,
not taint-tracking); Semgrep CE ships thousands of rules including real
intra-procedural taint analysis. The result below is exactly the gap that
scope difference predicts - not a surprise, a confirmation of a limitation the
project already documents.

**Corpus aggregate, loose CWE matching, all findings (8 of 11 categories
scored for every tool - `securecookie`, `trustbound`, `xpathi` are no-coverage
for all three, since none of the three tools here claims them):**

| tool | recall | FPR | precision | **Youden J** |
|---|---|---|---|---|
| scoursh | 4.3% | 4.8% | 0.482 | **-0.005** |
| semgrep (max ruleset) | 88.3% | 39.1% | 0.702 | **+0.492** |
| semgrep-default (p/default) | 90.2% | 42.3% | 0.689 | **+0.479** |

`J = 0.000` is a coin flip. **scoursh scores at essentially a coin flip on
this corpus at full corpus size**, matching the scout report's 192-case pilot
(`J = -0.031` there) in direction and magnitude - this is not new information,
it is the same finding confirmed at 14x the sample size with the full,
unbalanced, real corpus composition rather than a hand-balanced stratified
draw. Both Semgrep configurations land solidly above the coin flip, with the
maximum ruleset and the documented default within a few points of each other
- the two gate configurations do **not** materially change Semgrep's ranking
relative to scoursh here, which is itself worth stating: R5 exists so a
benchmark cannot be accused of picking whichever Semgrep configuration
flatters a conclusion, and here it would not have mattered which one was
picked.

**At `--min-severity high` (high+critical only), the picture changes
substantially for BOTH sides, and that shift is itself a finding, not a
footnote:**

| tool | recall | FPR | precision | **Youden J** |
|---|---|---|---|---|
| scoursh | 2.1% | 4.8% | 0.314 | **-0.027** |
| semgrep (max ruleset) | 18.1% | 16.4% | 0.535 | **+0.017** |
| semgrep-default (p/default) | 18.5% | 17.5% | 0.524 | **+0.010** |

Semgrep's advantage shrinks from ~50 points of J to essentially the same
coin-flip range scoursh occupies at every severity - because most of Semgrep's
findings in this corpus (`crypto`, `hash`, `sqli`, `weakrand`, `xss`) are its
own `WARNING`/medium tier, which this harness's common severity scale does not
promote to `high`. Only `cmdi` and `pathtraver` keep most of their true
positives at `high`+ for Semgrep. **Neither ranking flips - scoursh stays at
or below a coin flip in both columns - but the MARGIN is not a fixed property
of the tools; it is a property of which severity filter a reader applies**,
which is exactly why `bench/README.md`'s rule 3 requires publishing both
columns rather than one.

## Per-category diagnosis worth carrying forward

- **`ldapi` reproduces the scout report's diagnostic case exactly, at 5x the
  sample size.** scoursh: 27 TP, 0 FN, 32 FP, 0 TN - **100% recall and 100%
  false-positive rate**. It detects the presence of an LDAP filter
  construction, not the presence of the vulnerability, so it flags every case
  in the category regardless of whether it is the real or the sanitized
  variant. Read alone, "100% recall" is a perfect-looking number; Youden J (0)
  shows it has zero discriminating power. This is precisely the failure mode
  `bench/README.md`'s rule "recall alone is not a result" exists to catch, and
  it is the same rule with the same category on 4.6x more cases than the
  192-case pilot found it on.
- **`hash` is scoursh's one category with real, non-trivial signal**: 28 TP, 0
  FP at any severity (21.7% recall, 0% FPR, 1.000 precision) - every finding it
  reported there was correct, it simply misses more than it catches. This
  reproduces the pilot's finding that scoursh's `crypto`/`hash` checks are
  closer to competitive than its taint-shaped checks (`sqli`, `cmdi`,
  `pathtraver`, `xss`, all 0% recall here at full corpus size).
- **`crypto` is scoursh's worst category by Youden J** (-0.233): 0 TP, 27 FP.
  It reports findings but never on a genuinely vulnerable case in this sample
  - a pattern match firing on shape rather than on the actual defect.

## What is NOT measured here, and why - never a fabricated number

- **Bandit (Python) and gosec (Go) are not run.** Neither is installed in this
  environment (`command -v bandit` / `command -v gosec` both fail), and - this
  is the more important half - **neither would be applicable even if
  installed**: OWASP Benchmark is a Java-only corpus, and Bandit/gosec have no
  Python or Go source to analyse in it. The scout report's own §6.2 comparison
  roster lists both as fair baselines *scoped to their own language*, which
  this corpus does not offer. This is a scope mismatch, not an availability
  gap, and it is recorded as such rather than as a silent omission.
- **A NIST Juliet Java slice was investigated and found NOT obtainable within
  this harness's current design, structurally rather than by licence or
  network.** The most current, cleanly-licensed (CC0-1.0, public domain)
  mirror found (`UnitTestBot/juliet-java-test-suite`) was inspected directly
  (`CWE89_SQL_Injection__Environment_executeBatch_01.java`, confirmed by
  fetching the real file): like every Juliet port, it bundles a `bad()` method
  and one or more `good()`/`goodB2G()`/`goodG2B()` methods **in the same
  source file** per test case. `bench/lib/truth.sh`'s ground-truth format and
  `bench/lib/score.sh`'s `score_category` are FILE-level ("a case is flagged
  when the tool reports anything in that case's file", one `real: true|false`
  label per file) - a design carried over unchanged from OWASP Benchmark's
  one-vulnerability-per-file shape, and stated as such in both files' own
  headers. Every Juliet file in this port would have to be labelled `real:
  true` (it genuinely contains a real vulnerability, in `bad()`), which means
  no file could ever serve as a sanitized-trap negative control, which means
  false-positive rate - and therefore Youden J, this harness's whole headline
  metric - could not be computed at all; scoring only recall would be exactly
  the "recall alone is not a result" mistake `bench/README.md` exists to
  forbid. Scoring it honestly needs function- or line-range-level ground
  truth, which is a scorer capability this leg's scope does not include
  building (it would be a B3-sized change to the frozen scorer contract, not a
  B4-sized plug-in). Recorded here as a genuine "not obtainable as designed"
  cell, not a fabricated or approximated one.
- **`terraform-aws` / IaC is out of scope for this leg entirely** (it is the
  B6 methodology's IaC leg territory, not B4's SAST leg), even though scoursh's
  own adapter claims it structurally; it is simply never scored here because
  no IaC corpus was run.

## Reading it honestly

- **Both matching modes (strict and loose CWE) agree, for every tool, in every
  claimed category** - the strict and loose tables above are numerically
  identical for all three tools. This is the same agreement the 192-case pilot
  found, now confirmed at full corpus size: the ranking is not an artifact of
  the CWE-equivalence-class scoring method.
- **The no-coverage cells are not a defect in either tool.** `securecookie`,
  `trustbound` and `xpathi` are genuinely categories none of the three tools
  here claims to compete in (`scoursh_scope`/`semgrep_scope` both list the
  same eight categories) - they render as `*no coverage*`, never as a zero,
  per `bench/README.md`'s rule.
- **This is one machine, one run per tool/gate, not a statistical estimate
  with confidence intervals.** It is, however, the full corpus rather than a
  sample of it, so - unlike the smoke result - there is no sampling variance
  to worry about in the counts themselves; the 2,740-case denominator is the
  entire published ground truth this corpus offers for these categories.
- **This confirms, rather than discovers, the scout report's prediction**
  (§7.1: "SAST (taint-shaped defects): scoursh loses heavily; Youden J near or
  below zero" - *measured*). Nothing here is a new finding about scoursh's
  capability; it is the B4 leg's job to turn that prediction into a real,
  reproducible, full-corpus, dual-gate-config number, which this is.
