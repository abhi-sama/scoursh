# B8 — honesty + egress metrics

This leg gives scoursh's *structural* wins their own
scored table, separate from the per-category detection tables (B4-B6) where
the specialists win: the coverage-honesty metric below, plus the zero-egress proof.

**Published in `docs/COMPARISON.md`'s comparison table** — the "Coverage honesty",
"Zero-egress, kernel-enforced" and "Installed footprint" rows there each cite this
leg's own sections.

**B7 (DAST) had not landed when this leg was measured** (it has since landed - see
`bench/README.md`'s "B7: the DAST leg"). Nothing below computes a metric
that needed a DAST number; the footprint table's competitor roster is
SAST/IaC/SCA/secrets tools only, for the same reason. There is no
DAST-inclusive column — that was a **stated
not-measured gap** at the time, not folded into any total.

## 1. Coverage-honesty metric (§5.3)

> *"Of the checks this tool ships, what fraction can the reader confirm
> actually executed on this corpus?"*

`coverage-honesty/coverage-honesty.py` (also `bench/tools/coverage-honesty.py`
— committed in both places, byte-identical, so the harness has it as a
first-class tool and this leg has a frozen copy of the exact version that
produced its own numbers) walks every scoursh `run.json` already committed
under `bench/results/**` — B4 (SAST), B6 (IaC ×2, secrets), and every
SCA case in the B5 leg — and computes, per run:

| Field | Meaning |
|---|---|
| `checks_selected` | what `scan.sh` loaded for this module/profile — the ceiling |
| `checks_run` | what actually executed and could have produced a finding |
| `gap` | `checks_selected - checks_run` |
| `gap_declared` | of the gap, how many are named in a `coverage_reduction`/`skipped_checks` record with a stated reason |
| `accounted_pct` | `gap_declared / gap` — must be 100%, or it is a scoursh regression |

Full output: `coverage-honesty/scorecard.txt` (human) and
`coverage-honesty/scorecard.json` (machine). The headline:

```
TOTAL: 31 scoursh run(s) inspected, 93 total unrun-but-selected checks,
93 declared with a reason (100.0% accounted)
```

**31 of 31 runs, 100.0% accounted, zero undeclared gaps.** Every check a
run loaded but did not execute is named, in that run's own `run.json`, with a
machine-readable reason — `no_matching_files` (a language-scoped check on a
corpus with no files of that language), `single_worker`, `no_check_registry_on_disk_yet`,
and so on. The script exits non-zero and prints the offending path if it ever
finds an undeclared gap, so this is a real check, not a hand-picked number —
run it yourself: `python3 bench/tools/coverage-honesty.py bench/results`.

**Worked example (B4, the SAST leg over pure-Java OWASP Benchmark):**
`checks_selected` is 53 (scoursh's full SAST registry across six languages),
`checks_run` is 34. The 19-check gap is exactly scoursh's Go, JavaScript and
Python checks — structurally unable to fire on an all-Java corpus — and the
run's own `meta/coverage_reduction` record names all 19 by id, with
`reason=no_matching_files`. A reader does not have to trust a claim that
those checks "would have run on other input"; the run says so about itself,
before any finding is scored.

**SCA is a structural non-participant in this metric, and that absence is
itself declared.** Every `scoursh-sca` run in the B5 leg reports
`checks_selected: []` — SCA has no `*.rules` check registry at all (it is a
table lookup against `data/advisories.db`, not a pattern-rule engine,
AGENTS.md's own "sca is DIFFERENT" paragraph) — and the run records that fact
as `coverage_reduction reason=no_check_registry_on_disk_yet` rather than
either omitting the field or reporting a misleading `0/0 = 100%` as if the
mechanism applied. The script counts these runs (`gap` is correctly `0`,
because there is genuinely nothing to be silent about), but the honest
reading is "not applicable, and the run says why" — not "perfect score".

**No competitor in this benchmark set exposes the mirror-image number.**
Semgrep, Trivy, Grype, OSV-Scanner, Checkov, KICS, Gitleaks and TruffleHog's
raw output (already committed under `bench/results/b4-*`, `b6-*`,
`sca-lockfiles-26`) lists only findings and, at most, a rule/policy count —
none emit a machine-readable "loaded N checks, executed M, here is why the
other N-M did not run" record. This is a **structural** absence, so it is
reported as a labelled non-comparison here, per the harness's own §5.1 R4 and
R7 — never modelled as those tools scoring 0%, which would be exactly the
false accounting §5.3 exists to catch in the other direction.

## 2. Egress proof (§7.1's "Zero-egress: structural" prediction)

Three proof shapes, strongest first. All three ran on this host on
2026-09-10; raw logs and `run.json` for each are committed under
`egress-proof/`.

### 2a. Kernel-enforced: Tier A (`tools/run-sandboxed.sh`, no `--scope-conf`)

`tools/run-sandboxed.sh -- <command>` wraps `<command>` in a macOS Seatbelt
profile, `(version 1)(allow default)(deny network*)` — every network syscall
in the whole process tree is refused by the kernel at `connect()`, before a
packet is sent. This is not sampling; it is the strongest proof shape
available on this host (`tools/run-in-netns.sh`, the Linux netns equivalent,
needs root and was not run here).

```
$ tools/run-sandboxed.sh -- ./scan.sh sast --path lib     --profile-scan full --min-confidence low --format json --out <dir>
$ tools/run-sandboxed.sh -- ./scan.sh sca  --path tests/fixtures/sca/mixed-four-ecosystems           --format json --out <dir>
$ tools/run-sandboxed.sh -- ./scan.sh iac  --path tests/fixtures/iac/docker-compose                  --format json --out <dir>
```

| Module | Target | Exit | Artifacts |
|---|---|---|---|
| `sast` | `lib/` (16 files) | **0** | `egress-proof/tier-a-sandboxed/sast/` |
| `sca` | `tests/fixtures/sca/mixed-four-ecosystems` | **0** | `egress-proof/tier-a-sandboxed/sca/` |
| `iac` | `tests/fixtures/iac/docker-compose` | **0** | `egress-proof/tier-a-sandboxed/iac/` |

All three completed and wrote a full report with **zero network access
possible at the kernel level for the whole run** — this is what makes
AGENTS.md's "sast, sca, and iac genuinely make zero network calls" claim
provable rather than merely asserted. `tests/fixtures/` inputs were used only
because they are small and already in the tree; this is not a detection
measurement (R1 from `bench/README.md` does not apply — nothing here is
scored for recall), only a real-scan-shaped input to exercise the egress
path honestly.

### 2b. Detector: `--paranoid` alone (unsandboxed)

```
$ ./scan.sh sast --path lib --paranoid --profile-scan full --min-confidence low --format json --out <dir>
```

Exit 0. `egress-proof/paranoid-detector/stderr.txt`:

```
paranoid: connection observer attached (backend=lsof, family root pid=12016) - detector, not guarantee
...
paranoid: connection observer detached cleanly - zero out-of-allowlist connections observed this run
  (sampling-based; see docs/FOUNDATION.md tension 20 for what this does and does not prove)
```

Clean run, no errors, confirming the sampling-based detector's own stated
limitation (docs/USAGE.md: "a detector, not a guarantee") while agreeing with
the kernel-enforced result above.

### 2c. A real interaction found by running both layers together

Stacking Tier A and `--paranoid` in one invocation
(`egress-proof/tier-a-plus-paranoid-interaction/`) still exits 0 and still
reports "zero out-of-allowlist connections observed", but its stderr carries
141 repeated lines of:

```
error scoursh: command failed (status 126) at lib/paranoid.sh:385: ps -Ao pid=,ppid=
```

`--paranoid`'s process-family enumeration (`ps`, used to walk the descendant
tree it samples) fails under the Seatbelt profile on this host — the observer
still lands on its `lsof` backend and still reports correctly, but the
process-family half of its own sampling is measurably degraded inside Tier A.
This is reported here as an **observed environmental interaction**, not
silently smoothed over and not fixed in this leg (out of B8's scope — this
leg measures and reports, per the brief, rather than patching
`lib/paranoid.sh`). It does not weaken §2a's result, which needs no
`--paranoid` cooperation at all: the kernel-level guarantee holds regardless
of what the userspace detector running alongside it can observe.

### 2d. Competitors that fetch

Not re-measured here (already established by the B5 leg's own README, §3,
reused rather than restated): OSV-Scanner makes one live query to
`api.osv.dev` on **every** invocation with no offline flag; Trivy and Grype
each pull a multi-hundred-MB vulnerability database over the network on
refresh (cached, so not every run). None of the four SCA competitors, and no
tool in any other category here, can be wrapped in Tier A and still complete
— that would defeat their whole design. scoursh's `sast`/`iac`/`sca` legs
running clean under total kernel-level network denial (§2a) is therefore not
just "faster than the alternative" but a capability none of the compared
tools has at all.

## 3. Footprint table (§7.2 point 4)

Full raw numbers and commands: `footprint/measurements.md`. Summary:

| Metric | scoursh | Competitors (same category) |
|---|---|---|
| Installed footprint | **~5.2 MB** (`lib/ modules/ rules/ config/ scan.sh`), zero installed runtime dependency beyond bash+coreutils+grep/rg | 15 MB (gitleaks) – 241 MB (semgrep); each is a separately installed, versioned binary/venv |
| Peak process memory (top-level process, `/usr/bin/time -l`) | 13.2 MB (`sast` on 16 files) | 119.9 MB (trivy `config`), 128.2 MB (semgrep `p/default`) — see the caveat in `footprint/measurements.md` about what this number does and does not include |
| SCA DB-size before first finding | 86 MB for 3 ecosystems (already measured, `bench/results/sca-lockfiles-26/README.md` §3) | 1.3 GB (Trivy), 2.0 GB (Grype), 0 (OSV-Scanner — trades footprint for egress on every run) |
| Egress after setup completes | **zero, kernel-provable** (§2 above) | Trivy/Grype: DB refresh egress. OSV-Scanner: egress every run. Semgrep/Checkov/KICS/Gitleaks/TruffleHog: none observed in this benchmark's default-gate runs, but none of them can be wrapped in a deny-all-network sandbox and still complete their normal workflow (registry/update checks, `--verified` mode, etc.) the way scoursh's three offline modules can |

This table is not a ranked "scoursh wins" score — the same "no single overall
score" rule applies here as much as to the detection tables — it is four
independent measurements, each with its own unit, presented together because
they are structural properties that deserve
their own table rather than a prose footnote.

## 4. Reproducing this leg

```sh
# coverage-honesty (no network, reads only already-committed bench/results/)
python3 bench/tools/coverage-honesty.py bench/results

# egress proof (macOS only — Tier A wraps sandbox-exec; needs bench/results/*
# untouched and tests/fixtures/ present, both already in the tree)
tools/run-sandboxed.sh -- ./scan.sh sast --path lib --profile-scan full --min-confidence low --format json --out <dir>
./scan.sh sast --path lib --paranoid --profile-scan full --min-confidence low --format json --out <dir>

# footprint (versions/sizes will drift with Homebrew upgrades — re-measure,
# don't assume the numbers above hold on a different host or date)
du -sh lib modules rules config scan.sh
/usr/bin/time -l ./scan.sh sast --path lib --profile-scan full --min-confidence low --format json --out <dir>
```
