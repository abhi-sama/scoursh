# Footprint measurements, raw

One macOS host (Darwin, arm64, Homebrew-installed competitor tools), 2026-09-10.
Commands and full command lines below so this is a re-run, not a quote.

## Installed footprint (`du -sh` on the installed tree)

```
$ for cellar in semgrep/1.176.0 trivy/0.74.0 grype/0.118.0 osv-scanner/2.5.1 \
                checkov/3.3.10 kics/2.1.21 gitleaks/8.30.1 trufflehog/3.97.4; do
    du -sh "/opt/homebrew/Cellar/$cellar"
  done
```

| Tool | Version | Installed size |
|---|---|---|
| semgrep | 1.176.0 | 241M |
| checkov | 3.3.10 | 211M |
| trivy | 0.74.0 | 194M |
| kics | 2.1.21 | 172M |
| trufflehog | 3.97.4 | 112M |
| grype | 0.118.0 | 79M |
| osv-scanner | 2.5.1 | 52M |
| gitleaks | 8.30.1 | 15M |

```
$ du -sh lib modules rules config scan.sh   # scoursh's own tree, sast+iac+secrets only
920K  lib
4.0M  modules
124K  rules
44K   config
140K  scan.sh
```

scoursh's own code (`lib/ modules/ rules/ config/ scan.sh`, everything `sast`,
`iac` and secrets-via-SAST need) is **~5.2 MB total**, with **zero installed
runtime dependency** beyond what a development host already has: bash ≥4.2,
GNU coreutils or BSD equivalents, and `rg` or `grep -E` (AGENTS.md's frozen
portable-ERE dialect runs identically under either). There is no package
manager install step, no separate runtime, and no versioned interpreter to
match — the "one auditable bash tool" pitch, measured rather than asserted.

`data/advisories.db` + `data/versions.db` (SCA's own required input, built
by the separate, quarantined `tools/vendor-engines.sh advisories` step, never
at scan time) add ~172 MB for three ecosystems on this snapshot — see
`bench/results/sca-lockfiles-26/README.md` §3 for the full DB-size/egress
table, which already covers this column for SCA specifically and is not
reproduced here.

## Peak process memory footprint (`/usr/bin/time -l`, macOS)

`/usr/bin/time -l` reports the **wrapped process's own** peak resident set
(`getrusage`), not summed across every child it spawns. That is stated here
because it materially favours scoursh's number and a reader should be able to
weigh it: scoursh's top-level `scan.sh` is a thin bash orchestrator that
shells out to many short-lived `rg`/coreutils invocations rather than doing
matching in one long-lived process, so its own peak footprint undercounts the
cumulative work in a way semgrep's and trivy's single-process architectures
do not. The number below is real and reproducible, but it measures
"orchestrator memory", not "total memory moved during the scan" — read it as
a *structural* difference (many small processes vs. one big one), not only a
size difference.

```
$ /usr/bin/time -l ./scan.sh sast --path lib --profile-scan full --min-confidence low --format json --out <dir>
$ /usr/bin/time -l semgrep --config p/default --metrics=off --json --quiet lib
$ /usr/bin/time -l trivy config --format json --quiet tests/fixtures/iac/docker-compose
```

| Tool | Target | Peak memory footprint (top process) |
|---|---|---|
| scoursh (`sast`) | `lib/` (16 files) | **13.2 MB** |
| trivy `config` | `tests/fixtures/iac/docker-compose` (1 file) | 119.9 MB |
| semgrep (`p/default`) | `lib/` (16 files, bash — semgrep has no bash rules, 0 findings either way) | 128.2 MB |

Not a matched corpus across rows (different target, different language
support) — this is a footprint measurement, not a detection comparison, and
the targets were chosen only to be "a real scan the tool would actually run",
per §7.3's "no runtime comparison on too-small a corpus" rule, which binds
wall-clock claims and is honoured here in spirit for memory too: this is not
published as a ranked table for that reason, see `README.md`'s framing.
