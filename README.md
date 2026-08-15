# scoursh

**Scan exhaustively. Trust nothing over the network.**

`scoursh` is an egress-restricted, shell-based security scanner - meaning it has no back-channel to
anyone. It never phones home, never checks for updates, never fetches its own rules or advisories
from a server, and never sends telemetry to its maintainers or anyone else. One tool, one entry
point, one report - covering source code (SAST), dependencies (SCA), and infrastructure-as-code
(IaC) today, all three with **zero network calls of any kind**. A running-endpoint scanner (DAST)
and live cloud posture checking (CSPM) are already designed and next in line; by nature, those two
have to talk to *something* - but only ever to a target *you* explicitly pre-authorized, never
anywhere scoursh decided on its own. See [Why egress-restricted, not air-gapped](#why-egress-restricted-not-air-gapped)
for exactly where the line is drawn and why.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Table of contents

- [Why "scoursh"](#why-scoursh)
- [Features](#features)
- [Types of security scans, and where scoursh stands today](#types-of-security-scans-and-where-scoursh-stands-today)
- [scoursh vs. semgrep](#scoursh-vs-semgrep)
- [Why egress-restricted, not air-gapped](#why-egress-restricted-not-air-gapped)
- [Installation](#installation)
- [Try it yourself: sample vulnerable repos](#try-it-yourself-sample-vulnerable-repos)
- [Optional third-party engines](#optional-third-party-engines)
- [Build status](#build-status)
- [Known gaps](#known-gaps)
- [What's next](#whats-next)
- [Documentation](#documentation)
- [License](#license)

## Why "scoursh"

The name is a blend of **scour** - to search something thoroughly, corner to corner, and clean out
what you find - and **sh**, the Unix shell the entire tool is written in: no runtime, no
interpreter, no dependency beyond `bash` and standard coreutils. The tagline says the rest: *scan
exhaustively.*

## Features

- **Four scan surfaces in one tool** - source code, dependencies, infrastructure-as-code, and
  secrets, sharing one CLI, one exit-code contract, and one report.
- **Egress-restricted, enforced by destination, precisely defined** - scoursh itself has no
  back-channel to anyone: no update check, no telemetry, no rule registry to fetch from. SAST, SCA,
  and IaC make zero network calls, full stop. The only traffic that ever leaves the host at all is to
  a target *you* explicitly pre-authorized (a DAST target in `config/scope.conf`, or your own AWS
  account) - never to scoursh's maintainers, never to a third party, and never automatically. Every
  network call in the codebase, present or future, routes through one of two chokepoints, a dedicated
  lint fails the build if anything bypasses them, and a separate lint proves no AI/LLM provider is
  reachable from the shipped tool at all.
- **Deterministic output** - the same scan produces byte-identical findings whether it runs on
  Linux with GNU coreutils or macOS with a BSD userland, checked automatically in CI.
  Fingerprints survive reindentation and unrelated edits, so a diff or baseline never reports a
  false "fixed" or a false "new."
- **A detector for egress, on Linux *and* macOS** - `--paranoid` watches the process's own outbound
  connections and aborts on the first one outside scope, sampling through `ss` or `strace` on Linux
  and through `lsof` on macOS.
  It refuses the run outright rather than proceeding unobserved on a host that supports none of them.
  **On Linux there is also a guarantee** - `tools/run-in-netns.sh` builds a network namespace where an
  out-of-scope connection is not just detected but physically impossible.
  That one is Linux-only and has no macOS equivalent, so a macOS run has the detector and nothing
  behind it.
- **Honest about its own gaps** - every module a run skips, every coverage limitation, every
  unproven claim is recorded directly in the run's own output as a `coverage_reduction` or
  `coverage_gap` fact, not silently dropped from the report.
- **Optional extra firepower, still offline** - can shell out to vendored copies of semgrep,
  gitleaks, and trivy for broader coverage, with results deduplicated against scoursh's own
  findings, all still under the same zero-network-at-scan-time rule.
- **A real CI gate, not just a report** - a fixed 0-5 exit-code contract, severity thresholds,
  confidence filtering, and a `--fail-on-new` mode designed to gate a pull request rather than just
  produce a PDF nobody reads.
  Which parts of that are wired today, and which are accepted but inert, is in
  [Known gaps](#known-gaps).

## Types of security scans, and where scoursh stands today

Security scanning is usually split into a handful of categories, tied to *when* in a project's
lifecycle they run:

| Scanner type | What it scans | Stage in lifecycle | scoursh |
|---|---|---|---|
| **SAST** | Source code | Development / build | ✅ Available - `scan.sh sast` |
| **SCA** | Open source dependencies | Build / CI-CD pipeline | ✅ Available - `scan.sh sca`, once you have built an advisory database ([Installation](#installation)); see also [Known gaps](#known-gaps) |
| **IaC** | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | CI-CD pipeline | ✅ Available - `scan.sh iac` |
| **Secret detection** | Git repositories / files | Commit / pre-commit | ✅ Available - built into `sast` (`--history` replays across git history) |
| **DAST** | A running application | Staging / production | 🚧 Designed, not built - the CLI grammar and scope gate exist; no scan engine yet |
| **CSPM** | Live cloud infrastructure | Production / runtime | 🚧 Designed, not built - the read-only AWS wrapper exists ahead of schedule; `scan.sh cloud` does nothing yet, with or without `--live` |
| **Container image scanning** | Built Docker images (layers, installed packages) | Build / registry | ⛔ Not planned - `scoursh` lints Dockerfile/compose *source* as IaC, not built image layers |
| **Network / host scanning** | Servers, ports, OS patches | Operations / maintenance | ⛔ Not planned |

So today, `scoursh` covers everything on the *static* side of that list - before anything ever
runs, and before any code ships - in a single pass over a local checkout.
The dependency half of that coverage stays inert until you build `data/advisories.db` yourself
([Installation](#installation)).
See [What's next](#whats-next) for the rest.

### What's available today, in detail

- **SAST** (`modules/sast/`) - pattern-based scanning for Go, Java, JavaScript, and Python, covering
  injection, crypto misuse, and language-specific issues, plus a dedicated secrets pack.
  `--history` replays the secrets pack across git history, so a credential removed from the working
  tree but still reachable through git log still gets caught.
- **SCA** (`modules/sca/`) - parses lockfiles/manifests for six ecosystems (npm/yarn/pnpm,
  pip/poetry/Pipfile, Go modules, Maven, RubyGems, Composer) and matches every pinned dependency
  against a locally-generated advisory database sourced from [OSV.dev](https://osv.dev) - no
  network lookup at scan time.
  That advisory database is never bundled or auto-fetched, and until you build it once, every
  ecosystem walk skips the scan entirely ([Installation](#installation)).
  Its `--fail-on` severity gate is wired, the same one `sast` and `iac` use: a run carrying a finding
  at or above the threshold exits 1 and records `"gate": "fail"` in `run.json`.
  That gate went unevaluated in earlier revisions, so `scan.sh sca --fail-on critical` exited 0 on
  critical findings; it is fixed, and covered by a regression test.
- **IaC** (`modules/iac/`) - six rule packs: Terraform, Kubernetes manifests, Helm chart sources,
  CloudFormation templates, Dockerfile, and docker-compose.

The exact, generated breakdown of every rule pack and ecosystem - how many checks each carries and
what's still outstanding - is in [Build status](#build-status) below; it's regenerated from the
repository tree on every change, so it can't go stale the way hand-written status prose does.

## scoursh vs. semgrep

Both are pattern-based scanners, and they're not really competitors - `scoursh` can optionally
*vendor semgrep itself* as an add-on engine (see [Optional third-party
engines](#optional-third-party-engines)). But if you're deciding which to reach for, here's the
honest comparison:

| | scoursh | semgrep |
|---|---|---|
| Network posture | Zero network calls at scan time, enforced by CI-checked lints and (on Linux) a kernel-level network-namespace guarantee | Rule registry fetches and telemetry contact home by default unless explicitly disabled |
| Scope | SAST + SCA + IaC + secrets, one tool, one report, one exit-code contract | Primarily SAST; dependency/supply-chain scanning is a separate paid product |
| Matching engine | Regex/pattern-based; can optionally vendor semgrep itself for AST-aware matching | Full AST-aware, semantic pattern matching - more precise, broader language support |
| Rule ecosystem | Small, hand-authored, project-owned rule set | Large community and commercial rule registry |
| Determinism | Tested byte-identical across GNU and BSD userlands in CI | Not a stated design goal |
| Maturity | Early-stage, single project, 4 languages | Mature, widely adopted, dozens of languages, IDE integrations |

**Reach for scoursh** when the environment itself is the constraint - an air-gapped network, a
regulated pipeline where "the scanner phones home" is disqualifying on its own, or you want one CLI
covering SAST, SCA, and IaC instead of stitching several tools together.

**Reach for semgrep** when you need its semantic matching, its much larger rule registry, or broad
language coverage scoursh doesn't have yet.

**Or use both** - point `scoursh --use-engines` at a vendored copy of semgrep and get its matching
engine's coverage inside scoursh's own unified report, still with zero network calls once vendored.

## Why egress-restricted, not air-gapped

**What this does and doesn't mean.** scoursh is **egress-restricted, enforced by destination** -
not air-gapped, and that distinction is deliberate rather than pedantic: "air-gapped" would mean the
tool never touches a network at all, and that's not true of it as a whole, nor was it ever meant to
be. `dast` and `cloud --live` inherently have to talk to *something*, since testing a running
application or reading your live AWS configuration is the entire point of those two scans. What
scoursh actually guarantees is narrower, and it's the part that actually matters: **scoursh itself
has no back-channel, and it never decides on its own who to contact.** Exactly two kinds of outbound
traffic are ever permitted, and both require *you* to have named the exact target first: `curl` to a
host you explicitly authorized in `config/scope.conf`, and read-only AWS API calls to your own
account. Everything else - phoning home, a SaaS backend, fetching rules or advisories at scan time,
telemetry to scoursh's own maintainers or anyone else - is forbidden by design, with no
configuration flag that turns it back on. That's why SAST, SCA, and IaC - the three modules
actually built today - make genuinely zero network calls: nothing about reading source code,
dependency manifests, or config files needs an external target to begin with, so for those three,
"no network calls when authorized" and "no network calls at all" are the same thing in practice -
and it's the reason those three modules really can run unmodified on a genuinely air-gapped host,
even though the tool as a whole is not one. See `docs/FOUNDATION.md` tension 28 for the full
correction and `docs/adr/0001-egress-model-correction.md` for the dated decision record.

That single constraint shapes most of the architecture:

- Rules, payloads, wordlists, and advisory data are **vendored in the repo** and read from disk.
- `tools/vendor-engines.sh` is the only script that ever touches the network, is never called
  during a scan, and is quarantined and tested as such.
- Every HTTP call goes through one wrapper (`lib/http.sh`) that refuses any host absent from the
  resolved scope allowlist; every AWS call goes through one wrapper (`lib/awscli.sh`) that refuses
  any operation that is not read-only.
  The AWS half is real and tested, but it currently guards an empty set: no AWS call ships in the tool
  yet, and the project's own read-only lint reports zero call sites for it.
  The wrapper and its lint landed ahead of the cloud checks deliberately, so that no cloud check is
  ever written against a bare `aws` in the first place.
- The HTML report is self-contained, with no external assets and a strict inline CSP.
- `--paranoid` samples the process's own outbound connections during a run and aborts the moment
  it observes one outside the resolved allowlist.
  It has three sampling backends, tried in order: `ss`, then `strace -f -e trace=connect`, then
  `lsof`.
  The first two are Linux-only; `lsof` is what macOS ships, so `--paranoid` works there too.
  On a host where none of the three is usable, it refuses the entire scan with exit 4 before any
  module runs, rather than quietly downgrading to an unobserved one.
  It is a **detector, not a guarantee** on every platform: it samples, so a connection that opens and
  closes between two polls is never seen, and `lsof` has exactly the same blind spot `ss` does.
  `tools/run-in-netns.sh` is the guarantee - a network namespace whose route table admits only the
  declared scope, so an out-of-scope connection is categorically impossible rather than merely
  observed - and it is **Linux-only with no macOS equivalent**.
  On macOS the detector is the only egress control available; there is no stronger tier behind it.
- `tests/lint-no-ai.sh` scans the entire shipped tool for any AI/LLM provider hostname, SDK name, or
  API-key-shaped environment variable, and fails the build if it finds one.

## Installation

`scoursh` is pure POSIX-leaning bash - there is no build step and no runtime dependency beyond a
standard Unix toolchain (`bash`, `grep`/`rg`, `awk`, coreutils).

```sh
git clone https://github.com/abhi-sama/scoursh.git
cd scoursh
./scan.sh --help
```

`tests/run-tests.sh` is the real test entry point; `pnpm test` / `npm test` are thin aliases for it
(`package.json` exists only for that convention - scoursh has no JavaScript and no Node runtime
dependency).

**One-time setup for SCA, required before your first scan.**
`data/advisories.db` is not shipped with this repository - the advisory data is deliberately never
bundled or auto-fetched, and you build it yourself.
SCA's parsing and matching code is fully built and tested, but every ecosystem walk tests for that
file first and returns before it discovers or parses a single manifest.
So until you build it, `scan.sh sca` does not scan at all - and it says so rather than reporting a
clean project.
It **exits 4** (`missing required input`, [`docs/USAGE.md`](docs/USAGE.md)'s exit-code contract), writes
its report, records one `module=sca reason=no_advisories_db_on_disk ecosystems=<all six>` coverage
reduction in `run.json`, and puts a `SCA-COV-NO_ADVISORY_DB-01` finding on the report stating that zero
dependencies were checked.
Nothing about that run can be read as a clean dependency scan, by you or by CI - which is the point,
because absence of findings here is absence of evidence, never evidence of absence.
(`scan.sh all` behaves the same way except for the exit code: it skips `sca` with that same recorded
reason and finding, and leaves the exit code to the modules that did run.)

You build it on a networked box with `tools/vendor-engines.sh`, which resolves advisories from
[OSV.dev](https://osv.dev) into the pre-expanded rows the scanner looks up.
There are two ways to do it.

**Bulk, which is what you almost certainly want.**
`advisories bulk` imports a whole ecosystem's published export in one command, or all six with
`--all`, so you do not have to know in advance which advisories matter - which is the thing a
dependency scanner is supposed to tell you.
Because that export is rebuilt upstream continuously, there is no fixed checksum to pin, so an
import whose content was not verified refuses until you pass `--accept-unverified`.
Every import prints the integrity grade it achieved and records the digest of exactly what it
fetched into the database header, so you can pin that digest with `--sha256` next time.

**One advisory at a time**, when you already know the specific IDs you care about.
You supply them per ecosystem and `advisories <ecosystem>` resolves just those.
Here `--all` means "every ecosystem you have supplied an ID list for", not "every known advisory".

```sh
# Bulk: every advisory OSV publishes for an ecosystem, in one command.
tools/vendor-engines.sh advisories bulk --accept-unverified npm
# ...or all six ecosystems at once.
tools/vendor-engines.sh advisories bulk --accept-unverified --all
# ...or pin the exact bytes, once you know the digest you want.
tools/vendor-engines.sh advisories bulk --sha256 <hex> npm

# One advisory at a time, when you already know the IDs.
export SCOURSH_ADVISORY_NPM_IDS="GHSA-xxxx-xxxx-xxxx,GHSA-yyyy-yyyy-yyyy"
tools/vendor-engines.sh advisories npm
# or, once an ID list is set for each ecosystem you care about:
tools/vendor-engines.sh advisories --all
```

See [`tools/vendor-engines.sh advisories --help`](tools/vendor-engines.sh) for the full list of
per-ecosystem environment variables.

For the complete CLI, exit-code, and configuration-file reference, see
[`docs/USAGE.md`](docs/USAGE.md).
That document describes the grammar `scan.sh` accepts, not what each flag does today - read it
alongside [Known gaps](#known-gaps), which is where the accepted-but-inert flags are listed.

## Try it yourself: sample vulnerable repos

`scoursh` has no bundled test targets of its own - point it at any real project, or at one of the
well-known intentionally-vulnerable repos below to see it fire for real.

### IaC

```sh
git clone --depth 1 https://github.com/bridgecrewio/terragoat ~/scoursh-test-repos/terragoat
./scan.sh iac --path ~/scoursh-test-repos/terragoat            # Terraform

git clone --depth 1 https://github.com/bridgecrewio/cfngoat ~/scoursh-test-repos/cfngoat
./scan.sh iac --path ~/scoursh-test-repos/cfngoat               # CloudFormation

git clone --depth 1 https://github.com/madhuakula/kubernetes-goat ~/scoursh-test-repos/kubernetes-goat
./scan.sh iac --path ~/scoursh-test-repos/kubernetes-goat        # Kubernetes / Helm

git clone --depth 1 https://github.com/bridgecrewio/cnappgoat ~/scoursh-test-repos/cnappgoat
./scan.sh iac --path ~/scoursh-test-repos/cnappgoat              # multi-cloud Terraform
```

### SAST

```sh
git clone --depth 1 https://github.com/WebGoat/WebGoat ~/scoursh-test-repos/webgoat
./scan.sh sast --path ~/scoursh-test-repos/webgoat --lang java --history

git clone --depth 1 https://github.com/OWASP/NodeGoat ~/scoursh-test-repos/nodegoat
./scan.sh sast --path ~/scoursh-test-repos/nodegoat --lang js --history

git clone --depth 1 https://github.com/adeyosemanputra/pygoat ~/scoursh-test-repos/pygoat
./scan.sh sast --path ~/scoursh-test-repos/pygoat --lang py --history

git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava ~/scoursh-test-repos/owasp-benchmark
./scan.sh sast --path ~/scoursh-test-repos/owasp-benchmark --lang java
```

### SCA (and dual-purpose SAST + SCA)

```sh
git clone --depth 1 https://github.com/juice-shop/juice-shop ~/scoursh-test-repos/juice-shop
./scan.sh sast --path ~/scoursh-test-repos/juice-shop --lang js --history
./scan.sh sca --path ~/scoursh-test-repos/juice-shop   # finds nothing until you build data/advisories.db, see Installation
```

`scan.sh` never clones anything itself - `--path` must already point at a local, readable
directory. Re-run with `git -C <dir> pull` instead of re-cloning if you want to re-test after a
code change, since cloning into a non-empty directory fails.

## Optional third-party engines

Beyond its own native rule packs, `scoursh` can optionally shell out to a small set of vendored
third-party engines for extra coverage, gated behind `--use-engines`:

| Module | Engine | What it adds |
|---|---|---|
| `sast` | [semgrep](https://github.com/semgrep/semgrep) | Broader, AST-aware SAST coverage |
| `sast` | [gitleaks](https://github.com/gitleaks/gitleaks) | Secondary secrets detection, deduplicated against native findings at the same file/line |
| `iac` | [trivy](https://aquasecurity.github.io/trivy/) (`trivy config`) | Broader IaC misconfiguration coverage across Terraform, CloudFormation, Kubernetes, Helm, and docker-compose |

None of these engines ship with the repository. `tools/vendor-engines.sh` is the one script
permitted to touch the network - it is never called during a scan - and requires you to supply
the exact binary URL and checksum yourself via environment variables (`SCOURSH_SEMGREP_*`,
`SCOURSH_GITLEAKS_*`, `SCOURSH_TRIVY_*`); it never guesses or fetches a hardcoded version. Without
`--use-engines`, or with an engine simply absent, `scoursh` behaves exactly as if the flag were never
given - the run is unaffected, only the coverage gap is logged.

## Build status

Three modules are available today and produce real findings: `sast`, `iac`, and `sca` - the last of
those once you have built `data/advisories.db` ([Installation](#installation)).
`dast` and `cloud` are designed but not built; see [What's next](#whats-next).

Exactly which rule packs and ecosystems those three modules cover is generated below straight from
the repository tree, so it can't drift out of sync with what's actually on disk. In this table,
**landed** is the generator's own term for "built and covered by a passing test" - everything else
follows from that.

<!-- BEGIN GENERATED STATUS -->
<!--
  GENERATED by tools/gen-status.sh.  Everything between these two markers is
  machine-written from the repository tree and docs/DESIGN.md's own catalog.

  Do not hand-edit inside the markers: run `tools/gen-status.sh --write`.
  `tests/lint-status.sh` (run by `tests/run-tests.sh`) fails when a committed
  block differs from a fresh generation, so an edit here is a broken build.

  A MERGE CONFLICT INSIDE THIS BLOCK IS NEVER RESOLVED BY HAND.  Take either
  side of the conflict, then re-run `tools/gen-status.sh --write`.
-->

### Module status inventory (generated)

What is PLANNED is parsed from `docs/DESIGN.md`'s own catalog (§6.3 SAST, §6.5
SCA, §6.6 and §8.2 IaC).  What has LANDED is read off the repository tree.  What
REMAINS is the difference, computed rather than typed - which is why no sentence
in here has to be rewritten when a module lands, and why two branches landing
different modules cannot conflict over it.

**Landed** means both halves hold, and both are checked on every run:

1. the artifact exists at its path under `modules/`, and
2. the test tree exercises it - for a rule pack, at least one check id the pack
   itself declares appears in a `tests/**/*.sh` suite; for a script, its
   basename does; for an SCA ecosystem, every manifest `docs/DESIGN.md` §6.5
   names for it is parsed under `modules/sca/` and at least one has a real
   fixture file under `tests/fixtures/`.

A file that is present but that no suite names is **present, untested** - its own
state, never rounded up to landed.  Artifacts are identified by PATH and never by
a commit sha: a ticket cannot know its own landing sha, and invented ones have
shipped here before.

#### SAST - `docs/DESIGN.md` §6.3 catalog -> `modules/sast/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/sast/rules/crypto.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/go.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/injection.rules` | landed | 8 | `tests/suites/sast.sh` |
| `modules/sast/rules/java.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/javascript.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/ldap.rules` | landed | 3 | `tests/suites/sast.sh` |
| `modules/sast/rules/nosql.rules` | landed | 4 | `tests/suites/sast.sh` |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/secrets.rules` | landed | 5 | `tests/suites/records.sh` |
| `modules/sast/history.sh` | landed | - | `tests/suites/sast-history.sh` |

Landed 10 of 10.  Outstanding: none.

#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`

| Manifests | Status | Parsers | Exercised by |
| --- | --- | --- | --- |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-ecosystems-php/package-lock.json` |
| `requirements.txt`, `poetry.lock`, `Pipfile.lock` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-four-ecosystems/requirements.txt` |
| `go.mod`, `go.sum` | landed | 2 of 2 parsed | `tests/fixtures/sca/go-mod/go.mod` |
| `pom.xml`, `build.gradle` | landed | 2 of 2 parsed | `tests/fixtures/sca/maven/pom.xml` |
| `Gemfile.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/mixed-ecosystems/Gemfile.lock` |
| `composer.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/composer-no-manifest/composer.lock` |

Landed 6 of 6.  Outstanding: none.

#### IaC rule packs - `docs/DESIGN.md` §6.6 and §8.2 -> `modules/iac/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/iac/cloudformation.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/docker-compose.rules` | landed | 4 | `tests/suites/iac.sh` |
| `modules/iac/dockerfile.rules` | landed | 6 | `tests/suites/iac.sh` |
| `modules/iac/helm.rules` | landed | 3 | `tests/suites/iac.sh` |
| `modules/iac/kubernetes.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/terraform.rules` | landed | 7 | `tests/suites/iac-trivy.sh` |

Landed 6 of 6.  Outstanding: none.

#### Totals

- Pattern packs on disk: **15** (`modules/sast/rules/` 9, `modules/iac/` 6).
- Module directories present: `modules/dast/`, `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

## Known gaps

Some of the CLI grammar is accepted today but does nothing yet, because the machinery behind it
belongs to a later step; a few other rough edges in shipped behavior are listed here too.
Several are self-disclosed in the run's own `run.json`, but with one exception none of them warns you
on the console or changes an exit code, so they are listed here to be found while you are evaluating
the tool rather than in a pipeline:

- **`sca` scans nothing until you build an advisory database** - but it will not pretend otherwise.
  No `data/advisories.db` ships with this repository, and each ecosystem walk returns before it
  discovers or parses a single manifest without one.
  This is the one gap here that both warns on the console and changes the exit code: until you build it
  ([Installation](#installation)), `scan.sh sca` **exits 4**, prints one warning naming every ecosystem
  it could not scan, and reports a `SCA-COV-NO_ADVISORY_DB-01` finding saying zero dependencies were
  checked.
  It is listed here because it is a setup step you have to know about, not because it can be mistaken
  for a passing scan.
- **`--format` does nothing.**
  Every run writes all five artifacts - `findings.json`, `findings.jsonl`, `report.md`,
  `report.html`, and `run.json` - whatever `--format` is given, so `--format md` still writes the
  HTML report.
  `--format sarif` is accepted too, and nothing anywhere in the tree emits SARIF yet.
- **`--baseline FILE` is parsed and never read.**
  Baseline suppression arrives with persistent run state.
  A path that does not exist is accepted with no error, no warning, and no record of the flag in
  `run.json`.
- **`--fail-on-new` currently behaves identically to `--fail-on`.**
  Every finding is emitted with `status=new` until there is persistent run state to compare a run
  against, so there is nothing yet for it to narrow the gate down to.
- **`--jobs N` is parsed and ignored.**
  Every scan is single-worker and records `single_worker_no_parallel_scan_yet` in its own output.
- **`--authed` is parsed and read by nothing.**
  It belongs to `dast`, which is not built, and it is not recorded in `run.json` either.
- **There is no per-subcommand help.**
  `scan.sh dast --help`, `scan.sh cloud --help`, `scan.sh diff --help`, and `scan.sh sca --help` all
  print the same global usage and exit 0, so nothing there tells you a subcommand is unbuilt.
- `report`'s `--from` flag name is not specified in `docs/DESIGN.md`'s grammar block; `--from` is the
  engineer's own judgment call, noted as such in `scan.sh`'s own comments for a human to confirm or
  override.

## What's next

The full, dependency-ordered build plan lives in [`docs/DESIGN.md`](docs/DESIGN.md) §13, with a
running account of progress in [`CLAUDE.md`](CLAUDE.md)'s "Build order and where we are" section.
What's left, in priority order:

1. **DAST** (`scan.sh dast`) - the running-endpoint scanner, and now the top priority.
   A full, dependency-ordered ticket plan already exists
   ([`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md)), the CLI grammar and the scope gate are in
   place, the HTTP chokepoint (`lib/http.sh`) is complete and tested, and tooling to stand up a local,
   self-hosted test target already exists (`tools/dast-test-target.sh`), though it has not yet been
   observed running end to end - but no scanning code is written yet.
   Two things originally sat in front of it, and only one still does.
   Step 4 (SCA + IaC) is complete, so that half is cleared.
   The other, the two outstanding SAST rule packs below, is a sequencing preference from the original
   build order rather than a technical dependency: the first DAST ticket - the rate limiter, per-run
   request budget, and circuit breaker - touches `lib/http.sh` only and consumes no rule pack at all.
2. **Persistent run state** (`state/`) - needed before `--baseline` suppression, a `--fail-on-new` that
   means anything, and the `diff`/`report` subcommands do real work; all are currently no-ops.
   A full ticket plan exists here too ([`docs/STEP7-STATE-PLAN.md`](docs/STEP7-STATE-PLAN.md)).
3. **SARIF output** - `--format sarif` is accepted but nothing emits it yet.
4. **The compliance-mapping report.**
5. **Live cloud/CSPM scanning** (`scan.sh cloud`) - also fully planned
   ([`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md)), and last in the queue.
   The subcommand is inert today with or without `--live`; there is no `modules/cloud/` in the tree at
   all.
   The read-only AWS wrapper already exists ahead of schedule.

Outside that ordering: two SAST rule packs, `ldap.rules` and `nosql.rules`, are still outstanding from
step 3.
Container image scanning (scanning built image layers, not just Dockerfile/compose source) and
network/host scanning are not currently part of the design plan at all.

See [`ROADMAP.md`](ROADMAP.md) for the fuller breakdown, including work that's already landed ahead
of its normal turn (the optional engine adapters, the `--paranoid` connection observer, and the
Linux network-namespace guarantee are all further along than the step numbering alone would
suggest).

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) - the full CLI, exit-code, and configuration reference.
- [`docs/DESIGN.md`](docs/DESIGN.md) - the original handoff spec.
- [`docs/FOUNDATION.md`](docs/FOUNDATION.md) - the design-tension register: every non-obvious
  architectural decision, with its resolution.
- [`rules/RULE-FORMAT.md`](rules/RULE-FORMAT.md) - the frozen on-disk rule record format.
- [`docs/ADAPTERS.md`](docs/ADAPTERS.md) - the convention for optional third-party engine adapters.
- [`docs/CI-RUNBOOK.md`](docs/CI-RUNBOOK.md) - what CI runs and why.
- [`CLAUDE.md`](CLAUDE.md) - the contributor/agent guide: architecture, sharp edges, and build
  order.

## License

Apache License 2.0 - see [`LICENSE`](LICENSE).
