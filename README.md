# scoursh

**Scan exhaustively. Trust nothing over the network.**

`scoursh` is an air-gapped, shell-based security scanner. One tool, one entry point, one report -
covering source code (SAST), dependencies (SCA), and infrastructure-as-code (IaC) today, with a
running-endpoint scanner (DAST) and live cloud posture checking (CSPM) already designed and next in
line. It runs entirely offline against rules and data vendored *in the repository*, so it can sit
inside a fully isolated build environment with no telemetry, no SaaS backend, and nothing fetched
at scan time.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Table of contents

- [Why "scoursh"](#why-scoursh)
- [Features](#features)
- [Types of security scans, and where scoursh stands today](#types-of-security-scans-and-where-scoursh-stands-today)
- [scoursh vs. semgrep](#scoursh-vs-semgrep)
- [Why air-gapped](#why-air-gapped)
- [Installation](#installation)
- [Try it yourself: sample vulnerable repos](#try-it-yourself-sample-vulnerable-repos)
- [Optional third-party engines](#optional-third-party-engines)
- [Build status](#build-status)
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
- **Genuinely air-gapped** - not "air-gapped if you configure it right." Every network call in the
  codebase routes through one of two chokepoints (an HTTP wrapper and a read-only AWS wrapper), a
  dedicated lint fails the build if anything bypasses them, and a separate lint proves no AI/LLM
  provider is reachable from the shipped tool at all.
- **Deterministic output** - the same scan produces byte-identical findings whether it runs on
  Linux with GNU coreutils or macOS with a BSD userland, checked automatically in CI.
  Fingerprints survive reindentation and unrelated edits, so a diff or baseline never reports a
  false "fixed" or a false "new."
- **A detector *and* a guarantee for egress** - `--paranoid` watches the process's own outbound
  connections and aborts on the first one outside scope; on Linux, `tools/run-in-netns.sh` goes
  further and builds a network namespace where an out-of-scope connection is not just detected, it's
  physically impossible.
- **Honest about its own gaps** - every module a run skips, every coverage limitation, every
  unproven claim is recorded directly in the run's own output as a `coverage_reduction` or
  `coverage_gap` fact, not silently dropped from the report.
- **Optional extra firepower, still offline** - can shell out to vendored copies of semgrep,
  gitleaks, and trivy for broader coverage, with results deduplicated against scoursh's own
  findings, all still under the same zero-network-at-scan-time rule.
- **A real CI gate, not just a report** - a fixed 0-5 exit-code contract, severity thresholds,
  confidence filtering, and a `--fail-on-new` mode designed to gate a pull request rather than just
  produce a PDF nobody reads.

## Types of security scans, and where scoursh stands today

Security scanning is usually split into a handful of categories, tied to *when* in a project's
lifecycle they run:

| Scanner type | What it scans | Stage in lifecycle | scoursh |
|---|---|---|---|
| **SAST** | Source code | Development / build | ✅ Available - `scan.sh sast` |
| **SCA** | Open source dependencies | Build / CI-CD pipeline | ✅ Available - `scan.sh sca` |
| **IaC** | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | CI-CD pipeline | ✅ Available - `scan.sh iac` |
| **Secret detection** | Git repositories / files | Commit / pre-commit | ✅ Available - built into `sast` (`--history` replays across git history) |
| **DAST** | A running application | Staging / production | 🚧 Designed, not built - the CLI grammar and scope gate exist; no scan engine yet |
| **CSPM** | Live cloud infrastructure | Production / runtime | 🚧 Designed, not built - the read-only AWS wrapper exists ahead of schedule; no live checks yet |
| **Container image scanning** | Built Docker images (layers, installed packages) | Build / registry | ⛔ Not planned - `scoursh` lints Dockerfile/compose *source* as IaC, not built image layers |
| **Network / host scanning** | Servers, ports, OS patches | Operations / maintenance | ⛔ Not planned |

So today, `scoursh` covers everything on the *static* side of that list - before anything ever
runs, and before any code ships - in a single pass over a local checkout. See
[What's next](#whats-next) for the rest.

### What's available today, in detail

- **SAST** (`modules/sast/`) - pattern-based scanning for Go, Java, JavaScript, and Python, covering
  injection, crypto misuse, and language-specific issues, plus a dedicated secrets pack.
  `--history` replays the secrets pack across git history, so a credential removed from the working
  tree but still reachable through git log still gets caught.
- **SCA** (`modules/sca/`) - parses lockfiles/manifests for six ecosystems (npm/yarn/pnpm,
  pip/poetry/Pipfile, Go modules, Maven, RubyGems, Composer) and matches every pinned dependency
  against a locally-generated advisory database sourced from [OSV.dev](https://osv.dev) - no
  network lookup at scan time. (The database ships empty; see
  [Installation](#installation) for the one-time step to populate it.)
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

## Why air-gapped

Exactly two kinds of outbound traffic are ever permitted: `curl` to a host you explicitly
authorized in `config/scope.conf`, and read-only AWS API calls to your own account. Everything
else - telemetry, a SaaS backend, fetching rules or advisories at scan time - is forbidden by
design, so the tool can run on a host with no internet access at all.

That single constraint shapes most of the architecture:

- Rules, payloads, wordlists, and advisory data are **vendored in the repo** and read from disk.
- `tools/vendor-engines.sh` is the only script that ever touches the network, is never called
  during a scan, and is quarantined and tested as such.
- Every HTTP call goes through one wrapper (`lib/http.sh`) that refuses any host absent from the
  resolved scope allowlist; every AWS call goes through one wrapper (`lib/awscli.sh`) that refuses
  any operation that is not read-only.
- The HTML report is self-contained, with no external assets and a strict inline CSP.
- `--paranoid` samples the process's own outbound connections during a run and aborts the moment
  it observes one outside the resolved allowlist; `tools/run-in-netns.sh` goes further on Linux,
  building a network namespace whose route table admits only the declared scope, so an
  out-of-scope connection is categorically impossible rather than merely observed.
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

**One-time setup for SCA:** `data/advisories.db` ships empty on a fresh clone - SCA's parsing and
matching code is fully built and tested, but the actual advisory data is deliberately never
bundled or auto-fetched. Populate it yourself, on a networked box, with real advisory IDs you've
identified for the ecosystems you care about:

```sh
export SCOURSH_ADVISORY_NPM_IDS="GHSA-xxxx-xxxx-xxxx,GHSA-yyyy-yyyy-yyyy"
tools/vendor-engines.sh advisories npm
# or: tools/vendor-engines.sh advisories --all
```

See [`tools/vendor-engines.sh advisories --help`](tools/vendor-engines.sh) for the full list of
per-ecosystem environment variables.

For the complete CLI, exit-code, and configuration-file reference, see
[`docs/USAGE.md`](docs/USAGE.md).

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
./scan.sh sca --path ~/scoursh-test-repos/juice-shop   # needs data/advisories.db populated, see Installation
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

Three modules are available today and produce real findings: `sast`, `iac`, and `sca`.
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
| `modules/sast/rules/ldap.rules` | not landed | - | - |
| `modules/sast/rules/nosql.rules` | not landed | - | - |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/secrets.rules` | landed | 5 | `tests/suites/records.sh` |
| `modules/sast/history.sh` | landed | - | `tests/suites/sast-history.sh` |

Landed 8 of 10.  Outstanding: `ldap.rules`, `nosql.rules`.

#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`

| Manifests | Status | Parsers | Exercised by |
| --- | --- | --- | --- |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-ecosystems-php/package-lock.json` |
| `requirements.txt`, `poetry.lock`, `Pipfile.lock` | landed | 3 of 3 parsed | `tests/fixtures/sca/python-requirements/requirements.txt` |
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

- Pattern packs on disk: **13** (`modules/sast/rules/` 7, `modules/iac/` 6).
- Module directories present: `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

### Known gaps

- `report`'s `--from` flag name is not specified in `docs/DESIGN.md`'s grammar block; `--from` is the
  engineer's own judgment call, noted as such in `scan.sh`'s own comments for a human to confirm or
  override.
- No SARIF or compliance-mapping report exists yet, so `--format sarif` is accepted but there is
  nothing yet that emits SARIF.

## What's next

The full, dependency-ordered build plan lives in [`docs/DESIGN.md`](docs/DESIGN.md) §13, with a
running account of progress in [`CLAUDE.md`](CLAUDE.md)'s "Build order and where we are" section.
In short, what's left:

- Two outstanding SAST rule packs: `ldap.rules`, `nosql.rules`.
- **DAST** (`scan.sh dast`) - a full, dependency-ordered ticket plan already exists
  ([`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md)), but no work has started; it's gated on the
  two SAST packs above landing first. A local, self-hosted test target is already in place ahead of
  time (`tools/dast-test-target.sh`).
- **Live cloud/CSPM scanning** (`scan.sh cloud --live`) - also fully planned
  ([`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md)), gated on DAST completing. The read-only
  AWS wrapper already exists ahead of schedule.
- **SARIF output and a compliance report** - `--format sarif` is accepted but nothing emits it yet.
- **Persistent run state** (`state/`) - needed before `--baseline` suppression and the `diff`/`report`
  subcommands do real work; both are currently no-ops. A full ticket plan exists here too
  ([`docs/STEP7-STATE-PLAN.md`](docs/STEP7-STATE-PLAN.md)).
- Container image scanning (scanning built image layers, not just Dockerfile/compose source) and
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
