# scoursh

**scoursh - scan exhaustively**

`scoursh` is an air-gapped, shell-based security scanner: one tool, one entry point, no network
calls except the ones you explicitly authorize. It runs entirely offline against vendored rule
packs and vendored data, so it can sit inside an isolated build environment with no telemetry, no
SaaS backend, and nothing fetched at scan time.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Table of contents

- [What scoursh can do today](#what-scoursh-can-do-today)
- [Why air-gapped](#why-air-gapped)
- [Installation](#installation)
- [Usage](#usage)
- [Try it yourself: sample vulnerable repos](#try-it-yourself-sample-vulnerable-repos)
- [Optional third-party engines](#optional-third-party-engines)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [License](#license)

## What scoursh can do today

Security scanning is usually split into a handful of well-known categories, tied to *when* in a
project's lifecycle they run. Here is where `scoursh` sits in that picture:

| Scanner type | What it scans | Stage in lifecycle | scoursh support |
|---|---|---|---|
| **SAST** | Source code | Development / build | Landed - `scan.sh sast` |
| **SCA** | Open source dependencies | Build / CI-CD pipeline | Landed - `scan.sh sca` |
| **IaC** | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | CI-CD pipeline | Landed - `scan.sh iac` |
| **Secret detection** | Git repositories / files | Commit / pre-commit | Landed - folded into `sast` (`secrets.rules` plus `--history` for git-history replay) |
| **DAST** | A running application | Staging / production | Planned, not built - `scan.sh dast` parses its full flag grammar and enforces a scope gate, but has no scan engine behind it yet |
| **CSPM** | Live cloud infrastructure | Production / runtime | Planned, not built - `scan.sh cloud --live` is a no-op; the read-only AWS wrapper (`lib/awscli.sh`) already exists ahead of schedule |
| **Container image scanning** | Built Docker images (layers, installed packages) | Build / registry | Not built, not currently on the roadmap - `scoursh` lints Dockerfile/docker-compose *source* as part of `iac`, but does not scan built image layers |
| **Network / host scanning** | Servers, ports, OS patches | Operations / maintenance | Not built, not on the roadmap |

So today, `scoursh` covers everything on the *static* side of that list - SAST, SCA, IaC, and
secrets - across a single local checkout, before anything ever runs. See
[Roadmap](#roadmap) for what's planned next.

### Landed coverage, in detail

- **SAST** (`modules/sast/`) - pattern-based scanning for Go, Java, JavaScript, and Python, covering
  injection, crypto misuse, and language-specific issues, plus a dedicated secrets pack
  (`secrets.rules`). `--history` replays the secrets pack across git history via `history.sh`,
  emitting a separate `SAST-HIST-*` check family.
- **SCA** (`modules/sca/`) - parses lockfiles/manifests for six ecosystems (npm/yarn/pnpm,
  pip/poetry/Pipfile, Go modules, Maven, RubyGems, Composer) and matches every pinned dependency
  against a vendored, pre-expanded advisory database (`data/advisories.db`) - no network lookup at
  scan time.
- **IaC** (`modules/iac/`) - six rule packs: Terraform, Kubernetes manifests, Helm chart sources,
  CloudFormation templates, Dockerfile, and docker-compose.

The exact, generated breakdown of every rule pack and ecosystem - which ones are landed, how many
checks each carries, and what's still outstanding - is in
[Current status: what running a scan does today](#current-status-what-running-a-scan-does-today)
below; it's machine-generated from the repository tree so it can't drift out of date the way
hand-written status prose can.

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

## Usage

`scoursh` is a single entry point, `scan.sh`, with one subcommand per surface it scans.
Every run writes `run.json` into its output directory, whether or not any findings were produced.

```sh
scan.sh <command> [options]
```

### Commands

| Command | Flags | Notes |
|---|---|---|
| `sast` | `[--path DIR]` `[--lang py,js,go,java]` `[--history]` | Source code. `--history` replays secret checks across git history and requires `git` on `PATH`. |
| `sca` | `[--path DIR]` | Dependency/lockfile CVEs. |
| `iac` | `[--path DIR]` | Cloud IaC plus container/Kubernetes manifests. |
| `dast` | `--target NAME` `[--intensity passive\|safe\|active]` `[--authed]` | `--target` is required and must name an entry in `config/scope.conf` (see "The scope gate" below). `--intensity` defaults to `passive`. |
| `cloud` | `[--live]` `[--profile NAME]` `[--regions all\|us-east-1,...]` `[--assume-role ARN]` | `--live` requires the `aws` CLI on `PATH`; the run refuses (exit 4) if it is missing. |
| `all` | union of every module's own flags above | Runs sast, sca, iac unconditionally; runs dast only if `--target` is given and cloud only if `--live` is given. Every module it skips is recorded in `run.json` as a `coverage_reduction` fact, not silently dropped. |
| `diff` | `--against DIR` | `DIR` must be a prior run's output directory (must contain `findings.jsonl` or `run.json`). |
| `report` | `--from DIR` | Regenerate reports from a prior run's directory (same shape requirement as `diff --against`). |

`-h` / `--help` at any position before the first unrecognized token prints usage and exits 0.

### Global flags (apply to every command)

| Flag | Value | Default |
|---|---|---|
| `--profile-scan` | `quick` \| `full` \| `compliance` | `full` |
| `--paranoid` | boolean | off |
| `--allow-intrusive` | boolean | off |
| `--jobs N` | positive integer | from `config/scanner.conf` (`4`) |
| `--format` | CSV of `json,sarif,html,md` | all four |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` | from `config/scanner.conf` (`none`) |
| `--fail-on-new` | boolean; **requires `--fail-on`**, usage error otherwise | off |
| `--min-confidence` | `high\|medium\|low` | from `config/scanner.conf` (`low`) |
| `--baseline FILE` | path | none |
| `--out DIR` | path | `reports/<timestamp>` |

### Exit codes

Checked in this fixed order - the first true condition wins, never "worst finding wins":

| Code | Meaning |
|---|---|
| `0` | Clean, or findings all below `--fail-on`. |
| `1` | Findings at or above `--fail-on` (the CI gate). |
| `2` | Usage error (bad flag, bad value, missing required flag). |
| `3` | Scope violation (`dast --target` not found in `config/scope.conf`). |
| `4` | Missing required input (unreadable path, missing config file, missing required command). |
| `5` | Incomplete run (circuit breaker tripped or the run aborted mid-flight). A run that both trips the breaker and has gated findings exits `5`, not `1` - an incomplete run cannot assert a clean gate result either way. |

### The scope gate (dast)

Plain language: **`dast` will not touch a host you have not explicitly listed.**
Before any request goes out, `--target NAME` must match the `id` of an entry in `config/scope.conf`.
If `config/scope.conf` does not exist at all, the run refuses with exit `4` ("missing required input") -
`dast` cannot even attempt the gate.
If the file exists but has no entry with that `id`, the run refuses with exit `3` ("scope violation") -
the gate itself is refusing.
There is no raw-URL flag that bypasses this: `--target` only ever takes a name, never a URL.
`sast`, `sca`, and `iac` do not need `config/scope.conf` at all.

The gate matches on the normalized `(scheme, host, port)` tuple from the target's `base-url`, plus any
`extra-host` entries.
Path is **not** part of the gate - it only bounds what the crawler will fetch, it is not a safety
boundary.

### `--paranoid` - the connection observer (a detector, not a guarantee)

`--paranoid` builds a run-scoped allowlist from exactly four sets: every in-scope target address
`lib/http.sh` actually resolves this run, resolved AWS endpoint addresses for regions actually iterated
(empty, with a stated reason, until region iteration lands), the host's own `/etc/resolv.conf`
nameservers on port 53 plus loopback on any port, and `config/scanner.conf`'s `paranoid_allow` entries.
It then samples this run's own connections (`ss`, or a measured-usable `strace -f -e trace=connect`
fallback) and aborts with exit `3` on the first destination it observes outside that allowlist.
If neither `ss` nor a usable `strace` exists on the host, the run refuses with exit `4` rather than
pretending to be watching.

**Read this plainly: it is a detector, not a guarantee.**
Sampling can miss a connection that opens and closes between two polls.
`tools/run-in-netns.sh` is the actual guarantee: a network namespace whose only route is the declared
scope makes an out-of-scope connection categorically impossible rather than merely observable
(Linux-only, requires root/`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`).
Every `--paranoid` run states this same limitation in its own `run.json`, so the report never
overstates what the flag proved.

## Configuration

Both config files use the same on-disk record format: blank-line-separated `key: value` blocks, one
`#`-prefixed comment per line, no escaping in values.
Never hand-edit these with tooling that assumes shell syntax - the loader parses them as data and never
`source`s them.

### `config/scope.conf` - required only for `dast`

One record per target.

| Key | Required | Repeatable | Default | Value |
|---|---|---|---|---|
| `id` | yes | no | - | Target name used by `--target`. Pattern `^[a-z][a-z0-9-]*$`. Must be the first field. |
| `base-url` | yes | no | - | `https://host[:port][/path]`. Scheme must be `http` or `https`. |
| `extra-host` | no | yes | none | Additional `host[:port]` in scope for this target. |
| `allow-subdomains` | no | no | `false` | `true`/`false`. |
| `allow-private-addresses` | no | no | `false` | `true`/`false`. Gates the link-local/loopback deny list. |
| `notes` | no | no (multi-line) | empty | Free text. |

### `config/scanner.conf` - optional; an absent file behaves as if it contained only `id: scanner`

Resolution order for every key, checked independently per key: **CLI flag > environment variable >
file > built-in default**.
The environment variable for key `foo-bar` is `SCOURSH_CONFIG_FOO_BAR`.

| Key | Value | Default |
|---|---|---|
| `requests-per-second` | decimal, may be fractional | `4` |
| `jobs` | positive integer | `4` |
| `http-timeout` | positive integer (seconds) | `20` |
| `max-redirects` | non-negative integer | `5` |
| `request-budget` | positive integer, per run | `20000` |
| `circuit-breaker-failures` | positive integer | `10` |
| `circuit-breaker-window` | non-negative integer (seconds) | `60` |
| `fail-on` | severity name or `none` | `none` |
| `min-confidence` | `high\|medium\|low` | `low` |
| `redact-secrets` | `true`/`false` | `true` |
| `formats` | repeatable, `json\|sarif\|html\|md` | all four |
| `max-matches-per-file` | positive integer | `200` |
| `evidence-max-bytes` | positive integer | `512` |
| `scratch-dir` | absolute path | `${TMPDIR:-/tmp}` |
| `state-retain-runs` | positive integer | `30` |
| `history-window-days` | positive integer | `365` |
| `history-max-commits` | positive integer | `5000` |
| `lock-stale-seconds` | positive integer | `30` |
| `mutex-timeout-seconds` | positive integer | `120` |
| `paranoid-allow` | repeatable, `addr:port` | empty |
| `notes` | free text (multi-line) | empty |

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
./scan.sh sca --path ~/scoursh-test-repos/juice-shop
```

`scan.sh` never clones anything itself - `--path` must already point at a local, readable
directory. Re-run with `git -C <dir> pull` instead of re-cloning if you want to re-test after a
code change, since cloning into a non-empty directory fails.

## Optional third-party engines

Beyond its own native rule packs, `scoursh` can optionally shell out to a small set of vendored
third-party engines for extra coverage, gated behind `--use-engines`:

| Module | Engine | What it adds |
|---|---|---|
| `sast` | [semgrep](https://github.com/semgrep/semgrep) | Broader pattern-based SAST coverage |
| `sast` | [gitleaks](https://github.com/gitleaks/gitleaks) | Secondary secrets detection, deduplicated against `secrets.rules` findings at the same file/line |
| `iac` | [trivy](https://aquasecurity.github.io/trivy/) (`trivy config`) | Broader IaC misconfiguration coverage across Terraform, CloudFormation, Kubernetes, Helm, and docker-compose |

None of these engines ship with the repository. `tools/vendor-engines.sh` is the one script
permitted to touch the network - it is never called during a scan - and requires you to supply
the exact binary URL and checksum yourself via environment variables (`SCOURSH_SEMGREP_*`,
`SCOURSH_GITLEAKS_*`, `SCOURSH_TRIVY_*`); it never guesses or fetches a hardcoded version. Without
`--use-engines`, or with an engine simply absent, `scoursh` behaves exactly as if the flag were never
given - the run is unaffected, only the coverage gap is logged.

## Current status: what running a scan does today

Three modules have landed and produce real findings: `sast`, `iac`, and `sca`.
`dast` and `cloud` remain a logged no-op today; see [Roadmap](#roadmap).
Exactly which rule packs and ecosystems those three modules cover is GENERATED below by
`tools/gen-status.sh` from `modules/` itself, so it cannot drift from the tree.

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

## Roadmap

The full, dependency-ordered build plan lives in [`docs/DESIGN.md`](docs/DESIGN.md) §13, with a
running account of what has landed and what's next in [`CLAUDE.md`](CLAUDE.md)'s "Build order and
where we are" section. In short, what's left:

- Two outstanding SAST rule packs: `ldap.rules`, `nosql.rules`.
- **DAST** (`scan.sh dast`) - a full, dependency-ordered sub-ticket plan already exists
  ([`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md)), but no work has started; it is gated on the
  two SAST packs above landing first.
- **Live cloud/CSPM scanning** (`scan.sh cloud --live`) - also fully planned
  ([`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md)), gated on DAST completing. The read-only
  AWS wrapper (`lib/awscli.sh`) already exists ahead of schedule.
- **SARIF output and the compliance report** - `--format sarif` is accepted but nothing emits it yet.
- **Persistent run state** (`state/`) - needed before `--baseline` suppression and the `diff`/`report`
  subcommands do real work; both are currently logged no-ops.
- Container image scanning (scanning built image layers, not just Dockerfile/compose source) and
  network/host scanning are not currently part of the design plan at all.

See [`ROADMAP.md`](ROADMAP.md) for the fuller breakdown, including what has already landed ahead of
its normal step order (the optional engine adapters, the `--paranoid` connection observer, and the
Linux network-namespace guarantee are all further along than the step numbering alone would suggest).

## Documentation

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
