# scoursh

**Scan exhaustively. Trust nothing over the network.**

`scoursh` is an egress-restricted, shell-based security scanner: one tool, one CLI, one report,
across source code (SAST), dependencies (SCA), infrastructure-as-code (IaC), a running endpoint
(DAST), and live AWS configuration (Cloud/CSPM). It makes zero network calls except the ones you
explicitly authorize, runs on nothing but
`bash` and standard coreutils, and treats "we did not check that" as a first-class result instead of
folding it into "clean." The name blends **scour** (search thoroughly, corner to corner) and **sh**
(the shell it's written in) - *scan exhaustively*.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Contents

- [What it scans](#what-it-scans)
- [Why scoursh](#why-scoursh)
- [Install](#install)
- [Quickstart](#quickstart)
- [Commands & recipes](#commands--recipes)
- [Output & the audit report](#output--the-audit-report)
- [Safety model](#safety-model)
- [Documentation](#documentation)
- [Status](#status)
- [License](#license)

## What it scans

| Surface | Covers | Status |
|---|---|---|
| **SAST** | Source code - injection, crypto misuse, secrets, language-specific issues (Go, Java, JavaScript, Python), plus git-history secret replay | ✅ built - `scan.sh sast` |
| **SCA** | Dependency/lockfile CVEs across 6 ecosystems (npm, PyPI, Maven, Go, RubyGems, Composer) | ✅ built - `scan.sh sca`, once you've [built the advisory database](#commands--recipes) |
| **IaC** | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | ✅ built - `scan.sh iac` |
| **DAST** | A running application you've authorized - auth/crawl, passive checks, safe-active, the full injection family, application-layer (GraphQL, rate-limiting, JWT, IDOR) | ✅ built - `scan.sh dast` |
| **Cloud / CSPM** | Live AWS configuration | ✅ built - `scan.sh cloud`, 30 AWS services, read-only, credential-authorized, CIS/OWASP-mapped |

Roughly 290 checks ship across the five built surfaces. The complete catalogue - every check id,
what it catches, and what it needs to run - is [`docs/CHECKS.md`](docs/CHECKS.md) (also published as
a standalone page, [`docs/checks.html`](docs/checks.html)). Almost all of it runs with **no external
data**: point scoursh at a path or a running target and every SAST/IaC/DAST check works immediately.
Only dependency-CVE matching (SCA) and one banner check need the vendored advisory database - see
[Commands & recipes](#commands--recipes).

## Why scoursh

scoursh is not a deeper Semgrep, ZAP, or Trivy, and it won't claim to be - a specialist in any single
category outclasses it there. Its value is different: **one** unified, egress-safe sweep across five
surfaces, with no heavy toolchain to install, that states its own blind spots instead of quietly
reporting "clean" when it never actually looked. Reach for it as a CI baseline everywhere - including
air-gapped or egress-audited environments a specialist can't run in at all - or wherever "did it
actually check?" has to be an answerable question: an auditor, a post-incident review, compliance
evidence. Reach for a specialist - Semgrep, ZAP, Trivy, Checkov, Gitleaks, Prowler - when you need
its depth.

The full capability comparison, including measured head-to-head numbers and an honest verdict per
surface, is [`docs/COMPARISON.md`](docs/COMPARISON.md) (also
[`docs/comparison.html`](docs/comparison.html)).

## Install

No build step, no runtime dependency beyond a standard Unix toolchain:

- **bash >= 4.2** (macOS ships 3.2 by default - install a newer one and put it ahead of `/bin/bash`
  on `PATH`; `scan.sh` checks this itself and refuses with a clear message otherwise), plus
  `grep`/`rg`, `awk`, and coreutils.
- `git` on `PATH` is needed only for `sast --history`. Nothing else is required to run `sast`, `sca`,
  `iac`, or `dast`.
- `dast` additionally needs a target authorized in `config/scope.conf` - it's the safety control that
  keeps `scan.sh` from ever being pointed at a host you don't own. Copy the bundled fixture to try it
  against a local, disposable test target:

  ```sh
  cp tools/dast-test-target/scope.conf config/scope.conf   # authorizes 127.0.0.1:3400 as dast-test-target
  ```

```sh
git clone https://github.com/abhi-sama/scoursh.git
cd scoursh
./scan.sh --help
```

`tests/run-tests.sh` is the real test entry point; `pnpm test`/`npm test` are thin aliases for it -
scoursh has no Node runtime dependency.

## Quickstart

The single most useful command right after cloning - `--path` defaults to `.`, so this scans
scoursh's own source tree with no further setup:

```sh
./scan.sh sast
```

Every run writes to a fresh, timestamped directory under `reports/` and prints that path when it
finishes. `report.html` is the human-readable report; `findings.jsonl` (one JSON object per finding)
and `run.json` (the run's own identity, coverage facts, and exit-gate decision - what a CI step should
actually read) land alongside it on every run, whatever `--format` you asked for. Add `--format
html,audit` and you additionally get `report-audit.html`, built for an auditor rather than a triager:
every registered check, not just the ones that fired, in one of *found something / ran clean / didn't
run (why) / unaccounted*.

## Commands & recipes

This section is task-flow, copy-paste, and validated against this branch. The full flag-by-flag
reference - including every accepted-but-not-yet-live flag - is
[`docs/USAGE.md`](docs/USAGE.md); its own [Recipes](docs/USAGE.md#recipes) section has the deeper
version of everything below.

### 1. Populate the advisory database (needed only for SCA / dependency CVEs)

scoursh ships **no** advisory database - it is deliberately never bundled or auto-fetched. Build it
once, by hand, on a networked box:

```sh
tools/vendor-engines.sh advisories bulk --all --accept-unverified
```

This resolves OSV.dev's published export for all six ecosystems, verifies each archive's transport,
and writes `data/advisories.db`. `--accept-unverified` acknowledges an unpinned (transport-
authenticated, not content-pinned) fetch - pin the exact bytes with `--sha256` once you know the
digest you want. Without this step, `scan.sh sca` honestly reports that no advisory data was
available and **exits 4** rather than a false all-clear. `tools/vendor-engines.sh` is the *only*
script in this repository permitted to touch the network, and it is never invoked during a scan. Full
walkthrough, including measured import size/time and the `range_only_skipped` coverage caveat:
[`docs/USAGE.md`](docs/USAGE.md#dependency-data-dataadvisoriesdb).

### 2. Per-surface scans

```sh
./scan.sh sast --path DIR --format html,audit --out reports/sast
./scan.sh sca  --path DIR --format html,audit --out reports/sca      # needs step 1
./scan.sh iac  --path DIR --format html,audit --out reports/iac
./scan.sh dast --target NAME --i-own-target NAME --intensity passive --format html,audit --out reports/dast
```

### 3. DAST against a live app - the recipe that actually lands injection findings

A bare passive scan of a target the crawler hasn't seen much of finds relatively little - most of a
real application's surface is API endpoints a static HTML crawl never reaches:

```sh
./scan.sh dast \
  --target dast-test-target --i-own-target dast-test-target \
  --intensity active \
  --openapi ./openapi.json \
  --requests-per-second 2 --jobs 2 --circuit-breaker-failures 40 \
  --format json,sarif,html,md,audit \
  --out reports/dast-full
```

- `--intensity active` sends real attack payloads and **requires** `--i-own-target NAME` naming the
  same target.
- Import your real API surface with `--openapi`/`--har`/`--postman`/`--graphql-schema` so the scanner
  reaches real endpoints - a single-page app's own routes are close to invisible to a static crawl
  alone.
- The circuit breaker (10 failures/60s by default) is a **safety feature**, not a bug: it stops the
  run if the target stops answering. Go gentler than the unaffirmed defaults on a small target
  (`--requests-per-second 2 --jobs 2` - both already under the 4/s ceiling, so neither needs
  `--i-own-target` on its own) and raise `--circuit-breaker-failures` (which *does* need
  `--i-own-target`, since it's above the default 10) if an idiosyncratic-but-healthy target trips it
  during discovery, before the injection phase ever runs.
- Run one scan at a time against a target - concurrent scans multiply the effective request rate the
  target sees and can trip the breaker for reasons that have nothing to do with the target's health.

### 4. Everything in one run

```sh
./scan.sh all --path DIR --target NAME --i-own-target NAME --intensity active \
  --openapi ./openapi.json --requests-per-second 2 --jobs 2 --circuit-breaker-failures 40 \
  --format json,sarif,html,md,audit --out reports/all
```

`all` runs every module whose inputs are configured - `--path` drives SAST/SCA/IaC, `--target` drives
DAST - and records a `coverage_reduction` for any module it skips, rather than dropping it silently.

**Gotcha: don't scan `data/` itself.** After step 1, `data/advisories.db` is a several-hundred-MB
binary file. If `--path` includes it - for example, running `./scan.sh all --path .` from inside a
checkout where you just built the database - `sast` will walk it like source, producing noise and a
very slow run for no security value. Point `--path` at real source, or exclude `data/`.

### 5. Guided (interactive) mode

```sh
./scan.sh all --guided                    # walks you through the choices and runs the composed command
./scan.sh dast --guided --print-command   # walk through the choices, but print the command instead of running it
```

At the languages prompt, press **Enter** to accept the bracketed default and scan every language;
typing the literal word `all` is rejected (only `py`, `js`, `go`, `java` are valid, singly or
comma-separated) and re-prompts.

### 6. Optional specialist engines, for extra depth

```sh
tools/vendor-engines.sh <engine>          # semgrep | gitleaks | trivy - you pin version + URL + sha256
./scan.sh sast --path DIR --use-engines       # adds semgrep (broader rules) + gitleaks (secrets)
./scan.sh iac  --path DIR --use-engines       # adds trivy config (broader IaC coverage)
```

`--use-engines` only does anything once the named engine's vendored binary and ruleset are actually
on disk; absent, it is a silent no-op, never an error. Nothing is fetched at scan time.

### 7. CI gating, state, and other commands

```sh
./scan.sh sast --path DIR --fail-on high              # exit 1 if anything at/above high is found
./scan.sh sast --path DIR --fail-on high --fail-on-new    # ...but only for findings new since the last run
./scan.sh sast --path DIR --baseline config/baseline.json # suppress accepted-risk findings by fingerprint
./scan.sh diff --against reports/<prior-run>          # classify the latest run vs a named earlier one
./scan.sh report --from reports/<prior-run>           # regenerate report.md/html/sarif from a prior run's own findings, no rescan
./scan.sh cloud --live                                # AWS CSPM - 30 services, read-only, needs AWS credentials
```

## Output & the audit report

`--format` takes a CSV of `json,sarif,html,md,audit,agent` (default `json,sarif,html,md`):

- `json` -> `findings.json`; `sarif` -> a complete, schema-validated `report.sarif` that drops into
  GitHub code scanning or any SARIF-aware viewer (it deliberately omits `security-severity` - see
  [`docs/USAGE.md`](docs/USAGE.md#sarif-output) for why); `html`/`md` -> `report.html`/`report.md`.
- `findings.jsonl` and `run.json` are written on **every** run regardless of `--format` - they are
  mandatory per-run records, not one of the six selectable formats.
- `audit` is an **opt-in** value: it writes `report-audit.html` **alongside** `report.html`,
  never in place of it. Where the ordinary report lists findings, the audit report lists every
  registered check and its fate - found / ran clean / skipped (with a reason) / not covered - so "we
  looked and found nothing" and "we never looked" are never the same line.
- `agent` -> `agent-fix.json`, also **opt-in**: a compact, schema-projected findings file for a
  downstream AI fixing agent, with a deterministic fix scaffold where scoursh can derive one (an SCA
  version bump, an IaC one-line config fix, or a cloud CLI command explicitly labeled
  suggested/human-review/never-auto-run) and a coverage header so "did not check" can never read as
  "clean". Contract: [`docs/AGENT-FORMAT.md`](docs/AGENT-FORMAT.md).

Full reference: [`docs/USAGE.md`](docs/USAGE.md#--format-and-the-formats-config-key).

## Safety model

- **One egress chokepoint.** Every outbound HTTP call goes through `lib/http.sh`, which refuses any
  host absent from `config/scope.conf`'s resolved allowlist - no raw-URL bypass, enforced at runtime
  and lint-checked in the test suite. SAST, SCA, and IaC make zero network calls, full stop; DAST
  talks only to a target you named there.
- **Read-only AWS, by construction.** Every AWS call - across all 30 `scan.sh cloud` service checks -
  goes through `lib/awscli.sh`'s `aws_ro` wrapper, which refuses any operation that is not read-only,
  enforced at runtime and lint-checked in the test suite, the same way `lib/http.sh` gates DAST.
- **Active DAST requires `--i-own-target NAME`.** Raising the default rate limit, request budget, or
  intensity above `passive` needs this affirmation, and `NAME` must equal `--target` exactly - a
  stale command or a copied CI config can never carry an authorization to a host that changed hands.
  It's a key, not a switch: on its own it raises nothing and authorizes nothing; a host is only ever
  scannable if it has its own record in `config/scope.conf`.
- **A detector on top of the enforcement.** `--paranoid` samples the scan process's own outbound
  connections and aborts on the first one outside scope, on Linux (`ss`/`strace`) and macOS (`lsof`)
  alike. `tools/run-in-netns.sh` goes further on Linux, building a network namespace where an
  out-of-scope connection is physically impossible rather than merely observed - Linux-only, with no
  macOS equivalent.

This is deliberately **egress-restricted, not air-gapped**: `dast` and `cloud --live` inherently have
to talk to *something*, since testing a running app or reading live AWS config is the entire point of
those two scans. What's actually guaranteed is narrower, and it's the part that
matters - scoursh itself has no back-channel, and it never decides on its own who to contact. See
`docs/FOUNDATION.md` tension 28 for the full correction and `docs/adr/0001-egress-model-correction.md`
for the dated decision record.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) - the full CLI, exit-code, and configuration reference.
- [`docs/CHECKS.md`](docs/CHECKS.md) - every built-in check, grouped by surface and by what data it needs.
- [`docs/COMPARISON.md`](docs/COMPARISON.md) - the honest comparison against Semgrep, Trivy, Checkov,
  ZAP, Gitleaks, Prowler, and others, including measured head-to-head numbers.
- [`docs/DESIGN.md`](docs/DESIGN.md) - the original handoff spec, preserved verbatim.
- [`docs/FOUNDATION.md`](docs/FOUNDATION.md) - the design-tension register: every non-obvious
  architectural decision, with its resolution.
- [`rules/RULE-FORMAT.md`](rules/RULE-FORMAT.md) - the frozen on-disk rule record format.
- [`docs/ADAPTERS.md`](docs/ADAPTERS.md) - the convention for optional third-party engine adapters.
- [`docs/CI-RUNBOOK.md`](docs/CI-RUNBOOK.md) - how this project's tests actually run today (the
  hosted GitHub Actions workflow is dormant until the repository is public).
- [`ROADMAP.md`](ROADMAP.md) - what's landed and what's left, in priority order.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - how to propose a change and what a PR needs.
- [`AGENTS.md`](AGENTS.md) - the contributor/agent guide: architecture, sharp edges, and build order
  (`CLAUDE.md` is a symlink to the same file, for tooling that looks for that name specifically).

## Status

Five surfaces are built and produce real findings today: **SAST**, **IaC**, **SCA** (once you've
built `data/advisories.db`), **DAST** (once you've authorized a target), and **Cloud/AWS CSPM** (once
you've pointed it at an account with resolvable credentials). Guided mode, persistent run state with a
real `--fail-on-new` CI carve-out, a complete, schema-validated SARIF 2.1.0 writer, and both halves of
the compliance report (findings grouped by OWASP Top 10 category and by CIS AWS Foundations Benchmark
v3.0.0 control, each with an honest per-category/per-control
assessed/out-of-scope/not-applicable/filtered status, in both `report.md` and `report.html`) have also
landed. **Cloud/AWS (CSPM) is built**: `scan.sh cloud --live` resolves the account and its enabled
regions, runs read-only checks against all 30 services in `docs/DESIGN.md` §8.1's catalog through the
`aws_ro` chokepoint, and records access-denied, opted-out, or throttled services as a declared
coverage reduction rather than folding them into a silent clean pass. What's still open is the
`posture/` phase (SSO/edge/session drift checks against an operator-declared baseline) - the config
schema (`config/posture.conf.example`) exists but no posture check has landed yet - and there is no
bundled or hosted AWS account: you point it at your own.
See [`ROADMAP.md`](ROADMAP.md) for the full, current priority order, including recently-fixed defects
in shipped features, and [`docs/USAGE.md`'s "Accepted but not yet
implemented"](docs/USAGE.md#accepted-but-not-yet-implemented) for every flag that parses today but
changes nothing yet.

The exact, generated breakdown of every rule pack and ecosystem the three static-analysis modules
cover is below, straight from the repository tree, so it can't drift out of sync with what's on disk
(`dast` isn't part of this table - see [`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md) for its
own per-check landing record). **Landed** is the generator's own term for "built and covered by a
passing test."

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
| `modules/sast/rules/crypto.rules` | landed | 5 | `tests/suites/report.sh` |
| `modules/sast/rules/go.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/injection.rules` | landed | 8 | `tests/suites/sast.sh` |
| `modules/sast/rules/java.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/javascript.rules` | landed | 7 | `tests/suites/report.sh` |
| `modules/sast/rules/ldap.rules` | landed | 3 | `tests/suites/sast.sh` |
| `modules/sast/rules/nosql.rules` | landed | 4 | `tests/suites/sast.sh` |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/report.sh` |
| `modules/sast/rules/secrets.rules` | landed | 7 | `tests/suites/agent-format.sh` |
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
| `modules/iac/dockerfile.rules` | landed | 6 | `tests/suites/agent-format.sh` |
| `modules/iac/helm.rules` | landed | 3 | `tests/suites/iac.sh` |
| `modules/iac/kubernetes.rules` | landed | 8 | `tests/suites/agent-format.sh` |
| `modules/iac/terraform.rules` | landed | 7 | `tests/suites/agent-format.sh` |

Landed 6 of 6.  Outstanding: none.

#### Totals

- Pattern packs on disk: **15** (`modules/sast/rules/` 9, `modules/iac/` 6).
- Module directories present: `modules/cloud/`, `modules/dast/`, `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

## License

Apache License 2.0 - see [`LICENSE`](LICENSE). Contributions welcome - see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how a PR flows and what it needs.
