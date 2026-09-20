# scoursh

**Scan exhaustively. Trust nothing over the network.**

`scoursh` is an egress-restricted, shell-based security scanner: one tool, one CLI, one report,
across source code (SAST), dependencies (SCA), infrastructure-as-code (IaC), a running endpoint
(DAST), a network/host listener set, a container image, and live AWS configuration (Cloud/CSPM). It
makes zero network calls except the ones you explicitly authorize, runs on nothing but
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
| **Network / host** | Service-posture scanning over an operator-declared listener set (`config/scope.conf`'s `base-url`/`extra-host` entries) - reachability, banner/version disclosure, TLS posture on non-web ports, plaintext/STARTTLS transport posture. Never a port sweep or host discovery: a port scoursh was not told about is never probed | ✅ built - `scan.sh network --target NAME` |
| **Container image** | Offline OS-package (apk, dpkg, rpm) and language-dependency CVE matching, plus config-blob checks (effective runtime user, exposed ports, mutable base tag), against a `docker save` tarball or OCI image layout you supply - never a registry pull | ✅ built - `scan.sh image --image ID` |
| **Cloud / CSPM** | Live AWS configuration | ✅ built - `scan.sh cloud`, 30 AWS services, read-only, credential-authorized, CIS/OWASP-mapped |

319 checks ship across the seven built surfaces (53 SAST + 36 IaC + 92 DAST + 15 network + 11
container-image + 112 Cloud/AWS; SCA is a table lookup across 6 ecosystems rather than a check count).
The complete catalogue - every check id, what it catches, and what it needs to run - is
[`docs/CHECKS.md`](docs/CHECKS.md) (also published as a standalone page,
[`docs/checks.html`](docs/checks.html)). Almost all of it runs with **no external data**: point scoursh
at a path or a running target and every SAST/IaC/DAST/network check works immediately. Dependency-CVE
matching (SCA), most container-image checks, and the three version-lookup checks (one DAST, two
network) need the vendored advisory database - see
[Commands & recipes](#commands--recipes).

## Why scoursh

scoursh is not a deeper Semgrep, ZAP, or Trivy, and it won't claim to be - a specialist in any single
category outclasses it there. Its value is different:

- **One** unified, egress-safe sweep across seven surfaces (SAST, SCA, IaC, DAST, network/host,
  container image, Cloud/CSPM) in a single CLI and a single report, with no heavy toolchain to
  install - pure `bash` and coreutils.
- **Egress is restricted, not promised - and kernel-enforced for the three offline scanners.**
  `sast`/`sca`/`iac` genuinely make zero network calls, and `tools/run-sandboxed.sh` (macOS Seatbelt)
  and `tools/run-in-netns.sh` (Linux network namespaces) back that with a real, kernel-level
  deny-all-network guarantee rather than a policy the tool merely follows - which is why those three
  run in air-gapped and egress-audited environments a network-dependent specialist can't run in at
  all. `dast` and `cloud --live` inherently have to talk to the target or account you authorized, so
  scoursh is deliberately **egress-restricted, not air-gapped** overall - see
  [Safety model](#safety-model) for exactly what's guaranteed and where the line is.
- **"We did not check that" is a first-class, recorded result**, never folded into a silent "clean" -
  so "did it actually check?" stays an answerable question for an auditor, a post-incident review, or
  compliance evidence.
- **`--format agent`** emits a compact findings file (`reports/<run>/agent-fix.json`) shaped for a
  downstream fixing agent to consume and act on, not for a human to triage.

Reach for a specialist - Semgrep, ZAP, Trivy, Checkov, Gitleaks, Prowler - when you need its depth.

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
- `tar` on `PATH` is needed only for `image`, which reads a `docker save` tarball or an OCI image
  layout the operator supplies. Strictly, `tar` is not coreutils - it is called out separately here
  rather than folded into the line above, because a dependency that only one subcommand needs should
  be visible as exactly that.
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

Each surface needs one thing set up first, noted as a trailing comment:

```sh
./scan.sh sast    --path DIR --format html,audit --out reports/sast
./scan.sh sca     --path DIR --format html,audit --out reports/sca      # needs step 1 (data/advisories.db)
./scan.sh iac     --path DIR --format html,audit --out reports/iac
./scan.sh dast    --target NAME --format html,audit --out reports/dast     # NAME must be authorized first - see 3a below
./scan.sh network --target NAME --format html,audit --out reports/network  # same authorization; scans NAME's declared extra-host listeners
./scan.sh image   --image ID --format html,audit --out reports/image      # config/images.conf must name ID, or pass --source PATH
./scan.sh cloud   --live --format html,audit --out reports/cloud         # needs the `aws` CLI on PATH and resolvable credentials
```

`network` only probes `extra-host` listeners declared in `config/scope.conf` - a target with only
`base-url` gives it nothing to test, and every phase records `no_declared_listeners`. `image` never
pulls anything: point `--source` at a `docker save ID -o PATH` tarball or an OCI-layout directory (a
plain file is read as the tarball, a directory as the OCI layout). `cloud --live` makes real, read-only
AWS API calls against whichever account your credentials resolve to.

### 3a. Authorize a `dast`/`network` target

`--target NAME` refuses to run unless `NAME` is authorized in `config/scope.conf`. At an interactive
terminal, scoursh **offers to write the record for you** the moment it hits that refusal - answer its
prompts and the same command continues, no second invocation needed. Non-interactively (CI, a script),
write the record by hand - `config/scope.conf.example` documents every key; the minimum is:

```sh
cat >> config/scope.conf <<'EOF'
id: my-app
base-url: https://my-app.example.com/
EOF
```

Add one `extra-host: host:port` line per additional listener you want `network` to scan. `--guided`
walks through the same choices interactively: `./scan.sh dast --guided`.

### 3b. DAST against a single-page app (capture a HAR)

A static crawl only follows HTML links and mines literal-looking paths out of fetched JS - a real API
call an SPA makes from a click handler is invisible to it. Measured against a local Angular SPA
fixture: a plain crawl found **41 endpoints** (crawl + JS-mined) but missed a real search endpoint, a
real product-listing endpoint, and the login call's method and body entirely. Capturing ~20 seconds of
real browser traffic and importing it added exactly those **3** as verified `source: har` entries with
real methods and bodies, visible in `reports/<run>/inventory/endpoints.json`.

1. Open the app in Chrome, open DevTools (`Cmd+Opt+I` / `F12`) -> **Network** tab.
2. Check **Preserve log** (so an SPA route change or reload doesn't clear the capture).
3. Use the app for real for ~20-30 seconds - log in, click through the flows you want tested.
4. Right-click any request in the list -> **Save all as HAR with content**.
5. Run the scan against the saved file:

```sh
./scan.sh dast --target NAME --har ./capture.har --intensity passive --format html,audit --out reports/dast-har
```

Only the HAR's **paths** are used - any host it names is discarded, and every request scoursh sends
still goes to your authorized `base-url`. `--openapi FILE` does the same job when the app publishes an
OpenAPI/Swagger document instead (often at `/openapi.json` or `/swagger.json`); `config/discovery.conf`'s
`har-path`/`openapi-path` keys do either one for every future run without re-passing the flag.

### 4. DAST against a live app - the recipe that actually lands injection findings

A bare passive scan of a target the crawler hasn't seen much of finds relatively little - most of a
real application's surface is API endpoints a static HTML crawl never reaches:

```sh
./scan.sh dast \
  --target dast-test-target --i-own-target dast-test-target \
  --intensity active \
  --openapi ./openapi.json \
  --requests-per-second 2 --jobs 2 \
  --format json,sarif,html,md,audit,agent \
  --out reports/dast-full
```

- `--intensity active` sends real attack payloads and **requires** `--i-own-target NAME` naming the
  same target.
- Import your real API surface with `--openapi`/`--har`/`--postman`/`--graphql-schema` so the scanner
  reaches real endpoints - a single-page app's own routes are close to invisible to a static crawl
  alone (see 3b above for the HAR walkthrough).
- The circuit breaker is a **safety feature**, not a bug: it stops the run if the target genuinely stops
  answering (10 transport-level failures/60s by default) - a *separate*, much higher counter
  (`--circuit-breaker-5xx-failures`, default 200) tracks an application that merely answers unmatched
  paths with `5xx`, so an idiosyncratic-but-healthy target no longer needs either raised as routine
  practice. Go gentler than the unaffirmed defaults on a small target instead
  (`--requests-per-second 2 --jobs 2` - both already under the 4/s ceiling, so neither needs
  `--i-own-target` on its own).
- Run one scan at a time against a target - concurrent scans multiply the effective request rate the
  target sees and can trip the breaker for reasons that have nothing to do with the target's health.

### 5. Everything in one run

```sh
./scan.sh all --path DIR --target NAME --i-own-target NAME --intensity active \
  --openapi ./openapi.json --requests-per-second 2 --jobs 2 \
  --format json,sarif,html,md,audit,agent --out reports/all
```

`all` runs every module whose inputs are configured - `--path` drives SAST/SCA/IaC, `--target` drives
DAST - and records a `coverage_reduction` for any module it skips, rather than dropping it silently.

**Gotcha: don't scan `data/` itself.** After step 1, `data/advisories.db` is a several-hundred-MB
binary file. If `--path` includes it - for example, running `./scan.sh all --path .` from inside a
checkout where you just built the database - `sast` will walk it like source, producing noise and a
very slow run for no security value. Point `--path` at real source, or exclude `data/`.

### 6. Guided (interactive) mode

```sh
./scan.sh all --guided                    # walks you through the choices and runs the composed command
./scan.sh dast --guided --print-command   # walk through the choices, but print the command instead of running it
```

At the languages prompt, press **Enter** to accept the bracketed default and scan every language;
typing the literal word `all` is rejected (only `py`, `js`, `go`, `java` are valid, singly or
comma-separated) and re-prompts.

Prefer clicking over typing? [`docs/build.html`](docs/build.html) is a static, offline command builder:
pick a surface, point it at a path or target, toggle options, and copy the exact command it composes -
nothing on that page runs anything. `./scan.sh <command> --guided --print-command` is its terminal
equivalent.

### 7. Vendor the engines, for extra depth

`--use-engines` (`sast`: semgrep + gitleaks; `iac`: trivy) does nothing until the named engine's binary
is actually on disk under `modules/<module>/adapters/<engine>/` - absent, `scan.sh` warns
("`--use-engines was given, but no adapter is vendored ... this run will use no engine checks at
all`") but does not error, and nothing is ever fetched at scan time. Every adapter fetches a **raw, single-file executable**
and `chmod +x`'s it - it never unpacks an archive - so the fiddly part is that gitleaks and trivy publish
`.tar.gz` archives only: download and verify the archive yourself, extract it, then point the adapter at
the extracted file with a `file://` URL.

**gitleaks** (~20MB, MIT-licensed):

```sh
GITLEAKS_VERSION=8.30.1   # current version + platform asset names: https://github.com/gitleaks/gitleaks/releases
PLATFORM=darwin_arm64     # or linux_x64, linux_arm64, darwin_x64, ...
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${PLATFORM}.tar.gz"
grep "${PLATFORM}.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"   # compare this line's hash...
shasum -a 256 "gitleaks_${GITLEAKS_VERSION}_${PLATFORM}.tar.gz"          # ...against this one, by eye, before continuing

mkdir -p gitleaks-extracted && tar -xzf "gitleaks_${GITLEAKS_VERSION}_${PLATFORM}.tar.gz" -C gitleaks-extracted gitleaks
chmod +x gitleaks-extracted/gitleaks
curl -fsSLo gitleaks-extracted/gitleaks.toml "https://raw.githubusercontent.com/gitleaks/gitleaks/v${GITLEAKS_VERSION}/config/gitleaks.toml"

export SCOURSH_GITLEAKS_VERSION=$GITLEAKS_VERSION
export SCOURSH_GITLEAKS_URL="file://$(pwd)/gitleaks-extracted/gitleaks"
export SCOURSH_GITLEAKS_SHA256=$(shasum -a 256 gitleaks-extracted/gitleaks | cut -d' ' -f1)
export SCOURSH_GITLEAKS_RULES_URL="file://$(pwd)/gitleaks-extracted/gitleaks.toml"
export SCOURSH_GITLEAKS_RULES_SHA256=$(shasum -a 256 gitleaks-extracted/gitleaks.toml | cut -d' ' -f1)
tools/vendor-engines.sh gitleaks
```

**trivy** (~155MB, Apache-2.0) - the identical shape, minus a separate ruleset (trivy's checks are
compiled into the binary):

```sh
TRIVY_VERSION=0.74.0   # current version + platform asset names: https://github.com/aquasecurity/trivy/releases
ASSET=trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz   # or Linux-64bit, Linux-ARM64, macOS-64bit, ...
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${ASSET}"
grep "$ASSET" "trivy_${TRIVY_VERSION}_checksums.txt"    # compare this hash...
shasum -a 256 "$ASSET"                                  # ...against this one, before continuing

mkdir -p trivy-extracted && tar -xzf "$ASSET" -C trivy-extracted trivy
chmod +x trivy-extracted/trivy

export SCOURSH_TRIVY_VERSION=$TRIVY_VERSION
export SCOURSH_TRIVY_URL="file://$(pwd)/trivy-extracted/trivy"
export SCOURSH_TRIVY_SHA256=$(shasum -a 256 trivy-extracted/trivy | cut -d' ' -f1)
tools/vendor-engines.sh trivy
```

Then turn each on:

```sh
./scan.sh sast --path DIR --use-engines   # adds gitleaks (semgrep too, once vendored - see below)
./scan.sh iac  --path DIR --use-engines   # adds trivy config
```

**Do not commit the vendored `bin/`/`rules/` directories to git** - `modules/*/adapters/*/bin/` and
`.../rules/` are gitignored by design; re-run the vendor step per machine (or per CI image) instead:

- trivy's binary is ~155MB - over **GitHub's 100MB hard limit**, so pushing it is not merely unwise, it
  is impossible.
- gitleaks' default `gitleaks.toml` and binary are small enough to push, but a ~20MB binary blob checked
  into git history forever is still worth avoiding on general principle.
- semgrep's default ruleset, if you ever obtain one, ships under "Semgrep Rules License v1.0", which
  explicitly forbids redistribution - committing it to this (Apache-2.0, public) repository would be a
  license violation, not just bloat.

**semgrep has no working recipe here, and that's a real gap, not an oversight.** Unlike gitleaks and
trivy, semgrep publishes **zero binary assets** on its GitHub releases - installation is pip/pipx or
Homebrew only. A Homebrew install's `bin/semgrep` is a ~220-byte Python wrapper
(`#!/opt/homebrew/Cellar/semgrep/<version>/libexec/bin/python`, importing
`semgrep.console_scripts.entrypoint`) that depends on an entire ~240MB, version-pinned
Cellar tree staying in place - not a single, relocatable, checksummable artifact the way the other two
adapters expect. Pointing `SCOURSH_SEMGREP_URL` at that wrapper technically satisfies the adapter's
"is it executable" check, but the byte-identity guarantee `tools/vendor-engines.sh` exists for doesn't
hold: the wrapper breaks the moment that Homebrew formula is upgraded or removed, and there is no
publisher-issued checksum for a `pip`/`brew` install to verify against in the first place. Skip vendoring
semgrep until upstream ships a real release binary, or accept that a `pip`/`brew` install is unpinned and
treat it accordingly.

### 8. CI gating, state, and other commands

```sh
./scan.sh sast --path DIR --fail-on high              # exit 1 if anything at/above high is found
./scan.sh sast --path DIR --fail-on high --fail-on-new    # ...but only for findings new since the last run
./scan.sh sast --path DIR --baseline config/baseline.json # suppress accepted-risk findings by fingerprint
./scan.sh diff --against reports/<prior-run>          # classify the latest run vs a named earlier one
./scan.sh report --from reports/<prior-run>           # regenerate report.md/html/sarif from a prior run's own findings, no rescan
./scan.sh cloud --live                                # AWS CSPM - 30 services, read-only, needs AWS credentials
```

`report --from DIR` needs `DIR` to hold `findings.jsonl`, a well-formed `run.json`, `findings.fields`,
*and* `meta/` - all four, so it can't regenerate an aborted run's report (an abort never writes
`findings.jsonl`). Verified working end to end (re-rendered `report.md` byte-identical to the original
run bar its SARIF timestamp).

Every normal `sast`/`sca`/`iac`/`dast`/`cloud`/`network`/`image` run already auto-classifies its own
findings against `state/latest.json` - each finding's `status` in that run's own `findings.jsonl` is
already `new`/`recurring`/`fixed`/`unknown`, with no extra command needed. **`diff --against` itself is
currently broken on this branch**: the classification it computes is correct (visible in
`meta/diff_present`/`meta/diff_absent` in its output directory), but the rendered `report.md`/`run.json`
counts always read 0/0/0/0 regardless - verified by reproducing it from a clean `state/` directory twice.
Until fixed, read the per-run `findings.jsonl` `status` field above instead of running `diff` standalone.

## Output & the audit report

`--format` takes a CSV of `json,sarif,html,md,audit,agent` (default `json,sarif,html,md,agent` -
naming `--format` explicitly replaces that default list rather than adding to it):

- `json` -> `findings.json`; `sarif` -> a complete, schema-validated `report.sarif` that drops into
  GitHub code scanning or any SARIF-aware viewer (it deliberately omits `security-severity` - see
  [`docs/USAGE.md`](docs/USAGE.md#sarif-output) for why); `html`/`md` -> `report.html`/`report.md`.
- `findings.jsonl` and `run.json` are written on **every** run regardless of `--format` - they are
  mandatory per-run records, not one of the six selectable formats.
- `agent` -> `agent-fix.json`, in the default list so a plain run writes it with **no flag required**:
  a compact, schema-projected findings file for a downstream AI fixing agent, with a deterministic fix
  scaffold where scoursh can derive one (an SCA version bump, an IaC one-line config fix, or a cloud
  CLI command explicitly labeled suggested/human-review/never-auto-run) and a coverage header so "did
  not check" can never read as "clean". Contract: [`docs/AGENT-FORMAT.md`](docs/AGENT-FORMAT.md).
- `audit` is the one remaining **opt-in** value: it writes `report-audit.html` **alongside**
  `report.html`, never in place of it. Where the ordinary report lists findings, the audit report
  lists every registered check and its fate - found / ran clean / skipped (with a reason) / not
  covered - so "we looked and found nothing" and "we never looked" are never the same line.

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
  out-of-scope connection is physically impossible rather than merely observed. macOS gets two routes to
  the same kind of guarantee: `tools/run-sandboxed.sh` (a kernel-enforced, unprivileged deny-all-network
  sandbox - narrower than the netns route table, since it can't scope to one target, but genuinely
  physically impossible for `sast`/`sca`/`iac`, which need no network at all), and running
  `tools/run-in-netns.sh` unmodified inside a Linux container, for full parity.

This is deliberately **egress-restricted, not air-gapped**: `dast` and `cloud --live` inherently have
to talk to *something*, since testing a running app or reading live AWS config is the entire point of
those two scans. What's actually guaranteed is narrower, and it's the part that
matters - scoursh itself has no back-channel, and it never decides on its own who to contact. See
`docs/FOUNDATION.md` tension 28 for the full correction and `docs/adr/0001-egress-model-correction.md`
for the dated decision record.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) - the full CLI, exit-code, and configuration reference.
- [`docs/CHECKS.md`](docs/CHECKS.md) - every built-in check, grouped by surface and by what data it needs.
- [`docs/build.html`](docs/build.html) - a static, offline command builder: pick a surface, toggle
  options, and copy the exact command it composes.
- [`docs/AGENT-FORMAT.md`](docs/AGENT-FORMAT.md) - the `--format agent` contract, for a downstream
  AI fixing agent reading `agent-fix.json`.
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

Seven surfaces are built and produce real findings today: **SAST**, **IaC**, **SCA** (once you've
built `data/advisories.db`), **DAST** (once you've authorized a target), **Network/host** (once
you've authorized a target), **Container image** (once you've pointed it at a `docker save` tarball
or OCI layout), and **Cloud/AWS CSPM** (once you've pointed it at an account with resolvable
credentials). Guided mode, persistent run state with a
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
- Module directories present: `modules/cloud/`, `modules/dast/`, `modules/iac/`, `modules/image/`, `modules/network/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

## License

Apache License 2.0 - see [`LICENSE`](LICENSE). Contributions welcome - see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how a PR flows and what it needs.
