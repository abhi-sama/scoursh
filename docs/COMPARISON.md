# scoursh vs. the open-source security scanners

*Also available as a standalone page: [`comparison.html`](comparison.html).*

scoursh is not a better Semgrep, a better ZAP, or a better Trivy - and this page will not pretend
otherwise. On raw depth in any single category, the specialist wins. This is a straight account of
what scoursh does, what it does not do, and the narrow set of situations where it is the right
choice anyway.

> Licence & maintenance data from the GitHub API, 2026-09-08 · scoursh measured at v0.1.0-dev

## Contents

- [The headline](#the-headline)
- [What scoursh actually is](#what-scoursh-actually-is)
- [Declared limits](#declared-limits)
- [SAST](#sast)
- [SCA — dependencies](#sca--dependencies)
- [IaC — infrastructure as code](#iac--infrastructure-as-code)
- [DAST — running applications](#dast--running-applications)
- [Secrets](#secrets)
- [Cloud / CSPM](#cloud--cspm)
- [Measured head-to-head](#measured-head-to-head)
- [When to choose what](#when-to-choose-what)
- [Notes & sources](#notes--sources)

## The headline

**The position:** One auditable bash tool that sweeps four surfaces in a single run, refuses to talk
to anything outside an operator-declared allowlist, and - uniquely among the tools surveyed - reports
what it **did not** check as a first-class, non-clean output state.

That third property is the one no mainstream competitor offers, and it is the reason to reach for
scoursh. Portability and single-tool convenience are pleasant; the coverage honesty is unusual. The
market leader states the gap in its own documentation:

> "For the secret/license scanner, the Trivy report contains only findings. Therefore, we can't say
> for sure whether Trivy scanned at least one file or simply didn't find any findings."
>
> — Trivy troubleshooting documentation

Removing exactly that ambiguity is scoursh's design centre. Every registered check lands in one of
four buckets: it **found a problem**, it **ran and came back clean**, it **was skipped with a reason
on record**, or it is **not covered** - registered but never run. The last bucket is never folded into
"clean".

## What scoursh actually is

| | |
|---|---|
| **293** | security checks across five surfaces |
| **5** | surfaces: SAST, SCA, IaC, DAST, Cloud/CSPM |
| **0** | runtime deps beyond bash + coreutils |
| **1** | network chokepoint, lint-enforced |
| **30** | AWS services covered by the read-only Cloud/CSPM checks |

| Surface | Status | What shipped | Checks |
|---|---|---|---|
| SAST | landed | 9 rule packs across 6 languages, plus git-history secret replay | 53 |
| SCA | needs setup | 6 ecosystems, 12 manifest formats — advisory DB is built by hand, offline | table lookup |
| IaC | landed | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | 36 |
| DAST | landed | Full engine: auth, crawl, passive, safe-active, injection, tier-5 | 92 |
| Cloud / AWS | landed | 30 services, read-only, multi-account (`--assume-role`), CIS/OWASP-mapped | 112 |

> **Cloud is read-only and needs your own account.** `scan.sh cloud --live` runs 112 checks across 30
> AWS services through `lib/awscli.sh`'s `aws_ro` chokepoint, which refuses any call that is not
> read-only. It needs resolvable AWS credentials (profile, env, or instance role) - there is no
> bundled or hosted account - and an access-denied, opted-out, or throttled service is recorded as a
> coverage reduction rather than a silent clean pass. The `posture/` phase (SSO/edge/session drift
> against an operator-declared baseline) has a config schema but no checks yet.

Also shipping, and relevant when comparing against a specialist toolchain:

- **SARIF 2.1.0** - a complete, schema-validated document, so findings drop into GitHub code scanning
  and any SARIF-aware viewer.
- **Persistent state and diff** - findings classify as `new` / `recurring` / `fixed` / `unknown`
  against the prior run, with baseline suppression and a real `--fail-on-new` CI carve-out.
- **Optional engine adapters** - semgrep and gitleaks for SAST, `trivy config` for IaC, all opt-in and
  vendored ahead of time. Nothing is fetched during a scan.
- **Guided mode** - a bare `scan.sh` walks you through composing a real command and can print the
  exact non-interactive equivalent.
- **Test rigour** - 81 suites and 6 linters; 47% of the codebase is tests.

## Declared limits

These are scoursh's own, published in its design document rather than discovered by a reviewer. The
project's stated principle is that *a scan that overstates coverage is worse than one that names its
blind spots*.

- **Data-flow analysis.** The native tier is pattern/linter-grade. True taint and cross-function
  analysis needs the optional vendored engines. This is the most important caveat on the page.
- **Client-rendered apps.** No JavaScript execution, so a single-page app's routes are invisible
  unless you supply an OpenAPI, HAR, Postman or GraphQL spec.
- **Advisory freshness.** SCA is only as current as your last offline refresh - a deliberate, dated
  snapshot, never real-time.
- **Business logic.** Authorization checks are detection-oriented; complete access-control
  correctness still needs human review.
- **Speed.** Every static scan is single-worker. Measured: 114 s for 52 files. Compiled-Go competitors
  do comparable work in seconds.
- **Not a pentest.** Automated regression and posture scanning that complements a manual assessment;
  it does not replace one.

## SAST

| Tool | Coverage | Licence | Footprint | Egress | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 53 checks, 6 languages, + secrets & git history | Apache-2.0 | bash ≥ 4.2, grep/rg, awk | None | Four-state partition | Honest coverage; one tool across surfaces |
| Semgrep CE | ~3,000 community rules, 30+ languages; single-file analysis only | LGPL-2.1 | Python + OCaml binary | Registry fetch unless offline | Findings only | Best free SAST depth; readable rule DSL |
| Bandit | Python only | Apache-2.0 | Python | None | Findings only | Deep Python idiom coverage |
| gosec | Go only | Apache-2.0 | Single Go binary | None | Findings only | Fast, zero-dep, Go-native AST |
| njsscan | JavaScript / Node only | LGPL-3.0 | Python + semgrep | None | Findings only | Node and Express specific patterns |
| CodeQL | Deep interprocedural taint, 10+ languages | CLI proprietary | Multi-GB engine + DB build | Yes | Findings only | Best-in-class dataflow, if you qualify |

> **Read the CodeQL licence carefully.** The query libraries are MIT, but the CLI engine that runs
> them is governed by the GitHub CodeQL Terms - not an OSI-approved licence. It forbids use *"in
> connection with any codebase that is not an Open Source Codebase (e.g., code in a private repo in
> GitHub)"* unless you hold GitHub Advanced Security. If you are scanning private code, CodeQL is not
> a free option.

**Honest verdict:** **Semgrep CE wins on depth and it is not close** - roughly 3,000 rules against
scoursh's 53, across 30+ languages against 6. Use Semgrep as your primary SAST engine.

scoursh's SAST earns its place two ways: it is the only tool here that also replays its secrets rules
across **git history** without a second tool, and it tells you which of its own checks never ran.
Note the fair symmetry - Semgrep CE is *also* single-file-only, so the taint-analysis gap scoursh
declares is one CE shares; the difference is that 53 patterns are a thinner net than 3,000. **Position
it as a baseline sweep and history scan, not your deep SAST engine.**

## SCA — dependencies

| Tool | Coverage | Licence | Footprint | Egress | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 6 ecosystems, 12 manifest formats | Apache-2.0 | bash + coreutils | **None at scan time** — DB built offline | **Exits 4 rather than reporting clean** | Refuses to imply coverage it does not have |
| Trivy | 20+ ecosystems, plus containers, IaC and secrets | Apache-2.0 | Single Go binary | Auto-fetches vuln DB | Findings only | Breadth: one binary covers most of the stack |
| Grype | Broad; pairs with Syft SBOMs | Apache-2.0 | Single Go binary | Auto-fetches grype-db | Findings only | Precise version matching, low false positives |
| OSV-Scanner | OSV.dev-backed, polyglot | Apache-2.0 | Single Go binary | Queries OSV.dev | Findings only | Highest reported accuracy, fewest false positives |
| Dependency-Check | Java-centric, CPE matching | Apache-2.0 | JVM + NVD feed | Downloads NVD | Findings only | Entrenched in Java, Maven and Jenkins shops |

> **One-time setup, and it is a real cost.** scoursh does not ship an advisory database - it is
> deliberately never bundled or auto-fetched. Until you build it once on a networked box, `scan.sh
> sca` matches nothing. It does not report "0 vulnerabilities" when that happens: it exits 4 and names
> every ecosystem it did not check.

**Honest verdict:** **For finding CVEs, use Trivy, Grype or OSV-Scanner.** They auto-fetch a
maintained database and work in one command. scoursh requires a deliberate, manual database build
first, which is genuine adoption friction.

What that cost buys is the thing the others cannot offer: a dated, auditable, offline snapshot that
never phones home at scan time, and a scanner that fails loudly rather than silently when the data is
missing. **In an air-gapped or egress-audited environment that trade is correct. Everywhere else,
Trivy is the better default.**

## IaC — infrastructure as code

| Tool | Coverage | Licence | Footprint | Status | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 36 checks across 6 formats | Apache-2.0 | bash + coreutils | active | Four-state partition | Auditable plain-text packs; cross-format isolation tested |
| Checkov | 1,000+ policies, graph-based cross-resource analysis | Apache-2.0 | Python | active | Findings + skip comments | Terraform depth; cross-resource graph |
| KICS | 2,400+ queries, 22+ platforms | Apache-2.0 | Go binary + query pack | active | Findings only | Widest raw format coverage |
| Trivy `config` | tfsec's full inherited check set | Apache-2.0 | Single Go binary | active | Findings only | One binary for IaC, SCA and containers |
| tfsec | Merged into Trivy; no new rules | MIT | Go binary | superseded | — | Do not adopt — use `trivy config` |
| Terrascan | ~500 Rego policies | Apache-2.0 | Go binary | archived 2025-11-20 | — | Do not adopt — repository is read-only |

> **Two of the usual four are gone.** tfsec is frozen and redirects to Trivy. Terrascan was archived
> read-only by Tenable on 2025-11-20. Both still run, but neither will see a new rule or a new
> provider version again.

**Honest verdict:** **KICS and Checkov are far deeper** - 2,400+ and 1,000+ policies against scoursh's
36 - and Trivy gives you tfsec's inherited catalogue in a binary you may already run for SCA. scoursh's
36 checks are a smoke test, not a policy engine, and should be described that way.

Its narrow genuine edge: the packs are plain-text pattern records a reviewer can audit in an
afternoon, cross-format contamination is pinned by tests in both directions, and it reports which
packs never fired. **A fast, dependency-free sanity pass, with Checkov or KICS as the real gate.**

## DAST — running applications

| Tool | Coverage | Licence | Footprint | Egress / consent | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 92 checks in 16 families; passive → safe-active → injection | Apache-2.0 | bash + curl | **Refuses any host not in scope.conf** | **Four-state + declared reductions** | Runtime-enforced consent and blast-radius model |
| ZAP (by Checkmarx) | Full proxy, spider, AJAX spider, active and passive scan | Apache-2.0 | JVM + browser for AJAX spider | Whatever you point it at | Scan policy lists enabled rules | Best-in-class free DAST; large add-on ecosystem |
| Nuclei | 12,000+ community templates | MIT | Single Go binary | Fetches template updates | Reports templates run | Fastest known-CVE template coverage |
| Nikto | Web-server misconfiguration and known files | GPLv3 | Perl | Direct | Findings only | Decades of server-misconfig knowledge |
| Wapiti | Black-box injection families | GPL-2.0 | Python | Direct | Findings only | Simple, focused black-box injection |

scoursh's DAST differs less in what it checks than in what it refuses to do. It will not contact a
host absent from `config/scope.conf`. It holds itself to 4 requests per second and 4 concurrent
connections unless you assert `--i-own-target` *naming the same target*. It ships an identifying
User-Agent with no switch to remove it, on the reasoning that an authorised scan has no need to be
unidentifiable. Side-effecting checks need `--allow-intrusive` as well, because the parties harmed by
those are the target's users, and owning a host does not confer permission to affect them.

**Honest verdict:** **ZAP is the reference free DAST and scoursh does not displace it.** No JavaScript
execution, no proxy, no AJAX spider - any single-page app is invisible to scoursh's crawler unless you
feed it a spec or HAR capture. Nuclei's 12,000 templates dwarf 92 checks for known-CVE coverage.

Where scoursh is genuinely differentiated is the consent model: no other tool here makes "am I allowed
to do this" a runtime-enforced question. **It is the DAST you can safely leave running in CI against
your own staging estate - not the one you hand a pentester.**

## Secrets

| Tool | Coverage | Licence | Footprint | Egress | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 7 secret checks + git-history replay | Apache-2.0 | bash + git | None | Four-state partition | Secrets masked in every output, by construction |
| Gitleaks | Broad regex and entropy ruleset | MIT | Single Go binary | None | Findings only | Fastest git-native scanning; simplest licence |
| TruffleHog | Large detector set + live credential verification | AGPL-3.0 | Single Go binary | **Verification calls providers by design** | Findings only | Turns "maybe" into a confirmed incident |
| detect-secrets | Plugin-based, baseline workflow | Apache-2.0 | Python | None | Baseline audit workflow | Mature baseline loop for brownfield repos |

**Honest verdict:** **Use Gitleaks or TruffleHog as your dedicated secret scanner.** Seven checks
against a full ruleset is not a contest, and scoursh has no live verification.

scoursh's value here is narrower and different: a secret finding *cannot leak the secret into the
report*. Redaction is enforced by provenance at the single point every finding passes through, not by
hoping a pattern list is complete - and the test suite asserts the property that the value appears in
no byte the run wrote. That matters precisely when the report is an artefact you hand to someone else.
**A safe-by-construction secondary net, not your primary secret scanner.**

## Cloud / CSPM

> **scoursh has a real, but narrower, cloud checker.** 112 read-only checks across 30 AWS services,
> CIS AWS Foundations Benchmark v3.0.0 and OWASP mapped, single cloud provider (AWS), single
> compliance framework. This is an honest comparison, not a claim of parity with the specialists.

| Tool | Coverage | Licence | Footprint | Notes |
|---|---|---|---|---|
| scoursh | 112 checks, 30 AWS services, 1 framework (CIS) | Apache-2.0 | bash + AWS CLI | Read-only enforced at a runtime chokepoint (`aws_ro`), not merely by lint; no bundled account, single-tool multi-surface report |
| Prowler | ~600 AWS checks, 84 services, 44 compliance frameworks | Apache-2.0 | Python + AWS credentials | Depth plus broad compliance mapping — the default choice for serious cloud posture work |
| ScoutSuite | Multi-cloud posture with an HTML report | GPL-2.0 | Python | Excellent visual report; last commit ~1 year old |
| CloudSploit | AWS, Azure, GCP, OCI and GitHub plugins | GPL-3.0 | Node.js | Broad plugin model, actively maintained |
| Steampipe / Powerpipe | SQL over cloud APIs + large benchmark library | AGPL-3.0 | Go + Postgres FDW | Powerful, but the CLI licence blocks some organisations |

**Honest verdict:** **Use Prowler for depth.** Prowler's ~600 checks across 84 services and 44
compliance frameworks outclasses scoursh's 112-check, CIS-only, AWS-only catalogue on every depth
metric that matters for a dedicated cloud posture audit. What scoursh adds is not depth, it's the same
property the rest of the tool has: read-only enforced at a runtime chokepoint rather than by
convention, one report alongside SAST/SCA/IaC/DAST findings with the same fingerprint and severity
scheme, and the same "unexamined is not clean" accounting - an access-denied or opted-out service is a
declared coverage reduction, not a false pass. Reach for scoursh's cloud check as part of the baseline
sweep everywhere; reach for Prowler when cloud posture is the job itself.

## Measured head-to-head

Real numbers, measured on one machine, each tool run against the same target with default-ish config.
Findings were judged against a known ground truth, not taken from any tool's own output.

> **Read this first.** Three of the four targets (SAST, IaC, secrets) are scoursh's own committed
> test fixtures - its rules were authored against those exact files, so a high score there measures
> "still passes its own cases," not "finds vulnerabilities it has never seen." The SCA target is the
> fair one: real packages at real historically-vulnerable versions. Treat the recall gaps,
> false-positive counts, runtime, and footprint as the load-bearing signals here - not scoursh's
> home-turf recall.

### SAST — 41 planted issues

| Tool | Recall | False positives | Runtime | Footprint |
|---|---|---|---|---|
| **scoursh** | 40/41 (97.6%) | 0 | 68 s | 0 (repo only) |
| Semgrep (security-audit + secrets + owasp) | 12/41 (29.3%) | 0 | 1.6 s | ~450 MB |
| Bandit (python subset) | 6/12 | 0 | 0.13 s | 17 MB |
| gosec (go subset) | 4/5 | 0 | <0.1 s | Go toolchain + cache |

### SCA — 12 real vulnerable dependencies (the fair test)

| Tool | Packages caught | Runtime | Local DB / egress |
|---|---|---|---|
| **scoursh** | 12/12 | 98 s | ~10 MB, no egress |
| Trivy fs | 12/12 | ~4 s | 1.3 GB DB |
| Grype | 12/12 | 0.5 s | 2.0 GB DB |
| OSV-Scanner | 12/12 + 2 transitive | 3.5 s | live query to api.osv.dev |

> **Package-level recall is a tie - and the earlier exact-version gap is now closed.** The benchmark
> first surfaced that scoursh matched advisories by exact version only, missing most range-based npm
> advisories. That has since been fixed: npm now uses semver-range matching (real-CVE recall 3.6% →
> 100%) while the vendored database actually shrank (it was over-storing duplicated data). scoursh
> reads only the literal lockfile, so it does not do OSV-Scanner's transitive resolution - a real
> depth advantage for that tool.

### IaC — 44 planted misconfigurations

| Tool | Defects matched | Runtime | Notable |
|---|---|---|---|
| **scoursh** | 43/44 | 74 s | — |
| Trivy config | 150 checks, 26/36 files covered | ~3 s | zero findings on docker-compose or Helm files |
| Checkov | 157 checks, 27/36 files covered | 2.8 s | same Helm/compose blind spot |

### Secrets — 56 planted, 34 negative controls

| Tool | Recall | False positives | Runtime | Note |
|---|---|---|---|---|
| **scoursh** | 53/56 (94.6%) | 0/34 | 76 s | — |
| Gitleaks | 19/56 (33.9%) | 0/34 | 0.054 s | strong on API-key/token family, near-blind on generic "password" |
| TruffleHog | 1/56 (1.8%) | 0/34 | 0.66 s | built for verifiable service credentials, not generic literals |

> **The honest read.** On these targets scoursh had the higher recall with zero false positives and
> no vendored gigabytes - but it is **40-1000× slower** (a shell engine's per-check cost), and the
> SAST/IaC/secrets recall is measured partly on its own fixtures. DAST was attempted against a live
> OWASP Juice Shop: scoursh confirmed the login SQL-injection end-to-end, while the competitor run
> (ZAP crashed twice; Nikto/Nuclei/Wapiti did not finish in the session window) did not produce a
> clean comparison, so no DAST numbers are published here rather than invent them.

## When to choose what

**Choose scoursh when…**

- **You are air-gapped or egress-audited.** SAST, SCA and IaC make zero network calls; DAST talks
  only to hosts you declared, and cloud talks only to your own AWS account through a read-only
  chokepoint.
- **"Did it actually check?" must be answerable.** Compliance evidence, an auditor, a post-incident
  review.
- **You cannot install a toolchain.** No JVM, Python, Node, Go, Docker or build step.
- **You want one report across five surfaces** with one fingerprint scheme, severity rubric and diff
  model.
- **You need a CI gate with a real new-findings carve-out**, fail-closed when the diff is unusable.
- **Auditability is the requirement.** It is shell - a reviewer can read the rule that fired.

**Choose a specialist when…**

- **Deep SAST across many languages** → Semgrep CE
- **Interprocedural taint analysis** → CodeQL, licence permitting
- **Authoritative CVE detection** → Trivy, Grype or OSV-Scanner
- **Serious IaC policy enforcement** → Checkov or KICS
- **Real web-app testing or SPA coverage** → ZAP
- **Latest-CVE web templates** → Nuclei
- **Primary secret scanning or verification** → Gitleaks or TruffleHog
- **Deep, multi-cloud, multi-framework cloud posture work** → Prowler (scoursh's cloud checker is
  AWS-only, CIS-only, and single-account by default)

**In one sentence:** scoursh is the baseline sweep you run everywhere, including the places the good
tools cannot go - and the one that tells you what it missed. It is not a replacement for the good
tools.

## Notes & sources

> **This is not a detection benchmark.** No number here claims scoursh finds more or fewer real
> defects than any other tool. Nothing was run over a shared corpus and counted. This is a capability
> and positioning comparison.

scoursh figures were measured directly against the source tree at version 0.1.0-dev: check counts by
parsing the shipped rule packs, output formats and exit codes by running real scans, and the egress
chokepoint by running the project's own lint. Competitor licence, archive status and last-commit dates
come from the GitHub API, queried 2026-09-08. Rule and policy counts for competitors are as published
by their vendors or reported by the community; they were not independently recounted, and are labelled
throughout as approximate.

Licences shown are those governing the free, self-hosted tool. Several carry conditions worth checking
before adoption: **CodeQL**'s CLI is proprietary and restricted to open-source codebases;
**TruffleHog** and **Steampipe/Powerpipe** are AGPL-3.0; **ScoutSuite**, **CloudSploit**, **Nikto** and
**Wapiti** are GPL family. ZAP moved from OWASP to independent governance with Checkmarx backing in
September 2024 and remains Apache-2.0.

---

Prepared as an internal positioning document for the scoursh open-source launch. Every claim about
scoursh is traceable to a command or a source file in the repository; every claim about another tool
is traceable to that project's own repository or documentation.
