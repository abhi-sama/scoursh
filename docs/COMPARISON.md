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
- [Network / host](#network--host)
- [Secrets](#secrets)
- [Cloud / CSPM](#cloud--cspm)
- [Benchmark status](#benchmark-status)
- [When to choose what](#when-to-choose-what)
- [Notes & sources](#notes--sources)

## The headline

**The position:** One auditable bash tool that sweeps six surfaces in a single run, refuses to talk
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
| **308** | security checks across six surfaces |
| **6** | surfaces: SAST, SCA, IaC, DAST, Network/host, Cloud/CSPM |
| **0** | runtime deps beyond bash + coreutils |
| **1** | network chokepoint, lint-enforced |
| **30** | AWS services covered by the read-only Cloud/CSPM checks |

| Surface | Status | What shipped | Checks |
|---|---|---|---|
| SAST | landed | 9 rule packs across 6 languages, plus git-history secret replay | 53 |
| SCA | needs setup | 6 ecosystems, 12 manifest formats — advisory DB is built by hand, offline | table lookup |
| IaC | landed | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose | 36 |
| DAST | landed | Full engine: auth, crawl, passive, safe-active, injection, tier-5 | 92 |
| Network / host | landed | Declared-listener reachability, banner/TLS/HTTP identification, transport posture — never a port sweep | 15 |
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
- **Speed.** Measured: 114 s for 52 files at the default single worker. `--jobs N` now gives real
  multi-worker fan-out for `sast`/`sca`/`iac` (byte-identical findings regardless of width), but each
  worker is still a shell pattern engine, not a compiled parser - compiled-Go competitors do
  comparable per-file work in a fraction of the time.
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

## Network / host

| Tool | Coverage | Licence | Footprint | Egress / consent | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 15 checks: three-state reachability, banner/TLS/HTTP service+version identification, transport posture, over a DECLARED listener set | Apache-2.0 | bash, TCP connect only (no `nmap` dependency) | **Refuses any host:port not in scope.conf; never probes a port the operator did not declare** | **Three-state (open/not-open/filtered) + declared reductions** | Same runtime-enforced consent and ceiling model as DAST, applied to raw TCP |
| Nmap | Full port/service/OS discovery across an address range, hundreds of NSE scripts | Nmap Public Source Licence | C, no deps | Whatever you point it at | Findings only | The reference port scanner and host-discovery tool |
| testssl.sh | Deep TLS/SSL protocol, cipher and vulnerability assessment | GPLv2 | bash + openssl | Direct | Findings only | Far deeper single-purpose TLS auditor than any generalist |

scoursh's network module is deliberately **not a port scanner**. It verifies the reachability, service
identity, and transport posture of a listener set the operator already declared in
`config/scope.conf` (`base-url`/`extra-host` entries) - it never discovers a port the operator did not
name, gated by the identical `lib/http.sh` scope chokepoint and ceilings the DAST engine uses. There is
no `nmap` dependency: the TCP-state classification is pure bash, capability-probed and
deadline-bounded. An `nmap` adapter is filed (`docs/ADAPTERS.md`'s convention) but not yet built.
Two capabilities a network scanner conventionally claims are stated v1 exclusions rather than
oversights: OS patch-level inference (a backported distribution security fix leaves the banner's
version string unchanged, so version-string matching against a live host is structurally unreliable)
and UDP (no connect handshake, so "open" and "filtered" are indistinguishable without a
protocol-specific payload per service).

**Honest verdict:** **Use Nmap for port/host discovery and testssl.sh for a deep TLS audit.** scoursh's
6 `NET-TLS-*` checks are a posture summary, not a protocol-level cipher-suite audit, and it will never
tell you what else is listening on a host beyond what you already declared. What it adds is the same
property the rest of the tool has: a listener you told it about gets checked with the identical
consent-and-ceiling discipline as an authorized web target, in the same report as your code, dependency,
IaC, and cloud findings, with "not open"/"filtered"/"not tested" kept as distinct, honestly-reported
states rather than folded into a clean pass.

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

## Benchmark status

**The recall numbers that used to live in this section are retracted.** An earlier version of this
page published a "Measured head-to-head" table claiming, among other things, scoursh 40/41 (97.6%)
recall against Semgrep's 12/41 (29.3%) on a 41-issue SAST target. That target, like the IaC and
secrets targets in the same table, was scoursh's own committed test fixtures under `tests/fixtures/` -
files its own rules were authored against, which measures "still passes its own cases," not "finds
vulnerabilities it has never seen." No harness, corpus manifest, or scoring script for any of those
numbers ever shipped in this repository, so a reader could not have reproduced them. The whole section
is removed rather than re-caveated: a caveat is prose, and the table underneath it is what gets
screenshotted.

### Scope first, then score

Read the per-surface tables above before any recall number, on this page or a future one. A
checks-shipped gap predicts a recall gap; the recall gap should never be the first thing a reader sees.

- **SAST:** scoursh ships 53 checks across 6 languages; Semgrep CE ships roughly 3,000 across 30+.
- **IaC:** scoursh ships 36 checks across 6 formats; Checkov ships 1,000+, KICS 2,400+.
- **Secrets:** scoursh ships 7 dedicated secret checks against Gitleaks' and TruffleHog's broad,
  purpose-built rulesets.

A roughly 50-to-1 rule-count gap does not require a benchmark to predict a specialist win on recall. A
same-corpus comparison should confirm that gap, not report it as news.

### Why the old number was thrown away: a 192-case pilot that inverts it

We ran a real pilot to find out how much of the old SAST number was fixture bias. It was worth the
entire result.

**Setup.** A stratified 192-case sample (96 real vulnerabilities / 96 sanitized traps; 12 of each
across 8 CWE categories: `sqli cmdi ldapi pathtraver crypto hash weakrand xss`) drawn from
`OWASP-Benchmark/BenchmarkJava` (`master`, GPL-2.0, last pushed 2026-09-08) - a corpus scoursh has
never seen and did not author. Tools: scoursh `0.1.0-dev` @ `6787df3` (native tier, all defaults, no
`--use-engines`) against Semgrep CE `1.176.0` (`--config p/security-audit --config p/owasp-top-ten`).
Scored two ways - loose (any finding in the file) and strict (the finding's CWE in the case's
ground-truth equivalence class) - and both scorings agreed.

| SAST recall, same two tools | On scoursh's own fixtures (the old, retracted number) | On the neutral 192-case pilot |
|---|---|---|
| scoursh | 40/41 = 97.6% | **14/96 = 14.6%** (Youden J −0.031, below a coin flip) |
| Semgrep CE | 12/41 = 29.3% | **82/96 = 85.4%** (Youden J +0.583) |

Same two tools, same task shape, opposite ranking. That is not "the old number was a little
optimistic" - it is direct evidence that the old number measured "still passes its own test files,"
not "finds vulnerabilities it has never seen." We are publishing the inversion in place of the number
it replaced, because a benchmark that only shows results favourable to the project running it is not a
benchmark.

This is a **192-case pilot on one language (Java)**, not the finished benchmark - too small and too
narrow to be a final verdict. Treat it as what it is: the evidence for why the old table is gone, and
a preview of the real benchmark below.

Per-category results in the pilot were not uniformly bad: scoursh matched or beat Semgrep on `ldapi`
(12/12 vs 11/12), a pattern-shaped check, while losing heavily on the taint-shaped categories -
`sqli`, `cmdi`, `pathtraver` - where it found none of the 12 real cases in each. That split lines up
with a limitation the project already states, not a fresh one:

> **Declared, not discovered.** [`docs/DESIGN.md` §15](DESIGN.md) states plainly: *"native tier is
> pattern/linter-grade; true taint/cross-function analysis needs the optional vendored engines."* A
> pilot showing scoursh losing on taint-shaped injection categories confirms that declared limitation
> under measurement. It is a consistency result, not a surprise.

### Where scoursh's real wins are

None of the above is a case for parity on detection depth - see the per-surface "Honest verdict"
call-outs above for that. scoursh's genuine advantages are structural, hold regardless of which
detection benchmark eventually lands, and are drawn from the same per-surface tables above rather than
a new measurement:

| Property | scoursh | Typical specialist |
|---|---|---|
| Coverage honesty | Four-state partition (found / clean / skipped-with-reason / not covered) | Findings only - a clean run and an unrun check both look "clean" |
| Egress | Zero network calls for SAST/SCA/IaC; DAST/network/cloud refuse any destination outside an operator allowlist, provable live under `--paranoid` | Registry/database fetch, template updates, or live verification calls, per tool |
| Advisory DB footprint | ~10 MB, hand-built offline | 1.3-2.0 GB, auto-fetched (Trivy, Grype) |
| Runtime dependencies | bash + coreutils | JVM, Python, Node, Go toolchain, or a multi-GB engine, per tool |

### What is next

A real, neutral-corpus benchmark - pinned corpora with a commit/digest manifest, a published scorer,
every tool's raw output kept, and explicit per-category "not covered" cells rather than a forced
overall score - is in progress as a separate effort and will replace this section when it lands.
Until then, this page makes no detection-recall claim beyond the 192-case pilot above, which is
labelled and scoped as exactly that.

## When to choose what

**Choose scoursh when…**

- **You are air-gapped or egress-audited.** SAST, SCA and IaC make zero network calls; DAST and
  network talk only to hosts (and, for network, ports) you declared, and cloud talks only to your own
  AWS account through a read-only chokepoint.
- **"Did it actually check?" must be answerable.** Compliance evidence, an auditor, a post-incident
  review.
- **You cannot install a toolchain.** No JVM, Python, Node, Go, Docker or build step.
- **You want one report across six surfaces** with one fingerprint scheme, severity rubric and diff
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
- **Port/host discovery** → Nmap (scoursh only verifies a listener set you already declared)
- **Deep TLS/SSL protocol auditing** → testssl.sh
- **Primary secret scanning or verification** → Gitleaks or TruffleHog
- **Deep, multi-cloud, multi-framework cloud posture work** → Prowler (scoursh's cloud checker is
  AWS-only, CIS-only, and single-account by default)

**In one sentence:** scoursh is the baseline sweep you run everywhere, including the places the good
tools cannot go - and the one that tells you what it missed. It is not a replacement for the good
tools.

## Notes & sources

> **This page is a capability and positioning comparison, not a finished detection benchmark.** The
> one exception is the 192-case SAST pilot in [Benchmark status](#benchmark-status), which really was
> run over a shared, neutral corpus and scored against ground truth - it is disclosed there with its
> corpus, tool versions, and scope, precisely because it is the one number on this page that makes
> that claim. Every other row on this page - check counts, licences, footprints - is drawn from each
> project's own published data, not a shared run.

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
