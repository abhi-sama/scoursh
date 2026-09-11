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
- [Container image](#container-image)
- [Secrets](#secrets)
- [Cloud / CSPM](#cloud--cspm)
- [Benchmark status](#benchmark-status)
- [When to choose what](#when-to-choose-what)
- [Notes & sources](#notes--sources)

## The headline

**The position:** One auditable bash tool that sweeps seven surfaces in a single run, refuses to talk
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
| **319** | security checks across seven surfaces |
| **7** | surfaces: SAST, SCA, IaC, DAST, Network/host, Container image, Cloud/CSPM |
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
| Container image | landed | Offline apk/dpkg/rpm package + language-dep CVE matching against a `docker save` tarball or OCI layout — never a registry pull | 11 |
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
- **Container images.** Only the bounded, declared metadata paths a package-manager database and a
  handful of conventional language-manifest locations occupy are ever read - never a full rootfs
  materialisation, and never a running container or its runtime behaviour. rpm needs `sqlite3` on
  `PATH`, or matching is a declared coverage reduction rather than a silent clean pass.
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

## Container image

| Tool | Coverage | Licence | Footprint | Egress / consent | Coverage honesty | Unique strength |
|---|---|---|---|---|---|---|
| **scoursh** | 11 checks: installed apk/dpkg/rpm package CVEs, in-image language-dependency CVEs (npm/RubyGems/Composer/PyPI/Maven/Go), plus config-blob checks (effective runtime user, exposed ports, mutable base-image reference) | Apache-2.0 | bash + `tar` (rpm also needs `sqlite3` on `PATH`) | **Reads only an operator-supplied `docker save` tarball or OCI layout - never a registry pull, no daemon socket** | **Found / ran-clean / declared-skip (no advisory DB, no recognised package database, unreadable layer) kept as distinct states** | Correlates a built-artifact finding with the Dockerfile source finding for the same image (`rules/derived.rules`) |
| Trivy | Full image, filesystem, and repo scanning across OS packages, language deps, IaC misconfig, secrets, and SBOM export, plus registry/daemon pulls | Apache-2.0 | Go binary, self-contained | Pulls from a registry or local daemon directly | Findings only | The reference image scanner - broadest ecosystem and distro coverage, actively maintained vulnerability DB |
| Grype | OS package and language-dependency CVEs via Anchore's own feed, SBOM-driven | Apache-2.0 | Go binary, self-contained | Pulls from a registry or local daemon directly | Findings only | Fast, SBOM-native (pairs with Syft), strong feed-freshness tooling |

scoursh's image module is **not designed to reach a registry or a running container runtime at
all** - `lib/http.sh` refuses any host absent from `config/scope.conf` and there is no third egress
channel, so an image is supplied as a file, offline, the identical
model `data/advisories.db` already lives in for SCA. Trivy and Grype both pull directly from a
registry or a local daemon by design, which is real convenience scoursh's egress model does not
permit itself. What scoursh adds instead is the property the rest of the tool has: the same finding
lands in one report alongside this image's own source-code, dependency, IaC, and (if scanned) cloud
findings, with an absent advisory database or an unrecognised package database (a distroless/scratch
image, or an rpm database with no `sqlite3` on `PATH`) reported as a declared reduction rather than
folded into a silent clean pass. It is also the **built-artifact** counterpart to `iac`'s own
Dockerfile *source* linting rather than a replacement for it - see `docs/CHECKS.md`'s "Container
image" section and `docs/DESIGN.md` §15 for the boundary, including what neither scoursh feature
alone can see (a base image's own packages, drift between a digest-pinned Dockerfile and a
months-old build).

**Honest verdict:** **Use Trivy or Grype when you need registry-pull convenience, the broadest
distro/ecosystem coverage, or SBOM export** - both have years of dedicated feed maintenance behind
them that this module does not attempt to match. What scoursh adds is coverage in an egress-restricted
or air-gapped setting where pulling from a registry or daemon is off the table, and the same
found/ran-clean/declared-skip honesty discipline the rest of the tool applies, now extended to what
actually shipped inside an image rather than only to what a Dockerfile says it should contain. No
detection-rate comparison against Trivy or Grype is published here, for the identical reason given
under ["Benchmark status"](#benchmark-status): scoursh does not currently have a neutral, versioned
corpus for container-image findings, and a number computed only on this project's own fixtures would
repeat the exact mistake that section documents.

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

### Scope first, then score

Read the per-surface tables above before any recall number, on this page or a future one. A
checks-shipped gap predicts a recall gap; the recall gap should never be the first thing a reader sees.

- **SAST:** scoursh ships 53 checks across 6 languages; Semgrep CE ships roughly 3,000 across 30+.
- **IaC:** scoursh ships 36 checks across 6 formats; Checkov ships 1,000+, KICS 2,400+.
- **Secrets:** scoursh ships 7 dedicated secret checks against Gitleaks' and TruffleHog's broad,
  purpose-built rulesets.
- **Container image:** scoursh ships 11 checks across three package managers (apk/dpkg/rpm) plus six
  language ecosystems; Trivy and Grype each track a broader distro and vulnerability-feed surface,
  refreshed continuously against a registry rather than an offline, hand-refreshed database.

A roughly 50-to-1 rule-count gap does not require a benchmark to predict a specialist win on recall. A
same-corpus comparison should confirm that gap, not report it as news.

### The real benchmark: seven legs landed, all reproducible from `bench/`

`bench/` is a harness, a pinned corpus manifest, a scorer, and per-category results with raw tool
output committed alongside - see [`bench/README.md`](../bench/README.md) for what it is and the rules
every result below is held to, including why a tool's own recall on a corpus it authored its own rules
against is not published here. Seven of its legs have landed: **SAST** (the full 2,740-case OWASP
Benchmark corpus, not a sample), **SCA** (26 pinned npm/PyPI/Go lockfile cases against real OSV.dev
advisories), **IaC** (two hand-labelled corpora - TerraGoat/AWS and kubernetes-goat), **secrets**
(leaky-repo, 82 hand-labelled cases), **DAST** (a 20-case hand-labelled corpus against a local,
operator-owned OWASP Juice Shop container, scoursh vs OWASP ZAP), and **honesty + egress** (a
coverage-honesty audit over every run below, plus a kernel-enforced zero-egress proof).
Every number in the tables below traces to a committed `bench/results/<leg>/` directory carrying
the tool's raw output, its normalised records, a `MANIFEST` with exact version and corpus commit, and
the rendered scorecard - re-run any of it with the commands in that leg's own `README.md`.

**No number below is measured on `tests/fixtures/`, no single score spans categories, and every ratio
carries its tool version and corpus commit** - the three rules [`bench/README.md`](../bench/README.md)
exists to enforce.

**Cloud and network are out of scope for this benchmark entirely** - no neutral cloud-posture
corpus/account and no head-to-head with Nmap that would not be comparing discovery against a
declared-listener check, per the same scoping logic ["Network / host"](#network--host) already states
on this page.

#### Table 1 — where the specialists win, by how much

Scope first: a checks-shipped gap this large predicts a recall gap before any corpus is run.

| Category | scoursh scope | Best specialist scope | scoursh Youden J | Best specialist Youden J | Corpus |
|---|---|---|---|---|---|
| SAST — taint-shaped defects | 8 relevant checks (of 53 shipped) | Semgrep CE: ~3,000 rules shipped | **-0.005** all findings / **-0.027** high+critical | Semgrep (max ruleset) **+0.492** / **+0.017**; Semgrep (`p/default`) +0.479 / +0.010 | OWASP Benchmark, full 2,740 cases |
| IaC — Terraform | 7 checks (4 fired) | Trivy `config`: 49 rule ids fired (several hundred shipped) | **+0.038** | Trivy **+0.611**; KICS +0.496; Checkov +0.495 | TerraGoat/AWS, 71 hand-labelled resources |
| IaC — Kubernetes | 8 checks (6 fired) | Trivy `config`: 30 rule ids fired (several hundred shipped) | **+0.737** (2nd of 4) | Trivy **+0.842**; Checkov +0.447; KICS +0.438 | kubernetes-goat, 35 hand-labelled documents |

`J = 0.000` is a coin flip. On the full-corpus SAST leg, Semgrep's advantage narrows sharply at
high+critical severity alone (its taint findings are mostly `WARNING`/medium in this corpus) but the
ranking never flips - scoursh stays at or below a coin flip in both severity columns. On Kubernetes,
scoursh places second of four on J with **zero false positives**, but that is narrowness reading as
precision, not comprehensiveness: Checkov and KICS each find more of the genuinely misconfigured
documents (18/19 and 19/19 against scoursh's 14/19). Full per-category breakdowns, the false-positive
diagnoses (a commented-out Terraform attribute, a CIDR split across a continuation line), and the
borderline-label sensitivity tables are in each leg's own `README.md`.

Secrets follows the identical scope pattern - 7 dedicated checks against Gitleaks' and TruffleHog's
broad, purpose-built rulesets - but the one corpus benchmarked here does not confirm a recall gap in
that direction. That result is real and is reported in Table 2, with the corpus-dependency caveat that
makes it non-generalisable stated in full there.

#### Table 2 — where scoursh wins, by how much

| Property | scoursh | Best/typical competitor | Source |
|---|---|---|---|
| Coverage honesty | 31/31 runs, 100% of unrun-but-selected checks declared with a reason, zero undeclared gaps | Structural non-comparison - none of the 8 competitor tools measured across every leg below emit an equivalent "loaded N, ran M, here is why not the rest" record | [`b8-honesty-egress`](../bench/results/b8-honesty-egress/README.md) §1 |
| Zero-egress, kernel-enforced | `sast`/`sca`/`iac` completed with exit 0, full report written, wrapped in a macOS Seatbelt profile denying every network syscall in the process tree; `--paranoid`'s detector independently observed zero out-of-allowlist connections on the same runs | Not attempted for any competitor - none can complete its normal workflow (registry pull, DB refresh, live verification) inside a deny-all-network sandbox | [`b8-honesty-egress`](../bench/results/b8-honesty-egress/README.md) §2 |
| Installed footprint | ~5.2 MB, zero runtime dependency beyond bash + coreutils + grep/rg | 15 MB (Gitleaks) to 241 MB (Semgrep) - each its own separately installed, versioned binary or Python venv | [`b8-honesty-egress`](../bench/results/b8-honesty-egress/README.md) §3 |
| SCA DB size before first finding | 86 MB local (npm+PyPI+Go, 3 of 6 ecosystems), zero egress at scan time | Trivy 1.3 GB (auto-refreshed); Grype 2.0 GB (auto-refreshed); OSV-Scanner 0 bytes local but one live query to `api.osv.dev` on every run | [`sca-lockfiles-26`](../bench/results/sca-lockfiles-26/README.md) §3 |
| Secrets recall, measured corpus | 33/65 planted credentials (50.8%), **zero false positives**, J **+0.508** | Gitleaks 21/65 (32.3%), J +0.323; TruffleHog 9/65 (13.8%), J +0.079 | [`b6-secrets-leaky-repo`](../bench/results/b6-secrets-leaky-repo/README.md) |

**The secrets row is real and it is not general evidence that scoursh out-detects Gitleaks or
TruffleHog.** leaky-repo, the one corpus measured, is dominated by generic keyword-shaped credentials
(`password =`, `API_KEY=`, and similar) in configuration files - exactly the shape
`modules/sast/rules/secrets.rules` was widened to catch. The six cases a specialist finds and scoursh
misses are the mirror image: provider-shaped or encoded credentials (a base64 Docker-registry blob, an
npm `_authToken`, a MongoDB URI's userinfo) that scoursh has no detector for. And 26 of the corpus's 65
planted credentials - `.netrc`, `.pgpass`, `.htpasswd`, positional call arguments, a bare-file secret
with no keyword at all - were found by **none** of the three tools. A corpus weighted toward
provider-issued tokens, which is what a scan of real GitHub repositories mostly produces, would move
this ranking; this leg cannot say by how much. The defensible sentence, from the leg's own `README.md`:
*on a corpus of the credential-bearing config files that leak by accident, scoursh's generic-assignment
rules found half the planted secrets with no false positives, where Gitleaks found a third and
TruffleHog a seventh; on provider-specific token shapes the ordering reverses.*

The SCA leg (`sca-lockfiles-26`) also confirms the scout report's parity prediction for two of three
ecosystems it covers: scoursh matches Grype/OSV-Scanner/Trivy at 100% strict-identity recall on npm (6/6)
and PyPI (4/4), with zero false positives across all 26 cases in every category. It misses all 3 Go
cases (aggregate recall 10/13, J +0.769 against the other three's +1.000 each) - two are a stated,
self-reported gap in the offline advisory importer (semver-range-only advisories, no exact version to
match), the third a real, narrowly-scoped `go.mod` version-prefix bug in `modules/sca/go_engine.sh`,
filed as its own follow-up rather than folded into this measurement. See that leg's `README.md` §7 for
the full account of both.

#### Table 3 — DAST (B7): a narrow, SPA-constrained comparison

Juice Shop is a client-rendered Angular SPA. Neither tool executes JavaScript
in this run - ZAP's AJAX spider, built specifically for this case, could not
be measured in this environment at all (below) - so both tools see the same
small, mostly-static surface, and this corpus's own ground truth had to
hand-enumerate the REST endpoints neither crawl actually discovered. Read the
scope cell before the score: this is one 20-case corpus against one target,
not a general DAST detection claim in either direction.

| Matching | scoursh-dast Youden J | ZAP Youden J | Corpus |
|---|---|---|---|
| Loose CWE | **+0.047** | +0.024 | Juice Shop, 20 hand-labelled cases (cors, missing-csp, sqli, info-disclosure) |
| Strict CWE | **+0.214** | +0.000 | same |

`J = 0.000` is a coin flip; both tools score low in absolute terms on this
small corpus. The strict/loose gap for ZAP is a CWE-taxonomy disagreement,
not a detection difference: ZAP's own CORS and CSP checks fire on the
identical endpoints scoursh's do, but classify them under `CWE-264`/`CWE-693`
where scoursh uses `CWE-942`/`CWE-1021` - both are defensible, differently
specific readings of the same misconfiguration. **Neither tool caught the
one hand-verified real vulnerability** in this corpus: Juice Shop's own
documented admin-login SQL-injection bypass, a comment-injection auth bypass
that neither tool's automated SQLi technique is built to notice from a single
crafted request with no baseline to diff against. Full account, including
why ZAP's active scan needed five attempts in this environment (never the
memory-only cause a prior DAST attempt diagnosed) and exactly what this
corpus does and does not show:
[`bench/results/b7-dast-juiceshop/README.md`](../bench/results/b7-dast-juiceshop/README.md).

#### Not yet measured

| Leg | Status | Why |
|---|---|---|
| Cloud / CSPM | **Out of scope for this benchmark** | No AWS account available to the benchmark, and no neutral, versioned cloud-posture corpus identified. |
| Network / host | **Out of scope for this benchmark** | scoursh verifies a declared listener set; a fair competitor comparison would need a discovery-vs-verification distinction this benchmark's scorer does not model - see ["Network / host"](#network--host) above. |

### Reproducing every number above

Nothing above is asserted without the artefact that produced it. The harness, the pinned corpus
manifest, every tool's raw output, and the scorer are all committed:

- [`bench/README.md`](../bench/README.md) - the harness itself: what it is, what it refuses to publish, and the four rules every result above is held to.
- [`bench/corpus.lock`](../bench/corpus.lock) / [`bench/sca-advisories.lock`](../bench/sca-advisories.lock) - every corpus pinned by full commit hash (or, for the SCA leg's live OSV.dev advisories, a timestamped resolution) with its licence.
- [`bench/results/b4-sast-owasp-full/`](../bench/results/b4-sast-owasp-full/README.md) - the SAST leg.
- [`bench/results/sca-lockfiles-26/`](../bench/results/sca-lockfiles-26/README.md) - the SCA leg.
- [`bench/results/b6-iac-terragoat-aws/`](../bench/results/b6-iac-terragoat-aws/README.md) and [`bench/results/b6-iac-kubernetes-goat/`](../bench/results/b6-iac-kubernetes-goat/README.md) - the two IaC legs.
- [`bench/results/b6-secrets-leaky-repo/`](../bench/results/b6-secrets-leaky-repo/README.md) - the secrets leg.
- [`bench/results/b7-dast-juiceshop/`](../bench/results/b7-dast-juiceshop/README.md) - the DAST leg.
- [`bench/results/b8-honesty-egress/`](../bench/results/b8-honesty-egress/README.md) - the coverage-honesty metric and the egress proofs.

## When to choose what

**Choose scoursh when…**

- **You are air-gapped or egress-audited.** SAST, SCA, IaC, and container-image scanning make zero
  network calls (an image is a local file, never a registry pull); DAST and network talk only to
  hosts (and, for network, ports) you declared, and cloud talks only to your own AWS account through
  a read-only chokepoint.
- **"Did it actually check?" must be answerable.** Compliance evidence, an auditor, a post-incident
  review.
- **You cannot install a toolchain.** No JVM, Python, Node, Go, Docker or build step.
- **You want one report across seven surfaces** with one fingerprint scheme, severity rubric and diff
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

> **This page is a capability and positioning comparison, with one section that is a real benchmark.**
> [Benchmark status](#benchmark-status) carries the seven landed
> `bench/` legs (SAST, SCA, IaC ×2, secrets, DAST, honesty/egress) - every number there was run over a
> shared, neutral, pinned corpus and scored against committed ground truth, with the harness, raw tool
> output, and scorer all reproducible from the repository. Cloud and
> network are out of scope for this benchmark. There is deliberately no single overall score spanning
> categories. Every other row on this page - check counts, licences, footprints - is drawn from each
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

Every claim about scoursh is traceable to a command or a source file in the repository; every claim
about another tool is traceable to that project's own repository or documentation.
