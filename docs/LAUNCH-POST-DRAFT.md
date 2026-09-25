> **DRAFT - UNPUBLISHED.** Written for the maintainer to review, edit and publish. Nothing here has
> been posted anywhere. Every number below was checked against the repository at the 1.0.0 commit on
> `dev`; the sources are listed at the end so each one can be re-checked before posting.

# scoursh 1.0: a security scanner that tells you what it did not check

Most security scanners give you a list of findings. An empty list could mean the code is clean. It
could also mean the scanner never looked: a database was missing, a permission was denied, or no file
matched the rule. From the output alone you usually cannot tell which.

scoursh 1.0.0 is out today. It is a security scanner written in bash, and it is built around two
rules.

## 1. It only talks to hosts you authorised, and that is checked when the scan runs

scoursh scans seven surfaces from one command line: source code, dependencies,
infrastructure-as-code, a running web application, a declared set of network listeners, a container
image, and a live AWS account.

Two of those need a network. A web scan must send requests to the app, and an AWS scan must call the
AWS API. So scoursh does not claim to be air-gapped. It claims something narrower that it can
enforce:

- Every HTTP request goes through one gate. The gate refuses any host that is not in
  `config/scope.conf`. A `--target` with no record there stops the run with exit code 3, before any
  request is sent. If the scanned site redirects somewhere outside the scope, the redirect is not
  followed and the refusal is recorded.
- Every AWS call goes through one wrapper that refuses anything that is not a read-only operation.
- Rules, payloads and advisory data are read from disk. There is no telemetry and no fetching at
  scan time. The only command that reaches the internet is a separate vendoring tool, and a scan
  never calls it.

The source-code, dependency and IaC scanners make no network calls at all. The benchmark harness
checks this: it ran `sast`, `sca` and `iac` (on small in-tree inputs) inside a macOS Seatbelt sandbox
that denies every network syscall at the kernel. All three finished with exit 0 and wrote a full
report. In a separate, unsandboxed `sast` run, the tool's own connection monitor (`--paranoid`) saw
no connection outside the allowlist.

The network scanner is not a port scanner. It checks the listeners you declared, and it never probes
a port you did not name.

## 2. A check that did not run is never reported as clean

When scoursh cannot run a check, the report says so and gives the reason. Examples: the advisory
database is missing, an AWS call returned `AccessDenied`, or an AWS region is not enabled. These are
recorded as declared coverage reductions. A few concrete cases:

- `scoursh sca` with no advisory database does not print "0 vulnerabilities". It exits with code 4
  and names every ecosystem it did not check.
- An AWS `AccessDenied` is recorded as "could not look", never as "no resources found".
- The optional audit report puts every registered check in one of four groups: found, clean, not run
  (with its reason), or unaccounted. "Unaccounted" is never merged into "clean".

The benchmark checked this on all 31 scoursh runs it inspected: in **31 of 31** runs, all 93 checks
that were selected but not run had a recorded reason, with **zero** undeclared gaps. None of the 8
SAST, SCA, IaC and secrets tools it compared against (Semgrep, Trivy, Grype, OSV-Scanner, Checkov,
KICS, Gitleaks, TruffleHog)
emits an equivalent "loaded N checks, ran M, here is why not the rest" record, so this is a
non-comparison rather than a score.

## What is in 1.0.0

**319** checks ship: 53 SAST, 36 IaC, 92 DAST, 15 network, 11 container-image and 112 AWS checks
across 30 services. Dependency scanning covers 6 ecosystems (npm, PyPI, Maven, Go, RubyGems,
Composer). Output formats include SARIF 2.1.0, HTML, Markdown and JSON. Exit codes are fixed, so CI
can act on them.

Installing is one tarball. It is built reproducibly, carries a Sigstore build-provenance
attestation, and is published as an immutable GitHub Release. You can check where it came from with
`gh attestation verify` before you run it. A Homebrew formula lands with the release.

## Where it is weaker, and by how much

scoursh is not a deeper Semgrep, ZAP or Trivy. In its own category, a specialist wins. The
comparison in
[`docs/COMPARISON.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/COMPARISON.md)
measures that on neutral, pinned corpora, with raw tool output committed:

- **SAST** on the full 2,740-case OWASP Benchmark: Semgrep scored a Youden J of **+0.492**. scoursh
  scored **-0.005**, which is no better than a coin flip. scoursh ships 53 SAST checks; Semgrep CE
  ships about 3,000 rules.
- **IaC** on TerraGoat (AWS Terraform): Trivy scored **+0.611**, scoursh **+0.038**.

The same comparison has a few results in scoursh's favour. Each one comes with its limits written
next to it. For example, on one secrets corpus scoursh found 33 of 65 planted credentials with zero
false positives. That corpus is mostly the generic `password = ...` shape that scoursh's rules
target, and on provider-specific token shapes the ordering reverses.

## Known gaps in 1.0.0

- No container image of scoursh itself, and no one-line installer yet.
- rpm-based container images (RHEL, Fedora and relatives) report a coverage gap instead of package
  findings, because scoursh cannot decode binary RPM headers yet. Alpine and Debian/Ubuntu images
  get full package matching.
- The AWS posture phase (SSO/edge/session drift) is not built. It is a declared skip.
- You build the advisory database yourself on a networked machine with one command. By default,
  reports flag it once it is more than 30 days old.

If you want to help close any of these, [`docs/CONTRIBUTING-ROADMAP.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/CONTRIBUTING-ROADMAP.md)
lists each gap with where the code would go and how to check a fix.

Release notes: [`docs/RELEASE-NOTES-1.0.0.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/RELEASE-NOTES-1.0.0.md)
Repository: https://github.com/abhi-sama/scoursh

---

## Notes for the maintainer (delete before posting)

**The 2-3 things that should carry the post:**

1. **A screenshot of `report-audit.html`'s coverage matrix** from a real run, with a non-empty
   "not run (reason)" column. This is the "tells you what it did not check" claim made visible, and
   no number replaces it. Suggested run: `scoursh sast --path <a single-language repo> --format
   html,audit`. On an all-Java corpus the benchmark saw 19 Go/JavaScript/Python checks listed as not
   run with reason `no_matching_files` (b8 README §1, worked example).
2. **The "31 of 31 runs, zero undeclared gaps" figure**, from
   `bench/results/b8-honesty-egress/README.md` §1. It is the one measured number for the
   declared-gap discipline.
3. **A short terminal capture of a scope refusal**: `scoursh dast --target https://example.com/`
   with a `config/scope.conf` that does not name that target, showing exit 3 and the message (checked
   2026-09-24: exit 3, and the message lists the ids the file does declare; with no `scope.conf` at
   all the exit is 4 instead). Run it non-interactively (for example `</dev/null`): at an
   interactive terminal scoursh offers to write the scope record instead of refusing straight away.
   It shows the egress rule in one screen. Alternatively, use the Seatbelt zero-egress result from
   the same b8 README (§2).

**Consider leading with the weak SAST number** (-0.005 against Semgrep's +0.492) rather than hiding
it. The post argues that scoursh is honest about its limits, and publishing its worst measured
number is the most convincing way to make that argument.

**Wording to avoid:** "air-gapped" for the tool as a whole (only `sast`/`sca`/`iac` are; see
`docs/adr/0001-egress-model-correction.md`), "comprehensive", or any claim that scoursh finds more
than a named tool outside the measured corpora.

**Sources for every number above:**

| Claim | Source |
|---|---|
| 319 checks, per-surface split, 30 AWS services | `id:` records under `modules/**/*.rules`; `modules/cloud/aws/live/*.sh` |
| 6 SCA ecosystems | `docs/DESIGN.md` §6.5; `modules/sca/` |
| Exit 3 on a target missing from `scope.conf`; out-of-scope redirect not followed | Run by hand on this commit (exit 3); `lib/http.sh` (`http_request` header comment) |
| Read-only AWS wrapper | `lib/awscli.sh` (`aws_ro`) |
| `sca` with no database exits 4 | `docs/USAGE.md`, "Dependency data" |
| Seatbelt zero-egress runs (§2a); separate `--paranoid` run saw nothing (§2b) | `bench/results/b8-honesty-egress/README.md` §2 |
| 31 of 31 runs, 93 of 93 unrun checks declared; no equivalent record in the 8 named tools | `bench/results/b8-honesty-egress/README.md` §1 |
| SAST J +0.492 vs -0.005 | `bench/results/b4-sast-owasp-full/README.md` |
| IaC TerraGoat J +0.611 vs +0.038 | `docs/COMPARISON.md` Table 1; `bench/results/b6-iac-terragoat-aws/` |
| Secrets 33 of 65, zero false positives, and its caveat | `bench/results/b6-secrets-leaky-repo/README.md` |
| 30-day staleness flag | `lib/config.sh` default `advisory-max-age-days`; `modules/sca/run.sh` |
| Attested, reproducible, immutable release | `.github/workflows/release.yml`; `docs/USAGE.md` "Installing from a release" |
