# Roadmap

`scoursh`'s build order is defined in [`docs/DESIGN.md`](docs/DESIGN.md) §13 as ten sequential
steps. Steps do not always land in strict numeric order - anything with no dependency on a blocked
step is pulled forward when it's ready - so "current position" below is a snapshot of what's
actually landed, not a claim that steps finish in order. The authoritative, always-current account
lives in [`CLAUDE.md`](CLAUDE.md)'s "Build order and where we are" section; this file is a shorter,
reader-facing summary of the same information.

## Landed

- **Steps 1-2** - core libraries (`lib/records.sh`, `lib/core.sh`, `lib/findings.sh`,
  `lib/report.sh`), the `scan.sh` CLI grammar, and the check-registry/profile filter chain.
- **Step 3 (SAST)** - 8 of 10 planned rule packs, see below for what's left.
- **Step 4 (SCA + IaC)** - complete: all 6 SCA ecosystems, all 6 IaC rule packs.
- **Step 8 (`--paranoid` / network namespace isolation)** - complete: the connection-observer
  (`--paranoid`) and the Linux network-namespace guarantee (`tools/run-in-netns.sh`) have both
  shipped.
- **Step 9 (optional engine adapters)** - three adapters shipped ahead of schedule: `semgrep` and
  `gitleaks` for `sast`, `trivy config` for `iac`. The advisory-database expansion tooling
  (`tools/vendor-engines.sh advisories ...`) has also landed.
- `lib/http.sh` (the scope-gate chokepoint, normally part of step 5) and `lib/awscli.sh` (the
  read-only AWS wrapper, normally part of step 6) both landed early since neither depends on the
  steps in front of them.

## Not yet started

- **Step 3, remaining** - two SAST rule packs: `ldap.rules` and `nosql.rules`.
- **Step 5 (DAST)** - `scan.sh dast` currently parses its full flag grammar and enforces the scope
  gate, but has no scan engine behind it; it is a logged no-op. A complete, dependency-ordered
  sub-ticket breakdown already exists in
  [`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md) (tickets DAST-01 through DAST-30, following
  `docs/DESIGN.md` §13's `lib/http.sh -> auth.sh -> crawl.sh -> passive -> safe-active -> injection`
  sequence). Work does not start until the two SAST packs above have landed.
- **Step 6 (live cloud / CSPM scanning)** - `scan.sh cloud --live` is a no-op today. A complete
  sub-ticket breakdown exists in [`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md) (tickets
  CLOUD-01 through CLOUD-34 plus POSTURE-01 through POSTURE-04). Gated on step 5 (DAST) completing.
- **Step 7 (`state/` - persistent coverage tracking)** - needed before `--baseline` suppression and
  the `diff`/`report` subcommands do real work; both currently no-op with a stated reason.
- **Step 10 (SARIF output + compliance report)** - `--format sarif` is accepted today, but nothing
  emits it yet; same for the CIS/OWASP compliance report.
- Two derived/composite findings (`COMPOSITE-TOKEN-HIJACK` and its dependents) are intentionally
  not seeded yet, because their contributing checks don't exist until DAST (step 5) and cloud (step
  6) land.
- IPv6 / dual-stack routing support for `tools/run-in-netns.sh` was explicitly scoped out of that
  ticket and filed as a separate follow-up.

## Not currently on the roadmap

Two categories from the broader "types of security scanner" taxonomy are not part of
`docs/DESIGN.md`'s plan at all, not merely unbuilt:

- **Container image scanning** - scanning the layers and installed packages of a *built* Docker
  image (the way Trivy or Grype do). `scoursh` lints Dockerfile and docker-compose *source* as part
  of `iac`, which is a different, narrower thing.
- **Network / host scanning** - servers, open ports, OS patch levels.

If either of these matters to your use case, it's worth raising as an issue rather than assuming
it's simply "next."
