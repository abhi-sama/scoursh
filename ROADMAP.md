# Roadmap

`scoursh`'s build order is defined in [`docs/DESIGN.md`](docs/DESIGN.md) §13 as ten sequential
steps. Steps do not always land in strict numeric order - anything with no dependency on a blocked
step is pulled forward when it's ready - so "current position" below is a snapshot of what's
actually landed, not a claim that steps finish in order.
The fullest running account lives in [`AGENTS.md`](AGENTS.md)'s "Build order and where we are"
section, and the generated module status block it carries is the mechanically checked part of it.
This file is a shorter, reader-facing summary of the same information, and is hand-maintained
(see [Maintenance note](#maintenance-note-this-file-is-not-generated) at the end).

## Landed

- **Steps 1-2** - core libraries (`lib/records.sh`, `lib/core.sh`, `lib/findings.sh`,
  `lib/report.sh`), the `scan.sh` CLI grammar, and the check-registry/profile filter chain.
- **Step 3 (SAST)** - complete: all 10 planned step-3 artifacts.
  Those 10 are 9 rule packs plus `modules/sast/history.sh`, the git-history scanner, which is a
  script rather than a rule pack.
  (This entry read "8 of 10, 2 rule packs outstanding" until `ldap.rules` and `nosql.rules` landed
  without it being updated - the silent-staleness this file's own maintenance note warns about.
  The generated block in [`README.md`](README.md) reports 10 of 10, outstanding none, and is the
  authority.)
- **Step 4 (SCA + IaC)** - complete: all 6 SCA ecosystems, all 6 IaC rule packs.
  `modules/sca/run.sh` now calls `sast_evaluate_gate` like its SAST and IaC siblings, so
  `scan.sh sca --fail-on` really gates a run.
  It previously exited 0 whatever the severity, and that defect is fixed and pinned by a regression
  test.
- **Step 8 (`--paranoid` / network namespace isolation)** - complete: the connection-observer
  (`--paranoid`) and the Linux network-namespace guarantee (`tools/run-in-netns.sh`) have both
  shipped. macOS now has a real enforcement mechanism behind the detector too:
  `tools/run-sandboxed.sh` wraps Apple's Seatbelt (`sandbox-exec`) in three tiers - Tier A, an
  unconditional deny-all for `sast`/`sca`/`iac`; Tier B, a loopback relay plus an `lib/http.sh`
  redirect mode (`--scope-conf PATH`) that gives `dast`/`cloud`/`network` real target traffic while
  keeping off-host egress kernel-denied; and Tier C, running `tools/run-in-netns.sh` unmodified
  inside a Linux container on macOS for full namespace parity. See `AGENTS.md`'s own account of
  each tier and `docs/FOUNDATION.md` tension 20 for the detail.
- **Step 9 (optional engine adapters)** - three adapters shipped ahead of schedule: `semgrep` and
  `gitleaks` for `sast`, `trivy config` for `iac`. The advisory-database expansion tooling
  (`tools/vendor-engines.sh advisories ...`) has also landed.
- **Step 5 (DAST)** - complete: every ticket from DAST-01 through DAST-36 has landed (see
  [`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md)'s own status table).
  `scan.sh dast` runs the full engine described in `docs/DESIGN.md` §7 - session acquisition and
  crawling, every passive check, every safe-active and injection check, and the §7.4 tier-5 checks
  (JWT, GraphQL introspection, rate-limiting, object-level authorization, plaintext/mixed-content
  exposure) - subject to `--intensity`/`--authed`/`--i-own-target` gating the design always called for.
  It is no longer a no-op of any kind.
- `lib/http.sh` (the scope-gate chokepoint, normally part of step 5) and `lib/awscli.sh` (the
  read-only AWS wrapper, normally part of step 6) both landed early since neither depends on the
  steps in front of them.
- **`--format` now actually selects output artifacts, and every subcommand has real `--help`.**
  `scan.sh <cmd> --format <fmt>` writes exactly the artifacts `<fmt>` implies; `findings.jsonl` and
  `run.json` are written on every run regardless, as mandatory per-run records rather than
  `--format`-selectable artifacts.
  The no-`--format` default is unchanged (all four selectable formats, same as before).
  `scan.sh <command> --help` now prints that command's own accepted flags (generated from the
  parser's own flag table, so it cannot list a flag the parser would reject) and a plainly-stated
  build status, derived from the same on-disk check `scan_dispatch` itself uses wherever one exists.
- **`--format audit` - a fifth, opt-in format value.** `report_audit` writes `report-audit.html`
  alongside `report.html`, never replacing it: a per-category (sast/sca/iac/dast/cloud) coverage
  report that lists every registered check in exactly one of four states - found something, ran and
  found nothing, did not run (with the recorded reason), or unaccounted - with full not-covered
  detail rather than a count alone, so a registered-but-silent check can never read as "clean."
- **`--format agent` - originally a sixth, opt-in format value; a later captain decision made it a
  first-class deliverable in the default list (`json,sarif,html,md,agent`), so a plain run with no
  `--format` flag now writes it too.** `report_agent` writes
  `reports/<run>/agent-fix.json`, a compact findings file shaped for a downstream AI fixing agent
  rather than a human reader: fields byte-identical across every finding of a check are hoisted into
  a shared `checks{}` catalogue instead of repeated per finding, and a deterministic fix scaffold is
  included wherever scoursh can derive one (an SCA version bump, an IaC one-line config fix, or a
  cloud CLI command labeled suggested/human-review/never-auto-run), alongside the same honesty header
  the other formats carry so "did not check" can never read as "clean." Full contract:
  [`docs/AGENT-FORMAT.md`](docs/AGENT-FORMAT.md).
- **Step 7 (`state/` - persistent coverage tracking) is complete.** STATE-01 through STATE-08 have
  all landed (see [`docs/STEP7-STATE-PLAN.md`](docs/STEP7-STATE-PLAN.md)'s own status table): every
  normal run persists `state/<run-id>.json` and automatically classifies findings
  `new`/`recurring`/`fixed`/`unknown` against the prior run, `scan.sh diff --against DIR` does real
  classification against a named prior run, `config/baseline.json` (or `--baseline FILE`) suppression
  is live, and `--fail-on-new` now really is a carve-out - it gates on `status == new` only when the
  diff was usable, and falls back to every finding otherwise - rather than a synonym for `--fail-on`.
  `report --from DIR` (regenerating reports from a prior run's own findings, distinct from producing
  them during a scan) has since landed too, independent of `state/` (it needs no classification at
  all, only re-emission) - see AGENTS.md's own entry on it.
- **Step 10 (SARIF output + compliance report) is complete.** SARIF-01 through SARIF-06 (see
  [`docs/STEP10-SARIF-PLAN.md`](docs/STEP10-SARIF-PLAN.md)'s own status table) write a complete,
  schema-validated SARIF 2.1.0 document under `--format sarif`. COMPLIANCE-01 through COMPLIANCE-04
  add both halves of the compliance report to `report.md`/`report.html`: findings grouped by OWASP
  Top 10 2021 category (`data/owasp-categories.conf`) and by CIS AWS Foundations Benchmark v3.0.0
  control (`data/cis-mappings`), each with an honest per-category/per-control status distinguishing
  assessed-clean, out-of-scope, not applicable to the scanned account, and filtered out of this run
  by `--profile-scan`/`--intensity`.
- **Guided mode is complete.** GUIDE-01 through GUIDE-07 have all landed (see
  [`docs/STEP-GUIDE-PLAN.md`](docs/STEP-GUIDE-PLAN.md)'s own status section): a bare `scan.sh`, or
  `scan.sh <command> --guided`, walks an operator through composing a real command - including the
  DAST target/intensity/affirmation flow - and `--print-command` prints the exact equivalent
  non-interactive invocation, verified byte-identical to what "Run it" actually executes. `cloud` is
  now reachable at the G1 menu (`modules/cloud/aws/run.sh` exists), though its guided setup beyond the
  scan type and `--fail-on` isn't wired into `--guided` yet - the menu says so and hands back the
  equivalent direct command rather than asking questions it can't yet compose an answer to.
  [`docs/build.html`](docs/build.html) is the click-through equivalent of the same idea: a static,
  offline command builder page (pick a surface, point it at a path or target, toggle options) that
  composes and displays the exact command rather than running anything.
- **Step 6 (Cloud / AWS CSPM) is complete for the live-checks half.** `lib/awscli.sh`'s `aws_ro`
  chokepoint, `modules/cloud/aws/run.sh`'s dispatch entry point (account-authorization record +
  enabled-region iteration, `--assume-role` for multi-account), and all 30 `docs/DESIGN.md` §8.1
  services (`modules/cloud/aws/live/*.sh`) have landed - 112 checks total, CIS AWS Foundations
  Benchmark v3.0.0 and OWASP mapped, feeding the compliance report step 10 already ships. Every AWS
  call goes through `aws_ro`, which refuses anything that is not read-only; access-denied, opted-out,
  or throttled services are recorded as a coverage reduction, never folded into a clean pass. The
  `posture/` phase (`docs/DESIGN.md` §8.7's SSO/edge/session drift checks, POSTURE-02 through
  POSTURE-04) has not landed - only its config schema (`config/posture.conf.example`, POSTURE-01) does
  - so a posture-phase run today is a declared skip. A complete sub-ticket breakdown, including the
  three remaining posture tickets, is in
  [`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md).
- **`COMPOSITE-TOKEN-HIJACK` is now seeded** in `rules/derived.rules` (findings F5/F20, open since step
  1, are cleared): DAST supplies one contributor and the cloud module landing above supplies the
  other, so the composite finding this correlates is live rather than an intentionally-unseeded gap.
- **Network / host scanning is complete.** `modules/network/` (NET-01 through NET-11, see
  [`AGENTS.md`](AGENTS.md)'s "Network module (NET)" section for the full landing detail) ships
  `scan.sh network --target NAME`: service-posture scanning over the listener set
  `config/scope.conf`'s `base-url`/`extra-host` entries declare for that target - three-state
  reachability verification, banner/HTTP service and version disclosure, TLS posture on non-web
  ports, and plaintext/STARTTLS transport posture - gated by the identical `lib/http.sh` scope
  chokepoint, ceilings, and `--i-own-target` affirmation `dast` uses. This is deliberately **not** a
  port scanner or a host-discovery tool: a port the operator did not declare is never probed, and OS
  patch-level inference and UDP are stated-gap exclusions, not oversights - see
  [`docs/CHECKS.md`](docs/CHECKS.md) for why.
- **Container image scanning is complete.** `modules/image/` (IMG-01 through IMG-14, see
  [`AGENTS.md`](AGENTS.md)'s "Container image scanning (the IMAGE module)" section for the full
  landing detail) ships `scan.sh image --image ID [--source PATH]`: offline installed-package
  enumeration and CVE matching against a `docker save` tarball or OCI image-layout directory the
  operator supplies - never a registry pull, the same offline-database model SCA already lives in.
  Covers apk, dpkg, and rpm packages (rpm needs `sqlite3` on `PATH`; its absence is a declared
  coverage reduction, never a silent clean pass), language dependencies found inside the image's own
  rootfs (reusing `sca`'s tree-walkers), and config-blob checks (effective runtime user, exposed
  ports, mutable base-image reference). Correlates with `modules/iac/dockerfile.rules` findings for
  the same image via `rules/derived.rules` when `config/images.conf` names the Dockerfile that built
  it. This is the **built-artifact** counterpart to IaC's Dockerfile *source* linting, not a
  replacement for it - see [`docs/CHECKS.md`](docs/CHECKS.md)'s "Container image" section and
  `docs/DESIGN.md` §15 for what it deliberately does not do (no full-rootfs materialisation, no
  running-container/runtime inspection).

## Not yet started

Every `docs/DESIGN.md` §13 step (1 through 10) has now landed - see "Landed" above.
This section used to track one gap in an already-shipped feature - a macOS enforcement mechanism
behind `--paranoid`'s detector - and that has since landed too (`tools/run-sandboxed.sh`'s three
tiers; see "Landed" above). It is empty for the moment.

**Step 10 (SARIF output + compliance report) is complete and no longer listed here.**
The SARIF half writes a complete, schema-validated SARIF 2.1.0 document (`report_sarif`, SARIF-01
through SARIF-06) - `tool.driver`/`rules[]`/`artifacts[]`/`invocations[]` and a fully-mapped
`runs[0].results[]` carrying this run's actual findings. The compliance report is now **both halves
done** (COMPLIANCE-01 through COMPLIANCE-04): `data/owasp-categories.conf` expands every `owasp` id to
its published Top 10 2021 label and `data/cis-mappings` expands every `cis` id to its published CIS
AWS Foundations Benchmark v3.0.0 title, and `report.md`/`report.html` both group findings by category
and by control with an honest per-category/per-control status (assessed-clean, out-of-scope, not
applicable to the scanned account, or filtered out of this run by `--profile-scan`/`--intensity`).
A complete sub-ticket breakdown exists in
[`docs/STEP10-SARIF-PLAN.md`](docs/STEP10-SARIF-PLAN.md) (tickets SARIF-01 through SARIF-06 and
COMPLIANCE-01 through COMPLIANCE-04, all landed).
That plan's own central finding is that this step was three deliverables with three different
readiness states, not one: the SARIF emitter needed neither step 6 nor step 7; the compliance report's
OWASP half was unblocked too, and its CIS half needed only step 6's FIRST `cis`-carrying finding
(`modules/cloud/aws/live/s3.sh`), not step 6 to finish; and the `--fail-on` CI gate §13 item 10 also
names was already shipped in full and carries no ticket.

Outside that ordering:

- IPv6 / dual-stack routing support for `tools/run-in-netns.sh` has landed (the follow-up this line
  used to point at): the namespace's loopback and veth pair get IPv6 addressing and routing
  unconditionally, alongside IPv4, on every run, and the tool refuses to run at all (exit 4) on a
  host that lacks IPv6 kernel support or `ip6tables` rather than silently degrading the guarantee to
  IPv4-only. See `tools/run-in-netns.sh`'s own header comment and `AGENTS.md`'s "Step 8" section for
  the detail.

## Known defects in shipped features

These are not unbuilt steps.
They are features that ship today and are wrong, incomplete, or inert, and each one has to be
scheduled on its own.

- **Flags that were accepted and then ignored.**
  `--authed` used to be one - it no longer is: DAST's `auth.sh`/`crawl.sh` and every authenticated
  check now read it, and `scan.sh` records it as `run.json`'s `authorization.authed` field.
  `--baseline FILE`, `--fail-on-new` and `--jobs N` were three more; all three are now live - see
  "Recently fixed" below.
  (`--format` used to be a fifth: it was parsed and the resolved format list was then discarded, so
  every run wrote the same five artifacts whatever was asked for.  Fixed - see "Landed" above.
  `findings.jsonl` and `run.json` are mandatory per-run records rather than one of the four
  `--format` values, and are written on every run regardless of what `--format` asked for; `sarif`
  selects `report_sarif` like every other value and, as of SARIF-06, writes a complete document -
  see "Recently fixed" below and [`docs/USAGE.md`'s SARIF output section](docs/USAGE.md#sarif-output).)

## Recently fixed

Entries that used to sit under "Known defects" above, kept for a release or two so a reader who knew the
old behaviour can see what replaced it.

- **`--paranoid` had a real macOS *detector* but no macOS *guarantee*.**
  Of its three connection-observer backends, `ss` and `strace` are Linux-only; `lsof` was added as a
  third, measured-usable backend so `--paranoid` runs on macOS too, but that made it a genuine
  detector there, not a refusal - `tools/run-in-netns.sh` (step 8's *guarantee* tier) is a Linux
  network namespace and has no macOS equivalent, so a macOS run used to have the detector and nothing
  enforcing behind it. `tools/run-sandboxed.sh` closes that: Tier A is an unconditional Seatbelt
  (`sandbox-exec`) deny-all for `sast`/`sca`/`iac`, which make zero network calls by design; Tier B
  adds a loopback relay plus an `lib/http.sh` redirect mode (`--scope-conf PATH`) so `dast`/`cloud`/
  `network` still get real, scope-restricted target traffic while off-host egress stays
  kernel-denied; Tier C runs `tools/run-in-netns.sh` unmodified inside a Linux container on macOS for
  full namespace parity. All three fail loud (exit 4) and never degrade to an unsandboxed run. A host
  with none of `--paranoid`'s three detector backends still exits 4 before any module runs,
  independent of `run-sandboxed.sh`. See `AGENTS.md`'s own account of each tier and
  `docs/FOUNDATION.md` tension 20 for the full detail.
- **`--jobs N` was accepted, validated, exported and read by no module.**
  It is documented with a default of 4 and every `sast`/`sca`/`iac` scan was single-worker
  regardless, each module recording a flat `single_worker_no_parallel_scan_yet` coverage_reduction at
  every value of the flag. It is real now: `lib/parallel.sh` is the shared bounded fan-out, `sast`
  and `iac` split the file list through `_sast_walk_parallel` and `sca` splits the manifest list
  through `_sca_scan_parallel`, each worker writing its own finding shard (tension 17). A run at
  `--jobs 4` produces byte-identical findings to the same run at `--jobs 1`, because the merge sorts
  every shard together under `LC_ALL=C` and each worker's `run_record` appends land in a private
  directory the parent folds back in worker order rather than interleaving in `meta/`. The old flat
  reduction is replaced by one that names the resolved value
  (`reason=single_worker jobs=N ...`) or, on a parallel run, a `notes` line naming the worker count.
  A worker that dies exits `5` with an `incomplete_reason` naming `parallel_worker_failed` and
  records no coverage for the cell, rather than letting a half-scanned tree read as a clean report.
  DAST is unchanged and was never part of this defect: `lib/http.sh` reads the same number as an
  in-flight *connection* ceiling, which is a different meaning of it.
- **`--baseline FILE` was parsed and never read; `--fail-on-new` was a tautology.**
  Both needed the step 7 persistent-state work, which has since landed in full
  (`docs/STEP7-STATE-PLAN.md`, STATE-01 through STATE-08). `--baseline FILE` (or the default
  `config/baseline.json`) now really suppresses a matching finding by fingerprint - `suppressed: true`
  plus its reason, never a deletion, and excluded from every count and from `--fail-on`/
  `--fail-on-new`; an explicit path that does not exist is now a real error (`exit 4`) rather than a
  silent no-op. `--fail-on-new` now gates on `status == new` only when this run's diff against the
  prior one was usable, and falls back to every finding when it was not (a first run, a schema
  mismatch, or a `scan_root_id` mismatch), rather than behaving identically to `--fail-on` in every
  case.
- **`--format sarif` wrote a SARIF document with no findings in it.**
  `report_sarif` used to write the document skeleton only - `tool.driver`/`rules[]`/`artifacts[]`/
  `invocations[]` - with `runs[0].results[]` always empty, because the per-finding mapping (SARIF-04)
  had not landed yet.
  SARIF-04 through SARIF-06 (`docs/STEP10-SARIF-PLAN.md`) landed the mapping, the real schema
  validation (against the vendored OASIS SARIF 2.1.0 schema, plus a filesystem-backed check that every
  result's location resolves to a real file), and the operator documentation.
  `report.sarif` now carries this run's actual findings and is safe to point a code-scanning CI step
  at; see [`docs/USAGE.md`'s SARIF output section](docs/USAGE.md#sarif-output).
- **Dependency scanning skipped the scan entirely without an advisory database, and reported that as clean.**
  `data/advisories.db` still does not exist in this repository - the only advisory database in the tree
  is `tests/fixtures/sca/advisories.db`, a test fixture - and populating it is still the operator's job
  (`tools/vendor-engines.sh advisories`, run on a networked box; it takes either a list of OSV ids the
  operator supplies or, since the bulk importer landed, a whole ecosystem at once).
  What changed is that the tool now says so instead of reporting a clean scan.
  `scan.sh sca` with no database exits **4** (`SCOURSH_EXIT_INPUT`, "missing required input" -
  [`docs/FOUNDATION.md`](docs/FOUNDATION.md) tension 14's frozen precedence, no new code and no change
  to the order), writes its full report, and carries a `SCA-COV-NO_ADVISORY_DB-01` finding stating that
  zero dependencies were checked.
  `run.json` records **one** `module=sca reason=no_advisories_db_on_disk ecosystems=<all six>` reduction
  in place of the previous two-from-some-walks-and-nothing-from-the-others, and `checks_run` is no longer
  empty.
  A `scan.sh all` run is unaffected in its exit code, per the same tension's row for a module skipped
  under `all` for absent inputs; it still reports the blind spot.
- **Two SCA coverage roll-ups collided, and one was dropped silently.**
  The `SCA-COV-UNKNOWN_VERSION-01` roll-up carries no ecosystem component in its fingerprint - it names
  no single dependency, so it never could - and the Python, Java and Go paths each used to emit their
  own roll-up rather than joining npm's.
  A project with dependencies in two of those groups therefore produced two findings with an identical
  fingerprint, deduplication dropped one, and the survivor reported one walk's share as if it were the
  total (on a fixture carrying npm, PyPI, Maven and Go gaps, the report said 1 where the truth was 4;
  which walk's count survived depended on the merge sort, not on anything meaningful).
  The four walks now accumulate into one shared table that the module flushes once, so a run emits
  exactly one roll-up and its count is the true total across every ecosystem.
  The fix is at the emission layer on purpose: the fingerprint is byte-for-byte unchanged, so no
  `format_version` bump and no `state/` migration are owed
  ([`rules/RULE-FORMAT.md`](rules/RULE-FORMAT.md) §14 item 3).
  Adding an ecosystem component was weighed and rejected - see
  [`docs/FOUNDATION.md`](docs/FOUNDATION.md) tension 5 for the argument.

## Not currently on the roadmap

Nothing from the broader "types of security scanner" taxonomy is excluded from `docs/DESIGN.md`'s
plan at this point - this section is empty for the moment, kept as a heading because the taxonomy it
tracked is worth re-checking against before assuming a new category is simply "next."

Network / host scanning and container image scanning both used to be listed here; both shipped - see
"Network / host scanning is complete" and "Container image scanning is complete" under
[Landed](#landed).
Network / host scanning still carries two deliberate, stated exclusions rather than unbuilt work - OS
patch-level inference (banner-version matching cannot see a distribution's backported fixes) and UDP
(no connect handshake, so "open" and "filtered" are indistinguishable without a per-service payload).
Container image scanning likewise carries stated exclusions rather than unbuilt work - no
full-rootfs materialisation, no running-container/runtime inspection, and rpm needs `sqlite3` on
`PATH` or it is a declared coverage reduction. See [`docs/CHECKS.md`](docs/CHECKS.md) and
`docs/DESIGN.md` §15 for both.

## Maintenance note: this file is not generated

`tools/gen-status.sh` regenerates the module status block carried by `AGENTS.md`, `README.md`
and `docs/FOUNDATION.md`, and `tests/lint-status.sh` fails the build when a committed block
differs from a fresh generation.
`ROADMAP.md` is not one of those three targets, so nothing here is checked against the tree.
That makes this the one status surface in the repository that can go stale silently, and it has done
so before.
Read a count here as a claim to verify against the generated block, and correct it in the same change
as the work that invalidated it.
