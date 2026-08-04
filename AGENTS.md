# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

## What scoursh is

`scoursh` ("scan exhaustively") is a shell-based, air-gapped security scanner.
One tool audits three surfaces: source code (SAST plus SCA plus IaC), a running endpoint (DAST), and AWS configuration (live read-only plus IaC).

It is **target-agnostic**.
No application, company, product, environment, or endpoint name is ever baked into a script, a rule, or a document.
Every site-specific value comes from the operator's config at runtime.
Rules describe *classes* of issue, never a specific system.
This is `docs/DESIGN.md` §1 and it is a hard rule for every change.

## The no-egress rule, and why it drives everything

Exactly two kinds of outbound traffic are permitted:

1. `curl` to a host the operator authorised in `config/scope.conf`.
2. Read-only AWS API calls to the operator's own account.

Everything else is forbidden: no telemetry, no SaaS backend, no fetching rules or advisories at scan time.
The tool must run on an air-gapped host.

This single constraint explains most of the architecture, so do not "improve" a design decision without checking it against this first:

- Rules, payloads, wordlists, and advisory data are **vendored in the repo** and read from disk.
- `tools/vendor-engines.sh` is the only script that touches the internet, is never called during a scan, and is quarantined and documented as such.
- Every network call goes through the single wrapper `lib/http.sh`, which refuses any host absent from the resolved allowlist.
- Every AWS call goes through `lib/awscli.sh`, which refuses any operation that is not read-only (`docs/FOUNDATION.md` tension 23).
- The HTML report is self-contained with no external assets and a strict inline CSP, because a report that fetches a font is egress.
- Version-range arithmetic for SCA is done on the networked box and shipped pre-expanded, so the scanner only does table lookups (`docs/FOUNDATION.md` tension 25).

## Documents, and which one wins

| Document | Role |
|---|---|
| `docs/DESIGN.md` | The handoff spec. **Preserved verbatim**; its wording is load-bearing. Do not rewrite, re-order, summarise, or "improve" it. |
| `docs/FOUNDATION.md` | The design-tension register. 26 tensions, each with a committed RESOLUTION. **Where it contradicts the letter of `docs/DESIGN.md`, it wins**, and it says so explicitly at each point. |
| `rules/RULE-FORMAT.md` | The **FROZEN** on-disk record format. Normative and self-contained. |

Read all three before changing anything structural.
`docs/FOUNDATION.md` exists so that decisions are not re-litigated; if you disagree with a resolution, change the register deliberately and cost the change, do not quietly diverge in code.

## The frozen record format

`rules/RULE-FORMAT.md` defines blank-line-separated `key: value` block records.
It replaces the pipe-delimited rule format sketched in `docs/DESIGN.md` §6.2, because any regex containing `|` silently corrupts a pipe-delimited field split, and the §6.3 rule catalog is full of such regexes.
The rule **catalog** in §6.3 is unchanged; only the on-disk encoding is.

It is used by **every human-authored file**: all `*.rules` packs, `rules/derived.rules`, `rules/redaction.rules`, `modules/<m>/checks.rules`, and every `config/*.conf` including `config/scope.conf`.
Machine-generated files use JSON or the frozen TSV instead (`findings.jsonl`, `run.json`, `state/*.json`, `config/baseline.json`, `data/advisories.db`).

Key properties, so you do not have to re-read the spec to avoid breaking it:

- Values carry **no escaping at all**; the bytes after the first `": "` to end of line are the value.
- Comments are whole-line only (first byte `#`), so `#` is free inside values.
- A blank line separates records; a whitespace-only line is an **error**, not a separator.
- CRLF and BOM are errors, because a stray `\r` would silently end up inside every regex.
- Prose fields get multiple lines via two-space continuation lines; `pattern` is always single-line.
- Regexes declare a `dialect`, defaulting to a frozen portable ERE subset that behaves identically under `rg` and `grep -E`.

**The format is FROZEN.**
Every later module depends on it, and check ids feed the finding fingerprint, so a change invalidates `state/` and `config/baseline.json` and breaks the "fail only on new findings" CI mode.
The full cost is enumerated in `rules/RULE-FORMAT.md` §14, and a change requires a `format_version` bump and a `state/` migration.

## Sharp edges that are easy to get wrong

These are resolved decisions, not open questions.
Each has a full entry in `docs/FOUNDATION.md`.

- **The composite fingerprint's first component is the literal `composite`, not the finding's `module` field** (tension 6). The module field is `derived`; the two are different strings for different jobs. Passing the module through hashed `derived` and produced an identity no conformant implementation agrees with - invisible, because a composite fingerprint is only ever compared with itself. Assert it against a digest computed from raw bytes, never through `fingerprint_compute`.
- **Never put a line number in a fingerprint** (tension 5). It would make every finding `new` after any unrelated edit, destroying the diff, the baseline, and the CI gate. Repeated byte-identical matches in one file are told apart by an `occurrence` ordinal, not a line.
- **`fixed` is inferred only inside a covered (check, scope-cell) pair** (tension 12). Check-id-alone coverage lets a `--regions` or `--target` run report every unvisited region's or target's findings as remediated.
- **Never call `grep` or `rg` bare** (tension 4). `set -Eeuo pipefail` is mandatory and grep exits 1 on no-match, which is the normal case. Use `scan_match`, which distinguishes no-match from engine failure.
- **The `EXIT` cleanup trap is guarded on scratch-dir OWNERSHIP, never on subshell-ness** (tension 4 rule 5, finding F13, closed). The guard is `scratch_is_owned_here`: the creating process records its pid in a non-exported variable AND in an on-disk marker, and cleanup no-ops unless both say this process. Do not reach for `[[ $BASHPID == $$ ]]`: bash resets trapped `EXIT` actions in subshells, so that guard defends a case bash never produces, and it PASSES in an `xargs -P` worker - which is a fresh process - so the first worker to finish erases the shared scratch dir. Both halves are measured in `tests/suites/core.sh`.
- **The scratch dir holds only genuinely transient data** (finding F12): `scan_match` line files, the mutexes, and the rate, budget and breaker state. Finding shards and the unit journal live under `reports/<run>/` unconditionally, because the EXIT trap erases the scratch dir on the SIGTERM that resume itself is tested with. `--keep-shards` means "do not delete after a successful merge".
- **`msleep` reads a FIFO the process holds open read-write, and is chosen by MEASUREMENT** (tension 24, finding F14). `read -t </dev/null` returns at EOF instantly and does not sleep, and `read` returns non-zero for EOF and timeout alike, so an exit-status probe cannot tell them apart.
- **The mutex reclaim is single-winner and identity-bound** (tension 16, finding F15). A bare `rm -rf` of a stale lock can delete a *live* one and put two processes in the critical section. `lock_is_stale` needs BOTH age and non-liveness; requiring both is what bounds pid reuse.
- **Nothing exits outside 0-5** (tension 14, finding F16). `die` validates its code. `shred` is GNU-only and absent on macOS; it sits behind `erase_dir`, and overwrite-based erasure is best effort - `scratch-dir` on a tmpfs is the real control.
- **Shared state across `xargs -P` workers goes in files under an atomic-`mkdir` mutex** (tension 16). The rate limiter, request budget, circuit breaker, and AWS cache are all per-process otherwise, so `--jobs 8` means 8x the request rate and a breaker that never trips.
- **Workers write to their own shard file, never a shared `findings.jsonl`** (tension 17). Appends above `PIPE_BUF` interleave.
- **Never `source` a config file** (tension 26). It is a code-execution vector that would run before the scope gate is consulted.
- **A partial run must never report `fixed`** (tension 12). `state/` tracks coverage as **(check, scope-cell)** pairs; a prior finding whose own cell was not visited is `unknown`. `path-root` cells are comparable only between runs with the same `scan_root_id` (other cell kinds carry no path and are not gated by it). Two families refine this and can only narrow it: `SAST-HIST-*` adds a per-finding history-boundary test (tension 13), and a composite is `fixed` only when **(a)** its own record was selected this run, **(b)** every check in `requires`/`any-of` is covered - contributors that fired under the test that would let *their own* finding be `fixed`, listed checks that did not fire by being covered **this run** at all (a check with no entry in this run's `covered_checks` is never covered, whatever the prior run recorded) **and** having every cell the prior run covered them over revisited - and **(c)** the predicate no longer holds (tension 6). Reading contributor cells alone is not enough: it misses an unselected composite and a history contributor whose boundary has receded.
- **The scan root is a defined term** (tension 12): the git toplevel of the resolved `--path`, else the resolved `--path`. Every "repository-relative path" means scan-root-relative. scoursh's own install root is a different thing (tension 26).
- **An unusable diff is fail-closed at the gate** (tension 11 step 7). No prior state, an `fp_schema` mismatch, or a `scan_root_id` mismatch **on a run whose findings live in `path-root` cells** all set `diff_usable = false` (a `cloud`/`dast`/`posture`-only run is unaffected by `scan_root_id`, since those cells carry no path), and `--fail-on-new` then gates on **all** findings. `diff_usable` governs the **gate only** and never overrides a `status`: a first run's findings are `new` per tension 12's table, not `unknown`.
- **A secret is never a command-line argument and never touches disk raw** (tension 9). `sha256_of` reads stdin only.
- **Evidence is untrusted target output** (tension 10). It goes through `finding_set_evidence` and is escaped per emitter; the HTML report contains no `<script>` at all.
- **`tests/fixtures/{vuln,clean}/` are SHARED trees scanned wholesale, so landing a new `*.rules` pack changes what every existing pack is tested against - and what every existing pack's fixtures test the new one against.** Each pack asserts "stays quiet across the whole clean tree", so an overlapping `files:` glob is a cross-fire, not a local concern. `kubernetes.rules` (`bb75c9b`) landed **after** `docker-compose.rules` (`57d1cd1`) and its `tests/fixtures/clean/docker-compose.*.yml` fixtures, carried no compose guard, and so merged red: `tests/suites/iac.sh` reports `110 passed, 2 failed` at `bb75c9b` itself, and `dev` carried those two failures onward into every branch cut from it until they were fixed. `image:` and `privileged: true` are byte-identical vocabulary in the two schemas. A pack whose `files:` glob overlaps another's must state the boundary explicitly - `exclude-files` mirroring the owning pack's `files:` list where the shape has a conventional filename (docker-compose, Dockerfile), a content `context-deny` only where it does not (CloudFormation, Helm templates). Reach for `exclude-files` first: it cannot interact with a `context-window`, whereas a content deny on a check like `IAC-K8S-MUTABLE_TAG-01` forces widening a same-line-intent window that `rules/RULE-FORMAT.md` §10.2 requires to stay at `0`, trading a visible false positive for a silent false negative (finding F4).
- **A cross-fire fix needs a test in BOTH directions, because the naive fix for each is the other's bug.** Narrow too little and the false positives return; narrow too much and the pack goes inert - and an inert pack passes every "stays quiet" assertion in the suite, so the only thing that catches it is an assertion that the rules still FIRE. The kubernetes/docker-compose section of `tests/suites/iac.sh` pins both halves, and asserts them over `check_id@loc_path` pairs from a single scan of `tests/fixtures/iac-scope/` so neither half can be satisfied by breaking the other. That failure mode had already cost two tickets before it was tested.

## Build order and where we are

`docs/DESIGN.md` §13 gives the build order, in ten steps, starting with `lib/core.sh` / `lib/findings.sh` / `lib/report.sh` and ending with SARIF plus the compliance report plus docs.

**Process rule: shipping a §13 step updates this section, and its mirror in `docs/FOUNDATION.md`'s
"Where the build currently stands," in the same change.**
Step 3e (`modules/sast/history.sh`, commit `18c4c3f`) landed without either doc being updated, so its
existence was rediscovered a ticket downstream by an agent working on unrelated doc staleness, which is
exactly the failure mode this file exists to prevent (see "`main` can lag `dev`" below for the earlier,
sibling instance of the same pattern). Do not repeat it: a ticket that lands a `docs/DESIGN.md` §13
sub-step is not done until this paragraph's "Current position" and the FOUNDATION.md section it mirrors
both say so.

**Current position: §13 steps 1 and 2 are done, step 3 is under way, and step 4's IaC half has begun
landing out of step order.**
Step 3's sub-steps 3a, 3b, 3c, 3d, and 3e have landed on `dev`.
Step 3 as a whole is still not finished: `docs/DESIGN.md` §6.3's rule catalog also calls for the
`nosql` and `ldap` rule packs, and neither has landed yet.
Every per-language pack the catalog names - `python`, `javascript/ts`, `go`, and now `java` - has
shipped; nothing beyond `nosql.rules`/`ldap.rules` remains under the "language" heading.
`history.sh` (the `SAST-HIST-*` mechanism, tension 13) already shipped as 3e (see below); do not
re-list it as outstanding.
The next task for step 3 itself is its remainder (`nosql.rules` and `ldap.rules`).
Step 4's IaC half has also landed, out of sequence and ahead of step 3's remaining `nosql`/`ldap`
sub-steps, in three separate landings: `5de4460` shipped Terraform checks, `add2b21` added the
Helm-values slice of §6.6's container/orchestration catalog (`modules/iac/helm.rules`), and `25abfa3`
added the Dockerfile slice (`modules/iac/dockerfile.rules`).
CloudFormation, bare Kubernetes-manifest checks, and docker-compose checks are all still open under
§6.6 - see the detailed paragraph below.
**Step 4's SCA half is also under way, out of sequence, and now six ecosystems in - every ecosystem
`docs/DESIGN.md` §6.5 names: `ed8c283` shipped the npm/yarn/pnpm lockfile slice, a follow-on ticket
shipped the Python slice (`requirements.txt`/`poetry.lock`/`Pipfile.lock`) on top of it, `a2d37aa` then
added the Ruby slice (`Gemfile.lock`), a later ticket added the Java slice
(`pom.xml`/`build.gradle`, under check id `SCA-JAVA-VULNERABLE_DEP-01`), `7e7b186` added the
PHP/Composer slice (`composer.lock`, `SCA-PHP-VULNERABLE_DEP-01`), and this ticket adds the Go slice
(`go.mod`/`go.sum`, `SCA-GO-VULNERABLE_DEP-01`) - see the detailed paragraph below.**
Each ecosystem has its own self-contained `sca_scan_*_tree` entry point, called from
`modules/sca/run.sh`'s `_sca_run_module`; most live in `modules/sca/engine.sh`, while PHP and Go each
landed in their own file (`modules/sca/php_engine.sh`, `modules/sca/go_engine.sh`) per that file's own
header instruction not to fork `run.sh` per ecosystem.
Neither the Java nor the PHP row of this paragraph was written by the ticket that shipped it:
`a1b3c43` and `7e7b186` both landed without updating this section, and `ab23b79` ("Fix stale
'Go/Java/PHP remain' SCA status text") had to go back and add them - the stale-doc failure the process
rule above exists to prevent, twice.
With Go landed, no §6.5 manifest format is outstanding; what step 4 still owes is its remaining
container/orchestration and CloudFormation IaC checks.
The next tasks are therefore step 3's remaining `nosql.rules`/`ldap.rules` and those remaining IaC
checks - not step 3 alone.

Because `checks_registry_load` (`lib/checks.sh`) globs every `*.rules` file under `modules/iac/` with
no per-pack allowlist, all three IaC packs load together on any `scan.sh iac` run - `tests/suites/iac.sh`
now scans `IAC-TF-*`, `IAC-HELM-*`, AND `IAC-DOCKER-*` ids in its `checks_run` integration section.

**Step 4's IaC half has also started landing, out of the strict step order and ahead of step 3's
`nosql`/`ldap` packs and of SCA (`docs/DESIGN.md` §13 groups SCA and IaC into one step 4, "both reuse the
rule engine") - this is not step 4 being done, only its IaC half being under way.**
Two tickets have landed on `modules/iac/` so far:

- The Terraform ticket (commit `5de4460`, "IaC: Terraform checks via the pattern-rule engine") shipped
  the shared IaC scaffolding - `modules/iac/run.sh` (the `scan_dispatch iac` entry point, reusing
  `modules/sast/engine.sh`'s `sast_evaluate_gate` and `sast_index_checks` unchanged rather than forking
  an IaC-specific copy) and `modules/iac/parse.sh` (`iac_scan_file`/`iac_scan_tree`, the same two-pass
  design as `sast_scan_file` with only the finding-emission path forked so `module` reads `iac`) - plus
  `modules/iac/terraform.rules` (seven `IAC-TF-*` checks: open CIDR, public ACL, unencrypted-at-rest,
  KMS key rotation disabled, public IP, hardcoded secret, RDS publicly accessible), scoped to `*.tf`
  only.
  This ticket landed without this section (or `docs/FOUNDATION.md`'s mirror) being updated - the same
  process-note failure §13 step 3e's own paragraph below already documents for `history.sh` - so
  `modules/iac/` existing was rediscovered by the next ticket reading the tree rather than the docs;
  this section and its mirror are corrected here to close that gap, which is what this paragraph and the
  process note above exist to keep from recurring.
- This ticket ("IaC: Kubernetes manifest checks via the pattern-rule engine") shipped
  `modules/iac/kubernetes.rules`: eight `IAC-K8S-*` checks (privileged containers, host
  network/PID namespace sharing, missing resource limits/requests, `runAsNonRoot` unset, plaintext
  secrets in env vars, the mutable `:latest` image tag, wildcard RBAC verbs/resources, and
  `automountServiceAccountToken` left at its default), scoped to plain Kubernetes YAML/JSON manifests
  and reusing `modules/iac/run.sh`/`parse.sh` unchanged (they were already technology-agnostic).
  Helm chart templates and CloudFormation templates are explicitly excluded by design - see the pack's
  own header comment for the case-sensitivity (Kubernetes' lowerCamelCase field names versus
  CloudFormation's PascalCase) and `context-deny` (`\{\{` for Helm, `AWSTemplateFormatVersion|AWS::` for
  CloudFormation, on the three absence-style checks) mechanisms that keep it out of scope for those two
  shapes even though the file glob overlaps.

Step 4 as a whole is still **not** done: SCA (lockfile parsing -> `advisories.db`) has not started, and
`docs/DESIGN.md` §6.6's Docker/docker-compose/Helm-**rendered**-chart checks and §8.2's CloudFormation
checks remain separate, unstarted IaC sub-scopes - `modules/iac/` currently holds only
`terraform.rules` and `kubernetes.rules`.

**Step 5 (DAST) now has a written, dependency-ordered sub-ticket plan, but is not started.**
`docs/STEP5-DAST-PLAN.md` breaks the ~30-script step 5 scope into tickets DAST-01 through DAST-30,
ordered per `docs/DESIGN.md` §13's own `lib/http.sh -> auth.sh -> crawl.sh -> passive -> safe-active ->
injection -> §7.4` sequence, and states plainly that `lib/http.sh`'s scope-gate chokepoint (tension 19)
already shipped (see below) and is not re-planned - only the still-unbuilt tension-16 rate
limiter/budget/breaker piece (DAST-01) and everything under `modules/dast/` remain.
**No DAST-0x ticket is picked up until step 3's `nosql`/`ldap` rule packs (above) and step 4's SCA half
(above - IaC's own half has started, SCA's has not) are both complete on `dev`** - this plan is a
written breakdown for later, not permission to start now.
(Step 4's IaC half is a separate sub-scope and has already begun landing - see above - but that does not
lift this gate, which names SCA specifically.)

**Step 8 (`--paranoid` / `tools/run-in-netns.sh`) is half landed: NETNS-01 has shipped; PARANOID-01 has
not.**
`docs/STEP8-PARANOID-PLAN.md` splits `docs/DESIGN.md` §13 step 8 into **PARANOID-01** (the `--paranoid`
connection-observer and abort-on-out-of-scope enforcement, per `docs/FOUNDATION.md` tension 20's
RESOLUTION) and **NETNS-01** (`tools/run-in-netns.sh`, the network-namespace runner - optional and
root-requiring, stated directly in that ticket's own filed description, not only in the plan doc).
Both were filed to the backlog as real tickets (Crewban-57 and Crewban-58 respectively).
**NETNS-01 (Crewban-58) has now landed**: `tools/run-in-netns.sh` (a Linux-only, root/CAP_NET_ADMIN
+CAP_SYS_ADMIN-requiring wrapper) builds a network namespace whose route table admits only two sets of
IPv4 addresses - the resolved addresses of scoursh's in-scope targets, via `lib/http.sh`'s own
`http_scope_load`/`http_resolve_host` (tension 19's pinned resolution cache, never a re-implementation),
and the nameservers parsed from `/etc/resolv.conf` (tension 20's "set 3") - installs NO default route
inside the namespace, and execs the wrapped command inside it via `ip netns exec`. Teardown (namespace,
veth, NAT/iptables rules, `ip_forward` restoration) runs from the tool's own EXIT trap on every exit
path, success or failure, staying inside the project's 0-5 exit-code contract throughout. It is never
invoked by `scan.sh` and has no dependency on PARANOID-01 - the two are independent, peer mechanisms per
tension 20's "guarantee vs detector" distinction. `tests/suites/netns.sh` tests it: argument parsing,
the CapEff bitmask arithmetic, the target-IP/nameserver collectors, and the build/teardown command
sequence are unit-tested against stubbed `ip`/`iptables`/`sysctl` on any host; the "fails immediately, no
isolation action, `<command>` never runs" non-Linux/no-privilege paths (this ticket's ACs 3-4) are
exercised as real subprocess invocations on whichever host the suite runs on; and a real, kernel-level
out-of-scope-connection-fails test (this ticket's AC2) is gated behind a genuine Linux+root/capability+
tooling probe and is honestly marked SKIPPED (not a silent pass) on a host that does not meet it.
IPv6 routing is out of scope for this tool (an in-scope host that only resolves to IPv6 is logged and
skipped, never routed) - a follow-up ticket for dual-stack support was filed separately, per this
ticket's own out-of-scope list.
**PARANOID-01 (the `--paranoid` observer/abort mechanism) remains unimplemented.**
Unlike the DAST plan above, step 8 was never gated on any unlanded step: this planning ticket's own
acceptance criteria named `lib/http.sh` (the tension-19 chokepoint) as step 8's blocker, and it was
confirmed present on `dev` before either sub-ticket started - it shipped early, out of its normal step-5
sequence, exactly as noted below. PARANOID-01 may still be picked up independently at any time; it does
not depend on NETNS-01 having landed, or vice versa.

**Step 6 (Cloud/AWS) now also has a written, dependency-ordered sub-ticket plan, but is not started.**
`docs/STEP6-CLOUD-PLAN.md` breaks the `docs/DESIGN.md` §13 step 6 scope (`regions.sh` iteration -> the
§8.1 live read-only catalog -> the read-only-verb CI lint -> `posture/` checks) into tickets CLOUD-01
through CLOUD-34 plus POSTURE-01 through POSTURE-04, and states plainly that `tests/lint-aws-readonly.sh`
(tension 23's read-only lint) already shipped at step 1 as a no-op stub that passes over an empty set -
it is not re-planned as new matching logic, only the still-missing `lib/awscli.sh` chokepoint it lints
against, the exception-file seeding, and the negative-fixture test are (CLOUD-03). It also records that
the one IaC ticket already landed on `origin/dev` (`modules/iac/`, "IaC: Terraform checks via the
pattern-rule engine") is step 4's `docs/DESIGN.md` §8.2 work, not step 6's, and is out of this plan's
scope for that reason. **No CLOUD-0x or POSTURE-0x ticket is picked up until step 3's remaining
`nosql`/`ldap` packs, step 4 (SCA + IaC), and step 5 (DAST) are all complete on `dev`** - step 6 is
gated on the whole sequential chain in front of it, not just step 4, and this plan is a written
breakdown for later, not permission to start now.

**PARANOID-01 has now landed - `lib/paranoid.sh` implements `--paranoid` for real.**
It builds the four-set allowlist tension 20's RESOLUTION specifies (`paranoid_allowlist_build`).
It attaches a connection sampler (`ss`, or a measured-usable `strace -f -e trace=connect` fallback -
`paranoid_probe_backend`), aborts the run with exit `3` (`SCOURSH_EXIT_SCOPE`) on the first observed
destination outside that allowlist, and exits `4` (`SCOURSH_EXIT_INPUT`) when neither backend is
available or permitted.
It is wired into `scan.sh`'s `scan_main` right after config loads and before any module dispatch.
`tests/suites/paranoid.sh` is the deterministic no-egress fixture tension 20 calls for.
`SCOURSH_PARANOID_FORCE_BACKEND`/`SCOURSH_PARANOID_SAMPLE` stand in for the ss/strace probe and the
sampler itself (the same swappable-hook idiom `lib/http.sh`'s `SCOURSH_HTTP_RESOLVE`/
`SCOURSH_HTTP_TRANSPORT` already use).
So the suite never depends on `ss`/`strace` actually being installed - both are Linux-only, and this
project's CI matrix runs macOS too.
One correction surfaced while building this ticket, recorded in full in `docs/FOUNDATION.md` tension
20's own "Implementation" paragraph: the observer and the abort's kill action are scoped to the
DESCENDANT-PROCESS FAMILY rooted at the main `scan.sh` pid, not the raw OS process group tension 20's
prose names.
A plain `cmd &` never changes pgid, so scoping to the real process group would have let a violation's
`kill -TERM` reach unrelated processes sharing that group by accident - measured directly: it took out
this project's own test harness before the fix.
`tools/run-in-netns.sh` (NETNS-01) is **not** implemented by this ticket, exactly as
`docs/STEP8-PARANOID-PLAN.md` scoped it - it remains a separate, independently-schedulable,
root-requiring ticket.

**Step 3a-3d shipped the SAST module's rule packs and engine.**
Four tickets landed, in this order:

- **3a** (`6f25a67`, "SAST: native pattern engine + seed secrets/crypto/injection/python rules")
  shipped `modules/sast/engine.sh` (the native pattern engine: walks the repo, applies per-language
  rule packs, matches only through `lib/core.sh`'s `scan_match` family per tension 4 rule 2, and
  implements the `context` directive - the first ticket to evaluate it at all), `modules/sast/run.sh`
  (the `scan_dispatch sast` entry point, sourced rather than subprocessed per its own header), and
  four rule packs: `modules/sast/rules/secrets.rules`, `crypto.rules`, `injection.rules`, and
  `python.rules`.
  It also closed finding F4 (the `context-deny` window contradiction between `rules/RULE-FORMAT.md`
  §12.1 and §12.2); see `docs/FOUNDATION.md` "Known follow-ups" for the closure detail.
- **3c** (`754a994`, "SAST: seed Go rule pack") shipped `modules/sast/rules/go.rules`.
  It landed before 3b in commit order even though it is lettered after it; the letter is a step-3
  sub-label from the ticket titles, not a landing-order guarantee.
- **3b** (`446f642`, "SAST: seed JS/TS rule pack") shipped `modules/sast/rules/javascript.rules`.
- **3d** (`910d2c7`, "SAST: seed Java rule pack") shipped `modules/sast/rules/java.rules`: `Runtime.exec`
  is deliberately *not* re-declared under a new `SAST-JAVA-*` id, since `injection.rules`' existing
  `SAST-INJ-OS_COMMAND-01` already carries `Runtime.getRuntime().exec(` as one of its alternatives; the
  pack instead adds JDBC statement concatenation, XML parsers missing `disallow-doctype` (an absence
  check, `context-deny` with a non-zero window), unsafe `readObject` deserialization, a trust-all
  `X509TrustManager`/`HostnameVerifier` pair (two ids, one per code shape), and SpEL/OGNL injection (two
  ids, one per library). It landed after 3e in commit order, out of letter order, same as 3c did for 3b.

`modules/sast/rules/` now holds **seven** packs on disk: `secrets.rules`, `crypto.rules`,
`injection.rules`, `python.rules`, `go.rules`, `javascript.rules`, and `java.rules`.
Do not undercount this to six (or five) from an individual ticket's own description - a ticket written
before 3d (or 3c) landed will list fewer; check the directory, not the ticket text.

**Step 3e shipped `history.sh`, landing after 3a-3c and out of letter order (§13 lists it last in the
step-3 sentence, but it is not "3d").**
`18c4c3f` ("SAST: history.sh - replay secrets.rules across git history (§13 step 3e)") shipped
`modules/sast/history.sh` (429 lines): it replays `modules/sast/rules/secrets.rules` against git
history rather than the working tree, bounded by a commit/time window per `docs/DESIGN.md` §6.3, and
populates the `SAST-HIST-*` check family - including the `history` fingerprint profile (`blob_sha`,
`match_digest`, `occurrence`) and the per-finding `oldest_reaching_commit_time` that tension 13's
boundary test and tension 6 condition (b1) read once `state/` exists at step 7.
`tests/suites/sast-history.sh` (295 lines) tests it.
`modules/sast/` now has all three files `docs/DESIGN.md` §13 step 3 names for it: `engine.sh`, `run.sh`,
and `history.sh`; 3d then shipped `java.rules` after 3e (see above), so only the `nosql` and `ldap` rule
packs are still missing.

**Findings still open after 3a-3d and 3e, and the step each is inherited by:**

- **F5 and F20** - `rules/derived.rules` still does not seed `COMPOSITE-TOKEN-HIJACK`, because its
  contributors do not exist until steps 5 and 6.
  Seeding it now is a guaranteed `E051`/`E060` lint failure.
- **F17** - `aws_ro` pins `--no-cli-pager`, which AWS CLI v1 rejects.
  Lands with step 6 (cloud), when `lib/awscli.sh`'s first real caller ships.

F3, F4, F8, and F16's `look` half are closed (F3 and F8 as of step 2's `lib/checks.sh`; F4 as of 3a
above; F16's `look` half as of `lib/core.sh`'s `db_lookup_exact` and its new `tests/suites/core.sh`
test - see `docs/FOUNDATION.md`'s "Known follow-ups" for the full closure detail); do not re-flag any
of them.

**`main` can lag `dev` - check `dev`, not just `main`, before declaring a dependency unlanded.**
This project develops on `dev` and merges to `main` in batches, so a checkout of `main` can be several
merged tickets behind what `dev` already has.
An earlier agent run on the 3b ticket read a `main` checkout where `modules/` was genuinely still
absent, concluded the 3a dependency (and this stale memory) meant the work hadn't landed, and moved the
ticket to `blocked` - when 3a had in fact already merged to `dev`.
Before concluding a dependency is missing, check the actual workspace branch and, if it is behind, check
`dev`'s tip rather than trusting `main` or this file's prose alone.

**A ticket can never cite its own landing sha, because the squash merge mints that sha afterwards.**
Landings reach `dev` as squash commits, so the sha a ticket's own branch carries is not the sha its work
ends up with, and a ticket writing "`<sha>` (this ticket)" into these docs is guessing at a commit that
does not exist yet and generally never will.
This has already happened three times and shipped every time: `ae03175` (the Dockerfile slice, really
`25abfa3`), `11e7c97` (the Ruby SCA slice, really `a2d37aa`) and `d7a746f` (the Kubernetes IaC slice,
really `bb75c9b`) - eight references between them across `AGENTS.md` and `docs/FOUNDATION.md`, none of
which `git cat-file -e` could resolve until this change corrected them.
The third one landed while this very change was in review, which is the argument for the rule.
Write the landing in prose without a sha ("this ticket adds ..."), and let the next ticket that touches
the paragraph fill in the real one.
Before trusting any sha in these two files, resolve it:

```sh
grep -ohE '`[0-9a-f]{7,40}`' AGENTS.md docs/FOUNDATION.md | tr -d '`' | sort -u |
  while read -r s; do
    git cat-file -e "$s^{commit}" 2>/dev/null || echo "MISSING $s"
  done
```

It has exactly five known false positives, all in prose rather than in a citation: the two decimal/octal
IPv4 literals in `docs/FOUNDATION.md` tension 19's SSRF text (`2851995906`, `025154325002`), which are
not shas at all, and `ae03175`/`11e7c97`/`d7a746f` in the paragraph immediately above, which this note
quotes on purpose as the bad values to recognise.
Anything else it reports is a real reference to a commit that does not exist, and is a bug.

**A Crewban ticket that is `done` with `landed_sha` NULL is usually a bookkeeping gap, not stranded
work - prove the work is really unlanded before rescuing it by hand.**
Because every landing squashes, `git log origin/dev..<branch>` reports "1 commit ahead" for a branch
whose content is *already fully merged*, so commits-ahead is not evidence of anything.
The test that actually discriminates is `git cherry origin/dev origin/<branch>`: a leading `-` means the
patch is already upstream, `+` means it is not.
Confirm a `-` by comparing trees (`git rev-parse <branch>^{tree}` against the `dev` commit that landed
it); identical trees mean there is nothing to rescue and the correct outcome is to say so, not to open
an empty PR.
Two shapes cause the NULL: a landing job recorded against a sibling ticket that shared the branch, and
"merger" tickets (`crewban/resolve-merge-conflict-*`), which resolve the conflict in the *source*
ticket's workspace on the *source* ticket's branch and so frequently own no branch of their own.
Unpushed agent work, if any exists, lives outside this repo in the harness's per-ticket clones - at the
time of writing `~/.ace/workspaces/<ticket-uuid>`, a pre-rename path still in use by Crewban.
Sweep those with `git rev-list HEAD --not --remotes=origin` plus `git stash list` before concluding a
branch missing from `origin` means the work is lost; a commit found that way still has to be compared
against `dev` artifact by artifact, since it is usually a superseded draft of what already landed.

**One piece of step 5 landed out of sequence: `lib/http.sh` (the scope-gate chokepoint,
docs/FOUNDATION.md tension 19) now exists**, built and reviewed as its own ticket once tension 19's
contract itself was signed off, rather than waiting for steps 2-4.  It has no dependency on `scan.sh`,
SAST, or SCA/IaC - it is a self-contained URL-normalization/tuple-match/deny-list/redirect-loop library
over `config/scope.conf` - so pulling it forward cost nothing those steps would otherwise have blocked.
`modules/dast/`, the rate limiter/request budget/circuit breaker (tension 16), and IDN/general-IPv6-CIDR
support (both explicitly out of scope for this ticket) still arrive at step 5 proper.  Do not read this
paragraph as "step 5 is done" - see "Current position" above for what is actually next.
`docs/STEP5-DAST-PLAN.md` is the sub-ticket breakdown for that remaining step-5 work and already excludes
`lib/http.sh` from its "still to plan" list, since this paragraph is where that fact is recorded.

**A second piece of a later step also landed out of sequence: `modules/iac/` (step 4's IaC half) now
exists - in three separate landings, and still only partial.**
`5de4460` ("IaC: Terraform checks via the pattern-rule engine (§13 step 4)") shipped `modules/iac/run.sh`
(the `scan_dispatch iac` entry point), `modules/iac/parse.sh` (the Terraform HCL parser), and
`modules/iac/terraform.rules`, run through the same native pattern engine `modules/sast/engine.sh` built
at step 3a.
`terraform.rules` seeds seven checks: `IAC-TF-OPEN_CIDR-01`, `IAC-TF-PUBLIC_ACL-01`,
`IAC-TF-UNENCRYPTED-01`, `IAC-TF-KEY_ROTATION_DISABLED-01`, `IAC-TF-PUBLIC_IP-01`,
`IAC-TF-HARDCODED_SECRET-01`, and `IAC-TF-RDS_PUBLIC-01`.
`tests/suites/iac.sh` tests it.
A second landing, `add2b21` ("IaC: Helm chart checks via the pattern-rule engine (§13 step 4)"),
added `modules/iac/helm.rules`: three checks (`IAC-HELM-HOST_PORT-01`, `IAC-HELM-HOST_MOUNT-01`,
`IAC-HELM-HARDCODED_SECRET-01`) against Helm chart sources only (`values.yaml` and
`templates/*.yaml`) - its own header states that scope discipline explicitly (never a docker-compose
file, never a bare non-Helm Kubernetes manifest) and its own "KNOWN GAP" note confirms no
`modules/iac/kubernetes.rules` (or any other Kubernetes-manifest pattern pack) exists on `dev` as of
that landing.
A third landing, `25abfa3` ("IaC: Dockerfile checks via the pattern-rule engine (§13 step 4)") added
`modules/iac/dockerfile.rules`: six checks (`IAC-DOCKER-ROOT_USER-01`,
`IAC-DOCKER-LATEST_TAG-01`, `IAC-DOCKER-SECRET_ENV-01`, `IAC-DOCKER-REMOTE_ADD-01`,
`IAC-DOCKER-PIPE_TO_SHELL-01`, `IAC-DOCKER-UNPINNED_DIGEST-01`) scoped strictly to `Dockerfile`,
`Dockerfile.*`, and `*.dockerfile` - `docker-compose*.yml` and Helm `values.yaml` are deliberately NOT
in this pack's `files:` list, per `docs/DESIGN.md` §3's original combined `containers.rules` sketch
being deliberately split one-format-per-file.
So §6.6's container/orchestration catalog has now landed its Helm-values and Dockerfile slices: only
bare Kubernetes-manifest checks and docker-compose checks are still open, and so is CloudFormation -
this remains **Terraform + Helm-values + Dockerfile only**.
`modules/` as a whole now ships **ten** pattern packs on disk - the seven under `modules/sast/rules/`
plus `modules/iac/terraform.rules`, `modules/iac/helm.rules`, and `modules/iac/dockerfile.rules` - which
is the count `tests/lint-rules.sh`'s E060 fixture-coverage note now reports.
It landed ahead of step 3's remaining `nosql`/`ldap` rule packs and ahead of step 4's own SCA half, the
same "land what's ready, out of strict step order" pattern as `lib/http.sh` above.
`nosql`/`ldap`, the rest of §6.6's container/orchestration catalog (bare Kubernetes manifests and
docker-compose), and CloudFormation all remain open; do not read this paragraph as "step 4 is done."
Step 4's SCA half is covered in its own paragraph below and, with the Go slice, has landed every
ecosystem `docs/DESIGN.md` §6.5 names - npm, Python, Ruby, Java, PHP, and Go.

**A third piece of step 4 has now landed, in three sub-tickets: `modules/sca/` (the SCA module's npm,
Python, and Ruby slices).**
`ed8c283` ("SCA: parse npm lockfiles and match against data/advisories.db") shipped `modules/sca/run.sh`
(the `scan_dispatch sca` entry point - no check-registry gate, unlike SAST/IaC, since SCA is a table
lookup rather than a pattern-rule engine) and `modules/sca/engine.sh`: lockfile discovery,
`package-lock.json` (v1 and v2/v3), `yarn.lock`, and `pnpm-lock.yaml` parsing, npm's own (identity)
name normalisation, and the `data/advisories.db` exact-match lookup (`sca_lookup_exact`/
`sca_package_known`, both routed through `lib/core.sh`'s `db_lookup_exact` per tension 25), emitting
`SCA-NPM-VULNERABLE_DEP-01` and the `SCA-COV-UNKNOWN_VERSION-01` roll-up.
A follow-on ticket ("SCA: parse Python lockfiles and match against data/advisories.db") then added the
module's Python slice on top of that same `run.sh`/`engine.sh` split, exactly as `run.sh`'s own header
comment anticipated for a sibling ecosystem: `requirements.txt`, `poetry.lock`, and `Pipfile.lock`
parsing, PEP 503 name normalisation (`sca_pypi_normalize_name`), and `SCA-PY-VULNERABLE_DEP-01`
findings under ecosystem `pypi`, plus its own `SCA-COV-UNKNOWN_VERSION-01` roll-up - a separate finding
from npm's own when both ecosystems have unknown-version cases in the same run, a stated scope limit
rather than a true cross-ecosystem merge (see `modules/sca/engine.sh`'s `sca_scan_python_tree` header
comment).

`a2d37aa` ("SCA: parse Ruby Gemfile.lock and match against data/advisories.db (§13 step 4)") then added
Ruby/RubyGems, in `modules/sca/engine.sh` alongside the npm parser rather than a forked file:
`sca_parse_gemfile_lock` (Gemfile.lock's `GEM`/`GIT`/`PATH` `specs:` blocks - already flat, one resolved
gem per 4-space-indented line, so unlike npm v1 no recursion is needed), `sca_ruby_normalize_name`
(lowercase, tension 25's RubyGems rule - unlike npm's identity function), and direct-vs-transitive
classified from the lockfile's own top-level `DEPENDENCIES` stanza versus a specs-only entry.  It mints
`SCA-RUBY-VULNERABLE_DEP-01` via the same `_sca_emit_finding` the npm path uses, now dispatched by
ecosystem (`_sca_check_id_for_ecosystem`) rather than hardcoded to npm's own check id.
UNLIKE Python, Ruby joined npm's OWN shared `sca_scan_tree` call rather than getting a sibling function:
`sca_scan_tree` (`modules/sca/engine.sh`) now walks BOTH npm's and RubyGems' lockfiles in one call and
shares one `unknown_count` table across them, because two separate `sca_scan_tree` calls would emit two
`SCA-COV-UNKNOWN_VERSION-01` findings that collide on one fingerprint (it carries no
ecosystem/package/advisory_id component) - `findings_merge`'s dedup would then silently drop whichever
ecosystem lost the sort instead of merging their counts.  `sca_scan_python_tree` (the Python slice, see
above) still runs as its own separate call for the same reason it always did - to avoid touching
`sca_scan_tree`'s already-tested npm code path - so a run with unknown-version cases in both an npm/Ruby
lockfile AND a Python one still emits two separate roll-up findings; that gap is stated and filed, not a
defect either the Python or Ruby ticket needed to fix.
`tests/suites/sca.sh` proves the npm+Ruby merge concretely with a `mixed-ecosystems` fixture carrying
both an npm lockfile and a Gemfile.lock, asserting exactly one roll-up finding whose breakdown names
both ecosystems, and separately tests the Python slice and the real `scan.sh sca` end-to-end path for
all three ecosystems.
`tests/fixtures/sca/advisories.db` now carries `npm`, `pypi`, and `RubyGems` fixture rows, with the npm
and RubyGems rows sorted together under `LC_ALL=C` (tension 25's own `look`-compatible sort
requirement).

Java (`pom.xml`/`build.gradle`, `a1b3c43`) and PHP/Composer (`composer.lock`, `7e7b186`) landed after
that paragraph was written, each without updating this section; `ab23b79` went back and corrected the
"still open" sentences for both.

**The Go slice (`go.mod`/`go.sum`) landed last, and is the first SCA ecosystem to ship as its own
engine file: `modules/sca/go_engine.sh`.**
PHP had already broken `engine.sh`'s monopoly with `modules/sca/php_engine.sh`, but PHP's parser is
still driven from inside `sca_scan_tree`; Go is fully standalone - `sca_go_scan_tree` is its own entry
point, called from its own `_sca_go_run` in `modules/sca/run.sh`, exactly as that file's own header
invited a further ecosystem to land ("do not fork this file per ecosystem").
It parses `go.mod`'s `require` lines (single-line and block form), reading a trailing `// indirect`
comment as the direct-vs-transitive signal, and falls back to `go.sum` when no `go.mod` sits beside it -
in which case `dependency_type` is reported **`unknown`**, never guessed.
`go.mod` wins when both are present in one directory.
Normalisation follows tension 25's frozen Go row: the `/vN` major-version suffix is **retained** and a
`+incompatible` version suffix is **stripped** before the `data/advisories.db` lookup, and both halves
are pinned by a test that fails under the naive opposite reading.
`replace`/`exclude` directives are **not** resolved - a stated limitation recorded in
`go_engine.sh`'s own header and surfaced at runtime as a
`reason=go_replace_exclude_directives_not_resolved` coverage_reduction, not hidden.
`sca_go_scan_tree` does its own `data/advisories.db`-readable check (unlike `sca_scan_python_tree` and
`sca_scan_java_tree`, which rely on `_sca_npm_run` having gone first), so `_sca_go_run` carries no
ordering requirement; it is still called last for a stable emission order.
Like Python and Java, Go emits its **own** `SCA-COV-UNKNOWN_VERSION-01` roll-up rather than joining
npm/Ruby/PHP's shared one - the same stated, filed cross-ecosystem-merge gap, not a new one.
With Go landed, step 4's SCA half covers every §6.5 manifest format; `tests/fixtures/sca/advisories.db`
now carries `Go` rows alongside `npm`, `pypi`, `RubyGems`, `composer`, and `maven`, all sorted together
under `LC_ALL=C` (tension 25's `look`-compatible sort requirement).

**A third piece of step 4's IaC half has since landed on top of the Terraform one above:
`modules/iac/docker-compose.rules` (the "IaC: docker-compose checks via the pattern-rule engine"
ticket).**
docs/DESIGN.md §6.6 bundles docker-compose in with Dockerfile/Kubernetes/Helm under one prose
"containers.rules" bullet, but none of the decomposed IaC tickets had claimed the docker-compose slice
itself; this ticket closes exactly that one gap, reusing `modules/iac/run.sh`/`parse.sh` unchanged (they
already existed from the Terraform landing above) and adding only the new flat pack file plus its
fixtures.
`docker-compose.rules` seeds four checks: `IAC-COMPOSE-EXPOSED_PORT-01` (a host port bound without
restricting the interface), `IAC-COMPOSE-PRIVILEGED-01` (`privileged: true`),
`IAC-COMPOSE-SENSITIVE_MOUNT-01` (a host bind mount of `/var/run/docker.sock`, `/etc`, `/root`, `/home`,
`/proc`, `/sys`, or `/` itself), and `IAC-COMPOSE-PLAINTEXT_SECRET-01` (a literal credential value in an
`environment:` entry, rather than a `${VAR}`/`env_file:` reference).
Its `files:` globs match `docker-compose.yml`/`compose.yml` (and their `.yaml`/override-variant forms)
only - `tests/suites/iac.sh` has a dedicated cross-shape section proving a Kubernetes-manifest-shaped and
a Helm `values.yaml`-shaped fixture, each deliberately carrying content that would trip every
`IAC-COMPOSE-*` check if the engine ever inspected file content, still produce zero findings, and that a
mixed directory holding one file of each IaC shape never lets a check cross-attribute to the wrong file.
`modules/` as a whole now ships **nine** pattern packs on disk (the eight above plus this one), which is
the count `tests/lint-rules.sh`'s E060 fixture-coverage note now reports.
Dockerfile, Kubernetes-manifest, Helm-chart, and CloudFormation IaC rules remain unclaimed by any landed
ticket - do not read this paragraph as "step 4's container-rules bullet is done," only its
docker-compose slice is.

Step 1 delivered `lib/records.sh`, `lib/core.sh`, `lib/findings.sh` and `lib/report.sh`, plus
`rules/redaction.rules`, `data/severity-rubric.conf`, the `config/*.example` files, a fixture
end-to-end path under `tests/e2e/`, and the test suite.
The six findings that blocked it (F13, F14, F12, F15, F16, and F18 by consequence) are **closed**, each
in the tension that owns it; see `docs/FOUNDATION.md` "Known follow-ups".

Step 2 delivered `scan.sh` (the §5 CLI grammar, tension 14's exit-code precedence, and wiring
`lib/config.sh` ahead of dispatch) and, in a later ticket, `lib/checks.sh` (tension 15's check-set
filter chain and registry loader, wired into `scan.sh` via `_scan_apply_profile_filter` ahead of every
`scan_dispatch`).
Findings F3 (which of two incompatible readings decides the `compliance` profile - settled on the TAG
reading) and F8 (`derived` checks are exempt from the `--intensity` ceiling) are **closed** as part of
that; see their entries in `docs/FOUNDATION.md` "Known follow-ups", and tension 15's own RESOLUTION,
both amended in the same change.
`lib/checks.sh` also wires `SCOURSH_SELECTED_CHECKS`, the env var `lib/findings.sh`'s
`_derived_record_selected` was already reading at step 1 in anticipation of this filter chain landing.

**What steps 1 and 2 deliberately did not build**, so the boundary is not rediscovered: anything under
`modules/`, `lib/http.sh`, `lib/engines.sh`, `lib/awscli.sh`, SARIF, the compliance report, any shipped
rule pack, and `state/`.
`lib/http.sh` landed anyway, out of sequence - see above.
**Step 3a-3d and 3e then filled in most of that gap**: `modules/sast/` (with `engine.sh`, `run.sh`,
AND `history.sh` - see above) and its seven rule packs now exist, so `scan_dispatch sast` no longer
no-ops and `_scan_apply_profile_filter` finds a non-empty registry for SAST checks.
**The IaC-Terraform, IaC-Helm, and IaC-Dockerfile tickets (see the step 4 paragraph above), and this
Kubernetes ticket on top of them, then did the same for `modules/iac/`**: it now holds `run.sh`,
`parse.sh`, `terraform.rules`, `helm.rules`, `dockerfile.rules`, and `kubernetes.rules`, so
`scan_dispatch iac` no longer no-ops either and `_scan_apply_profile_filter` finds a non-empty registry
for IaC checks (including `IAC-K8S-*`) too - `modules/iac/` is removed from the "do not exist yet"
list below accordingly.
Everything else in the original list is still true: `modules/dast/`, `modules/cloud/`, `lib/engines.sh`,
`lib/awscli.sh`, SARIF, the compliance report, and `state/` do not exist yet.
`modules/sca/` also landed anyway, out of sequence - see above - and now holds `run.sh`, `engine.sh`,
`php_engine.sh`, and `go_engine.sh`.
Every `scan_dispatch` call for a module other than `sast`, `iac`, or `sca` remains a logged
`coverage_reduction` no-op (`reason=not_yet_built`); `scan_dispatch sca` is no longer one of them, since
`modules/sca/run.sh` now does real work for npm/yarn/pnpm, Python, RubyGems, Maven, Composer, and Go.
`sca` is DIFFERENT from that group in a way worth stating precisely, since it is easy to conflate the
two separate coverage_reduction mechanisms `scan.sh` has: `scan_dispatch sca` itself no longer no-ops
(its `reason=not_yet_built` no longer fires - `modules/sca/run.sh` is real), but
`_scan_apply_profile_filter sca` still records `reason=no_check_registry_on_disk_yet` on every run, and
always will - by design, not because the module is unbuilt.
`_scan_apply_profile_filter`'s check-registry side loads check ids from on-disk `*.rules` files
(`checks_registry_load`), and `modules/sca/` ships none: SCA is a table lookup against
`data/advisories.db`, not a pattern-rule engine, so it has no `modules/sca/checks.rules` registry to
ever populate (`modules/sca/run.sh`'s own header states this explicitly) and its findings are emitted
directly by the engine files instead.
Both mechanisms are real and tested against fixtures.
Diff classification (tension 12) and baseline suppression (tension 11 steps 5 and 6) belong to step 7;
step 1 ships the primitives they call - the merge, the fingerprint, `findings_mark_suppressed`, and
`classify_derived`, which is pure and already tested against tension 6's whole case table.

**Two run.json fields are deliberately empty at step 1**, rather than absent, so a
consumer never has to handle a missing key and the gap is visible in the output:

- `regions` is `[]`. Region iteration is `modules/cloud/aws/regions.sh` at step 6;
  nothing before it visits a region, and inferring regions from a finding's cell
  would report where findings happened to land rather than where the run looked.
- `run_identity` is absent. `docs/FOUNDATION.md` tension 18 records it in
  run.json, but its inputs include the normalised CLI flags, which arrive with
  `scan.sh` at step 2.

`checks_run` is the set of checks the run LOADED AND EXECUTED. It is not
tension 12's `covered_checks`, which is per-(check, cell) coverage persisted in
`state/` and owned by step 7: a check can be in `checks_run` and still be
uncovered for a cell the run never visited.

`rules/derived.rules` is **not** seeded, and that is deliberate: findings F5 and F20 record that
`COMPOSITE-TOKEN-HIJACK`'s contributors do not exist until steps 5 and 6, so seeding it now is a
guaranteed `E051` lint failure.  The derived *mechanism* is delivered and is tested against a fixture
composite under `tests/fixtures/rules/derived.rules`.

**Read `docs/FOUNDATION.md` "Known follow-ups" before starting step 2.**
Six findings remain open (F4, F3, F5, F20, F8, F17, plus F16's `look` half); all are cheap corrections
that cost nothing to defer, and each names the step it must land before.
This is a snapshot from before step 2 landed and is kept for history; it is stale on its own.
F3, F4, and F8 have since closed (see "Findings still open after 3a-3d and 3e" above for the current list:
only F5, F20, F17, and F16's `look` half remain).

Two amendments to §13 come from `docs/FOUNDATION.md` and applied from the start:

- `lib/records.sh` (the record parser) is built **before** step 1's stated contents, since tensions 1, 6, 9, 15, and 26 all depend on it.
- `lib/awscli.sh` is added to the layout and lands at the start of step 6, before any `aws/live/*.sh` script exists, so no script is ever written against a bare `aws`.

## Tests

```
tests/run-tests.sh                 # everything: every suite plus every linter
tests/run-tests.sh --list          # the source of truth for exactly which suites and linters exist today
tests/run-tests.sh <suite-name>    # one suite, e.g. tests/run-tests.sh sca
tests/run-tests.sh lint-rules      # or one linter by name
tests/lint-rules.sh                # record-format linter, error codes in rules/RULE-FORMAT.md §13
tests/lint-shell.sh                # the tension 4, 9, 24 and 26 shell lints
tests/lint-aws-readonly.sh         # read-only AWS lint, docs/FOUNDATION.md tension 23
tests/e2e/fixture-scan.sh <dir>    # the end-to-end path on its own, for eyeballing a report
```

**`tests/run-tests.sh --list` is the source of truth for the current suite and linter names, not this
paragraph.**
This file used to hand-copy that list (as "eight suites: records | core | config | checks | findings |
report | http | e2e | scan"), and it silently went stale the moment `sast`, `sast-history`, `sca`, `iac`,
`exit-code-matrix`, `gate-mutation-proof`, and `ci-smoke` were registered - each addition is a one-line
edit to `SUITES=(...)` in `tests/run-tests.sh` itself (`docs/CI-RUNBOOK.md` checklist item 8) that this
doc has no way of tracking automatically. Run `tests/run-tests.sh --list` to see what actually exists;
do not hand-maintain a duplicate enumeration here or trust one written before your current checkout.

See `docs/CI-RUNBOOK.md` for what CI actually runs, which checks are required on protected branches, the GNU/BSD dual-runner rationale, and the checklist for adding a new required check.

`package.json` at the repository root exists **only** so the conventional `pnpm test` / `npm test`
entry point runs the real suite above.
`pnpm test` is a thin alias for `bash tests/run-tests.sh`: no dependencies, no lockfile, no
`node_modules`, no build step.
scoursh has no Node runtime dependency and is not becoming a Node project; the shell entry point,
`tests/run-tests.sh`, remains the real one and the one to run directly when Node/npm/pnpm are not on
the box.
Anyone tempted to add a dependency, a devDependency, or tooling config to `package.json` has
misunderstood why it exists - don't.

Each suite runs in its own process, because `lib/core.sh` installs traps, sets shell options and owns a
scratch directory: a suite sharing a shell with another would not be testing what the tool does.
`shellcheck` runs over everything if it is installed and is skipped with a notice if it is not, since an
air-gapped host may not have it.

**Every test that pins a decision names the reading it fails under.**
That is not a style preference: review round 5 found that four rounds had all written the test after the
rule, so every suite agreed with its author's reading and certified the defect green.
A test that passes under both the correct and the rejected reading pins nothing and is worse than no
test, because it buys false confidence.

What the suite covers now, per `docs/DESIGN.md` §12 and the resolutions above:

- Every worked example in `rules/RULE-FORMAT.md` §12 and every negative example in §12.6, with the right error code at the right line and column.
- Fingerprint stability under reindentation and line shifts; five byte-identical matches in one file yielding five fingerprints; no duplicate fingerprint in the merged output.
- Tension 6's derived-finding case table, including cases 5, 6, 7, 8 and 9, each of which the round-2 rule returned `fixed` for.
- Redaction across all four output formats, with two distinct secrets yielding two distinct digests.
- Hostile evidence: a script tag, an ANSI sequence, a raw newline, invalid UTF-8 and a backtick run, asserted escaped in every emitter, with the CSP present and no `<script>` in the HTML.
- Byte-reproducible `findings.jsonl` across two runs.
- The five closed findings, each with a test that fails under the original implementation.

Still to come with their steps: SARIF schema validation (step 10), the read-only lint over a non-empty
`aws/live/` (step 6), a no-egress run under `--paranoid` (step 8), and byte-identical findings between
GNU and BSD userlands, which needs CI on both (`.github/workflows/ci.yml` runs the matrix).

## Things measured on this codebase, not assumed

Recorded because the review rounds found several confidently-stated shell facts that were simply wrong.

- `local a=$1 b=${#a}` gives `b=0`. Assignments in one `local` do not see each other; use two lines.
- Bash resets trapped `EXIT` actions in subshells. `xargs -P` workers are fresh processes and DO run them.
- A side-effecting function called as `$(f)` runs in a subshell and its writes are discarded. `occurrence_next` and `worker_id_set` therefore SET a variable rather than printing one; getting this wrong silently collapses every repeated match onto one fingerprint.
- BSD awk evaluates the source constant `0x80` as `0`, so hex literals are a GNU extension. The UTF-8 validator is pure bash for that reason.
- Bash's `=~` uses the system regcomp, which on macOS/BSD supports none of `\b`, `\w`, `\s`, `\d`. `grep -E` and `rg` support all four on both userlands. `redact()` therefore routes through the engine wrapper rather than matching in-process.
- `-n -b -o` produces byte-identical output under ripgrep 15.1.0 and BSD grep 2.6.0-FreeBSD, which is what `rules/RULE-FORMAT.md` §10.3's per-match ordinal needs.
- `printf '--- ...'` is parsed as options by bash's builtin printf; use `printf -- '--- ...'`.
- `find` over a directory that does not exist fails, and under `pipefail` takes the whole pipeline with it.
- ShellCheck versions disagree: Ubuntu's reports `SC2119`/`SC2120` where 0.11.0 does not. CI runs whatever the image ships, so a finding is silenced with an explicit `# shellcheck disable=` and a reason rather than left to the version.
- A comment line beginning `# shellcheck ` is parsed as a DIRECTIVE, so prose about shellcheck must not start a line with that word.
