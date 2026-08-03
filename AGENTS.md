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

**Current position: §13 steps 1 and 2 are done, and step 3 is under way.**
Step 3's sub-steps 3a, 3b, 3c, 3d, and 3e have landed on `dev`.
Step 3 as a whole is still not finished: `docs/DESIGN.md` §6.3's rule catalog also calls for the
`nosql` and `ldap` rule packs, and neither has landed yet.
Every per-language pack the catalog names - `python`, `javascript/ts`, `go`, and now `java` - has
shipped; nothing beyond `nosql.rules`/`ldap.rules` remains under the "language" heading.
`history.sh` (the `SAST-HIST-*` mechanism, tension 13) already shipped as 3e (see below); do not
re-list it as outstanding.
The next task is the remainder of step 3 (`nosql.rules` and `ldap.rules`).
Step 4's IaC half has also landed, out of sequence and ahead of step 3's remaining `nosql`/`ldap` sub-steps (see below).
Step 4's SCA half has not landed.

**Step 5 (DAST) now has a written, dependency-ordered sub-ticket plan, but is not started.**
`docs/STEP5-DAST-PLAN.md` breaks the ~30-script step 5 scope into tickets DAST-01 through DAST-30,
ordered per `docs/DESIGN.md` §13's own `lib/http.sh -> auth.sh -> crawl.sh -> passive -> safe-active ->
injection -> §7.4` sequence, and states plainly that `lib/http.sh`'s scope-gate chokepoint (tension 19)
already shipped (see below) and is not re-planned - only the still-unbuilt tension-16 rate
limiter/budget/breaker piece (DAST-01) and everything under `modules/dast/` remain.
**No DAST-0x ticket is picked up until step 3's `nosql`/`ldap` rule packs (above) and step 4's SCA half
are both complete on `dev`** - this plan is a written breakdown for later, not permission to start now.

**Step 8 (`--paranoid` / `tools/run-in-netns.sh`) now has a written sub-ticket plan, split into two
independently schedulable tickets, and neither is blocked.**
`docs/STEP8-PARANOID-PLAN.md` splits `docs/DESIGN.md` §13 step 8 into **PARANOID-01** (the `--paranoid`
connection-observer and abort-on-out-of-scope enforcement, per `docs/FOUNDATION.md` tension 20's
RESOLUTION) and **NETNS-01** (`tools/run-in-netns.sh`, the network-namespace runner - optional and
root-requiring, stated directly in that ticket's own filed description, not only in the plan doc).
Both were filed to the backlog as real tickets (Crewban-57 and Crewban-58 respectively); neither is
implemented by the planning ticket that produced the plan doc.
Unlike the DAST plan above, step 8 is **not** gated on any unlanded step: this planning ticket's own
acceptance criteria named `lib/http.sh` (the tension-19 chokepoint) as step 8's blocker, and it is
confirmed present on `dev` - it shipped early, out of its normal step-5 sequence, exactly as noted
below. Tension 20's RESOLUTION says explicitly that step 8's only real dependency is `lib/http.sh`'s
pinned resolution cache, "so the ordering already works." Both PARANOID-01 and NETNS-01 may be picked
up independently of each other and of the remaining un-landed steps.

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
- **F16's `look` half** - the O(n) `grep -F` fallback cost for SCA lookups.
  Lands with step 4's SCA half, which has not started.

F3, F4, and F8 are closed (F3 and F8 as of step 2's `lib/checks.sh`; F4 as of 3a above); do not
re-flag them.

**`main` can lag `dev` - check `dev`, not just `main`, before declaring a dependency unlanded.**
This project develops on `dev` and merges to `main` in batches, so a checkout of `main` can be several
merged tickets behind what `dev` already has.
An earlier agent run on the 3b ticket read a `main` checkout where `modules/` was genuinely still
absent, concluded the 3a dependency (and this stale memory) meant the work hadn't landed, and moved the
ticket to `blocked` - when 3a had in fact already merged to `dev`.
Before concluding a dependency is missing, check the actual workspace branch and, if it is behind, check
`dev`'s tip rather than trusting `main` or this file's prose alone.

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
exists.**
`5de4460` ("IaC: Terraform checks via the pattern-rule engine (§13 step 4)") shipped `modules/iac/run.sh`
(the `scan_dispatch iac` entry point), `modules/iac/parse.sh` (the Terraform HCL parser), and
`modules/iac/terraform.rules`, run through the same native pattern engine `modules/sast/engine.sh` built
at step 3a.
`terraform.rules` seeds seven checks: `IAC-TF-OPEN_CIDR-01`, `IAC-TF-PUBLIC_ACL-01`,
`IAC-TF-UNENCRYPTED-01`, `IAC-TF-KEY_ROTATION_DISABLED-01`, `IAC-TF-PUBLIC_IP-01`,
`IAC-TF-HARDCODED_SECRET-01`, and `IAC-TF-RDS_PUBLIC-01`.
`tests/suites/iac.sh` tests it.
This landing is **Terraform only**: CloudFormation and container (Dockerfile / Kubernetes-manifest) IaC
rules are still open and explicitly out of scope for it.
`modules/` as a whole now ships **eight** pattern packs on disk - the seven under `modules/sast/rules/`
plus `modules/iac/terraform.rules` - which is the count `tests/lint-rules.sh`'s E060 fixture-coverage
note now reports.
It landed ahead of step 3's remaining `nosql`/`ldap` rule packs and ahead of step 4's own SCA half, the
same "land what's ready, out of strict step order" pattern as `lib/http.sh` above.
Both `nosql`/`ldap` and SCA remain unstarted - do not read this paragraph as "step 4 is done."

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
Everything else in the original list is still true: `modules/dast/`, `modules/sca/`, `modules/cloud/`,
`lib/engines.sh`, `lib/awscli.sh`, SARIF, the compliance report, and `state/` do not exist yet.
`modules/iac/` landed anyway, out of sequence - see above.
Every `scan_dispatch` call for a module other than `sast` or `iac` remains a logged
`coverage_reduction` no-op (`reason=not_yet_built`), and every `_scan_apply_profile_filter` call for a
check set outside SAST/IaC finds an empty check registry (`reason=no_check_registry_on_disk_yet`),
until that module actually ships one - both mechanisms are real and tested against fixtures, they
simply have nothing on disk to find yet outside SAST and IaC.
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
tests/run-tests.sh                 # everything: eight suites plus four linters
tests/run-tests.sh --list          # what is available
tests/run-tests.sh records         # one suite: records | core | config | checks | findings | report | http | e2e | scan
tests/run-tests.sh lint-rules      # or one linter by name
tests/lint-rules.sh                # record-format linter, error codes in rules/RULE-FORMAT.md §13
tests/lint-shell.sh                # the tension 4, 9, 24 and 26 shell lints
tests/lint-aws-readonly.sh         # read-only AWS lint, docs/FOUNDATION.md tension 23
tests/e2e/fixture-scan.sh <dir>    # the end-to-end path on its own, for eyeballing a report
```

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
