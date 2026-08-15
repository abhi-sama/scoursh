# Step 7 (diff / state) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 7 - `docs/DESIGN.md` §13's "**Diff/state** (§9a): fingerprint history + `diff` command + 'fail on new only' mode" - can be picked up as a clean sequence of small, independently reviewable tickets the moment its blockers clear, instead of being re-derived from `docs/DESIGN.md` §9a and four `docs/FOUNDATION.md` tensions from scratch by whoever picks it up first, mirroring `docs/STEP5-DAST-PLAN.md` and `docs/STEP6-CLOUD-PLAN.md` for their steps.

Every design decision this plan sequences is already committed.
Tension 11 (the frozen nine-stage pipeline, the fail-closed `diff_usable` gate, the `baseline.json` object schema), tension 12 ((check, scope-cell) coverage, the classification table, the `scan_root_id` gate), tension 13 (the per-finding history boundary), and tension 6 (the composite three-condition rule) each carry a RESOLUTION, and the tickets below implement those resolutions rather than re-litigating them.
A ticket that finds itself disagreeing with one of those resolutions changes the register deliberately and costs the change, per `AGENTS.md`; it does not quietly diverge in code.

## Status: blocked, and now second in the priority order

**No step 7 ticket (any of STATE-01 through STATE-08 below) is picked up until every earlier `docs/DESIGN.md` §13 step is complete on `dev`.**
The build order (§13) is strictly sequential, so step 7 waits behind:

1. **§13 step 3 (SAST) finishes**: the `nosql.rules` and `ldap.rules` packs land.
   **Still outstanding**: the generated status block in `AGENTS.md` reports SAST at 8 of 10, with exactly those two outstanding.
2. **§13 step 4 (SCA + IaC) completes.**
   **This was a real blocker and it is now CLEARED**, recorded here rather than deleted so that a reader can see the gate held and was discharged rather than quietly dropped.
   The generated status block reports both halves complete: SCA 6 of 6 ecosystems, IaC 6 of 6 packs, with nothing outstanding in either.
3. **§13 step 5 (DAST) completes.**
   **Still outstanding**: zero of DAST-01 through DAST-30 (`docs/STEP5-DAST-PLAN.md`) has landed and `modules/dast/` does not exist.
4. **§13 step 6 (Cloud) completes.**
   **Still outstanding**: zero of CLOUD-01 through CLOUD-34 / POSTURE-01 through POSTURE-04 (`docs/STEP6-CLOUD-PLAN.md`) has landed and `modules/cloud/` does not exist.
   `lib/awscli.sh` is the one exception, and its absence must not be cited as evidence here, because it is no longer absent: the `aws_ro` chokepoint landed ahead of step 6 in a credential-less pass (`AGENTS.md`, "AWS module: what exists ahead of step 6"), leaving `modules/cloud/` as the thing that says step 6 is unstarted.

The generated status block in `AGENTS.md` (mirrored in `README.md` and `docs/FOUNDATION.md`) is what says whether these gates have lifted - read it there, not this snapshot.
The gate matters more for step 7 than for any earlier step: tension 12's coverage-cell table spans every module's scope kind (`path-root`, `target`, `account-region`, `scope-key`), and building classification before the `target` and `account-region` producers exist would leave those arms of the table untestable against real emitters.
Steps 8 and 9 are explicitly NOT in this gate: both have landed early, out of step order, and step 7 neither depends on them nor waits for anything behind them.

**Step 7 now sits SECOND in the project's priority order**, behind step 5 (DAST) and ahead of both step 10 (SARIF plus the compliance report) and step 6 (live cloud scanning).
That priority order is in genuine tension with gate item 4 above, and this plan does not pretend to resolve it: the owner's order puts step 7 ahead of step 6, while §13's sequential build order puts step 6 first, and the paragraph above gives a technical reason - not merely a sequencing preference - for wanting step 6's `account-region` producer to exist before classification is built and tested against it.
Whoever picks up STATE-01 has to settle that explicitly, rather than reading either the priority order or the gate as having silently overridden the other.
Note that the same question does not arise for gate item 3: step 5 is both ahead of step 7 in the build order and ahead of it in priority, so it blocks step 7 either way.

Whoever lifts this block should update the "Status" line above, and the two build-order sections named in "Doc-update process" below, in the same change that starts STATE-01.

## What already shipped - do not re-plan it

Step 7 is unusually well scaffolded: steps 1-3 landed most of its primitives in anticipation.
Whoever picks up a STATE-* ticket reads these before writing anything, the same way `docs/STEP6-CLOUD-PLAN.md` told CLOUD-03's implementer to read the existing lint first.

- **`lib/findings.sh` ships the classification primitives** (step 1): `findings_merge` (tension 11 stage 3's fingerprint-keyed merge/dedup), `findings_mark_suppressed` (stage 6's annotate-never-delete suppression), and `classify_derived` (tension 6's composite rule, pure, already tested against the full case table including cases 5-9).
  Finding records already carry `first_seen`, `last_seen`, `suppressed`, `suppressed_by`, `status`, and `rule_digest` fields.
- **`lib/core.sh` ships `scan_root_id_of`** - tension 12's frozen, measured recipe (git toplevel, `config --local --get remote.origin.url`, normalise-then-test, userinfo strip) - and `scan.sh` already calls it, so `run.json` carries `scan_root_id` today.
- **`lib/report.sh` already writes `diff_usable` into `run.json`**, currently always `false` via the `SCOURSH_DIFF_USABLE` default - honest, since no classification exists to make it true.
- **`scan.sh` already parses the step-7 CLI surface**: `--fail-on-new` (usage-errors without `--fail-on`, per tension 14), and the `diff` subcommand exists as a stub that validates `--against` and logs `reason=not_yet_built`.
- **The `--fail-on` gate itself already runs**: `sast_evaluate_gate` (`modules/sast/engine.sh`, reused unchanged by `modules/iac/run.sh` and `modules/sca/run.sh`) evaluates severity/confidence/suppression and sets scan_main's `gate` local, and `tests/suites/gate-mutation-proof.sh` pins it.
  Its current `--fail-on-new` predicate is a bare `status == new` test with `new` as the default status - which today gates on ALL findings, coincidentally matching tension 11's fail-closed posture, precisely because nothing yet assigns any other status.
  STATE-08 replaces that coincidence with the real carve-out; it does not build a gate from scratch.
  SCA's call site is the newest of the three and was missing at first: `modules/sca/run.sh` ran findings_merge -> derive_findings -> report_all with no gate call between them, so `scan.sh sca --fail-on critical` exited 0 on critical findings and `run.json` recorded `"gate": "not-evaluated"`.
  It now sources the SAST engine and calls `sast_evaluate_gate` before `report_all` like its two siblings, with an end-to-end regression case in `tests/suites/sca.sh` asserting exit 1 and `"gate": "fail"` over the `tests/fixtures/sca/npm-lock` fixture.
  STATE-08 therefore inherits three module call sites for this predicate, not two.
- **`lib/checks.sh` owns the check registry** (step 2), and `run.json`'s `checks_run` already records what ran.
  `checks_run` is NOT tension 12's `covered_checks` - the distinction is stated in `lib/records.sh` and in `AGENTS.md`, and STATE-02 is the ticket that builds the latter.
- **`modules/sast/history.sh`** (step 3e) already emits per-finding `oldest_reaching_commit_time` and resolves the enumeration boundary, in anticipation of tension 13's comparison landing here.

What does NOT exist, in any form: a `state/` directory, a writer or loader for `state/<run-id>.json` / `state/latest.json`, per-(check, cell) coverage recording, the classification engine, `config/baseline.json` handling, or a real `diff` command.
That is the whole of this plan.

## Where step 7 sits in the frozen pipeline

Tension 11's RESOLUTION freezes nine stages and assigns them owners.
Steps 1-4 of the pipeline (collect, fingerprint, merge, derive) shipped at §13 steps 1-3.
**§13 step 7 implements pipeline stages 5 (classify + `diff_usable`), 6 (suppress), and 8 (persist)**, plus the stage-7 gate predicate's `--fail-on-new` carve-out and the stage-9 reporting of deltas, suppressed sections, and stale baseline entries.
The ticket decomposition below is dependency-ordered along that pipeline, which is why it is mostly serial: the pipeline order IS the dependency order, and two tickets editing the same pipeline function in parallel is how merge conflicts (and worse, silent stage reordering) happen.

One consequence of tension 12, restated because every ticket below inherits it: `state/` files are **machine-generated JSON**, not `rules/RULE-FORMAT.md` records - the frozen record format governs human-authored files only, and `state/*.json` sits in the same machine-format family as `findings.jsonl` and `run.json`.
`config/baseline.json` is likewise JSON (tension 11 defines its object schema directly).
No STATE-* ticket touches `rules/RULE-FORMAT.md`, and none may: check ids feed the fingerprint, the format is frozen, and `fp_schema` exists precisely so state can survive the day that ever changes.

## Dependency-ordered sub-ticket list

### Tier 0 - the state store (blocks everything below)

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| STATE-01 | `lib/state.sh` - `state/` schema, writer, loader | nothing in this plan (step-1 primitives only) | Tension 12's frozen `state/<run-id>.json` shape; tension 11 stage 8 | The exact JSON shape is frozen in tension 12's RESOLUTION and is not redesigned here: `fp_schema`, `tool_version`, `run_id`, `completed_at`, `scan_root_id`, `covered_checks` (per check: `rule_digest`, `scope`, `cells`, plus `history_boundary` for `SAST-HIST-*` only), and `findings` (per finding: `fingerprint`, `check_id`, `cell` - JSON `null` for derived, never omitted, never a string sentinel - `severity`, `first_seen`, `last_seen`, `suppressed`, `oldest_reaching_commit_time` for history findings, `contributors` for derived findings). Writer persists ALL findings including suppressed ones with `first_seen` preserved (tension 11 stage 8), updates the `state/latest.json` pointer atomically (write-then-rename, same idiom as the report emitters), and prunes to `state_retain_runs` (default 30) newest runs plus `latest.json`. Loader reads `state/latest.json` or an explicit `--against` dir, surfaces `fp_schema` / `scan_root_id` for the guards STATE-03 owns, and treats a missing or unparsable state dir as "no prior state", never as an error. Tested against hand-authored fixture state files; no scanner integration yet. |
| STATE-02 | Per-(check, cell) coverage recording + persist-on-every-run wiring | STATE-01 | Tension 12's coverage-cell table and "enters `covered_checks` only if the check ran to completion over that cell" rule | Every module records the cells it is about to visit before visiting them (the same enumerate-then-execute structure tension 18 already imposes for `unit_key`), and a (check, cell) pair enters `covered_checks` only on completion: not if the module was unselected, a profile/intensity filter dropped the check (tension 15), the check skipped on a missing dependency or engine (tension 2), the breaker aborted the module (tension 16), a resumed run never reached it (tension 18), or the run never visited the cell. Cell values per the frozen table: `path-root` (SAST/history/IaC/SCA - the `--path` root relative to the scan root, a run parameter recorded at emission, never derived from the location), `target` (DAST), `account-region` (cloud live), `scope-key` (posture), JSON `null` (derived). Wires `state_write` into `scan_main` so every run persists `state/<run-id>.json`. For module kinds not yet emitting findings this records honestly empty coverage, exactly as `run.json`'s `regions: []` precedent. |

### Tier 1 - classification

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| STATE-03 | The classification engine: `new` / `recurring` / `fixed` / `unknown` + `diff_usable` | STATE-01, STATE-02 | Tension 12's four-row table and its two guards; tension 11 stage 5 | The table verbatim: `fixed` only inside a covered (check, cell) pair; uncovered-and-absent is `unknown`, carried forward with its original `first_seen`; `unknown` findings are excluded from the gate and reported "not assessed this run". `path-root` cells are comparable only between runs with equal `scan_root_id`, exact string equality, no subsumption in either direction. The two guards, by tension 12's stated mechanism: an `fp_schema` mismatch (whole diff) or `scan_root_id` mismatch (only when the selected modules put findings in `path-root` cells) treats the prior set as EMPTY for classification - this run's findings are `new` per the table, prior findings persist `unknown` with the mismatch as reason, nothing is `fixed` or `recurring` - and sets `diff_usable = false`. `diff_usable` governs the gate only and never overrides a `status`; a first run's findings are `new`, not `unknown`. A `rule_digest` change classifies normally but flags "rule changed" in the report. Must ship tension 12's eight-row fixture matrix (partial-run, region-scoped, target-scoped, non-git collision, nested-repo collision, cwd-independence, two-checkout portability, shallow/single-branch clone), each test naming the reading it fails under, per the project's testing rule. |
| STATE-04 | `SAST-HIST-*` refinement: the per-finding history boundary | STATE-03 | Tension 13's two-layer composition with tension 12 | Layer 1 (the (check, cell) test on `path-root`) is STATE-03's and runs first; an uncovered cell is `unknown` without consulting this rule. Layer 2, inside a covered cell, for a prior history finding absent this run: `oldest_reaching_commit_time` at or after this run's boundary `oldest_commit_time` means the walk could see it, so `fixed`; before it means the walk could not, so `unknown`. Reads the `history_boundary` block STATE-01 persists and the per-finding field `history.sh` already emits. The boundary lives in `covered_checks`, never in the cell string (the boundary-in-cell reading makes every history finding `unknown` forever under a rolling window - tension 13 case 6 is the test that catches it). Can only turn `fixed` into `unknown`, never the reverse. Ships tension 13's eight-row fixture table, including cases 6-8. |
| STATE-05 | Derived-finding refinement: the composite three-condition rule | STATE-03, STATE-04 | Tension 6's conditions (a)/(b)/(c); tension 12's derived row | Wires the already-shipped, already-tested `classify_derived` against real prior state: a composite is `fixed` only when (a) its own record was selected this run, (b) every check in `requires`/`any-of` is covered - contributors that fired by the test that would let their OWN finding be `fixed` (which for a `SAST-HIST-*` contributor is STATE-04's boundary test, hence the dependency), listed checks that did not fire by being covered this run at all AND having every previously-covered cell revisited - and (c) the predicate no longer holds. A composite's `cell` is JSON `null` and the (C, K) test is replaced entirely, never supplemented. Contributor fingerprints resolve to entries in the same persisted `findings` array; pairs are looked up, never inferred. NOTE: `rules/derived.rules` remains unseeded until steps 5/6 land `COMPOSITE-TOKEN-HIJACK`'s contributors (findings F5/F20), so this ticket tests against the fixture composite under `tests/fixtures/rules/derived.rules`, as the step-1 mechanism tests already do. |

### Tier 2 - the diff surface

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| STATE-06 | The `diff` command + automatic per-run classification + report delta | STATE-03, STATE-04, STATE-05 | `docs/DESIGN.md` §9a's command surface; tension 11 stage 9's delta reporting | Replaces `scan.sh`'s existing `diff` stub: `scan.sh diff --against <dir>` overrides the state source, and every normal run classifies automatically against `state/latest.json`. The report leads with the delta ("since last scan: +N new, -M fixed"), renders `unknown` as "not assessed this run" with the `run.json` reason, and says which of `fp_schema` / `scan_root_id` changed when a guard fired, including that a baseline rebuild is required. Depends on STATE-04/05 rather than landing before them because both refinements only narrow `fixed` to `unknown`: wiring the delta into every run before they land would ship a window of phantom history/composite remediations, the exact false all-clear tensions 13 and 6 exist to prevent. Sets `SCOURSH_DIFF_USABLE` for real, replacing `lib/report.sh`'s always-false default. |
| STATE-07 | `config/baseline.json` suppression | STATE-06 | Tension 11 stages 6 and 9, and its `baseline.json` object schema | Suppression is an annotation after classification and before persistence, never a deletion and never a diff input: `suppressed: true` + `suppressed_by`, via the already-shipped `findings_mark_suppressed`. Entry schema per tension 11: `{fingerprint, reason, added, expires}`, with a bare string accepted as `{fingerprint, reason: "", added: null, expires: null}` so §11's shape still loads. An entry past `expires` stops suppressing and the report says so; an entry matching nothing is reported `stale` in `run.json` and the report; `--baseline FILE` replaces the default file. Suppressed findings render in a collapsed "accepted risk" section and count separately in every summary. Ships tension 11's four ordering-hazard tests: unsuppress-does-not-create-new, suppressed-can-still-be-fixed, expired-entry-stops-suppressing, stale-entry-is-reported. Sequenced after STATE-06 because both edit the same pipeline wiring in `scan_main`, not because of a data dependency. |

### Tier 3 - the CI gate

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| STATE-08 | `--fail-on-new`: the fail-closed gate predicate | STATE-06, STATE-07 | Tension 11 stage 7's carve-out; tension 14's exit-code precedence (already shipped) | Replaces `sast_evaluate_gate`'s current bare `status == new` test with the frozen predicate: `suppressed == false` AND `confidence >= --min-confidence` AND, when `--fail-on-new` is given, `status == new` IF AND ONLY IF `diff_usable` is true - when false, the gate considers ALL findings regardless of status. The carve-out is not optional wording: a bare status test happens to gate correctly after an `fp_schema` bump (everything is `new`) but fails open on prior state that is present and merely stale in part, which is how the fail-open shipped in the register's own history. Exit code stays `SCOURSH_EXIT_GATE` (1) under the existing tension-14 precedence; no exit-code change. Also flips the `tests/suites/ci-smoke.sh` vuln-tree row that currently documents exit-0 as correct-for-now, and extends `tests/suites/gate-mutation-proof.sh` to cover the carve-out, with tests that fail under the bare-predicate reading. |

That is 8 tickets end to end, deliberately fewer and larger-grained than DAST's 30 or CLOUD's 34: step 7 is one pipeline over one data store, its stages are serial by construction (tension 11 froze the order), and slicing it thinner would create tickets that cannot be tested without their neighbour.
The only genuine parallelism is STATE-04 alongside nothing and STATE-07's internals (baseline parsing) being separable from its wiring; the `dependsOn` edges filed to the backlog encode exactly the graph above and nothing looser.

## Fixture and test obligations, stated once

Every STATE-* ticket carries its own tests in the same change, per this project's convention - there is no separate test ticket.
Three committed test tables are the floor, not the ceiling: tension 12's eight-row matrix (STATE-03), tension 13's eight-row table (STATE-04), and tension 11's four ordering hazards (STATE-07).
Every test names the reading it fails under, per the `AGENTS.md` testing rule: a test that passes under both the correct and the rejected reading pins nothing.
State fixtures are hand-authored JSON under `tests/fixtures/` (a new `tests/fixtures/state/` subtree is the natural home), never captured from a live run, so the suite stays deterministic and the fixtures stay readable in review.

## Doc-update process

Per `AGENTS.md`'s "Build order and where we are" process rule, whoever lands STATE-01 (the first real step-7 code) updates both `AGENTS.md`'s "Current position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section in the same change, and runs `tools/gen-status.sh --write` if any generated block is affected.
`docs/DESIGN.md` itself stays verbatim - it is never the place build-order status is recorded.
The same rule applies to whoever lands STATE-08 and thereby completes the step.
