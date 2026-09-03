# Step 10 (SARIF + compliance report) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 10 - `docs/DESIGN.md` §13's "SARIF + compliance-mapping report + `--fail-on` CI gate + docs/README" - can be picked up as a clean sequence of small, independently reviewable tickets, instead of being re-derived from `docs/DESIGN.md` §4, §8 and `docs/FOUNDATION.md` tension 22 from scratch by whoever picks it up first, mirroring `docs/STEP5-DAST-PLAN.md`, `docs/STEP6-CLOUD-PLAN.md` and `docs/STEP7-STATE-PLAN.md` for their steps.

Step 10 was the only §13 step with no plan document, and that absence is the reason it has never been picked up: every ticket below had to be discovered by reading the tree before it could be filed, and the discovery is the expensive half.
This document does that reading once.

Most of what this plan sequences is already committed.
`docs/FOUNDATION.md` tension 22 ("SARIF locations for findings with no file") carries a full RESOLUTION covering locations, `partialFingerprints`, `tool.driver.rules[]`, result `properties` and suppression, and the tickets below implement that resolution rather than re-litigating it.
A ticket that finds itself disagreeing with it changes the register deliberately and costs the change, per `AGENTS.md`; it does not quietly diverge in code.

Every claim in this document about what is or is not in the tree was checked against the tree at the time of writing, and the check is named inline so a later reader can re-run it rather than trust it.

## Status: SARIF-01 through SARIF-03 have landed; SARIF-04 through SARIF-06 and all of Track B remain unstarted

| Ticket | State |
|---|---|
| SARIF-01 - populate `logical_kind` / `logical_fqn` on every finding | landed |
| SARIF-02 - the generated location artifact writer, `reports/<run>/locations/<module>.txt` | landed |
| SARIF-03 - `report_sarif` skeleton: document, `tool.driver`, `rules[]`, `artifacts[]`, `invocations[]` | landed |
| SARIF-04 through SARIF-06 (Track A) | not started |
| COMPLIANCE-01 through COMPLIANCE-04 (Track B) | not started |

**SARIF-01 landed as its own change**, per this plan's own Tier 0 row: `_finding_default_logical` in `lib/findings.sh`, called from `finding_emit` immediately before the fingerprint is computed, fills `logical_kind`/`logical_fqn` from the profile's own `loc_*` fields for `path`/`history` (`kind=file`, `fqn=<loc_path>:<loc_line>`), `dast` (`kind=endpoint`, `fqn=<loc_target>:<loc_method> <loc_path_template>#<loc_param_name>`, verbatim from tension 22), `cloud` (`kind=resource`, `fqn=<loc_resource_key>`) and `posture` (`kind=control`, `fqn=<loc_control_id>`), and leaves `sca` and `derived` untouched since `modules/sca/` and the composite path already set their own identity before `finding_emit` runs. `tests/suites/findings.sh` carries one case per profile plus the two discriminating cases this plan's own acceptance criteria name: a single run emitting five profiles at once, asserting none is left with an empty `logical_kind` (the reading a per-module setter fails under), and a fingerprint-recomputation case per profile proving `finding_fingerprint` returns the same value before and after the default runs (the executable form of "the merged `findings.jsonl` is byte-identical before and after", since `logical_kind`/`logical_fqn` are absent from `_fp_components_for` for every profile). SARIF-02 is now unblocked.

**SARIF-02 has also landed.** `report_locations` (`lib/report.sh`, new section 5) writes `reports/<run>/locations/<module>.txt` - one line per finding whose profile carries no usable real file, keyed on the finding's own `logical_fqn` - and is called unconditionally from `report_all`, before `findings_write_jsonl`/`findings_write_json`/`report_md`/`report_html`, so every one of those emitters sees the write-back it makes. It rewrites `findings.fields` in place, the same read-decode-mutate-reencode-rewrite shape `findings_mark_suppressed` already uses: case 4 (`dast`, `cloud`, `posture`, `derived`) always gets a line; case 3 (`SAST-HIST-*`) gets one only when `loc_path` genuinely fails a filesystem test against the scan root (`_locations_history_resolves`), and that fallback line carries `loc_blob_sha` and `commit` so a reader can `git show` it; case 1 (a real working-tree file) and case 2 (`sca`, whose own `path` field already names a real, committed lockfile) are untouched. Every artifact-backed finding has its assigned line number written back onto its own `loc_line` - the exact field SARIF-04's mapping table already sends to `region.startLine` - so that ticket needs no per-case location logic of its own. Ordering is exactly the order `findings.fields` is already in when `report_locations` runs (`(module, check_id, fingerprint)` under `LC_ALL=C`, `findings_merge`'s own order, undisturbed by `derive_findings`' later re-sort), so two runs over an identical fixture assign the same line to the same finding and produce byte-identical location files, with no second sort needed. `SCOURSH_SCAN_ROOT_PATH` is a new variable `scan.sh` exports alongside `SCOURSH_SCAN_ROOT_ID`/`SCOURSH_PATH_ROOT` for the `sast`, `sca`, `iac` and `all` commands (the only commands that can ever emit a `SAST-HIST-*` finding) - the one absolute path the case-3 filesystem test needs; unset (a direct `report_locations`/`report_all` call, or a command with no `--path`) is treated as "cannot resolve", the fabrication-avoiding default tension 22 requires. `tests/suites/sarif-locations.sh` (33 assertions) is the proof: a fixture run per case-4 profile, each asserting the artifact file is a real file that exists at the path a SARIF would cite (tension 22's own validation requirement) and that `loc_line` points at the right line in it; a real git-repo fixture for case 3, one committed-and-deleted blob (fallback fires, carrying `loc_blob_sha`/`commit`) and one committed-and-still-present blob (left alone, proving case 3 is not case 4); case 1/2 fixtures proving `loc_line` and `path` are untouched and no artifact file is even created; a `report_all` call with `SCOURSH_FORMATS=md` (no `sarif`) proving the artifact is written unconditionally; and two independent runs over one fixture proving `locations/*.txt` is byte-identical across them.

**One sharp edge this ticket found and fixed rather than shipped: `report_all` - and therefore `report_locations` - runs more than once per run directory.** `scan.sh all` dispatches `sast`, then `sca`, then `iac` (and `dast` when `--target` is given) in one `scan_main` invocation, and each module's own `run.sh` calls `findings_merge` (which rebuilds `findings.fields` from every shard emitted so far, sast's included) and then `report_all` at its own end - so `report_locations` sees an earlier pass's findings again on every later call, not only its own. An append-only writer duplicates every earlier pass's lines and strands `loc_line` pointing at the wrong row once the file has grown past it - reproduced first with a real `scan.sh all --history` subprocess (three `report_all` calls, sast/sca/iac) landing 4 lines in `locations/sast.txt` for 2 real history findings, then with a synthetic two-pass fixture in the suite. `report_locations` truncates a module's artifact file the first time a given CALL touches it (`_loc_seen`), so every call is a full, idempotent regeneration from the current `findings.fields` snapshot - the same truncate-then-rebuild discipline `findings_write_jsonl`/`report_md`/`report_html` already use - rather than an unbounded append. `tests/suites/sarif-locations.sh`'s own multi-pass case pins it, and the same real subprocess (three `report_all` calls) now lands exactly 2 lines. SARIF-03 is now unblocked.

**SARIF-03 has also landed.** `report_sarif` (`lib/report.sh`, new section 5a) writes `reports/<run>/report.sarif`: `$schema`/`version: "2.1.0"`, `runs[0].tool.driver` (`name`, `version`, `informationUri`), `runs[0].tool.driver.rules[]`, `runs[0].artifacts[]`, `runs[0].invocations[0]`, and `runs[0].results: []` - SARIF-04's own territory. `report_all` now selects it exactly like the other three `--format` values (`[[ -z ${_rpt_want[sarif]:-} ]] || report_sarif "$rundir"`), replacing the stand-in comment.

`tool.driver.rules[]` is tension 22's "the full loaded check registry, keyed by `check_id`": `_sarif_build_registry` calls `checks_registry_load` (`lib/checks.sh`, now sourced by `lib/report.sh`) once per module across `sast`/`sca`/`iac`/`dast`/`cloud` (posture nests under `cloud`) and accumulates every record it finds into one map, so a check with zero findings this run still gets a `reportingDescriptor` - proven by a fixture run with no findings at all still listing every on-disk check. The ticket's own named trap - three id families a finding can carry with no `*.rules` record (SCA ids, `<engine>:...` adapter ids, and derived/composite ids, since `rules/derived.rules` is deliberately unseeded) - is closed by unioning the registry ids with the DISTINCT `check_id`s this run's own `findings.fields` already carries: for an id with no registry record, `_sarif_descriptor_synth` builds a minimal descriptor (`id`, `name` from the finding's `title`, `help.text` from its `remediation`, `defaultConfiguration.level` from its `base_severity`) and sets `properties.descriptorSource: "synthesised"`; a registry-backed descriptor never carries that property, so the distinction is visible in the document itself. A registry-backed descriptor additionally carries `properties.ruleDigest` (`records_digest`) and `properties.tags` (`external/cwe/<id>`, `external/owasp/<id>`, `external/cis/<id>` per non-`none` value), and `help.text`/`helpUri` are built from the record's own `remediation` and `references[]`, never from a finding - proven against a finding that deliberately disagrees with the record on every shared field, so the record winning is observable rather than assumed.

`runs[0].artifacts[]` lists exactly the `locations/<module>.txt` files this run's `report_locations` (SARIF-02) actually wrote, and nothing else - never a real working-tree source file (case 1) or an SCA lockfile (case 2), and never a module whose findings never needed the generated fallback. `runs[0].invocations[0]` mirrors `run.json`'s own `started_at`/"now" for the timestamps; `executionSuccessful`/`exitCode` read the same non-empty-`incomplete_reason` signal `run.json`'s own header already names as "exactly the exit-5 predicate" - a real signal, but a necessarily incomplete one at this point in the run, since `scan.sh` sets `SCOURSH_GATE_RESULT` only after every module's own `report_all` call has already run (the same ordering limitation `run.json`'s own `gate` field already carries and documents), so a `--fail-on` gate failure (exit 1) is not yet distinguishable from a clean run here.

`_sarif_build_registry` runs DIRECTLY inside `report_sarif`, never through `$(...)`, for the identical reason `checks_registry_load`'s own header gives: its `die()` on a malformed registry file must abort the run, and a `die()` inside a command substitution does not reliably do that. Sourcing `lib/checks.sh` from `lib/report.sh` adds one edge to the `shellcheck -x` hub-fan-out graph (`tests/lint-source-graph.sh`'s cap of 20); measured clean across the tree at landing time (worst case unrelated, at exactly the cap), so no back-edge cut was needed - re-measure before adding another hub-reaching edge near this one.

`tests/suites/sarif-rules.sh` (53 assertions) is the proof: the document shape and JSON validity; `--format` gating (`report.sarif` written by default, absent under `SCOURSH_FORMATS=md`); the full-registry claim against a zero-finding run; the registry-wins-over-a-disagreeing-finding case, field by field; one case per ungoverned id family (SCA, adapter, derived/composite) proving both that a synthesised descriptor exists at all (closing the ticket's own trap) and that it is marked `descriptorSource: "synthesised"`; `artifacts[]` presence/absence across a real-file and a generated-artifact finding; `invocations[]` under a clean run and an `incomplete_reason` run; and determinism across two runs of an identical fixture. Two of the discriminating assertions (the full-registry claim, and `descriptorSource` never appearing on a registry-backed descriptor) were confirmed by mutation - each was watched failing under the reading it names before the fix, per `AGENTS.md`'s testing rule.

## The central finding: step 10 is three pieces of work, not one

`docs/DESIGN.md` §13 item 10 reads as a single bullet, and that framing is what has kept step 10 looking like one large blocked unit.
It is not.
It bundles three deliverables with three completely different readiness states:

| Deliverable | State | Blocked on |
|---|---|---|
| **SARIF 2.1.0 emitter** (Track A) | Not started, and **unblocked today** | Nothing. Not step 6, not step 7. |
| **Compliance-mapping report** (Track B) | Not started, **half unblocked** | The OWASP half: nothing. The CIS half: step 6. |
| **`--fail-on` CI gate** | **Already shipped in full** | Nothing. No step 10 ticket exists for it. |

The consequence is that step 10 is not one thing waiting behind step 6 and step 7.
Track A (six tickets) can be picked up immediately, in parallel with any STATE-0x or CLOUD-0x work, and touches none of the same files.
So can the first three tickets of Track B.
Only COMPLIANCE-04 is genuinely blocked, and it is blocked on step 6 alone.

`ROADMAP.md` currently places step 10 second in priority behind step 7.
This plan does not change that ordering, and does not argue for changing it: it records that the ordering is a priority choice rather than a technical block, so that whoever wants a shippable, self-contained piece of work while step 6 and step 7 are open knows Track A is available.

## What already shipped - do not re-plan it

Whoever picks up a SARIF-0x or COMPLIANCE-0x ticket reads this section before writing anything, the same way `docs/STEP6-CLOUD-PLAN.md` told CLOUD-03's implementer to read the existing lint first.
Each row was verified against the tree, not inferred from a document.

### `--fail-on` is complete. There is no ticket for it.

`docs/DESIGN.md` §13 item 10 names the `--fail-on` CI gate as step 10 work.
It is done, and has been since step 3.
Verified end to end:

- Parsed and validated: `scan.sh` declares it in `_SCAN_FLAG_KIND` (`[global:fail-on]=value`), prints it in usage, and validates the value against `^(critical|high|medium|low|info|none)$`.
- Resolved through the full CLI-over-environment-over-file-over-default chain into `SCOURSH_FAIL_ON` and exported before dispatch (`scan.sh`, `_scan_capture` / the export list).
- Consumed by `sast_evaluate_gate` (`modules/sast/engine.sh`), which `modules/iac/run.sh`, `modules/sca/run.sh` and `modules/dast/run.sh` each reuse unchanged rather than forking, so the gate applies to every module that emits findings.
- The gate filters on severity **and** `--min-confidence` **and** `suppressed`, sets `scan_main`'s `gate` local, and reaches exit code 1 through tension 14's frozen precedence in `scan_exit_code`.
- Pinned by `tests/suites/sast.sh` (a real `scan.sh sast --fail-on high` subprocess against `tests/fixtures/vuln` exiting non-zero, against `tests/fixtures/clean` exiting zero, and a case proving the gate is opt-in and never ambient) and by `tests/suites/gate-mutation-proof.sh`.

`--fail-on-new` is a different question and is **not** step 10's either.
It parses, it requires `--fail-on` in the same invocation (exit 2 otherwise), and `sast_evaluate_gate` already reads `SCAN_FLAGS[fail-on-new]` and filters on `status == new`.
What it lacks is anything to narrow: every finding is `status=new` until persistent state exists to compare against.
`docs/STEP7-STATE-PLAN.md`'s **STATE-08** owns replacing that bare `status == new` test with tension 11's fail-closed predicate.
A step 10 ticket must not touch it.

### `--format` already selects. SARIF is the one value that selects nothing.

`--format` is **live**, not inert.
`report_all` (`lib/report.sh`) reads the `SCOURSH_FORMATS` CSV that `scan.sh` resolves via `config_scanner_list` and exports, and gates `findings.json`, `report.md` and `report.html` behind it.
`findings.jsonl` and `run.json` are written unconditionally, because they are mandatory per-run records rather than members of the four-value `--format` enum.

Measured on this tree, not inferred:

```
scan.sh sast --path <tree> --format md     ->  findings.jsonl  run.json  report.md
scan.sh sast --path <tree> --format sarif  ->  findings.jsonl  run.json
```

`--format md` writes **no** `report.html` and no `findings.json`.
`tests/suites/scan.sh` asserts exactly that for the `sarif` case, file by file.

So the SARIF gap is precise and small: the selection plumbing is finished, and `report_all` carries an explicit comment at the selection site saying an emitter does not exist yet.
Track A adds the emitter and one line to `report_all`.
It changes no flag, no config key, no validation, and no exit code.

`README.md`'s "Known defects" entry and `docs/USAGE.md`'s flag table and `--format` section all described `--format` as inert and claimed every run writes all five artifacts, which the measurement above shows is false.
That was stale prose rather than a defect in the code, and it was corrected in the same change that added this plan, because a plan whose central finding is "the selection plumbing is finished and only SARIF selects nothing" cannot ship alongside user-facing documentation asserting the opposite.
What SARIF-06 still owns is the last sentence of each: the statement that no SARIF writer exists, which stays true until Track A lands.

### The finding record is already structured for SARIF

`lib/findings.sh`'s `_finding_json` is the canonical field list, and it already carries everything a `result` needs.
No new finding field is required by Track A, with one exception (SARIF-01, below) that is a **population** gap rather than a schema gap.

### `reports/<run>/locations/` is already created, and nothing writes to it

`lib/core.sh` creates `"$SCOURSH_RUN_DIR"/{shards,units,meta,inventory,locations}` on every run.
`locations/` is tension 22's exact specified path for the generated location artifact, it is created empty on every run today, and no file anywhere in the tree writes into it.
SARIF-02 is the missing writer, not a missing directory.

### The `cis` field already exists on every finding

`rules/RULE-FORMAT.md` §9.1 gives every check record an optional, repeatable `cis` field ("CIS control id, for the compliance report"), §9.2 and §9.5 repeat it for the cloud/posture and script-check schemas, `lib/records.sh` declares it in all three field tables, `lib/findings.sh` copies it onto the finding, and `_finding_json` emits it as a JSON array.
This materially changes what `data/cis-mappings` can be; see Track B.

### The HTML report already counts by OWASP category

`lib/report.sh` maintains `_RPT_OWASP` and renders a "By OWASP category" table in the HTML report.
It is a **count table keyed by the bare id** (`A03:2021`), it has no equivalent in `report.md`, and it does not group the findings themselves.
COMPLIANCE-02 builds on it rather than replacing it.

## Track A - SARIF 2.1.0

`docs/DESIGN.md` §4 pins the version: "**SARIF 2.1.0** (CI / code-scanning ingestion)".
That is the OASIS `sarif-schema-2.1.0.json`, and the plan does not consider any other version.

### Scope: which parts of the schema are in

SARIF 2.1.0 is very large and almost all of it is optional.
The emitter implements exactly the subset tension 22's RESOLUTION names, plus what that subset structurally requires, and nothing else.

**In scope:**

| SARIF construct | Why |
|---|---|
| `$schema`, `version: "2.1.0"` | Required for any consumer to identify the document. |
| `runs[0].tool.driver` (`name`, `version`, `informationUri`, `rules[]`) | Tension 22 requires `rules[]`; `version` comes from `scoursh_version()`. `informationUri` is a static string naming this project and is never fetched by anything, so it is not egress; it is also not a scan target, so `tests/lint-shell.sh`'s DAST-35 "no bundled scan target" checks are not in play. |
| `runs[0].tool.driver.rules[]` as `reportingDescriptor` objects | Tension 22, verbatim: "the full loaded check registry, keyed by `check_id`". SARIF-03 owns it. |
| `runs[0].artifacts[]` | Tension 22: the generated location artifact "is included in the SARIF `artifacts` array". |
| `runs[0].results[]` | The findings. SARIF-04 owns the mapping. |
| `result.locations[0].physicalLocation` + `logicalLocations[0]` | Tension 22's chosen option 3: **both**, always. |
| `result.partialFingerprints` | Tension 22: `scourshFingerprint/v1`. |
| `result.properties` | Tension 22: `module`, `status`, `confidence`, `cvss`, `suppressed`. |
| `result.suppressions[]` with `kind: "external"` | Tension 22: a baseline-suppressed finding is emitted suppressed, never dropped. |
| `runs[0].invocations[0]` (`startTimeUtc`, `endTimeUtc`, `executionSuccessful`, `exitCode`) | The run-level audit facts `run.json` already records; cheap, and it is what makes a SARIF file self-describing as a run. |

**Explicitly out of scope**, so a reviewer does not read their absence as an oversight:

- `codeFlows`, `threadFlows`, `graphs`, `taintFlows`. scoursh's native tier is pattern-grade and has no data-flow model (`docs/DESIGN.md` §15). Emitting an empty or single-step code flow would overstate the analysis.
- `fixes[]`. `remediation` is prose, not a patch. A SARIF `fix` carries `artifactChanges` that a consumer may apply automatically, and scoursh has none to offer.
- `result.rank`. See "the severity trap" below: it would be a second, differently-derived severity number.
- `automationDetails`, `runAggregates`, `baselineGuid`, `versionControlProvenance`. These belong to the run-to-run identity story, which is tension 12's and step 7's. Wiring them before `state/` exists would mint a second, competing notion of run identity.
- Multiple `runs[]`. One scan is one run, even under `scan.sh all`; `module` distinguishes the findings inside it.

### The mapping, concretely

Derived from `lib/findings.sh`'s `_finding_json` field by field.
This table is the SARIF-04 specification; a ticket implementing it does not have to re-derive it.

| Finding field (`lib/findings.sh`) | SARIF 2.1.0 | Notes |
|---|---|---|
| `check_id` | `result.ruleId`, and the matching `reportingDescriptor.id` in `tool.driver.rules[]` | Tension 7: `check_id` is the identity; there is deliberately no field named `id`. |
| `title` | `result.message.text` | Already redacted on the way in (`_finding_redacted_field`). |
| `severity` | `result.level` | Mapped, not passed through. See the level mapping below. |
| `base_severity` | `result.properties.baseSeverity` | Kept so a consumer can see the rubric moved it (tension 8). |
| `confidence` | `result.properties.confidence` | Tension 22 names it. Never folded into `level`: the gate already applies `--min-confidence` separately and folding would double-count it. |
| `module` | `result.properties.module` | Tension 22 names it. |
| `cwe` | `reportingDescriptor.properties.tags` entry `external/cwe/CWE-95` | On the **rule**, not the result: it is a property of the check. `cwe` is legally `none` (SCA sets it so); a `none` emits no tag rather than a tag reading `none`. |
| `owasp` | `reportingDescriptor.properties.tags` entry `external/owasp/A03:2021` | As `cwe`. `none` is legal here too and emits no tag. |
| `cvss.vector`, `cvss.score` | `result.properties.cvss` (object, both fields) | Tension 22 names `cvss`. **Not** `security-severity`. See the severity trap. |
| `location.*` (profile-dependent) | `result.locations[0].physicalLocation` | Four cases; see the location table below. |
| `loc_line` | `physicalLocation.region.startLine` | Absent for profiles that carry no line; `region` is then omitted entirely rather than defaulted to 1. |
| `logical.kind`, `logical.fqn` | `logicalLocations[0].kind`, `.fullyQualifiedName` | Tension 22, verbatim. SARIF-01 is what makes these non-empty everywhere. |
| `evidence` | `result.message.text` continuation, or `result.locations[0].physicalLocation.region.snippet.text` | Untrusted target output (tension 10). It is already normalised, redacted and truncated on the way in; the emitter escapes it as JSON on the way out and adds no second truncation. |
| `remediation` | `reportingDescriptor.help.text` | On the rule: it is per-check guidance, identical for every result of that rule, and duplicating it per result inflates the file for no information. |
| `references[]` | `reportingDescriptor.helpUri` (first entry that is a URI) and `.help.text` (all entries) | The field is free-text tokens, not necessarily URIs (`rules/RULE-FORMAT.md` §9.1), so a non-URI entry must never become a `helpUri`. |
| `cis[]` | `reportingDescriptor.properties.tags` entries `external/cis/<id>` | Repeatable. Track B's report is a different consumer of the same field. |
| `fingerprint` | `result.partialFingerprints["scourshFingerprint/v1"]` | Tension 22, verbatim, and the reason tension 5 excludes line numbers matters here: a line-based fingerprint would make the consumer's own new/fixed history churn on every unrelated edit. |
| `status` | `result.properties.status` | Tension 22 names it. `new` for every finding until step 7 lands; see "what Track A does not claim". |
| `suppressed`, `suppressed_by` | `result.suppressions[0]` with `kind: "external"`, `justification` from `suppressed_by` | Tension 22: emitted suppressed, never dropped, so the consumer sees the accepted risk rather than a gap. |
| `rule_digest` | `reportingDescriptor.properties.ruleDigest` | Lets a consumer tell "the rule changed" from "the finding changed" (tension 12). |
| `cell` | `result.properties.cell` | Null for derived findings; emitted as JSON `null`, never omitted and never a string sentinel, matching tension 12's own rule for the same field in `state/`. |
| `first_seen`, `last_seen` | `result.properties.firstSeen` / `.lastSeen` | Not `result.provenance`: that structure is about the analysis run, not about finding age. |

### The location model: four cases, not two

Tension 22's RESOLUTION distinguishes "SAST, IaC, and container findings" (real source file) from "cloud, DAST, and posture findings" (generated artifact).
Reading the tree, there are **four** cases, not two, and the two extra ones are the ones a naive implementation gets wrong.
`_fp_profile_for` and `_fp_components_for` in `lib/findings.sh` are the authority for which profile a module has.

| Case | Modules / profiles | `physicalLocation.artifactLocation.uri` | Line |
|---|---|---|---|
| **1. Real working-tree file** | `path` profile: SAST native, SAST adapters, IaC, IaC adapters, and the `containers` module name `_fp_profile_for` already maps to the same profile | `loc_path` (scan-root-relative, already) | `loc_line` |
| **2. Real file, not in the fingerprint** | `sca` profile | the **`path`** field, which SCA sets to the lockfile's relative path | none |
| **3. Real file that may no longer exist** | `history` profile (`SAST-HIST-*`) | `loc_path` **if it still resolves in the working tree**, else the generated artifact | `loc_line` when the path resolves; the artifact line otherwise |
| **4. No file at all** | `dast`, `cloud`, `posture`, `derived` profiles | `locations/<module>.txt`, the generated artifact | the finding's line in that artifact |

Three things about this table are easy to get backwards, and each fails in the direction that reads as a working report.

**Case 2 is not case 4.**
The `sca` fingerprint profile is `ecosystem package advisory_id` and carries no path, so a mapping driven off the fingerprint components alone concludes SCA has no file and sends every dependency finding to the generated artifact.
It has one: `modules/sca/engine.sh` sets the non-fingerprint `path` field to the lockfile, and that lockfile is a real, committed file in the scanned tree that an engineer wants to be taken to.
Do **not** close this by adding `loc_path` to the `sca` profile: that changes the fingerprint of every shipped SCA check id, which `rules/RULE-FORMAT.md` §14 forbids without a `format_version` bump and a `state/` migration.

**Case 3 is the one tension 22 does not name.**
A `SAST-HIST-*` finding is a secret found in a *past commit*.
Its `loc_path` is the path that blob had **in that commit**, and the file may have been deleted, renamed, or never have existed on the current branch.
Tension 22's requirement is that the physical location "always points at a file that genuinely exists", so pointing at `loc_path` unconditionally violates it precisely for the findings most likely to be stale.
The test is a filesystem test at emit time, not an assumption, and the fallback is the generated artifact, whose line carries the blob sha and the commit so the reader can `git show` it.

**Case 4's artifact must exist before the SARIF is written.**
`report_all` writes the SARIF; the location artifact is an input to it, so SARIF-02 lands before SARIF-04 and is not folded into it.

### The three things that make SARIF wrong in a way that reads as right

These are the reasons Track A is six tickets rather than one, and each was verified against the tree.

#### 1. `logical_kind` and `logical_fqn` are empty on every DAST and SAST finding today

Tension 22's "Consequence for the build" says "§13 step 1 fixes the location model in the finding schema so every module records a logical identity from the start".
The **schema** half of that shipped: the fields exist, `finding_set` accepts them, `_finding_json` emits them.
The **population** half did not, for the two largest emitter groups in the tree.

Measured by grepping `logical_fqn` under `modules/`:

| Module | Sets a logical identity? |
|---|---|
| `modules/sca/` (`engine.sh`, `go_engine.sh`) | yes, `kind=dependency`, `fqn=<eco>:<pkg>@<ver>` |
| `modules/iac/` (`parse.sh`, trivy adapter) | yes, `kind=file`, `fqn=<relpath>:<line>` |
| `lib/findings.sh` (derived / composite) | yes, `kind=composite` |
| `modules/sast/` (`engine.sh`, `history.sh`, semgrep and gitleaks adapters) | **no** |
| `modules/dast/` (**27 files that call `finding_emit`**) | **no** |

So a SARIF emitter written today would emit an empty `logicalLocations[0].fullyQualifiedName` for every DAST finding, which is the majority of findings on any run with a target, and for every SAST finding, which is the majority on any run without one.
That is exactly option 2 in tension 22's own options list, the one it rejected as "validates and then invisible" - reached by accident rather than by choice.

The fix is SARIF-01, and its shape matters: the DAST logical identity tension 22 specifies, `<target>:<method> <path_template>#<param>`, is composed **entirely of fields the finding already carries** (`loc_target`, `loc_method`, `loc_path_template`, `loc_param_name`), because those are the `dast` fingerprint profile's own components.
The same holds for `cloud` and `posture`.
So this is a single, profile-driven default computed once in `finding_emit`, not an edit to 27 phase scripts, and this repository has already paid for the alternative reading: "a control each of twelve callers must remember is not a control" is tension 19's argument, restated across `AGENTS.md` for `dast_auth_apply`, `dast_endpoint_in_scope` and the secret backstop.

#### 2. The CVSS score never saw the severity, so it must not become `security-severity`

This is the trap that makes a SARIF file actively misleading rather than merely incomplete.

GitHub code scanning, the largest SARIF consumer and the one `docs/DESIGN.md` §4 names the format for, reads `reportingDescriptor.properties["security-severity"]` as a 0.0-10.0 number and **re-derives its own displayed severity bucket from it**, ignoring `result.level`.
The obvious move is therefore to publish the CVSS score scoursh already computes.

That would be wrong, and the reason is in `lib/findings.sh`:

```
_F[severity]  = severity_final( base_severity, exposure, auth, sensitive_data, confidence, floor, ceiling )
_F[_cvss_*]   = cvss_vector_of(               exposure, auth, sensitive_data, confidence )
```

`cvss_vector_of` takes **four arguments and none of them is a severity**.
The CVSS vector and score are generated from the rubric *facts* alone, as an audit trail for how the rubric moved the severity, and `cvss_score_of` is a frozen 24-row lookup over exactly the 24 vectors that mapping can produce.

The consequence: a `critical` SCA finding and an `info` SCA finding with the same exposure, auth, sensitivity and confidence carry the **same CVSS score**.
Publishing that score as `security-severity` would have a consumer display a severity that contradicts `result.level`, `run.json`, the HTML report and the `--fail-on` gate, all of which agree with each other.

SARIF-04 therefore maps `severity` to `result.level` and carries `cvss` in `result.properties` for audit, exactly as tension 22 says, and **does not emit `security-severity` at all**.
Whether to publish a `security-severity` derived from `severity` instead is a real question with a real cost (it is a fifth place severity is stated, and it must be kept in step with the rubric); it is deliberately left out of this plan rather than decided in passing, and is noted in SARIF-04's own out-of-scope list.

#### 3. Severity becomes legible to other tools for the first time, including where it was never scored

`result.level` in SARIF 2.1.0 has four values: `error`, `warning`, `note`, `none`.
scoursh has five severities.
The mapping is a real decision, not a formality, because it is what a consumer's own gate reads:

| scoursh `severity` | `result.level` | Note |
|---|---|---|
| `critical` | `error` | |
| `high` | `error` | |
| `medium` | `warning` | |
| `low` | `note` | |
| `info` | `note` | **not** `none`: `none` means "this rule did not evaluate to a problem", which is not what an `info` finding says. |

Collapsing five to four loses the `critical`/`high` and `low`/`info` distinctions in `level` alone, which is why `result.properties.severity` carries the original verbatim and `reportingDescriptor.defaultConfiguration.level` carries the check's own base.

The half of this that is genuinely new information for the project: **SCA advisory severities default to `medium` when the upstream advisory publishes none, and nothing downstream currently says so.**
`tools/vendor-engines.sh`'s `_veng_advisories_normalize_severity` takes an optional `DEFAULT` that is `medium` unless overridden, and every SCA ecosystem call site leaves it unset (`data/versions.db`'s `banner` namespace passes `high` explicitly instead, per `docs/VERSIONS-DB.md` §3).
So an advisory that OSV.dev publishes with no severity at all becomes a `medium` finding that is byte-indistinguishable, in `findings.json` and in every report, from an advisory genuinely rated medium.

Today that is invisible.
In SARIF it becomes a `warning` that a consumer's gate acts on, in a feed shared with tools that do carry real scores, which is the first time the difference has a cost.
The honest fix is cheap and is SARIF-04's: `data/advisories.db` rows are the only source of this, so the emitter marks a finding whose severity came from the fallback rather than from the advisory, via `result.properties.severityProvenance`.
That requires the fallback to be **distinguishable at emit time**, which it is not today - the row simply carries `medium` - so the provenance flag is carried from the importer through the db row, and SARIF-04 states plainly in its acceptance criteria that if it cannot be carried, the ticket records the gap in `run.json` rather than shipping a SARIF that silently asserts a score it does not have.

### The honesty constraint: the validation must be real

`docs/DESIGN.md` §12 says `tests/run-tests.sh` "validates JSON/SARIF schema".
Checked against the tree, that promise is **currently unmet in both halves**, and the JSON half is unmet in a way this project's own testing rule names as the worst case.

`tests/suites/report.sh` contains the only JSON validation in the suite.
It is a `python3 -c "json.load(...)"` **well-formedness** parse, not schema validation, over `findings.json`, `findings.jsonl` and `run.json`.
And when `python3` is absent it takes this branch:

```
else
  _t_ok 'python3 unavailable, JSON schema validation skipped'
fi
```

`_t_ok` records a **pass**.
So on any host without `python3`, the suite reports the JSON validation as passing when it did not run - which is the exact shape `AGENTS.md`'s standing rule forbids ("a skipped or unrun suite is NEVER reported as a pass") and which `tools/daily-suite.sh` had to grow `PASS-PARTIAL` and a non-zero exit to avoid for the container leg.

There is no SARIF validation of any kind, because there is nothing to validate.

Tension 22 already anticipated the vacuous-validation failure for SARIF specifically: "§12's 'validates JSON/SARIF schema' passes while the actual ingestion goal fails", and its RESOLUTION closes with a strengthened requirement - validate against the 2.1.0 schema **and** assert that every result's `locations[0].physicalLocation.artifactLocation.uri` is non-empty and points at a path that exists in the run directory or the scanned tree.

SARIF-05 owns making both real.
It is a separate ticket from SARIF-04 deliberately: a ticket that ships an emitter and its own validator tends to ship a validator that agrees with the emitter, which is round 5's lesson recorded in `AGENTS.md` ("four rounds had all written the test after the rule, so every suite agreed with its author's reading").

One constraint SARIF-05 inherits and must not break: **scoursh has no `python3` runtime dependency.**
`python3` appears nowhere under `lib/`, `modules/` or `scan.sh`; it is used only by `tools/vendor-engines.sh`, which runs on a networked box, and by the test suite.
A validator that requires a Python JSON-schema library turns a test dependency into a hard one for anyone running the suite, and reintroduces the skip-as-pass branch on the host that lacks it.
SARIF-05's acceptance criteria therefore require the skip to be a **reported skip**, never a pass, whichever mechanism it chooses.

### What Track A does not claim

Stated here so that a reviewer does not read these as gaps the emitter forgot:

- **Every result will carry `status: "new"`** until step 7 lands, because that is what every finding carries today. The SARIF is correct; the underlying classification is step 7's, and `partialFingerprints` is precisely what lets a consumer do its own tracking in the meantime.
- **`suppressions[]` will always be empty** until STATE-07 lands `config/baseline.json` suppression, for the same reason. The code path is written and tested against a hand-authored suppressed finding, so it is exercised rather than dormant.
- **No cloud or posture result will exist** until step 6 lands. The cloud and posture arms of the location model are built and tested against fixture findings, exactly as `docs/STEP7-STATE-PLAN.md`'s STATE-05 tests against a fixture composite.

### Track A ticket list

#### Tier 0 - the precondition

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **SARIF-01** (landed) | Populate `logical_kind` / `logical_fqn` on every finding | nothing | Tension 22's unmet step-1 precondition | A profile-driven default computed **once**, in `finding_emit` (`lib/findings.sh`), immediately before the fingerprint is computed, and applied only when the emitter has not already set the field - so `modules/sca/`, `modules/iac/` and the composite path keep the identities they set today, byte for byte, and nothing existing changes. Kinds and shapes per tension 22 and the fingerprint profiles: `path`/`history` -> `kind=file`, `fqn=<loc_path>:<loc_line>` (matching the shape `modules/iac/parse.sh` already uses); `sca` -> `kind=dependency` (already set); `dast` -> `kind=endpoint`, `fqn=<loc_target>:<loc_method> <loc_path_template>#<loc_param_name>` **verbatim from tension 22**; `cloud` -> `kind=resource`, `fqn=<loc_resource_key>` (the ARN, per `docs/STEP6-CLOUD-PLAN.md`); `posture` -> `kind=control`, `fqn=<loc_control_id>`; `derived` -> `kind=composite` (already set). **Must not change any fingerprint**: `logical_kind`/`logical_fqn` are not in `_fp_components_for` for any profile, and the acceptance criteria require a test asserting the merged `findings.jsonl` of a fixture run is byte-identical before and after, which is the only form of that claim that can fail. `logical_fqn` is already a `_finding_redacted_field` and stays one, so a DAST fqn built from target-supplied method and parameter data is redacted exactly as it is today. Tests: one per profile asserting a non-empty, correctly-shaped identity, plus a case naming the reading it fails under - a per-module setter passes a single-module test and leaves the other six empty, so the discriminating assertion is over a run that emits in **more than one** profile at once. |

#### Tier 1 - the location artifact

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **SARIF-02** (landed) | The generated location artifact writer, `reports/<run>/locations/<module>.txt` | SARIF-01 | Tension 22's chosen option 3, the physical half | Writes one line per finding whose profile carries no usable file, into a per-module file at the path `lib/core.sh` already creates. Line content is the finding's logical identity (SARIF-01's `logical_fqn`), so the file is human-readable on its own and a click-through in a code-scanning UI lands on a line that describes the resource. The line **number** is recorded back onto the finding for SARIF-04 to use as `region.startLine`. Ordering is deterministic (`LC_ALL=C` over the fingerprint), for the same reason `lib/report.sh`'s emitters are: a run-to-run reorder would churn every `startLine` and defeat the consumer's own diff even though `partialFingerprints` is stable. Covers cases 2, 3 and 4 of the location table above, including the case-3 filesystem test (`loc_path` still resolves under the scan root, or fall back), whose fallback line carries `loc_blob_sha` and `commit` so the reader can `git show` it. **Written unconditionally, not only under `--format sarif`**: it is a real artifact of the run and cheap, and gating it makes the SARIF emitter's behaviour depend on a file another format's flag decided to write. Tests: a fixture run per uncovered profile; a case asserting the file is a real file that exists at the URI the SARIF will cite, which is the assertion tension 22 says the validation must make. |

#### Tier 2 - the emitter

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **SARIF-03** | `report_sarif` skeleton: document, `tool.driver`, `rules[]`, `artifacts[]`, `invocations[]` | SARIF-02 | `docs/DESIGN.md` §4; tension 22's `rules[]` requirement | The static half of the document, with an empty `results[]`. `tool.driver.rules[]` is tension 22's "full loaded check registry, keyed by `check_id`", built from `checks_registry_load` (`lib/checks.sh`). **Three id families have no registry record, and the ticket must handle all three or the SARIF is invalid**, because a `result.ruleId` that matches no `reportingDescriptor` is what consumers reject: (1) **SCA ids** - `modules/sca/` ships no `*.rules` file at all, by design, because SCA is a table lookup rather than a pattern-rule engine (`modules/sca/run.sh`'s own header says so, and `_scan_apply_profile_filter sca` records `no_check_registry_on_disk_yet` on every run); (2) **adapter ids** - `<engine>:<engine's own rule id>` is minted at runtime and never declared in a `*.rules` file (`docs/ADAPTERS.md` §6); (3) **derived ids** - `rules/derived.rules` is deliberately unseeded (findings F5/F20). For all three the descriptor is **synthesised from the finding itself** (id, name from `title`, `help` from `remediation`, `defaultConfiguration.level` from `base_severity`) and carries `properties.descriptorSource: "synthesised"` so the difference is visible rather than hidden. Registry-backed descriptors carry the check's own `remediation`, `references`, `cwe`, `owasp`, `cis` and `rule_digest`. Adds the one `report_all` line that makes `--format sarif` select `report_sarif`, replacing the comment that currently stands in its place. |
| **SARIF-04** | `runs[0].results[]`: the per-finding mapping | SARIF-03 | Tension 22's result requirements; the mapping table in this document | Implements the field-by-field mapping table above, the four-case location table, the five-to-four `level` mapping, `partialFingerprints`, `properties` and `suppressions[]`. Reads `findings.fields` through `finding_decode`, never a hand-rolled parse of that format, exactly as `findings_write_json` and every `lib/report.sh` emitter already do - which is also what keeps the SARIF inside the redaction guarantee, since `finding_emit` is the single chokepoint every finding passes through and `_finding_secret_backstop` has already run by then. **Does not emit `security-severity`**, for the reason given above; that decision is stated in the ticket, not left implicit. Carries the SCA severity-provenance work, or records the gap in `run.json` if the provenance cannot be carried from the db row. Tests must include an escaping case in the shape `tests/suites/report.sh` already uses for the other three formats - a script tag, an ANSI sequence, a raw newline, invalid UTF-8, a backtick run - asserting the SARIF still parses and the bytes are escaped, because evidence is untrusted target output (tension 10) and JSON string escaping is the only defence a SARIF file has. |

#### Tier 3 - proof and documentation

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **SARIF-05** | Make the §12 SARIF **and JSON** validation real | SARIF-04 | `docs/DESIGN.md` §12; tension 22's strengthened validation requirement | Two halves, and the second is a pre-existing defect this ticket is the natural owner of. **(a)** Validate the emitted document against the OASIS `sarif-schema-2.1.0.json`, vendored under `tests/fixtures/` like every other data file this project reads (never fetched: `tools/vendor-engines.sh` is the only script permitted to reach the network and is never called during a test run), **and** assert tension 22's own extra condition - every result has a non-empty `locations[0].physicalLocation.artifactLocation.uri` resolving to a path that exists in the run directory or the scanned tree. A schema pass alone is explicitly insufficient here and tension 22 says why. **(b)** Fix the skip-as-pass in `tests/suites/report.sh`: the `python3`-absent branch currently calls `_t_ok`, reporting validation as passed when it did not run, against `AGENTS.md`'s standing rule. It becomes a reported skip that the suite surfaces, in the shape `tools/daily-suite.sh` already uses for its own skipped GNU leg. Must not add a `python3` runtime dependency to `scoursh` itself - there is none today anywhere under `lib/`, `modules/` or `scan.sh`. Every test names the reading it fails under: a validator that only checks well-formedness passes against a document with an empty `ruleId`, so the discriminating fixtures are a finding with a synthesised descriptor and a finding in each of the four location cases. |
| **SARIF-06** | SARIF documentation, and correcting the stale `--format` prose | SARIF-05 | `docs/DESIGN.md` §13 item 10's "docs/README" | Documents the emitter for an operator: what is in the file, what is deliberately not (the out-of-scope list above), how `partialFingerprints` interacts with a consumer's own tracking, and the explicit statement that `security-severity` is absent and why, since that is the field a GitHub-code-scanning user will look for first. Replaces the three "there is no SARIF writer anywhere in the tool" statements that are correct until Track A lands and false the moment it does: `README.md`'s "Known defects" entry, `docs/USAGE.md`'s global-flag table row for `--format`, and `docs/USAGE.md`'s "`--format` and the `formats` config key" section. (The **other** half of those three places - the claim that `--format` is inert and that every run writes all five artifacts - was already stale before this plan existed and was corrected in the change that added it, so this ticket inherits three accurate paragraphs that need one sentence each updated, not three wrong ones.) |

Six tickets.
SARIF-01 and SARIF-02 are the only two that touch files outside `lib/report.sh`, and neither touches a module: SARIF-01 is one function in `lib/findings.sh`, SARIF-02 is one new writer.
That is what keeps Track A parallelisable against STATE-0x and CLOUD-0x work, which touch `lib/state.sh` and `modules/cloud/` respectively.

## Track B - the compliance-mapping report

`docs/DESIGN.md` §4: "Group findings by OWASP Top 10 (Appendix B) and CIS AWS Benchmark control id (from `data/cis-mappings`), so the same scan produces both an engineering view and a compliance view."

### `data/cis-mappings` does not exist, and what it is for is not what §4 implies

Verified: `data/` contains exactly one file, `data/severity-rubric.conf`.
There is no `cis-mappings` anywhere in the tree, and the string appears in exactly two places, both of them `docs/DESIGN.md` (the §3 directory layout comment and the §4 sentence above).
`data/versions.db` and `data/advisories.db` are also absent, but deliberately and for a different reason: they are vendored by `tools/vendor-engines.sh` on a networked box and are absent by default in every checkout.

The part §4's wording gets ahead of, and which whoever picks up COMPLIANCE-03 must not implement literally: **the CIS control id is not looked up from a mappings file. It is authored on the check.**

`rules/RULE-FORMAT.md` §9.1 gives every check record an optional, repeatable `cis` field, described there as "CIS control id, for the compliance report"; §9.2 and §9.5 repeat it for the cloud/posture and script-check schemas; `lib/records.sh` declares it in all three field tables; `lib/findings.sh` copies it onto the finding; and `_finding_json` emits it.
`docs/STEP6-CLOUD-PLAN.md` already relies on this, telling every per-service ticket that "the `cis` field is an existing optional/repeatable field on every finding record ... No schema change is needed".
The format is **frozen**.

So a `data/cis-mappings` that supplied control **ids** would be a second, drifting source for a fact the frozen record format already carries - the exact failure `docs/VERSIONS-DB.md` cites when it says a db row deliberately carries no CWE, "a row that carried its own would be a second, drifting source for the same fact".

What the file is genuinely needed for is the thing a bare id cannot supply and a rule record has no business carrying: rendering `1.4` as **"1.4 - Ensure MFA is enabled for the root user account"**, in a named benchmark at a named version.
That is a vendored reference table keyed by control id, in the same family as `data/versions.db`, and it is what COMPLIANCE-03 specifies.

### The OWASP half is unblocked; the CIS half is not

**OWASP is achievable today.**
`owasp` is a **required** field on every pattern-rule record (`rules/RULE-FORMAT.md` §9.1), validated by `E026` against `^(A[0-9]{2}:[0-9]{4}|none)$`, and every module that emits findings sets it.
The HTML report already counts by category.
Nothing about grouping by OWASP needs step 6 or step 7.

**CIS is not.**
`docs/DESIGN.md` §4 says "CIS **AWS** Benchmark control id", and §8.1's closing sentence makes citing it a requirement of the live cloud checks specifically.
The check families that carry a `cis` value are the cloud and posture ones, and `modules/cloud/` does not exist: zero of `docs/STEP6-CLOUD-PLAN.md`'s CLOUD-01 through CLOUD-34 and POSTURE-01 through POSTURE-04 has landed.
A CIS compliance view built today would render an empty table on every possible run, and no test could distinguish "correctly reports no CIS findings" from "silently fails to find them" - which is the same absence-of-a-test-reading-as-a-clean-result failure `docs/DESIGN.md` §15 and this project's DAST work repeatedly name.

That split is why Track B is four tickets across two readiness states rather than one deliverable.

### One thing the record format promises and nothing implements

`rules/RULE-FORMAT.md` §9.1's `owasp` row ends: "The report expands it to the full label."
Nothing in the tree expands anything.
`lib/report.sh`'s `_RPT_OWASP` table renders the bare id, `report.md` has no OWASP section at all, and there is no id-to-label table of any kind: the only occurrences of an OWASP category's name anywhere under `lib/`, `modules/` or `scan.sh` are three incidental ones in a finding title and two remediation/comment strings, none of them keyed by an id and none reachable from a report.
COMPLIANCE-01 closes that, and it is listed first because both report views depend on it.

### Track B ticket list

#### Unblocked today

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **COMPLIANCE-01** | The OWASP category label table and its expansion | nothing | `rules/RULE-FORMAT.md` §9.1's unimplemented "The report expands it to the full label" | A vendored, auditable data table mapping each `A<nn>:<yyyy>` id to its published category name, read from disk rather than compiled into a `case` statement, for the same reason `data/severity-rubric.conf` is data: it is reviewable and diffable. Covers the OWASP Top 10 2021 set that `E026`'s pattern admits and that Appendix B names. An id with no row renders as the bare id plus a recorded reason, never as a blank or an invented label - a category the table has never heard of and a category with no findings must not look the same. `none` is a legal value on a real check and is not a missing label; it renders as "not categorised" and is counted separately. Tests assert both directions: a known id expands, an unknown id degrades visibly. |
| **COMPLIANCE-02** | The OWASP compliance view in `report.md` and `report.html` | COMPLIANCE-01 | `docs/DESIGN.md` §4's "compliance view"; Appendix B | Groups the **findings** by category, not merely counts them, which is what makes it a compliance view rather than the summary table `lib/report.sh` already renders; the existing `_RPT_OWASP` count table is kept and gains the label. Adds the equivalent section to `report.md`, which has none today. Renders Appendix B's coverage statement honestly alongside it - A04 not covered, A08/A09/A01 partial - because a compliance view that lists ten categories with findings under seven of them implies the other three are clean, and Appendix B exists precisely to say two of those three were never in scope. A category that is in scope and genuinely produced no finding, a category that is out of scope by design, and a category whose checks were filtered out of this run by `--profile-scan`/`--intensity` (tension 15) are three different facts and must render as three different things; `checks_run` and the run's `coverage_reduction` records are what distinguish them and are already written. HTML stays self-contained with the inline CSP and no `<script>`, per tension 10. |
| **COMPLIANCE-03** | `data/cis-mappings`: the format, the vendored file, and its importer | nothing | `docs/DESIGN.md` §3 and §4's named path | Specifies and creates the file **as a control-id-to-label reference table, not as a source of control ids** (see above). Format follows `data/versions.db`'s precedent, and the choice between the frozen `rules/RULE-FORMAT.md` record format and a TSV is made by the same rule that already governs it: human-authored files use records, machine-generated files use JSON or the frozen TSV. Since this table is transcribed from a published benchmark PDF by a human, it is a **records** file. Carries the benchmark name and version, because "CIS AWS Foundations Benchmark v3.0.0 control 1.4" and "v1.4.0 control 1.4" are different controls and a table that cannot say which it is silently misattributes findings. Ships a documented refresh procedure in the shape `docs/VERSIONS-DB.md` §5 already uses for the `banner` namespace, because a list nobody can refresh becomes wrong quietly. **This ticket is unblocked and lands the format and the table; it renders nothing.** It is separable from COMPLIANCE-04 for exactly that reason, and landing it early means step 6's own CLOUD-0x tickets have a table to check their `cis:` values against as they are written, rather than after. |

#### Blocked on step 6

| # | Ticket | Depends on | Implements | Notes |
|---|---|---|---|---|
| **COMPLIANCE-04** | The CIS compliance view in `report.md` and `report.html` | COMPLIANCE-02, COMPLIANCE-03, **and `modules/cloud/` existing** | `docs/DESIGN.md` §4's CIS half; §8.1's "every finding cites ... the CIS control id" | Groups findings by CIS control id, expanded through COMPLIANCE-03's table, and states the benchmark name and version at the head of the section. **Blocked on step 6**, and specifically on the first CLOUD-0x or POSTURE-0x ticket that emits a finding carrying a `cis` value: until then the view has no possible input and no test can tell a correct empty table from a broken one. It is **not** blocked on all of step 6 - one landed cloud check is enough to build and test against, so this ticket can be picked up well before CLOUD-34. Mirrors COMPLIANCE-02's honesty requirement: a control with no finding because it was assessed and passed, a control with no finding because its check has not been written, and a control not applicable to the account scanned are three different facts. Carries its own operator documentation, per §13 item 10's "docs/README". |

Four tickets, three of them available now.

## What this plan deliberately does not cover

- **`--fail-on`.** Shipped. See "What already shipped" above.
- **`--fail-on-new`.** `docs/STEP7-STATE-PLAN.md`'s STATE-08 owns it. A SARIF-0x ticket that touches `sast_evaluate_gate` is out of its lane.
- **A compliance `--profile-scan compliance` behaviour change.** The profile already exists and already filters on the `compliance` tag (tension 15, finding F3 closed). Track B renders findings; it does not change which checks run.
- **Any new `--format` value, config key, or exit code.** Track A adds an emitter behind an existing, already-validated value.
- **`security-severity`.** Deliberately excluded, with the reason recorded in SARIF-04 rather than left as an omission.

## Fixture and test obligations, stated once

Every SARIF-0x and COMPLIANCE-0x ticket carries its own tests in the same change, per this project's convention: there is no separate test ticket.

Every test names the reading it fails under, per the `AGENTS.md` testing rule.
That rule has unusually sharp teeth on this step, because most of the ways a SARIF emitter is wrong produce a file that parses, validates, and is silently useless - an empty `fullyQualifiedName`, a `ruleId` matching no descriptor, a `physicalLocation` pointing at a path that does not exist, a `security-severity` contradicting `level`.
Each of those passes a well-formedness check and a schema check alike.
Tension 22 says so directly, and its strengthened validation requirement is the floor rather than the ceiling.

Three specific obligations:

1. **The SARIF schema is vendored, never fetched.** `tests/fixtures/` is its home, alongside every other data file the suite reads. `tools/vendor-engines.sh` is the only script permitted to reach the network and is never invoked during a scan or a test run.
2. **No new runtime dependency.** `scoursh` uses no `python3` anywhere under `lib/`, `modules/` or `scan.sh` today, and SARIF-05 must not change that. If its validator needs a tool the host may lack, the absence is a **reported skip**, never a pass.
3. **The location assertion is filesystem-backed.** "Every result cites a file that exists" is checkable by `test -e` against the run directory and the scanned tree, and asserting it any other way asserts the emitter agrees with itself.

## Doc-update process

Per `AGENTS.md`'s "Build order and where we are" process rule, whoever lands **SARIF-01** (the first real step-10 code) updates both `AGENTS.md`'s "Current position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section in the same change, and runs `tools/gen-status.sh --write` if any generated block is affected.
The same rule applies to whoever lands the last ticket of either track and thereby completes it.

`ROADMAP.md`'s "Not yet started" entry for step 10 is updated by the same changes, and its "Known defects" list, along with `README.md`'s and `docs/USAGE.md`'s, loses its remaining SARIF entry as SARIF-06 lands.

`docs/DESIGN.md` itself stays verbatim.
It is never the place build-order status is recorded, and this plan does not propose editing it even where its §4 wording about `data/cis-mappings` is ahead of the frozen record format: that divergence is recorded here and, if it needs to be settled formally, belongs in `docs/FOUNDATION.md` as a tension, which is the document that wins where it contradicts `docs/DESIGN.md`.
