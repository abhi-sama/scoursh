# Optional engine adapters - directory convention and interface contract

> Normative and self-contained, the same way `rules/RULE-FORMAT.md` is: read this document alone to
> build or review an adapter, without needing the ticket that shipped it.
> `docs/DESIGN.md` §9 and §13 step 9 are the handoff spec this document implements; `docs/DESIGN.md` is
> preserved verbatim and is never edited to match this file - where the two differ, this document says
> so explicitly (see "Relationship to `docs/DESIGN.md`" below).
> `docs/FOUNDATION.md` Tension 27 records why this shape was chosen; this document states the contract
> itself.

## 1. What an adapter is, and what it is not

An adapter lets scoursh call a **vendored, offline, third-party engine** (`semgrep`, `gitleaks`,
`checkov`, ...) as an opt-in power-up on top of the native pattern-rule engine, per `docs/DESIGN.md` §9's
two-tier model: native is the zero-dependency default, engine-boosted is opt-in and adds taint/data-flow
depth the native engine cannot do in bash.

An adapter is **not**:

- a new way to reach the network at scan time (§2 below is absolute on this),
- a replacement for a module's native `*.rules` packs (native and adapter findings are merged and
  deduped, never one replacing the other),
- required for `scoursh` to run. Every module works with zero adapters present, exactly as it does
  today; an absent adapter degrades a run's *exhaustiveness*, never its *correctness* or its ability to
  complete. `tests/suites/vendor-engines.sh` and the rest of the suite prove this holds with the
  `adapters/` directories absent entirely, which is the state of every module as of this document.

**Zero adapters existed as of this document's first version.** It defined the convention a future
**single-engine-adapter ticket** would implement independently; each concrete adapter (`semgrep`,
`gitleaks`, an IaC engine, ...) is its own ticket, never bundled with the scaffold or with another
engine. **The first concrete adapter ticket has since shipped the first one** -
`modules/sast/adapters/semgrep/` - exactly as this section anticipated, one ticket, no others bundled
with it. §3 and §9 below are updated accordingly; the rest of this document's contract is unchanged by
that landing, which is the point of freezing the contract before the first adapter rather than after.
**A second concrete adapter ticket has since shipped a second one** - `modules/iac/adapters/trivy/`
(`trivy config`) - the first for a module other than `sast`, proving §4's directory-convention
generalization for real rather than leaving it a claim about a hypothetical future module. Nothing in
§2 through §8 needed to change to accommodate it; only §9's roster gained a row.
**A third concrete adapter ticket has now shipped the third one**, independently, on top of the
plumbing (`lib/engines.sh`, `--use-engines`) the first one built -
`modules/sast/adapters/gitleaks/`, still one ticket, no others bundled with it, and still no change to
this document's own contract; only §9's roster table gains another row.

## 2. The no-egress rule, restated for this document

Exactly one script in the whole repository is permitted to touch the network: `tools/vendor-engines.sh`
(`docs/DESIGN.md` §9, §13 step 9; `docs/FOUNDATION.md` Tension 27). It runs **once, by an operator, on a
networked box**, never as part of a scan, and it is the **only** place a `curl`/`wget` call vendoring an
engine's binary or ruleset is permitted to live.

This has one direct, load-bearing consequence for adapter code:

- **`adapter.sh` never fetches anything.** It only *detects* a vendored binary already committed to the
  repository at a fixed path (§4), *runs* it fully offline, and *normalizes* its output. It contains no
  `curl`, `wget`, `nc`, `ncat`, `netcat`, or `openssl s_client` invocation, and it never sources or calls
  `tools/vendor-engines.sh`.
- `tests/lint-shell.sh` enforces both directions: the tension-19 "no bypass" check (no bare
  curl/wget/nc/openssl outside `lib/http.sh`, now also excepting `tools/vendor-engines.sh` itself,
  §2 of this document) covers `adapter.sh` like every other file under `modules/`, and a second check
  added by this document's own ticket fails the build if anything under `scan.sh`'s dispatch path
  (`lib/`, `modules/`, `scan.sh`) sources, calls, or otherwise references `tools/vendor-engines.sh` -
  the two checks together are what makes "the only script permitted to reach the network" a property CI
  actually checks, not a comment someone can drift away from.

## 3. Runtime gating

`docs/DESIGN.md`'s directory layout names `lib/engines.sh` ("detect optional vendored engines; expose
`has_engine()`") and §6.4 names the `--use-engines` flag that must be given, together with a passing
`<engine>_detect`, before an adapter runs at all. **Both now exist**, built together with
the first concrete adapter, mirroring how `--paranoid`'s flag landed together with its first real
enforcement rather than as a separate ticket.

`has_engine MODULE ENGINE` (`lib/engines.sh`) answers exactly one pure filesystem question: does
`modules/<module>/adapters/<engine>/adapter.sh` exist, and does sourcing it and calling its own
`<engine>_detect` return 0? It is memoised per `(module, engine)` pair and deliberately never reads
`--use-engines` itself - the two conditions below are independent and ANDed together **at the calling
module's own call site**, never collapsed into `has_engine`:

```sh
if [[ ${SCAN_FLAGS[use-engines]:-} == true ]] && has_engine sast semgrep; then
  _sast_run_semgrep_adapter "$path"
else
  run_record coverage_reduction 'module=sast reason=engine_not_vendored engine=semgrep'
fi
```

`--use-engines` itself is a `scan.sh` global flag (alongside `--paranoid`, `--allow-intrusive`, ...);
`scan.sh` records its value into `run.json` (`run_record use_engines <bool>`) for every run regardless of
outcome, but does not itself call `has_engine` or run any adapter - that happens at each module's own
call site, per the snippet above. `lib/checks.sh`'s own registry-based filter chain
(`--profile-scan`/`--intensity`/`--allow-intrusive`) never reaches an adapter's findings either way: an
adapter check id is minted at runtime, not declared in a `*.rules` file, so that filter chain has nothing
of its own to select or drop (§6 below).

## 4. Directory convention

```
modules/<module>/adapters/<engine>/
  adapter.sh   # the three-function contract, §5 below
  bin/         # the vendored engine binary (or binaries), committed to git,
               # populated by tools/vendor-engines.sh on a networked box
  rules/       # the vendored local ruleset/config the engine runs against
               # offline, committed to git, populated the same way
```

- `<module>` is the scoursh module the adapter augments - `sast`, `iac`, and so on. `docs/DESIGN.md`'s
  own tree diagram shows `adapters/` only under `modules/sast/` (§3, §6.4), because SAST is the only
  module the spec text discusses engines for by name; this document generalizes the same convention to
  any module, which `docs/FOUNDATION.md` Tension 27 records as a deliberate extension DESIGN.md's literal
  diagram does not show but does not forbid either - IaC's `checkov`/`tfsec`/`trivy config` engines
  (`docs/DESIGN.md` §6.6's own "same pattern as §6.4" note) are the first case this generalization
  exists for.
- `<engine>` is the vendored tool's own name, lowercase, matching the check-id prefix §6 below uses -
  `semgrep`, `gitleaks`, `checkov`, and so on.
- `bin/` and `rules/` are conventional subdirectory names, not a schema this document freezes further;
  an adapter with no local ruleset (a self-contained binary) may omit `rules/`, and an adapter needing
  more than one binary may add further files under `bin/`. What is frozen is `adapter.sh`'s three
  functions (§5) and that nothing outside `bin/`/`rules/` under the adapter's own directory is ever
  fetched from the network by anything other than `tools/vendor-engines.sh`.
- No adapter directory existed on disk as of this document's first version; `modules/sast/adapters/semgrep/`
  is now the first (this ticket), created from nothing per this section - there was no placeholder or
  template file to copy, since an empty directory carries no content for git to track and a stale
  template would only have invited drift from this document, which is the actual contract. A future
  second adapter ticket does the same thing again, independently, for its own `<module>/<engine>` pair.

## 5. The `adapter.sh` interface contract

`adapter.sh` declares exactly three functions, named after the engine so that two adapters sourced into
the same process never collide:

| Function | Signature | Contract |
|---|---|---|
| `<engine>_detect` | `<engine>_detect` (no args) | Returns 0 if this engine's vendored binary (and ruleset, if it needs one) exists on disk at its fixed path under `bin/`/`rules/` **and** is executable; 1 otherwise. Pure filesystem check. Never touches the network, never runs the engine, never writes anything. |
| `<engine>_run` | `<engine>_run OUTPUT_FILE TARGET...` | Runs the vendored engine, fully offline, against `TARGET...` (paths under the scan root), writing the engine's own **native** JSON output to `OUTPUT_FILE`. Every invocation is the engine's own documented offline/no-update flag (`semgrep --offline --config <vendored rules>`, `gitleaks --no-banner`, ...) per `docs/DESIGN.md` §6.4/§9. Exits non-zero only on genuine engine failure, in which case the caller records a `coverage_reduction` and continues the run rather than aborting it (§7). |
| `<engine>_normalize` | `<engine>_normalize INPUT_FILE` | Reads `INPUT_FILE` (the file `<engine>_run` wrote) and, for every finding the engine reported, calls `lib/findings.sh`'s public API - `finding_new`, `finding_set`, `finding_set_evidence`, `finding_set_match`, `finding_emit` - to produce a scoursh finding record. Never assigns to the internal `_F` array directly (`tests/lint-shell.sh`'s existing "no direct assignment to a redacted field" check already forbids this repository-wide); never invents a field the finding schema does not have. |

All three are pure functions of their arguments and the filesystem; none of the three accepts a secret
or writes one to argv (`docs/FOUNDATION.md` tension 9 applies here exactly as it does to every other
engine file).

## 6. Check ids: `rules/RULE-FORMAT.md` §9.1.1a, not a new scheme

An adapter-produced finding's `check_id` uses the **adapter check id** namespace `rules/RULE-FORMAT.md`
§9.1.1a already freezes: `<engine>:<engine's own native rule id>`, for example
`semgrep:python.lang.security.eval` or `gitleaks:generic-api-key`. This document does not define a new
convention; it points at the one that already exists so the two cannot drift apart. Consequences that
follow directly from that section, restated here because they are easy to miss:

- Adapter check ids are **never** declared in a `*.rules` file or a `checks.rules`. They are produced at
  runtime by `<engine>_normalize` and are never linted by `tests/lint-rules.sh` (there is no record for
  it to check).
- Adapter check ids are unique **within their own adapter's output only**, not across the whole
  check-id namespace `rules/RULE-FORMAT.md` §9.1.1's table governs. Two different adapters, or an
  adapter and a native pattern rule, may produce unrelated findings that happen to share unrelated ids
  in different namespaces without conflict - that is what namespacing means.
- Because an adapter check id carries no `MODULE-FAMILY-NAME` shape, it is not a candidate for
  `_scan_apply_profile_filter`'s check-registry selection (`lib/checks.sh`) or for `state/`'s
  `covered_checks`. **This ticket settled this, rather than leaving it open**: `--profile-scan`,
  `--intensity` and `--allow-intrusive` narrow or widen NATIVE pattern-rule/script-check selection only
  and never reach an adapter's findings; whether an adapter's findings appear in a run is governed
  entirely by `--use-engines` plus that adapter's own `<engine>_detect` (§3), independent of every other
  filter. `lib/checks.sh`'s own header now states this boundary explicitly. `state/`'s
  `covered_checks` interaction is still open - `state/` itself does not exist yet (§13 step 7) - and is
  left for whichever ticket builds it.

## 7. Graceful degradation is mandatory, not best-effort

An absent, un-vendored, or failing adapter must never make a scan error, and must never silently produce
fewer findings without saying so. The contract, mirroring the pattern every `not_yet_built`/
`no_advisories_db_on_disk`/`engine_not_vendored`-style module gap already uses (`lib/core.sh`'s
`run_record`) - simplified here to the `<engine>_detect` boundary; §3 above shows the full call site
including the `--use-engines` flag check `has_engine` wraps around exactly this:

```sh
if <engine>_detect; then
  <engine>_run "$out_json" "${targets[@]}"
  <engine>_normalize "$out_json"
else
  run_record coverage_reduction "module=<module> reason=engine_not_vendored engine=<engine>"
fi
```

`<engine>_run` failing (a real engine crash, not "absent") is handled the same way: log it, record a
`coverage_reduction` with a distinct reason, and continue the run with native-only results for that
module - never abort the whole scan for an opt-in power-up.

`tests/suites/vendor-engines.sh` and the rest of the pre-this-ticket suite together proved the
zero-adapter case: every suite passed with no `modules/*/adapters/` directory on disk anywhere, because
no module's `run.sh` called into an adapter at all. **This ticket added the fixture proving the `else`
branch above for real**: `tests/suites/sast-semgrep.sh`'s "graceful degradation" section runs a real
`scan.sh sast --use-engines` subprocess against an install root that genuinely has no
`modules/sast/adapters/semgrep/` on disk, and asserts the exact `coverage_reduction
reason=engine_not_vendored engine=semgrep` line plus an unaffected exit code - and a second case, with
neither `--use-engines` given, asserts not even that line appears, proving "unmodified default
behaviour" rather than merely "no crash".

## 8. Round-trip requirement

A normalized adapter finding must survive fingerprinting, redaction, and every report format (JSON,
SARIF, HTML, Markdown) **identically** to a native finding - same schema, same redaction rules, same
emitters. This falls out of §5's requirement that `<engine>_normalize` only ever calls
`lib/findings.sh`'s existing public functions: those functions are exactly what a native pattern-rule
finding and an SCA table-lookup finding already go through, so an adapter finding gets the same
guarantees for free rather than needing its own emitter path. **This ticket (`tests/suites/sast-semgrep.sh`,
section C) is the fixture that proves this empirically**: a real `scan.sh sast --use-engines` subprocess
against a genuinely vendored (fake, stand-in) `semgrep` binary, asserting the resulting
`semgrep:<rule id>` finding appears, correctly, in `findings.jsonl`, `findings.json`, `report.md` and
`report.html` alike. **The trivy ticket (the second concrete adapter) has since shipped the equivalent
fixture for its own engine's output shape**, and **the gitleaks ticket (the third concrete adapter) has
now shipped the equivalent fixture for its own engine's output shape too**: `tests/suites/sast-gitleaks.sh`
section C runs a real `scan.sh sast --use-engines` subprocess against a genuinely vendored (fake,
stand-in) `gitleaks` binary and asserts the resulting `gitleaks:<rule id>` finding round-trips through
the same four formats.
A fourth concrete adapter's own ticket is responsible for the same fixture shape against its own engine's
output; this document states the requirement generally, it no longer has to prove it from nothing for
any of the three shapes already covered.

## 9. Roster

| Module | Engine | Status |
|---|---|---|
| sast | semgrep | shipped (the semgrep ticket, the first concrete adapter) - `modules/sast/adapters/semgrep/`; zero real binaries vendored in this repository (§1/§2 - `tools/vendor-engines.sh` is the only way to populate `bin/`/`rules/`, and nobody has run it here) |
| iac | trivy (`trivy config`) | shipped (the trivy ticket, the second concrete adapter, the first for a module other than sast) - `modules/iac/adapters/trivy/`; zero real binaries vendored in this repository (§1/§2, same as above). Detects on `bin/trivy` alone - no `rules/` is vendored, since trivy's misconfiguration checks are compiled into the binary itself (§4's "self-contained binary" case; see the adapter's own header for why `trivy config` was picked over `checkov`/`tfsec`) |
| sast | gitleaks | shipped (this ticket, the third concrete adapter) - `modules/sast/adapters/gitleaks/`; zero real binaries vendored in this repository, identically to semgrep above. Deduplicates against `modules/sast/rules/secrets.rules`' native findings by (loc_path, loc_match_digest) - a narrower, cross-check-id identity the ordinary per-run fingerprint dedup cannot catch on its own, since `check_id` is itself one of the fingerprint's hashed components (`modules/sast/adapters/gitleaks/adapter.sh`'s own `_gitleaks_dup_of_native_secret`) |

A concrete adapter ticket adds its own row here in the same change that ships it, per the project's
build-order process rule (`AGENTS.md`'s "Process rule" paragraph, `docs/FOUNDATION.md`'s mirror) - the
same rule that already governs `AGENTS.md`'s "Build order and where we are" section, applied to this
table instead of prose so a landed adapter cannot go unrecorded here either.

## 10. Relationship to `docs/DESIGN.md`

`docs/DESIGN.md` is preserved verbatim and is never rewritten to match this document. Two places worth
being explicit about, so a future reader does not mistake generalization for contradiction:

- §3's tree diagram and §6.4 show `adapters/` only under `modules/sast/`, naming `semgrep`/`gitleaks`.
  This document's directory convention (§4) generalizes the same shape to any module. That is an
  **extension**, not a correction: DESIGN.md's own §9 and §13 step 9 already speak of `adapters/` and
  `tools/vendor-engines.sh` without confining them to SAST, and §6.6 separately invites the same pattern
  for IaC ("same pattern as §6.4"). `docs/FOUNDATION.md` Tension 27 records the extension and why it
  does not need a DESIGN.md amendment.
- §6.5's SCA section and `docs/FOUNDATION.md` Tension 25 give `tools/vendor-engines.sh` a **second**,
  unrelated responsibility - expanding `data/advisories.db`/`data/versions.db`'s version ranges into
  exact-version rows on the networked box. That responsibility is real, already committed, and
  unimplemented; it is explicitly **not** built by this ticket (see `tools/vendor-engines.sh`'s own
  header for where that boundary is drawn) and is not an "engine adapter" in this document's sense at
  all - it shares the script for the same reason it shares the no-egress rule, not because it is part of
  this convention.
