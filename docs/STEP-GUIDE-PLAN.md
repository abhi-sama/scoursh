# Guided interactive mode sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that the guided interactive mode - `scan.sh --guided`, a mode that asks the operator
what to scan and composes the equivalent flags rather than requiring them to be typed - can be
picked up as a clean sequence of small, independently reviewable tickets (GUIDE-01 through
GUIDE-07) the moment it is claimed, instead of being re-derived from scratch by whoever picks it up
first, mirroring `docs/STEP5-DAST-PLAN.md`, `docs/STEP6-CLOUD-PLAN.md` and `docs/STEP7-STATE-PLAN.md`
for their steps.

This design was originally written and reviewed inside `docs/STEP5-DAST-PLAN.md`, because the ticket
that first proposed it was thinking about the DAST target-authorisation flow.
It covers `sast`, `sca`, `iac` and `cloud` as well as `dast`, was never actually DAST-specific, and an
audit of this project's status documents (2026-09-02) found it was real, planned, unbuilt work that
appeared in no top-level document - not `ROADMAP.md`, not `AGENTS.md`, not `docs/DESIGN.md` - because it
was buried inside a document about DAST.
This document is that fix: the design and the per-ticket table below are moved here verbatim (reworded
only where a sentence stopped making sense out of its old context), `docs/STEP5-DAST-PLAN.md` keeps a
short pointer at the old location, and `ROADMAP.md` now lists this plan under "Not yet started" so a
reader of the roadmap can actually find it.
No design decision changes in this move; see "Relationship to the ten-step build order" below for the
one genuinely new thing this document adds - a stated position on whether guided mode is one of
`docs/DESIGN.md` §13's ten steps.

## Status: GUIDE-01 landed; GUIDE-02 through GUIDE-07 remain unclaimed

**GUIDE-01 has landed.** `lib/guide.sh` exists and ships `guide_may_prompt`, `guide_menu`, `guide_ask`,
`guide_confirm`, and `_guide_shquote`, plus the guided-scope `INT`/`TERM` signal trap and the test-only
`SCOURSH_GUIDE_FORCE_TTY` hook, all exactly as this row specifies below.
`scan.sh` now sources `lib/guide.sh` (so a later ticket's `scan_main` routing needs no new source line),
but calls none of it: `scan.sh` still accepts neither `--guided` nor `--print-command`, and no menu is
wired to any real scan.
`tests/suites/guide.sh` (70 assertions) is the proof, and per this row's own instruction it proves the
**refusals** - piped stdin, each of the nine non-interactive environment markers, `SCOURSH_NO_PROMPT`,
EOF mid-flow, and SIGINT mid-flow - each exiting non-zero (or 0 for the SIGINT cancel path) without
blocking and without creating a run directory, including reproducing the pre-existing SIGINT-under-
`core_on_signal` exit-5 defect first and then showing `guide_menu`'s own trap fixing it.
GUIDE-02 through GUIDE-07 remain unclaimed and are otherwise unaffected by this landing (verified
against the tree: `scan.sh` has no `guided` or `print-command` key in `_SCAN_FLAG_KIND`, and no
`modules/` or `lib/` file outside `lib/guide.sh` calls a `guide_*` function).

Unlike step 6 or step 7, this work carries **no build-order gate at all** - it was never blocked on SAST,
SCA/IaC, or DAST completing, and nothing here waits on step 6 (cloud) or step 7 (state) either.
The only dependencies are internal, ticket-to-ticket:

- **GUIDE-01** (`lib/guide.sh` - the prompt gate, the signal trap, the menu primitives) has **no
  dependency of any kind** and can start immediately.
- **GUIDE-02** (`--guided`, `scan_main` routing, the `_scan_check_required` split) depends only on
  GUIDE-01.
- **GUIDE-03** (the scan-type menu, local-surface follow-ups, prerequisite honesty) depends only on
  GUIDE-02.
- **GUIDE-04** (the DAST branch and the affirmation) depends on GUIDE-02 and, structurally, on DAST-32
  (the flags a DAST prompt would emit have to exist before the prompt can emit them).
  **The DAST half of that dependency is already cleared**: DAST-32 landed as part of step 5, which
  completed in full (`docs/STEP5-DAST-PLAN.md`'s own status section; `docs/AGENTS.md`'s generated status
  block).
  Verified directly rather than taken on the status section's word: `lib/http.sh` already enforces the
  conservative ceilings and refers operators to `--i-own-target` by name (`lib/http.sh` around line
  1168).
  So GUIDE-04 today is blocked on GUIDE-02 alone, not on any DAST work.
- **GUIDE-05** (the `config/scope.conf` record writer) depends on GUIDE-02, GUIDE-03, and
  `lib/records.sh`, which shipped at step 1 and needs nothing further.
- **GUIDE-06** (the review screen, `--print-command`, the argv round-trip) depends on GUIDE-03, GUIDE-04
  and GUIDE-05.
- **GUIDE-07** (documentation: the guided quickstart, the flag table, the honest status column) depends
  on GUIDE-06.

**In short: this is a single chain, GUIDE-01 through GUIDE-07 in that order (GUIDE-04 and GUIDE-05 can
run in parallel once GUIDE-02/GUIDE-03 land) - GUIDE-01 has now landed, and GUIDE-02 through GUIDE-07
remain unclaimed - and every "blocked" reading this design once carried while DAST was still unbuilt is
stale.**
The old framing (visible in `docs/STEP5-DAST-PLAN.md`'s edit history) treated GUIDE-04 as waiting on DAST
completing; DAST is now complete, so the honest statement of what blocks GUIDE-04 today is "GUIDE-02
hasn't landed," the same as every other ticket in the chain past GUIDE-01.
See `ROADMAP.md` for where this plan sits in the project's overall priority order relative to step 6,
step 7 and step 10 - that ordering, not this status section, is the one to check first.

## Relationship to the ten-step build order

**Guided interactive mode is not one of `docs/DESIGN.md` §13's ten build steps, and this document
deliberately does not propose making it an eleventh.**
It is cross-cutting work that sits outside the numbered build order entirely: `docs/DESIGN.md` names no
guided or interactive mode anywhere in its text (verified: no case-insensitive match for "guided" or
"interactive" in that file), so there is no §13 step this design could be said to complete, unlike step
8 (`--paranoid`) or step 9 (engine adapters), which really are numbered steps that happened to land out
of sequence.

The reason this document states that plainly rather than inventing a "step 11" is `AGENTS.md`'s own
frozen-document rule, which this plan inherits rather than overrides: `docs/DESIGN.md` is "the handoff
spec... preserved verbatim; its wording is load-bearing," and it is "never the place build-order status
is recorded" (`docs/STEP6-CLOUD-PLAN.md`'s and `docs/STEP7-STATE-PLAN.md`'s own "Doc-update process"
sections both say this identically).
Minting a step number that `docs/DESIGN.md` itself does not recognise would either mean editing that
document - against the rule - or asserting a number nothing else in the project agrees exists, which is
a worse version of exactly the discoverability problem this document exists to fix.

Practically, this means:

- `docs/DESIGN.md`'s ten steps remain exactly as written; this plan does not touch that file.
- `ROADMAP.md`'s "Not yet started" list carries guided mode as its own entry, alongside (not numbered
  among) steps 6, 7 and 10, with a one-line description and a link to this document.
- `AGENTS.md`'s "Current position" paragraph and its `docs/DESIGN.md` §13 step tracking are unaffected -
  there is no step-13 sentence to update when a GUIDE-0x ticket lands, only this document's own Status
  section and `ROADMAP.md`'s entry (see "Doc-update process" at the end of this file).

## The one architectural decision everything else follows from

**The guided mode never runs a scan.**
It asks questions, composes an exact `scan.sh` argv, prints it, and hands that argv to the ordinary
`scan_parse_args` path.
One execution path runs scans, always.

That single constraint is what makes four of this design's requirements structural rather than a
checklist somebody has to keep honouring.

- **Every prompt has a flag equivalent**, because flags are the guided mode's *only* output: a prompt
  that could not be expressed as a flag could not be emitted at all.
- **Every existing validation still runs, unmoved.**
  `scan_parse_args` resets `SCAN_FLAGS` and `SCAN_COMMAND` at its top, so re-entry is clean, and the
  per-command flag-legality check (`scan_flag_kind`), the value-shape check
  (`scan_validate_flag_value`) and the cross-flag checks all execute on the composed argv exactly as
  they do on a hand-typed one.
  The rejected alternative - having the guided layer write `SCAN_FLAGS` entries directly - bypasses
  `scan_flag_kind` entirely, which is the *only* thing enforcing that a flag is legal for the command,
  and would let the guided layer set `SCAN_FLAGS[target]` under `sast`.
  It would also put an unset `SCAN_FLAGS[target]` in front of `scan_main`'s
  `config_scope_require "${SCAN_FLAGS[target]}"` (no `:-` default), which under `set -u` aborts with
  "unbound variable" through the ERR trap instead of a clean exit 2.
- **The printed command cannot drift from what ran**, because it *is* what ran: the same array is
  printed and executed, with no second renderer to keep in sync and no exclusion list to maintain.
- **Nothing downstream can tell the run was configured interactively**, which is what keeps the
  guided mode out of every safety-relevant code path.

## When it prompts, and every case where it must not

`scan.sh` is a CI tool.
A wrong answer here does not degrade an experience, it hangs somebody's build until a human notices.
Prompting is gated **conjunctively**, and the environment layer can only ever turn it *off*.

Guided mode is ON if and only if **all five** hold, evaluated in `scan_main` before any other work:

1. **Asked for.** Either `--guided` was given, or `$#` is `0` (the operator typed bare `scan.sh`).
2. **stdin is a terminal**: `[[ -t 0 ]]`.
3. **stderr is a terminal**: `[[ -t 2 ]]`.
   Both ends are checked because `select` writes its menu and `PS3` to **stderr**, not stdout
   (measured, below).
   Gating on `-t 1` would be checking the wrong stream, and gating on stdin alone lets a run whose
   stderr goes to a logfile block on a menu nobody can see.
4. **No non-interactive environment marker is set**, where the probe is any of `CI`,
   `CONTINUOUS_INTEGRATION`, `BUILD_NUMBER`, `JENKINS_URL`, `TEAMCITY_VERSION`, `GITHUB_ACTIONS`,
   `GITLAB_CI`, `BUILDKITE` or `TF_BUILD`.
   `CI` alone is not enough: Jenkins does not set it by default, and a runner that allocates a pty
   (`docker run -t`, an `expect` or `script` wrapper) satisfies conditions 2 and 3.
   The probe list is documented in `docs/USAGE.md` so it is an inspectable contract rather than a
   heuristic, and when any marker is present the operator's own explicit `--guided` is still required
   - a zero-argument invocation never auto-prompts there.
5. **`SCOURSH_NO_PROMPT` is unset or empty.**
   This variable can only ever *disable* prompting.
   There is deliberately no environment value that *enables* it, because an inherited variable that
   makes a tool block is the hang vector itself.

Otherwise guided mode is OFF and behaviour is byte-identical to today.

**Must not prompt, ever, in any of these:**

- Any of conditions 2 through 5 fails.
- Zero arguments with no terminal: byte-identical to today, `scan_usage` to stderr and `die` exit 2,
  "no command given".
  This is the strict non-regression, and it is the case `tests/suites/scan.sh`'s `'no command at all'`
  assertion already pins.
- A command that already carries every flag it needs, with no `--guided`: silent even on a terminal.
  `--guided` only ever fills flags that were **not** supplied on the command line, which is also how
  it degrades to a no-op.
- Inside `scan_dispatch`, any module, any check script, any `xargs -P` worker.
- After `run_init`.
  Once a run directory exists the run is under way, and a mid-run question leaves a half-written run
  directory waiting on a human.

**When prompting was explicitly requested but is ineligible, fail loudly and immediately.**
`--guided` with any of conditions 2 through 5 unmet is a usage error, exit 2, with a message naming the
concrete reason ("standard input is not a terminal", "`JENKINS_URL` is set in the environment"), the
sentence "nothing was run and nothing is waiting for input", and a worked flag example.
It is never a silent fallback to a default scan - a script that asked for guided setup and silently got
a passive scan is a worse outcome than a clear refusal - and it is never a block.

**`scan.sh dast --guided` must work**, and this is the reason the parser is split.
`scan_parse_args` today ends with the required-flag block, so `scan.sh dast` dies at
`'dast' requires --target` before anything else can run.
GUIDE-02 moves the required-flag and cross-flag block out of `scan_parse_args` into
`_scan_check_required`, called by `scan_main` **after** the guided pass, with the rules and the exit-2
message text unchanged.
`scan_parse_args` stays a pure function: it populates and shape-validates, and it never reads a
terminal.
That matters beyond tidiness.
`tests/suites/scan.sh` calls `scan_parse_args` directly, `tests/run-tests.sh` runs each suite as
`bash <path>` with no stdin or stderr redirection, and at a developer's terminal a suite file therefore
has stdin **and** stderr on a tty.
Putting the zero-argument guided branch inside `scan_parse_args` would make the project's own parser
tty-sensitive, surviving today only because `assert_status` happens to be written
`( "$@" ) >/dev/null 2>&1`.
A guard that depends on an incidental redirection in a generic test helper is not a guard.

**Four landed assertions move with the block**, and GUIDE-02 names them rather than discovering them
red.
They are identified by their `t_case` labels rather than by line number, because line numbers move and
this repository already has a rule about citing positions that go stale:
`'--fail-on-new requires --fail-on in the SAME invocation'`, `"'dast' requires --target"`, and the two
assertions under `"'diff' requires --against, 'report' requires --from"`.
Each is retargeted at `_scan_check_required` (or at a `scan_main`-level subprocess), keeping the exit
code and the message text asserted byte-identically, so the move is provably behaviour-preserving at
the CLI boundary.
`'no command at all'` does **not** move: zero-argument handling stays where it is, and the guided
branch sits in `scan_main` in front of it.

**No timeout, anywhere.**
`select` cannot time out, and a `read -t` fallback was considered and rejected: it would make the same
answers produce a different scan depending on typing speed, which breaks determinism outright.
The terminal gate plus "guided mode never runs unattended" is the control instead.
Somebody will propose a timeout as unattended safety; the reason it is absent belongs in
`lib/guide.sh`'s own header where the proposer will read it, not only here.

**Ctrl-C at a prompt must exit 0, and today it would exit 5.**
This is a real defect neither design caught, and it was measured rather than reasoned about.
`lib/core.sh` calls `core_install_traps` at source time, so `trap 'core_on_signal INT' INT` is armed
before any prompting can happen, and `core_on_signal` unconditionally does
`run_record incomplete_reason "run interrupted by SIG$sig"` then `exit "$SCOURSH_EXIT_INCOMPLETE"`.
Measured with a replica of that exact trap shape: SIGINT delivered while `select` is waiting produces
exit **5**, which in this project's frozen 0-5 table means "incomplete run (circuit breaker / aborted
mid-flight)" - the code that asserts a run started and could not complete an assessment.
Nothing ran.
A wrapper doing `scan.sh --guided || alert` would report a failed scan for an abandoned questionnaire.
GUIDE-01 therefore installs a guided-scope `INT`/`TERM` trap for the duration of prompting that prints
`Cancelled.  Nothing was scanned.` and exits 0, and **restores `core_on_signal` before `run_init`**, so
a real run's interrupt semantics are unchanged.
Its test sends SIGINT to a forced-terminal guided run and asserts both the exit code and that no run
directory was created.

**EOF at any prompt is exit 2**, with "input ended before the scan was configured; nothing ran".
This is not decoration either; see the measured `select` and `read` behaviour below for why an
unguarded version of each is a silent abort under this project's mandatory `set -Eeuo pipefail`.

## The menu flow

Menu items on **fixed** menus are fixed in number and order and are never reordered or removed by
availability.
An item whose module is not built is labelled and refused with one line if picked, rather than dropped:
renumbering would mean "answer 4" meant different things on different checkouts, which breaks both
reproducibility and anyone who wrote down what they ran.
New commands append at the end.
The availability labels are **derived from the filesystem at menu-build time**, through the same
capability probe `scan_dispatch` uses, so the menu can never claim a capability dispatch will not
deliver.
The conservative option is item 1 on every fixed menu.

**G1 - scan type.**

```
scoursh 0.1.0-dev - guided setup
--------------------------------

  This asks a few questions and then shows you the exact command it would
  run, so you can paste it into CI next time.  Nothing is scanned until you
  confirm at the end, and every answer here has a command-line flag.

  Press Enter at any menu to see the list again.
  To skip this and use flags directly:  scan.sh --help
  To turn it off permanently:           export SCOURSH_NO_PROMPT=1

What do you want to scan?

 1) Source code                              scan.sh sast    ready
 2) Dependencies and lockfiles               scan.sh sca     no advisory database installed
 3) Infrastructure as code                   scan.sh iac     ready
 4) A running web application over HTTP      scan.sh dast    not built yet in this version
 5) An AWS account, read-only                scan.sh cloud   not built yet in this version
 6) Everything this checkout can actually do scan.sh all     runs every ready surface
 7) Quit without scanning

pick a number>
```

Picking 4 or 5 today prints the honest explanation and returns here, rather than walking a whole
configuration flow and then running something inert:

```
  A running web application (DAST) is planned but not built yet in this
  version of scoursh.

  `scan.sh dast --target NAME` is accepted today: it checks the target
  against config/scope.conf, refuses if it is not authorised there, and then
  exits 0 without sending a single request.  It would report no findings, and
  that would not mean the target is clean.
```

Picking 2 with no `data/advisories.db` prints the same shape of explanation, ending with the sentence
that is the whole point of these screens: **a run that finds nothing because its data is missing is not
a run that found nothing wrong.**
Absence there means unknown, never safe, and the remedy (`tools/vendor-engines.sh advisories --all`, on
a networked machine) is named.
The operator may still proceed; the module already emits its own `coverage_reduction`.

**G2 - the local-surface follow-ups** (`sast`, `sca`, `iac`, and the local half of `all`): path, then
languages, then whether to replay the secret checks across git history.
Free text with the default shown in brackets, because `select` is single-choice only and `--lang` is
multi-value.
A path that does not exist re-asks once and then returns to G1; it never dies, because
`_scan_require_readable_path`'s exit 4 is the real gate and the guided mode must not duplicate it.
The `--history` option is labelled unavailable, and refuses with that reason, when `git` is not on
`PATH`.

**G3 - the DAST target**, read straight out of `config/scope.conf` through `config_scope_load`, so the
menu and the gate can never disagree about which targets exist:

```
  DAST only ever talks to a host you have authorised in config/scope.conf.
  That file is the tool's authorisation record.  This menu cannot override
  it: answering a question here never grants permission to scan anything.

Which target?

 1) staging-api    https://staging-api.internal:443
 2) staging-web    https://staging-web.internal:443
 3) Authorise a new target - writes a record into config/scope.conf
 4) Back

pick a number>
```

Each listed line shows the **normalised** `scheme://host:port` tuple the gate will actually match,
produced by `http_url_normalize`, not the raw `base-url` string.
There is deliberately **no free-text URL box on this screen**: a typed URL here would be a second scope
source, which is exactly the raw-URL bypass `docs/DESIGN.md` §7 forbids.
This is the one data-driven menu in the flow, so its numbering follows the operator's own file; the
answer is recorded by target id, never by position, so reproducibility is unaffected.
When `config/scope.conf` does not exist the menu collapses to "Authorise a target now / Back / Quit"
and states plainly that scoursh ships with no target of any kind and there is no demo host to point it
at, with the reason from the safety section above.

**G4 - authorising a new target.**
This is the most dangerous screen in the whole design, because it structurally resembles "the gate
refused, shall I remove the refusal?", which is the click-through everything else here avoids.
Four things keep it honest, and all four were corrections made in review.

```
  This will be appended to /path/to/config/scope.conf:

  ------------------------------------------------------------------
  id: staging-api
  base-url: https://staging-api.internal
  allow-subdomains: false
  allow-private-addresses: false
  notes: Authorised interactively via scan.sh --guided on 2026-08-14T10:22:31Z.
    Confirmed at the prompt after the normalised target and its resolved
    address were shown.
  ------------------------------------------------------------------

  The gate will match exactly:  https://staging-api.internal:443
  which resolves right now to:  10.4.7.22

  This authorises that host for EVERY scoursh run on this machine, not just
  this one, until you remove the record.

  This is plain data in scoursh's record format.  scoursh never executes a
  config file, so nothing written here can run.

  Type the host name  staging-api.internal  to write this, or anything else
  to cancel.
>
```

1. **It shows the normalised tuple and the currently-resolved address, not only the bytes.**
   `http_url_normalize` does real work between the typed string and the matched tuple: it
   percent-decodes the authority once, strips userinfo up to the **last** `@` (so
   `http://allowed@evil/` names host `evil`, as `lib/http.sh`'s own comment records), and canonicalises
   numeric IPv4 literals including octal and hex forms.
   It does **not** do IDN A-label conversion, which `lib/http.sh`'s header already records as "a real,
   known gap for a homograph-style bypass".
   An operator asked to type back a hostname the tool derived from their input is confirming the
   tool's parse, not the gate's match; showing both the tuple and the address is the only mitigation
   available for that gap, at the only moment it can be applied.
2. **It says the authorisation is file-wide.**
   Per the safety posture `docs/STEP5-DAST-PLAN.md` documents, `http_scope_match` walks every record in
   the file with no reference to the run's `--target`, so this is not "authorise a host for this run".
3. **`allow-subdomains` is always written `false`, and the menu does not offer otherwise.**
   `http_scope_match` implements subdomains as a bare suffix test (`$host == *".$s_host"`), so
   authorising a registrable or delegated zone with subdomains authorises an unbounded set of hosts
   the operator never enumerated, including any host somebody else can create in that zone.
   If you need it, open the gate's own file - widening the gate should mean editing the gate.
4. **`allow-private-addresses: true` may only ever be written alongside an IP-literal `base-url`,
   never a hostname.**
   This is the correction of a genuinely fatal defect in the design this section replaces, which
   proposed deriving that flag automatically from a DNS answer at write time.
   The flag is not range-scoped: `lib/http.sh`'s check is
   `if (( denied == 0 )) && [[ $_HTTP_MATCH_ALLOW_PRIVATE != true ]]`, a single boolean that disables
   the **entire** resolution-pinning deny list for that target - `127/8`, `169.254/16` where cloud
   metadata lives, `100.64/10` and `0/8` alike.
   Worse, the decision would be made once at write time against one DNS answer while the effect
   applies to every future resolution of that name, so a host that resolves to loopback today and to
   `169.254.169.254` tomorrow reaches cloud metadata through a record the guided mode wrote without
   ever asking.
   The repository already demonstrates the correct pattern: `tools/dast-test-target/scope.conf`
   authorises loopback as `base-url: http://127.0.0.1:3400/`, an **IP literal**, which sets
   `_HN_IS_LITERAL=true` so `addr=$host` and no resolution is ever consulted, closing the rebinding
   window entirely.
   If the operator types a name that resolves private, the guided mode offers to write the literal
   instead and says why.

The write itself copies the existing file to a temp file, appends a blank-line separator and the
record, runs `records_load` plus `records_validate` against the `scope-target` schema **on the temp
file**, and only then replaces the original by rename.
A malformed `config/scope.conf` makes `config_load_or_die` exit 4 on every future DAST run, so the
guided mode must not be able to brick the operator's config; a validation failure leaves the original
untouched, prints the `file:line:col` diagnostics and exits 4.
The writer is **append-only**: an id that already exists is refused, and no existing record is ever
edited, reordered or weakened.
There is deliberately **no flag equivalent**, and that is the point: writing an authorisation is a
config edit, not a per-run scan option, and the non-interactive equivalent is editing
`config/scope.conf` - the same act with the same reviewability.
An `--add-target` flag would turn "the gate refused" into a one-liner that removes the refusal, inside
CI, unreviewed.

**G5 - DAST intensity**, with the conservative option first and the standing invariant stated under
the list:

```
How hard should the scan push 'staging-api'?

 1) passive - read only: headers, cookies, TLS, markup, served JavaScript.
              Nothing is injected.                              (default)
 2) safe    - passive, plus content discovery and HTTP method enumeration.
              This puts hundreds of 404s into the target's logs.
 3) active  - safe, plus injection probes (SQLi, XSS, SSTI, traversal, ...)
              into every parameter found.  A target owner will read this as
              an attack.

  Detection only at every level: scoursh sends no destructive payload and
  does no credential brute forcing at any intensity, and cannot be told to.

  2 and 3 require you to affirm you are authorised for this host.  Permission
  to browse a host, or to port-scan it, is not permission to send it
  injection payloads.

pick a number>
```

**G6 - the limits router, then the affirmation, then each limit separately.**
The router states the *effective resolved* numbers, not literals, so an operator whose
`config/scanner.conf` sets a higher budget learns about the ceiling here rather than being confused by
it mid-run.
Choosing "keep these limits" after choosing `safe` or `active` at G5 forces the intensity back to
`passive`, and item 1's text says so explicitly when that applies.

The affirmation screen is the one place in the flow where an affirmation is asked:

```
-------------------------------------------------------------------
 Raising the limits for target 'staging-api'

 Base URL     https://staging-api.internal/
 Resolves to  10.4.7.22
 From         this machine, as user abhi

 Above the conservative limits, scoursh sends traffic a target owner will
 read as an attack: injection payloads in every parameter it found, and
 hundreds of requests for paths that probably do not exist.

 That traffic is attributable to you.  It leaves this machine's IP address,
 it carries a User-Agent naming this tool, and it lands in the target's logs
 next to your source address.

 It can also take the target down.  A host that is small, slow or shared can
 stop serving real users while this runs.

 Only continue if you own this host, or you hold written permission from
 whoever does that covers active security testing.

 Being able to reach a host is not permission.  A robots.txt or a
 security.txt file is not permission.  A bug bounty page is not permission
 unless it names this host and this kind of testing.

 Type the target name  staging-api  to continue, or anything else to keep
 the conservative limits.

>
```

Typing the target id rather than "yes" is deliberate: it cannot be answered by muscle memory or by a
stray digit in a keyboard buffer, and it makes the operator re-read which host this is about.
The resolved address is shown because "staging-api" feeling familiar and "staging-api" resolving to a
colleague's box are different facts.
There is **no retry loop**: a second attempt turns a deliberate act back into a click-through, and the
failure direction (keep the conservative limits) is safe.

**After a matched affirmation, each limit is its own menu, with the conservative value still at item 1.**
This is the second correction that a review round forced, and it is not cosmetic.
A flow that jumps from the affirmation straight into three prompts pre-filled with the *raised* values
gives an operator who presses Enter three times a 5x request rate, 4x concurrency and 10x budget
without a single further decision - which is precisely the click-through the affirmation exists to
prevent, sitting one keystroke after it.
The affirmation unlocked the door; it does not walk through it.
The acceptance criterion is written as a test: **a scripted answer sequence that picks item 1 at every
fixed menu must produce an argv containing no `--i-own-target`, no `--allow-intrusive` and no raised
limit.**
That is "the path of least resistance is the safe one", as an assertion rather than an aspiration.

```
Requests per second against 'staging-api'

 1) 4        - the conservative default                        (default)
 2) 20
 3) 50
 4) No limit - send as fast as the target answers

'No limit' can take a small or shared host offline.  The total request
budget and the failure breaker still apply either way.

pick a number>
```

```
Total request budget for 'staging-api'

scoursh stops the run once it has sent this many requests, whatever is still
queued.  There is always a budget.  It cannot be removed - it is what bounds
a crawler loop or a mistake in a parameter list.

 1) 5000    - the conservative default                         (default)
 2) 20000   - the value in your config/scanner.conf
 3) 100000

pick a number>
```

Item 2 on the budget menu appears only when `config/scanner.conf` actually sets a different value, and
showing it there is what explains the clamp the operator was told about one screen earlier.

`--allow-intrusive` is asked **separately, last, and only when intensity is `active` and the
affirmation matched**, with the most specific warning text in the flow, because its worst case reaches
the target's *users* rather than its owner:

```
Side-effecting checks against 'staging-api'?

These are off by default because their effects leave the target:

  - user enumeration through login, signup and password-reset responses,
    which on a real identity provider CREATES ACCOUNTS and SENDS EMAIL OR SMS
    to real people
  - a deliberate burst to test whether rate limiting exists at all

Owning a host does not always mean you may do this to its users.

 1) No - skip them                                             (default)
 2) Yes - run them

pick a number>
```

A defensible stricter position is that this should be flag-only and never reachable from a prompt at
all.
This plan offers it, gated behind `active` plus a matched affirmation and asked separately, but the
stricter alternative is genuinely arguable and is named here rather than settled silently.

**G7 - cloud**, when that module lands: read the live account read-only, or only the IaC on disk.
Both paths are read-only and enforced by `lib/awscli.sh` plus the build lint; the menu says so.

**G8 - the CI gate**: whether the run should exit non-zero on findings, and at what severity.

**G9 - review, and the exit.**

```
Ready.

  scan.sh dast --target staging-api --intensity active \
    --i-own-target staging-api --requests-per-second 50 \
    --request-budget 20000 --allow-intrusive --fail-on high

This will:
  - send injection payloads to https://staging-api.internal/
  - at up to 50 requests/second, stopping after 20000 requests
  - including checks that may email or create real users
  - and exit 1 if it finds anything high or critical

Authorisation affirmed for 'staging-api' by abhi at 2026-08-14T12:03:11Z.
That affirmation, and every limit it raised, is recorded in this run's
run.json.

 1) Run it
 2) Print the command and exit without running
 3) Cancel

pick a number>
```

Item ordering here differs from every other screen on purpose: this is an action menu rather than a
settings menu, so "Run it" stays at 1 for stable muscle memory, and all of the safety work already
happened upstream.
Option 2 writes to **stdout** (so it pipes and copies) and exits 0 with no run directory created.
It is load-bearing rather than a nicety - it is what converts an interactive operator into a scripting
one - and it therefore also exists as a real flag, `--print-command`, which renders the fully resolved
invocation for **any** invocation, guided or not, and exits 0 without running.
An interactive-only escape hatch from interactive-only capture would be self-defeating.
Cancel exits **0** with "Cancelled.  Nothing was scanned.", because a cancelled setup is a legitimate
outcome rather than an error, consistent with `--help` exiting 0.

## Flag equivalence

Every prompt maps to a flag.
`--print-command` and the two new global flags are the only additions to `_SCAN_FLAG_KIND` that the
guided mode itself needs; the rest already exist or arrive with DAST-32, which has landed.

| Prompt | Flag |
|---|---|
| G1 scan type | the subcommand: `sast` \| `sca` \| `iac` \| `dast` \| `cloud` \| `all` |
| G2 path | `--path DIR` |
| G2 languages | `--lang py,js,go,java` |
| G2 git history | `--history` |
| G3 target | `--target NAME` |
| G4 authorise a new target | **none, deliberately** - the non-interactive equivalent is editing `config/scope.conf` |
| G5 intensity | `--intensity passive\|safe\|active` |
| G6 affirmation | `--i-own-target NAME` (must equal `--target`; mismatch is exit 2) |
| G6 rate | `--requests-per-second N`, or `0` for no limit (the same key name `config/scanner.conf` already uses, so no second vocabulary is invented) |
| G6 budget | `--request-budget N` |
| G6 side-effecting checks | `--allow-intrusive` |
| G7 cloud live | `--live` (with `--profile`, `--regions`, `--assume-role` left at their defaults) |
| G8 CI gate | `--fail-on none\|high\|medium\|info` |
| G9 print and exit | `--print-command` |
| (turn the whole thing on) | `--guided` |
| (turn the whole thing off) | `SCOURSH_NO_PROMPT=1` |

Two flags the guided flow deliberately does **not** ask about, and names in its closing text instead,
because they belong to a CI setup written once rather than to a menu: `--fail-on-new` (which requires
`--fail-on`) and `--paranoid`.

## What is recorded for audit, and where

Four places, each answering a different question, and one of them survives the run directory being
deleted.

**1. `run.json`, a new top-level `authorization` object**, written on **every** DAST run, affirmed or
not.
Recording it unconditionally is deliberate: an absent key would be ambiguous between "nothing was
affirmed" and "this version does not record it", and the clamp that actually bit is exactly the fact a
reviewer needs in order to judge whether a run was gentle or heavy without reconstructing it.

```
"authorization": {
  "scope_target":        "staging-api",
  "scope_base_url":      "https://staging-api.internal/",
  "scope_conf_sha256":   "3f9a...",
  "affirmed":            true,
  "affirmation_source":  "interactive-guided",
  "affirmation_target":  "staging-api",
  "affirmed_at":         "2026-08-14T12:03:11Z",
  "intensity":           "active",
  "intrusive":           true,
  "authed":              false,
  "limits_relaxed":  ["intensity-ceiling:passive->active",
                      "requests-per-second:4->50",
                      "request-budget:5000->20000",
                      "allow-intrusive:false->true"],
  "limits_enforced": ["request-budget:20000 (finite, never removable)",
                      "circuit-breaker:10-failures/60s",
                      "scope-gate:config/scope.conf",
                      "payloads:detection-only",
                      "ssrf:in-scope-sentinels-only",
                      "user-agent:scoursh-identified"]
}
```

Why each of the load-bearing fields earns its place:

- `limits_relaxed` records the **delta**, from-value to to-value, not a boolean.
  "unrestricted: true" is not an audit record; it tells a later reader nothing about what traffic was
  actually authorised, whereas the delta reconstructs the traffic profile.
  An unaffirmed run records the clamps that bit in the same shape
  (`requests-per-second:200->4 reason=no_owner_affirmation source=file`), including the resolution
  layer the clamped value came from.
- `limits_enforced` records what was **not** relaxed, so the record is a complete statement rather
  than a partial one.
  The usual question after an incident is what the tool could not have done, and a list of what stayed
  on is the answer; without it a reader has to reason from the tool's version number.
- `intensity`, `intrusive` and `authed` are recorded on every run.
  `--authed` already exists as `[dast:authed]=bool` and DAST-03 gives it real teeth, and an
  authenticated active scan reaches state-changing endpoints an unauthenticated crawl never sees, so
  an authorisation record that cannot distinguish the two is not answering its own question.
- `scope_conf_sha256` ties the run to the exact authorisation-file state, so "was this host authorised
  at the time" is answerable from the run plus that file's git history.
- `affirmation_source` is one of `interactive-guided`, `flag`, or `none`, so a reviewer can tell a
  human answering a question at a terminal from a flag pasted into a CI file.
  Both are legitimate; they are different evidence, and collapsing them loses the distinction that
  matters most in review.

**2. `run.json`'s `invocation` and `config` facts**, which is where the determinism claim gets an
honest statement rather than an overstated one.
`invocation` is the fully rendered, shell-quoted command - the same array the guided mode printed and
executed.
That is safe to record verbatim only because `docs/FOUNDATION.md` tension 9 already forbids a secret
ever being a command-line argument; the frozen rule that keeps credentials off argv is what makes
recording argv a non-issue.
But **the argv is not the run's only input**, and saying otherwise would be wrong: `config_scanner_value`
resolves every scanner setting through CLI > env > file > default, and the guided flow sets only a
subset of those keys as flags, leaving `http-timeout`, `max-redirects`, `circuit-breaker-failures`,
`circuit-breaker-window`, `max-matches-per-file`, `evidence-max-bytes` and `redact-secrets` to resolve
from the environment or from `config/scanner.conf`.
The same printed command therefore produces a materially different scan on a different machine,
including different breaker and redirect behaviour.
So `config` records `scanner_conf_sha256` alongside `scope_conf_sha256`, and for every scanner key the
effective value plus its resolution source (`cli`, `env`, `file`, `default`).
That is a recording change rather than a new mechanism: `config_scanner_value` already computes exactly
that in its own `src` variable.
**Reproducibility is therefore stated as "this argv against these two digests", never as "this argv".**

**3. `reports/<run>/meta/<key>`** - the raw `run_record` fact files, free, already the mechanism, and
surviving as evidence independent of the JSON rendering.
This is **not** sufficient on its own: `run_record use_engines` writes `meta/use_engines`, and until
DAST-33 closed the equivalent gap `report_run_json` never rendered it into `run.json` - the reminder to
carry both is why this section stays as its own line item, not an assumption.

**4. `config/scope.conf` itself**, for a guided-written record only: a `notes:` line naming who added
it and when.
`reports/` is gitignored and run directories are deleted, so the authorisation decision has to outlive
them.
This is the one piece of the record that belongs with the authorisation rather than with a run, and it
is plain data in the frozen block-record format, written into a field the `scope-target` schema already
has, so no key is added to a safety-critical schema.

**What is deliberately not recorded.**
The affirmation is never persisted outside the run it was made for: no `scanner.conf` key, no dotfile,
no cache, no environment variable, no "remember this target", and `--i-own-target` must equal
`--target` so even the command line cannot carry it to another host.
Operator identity is recorded **only when `SCOURSH_OPERATOR` is set**, and is otherwise omitted rather
than harvested from `id -un` and the hostname.
`run.json` is frequently the artifact handed to a third party alongside a report, and quietly attaching
a username and machine name to every run is a privacy cost the audit requirement does not need: that it
happened, when, for which named target, by which route, and what numbers it changed is the complete set
of facts an auditor asks for.

**The test that pins the record**, and the reading it fails under: a suite case runs the guided flow
with the terminal check forced and a scripted answer stream, then runs the rendered command
non-interactively, and asserts the two `run.json` `authorization` objects are byte-identical.
It fails under the reading "the affirmation is a UI concept that the flag path need not reproduce",
which is exactly the drift that would turn the record back into decoration.

## `select`, measured rather than assumed

`select` is a bash builtin, so it adds **no dependency at all** and - unusually for this codebase - it
carries no GNU/BSD divergence risk, because the behaviour lives inside bash rather than in a userland
tool.
Every item below was measured on this machine on **bash 5.3.9** and cross-checked on **bash 3.2.57**
(macOS's own `/bin/bash`), and the two agreed on every one of them.
Two of these were stated *wrongly* in a design draft, in the direction that would have shipped a bug,
which is why they are recorded with their measurement rather than as folklore.

1. **The menu and the `PS3` prompt go to stderr; the loop body's output goes to stdout.**
   Measured: `printf '1\n' | bash -c 'select x in aa bb; do echo "BODY:$x"; break; done'` with the two
   streams captured separately puts `BODY:aa` on stdout and the numbered list plus `#?` on stderr.
   Good, because it keeps stdout clean for `--print-command`, but it is why the terminal gate must
   check `-t 2` and not `-t 1`.
2. **`select` reads stdin and prints its menu even when stdin is not a terminal.**
   Measured: `printf '2\n' | bash -c 'select x in a b; do echo $x; break; done'` prints `b`, with no
   terminal involved anywhere.
   A pipeline that happened to be feeding data in would have its menu answered by that data.
   This is why the terminal gate must be reached before any `select` is, and why a lint asserting that
   nothing outside `lib/guide.sh` uses `select` is worth having.
   (`read -p` differs: measured, it suppresses its prompt entirely when stdin is not a terminal.
   `select` does not.  The gate has to be ours, not the builtin's.)
3. **An empty line redisplays the list without entering the loop body.**
   So there is no press-Enter-for-default anywhere: Enter is inert, every advance costs a specific
   digit, and the flow cannot be held-Enter-ed through.
   Turn it into the feature it is, and say so in the header text.
4. **Invalid or out-of-range input *does* enter the loop body**, with the choice variable set to the
   empty string and `REPLY` holding the raw token.
   Measured: `zz` gives `CHOSE:[] REPLY:[zz]`, and `9` of 3 items gives `CHOSE:[] REPLY:[9]`.
   Every body must therefore test for an empty choice and re-prompt, or a typo becomes a silent wrong
   answer.
5. **At EOF, `select` ends the loop with status 1 - and as the last command of a function under
   `set -Eeuo pipefail` that aborts the caller.**
   Measured with this project's real trap shape: the ERR trap fires
   (`status=1 ... cmd=select x in a b`), the EXIT trap runs, and the process exits **1**.
   It does not "fall through silently", and the consequence is worse than a wrong prediction: exit 1
   is this project's "findings at or above `--fail-on`" code, so an EOF in a menu would be
   indistinguishable in CI from a failing security gate.
   **The fix is an explicit, unconditional `return 0` after every `select`**, measured to restore
   clean behaviour, and the idiom is already established here: `lib/checks.sh`'s `checks_select`
   carries the identical "explicit, unconditional success" comment for the same class of bug.
   A lint asserts it.
6. **The choice variable is UNSET after EOF, but set-to-empty after an invalid choice**, and `REPLY`
   is empty in both cases.
   Measured: reading the variable unguarded after an EOF-terminated `select` dies
   `y: unbound variable` under `set -u`, with the ERR trap firing.
   So a post-`select` predicate written naively as `[[ -z $var && -n $REPLY ]]` is *itself* the abort.
   Every post-`select` read uses `${var-}` and `${REPLY-}` defaulting, and a suite case runs each menu
   with `</dev/null` and asserts a clean classified exit rather than an unbound-variable abort.
7. **Layout is column-major and reflowed to `COLUMNS`, and an item-count cap does not control it.**
   Measured: 9 short items at `COLUMNS=80` *do* columnise into two rows of five, reading down the
   columns; and the seven-item scan-type menu above, with its long labels, splits into two column-major
   columns at `COLUMNS=200` and four at `COLUMNS=400`.
   Layout is a joint function of item width, item count and `COLUMNS` and it is not monotonic, so a
   "cap the menu at nine items" rule is not a rendering guarantee.
   **Setting `COLUMNS=1` for the menu's duration forces exactly one item per line regardless of width**
   (measured, 12 items, both bash versions), which is deterministic and removes a reading-order hazard
   at the exact moment one of the items says "No limit".
   Also measured: `COLUMNS` is **unset** in a non-interactive bash script even when attached to a pty,
   and bash defaults to 80, so this only bites operators whose environment exports it (some tmux and
   CI images) - which makes the hazard intermittent, and intermittent is worse than deterministic.
   Keep an item cap if you like, as a UI-length judgement, but never as the rendering control.
8. **A zero-item `select` exits status 0 with the body never running and the variable unset**, and
   prints no menu at all.
   Measured.
   `guide_menu` therefore dies on an empty item list rather than silently continuing.
9. **`REPLY` holds the raw input**, which is what the two typed-string confirmations (the affirmation
   and the scope write) use - through `read -r`, not `select`.
10. **A bare `read` at EOF aborts immediately under `set -e`**, unlike `select`, which at least reaches
    the next statement's status check.
    Measured: `read -r -p "FIRST> " a` on exhausted stdin returns 1, the ERR trap fires and the script
    dies on the spot, so the intended "EOF means cancel" semantics are unreachable from a bare read.
    Every prompt read is written `if ! IFS= read -r ...; then <cancel path>; fi`, and a lint on
    `lib/guide.sh` asserts it.

Menu text is plain ASCII, with no box-drawing characters, for the same portability reason this
repository already applies elsewhere.

## New tickets

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| GUIDE-01 | `lib/guide.sh` - the prompt gate, the signal trap, and the menu primitives | none; can land at any time | New file, sourced only by `scan.sh`. Ships `guide_may_prompt` (the exact five-condition rule, including the full non-interactive environment probe list), `guide_menu`, `guide_ask`, `guide_confirm`, and `_guide_shquote`. `guide_menu` absorbs every measured `select` edge above: `COLUMNS=1` for the menu's duration, an unconditional `return 0` after the loop, `${var-}`/`${REPLY-}` defaulting, dies on an empty item list, treats an empty choice with a non-empty `REPLY` as unusable and re-prompts, converts EOF into exit 2 with "input ended before the scan was configured; nothing ran", and caps consecutive unusable answers at 10. Installs the guided-scope `INT`/`TERM` trap and restores `core_on_signal` before returning. `_guide_shquote` is hand-rolled (single-quote wrap with `'\''` escaping when the value is not `[A-Za-z0-9_./:,=@%+-]+`) rather than `printf %q`, which diverges into `$'...'` forms for control characters. `SCOURSH_GUIDE_FORCE_TTY` is a **test-only** hook in the same swappable-hook idiom as `SCOURSH_HTTP_TRANSPORT` and `SCOURSH_PARANOID_FORCE_BACKEND`; it forces only the terminal check, never the environment-marker or `SCOURSH_NO_PROMPT` checks, and it is documented as test-only in the same breath as those two or it will end up in somebody's CI file. New `tests/suites/guide.sh`, and it must prove the **refusals** rather than only the happy path: piped stdin, each environment marker set, `SCOURSH_NO_PROMPT` set, EOF mid-flow, and SIGINT mid-flow each exit non-zero (or 0 for the cancel path) without blocking, and none of them creates a run directory. |
| GUIDE-02 | `--guided`, the `scan_main` routing, and the `_scan_check_required` split | GUIDE-01 | Adds `[global:guided]=bool` and `[global:print-command]=bool` to `_SCAN_FLAG_KIND`. Routes the zero-argument and `--guided` branches in **`scan_main`**, keeping `scan_parse_args` a pure function that never reads a terminal. Moves the required-flag and cross-flag block into `_scan_check_required`, called after the guided pass, with rules and exit-2 messages unchanged, and retargets the four named assertions in `tests/suites/scan.sh`. Adds the two lints that make flag parity structural rather than a convention: one in `tests/lint-shell.sh`, in the same shape as the tension-19 no-bypass check, failing the build if anything under `lib/` other than `guide.sh`, or anything under `modules/`, calls a `guide_*` function or uses `select` or `read -p`; and a suite case walking every key the guided flow can set against `_SCAN_FLAG_KIND` and failing on any key with no flag. Direct non-regression test: bare `scan.sh` with no terminal keeps today's exit-2 usage text byte-identically. |
| GUIDE-03 | The scan-type menu, the local-surface follow-ups, and prerequisite honesty | GUIDE-02 | Steps G1, G2, G8. Menu items fixed in number and order; availability labels derived at menu-build time from the same probe `scan_dispatch` uses, through **one shared function** so the menu can never advertise what dispatch will not deliver - with a suite case asserting the menu's ready set equals the set of modules with a `run.sh` on disk, because a shared-function convention is a thing a future edit can break. Five probes, each reusing the check the real code path already makes rather than inventing a second one: `data/advisories.db` for SCA, `git` on `PATH` for `--history`, `modules/dast/run.sh` and `modules/cloud/aws/run.sh` presence, the `aws` CLI for `cloud --live`, and `config/scope.conf` plus its target list via `config_scope_load` for DAST. Absence is never an error here, only a labelled menu state with an explanation. |
| GUIDE-04 | The DAST branch and the affirmation | GUIDE-02; DAST-32 (**landed** - see Status above) | Steps G3, G5, G6. The hard dependency on DAST-32 is structural rather than a convenience: the flags must exist before a prompt can emit them, because prompts emit nothing else - and DAST-32 has shipped, so today this ticket is blocked only on GUIDE-02. Every number in the prompt text is **interpolated from the same named constants DAST-32's clamp reads**, never typed as prose, and a suite case asserts the rendered prompt contains the constant's current value - otherwise the text drifts into promising a limit the code does not enforce, which is the most likely way this whole design quietly becomes theatre. The target menu offers only ids from `config/scope.conf` and has no free-text URL box. The affirmation requires typing the target id exactly, once, with no retry loop. After a matched affirmation each limit is its own menu with the conservative value at item 1, and the acceptance test named in the flow section above is part of the deliverable. `--allow-intrusive` is asked separately, last, only when intensity is `active`. The trailing lines that state what the affirmation does **not** do are part of the deliverable, not decoration: they are what stops "a full scan without the conservative limitations" being read as "a destructive scan". |
| GUIDE-05 | The `config/scope.conf` record writer | GUIDE-02, GUIDE-03, `lib/records.sh` (shipped) | Step G4, and the most dangerous thing in this design - it deserves the most adversarial review of anything here. Ships the offer, the preview showing raw bytes **plus** the normalised `http_url_normalize` tuple **plus** the currently-resolved address **plus** the file-wide-authorisation sentence, the typed-hostname confirmation, `allow-subdomains: false` always, `allow-private-addresses: true` only alongside an IP-literal `base-url`, append-only with an existing-id refusal, the deterministic id derivation (lowercase, dots and colons to dashes, `t-` prefix when it would not start with a letter, `-2` on collision) so the same URL always yields the same id, the dated `notes:` line, and validate-in-a-temp-file-then-rename. Frozen record format only, never sourced (tension 26), and the writer must never emit a value it did not receive verbatim from the operator - `rules/RULE-FORMAT.md` §5.3 already fixes that `$HOME` is five literal bytes, and the likeliest future way to break "no config file is ever sourced" is a well-meant convenience like a variable expansion or an `include` directive written into a file the loader would then have to evaluate. A suite case must prove the post-write gate behaviour is identical to a hand-edited file. **This ticket also owns an explicit decision, not a default:** `config/scope.conf` is not in `.gitignore` today (verified: it lists `reports/`, `state/`, `suite.log`, `findings-*/`, `.DS_Store` and `.dast-test-target/`), so a guided write makes an untracked file, possibly containing internal hostnames, appear in every clone. Either ignore it and lose the "commit this so the authorisation outlives the machine" story, or leave it tracked and document the consequence - but decide it here. |
| GUIDE-06 | The review screen, `--print-command`, and the argv round-trip | GUIDE-03, GUIDE-04, GUIDE-05 | Step G9. Prints the exact composed command, a plain-language statement of what it will actually do, and the affirmation restatement when one was made. `--print-command` is the non-interactive twin and works for any invocation. The load-bearing test: run the guided flow with a scripted answer stream, then run the rendered command non-interactively, and assert the two runs' `run.json` flag facts, `authorization` object and `config` object are byte-identical. It must fail under the reading "the printed command is a best-effort summary". |
| GUIDE-07 | Documentation: the guided quickstart, the flag table, and the honest status column | GUIDE-06 | `docs/USAGE.md` gains a guided-mode section stating the five prompt conditions verbatim, the full non-interactive environment probe list, the exit code for each refusal path, and the flag-equivalence table above; its existing Status column gains rows for `--guided`, `--print-command`, `--i-own-target`, `--requests-per-second`, `--request-budget` and `--contact`. That column applies directly here: **guided mode is live even while DAST is inert**, and the doc must say that picking DAST walks the whole flow and then runs something that does nothing yet, because that column exists precisely to close this class of trap. `config/scanner.conf.example` gains commented entries for the new keys. Nothing here restates a count or a build-order sentence that `tools/gen-status.sh` owns; per `AGENTS.md`, run `tools/gen-status.sh --write` and commit the result rather than typing any inventory figure. |

## Open decisions and residual risks

- **Bare `scan.sh` on a terminal changes behaviour**, from usage plus exit 2 to a menu.
  The terminal gate plus the environment probe makes this impossible in any pipeline, cron job or
  tty-less container, and `SCOURSH_NO_PROMPT=1` is the documented off switch, but this is the single
  decision in the design worth the project owner's explicit sign-off.
  The conservative alternative is to require `--guided` explicitly and leave bare invocation exactly as
  it is today; it costs only the "useful result inside sixty seconds from a fresh clone" premise.
  This plan ships the zero-argument behaviour and flags the decision rather than burying it.
- **The scope-writing offer is the piece most likely to be regretted.**
  Every mitigation above is real, and the residual risk is irreducible by tooling: a mistyped but
  valid base URL authorises a host the operator did not mean, and only the operator's own reading of
  the preview catches it.
- **`--i-own-target prod-api` can become CI boilerplate**, pasted once and still there after the target
  changes hands.
  The must-equal-`--target` rule and the recorded numeric deltas blunt this, but nothing prevents a
  stale affirmation living in a CI file for a year.
  A periodic re-affirmation is the obvious fix and is deliberately not designed here, because a
  time-based expiry that fires mid-pipeline is its own outage.
- **Prompt text can drift from enforced behaviour**, and a menu that promises a limit the code does not
  keep is worse than no menu.
  The interpolate-from-the-constants rule plus GUIDE-04's suite case are the guard, and every future
  edit to that text has to respect it.
- **"No limit" at the rate prompt is the option most likely to be chosen casually**, because its
  consequence lands on a host that may be shared or smaller than the operator believes.
  It carries the loudest single consequence line in the flow, and removing it is a reasonable response
  if it turns out to be picked without thought.
- **Interactive flows are hard to test without a pty**, and the honest limit of the proposed suite is
  that it exercises the guided run with the terminal check forced and stdin from a here-doc.
  It proves the state machine and the flag output, not the terminal rendering.
  Assertions are therefore written over choices made, never over line counts or column layout, and no
  test should be read as evidence that the menu looks right on a real terminal.
- **None of this has been built or run.**
  The `select` and `read` behaviours above are measured on this machine on bash 5.3.9 and 3.2.57, and
  the code facts cited from `scan.sh`, `lib/http.sh`, `lib/config.sh`, `lib/core.sh`, `lib/report.sh`,
  `lib/checks.sh` and the test tree were read out of the tree rather than recalled - but the flow, the
  clamping, the argv round-trip and the scope-write path are unimplemented, and the first ticket that
  builds any of them should expect to find at least one stated behaviour slightly different in context.

## Doc-update process

Whoever lands GUIDE-01 (the first real guided-mode code) updates this document's own Status section to
say so, and updates `ROADMAP.md`'s guided-mode entry to reflect what has landed, in the same change.
Because guided mode is not a `docs/DESIGN.md` §13 step (see "Relationship to the ten-step build order"
above), landing GUIDE-01 does **not** touch `AGENTS.md`'s "Current position" paragraph or
`docs/FOUNDATION.md`'s "Where the build currently stands" section - those two track the ten numbered
steps only, and there is no step-13 sentence for this work to correct.
`docs/DESIGN.md` itself stays untouched throughout, per this project's documented rule that its wording
is load-bearing and preserved verbatim.
