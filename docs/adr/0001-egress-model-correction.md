# ADR 0001 - the egress model is "egress-restricted," not "air-gapped"

- **Date:** 2026-08-07
- **Status:** Accepted
- **Owner:** operator decision, recorded per `docs/FOUNDATION.md`'s own rule that a deliberate
  divergence from a committed decision is written down, not quietly made in code.

## Context

`docs/DESIGN.md`'s title, its handoff header, and §1 all call scoursh an "air-gapped" scanner and say
it "must run on an air-gapped host."
`AGENTS.md` repeated the same claim.

That claim was never true of the architecture as designed.
`docs/DESIGN.md` §2 already permits two categories of scan-time network traffic: `curl` to hosts the
operator authorised in `config/scope.conf` (DAST needs to reach the target it is testing), and read-only
AWS API calls to the operator's own account.
Both happen *during* a scan, not before it.
"Air-gapped" describes a host with no network path at all; a tool that curls a live endpoint and calls a
live API is not that, whatever the intent behind the word.

The word also collapsed two different properties into one:

1. **The tool does not depend on live internet access to run.** Rules, payloads, wordlists, and
   (previously) advisory data are vendored and read from disk.
2. **The tool never exfiltrates the operator's data.** No telemetry, no SaaS backend, no upload of
   findings or source, ever.

Property 2 is the one that actually matters for a security tool an operator points at their own source
and their own infrastructure.
Property 1 was a *means* to something like property 2 in the original design, but was never the actual
requirement, and treating it as the requirement is what made "air-gapped" the wrong word: it describes
the means, not the guarantee.

## Decision

The operator corrected the framing.
The model going forward, in the operator's own words:

- Internet access is fine while **building** the tool (vendoring engines, writing code, running CI).
- The shipped tool may **download** what it needs to run well - rule updates, advisory data - but must
  **never upload** anything.
- **No AI in the shipped tool.** No model calls, no API keys for model providers, in the scan path.

The reference point named was **Invicti**: a scanner that pulls advisory/signature updates over a real
update channel, scans only explicitly authorized targets, keeps findings local (on-prem edition), and
has no AI in the scanning path.
scoursh adopts the same shape.

### The four rules, enforced by destination

A verb-only rule ("never upload") is not enforceable in isolation: a GET request can carry a finding in
its query string and technically be a "download."
The rules are therefore stated - and implemented - by **destination**, not by HTTP method:

1. **Allowed destinations at scan time** are exactly three: hosts in `config/scope.conf` (DAST
   targets), the AWS API (read-only calls only, per tension 23), and a configured advisory/rule update
   endpoint.
   Every other destination aborts the run.
   This is `docs/DESIGN.md` §2's corrected table.
2. **The update channel is explicit, not automatic.** `tools/update-advisories.sh` (or
   `scan.sh --update`, once `scan.sh` exists) is the only thing allowed to talk to the update endpoint,
   and it is never invoked as a side effect of a scan. A scan's rules do not change mid-run, and two
   scans of the same target with no update in between produce the same findings.
3. **Findings never leave the machine.** No flag, mode, or feature uploads scan output anywhere.
4. **No AI/LLM in the shipped tool**, enforced by a CI check that scans for provider hostnames, SDK
   names, and API-key environment-variable patterns, not by a comment asking nicely.

## What this replaces

- **"Air-gapped" is retired** as the name for this property, everywhere in the docs. The accurate term
  is **egress-restricted**: scan-time network access is restricted to an explicit, destination-based
  allowlist, not absent.
- **`tools/vendor-engines.sh`'s scope narrows.** It keeps its original job - populating optional engine
  binaries (`semgrep`, `gitleaks`) and their local rule databases, once, on a networked box, committed to
  the repo. What it no longer owns is `data/advisories.db`: `docs/FOUNDATION.md` tension 25 had assigned
  that file's generation to `vendor-engines.sh` under the old vendor-once model. That responsibility
  moves to `tools/update-advisories.sh`, which is invoked repeatably and explicitly rather than once at
  build time, and which reuses tension 25's frozen schema, format, and per-ecosystem name-normalisation
  rules unchanged. `docs/FOUNDATION.md` tension 27 records this narrowing against the register directly,
  per the register's own rule that a divergence is written down rather than silently made.
- **`docs/DESIGN.md`'s title, handoff header, §1, and §2 are corrected** to the language above. This is
  the one deliberate exception to `docs/FOUNDATION.md`'s own stated policy that `docs/DESIGN.md` is
  preserved verbatim: that policy exists to stop the *implementation* from quietly drifting away from
  the *spec*, and assumes the spec's wording is sound. Here the wording itself was the defect the
  operator corrected, not an implementation detail the register would normally override underneath
  unchanged prose. Everything else in `docs/DESIGN.md` - the module catalog, the rule format discussion,
  the build order, the architecture - is untouched.

## Consequences

- `lib/http.sh` (previously scheduled for `docs/DESIGN.md` §13 step 5) lands early, narrowed to the
  destination-allowlist chokepoint: resolve a URL's host, check it against scope hosts plus the
  configured update endpoint, abort on anything else. Rate limiting, the circuit breaker, and DAST's
  fuller curl defaults remain step 5 work, layered onto the same chokepoint later. AWS's destination
  category is enforced by the sibling chokepoint `lib/awscli.sh` (not yet built; tension 23), since AWS
  calls go through the `aws` CLI rather than curl - `lib/http.sh` itself only ever gates scope hosts and
  the update endpoint.
- `tools/update-advisories.sh` is new tooling, not a scan module. It ships with the mechanism only: no
  real advisory data is populated by this change. Populating `data/advisories.db` for real ecosystems
  (npm, PyPI, Maven, Go, RubyGems, Composer) is explicitly a follow-up ticket.
- Two CI checks enforce the corrected model going forward: `tests/lint-egress.sh` (no scan-path code can
  reach a non-allowlisted destination, and the update script is unreachable from the scan path) and
  `tests/lint-no-ai.sh` (no AI/LLM provider hostname, SDK name, or API-key environment-variable pattern
  anywhere in the shipped tool).

## Alternatives considered

- **Keep "air-gapped" and describe the update channel as a documented exception.** Rejected: an
  architecture with three stated exceptions to an "air-gapped" claim is not describing an invariant, and
  a rule-by-exception is a rule that eventually gets "cleaned up" back to the false absolute it was an
  exception to.
- **Drop network restrictions entirely and gate everything by an authorization flag instead.**
  Rejected: this is the shape of exactly the risk the operator ruled out - a scanner that can be
  configured to phone home with scan results or source code. Destination allowlisting is what makes
  "never upload" a property `lib/http.sh` can actually enforce, rather than a policy operators are
  trusted to configure correctly.
