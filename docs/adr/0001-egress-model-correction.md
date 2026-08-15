# ADR 0001: Correct the egress model - egress-restricted, not air-gapped

- **Status:** Accepted
- **Date:** 2026-08-15

## Context

`scoursh`'s founding documents describe the tool as "air-gapped."
`docs/DESIGN.md`'s title is "Air-Gapped Shell Security Scanner - Design & Implementation Plan," its §1
says the tool "runs on an air-gapped host," and `README.md` and `AGENTS.md` repeat the same claim in
several places, including README's headline sentence and a dedicated "Why air-gapped" section.

That claim has never been true of the architecture as designed, and it was never intended to be.
`docs/DESIGN.md` §7 (DAST) and §8 (cloud/AWS live) both require the scanner to make real network calls
*at scan time*: a DAST run `curl`s a live target the operator names, and a `cloud --live` run makes
read-only AWS API calls against the operator's own account.
Neither is vendored data resolved in advance; both are live traffic that has to leave the host while the
scan is running.
A tool that must reach a live target to do its job is not air-gapped by any ordinary reading of the
word.

The actual, and stronger, property `scoursh` was built to guarantee is narrower than "no network access
at all": exactly two categories of outbound traffic are ever permitted, each gated on the operator having
named the exact destination in advance, and every call - present and future - is forced through one of
two runtime chokepoints that refuse anything else by default.
`docs/FOUNDATION.md` tension 19 (the `lib/http.sh` scope gate) and tension 23 (the `lib/awscli.sh`
read-only guard) already record that this destination-restricted model is what was designed and built.
The "air-gapped" label was always describing something narrower and more mundane - SAST, SCA, and IaC
happen to need no network at all, since nothing about reading source code, lockfiles, or config files
needs an external target - but the label was written at the level of the whole tool, not those three
modules, and it stayed there as DAST and cloud were designed on top of it.

An earlier attempt to correct this (PR #66, "Correct the egress model: egress-restricted, not
air-gapped") closed unmerged, with 2 of its 3 CI checks failing.
That attempt bundled the correction with unrelated scope - a new advisory-update endpoint, a
destination-allowlist chokepoint, and two new linters - most of which has since landed through other,
independent tickets: `tests/lint-no-ai.sh` exists, and the advisory-database expansion shipped as
`tools/vendor-engines.sh advisories` under tension 25.
More importantly, that attempt rewrote `docs/DESIGN.md` itself, including its title - which this
project's own rule forbids: `docs/DESIGN.md` is the handoff spec and is preserved verbatim, its wording
load-bearing, never rewritten to match a later decision.

## Decision

`scoursh` is described, everywhere the claim is made about the tool as a whole, as
**egress-restricted, enforced by destination** - not air-gapped.

Exactly two categories of outbound traffic are permitted, and both require the operator to have named
the exact destination first:

1. `curl` (via `lib/http.sh`'s `http_request`) to a host authorized in `config/scope.conf`.
2. Read-only AWS API calls (via `lib/awscli.sh`'s `aws_ro`) to the operator's own account.

Everything else is refused by default at those two chokepoints, at runtime, with exit code
`SCOURSH_EXIT_SCOPE` - not merely undocumented or discouraged.
The three modules that exist today (SAST, SCA, IaC) make zero network calls at scan time, which remains
true and is preserved wherever it was the actual claim being made (e.g. "an air-gapped host may not have
`shellcheck` installed" describes a class of host the tool is expected to run on, not a claim about the
tool itself, and is left as-is).

This correction is recorded in `docs/FOUNDATION.md` as **tension 28**, following the register's own
convention: where it contradicts the letter of `docs/DESIGN.md`, the register wins, and it says so
explicitly.
`docs/DESIGN.md` is **not edited** - not its title, not §1, not any other section - per the
project's rule that the handoff spec is preserved verbatim.
`README.md` and `AGENTS.md`, which are not preserved-verbatim documents, are corrected directly:
the opening claim, the table of contents, the "Genuinely air-gapped, precisely defined" feature bullet,
the "Why air-gapped" section (renamed and reworded), and the equivalent claims in `AGENTS.md`'s "What
scoursh is" and "The no-egress rule" sections.

Not every occurrence of the word "air-gapped" in the tree is this same claim, and not every occurrence
is changed by this decision.
Several uses - describing the class of restricted-network host the tool is expected to install and run
on, e.g. in `tests/run-tests.sh`, `docs/CI-RUNBOOK.md`, and `lib/core.sh` - are accurate as written and
are left alone.
The ones changed are the ones asserting, of the tool as a whole, a guarantee it does not make.

## Consequences

- No document claims `scoursh` is air-gapped where that claim is false. `docs/FOUNDATION.md` tension 28
  is the authoritative correction; this ADR is its dated record.
- `docs/DESIGN.md` remains byte-unchanged, as required. Its "air-gapped" title and §1 text are now
  understood as superseded by tension 28, per the register's own precedence rule, rather than edited.
- The egress model as documented now matches what `lib/http.sh` and `lib/awscli.sh` already enforce at
  runtime - this is a documentation and terminology correction only; no chokepoint code changes.
- Future documents describing `scoursh`'s network posture as a whole should use "egress-restricted,
  enforced by destination," reserving "air-gapped" for describing the class of host the tool can run on
  (which remains an accurate and useful thing to say about SAST, SCA, and IaC).

## Supersedes

- `docs/DESIGN.md`'s title and its "air-gapped" framing in §1, §6.5, and §9, to the extent those
  describe the tool as a whole rather than the SAST/SCA/IaC modules specifically. `docs/DESIGN.md`'s
  text is unchanged; `docs/FOUNDATION.md` tension 28 is the record of what supersedes it and why.
- PR #66's unmerged attempt at this same correction, which is superseded in scope (this ADR corrects
  only the egress-model claim) and in mechanism (this ADR does not touch `docs/DESIGN.md`).
