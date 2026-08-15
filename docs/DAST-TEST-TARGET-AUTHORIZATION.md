# DAST test-target authorization record

Date: 2026-08-07.

## The decision

scoursh's DAST layer needs a running endpoint to scan, and the operator has no staging environment to
point it at.
The operator will not scan anything not owned outright, so scanning a third party - even a public one -
was never on the table.

Decision: self-host [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately
vulnerable application built for exactly this purpose, locally in Docker via `tools/dast-test-target.sh`.
It runs on the operator's own machine, on a fixed local port, started and stopped by the operator's own
tooling.
There is no legal ambiguity: it is the operator's own container, on the operator's own host, never
reachable from outside it.

## What is authorized

Exactly one target: `http://127.0.0.1:3400/`, the container `tools/dast-test-target.sh` manages, running
the pinned image `bkimminich/juice-shop:v20.1.1`.

The authorization is encoded the same way any real scoursh authorization is encoded: as a
`config/scope.conf`-format record, `rules/RULE-FORMAT.md` §9.4.
That record lives at `tools/dast-test-target/scope.conf` rather than under `config/`, deliberately kept
out of any shipped default (`docs/DESIGN.md` §1's target-agnostic rule: no application or product name is
ever baked into a shipped file).
It is a test fixture, loaded explicitly by `tests/e2e/dast-target-smoke.sh` and by an operator who wants
to point a real `scan.sh --module dast` run at this target, never installed automatically.

`allow-private-addresses: true` is set on that record because 127.0.0.0/8 is in `lib/http.sh`'s
resolution-pinning deny list by default (`docs/FOUNDATION.md` tension 19), and this target is loopback by
design.
No other host, port, or address range is authorized by this record.
`lib/http.sh`'s scope gate refuses everything else, exactly as it refuses everything outside a real
operator's `config/scope.conf` - see `tests/e2e/dast-target-smoke.sh`'s "the gate still refuses everything
else" case for a live check of that refusal against this exact fixture.

## The two test identities

`tools/dast-test-identities.sh` provisions two distinct throwaway accounts inside this same container,
`scoursh-dast-test-a@scoursh.local` and `scoursh-dast-test-b@scoursh.local`, so that a broken-access-control
/ cross-user check (`docs/STEP5-DAST-PLAN.md`'s DAST-29, `authz.sh`) has two real, distinct identities to
exercise once that check exists.
Their generated passwords are never committed: each lives in its own `600` secret-file under
`.dast-test-target/` (gitignored), referenced by path from a generated `.dast-test-target/auth.conf`, in
exactly the credential convention `rules/RULE-FORMAT.md` §9.6.2 already defines for a real operator's
`config/auth.conf`.

## Standing authorization

This record is the operator's standing authorization for scoursh (and any agent acting on the operator's
behalf) to run DAST scans, including active/injection-class checks once they exist, against
`http://127.0.0.1:3400/` for as long as `tools/dast-test-target.sh` is the process that started it.
It does not authorize scanning any other host reachable from the operator's machine, loopback or
otherwise; every other target still requires its own explicit `config/scope.conf` entry, evaluated by the
same gate.
