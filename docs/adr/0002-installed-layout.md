# ADR 0002: Keep installed-copy state outside the install tree

- **Status:** Accepted
- **Date:** 2026-09-23

## Context

A checkout historically keeps `config/`, generated advisory data, `state/`,
and `reports/` below its own root. That remains convenient for development,
but it is unsafe for an installed copy: a Homebrew Cellar can be writable and
is still deleted by an upgrade and cleanup. Operator authorisations, diff
state, reports, and a built advisory database must not live there.

## Decision

`lib/core.sh` exports resolved config, data, state, and reports directories.
A checkout has no marker and retains its historical in-tree locations. A
release build alone writes the uncommitted `.scoursh-packaged` marker, which
selects the XDG layout: config in `${XDG_CONFIG_HOME:-~/.config}/scoursh`,
generated data in `${XDG_DATA_HOME:-~/.local/share}/scoursh`, and state plus
reports in `${XDG_STATE_HOME:-~/.local/state}/scoursh/{state,reports}`.

`SCOURSH_HOME` takes precedence in either mode and uses its
`{config,data,state,reports}` children as one container-friendly root.
Read-only rules, payloads, wordlists, and compliance data remain in the
install root. Generated databases prefer user data and fall back to a bundled
copy; their existing per-file environment overrides still win.

## Consequences

- Package upgrades no longer delete operator state.
- `scoursh paths` reports every resolved location.
- Mutable directories are created lazily on first use.
- `docs/DESIGN.md` §3 remains unchanged; tension 26 records this exception.
