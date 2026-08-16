# DAST injection payloads

`docs/DESIGN.md` §7.3: "Payloads live in `payloads/` so they're auditable."
Every file here is a vendored, read-from-disk data file the §7.3 injection
probes (`modules/dast/active/*.sh`) load at runtime.
No probe reaches the network for a payload; these ship in the repository and are
read off disk, like every other rule and wordlist (`docs/FOUNDATION.md` the
no-egress rule).

## The non-destructive contract

`docs/DESIGN.md` §7.3, restated by the DAST-36 amendment for DAST-14..DAST-25:
detection-oriented, **non-destructive**, evidence-only.
Concretely, every payload in this directory is:

- **read-only** - it queries, delays, or breaks syntax; it never `DROP`s,
  `DELETE`s, `UPDATE`s, `INSERT`s, or writes;
- **not a stacked write** - the one place a stacked statement appears
  (`WAITFOR DELAY` for MSSQL, which `docs/DESIGN.md` §7.3 names explicitly) is a
  pure time delay, not a data change;
- **bounded** - a time-based payload sleeps for a small, capped number of
  seconds the probe substitutes, never an unbounded or amplifying expression;
- **non-exfiltrating** - it confirms a signal (a DB error, a boolean
  differential, a latency delta); it never dumps rows.

A change here that adds a destructive, unbounded, or exfiltrating payload
violates that contract and must be rejected in review.

## File format

One payload per line.
A line whose first byte is `#` is a comment; a blank line is ignored.
Templates use two placeholders the probe substitutes before sending:

- `%B` - the parameter's **baseline** value (its observed example, or `1`), so
  the payload breaks out of the same value shape the endpoint normally sees;
- `%N` - the **bounded sleep seconds** (time-based payloads only).

The boolean-pair file is the one exception: each line is
`<true-template><TAB><false-template>` - two payloads that are identical apart
from a condition that is always true versus always false, which is exactly the
"tautology vs contradiction that are otherwise identical" `docs/DESIGN.md` §7.3
asks for.

## Graceful degradation

A probe that cannot read a payload file (absent or empty) records a
`coverage_reduction` naming the technique it could not run and continues with
the techniques it can - it never errors, and it never reports the skipped
technique's silence as a clean result (`docs/DESIGN.md` §15).
