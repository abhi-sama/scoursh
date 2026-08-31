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

The path-traversal files (DAST-17) use a third placeholder and a fourth line
shape:

- `%M` - a marker's relative path (`pathtraversal-markers.txt`), substituted
  into a directory-climb template (`pathtraversal-sequences.txt`);
- `pathtraversal-markers.txt` is `<marker's relative path><TAB><ERE
  signature>` - the signature is matched against the response body, and must
  be specific to the marker file's real CONTENTS so a page that merely echoes
  the requested path back is not itself a match.

The template-injection file (DAST-18) takes NO placeholder and a fifth line
shape - a template expression is the whole parameter value, not a break-out
from an existing one:

- `ssti-expressions.txt` is `<template-engine family><TAB><payload><TAB><ERE
  signature of the EVALUATED result>`.
  The payload is one multiplication of two small integers wrapped in one
  engine's delimiters and nothing else; the signature is a literal sentinel
  wrapped around the PRODUCT, so an unevaluated echo of the payload can never
  match it.
  The invariant that makes that airtight, and which `tests/suites/dast-ssti.sh`
  re-derives from the file row by row, is that the digit `8` appears in every
  signature and in no payload - so no delete, reorder, re-encode or partial
  strip of what was sent can manufacture the result.
  The product is deliberately kept under 1000 because FreeMarker and every
  other locale-formatting engine groups from four digits up, and a
  plain-digit signature would then MISS the family it was aimed at.
  A row whose family has no check id in `modules/dast/active/checks.rules` is
  refused at runtime and recorded, never sent.

The NoSQL-injection boolean-pair file (DAST-21) mixes two row shapes in one
file, both still `<true-template><TAB><false-template>`:

- `nosqli-boolean-pairs.txt` rows 1-2 use `%B` (a `$where` JS string-context
  tautology, AND-based like `sqli-boolean-pairs.txt`); rows 3-4 carry NO `%B`
  at all - each column is a whole, standalone comparison-operator object
  literal (e.g. `{"$gte":""}`) that REPLACES the parameter's value outright,
  for an application that deserialises the raw parameter string as a
  query/filter fragment. Neither shape is `$where` combined with a modify
  operator, and neither is a write operator (`$set`/`$unset`/`$push`/
  `$pull`/`$inc`/`$rename`) - see the file's own header for the full
  reasoning.

The CRLF / header-injection file (DAST-23) adds a fourth placeholder and
carries no raw CR or LF byte on disk:

- `crlf-payloads.txt` uses `%B` (the baseline value, as everywhere else),
  `%NL` (this file's own stand-in for a literal CR LF pair, since a real one
  cannot survive as DATA inside a line-oriented text file), and `%H`/`%K` -
  this RUN's own random marker header line and body sentinel, generated once
  by the probe and never vendored, for the identical per-run-random reason
  `openredirect-payloads.txt`'s own `%S` sentinel host is generated rather
  than vendored: nothing but this run's own request could have put that exact
  string in the response, so one response is sufficient evidence with no
  baseline. See the file's own header for the full reasoning, including why
  its second template is sent only after the first already confirmed a
  signal.

## Graceful degradation

A probe that cannot read a payload file (absent or empty) records a
`coverage_reduction` naming the technique it could not run and continues with
the techniques it can - it never errors, and it never reports the skipped
technique's silence as a clean result (`docs/DESIGN.md` §15).
