# DAST content-discovery wordlist

`docs/DESIGN.md` §7.2: "Content discovery from the **vendored** wordlist
(status-code + length heuristics)."
`modules/dast/active/discovery.sh` (DAST-12) reads a candidate-path wordlist
from disk to drive its wordlist-based sweep.

## No wordlist ships in this repository - and why

**This directory intentionally contains no wordlist**, only this README.
A content-discovery wordlist is exactly the kind of large, frequently-updated
data set (SecLists and its kin run to hundreds of thousands of entries) that
would break `scoursh`'s two load-bearing invariants:

- **the no-egress rule** (`docs/FOUNDATION.md`, the no-egress rule) - fetching
  or updating a list at scan time is egress the operator did not authorise; and
- **the request budget** (DAST-01/DAST-32) - an unbounded list turns one safe
  pass into a request storm against an authorised target.

So the list is **vendored by the operator, offline, and read from disk** - the
same discipline every other data file in this tool follows (rule packs,
payloads, advisory data). The scanner performs no range arithmetic and no
fetching; it reads a plain file.

## How to vendor one

Put a plain-text file on disk and point the scanner at it:

- **Default path** (used when the env var is unset):
  `modules/dast/wordlists/content-discovery.txt` - not present in a fresh
  clone; create it here, or
- **override** with `SCOURSH_DAST_DISCOVERY_WORDLIST=/path/to/your-wordlist.txt`.

When no wordlist is found at either location, the wordlist-based technique
degrades to a **recorded coverage gap** (`docs/DESIGN.md` §15) - it never errors
and never reports its silence as a clean result. The fixed, in-code
sensitive-path and backup/temp-file techniques still run, because neither needs
an external list.

## File format

One candidate path per line, relative to the target's `base-url`.
A line whose first byte is `#` is a comment; a blank line is ignored.

Each entry is validated as a safe relative path before it is ever sent: an
entry carrying a control character, an absolute or scheme-qualified URL
(`http://...`, `//host/...`), a `..` traversal, or a token longer than
`_DISCOVERY_MAX_WORD_LEN` (128) bytes is dropped rather than requested. A
leading `/` is stripped so every entry resolves under the authorised base-url.

## Bounds

The sweep is **bounded**, so the list's size can never turn one pass into an
unbounded storm on top of the per-run request budget:

- `_DISCOVERY_MAX_WORDS` (default 500) - at most this many wordlist entries are
  probed per run; a longer list is truncated with a recorded coverage gap.
- `_DISCOVERY_MAX_REQUESTS` (default 600) - an absolute ceiling on total probe
  requests per run across every technique.

Every request is a read-only `GET` through `lib/http.sh` (tension 19), so it
inherits the rate limiter, request budget, circuit breaker and DAST-32 ceilings
like every other DAST request.
