# `tests/fixtures/secret-redaction/`

The positive controls for `tests/suites/secret-redaction.sh`.

Every credential-shaped string in this directory is a **fake test canary**, not a
credential.
None of them opens anything, anywhere, and none was ever issued by any provider.
They exist so the suite can plant a known value, scan it, and assert that value is
absent from every byte the run writes.

They are deliberately spelled so that a reader who greps this repository for a
leaked secret can tell in one line that these are not one, while still matching
`modules/sast/rules/secrets.rules`' own patterns - a canary that the scanner does
not detect proves nothing.
That is why the "fake" marker sits on the comment line ABOVE each value rather
than inside it: `secrets.rules` gives each of these checks `context-window: 0`,
so a same-line marker matching its `context-deny` list would suppress the very
finding the suite needs.
