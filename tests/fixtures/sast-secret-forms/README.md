# tests/fixtures/sast-secret-forms

The assignment-form matrix for `modules/sast/rules/secrets.rules`, consumed by
`tests/suites/sast-secrets-forms.sh`.

**Every credential value in this tree is a FAKE TEST VALUE.**
`Tr0ub4dor3xK`, `hunter2` and `s3cr3tT0kenV4lue0000` are invented strings that
open nothing; they exist so a rule change can be watched failing and then
passing.  Nothing here is, or has ever been, a real credential.

Each interesting line carries an inline `[[Pnn]]` or `[[Nnn]]` tag:

- `Pnn` is a **positive control**: the scanner MUST report a `SAST-SEC-*`
  finding on that line.  A miss is a false negative, which for a secrets
  scanner is the product silently failing at its one job.
- `Nnn` is a **negative control**: the scanner MUST stay quiet on that line.
  These are the shapes that look like a credential assignment but are a
  reference, a template, a path, a length, or a placeholder.  A hit is noise,
  and a rule set that flags every `KEY=value` line trains operators to ignore
  the tool - the same outcome as missing the secret.

This is a DEDICATED tree, deliberately not `tests/fixtures/{vuln,clean}/`.
Those two are scanned wholesale by every pack's suite, so a file added there
becomes every other pack's problem (see `AGENTS.md`, "cross-fire").  The
cross-fire direction that does matter for secrets.rules - it ships no `files:`
glob, so it reads every file in any tree it is pointed at - is asserted
separately in the suite, against `tests/fixtures/clean/` itself.
