# Recorded CORS responses (`tests/suites/dast-cors.sh`)

Each `*.headers` file is a **recorded** response-header block, in the exact shape
`lib/http.sh`'s header-capture sink writes: a status line, CRLF-terminated
header lines, then a blank line.
`tests/suites/dast-cors.sh` serves these through a stub `SCOURSH_HTTP_TRANSPORT`,
so the whole DAST-08 check - probe, header read, classify, emit - is exercised
with no network, no Docker and no live target (`docs/DESIGN.md` §12).

**CRLF is deliberate and load-bearing.**
It is what HTTP is on the wire, and a header reader that does not strip the
trailing `\r` compares `"<origin>\r"` against the sentinel, finds them unequal,
and reports a reflecting server clean.
Do not "normalise" these files to LF.

**The sentinel origin is the shipped default**
(`modules/dast/passive/cors_engine.sh`'s `CORS_SENTINEL_ORIGIN`).
The suite asserts that value matches what these files were recorded against and
says so in the failure message, so changing the sentinel fails loudly here
rather than silently turning every reflection case into a non-finding.
It is an RFC 2606 reserved `.example` name: it resolves to nothing, it is never
a request destination, and it names no application, company or product
(AGENTS.md §1).

| File | What it records |
|---|---|
| `reflect-plain.headers` | Origin echoed, credentials NOT allowed |
| `reflect-credentials.headers` | Origin echoed **and** `Access-Control-Allow-Credentials: true` |
| `reflect-nocache.headers` | As above, `TRUE` in a different case and no `Vary: Origin` |
| `reflect-lowercase.headers` | The same, with HTTP/2's mandatory lowercase field names |
| `wildcard.headers` | Literal `*` |
| `wildcard-credentials.headers` | Literal `*` plus credentials (a browser refuses to honour this pair) |
| `allowlist.headers` | A correctly-configured server: a static allowlisted origin that is not the sentinel |
| `suffix-trap.headers` | A value that CONTAINS the sentinel and is not equal to it |
| `none.headers` | No CORS header at all |
| `duplicate.headers` | Two `Access-Control-Allow-Origin` headers; the last one wins |
| `padded.headers` | Values wrapped in RFC 7230 optional whitespace |
