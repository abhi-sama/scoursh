# `tests/fixtures/dast/banner/` - recorded responses for the §7.1 banner check

One recorded HTTP response per file pair, replayed by the stub transport in `tests/suites/dast-banner.sh`.
Nothing here is captured from a real target, and nothing here names one: `docs/DESIGN.md` §1 makes
`scoursh` target-agnostic, so every host, product and version in this directory is invented.

Naming: `<case><path-with-slashes-as-underscores>.headers` and `.body`, with `<case>._default.*` as the
fallback for any path the case does not record.
`/` becomes the empty string, so the root document of case `basic` is `basic_.headers`.

Headers are stored CRLF-terminated with their status line, which is exactly what `lib/http.sh`'s
`http_request_capture` writes and therefore what `banner_header_each` has to be able to read.

| Case | What it records |
|---|---|
| `basic` | A server that discloses a product and version in `Server`, a name-only `X-Powered-By`, a generator meta tag in the root document, and one versioned bundle. `/about` repeats the same headers, which is what makes the per-target dedup testable. |
| `quiet` | A response that discloses nothing on any of the three channels. |
