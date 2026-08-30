# `tests/fixtures/dast/tls/` - recorded TLS material for DAST-07

Everything here is **synthetic and offline**.
No file in this directory came from, or names, a real host: every certificate is issued to the reserved
`fixture.example` domain (RFC 6761 `.example`), and every transcript is assembled from those
certificates rather than captured from a live target.
`docs/DESIGN.md` §12 requires DAST logic to be testable against recorded responses with no live target,
and `tests/lint-shell.sh`'s DAST-35 checks scan `tests/` for exactly this reason - a fixture naming a
resolvable host would fail the build.

## Certificates

Four leaf certificates, all RSA-2048, all valid until 2126 so no fixture can rot into a different
verdict as the calendar moves.
Three are issued by a throwaway fixture root (`scoursh fixture root`) whose private key was discarded
immediately and never committed; the fourth signs itself.

| File | Subject CN | subjectAltName | Issuer | What it is for |
|---|---|---|---|---|
| `host-specific.pem` | `api.fixture.example` | `DNS:api.fixture.example` | fixture root | The healthy case: CA-issued, host-specific, no wildcard. |
| `wildcard.pem` | `*.fixture.example` | `DNS:*.fixture.example, DNS:fixture.example` | fixture root | The wildcard case, with a SAN. |
| `no-san.pem` | `*.fixture.example` | **none** | fixture root | The CN-fallback case: a wildcard visible only in the CN. |
| `self-signed.pem` | `api.fixture.example` | `DNS:api.fixture.example` | itself | The self-signed case, where subject == issuer. |

**Expiry is never read off these files' own dates.**
`tls_expiry_state` takes `now` as an argument, so the suite computes each case's `now` relative to the
fixture's real `notAfter` (`tls_time_to_epoch` on the certificate itself).
That is what makes `expired`, `expiring` and `ok` all reachable from one committed certificate, and
what keeps every one of them deterministic - see `modules/dast/passive/tls_engine.sh`'s header for why
`openssl x509 -checkend` was rejected in favour of injectable time.

## Transcripts

`openssl s_client -connect ... -servername ... -showcerts` output, in **both userlands' spellings**,
because that divergence is the thing DAST-07 most easily gets wrong.
`openssl3-*` files use OpenSSL 1.1/3.x conventions (comma-form distinguished names,
`subject=CN = host, O = Org`); `libressl-*` files use LibreSSL / OpenSSL 1.0 conventions (slash-form
DNs, `subject=/O=Org/CN=host`, and the `New, TLSv1/SSLv3, Cipher is ...` family label that is **not**
the negotiated version).

| File | Protocol | Cipher | Verify | Certificate |
|---|---|---|---|---|
| `openssl3-tls13-host-specific.transcript` | TLSv1.3 | `TLS_AES_256_GCM_SHA384` | 0 (ok) | `host-specific.pem` |
| `openssl3-tls10-3des.transcript` | TLSv1 | `DES-CBC3-SHA` | 0 (ok) | `host-specific.pem` |
| `openssl3-tls12-wildcard.transcript` | TLSv1.2 | `ECDHE-RSA-AES256-GCM-SHA384` | 0 (ok) | `wildcard.pem` |
| `openssl3-tls12-wildcard-cn-only.transcript` | TLSv1.2 | `ECDHE-RSA-AES256-GCM-SHA384` | 0 (ok) | `no-san.pem` |
| `libressl-tls12-self-signed.transcript` | TLSv1.2 | `ECDHE-RSA-AES256-GCM-SHA384` | 18 (self signed certificate) | `self-signed.pem` |
| `libressl-tls11-rc4.transcript` | TLSv1.1 | `ECDHE-RSA-RC4-SHA` | 0 (ok) | `host-specific.pem` |
| `openssl3-handshake-failed.transcript` | TLSv1.3 *offered* | `0000` | 0 (ok) | none |

The last row is the one worth reading twice.
A failed handshake still prints an `SSL-Session:` block with a filled-in `Protocol  :` and
`Cipher    : 0000`, so a parser that accepted a protocol alone would report the *offered* version as
negotiated for a connection that agreed on nothing.
`tls_parse_session` requires the cipher for that reason, and `tests/suites/dast-tls.sh` pins it.
