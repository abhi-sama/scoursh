// tools/dast-test-target/http-client.js - a minimal HTTP client run INSIDE
// the local DAST test-target container via `docker exec`, never on the host.
//
// Why this exists rather than a host-side `curl`: tests/lint-shell.sh's "no
// bypass" check (docs/FOUNDATION.md tension 19) forbids curl/wget/nc anywhere
// outside lib/http.sh and tools/vendor-engines.sh, because a second path to
// the network would bypass the scope gate. tools/dast-test-target.sh and
// tools/dast-test-identities.sh are operator-run local setup tooling, not
// part of that dispatch path, but staying off host curl entirely means no
// new exemption is needed and the chokepoint's guarantee ("nothing but
// lib/http.sh and the one documented vendoring script ever calls curl")
// stays literally true. Running curl equivalent logic *inside the
// container's own Node runtime* reaches only the container's own localhost
// server and touches no other host.
//
// Also keeps credentials off argv (docs/FOUNDATION.md tension 9: a secret is
// never a command-line argument): the request spec, including any password
// or bearer token, is read from stdin as JSON, never passed as a docker exec
// argument that would appear in a process listing.
//
// Contract: reads one JSON object from stdin -
//   {"method": "GET"|"POST", "path": "/rest/...", "headers": {...}, "body": {...}}
// - and writes two things to stdout: the HTTP status code on the first line,
// then the raw response body (which may itself be multi-line JSON) on the
// rest. A transport-level failure (connection refused, etc.) prints to
// stderr and exits 1.

const http = require('http');

let input = '';
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  let spec;
  try {
    spec = JSON.parse(input);
  } catch (e) {
    process.stderr.write('ERR: invalid JSON request spec: ' + e.message + '\n');
    process.exit(1);
  }

  const hasBody = Object.prototype.hasOwnProperty.call(spec, 'body');
  const payload = hasBody ? JSON.stringify(spec.body) : null;
  const headers = Object.assign({}, spec.headers || {});
  if (payload !== null) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload);
  }

  const req = http.request(
    {
      host: '127.0.0.1',
      port: 3000,
      path: spec.path,
      method: spec.method || 'GET',
      headers,
    },
    (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        process.stdout.write(res.statusCode + '\n' + body + '\n');
      });
    }
  );
  req.on('error', (e) => {
    process.stderr.write('ERR: ' + e.message + '\n');
    process.exit(1);
  });
  if (payload !== null) {
    req.write(payload);
  }
  req.end();
});
