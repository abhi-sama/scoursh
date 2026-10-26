# Native finding precision

Native SAST/IaC regexes collect candidates. `modules/sast/precision.awk` and
`modules/iac/precision.awk` then inspect local syntax before emission. These
offline readers use the existing awk dependency; they never execute target code.
The frozen record format, check ids and fingerprint schema are unchanged. Removing
an earlier false candidate can change a later identical token's occurrence ordinal;
review baseline/diff changes during an upgrade rather than interpreting them as code edits.

Source checks distinguish comments/docstrings from code, constant arguments from
dynamic arguments, and current calls from adjacent calls. Local binding proofs
cover fixed module/expression names, sanitization, null-prototype dictionaries
and an explicit constant-key merge guard. Unknown data remains eligible; these
readers do not provide interprocedural taint analysis or a language type system.
Local reassignment, mutable argument escapes and closed scopes invalidate a safety
proof instead of borrowing a constant from a different receiver/function.
The secrets family bypasses this source filtering, including secrets in comments,
documentation and tests.

IaC checks inspect owning YAML/JSON maps, HCL blocks and Docker stages. A sibling
container/resource cannot supply a missing guard. Kubernetes fields require a
workload or RBAC kind and the corresponding spec ancestry; CloudFormation fields
require the resource's Properties map. Helm values without a provable consumer
remain review tasks. Templated/computed configuration still requires rendered
manifests or the optional offline semantic engines. Rules still collect candidates
with line-oriented patterns, so minified documents can hide candidate tokens even
when the ownership reader understands their structure. Native readers do not render
templates, resolve YAML aliases/merges or model every language/format extension.

An informational `Review required:` entry means the native candidate cannot
establish source trust, security use or deployment exposure. It carries no asserted
CWE/OWASP impact and a zero-impact CVSS vector. Review entries carry no automatic
edit scaffold, and the run records the unresolved native context as a coverage
reduction. It is not evidence of an exploitable
vulnerability. Secret redaction stays conservative: a placeholder names the scrubber
that matched, and does not by itself establish that a code token is a credential. The generic and Go-specific TLS checks are linked
through the existing `related` field when file, line and matched token agree; both
identities remain visible, and the reports link the related source statement.

SCA keeps installed identity and version together: npm aliases use their target
name, Go registry replacements use their effective coordinate, and Gradle block
comments do not declare dependencies. Unknown local Go replacements/excluded pins
remain a declared coverage reduction. Python markers are never evaluated on the
scanning host: only the impossible `< "0"` version condition is proven absent;
possible/unknown conditions remain candidates, with their marker and conditional installation
status carried into evidence. Composer derives its indentation
unit but still expects one structural token per line.

Run `tests/run-tests.sh static-precision` and `tests/run-tests.sh sca-precision`.
The source/IaC suite derives its roster from the shipped rule registry and checks
every audit safe/unsafe pair plus their combination in one file. It always runs
the grep fallback and repeats with ripgrep when available. Existing `sast`,
`iac`, `sca`, `sast-secrets-forms` and `secret-redaction` suites remain necessary.
Precision is measured on these controls and audited public inputs; it is not a
claim that arbitrary programs can be classified without false positives.
