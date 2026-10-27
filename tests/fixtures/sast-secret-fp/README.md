# sast-secret-fp: false-positive and recall regression controls

Each line below a tag is a verbatim shape that `modules/sast/rules/secrets.rules`
reported as a hardcoded credential on real public repositories, or a real
credential it silently dropped.  `tests/suites/sast-secrets-forms.sh` section H
scans this tree with the shipped pack and with the pack as it stood before the
fix, and asserts:

- `[[Nnn]]`: flagged before the fix, quiet now (a false positive that is gone).
- `[[Qnn]]`: quiet before and quiet now (a shape the fix must not start flagging).
- `[[Pnn]]`: reported before and reported now (a true positive that is kept).
- `[[Rnn]]`: missed before, reported now (a real credential the line-wide guards
  dropped because of something else on the same line).

Credential values are inert placeholders (`Tr0ub4dor3xK`, `s3cr3tT0kenV4lue0000`),
never provider-shaped strings.  The tree is copied out of `tests/` before it is
scanned, because the keyword records treat `tests/` as a non-production path.
