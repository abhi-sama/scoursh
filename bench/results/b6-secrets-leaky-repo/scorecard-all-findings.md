# Detection scorecard

Corpus categories: `secrets`

Cases: 82 (65 real, 17 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Matching granularity: `line` - a case is flagged only by a finding inside its
own recorded line range (window 0). Ranges within one file do not overlap.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| gitleaks | `8.30.1` | `2e951359cac53addbee56437da3ffb546e3dfe24` | secrets |
| scoursh-secrets | `0.1.0-dev+0be15e965f28` | `2e951359cac53addbee56437da3ffb546e3dfe24` | secrets |
| trufflehog | `trufflehog 3.97.4` | `2e951359cac53addbee56437da3ffb546e3dfe24` | secrets |

## Finding volume (records, not cases)

| tool | records kept | dropped by severity | no line | outside every labelled range |
|---|---|---|---|---|
| gitleaks | 22 | 0 | 0 | 1 |
| scoursh-secrets | 37 | 0 | 0 | 1 |
| trufflehog | 12 | 0 | 0 | 2 |

These are RECORD counts. Every number in the tables below counts CASES, so a
tool reporting one defect five times moves this table and nothing else.

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| gitleaks | secrets | 21 | 44 | 0 | 17 | 0.323 | 0.000 | 1.000 | +0.323 |
| scoursh-secrets | secrets | 33 | 32 | 0 | 17 | 0.508 | 0.000 | 1.000 | +0.508 |
| trufflehog | secrets | 9 | 56 | 1 | 16 | 0.138 | 0.059 | 0.900 | +0.079 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| gitleaks | 1 of 1 | 0 | 21 | 44 | 0 | 17 | 0.323 | 0.000 | 1.000 | +0.323 |
| scoursh-secrets | 1 of 1 | 0 | 33 | 32 | 0 | 17 | 0.508 | 0.000 | 1.000 | +0.508 |
| trufflehog | 1 of 1 | 0 | 9 | 56 | 1 | 16 | 0.138 | 0.059 | 0.900 | +0.079 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| gitleaks | secrets | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |
| scoursh-secrets | secrets | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |
| trufflehog | secrets | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| gitleaks | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |
| scoursh-secrets | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |
| trufflehog | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.
1 categor(y/ies) carry no ground-truth CWE and are excluded from this strict
aggregate rather than counted as misses - see the per-category table above.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| gitleaks | 0 of 0 | n/a - no category here carries a ground-truth CWE |
| scoursh-secrets | 0 of 0 | n/a - no category here carries a ground-truth CWE |
| trufflehog | 0 of 0 | n/a - no category here carries a ground-truth CWE |

1 categor(y/ies) are excluded from this check because no case in them carries a
ground-truth CWE, so strict matching is undefined there rather than failing.


## What this scorecard is not

- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
