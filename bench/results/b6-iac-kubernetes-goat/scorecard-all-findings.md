# Detection scorecard

Corpus categories: `kubernetes`

Cases: 35 (19 real, 16 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Matching granularity: `line` - a case is flagged only by a finding inside its
own recorded line range (window 0). Ranges within one file do not overlap.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| checkov | `3.3.10` | `723a0db478f050d173d23b4ce5044b65bce0bdd0` | terraform-aws kubernetes |
| kics | `2.1.21` | `723a0db478f050d173d23b4ce5044b65bce0bdd0` | terraform-aws kubernetes |
| scoursh-iac | `0.1.0-dev+0be15e965f28` | `723a0db478f050d173d23b4ce5044b65bce0bdd0` | terraform-aws kubernetes |
| trivy-config | `0.74.0` | `723a0db478f050d173d23b4ce5044b65bce0bdd0` | terraform-aws kubernetes |

## Finding volume (records, not cases)

| tool | records kept | dropped by severity | no line | outside every labelled range |
|---|---|---|---|---|
| checkov | 255 | 0 | 0 | 0 |
| kics | 451 | 0 | 0 | 0 |
| scoursh-iac | 51 | 0 | 0 | 0 |
| trivy-config | 316 | 0 | 3 | 0 |

These are RECORD counts. Every number in the tables below counts CASES, so a
tool reporting one defect five times moves this table and nothing else.

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| checkov | kubernetes | 18 | 1 | 8 | 8 | 0.947 | 0.500 | 0.692 | +0.447 |
| kics | kubernetes | 19 | 0 | 9 | 7 | 1.000 | 0.562 | 0.679 | +0.438 |
| scoursh-iac | kubernetes | 14 | 5 | 0 | 16 | 0.737 | 0.000 | 1.000 | +0.737 |
| trivy-config | kubernetes | 16 | 3 | 0 | 16 | 0.842 | 0.000 | 1.000 | +0.842 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| checkov | 1 of 1 | 0 | 18 | 1 | 8 | 8 | 0.947 | 0.500 | 0.692 | +0.447 |
| kics | 1 of 1 | 0 | 19 | 0 | 9 | 7 | 1.000 | 0.562 | 0.679 | +0.438 |
| scoursh-iac | 1 of 1 | 0 | 14 | 5 | 0 | 16 | 0.737 | 0.000 | 1.000 | +0.737 |
| trivy-config | 1 of 1 | 0 | 16 | 3 | 0 | 16 | 0.842 | 0.000 | 1.000 | +0.842 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| checkov | kubernetes | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |
| kics | kubernetes | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |
| scoursh-iac | kubernetes | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |
| trivy-config | kubernetes | - | - | - | - | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* | *no CWE in truth* |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| checkov | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |
| kics | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |
| scoursh-iac | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |
| trivy-config | 0 of 1 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.
1 categor(y/ies) carry no ground-truth CWE and are excluded from this strict
aggregate rather than counted as misses - see the per-category table above.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| checkov | 0 of 0 | n/a - no category here carries a ground-truth CWE |
| kics | 0 of 0 | n/a - no category here carries a ground-truth CWE |
| scoursh-iac | 0 of 0 | n/a - no category here carries a ground-truth CWE |
| trivy-config | 0 of 0 | n/a - no category here carries a ground-truth CWE |

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
