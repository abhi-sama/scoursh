# Detection scorecard

Corpus categories: `sca-go sca-npm sca-pypi`

Cases: 26 (13 real, 13 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| grype | `0.118.0` | `n/a - see bench/sca-advisories.lock (not a git-cloned corpus)` | sca-npm sca-pypi sca-go |
| osv-scanner | `2.5.1` | `n/a - see bench/sca-advisories.lock (not a git-cloned corpus)` | sca-npm sca-pypi sca-go |
| scoursh-sca | `0.1.0-dev+1710274dbf30` | `n/a - see bench/sca-advisories.lock (not a git-cloned corpus)` | sca-npm sca-pypi sca-go |
| trivy-fs | `0.74.0` | `n/a - see bench/sca-advisories.lock (not a git-cloned corpus)` | sca-npm sca-pypi sca-go |

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| grype | sca-go | 3 | 0 | 3 | 0 | 1.000 | 1.000 | 0.500 | +0.000 |
| grype | sca-npm | 6 | 0 | 3 | 3 | 1.000 | 0.500 | 0.667 | +0.500 |
| grype | sca-pypi | 4 | 0 | 3 | 1 | 1.000 | 0.750 | 0.571 | +0.250 |
| osv-scanner | sca-go | 3 | 0 | 3 | 0 | 1.000 | 1.000 | 0.500 | +0.000 |
| osv-scanner | sca-npm | 6 | 0 | 3 | 3 | 1.000 | 0.500 | 0.667 | +0.500 |
| osv-scanner | sca-pypi | 4 | 0 | 3 | 1 | 1.000 | 0.750 | 0.571 | +0.250 |
| scoursh-sca | sca-go | 0 | 3 | 0 | 3 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh-sca | sca-npm | 6 | 0 | 3 | 3 | 1.000 | 0.500 | 0.667 | +0.500 |
| scoursh-sca | sca-pypi | 4 | 0 | 3 | 1 | 1.000 | 0.750 | 0.571 | +0.250 |
| trivy-fs | sca-go | 3 | 0 | 3 | 0 | 1.000 | 1.000 | 0.500 | +0.000 |
| trivy-fs | sca-npm | 6 | 0 | 3 | 3 | 1.000 | 0.500 | 0.667 | +0.500 |
| trivy-fs | sca-pypi | 4 | 0 | 3 | 1 | 1.000 | 0.750 | 0.571 | +0.250 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| grype | 3 of 3 | 0 | 13 | 0 | 9 | 4 | 1.000 | 0.692 | 0.591 | +0.308 |
| osv-scanner | 3 of 3 | 0 | 13 | 0 | 9 | 4 | 1.000 | 0.692 | 0.591 | +0.308 |
| scoursh-sca | 3 of 3 | 0 | 10 | 3 | 6 | 7 | 0.769 | 0.462 | 0.625 | +0.307 |
| trivy-fs | 3 of 3 | 0 | 13 | 0 | 9 | 4 | 1.000 | 0.692 | 0.591 | +0.308 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| grype | sca-go | 3 | 0 | 0 | 3 | 1.000 | 0.000 | 1.000 | +1.000 |
| grype | sca-npm | 6 | 0 | 0 | 6 | 1.000 | 0.000 | 1.000 | +1.000 |
| grype | sca-pypi | 4 | 0 | 0 | 4 | 1.000 | 0.000 | 1.000 | +1.000 |
| osv-scanner | sca-go | 3 | 0 | 0 | 3 | 1.000 | 0.000 | 1.000 | +1.000 |
| osv-scanner | sca-npm | 6 | 0 | 0 | 6 | 1.000 | 0.000 | 1.000 | +1.000 |
| osv-scanner | sca-pypi | 4 | 0 | 0 | 4 | 1.000 | 0.000 | 1.000 | +1.000 |
| scoursh-sca | sca-go | 0 | 3 | 0 | 3 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh-sca | sca-npm | 6 | 0 | 0 | 6 | 1.000 | 0.000 | 1.000 | +1.000 |
| scoursh-sca | sca-pypi | 4 | 0 | 0 | 4 | 1.000 | 0.000 | 1.000 | +1.000 |
| trivy-fs | sca-go | 3 | 0 | 0 | 3 | 1.000 | 0.000 | 1.000 | +1.000 |
| trivy-fs | sca-npm | 6 | 0 | 0 | 6 | 1.000 | 0.000 | 1.000 | +1.000 |
| trivy-fs | sca-pypi | 4 | 0 | 0 | 4 | 1.000 | 0.000 | 1.000 | +1.000 |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| grype | 3 of 3 | 0 | 13 | 0 | 0 | 13 | 1.000 | 0.000 | 1.000 | +1.000 |
| osv-scanner | 3 of 3 | 0 | 13 | 0 | 0 | 13 | 1.000 | 0.000 | 1.000 | +1.000 |
| scoursh-sca | 3 of 3 | 0 | 10 | 3 | 0 | 13 | 0.769 | 0.000 | 1.000 | +0.769 |
| trivy-fs | 3 of 3 | 0 | 13 | 0 | 0 | 13 | 1.000 | 0.000 | 1.000 | +1.000 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| grype | 0 of 3 | sca-go sca-npm sca-pypi  |
| osv-scanner | 0 of 3 | sca-go sca-npm sca-pypi  |
| scoursh-sca | 1 of 3 | sca-npm sca-pypi  |
| trivy-fs | 0 of 3 | sca-go sca-npm sca-pypi  |


## What this scorecard is not

- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
