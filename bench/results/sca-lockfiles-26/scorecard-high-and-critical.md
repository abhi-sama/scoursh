# Detection scorecard

Corpus categories: `sca-go sca-npm sca-pypi`

Cases: 26 (13 real, 13 sanitized trap)

Severity filter: `high`. CWE equivalence classes: `bench/cwe-classes.conf`.

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
| grype | sca-go | 3 | 0 | 2 | 1 | 1.000 | 0.667 | 0.600 | +0.333 |
| grype | sca-npm | 5 | 1 | 2 | 4 | 0.833 | 0.333 | 0.714 | +0.500 |
| grype | sca-pypi | 3 | 1 | 1 | 3 | 0.750 | 0.250 | 0.750 | +0.500 |
| osv-scanner | sca-go | 3 | 0 | 1 | 2 | 1.000 | 0.333 | 0.750 | +0.667 |
| osv-scanner | sca-npm | 5 | 1 | 2 | 4 | 0.833 | 0.333 | 0.714 | +0.500 |
| osv-scanner | sca-pypi | 4 | 0 | 2 | 2 | 1.000 | 0.500 | 0.667 | +0.500 |
| scoursh-sca | sca-go | 0 | 3 | 0 | 3 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh-sca | sca-npm | 5 | 1 | 2 | 4 | 0.833 | 0.333 | 0.714 | +0.500 |
| scoursh-sca | sca-pypi | 3 | 1 | 1 | 3 | 0.750 | 0.250 | 0.750 | +0.500 |
| trivy-fs | sca-go | 3 | 0 | 2 | 1 | 1.000 | 0.667 | 0.600 | +0.333 |
| trivy-fs | sca-npm | 5 | 1 | 2 | 4 | 0.833 | 0.333 | 0.714 | +0.500 |
| trivy-fs | sca-pypi | 3 | 1 | 1 | 3 | 0.750 | 0.250 | 0.750 | +0.500 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| grype | 3 of 3 | 0 | 11 | 2 | 5 | 8 | 0.846 | 0.385 | 0.688 | +0.461 |
| osv-scanner | 3 of 3 | 0 | 12 | 1 | 5 | 8 | 0.923 | 0.385 | 0.706 | +0.538 |
| scoursh-sca | 3 of 3 | 0 | 8 | 5 | 3 | 10 | 0.615 | 0.231 | 0.727 | +0.384 |
| trivy-fs | 3 of 3 | 0 | 11 | 2 | 5 | 8 | 0.846 | 0.385 | 0.688 | +0.461 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| grype | sca-go | 2 | 1 | 0 | 3 | 0.667 | 0.000 | 1.000 | +0.667 |
| grype | sca-npm | 4 | 2 | 0 | 6 | 0.667 | 0.000 | 1.000 | +0.667 |
| grype | sca-pypi | 2 | 2 | 0 | 4 | 0.500 | 0.000 | 1.000 | +0.500 |
| osv-scanner | sca-go | 2 | 1 | 0 | 3 | 0.667 | 0.000 | 1.000 | +0.667 |
| osv-scanner | sca-npm | 4 | 2 | 0 | 6 | 0.667 | 0.000 | 1.000 | +0.667 |
| osv-scanner | sca-pypi | 2 | 2 | 0 | 4 | 0.500 | 0.000 | 1.000 | +0.500 |
| scoursh-sca | sca-go | 0 | 3 | 0 | 3 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh-sca | sca-npm | 4 | 2 | 0 | 6 | 0.667 | 0.000 | 1.000 | +0.667 |
| scoursh-sca | sca-pypi | 2 | 2 | 0 | 4 | 0.500 | 0.000 | 1.000 | +0.500 |
| trivy-fs | sca-go | 2 | 1 | 0 | 3 | 0.667 | 0.000 | 1.000 | +0.667 |
| trivy-fs | sca-npm | 4 | 2 | 0 | 6 | 0.667 | 0.000 | 1.000 | +0.667 |
| trivy-fs | sca-pypi | 2 | 2 | 0 | 4 | 0.500 | 0.000 | 1.000 | +0.500 |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| grype | 3 of 3 | 0 | 8 | 5 | 0 | 13 | 0.615 | 0.000 | 1.000 | +0.615 |
| osv-scanner | 3 of 3 | 0 | 8 | 5 | 0 | 13 | 0.615 | 0.000 | 1.000 | +0.615 |
| scoursh-sca | 3 of 3 | 0 | 6 | 7 | 0 | 13 | 0.462 | 0.000 | 1.000 | +0.462 |
| trivy-fs | 3 of 3 | 0 | 8 | 5 | 0 | 13 | 0.615 | 0.000 | 1.000 | +0.615 |

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
