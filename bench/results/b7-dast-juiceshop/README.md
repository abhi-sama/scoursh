# B7 DAST leg — scoursh vs OWASP ZAP, Juice Shop

`bench/results/b7-dast-juiceshop/` is the DAST leg's real measurement:
scoursh's `dast` module (authenticated, `--intensity active`) against OWASP
ZAP 2.17.0 (traditional spider, passive scan, active scan — no AJAX spider,
see below), over a 20-case hand-labelled ground truth against a local,
operator-owned OWASP Juice Shop container. This is ticket B7, the last
unmeasured leg named in `docs/COMPARISON.md`'s "Not yet measured" table; that
row is replaced by this leg's numbers in the same change that added this
README.

**Read this file before citing a number from this leg anywhere.** Three
things make it a narrower measurement than the SAST/SCA/IaC/secrets legs
before it, and all three are load-bearing for how to read the table below:
Juice Shop is a client-rendered SPA that both tools could reach only a small,
overlapping slice of; ZAP's AJAX spider (the one component built specifically
for that limitation) could not be measured in this environment at all; and
one active-scan rule had to be disabled after repeatedly crashing the
container. Every one of these is a measured, disclosed fact below, never a
silent adjustment.

## The target

`tools/dast-test-target.sh` (already landed on `dev`) starts
`bkimminich/juice-shop:v20.1.1`
(`sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf`),
fixed at `127.0.0.1:3400`, authorized by
`docs/DAST-TEST-TARGET-AUTHORIZATION.md` and
`tools/dast-test-target/scope.conf` — the same local, operator-owned target
scoursh's own `tests/e2e/dast-auth-live.sh` suite already scans. This leg
reused the already-running container named in its own dispatch brief rather
than starting a second one. `bench/corpus.lock`'s `dast-juiceshop` row pins
the image digest; see that row's own note for why `commit` there is the
*source* commit the `v20.1.1` tag dereferences to rather than the image
pin itself (`bench/lib/corpus.sh` requires a real 40-hex commit on every row
or the whole lock file fails to load).

VAmPI (`erev0s/vampi:latest`,
`sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12`) was
also obtained — a first `docker pull` attempt returned no output for several
minutes and was mistaken for "not obtainable" mid-session; a direct retry
completed normally, confirming Docker Hub was reachable throughout and the
first attempt was simply slow. It is pinned in `bench/corpus.lock` by digest
but **is not part of this leg's scored corpus**: a second target needs its
own hand-labelled truth set and its own full ZAP active-scan run, and each
ZAP active-scan attempt against Juice Shop *alone* took five real attempts
before one completed (below) — extending that to a second application was
outside this ticket's time budget once the Juice Shop measurement was real.
Recorded rather than dropped, so a follow-up ticket does not have to
re-derive whether VAmPI is obtainable here.

## Why ZAP took five attempts, and what changed between them

The scout report's §4.4 diagnosed the *previous* DAST attempt (2026-09-08) as
the wrapper (`zap-full-scan.py`) losing its control connection mid-scan on a
memory-constrained Docker VM, and named three fixes: `-config
start.checkForUpdates=false`, an explicit JVM heap, and polling the ZAP API
directly instead of the wrapper. The operator raised the shared Docker VM's
memory allocation (7.75 GiB → 15.6 GiB) before this leg started, discharging
that prerequisite. All three fixes were applied from the first attempt here
(`bench/run-dast-leg.sh cmd_zap_start`/`cmd_zap`) and the daemon itself never
lost its control connection once. It still took five attempts to reach a
completed active scan, for two *different*, newly-measured reasons — neither
one is the failure §4.4 diagnosed, and both are recorded because the naive
read of either ("ZAP just needs more memory") is wrong:

| # | Configuration | Outcome |
|---|---|---|
| 1 | `-Xmx2048m`, no container `--memory` ceiling, AJAX spider included | Container OOM-killed (`OOMKilled=true`, exit 137) ~30s into the AJAX spider |
| 2 | `-Xmx2048m`, `--memory=4g` | Same: OOM-killed ~30s into the AJAX spider |
| 3 | `-Xmx3072m`, `--memory=8g` | Same again: OOM-killed ~30s into the AJAX spider, at a memory ceiling twice the Docker VM headroom this leg otherwise needed |
| 4 | AJAX spider skipped entirely; traditional spider + passive + active scan | Reached the active scan, then OOM-killed again at a **stable 34% progress**, immediately after `DomXssScanRule` ("Cross Site Scripting (DOM Based)", plugin `40026`) started — the docker logs for every one of attempts 1-4 show a `Reaper thread starting` line (Crawljax's own browser-pool reaper) right before the container disappears, which is what identified the actual shared cause |
| 5 | Plugin `40026` explicitly disabled (`ascan/action/disableScanners/?ids=40026`) before starting the active scan; AJAX spider still skipped | **Completed**: spider 100%, passive queue drained, active scan 100%, 588 alerts exported |

**The real cause was never the JVM heap or the container memory ceiling** —
attempt 3 doubled both from attempt 1 and still failed in the same place,
which is the measurement that ruled the heap/ceiling out. It was a specific
component: both the AJAX spider (Crawljax driving headless Firefox) and
`DomXssScanRule` (Crawljax driving a headless browser for DOM-XSS detection)
launch the same browser-automation machinery, and that machinery is what
exhausted memory in this Docker Desktop environment, not ZAP's own JVM heap.
Disabling the one active-scan rule that used it (attempt 5) let the other
~100 default-policy active-scan rules run to completion; the AJAX spider has
no equivalent per-technique disable switch and was left out rather than
retried a fourth time.

**What this means for the numbers below, stated plainly:** DOM-based XSS via
`DomXssScanRule` was not tested by ZAP in this run, and neither tool's
crawl includes what the AJAX spider would have found by executing the SPA's
own JavaScript — Juice Shop's actual REST API surface is reachable only
because this leg's own ground truth hand-enumerates a slice of it (see
below), not because either tool discovered it. This is a real, disclosed
scope reduction against ZAP's own best-case capability, not a claim that ZAP
cannot do these things.

## The ground truth

`bench/labels/dast-juiceshop.truth` — 20 cases (14 real, 6 negative
controls) across four categories, each verified by probing the target
directly (`curl -i`) or, for the one SQL-injection case, by hand-reproducing
a challenge Juice Shop's own shipped challenge catalogue names explicitly
("Login Admin"). **No tool's output was consulted to produce it**
(methodology rule R2) — see that file's own header for the full account,
including why `cors` and `missing-csp` have no negative control anywhere in
this target (Juice Shop applies the same misconfiguration on every response
probed) and why `missing-csp` is scored as a single application-level case
rather than one per endpoint.

## The numbers

Both severity columns, both CWE-matching modes, always — methodology rule
R5/R3. Full scorecards: [`scorecard-all-findings.md`](scorecard-all-findings.md),
[`scorecard-high-and-critical.md`](scorecard-high-and-critical.md),
[`scorecard-all-findings.json`](scorecard-all-findings.json).

### Corpus aggregate, all findings

| tool | matching | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh-dast | loose | 3 | 11 | 1 | 5 | 0.214 | 0.167 | 0.750 | **+0.047** |
| scoursh-dast | strict | 3 | 11 | 0 | 6 | 0.214 | 0.000 | 1.000 | **+0.214** |
| zap | loose | 5 | 9 | 2 | 4 | 0.357 | 0.333 | 0.714 | **+0.024** |
| zap | strict | 0 | 14 | 0 | 6 | 0.000 | 0.000 | n/a | **+0.000** |

`J = 0.000` is a coin flip. Both tools score low in absolute terms — this
corpus is small (20 cases, four categories) and heavily constrained by what
either tool could actually reach on a SPA, stated above and in the "what
this does not show" section below.

### Per category (loose), all findings

| tool | category | TP/14 real cases split by category | recall | FPR | J |
|---|---|---|---|---|---|
| scoursh-dast | cors (12 cases) | 2 | 0.167 | n/a | n/a |
| scoursh-dast | missing-csp (1 case) | 1 | 1.000 | n/a | n/a |
| scoursh-dast | sqli (1 real + 2 traps) | 0 | 0.000 | 0.000 | +0.000 |
| scoursh-dast | info-disclosure (4 traps only) | — | n/a | 0.250 | n/a |
| zap | cors (12 cases) | 4 | 0.333 | n/a | n/a |
| zap | missing-csp (1 case) | 1 | 1.000 | n/a | n/a |
| zap | sqli (1 real + 2 traps) | 0 | 0.000 | 0.000 | +0.000 |
| zap | info-disclosure (4 traps only) | — | n/a | 0.500 | n/a |

## What this does show

- **On the endpoints each tool actually reached, ZAP's traditional spider
  found more of the target than scoursh's own crawler.** scoursh's DAST
  crawl is static-link-only and Juice Shop is an Angular SPA with almost no
  server-rendered `<a href>`; scoursh's own `dast/crawl` phase records this
  explicitly (`looks like a single-page app ... its API is not reachable by
  following links`) and reached 13 endpoints total. ZAP's traditional spider
  (no JavaScript execution either, but a different link-extraction
  implementation) reached a few more of the twelve `cors` cases (4 vs 2)
  before either tool's crawl ceiling was hit — genuinely reflecting a
  difference in each tool's static-crawl implementation on the identical
  input, not a difference in "AJAX awareness" (neither tool executed
  JavaScript in this run).
- **scoursh's `DAST-CORS-WILDCARD-01` and ZAP's `Cross-Domain
  Misconfiguration` (plugin `10098`) disagree on CWE**, and that disagreement
  is exactly what strict vs. loose matching exists to surface (methodology
  rule R3). scoursh assigns `CWE-942` (Permissive Cross-domain Policy);
  ZAP assigns `CWE-264` (Permissions, Privileges, and Access Control) — a
  real taxonomy choice by each project, not a scoring bug. Under loose
  matching both tools get credit for every wildcard-CORS endpoint they
  actually flagged; under strict matching ZAP's `cors` recall drops to
  0.000 because its own CWE for this exact defect is not in scoursh's
  class. The identical pattern repeats for `missing-csp`: scoursh's
  `DAST-HDR-CSP_MISSING-01` claims `CWE-1021`, ZAP's plugin `10038` claims
  `CWE-693` — both are defensible, generic-vs-specific readings of the same
  missing header, and neither tool is "wrong".
- **Neither tool caught the one hand-verified real vulnerability.** The
  Juice Shop admin-login SQL-injection bypass this leg reproduced by hand
  (`bench/labels/dast-juiceshop.truth`'s own `sqli-login` case) is a
  comment-injection auth bypass, not an error-based or boolean-differential
  signal either tool's automated SQLi technique is built to notice from a
  single crafted login attempt with no baseline comparison. This is a real,
  disclosed miss for both tools on the one case in this corpus with the
  clearest real-world impact, not evidence that either tool cannot ever find
  SQL injection — see docs/COMPARISON.md's own SAST SQLi numbers, which are a
  different check family entirely, for what scoursh's pattern-based approach
  *does* catch.
- **ZAP rated none of its 588 alerts "High" risk against this target.** The
  high+critical column (`scorecard-high-and-critical.md`) drops all 588 ZAP
  records and keeps 3 of scoursh's 18 — a fact about how ZAP's default
  active-scan policy calibrated this specific run's severities, not a claim
  ZAP found nothing.
- **scoursh's own passive run against this same target found a real,
  `critical`-severity finding this corpus does not score**:
  `DAST-JWT-SIG_NOT_VERIFIED-01`, confirming the target does not verify JWT
  signatures on at least one authenticated request. It sits outside this
  leg's four hand-labelled categories (see "what is out of scope" below) and
  is reported here for completeness, not folded into any number above.

## What this does not show

- **Neither tool's SPA-blind crawl is representative of its own ceiling.**
  ZAP's own AJAX spider — built specifically for this limitation — could not
  be measured in this environment at all (above). A comparison that *could*
  run the AJAX spider would very likely find ZAP discovering substantially
  more of Juice Shop's real REST/GraphQL surface than either tool reached
  here, since this leg's own ground truth had to hand-enumerate the handful
  of REST endpoints it scores at all.
- **This is one small corpus (20 cases, 4 categories) against one target.**
  It is not a claim about DAST detection in general, the same caveat every
  other landed leg's own README states for its own corpus.
- **`missing-csp` and `cors` have no negative control in this corpus**
  (`bench/labels/dast-juiceshop.truth`'s own header explains why: Juice Shop
  applies the same misconfiguration on every response probed), so `FPR`/`J`
  for those two categories render as `n/a` rather than a fabricated number —
  they can only show recall here.
- **scoursh's own DAST engine ships 92 checks** (docs/COMPARISON.md's DAST
  row) spanning authentication/session handling, GraphQL introspection,
  rate-limiting, host-header injection, JWT algorithm confusion, and
  object-level authorization; this corpus hand-verifies only four narrow
  categories reachable within this ticket's time budget. That is a scope
  limit on the CORPUS, never a claim about what scoursh's engine can find —
  methodology rule "lead each category with the scope cell before the score"
  applies here exactly as it does to every other landed leg.

## How to reproduce

```sh
bash tools/dast-test-target.sh start           # idempotent; reuses a running target
bash bench/run-dast-leg.sh setup               # provisions the two auth identities

bash bench/run-dast-leg.sh scoursh bench/results/b7-dast-juiceshop/scoursh-dast

bash bench/run-dast-leg.sh zap-start
bash bench/run-dast-leg.sh zap bench/results/b7-dast-juiceshop/zap
bash bench/run-dast-leg.sh teardown             # stops ONLY the ZAP container this script started

bash bench/run-dast-leg.sh normalise bench/results/b7-dast-juiceshop

bash bench/score.sh --truth bench/labels/dast-juiceshop.truth \
  --results bench/results/b7-dast-juiceshop --format md
bash bench/score.sh --truth bench/labels/dast-juiceshop.truth \
  --results bench/results/b7-dast-juiceshop --format md --min-severity high
```

`bench/run-dast-leg.sh scoursh` runs `scan.sh dast` directly against
`config/scope.conf`/`config/auth.conf` (removed again in a trap on every exit
path) rather than through a symlinked `SCOURSH_INSTALL_ROOT` fixture: a
symlinked fixture was tried first and failed `lib/records.sh`'s `E081`
owning-module check, because that check resolves each loaded `*.rules` file's
REALPATH and strips `SCOURSH_INSTALL_ROOT` as a literal prefix — a `modules`
symlink resolves straight through to this repository's real path, which is
not under a separate fixture root at all. Measured directly, at both default
and `--intensity active`, before `run-dast-leg.sh` was written the way it is
now; `tests/e2e/dast-auth-live.sh`'s own symlinked-fixture pattern still
works for its own passive-only assertions, so this is not a general defect,
only a shape the FIXROOT pattern's own realpath handling does not cover for a
direct `active/checks.rules` load.

## Runtime

scoursh: 179s wall clock for the full authenticated `--intensity active` run
(13 endpoints, 28 phases). ZAP: spider 21s, active scan (99 rules, plugin
`40026` disabled) 105s — both figures are the fifth, successful attempt only;
the four failed attempts before it are the "how ZAP took five attempts"
section above, not part of this number.
