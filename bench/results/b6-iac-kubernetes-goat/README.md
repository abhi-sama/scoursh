# B6 IaC leg, part 2 — kubernetes-goat scenarios, hand-labelled

**This is the B6 IaC leg's Kubernetes half.** Its sibling is
`bench/results/b6-iac-terragoat-aws/`; the secrets half is
`bench/results/b6-secrets-leaky-repo/`. None of it is published anywhere in
`docs/` — that is ticket B9.

Read this one **beside** the TerraGoat half rather than instead of it. The same
four tools, the same scoring method and the same label rules produce opposite
rankings on the two corpora, and that contrast is the leg's most useful output.

## What was run

| | |
|---|---|
| Corpus | `madhuakula/kubernetes-goat` @ `723a0db478f050d173d23b4ce5044b65bce0bdd0` (MIT), `scenarios/` |
| Scan root | a **slice**: `scenarios/` minus `metadata-db/` — see `SLICE-MANIFEST` and below |
| Ground truth | `bench/labels/kubernetes-goat.truth` — **hand-authored for this leg and committed**, rationale beside every case |
| Cases | **35**: 19 genuinely misconfigured documents, 16 correctly configured |
| scoursh | `0.1.0-dev+0be15e965f28`, `scan.sh iac --format json`, defaults, **not `--use-engines`** |
| Checkov | `3.3.10`, `checkov -d . -o json --compact --quiet` |
| KICS | `2.1.21`, `kics scan -p ROOT -q <installed query library>` |
| Trivy | `0.74.0`, `trivy config --skip-check-update` |
| Host | one macOS machine, one run each |

**The unit is the Kubernetes document** — one case per `---`-separated document
declaring a `kind:`, which is the object a real API server would create and the
object all three competitors name in their own `resource` field. Every document
in the slice is labelled, none skipped. The same "wrong reason still scores a
true positive" limitation applies as in the TerraGoat half, for the same reason
and with the same justification; the label file states it.

### The slice, and why it is not a tuning knob

`scenarios/metadata-db/` is a Helm chart whose `templates/*.yaml` are unrendered
Go templates — `metadata.name: {{ include ... }}` is not a Kubernetes manifest
until `helm template` has run, and scoring a plain-manifest scanner on it
measures template syntax rather than detection. The label set excludes it, so
the scan root excludes it, so the scan surface equals the labelled surface and
"outside every labelled range" means "the labeller declined to judge this"
rather than "nobody could have judged this".

Measured, and recorded because the obvious guess is wrong: **excluding it
changes no tool's finding count** — Checkov reports the same 253 failed checks
either way. `bench/make-slice.sh` records the exact arguments in a MANIFEST, only
ever removes paths, and is applied once for every tool.

## Scope first (§7.2 framing)

**scoursh ships 8 Kubernetes checks** (`modules/iac/kubernetes.rules`); the other
three ship several hundred each.

| tool | rule ids that fired here | records emitted |
|---|---|---|
| scoursh | 6 | 51 |
| Checkov | 28 | 255 |
| KICS | 37 | 451 |
| Trivy | 30 | 316 |

## The numbers

All findings, loose matching, line granularity, window 0:

| tool | TP | FN | FP | TN | recall | FPR | precision | **Youden J** |
|---|---|---|---|---|---|---|---|---|
| trivy-config | 16 | 3 | 0 | 16 | 0.842 | 0.000 | 1.000 | **+0.842** |
| scoursh-iac | 14 | 5 | 0 | 16 | 0.737 | 0.000 | 1.000 | **+0.737** |
| checkov | 18 | 1 | 8 | 8 | 0.947 | 0.500 | 0.692 | **+0.447** |
| kics | 19 | 0 | 9 | 7 | 1.000 | 0.562 | 0.679 | **+0.438** |

**scoursh places second of four on Youden J here, with zero false positives, on
6 rule ids against 28-37.** That is a real result and it should be read with its
cause attached rather than as a headline.

**Read the recall column and the J column together, because they disagree and
the disagreement is the point.** KICS finds every single misconfigured document
(recall 1.000) and flags nine of the sixteen correctly-configured ones as well;
Checkov is one behind on both. Recall alone would rank them first and second and
scoursh last — which is exactly the failure the scout report's rule R3 exists to
prevent, and exactly the `ldapi` row it caught in the SAST pilot. J = TPR − FPR
ranks them the other way round because eight of Checkov's ten false positives
and all nine of KICS's come from **one rule each fired against every ClusterIP
Service in the corpus** (`CKV_K8S_21`, "default namespace should not be used";
KICS `611ab018`, the same). A Service in the default namespace is a
namespace-hygiene preference, not a misconfiguration a reviewer would block on,
and this label set says so under its R-CLEAN rule.

So the honest summary of this row is: **scoursh's Kubernetes pack is narrow and
what it does check, it checks without noise.** It is not evidence that scoursh
detects more than Checkov or KICS — they each found more genuinely-misconfigured
documents than it did.

## What scoursh missed, and why each miss is diagnosable

Five of the 19 misconfigured documents:

| case | why scoursh missed it |
|---|---|
| `hunger-check` `Secret/vaultapikey` | no check for a committed `Secret` object with base64 `data:`. `IAC-K8S-PLAINTEXT_SECRET-01` looks for a credential in a container's `env:`, which is a different shape. **Trivy misses these too**; KICS catches them. |
| `hunger-check` `Secret/webhookapikey` | as above |
| `system-monitor` `Secret/goatvault` | as above |
| `hunger-check` `Role/secret-reader` | `resources: ["*"]` with `verbs: ["get","watch","list"]`. `IAC-K8S-WILDCARD_RBAC-01` did not fire — a wildcard RESOURCE list with narrow verbs is a different shape from a wildcard VERB list, and the pack appears to cover the second. |
| `insecure-rbac` `ClusterRoleBinding/superadmin` | binds the built-in `cluster-admin`. There is no wildcard anywhere in the document; recognising it needs the knowledge that `cluster-admin` is a privileged built-in, which no pattern rule has. |

The first four are candidate rule work. The fifth is an architectural limit of
the pattern tier, in the same family as `docs/DESIGN.md` §15's declared taint
gap, and should be recorded as a limitation rather than filed as a bug.

The six checks that did fire: `IAC-K8S-RUN_AS_ROOT-01` (14),
`IAC-K8S-SA_TOKEN_DEFAULT-01` (14), `IAC-K8S-MISSING_RESOURCE_LIMITS-01` (8),
`IAC-K8S-PRIVILEGED-01` (6), `IAC-K8S-HOST_NAMESPACE-01` (5),
`IAC-K8S-MUTABLE_TAG-01` (4). `IAC-K8S-PLAINTEXT_SECRET-01` and
`IAC-K8S-WILDCARD_RBAC-01` fired zero times.

## Sensitivity of the borderline labels

Three calls are marked BORDERLINE. Re-scoring with the two kube-bench Jobs
flipped from misconfigured to clean **and** the NodePort Service flipped from
clean to misconfigured — the combination least favourable to scoursh:

| tool | recall | FPR | Youden J |
|---|---|---|---|
| checkov | 0.947 → 0.944 | 0.500 → 0.529 | +0.447 → +0.415 |
| kics | 1.000 → 1.000 | 0.562 → 0.588 | +0.438 → +0.412 |
| scoursh-iac | 0.737 → 0.667 | 0.000 → 0.118 | +0.737 → +0.549 |
| trivy-config | 0.842 → 0.778 | 0.000 → 0.118 | +0.842 → +0.660 |

scoursh's J moves most in absolute terms, and **the ranking does not change**.

## Why only the all-findings column

Same reason as the TerraGoat half: Checkov CE ships no severity at all, so a
`--min-severity high` column would compare Trivy's and KICS's real severities
against a placeholder. See that leg's README for the measurement.

## How to reproduce

```sh
bench/fetch-corpus.sh kubernetes-goat
bench/make-slice.sh kubernetes-goat k8s-scenarios --from scenarios --exclude metadata-db
for t in scoursh-iac checkov kics trivy-config; do
  bench/run-tool.sh --tool "$t" \
    --root bench/corpora/_slices/k8s-scenarios/root --corpus kubernetes-goat \
    --out bench/results/b6-iac-kubernetes-goat --portable-paths
done
bench/score.sh --truth bench/labels/kubernetes-goat.truth \
  --results bench/results/b6-iac-kubernetes-goat --match line --format md
```

## Runtime

16 files, far below the size at which a runtime comparison means anything:
scoursh 67 s, Checkov 2 s, Trivy 1 s, KICS under 1 s. **Not a ratio** —
`bench/README.md`'s rule 4.
