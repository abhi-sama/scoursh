#!/usr/bin/env python3
"""bench/tools/coverage-honesty.py — the B8 coverage-honesty metric (scout
report §5.3): "of the checks this tool ships, what fraction can the reader
confirm actually executed on this corpus?"

Reads every scoursh run.json already committed under bench/results/**/raw/
(one per B4/B5/B6 leg run) and, for each, computes:

  checks_selected  - what scan.sh loaded for this profile/module (the ceiling)
  checks_run       - what actually executed and could have produced a finding
  gap              - checks_selected - checks_run
  gap_declared     - of the gap, how many are named in a coverage_reduction
                      or skipped_checks record with a stated reason (never a
                      silent zero)
  accounted_pct    - gap_declared / gap (must be 100% for every run; anything
                      less is a scoursh regression, not a benchmark result)

No competitor tool in this benchmark set (Semgrep, Trivy, Grype, OSV-Scanner,
Checkov, KICS, Gitleaks, TruffleHog) emits an equivalent record: their raw
output lists only what fired, never what a rule pack shipped, so there is no
JSON field to read the mirror-image number from. That absence is recorded
here as a structural fact per tool, not modelled as 0%. See docs/FOUNDATION.md
AGENTS.md "coverage_reduction" and "checks_run" entries for what the fields
mean; this script only counts them.

Usage: bench/tools/coverage-honesty.py [--json] bench/results
"""
import json
import sys
from pathlib import Path


def find_run_jsons(root: Path):
    return sorted(root.glob("**/raw/**/run.json"))


def leg_name_for(path: Path, results_root: Path) -> str:
    rel = path.relative_to(results_root)
    return rel.parts[0]


def tool_name_for(path: Path, results_root: Path) -> str:
    rel = path.relative_to(results_root)
    return rel.parts[1]


def declared_gap_checks(run: dict) -> set:
    declared = set()
    for cr in run.get("coverage_reduction", []) or []:
        checks = cr.get("checks") if isinstance(cr, dict) else None
        if checks:
            declared.update(checks)
        # freeform-string coverage_reduction entries (this project's own
        # meta/coverage_reduction lines are "module=... reason=... checks=[...]")
        if isinstance(cr, str) and "checks=[" in cr:
            inner = cr.split("checks=[", 1)[1].split("]", 1)[0]
            declared.update(c for c in inner.split() if c)
    for sk in run.get("skipped_checks", []) or []:
        if isinstance(sk, dict) and sk.get("check"):
            declared.add(sk["check"])
        elif isinstance(sk, str):
            declared.add(sk)
    return declared


def score_run(run: dict) -> dict:
    selected = set(run.get("checks_selected") or [])
    ran = set(run.get("checks_run") or [])
    gap = selected - ran
    declared = declared_gap_checks(run) & gap
    return {
        "checks_selected": len(selected),
        "checks_run": len(ran),
        "gap": len(gap),
        "gap_declared": len(declared),
        "gap_undeclared": sorted(gap - declared),
        "accounted_pct": (100.0 if not gap else round(100.0 * len(declared) / len(gap), 1)),
    }


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in argv
    results_root = Path(args[0] if args else "bench/results").resolve()
    rows = []
    for rj in find_run_jsons(results_root):
        try:
            run = json.loads(rj.read_text())
        except Exception as exc:  # pragma: no cover - defensive, reported not swallowed
            print(f"SKIP (unreadable): {rj}: {exc}", file=sys.stderr)
            continue
        if run.get("tool") != "scoursh":
            continue
        row = score_run(run)
        row["leg"] = leg_name_for(rj, results_root)
        row["tool"] = tool_name_for(rj, results_root)
        row["case"] = rj.parent.parent.name if rj.parent.name == "run" and rj.parent.parent.parent.name == "cases" else rj.parent.name
        row["path"] = str(rj.relative_to(results_root))
        rows.append(row)

    if as_json:
        print(json.dumps(rows, indent=2))
        return 0

    total_gap = sum(r["gap"] for r in rows)
    total_declared = sum(r["gap_declared"] for r in rows)
    print(f"{'leg':30} {'tool':16} {'selected':>8} {'run':>5} {'gap':>5} {'declared':>9} {'accounted':>10}")
    for r in rows:
        print(f"{r['leg']:30} {r['tool']:16} {r['checks_selected']:8} {r['checks_run']:5} "
              f"{r['gap']:5} {r['gap_declared']:9} {r['accounted_pct']:9.1f}%")
    print()
    print(f"TOTAL: {len(rows)} scoursh run(s) inspected, "
          f"{total_gap} total unrun-but-selected checks, "
          f"{total_declared} declared with a reason "
          f"({(100.0 if not total_gap else round(100.0*total_declared/total_gap,1))}% accounted)")
    undeclared = [r for r in rows if r["gap_undeclared"]]
    if undeclared:
        print("\nUNDECLARED GAPS (would be a scoursh regression, not expected):")
        for r in undeclared:
            print(f"  {r['path']}: {r['gap_undeclared']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
