# iac-secret-fp: IaC hardcoded-secret false-positive controls

Shapes the IaC secret rules reported as plaintext credentials on real public
repositories (awesome-compose, Bitnami charts, kubernetes/examples), each next
to a real literal the rule must keep reporting.  `tests/suites/iac.sh` scans
this tree with the shipped packs and with the packs as they stood before the
fix: `[[Nnn]]` lines were reported before and are quiet now, `[[Pnn]]` lines
are reported both times, under `rg` and under `grep -E` alike.  Kubernetes
controls sit on the env entry's `name:` line and name the `value:` line the
rule reports (`is the line below`).  Values are inert placeholders
(`Tr0ub4dor3xK`, `s3cr3tT0kenV4lue0000`).
