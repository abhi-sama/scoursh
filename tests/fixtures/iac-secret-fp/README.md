# iac-secret-fp: IaC hardcoded-secret false-positive controls

Shapes the IaC secret rules reported as plaintext credentials on real public
repositories (awesome-compose, Bitnami charts, kubernetes/examples), each next
to a real literal the rule must keep reporting.  `tests/suites/iac.sh` scans
this tree with the shipped packs and with the packs as they stood before the
fix: `[[Nnn]]` lines were reported before and are quiet now, `[[Pnn]]` lines
are reported both times.  Kubernetes controls are tagged on the env entry's
`name:` line, which is where that rule now reports.  Values are inert
placeholders (`Tr0ub4dor3xK`, `s3cr3tT0kenV4lue0000`).
