#!/usr/bin/env bash
# bench/tools/semgrep-default.sh - Semgrep CE at its DOCUMENTED DEFAULT free
# ruleset, the (a) half of the scout report's rule R5.  bench/tools/semgrep.sh
# is the (b) half - Semgrep's MAXIMUM free ruleset (p/security-audit plus
# p/owasp-top-ten).  Both are published as separate columns per R5 ("hiding
# which was used is how a benchmark gets accused of rigging").
#
# This is a distinct tool id rather than an env-var flip on the other adapter,
# because bench/run-tool.sh keys everything - the results directory, the
# MANIFEST, the scorecard row - off `$tool`, and the two gate configurations
# need to sit side by side in one results/ directory to be scored together.
#
# `--config auto` was tried as the literal reading of "documented default" and
# rejected, measured: it refuses to run under `--metrics=off`
# ("Cannot create auto config when metrics are off"), and metrics-off is this
# harness's own non-negotiable rule - a benchmark must not phone home about
# the corpus it is measuring (bench/tools/semgrep.sh's own header).  `p/default`
# is Semgrep's documented, metrics-independent starter ruleset and is what
# this file runs instead; which config a given run used is recorded in that
# run's own MANIFEST `gate:` line, never left to be inferred from the tool id.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SEMGREP_DEFAULT_SOURCED:-} ]] && return 0
BENCH_TOOL_SEMGREP_DEFAULT_SOURCED=1

# Set BEFORE sourcing semgrep.sh: that file's own assignment is
# `${BENCH_SEMGREP_CONFIG:-p/security-audit p/owasp-top-ten}`, so a value
# already present here wins and semgrep.sh's default is never applied.
BENCH_SEMGREP_CONFIG='p/default'
# shellcheck source=bench/tools/semgrep.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/semgrep.sh"

# Thin wrappers under this file's own tool id.  Everything below is the same
# Semgrep adapter machinery bench/tools/semgrep.sh implements; only the
# ruleset (set above, before that file loaded) differs.
semgrep-default_available() { semgrep_available; }
semgrep-default_version() { semgrep_version; }
semgrep-default_scope() { semgrep_scope; }
semgrep-default_run() { semgrep_run "$@"; }
semgrep-default_normalise() { semgrep_normalise "$@"; }
