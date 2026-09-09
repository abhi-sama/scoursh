#!/usr/bin/env bash
# modules/image/engine.sh - the container-image-scanning module's pure
# function library (IMG-01, data/scoursh-image-scan-design/report.md
# §3.1/§5.3's "module foundation" row).
#
# WHAT THIS TICKET SHIPS, AND WHAT IT DELIBERATELY DOES NOT.  IMG-01 is the
# ONLY shared-file ticket for this module - it registers the `IMAGE` module
# across every frozen table and shared list (rules/RULE-FORMAT.md,
# lib/records.sh, lib/checks.sh, lib/findings.sh, lib/report.sh, scan.sh -
# see this ticket's own commit) so every later ticket (IMG-02 onward) adds
# only its own files.  This file therefore ships NO acquisition (no
# docker-save/OCI-layout reader), NO distro enumerator (no apk/dpkg/rpm
# package-DB parser), and NO version comparator - report.md §1-§2's whole
# design is out of scope here.  Unlike modules/dast/engine.sh and
# modules/network/engine.sh, it declares no phase table: report.md's v1
# architecture is acquire -> enumerate -> compare, each its own file
# (`acquire.sh`, `distro/apk.sh`, ...), not a set of intensity-gated phases
# run in a fixed order over one target - there is nothing to gate on
# `--intensity` here, so a phase table would be a table with nothing to
# put in it.
#
# The run.sh / engine.sh split is modules/sast/'s, modules/dast/'s and
# modules/network/'s, reused verbatim: this file is a pure function library
# with the standard sourced-once guard and no side effects at source time,
# and modules/image/run.sh is the file that DOES something when sourced.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_ENGINE_SOURCED=1

# modules/sast/engine.sh is sourced for `sast_evaluate_gate` ALONE, reused
# rather than forked for the identical reason modules/dast/engine.sh's and
# modules/network/engine.sh's own comments give: despite its name that
# function is module-agnostic - it re-reads every finding in
# $rundir/findings.fields and applies the severity/confidence/fail-on-new
# filter chain with no module check anywhere in its body.  Guarded
# internally (its own sourced-once guard), so this source line is safe to
# leave unconditional exactly as its two siblings' are.
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"
if [[ -z ${SCOURSH_CHECKS_SOURCED:-} ]]; then
  # shellcheck source=lib/checks.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/checks.sh"
fi
