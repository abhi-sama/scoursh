#!/usr/bin/env bash
# tools/update-advisories.sh - the explicit, repeatable update channel for
# data/advisories.db.
#
# Owns:
#   docs/DESIGN.md          §2 (the egress model), §6.5 (SCA)
#   docs/FOUNDATION.md tension 25 (offline version matching for SCA - the frozen schema)
#   docs/FOUNDATION.md tension 27 (the egress-model correction that created this script)
#   docs/adr/0001-egress-model-correction.md
#
# This is the ONLY thing allowed to reach config/scanner.conf's
# advisory-update-url (enforced by lib/http.sh: this script is the only
# caller of http_allow_update_endpoint anywhere in the repository).  It is
# NEVER invoked during a scan - tests/lint-egress.sh asserts that scan.sh and
# every lib/ and modules/ script are unreachable to it and it to them - and a
# scan's rules must not change mid-run.  Run it explicitly, whenever you want
# fresher advisory data:
#
#   tools/update-advisories.sh [--config PATH] [--ecosystem LIST] [--out PATH]
#
# This ships the MECHANISM only.  No real advisory data is populated by this
# change; populating data/advisories.db for real ecosystems (npm, PyPI,
# Maven, Go, RubyGems, Composer, Cargo) against a real upstream feed is an
# explicit follow-up ticket.
#
# Output format is tension 25's frozen schema:
#   ecosystem \t package \t version \t advisory_id \t severity \t fixed_versions \t summary
# sorted by (ecosystem, package, version) under LC_ALL=C, with a `#` header
# line carrying the generation timestamp and source.  The update endpoint is
# expected to serve one TSV per ecosystem at `<advisory-update-url>/<eco>.tsv`;
# `#`-prefixed lines in a fetched file are treated as comments and dropped.
# This script does not trust the source to be pre-sorted: the final output is
# always re-sorted here, which is also what makes `LC_ALL=C look`'s prefix
# lookup (tension 25) safe regardless of upstream ordering.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"

CONFIG=$SCOURSH_INSTALL_ROOT/config/scanner.conf
OUT=$SCOURSH_INSTALL_ROOT/data/advisories.db
ECOSYSTEMS=(npm pypi maven go rubygems composer cargo)

usage() {
  cat <<'USAGE' >&2
tools/update-advisories.sh [--config PATH] [--ecosystem LIST] [--out PATH]

Fetches one advisory TSV per ecosystem from the update endpoint configured in
config/scanner.conf's advisory-update-url, and writes data/advisories.db in
the frozen schema (docs/FOUNDATION.md tension 25).

  --config PATH      scanner.conf to read advisory-update-url from
                      (default: config/scanner.conf)
  --ecosystem LIST    comma-separated ecosystem keys to fetch
                      (default: npm,pypi,maven,go,rubygems,composer,cargo)
  --out PATH          where to write the merged database
                      (default: data/advisories.db)

Never invoke this from a scan. It is the sole caller of
http_allow_update_endpoint, and tests/lint-egress.sh checks that it stays
that way.
USAGE
}

while (( $# > 0 )); do
  case $1 in
    --config)
      (( $# >= 2 )) || die "$SCOURSH_EXIT_USAGE" "--config requires a value"
      CONFIG=$2
      shift 2
      ;;
    --ecosystem)
      (( $# >= 2 )) || die "$SCOURSH_EXIT_USAGE" "--ecosystem requires a value"
      IFS=',' read -r -a ECOSYSTEMS <<<"$2"
      shift 2
      ;;
    --out)
      (( $# >= 2 )) || die "$SCOURSH_EXIT_USAGE" "--out requires a value"
      OUT=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit "$SCOURSH_EXIT_OK"
      ;;
    *)
      log_error "unknown argument: $1"
      usage
      exit "$SCOURSH_EXIT_USAGE"
      ;;
  esac
done

(( ${#ECOSYSTEMS[@]} > 0 )) || die "$SCOURSH_EXIT_USAGE" "--ecosystem produced an empty list"

http_allow_update_endpoint "$CONFIG"
BASE=$(http_update_url)
[[ -n $BASE ]] || die "$SCOURSH_EXIT_INPUT" \
  "no advisory-update-url configured in '$CONFIG'; the update channel is disabled until one is set"
BASE=${BASE%/}

WORK=$SCOURSH_SCRATCH/update-advisories
mkdir -p "$WORK"
MERGED=$WORK/merged.tsv
: >"$MERGED"

# Strips `#` comment lines and blank lines without a bare grep/rg (tension 4:
# the engine wrapper is for rule matching, not general text filtering, and
# `tools/` is inside lint-shell.sh's engine_files scope regardless).
_strip_comments() {
  local src=$1 dest=$2 line
  : >"$dest"
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == '#'* ]] && continue
    [[ -n $line ]] || continue
    printf '%s\n' "$line" >>"$dest"
  done <"$src"
}

# Shape-only validation: seven tab-separated fields, the required ones
# non-empty, and the row's own ecosystem field matches what was requested
# (catches a misrouted or misconfigured update endpoint). This is not a
# semantic validator - name normalisation and range correctness are the
# follow-up ticket's job once real data exists.
_validate_ecosystem_body() {
  local eco=$1 body=$2 line n=0
  local f_eco f_pkg f_ver f_adv f_sev f_fixed f_summary extra
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    n=$(( n + 1 ))
    IFS=$'\t' read -r f_eco f_pkg f_ver f_adv f_sev f_fixed f_summary extra <<<"$line"
    if [[ -n ${extra:-} ]]; then
      die "$SCOURSH_EXIT_INCOMPLETE" "update-advisories: $eco.tsv line $n has more than seven fields"
    fi
    if [[ -z $f_pkg || -z $f_ver || -z $f_adv || -z $f_sev || -z $f_fixed || -z $f_summary ]]; then
      die "$SCOURSH_EXIT_INCOMPLETE" "update-advisories: $eco.tsv line $n is missing a required field"
    fi
    if [[ $f_eco != "$eco" ]]; then
      die "$SCOURSH_EXIT_INCOMPLETE" \
        "update-advisories: $eco.tsv line $n claims ecosystem '$f_eco', expected '$eco' - refusing a misrouted feed"
    fi
  done <"$body"
  (( n > 0 )) || log_warn "update-advisories: $eco.tsv had no data rows after stripping comments"
}

fetched=0
for eco in "${ECOSYSTEMS[@]+"${ECOSYSTEMS[@]}"}"; do
  eco=${eco,,}
  raw=$WORK/$eco.raw.tsv
  body=$WORK/$eco.body.tsv
  url=$BASE/$eco.tsv
  log_info "update-advisories: fetching $eco from $url"
  if ! http_request GET "$url" -o "$raw"; then
    die "$SCOURSH_EXIT_INCOMPLETE" "update-advisories: fetch of '$eco' from '$url' failed"
  fi
  _strip_comments "$raw" "$body"
  _validate_ecosystem_body "$eco" "$body"
  cat -- "$body" >>"$MERGED"
  fetched=$(( fetched + 1 ))
done

(( fetched > 0 )) || die "$SCOURSH_EXIT_INPUT" "update-advisories: no ecosystems were fetched"

FINAL=$WORK/advisories.db.new
{
  printf '# scoursh advisories.db  generated_at=%s  source=%s  ecosystems=%s\n' \
    "$(now_iso)" "$BASE" "$(IFS=,; printf '%s' "${ECOSYSTEMS[*]}")"
  LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3 -- "$MERGED"
} >"$FINAL"

mkdir -p "$(dirname -- "$OUT")"
mv -f -- "$FINAL" "$OUT"
lines=$(wc -l <"$OUT")
log_info "update-advisories: wrote ${lines// /} lines to $OUT (ecosystems: ${ECOSYSTEMS[*]})"
