#!/usr/bin/env bash
# lib/state.sh - the state/ schema, writer, and loader (STATE-01).
#
# Owns:
#   docs/DESIGN.md      §9a - "After each run, persist the set of finding
#                        fingerprints (+ severity, first-seen) to state/."
#   docs/FOUNDATION.md  tension 12 - the FROZEN `state/<run-id>.json` shape
#                        (fp_schema, tool_version, run_id, completed_at,
#                        scan_root_id, covered_checks, findings), including
#                        the four conditional-field rules its RESOLUTION
#                        pins: `history_boundary` and a finding's
#                        `oldest_reaching_commit_time` exist only for
#                        `SAST-HIST-*`; `contributors` exists only for a
#                        derived finding; a finding's `cell` is present on
#                        EVERY finding and is JSON `null` for a derived one,
#                        never the string "none"; `scan_root_id` is present
#                        on every run.
#   docs/FOUNDATION.md  tension 11 stage 8 - "Persist state/: ALL findings,
#                        including suppressed ones, with their first_seen
#                        preserved."  This file is the writer for that stage;
#                        deciding WHAT is suppressed (stage 6) and WHAT
#                        classifies as new/recurring/fixed/unknown (stage 5)
#                        is not its job (see "What this file does NOT do").
#   docs/STEP7-STATE-PLAN.md STATE-01's own row is the ticket-level authority
#                        for this file's scope; read it before extending this
#                        one.
#
# ============================ WHAT THIS FILE IS =============================
# `state/<run-id>.json` is machine-generated JSON, not a `rules/RULE-FORMAT.md`
# record (tension 12's own note: the frozen record format governs
# human-authored files only).  This file is therefore its own small,
# purpose-built JSON reader and writer, in the same tradition as
# `modules/sca/engine.sh`'s `_sca_json_walk` and `modules/dast/crawl_engine.sh`'s
# `crawl_json_flatten` - a general JSON library is not vendored (tension 28's
# no-egress model has no reason to reach for one at scan time), and a fourth
# purpose-built copy scoped to one fixed, known schema is cheaper and more
# auditable than a fifth dependency.
#
# The WRITE side is an explicit, in-memory builder API
# (`state_set_run`/`state_add_covered`/`state_add_history_boundary`/
# `state_add_finding`, then `state_write`) rather than a reader of a live run
# directory's own `findings.fields`/coverage bookkeeping, because neither of
# those exists yet for coverage (STATE-02) - a caller that HAS real data (a
# future ticket's `scan_main`, or this ticket's own tests) builds it up
# through this API and asks this file to persist it faithfully.  The frozen
# shape is what is tested here, not any particular producer of it.
#
# ======================= WHAT THIS FILE DOES NOT DO ==========================
# Stated here rather than discovered later, because a ticket that "just adds
# one more thing" to a done file is how scope creep gets missed in review.
#
#   * It does not decide what a run's cells or covered checks ARE.  Recording
#     coverage as a scan runs - "every module records the cells it is about
#     to visit before visiting them" (tension 12) - is STATE-02.  This file
#     only persists whatever `state_add_covered` is told.
#   * It does not classify anything `new`/`recurring`/`fixed`/`unknown`.  That
#     is STATE-03 (the four-row table and its two guards), STATE-04 (the
#     `SAST-HIST-*` boundary refinement), and STATE-05 (the composite rule).
#     The loader below surfaces `fp_schema` and `scan_root_id` - the fields
#     those guards read - and a full, query-only view of everything else the
#     frozen shape carries, but makes no classification decision itself.
#   * It does not compute a `SAST-HIST-*` history boundary.  `modules/sast/
#     history.sh` (already shipped, step 3e) is what will supply
#     `state_add_history_boundary`'s arguments; this file only persists and
#     reloads the block tension 13 already froze.
#   * It does not wire into `scan_main`, `scan.sh diff`, or any module.  That
#     is STATE-02 (persist-on-every-run) and STATE-06 (the `diff` command).
#     Nothing outside this file and its own test suite calls anything here.
#
# ============================ KNOWN, TRACKED GAP =============================
# Tension 12's coverage-cell table has four `coverage-scope` kinds:
# `path-root` (SAST/history/IaC/SCA), `target` (DAST), `account-region`
# (cloud live), and `scope-key` (posture).  This ticket's own test suite
# exercises the schema for all four kinds by construction (the shape is the
# same JSON object regardless of which module produced it), but
# `account-region` has NO REAL EMITTER yet: `docs/DESIGN.md` §13 step 6
# (cloud) has not landed (`modules/cloud/` does not exist), so nothing in this
# repository has ever produced a genuine `account-region` coverage entry or
# finding to round-trip.  The `account-region` fixtures below are therefore
# HAND-AUTHORED, schema-only proof that the writer and loader treat that scope
# kind correctly in isolation - not evidence that it round-trips a real cloud
# finding, which can only be shown once step 6 exists.
# `docs/STEP7-STATE-PLAN.md`'s STATE-01 row and `AGENTS.md`'s "Current
# position" record this explicitly, so it is not silently assumed covered.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_STATE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_STATE_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# The five coverage-scope kinds tension 12 freezes.  `derived` findings carry
# no `coverage-scope` at all (rules/RULE-FORMAT.md §9.2) and so never appear
# in `covered_checks`; the four below are what a `covered_checks[<id>].scope`
# value is validated against on load.
_STATE_VALID_SCOPES='path-root target account-region scope-key'

_state_valid_scope() {
  [[ " $_STATE_VALID_SCOPES " == *" $1 "* ]]
}

# `state_default_dir` - `state/` sits beside `reports/` under the install
# root (docs/DESIGN.md §3's directory layout), exactly as `scan.sh` resolves
# `reports/<timestamp>` from `$SCOURSH_INSTALL_ROOT`.  Every function below
# takes the state directory as an optional argument defaulting to this, so a
# test (or a future caller before scan.sh wiring exists) can point it at a
# scratch directory instead of the real install tree.
state_default_dir() {
  : "${SCOURSH_INSTALL_ROOT:?state_default_dir: SCOURSH_INSTALL_ROOT is not set}"
  printf '%s/state' "$SCOURSH_INSTALL_ROOT"
}

# ---------------------------------------------------------------------------
# 1. The JSON flattener (own copy; see this file's header for why)
# ---------------------------------------------------------------------------
# `_state_json_flatten` - reads JSON on stdin, prints one line per SCALAR
# leaf to stdout: `<path><TAB><type><TAB><raw value>`.  `path` is the leaf's
# location, object keys and array indices joined by US (0x1f); `type` is one
# of `s` `n` `b` `z` (string, number, boolean, null); for a string, `raw
# value` is the bytes between the quotes, STILL JSON-escaped exactly as
# written, so a raw newline or tab inside a string can never desynchronise
# the TAB-delimited line or the US-delimited path (RFC 8259 §7 forbids a raw
# control byte in a JSON string).  On a syntax error it prints
# `__JSON_ERROR__<TAB><reason>` to stderr and exits 1, emitting no further
# leaves - this parser does not validate everything a schema might require
# (that is `_state_validate`'s job below), only that the bytes are JSON.
_state_json_flatten() {
  awk '
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    function readstr(  s, c) {
      i++
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    function emit(path, type, val) { print path "\t" type "\t" val }
    function value(path,   c, k, idx, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          value(path == "" ? k : path SEP k)
          first = 0
        }
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "]") { i++; return }
          value(path == "" ? idx : path SEP idx)
          idx++
          first = 0
        }
      }
      if (c == "\"") { emit(path, "s", readstr()); return }
      k = readtok()
      if (k == "") fail("unparseable value at byte " i)
      if (k == "true" || k == "false") { emit(path, "b", k); return }
      if (k == "null") { emit(path, "z", k); return }
      emit(path, "n", k)
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      skipws()
      if (i > n) exit 0
      value("")
    }
  '
}

# `_state_json_unescape RAW` - the inverse of the "still escaped" contract
# above, applied once a leaf's raw text is about to become a real bash value.
# `\uXXXX` above U+007F is left as its literal escape text rather than
# composing UTF-8 by hand, the same call `crawl_json_unescape` makes and for
# the same reason: this file has no need to decode it further, and leaving it
# visible keeps that gap visible rather than silently guessing.
# SC1003: `'\'` is a literal single backslash, the character this function
# exists to interpret.
# shellcheck disable=SC1003
_state_json_unescape() {
  local s=$1 out='' i n ch nx code decoded
  if [[ $s != *'\'* ]]; then
    printf '%s' "$s"
    return 0
  fi
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch != '\' ]]; then out+=$ch; continue; fi
    nx=${s:i+1:1}
    case $nx in
      '"') out+='"'; i=$(( i + 1 )) ;;
      '\') out+='\'; i=$(( i + 1 )) ;;
      '/') out+='/'; i=$(( i + 1 )) ;;
      b) out+=$'\b'; i=$(( i + 1 )) ;;
      f) out+=$'\f'; i=$(( i + 1 )) ;;
      n) out+=$'\n'; i=$(( i + 1 )) ;;
      r) out+=$'\r'; i=$(( i + 1 )) ;;
      t) out+=$'\t'; i=$(( i + 1 )) ;;
      u)
        code=${s:i+2:4}
        if [[ $code == 0000 ]]; then
          out+=' '
          i=$(( i + 5 ))
        elif [[ $code =~ ^00[0-7][0-9A-Fa-f]$ ]]; then
          # shellcheck disable=SC2059
          printf -v decoded "\\x${code:2:2}"
          out+=$decoded
          i=$(( i + 5 ))
        else
          out+='\u'
          i=$(( i + 1 ))
        fi
        ;;
      *) out+='\' ;;
    esac
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 2. Write side: an explicit in-memory builder, then state_write
# ---------------------------------------------------------------------------
declare -A _STATE_W=()
declare -a _STATE_W_COVERED_IDS=()
declare -A _STATE_W_COVERED_RULE_DIGEST=()
declare -A _STATE_W_COVERED_SCOPE=()
declare -A _STATE_W_COVERED_CELLS=()
declare -A _STATE_W_HB_COMMIT=()
declare -A _STATE_W_HB_TIME=()
declare -A _STATE_W_HB_OBJECTS=()
declare -A _STATE_W_HB_BOUND=()
declare -a _STATE_W_FINDINGS=()
declare -A _STATE_W_F_CHECK=()
declare -A _STATE_W_F_CELL=()
declare -A _STATE_W_F_SEVERITY=()
declare -A _STATE_W_F_FIRST_SEEN=()
declare -A _STATE_W_F_LAST_SEEN=()
declare -A _STATE_W_F_SUPPRESSED=()
declare -A _STATE_W_F_OLDEST=()
declare -A _STATE_W_F_CONTRIB=()

# Clears everything being built for the NEXT `state_write` call.  Every
# caller that builds a state file from scratch (this file's own tests, and
# eventually STATE-02's persist-on-every-run wiring) starts here.
state_reset() {
  _STATE_W=()
  _STATE_W_COVERED_IDS=()
  _STATE_W_COVERED_RULE_DIGEST=()
  _STATE_W_COVERED_SCOPE=()
  _STATE_W_COVERED_CELLS=()
  _STATE_W_HB_COMMIT=()
  _STATE_W_HB_TIME=()
  _STATE_W_HB_OBJECTS=()
  _STATE_W_HB_BOUND=()
  _STATE_W_FINDINGS=()
  _STATE_W_F_CHECK=()
  _STATE_W_F_CELL=()
  _STATE_W_F_SEVERITY=()
  _STATE_W_F_FIRST_SEEN=()
  _STATE_W_F_LAST_SEEN=()
  _STATE_W_F_SUPPRESSED=()
  _STATE_W_F_OLDEST=()
  _STATE_W_F_CONTRIB=()
}

# `state_set_run RUN_ID SCAN_ROOT_ID FP_SCHEMA TOOL_VERSION [COMPLETED_AT]`
# `fp_schema` and `tool_version` are taken as arguments rather than read from
# `lib/findings.sh`'s `$FP_SCHEMA`/`lib/core.sh`'s `scoursh_version` directly,
# so this file depends on nothing beyond lib/core.sh (this ticket's own
# "nothing in this plan, step-1 primitives only" scope) - a future caller
# that already has both values (scan.sh, by way of lib/report.sh) passes them
# through rather than this file re-deriving them a second way.
state_set_run() {
  local run_id=$1 scan_root_id=$2 fp_schema=$3 tool_version=$4 completed_at=${5:-$(now_iso)}
  [[ -n $run_id ]] || die "$SCOURSH_EXIT_INCOMPLETE" 'internal: state_set_run called with an empty run_id'
  _STATE_W[run_id]=$run_id
  _STATE_W[scan_root_id]=$scan_root_id
  _STATE_W[fp_schema]=$fp_schema
  _STATE_W[tool_version]=$tool_version
  _STATE_W[completed_at]=$completed_at
}

# `state_add_covered CHECK_ID RULE_DIGEST SCOPE CELL` - records one
# (check, cell) coverage pair, per tension 12's frozen shape.  Calling this
# more than once for the same CHECK_ID with a different CELL accumulates a
# deduplicated cell set; calling it with a different RULE_DIGEST/SCOPE
# overwrites the earlier value, which is the caller's own bug to avoid (a
# single check has one rule and one coverage-scope for the run).
state_add_covered() {
  local check_id=$1 rule_digest=$2 scope=$3 cell=$4
  [[ -n $check_id ]] || die "$SCOURSH_EXIT_INCOMPLETE" 'internal: state_add_covered called with an empty check_id'
  [[ -n $cell ]] || die "$SCOURSH_EXIT_INCOMPLETE" "internal: state_add_covered($check_id) called with an empty cell"
  if [[ -z ${_STATE_W_COVERED_SCOPE[$check_id]+set} ]]; then
    _STATE_W_COVERED_IDS+=("$check_id")
  fi
  _STATE_W_COVERED_RULE_DIGEST[$check_id]=$rule_digest
  _STATE_W_COVERED_SCOPE[$check_id]=$scope
  local existing=${_STATE_W_COVERED_CELLS[$check_id]:-}
  if [[ $'\n'"$existing"$'\n' != *$'\n'"$cell"$'\n'* ]]; then
    _STATE_W_COVERED_CELLS[$check_id]="${existing:+$existing$'\n'}$cell"
  fi
}

# `state_add_history_boundary CHECK_ID OLDEST_COMMIT OLDEST_COMMIT_TIME
#                             OBJECTS_SCANNED BOUND_BY`
# Tension 13's `history_boundary` block, attached to an already-`state_add_
# covered`-ed `SAST-HIST-*` check id.  This file does not enforce the id
# pattern - the caller (`modules/sast/history.sh`, eventually) owns which
# checks are history checks; this is purely storage.
state_add_history_boundary() {
  local check_id=$1 oldest_commit=$2 oldest_commit_time=$3 objects_scanned=$4 bound_by=$5
  [[ -n $check_id ]] || die "$SCOURSH_EXIT_INCOMPLETE" 'internal: state_add_history_boundary called with an empty check_id'
  _STATE_W_HB_COMMIT[$check_id]=$oldest_commit
  _STATE_W_HB_TIME[$check_id]=$oldest_commit_time
  _STATE_W_HB_OBJECTS[$check_id]=$objects_scanned
  _STATE_W_HB_BOUND[$check_id]=$bound_by
}

# `state_add_finding FINGERPRINT CHECK_ID CELL SEVERITY FIRST_SEEN LAST_SEEN
#                    SUPPRESSED [OLDEST_REACHING_COMMIT_TIME] [CONTRIBUTORS_CSV]`
#
# CELL='' means a derived finding's JSON `null` cell (tension 12: "the key is
# never omitted and is never the string 'none'" - `null` is unambiguous
# because a real cell is never the empty string, so this file uses that same
# invariant as its in-memory sentinel rather than a second boolean flag).
#
# CONTRIBUTORS_CSV is a comma-separated list of contributor fingerprints,
# present only for a derived finding; empty/omitted for an ordinary one.
state_add_finding() {
  local fingerprint=$1 check_id=$2 cell=$3 severity=$4 first_seen=$5 last_seen=$6 \
    suppressed=$7 oldest=${8:-} contrib_csv=${9:-}
  [[ -n $fingerprint ]] || die "$SCOURSH_EXIT_INCOMPLETE" 'internal: state_add_finding called with an empty fingerprint'
  if [[ -n ${_STATE_W_F_CHECK[$fingerprint]+set} ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" "internal: state_add_finding called twice for fingerprint $fingerprint"
  fi
  _STATE_W_FINDINGS+=("$fingerprint")
  _STATE_W_F_CHECK[$fingerprint]=$check_id
  _STATE_W_F_CELL[$fingerprint]=$cell
  _STATE_W_F_SEVERITY[$fingerprint]=$severity
  _STATE_W_F_FIRST_SEEN[$fingerprint]=$first_seen
  _STATE_W_F_LAST_SEEN[$fingerprint]=$last_seen
  _STATE_W_F_SUPPRESSED[$fingerprint]=$suppressed
  _STATE_W_F_OLDEST[$fingerprint]=$oldest
  local contrib_lines=''
  if [[ -n $contrib_csv ]]; then
    contrib_lines=${contrib_csv//,/$'\n'}
  fi
  _STATE_W_F_CONTRIB[$fingerprint]=$contrib_lines
}

# Renders the CURRENT in-memory write-side state as the frozen JSON shape, to
# stdout.  `covered_checks` keys are sorted (`LC_ALL=C`) for a reproducible
# byte layout; `findings` are emitted in the order `state_add_finding` was
# called, which is the caller's own ordering to make deterministic if it
# wants byte-reproducible output (tension 17's spirit, applied here even
# though this is a fresh per-run file rather than a merged one).
_state_write_json() {
  printf '{\n'
  printf '  "fp_schema": %s,\n' "$(json_string "${_STATE_W[fp_schema]:-}")"
  printf '  "tool_version": %s,\n' "$(json_string "${_STATE_W[tool_version]:-}")"
  printf '  "run_id": %s,\n' "$(json_string "${_STATE_W[run_id]:-}")"
  printf '  "completed_at": %s,\n' "$(json_string "${_STATE_W[completed_at]:-}")"
  printf '  "scan_root_id": %s,\n' "$(json_string "${_STATE_W[scan_root_id]:-}")"

  printf '  "covered_checks": {'
  local -a ids_sorted=()
  local id
  if (( ${#_STATE_W_COVERED_IDS[@]} > 0 )); then
    while IFS= read -r id; do
      [[ -n $id ]] && ids_sorted+=("$id")
    done < <(printf '%s\n' "${_STATE_W_COVERED_IDS[@]+"${_STATE_W_COVERED_IDS[@]}"}" | LC_ALL=C sort -u)
  fi
  local first=1 cell first_cell
  for id in "${ids_sorted[@]+"${ids_sorted[@]}"}"; do
    (( first )) || printf ','
    first=0
    printf '\n    %s: {"rule_digest":%s,"scope":%s,"cells":[' \
      "$(json_string "$id")" \
      "$(json_string "${_STATE_W_COVERED_RULE_DIGEST[$id]:-}")" \
      "$(json_string "${_STATE_W_COVERED_SCOPE[$id]:-}")"
    first_cell=1
    while IFS= read -r cell; do
      [[ -n $cell ]] || continue
      (( first_cell )) || printf ','
      first_cell=0
      printf '%s' "$(json_string "$cell")"
    done <<<"${_STATE_W_COVERED_CELLS[$id]:-}"
    printf ']'
    if [[ -n ${_STATE_W_HB_TIME[$id]:-} ]]; then
      printf ',"history_boundary":{"oldest_commit":%s,"oldest_commit_time":%s,"objects_scanned":%s,"bound_by":%s}' \
        "$(json_string "${_STATE_W_HB_COMMIT[$id]:-}")" \
        "$(json_string "${_STATE_W_HB_TIME[$id]:-}")" \
        "$(json_number "${_STATE_W_HB_OBJECTS[$id]:-0}")" \
        "$(json_string "${_STATE_W_HB_BOUND[$id]:-}")"
    fi
    printf '}'
  done
  (( first )) || printf '\n  '
  printf '},\n'

  printf '  "findings": ['
  local fp first_f=1 cfirst c
  for fp in "${_STATE_W_FINDINGS[@]+"${_STATE_W_FINDINGS[@]}"}"; do
    (( first_f )) || printf ','
    first_f=0
    printf '\n    {"fingerprint":%s,"check_id":%s,"cell":' \
      "$(json_string "$fp")" "$(json_string "${_STATE_W_F_CHECK[$fp]:-}")"
    if [[ -z ${_STATE_W_F_CELL[$fp]:-} ]]; then
      printf 'null'
    else
      printf '%s' "$(json_string "${_STATE_W_F_CELL[$fp]}")"
    fi
    printf ',"severity":%s,"first_seen":%s,"last_seen":%s,"suppressed":%s' \
      "$(json_string "${_STATE_W_F_SEVERITY[$fp]:-}")" \
      "$(json_string "${_STATE_W_F_FIRST_SEEN[$fp]:-}")" \
      "$(json_string "${_STATE_W_F_LAST_SEEN[$fp]:-}")" \
      "$(json_bool "${_STATE_W_F_SUPPRESSED[$fp]:-false}")"
    if [[ -n ${_STATE_W_F_OLDEST[$fp]:-} ]]; then
      printf ',"oldest_reaching_commit_time":%s' "$(json_string "${_STATE_W_F_OLDEST[$fp]}")"
    fi
    if [[ -n ${_STATE_W_F_CONTRIB[$fp]:-} ]]; then
      printf ',"contributors":['
      cfirst=1
      while IFS= read -r c; do
        [[ -n $c ]] || continue
        (( cfirst )) || printf ','
        cfirst=0
        printf '%s' "$(json_string "$c")"
      done <<<"${_STATE_W_F_CONTRIB[$fp]}"
      printf ']'
    fi
    printf '}'
  done
  (( first_f )) || printf '\n  '
  printf ']\n'
  printf '}\n'
}

# `state_write [STATE_DIR] [RETAIN_COUNT]` - persists the current in-memory
# write-side state as `STATE_DIR/<run_id>.json`, updates `STATE_DIR/
# latest.json` to the identical bytes, and prunes.  Both files are written
# write-then-rename (the same `mv` idiom `lib/findings.sh`'s
# `findings_mark_suppressed`/`findings_write_jsonl` already use for an
# in-place update), so a reader can never observe a half-written file.
# `latest.json` is a byte copy of `<run_id>.json` made ONCE the canonical
# file is safely in place, rather than a second render of `_state_write_json`
# - rendering twice risks the two disagreeing if a future version of that
# function ever reads a live clock (`completed_at` already does not, since it
# is resolved once by `state_set_run`, but the copy is cheap and removes the
# possibility by construction).
#
# RETAIN_COUNT defaults to 30, mirroring `rules/RULE-FORMAT.md` §9.6.1's
# `state-retain-runs` default - resolving the OPERATOR's configured value is
# the caller's job (`config_scanner_value state-retain-runs`, once scan.sh
# wiring exists); this file does not source lib/config.sh.
state_write() {
  local state_dir=${1:-$(state_default_dir)} retain=${2:-30}
  local run_id=${_STATE_W[run_id]:-}
  [[ -n $run_id ]] || die "$SCOURSH_EXIT_INCOMPLETE" 'internal: state_write called before state_set_run'
  mkdir -p "$state_dir"
  local file="$state_dir/$run_id.json"
  local tmp="$state_dir/.tmp.$run_id.$$"
  _state_write_json >"$tmp"
  mv -- "$tmp" "$file"
  local latest_tmp="$state_dir/.tmp.latest.$$"
  cp -- "$file" "$latest_tmp"
  mv -- "$latest_tmp" "$state_dir/latest.json"
  state_prune "$state_dir" "$retain"
}

# `state_prune STATE_DIR [RETAIN_COUNT]` - keeps the RETAIN_COUNT
# newest `<run-id>.json` files (by `LC_ALL=C` name sort, which sorts
# correctly because a run id is the ISO-8601 timestamp `now_iso` produces
# with `:` replaced by `-`) plus `latest.json`, which is never a candidate
# for deletion.  A non-numeric RETAIN_COUNT falls back to the same default
# `state_write` uses, rather than pruning everything or nothing.
state_prune() {
  local state_dir=$1 retain=${2:-30}
  [[ -d $state_dir ]] || return 0
  [[ $retain =~ ^[0-9]+$ ]] || retain=30
  local -a files=()
  local f
  while IFS= read -r f; do
    [[ -n $f ]] && files+=("$f")
  done < <(find "$state_dir" -maxdepth 1 -type f -name '*.json' ! -name 'latest.json' 2>/dev/null | LC_ALL=C sort -r)
  local i
  for (( i = retain; i < ${#files[@]}; i++ )); do
    rm -f -- "${files[$i]}"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 3. Read side: state_load_file / state_load_latest, then query accessors
# ---------------------------------------------------------------------------
_STATE_LOAD_OK=0
_STATE_LOAD_REASON=''
declare -A _STATE=()
declare -a _STATE_C_IDS=()
declare -A _STATE_C_SEEN=()
declare -A _STATE_C_RULE_DIGEST=()
declare -A _STATE_C_SCOPE=()
declare -A _STATE_C_CELLS=()
declare -A _STATE_HB_COMMIT=()
declare -A _STATE_HB_TIME=()
declare -A _STATE_HB_OBJECTS=()
declare -A _STATE_HB_BOUND=()
declare -a _STATE_F_IDS=()
declare -A _STATE_F_CHECK=()
declare -A _STATE_F_CELL=()
declare -A _STATE_F_SEVERITY=()
declare -A _STATE_F_FIRST_SEEN=()
declare -A _STATE_F_LAST_SEEN=()
declare -A _STATE_F_SUPPRESSED=()
declare -A _STATE_F_OLDEST=()
declare -A _STATE_F_CONTRIB=()

# Index-keyed scratch used only while parsing one file (see
# `_state_parse_finding_leaf`'s own comment for why: JSON key order inside one
# finding object is not guaranteed, least of all in a hand-authored fixture,
# so a finding cannot be keyed by its own `fingerprint` field until every leaf
# of it has been seen).
_STATE_FI_COUNT=0
declare -A _STATE_FI_FINGERPRINT=()
declare -A _STATE_FI_CHECK=()
declare -A _STATE_FI_CELL=()
declare -A _STATE_FI_CELL_SEEN=()
declare -A _STATE_FI_SEVERITY=()
declare -A _STATE_FI_FIRST_SEEN=()
declare -A _STATE_FI_LAST_SEEN=()
declare -A _STATE_FI_SUPPRESSED=()
declare -A _STATE_FI_SUPPRESSED_TYPE=()
declare -A _STATE_FI_OLDEST=()
declare -A _STATE_FI_CONTRIB=()

_state_clear_data() {
  _STATE=()
  _STATE_C_IDS=()
  _STATE_C_SEEN=()
  _STATE_C_RULE_DIGEST=()
  _STATE_C_SCOPE=()
  _STATE_C_CELLS=()
  _STATE_HB_COMMIT=()
  _STATE_HB_TIME=()
  _STATE_HB_OBJECTS=()
  _STATE_HB_BOUND=()
  _STATE_F_IDS=()
  _STATE_F_CHECK=()
  _STATE_F_CELL=()
  _STATE_F_SEVERITY=()
  _STATE_F_FIRST_SEEN=()
  _STATE_F_LAST_SEEN=()
  _STATE_F_SUPPRESSED=()
  _STATE_F_OLDEST=()
  _STATE_F_CONTRIB=()
  _STATE_FI_COUNT=0
  _STATE_FI_FINGERPRINT=()
  _STATE_FI_CHECK=()
  _STATE_FI_CELL=()
  _STATE_FI_CELL_SEEN=()
  _STATE_FI_SEVERITY=()
  _STATE_FI_FIRST_SEEN=()
  _STATE_FI_LAST_SEEN=()
  _STATE_FI_SUPPRESSED=()
  _STATE_FI_SUPPRESSED_TYPE=()
  _STATE_FI_OLDEST=()
  _STATE_FI_CONTRIB=()
}

state_load_reset() {
  _STATE_LOAD_OK=0
  _STATE_LOAD_REASON=''
  _state_clear_data
}

# True once a `state_load_*` call found a usable prior state.  Every caller
# checks this before reading anything else below - the accessors return the
# empty string for an unloaded or failed load rather than erroring, but that
# is not the same as "there was no prior state", which is what this predicate
# answers.
state_loaded() { (( _STATE_LOAD_OK )); }

# Why the load did not produce usable state: "no prior state" (file missing
# or unreadable - the ordinary first-run case) or an explicit reason a
# malformed record was rejected.  Meaningless (empty) once `state_loaded`.
state_load_reason() { printf '%s' "$_STATE_LOAD_REASON"; }

_state_parse_covered_leaf() {
  local type=$1 val=$2 check_id=$3 field=$4 sub=${5:-}
  [[ -n $check_id ]] || return 0
  if [[ -z ${_STATE_C_SEEN[$check_id]:-} ]]; then
    _STATE_C_SEEN[$check_id]=1
    _STATE_C_IDS+=("$check_id")
  fi
  [[ $type == s ]] && val=$(_state_json_unescape "$val")
  case $field in
    rule_digest) _STATE_C_RULE_DIGEST[$check_id]=$val ;;
    scope) _STATE_C_SCOPE[$check_id]=$val ;;
    cells)
      local existing=${_STATE_C_CELLS[$check_id]:-}
      _STATE_C_CELLS[$check_id]="${existing:+$existing$'\n'}$val"
      ;;
    history_boundary)
      case $sub in
        oldest_commit) _STATE_HB_COMMIT[$check_id]=$val ;;
        oldest_commit_time) _STATE_HB_TIME[$check_id]=$val ;;
        objects_scanned) _STATE_HB_OBJECTS[$check_id]=$val ;;
        bound_by) _STATE_HB_BOUND[$check_id]=$val ;;
        *) ;;
      esac
      ;;
    *) ;;
  esac
}

# A finding is index-keyed while parsing (see the section-3 comment above)
# because JSON object-key order is not something this reader may assume,
# least of all from a hand-authored fixture: the writer above always emits
# `fingerprint` first, but the loader must not depend on that.
_state_parse_finding_leaf() {
  local type=$1 val=$2 idx=$3 field=$4
  [[ $idx =~ ^[0-9]+$ ]] || return 0
  (( idx + 1 > _STATE_FI_COUNT )) && _STATE_FI_COUNT=$(( idx + 1 ))
  [[ $type == s ]] && val=$(_state_json_unescape "$val")
  case $field in
    fingerprint) _STATE_FI_FINGERPRINT[$idx]=$val ;;
    check_id) _STATE_FI_CHECK[$idx]=$val ;;
    cell)
      _STATE_FI_CELL_SEEN[$idx]=1
      [[ $type == z ]] && val=''
      _STATE_FI_CELL[$idx]=$val
      ;;
    severity) _STATE_FI_SEVERITY[$idx]=$val ;;
    first_seen) _STATE_FI_FIRST_SEEN[$idx]=$val ;;
    last_seen) _STATE_FI_LAST_SEEN[$idx]=$val ;;
    suppressed)
      _STATE_FI_SUPPRESSED[$idx]=$val
      _STATE_FI_SUPPRESSED_TYPE[$idx]=$type
      ;;
    oldest_reaching_commit_time) _STATE_FI_OLDEST[$idx]=$val ;;
    contributors)
      local existing=${_STATE_FI_CONTRIB[$idx]:-}
      _STATE_FI_CONTRIB[$idx]="${existing:+$existing$'\n'}$val"
      ;;
    *) ;;
  esac
}

_state_parse_flat() {
  local flat=$1 path type val
  local -a parts
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    IFS=$'\x1f' read -r -a parts <<<"$path"
    case ${parts[0]} in
      fp_schema | tool_version | run_id | completed_at | scan_root_id)
        (( ${#parts[@]} == 1 )) || continue
        [[ $type == s ]] && val=$(_state_json_unescape "$val")
        _STATE[${parts[0]}]=$val
        ;;
      covered_checks)
        _state_parse_covered_leaf "$type" "$val" "${parts[@]:1}"
        ;;
      findings)
        _state_parse_finding_leaf "$type" "$val" "${parts[@]:1}"
        ;;
      *) ;;
    esac
  done <"$flat"
}

# Converts the index-keyed finding scratch into the fingerprint-keyed public
# view, and is where "a finding entry has no fingerprint" is caught - that
# scratch is otherwise silently discarded, so this is the one place that can
# still see it.  Returns 1 (with `_STATE_LOAD_REASON` set) on the first
# entry missing one.
_state_finalize_findings() {
  local i fp
  for (( i = 0; i < _STATE_FI_COUNT; i++ )); do
    fp=${_STATE_FI_FINGERPRINT[$i]:-}
    if [[ -z $fp ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] has no fingerprint"
      return 1
    fi
    if [[ -n ${_STATE_F_CHECK[$fp]+set} ]]; then
      _STATE_LOAD_REASON="unparsable state file: duplicate fingerprint '$fp' in findings"
      return 1
    fi
    _STATE_F_IDS+=("$fp")
    _STATE_F_CHECK[$fp]=${_STATE_FI_CHECK[$i]:-}
    _STATE_F_CELL[$fp]=${_STATE_FI_CELL[$i]:-}
    _STATE_F_SEVERITY[$fp]=${_STATE_FI_SEVERITY[$i]:-}
    _STATE_F_FIRST_SEEN[$fp]=${_STATE_FI_FIRST_SEEN[$i]:-}
    _STATE_F_LAST_SEEN[$fp]=${_STATE_FI_LAST_SEEN[$i]:-}
    _STATE_F_SUPPRESSED[$fp]=${_STATE_FI_SUPPRESSED[$i]:-false}
    _STATE_F_OLDEST[$fp]=${_STATE_FI_OLDEST[$i]:-}
    _STATE_F_CONTRIB[$fp]=${_STATE_FI_CONTRIB[$i]:-}
    if [[ -z ${_STATE_FI_CHECK[$i]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) missing check_id"
      return 1
    fi
    if [[ -z ${_STATE_FI_CELL_SEEN[$i]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) missing cell"
      return 1
    fi
    if [[ -z ${_STATE_FI_SEVERITY[$i]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) missing severity"
      return 1
    fi
    if [[ -z ${_STATE_FI_FIRST_SEEN[$i]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) missing first_seen"
      return 1
    fi
    if [[ -z ${_STATE_FI_LAST_SEEN[$i]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) missing last_seen"
      return 1
    fi
    if [[ ${_STATE_FI_SUPPRESSED_TYPE[$i]:-} != b ]]; then
      _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) has a non-boolean suppressed"
      return 1
    fi
    case ${_STATE_FI_SUPPRESSED[$i]:-} in
      true | false) ;;
      *)
        _STATE_LOAD_REASON="unparsable state file: findings[$i] ($fp) has an invalid suppressed value"
        return 1
        ;;
    esac
  done
  return 0
}

# Structural validation over already-parsed data.  This is schema
# conformance to tension 12's frozen shape, never a classification decision:
# it answers "is this a well-formed state/ record", not "what does it mean".
_state_validate() {
  local k
  for k in fp_schema tool_version run_id completed_at scan_root_id; do
    if [[ -z ${_STATE[$k]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: missing or empty top-level field '$k'"
      return 1
    fi
  done

  local id
  for id in "${_STATE_C_IDS[@]+"${_STATE_C_IDS[@]}"}"; do
    if [[ -z ${_STATE_C_RULE_DIGEST[$id]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: covered_checks.$id missing rule_digest"
      return 1
    fi
    if [[ -z ${_STATE_C_SCOPE[$id]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: covered_checks.$id missing scope"
      return 1
    fi
    if ! _state_valid_scope "${_STATE_C_SCOPE[$id]}"; then
      _STATE_LOAD_REASON="unparsable state file: covered_checks.$id has an invalid scope '${_STATE_C_SCOPE[$id]}'"
      return 1
    fi
    if [[ -z ${_STATE_C_CELLS[$id]:-} ]]; then
      _STATE_LOAD_REASON="unparsable state file: covered_checks.$id has no cells"
      return 1
    fi
  done

  _state_finalize_findings
}

# `state_load_file FILE` - the loader.  A missing or unreadable FILE, and a
# syntactically or structurally malformed one, are both reported through
# `state_loaded`/`state_load_reason` rather than `die`: tension 12's own
# instruction is that a first run (no prior state at all) is the ordinary
# case, not an error, and STATE-01's own acceptance criterion is that a
# malformed record is REJECTED rather than half-loaded - so on ANY failure
# the data arrays are cleared back to empty before returning, and nothing
# partially parsed is ever visible through the accessors below.
state_load_file() {
  local file=$1
  state_load_reset
  if [[ ! -r $file ]]; then
    _STATE_LOAD_REASON="no prior state: $file not found or unreadable"
    return 0
  fi
  local flat=$SCOURSH_SCRATCH/state-load.$$.flat
  local err=$SCOURSH_SCRATCH/state-load.$$.err
  if ! _state_json_flatten <"$file" >"$flat" 2>"$err"; then
    local first_err=''
    [[ -r $err ]] && IFS= read -r first_err <"$err"
    first_err=${first_err#__JSON_ERROR__$'\t'}
    rm -f -- "$flat" "$err"
    _STATE_LOAD_REASON="unparsable state file $file: ${first_err:-invalid JSON}"
    return 0
  fi
  rm -f -- "$err"
  _state_parse_flat "$flat"
  rm -f -- "$flat"
  if ! _state_validate; then
    local reason=$_STATE_LOAD_REASON
    _state_clear_data
    _STATE_LOAD_REASON=$reason
    return 0
  fi
  _STATE_LOAD_OK=1
  return 0
}

# `state_load_latest [STATE_DIR]` - reads `STATE_DIR/latest.json`
# (default `state_default_dir`).  An absent `state/` directory or an absent
# `latest.json` inside it is the ordinary "no prior state" case, handled
# identically to any other unreadable file by `state_load_file`.
state_load_latest() {
  local state_dir=${1:-$(state_default_dir)}
  state_load_file "$state_dir/latest.json"
}

# ---------------------------------------------------------------------------
# 4. Query accessors over a successfully loaded state
# ---------------------------------------------------------------------------
# `state_field KEY` - one of fp_schema, tool_version, run_id, completed_at,
# scan_root_id.  STATE-03's two guards (tension 12) read `fp_schema` and
# `scan_root_id` from here.
state_field() { printf '%s' "${_STATE[$1]:-}"; }

state_covered_check_ids() { printf '%s\n' "${_STATE_C_IDS[@]+"${_STATE_C_IDS[@]}"}"; }
state_covered_rule_digest() { printf '%s' "${_STATE_C_RULE_DIGEST[$1]:-}"; }
state_covered_scope() { printf '%s' "${_STATE_C_SCOPE[$1]:-}"; }

# One cell per line; empty output (status 0) for a check id that was never
# covered - never distinguished by exit status, since "not covered" is data,
# not an error, in every caller this exists for.
state_covered_cells() {
  local existing=${_STATE_C_CELLS[$1]:-}
  [[ -n $existing ]] && printf '%s\n' "$existing"
  return 0
}

state_covered_has_cell() {
  local id=$1 cell=$2
  local existing=${_STATE_C_CELLS[$id]:-}
  [[ $'\n'"$existing"$'\n' == *$'\n'"$cell"$'\n'* ]]
}

state_history_boundary_field() {
  local id=$1 field=$2
  case $field in
    oldest_commit) printf '%s' "${_STATE_HB_COMMIT[$id]:-}" ;;
    oldest_commit_time) printf '%s' "${_STATE_HB_TIME[$id]:-}" ;;
    objects_scanned) printf '%s' "${_STATE_HB_OBJECTS[$id]:-}" ;;
    bound_by) printf '%s' "${_STATE_HB_BOUND[$id]:-}" ;;
    *) return 1 ;;
  esac
}

state_finding_fingerprints() { printf '%s\n' "${_STATE_F_IDS[@]+"${_STATE_F_IDS[@]}"}"; }

# `state_finding_field FINGERPRINT FIELD` - FIELD is one of check_id, cell
# (empty for a derived finding's JSON null), severity, first_seen, last_seen,
# suppressed (the literal `true`/`false`), oldest_reaching_commit_time
# (empty unless this is a SAST-HIST-* finding), or contributors (one
# fingerprint per line, empty unless this is a derived finding).
state_finding_field() {
  local fp=$1 field=$2
  case $field in
    check_id) printf '%s' "${_STATE_F_CHECK[$fp]:-}" ;;
    cell) printf '%s' "${_STATE_F_CELL[$fp]:-}" ;;
    severity) printf '%s' "${_STATE_F_SEVERITY[$fp]:-}" ;;
    first_seen) printf '%s' "${_STATE_F_FIRST_SEEN[$fp]:-}" ;;
    last_seen) printf '%s' "${_STATE_F_LAST_SEEN[$fp]:-}" ;;
    suppressed) printf '%s' "${_STATE_F_SUPPRESSED[$fp]:-false}" ;;
    oldest_reaching_commit_time) printf '%s' "${_STATE_F_OLDEST[$fp]:-}" ;;
    contributors)
      local existing=${_STATE_F_CONTRIB[$fp]:-}
      [[ -n $existing ]] && printf '%s\n' "$existing"
      return 0
      ;;
    *) return 1 ;;
  esac
}
