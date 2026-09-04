#!/usr/bin/env bash
# lib/guide_scope.sh - the config/scope.conf record writer for guided mode
# (docs/STEP-GUIDE-PLAN.md GUIDE-05, step G4): "the most dangerous thing in
# this design - it deserves the most adversarial review of anything here."
# This is the single path by which typed operator input becomes a persisted
# authorisation to send DAST traffic at a host.
#
# Owns:
#   docs/STEP-GUIDE-PLAN.md   GUIDE-05's own row, step G4 ("authorising a
#                             new target").  Not G3 (the target menu that
#                             offers "Authorise a new target" - GUIDE-04's
#                             job) and not the interactive prompt/confirm
#                             screen itself, which lives in lib/guide.sh's
#                             `guide_g4_authorize_target` (tests/lint-shell.sh
#                             confines every `guide_*`/`_guide_*` PRIMITIVE
#                             call to lib/guide.sh and scan.sh - this file
#                             calls neither `guide_ask` nor `guide_confirm`
#                             nor `guide_menu`, on purpose, so it needs no
#                             exemption from that check).
#
# THIS FILE IS PURE PLUMBING: id derivation, record-text rendering, the
# deny-list check reused from lib/http.sh, and the validate-in-a-temp-file-
# then-rename writer.  No terminal I/O, no `guide_*` call, testable with a
# plain scratch directory and no pty.
#
# TWO ABSOLUTE RULES, both from the plan's own G4 section, and both
# structural here rather than left to a caller's discipline:
#
# 1. FROZEN RECORD FORMAT, NEVER SOURCED (docs/FOUNDATION.md tension 26).
#    Every value this file writes is a plain `key: value`/continuation-line
#    byte sequence per rules/RULE-FORMAT.md; nothing here ever emits a
#    variable-expansion or include syntax a future loader could be tempted to
#    evaluate.  `guide_scope_append` (section 4) never composes the record
#    text itself - it validates whatever text it is given through the SAME
#    `records_load`/`records_validate` pair every other config loader in this
#    project uses (lib/checks.sh's registry loader, lib/config.sh's
#    `config_load_or_die`), so a malformed or hostile record is refused by
#    the frozen parser, not by a second, ad-hoc check invented here.
#
# 2. THE WRITER NEVER EMITS A VALUE IT DID NOT RECEIVE VERBATIM FROM THE
#    OPERATOR.  `guide_scope_record_text`'s `base-url` argument is written
#    byte-for-byte; this file never substitutes a normalised form, a
#    resolved address, or anything "helpful" into that field.  The one place
#    this matters most is docs/STEP-GUIDE-PLAN.md's fourth G4 correction:
#    `allow-private-addresses: true` is only ever appropriate alongside an
#    IP-literal `base-url` (never a hostname, since a private DNS answer can
#    change after the record is written - see `guide_scope_addr_denied`'s own
#    header), and the caller (lib/guide.sh) is the one that decides whether
#    to OFFER retyping a resolved-private hostname as a literal; this file
#    never invents that substitution on its own.
#
# THE ID DERIVATION (docs/STEP-GUIDE-PLAN.md GUIDE-05 row): lowercase,
# dots and colons to dashes, a `t-` prefix when the transform would not
# start with a letter, `-2` (then `-3`, ...) on collision with an id already
# in the file - so the SAME normalised (host, port) always derives the SAME
# id, and a later coincidental collision (two different hosts whose dots and
# colons transform to the same string) is disambiguated automatically rather
# than refused.  The source is the NORMALISED host:port
# (`http_url_normalize`'s own `_HN_HOST`/`_HN_PORT`), not the raw typed
# bytes, so two different spellings of the same URL (case, a trailing dot, an
# octal IPv4 literal) derive the same id - matching what "the same URL"
# means once the tool has parsed it.  The `^[a-z][a-z0-9-]*$` schema shape
# (rules/RULE-FORMAT.md §9.4) is enforced downstream by `records_validate`
# regardless of what this file produces, so an exotic host character this
# transform does not anticipate is a hard refusal at write time, never a
# silently-invalid id on disk.
#
# THE APPEND-ONLY GUARANTEE (`guide_scope_append`, section 4) is enforced by
# `records_load`'s own duplicate-id detection (E019) on the composed file,
# not by a second, separately-maintained uniqueness check: the id
# disambiguation above keeps that refusal from firing in ordinary use, but
# if it ever does - a race with a concurrent hand edit, or a caller that
# skips the disambiguation step - the write is refused (exit 4) and the
# original file is left untouched, exactly as for any other schema error.
# A suite case in tests/suites/guide-scope.sh drives this path directly,
# bypassing the disambiguation layer, to prove the refusal is real.
#
# THE config/scope.conf .gitignore DECISION (docs/STEP-GUIDE-PLAN.md GUIDE-05
# row: "this ticket also owns an explicit decision, not a default"):
# config/scope.conf stays OUT of .gitignore, unchanged from before this
# ticket.  A guided write is byte-identical in effect to a hand edit (the
# whole point of the "validate-in-a-temp-file-then-rename, identical to a
# hand-edited file" requirement below), and docs/STEP-GUIDE-PLAN.md's own G4
# text frames the non-interactive equivalent of this screen as "editing
# config/scope.conf - the same act with the same reviewability" - ignoring
# the file would sever that story and make a guided authorisation strictly
# less durable than a hand-typed one.  The cost (an operator's internal
# hostnames can appear in `git status`/`git diff` for a checkout that tracks
# this file) is accepted and stated here, in the same place a reader of this
# file's header would look for it, rather than solved by making the guided
# path behave differently from a hand edit.
#
# shellcheck shell=bash
#
# SC2329: every function in this file is public API, called only from
# lib/guide.sh's `guide_g4_authorize_target` and from
# tests/suites/guide-scope.sh - neither of which shellcheck's per-file `-x`
# check sees when THIS file is the analysis target (tests/run-tests.sh's
# shellcheck stage checks every lib/*.sh file standalone, not only as part of
# a larger entry point's graph).
# SC2034: GUIDE_SCOPE_SCHEME/HOST/PORT/IS_LITERAL/RESOLVED are the SET-A-
# VARIABLE output of guide_scope_parse/guide_scope_resolve (the same
# guide_menu/guide_ask idiom lib/guide.sh's own header documents - a `die`
# inside a `$(...)` command substitution only kills the subshell), read only
# by lib/guide.sh and by the test suite named above.
# shellcheck disable=SC2329,SC2034

if [[ -n ${SCOURSH_GUIDE_SCOPE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_GUIDE_SCOPE_SOURCED=1

# shellcheck source=lib/http.sh
source "${BASH_SOURCE[0]%/*}/http.sh"

# ---------------------------------------------------------------------------
# 1. Parsing and resolution, wrapped so a caller never reads lib/http.sh's
#    own `_HN_*` globals directly - this file's own public surface is the
#    only thing lib/guide.sh's interactive screen needs to know about.
# ---------------------------------------------------------------------------

GUIDE_SCOPE_SCHEME='' GUIDE_SCOPE_HOST='' GUIDE_SCOPE_PORT='' GUIDE_SCOPE_IS_LITERAL=false
# `guide_scope_parse RAW` - wraps `http_url_normalize`.  Returns 1 for
# anything that is not a well-formed absolute http(s) URL; the globals are
# then unreliable, exactly as `http_url_normalize` itself documents.
guide_scope_parse() {
  local raw=$1
  GUIDE_SCOPE_SCHEME='' GUIDE_SCOPE_HOST='' GUIDE_SCOPE_PORT='' GUIDE_SCOPE_IS_LITERAL=false
  http_url_normalize "$raw" || return 1
  GUIDE_SCOPE_SCHEME=$_HN_SCHEME
  GUIDE_SCOPE_HOST=$_HN_HOST
  GUIDE_SCOPE_PORT=$_HN_PORT
  GUIDE_SCOPE_IS_LITERAL=$_HN_IS_LITERAL
  return 0
}

GUIDE_SCOPE_RESOLVED=''
# `guide_scope_resolve HOST` - wraps `http_resolve_host`.  Never call this
# for a literal host (`GUIDE_SCOPE_IS_LITERAL == true`): the literal bytes
# already ARE the address, per `http_gate_url`'s own `[[ $is_literal == true
# ]] && addr=$host` reasoning, and a lookup on a literal is at best redundant
# and at worst a way for an operator's own resolver to answer something
# different from the bytes about to be written.
guide_scope_resolve() {
  GUIDE_SCOPE_RESOLVED=''
  local addr
  addr=$(http_resolve_host "$1") || return 1
  GUIDE_SCOPE_RESOLVED=$addr
  return 0
}

# `guide_scope_addr_denied ADDR` - is ADDR inside lib/http.sh's own
# resolution-pinning deny list (loopback/link-local/CGNAT/0.0.0.0/8, and the
# IPv6 equivalents)?  Reused verbatim from `http_gate_url`'s own dispatch
# (`_http_ipv4_denied`/`_http_ipv6_denied`) rather than re-derived, so this
# file's private/public judgement can never drift from the gate's.
guide_scope_addr_denied() {
  local addr=$1
  if [[ $addr == *:* ]]; then
    _http_ipv6_denied "$addr"
  else
    _http_ipv4_denied "$addr"
  fi
}

# ---------------------------------------------------------------------------
# 2. The deterministic id derivation
# ---------------------------------------------------------------------------

# `guide_scope_id_base HOST PORT` - the pure transform: lowercase, every `.`
# and `:` to `-`, and a `t-` prefix if the result would not start with a
# letter (an IP-literal host, or an IPv6 literal whose colons front-load
# dashes).  No uniqueness check here - see `guide_scope_unique_id`.
guide_scope_id_base() {
  local host=${1,,} port=$2
  local src="${host}:${port}" out='' i ch
  for (( i = 0; i < ${#src}; i++ )); do
    ch=${src:i:1}
    case $ch in
      .|:) out+='-' ;;
      *) out+=$ch ;;
    esac
  done
  [[ $out =~ ^[a-z] ]] || out="t-$out"
  printf '%s' "$out"
}

# `guide_scope_unique_id BASE [SCOPE_PATH]` - BASE, or BASE-2, BASE-3, ...
# until an id is found that does not already appear in SCOPE_PATH.  An
# absent SCOPE_PATH is zero existing ids (`config_scope_load`'s own
# optional-file contract); a PRESENT-but-malformed one dies loudly through
# that same call, exactly as any other consumer of it does - a guided write
# must never build a preview against a scope.conf it cannot actually trust.
guide_scope_unique_id() {
  local base=$1 scope_path=${2:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  records_clear scope
  config_scope_load "$scope_path" || true
  local candidate=$base n=1
  while records_index_of_id scope "$candidate" >/dev/null 2>&1; do
    n=$(( n + 1 ))
    candidate="${base}-${n}"
  done
  printf '%s' "$candidate"
}

# ---------------------------------------------------------------------------
# 3. Record-text rendering - the SAME text is shown in the preview and
#    written to disk (lib/guide.sh's screen never renders a second copy), so
#    the preview cannot drift from what gets written.
# ---------------------------------------------------------------------------

# `guide_scope_notes_text` - the dated `notes:` line's content (unwrapped,
# LF-separated; `guide_scope_record_text` below applies the two-space
# continuation prefix rules/RULE-FORMAT.md §6 requires).
guide_scope_notes_text() {
  printf 'Authorised interactively via scan.sh --guided on %s.\nConfirmed at the prompt after the normalised target and its resolved\naddress were shown.' "$(now_iso)"
}

# `guide_scope_record_text ID BASE_URL ALLOW_PRIVATE NOTES` - renders one
# rules/RULE-FORMAT.md §9.4 record, no trailing newline.  BASE_URL is written
# EXACTLY as given (see this file's header, rule 2); ALLOW_PRIVATE is the
# literal string `true` or `false` the caller already decided.
# `allow-subdomains` is always `false` - there is no parameter for it, per
# the plan's own third G4 correction (`http_scope_match` implements
# subdomains as an unbounded suffix test, and widening that is a gate edit,
# not a guided-mode option).
guide_scope_record_text() {
  local id=$1 base_url=$2 allow_private=$3 notes=$4
  local out="id: $id"
  out+=$'\n'"base-url: $base_url"
  out+=$'\n'"allow-subdomains: false"
  out+=$'\n'"allow-private-addresses: $allow_private"
  local first=true line
  while IFS= read -r line; do
    if [[ $first == true ]]; then
      out+=$'\n'"notes: $line"
      first=false
    else
      out+=$'\n'"  $line"
    fi
  done <<<"$notes"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 4. The write itself: copy, append, validate on the TEMP file, rename -
#    never validate-then-append, which would leave a window where a crash
#    between the two steps could deliver an unvalidated file.
# ---------------------------------------------------------------------------

# `guide_scope_append RECORD_TEXT [SCOPE_PATH]` - the append-only primitive.
# RECORD_TEXT is exactly one rendered record (`guide_scope_record_text`'s
# output), no trailing newline.  Copies the existing SCOPE_PATH (if any) to a
# temp file IN THE SAME DIRECTORY (so the final `mv` is a real rename, not a
# cross-filesystem copy), appends a blank-line separator and the record,
# loads and schema-validates the TEMP file, and only then replaces the
# original.  A parse or validation failure leaves the original untouched,
# prints the rules/RULE-FORMAT.md file:line:col diagnostics (via
# `records_load`/`records_validate`'s own `records_diag`), and dies exit 4 -
# `docs/STEP-GUIDE-PLAN.md`'s own "a malformed config/scope.conf makes
# config_load_or_die exit 4 on every future DAST run, so the guided mode must
# not be able to brick the operator's config."
#
# The append-only guarantee itself needs no separate check here: two
# consecutive blank lines are equivalent to one (rules/RULE-FORMAT.md §4),
# so `printf '\n\n'` is a correct separator whether or not the existing file
# already ended in a newline, and a duplicate id in the composed file is
# refused by `records_load`'s own E019 check before this function ever
# reaches `mv`.
guide_scope_append() {
  local record=$1 scope_path=${2:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  local dir
  dir=$(dirname -- "$scope_path")
  [[ -d $dir ]] || die "$SCOURSH_EXIT_INPUT" "cannot write '$scope_path': directory '$dir' does not exist"

  local tmp
  tmp=$(mktemp "$dir/.scope.conf.XXXXXX") \
    || die "$SCOURSH_EXIT_INCOMPLETE" "could not create a temporary file under '$dir'"

  if [[ -e $scope_path ]]; then
    cp -p -- "$scope_path" "$tmp" \
      || { rm -f "$tmp"; die "$SCOURSH_EXIT_INCOMPLETE" "could not copy '$scope_path' to a temporary file"; }
  else
    chmod 644 "$tmp" 2>/dev/null || true
  fi

  if [[ -s $tmp ]]; then
    printf '\n\n' >>"$tmp"
  fi
  printf '%s\n' "$record" >>"$tmp"

  local set=guide_scope_write_check
  records_clear "$set"
  if ! records_load "$tmp" scope-target "$set"; then
    rm -f "$tmp"
    die "$SCOURSH_EXIT_INPUT" "the composed $scope_path would fail to parse (rules/RULE-FORMAT.md diagnostics above); nothing was written"
  fi
  if ! records_validate "$set"; then
    records_clear "$set"
    rm -f "$tmp"
    die "$SCOURSH_EXIT_INPUT" "the composed $scope_path would fail schema validation (diagnostics above); nothing was written"
  fi
  records_clear "$set"

  mv -f -- "$tmp" "$scope_path" \
    || die "$SCOURSH_EXIT_INCOMPLETE" "could not replace '$scope_path'"
  return 0
}
