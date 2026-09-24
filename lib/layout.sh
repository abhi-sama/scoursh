#!/usr/bin/env bash
# lib/layout.sh - resolved writable locations for checkout and installed copies.
#
# This is sourced by lib/core.sh after it defines the exit constants and die().
# Keeping the resolver in its own small library prevents each -x caller of the
# core hub from re-expanding its implementation; this file is linted directly.
# shellcheck shell=bash

_SCOURSH_LAYOUT_ROOT=''
_SCOURSH_LAYOUT_MODE=''

scoursh_layout_resolve() {
  local root=${SCOURSH_INSTALL_ROOT:?scoursh_layout_resolve: SCOURSH_INSTALL_ROOT is not set}
  if [[ $_SCOURSH_LAYOUT_ROOT == "$root" ]]; then
    return 0
  fi

  if [[ -n ${SCOURSH_HOME:-} ]]; then
    SCOURSH_CONF_DIR=$SCOURSH_HOME/config
    SCOURSH_DATA_DIR=$SCOURSH_HOME/data
    SCOURSH_STATE_DIR=$SCOURSH_HOME/state
    SCOURSH_REPORTS_DIR=$SCOURSH_HOME/reports
    _SCOURSH_LAYOUT_MODE=home
  elif [[ -f $root/.scoursh-packaged ]]; then
    local home=${HOME:-}
    [[ -n $home ]] || die "$SCOURSH_EXIT_INPUT" \
      'HOME is required to resolve an installed scoursh layout; set SCOURSH_HOME for a single-root layout'
    SCOURSH_CONF_DIR=${XDG_CONFIG_HOME:-$home/.config}/scoursh
    SCOURSH_DATA_DIR=${XDG_DATA_HOME:-$home/.local/share}/scoursh
    SCOURSH_STATE_DIR=${XDG_STATE_HOME:-$home/.local/state}/scoursh/state
    SCOURSH_REPORTS_DIR=${XDG_STATE_HOME:-$home/.local/state}/scoursh/reports
    _SCOURSH_LAYOUT_MODE=installed
  else
    SCOURSH_CONF_DIR=$root/config
    SCOURSH_DATA_DIR=$root/data
    SCOURSH_STATE_DIR=$root/state
    SCOURSH_REPORTS_DIR=$root/reports
    _SCOURSH_LAYOUT_MODE=clone
  fi
  _SCOURSH_LAYOUT_ROOT=$root
  export SCOURSH_CONF_DIR SCOURSH_DATA_DIR SCOURSH_STATE_DIR SCOURSH_REPORTS_DIR
}

# `scoursh_data_file NAME` prefers generated user data and falls back to the
# package copy, which lets a read-only release carry an optional seed database.
scoursh_data_file() {
  local name=$1 candidate fallback
  scoursh_layout_resolve
  candidate=$SCOURSH_DATA_DIR/$name
  fallback=$SCOURSH_INSTALL_ROOT/data/$name
  if [[ -r $candidate ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' "$fallback"
  fi
}

# Optional adapter code stays under the install root.  Its generated assets
# prefer user data in installed/SCOURSH_HOME mode, then fall back to code-adjacent
# checkout assets.  WRITER_FALLBACK keeps a copied vendor.sh testable while the
# ordinary checkout writer and reader still resolve the same adapter directory.
scoursh_engine_dir() {
  local module=$1 engine=$2 candidate fallback
  scoursh_layout_resolve
  candidate=$SCOURSH_DATA_DIR/engines/$module/$engine
  fallback=$SCOURSH_INSTALL_ROOT/modules/$module/adapters/$engine
  if [[ $_SCOURSH_LAYOUT_MODE == installed || $_SCOURSH_LAYOUT_MODE == home ]]; then
    [[ -d $candidate ]] && { printf '%s' "$candidate"; return 0; }
  fi
  printf '%s' "$fallback"
}

scoursh_engine_dir_for_write() {
  local module=$1 engine=$2 writer_fallback=${3:-}
  scoursh_layout_resolve
  if [[ $_SCOURSH_LAYOUT_MODE == installed || $_SCOURSH_LAYOUT_MODE == home ]]; then
    printf '%s' "$SCOURSH_DATA_DIR/engines/$module/$engine"
  elif [[ -n $writer_fallback ]]; then
    printf '%s' "$writer_fallback"
  else
    printf '%s' "$SCOURSH_INSTALL_ROOT/modules/$module/adapters/$engine"
  fi
}
