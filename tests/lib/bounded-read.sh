#!/usr/bin/env bash
# tests/lib/bounded-read.sh - prove a response body is read with a BOUND at
# read time, without letting a wall clock decide the outcome.
#
# THE PROBLEM THIS EXISTS FOR.  Several engines here read a response body with
# `read -N <cap>` rather than the un-bounded `read -d ''` they used to use, so
# a hostile or merely enormous body is never slurped whole.  The obvious
# assertion - "the variable holds exactly <cap> bytes" - passes under BOTH
# implementations, because the pre-fix code slurped everything and then
# trimmed.  What actually distinguishes them is whether the whole body was
# ever READ, and four suites reached for elapsed time as a proxy for that:
#
#     assert_true "$([[ $ms -lt 800 ]] && ...)"
#
# 800ms was calibrated on a contributor's Mac.  On `macos-latest` one of these
# measured 801ms and failed a whole CI job by one millisecond; on
# `ubuntu-latest` three of them measured 1593ms, 1220ms and 1215ms with every
# implementation correct.  A ceiling that fails a slow machine for being slow
# is testing the machine.
#
# THE PATTERN THIS USES IS THE ONE PR #107 ESTABLISHED FOR THE CIRCUIT-BREAKER
# CASE: replace the elapsed-time assumption with a structural signal, so that
# no duration anywhere decides the verdict.  There the signal was a rendezvous
# on a FIFO; here it is the PRODUCER'S OWN PROGRESS.
#
# The body is delivered through a FIFO instead of being `cp`'d into place, by
# a producer that holds the write end open across a completion marker:
#
#   * a BOUNDED reader takes <cap> bytes and closes.  The producer is left
#     blocked mid-write on a full pipe, and its marker is NEVER written.
#   * an UN-BOUNDED reader drains the pipe to EOF.  EOF can only happen after
#     the producer closed fd 3, which happens after the marker is written - so
#     on the reading this assertion exists to reject, the marker is ALWAYS
#     present by the time the read returns.
#
# That ordering is the whole design: the race that remains is in the harmless
# direction only.  There is no sleep, no poll and no threshold.
#
# shellcheck shell=bash

# bounded_read_serve_fifo PATH SOURCE MARKER
#
# Replace PATH (a file the caller's transport stub was handed) with a FIFO and
# start a producer streaming SOURCE into it.  Records the producer's pid in
# _BR_PRODUCER_PID so the caller can reap it.  Returns immediately; the
# producer blocks until something opens the read end.
bounded_read_serve_fifo() {
  local path=$1 src=$2 marker=$3
  rm -f -- "$path" "$marker"
  mkfifo -- "$path"
  # fd 3 is held open ACROSS the marker write.  Do not "simplify" this to
  # `dd ... >"$path"; printf done >"$marker"`: dd would close the write end
  # when it exits, so a reader could reach EOF and be inspected before the
  # marker existed, and an un-bounded read would then look bounded - the one
  # direction this must never fail in.
  #
  # `>/dev/null 2>&1 </dev/null` IS LOAD-BEARING, NOT TIDINESS.  The caller is
  # a transport stub, and lib/http.sh runs the transport inside a command
  # SUBSTITUTION to read its status line.  A background child inherits that
  # pipe's write end, and `$(...)` does not return until EVERY holder of that
  # end has closed it - so a producer that keeps the inherited stdout open
  # deadlocks `http_request` itself: it waits for the producer, which is
  # waiting for a reader that only runs after `http_request` returns.
  # Measured: both suites hung indefinitely at exactly this point before the
  # redirections were added.
  (
    exec 3>"$path"
    # `&&` IS THE ASSERTION.  The marker must record that the producer DRAINED
    # the source, and a bounded reader closes the pipe under it, so `dd` dies
    # of SIGPIPE (status 141) or fails with EPIPE.  Written as two statements,
    # the marker is created ANYWAY the moment dd dies - measured: the bounded
    # reading reported the marker PRESENT, i.e. the assertion passed under the
    # implementation it exists to reject, which is the one direction that must
    # never happen.
    dd if="$src" bs=65536 >&3 2>/dev/null && printf 'done' >"$marker"
    exec 3>&-
    # SERVE EVERY LATER OPENER AN IMMEDIATE EOF.  A FIFO is consumed once, and
    # an engine may read its body sink more than once:
    # modules/dast/auth_engine.sh does the bounded `read -N` and then
    # `cat -- "$bodyf" >>"$corpus"`, because every authentication response is
    # kept for the enumeration scan.  Without this loop that second reader
    # opens a pipe whose only writer has gone and blocks forever - measured,
    # as a hung suite with a parked `cat` and no producer left alive.  Each
    # iteration BLOCKS in open() until someone opens the read end, so this is
    # a park, not a spin; `bounded_read_reap` is what ends it.
    while :; do
      exec 3>"$path"
      exec 3>&-
    done
  ) >/dev/null 2>&1 </dev/null &
  _BR_PRODUCER_PID=$!
  _BR_FIFO_PATH=$path
}

# bounded_read_producer_finished MARKER -> 0 if the producer drained SOURCE
#
# Present means the reader consumed the WHOLE body: the defect.  Absent means
# the reader stopped at its cap and left the producer parked: correct.
bounded_read_producer_finished() {
  [[ -f $1 ]]
}

# bounded_read_reap - stop the parked producer.
#
# On the correct reading the producer is still blocked on a full pipe and will
# never exit on its own, so this is required rather than tidy-up.  It is also
# why nothing here waits on it with a timeout: a wait would be a duration, and
# the point of this file is that no duration decides anything.
bounded_read_reap() {
  [[ -n ${_BR_PRODUCER_PID:-} ]] || return 0
  kill -9 "$_BR_PRODUCER_PID" 2>/dev/null || true
  wait "$_BR_PRODUCER_PID" 2>/dev/null || true
  _BR_PRODUCER_PID=
  # Put a REGULAR FILE back at the path.  lib/http.sh truncates its body sink
  # with `: >"$cap_body"` before every request, and opening a FIFO for writing
  # blocks until a reader arrives - so leaving the FIFO in place would hang the
  # NEXT request through this same sink rather than the one under test.
  if [[ -n ${_BR_FIFO_PATH:-} && -p ${_BR_FIFO_PATH:-} ]]; then
    rm -f -- "$_BR_FIFO_PATH"
    : >"$_BR_FIFO_PATH"
  fi
  _BR_FIFO_PATH=
}
