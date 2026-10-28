#!/usr/bin/env bash
# The bulk move leg: two 1.6.1 devices of one large identity both update to
# 1.7.0 at once (Eric's case, 10-28). bulk-move-before on the 1.6.1 build
# (A creates the identity and writes N records, B joins and holds them),
# then both folders open on the 1.7.0 test build together (bulk-move-after:
# both move, then a record written on each must reach the other), then once
# more with the 0.6 line retired (bulk-move-retired: a record crosses on 0.7 alone).
# Usage: LEGACY_BIN=<dir with a 1.6.1 flowsta-vault + sidecars>
# scripts/matrix-bulk-move.sh [log dir]. Needs the installed Vault CLOSED and
# the 1.7.0 test binary built (scripts/build-test-binary.sh).
# VAULT_MATRIX_BULK_RECORDS (2500) and VAULT_MATRIX_BULK_WAIT_MIN (45) pass through.
# NEW_BIN=<path to a flowsta-vault> runs the 1.7.0 half on that build instead of target/debug.
set -u
cd "$(dirname "$0")/.."
: "${LEGACY_BIN:?set LEGACY_BIN to the folder holding the 1.6.1 test build}"
LOGS="${1:-/tmp/vault-matrix-bulk-move-$$}"; mkdir -p "$LOGS"
export VAULT_MATRIX_MOVE_STATE="$LOGS/bulk-move-state.json"
DIR_A="$HOME/.local/share/flowsta-vault-md-c"
DIR_B="$HOME/.local/share/flowsta-vault-md-d"
rm -rf "$DIR_A" "$DIR_B"
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
waitnew() { for i in $(seq 1 36); do for p in $(answering); do [ "$p" != "${1:-}" ] && { echo $p; return 0; }; done; sleep 5; done; return 1; }
stop_all() {
  for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*|"$LEGACY_BIN"*|${NEW_BIN:+"$(dirname "$NEW_BIN")"*}) kill $pid 2>/dev/null;; esac; done
  for i in $(seq 1 15); do pgrep -x flowsta-vault >/dev/null || break; sleep 1; done
  for pid in $(pgrep -f "flowsta-vault-md-[cd]/"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done
  sleep 3
}
start_pair() { # $1 = bin for both (empty = the 1.7.0 test build), $2 = log tag
  VAULT_TEST_BIN="$1" dbus-run-session -- scripts/run-test-instance.sh md-c > "$LOGS/md-c-$2.log" 2>&1 &
  A=$(waitnew) || { echo "md-c never answered ($2)"; stop_all; exit 1; }
  VAULT_TEST_BIN="$1" dbus-run-session -- scripts/run-test-instance.sh md-d > "$LOGS/md-d-$2.log" 2>&1 &
  B=$(waitnew "$A") || { echo "md-d never answered ($2)"; stop_all; exit 1; }
}
echo "== bulk-move-before on 1.6.1 $(date -u +%H:%M:%S)"
start_pair "$LEGACY_BIN/flowsta-vault" 161
echo "   A=$A B=$B"
VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase=bulk-move-before > "$LOGS/bulk-move-before.log" 2>&1; rc=$?
grep -E '^   A wrote|RESULT|✗' "$LOGS/bulk-move-before.log"
stop_all
[ $rc -eq 0 ] || { echo "bulk-move-before failed"; exit 1; }
echo "== bulk-move-after on 1.7.0, both at once $(date -u +%H:%M:%S)"
start_pair "${NEW_BIN:-}" 170
echo "   A=$A B=$B"
VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase=bulk-move-after > "$LOGS/bulk-move-after.log" 2>&1; rc=$?
grep -E '^   [0-9]+ min|after the move:|RESULT|✗' "$LOGS/bulk-move-after.log"
stop_all
# Settled: both open again on 1.7.0, neither starts the 0.6 line, and a
# record now crosses on the 0.7 network or not at all (Eric's case).
echo "== bulk-move-retired on 1.7.0 $(date -u +%H:%M:%S)"
start_pair "${NEW_BIN:-}" 170r
echo "   A=$A B=$B"
VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase=bulk-move-retired > "$LOGS/bulk-move-retired.log" 2>&1; rc2=$?
grep -E '^   [0-9]+ min|retired:|RESULT|✗' "$LOGS/bulk-move-retired.log"
stop_all
rc=$((rc+rc2))
echo "== done rc=$rc $(date -u +%H:%M:%S); logs in $LOGS, $DIR_A, $DIR_B"
exit $rc
