#!/usr/bin/env bash
# The signing v1.6 leg: a fresh test instance writes on signing v1.5 with
# the v1.5 -> v1.6 pass held (VAULT_TEST_HOLD_V16=1, read by a debug build
# only): a signature revoked, another with its thumbnail edited. Then the
# same instance again without the hold: the pass carries both with their
# originals, the writes switch to v1.6, the list still reads two rows (each
# naming its v1.5 original, the revocation and the edited thumbnail kept),
# and a new signature is written on v1.6.
# Usage: scripts/matrix-signing-v16.sh [log dir]. Needs the installed Vault
# CLOSED, or built with the staging identifier.
set -u
cd "$(dirname "$0")/.."
LOGS="${1:-/tmp/vault-matrix-v16-$$}"; mkdir -p "$LOGS"
SUFFIX="hc-v16"
rm -rf "$HOME/.local/share/flowsta-vault-$SUFFIX"
export VAULT_MATRIX_V16_STATE="$LOGS/v16-state.json"
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
stop_instance() {
  for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*) kill $pid 2>/dev/null;; esac; done; sleep 3
  for pid in $(pgrep -f "flowsta-vault-${SUFFIX}/"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done; sleep 2
}
start_instance() {
  if [ "${2:-}" = hold ]; then
    env VAULT_TEST_HOLD_V16=1 dbus-run-session -- scripts/run-test-instance.sh "$SUFFIX" > "$LOGS/$1.log" 2>&1 &
  else
    dbus-run-session -- scripts/run-test-instance.sh "$SUFFIX" > "$LOGS/$1.log" 2>&1 &
  fi
  P=""; for i in $(seq 1 36); do P=$(answering | head -1); [ -n "$P" ] && break; sleep 5; done
  [ -n "$P" ] || { echo "$1: the instance never answered"; stop_instance; exit 1; }
}

start_instance before hold
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=v16-before > "$LOGS/matrix-v16-before.log" 2>&1; rc1=$?
grep -E '✓|✗|RESULT' "$LOGS/matrix-v16-before.log" | cut -c1-240
stop_instance
[ $rc1 -eq 0 ] || exit $rc1

start_instance after
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=v16-after > "$LOGS/matrix-v16-after.log" 2>&1; rc2=$?
grep -E '✓|✗|RESULT' "$LOGS/matrix-v16-after.log" | cut -c1-240
stop_instance
exit $rc2
