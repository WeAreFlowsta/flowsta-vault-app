#!/usr/bin/env bash
# The move, through the app, on one data folder: a 1.6.1 build creates an
# identity and signs (move-before), the 1.7.0 build opens the same folder and
# moves it (move-after), and opens it once more with the 0.6 line retired
# (move-retired). Usage: LEGACY_BIN=<dir with a 1.6.1 flowsta-vault + sidecars>
# scripts/matrix-move.sh [log dir]. Needs the installed Vault CLOSED and the
# 1.7.0 test binary built (scripts/build-test-binary.sh).
set -u
cd "$(dirname "$0")/.."
: "${LEGACY_BIN:?set LEGACY_BIN to the folder holding the 1.6.1 test build}"
LOGS="${1:-/tmp/vault-matrix-move-$$}"; mkdir -p "$LOGS"
SUFFIX=mv-a
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
export VAULT_MATRIX_MOVE_STATE="$LOGS/move-state.json"
rm -rf "$DIR"
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
waitport() { for i in $(seq 1 36); do p=$(answering | head -1); [ -n "$p" ] && { echo $p; return 0; }; sleep 5; done; return 1; }
# Stop the instance: the app, then whatever it spawned for this data folder
# (a conductor or key store left behind would hold the ports).
stop_instance() {
  for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*|"$LEGACY_BIN"*) kill $pid 2>/dev/null;; esac; done
  for i in $(seq 1 15); do pgrep -x flowsta-vault >/dev/null || break; sleep 1; done
  for pid in $(pgrep -f "$DIR"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done
  sleep 2
}
launch() { # $1 = bin (empty = 1.7.0 test build), $2 = log name
  VAULT_TEST_BIN="$1" dbus-run-session -- scripts/run-test-instance.sh "$SUFFIX" > "$LOGS/$2.log" 2>&1 &
  waitport || { echo "$2 never answered"; find "$DIR" -name '*.log' -exec tail -20 {} +; stop_instance; exit 1; }
}
rc_all=0
echo "== move-before on 1.6.1 $(date -u +%H:%M:%S)"
P=$(launch "$LEGACY_BIN/flowsta-vault" instance-1.6.1)
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=move-before > "$LOGS/move-before.log" 2>&1; rc=$?; rc_all=$((rc_all+rc))
grep -E 'RESULT|✗' "$LOGS/move-before.log"; stop_instance
[ $rc -eq 0 ] || { echo "move-before failed"; exit 1; }
echo "== move-after on 1.7.0 $(date -u +%H:%M:%S)"
P=$(launch "" instance-1.7.0-a)
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=move-after > "$LOGS/move-after.log" 2>&1; rc=$?; rc_all=$((rc_all+rc))
grep -E 'RESULT|✗' "$LOGS/move-after.log"; stop_instance
echo "== move-retired on 1.7.0 $(date -u +%H:%M:%S)"
P=$(launch "" instance-1.7.0-b)
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=move-retired > "$LOGS/move-retired.log" 2>&1; rc=$?; rc_all=$((rc_all+rc))
grep -E 'RESULT|✗' "$LOGS/move-retired.log"
echo "== kill the 0.7 conductor under the moved identity $(date -u +%H:%M:%S)"
scripts/matrix-kill-07.sh "$P" "$SUFFIX" > "$LOGS/kill-07.log" 2>&1; rc=$?; rc_all=$((rc_all+rc)); cat "$LOGS/kill-07.log"
stop_instance
echo "== done rc=$rc_all $(date -u +%H:%M:%S); logs in $LOGS and $DIR/xdg/com.flowsta.vault/logs/"
exit $rc_all
