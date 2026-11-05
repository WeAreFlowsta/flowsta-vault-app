#!/usr/bin/env bash
# The move, through the app, on one data folder: a 1.6.1 build creates an
# identity and signs (move-before), the 1.7.0 build opens the same folder and
# moves it (move-after), opens it once more with the 0.6 line retired
# (move-retired), then once more with the marker put back in 1.7.0's shape:
# 0.6 starts once and stops in-session (move-update), and once more for the
# watchdog's limit (crash loop). Each 1.7.0-build launch checks the kit
# cache (scripts/matrix-kits.sh). Usage: LEGACY_BIN=<dir with a 1.6.1 flowsta-vault + sidecars>
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
grep -E 'RESULT|✗' "$LOGS/move-after.log"
kits() { scripts/matrix-kits.sh "$P" "$@" > "$LOGS/kits.log" 2>&1; rc=$?; rc_all=$((rc_all+rc)); cat "$LOGS/kits.log"; }
kits both restore; stop_instance
echo "== move-retired on 1.7.0 $(date -u +%H:%M:%S)"
P=$(launch "" instance-1.7.0-b)
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=move-retired > "$LOGS/move-retired.log" 2>&1; rc=$?; rc_all=$((rc_all+rc))
grep -E 'RESULT|✗' "$LOGS/move-retired.log"
# The 0.6 line has retired, and its kit stays cached all the same.
kits both
echo "== kill the 0.7 conductor under the moved identity $(date -u +%H:%M:%S)"
scripts/matrix-kill-07.sh "$P" "$SUFFIX" > "$LOGS/kill-07.log" 2>&1; rc=$?; rc_all=$((rc_all+rc)); cat "$LOGS/kill-07.log"
echo "== an update's stop: nothing starts a conductor again $(date -u +%H:%M:%S)"
scripts/matrix-update-stop.sh "$P" "$SUFFIX" > "$LOGS/update-stop.log" 2>&1; rc=$?; rc_all=$((rc_all+rc)); cat "$LOGS/update-stop.log"
stop_instance
echo "== move-update: the marker in 1.7.0's shape, opened by this build $(date -u +%H:%M:%S)"
MARKER=$(ls "$DIR"/identities/*/moved-07 2>/dev/null | head -1)
[ -n "$MARKER" ] || { echo "no marker under $DIR"; exit 1; }
node -e '
const fs = require("fs"); const f = process.argv[1]; const m = JSON.parse(fs.readFileSync(f, "utf8"));
const v170 = ["v", "moved_at_ms", "vault_version", "private_records", "signatures", "revocations", "thumbnails", "born", "web_era_carried", "web_era_signatures", "restored", "line_06_needed"];
fs.writeFileSync(f, JSON.stringify(Object.fromEntries(v170.filter((k) => k in m).map((k) => [k, m[k]])), null, 2));' "$MARKER"
P=$(launch "" instance-1.7.0-c)
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=move-update > "$LOGS/move-update.log" 2>&1; rc=$?; rc_all=$((rc_all+rc))
grep -E 'RESULT|✗' "$LOGS/move-update.log"
kits both
stop_instance
if node -e 'const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); process.exit(Number.isInteger(m.carried_all_ms) && m.line_06_needed === false ? 0 : 1)' "$MARKER"; then
  echo "   ✓ move-update: the marker records the complete pass (carried_all_ms) and no 0.6 line needed"
else
  echo "   ✗ FAIL move-update: the marker after the stop: $(tr -d '\n' < "$MARKER")"; rc_all=$((rc_all+1))
fi
echo "== crash loop: four kills, the fourth held until the window passes $(date -u +%H:%M:%S)"
P=$(VAULT_TEST_WATCH_LIMIT=3,150 launch "" instance-1.7.0-d)
scripts/matrix-crash-loop.sh "$P" "$SUFFIX" 3 150 > "$LOGS/crash-loop.log" 2>&1; rc=$?; rc_all=$((rc_all+rc)); cat "$LOGS/crash-loop.log"
# After the crash loop: its unlock starts the conductor, which sets the kits aside.
kits both restore
stop_instance
echo "== done rc=$rc_all $(date -u +%H:%M:%S); logs in $LOGS and $DIR/xdg/com.flowsta.vault/logs/"
exit $rc_all
