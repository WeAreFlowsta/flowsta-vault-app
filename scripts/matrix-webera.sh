#!/usr/bin/env bash
# The web-era leg: a fresh test instance, bridge-matrix --phase=webera (a migrated
# web account restored, or a web account brought over, its signatures counted
# from the 0.7 read). Usage: scripts/matrix-webera.sh [log dir]. Needs the
# installed Vault CLOSED and the phrase at ~/.config/flowsta/staging-webera-phrase.
set -u
cd "$(dirname "$0")/.."
LOGS="${1:-/tmp/vault-matrix-webera-$$}"; mkdir -p "$LOGS"
rm -rf "$HOME/.local/share/flowsta-vault-hc-w"
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
dbus-run-session -- scripts/run-test-instance.sh hc-w > "$LOGS/hc-w.log" 2>&1 & PW=$!
P=""; for i in $(seq 1 36); do P=$(answering | head -1); [ -n "$P" ] && break; sleep 5; done
[ -n "$P" ] || { echo "hc-w never answered"; exit 1; }
VAULT_MATRIX_PORT=$P node scripts/bridge-matrix.mjs --phase=webera > "$LOGS/matrix-webera.log" 2>&1; rc=$?
grep -E '✓|✗|RESULT' "$LOGS/matrix-webera.log" | cut -c1-240
for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*) kill $pid 2>/dev/null;; esac; done; sleep 3
for pid in $(pgrep -f "flowsta-vault-hc-w/"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done
exit $rc
