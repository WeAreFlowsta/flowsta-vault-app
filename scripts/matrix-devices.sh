#!/usr/bin/env bash
# The devices matrix leg end to end: build the test binary (skip with
# SKIP_BUILD=1), start two FRESH test instances (md-c / md-d) under a session
# bus, run `bridge-matrix.mjs --phase=devices` against them, stop them.
# Usage: scripts/matrix-devices.sh [log dir]   (MATRIX_PHASE=bulk runs the bulk leg on the same pair)
# Needs the installed Vault CLOSED: a test instance exits at once otherwise
# (the single-instance plugin hands off to it, exit 0, empty data dir).
# The first instance takes 27777 then, the second 27778.
set -u
cd "$(dirname "$0")/.."
LOGS="${1:-/tmp/vault-matrix-$$}"; mkdir -p "$LOGS"; set -- "$LOGS"
echo "== build $(date -u +%H:%M:%S)"
[ -n "${SKIP_BUILD:-}" ] || scripts/build-test-binary.sh > "$1/matrix-build.log" 2>&1 || { echo "BUILD FAILED"; tail -20 "$1/matrix-build.log"; exit 1; }
rm -rf "$HOME/.local/share/flowsta-vault-md-c" "$HOME/.local/share/flowsta-vault-md-d"
echo "== instances $(date -u +%H:%M:%S)"
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
waitnew() { for i in $(seq 1 36); do for p in $(answering); do [ "$p" != "${1:-}" ] && { echo $p; return 0; }; done; sleep 5; done; return 1; }
# LEGACY_A_BIN=<dir holding a 1.6.1 flowsta-vault + its sidecars> starts A on
# that build (the mixed-version leg: a 1.6.1 sibling beside 1.7.0).
VAULT_TEST_BIN="${LEGACY_A_BIN:+$LEGACY_A_BIN/flowsta-vault}" dbus-run-session -- scripts/run-test-instance.sh md-c > "$1/md-c.log" 2>&1 & PA=$!
A=$(waitnew) || { echo "md-c never answered"; find "$HOME/.local/share/flowsta-vault-md-c" -name '*.log' -exec tail -20 {} +; kill $PA 2>/dev/null; exit 1; }
dbus-run-session -- scripts/run-test-instance.sh md-d > "$1/md-d.log" 2>&1 & PB=$!
B=$(waitnew "$A") || { echo "md-d never answered"; find "$HOME/.local/share/flowsta-vault-md-d" -name '*.log' -exec tail -20 {} +; kill $PA $PB 2>/dev/null; exit 1; }
echo "== leg A=$A B=$B $(date -u +%H:%M:%S)"
VAULT_MATRIX_MIXED="${LEGACY_A_BIN:+1}" VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase="${MATRIX_PHASE:-devices}" > "$1/matrix-devices.log" 2>&1
rc=$?
echo "== leg rc=$rc $(date -u +%H:%M:%S)"
grep -E 'RESULT|✗' "$1/matrix-devices.log" | head -20
# Test instances: the 1.7.0 build under target/debug and, on a mixed run, the
# 1.6.1 build in LEGACY_A_BIN - plus the conductors and key stores they left.
killtests() {
  for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*|${LEGACY_A_BIN:+$LEGACY_A_BIN*}) kill $pid 2>/dev/null;; esac; done
  sleep 2
  for pid in $(pgrep -f "flowsta-vault-md-[cd]/"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done
}
killtests; sleep 3; killtests
exit $rc
