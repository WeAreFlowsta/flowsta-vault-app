#!/usr/bin/env bash
# A device joins while one sibling is on and the device that MADE the app
# backups is off (a person's Mac, 11-19). Three FRESH test instances:
# A (md-c) creates the identity and makes backups, B (md-d) holds copies,
# A is stopped, C (md-e) restores beside B alone.
# Usage: scripts/matrix-maker-off.sh [log dir]   (SKIP_BUILD=1 skips the build)
# Needs the installed Vault CLOSED (see matrix-devices.sh).
set -uo pipefail
cd "$(dirname "$0")/.."
set -- "${1:-$HOME/.cache/vault-matrix-maker-off-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$1"
export RUST_LOG="${RUST_LOG:-warn,kitsune2=info,kitsune2_gossip=info,holochain_p2p=info}"
echo "== build $(date -u +%H:%M:%S)"
[ -n "${SKIP_BUILD:-}" ] || scripts/build-test-binary.sh > "$1/matrix-build.log" 2>&1 || { echo "BUILD FAILED"; tail -20 "$1/matrix-build.log"; exit 1; }
for s in md-c md-d md-e; do rm -rf "$HOME/.local/share/flowsta-vault-$s"; done
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
# The first port answering that is not one of those named.
waitnew() { for i in $(seq 1 36); do for p in $(answering); do case " $* " in *" $p "*) ;; *) echo $p; return 0;; esac; done; sleep 5; done; return 1; }
# The test processes of one instance: the app by the port it listens on, its
# conductors and key stores by the data folder in their command line.
stop_instance() { # port, suffix
  local pid; pid=$(ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
  [ -n "$pid" ] && case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*) kill "$pid" 2>/dev/null;; esac
  for i in $(seq 1 20); do curl -s -m 2 "http://127.0.0.1:$1/dev/status" > /dev/null || break; sleep 1; done
  sleep 3
  # (process names as the kernel keeps them: the first 15 characters)
  for name in vault-holochain vault-lair-keys; do
    for p in $(pgrep -x "$name"); do tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q "flowsta-vault-$2/" && kill -9 "$p" 2>/dev/null; done
  done
}
echo "== instances $(date -u +%H:%M:%S)"
dbus-run-session -- scripts/run-test-instance.sh md-c > "$1/md-c.log" 2>&1 &
A=$(waitnew) || { echo "md-c never answered"; exit 1; }
dbus-run-session -- scripts/run-test-instance.sh md-d > "$1/md-d.log" 2>&1 &
B=$(waitnew "$A") || { echo "md-d never answered"; stop_instance "$A" md-c; exit 1; }
STATE="$1/.state.json"
echo "== before: A=$A makes backups, B=$B holds copies $(date -u +%H:%M:%S)"
VAULT_MATRIX_STATE="$STATE" VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase=maker-off-before > "$1/maker-off-before.log" 2>&1
rc=$?
grep -E 'RESULT|✗' "$1/maker-off-before.log" | head -20
if [ $rc -eq 0 ] && [ -f "$STATE" ]; then
  echo "== A is stopped $(date -u +%H:%M:%S)"
  stop_instance "$A" md-c
  dbus-run-session -- scripts/run-test-instance.sh md-e > "$1/md-e.log" 2>&1 &
  C=$(waitnew "$B") || { echo "md-e never answered"; rc=1; C=""; }
  if [ -n "$C" ]; then
    echo "== after: C=$C joins beside B=$B alone $(date -u +%H:%M:%S)"
    VAULT_MATRIX_STATE="$STATE" VAULT_MATRIX_C_DIR="$HOME/.local/share/flowsta-vault-md-e" VAULT_MATRIX_PORT=$B VAULT_MATRIX_RESTORE_PORT=$C node scripts/bridge-matrix.mjs --phase=maker-off-after > "$1/maker-off-after.log" 2>&1
    rc=$?
    grep -E 'RESULT|✗|C asked' "$1/maker-off-after.log" | head -20
    stop_instance "$C" md-e
  fi
fi
rm -f "$STATE"
stop_instance "$A" md-c; stop_instance "$B" md-d
for s in md-c md-d md-e; do
  d="$HOME/.local/share/flowsta-vault-$s"; mkdir -p "$1/$s"
  for log in "$d/xdg/com.flowsta.vault/logs/Flowsta Vault.log" "$d/xdg/com.flowsta.vault.staging/logs/Flowsta Vault (Staging).log"; do
    [ -f "$log" ] && cp "$log" "$1/$s/app.log"
  done
done
echo "== rc=$rc; logs kept in $1 $(date -u +%H:%M:%S)"
exit $rc
