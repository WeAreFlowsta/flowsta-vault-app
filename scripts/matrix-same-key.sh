#!/usr/bin/env bash
# Two installs of one identity whose conductors run as the SAME key (two
# Vaults set up by phrase on 1.5.0 or earlier, both since updated): two FRESH
# test instances (hc-k / hc-l), `bridge-matrix.mjs --phase=same-key`, then
# both instances' logs searched for what a second chain under a key makes
# Holochain 0.7.1 say. The leg waits (up to 50 min) for one install to see
# the other, gives it a key of its own, and checks both then sync. A throwaway identity each run; the web-era fixture is
# never used. Usage: scripts/matrix-same-key.sh [log dir]. Needs the installed
# Vault CLOSED and the test binary built (scripts/build-test-binary.sh).
set -u
cd "$(dirname "$0")/.."
LOGS="${1:-/tmp/vault-matrix-same-key-$$}"; mkdir -p "$LOGS"
export RUST_LOG="${RUST_LOG:-warn,kitsune2=info,kitsune2_gossip=info,holochain_p2p=info}"
for s in k l; do rm -rf "$HOME/.local/share/flowsta-vault-hc-$s"; done
answering() { for p in 27777 27778 27779; do curl -s -m 2 "http://127.0.0.1:$p/dev/status" | grep -q '"harness":true' && echo $p; done; }
waitnew() { for i in $(seq 1 36); do for p in $(answering); do [ "$p" != "${1:-}" ] && { echo $p; return 0; }; done; sleep 5; done; return 1; }
killtests() {
  for pid in $(pgrep -x flowsta-vault); do case "$(readlink /proc/$pid/exe 2>/dev/null)" in *target/debug*) kill $pid 2>/dev/null;; esac; done
  sleep 2
  for pid in $(pgrep -f "flowsta-vault-hc-[kl]/"); do [ "$pid" != "$$" ] && kill -9 $pid 2>/dev/null; done
}
dbus-run-session -- scripts/run-test-instance.sh hc-k > "$LOGS/hc-k.log" 2>&1 &
A=$(waitnew) || { echo "hc-k never answered"; killtests; exit 1; }
dbus-run-session -- scripts/run-test-instance.sh hc-l > "$LOGS/hc-l.log" 2>&1 &
B=$(waitnew "$A") || { echo "hc-l never answered"; killtests; exit 1; }
echo "== leg A=$A B=$B $(date -u +%H:%M:%S)"
VAULT_MATRIX_SAME_KEY_OUT="$LOGS/chains.json" VAULT_MATRIX_PORT=$A VAULT_MATRIX_RESTORE_PORT=$B node scripts/bridge-matrix.mjs --phase=same-key > "$LOGS/matrix-same-key.log" 2>&1; rc=$?
grep -E '✓|✗|seen, |RESULT' "$LOGS/matrix-same-key.log" | cut -c1-400
killtests; sleep 3; killtests
for s in hc-k hc-l; do
  d="$HOME/.local/share/flowsta-vault-$s"; mkdir -p "$LOGS/$s"
  for log in "$d/xdg/com.flowsta.vault/logs/Flowsta Vault.log" "$d/xdg/com.flowsta.vault.staging/logs/Flowsta Vault (Staging).log"; do [ -f "$log" ] && cp "$log" "$LOGS/$s/app.log"; done
  for f in "$d"/identities/*/conductor*/holochain-stderr.log; do [ -f "$f" ] && cp "$f" "$LOGS/$s/$(basename "$(dirname "$f")")-holochain-stderr.log"; done
done
echo "== set aside (kept, never deleted)"
for s in hc-k hc-l; do ls -d "$HOME/.local/share/flowsta-vault-$s"/identities/*/conductor*-as-identity-key-* 2>/dev/null | sed "s|$HOME/.local/share/||"; done
grep -h "\[own key\]\|another install is running" "$LOGS"/hc-k/app.log "$LOGS"/hc-l/app.log 2>/dev/null | cut -c1-300
echo "== what the logs say"
for s in hc-k hc-l; do
  for what in "head has moved" "FOREIGN KEY" "HeadMoved" "ChainHeadMoved" "fork" "Fork" "warrant" "Warrant" "InvalidChain"; do
    n=$(cat "$LOGS/$s"/*.log 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -c -- "$what" || true)
    [ "${n:-0}" -gt 0 ] && echo "   $s: \"$what\" x $n"
  done
done
exit $rc
