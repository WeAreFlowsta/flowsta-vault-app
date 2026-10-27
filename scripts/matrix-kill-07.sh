#!/usr/bin/env bash
# Kill the 0.7 conductor under a running test instance and check the Vault
# brings it back by itself (the devices round's watchdog) and reads again.
# Usage: scripts/matrix-kill-07.sh <ipc port> <instance suffix>
set -u
PORT="${1:?port}"; SUFFIX="${2:?suffix}"
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
lines() { curl -s -m 5 "http://127.0.0.1:$PORT/dev/status" | python3 -c 'import sys,json; d=json.load(sys.stdin); print({l["generation"]:l["state"] for l in d.get("holochain_lines",[])})' 2>/dev/null; }
# The 0.7 conductor of this instance: by process name (the sidecar carries a
# target-triple suffix) and the data folder in its arguments, read from /proc
# so no shell running this script matches its own command line.
conductor_07() { for pid in $(pgrep -x vault-holochain); do tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | grep -q -- "vault-holochain-07[^ ]* -c $DIR/" && { echo $pid; return; }; done; }
echo "before: $(lines)"
PID=$(conductor_07)
[ -n "$PID" ] || { echo "✗ no 0.7 conductor found for $DIR"; exit 1; }
kill -9 "$PID"; echo "killed 0.7 conductor pid $PID $(date -u +%H:%M:%S)"
t0=$(date +%s); ok=0
for i in $(seq 1 60); do sleep 5; l=$(lines); case "$l" in *"'holochain-0.7': 'serving'"*) NEW=$(conductor_07); [ -n "$NEW" ] && [ "$NEW" != "$PID" ] && { ok=1; break; };; esac; done
echo "after: $(lines) in $(( $(date +%s) - t0 )) s (new pid ${NEW:-none})"
[ $ok -eq 1 ] && echo "  ✓ the 0.7 conductor came back by itself" || { echo "  ✗ FAIL the 0.7 conductor did not come back within 5 min"; exit 1; }
for i in $(seq 1 36); do code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'origin: https://ourtest.flowsta.com' "http://127.0.0.1:$PORT/signatures"); [ "$code" = 200 ] && { echo "  ✓ GET /signatures answers again (200)"; exit 0; }; sleep 5; done
echo "  ✗ FAIL GET /signatures did not answer within 3 min (last $code)"; exit 1
