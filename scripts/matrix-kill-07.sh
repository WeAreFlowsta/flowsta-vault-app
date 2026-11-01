#!/usr/bin/env bash
# Kill one line's conductor under a running test instance and check the
# Vault recovers it by itself (the watchdog's decision): the 0.7 line
# (default) is brought back; the 0.6 line beside a 0.7 primary is let go and
# attached again the next round it is wanted. Either way the reads answer.
# Usage: scripts/matrix-kill-07.sh <ipc port> <instance suffix> [07|06]
set -u
PORT="${1:?port}"; SUFFIX="${2:?suffix}"; LINE="${3:-07}"
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
case "$LINE" in
  07) GEN=holochain-0.7; BIN='vault-holochain-07[^ ]*' ;;
  06) GEN=holochain-0.6; BIN='vault-holochain-x86_64[^ ]*' ;;
  *) echo "line must be 07 or 06"; exit 2 ;;
esac
lines() { curl -s -m 5 "http://127.0.0.1:$PORT/dev/status" | python3 -c 'import sys,json; d=json.load(sys.stdin); print({l["generation"]:l["state"] for l in d.get("holochain_lines",[])})' 2>/dev/null; }
# The line's conductor of this instance: by process name (the sidecar
# carries a target-triple suffix) and the data folder in its arguments, read
# from /proc so no shell running this script matches its own command line.
conductor() { for pid in $(pgrep -x vault-holochain); do tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | grep -q -- "$BIN -c $DIR/" && { echo $pid; return; }; done; }
echo "before: $(lines)"
PID=$(conductor)
[ -n "$PID" ] || { echo "✗ no 0.${LINE#0} conductor found for $DIR"; exit 1; }
kill -9 "$PID"; echo "killed 0.${LINE#0} conductor pid $PID $(date -u +%H:%M:%S)"
t0=$(date +%s); ok=0
for i in $(seq 1 60); do sleep 5; l=$(lines); case "$l" in *"'$GEN': 'serving'"*) NEW=$(conductor); [ -n "$NEW" ] && [ "$NEW" != "$PID" ] && { ok=1; break; };; esac; done
echo "after: $(lines) in $(( $(date +%s) - t0 )) s (new pid ${NEW:-none})"
[ $ok -eq 1 ] && echo "  ✓ the 0.${LINE#0} conductor came back by itself" || { echo "  ✗ FAIL the 0.${LINE#0} conductor did not come back within 5 min"; exit 1; }
for i in $(seq 1 36); do code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'origin: https://ourtest.flowsta.com' "http://127.0.0.1:$PORT/signatures"); [ "$code" = 200 ] && { echo "  ✓ GET /signatures answers again (200)"; exit 0; }; sleep 5; done
echo "  ✗ FAIL GET /signatures did not answer within 3 min (last $code)"; exit 1
