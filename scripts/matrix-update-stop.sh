#!/usr/bin/env bash
# An update's stop under a running test instance, without the install or the
# restart: while the lines stop, the watchdog is asked for a conductor, as a
# call cut off by the stop asks it during a real update (the field logs:
# "conductor unreachable ... running watchdog" in the same second as the
# stop), and reads keep coming. Stopped with only the starts under way
# ended, a new conductor comes up (the race); stopped as an update's install
# stops them (the Vault closing), the watchdog says no and none does. Run it
# last on an instance: closing is for good.
# Usage: scripts/matrix-update-stop.sh <ipc port> <instance suffix>
set -u
PORT="${1:?port}"; SUFFIX="${2:?suffix}"
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
# The running build's log: a staging test build writes under its own
# identifier, and a release build run earlier on this folder leaves its log too.
LOG=$(ls -t "$DIR/xdg/com.flowsta.vault/logs/Flowsta Vault.log" "$DIR/xdg/com.flowsta.vault.staging/logs/Flowsta Vault (Staging).log" 2>/dev/null | head -1)
[ -n "$LOG" ] || { echo "  ✗ FAIL no Vault log under $DIR/xdg"; exit 1; }
BIN='vault-holochain-07[^ ]*'
lines() { curl -s -m 5 "http://127.0.0.1:$PORT/dev/status" | python3 -c 'import sys,json; d=json.load(sys.stdin); print({l["generation"]:l["state"] for l in d.get("holochain_lines",[])})' 2>/dev/null; }
# This instance's 0.7 conductor, as in matrix-kill-07.sh.
conductor() { for pid in $(pgrep -x vault-holochain); do tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | grep -q -- "$BIN -c $DIR/" && { echo $pid; return; }; done; }
poke() { curl -s -m 10 -o /dev/null -H 'origin: https://ourtest.flowsta.com' "http://127.0.0.1:$PORT/signatures"; }
stop_for_update() { curl -s -m 90 -X POST -H 'content-type: application/json' -d "{\"closing\":$1}" "http://127.0.0.1:$PORT/dev/stop-for-update"; }
# What a call that finds the conductor down gets: null = recovered (or nothing to do), else the refusal.
watchdog() { curl -s -m 180 -H 'content-type: application/json' -H 'origin: https://ourtest.flowsta.com' -X POST -d '{"op":"watchdog"}' "http://127.0.0.1:$PORT/dev/devices" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("watchdog") or "null")' 2>/dev/null; }
rc=0

echo "before: $(lines)"
before=$(conductor)
[ -n "$before" ] || { echo "  ✗ FAIL no 0.7 conductor found for $DIR"; exit 1; }

# 1. Only the starts under way ended: a read during and after the stop
# brings a conductor back.
stop_for_update false > /dev/null &
sleep 1; watchdog > /dev/null
for i in $(seq 1 10); do poke; sleep 1; done
wait
back=""
# A new conductor still running 10 s on is the race, whatever the status
# says: a recovery that finishes before the stop does is left running while
# the line reads off (the stop ends after it).
for i in $(seq 1 36); do
  poke; n=$(conductor)
  if [ -n "$n" ] && [ "$n" != "$before" ]; then sleep 10; [ "$(conductor)" = "$n" ] && { back=$n; break; }; fi
  sleep 5
done
if [ -n "$back" ]; then
  echo "  ✓ stopped with only the starts under way ended, a new conductor came up and runs (pid $back; the lines say $(lines)): the race"
else
  echo "  ✗ FAIL the race did not show: no new conductor within 3 min, so the next check proves nothing"; rc=1
fi

# 2. As an update's install stops them: reads during and after the stop,
# past a devices round (each minute), and no conductor comes up.
mark=$(wc -l < "$LOG")
stop_for_update true > /dev/null &
sleep 1; during=$(watchdog)
for i in $(seq 1 10); do poke; sleep 1; done
wait
after=$(watchdog)
case "$during|$after" in
  *"stays stopped"*"|"*"stays stopped"*) echo "  ✓ the watchdog, asked during the stop and after it, said the conductor stays stopped";;
  *) echo "  ✗ FAIL the watchdog, asked during the stop: \"$during\"; after it: \"$after\""; rc=1;;
esac
seen=""; t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt 80 ]; do poke; n=$(conductor); [ -n "$n" ] && seen="$seen $n"; sleep 5; done
if [ -z "$seen" ]; then
  echo "  ✓ stopped as an update's install does, no conductor came up in 90 s"
else
  echo "  ✗ FAIL a conductor came up after the stop:$seen"; rc=1
fi
refused=$(tail -n +"$((mark + 1))" "$LOG" | grep -c "the conductor stays stopped")
if [ "$refused" -eq 1 ]; then
  echo "  ✓ the log says so, once"
else
  echo "  ✗ FAIL the log says the conductor stays stopped $refused times (want once)"; rc=1
fi
started=$(tail -n +"$((mark + 1))" "$LOG" | grep -c "running start_holochain")
if [ "$started" -eq 0 ]; then
  echo "  ✓ no recovery start in the log after the stop"
else
  echo "  ✗ FAIL $started recovery start(s) in the log after the stop"; rc=1
fi
echo "after: $(lines)"
exit $rc
