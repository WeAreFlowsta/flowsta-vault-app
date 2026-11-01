#!/usr/bin/env bash
# A conductor that keeps stopping: kill the 0.7 conductor (the primary of a
# moved identity) under a running test instance <most> times, each brought
# back by the watchdog; the next kill is held (no restart, the sidebar says
# why, logged once) and the Vault brings it back by itself once the oldest
# recovery leaves the window. The instance runs with
# VAULT_TEST_WATCH_LIMIT=<most>,<secs>. Each kill is followed by the
# harness's watchdog call, so every kill is exactly one recovery. Unlocks
# first, with the password in the move leg's state file (a launch with no
# matrix phase stays locked).
# Usage: VAULT_MATRIX_MOVE_STATE=<file> scripts/matrix-crash-loop.sh <ipc port> <instance suffix> <most> <secs>
set -u
PORT="${1:?port}"; SUFFIX="${2:?suffix}"; MOST="${3:?most}"; WITHIN="${4:?secs}"
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
BIN='vault-holochain-07[^ ]*'
HELD='[watchdog] held: Holochain keeps stopping'
HOLD_MESSAGE='Holochain keeps stopping. The Vault tries again in a few minutes. Restarting the Vault may also help.'
# "<conductor status>|<message>"
now() { curl -s -m 5 "http://127.0.0.1:$PORT/dev/status" | python3 -c 'import sys,json; c=json.load(sys.stdin).get("conductor") or {}; print(c.get("status",""), c.get("message",""), sep="|")' 2>/dev/null; }
# What ensure_conductor_alive returned: empty when it recovered (or found nothing to do).
watchdog() { curl -s -m 180 -H 'content-type: application/json' -H 'origin: https://ourtest.flowsta.com' -X POST -d '{"op":"watchdog"}' "http://127.0.0.1:$PORT/dev/devices" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("watchdog") or "")' 2>/dev/null; }
# Same as matrix-kill-07.sh: by process name and the data folder, from /proc.
conductor() { for pid in $(pgrep -x vault-holochain); do tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | grep -q -- "$BIN -c $DIR/" && { echo $pid; return; }; done; }
holds_logged() { cat "$DIR"/xdg/com.flowsta.vault/logs/*.log 2>/dev/null | grep -c "held until the oldest"; }
signatures() { curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'origin: https://ourtest.flowsta.com' "http://127.0.0.1:$PORT/signatures"; }
fail() { echo "  ✗ FAIL $*"; exit 1; }
back() { # $1 = the killed pid, $2 = seconds: ready with a new conductor
  for i in $(seq 1 $(( $2 / 5 ))); do NEW=$(conductor); case "$(now)" in "ready|"*) [ -n "$NEW" ] && [ "$NEW" != "$1" ] && return 0;; esac; sleep 5; done; return 1
}

: "${VAULT_MATRIX_MOVE_STATE:?set it to the move state file, whose password unlocks the instance}"
# The password goes over stdin, never onto a command line.
code=$(python3 -c 'import sys,json; print(json.dumps({"password": json.load(open(sys.argv[1]))["password"]}))' "$VAULT_MATRIX_MOVE_STATE" \
  | curl -s -m 180 -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -H 'origin: https://ourtest.flowsta.com' -X POST -d @- "http://127.0.0.1:$PORT/dev/unlock-with-password")
[ "$code" = 200 ] || fail "POST /dev/unlock-with-password answered $code"
for i in $(seq 1 36); do [ "$(signatures)" = 200 ] && break; sleep 5; done
[ "$(signatures)" = 200 ] || fail "GET /signatures never answered before the first kill"
ls "$DIR"/xdg/com.flowsta.vault/logs/*.log >/dev/null 2>&1 || fail "no Vault log under $DIR/xdg"
LOGGED=$(holds_logged)
echo "before: $(now) (limit $MOST in $WITHIN s)"

for k in $(seq 1 "$MOST"); do
  PID=$(conductor); [ -n "$PID" ] || fail "no 0.7 conductor before kill $k"
  kill -9 "$PID"; t=$(date +%s); [ "$k" -eq 1 ] && T1=$t
  sleep 1; r=$(watchdog)
  [ -z "$r" ] || fail "kill $k: the watchdog answered '$r' (expected a recovery)"
  back "$PID" 120 || fail "kill $k: the conductor was not back within 2 min ($(now))"
  echo "  ✓ kill $k: back in $(( $(date +%s) - t )) s (pid $NEW)"
done

PID=$(conductor); [ -n "$PID" ] || fail "no 0.7 conductor before kill $((MOST + 1))"
kill -9 "$PID"; TH=$(date +%s); sleep 1
[ $(( TH - T1 )) -lt "$WITHIN" ] || fail "kill $((MOST + 1)) came $(( TH - T1 )) s after the first, outside the $WITHIN s window: too slow to test"
r=$(watchdog)
[ "$r" = "$HELD" ] || fail "kill $((MOST + 1)): the watchdog answered '$r' (expected '$HELD')"
echo "  ✓ kill $((MOST + 1)), $(( TH - T1 )) s after the first: held"
[ "$(now)" = "error|$HOLD_MESSAGE" ] && echo "  ✓ the sidebar says: $HOLD_MESSAGE" || fail "the status while held: $(now)"

# Held until the first recovery (about T1 + 1) is WITHIN old: no restart
# meanwhile, however often it is asked.
until [ $(( $(date +%s) - T1 )) -ge $(( WITHIN - 15 )) ]; do
  [ -z "$(conductor)" ] || fail "a conductor started while held, $(( $(date +%s) - T1 )) s after the first kill"
  r=$(watchdog); [ "$r" = "$HELD" ] || fail "asked again while held, the watchdog answered '$r'"
  sleep 10
done
[ "$(now)" = "error|$HOLD_MESSAGE" ] || fail "the status changed while held: $(now)"
echo "  ✓ still held $(( $(date +%s) - T1 )) s after the first kill, asked every 10 s"
[ $(( $(holds_logged) - LOGGED )) -eq 1 ] && echo "  ✓ the hold logged once" || fail "the hold logged $(( $(holds_logged) - LOGGED )) times"

back "$PID" $(( WITHIN + 120 )) || fail "not back by itself after the window ($(now))"
echo "  ✓ back by itself $(( $(date +%s) - TH )) s after the held kill, $(( $(date +%s) - T1 )) s after the first (pid $NEW)"
for i in $(seq 1 36); do code=$(signatures); [ "$code" = 200 ] && { echo "  ✓ GET /signatures answers again (200)"; exit 0; }; sleep 5; done
fail "GET /signatures did not answer within 3 min (last $code)"
