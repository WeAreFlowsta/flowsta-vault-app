#!/usr/bin/env bash
# A quit, live, on Linux: a test instance is started in its own data folder,
# asked to quit (SIGTERM, the clean path), and the quit is read back:
#   - the log says the page's processes were ended;
#   - no page process outlives the Vault;
#   - nothing printed a heap abort ("corrupted ...", "free(): ...").
# QUIT_ROUNDS quits (default 5). Needs scripts/build-test-binary.sh first.
# Output is kept in QUIT_LOGS; the data folder is removed at the end.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Linux ] || { echo "== a Linux check; skipped here"; exit 0; }
LOGS="${QUIT_LOGS:-$HOME/.cache/flowsta-vault-quit-check}"; rm -rf "$LOGS"; mkdir -p "$LOGS"
ROUNDS="${QUIT_ROUNDS:-5}"
SUFFIX=quit-check
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
fail() { echo "FAIL: $*" >&2; exit 1; }
nap() { python3 -c "import time; time.sleep($1)"; }
BIN_REAL="$(readlink -f "${VAULT_TEST_BIN:-src-tauri/target/debug/flowsta-vault}")"
ours() { for pid in $(pgrep -x flowsta-vault || true); do [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$BIN_REAL" ] && grep -qz "FLOWSTA_VAULT_DATA_DIR=$DIR" "/proc/$pid/environ" 2>/dev/null && echo "$pid"; done; }
# By the program file: the name in the process table is cut at 15 letters.
pages_of() { for p in $(pgrep -P "$1" || true); do case "$(readlink "/proc/$p/exe" 2>/dev/null)" in */WebKitWebProcess) echo "$p";; esac; done; }
[ -z "$(ours)" ] || fail "a quit-check instance is already up"
rm -rf "$DIR"
for i in $(seq 1 "$ROUNDS"); do
  OUT="$LOGS/quit-$i.out"
  scripts/run-test-instance.sh "$SUFFIX" > "$OUT" 2>&1 &
  app=""; pages=""
  for _ in $(seq 1 60); do
    app="$(ours | head -1)"
    if [ -n "$app" ]; then pages="$(pages_of "$app")"; [ -n "$pages" ] && break; fi
    nap 0.5
  done
  [ -n "$app" ] && [ -n "$pages" ] || fail "round $i: the Vault or its page process did not start (see $OUT)"
  nap 8
  pages="$(pages_of "$app")"
  kill -TERM "$app"
  for _ in $(seq 1 80); do [ -d "/proc/$app" ] || break; nap 0.5; done
  [ -d "/proc/$app" ] && fail "round $i: the Vault did not quit in 40 s"
  nap 2
  for p in $pages; do [ -d "/proc/$p" ] && fail "round $i: page process $p outlived the Vault"; done
  grep -q "\[exit\] ended [0-9]* page process" "$OUT" || fail "round $i: the log does not say the page's processes were ended"
  if grep -qE "corrupted|free\(\)|double free|malloc\(\)" "$OUT"; then fail "round $i: a heap abort was printed: $(grep -E 'corrupted|free\(\)|double free|malloc\(\)' "$OUT" | head -1)"; fi
  echo "   round $i: $(grep -o '\[exit\] ended [0-9]* page process[^ ]*' "$OUT" | head -1)"
done
rm -rf "$DIR"
echo "== $ROUNDS quits: passed (output kept at $LOGS)"
