#!/usr/bin/env bash
# The kit cache under a running test instance: once the primary line is up
# every bundled line's kit is set aside (`both`), also after the 0.6 line has
# retired (kits are kept for later Vaults and for apps that stay on a line;
# `current` = only the 0.7 kit, for a build that bundles one line). With `restore`,
# each cached line is restored from the cache and its binaries run.
# Usage: scripts/matrix-kits.sh <ipc port> both|current [restore]
set -u
PORT="${1:?port}"; EXPECT="${2:?both or current}"; RESTORE="${3:-}"
case "$EXPECT" in
  both) WANT="9 7" ;;     # 0.6: 2 binaries + 7 files; 0.7: 2 binaries + 5 files
  current) WANT="0 7" ;;
  *) echo "expect both or current"; exit 2 ;;
esac
# "<0.6 entries> <0.7 entries> <0.6 bytes> <0.7 bytes>"
kits() { curl -s -m 5 "http://127.0.0.1:$PORT/dev/status" | python3 -c '
import sys, json
k = json.load(sys.stdin).get("kits") or {}
a, b = k.get("holochain-0.6") or {}, k.get("holochain-0.7") or {}
print(len(a.get("entries", [])), len(b.get("entries", [])), a.get("packed", 0), b.get("packed", 0))' 2>/dev/null; }
mib() { python3 -c "print(f'{$1 / 1048576:.1f}')"; }
fail() { echo "  ✗ FAIL $*"; exit 1; }

now=""
for i in $(seq 1 36); do now=$(kits); [ "${now% * *}" = "$WANT" ] && break; sleep 5; done
read -r n06 n07 p06 p07 <<<"$now"
[ "$n06 $n07" = "$WANT" ] || fail "kits: 0.6 $n06 entries, 0.7 $n07 (want $WANT) after 3 min"
if [ "$EXPECT" = both ]; then
  echo "  ✓ kits cached: 0.6 $n06 entries ($(mib "$p06") MiB), 0.7 $n07 ($(mib "$p07") MiB)"
else
  echo "  ✓ only the 0.7 kit: 0.7 $n07 entries ($(mib "$p07") MiB)"
fi

[ "$RESTORE" = restore ] || exit 0
lines="holochain-0.7"; [ "$EXPECT" = both ] && lines="holochain-0.6 holochain-0.7"
for g in $lines; do
  v=${g#holochain-}; nf=5; [ "$v" = 0.6 ] && nf=7
  out=$(curl -s -m 120 -H 'content-type: application/json' -H 'origin: https://ourtest.flowsta.com' -X POST -d "{\"op\":\"kit-restore\",\"line\":\"$g\"}" "http://127.0.0.1:$PORT/dev/devices")
  got=$(python3 -c 'import sys,json; d=json.loads(sys.argv[1]); print(d.get("conductor",""), "|", d.get("lair",""), "|", d.get("files",""), "|", d.get("description",""))' "$out" 2>/dev/null)
  case "$got" in
    "holochain $v."*" | lair_keystore $v."*" | $nf | "*) echo "  ✓ the $v kit restores and runs: $got" ;;
    *) fail "the $v kit restore: ${got:-$out}" ;;
  esac
done
