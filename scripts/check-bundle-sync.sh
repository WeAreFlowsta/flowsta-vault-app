#!/usr/bin/env bash
# Verify that the bundled Holochain hApp resources line up across all three
# places that have to agree:
#
#   1. src-tauri/tauri.conf.json   bundle.resources   — what Tauri ships
#   2. src-tauri/src/dna.rs        BUNDLED_*_HAPP_FILE constants — what Rust loads
#   3. src-tauri/resources/        actual *.happ files on disk
#
# Drift between any of these = fresh installs fail with "DNA installation
# failed: hApp bundle not found" (the v0.4.1 bug).
#
# Exit 0 = all three agree. Exit 1 = drift detected (CI should fail the build).
#
# Run from the flowsta-vault repository root.

set -euo pipefail

bundle=$(python3 -c "
import json, sys
with open('src-tauri/tauri.conf.json') as f:
    cfg = json.load(f)
for r in sorted(cfg['bundle']['resources']):
    print(r.removeprefix('resources/'))
")

# Only match real assigned constants — not doc comments — so e.g. an
# `e.g. ('private', '1.10') -> 'flowsta_private_v1_10_happ.happ'` comment
# doesn't trigger a false positive. Allows digits in the middle so
# version-suffixed constants like `BUNDLED_SIGNING_V1_3_HAPP_FILE` match.
# The signing-coordinator hot-swap wasm ships alongside the happs and is
# referenced by its own constant — hold it to the same agreement.
constants=$(grep -E '^(pub )?const (BUNDLED_[A-Z0-9_]+_HAPP_FILE|SIGNING_COORDINATOR_WASM): &str =' src-tauri/src/dna.rs \
  | grep -oE '"[^"]+"' | tr -d '"' | sort -u)

on_disk=$(ls src-tauri/resources/*.happ src-tauri/resources/*.wasm 2>/dev/null | xargs -n1 basename | sort -u)

ok=1

while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "$bundle"  | grep -qx "$f" || { echo "DRIFT: $f referenced by dna.rs but not in tauri.conf.json bundle.resources"; ok=0; }
  echo "$on_disk" | grep -qx "$f" || { echo "DRIFT: $f referenced by dna.rs but not present in src-tauri/resources/"; ok=0; }
done <<< "$constants"

while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "$constants" | grep -qx "$f" || { echo "DRIFT: $f bundled by tauri.conf.json but not referenced by any bundle constant in dna.rs"; ok=0; }
done <<< "$bundle"

if [ "$ok" = "1" ]; then
  echo "OK — bundle, dna.rs, and src-tauri/resources/ all agree:"
  while IFS= read -r f; do
    [ -z "$f" ] || echo "  $f"
  done <<< "$constants"
else
  echo
  echo "Fix any DRIFT lines above before shipping. The three places that must agree are:"
  echo "  1. src-tauri/tauri.conf.json   bundle.resources"
  echo "  2. src-tauri/src/dna.rs        BUNDLED_*_HAPP_FILE constants"
  echo "  3. src-tauri/resources/        *.happ files on disk"
  exit 1
fi
