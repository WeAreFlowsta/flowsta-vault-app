#!/usr/bin/env bash
# Trim the Rust build dir after a gate. Each build variant (the e2e feature
# on, off, tests) leaves ~13 GB of artifacts, and a day of build-run-rebuild
# fills a laptop: this keeps the last two days' artifacts (both variants
# stay warm) and drops the incremental cache, which the next build remakes.
# Never touches the built binary.
set -euo pipefail
T="$(cd "$(dirname "$0")/../src-tauri" && pwd)/target/debug"
[ -d "$T" ] || exit 0
before=$(du -sk "$T" | cut -f1)
rm -rf "$T/incremental"
find "$T/deps" -maxdepth 1 -type f -mtime +2 -delete 2>/dev/null || true
find "$T/build" -maxdepth 1 -mindepth 1 -mtime +2 -exec rm -rf {} + 2>/dev/null || true
after=$(du -sk "$T" | cut -f1)
echo "build dir: $((before/1024/1024)) GB -> $((after/1024/1024)) GB"
