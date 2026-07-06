#!/usr/bin/env bash
# Launch an isolated Flowsta Vault test instance against STAGING.
#
# Used by the I1 restore harness (and any future multi-instance test):
# a debug binary honors FLOWSTA_VAULT_DATA_DIR, so each instance gets its
# own vault file / lair / conductor and its own IPC port (the server
# scans 27777-27779 — a dev vault typically holds 27777, so the first
# test instance lands on 27778).
#
# Build first with scripts/build-test-binary.sh — network params are
# COMPILE-time; a build without the FLOWSTA_* env silently bakes the
# prod bootstrap with no auth material (zero peers, no errors).
#
# Usage: scripts/run-test-instance.sh <suffix>   # e.g. i1-a, i1-b
set -euo pipefail
SUFFIX="${1:?usage: run-test-instance.sh <suffix>}"
DIR="$HOME/.local/share/flowsta-vault-$SUFFIX"
mkdir -p "$DIR"
cd "$(dirname "$0")/.."

# Staging network parameters — same values as the tauri:dev-staging script.
FLOWSTA_VAULT_DATA_DIR="$DIR" \
FLOWSTA_VAULT_AUTO_APPROVE=1 \
FLOWSTA_API_URL=https://auth-api-staging.flowsta.com \
FLOWSTA_BOOTSTRAP_URL=https://bootstrap-staging.flowsta.com \
FLOWSTA_SIGNAL_URL=wss://bootstrap-staging.flowsta.com \
FLOWSTA_AUTH_MATERIAL=eyJjbGllbnRfaWQiOiJmbG93c3RhX2FwcF9iZGZmZDBjMTcwOTBiZDRkMzEyMWUwZjZkZGUzMmE0MDJjYWNmMTk3NmNiYjIzNDgzODA1MDAyZTJkNmE0Zjk0In0= \
exec src-tauri/target/debug/flowsta-vault
