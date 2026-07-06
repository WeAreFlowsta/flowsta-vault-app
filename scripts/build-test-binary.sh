#!/usr/bin/env bash
# Build the debug test binary with the STAGING network baked in.
#
# The vault's network parameters (bootstrap/signal/auth material) are
# COMPILE-time (`option_env!`) — a cargo/tauri build without these env
# vars silently re-bakes the prod-bootstrap-no-auth defaults, and the
# resulting instance discovers zero peers with no error anywhere.
# ALWAYS build the test binary through this script.
set -euo pipefail
cd "$(dirname "$0")/.."

VITE_API_URL=https://auth-api-staging.flowsta.com \
VITE_WEB_URL=https://ourtest.flowsta.com \
FLOWSTA_API_URL=https://auth-api-staging.flowsta.com \
FLOWSTA_BOOTSTRAP_URL=https://bootstrap-staging.flowsta.com \
FLOWSTA_SIGNAL_URL=wss://bootstrap-staging.flowsta.com \
FLOWSTA_AUTH_MATERIAL=eyJjbGllbnRfaWQiOiJmbG93c3RhX2FwcF9iZGZmZDBjMTcwOTBiZDRkMzEyMWUwZjZkZGUzMmE0MDJjYWNmMTk3NmNiYjIzNDgzODA1MDAyZTJkNmE0Zjk0In0= \
npx tauri build --debug --no-bundle

# Trust nothing: prove the staging bootstrap made it into the binary's
# baked config template (string search fails when compression hides it,
# so check the compile-time env fingerprint via a fresh config instead).
echo "Built. Verify a fresh instance's conductor-config.yaml says"
echo "bootstrap-staging.flowsta.com before trusting any network result."
