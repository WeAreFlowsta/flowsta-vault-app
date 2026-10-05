#!/usr/bin/env bash
# Launches the e2e build of Flowsta Vault on an ISOLATED data folder for the
# UI tests (see e2e/README.md). @wdio/tauri-service runs this instead of the
# binary, so the app never sees the person's own Vault: its data lives in
# e2e/profile (wiped per run), it talks to STAGING, and it runs in a session
# bus of its own so the single-instance guard never hands it to a Vault that
# is already open.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export FLOWSTA_VAULT_DATA_DIR="${VAULT_E2E_DATA_DIR:-$HERE/profile/a}"
mkdir -p "$FLOWSTA_VAULT_DATA_DIR"
# The dev endpoints, so a spec can drive a second device without a window.
export FLOWSTA_VAULT_AUTO_APPROVE=1
# On a Wayland desktop the window is an XWayland window, which xdotool and
# screen recorders can see. VAULT_E2E_NATIVE_WAYLAND=1 keeps the native one.
if [ "${XDG_SESSION_TYPE:-}" = "wayland" ] && [ -z "${VAULT_E2E_NATIVE_WAYLAND:-}" ]; then export GDK_BACKEND=x11; fi
APP="$(cd "$HERE/../src-tauri/target/debug" && pwd)/flowsta-vault"
exec dbus-run-session -- "$APP" "$@"
