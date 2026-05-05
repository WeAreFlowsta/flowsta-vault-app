import { createContextId, type QRL, type Signal } from "@builder.io/qwik";
import type { ConnectionStatus } from "~/components/vault/StatusIndicator";

export const connectionStatusContext =
  createContextId<Signal<ConnectionStatus>>("app.connectionStatus");

export const autoLockContext =
  createContextId<Signal<number>>("app.autoLockMinutes");

/**
 * App-wide signatures store. The dashboard layout fetches signatures once
 * on conductor-ready + once after auto-link completes, and provides the
 * result here so Overview / Sign It / View All can all read the same signal
 * without re-triggering work on each navigation.
 */
export interface SignaturesStore {
  signatures: Signal<any[]>;
  loaded: Signal<boolean>;
  refreshing: Signal<boolean>;
  /** Force a fresh fetch (e.g. after sign / revoke / thumbnail edit). */
  refresh: QRL<() => Promise<void>>;
}

export const signaturesContext =
  createContextId<SignaturesStore>("app.signatures");

/**
 * Files queued by the OS file-explorer integration ("Sign with Flowsta
 * Vault" right-click) waiting to be handed off to the Sign It page. The
 * layout drains the Rust queue into this signal; the Sign It page reads it
 * and clears it once consumed.
 */
export const pendingSignPathsContext =
  createContextId<Signal<string[]>>("app.pendingSignPaths");
