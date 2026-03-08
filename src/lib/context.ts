import { createContextId, type Signal } from "@builder.io/qwik";
import type { ConnectionStatus } from "~/components/vault/StatusIndicator";

export const connectionStatusContext =
  createContextId<Signal<ConnectionStatus>>("app.connectionStatus");

export const autoLockContext =
  createContextId<Signal<number>>("app.autoLockMinutes");
