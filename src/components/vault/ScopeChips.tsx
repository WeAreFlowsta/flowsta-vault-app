import { component$, type QRL } from "@builder.io/qwik";

/** What an app or site may see, as chips. Email carries its own state:
 *  shared (with a way to stop) or merely asked for. */
const LABELS: Record<string, string> = {
  display_name: "Name",
  username: "Username",
  profile_picture: "Profile picture",
  did: "DID",
  public_key: "Public key",
  holochain: "Holochain",
  sign: "Sign",
  verify: "Verify",
  email: "Email",
};

interface Props {
  scopes: string[];
  /** True when this app holds an email grant made in the Vault. */
  emailShared?: boolean;
  stopping?: boolean;
  onStopSharing$?: QRL<() => void>;
}

export const ScopeChips = component$<Props>(({ scopes, emailShared = false, stopping = false, onStopSharing$ }) => {
  const others = scopes.filter((s) => s !== "openid" && s !== "email");
  const asksEmail = scopes.includes("email");
  if (others.length === 0 && !asksEmail && !emailShared) return null;
  return (
    <div class="mt-2 flex flex-wrap items-center gap-1.5">
      {others.map((scope) => (
        <span key={scope} class="rounded-full border border-gray-700 bg-black/30 px-2 py-0.5 text-[11px] text-gray-300">
          {LABELS[scope] ?? scope}
        </span>
      ))}
      {emailShared ? (
        <span class="flex items-center gap-1.5 rounded-full border border-pink-800/60 bg-pink-900/20 px-2 py-0.5 text-[11px] text-pink-200">
          Email shared
          {onStopSharing$ && (
            <button
              type="button"
              disabled={stopping}
              class="rounded-full bg-pink-900/40 px-1.5 text-[10px] text-pink-100 hover:bg-pink-800/60 disabled:opacity-50"
              onClick$={onStopSharing$}
              title="Stop sharing your email with this app - removes Flowsta's copy for it too"
            >
              {stopping ? "…" : "Stop sharing"}
            </button>
          )}
        </span>
      ) : asksEmail ? (
        <span class="rounded-full border border-gray-700 bg-black/30 px-2 py-0.5 text-[11px] text-gray-400" title="This app may ask for your email; you decide in the Vault when it does">
          Email · not shared
        </span>
      ) : null}
    </div>
  );
});
