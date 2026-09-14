import { component$ } from "@builder.io/qwik";
import type { FeedIcon, FeedItem } from "~/lib/activity";

/** One activity line: icon disc, text with the bold part, detail, time. */
const ICONS: Record<FeedIcon, { bg: string; fg: string; d: string }> = {
  signature: { bg: "bg-amber-900/30", fg: "text-amber-400", d: "M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" },
  backup: { bg: "bg-blue-900/30", fg: "text-sky-400", d: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" },
  link: { bg: "bg-green-900/30", fg: "text-green-400", d: "M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" },
  signin: { bg: "bg-indigo-900/30", fg: "text-indigo-300", d: "M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l3 3m0 0l-3 3m3-3H2.25" },
  email: { bg: "bg-pink-900/30", fg: "text-pink-300", d: "M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" },
  site: { bg: "bg-teal-900/30", fg: "text-teal-300", d: "M12 21a9 9 0 100-18 9 9 0 000 18zm0 0a8.949 8.949 0 004.951-1.488A3.987 3.987 0 0013 16.5h-2a3.987 3.987 0 00-3.951 3.012A8.949 8.949 0 0012 21zm-8.716-6.747A9.03 9.03 0 013 12c0-1.264.26-2.467.73-3.559M20.27 8.441A8.96 8.96 0 0121 12a9.03 9.03 0 01-.284 2.253" },
  identity: { bg: "bg-purple-900/30", fg: "text-purple-300", d: "M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" },
  password: { bg: "bg-gray-700/50", fg: "text-gray-300", d: "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" },
  device: { bg: "bg-cyan-900/30", fg: "text-cyan-300", d: "M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" },
};

export const ActivityRow = component$<{ item: FeedItem; when: string }>(({ item, when }) => {
  const icon = ICONS[item.icon];
  return (
    <div class="flex items-center gap-3">
      <div class={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${icon.bg}`}>
        <svg class={`h-4 w-4 ${icon.fg}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
          <path stroke-linecap="round" stroke-linejoin="round" d={icon.d} />
        </svg>
      </div>
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm text-white">
          {item.text}
          {item.strong && <span class="font-medium">{item.strong}</span>}
          {item.detail && (item.icon === "backup" || item.icon === "link") && (
            <>{" "}<span class="text-gray-400">{item.detail}</span></>
          )}
        </p>
        <p class="truncate text-xs text-gray-500">
          {item.detail && item.icon !== "backup" && item.icon !== "link" ? <>{item.detail} · </> : null}
          {when}
        </p>
      </div>
    </div>
  );
});
