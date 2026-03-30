import fs from "fs";
import { defineConfig, loadEnv, type UserConfig } from "vite";
import { qwikVite } from "@builder.io/qwik/optimizer";
import { qwikCity } from "@builder.io/qwik-city/vite";
import tsconfigPaths from "vite-tsconfig-paths";
import tailwindcss from "@tailwindcss/vite";

// Tauri expects a fixed port
const TAURI_DEV_PORT = 1421;

export default defineConfig(({ mode }): UserConfig => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [
      qwikCity(),
      qwikVite(),
      tsconfigPaths({ root: "." }),
      tailwindcss(),
    ],
    // Tauri expects a fixed port in dev mode
    server: {
      port: TAURI_DEV_PORT,
      strictPort: true,
      headers: {
        "Cache-Control": "public, max-age=0",
      },
      watch: {
        ignored: ["**/src-tauri/**"],
      },
    },
    define: {
      __APP_VERSION__: JSON.stringify(
        JSON.parse(fs.readFileSync("src-tauri/tauri.conf.json", "utf-8")).version
      ),
      __API_URL__: JSON.stringify(
        env.VITE_API_URL ?? "https://auth-api.flowsta.com"
      ),
      __WEB_URL__: JSON.stringify(
        env.VITE_WEB_URL ?? "https://flowsta.com"
      ),
    },
    // Tauri needs the build output to be a SPA (no SSR)
    build: {
      target: "esnext",
      outDir: "dist",
    },
    preview: {
      headers: {
        "Cache-Control": "public, max-age=600",
      },
    },
  };
});
