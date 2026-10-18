/// <reference types="vitest/config" />
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const outDir = resolve(import.meta.dirname, "../src/kestrix/server/static");

/** `emptyOutDir` wipes the package's static dir; recreate the tracked placeholder. */
function keepGitkeep(): Plugin {
  return {
    name: "kestrix-keep-gitkeep",
    apply: "build",
    closeBundle() {
      mkdirSync(outDir, { recursive: true });
      writeFileSync(resolve(outDir, ".gitkeep"), "");
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), keepGitkeep()],
  build: {
    outDir,
    emptyOutDir: true,
    target: "es2022",
    assetsInlineLimit: 0,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8765" },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    restoreMocks: true,
  },
});
