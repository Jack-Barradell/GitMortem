import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
import license from "rollup-plugin-license";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [
    vue(),
    tailwindcss(),
    license({
      thirdParty: {
        output: {
          file: fileURLToPath(
            new URL("../src/gitmortem/static/third-party-licenses.txt", import.meta.url),
          ),
        },
      },
    }),
  ],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  worker: { format: "es" },
  build: {
    outDir: "../src/gitmortem/static",
    emptyOutDir: true,
    chunkSizeWarningLimit: 1000,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8765" },
  },
});
