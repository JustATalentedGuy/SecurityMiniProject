import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": process.env.SSX_API_PROXY_TARGET || "http://127.0.0.1:8000",
      "/health": process.env.SSX_API_PROXY_TARGET || "http://127.0.0.1:8000",
      "/docs": process.env.SSX_API_PROXY_TARGET || "http://127.0.0.1:8000",
      "/openapi.json":
        process.env.SSX_API_PROXY_TARGET || "http://127.0.0.1:8000",
    },
  },
  test: { include: ["src/**/*.test.js"], environment: "node" },
});
