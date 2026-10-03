import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const python =
  process.env.SSX_TEST_PYTHON ||
  path.join(
    root,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
export default defineConfig({
  testDir: "./tests",
  timeout: 120000,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:5180",
    headless: true,
    channel: process.env.SSX_BROWSER_CHANNEL || undefined,
    trace: process.env.SSX_TEST_TRACE === "1" ? "retain-on-failure" : "off",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: `"${python}" "${path.join(root, "scripts/test_server.py")}"`,
      url: "http://127.0.0.1:8010/health",
      reuseExistingServer: false,
      timeout: 30000,
    },
    {
      command: "npm run dev -- --port 5180",
      url: "http://127.0.0.1:5180",
      env: { SSX_API_PROXY_TARGET: "http://127.0.0.1:8010" },
      reuseExistingServer: false,
      timeout: 30000,
    },
  ],
});
