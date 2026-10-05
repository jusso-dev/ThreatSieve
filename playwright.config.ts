import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: false,
  retries: 0,
  use: { baseURL: "http://127.0.0.1:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.CI
    ? [
        {
          command: "pnpm exec tsx scripts/dev-offline.ts",
          url: "http://127.0.0.1:8787/health",
          timeout: 120000,
        },
        {
          command: "pnpm --filter @threatsieve/web dev",
          url: "http://127.0.0.1:3000",
          timeout: 120000,
        },
      ]
    : undefined,
  reporter: "list",
  outputDir: "artifacts/playwright",
});
