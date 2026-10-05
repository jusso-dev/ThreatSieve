import type { E2EConfig } from "e2e";
import { web } from "@e2e-dev/web";
export default {
  tests: "tests/system/**/*.e2e.ts",
  targets: [
    {
      name: "chromium",
      engine: web(),
      app: {
        url: "http://127.0.0.1:3180",
        command: {
          executable: "pnpm",
          args: ["exec", "tsx", "scripts/e2e-server.ts"],
          startupTimeout: 180000,
          log: ".e2e/logs/app.log",
          env: {
            E2E_SKIP_BUILD: process.env.E2E_SKIP_BUILD ?? "0",
            NEXT_TELEMETRY_DISABLED: "1",
          },
        },
      },
    },
  ],
  workers: 1,
  retries: 0,
  timeout: 60000,
  assertionTimeout: 10000,
  cache: "off",
  trace: "retain-on-failure",
  reporters: ["list", "junit", "markdown"],
} satisfies E2EConfig;
