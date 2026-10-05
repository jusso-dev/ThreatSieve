/** Ephemeral offline system-test environment. Never uses deployed resources. */
import { build } from "esbuild";
import {
  Miniflare,
  Response as WorkerResponse,
  type Request as WorkerRequest,
} from "miniflare";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { buildDemoSeed } from "./demo-data";
import { upstreamResponse } from "../tests/system/support/upstreams";

async function main() {
  mkdirSync(".e2e/runtime", { recursive: true });
  await build({
    entryPoints: ["tests/system/support/worker.ts"],
    outfile: ".e2e/runtime/worker.mjs",
    bundle: true,
    format: "esm",
    platform: "browser",
    external: ["node:*"],
    target: "es2022",
  });
  const controlKey = crypto.randomUUID();
  const queues = [
    "ingest",
    "normalise",
    "enrich",
    "correlate",
    "classify",
    "export",
  ];
  const mf = new Miniflare({
    host: "127.0.0.1",
    port: 0,
    modules: true,
    scriptPath: ".e2e/runtime/worker.mjs",
    compatibilityDate: "2026-08-06",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: ["DB"],
    r2Buckets: ["ARCHIVE"],
    queueProducers: Object.fromEntries(
      queues.map((q) => [q.toUpperCase() + "_QUEUE", "intel-" + q]),
    ),
    queueConsumers: Object.fromEntries(
      [...queues, "dead-letter"].map((q) => [
        "intel-" + q,
        { maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 2 },
      ]),
    ),
    bindings: {
      APP_ENV: "development",
      WEB_ORIGIN: "http://127.0.0.1:3180",
      AUTO_ACCEPT_THRESHOLD: "0.90",
      REVIEW_THRESHOLD: "0.25",
      ARCHIVE_RAW: "true",
      VECTORIZE_ENABLED: "false",
      DAILY_CLASSIFICATION_LIMIT: "10000",
      ATTACK_ACCEPT_THRESHOLD: "0.90",
      ATTACK_PROBABLE_THRESHOLD: "0.70",
      ATTACK_WEAK_THRESHOLD: "0.50",
      TEST_CONTROL_TOKEN: controlKey,
      THREATFOX_AUTH_KEY: "synthetic-test-only",
      URLHAUS_AUTH_KEY: "synthetic-test-only",
    },
    outboundService: async (request: WorkerRequest) =>
      WorkerResponse.json(upstreamResponse(new URL(request.url))),
  });
  let child: ChildProcess | undefined;
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    child?.kill("SIGTERM");
    await mf.dispose();
    process.exit(0);
  };
  process.on("SIGTERM", () => void stop());
  process.on("SIGINT", () => void stop());
  try {
    const apiOrigin = (await mf.ready).origin;
    const db = await mf.getD1Database("DB");
    for (const name of readdirSync("migrations")
      .filter((n) => n.endsWith(".sql"))
      .sort()) {
      for (const statement of readFileSync("migrations/" + name, "utf8")
        .split(";")
        .map((s) => s.trim())
        .filter(Boolean))
        await db.prepare(statement).run();
    }
    const seed = await buildDemoSeed();
    for (const statement of seed.statements) await db.prepare(statement).run();
    writeFileSync(
      ".e2e/runtime/credentials.json",
      JSON.stringify({ controlKey, apiOrigin, adminKey: seed.token }),
      { mode: 0o600 },
    );
    const env = {
      ...process.env,
      API_ORIGIN: apiOrigin,
      NODE_ENV: "production",
      NEXT_TELEMETRY_DISABLED: "1",
    };
    if (process.env.E2E_SKIP_BUILD !== "1") {
      await new Promise<void>((resolve, reject) => {
        child = spawn("pnpm", ["--filter", "@threatsieve/web", "build"], {
          stdio: "inherit",
          env,
        });
        child.on("error", reject);
        child.on("exit", (code) =>
          code === 0
            ? resolve()
            : reject(new Error("Web build failed: " + code)),
        );
      });
    }
    child = spawn(
      "pnpm",
      [
        "--filter",
        "@threatsieve/web",
        "exec",
        "next",
        "start",
        "--hostname",
        "127.0.0.1",
        "--port",
        "3180",
      ],
      { stdio: "inherit", env },
    );
    child.on("error", (error) => {
      console.error(error);
      void stop();
    });
    child.on("exit", (code) => {
      if (!stopping) {
        console.error("Web server exited: " + code);
        void mf.dispose().then(() => process.exit(1));
      }
    });
  } catch (error) {
    await mf.dispose();
    throw error;
  }
}
main().catch((error) => {
  console.error(error);
  process.exit(1);
});
