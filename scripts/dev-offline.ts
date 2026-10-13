import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
// Browser tests use persisted synthetic seed assessments and must never call live AI or feeds.
const config = JSON.parse(
  readFileSync("wrangler.jsonc", "utf8").replace(/,\s*([}\]])/g, "$1"),
) as Record<string, unknown>;
delete config.ai;
delete config.vectorize;
delete config.triggers;
writeFileSync("wrangler.test.local.json", JSON.stringify(config, null, 2));
// wrangler dev does not apply pending D1 migrations. Browser tests call the
// canonical and matching tables added after 0018.
execFileSync(
  "pnpm",
  [
    "exec",
    "wrangler",
    "d1",
    "migrations",
    "apply",
    "threatsieve",
    "--local",
    "--config",
    "wrangler.test.local.json",
  ],
  { stdio: "inherit" },
);
execFileSync(
  "pnpm",
  [
    "exec",
    "wrangler",
    "dev",
    "--config",
    "wrangler.test.local.json",
    "--port",
    "8787",
  ],
  { stdio: "inherit" },
);
