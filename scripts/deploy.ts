import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
if (process.argv.includes("--help")) {
  console.log(
    "pnpm run deploy [--config-only] [--production]. Requires CLOUDFLARE_ACCOUNT_ID, THREATSIEVE_D1_ID, THREATSIEVE_WEB_ORIGIN, THREATSIEVE_API_ORIGIN. Remote migrations are applied separately.",
  );
  process.exit(0);
}
const stage = process.argv.includes("--production") ? "production" : "staging";
const configPath =
  stage === "production"
    ? "wrangler.deploy.local.json"
    : "wrangler.staging.local.json";
const databaseId = process.env.THREATSIEVE_D1_ID;
const account = process.env.CLOUDFLARE_ACCOUNT_ID;
const webOrigin = process.env.THREATSIEVE_WEB_ORIGIN;
const apiOrigin = process.env.THREATSIEVE_API_ORIGIN;
if (!databaseId || !account || !webOrigin || !apiOrigin)
  throw new Error(
    "Set THREATSIEVE_D1_ID, CLOUDFLARE_ACCOUNT_ID, THREATSIEVE_WEB_ORIGIN and THREATSIEVE_API_ORIGIN. See docs/deployment.md.",
  );
if (
  stage === "production" &&
  process.env.THREATSIEVE_PRODUCTION_RELEASE !== "approved"
)
  throw new Error(
    "Production release requires THREATSIEVE_PRODUCTION_RELEASE=approved in a protected deployment environment.",
  );
const config = JSON.parse(
  readFileSync("wrangler.jsonc", "utf8").replace(/,\s*([}\]])/g, "$1"),
) as {
  name: string;
  account_id?: string;
  main: string;
  vars: Record<string, string>;
  d1_databases: {
    database_id: string;
    database_name: string;
    migrations_dir: string;
  }[];
  r2_buckets: { bucket_name: string }[];
  vectorize: { index_name: string }[];
  send_email: { name: string; allowed_sender_addresses: string[] }[];
  queues: {
    producers: { queue: string }[];
    consumers: { queue: string; dead_letter_queue?: string }[];
  };
};
config.name = "threatsieve-api-" + stage;
config.account_id = account;
config.vars.APP_ENV = stage;
config.vars.WEB_ORIGIN = webOrigin;
config.vars.VECTORIZE_ENABLED =
  process.env.THREATSIEVE_VECTORIZE_ENABLED === "true" ? "true" : "false";
if (process.env.THREATSIEVE_AUTH_EMAIL_FROM) {
  config.vars.AUTH_EMAIL_FROM = process.env.THREATSIEVE_AUTH_EMAIL_FROM;
  config.send_email[0]!.allowed_sender_addresses = [
    process.env.THREATSIEVE_AUTH_EMAIL_FROM,
  ];
}
config.d1_databases[0]!.database_id = databaseId;
config.d1_databases[0]!.database_name = "threatsieve-" + stage;
config.r2_buckets[0]!.bucket_name = "threatsieve-archive-" + stage;
config.vectorize[0]!.index_name = "threatsieve-intel-" + stage;
for (const q of config.queues.producers) q.queue += "-" + stage;
for (const q of config.queues.consumers) {
  q.queue += "-" + stage;
  if (q.dead_letter_queue) q.dead_letter_queue += "-" + stage;
}
// Keep generated config at root so entrypoint and migration paths retain their meaning.
writeFileSync(configPath, JSON.stringify(config, null, 2));
if (process.argv.includes("--config-only")) {
  console.log(
    `Generated ${configPath}. Review and apply remote migrations before deployment.`,
  );
  process.exit(0);
}
execFileSync("pnpm", ["exec", "wrangler", "deploy", "--config", configPath], {
  stdio: "inherit",
});
execFileSync(
  "pnpm",
  ["--filter", "@threatsieve/web", "exec", "opennextjs-cloudflare", "build"],
  { stdio: "inherit", env: { ...process.env, API_ORIGIN: apiOrigin } },
);
const web = JSON.parse(
  readFileSync("apps/web/wrangler.jsonc", "utf8").replace(/,\s*([}\]])/g, "$1"),
);
web.name = "threatsieve-web-" + stage;
web.account_id = account;
web.vars = { API_ORIGIN: apiOrigin };
web.services = [
  { binding: "WORKER_SELF_REFERENCE", service: web.name },
  { binding: "THREATSIEVE_API", service: config.name },
];
mkdirSync("apps/web", { recursive: true });
writeFileSync("apps/web/" + configPath, JSON.stringify(web, null, 2));
execFileSync(
  "pnpm",
  [
    "--filter",
    "@threatsieve/web",
    "exec",
    "wrangler",
    "deploy",
    "--config",
    configPath,
  ],
  { stdio: "inherit" },
);
console.log(
  "Deployed " +
    stage +
    ". Database migrations are a separate, reviewed release step.",
);
