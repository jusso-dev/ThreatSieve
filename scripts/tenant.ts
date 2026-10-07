import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { digest } from "../packages/intel/src/normalise";
async function main() {
  const name = process.argv[2];
  const email = process.argv[3];
  const remote = process.argv.includes("--remote");
  if (!name || !email || !email.includes("@"))
    throw new Error(
      'Usage: pnpm tenant:create "Organisation" admin@example.com [--remote]',
    );
  const credentialName =
    process.env.THREATSIEVE_CREDENTIALS_NAME ?? "tenant-credentials.local.json";
  if (!/^[a-z0-9_-]+\.local\.json$/.test(credentialName))
    throw new Error(
      "Credential filename must end in .local.json and contain only letters, digits, underscores or hyphens.",
    );
  const credentialPath = "artifacts/" + credentialName;
  if (existsSync(credentialPath))
    throw new Error(
      "Credential file already exists. Choose a new THREATSIEVE_CREDENTIALS_NAME to preserve existing keys.",
    );
  const id = crypto.randomUUID();
  const userId = crypto.randomUUID();
  const key =
    "ts_" +
    crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "");
  const now = new Date().toISOString();
  const q = (value: string) => "'" + value.replaceAll("'", "''") + "'";
  const sql = [
    `INSERT INTO tenants(id,name,created_at,slug) VALUES(${[id, name, now, "workspace-" + id].map(q).join(",")});`,
    `INSERT OR IGNORE INTO users(id,email,created_at,name,updated_at) VALUES(${[userId, email.toLowerCase(), now, email, now].map(q).join(",")});`,
    `INSERT INTO tenant_members(tenant_id,user_id,role,id,created_at) SELECT ${q(id)},id,'admin',${q(crypto.randomUUID())},${q(now)} FROM users WHERE email=${q(email.toLowerCase())};`,
    `INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) SELECT ${q(crypto.randomUUID())},${q(id)},id,'Bootstrap administrator',${q(await digest(key))},'["admin"]',${q(now)} FROM users WHERE email=${q(email.toLowerCase())};`,
  ].join("\n");
  mkdirSync("artifacts", { recursive: true });
  const file = "artifacts/tenant.local.sql";
  writeFileSync(file, sql, { mode: 0o600 });
  const config = process.env.THREATSIEVE_WRANGLER_CONFIG ?? "wrangler.jsonc";
  execFileSync(
    "pnpm",
    [
      "exec",
      "wrangler",
      "d1",
      "execute",
      "DB",
      "--config",
      config,
      remote ? "--remote" : "--local",
      "--file",
      file,
    ],
    { stdio: "inherit" },
  );
  writeFileSync(
    credentialPath,
    JSON.stringify({ tenantId: id, apiKey: key }, null, 2),
    { mode: 0o600, flag: "wx" },
  );
  console.log(
    "Tenant provisioned. One-time key saved to " + credentialPath + ".",
  );
}
main().catch((e) => {
  console.error(e instanceof Error ? e.message : "Provision failed");
  process.exitCode = 1;
});
