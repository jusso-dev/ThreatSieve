import { writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { buildDemoSeed } from "./demo-data";
import { exportStix } from "../packages/stix/src/index";
async function main() {
  const { statements, tenant, token, firstAssessment } = await buildDemoSeed();
  mkdirSync("artifacts", { recursive: true });
  writeFileSync(
    "artifacts/demo-assessment.json",
    JSON.stringify(firstAssessment, null, 2),
  );
  writeFileSync(
    "artifacts/demo.stix.json",
    JSON.stringify(exportStix(firstAssessment), null, 2),
  );
  writeFileSync("artifacts/seed.local.sql", statements.join("\n"));
  execFileSync(
    "pnpm",
    [
      "exec",
      "wrangler",
      "d1",
      "execute",
      "threatsieve",
      "--local",
      "--file",
      "artifacts/seed.local.sql",
    ],
    { stdio: "inherit" },
  );
  writeFileSync(
    "credentials.local.json",
    JSON.stringify({ apiKey: token, tenantId: tenant }, null, 2),
    { mode: 0o600 },
  );
  writeFileSync(
    "apps/web/.env.local",
    "API_ORIGIN=http://127.0.0.1:8787\nDEVELOPMENT_API_KEY=" + token + "\n",
    { mode: 0o600 },
  );
  console.log(
    "Seeded six labelled synthetic scenarios. Local credential saved to credentials.local.json; pnpm dev opens the demonstration workspace.",
  );
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Seed failed");
  process.exitCode = 1;
});
