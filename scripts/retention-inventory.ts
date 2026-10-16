/** Read-only lifecycle inventory. This command contains no deletion path. */
import { execFileSync } from "node:child_process";
import { z } from "zod";

if (!process.argv.includes("--before"))
  throw new Error(
    "Use --before ISO_TIMESTAMP; this is an inventory, not retention approval",
  );
const cutoff = z.iso
  .datetime()
  .parse(process.argv[process.argv.indexOf("--before") + 1]);
const config =
  process.env.THREATSIEVE_WRANGLER_CONFIG ?? "wrangler.staging.local.json";
// The timestamp is schema validated; SQL and output contain no tenant or job IDs.
const sql = [
  "SELECT 'pipeline_jobs' AS kind,status,COUNT(*) AS total,SUM(created_at<'" +
    cutoff +
    "') AS older_than_cutoff FROM pipeline_jobs GROUP BY status",
  "SELECT 'outbox' AS kind,CASE WHEN dispatched_at IS NULL THEN 'undelivered' ELSE 'delivered' END AS status,COUNT(*) AS total,SUM(created_at<'" +
    cutoff +
    "') AS older_than_cutoff FROM outbox GROUP BY dispatched_at IS NULL",
  "SELECT 'intelligence_changes' AS kind,COUNT(*) AS total,SUM(created_at<'" +
    cutoff +
    "') AS older_than_cutoff FROM intelligence_changes",
  "SELECT 'intelligence_events' AS kind,COUNT(*) AS total,SUM(created_at<'" +
    cutoff +
    "') AS older_than_cutoff FROM intelligence_events",
  "SELECT 'active_feed_locks' AS kind,COUNT(*) AS protected_references FROM feed_locks",
  "SELECT 'unfinished_jobs' AS kind,COUNT(*) AS protected_references FROM pipeline_jobs WHERE status!='complete' OR result IS NULL",
].join(";");
try {
  const raw = execFileSync(
    "pnpm",
    [
      "exec",
      "wrangler",
      "d1",
      "execute",
      "DB",
      process.argv.includes("--remote") ? "--remote" : "--local",
      "--config",
      config,
      "--command",
      sql,
      "--json",
    ],
    {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const results = z
    .array(
      z.object({
        success: z.literal(true),
        results: z.array(z.record(z.string(), z.unknown())),
      }),
    )
    .parse(JSON.parse(raw));
  console.log(
    JSON.stringify(
      {
        mode: "inventory-only",
        cutoff,
        policy_approved: false,
        deletion_candidates: null,
        archive_lifecycle:
          "Unconfigured; inventory object counts and recovery references separately before proposing expiry",
        tables: results.flatMap((r) => r.results),
      },
      null,
      2,
    ),
  );
} catch {
  console.error(
    "Retention inventory failed; inspect private database/configuration diagnostics",
  );
  process.exitCode = 1;
}
