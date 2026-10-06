/** Repair committed global jobs overwritten by legacy late DLQ deliveries. Defaults to inspection. */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { z } from "zod";
const config =
  process.env.THREATSIEVE_WRANGLER_CONFIG ?? "wrangler.deploy.local.json";
const remote = process.argv.includes("--remote"),
  apply = process.argv.includes("--apply");
function sql(command: string) {
  return z
    .array(
      z.object({
        results: z.array(z.record(z.string(), z.unknown())),
        success: z.boolean(),
      }),
    )
    .parse(
      JSON.parse(
        execFileSync(
          "pnpm",
          [
            "exec",
            "wrangler",
            "d1",
            "execute",
            "DB",
            remote ? "--remote" : "--local",
            "--config",
            config,
            "--command",
            command,
            "--json",
          ],
          { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
        ),
      ),
    );
}
const predicate =
  "tenant_id IS NULL AND result IS NOT NULL AND status!='complete'";
const before = sql(
  "SELECT stage,COUNT(*) AS count FROM pipeline_jobs WHERE " +
    predicate +
    " GROUP BY stage",
);
console.log(
  JSON.stringify({
    mode: apply ? "repair" : "inspect",
    committedJobs: before.flatMap((x) => x.results),
  }),
);
if (apply) {
  const at = new Date().toISOString(),
    id = crypto.randomUUID();
  const tenant = z
    .uuid()
    .parse(
      process.env.THREATSIEVE_OPERATOR_TENANT ??
        JSON.parse(
          readFileSync("artifacts/tenant-credentials.local.json", "utf8"),
        ).tenantId,
    );
  const commands = [
    "UPDATE pipeline_jobs SET status='complete',error_type=NULL,lease_until=NULL,data=json_set(data,'$.generation',COALESCE(json_extract(data,'$.generation'),0)+1),updated_at='" +
      at +
      "' WHERE " +
      predicate,
    "UPDATE outbox SET dispatched_at=COALESCE(dispatched_at,'" +
      at +
      "'),lease_until=NULL,dispatch_token=NULL WHERE id IN (SELECT id FROM pipeline_jobs WHERE tenant_id IS NULL AND status='complete')",
    "INSERT INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES('" +
      id +
      "','" +
      tenant +
      "','operator:recovery','pipeline.committed_state_restored','global-feed-pipeline','" +
      id +
      "','{\"reason\":\"Restore committed results overwritten by legacy stale dead-letter deliveries\"}','" +
      at +
      "')",
  ];
  // Wrangler submits these reviewed statements as one D1 execution; all repairs are idempotent.
  const result = sql(commands.join(";"));
  writeFileSync(
    "artifacts/pipeline-recovery-result.local.json",
    JSON.stringify({ at, before, result }, null, 2),
    { mode: 0o600 },
  );
  console.log(
    "Committed global job state restored; unfinished jobs were not marked successful.",
  );
}

if (apply && process.argv.includes("--replay-unfinished")) {
  const at = new Date().toISOString(),
    cutoff = new Date(Date.now() - 3600000).toISOString(),
    id = crypto.randomUUID();
  const tenant = z
    .uuid()
    .parse(
      process.env.THREATSIEVE_OPERATOR_TENANT ??
        JSON.parse(
          readFileSync("artifacts/tenant-credentials.local.json", "utf8"),
        ).tenantId,
    );
  const eligible =
    "tenant_id IS NULL AND result IS NULL AND (status='failed' OR (status='queued' AND updated_at<'" +
    cutoff +
    "'))";
  const candidates = sql(
    "SELECT stage,status,COUNT(*) AS count FROM pipeline_jobs WHERE " +
      eligible +
      " GROUP BY stage,status",
  );
  const result = sql(
    [
      "UPDATE pipeline_jobs SET status='queued',attempt=0,error_type=NULL,lease_until=NULL,data=json_set(data,'$.generation',COALESCE(json_extract(data,'$.generation'),0)+1),updated_at='" +
        at +
        "' WHERE " +
        eligible,
      "UPDATE outbox SET data=(SELECT data FROM pipeline_jobs WHERE id=outbox.id),dispatched_at=NULL,lease_until=NULL,dispatch_token=NULL WHERE id IN (SELECT id FROM pipeline_jobs WHERE tenant_id IS NULL AND status='queued' AND updated_at='" +
        at +
        "')",
      "INSERT INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES('" +
        id +
        "','" +
        tenant +
        "','operator:recovery','pipeline.unfinished_replayed','global-feed-pipeline','" +
        id +
        "','{}','" +
        at +
        "')",
    ].join(";"),
  );
  writeFileSync(
    "artifacts/pipeline-unfinished-replay.local.json",
    JSON.stringify({ at, candidates, result }, null, 2),
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({ replayed: candidates.flatMap((x) => x.results) }),
  );
}
