import type { AppEnv } from "../../../apps/api/src/env";
import { getFeed } from "../../../workers/feed-sync/index";
import type {
  OperationalAlert,
  OperationalReport,
} from "../../schemas/src/operations";
const required = new Set([
  "mitre",
  "misp",
  "threatfox",
  "urlhaus",
  "feodo",
  "cisa-kev",
]);
type JobRow = OperationalReport["jobs"][number];
/**
 * Pipeline job summary SQL for the operations report, one statement per scope.
 *
 * pipeline_jobs is append-only, so the old single-predicate form
 * `(tenant_id=? OR tenant_id IS NULL) AND (status!='complete' OR updated_at>=?)`
 * could not seek on `jobs_operational_scope` and read every global job ever
 * created. Each compound term here is an equality or range seek on
 * (tenant_id,status,updated_at), so the rows read track live work rather than
 * table history. D1 allows at most five compound terms, hence two statements.
 */
const jobsSql = (scope: string, since: string) =>
  "SELECT stage,status,COUNT(*) AS count,MIN(created_at) AS oldest,SUM(CASE WHEN result IS NOT NULL AND status!='complete' THEN 1 ELSE 0 END) AS stale_result_count FROM (" +
  [
    ...["queued", "running", "failed"].map(
      (status) =>
        `SELECT stage,status,created_at,result FROM pipeline_jobs WHERE ${scope} AND status='${status}'`,
    ),
    `SELECT stage,status,created_at,result FROM pipeline_jobs WHERE ${scope} AND status='complete' AND updated_at>=${since}`,
  ].join(" UNION ALL ") +
  ") GROUP BY stage,status";
/** Binds (tenant, since). */
export const TENANT_JOBS_SQL = jobsSql("tenant_id=?1", "?2");
/** Binds (since). */
export const GLOBAL_JOBS_SQL = jobsSql("tenant_id IS NULL", "?1");
export async function operationalJobs(
  db: D1Database,
  tenant: string,
  since: string,
): Promise<JobRow[]> {
  const [own, global] = await Promise.all([
    db.prepare(TENANT_JOBS_SQL).bind(tenant, since).all<JobRow>(),
    db.prepare(GLOBAL_JOBS_SQL).bind(since).all<JobRow>(),
  ]);
  const merged = new Map<string, JobRow>();
  for (const row of [...own.results, ...global.results]) {
    const key = row.stage + "\u0000" + row.status,
      prev = merged.get(key);
    merged.set(
      key,
      prev
        ? {
            ...prev,
            count: prev.count + row.count,
            oldest:
              prev.oldest && row.oldest
                ? prev.oldest < row.oldest
                  ? prev.oldest
                  : row.oldest
                : (prev.oldest ?? row.oldest),
            stale_result_count:
              prev.stale_result_count + row.stale_result_count,
          }
        : { ...row },
    );
  }
  return [...merged.values()].sort(
    (a, b) =>
      (a.stage < b.stage ? -1 : a.stage > b.stage ? 1 : 0) ||
      (a.status < b.status ? -1 : a.status > b.status ? 1 : 0),
  );
}
export function operationalAlerts(
  report: Omit<OperationalReport, "alerts" | "status">,
  now = Date.now(),
): OperationalAlert[] {
  const alerts: OperationalAlert[] = [];
  const age = (at: string | null) =>
    at ? Math.max(0, now - Date.parse(at)) : Infinity;
  const add = (
    code: string,
    severity: OperationalAlert["severity"],
    subject: string,
    message: string,
  ) => alerts.push({ code, severity, subject, message });
  if (age(report.heartbeat) > 15 * 60000)
    add(
      "SCHEDULER_STALE",
      "critical",
      "scheduler",
      "No successful pipeline maintenance heartbeat within 15 minutes.",
    );
  if (age(report.archive_heartbeat) > 15 * 60000)
    add(
      "ARCHIVE_HEARTBEAT_STALE",
      "critical",
      "archive",
      "No successful archive write heartbeat within 15 minutes.",
    );
  for (const f of report.feeds) {
    if (!f.configured) {
      if (required.has(f.id))
        add(
          "FEED_NOT_CONFIGURED",
          "warning",
          f.id,
          "Required source needs credentials or configuration.",
        );
      continue;
    }
    if (!f.enabled) continue;
    if (f.status === "error")
      add(
        "FEED_FAILED",
        "critical",
        f.id,
        "Source processing has failed jobs. Inspect the source before replaying.",
      );
    else if (!f.last_sync)
      add(
        "FEED_INITIAL_SYNC",
        "warning",
        f.id,
        "The first complete source sync has not been recorded.",
      );
    else if (age(f.last_sync) > 12 * 3600000)
      add(
        "FEED_STALE",
        "critical",
        f.id,
        "Source has not completed a sync in 12 hours.",
      );
    if (f.status === "degraded")
      add(
        "FEED_QUARANTINE",
        "warning",
        f.id,
        "Source records were quarantined; inspect rejection details.",
      );
  }
  for (const j of report.jobs) {
    if (j.stale_result_count)
      add(
        "PIPELINE_STATE_CONFLICT",
        "critical",
        j.stage,
        "Committed results exist on unfinished jobs; investigate delivery state.",
      );
    if (j.status === "failed")
      add(
        "PIPELINE_FAILED",
        "critical",
        j.stage,
        "Processing jobs exhausted delivery or execution retries.",
      );
    else if (
      ["queued", "running"].includes(j.status) &&
      age(j.oldest) > 15 * 60000
    )
      add(
        "PIPELINE_LAG",
        "critical",
        j.stage,
        "Pending work is older than 15 minutes.",
      );
  }
  if (report.outbox.pending && age(report.outbox.oldest) > 10 * 60000)
    add(
      "OUTBOX_LAG",
      "critical",
      "outbox",
      "Unpublished work has waited longer than 10 minutes.",
    );
  if (report.usage.calls >= report.usage.daily_limit * 0.8)
    add(
      "CLASSIFICATION_BUDGET",
      "warning",
      "classifier",
      "Workspace has used at least 80% of its daily classification allowance.",
    );
  for (const c of report.integrations) {
    if (c.status === "error")
      add(
        "CONNECTOR_ERROR",
        "critical",
        c.connector_id,
        "OpenCTI connector reported a failed poll or delivery.",
      );
    if (age(c.last_poll_at) > 10 * 60000)
      add(
        "CONNECTOR_STALE",
        "critical",
        c.connector_id,
        "OpenCTI connector heartbeat is older than 10 minutes.",
      );
  }
  return alerts;
}
export async function operationalReport(
  env: AppEnv,
  tenant: string,
): Promise<OperationalReport> {
  const now = new Date(),
    since = new Date(now.getTime() - 86400000).toISOString(),
    day = now.toISOString().slice(0, 10);
  const [heartbeat, archive, feeds, jobs, outbox, usage, integrations] =
    await Promise.all([
      env.DB.prepare(
        "SELECT updated_at FROM operational_heartbeats WHERE name='pipeline'",
      ).first<{ updated_at: string }>(),
      env.ARCHIVE.head("ops/pipeline-heartbeat.json"),
      env.DB.prepare(
        "SELECT id,name,status,enabled,last_sync,next_sync,records_processed,records_added,records_updated,errors FROM sources WHERE id NOT IN ('customer','analyst','upload','demo') ORDER BY id",
      ).all<Omit<OperationalReport["feeds"][number], "configured">>(),
      operationalJobs(env.DB, tenant, since),
      env.DB.prepare(
        "SELECT COUNT(*) AS pending,MIN(o.created_at) AS oldest FROM outbox o JOIN pipeline_jobs p ON p.id=o.id WHERE o.dispatched_at IS NULL AND (p.tenant_id=? OR p.tenant_id IS NULL)",
      )
        .bind(tenant)
        .first<{ pending: number; oldest: string | null }>(),
      env.DB.prepare(
        "SELECT COALESCE((SELECT count FROM inference_budget WHERE tenant_id=? AND day=?),0) AS calls,COALESCE((SELECT SUM(input_tokens) FROM classification_runs WHERE tenant_id=? AND created_at>=?),0) AS input_tokens",
      )
        .bind(tenant, day, tenant, day)
        .first<{ calls: number; input_tokens: number }>(),
      env.DB.prepare(
        "SELECT connector_id,last_poll_at,last_success_at,status,error_type,version FROM integration_heartbeats WHERE tenant_id=? ORDER BY connector_id LIMIT 100",
      )
        .bind(tenant)
        .all<OperationalReport["integrations"][number]>(),
    ]);
  const configured = await Promise.all(
    feeds.results.map(async (f) => {
      let available = false;
      try {
        available =
          (await getFeed(env, f.id).healthCheck()).status !== "disabled";
      } catch {
        /* Enrichment adapters are not scheduled collection feeds. */
      }
      return { ...f, configured: available };
    }),
  );
  const report: Omit<OperationalReport, "alerts" | "status"> = {
    schema_version: "1.0",
    checked_at: now.toISOString(),
    heartbeat: heartbeat?.updated_at ?? null,
    archive_heartbeat: archive?.uploaded.toISOString() ?? null,
    feeds: configured,
    jobs,
    outbox: outbox ?? { pending: 0, oldest: null },
    usage: {
      calls: usage?.calls ?? 0,
      input_tokens: usage?.input_tokens ?? 0,
      daily_limit: Number(env.DAILY_CLASSIFICATION_LIMIT) || 10000,
    },
    integrations: integrations.results,
  };
  const alerts = operationalAlerts(report, now.getTime());
  return {
    ...report,
    alerts,
    status: alerts.some((a) => a.severity === "critical")
      ? "critical"
      : alerts.length
        ? "degraded"
        : "healthy",
  };
}
export async function recordMaintenanceHeartbeat(env: AppEnv) {
  const at = new Date().toISOString();
  await env.ARCHIVE.put(
    "ops/pipeline-heartbeat.json",
    JSON.stringify({ at, schema_version: "1.0" }),
  );
  await env.DB.prepare(
    "INSERT INTO operational_heartbeats VALUES('pipeline',?) ON CONFLICT(name) DO UPDATE SET updated_at=excluded.updated_at",
  )
    .bind(at)
    .run();
}
