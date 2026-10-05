import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { z, ZodError } from "zod";
import type { AppEnv } from "./env";
import {
  AssessRequest,
  BulkRequest,
  FeedbackRequest,
  EnvironmentSchema,
  Scopes,
  EvidenceSchema,
  type Principal,
  type Scope,
} from "../../../packages/schemas/src/index";
import {
  authenticate,
  authorize,
  rateLimit,
  createApiKey,
} from "../../../packages/auth/src/index";
import { Repository } from "../../../packages/database/src/repository";
import {
  AppError,
  errorType,
  log,
} from "../../../packages/observability/src/index";
import { boundedText } from "../../../packages/intel/src/feeds";
import { normalise, digest } from "../../../packages/intel/src/normalise";
import { classify } from "../../../workers/classify/index";
import {
  consume,
  dispatchOutbox,
  makeJob,
} from "../../../workers/ingest/pipeline";
import {
  getFeed,
  finalizeFeeds,
  queueFeedSync,
} from "../../../workers/feed-sync/index";
import { parseIndicators } from "../../../workers/ingest/upload";
import { exportStix } from "../../../packages/stix/src/index";

type Context = {
  Bindings: AppEnv;
  Variables: { principal: Principal; requestId: string };
};
export const app = new Hono<Context>();
app.use("*", secureHeaders());
app.use("*", async (c, next) => {
  const id = crypto.randomUUID();
  c.set("requestId", id);
  c.header("X-Request-Id", id);
  c.header("Cache-Control", "no-store");
  const start = Date.now();
  await next();
  log({
    request_id: id,
    tenant_id: c.get("principal")?.tenantId,
    duration_ms: Date.now() - start,
    result: String(c.res.status),
  });
});
app.use("*", async (c, next) =>
  cors({
    origin: c.env.WEB_ORIGIN,
    credentials: true,
    allowHeaders: ["Content-Type", "Authorization", "Idempotency-Key"],
    exposeHeaders: ["X-Request-Id"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  })(c, next),
);
app.onError((error, c) => {
  if (error instanceof ZodError)
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid request",
          issues: error.issues.map((i) => ({
            path: i.path,
            message: i.message,
          })),
          request_id: c.get("requestId"),
        },
      },
      400,
    );
  if (error instanceof AppError)
    return c.json(
      {
        error: {
          code: error.code,
          message: error.message,
          request_id: c.get("requestId"),
        },
      },
      error.status,
    );
  log({
    request_id: c.get("requestId"),
    result: "error",
    error_type: errorType(error),
  });
  return c.json(
    {
      error: {
        code: "INTERNAL_ERROR",
        message: "Request could not be completed",
        request_id: c.get("requestId"),
      },
    },
    500,
  );
});
app.get("/health", (c) => c.json({ status: "ok", service: "threatsieve-api" }));
app.get("/ready", async (c) => {
  try {
    await c.env.DB.prepare("SELECT 1 FROM sources LIMIT 1").first();
    return c.json({ status: "ready" });
  } catch {
    return c.json({ status: "not-ready" }, 503);
  }
});
app.post("/v1/session", async (c) => {
  const p = await authenticate(c.env.DB, c.req.raw);
  await rateLimit(c.env.DB, p, 10);
  const token = crypto.randomUUID() + crypto.randomUUID();
  const expiry = new Date(Date.now() + 8 * 3600000).toISOString();
  await c.env.DB.prepare("INSERT INTO sessions VALUES(?,?,?,?,?)")
    .bind(await digest(token), p.tenantId, p.userId, p.keyId, expiry)
    .run();
  c.header(
    "Set-Cookie",
    `ts_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${c.env.APP_ENV === "development" ? "" : "; Secure"}`,
  );
  await new Repository(c.env.DB).audit(
    p,
    "login",
    "session",
    c.get("requestId"),
  );
  return c.json({ tenantId: p.tenantId, expiresAt: expiry });
});
app.use("/v1/*", async (c, next) => {
  const p = await authenticate(c.env.DB, c.req.raw);
  c.set("principal", p);
  await rateLimit(c.env.DB, p);
  if (
    p.kind === "session" &&
    !["GET", "HEAD", "OPTIONS"].includes(c.req.method) &&
    c.req.header("Origin") !== c.env.WEB_ORIGIN
  )
    throw new AppError("INVALID_ORIGIN", 403, "Request origin is not allowed");
  await next();
});
const scope =
  (required: Scope) =>
  async (c: import("hono").Context<Context>, next: () => Promise<void>) => {
    authorize(c.get("principal"), required);
    await next();
  };
async function json(
  c: import("hono").Context<Context>,
  max = 1024 * 1024,
): Promise<unknown> {
  if (!c.req.header("content-type")?.includes("application/json"))
    throw new AppError("CONTENT_TYPE", 400, "Expected application/json");
  try {
    return JSON.parse(await boundedText(new Response(c.req.raw.body), max));
  } catch (error) {
    if (error instanceof Error && error.message.includes("size limit"))
      throw new AppError(
        "PAYLOAD_TOO_LARGE",
        413,
        "Request body exceeds size limit",
      );
    throw new AppError("INVALID_JSON", 400, "Invalid JSON body");
  }
}
app.get("/v1/me", (c) =>
  c.json({
    tenantId: c.get("principal").tenantId,
    userId: c.get("principal").userId,
    scopes: c.get("principal").scopes,
  }),
);
app.delete("/v1/session", async (c) => {
  const cookie = c.req
    .header("cookie")
    ?.split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("ts_session="))
    ?.slice(11);
  if (cookie)
    await c.env.DB.prepare("DELETE FROM sessions WHERE hash=? AND tenant_id=?")
      .bind(await digest(cookie), c.get("principal").tenantId)
      .run();
  c.header(
    "Set-Cookie",
    "ts_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
  );
  return c.json({ signedOut: true });
});
app.post("/v1/assess", scope("assessment:write"), async (c) => {
  const input = AssessRequest.parse(await json(c));
  let observable;
  try {
    observable = await normalise(input.observable, input.type);
  } catch (error) {
    throw new AppError(
      "INVALID_OBSERVABLE",
      422,
      error instanceof Error ? error.message : "Invalid observable",
    );
  }
  const p = c.get("principal");
  const repo = new Repository(c.env.DB);
  await repo.putObservable(
    observable,
    {
      sourceId: "upload",
      sourceName: "User submission",
      retrievedAt: new Date().toISOString(),
      redistributable: false,
    },
    p.tenantId,
  );
  const result = await classify(c.env, p.tenantId, observable.id);
  await repo.audit(
    p,
    "assessment.created",
    result.assessment_id,
    c.get("requestId"),
  );
  await repo.enqueue({
    ...makeJob(
      "export",
      observable.id,
      p.tenantId,
      { assessmentId: result.assessment_id },
      c.get("requestId"),
    ),
    jobId: "export:" + result.assessment_id,
  });
  c.executionCtx.waitUntil(dispatchOutbox(c.env));
  return c.json(result);
});
app.post("/v1/assess/bulk", scope("assessment:write"), async (c) => {
  const body = BulkRequest.parse(await json(c, 16 * 1024 * 1024));
  const p = c.get("principal");
  const key = "uploads/" + p.tenantId + "/" + crypto.randomUUID() + ".json";
  const inputs = body.observables.map((v) =>
    typeof v === "string" ? { observable: v } : v,
  );
  await c.env.ARCHIVE.put(key, JSON.stringify(inputs));
  const job = makeJob("bulk", key, p.tenantId, { key }, c.get("requestId"));
  const repo = new Repository(c.env.DB);
  await repo.enqueue(job);
  await repo.audit(p, "bulk.import", job.jobId, c.get("requestId"), {
    count: inputs.length,
  });
  c.executionCtx.waitUntil(dispatchOutbox(c.env));
  return c.json(
    {
      job_id: job.jobId,
      submitted: inputs.length,
      status: "queued",
      status_url: "/v1/jobs/" + job.jobId,
    },
    202,
  );
});
app.post("/v1/uploads", scope("assessment:write"), async (c) => {
  const format = z
    .enum(["text", "csv", "json", "stix"])
    .parse(c.req.query("format") ?? "text");
  let inputs;
  try {
    inputs = parseIndicators(
      await boundedText(new Response(c.req.raw.body), 16 * 1024 * 1024),
      format,
    );
  } catch (error) {
    throw new AppError(
      "INVALID_UPLOAD",
      422,
      error instanceof Error ? error.message : "Invalid upload",
    );
  }
  const p = c.get("principal");
  const key = "uploads/" + p.tenantId + "/" + crypto.randomUUID() + ".json";
  await c.env.ARCHIVE.put(key, JSON.stringify(inputs));
  const job = makeJob("bulk", key, p.tenantId, { key }, c.get("requestId"));
  const repo = new Repository(c.env.DB);
  await repo.enqueue(job);
  await repo.audit(p, "bulk.import", job.jobId, c.get("requestId"), {
    count: inputs.length,
    format,
  });
  c.executionCtx.waitUntil(dispatchOutbox(c.env));
  return c.json(
    { job_id: job.jobId, submitted: inputs.length, status: "queued" },
    202,
  );
});
app.get("/v1/jobs/:id", scope("assessment:read"), async (c) => {
  const job = await new Repository(c.env.DB).job(
    c.get("principal").tenantId,
    c.req.param("id")!,
  );
  if (!job) throw new AppError("NOT_FOUND", 404, "Job not found");
  const counts = await c.env.DB.prepare(
    "SELECT stage,status,COUNT(*) AS count FROM pipeline_jobs WHERE tenant_id=? AND (json_extract(data,'$.payload.bulkId')=? OR id=?) GROUP BY stage,status",
  )
    .bind(c.get("principal").tenantId, c.req.param("id")!, c.req.param("id")!)
    .all();
  return c.json({ ...job, stages: counts.results });
});
app.post("/v1/jobs/:id/replay", scope("admin"), async (c) => {
  const p = c.get("principal");
  const repo = new Repository(c.env.DB);
  const existing = await repo.job(p.tenantId, c.req.param("id")!);
  if (!existing) throw new AppError("NOT_FOUND", 404, "Job not found");
  if (existing.status !== "failed")
    throw new AppError(
      "JOB_NOT_FAILED",
      409,
      "Only failed jobs can be replayed",
    );
  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE pipeline_jobs SET status='queued',lease_until=NULL WHERE id=? AND tenant_id=? AND status='failed'",
    ).bind(c.req.param("id")!, p.tenantId),
    c.env.DB.prepare("UPDATE outbox SET dispatched_at=NULL WHERE id=?").bind(
      c.req.param("id")!,
    ),
  ]);
  await repo.audit(p, "job.replay", c.req.param("id")!, c.get("requestId"));
  c.executionCtx.waitUntil(dispatchOutbox(c.env));
  return c.json({ status: "queued" });
});
app.get("/v1/assessments", scope("assessment:read"), async (c) => {
  const limit = z.coerce
    .number()
    .int()
    .min(1)
    .max(100)
    .parse(c.req.query("limit") ?? 50);
  const data = await new Repository(c.env.DB).assessments(
    c.get("principal").tenantId,
    limit,
    c.req.query("cursor"),
  );
  return c.json({
    data,
    next_cursor:
      data.length === limit
        ? btoa(
            JSON.stringify([
              data.at(-1)!.created_at,
              data.at(-1)!.assessment_id,
            ]),
          )
        : null,
  });
});
app.get("/v1/assessments/:id", scope("assessment:read"), async (c) => {
  const a = await new Repository(c.env.DB).assessment(
    c.get("principal").tenantId,
    c.req.param("id")!,
  );
  if (!a) throw new AppError("NOT_FOUND", 404, "Assessment not found");
  return c.json(a);
});
for (const [action, status] of [
  ["confirm", "confirmed"],
  ["reject", "rejected"],
  ["modify", "modified"],
  ["investigate", "needs-investigation"],
] as const)
  app.post(
    "/v1/assessments/:id/" + action,
    scope("assessment:write"),
    async (c) => {
      const input = FeedbackRequest.parse(await json(c));
      return c.json(
        await new Repository(c.env.DB).feedback(
          c.get("principal"),
          c.req.param("id")!,
          status,
          input.field,
          input.value,
          input.reason,
          c.get("requestId"),
        ),
      );
    },
  );
app.post(
  "/v1/assessments/:id/reclassify",
  scope("assessment:write"),
  async (c) => {
    const p = c.get("principal");
    const repo = new Repository(c.env.DB);
    const a = await repo.assessment(p.tenantId, c.req.param("id")!);
    if (!a) throw new AppError("NOT_FOUND", 404, "Assessment not found");
    const job = makeJob(
      "classify",
      a.observable.id,
      p.tenantId,
      { force: true },
      c.get("requestId"),
    );
    await repo.enqueue(job);
    await repo.audit(
      p,
      "assessment.reclassify",
      a.assessment_id,
      c.get("requestId"),
    );
    c.executionCtx.waitUntil(dispatchOutbox(c.env));
    return c.json({ job_id: job.jobId, status: "queued" }, 202);
  },
);
app.get("/v1/assessments/:id/stix", scope("assessment:read"), async (c) => {
  const p = c.get("principal");
  const repo = new Repository(c.env.DB);
  const a = await repo.assessment(p.tenantId, c.req.param("id")!);
  if (!a) throw new AppError("NOT_FOUND", 404, "Assessment not found");
  const bundle = exportStix(a);
  await repo.audit(p, "export", a.assessment_id, c.get("requestId"));
  return c.json(bundle, 200, {
    "Content-Type": "application/stix+json",
    "Content-Disposition": `attachment; filename="${a.assessment_id}.stix.json"`,
  });
});
app.get("/v1/observables/:id", scope("intel:read"), async (c) => {
  const repo = new Repository(c.env.DB);
  if (!(await repo.visible(c.get("principal").tenantId, c.req.param("id")!)))
    throw new AppError("NOT_FOUND", 404, "Observable not found");
  const observable = await repo.observable(c.req.param("id")!);
  if (!observable) throw new AppError("NOT_FOUND", 404, "Observable not found");
  return c.json({ observable, evidence: await repo.evidence(observable.id) });
});
for (const [route, type] of [
  ["actors", "threat-actor"],
  ["malware", "malware"],
  ["campaigns", "campaign"],
  ["attack/techniques", "attack-technique"],
] as const) {
  app.get("/v1/" + route, scope("intel:read"), async (c) => {
    const limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .parse(c.req.query("limit") ?? 50);
    const rows = await c.env.DB.prepare(
      "SELECT data FROM entities WHERE type=? AND id>? ORDER BY id LIMIT ?",
    )
      .bind(type, c.req.query("cursor") ?? "", limit)
      .all<{ data: string }>();
    const data = rows.results.map((r) => JSON.parse(r.data) as { id: string });
    return c.json({
      data,
      next_cursor: data.length === limit ? data.at(-1)?.id : null,
    });
  });
  app.get("/v1/" + route + "/:id", scope("intel:read"), async (c) => {
    const repo = new Repository(c.env.DB);
    const entity = await repo.entity(c.req.param("id")!);
    const resolved =
      entity?.type === type
        ? entity
        : (await repo.resolveAlias(c.req.param("id")!, type))[0];
    if (!resolved) throw new AppError("NOT_FOUND", 404, "Entity not found");
    return c.json({
      entity: resolved,
      relationships: await repo.edges(resolved.id),
    });
  });
}
app.get("/v1/search", scope("intel:read"), async (c) => {
  const q = z.string().trim().min(1).max(256).parse(c.req.query("q"));
  const exact = await new Repository(c.env.DB).resolveAlias(q);
  const rows = await c.env.DB.prepare(
    "SELECT data FROM entities WHERE name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 30",
  )
    .bind(q.replace(/[\\%_]/g, "\\$&") + "%")
    .all<{ data: string }>();
  const candidates = [
    ...new Map(
      [
        ...exact,
        ...rows.results.map((r) => JSON.parse(r.data) as { id: string }),
      ].map((r) => [r.id, r]),
    ).values(),
  ];
  const repo = new Repository(c.env.DB);
  const data = [];
  for (const item of candidates)
    if (await repo.visible(c.get("principal").tenantId, item.id))
      data.push(item);
  return c.json({ data });
});
app.get("/v1/entities/:id", scope("intel:read"), async (c) => {
  const repo = new Repository(c.env.DB);
  const id = c.req.param("id")!;
  if (!(await repo.visible(c.get("principal").tenantId, id)))
    throw new AppError("NOT_FOUND", 404, "Entity not found");
  const entity = await repo.entity(id);
  if (!entity) throw new AppError("NOT_FOUND", 404, "Entity not found");
  const sources = await c.env.DB.prepare(
    "SELECT provenance FROM entity_sources WHERE entity_id=?",
  )
    .bind(id)
    .all<{ provenance: string }>();
  const edges = await repo.edges(id, 30);
  const relationships = [];
  for (const edge of edges) {
    const other =
      edge.sourceEntityId === id ? edge.targetEntityId : edge.sourceEntityId;
    if (await repo.visible(c.get("principal").tenantId, other))
      relationships.push({ ...edge, entity: await repo.entity(other) });
  }
  return c.json({
    entity,
    sources: sources.results.map((row) => JSON.parse(row.provenance)),
    relationships,
    ...(entity.type === "threat-actor"
      ? {
          fingerprint: await (
            await import("../../../packages/attack/src/fingerprints")
          ).fingerprint(repo, entity),
        }
      : {}),
  });
});
app.get("/v1/graph/:id", scope("intel:read"), async (c) => {
  const depth = z.coerce
    .number()
    .int()
    .min(1)
    .max(3)
    .parse(c.req.query("depth") ?? 2);
  const repo = new Repository(c.env.DB);
  if (!(await repo.visible(c.get("principal").tenantId, c.req.param("id")!)))
    throw new AppError("NOT_FOUND", 404, "Entity not found");
  const root = await repo.entity(c.req.param("id")!);
  if (!root) throw new AppError("NOT_FOUND", 404, "Entity not found");
  const nodes = new Map([[root.id, root]]);
  const edges = new Map();
  let frontier = [root.id];
  let truncated = false;
  for (let i = 0; i < depth; i++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const edge of await repo.edges(id, 30)) {
        if (nodes.size >= 100 || edges.size >= 200) {
          truncated = true;
          break;
        }
        const target =
          edge.sourceEntityId === id
            ? edge.targetEntityId
            : edge.sourceEntityId;
        if (!(await repo.visible(c.get("principal").tenantId, target)))
          continue;
        const entity = await repo.entity(target);
        if (!entity) continue;
        edges.set(edge.id, edge);
        if (!nodes.has(target)) {
          nodes.set(target, entity);
          next.push(target);
        }
      }
    }
    frontier = next;
  }
  return c.json({
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    truncated,
  });
});
app.get("/v1/clusters", scope("intel:read"), async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT * FROM threat_clusters WHERE observable_count>=2 ORDER BY last_seen DESC LIMIT 50",
  ).all();
  return c.json({ data: rows.results });
});
app.get("/v1/clusters/:id", scope("intel:read"), async (c) => {
  const cluster = await c.env.DB.prepare(
    "SELECT * FROM threat_clusters WHERE id=?",
  )
    .bind(c.req.param("id")!)
    .first();
  if (!cluster) throw new AppError("NOT_FOUND", 404, "Cluster not found");
  const members = await c.env.DB.prepare(
    "SELECT o.data FROM cluster_members m JOIN observables o ON o.id=m.observable_id WHERE m.cluster_id=? LIMIT 100",
  )
    .bind(c.req.param("id")!)
    .all<{ data: string }>();
  return c.json({
    ...cluster,
    members: members.results.map((r) => JSON.parse(r.data)),
    actor_association: "unknown",
  });
});
app.get("/v1/feeds", scope("feeds:read"), async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT * FROM sources WHERE id NOT IN ('customer','analyst','upload','demo') ORDER BY id",
  ).all<{ id: string; enabled: number; status: string }>();
  const data = rows.results.map((source) => {
    const missing =
      (source.id === "threatfox" && !c.env.THREATFOX_AUTH_KEY) ||
      (source.id === "urlhaus" && !c.env.URLHAUS_AUTH_KEY);
    return {
      ...source,
      enabled: missing ? 0 : source.enabled,
      status: missing ? "disabled" : source.status,
    };
  });
  return c.json({ data });
});
app.get("/v1/feeds/:id/health", scope("feeds:read"), async (c) => {
  try {
    return c.json(await getFeed(c.env, c.req.param("id")!).healthCheck());
  } catch {
    return c.json({ status: "disabled", checkedAt: new Date().toISOString() });
  }
});
app.post("/v1/feeds/:id/sync", scope("feeds:write"), async (c) => {
  const id = c.req.param("id")!;
  let feed;
  try {
    feed = getFeed(c.env, id);
  } catch {
    throw new AppError(
      "FEED_DISABLED",
      409,
      "Feed is unavailable or not configured",
    );
  }
  const health = await feed.healthCheck();
  if (health.status === "disabled")
    throw new AppError(
      "FEED_DISABLED",
      409,
      health.message ?? "Feed is disabled",
    );
  const repo = new Repository(c.env.DB);
  const job = await queueFeedSync(c.env, id, c.get("requestId"));
  await repo.audit(c.get("principal"), "feed.synced", id, c.get("requestId"));
  c.executionCtx.waitUntil(dispatchOutbox(c.env));
  return c.json({ job_id: job.jobId, status: "queued" }, 202);
});
app.get("/v1/feeds/:id/jobs", scope("feeds:read"), async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT id,stage,status,error_type,updated_at FROM pipeline_jobs WHERE tenant_id IS NULL AND (entity_id=? OR json_extract(data,'$.payload.feedId')=?) AND status!='complete' ORDER BY updated_at DESC LIMIT 100",
  )
    .bind(c.req.param("id")!, c.req.param("id")!)
    .all();
  return c.json({ data: rows.results });
});
app.post(
  "/v1/feeds/:id/jobs/:jobId/replay",
  scope("feeds:write"),
  async (c) => {
    const sourceId = c.req.param("id")!;
    const jobId = c.req.param("jobId")!;
    const row = await c.env.DB.prepare(
      "SELECT status FROM pipeline_jobs WHERE id=? AND tenant_id IS NULL AND (entity_id=? OR json_extract(data,'$.payload.feedId')=? OR json_extract(data,'$.correlationId') IN (SELECT json_extract(data,'$.correlationId') FROM pipeline_jobs WHERE stage='feed-sync' AND entity_id=?))",
    )
      .bind(jobId, sourceId, sourceId, sourceId)
      .first<{ status: string }>();
    if (!row) throw new AppError("NOT_FOUND", 404, "Feed job not found");
    if (row.status !== "failed")
      throw new AppError(
        "JOB_NOT_FAILED",
        409,
        "Only failed jobs can be replayed",
      );
    await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE pipeline_jobs SET status='queued',lease_until=NULL,error_type=NULL WHERE id=?",
      ).bind(jobId),
      c.env.DB.prepare("UPDATE outbox SET dispatched_at=NULL WHERE id=?").bind(
        jobId,
      ),
    ]);
    await new Repository(c.env.DB).audit(
      c.get("principal"),
      "feed.job.replay",
      jobId,
      c.get("requestId"),
    );
    c.executionCtx.waitUntil(dispatchOutbox(c.env));
    return c.json({ status: "queued" }, 202);
  },
);
for (const action of ["confirm", "reject"] as const)
  app.post(
    "/v1/relationships/:id/" + action,
    scope("assessment:write"),
    async (c) => {
      const input = FeedbackRequest.parse(await json(c));
      const p = c.get("principal");
      const exists = await c.env.DB.prepare(
        "SELECT id FROM relationships WHERE id=?",
      )
        .bind(c.req.param("id")!)
        .first();
      if (!exists)
        throw new AppError("NOT_FOUND", 404, "Relationship not found");
      const now = new Date().toISOString();
      await c.env.DB.batch([
        c.env.DB.prepare(
          "INSERT INTO relationship_feedback VALUES(?,?,?,?,?,?,?)",
        ).bind(
          crypto.randomUUID(),
          p.tenantId,
          c.req.param("id")!,
          p.userId,
          action,
          input.reason,
          now,
        ),
        c.env.DB.prepare(
          "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)",
        ).bind(
          crypto.randomUUID(),
          p.tenantId,
          p.userId,
          "relationship." + action,
          c.req.param("id")!,
          null,
          c.get("requestId"),
          JSON.stringify(input),
          now,
        ),
      ]);
      return c.json({ decision: action, assertion_scope: "tenant" });
    },
  );
app.get("/v1/environment", scope("intel:read"), async (c) => {
  const row = await c.env.DB.prepare(
    "SELECT data FROM customer_environments WHERE tenant_id=?",
  )
    .bind(c.get("principal").tenantId)
    .first<{ data: string }>();
  return c.json(row ? JSON.parse(row.data) : EnvironmentSchema.parse({}));
});
app.put("/v1/environment", scope("admin"), async (c) => {
  const data = EnvironmentSchema.parse(await json(c));
  const p = c.get("principal");
  await c.env.DB.prepare(
    "INSERT INTO customer_environments VALUES(?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at",
  )
    .bind(p.tenantId, JSON.stringify(data), new Date().toISOString())
    .run();
  await new Repository(c.env.DB).audit(
    p,
    "customer.environment.changed",
    p.tenantId,
    c.get("requestId"),
  );
  return c.json(data);
});
app.post("/v1/observations", scope("assessment:write"), async (c) => {
  const input = z
    .object({
      observable: AssessRequest,
      evidence: EvidenceSchema.omit({
        id: true,
        observableId: true,
        sourceId: true,
        provenance: true,
        createdAt: true,
      }),
      sharingAllowed: z.boolean().default(false),
    })
    .parse(await json(c));
  const p = c.get("principal");
  const obs = await normalise(
    input.observable.observable,
    input.observable.type,
  );
  const repo = new Repository(c.env.DB);
  const provenance = {
    sourceId: "customer",
    sourceName: "Customer telemetry",
    retrievedAt: new Date().toISOString(),
    redistributable: false,
  };
  await repo.putObservable(obs, provenance, p.tenantId);
  const id = crypto.randomUUID();
  const evidence = {
    ...input.evidence,
    id,
    observableId: obs.id,
    sourceId: "customer",
    provenance,
    createdAt: new Date().toISOString(),
  };
  await c.env.DB.prepare(
    "INSERT INTO customer_observations VALUES(?,?,?,?,?,?)",
  )
    .bind(
      id,
      p.tenantId,
      obs.id,
      JSON.stringify(evidence),
      evidence.observedAt ?? evidence.createdAt,
      Number(input.sharingAllowed),
    )
    .run();
  await repo.audit(p, "customer.observation.created", id, c.get("requestId"));
  return c.json({ id, observableId: obs.id }, 201);
});
app.post("/v1/api-keys", scope("admin"), async (c) => {
  const input = z
    .object({
      name: z.string().min(1).max(100),
      scopes: z.array(Scopes).min(1),
      expiresAt: z.iso.datetime().optional(),
    })
    .parse(await json(c));
  const key = await createApiKey(
    c.env.DB,
    c.get("principal"),
    input.name,
    input.scopes,
    input.expiresAt,
  );
  await new Repository(c.env.DB).audit(
    c.get("principal"),
    "api_key.created",
    key.id,
    c.get("requestId"),
  );
  return c.json(key, 201);
});
app.delete("/v1/api-keys/:id", scope("admin"), async (c) => {
  await c.env.DB.prepare(
    "UPDATE api_keys SET revoked_at=? WHERE tenant_id=? AND id=?",
  )
    .bind(
      new Date().toISOString(),
      c.get("principal").tenantId,
      c.req.param("id")!,
    )
    .run();
  await new Repository(c.env.DB).audit(
    c.get("principal"),
    "api_key.revoked",
    c.req.param("id")!,
    c.get("requestId"),
  );
  return c.json({ revoked: true });
});
app.get("/v1/exports", scope("assessment:read"), async (c) => {
  const limit = z.coerce
    .number()
    .int()
    .min(1)
    .max(100)
    .parse(c.req.query("limit") ?? 50);
  const cursor = c.req.query("cursor") ?? "";
  const rows = await c.env.DB.prepare(
    "SELECT id,assessment_id,created_at,created_at||'|'||id AS cursor FROM exports WHERE tenant_id=? AND created_at||'|'||id>? ORDER BY created_at,id LIMIT ?",
  )
    .bind(c.get("principal").tenantId, cursor, limit)
    .all();
  return c.json({ data: rows.results });
});
app.get("/v1/exports/:id", scope("assessment:read"), async (c) => {
  const row = await c.env.DB.prepare(
    "SELECT r2_key FROM exports WHERE tenant_id=? AND id=?",
  )
    .bind(c.get("principal").tenantId, c.req.param("id")!)
    .first<{ r2_key: string }>();
  if (!row) throw new AppError("NOT_FOUND", 404, "Export not found");
  const file = await c.env.ARCHIVE.get(row.r2_key);
  if (!file) throw new AppError("NOT_FOUND", 404, "Export archive not found");
  await new Repository(c.env.DB).audit(
    c.get("principal"),
    "export.download",
    c.req.param("id")!,
    c.get("requestId"),
  );
  return new Response(file.body, {
    headers: {
      "Content-Type": "application/stix+json",
      "Cache-Control": "no-store",
    },
  });
});
app.get("/v1/ops", scope("admin"), async (c) => {
  const tenant = c.get("principal").tenantId;
  const jobs = await c.env.DB.prepare(
    "SELECT stage,status,COUNT(*) AS count FROM pipeline_jobs WHERE tenant_id=? GROUP BY stage,status",
  )
    .bind(tenant)
    .all();
  const usage = await c.env.DB.prepare(
    "SELECT substr(created_at,1,10) AS day,model,SUM(input_tokens) AS input_tokens,COUNT(*) AS calls FROM classification_runs WHERE tenant_id=? GROUP BY day,model ORDER BY day DESC LIMIT 60",
  )
    .bind(tenant)
    .all();
  return c.json({ jobs: jobs.results, usage: usage.results });
});
app.notFound((c) =>
  c.json(
    {
      error: {
        code: "NOT_FOUND",
        message: "Endpoint not found",
        request_id: c.get("requestId"),
      },
    },
    404,
  ),
);
export default {
  fetch: app.fetch,
  queue: consume,
  async scheduled(
    event: ScheduledController,
    env: AppEnv,
    ctx: ExecutionContext,
  ) {
    ctx.waitUntil(
      (async () => {
        if (event.cron === "17 */6 * * *") {
          const sources = await env.DB.prepare(
            "SELECT id FROM sources WHERE enabled=1 AND id IN ('mitre','threatfox','misp','urlhaus','feodo','cisa-kev')",
          ).all<{ id: string }>();
          for (const source of sources.results) {
            if (
              (await getFeed(env, source.id).healthCheck()).status ===
              "disabled"
            )
              continue;
            await queueFeedSync(env, source.id);
          }
        }
        await dispatchOutbox(env);
        await finalizeFeeds(env);
        await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at<?")
          .bind(Math.floor(Date.now() / 60000))
          .run();
      })(),
    );
  },
} satisfies ExportedHandler<AppEnv, unknown>;
