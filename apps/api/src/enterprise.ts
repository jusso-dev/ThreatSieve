import {
  getPackage,
  requestPackage,
} from "../../../packages/enterprise/src/packages";
import { digest } from "../../../packages/intel/src/normalise";
import { WorkObjectSchema } from "../../../packages/schemas/src/enterprise";
import { integrationTargets } from "../../../packages/enterprise/src/integrations";
import { taxiiRoutes } from "./taxii";
import { publishCollection } from "../../../packages/enterprise/src/taxii";
import {
  queueBackfill,
  scheduleOperations,
} from "../../../packages/enterprise/src/automation";
import { dispatchOutbox } from "../../../workers/ingest/pipeline";
import { AssessRequest } from "../../../packages/schemas/src/index";
import { normalise } from "../../../packages/intel/src/normalise";
import {
  exportWorkspace,
  exportMisp,
  reportHtml,
  csvCell,
} from "../../../packages/enterprise/src/export";
import { Hono } from "hono";
import { z } from "zod";
import type { ApiContext } from "./context";
import { authorize } from "../../../packages/auth/src/index";
import { boundedText } from "../../../packages/intel/src/feeds";
import { AppError } from "../../../packages/observability/src/index";
import {
  WorkKind,
  WorkInput,
  WorkUpdate,
  SourceRating,
} from "../../../packages/schemas/src/enterprise";
import {
  OperationsRepository,
  Browse,
} from "../../../packages/enterprise/src/repository";
import {
  dossier,
  cachedCoverage,
} from "../../../packages/enterprise/src/intelligence";
const routes = new Hono<ApiContext>();
const repo = (c: import("hono").Context<ApiContext>) =>
  new OperationsRepository(c.env.DB, c.get("principal"));
export async function enterpriseJson(
  c: import("hono").Context<ApiContext>,
): Promise<unknown> {
  if (!c.req.header("content-type")?.includes("application/json"))
    throw new AppError("CONTENT_TYPE", 400, "Send application/json.");
  let raw: string;
  try {
    raw = await boundedText(new Response(c.req.raw.body), 131072);
  } catch {
    throw new AppError(
      "PAYLOAD_TOO_LARGE",
      413,
      "This request exceeds the 128 KB limit.",
    );
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new AppError("INVALID_JSON", 400, "The request is not valid JSON.");
  }
}
routes.use("*", async (c, next) => {
  authorize(
    c.get("principal"),
    c.req.method === "GET" || /\/notifications\/[^/]+\/read$/.test(c.req.path)
      ? "intel:read"
      : "assessment:write",
  );
  await next();
  if (c.req.method !== "GET" && c.res.status < 400)
    c.executionCtx.waitUntil(
      (async () => {
        await scheduleOperations(c.env.DB);
        await dispatchOutbox(c.env);
      })(),
    );
});
routes.get("/integrations", (c) =>
  c.json({
    data: integrationTargets(
      c.env.INTEGRATION_TARGETS,
      c.get("principal").tenantId,
    ).map((t) => ({ id: t.id, name: t.name })),
  }),
);
routes.get("/source-ratings", async (c) => {
  const r = repo(c);
  const rows = await r.db
    .prepare(
      "SELECT s.id,s.reliability AS default_weight,r.reliability,r.evidence_rating,r.rationale FROM sources s LEFT JOIN source_ratings r ON r.tenant_id=? AND r.source_id=s.id ORDER BY s.id",
    )
    .bind(r.tenant)
    .all();
  return c.json({ data: rows.results });
});
routes.get("/workspace/reference-labels", async (c) => {
  const r = repo(c),
    refs = z
      .array(
        z.object({
          type: z.enum([
            "entity",
            "evidence",
            "assessment",
            "requirement",
            "investigation",
            "watchlist",
            "collection",
            "report",
          ]),
          id: z.string().max(200),
        }),
      )
      .max(100)
      .parse(JSON.parse(z.string().max(25000).parse(c.req.query("refs"))));
  const labels: Record<string, string> = {};
  for (const ref of refs) {
    try {
      let name = ref.id;
      if (ref.type === "entity") {
        if (!(await r.intel.visible(r.tenant, ref.id))) continue;
        name = (await r.intel.entity(ref.id))?.name ?? ref.id;
      } else if (ref.type === "assessment") {
        const a = await r.intel.assessment(r.tenant, ref.id);
        if (!a) continue;
        name = a.observable.normalizedValue + " · assessment";
      } else if (ref.type === "evidence") {
        const e = await r.evidence(ref.id);
        name =
          e.provenance.sourceName +
          " · " +
          (typeof e.data.description === "string"
            ? e.data.description.slice(0, 120)
            : e.type);
      } else name = (await r.get(ref.id, ref.type)).title;
      labels[ref.type + ":" + ref.id] = name;
    } catch (e) {
      if (!(e instanceof AppError) || e.status !== 404) throw e;
    }
  }
  return c.json({ labels });
});
routes.get("/workspace/members", async (c) =>
  c.json({ data: await repo(c).members() }),
);
routes.get("/workspace/search", async (c) => {
  const q = z.string().trim().min(1).max(200).parse(c.req.query("q"));
  const r = repo(c);
  const pages = await Promise.all(
    WorkKind.options.map((kind) => r.list(kind, q, "", "", 10)),
  );
  return c.json({
    data: pages
      .flatMap((p) => p.data)
      .map((o) => ({
        id: o.id,
        name: o.title,
        type: o.kind,
        status: o.status,
      })),
  });
});
for (const [path, kind] of Object.entries({
  requirements: "requirement",
  investigations: "investigation",
  watchlists: "watchlist",
  collections: "collection",
  reports: "report",
  playbooks: "playbook",
}) as [string, z.infer<typeof WorkKind>][]) {
  routes.get("/" + path, async (c) => {
    const f = Browse.parse(c.req.query());
    const r = repo(c),
      page = await r.list(kind, f.q, f.status, f.cursor, f.limit);
    const metrics =
      kind === "requirement"
        ? await c.env.DB.prepare(
            "SELECT requirement_id,revision,data FROM requirement_metrics WHERE tenant_id=? AND requirement_id IN (SELECT value FROM json_each(?))",
          )
            .bind(r.tenant, JSON.stringify(page.data.map((o) => o.id)))
            .all<{ requirement_id: string; revision: number; data: string }>()
        : { results: [] };
    return c.json({
      ...page,
      data: page.data.map((o) => {
        const m = metrics.results.find(
          (m) => m.requirement_id === o.id && m.revision === o.revision,
        );
        return { ...o, ...(m ? { metrics: JSON.parse(m.data) } : {}) };
      }),
    });
  });
  routes.post("/" + path, async (c) => {
    if (kind === "playbook") authorize(c.get("principal"), "admin");
    const input = WorkInput.parse({
      ...z.record(z.string(), z.unknown()).parse(await enterpriseJson(c)),
      kind,
    });
    if (input.kind === "playbook")
      for (const action of input.actions)
        if (
          action.type === "send-webhook" &&
          !integrationTargets(
            c.env.INTEGRATION_TARGETS,
            c.get("principal").tenantId,
          ).some((t) => t.id === action.target)
        )
          throw new AppError(
            "INVALID_TARGET",
            400,
            "Choose a configured integration for this workspace.",
          );
    const r = repo(c),
      object = await r.save(input);
    await queueBackfill(r, object);
    if (object.kind === "requirement") await cachedCoverage(r, object);
    return c.json(object, 201);
  });
  routes.get("/" + path + "/:id", async (c) => {
    const r = repo(c),
      object = await r.get(c.req.param("id")!, kind);
    return c.json({
      object,
      history: await r.history(object.id),
      ...(kind === "requirement"
        ? { metrics: await cachedCoverage(r, object) }
        : {}),
    });
  });
  routes.put("/" + path + "/:id", async (c) => {
    if (kind === "playbook") authorize(c.get("principal"), "admin");
    const input = WorkUpdate.parse(await enterpriseJson(c));
    if (input.object.kind !== kind)
      throw new AppError(
        "KIND_MISMATCH",
        400,
        "Record type cannot be changed.",
      );
    if (input.object.kind === "playbook")
      for (const action of input.object.actions)
        if (
          action.type === "send-webhook" &&
          !integrationTargets(
            c.env.INTEGRATION_TARGETS,
            c.get("principal").tenantId,
          ).some((t) => t.id === action.target)
        )
          throw new AppError(
            "INVALID_TARGET",
            400,
            "Choose a configured integration for this workspace.",
          );
    const r = repo(c),
      object = await r.save(
        input.object,
        c.req.param("id")!,
        input.expected_revision,
        input.reason,
      );
    await queueBackfill(r, object);
    if (object.kind === "requirement") await cachedCoverage(r, object);
    return c.json(object);
  });
  routes.post("/" + path + "/:id/notes", async (c) => {
    await repo(c).get(c.req.param("id")!, kind);
    return c.json(
      await repo(c).note(c.req.param("id")!, await enterpriseJson(c)),
      201,
    );
  });
}
routes.get("/workspace/references", async (c) => {
  const r = repo(c),
    type = z
      .enum([
        "entity",
        "evidence",
        "assessment",
        "requirement",
        "investigation",
        "watchlist",
        "collection",
        "report",
      ])
      .parse(c.req.query("type") ?? "entity"),
    q = z
      .string()
      .max(200)
      .parse(c.req.query("q") ?? "");
  if (type === "entity") {
    const page = await r.intel.browseEntities(r.tenant, { q, limit: 20 });
    return c.json({
      data: page.data.map((e) => ({ id: e.id, name: e.name, type: e.type })),
    });
  }
  if (type === "assessment") {
    const data = await r.intel.assessments(r.tenant, 20, undefined, { q });
    return c.json({
      data: data.map((a) => ({
        id: a.assessment_id,
        name:
          a.observable.normalizedValue +
          " · " +
          (a.effective_classification ?? a.malicious.classification),
        type,
      })),
    });
  }
  if (type === "evidence") {
    const rows = await c.env.DB.prepare(
      "SELECT e.id,e.data FROM evidence e JOIN entities n ON n.id=e.entity_id WHERE (n.public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables t WHERE t.tenant_id=? AND t.observable_id=n.id)) AND (?='' OR instr(lower(n.name),lower(?))>0 OR instr(lower(e.id),lower(?))>0) UNION ALL SELECT id,data FROM customer_observations WHERE tenant_id=? AND (?='' OR instr(lower(data),lower(?))>0) LIMIT 20",
    )
      .bind(r.tenant, q, q, q, r.tenant, q, q)
      .all<{ id: string; data: string }>();
    return c.json({
      data: rows.results.map((row) => {
        const ev = JSON.parse(row.data) as {
          provenance: { sourceName: string };
          data: { description?: string };
        };
        return {
          id: row.id,
          type,
          name:
            ev.provenance.sourceName + " · " + (ev.data.description ?? row.id),
        };
      }),
    });
  }
  const page = await r.list(type, q, "", "", 20);
  return c.json({
    data: page.data.map((o) => ({ id: o.id, name: o.title, type })),
  });
});
routes.get("/evidence/:id", async (c) =>
  c.json(await repo(c).evidence(c.req.param("id"))),
);
routes.post("/collections/:id/packages", async (c) => {
  const input = z
    .object({ requestId: z.string().uuid() })
    .parse(await enterpriseJson(c));
  const id = await requestPackage(
    repo(c),
    c.req.param("id"),
    input.requestId,
    c.get("requestId"),
  );
  return c.json({ id, status_url: "/v1/collection-packages/" + id }, 202);
});
routes.get("/collection-packages/:id", async (c) => {
  const r = repo(c),
    row = await getPackage(r, c.req.param("id"));
  const parts = await r.db
    .prepare(
      "SELECT part,sha256,object_count,created_at FROM collection_package_parts WHERE tenant_id=? AND package_id=? AND object_count>0 ORDER BY part",
    )
    .bind(r.tenant, row.id)
    .all();
  const count = await r.db
    .prepare(
      "SELECT COUNT(*) AS n FROM collection_package_members WHERE tenant_id=? AND package_id=?",
    )
    .bind(r.tenant, row.id)
    .first<{ n: number }>();
  const failed = await r.db
    .prepare(
      "SELECT id,status,error_type FROM pipeline_jobs WHERE tenant_id=? AND json_extract(data,'$.payload.packageId')=? AND status IN ('failed','dead-letter') LIMIT 1",
    )
    .bind(r.tenant, row.id)
    .first();
  return c.json({
    schema_version: "1.0",
    id: row.id,
    collection_id: row.collection_id,
    revision: row.revision,
    status: failed ? "failed" : row.status,
    matched_entities: count?.n ?? 0,
    created_at: row.created_at,
    expires_at: row.expires_at,
    parts: parts.results,
    failed_job: failed,
    semantics:
      "Membership is snapshotted at request time. Redistributable content is captured while processing; current access and collection revision are checked on every download. Parts form one STIX package and may reference objects in other parts.",
  });
});
routes.get("/collection-packages/:id/parts/:part", async (c) => {
  const r = repo(c),
    row = await getPackage(r, c.req.param("id")),
    part = z.coerce
      .number()
      .int()
      .min(0)
      .max(100000)
      .parse(c.req.param("part"));
  if (row.status !== "complete")
    throw new AppError(
      "EXPORT_PENDING",
      409,
      "This package is still processing. Wait until all parts are ready.",
    );
  const record = await r.db
    .prepare(
      "SELECT r2_key,sha256,member_ids FROM collection_package_parts WHERE tenant_id=? AND package_id=? AND part=?",
    )
    .bind(r.tenant, row.id, part)
    .first<{ r2_key: string; sha256: string; member_ids: string }>();
  if (!record)
    throw new AppError("NOT_FOUND", 404, "This export part is unavailable.");
  for (const id of z
    .array(z.string())
    .max(100)
    .parse(JSON.parse(record.member_ids))) {
    const entity = await r.intel.entity(id);
    const denied =
      entity &&
      (await r.db
        .prepare(
          "SELECT 1 FROM tenant_source_policy WHERE tenant_id=? AND source_id=? AND enabled=0",
        )
        .bind(r.tenant, entity.provenance.sourceId)
        .first());
    if (
      !entity?.provenance.redistributable ||
      denied ||
      !(await r.intel.visible(r.tenant, id))
    )
      throw new AppError(
        "EXPORT_ACCESS_CHANGED",
        409,
        "Access or redistribution rights changed. Create a new export package.",
      );
  }
  const archived = await c.env.ARCHIVE.get(record.r2_key);
  if (!archived)
    throw new AppError(
      "EXPORT_UNAVAILABLE",
      503,
      "This export part is temporarily unavailable. Please retry.",
    );
  const body = await archived.text();
  if ((await digest(body)) !== record.sha256)
    throw new AppError(
      "EXPORT_INTEGRITY",
      503,
      "This export failed its integrity check. Please create a new package.",
    );
  if (part === 0) {
    const snapshot = WorkObjectSchema.parse(JSON.parse(row.snapshot));
    const current = await exportWorkspace(
      r,
      {
        ...snapshot,
        references: snapshot.references.filter(
          (ref) => ref.type === "assessment",
        ),
      },
      new Set(),
      false,
    );
    if (
      JSON.stringify(current.objects) !==
      JSON.stringify(JSON.parse(body).objects)
    )
      throw new AppError(
        "EXPORT_ASSESSMENT_CHANGED",
        409,
        "An assessment changed. Create a new export package.",
      );
  }
  const bundle = z
    .object({ objects: z.array(z.record(z.string(), z.unknown())) })
    .parse(JSON.parse(body));
  for (const edge of bundle.objects.filter(
    (o) =>
      o.type === "relationship" &&
      typeof o.x_threatsieve_relationship_id === "string",
  )) {
    const blocked = await r.db
      .prepare(
        "SELECT 1 FROM relationships r WHERE r.id=? AND (EXISTS(SELECT 1 FROM tenant_source_policy WHERE tenant_id=? AND source_id=r.source_id AND enabled=0) OR COALESCE((SELECT decision FROM relationship_feedback WHERE tenant_id=? AND relationship_id=r.id ORDER BY created_at DESC,id DESC LIMIT 1),'confirm')='reject' OR json_extract(r.data,'$.provenance.redistributable')!=1)",
      )
      .bind(edge.x_threatsieve_relationship_id, r.tenant, r.tenant)
      .first();
    if (blocked)
      throw new AppError(
        "EXPORT_RELATIONSHIP_CHANGED",
        409,
        "A relationship was rejected or restricted. Create a new export package.",
      );
  }
  await r.intel.audit(
    r.principal,
    "collection.package.downloaded",
    row.id,
    c.get("requestId"),
    { part },
  );
  c.header("Cache-Control", "private, no-store");
  c.header("Content-Type", "application/stix+json");
  c.header(
    "Content-Disposition",
    `attachment; filename="threatsieve-${row.id}-${part}.json"`,
  );
  return c.body(body);
});
for (const [path, kind] of Object.entries({
  requirements: "requirement",
  investigations: "investigation",
  collections: "collection",
  reports: "report",
  watchlists: "watchlist",
}) as [string, z.infer<typeof WorkKind>][]) {
  routes.get("/" + path + "/:id/export", async (c) => {
    const r = repo(c),
      o = await r.get(c.req.param("id")!, kind),
      format = z
        .enum(["html", "json", "csv", "stix", "misp"])
        .parse(c.req.query("format") ?? "json");
    await r.intel.audit(
      r.principal,
      "workspace.export",
      o.id,
      c.get("requestId"),
      { format, revision: o.revision },
    );
    c.header(
      "Content-Disposition",
      (format === "html" ? "inline" : "attachment") +
        '; filename="threatsieve-' +
        o.id +
        "." +
        (["stix", "misp"].includes(format) ? "json" : format) +
        '"',
    );
    if (format === "html") {
      c.header(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
      );
      return c.html(reportHtml(o));
    }
    if (format === "misp") return c.json(await exportMisp(r, o));
    if (format === "stix") {
      c.header("Content-Type", "application/stix+json");
      return c.body(JSON.stringify(await exportWorkspace(r, o)));
    }
    if (format === "csv") {
      c.header("Content-Type", "text/csv;charset=utf-8");
      return c.body(
        [
          ["type", "id", "relationship"],
          ...o.references.map((ref) => [ref.type, ref.id, ref.relation]),
        ]
          .map((row) => row.map(csvCell).join(","))
          .join("\r\n"),
      );
    }
    return c.json({ object: o, history: await r.history(o.id) });
  });
}
routes.post("/observables", async (c) => {
  const input = AssessRequest.parse(await enterpriseJson(c)),
    o = await normalise(input.observable, input.type),
    r = repo(c);
  await r.intel.putObservable(
    o,
    {
      sourceId: "upload",
      sourceName: "Analyst submission",
      retrievedAt: new Date().toISOString(),
      redistributable: false,
    },
    r.tenant,
  );
  await r.intel.audit(
    r.principal,
    "observable.created",
    o.id,
    c.get("requestId"),
  );
  return c.json(o, 201);
});
routes.get("/sightings", async (c) => {
  const f = Browse.parse(c.req.query());
  const entity = z.string().max(200).optional().parse(c.req.query("entity"));
  return c.json(await repo(c).sightings(entity, f.cursor, f.limit));
});
routes.post("/sightings", async (c) =>
  c.json(await repo(c).recordSighting(await enterpriseJson(c)), 201),
);
routes.post("/entities/:id/tags", async (c) => {
  const r = repo(c),
    id = c.req.param("id"),
    input = z
      .object({
        tag: z.string().trim().min(1).max(100),
        operation: z.enum(["add", "remove"]),
        reason: z.string().trim().min(3).max(1000),
      })
      .parse(await enterpriseJson(c));
  if (!(await r.intel.visible(r.tenant, id)))
    throw new AppError("NOT_FOUND", 404, "Entity unavailable");
  const now = new Date().toISOString(),
    event = crypto.randomUUID();
  await r.db.batch([
    input.operation === "add"
      ? r.db
          .prepare("INSERT OR IGNORE INTO entity_tags VALUES(?,?,?,?,?)")
          .bind(r.tenant, id, input.tag, r.principal.userId, now)
      : r.db
          .prepare(
            "DELETE FROM entity_tags WHERE tenant_id=? AND entity_id=? AND tag=?",
          )
          .bind(r.tenant, id, input.tag),
    r.db
      .prepare("INSERT INTO intelligence_events VALUES(?,?,?,?,?,?,?,?)")
      .bind(
        r.tenant,
        event,
        "entity",
        id,
        "tag." + input.operation,
        r.principal.userId,
        JSON.stringify(input),
        now,
      ),
    r.db
      .prepare(
        "INSERT INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES(?,?,?,?,?,?,?,?)",
      )
      .bind(
        event,
        r.tenant,
        r.principal.userId,
        "tag." + input.operation,
        id,
        c.get("requestId"),
        JSON.stringify(input),
        now,
      ),
  ]);
  return c.json({ status: "saved" });
});
routes.get("/entities/:id/dossier", async (c) => {
  const r = repo(c);
  if (!(await r.intel.visible(r.tenant, c.req.param("id")!)))
    throw new AppError("NOT_FOUND", 404, "Entity unavailable");
  return c.json(await dossier(r, c.req.param("id")!));
});
routes.get("/entities/:id/timeline", async (c) => {
  const r = repo(c);
  if (!(await r.intel.visible(r.tenant, c.req.param("id")!)))
    throw new AppError("NOT_FOUND", 404, "Entity unavailable");
  const days = z
    .enum(["1", "7", "30", "90", "365", "all"])
    .parse(c.req.query("days") ?? "30");
  const d = await dossier(r, c.req.param("id")!);
  const from =
    days === "all"
      ? ""
      : new Date(Date.now() - Number(days) * 86400000).toISOString();
  return c.json({
    data: d.timeline.filter((e) => e.timestamp >= from),
    truncated: d.truncated,
  });
});
routes.put("/feeds/:id/rating", async (c) => {
  authorize(c.get("principal"), "admin");
  const input = SourceRating.parse(await enterpriseJson(c)),
    r = repo(c),
    id = c.req.param("id")!,
    now = new Date().toISOString();
  if (
    !(await c.env.DB.prepare("SELECT id FROM sources WHERE id=?")
      .bind(id)
      .first())
  )
    throw new AppError("NOT_FOUND", 404, "Source unavailable");
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO source_ratings VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,source_id) DO UPDATE SET reliability=excluded.reliability,evidence_rating=excluded.evidence_rating,rationale=excluded.rationale,analyst_id=excluded.analyst_id,updated_at=excluded.updated_at",
    ).bind(
      r.tenant,
      id,
      input.reliability,
      input.evidenceRating,
      input.rationale,
      r.principal.userId,
      now,
    ),
    c.env.DB.prepare(
      "INSERT INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES(?,?,?,?,?,?,?,?)",
    ).bind(
      crypto.randomUUID(),
      r.tenant,
      r.principal.userId,
      "source.rated",
      id,
      c.get("requestId"),
      JSON.stringify(input),
      now,
    ),
  ]);
  return c.json({ status: "saved" });
});
routes.get("/notifications", async (c) => {
  const r = repo(c);
  const rows = await r.db
    .prepare(
      "SELECT n.id,n.object_id,n.entity_id,n.reason,n.created_at,r.read_at,o.data AS object FROM workspace_notifications n JOIN workspace_objects o ON o.tenant_id=n.tenant_id AND o.id=n.object_id LEFT JOIN notification_receipts r ON r.tenant_id=n.tenant_id AND r.notification_id=n.id AND r.user_id=? WHERE n.tenant_id=? ORDER BY n.created_at DESC,n.id LIMIT 100",
    )
    .bind(r.principal.userId, r.tenant)
    .all<{
      id: string;
      object_id: string;
      entity_id: string;
      reason: string;
      created_at: string;
      read_at: string | null;
      object: string;
    }>();
  return c.json({
    data: rows.results
      .filter((n) =>
        r.canRead(
          JSON.parse(
            n.object,
          ) as import("../../../packages/schemas/src/enterprise").WorkObject,
        ),
      )
      .map(({ object, ...n }) => ({
        ...n,
        objectType: (JSON.parse(object) as { kind: string }).kind,
      })),
  });
});
routes.post("/notifications/:id/read", async (c) => {
  const r = repo(c),
    id = c.req.param("id");
  const row = await r.db
    .prepare(
      "SELECT object_id FROM workspace_notifications WHERE tenant_id=? AND id=?",
    )
    .bind(r.tenant, id)
    .first<{ object_id: string }>();
  if (!row) throw new AppError("NOT_FOUND", 404, "Notification unavailable");
  await r.get(row.object_id);
  await r.db
    .prepare("INSERT OR REPLACE INTO notification_receipts VALUES(?,?,?,?)")
    .bind(r.tenant, id, r.principal.userId, new Date().toISOString())
    .run();
  return c.json({ status: "read" });
});
routes.delete("/watchlists/:id/members/:entityId", async (c) => {
  await repo(c).removeAutomaticMember(
    c.req.param("id"),
    c.req.param("entityId"),
  );
  return c.json({ status: "removed" });
});
routes.get("/workspace/:id/matches", async (c) => {
  const r = repo(c);
  await r.get(c.req.param("id"));
  const f = Browse.parse(c.req.query());
  const rows = await r.db
    .prepare(
      "SELECT m.entity_id,e.name,e.type,m.evidence_ids,m.criteria,m.matched_at,m.score,EXISTS(SELECT 1 FROM workspace_links l WHERE l.tenant_id=m.tenant_id AND l.object_id=m.object_id AND l.target_id=m.entity_id AND l.target_type='entity' AND l.relation='automation_member') AS automatic_member FROM workspace_matches m JOIN entities e ON e.id=m.entity_id WHERE m.tenant_id=? AND m.object_id=? AND m.entity_id>? AND (e.public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables t WHERE t.tenant_id=m.tenant_id AND t.observable_id=e.id)) ORDER BY m.entity_id LIMIT ?",
    )
    .bind(r.tenant, c.req.param("id"), f.cursor, f.limit + 1)
    .all<{
      entity_id: string;
      name: string;
      type: string;
      evidence_ids: string;
      criteria: string;
      matched_at: string;
      automatic_member: number;
      score: number | null;
    }>();
  return c.json({
    data: rows.results.slice(0, f.limit).map((row) => ({
      ...row,
      evidence_ids: JSON.parse(row.evidence_ids),
      criteria: JSON.parse(row.criteria),
    })),
    next_cursor:
      rows.results.length > f.limit
        ? rows.results[f.limit - 1]!.entity_id
        : null,
  });
});
routes.get("/playbooks/:id/executions", async (c) => {
  const r = repo(c);
  await r.get(c.req.param("id"), "playbook");
  const rows = await r.db
    .prepare(
      "SELECT id,event_id,status,data,created_at FROM automation_executions WHERE tenant_id=? AND playbook_id=? ORDER BY created_at DESC LIMIT 100",
    )
    .bind(r.tenant, c.req.param("id"))
    .all<{
      data: string;
      id: string;
      event_id: string;
      status: string;
      created_at: string;
    }>();
  return c.json({
    data: rows.results.map((row) => ({ ...row, data: JSON.parse(row.data) })),
  });
});
routes.post("/collections/:id/publish", async (c) => {
  const r = repo(c),
    o = await r.get(c.req.param("id"), "collection");
  return c.json(await publishCollection(r, o));
});
routes.get("/collections/:id/publication", async (c) => {
  const r = repo(c);
  await r.get(c.req.param("id"), "collection");
  return c.json({
    publication: await r.db
      .prepare(
        "SELECT revision,published_at,object_count FROM taxii_publications WHERE tenant_id=? AND collection_id=?",
      )
      .bind(r.tenant, c.req.param("id"))
      .first(),
  });
});
routes.get("/feeds/:id/quality", async (c) => {
  const r = repo(c),
    id = c.req.param("id");
  const source = await r.db
    .prepare("SELECT * FROM sources WHERE id=?")
    .bind(id)
    .first();
  if (!source) throw new AppError("NOT_FOUND", 404, "Source unavailable");
  const [rating, policy, jobs, rejections, samples, reviews] =
    await Promise.all([
      r.db
        .prepare(
          "SELECT reliability,evidence_rating,rationale,updated_at FROM source_ratings WHERE tenant_id=? AND source_id=?",
        )
        .bind(r.tenant, id)
        .first(),
      r.db
        .prepare(
          "SELECT enabled,reason,updated_at FROM tenant_source_policy WHERE tenant_id=? AND source_id=?",
        )
        .bind(r.tenant, id)
        .first(),
      r.db
        .prepare(
          "SELECT id,status,created_at,updated_at,error_type,result FROM pipeline_jobs WHERE entity_id=? AND stage='feed-sync' AND tenant_id IS NULL ORDER BY created_at DESC LIMIT 30",
        )
        .bind(id)
        .all<{
          id: string;
          status: string;
          created_at: string;
          updated_at: string;
          error_type: string | null;
          result: string | null;
        }>(),
      r.db
        .prepare(
          "SELECT error_type,COUNT(*) AS count FROM feed_rejections WHERE source_id=? GROUP BY error_type ORDER BY count DESC LIMIT 20",
        )
        .bind(id)
        .all(),
      r.db
        .prepare(
          "SELECT e.data FROM evidence e JOIN entities n ON n.id=e.entity_id WHERE e.source_id=? AND n.public_intel=1 ORDER BY e.created_at DESC LIMIT 5",
        )
        .bind(id)
        .all<{ data: string }>(),
      r.db
        .prepare(
          "SELECT f.original_value,f.analyst_value FROM analyst_feedback f JOIN assessments a ON a.tenant_id=f.tenant_id AND a.id=f.assessment_id WHERE f.tenant_id=? AND f.field='malicious' AND EXISTS(SELECT 1 FROM json_each(json_extract(a.data,'$.sources')) s WHERE json_extract(s.value,'$.sourceId')=?) AND f.id=(SELECT id FROM analyst_feedback ff WHERE ff.tenant_id=f.tenant_id AND ff.assessment_id=f.assessment_id AND ff.field='malicious' ORDER BY ff.created_at DESC,ff.id DESC LIMIT 1) LIMIT 1000",
        )
        .bind(r.tenant, id)
        .all<{ original_value: string; analyst_value: string }>(),
    ]);
  const labelled = reviews.results.map((v) => ({
    before: JSON.parse(v.original_value) as { classification?: string },
    after: JSON.parse(v.analyst_value) as { classification?: string },
  }));
  const malicious = labelled.filter(
    (v) => v.before.classification === "malicious",
  );
  const overturned = malicious.filter(
    (v) => v.after.classification === "benign",
  );
  return c.json({
    source,
    rating,
    policy: policy ?? { enabled: 1 },
    history: jobs.results.map((j) => ({
      ...j,
      result: j.result ? JSON.parse(j.result) : null,
      latency_ms:
        j.status === "complete"
          ? Date.parse(j.updated_at) - Date.parse(j.created_at)
          : null,
    })),
    rejections: rejections.results,
    samples: samples.results.map((s) => JSON.parse(s.data)),
    quality: {
      labelledAssessments: labelled.length,
      reviewedMalicious: malicious.length,
      overturnedAsBenign: overturned.length,
      reviewedFalsePositiveFraction: malicious.length
        ? overturned.length / malicious.length
        : null,
      label:
        "Tenant-reviewed assessments mentioning this source; not a calibrated source-wide accuracy estimate",
    },
  });
});
routes.put("/feeds/:id/policy", async (c) => {
  authorize(c.get("principal"), "admin");
  const r = repo(c),
    id = c.req.param("id"),
    input = z
      .object({
        enabled: z.boolean(),
        reason: z.string().trim().min(10).max(2000),
      })
      .parse(await enterpriseJson(c));
  if (
    !(await r.db.prepare("SELECT id FROM sources WHERE id=?").bind(id).first())
  )
    throw new AppError("NOT_FOUND", 404, "Source unavailable");
  await r.db.batch([
    r.db
      .prepare(
        "INSERT INTO tenant_source_policy VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,source_id) DO UPDATE SET enabled=excluded.enabled,reason=excluded.reason,updated_at=excluded.updated_at",
      )
      .bind(
        r.tenant,
        id,
        Number(input.enabled),
        input.reason,
        new Date().toISOString(),
      ),
    r.db
      .prepare("DELETE FROM requirement_metrics WHERE tenant_id=?")
      .bind(r.tenant),
  ]);
  await r.intel.audit(
    r.principal,
    "source.policy.changed",
    id,
    c.get("requestId"),
    input,
  );
  return c.json({
    status: "saved",
    message:
      "Policy applies to future assessments and current dossiers. Historical assessments retain their original evidence.",
  });
});

routes.get("/taxii/", (c) => {
  c.header("Content-Type", "application/taxii+json;version=2.1");
  const root = new URL("api/", c.req.url).href;
  return c.body(
    JSON.stringify({
      title: "ThreatSieve TAXII 2.1",
      default: root,
      api_roots: [root],
    }),
  );
});
routes.route("/taxii", taxiiRoutes);
export { routes as enterpriseRoutes };
