import { Hono } from "hono";
import type { ApiContext } from "./context";
import { OperationsRepository } from "../../../packages/enterprise/src/repository";
import { AppError } from "../../../packages/observability/src/index";
import { z } from "zod";
import type { WorkObject } from "../../../packages/schemas/src/enterprise";
const routes = new Hono<ApiContext>();
const media = "application/taxii+json;version=2.1";
const collection = (o: WorkObject) => ({
  id: o.id,
  title: o.title,
  description: o.description,
  can_read: true,
  can_write: false,
  media_types: ["application/stix+json;version=2.1"],
});
routes.use("*", async (c, next) => {
  const accept = c.req.header("accept");
  if (
    accept &&
    !accept.includes("*/*") &&
    !accept.includes("application/taxii+json")
  )
    throw new AppError(
      "NOT_ACCEPTABLE",
      406,
      "Use application/taxii+json;version=2.1",
    );
  await next();
  c.header("Content-Type", media);
  c.header("Cache-Control", "private, no-store");
});
routes.onError((error, c) => {
  const status =
    error instanceof AppError
      ? error.status
      : error instanceof z.ZodError
        ? 400
        : 500;
  return c.newResponse(
    JSON.stringify({
      title: status === 500 ? "TAXII request failed" : error.message,
      http_status: String(status),
    }),
    status as 400,
    { "Content-Type": media },
  );
});
routes.get("/", (c) => {
  const root = new URL(c.req.url.replace(/\/?$/, "/") + "api/").href;
  return c.json({
    title: "ThreatSieve TAXII 2.1",
    description: "Tenant-scoped, evidence-backed intelligence collections",
    default: root,
    api_roots: [root],
  });
});
routes.get("/api/", (c) =>
  c.json({
    title: "ThreatSieve workspace intelligence",
    versions: [media],
    max_content_length: 131072,
  }),
);
routes.get("/api/collections/", async (c) => {
  const p = c.get("principal");
  const rows = await c.env.DB.prepare(
    "SELECT o.data FROM workspace_objects o JOIN taxii_publications p ON p.tenant_id=o.tenant_id AND p.collection_id=o.id WHERE o.tenant_id=? AND o.kind='collection' AND o.status='published' AND json_extract(o.data,'$.publication')='taxii' ORDER BY o.id LIMIT 1000",
  )
    .bind(p.tenantId)
    .all<{ data: string }>();
  return c.json({
    collections: rows.results.map((r) =>
      collection(JSON.parse(r.data) as WorkObject),
    ),
  });
});
routes.use("/api/collections/:id/*", async (c, next) => {
  const repo = new OperationsRepository(c.env.DB, c.get("principal"));
  const o = await repo.get(c.req.param("id")!, "collection");
  if (
    o.kind !== "collection" ||
    o.status !== "published" ||
    o.publication !== "taxii"
  )
    throw new AppError("NOT_FOUND", 404, "Collection unavailable");
  await next();
});
routes.get("/api/collections/:id/", async (c) =>
  c.json(
    collection(
      await new OperationsRepository(c.env.DB, c.get("principal")).get(
        c.req.param("id"),
        "collection",
      ),
    ),
  ),
);
for (const path of [
  "objects/",
  "manifest/",
  "objects/:objectId/",
  "objects/:objectId/versions/",
])
  routes.get("/api/collections/:id/" + path, async (c) => {
    const p = c.get("principal"),
      id = c.req.param("id")!,
      objectId = c.req.param("objectId");
    const publication = await c.env.DB.prepare(
      "SELECT generation FROM taxii_publications WHERE tenant_id=? AND collection_id=?",
    )
      .bind(p.tenantId, id)
      .first<{ generation: string }>();
    if (!publication)
      throw new AppError("NOT_FOUND", 404, "No published snapshot exists");
    const q = c.req.query(),
      limit = z.coerce
        .number()
        .int()
        .min(1)
        .max(200)
        .parse(q.limit ?? 100),
      after = z.iso.datetime().optional().parse(q.added_after);
    const ids = z
        .string()
        .max(5000)
        .parse(objectId ?? q["match[id]"] ?? "")
        .split(",")
        .filter(Boolean),
      types = z
        .string()
        .max(1000)
        .parse(q["match[type]"] ?? "")
        .split(",")
        .filter(Boolean);
    const version = z
      .string()
      .max(1000)
      .parse(q["match[version]"] ?? "last");
    let cursor: {
      generation: string;
      date: string;
      id: string;
      version: string;
    } | null = null;
    if (q.next) {
      try {
        cursor = z
          .object({
            generation: z.string(),
            date: z.string(),
            id: z.string(),
            version: z.string(),
          })
          .parse(JSON.parse(atob(z.string().max(2000).parse(q.next))));
      } catch {
        throw new AppError(
          "INVALID_CURSOR",
          400,
          "Invalid pagination cursor. Restart from the first page.",
        );
      }
    }
    if (cursor && cursor.generation !== publication.generation)
      throw new AppError(
        "SNAPSHOT_CHANGED",
        409,
        "Collection was republished. Restart pagination with added_after.",
      );
    const args: (string | number)[] = [p.tenantId, id, publication.generation];
    const filters = ["tenant_id=?", "collection_id=?", "generation=?"];
    if (after) {
      filters.push("date_added>?");
      args.push(after);
    }
    if (ids.length) {
      filters.push("object_id IN (SELECT value FROM json_each(?))");
      args.push(JSON.stringify(ids));
    }
    if (types.length) {
      filters.push("type IN (SELECT value FROM json_each(?))");
      args.push(JSON.stringify(types));
    }
    if (!["last", "first", "all"].includes(version)) {
      filters.push("version IN (SELECT value FROM json_each(?))");
      args.push(JSON.stringify(version.split(",")));
    }
    if (cursor) {
      filters.push("(date_added,object_id,version)>(?,?,?)");
      args.push(cursor.date, cursor.id, cursor.version);
    }
    args.push(limit + 1);
    const rows = await c.env.DB.prepare(
      "SELECT object_id,version,type,date_added,data FROM taxii_objects WHERE " +
        filters.join(" AND ") +
        " ORDER BY date_added,object_id,version LIMIT ?",
    )
      .bind(...args)
      .all<{
        object_id: string;
        version: string;
        type: string;
        date_added: string;
        data: string;
      }>();
    const page = rows.results.slice(0, limit),
      last = page.at(-1),
      more = rows.results.length > limit;
    if (objectId && !page.length)
      throw new AppError("NOT_FOUND", 404, "Object unavailable");
    if (page.length) {
      c.header("X-TAXII-Date-Added-First", page[0]!.date_added);
      c.header("X-TAXII-Date-Added-Last", last!.date_added);
    }
    const meta = {
      more,
      ...(more && last
        ? {
            next: btoa(
              JSON.stringify({
                generation: publication.generation,
                date: last.date_added,
                id: last.object_id,
                version: last.version,
              }),
            ),
          }
        : {}),
    };
    if (path.includes("versions/"))
      return c.json({ ...meta, versions: page.map((o) => o.version) });
    if (path === "manifest/")
      return c.json({
        ...meta,
        objects: page.map((o) => ({
          id: o.object_id,
          date_added: o.date_added,
          version: o.version,
          media_type: "application/stix+json;version=2.1",
        })),
      });
    return c.json({
      ...meta,
      objects: page.map((o) => JSON.parse(o.data) as unknown),
    });
  });
routes.all("*", (c) =>
  c.newResponse(
    JSON.stringify({
      title:
        "This collection is read-only. Import through configured TAXII sources or bulk STIX upload.",
      http_status: "405",
    }),
    405,
    { Allow: "GET", "Content-Type": media },
  ),
);
export { routes as taxiiRoutes };
