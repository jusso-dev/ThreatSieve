import { Hono } from "hono";
import { z } from "zod";
import type { ApiContext } from "./context";
import { authorize } from "../../../packages/auth/src/index";
import { boundedText } from "../../../packages/intel/src/feeds";
import { digest } from "../../../packages/intel/src/normalise";
import { AppError, log } from "../../../packages/observability/src/index";
import { Repository } from "../../../packages/database/src/repository";
import { dispatchOutbox, makeJob } from "../../../workers/ingest/pipeline";
import {
  mapDocuments,
  mediaFormat,
  readIngestRequest,
} from "../../../packages/ingest/src/formats/index";
import {
  auditStatement,
  batchArchiveKey,
  getBatch,
  getItem,
  metricsStatement,
  prepareItems,
  storeItems,
  tally,
} from "../../../packages/ingest/src/service";
import { INGEST_MAX_BODY_BYTES } from "../../../packages/ingest/src/schema";

type Ctx = import("hono").Context<ApiContext>;
export const ingestRoutes = new Hono<ApiContext>();

async function body(c: Ctx): Promise<{ text: string; value: unknown }> {
  if (Number(c.req.header("content-length") ?? 0) > INGEST_MAX_BODY_BYTES)
    throw tooLarge();
  let text: string;
  try {
    text = await boundedText(
      new Response(c.req.raw.body),
      INGEST_MAX_BODY_BYTES,
    );
  } catch (error) {
    if (error instanceof Error && error.message.includes("size limit"))
      throw tooLarge();
    throw new AppError("INVALID_BODY", 400, "Request body could not be read");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new AppError("INVALID_JSON", 400, "Invalid JSON body");
  }
  if (nestedDeeper(value, 64))
    throw new AppError("INVALID_JSON", 400, "JSON nesting exceeds 64 levels");
  return { text, value };
}
/** Bounded so later recursive walks (hashing, validation) cannot overflow. */
function nestedDeeper(value: unknown, limit: number): boolean {
  if (limit < 0) return true;
  if (value && typeof value === "object")
    for (const child of Object.values(value))
      if (nestedDeeper(child, limit - 1)) return true;
  return false;
}
const tooLarge = () =>
  new AppError(
    "PAYLOAD_TOO_LARGE",
    413,
    "Request body exceeds " + INGEST_MAX_BODY_BYTES / 1048576 + " MiB",
  );

/** Returns the stored first response for a repeated Idempotency-Key. */
async function replay(c: Ctx, key: string | undefined, hash: string) {
  if (!key) return null;
  const row = await c.env.DB.prepare(
    "SELECT body_hash,status,response FROM ingest_requests WHERE tenant_id=? AND request_key=?",
  )
    .bind(c.get("principal").tenantId, key)
    .first<{ body_hash: string; status: number; response: string }>();
  if (!row) return null;
  if (row.body_hash !== hash)
    throw new AppError(
      "IDEMPOTENCY_CONFLICT",
      409,
      "This idempotency key was already used with a different body",
    );
  c.header("Idempotent-Replayed", "true");
  return c.json(JSON.parse(row.response), row.status as 200);
}
async function respond(
  c: Ctx,
  key: string | undefined,
  hash: string,
  status: 200 | 201 | 202 | 400,
  payload: unknown,
) {
  if (key) {
    const won = await c.env.DB.prepare(
      "INSERT INTO ingest_requests VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING RETURNING status",
    )
      .bind(
        c.get("principal").tenantId,
        key,
        hash,
        status,
        JSON.stringify(payload),
        new Date().toISOString(),
      )
      .first();
    // A concurrent request with the same key answered first.
    if (!won) {
      const winner = await replay(c, key, hash);
      if (winner) return winner;
    }
  }
  return c.json(payload, status);
}

ingestRoutes.post("/ingest", async (c) => {
  const p = c.get("principal");
  authorize(p, "ingest:write");
  const requestId = c.get("requestId");
  const key = z
    .string()
    .trim()
    .min(1)
    .max(200)
    .optional()
    .parse(c.req.header("Idempotency-Key"));
  const contentType = c.req.header("content-type");
  mediaFormat(contentType);
  const { text, value } = await body(c);
  const hash = await digest((contentType ?? "") + "\n" + text);
  const previous = await replay(c, key, hash);
  if (previous) return previous;

  const request = readIngestRequest(contentType, value);
  const mapped = mapDocuments(request);
  if (!mapped.length)
    throw new AppError(
      "NO_ITEMS",
      400,
      "The document contains no alerts or advisories",
    );
  const { accepted, rejected, superseded } = await prepareItems(
    p.tenantId,
    request,
    mapped,
    p.ingestSources,
  );
  const ip = c.req.header("cf-connecting-ip");
  const counts = {
    received: mapped.length,
    // Valid items, including earlier copies superseded within this request.
    accepted: accepted.length + superseded.length,
    rejected: rejected.length,
    deduplicated: superseded.length,
  };
  const errors = rejected.map((r) => ({
    index: r.index,
    document: r.document,
    ...(r.source_ref ? { source_ref: r.source_ref } : {}),
    ...(r.external_id ? { external_id: r.external_id } : {}),
    issues: r.issues,
  }));
  const record = (result: string, extra: Record<string, number> = {}) =>
    log({
      request_id: requestId,
      tenant_id: p.tenantId,
      stage: "ingest",
      format: request.format,
      result,
      items_received: counts.received,
      items_accepted: counts.accepted,
      items_rejected: counts.rejected,
      items_deduplicated: counts.deduplicated,
      ...extra,
    });

  if (!accepted.length) {
    await c.env.DB.batch([
      metricsStatement(c.env.DB, p.tenantId, counts),
      auditStatement(
        c.env.DB,
        p,
        "ingest.rejected",
        requestId,
        requestId,
        {
          key_id: p.keyId,
          format: request.format,
          ...counts,
        },
        ip,
      ),
    ]);
    record("rejected");
    return respond(c, key, hash, 400, {
      error: {
        code: "VALIDATION_ERROR",
        message: "No items were accepted",
        request_id: requestId,
        items: errors,
      },
    });
  }

  if (!request.batch) {
    const [prepared] = accepted;
    const [outcome] = await storeItems(
      c.env,
      p.tenantId,
      p.userId,
      requestId,
      accepted,
    );
    const stored = tally([outcome!]);
    await c.env.DB.batch([
      metricsStatement(c.env.DB, p.tenantId, {
        ...counts,
        deduplicated: stored.updated + stored.unchanged,
        created: stored.created,
        updated: stored.updated,
      }),
      auditStatement(
        c.env.DB,
        p,
        "ingest.item",
        prepared!.id,
        requestId,
        {
          key_id: p.keyId,
          format: request.format,
          source: prepared!.item.source.name,
          external_id: prepared!.item.external_id,
          tlp: prepared!.item.tlp,
          outcome: outcome!.outcome,
        },
        ip,
      ),
    ]);
    record("stored", {
      items_deduplicated: stored.updated + stored.unchanged,
      items_created: stored.created,
      items_updated: stored.updated,
    });
    return respond(c, key, hash, outcome!.outcome === "created" ? 201 : 200, {
      id: prepared!.id,
      status: outcome!.outcome,
      ...(outcome!.revision ? { revision: outcome!.revision } : {}),
      item: prepared!.item,
      normalisation: prepared!.normalisation,
    });
  }

  const batchId = "inb_" + crypto.randomUUID().replaceAll("-", "");
  const archiveKey = batchArchiveKey(p.tenantId, batchId);
  const job = makeJob(
    "ingest",
    batchId,
    p.tenantId,
    {
      mode: "structured-ingest",
      batchId,
      key: archiveKey,
      actor: p.userId,
    },
    requestId,
  );
  job.jobId = "ingest:" + batchId;
  const items = [
    ...accepted.map((a) => ({
      index: a.index,
      id: a.id,
      external_id: a.item.external_id,
      status: "queued",
    })),
    ...superseded.map((s) => ({
      index: s.index,
      id: s.id,
      status: "superseded",
      superseded_by: s.superseded_by,
    })),
  ].sort((a, b) => a.index - b.index);
  await c.env.ARCHIVE.put(archiveKey, JSON.stringify(accepted));
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO ingest_batches(id,tenant_id,job_id,key_id,user_id,format,status,received,accepted,rejected,superseded,items,errors,request_id,created_at) VALUES(?,?,?,?,?,?,'queued',?,?,?,?,?,?,?,?)",
      ).bind(
        batchId,
        p.tenantId,
        job.jobId,
        p.keyId,
        p.userId,
        request.format,
        counts.received,
        counts.accepted,
        counts.rejected,
        superseded.length,
        JSON.stringify(items),
        JSON.stringify(errors),
        requestId,
        job.createdAt,
      ),
      ...new Repository(c.env.DB).jobStatements(job),
      metricsStatement(c.env.DB, p.tenantId, counts),
      auditStatement(
        c.env.DB,
        p,
        "ingest.batch",
        batchId,
        requestId,
        {
          key_id: p.keyId,
          format: request.format,
          ...counts,
          sources: [...new Set(accepted.map((a) => a.item.source.name))].slice(
            0,
            20,
          ),
          item_ids: accepted.map((a) => a.id).slice(0, 100),
        },
        ip,
      ),
    ]);
  } catch (error) {
    await c.env.ARCHIVE.delete(archiveKey);
    throw error;
  }
  c.executionCtx.waitUntil(dispatchOutbox(c.env).catch(() => 0));
  record("queued");
  return respond(c, key, hash, 202, {
    ingest_id: batchId,
    status: "queued",
    status_url: "/v1/ingest/" + batchId,
    format: request.format,
    ...counts,
    items,
    errors,
  });
});

ingestRoutes.get("/ingest/metrics", async (c) => {
  authorize(c.get("principal"), "ingest:read");
  const days = z.coerce
    .number()
    .int()
    .min(1)
    .max(90)
    .parse(c.req.query("days") ?? 7);
  const since = new Date(Date.now() - (days - 1) * 86400000)
    .toISOString()
    .slice(0, 10);
  const rows = await c.env.DB.prepare(
    "SELECT day,received,accepted,rejected,deduplicated,created,updated FROM ingest_metrics WHERE tenant_id=? AND day>=? ORDER BY day DESC",
  )
    .bind(c.get("principal").tenantId, since)
    .all();
  return c.json({ data: rows.results });
});

ingestRoutes.get("/ingest/:id", async (c) => {
  authorize(c.get("principal"), "ingest:read");
  const id = z
    .string()
    .regex(/^(?:ing|inb)_[a-f0-9]{32,40}$/)
    .safeParse(c.req.param("id"));
  const tenant = c.get("principal").tenantId;
  const found = !id.success
    ? null
    : id.data.startsWith("inb_")
      ? await getBatch(c.env.DB, tenant, id.data)
      : await getItem(c.env, tenant, id.data);
  if (!found) throw new AppError("NOT_FOUND", 404, "Ingested item not found");
  return c.json(found);
});
