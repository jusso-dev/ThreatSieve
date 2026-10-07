import { Repository } from "../../database/src/repository";
import { z } from "zod";
import type { AppEnv } from "../../../apps/api/src/env";
import type { PipelineJob, Principal } from "../../schemas/src/index";
import { RelationshipSchema } from "../../schemas/src/index";
import { WorkObjectSchema } from "../../schemas/src/enterprise";
import { OperationsRepository } from "./repository";
import { entityStix, relationshipStix, exportWorkspace } from "./export";
import { stixId, type StixObject } from "../../stix/src/index";
import { digest } from "../../intel/src/normalise";
import { AppError } from "../../observability/src/index";

interface PackageRow {
  id: string;
  tenant_id: string;
  collection_id: string;
  revision: number;
  requested_by: string;
  principal: string;
  snapshot: string;
  status: string;
  created_at: string;
  expires_at: string;
}
const absent = () =>
  new AppError("NOT_FOUND", 404, "This export package is unavailable.");
export async function getPackage(repo: OperationsRepository, id: string) {
  const row = await repo.db
    .prepare("SELECT * FROM collection_packages WHERE tenant_id=? AND id=?")
    .bind(repo.tenant, id)
    .first<PackageRow>();
  if (
    !row ||
    (row.requested_by !== repo.principal.userId &&
      !repo.principal.scopes.includes("admin"))
  )
    throw absent();
  const current = await repo.get(row.collection_id, "collection");
  if (current.revision !== row.revision)
    throw new AppError(
      "EXPORT_CHANGED",
      409,
      "The collection changed. Create a new export package.",
    );
  if (Date.parse(row.expires_at) <= Date.now())
    throw new AppError(
      "EXPORT_EXPIRED",
      409,
      "This export has expired. Create a new package.",
    );
  return row;
}
export async function requestPackage(
  repo: OperationsRepository,
  collectionId: string,
  requestId: string,
  correlationId: string,
) {
  const object = await repo.get(collectionId, "collection");
  if (object.references.some((r) => !["entity", "assessment"].includes(r.type)))
    throw new AppError(
      "EXPORT_REFERENCES",
      422,
      "Large packages support entity and assessment references. Export linked reports or investigations separately.",
    );
  const id = await digest(repo.tenant + ":" + collectionId + ":" + requestId);
  const existing = await repo.db
    .prepare("SELECT id FROM collection_packages WHERE tenant_id=? AND id=?")
    .bind(repo.tenant, id)
    .first();
  if (existing) {
    await getPackage(repo, id);
    return id;
  }
  const count = await repo.db
    .prepare(
      "SELECT COUNT(*) AS n FROM workspace_matches WHERE tenant_id=? AND object_id=?",
    )
    .bind(repo.tenant, collectionId)
    .first<{ n: number }>();
  if ((count?.n ?? 0) > 100000)
    throw new AppError(
      "EXPORT_LIMIT",
      413,
      "Narrow this collection to 100,000 matched entities per export package.",
    );
  const now = new Date().toISOString();
  const captureToken = crypto.randomUUID();
  const job: PipelineJob = {
    jobId: id + ":part:0",
    tenantId: repo.tenant,
    entityId: collectionId,
    stage: "export",
    attempt: 0,
    createdAt: now,
    correlationId,
    payload: {
      mode: "collection-package",
      packageId: id,
      phase: "references",
      cursor: "",
      part: 0,
    },
  };
  await repo.db.batch([
    repo.db
      .prepare(
        "INSERT OR IGNORE INTO collection_packages(id,tenant_id,collection_id,revision,requested_by,principal,snapshot,created_at,expires_at,matched_count) VALUES(?,?,?,?,?,?,?,?,?,(SELECT COUNT(*) FROM workspace_matches WHERE tenant_id=? AND object_id=?))",
      )
      .bind(
        id,
        repo.tenant,
        collectionId,
        object.revision,
        repo.principal.userId,
        JSON.stringify(repo.principal),
        JSON.stringify({ ...object, _captureToken: captureToken }),
        now,
        new Date(Date.now() + 86400000).toISOString(),
        repo.tenant,
        collectionId,
      ),
    repo.db
      .prepare(
        "INSERT OR IGNORE INTO collection_package_members SELECT ?,?,entity_id FROM workspace_matches WHERE tenant_id=? AND object_id=? AND EXISTS(SELECT 1 FROM collection_packages WHERE tenant_id=? AND id=? AND json_extract(snapshot,'$._captureToken')=?)",
      )
      .bind(
        repo.tenant,
        id,
        repo.tenant,
        collectionId,
        repo.tenant,
        id,
        captureToken,
      ),
    repo.db
      .prepare(
        "INSERT OR IGNORE INTO collection_package_members SELECT ?,?,json_extract(value,'$.id') FROM json_each(?) WHERE json_extract(value,'$.type')='entity' AND EXISTS(SELECT 1 FROM collection_packages WHERE tenant_id=? AND id=? AND json_extract(snapshot,'$._captureToken')=?)",
      )
      .bind(
        repo.tenant,
        id,
        JSON.stringify(object.references),
        repo.tenant,
        id,
        captureToken,
      ),
    ...repo.intel.jobStatements(job),
  ]);
  await repo.intel.audit(
    repo.principal,
    "collection.package.requested",
    id,
    correlationId,
    { collectionId, revision: object.revision },
  );
  return id;
}
const Payload = z.object({
  packageId: z.string(),
  phase: z.enum(["references", "entities", "relationships"]),
  cursor: z.string(),
  part: z.number().int().nonnegative(),
});
export async function processPackage(
  env: Pick<AppEnv, "DB" | "ARCHIVE">,
  job: PipelineJob,
) {
  if (!job.tenantId) throw absent();
  const p = Payload.parse(job.payload);
  const row = await env.DB.prepare(
    "SELECT * FROM collection_packages WHERE tenant_id=? AND id=?",
  )
    .bind(job.tenantId, p.packageId)
    .first<PackageRow>();
  if (!row || Date.parse(row.expires_at) <= Date.now()) {
    await new Repository(env.DB).finish(job, { expired: true });
    return;
  }
  const repo = new OperationsRepository(
    env.DB,
    JSON.parse(row.principal) as Principal,
  );
  await getPackage(repo, p.packageId);
  const object = WorkObjectSchema.parse(JSON.parse(row.snapshot));
  const members: string[] = [];
  let objects: StixObject[] = [],
    cursor = p.cursor,
    phase = p.phase,
    complete = false;
  if (p.phase === "references") {
    const referenceObject = {
      ...object,
      references: object.references.filter((r) => r.type === "assessment"),
    };
    objects = (await exportWorkspace(repo, referenceObject, new Set(), false))
      .objects;
    phase = "entities";
    cursor = "";
  } else if (p.phase === "entities") {
    const rows = await repo.db
      .prepare(
        "SELECT entity_id FROM collection_package_members WHERE tenant_id=? AND package_id=? AND entity_id>? ORDER BY entity_id LIMIT 50",
      )
      .bind(repo.tenant, p.packageId, p.cursor)
      .all<{ entity_id: string }>();
    const ids = rows.results.map((r) => r.entity_id);
    for (const id of ids) {
      if (!(await repo.intel.visible(repo.tenant, id))) continue;
      const entity = await repo.intel.entity(id);
      if (!entity) continue;
      const denied = await repo.db
        .prepare(
          "SELECT 1 FROM tenant_source_policy WHERE tenant_id=? AND source_id=? AND enabled=0",
        )
        .bind(repo.tenant, entity.provenance.sourceId)
        .first();
      const stix = denied ? null : entityStix(entity, row.created_at);
      if (stix) {
        objects.push(stix);
        members.push(id);
      }
    }
    if (rows.results.length === 50) cursor = ids.at(-1)!;
    else {
      phase = "relationships";
      cursor = "";
    }
  } else {
    const rows = await repo.db
      .prepare(
        `SELECT r.id,r.data FROM relationships r
     JOIN collection_package_members src ON src.entity_id=r.source_entity_id AND src.tenant_id=? AND src.package_id=?
     JOIN collection_package_members dst ON dst.entity_id=r.target_entity_id AND dst.tenant_id=src.tenant_id AND dst.package_id=src.package_id
     WHERE r.id>? AND NOT EXISTS(SELECT 1 FROM tenant_source_policy p WHERE p.tenant_id=? AND p.source_id=r.source_id AND p.enabled=0)
     AND COALESCE((SELECT decision FROM relationship_feedback WHERE tenant_id=? AND relationship_id=r.id ORDER BY created_at DESC,id DESC LIMIT 1),'confirm')!='reject'
     ORDER BY r.id LIMIT 50`,
      )
      .bind(repo.tenant, p.packageId, p.cursor, repo.tenant, repo.tenant)
      .all<{ id: string; data: string }>();
    for (const row of rows.results) {
      const edge = RelationshipSchema.parse(JSON.parse(row.data));
      if (
        !edge.provenance.redistributable ||
        !(await repo.intel.visible(repo.tenant, edge.sourceEntityId)) ||
        !(await repo.intel.visible(repo.tenant, edge.targetEntityId))
      )
        continue;
      const source = await repo.intel.entity(edge.sourceEntityId),
        target = await repo.intel.entity(edge.targetEntityId);
      const a = source ? entityStix(source, object.updatedAt) : null,
        b = target ? entityStix(target, object.updatedAt) : null;
      if (a && b) {
        objects.push(relationshipStix(edge, a.id, b.id));
        members.push(edge.sourceEntityId, edge.targetEntityId);
      }
    }
    cursor = rows.results.at(-1)?.id ?? cursor;
    complete = rows.results.length < 50;
  }
  const content = JSON.stringify({
    type: "bundle",
    id: stixId("bundle", p.packageId + ":" + p.part),
    objects,
  });
  const checksum = await digest(content);
  // Content-addressed objects prevent an expired/retried job from overwriting an accepted part.
  const key = `packages/${repo.tenant}/${p.packageId}/${p.part}/${checksum}.json`;
  await env.ARCHIVE.put(key, content, {
    httpMetadata: { contentType: "application/stix+json" },
  });
  await repo.db.batch([
    repo.db
      .prepare(
        "INSERT OR IGNORE INTO collection_package_parts VALUES(?,?,?,?,?,?,?,?,?)",
      )
      .bind(
        repo.tenant,
        p.packageId,
        p.part,
        key,
        checksum,
        objects.length,
        JSON.stringify([...new Set(members)]),
        JSON.stringify({ phase, cursor, complete }),
        new Date().toISOString(),
      ),
  ]);
  const accepted = await repo.db
    .prepare(
      "SELECT continuation FROM collection_package_parts WHERE tenant_id=? AND package_id=? AND part=?",
    )
    .bind(repo.tenant, p.packageId, p.part)
    .first<{ continuation: string }>();
  const saved = z
    .object({
      phase: z.enum(["references", "entities", "relationships"]),
      cursor: z.string(),
      complete: z.boolean(),
    })
    .parse(JSON.parse(accepted!.continuation));
  await repo.db
    .prepare(
      "UPDATE collection_packages SET status=? WHERE tenant_id=? AND id=? AND status!='complete'",
    )
    .bind(saved.complete ? "complete" : "running", repo.tenant, p.packageId)
    .run();
  await repo.intel.finish(
    job,
    { packageId: p.packageId, part: p.part, objects: objects.length },
    saved.complete
      ? undefined
      : {
          ...job,
          jobId: p.packageId + ":part:" + (p.part + 1),
          attempt: 0,
          generation: 0,
          payload: {
            mode: "collection-package",
            packageId: p.packageId,
            phase: saved.phase,
            cursor: saved.cursor,
            part: p.part + 1,
          },
        },
  );
}

/** Only disposable export copies expire. Original intelligence/evidence is never deleted. */
export async function cleanupPackages(env: Pick<AppEnv, "DB" | "ARCHIVE">) {
  const cutoff = new Date(Date.now() - 3600000).toISOString();
  const rows = await env.DB.prepare(
    "SELECT tenant_id,id FROM collection_packages WHERE expires_at<? ORDER BY expires_at LIMIT 2",
  )
    .bind(cutoff)
    .all<{ tenant_id: string; id: string }>();
  for (const row of rows.results) {
    const prefix = `packages/${row.tenant_id}/${row.id}/`;
    const page = await env.ARCHIVE.list({ prefix, limit: 50 });
    if (page.objects.length)
      await env.ARCHIVE.delete(page.objects.map((o) => o.key));
    if (!page.truncated)
      await env.DB.prepare(
        "DELETE FROM collection_packages WHERE tenant_id=? AND id=? AND expires_at<?",
      )
        .bind(row.tenant_id, row.id, cutoff)
        .run();
  }
}
