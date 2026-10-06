import { exportWorkspace } from "./export";
import { OperationsRepository } from "./repository";
import { AppError } from "../../observability/src/index";
import type { WorkObject } from "../../schemas/src/enterprise";
/** Snapshot publication prevents changing membership from skipping or duplicating pages. */
export async function publishCollection(
  repo: OperationsRepository,
  object: WorkObject,
) {
  if (object.tenantId !== repo.tenant)
    throw new AppError("NOT_FOUND", 404, "Collection unavailable");
  if (
    object.kind !== "collection" ||
    object.status !== "published" ||
    object.publication !== "taxii"
  )
    throw new AppError(
      "NOT_PUBLISHED",
      409,
      "Publish this collection to TAXII first.",
    );
  const bundle = await exportWorkspace(repo, object);
  const generation = crypto.randomUUID(),
    now = new Date().toISOString();
  const previous = await repo.db
    .prepare(
      "SELECT o.object_id,o.version,o.date_added FROM taxii_objects o JOIN taxii_publications p ON p.tenant_id=o.tenant_id AND p.collection_id=o.collection_id AND p.generation=o.generation WHERE o.tenant_id=? AND o.collection_id=?",
    )
    .bind(repo.tenant, object.id)
    .all<{ object_id: string; version: string; date_added: string }>();
  const dates = new Map(
    previous.results.map((o) => [o.object_id + ":" + o.version, o.date_added]),
  );
  for (let i = 0; i < bundle.objects.length; i += 80)
    await repo.db.batch(
      bundle.objects.slice(i, i + 80).map((o) => {
        const version = String(o.modified ?? o.created ?? object.updatedAt);
        return repo.db
          .prepare("INSERT INTO taxii_objects VALUES(?,?,?,?,?,?,?,?)")
          .bind(
            repo.tenant,
            object.id,
            generation,
            o.id,
            version,
            o.type,
            dates.get(o.id + ":" + version) ?? now,
            JSON.stringify(o),
          );
      }),
    );
  // Only expose the snapshot if the collection was not edited during publication.
  const result = await repo.db
    .prepare(
      "INSERT INTO taxii_publications SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=? AND id=? AND revision=?) ON CONFLICT(tenant_id,collection_id) DO UPDATE SET generation=excluded.generation,revision=excluded.revision,published_at=excluded.published_at,object_count=excluded.object_count",
    )
    .bind(
      repo.tenant,
      object.id,
      generation,
      object.revision,
      now,
      bundle.objects.length,
      repo.tenant,
      object.id,
      object.revision,
    )
    .run();
  if (!result.meta.changes)
    throw new AppError(
      "REVISION_CONFLICT",
      409,
      "Collection changed during publication. Publish its latest revision.",
    );
  await repo.intel.audit(
    repo.principal,
    "collection.published",
    object.id,
    generation,
    { revision: object.revision, objects: bundle.objects.length },
  );
  return { generation, objects: bundle.objects.length, publishedAt: now };
}
