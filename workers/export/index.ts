import { Repository } from "../../packages/database/src/repository";
import { exportStix } from "../../packages/stix/src/index";
import { digest } from "../../packages/intel/src/normalise";
export async function exportAssessment(
  env: {
    DB: D1Database;
    ARCHIVE: {
      put(
        key: string,
        value: string,
        options: { httpMetadata: { contentType: string } },
      ): Promise<unknown>;
    };
  },
  tenantId: string,
  assessmentId: string,
) {
  const repo = new Repository(env.DB);
  const a = await repo.assessment(tenantId, assessmentId);
  if (!a) throw new Error("Assessment not found");
  const revision = a.revision ?? 0;
  const existing = await env.DB.prepare(
    "SELECT id,r2_key FROM assessment_exports WHERE tenant_id=? AND assessment_id=? AND revision=?",
  )
    .bind(tenantId, assessmentId, revision)
    .first<{ id: string; r2_key: string }>();
  if (existing) return existing;
  const id = await digest(tenantId + ":" + assessmentId + ":" + revision);
  const key =
    "exports/" + tenantId + "/" + assessmentId + "/" + revision + ".json";
  await env.ARCHIVE.put(key, JSON.stringify(exportStix(a)), {
    httpMetadata: { contentType: "application/stix+json" },
  });
  // If feedback raced with serialization, retry against the current decision instead of publishing stale intelligence.
  const result = await env.DB.prepare(
    "INSERT OR IGNORE INTO assessment_exports(id,tenant_id,assessment_id,revision,r2_key,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM assessments WHERE tenant_id=? AND id=? AND revision=?)",
  )
    .bind(
      id,
      tenantId,
      assessmentId,
      revision,
      key,
      new Date().toISOString(),
      tenantId,
      assessmentId,
      revision,
    )
    .run();
  if (!result.meta.changes) {
    const saved = await env.DB.prepare(
      "SELECT id,r2_key FROM assessment_exports WHERE id=?",
    )
      .bind(id)
      .first<{ id: string; r2_key: string }>();
    if (saved) return saved;
    throw new Error("Assessment changed during export; retry current revision");
  }
  return { id, r2_key: key };
}
