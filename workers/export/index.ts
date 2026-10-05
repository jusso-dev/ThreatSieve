import type { AppEnv } from "../../apps/api/src/env";
import { Repository } from "../../packages/database/src/repository";
import { exportStix } from "../../packages/stix/src/index";
export async function exportAssessment(
  env: AppEnv,
  tenantId: string,
  assessmentId: string,
) {
  const repo = new Repository(env.DB);
  const a = await repo.assessment(tenantId, assessmentId);
  if (!a) throw new Error("Assessment not found");
  const existing = await env.DB.prepare(
    "SELECT id,r2_key FROM exports WHERE tenant_id=? AND assessment_id=?",
  )
    .bind(tenantId, assessmentId)
    .first<{ id: string; r2_key: string }>();
  if (existing) return existing;
  const id = crypto.randomUUID();
  const key = "exports/" + tenantId + "/" + assessmentId + ".json";
  await env.ARCHIVE.put(key, JSON.stringify(exportStix(a)), {
    httpMetadata: { contentType: "application/stix+json" },
  });
  await env.DB.prepare("INSERT INTO exports VALUES(?,?,?,?,?)")
    .bind(id, tenantId, assessmentId, key, new Date().toISOString())
    .run();
  return { id, r2_key: key };
}
