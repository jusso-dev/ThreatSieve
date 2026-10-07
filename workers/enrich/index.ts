import { z } from "zod";
import type { AppEnv } from "../../apps/api/src/env";
import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
export async function enrichEntity(
  env: AppEnv,
  entityId: string,
  indexing = false,
) {
  const repo = new Repository(env.DB);
  const entity = await repo.entity(entityId);
  if (!entity) throw new Error("Entity not found");
  const text = entity.description.slice(0, 6000);
  if (
    (!indexing && env.VECTORIZE_ENABLED !== "true") ||
    !text ||
    !["attack-technique", "threat-actor", "malware", "campaign"].includes(
      entity.type,
    )
  )
    return { strategy: "graph-context", embedded: false };
  const global = await env.DB.prepare(
    "SELECT public_intel FROM entities WHERE id=?",
  )
    .bind(entityId)
    .first<{ public_intel: number }>();
  if (
    !global?.public_intel ||
    ["customer", "upload"].includes(entity.provenance.sourceId)
  )
    return { strategy: "private-graph-context", embedded: false };
  const version = await digest(
    JSON.stringify({
      text,
      model: "@cf/baai/bge-base-en-v1.5",
      type: entity.type,
      source: entity.provenance.sourceId,
    }),
  );
  const previous = await env.DB.prepare(
    "SELECT evidence_version FROM vector_versions WHERE entity_id=?",
  )
    .bind(entityId)
    .first<{ evidence_version: string }>();
  if (previous?.evidence_version === version)
    return { strategy: "graph-context", embedded: true, cached: true };
  const output = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
    text: [text],
  });
  const values = z
    .object({ data: z.array(z.array(z.number()).length(768)).length(1) })
    .parse(output).data[0]!;
  await env.VECTOR_INDEX.upsert([
    {
      id: await digest(entityId),
      values,
      metadata: {
        entityType: entity.type,
        entityId: entity.id,
        source: entity.provenance.sourceId,
        version,
      },
    },
  ]);
  await env.DB.prepare(
    "INSERT INTO vector_versions VALUES(?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET evidence_version=excluded.evidence_version,model=excluded.model,updated_at=excluded.updated_at",
  )
    .bind(
      entity.id,
      version,
      "@cf/baai/bge-base-en-v1.5",
      new Date().toISOString(),
    )
    .run();
  return { strategy: "graph-context-and-semantic-index", embedded: true };
}
