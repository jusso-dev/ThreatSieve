import { z } from "zod";
import type { AppEnv } from "../../apps/api/src/env";
import { EntitySchema } from "../../packages/schemas/src/index";
import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
const MODEL = "@cf/baai/bge-base-en-v1.5";
/** One bounded provider request and one D1 commit for an embedding batch. */
export async function indexEntities(env: AppEnv, entityIds: string[]) {
  const ids = z.array(z.string()).max(80).parse(entityIds);
  if (!ids.length) return { embeddedIds: [], cachedIds: [] };
  const rows = await env.DB.prepare(
    `SELECT e.data,v.evidence_version FROM entities e LEFT JOIN vector_versions v ON v.entity_id=e.id
 WHERE e.id IN (SELECT value FROM json_each(?)) AND e.public_intel=1
 AND e.type IN ('attack-technique','threat-actor','malware','campaign')
 AND json_extract(e.data,'$.provenance.sourceId') NOT IN ('customer','upload') ORDER BY e.id`,
  )
    .bind(JSON.stringify(ids))
    .all<{ data: string; evidence_version: string | null }>();
  const prepared = await Promise.all(
    rows.results.map(async (row) => {
      const entity = EntitySchema.parse(JSON.parse(row.data));
      const text = entity.description.slice(0, 6000);
      const version = await digest(
        JSON.stringify({
          text,
          model: MODEL,
          type: entity.type,
          source: entity.provenance.sourceId,
        }),
      );
      return {
        entity,
        text,
        version,
        cached: row.evidence_version === version,
      };
    }),
  );
  const cached = prepared.filter((r) => r.text && r.cached),
    pending = prepared.filter((r) => r.text && !r.cached);
  if (pending.length) {
    const output = await env.AI.run(MODEL, {
      text: pending.map((r) => r.text),
    });
    const vectors = z
      .object({
        data: z
          .array(z.array(z.number().finite()).length(768))
          .length(pending.length),
      })
      .parse(output).data;
    await env.VECTOR_INDEX.upsert(
      await Promise.all(
        pending.map(async (r, i) => ({
          id: await digest(r.entity.id),
          values: vectors[i]!,
          metadata: {
            entityType: r.entity.type,
            entityId: r.entity.id,
            source: r.entity.provenance.sourceId,
            version: r.version,
          },
        })),
      ),
    );
    const now = new Date().toISOString();
    await env.DB.batch(
      pending.map((r) =>
        env.DB.prepare(
          "INSERT INTO vector_versions VALUES(?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET evidence_version=excluded.evidence_version,model=excluded.model,updated_at=excluded.updated_at",
        ).bind(r.entity.id, r.version, MODEL, now),
      ),
    );
  }
  return {
    embeddedIds: [...cached, ...pending].map((r) => r.entity.id),
    cachedIds: cached.map((r) => r.entity.id),
  };
}
export async function enrichEntity(
  env: AppEnv,
  entityId: string,
  indexing = false,
) {
  if (!(await new Repository(env.DB).entity(entityId)))
    throw new Error("Entity not found");
  if (!indexing && env.VECTORIZE_ENABLED !== "true")
    return { strategy: "graph-context", embedded: false };
  const result = await indexEntities(env, [entityId]);
  const embedded = result.embeddedIds.includes(entityId);
  return {
    strategy: embedded ? "graph-context-and-semantic-index" : "graph-context",
    embedded,
    cached: result.cachedIds.includes(entityId),
  };
}
