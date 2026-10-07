import { z } from "zod";
import type { AppEnv } from "../../apps/api/src/env";
import type { PipelineJob } from "../../packages/schemas/src/index";
import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
import { indexEntities } from "./index";
const Payload = z.object({
  cursor: z.string().default(""),
  runId: z.string().uuid(),
});
export async function backfillVectors(env: AppEnv, job: PipelineJob) {
  const { cursor, runId } = Payload.parse(job.payload);
  const rows = await env.DB.prepare(
    "SELECT id FROM entities WHERE public_intel=1 AND type IN ('attack-technique','threat-actor','malware','campaign') AND length(json_extract(data,'$.description'))>0 AND id>? ORDER BY id LIMIT 80",
  )
    .bind(cursor)
    .all<{ id: string }>();
  const indexed = await indexEntities(
    env,
    rows.results.map((r) => r.id),
  );
  const last = rows.results.at(-1)?.id;
  const next: PipelineJob | undefined =
    rows.results.length === 80
      ? {
          ...job,
          jobId: runId + ":page:" + (await digest(last!)),
          attempt: 0,
          generation: 0,
          payload: { mode: "vector-backfill", runId, cursor: last },
        }
      : undefined;
  await new Repository(env.DB).finish(
    job,
    {
      scanned: rows.results.length,
      submitted: indexed.embeddedIds.length,
      cached: indexed.cachedIds.length,
    },
    next,
  );
}
