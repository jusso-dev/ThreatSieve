import { z } from "zod";
import type { AppEnv } from "../../apps/api/src/env";
import type { PipelineJob } from "../../packages/schemas/src/index";
import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
const Payload = z.object({
  cursor: z.string().default(""),
  runId: z.string().uuid(),
});
export async function backfillVectors(env: AppEnv, job: PipelineJob) {
  const { cursor, runId } = Payload.parse(job.payload);
  const rows = await env.DB.prepare(
    "SELECT id FROM entities WHERE public_intel=1 AND type IN ('attack-technique','threat-actor','malware','campaign') AND length(json_extract(data,'$.description'))>0 AND id>? ORDER BY id LIMIT 20",
  )
    .bind(cursor)
    .all<{ id: string }>();
  const children: PipelineJob[] = await Promise.all(
    rows.results.map(async ({ id }) => ({
      ...job,
      jobId: runId + ":index:" + (await digest(id)),
      entityId: id,
      attempt: 0,
      generation: 0,
      payload: { mode: "vector-index", runId },
    })),
  );
  if (rows.results.length === 20)
    children.push({
      ...job,
      jobId: runId + ":page:" + (await digest(rows.results.at(-1)!.id)),
      attempt: 0,
      generation: 0,
      payload: {
        mode: "vector-backfill",
        runId,
        cursor: rows.results.at(-1)!.id,
      },
    });
  await new Repository(env.DB).finish(
    job,
    { scanned: rows.results.length },
    children,
  );
}
