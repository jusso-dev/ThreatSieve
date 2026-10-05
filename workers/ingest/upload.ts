import { z } from "zod";
export { parseIndicators } from "../../packages/intel/src/upload";
import {
  AssessRequest,
  type PipelineJob,
} from "../../packages/schemas/src/index";
import { normalise, digest } from "../../packages/intel/src/normalise";
import { Repository } from "../../packages/database/src/repository";
import type { AppEnv } from "../../apps/api/src/env";
import { makeJob } from "./pipeline";
export async function processBulk(env: AppEnv, job: PipelineJob) {
  if (!job.tenantId) throw new Error("Bulk requires tenant");
  const repo = new Repository(env.DB);
  const file = await env.ARCHIVE.get(String(job.payload.key));
  if (!file) throw new Error("Upload missing");
  const inputs = z.array(AssessRequest).parse(await file.json());
  const offset = Number(job.payload.offset ?? 0);
  const page = inputs.slice(offset, offset + 100);
  let valid = 0;
  const errors: { index: number; error: string }[] = [];
  const seen = new Set<string>();
  for (const [i, input] of page.entries()) {
    let obs;
    try {
      obs = await normalise(input.observable, input.type);
    } catch {
      errors.push({
        index: offset + i,
        error: "Invalid or ambiguous observable",
      });
      continue;
    }
    {
      if (seen.has(obs.id)) continue;
      seen.add(obs.id);
      await repo.putObservable(
        obs,
        {
          sourceId: "upload",
          sourceName: "User upload",
          retrievedAt: new Date().toISOString(),
          redistributable: false,
        },
        job.tenantId,
      );
      const id = job.payload.rootId ?? job.jobId;
      const child = {
        ...makeJob(
          "enrich",
          obs.id,
          job.tenantId,
          { bulkId: id },
          job.correlationId,
        ),
        jobId: await digest(String(id) + obs.id),
      };
      await repo.enqueue(child);
      valid++;
    }
  }
  const nextOffset = offset + page.length;
  await repo.finish(
    job,
    { processed: page.length, valid, errors, total: inputs.length },
    nextOffset < inputs.length
      ? {
          ...job,
          jobId:
            String(job.payload.rootId ?? job.jobId) + ":page:" + nextOffset,
          payload: {
            ...job.payload,
            rootId: job.payload.rootId ?? job.jobId,
            offset: nextOffset,
          },
        }
      : undefined,
  );
}
