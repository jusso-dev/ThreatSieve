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

export type BulkDiagnostics = {
  processed: number;
  accepted: number;
  duplicates: number;
  rejected: number;
  errors: { index: number; error: string }[];
};

function priorDiagnostics(payload: PipelineJob["payload"]): BulkDiagnostics {
  const raw = payload.diagnostics;
  if (!raw || typeof raw !== "object")
    return {
      processed: 0,
      accepted: 0,
      duplicates: 0,
      rejected: 0,
      errors: [],
    };
  const d = raw as Record<string, unknown>;
  return {
    processed: Number(d.processed ?? 0),
    accepted: Number(d.accepted ?? 0),
    duplicates: Number(d.duplicates ?? 0),
    rejected: Number(d.rejected ?? 0),
    errors: Array.isArray(d.errors)
      ? (d.errors as BulkDiagnostics["errors"])
      : [],
  };
}

export async function processBulk(env: AppEnv, job: PipelineJob) {
  if (!job.tenantId) throw new Error("Bulk requires tenant");
  const repo = new Repository(env.DB);
  const file = await env.ARCHIVE.get(String(job.payload.key));
  if (!file) throw new Error("Upload missing");
  const inputs = z.array(AssessRequest).parse(await file.json());
  const offset = Number(job.payload.offset ?? 0);
  const page = inputs.slice(offset, offset + 100);
  const prior = priorDiagnostics(job.payload);
  const seen = new Set<string>(
    Array.isArray(job.payload.seenIds)
      ? (job.payload.seenIds as string[])
      : [],
  );
  let accepted = 0;
  let duplicates = 0;
  let rejected = 0;
  const errors: { index: number; error: string }[] = [];
  for (const [i, input] of page.entries()) {
    let obs;
    try {
      obs = await normalise(input.observable, input.type);
    } catch {
      errors.push({
        index: offset + i,
        error: "Invalid or ambiguous observable",
      });
      rejected++;
      continue;
    }
    if (seen.has(obs.id)) {
      duplicates++;
      continue;
    }
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
    accepted++;
  }
  const diagnostics: BulkDiagnostics = {
    processed: prior.processed + page.length,
    accepted: prior.accepted + accepted,
    duplicates: prior.duplicates + duplicates,
    rejected: prior.rejected + rejected,
    errors: [...prior.errors, ...errors],
  };
  const nextOffset = offset + page.length;
  const rootId = String(job.payload.rootId ?? job.jobId);
  await repo.finish(
    job,
    diagnostics,
    nextOffset < inputs.length
      ? {
          ...job,
          jobId: rootId + ":page:" + nextOffset,
          payload: {
            ...job.payload,
            rootId,
            offset: nextOffset,
            seenIds: [...seen],
            diagnostics,
          },
        }
      : undefined,
  );
}
