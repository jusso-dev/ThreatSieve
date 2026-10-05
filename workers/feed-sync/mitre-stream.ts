import { z } from "zod";
import { archiveStream } from "../../packages/intel/src/archive-stream";
import type { AppEnv } from "../../apps/api/src/env";
import type { PipelineJob } from "../../packages/schemas/src/index";
import { Repository } from "../../packages/database/src/repository";
import { streamStixObjects } from "../../packages/intel/src/stix-stream";
import { makeJob } from "../ingest/pipeline";
/** Official ATT&CK snapshots are too large to JSON.parse safely in one Worker heap. */
export async function syncMitreStream(env: AppEnv, job: PipelineJob) {
  const repo = new Repository(env.DB);
  const response = await fetch(
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    { redirect: "manual", signal: AbortSignal.timeout(120000) },
  );
  if (!response.ok || !response.body)
    throw new Error("MITRE upstream HTTP " + response.status);
  let bytes = 0;
  const limited = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        bytes += chunk.byteLength;
        if (bytes > 96 * 1024 * 1024)
          throw new Error("ATT&CK snapshot exceeds 96 MiB");
        controller.enqueue(chunk);
      },
    }),
  );
  const [archive, parse] = limited.tee();
  const now = new Date().toISOString();
  const rawKey =
    "raw/mitre/" +
    now.slice(0, 10).replaceAll("-", "/") +
    "/" +
    job.jobId +
    ".json";
  let archiveError: unknown;
  const archived = archiveStream(env.ARCHIVE, rawKey, archive).catch(
    (error) => {
      archiveError = error;
    },
  );
  let records = 0;
  let chunk: unknown[] = [];
  const chunkKeys: string[] = [];
  const flush = async () => {
    const key =
      "raw/mitre/chunks/" + job.jobId + "/" + chunkKeys.length + ".json";
    await env.ARCHIVE.put(key, JSON.stringify(chunk));
    chunkKeys.push(key);
    chunk = [];
  };
  try {
    for await (const item of streamStixObjects(parse)) {
      z.object({ id: z.string(), type: z.string() }).passthrough().parse(item);
      chunk.push(item);
      records++;
      if (records > 50000)
        throw new Error(
          "ATT&CK snapshot exceeds 50,000 objects; split the collection",
        );
      if (chunk.length === 100) await flush();
    }
    if (chunk.length) await flush();
    await archived;
    if (archiveError) throw archiveError;
  } catch (error) {
    await archived.catch(() => undefined);
    throw error;
  }
  for (const [index, key] of chunkKeys.entries())
    await repo.enqueue({
      ...makeJob(
        "normalise",
        "mitre",
        undefined,
        { feedId: "mitre", feedChunk: key, rawKey, feedJobId: job.jobId },
        job.correlationId,
      ),
      jobId: job.jobId + ":chunk:" + index,
    });
  await repo.finish(job, { rawKey, records, checkpoint: now });
  await env.DB.prepare(
    "UPDATE sources SET status='syncing',last_error=NULL WHERE id='mitre'",
  ).run();
}
