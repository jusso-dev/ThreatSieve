import { z } from "zod";
export { parseIndicators } from "../../packages/intel/src/upload";
import {
  AssessRequest,
  type PipelineJob,
} from "../../packages/schemas/src/index";
import { normalise, digest } from "../../packages/intel/src/normalise";
import {
  BULK_ARCHIVE_PAGE_SIZE,
  archivePageKey,
  partitionArchive,
} from "../../packages/intel/src/archive-pages";
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
export const BULK_ERROR_SAMPLE_LIMIT = 20;

export async function processBulk(env: AppEnv, job: PipelineJob) {
  if (!job.tenantId) throw new Error("Bulk requires tenant");

  const key = z.string().parse(job.payload.key);
  const rootId = String(job.payload.rootId ?? job.jobId);
  const offset = z
    .number()
    .int()
    .nonnegative()
    .parse(job.payload.offset ?? 0);
  if (offset % 100) throw new Error("Invalid bulk page offset");
  const fence =
    "EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id=? AND status IN ('queued','running') AND result IS NULL AND COALESCE(json_extract(data,'$.generation'),0)=?) AND EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id=? AND stage='bulk' AND json_extract(data,'$.payload.key')=?)";
  const fenceValues = [
    job.jobId,
    job.tenantId,
    job.generation ?? 0,
    rootId,
    job.tenantId,
    key,
  ];
  const active = await env.DB.prepare("SELECT 1 WHERE " + fence)
    .bind(...fenceValues)
    .first();
  if (!active) return;
  // Partition an existing upload once when upgrading a legacy continuation.
  let total = z.number().int().nonnegative().parse(job.payload.total);
  if (!job.payload.partitioned) {
    const file = await env.ARCHIVE.get(key);
    if (!file) throw new Error("Upload missing");
    const inputs = z.array(AssessRequest).parse(await file.json());
    total = inputs.length;
    await partitionArchive(env.ARCHIVE, key, inputs, BULK_ARCHIVE_PAGE_SIZE);
  }
  const archiveOffset =
    Math.floor(offset / BULK_ARCHIVE_PAGE_SIZE) * BULK_ARCHIVE_PAGE_SIZE;
  const file = await env.ARCHIVE.get(archivePageKey(key, archiveOffset));
  if (!file) throw new Error("Upload page missing");
  const archived = z
    .array(AssessRequest)
    .max(BULK_ARCHIVE_PAGE_SIZE)
    .parse(await file.json());
  const page = archived.slice(
    offset - archiveOffset,
    offset - archiveOffset + 100,
  );
  if (offset > total || page.length !== Math.min(100, total - offset))
    throw new Error("Upload page size mismatch");
  if (!job.payload.partitioned && offset) {
    // Negative ordinals are migration-only deduplication seeds, not new inputs.
    // Previous page results supply the already committed cumulative totals.
    const seen = z.array(z.string()).parse(job.payload.seenIds ?? []);
    for (let start = 0; start < seen.length; start += 100)
      await env.DB.prepare(
        "INSERT OR IGNORE INTO bulk_items(tenant_id,bulk_id,input_index,observable_id,outcome) SELECT ?,?,-CAST(key AS INTEGER)-?-1,value,'accepted' FROM json_each(?) WHERE " +
          fence,
      )
        .bind(
          job.tenantId,
          rootId,
          start,
          JSON.stringify(seen.slice(start, start + 100)),
          ...fenceValues,
        )
        .run();
  }
  for (const [i, input] of page.entries()) {
    const writes: D1PreparedStatement[] = [];
    const repo = new Repository(env.DB, writes);
    const index = offset + i;
    let obs;
    try {
      obs = await normalise(input.observable, input.type);
    } catch {
      /* recorded below */
    }
    if (obs) {
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
    }
    const token = crypto.randomUUID();
    const statements = [
      env.DB.prepare(
        "INSERT INTO pipeline_commit_guard(token,won) SELECT ?,CASE WHEN " +
          fence +
          " THEN 1 ELSE 0 END",
      ).bind(token, ...fenceValues),
      ...writes,
      env.DB.prepare(
        "INSERT OR IGNORE INTO bulk_items(tenant_id,bulk_id,input_index,observable_id,outcome,error) SELECT ?,?,?,?,CASE WHEN ? IS NULL THEN 'rejected' WHEN EXISTS(SELECT 1 FROM bulk_items WHERE tenant_id=? AND bulk_id=? AND observable_id=? AND outcome='accepted') THEN 'duplicates' ELSE 'accepted' END,? WHERE " +
          fence,
      ).bind(
        job.tenantId,
        rootId,
        index,
        obs?.id ?? null,
        obs?.id ?? null,
        job.tenantId,
        rootId,
        obs?.id ?? null,
        obs ? null : "Invalid or ambiguous observable",
        ...fenceValues,
      ),
    ];
    if (obs) {
      const child = {
        ...makeJob(
          "enrich",
          obs.id,
          job.tenantId,
          { bulkId: rootId },
          job.correlationId,
        ),
        jobId: await digest(rootId + obs.id),
      };
      statements.push(
        ...repo.jobStatements(child, {
          guard: {
            sql:
              "EXISTS(SELECT 1 FROM bulk_items WHERE tenant_id=? AND bulk_id=? AND input_index=? AND outcome='accepted') AND " +
              fence,
            bindings: [job.tenantId, rootId, index, ...fenceValues],
          },
        }),
      );
    }
    // Outcome and downstream delivery commit together. Redelivery cannot count
    // the same input twice or publish a second enrichment.
    statements.push(
      env.DB.prepare("DELETE FROM pipeline_commit_guard WHERE token=?").bind(
        token,
      ),
    );
    try {
      await env.DB.batch(statements);
    } catch (error) {
      if (
        error instanceof Error &&
        /CHECK constraint failed: won=1/.test(error.message)
      )
        return;
      throw error;
    }
  }
  const counts = await env.DB.prepare(
    "SELECT COUNT(*) AS processed,COALESCE(SUM(outcome='accepted'),0) AS accepted,COALESCE(SUM(outcome='duplicates'),0) AS duplicates,COALESCE(SUM(outcome='rejected'),0) AS rejected FROM bulk_items WHERE tenant_id=? AND bulk_id=? AND input_index>=? AND input_index<?",
  )
    .bind(job.tenantId, rootId, offset, offset + page.length)
    .first<Omit<BulkDiagnostics, "errors">>();
  const errors = await env.DB.prepare(
    "SELECT input_index AS 'index',error FROM bulk_items WHERE tenant_id=? AND bulk_id=? AND outcome='rejected' AND input_index>=? AND input_index<? ORDER BY input_index LIMIT ?",
  )
    .bind(
      job.tenantId,
      rootId,
      offset,
      offset + page.length,
      BULK_ERROR_SAMPLE_LIMIT,
    )
    .all<BulkDiagnostics["errors"][number]>();
  const previous = offset
    ? await env.DB.prepare(
        "SELECT result FROM pipeline_jobs WHERE tenant_id=? AND id=? AND status='complete'",
      )
        .bind(
          job.tenantId,
          offset === 100 ? rootId : rootId + ":page:" + (offset - 100),
        )
        .first<{ result: string }>()
    : null;
  if (offset && !previous) throw new Error("Previous bulk page not committed");
  const prior = previous
    ? (JSON.parse(previous.result) as BulkDiagnostics)
    : undefined;
  const diagnostics: BulkDiagnostics = {
    processed: (prior?.processed ?? 0) + (counts?.processed ?? 0),
    accepted: (prior?.accepted ?? 0) + (counts?.accepted ?? 0),
    duplicates: (prior?.duplicates ?? 0) + (counts?.duplicates ?? 0),
    rejected: (prior?.rejected ?? 0) + (counts?.rejected ?? 0),
    errors: [...(prior?.errors ?? []), ...errors.results].slice(
      0,
      BULK_ERROR_SAMPLE_LIMIT,
    ),
  };
  const nextOffset = offset + page.length;
  await new Repository(env.DB).finish(
    job,
    diagnostics,
    nextOffset < total
      ? {
          ...job,
          jobId: rootId + ":page:" + nextOffset,
          generation: undefined,
          // Fixed-size contract: never carry previous IDs, errors, or totals.
          payload: {
            key,
            total,
            partitioned: true,
            rootId,
            bulkId: rootId,
            offset: nextOffset,
          },
        }
      : undefined,
  );
}
