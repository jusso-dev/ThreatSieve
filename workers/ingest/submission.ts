import type { Principal } from "../../packages/schemas/src/index";
import { Repository } from "../../packages/database/src/repository";
import { canonicalJson, digest } from "../../packages/intel/src/normalise";
import { AppError } from "../../packages/observability/src/index";
import { makeJob } from "./pipeline";
interface UploadArchive {
  put(key: string, body: string): Promise<unknown>;
  delete(key: string): Promise<void>;
}
export async function submitBulk(
  db: D1Database,
  archive: UploadArchive,
  p: Principal,
  inputs: unknown[],
  requestKey: string | undefined,
  correlationId: string,
) {
  const repo = new Repository(db);
  const hash = await digest(canonicalJson(inputs));
  const replay = async () => {
    if (!requestKey) return null;
    const row = await db
      .prepare(
        "SELECT job_id,body_hash FROM request_idempotency WHERE tenant_id=? AND request_key=?",
      )
      .bind(p.tenantId, requestKey)
      .first<{ job_id: string; body_hash: string }>();
    if (row && row.body_hash !== hash)
      throw new AppError(
        "IDEMPOTENCY_CONFLICT",
        409,
        "This idempotency key was already used with different indicators",
      );
    return row;
  };
  const previous = await replay();
  if (previous)
    return {
      job_id: previous.job_id,
      submitted: inputs.length,
      status: "queued",
      replayed: true,
    };
  const key = "uploads/" + p.tenantId + "/" + crypto.randomUUID() + ".json";
  const job = makeJob(
    "bulk",
    key,
    p.tenantId,
    { key, total: inputs.length },
    correlationId,
  );
  job.payload.bulkId = job.jobId;
  await archive.put(key, JSON.stringify(inputs));
  try {
    const statements = requestKey
      ? [
          db
            .prepare(
              "INSERT OR IGNORE INTO request_idempotency VALUES(?,?,?,?,?)",
            )
            .bind(p.tenantId, requestKey, hash, job.jobId, job.createdAt),
        ]
      : [];
    statements.push(...repo.jobStatements(job, { requestKey }));
    statements.push(
      db
        .prepare(
          "INSERT INTO audit_events SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=?)",
        )
        .bind(
          crypto.randomUUID(),
          p.tenantId,
          p.userId,
          "bulk.import",
          job.jobId,
          null,
          correlationId,
          JSON.stringify({ count: inputs.length }),
          job.createdAt,
          job.jobId,
        ),
    );
    await db.batch(statements);
  } catch (error) {
    await archive.delete(key);
    throw error;
  }
  let winner;
  try {
    winner = await replay();
  } catch (error) {
    await archive.delete(key);
    throw error;
  }
  if (winner && winner.job_id !== job.jobId) await archive.delete(key);
  return {
    job_id: winner?.job_id ?? job.jobId,
    submitted: inputs.length,
    status: "queued",
    replayed: !!winner && winner.job_id !== job.jobId,
  };
}
