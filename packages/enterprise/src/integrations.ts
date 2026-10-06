import { z } from "zod";
import { AppError } from "../../observability/src/index";
import type { AppEnv } from "../../../apps/api/src/env";
import type { PipelineJob } from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
const Target = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,60}$/),
  name: z.string().max(100),
  url: z.url(),
  allowedHost: z.string(),
  tenantIds: z.array(z.string()).min(1).max(1000),
  secretName: z.string().regex(/^[A-Z0-9_]{1,80}$/),
  allowPrivateIdentifiers: z.boolean().default(false),
});
export function integrationTargets(raw: string | undefined, tenant: string) {
  return z
    .array(Target)
    .max(50)
    .parse(JSON.parse(raw ?? "[]"))
    .filter((t) => t.tenantIds.includes(tenant))
    .map((t) => {
      const u = new URL(t.url);
      if (
        u.protocol !== "https:" ||
        u.hostname !== t.allowedHost ||
        u.username ||
        u.password ||
        (u.port && u.port !== "443") ||
        /^(localhost|.*\.local|.*\.internal|\d+\.\d+\.\d+\.\d+|\[.*\])$/.test(
          u.hostname,
        )
      )
        throw new AppError(
          "INTEGRATION_POLICY",
          400,
          "Integration requires an approved HTTPS DNS host.",
        );
      return t;
    });
}
export async function deliverIntegration(
  env: AppEnv,
  job: PipelineJob,
  request: typeof fetch = (input, init) => fetch(input, init),
) {
  if (!job.tenantId) throw new Error("Integration requires tenant");
  if (
    !(await env.DB.prepare(
      "SELECT 1 FROM tenant_members WHERE tenant_id=? AND user_id=? AND role='admin'",
    )
      .bind(job.tenantId, z.string().parse(job.payload.ownerId))
      .first())
  )
    throw new Error("Integration owner no longer authorized");
  const target = integrationTargets(env.INTEGRATION_TARGETS, job.tenantId).find(
    (t) => t.id === job.payload.target,
  );
  if (!target) throw new Error("Integration target unavailable for workspace");
  const secrets = z
      .record(z.string(), z.string().min(20))
      .parse(JSON.parse(env.INTEGRATION_SECRETS ?? "{}")),
    secret = secrets[target.secretName];
  if (!secret) throw new Error("Integration credential not configured");
  const intel = new Repository(env.DB);
  if (!(await intel.visible(job.tenantId, job.entityId)))
    throw new Error("Integration entity unavailable");
  const entity = await intel.entity(job.entityId);
  if (!entity!.provenance.redistributable) {
    const privateOwned = await env.DB.prepare(
      "SELECT 1 FROM entities e JOIN tenant_observables t ON t.observable_id=e.id AND t.tenant_id=? WHERE e.id=? AND e.public_intel=0",
    )
      .bind(job.tenantId, job.entityId)
      .first();
    if (!privateOwned || !target.allowPrivateIdentifiers)
      throw new Error(
        "Identifier redistribution is not authorized for this integration",
      );
  }
  // Only selected identifiers and the event are sent. Raw intelligence and customer telemetry are excluded.
  const payload = JSON.stringify({
    schema_version: "1.0",
    event_id: job.payload.eventId,
    event_type: job.payload.eventType,
    entity: { id: entity!.id, type: entity!.type, name: entity!.name },
    workspace: job.tenantId,
    occurred_at: job.createdAt,
  });
  const response = await request(target.url, {
    method: "POST",
    redirect: "manual",
    signal: AbortSignal.timeout(10000),
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + secret,
      "Idempotency-Key": job.jobId,
    },
    body: payload,
  });
  await response.body?.cancel();
  if (!response.ok) throw new Error("Integration delivery rejected");
  await intel.finish(job, {
    delivered: true,
    target: target.id,
    status: response.status,
  });
}
