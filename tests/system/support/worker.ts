import { hashPassword } from "better-auth/crypto";
/** Test-only Worker entry. Production wrangler.jsonc never imports this module. */
import production from "../../../apps/api/src/index";
import type { AppEnv } from "../../../apps/api/src/env";
import { Repository } from "../../../packages/database/src/repository";
import { digest } from "../../../packages/intel/src/normalise";
import { RecordedTransport } from "../../helpers";
import {
  FLASH,
  FULL,
  type DecisionRequest,
} from "../../../packages/clef/src/index";
import { z } from "zod";
import { Scopes } from "../../../packages/schemas/src/index";

type TestEnv = AppEnv & { TEST_CONTROL_TOKEN: string };
function environment(env: TestEnv): AppEnv {
  // The real WorkersAITransport runs; only the remote AI binding is replaced.
  // Ai's generated interface contains unused streaming and model overloads.
  const ai = {
    async run(model: string, input: DecisionRequest) {
      if (model !== FLASH && model !== FULL)
        throw new Error("Unexpected model in offline test");
      const state = z
        .object({ observable: z.object({ normalizedValue: z.string() }) })
        .passthrough()
        .parse(input.state);
      if (state.observable.normalizedValue.startsWith("classifier-failure."))
        throw new Error("Synthetic upstream outage");
      const reply = await new RecordedTransport(0.97, "c2", 0.1).run(
        model,
        input,
      );
      return { ...reply, model_version: "synthetic-e2e-v1" };
    },
  } as unknown as Ai;
  const email = {
    async send(message: EmailMessageBuilder) {
      const recipient = typeof message.to === "string" ? message.to : "unknown";
      await env.ARCHIVE.put("test-mail/" + recipient, JSON.stringify(message));
      return { messageId: crypto.randomUUID() };
    },
  } as SendEmail;
  return { ...env, AI: ai, EMAIL: email };
}
export default {
  async fetch(request: Request, env: TestEnv, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/__test/"))
      return production.fetch(request, environment(env), ctx);
    if (request.headers.get("X-Test-Control") !== env.TEST_CONTROL_TOKEN)
      return new Response(null, { status: 404 });
    if (url.pathname === "/__test/mail" && request.method === "POST") {
      const { email } = z
        .object({ email: z.string().email() })
        .parse(await request.json());
      const mail = await env.ARCHIVE.get("test-mail/" + email);
      return Response.json(mail ? await mail.json() : null);
    }
    const repo = new Repository(env.DB);
    if (url.pathname === "/__test/workspace" && request.method === "POST") {
      const input = z
        .object({
          scopes: z.array(Scopes).default(["admin"]),
          seeded: z.boolean().default(true),
          extraAssessments: z.number().int().min(0).max(120).default(0),
        })
        .parse(await request.json());
      const tenantId = crypto.randomUUID(),
        keyId = crypto.randomUUID(),
        key = crypto.randomUUID() + crypto.randomUUID();
      const now = new Date().toISOString();
      const userId = crypto.randomUUID(),
        email = userId + "@example.com",
        password = "Synthetic passphrase 42!";
      const role = input.scopes.includes("admin")
        ? "admin"
        : input.scopes.includes("assessment:write")
          ? "analyst"
          : "viewer";
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)",
        ).bind(tenantId, "Isolated E2E workspace", now),
        env.DB.prepare(
          "INSERT INTO users(id,email,name,email_verified,created_at,updated_at) VALUES(?,?,?,1,?,?)",
        ).bind(userId, email, "Demo analyst", now, now),
        env.DB.prepare(
          "INSERT INTO auth_accounts(id,account_id,provider_id,user_id,password,created_at,updated_at) VALUES(?,?,'credential',?,?,?,?)",
        ).bind(userId, userId, userId, await hashPassword(password), now, now),
        env.DB.prepare(
          "INSERT INTO tenant_members(id,tenant_id,user_id,role,created_at) VALUES(?,?,?,?,?)",
        ).bind(userId, tenantId, userId, role, now),
        env.DB.prepare(
          "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
        ).bind(
          keyId,
          tenantId,
          userId,
          "Test-only key",
          await digest(key),
          JSON.stringify(input.scopes),
          now,
        ),
        env.DB.prepare(
          "INSERT INTO customer_environments SELECT ?,data,updated_at FROM customer_environments WHERE tenant_id='demo-tenant'",
        ).bind(tenantId),
        env.DB.prepare(
          "INSERT INTO customer_assets SELECT id,?,name,product,internet_exposed,data FROM customer_assets WHERE tenant_id='demo-tenant'",
        ).bind(tenantId),
      ]);
      const assessments = input.seeded
        ? await repo.assessments("demo-tenant", 100)
        : [];
      for (const a of assessments) await repo.saveAssessment(tenantId, a, []);
      for (let i = 0; i < input.extraAssessments; i++) {
        const a = assessments[0]!;
        await repo.saveAssessment(
          tenantId,
          {
            ...a,
            assessment_id: `page-${String(i).padStart(3, "0")}`,
            created_at: now,
          },
          [],
        );
      }
      return Response.json({
        tenantId,
        keyId,
        key,
        assessments,
        email,
        password,
        userId,
      });
    }
    if (url.pathname === "/__test/inspect" && request.method === "POST") {
      const { tenantId } = z
        .object({ tenantId: z.string() })
        .parse(await request.json());
      const audit = await env.DB.prepare(
        "SELECT action,entity_id,data FROM audit_events WHERE tenant_id=? ORDER BY created_at,id",
      )
        .bind(tenantId)
        .all();
      const feedback = await env.DB.prepare(
        "SELECT field,analyst_value,reason FROM analyst_feedback WHERE tenant_id=?",
      )
        .bind(tenantId)
        .all();
      const jobs = await env.DB.prepare(
        "SELECT id,stage,status,error_type FROM pipeline_jobs WHERE tenant_id=?",
      )
        .bind(tenantId)
        .all();
      const runs = await env.DB.prepare(
        "SELECT model,data FROM classification_runs WHERE tenant_id=?",
      )
        .bind(tenantId)
        .all();
      return Response.json({
        audit: audit.results,
        feedback: feedback.results,
        jobs: jobs.results,
        runs: runs.results,
      });
    }
    if (url.pathname === "/__test/feed-state" && request.method === "POST") {
      const { sourceId, jobId } = z
        .object({ sourceId: z.string(), jobId: z.string().optional() })
        .parse(await request.json());
      const job = jobId
        ? await env.DB.prepare(
            "SELECT result FROM pipeline_jobs WHERE id=? AND entity_id=?",
          )
            .bind(jobId, sourceId)
            .first<{ result: string | null }>()
        : null;
      const provenance = await env.DB.prepare(
        "SELECT provenance FROM entity_sources WHERE source_id=?",
      )
        .bind(sourceId)
        .all();
      const checkpoint = await env.DB.prepare(
        "SELECT checkpoint FROM feed_checkpoints WHERE source_id=?",
      )
        .bind(sourceId)
        .first();
      const evidence = await env.DB.prepare(
        "SELECT id,raw_key FROM evidence WHERE source_id=?",
      )
        .bind(sourceId)
        .all();
      const archive = await env.ARCHIVE.list({
        prefix: "raw/" + sourceId + "/",
      });
      return Response.json({
        checkpoint,
        provenance: provenance.results,
        evidence: evidence.results,
        archive: archive.objects.map((o) => o.key),
        finalized: job?.result
          ? JSON.parse(job.result).finalized === true
          : false,
      });
    }
    return new Response(null, { status: 404 });
  },
  queue(batch: MessageBatch<unknown>, env: TestEnv) {
    return production.queue(batch, environment(env));
  },
} satisfies ExportedHandler<TestEnv>;
