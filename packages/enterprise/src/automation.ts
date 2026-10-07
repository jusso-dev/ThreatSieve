import { publishCollection } from "./taxii";
import { Repository } from "../../database/src/repository";
import { OperationsRepository } from "./repository";
import { criterionMatches, dossier, cachedCoverage } from "./intelligence";
import {
  WorkObjectSchema,
  WorkInput,
  type WorkObject,
} from "../../schemas/src/enterprise";
import type { PipelineJob, Principal } from "../../schemas/src/index";
import { digest } from "../../intel/src/normalise";
import { z } from "zod";
interface Change {
  id: string;
  tenant_id: string | null;
  entity_id: string;
  event_type: string;
  reference_id: string;
  created_at: string;
}
function operationJob(
  id: string,
  entity: string,
  payload: Record<string, unknown>,
  tenant?: string,
): PipelineJob {
  return {
    jobId: id,
    entityId: entity,
    tenantId: tenant,
    stage: "operations",
    attempt: 0,
    createdAt: new Date().toISOString(),
    correlationId: id,
    payload,
  };
}
/** A committed SQL change and its queued job are connected atomically. Redelivery is safe. */
export async function scheduleOperations(db: D1Database) {
  const rows = await db
    .prepare(
      "SELECT id,entity_id,tenant_id FROM intelligence_changes WHERE queued_at IS NULL ORDER BY sequence LIMIT 25",
    )
    .all<Change>();
  const intel = new Repository(db);
  for (const row of rows.results)
    await db.batch([
      ...intel.jobStatements(
        operationJob(
          "change:" + row.id,
          row.entity_id,
          { eventId: row.id },
          row.tenant_id ?? undefined,
        ),
      ),
      db
        .prepare(
          "UPDATE intelligence_changes SET queued_at=? WHERE id=? AND queued_at IS NULL",
        )
        .bind(new Date().toISOString(), row.id),
    ]);
  return rows.results.length;
}
export async function matchObject(
  repo: OperationsRepository,
  object: WorkObject,
  change: Change,
) {
  if (!(await repo.intel.visible(repo.tenant, change.entity_id))) return null;
  const direct =
    object.references.some(
      (r) => r.type === "entity" && r.id === change.entity_id,
    ) ||
    Boolean(
      await repo.db
        .prepare(
          "SELECT 1 FROM workspace_links WHERE tenant_id=? AND object_id=? AND target_type='entity' AND target_id=? AND relation IN ('member','automation_member')",
        )
        .bind(repo.tenant, object.id, change.entity_id)
        .first(),
    );
  // Empty criteria cannot match a new entity. Curated references still match directly.
  if (
    !direct &&
    !(
      "criteria" in object &&
      Object.values(object.criteria).some(
        (v) => Array.isArray(v) && v.length > 0,
      )
    )
  )
    return null;
  const d = await dossier(repo, change.entity_id);
  const criteria =
    "criteria" in object
      ? criterionMatches(
          object.criteria,
          {
            ...d.entity,
            data: {
              ...d.entity.data,
              tags: [
                ...(Array.isArray(d.entity.data.tags)
                  ? d.entity.data.tags
                  : []),
                ...d.workspaceTags,
              ],
            },
          },
          d.evidence,
        )
      : null;
  if (!direct && !criteria?.matches) return null;
  return {
    dossier: d,
    evidenceIds: (criteria?.evidence ?? d.evidence).map((e) => e.id),
    dimensions: criteria?.dimensions ?? [],
    direct,
  };
}
async function actor(
  db: D1Database,
  tenant: string,
  user: string,
): Promise<Principal | null> {
  const member = await db
    .prepare("SELECT role FROM tenant_members WHERE tenant_id=? AND user_id=?")
    .bind(tenant, user)
    .first<{ role: string }>();
  if (!member || member.role === "viewer") return null;
  return {
    tenantId: tenant,
    userId: user,
    keyId: "automation",
    kind: "key",
    scopes:
      member.role === "admin"
        ? ["admin"]
        : ["intel:read", "assessment:read", "assessment:write"],
  };
}
export async function processOperation(db: D1Database, job: PipelineJob) {
  const intel = new Repository(db);
  if (job.payload.mode === "backfill") {
    if (!job.tenantId || typeof job.payload.objectId !== "string")
      throw new Error("Backfill requires workspace");
    const cursor = z.string().parse(job.payload.cursor ?? "");
    const row = await db
      .prepare(
        "SELECT data FROM workspace_objects WHERE tenant_id=? AND id=? AND status IN ('active','published')",
      )
      .bind(job.tenantId, job.payload.objectId)
      .first<{ data: string }>();
    if (!row) {
      await intel.finish(job, { skipped: "inactive" });
      return;
    }
    const object = WorkObjectSchema.parse(JSON.parse(row.data));
    const principal = await actor(db, job.tenantId, object.ownerId);
    if (!principal) {
      await intel.finish(job, { skipped: "owner unavailable" });
      return;
    }
    const rows = await db
      .prepare(
        "SELECT id FROM entities e WHERE id>? AND (public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables t WHERE t.tenant_id=? AND t.observable_id=e.id)) AND (?=1 OR e.id IN (SELECT json_extract(value,'$.id') FROM json_each(?) WHERE json_extract(value,'$.type')='entity') OR EXISTS(SELECT 1 FROM workspace_links WHERE tenant_id=? AND object_id=? AND target_type='entity' AND target_id=e.id AND relation IN ('member','automation_member'))) ORDER BY id LIMIT 21",
      )
      .bind(
        cursor,
        job.tenantId,
        Number(
          "criteria" in object &&
            Object.values(object.criteria).some(
              (v) => Array.isArray(v) && v.length > 0,
            ),
        ),
        JSON.stringify(object.references),
        job.tenantId,
        object.id,
      )
      .all<{ id: string }>();
    for (const entity of rows.results.slice(0, 20)) {
      const eventId =
        "backfill:" + object.id + ":" + object.revision + ":" + entity.id;
      const now = new Date().toISOString();
      await db.batch([
        db
          .prepare(
            "INSERT OR IGNORE INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at,queued_at) VALUES(?,?,?,?,?,?,?)",
          )
          .bind(
            eventId,
            job.tenantId,
            entity.id,
            "indicator.updated",
            entity.id,
            now,
            now,
          ),
        ...intel.jobStatements(
          operationJob(
            eventId,
            entity.id,
            { eventId, objectId: object.id },
            job.tenantId,
          ),
        ),
      ]);
    }
    if (rows.results.length > 20) {
      const cursor = rows.results[19]!.id;
      await intel.enqueue(
        operationJob(
          "backfill:" + object.id + ":" + object.revision + ":page:" + cursor,
          object.id,
          { mode: "backfill", objectId: object.id, cursor },
          job.tenantId,
        ),
      );
    }
    if (object.kind === "requirement")
      await cachedCoverage(new OperationsRepository(db, principal), object);
    await intel.finish(job, {
      scanned: Math.min(rows.results.length, 20),
      more: rows.results.length > 20,
    });
    return;
  }
  if (job.payload.mode === "publish-taxii") {
    if (!job.tenantId) throw new Error("Publication requires tenant");
    const user = z.string().parse(job.payload.ownerId),
      principal = await actor(db, job.tenantId, user);
    if (!principal?.scopes.includes("admin"))
      throw new Error("Publication owner no longer authorized");
    const repo = new OperationsRepository(db, principal),
      object = await repo.get(
        z.string().parse(job.payload.collectionId),
        "collection",
      );
    await intel.finish(job, await publishCollection(repo, object));
    return;
  }
  const eventId = z.string().parse(job.payload.eventId);
  const event = await db
    .prepare("SELECT * FROM intelligence_changes WHERE id=?")
    .bind(eventId)
    .first<Change>();
  if (!event) {
    await intel.finish(job, { skipped: "event unavailable" });
    return;
  }
  if (typeof job.payload.objectId !== "string") {
    const cursor = z.string().parse(job.payload.cursor ?? "");
    const rows = await db
      .prepare(
        "SELECT tenant_id,id FROM workspace_objects WHERE status IN ('active','published') AND kind IN ('requirement','watchlist','collection','playbook') AND (? IS NULL OR tenant_id=?) AND (tenant_id || ':' || id)>? ORDER BY tenant_id,id LIMIT 26",
      )
      .bind(event.tenant_id, event.tenant_id, cursor)
      .all<{ tenant_id: string; id: string }>();
    for (const row of rows.results.slice(0, 25))
      await intel.enqueue(
        operationJob(
          "change:" + event.id + ":" + row.tenant_id + ":" + row.id,
          event.entity_id,
          { eventId: event.id, objectId: row.id },
          row.tenant_id,
        ),
      );
    if (rows.results.length > 25) {
      const last = rows.results[24]!;
      const nextCursor = last.tenant_id + ":" + last.id;
      await intel.enqueue(
        operationJob(
          "change:" + event.id + ":page:" + nextCursor,
          event.entity_id,
          { eventId: event.id, cursor: nextCursor },
          event.tenant_id ?? undefined,
        ),
      );
    }
    await intel.finish(job, { dispatched: Math.min(rows.results.length, 25) });
    return;
  }
  if (!job.tenantId || (event.tenant_id && event.tenant_id !== job.tenantId))
    throw new Error("Operations tenant boundary rejected");
  const row = await db
    .prepare(
      "SELECT data FROM workspace_objects WHERE tenant_id=? AND id=? AND status IN ('active','published')",
    )
    .bind(job.tenantId, job.payload.objectId)
    .first<{ data: string }>();
  if (!row) {
    await intel.finish(job, { skipped: "inactive subscription" });
    return;
  }
  const object = WorkObjectSchema.parse(JSON.parse(row.data));
  const principal = await actor(db, job.tenantId, object.ownerId);
  if (!principal) {
    await intel.finish(job, { skipped: "owner no longer has write access" });
    return;
  }
  const repo = new OperationsRepository(db, principal);
  if (object.kind === "playbook") {
    if (!principal.scopes.includes("admin")) {
      await intel.finish(job, {
        skipped: "playbook owner no longer administrator",
      });
      return;
    }
    if (object.trigger !== event.event_type) {
      await intel.finish(job, { skipped: "different trigger" });
      return;
    }
    const hasCriteria =
      Object.values(object.criteria).some(
        (v) => Array.isArray(v) && v.length > 0,
      ) ||
      object.criteria.minConfidence > 0 ||
      Boolean(object.criteria.from || object.criteria.to);
    const matched = hasCriteria ? await matchObject(repo, object, event) : null;
    if (hasCriteria && !matched) {
      await intel.finish(job, { skipped: "conditions not met" });
      return;
    }
    try {
      await executePlaybook(repo, object, event, job);
    } catch (error) {
      const id =
        "automation_" +
        (await digest(repo.tenant + ":" + object.id + ":" + event.id));
      await db
        .prepare(
          "INSERT INTO automation_executions VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET status=excluded.status,data=excluded.data",
        )
        .bind(
          repo.tenant,
          id,
          object.id,
          event.id,
          "failed",
          JSON.stringify({
            revision: object.revision,
            errorType: error instanceof Error ? error.name : "ExecutionError",
            message:
              "Execution failed; queued retry and dead-letter controls apply.",
          }),
          new Date().toISOString(),
        )
        .run();
      throw error;
    }
  } else if (["watchlist", "requirement", "collection"].includes(object.kind)) {
    // Derived match events cannot recursively trigger another round of subscriptions.
    if (["watchlist.match", "requirement.match"].includes(event.event_type)) {
      await intel.finish(job, { skipped: "derived event" });
      return;
    }
    const matched = await matchObject(repo, object, event);
    if (matched) {
      const old = await db
        .prepare(
          "SELECT score,event_id FROM workspace_matches WHERE tenant_id=? AND object_id=? AND entity_id=?",
        )
        .bind(repo.tenant, object.id, event.entity_id)
        .first<{ score: number | null; event_id: string }>();
      const now = new Date().toISOString();
      const id = "match:" + object.id + ":" + event.id;
      const statements = [
        db
          .prepare(
            "INSERT INTO workspace_matches VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,object_id,entity_id) DO UPDATE SET evidence_ids=excluded.evidence_ids,criteria=excluded.criteria,event_id=excluded.event_id,matched_at=excluded.matched_at,score=excluded.score",
          )
          .bind(
            repo.tenant,
            object.id,
            event.entity_id,
            JSON.stringify(matched.evidenceIds),
            JSON.stringify(matched.dimensions),
            event.id,
            now,
            matched.dossier.scores.threat.value,
          ),
      ];
      // Minimum meaningful score movement is 15 policy points, not a model probability.
      const significant =
        event.event_type !== "score.changed" ||
        old?.score === null ||
        old === null ||
        Math.abs(
          (old.score ?? 0) - (matched.dossier.scores.threat.value ?? 0),
        ) >= 15;
      const notify =
        object.kind === "watchlist"
          ? object.triggers.includes(
              event.event_type as (typeof object.triggers)[number],
            ) && significant
          : object.kind === "requirement" && !old;
      if (notify && old?.event_id !== event.id) {
        statements.push(
          notification(
            db,
            repo.tenant,
            id,
            object.id,
            event.entity_id,
            event.id,
            object.title + ": " + event.event_type.replaceAll(".", " "),
            now,
          ),
        );
        statements.push(
          db
            .prepare(
              "INSERT OR IGNORE INTO intelligence_events VALUES(?,?,?,?,?,?,?,?)",
            )
            .bind(
              repo.tenant,
              id,
              "entity",
              event.entity_id,
              object.kind + ".match",
              "automation:" + object.id,
              JSON.stringify({
                objectId: object.id,
                evidenceIds: matched.evidenceIds,
                eventId: event.id,
              }),
              now,
            ),
        );
      }
      await db.batch(statements);
    } else
      await db
        .prepare(
          "DELETE FROM workspace_matches WHERE tenant_id=? AND object_id=? AND entity_id=?",
        )
        .bind(repo.tenant, object.id, event.entity_id)
        .run();
  }
  if (object.kind === "requirement") {
    await db
      .prepare(
        "DELETE FROM requirement_metrics WHERE tenant_id=? AND requirement_id=?",
      )
      .bind(repo.tenant, object.id)
      .run();
    await cachedCoverage(repo, object);
  }
  await intel.finish(job, {
    processed: true,
    objectId: object.id,
    eventId: event.id,
  });
}
function notification(
  db: D1Database,
  tenant: string,
  id: string,
  object: string,
  entity: string | null,
  event: string,
  reason: string,
  now: string,
) {
  return db
    .prepare(
      "INSERT OR IGNORE INTO workspace_notifications(tenant_id,id,object_id,entity_id,event_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(tenant, id, object, entity, event, reason, now);
}
async function executePlaybook(
  repo: OperationsRepository,
  object: WorkObject & { kind: "playbook" },
  event: Change,
  job: PipelineJob,
) {
  const id =
    "automation_" +
    (await digest(repo.tenant + ":" + object.id + ":" + event.id));
  if (
    await repo.db
      .prepare(
        "SELECT 1 FROM automation_executions WHERE tenant_id=? AND id=? AND status='complete'",
      )
      .bind(repo.tenant, id)
      .first()
  )
    return;
  const now = new Date().toISOString();
  const statements: D1PreparedStatement[] = [];
  const outcomes: Record<string, unknown>[] = [];
  const visible = await repo.intel.visible(repo.tenant, event.entity_id);
  for (const [i, action] of object.actions.entries()) {
    const actionId = id + ":" + i;
    if (action.type === "notify") {
      statements.push(
        notification(
          repo.db,
          repo.tenant,
          actionId,
          object.id,
          visible ? event.entity_id : null,
          event.id,
          object.title + ": " + event.event_type.replaceAll(".", " "),
          now,
        ),
      );
      outcomes.push({ action: action.type, result: "notified" });
      continue;
    }
    if (action.type === "publish-taxii") {
      const target = await repo.get(action.target ?? "", "collection");
      statements.push(
        ...repo.intel.jobStatements({
          ...job,
          jobId: actionId,
          stage: "operations",
          payload: {
            mode: "publish-taxii",
            collectionId: target.id,
            ownerId: object.ownerId,
          },
          createdAt: now,
          attempt: 0,
        }),
      );
      outcomes.push({ action: action.type, result: "queued", jobId: actionId });
      continue;
    }
    if (!visible) {
      outcomes.push({
        action: action.type,
        result: "skipped",
        reason: "Event has no visible intelligence entity",
      });
      continue;
    }
    if (action.type === "send-webhook") {
      statements.push(
        ...repo.intel.jobStatements({
          ...job,
          jobId: actionId,
          stage: "operations",
          payload: {
            mode: "integration",
            target: action.target,
            eventId: event.id,
            eventType: event.event_type,
            ownerId: object.ownerId,
          },
          createdAt: now,
          attempt: 0,
        }),
      );
      outcomes.push({ action: action.type, result: "queued", jobId: actionId });
      continue;
    }
    if (action.type === "tag") {
      if (!action.target?.trim()) throw new Error("Tag action requires a tag");
      statements.push(
        repo.db
          .prepare("INSERT OR IGNORE INTO entity_tags VALUES(?,?,?,?,?)")
          .bind(
            repo.tenant,
            event.entity_id,
            action.target.trim(),
            "automation:" + object.id,
            now,
          ),
      );
    } else if (action.type === "create-investigation") {
      const title = action.target || object.title;
      const work: WorkObject = {
        ...WorkInput.parse({
          kind: "investigation",
          title,
          description: "Created by playbook " + object.title,
          ownerId: object.ownerId,
          references: [
            { type: "entity", id: event.entity_id, relation: "investigates" },
          ],
        }),
        id: actionId,
        tenantId: repo.tenant,
        ownerId: object.ownerId,
        revision: 1,
        createdBy: "automation:" + object.id,
        createdAt: now,
        updatedAt: now,
      };
      statements.push(
        repo.db
          .prepare(
            "INSERT OR IGNORE INTO workspace_objects VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
          )
          .bind(
            repo.tenant,
            work.id,
            work.kind,
            work.title,
            work.status,
            work.priority,
            work.ownerId,
            1,
            actionId,
            JSON.stringify(work),
            now,
            now,
          ),
      );
      statements.push(
        repo.db
          .prepare("INSERT OR IGNORE INTO workspace_links VALUES(?,?,?,?,?)")
          .bind(
            repo.tenant,
            work.id,
            "entity",
            event.entity_id,
            "investigates",
          ),
      );
      statements.push(
        repo.db
          .prepare(
            "INSERT OR IGNORE INTO intelligence_events VALUES(?,?,?,?,?,?,?,?)",
          )
          .bind(
            repo.tenant,
            actionId,
            "investigation",
            work.id,
            "investigation.created",
            "automation:" + object.id,
            JSON.stringify({
              after: work,
              playbookId: object.id,
              eventId: event.id,
            }),
            now,
          ),
      );
    } else if (action.type === "add-to-watchlist") {
      const target = await repo.get(action.target ?? "", "watchlist");
      // Automatic membership is separate from analyst-curated references and cannot overwrite an edit.
      statements.push(
        repo.db
          .prepare("INSERT OR IGNORE INTO workspace_links VALUES(?,?,?,?,?)")
          .bind(
            repo.tenant,
            target.id,
            "entity",
            event.entity_id,
            "automation_member",
          ),
      );
      const intelligence = await dossier(repo, event.entity_id);
      statements.push(
        repo.db
          .prepare(
            "INSERT INTO workspace_matches VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,object_id,entity_id) DO NOTHING",
          )
          .bind(
            repo.tenant,
            target.id,
            event.entity_id,
            JSON.stringify(intelligence.evidence.map((e) => e.id)),
            JSON.stringify(["playbook_membership"]),
            event.id,
            now,
            intelligence.scores.threat.value,
          ),
      );
      statements.push(
        notification(
          repo.db,
          repo.tenant,
          actionId,
          target.id,
          event.entity_id,
          event.id,
          "Added by playbook " + object.title,
          now,
        ),
      );
    } else if (action.type === "enrich" || action.type === "export") {
      let payload: Record<string, unknown> = {};
      if (action.type === "export") {
        const latest = await repo.db
          .prepare(
            "SELECT id FROM assessments WHERE tenant_id=? AND observable_id=? ORDER BY created_at DESC LIMIT 1",
          )
          .bind(repo.tenant, event.entity_id)
          .first<{ id: string }>();
        if (!latest) {
          outcomes.push({
            action: action.type,
            result: "skipped",
            reason: "No assessment is available to export",
          });
          continue;
        }
        payload = { assessmentId: latest.id };
      }
      statements.push(
        ...repo.intel.jobStatements({
          ...job,
          jobId: actionId,
          stage: action.type,
          tenantId: repo.tenant,
          payload,
          createdAt: now,
          attempt: 0,
        }),
      );
      outcomes.push({ action: action.type, result: "queued", jobId: actionId });
      continue;
    }
    outcomes.push({
      action: action.type,
      result: "complete",
      target: action.target,
    });
  }
  statements.push(
    repo.db
      .prepare(
        "INSERT INTO automation_executions VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET status=excluded.status,data=excluded.data",
      )
      .bind(
        repo.tenant,
        id,
        object.id,
        event.id,
        "complete",
        JSON.stringify({
          actions: outcomes,
          revision: object.revision,
          eventType: event.event_type,
          entityId: visible ? event.entity_id : null,
        }),
        now,
      ),
  );
  statements.push(
    repo.db
      .prepare(
        "INSERT OR IGNORE INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES(?,?,?,?,?,?,?,?)",
      )
      .bind(
        id,
        repo.tenant,
        "automation:" + object.id,
        "playbook.executed",
        object.id,
        event.id,
        JSON.stringify({ executionId: id, actions: outcomes }),
        now,
      ),
  );
  await repo.db.batch(statements);
}

export async function queueBackfill(
  repo: OperationsRepository,
  object: WorkObject,
) {
  if (
    !["requirement", "watchlist", "collection"].includes(object.kind) ||
    !["active", "published"].includes(object.status)
  )
    return;
  const job = operationJob(
    "backfill:" + object.id + ":" + object.revision,
    object.id,
    { mode: "backfill", objectId: object.id },
    repo.tenant,
  );
  await repo.intel.enqueue(job);
  return job.jobId;
}
