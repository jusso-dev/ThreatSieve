import { z } from "zod";
import type {
  Assessment,
  Evidence,
  IntelEntity,
  IntelRelationship,
  Observable,
  PipelineJob,
  Principal,
} from "../../schemas/src/index";
import {
  EntitySchema,
  EvidenceSchema,
  ObservableSchema,
  RelationshipSchema,
  JobSchema,
  Role,
} from "../../schemas/src/index";
import { aliasKey } from "../../intel/src/normalise";
import { AppError } from "../../observability/src/index";
export class Repository {
  constructor(readonly db: D1Database) {}
  async observable(id: string) {
    const r = await this.db
      .prepare("SELECT data FROM observables WHERE id=?")
      .bind(id)
      .first<{ data: string }>();
    return r ? ObservableSchema.parse(JSON.parse(r.data)) : null;
  }
  async entity(id: string) {
    const r = await this.db
      .prepare("SELECT data FROM entities WHERE id=?")
      .bind(id)
      .first<{ data: string }>();
    return r ? EntitySchema.parse(JSON.parse(r.data)) : null;
  }
  async resolveAlias(name: string, type?: string) {
    const rows = await this.db
      .prepare(
        "SELECT DISTINCT e.data FROM entities e LEFT JOIN entity_aliases a ON a.entity_id=e.id WHERE (a.alias=? OR e.external_id=? OR lower(e.name)=?) AND (? IS NULL OR e.type=?) LIMIT 3",
      )
      .bind(aliasKey(name), name, aliasKey(name), type ?? null, type ?? null)
      .all<{ data: string }>();
    return rows.results.map((r) => EntitySchema.parse(JSON.parse(r.data)));
  }
  entityStatements(e: IntelEntity) {
    const now = new Date().toISOString();
    return [
      this.db
        .prepare(
          "INSERT INTO entities(id,type,name,external_id,data,created_at,updated_at,public_intel) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,external_id=excluded.external_id,data=excluded.data,updated_at=excluded.updated_at,public_intel=MAX(entities.public_intel,excluded.public_intel)",
        )
        .bind(
          e.id,
          e.type,
          e.name,
          e.externalId ?? null,
          JSON.stringify(e),
          now,
          now,
          Number(!["upload", "customer"].includes(e.provenance.sourceId)),
        ),
      this.db
        .prepare(
          "INSERT INTO entity_sources VALUES(?,?,?,?) ON CONFLICT(entity_id,source_id,source_record_id) DO UPDATE SET provenance=excluded.provenance",
        )
        .bind(
          e.id,
          e.provenance.sourceId,
          e.provenance.sourceRecordId ?? e.id,
          JSON.stringify(e.provenance),
        ),
      ...[e.name, ...e.aliases].map((a) =>
        this.db
          .prepare(
            "INSERT OR IGNORE INTO entity_aliases(alias,entity_id,source_id) VALUES(?,?,?)",
          )
          .bind(aliasKey(a), e.id, e.provenance.sourceId),
      ),
    ];
  }
  async putEntity(e: IntelEntity) {
    const statements = this.entityStatements(e);
    const table = {
      "threat-actor": "threat_actors",
      malware: "malware",
      campaign: "campaigns",
    }[e.type as "threat-actor" | "malware" | "campaign"];
    if (table)
      statements.push(
        this.db
          .prepare(`INSERT OR IGNORE INTO ${table}(entity_id) VALUES(?)`)
          .bind(e.id),
      );
    if (e.type === "attack-technique" && e.externalId)
      statements.push(
        this.db
          .prepare(
            "INSERT OR IGNORE INTO attack_techniques(entity_id,mitre_id) VALUES(?,?)",
          )
          .bind(e.id, e.externalId),
      );
    if (e.type === "attack-tactic" && e.externalId)
      statements.push(
        this.db
          .prepare(
            "INSERT OR IGNORE INTO attack_tactics(entity_id,mitre_id) VALUES(?,?)",
          )
          .bind(e.id, e.externalId),
      );
    if (e.type === "threat-actor")
      for (const a of e.aliases)
        statements.push(
          this.db
            .prepare(
              "INSERT OR IGNORE INTO actor_aliases(alias,entity_id,source_id) VALUES(?,?,?)",
            )
            .bind(aliasKey(a), e.id, e.provenance.sourceId),
        );
    if (e.type === "vulnerability")
      statements.push(
        this.db
          .prepare(
            "INSERT INTO vulnerabilities(entity_id,cve,vendor,product,kev,due_date) VALUES(?,?,?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,kev=excluded.kev,due_date=excluded.due_date",
          )
          .bind(
            e.id,
            e.externalId ?? e.name,
            String(e.data.vendorProject ?? ""),
            String(e.data.product ?? ""),
            Number(e.provenance.sourceId === "cisa-kev"),
            typeof e.data.dueDate === "string" ? e.data.dueDate : null,
          ),
      );
    await this.db.batch(statements);
  }
  async putObservable(
    o: Observable,
    provenance: IntelEntity["provenance"],
    tenantId?: string,
  ) {
    const previous = await this.observable(o.id);
    if (previous && ["upload", "customer"].includes(provenance.sourceId)) {
      if (tenantId)
        await this.db
          .prepare("INSERT OR IGNORE INTO tenant_observables VALUES(?,?,?)")
          .bind(tenantId, o.id, new Date().toISOString())
          .run();
      return;
    }

    const merged = {
      ...o,
      createdAt: previous?.createdAt ?? o.createdAt,
      firstSeen: [previous?.firstSeen, o.firstSeen].filter(Boolean).sort()[0],
      lastSeen: [previous?.lastSeen, o.lastSeen].filter(Boolean).sort().at(-1),
    };
    const e: IntelEntity = {
      id: o.id,
      type: "observable",
      name: o.normalizedValue,
      description: "",
      aliases: [],
      data: { observableType: o.type },
      provenance,
    };
    await this.db.batch([
      ...this.entityStatements(e),
      this.db
        .prepare(
          "INSERT INTO observables(id,type,normalized_value,first_seen,last_seen,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET first_seen=excluded.first_seen,last_seen=excluded.last_seen,data=excluded.data",
        )
        .bind(
          o.id,
          o.type,
          o.normalizedValue,
          merged.firstSeen ?? null,
          merged.lastSeen ?? null,
          JSON.stringify(merged),
        ),
      ...(tenantId
        ? [
            this.db
              .prepare("INSERT OR IGNORE INTO tenant_observables VALUES(?,?,?)")
              .bind(tenantId, o.id, new Date().toISOString()),
          ]
        : []),
    ]);
  }
  async putEvidence(entityId: string, e: Evidence) {
    await this.db
      .prepare(
        "INSERT INTO evidence(id,entity_id,source_id,data,raw_key,observed_at,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,raw_key=excluded.raw_key,observed_at=excluded.observed_at",
      )
      .bind(
        e.id,
        entityId,
        e.sourceId,
        JSON.stringify(e),
        e.rawKey ?? null,
        e.observedAt ?? null,
        e.createdAt,
      )
      .run();
  }
  async evidence(entityId: string, limit = 100) {
    const rows = await this.db
      .prepare(
        "SELECT data FROM evidence WHERE entity_id=? ORDER BY observed_at DESC,id LIMIT ?",
      )
      .bind(entityId, limit)
      .all<{ data: string }>();
    return rows.results.map((r) => EvidenceSchema.parse(JSON.parse(r.data)));
  }
  async putRelationship(r: IntelRelationship) {
    await this.db
      .prepare(
        "INSERT INTO relationships(id,source_entity_id,target_entity_id,relationship_type,assertion_type,confidence,source_id,data,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,confidence=excluded.confidence",
      )
      .bind(
        r.id,
        r.sourceEntityId,
        r.targetEntityId,
        r.relationshipType,
        r.assertionType,
        r.confidence,
        r.provenance.sourceId,
        JSON.stringify(r),
        r.createdAt,
      )
      .run();
  }
  async edges(entityId: string, limit = 80) {
    const r = await this.db
      .prepare(
        "SELECT data FROM relationships WHERE source_entity_id=? OR target_entity_id=? ORDER BY confidence DESC,id LIMIT ?",
      )
      .bind(entityId, entityId, limit)
      .all<{ data: string }>();
    return r.results.map((x) => RelationshipSchema.parse(JSON.parse(x.data)));
  }
  async visible(tenantId: string, id: string) {
    return Boolean(
      await this.db
        .prepare(
          "SELECT id FROM entities WHERE id=? AND (public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables WHERE tenant_id=? AND observable_id=entities.id))",
        )
        .bind(id, tenantId)
        .first(),
    );
  }
  async assessment(tenantId: string, id: string): Promise<Assessment | null> {
    const row = await this.db
      .prepare("SELECT data FROM assessments WHERE tenant_id=? AND id=?")
      .bind(tenantId, id)
      .first<{ data: string }>();
    return row ? (JSON.parse(row.data) as Assessment) : null;
  }
  async assessments(tenantId: string, limit = 50, cursor?: string) {
    const [time, id] = cursor
      ? z
          .tuple([z.string().datetime(), z.string().min(1)])
          .parse(JSON.parse(atob(cursor)))
      : [null, null];
    const rows = await this.db
      .prepare(
        "SELECT data FROM assessments WHERE tenant_id=? AND (? IS NULL OR created_at<? OR (created_at=? AND id>?)) ORDER BY created_at DESC,id LIMIT ?",
      )
      .bind(tenantId, time, time, time, id, limit)
      .all<{ data: string }>();
    return rows.results.map((r) => JSON.parse(r.data) as Assessment);
  }
  async cached(tenantId: string, key: string) {
    const row = await this.db
      .prepare(
        "SELECT assessment_id FROM classification_cache WHERE tenant_id=? AND cache_key=?",
      )
      .bind(tenantId, key)
      .first<{ assessment_id: string }>();
    return row ? this.assessment(tenantId, row.assessment_id) : null;
  }
  async saveAssessment(tenantId: string, a: Assessment, cacheKeys: string[]) {
    const statements = [
      this.db
        .prepare(
          "INSERT OR IGNORE INTO assessments(id,tenant_id,observable_id,evidence_version,status,severity,confidence,human_review,data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(
          a.assessment_id,
          tenantId,
          a.observable.id,
          a.evidence_version,
          a.status,
          a.severity,
          a.confidence,
          Number(a.human_review),
          JSON.stringify(a),
          a.created_at,
        ),
      ...cacheKeys.map((key) =>
        this.db
          .prepare(
            "INSERT INTO classification_cache(tenant_id,cache_key,assessment_id,created_at) VALUES(?,?,?,?) ON CONFLICT(tenant_id,cache_key) DO UPDATE SET assessment_id=excluded.assessment_id,created_at=excluded.created_at",
          )
          .bind(tenantId, key, a.assessment_id, a.created_at),
      ),
    ];
    for (const run of a.runs)
      statements.push(
        this.db
          .prepare(
            "INSERT OR IGNORE INTO classification_runs(id,tenant_id,assessment_id,model,schema_version,evidence_version,input_tokens,duration_ms,data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
          )
          .bind(
            run.id,
            tenantId,
            a.assessment_id,
            run.model,
            run.schemaVersion,
            run.evidenceVersion,
            run.inputTokens,
            run.durationMs,
            JSON.stringify(run),
            run.timestamp,
          ),
      );
    for (const m of a.attack)
      statements.push(
        this.db
          .prepare("INSERT OR IGNORE INTO assessment_attack VALUES(?,?,?,?,?)")
          .bind(
            tenantId,
            a.assessment_id,
            m.techniqueId,
            m.probability,
            JSON.stringify(m),
          ),
      );
    for (const m of a.actors)
      statements.push(
        this.db
          .prepare("INSERT OR IGNORE INTO assessment_actors VALUES(?,?,?,?,?)")
          .bind(
            tenantId,
            a.assessment_id,
            m.id,
            m.association_probability,
            JSON.stringify(m),
          ),
      );
    for (const m of a.recommended_actions)
      statements.push(
        this.db
          .prepare("INSERT OR IGNORE INTO assessment_actions VALUES(?,?,?,?)")
          .bind(tenantId, a.assessment_id, m.action, JSON.stringify(m)),
      );
    await this.db.batch(statements);
  }
  jobStatements(job: PipelineJob) {
    const queue =
      job.stage === "feed-sync" || job.stage === "bulk" ? "ingest" : job.stage;
    return [
      this.db
        .prepare(
          "INSERT OR IGNORE INTO pipeline_jobs(id,tenant_id,entity_id,stage,status,data,created_at,updated_at) VALUES(?,?,?,?,'queued',?,?,?)",
        )
        .bind(
          job.jobId,
          job.tenantId ?? null,
          job.entityId,
          job.stage,
          JSON.stringify(job),
          job.createdAt,
          job.createdAt,
        ),
      this.db
        .prepare(
          "INSERT OR IGNORE INTO outbox(id,queue,data,created_at) VALUES(?,?,?,?)",
        )
        .bind(job.jobId, queue, JSON.stringify(job), job.createdAt),
    ];
  }
  async enqueue(job: PipelineJob) {
    await this.db.batch(this.jobStatements(job));
  }
  async finish(job: PipelineJob, result: unknown, next?: PipelineJob) {
    const statements = [
      this.db
        .prepare(
          "UPDATE pipeline_jobs SET status='complete',result=?,lease_until=NULL,updated_at=? WHERE id=?",
        )
        .bind(JSON.stringify(result), new Date().toISOString(), job.jobId),
    ];
    if (next) statements.push(...this.jobStatements(next));
    await this.db.batch(statements);
  }
  async job(tenantId: string, id: string) {
    return this.db
      .prepare(
        "SELECT id,stage,status,attempt,result,error_type,created_at,updated_at FROM pipeline_jobs WHERE tenant_id=? AND id=?",
      )
      .bind(tenantId, id)
      .first();
  }
  async claim(job: PipelineJob) {
    const now = new Date().toISOString();
    const until = new Date(Date.now() + 300000).toISOString();
    const r = await this.db
      .prepare(
        "UPDATE pipeline_jobs SET status='running',attempt=attempt+1,lease_until=?,updated_at=? WHERE id=? AND (status='queued' OR (status='running' AND lease_until<?))",
      )
      .bind(until, now, job.jobId, now)
      .run();
    return r.meta.changes > 0;
  }
  async audit(
    p: Principal,
    action: string,
    entityId: string,
    correlationId: string,
    data: unknown = {},
    ip?: string,
  ) {
    await this.db
      .prepare("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(
        crypto.randomUUID(),
        p.tenantId,
        p.userId,
        action,
        entityId,
        ip ?? null,
        correlationId,
        JSON.stringify(data),
        new Date().toISOString(),
      )
      .run();
  }
  async feedback(
    p: Principal,
    id: string,
    decision: Assessment["status"],
    field: string,
    value: unknown,
    reason: string,
    correlationId: string,
  ) {
    const a = await this.assessment(p.tenantId, id);
    if (!a) throw new AppError("NOT_FOUND", 404, "Assessment not found");
    const now = new Date().toISOString();
    const updated: Assessment = { ...a, status: decision };
    if (decision === "modified") {
      if (field === "malicious")
        updated.effective_classification = z
          .enum(["malicious", "suspicious", "benign", "unknown"])
          .parse(value);
      else if (field === "role") Role.parse(value);
      else if (field === "attack" || field === "actors") {
        const ids = z.array(z.string()).max(20).parse(value);
        for (const entityId of ids) {
          const entity = await this.entity(entityId);
          if (
            !entity ||
            entity.type !==
              (field === "attack" ? "attack-technique" : "threat-actor")
          )
            throw new AppError(
              "INVALID_OVERRIDE",
              422,
              "Analyst selections must reference existing intelligence entities",
            );
        }
      } else
        throw new AppError(
          "INVALID_OVERRIDE",
          422,
          "Modify a specific decision field",
        );
      updated.analyst_decision = {
        field,
        value,
        reason,
        analystId: p.userId,
        createdAt: now,
      };
    }
    if (decision === "confirmed") updated.human_review = false;
    if (
      decision === "rejected" ||
      decision === "needs-investigation" ||
      decision === "modified"
    ) {
      updated.human_review = true;
      updated.recommended_actions = [
        {
          action: "investigate",
          confidence: a.confidence,
          reason_codes: a.reason_codes,
        },
      ];
    }
    const originalFields: Record<string, unknown> = {
      assessment: a,
      malicious: a.malicious,
      role: a.role,
      attack: a.attack,
      actors: a.actors,
    };
    await this.db.batch([
      this.db
        .prepare("INSERT INTO analyst_feedback VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(
          crypto.randomUUID(),
          p.tenantId,
          id,
          p.userId,
          field,
          JSON.stringify(originalFields[field] ?? null),
          JSON.stringify(value ?? decision),
          reason,
          now,
        ),
      this.db
        .prepare(
          "UPDATE assessments SET status=?,data=? WHERE tenant_id=? AND id=?",
        )
        .bind(decision, JSON.stringify(updated), p.tenantId, id),
      this.db
        .prepare(
          "DELETE FROM classification_cache WHERE tenant_id=? AND assessment_id=?",
        )
        .bind(p.tenantId, id),
      this.db
        .prepare("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(
          crypto.randomUUID(),
          p.tenantId,
          p.userId,
          "assessment." + decision,
          id,
          null,
          correlationId,
          JSON.stringify({ field, reason }),
          now,
        ),
    ]);
    return updated;
  }
  async queuedMessage(id: string) {
    const row = await this.db
      .prepare("SELECT data FROM pipeline_jobs WHERE id=?")
      .bind(id)
      .first<{ data: string }>();
    return row ? JobSchema.parse(JSON.parse(row.data)) : null;
  }
}
