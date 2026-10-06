import { z } from "zod";
import { Repository } from "../../database/src/repository";
import { AppError } from "../../observability/src/index";
import { canonicalJson, digest, normalise } from "../../intel/src/normalise";
import {
  EvidenceSchema,
  type Principal,
  type Evidence,
} from "../../schemas/src/index";
import {
  WorkInput,
  WorkObjectSchema,
  type WorkObject,
  type WorkKind,
  Reference,
  NoteInput,
  SightingInput,
  type Sighting,
  type IntelligenceEvent,
} from "../../schemas/src/enterprise";
export class OperationsRepository {
  readonly intel: Repository;
  constructor(
    readonly db: D1Database,
    readonly principal: Principal,
  ) {
    this.intel = new Repository(db);
  }
  get tenant() {
    return this.principal.tenantId;
  }
  private unavailable(): never {
    throw new AppError(
      "NOT_FOUND",
      404,
      "This workspace record is unavailable.",
    );
  }
  canRead(o: WorkObject) {
    return (
      !(o.kind === "collection" && o.publication === "private") ||
      o.ownerId === this.principal.userId ||
      o.collaborators.includes(this.principal.userId) ||
      this.principal.scopes.includes("admin")
    );
  }
  async get(id: string, kind?: WorkKind): Promise<WorkObject> {
    const row = await this.db
      .prepare("SELECT data FROM workspace_objects WHERE tenant_id=? AND id=?")
      .bind(this.tenant, id)
      .first<{ data: string }>();
    if (!row) this.unavailable();
    const o = WorkObjectSchema.parse(JSON.parse(row.data));
    if ((kind && o.kind !== kind) || !this.canRead(o)) this.unavailable();
    return o;
  }
  async list(kind: WorkKind, q = "", status = "", cursor = "", limit = 50) {
    const rows = await this.db
      .prepare(
        `SELECT data FROM workspace_objects WHERE tenant_id=? AND kind=? AND (?='' OR instr(lower(title),lower(?))>0) AND (?='' OR status=?) AND (?='' OR id>?) AND (kind!='collection' OR json_extract(data,'$.publication')!='private' OR owner_id=? OR EXISTS(SELECT 1 FROM json_each(json_extract(data,'$.collaborators')) WHERE value=?) OR ?=1) ORDER BY id LIMIT ?`,
      )
      .bind(
        this.tenant,
        kind,
        q,
        q,
        status,
        status,
        cursor,
        cursor,
        this.principal.userId,
        this.principal.userId,
        Number(this.principal.scopes.includes("admin")),
        limit + 1,
      )
      .all<{ data: string }>();
    const data = rows.results
      .slice(0, limit)
      .map((r) => WorkObjectSchema.parse(JSON.parse(r.data)));
    return {
      data,
      next_cursor: rows.results.length > limit ? data.at(-1)!.id : null,
    };
  }
  async members() {
    return (
      await this.db
        .prepare(
          "SELECT u.id,u.name,u.email,m.role FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=? ORDER BY u.name,u.id LIMIT 200",
        )
        .bind(this.tenant)
        .all<{ id: string; name: string | null; email: string; role: string }>()
    ).results;
  }
  async validateMembers(ids: string[]) {
    for (const id of new Set(ids)) {
      if (
        !(await this.db
          .prepare(
            "SELECT 1 FROM tenant_members WHERE tenant_id=? AND user_id=?",
          )
          .bind(this.tenant, id)
          .first())
      )
        throw new AppError(
          "INVALID_MEMBER",
          400,
          "Owners, collaborators and task assignees must belong to this workspace.",
        );
    }
  }
  async evidence(id: string): Promise<Evidence> {
    const privateRow = await this.db
      .prepare(
        "SELECT data FROM customer_observations WHERE tenant_id=? AND id=?",
      )
      .bind(this.tenant, id)
      .first<{ data: string }>();
    if (privateRow) return EvidenceSchema.parse(JSON.parse(privateRow.data));
    const row = await this.db
      .prepare("SELECT entity_id,data FROM evidence WHERE id=?")
      .bind(id)
      .first<{ entity_id: string; data: string }>();
    if (!row || !(await this.intel.visible(this.tenant, row.entity_id)))
      this.unavailable();
    return EvidenceSchema.parse(JSON.parse(row.data));
  }
  async validateReferences(refs: Reference[]) {
    for (const ref of refs) {
      if (ref.type === "entity") {
        if (!(await this.intel.visible(this.tenant, ref.id)))
          this.unavailable();
      } else if (ref.type === "assessment") {
        if (!(await this.intel.assessment(this.tenant, ref.id)))
          this.unavailable();
      } else if (ref.type === "evidence") await this.evidence(ref.id);
      else await this.get(ref.id, ref.type);
    }
  }
  private eventStatement(
    id: string,
    type: string,
    subjectType: string,
    subjectId: string,
    data: unknown,
    now: string,
    gate?: { id: string; change: string },
  ) {
    return this.db
      .prepare(
        `INSERT OR IGNORE INTO intelligence_events(tenant_id,id,subject_type,subject_id,event_type,actor_id,data,created_at) SELECT ?,?,?,?,?,?,?,? ${gate ? "WHERE EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=? AND id=? AND change_id=?)" : ""}`,
      )
      .bind(
        this.tenant,
        id,
        subjectType,
        subjectId,
        type,
        this.principal.userId,
        JSON.stringify(data),
        now,
        ...(gate ? [this.tenant, gate.id, gate.change] : []),
      );
  }
  private auditStatement(
    id: string,
    action: string,
    subjectId: string,
    data: unknown,
    now: string,
    gate?: { id: string; change: string },
  ) {
    return this.db
      .prepare(
        `INSERT INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) SELECT ?,?,?,?,?,?,?,? ${gate ? "WHERE EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=? AND id=? AND change_id=?)" : ""}`,
      )
      .bind(
        id,
        this.tenant,
        this.principal.userId,
        action,
        subjectId,
        id,
        JSON.stringify(data),
        now,
        ...(gate ? [this.tenant, gate.id, gate.change] : []),
      );
  }
  async removeAutomaticMember(id: string, entityId: string) {
    const object = await this.get(id, "watchlist");
    if (!(await this.intel.visible(this.tenant, entityId))) this.unavailable();
    const change = crypto.randomUUID(),
      now = new Date().toISOString();
    await this.db.batch([
      this.db
        .prepare(
          "DELETE FROM workspace_links WHERE tenant_id=? AND object_id=? AND target_type='entity' AND target_id=? AND relation='automation_member'",
        )
        .bind(this.tenant, object.id, entityId),
      this.db
        .prepare(
          "DELETE FROM workspace_matches WHERE tenant_id=? AND object_id=? AND entity_id=?",
        )
        .bind(this.tenant, object.id, entityId),
      this.eventStatement(
        change,
        "watchlist.member_removed",
        "watchlist",
        object.id,
        { entityId, reason: "Analyst removed automatic membership" },
        now,
      ),
      this.auditStatement(
        change,
        "watchlist.member_removed",
        object.id,
        { entityId },
        now,
      ),
    ]);
  }
  async save(
    raw: unknown,
    id?: string,
    expected?: number,
    reason = "Created by analyst",
  ) {
    const input = WorkInput.parse(raw);
    if (input.kind === "playbook") {
      for (const action of input.actions) {
        if (action.type === "tag" && !action.target?.trim())
          throw new AppError(
            "INVALID_ACTION",
            400,
            "Choose a tag for the tag action.",
          );
        if (action.type === "publish-taxii") {
          const collection = await this.get(action.target ?? "", "collection");
          if (
            collection.kind !== "collection" ||
            collection.publication !== "taxii" ||
            collection.status !== "published"
          )
            throw new AppError(
              "INVALID_ACTION",
              400,
              "Choose a published TAXII collection.",
            );
        }
        if (action.type === "send-webhook" && !action.target?.trim())
          throw new AppError(
            "INVALID_ACTION",
            400,
            "Choose a configured integration target.",
          );
        if (action.type === "add-to-watchlist")
          await this.get(action.target ?? "", "watchlist");
        if (
          action.type === "create-investigation" &&
          action.target &&
          action.target.length < 3
        )
          throw new AppError(
            "INVALID_ACTION",
            400,
            "Investigation titles need at least three characters.",
          );
      }
    }
    const previous = id ? await this.get(id, input.kind) : null;
    if (previous && expected !== previous.revision)
      throw new AppError(
        "REVISION_CONFLICT",
        409,
        "Another analyst changed this record. Reload the latest revision before saving; your draft has not been overwritten.",
      );
    const ownerId = input.ownerId ?? previous?.ownerId ?? this.principal.userId;
    await this.validateMembers([
      ownerId,
      ...input.collaborators,
      ...(input.kind === "requirement" ? input.stakeholders : []),
      ...(input.kind === "investigation"
        ? input.tasks.flatMap((t) => (t.ownerId ? [t.ownerId] : []))
        : []),
    ]);
    await this.validateReferences(input.references);
    if (id && input.references.some((r) => r.id === id))
      throw new AppError(
        "SELF_REFERENCE",
        400,
        "A record cannot reference itself.",
      );
    const now = new Date().toISOString();
    const change = crypto.randomUUID();
    const objectId = id ?? crypto.randomUUID();
    const object: WorkObject = {
      ...input,
      ownerId,
      id: objectId,
      tenantId: this.tenant,
      revision: (previous?.revision ?? 0) + 1,
      createdAt: previous?.createdAt ?? now,
      updatedAt: now,
      createdBy: previous?.createdBy ?? this.principal.userId,
    };
    const gate = { id: objectId, change };
    const first = previous
      ? this.db
          .prepare(
            "UPDATE workspace_objects SET title=?,status=?,priority=?,owner_id=?,revision=revision+1,change_id=?,data=?,updated_at=? WHERE tenant_id=? AND id=? AND revision=?",
          )
          .bind(
            object.title,
            object.status,
            object.priority,
            ownerId,
            change,
            JSON.stringify(object),
            now,
            this.tenant,
            objectId,
            expected!,
          )
      : this.db
          .prepare(
            "INSERT INTO workspace_objects VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
          )
          .bind(
            this.tenant,
            objectId,
            object.kind,
            object.title,
            object.status,
            object.priority,
            ownerId,
            1,
            change,
            JSON.stringify(object),
            now,
            now,
          );
    const conditional =
      "EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=? AND id=? AND change_id=?)";
    const statements = [
      first,
      this.db
        .prepare(
          `DELETE FROM workspace_links WHERE tenant_id=? AND object_id=? AND relation!='automation_member' AND ${conditional}`,
        )
        .bind(this.tenant, objectId, this.tenant, objectId, change),
      ...input.references.map((r) =>
        this.db
          .prepare(
            `INSERT OR IGNORE INTO workspace_links SELECT ?,?,?,?,? WHERE ${conditional}`,
          )
          .bind(
            this.tenant,
            objectId,
            r.type,
            r.id,
            r.relation,
            this.tenant,
            objectId,
            change,
          ),
      ),
      this.eventStatement(
        change,
        object.kind + (previous ? ".updated" : ".created"),
        object.kind,
        objectId,
        { reason, revision: object.revision, before: previous, after: object },
        now,
        gate,
      ),
      this.auditStatement(
        change,
        object.kind + (previous ? ".updated" : ".created"),
        objectId,
        { reason, revision: object.revision },
        now,
        gate,
      ),
    ];
    const results = await this.db.batch(statements);
    if (!results[0]!.meta.changes)
      throw new AppError(
        "REVISION_CONFLICT",
        409,
        "Another analyst saved first. Reload this record before retrying.",
      );
    return object;
  }
  async note(id: string, raw: unknown) {
    const o = await this.get(id);
    const input = NoteInput.parse(raw);
    await this.validateReferences(input.references);
    const noteId = crypto.randomUUID(),
      now = new Date().toISOString();
    await this.db.batch([
      this.eventStatement(noteId, input.type, o.kind, id, input, now),
      this.auditStatement(
        noteId,
        "workspace." + input.type,
        id,
        { references: input.references },
        now,
      ),
    ]);
    return {
      id: noteId,
      ...input,
      createdAt: now,
      authorId: this.principal.userId,
    };
  }
  async history(id: string, from?: string) {
    await this.get(id);
    return this.events(id, from);
  }
  async events(id: string, from = "1970-01-01T00:00:00.000Z") {
    const rows = await this.db
      .prepare(
        "SELECT id,subject_type,subject_id,event_type,actor_id,data,created_at FROM intelligence_events WHERE tenant_id=? AND subject_id=? AND created_at>=? ORDER BY created_at DESC,id LIMIT 101",
      )
      .bind(this.tenant, id, from)
      .all<Omit<IntelligenceEvent, "data"> & { data: string }>();
    return {
      data: rows.results.slice(0, 100).map((r) => ({
        ...r,
        data: JSON.parse(r.data) as Record<string, unknown>,
      })),
      truncated: rows.results.length > 100,
    };
  }
  async related(id: string, type = "entity") {
    const rows = await this.db
      .prepare(
        "SELECT DISTINCT o.data FROM workspace_links l JOIN workspace_objects o ON o.tenant_id=l.tenant_id AND o.id=l.object_id WHERE l.tenant_id=? AND l.target_type=? AND l.target_id=? ORDER BY o.updated_at DESC LIMIT 100",
      )
      .bind(this.tenant, type, id)
      .all<{ data: string }>();
    return rows.results
      .map((r) => WorkObjectSchema.parse(JSON.parse(r.data)))
      .filter((o) => this.canRead(o));
  }
  async sightings(id?: string, cursor = "", limit = 50) {
    const rows = await this.db
      .prepare(
        "SELECT data FROM sightings WHERE tenant_id=? AND (?='' OR observable_id=?) AND (?='' OR id>?) ORDER BY id LIMIT ?",
      )
      .bind(this.tenant, id ?? "", id ?? "", cursor, cursor, limit + 1)
      .all<{ data: string }>();
    const data = rows.results
      .slice(0, limit)
      .map((r) => JSON.parse(r.data) as Sighting);
    return {
      data,
      next_cursor: rows.results.length > limit ? data.at(-1)!.id : null,
    };
  }
  async recordSighting(raw: unknown) {
    const input = SightingInput.parse(raw);
    if (Date.parse(input.observedAt) > Date.now() + 300000)
      throw new AppError(
        "FUTURE_SIGHTING",
        400,
        "Observation time cannot be in the future.",
      );
    const id =
      "sighting_" +
      (await digest(this.tenant + ":" + input.source + ":" + input.externalId));
    const existing = await this.db
      .prepare("SELECT data FROM sightings WHERE tenant_id=? AND id=?")
      .bind(this.tenant, id)
      .first<{ data: string }>();
    if (existing) {
      const old = JSON.parse(existing.data) as Sighting;
      if (canonicalJson(SightingInput.parse(old)) !== canonicalJson(input))
        throw new AppError(
          "IDEMPOTENCY_CONFLICT",
          409,
          "This source event ID already belongs to a different sighting.",
        );
      return old;
    }
    const observable = await normalise(
      input.observable.observable,
      input.observable.type,
    );
    const now = new Date().toISOString();
    const provenance = {
      sourceId: "customer",
      sourceName: input.source,
      retrievedAt: now,
      sourceRecordId: input.externalId,
      redistributable: false,
    };
    await this.intel.putObservable(observable, provenance, this.tenant);
    const data: Sighting = {
      ...input,
      id,
      observableId: observable.id,
      createdAt: now,
      createdBy: this.principal.userId,
    };
    const evidence: Evidence = {
      id,
      observableId: observable.id,
      type: "telemetry",
      sourceId: "customer",
      provenance,
      data: {
        description: input.context,
        asset: input.asset,
        environment: input.environment,
        count: input.count,
        sighting: true,
      },
      observedAt: input.observedAt,
      confidence: input.confidence,
      createdAt: now,
      behavioural: false,
    };
    await this.db.batch([
      this.db
        .prepare("INSERT OR IGNORE INTO sightings VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(
          this.tenant,
          id,
          observable.id,
          input.source,
          input.observedAt,
          input.count,
          input.confidence,
          JSON.stringify(data),
          now,
        ),
      this.db
        .prepare(
          "INSERT OR IGNORE INTO customer_observations VALUES(?,?,?,?,?,0)",
        )
        .bind(
          id,
          this.tenant,
          observable.id,
          JSON.stringify(evidence),
          input.observedAt,
        ),
      this.eventStatement(
        id,
        "sighting.created",
        "entity",
        observable.id,
        { sightingId: id, evidenceId: id, source: input.source },
        now,
      ),
      this.db
        .prepare(
          "INSERT OR IGNORE INTO audit_events(id,tenant_id,actor_id,action,entity_id,correlation_id,data,created_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .bind(
          id,
          this.tenant,
          this.principal.userId,
          "sighting.created",
          observable.id,
          id,
          JSON.stringify({ sightingId: id }),
          now,
        ),
    ]);
    const stored = await this.db
      .prepare("SELECT data FROM sightings WHERE tenant_id=? AND id=?")
      .bind(this.tenant, id)
      .first<{ data: string }>();
    const result = JSON.parse(stored!.data) as Sighting;
    if (canonicalJson(SightingInput.parse(result)) !== canonicalJson(input))
      throw new AppError(
        "IDEMPOTENCY_CONFLICT",
        409,
        "Another request used this source event ID.",
      );
    return result;
  }
}
export const Browse = z.object({
  q: z.string().max(200).default(""),
  status: z.string().max(30).default(""),
  cursor: z.string().max(200).default(""),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
