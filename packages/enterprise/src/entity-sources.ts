import type { IntelRelationship } from "../../schemas/src/index";
import type { LookupSource } from "../../schemas/src/lookup";
import {
  entitySourceFacts,
  licenceFields,
  sourceLicences,
} from "../../database/src/lookup";
import { sourceReliabilities } from "./sources";

export interface SourceLicenceRequest {
  /** Entity ids whose source records count (all canonical members). */
  entityIds: string[];
  /** Relationships returned beside the entity; their sources count too. */
  relationships?: Pick<
    IntelRelationship,
    "provenance" | "firstSeen" | "lastSeen"
  >[];
}
interface Facts {
  redistributable: boolean;
  first: string | null;
  last: string | null;
  retrieved: string | null;
  url: string | null;
  urlAt: string;
}
const iso = (value: string | null | undefined) => {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
};
const earlier = (a: string | null, b: string | null) =>
  a && b ? (a < b ? a : b) : (a ?? b);
const later = (a: string | null, b: string | null) =>
  a && b ? (a > b ? a : b) : (a ?? b);

/**
 * `source_licences` for entity and catalogue responses: the same objects as
 * POST /v1/lookup `sources[]`, one per source behind the entity's records and
 * behind each returned relationship, sorted by source_id. `first_seen` and
 * `last_seen` are the earliest and latest dates the source gives (publication
 * for entity records, sightings for relationships). Sources the tenant
 * disabled never appear. Three D1 reads whatever the number of requests.
 */
export async function entitySourceLicences<K>(
  db: D1Database,
  tenantId: string,
  requests: Map<K, SourceLicenceRequest>,
): Promise<Map<K, LookupSource[]>> {
  const result = new Map<K, LookupSource[]>();
  if (!requests.size) return result;
  const [facts, { sources, disabled }, reliabilities] = await Promise.all([
    entitySourceFacts(
      db,
      tenantId,
      [...requests.values()].flatMap((r) => r.entityIds),
    ),
    sourceLicences(db, tenantId),
    sourceReliabilities(db, tenantId),
  ]);
  const reliability = new Map(reliabilities.map((s) => [s.id, s.reliability]));
  for (const [key, request] of requests) {
    const merged = new Map<string, Facts>();
    const add = (sourceId: string, next: Omit<Facts, "urlAt">) => {
      const c = merged.get(sourceId) ?? {
        redistributable: true,
        first: null,
        last: null,
        retrieved: null,
        url: null,
        urlAt: "",
      };
      c.redistributable &&= next.redistributable;
      c.first = earlier(c.first, iso(next.first));
      c.last = later(c.last, iso(next.last));
      const retrieved = iso(next.retrieved);
      c.retrieved = later(c.retrieved, retrieved);
      if (next.url && (retrieved ?? "") >= c.urlAt) {
        c.url = next.url;
        c.urlAt = retrieved ?? "";
      }
      merged.set(sourceId, c);
    };
    for (const id of new Set(request.entityIds))
      for (const f of facts.get(id) ?? []) {
        const split = f.latest_url?.indexOf("\u001f") ?? -1;
        add(f.source_id, {
          redistributable: f.redistributable,
          first: f.first_published,
          last: f.last_published,
          retrieved: f.retrieved_at,
          url: split >= 0 ? f.latest_url!.slice(split + 1) : null,
        });
      }
    for (const r of request.relationships ?? []) {
      if (disabled.has(r.provenance.sourceId)) continue;
      add(r.provenance.sourceId, {
        redistributable: r.provenance.redistributable === true,
        first: r.firstSeen ?? null,
        last: r.lastSeen ?? null,
        retrieved: r.provenance.retrievedAt,
        url: r.provenance.sourceUrl ?? null,
      });
    }
    result.set(
      key,
      [...merged.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([id, c]) => ({
          ...licenceFields(id, sources.get(id), c.redistributable),
          reliability: reliability.get(id) ?? 0.5,
          first_seen: c.first,
          last_seen: c.last,
          retrieved_at: c.retrieved,
          source_url: c.url,
        })),
    );
  }
  return result;
}
