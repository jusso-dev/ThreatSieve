import { z } from "zod";
import { EvidenceSchema, type Evidence } from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
import { errorType } from "../../observability/src/index";
import type { FeedSecrets } from "./feeds";
import { OptionalFeed } from "./optional-feeds";
import { fetchOsv, type OsvSummary } from "./cve";
import { digest } from "./normalise";

/**
 * Rate-limited per-observable sources used by POST /v1/lookup. Answers are
 * cached in D1 with a TTL and never written to the shared graph.
 *
 * GreyNoise and CrowdSec answers are cached per tenant: a tenant never sees
 * another tenant's lookups, their timing or their pending state. OSV answers
 * are public advisory data and are cached once for everyone.
 *
 * Daily budgets are global per source because the provider quota belongs to
 * the operator's key. A lookup reads every budget in one query, claims cache
 * misses in one statement per source, and enqueues one refresh job per
 * source on the enrich queue, so the number of D1 statements does not grow
 * with the number of observables.
 */
export const LOOKUP_SOURCES = ["greynoise", "crowdsec", "osv"] as const;
export type LookupSourceId = (typeof LOOKUP_SOURCES)[number];
const NAMES: Record<LookupSourceId, string> = {
  greynoise: "GreyNoise",
  crowdsec: "CrowdSec CTI",
  osv: "OSV.dev",
};
export const LOOKUP_CACHE_TTL_SECONDS: Record<LookupSourceId, number> = {
  greynoise: 86400,
  crowdsec: 86400,
  osv: 86400,
};
const ERROR_TTL_SECONDS = 900;
/** Covers the enrich queue's retries; a stuck claim is reclaimed afterwards. */
export const PENDING_TTL_SECONDS = 1800;
const PER_REQUEST: Record<LookupSourceId, number> = {
  greynoise: 5,
  crowdsec: 10,
  osv: 25,
};
const DAILY_DEFAULT: Record<LookupSourceId, number> = {
  greynoise: 7,
  crowdsec: 45,
  osv: 2000,
};
/** Give up (and refund the budget) on this queue delivery or later. */
export const FINAL_ATTEMPT = 4;
export type LookupEnv = { DB: D1Database; ARCHIVE: R2Bucket } & FeedSecrets;

export function lookupApplies(source: LookupSourceId, type: string) {
  if (source === "greynoise") return type === "ipv4";
  if (source === "crowdsec") return type === "ipv4" || type === "ipv6";
  return type === "cve";
}
/** Keyed sources stay disabled until their Worker secret is provisioned. */
export function lookupConfigured(env: FeedSecrets, source: LookupSourceId) {
  if (source === "greynoise") return Boolean(env.GREYNOISE_API_KEY);
  if (source === "crowdsec") return Boolean(env.CROWDSEC_API_KEY);
  return true;
}
/** Cache partition: the tenant for keyed sources, global for OSV. */
export function lookupScope(source: LookupSourceId, tenantId: string) {
  return source === "osv" ? "" : tenantId;
}
function dailyLimit(env: FeedSecrets, source: LookupSourceId) {
  const value =
    source === "greynoise"
      ? env.GREYNOISE_DAILY_LIMIT
      : source === "crowdsec"
        ? env.CROWDSEC_DAILY_LIMIT
        : env.OSV_DAILY_LIMIT;
  return z.coerce
    .number()
    .int()
    .min(0)
    .max(1_000_000)
    .catch(DAILY_DEFAULT[source])
    .parse(value ?? DAILY_DEFAULT[source]);
}
const budgetBucket = (source: LookupSourceId, at: Date) =>
  "budget:" + source + ":" + at.toISOString().slice(0, 10);

export interface CachedLookup {
  sourceId: LookupSourceId;
  scope: string;
  key: string;
  status: "pending" | "found" | "not_found" | "error";
  data: unknown;
  fetchedAt: string;
  expiresAt: string;
}
/** Rows for the given keys in the tenant's partition and the global one. */
export async function readLookupCache(
  db: D1Database,
  tenantId: string,
  keys: string[],
) {
  const result = new Map<string, CachedLookup>();
  if (!keys.length) return result;
  const rows = await db
    .prepare(
      "SELECT source_id,scope,lookup_key,status,data,fetched_at,expires_at FROM source_lookup_cache WHERE scope IN (?1,'') AND lookup_key IN (SELECT value FROM json_each(?2))",
    )
    .bind(tenantId, JSON.stringify(keys))
    .all<{
      source_id: LookupSourceId;
      scope: string;
      lookup_key: string;
      status: CachedLookup["status"];
      data: string;
      fetched_at: string;
      expires_at: string;
    }>();
  for (const row of rows.results) {
    if (
      !LOOKUP_SOURCES.includes(row.source_id) ||
      row.scope !== lookupScope(row.source_id, tenantId)
    )
      continue;
    result.set(row.source_id + "|" + row.lookup_key, {
      sourceId: row.source_id,
      scope: row.scope,
      key: row.lookup_key,
      status: row.status,
      data: JSON.parse(row.data),
      fetchedAt: row.fetched_at,
      expiresAt: row.expires_at,
    });
  }
  return result;
}
export function cachedEvidence(entry: CachedLookup): Evidence[] {
  if (entry.status !== "found") return [];
  return z.array(EvidenceSchema).catch([]).parse(entry.data);
}
export function cachedOsv(entry: CachedLookup): OsvSummary | null {
  if (entry.status !== "found") return null;
  return entry.data as OsvSummary;
}

export interface LookupItem {
  key: string;
  value: string;
}
export const LookupJobSchema = z.object({
  mode: z.literal("source-lookup"),
  source: z.enum(LOOKUP_SOURCES),
  scope: z.string().max(200),
  budget: z.string().max(200),
  items: z
    .array(z.object({ key: z.string().max(200), value: z.string().max(8192) }))
    .max(100),
});
export type LookupJobPayload = z.infer<typeof LookupJobSchema>;
/**
 * Claims cache misses within today's budget. Returns the claimed items per
 * source, and the misses left for a later request because this request's
 * per-source cap was reached. Misses beyond the daily budget are dropped.
 */
export async function claimLookups(
  env: LookupEnv,
  tenantId: string,
  misses: Map<LookupSourceId, LookupItem[]>,
  now: Date,
) {
  const claimed = new Map<LookupSourceId, LookupItem[]>();
  const later = new Map<LookupSourceId, LookupItem[]>();
  const sources = [...misses.keys()].filter((s) => misses.get(s)!.length);
  if (!sources.length)
    return { claimed, later, jobs: [] as LookupJobPayload[] };
  const used = await env.DB.prepare(
    "SELECT bucket,count FROM rate_limits WHERE bucket IN (SELECT value FROM json_each(?))",
  )
    .bind(JSON.stringify(sources.map((s) => budgetBucket(s, now))))
    .all<{ bucket: string; count: number }>();
  const spent = new Map(used.results.map((r) => [r.bucket, r.count]));
  const at = now.toISOString();
  const minute = Math.floor(now.getTime() / 60000);
  const jobs: LookupJobPayload[] = [];
  for (const source of sources) {
    const bucket = budgetBucket(source, now);
    const remaining = Math.max(
      0,
      dailyLimit(env, source) - (spent.get(bucket) ?? 0),
    );
    if (!remaining) continue;
    const items = misses.get(source)!;
    const take = Math.min(remaining, PER_REQUEST[source]);
    later.set(source, items.slice(take, remaining));
    const wanted = items.slice(0, take);
    if (!wanted.length) continue;
    const scope = lookupScope(source, tenantId);
    // One statement claims every missing or expired row; a row another
    // request already holds as pending is left alone.
    const rows = await env.DB.prepare(
      `INSERT INTO source_lookup_cache(source_id,scope,lookup_key,status,data,fetched_at,expires_at)
       SELECT ?1,?2,value,'pending','{}',?3,?4 FROM json_each(?5) WHERE true
       ON CONFLICT(source_id,scope,lookup_key) DO UPDATE SET status='pending',data='{}',fetched_at=excluded.fetched_at,expires_at=excluded.expires_at
       WHERE source_lookup_cache.expires_at<=?3 RETURNING lookup_key`,
    )
      .bind(
        source,
        scope,
        at,
        new Date(now.getTime() + PENDING_TTL_SECONDS * 1000).toISOString(),
        JSON.stringify(wanted.map((i) => i.key)),
      )
      .all<{ lookup_key: string }>();
    const won = new Set(rows.results.map((r) => r.lookup_key));
    const mine = wanted.filter((i) => won.has(i.key));
    if (!mine.length) continue;
    await env.DB.prepare(
      "INSERT INTO rate_limits(bucket,count,expires_at) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=count+excluded.count",
    )
      .bind(bucket, mine.length, minute + 2880)
      .run();
    claimed.set(source, mine);
    jobs.push({
      mode: "source-lookup",
      source,
      scope,
      budget: bucket,
      items: mine,
    });
  }
  return { claimed, later, jobs };
}

/**
 * Enrich-queue handler for one claimed batch. Rows that are no longer
 * pending were finished by an earlier delivery and are skipped. A failed
 * item keeps its claim and the job is retried; on the final attempt it is
 * cached as an error briefly and its budget unit is refunded.
 */
export async function processLookupJob(
  env: LookupEnv,
  payload: LookupJobPayload,
  attempt: number,
  request: typeof fetch = (input, init) => fetch(input, init),
  now = () => new Date(),
) {
  const final = attempt >= FINAL_ATTEMPT;
  const status = await env.DB.prepare(
    "SELECT lookup_key,status FROM source_lookup_cache WHERE source_id=? AND scope=? AND lookup_key IN (SELECT value FROM json_each(?))",
  )
    .bind(
      payload.source,
      payload.scope,
      JSON.stringify(payload.items.map((i) => i.key)),
    )
    .all<{ lookup_key: string; status: string }>();
  const open = new Set(
    status.results
      .filter((r) => r.status === "pending")
      .map((r) => r.lookup_key),
  );
  let failed = 0,
    refunded = 0,
    done = 0;
  let lastError: unknown;
  for (const item of payload.items) {
    if (!open.has(item.key)) continue;
    const result = await fetchLookup(env, payload.source, item, request, now());
    if (result.ok) {
      await storeLookup(
        env,
        payload,
        item.key,
        result.status,
        result.data,
        LOOKUP_CACHE_TTL_SECONDS[payload.source],
        now(),
      );
      done++;
    } else if (final) {
      await storeLookup(
        env,
        payload,
        item.key,
        "error",
        { error: errorType(result.error) },
        ERROR_TTL_SECONDS,
        now(),
      );
      refunded++;
      lastError = result.error;
    } else {
      failed++;
      lastError = result.error;
    }
  }
  if (refunded)
    await env.DB.prepare(
      "UPDATE rate_limits SET count=MAX(0,count-?) WHERE bucket=?",
    )
      .bind(refunded, payload.budget)
      .run();
  if (done)
    await env.DB.prepare(
      "UPDATE sources SET status='healthy',last_sync=?,last_error=NULL,records_processed=records_processed+? WHERE id=?",
    )
      .bind(now().toISOString(), done, payload.source)
      .run();
  if (failed || refunded)
    await env.DB.prepare(
      "UPDATE sources SET status='error',errors=errors+1,last_error=? WHERE id=?",
    )
      .bind(errorType(lastError), payload.source)
      .run();
  if (failed) throw new Error("Lookup provider failed; retrying " + failed);
  return { done, refunded };
}
async function storeLookup(
  env: LookupEnv,
  payload: LookupJobPayload,
  key: string,
  status: CachedLookup["status"],
  data: unknown,
  ttl: number,
  at: Date,
) {
  await env.DB.prepare(
    "UPDATE source_lookup_cache SET status=?,data=?,fetched_at=?,expires_at=? WHERE source_id=? AND scope=? AND lookup_key=? AND status='pending'",
  )
    .bind(
      status,
      JSON.stringify(data),
      at.toISOString(),
      new Date(at.getTime() + ttl * 1000).toISOString(),
      payload.source,
      payload.scope,
      key,
    )
    .run();
}
async function fetchLookup(
  env: LookupEnv,
  source: LookupSourceId,
  item: LookupItem,
  request: typeof fetch,
  at: Date,
): Promise<
  | { ok: true; status: "found" | "not_found"; data: unknown }
  | { ok: false; error: unknown }
> {
  const archive = async (raw: unknown) => {
    if (raw === null || raw === undefined) return;
    await env.ARCHIVE.put(
      "raw/" +
        source +
        "/lookups/" +
        at.toISOString().slice(0, 10).replace(/-/g, "/") +
        "/" +
        (await digest(item.key + ":" + at.toISOString())) +
        ".json",
      JSON.stringify(raw),
      { httpMetadata: { contentType: "application/json" } },
    );
  };
  try {
    if (source === "osv") {
      const { raw, summary } = await fetchOsv(request, item.value);
      await archive(raw);
      return summary
        ? { ok: true, status: "found", data: summary }
        : { ok: true, status: "not_found", data: {} };
    }
    const feed = new OptionalFeed(
      source,
      NAMES[source],
      new Repository(env.DB),
      {
        enabled: true,
        apiKey:
          source === "greynoise" ? env.GREYNOISE_API_KEY : env.CROWDSEC_API_KEY,
      },
      request,
    );
    const batch = await feed.fetch(item.value);
    await archive(batch.raw);
    const evidence: Evidence[] = [];
    for (const record of batch.records)
      for (const normalized of await feed.normalize(record))
        evidence.push(...normalized.evidence);
    return evidence.length
      ? { ok: true, status: "found", data: evidence }
      : { ok: true, status: "not_found", data: [] };
  } catch (error) {
    return { ok: false, error };
  }
}
