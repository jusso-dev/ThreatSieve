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
 * cached in D1 with a TTL and never written to the shared graph, so one
 * tenant's lookup does not make the value browsable by another tenant.
 * Cache misses are refreshed after the response, within a daily budget.
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
const PENDING_TTL_SECONDS = 120;
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
export function perRequestLimit(source: LookupSourceId) {
  return PER_REQUEST[source];
}
export interface CachedLookup {
  sourceId: LookupSourceId;
  key: string;
  status: "pending" | "found" | "not_found" | "error";
  data: unknown;
  fetchedAt: string;
  expiresAt: string;
}
export async function readLookupCache(db: D1Database, keys: string[]) {
  const result = new Map<string, CachedLookup>();
  if (!keys.length) return result;
  const rows = await db
    .prepare(
      "SELECT source_id,lookup_key,status,data,fetched_at,expires_at FROM source_lookup_cache WHERE lookup_key IN (SELECT value FROM json_each(?))",
    )
    .bind(JSON.stringify(keys))
    .all<{
      source_id: LookupSourceId;
      lookup_key: string;
      status: CachedLookup["status"];
      data: string;
      fetched_at: string;
      expires_at: string;
    }>();
  for (const row of rows.results)
    result.set(row.source_id + "|" + row.lookup_key, {
      sourceId: row.source_id,
      key: row.lookup_key,
      status: row.status,
      data: JSON.parse(row.data),
      fetchedAt: row.fetched_at,
      expiresAt: row.expires_at,
    });
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
/**
 * Claims an expired or missing cache entry so concurrent lookups do not spend
 * provider budget twice, then charges the source's daily budget.
 */
export async function reserveLookup(
  env: LookupEnv,
  source: LookupSourceId,
  key: string,
  now: Date,
) {
  const at = now.toISOString();
  const claimed = await env.DB.prepare(
    "INSERT INTO source_lookup_cache(source_id,lookup_key,status,data,fetched_at,expires_at) VALUES(?,?,'pending','{}',?,?) ON CONFLICT(source_id,lookup_key) DO UPDATE SET status='pending',data='{}',fetched_at=excluded.fetched_at,expires_at=excluded.expires_at WHERE source_lookup_cache.expires_at<=?",
  )
    .bind(
      source,
      key,
      at,
      new Date(now.getTime() + PENDING_TTL_SECONDS * 1000).toISOString(),
      at,
    )
    .run();
  if (!claimed.meta.changes) return false;
  const minute = Math.floor(now.getTime() / 60000);
  const budget = await env.DB.prepare(
    "INSERT INTO rate_limits(bucket,count,expires_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count",
  )
    .bind("budget:" + source + ":" + at.slice(0, 10), minute + 2880)
    .first<{ count: number }>();
  if ((budget?.count ?? 0) <= dailyLimit(env, source)) return true;
  await env.DB.prepare(
    "DELETE FROM source_lookup_cache WHERE source_id=? AND lookup_key=? AND status='pending' AND fetched_at=?",
  )
    .bind(source, key, at)
    .run();
  return false;
}
export interface LookupTask {
  source: LookupSourceId;
  key: string;
  value: string;
}
/** Runs after the response; failures are cached briefly, never thrown. */
export async function refreshLookup(
  env: LookupEnv,
  task: LookupTask,
  request: typeof fetch = (input, init) => fetch(input, init),
  now = new Date(),
) {
  const at = now.toISOString();
  const store = (status: CachedLookup["status"], data: unknown, ttl: number) =>
    env.DB.prepare(
      "UPDATE source_lookup_cache SET status=?,data=?,fetched_at=?,expires_at=? WHERE source_id=? AND lookup_key=?",
    )
      .bind(
        status,
        JSON.stringify(data),
        at,
        new Date(now.getTime() + ttl * 1000).toISOString(),
        task.source,
        task.key,
      )
      .run();
  const archive = async (raw: unknown) => {
    if (raw === null || raw === undefined) return;
    await env.ARCHIVE.put(
      "raw/" +
        task.source +
        "/lookups/" +
        at.slice(0, 10).replace(/-/g, "/") +
        "/" +
        (await digest(task.key + ":" + at)) +
        ".json",
      JSON.stringify(raw),
      { httpMetadata: { contentType: "application/json" } },
    );
  };
  try {
    if (task.source === "osv") {
      const { raw, summary } = await fetchOsv(request, task.value);
      await archive(raw);
      await store(
        summary ? "found" : "not_found",
        summary ?? {},
        LOOKUP_CACHE_TTL_SECONDS.osv,
      );
    } else {
      const feed = new OptionalFeed(
        task.source,
        NAMES[task.source],
        new Repository(env.DB),
        {
          enabled: true,
          apiKey:
            task.source === "greynoise"
              ? env.GREYNOISE_API_KEY
              : env.CROWDSEC_API_KEY,
        },
        request,
      );
      const batch = await feed.fetch(task.value);
      await archive(batch.raw);
      const evidence: Evidence[] = [];
      for (const record of batch.records)
        for (const normalized of await feed.normalize(record))
          evidence.push(...normalized.evidence);
      await store(
        evidence.length ? "found" : "not_found",
        evidence,
        LOOKUP_CACHE_TTL_SECONDS[task.source],
      );
    }
    await env.DB.prepare(
      "UPDATE sources SET status='healthy',last_sync=?,last_error=NULL,records_processed=records_processed+1 WHERE id=?",
    )
      .bind(at, task.source)
      .run();
  } catch (error) {
    await store("error", { error: errorType(error) }, ERROR_TTL_SECONDS);
    await env.DB.prepare(
      "UPDATE sources SET status='error',errors=errors+1,last_error=? WHERE id=?",
    )
      .bind(errorType(error), task.source)
      .run();
  }
}
