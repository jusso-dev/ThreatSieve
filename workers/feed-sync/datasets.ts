import type { AppEnv } from "../../apps/api/src/env";
import type { FeedBatch, FeedHealth } from "../../packages/schemas/src/index";
import { errorType, log } from "../../packages/observability/src/index";
import { PublicFeed } from "../../packages/intel/src/feeds";
import { lookupConfigured } from "../../packages/intel/src/source-lookups";
import { importIpToAsn } from "../../packages/intel/src/network";
import {
  NvdCursor,
  importEpss,
  nvdDue,
  nvdPageSize,
  syncNvdPage,
} from "../../packages/intel/src/cve";

/**
 * Scheduled reference datasets for POST /v1/lookup. They bypass the record
 * fan-out pipeline: IP-to-ASN and EPSS are whole-file imports into R2 shards,
 * NVD pages are upserted into cve_records. Each run holds the source's
 * feed lock, records its outcome on the sources row and archives raw data.
 */
export const DATASET_SOURCES = ["iptoasn", "epss", "nvd"] as const;
/** Queried per observable by /v1/lookup; never bulk-synced. */
export const LOOKUP_ONLY_SOURCES = ["greynoise", "crowdsec", "osv"] as const;
export const HUB_SOURCE_NAMES: Record<string, string> = {
  iptoasn: "IPtoASN",
  epss: "FIRST EPSS",
  nvd: "NVD",
  osv: "OSV.dev",
  greynoise: "GreyNoise",
  crowdsec: "CrowdSec CTI",
};
/** Health for scheduled datasets and lookup sources; they have no record feed. */
export class HubSource extends PublicFeed {
  override async healthCheck(): Promise<FeedHealth> {
    const row = await this.repo.db
      .prepare("SELECT enabled,status,last_error FROM sources WHERE id=?")
      .bind(this.id)
      .first<{ enabled: number; status: string; last_error: string | null }>();
    const keyMissing =
      (this.id === "greynoise" || this.id === "crowdsec") &&
      !lookupConfigured(this.secrets, this.id);
    return {
      status:
        !row?.enabled || keyMissing
          ? "disabled"
          : row.status === "error"
            ? "error"
            : "healthy",
      message: keyMissing
        ? "Source credential required"
        : (row?.last_error ?? undefined),
      checkedAt: new Date().toISOString(),
    };
  }
  override async fetch(): Promise<FeedBatch> {
    throw new Error("Scheduled dataset or lookup source; not a record feed");
  }
}
const DAILY_IMPORT_MS = 20 * 3600000;
const LOCK_EXPIRY_MS = 30 * 60000;
const NVD_PAGE_GAP_MS = 6000;

type Request = typeof fetch;
const defaultRequest: Request = (input, init) => fetch(input, init);

async function withLock<T>(
  env: AppEnv,
  sourceId: string,
  now: Date,
  work: () => Promise<T>,
): Promise<T | undefined> {
  const token = "dataset:" + crypto.randomUUID();
  await env.DB.prepare(
    "DELETE FROM feed_locks WHERE source_id=? AND job_id LIKE 'dataset:%' AND acquired_at<?",
  )
    .bind(sourceId, new Date(now.getTime() - LOCK_EXPIRY_MS).toISOString())
    .run();
  const lock = await env.DB.prepare(
    "INSERT OR IGNORE INTO feed_locks(source_id,job_id,acquired_at) VALUES(?,?,?)",
  )
    .bind(sourceId, token, now.toISOString())
    .run();
  if (!lock.meta.changes) return undefined;
  try {
    return await work();
  } finally {
    await env.DB.prepare(
      "DELETE FROM feed_locks WHERE source_id=? AND job_id=?",
    )
      .bind(sourceId, token)
      .run();
  }
}
async function source(env: AppEnv, id: string) {
  return env.DB.prepare("SELECT enabled,last_sync FROM sources WHERE id=?")
    .bind(id)
    .first<{ enabled: number; last_sync: string | null }>();
}
async function succeeded(
  env: AppEnv,
  id: string,
  now: Date,
  counts: { processed: number; added: number; next?: Date },
) {
  await env.DB.prepare(
    "UPDATE sources SET status='healthy',last_error=NULL,last_sync=?,next_sync=?,records_processed=records_processed+?,records_added=records_added+? WHERE id=?",
  )
    .bind(
      now.toISOString(),
      counts.next?.toISOString() ?? null,
      counts.processed,
      counts.added,
      id,
    )
    .run();
}
async function failed(env: AppEnv, id: string, error: unknown) {
  await env.DB.prepare(
    "UPDATE sources SET status='error',errors=errors+1,last_error=? WHERE id=?",
  )
    .bind(errorType(error), id)
    .run();
  log({ stage: "dataset", result: "error", error_type: errorType(error) });
}
async function dailyImport(
  env: AppEnv,
  id: "iptoasn" | "epss",
  now: Date,
  request: Request,
  force: boolean,
) {
  const row = await source(env, id);
  if (!row?.enabled) return;
  if (
    !force &&
    row.last_sync &&
    now.getTime() - Date.parse(row.last_sync) < DAILY_IMPORT_MS
  )
    return;
  await withLock(env, id, now, async () => {
    try {
      const result =
        id === "iptoasn"
          ? await importIpToAsn(env, request, now)
          : await importEpss(env, request, now);
      await succeeded(env, id, now, {
        processed: result.records,
        added: result.changed ? result.records : 0,
        next: new Date(now.getTime() + 86400000),
      });
    } catch (error) {
      await failed(env, id, error);
    }
  });
}
/** A few NVD pages per tick keeps well inside the public rate limits. */
export async function syncNvd(
  env: AppEnv,
  now = new Date(),
  request: Request = defaultRequest,
  sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),
) {
  const row = await source(env, "nvd");
  if (!row?.enabled) return;
  await withLock(env, "nvd", now, async () => {
    const checkpoint = await env.DB.prepare(
      "SELECT checkpoint FROM feed_checkpoints WHERE source_id='nvd'",
    ).first<{ checkpoint: string }>();
    let cursor = checkpoint
      ? NvdCursor.parse(JSON.parse(checkpoint.checkpoint))
      : null;
    if (!nvdDue(cursor, now)) return;
    const pages = env.NVD_API_KEY ? 3 : 1;
    let stored = 0;
    try {
      for (let page = 0; page < pages; page++) {
        if (page) await sleep(NVD_PAGE_GAP_MS);
        const result = await syncNvdPage(
          env,
          request,
          {
            apiKey: env.NVD_API_KEY,
            pageSize: nvdPageSize(env.NVD_PAGE_SIZE),
            cursor,
          },
          new Date(now.getTime() + page * NVD_PAGE_GAP_MS),
        );
        stored += result.stored;
        cursor = result.cursor;
        await env.DB.prepare(
          "INSERT INTO feed_checkpoints(source_id,checkpoint,updated_at) VALUES('nvd',?,?) ON CONFLICT(source_id) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=excluded.updated_at",
        )
          .bind(JSON.stringify(cursor), now.toISOString())
          .run();
        if (result.complete && cursor.mode === "incremental") break;
      }
      await succeeded(env, "nvd", now, { processed: stored, added: stored });
    } catch (error) {
      await failed(env, "nvd", error);
    }
  });
}
/** Called from the Worker's scheduled handler; never throws. */
export async function runScheduledDatasets(
  env: AppEnv,
  cron: string,
  now = new Date(),
  request: Request = defaultRequest,
) {
  try {
    if (cron === "17 */6 * * *") {
      await dailyImport(env, "iptoasn", now, request, false);
      await dailyImport(env, "epss", now, request, false);
    }
    await syncNvd(env, now, request);
    await env.DB.prepare("DELETE FROM source_lookup_cache WHERE expires_at<?")
      .bind(new Date(now.getTime() - 7 * 86400000).toISOString())
      .run();
  } catch (error) {
    log({ stage: "dataset", result: "error", error_type: errorType(error) });
  }
}
