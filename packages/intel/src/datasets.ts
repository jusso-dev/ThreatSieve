import { z } from "zod";

/**
 * Bulk reference datasets (IP-to-ASN, EPSS) are too large to keep as D1 rows
 * and are re-imported daily. They are stored in R2 as sorted, contiguous
 * shards plus a small index of each shard's first key. D1 holds only the
 * current version, so a lookup never sees a half-written import.
 */
export type ShardRow = [string, ...(string | number | null)[]];
export type ShardIndex = { first: string; shard: number }[];
export const DEFAULT_ROWS_PER_SHARD = 4000;

export function datasetPrefix(dataset: string, version: string) {
  return "datasets/" + dataset + "/" + version + "/";
}

/** Writes rows that arrive in strictly increasing key order. */
export class ShardWriter {
  private rows: ShardRow[] = [];
  private index: ShardIndex = [];
  private last: string | undefined;
  count = 0;
  constructor(
    private bucket: R2Bucket,
    private prefix: string,
    private family: string,
    private rowsPerShard = DEFAULT_ROWS_PER_SHARD,
  ) {}
  async add(row: ShardRow) {
    if (this.last !== undefined && row[0] <= this.last)
      throw new Error("Dataset rows must be strictly increasing");
    this.last = row[0];
    this.rows.push(row);
    this.count++;
    if (this.rows.length >= this.rowsPerShard) await this.flush();
  }
  private async flush() {
    if (!this.rows.length) return;
    const shard = this.index.length;
    this.index.push({ first: this.rows[0]![0], shard });
    await this.bucket.put(
      this.prefix + this.family + "/" + shard + ".json",
      JSON.stringify(this.rows),
      { httpMetadata: { contentType: "application/json" } },
    );
    this.rows = [];
  }
  async finish() {
    await this.flush();
    await this.bucket.put(
      this.prefix + "index/" + this.family + ".json",
      JSON.stringify(this.index),
      { httpMetadata: { contentType: "application/json" } },
    );
    return { family: this.family, shards: this.index.length, rows: this.count };
  }
}

const cache = new Map<string, Promise<unknown>>();
const CACHE_LIMIT = 96;
/** Objects are immutable per version, so an isolate-level cache is safe. */
async function readJson(bucket: R2Bucket, key: string): Promise<unknown> {
  let value = cache.get(key);
  if (!value) {
    value = bucket.get(key).then(async (object) => {
      if (!object) return null;
      return JSON.parse(await object.text()) as unknown;
    });
    value.catch(() => cache.delete(key));
    cache.set(key, value);
    if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value!);
  }
  return value;
}
export function clearDatasetCache() {
  cache.clear();
}
const IndexSchema = z.array(
  z.object({ first: z.string(), shard: z.number().int().min(0) }),
);
const RowsSchema = z.array(
  z.tuple([z.string()]).rest(z.union([z.string(), z.number(), z.null()])),
);
/** Last index position whose key is <= target, or -1. */
function floor<T>(items: T[], key: (item: T) => string, target: string) {
  let low = 0,
    high = items.length - 1,
    found = -1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (key(items[mid]!) <= target) {
      found = mid;
      low = mid + 1;
    } else high = mid - 1;
  }
  return found;
}
export class DatasetReader {
  constructor(
    private bucket: R2Bucket,
    readonly dataset: string,
    readonly version: string,
  ) {}
  /** The row with the greatest key not above `key`, if any. */
  async floor(family: string, key: string): Promise<ShardRow | null> {
    const prefix = datasetPrefix(this.dataset, this.version);
    const index = await readJson(
      this.bucket,
      prefix + "index/" + family + ".json",
    );
    if (!index) return null;
    const entries = IndexSchema.parse(index);
    const position = floor(entries, (e) => e.first, key);
    if (position < 0) return null;
    const rows = await readJson(
      this.bucket,
      prefix + family + "/" + entries[position]!.shard + ".json",
    );
    if (!rows) throw new Error("Dataset shard missing");
    const parsed = RowsSchema.parse(rows) as ShardRow[];
    const row = floor(parsed, (r) => r[0], key);
    return row < 0 ? null : parsed[row]!;
  }
  async exact(family: string, key: string) {
    const row = await this.floor(family, key);
    return row && row[0] === key ? row : null;
  }
}

export interface DatasetVersion {
  dataset: string;
  version: string;
  source_digest: string;
  source_updated_at: string | null;
  record_count: number;
  imported_at: string;
  previous_version: string | null;
}
export async function currentVersions(
  db: D1Database,
): Promise<Map<string, DatasetVersion>> {
  const rows = await db
    .prepare("SELECT * FROM dataset_versions")
    .all<DatasetVersion>();
  return new Map(rows.results.map((row) => [row.dataset, row]));
}
/** Switch to a fully written version and drop the one before the previous. */
export async function promoteVersion(
  db: D1Database,
  bucket: R2Bucket,
  next: Omit<DatasetVersion, "previous_version">,
) {
  const current = (await currentVersions(db)).get(next.dataset);
  await db
    .prepare(
      "INSERT INTO dataset_versions(dataset,version,source_digest,source_updated_at,record_count,imported_at,previous_version) VALUES(?,?,?,?,?,?,?) ON CONFLICT(dataset) DO UPDATE SET version=excluded.version,source_digest=excluded.source_digest,source_updated_at=excluded.source_updated_at,record_count=excluded.record_count,imported_at=excluded.imported_at,previous_version=excluded.previous_version",
    )
    .bind(
      next.dataset,
      next.version,
      next.source_digest,
      next.source_updated_at,
      next.record_count,
      next.imported_at,
      current?.version ?? null,
    )
    .run();
  // Derived shards are rebuildable from the archived source file. Keep the
  // previous version for rollback and remove anything older.
  const keep = new Set([next.version, current?.version].filter(Boolean));
  let cursor: string | undefined;
  do {
    const listing = await bucket.list({
      prefix: "datasets/" + next.dataset + "/",
      cursor,
      limit: 1000,
    });
    const stale = listing.objects
      .map((o) => o.key)
      .filter((key) => !keep.has(key.split("/")[2]!));
    if (stale.length) await bucket.delete(stale);
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
}

/** Reads a whole bounded response body; datasets are hashed before parsing. */
export async function boundedBytes(
  response: Response,
  maxBytes: number,
): Promise<Uint8Array> {
  if (!response.body) throw new Error("Empty upstream response");
  if (Number(response.headers.get("content-length")) > maxBytes)
    throw new Error("Payload exceeds size limit");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error("Payload exceeds size limit");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel();
    throw error;
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return all;
}
export async function bytesDigest(bytes: Uint8Array) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
/** Streams the lines of a gzip file without materialising the text. */
export async function* gzipLines(
  bytes: Uint8Array,
  maxLines = 5_000_000,
): AsyncGenerator<string> {
  const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream("utf-8", { fatal: true }));
  const reader = stream.getReader();
  let buffer = "";
  let lines = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (value) {
      const parts = (buffer + value).split("\n");
      buffer = parts.pop()!;
      for (const line of parts) {
        if (++lines > maxLines) throw new Error("Dataset exceeds line limit");
        yield line.replace(/\r$/, "");
      }
    }
    if (done) break;
  }
  if (buffer) yield buffer.replace(/\r$/, "");
}
/** Fixed upstream URLs only; redirects are refused like every other feed. */
export async function fetchDataset(
  request: typeof fetch,
  url: string,
  maxBytes: number,
) {
  const response = await request(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(120000),
  });
  if (!response.ok) throw new Error("Upstream HTTP " + response.status);
  return boundedBytes(response, maxBytes);
}
export function versionFor(date: Date, sourceDigest: string) {
  return (
    date.toISOString().slice(0, 10).replace(/-/g, "") +
    "-" +
    sourceDigest.slice(0, 12)
  );
}
/** Keeps the original upstream file, as every feed archives raw data. */
export async function archiveSource(
  bucket: R2Bucket,
  dataset: string,
  name: string,
  version: string,
  bytes: Uint8Array,
) {
  await bucket.put(
    "raw/" +
      dataset +
      "/" +
      version.slice(0, 4) +
      "/" +
      version.slice(4, 6) +
      "/" +
      version.slice(6, 8) +
      "/" +
      version +
      "-" +
      name,
    bytes,
    { httpMetadata: { contentType: "application/gzip" } },
  );
}
