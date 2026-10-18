import { z } from "zod";
import { boundedText } from "./feeds";
import {
  ShardWriter,
  archiveSource,
  bytesDigest,
  currentVersions,
  datasetPrefix,
  fetchDataset,
  gzipLines,
  promoteVersion,
  versionFor,
} from "./datasets";
import { digest } from "./normalise";

/**
 * CVE context for /v1/lookup: FIRST EPSS (daily CSV), NVD API 2.0
 * (incremental by lastModified) and OSV (per-CVE, cached). KEV stays in the
 * existing cisa-kev feed and is merged at read time.
 */
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
export const EPSS_BASE = "https://epss.empiricalsecurity.com/";
const MAX_EPSS_DOWNLOAD = 64 * 1024 * 1024;

export function epssUrl(date: Date) {
  // The "-current" alias redirects; feeds refuse redirects, so use the dated file.
  return (
    EPSS_BASE + "epss_scores-" + date.toISOString().slice(0, 10) + ".csv.gz"
  );
}
export interface EpssRow {
  cve: string;
  score: number;
  percentile: number;
}
export async function parseEpss(bytes: Uint8Array) {
  let scoreDate: string | null = null;
  const rows: EpssRow[] = [];
  let header = false;
  for await (const line of gzipLines(bytes, 2_000_000)) {
    if (!line) continue;
    if (line.startsWith("#")) {
      const match = /score_date:([0-9T:.-]+Z?)/.exec(line);
      if (match) scoreDate = new Date(match[1]!).toISOString();
      continue;
    }
    if (!header) {
      if (line.trim() !== "cve,epss,percentile")
        throw new Error("Unexpected EPSS header");
      header = true;
      continue;
    }
    const [cve, epss, percentile] = line.split(",");
    const score = Number(epss),
      rank = Number(percentile);
    if (
      !cve ||
      !CVE_ID.test(cve) ||
      !(score >= 0 && score <= 1) ||
      !(rank >= 0 && rank <= 1)
    )
      continue;
    rows.push({ cve, score, percentile: rank });
  }
  if (!header || !scoreDate) throw new Error("EPSS file missing score date");
  rows.sort((a, b) => (a.cve < b.cve ? -1 : a.cve > b.cve ? 1 : 0));
  return { scoreDate, rows };
}
export async function importEpss(
  env: { DB: D1Database; ARCHIVE: R2Bucket },
  request: typeof fetch,
  now = new Date(),
) {
  let bytes: Uint8Array | undefined;
  let lastError: unknown;
  // Today's file appears during the UTC day; fall back to yesterday's.
  for (const offset of [0, 1]) {
    try {
      bytes = await fetchDataset(
        request,
        epssUrl(new Date(now.getTime() - offset * 86400000)),
        MAX_EPSS_DOWNLOAD,
      );
      break;
    } catch (error) {
      lastError = error;
      if (!(error instanceof Error && /HTTP 404\b/.test(error.message)))
        throw error;
    }
  }
  if (!bytes) throw lastError;
  const sourceDigest = await bytesDigest(bytes);
  const current = (await currentVersions(env.DB)).get("epss");
  if (current?.source_digest === sourceDigest)
    return {
      version: current.version,
      records: current.record_count,
      changed: false,
    };
  const { scoreDate, rows } = await parseEpss(bytes);
  const version = versionFor(new Date(scoreDate), sourceDigest);
  await archiveSource(
    env.ARCHIVE,
    "epss",
    "epss_scores.csv.gz",
    version,
    bytes,
  );
  const writer = new ShardWriter(
    env.ARCHIVE,
    datasetPrefix("epss", version),
    "scores",
  );
  let previous = "";
  for (const row of rows) {
    if (row.cve === previous) continue;
    previous = row.cve;
    await writer.add([row.cve, row.score, row.percentile]);
  }
  const { rows: records } = await writer.finish();
  if (!records) throw new Error("EPSS file contained no scores");
  await promoteVersion(env.DB, env.ARCHIVE, {
    dataset: "epss",
    version,
    source_digest: sourceDigest,
    source_updated_at: scoreDate,
    record_count: records,
    imported_at: now.toISOString(),
  });
  return { version, records, changed: true };
}

// NVD API 2.0 ----------------------------------------------------------------
export const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_WINDOW_MS = 120 * 86400000;
export const NVD_INCREMENTAL_INTERVAL_MS = 2 * 3600000;
export const NvdCursor = z.discriminatedUnion("mode", [
  z.object({
    mode: z.literal("backfill"),
    startIndex: z.number().int().min(0),
    startedAt: z.iso.datetime(),
  }),
  z.object({
    mode: z.literal("incremental"),
    since: z.iso.datetime(),
    startIndex: z.number().int().min(0),
    windowEnd: z.iso.datetime().optional(),
  }),
]);
export type NvdCursor = z.infer<typeof NvdCursor>;
export function nvdDue(cursor: NvdCursor | null, now: Date) {
  if (!cursor || cursor.mode === "backfill" || cursor.windowEnd) return true;
  return (
    now.getTime() - Date.parse(cursor.since) >= NVD_INCREMENTAL_INTERVAL_MS
  );
}
const NvdMetric = z
  .object({
    type: z.string().optional(),
    cvssData: z
      .object({
        version: z.string(),
        vectorString: z.string().optional(),
        baseScore: z.number().min(0).max(10),
      })
      .passthrough(),
  })
  .passthrough();
const CpeMatch = z
  .object({
    vulnerable: z.boolean(),
    criteria: z.string(),
    versionStartIncluding: z.string().optional(),
    versionStartExcluding: z.string().optional(),
    versionEndIncluding: z.string().optional(),
    versionEndExcluding: z.string().optional(),
  })
  .passthrough();
const NvdCve = z
  .object({
    id: z.string().regex(CVE_ID),
    published: z.string().optional(),
    lastModified: z.string(),
    vulnStatus: z.string().optional(),
    descriptions: z
      .array(z.object({ lang: z.string(), value: z.string() }))
      .default([]),
    metrics: z.record(z.string(), z.array(z.unknown())).default({}),
    weaknesses: z
      .array(
        z
          .object({
            description: z.array(z.object({ value: z.string() })).default([]),
          })
          .passthrough(),
      )
      .default([]),
    configurations: z
      .array(
        z
          .object({
            nodes: z
              .array(
                z
                  .object({ cpeMatch: z.array(z.unknown()).default([]) })
                  .passthrough(),
              )
              .default([]),
          })
          .passthrough(),
      )
      .default([]),
    affected: z.array(z.unknown()).default([]),
    references: z
      .array(
        z
          .object({ url: z.string(), tags: z.array(z.string()).optional() })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();
const NvdAffected = z
  .object({
    affectedData: z
      .array(
        z
          .object({
            vendor: z.string().optional(),
            product: z.string().optional(),
            packageName: z.string().optional(),
            versions: z
              .array(
                z
                  .object({
                    version: z.string().optional(),
                    lessThan: z.string().optional(),
                    lessThanOrEqual: z.string().optional(),
                    status: z.string().optional(),
                  })
                  .passthrough(),
              )
              .default([]),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();
export interface Affected {
  vendor: string;
  product: string;
  versions: string | null;
}
export interface CveRecord {
  cve: string;
  published: string | null;
  lastModified: string;
  status: string | null;
  description: string;
  cvss: { version: string; base_score: number; vector: string | null } | null;
  cwe: string[];
  affected: Affected[];
  references: { url: string; tags: string[] }[];
}
/** NVD timestamps omit the zone and are UTC. */
function nvdDate(value: string | undefined) {
  if (!value) return null;
  const time = Date.parse(
    /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : value + "Z",
  );
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}
const CVSS_ORDER = [
  "cvssMetricV40",
  "cvssMetricV31",
  "cvssMetricV30",
  "cvssMetricV2",
];
function cpeVersions(m: z.infer<typeof CpeMatch>, version: string | undefined) {
  const parts = [
    m.versionStartIncluding && ">= " + m.versionStartIncluding,
    m.versionStartExcluding && "> " + m.versionStartExcluding,
    m.versionEndIncluding && "<= " + m.versionEndIncluding,
    m.versionEndExcluding && "< " + m.versionEndExcluding,
  ].filter(Boolean);
  if (parts.length) return parts.join(", ");
  return version && version !== "*" && version !== "-" ? version : null;
}
const unescapeCpe = (s: string) => s.replace(/\\(.)/g, "$1");
export function parseNvdCve(raw: unknown): CveRecord {
  const cve = NvdCve.parse(raw);
  const lastModified = nvdDate(cve.lastModified);
  if (!lastModified) throw new Error("Invalid NVD lastModified");
  let cvss: CveRecord["cvss"] = null;
  for (const primary of [true, false]) {
    for (const key of CVSS_ORDER) {
      const metric = (cve.metrics[key] ?? [])
        .map((m) => NvdMetric.safeParse(m))
        .find((m) => m.success && (m.data.type === "Primary") === primary);
      if (metric?.success) {
        cvss = {
          version: metric.data.cvssData.version,
          base_score: metric.data.cvssData.baseScore,
          vector: metric.data.cvssData.vectorString ?? null,
        };
        break;
      }
    }
    if (cvss) break;
  }
  const affected = new Map<string, Affected>();
  for (const configuration of cve.configurations)
    for (const node of configuration.nodes)
      for (const raw of node.cpeMatch) {
        const match = CpeMatch.safeParse(raw);
        if (!match.success || !match.data.vulnerable) continue;
        const fields = match.data.criteria.split(/(?<!\\):/);
        if (fields.length < 6 || !fields[3] || !fields[4]) continue;
        const item = {
          vendor: unescapeCpe(fields[3]),
          product: unescapeCpe(fields[4]),
          versions: cpeVersions(match.data, fields[5]),
        };
        affected.set(JSON.stringify(item), item);
      }
  if (!affected.size)
    for (const raw of cve.affected) {
      const parsed = NvdAffected.safeParse(raw);
      if (!parsed.success) continue;
      for (const a of parsed.data.affectedData) {
        const product = a.product ?? a.packageName;
        if (!a.vendor || !product) continue;
        const ranges = a.versions
          .filter((v) => v.status === "affected")
          .map((v) =>
            v.lessThan && v.lessThan !== "*"
              ? (v.version && v.version !== "0"
                  ? ">= " + v.version + ", "
                  : "") +
                "< " +
                v.lessThan
              : v.lessThanOrEqual
                ? "<= " + v.lessThanOrEqual
                : (v.version ?? ""),
          )
          .filter(Boolean);
        const item = {
          vendor: a.vendor,
          product,
          versions: ranges.length ? ranges.join("; ") : null,
        };
        affected.set(JSON.stringify(item), item);
      }
    }
  const references = new Map<string, { url: string; tags: string[] }>();
  for (const r of cve.references)
    if (/^https?:\/\//i.test(r.url) && !references.has(r.url))
      references.set(r.url, { url: r.url, tags: r.tags ?? [] });
  return {
    cve: cve.id,
    published: nvdDate(cve.published),
    lastModified,
    status: cve.vulnStatus ?? null,
    description:
      (
        cve.descriptions.find((d) => d.lang === "en") ?? cve.descriptions[0]
      )?.value.slice(0, 4000) ?? "",
    cvss,
    cwe: [
      ...new Set(
        cve.weaknesses.flatMap((w) =>
          w.description.map((d) => d.value).filter((v) => /^CWE-\d+$/.test(v)),
        ),
      ),
    ].sort(),
    affected: [...affected.values()]
      .sort((a, b) =>
        (a.vendor + "\0" + a.product + "\0" + (a.versions ?? "")).localeCompare(
          b.vendor + "\0" + b.product + "\0" + (b.versions ?? ""),
        ),
      )
      .slice(0, 50),
    references: [...references.values()].slice(0, 50),
  };
}
const NvdPage = z.object({
  resultsPerPage: z.number().int().min(0),
  startIndex: z.number().int().min(0),
  totalResults: z.number().int().min(0),
  vulnerabilities: z.array(z.object({ cve: z.unknown() })),
});
/** NVD allows 2,000; 1,000 keeps a page well inside Worker memory. */
export const NVD_MAX_PAGE_SIZE = 1000;
const NVD_MAX_PAGE_BYTES = 32 * 1024 * 1024;
export function nvdPageSize(value: unknown) {
  const size = Math.trunc(Number(value ?? NVD_MAX_PAGE_SIZE));
  return Number.isFinite(size)
    ? Math.min(NVD_MAX_PAGE_SIZE, Math.max(1, size))
    : NVD_MAX_PAGE_SIZE;
}
export function nvdPageUrl(cursor: NvdCursor, pageSize: number) {
  const url = new URL(NVD_URL);
  url.searchParams.set("resultsPerPage", String(pageSize));
  url.searchParams.set("startIndex", String(cursor.startIndex));
  if (cursor.mode === "incremental") {
    url.searchParams.set("lastModStartDate", cursor.since);
    url.searchParams.set("lastModEndDate", cursor.windowEnd!);
  }
  return url;
}
/**
 * One NVD page per call. The first run pages through every CVE, then
 * incremental windows (at most 120 days, NVD's limit) start from the time the
 * backfill began, so records changed during the backfill are not missed.
 */
export async function syncNvdPage(
  env: { DB: D1Database; ARCHIVE: R2Bucket },
  request: typeof fetch,
  options: { apiKey?: string; pageSize?: number; cursor: NvdCursor | null },
  now = new Date(),
) {
  const pageSize = nvdPageSize(options.pageSize);
  let cursor: NvdCursor = options.cursor ?? {
    mode: "backfill",
    startIndex: 0,
    startedAt: now.toISOString(),
  };
  if (cursor.mode === "incremental" && !cursor.windowEnd)
    cursor = {
      ...cursor,
      startIndex: 0,
      windowEnd: new Date(
        Math.min(Date.parse(cursor.since) + MAX_WINDOW_MS, now.getTime()),
      ).toISOString(),
    };
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.apiKey) headers.apiKey = options.apiKey;
  const response = await request(nvdPageUrl(cursor, pageSize), {
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(90000),
  });
  if (!response.ok) throw new Error("Upstream HTTP " + response.status);
  // Bounded read: an oversized page fails instead of exhausting memory.
  const text = await boundedText(response, NVD_MAX_PAGE_BYTES);
  const date = now.toISOString().slice(0, 10).replace(/-/g, "/");
  await env.ARCHIVE.put(
    "raw/nvd/" + date + "/" + (await digest(JSON.stringify(cursor))) + ".json",
    text,
    { httpMetadata: { contentType: "application/json" } },
  );
  const page = NvdPage.parse(JSON.parse(text));
  const retrievedAt = now.toISOString();
  let stored = 0,
    rejected = 0;
  const statements: D1PreparedStatement[] = [];
  for (const item of page.vulnerabilities) {
    let record: CveRecord;
    try {
      record = parseNvdCve(item.cve);
    } catch {
      rejected++;
      continue;
    }
    stored++;
    statements.push(
      env.DB.prepare(
        "INSERT INTO cve_records(cve,published,last_modified,status,description,cvss_version,cvss_score,cvss_vector,data,retrieved_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET published=excluded.published,last_modified=excluded.last_modified,status=excluded.status,description=excluded.description,cvss_version=excluded.cvss_version,cvss_score=excluded.cvss_score,cvss_vector=excluded.cvss_vector,data=excluded.data,retrieved_at=excluded.retrieved_at WHERE excluded.last_modified>=cve_records.last_modified",
      ).bind(
        record.cve,
        record.published,
        record.lastModified,
        record.status,
        record.description,
        record.cvss?.version ?? null,
        record.cvss?.base_score ?? null,
        record.cvss?.vector ?? null,
        JSON.stringify({
          cwe: record.cwe,
          affected: record.affected,
          references: record.references,
        }),
        retrievedAt,
      ),
    );
  }
  for (let i = 0; i < statements.length; i += 100)
    await env.DB.batch(statements.slice(i, i + 100));
  const nextIndex = page.startIndex + page.vulnerabilities.length;
  const complete =
    page.vulnerabilities.length === 0 || nextIndex >= page.totalResults;
  const next: NvdCursor = !complete
    ? { ...cursor, startIndex: nextIndex }
    : cursor.mode === "backfill"
      ? { mode: "incremental", since: cursor.startedAt, startIndex: 0 }
      : { mode: "incremental", since: cursor.windowEnd!, startIndex: 0 };
  return { cursor: next, stored, rejected, complete, total: page.totalResults };
}
export async function cveRecords(db: D1Database, ids: string[]) {
  if (!ids.length)
    return new Map<string, CveRecord & { retrievedAt: string }>();
  const rows = await db
    .prepare(
      "SELECT cve,published,last_modified,status,description,cvss_version,cvss_score,cvss_vector,data,retrieved_at FROM cve_records WHERE cve IN (SELECT value FROM json_each(?))",
    )
    .bind(JSON.stringify(ids))
    .all<{
      cve: string;
      published: string | null;
      last_modified: string;
      status: string | null;
      description: string;
      cvss_version: string | null;
      cvss_score: number | null;
      cvss_vector: string | null;
      data: string;
      retrieved_at: string;
    }>();
  return new Map(
    rows.results.map((row) => {
      const data = JSON.parse(row.data) as Pick<
        CveRecord,
        "cwe" | "affected" | "references"
      >;
      return [
        row.cve,
        {
          cve: row.cve,
          published: row.published,
          lastModified: row.last_modified,
          status: row.status,
          description: row.description,
          cvss:
            row.cvss_version && row.cvss_score !== null
              ? {
                  version: row.cvss_version,
                  base_score: row.cvss_score,
                  vector: row.cvss_vector,
                }
              : null,
          ...data,
          retrievedAt: row.retrieved_at,
        },
      ];
    }),
  );
}

// OSV ------------------------------------------------------------------------
export const OSV_URL = "https://api.osv.dev/v1/vulns/";
const OsvRecord = z
  .object({
    id: z.string(),
    aliases: z.array(z.string()).default([]),
    related: z.array(z.string()).default([]),
    published: z.string().optional(),
    modified: z.string(),
    summary: z.string().optional(),
    details: z.string().optional(),
    affected: z
      .array(
        z
          .object({
            package: z
              .object({ ecosystem: z.string(), name: z.string() })
              .passthrough()
              .optional(),
            ranges: z
              .array(
                z
                  .object({
                    type: z.string(),
                    events: z.array(z.record(z.string(), z.string())),
                  })
                  .passthrough(),
              )
              .default([]),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();
export interface OsvSummary {
  id: string;
  ids: string[];
  published: string | null;
  modified: string;
  description: string;
  affected: Affected[];
}
export function parseOsv(raw: unknown, cve: string): OsvSummary {
  const record = OsvRecord.parse(raw);
  const affected = new Map<string, Affected>();
  for (const a of record.affected) {
    if (!a.package) continue;
    const ranges = a.ranges
      .filter((r) => r.type !== "GIT")
      .flatMap((r) =>
        r.events.map((e) =>
          Object.entries(e)
            .map(([k, v]) => k + " " + v)
            .join(""),
        ),
      );
    const item = {
      vendor: a.package.ecosystem,
      product: a.package.name,
      versions: ranges.length ? ranges.join(", ") : null,
    };
    affected.set(JSON.stringify(item), item);
  }
  return {
    id: record.id,
    ids: [
      ...new Set(
        [record.id, ...record.aliases, ...record.related].filter(
          (id) => id !== cve,
        ),
      ),
    ]
      .sort()
      .slice(0, 50),
    published: record.published
      ? new Date(record.published).toISOString()
      : null,
    modified: new Date(record.modified).toISOString(),
    description: (record.summary ?? record.details ?? "").slice(0, 4000),
    affected: [...affected.values()].slice(0, 50),
  };
}
/** Returns null when OSV has no record under the CVE identifier. */
export async function fetchOsv(request: typeof fetch, cve: string) {
  if (!CVE_ID.test(cve)) throw new Error("Invalid CVE");
  const response = await request(OSV_URL + cve, {
    headers: { Accept: "application/json" },
    redirect: "manual",
    signal: AbortSignal.timeout(20000),
  });
  if (response.status === 404) return { raw: null, summary: null };
  if (!response.ok) throw new Error("Upstream HTTP " + response.status);
  const raw: unknown = JSON.parse(await boundedText(response, 4 * 1024 * 1024));
  return { raw, summary: parseOsv(raw, cve) };
}
