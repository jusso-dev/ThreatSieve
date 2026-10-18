import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import type { Miniflare } from "miniflare";
import { hubFetch, json, migratedDatabase } from "./hub-fixtures";
import {
  DatasetReader,
  ShardWriter,
  clearDatasetCache,
  currentVersions,
  datasetCacheStats,
  setDatasetCacheLimit,
} from "../packages/intel/src/datasets";
import {
  addressKey,
  coveringPrefix,
  importIpToAsn,
  lookupAddress,
  lookupAsn,
  parseIpToAsnLine,
} from "../packages/intel/src/network";
import {
  epssUrl,
  fetchOsv,
  importEpss,
  nvdDue,
  nvdPageSize,
  nvdPageUrl,
  parseNvdCve,
  parseOsv,
  syncNvdPage,
  cveRecords,
} from "../packages/intel/src/cve";
import { OptionalFeed } from "../packages/intel/src/optional-feeds";
import { Repository } from "../packages/database/src/repository";
import { runScheduledDatasets, syncNvd } from "../workers/feed-sync/datasets";
import type { AppEnv } from "../apps/api/src/env";

let mf: Miniflare;
let db: D1Database;
let bucket: R2Bucket;
beforeAll(async () => {
  ({ mf, db, bucket } = await migratedDatabase());
}, 120000);
afterAll(async () => {
  await mf?.dispose();
});

describe("IPtoASN network context", () => {
  it("parses routed ranges and skips unrouted space", () => {
    expect(
      parseIpToAsnLine("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed"),
    ).toBeNull();
    expect(parseIpToAsnLine("garbage")).toBeNull();
    const row = parseIpToAsnLine(
      "1.0.4.0\t1.0.6.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd",
    );
    expect(row).toMatchObject({
      family: "v4",
      start: "01000400",
      end: "010006ff",
      asn: 38803,
      country: "AU",
      org: "GTELECOM-AS-AP Gtelecom Pty Ltd",
    });
    expect(
      parseIpToAsnLine(
        "2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64501\tNone\tX",
      ),
    ).toMatchObject({ family: "v6", country: null });
  });
  it("derives the largest CIDR inside a non-aligned range", () => {
    const range = (a: string, b: string, ip: string) =>
      coveringPrefix(
        addressKey(ip).value,
        addressKey(a).value,
        addressKey(b).value,
        addressKey(ip).family,
      );
    expect(range("1.0.4.0", "1.0.6.255", "1.0.4.9")).toBe("1.0.4.0/23");
    expect(range("1.0.4.0", "1.0.6.255", "1.0.6.1")).toBe("1.0.6.0/24");
    expect(range("203.0.113.0", "203.0.113.255", "203.0.113.7")).toBe(
      "203.0.113.0/24",
    );
    expect(
      range("2001:db9::", "2001:db9:0:ff:ffff:ffff:ffff:ffff", "2001:db9::5"),
    ).toBe("2001:db9::/56");
  });
  it("finds rows across shard boundaries with a floor search", async () => {
    const writer = new ShardWriter(bucket, "datasets/test/v1/", "keys", 2);
    for (const key of ["b", "d", "f", "h", "j"]) await writer.add([key, key]);
    await expect(writer.add(["a"])).rejects.toThrow(/increasing/);
    expect(await writer.finish()).toEqual({
      family: "keys",
      shards: 3,
      rows: 5,
    });
    const reader = new DatasetReader(bucket, "test", "v1");
    expect(await reader.floor("keys", "a")).toBeNull();
    expect((await reader.floor("keys", "e"))?.[0]).toBe("d");
    expect((await reader.floor("keys", "z"))?.[0]).toBe("j");
    expect(await reader.exact("keys", "e")).toBeNull();
    expect((await reader.exact("keys", "f"))?.[0]).toBe("f");
  });
  it("answers 500 addresses spread across shards within the cache byte cap", async () => {
    clearDatasetCache();
    const writer = new ShardWriter(bucket, "datasets/spread/v1/", "v4", 100);
    // 20,000 /24 ranges in 200 shards.
    for (let i = 0; i < 20000; i++) {
      const start = (10 << 24) + i * 256;
      const hex = (n: number) => (n >>> 0).toString(16).padStart(8, "0");
      await writer.add([
        hex(start),
        hex(start + 255),
        64512 + (i % 1000),
        "AU",
        "AS-" + i,
      ]);
    }
    expect((await writer.finish()).shards).toBe(200);
    const limit = 256 * 1024;
    setDatasetCacheLimit(limit);
    try {
      const reader = new DatasetReader(bucket, "spread", "v1");
      let peak = 0;
      for (let n = 0; n < 500; n++) {
        const i = (n * 7919) % 20000;
        const ip = [10, (i >> 8) & 255, i & 255, 9].join(".");
        const facts = await lookupAddress(reader, ip);
        expect(facts?.as_org).toBe("AS-" + i);
        peak = Math.max(peak, datasetCacheStats().bytes);
      }
      // One shard is about 10 KB of text; the cap holds with one in flight.
      expect(peak).toBeLessThanOrEqual(limit + 64 * 1024);
      expect(datasetCacheStats().entries).toBeGreaterThan(1);
    } finally {
      setDatasetCacheLimit(16 * 1024 * 1024);
      clearDatasetCache();
    }
  }, 120000);
  it("rejects rows that would break raw key search", async () => {
    const writer = new ShardWriter(bucket, "datasets/bad/v1/", "keys");
    await expect(writer.add(['a"b', 1])).rejects.toThrow(/plain text/);
    await expect(writer.add(["ok", Number.NaN])).rejects.toThrow(
      /invalid value/,
    );
  });
  it("imports the dataset into R2 shards and answers IP and ASN lookups", async () => {
    const { request, calls } = hubFetch();
    const env = { DB: db, ARCHIVE: bucket };
    const now = new Date("2099-01-03T00:00:00.000Z");
    const first = await importIpToAsn(env, request, now);
    expect(first).toMatchObject({ changed: true, records: 7 });
    expect(calls).toHaveLength(2);
    const version = (await currentVersions(db)).get("iptoasn")!;
    expect(version.version).toBe(first.version);
    expect(
      await bucket.head(
        "raw/iptoasn/2099/01/03/" + first.version + "-ip2asn-v4.tsv.gz",
      ),
    ).not.toBeNull();
    const reader = new DatasetReader(bucket, "iptoasn", version.version);
    expect(await lookupAddress(reader, "203.0.113.7")).toEqual({
      asn: 64500,
      as_org: "EXAMPLE-AS Example Hosting",
      prefix: "203.0.113.0/24",
      country: "AU",
    });
    expect(await lookupAddress(reader, "1.0.2.1")).toBeNull();
    expect(await lookupAddress(reader, "2001:db8::1")).toMatchObject({
      asn: 64501,
      prefix: "2001:db8::/32",
      country: "DE",
    });
    expect(await lookupAsn(reader, 38803)).toEqual({
      asn: 38803,
      as_org: "GTELECOM-AS-AP Gtelecom Pty Ltd",
      prefix: null,
      country: "AU",
    });
    expect(await lookupAsn(reader, 1)).toBeNull();
    // Unchanged upstream files do not create a new version.
    const again = await importIpToAsn(
      env,
      request,
      new Date("2099-01-04T00:00:00Z"),
    );
    expect(again).toMatchObject({ changed: false, version: first.version });
  });
});

describe("FIRST EPSS", () => {
  it("uses the dated file, falls back a day and stores sorted scores", async () => {
    const now = new Date("2099-01-04T01:00:00.000Z");
    expect(epssUrl(now)).toBe(
      "https://epss.empiricalsecurity.com/epss_scores-2099-01-04.csv.gz",
    );
    const { request, calls } = hubFetch({
      [epssUrl(now)]: () => new Response("not yet", { status: 404 }),
    });
    const result = await importEpss({ DB: db, ARCHIVE: bucket }, request, now);
    expect(result).toMatchObject({ changed: true, records: 3 });
    expect(calls).toEqual([
      epssUrl(now),
      epssUrl(new Date("2099-01-03T01:00:00.000Z")),
    ]);
    const version = (await currentVersions(db)).get("epss")!;
    expect(version.source_updated_at).toBe("2099-01-03T12:00:28.000Z");
    const reader = new DatasetReader(bucket, "epss", version.version);
    expect(await reader.exact("scores", "CVE-2099-0001")).toEqual([
      "CVE-2099-0001",
      0.97,
      0.999,
    ]);
    expect(await reader.exact("scores", "CVE-2099-9999")).toBeNull();
  });
  it("refuses a file without the expected header", async () => {
    const { request } = hubFetch({
      "https://epss.empiricalsecurity.com/": () =>
        new Response(gzipSync("cve,score\n")),
    });
    await expect(
      importEpss(
        { DB: db, ARCHIVE: bucket },
        request,
        new Date("2099-02-01T00:00:00Z"),
      ),
    ).rejects.toThrow(/header/);
  });
});

describe("NVD API 2.0", () => {
  const page = json("nvd-page.json") as {
    vulnerabilities: { cve: unknown }[];
  };
  it("clamps the NVD page size to 1,000", () => {
    expect(nvdPageSize(2000)).toBe(1000);
    expect(nvdPageSize("250")).toBe(250);
    expect(nvdPageSize("lots")).toBe(1000);
    expect(nvdPageSize(0)).toBe(1);
    expect(nvdPageSize(undefined)).toBe(1000);
  });
  it("normalises CVSS, CWE, affected products and references", () => {
    const record = parseNvdCve(page.vulnerabilities[0]!.cve);
    expect(record).toMatchObject({
      cve: "CVE-2099-0001",
      published: "2099-01-01T00:00:00.000Z",
      lastModified: "2099-01-03T10:00:00.000Z",
      status: "Analyzed",
      description: "Synthetic path traversal in Example Demo App before 1.0.1.",
      // NVD's primary score wins over a CNA's secondary CVSS 4.0 score.
      cvss: {
        version: "3.1",
        base_score: 9.8,
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
      cwe: ["CWE-22"],
      affected: [
        { vendor: "example", product: "demo-app", versions: "< 1.0.1" },
      ],
      references: [
        {
          url: "https://example.test/advisories/demo-app",
          tags: ["Vendor Advisory"],
        },
      ],
    });
    expect(parseNvdCve(page.vulnerabilities[1]!.cve)).toMatchObject({
      cvss: null,
      affected: [
        { vendor: "Example", product: "Widget", versions: ">= 2.0, < 2.4" },
      ],
    });
    expect(() => parseNvdCve(page.vulnerabilities[2]!.cve)).toThrow();
  });
  it("backfills, then moves to bounded lastModified windows", async () => {
    const { request, calls } = hubFetch();
    const env = { DB: db, ARCHIVE: bucket };
    const now = new Date("2099-01-04T00:00:00.000Z");
    expect(nvdDue(null, now)).toBe(true);
    const first = await syncNvdPage(
      env,
      request,
      { cursor: null, pageSize: 1000 },
      now,
    );
    expect(first).toMatchObject({ stored: 2, rejected: 1, complete: true });
    expect(first.cursor).toEqual({
      mode: "incremental",
      since: now.toISOString(),
      startIndex: 0,
    });
    expect(new URL(calls[0]!).searchParams.get("lastModStartDate")).toBeNull();
    expect(nvdDue(first.cursor, new Date(now.getTime() + 3600000))).toBe(false);
    const later = new Date(now.getTime() + 200 * 86400000);
    expect(nvdDue(first.cursor, later)).toBe(true);
    const second = await syncNvdPage(
      env,
      request,
      { cursor: first.cursor, apiKey: "test-nvd-key" },
      later,
    );
    const url = new URL(calls[1]!);
    expect(url.searchParams.get("lastModStartDate")).toBe(now.toISOString());
    // NVD rejects windows over 120 days.
    expect(url.searchParams.get("lastModEndDate")).toBe(
      new Date(now.getTime() + 120 * 86400000).toISOString(),
    );
    expect(second.cursor).toMatchObject({
      mode: "incremental",
      since: new Date(now.getTime() + 120 * 86400000).toISOString(),
    });
    const records = await cveRecords(db, ["CVE-2099-0001", "CVE-2099-9999"]);
    expect([...records.keys()]).toEqual(["CVE-2099-0001"]);
    expect(records.get("CVE-2099-0001")!.cvss?.base_score).toBe(9.8);
  });
  it("pages within a window and keeps newer records", async () => {
    const url = nvdPageUrl(
      {
        mode: "incremental",
        since: "2099-01-01T00:00:00.000Z",
        startIndex: 1000,
        windowEnd: "2099-01-02T00:00:00.000Z",
      },
      1000,
    );
    expect(url.searchParams.get("startIndex")).toBe("1000");
    const older = structuredClone(page);
    (older.vulnerabilities[0]!.cve as Record<string, unknown>).lastModified =
      "2098-01-01T00:00:00.000";
    (older.vulnerabilities[0]!.cve as Record<string, unknown>).vulnStatus =
      "Stale";
    const { request } = hubFetch({
      "https://services.nvd.nist.gov/": () => Response.json(older),
    });
    await syncNvdPage(
      { DB: db, ARCHIVE: bucket },
      request,
      { cursor: null },
      new Date(),
    );
    const row = (await cveRecords(db, ["CVE-2099-0001"])).get("CVE-2099-0001");
    expect(row?.status).toBe("Analyzed");
  });
});

describe("OSV by CVE identifier", () => {
  it("collects aliases and affected packages, and treats 404 as no record", async () => {
    const summary = parseOsv(json("osv-cve.json"), "CVE-2099-0001");
    expect(summary).toMatchObject({
      id: "CVE-2099-0001",
      ids: ["EXAMPLE-SA-2099:0001", "GHSA-xxxx-yyyy-zzzz"],
      affected: [
        {
          vendor: "npm",
          product: "demo-app",
          versions: "introduced 0, fixed 1.0.1",
        },
      ],
    });
    const { request } = hubFetch();
    expect((await fetchOsv(request, "CVE-2099-0002")).summary).toBeNull();
    await expect(fetchOsv(request, "not-a-cve")).rejects.toThrow();
  });
});

describe("GreyNoise and CrowdSec lookups", () => {
  const repo = {} as Repository;
  const greynoise = json("greynoise-community.json");
  it("classifies GreyNoise noise and RIOT answers as scanner facts", async () => {
    const feed = new OptionalFeed("greynoise", "GreyNoise", repo, {
      enabled: true,
      apiKey: "test-only",
    });
    const [noise] = await feed.normalize({
      observable: "198.51.100.7",
      raw: greynoise.noise,
    });
    expect(noise!.evidence[0]!.data).toMatchObject({
      role: "scanning",
      scanner: {
        isScanner: true,
        benignService: false,
        name: "Example Scanner",
      },
    });
    expect(noise!.evidence[0]!.provenance.sourceUrl).toBe(
      "https://viz.greynoise.io/ip/198.51.100.7",
    );
    const [riot] = await feed.normalize({
      observable: "1.0.0.1",
      raw: greynoise.riot,
    });
    expect(riot!.evidence[0]!.data).toMatchObject({
      malicious: false,
      scanner: { isScanner: false, benignService: true, name: "Cloudflare" },
    });
  });
  it("treats an unobserved address as no record rather than a failure", async () => {
    const { request, calls } = hubFetch();
    const feed = new OptionalFeed(
      "greynoise",
      "GreyNoise",
      repo,
      { enabled: true, apiKey: "test-only" },
      request,
    );
    expect((await feed.fetch("203.0.113.9")).records).toEqual([]);
    expect(calls[0]).toBe("https://api.greynoise.io/v3/community/203.0.113.9");
    await expect(feed.fetch("2001:db8::1")).rejects.toThrow(/IPv4/);
  });
  it("maps CrowdSec smoke behaviours to scanner facts and tags", async () => {
    const { request } = hubFetch();
    const feed = new OptionalFeed(
      "crowdsec",
      "CrowdSec CTI",
      repo,
      { enabled: true, apiKey: "test-only" },
      request,
    );
    const batch = await feed.fetch("198.51.100.7");
    const [record] = await feed.normalize(batch.records[0]);
    expect(record!.evidence[0]).toMatchObject({
      observedAt: "2099-01-02T12:00:00.000Z",
      data: {
        malicious: true,
        role: "scanning",
        tags: ["community-blocklist", "ssh:bruteforce", "tcp:scan"],
        scanner: { isScanner: true, benignService: false, name: null },
      },
    });
    expect((await feed.fetch("2001:db8::1")).records).toEqual([]);
    await expect(
      new OptionalFeed("crowdsec", "CrowdSec CTI", repo, {
        enabled: true,
      }).fetch("198.51.100.7"),
    ).rejects.toThrow(/credential/);
  });
});

describe("scheduled datasets", () => {
  it("imports daily datasets once per day and records source health", async () => {
    const fresh = await migratedDatabase();
    try {
      const env = { DB: fresh.db, ARCHIVE: fresh.bucket } as unknown as AppEnv;
      const { request, calls } = hubFetch();
      const now = new Date("2099-01-04T06:17:00.000Z");
      await runScheduledDatasets(env, "17 */6 * * *", now, request);
      const rows = await fresh.db
        .prepare(
          "SELECT id,status,last_sync FROM sources WHERE id IN ('iptoasn','epss','nvd') ORDER BY id",
        )
        .all<{ id: string; status: string; last_sync: string }>();
      expect(rows.results).toEqual([
        { id: "epss", status: "healthy", last_sync: now.toISOString() },
        { id: "iptoasn", status: "healthy", last_sync: now.toISOString() },
        { id: "nvd", status: "healthy", last_sync: now.toISOString() },
      ]);
      const count = calls.length;
      // A later tick inside the daily window and NVD's two-hour interval is a no-op.
      await runScheduledDatasets(
        env,
        "17 */6 * * *",
        new Date(now.getTime() + 3600000),
        request,
      );
      expect(calls.length).toBe(count);
      expect(
        await fresh.db
          .prepare("SELECT COUNT(*) AS n FROM feed_locks")
          .first("n"),
      ).toBe(0);
    } finally {
      await fresh.mf.dispose();
    }
  }, 120000);
  it("records failures without throwing and skips disabled sources", async () => {
    const fresh = await migratedDatabase();
    try {
      const env = { DB: fresh.db, ARCHIVE: fresh.bucket } as unknown as AppEnv;
      await fresh.db
        .prepare("UPDATE sources SET enabled=0 WHERE id='epss'")
        .run();
      const { request, calls } = hubFetch({
        "https://iptoasn.com/": () => new Response("busy", { status: 503 }),
        "https://services.nvd.nist.gov/": () =>
          new Response("slow down", { status: 403 }),
      });
      await runScheduledDatasets(env, "17 */6 * * *", new Date(), request);
      expect(calls.some((c) => c.includes("epss"))).toBe(false);
      const rows = await fresh.db
        .prepare(
          "SELECT id,status,last_error FROM sources WHERE id IN ('iptoasn','nvd') ORDER BY id",
        )
        .all();
      expect(rows.results).toEqual([
        { id: "iptoasn", status: "error", last_error: "UpstreamUnavailable" },
        { id: "nvd", status: "error", last_error: "UpstreamAccessDenied" },
      ]);
      await syncNvd(env, new Date(), request);
      expect(
        await fresh.db
          .prepare("SELECT COUNT(*) AS n FROM feed_locks")
          .first("n"),
      ).toBe(0);
    } finally {
      await fresh.mf.dispose();
    }
  }, 120000);
});
