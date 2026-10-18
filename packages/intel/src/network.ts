import ipaddr from "ipaddr.js";
import {
  DatasetReader,
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

/**
 * IP-to-ASN and country context from iptoasn.com (PDDL 1.0). The whole
 * dataset is imported on a schedule, so a lookup never calls a third party.
 */
export const IPTOASN_URLS = {
  v4: "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
  v6: "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
} as const;
const MAX_DOWNLOAD = 64 * 1024 * 1024;
type Family = "v4" | "v6";
const BITS: Record<Family, number> = { v4: 32, v6: 128 };
const WIDTH: Record<Family, number> = { v4: 8, v6: 32 };

export interface NetworkFacts {
  asn: number;
  as_org: string | null;
  prefix: string | null;
  country: string | null;
}
export function addressKey(value: string): {
  family: Family;
  key: string;
  value: bigint;
} {
  const parsed = ipaddr.parse(value);
  const family: Family = parsed.kind() === "ipv4" ? "v4" : "v6";
  const number = parsed
    .toByteArray()
    .reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);
  return {
    family,
    key: number.toString(16).padStart(WIDTH[family], "0"),
    value: number,
  };
}
export function asnKey(asn: number) {
  return String(asn).padStart(10, "0");
}
function format(value: bigint, family: Family) {
  const bytes: number[] = [];
  for (let i = 0; i < BITS[family] / 8; i++) {
    bytes.unshift(Number(value & 255n));
    value >>= 8n;
  }
  return ipaddr.fromByteArray(bytes).toString();
}
/** The largest CIDR block holding the address that stays inside the range. */
export function coveringPrefix(
  address: bigint,
  start: bigint,
  end: bigint,
  family: Family,
): string | null {
  const bits = BigInt(BITS[family]);
  const all = (1n << bits) - 1n;
  for (let length = 0n; length <= bits; length++) {
    const host = (1n << (bits - length)) - 1n;
    const base = address & (all ^ host);
    if (base >= start && (base | host) <= end)
      return format(base, family) + "/" + length;
  }
  return null;
}
export interface IpToAsnRow {
  family: Family;
  start: string;
  end: string;
  asn: number;
  country: string | null;
  org: string | null;
}
/** Returns null for unrouted space and malformed lines. */
export function parseIpToAsnLine(line: string): IpToAsnRow | null {
  const [start, end, asn, country, ...description] = line.split("\t");
  if (!start || !end || !asn) return null;
  const number = Number(asn);
  if (!Number.isInteger(number) || number < 1 || number > 4294967295)
    return null;
  let from, to;
  try {
    from = addressKey(start);
    to = addressKey(end);
  } catch {
    return null;
  }
  if (from.family !== to.family || from.value > to.value) return null;
  const org = description.join("\t").trim();
  return {
    family: from.family,
    start: from.key,
    end: to.key,
    asn: number,
    country: country && /^[A-Z]{2}$/.test(country) ? country : null,
    org: org && org !== "Not routed" ? org.slice(0, 200) : null,
  };
}
export async function importIpToAsn(
  env: { DB: D1Database; ARCHIVE: R2Bucket },
  request: typeof fetch,
  now = new Date(),
) {
  const files = {
    v4: await fetchDataset(request, IPTOASN_URLS.v4, MAX_DOWNLOAD),
    v6: await fetchDataset(request, IPTOASN_URLS.v6, MAX_DOWNLOAD),
  };
  const sourceDigest = await bytesDigest(
    new TextEncoder().encode(
      (await bytesDigest(files.v4)) + (await bytesDigest(files.v6)),
    ),
  );
  const current = (await currentVersions(env.DB)).get("iptoasn");
  if (current?.source_digest === sourceDigest)
    return {
      version: current.version,
      records: current.record_count,
      changed: false,
    };
  const version = versionFor(now, sourceDigest);
  const prefix = datasetPrefix("iptoasn", version);
  const asns = new Map<number, [string | null, string | null]>();
  let records = 0;
  for (const family of ["v4", "v6"] as const) {
    await archiveSource(
      env.ARCHIVE,
      "iptoasn",
      "ip2asn-" + family + ".tsv.gz",
      version,
      files[family],
    );
    const writer = new ShardWriter(env.ARCHIVE, prefix, family);
    for await (const line of gzipLines(files[family])) {
      const row = parseIpToAsnLine(line);
      if (!row) continue;
      if (row.family !== family) throw new Error("Unexpected address family");
      await writer.add([row.start, row.end, row.asn, row.country, row.org]);
      if (!asns.has(row.asn)) asns.set(row.asn, [row.country, row.org]);
    }
    records += (await writer.finish()).rows;
  }
  const asnWriter = new ShardWriter(env.ARCHIVE, prefix, "asn");
  for (const asn of [...asns.keys()].sort((a, b) => a - b))
    await asnWriter.add([asnKey(asn), ...asns.get(asn)!]);
  await asnWriter.finish();
  if (!records) throw new Error("IPtoASN dataset contained no routed ranges");
  await promoteVersion(env.DB, env.ARCHIVE, {
    dataset: "iptoasn",
    version,
    source_digest: sourceDigest,
    source_updated_at: null,
    record_count: records,
    imported_at: now.toISOString(),
  });
  return { version, records, changed: true };
}
export async function lookupAddress(
  reader: DatasetReader,
  address: string,
): Promise<NetworkFacts | null> {
  const ip = addressKey(address);
  const row = await reader.floor(ip.family, ip.key);
  if (!row) return null;
  const [start, end, asn, country, org] = row;
  if (typeof end !== "string" || end < ip.key || typeof asn !== "number")
    return null;
  return {
    asn,
    as_org: typeof org === "string" ? org : null,
    prefix: coveringPrefix(
      ip.value,
      BigInt("0x" + start),
      BigInt("0x" + end),
      ip.family,
    ),
    country: typeof country === "string" ? country : null,
  };
}
export async function lookupAsn(
  reader: DatasetReader,
  asn: number,
): Promise<NetworkFacts | null> {
  const row = await reader.exact("asn", asnKey(asn));
  if (!row) return null;
  return {
    asn,
    as_org: typeof row[2] === "string" ? row[2] : null,
    prefix: null,
    country: typeof row[1] === "string" ? row[1] : null,
  };
}
