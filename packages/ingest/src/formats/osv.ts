import { z } from "zod";
import { parseCvssVector } from "../severity";
import {
  clip,
  documentIssues,
  httpLinks,
  isRecord,
  str,
  type Mapped,
} from "./common";

const date = z.iso.datetime({ offset: true });
const Severity = z.looseObject({ type: z.string(), score: z.string() });
/** The OSV schema fields the mapper reads; other properties are kept in `raw`. */
export const OsvRecord = z.looseObject({
  schema_version: z.string().optional(),
  id: z.string().min(1).max(256),
  modified: date,
  published: date.optional(),
  withdrawn: date.optional(),
  aliases: z.array(z.string()).optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  severity: z.array(Severity).optional(),
  affected: z
    .array(
      z.looseObject({
        package: z
          .looseObject({
            ecosystem: z.string(),
            name: z.string(),
            purl: z.string().optional(),
          })
          .optional(),
        severity: z.array(Severity).optional(),
        ranges: z
          .array(
            z.looseObject({
              type: z.string(),
              events: z.array(z.record(z.string(), z.string())),
            }),
          )
          .optional(),
        versions: z.array(z.string()).optional(),
        ecosystem_specific: z.unknown().optional(),
        database_specific: z.unknown().optional(),
      }),
    )
    .optional(),
  references: z
    .array(z.looseObject({ type: z.string(), url: z.string() }))
    .optional(),
  database_specific: z.unknown().optional(),
});

/** Advisory databases by OSV ID prefix, reported as the source vendor. */
const DATABASES: Record<string, string> = {
  GHSA: "GitHub Advisory Database",
  PYSEC: "PyPI Advisory Database",
  RUSTSEC: "RustSec",
  GO: "Go Vulnerability Database",
  OSV: "OSS-Fuzz",
  CVE: "CVE",
  DSA: "Debian",
  DLA: "Debian",
  USN: "Ubuntu",
  ALSA: "AlmaLinux",
  RLSA: "Rocky Linux",
  MAL: "OpenSSF Malicious Packages",
};
const CVSS: Record<string, string> = {
  CVSS_V2: "2.0",
  CVSS_V3: "3.1",
  CVSS_V4: "4.0",
};

/** Pairs OSV range events into introduced/fixed/last_affected bounds. */
function bounds(events: Record<string, string>[]) {
  const out: Record<string, string>[] = [];
  let open: string | undefined;
  for (const event of events) {
    if (event.introduced !== undefined) {
      if (open !== undefined) out.push({ introduced: open });
      open = event.introduced;
    } else if (event.fixed !== undefined || event.last_affected !== undefined) {
      const [key, value] =
        event.fixed !== undefined
          ? ["fixed", event.fixed]
          : ["last_affected", event.last_affected!];
      out.push(
        open === undefined
          ? { [key]: value }
          : { introduced: open, [key]: value },
      );
      open = undefined;
    } else if (event.limit !== undefined) out.push({ limit: event.limit });
  }
  if (open !== undefined) out.push({ introduced: open });
  return out.map((b) =>
    Object.fromEntries(Object.entries(b).map(([k, v]) => [k, v.slice(0, 200)])),
  );
}
function firstSeverity(value: unknown): string | undefined {
  return isRecord(value) ? str(value.severity)?.slice(0, 64) : undefined;
}

/** Maps one OSV record to one advisory. */
export function mapOsv(document: unknown): Mapped[] {
  const parsed = OsvRecord.safeParse(document);
  if (!parsed.success)
    return [
      {
        source_ref: isRecord(document) ? str(document.id) : undefined,
        issues: documentIssues(parsed.error),
        warnings: [],
      },
    ];
  const r = parsed.data;
  const warnings: string[] = [];
  if (r.withdrawn) warnings.push("Record was withdrawn at " + r.withdrawn);

  let cvss: { version: string; score?: number; vector: string } | undefined;
  for (const s of [
    ...(r.severity ?? []),
    ...(r.affected ?? []).flatMap((a) => a.severity ?? []),
  ]) {
    const version = CVSS[s.type];
    if (!version) continue;
    const vector = s.score.trim();
    const actual =
      version === "3.1" && vector.startsWith("CVSS:3.0/") ? "3.0" : version;
    const checked = parseCvssVector(actual, vector);
    if (!checked.ok) {
      warnings.push(s.type + " vector ignored: " + checked.message);
      continue;
    }
    const candidate = {
      version: actual,
      vector,
      ...(checked.score === null ? {} : { score: checked.score }),
    };
    if (!cvss || (candidate.score ?? -1) > (cvss.score ?? -1)) cvss = candidate;
  }

  const products = new Map<
    string,
    {
      vendor: string;
      product: string;
      purl?: string;
      versions: Record<string, string>[];
    }
  >();
  for (const a of r.affected ?? []) {
    if (!a.package) continue;
    const key = JSON.stringify([
      a.package.ecosystem,
      a.package.name,
      a.package.purl,
    ]);
    const entry = products.get(key) ?? {
      vendor: a.package.ecosystem.slice(0, 200),
      product: a.package.name.slice(0, 300),
      ...(a.package.purl ? { purl: a.package.purl } : {}),
      versions: [],
    };
    const ranges = (a.ranges ?? []).flatMap((range) => bounds(range.events));
    entry.versions.push(
      ...(ranges.length
        ? ranges
        : (a.versions ?? []).map((v) => ({ version: v.slice(0, 200) }))),
    );
    products.set(key, entry);
  }
  const affected = [...products.values()].slice(0, 1000).map((p) => {
    if (p.versions.length > 200)
      warnings.push("Versions of " + p.product + " truncated to 200");
    const { versions, ...rest } = p;
    return versions.length
      ? { ...rest, versions: versions.slice(0, 200) }
      : rest;
  });
  const vendorSeverity =
    firstSeverity(r.database_specific) ??
    (r.affected ?? [])
      .map(
        (a) =>
          firstSeverity(a.ecosystem_specific) ??
          firstSeverity(a.database_specific),
      )
      .find(Boolean);
  const cwes =
    isRecord(r.database_specific) && Array.isArray(r.database_specific.cwe_ids)
      ? r.database_specific.cwe_ids.filter(
          (c): c is string => typeof c === "string",
        )
      : [];
  const prefix = r.id.split("-")[0]!.toUpperCase();
  return [
    {
      source_ref: r.id,
      warnings,
      item: {
        type: "advisory",
        external_id: r.id,
        title: clip(
          r.summary?.trim() ||
            r.details?.trim().split("\n")[0]?.slice(0, 200) ||
            r.id,
          1000,
          "title",
          warnings,
        ),
        summary: clip(r.details, 65536, "summary", warnings),
        ...(vendorSeverity ? { vendor_severity: vendorSeverity } : {}),
        source: {
          name: "OSV",
          url: "https://osv.dev/vulnerability/" + encodeURIComponent(r.id),
          ...(DATABASES[prefix] ? { vendor: DATABASES[prefix] } : {}),
        },
        published_at: r.published ?? r.modified,
        updated_at: r.modified,
        cve_ids: [
          ...new Set(
            [r.id, ...(r.aliases ?? [])].filter((id) =>
              /^CVE-\d{4}-\d{4,}$/i.test(id),
            ),
          ),
        ],
        ...(cvss ? { cvss } : {}),
        affected_products: affected,
        references: httpLinks(
          (r.references ?? []).map((x) => ({ url: x.url, title: x.type })),
          warnings,
        ),
        tags: [
          ...new Set([
            ...[...products.values()].map((p) => "ecosystem:" + p.vendor),
            ...cwes,
            ...(r.withdrawn ? ["withdrawn"] : []),
          ]),
        ]
          .map((t) => t.slice(0, 100))
          .slice(0, 100),
        raw: document,
      },
    },
  ];
}
