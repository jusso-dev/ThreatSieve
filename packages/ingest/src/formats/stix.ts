import { z } from "zod";
import { normalizeValue } from "../../../intel/src/normalise";
import { tlpOf } from "../../../intel/src/taxii-sources";
import { refang } from "../normalise";
import { AppError } from "../../../observability/src/index";
import { INGEST_MAX_ITEMS, type IndicatorType, type TlpInput } from "../schema";
import {
  clip,
  documentIssues,
  httpLinks,
  isRecord,
  records,
  str,
  type Mapped,
} from "./common";

const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
export const StixBundle = z.looseObject({
  type: z.literal("bundle"),
  id: z.string().regex(new RegExp("^bundle--" + uuid + "$", "i")),
  objects: z
    .array(
      z.looseObject({
        type: z.string().regex(/^[a-z0-9-]{2,250}$/),
        id: z.string().max(300),
      }),
    )
    .max(10000),
});
const StixTimestamp = z.iso.datetime();
const Mappable = z.looseObject({
  id: z.string(),
  spec_version: z.literal("2.1").optional(),
  created: StixTimestamp,
  modified: StixTimestamp,
  name: z.string().optional(),
  description: z.string().optional(),
  confidence: z.number().int().min(0).max(100).optional(),
  labels: z.array(z.string()).optional(),
});

/** Objects that become ingest items; everything else is context. */
const ITEM_TYPES: Record<string, "alert" | "advisory"> = {
  indicator: "alert",
  sighting: "alert",
  incident: "alert",
  vulnerability: "advisory",
  report: "advisory",
};
const ORDER: TlpInput[] = ["clear", "green", "amber", "amber+strict", "red"];

// Only `object:path = 'literal'` comparisons are read. The pattern is matched
// as text and never evaluated.
const COMPARISON =
  /(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file):(value|hashes\.(?:'([^']+)'|([A-Za-z0-9-]+)))\s*=\s*'((?:[^'\\]|\\.)*)'/g;
const HASHES: Record<string, IndicatorType> = {
  MD5: "md5",
  "SHA-1": "sha1",
  SHA1: "sha1",
  "SHA-256": "sha256",
  SHA256: "sha256",
};
export function patternIndicators(pattern: string, warnings: string[]) {
  const found: { type: IndicatorType; value: string }[] = [];
  for (const m of pattern.slice(0, 65536).matchAll(COMPARISON)) {
    const value = m[5]!.replace(/\\(['\\])/g, "$1");
    let type: IndicatorType | undefined;
    if (m[1] === "file") {
      const algorithm = (m[3] ?? m[4] ?? "").toUpperCase();
      type = HASHES[algorithm];
      if (!type)
        warnings.push("Unsupported hash algorithm " + algorithm + " skipped");
    } else if (m[2] === "value")
      type = (
        {
          "ipv4-addr": value.includes("/") ? "cidr" : "ipv4",
          "ipv6-addr": value.includes("/") ? "cidr" : "ipv6",
          "domain-name": "domain",
          url: "url",
          "email-addr": "email",
        } as const
      )[m[1] as "url"];
    if (type) found.push({ type, value });
  }
  return found;
}

function validIndicator(type: IndicatorType, value: string) {
  try {
    normalizeValue(refang(value), type);
    return true;
  } catch {
    return false;
  }
}

/** Maps a STIX 2.1 bundle's indicators, sightings, incidents, vulnerabilities and reports. */
export function mapStix(document: unknown): Mapped[] {
  const parsed = StixBundle.safeParse(document);
  if (!parsed.success)
    return [{ issues: documentIssues(parsed.error), warnings: [] }];
  const objects = parsed.data.objects as Record<string, unknown>[];
  const byId = new Map(objects.map((o) => [String(o.id), o]));
  // Marking definitions declared in the bundle, in addition to the standard
  // TLP 1.0 and 2.0 definitions that tlpOf already knows.
  const localTlp = new Map<string, TlpInput>();
  for (const o of objects) {
    if (o.type !== "marking-definition") continue;
    const definition = isRecord(o.definition) ? o.definition : {};
    const label = (
      str(definition.tlp) ??
      str(o.name)?.replace(/^TLP:\s*/i, "") ??
      ""
    ).toLowerCase();
    if (o.definition_type === "tlp" || /^tlp:/i.test(String(o.name ?? "")))
      if (
        ["white", "clear", "green", "amber", "amber+strict", "red"].includes(
          label,
        )
      )
        localTlp.set(
          String(o.id),
          label === "white" ? "clear" : (label as TlpInput),
        );
  }
  // Fail before mapping so a bundle cannot spend CPU on items it will reject.
  if (
    objects.filter((o) => ITEM_TYPES[String(o.type)]).length > INGEST_MAX_ITEMS
  )
    throw new AppError(
      "TOO_MANY_ITEMS",
      413,
      "A request accepts at most " + INGEST_MAX_ITEMS + " items",
    );
  // Relationship endpoints indexed once instead of scanned per object.
  const neighbours = new Map<string, string[]>();
  for (const r of objects)
    if (r.type === "relationship")
      for (const [from, to] of [
        [r.source_ref, r.target_ref],
        [r.target_ref, r.source_ref],
      ]) {
        const list = neighbours.get(String(from)) ?? [];
        list.push(String(to));
        neighbours.set(String(from), list);
      }
  // Each referenced indicator's pattern is read and checked at most once.
  const patterns = new Map<
    string,
    {
      found: { type: IndicatorType; value: string; valid: boolean }[];
      warnings: string[];
    }
  >();
  const indicatorsOf = (source: Record<string, unknown>) => {
    const key = String(source.id);
    let entry = patterns.get(key);
    if (!entry) {
      const warnings: string[] = [];
      const found = patternIndicators(String(source.pattern), warnings).map(
        (f) => ({ ...f, valid: validIndicator(f.type, f.value) }),
      );
      entry = { found, warnings };
      patterns.set(key, entry);
    }
    return entry;
  };
  const mitreId = (o: Record<string, unknown> | undefined) =>
    records(o?.external_references).find(
      (r) =>
        r.source_name === "mitre-attack" &&
        /^T\d{4}(\.\d{3})?$/.test(String(r.external_id)),
    )?.external_id as string | undefined;
  const cveOf = (o: Record<string, unknown> | undefined) => [
    ...records(o?.external_references)
      .filter((r) => String(r.source_name).toLowerCase() === "cve")
      .map((r) => String(r.external_id)),
    ...(/^CVE-\d{4}-\d{4,}$/i.test(String(o?.name ?? ""))
      ? [String(o!.name)]
      : []),
  ];

  const out: Mapped[] = [];
  for (const object of objects) {
    const type = ITEM_TYPES[String(object.type)];
    if (!type) continue;
    const warnings: string[] = [];
    const source_ref = String(object.id);
    const valid = Mappable.safeParse(object);
    if (!valid.success) {
      out.push({ source_ref, issues: documentIssues(valid.error), warnings });
      continue;
    }
    const o = valid.data;
    // The most restrictive marking wins.
    let tlp: TlpInput | undefined;
    const standard = tlpOf(object);
    if (standard !== "unmarked") tlp = standard;
    for (const ref of Array.isArray(object.object_marking_refs)
      ? object.object_marking_refs
      : []) {
      const local = localTlp.get(String(ref));
      if (local && (!tlp || ORDER.indexOf(local) > ORDER.indexOf(tlp)))
        tlp = local;
    }
    const creator = byId.get(String(object.created_by_ref ?? ""));
    const linkedIds = new Set([
      ...(neighbours.get(o.id) ?? []),
      ...(Array.isArray(object.object_refs)
        ? object.object_refs.map(String)
        : []),
      ...(object.type === "sighting" ? [String(object.sighting_of_ref)] : []),
    ]);
    if (linkedIds.size > 1000)
      warnings.push("Only the first 1000 related objects were read");
    const linked = [...linkedIds]
      .slice(0, 1000)
      .map((id) => byId.get(id))
      .filter(isRecord);

    const indicators: {
      type: IndicatorType;
      value: string;
      confidence?: number;
    }[] = [];
    const indicatorObjects =
      object.type === "indicator"
        ? [object]
        : linked.filter((x) => x.type === "indicator");
    for (const source of indicatorObjects) {
      if (
        source.pattern_type !== "stix" ||
        typeof source.pattern !== "string"
      ) {
        warnings.push(
          "Indicator " +
            String(source.id) +
            " has a non-STIX pattern; not extracted",
        );
        continue;
      }
      const { found, warnings: notes } = indicatorsOf(source);
      warnings.push(...notes);
      if (!found.length)
        warnings.push(
          "No supported comparisons in pattern of " + String(source.id),
        );
      const confidence =
        typeof source.confidence === "number" ? source.confidence : undefined;
      for (const { valid, ...f } of found) {
        // A report or sighting is not rejected for a bad value in an indicator
        // it references; that indicator is reported on its own.
        if (source !== object && !valid) {
          warnings.push(
            "Invalid " + f.type + " from " + String(source.id) + " skipped",
          );
          continue;
        }
        indicators.push(confidence === undefined ? f : { ...f, confidence });
      }
    }
    const target =
      object.type === "sighting"
        ? byId.get(String(object.sighting_of_ref))
        : undefined;
    const severityKey = Object.keys(object).find((k) =>
      /^x_(?:[a-z0-9]+_)*severity$/.test(k),
    );
    const vendorSeverity = severityKey ? object[severityKey] : undefined;
    const title =
      o.name ??
      (target
        ? "Sighting of " + (str(target.name) ?? String(target.id))
        : undefined) ??
      String(object.type) + " " + o.id;
    out.push({
      source_ref,
      warnings,
      item: {
        type,
        external_id: o.id,
        title: clip(title, 1000, "title", warnings),
        summary: clip(o.description, 65536, "summary", warnings),
        ...(typeof vendorSeverity === "string" ||
        typeof vendorSeverity === "number"
          ? { vendor_severity: vendorSeverity }
          : {}),
        source: { name: str(creator?.name)?.slice(0, 200) ?? "STIX" },
        published_at: o.created,
        updated_at: o.modified,
        cve_ids: [
          ...new Set(
            [o, ...linked.filter((x) => x.type === "vulnerability")].flatMap(
              cveOf,
            ),
          ),
        ],
        indicators: indicators.slice(0, 1000),
        attack_techniques: [
          ...new Set(
            linked
              .filter((x) => x.type === "attack-pattern")
              .map(mitreId)
              .filter((x): x is string => !!x),
          ),
        ],
        references: httpLinks(
          records(object.external_references).map((r) => ({
            url: r.url,
            title: r.description ?? r.source_name,
          })),
          warnings,
        ),
        tags: [
          ...new Set(
            [
              ...(o.labels ?? []),
              ...(Array.isArray(object.indicator_types)
                ? object.indicator_types
                : []),
              ...(Array.isArray(object.report_types)
                ? object.report_types
                : []),
            ]
              .filter((t): t is string => typeof t === "string" && !!t.trim())
              .map((t) => t.slice(0, 100)),
          ),
        ].slice(0, 100),
        ...(tlp ? { tlp } : {}),
        raw: object,
      },
    });
  }
  return out;
}
