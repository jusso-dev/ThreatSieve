import { z } from "zod";

/** Request limits. Every value from the payload is untrusted. */
export const INGEST_MAX_BODY_BYTES = 5 * 1024 * 1024;
export const INGEST_MAX_ITEMS = 500;
/** Larger originals are kept in R2 and fetched on read. */
export const INGEST_INLINE_RAW_BYTES = 256 * 1024;

export const IngestFormat = z.enum(["native", "stix", "csaf", "osv"]);
export type IngestFormat = z.infer<typeof IngestFormat>;
export const IngestType = z.enum(["alert", "advisory"]);
export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;
/** TLP 2.0 labels; `white` is the TLP 1.0 name for `clear`. */
export const TlpInput = z.enum([
  "clear",
  "white",
  "green",
  "amber",
  "amber+strict",
  "red",
]);
export type TlpInput = z.infer<typeof TlpInput>;
export const Tlp = TlpInput.exclude(["white"]);
export type Tlp = z.infer<typeof Tlp>;
export const IndicatorType = z.enum([
  "ipv4",
  "ipv6",
  "cidr",
  "domain",
  "url",
  "email",
  "md5",
  "sha1",
  "sha256",
]);
export type IndicatorType = z.infer<typeof IndicatorType>;

const httpUrl = z.url({ protocol: /^https?$/ }).max(2048);
const timestamp = z.iso.datetime({ offset: true });
const text = (max: number) => z.string().min(1).max(max);
const versionText = z.string().min(1).max(200);

export const CvssInput = z
  .strictObject({
    version: z.enum(["2.0", "3.0", "3.1", "4.0"]),
    score: z.number().min(0).max(10).optional(),
    vector: z.string().min(1).max(512).optional(),
  })
  .refine((v) => v.score !== undefined || v.vector !== undefined, {
    message: "Provide a score, a vector, or both",
  });
export const VersionRange = z
  .strictObject({
    version: versionText.optional(),
    introduced: versionText.optional(),
    fixed: versionText.optional(),
    last_affected: versionText.optional(),
    limit: versionText.optional(),
    /** A free-form range expression such as `vers:npm/>=1.0.0|<1.2.3`. */
    range: z.string().min(1).max(500).optional(),
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), {
    message: "A version range needs at least one bound",
  });
export const AffectedProduct = z.strictObject({
  vendor: text(200).optional(),
  product: text(300),
  versions: z.array(VersionRange).max(200).optional(),
  cpe: z
    .string()
    .max(500)
    .regex(
      /^cpe:(?:2\.3:[aho*-]:|\/[aho]:)\S*$/,
      "Expected a CPE 2.2 or 2.3 name",
    )
    .optional(),
  purl: z
    .string()
    .max(1000)
    .regex(/^pkg:[A-Za-z.+-][A-Za-z0-9.+-]*\/\S+$/, "Expected a package URL")
    .optional(),
});
export const IndicatorInput = z.strictObject({
  type: IndicatorType,
  value: text(8192),
  confidence: z.number().int().min(0).max(100).optional(),
});

/**
 * The native ingest item. Every other format is mapped into this shape and
 * validated against it, so this schema is the single strict contract.
 */
export const NativeItem = z.strictObject({
  type: IngestType,
  /** Producer's identifier; with `source.name` it is the deduplication key. */
  external_id: text(256).optional(),
  title: text(1000),
  summary: z.string().max(65536).optional(),
  severity: Severity.optional(),
  /** The producer's own severity, kept verbatim and mapped onto `severity`. */
  vendor_severity: z
    .union([z.string().min(1).max(64), z.number().min(0).max(10)])
    .optional(),
  source: z.strictObject({
    name: text(200),
    url: httpUrl.optional(),
    vendor: text(200).optional(),
  }),
  published_at: timestamp.optional(),
  updated_at: timestamp.optional(),
  cve_ids: z
    .array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i, "Expected CVE-YYYY-NNNN"))
    .max(500)
    .optional(),
  cvss: CvssInput.optional(),
  affected_products: z.array(AffectedProduct).max(1000).optional(),
  indicators: z.array(IndicatorInput).max(1000).optional(),
  attack_techniques: z
    .array(
      z
        .string()
        .regex(/^T\d{4}(?:\.\d{3})?$/i, "Expected an ATT&CK technique ID"),
    )
    .max(200)
    .optional(),
  references: z
    .array(z.strictObject({ url: httpUrl, title: text(500).optional() }))
    .max(200)
    .optional(),
  tags: z.array(text(100)).max(100).optional(),
  tlp: TlpInput.optional(),
  /** The original payload, stored as received and never interpreted. */
  raw: z.unknown().optional(),
});
export type NativeItem = z.infer<typeof NativeItem>;

/** `application/json` batch wrapper; `items` holds documents of `format`. */
export const IngestEnvelope = z.strictObject({
  format: IngestFormat.default("native"),
  /** Applied only to items that carry no TLP marking of their own. */
  default_tlp: TlpInput.optional(),
  items: z.array(z.unknown()).min(1).max(INGEST_MAX_ITEMS),
});

export interface NormalisedIndicator {
  type: IndicatorType;
  value: string;
  /** Defanged for display; never a clickable or resolvable form. */
  display_value: string;
  confidence?: number;
}
export interface NormalisedItem {
  type: z.infer<typeof IngestType>;
  format: IngestFormat;
  external_id: string;
  external_id_source: "provided" | "derived";
  title: string;
  summary: string | null;
  severity: Severity;
  severity_source: "provided" | "vendor" | "cvss" | "default";
  vendor_severity: string | number | null;
  source: { name: string; url: string | null; vendor: string | null };
  published_at: string | null;
  updated_at: string | null;
  cve_ids: string[];
  cvss: { version: string; score: number | null; vector: string | null } | null;
  affected_products: z.infer<typeof AffectedProduct>[];
  indicators: NormalisedIndicator[];
  attack_techniques: string[];
  references: { url: string; title?: string }[];
  tags: string[];
  tlp: Tlp;
  tlp_source: "provided" | "default";
}
export interface Normalisation {
  changes: { path: (string | number)[]; from: unknown; to: unknown }[];
  warnings: string[];
}
export interface ItemIssue {
  path: (string | number)[];
  message: string;
}
