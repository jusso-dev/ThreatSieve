import { z } from "zod";

/** POST /v1/lookup: bulk, deterministic reads over stored intelligence. */
export const LOOKUP_MAX_OBSERVABLES = 500;
export const LookupType = z.enum([
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "md5",
  "sha1",
  "sha256",
  "cve",
  "asn",
]);
export type LookupType = z.infer<typeof LookupType>;
export const LookupSection = z.enum([
  "reputation",
  "network",
  "cve",
  "relationships",
]);
export type LookupSection = z.infer<typeof LookupSection>;
export const LookupRequest = z.object({
  observables: z
    .array(
      z.object({
        type: LookupType,
        value: z.string().min(1).max(8192),
      }),
    )
    .min(1)
    .max(LOOKUP_MAX_OBSERVABLES),
  include: z
    .array(LookupSection)
    .min(1)
    .default(["reputation", "network", "cve", "relationships"]),
});
export type LookupRequest = z.input<typeof LookupRequest>;

const Iso = z.string();
export const LookupSourceSchema = z.object({
  source_id: z.string(),
  name: z.string(),
  license: z.string().nullable(),
  redistributable: z.boolean(),
  commercial_use: z.boolean().nullable(),
  reliability: z.number().min(0).max(1),
  first_seen: Iso.nullable(),
  last_seen: Iso.nullable(),
  retrieved_at: Iso.nullable(),
  source_url: z.string().nullable(),
});
export const ScannerSchema = z.object({
  is_scanner: z.boolean(),
  benign_service: z.boolean(),
  name: z.string().nullable(),
  source_id: z.string(),
});
export const ReputationSchema = z.object({
  classification: z.enum(["malicious", "suspicious", "benign", "unknown"]),
  score: z.number().int().min(0).max(100).nullable(),
  confidence: z.number().int().min(0).max(100).nullable(),
  scanner: ScannerSchema.nullable(),
  tags: z.array(z.string()),
});
export const NetworkSchema = z.object({
  asn: z.number().int().positive(),
  as_org: z.string().nullable(),
  prefix: z.string().nullable(),
  country: z.string().nullable(),
});
const Affected = z.object({
  vendor: z.string(),
  product: z.string(),
  versions: z.string().nullable(),
});
export const CveSectionSchema = z.object({
  id: z.string(),
  description: z.string().nullable(),
  published: Iso.nullable(),
  status: z.string().nullable(),
  cvss: z
    .object({
      version: z.string(),
      base_score: z.number(),
      vector: z.string().nullable(),
    })
    .nullable(),
  cwe: z.array(z.string()),
  kev: z
    .object({
      listed: z.boolean(),
      date_added: z.string().nullable(),
      due_date: z.string().nullable(),
      ransomware: z.string().nullable(),
    })
    .nullable(),
  epss: z
    .object({
      score: z.number().min(0).max(1),
      percentile: z.number().min(0).max(1),
      date: z.string(),
    })
    .nullable(),
  osv_ids: z.array(z.string()),
  affected: z.array(Affected),
  references: z.array(z.object({ url: z.string(), tags: z.array(z.string()) })),
});
export const LookupRelationshipSchema = z.object({
  id: z.string(),
  type: z.string(),
  direction: z.enum(["outgoing", "incoming"]),
  assertion: z.enum([
    "observed",
    "source_claimed",
    "analyst_confirmed",
    "model_inferred",
  ]),
  confidence: z.number().int().min(0).max(100),
  source_id: z.string(),
  target: z.object({
    id: z.string(),
    type: z.string(),
    name: z.string(),
    aliases: z.array(z.string()),
    external_ids: z.record(z.string(), z.string()),
  }),
});
export const LookupResultSchema = z.object({
  type: LookupType,
  value: z.string(),
  input: z.string(),
  found: z.boolean(),
  entity_id: z.string().nullable(),
  ttl_seconds: z.number().int().positive(),
  error: z.object({ code: z.string(), message: z.string() }).optional(),
  pending_sources: z.array(z.string()),
  reputation: ReputationSchema.nullable(),
  network: NetworkSchema.nullable(),
  cve: CveSectionSchema.nullable(),
  relationships: z.array(LookupRelationshipSchema),
  sources: z.array(LookupSourceSchema),
});
export const LookupResponseSchema = z.object({
  as_of: Iso,
  results: z.array(LookupResultSchema),
});
export type LookupSource = z.infer<typeof LookupSourceSchema>;
export type LookupResult = z.infer<typeof LookupResultSchema>;
export type LookupResponse = z.infer<typeof LookupResponseSchema>;
