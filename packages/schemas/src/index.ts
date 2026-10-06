import { z } from "zod";

export const Probability = z.number().min(0).max(1);
export const ObservableType = z.enum([
  "ipv4",
  "ipv6",
  "cidr",
  "domain",
  "hostname",
  "url",
  "email",
  "sha256",
  "sha1",
  "md5",
  "cve",
  "ja3",
  "ja4",
  "certificate",
  "asn",
  "file",
  "process",
  "registry-key",
  "user-agent",
  "mutex",
]);
export type ObservableType = z.infer<typeof ObservableType>;
export const Provenance = z.object({
  sourceId: z.string().min(1),
  sourceName: z.string().min(1),
  sourceUrl: z.url().optional(),
  sourceRecordId: z.string().optional(),
  retrievedAt: z.iso.datetime(),
  publishedAt: z.string().optional(),
  sourceConfidence: Probability.optional(),
  license: z.string().optional(),
  redistributable: z.boolean().default(false),
});
export type SourceProvenance = z.infer<typeof Provenance>;
export const ObservableSchema = z.object({
  id: z.string(),
  type: ObservableType,
  value: z.string(),
  normalizedValue: z.string(),
  firstSeen: z.string().optional(),
  lastSeen: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Observable = z.infer<typeof ObservableSchema>;
export const EntityType = z.enum([
  "observable",
  "threat-actor",
  "malware",
  "tool",
  "campaign",
  "attack-technique",
  "attack-tactic",
  "vulnerability",
  "infrastructure",
  "organization",
  "sector",
  "country",
  "security-product",
  "intrusion-set",
  "course-of-action",
  "report",
  "cluster",
]);
export type EntityType = z.infer<typeof EntityType>;
export const Assertion = z.enum([
  "observed",
  "source_claimed",
  "analyst_confirmed",
  "model_inferred",
]);
export const EntitySchema = z.object({
  id: z.string(),
  type: EntityType,
  name: z.string().max(4096),
  description: z.string().max(100000).default(""),
  aliases: z.array(z.string()).default([]),
  externalId: z.string().optional(),
  data: z.record(z.string(), z.unknown()).default({}),
  provenance: Provenance,
});
export type IntelEntity = z.infer<typeof EntitySchema>;
export const RelationshipSchema = z.object({
  id: z.string(),
  sourceEntityId: z.string(),
  targetEntityId: z.string(),
  relationshipType: z.string().min(1).max(100),
  evidenceIds: z.array(z.string()).max(100).optional(),
  analystStatus: z.enum(["unreviewed", "confirmed", "rejected"]).optional(),
  assertionType: Assertion,
  confidence: Probability,
  sourceIds: z.array(z.string()).min(1),
  provenance: Provenance,
  firstSeen: z.string().optional(),
  lastSeen: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type IntelRelationship = z.infer<typeof RelationshipSchema>;
export const EvidenceSchema = z.object({
  id: z.string(),
  observableId: z.string().optional(),
  type: z.enum([
    "feed",
    "dns",
    "asn",
    "rdap",
    "certificate",
    "malware",
    "sandbox",
    "telemetry",
    "threat-report",
    "attack",
    "analyst",
    "customer",
    "correlation",
  ]),
  data: z.record(z.string(), z.unknown()),
  sourceId: z.string(),
  provenance: Provenance,
  observedAt: z.string().optional(),
  confidence: Probability,
  createdAt: z.string(),
  behavioural: z.boolean().default(false),
  rawKey: z.string().optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;
export const RecordSchema = z
  .object({
    entity: EntitySchema.optional(),
    observable: z
      .object({
        type: ObservableType.optional(),
        value: z.string().max(8192),
        firstSeen: z.string().optional(),
        lastSeen: z.string().optional(),
      })
      .optional(),
    relationships: z.array(RelationshipSchema).default([]),
    evidence: z.array(EvidenceSchema).default([]),
    provenance: Provenance,
  })
  .refine(
    (r) => r.entity || r.observable || r.relationships.length > 0,
    "Record must contain intelligence",
  );
export type NormalizedIntelRecord = z.infer<typeof RecordSchema>;
export const Stage = z.enum([
  "operations",
  "ingest",
  "normalise",
  "enrich",
  "correlate",
  "classify",
  "export",
  "feed-sync",
  "bulk",
]);
export const JobSchema = z.object({
  jobId: z.string(),
  tenantId: z.string().optional(),
  entityId: z.string(),
  stage: Stage,
  attempt: z.number().int().min(0),
  createdAt: z.string(),
  correlationId: z.string(),
  payload: z.record(z.string(), z.unknown()).default({}),
});
export type PipelineJob = z.infer<typeof JobSchema>;
export const CandidateSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: EntityType,
  externalId: z.string().optional(),
  description: z.string(),
  evidenceIds: z.array(z.string()),
  dimensions: z.array(z.string()),
  origin: z.enum(["graph", "vector", "source", "confirmed"]),
});
export type Candidate = z.infer<typeof CandidateSchema>;
export const EnvironmentSchema = z.object({
  technologies: z.array(z.string().max(100)).max(200).default([]),
  vendors: z.array(z.string()).max(100).default([]),
  products: z.array(z.string()).max(200).default([]),
  cloudProviders: z.array(z.string()).max(50).default([]),
  operatingSystems: z.array(z.string()).max(50).default([]),
  industries: z.array(z.string()).max(50).default([]),
  countries: z.array(z.string()).max(100).default([]),
  regions: z.array(z.string().max(200)).max(100).default([]),
  brands: z.array(z.string().max(200)).max(100).default([]),
  domains: z.array(z.string().max(200)).max(100).default([]),
  subsidiaries: z.array(z.string().max(200)).max(100).default([]),
  criticalAssets: z.array(z.string().max(200)).max(100).default([]),
  software: z.array(z.string().max(200)).max(100).default([]),
  identityProviders: z.array(z.string().max(200)).max(100).default([]),
  securityProducts: z.array(z.string().max(200)).max(100).default([]),
  vips: z.array(z.string().max(200)).max(100).default([]),
  exposedServices: z.array(z.string().max(200)).max(100).default([]),
});
export type CustomerEnvironment = z.infer<typeof EnvironmentSchema>;
export interface EvidenceBundle {
  observable: Observable;
  evidence: Evidence[];
  relationships: IntelRelationship[];
  attackCandidates: Candidate[];
  actorCandidates: Candidate[];
  relatedEntities: IntelEntity[];
  customerContext: {
    environment: CustomerEnvironment;
    observed: boolean;
    exposedAssets: number;
  };
  evidenceVersion: string;
  truncated: boolean;
}
export const reasonCodes = [
  "MULTI_SOURCE_CONFIRMATION",
  "KNOWN_C2",
  "KNOWN_MALWARE_HASH",
  "KNOWN_PHISHING_URL",
  "KNOWN_SCANNER",
  "KNOWN_BENIGN_INFRASTRUCTURE",
  "MALWARE_RELATIONSHIP",
  "CAMPAIGN_RELATIONSHIP",
  "ATTACK_BEHAVIOUR_MATCH",
  "ACTOR_TTP_SIMILARITY",
  "ACTOR_MALWARE_SIMILARITY",
  "ACTOR_INFRASTRUCTURE_SIMILARITY",
  "CISA_KEV",
  "CUSTOMER_TECH_MATCH",
  "CUSTOMER_OBSERVED",
  "CUSTOMER_ASSET_EXPOSED",
  "STALE_INTELLIGENCE",
  "SINGLE_SOURCE_ONLY",
  "CONFLICTING_SOURCES",
  "LOW_EVIDENCE",
  "SHARED_INFRASTRUCTURE",
] as const;
export type ReasonCode = (typeof reasonCodes)[number];
export interface ConfidenceFactor {
  code: ReasonCode;
  value: number;
  weight: number;
  evidenceIds: string[];
}
export const Role = z.enum([
  "c2",
  "payload",
  "phishing",
  "scanning",
  "exploit",
  "staging",
  "exfiltration",
  "benign",
  "unknown",
]);
export type ThreatRole = z.infer<typeof Role>;
export interface AttackMapping {
  techniqueId: string;
  entityId: string;
  probability: number;
  confidence: number;
  evidenceIds: string[];
  mappingType: "source_claimed" | "analyst_confirmed" | "model_inferred";
  status: "accepted" | "probable" | "weak";
  modelVersion?: string;
}
export interface ActorAssessment {
  id: string;
  name: string;
  association_probability: number;
  evidenceIds: string[];
  assertion_type: "model_inferred";
  dimensions: string[];
  strongAttribution: boolean;
}
export interface RelevanceAssessment {
  relevance: number;
  priority: "critical" | "high" | "medium" | "low";
  reasons: ReasonCode[];
  exposedAssets: number;
  observed: boolean;
}
export interface ClassificationRun {
  id: string;
  model: string;
  modelVersion?: string;
  schemaVersion: string;
  questionSetVersion: string;
  timestamp: string;
  evidenceVersion: string;
  candidateSet: Candidate[];
  raw: unknown;
  inputTokens: number;
  durationMs: number;
}
export interface Assessment {
  revision?: number;
  updated_at?: string;
  effective_role?: ThreatRole;
  effective_attack?: string[];
  effective_actors?: string[];
  analyst_decision?: {
    field: string;
    value: unknown;
    reason: string;
    analystId: string;
    createdAt: string;
  };
  effective_classification?: "malicious" | "suspicious" | "benign" | "unknown";
  schema_version: "1.0";
  assessment_id: string;
  observable: Observable;
  malicious: {
    probability: number;
    classification: "malicious" | "suspicious" | "benign" | "unknown";
  };
  role: { value: ThreatRole; probability: number };
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: number;
  confidence_factors: ConfidenceFactor[];
  attack: AttackMapping[];
  actors: ActorAssessment[];
  malware: { id: string; name: string; confidence: number }[];
  customer: RelevanceAssessment;
  recommended_actions: {
    action:
      | "block"
      | "monitor"
      | "hunt"
      | "investigate"
      | "isolate"
      | "patch"
      | "enrich"
      | "ignore";
    confidence: number;
    reason_codes: ReasonCode[];
  }[];
  human_review: boolean;
  human_review_probability: number;
  evidence: Evidence[];
  sources: SourceProvenance[];
  reason_codes: ReasonCode[];
  models: {
    classifier: string;
    schema_version: string;
    question_set_version: string;
  };
  runs: ClassificationRun[];
  evidence_version: string;
  created_at: string;
  status:
    "pending" | "confirmed" | "rejected" | "modified" | "needs-investigation";
  demo: boolean;
}
export const AssessRequest = z.object({
  observable: z.string().trim().min(1).max(8192),
  type: ObservableType.optional(),
});
export const BulkRequest = z.object({
  observables: z
    .array(z.union([z.string().min(1).max(8192), AssessRequest]))
    .min(1)
    .max(100000),
});
export const FeedbackRequest = z.object({
  expected_revision: z.number().int().nonnegative().optional(),
  field: z
    .enum(["assessment", "malicious", "role", "attack", "actors"])
    .default("assessment"),
  value: z.unknown().optional(),
  reason: z.string().trim().min(3).max(2000),
});
export const Scopes = z.enum([
  "intel:read",
  "assessment:read",
  "assessment:write",
  "feeds:read",
  "feeds:write",
  "admin",
]);
export type Scope = z.infer<typeof Scopes>;
export interface Principal {
  tenantId: string;
  userId: string;
  keyId: string;
  scopes: Scope[];
  kind: "key" | "session";
}
export interface FeedHealth {
  status: "healthy" | "error" | "disabled";
  message?: string;
  checkedAt: string;
}
export interface FeedBatch {
  more?: boolean;
  records: unknown[];
  cursor: string;
  raw: unknown;
}
export interface ThreatFeedProvider {
  id: string;
  name: string;
  type: "stix" | "json" | "csv" | "text" | "misp" | "taxii";
  healthCheck(): Promise<FeedHealth>;
  fetch(cursor?: string): Promise<FeedBatch>;
  normalize(raw: unknown): Promise<NormalizedIntelRecord[]>;
  getCheckpoint(): Promise<string | null>;
  setCheckpoint(checkpoint: string): Promise<void>;
}
