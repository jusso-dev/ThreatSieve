import { z } from "zod";
import { AssessRequest, EntityType, Probability } from "./index";
const text = z.string().trim().max(200);
const list = z.array(text.min(1)).max(50).default([]);
export const WorkKind = z.enum([
  "requirement",
  "investigation",
  "watchlist",
  "collection",
  "report",
  "playbook",
]);
export type WorkKind = z.infer<typeof WorkKind>;
export const Priority = z.enum(["critical", "high", "medium", "low"]);
export const Reference = z.object({
  type: z.enum([
    "entity",
    "evidence",
    "assessment",
    "requirement",
    "investigation",
    "watchlist",
    "collection",
    "report",
  ]),
  id: z.string().min(1).max(200),
  relation: z
    .enum([
      "references",
      "supports",
      "contradicts",
      "satisfies",
      "member",
      "investigates",
    ])
    .default("references"),
});
export type Reference = z.infer<typeof Reference>;
export const MatchCriteria = z
  .object({
    entityTypes: z.array(EntityType).max(20).default([]),
    keywords: list,
    technologies: list,
    industries: list,
    countries: list,
    actors: list,
    techniques: list,
    tags: list,
    sourceIds: list,
    from: z.iso.datetime().optional(),
    to: z.iso.datetime().optional(),
    minConfidence: Probability.default(0),
  })
  .refine((v) => !v.from || !v.to || v.from <= v.to, {
    message: "End date must follow start date",
  });
export type MatchCriteria = z.infer<typeof MatchCriteria>;
export const Task = z.object({
  id: z.string().min(1).max(100),
  title: text.min(1),
  done: z.boolean().default(false),
  ownerId: z.string().max(200).optional(),
  dueAt: z.iso.datetime().optional(),
});
const common = {
  title: text.min(3),
  description: z.string().max(10000).default(""),
  priority: Priority.default("medium"),
  ownerId: z.string().max(200).optional(),
  collaborators: list,
  tags: list,
  references: z.array(Reference).max(100).default([]),
};
export const WorkInput = z.discriminatedUnion("kind", [
  z.object({
    ...common,
    kind: z.literal("requirement"),
    status: z.enum(["draft", "active", "review", "closed"]).default("active"),
    question: z.string().trim().min(3).max(2000),
    stakeholders: list,
    criteria: MatchCriteria.default(() => MatchCriteria.parse({})),
    collectionRequirements: list,
    gaps: list,
    lastReviewed: z.iso.datetime().optional(),
    nextReview: z.iso.datetime().optional(),
  }),
  z.object({
    ...common,
    kind: z.literal("investigation"),
    status: z
      .enum(["open", "in-progress", "waiting", "review", "closed"])
      .default("open"),
    hypothesis: z.string().max(10000).default(""),
    tasks: z.array(Task).max(100).default([]),
  }),
  z.object({
    ...common,
    kind: z.literal("watchlist"),
    status: z.enum(["active", "paused", "closed"]).default("active"),
    criteria: MatchCriteria.default(() => MatchCriteria.parse({})),
    triggers: z
      .array(
        z.enum([
          "evidence.created",
          "evidence.updated",
          "relationship.created",
          "score.changed",
          "sighting.created",
          "indicator.updated",
        ]),
      )
      .min(1)
      .default(["evidence.created", "evidence.updated", "sighting.created"]),
  }),
  z.object({
    ...common,
    kind: z.literal("collection"),
    status: z.enum(["draft", "published", "archived"]).default("draft"),
    criteria: MatchCriteria.default(() => MatchCriteria.parse({})),
    publication: z.enum(["private", "workspace", "taxii"]).default("workspace"),
  }),
  z.object({
    ...common,
    kind: z.literal("report"),
    status: z
      .enum(["draft", "review", "published", "archived"])
      .default("draft"),
    reportType: z
      .enum([
        "threat-brief",
        "actor-profile",
        "campaign-report",
        "ioc-package",
        "investigation-report",
        "executive-brief",
        "requirement-update",
      ])
      .default("threat-brief"),
    body: z.string().max(50000).default(""),
  }),
  z.object({
    ...common,
    kind: z.literal("playbook"),
    status: z.enum(["active", "paused"]).default("paused"),
    trigger: z.enum([
      "indicator.created",
      "indicator.updated",
      "score.changed",
      "sighting.created",
      "relationship.created",
      "feed.failed",
      "investigation.created",
      "watchlist.match",
      "requirement.match",
    ]),
    criteria: MatchCriteria.default(() => MatchCriteria.parse({})),
    actions: z
      .array(
        z.object({
          type: z.enum([
            "notify",
            "tag",
            "add-to-watchlist",
            "create-investigation",
            "enrich",
            "export",
            "send-webhook",
            "publish-taxii",
          ]),
          target: text.optional(),
        }),
      )
      .min(1)
      .max(5),
  }),
]);
export type WorkInput = z.infer<typeof WorkInput>;
export type WorkObject = WorkInput & {
  id: string;
  tenantId: string;
  ownerId: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};
export const WorkUpdate = z.object({
  expected_revision: z.number().int().positive(),
  object: WorkInput,
  reason: z.string().trim().min(3).max(2000),
});
export const NoteInput = z.object({
  type: z.enum(["note", "decision"]).default("note"),
  body: z.string().trim().min(1).max(10000),
  references: z.array(Reference).max(30).default([]),
});
export const SightingInput = z.object({
  observable: AssessRequest,
  observedAt: z.iso.datetime(),
  source: z.enum([
    "siem",
    "edr",
    "firewall",
    "dns",
    "proxy",
    "email-security",
    "analyst",
    "partner",
    "threat-feed",
    "honeypot",
    "customer-telemetry",
  ]),
  asset: text.default(""),
  environment: text.default(""),
  count: z.number().int().min(1).max(100000000).default(1),
  confidence: Probability.default(0.8),
  context: z.string().max(5000).default(""),
  externalId: text.min(1),
});
export type SightingInput = z.infer<typeof SightingInput>;
export interface Sighting extends SightingInput {
  id: string;
  observableId: string;
  createdAt: string;
  createdBy: string;
}
export interface IntelligenceEvent {
  id: string;
  subject_type: string;
  subject_id: string;
  event_type: string;
  actor_id: string;
  data: Record<string, unknown>;
  created_at: string;
}
export const SourceRating = z.object({
  reliability: z.enum(["A", "B", "C", "D", "E", "F"]),
  evidenceRating: z.number().int().min(1).max(6),
  rationale: z.string().trim().min(10).max(2000),
});
export const WorkObjectSchema = WorkInput.and(
  z.object({
    id: z.string(),
    tenantId: z.string(),
    ownerId: z.string(),
    revision: z.number().int().positive(),
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
    createdBy: z.string(),
  }),
);
