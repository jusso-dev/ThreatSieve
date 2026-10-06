import { z } from "zod";
import { EntityType, ObservableType } from "./index";

export const AssessmentFilters = z.object({
  view: z.enum(["all", "attention", "review"]).default("all"),
  q: z.string().trim().max(256).default(""),
  severity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional(),
  classification: z
    .enum(["malicious", "suspicious", "benign", "unknown"])
    .optional(),
  observable_type: ObservableType.optional(),
  status: z
    .enum([
      "pending",
      "confirmed",
      "rejected",
      "modified",
      "needs-investigation",
    ])
    .optional(),
  min_confidence: z.coerce.number().min(0).max(1).optional(),
  observed: z.enum(["yes", "no"]).optional(),
  sort: z
    .enum(["newest", "oldest", "confidence", "relevance"])
    .default("newest"),
});
export type AssessmentFilters = z.infer<typeof AssessmentFilters>;
export const EntityFilters = z.object({
  q: z.string().trim().max(256).default(""),
  type: EntityType.optional(),
  source: z.string().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: z.string().max(2000).optional(),
});
export type EntityFilters = z.infer<typeof EntityFilters>;
export const SavedViewInput = z.object({
  name: z.string().trim().min(1).max(60),
  filters: AssessmentFilters,
});
