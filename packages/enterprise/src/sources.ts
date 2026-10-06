import type { SourceReliability } from "../../scoring/src/index";
export const admiraltyWeights: Record<string, number> = {
  A: 0.95,
  B: 0.8,
  C: 0.65,
  D: 0.4,
  E: 0.2,
  F: 0.5,
};
/** Uncalibrated policy weights. F means reliability cannot be judged, not unreliability. */
export async function sourceReliabilities(db: D1Database, tenant: string) {
  const rows = await db
    .prepare(
      "SELECT s.id,s.independent_group,s.reliability,r.reliability AS rating FROM sources s LEFT JOIN source_ratings r ON r.tenant_id=? AND r.source_id=s.id",
    )
    .bind(tenant)
    .all<SourceReliability & { rating: string | null }>();
  return rows.results.map(({ rating, ...s }) => ({
    ...s,
    reliability: rating
      ? (admiraltyWeights[rating] ?? s.reliability)
      : s.reliability,
  }));
}
