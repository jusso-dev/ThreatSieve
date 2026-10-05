import type { IntelEntity } from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
export interface WeightedReference {
  id: string;
  weight: number;
  evidenceCount: number;
  sourceIds: string[];
}
export interface ThreatActorFingerprint {
  actorId: string;
  aliases: string[];
  techniques: WeightedReference[];
  malware: WeightedReference[];
  tools: WeightedReference[];
  campaigns: WeightedReference[];
  vulnerabilities: WeightedReference[];
  sectors: WeightedReference[];
  countries: WeightedReference[];
  infrastructureTraits: Record<string, unknown>;
  updatedAt: string;
  calibrated: false;
}
export async function fingerprint(
  repo: Repository,
  actor: IntelEntity,
): Promise<ThreatActorFingerprint> {
  const result: ThreatActorFingerprint = {
    actorId: actor.id,
    aliases: actor.aliases,
    techniques: [],
    malware: [],
    tools: [],
    campaigns: [],
    vulnerabilities: [],
    sectors: [],
    countries: [],
    infrastructureTraits: {},
    updatedAt: new Date().toISOString(),
    calibrated: false,
  };
  const edges = await repo.edges(actor.id, 500);
  const grouped = new Map<
    string,
    { confidence: number; sourceIds: Set<string>; count: number }
  >();
  for (const edge of edges) {
    const id =
      edge.sourceEntityId === actor.id
        ? edge.targetEntityId
        : edge.sourceEntityId;
    const value = grouped.get(id) ?? {
      confidence: 0,
      sourceIds: new Set<string>(),
      count: 0,
    };
    value.confidence += edge.confidence;
    value.count++;
    for (const sourceId of edge.sourceIds) value.sourceIds.add(sourceId);
    grouped.set(id, value);
  }
  for (const [id, value] of grouped) {
    const entity = await repo.entity(id);
    if (!entity) continue;
    const reference = {
      id,
      weight: Math.min(
        1,
        (value.confidence / value.count) * Math.log2(value.count + 1),
      ),
      evidenceCount: value.count,
      sourceIds: [...value.sourceIds],
    };
    switch (entity.type) {
      case "attack-technique":
        result.techniques.push(reference);
        break;
      case "malware":
        result.malware.push(reference);
        break;
      case "tool":
        result.tools.push(reference);
        break;
      case "campaign":
        result.campaigns.push(reference);
        break;
      case "vulnerability":
        result.vulnerabilities.push(reference);
        break;
      case "sector":
        result.sectors.push(reference);
        break;
      case "country":
        result.countries.push(reference);
        break;
    }
  }
  await repo.db
    .prepare("UPDATE threat_actors SET fingerprint=? WHERE entity_id=?")
    .bind(JSON.stringify(result), actor.id)
    .run();
  return result;
}
export interface AttributionEvidence {
  actorId: string;
  sourceAttribution: number;
  malwareSimilarity: number;
  techniqueSimilarity: number;
  infrastructureSimilarity: number;
  targetingSimilarity: number;
  temporalSimilarity: number;
  combinedConfidence: number;
  independentDimensions: number;
  calibrated: false;
}
export function attributionMatrix(
  actorId: string,
  dimensions: Record<string, number>,
): AttributionEvidence {
  const fields = {
    sourceAttribution: dimensions.source_attribution ?? 0,
    malwareSimilarity: dimensions.malware_overlap ?? 0,
    techniqueSimilarity: dimensions.ttp_overlap ?? 0,
    infrastructureSimilarity: dimensions.infrastructure_overlap ?? 0,
    targetingSimilarity: dimensions.targeting_overlap ?? 0,
    temporalSimilarity: dimensions.temporal_overlap ?? 0,
  };
  const values = Object.values(fields);
  const independentDimensions = values.filter((v) => v > 0.5).length;
  return {
    actorId,
    ...fields,
    combinedConfidence: Math.min(
      independentDimensions < 3 ? 0.69 : 0.95,
      values.reduce((a, b) => a + b, 0) / values.length,
    ),
    independentDimensions,
    calibrated: false,
  };
}
