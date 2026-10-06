import type {
  Candidate,
  EvidenceBundle,
  IntelEntity,
  IntelRelationship,
} from "../../schemas/src/index";
import { EnvironmentSchema, EvidenceSchema } from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
import { canonicalJson, digest } from "../../intel/src/normalise";
import { AppError } from "../../observability/src/index";
export async function buildEvidenceBundle(
  repo: Repository,
  tenantId: string,
  observableId: string,
): Promise<EvidenceBundle> {
  if (!(await repo.visible(tenantId, observableId)))
    throw new AppError("NOT_FOUND", 404, "Observable not found");
  const observable = await repo.observable(observableId);
  if (!observable) throw new AppError("NOT_FOUND", 404, "Observable not found");
  const evidence = await repo.evidence(observableId, 101, tenantId);
  let truncated = evidence.length > 100;
  evidence.splice(100);
  const customer = await repo.db
    .prepare(
      "SELECT data FROM customer_observations WHERE tenant_id=? AND observable_id=? ORDER BY observed_at DESC LIMIT 30",
    )
    .bind(tenantId, observableId)
    .all<{ data: string }>();
  for (const row of customer.results)
    evidence.push(EvidenceSchema.parse(JSON.parse(row.data)));
  const relationships: IntelRelationship[] = [];
  const relatedEntities: IntelEntity[] = [];
  const seen = new Set([observableId]);
  const edgeIds = new Set<string>();
  let frontier = [observableId];
  const attackCandidates: Candidate[] = [];
  const actorCandidates: Candidate[] = [];
  for (let depth = 0; depth < 3 && frontier.length; depth++) {
    const next: string[] = [];
    for (const id of frontier.slice(0, 30)) {
      const edges = await repo.edges(id, 41, tenantId);
      if (edges.length > 40) truncated = true;
      for (const edge of edges.slice(0, 40)) {
        const target =
          edge.sourceEntityId === id
            ? edge.targetEntityId
            : edge.sourceEntityId;
        if (!(await repo.visible(tenantId, target))) continue;
        if (!edgeIds.has(edge.id)) {
          relationships.push(edge);
          edgeIds.add(edge.id);
        }
        if (seen.has(target)) continue;
        seen.add(target);
        const entity = await repo.entity(target);
        if (!entity) continue;
        relatedEntities.push(entity);
        if (
          entity.type === "malware" ||
          entity.type === "campaign" ||
          entity.type === "tool"
        )
          next.push(target);
        const dimensions = [
          depth === 0 ? "source_attribution" : "malware_overlap",
        ];
        const candidate: Candidate = {
          id: entity.id,
          name: entity.name,
          type: entity.type,
          externalId: entity.externalId,
          description: entity.description.slice(0, 2000),
          evidenceIds: evidence
            .filter(
              (e) =>
                e.behavioural || e.data.malwareEntityId === id || depth === 0,
            )
            .map((e) => e.id),
          dimensions,
          origin: "graph",
        };
        if (entity.type === "attack-technique" && attackCandidates.length < 20)
          attackCandidates.push(candidate);
        if (entity.type === "threat-actor" && actorCandidates.length < 10)
          actorCandidates.push(candidate);
      }
    }
    frontier = next;
  }
  const env = await repo.db
    .prepare("SELECT data FROM customer_environments WHERE tenant_id=?")
    .bind(tenantId)
    .first<{ data: string }>();
  const environment = EnvironmentSchema.parse(env ? JSON.parse(env.data) : {});
  const products = evidence.flatMap((e) =>
    typeof e.data.product === "string" ? [e.data.product.toLowerCase()] : [],
  );
  const assets = await repo.db
    .prepare(
      "SELECT product FROM customer_assets WHERE tenant_id=? AND internet_exposed=1 LIMIT 1000",
    )
    .bind(tenantId)
    .all<{ product: string }>();
  const customerContext = {
    environment,
    observed: customer.results.length > 0,
    exposedAssets: assets.results.filter((a) =>
      products.includes(a.product.toLowerCase()),
    ).length,
  };
  const material = {
    evidence: evidence.map((e) => ({
      ...e,
      createdAt: undefined,
      rawKey: undefined,
      provenance: { ...e.provenance, retrievedAt: undefined },
    })),
    relationships: relationships.map((r) => ({
      ...r,
      createdAt: undefined,
      updatedAt: undefined,
      provenance: { ...r.provenance, retrievedAt: undefined },
    })),
    attackCandidates,
    actorCandidates,
    customerContext,
    day: new Date().toISOString().slice(0, 10),
  };
  return {
    observable,
    evidence,
    relationships,
    attackCandidates,
    actorCandidates,
    relatedEntities,
    customerContext,
    evidenceVersion: await digest(canonicalJson(material)),
    truncated,
  };
}
export interface EmbeddingService {
  embed(text: string): Promise<number[]>;
}
export async function retrieveSemanticCandidates(
  repo: Repository,
  bundle: EvidenceBundle,
  index: VectorizeIndex,
  embeddings: EmbeddingService,
) {
  const text = bundle.evidence
    .filter((e) => e.behavioural)
    .map((e) => JSON.stringify(e.data))
    .join("\n")
    .slice(0, 6000);
  if (!text) return;
  const values = await embeddings.embed(text);
  const results = await index.query(values, {
    topK: 10,
    returnMetadata: "all",
    filter: { entityType: { $in: ["attack-technique", "threat-actor"] } },
  });
  for (const hit of results.matches) {
    const id = hit.metadata?.entityId;
    if (typeof id !== "string" || hit.score < 0.7) continue;
    const entity = await repo.entity(id);
    if (!entity) continue;
    const dest =
      entity.type === "attack-technique"
        ? bundle.attackCandidates
        : entity.type === "threat-actor"
          ? bundle.actorCandidates
          : null;
    if (!dest || dest.some((c) => c.id === id) || dest.length >= 20) continue;
    dest.push({
      id,
      name: entity.name,
      type: entity.type,
      externalId: entity.externalId,
      description: entity.description.slice(0, 2000),
      origin: "vector",
      evidenceIds: bundle.evidence
        .filter((e) => e.behavioural)
        .map((e) => e.id),
      dimensions: ["semantic_similarity"],
    });
  }
  bundle.evidenceVersion = await digest(
    bundle.evidenceVersion +
      canonicalJson({
        attack: bundle.attackCandidates,
        actors: bundle.actorCandidates,
      }),
  );
}
