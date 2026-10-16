import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
import { EvidenceSchema } from "../../packages/schemas/src/index";
import { freshness } from "../../packages/intel/src/freshness";
import type { Evidence } from "../../packages/schemas/src/index";

/**
 * Vocabulary: observed (the world) / retrieved (the source told us) / processed
 * (our pipeline wrote). Observation fields (first_seen, last_seen,
 * first_observed, last_observed) only ever hold evidence `observedAt` bounds.
 * Wall-clock processing time goes exclusively into `last_processed_at`.
 */
export type GroupingKind =
  "shared-malware" | "shared-report" | "shared-certificate";

export interface Grouping {
  kind: GroupingKind;
  key: string;
}

/**
 * Cluster confidence is recomputed from ALL member evidence records carrying
 * the cluster's grouping signal on every run — never frozen at the first
 * writer's value:
 *
 *   confidence = 0.7 * (sum(evidence confidence) / N)
 *
 * i.e. the evidence-weighted mean of member-evidence confidence (every evidence
 * record counts once, so corroboration from more records carries more weight),
 * scaled by a fixed 0.7 correlation haircut because a cluster is weaker
 * evidence than any single direct observation. N is the number of member
 * evidence records. The same formula is stated in each cluster's description.
 */
const CORRELATION_HAIRCUT = 0.7;

export function evidenceWeightedConfidence(confidences: number[]): number {
  if (!confidences.length) return 0;
  return (
    CORRELATION_HAIRCUT *
    (confidences.reduce((sum, c) => sum + c, 0) / confidences.length)
  );
}

/** The shared signal that groups evidence: shared report, certificate, or malware. */
export function groupingFor(ev: Evidence): Grouping | null {
  const malware = ev.data.malwareEntityId;
  const report = ev.data.reportId;
  const certificate = ev.data.certificate;
  return typeof report === "string"
    ? { kind: "shared-report", key: "report:" + ev.sourceId + ":" + report }
    : typeof certificate === "string"
      ? { kind: "shared-certificate", key: "certificate:" + certificate }
      : typeof malware === "string"
        ? { kind: "shared-malware", key: "malware:" + malware }
        : null;
}

/** Pinned rationale format: "<grouping kind> <key>; N evidence records from M sources". */
export function rationaleFor(
  grouping: Grouping,
  evidenceRecords: number,
  sources: number,
): string {
  return (
    grouping.kind +
    " " +
    grouping.key +
    "; " +
    evidenceRecords +
    " evidence records from " +
    sources +
    " sources"
  );
}

function clusterDescription(grouping: Grouping, rationale: string): string {
  const association =
    grouping.kind === "shared-malware"
      ? "Grouping reflects a shared malware association: the observables are linked to the same malware family. That is a shared association, NOT evidence of coordinated activity."
      : grouping.kind === "shared-report"
        ? "Grouping reflects co-mention in a single source report. That is a shared association, NOT evidence of coordinated activity."
        : "Grouping reflects a shared TLS certificate. That is a shared association, NOT evidence of coordinated activity.";
  return (
    "An evidence-linked cluster (" +
    rationale +
    "). This is not a confirmed campaign or actor attribution. " +
    association +
    " Correlation confidence is evidence-weighted: " +
    CORRELATION_HAIRCUT +
    " x the mean confidence of all member evidence records, recomputed on every correlation run."
  );
}

export async function correlate(repo: Repository, observableId: string) {
  const evidence = await repo.evidence(observableId);
  // Wall-clock processing time: the ONLY "now" in this module, written solely
  // to threat_clusters.last_processed_at.
  const now = new Date().toISOString();
  const clusters = new Map<
    string,
    Grouping & { fresh: Map<string, Evidence> }
  >();
  for (const ev of evidence) {
    const grouping = groupingFor(ev);
    if (!grouping) continue;
    const id = "cluster_" + (await digest(grouping.key));
    const entry = clusters.get(id) ?? { ...grouping, fresh: new Map() };
    entry.fresh.set(ev.id, ev);
    clusters.set(id, entry);
  }
  for (const [id, grouping] of clusters) {
    const { kind, key, fresh } = grouping;
    // Recompute aggregates from ALL member evidence records carrying this
    // grouping signal on every run (the current run's records are merged in
    // because their member rows are written below).
    const seen = new Map<string, Evidence>();
    const prior = await repo.db
      .prepare(
        "SELECT e.data FROM cluster_members m JOIN evidence e ON e.entity_id=m.observable_id WHERE m.cluster_id=?",
      )
      .bind(id)
      .all<{ data: string }>();
    for (const r of prior.results) {
      const ev = EvidenceSchema.parse(JSON.parse(r.data));
      if (groupingFor(ev)?.key === key) seen.set(ev.id, ev);
    }
    for (const [evId, ev] of fresh) seen.set(evId, ev);
    const members = [...seen.values()];
    // Observation bounds come from evidence observedAt only: unknown stays
    // unknown (null), never falling back to processing time.
    const observed = freshness(members, now);
    const firstObserved = observed.first_observed;
    const lastObserved = observed.last_observed;
    const confidence = evidenceWeightedConfidence(
      members.map((m) => m.confidence),
    );
    const sources = new Set(members.map((m) => m.sourceId)).size;
    const rationale = rationaleFor(grouping, members.length, sources);
    // Cluster name year derives from the earliest observation, not processing date.
    const name =
      "Unknown Cluster TS-" +
      (firstObserved?.slice(0, 4) ?? "UNKNOWN") +
      "-" +
      id.slice(-6).toUpperCase();
    await repo.putEntity({
      id,
      type: "cluster",
      name,
      description: clusterDescription(grouping, rationale),
      aliases: [],
      data: { signal: key, groupingKind: kind, rationale },
      provenance: members[0]!.provenance,
    });
    await repo.db.batch([
      repo.db
        .prepare(
          "INSERT INTO threat_clusters(id,name,status,first_seen,last_seen,confidence,observable_count,first_observed,last_observed,last_processed_at,grouping_key,rationale) VALUES(?,?,'emerging',?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, first_seen=excluded.first_seen, last_seen=excluded.last_seen, confidence=excluded.confidence, first_observed=excluded.first_observed, last_observed=excluded.last_observed, last_processed_at=excluded.last_processed_at, grouping_key=excluded.grouping_key, rationale=excluded.rationale",
        )
        .bind(
          id,
          name,
          firstObserved,
          lastObserved,
          confidence,
          0,
          firstObserved,
          lastObserved,
          now,
          key,
          rationale,
        ),
      ...[...fresh.values()].map((ev) =>
        repo.db
          .prepare("INSERT OR IGNORE INTO cluster_members VALUES(?,?,?)")
          .bind(id, observableId, ev.id),
      ),
      repo.db
        .prepare(
          "UPDATE threat_clusters SET observable_count=(SELECT COUNT(DISTINCT observable_id) FROM cluster_members WHERE cluster_id=?) WHERE id=?",
        )
        .bind(id, id),
    ]);
  }
}
