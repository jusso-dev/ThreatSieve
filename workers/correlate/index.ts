import { Repository } from "../../packages/database/src/repository";
import { digest } from "../../packages/intel/src/normalise";
export async function correlate(repo: Repository, observableId: string) {
  const evidence = await repo.evidence(observableId);
  for (const ev of evidence) {
    const malware = ev.data.malwareEntityId;
    const report = ev.data.reportId;
    const certificate = ev.data.certificate;
    const signal =
      typeof report === "string"
        ? "report:" + ev.sourceId + ":" + report
        : typeof certificate === "string"
          ? "certificate:" + certificate
          : typeof malware === "string"
            ? "malware:" + malware
            : null;
    if (!signal) continue;
    const id = "cluster_" + (await digest(signal));
    const now = new Date().toISOString();
    const name =
      "Unknown Cluster TS-" +
      now.slice(0, 4) +
      "-" +
      id.slice(-6).toUpperCase();
    await repo.putEntity({
      id,
      type: "cluster",
      name,
      description:
        "An evidence-linked cluster. This is not a confirmed campaign or actor attribution.",
      aliases: [],
      data: { signal },
      provenance: ev.provenance,
    });
    await repo.db.batch([
      repo.db
        .prepare(
          "INSERT INTO threat_clusters(id,name,status,first_seen,last_seen,confidence) VALUES(?,?,'emerging',?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
        )
        .bind(id, name, ev.observedAt ?? now, now, ev.confidence * 0.7),
      repo.db
        .prepare("INSERT OR IGNORE INTO cluster_members VALUES(?,?,?)")
        .bind(id, observableId, ev.id),
      repo.db
        .prepare(
          "UPDATE threat_clusters SET observable_count=(SELECT COUNT(*) FROM cluster_members WHERE cluster_id=?) WHERE id=?",
        )
        .bind(id, id),
    ]);
  }
}
