import {
  RecordSchema,
  type NormalizedIntelRecord,
  type IntelRelationship,
} from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
import { digest, normalise } from "./normalise";
export async function ingestRecord(
  repo: Repository,
  input: NormalizedIntelRecord,
  rawKey?: string,
) {
  const record = RecordSchema.parse(input);
  let id = record.entity?.id;
  if (record.entity) {
    // Keep one entity per CVE / ATT&CK ID: a re-keyed copy from another STIX
    // producer adds provenance and evidence without overwriting the original.
    const canonical = await repo.canonicalEntityId(record.entity);
    if (canonical && canonical !== record.entity.id) {
      id = canonical;
      await repo.attachSource(canonical, record.entity);
    } else await repo.putEntity(record.entity);
  }
  if (record.observable) {
    const observable = await normalise(
      record.observable.value,
      record.observable.type,
    );
    observable.firstSeen = record.observable.firstSeen;
    observable.lastSeen = record.observable.lastSeen;
    id = observable.id;
    await repo.putObservable(observable, record.provenance);
  }
  for (const evidence of record.evidence) {
    if (!id) throw new Error("Evidence requires an entity");
    await repo.putEvidence(id, {
      ...evidence,
      observableId: record.observable ? id : undefined,
      rawKey,
    });
    const malwareId = evidence.data.malwareEntityId;
    if (typeof malwareId === "string") {
      const now = new Date().toISOString();
      const relation: IntelRelationship = {
        id:
          "rel_" +
          (await digest(
            id + ":INDICATES:" + malwareId + ":" + record.provenance.sourceId,
          )),
        sourceEntityId: id,
        targetEntityId: malwareId,
        relationshipType: "INDICATES",
        assertionType: "source_claimed",
        confidence: evidence.confidence,
        sourceIds: [record.provenance.sourceId],
        provenance: record.provenance,
        createdAt: now,
        updatedAt: now,
      };
      await repo.putRelationship(relation);
    }
  }
  for (const r of record.relationships) await repo.putRelationship(r);
  return id;
}
