import { createHash } from "node:crypto";
import type { Assessment } from "../../schemas/src/index";
export type StixObject = Record<string, unknown> & { type: string; id: string };
export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}
export function stixId(type: string, key: string) {
  const bytes = createHash("sha1")
    .update(Buffer.from("00abedb4aa42466c9c01fed23315a9b7", "hex"))
    .update(key)
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6]! & 15) | 80;
  bytes[8] = (bytes[8]! & 63) | 128;
  const h = bytes.toString("hex");
  return (
    type +
    "--" +
    [
      h.slice(0, 8),
      h.slice(8, 12),
      h.slice(12, 16),
      h.slice(16, 20),
      h.slice(20),
    ].join("-")
  );
}
const escape = (v: string) => v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
export function indicatorPattern(a: Assessment): string | undefined {
  const value = escape(a.observable.normalizedValue);
  const paths: Record<string, string> = {
    domain: "domain-name:value",
    hostname: "domain-name:value",
    ipv4: "ipv4-addr:value",
    ipv6: "ipv6-addr:value",
    url: "url:value",
    email: "email-addr:value",
    md5: "file:hashes.'MD5'",
    sha1: "file:hashes.'SHA-1'",
    sha256: "file:hashes.'SHA-256'",
    mutex: "mutex:name",
    "registry-key": "windows-registry-key:key",
    file: "file:name",
    process: "process:command_line",
  };
  const path = paths[a.observable.type];
  return path ? `[${path} = '${value}']` : undefined;
}
export function exportStix(
  a: Assessment,
  options: { includeRestricted: boolean } = { includeRestricted: false },
): StixBundle {
  const now = a.created_at;
  const sources = a.sources.filter(
    (s) => options.includeRestricted || s.redistributable,
  );
  const allowed = new Set(sources.map((s) => s.sourceId));
  const evidence = a.evidence.filter((e) => allowed.has(e.sourceId));
  const permittedIds = new Set(evidence.map((e) => e.id));
  const base = {
    spec_version: "2.1",
    created: now,
    modified: now,
    confidence: Math.round(a.confidence * 100),
    x_threatsieve_assessment_id: a.assessment_id,
    x_threatsieve_demo: a.demo,
  };
  const objects: StixObject[] = [];
  const expression = indicatorPattern(a);
  const rootType = expression
    ? "indicator"
    : a.observable.type === "cve"
      ? "vulnerability"
      : "observed-data";
  const rootId = stixId(rootType, a.observable.id);
  const external_references = sources.map((s) => ({
    source_name: s.sourceName,
    description: "ThreatSieve source " + s.sourceId,
    ...(s.sourceUrl ? { url: s.sourceUrl } : {}),
    ...(s.sourceRecordId ? { external_id: s.sourceRecordId } : {}),
  }));
  if (expression)
    objects.push({
      type: "indicator",
      id: rootId,
      ...base,
      name: a.observable.normalizedValue,
      pattern_type: "stix",
      pattern_version: "2.1",
      pattern: expression,
      valid_from: now,
      indicator_types: [
        a.malicious.classification === "malicious"
          ? "malicious-activity"
          : "anomalous-activity",
      ],
      x_threatsieve_classification: a.malicious,
      external_references,
    });
  else if (a.observable.type === "cve")
    objects.push({
      type: "vulnerability",
      id: rootId,
      ...base,
      name: a.observable.normalizedValue,
      external_references: [
        { source_name: "cve", external_id: a.observable.normalizedValue },
        ...external_references,
      ],
    });
  else {
    const type =
      a.observable.type === "asn"
        ? "autonomous-system"
        : "x-threatsieve-observable";
    const scoId = stixId(type, a.observable.id);
    objects.push({
      type,
      id: scoId,
      spec_version: "2.1",
      ...(type === "autonomous-system"
        ? { number: Number(a.observable.normalizedValue.replace(/^AS/, "")) }
        : {
            x_observable_type: a.observable.type,
            x_value: a.observable.normalizedValue,
          }),
    });
    objects.push({
      type: "observed-data",
      id: rootId,
      ...base,
      first_observed: a.observable.firstSeen ?? now,
      last_observed: a.observable.lastSeen ?? now,
      number_observed: 1,
      object_refs: [scoId],
    });
  }
  for (const mapping of a.attack) {
    const ids = mapping.evidenceIds.filter((id) => permittedIds.has(id));
    if (!ids.length) continue;
    const id = stixId("attack-pattern", mapping.techniqueId);
    objects.push({
      type: "attack-pattern",
      id,
      ...base,
      name: mapping.techniqueId,
      external_references: [
        { source_name: "mitre-attack", external_id: mapping.techniqueId },
      ],
    });
    objects.push({
      type: "relationship",
      id: stixId("relationship", rootId + ":indicates:" + id),
      ...base,
      relationship_type: "indicates",
      source_ref: rootId,
      target_ref: id,
      confidence: Math.round(mapping.confidence * 100),
      x_threatsieve_assertion_type: mapping.mappingType,
      x_threatsieve_probability: mapping.probability,
      x_threatsieve_evidence_ids: ids,
    });
  }
  for (const malware of a.malware) {
    const support = evidence.filter(
      (e) => e.data.malwareEntityId === malware.id,
    );
    if (!support.length) continue;
    const id = stixId("malware", malware.id);
    objects.push({
      type: "malware",
      id,
      ...base,
      name: malware.name,
      is_family: true,
    });
    objects.push({
      type: "relationship",
      id: stixId("relationship", rootId + ":indicates:" + id),
      ...base,
      relationship_type: "indicates",
      source_ref: rootId,
      target_ref: id,
      confidence: Math.round(malware.confidence * 100),
      x_threatsieve_assertion_type: "source_claimed",
      x_threatsieve_evidence_ids: support.map((e) => e.id),
    });
  }
  objects.push({
    type: "note",
    id: stixId("note", a.assessment_id),
    ...base,
    abstract: "ThreatSieve evidence-backed assessment",
    content: JSON.stringify({
      classification: a.malicious,
      analyst_decision: a.analyst_decision,
      effective_classification: a.effective_classification,
      role: a.role,
      review: a.human_review,
      reason_codes: a.reason_codes,
      evidence,
      model: a.models,
      actor_associations: a.actors
        .filter((actor) => actor.evidenceIds.some((id) => permittedIds.has(id)))
        .map((actor) => ({
          ...actor,
          evidenceIds: actor.evidenceIds.filter((id) => permittedIds.has(id)),
        })),
      notice:
        "Actor associations and model-inferred mappings are not confirmed attribution.",
    }),
    object_refs: [rootId],
    x_threatsieve_assertion_type: "model_inferred",
  });
  return { type: "bundle", id: stixId("bundle", a.assessment_id), objects };
}
