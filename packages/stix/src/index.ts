import { createHash } from "node:crypto";
import type { Assessment } from "../../schemas/src/index";
import {
  publicationState,
  publishableClaims,
  type PublicationAudience,
  type PublicationState,
} from "./policy";
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
  const path =
    a.observable.type === "cidr"
      ? value.includes(":")
        ? "ipv6-addr:value"
        : "ipv4-addr:value"
      : paths[a.observable.type];
  return path ? `[${path} = '${value}']` : undefined;
}
export function exportStix(
  a: Assessment,
  options: { includeRestricted?: boolean; audience: PublicationAudience },
): StixBundle {
  const operational = options.audience === "operational";
  // One publication authority: packages/stix/src/policy.ts decides what may be
  // published; this function only renders the verdict.
  const state: PublicationState = {
    ...publicationState(a),
    audience: options.audience,
  };
  const now = a.updated_at ?? a.created_at;
  const classification =
    a.effective_classification ?? a.malicious.classification;
  const decision = a.effective_classification
    ? { classification, assertion_type: "analyst_confirmed" }
    : { ...a.malicious, assertion_type: "model_inferred" };
  const effectiveRole = a.effective_role
    ? { value: a.effective_role, assertion_type: "analyst_confirmed" }
    : a.role;
  const sources = a.sources.filter(
    (s) => options.includeRestricted || s.redistributable,
  );
  const allowed = new Set(sources.map((s) => s.sourceId));
  const evidence = a.evidence.filter(
    (e) =>
      allowed.has(e.sourceId) &&
      (options.includeRestricted || e.provenance.redistributable === true),
  );
  const permittedIds = new Set(evidence.map((e) => e.id));
  // Derived-data rights and revocation are decided by the policy in
  // publishableClaims: operational exports publish a claim only when the
  // policy permits it. Research exports keep today's full behavior.
  const rights = operational ? publishableClaims(a) : null;
  const claimClassification = !operational || (rights?.classification ?? false);
  const claimRole = !operational || (rights?.role ?? false);
  const indicatorType =
    classification === "malicious" &&
    claimClassification &&
    (!operational || state.eligible)
      ? "malicious-activity"
      : classification === "benign"
        ? "benign"
        : "anomalous-activity";
  const base = {
    spec_version: "2.1",
    created: a.created_at,
    modified: now,
    confidence: Math.round(a.confidence * 100),
    x_threatsieve_assessment_id: a.assessment_id,
    x_threatsieve_revision: a.revision ?? 0,
    x_threatsieve_demo: a.demo,
  };
  const objects: StixObject[] = [];
  // Export marking: every root object carries the publication state; only an
  // operational export of an eligible assessment may claim operational use.
  const marking = {
    x_threatsieve_publication_state: state,
    ...(operational
      ? {
          x_threatsieve_approved_for_operational_use:
            state.eligible && !state.revoked,
          revoked: state.revoked,
        }
      : {}),
  };
  const validity =
    operational && state.valid_until ? { valid_until: state.valid_until } : {};
  const keptAttack = new Set<string>();
  const keptActors = new Set<string>();
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
      indicator_types: [indicatorType],
      ...(claimClassification
        ? { x_threatsieve_classification: decision }
        : {}),
      // Model history is research material; operational exports carry only
      // the publication verdict and retained claims.
      ...(operational ? {} : { x_threatsieve_model_classification: a.malicious }),
      external_references,
      ...marking,
      ...validity,
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
      ...marking,
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
      ...marking,
    });
  }
  for (const mapping of a.attack.filter(
    (m) => !a.effective_attack || a.effective_attack.includes(m.techniqueId),
  )) {
    const ids = operational
      ? (rights?.attack.get(mapping.techniqueId) ?? [])
      : mapping.evidenceIds.filter((id) => permittedIds.has(id));
    if (!ids.length) continue;
    keptAttack.add(mapping.techniqueId);
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
    const ids = operational
      ? (rights?.malware.get(malware.id) ?? [])
      : evidence
          .filter((e) => e.data.malwareEntityId === malware.id)
          .map((e) => e.id);
    if (!ids.length) continue;
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
      x_threatsieve_evidence_ids: ids,
    });
  }
  const actorAssociations = a.actors
    .filter(
      (actor) =>
        (!a.effective_actors || a.effective_actors.includes(actor.id)) &&
        (operational
          ? rights?.actors.has(actor.id) ?? false
          : actor.evidenceIds.some((id) => permittedIds.has(id))),
    )
    .map((actor) => {
      keptActors.add(actor.id);
      return {
        ...actor,
        evidenceIds: operational
          ? (rights?.actors.get(actor.id) ?? [])
          : actor.evidenceIds.filter((id) => permittedIds.has(id)),
      };
    });
  // Analyst selections may not resurrect claims the policy dropped.
  const retained = (ids: string[] | undefined, kept: Set<string>) =>
    operational ? (ids?.filter((id) => kept.has(id)) ?? undefined) : ids;
  objects.push({
    type: "note",
    id: stixId("note", a.assessment_id),
    ...base,
    abstract: "ThreatSieve evidence-backed assessment",
    content: JSON.stringify({
      ...(claimClassification ? { classification: decision } : {}),
      analyst_decision: options.includeRestricted
        ? a.analyst_decision
        : a.analyst_decision && {
            field: a.analyst_decision.field,
            value: a.analyst_decision.value,
            createdAt: a.analyst_decision.createdAt,
          },
      effective_classification: a.effective_classification,
      ...(claimRole ? { role: effectiveRole } : {}),
      analyst_attack_selections: retained(
        a.effective_attack,
        keptAttack,
      ),
      analyst_actor_selections: retained(
        a.effective_actors,
        keptActors,
      ),
      reason_codes: a.reason_codes,
      evidence,
      // Model history and the raw review flag are research material; the
      // operational verdict is carried in x_threatsieve_publication_state.
      ...(operational ? {} : { review: a.human_review, model: a.models }),
      actor_associations: actorAssociations,
      notice:
        "Actor associations and model-inferred mappings are not confirmed attribution.",
    }),
    object_refs: [rootId],
    x_threatsieve_assertion_type: "model_inferred",
  });
  return {
    type: "bundle",
    id: stixId("bundle", a.assessment_id + ":" + (a.revision ?? 0)),
    objects,
  };
}
