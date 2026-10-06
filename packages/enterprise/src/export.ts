import {
  stixId,
  exportStix,
  type StixObject,
  type StixBundle,
} from "../../stix/src/index";
import type { IntelEntity } from "../../schemas/src/index";
import type { WorkObject } from "../../schemas/src/enterprise";
import { OperationsRepository } from "./repository";
export const escapeHtml = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
export function csvCell(value: string) {
  const safe = /^(?:\s*[=+\-@]|[\t\r\n])/.test(value) ? "'" + value : value;
  return '"' + safe.replaceAll('"', '""') + '"';
}
export function entityStix(
  entity: IntelEntity,
  created: string,
): StixObject | null {
  if (!entity.provenance.redistributable) return null;
  const map: Record<string, string> = {
    "threat-actor": "threat-actor",
    "intrusion-set": "intrusion-set",
    "attack-technique": "attack-pattern",
    malware: "malware",
    tool: "tool",
    campaign: "campaign",
    vulnerability: "vulnerability",
    infrastructure: "infrastructure",
    "course-of-action": "course-of-action",
  };
  const original = entity.data.stix as Record<string, unknown> | undefined;
  const type =
    original?.type === "intrusion-set" ? "intrusion-set" : map[entity.type];
  created =
    typeof original?.created === "string"
      ? original.created
      : (entity.provenance.publishedAt ??
        entity.provenance.retrievedAt ??
        created);
  const modified =
    typeof original?.modified === "string" ? original.modified : created;
  const references = [
    {
      source_name: entity.provenance.sourceName,
      ...(entity.externalId ? { external_id: entity.externalId } : {}),
      ...(entity.provenance.sourceUrl
        ? { url: entity.provenance.sourceUrl }
        : {}),
    },
  ];
  if (type)
    return {
      type,
      id: entity.id.startsWith(type + "--")
        ? entity.id
        : stixId(type, entity.id),
      spec_version: "2.1",
      created,
      modified,
      name: entity.name,
      description: entity.description,
      ...(type === "malware" ? { is_family: true } : {}),
      external_references: [
        ...references,
        ...(Array.isArray(original?.external_references)
          ? original.external_references
          : []),
      ],
      ...(entity.aliases.length &&
      ["malware", "tool", "threat-actor", "intrusion-set", "campaign"].includes(
        type,
      )
        ? { aliases: entity.aliases }
        : {}),
      x_threatsieve_entity_id: entity.id,
      x_threatsieve_assertion_type: "source_claimed",
    };
  if (entity.type === "observable") {
    const observableType = String(entity.data.observableType ?? "");
    const sco: Record<string, string> = {
      domain: "domain-name",
      hostname: "domain-name",
      ipv4: "ipv4-addr",
      ipv6: "ipv6-addr",
      url: "url",
      email: "email-addr",
      mutex: "mutex",
      "registry-key": "windows-registry-key",
      process: "process",
      asn: "autonomous-system",
      sha256: "file",
      sha1: "file",
      md5: "file",
    };
    const t =
      sco[observableType] ??
      (observableType === "cidr"
        ? entity.name.includes(":")
          ? "ipv6-addr"
          : "ipv4-addr"
        : "x-threatsieve-observable");
    const fields =
      t === "file"
        ? {
            hashes: {
              [{ sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" }[
                observableType as "sha256"
              ]]: entity.name,
            },
          }
        : t === "autonomous-system"
          ? { number: Number(entity.name.replace(/^AS/, "")) }
          : t === "process"
            ? { command_line: entity.name }
            : t === "windows-registry-key"
              ? { key: entity.name }
              : t === "mutex"
                ? { name: entity.name }
                : t === "x-threatsieve-observable"
                  ? { x_value: entity.name, x_observable_type: observableType }
                  : { value: entity.name };
    return {
      type: t,
      id: stixId(t, entity.id),
      spec_version: "2.1",
      ...fields,
      x_threatsieve_entity_id: entity.id,
    };
  }
  return null;
}
export async function exportWorkspace(
  repo: OperationsRepository,
  o: WorkObject,
  seen = new Set<string>(),
): Promise<StixBundle> {
  if (seen.has(o.id))
    return { type: "bundle", id: stixId("bundle", o.id), objects: [] };
  if (seen.size >= 20)
    throw new (await import("../../observability/src/index")).AppError(
      "EXPORT_TOO_DEEP",
      413,
      "Export at most 20 linked workspace objects in one package.",
    );
  seen.add(o.id);
  const objects = new Map<string, StixObject>(),
    entities = new Map<string, string>();
  const references = [...o.references];
  if (o.kind === "collection") {
    const matches = await repo.db
      .prepare(
        "SELECT entity_id FROM workspace_matches WHERE tenant_id=? AND object_id=? ORDER BY entity_id LIMIT 101",
      )
      .bind(repo.tenant, o.id)
      .all<{ entity_id: string }>();
    if (matches.results.length > 100)
      throw new (await import("../../observability/src/index")).AppError(
        "COLLECTION_TOO_LARGE",
        413,
        "Narrow collection criteria to 100 entities before exporting this curated package.",
      );
    for (const row of matches.results)
      if (
        !references.some((r) => r.type === "entity" && r.id === row.entity_id)
      )
        references.push({
          type: "entity",
          id: row.entity_id,
          relation: "member",
        });
  }
  for (const ref of references) {
    if (ref.type === "assessment") {
      const a = await repo.intel.assessment(repo.tenant, ref.id);
      if (a) for (const obj of exportStix(a).objects) objects.set(obj.id, obj);
    } else if (ref.type === "entity") {
      if (!(await repo.intel.visible(repo.tenant, ref.id))) continue;
      const e = await repo.intel.entity(ref.id);
      const obj = e ? entityStix(e, o.updatedAt) : null;
      if (obj) {
        objects.set(obj.id, obj);
        entities.set(ref.id, obj.id);
      }
    } else if (
      [
        "report",
        "collection",
        "investigation",
        "requirement",
        "watchlist",
      ].includes(ref.type)
    ) {
      const nested = await repo.get(
        ref.id,
        ref.type as import("../../schemas/src/enterprise").WorkKind,
      );
      for (const obj of (await exportWorkspace(repo, nested, seen)).objects)
        objects.set(obj.id, obj);
    }
  }
  for (const [id] of entities)
    for (const edge of await repo.intel.edges(id, 100, repo.tenant)) {
      if (
        !edge.provenance.redistributable ||
        !entities.has(edge.sourceEntityId) ||
        !entities.has(edge.targetEntityId)
      )
        continue;
      const object: StixObject = {
        type: "relationship",
        id: stixId("relationship", edge.id),
        spec_version: "2.1",
        created: edge.createdAt,
        modified: edge.updatedAt,
        relationship_type: edge.relationshipType
          .toLowerCase()
          .replaceAll("_", "-"),
        source_ref: entities.get(edge.sourceEntityId),
        target_ref: entities.get(edge.targetEntityId),
        confidence: Math.round(edge.confidence * 100),
        x_threatsieve_assertion_type: edge.assertionType,
        external_references: [{ source_name: edge.provenance.sourceName }],
      };
      objects.set(object.id, object);
    }
  if (o.kind === "report" && o.status === "published" && objects.size) {
    const report: StixObject = {
      type: "report",
      id: stixId("report", o.id),
      spec_version: "2.1",
      created: o.createdAt,
      modified: o.updatedAt,
      name: o.title,
      description: o.body,
      published: o.updatedAt,
      report_types: ["threat-report"],
      object_refs: [...objects.keys()],
      x_threatsieve_assertion_type: "analyst_authored",
    };
    objects.set(report.id, report);
  }
  return {
    type: "bundle",
    id: stixId("bundle", o.id + ":" + o.revision),
    objects: [...objects.values()],
  };
}
export function reportHtml(o: WorkObject) {
  const body =
    o.kind === "report"
      ? o.body
      : o.kind === "requirement"
        ? o.question
        : o.kind === "investigation"
          ? o.hypothesis
          : o.description;
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>' +
    escapeHtml(o.title) +
    " · ThreatSieve</title><style>body{font:14px/1.7 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:24px;color:#1b242c}h1{font-size:24px}h2{font-size:16px}header{border-bottom:1px solid #ccc;padding-bottom:16px}article{white-space:pre-wrap}li{overflow-wrap:anywhere}small{color:#52606d}@media print{body{margin:0;max-width:none}}</style></head><body><header><small>THREATSIEVE · WORKSPACE PRIVATE · REVISION " +
    o.revision +
    "</small><h1>" +
    escapeHtml(o.title) +
    "</h1><p>" +
    escapeHtml(o.kind + " · " + o.status + " · " + o.priority + " priority") +
    "</p><small>" +
    escapeHtml(o.updatedAt) +
    "</small></header><h2>Analyst-authored intelligence</h2><article>" +
    escapeHtml(body) +
    "</article><h2>References</h2><ul>" +
    o.references
      .map(
        (r) =>
          "<li>" +
          escapeHtml(r.relation + " · " + r.type + " · " + r.id) +
          "</li>",
      )
      .join("") +
    "</ul><p><small>References point to original records. Analyst-authored statements are not automatically verified. This document may contain tenant-private information.</small></p></body></html>"
  );
}

/** A downloadable MISP event; analyst-curated remote events are never overwritten. */
export async function exportMisp(repo: OperationsRepository, o: WorkObject) {
  const bundle = await exportWorkspace(repo, o);
  const attributes: Record<string, unknown>[] = [];
  for (const object of bundle.objects) {
    const typeMap: Record<string, string> = {
      "domain-name": "domain",
      "ipv4-addr": "ip-dst",
      "ipv6-addr": "ip-dst",
      url: "url",
      "email-addr": "email-src",
      mutex: "mutex",
      "windows-registry-key": "regkey",
    };
    if (typeMap[object.type])
      attributes.push({
        uuid: stixId("attribute", object.id).split("--")[1],
        type: typeMap[object.type],
        category: ["email-src", "email-dst"].includes(typeMap[object.type]!)
          ? "Payload delivery"
          : typeMap[object.type] === "regkey"
            ? "Persistence mechanism"
            : typeMap[object.type] === "mutex"
              ? "Artifacts dropped"
              : "Network activity",
        value: object.value ?? object.name ?? object.key,
        to_ids: false,
        distribution: "0",
        comment:
          "ThreatSieve source-backed observable; see preserved source assertions.",
        Tag: [{ name: "threatsieve:assertion=source-claimed" }],
        x_threatsieve: object,
      });
    if (
      object.type === "file" &&
      object.hashes &&
      typeof object.hashes === "object"
    )
      for (const [algorithm, value] of Object.entries(object.hashes)) {
        const type = (
          { "SHA-256": "sha256", "SHA-1": "sha1", MD5: "md5" } as Record<
            string,
            string
          >
        )[algorithm];
        if (type && typeof value === "string")
          attributes.push({
            uuid: stixId("attribute", object.id + algorithm).split("--")[1],
            type,
            category: "Payload delivery",
            value,
            to_ids: false,
            distribution: "0",
            x_threatsieve: object,
          });
      }
    if (object.type === "indicator" && typeof object.pattern === "string") {
      const match =
        /^\[(domain-name:value|ipv4-addr:value|ipv6-addr:value|url:value|email-addr:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)') = '((?:[^'\\]|\\.)*)'\]$/.exec(
          object.pattern,
        );
      if (match) {
        const type = (
          {
            "domain-name:value": "domain",
            "ipv4-addr:value": "ip-dst",
            "ipv6-addr:value": "ip-dst",
            "url:value": "url",
            "email-addr:value": "email-src",
            "file:hashes.'MD5'": "md5",
            "file:hashes.'SHA-1'": "sha1",
            "file:hashes.'SHA-256'": "sha256",
          } as Record<string, string>
        )[match[1]!]!;
        attributes.push({
          uuid: stixId("attribute", object.id).split("--")[1],
          type,
          category: [
            "md5",
            "sha1",
            "sha256",
            "email-src",
            "email-dst",
          ].includes(type)
            ? "Payload delivery"
            : "Network activity",
          value: match[2]!.replace(/\\(['\\])/g, "$1"),
          to_ids: false,
          distribution: "0",
          comment:
            "ThreatSieve assessed indicator; review decision metadata before detection use.",
          x_threatsieve: object,
        });
      }
    }
  }
  return {
    Event: {
      uuid: /^[0-9a-f-]{36}$/i.test(o.id)
        ? o.id
        : stixId("report", o.id).split("--")[1],
      info: o.title,
      Orgc: {
        uuid: stixId("identity", repo.tenant).split("--")[1],
        name: "ThreatSieve workspace",
      },
      date: o.updatedAt.slice(0, 10),
      timestamp: String(Math.floor(Date.parse(o.updatedAt) / 1000)),
      distribution: "0",
      analysis: "2",
      threat_level_id: "4",
      published: false,
      Attribute: attributes,
      Tag: o.tags.map((name) => ({ name })),
      x_threatsieve: {
        revision: o.revision,
        kind: o.kind,
        provenance: "Analyst-curated export",
        stix_bundle: bundle,
      },
    },
  };
}
