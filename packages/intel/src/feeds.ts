import { z } from "zod";
import type {
  ThreatFeedProvider,
  FeedBatch,
  FeedHealth,
  NormalizedIntelRecord,
  SourceProvenance,
  IntelRelationship,
  IntelEntity,
  Evidence,
} from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
import { digest, entityId } from "./normalise";

export async function boundedText(
  response: Response,
  maxBytes = 32 * 1024 * 1024,
): Promise<string> {
  if (!response.body) throw new Error("Empty upstream response");
  if (Number(response.headers.get("content-length")) > maxBytes)
    throw new Error("Payload exceeds size limit");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error("Payload exceeds size limit");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel();
    throw error;
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(all);
}
export const StixObject = z
  .object({
    id: z.string(),
    type: z.string(),
    name: z.string().optional(),
    description: z.string().max(100000).optional(),
    aliases: z.array(z.string()).optional(),
    external_references: z
      .array(
        z
          .object({
            source_name: z.string(),
            external_id: z.string().optional(),
            url: z.string().optional(),
          })
          .passthrough(),
      )
      .optional(),
    source_ref: z.string().optional(),
    target_ref: z.string().optional(),
    relationship_type: z.string().optional(),
    modified: z.string().optional(),
    created: z.string().optional(),
    revoked: z.boolean().optional(),
    x_mitre_deprecated: z.boolean().optional(),
    x_mitre_aliases: z.array(z.string()).optional(),
  })
  .passthrough();
export const StixBundle = z.object({
  type: z.literal("bundle"),
  objects: z.array(StixObject).max(100000),
});
const STIX_TYPES: Record<string, IntelEntity["type"]> = {
  "attack-pattern": "attack-technique",
  "x-mitre-tactic": "attack-tactic",
  "intrusion-set": "threat-actor",
  "threat-actor": "threat-actor",
  malware: "malware",
  tool: "tool",
  campaign: "campaign",
  infrastructure: "infrastructure",
  "course-of-action": "course-of-action",
  report: "report",
  vulnerability: "vulnerability",
};
export async function stixRecord(
  raw: unknown,
  p: SourceProvenance,
): Promise<NormalizedIntelRecord[]> {
  const o = StixObject.parse(raw);
  if (o.revoked || o.x_mitre_deprecated) return [];
  p = { ...p, sourceRecordId: o.id, publishedAt: o.modified ?? o.created };
  const records: NormalizedIntelRecord[] = [];
  if (
    o.type === "relationship" &&
    o.source_ref &&
    o.target_ref &&
    o.relationship_type
  ) {
    const now = new Date().toISOString();
    const rel: IntelRelationship = {
      id: o.id,
      sourceEntityId: o.source_ref,
      targetEntityId: o.target_ref,
      relationshipType: o.relationship_type.toUpperCase().replace(/-/g, "_"),
      assertionType: "source_claimed",
      confidence: 0.9,
      sourceIds: [p.sourceId],
      provenance: p,
      createdAt: now,
      updatedAt: now,
    };
    records.push({ provenance: p, relationships: [rel], evidence: [] });
    return records;
  }
  const SCO_TYPES: Record<
    string,
    "domain" | "ipv4" | "ipv6" | "url" | "email"
  > = {
    "domain-name": "domain",
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    url: "url",
    "email-addr": "email",
  };
  if (SCO_TYPES[o.type] && typeof o.value === "string")
    return [
      {
        observable: {
          value: o.value,
          type:
            o.value.includes("/") && ["ipv4-addr", "ipv6-addr"].includes(o.type)
              ? "cidr"
              : SCO_TYPES[o.type],
        },
        provenance: p,
        relationships: [],
        evidence: [],
      },
    ];
  if (o.type === "indicator" && typeof o.pattern === "string") {
    const match =
      /^\[(domain-name:value|ipv4-addr:value|ipv6-addr:value|url:value|email-addr:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)') = '((?:[^'\\]|\\.)*)'\]$/.exec(
        o.pattern,
      );
    if (!match) throw new Error("Unsupported compound STIX indicator pattern");
    return [
      {
        observable: { value: match[2]!.replace(/\\(['\\])/g, "$1") },
        provenance: p,
        relationships: [],
        evidence: [
          {
            id: "ev_" + (await digest(p.sourceId + ":" + o.id)),
            type: "feed",
            sourceId: p.sourceId,
            provenance: p,
            data: {
              description: o.description ?? "",
              stix: o,
              sourceClaim: "STIX indicator",
            },
            confidence: 0.6,
            createdAt: new Date().toISOString(),
            behavioural: false,
          },
        ],
      },
    ];
  }
  const type = STIX_TYPES[o.type];
  if (!type || !o.name) return [];
  const externalId = o.external_references?.find(
    (r) => r.source_name === "mitre-attack",
  )?.external_id;
  records.push({
    entity: {
      id: o.id,
      type,
      name: o.name,
      description: o.description ?? "",
      aliases: o.aliases ?? o.x_mitre_aliases ?? [],
      externalId,
      data: { stix: o },
      provenance: p,
    },
    provenance: p,
    relationships: [],
    evidence: [
      {
        id:
          "ev_" +
          (await digest(
            p.sourceId + ":" + o.id + ":" + (o.modified ?? o.created ?? ""),
          )),
        type: p.sourceId === "mitre" ? "attack" : "feed",
        sourceId: p.sourceId,
        provenance: p,
        data: {
          description: o.description ?? o.name,
          stixType: o.type,
          externalId,
          aliases: o.aliases ?? o.x_mitre_aliases ?? [],
          knowledgeOnly: true,
        },
        confidence:
          typeof o.confidence === "number"
            ? Math.max(0, Math.min(1, o.confidence / 100))
            : 0.8,
        createdAt: new Date().toISOString(),
        observedAt: o.modified ?? o.created,
        behavioural: false,
      },
    ],
  });
  return records;
}
const ThreatFoxItem = z.object({
  id: z.union([z.string(), z.number()]),
  ioc: z.string(),
  ioc_type: z.string(),
  threat_type: z.string(),
  malware: z.string().optional(),
  malware_printable: z.string().optional(),
  malware_alias: z.string().nullish(),
  confidence_level: z.number().min(0).max(100),
  first_seen: z.string(),
  last_seen: z.string().nullish(),
  tags: z.array(z.string()).nullish(),
  reference: z.string().nullish(),
  threat_type_desc: z.string().optional(),
});
export interface FeedSecrets {
  THREATFOX_AUTH_KEY?: string;
  URLHAUS_AUTH_KEY?: string;
  OTX_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  GREYNOISE_API_KEY?: string;
  TAXII_ENABLED?: string;
  TAXII_ENDPOINT?: string;
  TAXII_ALLOWED_HOST?: string;
  TAXII_API_KEY?: string;
  TAXII_PAGE_LIMIT?: string;
  STIX_ENABLED?: string;
  STIX_ENDPOINT?: string;
  STIX_ALLOWED_HOST?: string;
  STIX_API_KEY?: string;
  MISP_FEED_ENABLED?: string;
  MISP_FEED_ENDPOINT?: string;
  MISP_FEED_ALLOWED_HOST?: string;
  MISP_FEED_API_KEY?: string;
  OTX_ENABLED?: string;
}
export class PublicFeed implements ThreatFeedProvider {
  readonly type = "json" as const;
  constructor(
    readonly id: string,
    readonly name: string,
    protected repo: Repository,
    protected secrets: FeedSecrets = {},
    // Workers fetch must keep its global receiver when stored on a provider.
    protected request: typeof fetch = (input, init) => fetch(input, init),
  ) {}
  async getCheckpoint() {
    return (
      (
        await this.repo.db
          .prepare("SELECT checkpoint FROM feed_checkpoints WHERE source_id=?")
          .bind(this.id)
          .first<{ checkpoint: string }>()
      )?.checkpoint ?? null
    );
  }
  async setCheckpoint(checkpoint: string) {
    await this.repo.db
      .prepare(
        "INSERT INTO feed_checkpoints VALUES(?,?,?) ON CONFLICT(source_id) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=excluded.updated_at",
      )
      .bind(this.id, checkpoint, new Date().toISOString())
      .run();
  }
  async healthCheck(): Promise<FeedHealth> {
    const keyMissing =
      (this.id === "threatfox" && !this.secrets.THREATFOX_AUTH_KEY) ||
      (this.id === "urlhaus" && !this.secrets.URLHAUS_AUTH_KEY);
    const row = await this.repo.db
      .prepare("SELECT status,last_error FROM sources WHERE id=?")
      .bind(this.id)
      .first<{ status: string; last_error: string | null }>();
    return {
      status: keyMissing
        ? "disabled"
        : row?.status === "error"
          ? "error"
          : "healthy",
      message: keyMissing
        ? "Source credential required"
        : (row?.last_error ?? undefined),
      checkedAt: new Date().toISOString(),
    };
  }
  async fetch(_cursor?: string): Promise<FeedBatch> {
    let url: string;
    let init: RequestInit = {};
    switch (this.id) {
      case "mitre":
        url =
          "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
        break;
      case "threatfox":
        if (!this.secrets.THREATFOX_AUTH_KEY)
          throw new Error("ThreatFox credential required");
        url = "https://threatfox-api.abuse.ch/api/v1/";
        init = {
          method: "POST",
          headers: {
            "Auth-Key": this.secrets.THREATFOX_AUTH_KEY,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ query: "get_iocs", days: 7 }),
        };
        break;
      default:
        throw new Error("Unsupported feed: " + this.id);
    }
    const response = await this.request(url, {
      ...init,
      // Workers has no redirect:error; reject all non-2xx responses below.
      redirect: "manual",
      signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) throw new Error("Upstream HTTP " + response.status);
    const raw: unknown = JSON.parse(await boundedText(response));
    let records: unknown[];
    if (this.id === "mitre") records = StixBundle.parse(raw).objects;
    else {
      const body = z
        .object({
          query_status: z.string(),
          data: z.array(z.unknown()).optional(),
        })
        .parse(raw);
      if (!["ok", "no_result"].includes(body.query_status))
        throw new Error("ThreatFox rejected query");
      records = body.data ?? [];
    }
    return { records, raw, cursor: new Date().toISOString() };
  }
  provenance(): SourceProvenance {
    return {
      sourceId: this.id,
      sourceName: this.name,
      retrievedAt: new Date().toISOString(),
      redistributable: this.id === "mitre",
      license: this.id === "mitre" ? "ATT&CK Terms of Use" : "Provider terms",
    };
  }
  async normalize(raw: unknown): Promise<NormalizedIntelRecord[]> {
    const p = this.provenance();
    if (this.id === "mitre") return stixRecord(raw, p);
    if (this.id !== "threatfox") throw new Error("Unsupported normalizer");
    const item = ThreatFoxItem.parse(raw);
    p.sourceRecordId = String(item.id);
    p.sourceUrl = "https://threatfox.abuse.ch/ioc/" + item.id + "/";
    p.sourceConfidence = item.confidence_level / 100;
    p.publishedAt = item.first_seen;
    let value = item.ioc;
    let type: "domain" | "url" | "sha256" | "md5" | "ipv4" | "ipv6" | undefined;
    if (item.ioc_type === "ip:port") {
      const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(value);
      if (!m) throw new Error("Invalid IP and port");
      value = m[1] ?? m[2]!;
      type = value.includes(":") ? "ipv6" : "ipv4";
    } else if (["domain", "url", "sha256", "md5"].includes(item.ioc_type))
      type = item.ioc_type as "domain" | "url" | "sha256" | "md5";
    else throw new Error("Unsupported ThreatFox IoC type");
    const now = new Date().toISOString();
    const e: Evidence = {
      id: "ev_" + (await digest("threatfox:" + item.id)),
      type: "feed",
      sourceId: "threatfox",
      provenance: p,
      confidence: item.confidence_level / 100,
      createdAt: now,
      observedAt: new Date(item.last_seen ?? item.first_seen).toISOString(),
      behavioural: false,
      data: {
        malicious: true,
        role:
          item.threat_type === "botnet_cc"
            ? "c2"
            : item.threat_type.includes("payload")
              ? "payload"
              : "unknown",
        malware: item.malware_printable ?? item.malware,
        tags: item.tags ?? [],
        upstream: item,
      },
    };
    const records: NormalizedIntelRecord[] = [
      {
        observable: {
          value,
          type,
          firstSeen: new Date(item.first_seen).toISOString(),
          lastSeen: e.observedAt,
        },
        provenance: p,
        evidence: [e],
        relationships: [],
      },
    ];
    if (item.malware_printable) {
      const matches = await this.repo.resolveAlias(
        item.malware_printable,
        "malware",
      );
      const id =
        matches.length === 1
          ? matches[0]!.id
          : await entityId("malware", item.malware_printable);
      e.data.malwareEntityId = id;
      if (matches.length !== 1)
        records.unshift({
          entity: {
            id,
            type: "malware",
            name: item.malware_printable,
            description: "Source-provided malware association",
            aliases: item.malware_alias?.split(",").map((a) => a.trim()) ?? [],
            data: {},
            provenance: p,
          },
          provenance: p,
          relationships: [],
          evidence: [],
        });
    }
    return records;
  }
}
