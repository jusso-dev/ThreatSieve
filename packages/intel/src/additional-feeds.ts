import { z } from "zod";
import { PublicFeed, boundedText } from "./feeds";
import type {
  FeedBatch,
  NormalizedIntelRecord,
  IntelEntity,
  Evidence,
  SourceProvenance,
} from "../../schemas/src/index";
import { digest, entityId, normalise } from "./normalise";
const GalaxyValue = z
  .object({
    uuid: z.string(),
    value: z.string(),
    description: z.string().optional(),
    meta: z
      .object({
        synonyms: z.array(z.string()).optional(),
        refs: z.array(z.string()).optional(),
        external_id: z.union([z.string(), z.array(z.string())]).optional(),
      })
      .passthrough()
      .optional(),
    collection: z.string(),
    license: z.string().optional(),
    version: z.union([z.number(), z.string()]).optional(),
  })
  .passthrough();
const KEV = z.object({
  cveID: z.string(),
  vendorProject: z.string(),
  product: z.string(),
  vulnerabilityName: z.string(),
  dateAdded: z.string(),
  shortDescription: z.string(),
  requiredAction: z.string(),
  dueDate: z.string(),
  knownRansomwareCampaignUse: z.string().optional(),
  notes: z.string().optional(),
});
const URLItem = z
  .object({
    id: z.union([z.string(), z.number()]),
    url: z.string(),
    url_status: z.string().optional(),
    date_added: z.string(),
    threat: z.string().optional(),
    tags: z.array(z.string()).nullish(),
    urlhaus_reference: z.string().optional(),
    payloads: z
      .array(
        z
          .object({
            response_sha256: z.string().optional(),
            response_md5: z.string().optional(),
            signature: z.string().nullish(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();
const Feodo = z
  .object({
    ip_address: z.string(),
    port: z.number().optional(),
    status: z.string().optional(),
    first_seen: z.string(),
    last_online: z.string().optional(),
    malware: z.string(),
  })
  .passthrough();
export class AdditionalFeed extends PublicFeed {
  override async fetch(_cursor?: string): Promise<FeedBatch> {
    let records: unknown[];
    let raw: unknown;
    const now = new Date().toISOString();
    if (this.id === "misp") {
      const collections = [
        "threat-actor",
        "mitre-intrusion-set",
        "mitre-malware",
        "ransomware",
        "tool",
        "mitre-campaign",
      ];
      const bundles: unknown[] = [];
      records = [];
      for (const collection of collections) {
        const response = await this.request(
          "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/" +
            collection +
            ".json",
          { redirect: "error", signal: AbortSignal.timeout(30000) },
        );
        if (!response.ok)
          throw new Error("MISP upstream HTTP " + response.status);
        const bundle = z
          .object({
            values: z.array(z.record(z.string(), z.unknown())),
            version: z.union([z.string(), z.number()]),
            license: z.string().optional(),
          })
          .passthrough()
          .parse(JSON.parse(await boundedText(response)));
        bundles.push(bundle);
        records.push(
          ...bundle.values.map((v) => ({
            ...v,
            collection,
            license: bundle.license,
            version: bundle.version,
          })),
        );
      }
      raw = bundles;
    } else {
      let url: string;
      const headers: Record<string, string> = {};
      switch (this.id) {
        case "urlhaus":
          if (!this.secrets.URLHAUS_AUTH_KEY)
            throw new Error("URLhaus credential required");
          url = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
          headers["Auth-Key"] = this.secrets.URLHAUS_AUTH_KEY;
          break;
        case "feodo":
          url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
          break;
        case "cisa-kev":
          url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
          break;
        default:
          throw new Error("Unsupported feed");
      }
      const response = await this.request(url, {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(60000),
      });
      if (!response.ok) throw new Error("Upstream HTTP " + response.status);
      raw = JSON.parse(await boundedText(response));
      if (this.id === "urlhaus") {
        const body = z
          .object({
            query_status: z.string(),
            urls: z.array(z.unknown()).optional(),
          })
          .parse(raw);
        if (!["ok", "no_results"].includes(body.query_status))
          throw new Error("URLhaus query failed");
        records = body.urls ?? [];
      } else if (this.id === "cisa-kev")
        records = z
          .object({ vulnerabilities: z.array(z.unknown()) })
          .parse(raw).vulnerabilities;
      else records = z.array(z.unknown()).parse(raw);
    }
    return { raw, records, cursor: now };
  }
  override async normalize(raw: unknown): Promise<NormalizedIntelRecord[]> {
    const p = this.provenance();
    const now = new Date().toISOString();
    if (this.id === "misp") {
      const item = GalaxyValue.parse(raw);
      const aliases = item.meta?.synonyms ?? [];
      const type: IntelEntity["type"] =
        item.collection.includes("intrusion") ||
        item.collection === "threat-actor"
          ? "threat-actor"
          : item.collection.includes("campaign")
            ? "campaign"
            : item.collection === "tool"
              ? "tool"
              : "malware";
      const externalFromRefs = item.meta?.refs?.flatMap(
        (ref) =>
          /^https:\/\/attack\.mitre\.org\/(groups|software|campaigns)\/([GSC]\d+)\//.exec(
            ref,
          )?.[2] ?? [],
      )[0];
      const externalMeta = item.meta?.external_id;
      const externalId =
        externalFromRefs ??
        (Array.isArray(externalMeta) ? externalMeta[0] : externalMeta) ??
        aliases.find((a) => /^[GSC]\d{4}$/.test(a));
      const matches = await this.repo.resolveAlias(
        externalId ?? item.value,
        type,
      );
      const existing = matches.length === 1 ? matches[0] : undefined;
      const id = existing?.id ?? (await entityId(type, item.value));
      p.sourceRecordId = item.uuid;
      p.license = item.license ?? "Collection-specific terms";
      p.sourceUrl =
        "https://github.com/MISP/misp-galaxy/blob/main/clusters/" +
        item.collection +
        ".json";
      const entity: IntelEntity = {
        id,
        type,
        name: existing?.name ?? item.value,
        description: existing?.description || item.description || "",
        aliases: [
          ...new Set([...(existing?.aliases ?? []), item.value, ...aliases]),
        ],
        externalId: existing?.externalId ?? externalId,
        data: { ...existing?.data, galaxy: item, version: item.version },
        provenance: p,
      };
      const evidence: Evidence = {
        id: "ev_" + (await digest("misp:" + item.uuid)),
        type: "feed",
        sourceId: "misp",
        data: { aliases, externalId, collection: item.collection },
        provenance: p,
        confidence: 0.8,
        createdAt: now,
        behavioural: false,
      };
      return [
        { entity, evidence: [evidence], relationships: [], provenance: p },
      ];
    }
    if (this.id === "cisa-kev") {
      const item = KEV.parse(raw);
      p.sourceRecordId = item.cveID;
      p.sourceUrl =
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
      p.sourceConfidence = 0.98;
      p.publishedAt = item.dateAdded;
      p.redistributable = true;
      p.license = "US government public data";
      const evidence: Evidence = {
        id: "ev_" + (await digest("cisa-kev:" + item.cveID)),
        type: "feed",
        sourceId: this.id,
        provenance: p,
        confidence: 0.98,
        createdAt: now,
        observedAt: new Date(item.dateAdded).toISOString(),
        behavioural: false,
        data: {
          kev: true,
          vendor: item.vendorProject,
          product: item.product,
          description: item.shortDescription,
          requiredAction: item.requiredAction,
          dueDate: item.dueDate,
          ransomware: item.knownRansomwareCampaignUse,
          notes: item.notes,
        },
      };
      const id = await entityId("vulnerability", item.cveID);
      return [
        {
          entity: {
            id,
            type: "vulnerability",
            name: item.cveID,
            description: item.shortDescription,
            aliases: [],
            externalId: item.cveID,
            data: item,
            provenance: p,
          },
          provenance: p,
          relationships: [],
          evidence: [],
        },
        {
          observable: { value: item.cveID, type: "cve" },
          evidence: [evidence],
          relationships: [],
          provenance: p,
        },
      ];
    }
    if (this.id === "urlhaus") {
      const item = URLItem.parse(raw);
      p.sourceRecordId = String(item.id);
      p.sourceUrl =
        item.urlhaus_reference ??
        "https://urlhaus.abuse.ch/url/" + item.id + "/";
      p.publishedAt = item.date_added;
      const evidence: Evidence = {
        id: "ev_" + (await digest("urlhaus:" + item.id)),
        type: "feed",
        sourceId: this.id,
        provenance: p,
        confidence: 0.85,
        createdAt: now,
        observedAt: new Date(item.date_added + " UTC").toISOString(),
        behavioural: false,
        data: {
          malicious: true,
          role: "payload",
          description: "URLhaus reports malware delivery at this exact URL.",
          tags: item.tags ?? [],
          status: item.url_status,
        },
      };
      const url = await normalise(item.url, "url");
      const host = await normalise(new URL(item.url).hostname);
      const records: NormalizedIntelRecord[] = [
        {
          observable: { value: item.url, type: "url" },
          provenance: p,
          evidence: [evidence],
          relationships: [
            {
              id: "rel_" + (await digest(url.id + ":host:" + host.id)),
              sourceEntityId: url.id,
              targetEntityId: host.id,
              relationshipType: "HOSTED_ON",
              assertionType: "observed",
              confidence: 1,
              sourceIds: [this.id],
              provenance: p,
              createdAt: now,
              updatedAt: now,
            },
          ],
        },
        {
          observable: { value: host.normalizedValue, type: host.type },
          provenance: p,
          relationships: [],
          evidence: [],
        },
      ];
      for (const payload of item.payloads ?? []) {
        for (const [type, value] of [
          ["sha256", payload.response_sha256],
          ["md5", payload.response_md5],
        ] as const) {
          if (!value) continue;
          records.push({
            observable: { value, type },
            provenance: p,
            relationships: [],
            evidence: [
              {
                ...evidence,
                id: "ev_" + (await digest("urlhaus:" + item.id + ":" + value)),
                type: "malware",
                data: {
                  description: "Payload observed at URLhaus URL",
                  signature: payload.signature,
                  parentUrl: item.url,
                  malicious:
                    typeof payload.signature === "string" &&
                    payload.signature.length > 0,
                },
              },
            ],
          });
        }
      }
      return records;
    }
    if (this.id === "feodo") {
      const item = Feodo.parse(raw);
      p.sourceRecordId = item.ip_address + ":" + (item.port ?? 0);
      p.sourceUrl = "https://feodotracker.abuse.ch/";
      const matches = await this.repo.resolveAlias(item.malware, "malware");
      const malwareId =
        matches.length === 1
          ? matches[0]!.id
          : await entityId("malware", item.malware);
      const evidence: Evidence = {
        id: "ev_" + (await digest("feodo:" + p.sourceRecordId)),
        type: "feed",
        sourceId: this.id,
        provenance: p,
        confidence: 0.9,
        createdAt: now,
        observedAt: new Date(item.last_online ?? item.first_seen).toISOString(),
        behavioural: false,
        data: {
          malicious: true,
          role: "c2",
          malware: item.malware,
          malwareEntityId: malwareId,
          port: item.port,
          status: item.status,
        },
      };
      return [
        ...(matches.length === 1
          ? []
          : [
              {
                entity: {
                  id: malwareId,
                  type: "malware" as const,
                  name: item.malware,
                  description: "Feodo source-provided malware association",
                  aliases: [],
                  data: {},
                  provenance: p,
                },
                provenance: p,
                relationships: [],
                evidence: [],
              },
            ]),
        {
          observable: {
            value: item.ip_address,
            firstSeen: new Date(item.first_seen).toISOString(),
            lastSeen: evidence.observedAt,
          },
          provenance: p,
          relationships: [],
          evidence: [evidence],
        },
      ];
    }
    return super.normalize(raw);
  }
}
export function providerProvenance(id: string, name: string): SourceProvenance {
  return {
    sourceId: id,
    sourceName: name,
    retrievedAt: new Date().toISOString(),
    redistributable: false,
  };
}
