import { z } from "zod";
import { PublicFeed, boundedText, StixBundle, stixRecord } from "./feeds";
import { providerProvenance } from "./additional-feeds";
import { digest, normalise } from "./normalise";
import { Repository } from "../../database/src/repository";
import type {
  FeedBatch,
  FeedHealth,
  NormalizedIntelRecord,
} from "../../schemas/src/index";
import { parseIndicators } from "./upload";
export interface OptionalFeedConfig {
  enabled: boolean;
  apiKey?: string;
  endpoint?: string;
  allowedHost?: string;
  format?: "stix" | "misp" | "text" | "csv" | "json";
}
export class OptionalFeed extends PublicFeed {
  constructor(
    id: "otx" | "virustotal" | "greynoise" | "taxii" | "stix" | "misp-feed",
    name: string,
    repo: Repository,
    private config: OptionalFeedConfig,
    request: typeof fetch = fetch,
  ) {
    super(id, name, repo, {}, request);
  }
  override async healthCheck(): Promise<FeedHealth> {
    return {
      status: this.config.enabled ? "healthy" : "disabled",
      message: this.config.enabled
        ? "Configured; last sync status available from source operations"
        : "Enable explicitly with provider credentials and terms reviewed",
      checkedAt: new Date().toISOString(),
    };
  }
  override async fetch(cursor?: string): Promise<FeedBatch> {
    if (!this.config.enabled) throw new Error("Feed disabled");
    let url: URL;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (this.id === "otx") {
      if (!this.config.apiKey) throw new Error("OTX credential required");
      url = new URL("https://otx.alienvault.com/api/v1/pulses/subscribed");
      if (cursor)
        url.searchParams.set("modified_since", z.iso.datetime().parse(cursor));
      url.searchParams.set("limit", "100");
      headers["X-OTX-API-KEY"] = this.config.apiKey;
    } else if (this.id === "virustotal") {
      if (!this.config.apiKey || !cursor)
        throw new Error("VirusTotal credential and observable required");
      const obs = await normalise(cursor);
      const path =
        obs.type === "domain"
          ? "domains"
          : obs.type === "ipv4" || obs.type === "ipv6"
            ? "ip_addresses"
            : ["sha256", "sha1", "md5"].includes(obs.type)
              ? "files"
              : null;
      if (!path) throw new Error("Unsupported VirusTotal observable");
      url = new URL(
        "https://www.virustotal.com/api/v3/" +
          path +
          "/" +
          encodeURIComponent(obs.normalizedValue),
      );
      headers["x-apikey"] = this.config.apiKey;
    } else if (this.id === "greynoise") {
      if (!this.config.apiKey || !cursor)
        throw new Error("GreyNoise credential and IP required");
      const obs = await normalise(cursor);
      if (obs.type !== "ipv4")
        throw new Error("GreyNoise Community requires IPv4");
      url = new URL(
        "https://api.greynoise.io/v3/community/" + obs.normalizedValue,
      );
      headers.key = this.config.apiKey;
    } else {
      if (!this.config.endpoint || !this.config.allowedHost)
        throw new Error(
          "Operator-configured endpoint and allowlisted hostname required",
        );
      url = new URL(this.config.endpoint);
      if (
        url.protocol !== "https:" ||
        url.hostname !== this.config.allowedHost ||
        url.username ||
        url.password ||
        (url.port && url.port !== "443") ||
        /^(localhost|.*\.local|\d+\.\d+\.\d+\.\d+|\[.*\])$/.test(url.hostname)
      )
        throw new Error(
          "Endpoint must use an explicitly approved HTTPS DNS host",
        );
      if (this.id === "taxii") {
        headers.Accept = "application/taxii+json;version=2.1";
        if (cursor)
          url.searchParams.set("added_after", z.iso.datetime().parse(cursor));
        url.searchParams.set("limit", "100");
      }
      if (this.config.apiKey)
        headers.Authorization = "Bearer " + this.config.apiKey;
    }
    const response = await this.request(url, {
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error("Provider HTTP " + response.status);
    const text = await boundedText(response, 8 * 1024 * 1024);
    let raw: unknown;
    let records: unknown[];
    if (
      this.config.format &&
      ["csv", "text", "json"].includes(this.config.format)
    ) {
      raw = text;
      records = parseIndicators(text, this.config.format).map((observable) => ({
        observable,
      }));
    } else {
      raw = JSON.parse(text);
      if (this.id === "otx")
        records = z
          .object({ results: z.array(z.unknown()) })
          .parse(raw).results;
      else if (this.id === "taxii")
        records = z
          .object({
            objects: z.array(z.unknown()),
            more: z.boolean().optional(),
          })
          .parse(raw).objects;
      else if (this.id === "stix") records = StixBundle.parse(raw).objects;
      else if (this.id === "misp-feed") {
        const body = z
          .object({
            Event: z.object({ Attribute: z.array(z.unknown()).optional() }),
          })
          .parse(raw);
        records = body.Event.Attribute ?? [];
      } else records = [{ raw, observable: cursor }];
    }
    return { raw, records, cursor: new Date().toISOString() };
  }
  override async normalize(input: unknown): Promise<NormalizedIntelRecord[]> {
    const provenance = providerProvenance(this.id, this.name);
    if (this.id === "stix" || this.id === "taxii")
      return stixRecord(input, provenance);
    const now = new Date().toISOString();
    const make = async (
      value: string,
      data: Record<string, unknown>,
      recordId: string,
    ): Promise<NormalizedIntelRecord> => ({
      observable: { value },
      provenance: { ...provenance, sourceRecordId: recordId },
      relationships: [],
      evidence: [
        {
          id: "ev_" + (await digest(this.id + ":" + recordId)),
          type: "feed",
          sourceId: this.id,
          provenance: { ...provenance, sourceRecordId: recordId },
          data,
          confidence: 0.65,
          createdAt: now,
          observedAt: now,
          behavioural: false,
        },
      ],
    });
    if (this.id === "otx") {
      const pulse = z
        .object({
          id: z.string(),
          name: z.string(),
          indicators: z.array(
            z.object({
              id: z.number(),
              indicator: z.string(),
              type: z.string(),
            }),
          ),
        })
        .parse(input);
      const result: NormalizedIntelRecord[] = [];
      for (const i of pulse.indicators) {
        try {
          await normalise(i.indicator);
          result.push(
            await make(
              i.indicator,
              {
                description: pulse.name,
                reportId: pulse.id,
                sourceClaim: "Listed in OTX pulse",
              },
              String(i.id),
            ),
          );
        } catch {
          continue;
        }
      }
      return result;
    }
    if (this.id === "virustotal") {
      const item = z
        .object({
          observable: z.string(),
          raw: z.object({
            data: z.object({
              id: z.string(),
              attributes: z
                .object({
                  last_analysis_stats: z.record(z.string(), z.number()),
                })
                .passthrough(),
            }),
          }),
        })
        .parse(input);
      const stats = item.raw.data.attributes.last_analysis_stats;
      return [
        await make(
          item.observable,
          {
            analysisStats: stats,
            malicious: (stats.malicious ?? 0) > 0,
            description:
              "VirusTotal engine results; engines are not counted as independent sources",
          },
          item.raw.data.id,
        ),
      ];
    }
    if (this.id === "greynoise") {
      const item = z
        .object({
          observable: z.string(),
          raw: z
            .object({
              ip: z.string(),
              noise: z.boolean(),
              riot: z.boolean(),
              classification: z.string().optional(),
              name: z.string().optional(),
            })
            .passthrough(),
        })
        .parse(input);
      return [
        await make(
          item.observable,
          {
            ...item.raw,
            role: item.raw.noise ? "scanning" : "unknown",
            malicious:
              item.raw.classification === "malicious"
                ? true
                : item.raw.riot
                  ? false
                  : undefined,
          },
          item.raw.ip,
        ),
      ];
    }
    if (this.id === "misp-feed") {
      const item = z
        .object({
          uuid: z.string(),
          value: z.string(),
          type: z.string(),
          comment: z.string().optional(),
          to_ids: z.boolean().optional(),
        })
        .parse(input);
      if (
        ![
          "ip-src",
          "ip-dst",
          "domain",
          "hostname",
          "url",
          "md5",
          "sha1",
          "sha256",
          "email-src",
          "email-dst",
        ].includes(item.type)
      )
        return [];
      return [
        await make(
          item.value,
          { description: item.comment ?? "", to_ids: item.to_ids },
          item.uuid,
        ),
      ];
    }
    const item = z
      .object({ observable: z.object({ observable: z.string() }) })
      .parse(input);
    return [
      await make(
        item.observable.observable,
        {
          description:
            "Operator-configured indicator list; maliciousness unconfirmed",
        },
        await digest(item.observable.observable),
      ),
    ];
  }
}
