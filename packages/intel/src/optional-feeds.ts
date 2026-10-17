import { z } from "zod";
import { PublicFeed, boundedText, StixBundle, stixRecord } from "./feeds";
import { providerProvenance } from "./additional-feeds";
import { digest, normalise } from "./normalise";
import { Repository } from "../../database/src/repository";
import type {
  FeedBatch,
  FeedHealth,
  NormalizedIntelRecord,
  ObservableType,
} from "../../schemas/src/index";
import { parseIndicators } from "./upload";
export interface OptionalFeedConfig {
  enabled: boolean;
  apiKey?: string;
  endpoint?: string;
  allowedHost?: string;
  format?: "stix" | "misp" | "text" | "csv" | "json";
  /** TAXII objects per page (1-1000); servers may cap it lower. Default 100. */
  pageLimit?: number;
  /** Yeti only: import observables carrying all of these tags. */
  tags?: string[];
}
function approvedEndpoint(config: OptionalFeedConfig): URL {
  if (!config.endpoint || !config.allowedHost)
    throw new Error(
      "Operator-configured endpoint and allowlisted hostname required",
    );
  const url = new URL(config.endpoint);
  if (
    url.protocol !== "https:" ||
    url.hostname !== config.allowedHost ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443") ||
    /^(localhost|.*\.local|\d+\.\d+\.\d+\.\d+|\[.*\])$/.test(url.hostname)
  )
    throw new Error("Endpoint must use an explicitly approved HTTPS DNS host");
  return url;
}
function pageLimit(value: number | undefined) {
  return z.number().int().min(1).max(1000).catch(100).parse(value);
}
// Yeti stores every DNS name as `hostname`; normalisation decides domain vs
// hostname. Types without a reliable ThreatSieve equivalent are skipped.
const yetiTypes: Record<string, ObservableType | "dns"> = {
  ipv4: "ipv4",
  ipv6: "ipv6",
  cidr: "cidr",
  hostname: "dns",
  url: "url",
  email: "email",
  md5: "md5",
  sha1: "sha1",
  sha256: "sha256",
  ja3: "ja3",
  asn: "asn",
  mutex: "mutex",
  registry_key: "registry-key",
  user_agent: "user-agent",
};
const YetiTag = z.object({
  name: z.string().optional(),
  last_seen: z.string().optional(),
  fresh: z.boolean().optional(),
});
const YetiObservable = z.object({
  id: z.string().min(1),
  value: z.string().min(1),
  type: z.string(),
  modified: z.string(),
  // Yeti 2.x releases before the tag list change return a name-keyed map.
  tags: z.union([z.array(YetiTag), z.record(z.string(), YetiTag)]).default([]),
  context: z.array(z.record(z.string(), z.unknown())).default([]),
});
function yetiTimestamp(value: string): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error("Invalid Yeti timestamp");
  // Yeti filters at millisecond precision and its date filter is inclusive.
  return new Date(time).toISOString();
}
function observationDate(
  value: string | number | undefined,
): string | undefined {
  if (value === undefined) return undefined;
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}
export class OptionalFeed extends PublicFeed {
  constructor(
    id:
      | "otx"
      | "virustotal"
      | "greynoise"
      | "taxii"
      | "stix"
      | "misp-feed"
      | "yeti",
    name: string,
    repo: Repository,
    private config: OptionalFeedConfig,
    request: typeof fetch = (input, init) => fetch(input, init),
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
    if (this.id === "yeti") return this.fetchYeti(cursor);
    let url: URL;
    const started = new Date().toISOString();
    const resume = cursor?.startsWith("{")
      ? z
          .object({
            from: z.iso.datetime().optional(),
            next: z.string().max(2000),
            checkpoint: z.iso.datetime(),
          })
          .parse(JSON.parse(cursor))
      : null;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (this.id === "otx") {
      if (!this.config.apiKey) throw new Error("OTX credential required");
      url = new URL("https://otx.alienvault.com/api/v1/pulses/subscribed");
      if (resume?.from || (cursor && !resume))
        url.searchParams.set(
          "modified_since",
          z.iso.datetime().parse(resume?.from ?? cursor),
        );
      if (resume)
        url.searchParams.set(
          "page",
          z.coerce.number().int().positive().parse(resume.next).toString(),
        );
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
      url = approvedEndpoint(this.config);
      if (this.id === "taxii") {
        headers.Accept = "application/taxii+json;version=2.1";
        if (resume?.from || (cursor && !resume))
          url.searchParams.set(
            "added_after",
            z.iso.datetime().parse(resume?.from ?? cursor),
          );
        if (resume) url.searchParams.set("next", resume.next);
        url.searchParams.set("limit", String(pageLimit(this.config.pageLimit)));
      }
      if (this.config.apiKey)
        headers.Authorization = "Bearer " + this.config.apiKey;
    }
    const response = await this.request(url, {
      headers,
      redirect: "manual",
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
            Event: z
              .object({
                uuid: z.string().optional(),
                info: z.string().optional(),
                timestamp: z.string().optional(),
                Tag: z.array(z.object({ name: z.string() })).default([]),
                Galaxy: z.array(z.unknown()).default([]),
                Attribute: z
                  .array(z.record(z.string(), z.unknown()))
                  .default([]),
                Object: z
                  .array(
                    z.object({
                      uuid: z.string(),
                      name: z.string(),
                      Attribute: z
                        .array(z.record(z.string(), z.unknown()))
                        .default([]),
                    }),
                  )
                  .default([]),
              })
              .passthrough(),
          })
          .parse(raw);
        const e = body.Event;
        records = [
          ...e.Attribute,
          ...e.Object.flatMap((o) =>
            o.Attribute.map((a) => ({
              ...a,
              objectUuid: o.uuid,
              objectName: o.name,
            })),
          ),
        ].map((a) => ({
          ...a,
          eventUuid: e.uuid,
          eventInfo: e.info,
          eventTags: e.Tag.map((t) => t.name),
          eventGalaxies: e.Galaxy,
        }));
      } else records = [{ raw, observable: cursor }];
    }
    if (this.id === "taxii") {
      const page = z
        .object({
          more: z.boolean().default(false),
          next: z.string().max(2000).optional(),
        })
        .parse(raw);
      const checkpoint = z.iso
        .datetime()
        .parse(
          response.headers.get("X-TAXII-Date-Added-Last") ??
            resume?.checkpoint ??
            (cursor && !resume ? cursor : started),
        );
      if (page.more && !page.next)
        throw new Error("TAXII pagination requires a next token");
      if (page.more && page.next === resume?.next)
        throw new Error("TAXII returned a repeated next token");
      return {
        raw,
        records,
        more: page.more,
        cursor: page.more
          ? JSON.stringify({
              from: resume?.from ?? (cursor && !resume ? cursor : undefined),
              next: page.next,
              checkpoint,
            })
          : new Date(Date.parse(checkpoint) - 1).toISOString(),
      };
    }
    if (this.id === "otx") {
      const page = z
        .object({ next: z.string().nullable().optional() })
        .parse(raw);
      if (page.next) {
        const next = new URL(page.next);
        if (next.origin !== url.origin || next.pathname !== url.pathname)
          throw new Error("Unexpected OTX pagination endpoint");
        const number = z.coerce
          .number()
          .int()
          .positive()
          .parse(next.searchParams.get("page"));
        if (String(number) === resume?.next)
          throw new Error("Repeated OTX page");
        return {
          raw,
          records,
          more: true,
          cursor: JSON.stringify({
            from: resume?.from ?? (cursor && !resume ? cursor : undefined),
            next: String(number),
            checkpoint: resume?.checkpoint ?? started,
          }),
        };
      }
      return { raw, records, cursor: resume?.checkpoint ?? started };
    }
    return { raw, records, cursor: started };
  }
  /** Keyset pages on Yeti `modified` (inclusive filter). A page offset is only
   * used to step past a full page that shares one timestamp. */
  private async fetchYeti(cursor?: string): Promise<FeedBatch> {
    if (!this.config.apiKey) throw new Error("Yeti credential required");
    const base = approvedEndpoint(this.config);
    const api = (path: string) =>
      new URL(base.pathname.replace(/\/+$/, "") + "/api/v2/" + path, base);
    const resume = cursor?.startsWith("{")
      ? z
          .object({
            from: z.iso.datetime().optional(),
            page: z.number().int().nonnegative(),
          })
          .parse(JSON.parse(cursor))
      : { from: cursor ? z.iso.datetime().parse(cursor) : undefined, page: 0 };
    const auth = await this.request(api("auth/api-token"), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "x-yeti-apikey": this.config.apiKey,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(30000),
    });
    if (!auth.ok) throw new Error("Yeti authentication HTTP " + auth.status);
    const token = z
      .object({ access_token: z.string().min(1) })
      .parse(JSON.parse(await boundedText(auth, 64 * 1024))).access_token;
    const count = pageLimit(this.config.pageLimit);
    const query: Record<string, string | string[]> = {};
    if (resume.from) query.modified = ">" + resume.from;
    if (this.config.tags?.length) query.tags = this.config.tags;
    const response = await this.request(api("observables/search"), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify({
        query,
        sorting: [
          ["modified", true],
          ["value", true],
        ],
        count,
        page: resume.page,
      }),
      redirect: "manual",
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error("Provider HTTP " + response.status);
    const raw: unknown = JSON.parse(
      await boundedText(response, 8 * 1024 * 1024),
    );
    const records = z
      .object({ observables: z.array(z.unknown()) })
      .parse(raw).observables;
    const last = records.length
      ? yetiTimestamp(YetiObservable.parse(records.at(-1)).modified)
      : undefined;
    if (records.length < count)
      // Never fall back to the worker clock: Yeti stamps `modified` with its
      // own, so an empty first sync keeps the lower bound open.
      return {
        raw,
        records,
        cursor: last ?? resume.from ?? JSON.stringify({ page: 0 }),
      };
    const stalled = resume.from !== undefined && last === resume.from;
    return {
      raw,
      records,
      more: true,
      cursor: JSON.stringify(
        stalled
          ? { from: resume.from, page: resume.page + 1 }
          : { from: last, page: 0 },
      ),
    };
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
      observedAt?: string | number,
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
          observedAt: observationDate(observedAt),
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
              first_seen: z.string().optional(),
              last_seen: z.string().optional(),
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
              i.last_seen ?? i.first_seen,
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
                  last_analysis_date: z.number().int().nonnegative().optional(),
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
            malicious: (stats.malicious ?? 0) > 0 ? true : undefined,
            description:
              "VirusTotal engine results; engines are not counted as independent sources",
          },
          item.raw.data.id,
          item.raw.data.attributes.last_analysis_date,
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
              last_seen: z.string().optional(),
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
          item.raw.last_seen,
        ),
      ];
    }
    if (this.id === "yeti") {
      const item = YetiObservable.parse(input);
      const mapped = yetiTypes[item.type];
      if (!mapped) return [];
      let type: ObservableType;
      try {
        type = (
          await normalise(item.value, mapped === "dns" ? undefined : mapped)
        ).type;
      } catch {
        return [];
      }
      if (mapped === "dns" && type !== "domain" && type !== "hostname")
        return [];
      const tags = Array.isArray(item.tags)
        ? item.tags.flatMap((t) => (t.name ? [{ ...t, name: t.name }] : []))
        : Object.entries(item.tags).map(([name, t]) => ({ ...t, name }));
      const seen = tags
        .map((t) => (t.last_seen ? Date.parse(t.last_seen) : NaN))
        .filter(Number.isFinite);
      const record = await make(
        item.value,
        {
          description: "Observable recorded in Yeti",
          sourceClaim: "Recorded in Yeti",
          yetiId: item.id,
          yetiType: item.type,
          tags: tags.filter((t) => t.fresh !== false).map((t) => t.name),
          expiredTags: tags.filter((t) => t.fresh === false).map((t) => t.name),
          // Yeti often aggregates other feeds; keep the named upstreams visible.
          contextSources: [
            ...new Set(
              item.context.flatMap((c) =>
                typeof c.source === "string" ? [c.source] : [],
              ),
            ),
          ].slice(0, 20),
        },
        item.id,
        seen.length ? new Date(Math.max(...seen)).toISOString() : undefined,
      );
      record.observable = { value: item.value, type };
      return [record];
    }
    if (this.id === "misp-feed") {
      const item = z
        .object({
          uuid: z.string(),
          value: z.string(),
          type: z.string(),
          comment: z.string().optional(),
          to_ids: z.boolean().optional(),
          timestamp: z.string().optional(),
          first_seen: z.string().optional(),
          last_seen: z.string().optional(),
          eventUuid: z.string().optional(),
          eventInfo: z.string().optional(),
          eventTags: z.array(z.string()).default([]),
          Tag: z.array(z.object({ name: z.string() })).default([]),
        })
        .passthrough()
        .parse(input);
      const parts = item.type.includes("|")
        ? item.type.split("|")
        : [item.type];
      const values = item.type.includes("|")
        ? item.value.split("|")
        : [item.value];
      const supported: Record<string, string> = {
        "ip-src": "ipv4",
        "ip-dst": "ipv4",
        domain: "domain",
        hostname: "hostname",
        url: "url",
        md5: "md5",
        sha1: "sha1",
        sha256: "sha256",
        "email-src": "email",
        "email-dst": "email",
        mutex: "mutex",
        regkey: "registry-key",
        ja3: "ja3",
        ja4: "ja4",
        AS: "asn",
        "x509-fingerprint-sha256": "certificate",
      };
      const records: NormalizedIntelRecord[] = [];
      for (const [index, part] of parts.entries()) {
        if (!supported[part] || !values[index]) continue;
        const value = values[index]!;
        const type = (
          part.startsWith("ip-")
            ? value.includes(":")
              ? "ipv6"
              : "ipv4"
            : supported[part]
        ) as import("../../schemas/src/index").ObservableType;
        await normalise(value, type);
        const record = await make(
          value,
          {
            description: item.comment ?? item.eventInfo ?? "",
            to_ids: item.to_ids,
            mispUuid: item.uuid,
            eventUuid: item.eventUuid,
            tags: [...item.eventTags, ...item.Tag.map((t) => t.name)],
            misp: item,
          },
          item.uuid + ":" + part,
          item.last_seen ?? item.first_seen,
        );
        record.observable = { value, type };
        records.push(record);
      }
      return records;
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
