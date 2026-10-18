import {
  EnvironmentSchema,
  type Evidence,
  type IntelRelationship,
  type ObservableType,
  type Principal,
} from "../../schemas/src/index";
import {
  LookupRequest,
  type LookupResponse,
  type LookupResult,
  type LookupSection,
  type LookupSource,
} from "../../schemas/src/lookup";
import {
  entitiesById,
  evidenceFor,
  relationshipsFor,
  sourceLicences,
  visibleEntities,
  type SourceLicence,
} from "../../database/src/lookup";
import { entityId, normalise } from "../../intel/src/normalise";
import { DatasetReader, currentVersions } from "../../intel/src/datasets";
import { lookupAddress, lookupAsn } from "../../intel/src/network";
import { cveRecords } from "../../intel/src/cve";
import {
  LOOKUP_SOURCES,
  cachedEvidence,
  cachedOsv,
  claimLookups,
  lookupApplies,
  lookupConfigured,
  readLookupCache,
  type CachedLookup,
  type LookupEnv,
  type LookupItem,
  type LookupSourceId,
} from "../../intel/src/source-lookups";
import { Repository } from "../../database/src/repository";
import { scoreDossier } from "./scoring";
import { sourceReliabilities } from "./sources";

/** How long a client may reuse a fact, per source. Feeds sync every 6 hours. */
export const SOURCE_TTL_SECONDS: Record<string, number> = {
  iptoasn: 86400,
  epss: 86400,
  nvd: 21600,
  osv: 86400,
  greynoise: 86400,
  crowdsec: 86400,
};
const DEFAULT_TTL = 21600;
const NOT_FOUND_TTL = 3600;
const PENDING_TTL = 300;

interface Normalised {
  type: ObservableType;
  value: string;
  input: string;
  id: string;
}
type Item =
  | Normalised
  | { invalid: true; type: ObservableType; input: string; message: string };
interface Contribution {
  first: string[];
  last: string[];
  retrieved: string[];
  url: string | null;
  urlAt: string;
  redistributable: boolean;
}
const iso = (value: string | null | undefined) => {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
};
function externalIds(externalId: string | undefined): Record<string, string> {
  if (!externalId) return {};
  if (/^(TA|T|G|S|C|M|DS)\d{4}(\.\d{3})?$/.test(externalId))
    return { mitre: externalId };
  if (/^CVE-\d{4}-\d{4,}$/.test(externalId)) return { cve: externalId };
  return { external: externalId };
}
const SCANNER_PRIORITY = ["greynoise", "crowdsec"];

/**
 * Deterministic bulk lookup. Reads only stored intelligence, imported
 * datasets and cached source answers; never calls Workers AI. Cache misses
 * for rate-limited sources are claimed in bulk and refreshed by jobs on the
 * enrich queue; `dispatch` is called when jobs were queued. The number of
 * D1 statements is fixed, independent of the number of observables.
 */
export async function lookupObservables(
  env: LookupEnv,
  principal: Pick<Principal, "tenantId">,
  body: unknown,
  options: {
    now?: Date;
    /** Set to false to read caches without claiming refreshes. */
    refresh?: boolean;
    dispatch?: () => void;
  } = {},
): Promise<LookupResponse> {
  const now = options.now ?? new Date();
  const input = LookupRequest.parse(body);
  const include = new Set<LookupSection>(input.include);
  const tenant = principal.tenantId;

  const items: Item[] = [];
  const seen = new Set<string>();
  for (const o of input.observables) {
    let observable;
    try {
      observable = await normalise(o.value, o.type);
    } catch (error) {
      const key = "invalid:" + o.type + ":" + o.value;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push({
        invalid: true,
        type: o.type,
        input: o.value,
        message: error instanceof Error ? error.message : "Invalid observable",
      });
      continue;
    }
    if (seen.has(observable.id)) continue;
    seen.add(observable.id);
    items.push({
      type: observable.type,
      value: observable.normalizedValue,
      input: o.value,
      id: observable.id,
    });
  }
  const valid = items.filter((i): i is Normalised => !("invalid" in i));
  const { sources, disabled } = await sourceLicences(env.DB, tenant);
  const allowed = (id: string) =>
    !disabled.has(id) && (sources.get(id)?.enabled ?? 1) === 1;
  const reliabilities = await sourceReliabilities(env.DB, tenant);
  const reliability = new Map(reliabilities.map((s) => [s.id, s.reliability]));

  // Anchors: the observable, plus the vulnerability entity behind a CVE.
  const vulnerabilityIds = new Map<string, string>();
  for (const item of valid)
    if (item.type === "cve")
      vulnerabilityIds.set(
        item.id,
        await entityId("vulnerability", item.value),
      );
  const visible = await visibleEntities(env.DB, tenant, [
    ...valid.map((i) => i.id),
    ...vulnerabilityIds.values(),
  ]);
  const evidence = await evidenceFor(
    env.DB,
    tenant,
    valid.filter((i) => visible.has(i.id)).map((i) => i.id),
  );
  const anchorsFor = (item: Normalised) =>
    [item.id, vulnerabilityIds.get(item.id)].filter(
      (id): id is string => !!id && visible.has(id),
    );
  const relationships = include.has("relationships")
    ? await relationshipsFor(env.DB, tenant, valid.flatMap(anchorsFor))
    : new Map<string, IntelRelationship[]>();
  const targets = await entitiesById(
    env.DB,
    [...relationships.values()]
      .flat()
      .flatMap((r) => [r.sourceEntityId, r.targetEntityId]),
  );

  // Cached lookup sources, and refreshes for misses.
  const wanted = (source: (typeof LOOKUP_SOURCES)[number], item: Normalised) =>
    lookupApplies(source, item.type) &&
    lookupConfigured(env, source) &&
    allowed(source) &&
    (source === "osv" ? include.has("cve") : include.has("reputation"));
  const cache = await readLookupCache(env.DB, tenant, [
    ...new Set(
      valid
        .filter((item) => LOOKUP_SOURCES.some((s) => wanted(s, item)))
        .map((i) => i.id),
    ),
  ]);
  const fresh = (entry: CachedLookup | undefined) =>
    entry && Date.parse(entry.expiresAt) > now.getTime() ? entry : undefined;
  const pending = new Map<string, Set<string>>();
  const markPending = (key: string, source: string) =>
    (pending.get(key) ?? pending.set(key, new Set()).get(key)!).add(source);
  const misses = new Map<LookupSourceId, LookupItem[]>();
  for (const item of valid)
    for (const source of LOOKUP_SOURCES) {
      if (!wanted(source, item)) continue;
      const entry = fresh(cache.get(source + "|" + item.id));
      if (entry?.status === "pending") markPending(item.id, source);
      if (entry) continue;
      (misses.get(source) ?? misses.set(source, []).get(source)!).push({
        key: item.id,
        value: item.value,
      });
    }
  if (options.refresh !== false && misses.size) {
    const { claimed, later, jobs } = await claimLookups(
      env,
      tenant,
      misses,
      now,
    );
    // Claimed misses are being fetched; misses over this request's cap but
    // within today's budget will be claimed by the next lookup.
    for (const map of [claimed, later])
      for (const [source, items] of map)
        for (const item of items) markPending(item.key, source);
    if (jobs.length) {
      const repo = new Repository(env.DB);
      const at = now.toISOString();
      await env.DB.batch(
        jobs.flatMap((payload) =>
          repo.jobStatements({
            jobId: crypto.randomUUID(),
            tenantId: tenant,
            entityId: payload.source,
            stage: "enrich",
            attempt: 0,
            createdAt: at,
            correlationId: crypto.randomUUID(),
            payload: { ...payload },
          }),
        ),
      );
      options.dispatch?.();
    }
  }

  // Imported datasets and NVD records.
  const versions = await currentVersions(env.DB);
  const network =
    include.has("network") && allowed("iptoasn") && versions.get("iptoasn")
      ? new DatasetReader(
          env.ARCHIVE,
          "iptoasn",
          versions.get("iptoasn")!.version,
        )
      : null;
  const epssVersion = versions.get("epss");
  const epss =
    include.has("cve") && allowed("epss") && epssVersion
      ? new DatasetReader(env.ARCHIVE, "epss", epssVersion.version)
      : null;
  const cves = valid.filter((i) => i.type === "cve").map((i) => i.value);
  const nvd =
    include.has("cve") && allowed("nvd")
      ? await cveRecords(env.DB, cves)
      : new Map();
  const kevKnown =
    allowed("cisa-kev") && Boolean(sources.get("cisa-kev")?.last_sync);

  const results: LookupResult[] = [];
  for (const item of items) {
    if ("invalid" in item) {
      results.push({
        type: item.type as LookupResult["type"],
        value: item.input,
        input: item.input,
        found: false,
        entity_id: null,
        ttl_seconds: NOT_FOUND_TTL,
        error: { code: "INVALID_OBSERVABLE", message: item.message },
        pending_sources: [],
        reputation: null,
        network: null,
        cve: null,
        relationships: [],
        sources: [],
      });
      continue;
    }
    const contributions = new Map<string, Contribution>();
    const contribute = (
      sourceId: string,
      facts: {
        first?: string | null;
        last?: string | null;
        retrieved?: string | null;
        url?: string | null;
        redistributable?: boolean;
      },
    ) => {
      const c = contributions.get(sourceId) ?? {
        first: [],
        last: [],
        retrieved: [],
        url: null,
        urlAt: "",
        redistributable: true,
      };
      const first = iso(facts.first),
        last = iso(facts.last),
        retrieved = iso(facts.retrieved);
      if (first) c.first.push(first);
      if (last) c.last.push(last);
      if (retrieved) c.retrieved.push(retrieved);
      if (facts.url && (last ?? "") >= c.urlAt) {
        c.url = facts.url;
        c.urlAt = last ?? "";
      }
      if (facts.redistributable === false) c.redistributable = false;
      contributions.set(sourceId, c);
    };
    const stored = evidence.get(item.id) ?? [];
    const looked: Evidence[] = [];
    let osv = null;
    for (const source of LOOKUP_SOURCES) {
      if (!wanted(source, item)) continue;
      const entry = fresh(cache.get(source + "|" + item.id));
      if (!entry) continue;
      if (source === "osv") osv = cachedOsv(entry);
      else looked.push(...cachedEvidence(entry));
    }

    // Reputation: stored evidence plus cached lookups, scored by dossier-v1.
    let reputation: LookupResult["reputation"] = null;
    const reputationEvidence = [...stored, ...looked].filter(
      (e) => !disabled.has(e.sourceId),
    );
    if (
      include.has("reputation") &&
      item.type !== "cve" &&
      reputationEvidence.length
    ) {
      const dossier = scoreDossier(
        {
          id: item.id,
          type: "observable",
          name: item.value,
          description: "",
          aliases: [],
          data: {},
          provenance: {
            sourceId: "lookup",
            sourceName: "Lookup",
            retrievedAt: now.toISOString(),
            redistributable: false,
          },
        },
        reputationEvidence,
        reliabilities,
        EnvironmentSchema.parse({}),
        null,
        now.getTime(),
      );
      const scannerFacts = reputationEvidence
        .map((e) => {
          const s = e.data.scanner as
            | { isScanner?: unknown; benignService?: unknown; name?: unknown }
            | undefined;
          const isScanner = s?.isScanner === true || e.data.role === "scanning";
          const benign = s?.benignService === true;
          return isScanner || benign
            ? {
                sourceId: e.sourceId,
                isScanner,
                benign,
                name: typeof s?.name === "string" ? s.name : null,
              }
            : null;
        })
        .filter((s) => s !== null)
        .sort(
          (a, b) =>
            (SCANNER_PRIORITY.indexOf(a.sourceId) + 1 || 99) -
              (SCANNER_PRIORITY.indexOf(b.sourceId) + 1 || 99) ||
            a.sourceId.localeCompare(b.sourceId),
        );
      const malicious = reputationEvidence.some(
        (e) => e.data.malicious === true,
      );
      const benign =
        reputationEvidence.some((e) => e.data.malicious === false) ||
        scannerFacts.some((s) => s.benign);
      reputation = {
        classification:
          malicious && benign
            ? "suspicious"
            : malicious
              ? "malicious"
              : benign
                ? "benign"
                : scannerFacts.some((s) => s.isScanner)
                  ? "suspicious"
                  : "unknown",
        score: dossier.threat.value,
        confidence: dossier.confidence.value,
        scanner: scannerFacts.length
          ? {
              is_scanner: scannerFacts.some((s) => s.isScanner),
              benign_service: scannerFacts.some((s) => s.benign),
              name: scannerFacts.find((s) => s.name)?.name ?? null,
              source_id: scannerFacts[0]!.sourceId,
            }
          : null,
        tags: [
          ...new Set(
            reputationEvidence.flatMap((e) =>
              Array.isArray(e.data.tags)
                ? e.data.tags.filter((t): t is string => typeof t === "string")
                : [],
            ),
          ),
        ]
          .sort()
          .slice(0, 25),
      };
      for (const e of reputationEvidence)
        contribute(e.sourceId, {
          first: e.observedAt ?? e.createdAt,
          last: e.observedAt ?? e.createdAt,
          retrieved: e.provenance.retrievedAt,
          url: e.provenance.sourceUrl,
          redistributable: e.provenance.redistributable,
        });
    }

    // Network context from the imported IP-to-ASN dataset.
    let networkFacts: LookupResult["network"] = null;
    if (network && ["ipv4", "ipv6", "asn"].includes(item.type)) {
      networkFacts =
        item.type === "asn"
          ? await lookupAsn(network, Number(item.value.slice(2)))
          : await lookupAddress(network, item.value);
      if (networkFacts)
        contribute("iptoasn", {
          retrieved: versions.get("iptoasn")!.imported_at,
          url: "https://iptoasn.com/",
        });
    }

    // CVE context: NVD, EPSS, KEV and OSV merged by CVE identifier.
    let cve: LookupResult["cve"] = null;
    if (include.has("cve") && item.type === "cve") {
      const record = nvd.get(item.value);
      const score = epss ? await epss.exact("scores", item.value) : null;
      const kev = allowed("cisa-kev")
        ? stored.find((e) => e.sourceId === "cisa-kev" && e.data.kev === true)
        : undefined;
      if (record || score || kev || osv) {
        const text = (v: unknown) => (typeof v === "string" && v ? v : null);
        cve = {
          id: item.value,
          description:
            record?.description ||
            text(kev?.data.description) ||
            osv?.description ||
            null,
          published: record?.published ?? osv?.published ?? null,
          status: record?.status ?? null,
          cvss: record?.cvss ?? null,
          cwe: record?.cwe ?? [],
          kev: kev
            ? {
                listed: true,
                date_added: kev.observedAt?.slice(0, 10) ?? null,
                due_date: text(kev.data.dueDate),
                ransomware: text(kev.data.ransomware),
              }
            : kevKnown
              ? {
                  listed: false,
                  date_added: null,
                  due_date: null,
                  ransomware: null,
                }
              : null,
          epss: score
            ? {
                score: Number(score[1]),
                percentile: Number(score[2]),
                date: (
                  epssVersion!.source_updated_at ?? epssVersion!.imported_at
                ).slice(0, 10),
              }
            : null,
          osv_ids: osv?.ids ?? [],
          affected: record?.affected.length
            ? record.affected
            : kev && text(kev.data.vendor) && text(kev.data.product)
              ? [
                  {
                    vendor: text(kev.data.vendor)!,
                    product: text(kev.data.product)!,
                    versions: null,
                  },
                ]
              : (osv?.affected ?? []),
          references: record?.references ?? [],
        };
        if (record)
          contribute("nvd", {
            first: record.published,
            last: record.lastModified,
            retrieved: record.retrievedAt,
            url: "https://nvd.nist.gov/vuln/detail/" + item.value,
          });
        if (score)
          contribute("epss", {
            last: epssVersion!.source_updated_at,
            retrieved: epssVersion!.imported_at,
            url: "https://api.first.org/data/v1/epss?cve=" + item.value,
          });
        if (kev)
          contribute("cisa-kev", {
            first: kev.observedAt,
            last: kev.observedAt,
            retrieved: kev.provenance.retrievedAt,
            url: kev.provenance.sourceUrl,
            redistributable: kev.provenance.redistributable,
          });
        if (osv) {
          contribute("osv", {
            first: osv.published,
            last: osv.modified,
            // The OSV cache is shared by all tenants; its fetch time would
            // reveal when another tenant looked the CVE up.
            retrieved: null,
            url: "https://osv.dev/vulnerability/" + encodeURIComponent(osv.id),
          });
        }
      }
    }

    // Relationships around the observable (and a CVE's vulnerability entity).
    const related: LookupResult["relationships"] = [];
    const relationshipIds = new Set<string>();
    for (const anchor of anchorsFor(item))
      for (const r of relationships.get(anchor) ?? []) {
        if (relationshipIds.has(r.id)) continue;
        const outgoing = r.sourceEntityId === anchor;
        const target = targets.get(
          outgoing ? r.targetEntityId : r.sourceEntityId,
        );
        if (!target) continue;
        relationshipIds.add(r.id);
        related.push({
          id: r.id,
          type: r.relationshipType.toLowerCase().replace(/_/g, "-"),
          direction: outgoing ? "outgoing" : "incoming",
          assertion: r.assertionType,
          confidence: Math.round(r.confidence * 100),
          source_id: r.provenance.sourceId,
          target: {
            id: target.id,
            type: target.type,
            name: target.name,
            aliases: target.aliases,
            external_ids: externalIds(target.externalId),
          },
        });
        contribute(r.provenance.sourceId, {
          first: r.firstSeen,
          last: r.lastSeen,
          retrieved: r.provenance.retrievedAt,
          url: r.provenance.sourceUrl,
          redistributable: r.provenance.redistributable,
        });
      }
    related.sort(
      (a, b) => b.confidence - a.confidence || a.id.localeCompare(b.id),
    );
    const relationshipList = related.slice(0, 25);

    const sourceList: LookupSource[] = [...contributions.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, c]) => {
        const row: SourceLicence | undefined = sources.get(id);
        return {
          source_id: id,
          name: row?.name ?? id,
          license: row?.license ?? null,
          redistributable: row?.redistributable === 1 && c.redistributable,
          commercial_use:
            row?.commercial_use === null || row?.commercial_use === undefined
              ? null
              : row.commercial_use === 1,
          reliability: reliability.get(id) ?? 0.5,
          first_seen: c.first.sort()[0] ?? null,
          last_seen: c.last.sort().at(-1) ?? null,
          retrieved_at: c.retrieved.sort().at(-1) ?? null,
          source_url: c.url,
        };
      });
    const found = Boolean(
      visible.has(item.id) || reputation || cve || relationshipList.length,
    );
    const pendingSources = [...(pending.get(item.id) ?? [])].sort();
    let ttl = sourceList.length
      ? Math.min(
          ...sourceList.map(
            (s) => SOURCE_TTL_SECONDS[s.source_id] ?? DEFAULT_TTL,
          ),
        )
      : found
        ? DEFAULT_TTL
        : NOT_FOUND_TTL;
    if (pendingSources.length) ttl = Math.min(ttl, PENDING_TTL);
    results.push({
      type: item.type as LookupResult["type"],
      value: item.value,
      input: item.input,
      found,
      entity_id: visible.has(item.id) ? item.id : null,
      ttl_seconds: ttl,
      pending_sources: pendingSources,
      reputation,
      network: networkFacts,
      cve,
      relationships: relationshipList,
      sources: sourceList,
    });
  }
  return { as_of: now.toISOString(), results };
}
