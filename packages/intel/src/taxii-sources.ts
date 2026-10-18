import { z } from "zod";
import { log } from "../../observability/src/index";

/**
 * Additional generic TAXII 2.1 sources, configured as JSON in the
 * `TAXII_SOURCES` Worker value. The original single slot (`TAXII_*`, source
 * id `taxii`) is unchanged. Each entry becomes its own source (`taxii-<name>`)
 * with its own checkpoint, lock, independence group, licence record, schedule
 * and TLP allow-list. Tokens stay in Worker secrets named by the entry.
 */
export const TlpLevel = z.enum([
  "clear",
  "green",
  "amber",
  "amber+strict",
  "red",
  "unmarked",
]);
export type TlpLevel = z.infer<typeof TlpLevel>;
const TlpSetting = z
  .union([TlpLevel, z.literal("white")])
  .transform((v): TlpLevel => (v === "white" ? "clear" : v));
export const TaxiiSourceConfig = z.object({
  id: z.string().regex(/^taxii-[a-z0-9][a-z0-9-]{0,38}$/),
  name: z.string().min(1).max(100),
  /** Collection objects URL, or the API root URL when `collection` is set. */
  endpoint: z.url(),
  allowed_host: z.string().min(1).max(253),
  collection: z
    .string()
    .regex(/^[A-Za-z0-9._~-]{1,200}$/)
    .optional(),
  /** Name of the Worker secret holding the bearer token. */
  api_key_secret: z
    .string()
    .regex(/^TAXII_[A-Z0-9_]{1,50}_(API_KEY|TOKEN)$/)
    .optional(),
  tlp: z.array(TlpSetting).min(1).default(["clear", "green"]),
  page_limit: z.number().int().min(1).max(1000).default(100),
  schedule: z.enum(["6h", "daily", "manual"]).default("6h"),
  license: z.string().min(1).max(200).default("Provider terms"),
  redistributable: z.boolean().default(false),
  commercial_use: z.boolean().nullable().default(null),
});
export type TaxiiSourceConfig = z.infer<typeof TaxiiSourceConfig>;

/** Invalid entries are skipped and logged, never partially applied. */
export function taxiiSourceConfigs(env: {
  TAXII_SOURCES?: string;
}): TaxiiSourceConfig[] {
  if (!env.TAXII_SOURCES?.trim()) return [];
  let raw: unknown;
  try {
    raw = JSON.parse(env.TAXII_SOURCES);
  } catch {
    log({ stage: "config", result: "error", error_type: "TaxiiSourcesJson" });
    return [];
  }
  if (!Array.isArray(raw)) return [];
  const configs: TaxiiSourceConfig[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const parsed = TaxiiSourceConfig.safeParse(entry);
    if (!parsed.success || seen.has(parsed.data.id)) {
      log({
        stage: "config",
        result: "error",
        error_type: "TaxiiSourceInvalid",
      });
      continue;
    }
    seen.add(parsed.data.id);
    configs.push(parsed.data);
  }
  return configs;
}
export function taxiiObjectsUrl(config: TaxiiSourceConfig) {
  if (!config.collection) return config.endpoint;
  const root = config.endpoint.replace(/\/+$/, "");
  return root + "/collections/" + config.collection + "/objects/";
}
/** Creates the source row (needed for checkpoints and locks) once. */
export async function ensureTaxiiSources(
  db: D1Database,
  configs: TaxiiSourceConfig[],
) {
  if (!configs.length) return;
  await db.batch(
    configs.map((c) =>
      db
        .prepare(
          "INSERT OR IGNORE INTO sources(id,name,independent_group,reliability,enabled,license,redistributable,commercial_use) VALUES(?,?,?,0.5,1,?,?,?)",
        )
        .bind(
          c.id,
          c.name,
          c.id,
          c.license,
          Number(c.redistributable),
          c.commercial_use === null ? null : Number(c.commercial_use),
        ),
    ),
  );
}

// Standard STIX 2.1 TLP 1.0 marking definitions and the TLP 2.0 extension's.
const TLP_MARKINGS: Record<string, Exclude<TlpLevel, "unmarked">> = {
  "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
  "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
  "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
  "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
  "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",
  "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",
  "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "amber",
  "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber+strict",
  "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",
};
const ORDER: TlpLevel[] = [
  "unmarked",
  "clear",
  "green",
  "amber",
  "amber+strict",
  "red",
];
/** The most restrictive recognised TLP marking on a STIX object. */
export function tlpOf(object: unknown): TlpLevel {
  const refs =
    object && typeof object === "object"
      ? (object as { object_marking_refs?: unknown }).object_marking_refs
      : undefined;
  let level: TlpLevel = "unmarked";
  if (Array.isArray(refs))
    for (const ref of refs) {
      const tlp = typeof ref === "string" ? TLP_MARKINGS[ref] : undefined;
      if (tlp && ORDER.indexOf(tlp) > ORDER.indexOf(level)) level = tlp;
    }
  return level;
}
export function tlpAllowed(object: unknown, allow: TlpLevel[]) {
  return allow.includes(tlpOf(object));
}
