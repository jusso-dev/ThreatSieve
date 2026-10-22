import ipaddr from "ipaddr.js";
import { digest, normalizeValue } from "../../intel/src/normalise";
import {
  NativeItem,
  type IndicatorType,
  type IngestFormat,
  type ItemIssue,
  type Normalisation,
  type NormalisedIndicator,
  type NormalisedItem,
  type Severity,
  type TlpInput,
} from "./schema";
import { cvssSeverity, mapVendorSeverity, parseCvssVector } from "./severity";

// C0/C1 controls (except tab and newline), zero-width and bidi-override
// characters can hide or reorder text when it is displayed.
const INVISIBLE: [number, number][] = [
  [0x00, 0x08],
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
];
const invisible = (char: string) => {
  const code = char.codePointAt(0)!;
  return INVISIBLE.some(([from, to]) => code >= from && code <= to);
};

/** Linear-time removal of `<!-- … -->`; an unclosed comment is left as text. */
function withoutComments(value: string) {
  let out = "";
  let at = 0;
  for (;;) {
    const start = value.indexOf("<!--", at);
    const end = start < 0 ? -1 : value.indexOf("-->", start + 4);
    if (end < 0) return out + value.slice(at);
    out += value.slice(at, start);
    at = end + 3;
  }
}

/**
 * Reduces untrusted text to plain display text: markup tags and invisible or
 * direction-changing characters are removed. Renderers must still escape it.
 */
export function sanitizeText(value: string, multiline = false): string {
  let text = withoutComments(value)
    .normalize("NFC")
    .replace(/<\/?[A-Za-z][^<>]*>/g, "")
    .replace(/\r\n?/g, "\n");
  text = [...text].filter((char) => !invisible(char)).join("");
  text = multiline
    ? text
        .replace(/[^\S\n]+/g, " ")
        .replace(/ *\n */g, "\n")
        .replace(/\n{3,}/g, "\n\n")
    : text.replace(/\s+/g, " ");
  return text.trim();
}

/** Reverses common defanging so `hxxp://evil[.]example` validates. */
export function refang(value: string): string {
  return value
    .trim()
    .replace(/^hxxp(s?)/i, "http$1")
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}/gi, ".")
    .replace(/\[(?:@|at)\]|\((?:@|at)\)/gi, "@")
    .replace(/\[:\]/g, ":");
}

/** Display form that cannot be clicked, resolved or pasted into a browser. */
export function defang(type: IndicatorType, value: string): string {
  switch (type) {
    case "url": {
      const match = /^(https?):\/\/([^/?#]*)(.*)$/i.exec(value);
      if (!match) return value.replace(/\./g, "[.]");
      return (
        match[1]!.toLowerCase().replace("http", "hxxp") +
        "[://]" +
        match[2]!.replace(/\./g, "[.]") +
        match[3]
      );
    }
    case "domain":
    case "ipv4":
      return value.replace(/\./g, "[.]");
    case "ipv6":
      return value.replace(/:/g, "[:]");
    case "cidr":
      return value.includes(":")
        ? value.replace(/:/g, "[:]")
        : value.replace(/\./g, "[.]");
    case "email": {
      const at = value.lastIndexOf("@");
      return (
        value.slice(0, at) + "[@]" + value.slice(at + 1).replace(/\./g, "[.]")
      );
    }
    default:
      return value;
  }
}

function timestamp(value: string): string {
  // Date keeps millisecond precision; STIX and OSV may send up to nanoseconds.
  return new Date(value.replace(/(\.\d{3})\d+/, "$1")).toISOString();
}

export interface NormaliseContext {
  format: IngestFormat;
  /** Applied when the item carries no TLP marking. */
  defaultTlp?: TlpInput;
  /** Source names this API key may submit for; undefined means any. */
  allowedSources?: string[];
  /** Notes from the format mapper, reported with the item. */
  warnings?: string[];
}
export type NormaliseResult =
  | {
      ok: true;
      item: NormalisedItem;
      raw: unknown;
      normalisation: Normalisation;
    }
  | { ok: false; issues: ItemIssue[]; external_id?: string };

/** Lower-cased, whitespace-collapsed source name used in the dedupe key. */
export function sourceKey(name: string) {
  return sanitizeText(name).normalize("NFKC").toLowerCase();
}
export async function itemId(
  tenantId: string,
  source: string,
  externalId: string,
) {
  const hash = await digest(
    tenantId + "\n" + sourceKey(source) + "\n" + externalId,
  );
  return "ing_" + hash.slice(0, 40);
}

/**
 * Validates one item against the native schema and returns its normalised
 * form plus a record of every change made. Never throws on bad input.
 */
export async function normaliseItem(
  input: unknown,
  context: NormaliseContext,
): Promise<NormaliseResult> {
  const parsed = NativeItem.safeParse(input);
  const externalHint =
    input && typeof input === "object" && "external_id" in input
      ? String((input as { external_id: unknown }).external_id).slice(0, 256)
      : undefined;
  if (!parsed.success)
    return {
      ok: false,
      external_id: externalHint,
      issues: parsed.error.issues.map((i) => ({
        path: i.path.map((p) => (typeof p === "symbol" ? String(p) : p)),
        message: i.message,
      })),
    };
  const v = parsed.data;
  const issues: ItemIssue[] = [];
  const changes: Normalisation["changes"] = [];
  const warnings = [...(context.warnings ?? [])];
  const brief = (v: unknown) =>
    typeof v === "string" && v.length > 500 ? v.slice(0, 500) + "…" : v;
  const change = (path: (string | number)[], from: unknown, to: unknown) => {
    if (from !== to && changes.length < 200)
      changes.push({ path, from: brief(from), to: brief(to) });
  };
  const clean = (
    path: (string | number)[],
    value: string,
    multiline = false,
  ) => {
    const out = sanitizeText(value, multiline);
    if (out !== value) change(path, value, out);
    return out;
  };

  const title = clean(["title"], v.title);
  if (!title)
    issues.push({
      path: ["title"],
      message: "Title is empty after sanitising",
    });
  const summary =
    v.summary === undefined
      ? null
      : clean(["summary"], v.summary, true) || null;
  const source = {
    name: clean(["source", "name"], v.source.name),
    url: v.source.url ?? null,
    vendor:
      v.source.vendor === undefined
        ? null
        : clean(["source", "vendor"], v.source.vendor) || null,
  };
  if (!source.name)
    issues.push({
      path: ["source", "name"],
      message: "Source name is empty after sanitising",
    });
  if (
    context.allowedSources &&
    !context.allowedSources.map(sourceKey).includes(sourceKey(source.name))
  )
    issues.push({
      path: ["source", "name"],
      message: "This API key may not submit items for this source",
    });

  let externalId = v.external_id?.trim();
  if (
    externalId !== undefined &&
    [...externalId].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    issues.push({
      path: ["external_id"],
      message: "External ID contains control characters",
    });
  const dates = {
    published_at: null as string | null,
    updated_at: null as string | null,
  };
  for (const key of ["published_at", "updated_at"] as const) {
    const value = v[key];
    if (value === undefined) continue;
    dates[key] = timestamp(value);
    change([key], value, dates[key]);
  }

  const cveIds: string[] = [];
  v.cve_ids?.forEach((cve, i) => {
    const upper = cve.toUpperCase();
    change(["cve_ids", i], cve, upper);
    if (!cveIds.includes(upper)) cveIds.push(upper);
  });

  let externalIdSource: NormalisedItem["external_id_source"] = "provided";
  if (!externalId) {
    // Without a producer ID the content identifies the item, so an edited
    // title or date creates a new record rather than updating one. Hashing
    // normalised values keeps equivalent resubmissions on the same record.
    externalId =
      "sha256:" +
      (await digest(
        JSON.stringify([v.type, title, dates.published_at, [...cveIds].sort()]),
      ));
    externalIdSource = "derived";
    warnings.push(
      "No external_id; derived one from type, title, published_at and cve_ids",
    );
  }

  let cvss: NormalisedItem["cvss"] = null;
  if (v.cvss) {
    let score = v.cvss.score ?? null;
    const vector = v.cvss.vector?.trim() ?? null;
    if (vector) {
      const checked = parseCvssVector(v.cvss.version, vector);
      if (!checked.ok)
        issues.push({ path: ["cvss", "vector"], message: checked.message });
      else if (score === null && checked.score !== null) {
        score = checked.score;
        change(["cvss", "score"], undefined, score);
      } else if (
        checked.score !== null &&
        score !== null &&
        Math.abs(checked.score - score) > 0.1
      )
        warnings.push(
          "CVSS score " +
            score +
            " differs from the vector's base score " +
            checked.score +
            "; kept the supplied score",
        );
    }
    cvss = { version: v.cvss.version, score, vector };
  }

  let severity: Severity = "info";
  let severitySource: NormalisedItem["severity_source"] = "default";
  const vendorSeverity = v.vendor_severity ?? null;
  const vendorMapped =
    vendorSeverity === null ? null : mapVendorSeverity(vendorSeverity);
  if (vendorSeverity !== null && !vendorMapped)
    warnings.push(
      "Vendor severity " +
        JSON.stringify(vendorSeverity) +
        " is not recognised",
    );
  if (v.severity) {
    severity = v.severity;
    severitySource = "provided";
  } else if (vendorMapped) {
    severity = vendorMapped;
    severitySource = "vendor";
  } else if (cvss?.score != null) {
    severity = cvssSeverity(cvss.score, cvss.version);
    severitySource = "cvss";
  } else
    warnings.push(
      "No severity, vendor severity or CVSS score; defaulted to info",
    );
  if (severitySource !== "provided") change(["severity"], v.severity, severity);

  const indicators: NormalisedIndicator[] = [];
  const seen = new Map<string, NormalisedIndicator>();
  v.indicators?.forEach((indicator, i) => {
    const input = refang(indicator.value);
    let value: string;
    try {
      value = normalizeValue(input, indicator.type);
    } catch (error) {
      issues.push({
        path: ["indicators", i, "value"],
        // URL parsing errors name the parser, not the field; keep ours stable.
        message:
          error instanceof Error && !(error instanceof TypeError)
            ? error.message
            : "Invalid " + indicator.type,
      });
      return;
    }
    if (indicator.type === "domain" && !value.includes("."))
      return issues.push({
        path: ["indicators", i, "value"],
        message: "Invalid domain",
      });
    if (["ipv4", "ipv6"].includes(indicator.type)) {
      const range = ipaddr.parse(value).range();
      if (range !== "unicast")
        warnings.push(
          "Indicator " + i + " is a " + range + " address, not a public one",
        );
    }
    change(["indicators", i, "value"], indicator.value, value);
    const key = indicator.type + ":" + value;
    const existing = seen.get(key);
    if (existing) {
      if ((indicator.confidence ?? -1) > (existing.confidence ?? -1))
        existing.confidence = indicator.confidence;
      return;
    }
    const normalised: NormalisedIndicator = {
      type: indicator.type,
      value,
      display_value: defang(indicator.type, value),
      ...(indicator.confidence === undefined
        ? {}
        : { confidence: indicator.confidence }),
    };
    seen.set(key, normalised);
    indicators.push(normalised);
  });

  const attack = [
    ...new Set(v.attack_techniques?.map((t) => t.toUpperCase()) ?? []),
  ];
  const tags: string[] = [];
  v.tags?.forEach((tag, i) => {
    const out = clean(["tags", i], tag);
    if (out && !tags.some((t) => t.toLowerCase() === out.toLowerCase()))
      tags.push(out);
  });
  const references: NormalisedItem["references"] = [];
  v.references?.forEach((ref, i) => {
    if (references.some((r) => r.url === ref.url)) return;
    const title =
      ref.title === undefined
        ? undefined
        : clean(["references", i, "title"], ref.title);
    references.push(title ? { url: ref.url, title } : { url: ref.url });
  });
  const products = (v.affected_products ?? []).map((p, i) => ({
    ...p,
    product: clean(["affected_products", i, "product"], p.product),
    ...(p.vendor === undefined
      ? {}
      : { vendor: clean(["affected_products", i, "vendor"], p.vendor) }),
  }));

  let tlpInput = v.tlp;
  let tlpSource: NormalisedItem["tlp_source"] = "provided";
  if (!tlpInput) {
    // Unmarked items stay inside the tenant: fail closed to AMBER.
    tlpInput = context.defaultTlp ?? "amber";
    tlpSource = "default";
  }
  const tlp = tlpInput === "white" ? "clear" : tlpInput;
  if (tlp !== v.tlp) change(["tlp"], v.tlp, tlp);

  if (issues.length) return { ok: false, issues, external_id: externalId };
  return {
    ok: true,
    raw: v.raw,
    normalisation: { changes, warnings },
    item: {
      type: v.type,
      format: context.format,
      external_id: externalId,
      external_id_source: externalIdSource,
      title,
      summary,
      severity,
      severity_source: severitySource,
      vendor_severity: vendorSeverity,
      source,
      ...dates,
      cve_ids: cveIds,
      cvss,
      affected_products: products,
      indicators,
      attack_techniques: attack,
      references,
      tags,
      tlp,
      tlp_source: tlpSource,
    },
  };
}
