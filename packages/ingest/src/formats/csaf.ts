import { z } from "zod";
import type { TlpInput } from "../schema";
import {
  clip,
  documentIssues,
  httpLinks,
  isRecord,
  records,
  str,
  type Mapped,
} from "./common";

const date = z.iso.datetime({ offset: true });
const Reference = z.looseObject({
  url: z.string(),
  summary: z.string().optional(),
});
const Note = z.looseObject({ category: z.string(), text: z.string() });
const Cvss = z.looseObject({
  version: z.string(),
  baseScore: z.number().min(0).max(10),
  vectorString: z.string(),
});
/** The CSAF 2.0 fields the mapper reads; other properties are kept in `raw`. */
export const CsafDocument = z.looseObject({
  document: z.looseObject({
    category: z.string().min(1),
    csaf_version: z.literal("2.0"),
    title: z.string().min(1),
    publisher: z.looseObject({
      category: z.string(),
      name: z.string().min(1),
      namespace: z.url(),
    }),
    tracking: z.looseObject({
      id: z.string().min(1).max(256),
      current_release_date: date,
      initial_release_date: date,
      status: z.enum(["draft", "final", "interim"]),
      version: z.string().min(1),
      revision_history: z.array(z.unknown()).min(1),
    }),
    distribution: z
      .looseObject({
        tlp: z
          .looseObject({ label: z.enum(["AMBER", "GREEN", "RED", "WHITE"]) })
          .optional(),
      })
      .optional(),
    aggregate_severity: z.looseObject({ text: z.string().min(1) }).optional(),
    notes: z.array(Note).optional(),
    references: z.array(Reference).optional(),
  }),
  product_tree: z.looseObject({}).optional(),
  vulnerabilities: z
    .array(
      z.looseObject({
        cve: z.string().optional(),
        cwe: z.looseObject({ id: z.string() }).optional(),
        notes: z.array(Note).optional(),
        references: z.array(Reference).optional(),
        product_status: z.record(z.string(), z.array(z.string())).optional(),
        scores: z
          .array(
            z.looseObject({
              cvss_v2: Cvss.optional(),
              cvss_v3: Cvss.optional(),
            }),
          )
          .optional(),
        threats: z
          .array(z.looseObject({ category: z.string(), details: z.string() }))
          .optional(),
      }),
    )
    .optional(),
});

interface Leaf {
  vendor?: string;
  product: string;
  version?: string;
  range?: string;
  cpe?: string;
  purl?: string;
}
/** Resolves every product_id in the tree to vendor, product and version. */
function productIndex(tree: unknown) {
  const index = new Map<string, Leaf>();
  const helper = (p: Record<string, unknown>) => {
    const h = isRecord(p.product_identification_helper)
      ? p.product_identification_helper
      : {};
    return { cpe: str(h.cpe), purl: str(h.purl) };
  };
  const walk = (branches: unknown, context: Partial<Leaf>, depth: number) => {
    if (depth > 30) return;
    for (const branch of records(branches)) {
      const name = str(branch.name);
      const next = { ...context };
      switch (branch.category) {
        case "vendor":
          next.vendor = name;
          break;
        case "product_name":
        case "product_family":
          next.product = name;
          break;
        case "product_version":
          next.version = name;
          break;
        case "product_version_range":
          next.range = name;
          break;
        case "service_pack":
        case "patch_level":
          next.version = name;
      }
      if (isRecord(branch.product) && str(branch.product.product_id))
        index.set(String(branch.product.product_id), {
          ...next,
          product:
            next.product ?? str(branch.product.name) ?? "Unknown product",
          ...helper(branch.product),
        });
      walk(branch.branches, next, depth + 1);
    }
  };
  if (isRecord(tree)) {
    walk(tree.branches, {}, 0);
    for (const p of records(tree.full_product_names))
      if (str(p.product_id))
        index.set(String(p.product_id), {
          product: str(p.name) ?? String(p.product_id),
          ...helper(p),
        });
    for (const r of records(tree.relationships)) {
      const p = isRecord(r.full_product_name) ? r.full_product_name : {};
      if (str(p.product_id) && !index.has(String(p.product_id)))
        index.set(String(p.product_id), {
          ...(index.get(String(r.product_reference)) ?? {
            product: str(p.name) ?? String(p.product_id),
          }),
          ...helper(p),
        });
    }
  }
  return index;
}

const AFFECTED = [
  "known_affected",
  "first_affected",
  "last_affected",
  "under_investigation",
];
const FIXED = ["fixed", "first_fixed"];
const TLP: Record<string, TlpInput> = {
  WHITE: "clear",
  GREEN: "green",
  AMBER: "amber",
  RED: "red",
};

/** Maps one CSAF 2.0 document to one advisory. */
export function mapCsaf(document: unknown): Mapped[] {
  const parsed = CsafDocument.safeParse(document);
  if (!parsed.success) {
    const id =
      isRecord(document) &&
      isRecord(document.document) &&
      isRecord(document.document.tracking)
        ? str(document.document.tracking.id)
        : undefined;
    return [
      { source_ref: id, issues: documentIssues(parsed.error), warnings: [] },
    ];
  }
  const { document: d, vulnerabilities = [] } = parsed.data;
  const warnings: string[] = [];
  const note =
    ["summary", "description", "general"]
      .map((c) => d.notes?.find((n) => n.category === c)?.text)
      .find((t) => t?.trim()) ?? vulnerabilities[0]?.notes?.[0]?.text;

  let best: { version: string; score: number; vector: string } | undefined;
  for (const v of vulnerabilities)
    for (const s of v.scores ?? [])
      for (const c of [s.cvss_v3, s.cvss_v2])
        if (c && (!best || c.baseScore > best.score))
          best = {
            version: c.version,
            score: c.baseScore,
            vector: c.vectorString,
          };
  if (best && !["2.0", "3.0", "3.1"].includes(best.version)) {
    warnings.push("Unsupported CVSS version " + best.version + " ignored");
    best = undefined;
  }

  const index = productIndex(parsed.data.product_tree);
  const products = new Map<
    string,
    {
      vendor?: string;
      product: string;
      cpe?: string;
      purl?: string;
      versions: Record<string, string>[];
    }
  >();
  let unresolved = 0;
  for (const v of vulnerabilities)
    for (const [status, ids] of Object.entries(v.product_status ?? {})) {
      const fixed = FIXED.includes(status);
      if (!fixed && !AFFECTED.includes(status)) continue;
      for (const id of ids) {
        const leaf = index.get(id);
        if (!leaf) {
          unresolved++;
          continue;
        }
        const key = JSON.stringify([
          leaf.vendor,
          leaf.product,
          leaf.cpe,
          leaf.purl,
        ]);
        const entry = products.get(key) ?? {
          ...(leaf.vendor ? { vendor: leaf.vendor.slice(0, 200) } : {}),
          product: leaf.product.slice(0, 300),
          ...(leaf.cpe ? { cpe: leaf.cpe } : {}),
          ...(leaf.purl ? { purl: leaf.purl } : {}),
          versions: [],
        };
        const version = leaf.range
          ? { range: leaf.range.slice(0, 500) }
          : leaf.version
            ? { [fixed ? "fixed" : "version"]: leaf.version.slice(0, 200) }
            : undefined;
        if (
          version &&
          !entry.versions.some(
            (x) => JSON.stringify(x) === JSON.stringify(version),
          )
        )
          entry.versions.push(version);
        products.set(key, entry);
      }
    }
  if (unresolved)
    warnings.push(
      unresolved + " product_id reference(s) not found in product_tree",
    );
  const affected = [...products.values()].slice(0, 1000).map((p) => {
    if (p.versions.length > 200)
      warnings.push("Versions of " + p.product + " truncated to 200");
    const { versions, ...rest } = p;
    return versions.length
      ? { ...rest, versions: versions.slice(0, 200) }
      : rest;
  });
  if (products.size > 1000)
    warnings.push("Affected products truncated to 1000");

  const severity =
    d.aggregate_severity?.text ??
    vulnerabilities
      .flatMap((v) => v.threats ?? [])
      .find((t) => t.category === "impact")?.details;
  const label = d.distribution?.tlp?.label;
  return [
    {
      source_ref: d.tracking.id,
      warnings,
      item: {
        type: "advisory",
        external_id: d.tracking.id,
        title: clip(d.title, 1000, "title", warnings),
        summary: clip(note, 65536, "summary", warnings),
        ...(severity ? { vendor_severity: severity.slice(0, 64) } : {}),
        source: {
          name: d.publisher.name.slice(0, 200),
          ...(/^https?:/i.test(d.publisher.namespace)
            ? { url: d.publisher.namespace }
            : {}),
          ...(d.publisher.category === "vendor"
            ? { vendor: d.publisher.name.slice(0, 200) }
            : {}),
        },
        published_at: d.tracking.initial_release_date,
        updated_at: d.tracking.current_release_date,
        cve_ids: [
          ...new Set(
            vulnerabilities.map((v) => v.cve).filter((c): c is string => !!c),
          ),
        ],
        ...(best ? { cvss: best } : {}),
        affected_products: affected,
        references: httpLinks(
          [
            ...(d.references ?? []),
            ...vulnerabilities.flatMap((v) => v.references ?? []),
          ].map((r) => ({ url: r.url, title: r.summary })),
          warnings,
        ),
        tags: [
          ...new Set([
            "csaf:" + d.category,
            ...vulnerabilities
              .map((v) => v.cwe?.id)
              .filter((c): c is string => !!c),
          ]),
        ]
          .map((t) => t.slice(0, 100))
          .slice(0, 100),
        ...(label ? { tlp: TLP[label] } : {}),
        raw: document,
      },
    },
  ];
}
