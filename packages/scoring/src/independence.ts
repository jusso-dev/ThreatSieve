import type { SourceProvenance } from "../../schemas/src/index";

export type IndependencePolicy = { id: string; independent_group: string };
export function upstreamIdentity(p: SourceProvenance): string | undefined {
  return p.sourceRecordId
    ? JSON.stringify([p.sourceRecordNamespace ?? p.sourceId, p.sourceRecordId])
    : undefined;
}

/** Connected groups prevent a mirror or multiple reports from one producer
 * earning independent credit. Unknown origins fall back to provider policy. */
export function independentSourceCount(
  provenances: SourceProvenance[],
  policies: IndependencePolicy[] = [],
) {
  const parent = provenances.map((_, i) => i);
  const root = (i: number): number =>
    parent[i] === i ? i : (parent[i] = root(parent[i]!));
  const seen = new Map<string, number>();
  provenances.forEach((p, i) => {
    const origin = p.originalSourceId ?? p.sourceId;
    const group =
      policies.find((s) => s.id === p.sourceId)?.independent_group ??
      p.sourceId;
    const record = upstreamIdentity(p);
    for (const key of [
      "group:" + group,
      "origin:" + p.sourceId,
      "origin:" + origin,
      ...(record ? ["record:" + record] : []),
    ]) {
      const previous = seen.get(key);
      if (previous !== undefined) parent[root(i)] = root(previous);
      else seen.set(key, i);
    }
  });
  return new Set(parent.map((_, i) => root(i))).size;
}
