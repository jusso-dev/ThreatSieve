import type { IntelRelationship } from "../../schemas/src/index";
/** Unweighted shortest path through supplied, authorized edges only. */
export function shortestPath(
  edges: IntelRelationship[],
  from: string,
  to: string,
): string[] | null {
  const previous = new Map<string, string | null>([[from, null]]),
    queue = [from];
  for (let i = 0; i < queue.length; i++) {
    const node = queue[i]!;
    if (node === to) break;
    for (const edge of edges) {
      const next =
        edge.sourceEntityId === node
          ? edge.targetEntityId
          : edge.targetEntityId === node
            ? edge.sourceEntityId
            : null;
      if (next && !previous.has(next)) {
        previous.set(next, node);
        queue.push(next);
      }
    }
  }
  if (!previous.has(to)) return null;
  const result: string[] = [];
  let node: string | null = to;
  while (node !== null) {
    result.unshift(node);
    node = previous.get(node) ?? null;
  }
  return result;
}
export function connectedNodes(
  edges: IntelRelationship[],
  root: string,
  hidden: string[],
) {
  const allowed = edges.filter(
    (e) =>
      !hidden.includes(e.sourceEntityId) && !hidden.includes(e.targetEntityId),
  );
  const ids = new Set<string>([root]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const e of allowed)
      if (ids.has(e.sourceEntityId) || ids.has(e.targetEntityId)) {
        if (!ids.has(e.sourceEntityId) || !ids.has(e.targetEntityId))
          changed = true;
        ids.add(e.sourceEntityId);
        ids.add(e.targetEntityId);
      }
  }
  return ids;
}
