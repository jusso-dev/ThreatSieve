"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Network, ArrowUpRight, Plus, Minus, RotateCcw } from "lucide-react";
import { useApi } from "@/lib/api";
import { percent } from "@/lib/utils";
import { Button } from "./ui/button";
import { DataState } from "./shell";
import type {
  IntelEntity,
  IntelRelationship,
} from "../../../packages/schemas/src/index";

export function IntelligenceGraph({ entityId }: { entityId: string }) {
  const [depth, setDepth] = useState("2"),
    [selected, setSelected] = useState(""),
    [mode, setMode] = useState("graph"),
    [zoom, setZoom] = useState(1);
  const { data, error, loading } = useApi<{
    nodes: IntelEntity[];
    edges: IntelRelationship[];
    truncated: boolean;
  }>("v1/graph/" + encodeURIComponent(entityId) + "?depth=" + depth);
  const layout = useMemo(() => {
    const nodes = data?.nodes ?? [];
    const edges = data?.edges ?? [];
    const levels = new Map<string, number>([[entityId, 0]]);
    let frontier = [entityId];
    for (let d = 1; d <= 3; d++) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const edge of edges) {
          const other =
            edge.sourceEntityId === id
              ? edge.targetEntityId
              : edge.targetEntityId === id
                ? edge.sourceEntityId
                : null;
          if (other && !levels.has(other)) {
            levels.set(other, d);
            next.push(other);
          }
        }
      }
      frontier = next;
    }
    const counts = new Map<number, number>();
    const positions = new Map(
      nodes.map((node) => {
        const level = levels.get(node.id) ?? 1;
        const row = counts.get(level) ?? 0;
        counts.set(level, row + 1);
        return [node.id, { x: 24 + level * 260, y: 30 + row * 110 }];
      }),
    );
    return {
      positions,
      width: Math.max(620, (Math.max(0, ...levels.values()) + 1) * 260 + 24),
      height: Math.max(290, Math.max(0, ...counts.values()) * 110 + 30),
    };
  }, [data, entityId]);
  const node = data?.nodes.find((n) => n.id === (selected || entityId));
  const byId = new Map(data?.nodes.map((n) => [n.id, n]) ?? []);
  const edges =
    mode === "list"
      ? (data?.edges ?? [])
      : (data?.edges.filter(
          (e) => e.sourceEntityId === node?.id || e.targetEntityId === node?.id,
        ) ?? []);
  return (
    <section className="panel graph-panel" id="relationships">
      <div className="section-title">
        <h2>
          <Network size={17} />
          Intelligence graph
        </h2>
        <span className="muted">
          {data?.nodes.length ?? 0} entities · {data?.edges.length ?? 0}{" "}
          relationships
        </span>
      </div>
      <p className="panel-subtitle">
        Arrows follow the source relationship. Dashed lines indicate model
        inference, not established fact.
      </p>
      <div className="graph-toolbar">
        <div className="segmented-control" aria-label="Relationship view">
          <button
            aria-pressed={mode === "graph"}
            onClick={() => setMode("graph")}
          >
            Graph
          </button>
          <button
            aria-pressed={mode === "list"}
            onClick={() => setMode("list")}
          >
            Relationship list
          </button>
        </div>
        <label className="filter-field">
          <span>Graph depth</span>
          <select
            aria-label="Graph depth"
            value={depth}
            onChange={(e) => {
              setDepth(e.target.value);
              setSelected("");
            }}
          >
            {[1, 2, 3].map((d) => (
              <option key={d} value={d}>
                {d} hop{d > 1 ? "s" : ""}
              </option>
            ))}
          </select>
        </label>
        {mode === "graph" && (
          <div className="actions">
            <Button
              size="sm"
              variant="outline"
              aria-label="Zoom out"
              disabled={zoom <= 0.6}
              onClick={() => setZoom((z) => Math.max(0.6, z - 0.2))}
            >
              <Minus size={14} />
            </Button>
            <span className="mono">{Math.round(zoom * 100)}%</span>
            <Button
              size="sm"
              variant="outline"
              aria-label="Zoom in"
              disabled={zoom >= 1.4}
              onClick={() => setZoom((z) => Math.min(1.4, z + 0.2))}
            >
              <Plus size={14} />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Reset graph zoom"
              onClick={() => setZoom(1)}
            >
              <RotateCcw size={14} />
            </Button>
          </div>
        )}
      </div>
      <DataState loading={loading} error={error} />
      {data && !loading && (
        <>
          {mode === "graph" && (
            <div
              className="relationship-canvas"
              tabIndex={0}
              aria-label="Scrollable intelligence graph"
            >
              <div
                style={{
                  width: layout.width * zoom,
                  height: layout.height * zoom,
                }}
              >
                <div
                  className="graph-stage"
                  style={{
                    width: layout.width,
                    height: layout.height,
                    transform: `scale(${zoom})`,
                  }}
                >
                  <svg
                    width={layout.width}
                    height={layout.height}
                    aria-hidden="true"
                  >
                    <defs>
                      <marker
                        id={"arrow-" + entityId}
                        markerWidth="8"
                        markerHeight="8"
                        refX="7"
                        refY="3"
                        orient="auto"
                      >
                        <path d="M0,0 L0,6 L7,3 z" fill="#71877e" />
                      </marker>
                    </defs>
                    {data.edges.map((edge) => {
                      const from = layout.positions.get(edge.sourceEntityId),
                        to = layout.positions.get(edge.targetEntityId);
                      if (!from || !to) return null;
                      const forward = to.x > from.x;
                      const x1 = from.x + (forward ? 210 : 0),
                        x2 = to.x + (forward ? 0 : 210),
                        y1 = from.y + 36,
                        y2 = to.y + 36;
                      const curve = (x1 + x2) / 2;
                      return (
                        <g key={edge.id}>
                          <path
                            d={`M${x1},${y1} C${curve},${y1} ${curve},${y2} ${x2},${y2}`}
                            fill="none"
                            stroke={
                              edge.assertionType === "model_inferred"
                                ? "#a27632"
                                : "#71877e"
                            }
                            strokeWidth={1.5}
                            strokeDasharray={
                              edge.assertionType === "model_inferred"
                                ? "5 4"
                                : undefined
                            }
                            markerEnd={`url(#arrow-${entityId})`}
                          />
                          <text
                            x={curve}
                            y={(y1 + y2) / 2 - 9}
                            textAnchor="middle"
                          >
                            {edge.relationshipType
                              .replaceAll("_", " ")
                              .toLowerCase()}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                  {data.nodes.map((n) => {
                    const pos = layout.positions.get(n.id)!;
                    return (
                      <button
                        key={n.id}
                        className={
                          "graph-node positioned-node " +
                          (node?.id === n.id ? "graph-root" : "")
                        }
                        style={{ left: pos.x, top: pos.y }}
                        aria-pressed={node?.id === n.id}
                        onClick={() => setSelected(n.id)}
                        title={n.name}
                      >
                        <small>{n.type.replaceAll("-", " ")}</small>
                        <strong>
                          {n.externalId ? n.externalId + " · " : ""}
                          {n.name}
                        </strong>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
          {mode === "graph" && node && (
            <div className="graph-inspector">
              <div>
                <span className="eyebrow">SELECTED ENTITY</span>
                <strong>{node.name}</strong>
                <small>Source: {node.provenance.sourceName}</small>
                <p>{node.description.slice(0, 600)}</p>
              </div>
              <Link
                className="text-link"
                href={"/intelligence/" + encodeURIComponent(node.id)}
              >
                Open intelligence record <ArrowUpRight size={14} />
              </Link>
            </div>
          )}
          <div className="relationship-list">
            {edges.map((e) => (
              <article key={e.id} className="relationship-row">
                <div className="relationship-path">
                  <Link
                    href={
                      "/intelligence/" + encodeURIComponent(e.sourceEntityId)
                    }
                  >
                    {byId.get(e.sourceEntityId)?.name ?? e.sourceEntityId}
                  </Link>
                  <span>
                    → {e.relationshipType.replaceAll("_", " ").toLowerCase()} →
                  </span>
                  <Link
                    href={
                      "/intelligence/" + encodeURIComponent(e.targetEntityId)
                    }
                  >
                    {byId.get(e.targetEntityId)?.name ?? e.targetEntityId}
                  </Link>
                </div>
                <div className="relationship-meta">
                  <span className={"assertion " + e.assertionType}>
                    {e.assertionType.replaceAll("_", " ")}
                  </span>
                  <span>{percent(e.confidence)} confidence</span>
                  <span>{e.provenance.sourceName}</span>
                </div>
              </article>
            ))}
          </div>
          {!edges.length && (
            <p className="tooltip-note">
              No visible source-backed relationships for this selection.
            </p>
          )}
          {data.truncated && (
            <div className="notice">
              This graph is bounded to 100 entities, 200 relationships and 30
              relationships per entity. Open a related record to continue
              investigating.
            </div>
          )}
        </>
      )}
    </section>
  );
}
