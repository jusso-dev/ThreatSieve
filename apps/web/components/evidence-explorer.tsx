"use client";
import Link from "next/link";
import { useApi } from "@/lib/api";
import { useState } from "react";
import { FileSearch, Clock, Copy } from "lucide-react";
import { percent, relativeTime, absoluteTime } from "@/lib/utils";
import { copyText } from "@/lib/view-state";
import { FilterSelect, QueryField, EmptyResults } from "./filter-controls";
import { Button } from "./ui/button";
import type { Evidence } from "../../../packages/schemas/src/index";

export function EvidenceExplorer({
  evidence,
  selectedIds,
  onClear,
}: {
  evidence: Evidence[];
  selectedIds: string[];
  onClear: () => void;
}) {
  const ratings = useApi<{
    data: {
      id: string;
      reliability: string | null;
      evidence_rating: number | null;
      rationale: string | null;
      default_weight: number;
    }[];
  }>("v1/source-ratings");
  const [source, setSource] = useState(""),
    [query, setQuery] = useState(""),
    [kind, setKind] = useState(""),
    [mode, setMode] = useState("records");
  const sources = [
    ...new Map(
      evidence.map((e) => [e.provenance.sourceId, e.provenance.sourceName]),
    ).entries(),
  ];
  const filtered = evidence
    .filter(
      (e) =>
        (!source || e.provenance.sourceId === source) &&
        (!kind || (kind === "behavioural" ? e.behavioural : !e.behavioural)) &&
        (!selectedIds.length || selectedIds.includes(e.id)) &&
        (!query ||
          JSON.stringify([e.id, e.data, e.provenance.sourceName])
            .toLowerCase()
            .includes(query.toLowerCase())),
    )
    .sort((a, b) =>
      (b.observedAt ?? b.createdAt).localeCompare(a.observedAt ?? a.createdAt),
    );
  const reset = () => {
    setSource("");
    setQuery("");
    setKind("");
    onClear();
  };
  return (
    <section className="panel" id="evidence" tabIndex={-1}>
      <div className="section-title">
        <h2>
          <FileSearch size={17} />
          Evidence & provenance{" "}
          <span className="count-badge">{evidence.length}</span>
        </h2>
        <div className="segmented-control" aria-label="Evidence presentation">
          <button
            aria-pressed={mode === "records"}
            onClick={() => setMode("records")}
          >
            Records
          </button>
          <button
            aria-pressed={mode === "timeline"}
            onClick={() => setMode("timeline")}
          >
            <Clock size={13} />
            Timeline
          </button>
        </div>
      </div>
      <div className="evidence-toolbar">
        <QueryField label="Search evidence" value={query} onChange={setQuery} />
        <FilterSelect
          label="Evidence source"
          value={source}
          options={[["", "All sources"], ...sources]}
          onChange={setSource}
        />
        <FilterSelect
          label="Evidence context"
          value={kind}
          options={[
            ["", "All context"],
            ["behavioural", "Behavioural"],
            ["contextual", "Contextual"],
          ]}
          onChange={setKind}
        />
      </div>
      <div className="result-summary">
        <span>
          {filtered.length} of {evidence.length} evidence records
        </span>
        {(selectedIds.length > 0 || source || query || kind) && (
          <button className="text-link" onClick={reset}>
            Show all evidence
          </button>
        )}
      </div>
      {selectedIds.length > 0 && (
        <p className="notice">
          Showing evidence cited by the selected ATT&CK mapping.
        </p>
      )}
      <div
        className={
          "evidence-list " + (mode === "timeline" ? "evidence-timeline" : "")
        }
      >
        {filtered.map((e) => (
          <article className="evidence-item" key={e.id}>
            <div className="evidence-header">
              <span className="source-icon">
                {e.provenance.sourceName.slice(0, 2).toUpperCase()}
              </span>
              <strong>{e.provenance.sourceName}</strong>
              <time
                dateTime={e.observedAt ?? e.createdAt}
                title={absoluteTime(e.observedAt ?? e.createdAt)}
              >
                {relativeTime(e.observedAt ?? e.createdAt)}
              </time>
            </div>
            {mode === "timeline" && (
              <p className="evidence-date">
                {e.observedAt ? "Observed" : "Recorded"}{" "}
                {absoluteTime(e.observedAt ?? e.createdAt)}
              </p>
            )}
            <p>
              {typeof e.data.description === "string"
                ? e.data.description
                : typeof e.data.role === "string"
                  ? "Source reports role: " + e.data.role
                  : "Source-provided intelligence record"}
            </p>
            <div className="evidence-tags">
              <span>{e.type}</span>
              <Link
                className="text-link"
                href={"/sources/" + e.sourceId}
                title={
                  ratings.data?.data.find((r) => r.id === e.sourceId)
                    ?.rationale ??
                  "Source quality and workspace reliability policy"
                }
              >
                Source quality{" "}
                {ratings.data?.data.find((r) => r.id === e.sourceId)
                  ?.reliability ?? "unrated"}
                {ratings.data?.data.find((r) => r.id === e.sourceId)
                  ?.evidence_rating ?? ""}
              </Link>
              <span>{percent(e.confidence)} source confidence</span>
              <span>
                {e.behavioural ? "Behavioural evidence" : "Contextual evidence"}
              </span>
            </div>
            <details>
              <summary>View original fields and provenance</summary>
              <dl className="provenance-details">
                <div>
                  <dt>Evidence ID</dt>
                  <dd className="mono">{e.id}</dd>
                </div>
                <div>
                  <dt>Retrieved</dt>
                  <dd>{absoluteTime(e.provenance.retrievedAt)}</dd>
                </div>
                <div>
                  <dt>Licence</dt>
                  <dd>{e.provenance.license ?? "Not supplied"}</dd>
                </div>
                <div>
                  <dt>Redistribution</dt>
                  <dd>
                    {e.provenance.redistributable
                      ? "Permitted by source metadata"
                      : "Restricted or unverified"}
                  </dd>
                </div>
              </dl>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  void copyText(e.id, "Evidence reference copied.")
                }
              >
                <Copy size={13} />
                Copy evidence ID
              </Button>
              <pre>
                {JSON.stringify(
                  { data: e.data, provenance: e.provenance, rawKey: e.rawKey },
                  null,
                  2,
                )}
              </pre>
            </details>
          </article>
        ))}
      </div>
      {!filtered.length &&
        (evidence.length ? (
          <EmptyResults noun="evidence records" onReset={reset} />
        ) : (
          <p className="panel-subtitle">
            No supporting source evidence is currently available. Unknown is the
            appropriate outcome.
          </p>
        ))}
    </section>
  );
}
