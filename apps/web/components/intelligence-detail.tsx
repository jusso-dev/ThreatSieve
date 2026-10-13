"use client";
import { useState } from "react";
import { useApi } from "@/lib/api";
import { absoluteTime } from "@/lib/utils";
import type { Assessment, IntelEntity } from "../../../packages/schemas/src/index";
import { IntelligenceCard } from "./intelligence-card";

type SourceAssertion = {
  sourceId: string;
  sourceName: string;
  sourceRecordId?: string;
  mirrored: boolean;
};

type EntityLineage = {
  entity: IntelEntity;
  canonical_id: string;
  alias_ids: string[];
  source_assertions: SourceAssertion[];
  source_count: number;
  mirror_count: number;
  independent_corroboration_count: number;
  assessments?: Array<
    Assessment & { assessment_count: number; history?: Assessment[] }
  >;
};

export function IntelligenceDetail({ id }: { id: string }) {
  const lineage = useApi<EntityLineage>(
    "v1/entities/" + encodeURIComponent(id) + "?history=1",
  );
  const canonicalId = lineage.data?.canonical_id ?? id;
  const [historyOpen, setHistoryOpen] = useState(false);
  const assertions = lineage.data?.source_assertions ?? [];
  const assessments = lineage.data?.assessments ?? [];

  return (
    <>
      <IntelligenceCard id={canonicalId} />
      <section className="panel intelligence-lineage" aria-label="Source lineage">
        <h2>Source lineage</h2>
        <p className="muted">
          Canonical record{" "}
          <span className="mono">{lineage.data?.canonical_id ?? id}</span>
          {lineage.data
            ? ` · seen via ${lineage.data.source_count} sources; ${lineage.data.mirror_count} mirrors`
            : ""}
        </p>
        {lineage.loading && <p className="muted">Loading lineage…</p>}
        {lineage.error && (
          <p className="muted">Lineage unavailable for this record.</p>
        )}
        {assertions.length > 0 && (
          <ul className="source-assertion-list">
            {assertions.map((s, i) => (
              <li key={s.sourceId + ":" + (s.sourceRecordId ?? i)}>
                <strong>{s.sourceName}</strong>
                {s.mirrored ? (
                  <span className="tag">mirror</span>
                ) : (
                  <span className="tag">direct</span>
                )}
                {s.sourceRecordId && (
                  <span className="mono muted"> {s.sourceRecordId}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      {assessments.length > 0 && (
        <section
          className="panel assessment-history"
          aria-label="Assessment history"
        >
          <div className="actions">
            <h2>Assessment history</h2>
            <button
              className="text-link"
              onClick={() => setHistoryOpen((v) => !v)}
            >
              {historyOpen ? "Hide history" : "Expand history"}
            </button>
          </div>
          {assessments.map((slot) => (
            <div key={slot.assessment_id} className="assessment-slot">
              <p>
                Latest · {slot.malicious.classification} · confidence{" "}
                {slot.confidence} · {slot.assessment_count} assessment
                {slot.assessment_count === 1 ? "" : "s"}
              </p>
              {historyOpen &&
                (slot.history ?? [slot]).map((a) => (
                  <details key={a.assessment_id} className="history-entry">
                    <summary>
                      {a.assessment_id} · rev {a.revision ?? 0} ·{" "}
                      {absoluteTime(a.updated_at ?? a.created_at)}
                    </summary>
                    <p>
                      {a.malicious.classification} · {a.status}
                      {a.analyst_decision?.reason
                        ? ` · revision reason: ${a.analyst_decision.reason}`
                        : ""}
                    </p>
                  </details>
                ))}
            </div>
          ))}
        </section>
      )}
    </>
  );
}
