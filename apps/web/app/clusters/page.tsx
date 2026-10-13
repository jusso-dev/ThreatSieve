"use client";
import { useState } from "react";
import { Network, ArrowUpRight } from "lucide-react";
import { useApi, api } from "@/lib/api";
import { percent, relativeTime } from "@/lib/utils";
import { PageHeader, DataState } from "@/components/shell";
import { Button } from "@/components/ui/button";
interface Cluster {
  id: string;
  name: string;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  first_observed: string | null;
  last_observed: string | null;
  last_processed_at: string | null;
  grouping_key: string | null;
  rationale: string | null;
  confidence: number;
  observable_count: number;
}
export default function Clusters() {
  const { data, error, loading } = useApi<{ data: Cluster[] }>("v1/clusters");
  const [selected, setSelected] = useState<
    Cluster & { members: { normalizedValue: string; type: string }[] }
  >();
  const [detailError, setDetailError] = useState("");
  return (
    <>
      <PageHeader
        eyebrow="THREAT INTELLIGENCE"
        title="Emerging clusters"
        description="Related activity with room for uncertainty. A cluster is not a campaign."
      />
      <DataState
        loading={loading}
        error={error}
        empty={!loading && !error && !data?.data.length}
      />
      <div className="cluster-grid">
        {data?.data.map((c) => (
          <section className="cluster-card" key={c.id}>
            <span className="tag">
              <Network size={12} />
              {c.status.toUpperCase()}
            </span>
            <h3>{c.name}</h3>
            <p>
              Potential actor association: <strong>UNKNOWN</strong>
            </p>
            <div className="detail-row">
              <span>Related observables</span>
              <strong>{c.observable_count}</strong>
            </div>
            <div className="detail-row">
              <span>Last observed</span>
              <strong>
                {(c.last_observed ?? c.last_seen)
                  ? relativeTime(c.last_observed ?? c.last_seen!)
                  : "Unknown"}
              </strong>
            </div>
            <div className="detail-row">
              <span>Last processed</span>
              <strong>
                {c.last_processed_at
                  ? relativeTime(c.last_processed_at)
                  : "Unknown"}
              </strong>
            </div>
            <div className="detail-row">
              <span>Correlation confidence (evidence-weighted)</span>
              <strong>{percent(c.confidence)}</strong>
            </div>
            <p className="tooltip-note">
              Grouping: {c.rationale ?? "Rationale unknown"}
            </p>
            {c.grouping_key?.startsWith("malware:") && (
              <p className="tooltip-note">
                Shared malware association: the members link to the same malware
                family. This is not evidence of coordinated activity.
              </p>
            )}
            <Button
              variant="outline"
              size="sm"
              style={{ marginTop: 20 }}
              onClick={() => {
                void api<
                  Cluster & {
                    members: { normalizedValue: string; type: string }[];
                  }
                >("v1/clusters/" + c.id)
                  .then(setSelected)
                  .catch((e) =>
                    setDetailError(
                      e instanceof Error
                        ? e.message
                        : "We couldn’t load this cluster. Please try again.",
                    ),
                  );
              }}
            >
              Inspect cluster
              <ArrowUpRight size={13} />
            </Button>
          </section>
        ))}
      </div>
      {detailError && (
        <div className="notice text-red" role="alert">
          {detailError}
        </div>
      )}
      {selected && (
        <section className="panel" style={{ marginTop: 25 }}>
          <h2>{selected.name}</h2>
          <p className="panel-subtitle">
            First observed{" "}
            {(selected.first_observed ?? selected.first_seen)
              ? new Date(
                  selected.first_observed ?? selected.first_seen!,
                ).toLocaleDateString()
              : "Unknown"}{" "}
            · Source-backed membership
          </p>
          <div className="detail-row">
            <span>Last observed</span>
            <strong>
              {(selected.last_observed ?? selected.last_seen)
                ? relativeTime(selected.last_observed ?? selected.last_seen!)
                : "Unknown"}
            </strong>
          </div>
          <div className="detail-row">
            <span>Last processed</span>
            <strong>
              {selected.last_processed_at
                ? relativeTime(selected.last_processed_at)
                : "Unknown"}
            </strong>
          </div>
          <div className="detail-row">
            <span>Correlation confidence (evidence-weighted)</span>
            <strong>{percent(selected.confidence)}</strong>
          </div>
          <p className="tooltip-note">
            Grouping: {selected.rationale ?? "Rationale unknown"}
          </p>
          <div className="cluster-members">
            {selected.members.map((m) => (
              <span className="tag mono" key={m.normalizedValue}>
                {m.normalizedValue}
              </span>
            ))}
          </div>
          <p className="tooltip-note">
            No customer identities or private telemetry are exposed in this
            view.
          </p>
          <p className="tooltip-note">
            Clusters are evidence-linked associations, not confirmed campaigns
            or actor attribution.
          </p>
        </section>
      )}
    </>
  );
}
