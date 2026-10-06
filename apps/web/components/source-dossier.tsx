"use client";
import Link from "next/link";
import { useState } from "react";
import { api, useApi } from "@/lib/api";
import { usePermission } from "@/lib/access";
import { absoluteTime, relativeTime } from "@/lib/utils";
import { PageHeader, DataState } from "./shell";
import { Button } from "./ui/button";
import { EvidenceExplorer } from "./evidence-explorer";
import type { Evidence } from "../../../packages/schemas/src/index";
interface Quality {
  source: {
    id: string;
    name: string;
    status: string;
    license: string;
    redistributable: number;
    last_sync: string | null;
    next_sync: string | null;
    records_processed: number;
    records_added: number;
    records_updated: number;
    errors: number;
    last_error: string | null;
    reliability: number;
  };
  rating: {
    reliability: string;
    evidence_rating: number;
    rationale: string;
    updated_at: string;
  } | null;
  policy: { enabled: number; reason?: string };
  history: {
    id: string;
    status: string;
    created_at: string;
    updated_at: string;
    latency_ms: number | null;
    error_type: string | null;
    result: { records?: number; finalized?: boolean } | null;
  }[];
  rejections: { error_type: string; count: number }[];
  samples: Evidence[];
  quality: {
    labelledAssessments: number;
    reviewedMalicious: number;
    overturnedAsBenign: number;
    reviewedFalsePositiveFraction: number | null;
    label: string;
  };
}
export function SourceDossier({ id }: { id: string }) {
  const { data, error, loading, reload } = useApi<Quality>(
    "v1/feeds/" + id + "/quality",
  );
  const jobs = useApi<{
    data: {
      id: string;
      stage: string;
      status: string;
      error_type: string | null;
    }[];
  }>("v1/feeds/" + id + "/jobs");
  const canWrite = usePermission("feeds:write"),
    admin = usePermission("admin");
  const [busy, setBusy] = useState(false),
    [message, setMessage] = useState(""),
    [rating, setRating] = useState("B"),
    [evidenceRating, setEvidenceRating] = useState("2"),
    [rationale, setRationale] = useState("");
  if (!data || loading || error)
    return <DataState error={error} loading={loading} />;
  const run = async (path: string, body?: unknown, method = "POST") => {
    setBusy(true);
    setMessage("");
    try {
      await api(path, {
        method,
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      await reload();
      await jobs.reload();
      return true;
    } catch (e) {
      setMessage(
        e instanceof Error ? e.message : "Unable to complete source operation",
      );
      return false;
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Link href="/sources" className="back-link">
        ← Intelligence sources
      </Link>
      <PageHeader
        eyebrow="SOURCE OPERATIONS"
        title={data.source.name}
        description="Source assertions, collection health and workspace trust policy."
        action={
          <div className="actions">
            <Button
              variant="outline"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  const h = await api<{ status: string; message?: string }>(
                    "v1/feeds/" + id + "/health",
                  );
                  setMessage(
                    h.status +
                      ": " +
                      (h.message ??
                        "Configuration verified. A successful sync confirms upstream connectivity."),
                  );
                } catch (error) {
                  setMessage(
                    error instanceof Error
                      ? error.message
                      : "Could not check the source configuration. Try again.",
                  );
                } finally {
                  setBusy(false);
                }
              }}
            >
              Test configuration
            </Button>
            <Button
              disabled={!canWrite || busy}
              onClick={() => void run("v1/feeds/" + id + "/sync")}
            >
              Sync now
            </Button>
          </div>
        }
      />
      {message && (
        <p role="status" className="notice">
          {message}
        </p>
      )}
      <div className="work-detail-grid">
        <div>
          <section className="work-section">
            <h2>Collection health</h2>
            <dl className="source-facts">
              <div>
                <dt>State</dt>
                <dd>{data.source.status}</dd>
              </div>
              <div>
                <dt>Last successful sync</dt>
                <dd>
                  {data.source.last_sync
                    ? relativeTime(data.source.last_sync)
                    : "Never synced"}
                </dd>
              </div>
              <div>
                <dt>Next scheduled sync</dt>
                <dd>
                  {data.source.next_sync
                    ? absoluteTime(data.source.next_sync)
                    : "Manual / not scheduled"}
                </dd>
              </div>
              <div>
                <dt>Processed</dt>
                <dd>{data.source.records_processed.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Added</dt>
                <dd>{data.source.records_added.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Updates / repeated records</dt>
                <dd>{data.source.records_updated.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Errors</dt>
                <dd>{data.source.errors}</dd>
              </div>
            </dl>
            {data.source.last_error && (
              <p className="form-error">{data.source.last_error}</p>
            )}
          </section>
          <section className="work-section">
            <h2>Sync history</h2>
            <div className="table-scroll">
              <table className="intel-table">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Status</th>
                    <th>Records</th>
                    <th>Queue + fetch latency</th>
                    <th>Processing</th>
                  </tr>
                </thead>
                <tbody>
                  {data.history.map((j) => (
                    <tr key={j.id}>
                      <td title={absoluteTime(j.created_at)}>
                        {relativeTime(j.created_at)}
                      </td>
                      <td>{j.status}</td>
                      <td>{j.result?.records ?? "—"}</td>
                      <td>
                        {j.latency_ms === null
                          ? "—"
                          : (j.latency_ms / 1000).toFixed(1) + "s"}
                      </td>
                      <td>
                        {j.result?.finalized
                          ? "Complete"
                          : (j.error_type ?? "In progress")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!data.history.length && (
              <p className="muted">No sync history recorded.</p>
            )}
          </section>
          <section className="work-section">
            <h2>Processing errors & replay</h2>
            {data.rejections.map((r) => (
              <p key={r.error_type}>
                {r.count} quarantined records · {r.error_type}
              </p>
            ))}
            {jobs.data?.data.map((j) => (
              <div key={j.id} className="match-row">
                <div>
                  <strong>
                    {j.stage} · {j.status}
                  </strong>
                  <small>{j.error_type ?? "Processing"}</small>
                </div>
                {j.status === "failed" && (
                  <Button
                    disabled={!canWrite || busy}
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void run(
                        "v1/feeds/" +
                          id +
                          "/jobs/" +
                          encodeURIComponent(j.id) +
                          "/replay",
                      )
                    }
                  >
                    Replay failed job
                  </Button>
                )}
              </div>
            ))}
            {!data.rejections.length && !jobs.data?.data.length && (
              <p className="muted">
                No rejected records or unfinished processing jobs.
              </p>
            )}
          </section>
          <section className="work-section">
            <h2>Recent evidence samples</h2>
            <EvidenceExplorer
              evidence={data.samples}
              selectedIds={[]}
              onClear={() => {}}
            />
          </section>
        </div>
        <aside>
          <section className="work-section">
            <h2>Source reliability</h2>
            <p>
              {data.rating
                ? data.rating.reliability + data.rating.evidence_rating
                : "Unrated by this workspace"}{" "}
              ·{" "}
              {data.rating?.rationale ??
                "Using the provider’s configured policy weight."}
            </p>
            <p className="muted">
              Admiralty reliability and information credibility are analyst
              ratings. They are not statistically calibrated accuracy.
            </p>
            <form
              className="work-editor"
              onSubmit={async (e) => {
                e.preventDefault();
                if (
                  await run(
                    "v1/feeds/" + id + "/rating",
                    {
                      reliability: rating,
                      evidenceRating: Number(evidenceRating),
                      rationale,
                    },
                    "PUT",
                  )
                )
                  setRationale("");
              }}
            >
              <label>
                Reliability
                <select
                  disabled={!admin}
                  value={rating}
                  onChange={(e) => setRating(e.target.value)}
                >
                  {[
                    "A · Completely reliable",
                    "B · Usually reliable",
                    "C · Fairly reliable",
                    "D · Not usually reliable",
                    "E · Unreliable",
                    "F · Cannot be judged",
                  ].map((v) => (
                    <option key={v} value={v[0]}>
                      {v}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Information credibility
                <select
                  disabled={!admin}
                  value={evidenceRating}
                  onChange={(e) => setEvidenceRating(e.target.value)}
                >
                  {[
                    "1 · Confirmed",
                    "2 · Probably true",
                    "3 · Possibly true",
                    "4 · Doubtful",
                    "5 · Improbable",
                    "6 · Cannot be judged",
                  ].map((v) => (
                    <option value={v[0]} key={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Rating rationale
                <textarea
                  required
                  minLength={10}
                  maxLength={2000}
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                />
              </label>
              <Button disabled={!admin || busy}>Save workspace rating</Button>
            </form>
          </section>
          <section className="work-section">
            <h2>Reviewed outcomes</h2>
            <p>
              {data.quality.reviewedMalicious} malicious assessments reviewed ·{" "}
              {data.quality.overturnedAsBenign} overturned as benign
            </p>
            <p>
              Reviewed false-positive fraction:{" "}
              {data.quality.reviewedFalsePositiveFraction === null
                ? "Insufficient labels"
                : Math.round(data.quality.reviewedFalsePositiveFraction * 100) +
                  "%"}
            </p>
            <small>{data.quality.label}</small>
          </section>
          <section className="work-section">
            <h2>Workspace source policy</h2>
            <p>
              {data.policy.enabled ? "Included" : "Excluded"} in new assessments
              and current dossiers.
            </p>
            <p className="muted">
              Shared collection continues for other organisations. Historical
              assessments preserve their original evidence.
            </p>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const form = new FormData(e.currentTarget);
                await run(
                  "v1/feeds/" + id + "/policy",
                  {
                    enabled: !data.policy.enabled,
                    reason: String(form.get("reason")),
                  },
                  "PUT",
                );
              }}
            >
              <label>
                Policy change reason
                <textarea
                  name="reason"
                  required
                  minLength={10}
                  maxLength={2000}
                />
              </label>
              <Button variant="outline" disabled={!admin || busy}>
                {data.policy.enabled
                  ? "Exclude from workspace"
                  : "Include in workspace"}
              </Button>
            </form>
          </section>
          <section className="work-section">
            <h2>Usage & redistribution</h2>
            <p>{data.source.license}</p>
            <p>
              {data.source.redistributable
                ? "Redistribution permitted by configured policy."
                : "Restricted. External exports omit source-restricted assertions."}
            </p>
          </section>
        </aside>
      </div>
    </>
  );
}
