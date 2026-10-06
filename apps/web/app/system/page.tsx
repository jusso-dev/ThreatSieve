"use client";
import Link from "next/link";
import { useEffect } from "react";
import { usePermission } from "@/lib/access";
import { useApi } from "@/lib/api";
import { PageHeader, DataState } from "@/components/shell";
import { Button } from "@/components/ui/button";
import { relativeTime, absoluteTime } from "@/lib/utils";
import type { OperationalReport } from "../../../../packages/schemas/src/operations";

export default function SystemPage() {
  const allowed = usePermission("ops:read");
  return allowed ? (
    <SystemHealth />
  ) : (
    <p className="muted">
      Operational monitoring requires administrator access or an ops:read API
      key.
    </p>
  );
}
function SystemHealth() {
  const { data, error, loading, reload } =
    useApi<OperationalReport>("v1/ops/status");
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void reload();
    }, 60000);
    return () => clearInterval(timer);
  }, [reload]);
  return (
    <>
      <PageHeader
        eyebrow="PLATFORM OPERATIONS"
        title="System health"
        description="Collection freshness, processing backlog and integration delivery. This view contains your workspace and shared-feed operations."
        action={
          <Button
            variant="outline"
            disabled={loading}
            onClick={() => void reload()}
          >
            Refresh health
          </Button>
        }
      />
      <DataState loading={loading && !data} error={error} />
      {data && (
        <>
          <section className="work-section">
            <div className="section-title">
              <h2>Service status: {data.status}</h2>
              <span className="muted">
                Checked {absoluteTime(data.checked_at)}
              </span>
            </div>
            <p className="muted">
              Pipeline maintenance{" "}
              {data.heartbeat
                ? relativeTime(data.heartbeat)
                : "not yet recorded"}{" "}
              · Archive write{" "}
              {data.archive_heartbeat
                ? relativeTime(data.archive_heartbeat)
                : "not yet recorded"}
            </p>
            {!data.alerts.length ? (
              <p>No operational thresholds are currently breached.</p>
            ) : (
              <div className="ops-alerts">
                {data.alerts.map((a, i) => (
                  <article
                    className={"ops-alert " + a.severity}
                    key={a.code + a.subject + i}
                  >
                    <strong>
                      {a.severity.toUpperCase()} · {a.subject}
                    </strong>
                    <p>{a.message}</p>
                    <small>{a.code}</small>
                    {data.feeds.some((f) => f.id === a.subject) && (
                      <Link href={"/sources/" + a.subject}>
                        Inspect source →
                      </Link>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>
          <section className="work-section">
            <h2>Intelligence collection</h2>
            <div className="table-scroll">
              <table className="work-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Last completed sync</th>
                    <th>Next sync</th>
                    <th>Processed</th>
                    <th>Added</th>
                    <th>Repeated / updated</th>
                  </tr>
                </thead>
                <tbody>
                  {data.feeds.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <Link href={"/sources/" + f.id}>{f.name}</Link>
                      </td>
                      <td>
                        {!f.configured
                          ? "Not configured"
                          : !f.enabled
                            ? "Paused"
                            : f.status}
                      </td>
                      <td>
                        {f.last_sync
                          ? relativeTime(f.last_sync)
                          : "No completed sync"}
                      </td>
                      <td>{f.next_sync ? absoluteTime(f.next_sync) : "—"}</td>
                      <td>{f.records_processed.toLocaleString()}</td>
                      <td>{f.records_added.toLocaleString()}</td>
                      <td>{f.records_updated.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="work-section">
            <h2>Pipeline jobs</h2>
            <p className="muted">
              Pending and failed work, plus completions in the last 24 hours.
              Queue age measures the original enqueue time, including retries.
            </p>
            <div className="table-scroll">
              <table className="work-table">
                <thead>
                  <tr>
                    <th>Stage</th>
                    <th>Status</th>
                    <th>Jobs</th>
                    <th>Oldest created</th>
                    <th>State conflicts</th>
                  </tr>
                </thead>
                <tbody>
                  {data.jobs.map((j) => (
                    <tr key={j.stage + j.status}>
                      <td>{j.stage}</td>
                      <td>{j.status}</td>
                      <td>{j.count.toLocaleString()}</td>
                      <td>{relativeTime(j.oldest)}</td>
                      <td>{j.stale_result_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p>
              {data.outbox.pending} unpublished outbox jobs
              {data.outbox.oldest
                ? " · oldest " + relativeTime(data.outbox.oldest)
                : ""}
              .
            </p>
          </section>
          <section className="work-section">
            <h2>Classification allowance</h2>
            <p>
              {data.usage.calls.toLocaleString()} of{" "}
              {data.usage.daily_limit.toLocaleString()} assessment attempts
              today (UTC) · {data.usage.input_tokens.toLocaleString()} recorded
              input tokens.
            </p>
            <p className="muted">
              This is an operational allowance, not an invoice or measured
              currency cost.
            </p>
          </section>
          <section className="work-section">
            <h2>OpenCTI delivery</h2>
            <p className="muted">
              A successful poll means the connector accepted available bundles
              through its helper. Confirm indexing in OpenCTI separately.
            </p>
            {data.integrations.length ? (
              <div className="table-scroll">
                <table className="work-table">
                  <thead>
                    <tr>
                      <th>Connector</th>
                      <th>Status</th>
                      <th>Last poll</th>
                      <th>Last successful poll</th>
                      <th>Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.integrations.map((i) => (
                      <tr key={i.connector_id}>
                        <td className="mono">{i.connector_id}</td>
                        <td>
                          {i.status}
                          {i.error_type ? " · " + i.error_type : ""}
                        </td>
                        <td>{relativeTime(i.last_poll_at)}</td>
                        <td>
                          {i.last_success_at
                            ? relativeTime(i.last_success_at)
                            : "Not recorded"}
                        </td>
                        <td>{i.version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p>
                No connector heartbeat is registered. Connection health has not
                been verified.
              </p>
            )}
          </section>
        </>
      )}
    </>
  );
}
