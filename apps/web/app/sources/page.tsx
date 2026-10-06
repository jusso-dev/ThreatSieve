"use client";
import { usePermission } from "@/lib/access";
import { useState } from "react";
import { RefreshCw, Database, CheckCircle2 } from "lucide-react";
import { api, useApi } from "@/lib/api";
import { relativeTime } from "@/lib/utils";
import { PageHeader, DataState } from "@/components/shell";
import { Button } from "@/components/ui/button";
interface Source {
  id: string;
  name: string;
  status: string;
  enabled: number;
  last_sync: string | null;
  next_sync: string | null;
  records_processed: number;
  records_added: number;
  records_updated: number;
  errors: number;
  license: string;
  redistributable: number;
  last_error: string | null;
}
export default function Sources() {
  const canWrite = usePermission("feeds:write");
  const { data, error, loading, reload } = useApi<{ data: Source[] }>(
    "v1/feeds",
  );
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const sync = async (id: string) => {
    setBusy(id);
    try {
      await api("v1/feeds/" + id + "/sync", { method: "POST" });
      setMessage(
        "Sync queued. Source status updates as the import progresses.",
      );
      await reload();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Sync failed");
    } finally {
      setBusy("");
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="THREAT INTELLIGENCE"
        title="Intelligence sources"
        description="Know where your intelligence comes from, and when it was last seen."
        action={
          <Button variant="outline" onClick={() => void reload()}>
            <RefreshCw size={14} />
            Refresh status
          </Button>
        }
      />
      <div className="demo-banner">
        <Database size={14} />
        Feed health reflects actual sync state. Sources requiring credentials
        remain disabled until configured.
      </div>
      {message && (
        <div className="notice" role="status" style={{ marginBottom: 20 }}>
          {message}
        </div>
      )}
      <DataState loading={loading} error={error} />
      {data && (
        <section className="intelligence-panel table-scroll">
          <table className="source-table">
            <thead>
              <tr>
                <th>Intelligence source</th>
                <th>Status</th>
                <th>Last sync</th>
                <th>Records processed</th>
                <th>Redistribution</th>
                <th>Errors</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.data.map((s) => (
                <tr key={s.id}>
                  <td>
                    <div className="source-name">
                      <span>{s.name.slice(0, 2).toUpperCase()}</span>
                      {s.name}
                    </div>
                    <div className="source-license">{s.license}</div>
                  </td>
                  <td>
                    <span
                      className={
                        "status-label " + (!s.enabled ? "disabled" : s.status)
                      }
                    >
                      <span
                        className={
                          s.status === "healthy"
                            ? "status-dot"
                            : "status-dot warning"
                        }
                      />
                      {!s.enabled
                        ? "Disabled"
                        : s.status === "never-synced"
                          ? "Awaiting first sync"
                          : s.status}
                    </span>
                  </td>
                  <td className="muted">
                    {s.last_sync ? relativeTime(s.last_sync) : "Not yet synced"}
                  </td>
                  <td className="mono">
                    {s.records_processed.toLocaleString()}
                  </td>
                  <td className="muted">
                    {s.redistributable
                      ? "Permitted"
                      : "Restricted / review terms"}
                  </td>
                  <td
                    className={s.errors ? "text-red" : "muted"}
                    title={s.last_error ?? undefined}
                  >
                    {s.errors}
                  </td>
                  <td>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!canWrite || !s.enabled || busy === s.id}
                      onClick={() => void sync(s.id)}
                    >
                      <RefreshCw size={12} />
                      {busy === s.id ? "Queuing…" : "Sync"}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      <div className="operations-note">
        <CheckCircle2 size={15} />
        <p>
          Raw responses are archived in R2. Checkpoints advance only after
          records finish processing.
        </p>
      </div>
    </>
  );
}
