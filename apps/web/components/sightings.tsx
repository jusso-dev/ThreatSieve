"use client";
import Link from "next/link";
import { useState } from "react";
import { api, useApi } from "@/lib/api";
import { usePermission } from "@/lib/access";
import { absoluteTime } from "@/lib/utils";
import type { Sighting } from "../../../packages/schemas/src/enterprise";
import { PageHeader, DataState } from "./shell";
import { Modal } from "./ui/modal";
import { Button } from "./ui/button";
export function Sightings() {
  const [cursor, setCursor] = useState("");
  const { data, error, loading, reload } = useApi<{
    data: Sighting[];
    next_cursor: string | null;
  }>("v1/sightings?cursor=" + encodeURIComponent(cursor));
  const [open, setOpen] = useState(false);
  const canWrite = usePermission("assessment:write");
  return (
    <>
      <PageHeader
        eyebrow="ENVIRONMENT OBSERVATIONS"
        title="Sightings"
        description="What your organisation has observed, separate from what sources report."
        action={
          <Button disabled={!canWrite} onClick={() => setOpen(true)}>
            Record sighting
          </Button>
        }
      />
      <DataState loading={loading} error={error} />
      {data && (
        <div className="table-scroll">
          <table className="intel-table">
            <thead>
              <tr>
                <th>Observable</th>
                <th>Time</th>
                <th>Source</th>
                <th>Asset / environment</th>
                <th>Count</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {data.data.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link
                      className="mono"
                      href={"/intelligence/" + s.observableId}
                    >
                      {s.observable.observable}
                    </Link>
                  </td>
                  <td>{absoluteTime(s.observedAt)}</td>
                  <td>{s.source}</td>
                  <td>{s.asset || s.environment || "Not supplied"}</td>
                  <td>{s.count}</td>
                  <td>{Math.round(s.confidence * 100)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data.data.length && (
            <p className="work-empty">
              No observations recorded. Submit sightings through the API or
              record an analyst observation.
            </p>
          )}
        </div>
      )}
      <div className="actions">
        <Button
          variant="ghost"
          disabled={!cursor}
          onClick={() => setCursor("")}
        >
          First page
        </Button>
        <Button
          variant="ghost"
          disabled={!data?.next_cursor}
          onClick={() => setCursor(data?.next_cursor ?? "")}
        >
          Next page
        </Button>
      </div>
      {open && (
        <SightingForm
          onClose={() => setOpen(false)}
          onSaved={() => {
            setOpen(false);
            void reload();
          }}
        />
      )}
    </>
  );
}
export function SightingForm({
  observable = "",
  onClose,
  onSaved,
}: {
  observable?: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [value, setValue] = useState(observable),
    [source, setSource] = useState("analyst"),
    [time, setTime] = useState(new Date().toISOString().slice(0, 16)),
    [asset, setAsset] = useState(""),
    [context, setContext] = useState(""),
    [environment, setEnvironment] = useState(""),
    [confidence, setConfidence] = useState(80),
    [externalId, setExternalId] = useState(() => crypto.randomUUID()),
    [count, setCount] = useState(1),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <Modal titleId="sighting-title" onClose={onClose} busy={busy}>
      <h2 id="sighting-title">Record an observation</h2>
      <p>This does not classify the observable as malicious.</p>
      <form
        className="work-editor"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            await api("v1/sightings", {
              method: "POST",
              body: JSON.stringify({
                observable: { observable: value },
                source,
                observedAt: new Date(time + "Z").toISOString(),
                asset,
                context,
                environment,
                confidence: confidence / 100,
                externalId,
                count,
              }),
            });
            onSaved();
          } catch (e) {
            setError(
              e instanceof Error ? e.message : "Could not record sighting.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Observable
          <input
            required
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </label>
        <div className="form-columns">
          <label>
            Source
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {[
                "analyst",
                "siem",
                "edr",
                "firewall",
                "dns",
                "proxy",
                "email-security",
                "partner",
                "threat-feed",
                "honeypot",
                "customer-telemetry",
              ].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Observed time (UTC)
            <input
              type="datetime-local"
              required
              value={time}
              onChange={(e) => setTime(e.target.value)}
            />
          </label>
          <label>
            Count
            <input
              type="number"
              min={1}
              max={100000000}
              required
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
            />
          </label>
        </div>
        <label>
          Asset
          <input
            value={asset}
            maxLength={200}
            onChange={(e) => setAsset(e.target.value)}
          />
        </label>
        <div className="form-columns">
          <label>
            Environment
            <input
              value={environment}
              maxLength={200}
              onChange={(e) => setEnvironment(e.target.value)}
            />
          </label>
          <label>
            Observation confidence (%)
            <input
              type="number"
              min={0}
              max={100}
              required
              value={confidence}
              onChange={(e) => setConfidence(Number(e.target.value))}
            />
          </label>
        </div>
        <label>
          Source event ID
          <input
            required
            value={externalId}
            onChange={(e) => setExternalId(e.target.value)}
          />
          <small>
            Retries with the same event ID do not duplicate this observation.
          </small>
        </label>
        <label>
          Observation context
          <textarea
            value={context}
            onChange={(e) => setContext(e.target.value)}
            maxLength={5000}
            rows={4}
          />
        </label>
        {error && (
          <p role="alert" className="form-error">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button disabled={busy}>
            {busy ? "Recording…" : "Save sighting"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
