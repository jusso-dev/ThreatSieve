"use client";
import Link from "next/link";
import { IntelligenceGraph } from "./intelligence-graph";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, useApi } from "@/lib/api";
import { Button } from "./ui/button";
import { DataState } from "./shell";
import { relativeTime } from "@/lib/utils";
import type { WorkObject } from "../../../packages/schemas/src/enterprise";
export function WorkspaceMatches({
  object,
  onAccept,
  canWrite,
}: {
  object: WorkObject;
  onAccept: (id: string) => void;
  canWrite: boolean;
}) {
  const [cursor, setCursor] = useState("");
  const { data, error, loading, reload } = useApi<{
    data: {
      entity_id: string;
      name: string;
      type: string;
      evidence_ids: string[];
      matched_at: string;
      automatic_member: number;
      score: number | null;
    }[];
    next_cursor: string | null;
  }>(
    "v1/workspace/" +
      object.id +
      "/matches?limit=20&cursor=" +
      encodeURIComponent(cursor),
  );
  return (
    <section className="work-section">
      <div className="section-title">
        <h2>Matching intelligence</h2>
        <Button variant="ghost" size="sm" onClick={() => void reload()}>
          Refresh matches
        </Button>
      </div>
      <p className="muted">
        Criteria matches from background collection. Review the evidence before
        accepting support for a requirement.
      </p>
      <DataState loading={loading} error={error} />
      {data?.data.map((m) => (
        <div className="match-row" key={m.entity_id}>
          <div>
            <Link href={"/intelligence/" + m.entity_id}>{m.name}</Link>
            <small>
              {m.automatic_member ? "Playbook membership · " : ""}
              {m.type} · {m.evidence_ids.length} supporting records ·{" "}
              {relativeTime(m.matched_at)}
            </small>
          </div>
          <span>Threat {m.score ?? "unknown"}</span>
          {!!m.automatic_member && canWrite && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                void api(
                  "v1/watchlists/" + object.id + "/members/" + m.entity_id,
                  { method: "DELETE" },
                )
                  .then(() => reload())
                  .catch(() => {});
              }}
            >
              Remove membership
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={
              !canWrite ||
              object.references.some(
                (r) => r.id === m.entity_id && r.type === "entity",
              )
            }
            onClick={() => onAccept(m.entity_id)}
          >
            Link intelligence
          </Button>
        </div>
      ))}
      {data && !data.data.length && (
        <p className="muted">
          No matches yet. Active requirements, watchlists and published
          collections process incoming intelligence asynchronously.
        </p>
      )}
      <div className="actions">
        <Button
          variant="ghost"
          size="sm"
          disabled={!cursor}
          onClick={() => setCursor("")}
        >
          First page
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={!data?.next_cursor}
          onClick={() => setCursor(data?.next_cursor ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}
export function ExecutionHistory({ id }: { id: string }) {
  const { data, error, loading, reload } = useApi<{
    data: {
      id: string;
      status: string;
      created_at: string;
      data: {
        eventType?: string;
        message?: string;
        actions?: { action: string; result: string; reason?: string }[];
      };
    }[];
  }>("v1/playbooks/" + id + "/executions");
  return (
    <section className="work-section">
      <div className="section-title">
        <h2>Execution history</h2>
        <Button variant="ghost" size="sm" onClick={() => void reload()}>
          Refresh history
        </Button>
      </div>
      <DataState loading={loading} error={error} />
      {data?.data.map((e) => (
        <article className="execution-row" key={e.id}>
          <strong>
            {e.status} · {e.data.eventType ?? "automation"}
          </strong>
          <small>{relativeTime(e.created_at)}</small>
          {e.data.message && <p>{e.data.message}</p>}
          <ul>
            {e.data.actions?.map((a, i) => (
              <li key={i}>
                {a.action}: {a.result}
                {a.reason ? " — " + a.reason : ""}
              </li>
            ))}
          </ul>
        </article>
      ))}
      {data && !data.data.length && (
        <p className="muted">
          No executions. Activate this playbook to process future matching
          events.
        </p>
      )}
    </section>
  );
}
export function CollectionPublication({
  object,
  canWrite,
}: {
  object: WorkObject;
  canWrite: boolean;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const state = useApi<{
    publication: {
      revision: number;
      published_at: string;
      object_count: number;
    } | null;
  }>("v1/collections/" + object.id + "/publication");
  return (
    <section className="work-section">
      <h2>TAXII publication</h2>
      <p>
        Consumers use scoped API keys from this workspace. Only redistributable
        intelligence is included.
      </p>
      <code className="endpoint">
        /v1/taxii/api/collections/{object.id}/objects/
      </code>
      {state.data?.publication ? (
        <p>
          {state.data.publication.object_count} objects · revision{" "}
          {state.data.publication.revision} ·{" "}
          {relativeTime(state.data.publication.published_at)}
          {state.data.publication.revision !== object.revision
            ? " · New changes are unpublished"
            : ""}
        </p>
      ) : (
        <p>No snapshot published.</p>
      )}
      <Button
        variant="outline"
        disabled={!canWrite || busy}
        onClick={async () => {
          setBusy(true);
          setError("");
          try {
            await api("v1/collections/" + object.id + "/publish", {
              method: "POST",
            });
            await state.reload();
          } catch (e) {
            setError(e instanceof Error ? e.message : "Publication failed");
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Publishing…" : "Publish current snapshot"}
      </Button>
      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}
    </section>
  );
}

export function InvestigationGraph({ object }: { object: WorkObject }) {
  const entities = object.references.filter((r) => r.type === "entity");
  const labels = useApi<{ labels: Record<string, string> }>(
    "v1/workspace/reference-labels?refs=" +
      encodeURIComponent(
        JSON.stringify(entities.map(({ type, id }) => ({ type, id }))),
      ),
  );
  const [root, setRoot] = useState(entities[0]?.id ?? "");
  if (!entities.length)
    return (
      <section className="work-section">
        <h2>Investigation graph</h2>
        <p className="muted">
          Pin an entity to explore its relationships and behavioural context.
        </p>
      </section>
    );
  return (
    <section className="work-section">
      <label>
        Investigation graph root
        <select
          value={root || entities[0]!.id}
          onChange={(e) => setRoot(e.target.value)}
        >
          {entities.map((r) => (
            <option key={r.id} value={r.id}>
              {labels.data?.labels["entity:" + r.id] ?? r.id.slice(0, 24)}
            </option>
          ))}
        </select>
      </label>
      <IntelligenceGraph
        key={root || entities[0]!.id}
        entityId={root || entities[0]!.id}
      />
    </section>
  );
}

interface PackageManifest {
  id: string;
  status: string;
  matched_entities: number;
  expires_at: string;
  parts: { part: number; sha256: string; object_count: number }[];
}
export function CollectionPackage({
  object,
  canWrite,
}: {
  object: WorkObject;
  canWrite: boolean;
}) {
  const [id, setId] = useState(""),
    [manifest, setManifest] = useState<PackageManifest | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const result = await api<PackageManifest>(
          "v1/collection-packages/" + id,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setManifest(result);
        if (!["complete", "failed"].includes(result.status))
          timer = setTimeout(() => void poll(), 3000);
        else if (result.status === "complete")
          toast.success("Your STIX package is ready to download.");
      } catch (e) {
        if (!controller.signal.aborted)
          setError(
            e instanceof Error ? e.message : "Could not load export progress.",
          );
      }
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [id]);
  function save(value: unknown, name: string, pretty = true) {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(value, null, pretty ? 2 : undefined)], {
        type: "application/json",
      }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <section className="work-section">
      <h2>STIX export package</h2>
      <p>
        Export up to 100,000 matched entities in background jobs. Download every
        part to retain relationships across the package. Entity and assessment
        references are supported; linked workspace documents are exported
        separately.
      </p>
      <Button
        variant="outline"
        disabled={
          !canWrite ||
          busy ||
          Boolean(manifest && !["complete", "failed"].includes(manifest.status))
        }
        onClick={async () => {
          setBusy(true);
          setError("");
          try {
            const result = await api<{ id: string }>(
              "v1/collections/" + object.id + "/packages",
              {
                method: "POST",
                body: JSON.stringify({ requestId: crypto.randomUUID() }),
              },
            );
            setManifest(null);
            setId(result.id);
          } catch (e) {
            setError(
              e instanceof Error ? e.message : "Export could not start.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Starting export…" : "Prepare STIX package"}
      </Button>
      {manifest && (
        <>
          <p role="status">
            {manifest.status === "complete"
              ? "Ready"
              : manifest.status === "failed"
                ? "Processing failed — an administrator can replay the failed job."
                : "Processing"}{" "}
            · {manifest.matched_entities.toLocaleString()} matched entities ·{" "}
            {manifest.parts.length} parts prepared
          </p>
          {manifest.status === "complete" && (
            <>
              <p>
                Downloads expire{" "}
                {new Date(manifest.expires_at).toLocaleString()}.
              </p>
              <Button
                variant="outline"
                onClick={() => {
                  save(manifest, "threatsieve-package-manifest.json");
                  toast.success("Export manifest downloaded.");
                }}
              >
                Download manifest
              </Button>
              <ul>
                {manifest.parts.map((part) => (
                  <li key={part.part}>
                    <Button
                      variant="ghost"
                      onClick={async () => {
                        try {
                          const bundle = await api<unknown>(
                            `v1/collection-packages/${id}/parts/${part.part}`,
                          );
                          save(bundle, `threatsieve-${id}-${part.part}.json`);
                          toast.success("STIX part downloaded.");
                        } catch (e) {
                          setError(
                            e instanceof Error ? e.message : "Download failed.",
                          );
                        }
                      }}
                    >
                      Download part {part.part + 1} · {part.object_count}{" "}
                      objects
                    </Button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}
      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}
    </section>
  );
}
