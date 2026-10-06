"use client";
import Link from "next/link";
import { usePermission } from "@/lib/access";
import { useState, useEffect } from "react";
import { Plus } from "lucide-react";
import { api, useApi } from "@/lib/api";
import { workApi, workspaces } from "@/lib/workspace";
import type {
  Reference,
  WorkKind,
  WorkObject,
} from "../../../packages/schemas/src/enterprise";
import { Button } from "./ui/button";
import { Modal } from "./ui/modal";
import { QueryField } from "./filter-controls";
import { DataState } from "./shell";
export function referenceHref(r: Reference) {
  return r.type === "entity"
    ? "/intelligence/" + encodeURIComponent(r.id)
    : r.type === "assessment"
      ? "/investigations/" + encodeURIComponent(r.id)
      : r.type === "evidence"
        ? "/evidence/" + encodeURIComponent(r.id)
        : "/" + workspaces[r.type].path + "/" + encodeURIComponent(r.id);
}
export function ReferenceList({ references }: { references: Reference[] }) {
  const labels = useApi<{ labels: Record<string, string> }>(
    "v1/workspace/reference-labels?refs=" +
      encodeURIComponent(
        JSON.stringify(references.map(({ type, id }) => ({ type, id }))),
      ),
  );
  return (
    <ul className="reference-list">
      {references.map((r, i) => (
        <li key={r.type + r.id + i}>
          <span>{r.relation}</span>
          <Link href={referenceHref(r)}>
            {labels.data?.labels[r.type + ":" + r.id] ?? r.type}{" "}
            <small className="mono" title={r.id}>
              {r.id.slice(0, 18)}…
            </small>
          </Link>
        </li>
      ))}
    </ul>
  );
}
export function ReferencePicker({
  onClose,
  onSelect,
}: {
  onClose: () => void;
  onSelect: (r: Reference) => void;
}) {
  const [type, setType] = useState<Reference["type"]>("entity"),
    [q, setQ] = useState(""),
    [relation, setRelation] = useState<Reference["relation"]>("references");
  const { data, error, loading } = useApi<{
    data: { id: string; name: string; type: string }[];
  }>("v1/workspace/references?type=" + type + "&q=" + encodeURIComponent(q));
  return (
    <Modal titleId="reference-title" onClose={onClose}>
      <h2 id="reference-title">Link existing intelligence</h2>
      <p>
        Select a record in this workspace. Its original provenance remains
        attached.
      </p>
      <div className="form-columns">
        <label>
          Record type
          <select
            value={type}
            onChange={(e) => setType(e.target.value as Reference["type"])}
          >
            {[
              "entity",
              "evidence",
              "assessment",
              "requirement",
              "investigation",
              "watchlist",
              "collection",
              "report",
            ].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
        <label>
          Relationship
          <select
            value={relation}
            onChange={(e) =>
              setRelation(e.target.value as Reference["relation"])
            }
          >
            {[
              "references",
              "supports",
              "contradicts",
              "satisfies",
              "member",
              "investigates",
            ].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
      </div>
      <QueryField label="Search existing records" value={q} onChange={setQ} />
      <DataState loading={loading} error={error} />
      <div className="reference-results">
        {data?.data.map((r) => (
          <button
            key={r.id}
            onClick={() => onSelect({ type, id: r.id, relation })}
          >
            <strong>{r.name}</strong>
            <small>
              {r.type} · {r.id}
            </small>
          </button>
        ))}
      </div>
      {data && !data.data.length && (
        <p className="muted">No accessible records match this search.</p>
      )}
    </Modal>
  );
}
export function PinToWorkspace({
  reference,
  initialOpen = false,
}: {
  reference: Reference;
  initialOpen?: boolean;
}) {
  const canWrite = usePermission("assessment:write");
  const [open, setOpen] = useState(initialOpen && canWrite);
  useEffect(() => {
    if (initialOpen && canWrite) setOpen(true);
  }, [initialOpen, canWrite]);
  return (
    <>
      <Button
        variant="outline"
        disabled={!canWrite}
        onClick={() => setOpen(true)}
      >
        <Plus size={14} />
        Add to workspace
      </Button>
      {open && (
        <PinDialog reference={reference} onClose={() => setOpen(false)} />
      )}
    </>
  );
}
function PinDialog({
  reference,
  onClose,
}: {
  reference: Reference;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<WorkKind>("investigation"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { data } = useApi<{ data: WorkObject[] }>(
    "v1/" + workApi(kind) + "?limit=100",
  );
  return (
    <>
      {
        <Modal titleId="pin-title" busy={busy} onClose={() => onClose()}>
          <h2 id="pin-title">Pin intelligence</h2>
          <label>
            Destination type
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as WorkKind)}
            >
              {(
                [
                  "investigation",
                  "requirement",
                  "watchlist",
                  "collection",
                  "report",
                ] as WorkKind[]
              ).map((k) => (
                <option key={k} value={k}>
                  {workspaces[k].title}
                </option>
              ))}
            </select>
          </label>
          <div className="reference-results">
            {data?.data.map((o) => (
              <button
                disabled={
                  busy ||
                  o.references.some(
                    (r) => r.type === reference.type && r.id === reference.id,
                  )
                }
                key={o.id}
                onClick={async () => {
                  setBusy(true);
                  setError("");
                  try {
                    await api("v1/" + workApi(kind) + "/" + o.id, {
                      method: "PUT",
                      body: JSON.stringify({
                        object: {
                          ...o,
                          references: [...o.references, reference],
                        },
                        expected_revision: o.revision,
                        reason: "Pinned intelligence to " + kind,
                      }),
                    });
                    onClose();
                  } catch (e) {
                    setError(
                      e instanceof Error
                        ? e.message
                        : "Could not pin intelligence.",
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {o.title}
                <small>{o.status}</small>
              </button>
            ))}
          </div>
          {data && !data.data.length && (
            <p>
              Create a{" "}
              <Link className="text-link" href={"/" + workspaces[kind].path}>
                {kind}
              </Link>{" "}
              before pinning intelligence.
            </p>
          )}
          {error && (
            <p role="alert" className="form-error">
              {error}
            </p>
          )}
        </Modal>
      }
    </>
  );
}
