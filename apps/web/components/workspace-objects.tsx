"use client";
import Link from "next/link";
import { PlaybookActions } from "./playbook-actions";
import { z } from "zod";
import {
  WorkspaceMatches,
  ExecutionHistory,
  CollectionPublication,
  InvestigationGraph,
} from "./workspace-activity";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Plus, ArrowLeft, RefreshCw } from "lucide-react";
import { api, useApi } from "@/lib/api";
import { usePermission } from "@/lib/access";
import { useViewState } from "@/lib/view-state";
import { workspaces, workApi, splitValues } from "@/lib/workspace";
import { absoluteTime, relativeTime } from "@/lib/utils";
import {
  WorkInput,
  type WorkKind,
  type WorkObject,
  type IntelligenceEvent,
} from "../../../packages/schemas/src/enterprise";
import { PageHeader, DataState } from "./shell";
import { Button } from "./ui/button";
import { Modal } from "./ui/modal";
import { QueryField, FilterSelect } from "./filter-controls";
import { ReferencePicker, ReferenceList } from "./workspace-references";
export interface RequirementMetrics {
  coverage: number | null;
  coverageLabel: string;
  freshness: string | null;
  confidence: number | null;
  evidenceCount: number;
  newEvidence: number;
  criteria: { name: string; satisfied: boolean }[];
  gaps: { code: string; message: string }[];
}
interface WorkDetailResponse {
  object: WorkObject;
  history: { data: IntelligenceEvent[]; truncated: boolean };
  metrics?: RequirementMetrics;
}
const score = (n: number | null | undefined, probability = false) =>
  n == null ? "Unknown" : Math.round(n * (probability ? 100 : 1)) + "%";
export function WorkspaceList({ kind }: { kind: WorkKind }) {
  const config = workspaces[kind],
    router = useRouter(),
    canWrite = usePermission(
      kind === "playbook" ? "admin" : "assessment:write",
    );
  const { params, update } = useViewState();
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (params.get("new") === "1" && canWrite) {
      setOpen(true);
      update({ new: "" }, true);
    }
  }, [params, canWrite]);
  const query = new URLSearchParams({
    q: params.get("q") ?? "",
    status: params.get("status") ?? "",
    cursor: params.get("cursor") ?? "",
    limit: "25",
  });
  const { data, loading, error, reload } = useApi<{
    data: (WorkObject & { metrics?: RequirementMetrics })[];
    next_cursor: string | null;
  }>("v1/" + workApi(kind) + "?" + query);
  const members = useApi<{
    data: { id: string; name: string; email: string }[];
  }>("v1/workspace/members");
  return (
    <>
      <PageHeader
        eyebrow="INTELLIGENCE OPERATIONS"
        title={config.title}
        description={config.description}
        action={
          <div className="actions">
            <Button
              variant="ghost"
              aria-label="Refresh workspace"
              onClick={() => void reload()}
            >
              <RefreshCw size={15} />
            </Button>
            <Button disabled={!canWrite} onClick={() => setOpen(true)}>
              <Plus size={15} />
              New {config.singular}
            </Button>
          </div>
        }
      />
      <div className="work-toolbar">
        <QueryField
          label={"Search " + config.title.toLowerCase()}
          value={params.get("q") ?? ""}
          onChange={(v) => update({ q: v }, true)}
        />
        <FilterSelect
          label="Status"
          value={params.get("status") ?? ""}
          onChange={(v) => update({ status: v })}
          options={[
            ["", "All statuses"],
            ...config.statuses.map((s) => [s, s.replaceAll("-", " ")] as const),
          ]}
        />
      </div>
      <DataState loading={loading} error={error} />
      {data && !loading && (
        <>
          <div className="table-scroll work-table">
            <table className="intel-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>{config.singular}</th>
                  <th>Status</th>
                  {kind === "requirement" && (
                    <>
                      <th>Coverage</th>
                      <th>Freshness</th>
                      <th>Confidence</th>
                      <th>New evidence</th>
                    </>
                  )}
                  <th>Owner</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {data.data.map((o) => (
                  <tr key={o.id}>
                    <td>
                      <span className={"priority-text " + o.priority}>
                        {o.priority}
                      </span>
                    </td>
                    <td>
                      <Link
                        className="work-title"
                        href={"/" + config.path + "/" + o.id}
                      >
                        {o.title}
                      </Link>
                      <small className="work-subtitle">
                        {o.kind === "requirement"
                          ? o.question
                          : o.description.slice(0, 100)}
                      </small>
                    </td>
                    <td>{o.status.replaceAll("-", " ")}</td>
                    {kind === "requirement" && (
                      <>
                        <td>{score(o.metrics?.coverage)}</td>
                        <td>
                          {o.metrics?.freshness
                            ? relativeTime(o.metrics.freshness)
                            : "No support"}
                        </td>
                        <td>{score(o.metrics?.confidence, true)}</td>
                        <td>{o.metrics?.newEvidence ?? 0}</td>
                      </>
                    )}
                    <td>
                      {members.data?.data.find((m) => m.id === o.ownerId)
                        ?.name || "Workspace member"}
                    </td>
                    <td title={absoluteTime(o.updatedAt)}>
                      {relativeTime(o.updatedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.data.length && (
            <div className="work-empty">
              <h2>
                {params.get("q") || params.get("status")
                  ? "No matching records"
                  : "No " + config.title.toLowerCase() + " yet"}
              </h2>
              <p>{config.description}</p>
              <Button
                variant="outline"
                disabled={!canWrite}
                onClick={() => setOpen(true)}
              >
                Create {config.singular}
              </Button>
            </div>
          )}
          <div className="table-footer">
            <span>{data.data.length} records on this page</span>
            <div className="actions">
              <Button
                variant="outline"
                size="sm"
                disabled={!params.get("cursor")}
                onClick={() => update({ cursor: "" })}
              >
                First page
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!data.next_cursor}
                onClick={() => update({ cursor: data.next_cursor ?? "" })}
              >
                Next page
              </Button>
            </div>
          </div>
        </>
      )}
      {open && (
        <WorkEditor
          kind={kind}
          onClose={() => setOpen(false)}
          onSaved={(o) => router.push("/" + config.path + "/" + o.id)}
        />
      )}
    </>
  );
}
export function WorkspaceDetail({ kind, id }: { kind: WorkKind; id: string }) {
  const { data, error, loading, reload } = useApi<WorkDetailResponse>(
    "v1/" + workApi(kind) + "/" + id,
  );
  const canWrite = usePermission(
    kind === "playbook" ? "admin" : "assessment:write",
  );
  const [editing, setEditing] = useState(false),
    [pin, setPin] = useState(false),
    [note, setNote] = useState(""),
    [noteType, setNoteType] = useState("note"),
    [busy, setBusy] = useState(false),
    [task, setTask] = useState(""),
    [pendingTasks, setPendingTasks] = useState<Record<string, boolean>>({}),
    [message, setMessage] = useState("");
  const members = useApi<{
    data: { id: string; name: string; email: string }[];
  }>("v1/workspace/members");
  if (!data) return <DataState loading={loading} error={error} />;
  const o = data.object,
    config = workspaces[kind];
  const save = async (next: WorkObject, reason: string) => {
    setBusy(true);
    setMessage("");
    try {
      await api("v1/" + workApi(kind) + "/" + id, {
        method: "PUT",
        body: JSON.stringify({
          object: next,
          expected_revision: o.revision,
          reason,
        }),
      });
      await reload();
      return true;
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Could not save changes.");
      return false;
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Link className="back-link" href={"/" + config.path}>
        <ArrowLeft size={13} />
        {config.title}
      </Link>
      <PageHeader
        eyebrow={kind.toUpperCase() + " · REVISION " + o.revision}
        title={o.title}
        description={o.description}
        action={
          <div className="actions">
            {(kind === "report" ||
              kind === "collection" ||
              kind === "investigation") && (
              <Button asChild variant="outline">
                <a
                  href={
                    "/api/v1/" +
                    workApi(kind) +
                    "/" +
                    id +
                    "/export?format=html"
                  }
                  target="_blank"
                  rel="noopener"
                >
                  Export / print
                </a>
              </Button>
            )}
            <Button
              disabled={!canWrite}
              variant="outline"
              onClick={() => setEditing(true)}
            >
              Edit {config.singular}
            </Button>
          </div>
        }
      />
      <div className="work-properties">
        <span className={"priority-text " + o.priority}>
          {o.priority} priority
        </span>
        <span>{o.status.replaceAll("-", " ")}</span>
        <span>
          Owner:{" "}
          {members.data?.data.find((m) => m.id === o.ownerId)?.name ||
            "Workspace member"}
        </span>
        <span>Updated {relativeTime(o.updatedAt)}</span>
        {o.tags.map((t) => (
          <span className="entity-type" key={t}>
            {t}
          </span>
        ))}
      </div>
      {message && (
        <p className="form-error" role="alert">
          {message}
        </p>
      )}
      <div className="work-detail-grid">
        <div>
          {o.kind === "requirement" && (
            <section className="work-section">
              <h2>Intelligence question</h2>
              <p className="question-text">{o.question}</p>
              <dl className="work-metrics">
                <div>
                  <dt>Coverage</dt>
                  <dd>{score(data.metrics?.coverage)}</dd>
                </div>
                <div>
                  <dt>Evidence confidence</dt>
                  <dd>{score(data.metrics?.confidence, true)}</dd>
                </div>
                <div>
                  <dt>Supporting records</dt>
                  <dd>{data.metrics?.evidenceCount ?? 0}</dd>
                </div>
                <div>
                  <dt>Newest support</dt>
                  <dd>
                    {data.metrics?.freshness
                      ? relativeTime(data.metrics.freshness)
                      : "None"}
                  </dd>
                </div>
              </dl>
              <p className="muted">{data.metrics?.coverageLabel}</p>
              <div className="criteria-grid">
                {data.metrics?.criteria.map((c) => (
                  <span key={c.name}>
                    {c.satisfied ? "Supported" : "Gap"} · {c.name}
                  </span>
                ))}
              </div>
              <h3>Collection requirements</h3>
              {o.collectionRequirements.length ? (
                <ul>
                  {o.collectionRequirements.map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No additional collection tasks defined.</p>
              )}
              <h3>Intelligence gaps</h3>
              {data.metrics?.gaps.map((g, i) => (
                <p className="gap-row" key={g.code + i}>
                  {g.message}
                </p>
              ))}
              <div className="actions">
                <span>
                  Next review:{" "}
                  {o.nextReview ? absoluteTime(o.nextReview) : "Not scheduled"}
                </span>
                <Button
                  variant="outline"
                  disabled={!canWrite || busy}
                  onClick={() =>
                    void save(
                      { ...o, lastReviewed: new Date().toISOString() },
                      "Requirement reviewed",
                    )
                  }
                >
                  Mark reviewed
                </Button>
              </div>
            </section>
          )}
          {o.kind === "investigation" && (
            <section className="work-section">
              <h2>Working hypothesis</h2>
              <p className="preserve-lines">
                {o.hypothesis ||
                  "No hypothesis recorded. Add a testable explanation before drawing conclusions."}
              </p>
              <h3>Tasks</h3>
              {o.tasks.map((t) => (
                <label className="task-row" key={t.id}>
                  <input
                    type="checkbox"
                    checked={pendingTasks[t.id] ?? t.done}
                    disabled={!canWrite || busy}
                    onChange={(e) => {
                      const done = e.target.checked;
                      setPendingTasks((v) => ({ ...v, [t.id]: done }));
                      void save(
                        {
                          ...o,
                          tasks: o.tasks.map((x) =>
                            x.id === t.id ? { ...x, done } : x,
                          ),
                        },
                        "Task status changed",
                      ).finally(() =>
                        setPendingTasks((v) => {
                          const copy = { ...v };
                          delete copy[t.id];
                          return copy;
                        }),
                      );
                    }}
                  />
                  <span>{t.title}</span>
                  {t.dueAt && <small>{absoluteTime(t.dueAt)}</small>}
                </label>
              ))}
              <form
                className="inline-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (task.trim())
                    void save(
                      {
                        ...o,
                        tasks: [
                          ...o.tasks,
                          {
                            id: crypto.randomUUID(),
                            title: task.trim(),
                            done: false,
                          },
                        ],
                      },
                      "Task added",
                    ).then((saved) => {
                      if (saved) setTask("");
                    });
                }}
              >
                <input
                  aria-label="New investigation task"
                  value={task}
                  onChange={(e) => setTask(e.target.value)}
                  maxLength={200}
                  placeholder="Add an investigation task"
                />
                <Button
                  variant="outline"
                  disabled={!canWrite || busy || !task.trim()}
                >
                  Add task
                </Button>
              </form>
            </section>
          )}
          {o.kind === "report" && (
            <section className="work-section report-content">
              <h2>{o.reportType.replaceAll("-", " ")}</h2>
              <div className="preserve-lines">
                {o.body || "This report has no authored content yet."}
              </div>
              <p className="muted">
                Analyst-authored text. Citations are listed below; references do
                not establish that every statement has been verified.
              </p>
            </section>
          )}
          {"criteria" in o && o.kind !== "requirement" && (
            <section className="work-section">
              <h2>Collection criteria</h2>
              <dl className="criteria-grid">
                {Object.entries(o.criteria)
                  .filter(([, v]) => Array.isArray(v) && v.length)
                  .map(([k, v]) => (
                    <div key={k}>
                      <dt>{k}</dt>
                      <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
                    </div>
                  ))}
              </dl>
              {o.kind === "watchlist" && (
                <p>
                  Notify on:{" "}
                  {o.triggers.map((t) => t.replaceAll(".", " ")).join(", ")}
                </p>
              )}
              {o.kind === "collection" && (
                <p>
                  Access: {o.publication}. Publication preserves source
                  redistribution restrictions.
                </p>
              )}
              {o.kind === "playbook" && (
                <>
                  <p>Trigger: {o.trigger}</p>
                  <ol>
                    {o.actions.map((a, i) => (
                      <li key={i}>
                        {a.type}
                        {a.target ? " · " + a.target : ""}
                      </li>
                    ))}
                  </ol>
                </>
              )}
            </section>
          )}
          <section className="work-section">
            <div className="section-title">
              <h2>Referenced intelligence</h2>
              <Button
                size="sm"
                variant="outline"
                disabled={!canWrite}
                onClick={() => setPin(true)}
              >
                <Plus size={14} />
                Add reference
              </Button>
            </div>
            <ReferenceList references={o.references} />
            {!o.references.length && (
              <p className="muted">
                No intelligence pinned. Link existing records to preserve their
                provenance.
              </p>
            )}
          </section>
          {["requirement", "watchlist", "collection"].includes(o.kind) && (
            <WorkspaceMatches
              object={o}
              canWrite={canWrite}
              onAccept={(entityId) =>
                void save(
                  {
                    ...o,
                    references: [
                      ...o.references,
                      {
                        type: "entity",
                        id: entityId,
                        relation:
                          o.kind === "requirement" ? "supports" : "member",
                      },
                    ],
                  },
                  "Analyst linked matching intelligence",
                )
              }
            />
          )}
          {o.kind === "investigation" && <InvestigationGraph object={o} />}
          {o.kind === "playbook" && <ExecutionHistory id={o.id} />}
          {o.kind === "collection" &&
            o.status === "published" &&
            o.publication === "taxii" && (
              <CollectionPublication object={o} canWrite={canWrite} />
            )}
          <section className="work-section">
            <h2>Analyst notes & decisions</h2>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                  await api("v1/" + workApi(kind) + "/" + id + "/notes", {
                    method: "POST",
                    body: JSON.stringify({
                      type: noteType,
                      body: note,
                      references: [],
                    }),
                  });
                  setNote("");
                  await reload();
                } catch {
                  // The API helper displays errors and preserves the note draft.
                } finally {
                  setBusy(false);
                }
              }}
            >
              <label htmlFor="note-type">Entry type</label>
              <select
                id="note-type"
                value={noteType}
                onChange={(e) => setNoteType(e.target.value)}
              >
                <option value="note">Analyst note</option>
                <option value="decision">Analyst decision</option>
              </select>
              <label htmlFor="analyst-note">Reasoning and evidence</label>
              <textarea
                id="analyst-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={10000}
                rows={4}
              />
              <div className="form-actions">
                <Button disabled={!canWrite || busy || !note.trim()}>
                  Record {noteType}
                </Button>
              </div>
            </form>
          </section>
        </div>
        <aside className="work-history">
          <h2>Activity & decision log</h2>
          {data.history.data.map((e) => (
            <article key={e.id}>
              <div>
                <strong>{e.event_type.replaceAll(".", " ")}</strong>
                <time title={absoluteTime(e.created_at)}>
                  {relativeTime(e.created_at)}
                </time>
              </div>
              <small>
                {members.data?.data.find((m) => m.id === e.actor_id)?.name ||
                  "Workspace member"}
              </small>
              <p className="preserve-lines">
                {typeof e.data.body === "string"
                  ? e.data.body
                  : typeof e.data.reason === "string"
                    ? e.data.reason
                    : ""}
              </p>
            </article>
          ))}
          {data.history.truncated && (
            <p className="muted">Showing the latest 100 events.</p>
          )}
        </aside>
      </div>
      {editing && (
        <WorkEditor
          kind={kind}
          initial={o}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            void reload();
          }}
        />
      )}
      {pin && (
        <ReferencePicker
          onClose={() => setPin(false)}
          onSelect={(ref) => {
            setPin(false);
            void save(
              { ...o, references: [...o.references, ref] },
              "Intelligence reference added",
            );
          }}
        />
      )}
    </>
  );
}
export function WorkEditor({
  kind,
  initial,
  onClose,
  onSaved,
}: {
  kind: WorkKind;
  initial?: WorkObject;
  onClose: () => void;
  onSaved: (o: WorkObject) => void;
}) {
  const config = workspaces[kind];
  const [draft, setDraft] = useState<Record<string, unknown>>(() =>
    initial
      ? { ...initial }
      : {
          kind,
          title: "",
          description: "",
          priority: "medium",
          status: config.statuses[0],
          question: "",
          criteria: {},
          references: [],
          ...(kind === "playbook"
            ? { trigger: "sighting.created", actions: [{ type: "notify" }] }
            : {}),
        },
  );
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [reason, setReason] = useState("");
  const members = useApi<{
    data: { id: string; name: string; email: string }[];
  }>("v1/workspace/members");
  const set = (key: string, value: unknown) =>
    setDraft((d) => ({ ...d, [key]: value }));
  const str = (key: string) =>
    typeof draft[key] === "string" ? String(draft[key]) : "";
  const listField = (key: string, label: string) => (
    <label key={key}>
      {label}
      <input
        value={
          Array.isArray(draft[key])
            ? (draft[key] as string[]).join(", ")
            : str(key)
        }
        onChange={(e) => set(key, e.target.value)}
      />
      <small>Comma-separated values</small>
    </label>
  );
  const textField = (key: string, label: string, rows = 3) => (
    <label>
      {label}
      <textarea
        rows={rows}
        value={str(key)}
        onChange={(e) => set(key, e.target.value)}
        maxLength={key === "body" ? 50000 : 10000}
      />
    </label>
  );
  return (
    <Modal titleId="work-editor-title" busy={busy} onClose={onClose}>
      <h2 id="work-editor-title">
        {initial ? "Edit" : "New"} {config.singular}
      </h2>
      <form
        className="work-editor"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          try {
            const normalizeLists = (
              data: Record<string, unknown>,
              keys: string[],
            ) =>
              Object.fromEntries(
                Object.entries(data).map(([k, v]) => [
                  k,
                  keys.includes(k) && typeof v === "string"
                    ? splitValues(v)
                    : v,
                ]),
              );
            const prepared = normalizeLists(draft, [
              "tags",
              "collaborators",
              "stakeholders",
              "collectionRequirements",
              "gaps",
            ]);
            if (draft.criteria)
              prepared.criteria = normalizeLists(
                draft.criteria as Record<string, unknown>,
                [
                  "keywords",
                  "technologies",
                  "industries",
                  "countries",
                  "actors",
                  "techniques",
                  "sourceIds",
                  "tags",
                  "entityTypes",
                ],
              );
            const object = WorkInput.parse(prepared);
            const result = await api<WorkObject>(
              "v1/" + workApi(kind) + (initial ? "/" + initial.id : ""),
              {
                method: initial ? "PUT" : "POST",
                body: JSON.stringify(
                  initial
                    ? { object, expected_revision: initial.revision, reason }
                    : object,
                ),
              },
            );
            onSaved(result);
          } catch (e) {
            setError(
              e instanceof z.ZodError
                ? e.issues
                    .map((issue) => issue.path.join(" ") + ": " + issue.message)
                    .join(". ")
                : e instanceof Error
                  ? e.message
                  : "Could not save this record.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Title
          <input
            autoFocus
            required
            minLength={3}
            maxLength={200}
            value={str("title")}
            onChange={(e) => set("title", e.target.value)}
          />
        </label>
        <div className="form-columns">
          <label>
            Priority
            <select
              value={str("priority")}
              onChange={(e) => set("priority", e.target.value)}
            >
              {["critical", "high", "medium", "low"].map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <label>
            Status
            <select
              value={str("status")}
              onChange={(e) => set("status", e.target.value)}
            >
              {config.statuses.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <label>
            Owner
            <select
              value={str("ownerId")}
              onChange={(e) => set("ownerId", e.target.value || undefined)}
            >
              <option value="">Assign to me</option>
              {members.data?.data.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name || m.email}
                </option>
              ))}
            </select>
          </label>
        </div>
        {textField("description", "Description")}
        {kind === "requirement" &&
          textField("question", "Intelligence question", 2)}
        {kind === "investigation" &&
          textField("hypothesis", "Working hypothesis", 4)}
        {kind === "report" && (
          <>
            <label>
              Report type
              <select
                value={str("reportType") || "threat-brief"}
                onChange={(e) => set("reportType", e.target.value)}
              >
                {[
                  "threat-brief",
                  "actor-profile",
                  "campaign-report",
                  "ioc-package",
                  "investigation-report",
                  "executive-brief",
                  "requirement-update",
                ].map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            </label>
            {textField("body", "Report content", 12)}
          </>
        )}
        {listField("tags", "Tags")}
        <details>
          <summary>Collaboration</summary>
          <fieldset>
            <legend>Collaborators</legend>
            {members.data?.data.map((m) => (
              <label className="task-row" key={m.id}>
                <input
                  type="checkbox"
                  checked={
                    Array.isArray(draft.collaborators) &&
                    draft.collaborators.includes(m.id)
                  }
                  onChange={(e) =>
                    set(
                      "collaborators",
                      e.target.checked
                        ? [
                            ...(Array.isArray(draft.collaborators)
                              ? draft.collaborators
                              : []),
                            m.id,
                          ]
                        : (Array.isArray(draft.collaborators)
                            ? draft.collaborators
                            : []
                          ).filter((id) => id !== m.id),
                    )
                  }
                />
                {m.name || m.email}
              </label>
            ))}
          </fieldset>
          {kind === "requirement" && (
            <fieldset>
              <legend>Stakeholders</legend>
              {members.data?.data.map((m) => (
                <label className="task-row" key={m.id}>
                  <input
                    type="checkbox"
                    checked={
                      Array.isArray(draft.stakeholders) &&
                      draft.stakeholders.includes(m.id)
                    }
                    onChange={(e) =>
                      set(
                        "stakeholders",
                        e.target.checked
                          ? [
                              ...(Array.isArray(draft.stakeholders)
                                ? draft.stakeholders
                                : []),
                              m.id,
                            ]
                          : (Array.isArray(draft.stakeholders)
                              ? draft.stakeholders
                              : []
                            ).filter((id) => id !== m.id),
                      )
                    }
                  />
                  {m.name || m.email}
                </label>
              ))}
            </fieldset>
          )}
        </details>
        {["requirement", "watchlist", "collection", "playbook"].includes(
          kind,
        ) && (
          <details open={kind === "requirement"}>
            <summary>Collection criteria</summary>
            <p className="muted">
              Structured criteria identify candidate support. They do not assert
              attribution.
            </p>
            <div className="form-columns">
              {[
                "keywords",
                "technologies",
                "industries",
                "countries",
                "actors",
                "techniques",
                "sourceIds",
                "tags",
                "entityTypes",
              ].map((key) => {
                const criteria = (draft.criteria ?? {}) as Record<
                  string,
                  unknown
                >;
                return (
                  <label key={key}>
                    {key}
                    <input
                      value={
                        Array.isArray(criteria[key])
                          ? (criteria[key] as string[]).join(", ")
                          : typeof criteria[key] === "string"
                            ? String(criteria[key])
                            : ""
                      }
                      onChange={(e) =>
                        set("criteria", { ...criteria, [key]: e.target.value })
                      }
                    />
                  </label>
                );
              })}
              {["from", "to"].map((key) => {
                const criteria = (draft.criteria ?? {}) as Record<
                  string,
                  unknown
                >;
                return (
                  <label key={key}>
                    {key === "from" ? "From date" : "To date"}
                    <input
                      type="date"
                      value={
                        typeof criteria[key] === "string"
                          ? String(criteria[key]).slice(0, 10)
                          : ""
                      }
                      onChange={(e) =>
                        set("criteria", {
                          ...criteria,
                          [key]: e.target.value
                            ? new Date(
                                e.target.value +
                                  (key === "to"
                                    ? "T23:59:59.999Z"
                                    : "T00:00:00.000Z"),
                              ).toISOString()
                            : undefined,
                        })
                      }
                    />
                  </label>
                );
              })}
            </div>
          </details>
        )}
        {kind === "requirement" && (
          <>
            {listField("collectionRequirements", "Collection tasks")}
            {listField("gaps", "Known intelligence gaps")}
            <label>
              Next review
              <input
                type="date"
                value={str("nextReview").slice(0, 10)}
                onChange={(e) =>
                  set(
                    "nextReview",
                    e.target.value
                      ? new Date(e.target.value).toISOString()
                      : undefined,
                  )
                }
              />
            </label>
          </>
        )}
        {kind === "collection" && (
          <label>
            Publication
            <select
              value={str("publication") || "workspace"}
              onChange={(e) => set("publication", e.target.value)}
            >
              <option value="private">
                Private to owner and collaborators
              </option>
              <option value="workspace">Workspace</option>
              <option value="taxii">Authenticated TAXII collection</option>
            </select>
          </label>
        )}
        {kind === "playbook" && (
          <>
            <label>
              Trigger
              <select
                value={str("trigger") || "sighting.created"}
                onChange={(e) => set("trigger", e.target.value)}
              >
                {[
                  "sighting.created",
                  "indicator.created",
                  "indicator.updated",
                  "score.changed",
                  "relationship.created",
                  "feed.failed",
                  "investigation.created",
                  "watchlist.match",
                  "requirement.match",
                ].map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
            <PlaybookActions
              actions={
                Array.isArray(draft.actions)
                  ? (draft.actions as { type: string; target?: string }[])
                  : [{ type: "notify" }]
              }
              onChange={(actions) => set("actions", actions)}
            />
          </>
        )}
        {initial && (
          <label>
            Reason for change
            <textarea
              required
              minLength={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={2}
            />
          </label>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button disabled={busy}>
            {busy ? "Saving…" : "Save " + config.singular}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
