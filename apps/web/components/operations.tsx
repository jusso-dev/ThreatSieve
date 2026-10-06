"use client";
import { usePermission } from "@/lib/access";
import Link from "next/link";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowUpRight,
  ArrowRight,
  Plus,
  Copy,
  ShieldAlert,
  Globe,
  Hash,
  Server,
  RefreshCw,
  CircleHelp,
  Layers,
  CheckCheck,
} from "lucide-react";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useApi, api } from "@/lib/api";
import { percent, relativeTime } from "@/lib/utils";
import { Modal } from "./ui/modal";
import { Button } from "./ui/button";
import { PageHeader, DataState } from "./shell";
import type { Assessment } from "../../../packages/schemas/src/index";
import { useViewState, copyText } from "@/lib/view-state";
import { QueryField, FilterSelect, EmptyResults } from "./filter-controls";
import { SavedViews } from "./saved-views";
import { AssessmentFilters } from "../../../packages/schemas/src/query";
export function Severity({ value }: { value: string }) {
  return (
    <span className={"severity severity-" + value}>
      <span />
      {value}
    </span>
  );
}
export function Operations() {
  const canWrite = usePermission("assessment:write");
  const { params: urlParams, update } = useViewState();
  const parsedFilters = AssessmentFilters.safeParse(
    Object.fromEntries(urlParams),
  );
  const filters = parsedFilters.success
    ? parsedFilters.data
    : AssessmentFilters.parse({ view: "attention" });
  if (!urlParams.has("view")) filters.view = "attention";
  const filter = filters.view;
  const investigationHref = (id: string) =>
    "/investigations/" +
    encodeURIComponent(id) +
    "?return_to=" +
    encodeURIComponent("/?" + urlParams.toString());
  const cursor = urlParams.get("cursor") ?? "";
  const [history, setHistory] = useState<string[]>([]);
  const change = (key: string, value: string, replace = false) => {
    setHistory([]);
    update({ [key]: value }, replace);
  };
  const setFilter = (value: string) => change("view", value);
  const apply = (next: AssessmentFilters) => {
    setHistory([]);
    update(
      Object.fromEntries(
        [
          "view",
          "q",
          "severity",
          "classification",
          "observable_type",
          "status",
          "min_confidence",
          "observed",
          "sort",
        ].map((key) => [
          key,
          String(next[key as keyof AssessmentFilters] ?? ""),
        ]),
      ),
    );
  };
  const params = new URLSearchParams(
    Object.entries(filters).map(([key, value]) => [key, String(value)]),
  );
  params.set("limit", "50");
  if (cursor) params.set("cursor", cursor);
  const { data, error, loading, reload } = useApi<{
    data: Assessment[];
    next_cursor: string | null;
    summary: {
      total: number;
      attention: number;
      critical: number;
      high: number;
      review: number;
    };
    priority: Assessment[];
  }>("v1/assessments?" + params.toString());
  const [observable, setObservable] = useState("");
  const [showAssess, setShowAssess] = useState(false);
  useEffect(() => {
    if (urlParams.get("assess") === "1" && canWrite) {
      setShowAssess(true);
      update({ assess: "" }, true);
    }
  }, [urlParams, canWrite]);
  const [busy, setBusy] = useState(false);
  const [assessError, setAssessError] = useState("");
  const router = useRouter();
  const all = data?.data ?? [];
  const summary = data?.summary ?? {
    total: 0,
    attention: 0,
    critical: 0,
    high: 0,
    review: 0,
  };
  const filtered = all;
  const priorities = data?.priority ?? [];
  const columns: ColumnDef<Assessment>[] = [
    {
      header: "Observable",
      accessorKey: "observable.normalizedValue",
      cell: ({ row }) => (
        <Link
          href={investigationHref(row.original.assessment_id)}
          className="observable-cell"
        >
          <span className="observable-icon">
            {row.original.observable.type === "domain" ? (
              <Globe size={17} />
            ) : row.original.observable.type.includes("sha") ? (
              <Hash size={17} />
            ) : (
              <Server size={17} />
            )}
          </span>
          <span>
            <strong>{row.original.observable.normalizedValue}</strong>
            <small>
              {row.original.observable.type} <span>·</span>{" "}
              {(row.original.effective_role ?? row.original.role.value) === "c2"
                ? "Command & control"
                : (row.original.effective_role ?? row.original.role.value)}
            </small>
          </span>
        </Link>
      ),
    },
    {
      header: "Priority",
      cell: ({ row }) => <Severity value={row.original.severity} />,
    },
    {
      header: "Decision",
      cell: ({ row }) => (
        <span
          className={
            (row.original.effective_classification ??
              row.original.malicious.classification) === "malicious"
              ? "text-red"
              : (row.original.effective_classification ??
                    row.original.malicious.classification) === "benign"
                ? "text-green"
                : "text-amber"
          }
        >
          {row.original.effective_classification ??
            row.original.malicious.classification}{" "}
          <span className="mono muted">
            {row.original.effective_classification
              ? "· analyst"
              : percent(row.original.malicious.probability)}
          </span>
        </span>
      ),
    },
    {
      header: "Confidence",
      cell: ({ row }) => (
        <div className="confidence-cell">
          <span className="confidence-track">
            <i style={{ width: percent(row.original.confidence) }} />
          </span>
          <span className="mono">{percent(row.original.confidence)}</span>
        </div>
      ),
    },
    {
      header: "Review",
      cell: ({ row }) => (
        <span className={"review-status status-" + row.original.status}>
          {row.original.status.replaceAll("-", " ")}
        </span>
      ),
    },
    {
      header: "Sources",
      cell: ({ row }) => (
        <span className="source-count">
          <Layers size={13} />
          {row.original.sources.length} sources
        </span>
      ),
    },
    {
      header: "Assessed",
      cell: ({ row }) => (
        <span className="muted mono">
          {relativeTime(row.original.created_at)}
        </span>
      ),
    },
    {
      id: "open",
      header: "",
      cell: ({ row }) => (
        <Link
          aria-label={"Investigate " + row.original.observable.normalizedValue}
          href={investigationHref(row.original.assessment_id)}
        >
          <ArrowUpRight size={17} />
        </Link>
      ),
    },
  ];
  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });
  const submit = async () => {
    if (!observable.trim()) return;
    setBusy(true);
    setAssessError("");
    try {
      const a = await api<Assessment>("v1/assess", {
        method: "POST",
        body: JSON.stringify({ observable }),
      });
      router.push(investigationHref(a.assessment_id));
    } catch (e) {
      setAssessError(e instanceof Error ? e.message : "Assessment failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="THREAT OPERATIONS"
        title="Threat operations"
        description="Your intelligence, correlated and prioritised for action."
        action={
          <div className="actions">
            <Button
              variant="outline"
              onClick={() => void reload()}
              aria-label="Refresh intelligence"
            >
              <RefreshCw size={15} />
            </Button>
            <Button
              disabled={!canWrite}
              title={
                !canWrite
                  ? "An analyst or admin role is required to assess indicators."
                  : undefined
              }
              onClick={() => setShowAssess(true)}
            >
              <Plus size={16} /> Assess observable
            </Button>
          </div>
        }
      />
      {all.some((a) => a.demo) && (
        <div className="demo-banner">
          <CircleHelp size={14} />
          <span>
            Demonstration workspace. Synthetic scenarios illustrate decisions;
            they are not live threat intelligence.
          </span>
          <span className="demo-label">DEMO</span>
        </div>
      )}
      <section
        className="attention-strip"
        aria-label="Threat attention summary"
      >
        <button
          onClick={() => setFilter("attention")}
          className="attention-primary"
        >
          <span>Requires attention</span>
          <strong>{summary.attention.toString().padStart(2, "0")}</strong>
          <small>Prioritised intelligence</small>
        </button>
        <button
          onClick={() =>
            apply({ ...filters, view: "attention", severity: "critical" })
          }
        >
          <span className="text-red">Critical</span>
          <strong>{summary.critical.toString().padStart(2, "0")}</strong>
          <small>Immediate investigation</small>
        </button>
        <button
          onClick={() =>
            apply({ ...filters, view: "attention", severity: "high" })
          }
        >
          <span className="text-amber">High priority</span>
          <strong>{summary.high.toString().padStart(2, "0")}</strong>
          <small>Elevated threat activity</small>
        </button>
        <button onClick={() => setFilter("review")}>
          <span>Analyst review</span>
          <strong>{summary.review.toString().padStart(2, "0")}</strong>
          <small>Human judgment required</small>
        </button>
        <div className="signal-summary">
          <span className="signal-icon">
            <ShieldAlert size={25} />
          </span>
          <p>
            Signal over noise.
            <small>{summary.total} assessments with traceable evidence</small>
          </p>
        </div>
      </section>
      <DataState loading={loading} error={error} />
      {
        <>
          <div className="section-title">
            <h2>
              Priority intelligence{" "}
              <span className="count-badge">{priorities.length}</span>
            </h2>
            <span className="muted">Ordered by customer relevance</span>
          </div>
          <section className="priority-grid">
            {priorities.map((a, i) => (
              <Link
                className={"priority-card priority-" + a.severity}
                key={a.assessment_id}
                href={investigationHref(a.assessment_id)}
              >
                <div className="priority-top">
                  <Severity value={a.severity} />
                  <span className="mono muted">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                </div>
                <h3>
                  {a.observable.type === "cve"
                    ? "Exploited vulnerability exposure"
                    : a.role.value === "c2"
                      ? "Command & control infrastructure"
                      : a.observable.type === "sha256"
                        ? "Known malware payload"
                        : "Potential threat activity"}
                </h3>
                <p className="priority-observable mono">
                  {a.observable.normalizedValue}
                </p>
                <div className="priority-relevance">
                  <strong>{percent(a.customer.relevance)}</strong>
                  <span>customer relevance</span>
                  <ArrowUpRight size={19} />
                </div>
                <div className="priority-meta">
                  <span>
                    {a.customer.exposedAssets > 0
                      ? `${a.customer.exposedAssets} exposed assets`
                      : `${a.evidence.length} evidence records`}
                  </span>
                  <span>
                    {a.human_review ? "Review required" : "Ready for action"}
                  </span>
                </div>
              </Link>
            ))}
          </section>
          <section className="intelligence-panel">
            <div className="panel-toolbar">
              <div className="tabs">
                {[
                  ["attention", "Requires attention"],
                  ["all", "All intelligence"],
                  ["review", "Needs review"],
                ].map(([id, label]) => (
                  <button
                    key={id}
                    aria-pressed={filter === id}
                    className={filter === id ? "selected" : ""}
                    onClick={() => setFilter(id!)}
                  >
                    {label}
                    {id === "attention" && <span>{summary.attention}</span>}
                  </button>
                ))}
              </div>
              <div className="table-controls">
                <SavedViews filters={filters} onApply={apply} />
              </div>
            </div>
            <div className="triage-filters">
              <QueryField
                label="Filter observables"
                placeholder="Filter observables…"
                value={filters.q}
                onChange={(v) => change("q", v, true)}
              />
              <FilterSelect
                label="Priority"
                value={filters.severity ?? ""}
                options={[
                  ["", "Any priority"],
                  ["critical", "Critical"],
                  ["high", "High"],
                  ["medium", "Medium"],
                  ["low", "Low"],
                  ["informational", "Informational"],
                ]}
                onChange={(v) => change("severity", v)}
              />
              <FilterSelect
                label="Decision"
                value={filters.classification ?? ""}
                options={[
                  ["", "Any decision"],
                  ["malicious", "Malicious"],
                  ["suspicious", "Suspicious"],
                  ["benign", "Benign"],
                  ["unknown", "Unknown"],
                ]}
                onChange={(v) => change("classification", v)}
              />
              <FilterSelect
                label="Customer observation"
                value={filters.observed ?? ""}
                options={[
                  ["", "All observations"],
                  ["yes", "Observed internally"],
                  ["no", "Not observed internally"],
                ]}
                onChange={(v) => change("observed", v)}
              />
              <FilterSelect
                label="Sort assessments"
                value={filters.sort}
                options={[
                  ["newest", "Newest first"],
                  ["oldest", "Oldest first"],
                  ["confidence", "Highest confidence"],
                  ["relevance", "Most relevant"],
                ]}
                onChange={(v) => change("sort", v)}
              />
            </div>
            <details className="advanced-filters">
              <summary>More filters & view options</summary>
              <div className="triage-filters">
                <FilterSelect
                  label="Observable type"
                  value={filters.observable_type ?? ""}
                  options={[
                    ["", "Any type"],
                    ...[
                      "ipv4",
                      "ipv6",
                      "domain",
                      "hostname",
                      "url",
                      "email",
                      "sha256",
                      "sha1",
                      "md5",
                      "cve",
                      "ja3",
                      "ja4",
                      "certificate",
                      "asn",
                      "file",
                      "process",
                      "registry-key",
                      "user-agent",
                      "mutex",
                    ].map((v) => [v, v] as const),
                  ]}
                  onChange={(v) => change("observable_type", v)}
                />
                <FilterSelect
                  label="Review status"
                  value={filters.status ?? ""}
                  options={[
                    ["", "Any status"],
                    ["pending", "Pending"],
                    ["confirmed", "Confirmed"],
                    ["rejected", "Rejected"],
                    ["modified", "Modified"],
                    ["needs-investigation", "Needs investigation"],
                  ]}
                  onChange={(v) => change("status", v)}
                />
                <FilterSelect
                  label="Minimum confidence"
                  value={String(filters.min_confidence ?? "")}
                  options={[
                    ["", "Any confidence"],
                    ["0.5", "50% or higher"],
                    ["0.7", "70% or higher"],
                    ["0.9", "90% or higher"],
                  ]}
                  onChange={(v) => change("min_confidence", v)}
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    void copyText(
                      window.location.href,
                      "Triage view link copied. Workspace permissions still apply.",
                    )
                  }
                >
                  <Copy size={14} />
                  Copy view link
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    apply(AssessmentFilters.parse({ view: filter }))
                  }
                >
                  Clear filters
                </Button>
              </div>
            </details>
            {!loading &&
              !error &&
              (filtered.length ? (
                <div className="table-scroll">
                  <table className="intel-table">
                    <thead>
                      {table.getHeaderGroups().map((group) => (
                        <tr key={group.id}>
                          {group.headers.map((header) => (
                            <th key={header.id}>
                              {flexRender(
                                header.column.columnDef.header,
                                header.getContext(),
                              )}
                            </th>
                          ))}
                        </tr>
                      ))}
                    </thead>
                    <tbody>
                      {table.getRowModel().rows.map((row) => (
                        <tr key={row.id}>
                          {row.getVisibleCells().map((cell) => (
                            <td key={cell.id}>
                              {flexRender(
                                cell.column.columnDef.cell,
                                cell.getContext(),
                              )}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyResults
                  noun="assessments"
                  onReset={() =>
                    apply(AssessmentFilters.parse({ view: "all" }))
                  }
                />
              ))}
            <div className="table-footer">
              <span>
                {filtered.length} assessments on page {history.length + 1}
              </span>
              <div className="actions">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!cursor || loading}
                  onClick={() => {
                    update({ cursor: history.at(-1) ?? "" });
                    setHistory(history.slice(0, -1));
                  }}
                >
                  Previous page
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!data?.next_cursor || loading}
                  onClick={() => {
                    setHistory([...history, cursor]);
                    update({ cursor: data!.next_cursor! });
                  }}
                >
                  Next page
                </Button>
              </div>
              <span>
                <CheckCheck size={13} /> Full provenance retained
              </span>
            </div>
          </section>
          <div className="operations-note">
            <CircleHelp size={16} />
            <p>
              <strong>Unknown is an intelligence outcome.</strong> Actor
              associations remain unconfirmed until independent evidence
              supports attribution.
            </p>
            <Link href="/clusters">
              Explore emerging clusters <ArrowRight size={14} />
            </Link>
          </div>
        </>
      }
      {showAssess && (
        <Modal
          titleId="assess-title"
          busy={busy}
          onClose={() => setShowAssess(false)}
        >
          <h2 id="assess-title">Assess an observable</h2>
          <p>
            ThreatSieve will gather existing evidence and classify the supported
            decisions.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <label htmlFor="observable">IP, domain, URL, hash or CVE</label>
            <input
              id="observable"
              autoFocus
              required
              value={observable}
              onChange={(e) => setObservable(e.target.value)}
              placeholder="example.com"
            />
            {assessError && (
              <p role="alert" className="text-red">
                {assessError}
              </p>
            )}
            <div className="modal-actions">
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setShowAssess(false)}
              >
                Cancel
              </Button>
              <Button disabled={busy}>
                {busy ? "Evaluating evidence…" : "Run assessment"}
                <ArrowRight size={15} />
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
