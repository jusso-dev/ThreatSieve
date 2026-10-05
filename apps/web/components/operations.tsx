"use client";
import Link from "next/link";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowUpRight,
  ArrowRight,
  Plus,
  Filter,
  ShieldAlert,
  Globe,
  Hash,
  Server,
  Search,
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
export function Severity({ value }: { value: string }) {
  return (
    <span className={"severity severity-" + value}>
      <span />
      {value}
    </span>
  );
}
export function Operations() {
  const [filter, setFilterValue] = useState("attention");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const setFilter = (value: string) => {
    setFilterValue(value);
    setCursor("");
    setHistory([]);
  };
  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search);
      setCursor("");
      setHistory([]);
    }, 250);
    return () => clearTimeout(timer);
  }, [search]);
  const params = new URLSearchParams({
    view: filter,
    q: query,
    limit: "50",
    ...(cursor ? { cursor } : {}),
  });
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
          href={"/investigations/" + row.original.assessment_id}
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
      header: "Sources",
      cell: ({ row }) => (
        <span className="source-count">
          <Layers size={13} />
          {row.original.sources.length} sources
        </span>
      ),
    },
    {
      header: "Updated",
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
          href={"/investigations/" + row.original.assessment_id}
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
      router.push("/investigations/" + a.assessment_id);
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
        title="Focus on what matters."
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
            <Button onClick={() => setShowAssess(true)}>
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
        <div>
          <span className="text-red">Critical</span>
          <strong>{summary.critical.toString().padStart(2, "0")}</strong>
          <small>Immediate investigation</small>
        </div>
        <div>
          <span className="text-amber">High priority</span>
          <strong>{summary.high.toString().padStart(2, "0")}</strong>
          <small>Elevated threat activity</small>
        </div>
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
      {!loading && !error && (
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
                href={"/investigations/" + a.assessment_id}
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
                    className={filter === id ? "selected" : ""}
                    onClick={() => setFilter(id!)}
                  >
                    {label}
                    {id === "attention" && <span>{summary.attention}</span>}
                  </button>
                ))}
              </div>
              <div className="table-controls">
                <div className="inline-search">
                  <Search size={14} />
                  <input
                    aria-label="Filter observables"
                    placeholder="Filter observables…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <Filter size={16} />
              </div>
            </div>
            {filtered.length ? (
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
              <DataState empty />
            )}
            <div className="table-footer">
              <span>
                {filtered.length} assessments on page {history.length + 1}
              </span>
              <div className="actions">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!history.length || loading}
                  onClick={() => {
                    setCursor(history.at(-1)!);
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
                    setCursor(data!.next_cursor!);
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
      )}
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
