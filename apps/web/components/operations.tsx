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
  useTable,
  tableFeatures,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useApi, api } from "@/lib/api";
import { percent, relativeTime } from "@/lib/utils";
import { Modal } from "./ui/modal";
import { Button } from "./ui/button";
import { PageHeader, DataState } from "./shell";
import {
  EnvironmentSchema,
  type Assessment,
  type CustomerEnvironment,
} from "../../../packages/schemas/src/index";
import { operationalUrgency } from "../../../packages/enterprise/src/urgency";
import {
  cvePriorityTitle,
  evaluateCustomerExposure,
  exposureRelevanceLabel,
  type ExposureClaim,
} from "../../../packages/enterprise/src/scoring";
import { effectiveRecommendations } from "../../../packages/database/src/decision-state";
import { useViewState, copyText } from "@/lib/view-state";
import { QueryField, FilterSelect, EmptyResults } from "./filter-controls";
import { SavedViews } from "./saved-views";
import { AssessmentFilters } from "../../../packages/schemas/src/query";
const assessmentTableFeatures = tableFeatures({});

export function Severity({ value }: { value: string }) {
  return (
    <span className={"severity severity-" + value}>
      <span />
      {value}
    </span>
  );
}
// leaf-1.2.2 (audit finding 5): threat severity, evidence confidence, customer
// relevance and operational urgency are four SEPARATELY LABELLED values. A
// "High" threat badge never shares a row with an unexplained "Low" relevance
// badge — every value carries its own label. Unknown renders as "Unknown",
// never 0% (finding 7 vocabulary): a claim without supporting evidence is
// unknown, not zero, and routes to the enrichment backlog.
const confidenceDisplay = (a: Assessment) =>
  a.evidence.length ? percent(a.confidence) : "Unknown";
function productsFrom(a: Assessment) {
  return a.evidence.flatMap((e) => {
    const product =
      typeof e.data.product === "string" ? e.data.product : undefined;
    const version =
      typeof e.data.version === "string" ? e.data.version : undefined;
    const vendor =
      typeof e.data.vendor === "string" ? e.data.vendor : undefined;
    return product || version || vendor
      ? [{ product, version, vendor }]
      : [];
  });
}
function exposureFor(
  a: Assessment,
  environment: CustomerEnvironment | undefined,
): ExposureClaim {
  return evaluateCustomerExposure({
    environment: environment ?? EnvironmentSchema.parse({}),
    products: productsFrom(a),
    kev:
      a.evidence.some((e) => e.data.kev === true) ||
      a.customer.reasons.includes("CISA_KEV"),
    observations: a.customer.observed
      ? [{ observableId: a.observable.id }]
      : [],
  });
}
// leaf-1.3.2: empty profile → Unknown, never 0% relevance from KEV alone
const relevanceDisplay = (
  a: Assessment,
  environment?: CustomerEnvironment,
) => {
  if (!a.evidence.length) return "Unknown";
  const claim = exposureFor(a, environment);
  return exposureRelevanceLabel(claim, a.customer.relevance);
};
function priorityTitle(a: Assessment, claim: ExposureClaim) {
  if (a.observable.type === "cve") return cvePriorityTitle(claim);
  if (a.role.value === "c2") return "Command & control infrastructure";
  if (a.observable.type === "sha256") return "Known malware payload";
  return "Potential threat activity";
}
function exposureMetaLine(a: Assessment, claim: ExposureClaim) {
  if (claim.applicability === "unknown")
    return "Applicability to your environment unknown";
  if (claim.matchedAssetIds.length)
    return `${claim.matchedAssetIds.length} matched assets`;
  if (claim.hasSighting || a.customer.observed)
    return "SIEM/EDR sighting recorded";
  return `${a.evidence.length} evidence records`;
}
function urgencyDisplay(a: Assessment) {
  const { urgency, unknownComponents } = operationalUrgency(a);
  // Zero evidence means the assessment is unrankable — unknown urgency, never
  // a low score.
  if (unknownComponents.includes("evidenceConfidence")) return "Unknown";
  return percent(urgency) + (unknownComponents.length ? " (partial)" : "");
}
function urgencyDetail(a: Assessment) {
  const unknown = operationalUrgency(a).unknownComponents;
  return unknown.length
    ? "Unknown inputs treated as neutral: " + unknown.join(", ")
    : undefined;
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
    enrichment_backlog: Assessment[];
  }>("v1/assessments?" + params.toString());
  const { data: environment } = useApi<CustomerEnvironment>("v1/environment");
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
  const backlog = data?.enrichment_backlog ?? [];
  const columns: ColumnDef<typeof assessmentTableFeatures, Assessment>[] = [
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
      header: "Threat severity",
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
      header: "Overall confidence",
      cell: ({ row }) =>
        row.original.evidence.length ? (
          <div className="confidence-cell">
            <span className="confidence-track">
              <i style={{ width: percent(row.original.confidence) }} />
            </span>
            <span className="mono">{percent(row.original.confidence)}</span>
          </div>
        ) : (
          <span className="muted mono">Unknown</span>
        ),
    },
    {
      header: "Customer relevance",
      cell: ({ row }) => (
        <span className="mono">
          {relevanceDisplay(row.original, environment)}
        </span>
      ),
    },
    {
      header: "Operational urgency",
      cell: ({ row }) => (
        <span className="mono" title={urgencyDetail(row.original)}>
          {urgencyDisplay(row.original)}
        </span>
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
  const table = useTable({
    features: assessmentTableFeatures,
    data: filtered,
    columns,
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
          <span className="text-red">Critical severity</span>
          <strong>{summary.critical.toString().padStart(2, "0")}</strong>
          <small>Immediate investigation</small>
        </button>
        <button
          onClick={() =>
            apply({ ...filters, view: "attention", severity: "high" })
          }
        >
          <span className="text-amber">High severity</span>
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
            <span className="muted">Ordered by operational urgency</span>
          </div>
          <section className="priority-grid">
            {priorities.map((a, i) => {
              const claim = exposureFor(a, environment);
              return (
              <Link
                className={"priority-card priority-" + a.severity}
                key={a.assessment_id}
                href={investigationHref(a.assessment_id)}
              >
                <div className="priority-top">
                  <span>
                    <span className="muted">Threat severity</span>{" "}
                    <Severity value={a.severity} />
                  </span>
                  <span className="mono muted">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                </div>
                <h3>{priorityTitle(a, claim)}</h3>
                <p className="priority-observable mono">
                  {a.observable.normalizedValue}
                </p>
                {claim.kev && claim.applicability === "unknown" ? (
                  <p className="muted" style={{ fontSize: 12, margin: "4px 0" }}>
                    Known exploited vulnerability · Applicability to your
                    environment unknown
                  </p>
                ) : null}
                <div
                  className="priority-relevance"
                  title={urgencyDetail(a)}
                >
                  <strong>{urgencyDisplay(a)}</strong>
                  <span>Operational urgency</span>
                  <ArrowUpRight size={19} />
                </div>
                <div className="priority-meta">
                  <span>
                    Overall confidence ·{" "}
                    <span className="mono">{confidenceDisplay(a)}</span>
                  </span>
                  <span>
                    Customer relevance ·{" "}
                    <span className="mono">
                      {relevanceDisplay(a, environment)}
                    </span>
                  </span>
                </div>
                <div className="priority-meta">
                  <span>{exposureMetaLine(a, claim)}</span>
                  <span>
                    {a.human_review ? "Review required" : "Ready for action"}
                  </span>
                </div>
              </Link>
              );
            })}
          </section>
          {backlog.length > 0 && (
            <>
              <div className="section-title">
                <h2>
                  Enrichment backlog{" "}
                  <span className="count-badge">{backlog.length}</span>
                </h2>
                <span className="muted">
                  Insufficient evidence — unknown, not low. Enrich before these
                  can be ranked. Showing the 20 most recent.
                </span>
              </div>
              <section
                className="intelligence-panel"
                aria-label="Enrichment backlog"
              >
                <div className="table-scroll">
                  <table className="intel-table">
                    <thead>
                      <tr>
                        <th>Observable</th>
                        <th>Threat severity</th>
                        <th>Evidence confidence</th>
                        <th>Customer relevance</th>
                        <th>Operational urgency</th>
                        <th>Recommended action</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {backlog.map((a) => (
                        <tr key={a.assessment_id}>
                          <td>
                            <Link
                              href={investigationHref(a.assessment_id)}
                              className="observable-cell"
                            >
                              <span className="observable-icon">
                                {a.observable.type === "domain" ? (
                                  <Globe size={17} />
                                ) : a.observable.type.includes("sha") ? (
                                  <Hash size={17} />
                                ) : (
                                  <Server size={17} />
                                )}
                              </span>
                              <span>
                                <strong>{a.observable.normalizedValue}</strong>
                                <small>{a.observable.type}</small>
                              </span>
                            </Link>
                          </td>
                          <td>
                            <Severity value={a.severity} />
                          </td>
                          <td>
                            <span className="mono">
                              {confidenceDisplay(a)}
                            </span>
                          </td>
                          <td>
                            <span className="mono">
                              {relevanceDisplay(a, environment)}
                            </span>
                          </td>
                          <td>
                            <span className="mono" title={urgencyDetail(a)}>
                              {urgencyDisplay(a)}
                            </span>
                          </td>
                          <td>
                            <span className="review-status">
                              {effectiveRecommendations(a)[0]?.action ??
                                "enrich"}
                            </span>
                          </td>
                          <td>
                            <Link
                              aria-label={
                                "Enrich " + a.observable.normalizedValue
                              }
                              href={investigationHref(a.assessment_id)}
                            >
                              Enrich <ArrowUpRight size={15} />
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
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
                label="Threat severity"
                value={filters.severity ?? ""}
                options={[
                  ["", "Any severity"],
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
                  ["relevance", "Highest operational urgency"],
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
                          {row.getAllCells().map((cell) => (
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
