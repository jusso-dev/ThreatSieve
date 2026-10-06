"use client";
import { usePermission } from "@/lib/access";
import { toast } from "sonner";
import Link from "next/link";
import { useState } from "react";
import {
  ArrowLeft,
  Copy,
  Download,
  Check,
  X,
  ShieldCheck,
  Activity,
  Crosshair,
  CheckCircle2,
  HelpCircle,
  RefreshCw,
} from "lucide-react";
import { api, useApi } from "@/lib/api";
import { percent, relativeTime } from "@/lib/utils";
import { DataState } from "./shell";
import { Modal } from "./ui/modal";
import { Button } from "./ui/button";
import { Severity } from "./operations";
import type { Assessment } from "../../../packages/schemas/src/index";
import { IntelligenceGraph } from "./intelligence-graph";
import { EvidenceExplorer } from "./evidence-explorer";
import { copyText, defang } from "@/lib/view-state";
import { ReassessmentProgress } from "./reassessment-progress";
export function Investigation({
  id,
  returnTo = "/",
}: {
  id: string;
  returnTo?: string;
}) {
  const canWrite = usePermission("assessment:write");
  const {
    data: a,
    error,
    loading,
    reload,
  } = useApi<Assessment>("v1/assessments/" + id);
  const [feedback, setFeedback] = useState("");
  const [reason, setReason] = useState("");
  const [feedbackError, setFeedbackError] = useState("");
  const [override, setOverride] = useState("unknown");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [evidenceIds, setEvidenceIds] = useState<string[]>([]);
  const [reassessing, setReassessing] = useState(false);
  const [reassessmentJob, setReassessmentJob] = useState("");
  if (loading || error || !a)
    return <DataState loading={loading} error={error} />;
  const beginFeedback = (action: string) => {
    setFeedbackError("");
    setFeedback(action);
  };
  const save = async () => {
    setBusy(true);
    setFeedbackError("");
    try {
      await api("v1/assessments/" + id + "/" + feedback, {
        method: "POST",
        body: JSON.stringify({
          reason,
          expected_revision: a.revision ?? 0,
          ...(feedback === "modify"
            ? { field: "malicious", value: override }
            : {}),
        }),
      });
      setFeedback("");
      setReason("");
      setMessage("Analyst decision saved with an audit record.");
      await reload();
    } catch (e) {
      setFeedbackError(e instanceof Error ? e.message : "Feedback failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Link className="back-link" href={returnTo}>
        <ArrowLeft size={13} />
        Threat operations
      </Link>
      <div className="page-heading">
        <div>
          <div className="investigation-title">
            <h1>{a.observable.normalizedValue}</h1>
            <Severity value={a.severity} />
          </div>
          <div className="investigation-meta">
            <span
              className={
                (a.effective_classification ?? a.malicious.classification) ===
                "malicious"
                  ? "text-red"
                  : "text-amber"
              }
            >
              {(
                a.effective_classification ?? a.malicious.classification
              ).toUpperCase()}{" "}
              {a.effective_classification
                ? "· analyst decision"
                : percent(a.malicious.probability)}
            </span>
            <span>·</span>
            <span>
              {(a.effective_role ?? a.role.value) === "c2"
                ? "Command & control"
                : (a.effective_role ?? a.role.value)}
            </span>
            <span>·</span>
            <span>{percent(a.confidence)} confidence</span>
          </div>
        </div>
        <div className="actions">
          <Button
            variant="outline"
            onClick={() =>
              void copyText(
                defang(a.observable.normalizedValue),
                "Defanged observable copied for safe sharing.",
              )
            }
          >
            <Copy size={14} />
            Copy defanged
          </Button>
          <Button variant="outline" asChild>
            <a
              href={"/api/v1/assessments/" + id + "/stix"}
              download
              onClick={async (event) => {
                event.preventDefault();
                try {
                  const bundle = await api<unknown>(
                    "v1/assessments/" + id + "/stix",
                  );
                  const url = URL.createObjectURL(
                    new Blob([JSON.stringify(bundle, null, 2)], {
                      type: "application/json",
                    }),
                  );
                  const link = document.createElement("a");
                  link.href = url;
                  link.download = id + ".stix.json";
                  link.click();
                  setTimeout(() => URL.revokeObjectURL(url), 1000);
                  toast.success(
                    "STIX export downloaded. Source provenance is included.",
                  );
                } catch {
                  /* The API helper displays an actionable error toast. */
                }
              }}
            >
              <Download size={14} />
              Export STIX
            </a>
          </Button>
          <Button
            variant="outline"
            disabled={!canWrite || reassessing}
            onClick={() => {
              setReassessing(true);
              void api<{ job_id: string }>(
                "v1/assessments/" + id + "/reclassify",
                { method: "POST" },
              )
                .then((r) => setReassessmentJob(r.job_id))
                .catch((e) =>
                  setMessage(
                    e instanceof Error
                      ? e.message
                      : "We couldn’t queue reclassification. Please try again.",
                  ),
                )
                .finally(() => setReassessing(false));
            }}
          >
            <RefreshCw size={14} />
            Reassess
          </Button>
        </div>
      </div>
      {a.demo && (
        <div className="demo-banner">
          <HelpCircle size={14} />
          Synthetic demonstration. These probabilities illustrate the workflow
          and are not a live Clef result.
        </div>
      )}
      {reassessmentJob && (
        <ReassessmentProgress key={reassessmentJob} jobId={reassessmentJob} />
      )}
      {message && (
        <div className="notice" role="status">
          {message}
        </div>
      )}
      {a.analyst_decision && (
        <div className="notice">
          <strong>
            Analyst override: {a.analyst_decision.field} →{" "}
            {String(a.analyst_decision.value)}
          </strong>
          <p>{a.analyst_decision.reason}</p>
          <small>Original model probabilities remain visible below.</small>
        </div>
      )}
      <nav className="investigation-jumps" aria-label="Investigation sections">
        <a href="#decision">Decision</a>
        <a href="#evidence">
          Evidence <span>{a.evidence.length}</span>
        </a>
        <a href="#relationships">Relationships</a>
        <a href="#model-provenance">Model provenance</a>
        <a href="#analyst-review">Analyst review</a>
      </nav>
      <div className="investigation-grid">
        <div>
          <section className="panel" id="decision">
            <h2>
              <ShieldCheck size={17} />
              Original model decision
            </h2>
            <div className="decision-layout">
              <div>
                {[
                  ["Malicious", a.malicious.probability],
                  [
                    a.role.value === "c2" ? "Command & control" : a.role.value,
                    a.role.probability,
                  ],
                  ["Human review", a.human_review_probability],
                ].map(([label, value]) => (
                  <div key={String(label)}>
                    <div className="probability-row">
                      <span>{label}</span>
                      <strong>{percent(Number(value))}</strong>
                    </div>
                    <div
                      className="probability-bar"
                      style={{ marginTop: -10, marginBottom: 20 }}
                    >
                      <span style={{ width: percent(Number(value)) }} />
                    </div>
                  </div>
                ))}
              </div>
              <div>
                <span className="tag">
                  {a.status === "pending"
                    ? "MODEL ASSESSMENT"
                    : a.status.toUpperCase()}
                </span>
                <p className="tooltip-note">
                  {a.human_review
                    ? "The evidence gate requires analyst review before acting on this assessment."
                    : "The assessment passed the configured confidence and review gates."}
                </p>
                <div className="detail-row">
                  <span>Evidence strength</span>
                  <strong>{percent(a.confidence)}</strong>
                </div>
                <div className="detail-row">
                  <span>Classifier</span>
                  <strong className="mono">
                    {a.demo
                      ? "Demonstration"
                      : a.models.classifier.split("/").at(-1)}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Assessed</span>
                  <strong>{relativeTime(a.created_at)}</strong>
                </div>
              </div>
            </div>
            <details>
              <summary
                className="text-link"
                style={{ fontSize: 10, cursor: "pointer" }}
              >
                Inspect confidence calculation
              </summary>
              <div style={{ marginTop: 12 }}>
                {a.confidence_factors.map((f, i) => (
                  <div className="detail-row" key={i}>
                    <span>{f.code.replaceAll("_", " ").toLowerCase()}</span>
                    <strong className="mono">
                      {f.value.toFixed(2)} × {f.weight.toFixed(2)}
                    </strong>
                  </div>
                ))}
              </div>
              <p className="tooltip-note">
                Policy weights are inspectable heuristics, not statistically
                calibrated probabilities.
              </p>
            </details>
          </section>
          <EvidenceExplorer
            evidence={a.evidence}
            selectedIds={evidenceIds}
            onClear={() => setEvidenceIds([])}
          />
          <IntelligenceGraph entityId={a.observable.id} />
          <section className="panel" id="model-provenance">
            <h2>
              <Activity size={17} />
              Model & decision provenance
            </h2>
            <div className="detail-row">
              <span>Schema / question set</span>
              <strong className="mono">
                {a.models.schema_version} / {a.models.question_set_version}
              </strong>
            </div>
            <div className="detail-row">
              <span>Evidence version</span>
              <strong className="mono">
                {a.evidence_version.slice(0, 20)}…
              </strong>
            </div>
            <details style={{ marginTop: 15 }}>
              <summary className="text-link" style={{ fontSize: 11 }}>
                Full probability distributions & candidate sets
              </summary>
              <pre className="raw-json">{JSON.stringify(a.runs, null, 2)}</pre>
            </details>
          </section>
        </div>
        <aside className="investigation-side">
          <section className="panel">
            <h2>
              <Crosshair size={17} />
              Customer relevance
            </h2>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 13,
              }}
            >
              <Severity value={a.customer.priority} />
              <strong
                style={{ fontSize: 28, fontWeight: 500, color: "#285f44" }}
              >
                {percent(a.customer.relevance)}
              </strong>
            </div>
            <div className="detail-row">
              <span>Observed internally</span>
              <strong className={a.customer.observed ? "text-green" : ""}>
                {a.customer.observed ? "YES" : "NO"}
              </strong>
            </div>
            <div className="detail-row">
              <span>Exposed assets</span>
              <strong>{a.customer.exposedAssets}</strong>
            </div>
            <div className="detail-row">
              <span>CISA KEV evidence</span>
              <strong>
                {a.reason_codes.includes("CISA_KEV") ? "YES" : "NO"}
              </strong>
            </div>
            {a.customer.reasons.map((r) => (
              <div className="reason" key={r}>
                <CheckCircle2 size={12} />
                {r.replaceAll("_", " ").toLowerCase()}
              </div>
            ))}
          </section>
          <section className="panel">
            <h2>ATT&CK behaviour</h2>
            {a.attack.length ? (
              a.attack.map((m) => (
                <div className="attack-item" key={m.techniqueId}>
                  <div>
                    <Link
                      className="mono text-link"
                      href={"/intelligence/" + encodeURIComponent(m.entityId)}
                    >
                      {m.techniqueId}
                    </Link>
                    <strong>{percent(m.probability)}</strong>
                  </div>
                  <div className="probability-bar">
                    <span style={{ width: percent(m.probability) }} />
                  </div>
                  <small>
                    {m.status} · {m.mappingType.replaceAll("_", " ")} ·{" "}
                    <button
                      className="text-link"
                      onClick={() => {
                        setEvidenceIds(m.evidenceIds);
                        document.getElementById("evidence")?.focus();
                        document.getElementById("evidence")?.scrollIntoView({
                          behavior: "smooth",
                          block: "start",
                        });
                      }}
                    >
                      {m.evidenceIds.length} evidence records
                    </button>
                  </small>
                </div>
              ))
            ) : (
              <p className="tooltip-note">
                No supported behavioural mapping. Maliciousness alone does not
                imply an ATT&CK technique.
              </p>
            )}
          </section>
          <section className="panel">
            <h2>Potential actor associations</h2>
            {a.actors.map((actor) => (
              <div className="detail-row" key={actor.id}>
                <span>{actor.name}</span>
                <strong>{percent(actor.association_probability)}</strong>
              </div>
            ))}
            <div className="detail-row">
              <span>Attribution status</span>
              <strong>Unknown</strong>
            </div>
            <p className="tooltip-note">
              Similarity is not attribution. No actor association is presented
              as a confirmed fact.
            </p>
          </section>
          <section className="panel">
            <h2>Recommended actions</h2>
            <div className="action-list">
              {a.recommended_actions.map((action) => (
                <span className="tag" key={action.action}>
                  {action.action.toUpperCase()}
                </span>
              ))}
            </div>
            <p className="tooltip-note">
              Recommendations only. ThreatSieve does not block or isolate
              infrastructure.
            </p>
          </section>
          <section
            id="analyst-review"
            className={"panel " + (a.human_review ? "review-panel" : "")}
          >
            <h2>Analyst decision</h2>
            <p className="panel-subtitle">
              Review the supporting evidence and record your judgment.
            </p>
            <div className="actions">
              <Button
                size="sm"
                disabled={!canWrite}
                onClick={() => beginFeedback("confirm")}
              >
                <Check size={14} />
                Confirm
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!canWrite}
                onClick={() => beginFeedback("reject")}
              >
                <X size={14} />
                Reject
              </Button>
            </div>
            <Button
              size="sm"
              variant="outline"
              style={{ marginTop: 8 }}
              disabled={!canWrite}
              onClick={() => beginFeedback("modify")}
            >
              Modify classification
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={!canWrite}
              onClick={() => beginFeedback("investigate")}
              style={{ marginTop: 8 }}
            >
              Needs investigation
            </Button>
          </section>
        </aside>
      </div>
      {feedback && (
        <Modal
          titleId="feedback-title"
          busy={busy}
          onClose={() => setFeedback("")}
        >
          <h2 id="feedback-title">Record analyst decision</h2>
          <p>
            {feedback === "confirm"
              ? "Confirm"
              : feedback === "reject"
                ? "Reject"
                : feedback === "modify"
                  ? "Modify"
                  : "Investigate"}{" "}
            this assessment. Your reasoning is retained in the audit trail.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            {feedback === "modify" && (
              <>
                <label htmlFor="override">Classification</label>
                <select
                  id="override"
                  value={override}
                  onChange={(e) => setOverride(e.target.value)}
                >
                  {["malicious", "suspicious", "benign", "unknown"].map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </>
            )}
            <label htmlFor="feedback">Reason</label>
            <textarea
              id="feedback"
              autoFocus
              required
              minLength={3}
              maxLength={2000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={4}
            />
            {feedbackError && (
              <div role="alert" className="notice text-red">
                <p>{feedbackError}</p>
                <Button
                  type="button"
                  variant="outline"
                  disabled={busy}
                  onClick={() => {
                    setFeedback("");
                    void reload();
                  }}
                >
                  Reload assessment
                </Button>
              </div>
            )}
            <div className="modal-actions">
              <Button
                type="button"
                variant="outline"
                onClick={() => setFeedback("")}
              >
                Cancel
              </Button>
              <Button disabled={busy}>
                {busy ? "Saving…" : "Save decision"}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
