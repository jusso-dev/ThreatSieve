"use client";
import Link from "next/link";
import { EntityTags } from "./entity-tags";
import { useState } from "react";
import { ArrowLeft, Copy } from "lucide-react";
import { useApi } from "@/lib/api";
import { absoluteTime } from "@/lib/utils";
import { copyText, defang } from "@/lib/view-state";
import { workspaces } from "@/lib/workspace";
import type { Dossier } from "../../../packages/enterprise/src/types";
import { PageHeader, DataState } from "./shell";
import { Button } from "./ui/button";
import { EvidenceExplorer } from "./evidence-explorer";
import { IntelligenceGraph } from "./intelligence-graph";
import { PinToWorkspace } from "./workspace-references";

export function IntelligenceCard({ id }: { id: string }) {
  const { data, error, loading, reload } = useApi<Dossier>(
    "v1/entities/" + encodeURIComponent(id) + "/dossier",
  );
  const [tab, setTab] = useState("overview"),
    [days, setDays] = useState("30");
  if (!data || loading || error)
    return <DataState loading={loading} error={error} />;
  const e = data.entity,
    s = data.scores,
    a = data.assessments[0],
    dates = data.evidence
      .map((x) => x.observedAt ?? x.createdAt)
      .filter((x) => Number.isFinite(Date.parse(x)))
      .sort();
  const classification =
    a?.effective_classification ??
    a?.malicious.classification ??
    "Not assessed";
  const timeline = data.timeline.filter(
    (x) =>
      (tab !== "history" || !["evidence", "relationship"].includes(x.type)) &&
      (days === "all" ||
        Date.parse(x.timestamp) >= Date.now() - Number(days) * 86400000),
  );
  return (
    <>
      <Link className="back-link" href="/intelligence">
        <ArrowLeft size={13} />
        Intelligence library
      </Link>
      <PageHeader
        eyebrow={e.type.replaceAll("-", " ").toUpperCase()}
        title={e.name}
        description={e.externalId ?? "Canonical intelligence record"}
        action={
          <div className="actions">
            <Button
              variant="outline"
              onClick={() =>
                void copyText(
                  e.type === "observable"
                    ? defang(e.name)
                    : (e.externalId ?? e.name),
                )
              }
            >
              <Copy size={14} />
              {e.type === "observable" ? "Copy defanged" : "Copy reference"}
            </Button>
            <PinToWorkspace
              initialOpen={
                typeof window !== "undefined" &&
                new URLSearchParams(window.location.search).get("pin") === "1"
              }
              reference={{ type: "entity", id, relation: "references" }}
            />
          </div>
        }
      />
      <EntityTags id={id} tags={data.workspaceTags} reload={reload} />
      <div className="dossier-verdict">
        <strong>{classification}</strong>
        <span>
          Threat <b>{s.threat.value ?? "Unknown"}</b>
        </span>
        <span>
          Confidence{" "}
          <b>
            {s.confidence.value === null ? "Unknown" : s.confidence.value + "%"}
          </b>
        </span>
        <span>
          Relevance <b>{s.relevance.value ?? "Unknown"}</b>
        </span>
        <span className={"priority-text " + s.priority.label}>
          {s.priority.label} priority
        </span>
      </div>
      <dl className="dossier-facts">
        <div>
          <dt>First supporting observation</dt>
          <dd>{dates[0] ? absoluteTime(dates[0]) : "Not supplied"}</dd>
        </div>
        <div>
          <dt>Last supporting observation</dt>
          <dd>{dates.at(-1) ? absoluteTime(dates.at(-1)!) : "Not supplied"}</dd>
        </div>
        <div>
          <dt>Source assertions</dt>
          <dd>{data.provenance.length}</dd>
        </div>
      </dl>
      <nav className="dossier-tabs" aria-label="Intelligence dossier sections">
        {[
          "overview",
          "relationships",
          "evidence",
          "timeline",
          "attack",
          "history",
        ].map((t) => (
          <button key={t} aria-pressed={tab === t} onClick={() => setTab(t)}>
            {t === "attack" ? "ATT&CK" : t[0]!.toUpperCase() + t.slice(1)}
          </button>
        ))}
      </nav>
      {tab === "overview" && (
        <div className="dossier-overview">
          <div>
            <section className="work-section">
              <h2>Intelligence summary</h2>
              <p className="preserve-lines">
                {e.description || "No source description has been supplied."}
              </p>
              {e.aliases.length > 0 && <p>Aliases: {e.aliases.join(", ")}</p>}
              {a && (
                <Link
                  className="text-link"
                  href={"/investigations/" + a.assessment_id}
                >
                  Open latest assessment →
                </Link>
              )}
            </section>
            <section className="work-section">
              <h2>Why these scores?</h2>
              <p className="muted">
                Policy {s.policy}. These are inspectable heuristics, not
                calibrated probabilities.
              </p>
              {(["threat", "confidence", "relevance"] as const).map((key) => (
                <details
                  className="score-explanation"
                  key={key}
                  open={key === "threat"}
                >
                  <summary>
                    {key[0]!.toUpperCase() + key.slice(1)} ·{" "}
                    {s[key].value ?? "Unknown"}
                  </summary>
                  {s[key].factors.length ? (
                    <table className="factor-table">
                      <tbody>
                        {s[key].factors.map((f) => (
                          <tr key={f.code}>
                            <td>
                              {f.points > 0 ? "+" : ""}
                              {f.points}
                            </td>
                            <td>
                              {f.label}
                              <small>
                                {f.evidenceIds.length} supporting records
                              </small>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p>
                      No qualifying evidence. Absence of evidence does not
                      establish benignness.
                    </p>
                  )}
                </details>
              ))}
              <p className="muted">Priority: {s.priority.formula}.</p>
            </section>
            <section className="work-section">
              <h2>Source provenance</h2>
              {data.provenance.map((p, i) => (
                <div className="source-assertion" key={i}>
                  <strong>{String(p.sourceName)}</strong>
                  <span>
                    {typeof p.sourceRecordId === "string"
                      ? p.sourceRecordId
                      : "No source record identifier"}
                  </span>
                  <small>
                    {typeof p.license === "string"
                      ? p.license
                      : "Licence not supplied"}{" "}
                    ·{" "}
                    {p.redistributable
                      ? "Redistributable"
                      : "Redistribution restricted"}
                  </small>
                </div>
              ))}
            </section>
          </div>
          <aside>
            <section className="work-section">
              <h2>Intelligence gaps</h2>
              {s.gaps.length ? (
                s.gaps.map((g) => (
                  <p className="gap-row" key={g.code}>
                    {g.message}
                  </p>
                ))
              ) : (
                <p>
                  No gaps detected by the current rules. This is not proof of
                  completeness.
                </p>
              )}
            </section>
            <section className="work-section">
              <h2>Analyst next steps</h2>
              {a?.recommended_actions.map((x) => (
                <p className="action-recommendation" key={x.action}>
                  <strong>{x.action}</strong>
                  <small>{x.reason_codes.join(" · ")}</small>
                </p>
              ))}
              {!a && (
                <p>
                  Assess this observable before making an operational decision.
                </p>
              )}
            </section>
            <section className="work-section">
              <h2>Organisational memory</h2>
              {data.related
                .filter(
                  (o) => o.kind !== "investigation" && o.kind !== "playbook",
                )
                .map((o) => (
                  <Link
                    className="dossier-work-link"
                    key={o.id}
                    href={"/" + workspaces[o.kind].path + "/" + o.id}
                  >
                    {o.title}
                    <small>
                      {o.kind} · {o.status}
                    </small>
                  </Link>
                ))}
              {!data.related.length && (
                <p>
                  No requirements, watchlists or collections reference this
                  entity yet.
                </p>
              )}
            </section>
          </aside>
        </div>
      )}
      {tab === "relationships" && <IntelligenceGraph entityId={id} />}
      {tab === "evidence" && (
        <EvidenceExplorer
          evidence={data.evidence}
          selectedIds={[]}
          onClear={() => {}}
        />
      )}
      {(tab === "timeline" || tab === "history") && (
        <section className="work-section">
          <div className="section-title">
            <h2>
              {tab === "history"
                ? "Change & decision history"
                : "Intelligence timeline"}
            </h2>
            <select
              aria-label="Timeline period"
              value={days}
              onChange={(e) => setDays(e.target.value)}
            >
              {[
                ["1", "24 hours"],
                ["7", "7 days"],
                ["30", "30 days"],
                ["90", "90 days"],
                ["365", "1 year"],
                ["all", "All recorded history"],
              ].map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          {timeline.map((x, i) => (
            <article className="timeline-event" key={x.id + i}>
              <time>{absoluteTime(x.timestamp)}</time>
              <div>
                <strong>{x.title}</strong>
                <p>{x.description}</p>
                {x.reference.type === "evidence" ? (
                  <Link
                    className="text-link"
                    href={"/evidence/" + x.reference.id}
                  >
                    Open evidence
                  </Link>
                ) : x.reference.type === "assessment" ? (
                  <Link
                    className="text-link"
                    href={"/investigations/" + x.reference.id}
                  >
                    Open decision
                  </Link>
                ) : x.reference.type === "relationship" ? (
                  <button
                    className="text-link"
                    onClick={() => setTab("relationships")}
                  >
                    Inspect relationship provenance
                  </button>
                ) : (
                  <small>Audited workspace event</small>
                )}
              </div>
            </article>
          ))}
          {!timeline.length && <p>No recorded events in this period.</p>}
        </section>
      )}
      {tab === "attack" && (
        <section className="work-section">
          <h2>Behaviour-supported ATT&CK mappings</h2>
          {a?.attack.map((t) => (
            <div className="source-assertion" key={t.techniqueId}>
              <Link href={"/intelligence/" + t.entityId}>{t.techniqueId}</Link>
              <span>
                {Math.round(t.probability * 100)}% ·{" "}
                {t.mappingType.replaceAll("_", " ")}
              </span>
              <div>
                {t.evidenceIds.map((id) => (
                  <Link key={id} className="text-link" href={"/evidence/" + id}>
                    Supporting evidence →{" "}
                  </Link>
                ))}
              </div>
            </div>
          ))}
          {!a?.attack.length && (
            <p>
              No behaviour-supported mappings are available. A malicious
              indicator alone is insufficient.
            </p>
          )}
        </section>
      )}
      {data.truncated && (
        <p className="notice">
          This dossier is a bounded view. Open individual sources, assessments
          and related records for additional context.
        </p>
      )}
    </>
  );
}
