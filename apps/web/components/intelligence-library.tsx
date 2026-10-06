"use client";
import Link from "next/link";
import { ArrowUpRight, BookOpen, Copy, RefreshCw, Search } from "lucide-react";
import { useState } from "react";
import { useApi } from "@/lib/api";
import { useViewState, copyText } from "@/lib/view-state";
import { PageHeader, DataState } from "./shell";
import { Button } from "./ui/button";
import { QueryField, FilterSelect, EmptyResults } from "./filter-controls";
import type { IntelEntity } from "../../../packages/schemas/src/index";

const kinds = [
  ["", "All intelligence"],
  ["threat-actor", "Threat actors"],
  ["malware", "Malware"],
  ["campaign", "Campaigns"],
  ["attack-technique", "ATT&CK techniques"],
  ["vulnerability", "Vulnerabilities"],
  ["observable", "Observables"],
  ["tool", "Tools"],
  ["attack-tactic", "ATT&CK tactics"],
  ["infrastructure", "Infrastructure"],
  ["cluster", "Clusters"],
] as const;
export function IntelligenceLibrary() {
  const { params, update } = useViewState();
  const [history, setHistory] = useState<string[]>([]);
  const type = params.get("type") ?? "",
    q = params.get("q") ?? "",
    source = params.get("source") ?? "";
  const query = new URLSearchParams({
    limit: "50",
    ...(type ? { type } : {}),
    ...(q ? { q } : {}),
    ...(source ? { source } : {}),
    ...(params.get("cursor") ? { cursor: params.get("cursor")! } : {}),
  });
  const { data, error, loading, reload } = useApi<{
    data: IntelEntity[];
    next_cursor: string | null;
  }>("v1/entities?" + query);
  const sources = useApi<{ data: { id: string; name: string }[] }>("v1/feeds");
  const change = (key: string, value: string, replace = false) => {
    setHistory([]);
    update({ [key]: value }, replace);
  };
  const reset = () => {
    setHistory([]);
    update({ q: "", type: "", source: "" });
  };
  return (
    <>
      <PageHeader
        eyebrow="INTELLIGENCE LIBRARY"
        title="Threat library"
        description="Find known entities, resolve aliases and follow the evidence behind their relationships."
        action={
          <div className="actions">
            <Button
              variant="outline"
              onClick={() =>
                void copyText(
                  window.location.href,
                  "View link copied. Workspace permissions still apply.",
                )
              }
            >
              <Copy size={15} />
              Copy view link
            </Button>
            <Button
              variant="outline"
              aria-label="Refresh library"
              onClick={() => void reload()}
            >
              <RefreshCw size={15} />
            </Button>
          </div>
        }
      />
      <div className="library-layout">
        <nav className="library-nav panel" aria-label="Intelligence categories">
          <div className="library-nav-title">
            <BookOpen size={16} />
            Browse knowledge
          </div>
          {kinds.map(([value, label]) => (
            <button
              key={value}
              aria-pressed={type === value}
              className={type === value ? "selected" : ""}
              onClick={() => change("type", value)}
            >
              {label}
              {type === value && <ArrowUpRight size={14} />}
            </button>
          ))}
          <p>
            Source intelligence provides context. It does not establish
            attribution for your observations.
          </p>
        </nav>
        <section
          className="intelligence-panel library-results"
          aria-label="Intelligence results"
        >
          <div className="library-toolbar">
            <QueryField
              label="Search library"
              placeholder="Name, alias, MITRE ID or observable prefix…"
              value={q}
              onChange={(v) => change("q", v, true)}
            />
            <FilterSelect
              label="Source"
              value={source}
              options={[
                ["", "All sources"],
                ...(sources.data?.data.map((s) => [s.id, s.name] as const) ??
                  []),
              ]}
              onChange={(v) => change("source", v)}
            />
          </div>
          <div className="result-summary">
            <span>
              {kinds.find((k) => k[0] === type)?.[1] ?? "Intelligence"} ·{" "}
              {loading
                ? "Loading…"
                : `${data?.data.length ?? 0} records on this page`}
            </span>
            {(q || type || source) && (
              <button className="text-link" onClick={reset}>
                Clear filters
              </button>
            )}
          </div>
          <DataState loading={loading} error={error} />
          {!loading && !error && data && !data.data.length && (
            <EmptyResults onReset={reset} />
          )}
          {!loading && !error && data && data.data.length > 0 && (
            <div className="table-scroll">
              <table className="intel-table library-table">
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Reference</th>
                  </tr>
                </thead>
                <tbody>
                  {data.data.map((e) => (
                    <tr key={e.id}>
                      <td>
                        <Link
                          className="entity-link"
                          href={"/intelligence/" + encodeURIComponent(e.id)}
                        >
                          <strong>{e.name}</strong>
                          <ArrowUpRight size={14} />
                        </Link>
                        {e.aliases.length > 0 && (
                          <small className="entity-aliases">
                            Also known as {e.aliases.slice(0, 3).join(" · ")}
                            {e.aliases.length > 3
                              ? ` +${e.aliases.length - 3} aliases`
                              : ""}
                          </small>
                        )}
                        <p className="entity-description">
                          {e.description ||
                            "Source-backed observable. Open the record to inspect provenance."}
                        </p>
                      </td>
                      <td>
                        <span className="entity-type">
                          {e.type.replaceAll("-", " ")}
                        </span>
                      </td>
                      <td>{e.provenance.sourceName}</td>
                      <td className="mono">{e.externalId ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="table-footer">
            <span>
              <Search size={13} />
              Search matches names, aliases and external IDs.
            </span>
            <div className="actions">
              <Button
                size="sm"
                variant="outline"
                disabled={!params.get("cursor") || loading}
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
                  setHistory([...history, params.get("cursor") ?? ""]);
                  update({ cursor: data!.next_cursor! });
                }}
              >
                Next page
              </Button>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
