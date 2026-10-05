"use client";
import Link from "next/link";
import { ArrowLeft, ArrowUpRight } from "lucide-react";
import { useApi } from "@/lib/api";
import { DataState, PageHeader } from "./shell";
import type {
  IntelEntity,
  IntelRelationship,
  SourceProvenance,
} from "../../../packages/schemas/src/index";
export function IntelligenceDetail({ id }: { id: string }) {
  const { data, error, loading } = useApi<{
    entity: IntelEntity;
    sources: SourceProvenance[];
    relationships: (IntelRelationship & { entity: IntelEntity | null })[];
  }>("v1/entities/" + encodeURIComponent(id));
  if (!data) return <DataState loading={loading} error={error} />;
  const { entity, sources, relationships } = data;
  return (
    <>
      <Link className="back-link" href="/">
        <ArrowLeft size={13} />
        Threat operations
      </Link>
      <PageHeader
        eyebrow={entity.type.toUpperCase()}
        title={entity.name}
        description={entity.externalId ?? "Source-backed intelligence entity"}
      />
      <div className="investigation-grid">
        <div>
          <section className="panel">
            <div className="panel-header">
              <h2>Intelligence record</h2>
            </div>
            <div style={{ padding: 24 }}>
              <p style={{ whiteSpace: "pre-wrap", lineHeight: 1.8 }}>
                {entity.description ||
                  "The source provides no description for this entity."}
              </p>
              {entity.aliases.length > 0 && (
                <>
                  <h3>Known aliases</h3>
                  <p>{entity.aliases.join(" · ")}</p>
                </>
              )}
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h2>Evidence-backed relationships</h2>
              <span>{relationships.length} shown · bounded to 30</span>
            </div>
            {relationships.length === 0 ? (
              <p style={{ padding: 24 }}>
                No relationships imported for this entity.
              </p>
            ) : (
              relationships.map((edge) => (
                <div
                  className="detail-row"
                  key={edge.id}
                  style={{ padding: "16px 24px" }}
                >
                  <div>
                    <strong>{edge.relationshipType}</strong>
                    <p>
                      {edge.assertionType.replaceAll("_", " ")} ·{" "}
                      {Math.round(edge.confidence * 100)}% confidence
                    </p>
                    <small>Sources: {edge.sourceIds.join(", ")}</small>
                  </div>
                  {edge.entity && (
                    <Link
                      href={
                        "/intelligence/" + encodeURIComponent(edge.entity.id)
                      }
                    >
                      {edge.entity.name} <ArrowUpRight size={13} />
                    </Link>
                  )}
                </div>
              ))
            )}
          </section>
        </div>
        <aside>
          <section className="panel">
            <div className="panel-header">
              <h2>Source provenance</h2>
            </div>
            {sources.map((source, index) => (
              <div style={{ padding: 24 }} key={source.sourceId + index}>
                <strong>{source.sourceName}</strong>
                <p>
                  Retrieved {new Date(source.retrievedAt).toLocaleDateString()}
                </p>
                <small>
                  {source.license ?? "Licence not supplied"} ·{" "}
                  {source.redistributable
                    ? "Redistribution permitted"
                    : "Redistribution restricted or unverified"}
                </small>
              </div>
            ))}
          </section>
        </aside>
      </div>
    </>
  );
}
