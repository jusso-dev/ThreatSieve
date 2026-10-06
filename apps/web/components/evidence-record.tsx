"use client";
import { useApi } from "@/lib/api";
import type { Evidence } from "../../../packages/schemas/src/index";
import { EvidenceExplorer } from "./evidence-explorer";
import { PageHeader, DataState } from "./shell";
import { PinToWorkspace } from "./workspace-references";
export function EvidenceRecord({ id }: { id: string }) {
  const { data, error, loading } = useApi<Evidence>(
    "v1/evidence/" + encodeURIComponent(id),
  );
  return (
    <>
      <PageHeader
        eyebrow="ORIGINAL EVIDENCE"
        title={data?.provenance.sourceName ?? "Evidence"}
        description="A source assertion, preserved independently from analyst judgement."
        action={
          <PinToWorkspace
            reference={{ type: "evidence", id, relation: "supports" }}
          />
        }
      />
      <DataState loading={loading} error={error} />
      {data && (
        <EvidenceExplorer
          evidence={[data]}
          selectedIds={[]}
          onClear={() => {}}
        />
      )}
    </>
  );
}
