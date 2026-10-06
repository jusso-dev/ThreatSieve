import { Suspense } from "react";
import { WorkspaceList } from "@/components/workspace-objects";
export default function Page() {
  return (
    <Suspense fallback={<p>Loading workspace…</p>}>
      <WorkspaceList kind="collection" />
    </Suspense>
  );
}
