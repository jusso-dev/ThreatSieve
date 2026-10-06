import { Suspense } from "react";
import { IntelligenceLibrary } from "@/components/intelligence-library";
import { DataState } from "@/components/shell";
export const metadata = { title: "Intelligence library" };
export default function Page() {
  return (
    <Suspense fallback={<DataState loading />}>
      <IntelligenceLibrary />
    </Suspense>
  );
}
