import { EvidenceRecord } from "@/components/evidence-record";
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <EvidenceRecord id={id} />;
}
