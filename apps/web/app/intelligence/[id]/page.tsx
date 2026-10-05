import { IntelligenceDetail } from "@/components/intelligence-detail";
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <IntelligenceDetail id={id} />;
}
