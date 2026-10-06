import { SourceDossier } from "@/components/source-dossier";
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <SourceDossier id={id} />;
}
