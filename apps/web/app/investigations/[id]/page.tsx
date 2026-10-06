import { Investigation } from "@/components/investigation";
export default async function Page({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { id } = await params;
  const { return_to } = await searchParams;
  const returnTo =
    typeof return_to === "string" &&
    return_to.startsWith("/?") &&
    return_to.length < 3000
      ? return_to
      : "/";
  return <Investigation id={id} returnTo={returnTo} />;
}
