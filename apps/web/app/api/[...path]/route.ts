import { NextRequest } from "next/server";
export const dynamic = "force-dynamic";
async function handler(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path } = await params;
  if (path.some((s) => s === ".." || s.includes("/")))
    return Response.json(
      { error: { message: "Invalid path" } },
      { status: 400 },
    );
  const base = process.env.API_ORIGIN ?? "http://127.0.0.1:8787";
  const url = new URL("/" + path.map(encodeURIComponent).join("/"), base);
  url.search = request.nextUrl.search;
  const headers = new Headers();
  for (const key of [
    "content-type",
    "cookie",
    "authorization",
    "idempotency-key",
  ]) {
    const value = request.headers.get(key);
    if (value) headers.set(key, value);
  }
  const devKey =
    process.env.NODE_ENV === "development"
      ? process.env.DEVELOPMENT_API_KEY
      : undefined;
  if (devKey && !headers.has("authorization"))
    headers.set("authorization", "Bearer " + devKey);
  if (request.headers.has("origin"))
    headers.set("origin", request.headers.get("origin")!);
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 16 * 1024 * 1024)
    return Response.json(
      { error: { message: "Upload exceeds 16 MiB" } },
      { status: 413 },
    );
  try {
    const response = await fetch(url, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      duplex: "half",
      redirect: "manual",
      cache: "no-store",
    } as RequestInit);
    const resultHeaders = new Headers();
    for (const key of [
      "content-type",
      "set-cookie",
      "x-request-id",
      "content-disposition",
    ]) {
      const value = response.headers.get(key);
      if (value) resultHeaders.set(key, value);
    }
    resultHeaders.set("Cache-Control", "no-store");
    return new Response(response.body, {
      status: response.status,
      headers: resultHeaders,
    });
  } catch {
    return Response.json(
      {
        error: {
          code: "API_UNAVAILABLE",
          message:
            "ThreatSieve API is unavailable. Start the API Worker and try again.",
        },
      },
      { status: 503 },
    );
  }
}
export { handler as GET, handler as POST, handler as PUT, handler as DELETE };
