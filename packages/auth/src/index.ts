import { z } from "zod";
import { Scopes, type Principal, type Scope } from "../../schemas/src/index";
import { digest } from "../../intel/src/normalise";
import { AppError } from "../../observability/src/index";
export async function authenticate(
  db: D1Database,
  request: Request,
): Promise<Principal> {
  const bearer = request.headers.get("authorization");
  const cookie = request.headers
    .get("cookie")
    ?.split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith("ts_session="))
    ?.slice(11);
  const token = bearer?.startsWith("Bearer ") ? bearer.slice(7) : undefined;
  if (!token && !cookie)
    throw new AppError("UNAUTHORIZED", 401, "Authentication required");
  let row: {
    id: string;
    tenant_id: string;
    user_id: string;
    scopes: string;
  } | null;
  let kind: Principal["kind"] = "key";
  if (token) {
    row = await db
      .prepare(
        "SELECT id,tenant_id,user_id,scopes FROM api_keys WHERE hash=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
      )
      .bind(await digest(token), new Date().toISOString())
      .first();
  } else {
    kind = "session";
    row = await db
      .prepare(
        "SELECT k.id,s.tenant_id,s.user_id,k.scopes FROM sessions s JOIN api_keys k ON k.id=s.key_id WHERE s.hash=? AND s.expires_at>? AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>?)",
      )
      .bind(
        await digest(cookie!),
        new Date().toISOString(),
        new Date().toISOString(),
      )
      .first();
  }
  if (!row)
    throw new AppError(
      "UNAUTHORIZED",
      401,
      "Credentials are invalid or expired",
    );
  await db
    .prepare("UPDATE api_keys SET last_used_at=? WHERE id=? AND tenant_id=?")
    .bind(new Date().toISOString(), row.id, row.tenant_id)
    .run();
  return {
    tenantId: row.tenant_id,
    userId: row.user_id,
    keyId: row.id,
    scopes: z.array(Scopes).parse(JSON.parse(row.scopes)),
    kind,
  };
}
export function authorize(principal: Principal, scope: Scope) {
  if (!principal.scopes.includes(scope) && !principal.scopes.includes("admin"))
    throw new AppError("FORBIDDEN", 403, "Missing required scope: " + scope);
}
export async function rateLimit(
  db: D1Database,
  p: Principal,
  limit = 120,
  now = Date.now(),
) {
  const minute = Math.floor(now / 60000);
  for (const [id, max] of [
    [p.tenantId, limit * 5],
    [p.tenantId + ":" + p.keyId, limit],
  ] as const) {
    const key = id + ":" + minute;
    const row = await db
      .prepare(
        "INSERT INTO rate_limits(bucket,count,expires_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count",
      )
      .bind(key, minute + 2)
      .first<{ count: number }>();
    if (row && row.count > max)
      throw new AppError(
        "RATE_LIMITED",
        429,
        "Rate limit exceeded; retry in 60 seconds",
      );
  }
}
export async function createApiKey(
  db: D1Database,
  p: Principal,
  name: string,
  scopes: Scope[],
  expiresAt?: string,
) {
  if (scopes.some((s) => !p.scopes.includes("admin") && !p.scopes.includes(s)))
    throw new AppError("FORBIDDEN", 403, "Cannot grant scopes you do not hold");
  const token =
    "ts_" +
    Array.from(crypto.getRandomValues(new Uint8Array(32)), (v) =>
      v.toString(16).padStart(2, "0"),
    ).join("");
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(
      id,
      p.tenantId,
      p.userId,
      name,
      await digest(token),
      JSON.stringify(scopes),
      new Date().toISOString(),
      expiresAt ?? null,
    )
    .run();
  return { id, key: token, name, scopes, expires_at: expiresAt ?? null };
}
