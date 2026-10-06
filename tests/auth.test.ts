import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { app } from "../apps/api/src/index";
import type { AppEnv } from "../apps/api/src/env";
import { migrationStatements } from "../packages/database/src/migrations";
import { hashPassword } from "better-auth/crypto";
let mf: Miniflare;
let db: D1Database;
let env: AppEnv;
const origin = "http://localhost:3000";
const mails: EmailMessageBuilder[] = [];
let failMail = false;
const password = "A strong synthetic passphrase 42!";
let ip = 0;
async function call(
  path: string,
  body?: unknown,
  cookie?: string,
  customOrigin = origin,
) {
  return app.fetch(
    new Request("http://api.test" + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: customOrigin,
        "cf-connecting-ip": "192.0.2." + ++ip,
        ...(cookie ? { Cookie: cookie } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env,
  );
}
async function signIn(email: string) {
  const response = await call("/auth/sign-in/email", { email, password });
  expect(response.status, await response.clone().text()).toBe(200);
  return response.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
}
async function seedUser(
  id: string,
  email: string,
  tenant: string,
  role = "admin",
) {
  const now = new Date().toISOString();
  await db
    .prepare(
      "INSERT INTO users(id,email,name,email_verified,created_at,updated_at) VALUES(?,?,?,1,?,?)",
    )
    .bind(id, email, id, now, now)
    .run();
  await db
    .prepare(
      "INSERT INTO auth_accounts(id,account_id,provider_id,user_id,password,created_at,updated_at) VALUES(?,?,'credential',?,?,?,?)",
    )
    .bind(id, id, id, await hashPassword(password), now, now)
    .run();
  await db
    .prepare(
      "INSERT INTO tenant_members(id,tenant_id,user_id,role,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(id, tenant, id, role, now)
    .run();
}
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  for (const file of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + file, "utf8"),
    ))
      await db.prepare(sql).run();
  const mailer = {
    async send(message: EmailMessageBuilder) {
      if (failMail) throw new Error("Synthetic delivery failure");
      mails.push(message);
      return { messageId: crypto.randomUUID() };
    },
  } as SendEmail;
  env = {
    DB: db,
    APP_ENV: "development",
    WEB_ORIGIN: origin,
    BETTER_AUTH_SECRET: crypto.randomUUID() + crypto.randomUUID(),
    AUTH_EMAIL_FROM: "test@example.com",
    EMAIL: mailer,
  } as AppEnv;
  for (const tenant of ["a", "b"])
    await db
      .prepare("INSERT INTO tenants(id,name,slug,created_at) VALUES(?,?,?,?)")
      .bind(tenant, "Team " + tenant, tenant, new Date().toISOString())
      .run();
  await seedUser("alice", "alice@example.com", "a");
  await seedUser("bob", "bob@example.com", "b");
}, 30000);
afterAll(async () => {
  await mf?.dispose();
});
describe("Better Auth teams", () => {
  it("signs in with HttpOnly cookies, selects existing tenant and signs out server-side", async () => {
    const cookie = await signIn("alice@example.com");
    expect(cookie).toContain("better-auth.session_token");
    const me = await call("/v1/me", undefined, cookie);
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({
      tenantId: "a",
      userId: "alice",
      role: "admin",
    });
    expect((await call("/auth/sign-out", {}, cookie)).status).toBe(200);
    expect((await call("/v1/me", undefined, cookie)).status).toBe(401);
  });
  it("rejects foreign origins, weak passwords and workspace creation", async () => {
    expect(
      (
        await call(
          "/auth/sign-in/email",
          { email: "alice@example.com", password },
          undefined,
          "https://evil.example",
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await call("/auth/sign-up/email", {
          email: "weak@example.com",
          name: "Weak",
          password: "short",
        })
      ).status,
    ).toBe(400);
    const cookie = await signIn("alice@example.com");
    expect(
      (
        await call(
          "/auth/organization/create",
          { name: "Unapproved", slug: "no" },
          cookie,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await call(
          "/auth/organization/set-active",
          { organizationId: "b" },
          cookie,
        )
      ).status,
    ).toBe(403);
  });
  it("requires verified email, validates invite recipient, grants limited role and audits acceptance", async () => {
    const admin = await signIn("alice@example.com");
    const invite = await call(
      "/auth/organization/invite-member",
      { email: "charlie@example.com", role: "analyst", organizationId: "a" },
      admin,
    );
    expect(invite.status, await invite.clone().text()).toBe(200);
    const { id } = (await invite.json()) as { id: string };
    expect(mails.at(-1)?.text).toContain("/accept-invitation?id=" + id);
    const wrong = await signIn("bob@example.com");
    expect(
      (
        await call(
          "/auth/organization/accept-invitation",
          { invitationId: id },
          wrong,
        )
      ).ok,
    ).toBe(false);
    const signup = await call("/auth/sign-up/email", {
      email: "charlie@example.com",
      name: "Charlie",
      password,
    });
    expect(signup.status, await signup.clone().text()).toBe(200);
    expect(
      (
        await call("/auth/sign-in/email", {
          email: "charlie@example.com",
          password,
        })
      ).status,
    ).toBe(403);
    const url = mails.at(-1)!.text!.match(/http[^\s]+/)![0]!;
    const verified = await call(
      new URL(url).pathname.replace("/api/auth", "/auth") + new URL(url).search,
    );
    expect(verified.status, await verified.clone().text()).toBe(302);
    const member = await signIn("charlie@example.com");
    expect((await call("/v1/me", undefined, member)).status).toBe(403);
    expect(
      (
        await call(
          "/auth/organization/accept-invitation",
          { invitationId: id },
          member,
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await call(
          "/auth/organization/set-active",
          { organizationId: "a" },
          member,
        )
      ).status,
    ).toBe(200);
    expect((await call("/v1/me", undefined, member)).status).toBe(200);
    expect(
      (
        await call(
          "/auth/organization/invite-member",
          { email: "escalate@example.com", role: "admin", organizationId: "a" },
          member,
        )
      ).status,
    ).toBe(403);
    expect((await call("/v1/feeds/threatfox/sync", {}, member)).status).toBe(
      403,
    );
    expect(
      (await db
        .prepare(
          "SELECT COUNT(*) AS n FROM audit_events WHERE action='organization/accept-invitation' AND tenant_id='a'",
        )
        .first<{ n: number }>())!.n,
    ).toBe(1);
  });
  it("protects the last admin atomically and never crosses tenant membership boundaries", async () => {
    const admin = await signIn("alice@example.com");
    expect(
      (
        await call(
          "/auth/organization/remove-member",
          { memberIdOrEmail: "alice", organizationId: "a" },
          admin,
        )
      ).ok,
    ).toBe(false);
    expect(
      (
        await call(
          "/auth/organization/update-member-role",
          { memberId: "bob", role: "viewer", organizationId: "a" },
          admin,
        )
      ).status,
    ).toBe(403);
    await expect(
      db
        .prepare("UPDATE tenant_members SET role='viewer' WHERE id='alice'")
        .run(),
    ).rejects.toThrow();
    await expect(
      db.prepare("DELETE FROM tenant_members WHERE id='alice'").run(),
    ).rejects.toThrow();
  });
  it("role changes and removal apply to existing sessions immediately", async () => {
    const admin = await signIn("alice@example.com");
    const cookie = await signIn("charlie@example.com");
    const member = await db
      .prepare(
        "SELECT id FROM tenant_members WHERE user_id=(SELECT id FROM users WHERE email=?)",
      )
      .bind("charlie@example.com")
      .first<{ id: string }>();
    expect(
      (
        await call(
          "/auth/organization/update-member-role",
          { memberId: member!.id, role: "viewer", organizationId: "a" },
          admin,
        )
      ).status,
    ).toBe(200);
    expect(
      (await call("/v1/assess", { observable: "example.com" }, cookie)).status,
    ).toBe(403);
    expect(
      (
        await call(
          "/auth/organization/remove-member",
          { memberIdOrEmail: member!.id, organizationId: "a" },
          admin,
        )
      ).status,
    ).toBe(200);
    expect((await call("/v1/me", undefined, cookie)).status).toBe(403);
  });
  it("password reset creates credentials for the existing account and rejects token reuse", async () => {
    const now = new Date().toISOString();
    await db
      .prepare(
        "INSERT INTO users(id,email,name,created_at,updated_at) VALUES('legacy','legacy@example.com','Legacy',?,?)",
      )
      .bind(now, now)
      .run();
    expect(
      (
        await call("/auth/request-password-reset", {
          email: "legacy@example.com",
          redirectTo: origin + "/reset-password",
        })
      ).status,
    ).toBe(200);
    const resetLink = new URL(mails.at(-1)!.text!.match(/http[^\s]+/)![0]!);
    const reset = await call(
      resetLink.pathname.replace("/api/auth", "/auth") + resetLink.search,
    );
    expect(reset.status).toBe(302);
    const token = new URL(reset.headers.get("location")!).searchParams.get(
      "token",
    )!;
    expect(
      (await call("/auth/reset-password", { token, newPassword: password }))
        .status,
    ).toBe(200);
    await signIn("legacy@example.com");
    expect(
      (await call("/auth/reset-password", { token, newPassword: password })).ok,
    ).toBe(false);
  });
  it("handles mail failure without pretending the invitation was delivered, and supports retry", async () => {
    const admin = await signIn("alice@example.com");
    failMail = true;
    const failure = await call(
      "/auth/organization/invite-member",
      { email: "delivery@example.com", role: "viewer", organizationId: "a" },
      admin,
    );
    failMail = false;
    expect(failure.status).toBe(503);
    expect(
      (
        await call(
          "/auth/organization/invite-member",
          {
            email: "delivery@example.com",
            role: "viewer",
            organizationId: "a",
            resend: true,
          },
          admin,
        )
      ).status,
    ).toBe(200);
  });
});

it("canceled and expired invitations cannot be accepted or disclose team details to other users", async () => {
  const admin = await signIn("alice@example.com"),
    recipient = await signIn("bob@example.com");
  const response = await call(
    "/auth/organization/invite-member",
    { email: "bob@example.com", role: "viewer", organizationId: "a" },
    admin,
  );
  expect(response.status).toBe(200);
  const invite = (await response.json()) as { id: string };
  expect(
    (
      await call(
        "/auth/organization/get-invitation?id=" + invite.id,
        undefined,
        admin,
      )
    ).status,
  ).toBe(403);
  expect(
    (
      await call(
        "/auth/organization/cancel-invitation",
        { invitationId: invite.id },
        admin,
      )
    ).status,
  ).toBe(200);
  expect(
    (
      await call(
        "/auth/organization/accept-invitation",
        { invitationId: invite.id },
        recipient,
      )
    ).ok,
  ).toBe(false);
  await db
    .prepare(
      "UPDATE auth_invitations SET status='pending',expires_at=? WHERE id=?",
    )
    .bind("2000-01-01T00:00:00.000Z", invite.id)
    .run();
  expect(
    (
      await call(
        "/auth/organization/accept-invitation",
        { invitationId: invite.id },
        recipient,
      )
    ).ok,
  ).toBe(false);
  expect(
    await db
      .prepare(
        "SELECT id FROM tenant_members WHERE tenant_id='a' AND user_id='bob'",
      )
      .first(),
  ).toBeNull();
});
it("repeated sign-in failures are rate-limited and production rejects key-to-session exchange", async () => {
  let response: Response | undefined;
  for (let attempt = 0; attempt < 6; attempt++)
    response = await app.fetch(
      new Request("http://api.test/auth/sign-in/email", {
        method: "POST",
        headers: {
          Origin: origin,
          "Content-Type": "application/json",
          "cf-connecting-ip": "203.0.113.250",
        },
        body: JSON.stringify({ email: "missing@example.com", password }),
      }),
      env,
    );
  expect(response!.status).toBe(429);
  const production = { ...env, APP_ENV: "production" };
  expect(
    (
      await app.fetch(
        new Request("http://api.test/v1/session", {
          method: "POST",
          headers: { Origin: origin, Authorization: "Bearer legacy-key" },
        }),
        production,
      )
    ).status,
  ).toBe(401);
});
it("demoting a member revokes their existing API keys and preserves the other tenant's keys", async () => {
  await seedUser("key-owner", "key-owner@example.com", "a", "analyst");
  const now = new Date().toISOString();
  for (const tenant of ["a", "b"])
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,'test',?,'[\"assessment:write\"]',?)",
      )
      .bind("key-" + tenant, tenant, "key-owner", "hash-" + tenant, now)
      .run();
  const admin = await signIn("alice@example.com");
  expect(
    (
      await call(
        "/auth/organization/update-member-role",
        { memberId: "key-owner", organizationId: "a", role: "viewer" },
        admin,
      )
    ).status,
  ).toBe(200);
  expect(
    (
      await db
        .prepare("SELECT revoked_at FROM api_keys WHERE id='key-a'")
        .first<{ revoked_at: string | null }>()
    )?.revoked_at,
  ).not.toBeNull();
  expect(
    (
      await db
        .prepare("SELECT revoked_at FROM api_keys WHERE id='key-b'")
        .first<{ revoked_at: string | null }>()
    )?.revoked_at,
  ).toBeNull();
});
