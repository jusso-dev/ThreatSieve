import {
  test,
  expect,
  request,
  runtime,
  workspace as createWorkspace,
  login,
} from "./support/fixtures";
import { z } from "zod";

test("unauthenticated browser is redirected and invalid credentials remain signed out", async ({
  browser,
  screen,
}) => {
  await browser.goto("/");
  await expect(
    screen.getByRole("heading", "Welcome to your workspace."),
  ).toBeVisible();
  await screen.getByLabel("Work email").fill("invalid@example.com");
  await screen.getByLabel("Password").fill("invalid-synthetic-password");
  await screen.getByRole("button", "Sign in").click();
  await expect(screen.getByRole("alert")).toBeVisible();
  expect(
    (await browser.cookies()).some(
      (c) => c.name === "better-auth.session_token",
    ),
  ).toBe(false);
});
test("real sign-in persists an HttpOnly session without browser-stored API keys", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/sign-in");
  await screen.getByLabel("Work email").fill(workspace.email);
  await screen.getByLabel("Password").fill(workspace.password);
  await screen.getByRole("button", "Sign in").click();
  await expect(screen.getByRole("heading", "Your team")).toBeVisible();
  const cookie = (await browser.cookies()).find(
    (c) => c.name === "better-auth.session_token",
  );
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");
  expect(
    await browser.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
      cookies: document.cookie,
    })),
  ).toEqual({ local: {}, session: {}, cookies: "" });
  await browser.reload();
  await expect(screen.getByRole("heading", "Your team")).toBeVisible();
});
test("logout revokes the server session and protects subsequent navigation", async ({
  browser,
  screen,
  workspace,
}) => {
  await login(browser, workspace);
  await browser.goto("/");
  await expect(screen.getByRole("heading", "Threat operations")).toBeVisible();
  const cookie = (await browser.cookies()).find(
    (c) => c.name === "better-auth.session_token",
  )!;
  await browser.evaluate(async () => {
    await fetch("/api/auth/sign-out", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    return null;
  });
  await browser.reload();
  await expect(
    screen.getByRole("heading", "Welcome to your workspace."),
  ).toBeVisible();
  const response = await fetch(runtime().apiOrigin + "/v1/me", {
    headers: { Cookie: `better-auth.session_token=${cookie.value}` },
  });
  expect(response.status).toBe(401);
});
test("read-only credentials cannot classify, change inventory, sync feeds or create keys", async () => {
  const reader = await createWorkspace({
    scopes: ["intel:read", "assessment:read", "feeds:read"],
  });
  expect((await request(reader, "/v1/assessments")).status).toBe(200);
  for (const [path, method, body] of [
    ["/v1/assess", "POST", { observable: "example.com" }],
    ["/v1/environment", "PUT", {}],
    ["/v1/feeds/threatfox/sync", "POST", {}],
    ["/v1/api-keys", "POST", { name: "escalation", scopes: ["admin"] }],
  ] as const) {
    expect(
      (await request(reader, path, { method, body: JSON.stringify(body) }))
        .status,
    ).toBe(403);
  }
});
test("cookie-authenticated writes reject absent and foreign origins", async ({
  workspace,
}) => {
  const session = await request(workspace, "/v1/session", { method: "POST" });
  const cookie = session.headers.get("set-cookie")!.split(";")[0]!;
  for (const origin of [undefined, "https://attacker.invalid"]) {
    const response = await fetch(runtime().apiOrigin + "/v1/environment", {
      method: "PUT",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/json",
        ...(origin ? { Origin: origin } : {}),
      },
      body: "{}",
    });
    expect(response.status).toBe(403);
  }
  expect(
    (
      await request(workspace, "/v1/session", {
        method: "POST",
        headers: { Origin: "https://attacker.invalid" },
      })
    ).status,
  ).toBe(403);
});
test("revoking an API key also invalidates sessions derived from that key", async ({
  workspace,
}) => {
  const keyResponse = await request(workspace, "/v1/api-keys", {
    method: "POST",
    body: JSON.stringify({ name: "Ephemeral reader", scopes: ["intel:read"] }),
  });
  expect(keyResponse.status).toBe(201);
  const key = z
    .object({ id: z.string(), key: z.string() })
    .parse(await keyResponse.json());
  const reader = { ...workspace, key: key.key };
  const session = await request(reader, "/v1/session", { method: "POST" });
  expect(session.status).toBe(200);
  const cookie = session.headers.get("set-cookie")!.split(";")[0]!;
  expect(
    (await request(workspace, "/v1/api-keys/" + key.id, { method: "DELETE" }))
      .status,
  ).toBe(200);
  expect((await request(reader, "/v1/me")).status).toBe(401);
  expect(
    (
      await fetch(runtime().apiOrigin + "/v1/me", {
        headers: { Cookie: cookie },
      })
    ).status,
  ).toBe(401);
});
test("unauthorized API responses are non-cacheable and do not expose credentials", async () => {
  const response = await fetch(runtime().apiOrigin + "/v1/assessments");
  expect(response.status).toBe(401);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("x-request-id")).toBeTruthy();
  expect(await response.text()).not.toContain(runtime().adminKey);
});
test("malformed JSON, invalid types, invalid cursors and excessive graph depth are rejected", async ({
  workspace,
}) => {
  for (const body of [
    "{",
    JSON.stringify({ observable: "example.com", type: "invented" }),
    JSON.stringify({ observable: "" }),
  ]) {
    expect(
      (await request(workspace, "/v1/assess", { method: "POST", body })).status,
    ).toBe(400);
  }
  expect(
    (
      await request(workspace, "/v1/assess", {
        method: "POST",
        body: JSON.stringify({ observable: "not an observable" }),
      })
    ).status,
  ).toBe(422);
  expect(
    (await request(workspace, "/v1/assessments?cursor=invalid")).status,
  ).toBe(400);
  expect((await request(workspace, "/v1/graph/anything?depth=99")).status).toBe(
    400,
  );
});
