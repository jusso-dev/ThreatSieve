import { z } from "zod";
import {
  test,
  expect,
  runtime,
  workspace as createWorkspace,
} from "./support/fixtures";
test("parallel sessions retain tenant isolation and sign-out revokes only its own session", async ({
  workspace,
}) => {
  const tenants = [workspace, await createWorkspace()];
  const headers = {
    Origin: "http://127.0.0.1:3180",
    "Content-Type": "application/json",
    "cf-connecting-ip": "192.0.2.249",
  };
  const sessions = await Promise.all(
    tenants.map(async (tenant) => {
      const login = await fetch(runtime().apiOrigin + "/auth/sign-in/email", {
        method: "POST",
        headers,
        body: JSON.stringify({
          email: tenant.email,
          password: tenant.password,
        }),
      });
      expect(login.status).toBe(200);
      return {
        tenant,
        cookie: login.headers
          .getSetCookie()
          .map((c) => c.split(";")[0])
          .join("; "),
      };
    }),
  );
  for (let round = 0; round < 5; round++) {
    await Promise.all(
      Array.from({ length: 10 }, async (_, index) => {
        const session = sessions[index % 2]!;
        const response = await fetch(runtime().apiOrigin + "/v1/me", {
          headers: { Cookie: session.cookie },
        });
        expect(response.status).toBe(200);
        const principal = z
          .object({ tenantId: z.string(), userId: z.string() })
          .parse(await response.json());
        expect(principal.tenantId).toBe(session.tenant.tenantId);
        expect(principal.userId).toBe(session.tenant.userId);
      }),
    );
  }
  const logout = await fetch(runtime().apiOrigin + "/auth/sign-out", {
    method: "POST",
    headers: { ...headers, Cookie: sessions[0]!.cookie },
    body: "{}",
  });
  expect(logout.status).toBe(200);
  expect(
    (
      await fetch(runtime().apiOrigin + "/v1/me", {
        headers: { Cookie: sessions[0]!.cookie },
      })
    ).status,
  ).toBe(401);
  expect(
    (
      await fetch(runtime().apiOrigin + "/v1/me", {
        headers: { Cookie: sessions[1]!.cookie },
      })
    ).status,
  ).toBe(200);
});
