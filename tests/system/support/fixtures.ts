import { test as base, type Browser } from "@e2e-dev/web";
import { readFileSync } from "node:fs";
import { z } from "zod";
import type { Assessment } from "../../../packages/schemas/src/index";
export { expect } from "e2e";
export const runtime = () =>
  z
    .object({
      controlKey: z.string(),
      apiOrigin: z.string(),
      adminKey: z.string(),
    })
    .parse(JSON.parse(readFileSync(".e2e/runtime/credentials.json", "utf8")));
export async function control(path: string, body: unknown) {
  const config = runtime();
  const response = await fetch(config.apiOrigin + "/__test/" + path, {
    method: "POST",
    headers: {
      "X-Test-Control": config.controlKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!response.ok)
    throw new Error(
      `Test setup failed: ${response.status} ${await response.text()}`,
    );
  return response.json() as Promise<unknown>;
}
const Workspace = z.object({
  tenantId: z.string(),
  email: z.string(),
  password: z.string(),
  userId: z.string(),
  keyId: z.string(),
  key: z.string(),
  assessments: z.array(z.custom<Assessment>()),
});
export type Workspace = z.infer<typeof Workspace>;
export async function workspace(
  options: {
    scopes?: string[];
    seeded?: boolean;
    extraAssessments?: number;
  } = {},
) {
  return Workspace.parse(await control("workspace", options));
}
export function request(w: Workspace, path: string, init: RequestInit = {}) {
  return fetch(runtime().apiOrigin + path, {
    ...init,
    headers: {
      Authorization: "Bearer " + w.key,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
}
export async function login(browser: Browser, w: Workspace) {
  const response = await fetch(runtime().apiOrigin + "/auth/sign-in/email", {
    method: "POST",
    headers: {
      Origin: "http://127.0.0.1:3180",
      "Content-Type": "application/json",
      "cf-connecting-ip": "192.0.2." + Math.floor(Math.random() * 254),
    },
    body: JSON.stringify({ email: w.email, password: w.password }),
  });
  if (response.status !== 201 && response.status !== 200)
    throw new Error("Session setup failed: " + (await response.text()));
  const cookie = response.headers.get("set-cookie")!.split(";")[0]!;
  const separator = cookie.indexOf("=");
  await browser.setCookies([
    {
      name: cookie.slice(0, separator),
      value: cookie.slice(separator + 1),
      url: "http://127.0.0.1:3180",
      httpOnly: true,
      sameSite: "Strict",
    },
  ]);
}
export const test = base.extend<{ workspace: Workspace }>({
  workspace: async (_fixtures, use) => {
    await use(await workspace());
  },
});
export const signedIn = test.extend<{ authenticated: boolean }>({
  authenticated: async ({ browser, workspace }, use) => {
    await login(browser, workspace);
    await use(true);
  },
});
export function beacon(w: Workspace) {
  return w.assessments.find(
    (a) => a.observable.value === "beacon.demo.example",
  )!;
}
/** HTTP assertions validate the fields they depend on; this preserves the versioned API type. */
export async function json<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}
