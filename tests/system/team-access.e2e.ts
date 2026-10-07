import {
  signedIn as test,
  expect,
  control,
  login,
  runtime,
} from "./support/fixtures";
import { copyFileSync, readdirSync } from "node:fs";
import { z } from "zod";

function capture(relative: string, target: string) {
  const source = readdirSync(".e2e/artifacts", { recursive: true }).find(
    (p) => typeof p === "string" && p.endsWith("/" + relative),
  );
  if (!source) throw new Error("Screenshot artifact was not created");
  copyFileSync(".e2e/artifacts/" + source, target);
}
const mailSchema = z.object({ text: z.string() });
async function mailLink(email: string) {
  const mail = mailSchema.parse(await control("mail", { email }));
  return mail.text.match(/http[^\s]+/)![0]!;
}

test("team invitation travels through signup, verification, acceptance and role changes", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  const email = "invited-" + crypto.randomUUID() + "@example.com";
  await browser.goto("/team");
  await expect(screen.getByRole("heading", "Your team")).toBeVisible();
  await screen.getByLabel("Work email").fill(email);
  await screen
    .getByLabel("Role", { exact: true })
    .selectOption({ value: "analyst" });
  await screen.getByRole("button", "Send invitation").click();
  await expect(
    screen.getByText(
      "Invitation sent. Your teammate can join from their email.",
    ),
  ).toBeVisible();
  await expect(screen.getByRole("button", "Resend")).toBeVisible();
  const invitation = await mailLink(email);
  await browser.evaluate(async () => {
    await fetch("/api/auth/sign-out", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    return null;
  });
  await browser.goto(invitation);
  await screen.getByRole("link", "Create an account").click();
  await screen.getByLabel("Your name").fill("Invited analyst");
  await screen.getByLabel("Work email").fill(email);
  await screen
    .getByLabel("Password", { exact: true })
    .fill("Synthetic invitation passphrase!");
  await screen
    .getByLabel("Confirm password")
    .fill("Synthetic invitation passphrase!");
  await screen.getByRole("button", "Create account").click();
  await expect(screen.getByRole("heading", "Check your inbox.")).toBeVisible();
  await browser.goto(await mailLink(email));
  await expect(screen.getByRole("button", "Accept invitation")).toBeVisible();
  await screen.getByRole("button", "Accept invitation").click();
  await expect(screen.getByRole("heading", "Threat operations")).toBeVisible();
  await browser.goto("/team");
  await expect(screen.getByText("Invited analyst (you)")).toBeVisible();
  await expect(screen.getByRole("button", "Send invitation")).not.toBeVisible();
  const permission = await browser.evaluate(async () => ({
    status: (await fetch("/api/v1/feeds/threatfox/sync", { method: "POST" }))
      .status,
  }));
  expect(permission.status).toBe(403);
  await login(browser, workspace);
  await browser.goto("/team");
  await screen
    .getByLabel("Role for " + email)
    .selectOption({ value: "viewer" });
  await expect(
    screen.getByText(
      "Role updated. Any API keys issued to this member were revoked.",
    ),
  ).toBeVisible();
  if (process.env.UPDATE_SCREENSHOTS === "1") {
    await browser.setViewport(
      await browser.evaluate(() => ({
        width: window.innerWidth,
        height: document.documentElement.scrollHeight,
      })),
    );
    await browser.evaluate(() => {
      document.getAnimations().forEach((animation) => animation.finish());
      return null;
    });
    capture(await app.screenshot("team-access"), "docs/images/team-access.png");
  }
});

test("admins can resend and cancel invitations, with clear success notifications", async ({
  browser,
  screen,
}) => {
  const email = "cancel-" + crypto.randomUUID() + "@example.com";
  await browser.goto("/team");
  await screen.getByLabel("Work email").fill(email);
  await screen.getByRole("button", "Send invitation").click();
  await screen.getByRole("button", "Resend").click();
  await expect(screen.getByText("Invitation sent again.")).toBeVisible();
  await screen.getByRole("button", "Cancel invitation").click();
  await expect(
    screen.getByText("Invitation canceled. The old link will no longer work."),
  ).toBeVisible();
  await expect(
    screen.getByText("All caught up. There are no pending invitations."),
  ).toBeVisible();
});

test("the last administrator gets a friendly error and retains access", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/team");
  await screen
    .getByLabel("Role for " + workspace.email)
    .selectOption({ value: "viewer" });
  await expect(
    screen
      .getByRole("alert")
      .filter({ hasText: "Your team needs at least one admin." }),
  ).toContainText("Your team needs at least one admin.");
  await browser.reload();
  await expect(screen.getByRole("button", "Send invitation")).toBeVisible();
  await screen.getByRole("button", "Remove", { exact: true }).click();
  await expect(screen.getByRole("dialog")).toBeVisible();
  await browser.keyboard.press("Escape");
  await expect(screen.getByRole("dialog")).not.toBeVisible();
});

test("password reset works through the email link and revokes older sessions", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  await browser.goto("/sign-in");
  if (process.env.UPDATE_SCREENSHOTS === "1")
    capture(
      await app.screenshot("better-auth-sign-in"),
      "docs/images/sign-in.png",
    );
  const cookies = await browser.cookies();
  const oldCookie = cookies.map((c) => c.name + "=" + c.value).join("; ");
  await screen.getByRole("link", "Forgot password?").click();
  await expect(
    screen.getByRole("heading", "Let’s get you back in."),
  ).toBeVisible();
  await screen.getByLabel("Work email").fill(workspace.email);
  await screen.getByRole("button", "Send reset link").click();
  await expect(screen.getByRole("heading", "Check your inbox.")).toBeVisible();
  await browser.goto(await mailLink(workspace.email));
  await screen
    .getByLabel("New password")
    .fill("A brand new synthetic passphrase!");
  await screen
    .getByLabel("Confirm password")
    .fill("A brand new synthetic passphrase!");
  await screen.getByRole("button", "Save new password").click();
  await expect(
    screen.getByRole("heading", "Welcome to your workspace."),
  ).toBeVisible();
  const revoked = await fetch(runtime().apiOrigin + "/v1/me", {
    headers: { Cookie: oldCookie },
  });
  expect(revoked.status).toBe(401);
  await screen.getByLabel("Work email").fill(workspace.email);
  await screen
    .getByLabel("Password", { exact: true })
    .fill("A brand new synthetic passphrase!");
  await screen.getByRole("button", "Sign in", { exact: true }).click();
  await expect(screen.getByRole("heading", "Your team")).toBeVisible();
});

test("team management stays usable on mobile without horizontal overflow", async ({
  browser,
  screen,
  app,
}) => {
  await browser.setViewport({ width: 390, height: 844 });
  await browser.goto("/team");
  await expect(screen.getByRole("button", "Send invitation")).toBeVisible();
  expect(
    await browser.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  if (process.env.UPDATE_SCREENSHOTS === "1") {
    await browser.setViewport(
      await browser.evaluate(() => ({
        width: window.innerWidth,
        height: document.documentElement.scrollHeight,
      })),
    );
    await browser.evaluate(() => {
      document.getAnimations().forEach((animation) => animation.finish());
      return null;
    });
    capture(await app.screenshot("team-mobile"), "docs/images/team-mobile.png");
  }
});

test("authenticator enrollment and second-factor sign-in protect the workspace", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  const { authenticatorCode } = await import("../totp");
  await browser.goto("/security");
  await screen.getByLabel("Current password").fill(workspace.password);
  await screen.getByRole("button", "Set up authenticator").click();
  await expect(screen.getByLabel("Authenticator setup key")).toBeVisible();
  const secret = await browser.evaluate(
    () => (document.querySelector("#setup-key") as HTMLInputElement).value,
  );
  await screen
    .getByLabel("Authenticator code", { exact: true })
    .fill(authenticatorCode(secret));
  await screen.getByRole("button", "Verify authenticator").click();
  await expect(
    screen.getByRole("heading", "Save your recovery codes"),
  ).toBeVisible();
  await screen.getByRole("button", "I have saved my recovery codes").click();
  await expect(
    screen.getByRole("button", "Replace recovery codes"),
  ).toBeVisible();
  if (process.env.UPDATE_SCREENSHOTS === "1")
    capture(
      await app.screenshot("account-security"),
      "docs/images/account-security.png",
    );
  await browser.evaluate(async () => {
    await fetch("/api/auth/sign-out", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    return null;
  });
  await browser.goto("/sign-in");
  await screen.getByLabel("Work email").fill(workspace.email);
  await screen.getByLabel("Password", { exact: true }).fill(workspace.password);
  await screen.getByRole("button", "Sign in", { exact: true }).click();
  await expect(
    screen.getByRole("heading", "Verify your identity."),
  ).toBeVisible();
  expect(
    await browser.evaluate(async () => (await fetch("/api/v1/me")).status),
  ).toBe(401);
  await screen
    .getByLabel("Authenticator code", { exact: true })
    .fill(authenticatorCode(secret));
  await screen.getByRole("button", "Verify and sign in").click();
  await expect(screen.getByRole("heading", "Your team")).toBeVisible();
});
