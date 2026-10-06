import {
  signedIn as test,
  expect,
  request,
  json,
  workspace as createWorkspace,
  login,
} from "./support/fixtures";
import type { Assessment } from "../../packages/schemas/src/index";

test("queue filters agree with server results and empty search recovers", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/");
  await screen.getByRole("button", "Needs review").click();
  const review = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?view=review"),
  );
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(
    review.data.length,
  );
  await screen.getByRole("button", "All intelligence").click();
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(6);
  await screen.getByLabel("Filter observables").fill("no-match.synthetic.test");
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(0);
  await screen.getByLabel("Filter observables").fill("beacon");
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(1);
  await expect(
    screen.getByRole("link", "Investigate beacon.demo.example"),
  ).toBeVisible();
});
test("pagination traverses more than one page without duplicate assessment IDs", async ({
  browser,
  screen,
}) => {
  const w = await createWorkspace({ extraAssessments: 55 });
  await login(browser, w);
  await browser.goto("/");
  await screen.getByRole("button", "All intelligence").click();
  await expect(screen.getByText("50 assessments on page 1")).toBeVisible();
  const first = await browser.evaluate(() =>
    Array.from(
      document.querySelectorAll('a[aria-label^="Investigate "]'),
      (e) => e.getAttribute("href"),
    ),
  );
  await screen.getByRole("button", "Next page").click();
  await expect(screen.getByText("11 assessments on page 2")).toBeVisible();
  const second = await browser.evaluate(() =>
    Array.from(
      document.querySelectorAll('a[aria-label^="Investigate "]'),
      (e) => e.getAttribute("href"),
    ),
  );
  expect(new Set([...first, ...second]).size).toBe(61);
  await expect(screen.getByRole("button", "Next page")).toBeDisabled();
  await screen.getByRole("button", "Previous page").click();
  await expect(screen.getByText("50 assessments on page 1")).toBeVisible();
});
test("a new tenant has an honest empty state and no demonstration assessments", async ({
  browser,
  screen,
}) => {
  await login(browser, await createWorkspace({ seeded: false }));
  await browser.goto("/");
  await expect(
    screen.getByText("0 assessments with traceable evidence"),
  ).toBeVisible();
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(0);
  await expect(screen.getByText(/Demonstration workspace/)).not.toBeVisible();
});
test("assess dialog reports invalid input then opens a real unknown assessment", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/");
  await screen.getByRole("button", "Assess observable").click();
  await screen
    .getByLabel("IP, domain, URL, hash or CVE")
    .fill("not an observable");
  await screen.getByRole("button", "Run assessment").click();
  await expect(screen.getByRole("dialog").getByRole("alert")).toBeVisible();
  await screen
    .getByLabel("IP, domain, URL, hash or CVE")
    .fill("unknown-new.synthetic.test");
  await screen.getByRole("button", "Run assessment").click();
  await expect(
    screen.getByRole("heading", "unknown-new.synthetic.test"),
  ).toBeVisible();
  const list = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?q=unknown-new.synthetic.test"),
  );
  expect(list.data).toHaveLength(1);
  expect(list.data[0]!.malicious.classification).toBe("unknown");
  expect(list.data[0]!.attack).toHaveLength(0);
  expect(list.data[0]!.actors).toHaveLength(0);
  expect(list.data[0]!.human_review).toBe(true);
  expect(list.data[0]!.runs.map((run) => run.model)).toEqual([
    "@cf/cloudflare/clef-flash",
    "@cf/cloudflare/clef",
  ]);
});
test("search opens known intelligence without creating an assessment", async ({
  browser,
  screen,
  workspace,
}) => {
  const before = await json<{ summary: { total: number } }>(
    await request(workspace, "/v1/assessments"),
  );
  await browser.goto("/");
  await screen.getByRole("textbox", "Search intelligence").fill("DemoRAT");
  await screen.getByRole("button", /DemoRAT malware/).click();
  await expect(screen.getByRole("heading", "DemoRAT")).toBeVisible();
  const after = await json<{ summary: { total: number } }>(
    await request(workspace, "/v1/assessments"),
  );
  expect(after.summary.total).toBe(before.summary.total);
});
test("temporary intelligence outage displays a recoverable error", async ({
  browser,
  screen,
}) => {
  let fail = true;
  await browser.route("**/api/v1/assessments?*", async (route) => {
    if (fail)
      await route.fulfill({
        status: 503,
        json: { error: { message: "Synthetic temporary outage" } },
      });
    else await route.continue();
  });
  await browser.goto("/");
  await expect(
    screen
      .getByRole("alert")
      .filter({ hasText: "ThreatSieve is temporarily unavailable" }),
  ).toBeVisible();
  fail = false;
  await screen.getByRole("button", "Refresh intelligence").click();
  await expect(screen.getByRole("table")).toBeVisible();
});
test("environment edits persist after reload and remain tenant-scoped", async ({
  browser,
  screen,
  workspace,
}) => {
  const other = await createWorkspace();
  await browser.goto("/inventory");
  await screen
    .getByLabel("Technologies")
    .fill("Windows 11, FortiGate, SyntheticPlatform");
  await screen.getByRole("button", "Save environment").click();
  await expect(screen.getByText(/Environment profile saved/)).toBeVisible();
  await browser.reload();
  await expect(screen.getByLabel("Technologies")).toHaveValue(
    "Windows 11, FortiGate, SyntheticPlatform",
  );
  const own = await json<{ technologies: string[] }>(
    await request(workspace, "/v1/environment"),
  );
  const foreign = await json<{ technologies: string[] }>(
    await request(other, "/v1/environment"),
  );
  expect(own.technologies).toContain("SyntheticPlatform");
  expect(foreign.technologies).not.toContain("SyntheticPlatform");
});
test("unknown cluster exposes source-backed members without forced actor attribution", async ({
  browser,
  screen,
}) => {
  await browser.goto("/clusters");
  await expect(screen.getByRole("heading", "Emerging clusters")).toBeVisible();
  const cluster = browser
    .locator(".cluster-card")
    .filter({ hasText: "Unknown Cluster TS-2026-0042" });
  await expect(cluster.getByText("UNKNOWN")).toBeVisible();
  await cluster.getByRole("button", "Inspect cluster").click();
  await expect(screen.getByText("beacon.demo.example")).toBeVisible();
  await expect(
    screen.getByText(/No customer identities or private telemetry/),
  ).toBeVisible();
});
