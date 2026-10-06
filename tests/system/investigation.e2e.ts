import {
  signedIn as test,
  expect,
  request,
  beacon,
  control,
  json,
} from "./support/fixtures";
import type { Assessment } from "../../packages/schemas/src/index";
import { z } from "zod";

for (const [button, status, _action, review] of [
  ["Confirm", "confirmed", "confirm", false],
  ["Reject", "rejected", "reject", true],
  ["Needs investigation", "needs-investigation", "investigate", true],
] as const) {
  test(`${button} persists the decision, audit and review queue state`, async ({
    browser,
    screen,
    workspace,
  }) => {
    const a = beacon(workspace);
    await browser.goto("/investigations/" + a.assessment_id);
    await screen.getByRole("button", button).click();
    await screen
      .getByLabel("Reason")
      .fill("Independent evidence reviewed in isolated system test.");
    await screen.getByRole("button", "Save decision").click();
    await expect(
      screen.getByText("Analyst decision saved with an audit record."),
    ).toBeVisible();
    const saved = await json<Assessment>(
      await request(workspace, "/v1/assessments/" + a.assessment_id),
    );
    expect(saved.status).toBe(status);
    expect(saved.human_review).toBe(review);
    expect(saved.malicious).toEqual(a.malicious);
    const persisted = z
      .object({
        audit: z.array(z.object({ action: z.string() })),
        feedback: z.array(z.unknown()),
      })
      .parse(await control("inspect", { tenantId: workspace.tenantId }));
    expect(persisted.feedback).toHaveLength(1);
    expect(
      persisted.audit.some((e) => e.action === "assessment." + status),
    ).toBe(true);
    const queue = await json<{ data: Assessment[] }>(
      await request(workspace, "/v1/assessments?view=review"),
    );
    expect(
      queue.data.some(
        (item: { assessment_id: string }) =>
          item.assessment_id === a.assessment_id,
      ),
    ).toBe(review);
    await browser.reload();
    await expect(screen.getByRole("heading", a.observable.value)).toBeVisible();
  });
}
test("analyst modification changes effective classification but retains model probabilities", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace);
  await browser.goto("/investigations/" + a.assessment_id);
  await screen.getByRole("button", "Modify classification").click();
  await screen.getByLabel("Classification").selectOption({ value: "benign" });
  await screen
    .getByLabel("Reason")
    .fill("Verified synthetic benign override with source owner.");
  await screen.getByRole("button", "Save decision").click();
  await expect(
    screen.getByText("Analyst decision saved with an audit record."),
  ).toBeVisible();
  const saved = await json<Assessment>(
    await request(workspace, "/v1/assessments/" + a.assessment_id),
  );
  expect(saved.effective_classification).toBe("benign");
  expect(saved.malicious).toEqual(a.malicious);
  expect(saved.runs).toEqual(a.runs);
  expect(saved.status).toBe("modified");
});
test("concurrent analyst update produces a real revision conflict and preserves the draft", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace);
  await browser.goto("/investigations/" + a.assessment_id);
  await screen.getByRole("button", "Confirm").click();
  await screen
    .getByLabel("Reason")
    .fill("Draft retained when a second analyst updates this record.");
  expect(
    (
      await request(
        workspace,
        `/v1/assessments/${a.assessment_id}/investigate`,
        {
          method: "POST",
          body: JSON.stringify({
            reason: "Concurrent analyst needs further evidence.",
          }),
        },
      )
    ).status,
  ).toBe(200);
  await screen.getByRole("button", "Save decision").click();
  await expect(screen.getByRole("dialog").getByRole("alert")).toContainText(
    "This assessment has changed",
  );
  await expect(screen.getByLabel("Reason")).toHaveValue(
    "Draft retained when a second analyst updates this record.",
  );
  await screen.getByRole("button", "Reload assessment").click();
  await expect(screen.getByRole("dialog")).not.toBeVisible();
});
test("evidence, graph nodes and attribution caveat remain inspectable", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/investigations/" + beacon(workspace).assessment_id);
  await expect(
    screen.getByRole("heading", /^Evidence & provenance/),
  ).toBeVisible();
  await expect(
    screen.getByRole("heading", "Potential actor associations"),
  ).toBeVisible();
  await screen.getByRole("button", "malware DemoRAT").click();
  await expect(
    screen.getByText(/Synthetic malware entity used solely/),
  ).toBeVisible();
  await expect(screen.getByText(/Similarity is not attribution/)).toBeVisible();
});
test("STIX download contains valid bundle objects and excludes private customer evidence", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace);
  await browser.goto("/investigations/" + a.assessment_id);
  const file = await browser.waitForDownload(() =>
    screen.getByRole("link", "Export STIX").click(),
  );
  expect(file.suggestedFilename).toContain(".stix.json");
  const raw = await (
    await request(workspace, "/v1/assessments/" + a.assessment_id + "/stix")
  ).text();
  const bundle = z
    .object({
      type: z.literal("bundle"),
      objects: z.array(
        z.object({ type: z.string(), id: z.string() }).passthrough(),
      ),
    })
    .parse(JSON.parse(raw));
  expect(bundle.objects.some((o) => o.type === "indicator")).toBe(true);
  expect(raw).not.toContain(workspace.tenantId);
  expect(raw).not.toContain(workspace.key);
  expect(raw).not.toContain("workstation ABC");
});
test("unknown assessment identifier displays an error without exposing another record", async ({
  browser,
  screen,
}) => {
  await browser.goto("/investigations/nonexistent-synthetic-id");
  await expect(
    screen
      .getByRole("alert")
      .filter({ hasText: "This item is no longer available." }),
  ).toContainText("This item is no longer available.");
  await expect(screen.getByRole("button", "Confirm")).not.toBeVisible();
});

test("forced reassessment queues new model runs and produces tenant-protected archive exports", async ({
  workspace,
}) => {
  const { workspace: createWorkspace } = await import("./support/fixtures");
  const foreign = await createWorkspace();
  const initial = await json<Assessment>(
    await request(workspace, "/v1/assess", {
      method: "POST",
      body: JSON.stringify({ observable: "reassess.synthetic.test" }),
    }),
  );
  const response = await request(
    workspace,
    "/v1/assessments/" + initial.assessment_id + "/reclassify",
    { method: "POST" },
  );
  expect(response.status).toBe(202);
  const job = await json<{ job_id: string }>(response);
  await expect
    .poll(
      async () =>
        (
          await json<{ status: string }>(
            await request(workspace, "/v1/jobs/" + job.job_id),
          )
        ).status,
      { timeout: 15000 },
    )
    .toBe("complete");
  const latest = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?q=reassess.synthetic.test"),
  );
  expect(latest.data[0]!.runs[0]!.id).not.toBe(initial.runs[0]!.id);
  await expect
    .poll(
      async () =>
        (
          await json<{ data: unknown[] }>(
            await request(workspace, "/v1/exports"),
          )
        ).data.length,
      { timeout: 15000 },
    )
    .toBeGreaterThan(0);
  const exports = await json<{ data: { id: string }[] }>(
    await request(workspace, "/v1/exports"),
  );
  const archived = await request(
    workspace,
    "/v1/exports/" + exports.data[0]!.id,
  );
  expect(archived.status).toBe(200);
  expect((await json<{ type: string }>(archived)).type).toBe("bundle");
  expect(
    (await request(foreign, "/v1/exports/" + exports.data[0]!.id)).status,
  ).toBe(404);
});
