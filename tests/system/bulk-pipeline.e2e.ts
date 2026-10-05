import {
  signedIn as test,
  expect,
  request,
  json,
  control,
} from "./support/fixtures";
import type { Assessment } from "../../packages/schemas/src/index";
import { resolve } from "node:path";
interface Job {
  id: string;
  pipeline_status: string;
  totals: { processed: number; rejected: number };
  stages: { stage: string; status: string; count: number }[];
}
async function completed(w: Parameters<typeof request>[0], id: string) {
  await expect
    .poll(
      async () =>
        (await json<Job>(await request(w, "/v1/jobs/" + id))).pipeline_status,
      { timeout: 30000 },
    )
    .toBe("complete");
  return json<Job>(await request(w, "/v1/jobs/" + id));
}
test("paste import finishes every queue stage, deduplicates and isolates invalid indicators", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/bulk");
  await screen
    .getByLabel("Indicators to analyse")
    .fill(
      "Bulk-One.synthetic.test\nbulk-one.synthetic.test\n192.0.2.211\nnot an observable",
    );
  await screen.getByRole("button", "Analyse indicators").click();
  await expect(screen.getByRole("status")).toHaveText("Analysis complete", {
    timeout: 30000,
  });
  const list = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments"),
  );
  expect(
    list.data.filter(
      (a) => a.observable.normalizedValue === "bulk-one.synthetic.test",
    ),
  ).toHaveLength(1);
  expect(
    list.data.filter((a) => a.observable.normalizedValue === "192.0.2.211"),
  ).toHaveLength(1);
  await expect(screen.getByText("classify · complete")).toBeVisible();
});
for (const format of ["csv", "json", "stix.json"] as const) {
  test(`${format} file upload reaches persisted assessments through the real pipeline`, async ({
    browser,
    screen,
    workspace,
  }) => {
    await browser.goto("/bulk");
    await screen
      .getByLabel(/Select your intelligence file/)
      .setInputFiles(resolve("tests/system/fixtures/indicators." + format));
    await screen.getByRole("button", "Upload & analyse").click();
    await expect(screen.getByRole("status")).toHaveText("Analysis complete", {
      timeout: 30000,
    });
    const list = await json<{ data: Assessment[] }>(
      await request(workspace, "/v1/assessments?q=file-upload.synthetic.test"),
    );
    expect(list.data).toHaveLength(1);
    expect(list.data[0]!.attack).toHaveLength(0);
    expect(list.data[0]!.actors).toHaveLength(0);
  });
}
test("concurrent identical submissions share one root job and changed payload is rejected", async ({
  workspace,
}) => {
  const headers = { "Idempotency-Key": crypto.randomUUID() };
  const body = JSON.stringify({ observables: ["idempotent.synthetic.test"] });
  const responses = await Promise.all([
    request(workspace, "/v1/assess/bulk", { method: "POST", headers, body }),
    request(workspace, "/v1/assess/bulk", { method: "POST", headers, body }),
  ]);
  for (const r of responses) expect(r.status).toBe(202);
  const jobs = await Promise.all(
    responses.map((r) => json<{ job_id: string }>(r)),
  );
  expect(jobs[0]!.job_id).toBe(jobs[1]!.job_id);
  expect(
    (
      await request(workspace, "/v1/assess/bulk", {
        method: "POST",
        headers,
        body: JSON.stringify({ observables: ["different.synthetic.test"] }),
      })
    ).status,
  ).toBe(409);
  const job = await completed(workspace, jobs[0]!.job_id);
  expect(job.totals).toEqual({ processed: 1, rejected: 0 });
  expect(
    job.stages.some((s) => s.stage === "classify" && s.status === "complete"),
  ).toBe(true);
});
test("bulk jobs over the 100-row processing page retain accurate totals and deduplicate across pages", async ({
  workspace,
}) => {
  const values = Array.from({ length: 102 }, () => "cross-page.synthetic.test");
  values[100] = "not an observable";
  const submitted = await request(workspace, "/v1/assess/bulk", {
    method: "POST",
    body: JSON.stringify({ observables: values }),
  });
  expect(submitted.status).toBe(202);
  const { job_id } = await json<{ job_id: string }>(submitted);
  const job = await completed(workspace, job_id);
  expect(job.totals).toEqual({ processed: 102, rejected: 1 });
  const list = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?q=cross-page.synthetic.test"),
  );
  expect(list.data).toHaveLength(1);
});
for (const [format, body] of [
  ["json", "{"],
  ["csv", "unsupported\nexample.com"],
  [
    "stix",
    JSON.stringify({
      type: "bundle",
      objects: [
        {
          type: "indicator",
          pattern:
            "[domain-name:value = 'a.test' OR domain-name:value = 'b.test']",
        },
      ],
    }),
  ],
] as const) {
  test(`invalid ${format} upload returns a useful error without creating work`, async ({
    workspace,
  }) => {
    const response = await request(workspace, "/v1/uploads?format=" + format, {
      method: "POST",
      body,
    });
    expect(response.status).toBe(422);
    expect(
      (
        (await control("inspect", { tenantId: workspace.tenantId })) as {
          jobs: unknown[];
        }
      ).jobs,
    ).toHaveLength(0);
    const error = await json<{ error: { code: string; message: string } }>(
      response,
    );
    expect(error.error.message.length).toBeGreaterThan(5);
  });
}
test("a lost upload response can be retried safely with the same idempotency key", async ({
  browser,
  screen,
  workspace,
}) => {
  const keys: string[] = [];
  await browser.route("**/api/v1/uploads?*", async (route) => {
    keys.push(route.request.headers["idempotency-key"]!);
    if (keys.length === 1) {
      // Commit the real API submission, then simulate losing its response.
      const response = await request(workspace, "/v1/uploads?format=text", {
        method: "POST",
        headers: { "Idempotency-Key": keys[0]! },
        body: route.request.postData,
      });
      expect(response.status).toBe(202);
      await route.abort();
    } else await route.continue();
  });
  await browser.goto("/bulk");
  await screen
    .getByLabel("Indicators to analyse")
    .fill("lost-response.synthetic.test");
  await screen.getByRole("button", "Analyse indicators").click();
  await expect(
    screen.getByRole("alert").filter({ hasText: "Failed to fetch" }),
  ).toContainText("Failed to fetch");
  await screen.getByRole("button", "Analyse indicators").click();
  await expect(screen.getByRole("status")).toHaveText("Analysis complete", {
    timeout: 30000,
  });
  expect(keys).toHaveLength(2);
  expect(keys[1]).toBe(keys[0]);
  const list = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?q=lost-response.synthetic.test"),
  );
  expect(list.data).toHaveLength(1);
});

test("oversized uploads are rejected by both browser validation and the API", async ({
  browser,
  screen,
  workspace,
}) => {
  const { writeFileSync, unlinkSync } = await import("node:fs");
  const filename = resolve(
    ".e2e/runtime/oversized-" + workspace.tenantId + ".csv",
  );
  const body = "x".repeat(16 * 1024 * 1024 + 1);
  writeFileSync(filename, body);
  try {
    await browser.goto("/bulk");
    await screen
      .getByLabel(/Select your intelligence file/)
      .setInputFiles(filename);
    await screen.getByRole("button", "Upload & analyse").click();
    await expect(
      screen
        .getByRole("alert")
        .filter({ hasText: "Files must be 16 MiB or smaller" }),
    ).toBeVisible();
    expect(
      (
        await request(workspace, "/v1/uploads?format=text", {
          method: "POST",
          body,
        })
      ).status,
    ).toBe(413);
    expect(
      (
        (await control("inspect", { tenantId: workspace.tenantId })) as {
          jobs: unknown[];
        }
      ).jobs,
    ).toHaveLength(0);
  } finally {
    unlinkSync(filename);
  }
});
