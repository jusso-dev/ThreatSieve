import {
  test,
  expect,
  request,
  json,
  workspace as createWorkspace,
  beacon,
  login,
} from "./support/fixtures";
import type { Assessment } from "../../packages/schemas/src/index";

test("private assessments, observables, search and graphs are invisible to a second tenant", async ({
  workspace,
}) => {
  const foreign = await createWorkspace({ seeded: false });
  const a = await json<Assessment>(
    await request(workspace, "/v1/assess", {
      method: "POST",
      body: JSON.stringify({ observable: "private-customer.synthetic.test" }),
    }),
  );
  for (const path of [
    `/v1/assessments/${a.assessment_id}`,
    `/v1/assessments/${a.assessment_id}/stix`,
    `/v1/observables/${a.observable.id}`,
    `/v1/graph/${a.observable.id}`,
    `/v1/entities/${a.observable.id}`,
  ])
    expect((await request(foreign, path)).status).toBe(404);
  const results = await json<{ data: unknown[] }>(
    await request(foreign, "/v1/search?q=private-customer"),
  );
  expect(results.data).toHaveLength(0);
  const response = await request(
    foreign,
    `/v1/assessments/${a.assessment_id}/confirm`,
    {
      method: "POST",
      body: JSON.stringify({ reason: "Unauthorized foreign change" }),
    },
  );
  expect(response.status).toBe(404);
  expect(
    (
      await json<Assessment>(
        await request(workspace, "/v1/assessments/" + a.assessment_id),
      )
    ).status,
  ).toBe("pending");
});
test("bulk job IDs do not grant another tenant access or replay privileges", async ({
  workspace,
}) => {
  const foreign = await createWorkspace();
  const job = await json<{ job_id: string }>(
    await request(workspace, "/v1/assess/bulk", {
      method: "POST",
      body: JSON.stringify({ observables: ["private-job.synthetic.test"] }),
    }),
  );
  expect((await request(foreign, "/v1/jobs/" + job.job_id)).status).toBe(404);
  expect(
    (
      await request(foreign, "/v1/jobs/" + job.job_id + "/replay", {
        method: "POST",
      })
    ).status,
  ).toBe(404);
});
test("customer observation content is excluded from other tenants and public STIX", async ({
  workspace,
}) => {
  const foreign = await createWorkspace();
  const marker = "PRIVATE-DEVICE-" + crypto.randomUUID();
  const observable = "shared-observation.synthetic.test";
  expect(
    (
      await request(workspace, "/v1/observations", {
        method: "POST",
        body: JSON.stringify({
          observable: { observable },
          evidence: {
            type: "telemetry",
            data: {
              device: marker,
              description: "Synthetic private observation",
            },
            confidence: 0.8,
            behavioural: false,
          },
          sharingAllowed: false,
        }),
      })
    ).status,
  ).toBe(201);
  const own = await json<Assessment>(
    await request(workspace, "/v1/assess", {
      method: "POST",
      body: JSON.stringify({ observable }),
    }),
  );
  expect(JSON.stringify(own.evidence)).toContain(marker);
  const other = await json<Assessment>(
    await request(foreign, "/v1/assess", {
      method: "POST",
      body: JSON.stringify({ observable }),
    }),
  );
  expect(JSON.stringify(other)).not.toContain(marker);
  const stix = await (
    await request(workspace, "/v1/assessments/" + own.assessment_id + "/stix")
  ).text();
  expect(stix).not.toContain(marker);
});
test("SQL-shaped search input cannot broaden results or damage the database", async ({
  workspace,
}) => {
  const attack = "' OR 1=1; DROP TABLE assessments; --";
  const result = await request(
    workspace,
    "/v1/search?q=" + encodeURIComponent(attack),
  );
  expect(result.status).toBe(200);
  expect((await json<{ data: unknown[] }>(result)).data).toHaveLength(0);
  expect(
    (
      await json<{ data: unknown[] }>(
        await request(workspace, "/v1/assessments"),
      )
    ).data,
  ).toHaveLength(6);
});
test("analyst comments render adversarial markup as text without executing it", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace);
  const payload = '<img src=x onerror="document.body.dataset.compromised=1">';
  await login(browser, workspace);
  await browser.goto("/investigations/" + a.assessment_id);
  await screen.getByRole("button", "Modify classification").click();
  await screen.getByLabel("Classification").selectOption({ value: "unknown" });
  await screen.getByLabel("Reason").fill(payload);
  await screen.getByRole("button", "Save decision").click();
  await expect(
    screen.getByText("Analyst decision saved with an audit record."),
  ).toBeVisible();
  await browser.reload();
  await expect(screen.getByText(payload)).toBeVisible();
  expect(
    await browser.evaluate(() => document.body.dataset.compromised ?? null),
  ).toBe(null);
});
test("invented ATT&CK and actor overrides are rejected rather than becoming intelligence", async ({
  workspace,
}) => {
  for (const field of ["attack", "actors"]) {
    const response = await request(
      workspace,
      `/v1/assessments/${beacon(workspace).assessment_id}/modify`,
      {
        method: "POST",
        body: JSON.stringify({
          field,
          value: ["invented-entity"],
          reason: "Unsupported synthetic attribution",
        }),
      },
    );
    expect(response.status).toBe(422);
  }
});
