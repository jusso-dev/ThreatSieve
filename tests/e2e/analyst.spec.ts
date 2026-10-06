import { test, expect } from "@playwright/test";
test("analyst can investigate evidence, inspect the graph, filter and export", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Threat operations" }),
  ).toBeVisible();
  await expect(page.getByText("Demonstration workspace.")).toBeVisible();
  await page
    .getByRole("button", { name: "All intelligence", exact: true })
    .click();
  await expect(
    page.getByRole("link", {
      name: "Investigate beacon.demo.example",
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Investigate beacon.demo.example", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "beacon.demo.example", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Evidence & provenance" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Potential actor associations" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "malware DemoRAT" }).click();
  await expect(
    page.getByText(/Synthetic malware entity used solely/),
  ).toBeVisible();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await page
    .getByLabel("Reason", { exact: true })
    .fill("Validated synthetic scenario evidence in browser test.");
  await page.getByRole("button", { name: "Save decision" }).click();
  await expect(
    page.getByText("Analyst decision saved with an audit record."),
  ).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export STIX" }).click();
  expect((await download).suggestedFilename()).toContain(".stix.json");
  await page.screenshot({
    path: "artifacts/investigation.png",
    fullPage: true,
  });
});
test("source operations, inventory and responsive workspace render", async ({
  page,
}) => {
  await page.goto("/sources");
  await expect(
    page.getByRole("heading", { name: "Intelligence sources", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("cell").filter({ hasText: "ThreatFox" }).first(),
  ).toBeVisible();
  await page.goto("/inventory");
  await expect(page.getByLabel("Technologies", { exact: true })).toHaveValue(
    /FortiGate/,
  );
  await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await page.screenshot({
    path: "artifacts/operations-desktop.png",
    animations: "disabled",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: "artifacts/operations-mobile.png",
    animations: "disabled",
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("link", { name: "Bulk analysis" }).click();
  await expect(
    page.getByRole("heading", { name: "Bulk analysis" }),
  ).toBeVisible();
});

test("dialogs contain keyboard focus and restore it, and the sidebar rail spans the full document", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  const rail = await page.locator(".app-shell").evaluate((element) => ({
    height: element.getBoundingClientRect().height,
    pageHeight: document.documentElement.scrollHeight,
    color: getComputedStyle(element).backgroundColor,
  }));
  expect(Math.abs(rail.height - rail.pageHeight)).toBeLessThan(1);
  expect(rail.color).toBe("rgb(23, 35, 34)");
  const launch = page.getByRole("button", {
    name: "Assess observable",
    exact: true,
  });
  await launch.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Tab");
    expect(
      await page.evaluate(() => !!document.activeElement?.closest("dialog")),
    ).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(launch).toBeFocused();
  await page.setViewportSize({ width: 390, height: 600 });
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await expect(
    page.getByRole("dialog", { name: "Workspace navigation" }),
  ).toBeVisible();
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press("Tab");
    expect(
      await page.evaluate(() => !!document.activeElement?.closest(".sidebar")),
    ).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "Toggle navigation" }),
  ).toBeFocused();
});
test("needs-investigation feedback remains in attention and review queues", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", { name: "All intelligence", exact: true })
    .click();
  await page
    .getByRole("link", { name: "Investigate beacon.demo.example", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Needs investigation", exact: true })
    .click();
  await page
    .getByLabel("Reason", { exact: true })
    .fill("This synthetic investigation remains unresolved.");
  await page.getByRole("button", { name: "Save decision" }).click();
  await expect(
    page.getByText("Analyst decision saved with an audit record."),
  ).toBeVisible();
  await page.goto("/");
  await expect(
    page.getByRole("link", {
      name: "Investigate beacon.demo.example",
      exact: true,
    }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Needs review", exact: true }).click();
  await expect(
    page.getByRole("link", {
      name: "Investigate beacon.demo.example",
      exact: true,
    }),
  ).toBeVisible();
});
test("search reports failed assessments and selecting a known entity does not invoke classification", async ({
  page,
}) => {
  let classifications = 0;
  await page.route("**/api/v1/assess", (route) => {
    classifications++;
    return route.fulfill({
      status: 503,
      json: { error: { message: "Classifier unavailable for test" } },
    });
  });
  await page.goto("/");
  const search = page.getByRole("textbox", { name: "Search intelligence" });
  await search.fill("unavailable.example");
  await search.press("Enter");
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "ThreatSieve is temporarily unavailable" }),
  ).toBeVisible();
  expect(classifications).toBe(1);
  await search.fill("DemoRAT");
  await page.getByRole("button", { name: /DemoRAT malware/ }).click();
  await expect(
    page.getByRole("heading", { name: "DemoRAT", exact: true }),
  ).toBeVisible();
  expect(classifications).toBe(1);
});
test("bulk retries reuse an idempotency key and terminal progress stops polling", async ({
  page,
}) => {
  await page.clock.install();
  const keys: string[] = [];
  let polls = 0;
  await page.route("**/api/v1/uploads?*", (route) => {
    keys.push(route.request().headers()["idempotency-key"]!);
    if (keys.length === 1) return route.abort("failed");
    return route.fulfill({ status: 202, json: { job_id: "test-bulk-job" } });
  });
  await page.route("**/api/v1/jobs/test-bulk-job", (route) => {
    polls++;
    return route.fulfill({
      json: {
        id: "test-bulk-job",
        status: "complete",
        pipeline_status: "complete",
        totals: { processed: 2, rejected: 0 },
        result: null,
        stages: [{ stage: "classify", status: "complete", count: 2 }],
      },
    });
  });
  await page.goto("/bulk");
  await page
    .getByLabel("Indicators to analyse")
    .fill("one.example\ntwo.example");
  await page
    .getByRole("button", { name: "Analyse indicators", exact: true })
    .click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Check your connection and try again." }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Analyse indicators", exact: true })
    .click();
  await expect(page.getByRole("status")).toHaveText("Analysis complete");
  expect(keys).toHaveLength(2);
  expect(keys[0]).toBeTruthy();
  expect(keys[1]).toBe(keys[0]);
  await page.clock.fastForward(15000);
  expect(polls).toBe(1);
});

test("stale analyst edits show the conflict inside the dialog and offer a reload", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", { name: "All intelligence", exact: true })
    .click();
  await page
    .getByRole("link", { name: "Investigate beacon.demo.example", exact: true })
    .click();
  await page.route("**/api/v1/assessments/*/confirm", async (route) => {
    expect(route.request().postDataJSON().expected_revision).toBeGreaterThan(0);
    await route.fulfill({
      status: 409,
      json: {
        error: {
          code: "ASSESSMENT_CHANGED",
          message:
            "Another analyst updated this assessment. Refresh before saving your decision.",
        },
      },
    });
  });
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Reason", { exact: true })
    .fill("Validating concurrent analyst feedback");
  await dialog.getByRole("button", { name: "Save decision" }).click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Another analyst updated",
  );
  await expect(dialog.getByLabel("Reason", { exact: true })).toHaveValue(
    "Validating concurrent analyst feedback",
  );
  await dialog.getByRole("button", { name: "Reload assessment" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(
    page.getByRole("heading", { name: "beacon.demo.example", exact: true }),
  ).toBeVisible();
});

test("search waits for workspace permissions before accepting input", async ({
  page,
}) => {
  let release!: () => void;
  const permissionDelay = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/me", async (route) => {
    await permissionDelay;
    await route.continue();
  });
  try {
    await page.goto("/");
    const search = page.getByRole("textbox", { name: "Search intelligence" });
    await expect(search).toBeDisabled();
    release();
    await expect(search).toBeEnabled();
    await search.fill("DemoRAT");
    await expect(
      page.getByRole("button", { name: /DemoRAT malware/ }),
    ).toBeVisible();
  } finally {
    release();
  }
});
