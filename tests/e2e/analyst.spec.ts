import { test, expect } from "@playwright/test";
test("analyst can investigate evidence, inspect the graph, filter and export", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Focus on what matters." }),
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
    page.getByRole("heading", { name: "From indicators to intelligence." }),
  ).toBeVisible();
});
