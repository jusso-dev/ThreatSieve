import {
  signedIn as test,
  expect,
  request,
  json,
  beacon,
  workspace as createWorkspace,
} from "./support/fixtures";
import type { Assessment, IntelEntity } from "../../packages/schemas/src/index";
import { copyFileSync, readdirSync } from "node:fs";

function capture(relative: string, target: string) {
  const source = readdirSync(".e2e/artifacts", { recursive: true }).find(
    (p) => typeof p === "string" && p.endsWith("/" + relative),
  );
  if (!source) throw new Error("Screenshot missing");
  copyFileSync(".e2e/artifacts/" + source, "docs/images/" + target + ".png");
}

test("library filters, alias search and entity pivots use persisted intelligence", async ({
  browser,
  screen,
}) => {
  await browser.goto("/intelligence");
  await screen.getByRole("button", "Malware", { exact: true }).click();
  await expect(
    screen.getByRole("link", "DemoRAT", { exact: true }),
  ).toBeVisible();
  await screen.getByLabel("Search library").fill("DemoRAT");
  await screen.getByRole("link", "DemoRAT", { exact: true }).click();
  await expect(screen.getByRole("heading", "DemoRAT")).toBeVisible();
  await expect(screen.getByRole("heading", "Source provenance")).toBeVisible();
  await screen
    .getByRole("link", "Intelligence library", { exact: true })
    .last()
    .click();
  await expect(
    screen.getByRole("heading", "Explore the intelligence."),
  ).toBeVisible();
});
test("triage filters survive reload and sort across all server results", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/?view=all&classification=benign&sort=confidence");
  await expect(screen.getByLabel("Decision")).toHaveValue("benign");
  const result = await json<{ data: Assessment[] }>(
    await request(
      workspace,
      "/v1/assessments?classification=benign&sort=confidence",
    ),
  );
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(
    result.data.length,
  );
  await browser.reload();
  await expect(screen.getByLabel("Decision")).toHaveValue("benign");
  await screen.getByLabel("Decision").selectOption({ value: "malicious" });
  const malicious = await json<{ data: Assessment[] }>(
    await request(workspace, "/v1/assessments?classification=malicious"),
  );
  await expect(screen.getByRole("link", /^Investigate /)).toHaveCount(
    malicious.data.length,
  );
});
test("personal saved views persist, apply and can be removed", async ({
  browser,
  screen,
}) => {
  await browser.goto("/?view=all&severity=high&sort=relevance");
  await screen.getByRole("button", "Save view", { exact: true }).click();
  await screen.getByLabel("View name").fill("High priority review");
  await screen.getByRole("button", "Save triage view").click();
  await expect(screen.getByRole("dialog")).not.toBeVisible();
  await browser.goto("/");
  await screen
    .getByLabel("Saved triage views")
    .selectOption("High priority review");
  await expect(screen.getByLabel("Priority", { exact: true })).toHaveValue(
    "high",
  );
  await expect(screen.getByLabel("Sort assessments")).toHaveValue("relevance");
  await screen.getByRole("button", "Delete saved view").click();
  await expect(screen.getByLabel("Saved triage views")).toHaveValue("");
});
test("saved views enforce owner and tenant boundaries and reject unsafe filters", async ({
  workspace,
}) => {
  const foreign = await createWorkspace();
  const response = await request(workspace, "/v1/saved-views", {
    method: "POST",
    body: JSON.stringify({
      name: "Private triage",
      filters: { view: "review", q: "private-marker" },
    }),
  });
  expect(response.status).toBe(201);
  const own = await json<{ data: { id: string }[] }>(
    await request(workspace, "/v1/saved-views"),
  );
  const other = await json<{ data: unknown[] }>(
    await request(foreign, "/v1/saved-views"),
  );
  expect(other.data).toHaveLength(0);
  expect(
    (
      await request(foreign, "/v1/saved-views/" + own.data[0]!.id, {
        method: "DELETE",
      })
    ).status,
  ).toBe(404);
  expect(
    (
      await request(workspace, "/v1/saved-views", {
        method: "POST",
        body: JSON.stringify({
          name: "Invalid",
          filters: { sort: "DROP TABLE entities" },
        }),
      })
    ).status,
  ).toBe(400);
});
test("all sort modes paginate deterministically without duplicate assessments", async ({
  workspace,
}) => {
  for (const sort of ["newest", "oldest", "confidence", "relevance"]) {
    const ids: string[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < 6; page++) {
      const result: { data: Assessment[]; next_cursor: string | null } =
        await json<{
          data: Assessment[];
          next_cursor: string | null;
        }>(
          await request(
            workspace,
            "/v1/assessments?limit=2&sort=" +
              sort +
              (cursor ? "&cursor=" + encodeURIComponent(cursor) : ""),
          ),
        );
      ids.push(...result.data.map((a) => a.assessment_id));
      cursor = result.next_cursor;
      if (!cursor) break;
    }
    expect(ids).toHaveLength(6);
    expect(new Set(ids).size).toBe(6);
  }
  expect(
    (await request(workspace, "/v1/assessments?min_confidence=2")).status,
  ).toBe(400);
  expect((await request(workspace, "/v1/entities?cursor=garbage")).status).toBe(
    400,
  );
});
test("library pagination and literal query filtering preserve visibility", async ({
  workspace,
}) => {
  const foreign = await createWorkspace({ seeded: false });
  const privateName = "library-private-" + crypto.randomUUID() + ".test";
  await request(workspace, "/v1/assess", {
    method: "POST",
    body: JSON.stringify({ observable: privateName }),
  });
  const own = await json<{ data: IntelEntity[] }>(
    await request(workspace, "/v1/entities?q=" + privateName),
  );
  const other = await json<{ data: IntelEntity[] }>(
    await request(foreign, "/v1/entities?q=" + privateName),
  );
  expect(own.data).toHaveLength(1);
  expect(other.data).toHaveLength(0);
  const wild = await json<{ data: IntelEntity[] }>(
    await request(workspace, "/v1/entities?q=%25"),
  );
  expect(wild.data).toHaveLength(0);
  const first = await json<{ data: IntelEntity[]; next_cursor: string }>(
    await request(workspace, "/v1/entities?limit=2"),
  );
  const second = await json<{ data: IntelEntity[] }>(
    await request(
      workspace,
      "/v1/entities?limit=2&cursor=" + encodeURIComponent(first.next_cursor),
    ),
  );
  expect(new Set([...first.data, ...second.data].map((e) => e.id)).size).toBe(
    4,
  );
});
test("evidence filters, timeline and graph relationship list remain usable", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/investigations/" + beacon(workspace).assessment_id);
  await screen.getByRole("button", "Timeline", { exact: true }).click();
  await expect(browser.locator(".evidence-timeline")).toBeVisible();
  await screen.getByLabel("Search evidence").fill("no-such-record");
  await expect(
    screen.getByRole("heading", "No evidence records match these filters"),
  ).toBeVisible();
  await screen.getByRole("button", "Show all evidence").click();
  await expect(browser.locator(".evidence-item")).toHaveCount(
    beacon(workspace).evidence.length,
  );
  await screen
    .getByRole("button", "Relationship list", { exact: true })
    .click();
  const graph = await json<{ edges: unknown[] }>(
    await request(
      workspace,
      "/v1/graph/" + beacon(workspace).observable.id + "?depth=2",
    ),
  );
  await expect(browser.locator(".relationship-row")).toHaveCount(
    graph.edges.length,
  );
  await screen.getByRole("button", "Graph", { exact: true }).click();
  await screen.getByRole("button", "Zoom out").click();
  await expect(screen.getByText("80%", { exact: true })).toBeVisible();
  await screen.getByRole("button", "Reset graph zoom").click();
  await expect(screen.getByText("100%", { exact: true })).toBeVisible();
});
test("source details expose operational context without hiding errors in tooltips", async ({
  browser,
  screen,
}) => {
  await browser.goto("/sources");
  await screen.getByLabel("Find source").fill("ThreatFox");
  await screen.getByRole("button", "ThreatFox", { exact: true }).click();
  await expect(
    screen.getByRole("heading", "ThreatFox · Source details"),
  ).toBeVisible();
  await expect(
    screen.getByText("Records added", { exact: true }),
  ).toBeVisible();
  await expect(
    screen.getByRole("link", "Browse intelligence from this source →"),
  ).toBeVisible();
});
test("keyboard search selects an existing record without creating a classification", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/");
  await screen.getByRole("textbox", "Search intelligence").fill("DemoRAT");
  await expect(screen.getByRole("button", /DemoRAT malware/)).toBeVisible();
  await browser.keyboard.press("ArrowDown");
  await browser.keyboard.press("Enter");
  await expect(screen.getByRole("heading", "DemoRAT")).toBeVisible();
  const list = await json<{ summary: { total: number } }>(
    await request(workspace, "/v1/assessments"),
  );
  expect(list.summary.total).toBe(6);
});
test("workbench desktop and mobile screenshots document live synthetic workflows", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  for (const [path, heading, image] of [
    ["/", "Focus on what matters.", "operations"],
    ["/intelligence", "Explore the intelligence.", "intelligence-library"],
    [
      "/investigations/" + beacon(workspace).assessment_id,
      "beacon.demo.example",
      "investigation",
    ],
    ["/sources", "Intelligence sources", "sources"],
    ["/bulk", "From indicators to intelligence.", "bulk"],
    ["/clusters", "Emerging clusters", "clusters"],
    ["/inventory", "Your environment", "inventory"],
  ]) {
    await browser.setViewport({ width: 1440, height: 1000 });
    await browser.goto(path!);
    await expect(
      screen.getByRole("heading", heading!, { exact: true }),
    ).toBeVisible();
    if (path === "/" || path === "/intelligence" || path === "/sources")
      await expect(screen.getByRole("table")).toBeVisible();
    else if (path!.startsWith("/investigations"))
      await expect(screen.getByRole("button", "malware DemoRAT")).toBeVisible();
    if (process.env.UPDATE_SCREENSHOTS === "1") {
      await browser.setViewport(
        await browser.evaluate(() => ({
          width: 1440,
          height: Math.min(8000, document.documentElement.scrollHeight),
        })),
      );
      capture(await app.screenshot(image!), image!);
    }
  }
  for (const [path, image] of [
    ["/", "operations-mobile"],
    ["/intelligence", "intelligence-library-mobile"],
    [
      "/investigations/" + beacon(workspace).assessment_id,
      "investigation-mobile",
    ],
  ]) {
    await browser.setViewport({ width: 390, height: 844 });
    await browser.goto(path!);
    if (path === "/" || path === "/intelligence")
      await expect(screen.getByRole("table")).toBeVisible();
    else if (path!.startsWith("/investigations"))
      await expect(screen.getByRole("button", "malware DemoRAT")).toBeVisible();
    expect(
      await browser.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    if (process.env.UPDATE_SCREENSHOTS === "1") {
      await browser.setViewport(
        await browser.evaluate(() => ({
          width: 390,
          height: Math.min(10000, document.documentElement.scrollHeight),
        })),
      );
      capture(await app.screenshot(image!), image!);
    }
  }
  if (process.env.UPDATE_SCREENSHOTS === "1") {
    await browser.setViewport({ width: 390, height: 844 });
    await browser.goto("/");
    await screen.getByRole("button", "Toggle navigation").click();
    await expect(
      screen.getByRole("dialog", "Workspace navigation"),
    ).toBeVisible();
    await browser.evaluate(() => {
      document.getAnimations().forEach((a) => a.finish());
      return null;
    });
    capture(await app.screenshot("mobile-navigation"), "mobile-navigation");
  }
});

test("returning to the queue restores the originating filters", async ({
  browser,
  screen,
}) => {
  await browser.goto("/?view=all&q=beacon&sort=confidence");
  await screen.getByRole("link", "Investigate beacon.demo.example").click();
  await expect(
    screen.getByRole("heading", "beacon.demo.example"),
  ).toBeVisible();
  await screen
    .getByRole("link", "Threat operations", { exact: true })
    .last()
    .click();
  await expect(screen.getByLabel("Filter observables")).toHaveValue("beacon");
  await expect(screen.getByLabel("Sort assessments")).toHaveValue("confidence");
});
test("reassessment reports completion and links to the new immutable decision", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/investigations/" + beacon(workspace).assessment_id);
  await screen.getByRole("button", "Reassess", { exact: true }).click();
  await expect(
    screen.getByRole("link", "Open updated assessment →"),
  ).toBeVisible();
  const old = await json<Assessment>(
    await request(
      workspace,
      "/v1/assessments/" + beacon(workspace).assessment_id,
    ),
  );
  expect(old.demo).toBe(true);
  await screen.getByRole("link", "Open updated assessment →").click();
  await expect(
    screen.getByRole("heading", "beacon.demo.example"),
  ).toBeVisible();
  await expect
    .poll(() => browser.evaluate(() => window.location.pathname))
    .not.toBe("/investigations/" + beacon(workspace).assessment_id);
});

test("malformed upstream observation dates cannot crash the evidence view", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = structuredClone(beacon(workspace));
  a.evidence[0]!.observedAt = "upstream-date-unavailable";
  await browser.route(
    "**/api/v1/assessments/" + a.assessment_id,
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(a),
      });
    },
  );
  await browser.goto("/investigations/" + a.assessment_id);
  await screen.getByRole("button", "Timeline", { exact: true }).click();
  await expect(
    browser.locator(".evidence-header").getByText("Time unavailable"),
  ).toBeVisible();
  await expect(
    screen.getByRole("heading", "Original model decision"),
  ).toBeVisible();
});
