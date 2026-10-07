import {
  signedIn as test,
  expect,
  request,
  json,
  workspace as otherWorkspace,
  beacon,
} from "./support/fixtures";
import type { WorkObject } from "../../packages/schemas/src/enterprise";
import { copyFileSync, readdirSync } from "node:fs";
async function create(
  w: Parameters<typeof request>[0],
  path: string,
  body: unknown,
) {
  const res = await request(w, "/v1/" + path, {
    method: "POST",
    body: JSON.stringify(body),
  });
  expect(res.status, await res.clone().text()).toBe(201);
  return json<WorkObject>(res);
}
function capture(relative: string, name: string) {
  const source = readdirSync(".e2e/artifacts", { recursive: true }).find(
    (p) => typeof p === "string" && p.endsWith("/" + relative),
  );
  if (!source) throw new Error("Screenshot missing");
  copyFileSync(".e2e/artifacts/" + source, "docs/images/" + name + ".png");
}
test("analysts create investigations, preserve drafts, record decisions and complete tasks", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/cases?new=1");
  await expect(screen.getByRole("dialog")).toBeVisible();
  await screen
    .getByLabel("Title", { exact: true })
    .fill("Demo suspicious infrastructure investigation");
  await screen
    .getByLabel("Working hypothesis")
    .fill(
      "A shared payload may explain the observations; attribution remains unknown.",
    );
  await screen
    .getByRole("button", "Save investigation", { exact: true })
    .click();
  await expect(
    screen.getByRole("heading", "Demo suspicious infrastructure investigation"),
  ).toBeVisible();
  await screen
    .getByLabel("New investigation task")
    .fill("Check independent behavioural evidence");
  await screen.getByRole("button", "Add task", { exact: true }).click();
  await screen.getByLabel("Check independent behavioural evidence").check();
  await screen.getByLabel("Entry type").selectOption({ value: "decision" });
  await screen
    .getByLabel("Reasoning and evidence")
    .fill(
      "Do not attribute this to an actor without behavioural corroboration.",
    );
  await screen.getByRole("button", "Record decision").click();
  await expect(
    screen.getByText(
      "Do not attribute this to an actor without behavioural corroboration.",
      { exact: true },
    ),
  ).toBeVisible();
  await browser.reload();
  await expect(
    screen.getByLabel("Check independent behavioural evidence"),
  ).toBeChecked();
  const list = await json<{ data: WorkObject[] }>(
    await request(workspace, "/v1/investigations"),
  );
  expect(list.data[0]!.kind).toBe("investigation");
});
test("PIR coverage is evidence-linked and scoped; matches remain suggestions", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace);
  const requirement = await create(workspace, "requirements", {
    title: "Demo C2 coverage requirement",
    question: "Which observed domains have supporting C2 evidence?",
    criteria: { entityTypes: ["observable"], keywords: ["beacon"] },
    references: [
      { type: "assessment", id: a.assessment_id, relation: "supports" },
    ],
  });
  const foreign = await otherWorkspace({ seeded: false });
  expect(
    (await request(foreign, "/v1/requirements/" + requirement.id)).status,
  ).toBe(404);
  const detail = await json<{
    metrics: { coverage: number; evidenceCount: number };
  }>(await request(workspace, "/v1/requirements/" + requirement.id));
  expect(detail.metrics.coverage).toBe(100);
  expect(detail.metrics.evidenceCount).toBeGreaterThan(0);
  await browser.goto("/requirements/" + requirement.id);
  await expect(
    screen.getByRole("heading", "Matching intelligence"),
  ).toBeVisible();
  await expect(screen.getByRole("heading", "Intelligence gaps")).toBeVisible();
});
test("workspace edits require revisions and exports cannot cross tenant boundaries", async ({
  workspace,
}) => {
  const foreign = await otherWorkspace({ seeded: false });
  for (const [path, kind] of [
    ["requirements", "requirement"],
    ["investigations", "investigation"],
    ["watchlists", "watchlist"],
    ["collections", "collection"],
    ["reports", "report"],
    ["playbooks", "playbook"],
  ]) {
    const o = await create(workspace, path!, {
      title: "Demo isolated " + kind,
      question: "What evidence exists?",
      trigger: "sighting.created",
      actions: [{ type: "notify" }],
    });
    expect((await request(foreign, "/v1/" + path + "/" + o.id)).status).toBe(
      404,
    );
    const update = {
      object: { ...o, title: o.title + " revised" },
      expected_revision: o.revision,
      reason: "Analyst corrected title",
    };
    expect(
      (
        await request(workspace, "/v1/" + path + "/" + o.id, {
          method: "PUT",
          body: JSON.stringify(update),
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(workspace, "/v1/" + path + "/" + o.id, {
          method: "PUT",
          body: JSON.stringify(update),
        })
      ).status,
    ).toBe(409);
    if (kind !== "playbook")
      expect(
        (
          await request(
            foreign,
            "/v1/" + path + "/" + o.id + "/export?format=json",
          )
        ).status,
      ).toBe(404);
  }
  expect(
    (
      await request(workspace, "/v1/reports", {
        method: "POST",
        body: JSON.stringify({ title: "oversized", body: "x".repeat(140000) }),
      })
    ).status,
  ).toBe(413);
});
test("private sightings are idempotent, do not imply maliciousness and trigger watchlist notifications", async ({
  browser,
  screen,
  workspace,
}) => {
  const value = "sighting-" + crypto.randomUUID() + ".test";
  const watch = await create(workspace, "watchlists", {
    title: "Demo customer sightings",
    criteria: { keywords: [value] },
    triggers: ["sighting.created"],
  });
  const body = {
    observable: { observable: value },
    observedAt: new Date().toISOString(),
    source: "dns",
    externalId: "event-1",
    context: "Customer DNS observation",
    count: 3,
  };
  const response = await request(workspace, "/v1/sightings", {
    method: "POST",
    body: JSON.stringify(body),
  });
  expect(response.status).toBe(201);
  const sighting = await json<{ id: string; observableId: string }>(response);
  const retry = await json<{ id: string }>(
    await request(workspace, "/v1/sightings", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  );
  expect(retry.id).toBe(sighting.id);
  const dossier = await json<{ scores: { threat: { value: number | null } } }>(
    await request(
      workspace,
      "/v1/entities/" + sighting.observableId + "/dossier",
    ),
  );
  expect(dossier.scores.threat.value).toBe(null);
  await expect
    .poll(
      async () => {
        const n = await json<{ data: { object_id: string }[] }>(
          await request(workspace, "/v1/notifications"),
        );
        return n.data.some((n) => n.object_id === watch.id);
      },
      { timeout: 30000 },
    )
    .toBe(true);
  await browser.goto("/sightings");
  await expect(screen.getByRole("link", value, { exact: true })).toBeVisible();
  await screen.getByRole("button", "Open intelligence notifications").click();
  await expect(
    screen.getByRole("heading", "Intelligence notifications"),
  ).toBeVisible();
  await expect(
    screen.getByRole("link", /^Demo customer sightings:/),
  ).toBeVisible();
});
test("workspace tags persist and stay private across tenants", async ({
  browser,
  screen,
  workspace,
}) => {
  const a = beacon(workspace),
    id = a.observable.id;
  await browser.goto("/intelligence/" + id);
  await screen.getByLabel("Add workspace tag").fill("priority-hunt");
  await screen.getByRole("button", "Add tag", { exact: true }).click();
  await expect(
    screen.getByRole("button", "Remove tag priority-hunt"),
  ).toBeVisible();
  await browser.reload();
  await expect(
    screen.getByRole("button", "Remove tag priority-hunt"),
  ).toBeVisible();
  const foreign = await otherWorkspace({ seeded: false });
  const d = await json<{ workspaceTags: string[] }>(
    await request(foreign, "/v1/entities/" + id + "/dossier"),
  );
  expect(d.workspaceTags).not.toContain("priority-hunt");
  await screen.getByRole("button", "Remove tag priority-hunt").click();
  await expect(
    screen.getByRole("button", "Remove tag priority-hunt"),
  ).not.toBeVisible();
});
test("TAXII snapshots support authenticated discovery, manifests, pagination and isolation", async ({
  workspace,
}) => {
  const ids = workspace.assessments.slice(0, 3).map((a) => ({
    type: "assessment",
    id: a.assessment_id,
    relation: "member",
  }));
  const collection = await create(workspace, "collections", {
    title: "Demo published collection",
    status: "published",
    publication: "taxii",
    references: ids,
  });
  const pub = await request(
    workspace,
    "/v1/collections/" + collection.id + "/publish",
    { method: "POST" },
  );
  expect(pub.status, await pub.clone().text()).toBe(200);
  const get = (path: string) =>
    request(workspace, path, {
      headers: { Accept: "application/taxii+json;version=2.1" },
    });
  expect((await get("/v1/taxii/")).status).toBe(200);
  const path = "/v1/taxii/api/collections/" + collection.id + "/";
  expect((await get(path + "objects/?next=not-base64!")).status).toBe(400);
  const first = await get(path + "objects/?limit=1");
  expect(first.headers.get("content-type")).toContain("application/taxii+json");
  const page = await json<{
    objects: { id: string }[];
    more: boolean;
    next: string;
  }>(first);
  expect(page.objects).toHaveLength(1);
  expect(page.more).toBe(true);
  const second = await json<{ objects: { id: string }[] }>(
    await get(path + "objects/?limit=1&next=" + encodeURIComponent(page.next)),
  );
  expect(second.objects[0]!.id).not.toBe(page.objects[0]!.id);
  const manifest = await json<{
    objects: { id: string; date_added: string }[];
  }>(await get(path + "manifest/?limit=1"));
  expect(manifest.objects[0]!.date_added).toBeTruthy();
  const foreign = await otherWorkspace({ seeded: false });
  expect(
    (
      await request(foreign, path + "objects/", {
        headers: { Accept: "application/taxii+json;version=2.1" },
      })
    ).status,
  ).toBe(404);
  expect(
    (
      await request(workspace, path + "objects/", {
        method: "POST",
        body: "{}",
      })
    ).status,
  ).toBe(405);
});
test("report HTML escapes hostile content and MISP exports preserve review semantics", async ({
  workspace,
}) => {
  const report = await create(workspace, "reports", {
    title: "Demo authored brief",
    body: '<script>alert("unsafe")</script> Evidence remains uncertain.',
    status: "published",
    references: [{ type: "assessment", id: beacon(workspace).assessment_id }],
  });
  const html = await request(
    workspace,
    "/v1/reports/" + report.id + "/export?format=html",
  );
  const body = await html.text();
  expect(body).not.toContain("<script>");
  expect(body).toContain("&lt;script&gt;");
  expect(html.headers.get("content-security-policy")).toContain(
    "default-src 'none'",
  );
  const misp = await json<{ Event: { Attribute: { to_ids: boolean }[] } }>(
    await request(
      workspace,
      "/v1/reports/" + report.id + "/export?format=misp",
    ),
  );
  expect(misp.Event.Attribute.length).toBeGreaterThan(0);
  expect(misp.Event.Attribute.every((a) => a.to_ids === false)).toBe(true);
});
test("command palette opens with keyboard and routes to a real requirement form", async ({
  browser,
  screen,
}) => {
  await browser.goto("/");
  // Navigation can finish before React installs the global keyboard listener.
  // This control becomes enabled only after the hydrated workspace loads access.
  await expect(
    screen.getByLabel("Search intelligence", { exact: true }),
  ).toBeEnabled();
  await browser.keyboard.press("Control+k");
  await expect(screen.getByRole("heading", "Search & commands")).toBeVisible();
  await screen
    .getByLabel("Search all intelligence and commands")
    .fill("Create requirement");
  await screen.getByRole("option", /Create requirement/).click();
  await expect(
    screen.getByRole("heading", "New requirement", { exact: true }),
  ).toBeVisible();
  await browser.keyboard.press("Escape");
  await expect(screen.getByRole("dialog")).not.toBeVisible();
});
test("viewer cannot create workspace objects, sightings, source policies or playbooks", async ({
  workspace,
}) => {
  const viewer = await otherWorkspace({
    scopes: ["intel:read", "assessment:read", "feeds:read"],
    seeded: false,
  });
  for (const [path, body] of [
    ["investigations", { title: "unauthorized" }],
    ["sightings", {}],
    ["playbooks", {}],
  ])
    expect(
      (
        await request(viewer, "/v1/" + path, {
          method: "POST",
          body: JSON.stringify(body),
        })
      ).status,
    ).toBe(403);
  expect(
    (
      await request(viewer, "/v1/feeds/mitre/policy", {
        method: "PUT",
        body: JSON.stringify({
          enabled: false,
          reason: "Unauthorized policy change",
        }),
      })
    ).status,
  ).toBe(403);
  expect((await request(workspace, "/v1/feeds/mitre/quality")).status).toBe(
    200,
  );
});
test("enterprise workspaces, dossier, graph and source console render without mobile overflow", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  const a = beacon(workspace);
  const requirement = await create(workspace, "requirements", {
    title: "Demo exploited technology coverage",
    question: "Which observed threats affect our exposed technologies?",
    priority: "high",
    criteria: { keywords: ["beacon"] },
    references: [
      { type: "assessment", id: a.assessment_id, relation: "supports" },
    ],
  });
  const investigation = await create(workspace, "investigations", {
    title: "Demo infrastructure investigation",
    hypothesis:
      "Shared infrastructure requires independent corroboration before attribution.",
    priority: "high",
    references: [
      { type: "entity", id: a.observable.id, relation: "investigates" },
    ],
    tasks: [{ id: "triage", title: "Validate source provenance", done: false }],
  });
  await create(workspace, "watchlists", {
    title: "Demo infrastructure watch",
    criteria: { keywords: ["beacon"] },
  });
  await create(workspace, "collections", {
    title: "Demo October intelligence package",
    references: [{ type: "assessment", id: a.assessment_id }],
  });
  const report = await create(workspace, "reports", {
    title: "Demo operational threat brief",
    body: "Observed infrastructure warrants review. Current evidence does not support actor attribution.\n\nRecommended next step: validate customer observations against the source evidence.",
    references: [{ type: "assessment", id: a.assessment_id }],
  });
  await create(workspace, "playbooks", {
    title: "Demo sighting notification",
    status: "paused",
    trigger: "sighting.created",
    actions: [{ type: "notify" }],
  });
  for (const [path, heading, name] of [
    ["/requirements", "Intelligence requirements", "requirements"],
    [
      "/requirements/" + requirement.id,
      requirement.title,
      "requirement-detail",
    ],
    [
      "/cases/" + investigation.id,
      investigation.title,
      "analyst-investigation",
    ],
    ["/watchlists", "Watchlists", "watchlists"],
    ["/collections", "Collections", "collections"],
    ["/reports/" + report.id, report.title, "intelligence-report"],
    ["/automations", "Automation", "automation"],
    [
      "/intelligence/" + a.observable.id,
      a.observable.normalizedValue,
      "entity-dossier",
    ],
    ["/sources/mitre", "MITRE ATT&CK", "source-operations"],
    ["/system", "System health", "system-health"],
  ]) {
    await browser.setViewport({ width: 1440, height: 1000 });
    await browser.goto(path!);
    await expect(
      screen.getByRole("heading", heading!, { exact: true }),
    ).toBeVisible();
    if (process.env.UPDATE_SCREENSHOTS === "1")
      capture(await app.screenshot(name!), name!);
    await browser.setViewport({ width: 390, height: 844 });
    expect(
      await browser.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  }
});

test("system health reports unavailable integrations honestly and refreshes", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/system");
  await expect(
    screen.getByRole("heading", "System health", { exact: true }),
  ).toBeVisible();
  await expect(
    screen.getByText(
      "No connector heartbeat is registered. Connection health has not been verified.",
    ),
  ).toBeVisible();
  await screen.getByRole("button", "Refresh health").click();
  await expect(
    screen.getByRole("heading", "Pipeline jobs", { exact: true }),
  ).toBeVisible();
  const response = await request(workspace, "/v1/ops/status");
  expect(response.status).toBe(200);
  const report = await json<{
    alerts: { code: string }[];
    integrations: unknown[];
  }>(response);
  expect(report.integrations).toHaveLength(0);
  expect(report.alerts.some((a) => a.code === "SCHEDULER_STALE")).toBe(true);
});

test("analysts prepare queued STIX packages with checksummed downloads", async ({
  browser,
  screen,
  workspace,
  app,
}) => {
  const collection = await create(workspace, "collections", {
    title: "Demo analyst export package",
    references: [
      {
        type: "assessment",
        id: workspace.assessments[0]!.assessment_id,
        relation: "member",
      },
    ],
  });
  await browser.goto("/collections/" + collection.id);
  await screen
    .getByRole("button", "Prepare STIX package", { exact: true })
    .click();
  await expect(
    screen.getByRole("button", "Download manifest", { exact: true }),
  ).toBeVisible({ timeout: 30000 });
  await expect(
    screen.getByRole("button", "Download part 1", { exact: false }),
  ).toBeVisible();
  const manifest = await browser.evaluate(async () => {
    const response = await fetch(
      location.origin +
        "/api/v1/collections/" +
        location.pathname.split("/").at(-1) +
        "/packages",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: crypto.randomUUID() }),
      },
    );
    return {
      status: response.status,
      body: (await response.json()) as { id: string },
    };
  });
  expect(manifest.status).toBe(202);
  const foreign = await otherWorkspace({ seeded: false });
  expect(
    (await request(foreign, "/v1/collection-packages/" + manifest.body.id))
      .status,
  ).toBe(404);
  if (process.env.UPDATE_SCREENSHOTS === "1")
    capture(await app.screenshot("collection-export"), "collection-export");
});
