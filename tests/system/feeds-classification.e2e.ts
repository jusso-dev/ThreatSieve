import {
  signedIn as test,
  expect,
  request,
  json,
  control,
} from "./support/fixtures";
import { feedDomain } from "./support/upstreams";
import type { Assessment, IntelEntity } from "../../packages/schemas/src/index";
interface Source {
  id: string;
  status: string;
  records_processed: number;
  last_sync: string | null;
  last_error: string | null;
}
async function sync(w: Parameters<typeof request>[0], id: string) {
  const response = await request(w, "/v1/feeds/" + id + "/sync", {
    method: "POST",
  });
  expect(response.status).toBe(202);
  const { job_id } = await json<{ job_id: string }>(response);
  await expect
    .poll(
      async () =>
        (
          (await control("feed-state", { sourceId: id, jobId: job_id })) as {
            finalized: boolean;
          }
        ).finalized,
      { timeout: 30000 },
    )
    .toBe(true);
  const responseState = await request(w, "/v1/feeds");
  expect(responseState.status).toBe(200);
  const feeds = await json<{ data: Source[] }>(responseState);
  const source = feeds.data.find((f) => f.id === id)!;
  expect(source.status, `${id}: ${source.last_error ?? "sync completed"}`).toBe(
    "healthy",
  );
}
test("six bundled feeds sync through queues, archive provenance and resolve canonical aliases", async ({
  browser,
  screen,
  workspace,
}) => {
  for (const id of [
    "mitre",
    "misp",
    "threatfox",
    "urlhaus",
    "feodo",
    "cisa-kev",
  ]) {
    await sync(workspace, id);
    const state = (await control("feed-state", { sourceId: id })) as {
      checkpoint: unknown;
      evidence: unknown[];
      provenance: unknown[];
      archive: string[];
    };
    expect(state.checkpoint).toBeTruthy();
    expect(
      state.evidence.length + state.provenance.length,
      id + " must retain provenance",
    ).toBeGreaterThan(0);
    expect(state.archive.length).toBeGreaterThan(0);
  }
  const alias = await json<{ data: IntelEntity[] }>(
    await request(workspace, "/v1/search?q=Synthetic%20Alias"),
  );
  expect(alias.data.filter((e) => e.type === "threat-actor")).toHaveLength(1);
  expect(alias.data[0]!.name).toBe("Synthetic E2E Actor");
  expect(alias.data[0]!.aliases).toContain("Synthetic Alias");
  await browser.goto("/sources");
  await expect(
    screen.getByRole("heading", "Intelligence sources"),
  ).toBeVisible();
  await expect(
    screen.getByRole("row").filter({ hasText: "ThreatFox" }),
  ).toContainText("healthy");
});
test("ThreatFox to ATT&CK candidates to classification preserves full model provenance and caches unchanged evidence", async ({
  browser,
  screen,
  workspace,
}) => {
  await sync(workspace, "mitre");
  await sync(workspace, "threatfox");
  const before = (await control("feed-state", { sourceId: "threatfox" })) as {
    evidence: unknown[];
  };
  await sync(workspace, "threatfox");
  const after = (await control("feed-state", { sourceId: "threatfox" })) as {
    evidence: unknown[];
  };
  expect(after.evidence.length).toBe(before.evidence.length);
  const response = await request(workspace, "/v1/assess", {
    method: "POST",
    body: JSON.stringify({ observable: feedDomain }),
  });
  expect(response.status).toBe(200);
  const a = await json<Assessment>(response);
  expect(a.sources.some((s) => s.sourceId === "threatfox")).toBe(true);
  expect(a.runs.length).toBeGreaterThan(0);
  expect(a.runs[0]!.model).toBe("@cf/cloudflare/clef-flash");
  expect(a.runs[0]!.modelVersion).toBe("synthetic-e2e-v1");
  expect(a.runs[0]!.candidateSet.some((c) => c.externalId === "T1059")).toBe(
    true,
  );
  expect(a.actors).toHaveLength(0);
  // A malware association creates candidates, not observed shell behaviour.
  expect(a.attack).toHaveLength(0);
  const raw = a.runs[0]!.raw as {
    answers: { role: { probabilities: Record<string, number> } };
  };
  expect(Object.keys(raw.answers.role.probabilities).length).toBeGreaterThan(5);
  const repeated = await json<Assessment>(
    await request(workspace, "/v1/assess", {
      method: "POST",
      body: JSON.stringify({ observable: feedDomain.toUpperCase() }),
    }),
  );
  expect(repeated.assessment_id).toBe(a.assessment_id);
  expect(repeated.runs).toEqual(a.runs);
  await browser.goto("/investigations/" + a.assessment_id);
  await expect(screen.getByRole("heading", feedDomain)).toBeVisible();
  await expect(screen.getByText("ThreatFox", { exact: true })).toBeVisible();
});
test("disabled optional sources explain their status and reject sync attempts", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/sources");
  for (const name of ["OTX", "VirusTotal", "GreyNoise"])
    await expect(
      screen.getByRole("row").filter({ hasText: name }),
    ).toContainText("Disabled");
  expect(
    (await request(workspace, "/v1/feeds/virustotal/sync", { method: "POST" }))
      .status,
  ).toBe(409);
});
test("classifier outage fails safely without publishing an assessment", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/");
  await screen.getByRole("button", "Assess observable").click();
  await screen
    .getByLabel("IP, domain, URL, hash or CVE")
    .fill("classifier-failure.synthetic.test");
  await screen.getByRole("button", "Run assessment").click();
  await expect(screen.getByRole("dialog").getByRole("alert")).toBeVisible();
  const list = await json<{ data: Assessment[] }>(
    await request(
      workspace,
      "/v1/assessments?q=classifier-failure.synthetic.test",
    ),
  );
  expect(list.data).toHaveLength(0);
  await expect(screen.getByRole("dialog")).toBeVisible();
});
