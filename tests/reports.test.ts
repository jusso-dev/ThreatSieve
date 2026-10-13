import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { OperationsRepository } from "../packages/enterprise/src/repository";
import { reportHtml } from "../packages/enterprise/src/export";
import type { Principal } from "../packages/schemas/src/index";
import type { WorkObject } from "../packages/schemas/src/enterprise";

let mf: Miniflare;
let db: D1Database;
let repo: OperationsRepository;

const principal: Principal = {
  tenantId: "reports-a",
  userId: "analyst-r",
  keyId: "r",
  kind: "key",
  scopes: ["admin"],
};

beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  for (const f of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + f, "utf8"),
    ))
      await db.prepare(sql).run();
  const now = new Date().toISOString();
  await db
    .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
    .bind(principal.tenantId, "Reports", now)
    .run();
  await db
    .prepare("INSERT INTO users(id,email,created_at) VALUES(?,?,?)")
    .bind(principal.userId, "analyst-r@example.test", now)
    .run();
  await db
    .prepare(
      "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES(?,?,?)",
    )
    .bind(principal.tenantId, principal.userId, "admin")
    .run();
  repo = new OperationsRepository(db, principal);
});

afterAll(async () => {
  await mf?.dispose();
});

function reportFixture(
  overrides: Partial<Extract<WorkObject, { kind: "report" }>> = {},
): Extract<WorkObject, { kind: "report" }> {
  return {
    kind: "report",
    title: "Leaf report",
    description: "",
    priority: "medium",
    status: "draft",
    reportType: "threat-brief",
    body: "Live body text",
    claims: [
      {
        text: "Actor used spearphishing against finance",
        sourceRefs: ["src-feed-1", "ev-99"],
      },
    ],
    tlp: "amber",
    audience: ["CISO", "SOC"],
    approvedBy: "reviewer-a",
    approvedAt: "2026-10-01T12:00:00.000Z",
    publishedRevisions: [],
    tags: [],
    collaborators: [],
    references: [],
    id: "fixture",
    tenantId: principal.tenantId,
    ownerId: principal.userId,
    revision: 1,
    createdAt: "2026-10-01T00:00:00.000Z",
    updatedAt: "2026-10-01T00:00:00.000Z",
    createdBy: principal.userId,
    ...overrides,
  };
}

describe("report HTML export", () => {
  it("renders claim text with claim-level citations and header markings", () => {
    const html = reportHtml(reportFixture());
    expect(html).toContain("Actor used spearphishing against finance");
    expect(html).toMatch(
      /Actor used spearphishing against finance[\s\S]*src-feed-1/,
    );
    expect(html).toContain("TLP:AMBER");
    expect(html).toContain("Audience: CISO, SOC");
    expect(html).toContain("Approved by reviewer-a");
    expect(html).toContain("2026-10-01T12:00:00.000Z");
  });

  it("exports reports with no claims without inventing any", () => {
    const html = reportHtml(reportFixture({ claims: [] }));
    expect(html).not.toContain("<h2>Claims</h2>");
    expect(html).toContain("Live body text");
  });
});

describe("publish freezes revision", () => {
  it("keeps published revision immutable after later edits and retains reason", async () => {
    const created = await repo.save({
      kind: "report",
      title: "Immutable brief",
      body: "Original published body",
      claims: [
        {
          text: "Original claim about infrastructure",
          sourceRefs: ["src-a"],
        },
      ],
      tlp: "green",
      audience: ["IR"],
      approvedBy: "lead-analyst",
      approvedAt: "2026-10-02T08:00:00.000Z",
      status: "draft",
    });
    const published = await repo.save(
      {
        ...created,
        status: "published",
      },
      created.id,
      created.revision,
      "Ready for CISO distribution",
    );
    expect(published.kind).toBe("report");
    if (published.kind !== "report") return;
    expect(published.publishedRevisions).toHaveLength(1);
    const frozen = published.publishedRevisions[0]!;
    expect(frozen.body).toBe("Original published body");
    expect(frozen.claims[0]?.text).toBe(
      "Original claim about infrastructure",
    );
    expect(frozen.reason).toBe("Ready for CISO distribution");
    expect(frozen.tlp).toBe("green");

    const edited = await repo.save(
      {
        ...published,
        body: "Mutated live body",
        claims: [
          {
            text: "Mutated claim that must not rewrite the freeze",
            sourceRefs: ["src-b"],
          },
        ],
        status: "published",
      },
      published.id,
      published.revision,
      "Post-publish wording tweak",
    );
    expect(edited.kind).toBe("report");
    if (edited.kind !== "report") return;
    expect(edited.body).toBe("Mutated live body");
    expect(edited.revision).toBeGreaterThan(published.revision);
    expect(edited.publishedRevisions).toHaveLength(1);
    expect(edited.publishedRevisions[0]?.body).toBe(
      "Original published body",
    );
    expect(edited.publishedRevisions[0]?.claims[0]?.text).toBe(
      "Original claim about infrastructure",
    );
    expect(edited.publishedRevisions[0]?.reason).toBe(
      "Ready for CISO distribution",
    );

    const history = await repo.history(edited.id);
    const reasons = history.data
      .map((e) =>
        typeof e.data.reason === "string" ? e.data.reason : undefined,
      )
      .filter(Boolean);
    expect(reasons).toContain("Ready for CISO distribution");
    expect(reasons).toContain("Post-publish wording tweak");
  });
});
