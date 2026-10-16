import { describe, it, expect } from "vitest";
import {
  freshness,
  reassessmentTrigger,
} from "../packages/intel/src/freshness";
import {
  ClefDecisionEngine,
  freshEvidenceGate,
  FRESH_EVIDENCE_DAYS,
} from "../packages/clef/src/index";
import {
  EnvironmentSchema,
  type Assessment,
  type Evidence,
  type EvidenceBundle,
  type IntelRelationship,
} from "../packages/schemas/src/index";
import { normalise } from "../packages/intel/src/normalise";
import { RecordedTransport } from "./helpers";

const DAY = 86400000;
/** Pinned reference time so freshness assertions are deterministic. */
const NOW = "2026-10-13T00:00:00.000Z";
const at = (daysAgo: number) =>
  new Date(Date.parse(NOW) - daysAgo * DAY).toISOString();

/**
 * Audit case (finding 2): IP 162.243.103.246 was ranked first as a current
 * high-priority threat on the strength of ONE Feodo record 220 days old whose
 * original status was "offline". The record mirrors the Feodo normalisation
 * in packages/intel/src/additional-feeds.ts (data.status from the feed
 * record, observedAt = last_online ?? first_seen).
 */
function feodoEvidence(): Evidence {
  return {
    id: "ev_feodo_162_243_103_246",
    type: "feed",
    sourceId: "feodo",
    provenance: {
      sourceId: "feodo",
      sourceName: "Feodo Tracker",
      sourceUrl: "https://feodotracker.abuse.ch/",
      sourceRecordId: "162.243.103.246:443",
      retrievedAt: at(220),
      redistributable: true,
    },
    data: {
      malicious: true,
      role: "c2",
      malware: "Feodo",
      malwareEntityId: "malware-feodo",
      port: 443,
      status: "offline",
    },
    observedAt: at(220),
    confidence: 0.9,
    createdAt: at(220),
    behavioural: false,
  };
}

async function auditBundle(): Promise<EvidenceBundle> {
  const evidence = feodoEvidence();
  const observable = await normalise("162.243.103.246");
  const relationship: IntelRelationship = {
    id: "rel-feodo-malware",
    sourceEntityId: observable.id,
    targetEntityId: "malware-feodo",
    relationshipType: "uses",
    evidenceIds: [evidence.id],
    assertionType: "source_claimed",
    confidence: 0.9,
    sourceIds: ["feodo"],
    provenance: evidence.provenance,
    createdAt: at(220),
    updatedAt: at(220),
  };
  return {
    observable,
    evidence: [evidence],
    relationships: [relationship],
    attackCandidates: [],
    actorCandidates: [],
    relatedEntities: [
      {
        id: "malware-feodo",
        type: "malware",
        name: "Feodo",
        description: "Feodo source-provided malware association",
        aliases: [],
        data: {},
        provenance: evidence.provenance,
      },
    ],
    customerContext: {
      environment: EnvironmentSchema.parse({}),
      observed: false,
      exposedAssets: 0,
    },
    evidenceVersion: "v1",
    truncated: false,
  };
}

const feodoSources = [
  { id: "feodo", independent_group: "abuse.ch", reliability: 0.9 },
];

/** Three independent telemetry sources: enough corroboration for auto-accept. */
async function corroboratedBundle(observedAt: string): Promise<EvidenceBundle> {
  const evidence: Evidence[] = ["a", "b", "c"].map((s) => ({
    id: "ev-" + s,
    type: "telemetry",
    sourceId: "source-" + s,
    provenance: {
      sourceId: "source-" + s,
      sourceName: "Independent source " + s,
      retrievedAt: observedAt,
      redistributable: true,
    },
    data: { malicious: true, role: "c2" },
    confidence: 1,
    createdAt: observedAt,
    observedAt,
    behavioural: false,
  }));
  return {
    observable: await normalise("203.0.113.10"),
    evidence,
    relationships: [],
    attackCandidates: [],
    actorCandidates: [],
    relatedEntities: [],
    customerContext: {
      environment: EnvironmentSchema.parse({}),
      observed: false,
      exposedAssets: 0,
    },
    evidenceVersion: "v1",
    truncated: false,
  };
}
const corroboratedSources = ["a", "b", "c"].map((s) => ({
  id: "source-" + s,
  independent_group: "group-" + s,
  reliability: 1,
}));

const blockActions = (): Assessment["recommended_actions"] => [
  { action: "block", confidence: 0.95, reason_codes: ["KNOWN_C2"] },
  { action: "hunt", confidence: 0.95, reason_codes: ["KNOWN_C2"] },
];

describe("freshness policy (packages/intel/src/freshness.ts)", () => {
  it("calculates bounds for large correlation groups without spreading into the call stack", () => {
    const evidence = Array.from({ length: 150000 }, () => ({
      observedAt: at(2),
    }));
    const state = freshness(evidence, NOW);
    expect(state.first_observed).toBe(at(2));
    expect(state.last_observed).toBe(at(2));
    expect(state.activity).toBe("active");
  });
  it("future observations cannot extend activity or satisfy the blocking freshness gate", () => {
    const future = { observedAt: at(-180), data: { malicious: true } };
    const state = freshness([future], NOW);
    expect(state.activity).toBe("unknown");
    expect(state.last_observed).toBeNull();
    expect(state.valid_until).toBeNull();
    expect(state.stale_reasons).toContain("FUTURE_OBSERVATION_DATE");
    expect(
      freshEvidenceGate(blockActions(), [future], {
        awaitingReview: false,
        now: NOW,
      }).downgraded,
    ).toBe(true);
    const mixed = freshness([{ observedAt: at(2) }, future], NOW);
    expect(mixed.activity).toBe("stale");
    expect(mixed.last_observed).toBe(at(2));
  });

  it.each([
    [{ observedAt: at(2), data: { status: "offline" } }],
    [{ observedAt: at(2) }, { data: { malicious: true } }],
  ])(
    "incomplete or offline observations cannot justify a fresh block",
    (...evidence) => {
      expect(
        freshEvidenceGate(blockActions(), evidence, {
          awaitingReview: false,
          now: NOW,
        }).downgraded,
      ).toBe(true);
    },
  );

  it("active only with recent dated evidence, nothing offline or undated", () => {
    const state = freshness(
      [{ observedAt: at(5), data: { malicious: true, status: "online" } }],
      NOW,
    );
    expect(state.activity).toBe("active");
    expect(state.stale).toBe(false);
    expect(state.stale_reasons).toEqual([]);
    expect(state.first_observed).toBe(at(5));
    expect(state.last_observed).toBe(at(5));
    expect(state.valid_until).toBe(
      new Date(Date.parse(at(5)) + 90 * DAY).toISOString(),
    );
  });

  it("stale past 30 days, expired past 90 days, with age reasons", () => {
    const stale = freshness([{ observedAt: at(40) }], NOW);
    expect(stale.activity).toBe("stale");
    expect(stale.stale).toBe(true);
    expect(stale.stale_reasons).toContain("EVIDENCE_OLDER_THAN_30D");
    expect(stale.stale_reasons).not.toContain("EVIDENCE_OLDER_THAN_90D");

    const expired = freshness([{ observedAt: at(100) }], NOW);
    expect(expired.activity).toBe("expired");
    expect(expired.stale).toBe(true);
    expect(expired.stale_reasons).toContain("EVIDENCE_OLDER_THAN_30D");
    expect(expired.stale_reasons).toContain("EVIDENCE_OLDER_THAN_90D");
  });

  it("unknown when there are no evidence dates — never active, never fresh", () => {
    for (const evidence of [
      [],
      [{ data: { malicious: true } }],
      [{ observedAt: "not-a-date", data: {} }],
    ]) {
      const state = freshness(evidence, NOW);
      expect(state.activity).toBe("unknown");
      expect(state.stale).toBe(true);
      expect(state.first_observed).toBeNull();
      expect(state.last_observed).toBeNull();
      expect(state.valid_until).toBeNull();
      expect(state.stale_reasons).toContain("NO_OBSERVATION_DATES");
    }
  });

  it("source status offline at collection can never yield activity active", () => {
    const fresh = freshness(
      [{ observedAt: at(2), data: { status: "offline" } }],
      NOW,
    );
    expect(fresh.activity).not.toBe("active");
    expect(fresh.activity).toBe("stale");
    expect(fresh.stale).toBe(true);
    expect(fresh.stale_reasons).toContain(
      "SOURCE_STATUS_OFFLINE_AT_COLLECTION",
    );

    const expired = freshness(
      [{ observedAt: at(220), data: { status: "offline" } }],
      NOW,
    );
    expect(expired.activity).toBe("expired");
    expect(expired.stale_reasons).toContain(
      "SOURCE_STATUS_OFFLINE_AT_COLLECTION",
    );
  });

  it("undated evidence alongside dated evidence blocks active (fail-closed)", () => {
    const state = freshness(
      [
        { observedAt: at(1), data: { malicious: true } },
        { data: { malicious: true } },
      ],
      NOW,
    );
    expect(state.activity).not.toBe("active");
    expect(state.stale_reasons).toContain("EVIDENCE_WITHOUT_OBSERVATION_DATE");
  });

  it("last_observed is the newest evidence observation, never wall clock or processing time", () => {
    const state = freshness(
      [
        {
          observedAt: at(220),
          data: {},
        },
        { observedAt: at(5), data: {} },
      ],
      NOW,
    );
    expect(state.first_observed).toBe(at(220));
    expect(state.last_observed).toBe(at(5));
    expect(state.last_observed).not.toBe(NOW);
    // valid_until is derived from the observation, not from `now`.
    expect(state.valid_until).toBe(
      new Date(Date.parse(at(5)) + 90 * DAY).toISOString(),
    );
  });
});

describe("audit regression — one 220-day-old Feodo record, status offline", () => {
  it("is expired/stale, never active; last_observed is the evidence observedAt", () => {
    const evidence = feodoEvidence();
    const state = freshness([evidence], NOW);
    expect(state.activity).toBe("expired");
    expect(state.activity).not.toBe("active");
    expect(state.stale).toBe(true);
    expect(state.last_observed).toBe(evidence.observedAt);
    expect(state.last_observed).not.toBe(NOW);
    expect(state.first_observed).toBe(evidence.observedAt);
    expect(state.valid_until).toBe(
      new Date(Date.parse(evidence.observedAt!) + 90 * DAY).toISOString(),
    );
    expect(state.stale_reasons).toContain(
      "SOURCE_STATUS_OFFLINE_AT_COLLECTION",
    );
    expect(state.stale_reasons).toContain("EVIDENCE_OLDER_THAN_90D");
  });

  it("retains the historical malicious association and fires the reassessment trigger", () => {
    const evidence = feodoEvidence();
    const before = JSON.stringify(evidence);
    const state = freshness([evidence], NOW);
    // Historical malicious association is retained: nothing is dropped or rewritten.
    expect(JSON.stringify(evidence)).toBe(before);
    expect(evidence.data.malicious).toBe(true);
    expect(evidence.data.malwareEntityId).toBe("malware-feodo");

    const reassessment = reassessmentTrigger(state);
    expect(reassessment.trigger).toBe(true);
    expect(reassessment.reason_codes).toContain("EXPIRED_INDICATOR");
    expect(reassessment.reason_codes).toContain("HISTORICAL_ASSOCIATION_ONLY");
  });

  it("never recommends block and keeps the Feodo association through classification", async () => {
    const b = await auditBundle();
    const a = await new ClefDecisionEngine(
      new RecordedTransport(),
    ).classifyObservable(b, feodoSources);
    expect(a.recommended_actions.some((x) => x.action === "block")).toBe(false);
    // The historical association survives assessment — it is aged, not deleted.
    expect(a.evidence).toHaveLength(1);
    expect(a.evidence[0]!.data.malicious).toBe(true);
    expect(a.evidence[0]!.data.status).toBe("offline");
    expect(a.malware.map((m) => m.id)).toContain("malware-feodo");

    const state = freshness(a.evidence);
    expect(state.activity).toBe("expired");
    expect(reassessmentTrigger(state).reason_codes).toContain(
      "EXPIRED_INDICATOR",
    );
    // A block recommendation is downgraded even when posed directly.
    const gated = freshEvidenceGate(blockActions(), a.evidence, {
      awaitingReview: false,
      now: NOW,
    });
    expect(gated.downgraded).toBe(true);
    expect(gated.actions.some((x) => x.action === "block")).toBe(false);
    expect(gated.actions.flatMap((x) => x.reason_codes)).toContain(
      "FRESH_EVIDENCE_REQUIRED",
    );
  });
});

describe("block requires fresh evidence (FRESH_EVIDENCE_REQUIRED)", () => {
  it("keeps block with evidence within 14 days and a cleared review", () => {
    for (const age of [0, 1, FRESH_EVIDENCE_DAYS]) {
      const gated = freshEvidenceGate(
        blockActions(),
        [{ observedAt: at(age), data: { malicious: true } }],
        { awaitingReview: false, now: NOW },
      );
      expect(gated.downgraded).toBe(false);
      expect(gated.actions[0]!.action).toBe("block");
      expect(gated.actions.map((x) => x.action)).toContain("hunt");
    }
  });

  it("downgrades block to monitor past the 14-day window", () => {
    const gated = freshEvidenceGate(
      blockActions(),
      [{ observedAt: at(FRESH_EVIDENCE_DAYS + 1), data: { malicious: true } }],
      { awaitingReview: false, now: NOW },
    );
    expect(gated.downgraded).toBe(true);
    expect(gated.actions.some((x) => x.action === "block")).toBe(false);
    expect(gated.actions.map((x) => x.action)).toContain("monitor");
    expect(gated.actions.map((x) => x.action)).toContain("hunt");
    for (const action of gated.actions)
      expect(action.reason_codes).toContain("FRESH_EVIDENCE_REQUIRED");
  });

  it("downgrades block to hunt where behavioural evidence exists", () => {
    const gated = freshEvidenceGate(
      blockActions(),
      [{ observedAt: at(200), data: { malicious: true } }],
      { awaitingReview: false, behaviour: true, now: NOW },
    );
    expect(gated.downgraded).toBe(true);
    expect(gated.actions.some((x) => x.action === "block")).toBe(false);
    // Hunt already existed for the behaviour; it is merged, not duplicated.
    expect(gated.actions.filter((x) => x.action === "hunt")).toHaveLength(1);
    expect(gated.actions[0]!.reason_codes).toContain("FRESH_EVIDENCE_REQUIRED");
  });

  it("downgrades block while the assessment is awaiting review", () => {
    const gated = freshEvidenceGate(
      blockActions(),
      [{ observedAt: at(0), data: { malicious: true } }],
      { awaitingReview: true, now: NOW },
    );
    expect(gated.downgraded).toBe(true);
    expect(gated.actions.some((x) => x.action === "block")).toBe(false);
    expect(gated.actions.map((x) => x.action)).toContain("monitor");
  });

  it("downgrades block when evidence carries no observation dates (fail-closed)", () => {
    const gated = freshEvidenceGate(
      blockActions(),
      [{ data: { malicious: true } }],
      { awaitingReview: false, now: NOW },
    );
    expect(gated.downgraded).toBe(true);
    expect(gated.actions.some((x) => x.action === "block")).toBe(false);
  });

  it("leaves actions without a block untouched", () => {
    const actions: Assessment["recommended_actions"] = [
      { action: "investigate", confidence: 0.5, reason_codes: [] },
    ];
    const gated = freshEvidenceGate(actions, [{ observedAt: at(500) }], {
      awaitingReview: true,
      now: NOW,
    });
    expect(gated.downgraded).toBe(false);
    expect(gated.actions).toBe(actions);
  });

  it("keeps block for fresh corroborated evidence through the decision engine", async () => {
    const b = await corroboratedBundle(new Date().toISOString());
    const a = await new ClefDecisionEngine(
      new RecordedTransport(),
    ).classifyObservable(b, corroboratedSources);
    expect(a.malicious.classification).toBe("malicious");
    expect(a.human_review).toBe(false);
    expect(a.recommended_actions.map((x) => x.action)).toContain("block");
  });

  it("downgrades engine block recommendations outside the 14-day window", async () => {
    // 20 days old: still inside the 30-day freshness window, but past the
    // stricter bar for recommending a block.
    const b = await corroboratedBundle(
      new Date(Date.now() - 20 * DAY).toISOString(),
    );
    const a = await new ClefDecisionEngine(
      new RecordedTransport(),
    ).classifyObservable(b, corroboratedSources);
    expect(a.malicious.classification).toBe("malicious");
    expect(a.human_review).toBe(false);
    expect(a.recommended_actions.some((x) => x.action === "block")).toBe(false);
    expect(a.recommended_actions.map((x) => x.action)).toContain("monitor");
    expect(a.recommended_actions.map((x) => x.action)).toContain("hunt");
    expect(a.reason_codes).toContain("FRESH_EVIDENCE_REQUIRED");
    for (const action of a.recommended_actions)
      if (action.action === "monitor")
        expect(action.reason_codes).toContain("FRESH_EVIDENCE_REQUIRED");
  });
});
