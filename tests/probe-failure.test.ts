import { expect, it } from "vitest";
import { z } from "zod";
import { alertLabels, probeFailureReason } from "../scripts/probe-failure";
it("production probe names the failure class without echoing details", async () => {
  // The same TimeoutError fetch rejects with, without touching the network.
  const signal = AbortSignal.timeout(1);
  await new Promise((resolve) => signal.addEventListener("abort", resolve));
  const timeout: unknown = signal.reason;
  expect(probeFailureReason(timeout)).toBe("timed out after 30 seconds");
  expect(probeFailureReason(new Error("ProbeHTTP503"))).toBe("HTTP 503");
  expect(
    probeFailureReason(
      z.object({ alerts: z.array(z.string()) }).safeParse({}).error,
    ),
  ).toBe("unexpected response shape");
  expect(probeFailureReason(new SyntaxError("Unexpected token <"))).toBe(
    "unexpected response shape",
  );
  expect(
    probeFailureReason(new Error("tenant-secret https://api.example/x")),
  ).toBe("request failed");
});
it("production probe names lagging stages but never tenant subjects", () => {
  const alerts = [
    { code: "PIPELINE_LAG", severity: "critical", subject: "classify" },
    { code: "PIPELINE_LAG", severity: "critical", subject: "classify" },
    {
      code: "CONNECTOR_STALE",
      severity: "critical",
      subject: "11111111-1111-4111-8111-111111111111",
    },
    { code: "FEED_NOT_CONFIGURED", severity: "warning", subject: "threatfox" },
    { code: "PIPELINE_BACKLOG", severity: "warning", subject: "enrich" },
  ];
  expect(alertLabels(alerts, "critical")).toEqual([
    "PIPELINE_LAG(classify)",
    "CONNECTOR_STALE",
  ]);
  expect(alertLabels(alerts, "warning")).toEqual([
    "FEED_NOT_CONFIGURED(threatfox)",
    "PIPELINE_BACKLOG(enrich)",
  ]);
});
