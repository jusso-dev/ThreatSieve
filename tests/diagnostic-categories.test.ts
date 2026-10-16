import { expect, it } from "vitest";
import { errorType } from "../packages/observability/src/index";
import { wilsonInterval } from "../packages/scoring/src/evaluation";
it("diagnostics expose stable categories without provider messages or credentials", () => {
  for (const [message, category] of [
    ["ThreatFox credential required", "FeedCredentialsMissing"],
    [
      "ThreatFox upstream HTTP 403 https://private.invalid/?key=never-log-this",
      "UpstreamAccessDenied",
    ],
    ["URLhaus upstream HTTP 429", "UpstreamRateLimited"],
    ["MISP upstream HTTP 503", "UpstreamUnavailable"],
    ["ThreatFox upstream HTTP 503 request timed out", "UpstreamUnavailable"],
    ["URLhaus credential required after timeout", "FeedCredentialsMissing"],
    ["fetch failed https://private.invalid", "UpstreamNetwork"],
    ["D1_ERROR: SQL timeout secret-value", "D1Timeout"],
  ])
    expect(errorType(new Error(message))).toBe(category);
});
it("Wilson intervals reflect small denominators and undefined rates", () => {
  expect(wilsonInterval(0, 0)).toBeNull();
  const interval = wilsonInterval(1, 1)!;
  expect(interval.lower).toBeCloseTo(0.2065, 3);
  expect(interval.upper).toBeCloseTo(1);
  expect(wilsonInterval(50, 100)!.lower).toBeCloseTo(0.4038, 3);
});
