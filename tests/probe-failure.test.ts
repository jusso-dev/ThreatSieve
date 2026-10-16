import { expect, it } from "vitest";
import { z } from "zod";
import { probeFailureReason } from "../scripts/probe-failure";
it("production probe names the failure class without echoing details", async () => {
  const timeout = await fetch("https://example.invalid", {
    signal: AbortSignal.timeout(0),
  }).catch((e: unknown) => e);
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
