import { describe, it, expect } from "vitest";
import {
  normalise,
  detectType,
  normalizeValue,
} from "../packages/intel/src/normalise";
import { parseIndicators } from "../workers/ingest/upload";
describe("observable identities", () => {
  it("converges domains, hashes and IPv6 equivalents", async () => {
    expect((await normalise("EXAMPLE.com.")).id).toBe(
      (await normalise("example.com")).id,
    );
    expect((await normalise("A".repeat(64))).id).toBe(
      (await normalise("sha256:" + "a".repeat(64))).id,
    );
    expect((await normalise("2001:0db8:0:0::1")).id).toBe(
      (await normalise("2001:db8::1")).id,
    );
  });
  it("preserves URL query order, path case and email local case", () => {
    expect(normalizeValue("HTTPS://EXAMPLE.COM:443/A?z=1&a=2#x", "url")).toBe(
      "https://example.com/A?z=1&a=2",
    );
    expect(normalizeValue("Alice@EXAMPLE.com", "email")).toBe(
      "Alice@example.com",
    );
  });
  it("rejects ambiguous values, invalid IPs and dangerous schemes", async () => {
    expect(() => detectType("svchost.exe /c foo")).toThrow();
    expect(() => detectType("999.1.2.3")).toThrow();
    expect(() => normalizeValue("javascript:alert(1)", "url")).toThrow();
    await expect(normalise("010.0.0.1", "ipv4")).rejects.toThrow();
  });
  it("parses quoted CSV and rejects complex STIX expressions", () => {
    expect(
      parseIndicators(
        'observable,type\n"https://example.com/a,b",url',
        "csv",
      )[0]?.observable,
    ).toContain("a,b");
    expect(() =>
      parseIndicators(
        JSON.stringify({
          type: "bundle",
          objects: [
            {
              type: "indicator",
              pattern:
                "[domain-name:value = 'a.com' OR domain-name:value = 'b.com']",
            },
          ],
        }),
        "stix",
      ),
    ).toThrow();
  });
});
