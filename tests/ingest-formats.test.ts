import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mapCsaf } from "../packages/ingest/src/formats/csaf";
import { mapOsv } from "../packages/ingest/src/formats/osv";
import {
  mapStix,
  patternIndicators,
} from "../packages/ingest/src/formats/stix";
import type { Mapped } from "../packages/ingest/src/formats/common";
import {
  defang,
  normaliseItem,
  refang,
  sanitizeText,
} from "../packages/ingest/src/normalise";
import {
  cvssSeverity,
  mapVendorSeverity,
  parseCvssVector,
} from "../packages/ingest/src/severity";
import type { NormalisedItem } from "../packages/ingest/src/schema";

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync("tests/fixtures/ingest/" + name, "utf8"));

/** Maps then normalises, as the API does. */
async function run(mapped: Mapped[], format: "stix" | "csaf" | "osv") {
  const items: (NormalisedItem & { warnings: string[] })[] = [];
  const failures: { ref?: string; issues: unknown }[] = [];
  for (const m of mapped) {
    if (m.issues) {
      failures.push({ ref: m.source_ref, issues: m.issues });
      continue;
    }
    const r = await normaliseItem(m.item, { format, warnings: m.warnings });
    if (r.ok) items.push({ ...r.item, warnings: r.normalisation.warnings });
    else failures.push({ ref: m.source_ref, issues: r.issues });
  }
  return { items, failures };
}
afterEach(() => vi.unstubAllGlobals());

describe("STIX 2.1 mapper", () => {
  it("maps the OASIS C2 indicator bundle and resolves the producing identity", async () => {
    const { items, failures } = await run(
      mapStix(fixture("stix-indicators-for-C2-with-COA.json")),
      "stix",
    );
    expect(failures).toEqual([]);
    expect(items.map((i) => i.external_id)).toEqual([
      "indicator--53fe3b22-0201-47cf-85d0-97c02164528d",
      "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
    ]);
    const [ip, hash] = items;
    expect(ip).toMatchObject({
      type: "alert",
      title: "IP Address for known C2 channel",
      source: { name: "The MITRE Corporation - DHS Support Team" },
      published_at: "2014-05-08T09:00:00.000Z",
      indicators: [
        { type: "ipv4", value: "10.0.0.0", display_value: "10[.]0[.]0[.]0" },
      ],
      tags: ["malicious-activity"],
      // Unmarked STIX fails closed.
      tlp: "amber",
      tlp_source: "default",
    });
    expect(ip!.warnings).toContain(
      "Indicator 0 is a private address, not a public one",
    );
    expect(hash!.indicators).toEqual([
      {
        type: "sha256",
        value:
          "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        display_value:
          "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
      },
    ]);
  });

  it("maps the Poison Ivy report, rejecting only the indicator with a malformed value", async () => {
    const { items, failures } = await run(
      mapStix(fixture("stix-poisonivy.json")),
      "stix",
    );
    // 25 indicators, 6 vulnerabilities and 1 report; one indicator has the
    // value 'domain autuo.xicp.net', which is not a domain.
    expect(items).toHaveLength(31);
    expect(failures).toEqual([
      {
        ref: "indicator--4e4c4ad7-4909-456a-b6fa-e24a6f682a40",
        issues: [
          { path: ["indicators", 0, "value"], message: "Invalid domain" },
        ],
      },
    ]);
    const vulnerability = items.find((i) => i.title === "CVE-2012-0158");
    expect(vulnerability).toMatchObject({
      type: "advisory",
      cve_ids: ["CVE-2012-0158"],
    });
    const multi = items.find((i) => i.title === "www.webserver.dynssl.com")!;
    expect(multi.indicators.map((i) => i.type)).toContain("domain");
    expect(
      multi.indicators.filter((i) => i.type === "ipv4").length,
    ).toBeGreaterThan(1);
    const fileName = items.find((i) => i.title === "CBricksDoc")!;
    expect(fileName.indicators).toEqual([]);
    expect(fileName.warnings.join()).toContain("No supported comparisons");
    const report = items.find((i) => i.external_id.startsWith("report--"))!;
    expect(report).toMatchObject({
      type: "advisory",
      title: "Poison Ivy: Assessing Damage and Extracting Intelligence",
      source: { name: "FireEye, Inc." },
    });
    expect(report.cve_ids).toEqual(
      expect.arrayContaining([
        "CVE-2012-0158",
        "CVE-2013-0422",
        "CVE-2010-3333",
      ]),
    );
    expect(report.indicators.length).toBeGreaterThan(20);
    expect(report.warnings.join()).toContain(
      "Invalid domain from indicator--4e4c4ad7",
    );
  });

  it("reads TLP from standard and bundle-local marking definitions; the strictest wins", async () => {
    const bundle = {
      type: "bundle",
      id: "bundle--00000000-0000-4000-8000-000000000001",
      objects: [
        {
          type: "marking-definition",
          spec_version: "2.1",
          id: "marking-definition--00000000-0000-4000-8000-0000000000aa",
          created: "2026-01-01T00:00:00Z",
          definition_type: "tlp",
          definition: { tlp: "red" },
        },
        ...["green", "red"].map((level, i) => ({
          type: "indicator",
          spec_version: "2.1",
          id: "indicator--00000000-0000-4000-8000-00000000000" + i,
          created: "2026-01-01T00:00:00Z",
          modified: "2026-01-01T00:00:00Z",
          pattern_type: "stix",
          pattern: "[url:value = 'https://evil.example/" + level + "']",
          valid_from: "2026-01-01T00:00:00Z",
          object_marking_refs: [
            // TLP:GREEN (TLP 1.0 standard definition)
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            ...(level === "red"
              ? ["marking-definition--00000000-0000-4000-8000-0000000000aa"]
              : []),
          ],
        })),
      ],
    };
    const { items } = await run(mapStix(bundle), "stix");
    expect(items.map((i) => [i.tlp, i.tlp_source])).toEqual([
      ["green", "provided"],
      ["red", "provided"],
    ]);
    expect(items[0]!.indicators[0]!.display_value).toBe(
      "hxxps[://]evil[.]example/green",
    );
  });

  it("extracts only literal equality comparisons and never evaluates patterns", () => {
    const warnings: string[] = [];
    expect(
      patternIndicators(
        "[file:hashes.'SHA-512' = 'aa'] OR [file:hashes.MD5 = 'D41D8CD98F00B204E9800998ECF8427E'] OR [url:value MATCHES '.*'] OR [email-addr:value = 'a\\'b@x.test']",
        warnings,
      ),
    ).toEqual([
      { type: "md5", value: "D41D8CD98F00B204E9800998ECF8427E" },
      { type: "email", value: "a'b@x.test" },
    ]);
    expect(warnings).toEqual(["Unsupported hash algorithm SHA-512 skipped"]);
  });

  it("refuses a bundle with more mappable objects than a request allows, before mapping", () => {
    const objects = Array.from({ length: 501 }, (_, i) => ({
      type: "indicator",
      id: "indicator--00000000-0000-4000-8000-" + String(i).padStart(12, "0"),
      created: "2026-01-01T00:00:00Z",
      modified: "2026-01-01T00:00:00Z",
      pattern_type: "stix",
      pattern: "[ipv4-addr:value = '192.0.2.1']",
    }));
    expect(() =>
      mapStix({
        type: "bundle",
        id: "bundle--00000000-0000-4000-8000-000000000002",
        objects,
      }),
    ).toThrow(/at most 500 items/);
  });

  it("rejects a document that is not a STIX bundle", () => {
    const [result] = mapStix({ type: "indicator", id: "indicator--x" });
    expect(result!.issues?.[0]?.path).toEqual(["type"]);
  });
});

describe("CSAF 2.0 mapper", () => {
  it("maps the Red Hat advisory using the vendor's aggregate severity", async () => {
    const { items, failures } = await run(
      mapCsaf(fixture("csaf-rhsa-2021_5217.json")),
      "csaf",
    );
    expect(failures).toEqual([]);
    expect(items[0]).toMatchObject({
      type: "advisory",
      external_id: "RHSA-2021:5217",
      title:
        "Red Hat Security Advisory: Red Hat Single Sign-On 7.5.0 security update",
      severity: "high",
      severity_source: "vendor",
      vendor_severity: "Important",
      source: {
        name: "Red Hat Product Security",
        url: "https://www.redhat.com",
      },
      cve_ids: ["CVE-2021-4133"],
      tlp: "clear",
      tlp_source: "provided",
      affected_products: [
        { vendor: "Red Hat", product: "Red Hat Single Sign-On" },
      ],
      tags: ["csaf:csaf_security_advisory", "CWE-863"],
    });
    expect(items[0]!.summary).toMatch(/^A security update is now available/);
  });

  it("maps the BSI advisory's CVSS, CPEs and affected and fixed versions", async () => {
    const { items } = await run(
      mapCsaf(fixture("csaf-bsi-2022-0001.json")),
      "csaf",
    );
    const item = items[0]!;
    expect(item).toMatchObject({
      external_id: "BSI-2022-0001",
      severity: "medium",
      vendor_severity: "Moderate",
      cve_ids: ["CVE-2022-27193"],
      cvss: { version: "3.1", score: 6.1 },
    });
    expect(item.affected_products).toContainEqual({
      vendor: "CSAF Tools",
      product: "CVRF-CSAF-Converter",
      versions: [{ version: "1.0.0-alpha" }],
      cpe: "cpe:/a:csaf-tools:cvrf-csaf-converter:1.0.0-alpha",
    });
    expect(item.affected_products).toContainEqual(
      expect.objectContaining({ versions: [{ fixed: "1.0.0-rc2" }] }),
    );
  });

  it("maps the Cisco advisory's product tree and falls back to CVSS severity", async () => {
    const { items } = await run(
      mapCsaf(fixture("csaf-cisco-sa-20180328-smi2.json")),
      "csaf",
    );
    const item = items[0]!;
    expect(item).toMatchObject({
      external_id: "cisco-sa-20180328-smi2",
      severity: "critical",
      severity_source: "cvss",
      vendor_severity: null,
      cvss: {
        version: "3.0",
        score: 9.8,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
      cve_ids: ["CVE-2018-0171"],
      tlp: "amber",
      tlp_source: "default",
    });
    const ios = item.affected_products.find((p) => p.product === "IOS")!;
    expect(ios.vendor).toBe("Cisco");
    expect(ios.versions).toContainEqual({ version: "12.2(55)SE" });
    expect(item.affected_products.map((p) => p.product)).toContain(
      "Cisco IOS XE Software",
    );
  });

  it("skips an invalid CVSS block with a warning instead of rejecting the advisory", async () => {
    const doc = fixture("csaf-bsi-2022-0001.json") as {
      vulnerabilities: { scores: { cvss_v3: { vectorString: string } }[] }[];
    };
    doc.vulnerabilities[0]!.scores[0]!.cvss_v3.vectorString = "CVSS:3.0/AV:L";
    const { items, failures } = await run(mapCsaf(doc), "csaf");
    expect(failures).toEqual([]);
    expect(items[0]!.cvss).toBeNull();
    expect(items[0]!.warnings.join()).toContain("CVSS score ignored");
  });

  it("reports document-level problems with their path", () => {
    const doc = fixture("csaf-bsi-2022-0001.json") as {
      document: { tracking: Record<string, unknown> };
    };
    delete doc.document.tracking.current_release_date;
    const [result] = mapCsaf(doc);
    expect(result!.source_ref).toBe("BSI-2022-0001");
    expect(result!.issues?.[0]?.path).toEqual([
      "document",
      "tracking",
      "current_release_date",
    ]);
  });
});

describe("OSV mapper", () => {
  it("maps the GHSA record and computes the CVSS v3.1 base score from its vector", async () => {
    const { items } = await run(
      mapOsv(fixture("osv-GHSA-c2qf-rxjj-qqgw.json")),
      "osv",
    );
    expect(items[0]).toMatchObject({
      type: "advisory",
      external_id: "GHSA-c2qf-rxjj-qqgw",
      title: "semver vulnerable to Regular Expression Denial of Service",
      source: { name: "OSV", vendor: "GitHub Advisory Database" },
      cve_ids: ["CVE-2022-25883"],
      cvss: {
        version: "3.1",
        score: 7.5,
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      },
      severity: "high",
      severity_source: "vendor",
      vendor_severity: "HIGH",
      // OSV's nanosecond timestamp, at millisecond precision.
      updated_at: "2026-09-10T03:50:02.224Z",
      affected_products: [
        {
          vendor: "npm",
          product: "semver",
          purl: "pkg:npm/semver",
          versions: [
            { introduced: "7.0.0", fixed: "7.5.2" },
            { introduced: "6.0.0", fixed: "6.3.1" },
            { introduced: "2.0.0-alpha", fixed: "5.7.2" },
          ],
        },
      ],
      tags: ["ecosystem:npm", "CWE-1333"],
    });
  });

  it("maps the PyPI record without a summary or severity", async () => {
    const { items } = await run(
      mapOsv(fixture("osv-PYSEC-2023-74.json")),
      "osv",
    );
    expect(items[0]).toMatchObject({
      external_id: "PYSEC-2023-74",
      cve_ids: ["CVE-2023-32681"],
      severity: "info",
      severity_source: "default",
      source: { vendor: "PyPI Advisory Database" },
    });
    expect(items[0]!.title).toMatch(/^Requests is a HTTP library/);
    expect(items[0]!.affected_products[0]!.versions).toContainEqual({
      introduced: "2.3.0",
      fixed: "2.31.0",
    });
  });
});

describe("normalisation", () => {
  const base = {
    type: "alert",
    title: "Test",
    source: { name: "SIEM" },
    external_id: "a-1",
  };

  it("uppercases CVEs, refangs and validates indicators, and records each change", async () => {
    const r = await normaliseItem(
      {
        ...base,
        cve_ids: ["cve-2024-3094", "CVE-2024-3094"],
        attack_techniques: ["t1059.001"],
        indicators: [
          { type: "domain", value: "Evil[.]Example.COM" },
          { type: "url", value: "hxxps://evil[.]example/a#frag" },
          { type: "ipv6", value: "2001:DB8::0:1" },
          {
            type: "sha1",
            value: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            confidence: 80,
          },
          { type: "email", value: "x@evil.example" },
        ],
        tlp: "white",
      },
      { format: "native" },
    );
    if (!r.ok) throw new Error(JSON.stringify(r.issues));
    expect(r.item.cve_ids).toEqual(["CVE-2024-3094"]);
    expect(r.item.attack_techniques).toEqual(["T1059.001"]);
    expect(r.item.tlp).toBe("clear");
    expect(r.item.indicators).toEqual([
      {
        type: "domain",
        value: "evil.example.com",
        display_value: "evil[.]example[.]com",
      },
      {
        type: "url",
        value: "https://evil.example/a",
        display_value: "hxxps[://]evil[.]example/a",
      },
      {
        type: "ipv6",
        value: "2001:db8::1",
        display_value: "2001[:]db8[:][:]1",
      },
      {
        type: "sha1",
        value: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        display_value: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        confidence: 80,
      },
      {
        type: "email",
        value: "x@evil.example",
        display_value: "x[@]evil[.]example",
      },
    ]);
    expect(r.normalisation.changes).toContainEqual({
      path: ["cve_ids", 0],
      from: "cve-2024-3094",
      to: "CVE-2024-3094",
    });
    expect(r.normalisation.changes).toContainEqual({
      path: ["tlp"],
      from: "white",
      to: "clear",
    });
  });

  it("reports every invalid field with its path", async () => {
    const r = await normaliseItem(
      {
        type: "incident",
        title: "",
        source: { name: "X", url: "javascript:alert(1)" },
        severity: "severe",
        cve_ids: ["CVE-24-1"],
        indicators: [
          { type: "ipv4", value: "300.1.1.1" },
          { type: "md5", value: "abc" },
        ],
        cvss: { version: "3.1", vector: "CVSS:3.1/AV:X" },
        unexpected: true,
      },
      { format: "native" },
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    const paths = r.issues.map((i) => i.path.join("."));
    expect(paths).toEqual(
      expect.arrayContaining([
        "type",
        "title",
        "source.url",
        "severity",
        "cve_ids.0",
        "",
      ]),
    );
    // Value checks run once the shape is valid.
    const second = await normaliseItem(
      {
        ...base,
        indicators: [
          { type: "ipv4", value: "300.1.1.1" },
          { type: "md5", value: "abc" },
        ],
        cvss: { version: "3.1", vector: "CVSS:3.1/AV:X" },
      },
      { format: "native" },
    );
    expect(second.ok ? [] : second.issues).toEqual([
      { path: ["cvss", "vector"], message: "Invalid CVSS v3 base metrics" },
      { path: ["indicators", 0, "value"], message: "Invalid IPv4 address" },
      { path: ["indicators", 1, "value"], message: "Invalid md5" },
    ]);
  });

  it("strips markup and invisible characters from display text", async () => {
    expect(
      sanitizeText(
        "<script>x</script><b>Bad</b>\u202Egnp.exe\u200B <!-- c --> versions <7.5",
        false,
      ),
    ).toBe("xBadgnp.exe versions <7.5");
    const r = await normaliseItem(
      {
        ...base,
        title: "<img src=x onerror=alert(1)>Alert",
        summary: "a\r\n\r\n\r\n\r\nb\u0007",
      },
      { format: "native" },
    );
    if (!r.ok) throw new Error("expected ok");
    expect(r.item.title).toBe("Alert");
    expect(r.item.summary).toBe("a\n\nb");
  });

  it("strips comments in linear time", () => {
    const start = Date.now();
    expect(sanitizeText("<!--".repeat(16000) + "x")).toBe(
      "<!--".repeat(16000) + "x",
    );
    expect(sanitizeText("a<!-- b -->c<!-- d")).toBe("ac<!-- d");
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it("maps vendor severity, keeps the original, and falls back to CVSS then info", async () => {
    const severity = async (extra: object) => {
      const r = await normaliseItem(
        { ...base, ...extra },
        { format: "native" },
      );
      if (!r.ok) throw new Error(JSON.stringify(r.issues));
      return [r.item.severity, r.item.severity_source, r.item.vendor_severity];
    };
    expect(await severity({ vendor_severity: "Important" })).toEqual([
      "high",
      "vendor",
      "Important",
    ]);
    expect(await severity({ vendor_severity: "P1" })).toEqual([
      "critical",
      "vendor",
      "P1",
    ]);
    expect(await severity({ vendor_severity: 5.5 })).toEqual([
      "medium",
      "vendor",
      5.5,
    ]);
    expect(
      await severity({ severity: "low", vendor_severity: "Critical" }),
    ).toEqual(["low", "provided", "Critical"]);
    expect(
      await severity({
        vendor_severity: "unknown",
        cvss: { version: "2.0", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C" },
      }),
    ).toEqual(["high", "cvss", "unknown"]);
    expect(await severity({})).toEqual(["info", "default", null]);
  });

  it("derives a stable external ID when none is supplied", async () => {
    const a = await normaliseItem(
      { type: "alert", title: "Same", source: { name: "S" } },
      { format: "native" },
    );
    const b = await normaliseItem(
      { type: "alert", title: "Same", source: { name: "S" } },
      { format: "native" },
    );
    if (!a.ok || !b.ok) throw new Error("expected ok");
    expect(a.item.external_id_source).toBe("derived");
    expect(a.item.external_id).toBe(b.item.external_id);
    // Equivalent dates and CVE lists derive the same ID.
    const c = await normaliseItem(
      {
        type: "alert",
        title: "Same",
        source: { name: "S" },
        published_at: "2024-01-01T00:00:00Z",
        cve_ids: ["cve-2024-0002", "CVE-2024-0001"],
      },
      { format: "native" },
    );
    const d = await normaliseItem(
      {
        type: "alert",
        title: "Same",
        source: { name: "S" },
        published_at: "2024-01-01T00:00:00.000+00:00",
        cve_ids: ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0001"],
      },
      { format: "native" },
    );
    if (!c.ok || !d.ok) throw new Error("expected ok");
    expect(c.item.external_id).toBe(d.item.external_id);
  });

  it("restricts sources for source-scoped keys", async () => {
    const r = await normaliseItem(base, {
      format: "native",
      allowedSources: ["EDR"],
    });
    expect(r.ok ? [] : r.issues.map((i) => i.path)).toEqual([
      ["source", "name"],
    ]);
    expect(
      (
        await normaliseItem(base, {
          format: "native",
          allowedSources: [" siem "],
        })
      ).ok,
    ).toBe(true);
  });

  it("never makes a network request, even for URLs in the payload", async () => {
    const fetch = vi.fn(() => {
      throw new Error("ingest must not fetch");
    });
    vi.stubGlobal("fetch", fetch);
    for (const name of [
      "stix-poisonivy.json",
      "csaf-cisco-sa-20180328-smi2.json",
      "osv-GHSA-c2qf-rxjj-qqgw.json",
    ]) {
      const mapper = name.startsWith("stix")
        ? mapStix
        : name.startsWith("csaf")
          ? mapCsaf
          : mapOsv;
      await run(mapper(fixture(name)), "stix");
    }
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("severity scale", () => {
  it("computes CVSS base scores from vectors", () => {
    expect(
      parseCvssVector("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toEqual({ ok: true, score: 9.8 });
    expect(
      parseCvssVector("3.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"),
    ).toEqual({ ok: true, score: 6.4 });
    expect(
      parseCvssVector("3.0", "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
    ).toEqual({ ok: true, score: 0 });
    expect(parseCvssVector("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P")).toEqual({
      ok: true,
      score: 7.5,
    });
    expect(
      parseCvssVector(
        "4.0",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      ),
    ).toEqual({ ok: true, score: null });
    expect(
      parseCvssVector("3.1", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").ok,
    ).toBe(false);
  });

  it("uses FIRST qualitative bands", () => {
    expect(
      [0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map((s) => cvssSeverity(s)),
    ).toEqual([
      "info",
      "low",
      "low",
      "medium",
      "medium",
      "high",
      "high",
      "critical",
      "critical",
    ]);
    expect(cvssSeverity(10, "2.0")).toBe("high");
    expect(mapVendorSeverity("Moderate")).toBe("medium");
    expect(mapVendorSeverity("severity-2")).toBe("high");
    expect(mapVendorSeverity("Negligible")).toBe("info");
    expect(mapVendorSeverity("purple")).toBeNull();
  });

  it("defangs for display and refangs on input", () => {
    expect(defang("url", "http://a.example:8080/x.y")).toBe(
      "hxxp[://]a[.]example:8080/x.y",
    );
    expect(defang("cidr", "192.0.2.0/24")).toBe("192[.]0[.]2[.]0/24");
    expect(refang("hxxp[://]a[.]example(.)com")).toBe("http://a.example.com");
  });
});
