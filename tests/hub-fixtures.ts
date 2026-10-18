import { gzipSync } from "node:zlib";
import { readFileSync, readdirSync } from "node:fs";
import { Miniflare } from "miniflare";
import { migrationStatements } from "../packages/database/src/migrations";

/** Offline fixtures for the lookup-hub sources. Unknown URLs fail the test. */
export const fixture = (name: string) =>
  readFileSync("tests/fixtures/hub/" + name);
export const json = (name: string) =>
  JSON.parse(fixture(name).toString("utf8")) as Record<string, unknown>;

export function hubFetch(
  overrides: Record<string, (url: URL) => Response | undefined> = {},
) {
  const calls: string[] = [];
  const greynoise = json("greynoise-community.json") as Record<
    string,
    Record<string, unknown>
  >;
  const request: typeof fetch = async (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    calls.push(url.href);
    for (const [prefix, handler] of Object.entries(overrides))
      if (url.href.startsWith(prefix)) {
        const response = handler(url);
        if (response) return response;
      }
    const gz = (name: string) =>
      new Response(gzipSync(fixture(name)), {
        headers: { "content-type": "application/gzip" },
      });
    if (url.href === "https://iptoasn.com/data/ip2asn-v4.tsv.gz")
      return gz("iptoasn-v4.tsv");
    if (url.href === "https://iptoasn.com/data/ip2asn-v6.tsv.gz")
      return gz("iptoasn-v6.tsv");
    if (
      /^https:\/\/epss\.empiricalsecurity\.com\/epss_scores-\d{4}-\d\d-\d\d\.csv\.gz$/.test(
        url.href,
      )
    )
      return gz("epss.csv");
    if (
      url.origin + url.pathname ===
      "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
      return Response.json(json("nvd-page.json"));
    if (url.href === "https://api.osv.dev/v1/vulns/CVE-2099-0001")
      return Response.json(json("osv-cve.json"));
    if (url.href.startsWith("https://api.osv.dev/v1/vulns/"))
      return Response.json(
        { code: 5, message: "Bug not found." },
        { status: 404 },
      );
    if (url.href.startsWith("https://api.greynoise.io/v3/community/")) {
      const ip = url.pathname.split("/").at(-1);
      const hit = Object.values(greynoise).find(
        (r) => r.ip === ip && r.message === "Success",
      );
      return hit
        ? Response.json(hit)
        : Response.json({ ...greynoise.not_observed, ip }, { status: 404 });
    }
    if (url.href.startsWith("https://cti.api.crowdsec.net/v2/smoke/")) {
      const ip = decodeURIComponent(url.pathname.split("/").at(-1)!);
      return ip === "198.51.100.7"
        ? Response.json(json("crowdsec-smoke.json"))
        : Response.json(
            { message: "IP address information not found" },
            { status: 404 },
          );
    }
    throw new Error("Unexpected network request in test: " + url.href);
  };
  return { request, calls };
}

export async function migratedDatabase() {
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
    r2Buckets: ["ARCHIVE"],
  });
  const db = await mf.getD1Database("DB");
  const bucket = (await mf.getR2Bucket("ARCHIVE")) as unknown as R2Bucket;
  for (const name of readdirSync("migrations").sort())
    for (const statement of migrationStatements(
      readFileSync("migrations/" + name, "utf8"),
    ))
      await db.prepare(statement).run();
  return { mf, db, bucket };
}
