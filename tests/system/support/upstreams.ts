/** Synthetic upstream documents; every request is intercepted before the network. */
export const feedDomain = "feed-c2.synthetic.test";
export const malwareId = "malware--11111111-1111-4111-8111-111111111111";
export const techniqueId =
  "attack-pattern--22222222-2222-4222-8222-222222222222";
export const actorId = "intrusion-set--44444444-4444-4444-8444-444444444444";
export function upstreamResponse(url: URL): unknown {
  if (
    url.hostname === "raw.githubusercontent.com" &&
    url.pathname.includes("attack-stix-data")
  )
    return {
      type: "bundle",
      id: "bundle--55555555-5555-4555-8555-555555555555",
      objects: [
        {
          type: "malware",
          id: malwareId,
          name: "Synthetic E2E RAT",
          description: "Synthetic malware used by offline system tests",
          is_family: true,
        },
        {
          type: "attack-pattern",
          id: techniqueId,
          name: "Synthetic Command Behaviour",
          description: "Synthetic shell command execution test",
          external_references: [
            { source_name: "mitre-attack", external_id: "T1059" },
          ],
        },
        {
          type: "intrusion-set",
          id: actorId,
          name: "Synthetic E2E Actor",
          description: "Synthetic actor, not a real-world attribution",
          aliases: ["Synthetic Alias"],
          external_references: [
            { source_name: "mitre-attack", external_id: "G9000" },
          ],
        },
        {
          type: "relationship",
          id: "relationship--33333333-3333-4333-8333-333333333333",
          source_ref: malwareId,
          target_ref: techniqueId,
          relationship_type: "uses",
        },
      ],
    };
  if (
    url.hostname === "raw.githubusercontent.com" &&
    url.pathname.includes("misp-galaxy")
  )
    return {
      version: 1,
      license: "Synthetic test data",
      values: url.pathname.endsWith("/threat-actor.json")
        ? [
            {
              uuid: "44444444-4444-4444-8444-444444444444",
              value: "Synthetic E2E Actor",
              description: "Synthetic alias record",
              meta: { synonyms: ["Synthetic Alias"], external_id: ["G9000"] },
            },
          ]
        : [],
    };
  if (url.hostname === "threatfox-api.abuse.ch")
    return {
      query_status: "ok",
      data: [
        {
          id: "synthetic-system-ioc",
          ioc: feedDomain,
          ioc_type: "domain",
          threat_type: "botnet_cc",
          malware_printable: "Synthetic E2E RAT",
          confidence_level: 95,
          first_seen: new Date().toISOString(),
          tags: ["synthetic-e2e"],
        },
      ],
    };
  if (url.hostname === "urlhaus-api.abuse.ch")
    return {
      query_status: "ok",
      urls: [
        {
          id: "synthetic-url",
          url: "https://payload.synthetic.test/drop.exe",
          url_status: "online",
          date_added: new Date().toISOString().slice(0, 19).replace("T", " "),
          tags: ["synthetic"],
          payloads: [
            { response_sha256: "a".repeat(64), signature: "Synthetic E2E RAT" },
          ],
        },
      ],
    };
  if (url.hostname === "feodotracker.abuse.ch")
    return [
      {
        ip_address: "192.0.2.190",
        port: 443,
        status: "online",
        first_seen: new Date().toISOString(),
        last_online: new Date().toISOString(),
        malware: "Synthetic E2E RAT",
      },
    ];
  if (url.hostname === "www.cisa.gov")
    return {
      vulnerabilities: [
        {
          cveID: "CVE-2024-21762",
          vendorProject: "Fortinet",
          product: "FortiOS",
          vulnerabilityName: "Synthetic KEV test",
          dateAdded: "2026-01-01",
          shortDescription: "Synthetic KEV fixture",
          requiredAction: "Apply vendor update",
          dueDate: "2026-01-22",
          knownRansomwareCampaignUse: "Known",
          notes: "Synthetic data",
        },
      ],
    };
  throw new Error("Blocked unexpected external request: " + url.hostname);
}
