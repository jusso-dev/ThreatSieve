# Intelligence sources

All provider imports require provenance. Raw feed data is archived in R2 before normalisation. Checkpoints move only once downstream processing finishes. Failures remain visible in source operations and pipeline jobs.

| Provider | Interface | Notes |
| --- | --- | --- |
| MITRE ATT&CK | Official `mitre-attack/attack-stix-data` enterprise STIX 2.1 | IDs, aliases, external refs, descriptions and relationships retained; revoked/deprecated objects excluded |
| MISP Galaxy | Official `MISP/misp-galaxy` collections | threat-actor, mitre-intrusion-set, mitre-malware, ransomware, tool, mitre-campaign; explicit MITRE references and unambiguous aliases resolve canonical entities |
| ThreatFox | `get_iocs` Community API | Auth-Key required; seven-day window; IP:port split without treating the port as part of IP identity |
| URLhaus | Authenticated recent URL API | Recent additions are bounded by upstream limits; payload hashes retained when supplied; no maliciousness automatically propagates to the host |
| Feodo Tracker | Official JSON C2 list | Source-provided malware, port and first/last observation preserved |
| CISA KEV | Official JSON catalogue | CVE, vendor, product, due date, ransomware field and notes retained |

MISP source aliases are not independently verified identities. Ambiguous aliases do not cause automatic entity merging. An explicit MITRE external reference is preferred. Sync MITRE before MISP and indicator feeds.

ThreatFox and URLhaus credentials are Worker secrets (`THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`). Feeds can require commercial agreements. Redistribution is denied by default except explicitly permitted sources; review the provider's current terms before commercial distribution. Source-level redistribution settings are conservative and do not replace a legal review of derivative intelligence.

Optional adapters in `packages/intel/src/optional-feeds.ts` implement OTX subscribed pulses, VirusTotal observable lookup, GreyNoise Community lookup, TAXII object envelopes, generic STIX and MISP attributes. They are disabled unless configured explicitly. The MVP operations UI exposes required feeds; custom optional endpoints are operator-configured. External enrichment failures are independent jobs and do not halt unrelated processing.

Custom endpoints require a configured HTTPS URL and exact approved DNS hostname. URL redirects are rejected. Never populate those settings from threat-feed content. Arbitrary URL inspection, crawling, passive DNS vendor contracts and sandbox execution are outside this release.

The recent-URL endpoint is a bounded window, not a full URLhaus historical mirror. ATT&CK imports enterprise data; mobile and ICS collections can use the same STIX adapter as separately configured sources. Feed payload limits are explicit. Larger archives need provider pagination or split files; compressed archives are not accepted.

References: [MITRE STIX](https://github.com/mitre-attack/attack-stix-data), [MISP Galaxy](https://github.com/MISP/misp-galaxy), [ThreatFox API](https://threatfox.abuse.ch/api/), [URLhaus API](https://urlhaus-api.abuse.ch/), [Feodo](https://feodotracker.abuse.ch/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
