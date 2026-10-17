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

Optional adapters in `packages/intel/src/optional-feeds.ts` implement OTX subscribed pulses, VirusTotal observable lookup, GreyNoise Community lookup, TAXII object envelopes, generic STIX, MISP attributes and [Yeti](#yeti) observables. They are disabled unless configured explicitly. The MVP operations UI exposes required feeds; custom optional endpoints are operator-configured. External enrichment failures are independent jobs and do not halt unrelated processing.

Custom endpoints require a configured HTTPS URL and exact approved DNS hostname. URL redirects are rejected. Never populate those settings from threat-feed content. Arbitrary URL inspection, crawling, passive DNS vendor contracts and sandbox execution are outside this release.

The recent-URL endpoint is a bounded window, not a full URLhaus historical mirror. ATT&CK imports enterprise data; mobile and ICS collections can use the same STIX adapter as separately configured sources. Feed payload limits are explicit. Larger archives need provider pagination or split files; compressed archives are not accepted.

## Yeti

[Yeti](https://yeti-platform.io/) is an open-source forensic intelligence platform. ThreatSieve imports observables from a Yeti instance through its v2 API. It does not write to Yeti.

Set these Worker values, then enable the `yeti` source in source operations or use Sync now:

- `YETI_ENABLED=true`
- `YETI_ENDPOINT`: the instance base URL, such as `https://yeti.example.org/`. A path prefix is kept if Yeti sits behind one.
- `YETI_ALLOWED_HOST`: the exact hostname in `YETI_ENDPOINT`.
- `YETI_API_KEY`: a Yeti user API key, provisioned with `wrangler secret put`. Give it a read-only account.
- `YETI_TAGS` (optional): comma-separated tags. Only observables carrying every listed tag are imported. Use this to pull a curated subset rather than everything Yeti has collected.
- `YETI_PAGE_LIMIT` (optional): observables per request, 1 to 1000, default 100.

Each sync exchanges the API key for a short-lived token at `/api/v2/auth/api-token`, then searches `/api/v2/observables/search` for observables modified since the last checkpoint, oldest first. Full pages enqueue another sync. The first sync backfills the whole instance (or tag selection), so start with `YETI_TAGS` on a large instance.

Mapping rules:

- Yeti `hostname` values become `domain` or `hostname` through normal ThreatSieve detection. IPv4, IPv6, CIDR, URL, email, MD5, SHA-1, SHA-256, JA3, ASN, mutex, registry key and user agent map directly.
- Other Yeti types, such as `file`, `path` and `command_line`, are skipped. Values that fail ThreatSieve validation are skipped too.
- Tags and their freshness are kept as evidence. Expired tags are listed separately. The latest tag `last_seen` is the observation time. With no tags, observation time stays unknown.
- Neither tags nor presence in Yeti mark an observable malicious.
- Yeti `context` source names are retained as `contextSources`.

Yeti often aggregates public feeds, including abuse.ch. The `yeti` source is its own independence group, so the same indicator arriving from Yeti and directly from ThreatFox counts as two sources. Check `contextSources` and lower the source's reliability, or use `YETI_TAGS` to import only your own analysis, if that double-counting matters for your scoring.

The instance must be reachable over HTTPS on an approved DNS name. Private IP addresses, `.local` names and redirects are rejected, as with the other custom endpoints.

References: [MITRE STIX](https://github.com/mitre-attack/attack-stix-data), [MISP Galaxy](https://github.com/MISP/misp-galaxy), [ThreatFox API](https://threatfox.abuse.ch/api/), [URLhaus API](https://urlhaus-api.abuse.ch/), [Feodo](https://feodotracker.abuse.ch/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
