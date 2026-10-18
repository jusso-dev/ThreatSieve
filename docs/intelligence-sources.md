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
| [IPtoASN](#iptoasn) | Daily whole-file import | IP range to ASN, AS name and country for [lookup](api.md#bulk-lookup); no per-request calls |
| [FIRST EPSS](#first-epss) | Daily CSV import | Exploit prediction score and percentile per CVE |
| [NVD](#nvd) | API 2.0, incremental by `lastModified` | CVE description, CVSS, CWE, affected products and references |
| [OSV](#osv) | Per-CVE lookup, cached | Advisory identifiers and affected packages |
| [GreyNoise](#greynoise-and-crowdsec) | Community API lookup, cached | Internet scanner and business-service classification (IPv4) |
| [CrowdSec CTI](#greynoise-and-crowdsec) | Smoke API lookup, cached | Behaviours, reputation and benign-service classification (IPv4, IPv6) |

MISP source aliases are not independently verified identities. Ambiguous aliases do not cause automatic entity merging. An explicit MITRE external reference is preferred. Sync MITRE before MISP and indicator feeds.

ThreatFox and URLhaus credentials are Worker secrets (`THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`). Feeds can require commercial agreements. Redistribution is denied by default except explicitly permitted sources; review the provider's current terms before commercial distribution. Source-level redistribution settings are conservative and do not replace a legal review of derivative intelligence.

Optional adapters in `packages/intel/src/optional-feeds.ts` implement OTX subscribed pulses, VirusTotal observable lookup, GreyNoise Community and CrowdSec CTI lookups, TAXII object envelopes, generic STIX, MISP attributes and [Yeti](#yeti) observables. They are disabled unless configured explicitly. The MVP operations UI exposes required feeds; custom optional endpoints are operator-configured. External enrichment failures are independent jobs and do not halt unrelated processing.

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

## Licence records

Each source row in D1 records `license`, `redistributable` and `commercial_use` (migration `0034`). `commercial_use` is 1 when the provider's terms permit commercial use, 0 when commercial use needs a separate agreement, and `NULL` when unknown or operator-defined. [`POST /v1/lookup`](api.md#bulk-lookup) returns these with every fact, and the entity and catalogue APIs return them in [`source_licences`](api.md#source-licences-on-entity-apis). They were set from the providers' published terms in October 2026. Review them before commercial distribution; they do not replace legal review.

| Source | Redistributable | Commercial use | Basis |
| --- | --- | --- | --- |
| MITRE ATT&CK | yes | yes | ATT&CK Terms of Use: royalty-free licence with attribution |
| MISP Galaxy | no | yes | Collection licences are CC0, BSD-2-Clause or CC BY-SA 4.0; redistribution stays off for share-alike review |
| ThreatFox, URLhaus, Feodo | no | no | abuse.ch fair use; commercial use needs an abuse.ch/Spamhaus agreement |
| CISA KEV | yes | yes | US government data, CC0 |
| IPtoASN | yes | yes | Public Domain Dedication and License (PDDL) 1.0, stated on iptoasn.com |
| FIRST EPSS | yes | yes | Published freely by FIRST; cite FIRST and EPSS |
| NVD | yes | yes | US government data; products must state "This product uses the NVD API but is not endorsed or certified by the NVD" |
| OSV | yes | unknown | OSV.dev aggregates many databases under their own licences (mostly CC-BY 4.0); check the record's source |
| GreyNoise | no | no | Community API terms: free tier, 50 lookups per week; commercial use needs a paid licence |
| CrowdSec CTI | no | no | CTI API terms; commercial use needs the CrowdSec partnership programme |
| VirusTotal | no | no | Public API terms prohibit commercial use |
| OTX, TAXII, STIX, MISP feed, Yeti | no | unknown | Account or operator terms |
| Customer, analyst, upload | no | unknown | Tenant-private |

## IPtoASN

[iptoasn.com](https://iptoasn.com/) publishes routed IPv4 and IPv6 ranges with the origin ASN, country and AS description, updated hourly, under the PDDL 1.0. ThreatSieve downloads `ip2asn-v4.tsv.gz` and `ip2asn-v6.tsv.gz` at most once a day from the six-hourly cron, archives both files under `raw/iptoasn/`, skips the import when they are unchanged, and writes sorted shards of 4,000 ranges plus an ASN table to R2 under `datasets/iptoasn/<version>/`. `dataset_versions` switches to the new version only after every shard is written. The previous version is kept for rollback; older derived shards are deleted because they can be rebuilt from the archived files.

Lookups binary-search the shard index, so `/v1/lookup` never calls a third party for network context. Unrouted space returns no network. `prefix` is the largest CIDR block that holds the address and stays inside the announced range; iptoasn ranges are not always CIDR-aligned. Country is the registry country of the range, not geolocation of the host. No key is needed. Set the `iptoasn` source's `enabled` to 0 to stop imports.

## FIRST EPSS

[EPSS](https://www.first.org/epss/) publishes a daily probability (0–1) and percentile of exploitation activity for every published CVE. ThreatSieve fetches the dated file `epss_scores-YYYY-MM-DD.csv.gz` from `epss.empiricalsecurity.com` (the `-current` alias redirects, and feeds refuse redirects), falling back to the previous day before today's file appears. The file is archived, parsed, sorted and stored as R2 shards in the same way as IPtoASN. The score date from the file header is reported as `epss.date`. EPSS is a prioritisation signal, not evidence that a vulnerability has been exploited.

## NVD

The [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) supplies descriptions, CVSS, CWE, CPE-derived affected products and references, upserted into `cve_records`. The first run pages through every CVE (`NVD_PAGE_SIZE`, default and maximum 1,000; larger values are clamped, and a page body over 32 MiB is refused). It then switches to `lastModStartDate`/`lastModEndDate` windows of at most 120 days, starting from the time the backfill began, so records changed during the backfill are caught. Each five-minute tick fetches one page without a key and up to three pages six seconds apart with `NVD_API_KEY` (a Worker secret), well inside NVD's limits of 5 and 50 requests per 30 seconds. Once caught up, incremental windows run every two hours. Raw pages are archived under `raw/nvd/`. An update never replaces a record with an older `lastModified`.

`cve.cvss` prefers NVD's primary score, newest CVSS version first (4.0, 3.1, 3.0, 2.0), then a CNA's secondary score. Affected products come from vulnerable CPE matches, or from the CVE record's `affected` data when NVD has not analysed the CVE. Any product that shows NVD data must carry the NVD notice in the table above.

## OSV

[OSV.dev](https://osv.dev/) is queried at `GET /v1/vulns/<CVE>` for CVEs passed to `/v1/lookup`, after the response, at most 25 per request and `OSV_DAILY_LIMIT` (default 2,000) per day. Results, including "no record", are cached for 24 hours. `osv_ids` lists the record's aliases and related advisories (GHSA, distribution advisories). OSV holds a record under the CVE identifier only for some CVEs; a GHSA that merely aliases a CVE is not found this way. No key is needed.

## GreyNoise and CrowdSec

Both are lookup-only sources. They are never bulk-synced (`POST /v1/feeds/:id/sync` returns 409 `FEED_NOT_SYNCABLE`) and stay disabled until their Worker secret exists: `GREYNOISE_API_KEY` for the [GreyNoise Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) (IPv4 only) and `CROWDSEC_API_KEY` for the [CrowdSec CTI smoke API](https://docs.crowdsec.net/u/cti_api/intro) (IPv4 and IPv6). When `/v1/lookup` sees an address without a fresh cached answer, it reads today's remaining budget (one query for all sources), claims up to the per-request cap of misses in one statement, charges the budget for what it claimed, and queues one refresh job per source on the enrich queue. Misses over the per-request cap but within the budget are reported as pending and claimed by later lookups; once the budget is spent, lookups stop claiming and make no further provider calls that day. Budgets: `GREYNOISE_DAILY_LIMIT` (default 7, because the free tier allows 50 lookups per week) and `CROWDSEC_DAILY_LIMIT` (default 45, against a free allowance of 1,500 per month), with at most 5 and 10 new lookups per request. Budgets are global per source, because the provider quota belongs to the operator's key. Refresh jobs retry with backoff; on the last attempt a failure is cached for 15 minutes and its budget unit refunded. Answers and "not observed" results are cached for 24 hours. Raw answers are archived under `raw/<source>/lookups/`.

Answers are normalised by the existing adapters in `optional-feeds.ts` and stored only in `source_lookup_cache`, partitioned by tenant. They never enter the shared graph, and a tenant never sees another tenant's answers, lookup times or pending state. The same address looked up by two tenants costs two provider calls.

**Licence.** The GreyNoise Community API and the free CrowdSec CTI key are for non-commercial use. Every answer is labelled `commercial_use: false` and `redistributable: false`, but labels do not change the terms: serving these answers to customers of a commercial service needs a commercial GreyNoise licence or CrowdSec partnership. Provision the keys only where that is settled, and exclude the sources per tenant (`PUT /v1/feeds/:id/policy`) for tenants that must not receive them.

- GreyNoise `noise` (seen scanning the internet in the last 90 days) sets `scanner.is_scanner`. `riot` (a known business service) or a `benign` classification sets `scanner.benign_service`. Classification `malicious` is a malicious assertion; RIOT is a benign one.
- CrowdSec `scanner:*` classifications or `*scan*` behaviours set `is_scanner`. False-positive classifications (CDNs, crawlers) or a `benign`/`safe` reputation set `benign_service`. Reputation `malicious` is a malicious assertion. Behaviour and classification names become tags.

References: [MITRE STIX](https://github.com/mitre-attack/attack-stix-data), [MISP Galaxy](https://github.com/MISP/misp-galaxy), [ThreatFox API](https://threatfox.abuse.ch/api/), [URLhaus API](https://urlhaus-api.abuse.ch/), [Feodo](https://feodotracker.abuse.ch/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
