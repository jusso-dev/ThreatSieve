# Foiled integration

[Foiled](https://github.com/jusso-dev/foiled) is a honeypot and deception platform. It uses ThreatSieve as its single external intelligence hub instead of integrating feeds itself: Foiled asks ThreatSieve about the addresses, domains, hashes and CVEs its sensors see, and ThreatSieve can import Foiled's own observations back over TAXII 2.1.

## What Foiled calls

| Route | Use |
| --- | --- |
| [`POST /v1/lookup`](api.md#bulk-lookup) | Reputation, scanner classification, network context, CVE context and relationships for up to 500 observables per call |
| `GET /v1/actors`, `GET /v1/campaigns`, `GET /v1/attack/techniques`, `GET /v1/entities/:id` | Actor, campaign and ATT&CK catalogue with aliases, external IDs, references and per-source licences |

All of these need only `intel:read`. Lookups never call Workers AI, never create assessments, and read only stored intelligence, imported datasets and cached source answers.

## Service binding

Foiled reaches the ThreatSieve API Worker through a [service binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/), so lookups do not leave Cloudflare's network or pass through a public hostname. In Foiled's Wrangler configuration:

```jsonc
{
  "services": [
    { "binding": "THREATSIEVE", "service": "threatsieve-api-production" },
  ],
}
```

Use `threatsieve-api-staging` for a staging Foiled. The deployment script names the API Worker `threatsieve-api-<stage>`. Both Workers must be in the same Cloudflare account.

```ts
const response = await env.THREATSIEVE.fetch("https://threatsieve/v1/lookup", {
  method: "POST",
  headers: {
    Authorization: "Bearer " + env.THREATSIEVE_API_KEY,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    observables: [{ type: "ipv4", value: "203.0.113.7" }],
    include: ["reputation", "network"],
  }),
});
```

The hostname in the URL is ignored by a service binding; the request goes to the API Worker's fetch handler and is authenticated by the API key exactly as over HTTPS. Browser session cookies and the web `Origin` check do not apply to key-authenticated requests. Tests on both sides use fakes and make no network calls.

## API key

Create a dedicated key in the ThreatSieve workspace (tenant) that should own Foiled's lookups. Use an admin session or admin key:

```sh
curl -X POST "$THREATSIEVE_API_ORIGIN/v1/api-keys" \
  -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"Foiled lookups","scopes":["intel:read"],"expiresAt":"2027-10-01T00:00:00.000Z"}'
```

The plaintext key is shown once. Store it only as a Foiled Worker secret:

```sh
pnpm exec wrangler secret put THREATSIEVE_API_KEY --name <foiled-worker>
```

Grant `intel:read` and nothing else. The key's tenant decides what Foiled sees: that tenant's source policy (`PUT /v1/feeds/:id/policy`), Admiralty source ratings and private observables. To rotate, create a new key, update the Foiled secret, then revoke the old key with `DELETE /v1/api-keys/:id`.

## Rate limits and caching

- Lookups use their own bucket: `LOOKUP_RATE_LIMIT` requests per minute per key (default 60) and five times that per tenant. Assessment and other API traffic does not count against it, and lookups do not count against them.
- A 429 response carries `Retry-After` in seconds. Back off for that long.
- Send up to 500 observables per request. Above that the API returns 413 `TOO_MANY_OBSERVABLES`. Batch rather than calling per event.
- Cache each result for no longer than its `ttl_seconds`. Results with non-empty `pending_sources` have a TTL of at most 300 seconds: ThreatSieve is fetching GreyNoise, CrowdSec or OSV after the response, and the next lookup after that will include the answer.
- GreyNoise and CrowdSec have small daily budgets (`GREYNOISE_DAILY_LIMIT`, default 7; `CROWDSEC_DAILY_LIMIT`, default 45). Most addresses will never have GreyNoise data on the community tier. Treat a missing `scanner` as unknown, not as "not a scanner".

## Licences and redistribution

Every result lists the sources behind its facts with `license`, `redistributable` and `commercial_use` (`null` when unknown). Foiled treats `redistributable: false` or `commercial_use: false` as never-resell and never-export: such facts are shown only to the tenant that looked them up and are not republished over Foiled's TAXII server. Where NVD contributes, the product must state "This product uses the NVD API but is not endorsed or certified by the NVD." See [licence records](intelligence-sources.md#licence-records).

Relationship `assertion` keeps ThreatSieve's values: `observed`, `source_claimed`, `analyst_confirmed`, `model_inferred`. None of them is attribution. Weight `model_inferred` lowest.

## Importing Foiled intelligence into ThreatSieve

Foiled publishes its honeypot observations over TAXII 2.1. ThreatSieve can import them with the existing generic [TAXII feed adapter](taxii-misp.md#taxii--stix--misp-collection); no code change is needed.

1. In Foiled, create a TAXII collection for ThreatSieve and a read-only credential for it. Put only objects marked TLP:CLEAR or TLP:GREEN, and only Foiled's own observations, in that collection. ThreatSieve's TAXII adapter does not read `object_marking_refs`, so TLP is enforced by what the collection exposes, as with the [OpenCTI reader](opencti.md#opencti-as-a-threatsieve-source). TLP:AMBER and TLP:RED objects must never be in it.
2. Exclude objects that came from ThreatSieve (for example enrichments Foiled stored from `/v1/lookup`). Re-importing them would make ThreatSieve count its own data as independent corroboration.
3. Set the API Worker values, using `wrangler secret put` for the token:
   - `TAXII_ENABLED=true`
   - `TAXII_ENDPOINT`: the collection's objects URL, for example `https://foiled.example.com/taxii2/<api-root>/collections/<collection-id>/objects/`
   - `TAXII_ALLOWED_HOST`: the exact hostname in `TAXII_ENDPOINT`
   - `TAXII_API_KEY`: the Foiled reader token, sent as a bearer token
   - `TAXII_PAGE_LIMIT` (optional, 1–1000, default 100)
4. Record Foiled's terms on the source row and enable the schedule, for example `UPDATE sources SET name='Foiled (TAXII 2.1)', license='Foiled honeypot intelligence, operator terms', redistributable=0, commercial_use=NULL, enabled=1 WHERE id='taxii'`. Then use **Sync now** (`POST /v1/feeds/taxii/sync`) or wait for the six-hourly schedule.

The endpoint must be HTTPS on an approved DNS name; redirects, IP literals and `.local` names are rejected. Imported records keep `redistributable: false` and Foiled's STIX `created_by_ref` as their original source, so they are never re-exported by ThreatSieve's own TAXII publication without an explicit decision, and the `taxii` independence group stops Foiled from being double-counted with itself.

There is one generic TAXII source. The production deployment already uses it for [OpenCTI](opencti.md#opencti-as-a-threatsieve-source). While OpenCTI holds it, either add Foiled to OpenCTI as a TAXII feed (OpenCTI then applies its TLP group filter before the data reaches ThreatSieve), or add a second TAXII source to ThreatSieve, which is a code change.
