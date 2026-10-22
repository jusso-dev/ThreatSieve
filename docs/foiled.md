# Foiled integration

[Foiled](https://github.com/jusso-dev/foiled) is a honeypot and deception platform. It uses ThreatSieve as its single external intelligence hub instead of integrating feeds itself: Foiled asks ThreatSieve about the addresses, domains, hashes and CVEs its sensors see, and ThreatSieve can import Foiled's own observations back over TAXII 2.1.

## What Foiled calls

| Route                                                                                      | Use                                                                                                                                                               |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`POST /v1/lookup`](api.md#bulk-lookup)                                                    | Reputation, scanner classification, network context, CVE context and relationships for up to 500 observables per call                                             |
| `GET /v1/actors`, `GET /v1/campaigns`, `GET /v1/attack/techniques`, `GET /v1/entities/:id` | Actor, campaign and ATT&CK catalogue with aliases, external IDs, references and per-source licences in [`source_licences`](api.md#source-licences-on-entity-apis) |

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

Every lookup result lists the sources behind its facts with `license`, `redistributable` and `commercial_use` (`null` when unknown). Catalogue and entity responses carry the same objects in `source_licences`, so Foiled reads licence flags per source from ThreatSieve instead of keeping its own copy of the licence table. Foiled treats `redistributable: false` or `commercial_use: false` as never-resell and never-export: such facts are shown only to the tenant that looked them up and are not republished over Foiled's TAXII server. Where NVD contributes, the product must state "This product uses the NVD API but is not endorsed or certified by the NVD." See [licence records](intelligence-sources.md#licence-records).

Relationship `assertion` keeps ThreatSieve's values: `observed`, `source_claimed`, `analyst_confirmed`, `model_inferred`. None of them is attribution. Weight `model_inferred` lowest.

## Importing Foiled intelligence into ThreatSieve

Foiled publishes its honeypot observations over TAXII 2.1. ThreatSieve imports them as an [additional TAXII source](taxii-misp.md#additional-taxii-sources), alongside the OpenCTI source that already uses the original `taxii` slot. No code change is needed.

1. In Foiled, create a TAXII collection for ThreatSieve and a read-only credential for it. Put only Foiled's own observations in it. Exclude anything Foiled obtained from ThreatSieve (such as enrichments stored from `/v1/lookup`): re-importing it would make ThreatSieve count its own data as independent corroboration.
2. Mark objects with standard TLP markings. ThreatSieve imports only the TLP levels in the source's `tlp` allow-list (default TLP:CLEAR and TLP:GREEN) and skips unmarked objects unless `unmarked` is listed. Keep TLP:AMBER and TLP:RED out of the collection anyway, so the allow-list is a second control rather than the only one.
3. Store the reader token as a Worker secret: `pnpm exec wrangler secret put TAXII_FOILED_API_KEY --name threatsieve-api-<stage>`.
4. Add an entry to the `TAXII_SOURCES` Worker value:

   ```json
   [
     {
       "id": "taxii-foiled",
       "name": "Foiled (TAXII 2.1)",
       "endpoint": "https://foiled.example.com/taxii2/foiled/",
       "collection": "<collection-id>",
       "allowed_host": "foiled.example.com",
       "api_key_secret": "TAXII_FOILED_API_KEY",
       "tlp": ["clear", "green"],
       "schedule": "6h",
       "license": "Foiled honeypot intelligence, operator terms",
       "redistributable": true,
       "commercial_use": null
     }
   ]
   ```

5. Deploy. The `taxii-foiled` source row is created on the next feed listing, Sync now or scheduled run. Use **Sync now** (`POST /v1/feeds/taxii-foiled/sync`) or wait for the six-hourly schedule.

The endpoint must be HTTPS on the approved hostname; redirects, IP literals and `.local` names are rejected. Imported records are redistributable, like every feed in this non-commercial deployment, so ThreatSieve's own TAXII publication re-shares them; set `"redistributable": false` to stop that. They keep Foiled's STIX `created_by_ref` as their original source. The source has its own `taxii-foiled` independence group, so Foiled is not double-counted with itself, and tenants can exclude it with `PUT /v1/feeds/taxii-foiled/policy`.
