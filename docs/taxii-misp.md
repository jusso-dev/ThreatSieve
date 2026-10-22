# TAXII and MISP interoperability

## TAXII 2.1 publication

ThreatSieve provides a read-only [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) API over explicit collection snapshots. Create a collection, choose TAXII publication, set its status to Published, then publish its current snapshot. Editing a collection does not silently change a snapshot already consumed downstream. Playbooks can request republication.

Send `Authorization: Bearer <scoped API key>` and `Accept: application/taxii+json;version=2.1`. The key needs `intel:read` in the collection's tenant.

| Endpoint                                                    | Purpose                                                   |
| ----------------------------------------------------------- | --------------------------------------------------------- |
| `/v1/taxii/`                                                | Discovery                                                 |
| `/v1/taxii/api/`                                            | API root information                                      |
| `/v1/taxii/api/collections/`                                | Published collections visible to the authenticated tenant |
| `/v1/taxii/api/collections/:id/`                            | Collection metadata; `can_write: false`                   |
| `/v1/taxii/api/collections/:id/objects/`                    | STIX envelope                                             |
| `/v1/taxii/api/collections/:id/manifest/`                   | Object IDs, versions and date added                       |
| `/v1/taxii/api/collections/:id/objects/:objectId/`          | Specific object                                           |
| `/v1/taxii/api/collections/:id/objects/:objectId/versions/` | Versions in the current snapshot                          |

Object/manifest requests support `added_after`, `match[id]`, `match[type]`, `match[version]`, `limit` (1–200) and opaque `next`. Pagination sorts by date added, ID and version. Date-added headers are returned. A snapshot changes atomically after export completes; an old continuation token returns 409 and the client must restart. Publication retains one current version per object, so first/last/all version selection refers to that snapshot. Collections are tenant-authenticated, never anonymous public endpoints. Writes to TAXII endpoints return 405; use collection APIs or import workflows.

Source redistribution restrictions apply to export. Tenant sightings remain private and are not automatically exported as global STIX sightings. Existing assessment export metadata distinguishes source assertions, model inference and analyst confirmation. Reports can be included through references; authored report text remains explicitly analyst-authored.

## TAXII / STIX / MISP collection

Optional feed adapters are wired into the existing source-sync, R2 archive, normalization, quarantine and checkpoint pipeline. Configure operator-approved shared intelligence feeds using encrypted Worker environment values:

- `TAXII_ENABLED=true`, `TAXII_ENDPOINT` (collection objects URL), `TAXII_ALLOWED_HOST`, optional `TAXII_API_KEY`.
- `STIX_ENABLED=true`, `STIX_ENDPOINT`, `STIX_ALLOWED_HOST`, optional `STIX_API_KEY`.
- `MISP_FEED_ENABLED=true`, `MISP_FEED_ENDPOINT`, `MISP_FEED_ALLOWED_HOST`, optional `MISP_FEED_API_KEY`.
- `OTX_ENABLED=true`, `OTX_API_KEY` for subscribed pulses.

Endpoints require HTTPS, exact approved hostnames and no redirects. They are deployment configuration, never taken from threat-report text. These adapters import shared threat intelligence; do not configure tenant-private telemetry as a global feed. Enable the corresponding source's scheduler flag after reviewing its terms, or use Sync now. Credentials are not returned to the frontend.

### Additional TAXII sources

The `TAXII_*` values configure one source (`taxii`), which the production deployment uses for OpenCTI. Further TAXII 2.1 sources are configured as a JSON array in the `TAXII_SOURCES` Worker value. Each entry becomes its own source with its own checkpoint, sync lock, independence group, licence record and schedule; the `taxii` slot is unchanged.

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
    "page_limit": 100,
    "schedule": "6h",
    "license": "Foiled honeypot intelligence, operator terms",
    "redistributable": true,
    "commercial_use": null
  }
]
```

- `id` must match `taxii-<name>` (lowercase letters, digits and hyphens). The source row is created on first use with reliability 0.5 and the given licence fields; later edits to the row are kept, except `redistributable`, which always follows this configuration.
- `endpoint` is the collection's objects URL, or the API root URL when `collection` is set (the objects URL is then `<root>/collections/<collection>/objects/`). It must be HTTPS on `allowed_host`; redirects, IP literals and `.local` names are rejected.
- `api_key_secret` names the Worker secret holding the bearer token, and must look like `TAXII_<NAME>_API_KEY` or `TAXII_<NAME>_TOKEN`. Provision it with `wrangler secret put`. If it is named but missing, the source stays disabled.
- `tlp` is the allow-list of TLP markings to import: `clear` (or `white`), `green`, `amber`, `amber+strict`, `red`, `unmarked`. Default `["clear","green"]`. ThreatSieve recognises the standard STIX 2.1 TLP 1.0 and TLP 2.0 marking-definition IDs in `object_marking_refs`; an object takes its most restrictive TLP marking, and objects with no recognised TLP marking count as `unmarked`. Objects outside the list are skipped, not imported. The original `taxii` slot does not filter markings.
- `schedule` is `6h` (each six-hourly run), `daily` (at most once in 20 hours) or `manual` (Sync now only).
- `redistributable` defaults to `true`, as for every feed in this non-commercial deployment. Set it to `false` to keep a partner's records out of TAXII publication, exports and packages. Imported records keep the STIX `created_by_ref` as their original producer.

Invalid entries are skipped and logged, never partially applied.

To import a Foiled honeypot collection, including how TLP and redistribution are handled, see [Foiled](foiled.md#importing-foiled-intelligence-into-threatsieve).

TAXII next tokens and original `added_after` survive checkpoints. A page is committed only after its processing jobs finish; further pages enqueue another sync. Missing/repeating continuation tokens fail instead of silently losing records. OTX pagination follows numeric page tokens only on its pinned endpoint.

## MISP event exchange

The importer supports event attributes, object attributes, compound attributes such as `domain|ip-dst` and `filename|sha256`, tags/taxonomy strings, UUIDs and supplied galaxy/object metadata. It preserves the original MISP attribute, object/event identifiers and warninglist metadata when supplied. `to_ids` and tag presence do not independently establish maliciousness. Unsupported attribute types are not converted into invented indicators.

Download a collection, report or investigation as MISP JSON and import it into MISP through its event-import workflow. The exporter follows [MISP core format](https://www.misp-standard.org/rfc/misp-standard-core.html), uses stable attribute UUIDs, org-only distribution and `to_ids: false` until an analyst chooses detection use. STIX assertions and ThreatSieve provenance are retained in custom metadata. This is a deliberate reviewable exchange; no process overwrites an analyst-curated remote MISP event. MISP warninglist/taxonomy strings are retained, not treated as a complete local replica of MISP's policy engine.
