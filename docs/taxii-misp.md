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

TAXII next tokens and original `added_after` survive checkpoints. A page is committed only after its processing jobs finish; further pages enqueue another sync. Missing/repeating continuation tokens fail instead of silently losing records. OTX pagination follows numeric page tokens only on its pinned endpoint.

## MISP event exchange

The importer supports event attributes, object attributes, compound attributes such as `domain|ip-dst` and `filename|sha256`, tags/taxonomy strings, UUIDs and supplied galaxy/object metadata. It preserves the original MISP attribute, object/event identifiers and warninglist metadata when supplied. `to_ids` and tag presence do not independently establish maliciousness. Unsupported attribute types are not converted into invented indicators.

Download a collection, report or investigation as MISP JSON and import it into MISP through its event-import workflow. The exporter follows [MISP core format](https://www.misp-standard.org/rfc/misp-standard-core.html), uses stable attribute UUIDs, org-only distribution and `to_ids: false` until an analyst chooses detection use. STIX assertions and ThreatSieve provenance are retained in custom metadata. This is a deliberate reviewable exchange; no process overwrites an analyst-curated remote MISP event. MISP warninglist/taxonomy strings are retained, not treated as a complete local replica of MISP's policy engine.
