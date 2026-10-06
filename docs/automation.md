# Event automation

Playbooks are deliberately smaller than a SOAR system. Administrators choose a trigger, deterministic criteria and up to five ordered actions. The owner's current membership and permissions are checked again when work executes. Paused rules do not execute.

Supported triggers are indicator creation/update, assessment score change, sighting creation, relationship creation, feed failure, investigation creation, watchlist match and requirement match. Watchlists can also notify on evidence creation/update. A score-change watchlist notification requires a change of at least 15 deterministic threat-score points. This is a policy threshold, not a calibrated probability.

Actions:

| Action               | Result                                                             |
| -------------------- | ------------------------------------------------------------------ |
| Notify               | Workspace notification with per-user read state                    |
| Tag                  | Tenant-specific entity tag                                         |
| Add to watchlist     | Tenant membership link with provenance to the playbook execution   |
| Create investigation | One idempotent investigation referencing the triggering entity     |
| Enrich               | Existing graph/semantic enrichment pipeline                        |
| Export               | Latest assessment enters the existing STIX/OpenCTI export pipeline |
| Publish TAXII        | Snapshot of an explicitly configured, published tenant collection  |
| Send webhook         | Queued HTTPS delivery to an operator-approved integration          |

SQL change records and outbox jobs are persisted atomically. Global changes fan out in bounded pages of 25 subscriptions; private changes only reach that tenant. Initial collection scans page through visible entities in batches of 20. Actions use stable event/rule/action identities, and completed executions are not repeated. Database actions are transactional. Queued external actions have separate pipeline job IDs and delivery status; an execution that queued a delivery is not proof the receiver accepted it. Queue retries, leases and dead-letter handling apply. Generated investigations and derived matches cannot recursively trigger unrestricted automation loops.

Automatic watchlist memberships survive unrelated analyst edits. Matching intelligence identifies playbook memberships and allows analysts to remove them; later matching events can add them again if the playbook remains active. Workspace tags are visible in entity dossiers, editable with audit history, and usable in collection criteria.

## Webhook configuration

Store configuration in the API Worker's encrypted environment using Wrangler secrets. `INTEGRATION_TARGETS` is a JSON array:

```json
[
  {
    "id": "soc-receiver",
    "name": "SOC event receiver",
    "url": "https://receiver.example.com/threatsieve",
    "allowedHost": "receiver.example.com",
    "tenantIds": ["your-tenant-id"],
    "secretName": "SOC_RECEIVER_TOKEN",
    "allowPrivateIdentifiers": false
  }
]
```

`INTEGRATION_SECRETS` is a JSON object mapping secret names to bearer tokens of at least 20 characters. Never commit these values. Only integration IDs and names are returned to the UI. Targets must use HTTPS on an explicitly allowlisted DNS host without credentials or nonstandard ports; literal IPs and local/internal hostnames are rejected. Operators control the target and its DNS. Redirects are not followed. Requests time out after ten seconds and response bodies are not logged.

The event contains an event ID/type, workspace identifier and entity ID/type/name. It contains no raw intelligence, asset details or telemetry context. Restricted public source identifiers cannot be delivered. Private tenant-owned identifiers require explicit operator permission through `allowPrivateIdentifiers: true` as well as the administrator's playbook. Receivers must deduplicate `Idempotency-Key` because delivery is at least once. Secret rotation happens outside playbooks.

No integration is enabled by default and no receiver is contacted by tests. OpenCTI continues to use the supported connector helper, not direct per-entity GraphQL mutations.
