# Asynchronous collection packages

Open a collection and choose **Prepare STIX package**. The export snapshots up to 100,000 matched entity IDs and explicit entity references. The existing export queue processes 50 entities or relationships per job. Assessment references are exported in the initial bounded part. Linked reports/investigations must be exported separately; requests containing those references receive a clear validation error.

The manifest lists non-empty STIX parts, SHA-256 hashes, object counts, collection revision and expiry. Download every listed part: relationships can refer to objects in other parts. Consumers should deduplicate STIX IDs when combining bundles. A configured size limit is not a production throughput guarantee.

```http
POST /v1/collections/:id/packages
Content-Type: application/json

{"requestId":"a-client-generated-uuid"}
```

Reusing `requestId` for the same collection and tenant returns the same package. Poll `GET /v1/collection-packages/:id`, then retrieve `GET /v1/collection-packages/:id/parts/:part` for each listed part. Authentication is required throughout. Processing failures reference the existing replayable pipeline job.

Membership is fixed at request time; intelligence is captured during processing. The collection revision and access are rechecked during processing and every download. Only the requesting analyst or a workspace administrator can retrieve a package, and the current collection ACL still applies. Private foreign entities, nonredistributable intelligence and disabled sources are excluded. Downloads fail closed if access/source rights change, a relationship is rejected, an assessment is revised or the collection changes. Regenerate the package after those changes.

Retries use content-addressed R2 objects and persisted continuation state. SHA-256 checks are verified before download. Packages expire after 24 hours. Maintenance removes expired export copies in bounded batches after a one-hour grace period; original intelligence, assessments, evidence and audit history are retained. This temporary-file policy is separate from customer intelligence retention.
