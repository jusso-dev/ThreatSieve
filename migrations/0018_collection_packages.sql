-- Immutable collection membership snapshots. Content is revalidated before download.
CREATE TABLE collection_packages (
  id TEXT NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  collection_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  matched_count INTEGER NOT NULL CHECK(matched_count<=100000),
  requested_by TEXT NOT NULL,
  principal TEXT NOT NULL CHECK(json_valid(principal)),
  snapshot TEXT NOT NULL CHECK(json_valid(snapshot)),
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','complete')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id,id)
);
CREATE INDEX collection_packages_collection ON collection_packages(tenant_id,collection_id,created_at);
CREATE TABLE collection_package_members (
  tenant_id TEXT NOT NULL,
  package_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  PRIMARY KEY(tenant_id,package_id,entity_id),
  FOREIGN KEY(tenant_id,package_id) REFERENCES collection_packages(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE collection_package_parts (
  tenant_id TEXT NOT NULL,
  package_id TEXT NOT NULL,
  part INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  object_count INTEGER NOT NULL,
  member_ids TEXT NOT NULL CHECK(json_valid(member_ids)),
  continuation TEXT NOT NULL CHECK(json_valid(continuation)),
  created_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id,package_id,part),
  FOREIGN KEY(tenant_id,package_id) REFERENCES collection_packages(tenant_id,id) ON DELETE CASCADE
);

CREATE INDEX pipeline_package_jobs ON pipeline_jobs(tenant_id,json_extract(data,'$.payload.packageId'),status);
CREATE INDEX collection_packages_expiry ON collection_packages(expires_at);
