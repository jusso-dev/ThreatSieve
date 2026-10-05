CREATE TABLE feed_rejections (id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), job_id TEXT NOT NULL REFERENCES pipeline_jobs(id), raw_key TEXT NOT NULL, record_offset INTEGER NOT NULL, error_type TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX feed_rejections_source ON feed_rejections(source_id,created_at DESC);
CREATE TABLE vector_versions (entity_id TEXT PRIMARY KEY REFERENCES entities(id), evidence_version TEXT NOT NULL, model TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE request_idempotency (tenant_id TEXT NOT NULL REFERENCES tenants(id), request_key TEXT NOT NULL, body_hash TEXT NOT NULL, job_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,request_key));
CREATE TABLE feed_locks (source_id TEXT PRIMARY KEY REFERENCES sources(id), job_id TEXT NOT NULL, acquired_at TEXT NOT NULL);
