-- Preserve old exports and add immutable versions for corrected assessments.
ALTER TABLE assessments ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
CREATE TABLE assessment_exports (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), assessment_id TEXT NOT NULL, revision INTEGER NOT NULL, r2_key TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(tenant_id,assessment_id,revision));
INSERT INTO assessment_exports SELECT id,tenant_id,assessment_id,0,r2_key,created_at FROM exports;
CREATE INDEX assessment_exports_cursor ON assessment_exports(tenant_id,created_at,id);
CREATE INDEX assessments_review_cursor ON assessments(tenant_id,status,created_at DESC,id);
CREATE INDEX pipeline_bulk_scope ON pipeline_jobs(tenant_id,json_extract(data,'$.payload.bulkId'),stage,status);
