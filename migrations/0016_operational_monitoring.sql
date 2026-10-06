CREATE TABLE operational_heartbeats(name TEXT PRIMARY KEY,updated_at TEXT NOT NULL);
CREATE TABLE integration_heartbeats(tenant_id TEXT NOT NULL REFERENCES tenants(id),connector_id TEXT NOT NULL,last_poll_at TEXT NOT NULL,last_success_at TEXT,status TEXT NOT NULL CHECK(status IN ('ok','error')),error_type TEXT,version TEXT NOT NULL,PRIMARY KEY(tenant_id,connector_id));
CREATE INDEX jobs_operational_scope ON pipeline_jobs(tenant_id,status,updated_at);
CREATE INDEX classification_usage_window ON classification_runs(tenant_id,created_at);
