CREATE TABLE tenant_source_policy (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),source_id TEXT NOT NULL REFERENCES sources(id),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),reason TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,source_id)
);
CREATE INDEX feedback_source_reviews ON analyst_feedback(tenant_id,field,created_at DESC);
