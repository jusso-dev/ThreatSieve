ALTER TABLE entities ADD COLUMN public_intel INTEGER NOT NULL DEFAULT 1;
CREATE TABLE tenant_observables (tenant_id TEXT NOT NULL REFERENCES tenants(id), observable_id TEXT NOT NULL REFERENCES observables(id), created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,observable_id));
CREATE INDEX entity_visibility ON entities(public_intel,type,name);
CREATE INDEX jobs_correlation ON pipeline_jobs(json_extract(data,'$.correlationId'),status);
CREATE UNIQUE INDEX exports_assessment ON exports(tenant_id,assessment_id);
