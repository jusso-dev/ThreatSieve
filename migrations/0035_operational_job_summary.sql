-- Answer the operations job summary from indexes alone. Row lookups walked the
-- overflow pages of each job's data JSON, so a large feed sync pushed
-- /v1/ops/status past the production probe's 30 second timeout.
CREATE INDEX IF NOT EXISTS jobs_operational_summary ON pipeline_jobs(tenant_id,status,updated_at,stage,created_at);
DROP INDEX IF EXISTS jobs_operational_scope;
CREATE INDEX IF NOT EXISTS jobs_unfinished_result ON pipeline_jobs(tenant_id,stage,status) WHERE result IS NOT NULL AND status!='complete';
