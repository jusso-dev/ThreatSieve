-- One outcome per input, durable across queue redelivery and manual replay.
CREATE TABLE bulk_items (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  bulk_id TEXT NOT NULL REFERENCES pipeline_jobs(id),
  input_index INTEGER NOT NULL,
  observable_id TEXT,
  outcome TEXT NOT NULL CHECK(outcome IN ('accepted','duplicates','rejected')),
  error TEXT,
  PRIMARY KEY(tenant_id,bulk_id,input_index)
);
CREATE UNIQUE INDEX bulk_unique_accepted ON bulk_items(tenant_id,bulk_id,observable_id) WHERE outcome='accepted';
CREATE INDEX bulk_outcome_lookup ON bulk_items(tenant_id,bulk_id,outcome,input_index);
