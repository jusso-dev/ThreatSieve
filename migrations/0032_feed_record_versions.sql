CREATE TABLE feed_record_versions (
  source_id TEXT NOT NULL,
  record_key TEXT NOT NULL,
  material_version TEXT NOT NULL,
  entity_id TEXT,
  collected_at TEXT NOT NULL,
  delivery_token TEXT NOT NULL,
  PRIMARY KEY(source_id,record_key)
);
-- Used only within a D1 batch. A lost compare-and-swap rolls back all writes,
-- including provenance, evidence-change triggers and downstream delivery.
CREATE TABLE pipeline_commit_guard (
  token TEXT PRIMARY KEY,
  won INTEGER NOT NULL CHECK(won=1)
);
