-- Copy all legacy assertions into provider-local namespaces unless explicit
-- original identity was already captured. Do not infer mirrors from local IDs.
CREATE TABLE entity_sources_namespaced (
  entity_id TEXT NOT NULL REFERENCES entities(id),
  source_id TEXT NOT NULL REFERENCES sources(id),
  source_record_id TEXT NOT NULL,
  provenance TEXT NOT NULL CHECK(json_valid(provenance)),
  record_namespace TEXT NOT NULL,
  original_source_id TEXT NOT NULL,
  PRIMARY KEY(entity_id,source_id,record_namespace,source_record_id)
);
INSERT INTO entity_sources_namespaced SELECT entity_id,source_id,source_record_id,provenance,COALESCE(json_extract(provenance,'$.sourceRecordNamespace'),source_id),COALESCE(json_extract(provenance,'$.originalSourceId'),source_id) FROM entity_sources;
DROP TABLE entity_sources;
ALTER TABLE entity_sources_namespaced RENAME TO entity_sources;
CREATE INDEX entity_sources_source ON entity_sources(source_id,entity_id);
CREATE INDEX entity_sources_record_lookup ON entity_sources(source_id,source_record_id,entity_id);
CREATE INDEX entity_sources_upstream_lookup ON entity_sources(source_record_id,entity_id);
CREATE INDEX entity_sources_namespaced_lookup ON entity_sources(record_namespace,source_record_id,entity_id);
