CREATE TABLE entity_sources (entity_id TEXT NOT NULL REFERENCES entities(id), source_id TEXT NOT NULL REFERENCES sources(id), source_record_id TEXT NOT NULL, provenance TEXT NOT NULL CHECK(json_valid(provenance)), PRIMARY KEY(entity_id,source_id,source_record_id));
CREATE INDEX entity_sources_source ON entity_sources(source_id,entity_id);
