CREATE TABLE relationship_assertions (
 id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL, source_id TEXT NOT NULL REFERENCES sources(id),
 data TEXT NOT NULL CHECK(json_valid(data)), recorded_at TEXT NOT NULL
);
-- statement-breakpoint
CREATE INDEX relationship_assertion_history ON relationship_assertions(relationship_id,recorded_at DESC,id);
-- statement-breakpoint
INSERT INTO relationship_assertions SELECT 'legacy:'||id,id,source_id,data,created_at FROM relationships;
-- statement-breakpoint
CREATE TRIGGER change_evidence_updated AFTER UPDATE ON evidence
WHEN json_extract(OLD.data,'$.data')!=json_extract(NEW.data,'$.data') AND EXISTS(SELECT 1 FROM entities WHERE id=NEW.entity_id AND public_intel=1) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
BEGIN
INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at) VALUES(lower(hex(randomblob(16))),NULL,NEW.entity_id,'evidence.updated',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
END;
-- statement-breakpoint
CREATE TRIGGER change_assessment_updated AFTER UPDATE ON assessments
WHEN OLD.data!=NEW.data AND EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=NEW.tenant_id AND status='active')
BEGIN
INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at) VALUES(lower(hex(randomblob(16))),NEW.tenant_id,NEW.observable_id,'score.changed',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
END;
