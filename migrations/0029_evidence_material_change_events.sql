-- Collection/archive metadata must not masquerade as new intelligence, while
-- observation dates and confidence changes must reach subscriptions and rules.
DROP TRIGGER change_evidence_updated;
-- statement-breakpoint
CREATE TRIGGER change_evidence_updated AFTER UPDATE ON evidence
WHEN json_remove(OLD.data,'$.provenance.retrievedAt','$.createdAt','$.rawKey')!=json_remove(NEW.data,'$.provenance.retrievedAt','$.createdAt','$.rawKey')
 AND EXISTS(SELECT 1 FROM entities WHERE id=NEW.entity_id AND public_intel=1)
 AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
BEGIN
INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at) VALUES(lower(hex(randomblob(16))),NULL,NEW.entity_id,'evidence.updated',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
END;
