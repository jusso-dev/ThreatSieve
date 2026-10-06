CREATE TRIGGER change_tag_created AFTER INSERT ON entity_tags
WHEN EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=NEW.tenant_id AND status='active')
BEGIN
INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at) VALUES(lower(hex(randomblob(16))),NEW.tenant_id,NEW.entity_id,'indicator.updated',NEW.tag,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
END;
-- statement-breakpoint
CREATE TRIGGER change_tag_removed AFTER DELETE ON entity_tags
WHEN EXISTS(SELECT 1 FROM workspace_objects WHERE tenant_id=OLD.tenant_id AND status='active')
BEGIN
INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at) VALUES(lower(hex(randomblob(16))),OLD.tenant_id,OLD.entity_id,'indicator.updated',OLD.tag,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
END;
