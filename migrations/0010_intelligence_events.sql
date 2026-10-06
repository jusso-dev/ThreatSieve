CREATE TABLE intelligence_changes (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
 tenant_id TEXT, entity_id TEXT NOT NULL, event_type TEXT NOT NULL,
 reference_id TEXT NOT NULL, created_at TEXT NOT NULL, queued_at TEXT
);
-- statement-breakpoint
CREATE INDEX intelligence_changes_pending ON intelligence_changes(queued_at,sequence);
-- statement-breakpoint
CREATE TABLE workspace_matches (
 tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, entity_id TEXT NOT NULL,
 evidence_ids TEXT NOT NULL CHECK(json_valid(evidence_ids)), criteria TEXT NOT NULL CHECK(json_valid(criteria)),
 event_id TEXT NOT NULL, matched_at TEXT NOT NULL, score REAL,
 PRIMARY KEY(tenant_id,object_id,entity_id),
 FOREIGN KEY(tenant_id,object_id) REFERENCES workspace_objects(tenant_id,id)
);
-- statement-breakpoint
CREATE INDEX matches_entity ON workspace_matches(tenant_id,entity_id,object_id);
-- statement-breakpoint
CREATE TABLE entity_tags (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), entity_id TEXT NOT NULL REFERENCES entities(id),
 tag TEXT NOT NULL, actor_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,entity_id,tag)
);
-- statement-breakpoint
CREATE TABLE notification_receipts (
 tenant_id TEXT NOT NULL, notification_id TEXT NOT NULL, user_id TEXT NOT NULL, read_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,notification_id,user_id),
 FOREIGN KEY(tenant_id,notification_id) REFERENCES workspace_notifications(tenant_id,id)
);
-- statement-breakpoint
CREATE TRIGGER change_entity_created AFTER INSERT ON entities
 WHEN (NEW.public_intel=1) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NULL,NEW.id,'indicator.created',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_entity_updated AFTER UPDATE ON entities
 WHEN (NEW.public_intel=1 AND (json_extract(OLD.data,'$.data')!=json_extract(NEW.data,'$.data') OR json_extract(OLD.data,'$.aliases')!=json_extract(NEW.data,'$.aliases') OR OLD.name!=NEW.name OR COALESCE(json_extract(OLD.data,'$.description'),'')!=COALESCE(json_extract(NEW.data,'$.description'),''))) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NULL,NEW.id,'indicator.updated',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_evidence_created AFTER INSERT ON evidence
 WHEN (EXISTS(SELECT 1 FROM entities WHERE id=NEW.entity_id AND public_intel=1)) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NULL,NEW.entity_id,'evidence.created',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_relationship_created AFTER INSERT ON relationships
 WHEN (EXISTS(SELECT 1 FROM entities WHERE id=NEW.source_entity_id AND public_intel=1) AND EXISTS(SELECT 1 FROM entities WHERE id=NEW.target_entity_id AND public_intel=1)) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NULL,NEW.source_entity_id,'relationship.created',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_assessment_created AFTER INSERT ON assessments
 WHEN (1) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NEW.tenant_id,NEW.observable_id,'score.changed',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_operation_event AFTER INSERT ON intelligence_events
 WHEN (NEW.event_type IN ('sighting.created','watchlist.match','requirement.match') OR (NEW.event_type='investigation.created' AND NEW.actor_id NOT LIKE 'automation:%')) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NEW.tenant_id,NEW.subject_id,NEW.event_type,NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
-- statement-breakpoint
CREATE TRIGGER change_source_failed AFTER UPDATE ON sources
 WHEN (NEW.errors>OLD.errors) AND EXISTS(SELECT 1 FROM workspace_objects WHERE status IN ('active','published'))
 BEGIN
 INSERT INTO intelligence_changes(id,tenant_id,entity_id,event_type,reference_id,created_at)
 VALUES(lower(hex(randomblob(16))),NULL,NEW.id,'feed.failed',NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 END;
