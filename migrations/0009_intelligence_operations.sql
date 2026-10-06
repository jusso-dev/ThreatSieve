CREATE TABLE workspace_objects (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('requirement','investigation','watchlist','collection','report','playbook')),
 title TEXT NOT NULL, status TEXT NOT NULL, priority TEXT NOT NULL,
 owner_id TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 change_id TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX workspace_browse ON workspace_objects(tenant_id,kind,updated_at DESC,id);
CREATE INDEX workspace_owner ON workspace_objects(tenant_id,owner_id,status);
CREATE TABLE workspace_links (
 tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, target_type TEXT NOT NULL,
 target_id TEXT NOT NULL, relation TEXT NOT NULL,
 PRIMARY KEY(tenant_id,object_id,target_type,target_id,relation),
 FOREIGN KEY(tenant_id,object_id) REFERENCES workspace_objects(tenant_id,id)
);
CREATE INDEX workspace_reverse ON workspace_links(tenant_id,target_type,target_id,object_id);
CREATE TABLE intelligence_events (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
 subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, event_type TEXT NOT NULL,
 actor_id TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX intelligence_timeline ON intelligence_events(tenant_id,subject_id,created_at DESC,id);
CREATE INDEX intelligence_dispatch ON intelligence_events(tenant_id,created_at,id);
CREATE TABLE sightings (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
 observable_id TEXT NOT NULL REFERENCES observables(id), source TEXT NOT NULL,
 observed_at TEXT NOT NULL, count INTEGER NOT NULL CHECK(count>0), confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
 data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX sightings_entity ON sightings(tenant_id,observable_id,observed_at DESC,id);
CREATE TABLE source_ratings (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), source_id TEXT NOT NULL REFERENCES sources(id),
 reliability TEXT NOT NULL CHECK(reliability IN ('A','B','C','D','E','F')),
 evidence_rating INTEGER NOT NULL CHECK(evidence_rating BETWEEN 1 AND 6),
 rationale TEXT NOT NULL, analyst_id TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,source_id)
);
CREATE TABLE workspace_notifications (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
 object_id TEXT NOT NULL, entity_id TEXT, event_id TEXT NOT NULL,
 reason TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX workspace_notifications_unread ON workspace_notifications(tenant_id,read_at,created_at DESC);
CREATE TABLE automation_executions (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL, playbook_id TEXT NOT NULL,
 event_id TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)),
 created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,playbook_id,event_id)
);
CREATE TABLE requirement_metrics (
 tenant_id TEXT NOT NULL, requirement_id TEXT NOT NULL, revision INTEGER NOT NULL,
 data TEXT NOT NULL CHECK(json_valid(data)), updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,requirement_id),
 FOREIGN KEY(tenant_id,requirement_id) REFERENCES workspace_objects(tenant_id,id)
);
