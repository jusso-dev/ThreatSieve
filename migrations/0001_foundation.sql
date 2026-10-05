PRAGMA foreign_keys = ON;
CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE tenant_members (tenant_id TEXT NOT NULL REFERENCES tenants(id), user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')), PRIMARY KEY(tenant_id,user_id));
CREATE TABLE api_keys (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), user_id TEXT NOT NULL, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL CHECK(json_valid(scopes)), created_at TEXT NOT NULL, expires_at TEXT, last_used_at TEXT, revoked_at TEXT);
CREATE INDEX api_keys_tenant ON api_keys(tenant_id,created_at);
CREATE TABLE sessions (hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), user_id TEXT NOT NULL, key_id TEXT NOT NULL REFERENCES api_keys(id), expires_at TEXT NOT NULL);
CREATE TABLE rate_limits (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE sources (id TEXT PRIMARY KEY, name TEXT NOT NULL, independent_group TEXT NOT NULL, reliability REAL NOT NULL CHECK(reliability BETWEEN 0 AND 1), enabled INTEGER NOT NULL DEFAULT 1, license TEXT NOT NULL, redistributable INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'never-synced', last_sync TEXT, next_sync TEXT, records_processed INTEGER NOT NULL DEFAULT 0, records_added INTEGER NOT NULL DEFAULT 0, records_updated INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0, last_error TEXT);
CREATE TABLE feed_checkpoints (source_id TEXT PRIMARY KEY REFERENCES sources(id), checkpoint TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE entities (id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL, external_id TEXT, data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX entities_type_name ON entities(type,name COLLATE NOCASE,id);
CREATE INDEX entities_external ON entities(external_id);
CREATE TABLE entity_aliases (alias TEXT NOT NULL, entity_id TEXT NOT NULL REFERENCES entities(id), source_id TEXT NOT NULL REFERENCES sources(id), PRIMARY KEY(alias,entity_id,source_id));
CREATE TABLE observables (id TEXT PRIMARY KEY REFERENCES entities(id), type TEXT NOT NULL, normalized_value TEXT NOT NULL, first_seen TEXT, last_seen TEXT, data TEXT NOT NULL CHECK(json_valid(data)), UNIQUE(type,normalized_value));
CREATE INDEX observables_lookup ON observables(normalized_value);
CREATE TABLE relationships (id TEXT PRIMARY KEY, source_entity_id TEXT NOT NULL, target_entity_id TEXT NOT NULL, relationship_type TEXT NOT NULL, assertion_type TEXT NOT NULL CHECK(assertion_type IN ('observed','source_claimed','analyst_confirmed','model_inferred')), confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1), source_id TEXT NOT NULL REFERENCES sources(id), data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL);
CREATE INDEX relationships_forward ON relationships(source_entity_id,relationship_type,target_entity_id);
CREATE INDEX relationships_reverse ON relationships(target_entity_id,relationship_type,source_entity_id);
CREATE TABLE evidence (id TEXT PRIMARY KEY, entity_id TEXT NOT NULL, source_id TEXT NOT NULL REFERENCES sources(id), data TEXT NOT NULL CHECK(json_valid(data)), raw_key TEXT, observed_at TEXT, created_at TEXT NOT NULL);
CREATE INDEX evidence_entity ON evidence(entity_id,observed_at DESC,id);
CREATE TABLE attack_techniques (entity_id TEXT PRIMARY KEY REFERENCES entities(id), mitre_id TEXT NOT NULL UNIQUE);
CREATE TABLE attack_tactics (entity_id TEXT PRIMARY KEY REFERENCES entities(id), mitre_id TEXT NOT NULL UNIQUE);
CREATE TABLE threat_actors (entity_id TEXT PRIMARY KEY REFERENCES entities(id), fingerprint TEXT NOT NULL DEFAULT '{}');
CREATE TABLE actor_aliases (alias TEXT NOT NULL, entity_id TEXT NOT NULL REFERENCES entities(id), source_id TEXT NOT NULL, PRIMARY KEY(alias,entity_id,source_id));
CREATE TABLE malware (entity_id TEXT PRIMARY KEY REFERENCES entities(id));
CREATE TABLE campaigns (entity_id TEXT PRIMARY KEY REFERENCES entities(id));
CREATE TABLE vulnerabilities (entity_id TEXT PRIMARY KEY REFERENCES entities(id), cve TEXT NOT NULL UNIQUE, vendor TEXT, product TEXT, kev INTEGER NOT NULL DEFAULT 0, due_date TEXT);
CREATE TABLE threat_clusters (id TEXT PRIMARY KEY REFERENCES entities(id), name TEXT NOT NULL, status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, confidence REAL NOT NULL, observable_count INTEGER NOT NULL DEFAULT 0, assessment_id TEXT);
CREATE TABLE cluster_members (cluster_id TEXT NOT NULL REFERENCES threat_clusters(id), observable_id TEXT NOT NULL REFERENCES observables(id), evidence_id TEXT NOT NULL REFERENCES evidence(id), PRIMARY KEY(cluster_id,observable_id));
CREATE TABLE assessments (id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id), observable_id TEXT NOT NULL REFERENCES observables(id), evidence_version TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', severity TEXT NOT NULL, confidence REAL NOT NULL, human_review INTEGER NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE INDEX assessments_queue ON assessments(tenant_id,status,human_review,created_at DESC,id);
CREATE INDEX assessments_observable ON assessments(tenant_id,observable_id,created_at DESC);
CREATE TABLE assessment_attack (tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, technique_id TEXT NOT NULL, probability REAL NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,assessment_id,technique_id), FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id));
CREATE TABLE assessment_actors (tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, actor_id TEXT NOT NULL, probability REAL NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,assessment_id,actor_id), FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id));
CREATE TABLE assessment_actions (tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, action TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,assessment_id,action), FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id));
CREATE TABLE analyst_feedback (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, analyst_id TEXT NOT NULL, field TEXT NOT NULL, original_value TEXT NOT NULL, analyst_value TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(tenant_id,assessment_id) REFERENCES assessments(tenant_id,id));
CREATE INDEX feedback_tenant ON analyst_feedback(tenant_id,assessment_id,created_at);
CREATE TABLE relationship_feedback (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), relationship_id TEXT NOT NULL REFERENCES relationships(id), analyst_id TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE customer_environments (tenant_id TEXT PRIMARY KEY REFERENCES tenants(id), data TEXT NOT NULL CHECK(json_valid(data)), updated_at TEXT NOT NULL);
CREATE TABLE customer_assets (id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, product TEXT NOT NULL, internet_exposed INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(tenant_id,id));
CREATE TABLE customer_observations (id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id), observable_id TEXT NOT NULL REFERENCES observables(id), data TEXT NOT NULL CHECK(json_valid(data)), observed_at TEXT NOT NULL, sharing_allowed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant_id,id));
CREATE INDEX observations_lookup ON customer_observations(tenant_id,observable_id,observed_at);
CREATE TABLE classification_runs (id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id), assessment_id TEXT NOT NULL, model TEXT NOT NULL, schema_version TEXT NOT NULL, evidence_version TEXT NOT NULL, input_tokens INTEGER NOT NULL, duration_ms INTEGER NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE INDEX runs_cost ON classification_runs(tenant_id,created_at,model);
CREATE TABLE classification_cache (tenant_id TEXT NOT NULL REFERENCES tenants(id), cache_key TEXT NOT NULL, assessment_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,cache_key));
CREATE TABLE pipeline_jobs (id TEXT PRIMARY KEY, tenant_id TEXT REFERENCES tenants(id), entity_id TEXT NOT NULL, stage TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('queued','running','complete','failed')), attempt INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL CHECK(json_valid(data)), result TEXT, error_type TEXT, lease_until TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX jobs_tenant ON pipeline_jobs(tenant_id,created_at DESC,id);
CREATE TABLE outbox (id TEXT PRIMARY KEY REFERENCES pipeline_jobs(id), queue TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)), dispatched_at TEXT, created_at TEXT NOT NULL);
CREATE INDEX outbox_pending ON outbox(dispatched_at,created_at);
CREATE TABLE audit_events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), actor_id TEXT NOT NULL, action TEXT NOT NULL, entity_id TEXT, source_ip TEXT, correlation_id TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE INDEX audit_tenant ON audit_events(tenant_id,created_at DESC,id);
CREATE TABLE exports (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), assessment_id TEXT NOT NULL, r2_key TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE inference_budget (tenant_id TEXT NOT NULL REFERENCES tenants(id), day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(tenant_id,day));
INSERT INTO sources(id,name,independent_group,reliability,license,redistributable) VALUES
('mitre','MITRE ATT&CK','mitre',0.95,'ATT&CK Terms of Use',1),
('misp','MISP Galaxy','misp',0.85,'Collection-specific licenses',0),
('threatfox','ThreatFox','abuse.ch',0.85,'abuse.ch fair use / commercial agreement',0),
('urlhaus','URLhaus','abuse.ch',0.85,'abuse.ch fair use / commercial agreement',0),
('feodo','Feodo Tracker','abuse.ch',0.9,'abuse.ch fair use / commercial agreement',0),
('cisa-kev','CISA KEV','cisa',0.98,'US government public data',1),
('customer','Customer telemetry','customer',0.9,'Tenant private',0),
('analyst','Analyst confirmation','analyst',1,'Tenant private',0),
('upload','User upload','upload',0.5,'Uploader supplied',0),
('demo','Synthetic demonstration','demo',0.8,'Synthetic test data only',1);
INSERT INTO sources(id,name,independent_group,reliability,enabled,license) VALUES
('otx','LevelBlue OTX','otx',0.65,0,'Account terms'),('virustotal','VirusTotal','virustotal',0.8,0,'Account terms'),('greynoise','GreyNoise','greynoise',0.8,0,'Account terms'),('taxii','TAXII feed','taxii',0.5,0,'Provider terms'),('stix','STIX feed','stix',0.5,0,'Provider terms'),('misp-feed','MISP feed','misp-feed',0.5,0,'Provider terms');
