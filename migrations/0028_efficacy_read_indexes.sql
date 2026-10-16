-- Avoid scans of global history for a single identity, graph edge or dossier.
CREATE INDEX IF NOT EXISTS entity_sources_upstream_lookup ON entity_sources(source_record_id,entity_id);
CREATE INDEX IF NOT EXISTS relationship_feedback_latest ON relationship_feedback(tenant_id,relationship_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS intelligence_changes_entity_history ON intelligence_changes(entity_id,created_at DESC,tenant_id);
CREATE INDEX IF NOT EXISTS clusters_recent_populated ON threat_clusters(last_seen DESC) WHERE observable_count>=2;
