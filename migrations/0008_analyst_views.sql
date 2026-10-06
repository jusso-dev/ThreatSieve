CREATE TABLE saved_views (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  filters TEXT NOT NULL CHECK(json_valid(filters)),
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id,user_id,name)
);
CREATE INDEX saved_views_owner ON saved_views(tenant_id,user_id,created_at);
CREATE INDEX entities_browse ON entities(type,name COLLATE NOCASE,id);
CREATE INDEX entity_sources_lookup ON entity_sources(source_id,entity_id);
CREATE INDEX entities_name_lookup ON entities(name COLLATE NOCASE,id);
CREATE INDEX entities_external_lookup ON entities(external_id COLLATE NOCASE,id);
CREATE INDEX assessments_time_cursor ON assessments(tenant_id,created_at DESC,id);
CREATE INDEX assessments_confidence_cursor ON assessments(tenant_id,json_extract(data,'$.confidence') DESC,id);
CREATE INDEX assessments_relevance_cursor ON assessments(tenant_id,json_extract(data,'$.customer.relevance') DESC,id);
