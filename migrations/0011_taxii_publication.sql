CREATE TABLE taxii_publications (
 tenant_id TEXT NOT NULL, collection_id TEXT NOT NULL, generation TEXT NOT NULL,
 revision INTEGER NOT NULL, published_at TEXT NOT NULL, object_count INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,collection_id),
 FOREIGN KEY(tenant_id,collection_id) REFERENCES workspace_objects(tenant_id,id)
);
CREATE TABLE taxii_objects (
 tenant_id TEXT NOT NULL, collection_id TEXT NOT NULL, generation TEXT NOT NULL,
 object_id TEXT NOT NULL, version TEXT NOT NULL, type TEXT NOT NULL,
 date_added TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)),
 PRIMARY KEY(tenant_id,collection_id,generation,object_id,version)
);
CREATE INDEX taxii_page ON taxii_objects(tenant_id,collection_id,generation,date_added,object_id,version);
