-- Cluster observation semantics. Vocabulary: observed (the world) / retrieved (the source told us) / processed (our pipeline wrote).
-- threat_clusters.last_seen keeps its name but now means the latest member-evidence observedAt (observation time), never pipeline processing time.
-- first_seen/last_seen become NULL when no member evidence carries an observation time: unknown stays unknown.
-- Wall-clock processing time is recorded only in last_processed_at. The rebuild makes first_seen/last_seen nullable and adds the new columns.
-- Tables are swapped in dependency order so foreign keys stay valid even when enforced.
ALTER TABLE threat_clusters RENAME TO threat_clusters_legacy;
CREATE TABLE threat_clusters (id TEXT PRIMARY KEY REFERENCES entities(id), name TEXT NOT NULL, status TEXT NOT NULL, first_seen TEXT, last_seen TEXT, confidence REAL NOT NULL, observable_count INTEGER NOT NULL DEFAULT 0, assessment_id TEXT, first_observed TEXT, last_observed TEXT, last_processed_at TEXT, grouping_key TEXT, rationale TEXT);
INSERT INTO threat_clusters(id,name,status,first_seen,last_seen,confidence,observable_count,assessment_id) SELECT id,name,status,first_seen,last_seen,confidence,observable_count,assessment_id FROM threat_clusters_legacy;
CREATE TABLE cluster_members_new (cluster_id TEXT NOT NULL REFERENCES threat_clusters(id), observable_id TEXT NOT NULL REFERENCES observables(id), evidence_id TEXT NOT NULL REFERENCES evidence(id), PRIMARY KEY(cluster_id,observable_id));
INSERT INTO cluster_members_new SELECT cluster_id,observable_id,evidence_id FROM cluster_members;
DROP TABLE cluster_members;
DROP TABLE threat_clusters_legacy;
ALTER TABLE cluster_members_new RENAME TO cluster_members;
-- Backfill observation bounds and grouping rationale from member evidence where possible.
-- Correlate refines these lazily on its next run for each cluster: it recomputes over every evidence record backing a member observable, not only the linked evidence_id.
-- char(59) renders the semicolon that separates the pinned rationale format.
UPDATE threat_clusters SET first_observed = (SELECT MIN(e.observed_at) FROM cluster_members m JOIN evidence e ON e.id=m.evidence_id WHERE m.cluster_id=threat_clusters.id), last_observed = (SELECT MAX(e.observed_at) FROM cluster_members m JOIN evidence e ON e.id=m.evidence_id WHERE m.cluster_id=threat_clusters.id), grouping_key = (SELECT json_extract(en.data,'$.data.signal') FROM entities en WHERE en.id=threat_clusters.id);
UPDATE threat_clusters SET first_seen = first_observed, last_seen = last_observed, confidence = COALESCE(0.7 * (SELECT AVG(json_extract(e.data,'$.confidence')) FROM cluster_members m JOIN evidence e ON e.id=m.evidence_id WHERE m.cluster_id=threat_clusters.id), confidence);
UPDATE threat_clusters SET rationale = (CASE WHEN grouping_key LIKE 'report:%' THEN 'shared-report' WHEN grouping_key LIKE 'certificate:%' THEN 'shared-certificate' WHEN grouping_key LIKE 'malware:%' THEN 'shared-malware' END) || ' ' || grouping_key || char(59) || ' ' || (SELECT COUNT(*) FROM cluster_members m JOIN evidence e ON e.id=m.evidence_id WHERE m.cluster_id=threat_clusters.id) || ' evidence records from ' || (SELECT COUNT(DISTINCT e.source_id) FROM cluster_members m JOIN evidence e ON e.id=m.evidence_id WHERE m.cluster_id=threat_clusters.id) || ' sources' WHERE grouping_key IS NOT NULL;
