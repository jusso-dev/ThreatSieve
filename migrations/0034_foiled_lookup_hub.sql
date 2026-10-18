-- Bulk lookup hub for Foiled and other integrations.
-- commercial_use records whether a source's terms permit commercial use of its
-- data: 1 permitted, 0 not permitted without a separate agreement, NULL unknown.
ALTER TABLE sources ADD COLUMN commercial_use INTEGER CHECK(commercial_use IN (0,1));
UPDATE sources SET commercial_use=1 WHERE id IN ('mitre','cisa-kev','misp','demo');
UPDATE sources SET commercial_use=0 WHERE id IN ('threatfox','urlhaus','feodo','virustotal','greynoise');
UPDATE sources SET license='GreyNoise Community API terms (free tier, 50 lookups per week, commercial use needs a paid licence)' WHERE id='greynoise';
UPDATE sources SET license='VirusTotal public API terms (non-commercial)' WHERE id='virustotal';
-- GreyNoise was seeded disabled before its lookup was wired. It stays inert
-- until GREYNOISE_API_KEY is provisioned.
UPDATE sources SET enabled=1 WHERE id='greynoise';
INSERT OR IGNORE INTO sources(id,name,independent_group,reliability,enabled,license,redistributable,commercial_use) VALUES
('iptoasn','IPtoASN','iptoasn',0.85,1,'Public Domain Dedication and License (PDDL) 1.0',1,1),
('crowdsec','CrowdSec CTI','crowdsec',0.75,1,'CrowdSec CTI API terms (commercial use needs the partnership programme)',0,0),
('epss','FIRST EPSS','epss',0.8,1,'FIRST EPSS, published freely, cite FIRST',1,1),
('nvd','NVD','nvd',0.9,1,'US government public data, NVD API notice required',1,1),
('osv','OSV.dev','osv',0.8,1,'OSV.dev aggregate, per-source licences (mostly CC-BY 4.0)',1,NULL);
-- Current version of each scheduled dataset. Shards live in R2 under
-- datasets/<dataset>/<version>/ and a version is switched only after every shard
-- and index object has been written.
CREATE TABLE dataset_versions (
  dataset TEXT PRIMARY KEY REFERENCES sources(id),
  version TEXT NOT NULL,
  source_digest TEXT NOT NULL,
  source_updated_at TEXT,
  record_count INTEGER NOT NULL,
  imported_at TEXT NOT NULL,
  previous_version TEXT
);
-- NVD CVE context, upserted incrementally by lastModified.
CREATE TABLE cve_records (
  cve TEXT PRIMARY KEY,
  published TEXT,
  last_modified TEXT NOT NULL,
  status TEXT,
  description TEXT NOT NULL DEFAULT '',
  cvss_version TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  data TEXT NOT NULL CHECK(json_valid(data)),
  retrieved_at TEXT NOT NULL
);
CREATE INDEX cve_records_modified ON cve_records(last_modified);
-- Cached per-observable answers from rate-limited lookup sources. Kept out of
-- the shared graph so a tenant's lookup never reveals the value to others.
CREATE TABLE source_lookup_cache (
  source_id TEXT NOT NULL REFERENCES sources(id),
  lookup_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','found','not_found','error')),
  data TEXT NOT NULL CHECK(json_valid(data)),
  fetched_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(source_id,lookup_key)
);
CREATE INDEX source_lookup_cache_expiry ON source_lookup_cache(expires_at);
