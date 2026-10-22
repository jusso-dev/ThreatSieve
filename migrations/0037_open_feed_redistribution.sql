-- ThreatSieve is a non-commercial open-source project and redistributes every
-- feed it collects, so all feed sources and their stored records become
-- redistributable. Tenant-private sources (customer, analyst, upload) are
-- tenant data, not feeds, and stay private. Additional TAXII sources
-- (taxii-*) are left alone: their TAXII_SOURCES entry may opt out explicitly,
-- and ensureTaxiiSources applies that setting. commercial_use is unchanged.
UPDATE sources SET redistributable=1 WHERE redistributable=0 AND id NOT IN ('customer','analyst','upload') AND id NOT LIKE 'taxii-%';
UPDATE entities SET data=json_set(data,'$.provenance.redistributable',json('true')) WHERE json_extract(data,'$.provenance.redistributable')=0 AND COALESCE(json_extract(data,'$.provenance.sourceId'),'') NOT IN ('customer','analyst','upload','lookup') AND COALESCE(json_extract(data,'$.provenance.sourceId'),'') NOT LIKE 'taxii-%';
UPDATE evidence SET data=json_set(data,'$.provenance.redistributable',json('true')) WHERE json_extract(data,'$.provenance.redistributable')=0 AND source_id NOT IN ('customer','analyst','upload') AND source_id NOT LIKE 'taxii-%';
UPDATE relationships SET data=json_set(data,'$.provenance.redistributable',json('true')) WHERE json_extract(data,'$.provenance.redistributable')=0 AND source_id NOT IN ('customer','analyst','upload') AND source_id NOT LIKE 'taxii-%';
UPDATE entity_sources SET provenance=json_set(provenance,'$.redistributable',json('true')) WHERE json_extract(provenance,'$.redistributable')=0 AND source_id NOT IN ('customer','analyst','upload') AND source_id NOT LIKE 'taxii-%';
