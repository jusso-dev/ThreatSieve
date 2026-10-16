-- Keep name resolution and feed polling bounded as intelligence/job history grows.
CREATE INDEX IF NOT EXISTS entities_lower_name_lookup ON entities(lower(name),id);
CREATE INDEX IF NOT EXISTS jobs_feed_finalization ON pipeline_jobs(stage,status,json_extract(result,'$.finalized'),created_at);
