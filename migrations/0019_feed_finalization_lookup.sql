CREATE INDEX jobs_feed_unfinalized ON pipeline_jobs(created_at) WHERE stage='feed-sync' AND status='complete' AND json_extract(result,'$.finalized') IS NULL;
