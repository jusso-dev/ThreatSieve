DROP INDEX IF EXISTS jobs_feed_unfinalized;
CREATE INDEX IF NOT EXISTS jobs_feed_stage_status ON pipeline_jobs(stage, status, created_at);
