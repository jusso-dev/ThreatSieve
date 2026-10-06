ALTER TABLE outbox ADD COLUMN lease_until TEXT;
ALTER TABLE outbox ADD COLUMN dispatch_token TEXT;
CREATE INDEX outbox_delivery_lease ON outbox(dispatched_at,lease_until,created_at);
CREATE INDEX jobs_recovery ON pipeline_jobs(status,lease_until,updated_at);
CREATE INDEX jobs_feed_parent ON pipeline_jobs(json_extract(data,'$.payload.feedJobId'),stage);
