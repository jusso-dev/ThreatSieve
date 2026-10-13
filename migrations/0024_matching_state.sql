-- Matching evaluation state for requirement/watchlist/collection matches.
-- Default complete keeps existing rows valid. New writes set queued/running/complete/failed.
ALTER TABLE workspace_matches ADD COLUMN match_status TEXT NOT NULL DEFAULT 'complete';
ALTER TABLE workspace_matches ADD COLUMN last_evaluated_at TEXT;
