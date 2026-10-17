-- Optional Yeti forensic intelligence platform import. Disabled until an
-- operator configures the instance and reviews what it aggregates.
INSERT OR IGNORE INTO sources(id,name,independent_group,reliability,enabled,license) VALUES
('yeti','Yeti','yeti',0.5,0,'Instance operator terms');
