-- Historical corroborating evidence must not inflate the number of observables.
UPDATE threat_clusters SET observable_count=(SELECT COUNT(DISTINCT observable_id) FROM cluster_members WHERE cluster_id=threat_clusters.id);
