-- Reversible entity-to-entity identity collapse (alias entity id → canonical).
-- Not named entity_aliases: that 0001 table is name-lookup text aliases
-- (alias TEXT, entity_id, source_id) used by Repository.sourceStatements /
-- resolveAlias. This table is a different concept and must not collide.
CREATE TABLE IF NOT EXISTS canonical_aliases (
  tenant_id TEXT NOT NULL,
  canonical_id TEXT NOT NULL,
  alias_id TEXT NOT NULL,
  basis TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, alias_id)
);
CREATE INDEX IF NOT EXISTS canonical_aliases_canonical
  ON canonical_aliases(tenant_id, canonical_id);
