-- statement-breakpoint
CREATE TRIGGER tenant_member_keep_admin_delete BEFORE DELETE ON tenant_members
WHEN OLD.role='admin' AND (SELECT COUNT(*) FROM tenant_members WHERE tenant_id=OLD.tenant_id AND role='admin')<=1
BEGIN
  SELECT RAISE(ABORT,'A workspace must retain at least one admin');
END;
-- statement-breakpoint
CREATE TRIGGER tenant_member_keep_admin_update BEFORE UPDATE OF role ON tenant_members
WHEN OLD.role='admin' AND NEW.role<>'admin' AND (SELECT COUNT(*) FROM tenant_members WHERE tenant_id=OLD.tenant_id AND role='admin')<=1
BEGIN
  SELECT RAISE(ABORT,'A workspace must retain at least one admin');
END;
