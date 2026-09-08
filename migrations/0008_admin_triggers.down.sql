BEGIN;

UPDATE admin_roles
   SET permissions = permissions - 'policy:write' - 'snapshot:write'
 WHERE name = 'operator';

DROP INDEX IF EXISTS admin_triggers_pending_idx;
DROP TABLE IF EXISTS admin_triggers;
DROP TYPE IF EXISTS trigger_status;
DROP TYPE IF EXISTS trigger_kind;

COMMIT;
