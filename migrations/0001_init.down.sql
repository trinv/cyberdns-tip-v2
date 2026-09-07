BEGIN;

DROP TABLE IF EXISTS admin_audit_log;
DROP TABLE IF EXISTS admin_users;
DROP TABLE IF EXISTS admin_roles;

DROP TABLE IF EXISTS snapshots;
DROP TABLE IF EXISTS snapshot_sets;

DROP TABLE IF EXISTS tenant_denylist;
DROP TABLE IF EXISTS tenant_allowlist;
DROP TABLE IF EXISTS tenant_categories;
DROP TABLE IF EXISTS tenant_tokens;

DROP TABLE IF EXISTS false_positive_events;
DROP TABLE IF EXISTS decision_changes;
DROP TABLE IF EXISTS shadow_decisions;
DROP TABLE IF EXISTS domain_decisions;
DROP TABLE IF EXISTS policy_runs;

DROP TABLE IF EXISTS global_block_overrides;
DROP TABLE IF EXISTS global_allowlist;

DROP TRIGGER IF EXISTS domain_evidence_no_update ON domain_evidence;
DROP TABLE IF EXISTS domain_evidence;
DROP FUNCTION IF EXISTS domain_evidence_append_only();

DROP TABLE IF EXISTS domain_source_categories;
DROP TABLE IF EXISTS domain_sources;
DROP TABLE IF EXISTS regex_rules;
DROP TABLE IF EXISTS domains;

DROP TABLE IF EXISTS feed_imports;
DROP TABLE IF EXISTS sources;
DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS categories;

DROP TYPE IF EXISTS snapshot_status;
DROP TYPE IF EXISTS import_status;
DROP TYPE IF EXISTS allowlist_tier;
DROP TYPE IF EXISTS policy_run_status;
DROP TYPE IF EXISTS policy_action;
DROP TYPE IF EXISTS source_origin;

COMMIT;
