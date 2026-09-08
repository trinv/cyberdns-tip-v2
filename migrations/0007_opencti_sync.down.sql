BEGIN;
DROP TABLE IF EXISTS opencti_stream_state;
DROP INDEX IF EXISTS domain_sources_record_idx;
ALTER TABLE domain_sources DROP COLUMN IF EXISTS source_modified_at;
COMMIT;
