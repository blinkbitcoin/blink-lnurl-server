-- NULL mode is "untyped": existing rows keep behaving exactly as before this migration.
ALTER TABLE spark_accounts ADD COLUMN mode TEXT CHECK (mode IN ('enhanced', 'anon'));
ALTER TABLE spark_accounts ADD COLUMN mode_source TEXT CHECK (mode_source IN ('signup', 'switch', 'migration'));
ALTER TABLE spark_accounts ADD COLUMN mode_updated_at INTEGER;
-- Client timestamp of the last accepted mode request; the monotonic anti-replay/rollback anchor.
ALTER TABLE spark_accounts ADD COLUMN mode_last_timestamp INTEGER;
ALTER TABLE spark_accounts ADD COLUMN country TEXT;
ALTER TABLE spark_accounts ADD COLUMN country_updated_at INTEGER;
