-- NULL mode is "untyped": existing rows keep behaving exactly as before this migration.
ALTER TABLE spark_accounts
    ADD COLUMN mode TEXT CONSTRAINT spark_accounts_mode_check CHECK (mode IN ('enhanced', 'anon')),
    ADD COLUMN mode_source TEXT CONSTRAINT spark_accounts_mode_source_check CHECK (mode_source IN ('signup', 'switch', 'migration')),
    ADD COLUMN mode_updated_at BIGINT,
    -- Client timestamp of the last accepted mode request; the monotonic anti-replay/rollback anchor.
    ADD COLUMN mode_last_timestamp BIGINT,
    ADD COLUMN country TEXT,
    ADD COLUMN country_updated_at BIGINT;
