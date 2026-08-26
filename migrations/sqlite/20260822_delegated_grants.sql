CREATE TABLE delegated_grants (
    delegated_pubkey TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES spark_accounts(account_id),
    owner_pubkey TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX delegated_grants_account_id ON delegated_grants (account_id);
