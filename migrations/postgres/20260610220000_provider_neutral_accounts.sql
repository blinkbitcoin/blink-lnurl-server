-- Provider-neutral account ownership tables.
-- DATA-03 production backfill is intentionally superseded by D-11: this system is not deployed,
-- so legacy Spark rows remain writable without production backfill DML in this migration.

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CONSTRAINT accounts_provider_check CHECK (provider IN ('spark', 'blink')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE account_identifiers (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    identifier TEXT NOT NULL,
    identifier_kind TEXT NOT NULL CONSTRAINT account_identifiers_identifier_kind_check CHECK (identifier_kind IN ('username', 'phone')),
    description TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, domain, identifier),
    CONSTRAINT account_identifiers_domain_identifier_key UNIQUE (domain, identifier)
);

CREATE TABLE spark_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    pubkey TEXT NOT NULL CONSTRAINT spark_accounts_pubkey_key UNIQUE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE blink_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    blink_account_id TEXT NOT NULL CONSTRAINT blink_accounts_blink_account_id_key UNIQUE,
    btc_wallet_id TEXT NOT NULL,
    usd_wallet_id TEXT NOT NULL,
    default_wallet TEXT NOT NULL CONSTRAINT blink_accounts_default_wallet_check CHECK (default_wallet IN ('btc', 'usd')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

ALTER TABLE invoices ADD COLUMN account_id TEXT REFERENCES accounts(account_id);
CREATE INDEX idx_invoices_account_id ON invoices(account_id);

ALTER TABLE zaps ADD COLUMN account_id TEXT REFERENCES accounts(account_id);
CREATE INDEX idx_zaps_account_id ON zaps(account_id);

ALTER TABLE sender_comments ADD COLUMN account_id TEXT REFERENCES accounts(account_id);
CREATE INDEX idx_sender_comments_account_id ON sender_comments(account_id);
