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
CREATE INDEX idx_account_identifiers_account_domain_kind
    ON account_identifiers (account_id, domain, identifier_kind, identifier);

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

CREATE TABLE allowed_domains (
    domain VARCHAR(255) PRIMARY KEY
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Timestamps stay as unix epoch integers by convention because the Rust layer,
-- LNURL protocol handling, and cross-backend tests already operate on epoch values.
CREATE TABLE invoices (
    payment_hash VARCHAR(64) PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    provider VARCHAR(32) CONSTRAINT invoices_provider_check CHECK (provider IN ('spark', 'blink')),
    wallet_kind VARCHAR(32) CONSTRAINT invoices_wallet_kind_check CHECK (wallet_kind IN ('btc', 'usd')),
    wallet_id VARCHAR(255),
    provider_payment_hash VARCHAR(255),
    user_pubkey VARCHAR(66) NOT NULL,
    invoice TEXT NOT NULL,
    preimage VARCHAR(64),
    expired_at BIGINT,
    invoice_expiry BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    domain VARCHAR(255),
    amount_received_sat BIGINT
);
CREATE INDEX idx_invoices_account_id ON invoices(account_id);
CREATE INDEX idx_invoices_account_id_updated_at ON invoices(account_id, updated_at);
CREATE INDEX idx_invoices_user_pubkey_updated_at ON invoices(user_pubkey, updated_at);
CREATE INDEX idx_invoices_invoice_expiry ON invoices(invoice_expiry);
CREATE INDEX idx_invoices_updated_at ON invoices(updated_at);

-- Zap/comment side effects may be written before the invoice row exists, so
-- payment_hash stays intentionally loose instead of using invoice foreign keys.
CREATE TABLE zaps (
    payment_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    zap_request TEXT NOT NULL,
    zap_event TEXT,
    user_pubkey VARCHAR(66) NOT NULL,
    invoice_expiry BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    is_user_nostr_key BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_zaps_account_id ON zaps(account_id);
CREATE INDEX idx_zaps_user_pubkey_updated_at ON zaps(user_pubkey, updated_at);
CREATE INDEX idx_zaps_invoice_expiry ON zaps(invoice_expiry);
CREATE INDEX idx_zaps_updated_at ON zaps(updated_at);

CREATE TABLE sender_comments (
    payment_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    user_pubkey VARCHAR(66) NOT NULL,
    sender_comment VARCHAR(255) NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX idx_sender_comments_account_id ON sender_comments(account_id);
CREATE INDEX idx_sender_comments_user_pubkey_updated_at ON sender_comments(user_pubkey, updated_at);
CREATE INDEX idx_sender_comments_updated_at ON sender_comments(updated_at);

CREATE TABLE pending_zap_receipts (
    payment_hash VARCHAR(64) PRIMARY KEY,
    created_at BIGINT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at BIGINT NOT NULL,
    claimed_at BIGINT
);
CREATE INDEX idx_pending_zap_receipts_next_retry_at ON pending_zap_receipts(next_retry_at);

CREATE TABLE domain_webhooks (
    domain VARCHAR(255) PRIMARY KEY,
    url TEXT NOT NULL,
    webhook_secret TEXT NOT NULL
);

CREATE TABLE webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    identifier TEXT NOT NULL,
    domain TEXT NOT NULL,
    url TEXT,
    payload TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    succeeded_at BIGINT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at BIGINT NOT NULL,
    claimed_at BIGINT,
    last_error_status_code INTEGER,
    last_error_body TEXT
);
CREATE UNIQUE INDEX idx_webhook_deliveries_one_pending
    ON webhook_deliveries (identifier, domain)
    WHERE succeeded_at IS NULL;
CREATE INDEX idx_webhook_deliveries_pending
    ON webhook_deliveries (domain, next_retry_at)
    WHERE succeeded_at IS NULL;
CREATE INDEX idx_webhook_deliveries_created_at
    ON webhook_deliveries (created_at);
