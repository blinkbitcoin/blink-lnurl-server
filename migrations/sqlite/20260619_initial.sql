CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('spark', 'blink')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE account_identifiers (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    identifier TEXT NOT NULL,
    identifier_kind TEXT NOT NULL CHECK (identifier_kind IN ('username', 'phone')),
    description TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, domain, identifier)
);
CREATE UNIQUE INDEX account_identifiers_domain_identifier_key
    ON account_identifiers (domain, identifier);
CREATE INDEX idx_account_identifiers_account_domain_kind
    ON account_identifiers (account_id, domain, identifier_kind, identifier);

CREATE TABLE spark_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    pubkey TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX spark_accounts_pubkey_key ON spark_accounts (pubkey);

CREATE TABLE blink_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    blink_account_id TEXT NOT NULL,
    btc_wallet_id TEXT NOT NULL,
    usd_wallet_id TEXT NOT NULL,
    default_wallet TEXT NOT NULL CHECK (default_wallet IN ('btc', 'usd')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX blink_accounts_blink_account_id_key
    ON blink_accounts (blink_account_id);

CREATE TABLE allowed_domains (
    domain TEXT PRIMARY KEY
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE invoices (
    payment_hash TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    provider TEXT,
    wallet_kind TEXT,
    wallet_id TEXT,
    provider_payment_hash TEXT,
    user_pubkey TEXT NOT NULL,
    invoice TEXT NOT NULL,
    preimage TEXT,
    expired_at INTEGER,
    invoice_expiry INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    domain TEXT,
    amount_received_sat INTEGER
);
CREATE INDEX idx_invoices_account_id ON invoices(account_id);
CREATE INDEX idx_invoices_account_id_updated_at ON invoices(account_id, updated_at);
CREATE INDEX idx_invoices_user_pubkey_updated_at ON invoices(user_pubkey, updated_at);
CREATE INDEX idx_invoices_invoice_expiry ON invoices(invoice_expiry);
CREATE INDEX idx_invoices_updated_at ON invoices(updated_at);

CREATE TABLE zaps (
    payment_hash TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    zap_request TEXT NOT NULL,
    zap_event TEXT,
    user_pubkey TEXT NOT NULL,
    invoice_expiry INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    is_user_nostr_key INTEGER NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_zaps_account_id ON zaps(account_id);
CREATE INDEX idx_zaps_user_pubkey_updated_at ON zaps(user_pubkey, updated_at);
CREATE INDEX idx_zaps_invoice_expiry ON zaps(invoice_expiry);
CREATE INDEX idx_zaps_updated_at ON zaps(updated_at);

CREATE TABLE sender_comments (
    payment_hash TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    user_pubkey TEXT NOT NULL,
    sender_comment TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX idx_sender_comments_account_id ON sender_comments(account_id);
CREATE INDEX idx_sender_comments_user_pubkey_updated_at ON sender_comments(user_pubkey, updated_at);
CREATE INDEX idx_sender_comments_updated_at ON sender_comments(updated_at);

CREATE TABLE pending_zap_receipts (
    payment_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER NOT NULL,
    claimed_at INTEGER
);
CREATE INDEX idx_pending_zap_receipts_next_retry_at ON pending_zap_receipts(next_retry_at);

CREATE TABLE domain_webhooks (
    domain TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    webhook_secret TEXT NOT NULL
);

CREATE TABLE webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    domain TEXT NOT NULL,
    url TEXT,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    succeeded_at INTEGER,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER NOT NULL,
    claimed_at INTEGER,
    last_error_status_code INTEGER,
    last_error_body TEXT,
    UNIQUE (identifier, domain)
);
CREATE INDEX idx_webhook_deliveries_pending
    ON webhook_deliveries (domain, next_retry_at)
    WHERE succeeded_at IS NULL;
CREATE INDEX idx_webhook_deliveries_created_at
    ON webhook_deliveries (created_at);
