-- Round-2 review: store the PROVEN identifier with each binding. nostr.json
-- resolution matches the binding's own username, so a proof for one handle can
-- never serve another handle of the same account (Blink Core may provision
-- several usernames per account/domain through the internal route).
--
-- Recreates the table rather than ALTERing: the primary key widens to include
-- the username, and SQLite cannot change a PK in place. Pre-production data
-- loss is accepted — bindings are client-creatable and every registration is
-- an idempotent upsert, so wallets simply re-prove on their next attempt.
DROP TABLE nostr_identities;
CREATE TABLE nostr_identities (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    nostr_pubkey TEXT NOT NULL CONSTRAINT nostr_identities_pubkey_hex CHECK (length(nostr_pubkey) = 64),
    username TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, domain, username)
);
CREATE INDEX idx_nostr_identities_domain ON nostr_identities(domain);
