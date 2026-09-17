-- NIP-05 verified nostr identities. A row asserts that the domain operator
-- maps `username@domain` (resolved through account_identifiers) to
-- nostr_pubkey (lowercase hex x-only secp256k1).
--
-- Rows are deleted in the same transaction wherever an account's username
-- identifier is deleted or transferred, so a verified handle can never
-- outlive the registration it attests to (anti-impersonation invariant).
CREATE TABLE nostr_identities (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    nostr_pubkey TEXT NOT NULL CONSTRAINT nostr_identities_pubkey_hex CHECK (length(nostr_pubkey) = 64),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, domain)
);
CREATE INDEX idx_nostr_identities_domain ON nostr_identities(domain);
