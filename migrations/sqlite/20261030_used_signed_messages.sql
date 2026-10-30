-- Every signed statement a mutating /lnurlpay route has acted on, so the same
-- authorization is never acted on twice.
--
-- Keyed on the statement (pubkey + exact signed message) rather than the
-- signature bytes: ECDSA signatures are malleable, so two distinct signatures
-- can authorize the same statement.
CREATE TABLE used_signed_messages (
    statement_hash BLOB PRIMARY KEY,
    -- Which route acted on the statement. Diagnostic only: a claimed
    -- statement is refused whichever route presents it.
    route TEXT NOT NULL,
    -- When the row may be pruned: the point past which the statement's own
    -- timestamp is refused anyway. An untimestamped statement never expires.
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_used_signed_messages_expires_at
    ON used_signed_messages (expires_at);
