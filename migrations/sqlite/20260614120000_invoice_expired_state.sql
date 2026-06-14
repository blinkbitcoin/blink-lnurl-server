-- Explicit provider-validated invoice expiry state for Blink callbacks.
ALTER TABLE invoices ADD COLUMN expired_at BIGINT;
