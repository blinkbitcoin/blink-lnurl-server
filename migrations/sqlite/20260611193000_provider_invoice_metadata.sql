-- Provider-neutral invoice metadata for new Spark and Blink invoice rows.
ALTER TABLE invoices ADD COLUMN provider VARCHAR(32);
ALTER TABLE invoices ADD COLUMN wallet_kind VARCHAR(32);
ALTER TABLE invoices ADD COLUMN wallet_id VARCHAR(255);
ALTER TABLE invoices ADD COLUMN provider_payment_hash VARCHAR(255);
