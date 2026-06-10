use crate::models::ListMetadataMetadata;

use crate::user::User;
use crate::zap::Zap;

#[derive(Debug, thiserror::Error)]
pub enum LnurlRepositoryError {
    #[error("name taken")]
    NameTaken,
    #[error("source user does not own this username")]
    SourceNotOwner,
    #[error("database error: {0}")]
    General(anyhow::Error),
}

pub struct LnurlSenderComment {
    pub comment: String,
    pub payment_hash: String,
    pub user_pubkey: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Invoice {
    pub payment_hash: String,
    pub user_pubkey: String,
    pub invoice: String,
    pub preimage: Option<String>,
    pub invoice_expiry: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// The domain this invoice was created for, if any.
    pub domain: Option<String>,
    /// Amount received in satoshis (from the HTLC). NULL when unknown.
    pub amount_received_sat: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PendingZapReceipt {
    pub payment_hash: String,
    pub created_at: i64,
    pub retry_count: i32,
    pub next_retry_at: i64,
}

#[async_trait::async_trait]
pub trait LnurlRepository {
    async fn delete_user(&self, domain: &str, pubkey: &str) -> Result<(), LnurlRepositoryError>;
    async fn get_user_by_name(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<Option<User>, LnurlRepositoryError>;
    async fn get_user_by_pubkey(
        &self,
        domain: &str,
        pubkey: &str,
    ) -> Result<Option<User>, LnurlRepositoryError>;
    async fn upsert_user(&self, user: &User) -> Result<(), LnurlRepositoryError>;

    /// Atomically transfer ownership of `username` in `domain` from `from_pubkey`
    /// to `to_pubkey`, replacing any existing row for `to_pubkey`.
    /// Returns [`LnurlRepositoryError::SourceNotOwner`] if `from_pubkey` does not
    /// currently own `username` in `domain`.
    async fn transfer_username(
        &self,
        domain: &str,
        from_pubkey: &str,
        to_pubkey: &str,
        username: &str,
        description: &str,
    ) -> Result<(), LnurlRepositoryError>;

    async fn upsert_zap(&self, zap: &Zap) -> Result<(), LnurlRepositoryError>;
    async fn get_zap_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Zap>, LnurlRepositoryError>;
    async fn insert_lnurl_sender_comment(
        &self,
        comment: &LnurlSenderComment,
    ) -> Result<(), LnurlRepositoryError>;
    async fn get_metadata_by_pubkey(
        &self,
        pubkey: &str,
        offset: u32,
        limit: u32,
        updated_after: Option<i64>,
    ) -> Result<Vec<ListMetadataMetadata>, LnurlRepositoryError>;

    /// Get all allowed domains from the database
    async fn list_domains(&self) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Insert a domain if it doesn't already exist
    async fn add_domain(&self, domain: &str) -> Result<(), LnurlRepositoryError>;

    /// Filter a list of payment hashes to only those the server already knows about
    /// (i.e. have an existing invoice, zap, or sender comment record).
    async fn filter_known_payment_hashes(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Insert or update an invoice
    async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), LnurlRepositoryError>;

    /// Batch upsert invoices with preimages. Inserts new records, or updates existing
    /// ones only if they belong to the same user and don't already have a preimage.
    /// Returns payment hashes that were actually inserted or updated.
    async fn upsert_invoices_paid(
        &self,
        invoices: &[Invoice],
    ) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Get an invoice by payment hash
    async fn get_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Invoice>, LnurlRepositoryError>;

    /// Get both the zap and invoice for a payment hash in a single query
    async fn get_zap_and_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<(Option<Zap>, Option<Invoice>), LnurlRepositoryError>;
    /// Insert a pending zap receipt into the queue
    async fn insert_pending_zap_receipt(
        &self,
        pending: &PendingZapReceipt,
    ) -> Result<(), LnurlRepositoryError>;

    /// Batch insert pending zap receipts into the queue
    async fn insert_pending_zap_receipt_batch(
        &self,
        pending: &[PendingZapReceipt],
    ) -> Result<(), LnurlRepositoryError>;

    /// Get pending zap receipts ready for processing (`next_retry_at` <= now),
    /// atomically claiming them. Items already claimed by another instance
    /// within the last 5 minutes are skipped.
    async fn take_pending_zap_receipts(
        &self,
        limit: u32,
    ) -> Result<Vec<PendingZapReceipt>, LnurlRepositoryError>;

    /// Update retry count and next retry time for a pending zap receipt
    async fn update_pending_zap_receipt_retry(
        &self,
        payment_hash: &str,
        retry_count: i32,
        next_retry_at: i64,
    ) -> Result<(), LnurlRepositoryError>;

    /// Delete a pending zap receipt from the queue
    async fn delete_pending_zap_receipt(
        &self,
        payment_hash: &str,
    ) -> Result<(), LnurlRepositoryError>;

    /// Get or create a setting. If the key doesn't exist, insert the default value.
    /// Returns the current value (either existing or newly inserted).
    async fn get_or_create_setting(
        &self,
        key: &str,
        default_value: &str,
    ) -> Result<String, LnurlRepositoryError>;

    /// Get data needed to build webhook payloads for the given payment hashes.
    /// Joins invoices, users, `sender_comments`, and `domain_webhooks`.
    /// Returns rows for invoices that have a domain and a preimage.
    async fn get_webhook_payloads(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<WebhookPayloadData>, LnurlRepositoryError>;
}

/// Data returned by the webhook enqueue query.
pub struct WebhookPayloadData {
    pub payment_hash: String,
    pub user_pubkey: String,
    pub invoice: String,
    pub preimage: String,
    pub amount_received_sat: Option<i64>,
    pub lightning_address: Option<String>,
    pub sender_comment: Option<String>,
    pub domain: String,
}

#[cfg(test)]
pub mod provider_neutral_schema_tests {
    use sqlx::{Row, SqlitePool};

    const ACCOUNT_TABLES: &[&str] = &[
        "accounts",
        "account_identifiers",
        "spark_accounts",
        "blink_accounts",
    ];

    const SIDE_EFFECT_TABLES: &[&str] = &["invoices", "zaps", "sender_comments"];

    struct TableExpectation<'a> {
        name: &'a str,
        required_columns: &'a [&'a str],
        forbidden_columns: &'a [&'a str],
    }

    const ACCOUNT_EXPECTATIONS: &[TableExpectation<'_>] = &[
        TableExpectation {
            name: "accounts",
            required_columns: &["account_id", "provider", "created_at", "updated_at"],
            forbidden_columns: &["description", "deleted_at"],
        },
        TableExpectation {
            name: "account_identifiers",
            required_columns: &[
                "account_id",
                "domain",
                "identifier",
                "identifier_kind",
                "description",
                "created_at",
                "updated_at",
            ],
            forbidden_columns: &["deleted_at"],
        },
        TableExpectation {
            name: "spark_accounts",
            required_columns: &["account_id", "pubkey", "created_at", "updated_at"],
            forbidden_columns: &["deleted_at"],
        },
        TableExpectation {
            name: "blink_accounts",
            required_columns: &[
                "account_id",
                "blink_account_id",
                "btc_wallet_id",
                "usd_wallet_id",
                "default_wallet",
                "created_at",
                "updated_at",
            ],
            forbidden_columns: &["deleted_at"],
        },
    ];

    #[tokio::test]
    async fn sqlite_provider_neutral_schema_migrates() {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        crate::sqlite::run_migrations(&pool).await.unwrap();

        provider_neutral_schema_migrates(SqlSchema::Sqlite(&pool)).await;
    }

    #[tokio::test]
    async fn postgres_provider_neutral_schema_migrates() {
        let Some(url) = std::env::var("LNURL_TEST_POSTGRES_URL").ok() else {
            return;
        };
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        crate::postgresql::run_migrations(&pool).await.unwrap();

        provider_neutral_schema_migrates(SqlSchema::Postgres(&pool)).await;
    }

    enum SqlSchema<'a> {
        Sqlite(&'a SqlitePool),
        Postgres(&'a sqlx::PgPool),
    }

    async fn provider_neutral_schema_migrates(schema: SqlSchema<'_>) {
        match schema {
            SqlSchema::Sqlite(pool) => assert_sqlite_schema(pool).await,
            SqlSchema::Postgres(pool) => assert_postgres_schema(pool).await,
        }
    }

    async fn assert_sqlite_schema(pool: &SqlitePool) {
        for table in ACCOUNT_TABLES {
            assert!(
                sqlite_table_exists(pool, table).await,
                "missing table {table}"
            );
        }

        for expectation in ACCOUNT_EXPECTATIONS {
            let columns = sqlite_columns(pool, expectation.name).await;
            assert_columns(expectation.name, &columns, expectation.required_columns);
            assert_no_columns(expectation.name, &columns, expectation.forbidden_columns);
        }

        for table in SIDE_EFFECT_TABLES {
            let columns = sqlite_columns(pool, table).await;
            assert_columns(table, &columns, &["account_id", "user_pubkey"]);
            let account_id = sqlite_column(pool, table, "account_id").await;
            assert_eq!(account_id.notnull, 0, "{table}.account_id must be nullable");
        }

        assert_sqlite_check_contains(pool, "accounts", "'spark'").await;
        assert_sqlite_check_contains(pool, "accounts", "'blink'").await;
        assert_sqlite_check_contains(pool, "account_identifiers", "'username'").await;
        assert_sqlite_check_contains(pool, "account_identifiers", "'phone'").await;
        assert_sqlite_check_contains(pool, "blink_accounts", "'btc'").await;
        assert_sqlite_check_contains(pool, "blink_accounts", "'usd'").await;
        assert_sqlite_index_exists(pool, "account_identifiers_domain_identifier_key").await;
        assert_sqlite_index_exists(pool, "spark_accounts_pubkey_key").await;
        assert_sqlite_index_exists(pool, "blink_accounts_blink_account_id_key").await;
        assert_sqlite_index_exists(pool, "idx_invoices_account_id").await;
        assert_sqlite_index_exists(pool, "idx_zaps_account_id").await;
        assert_sqlite_index_exists(pool, "idx_sender_comments_account_id").await;
    }

    async fn assert_postgres_schema(pool: &sqlx::PgPool) {
        for table in ACCOUNT_TABLES {
            assert!(
                postgres_table_exists(pool, table).await,
                "missing table {table}"
            );
        }

        for expectation in ACCOUNT_EXPECTATIONS {
            let columns = postgres_columns(pool, expectation.name).await;
            assert_columns(expectation.name, &columns, expectation.required_columns);
            assert_no_columns(expectation.name, &columns, expectation.forbidden_columns);
        }

        for table in SIDE_EFFECT_TABLES {
            let columns = postgres_columns(pool, table).await;
            assert_columns(table, &columns, &["account_id", "user_pubkey"]);
            assert!(
                postgres_column_is_nullable(pool, table, "account_id").await,
                "{table}.account_id must be nullable"
            );
        }

        assert_postgres_check_contains(pool, "accounts", "'spark'").await;
        assert_postgres_check_contains(pool, "accounts", "'blink'").await;
        assert_postgres_check_contains(pool, "account_identifiers", "'username'").await;
        assert_postgres_check_contains(pool, "account_identifiers", "'phone'").await;
        assert_postgres_check_contains(pool, "blink_accounts", "'btc'").await;
        assert_postgres_check_contains(pool, "blink_accounts", "'usd'").await;
        assert_postgres_index_exists(pool, "account_identifiers_domain_identifier_key").await;
        assert_postgres_index_exists(pool, "spark_accounts_pubkey_key").await;
        assert_postgres_index_exists(pool, "blink_accounts_blink_account_id_key").await;
        assert_postgres_index_exists(pool, "idx_invoices_account_id").await;
        assert_postgres_index_exists(pool, "idx_zaps_account_id").await;
        assert_postgres_index_exists(pool, "idx_sender_comments_account_id").await;
    }

    fn assert_columns(table: &str, columns: &[String], expected: &[&str]) {
        for column in expected {
            assert!(
                columns.iter().any(|actual| actual == column),
                "{table} missing column {column}; columns: {columns:?}"
            );
        }
    }

    fn assert_no_columns(table: &str, columns: &[String], forbidden: &[&str]) {
        for column in forbidden {
            assert!(
                !columns.iter().any(|actual| actual == column),
                "{table} must not expose column {column}"
            );
        }
    }

    struct SqliteColumn {
        notnull: i64,
    }

    async fn sqlite_table_exists(pool: &SqlitePool, table: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    async fn sqlite_columns(pool: &SqlitePool, table: &str) -> Vec<String> {
        let query = format!("PRAGMA table_info({table})");
        sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String, _>("name").unwrap())
            .collect()
    }

    async fn sqlite_column(pool: &SqlitePool, table: &str, column: &str) -> SqliteColumn {
        let query = format!("PRAGMA table_info({table})");
        let row = sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.try_get::<String, _>("name").unwrap() == column)
            .unwrap_or_else(|| panic!("{table} missing column {column}"));
        SqliteColumn {
            notnull: row.try_get("notnull").unwrap(),
        }
    }

    async fn assert_sqlite_check_contains(pool: &SqlitePool, table: &str, expected: &str) {
        let sql = sqlx::query_scalar::<_, String>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(
            sql.contains(expected),
            "{table} DDL missing {expected}: {sql}"
        );
    }

    async fn assert_sqlite_index_exists(pool: &SqlitePool, index: &str) {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .bind(index)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "missing SQLite index/constraint {index}");
    }

    async fn postgres_table_exists(pool: &sqlx::PgPool, table: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    async fn postgres_columns(pool: &sqlx::PgPool, table: &str) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn postgres_column_is_nullable(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
        let nullable = sqlx::query_scalar::<_, String>(
            "SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
        )
        .bind(table)
        .bind(column)
        .fetch_one(pool)
        .await
        .unwrap();
        nullable == "YES"
    }

    async fn assert_postgres_check_contains(pool: &sqlx::PgPool, table: &str, expected: &str) {
        let definitions = sqlx::query_scalar::<_, String>(
            "SELECT pg_get_constraintdef(c.oid)
             FROM pg_constraint c
             JOIN pg_class t ON t.oid = c.conrelid
             JOIN pg_namespace n ON n.oid = t.relnamespace
             WHERE n.nspname = 'public' AND t.relname = $1 AND c.contype = 'c'",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap();
        assert!(
            definitions
                .iter()
                .any(|definition| definition.contains(expected)),
            "{table} checks missing {expected}: {definitions:?}"
        );
    }

    async fn assert_postgres_index_exists(pool: &sqlx::PgPool, index: &str) {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(index)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "missing Postgres index/constraint {index}");
    }
}
