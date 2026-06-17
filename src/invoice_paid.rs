use std::str::FromStr;

use crate::models::PaidInvoice;
use bitcoin::hashes::{Hash, sha256};
use lightning_invoice::Bolt11Invoice;
use tokio::sync::watch;
use tracing::{debug, error};

use crate::repository::{
    AccountProvider, Invoice, LnurlRepository, LnurlRepositoryError, WalletKind,
};
use crate::time::now_millis;
use crate::webhooks::WebhookRepository;

#[derive(Debug, thiserror::Error)]
pub enum HandleInvoicePaidError {
    #[error("invalid invoice: {0}")]
    InvalidInvoice(String),
    #[error("invalid preimage: {0}")]
    InvalidPreimage(String),
    #[error(transparent)]
    Repository(#[from] LnurlRepositoryError),
}

/// Verify that the SHA-256 hash of the preimage matches the expected payment hash.
/// Both values are hex-encoded strings.
fn verify_preimage(payment_hash: &str, preimage: &str) -> Result<(), HandleInvoicePaidError> {
    let preimage_bytes = hex::decode(preimage).map_err(|e| {
        HandleInvoicePaidError::InvalidPreimage(format!("could not hex-decode preimage: {e}"))
    })?;
    let computed_hash = sha256::Hash::hash(&preimage_bytes).to_string();
    if computed_hash != payment_hash {
        return Err(HandleInvoicePaidError::InvalidPreimage(
            "preimage does not match payment hash".to_string(),
        ));
    }
    Ok(())
}

/// Handle an invoice being paid by storing the preimage and queueing for background processing.
pub async fn handle_invoice_paid<DB>(
    db: &DB,
    payment_hash: &str,
    preimage: &str,
    amount_received_sat: Option<i64>,
    trigger: &watch::Sender<()>,
) -> Result<(), HandleInvoicePaidError>
where
    DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
{
    verify_preimage(payment_hash, preimage)?;

    let now = now_millis();

    // Get the existing invoice
    let Some(mut invoice) = db.get_invoice_by_payment_hash(payment_hash).await? else {
        debug!(
            "Invoice not found for payment hash {}, cannot mark as paid",
            payment_hash
        );
        return Ok(());
    };

    if invoice.preimage.is_none() {
        invoice.preimage = Some(preimage.to_string());
        invoice.amount_received_sat = amount_received_sat;
        invoice.updated_at = now;
        db.upsert_invoice(&invoice).await?;
        debug!("Stored preimage for invoice {}", payment_hash);

        crate::zap::enqueue_zap_receipt(db, payment_hash).await?;
    }

    // Notify for all payment hashes, not just newly-affected ones, so that
    // webhooks are delivered even if the server crashed after storing preimages
    // but before enqueueing webhooks. Idempotent via ON CONFLICT DO NOTHING.
    if let Err(e) = crate::webhook_notify::notify_webhooks(db, &[payment_hash.to_string()]).await {
        error!("Failed to enqueue webhook for {}: {}", payment_hash, e);
    }

    if trigger.send(()).is_err() {
        error!("Failed to trigger background processor - receiver dropped");
    }

    Ok(())
}

/// Handle multiple invoices being paid by storing preimages and queueing for background
/// processing in batch. Only processes invoices for payment hashes the server already
/// knows about (has an existing invoice, zap, or sender comment record).
/// Existing invoices are only updated if they belong to the same user and don't already
/// have a preimage.
pub async fn handle_invoices_paid<DB>(
    db: &DB,
    items: &[PaidInvoice],
    user_pubkey: &str,
    trigger: &watch::Sender<()>,
) -> Result<(), HandleInvoicePaidError>
where
    DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
{
    let now = now_millis();
    let mut invoices = Vec::with_capacity(items.len());

    for item in items {
        let preimage_bytes = hex::decode(&item.preimage).map_err(|e| {
            HandleInvoicePaidError::InvalidPreimage(format!("could not hex-decode preimage: {e}"))
        })?;
        let payment_hash = sha256::Hash::hash(&preimage_bytes).to_string();

        let bolt11 = Bolt11Invoice::from_str(&item.invoice).map_err(|e| {
            HandleInvoicePaidError::InvalidInvoice(format!("invalid bolt11 invoice: {e}"))
        })?;

        if bolt11.payment_hash().to_string() != payment_hash {
            return Err(HandleInvoicePaidError::InvalidPreimage(format!(
                "invoice payment hash does not match preimage for hash {payment_hash}"
            )));
        }

        let invoice_expiry = bolt11
            .expires_at()
            .map_or(0, |t| i64::try_from(t.as_millis()).unwrap_or(i64::MAX));

        invoices.push(Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash,
            user_pubkey: user_pubkey.to_string(),
            invoice: item.invoice.clone(),
            preimage: Some(item.preimage.clone()),
            expired_at: None,
            invoice_expiry,
            created_at: now,
            updated_at: now,
            domain: None,
            amount_received_sat: None,
        });
    }

    // Only process invoices for payment hashes the server already knows about
    // (has an existing invoice, zap, or sender comment).
    let all_hashes: Vec<String> = invoices.iter().map(|i| i.payment_hash.clone()).collect();
    let known_hashes: std::collections::HashSet<String> = db
        .filter_known_payment_hashes(&all_hashes)
        .await?
        .into_iter()
        .collect();

    let invoices: Vec<Invoice> = invoices
        .into_iter()
        .filter(|i| known_hashes.contains(&i.payment_hash))
        .collect();

    if invoices.is_empty() {
        debug!("No known payment hashes in invoices-paid request, skipping");
        return Ok(());
    }

    let payment_hashes: Vec<String> = invoices.iter().map(|i| i.payment_hash.clone()).collect();
    let affected = db.upsert_invoices_paid(&invoices).await?;

    if !affected.is_empty() {
        debug!("Stored preimages for {} invoices", affected.len());

        crate::zap::enqueue_zap_receipts(db, &affected).await?;
    }

    // Notify for all payment hashes, not just newly-affected ones, so that
    // webhooks are delivered even if the server crashed after storing preimages
    // but before enqueueing webhooks. Idempotent via ON CONFLICT DO NOTHING.
    if let Err(e) = crate::webhook_notify::notify_webhooks(db, &payment_hashes).await {
        error!("Failed to enqueue webhooks: {}", e);
    }

    if trigger.send(()).is_err() {
        error!("Failed to trigger background processor - receiver dropped");
    }

    Ok(())
}

/// Create a new invoice record for LUD-21 and NIP-57 support.
#[allow(dead_code)]
pub async fn create_invoice<DB>(
    db: &DB,
    payment_hash: &str,
    user_pubkey: &str,
    invoice: &str,
    invoice_expiry: i64,
    domain: &str,
) -> Result<(), LnurlRepositoryError>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    create_invoice_for_account(
        db,
        payment_hash,
        None,
        user_pubkey,
        invoice,
        invoice_expiry,
        domain,
    )
    .await
}

/// Create a new invoice record with optional provider-neutral account ownership.
pub async fn create_invoice_for_account<DB>(
    db: &DB,
    payment_hash: &str,
    account_id: Option<&str>,
    user_pubkey: &str,
    invoice: &str,
    invoice_expiry: i64,
    domain: &str,
) -> Result<(), LnurlRepositoryError>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    create_provider_invoice_for_account(
        db,
        payment_hash,
        account_id,
        None,
        None,
        None,
        None,
        user_pubkey,
        invoice,
        invoice_expiry,
        domain,
    )
    .await
}

/// Create a new invoice record with typed provider-neutral invoice metadata.
#[allow(clippy::too_many_arguments)]
pub async fn create_provider_invoice_for_account<DB>(
    db: &DB,
    payment_hash: &str,
    account_id: Option<&str>,
    provider: Option<AccountProvider>,
    wallet_kind: Option<WalletKind>,
    wallet_id: Option<&str>,
    provider_payment_hash: Option<&str>,
    user_pubkey: &str,
    invoice: &str,
    invoice_expiry: i64,
    domain: &str,
) -> Result<(), LnurlRepositoryError>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    let now = now_millis();
    let invoice_record = Invoice {
        account_id: account_id.map(str::to_string),
        provider,
        wallet_kind,
        wallet_id: wallet_id.map(str::to_string),
        provider_payment_hash: provider_payment_hash.map(str::to_string),
        payment_hash: payment_hash.to_string(),
        user_pubkey: user_pubkey.to_string(),
        invoice: invoice.to_string(),
        preimage: None,
        expired_at: None,
        invoice_expiry,
        created_at: now,
        updated_at: now,
        domain: Some(domain.to_string()),
        amount_received_sat: None,
    };
    db.upsert_invoice(&invoice_record).await?;
    debug!("Created invoice record for payment hash {}", payment_hash);
    Ok(())
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder};

    /// Generate a valid bolt11 invoice for the given preimage bytes.
    /// Returns (`preimage_hex`, `payment_hash_hex`, `invoice_string`).
    pub fn generate_test_invoice(preimage_bytes: &[u8; 32]) -> (String, String, String) {
        let preimage_hex = hex::encode(preimage_bytes);
        let payment_hash = sha256::Hash::hash(preimage_bytes);

        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[42u8; 32]).unwrap();

        let invoice = InvoiceBuilder::new(Currency::Regtest)
            .description("test invoice".to_string())
            .payment_hash(payment_hash)
            .payment_secret(lightning_invoice::PaymentSecret([0u8; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(1_000_000)
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
            .unwrap();

        (preimage_hex, payment_hash.to_string(), invoice.to_string())
    }
}

/// Shared test logic that runs against any `LnurlRepository` implementation.
#[cfg(test)]
mod shared_tests {
    use super::*;
    use crate::repository::{
        AccountIdentifierKind, AccountProvider, LnurlSenderComment, NewAccountIdentifier,
        NewSparkRegistration,
    };

    use super::test_helpers::generate_test_invoice;

    pub async fn create_invoice_for_account_sets_account_id<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some("acct_spark_invoice".to_string()),
            pubkey: "spark_account_invoice_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "account-invoice.example.com".to_string(),
                identifier: "invoiceowner".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "invoice owner".to_string(),
            },
        })
        .await
        .unwrap();
        let account = db
            .get_account_by_spark_pubkey("spark_account_invoice_pubkey")
            .await
            .unwrap()
            .expect("Spark account should be created");
        assert_eq!(account.provider, AccountProvider::Spark);

        create_invoice_for_account(
            db,
            "account_invoice_hash",
            Some(account.account_id.as_str()),
            "spark_account_invoice_pubkey",
            "lnbc1accountinvoice",
            i64::MAX,
            "account-invoice.example.com",
        )
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash("account_invoice_hash")
            .await
            .unwrap()
            .expect("invoice should be stored");
        assert_eq!(stored.account_id.as_deref(), Some("acct_spark_invoice"));
        assert!(stored.provider.is_none());
        assert!(stored.wallet_kind.is_none());
        assert!(stored.wallet_id.is_none());
        assert!(stored.provider_payment_hash.is_none());
        assert_eq!(stored.user_pubkey, "spark_account_invoice_pubkey");
        assert_eq!(
            stored.domain.as_deref(),
            Some("account-invoice.example.com")
        );
    }

    pub async fn create_invoice_for_account_sets_provider_metadata<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some("acct_provider_helper".to_string()),
            pubkey: "spark_provider_helper_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "provider-helper.example.com".to_string(),
                identifier: "providerhelper".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "provider helper".to_string(),
            },
        })
        .await
        .unwrap();

        create_provider_invoice_for_account(
            db,
            "provider_helper_invoice_hash",
            Some("acct_provider_helper"),
            Some(AccountProvider::Spark),
            Some(crate::repository::WalletKind::Btc),
            None,
            None,
            "spark_provider_helper_pubkey",
            "lnbc1providerhelper",
            i64::MAX,
            "provider-helper.example.com",
        )
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash("provider_helper_invoice_hash")
            .await
            .unwrap()
            .expect("invoice should be stored");
        assert_eq!(stored.account_id.as_deref(), Some("acct_provider_helper"));
        assert_eq!(stored.provider, Some(AccountProvider::Spark));
        assert_eq!(stored.wallet_kind, Some(crate::repository::WalletKind::Btc));
        assert!(stored.wallet_id.is_none());
        assert!(stored.provider_payment_hash.is_none());
        assert_eq!(
            stored.domain.as_deref(),
            Some("provider-helper.example.com")
        );
    }

    pub async fn blink_settlement_fallback_persists_through_paid_invoice_handler_test_01<DB>(
        db: &DB,
    ) where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let (trigger, _rx) = watch::channel(());
        let preimage_bytes = [9u8; 32];
        let (preimage_hex, payment_hash, invoice_str) = generate_test_invoice(&preimage_bytes);

        create_provider_invoice_for_account(
            db,
            &payment_hash,
            None,
            Some(AccountProvider::Blink),
            Some(WalletKind::Btc),
            Some("btc_wallet_test_01"),
            Some("provider_payment_hash_test_01"),
            "",
            &invoice_str,
            i64::MAX,
            "settlement-test.example.com",
        )
        .await
        .unwrap();

        handle_invoice_paid(db, &payment_hash, &preimage_hex, Some(123), &trigger)
            .await
            .unwrap();

        let stored = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("Blink invoice should stay stored");
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.preimage.as_deref(), Some(preimage_hex.as_str()));
        assert_eq!(stored.amount_received_sat, Some(123));

        let pending = db.take_pending_zap_receipts(10).await.unwrap();
        assert!(
            pending
                .iter()
                .any(|receipt| receipt.payment_hash == payment_hash),
            "central handler should enqueue zap receipt side effects"
        );
    }

    pub async fn invoices_paid_creates_invoice_when_only_comment_exists<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let (trigger, _rx) = watch::channel(());

        let preimage_bytes = [1u8; 32];
        let (preimage_hex, payment_hash, invoice_str) = generate_test_invoice(&preimage_bytes);
        let user_pubkey = "test_user_pubkey";

        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: None,
            comment: "hello from sender".to_string(),
            payment_hash: payment_hash.clone(),
            user_pubkey: user_pubkey.to_string(),
            updated_at: 1000,
        })
        .await
        .unwrap();

        assert!(
            db.get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .is_none()
        );

        handle_invoices_paid(
            db,
            &[PaidInvoice {
                preimage: preimage_hex.clone(),
                invoice: invoice_str.clone(),
            }],
            user_pubkey,
            &trigger,
        )
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should have been created");
        assert_eq!(stored.preimage.as_deref(), Some(preimage_hex.as_str()));
        assert_eq!(stored.user_pubkey, user_pubkey);
        assert_eq!(stored.invoice, invoice_str);
    }

    pub async fn invoices_paid_creates_invoice_when_only_zap_exists<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let (trigger, _rx) = watch::channel(());

        let preimage_bytes = [2u8; 32];
        let (preimage_hex, payment_hash, invoice_str) = generate_test_invoice(&preimage_bytes);
        let user_pubkey = "test_user_pubkey";

        db.upsert_zap(&crate::zap::Zap {
            account_id: None,
            payment_hash: payment_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: None,
            user_pubkey: user_pubkey.to_string(),
            invoice_expiry: i64::MAX,
            updated_at: 1000,
            is_user_nostr_key: false,
        })
        .await
        .unwrap();

        assert!(
            db.get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .is_none()
        );

        handle_invoices_paid(
            db,
            &[PaidInvoice {
                preimage: preimage_hex.clone(),
                invoice: invoice_str.clone(),
            }],
            user_pubkey,
            &trigger,
        )
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should have been created");
        assert_eq!(stored.preimage.as_deref(), Some(preimage_hex.as_str()));
        assert_eq!(stored.user_pubkey, user_pubkey);
        assert_eq!(stored.invoice, invoice_str);
    }

    pub async fn invoices_paid_ignores_unknown_payment_hash<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let (trigger, _rx) = watch::channel(());

        let preimage_bytes = [3u8; 32];
        let (preimage_hex, payment_hash, invoice_str) = generate_test_invoice(&preimage_bytes);
        let user_pubkey = "test_user_pubkey";

        handle_invoices_paid(
            db,
            &[PaidInvoice {
                preimage: preimage_hex,
                invoice: invoice_str,
            }],
            user_pubkey,
            &trigger,
        )
        .await
        .unwrap();

        assert!(
            db.get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .is_none(),
            "invoice should not be created for unknown payment hash"
        );
    }

    pub async fn invoices_paid_filters_mixed_batch<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let (trigger, _rx) = watch::channel(());
        let user_pubkey = "test_user_pubkey";

        let known_preimage = [4u8; 32];
        let (known_hex, known_hash, known_invoice) = generate_test_invoice(&known_preimage);
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: None,
            comment: "known".to_string(),
            payment_hash: known_hash.clone(),
            user_pubkey: user_pubkey.to_string(),
            updated_at: 1000,
        })
        .await
        .unwrap();

        let unknown_preimage = [5u8; 32];
        let (unknown_hex, unknown_hash, unknown_invoice) = generate_test_invoice(&unknown_preimage);

        handle_invoices_paid(
            db,
            &[
                PaidInvoice {
                    preimage: known_hex.clone(),
                    invoice: known_invoice.clone(),
                },
                PaidInvoice {
                    preimage: unknown_hex,
                    invoice: unknown_invoice,
                },
            ],
            user_pubkey,
            &trigger,
        )
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash(&known_hash)
            .await
            .unwrap()
            .expect("known invoice should have been created");
        assert_eq!(stored.preimage.as_deref(), Some(known_hex.as_str()));

        assert!(
            db.get_invoice_by_payment_hash(&unknown_hash)
                .await
                .unwrap()
                .is_none(),
            "unknown invoice should not be created"
        );
    }

    pub async fn get_or_create_setting_returns_default_on_first_call<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let value = db
            .get_or_create_setting("webhook_secret", "my_secret")
            .await
            .unwrap();
        assert_eq!(value, "my_secret");
    }

    pub async fn get_or_create_setting_returns_existing_on_subsequent_calls<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let first = db
            .get_or_create_setting("webhook_secret", "first_secret")
            .await
            .unwrap();
        let second = db
            .get_or_create_setting("webhook_secret", "different_secret")
            .await
            .unwrap();
        assert_eq!(first, "first_secret");
        assert_eq!(
            second, "first_secret",
            "should return the first value, not the new default"
        );
    }
}

#[cfg(test)]
mod sqlite_tests {
    use super::shared_tests;

    async fn setup_test_db() -> crate::sqlite::LnurlRepository {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap();
        crate::sqlite::run_migrations(&pool).await.unwrap();
        crate::sqlite::LnurlRepository::new(pool)
    }

    #[tokio::test]
    async fn create_invoice_for_account_sets_account_id() {
        let db = setup_test_db().await;
        shared_tests::create_invoice_for_account_sets_account_id(&db).await;
    }

    #[tokio::test]
    async fn create_invoice_for_account_sets_provider_metadata() {
        let db = setup_test_db().await;
        shared_tests::create_invoice_for_account_sets_provider_metadata(&db).await;
    }

    #[tokio::test]
    async fn blink_settlement_fallback_persists_through_paid_invoice_handler_test_01() {
        let db = setup_test_db().await;
        shared_tests::blink_settlement_fallback_persists_through_paid_invoice_handler_test_01(&db)
            .await;
    }

    #[tokio::test]
    async fn invoices_paid_creates_invoice_when_only_comment_exists() {
        let db = setup_test_db().await;
        shared_tests::invoices_paid_creates_invoice_when_only_comment_exists(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_creates_invoice_when_only_zap_exists() {
        let db = setup_test_db().await;
        shared_tests::invoices_paid_creates_invoice_when_only_zap_exists(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_ignores_unknown_payment_hash() {
        let db = setup_test_db().await;
        shared_tests::invoices_paid_ignores_unknown_payment_hash(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_filters_mixed_batch() {
        let db = setup_test_db().await;
        shared_tests::invoices_paid_filters_mixed_batch(&db).await;
    }

    #[tokio::test]
    async fn get_or_create_setting_returns_default_on_first_call() {
        let db = setup_test_db().await;
        shared_tests::get_or_create_setting_returns_default_on_first_call(&db).await;
    }

    #[tokio::test]
    async fn get_or_create_setting_returns_existing_on_subsequent_calls() {
        let db = setup_test_db().await;
        shared_tests::get_or_create_setting_returns_existing_on_subsequent_calls(&db).await;
    }
}

// PostgreSQL tests - only run when LNURL_TEST_POSTGRES_URL is set.
// Example: LNURL_TEST_POSTGRES_URL="postgres://user:pass@localhost/lnurl_test" cargo test
#[cfg(test)]
mod postgres_tests {
    use super::shared_tests;

    async fn setup_test_db() -> Option<crate::postgresql::LnurlRepository> {
        let url = std::env::var("LNURL_TEST_POSTGRES_URL").ok()?;
        let pool = sqlx::PgPool::connect(&url).await.ok()?;
        crate::postgresql::run_migrations(&pool).await.ok()?;

        sqlx::query("DELETE FROM invoices")
            .execute(&pool)
            .await
            .ok()?;
        sqlx::query("DELETE FROM zaps").execute(&pool).await.ok()?;
        sqlx::query("DELETE FROM sender_comments")
            .execute(&pool)
            .await
            .ok()?;
        sqlx::query("DELETE FROM settings")
            .execute(&pool)
            .await
            .ok()?;

        Some(crate::postgresql::LnurlRepository::new(pool))
    }

    #[tokio::test]
    async fn create_invoice_for_account_sets_account_id() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::create_invoice_for_account_sets_account_id(&db).await;
    }

    #[tokio::test]
    async fn create_invoice_for_account_sets_provider_metadata() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::create_invoice_for_account_sets_provider_metadata(&db).await;
    }

    #[tokio::test]
    async fn blink_settlement_fallback_persists_through_paid_invoice_handler_test_01() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::blink_settlement_fallback_persists_through_paid_invoice_handler_test_01(&db)
            .await;
    }

    #[tokio::test]
    async fn invoices_paid_creates_invoice_when_only_comment_exists() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::invoices_paid_creates_invoice_when_only_comment_exists(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_creates_invoice_when_only_zap_exists() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::invoices_paid_creates_invoice_when_only_zap_exists(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_ignores_unknown_payment_hash() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::invoices_paid_ignores_unknown_payment_hash(&db).await;
    }

    #[tokio::test]
    async fn invoices_paid_filters_mixed_batch() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::invoices_paid_filters_mixed_batch(&db).await;
    }

    #[tokio::test]
    async fn get_or_create_setting_returns_default_on_first_call() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::get_or_create_setting_returns_default_on_first_call(&db).await;
    }

    #[tokio::test]
    async fn get_or_create_setting_returns_existing_on_subsequent_calls() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::get_or_create_setting_returns_existing_on_subsequent_calls(&db).await;
    }
}
