use serde::Serialize;
use tracing::debug;

use crate::repository::{LnurlRepository, LnurlRepositoryError};
use crate::time::now_millis;
use crate::webhooks::{NewWebhookDelivery, WebhookRepository, WebhookService};

/// The JSON payload sent to the webhook URL when a payment is received.
/// Uses adjacently tagged representation so all payloads share the same
/// `{ "template": "...", "data": { ... } }` envelope.
#[derive(Debug, Serialize)]
#[serde(tag = "template", content = "data", rename_all = "snake_case")]
pub enum WebhookPayload {
    SparkPaymentReceived {
        payment_hash: String,
        user_pubkey: String,
        invoice: String,
        preimage: String,
        amount_sat: Option<i64>,
        lightning_address: Option<String>,
        sender_comment: Option<String>,
        timestamp: i64,
    },
}

/// Build webhook payloads for the given payment hashes and enqueue them
/// for delivery via the webhook service.
pub async fn notify_webhooks<DB>(
    db: &DB,
    webhook_service: &WebhookService<DB>,
    payment_hashes: &[String],
) -> Result<(), LnurlRepositoryError>
where
    DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
{
    let data = db.get_webhook_payloads(payment_hashes).await?;
    if data.is_empty() {
        return Ok(());
    }

    let now = now_millis();
    let mut deliveries = Vec::with_capacity(data.len());
    for item in data {
        let payload = WebhookPayload::SparkPaymentReceived {
            payment_hash: item.payment_hash.clone(),
            user_pubkey: item.user_pubkey,
            invoice: item.invoice,
            preimage: item.preimage,
            amount_sat: item.amount_received_sat,
            lightning_address: item.lightning_address,
            sender_comment: item.sender_comment,
            timestamp: now,
        };

        let json = serde_json::to_string(&payload).map_err(|e| {
            LnurlRepositoryError::General(anyhow::anyhow!(
                "failed to serialize webhook payload for {}: {}",
                item.payment_hash,
                e
            ))
        })?;

        deliveries.push(NewWebhookDelivery {
            identifier: item.payment_hash,
            domain: item.domain,
            payload: json,
        });
    }

    debug!("Notifying {} webhook deliveries", deliveries.len());
    webhook_service
        .enqueue(&deliveries)
        .await
        .map_err(|e| LnurlRepositoryError::General(e.into()))?;
    Ok(())
}

#[cfg(test)]
mod test_helpers {
    use bitcoin::hashes::{Hash, sha256};
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

#[cfg(test)]
mod shared_tests {
    use crate::repository::{
        AccountIdentifierKind, AccountProvider, Invoice, LnurlRepository, NewAccountIdentifier,
        NewBlinkAccount, WalletKind,
    };
    use crate::time::now_millis;
    use crate::webhooks::{WebhookRepository, WebhookService};

    pub async fn enqueue_webhooks_creates_delivery<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let webhook_service = WebhookService::new(db.clone());
        let preimage_bytes = [10u8; 32];
        let (preimage_hex, payment_hash, invoice_str) =
            super::test_helpers::generate_test_invoice(&preimage_bytes);

        let domain = "enqueue-test.example.com";

        db.add_domain(domain).await.unwrap();
        db.upsert_user(&crate::user::User {
            name: "alice".to_string(),
            pubkey: "enqueue_pubkey".to_string(),
            domain: domain.to_string(),
            description: String::new(),
        })
        .await
        .unwrap();

        let now = now_millis();
        let invoice = Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: payment_hash.clone(),
            user_pubkey: "enqueue_pubkey".to_string(),
            invoice: invoice_str,
            preimage: Some(preimage_hex.clone()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some(domain.to_string()),
            amount_received_sat: Some(1000),
        };
        db.upsert_invoice(&invoice).await.unwrap();

        crate::webhook_notify::notify_webhooks(
            db,
            &webhook_service,
            std::slice::from_ref(&payment_hash),
        )
        .await
        .unwrap();

        let deliveries = db.take_pending_webhook_deliveries().await.unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].identifier, payment_hash);
        assert_eq!(deliveries[0].domain, domain);

        let payload: serde_json::Value = serde_json::from_str(&deliveries[0].payload).unwrap();
        assert_eq!(payload["template"], "payment_received");
        let data = &payload["data"];
        assert_eq!(data["payment_hash"], payment_hash);
        assert_eq!(data["preimage"], preimage_hex);
        assert_eq!(data["lightning_address"], "alice@enqueue-test.example.com");
        assert_eq!(data["amount_sat"], 1000);

        let data_object = data.as_object().expect("payload data must be an object");
        assert!(!data_object.contains_key("provider"));
        assert!(!data_object.contains_key("account_id"));
        assert!(!data_object.contains_key("user_pubkey"));
    }

    pub async fn provider_neutral_invoice_uses_account_identifier_lightning_address<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let webhook_service = WebhookService::new(db.clone());
        let preimage_bytes = [13u8; 32];
        let (preimage_hex, payment_hash, invoice_str) =
            super::test_helpers::generate_test_invoice(&preimage_bytes);

        let domain = "blink-webhook.example.com";
        db.add_domain(domain).await.unwrap();
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some("acct_webhook_blink".to_string()),
            blink_account_id: "blink_webhook_account".to_string(),
            btc_wallet_id: "blink_webhook_btc".to_string(),
            usd_wallet_id: "blink_webhook_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![NewAccountIdentifier {
                domain: domain.to_string(),
                identifier: "alice".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "blink alice".to_string(),
            }],
        })
        .await
        .unwrap();

        let now = now_millis();
        db.upsert_invoice(&Invoice {
            account_id: Some("acct_webhook_blink".to_string()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: Some("blink_webhook_btc".to_string()),
            provider_payment_hash: Some(payment_hash.clone()),
            payment_hash: payment_hash.clone(),
            user_pubkey: String::new(),
            invoice: invoice_str,
            preimage: Some(preimage_hex),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some(domain.to_string()),
            amount_received_sat: Some(2100),
        })
        .await
        .unwrap();

        let payloads = db
            .get_webhook_payloads(std::slice::from_ref(&payment_hash))
            .await
            .unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0].lightning_address.as_deref(),
            Some("alice@blink-webhook.example.com")
        );
        assert_eq!(payloads[0].user_pubkey, "");

        crate::webhook_notify::notify_webhooks(
            db,
            &webhook_service,
            std::slice::from_ref(&payment_hash),
        )
        .await
        .unwrap();

        let deliveries = db.take_pending_webhook_deliveries().await.unwrap();
        assert_eq!(deliveries.len(), 1);
        let payload: serde_json::Value = serde_json::from_str(&deliveries[0].payload).unwrap();
        assert_eq!(payload["template"], "payment_received");
        assert_eq!(
            payload["data"]["lightning_address"],
            "alice@blink-webhook.example.com"
        );
        let data_object = payload["data"]
            .as_object()
            .expect("payload data must be an object");
        assert!(!data_object.contains_key("provider"));
        assert!(!data_object.contains_key("account_id"));
        assert!(!data_object.contains_key("user_pubkey"));
    }

    pub async fn enqueue_webhooks_skips_invoice_without_domain<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let webhook_service = WebhookService::new(db.clone());
        let preimage_bytes = [11u8; 32];
        let (preimage_hex, payment_hash, invoice_str) =
            super::test_helpers::generate_test_invoice(&preimage_bytes);

        let now = now_millis();
        let invoice = Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: payment_hash.clone(),
            user_pubkey: "no_domain_pubkey".to_string(),
            invoice: invoice_str,
            preimage: Some(preimage_hex),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: None,
            amount_received_sat: None,
        };
        db.upsert_invoice(&invoice).await.unwrap();

        crate::webhook_notify::notify_webhooks(db, &webhook_service, &[payment_hash])
            .await
            .unwrap();

        let deliveries = db.take_pending_webhook_deliveries().await.unwrap();
        assert!(
            deliveries.is_empty(),
            "no delivery should be created for invoices without a domain"
        );
    }

    pub async fn enqueue_webhooks_is_idempotent<DB>(db: &DB)
    where
        DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
    {
        let webhook_service = WebhookService::new(db.clone());
        let preimage_bytes = [12u8; 32];
        let (preimage_hex, payment_hash, invoice_str) =
            super::test_helpers::generate_test_invoice(&preimage_bytes);

        let domain = "idempotent-test.example.com";

        db.add_domain(domain).await.unwrap();

        let now = now_millis();
        let invoice = Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: payment_hash.clone(),
            user_pubkey: "idem_pubkey".to_string(),
            invoice: invoice_str,
            preimage: Some(preimage_hex),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some(domain.to_string()),
            amount_received_sat: Some(1000),
        };
        db.upsert_invoice(&invoice).await.unwrap();

        // Enqueue twice — second should be a no-op (ON CONFLICT DO NOTHING)
        crate::webhook_notify::notify_webhooks(
            db,
            &webhook_service,
            std::slice::from_ref(&payment_hash),
        )
        .await
        .unwrap();
        crate::webhook_notify::notify_webhooks(
            db,
            &webhook_service,
            std::slice::from_ref(&payment_hash),
        )
        .await
        .unwrap();

        let deliveries = db.take_pending_webhook_deliveries().await.unwrap();
        assert_eq!(
            deliveries.len(),
            1,
            "duplicate enqueue should not create a second delivery"
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
    async fn webhook_payload_enqueue_webhooks_creates_delivery() {
        let db = setup_test_db().await;
        shared_tests::enqueue_webhooks_creates_delivery(&db).await;
    }

    #[tokio::test]
    async fn enqueue_webhooks_skips_invoice_without_domain() {
        let db = setup_test_db().await;
        shared_tests::enqueue_webhooks_skips_invoice_without_domain(&db).await;
    }

    #[tokio::test]
    async fn enqueue_webhooks_is_idempotent() {
        let db = setup_test_db().await;
        shared_tests::enqueue_webhooks_is_idempotent(&db).await;
    }

    #[tokio::test]
    async fn webhook_payload_provider_neutral_invoice_uses_account_identifier_lightning_address() {
        let db = setup_test_db().await;
        shared_tests::provider_neutral_invoice_uses_account_identifier_lightning_address(&db).await;
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

        sqlx::query("DELETE FROM webhook_deliveries")
            .execute(&pool)
            .await
            .ok()?;
        sqlx::query("DELETE FROM domain_webhooks")
            .execute(&pool)
            .await
            .ok()?;
        sqlx::query("DELETE FROM invoices")
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
    async fn webhook_payload_enqueue_webhooks_creates_delivery() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::enqueue_webhooks_creates_delivery(&db).await;
    }

    #[tokio::test]
    async fn enqueue_webhooks_skips_invoice_without_domain() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::enqueue_webhooks_skips_invoice_without_domain(&db).await;
    }

    #[tokio::test]
    async fn enqueue_webhooks_is_idempotent() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::enqueue_webhooks_is_idempotent(&db).await;
    }

    #[tokio::test]
    async fn webhook_payload_provider_neutral_invoice_uses_account_identifier_lightning_address() {
        let Some(db) = setup_test_db().await else {
            return;
        };
        shared_tests::provider_neutral_invoice_uses_account_identifier_lightning_address(&db).await;
    }
}
