#![allow(dead_code)]
#![allow(unused_imports)]

use super::*;
pub(super) use crate::identifier::IdentifierError;
use crate::invoice_paid::{
    HandleInvoicePaidError, create_provider_invoice_for_account, handle_invoice_paid,
    handle_invoices_paid,
};
pub(super) use crate::models::sanitize_username;
pub(super) use crate::models::{
    CheckUsernameAvailableResponse, CreateBlinkAccountRequest, CreateBlinkAccountResponse,
    INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS, INTERNAL_ERROR_IDENTIFIER_CONFLICT,
    INTERNAL_ERROR_INTERNAL_SERVER_ERROR, INTERNAL_ERROR_INVALID_DOMAIN,
    INTERNAL_ERROR_INVALID_IDENTIFIER, INTERNAL_ERROR_INVALID_REQUEST, INTERNAL_ERROR_NOT_FOUND,
    INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED, InternalAccountIdentifierResponse,
    InternalErrorResponse, InternalIdentifierLookupResponse, InternalProviderDetailsResponse,
    InternalTransferToSparkRequest, InternalTransferToSparkResponse, InvoicePaidRequest,
    InvoicesPaidRequest, ListMetadataMetadata, UpdateBlinkAccountRequest,
};
use crate::providers::{CreateInvoiceRequest, PaymentStatusRequest, ProviderError};
pub(super) use crate::repository::{
    AccountIdentifierKind, AccountProvider, BlinkToSparkIdentifierTransfer, IdentifierTransfer,
    Invoice, LnurlRepository, LnurlRepositoryError, LnurlSenderComment, NewAccountIdentifier,
    NewBlinkAccount, PendingZapReceipt, ResolvedRecipient, SparkUsername, UpdatedBlinkAccount,
    WalletKind, generate_account_id,
};
pub(super) use crate::routes::lnurl_pay::lnurl_error;
use crate::state::State;
use crate::time::now_millis;
pub(super) use crate::webhooks::NewWebhookDelivery;
pub(super) use crate::webhooks::repository::WebhookRepositoryError;
pub(super) use crate::zap::Zap;
pub(super) use axum::body::Bytes;
pub(super) use axum::extract::{Path, Query};
pub(super) use axum::http::{HeaderMap, Request, StatusCode};
pub(super) use axum::middleware;
pub(super) use axum::response::IntoResponse;
pub(super) use axum::routing::{get, post};
pub(super) use axum::{Extension, Json, Router};
use axum_extra::extract::Host;
pub(super) use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
pub(super) use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
pub(super) use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightning_invoice::Bolt11Invoice;
pub(super) use serde_json::{Value, json};
pub(super) use std::collections::HashMap;
pub(super) use std::str::FromStr;
pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) use std::sync::{Arc, Mutex};
pub(super) use tokio::sync::watch;
pub(super) use tower::util::ServiceExt;

// -- Mock repository -------------------------------------------------------

#[derive(Clone, Default)]
pub(super) struct MockRepository {
    pub(super) invoices: std::sync::Arc<Mutex<HashMap<String, Invoice>>>,
    pub(super) pending_zap_receipts: std::sync::Arc<Mutex<HashMap<String, PendingZapReceipt>>>,
    pub(super) webhook_deliveries: std::sync::Arc<Mutex<Vec<NewWebhookDelivery>>>,
    pub(super) created_blink_accounts: std::sync::Arc<Mutex<Vec<NewBlinkAccount>>>,
    pub(super) create_blink_account_error:
        std::sync::Arc<Mutex<Option<MockCreateBlinkAccountError>>>,
    pub(super) updated_blink_accounts: std::sync::Arc<Mutex<Vec<(String, WalletKind)>>>,
    pub(super) update_blink_account_error:
        std::sync::Arc<Mutex<Option<MockUpdateBlinkAccountError>>>,
    pub(super) resolved_recipient: std::sync::Arc<Mutex<Option<ResolvedRecipient>>>,
    pub(super) resolve_calls: std::sync::Arc<Mutex<Vec<(String, String)>>>,
    pub(super) blink_to_spark_transfers: std::sync::Arc<Mutex<Vec<BlinkToSparkIdentifierTransfer>>>,
}

#[derive(Clone, Copy)]
pub(super) enum MockCreateBlinkAccountError {
    BlinkAccountExists,
    IdentifierConflict,
    NameTaken,
}

#[derive(Clone, Copy)]
pub(super) enum MockUpdateBlinkAccountError {
    AccountNotFound,
    Storage,
}

impl MockRepository {
    pub(super) fn fail_next_blink_account_creation(&self, error: MockCreateBlinkAccountError) {
        *self.create_blink_account_error.lock().unwrap() = Some(error);
    }

    pub(super) fn created_blink_account_count(&self) -> usize {
        self.created_blink_accounts.lock().unwrap().len()
    }

    pub(super) fn fail_next_blink_account_update(&self, error: MockUpdateBlinkAccountError) {
        *self.update_blink_account_error.lock().unwrap() = Some(error);
    }

    pub(super) fn updated_blink_account_count(&self) -> usize {
        self.updated_blink_accounts.lock().unwrap().len()
    }

    pub(super) fn with_resolved_recipient(self, recipient: ResolvedRecipient) -> Self {
        *self.resolved_recipient.lock().unwrap() = Some(recipient);
        self
    }

    pub(super) fn resolve_calls(&self) -> Vec<(String, String)> {
        self.resolve_calls.lock().unwrap().clone()
    }

    pub(super) fn blink_to_spark_transfer_count(&self) -> usize {
        self.blink_to_spark_transfers.lock().unwrap().len()
    }

    pub(super) fn blink_to_spark_transfers(&self) -> Vec<BlinkToSparkIdentifierTransfer> {
        self.blink_to_spark_transfers.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl LnurlRepository for MockRepository {
    async fn get_spark_username_by_name(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<SparkUsername>, LnurlRepositoryError> {
        Ok(None)
    }
    async fn get_spark_username_by_pubkey(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<SparkUsername>, LnurlRepositoryError> {
        Ok(None)
    }
    async fn resolve_recipient_by_identifier(
        &self,
        domain: &str,
        identifier: &str,
    ) -> Result<Option<ResolvedRecipient>, LnurlRepositoryError> {
        self.resolve_calls
            .lock()
            .unwrap()
            .push((domain.to_string(), identifier.to_string()));
        Ok(self.resolved_recipient.lock().unwrap().clone())
    }
    async fn get_account_by_spark_pubkey(
        &self,
        _: &str,
    ) -> Result<Option<crate::repository::Account>, LnurlRepositoryError> {
        Ok(None)
    }
    async fn create_blink_account(
        &self,
        account: &NewBlinkAccount,
    ) -> Result<(), LnurlRepositoryError> {
        self.created_blink_accounts
            .lock()
            .unwrap()
            .push(account.clone());
        if let Some(error) = self.create_blink_account_error.lock().unwrap().take() {
            return match error {
                MockCreateBlinkAccountError::BlinkAccountExists => {
                    Err(LnurlRepositoryError::BlinkAccountExists)
                }
                MockCreateBlinkAccountError::IdentifierConflict => {
                    Err(LnurlRepositoryError::IdentifierConflict)
                }
                MockCreateBlinkAccountError::NameTaken => Err(LnurlRepositoryError::NameTaken),
            };
        }
        Ok(())
    }
    async fn update_blink_default_wallet(
        &self,
        blink_account_id: &str,
        default_wallet: WalletKind,
    ) -> Result<UpdatedBlinkAccount, LnurlRepositoryError> {
        self.updated_blink_accounts
            .lock()
            .unwrap()
            .push((blink_account_id.to_string(), default_wallet));
        if let Some(error) = self.update_blink_account_error.lock().unwrap().take() {
            return match error {
                MockUpdateBlinkAccountError::AccountNotFound => {
                    Err(LnurlRepositoryError::AccountNotFound)
                }
                MockUpdateBlinkAccountError::Storage => Err(LnurlRepositoryError::General(
                    anyhow::anyhow!("forced update failure"),
                )),
            };
        }
        Ok(UpdatedBlinkAccount {
            account_id: "acct_updated_blink".to_string(),
            provider: AccountProvider::Blink,
            blink_account_id: blink_account_id.to_string(),
            default_wallet,
        })
    }
    async fn transfer_identifier(
        &self,
        _: &IdentifierTransfer,
    ) -> Result<(), LnurlRepositoryError> {
        Ok(())
    }
    async fn transfer_blink_identifier_to_spark(
        &self,
        transfer: &BlinkToSparkIdentifierTransfer,
    ) -> Result<(), LnurlRepositoryError> {
        self.blink_to_spark_transfers
            .lock()
            .unwrap()
            .push(transfer.clone());
        Ok(())
    }
    async fn upsert_zap(&self, _: &Zap) -> Result<(), LnurlRepositoryError> {
        Ok(())
    }
    async fn get_zap_by_payment_hash(&self, _: &str) -> Result<Option<Zap>, LnurlRepositoryError> {
        Ok(None)
    }
    async fn insert_lnurl_sender_comment(
        &self,
        _: &LnurlSenderComment,
    ) -> Result<(), LnurlRepositoryError> {
        Ok(())
    }
    async fn get_metadata_by_pubkey(
        &self,
        _: &str,
        _: u32,
        _: u32,
        _: Option<i64>,
    ) -> Result<Vec<ListMetadataMetadata>, LnurlRepositoryError> {
        Ok(vec![])
    }
    async fn list_domains(&self) -> Result<Vec<String>, LnurlRepositoryError> {
        Ok(vec![])
    }
    async fn add_domain(&self, _: &str) -> Result<(), LnurlRepositoryError> {
        Ok(())
    }
    async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), LnurlRepositoryError> {
        self.invoices
            .lock()
            .unwrap()
            .insert(invoice.payment_hash.clone(), invoice.clone());
        Ok(())
    }
    async fn get_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Invoice>, LnurlRepositoryError> {
        Ok(self.invoices.lock().unwrap().get(payment_hash).cloned())
    }
    async fn mark_invoice_expired(
        &self,
        payment_hash: &str,
        expired_at: i64,
    ) -> Result<(), LnurlRepositoryError> {
        if let Some(invoice) = self.invoices.lock().unwrap().get_mut(payment_hash) {
            invoice.expired_at = Some(expired_at);
            invoice.updated_at = expired_at;
        }
        Ok(())
    }
    async fn get_zap_and_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<(Option<Zap>, Option<Invoice>), LnurlRepositoryError> {
        Ok((
            None,
            self.invoices.lock().unwrap().get(payment_hash).cloned(),
        ))
    }
    async fn insert_pending_zap_receipt(
        &self,
        pending: &PendingZapReceipt,
    ) -> Result<(), LnurlRepositoryError> {
        self.pending_zap_receipts
            .lock()
            .unwrap()
            .insert(pending.payment_hash.clone(), pending.clone());
        Ok(())
    }
    async fn take_pending_zap_receipts(
        &self,
        _limit: u32,
    ) -> Result<Vec<PendingZapReceipt>, LnurlRepositoryError> {
        Ok(self
            .pending_zap_receipts
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect())
    }
    async fn update_pending_zap_receipt_retry(
        &self,
        _: &str,
        _: i32,
        _: i64,
    ) -> Result<(), LnurlRepositoryError> {
        Ok(())
    }
    async fn delete_pending_zap_receipt(
        &self,
        payment_hash: &str,
    ) -> Result<(), LnurlRepositoryError> {
        self.pending_zap_receipts
            .lock()
            .unwrap()
            .remove(payment_hash);
        Ok(())
    }
    async fn filter_known_payment_hashes(
        &self,
        _payment_hashes: &[String],
    ) -> Result<Vec<String>, LnurlRepositoryError> {
        Ok(vec![])
    }
    async fn upsert_invoices_paid(
        &self,
        invoices: &[Invoice],
    ) -> Result<Vec<String>, LnurlRepositoryError> {
        let mut store = self.invoices.lock().unwrap();
        let mut updated = Vec::new();
        for invoice in invoices {
            store.insert(invoice.payment_hash.clone(), invoice.clone());
            updated.push(invoice.payment_hash.clone());
        }
        Ok(updated)
    }
    async fn insert_pending_zap_receipt_batch(
        &self,
        pending: &[PendingZapReceipt],
    ) -> Result<(), LnurlRepositoryError> {
        let mut store = self.pending_zap_receipts.lock().unwrap();
        for p in pending {
            store.insert(p.payment_hash.clone(), p.clone());
        }
        Ok(())
    }
    async fn get_or_create_setting(
        &self,
        _key: &str,
        default_value: &str,
    ) -> Result<String, LnurlRepositoryError> {
        Ok(default_value.to_string())
    }
    async fn get_webhook_payloads(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<crate::repository::WebhookPayloadData>, LnurlRepositoryError> {
        let invoices = self.invoices.lock().unwrap();
        Ok(payment_hashes
            .iter()
            .filter_map(|payment_hash| {
                let invoice = invoices.get(payment_hash)?;
                Some(crate::repository::WebhookPayloadData {
                    account_id: invoice.account_id.clone(),
                    payment_hash: invoice.payment_hash.clone(),
                    user_pubkey: invoice.user_pubkey.clone(),
                    invoice: invoice.invoice.clone(),
                    preimage: invoice.preimage.clone()?,
                    amount_received_sat: invoice.amount_received_sat,
                    lightning_address: invoice
                        .domain
                        .as_ref()
                        .map(|domain| format!("alice@{domain}")),
                    sender_comment: Some("verify fallback zap".to_string()),
                    domain: invoice.domain.clone()?,
                })
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::webhooks::WebhookRepository for MockRepository {
    async fn insert_webhook_deliveries(
        &self,
        deliveries: &[crate::webhooks::NewWebhookDelivery],
    ) -> Result<(), WebhookRepositoryError> {
        self.webhook_deliveries
            .lock()
            .unwrap()
            .extend_from_slice(deliveries);
        Ok(())
    }
    async fn take_pending_webhook_deliveries(
        &self,
    ) -> Result<Vec<crate::webhooks::repository::WebhookDelivery>, WebhookRepositoryError> {
        Ok(vec![])
    }
    async fn update_webhook_delivery_success(
        &self,
        _: i64,
        _: i64,
        _: &str,
    ) -> Result<(), WebhookRepositoryError> {
        Ok(())
    }
    async fn update_webhook_delivery_failure(
        &self,
        _: i64,
        _: i32,
        _: i64,
        _: Option<i32>,
        _: Option<&str>,
        _: &str,
    ) -> Result<(), WebhookRepositoryError> {
        Ok(())
    }
    async fn unclaim_webhook_deliveries(&self, _: &[i64]) -> Result<(), WebhookRepositoryError> {
        Ok(())
    }
    async fn delete_webhook_deliveries_older_than(
        &self,
        _: i64,
    ) -> Result<u64, WebhookRepositoryError> {
        Ok(0)
    }
    async fn delete_webhook_delivery(&self, _: i64) -> Result<(), WebhookRepositoryError> {
        Ok(())
    }
    async fn park_webhook_delivery(&self, _: i64) -> Result<(), WebhookRepositoryError> {
        Ok(())
    }
    async fn list_webhook_configs(
        &self,
    ) -> Result<Vec<crate::webhooks::repository::WebhookConfig>, WebhookRepositoryError> {
        Ok(vec![])
    }
}

// -- Test helpers ----------------------------------------------------------

pub(super) const TEST_WEBHOOK_SECRET: &str = "test_webhook_secret_0123456789abcdef";
pub(super) const TEST_PREIMAGE_HEX: &str =
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
pub(super) const TEST_RECEIVER_PUBKEY: &str = "02abc123";

pub(super) fn compute_payment_hash(preimage_hex: &str) -> String {
    let preimage_bytes = hex::decode(preimage_hex).unwrap();
    sha256::Hash::hash(&preimage_bytes).to_string()
}

pub(super) fn compute_hmac(secret: &str, body: &[u8]) -> String {
    let mut engine = HmacEngine::<sha256::Hash>::new(secret.as_bytes());
    engine.input(body);
    let hmac: Hmac<sha256::Hash> = Hmac::from_engine(engine);
    hex::encode(hmac.to_byte_array())
}

pub(super) fn make_webhook_payload(
    event_type: &str,
    preimage: Option<&str>,
    receiver_pubkey: Option<&str>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "id": "018677b5-e419-99d1-0000-a7030393c9af",
        "created_at": "2025-03-09T12:00:00Z",
        "updated_at": "2025-03-09T12:00:05Z",
        "network": "MAINNET",
        "request_status": "COMPLETED",
        "status": "TRANSFER_COMPLETED",
        "type": event_type,
        "timestamp": "2025-03-09T12:00:06Z",
        "invoice_amount": {"value": 50_000, "unit": "SATOSHI"},
        "htlc_amount": {"value": 50_000, "unit": "SATOSHI"},
    });
    if let Some(p) = preimage {
        payload["payment_preimage"] = serde_json::Value::String(p.to_string());
    }
    if let Some(r) = receiver_pubkey {
        payload["receiver_identity_public_key"] = serde_json::Value::String(r.to_string());
    }
    payload
}

pub(super) fn signed_headers_and_body(
    secret: &str,
    payload: &serde_json::Value,
) -> (HeaderMap, Bytes) {
    let body = serde_json::to_vec(payload).unwrap();
    let sig = compute_hmac(secret, &body);
    let mut headers = HeaderMap::new();
    headers.insert("X-Spark-Signature", sig.parse().unwrap());
    (headers, Bytes::from(body))
}

pub(super) async fn internal_route_test_state(
    repo: MockRepository,
    internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
) -> State<MockRepository> {
    internal_route_test_state_with_blink_endpoint(
        repo,
        internal_auth,
        blink_client::PRODUCTION_GRAPHQL_ENDPOINT,
    )
    .await
}

pub(super) async fn internal_route_test_state_with_blink_endpoint(
    repo: MockRepository,
    internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
    blink_endpoint: &str,
) -> State<MockRepository> {
    internal_route_test_state_with_blink_endpoint_and_provider_flags(
        repo,
        internal_auth,
        blink_endpoint,
        true,
        true,
    )
    .await
}

pub(super) async fn internal_route_test_state_with_blink_endpoint_and_provider_flags(
    repo: MockRepository,
    internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
    blink_endpoint: &str,
    spark_enabled: bool,
    blink_enabled: bool,
) -> State<MockRepository> {
    let network = spark_client::Network::Regtest;
    let auth_seed = [7_u8; 32];
    let blink_webhook_url = Some("http://127.0.0.1/webhook/blink".to_string());
    let spark_client =
        spark_client::Client::new(spark_client::ClientConfig::new(network, auth_seed))
            .await
            .unwrap();
    let providers = Arc::new(crate::providers::ProviderRegistry::new(
        spark_client.clone(),
        (!blink_endpoint.is_empty()).then_some(blink_endpoint),
        blink_webhook_url,
        spark_enabled,
        blink_enabled,
    ));
    let (invoice_paid_trigger, _rx) = watch::channel(());
    State {
        db: repo.clone(),
        spark_client,
        providers,
        internal_auth,
        scheme: "http".to_string(),
        min_sendable: 1_000,
        max_sendable: 4_000_000_000,
        include_spark_address: false,
        domains: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
        nostr_keys: None,
        ca_cert: None,
        crl_url: None,
        crl: std::collections::HashSet::new(),
        invoice_paid_trigger,
        webhook_secret: TEST_WEBHOOK_SECRET.to_string(),
    }
}

pub(super) fn setup_repo_with_invoice(preimage_hex: &str, receiver_pubkey: &str) -> MockRepository {
    let repo = MockRepository::default();
    let payment_hash = compute_payment_hash(preimage_hex);
    repo.invoices.lock().unwrap().insert(
        payment_hash.clone(),
        Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash,
            user_pubkey: receiver_pubkey.to_string(),
            invoice: "lnbc1...".to_string(),
            preimage: None,
            expired_at: None,
            invoice_expiry: i64::MAX,
            created_at: 0,
            updated_at: 0,
            domain: None,
            amount_received_sat: None,
        },
    );
    repo
}

pub(super) fn generate_route_test_invoice(preimage_byte: u8) -> (String, String) {
    generate_route_test_invoice_with_description_hash(
        preimage_byte,
        sha256::Hash::hash("route test invoice".as_bytes()),
    )
}

pub(super) fn generate_route_test_invoice_with_description_hash(
    preimage_byte: u8,
    description_hash: sha256::Hash,
) -> (String, String) {
    let preimage = [preimage_byte; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[42_u8; 32]).unwrap();
    let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
        .description_hash(description_hash)
        .payment_hash(payment_hash)
        .payment_secret(lightning_invoice::PaymentSecret([0_u8; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .expect("test invoice should build");

    (payment_hash.to_string(), invoice.to_string())
}

pub(super) async fn start_blink_invoice_mock_server(
    _bolt11: String,
    fail: bool,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<Value>>>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let calls_for_route = Arc::clone(&calls);
    let bodies_for_route = Arc::clone(&bodies);
    let app = Router::new().route(
        "/graphql",
        post(move |Json(body): Json<Value>| {
            let calls = Arc::clone(&calls_for_route);
            let bodies = Arc::clone(&bodies_for_route);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                bodies.lock().unwrap().push(body.clone());
                if fail {
                    return Json(json!({
                        "data": {
                            "lnInvoiceCreateOnBehalfOfRecipient": { "invoice": null, "errors": [{"message": "upstream hidden"}] },
                            "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": { "invoice": null, "errors": [{"message": "upstream hidden"}] }
                        }
                    }));
                }
                let request_description_hash = body["variables"]["input"]["descriptionHash"]
                    .as_str()
                    .and_then(|hash| sha256::Hash::from_str(hash).ok())
                    .expect("Blink invoice mock requires a description hash");
                let call_index = u8::try_from(calls.load(Ordering::SeqCst)).unwrap_or(u8::MAX);
                let (_, bolt11) = generate_route_test_invoice_with_description_hash(
                    100_u8.saturating_add(call_index),
                    request_description_hash,
                );
                Json(json!({
                    "data": {
                        "lnInvoiceCreateOnBehalfOfRecipient": {
                            "invoice": { "paymentRequest": bolt11, "paymentHash": "provider_btc_hash" },
                            "errors": []
                        },
                        "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": {
                            "invoice": { "paymentRequest": bolt11, "paymentHash": "provider_usd_hash" },
                            "errors": []
                        }
                    }
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener should bind");
    let addr = listener
        .local_addr()
        .expect("mock listener should have addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock Blink server should serve");
    });
    (format!("http://{addr}/graphql"), calls, bodies)
}

pub(super) async fn start_blink_status_mock_server(
    status: &'static str,
    preimage: Option<String>,
    fail: bool,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<Value>>>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let calls_for_route = Arc::clone(&calls);
    let bodies_for_route = Arc::clone(&bodies);
    let app = Router::new().route(
        "/graphql",
        post(move |Json(body): Json<Value>| {
            let calls = Arc::clone(&calls_for_route);
            let bodies = Arc::clone(&bodies_for_route);
            let preimage = preimage.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                bodies.lock().unwrap().push(body.clone());
                if fail {
                    return Json(json!({
                        "errors": [{"message": "upstream status hidden"}]
                    }));
                }
                let payment_hash = body["variables"]["input"]["paymentHash"]
                    .as_str()
                    .expect("Blink status mock requires paymentHash")
                    .to_string();
                Json(json!({
                    "data": {
                        "lnInvoicePaymentStatusByHash": {
                            "status": status,
                            "paymentHash": payment_hash,
                            "paymentRequest": "lnbc1status",
                            "paymentPreimage": preimage
                        }
                    }
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener should bind");
    let addr = listener
        .local_addr()
        .expect("mock listener should have addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock Blink status server should serve");
    });
    (format!("http://{addr}/graphql"), calls, bodies)
}

pub(super) fn route_test_invoice(
    provider: Option<AccountProvider>,
    payment_hash: String,
    invoice: &str,
    preimage: Option<String>,
) -> Invoice {
    Invoice {
        account_id: Some("acct_verify_blink".to_string()),
        provider,
        wallet_kind: Some(WalletKind::Btc),
        wallet_id: Some("btc_wallet_verify".to_string()),
        provider_payment_hash: Some(payment_hash.clone()),
        payment_hash,
        user_pubkey: String::new(),
        invoice: invoice.to_string(),
        preimage,
        expired_at: None,
        invoice_expiry: i64::MAX,
        created_at: 0,
        updated_at: 0,
        domain: Some("verify.example.com".to_string()),
        amount_received_sat: None,
    }
}

pub(super) async fn call_verify(state: State<MockRepository>, payment_hash: &str) -> Value {
    let response =
        LnurlServer::<MockRepository>::verify(Path(payment_hash.to_string()), Extension(state))
            .await
            .into_response();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    serde_json::from_slice(&body.expect("verify response body reads"))
        .expect("verify response body is JSON")
}

pub(super) async fn get_public_invoice(
    state: State<MockRepository>,
    identifier: &str,
    params: LnurlPayCallbackParams,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    LnurlServer::<MockRepository>::handle_invoice(
        Host("example.com".to_string()),
        Path(identifier.to_string()),
        Query(params),
        Extension(state),
    )
    .await
}

pub(super) fn assert_lnurl_error(
    result: Result<Json<Value>, (StatusCode, Json<Value>)>,
    reason: &str,
) {
    let Err((status, Json(body))) = result else {
        panic!("expected LNURL error {reason}");
    };
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["reason"], reason);
}

pub(super) fn internal_test_token() -> String {
    let private_key = include_bytes!("../../tests/fixtures/internal_auth_private.pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("blink-internal-test-key".to_string());
    encode(
        &header,
        &serde_json::json!({
            "sub": "blink-core-test-service",
            "iss": "https://issuer.internal.test",
            "aud": "lnurl-server.internal.test",
            "exp": 4_102_444_800_u64,
            "nbf": 1_700_000_000_u64,
            "scope": "blink:accounts:create blink:accounts:read"
        }),
        &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
    )
    .expect("test JWT must sign")
}

pub(super) fn internal_auth_state() -> Arc<crate::internal_auth::InternalAuthState> {
    let jwks = include_str!("../../tests/fixtures/internal_auth_jwks.json");
    Arc::new(
        crate::internal_auth::InternalAuthState::from_jwks_json(
            jwks,
            "https://issuer.internal.test".to_string(),
            "lnurl-server.internal.test".to_string(),
        )
        .expect("test JWKS fixture must load"),
    )
}

pub(super) async fn internal_account_app(repo: MockRepository) -> Router {
    let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
    internal_account_app_with_state(state)
}

pub(super) fn internal_account_app_with_state(state: State<MockRepository>) -> Router {
    Router::new()
        .route(
            "/internal/blink/accounts",
            post(LnurlServer::<MockRepository>::create_internal_blink_account),
        )
        .route(
            "/internal/blink/accounts/{blink_account_id}",
            axum::routing::patch(LnurlServer::<MockRepository>::update_internal_blink_account),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::internal_auth::internal_auth::<MockRepository>,
        ))
        .layer(Extension(state))
}

pub(super) async fn internal_lookup_app(repo: MockRepository) -> Router {
    let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
    internal_lookup_app_with_state(state)
}

pub(super) fn internal_lookup_app_with_state(state: State<MockRepository>) -> Router {
    Router::new()
        .route(
            "/internal/domains/{domain}/identifiers/{identifier}",
            get(LnurlServer::<MockRepository>::get_internal_identifier),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::internal_auth::internal_auth::<MockRepository>,
        ))
        .layer(Extension(state))
}

pub(super) fn blink_webhook_app_with_state(state: State<MockRepository>) -> Router {
    Router::new()
        .route(
            "/webhook/blink",
            post(LnurlServer::<MockRepository>::blink_webhook),
        )
        .layer(Extension(state))
}

pub(super) fn internal_transfer_to_spark_app_with_state(state: State<MockRepository>) -> Router {
    Router::new()
        .route(
            "/internal/identifiers/transfer-to-spark",
            post(LnurlServer::<MockRepository>::transfer_identifier_to_spark),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::internal_auth::internal_auth::<MockRepository>,
        ))
        .layer(Extension(state))
}

pub(super) async fn internal_transfer_to_spark_app(repo: MockRepository) -> Router {
    let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
    internal_transfer_to_spark_app_with_state(state)
}

pub(super) async fn post_internal_transfer_to_spark(
    app: Router,
    payload: InternalTransferToSparkRequest,
    scope: &str,
) -> (StatusCode, Value) {
    let body = serde_json::to_vec(&payload).expect("request serializes");
    post_internal_transfer_to_spark_raw(app, body, scope).await
}

pub(super) async fn post_internal_transfer_to_spark_raw(
    app: Router,
    body: impl Into<axum::body::Body>,
    scope: &str,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/internal/identifiers/transfer-to-spark")
        .header(
            "authorization",
            format!("Bearer {}", internal_test_token_with_scope(scope)),
        )
        .header("content-type", "application/json")
        .body(body.into())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("response body is JSON")
    };
    (status, body)
}

pub(super) async fn post_blink_webhook(app: Router, payload: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/webhook/blink")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&payload).expect("request serializes"),
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("response body is JSON")
    };
    (status, body)
}

pub(super) fn blink_webhook_payload(status: &str, payment_hash: &str) -> Value {
    json!({
        "paymentHash": payment_hash,
        "paymentPreimage": TEST_PREIMAGE_HEX,
        "status": status
    })
}

pub(super) async fn post_blink_webhook_path(app: Router, uri: &str, payload: Value) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&payload).expect("request serializes"),
        ))
        .expect("request builds");

    app.oneshot(request).await.expect("route responds").status()
}

pub(super) fn valid_create_blink_account_payload() -> CreateBlinkAccountRequest {
    CreateBlinkAccountRequest {
        domain: "Example.COM".to_string(),
        blink_account_id: "blink_account_123".to_string(),
        btc_wallet_id: "btc_wallet_123".to_string(),
        usd_wallet_id: "usd_wallet_123".to_string(),
        default_wallet: "usd".to_string(),
        description: "Blink account".to_string(),
        identifiers: vec![" Alice_123 ".to_string(), "+573005871212".to_string()],
    }
}

pub(super) async fn post_internal_blink_account(
    app: Router,
    payload: CreateBlinkAccountRequest,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/internal/blink/accounts")
        .header("authorization", format!("Bearer {}", internal_test_token()))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&payload).expect("request serializes"),
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("response body is JSON")
    };
    (status, body)
}

pub(super) async fn patch_internal_blink_account(
    app: Router,
    blink_account_id: &str,
    payload: UpdateBlinkAccountRequest,
    token: Option<String>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("PATCH")
        .uri(format!("/internal/blink/accounts/{blink_account_id}"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(
            serde_json::to_vec(&payload).expect("request serializes"),
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("response body is JSON")
    };
    (status, body)
}

pub(super) async fn get_internal_identifier(
    app: Router,
    path: &str,
    token: String,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("response body is JSON")
    };
    (status, body)
}

pub(super) fn internal_test_token_with_scope(scope: &str) -> String {
    let private_key = include_bytes!("../../tests/fixtures/internal_auth_private.pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("blink-internal-test-key".to_string());
    encode(
        &header,
        &serde_json::json!({
            "sub": "blink-core-test-service",
            "iss": "https://issuer.internal.test",
            "aud": "lnurl-server.internal.test",
            "exp": 4_102_444_800_u64,
            "nbf": 1_700_000_000_u64,
            "scope": scope
        }),
        &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
    )
    .expect("test JWT must sign")
}

pub(super) fn blink_resolved_recipient() -> ResolvedRecipient {
    ResolvedRecipient {
        account_id: "acct_blink_lookup".to_string(),
        provider: AccountProvider::Blink,
        domain: "example.com".to_string(),
        identifier: "alice".to_string(),
        identifier_kind: AccountIdentifierKind::Username,
        description: "Alice Blink account".to_string(),
        spark_pubkey: None,
        blink_account_id: Some("blink_account_123".to_string()),
        btc_wallet_id: Some("btc_wallet_123".to_string()),
        usd_wallet_id: Some("usd_wallet_123".to_string()),
        default_wallet: Some(WalletKind::Usd),
    }
}

pub(super) fn spark_resolved_recipient() -> ResolvedRecipient {
    ResolvedRecipient {
        account_id: "acct_spark_lookup".to_string(),
        provider: AccountProvider::Spark,
        domain: "example.com".to_string(),
        identifier: "bob".to_string(),
        identifier_kind: AccountIdentifierKind::Username,
        description: "Bob Spark account".to_string(),
        spark_pubkey: Some("spark_pubkey_123".to_string()),
        blink_account_id: None,
        btc_wallet_id: None,
        usd_wallet_id: None,
        default_wallet: None,
    }
}

pub(super) fn post_transfer_spark_recipient() -> ResolvedRecipient {
    ResolvedRecipient {
        account_id: "acct_spark_after_transfer".to_string(),
        provider: AccountProvider::Spark,
        domain: "example.com".to_string(),
        identifier: "alice".to_string(),
        identifier_kind: AccountIdentifierKind::Username,
        description: "Alice moved to Spark".to_string(),
        spark_pubkey: Some("spark_after_transfer_pubkey".to_string()),
        blink_account_id: None,
        btc_wallet_id: None,
        usd_wallet_id: None,
        default_wallet: None,
    }
}

pub(super) fn valid_internal_transfer_to_spark_payload() -> InternalTransferToSparkRequest {
    InternalTransferToSparkRequest {
        domain: "Example.COM".to_string(),
        identifier: " Alice ".to_string(),
        destination_spark_pubkey:
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
        description: "Moved to Spark".to_string(),
    }
}

pub(super) fn metadata_entries(metadata: &str) -> Vec<(String, String)> {
    serde_json::from_str::<Vec<(String, String)>>(metadata)
        .expect("metadata must be a JSON array of string tuples")
}

pub(super) fn phone_blink_resolved_recipient() -> ResolvedRecipient {
    ResolvedRecipient {
        identifier: "+573005871212".to_string(),
        identifier_kind: AccountIdentifierKind::Phone,
        description: "Phone Blink account".to_string(),
        ..blink_resolved_recipient()
    }
}
