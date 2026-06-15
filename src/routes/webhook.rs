use axum::{
    Extension, Json,
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
use lightning_invoice::Bolt11Invoice;
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;
use tracing::{debug, error, trace, warn};

use crate::{
    invoice_paid::{HandleInvoicePaidError, handle_invoice_paid},
    providers::{PaymentStatusRequest, ProviderError},
    repository::{AccountProvider, LnurlRepository, LnurlRepositoryError},
    state::State,
    time::now_millis,
};

use super::LnurlServer;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlinkInvoiceWebhookPayload {
    pub payment_hash: String,
    pub payment_preimage: Option<String>,
    pub payment_request: Option<String>,
    pub status: BlinkInvoiceWebhookStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum BlinkInvoiceWebhookStatus {
    #[serde(rename = "PAID")]
    Paid,
    #[serde(rename = "EXPIRED")]
    Expired,
}

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    /// Webhook endpoint for SSP payment notifications.
    /// Verifies HMAC-SHA256 signature and processes payment preimages.
    pub async fn webhook(
        Extension(state): Extension<State<DB>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        process_webhook(
            &state.db,
            &state.webhook_service,
            &state.webhook_secret,
            &state.invoice_paid_trigger,
            &headers,
            &body,
        )
        .await
    }

    pub async fn blink_webhook(
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<BlinkInvoiceWebhookPayload>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        validate_blink_payment_request_hash(
            &payload.payment_hash,
            payload.payment_request.as_deref(),
        )?;

        match payload.status {
            BlinkInvoiceWebhookStatus::Paid => {
                settle_blink_invoice_by_payment_hash(
                    &state,
                    &payload.payment_hash,
                    payload.payment_preimage.as_deref(),
                )
                .await
                .map_err(|e| blink_webhook_settlement_error(&payload.payment_hash, &e))?;
            }
            BlinkInvoiceWebhookStatus::Expired => {
                expire_blink_invoice_by_payment_hash(&state, &payload.payment_hash)
                    .await
                    .map_err(|e| blink_webhook_settlement_error(&payload.payment_hash, &e))?;
            }
        }

        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub(super) async fn process_webhook<DB>(
    db: &DB,
    webhook_service: &crate::webhooks::WebhookService<DB>,
    webhook_secret: &str,
    invoice_paid_trigger: &tokio::sync::watch::Sender<()>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(), (StatusCode, Json<Value>)>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    // Verify HMAC-SHA256 signature
    let signature_header = headers
        .get("X-Spark-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            trace!("missing X-Spark-Signature header");
            (
                StatusCode::UNAUTHORIZED,
                Json(Value::String("missing signature".into())),
            )
        })?;

    let signature_bytes = hex::decode(signature_header).map_err(|_| {
        trace!("invalid signature hex encoding");
        (
            StatusCode::UNAUTHORIZED,
            Json(Value::String("invalid signature".into())),
        )
    })?;

    let mut engine = HmacEngine::<sha256::Hash>::new(webhook_secret.as_bytes());
    engine.input(body);
    let expected_hmac: Hmac<sha256::Hash> = Hmac::from_engine(engine);

    if expected_hmac.to_byte_array() != signature_bytes.as_slice() {
        trace!("invalid webhook signature");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(Value::String("invalid signature".into())),
        ));
    }

    // Parse the body
    let payload: SspWebhookPayload = serde_json::from_slice(body).map_err(|e| {
        trace!("invalid webhook payload: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid payload".into())),
        )
    })?;

    // Only process lightning receive finished events
    if payload.event_type != "SPARK_LIGHTNING_RECEIVE_FINISHED" {
        debug!("ignoring webhook event type: {}", payload.event_type);
        return Ok(());
    }

    let payment_preimage = payload.payment_preimage.ok_or_else(|| {
        trace!("missing payment_preimage in webhook payload");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("missing payment_preimage".into())),
        )
    })?;

    let receiver_pubkey = payload.receiver_identity_public_key.ok_or_else(|| {
        trace!("missing receiver_identity_public_key in webhook payload");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("missing receiver_identity_public_key".into())),
        )
    })?;

    // Compute payment hash from preimage
    let preimage_bytes = hex::decode(&payment_preimage).map_err(|e| {
        trace!("invalid preimage hex: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid preimage".into())),
        )
    })?;
    let payment_hash = sha256::Hash::hash(&preimage_bytes).to_string();

    // Look up invoice
    let invoice = db
        .get_invoice_by_payment_hash(&payment_hash)
        .await
        .map_err(|e| {
            error!("failed to get invoice: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        })?;

    let Some(invoice) = invoice else {
        debug!(
            "no invoice found for payment hash {} from webhook",
            payment_hash
        );
        return Ok(());
    };

    // Verify invoice belongs to the receiver
    if invoice.user_pubkey != receiver_pubkey {
        warn!(
            "webhook invoice user mismatch: expected={}, got={}",
            receiver_pubkey, invoice.user_pubkey
        );
        return Ok(());
    }

    let amount_received_sat = match &payload.htlc_amount {
        Some(amount) if amount.unit == "SATOSHI" => Some(amount.value),
        Some(amount) if amount.unit == "MILLISATOSHI" => {
            if amount.value % 1000 != 0 {
                warn!(
                    "truncating htlc_amount from {} msat to {} sat",
                    amount.value,
                    amount.value / 1000
                );
            }
            Some(amount.value / 1000)
        }
        Some(amount) => {
            warn!("unexpected htlc_amount unit: {}", amount.unit);
            None
        }
        None => None,
    };

    // Handle the invoice paid event
    if let Err(e) = handle_invoice_paid(
        db,
        webhook_service,
        &payment_hash,
        &payment_preimage,
        amount_received_sat,
        invoice_paid_trigger,
    )
    .await
    {
        error!(
            "failed to handle webhook invoice paid for {}: {}",
            payment_hash, e
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Value::String("internal server error".into())),
        ));
    }

    debug!(
        "webhook processed: invoice {} paid for pubkey {}",
        payment_hash, receiver_pubkey
    );
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(super) enum BlinkSettlementError {
    #[error(transparent)]
    Repository(#[from] LnurlRepositoryError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    InvoicePaid(#[from] HandleInvoicePaidError),
}

fn blink_webhook_settlement_error(
    payment_hash: &str,
    error: &BlinkSettlementError,
) -> (StatusCode, Json<Value>) {
    if matches!(
        error,
        BlinkSettlementError::InvoicePaid(
            HandleInvoicePaidError::InvalidInvoice(_) | HandleInvoicePaidError::InvalidPreimage(_)
        )
    ) {
        trace!(
            "invalid Blink webhook payload for {}: {}",
            payment_hash, error
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid payload".into())),
        );
    }

    error!(
        "failed to process Blink webhook for {}: {}",
        payment_hash, error
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Value::String("internal server error".into())),
    )
}

fn validate_blink_payment_request_hash(
    payment_hash: &str,
    payment_request: Option<&str>,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(payment_request) = payment_request else {
        return Ok(());
    };

    let invoice = Bolt11Invoice::from_str(payment_request).map_err(|e| {
        trace!("invalid Blink webhook paymentRequest: {e}");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid paymentRequest".into())),
        )
    })?;

    if invoice.payment_hash().to_string() != payment_hash {
        trace!("Blink webhook paymentRequest hash does not match paymentHash");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("paymentRequest hash mismatch".into())),
        ));
    }

    Ok(())
}

pub(super) async fn settle_blink_invoice_by_payment_hash<DB>(
    state: &State<DB>,
    payment_hash: &str,
    supplied_preimage: Option<&str>,
) -> Result<Option<String>, BlinkSettlementError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let Some(invoice) = state.db.get_invoice_by_payment_hash(payment_hash).await? else {
        return Ok(None);
    };
    if invoice.provider != Some(AccountProvider::Blink) {
        return Ok(None);
    }

    if let Some(preimage) = supplied_preimage {
        handle_invoice_paid(
            &state.db,
            &state.webhook_service,
            payment_hash,
            preimage,
            None,
            &state.invoice_paid_trigger,
        )
        .await?;
        return Ok(Some(preimage.to_string()));
    }

    let status = state
        .providers
        .provider_for(AccountProvider::Blink)
        .payment_status(PaymentStatusRequest { payment_hash })
        .await?;

    if !status.settled {
        return Ok(None);
    }

    let Some(preimage) = status.preimage else {
        return Ok(None);
    };

    handle_invoice_paid(
        &state.db,
        &state.webhook_service,
        payment_hash,
        &preimage,
        status.amount_received_sat,
        &state.invoice_paid_trigger,
    )
    .await?;

    Ok(Some(preimage))
}

async fn expire_blink_invoice_by_payment_hash<DB>(
    state: &State<DB>,
    payment_hash: &str,
) -> Result<(), BlinkSettlementError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let Some(invoice) = state.db.get_invoice_by_payment_hash(payment_hash).await? else {
        return Ok(());
    };
    if invoice.provider != Some(AccountProvider::Blink) {
        return Ok(());
    }

    let status = state
        .providers
        .provider_for(AccountProvider::Blink)
        .payment_status(PaymentStatusRequest { payment_hash })
        .await?;

    if status.expired {
        state
            .db
            .mark_invoice_expired(payment_hash, now_millis())
            .await?;
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct SspWebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
    payment_preimage: Option<String>,
    receiver_identity_public_key: Option<String>,
    htlc_amount: Option<SspAmount>,
}

#[derive(Debug, Deserialize)]
struct SspAmount {
    value: i64,
    unit: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_support::*;
    use serde_json::{Value, json};
    #[tokio::test]
    async fn blink_webhook_paid_supplied_preimage_uses_central_side_effects() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknativewebhook",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = blink_webhook_app_with_state(state);

        let (status, body) =
            post_blink_webhook(app, blink_webhook_payload("PAID", &payment_hash)).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blink_webhook_paid_without_preimage_noops_when_status_has_no_preimage() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1ignoredblinknativewebhook",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = blink_webhook_app_with_state(state);
        let mut payload = blink_webhook_payload("PAID", &payment_hash);
        payload.as_object_mut().unwrap().remove("paymentPreimage");

        let (status, body) = post_blink_webhook(app, payload).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.preimage.is_none());
        assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
        assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn blink_webhook_paid_without_preimage_uses_blink_status_fallback() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknativefallback",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = blink_webhook_app_with_state(state);
        let mut payload = blink_webhook_payload("PAID", &payment_hash);
        payload.as_object_mut().unwrap().remove("paymentPreimage");

        let (status, body) = post_blink_webhook(app, payload).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blink_webhook_paid_does_not_settle_non_blink_invoices() {
        for provider in [Some(AccountProvider::Spark), None] {
            let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
            let (endpoint, calls, _) =
                start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                    .await;
            let repo = MockRepository::default();
            repo.upsert_invoice(&route_test_invoice(
                provider,
                payment_hash.clone(),
                "lnbc1notblink",
                None,
            ))
            .await
            .unwrap();
            let state = internal_route_test_state_with_blink_endpoint(
                repo.clone(),
                Some(internal_auth_state()),
                &endpoint,
            )
            .await;
            let app = blink_webhook_app_with_state(state);

            let (status, body) =
                post_blink_webhook(app, blink_webhook_payload("PAID", &payment_hash)).await;

            assert!(status.is_success());
            assert_eq!(body, Value::Null);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let invoice = repo
                .get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .expect("invoice exists");
            assert!(invoice.preimage.is_none());
            assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
            assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn blink_webhook_paid_rejects_invalid_supplied_preimages_without_retry_status() {
        for invalid_preimage in ["not-hex", &"00".repeat(32)] {
            let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
            let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
            let repo = MockRepository::default();
            repo.upsert_invoice(&route_test_invoice(
                Some(AccountProvider::Blink),
                payment_hash.clone(),
                "lnbc1invalidpreimage",
                None,
            ))
            .await
            .unwrap();
            let state = internal_route_test_state_with_blink_endpoint(
                repo.clone(),
                Some(internal_auth_state()),
                &endpoint,
            )
            .await;
            let app = blink_webhook_app_with_state(state);
            let mut payload = blink_webhook_payload("PAID", &payment_hash);
            payload["paymentPreimage"] = json!(invalid_preimage);

            let (status, body) = post_blink_webhook(app, payload).await;

            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, json!("invalid payload"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let invoice = repo
                .get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .expect("invoice exists");
            assert!(invoice.preimage.is_none());
            assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
            assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn blink_webhook_is_unauthenticated() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, _calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkforbidden",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = blink_webhook_app_with_state(state);

        let (status, body) =
            post_blink_webhook(app, blink_webhook_payload("PAID", &payment_hash)).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn webhook_blink_route_is_public_and_old_internal_route_absent() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, _calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkroute",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = blink_webhook_app_with_state(state);

        let public_status = post_blink_webhook_path(
            app.clone(),
            "/webhook/blink",
            blink_webhook_payload("PAID", &payment_hash),
        )
        .await;
        let old_internal_status = post_blink_webhook_path(
            app,
            "/internal/blink/invoice-paid",
            blink_webhook_payload("PAID", &payment_hash),
        )
        .await;

        assert!(public_status.is_success());
        assert_eq!(old_internal_status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn blink_webhook_paid_rejects_payment_request_hash_mismatch() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (_other_hash, payment_request) = generate_route_test_invoice(77);
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkmismatch",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;
        let app = blink_webhook_app_with_state(state);
        let mut payload = blink_webhook_payload("PAID", &payment_hash);
        payload["paymentRequest"] = json!(payment_request);

        let (status, body) = post_blink_webhook(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!("paymentRequest hash mismatch"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.preimage.is_none());
    }

    #[tokio::test]
    async fn blink_webhook_expired_marks_blink_invoice_expired_without_preimage() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) = start_blink_status_mock_server("EXPIRED", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkexpired",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;
        let app = blink_webhook_app_with_state(state);
        let mut payload = blink_webhook_payload("EXPIRED", &payment_hash);
        payload.as_object_mut().unwrap().remove("paymentPreimage");

        let (status, body) = post_blink_webhook(app, payload).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.expired_at.is_some());
        assert!(invoice.preimage.is_none());
    }

    #[tokio::test]
    async fn blink_webhook_expired_non_expired_fallback_leaves_state_unset() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) = start_blink_status_mock_server("PENDING", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknotexpired",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;
        let app = blink_webhook_app_with_state(state);
        let mut payload = blink_webhook_payload("EXPIRED", &payment_hash);
        payload.as_object_mut().unwrap().remove("paymentPreimage");

        let (status, body) = post_blink_webhook(app, payload).await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.expired_at.is_none());
        assert!(invoice.preimage.is_none());
    }

    #[tokio::test]
    async fn verify_blink_expired_returns_unsettled_without_status_fallback() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        let mut invoice = route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1verifyexpiredblink",
            None,
        );
        invoice.expired_at = Some(now_millis());
        repo.upsert_invoice(&invoice).await.unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;

        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], false);
        assert_eq!(body["preimage"], Value::Null);
        assert_eq!(body["pr"], "lnbc1verifyexpiredblink");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.preimage.is_none());
        assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
        assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_valid_payment_marks_invoice_paid() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));

        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
    }

    #[tokio::test]
    async fn webhook_millisatoshi_htlc_amount_converts_to_sat() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let mut payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        payload["htlc_amount"] = serde_json::json!({"value": 50_000_000, "unit": "MILLISATOSHI"});
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert_eq!(invoice.amount_received_sat, Some(50_000));
    }

    #[tokio::test]
    async fn webhook_missing_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());
        let headers = HeaderMap::new();
        let body = Bytes::from(b"{}".to_vec());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_invalid_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", "deadbeef".repeat(8).parse().unwrap());
        let body = Bytes::from(body_bytes);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_non_hex_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let body = Bytes::from(b"{}".to_vec());
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", "not-valid-hex!".parse().unwrap());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_invalid_json_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let body_bytes = b"not json";
        let sig = compute_hmac(TEST_WEBHOOK_SECRET, body_bytes);
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", sig.parse().unwrap());
        let body = Bytes::from(body_bytes.to_vec());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_non_receive_event_type_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload("SOME_OTHER_EVENT", None, None);
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_missing_preimage_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            None,
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_missing_receiver_pubkey_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            None,
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_invalid_preimage_hex_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some("not-valid-hex"),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_no_matching_invoice_succeeds_silently() {
        let repo = MockRepository::default(); // no invoices
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_pubkey_mismatch_succeeds_silently() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, "02different_pubkey");
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY), // doesn't match invoice's pubkey
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // Invoice should NOT have been updated
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert!(invoice.preimage.is_none());
    }

    #[tokio::test]
    async fn webhook_already_paid_invoice_is_idempotent() {
        let repo = MockRepository::default();
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        repo.invoices.lock().unwrap().insert(
            payment_hash.clone(),
            Invoice {
                account_id: None,
                provider: None,
                wallet_kind: None,
                wallet_id: None,
                provider_payment_hash: None,
                payment_hash: payment_hash.clone(),
                user_pubkey: TEST_RECEIVER_PUBKEY.to_string(),
                invoice: "lnbc1...".to_string(),
                preimage: Some(TEST_PREIMAGE_HEX.to_string()),
                expired_at: None,
                invoice_expiry: i64::MAX,
                created_at: 0,
                updated_at: 0,
                domain: None,
                amount_received_sat: None,
            },
        );
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // No pending zap receipt should be created for an already-paid invoice
        assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_triggers_invoice_paid_notification() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // The watch channel should have been notified
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn webhook_signature_uses_correct_secret() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        // Sign with a different secret than the server expects
        let (headers, body) = signed_headers_and_body("wrong_secret", &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_lightning_send_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "PREIMAGE_PROVIDED",
            "type": "SPARK_LIGHTNING_SEND_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "encoded_invoice": "lnbc50u1p...",
            "fee": {"value": 100, "unit": "SATOSHI"},
            "idempotency_key": "user-defined-key-123",
            "invoice_amount": {"value": 50_000, "unit": "SATOSHI"}
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_coop_exit_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "SUCCEEDED",
            "type": "SPARK_COOP_EXIT_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "fee": {"value": 500, "unit": "SATOSHI"},
            "withdrawal_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "l1_broadcast_fee": {"value": 200, "unit": "SATOSHI"},
            "exit_speed": "NORMAL",
            "coop_exit_txid": "a1b2c3d4...",
            "expires_at": "2025-03-10T12:00:00Z",
            "total_amount": {"value": 49_300, "unit": "SATOSHI"}
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_static_deposit_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "TRANSFER_COMPLETED",
            "type": "SPARK_STATIC_DEPOSIT_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "deposit_amount": {"value": 100_000, "unit": "SATOSHI"},
            "credit_amount": {"value": 99_500, "unit": "SATOSHI"},
            "max_fee": {"value": 1000, "unit": "SATOSHI"},
            "transaction_id": "d4e5f6a7b8c9...",
            "output_index": 0,
            "bitcoin_network": "MAINNET",
            "static_deposit_address": "bc1q..."
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }
}
