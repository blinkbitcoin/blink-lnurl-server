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
pub(crate) enum BlinkSettlementError {
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

pub(crate) async fn settle_blink_invoice_by_payment_hash<DB>(
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
