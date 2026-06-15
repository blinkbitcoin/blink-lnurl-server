mod account;
mod lnurl_pay;
mod zap;
pub use lnurl_pay::{LnurlPayCallbackParams, PayResponse, Tag};

use crate::identifier::{IdentifierKind, WalletModifier, parse_public_identifier};
use crate::models::{
    CheckUsernameAvailableResponse, CreateBlinkAccountRequest, CreateBlinkAccountResponse,
    INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS, INTERNAL_ERROR_IDENTIFIER_CONFLICT,
    INTERNAL_ERROR_INTERNAL_SERVER_ERROR, INTERNAL_ERROR_INVALID_DOMAIN,
    INTERNAL_ERROR_INVALID_IDENTIFIER, INTERNAL_ERROR_INVALID_REQUEST, INTERNAL_ERROR_NOT_FOUND,
    INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED, InternalAccountIdentifierResponse,
    InternalErrorResponse, InternalIdentifierLookupResponse, InternalProviderDetailsResponse,
    InternalTransferToSparkRequest, InternalTransferToSparkResponse, InvoicePaidRequest,
    InvoicesPaidRequest,
};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::Host;
use bitcoin::{
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256},
    secp256k1::XOnlyPublicKey,
};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use nostr::{Event, JsonUtil};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;
use std::{collections::HashSet, marker::PhantomData};
use tracing::{debug, error, trace, warn};

use crate::{
    invoice_paid::{
        HandleInvoicePaidError, create_provider_invoice_for_account, handle_invoice_paid,
        handle_invoices_paid,
    },
    repository::LnurlSenderComment,
    time::now_millis,
    zap::Zap,
};
use crate::{
    providers::{CreateInvoiceRequest, PaymentStatusRequest, ProviderError},
    repository::{
        AccountIdentifierKind, AccountProvider, BlinkToSparkIdentifierTransfer, LnurlRepository,
        LnurlRepositoryError, NewAccountIdentifier, NewBlinkAccount, ResolvedRecipient, WalletKind,
        generate_account_id,
    },
    state::State,
};

const ACCEPTABLE_TIME_DIFF_SECS: u64 = 600;
const DEFAULT_METADATA_OFFSET: u32 = 0;
const DEFAULT_METADATA_LIMIT: u32 = 100;
/// Maximum number of nostr relays to connect to when publishing zap receipts.
const MAX_NOSTR_RELAYS: usize = 10;
/// Maximum size (bytes) of a nostr event JSON (zap request or zap receipt).
const MAX_NOSTR_EVENT_SIZE: usize = 32_768;
/// Maximum length of a sender comment (LUD-12).
const MAX_COMMENT_LENGTH: usize = 255;
const BLINK_BTC_EXPIRY_LIMIT_SECS: u32 = 86_400;
const BLINK_USD_EXPIRY_LIMIT_SECS: u32 = 300;

#[cfg(test)]
const fn public_lnurl_error_reasons() -> [&'static str; 6] {
    [
        "unsupported wallet",
        "expiry too long",
        "missing amount",
        "amount out of range",
        "comment too long",
        "invoice creation failed",
    ]
}

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

pub struct LnurlServer<DB> {
    db: PhantomData<DB>,
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

    pub async fn transfer_identifier_to_spark(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Extension(state): Extension<State<DB>>,
        body: Bytes,
    ) -> Result<Json<InternalTransferToSparkResponse>, (StatusCode, Json<InternalErrorResponse>)>
    {
        crate::internal_auth::require_scope(
            &principal,
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )?;

        let payload: InternalTransferToSparkRequest =
            serde_json::from_slice(&body).map_err(|e| {
                trace!("invalid internal transfer request JSON: {e}");
                internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST)
            })?;

        let domain = validate_internal_domain(&payload.domain)?;
        let parsed = parse_public_identifier(&payload.identifier).map_err(|e| {
            trace!(
                "invalid internal transfer identifier '{}': {e:?}",
                payload.identifier
            );
            internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
        })?;
        if parsed.wallet.is_some() {
            return Err(internal_bad_request(
                INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED,
            ));
        }
        let identifier = parsed.canonical;
        let destination_spark_pubkey =
            validate_internal_required_string(&payload.destination_spark_pubkey)?;
        let destination_spark_pubkey = account::parse_pubkey(&destination_spark_pubkey)
            .map_err(|_| internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))?
            .to_string();
        let description = validate_internal_description(&payload.description)?;

        let source_recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &identifier)
            .await
            .map_err(|e| internal_transfer_to_spark_error(e, &domain, &identifier))?;
        let Some(source_recipient) = source_recipient else {
            return Err(internal_transfer_to_spark_error(
                LnurlRepositoryError::SourceNotOwner,
                &domain,
                &identifier,
            ));
        };
        if source_recipient.provider != AccountProvider::Blink {
            return Err(internal_transfer_to_spark_error(
                LnurlRepositoryError::InvalidOwnership,
                &domain,
                &identifier,
            ));
        }

        state
            .db
            .transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
                domain: domain.clone(),
                identifier: identifier.clone(),
                source_account_id: source_recipient.account_id,
                destination_spark_pubkey: destination_spark_pubkey.clone(),
                description,
            })
            .await
            .map_err(|e| internal_transfer_to_spark_error(e, &domain, &identifier))?;

        Ok(Json(InternalTransferToSparkResponse {
            domain: domain.clone(),
            identifier: identifier.clone(),
            provider: AccountProvider::Spark.as_str().to_string(),
            spark_pubkey: destination_spark_pubkey,
            lightning_address: format!("{identifier}@{domain}"),
            lnurl: format!("lnurlp://{domain}/lnurlp/{identifier}"),
        }))
    }

    pub async fn create_internal_blink_account(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<CreateBlinkAccountRequest>,
    ) -> Result<Json<CreateBlinkAccountResponse>, (StatusCode, Json<InternalErrorResponse>)> {
        crate::internal_auth::require_scope(
            &principal,
            crate::internal_auth::SCOPE_BLINK_ACCOUNTS_CREATE,
        )?;

        let domain = validate_internal_domain(&payload.domain)?;
        let blink_account_id = validate_internal_required_string(&payload.blink_account_id)?;
        let btc_wallet_id = validate_internal_required_string(&payload.btc_wallet_id)?;
        let usd_wallet_id = validate_internal_required_string(&payload.usd_wallet_id)?;
        let description = validate_internal_description(&payload.description)?;
        if payload.identifiers.is_empty() {
            return Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST));
        }

        let default_wallet = parse_internal_default_wallet(&payload.default_wallet)?;
        let mut identifiers = Vec::with_capacity(payload.identifiers.len());
        let mut response_identifiers = Vec::with_capacity(payload.identifiers.len());
        let mut seen_identifiers = HashSet::with_capacity(payload.identifiers.len());
        for raw_identifier in &payload.identifiers {
            let parsed = parse_public_identifier(raw_identifier).map_err(|e| {
                trace!("invalid internal account identifier '{raw_identifier}': {e:?}");
                internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
            })?;
            if parsed.wallet.is_some() {
                return Err(internal_bad_request(
                    INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED,
                ));
            }
            if !seen_identifiers.insert((domain.clone(), parsed.canonical.clone())) {
                return Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST));
            }
            let identifier_kind = match parsed.kind {
                IdentifierKind::Username => AccountIdentifierKind::Username,
                IdentifierKind::Phone => AccountIdentifierKind::Phone,
            };
            let kind = identifier_kind.as_str().to_string();
            identifiers.push(NewAccountIdentifier {
                domain: domain.clone(),
                identifier: parsed.canonical.clone(),
                identifier_kind,
                description: description.clone(),
            });
            response_identifiers.push(InternalAccountIdentifierResponse {
                identifier: parsed.canonical,
                kind,
                description: description.clone(),
            });
        }

        let account_id = generate_account_id(AccountProvider::Blink);
        let account = NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: blink_account_id.clone(),
            btc_wallet_id: btc_wallet_id.clone(),
            usd_wallet_id: usd_wallet_id.clone(),
            default_wallet,
            identifiers,
        };

        state
            .db
            .create_blink_account(&account)
            .await
            .map_err(internal_account_creation_error)?;

        Ok(Json(CreateBlinkAccountResponse {
            account_id,
            provider: AccountProvider::Blink.as_str().to_string(),
            blink_account_id,
            btc_wallet_id,
            usd_wallet_id,
            default_wallet: default_wallet.as_str().to_string(),
            domain,
            identifiers: response_identifiers,
        }))
    }

    pub async fn get_internal_identifier(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Path((domain, identifier)): Path<(String, String)>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<InternalIdentifierLookupResponse>, (StatusCode, Json<InternalErrorResponse>)>
    {
        crate::internal_auth::require_scope(&principal, crate::internal_auth::SCOPE_ACCOUNTS_READ)?;

        let domain = validate_internal_lookup_domain(&domain)?;
        let parsed = parse_public_identifier(&identifier).map_err(|e| {
            trace!("invalid internal lookup identifier '{identifier}': {e:?}");
            internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
        })?;

        let recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &parsed.canonical)
            .await
            .map_err(|e| internal_lookup_storage_error(&e))?;
        let Some(recipient) = recipient else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(InternalErrorResponse::new(INTERNAL_ERROR_NOT_FOUND)),
            ));
        };

        Ok(Json(internal_identifier_lookup_response(
            recipient,
            parsed.wallet,
        )))
    }
}

fn internal_identifier_lookup_response(
    recipient: ResolvedRecipient,
    requested_wallet: Option<WalletModifier>,
) -> InternalIdentifierLookupResponse {
    InternalIdentifierLookupResponse {
        provider: recipient.provider.as_str().to_string(),
        account_id: recipient.account_id,
        domain: recipient.domain,
        identifier: recipient.identifier,
        identifier_kind: recipient.identifier_kind.as_str().to_string(),
        description: recipient.description,
        requested_wallet: requested_wallet
            .map(|wallet| wallet_modifier_response_value(wallet).to_string()),
        provider_details: InternalProviderDetailsResponse {
            spark_pubkey: recipient.spark_pubkey,
            blink_account_id: recipient.blink_account_id,
            btc_wallet_id: recipient.btc_wallet_id,
            usd_wallet_id: recipient.usd_wallet_id,
            default_wallet: recipient
                .default_wallet
                .map(|wallet| wallet.as_str().to_string()),
        },
    }
}

const fn wallet_modifier_response_value(modifier: WalletModifier) -> &'static str {
    match modifier {
        WalletModifier::Btc => "btc",
        WalletModifier::Usd => "usd",
    }
}

fn validate_internal_domain(
    domain: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
    } else {
        Ok(domain)
    }
}

fn validate_internal_lookup_domain(
    domain: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_DOMAIN))
    } else {
        Ok(domain)
    }
}

fn validate_internal_required_string(
    value: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let value = value.trim();
    if value.is_empty() {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
    } else {
        Ok(value.to_string())
    }
}

fn validate_internal_description(
    description: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let description = validate_internal_required_string(description)?;
    lnurl_pay::validate_description(&description)
        .map(|()| description)
        .map_err(|(_status, _body)| internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
}

fn parse_internal_default_wallet(
    wallet: &str,
) -> Result<WalletKind, (StatusCode, Json<InternalErrorResponse>)> {
    match wallet.trim().to_lowercase().as_str() {
        "btc" => Ok(WalletKind::Btc),
        "usd" => Ok(WalletKind::Usd),
        _ => Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST)),
    }
}

fn internal_account_creation_error(
    error: LnurlRepositoryError,
) -> (StatusCode, Json<InternalErrorResponse>) {
    match error {
        LnurlRepositoryError::BlinkAccountExists => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS,
            )),
        ),
        LnurlRepositoryError::IdentifierConflict | LnurlRepositoryError::NameTaken => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_IDENTIFIER_CONFLICT,
            )),
        ),
        error => {
            error!("failed to create internal Blink account: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InternalErrorResponse::new(
                    INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
                )),
            )
        }
    }
}

fn internal_transfer_to_spark_error(
    error: LnurlRepositoryError,
    domain: &str,
    identifier: &str,
) -> (StatusCode, Json<InternalErrorResponse>) {
    match error {
        LnurlRepositoryError::SourceNotOwner | LnurlRepositoryError::AccountNotFound => (
            StatusCode::NOT_FOUND,
            Json(InternalErrorResponse::new(INTERNAL_ERROR_NOT_FOUND)),
        ),
        LnurlRepositoryError::InvalidOwnership | LnurlRepositoryError::InvalidProvider => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(INTERNAL_ERROR_INVALID_REQUEST)),
        ),
        LnurlRepositoryError::IdentifierConflict | LnurlRepositoryError::NameTaken => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_IDENTIFIER_CONFLICT,
            )),
        ),
        error => {
            error!(
                "failed to transfer internal identifier {identifier}@{domain} to Spark: {error}"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InternalErrorResponse::new(
                    INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
                )),
            )
        }
    }
}

fn internal_lookup_storage_error(
    error: &LnurlRepositoryError,
) -> (StatusCode, Json<InternalErrorResponse>) {
    error!("failed to resolve internal identifier lookup: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(InternalErrorResponse::new(
            INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
        )),
    )
}

fn internal_bad_request(message: &'static str) -> (StatusCode, Json<InternalErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(InternalErrorResponse::new(message)),
    )
}

#[allow(clippy::too_many_lines)]
async fn process_webhook<DB>(
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

#[cfg(test)]
fn validate_username(username: &str) -> Result<(), (StatusCode, Json<Value>)> {
    account::validate_username(username)
}

#[cfg(test)]
fn public_lookup_username(
    identifier: &str,
) -> Result<Option<String>, crate::identifier::IdentifierError> {
    account::public_lookup_username(identifier)
}

#[cfg(test)]
fn parse_public_identifier_for_public_route(
    identifier: &str,
) -> Result<Option<lnurl_pay::PublicIdentifierIntent>, crate::identifier::IdentifierError> {
    account::parse_public_identifier_for_public_route(identifier)
}

#[cfg(test)]
async fn resolve_public_recipient<DB>(
    state: &State<DB>,
    domain: &str,
    intent: lnurl_pay::PublicIdentifierIntent,
) -> Result<Option<lnurl_pay::PublicRecipient>, (StatusCode, Json<Value>)>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    account::resolve_public_recipient(state, domain, intent).await
}

#[cfg(test)]
fn spark_transfer_error(error: LnurlRepositoryError, username: &str) -> (StatusCode, Json<Value>) {
    account::spark_transfer_error(error, username)
}

#[cfg(test)]
fn spark_registration_error(
    error: LnurlRepositoryError,
    username: &str,
) -> (StatusCode, Json<Value>) {
    account::spark_registration_error(error, username)
}

#[cfg(test)]
fn spark_user_from_recipient(
    recipient: ResolvedRecipient,
) -> Result<crate::user::User, LnurlRepositoryError> {
    account::spark_user_from_recipient(recipient)
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
    use crate::identifier::IdentifierError;
    use crate::models::ListMetadataMetadata;
    use crate::models::sanitize_username;
    use crate::repository::{
        IdentifierTransfer, Invoice, LnurlRepositoryError, LnurlSenderComment, PendingZapReceipt,
    };
    use crate::routes::lnurl_pay::lnurl_error;
    use crate::user::User;
    use crate::webhooks::NewWebhookDelivery;
    use crate::webhooks::repository::WebhookRepositoryError;
    use crate::zap::Zap;
    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::middleware;
    use axum::routing::{get, post};
    use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
    use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use tower::util::ServiceExt;

    // -- Mock repository -------------------------------------------------------

    #[derive(Clone, Default)]
    struct MockRepository {
        invoices: std::sync::Arc<Mutex<HashMap<String, Invoice>>>,
        pending_zap_receipts: std::sync::Arc<Mutex<HashMap<String, PendingZapReceipt>>>,
        webhook_deliveries: std::sync::Arc<Mutex<Vec<NewWebhookDelivery>>>,
        created_blink_accounts: std::sync::Arc<Mutex<Vec<NewBlinkAccount>>>,
        create_blink_account_error: std::sync::Arc<Mutex<Option<MockCreateBlinkAccountError>>>,
        resolved_recipient: std::sync::Arc<Mutex<Option<ResolvedRecipient>>>,
        resolve_calls: std::sync::Arc<Mutex<Vec<(String, String)>>>,
        blink_to_spark_transfers: std::sync::Arc<Mutex<Vec<BlinkToSparkIdentifierTransfer>>>,
    }

    #[derive(Clone, Copy)]
    enum MockCreateBlinkAccountError {
        BlinkAccountExists,
        IdentifierConflict,
        NameTaken,
    }

    impl MockRepository {
        fn fail_next_blink_account_creation(&self, error: MockCreateBlinkAccountError) {
            *self.create_blink_account_error.lock().unwrap() = Some(error);
        }

        fn created_blink_account_count(&self) -> usize {
            self.created_blink_accounts.lock().unwrap().len()
        }

        fn with_resolved_recipient(self, recipient: ResolvedRecipient) -> Self {
            *self.resolved_recipient.lock().unwrap() = Some(recipient);
            self
        }

        fn resolve_calls(&self) -> Vec<(String, String)> {
            self.resolve_calls.lock().unwrap().clone()
        }

        fn blink_to_spark_transfer_count(&self) -> usize {
            self.blink_to_spark_transfers.lock().unwrap().len()
        }

        fn blink_to_spark_transfers(&self) -> Vec<BlinkToSparkIdentifierTransfer> {
            self.blink_to_spark_transfers.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LnurlRepository for MockRepository {
        async fn delete_user(&self, _: &str, _: &str) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn get_user_by_name(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<User>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn get_user_by_pubkey(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<User>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn upsert_user(&self, _: &User) -> Result<(), LnurlRepositoryError> {
            Ok(())
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
        async fn transfer_username(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn upsert_zap(&self, _: &Zap) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn get_zap_by_payment_hash(
            &self,
            _: &str,
        ) -> Result<Option<Zap>, LnurlRepositoryError> {
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
        ) -> Result<Vec<crate::webhooks::repository::WebhookDelivery>, WebhookRepositoryError>
        {
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
        async fn unclaim_webhook_deliveries(
            &self,
            _: &[i64],
        ) -> Result<(), WebhookRepositoryError> {
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
        ) -> Result<Vec<crate::webhooks::repository::WebhookConfig>, WebhookRepositoryError>
        {
            Ok(vec![])
        }
    }

    // -- Test helpers ----------------------------------------------------------

    const TEST_WEBHOOK_SECRET: &str = "test_webhook_secret_0123456789abcdef";
    const TEST_PREIMAGE_HEX: &str =
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const TEST_RECEIVER_PUBKEY: &str = "02abc123";

    fn compute_payment_hash(preimage_hex: &str) -> String {
        let preimage_bytes = hex::decode(preimage_hex).unwrap();
        sha256::Hash::hash(&preimage_bytes).to_string()
    }

    fn compute_hmac(secret: &str, body: &[u8]) -> String {
        let mut engine = HmacEngine::<sha256::Hash>::new(secret.as_bytes());
        engine.input(body);
        let hmac: Hmac<sha256::Hash> = Hmac::from_engine(engine);
        hex::encode(hmac.to_byte_array())
    }

    fn make_webhook_payload(
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

    fn signed_headers_and_body(secret: &str, payload: &serde_json::Value) -> (HeaderMap, Bytes) {
        let body = serde_json::to_vec(payload).unwrap();
        let sig = compute_hmac(secret, &body);
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", sig.parse().unwrap());
        (headers, Bytes::from(body))
    }

    async fn internal_route_test_state(
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

    async fn internal_route_test_state_with_blink_endpoint(
        repo: MockRepository,
        internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
        blink_endpoint: &str,
    ) -> State<MockRepository> {
        let network = spark_client::Network::Regtest;
        let auth_seed = [7_u8; 32];
        let spark_client =
            spark_client::Client::new(spark_client::ClientConfig::new(network, auth_seed))
                .await
                .unwrap();
        let providers = Arc::new(crate::providers::ProviderRegistry::new(
            spark_client.clone(),
            blink_client::Client::new(blink_client::ClientConfig::new(blink_endpoint)),
        ));
        let (invoice_paid_trigger, _rx) = watch::channel(());
        State {
            db: repo.clone(),
            webhook_service: crate::webhooks::WebhookService::new(repo),
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

    fn setup_repo_with_invoice(preimage_hex: &str, receiver_pubkey: &str) -> MockRepository {
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

    fn generate_route_test_invoice(preimage_byte: u8) -> (String, String) {
        generate_route_test_invoice_with_description_hash(
            preimage_byte,
            sha256::Hash::hash("route test invoice".as_bytes()),
        )
    }

    fn generate_route_test_invoice_with_description_hash(
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

    async fn start_blink_invoice_mock_server(
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

    async fn start_blink_status_mock_server(
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

    fn route_test_invoice(
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

    async fn call_verify(state: State<MockRepository>, payment_hash: &str) -> Value {
        let response =
            LnurlServer::<MockRepository>::verify(Path(payment_hash.to_string()), Extension(state))
                .await
                .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        serde_json::from_slice(&body.expect("verify response body reads"))
            .expect("verify response body is JSON")
    }

    async fn get_public_invoice(
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

    fn assert_lnurl_error(result: Result<Json<Value>, (StatusCode, Json<Value>)>, reason: &str) {
        let Err((status, Json(body))) = result else {
            panic!("expected LNURL error {reason}");
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], reason);
    }

    fn internal_test_token() -> String {
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
                "scope": "blink:accounts:create accounts:read"
            }),
            &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
        )
        .expect("test JWT must sign")
    }

    fn internal_auth_state() -> Arc<crate::internal_auth::InternalAuthState> {
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

    async fn internal_account_app(repo: MockRepository) -> Router {
        let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
        internal_account_app_with_state(state)
    }

    fn internal_account_app_with_state(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/internal/blink/accounts",
                post(LnurlServer::<MockRepository>::create_internal_blink_account),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state))
    }

    async fn internal_lookup_app(repo: MockRepository) -> Router {
        let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
        internal_lookup_app_with_state(state)
    }

    fn internal_lookup_app_with_state(state: State<MockRepository>) -> Router {
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

    fn blink_webhook_app_with_state(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/webhook/blink",
                post(LnurlServer::<MockRepository>::blink_webhook),
            )
            .layer(Extension(state))
    }

    fn internal_transfer_to_spark_app_with_state(state: State<MockRepository>) -> Router {
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

    async fn internal_transfer_to_spark_app(repo: MockRepository) -> Router {
        let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
        internal_transfer_to_spark_app_with_state(state)
    }

    async fn post_internal_transfer_to_spark(
        app: Router,
        payload: InternalTransferToSparkRequest,
        scope: &str,
    ) -> (StatusCode, Value) {
        let body = serde_json::to_vec(&payload).expect("request serializes");
        post_internal_transfer_to_spark_raw(app, body, scope).await
    }

    async fn post_internal_transfer_to_spark_raw(
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

    async fn post_blink_webhook(app: Router, payload: Value) -> (StatusCode, Value) {
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

    fn blink_webhook_payload(status: &str, payment_hash: &str) -> Value {
        json!({
            "paymentHash": payment_hash,
            "paymentPreimage": TEST_PREIMAGE_HEX,
            "status": status
        })
    }

    async fn post_blink_webhook_path(app: Router, uri: &str, payload: Value) -> StatusCode {
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

    fn valid_create_blink_account_payload() -> CreateBlinkAccountRequest {
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

    async fn post_internal_blink_account(
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

    async fn get_internal_identifier(
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

    fn internal_test_token_with_scope(scope: &str) -> String {
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

    fn blink_resolved_recipient() -> ResolvedRecipient {
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

    fn spark_resolved_recipient() -> ResolvedRecipient {
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

    fn post_transfer_spark_recipient() -> ResolvedRecipient {
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

    fn valid_internal_transfer_to_spark_payload() -> InternalTransferToSparkRequest {
        InternalTransferToSparkRequest {
            domain: "Example.COM".to_string(),
            identifier: " Alice ".to_string(),
            destination_spark_pubkey:
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            description: "Moved to Spark".to_string(),
        }
    }

    // -- Tests -----------------------------------------------------------------

    fn assert_bad_username(result: Result<(), (StatusCode, Json<Value>)>) {
        let Err((status, Json(body))) = result else {
            panic!("expected invalid username error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, Value::String("invalid username".to_string()));
    }

    #[test]
    fn create_update_username_validation_uses_blink_rules_after_trim() {
        assert!(validate_username(&sanitize_username(" Alice_123 ")).is_ok());

        for invalid in ["", "   ", " alice+foo ", " 12345 ", " bc1alice "] {
            assert_bad_username(validate_username(&sanitize_username(invalid)));
        }
    }

    #[test]
    fn public_lookup_identifier_keeps_legacy_names_but_blocks_phone_like_fallback() {
        assert_eq!(
            public_lookup_username("legacy.name"),
            Ok(Some("legacy.name".to_string()))
        );

        for phone_like in ["12345", "3005871212"] {
            assert_eq!(public_lookup_username(phone_like), Ok(None));
        }
        for phone_like in ["573005871212", "+573005871212", "00573005871212"] {
            assert_eq!(
                public_lookup_username(phone_like),
                Ok(Some("+573005871212".to_string()))
            );
        }
    }

    #[test]
    fn public_lookup_identifier_strips_recognized_modifiers_and_rejects_others() {
        assert_eq!(
            public_lookup_username("alice+BTC"),
            Ok(Some("alice".to_string()))
        );

        for invalid in ["alice+eur", "alice+btc+usd"] {
            assert_eq!(
                public_lookup_username(invalid),
                Err(crate::identifier::IdentifierError::InvalidModifier)
            );
        }
    }

    #[test]
    fn public_identifier_rejects_invalid_wallet_modifier_test_01() {
        let btc = parse_public_identifier_for_public_route("Alice+BTC")
            .expect("BTC modifier should parse")
            .expect("username should produce public intent");
        assert_eq!(btc.canonical, "alice");
        assert_eq!(btc.wallet, Some(WalletKind::Btc));
        assert_eq!(btc.callback_identifier, "alice+btc");

        let usd = parse_public_identifier_for_public_route("alice+Usd")
            .expect("USD modifier should parse")
            .expect("username should produce public intent");
        assert_eq!(usd.canonical, "alice");
        assert_eq!(usd.wallet, Some(WalletKind::Usd));
        assert_eq!(usd.callback_identifier, "alice+usd");

        for invalid in ["alice+eur", "alice+btc+usd", "alice+usd+btc"] {
            assert!(
                matches!(
                    parse_public_identifier_for_public_route(invalid),
                    Err(IdentifierError::InvalidModifier)
                ),
                "invalid wallet modifier must fail before route lookup: {invalid}"
            );
        }
    }

    // -- Spark management account-backed compatibility ------------------------

    fn handler_source(name: &str) -> &'static str {
        const SOURCES: [&str; 4] = [
            include_str!("mod.rs"),
            include_str!("account.rs"),
            include_str!("lnurl_pay.rs"),
            include_str!("zap.rs"),
        ];

        let marker = format!("    pub async fn {name}(");
        for source in SOURCES {
            if let Some(start) = source.find(&marker) {
                let rest = &source[start..];
                let next = rest.find("\n    pub async fn ").unwrap_or(rest.len());
                return &rest[..next];
            }
        }

        panic!("handler must exist");
    }

    #[test]
    fn spark_management_routes_use_provider_neutral_repository_calls() {
        let register = handler_source("register");
        assert!(
            register.contains("upsert_spark_registration"),
            "register must write through the account-backed Spark registration API"
        );
        assert!(
            !register.contains("upsert_user"),
            "register must not write exclusively through the legacy user API"
        );

        let available = handler_source("available");
        assert!(
            available.contains("resolve_recipient_by_identifier"),
            "availability must resolve account-backed identifiers"
        );
        assert!(
            !available.contains("get_user_by_name"),
            "availability must not rely exclusively on legacy user lookup"
        );

        let recover = handler_source("recover");
        assert!(
            recover.contains("get_account_by_spark_pubkey"),
            "recover must prove Spark account ownership through provider-neutral lookup"
        );

        let unregister = handler_source("unregister");
        assert!(
            unregister.contains("delete_spark_registration"),
            "unregister must delete only the active Spark registration"
        );
        assert!(
            unregister.contains("&username"),
            "unregister must pass the signed canonical username into repository deletion"
        );
        assert!(
            unregister.contains("spark_unregister_error"),
            "unregister must map not-owned targeted deletion to the public not-found convention"
        );
        assert!(
            !unregister.contains("delete_user"),
            "unregister must not delete the legacy user row directly from the route"
        );
    }

    #[test]
    fn transfer_route_uses_provider_neutral_identifier_transfer() {
        let transfer = handler_source("transfer");
        assert!(
            transfer.contains("IdentifierTransfer"),
            "transfer must build the provider-neutral IdentifierTransfer DTO"
        );
        assert!(
            transfer.contains("transfer_identifier"),
            "transfer must move ownership through the provider-neutral repository API"
        );
        assert!(
            transfer.contains("destination_spark_pubkey"),
            "transfer must pass the verified destination Spark pubkey to the repository"
        );
        assert!(
            !transfer.contains("get_account_by_spark_pubkey(&to_pubkey)"),
            "transfer must not require a pre-existing destination Spark account"
        );
        assert!(
            !transfer.contains("transfer_username"),
            "transfer must not rely exclusively on legacy username transfer"
        );
        assert!(
            transfer.contains("verify_transfer_signature"),
            "transfer must preserve both Spark signature checks"
        );
    }

    #[test]
    fn spark_transfer_route_contract_still_uses_provider_neutral_transfer() {
        let transfer = handler_source("transfer");
        assert!(
            transfer.matches("verify_transfer_signature").count() >= 2,
            "public Spark transfer must keep both Spark signature verifications"
        );
        assert!(
            transfer.contains("from_pk == to_pk"),
            "public Spark transfer must keep same source/target pubkey rejection"
        );
        assert!(
            transfer.contains("IdentifierTransfer"),
            "public Spark transfer must still construct IdentifierTransfer"
        );
        assert!(
            transfer.contains("transfer_identifier"),
            "public Spark transfer must still call transfer_identifier"
        );
        assert!(
            transfer.contains("TransferLnurlPayResponse"),
            "public Spark transfer response type must stay unchanged"
        );
        assert!(
            !transfer.contains("SCOPE_TRANSFER_WRITE") && !transfer.contains("require_scope"),
            "public Spark transfer route must not require internal JWT scopes"
        );

        let internal_transfer = handler_source("transfer_identifier_to_spark");
        assert!(
            internal_transfer.contains("SCOPE_TRANSFER_WRITE"),
            "only the internal Blink-to-Spark transfer route should require transfer:write"
        );
        assert!(
            internal_transfer.contains("AccountProvider::Blink"),
            "internal transfer must reject non-Blink current owners"
        );
    }

    #[test]
    fn transfer_provider_neutral_conflicts_keep_legacy_contract() {
        for error in [
            LnurlRepositoryError::NameTaken,
            LnurlRepositoryError::IdentifierConflict,
        ] {
            let (status, Json(body)) = spark_transfer_error(error, "alice");
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body, Value::String("name already taken".to_string()));
        }

        let (status, Json(body)) =
            spark_transfer_error(LnurlRepositoryError::SourceNotOwner, "alice");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body,
            Value::String("source pubkey does not own this username".to_string())
        );
    }

    #[test]
    fn metadata_response_preserves_account_id_field() {
        let field_names: Vec<_> = serde_json::to_value(ListMetadataMetadata {
            payment_hash: "metadata_hash".to_string(),
            account_id: Some("acct_spark_metadata".to_string()),
            sender_comment: None,
            nostr_zap_request: None,
            nostr_zap_receipt: None,
            updated_at: 42,
            preimage: None,
        })
        .expect("metadata should serialize")
        .as_object()
        .expect("metadata should serialize as object")
        .keys()
        .cloned()
        .collect();

        assert_eq!(
            field_names,
            vec![
                "account_id",
                "nostr_zap_receipt",
                "nostr_zap_request",
                "payment_hash",
                "preimage",
                "sender_comment",
                "updated_at",
            ]
        );
    }

    #[test]
    fn spark_registration_conflicts_keep_duplicate_name_contract() {
        for error in [
            LnurlRepositoryError::NameTaken,
            LnurlRepositoryError::IdentifierConflict,
        ] {
            let (status, Json(body)) = spark_registration_error(error, "alice");
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body, Value::String("name already taken".to_string()));
        }
    }

    // -- Public LNURL provider-dispatch compatibility -------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn public_lnurl_discovery_shape_remains_spark_compatible() {
        let user = User {
            domain: "localhost:8080".to_string(),
            pubkey: "02abc123".to_string(),
            name: "alice".to_string(),
            description: "Alice wallet".to_string(),
        };
        let response = PayResponse {
            callback: "http://localhost:8080/lnurlp/alice/invoice".to_string(),
            max_sendable: 1_000_000,
            min_sendable: 1_000,
            tag: Tag::Pay,
            metadata: lnurl_pay::get_metadata(&user.domain, &user),
            comment_allowed: Some(MAX_COMMENT_LENGTH as u32),
            allows_nostr: None,
            nostr_pubkey: None,
        };

        let body = serde_json::to_value(response).expect("PayResponse serializes");
        assert_eq!(body["tag"], "payRequest");
        assert_eq!(
            body["callback"],
            "http://localhost:8080/lnurlp/alice/invoice"
        );
        assert_eq!(body["minSendable"], 1_000);
        assert_eq!(body["maxSendable"], 1_000_000);
        assert_eq!(body["commentAllowed"], MAX_COMMENT_LENGTH);
        assert!(body.get("metadata").is_some());
        assert!(body.get("provider").is_none());
        assert!(body.get("account_id").is_none());
    }

    #[test]
    fn public_invoice_and_verify_shapes_remain_spark_compatible() {
        let invoice_body = json!({
            "pr": "lnbc1testinvoice",
            "routes": Vec::<String>::new(),
            "verify": "http://localhost:8080/verify/payment_hash",
        });
        assert_eq!(invoice_body["pr"], "lnbc1testinvoice");
        assert_eq!(invoice_body["routes"].as_array().unwrap().len(), 0);
        assert_eq!(
            invoice_body["verify"],
            "http://localhost:8080/verify/payment_hash"
        );
        assert!(invoice_body.get("provider").is_none());
        assert!(invoice_body.get("account_id").is_none());

        let verify_body = json!({
            "status": "OK",
            "settled": false,
            "preimage": Value::Null,
            "pr": "lnbc1testinvoice",
        });
        assert_eq!(verify_body["status"], "OK");
        assert_eq!(verify_body["settled"], false);
        assert!(verify_body.get("provider").is_none());
    }

    #[tokio::test]
    async fn verify_spark_and_unowned_invoices_remain_local_state_only_setl_01_d_07() {
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Spark),
            "spark_verify_hash".to_string(),
            "lnbc1sparkverify",
            None,
        ))
        .await
        .unwrap();
        repo.upsert_invoice(&route_test_invoice(
            None,
            "legacy_verify_hash".to_string(),
            "lnbc1legacyverify",
            Some(TEST_PREIMAGE_HEX.to_string()),
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let spark_body = call_verify(state.clone(), "spark_verify_hash").await;
        assert_eq!(spark_body["status"], "OK");
        assert_eq!(spark_body["settled"], false);
        assert_eq!(spark_body["preimage"], Value::Null);
        assert_eq!(spark_body["pr"], "lnbc1sparkverify");

        let legacy_body = call_verify(state, "legacy_verify_hash").await;
        assert_eq!(legacy_body["status"], "OK");
        assert_eq!(legacy_body["settled"], true);
        assert_eq!(legacy_body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(legacy_body["pr"], "lnbc1legacyverify");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verify_blink_local_preimage_returns_settled_without_status_setl_02() {
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            compute_payment_hash(TEST_PREIMAGE_HEX),
            "lnbc1blinklocalverify",
            Some(TEST_PREIMAGE_HEX.to_string()),
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let body = call_verify(state, &compute_payment_hash(TEST_PREIMAGE_HEX)).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1blinklocalverify");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn blink_verify_uses_local_preimage_state_test_01() {
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1test01localverify",
            Some(TEST_PREIMAGE_HEX.to_string()),
        ))
        .await
        .expect("local Blink invoice fixture stores");
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;

        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1test01localverify");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "local LUD-21 state must avoid Blink status calls"
        );
    }

    #[tokio::test]
    async fn verify_blink_status_preimage_uses_central_side_effects_setl_03_07_08_d_09_d_22() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkfallbackverify",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1blinkfallbackverify");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash),
            "verify fallback must enqueue zap receipts through handle_invoice_paid"
        );
        assert_eq!(
            repo.webhook_deliveries.lock().unwrap().len(),
            1,
            "verify fallback must enqueue webhook deliveries through handle_invoice_paid"
        );
    }

    #[tokio::test]
    async fn blink_settlement_fallback_persists_through_paid_invoice_handler_test_01() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1test01fallbackverify",
            None,
        ))
        .await
        .expect("unsettled Blink invoice fixture stores");
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;

        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1test01fallbackverify");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let stored = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .expect("invoice lookup succeeds")
            .expect("invoice stays stored");
        assert_eq!(stored.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn verify_blink_paid_status_without_preimage_remains_unsettled_setl_03_d_10() {
        let payment_hash = "blink_paid_without_preimage_hash".to_string();
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknopreimageverify",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], false);
        assert_eq!(body["preimage"], Value::Null);
        assert_eq!(body["pr"], "lnbc1blinknopreimageverify");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert!(invoice.preimage.is_none());
        assert!(
            !repo
                .pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
    }

    #[tokio::test]
    async fn verify_blink_status_error_returns_generic_lnurl_error_d_11() {
        let payment_hash = "blink_status_error_hash".to_string();
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, true).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkerrorverify",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], "Internal server error");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    fn metadata_entries(metadata: &str) -> Vec<(String, String)> {
        serde_json::from_str::<Vec<(String, String)>>(metadata)
            .expect("metadata must be a JSON array of string tuples")
    }

    fn phone_blink_resolved_recipient() -> ResolvedRecipient {
        ResolvedRecipient {
            identifier: "+573005871212".to_string(),
            identifier_kind: AccountIdentifierKind::Phone,
            description: "Phone Blink account".to_string(),
            ..blink_resolved_recipient()
        }
    }

    #[tokio::test]
    async fn blink_public_discovery_username_metadata_uses_description_and_requested_identity_lnurl_01_lnurl_02_d_01_d_02_d_19()
     {
        // LNURL-01/LNURL-02/D-01/D-02/D-19: public discovery must resolve a
        // Blink recipient by canonical identifier, expose the requested
        // Lightning Address identity, and not require Spark-only metadata.
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("Example.COM".to_string()),
            Path("alice".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(response.callback, "http://example.com/lnurlp/alice/invoice");
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Alice Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "alice@example.com".to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_wallet_alias_preserves_public_identity_but_looks_up_canonical_lnurl_01_lnurl_02_d_03_comp_04()
     {
        // LNURL-01/LNURL-02/D-03/COMP-04: virtual +usd aliases influence only
        // public metadata/callback identity and wallet intent; repository lookup
        // remains canonical and never persists identifier+usd.
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("alice+usd".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink alias discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(
            response.callback,
            "http://example.com/lnurlp/alice+usd/invoice"
        );
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Alice Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "alice+usd@example.com".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_phone_identifier_keeps_requested_phone_identity_lnurl_01_lnurl_02_d_04()
     {
        // LNURL-01/LNURL-02/D-04: payer-supplied public phone identifiers are
        // allowed in metadata identity and must not be masked by description.
        let repo =
            MockRepository::default().with_resolved_recipient(phone_blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("573005871212".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink phone discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "+573005871212".to_string())]
        );
        assert_eq!(
            response.callback,
            "http://example.com/lnurlp/+573005871212/invoice"
        );
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Phone Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "+573005871212@example.com".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_missing_and_invalid_phone_like_identifiers_keep_spark_not_found_shape_d_19()
     {
        // D-19: missing/invalid Blink-looking public discovery must not leak
        // Blink-specific provider, account, phone, or existence details.
        let missing_repo = MockRepository::default();
        let missing_state = internal_route_test_state(missing_repo, None).await;
        let missing = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("alice".to_string()),
            Extension(missing_state),
        )
        .await;

        let Err((missing_status, Json(missing_body))) = missing else {
            panic!("missing recipient should keep Spark-compatible not-found shape");
        };
        assert_eq!(missing_status, StatusCode::NOT_FOUND);
        assert_eq!(missing_body, Value::String(String::new()));

        let invalid_repo = MockRepository::default();
        let invalid_state = internal_route_test_state(invalid_repo.clone(), None).await;
        let invalid = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("12345".to_string()),
            Extension(invalid_state),
        )
        .await;

        let Err((invalid_status, Json(invalid_body))) = invalid else {
            panic!("invalid phone-like recipient should keep Spark-compatible not-found shape");
        };
        assert_eq!(invalid_status, StatusCode::NOT_FOUND);
        assert_eq!(invalid_body, Value::String(String::new()));
        assert!(invalid_repo.resolve_calls().is_empty());
    }

    #[test]
    fn provider_invoice_metadata_contract_prov_04_lnurl_05_lnurl_06_d_11_d_13_d_15() {
        // PROV-04/LNURL-05/D-11/D-13/D-15: provider-neutral invoice rows must
        // carry typed provider/wallet metadata without any raw provider payload.
        let invoice = Invoice {
            account_id: Some("acct_spark_provider_metadata".to_string()),
            provider: Some(AccountProvider::Spark),
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: "provider_invoice_metadata_hash".to_string(),
            user_pubkey: "spark_provider_metadata_pubkey".to_string(),
            invoice: "lnbc1providerinvoice".to_string(),
            preimage: None,
            expired_at: None,
            invoice_expiry: i64::MAX,
            created_at: 1,
            updated_at: 2,
            domain: Some("provider-metadata.example.com".to_string()),
            amount_received_sat: None,
        };
        assert_eq!(invoice.provider, Some(AccountProvider::Spark));
        assert_eq!(invoice.wallet_kind, Some(WalletKind::Btc));
        assert!(invoice.wallet_id.is_none());
        assert!(invoice.provider_payment_hash.is_none());
        assert_eq!(
            invoice.account_id.as_deref(),
            Some("acct_spark_provider_metadata")
        );
        assert_eq!(
            invoice.domain.as_deref(),
            Some("provider-metadata.example.com")
        );

        let provider_invoice = crate::providers::ProviderInvoice {
            bolt11: invoice.invoice.clone(),
            wallet_kind: WalletKind::Btc,
            wallet_id: None,
            provider_payment_hash: None,
        };
        assert_eq!(provider_invoice.wallet_kind, WalletKind::Btc);

        // LNURL-06: the public callback success body stays exactly pr/routes/verify.
        let callback_body = json!({
            "pr": provider_invoice.bolt11,
            "routes": Vec::<String>::new(),
            "verify": "http://provider-metadata.example.com/verify/provider_invoice_metadata_hash",
        });
        let keys = callback_body
            .as_object()
            .expect("callback body must be an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["pr", "routes", "verify"]);
    }

    #[test]
    fn unsupported_spark_usd_maps_to_existing_lnurl_error_shape() {
        let routes_source = include_str!("mod.rs");
        assert!(
            routes_source.contains("fn map_provider_invoice_error"),
            "routes must own provider error to LNURL JSON mapping"
        );
        assert!(
            routes_source.contains("ProviderError::UnsupportedWallet"),
            "unsupported wallet errors must be mapped at the route boundary"
        );

        let (status, Json(body)) = lnurl_error("unsupported wallet");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], "unsupported wallet");
    }

    #[test]
    fn public_invoice_handler_source_uses_provider_dispatch_boundary() {
        let invoice = handler_source("handle_invoice");
        assert!(
            invoice.contains("parse_public_identifier"),
            "callback must parse wallet modifiers before provider dispatch"
        );
        assert!(
            invoice.contains("resolve_public_recipient"),
            "callback must resolve account-backed recipients through the public lookup helper"
        );
        assert!(
            invoice.contains("provider_for"),
            "callback must select the provider by resolved recipient provider"
        );
        assert!(
            invoice.contains("create_invoice"),
            "callback must create invoices through the selected provider"
        );
        let direct_wallet_call = ["state", "wallet", "create_lightning_invoice"].join(".");
        assert!(
            !invoice.contains(&direct_wallet_call),
            "callback must not call the Spark wallet directly"
        );

        let providers_source = include_str!("../providers.rs");
        let provider_runtime_source = providers_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .and_then(|runtime| runtime.split("pub enum BlinkSettlementNotification").next())
            .expect("providers source should have runtime section");
        assert!(!provider_runtime_source.contains("use axum"));
        assert!(!provider_runtime_source.contains("serde_json"));
    }

    #[test]
    fn spark_signature_validation_source_uses_adapter_boundary() {
        let routes_source = include_str!("mod.rs");
        let production_mod = routes_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("routes source should have production section");
        let production_routes = format!("{production_mod}\n{}", include_str!("account.rs"));
        let state_source = include_str!("../state.rs");

        assert!(production_routes.contains("Signature::from_der"));
        assert!(production_routes.contains("ACCEPTABLE_TIME_DIFF_SECS"));
        assert!(!production_routes.contains("state.wallet.verify_message"));
        assert!(production_routes.contains("state.spark_client.verify_message"));
        assert!(state_source.contains("pub spark_client"));
    }

    #[test]
    fn spark_bootstrap_and_state_source_use_adapter_boundary() {
        let main_source = include_str!("../main.rs");
        let production_main = main_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("main source should have production section");
        let state_source = include_str!("../state.rs");

        assert!(production_main.contains("parse_auth_seed(args.ssp_auth_seed.as_deref())"));
        assert!(production_main.contains("spark_client::ClientConfig::new(args.network"));
        assert!(production_main.contains("register_webhook(spark_client.clone()"));
        assert!(
            production_main.contains("format!(\"{}://{}/webhook\", args.scheme, webhook_domain)")
        );
        assert!(production_main.contains("std::time::Duration::from_secs(1)"));
        assert!(production_main.contains("std::time::Duration::from_mins(1)"));

        for marker in [
            "use spark::",
            "use spark_wallet::",
            "SparkWalletConfig",
            "DefaultSigner",
            "ServiceProvider",
            "InMemoryTreeStore",
            "InMemoryTokenOutputStore",
            "SparkWalletWebhookEventType",
        ] {
            assert!(
                !production_main.contains(marker),
                "main runtime must not contain raw Spark marker {marker}"
            );
        }

        for marker in [
            "use spark::",
            "use spark_wallet::",
            "SparkWallet",
            "DefaultSigner",
            "ServiceProvider",
            "ConnectionManager",
            "InMemorySessionStore",
            "pub wallet",
            "pub connection_manager",
            "pub coordinator",
            "pub signer",
            "pub session_store",
            "pub service_provider",
        ] {
            assert!(
                !state_source.contains(marker),
                "state must not expose raw Spark marker {marker}"
            );
        }
    }

    fn strip_line_comments(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn spark_client_extraction_source_audit_guards_runtime_boundaries() {
        let main_source = include_str!("../main.rs");
        let state_source = include_str!("../state.rs");
        let providers_source = include_str!("../providers.rs");
        let e2e_auth_source = include_str!("../bin/e2e_auth.rs");
        let routes_source = include_str!("mod.rs");

        let production_main = strip_line_comments(
            main_source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .expect("main source should have production section"),
        );
        let production_state = strip_line_comments(state_source);
        let production_providers = strip_line_comments(
            providers_source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .and_then(|runtime| runtime.split("pub enum BlinkSettlementNotification").next())
                .expect("providers source should have production section"),
        );
        let production_routes = strip_line_comments(
            routes_source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .expect("routes source should have production section"),
        );

        assert!(e2e_auth_source.contains("spark_client::Client::build_auth_payload"));
        for marker in ["use spark::", "use spark_wallet::"] {
            assert!(
                !e2e_auth_source.contains(marker),
                "e2e_auth must use adapter signing, not raw marker {marker}"
            );
        }

        for (name, source) in [
            ("src/main.rs", production_main.as_str()),
            ("src/state.rs", production_state.as_str()),
            ("src/providers.rs", production_providers.as_str()),
            ("src/routes.rs", production_routes.as_str()),
        ] {
            for marker in [
                "use spark::",
                "use spark_wallet::",
                "spark_wallet::SparkWallet",
                "SparkWalletConfig",
                "DefaultSigner",
                "state.wallet.verify_message",
                "ServiceProvider::new",
                "SparkWalletWebhookEventType",
            ] {
                assert!(
                    !source.contains(marker),
                    "{name} runtime boundary must not contain raw Spark marker {marker}"
                );
            }
        }
    }

    #[test]
    fn public_invoice_callback_keeps_wallet_aliases_virtual_in_storage_audit() {
        // D-03/PROV-04/LNURL-05: callback identifiers such as alice+btc and
        // alice+usd are public route identities only. Storage and dispatch must
        // use the resolved canonical recipient/account metadata instead.
        let invoice = handler_source("handle_invoice");
        assert!(
            invoice.contains("public_recipient.callback_identifier"),
            "callback metadata hashing should preserve requested public identity"
        );
        assert!(
            invoice.contains("Some(&account_id)")
                && invoice.contains("public_recipient.recipient.provider")
                && invoice.contains("res.wallet_id.as_deref()"),
            "invoice persistence must use resolved account/provider/wallet metadata"
        );
        assert!(
            !invoice.contains("identifier+btc")
                && !invoice.contains("identifier+usd")
                && !invoice.contains("callback_identifier.clone()"),
            "virtual aliases must not be persisted as account identifiers"
        );
    }

    #[tokio::test]
    async fn post_transfer_public_invoice_uses_spark_provider() {
        let repo =
            MockRepository::default().with_resolved_recipient(post_transfer_spark_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;
        let intent = parse_public_identifier_for_public_route("alice")
            .expect("identifier should parse")
            .expect("username should resolve as public intent");

        let public_recipient = resolve_public_recipient(&state, "example.com", intent)
            .await
            .expect("lookup should not fail")
            .expect("transferred identifier should resolve");
        assert_eq!(public_recipient.recipient.provider, AccountProvider::Spark);
        assert_eq!(
            public_recipient.recipient.spark_pubkey.as_deref(),
            Some("spark_after_transfer_pubkey")
        );

        let (_payment_hash, bolt11) = generate_route_test_invoice(31);
        let invoice = Bolt11Invoice::from_str(&bolt11).expect("test invoice parses");
        let payment_hash = invoice.payment_hash().to_string();
        create_provider_invoice_for_account(
            &repo,
            &payment_hash,
            Some(&public_recipient.recipient.account_id),
            Some(public_recipient.recipient.provider),
            Some(WalletKind::Btc),
            None,
            None,
            public_recipient
                .recipient
                .spark_pubkey
                .as_deref()
                .expect("Spark recipient has pubkey"),
            &bolt11,
            i64::MAX,
            &public_recipient.recipient.domain,
        )
        .await
        .expect("post-transfer Spark invoice should persist");

        let stored = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("new invoice should be persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Spark));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Btc));
        assert_eq!(stored.wallet_id, None);
        assert_eq!(stored.provider_payment_hash, None);
        assert_eq!(
            stored.account_id.as_deref(),
            Some("acct_spark_after_transfer")
        );
        assert_eq!(stored.user_pubkey, "spark_after_transfer_pubkey");
        assert_eq!(stored.domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn post_transfer_historical_blink_invoice_owner_is_unchanged() {
        let repo =
            MockRepository::default().with_resolved_recipient(post_transfer_spark_recipient());
        let historical_payment_hash = "historical_blink_before_transfer".to_string();
        repo.upsert_invoice(&Invoice {
            account_id: Some("acct_original_blink".to_string()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Usd),
            wallet_id: Some("original_blink_usd_wallet".to_string()),
            provider_payment_hash: Some("original_blink_provider_hash".to_string()),
            payment_hash: historical_payment_hash.clone(),
            user_pubkey: String::new(),
            invoice: "lnbc1historicalblink".to_string(),
            preimage: None,
            expired_at: None,
            invoice_expiry: i64::MAX,
            created_at: 1,
            updated_at: 1,
            domain: Some("example.com".to_string()),
            amount_received_sat: Some(42),
        })
        .await
        .unwrap();

        let state = internal_route_test_state(repo.clone(), None).await;
        let intent = parse_public_identifier_for_public_route("alice")
            .expect("identifier should parse")
            .expect("username should resolve as public intent");
        let public_recipient = resolve_public_recipient(&state, "example.com", intent)
            .await
            .expect("lookup should not fail")
            .expect("transferred identifier should resolve");
        assert_eq!(public_recipient.recipient.provider, AccountProvider::Spark);

        let stored = repo
            .get_invoice_by_payment_hash(&historical_payment_hash)
            .await
            .unwrap()
            .expect("historical Blink invoice should remain persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.account_id.as_deref(), Some("acct_original_blink"));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(
            stored.wallet_id.as_deref(),
            Some("original_blink_usd_wallet")
        );
        assert_eq!(stored.payment_hash, historical_payment_hash);
        assert_eq!(stored.amount_received_sat, Some(42));
    }

    #[test]
    fn blink_provider_source_boundaries_remain_route_and_registry_owned() {
        let routes_source = include_str!("mod.rs");
        let route_runtime_source = routes_source
            .split("#[cfg(test)]")
            .next()
            .expect("routes source should have runtime section");
        assert!(
            !route_runtime_source.contains("blink_client"),
            "routes must not call Blink GraphQL client directly"
        );
        assert!(
            routes_source.contains("ProviderError::MissingBlinkDefaultWallet")
                && routes_source.contains("ProviderError::MissingBlinkBtcWalletId")
                && routes_source.contains("ProviderError::MissingBlinkUsdWalletId")
                && routes_source.contains("ProviderError::BlinkInvoiceCreationFailed")
                && routes_source.contains("ProviderError::BlinkPaymentStatusUnavailable"),
            "route provider-error mapping must cover Blink provider failures"
        );

        let providers_source = include_str!("../providers.rs");
        assert!(
            providers_source.contains("AccountProvider::Blink => self.blink.as_ref()"),
            "registry must dispatch Blink centrally through ProviderRegistry"
        );
    }

    #[test]
    fn public_lnurl_error_reason_contract_is_explicit_and_plain() {
        // D-16/D-17/D-18/D-19: public LNURL error categories must stay stable,
        // plain, and provider-neutral so Blink internals never leak through
        // user-correctable or upstream provider failures.
        assert_eq!(
            public_lnurl_error_reasons(),
            [
                "unsupported wallet",
                "expiry too long",
                "missing amount",
                "amount out of range",
                "comment too long",
                "invoice creation failed",
            ]
        );

        for reason in public_lnurl_error_reasons() {
            let (status, Json(body)) = lnurl_error(reason);
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["status"], "ERROR");
            assert_eq!(body["reason"], reason);
            assert!(body.get("provider").is_none());
            assert!(body.get("account_id").is_none());
        }
    }

    #[test]
    fn spark_recipient_adapts_to_legacy_recover_fields() {
        let recipient = crate::repository::ResolvedRecipient {
            account_id: "acct_spark_test".to_string(),
            provider: crate::repository::AccountProvider::Spark,
            domain: "example.com".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: crate::repository::AccountIdentifierKind::Username,
            description: "Alice wallet".to_string(),
            spark_pubkey: Some("spark_pubkey".to_string()),
            blink_account_id: None,
            btc_wallet_id: None,
            usd_wallet_id: None,
            default_wallet: None,
        };

        let user = spark_user_from_recipient(recipient).expect("Spark recipient should adapt");
        assert_eq!(user.name, "alice");
        assert_eq!(user.domain, "example.com");
        assert_eq!(user.pubkey, "spark_pubkey");
        assert_eq!(user.description, "Alice wallet");
    }

    #[test]
    fn invoice_callback_writes_account_owned_side_effects() {
        let invoice_callback = handler_source("handle_invoice");
        assert!(
            invoice_callback.contains("account_id"),
            "invoice callback must carry resolved account ownership into side effects"
        );
        assert!(
            invoice_callback.contains("create_provider_invoice_for_account"),
            "invoice callback must use provider-aware account invoice construction"
        );
        assert!(
            !invoice_callback.contains("crate::invoice_paid::create_invoice(")
                && !invoice_callback.contains("invoice_paid::create_invoice("),
            "migrated invoice callback must not use the legacy account-less helper"
        );
    }

    #[tokio::test]
    async fn public_invoice_callback_blink_default_persists_provider_metadata_prov_04_lnurl_05_lnurl_06_d_12_d_15_d_16()
     {
        // PROV-04/LNURL-05/LNURL-06/D-12/D-15/D-16: Blink public callbacks must
        // create invoices through the provider registry, return exactly
        // pr/routes/verify, and persist provider-neutral metadata without a fake
        // Spark pubkey.
        let (_payment_hash, bolt11) = generate_route_test_invoice(11);
        let (endpoint, calls, _bodies) =
            start_blink_invoice_mock_server(bolt11.clone(), false).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let Json(body) = get_public_invoice(
            state,
            "alice",
            LnurlPayCallbackParams {
                amount: Some(1_000),
                ..LnurlPayCallbackParams::default()
            },
        )
        .await
        .expect("Blink default invoice callback should succeed");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            body.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["pr", "routes", "verify"]
        );
        let returned_invoice = Bolt11Invoice::from_str(body["pr"].as_str().unwrap())
            .expect("mock should return a valid invoice");
        let payment_hash = returned_invoice.payment_hash().to_string();
        assert_eq!(
            body["verify"],
            format!("http://example.com/verify/{payment_hash}")
        );
        let stored = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should be persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(stored.wallet_id.as_deref(), Some("usd_wallet_123"));
        assert_eq!(
            stored.provider_payment_hash.as_deref(),
            Some("provider_usd_hash")
        );
        assert_eq!(stored.account_id.as_deref(), Some("acct_blink_lookup"));
        assert_eq!(stored.domain.as_deref(), Some("example.com"));
        assert_eq!(stored.payment_hash, payment_hash);
        assert_ne!(
            stored.user_pubkey, "spark_pubkey_123",
            "Blink must not invent a fake Spark pubkey"
        );
    }

    #[tokio::test]
    async fn public_invoice_callback_blink_wallet_alias_and_expiry_policy_lnurl_04_d_03_d_05_d_06_d_07_d_08_d_09_d_10()
     {
        // LNURL-04/D-03/D-05-D-10: +btc/+usd aliases select Blink wallets and
        // route-owned expiry policy converts public seconds to provider-ready
        // minutes before dispatch.
        let (_payment_hash, bolt11) = generate_route_test_invoice(12);
        let (endpoint, calls, bodies) = start_blink_invoice_mock_server(bolt11, false).await;

        for (identifier, expiry, expected_wallet, expected_expiry) in [
            ("alice+btc", None, "btc_wallet_123", None),
            ("alice+btc", Some(60), "btc_wallet_123", Some(1)),
            ("alice+btc", Some(61), "btc_wallet_123", Some(2)),
            ("alice+btc", Some(86_400), "btc_wallet_123", Some(1440)),
            ("alice+usd", Some(300), "usd_wallet_123", Some(5)),
        ] {
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            let _ = get_public_invoice(
                state,
                identifier,
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    expiry,
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await
            .expect("accepted Blink expiry should create invoice");
            let body = bodies
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("provider body captured");
            assert_eq!(
                body["variables"]["input"]["recipientWalletId"],
                expected_wallet
            );
            match expected_expiry {
                Some(minutes) => assert_eq!(body["variables"]["input"]["expiresIn"], minutes),
                None => assert!(body["variables"]["input"].get("expiresIn").is_none()),
            }
        }

        for (identifier, expiry) in [("alice+btc", 86_401), ("alice+usd", 301)] {
            let before = calls.load(Ordering::SeqCst);
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            assert_lnurl_error(
                get_public_invoice(
                    state,
                    identifier,
                    LnurlPayCallbackParams {
                        amount: Some(1_000),
                        expiry: Some(expiry),
                        ..LnurlPayCallbackParams::default()
                    },
                )
                .await,
                "expiry too long",
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                before,
                "over-limit expiry must not dispatch provider calls"
            );
        }
    }

    #[tokio::test]
    async fn public_invoice_callback_validation_before_dispatch_lnurl_03_comp_04_d_17_d_18() {
        // LNURL-03/COMP-04/D-17/D-18: route-owned validation must happen before
        // provider dispatch and public errors must use stable plain phrases.
        let (_payment_hash, bolt11) = generate_route_test_invoice(13);
        let (endpoint, calls, _bodies) = start_blink_invoice_mock_server(bolt11, false).await;

        for (params, expected) in [
            (LnurlPayCallbackParams::default(), "missing amount"),
            (
                LnurlPayCallbackParams {
                    amount: Some(0),
                    ..LnurlPayCallbackParams::default()
                },
                "amount out of range",
            ),
            (
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    comment: Some("x".repeat(MAX_COMMENT_LENGTH + 1)),
                    ..LnurlPayCallbackParams::default()
                },
                "comment too long",
            ),
            (
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    nostr: Some("not-json".to_string()),
                    ..LnurlPayCallbackParams::default()
                },
                "nostr zap not supported",
            ),
        ] {
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            let before = calls.load(Ordering::SeqCst);
            assert_lnurl_error(get_public_invoice(state, "alice", params).await, expected);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                before,
                "{expected} must happen before provider dispatch"
            );
        }

        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let before = calls.load(Ordering::SeqCst);
        assert_lnurl_error(
            get_public_invoice(
                state,
                "alice",
                LnurlPayCallbackParams {
                    amount: Some(2_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "internal server error",
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "provider amount mismatch is rejected after provider dispatch"
        );

        let spark_repo =
            MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let spark_state =
            internal_route_test_state_with_blink_endpoint(spark_repo, None, &endpoint).await;
        assert_lnurl_error(
            get_public_invoice(
                spark_state,
                "bob+usd",
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "unsupported wallet",
        );

        let (failing_endpoint, _failing_calls, _failing_bodies) =
            start_blink_invoice_mock_server("lnbc1unused".to_string(), true).await;
        let failing_repo =
            MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let failing_state =
            internal_route_test_state_with_blink_endpoint(failing_repo, None, &failing_endpoint)
                .await;
        assert_lnurl_error(
            get_public_invoice(
                failing_state,
                "alice",
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "invoice creation failed",
        );
    }

    #[tokio::test]
    async fn create_internal_blink_account_happy_path_requires_valid_internal_token() {
        // D-01/D-04/D-08/D-09/D-13/D-14/D-16/D-17/D-19: the internal account
        // creation happy path is locked to /internal/blink/accounts, a scoped
        // RS256 JWT, local deterministic JWKS/key fixtures, route-boundary
        // normalization, and exactly one provider-neutral repository write.
        let jwks = include_str!("../../tests/fixtures/internal_auth_jwks.json");
        let private_key = include_bytes!("../../tests/fixtures/internal_auth_private.pem");
        let auth_state = Arc::new(
            crate::internal_auth::InternalAuthState::from_jwks_json(
                jwks,
                "https://issuer.internal.test".to_string(),
                "lnurl-server.internal.test".to_string(),
            )
            .expect("test JWKS fixture must load"),
        );

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("blink-internal-test-key".to_string());
        let token = encode(
            &header,
            &serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": "https://issuer.internal.test",
                "aud": "lnurl-server.internal.test",
                "exp": 4_102_444_800_u64,
                "nbf": 1_700_000_000_u64,
                "scope": "blink:accounts:create accounts:read"
            }),
            &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
        )
        .expect("test JWT must sign");

        let repo = MockRepository::default();
        let state = internal_route_test_state(repo.clone(), Some(auth_state)).await;
        let app = Router::new()
            .route(
                "/internal/blink/accounts",
                post(LnurlServer::<MockRepository>::create_internal_blink_account),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state));

        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/accounts")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&CreateBlinkAccountRequest {
                    domain: "Example.COM".to_string(),
                    blink_account_id: "blink_account_123".to_string(),
                    btc_wallet_id: "btc_wallet_123".to_string(),
                    usd_wallet_id: "usd_wallet_123".to_string(),
                    default_wallet: "usd".to_string(),
                    description: "Blink account".to_string(),
                    identifiers: vec![" Alice_123 ".to_string(), "+573005871212".to_string()],
                })
                .expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let response: CreateBlinkAccountResponse =
            serde_json::from_slice(&body).expect("response deserializes");
        assert_eq!(response.provider, "blink");
        assert_eq!(response.domain, "example.com");
        assert_eq!(response.identifiers[0].identifier, "alice_123");

        let created = repo.created_blink_accounts.lock().unwrap();
        assert_eq!(
            created.len(),
            1,
            "create_blink_account is called exactly once"
        );
        let account = &created[0];
        assert!(
            account
                .account_id
                .as_deref()
                .is_some_and(|id| id.starts_with("acct_blink_"))
        );
        assert_eq!(account.blink_account_id, "blink_account_123");
        assert_eq!(account.default_wallet, WalletKind::Usd);
        assert_eq!(account.identifiers.len(), 2);
        assert_eq!(account.identifiers[0].domain, "example.com");
        assert_eq!(account.identifiers[0].identifier, "alice_123");
        assert_eq!(
            account.identifiers[0].identifier_kind,
            AccountIdentifierKind::Username
        );
        assert_eq!(account.identifiers[0].description, "Blink account");
        assert_eq!(account.identifiers[1].identifier, "+573005871212");
        assert_eq!(
            account.identifiers[1].identifier_kind,
            AccountIdentifierKind::Phone
        );
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_missing_identifiers_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers.clear();

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_invalid_default_wallet_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.default_wallet = "eur".to_string();

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_invalid_identifier_without_repository_write()
    {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["not valid".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_identifier"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_wallet_modifier_without_repository_write() {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["alice+btc".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "wallet_modifier_not_allowed"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_duplicate_normalized_identifier_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["Alice_123".to_string(), " alice_123 ".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_duplicate_blink_account_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::BlinkAccountExists);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "blink_account_exists"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_identifier_conflict_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::IdentifierConflict);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "identifier_conflict"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_name_taken_fallback_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::NameTaken);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "identifier_conflict"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_fails_closed_when_internal_auth_config_is_absent() {
        // D-03/D-07/D-27: absent configured internal auth state returns 401 before handler writes.
        let repo = MockRepository::default();
        let state = internal_route_test_state(repo.clone(), None).await;
        let app = internal_account_app_with_state(state);

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, Value::Null);
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_requires_create_scope_before_repository_write() {
        // D-09/D-10: valid internal JWTs without the route scope receive 403.
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/accounts")
            .header(
                "authorization",
                format!("Bearer {}", internal_test_token_with_scope("accounts:read")),
            )
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&valid_create_blink_account_payload())
                    .expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body: Value = serde_json::from_slice(&body).expect("response body is JSON");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

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
    async fn internal_transfer_to_spark_requires_transfer_scope() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            "blink:accounts:create accounts:read",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn transfer_route_rejects_invalid_scope_before_side_effects_test_01() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            "accounts:read",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(
            repo.resolve_calls().is_empty(),
            "scope failures must happen before repository lookups"
        );
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_rejects_invalid_destination_pubkey_without_transfer() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;
        let mut payload = valid_internal_transfer_to_spark_payload();
        payload.destination_spark_pubkey = "not-a-pubkey".to_string();

        let (status, body) = post_internal_transfer_to_spark(
            app,
            payload,
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_missing_scope_rejects_malformed_json_before_parsing() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) =
            post_internal_transfer_to_spark_raw(app, "{", "blink:accounts:create accounts:read")
                .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_rejects_spark_owned_source() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn transfer_route_rejects_invalid_ownership_before_side_effects_test_01() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert_eq!(
            repo.blink_to_spark_transfer_count(),
            0,
            "non-Blink owners must not reach transfer side effects"
        );
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_moves_blink_identifier_to_spark() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["identifier"], "alice");
        assert_eq!(body["provider"], "spark");
        assert_eq!(
            body["spark_pubkey"],
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(body["lightning_address"], "alice@example.com");
        assert_eq!(body["lnurl"], "lnurlp://example.com/lnurlp/alice");
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(repo.blink_to_spark_transfers().len(), 1);
        let transfer = repo.blink_to_spark_transfers().remove(0);
        assert_eq!(transfer.domain, "example.com");
        assert_eq!(transfer.identifier, "alice");
        assert_eq!(transfer.source_account_id, "acct_blink_lookup");
        assert_eq!(
            transfer.destination_spark_pubkey,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(transfer.description, "Moved to Spark");
    }

    #[tokio::test]
    async fn internal_identifier_lookup_blink_parses_btc_modifier_before_repository_lookup() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice+btc",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(body["provider"], "blink");
        assert_eq!(body["account_id"], "acct_blink_lookup");
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["identifier"], "alice");
        assert_eq!(body["identifier_kind"], "username");
        assert_eq!(body["description"], "Alice Blink account");
        assert_eq!(body["requested_wallet"], "btc");
        assert_eq!(
            body["provider_details"]["blink_account_id"],
            "blink_account_123"
        );
        assert_eq!(body["provider_details"]["btc_wallet_id"], "btc_wallet_123");
        assert_eq!(body["provider_details"]["usd_wallet_id"], "usd_wallet_123");
        assert_eq!(body["provider_details"]["default_wallet"], "usd");
        assert!(
            body["provider_details"]
                .get("spark_pubkey")
                .is_none_or(Value::is_null)
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_spark_returns_spark_details_and_usd_wallet_intent() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/Example.COM/identifiers/bob+usd",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "bob".to_string())]
        );
        assert_eq!(body["provider"], "spark");
        assert_eq!(body["account_id"], "acct_spark_lookup");
        assert_eq!(body["requested_wallet"], "usd");
        assert_eq!(body["provider_details"]["spark_pubkey"], "spark_pubkey_123");
        assert!(
            body["provider_details"]
                .get("blink_account_id")
                .is_none_or(Value::is_null)
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_requires_accounts_read_scope_before_repository_lookup() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice",
            internal_test_token_with_scope("blink:accounts:create"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
    }

    #[tokio::test]
    async fn internal_identifier_lookup_returns_not_found_for_missing_identifier() {
        let repo = MockRepository::default();
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({"error": "not_found"}));
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_rejects_invalid_domain_and_identifier() {
        let repo = MockRepository::default();
        let app = internal_lookup_app(repo.clone()).await;

        let (domain_status, domain_body) = get_internal_identifier(
            app.clone(),
            "/internal/domains/%20%20/identifiers/alice",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;
        let (identifier_status, identifier_body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice+eur",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(domain_status, StatusCode::BAD_REQUEST);
        assert_eq!(domain_body, json!({"error": "invalid_domain"}));
        assert_eq!(identifier_status, StatusCode::BAD_REQUEST);
        assert_eq!(identifier_body, json!({"error": "invalid_identifier"}));
        assert!(repo.resolve_calls().is_empty());
    }

    #[tokio::test]
    async fn rejected_rpc_style_identifier_lookup_route_is_not_mounted() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, _body) = get_internal_identifier(
            app,
            "/internal/accounts/by-identifier/alice?domain=example.com",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(repo.resolve_calls().is_empty());
    }

    #[test]
    fn internal_identifier_lookup_route_shape_is_locked_to_restful_path() {
        let main_source = include_str!("../main.rs");
        assert!(main_source.contains("/domains/{domain}/identifiers/{identifier}"));
        assert!(!main_source.contains("accounts/by-identifier"));
    }

    #[test]
    fn internal_route_boundary_keeps_spark_and_public_routes_outside_internal_auth() {
        // D-01/D-02/D-28: `/internal` is nested separately, Spark management routes
        // keep `auth::auth`, and public LNURL routes remain outside internal JWT auth.
        let main_source = include_str!("../main.rs");
        let internal_mount = main_source
            .find(".nest(\"/internal\", internal_router)")
            .expect("internal router must be nested separately");
        let spark_auth = main_source
            .find("auth::auth::<DB>")
            .expect("Spark compatibility routes must keep certificate auth");
        let public_lnurl = main_source
            .find("/.well-known/lnurlp/{identifier}")
            .expect("public LNURL route must remain mounted");
        let internal_auth = main_source
            .find("internal_auth::internal_auth::<DB>")
            .expect("internal router must use internal JWT middleware");

        assert!(internal_auth < internal_mount);
        assert!(internal_mount < spark_auth);
        assert!(spark_auth < public_lnurl);
        assert!(main_source.contains("/blink/accounts"));
        assert!(main_source.contains("/lnurlpay/{pubkey}"));
        assert!(main_source.contains("/lnurlp/{identifier}"));
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

    // -- Transfer signature verification ---------------------------------------
    //
    // The transfer route verifies signatures through spark-client. These local
    // checks exercise the same canonical "transfer:{username}-{to_pubkey}"
    // message binding without constructing a runtime Spark client.

    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Deterministic keypair from a seed byte.
    fn transfer_key(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
        let public = PublicKey::from_secret_key(&secp, &secret);
        (secret, public)
    }

    /// Sign `message` the way the SDK does: ECDSA over `sha256(message)`.
    fn sign(secret: &SecretKey, message: &str) -> Signature {
        let secp = Secp256k1::new();
        let digest = sha256::Hash::hash(message.as_bytes());
        secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()), secret)
    }

    /// The canonical message the transfer route signs and verifies.
    fn transfer_message(username: &str, to_pubkey: &PublicKey) -> String {
        format!("transfer:{username}-{}", hex::encode(to_pubkey.serialize()))
    }

    #[test]
    fn transfer_signature_accepts_valid() {
        let secp = Secp256k1::new();
        let (alice_secret, alice_pubkey) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let message = transfer_message("alice", &bob_pubkey);
        let sig = sign(&alice_secret, &message);

        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(sha256::Hash::hash(message.as_bytes()).to_byte_array()),
                &sig,
                &alice_pubkey,
            )
            .is_ok(),
            "a valid signature over the canonical message must verify"
        );
    }

    #[test]
    fn transfer_signature_rejects_forged_signer() {
        // Alice signs, but the request attributes the signature to Bob's key.
        let secp = Secp256k1::new();
        let (alice_secret, _) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let message = transfer_message("alice", &bob_pubkey);
        let sig = sign(&alice_secret, &message);

        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(sha256::Hash::hash(message.as_bytes()).to_byte_array()),
                &sig,
                &bob_pubkey,
            )
            .is_err(),
            "a signature made by a different key must be rejected"
        );
    }

    #[test]
    fn transfer_signature_is_bound_to_message() {
        // A signature verifies only for the exact bytes signed: changing the
        // username invalidates it, and a register-style "{name}-{timestamp}"
        // signature cannot be replayed as a transfer (the "transfer:" prefix
        // domain-separates the two flows).
        let secp = Secp256k1::new();
        let (alice_secret, alice_pubkey) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let sig = sign(&alice_secret, &transfer_message("alice", &bob_pubkey));

        let tampered_username = transfer_message("mallory", &bob_pubkey);
        let register_style = String::from("alice-1700000000");
        for other in [tampered_username, register_style] {
            assert!(
                secp.verify_ecdsa(
                    &Message::from_digest(sha256::Hash::hash(other.as_bytes()).to_byte_array()),
                    &sig,
                    &alice_pubkey,
                )
                .is_err(),
                "signature must not verify against a different message: {other}"
            );
        }
    }
}
