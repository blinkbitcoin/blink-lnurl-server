use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::Host;
use bitcoin::{
    hashes::{Hash, sha256},
    secp256k1::XOnlyPublicKey,
};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use nostr::{Event, JsonUtil};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;
use tracing::{debug, error, trace};

use crate::{
    invoice_paid::{
        HandleInvoicePaidError, create_provider_invoice_for_account, handle_invoice_paid,
        handle_invoices_paid,
    },
    models::{CheckUsernameAvailableResponse, InvoicePaidRequest, InvoicesPaidRequest},
    providers::{CreateInvoiceRequest, ProviderError},
    repository::{
        AccountProvider, LnurlRepository, LnurlSenderComment, ResolvedRecipient, WalletKind,
    },
    state::State,
    time::now_millis,
    zap::Zap,
};

use super::{
    BLINK_BTC_EXPIRY_LIMIT_SECS, BLINK_USD_EXPIRY_LIMIT_SECS, LnurlServer, MAX_COMMENT_LENGTH,
    MAX_NOSTR_EVENT_SIZE, account, settle_blink_invoice_by_payment_hash,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LnurlPayCallbackParams {
    pub amount: Option<u64>,
    pub comment: Option<String>,
    pub nostr: Option<String>,
    pub expiry: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    #[serde(rename = "payRequest")]
    Pay,
    #[serde(rename = "withdrawRequest")]
    Withdraw,
    #[serde(rename = "channelRequest")]
    Channel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayResponse {
    /// a second-level url which give you an invoice with a GET request
    /// and an amount
    pub callback: String,
    /// max sendable amount for a given user on a given service
    #[serde(rename = "maxSendable")]
    pub max_sendable: u64,
    /// min sendable amount for a given user on a given service,
    /// can not be less than 1 or more than `max_sendable`
    #[serde(rename = "minSendable")]
    pub min_sendable: u64,
    /// tag of the request
    pub tag: Tag,
    /// Metadata json which must be presented as raw string here,
    /// this is required to pass signature verification at a later step
    pub metadata: String,

    /// Optional, if true, the service allows comments
    /// the number is the max length of the comment
    #[serde(rename = "commentAllowed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_allowed: Option<u32>,

    /// Optional, if true, the service allows nostr zaps
    #[serde(rename = "allowsNostr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allows_nostr: Option<bool>,

    /// Optional, if true, the nostr pubkey that will be used to sign zap events
    #[serde(rename = "nostrPubkey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<XOnlyPublicKey>,
}

pub(super) struct PublicIdentifierIntent {
    pub(super) canonical: String,
    pub(super) wallet: Option<WalletKind>,
    pub(super) callback_identifier: String,
}

pub(super) struct PublicRecipient {
    pub(super) recipient: ResolvedRecipient,
    pub(super) wallet: Option<WalletKind>,
    pub(super) callback_identifier: String,
}

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    pub async fn available(
        Host(host): Host,
        Path(identifier): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<CheckUsernameAvailableResponse>, (StatusCode, Json<Value>)> {
        let username = account::canonical_spark_username_for_route(&identifier)?;
        let domain = account::sanitize_domain(&state, &host).await?;
        let recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &username)
            .await
            .map_err(|e| {
                error!("failed to execute query: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            })?;

        Ok(Json(CheckUsernameAvailableResponse {
            available: recipient.is_none(),
        }))
    }

    pub async fn handle_lnurl_pay(
        Host(host): Host,
        Path(identifier): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<PayResponse>, (StatusCode, Json<Value>)> {
        if identifier.is_empty() {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        }

        let domain = account::sanitize_domain(&state, &host).await?;
        let Some(public_identifier) =
            account::parse_public_identifier_for_public_route(&identifier).map_err(|e| {
                trace!("invalid public identifier '{identifier}': {e:?}");
                lnurl_error("invalid identifier")
            })?
        else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let public_recipient =
            account::resolve_public_recipient(&state, &domain, public_identifier).await?;
        let Some(public_recipient) = public_recipient else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };

        let (allows_nostr, nostr_pubkey) = if let Some(nostr_keys) = state.nostr_keys.as_ref() {
            let xonly_pubkey = nostr_keys.public_key.xonly().map_err(|e| {
                error!(
                    "invalid nostr pubkey in server keys, could not parse: {:?}",
                    e
                );
                lnurl_error("internal server error")
            })?;
            (Some(true), Some(xonly_pubkey))
        } else {
            (None, None)
        };
        Ok(Json(PayResponse {
            callback: format!(
                "{}://{}/lnurlp/{}/invoice",
                state.scheme, domain, public_recipient.callback_identifier
            ),
            max_sendable: state.max_sendable,
            min_sendable: state.min_sendable,
            tag: Tag::Pay,
            metadata: get_metadata_for_recipient(
                &public_recipient.recipient,
                &public_recipient.callback_identifier,
            ),
            #[allow(clippy::cast_possible_truncation)]
            comment_allowed: Some(MAX_COMMENT_LENGTH as u32),
            allows_nostr,
            nostr_pubkey,
        }))
    }

    #[allow(clippy::too_many_lines)]
    pub async fn handle_invoice(
        Host(host): Host,
        Path(identifier): Path<String>,
        Query(params): Query<LnurlPayCallbackParams>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        if identifier.is_empty() {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        }

        let Some(public_identifier) =
            account::parse_public_identifier_for_public_route(&identifier).map_err(|e| {
                trace!("invalid public identifier '{identifier}': {e:?}");
                lnurl_error("invalid identifier")
            })?
        else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let domain = account::sanitize_domain(&state, &host).await?;
        let public_recipient =
            account::resolve_public_recipient(&state, &domain, public_identifier).await?;
        let Some(public_recipient) = public_recipient else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let account_id = public_recipient.recipient.account_id.clone();
        let legacy_user_pubkey = public_recipient
            .recipient
            .spark_pubkey
            .as_deref()
            .unwrap_or("")
            .to_string();

        let Some(amount_msat) = params.amount else {
            trace!("missing amount");
            return Err(lnurl_error("missing amount"));
        };

        if amount_msat % 1000 != 0 {
            trace!("not a full sat amount");
            return Err(lnurl_error("amount must be a whole sat amount"));
        }

        if amount_msat < state.min_sendable || amount_msat > state.max_sendable {
            trace!("amount outside advertised minSendable/maxSendable range");
            return Err(lnurl_error("amount out of range"));
        }

        if let Some(comment) = params.comment.as_deref()
            && comment.trim().len() > MAX_COMMENT_LENGTH
        {
            return Err(lnurl_error("comment too long"));
        }

        let nostr_pubkey = state
            .nostr_keys
            .as_ref()
            .map(|nostr_keys| {
                nostr_keys.public_key.xonly().map_err(|e| {
                    error!(
                        "invalid nostr pubkey in server keys, could not parse: {:?}",
                        e
                    );
                    lnurl_error("internal server error")
                })
            })
            .transpose()?;

        let desc_hash = if let Some(raw_event) = &params.nostr {
            let Some(expected_nostr_pubkey) = nostr_pubkey else {
                trace!("nostr zap not supported");
                return Err(lnurl_error("nostr zap not supported"));
            };

            if raw_event.len() > MAX_NOSTR_EVENT_SIZE {
                return Err(lnurl_error("nostr event too large"));
            }

            let event = Event::from_json(raw_event).map_err(|e| {
                trace!("invalid nostr event, could not parse: {}", e);
                lnurl_error("invalid nostr event")
            })?;
            super::zap::validate_nostr_zap_request(amount_msat, &event, expected_nostr_pubkey)?;
            sha256::Hash::hash(raw_event.as_bytes())
        } else {
            let metadata = get_metadata_for_recipient(
                &public_recipient.recipient,
                &public_recipient.callback_identifier,
            );
            sha256::Hash::hash(metadata.as_bytes())
        };

        let expiry = callback_expiry_for_provider(
            public_recipient.recipient.provider,
            public_recipient.wallet,
            public_recipient.recipient.default_wallet,
            params.expiry,
        )?;

        let res = state
            .providers
            .provider_for(public_recipient.recipient.provider)
            .create_invoice(CreateInvoiceRequest {
                recipient: &public_recipient.recipient,
                wallet: public_recipient.wallet,
                amount_sat: amount_msat / 1000,
                description_hash: desc_hash.to_byte_array(),
                expiry,
                include_spark_address: state.include_spark_address,
            })
            .await
            .map_err(map_provider_invoice_error)?;

        debug!("Created lightning invoice: {:?}", res);

        let invoice = Bolt11Invoice::from_str(&res.bolt11).map_err(|e| {
            error!("failed to parse invoice: {}", e);
            lnurl_error("internal server error")
        })?;

        if !matches!(invoice.description(), Bolt11InvoiceDescriptionRef::Hash(hash) if hash.0.to_string() == desc_hash.to_string())
        {
            error!("provider returned invoice with unexpected description hash");
            return Err(lnurl_error("internal server error"));
        }

        let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() else {
            error!("provider returned invoice without an amount");
            return Err(lnurl_error("internal server error"));
        };

        if invoice_amount_msat != amount_msat {
            error!(
                "provider returned invoice amount {} msat, expected {} msat",
                invoice_amount_msat, amount_msat
            );
            return Err(lnurl_error("internal server error"));
        }

        // Calculate expiry timestamp: current time + expiry duration from invoice
        let expiry_timestamp = invoice.expires_at().ok_or_else(|| {
            error!(
                "invoice has invalid expiry: duration since epoch {}s, expiry time: {}s",
                invoice.duration_since_epoch().as_secs(),
                invoice.expiry_time().as_secs()
            );
            lnurl_error("internal server error")
        })?;

        let updated_at = now_millis();
        let payment_hash = invoice.payment_hash().to_string();
        let invoice_expiry: i64 = i64::try_from(expiry_timestamp.as_secs()).map_err(|e| {
            error!(
                "invoice has invalid expiry for i64: duration since epoch {}s, expiry time: {}s: {e}",
                invoice.duration_since_epoch().as_secs(),
                invoice.expiry_time().as_secs(),
            );
            lnurl_error("internal server error")
        })?;

        // save to zap event to db
        if let Some(zap_request) = params.nostr {
            let zap = Zap {
                account_id: Some(account_id.clone()),
                payment_hash: payment_hash.clone(),
                zap_request,
                zap_event: None,
                user_pubkey: legacy_user_pubkey.clone(),
                invoice_expiry,
                updated_at,
                is_user_nostr_key: false,
            };
            if let Err(e) = state.db.upsert_zap(&zap).await {
                error!("failed to save zap event: {}", e);
                return Err(lnurl_error("internal server error"));
            }
        }

        if let Some(comment) = params.comment {
            let comment = comment.trim();
            if !comment.is_empty()
                && let Err(e) = state
                    .db
                    .insert_lnurl_sender_comment(&LnurlSenderComment {
                        account_id: Some(account_id.clone()),
                        comment: comment.to_string(),
                        payment_hash: payment_hash.clone(),
                        user_pubkey: legacy_user_pubkey.clone(),
                        updated_at,
                    })
                    .await
            {
                error!("Failed to insert lnurl sender comment: {:?}", e);
                return Err(lnurl_error("internal server error"));
            }
        }

        // Store invoice for LUD-21 verify support and webhook delivery
        if let Err(e) = create_provider_invoice_for_account(
            &state.db,
            &payment_hash,
            Some(&account_id),
            Some(public_recipient.recipient.provider),
            Some(res.wallet_kind),
            res.wallet_id.as_deref(),
            res.provider_payment_hash.as_deref(),
            &legacy_user_pubkey,
            &res.bolt11,
            invoice_expiry,
            &domain,
        )
        .await
        {
            error!("Failed to create invoice record: {}", e);
            return Err(lnurl_error("internal server error"));
        }

        let verify_url = format!("{}://{}/verify/{}", state.scheme, domain, payment_hash);

        Ok(Json(json!({
            "pr": res.bolt11,
            "routes": Vec::<String>::new(),
            "verify": verify_url,
        })))
    }

    /// LUD-21 verify endpoint
    pub async fn verify(
        Path(payment_hash): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> impl IntoResponse {
        let mut invoice = match state.db.get_invoice_by_payment_hash(&payment_hash).await {
            Ok(Some(invoice)) => invoice,
            Ok(None) => {
                return Json(json!({
                    "status": "ERROR",
                    "reason": "Not found"
                }));
            }
            Err(e) => {
                error!("Failed to get invoice by payment hash: {}", e);
                return Json(json!({
                    "status": "ERROR",
                    "reason": "Internal server error"
                }));
            }
        };

        if invoice.preimage.is_none()
            && invoice.expired_at.is_none()
            && invoice.provider == Some(AccountProvider::Blink)
        {
            match settle_blink_invoice_by_payment_hash(&state, &payment_hash, None).await {
                Ok(Some(preimage)) => {
                    invoice.preimage = Some(preimage);
                }
                Ok(None) => {}
                Err(e) => {
                    error!(
                        "Failed to settle Blink invoice during public verify for {}: {}",
                        payment_hash, e
                    );
                    return Json(json!({
                        "status": "ERROR",
                        "reason": "Internal server error"
                    }));
                }
            }
        }

        let settled = invoice.preimage.is_some();
        Json(json!({
            "status": "OK",
            "settled": settled,
            "preimage": invoice.preimage,
            "pr": invoice.invoice
        }))
    }

    /// Invoice-paid notification endpoint (single invoice).
    /// Deprecated: use `invoices_paid` instead, which supports batch notifications.
    /// TODO(DEF-legacy-invoice-paid): Remove after all clients have migrated to `invoices_paid`.
    pub async fn invoice_paid(
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<InvoicePaidRequest>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        let pubkey = account::validate(
            &pubkey,
            &payload.signature,
            &payload.preimage,
            payload.timestamp,
            &state,
        )
        .await?;

        let preimage_bytes = hex::decode(&payload.preimage).map_err(|e| {
            trace!("invalid preimage, could not decode: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(Value::String("invalid preimage".into())),
            )
        })?;
        let payment_hash = bitcoin::hashes::sha256::Hash::hash(&preimage_bytes);
        let payment_hash_hex = payment_hash.to_string();

        // Verify the invoice belongs to this user
        let invoice = state
            .db
            .get_invoice_by_payment_hash(&payment_hash_hex)
            .await
            .map_err(|e| {
                error!("Failed to get invoice: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            })?
            .ok_or_else(|| {
                trace!("invoice not found for payment hash: {}", payment_hash_hex);
                (
                    StatusCode::NOT_FOUND,
                    Json(Value::String("invoice not found".into())),
                )
            })?;

        if invoice.user_pubkey != pubkey.to_string() {
            trace!("invoice does not belong to this user");
            return Err((
                StatusCode::NOT_FOUND,
                Json(Value::String("invoice not found".into())),
            ));
        }

        // Use the central invoice paid handler
        handle_invoice_paid(
            &state.db,
            &state.webhook_service,
            &payment_hash_hex,
            &payload.preimage,
            None,
            &state.invoice_paid_trigger,
        )
        .await
        .map_err(|e| {
            error!("Failed to handle invoice paid: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        })?;

        debug!(
            "Invoice paid notification received for payment hash {}",
            payment_hash_hex
        );
        Ok(())
    }

    /// Batch invoices-paid notification endpoint.
    /// Client notifies server that multiple invoices were paid with their preimages.
    pub async fn invoices_paid(
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<InvoicesPaidRequest>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        const MAX_PREIMAGES: usize = 100;

        if payload.invoices.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String("invoices must not be empty".into())),
            ));
        }

        if payload.invoices.len() > MAX_PREIMAGES {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String(format!(
                    "too many invoices, max is {MAX_PREIMAGES}"
                ))),
            ));
        }

        let pubkey = account::validate(
            &pubkey,
            &payload.signature,
            &pubkey,
            payload.timestamp,
            &state,
        )
        .await?;

        handle_invoices_paid(
            &state.db,
            &state.webhook_service,
            &payload.invoices,
            &pubkey.to_string(),
            &state.invoice_paid_trigger,
        )
        .await
        .map_err(|e| match &e {
            HandleInvoicePaidError::InvalidInvoice(msg)
            | HandleInvoicePaidError::InvalidPreimage(msg) => {
                trace!("Invalid input in invoices-paid: {}", msg);
                (StatusCode::BAD_REQUEST, Json(Value::String(msg.clone())))
            }
            HandleInvoicePaidError::Repository(_) => {
                error!("Failed to handle invoices paid: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            }
        })?;

        debug!(
            "Invoices paid notification received for {} invoices",
            payload.invoices.len()
        );
        Ok(())
    }
}

pub(super) fn validate_description(description: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if description.chars().take(256).count() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("description too long".into())),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn get_metadata(domain: &str, user: &crate::user::User) -> String {
    json!(vec![
        vec!["text/plain", &user.description],
        vec!["text/identifier", &format!("{}@{}", user.name, domain)],
    ])
    .to_string()
}

fn get_metadata_for_recipient(recipient: &ResolvedRecipient, requested_identifier: &str) -> String {
    json!(vec![
        vec!["text/plain", &recipient.description],
        vec![
            "text/identifier",
            &format!("{}@{}", requested_identifier, recipient.domain),
        ],
    ])
    .to_string()
}

fn callback_expiry_for_provider(
    provider: AccountProvider,
    requested_wallet: Option<WalletKind>,
    default_wallet: Option<WalletKind>,
    expiry_secs: Option<u32>,
) -> Result<Option<u32>, (StatusCode, Json<Value>)> {
    if provider != AccountProvider::Blink {
        return Ok(expiry_secs);
    }

    let Some(seconds) = expiry_secs else {
        return Ok(None);
    };
    let Some(wallet) = requested_wallet.or(default_wallet) else {
        error!("Blink callback has no selected or default wallet for expiry policy");
        return Err(lnurl_error("internal server error"));
    };

    let limit = match wallet {
        WalletKind::Btc => BLINK_BTC_EXPIRY_LIMIT_SECS,
        WalletKind::Usd => BLINK_USD_EXPIRY_LIMIT_SECS,
    };
    if seconds > limit {
        trace!("Blink {wallet:?} callback expiry {seconds}s exceeds limit {limit}s");
        return Err(lnurl_error("expiry too long"));
    }

    Ok(Some(seconds.div_ceil(60)))
}

fn map_provider_invoice_error(error: ProviderError) -> (StatusCode, Json<Value>) {
    match error {
        ProviderError::UnsupportedWallet { provider, wallet } => {
            trace!("unsupported wallet {wallet:?} for provider {provider:?}");
            lnurl_error("unsupported wallet")
        }
        ProviderError::InvoiceCreationFailed(err) => {
            error!("failed to create lightning invoice: {err}");
            lnurl_error("invoice creation failed")
        }
        ProviderError::BlinkInvoiceCreationFailed(err) => {
            error!("failed to create Blink lightning invoice: {err}");
            lnurl_error("invoice creation failed")
        }
        ProviderError::UnsupportedProvider(provider) => {
            error!("unsupported provider for public LNURL invoice: {provider:?}");
            lnurl_error("internal server error")
        }
        ProviderError::MissingSparkPubkey
        | ProviderError::InvalidSparkPubkey
        | ProviderError::MissingBlinkDefaultWallet
        | ProviderError::MissingBlinkBtcWalletId
        | ProviderError::MissingBlinkUsdWalletId
        | ProviderError::BlinkPaymentStatusUnavailable(_)
        | ProviderError::PaymentStatusUnavailable(_) => {
            error!("invalid provider invoice state: {error}");
            lnurl_error("internal server error")
        }
    }
}

pub(super) fn lnurl_error(message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(Value::Object(
            vec![
                ("status".into(), Value::String("ERROR".to_string())),
                ("reason".into(), Value::String(message.to_string())),
            ]
            .into_iter()
            .collect(),
        )),
    )
}
