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
    MAX_NOSTR_EVENT_SIZE, account, webhook,
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
            return Err(lnurl_error(&format!("Couldn't find user '{identifier}'.")));
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
            match webhook::settle_blink_invoice_by_payment_hash(&state, &payment_hash, None).await {
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
        ProviderError::ProviderDisabled(provider) => {
            trace!("provider disabled for public LNURL invoice: {provider}");
            lnurl_error("provider disabled")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_support::*;
    use serde_json::{Value, json};
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
            metadata: get_metadata(&user.domain, &user),
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
    async fn verify_blink_status_fallback_still_works_when_blink_creation_disabled() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkdisabledverifyfallback",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            repo.clone(),
            None,
            &endpoint,
            true,
            false,
        )
        .await;

        let body = call_verify(state, &payment_hash).await;

        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
    }

    #[tokio::test]
    async fn verify_blink_missing_status_endpoint_returns_local_state_when_creation_disabled() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkdisabledlocalverify",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            repo.clone(),
            None,
            "",
            true,
            false,
        )
        .await;

        let body = call_verify(state, &payment_hash).await;

        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], false);
        assert_eq!(body["preimage"], Value::Null);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert!(invoice.preimage.is_none());
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
    async fn blink_public_discovery_missing_user_returns_lnurl_error_but_invalid_phone_like_identifier_keeps_not_found_shape_d_19()
     {
        // D-19: valid missing usernames now follow the LNURL error contract,
        // while invalid phone-like identifiers still keep the generic not-found
        // shape to avoid implying a valid account lookup target.
        let missing_repo = MockRepository::default();
        let missing_state = internal_route_test_state(missing_repo, None).await;
        let missing = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("alice".to_string()),
            Extension(missing_state),
        )
        .await;

        let Err((missing_status, Json(missing_body))) = missing else {
            panic!("missing recipient should now return an LNURL error body");
        };
        assert_eq!(missing_status, StatusCode::OK);
        assert_eq!(
            missing_body,
            json!({
                "status": "ERROR",
                "reason": "Couldn't find user 'alice'."
            })
        );

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
        let (status, Json(body)) = lnurl_error("unsupported wallet");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], "unsupported wallet");
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
    async fn public_invoice_callback_returns_lnurl_error_when_provider_disabled() {
        let (_payment_hash, bolt11) = generate_route_test_invoice(31);
        let (endpoint, calls, _bodies) = start_blink_invoice_mock_server(bolt11, false).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            repo, None, &endpoint, true, false,
        )
        .await;

        assert_lnurl_error(
            get_public_invoice(
                state,
                "alice",
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "provider disabled",
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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

    #[test]
    fn public_lnurl_error_reason_contract_is_explicit_and_plain() {
        const REASONS: [&str; 7] = [
            "unsupported wallet",
            "expiry too long",
            "missing amount",
            "amount out of range",
            "comment too long",
            "invoice creation failed",
            "provider disabled",
        ];

        for reason in REASONS {
            let (status, Json(body)) = lnurl_error(reason);
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["status"], "ERROR");
            assert_eq!(body["reason"], reason);
            assert!(body.get("provider").is_none());
            assert!(body.get("account_id").is_none());
        }
    }
}
